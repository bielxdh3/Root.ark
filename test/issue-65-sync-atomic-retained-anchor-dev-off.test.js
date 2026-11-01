"use strict";

// Separate persistent Sync v2 anchor; genuine SQLite/Ed25519. Owner-provided
// minimum is a synthetic fixture, NOT an independently operated custody proof.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const protocol = require("../sync-client/rootark-sync-protocol");
const { GENESIS, ANCHOR_DOMAIN, WITNESS_DOMAIN,
  Zk1SyncAtomicCasFloorLedgerDevOff } = require(
  "../src/services/zk1SyncAtomicCasFloorLedgerDevOff");
const { Zk1SyncAtomicRetainedAnchorDevOff, CHAIN_DOMAIN } = require(
  "../src/services/zk1SyncAtomicRetainedAnchorDevOff");
const { createPrivateAuthorityFixture } = require(
  "./support/issue-65-private-authority-fixture");

const deny = { code: "SYNC_ATOMIC_RETAINED_ANCHOR_DEV_OFF_DENIED" };
function nonce() { return crypto.randomBytes(32).toString("base64url"); }
function head() { return crypto.randomBytes(32).toString("hex"); }
function fixture(t) {
  const dir = createPrivateAuthorityFixture("zk65-v2-anchor-");
  const filename = path.join(dir, "anchor.sqlite");
  const keys = crypto.generateKeyPairSync("ed25519");
  const scopes = ["alice:store", "alice:separate"];
  const ownerBindings = scopes.map((scope) => ({ scope,
    accountId: crypto.randomUUID(), storeId: crypto.randomUUID() }));
  const trustedMinimumHeads = scopes.map((scope) => ({ scope,
    sequence: 0, headHash: GENESIS }));
  const options = { filename, bootstrapNew: true, signerPrivateKey: keys.privateKey,
    ownerBindings, trustedMinimumHeads };
  const opened = new Set();
  function open(overrides = {}) {
    const service = new Zk1SyncAtomicRetainedAnchorDevOff({ ...options, ...overrides });
    opened.add(service);
    return service;
  }
  function close(service) { service.close(); opened.delete(service); }
  t.after(() => {
    for (const service of opened) service.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  return { filename, keys, scopes, options, ownerBindings,
    trustedMinimumHeads, open, close };
}
function verify(service, publicKey, scope, expectedSequence, expectedHead) {
  const challenge = nonce();
  const receipt = service.readSignedHead({ scope, nonce: challenge });
  assert.deepEqual(Object.keys(receipt).sort(), ["signature", "statement"]);
  assert.deepEqual(Object.keys(receipt.statement).sort(),
    ["version", "scope", "nonce", "sequence", "headHash"].sort());
  assert.equal(receipt.statement.version, 1);
  assert.equal(receipt.statement.scope, scope);
  assert.equal(receipt.statement.nonce, challenge);
  assert.equal(receipt.statement.sequence, expectedSequence);
  assert.equal(receipt.statement.headHash, expectedHead);
  assert.equal(crypto.verify(null, Buffer.from(ANCHOR_DOMAIN
    + protocol.canonicalJson(receipt.statement)), publicKey,
  Buffer.from(receipt.signature, "base64url")), true);
  return receipt;
}
function advance(service, scope, expectedSequence, expectedHeadHash, next) {
  return service.compareAndAdvance({ scope, expectedSequence, expectedHeadHash,
    sequence: expectedSequence + 1, headHash: next });
}

test("Sync v2 retained anchor separately signs fresh genesis, CAS advances, and survives reopen", (t) => {
  const f = fixture(t);
  const anchor = f.open();
  verify(anchor, f.keys.publicKey, f.scopes[0], 0, GENESIS);
  verify(anchor, f.keys.publicKey, f.scopes[1], 0, GENESIS);
  const first = head();
  assert.equal(advance(anchor, f.scopes[0], 0, GENESIS, first), true);
  const second = head();
  assert.equal(advance(anchor, f.scopes[0], 1, first, second), true);
  verify(anchor, f.keys.publicKey, f.scopes[0], 2, second);
  verify(anchor, f.keys.publicKey, f.scopes[1], 0, GENESIS);
  f.close(anchor);
  const reopened = f.open({ trustedMinimumHeads: [
    { scope: f.scopes[0], sequence: 1, headHash: first },
    { scope: f.scopes[1], sequence: 0, headHash: GENESIS },
  ] });
  verify(reopened, f.keys.publicKey, f.scopes[0], 2, second);
  assert.equal(advance(reopened, f.scopes[0], 1, first, head()), false,
    "a lost or replayed compare cannot overwrite the current retained floor");
});

test("Sync v2 retained anchor enforces strict exact CAS and rejects caller-supplied scopes", (t) => {
  const f = fixture(t);
  const a = f.open();
  const first = head();
  assert.equal(advance(a, f.scopes[0], 0, GENESIS, first), true);
  assert.equal(advance(a, f.scopes[0], 0, GENESIS, head()), false);
  assert.equal(advance(a, f.scopes[0], 1, GENESIS, head()), false);
  assert.throws(() => a.compareAndAdvance({ scope: f.scopes[0],
    expectedSequence: 1, expectedHeadHash: first,
    sequence: 3, headHash: head() }), deny);
  assert.throws(() => a.readSignedHead({ scope: "mallory:store", nonce: nonce() }), deny);
  assert.throws(() => a.readSignedHead({ scope: f.scopes[0], nonce: "bad" }), deny);
  assert.throws(() => a.readSignedHead({ scope: f.scopes[0], nonce: nonce(),
    physicalDurable: true }), deny);
  verify(a, f.keys.publicKey, f.scopes[0], 1, first);
});

test("Sync v2 retained anchor serializes distinct SQLite connections and fences stale CAS", (t) => {
  const f = fixture(t);
  const a = f.open();
  const b = f.open();
  const first = head(), fork = head();
  assert.equal(advance(a, f.scopes[0], 0, GENESIS, first), true);
  assert.equal(advance(b, f.scopes[0], 0, GENESIS, fork), false);
  verify(b, f.keys.publicKey, f.scopes[0], 1, first);
  const next = head();
  assert.equal(advance(b, f.scopes[0], 1, first, next), true);
  verify(a, f.keys.publicKey, f.scopes[0], 2, next);
});

test("Sync v2 retained anchor refuses rollback below separately trusted prior high-water", (t) => {
  const f = fixture(t);
  let a = f.open();
  const first = head();
  assert.equal(advance(a, f.scopes[0], 0, GENESIS, first), true);
  f.close(a);
  const old = path.join(path.dirname(f.filename), "old-anchor.sqlite");
  fs.copyFileSync(f.filename, old);
  if (process.platform !== "win32") fs.chmodSync(old, 0o600);
  a = f.open();
  const next = head();
  assert.equal(advance(a, f.scopes[0], 1, first, next), true);
  f.close(a);
  fs.copyFileSync(old, f.filename);
  assert.throws(() => f.open({ trustedMinimumHeads: [
    { scope: f.scopes[0], sequence: 2, headHash: next },
    { scope: f.scopes[1], sequence: 0, headHash: GENESIS },
  ] }), deny, "an outdated SQLite file cannot contradict an externally retained head");
});

test("Sync v2 retained anchor refuses historical tamper, forged forward link, triggers and weak schema", (t) => {
  for (const variant of ["middle_history", "forward_history", "trigger", "weakened_schema"]) {
    const f = fixture(t);
    const a = f.open();
    const first = head();
    assert.equal(advance(a, f.scopes[0], 0, GENESIS, first), true);
    assert.equal(advance(a, f.scopes[0], 1, first, head()), true);
    f.close(a);
    const db = new Database(f.filename, { fileMustExist: true });
    let expectedTrustedHead = null;
    try {
      if (variant === "middle_history") {
        db.prepare(`UPDATE atomic_anchor_history SET previous_chain=?
          WHERE scope=? AND sequence=1`).run(head(), f.scopes[0]);
      } else if (variant === "forward_history") {
        const previous = db.prepare(`SELECT sequence,head_hash,chain_hash
          FROM atomic_anchor_head WHERE scope=?`).get(f.scopes[0]);
        assert.equal(previous.sequence, 2);
        expectedTrustedHead = previous.head_hash;
        const next = head();
        const chain = { scope: f.scopes[0],
          accountId: f.ownerBindings[0].accountId,
          storeId: f.ownerBindings[0].storeId,
          sequence: 3, previousHash: previous.head_hash,
          previousChain: previous.chain_hash, headHash: next };
        const forgedHash = crypto.createHash("sha256")
          .update(CHAIN_DOMAIN + protocol.canonicalJson(chain)).digest("hex");
        // A SQLite writer can correctly recompute EVERY ordinary SHA-256
        // link, but cannot produce the isolated Ed25519 per-entry seal.
        db.prepare(`INSERT INTO atomic_anchor_history
          (scope,sequence,previous_hash,previous_chain,head_hash,chain_hash,seal)
          VALUES(?,?,?,?,?,?,?)`).run(f.scopes[0], 3, previous.head_hash,
          previous.chain_hash, next, forgedHash,
          crypto.randomBytes(64).toString("base64url"));
        db.prepare(`UPDATE atomic_anchor_head SET sequence=3,
          head_hash=?, chain_hash=? WHERE scope=?`).run(next, forgedHash, f.scopes[0]);
      } else if (variant === "trigger") {
        db.exec(`CREATE TRIGGER erase_anchor_history AFTER INSERT ON atomic_anchor_history
          BEGIN DELETE FROM atomic_anchor_history WHERE scope=NEW.scope
            AND sequence=NEW.sequence; END`);
      } else {
        db.transaction(() => {
          db.exec("ALTER TABLE atomic_anchor_history RENAME TO old_anchor_history");
          db.exec(`CREATE TABLE atomic_anchor_history (
            scope TEXT NOT NULL,sequence INTEGER NOT NULL,previous_hash TEXT NOT NULL,
            previous_chain TEXT NOT NULL,head_hash TEXT NOT NULL,chain_hash TEXT NOT NULL,
            seal TEXT NOT NULL,
            PRIMARY KEY(scope,sequence))`);
          db.exec("INSERT INTO atomic_anchor_history SELECT * FROM old_anchor_history");
          db.exec("DROP TABLE old_anchor_history");
        }).immediate();
      }
    } finally { db.close(); }
    const opts = expectedTrustedHead === null ? {} : { trustedMinimumHeads: [
      { scope: f.scopes[0], sequence: 2, headHash: expectedTrustedHead },
      { scope: f.scopes[1], sequence: 0, headHash: GENESIS },
    ] };
    assert.throws(() => f.open(opts), deny,
      `${variant} must not survive read-only startup, even with a valid pinned prefix`);
  }
});

test("Sync v2 retained anchor never treats signer rotation or wrong owner binding as authoritative", (t) => {
  const f = fixture(t);
  const a = f.open();
  assert.equal(advance(a, f.scopes[0], 0, GENESIS, head()), true);
  f.close(a);
  assert.throws(() => f.open({ signerPrivateKey: crypto.generateKeyPairSync(
    "ed25519").privateKey }), deny);
  const wrong = f.ownerBindings.map((item) => ({ ...item }));
  wrong[0].storeId = crypto.randomUUID();
  assert.throws(() => f.open({ ownerBindings: wrong }), deny);
});

test("Sync v2 CAS ledger consumes a distinct persisted signed retained anchor without a mock floor", async (t) => {
  const f = fixture(t);
  const anchor = f.open();
  const cas = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const owner = { ...f.ownerBindings[0], username: "alice", compartmentId: "private" };
  const pair = { operationIds: ["delete.one", "move.two"], envelopeDigests: [head(), head()] };
  const physical = { commitId: crypto.randomUUID(), storeHeadSha256: head(), fencingEpoch: 9 };
  const physicalFence = { withCurrentRead: async (challenge, continuation) => {
    let held = true;
    try {
      const statement = { version: 2, ...owner, nonce: challenge.nonce,
        operationIds: challenge.operationIds, envelopeDigests: challenge.envelopeDigests,
        ...physical, physicalDurable: true };
      const receipt = { statement, signature: crypto.sign(null,
        Buffer.from(WITNESS_DOMAIN + protocol.canonicalJson(statement)),
        witness.privateKey).toString("base64url") };
      return await continuation({ receipt, lineage: null }, {
        assertHeld: () => held,
      });
    } finally { held = false; }
  } };
  const options = { filename: path.join(path.dirname(f.filename), "cas.sqlite"),
    bootstrapNew: true, casPrivateKey: cas.privateKey,
    witnessPublicKey: witness.publicKey, anchorPublicKey: f.keys.publicKey,
    ownerBindings: [owner], physicalFence, retainedAnchor: anchor };
  let ledger = await Zk1SyncAtomicCasFloorLedgerDevOff.open(options);
  t.after(() => ledger?.close());
  const input = { scope: owner.scope, accountId: owner.accountId, storeId: owner.storeId,
    ...pair };
  const advanced = await ledger.recordPhysicalPair(input);
  verify(anchor, f.keys.publicKey, owner.scope, 1, advanced.headHash);
  assert.deepEqual(await ledger.recordPhysicalPair(input), advanced,
    "lost client ACK cannot make the durable external floor advance twice");
  const current = await ledger.freshCurrent({ scope: owner.scope,
    accountId: owner.accountId, storeId: owner.storeId, nonce: nonce(), ...physical });
  assert.equal(current.statement.sequence, 1);
  assert.equal(current.statement.current, true);
  ledger.close();
  ledger = null;
  f.close(anchor);
  const recoveredAnchor = f.open({ trustedMinimumHeads: [
    { scope: owner.scope, sequence: 1, headHash: advanced.headHash },
    { scope: f.scopes[1], sequence: 0, headHash: GENESIS },
  ] });
  ledger = await Zk1SyncAtomicCasFloorLedgerDevOff.open({ ...options,
    retainedAnchor: recoveredAnchor });
  assert.deepEqual(await ledger.recordPhysicalPair(input), advanced);
  verify(recoveredAnchor, f.keys.publicKey, owner.scope, 1, advanced.headHash);
  ledger.close();
  ledger = null;
});
