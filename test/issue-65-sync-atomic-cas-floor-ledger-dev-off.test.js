"use strict";

// Genuine SQLite WAL/FULL durability semantics, real Ed25519 signatures and
// adversarial reopens. The off-host physical fence and retained anchor here
// are deliberately synthetic: these tests DO NOT prove physical independence.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const { assertPrivateSqliteFile } = require("../src/services/zk1PrivateSqlitePath");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { Zk1SyncAtomicCasFloorLedgerDevOff, WITNESS_DOMAIN,
  CAS_DOMAIN, ANCHOR_DOMAIN, LINEAGE_DOMAIN, GENESIS } =
  require("../src/services/zk1SyncAtomicCasFloorLedgerDevOff");

const deny = { code: "SYNC_ATOMIC_CAS_DEV_OFF_UNVERIFIED" };
const b64 = () => crypto.randomBytes(32).toString("base64url");
const keys = () => crypto.generateKeyPairSync("ed25519");
function sign(privateKey, domain, statement) {
  return { statement,
    signature: crypto.sign(null, Buffer.from(domain
      + protocol.canonicalJson(statement)), privateKey).toString("base64url") };
}
function fixture(t) {
  const dir = createPrivateAuthorityFixture("zk65-cas-v2-ledger-");
  const filename = path.join(dir, "authority.db");
  const cas = keys(), witness = keys(), anchor = keys();
  const binding = Object.freeze({ scope: "alice:store-one",
    accountId: crypto.randomUUID(), storeId: crypto.randomUUID(),
    username: "alice", compartmentId: "private-1" });
  const pair = { operationIds: ["delete.first", "move:second"],
    envelopeDigests: [crypto.randomBytes(32).toString("hex"),
      crypto.randomBytes(32).toString("hex")] };
  const physical = { commitId: crypto.randomUUID(),
    storeHeadSha256: crypto.randomBytes(32).toString("hex"),
    fencingEpoch: 7 };
  const anchorHead = { sequence: 0, headHash: GENESIS };
  const effects = { badWitness: false, badLineage: false, forceLineage: false,
    badAnchor: false, refuseAnchor: false, loseAnchorAck: false,
    earlyFenceRelease: false, adoptedEarlyRelease: false,
    lateFenceInvocation: false, lateContinuation: null,
    swallowFenceError: false, releaseFenceError: false,
    withLease: 0, signedPhysical: 0, anchorAdvances: 0,
    pausedAtLease: null, detachedSettled: null,
    leaseProbeCount: 0, expireLeaseAtProbe: null };
  const previouslyWitnessed = new Set();
  const physicalFence = {
    withCurrentRead: async (challenge, continuation) => {
      effects.withLease++;
      if (effects.pausedAtLease) await effects.pausedAtLease;
      let held = true;
      const lease = { assertHeld: () => {
        effects.leaseProbeCount++;
        return held && (effects.expireLeaseAtProbe === null
          || effects.leaseProbeCount < effects.expireLeaseAtProbe);
      } };
      try {
      const statement = { version: 2, ...binding, nonce: challenge.nonce,
        operationIds: challenge.operationIds, envelopeDigests: challenge.envelopeDigests,
        ...physical, physicalDurable: true };
      effects.signedPhysical++;
      const signer = effects.badWitness ? keys().privateKey : witness.privateKey;
      const previous = challenge.expectedPrevious;
      const changed = previous && (previous.commitId !== physical.commitId
        || previous.storeHeadSha256 !== physical.storeHeadSha256);
      const physicalId = `${physical.commitId}:${physical.storeHeadSha256}`;
      const lineage = changed && (effects.forceLineage
        || !previouslyWitnessed.has(physicalId))
        ? sign(effects.badLineage ? keys().privateKey : witness.privateKey,
          LINEAGE_DOMAIN, { version: 1, scope: binding.scope,
            accountId: binding.accountId, storeId: binding.storeId,
            nonce: challenge.nonce, previousCommitId: previous.commitId,
            previousHeadSha256: previous.storeHeadSha256,
            previousFencingEpoch: previous.fencingEpoch,
            commitId: physical.commitId,
            storeHeadSha256: physical.storeHeadSha256,
            fencingEpoch: physical.fencingEpoch, physicalDurable: true })
        : null;
      const bundle = { receipt: sign(signer, WITNESS_DOMAIN, statement), lineage };
      if (effects.lateFenceInvocation) {
        // Callback is invoked only AFTER adapter has already returned.
        // A truthful separately held lease would not make that safe.
        effects.lateContinuation = () => continuation(bundle,
          { assertHeld: () => true });
        return undefined;
      }
      if (effects.earlyFenceRelease) {
        // Hostile provider releases the lock without awaiting continuation.
        effects.detachedSettled = continuation(bundle, lease).then(() => true, () => false);
        return undefined;
      }
      if (effects.adoptedEarlyRelease) {
        // `return promise` releases finally before the callback's await settles.
        return continuation(bundle, lease);
      }
      if (effects.swallowFenceError) {
        try { await continuation(bundle, lease); } catch { /* hostile provider hides failure */ }
        return undefined;
      }
      const result = await continuation(bundle, lease);
      previouslyWitnessed.add(physicalId);
      if (effects.releaseFenceError) throw new Error("PHYSICAL_FENCE_RELEASE_FAILED");
      return result;
      } finally { held = false; }
    },
  };
  const retainedAnchor = {
    readSignedHead: async ({ scope, nonce }) => sign(
      effects.badAnchor ? keys().privateKey : anchor.privateKey,
      ANCHOR_DOMAIN, { version: 1, scope, nonce, ...anchorHead }),
    compareAndAdvance: async ({ expectedSequence, expectedHeadHash,
      sequence, headHash }) => {
      if (effects.refuseAnchor) return false;
      if (expectedSequence !== anchorHead.sequence
        || expectedHeadHash !== anchorHead.headHash
        || sequence !== expectedSequence + 1) return false;
      Object.assign(anchorHead, { sequence, headHash });
      effects.anchorAdvances++;
      if (effects.loseAnchorAck) throw new Error("EXTERNAL_CAS_ACK_LOST");
      return true;
    },
  };
  const options = { filename, bootstrapNew: true,
    casPrivateKey: cas.privateKey, witnessPublicKey: witness.publicKey,
    anchorPublicKey: anchor.publicKey, ownerBindings: [binding],
    physicalFence, retainedAnchor };
  const opened = new Set();
  async function open() {
    const ledger = await Zk1SyncAtomicCasFloorLedgerDevOff.open(options);
    opened.add(ledger);
    return ledger;
  }
  function close(ledger) {
    ledger.close();
    opened.delete(ledger);
  }
  t.after(() => {
    for (const ledger of opened) ledger.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  return { filename, binding, pair, physical, anchorHead, effects, options,
    cas, witness, anchor, retainedAnchor, physicalFence, open, close };
}
function request(f, overrides = {}) {
  return { scope: f.binding.scope, accountId: f.binding.accountId,
    storeId: f.binding.storeId, operationIds: f.pair.operationIds,
    envelopeDigests: f.pair.envelopeDigests, ...overrides };
}
function challenge(f, overrides = {}) {
  return { scope: f.binding.scope, accountId: f.binding.accountId,
    storeId: f.binding.storeId, nonce: b64(), ...f.physical, ...overrides };
}
function verifyCurrentSignature(f, received) {
  assert.equal(received.statement.current, true);
  assert.equal(received.statement.version, 2);
  assert.equal(crypto.verify(null, Buffer.from(CAS_DOMAIN
    + protocol.canonicalJson(received.statement)), f.cas.publicKey,
  Buffer.from(received.signature, "base64url")), true);
  assert.equal(received.statement.accountId, f.binding.accountId);
  assert.equal(received.statement.storeId, f.binding.storeId);
}

test("Sync v2 durable CAS requires independent signed retained genesis before bootstrap", async (t) => {
  const f = fixture(t);
  f.effects.badAnchor = true;
  await assert.rejects(f.open(), deny);
  f.effects.badAnchor = false;
  const ledger = await f.open();
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny,
    "no current signed floor can exist before the first independently fenced batch");
});

test("Sync v2 exported constructor cannot bypass signed external preflight", async (t) => {
  const f = fixture(t);
  let opened = null;
  let failure = null;
  try {
    // Static open() is the only entry point allowed to mint the module-private
    // preflight token after the fresh signed retained-head and read-only audit.
    opened = new Zk1SyncAtomicCasFloorLedgerDevOff(f.options);
  } catch (error) { failure = error; }
  finally { opened?.close(); }
  assert.equal(failure?.code, deny.code);
  assert.equal(fs.readdirSync(path.dirname(f.filename)).includes(path.basename(f.filename)), false,
    "unverified direct construction must not create a local CAS authority");

  const verified = await f.open();
  f.close(verified);
  f.effects.badAnchor = true;
  opened = null;
  failure = null;
  try { opened = new Zk1SyncAtomicCasFloorLedgerDevOff(f.options); }
  catch (error) { failure = error; }
  finally { opened?.close(); }
  assert.equal(failure?.code, deny.code,
    "direct construction must not bypass externally signed restart validation");
});

test("Sync v2 constructor cannot forge internal preflight through a Proxy symbol getter", (t) => {
  const f = fixture(t);
  const forged = new Proxy(f.options, {
    get(target, key, receiver) {
      // A private Symbol property name is not a secret against a Proxy:
      // the trap sees the unknown symbol as soon as destructuring reads it.
      if (typeof key === "symbol") return { kind: "absent" };
      return Reflect.get(target, key, receiver);
    },
  });
  let opened = null;
  let failure = null;
  try { opened = new Zk1SyncAtomicCasFloorLedgerDevOff(forged); }
  catch (error) { failure = error; }
  finally { opened?.close(); }
  assert.equal(failure?.code, deny.code,
    "a caller must not synthesize the module-private signed preflight");
  assert.equal(fs.readdirSync(path.dirname(f.filename)).includes(path.basename(f.filename)), false,
    "forged preflight must fail without writing a SQLite authority");
});

test("Sync v2 bootstrap never adopts a SQLite file created during the signed genesis challenge", async (t) => {
  const f = fixture(t);
  const readHead = f.retainedAnchor.readSignedHead;
  let injected = false;
  f.retainedAnchor.readSignedHead = async (challenge) => {
    if (!injected) {
      const attacker = new Database(f.filename);
      try {
        attacker.exec("CREATE TABLE intruder_marker (id INTEGER PRIMARY KEY)");
      } finally { attacker.close(); }
      if (process.platform !== "win32") fs.chmodSync(f.filename, 0o600);
      assertPrivateSqliteFile(f.filename);
      injected = true;
    }
    return readHead(challenge);
  };
  await assert.rejects(f.open(), deny,
    "an unexpected file appearing during genesis must not be adopted or opened writable");
  assert.equal(injected, true);
  const verify = new Database(f.filename, { readonly: true, fileMustExist: true });
  try {
    const tables = verify.prepare(`SELECT name FROM sqlite_schema
      WHERE type='table' ORDER BY name`).all().map((row) => row.name);
    assert.deepEqual(tables, ["intruder_marker"],
      "denial must happen before CREATE TABLE IF NOT EXISTS mutates the unexpected SQLite file");
  } finally { verify.close(); }
  assert.equal(f.anchorHead.sequence, 0);
});

test("Sync v2 physically witnessed pair advances SQLite and off-host high-water once; restart preserves floor", async (t) => {
  const f = fixture(t);
  const first = await f.open();
  const committed = await first.recordPhysicalPair(request(f));
  assert.equal(committed.sequence, 1);
  assert.equal(committed.headHash, f.anchorHead.headHash);
  assert.equal(f.effects.anchorAdvances, 1);
  const nonce = b64();
  const signed = await first.freshCurrent(challenge(f, { nonce }));
  verifyCurrentSignature(f, signed);
  assert.equal(signed.statement.sequence, 1);
  assert.equal(signed.statement.nonce, nonce);
  assert.equal(signed.statement.storeHeadSha256, f.physical.storeHeadSha256);
  const repeat = await first.recordPhysicalPair(request(f));
  assert.deepEqual(repeat, committed);
  assert.equal(f.effects.anchorAdvances, 1, "lost ACK never re-advances external floor");
  f.close(first);
  const reloaded = await f.open();
  verifyCurrentSignature(f, await reloaded.freshCurrent(challenge(f)));
  assert.deepEqual(await reloaded.recordPhysicalPair(request(f)), committed);
  assert.equal(f.effects.anchorAdvances, 1);
});

test("Sync v2 rejects forgery, wrong owner/store and unauthorized extra input before signing", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  f.effects.badWitness = true;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny);
  f.effects.badWitness = false;
  for (const altered of [
    { scope: "bob:store" }, { accountId: crypto.randomUUID() },
    { storeId: crypto.randomUUID() }, { operationIds: ["same", "same"] },
    { envelopeDigests: ["AAAA", f.pair.envelopeDigests[1]] },
    { commitId: crypto.randomUUID() },
  ]) await assert.rejects(ledger.recordPhysicalPair(request(f, altered)), deny);
  await ledger.recordPhysicalPair(request(f));
  for (const altered of [
    { scope: "bob:store" }, { storeId: crypto.randomUUID() },
    { accountId: crypto.randomUUID() }, { nonce: "bogus" },
    { fencingEpoch: 1 }, { commitId: crypto.randomUUID() },
    { callerAuthorized: true },
  ]) await assert.rejects(ledger.freshCurrent(challenge(f, altered)), deny);
  f.effects.badWitness = true;
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny);
  f.effects.badWitness = false;
  f.effects.badAnchor = true;
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny);
});

test("Sync v2 CAS denies stale forks, replay and rollback despite a freshly signed witness", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  await ledger.recordPhysicalPair(request(f));
  const old = { ...f.physical };
  f.physical.commitId = crypto.randomUUID();
  f.physical.storeHeadSha256 = crypto.randomBytes(32).toString("hex");
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "different head with same fencing epoch must not advance");
  f.physical.fencingEpoch++;
  f.effects.badLineage = true;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "new head requires an independently signed previous-to-current lineage");
  f.effects.badLineage = false;
  const second = await ledger.recordPhysicalPair(request(f));
  assert.equal(second.sequence, 2);
  assert.equal(f.anchorHead.sequence, 2);
  const currentPhysical = { ...f.physical };
  Object.assign(f.physical, { ...old, fencingEpoch: f.physical.fencingEpoch + 1 });
  f.effects.forceLineage = true;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "a previously committed physical head with valid fresh signed lineage and higher epoch cannot be re-admitted");
  assert.equal(f.effects.anchorAdvances, 2,
    "replayed old head must not advance the externally signed CAS floor");
  Object.assign(f.physical, currentPhysical);
  verifyCurrentSignature(f, await ledger.freshCurrent(challenge(f)));
  assert.equal(f.effects.anchorAdvances, 2,
    "a replay denied before the mutable phase cannot poison legitimate current readback");
  Object.assign(f.physical, old);
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny,
    "rolled-back physical witness current cannot sign the newer head");
  f.anchorHead.sequence = 1;
  f.anchorHead.headHash = crypto.randomBytes(32).toString("hex");
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny,
    "signed externally rolled-back/altered floor cannot authorize readback");
});

test("Sync v2 retained CAS tip refuses tampering with a non-tip historical link or signed pair", async (t) => {
  for (const variant of ["prior_hash", "signed_pair", "missing_prior"]) {
    const f = fixture(t);
    const ledger = await f.open();
    await ledger.recordPhysicalPair(request(f));
    for (let i = 0; i < 2; i++) {
      f.physical.commitId = crypto.randomUUID();
      f.physical.storeHeadSha256 = crypto.randomBytes(32).toString("hex");
      f.physical.fencingEpoch++;
      await ledger.recordPhysicalPair(request(f));
    }
    assert.equal(f.anchorHead.sequence, 3);
    f.close(ledger);
    const db = new Database(f.filename, { fileMustExist: true });
    try {
      if (variant === "prior_hash") db.prepare(`UPDATE atomic_cas_history
        SET previous_hash=? WHERE scope=? AND sequence=2`).run(
        crypto.randomBytes(32).toString("hex"), f.binding.scope);
      if (variant === "signed_pair") db.prepare(`UPDATE atomic_cas_history
        SET operation_ids=? WHERE scope=? AND sequence=2`).run(
        protocol.canonicalJson(["tampered.one", "tampered.two"]), f.binding.scope);
      if (variant === "missing_prior") db.prepare(`DELETE FROM atomic_cas_history
        WHERE scope=? AND sequence=2`).run(f.binding.scope);
    } finally { db.close(); }
    const before = crypto.createHash("sha256")
      .update(fs.readFileSync(f.filename)).digest("hex");
    await assert.rejects(f.open(), deny,
      `signed retained current floor cannot hide a ${variant} historical corruption`);
    const after = crypto.createHash("sha256")
      .update(fs.readFileSync(f.filename)).digest("hex");
    assert.equal(after, before,
      "startup denial must not mutate the SQLite main file before readonly audit");
    assert.equal(f.anchorHead.sequence, 3,
      "corrupted historical evidence must not roll back external high-water");
  }
});

test("Sync v2 closes read-only startup snapshot before awaiting the independent retained head", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  await ledger.recordPhysicalPair(request(f));
  f.close(ledger);
  const readHead = f.retainedAnchor.readSignedHead;
  let checkpointObserved = false;
  f.retainedAnchor.readSignedHead = async (challenge) => {
    if (!checkpointObserved) {
      const writer = new Database(f.filename, { fileMustExist: true });
      try {
        writer.pragma("busy_timeout = 0");
        assert.equal(writer.pragma("journal_mode", { simple: true }), "wal");
        writer.pragma("user_version = 17");
        const observedWal = writer.pragma("wal_checkpoint(PASSIVE)");
        assert.equal(observedWal.length, 1);
        assert.ok(observedWal[0].log >= 1,
          "the independent writer must have generated a real WAL frame");
        const checkpoint = writer.pragma("wal_checkpoint(TRUNCATE)");
        assert.equal(checkpoint.length, 1);
        assert.equal(checkpoint[0].busy, 0,
          "the external authority must never hold a SQLite reader that pins WAL checkpoints");
        assert.ok(checkpoint[0].log >= 0 && checkpoint[0].checkpointed >= 0,
          "a no-op checkpoint outside WAL cannot satisfy the preflight test");
        checkpointObserved = true;
      } finally { writer.close(); }
    }
    return readHead(challenge);
  };
  const reopened = await f.open();
  assert.equal(checkpointObserved, true,
    "a genuine WAL checkpoint must occur during signed external readback");
  verifyCurrentSignature(f, await reopened.freshCurrent(challenge(f)));
});

test("Sync v2 rejects corruption during signed external lookup before the read-only preflight", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  await ledger.recordPhysicalPair(request(f));
  f.close(ledger);
  const readHead = f.retainedAnchor.readSignedHead;
  let corrupted = false;
  let afterCorruptionHash;
  f.retainedAnchor.readSignedHead = async (challenge) => {
    if (!corrupted) {
      const writer = new Database(f.filename, { fileMustExist: true });
      try {
        const changed = writer.prepare(`UPDATE atomic_cas_history
          SET previous_hash=? WHERE scope=? AND sequence=1`).run(
          crypto.randomBytes(32).toString("hex"), f.binding.scope);
        assert.equal(changed.changes, 1);
        corrupted = true;
      } finally { writer.close(); }
      afterCorruptionHash = crypto.createHash("sha256")
        .update(fs.readFileSync(f.filename)).digest("hex");
    }
    return readHead(challenge);
  };
  await assert.rejects(f.open(), deny,
    "post-snapshot corruption must fail the fresh full-history audit before any usable signer escapes");
  assert.equal(corrupted, true);
  assert.equal(crypto.createHash("sha256")
    .update(fs.readFileSync(f.filename)).digest("hex"), afterCorruptionHash,
    "read-only startup must not checkpoint or mutate the corrupt file after tampering");
  assert.equal(f.anchorHead.sequence, 1,
    "a failed recovery cannot mutate the independently signed high-water");
});

test("Sync v2 refuses to return a signer when its second signed anchor callback corrupts local history", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  await ledger.recordPhysicalPair(request(f));
  f.close(ledger);
  const readHead = f.retainedAnchor.readSignedHead;
  let lookups = 0;
  f.retainedAnchor.readSignedHead = async (challenge) => {
    lookups++;
    if (lookups === 2) {
      const writer = new Database(f.filename, { fileMustExist: true });
      try {
        const update = writer.prepare(`UPDATE atomic_cas_history
          SET previous_hash=? WHERE scope=? AND sequence=1`).run(
          crypto.randomBytes(32).toString("hex"), f.binding.scope);
        assert.equal(update.changes, 1);
      } finally { writer.close(); }
    }
    return readHead(challenge);
  };
  await assert.rejects(f.open(), deny,
    "even the final post-writable signed anchor callback cannot corrupt the chain and return an authority");
  assert.equal(lookups, 2);
  assert.equal(f.anchorHead.sequence, 1);
});

test("Sync v2 rejects second-callback signer-identity and unauthorized-scope injections", async (t) => {
  for (const variant of ["forged_fingerprint", "foreign_head", "orphan_history"]) {
    const f = fixture(t);
    const ledger = await f.open();
    await ledger.recordPhysicalPair(request(f));
    f.close(ledger);
    const originalRead = f.retainedAnchor.readSignedHead;
    let calls = 0;
    f.retainedAnchor.readSignedHead = async (challenge) => {
      calls++;
      if (calls === 2) {
        const writer = new Database(f.filename, { fileMustExist: true });
        try {
          if (variant === "forged_fingerprint") {
            const updated = writer.prepare(`UPDATE atomic_cas_identity
              SET cas_fingerprint=? WHERE id=1`).run("00".repeat(32));
            assert.equal(updated.changes, 1);
          } else if (variant === "foreign_head") {
            const added = writer.prepare(`INSERT INTO atomic_cas_head
              SELECT ?,account_id,store_id,sequence,head_hash,commit_id,
                store_head,fencing_epoch,operation_ids,envelope_digests
              FROM atomic_cas_head WHERE scope=?`).run("bob:foreign", f.binding.scope);
            assert.equal(added.changes, 1);
          } else {
            const added = writer.prepare(`INSERT INTO atomic_cas_history
              SELECT ?,sequence,previous_hash,?,commit_id,store_head,
                fencing_epoch,operation_ids,envelope_digests
              FROM atomic_cas_history WHERE scope=?`).run("bob:orphan",
              crypto.randomBytes(32).toString("hex"), f.binding.scope);
            assert.equal(added.changes, 1);
          }
        } finally { writer.close(); }
      }
      return originalRead(challenge);
    };
    await assert.rejects(f.open(), deny,
      `${variant}: a second signed external callback cannot mutate authority identities or scopes`);
    assert.equal(calls, 2, "the negative must reach the post-writable callback");
    assert.equal(f.anchorHead.sequence, 1);
  }
});

test("Sync v2 refuses an old seven-column history schema or missing uniqueness before writable reopen", async (t) => {
  for (const variant of ["legacy_schema", "weakened_unique_constraints"]) {
    const f = fixture(t);
    const ledger = await f.open();
    await ledger.recordPhysicalPair(request(f));
    f.close(ledger);
    const db = new Database(f.filename, { fileMustExist: true });
    try {
      db.transaction(() => {
        db.exec("ALTER TABLE atomic_cas_history RENAME TO historical_original");
        if (variant === "legacy_schema") {
          db.exec(`CREATE TABLE atomic_cas_history (
            scope TEXT NOT NULL, sequence INTEGER NOT NULL,
            previous_hash TEXT NOT NULL, head_hash TEXT NOT NULL UNIQUE,
            commit_id TEXT NOT NULL, store_head TEXT NOT NULL,
            fencing_epoch INTEGER NOT NULL, PRIMARY KEY(scope,sequence),
            UNIQUE(scope,commit_id), UNIQUE(scope,store_head))`);
          db.exec(`INSERT INTO atomic_cas_history
            (scope,sequence,previous_hash,head_hash,commit_id,store_head,fencing_epoch)
            SELECT scope,sequence,previous_hash,head_hash,commit_id,store_head,fencing_epoch
            FROM historical_original`);
        } else {
          db.exec(`CREATE TABLE atomic_cas_history (
            scope TEXT NOT NULL, sequence INTEGER NOT NULL,
            previous_hash TEXT NOT NULL, head_hash TEXT NOT NULL UNIQUE,
            commit_id TEXT NOT NULL, store_head TEXT NOT NULL,
            fencing_epoch INTEGER NOT NULL, operation_ids TEXT NOT NULL,
            envelope_digests TEXT NOT NULL, PRIMARY KEY(scope,sequence))`);
          db.exec(`INSERT INTO atomic_cas_history SELECT * FROM historical_original`);
        }
        db.exec("DROP TABLE historical_original");
      }).immediate();
    } finally { db.close(); }
    const before = crypto.createHash("sha256")
      .update(fs.readFileSync(f.filename)).digest("hex");
    await assert.rejects(f.open(), deny,
      `${variant}: required pair columns and unique constraints must be immutable`);
    assert.equal(crypto.createHash("sha256")
      .update(fs.readFileSync(f.filename)).digest("hex"), before,
    "untrusted schema must be rejected before a writable SQLite connection");
    assert.equal(f.anchorHead.sequence, 1);
  }
});

test("Sync v2 refuses weakened persisted signer-identity constraints before writable open", async (t) => {
  for (const variant of ["no_primary_key", "no_fixed_identity_check",
    "commented_out_identity_check"]) {
    const f = fixture(t);
    const ledger = await f.open();
    await ledger.recordPhysicalPair(request(f));
    f.close(ledger);
    const db = new Database(f.filename, { fileMustExist: true });
    try {
      db.transaction(() => {
        db.exec("ALTER TABLE atomic_cas_identity RENAME TO saved_cas_identity");
        const identityIdDefinition = variant === "no_primary_key"
          ? "id INTEGER"
          : variant === "commented_out_identity_check"
            ? "id INTEGER PRIMARY KEY /* CHECK(id=1) */"
            : "id INTEGER PRIMARY KEY";
        db.exec(`CREATE TABLE atomic_cas_identity (
          ${identityIdDefinition},
          cas_fingerprint TEXT NOT NULL, witness_fingerprint TEXT NOT NULL,
          anchor_fingerprint TEXT NOT NULL)`);
        db.exec(`INSERT INTO atomic_cas_identity SELECT * FROM saved_cas_identity`);
        db.exec("DROP TABLE saved_cas_identity");
      }).immediate();
    } finally { db.close(); }
    const before = crypto.createHash("sha256")
      .update(fs.readFileSync(f.filename)).digest("hex");
    await assert.rejects(f.open(), deny,
      `${variant}: matching signer fingerprints cannot authorize a weak identity schema`);
    assert.equal(crypto.createHash("sha256")
      .update(fs.readFileSync(f.filename)).digest("hex"), before,
      "identity table must be rejected before writable recovery changes SQLite");
    assert.equal(f.anchorHead.sequence, 1);
  }
});

test("Sync v2 prevents a hostile SQLite trigger from acknowledging a missing durable history append", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  const injected = new Database(f.filename, { fileMustExist: true });
  try {
    injected.exec(`CREATE TRIGGER erase_atomic_cas_history_after_insert
      AFTER INSERT ON atomic_cas_history BEGIN
        DELETE FROM atomic_cas_history
          WHERE scope=NEW.scope AND sequence=NEW.sequence;
      END`);
  } finally { injected.close(); }
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "CAS cannot advance external high-water after SQLite trigger erased append");
  assert.equal(f.effects.anchorAdvances, 0);
  assert.equal(f.anchorHead.sequence, 0);
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "ambiguous local SQLite append permanently fences the current authority");
  f.close(ledger);
  await assert.rejects(f.open(), deny,
    "read-only startup must refuse unapproved SQLite triggers before writable open");
});

test("Sync v2 read-only startup denies a hostile trigger even when its retained chain is intact", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  await ledger.recordPhysicalPair(request(f));
  f.close(ledger);
  const injected = new Database(f.filename, { fileMustExist: true });
  try {
    injected.exec(`CREATE TRIGGER erase_atomic_cas_history_after_insert
      AFTER INSERT ON atomic_cas_history BEGIN
        DELETE FROM atomic_cas_history
          WHERE scope=NEW.scope AND sequence=NEW.sequence;
      END`);
  } finally { injected.close(); }
  const before = crypto.createHash("sha256")
    .update(fs.readFileSync(f.filename)).digest("hex");
  await assert.rejects(f.open(), deny,
    "valid historical chain and matching signed high-water cannot permit an unapproved trigger");
  assert.equal(crypto.createHash("sha256")
    .update(fs.readFileSync(f.filename)).digest("hex"), before,
    "read-only startup refusal must not mutate the trusted SQLite main file");
  assert.equal(f.anchorHead.sequence, 1);
  assert.equal(f.effects.anchorAdvances, 1);
});

test("Sync v2 expiry immediately after the appended history scan denies external CAS advance", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  // The sixth physical lease probe is after tx.immediate() plus its O(N)
  // committed-history readback, before any off-host compareAndAdvance.
  f.effects.expireLeaseAtProbe = 6;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny);
  assert.equal(f.effects.leaseProbeCount, 6);
  assert.equal(f.effects.anchorAdvances, 0,
    "an expired physical fence cannot advance the independent high-water");
  assert.equal(f.anchorHead.sequence, 0);
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "a locally committed but externally ambiguous attempt must remain quarantined");
});

test("Sync v2 expiry after signed retained readback never acknowledges a committed pair", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  // The ninth probe follows the final complete local history audit after
  // the signed external readback, before clearing the uncertainty latch.
  f.effects.expireLeaseAtProbe = 9;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny);
  assert.equal(f.effects.leaseProbeCount, 9);
  assert.equal(f.effects.anchorAdvances, 1,
    "the external advance may already have happened; never claim rollback");
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny,
    "an expired fence cannot emit a positive current receipt");
});

test("Sync v2 rejects malformed current-head JSON with generic fail-closed error", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  await ledger.recordPhysicalPair(request(f));
  const tamper = new Database(f.filename, { fileMustExist: true });
  try {
    tamper.prepare(`UPDATE atomic_cas_head SET operation_ids=?
      WHERE scope=?`).run("{invalid_json", f.binding.scope);
  } finally { tamper.close(); }
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny,
    "corrupted head JSON cannot escape as raw SyntaxError or authorize current");
  f.close(ledger);
  await assert.rejects(f.open(), deny,
    "startup must reject the corrupted head before writable authority opening");
});

test("Sync v2 refuses early-returning physical fence instead of issuing a CAS ACK", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  f.effects.earlyFenceRelease = true;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "continuation must settle before provider releases the physical fence");
  assert.ok(f.effects.detachedSettled);
  await f.effects.detachedSettled;
  f.effects.earlyFenceRelease = false;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "settled detached continuation cannot clear the permanent denial latch");
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny);
});

test("Sync v2 rejects Promise adoption that releases a physical finally lock too early", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  f.effects.adoptedEarlyRelease = true;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "returning a continuation Promise does not keep an async finally lease held");
  f.effects.adoptedEarlyRelease = false;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "released lease must permanently poison the in-process signing authority");
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny);
});

test("Sync v2 denies delayed physical continuation after adapter returned and released queue", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  f.effects.lateFenceInvocation = true;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny);
  assert.equal(typeof f.effects.lateContinuation, "function");
  await assert.rejects(f.effects.lateContinuation(), deny,
    "a delayed valid signed receipt and positive lease probe must not bypass closed call");
  assert.equal(f.anchorHead.sequence, 0);
  assert.equal(f.effects.anchorAdvances, 0,
    "callback after return must not mutate external high-water");
  f.effects.lateFenceInvocation = false;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "early adapter return permanently latches this in-process authority");
});

test("Sync v2 rejects swallowed witness failure even if fence returns undefined", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  f.effects.badWitness = true;
  f.effects.swallowFenceError = true;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "failed continuation cannot be confused with a successful undefined result");
  f.effects.badWitness = false;
  f.effects.swallowFenceError = false;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "a provider that swallowed an authority failure must not later issue an ACK");
});

test("Sync v2 poisons the CAS authority when physical fence release fails after durable callback", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  f.effects.releaseFenceError = true;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "physical lease failure after CAS advance must not produce a success reply");
  f.effects.releaseFenceError = false;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "failure during physical-fence release must remain latched even after repair");
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny);
});

test("Sync v2 ambiguous durable external CAS advance latches fail-closed across restart", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  f.effects.refuseAnchor = true;
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny);
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "uncertain append must not retry from a speculative local head");
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny);
  f.close(ledger);
  await assert.rejects(f.open(), deny,
    "locally persisted head cannot be reopened against older retained anchor");
});

test("Sync v2 lost external CAS ACK only recovers after reopen and independently signed current floor", async (t) => {
  const f = fixture(t);
  const first = await f.open();
  f.effects.loseAnchorAck = true;
  await assert.rejects(first.recordPhysicalPair(request(f)), deny);
  assert.equal(f.anchorHead.sequence, 1,
    "external CAS advanced durably before the reply was lost");
  await assert.rejects(first.recordPhysicalPair(request(f)), deny,
    "uncertain live process must never retry based on local state alone");
  f.close(first);
  f.effects.loseAnchorAck = false;
  const recovered = await f.open();
  const floor = await recovered.recordPhysicalPair(request(f));
  assert.equal(floor.sequence, 1);
  assert.equal(floor.headHash, f.anchorHead.headHash);
  assert.equal(f.effects.anchorAdvances, 1,
    "recovery must not double-commit the externally durable high-water");
  verifyCurrentSignature(f, await recovered.freshCurrent(challenge(f)));
});

test("Sync v2 independent floor catches local SQLite rollback and refuses new signer identity", async (t) => {
  const f = fixture(t);
  let ledger = await f.open();
  await ledger.recordPhysicalPair(request(f));
  f.close(ledger);
  const backup = path.join(path.dirname(f.filename), "old-floor.db");
  fs.copyFileSync(f.filename, backup);
  if (process.platform !== "win32") fs.chmodSync(backup, 0o600);
  f.physical.commitId = crypto.randomUUID();
  f.physical.storeHeadSha256 = crypto.randomBytes(32).toString("hex");
  f.physical.fencingEpoch++;
  ledger = await f.open();
  await ledger.recordPhysicalPair(request(f));
  f.close(ledger);
  fs.copyFileSync(backup, f.filename);
  await assert.rejects(f.open(), deny,
    "external high-water survives local rollback and rejects an old valid SQLite file");
  await assert.rejects(Zk1SyncAtomicCasFloorLedgerDevOff.open({
    ...f.options, casPrivateKey: keys().privateKey,
  }), deny, "CAS signer identity cannot silently rotate while retaining prior floor");
});

test("Sync v2 concurrent lost-ACK retries serialize to a single durable physical floor", async (t) => {
  const f = fixture(t);
  const ledger = await f.open();
  const replies = await Promise.all(Array.from({ length: 12 },
    () => ledger.recordPhysicalPair(request(f))));
  assert.equal(f.effects.anchorAdvances, 1);
  assert.equal(f.anchorHead.sequence, 1);
  assert.equal(new Set(replies.map((reply) => reply.headHash)).size, 1);
  verifyCurrentSignature(f, await ledger.freshCurrent(challenge(f)));
});
