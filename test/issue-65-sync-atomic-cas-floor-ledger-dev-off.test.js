"use strict";

// Genuine SQLite WAL/FULL durability semantics, real Ed25519 signatures and
// adversarial reopens. The off-host physical fence and retained anchor here
// are deliberately synthetic: these tests DO NOT prove physical independence.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
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
  const effects = { badWitness: false, badLineage: false,
    badAnchor: false, refuseAnchor: false, loseAnchorAck: false,
    earlyFenceRelease: false, adoptedEarlyRelease: false,
    swallowFenceError: false, releaseFenceError: false,
    withLease: 0, signedPhysical: 0, anchorAdvances: 0,
    pausedAtLease: null, detachedSettled: null };
  const previouslyWitnessed = new Set();
  const physicalFence = {
    withCurrentRead: async (challenge, continuation) => {
      effects.withLease++;
      if (effects.pausedAtLease) await effects.pausedAtLease;
      let held = true;
      const lease = { assertHeld: () => held };
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
      const lineage = changed && !previouslyWitnessed.has(physicalId)
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
  Object.assign(f.physical, { ...old, fencingEpoch: f.physical.fencingEpoch + 1 });
  await assert.rejects(ledger.recordPhysicalPair(request(f)), deny,
    "previous physical head cannot be freshly signed into a new CAS sequence");
  Object.assign(f.physical, old);
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny,
    "rolled-back physical witness current cannot sign the newer head");
  f.anchorHead.sequence = 1;
  f.anchorHead.headHash = crypto.randomBytes(32).toString("hex");
  await assert.rejects(ledger.freshCurrent(challenge(f)), deny,
    "signed externally rolled-back/altered floor cannot authorize readback");
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
