"use strict";

// This is a TEST-ONLY synthetic physical lease/proof. The production-shape
// adapter has NO signer and never turns PostgreSQL rows into physical ACKs.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const protocol = require("../sync-client/rootark-sync-protocol");
const { WITNESS_DOMAIN } = require("../src/services/zk1SyncAtomicCasFloorLedgerDevOff");
const { createZk1SyncAtomicPgPhysicalFenceDevOff } =
  require("../src/services/zk1SyncAtomicPgPhysicalFenceDevOff");

const DENIED = { code: "SYNC_ATOMIC_PG_FENCE_DEV_OFF_DENIED" };
const randomHash = () => crypto.randomBytes(32).toString("hex");
const nonce = () => crypto.randomBytes(32).toString("base64url");

test("DEV-OFF PG physical fence requires a separately signed witness AND exact read-only SQL pair", async (t) => {
  const previousEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = "test";
  t.after(() => {
    if (previousEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousEnv;
  });
  const signer = crypto.generateKeyPairSync("ed25519");
  const challenge = {
    scope: "alice:protected", accountId: crypto.randomUUID(), storeId: crypto.randomUUID(),
    username: "alice", compartmentId: "compartment-x", nonce: nonce(),
    operationIds: ["delete:reserved", "move:reserved"],
    envelopeDigests: [randomHash(), randomHash()], expectedPrevious: null,
  };
  const ownerBindings = [{ scope: challenge.scope, accountId: challenge.accountId,
    storeId: challenge.storeId, username: challenge.username,
    compartmentId: challenge.compartmentId }];
  const physical = {
    version: 2, scope: challenge.scope, accountId: challenge.accountId,
    storeId: challenge.storeId, username: challenge.username,
    compartmentId: challenge.compartmentId, nonce: challenge.nonce,
    operationIds: challenge.operationIds, envelopeDigests: challenge.envelopeDigests,
    commitId: crypto.randomUUID(), storeHeadSha256: randomHash(),
    fencingEpoch: 8, physicalDurable: true,
  };
  let mode = "valid";
  let held = true;
  let continued = 0;
  let observed = 0;
  const mockReadback = {
    async verifyCurrentSignedPair(input) {
      observed++;
      assert.deepEqual(input, { scope: challenge.scope,
        operationIds: challenge.operationIds,
        envelopeDigests: challenge.envelopeDigests });
      if (mode === "expired-after-read") held = false;
      return { scope: challenge.scope, commitId: mode === "wrong-sql-commit"
        ? crypto.randomUUID() : physical.commitId,
      head: mode === "wrong-sql-head" ? randomHash() : physical.storeHeadSha256,
      username: mode === "wrong-sql-user" ? "other-user" : challenge.username,
      compartmentId: mode === "wrong-sql-compartment" ? "other-compartment"
        : challenge.compartmentId,
      operationIds: challenge.operationIds, envelopeDigests: challenge.envelopeDigests,
      localPgRowsConsistent: mode !== "sql-unverified",
      witnessVerified: false, clientAckAuthorized: false };
    },
  };
  const externalPhysicalFence = {
    async withCurrentRead(input, continuation) {
      assert.deepEqual(input, challenge);
      const statement = { ...physical };
      if (mode === "wrong-nonce") statement.nonce = nonce();
      if (mode === "wrong-owner") statement.storeId = crypto.randomUUID();
      if (mode === "wrong-epoch") statement.fencingEpoch = 0;
      if (mode === "wrong-pair") statement.envelopeDigests = [randomHash(), randomHash()];
      const signature = crypto.sign(null, Buffer.from((mode === "invalid-signature"
        ? "unrelated-signature-domain\0" : WITNESS_DOMAIN)
        + protocol.canonicalJson(statement)), signer.privateKey).toString("base64url");
      return continuation({ receipt: { statement, signature }, lineage: null },
        { assertHeld: () => held });
    },
  };
  const options = { externalPhysicalFence, witnessPublicKey: signer.publicKey,
    ownerBindings,
    unsafeTestReadback: mockReadback };

  process.env.NODE_ENV = "production";
  assert.throws(() => createZk1SyncAtomicPgPhysicalFenceDevOff(options), DENIED,
    "synthetic SQL evidence may not be configured outside an explicit test runtime");
  process.env.NODE_ENV = "test";
  assert.throws(() => createZk1SyncAtomicPgPhysicalFenceDevOff({
    ...options, externalPhysicalFence: null }), DENIED,
  "a SQL observer never becomes its own physical witness");
  assert.throws(() => createZk1SyncAtomicPgPhysicalFenceDevOff({
    ...options, witnessPublicKey: crypto.generateKeyPairSync("ed25519").privateKey,
  }), DENIED);
  assert.throws(() => createZk1SyncAtomicPgPhysicalFenceDevOff({
    ...options, ownerBindings: [] }), DENIED,
  "operator identity bindings must be explicitly pinned");
  assert.throws(() => createZk1SyncAtomicPgPhysicalFenceDevOff({
    ...options, ownerBindings: [...ownerBindings, { ...ownerBindings[0] }] }),
  DENIED, "a duplicated scope cannot ambiguously select an independent owner");

  const adapter = createZk1SyncAtomicPgPhysicalFenceDevOff(options);
  for (const mismatch of [{ scope: "another:scope" },
    { accountId: crypto.randomUUID() }, { storeId: crypto.randomUUID() },
    { username: "another-user" }, { compartmentId: "another-compartment" }]) {
    await assert.rejects(adapter.withCurrentRead({ ...challenge, ...mismatch }, async () => {
      continued++;
    }), DENIED, "input-controlled owner identities cannot replace pinned operator values");
  }
  assert.equal(observed, 0,
    "wrong owner binding must be rejected before any physical/SQL verification");
  const detachedRoster = [{ ...ownerBindings[0] }];
  const immutablyPinned = createZk1SyncAtomicPgPhysicalFenceDevOff({
    ...options, ownerBindings: detachedRoster,
  });
  detachedRoster[0].storeId = crypto.randomUUID();
  assert.equal(await immutablyPinned.withCurrentRead(challenge,
    async () => "ORIGINAL_OWNER_STILL_PINNED"),
  "ORIGINAL_OWNER_STILL_PINNED",
  "mutating the source config after initialization cannot retarget the owner");
  assert.equal(observed, 1, "immutable roster admission exercised the actual readback");
  observed = 0; // isolate the original adapter's independent test counter
  assert.equal(await adapter.withCurrentRead(challenge, async (bundle, lease) => {
    continued++;
    assert.equal(lease.assertHeld(), true);
    assert.equal(bundle.receipt.statement.commitId, physical.commitId);
    assert.equal(bundle.receipt.statement.physicalDurable, true);
    return "accepted-test-only";
  }), "accepted-test-only");
  assert.equal(continued, 1);
  assert.equal(observed, 1);

  for (mode of ["wrong-nonce", "wrong-owner", "wrong-epoch", "wrong-pair",
    "invalid-signature", "wrong-sql-commit", "wrong-sql-head", "wrong-sql-user",
    "wrong-sql-compartment", "sql-unverified",
    "expired-after-read"]) {
    held = true;
    await assert.rejects(adapter.withCurrentRead(challenge, async () => {
      continued++;
      return "ILLEGAL_ACK";
    }), DENIED, `${mode} must fail closed without continuing to any CAS signer`);
    assert.equal(continued, 1);
  }

  // A broken physical provider may start a valid callback and return without
  // awaiting it. The late PostgreSQL readback MUST NOT enter continuation.
  held = true;
  let releaseSql;
  const pausedSql = new Promise((resolve) => { releaseSql = resolve; });
  let lateCallback;
  const lateAdapter = createZk1SyncAtomicPgPhysicalFenceDevOff({
    witnessPublicKey: signer.publicKey, ownerBindings,
    unsafeTestReadback: {
      async verifyCurrentSignedPair() {
        await pausedSql;
        return { scope: challenge.scope, commitId: physical.commitId,
          head: physical.storeHeadSha256,
          username: challenge.username, compartmentId: challenge.compartmentId,
          operationIds: challenge.operationIds,
          envelopeDigests: challenge.envelopeDigests,
          localPgRowsConsistent: true, witnessVerified: false,
          clientAckAuthorized: false };
      },
    },
    externalPhysicalFence: {
      async withCurrentRead(_request, callback) {
        const statement = { ...physical };
        const signature = crypto.sign(null, Buffer.from(WITNESS_DOMAIN
          + protocol.canonicalJson(statement)), signer.privateKey).toString("base64url");
        lateCallback = callback({ receipt: { statement, signature }, lineage: null },
          { assertHeld: () => true });
        return undefined; // deliberately drops the awaited continuation
      },
    },
  });
  await assert.rejects(lateAdapter.withCurrentRead(challenge, async () => {
    continued++;
    return "UNAUTHORIZED_LATE_CONTINUATION";
  }), DENIED);
  releaseSql();
  await assert.rejects(lateCallback, DENIED,
    "a detached callback may not enter a continuation after provider return");
  assert.equal(continued, 1);

  // A PostgreSQL pool acquisition can hang before statement_timeout applies.
  // Keep that unresolved request occupying its per-scope quota until it settles.
  let releasePending;
  const stalled = new Promise((resolve) => { releasePending = resolve; });
  const limited = createZk1SyncAtomicPgPhysicalFenceDevOff({
    witnessPublicKey: signer.publicKey, ownerBindings, readbackTimeoutMs: 100,
    operationTimeoutMs: 600,
    unsafeTestReadback: {
      async verifyCurrentSignedPair() {
        await stalled;
        return { scope: challenge.scope, username: challenge.username,
          compartmentId: challenge.compartmentId, commitId: physical.commitId,
          head: physical.storeHeadSha256, operationIds: challenge.operationIds,
          envelopeDigests: challenge.envelopeDigests,
          localPgRowsConsistent: true, witnessVerified: false,
          clientAckAuthorized: false };
      },
    },
    externalPhysicalFence: {
      async withCurrentRead(_request, callback) {
        const statement = { ...physical };
        const signature = crypto.sign(null, Buffer.from(WITNESS_DOMAIN
          + protocol.canonicalJson(statement)), signer.privateKey).toString("base64url");
        return callback({ receipt: { statement, signature }, lineage: null },
          { assertHeld: () => true });
      },
    },
  });
  await assert.rejects(limited.withCurrentRead(challenge, async () => {
    continued++;
    return "UNAUTHORIZED_STALLED_CONTINUATION";
  }), DENIED, "an unresolved PostgreSQL acquisition must have a finite deadline");
  await assert.rejects(limited.withCurrentRead(challenge, async () => {
    continued++;
  }), DENIED, "a timed-out unresolved SQL read still occupies its scope slot");
  releasePending();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(await limited.withCurrentRead(challenge, async (_bundle, lease) => {
    assert.equal(lease.assertHeld(), true);
    return "SETTLED_SQL_SLOT_RECOVERED";
  }), "SETTLED_SQL_SLOT_RECOVERED",
  "a real completed read releases its bounded pending scope slot");
  assert.equal(continued, 1);

  const signedBundle = () => ({ receipt: {
    statement: { ...physical },
    signature: crypto.sign(null, Buffer.from(WITNESS_DOMAIN
      + protocol.canonicalJson(physical)), signer.privateKey).toString("base64url"),
  }, lineage: null });
  mode = "wrong-sql-head";
  held = true;
  const swallowedSqlFailure = createZk1SyncAtomicPgPhysicalFenceDevOff({
    unsafeTestReadback: mockReadback, witnessPublicKey: signer.publicKey,
    ownerBindings,
    externalPhysicalFence: {
      async withCurrentRead(_request, callback) {
        try { await callback(signedBundle(), { assertHeld: () => true }); }
        catch { /* hostile provider swallows the failed SQL proof */ }
        return undefined;
      },
    },
  });
  await assert.rejects(swallowedSqlFailure.withCurrentRead(challenge, async () => {
    continued++;
    return "ILLEGAL_SQL_ACK";
  }), DENIED, "a swallowed callback exception and undefined result cannot count as success");
  assert.equal(continued, 1);

  const droppedCallback = createZk1SyncAtomicPgPhysicalFenceDevOff({
    unsafeTestReadback: mockReadback, witnessPublicKey: signer.publicKey,
    ownerBindings,
    externalPhysicalFence: {
      async withCurrentRead(_request, callback) {
        void callback(signedBundle(), { assertHeld: () => true });
        return undefined; // does not retain, await or catch the callback Promise
      },
    },
  });
  await assert.rejects(droppedCallback.withCurrentRead(challenge, async () => {
    continued++;
    return "DROPPED_CALLBACK_ACK";
  }), DENIED);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(continued, 1,
    "a discarded rejected callback must not succeed or become an unhandled rejection");

  mode = "valid";
  const swallowedFinalLease = createZk1SyncAtomicPgPhysicalFenceDevOff({
    unsafeTestReadback: mockReadback, witnessPublicKey: signer.publicKey,
    ownerBindings,
    externalPhysicalFence: {
      async withCurrentRead(_request, callback) {
        let checks = 0;
        try { await callback(signedBundle(), {
          // Valid through the continuation, expired at the final assertion.
          assertHeld: () => ++checks < 4,
        }); } catch { /* malicious provider suppresses expired lease */ }
        return "RETURNED_IGNORING_FAILED_FINAL_LEASE";
      },
    },
  });
  await assert.rejects(swallowedFinalLease.withCurrentRead(challenge, async () => {
    continued++;
    return "RETURNED_IGNORING_FAILED_FINAL_LEASE";
  }), DENIED, "an expired post-continuation lease cannot be disguised as a positive result");
  assert.equal(continued, 2, "the callback ran, but no successful result escaped the adapter");
});
