"use strict";

// Local Node22/WSL process gate closed; run this suite on hosted CI.
// RED integration contract: two real Ed25519-signed AES-GCM DELETE→MOVE
// envelopes require one batch transport and one fsynced local ACK, but ONLY
// after a separately signed, owner-pinned physical admission statement.
// The synthetic test witness models verification, NOT real remote fsync/CAS.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { DOMAIN: OWNER_PROVISION_DOMAIN } =
  require("../sync-client/rootark-sync-atomic-owner-provision");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const BYTES = Buffer.from("REAL_ENCRYPTED_MOVE_SOURCE_PAYLOAD_FOR_ATOMIC_QUEUE");
const TARGET = "destination.ct";
const SOURCE = "source.ct";
const DEVICE = "device-a";
const ACCOUNT_ID = "ca628a48-765e-4b0d-a746-3bc67d53e3b1";
const STORE_ID = "d95a7868-857c-4213-a5ad-3c10374b4fa7";
const OTHER_ACCOUNT_ID = "ffef1473-eb42-48a4-9c7e-2d9e7c458211";
const OTHER_STORE_ID = "ad112afc-ff8e-4803-9f5c-b517cc778588";
const sha256 = (input) => crypto.createHash("sha256").update(input).digest("hex");
const exact = (input) => JSON.parse(protocol.canonicalJson(input));
function assertSameSignedEnvelopes(actual, expected, message) {
  // Durable journal reloads turn the canonical null-prototype signed fields
  // into plain JSON objects. Equality of the entire canonical encoding still
  // checks every signed byte (including AAD, ciphertext and Ed25519 proof).
  assert.equal(protocol.canonicalJson(actual), protocol.canonicalJson(expected), message);
}

test("a CAS floor cannot impersonate the independent witness with the same Ed25519 key", () => {
  const key = crypto.generateKeyPairSync("ed25519").publicKey
    .export({ type: "spki", format: "der" });
  assert.throws(() => new SyncEngine({
    adapter: { push() {}, list() {} },
    atomicBatchWitnessPublicKey: key,
    atomicBatchCasFloorPublicKey: Buffer.from(key),
  }), { code: "authorization_required" });
});

async function snapshotPinnedJournal(filename, priorIdentity = null) {
  const handle = await fsp.open(filename,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const before = await handle.stat({ bigint: true });
    const namedBefore = await fsp.lstat(filename, { bigint: true });
    assert.equal(before.isFile(), true);
    assert.equal(before.nlink, 1n);
    for (const observed of [namedBefore]) {
      assert.equal(observed.isFile(), true);
      assert.equal(observed.dev, before.dev);
      assert.equal(observed.ino, before.ino);
      assert.equal(observed.nlink, before.nlink);
    }
    if (priorIdentity) {
      assert.equal(before.dev, priorIdentity.dev,
        "the poisoned journal must keep its original device");
      assert.equal(before.ino, priorIdentity.ino,
        "the poisoned journal must keep its original inode");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const namedAfter = await fsp.lstat(filename, { bigint: true });
    for (const observed of [after, namedAfter]) {
      assert.equal(observed.isFile(), true);
      assert.equal(observed.dev, before.dev);
      assert.equal(observed.ino, before.ino);
      assert.equal(observed.nlink, before.nlink);
      assert.equal(observed.size, BigInt(bytes.length));
    }
    assert.equal(before.size, after.size);
    return { bytes, identity: { dev: before.dev, ino: before.ino } };
  } finally {
    await handle.close();
  }
}

async function fixture(t, { batchResponse, witnessResponse, casResponse,
  missingCapability = false, interleaved = false,
  missingWitnessReadback = false, missingCasReadback = false,
  onWitnessChallenge = null,
  deleteExpiresInMs = 120000, filesOnDemand = false } = {}) {
  const root = createPrivateAuthorityFixture("cos-pr235-engine-batch-");
  t.after(async () => {
    await fsp.rm(root, { recursive: true, force: true, maxRetries: 5 });
  });
  const journalPath = path.join(root, "local-sync-journal.json");
  const snapshotPath = path.join(root, "snapshot.json");
  const fileKey = crypto.randomBytes(32);
  const signing = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const witnessPublicKey = witness.publicKey.export({ type: "spki", format: "der" });
  const casSigner = crypto.generateKeyPairSync("ed25519");
  const casPublicKey = casSigner.publicKey.export({ type: "spki", format: "der" });
  const ownerProvisioner = crypto.generateKeyPairSync("ed25519");
  const ownerStatement = { type: "atomic-owner-provisioning", version: 1,
    scope: "alice:store", sequence: 1,
    accountId: ACCOUNT_ID, storeId: STORE_ID, username: "alice",
    compartmentId: "private",
    witnessSpki: witnessPublicKey.toString("base64url"),
    casSpki: casPublicKey.toString("base64url") };
  const ownerProvisioning = { statement: ownerStatement,
    signature: crypto.sign(null, Buffer.from(OWNER_PROVISION_DOMAIN
      + protocol.canonicalJson(ownerStatement)), ownerProvisioner.privateKey)
      .toString("base64url") };
  const ownerProvisionDigest = sha256(OWNER_PROVISION_DOMAIN
    + protocol.canonicalJson(ownerProvisioning));
  const receiptFor = (pair, overrides = {}) => {
    const statement = {
      version: 2,
      scope: "alice:store",
      accountId: ACCOUNT_ID,
      storeId: STORE_ID,
      username: "alice",
      compartmentId: "private",
      nonce: overrides.nonce || crypto.randomBytes(32).toString("base64url"),
      operationIds: pair.map((entry) => entry.operationId),
      envelopeDigests: pair.map((entry) => sha256(protocol.canonicalJson(entry))),
      commitId: crypto.randomBytes(16).toString("base64url"),
      storeHeadSha256: sha256("synthetic-test-store-head"),
      fencingEpoch: 1,
      physicalDurable: true,
      ...overrides,
    };
    return { statement, signature: crypto.sign(null,
      Buffer.from("rootark-sync-atomic-batch-witness-v2\0"
        + protocol.canonicalJson(statement)), witness.privateKey).toString("base64url") };
  };
  const legacyReceiptFor = (pair, nonce, oldDomainWithV2Shape = false) => {
    const { statement } = receiptFor(pair, { nonce,
      ...(oldDomainWithV2Shape ? {} : { version: 1 }) });
    if (!oldDomainWithV2Shape) {
      for (const key of ["accountId", "storeId", "username", "compartmentId"]) {
        delete statement[key];
      }
    }
    return { statement, signature: crypto.sign(null,
      Buffer.from("rootark-sync-atomic-batch-witness-v1\0"
        + protocol.canonicalJson(statement)), witness.privateKey).toString("base64url") };
  };
  const casFloorFor = (receipt, nonce, overrides = {}) => {
    const statement = {
      version: 2,
      scope: "alice:store",
      accountId: ACCOUNT_ID,
      storeId: STORE_ID,
      nonce,
      commitId: receipt.statement.commitId,
      storeHeadSha256: receipt.statement.storeHeadSha256,
      fencingEpoch: receipt.statement.fencingEpoch,
      sequence: 1,
      current: true,
      ...overrides,
    };
    return { statement, signature: crypto.sign(null,
      Buffer.from("rootark-sync-atomic-batch-external-cas-floor-v2\0"
        + protocol.canonicalJson(statement)), casSigner.privateKey).toString("base64url") };
  };
  const legacyCasFloorFor = (receipt, nonce, oldDomainWithV2Shape = false) => {
    const { statement } = casFloorFor(receipt, nonce,
      oldDomainWithV2Shape ? {} : { version: 1 });
    if (!oldDomainWithV2Shape) {
      delete statement.accountId;
      delete statement.storeId;
    }
    return { statement, signature: crypto.sign(null,
      Buffer.from("rootark-sync-atomic-batch-external-cas-floor-v1\0"
        + protocol.canonicalJson(statement)), casSigner.privateKey).toString("base64url") };
  };
  const publicKey = signing.publicKey.export({ type: "spki", format: "der" })
    .toString("base64url");
  const eventId = crypto.randomUUID();
  const signed = async (verb, { operationId, target = TARGET, objectId,
    fileId, plaintext = BYTES } = {}) => {
    const operation = protocol.createOperation({
      operation: verb, operationId: operationId || crypto.randomUUID(),
      objectId: objectId || "object-" + verb,
      fileId: fileId || "file-" + verb,
      versionId: crypto.randomUUID(), deviceId: DEVICE,
      keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: 2, deviceId: DEVICE },
      baseRevision: { counter: 1, deviceId: DEVICE },
      metadata: { path: target, ...(verb === "move" ? { sourcePath: SOURCE }
        : verb === "create" ? { size: plaintext.length } : {}) },
      plaintext: verb === "move"
        ? protocol.encodeMovePayload(plaintext, fileKey)
        : verb === "delete" ? Buffer.from("{}") : plaintext,
      fileKey,
    });
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", privateKey: signing.privateKey, publicKey,
      expiresAt: Date.now() + (verb === "delete" ? deleteExpiresInMs : 120000),
    });
    assert.equal(await verifyAuthorizationProof(operation.authorization, operation, {
      username: "alice",
      trustedDevicePublicKeys: { [DEVICE]: publicKey },
      revokedDeviceIds: [],
    }), true, "real Ed25519 proof must verify independently of engine");
    return operation;
  };
  const deleted = await signed("delete", {
    operationId: "webdav-" + eventId + "-" + sha256("delete:" + TARGET).slice(0, 24),
    objectId: "displaced-target-object", fileId: "displaced-target-file",
  });
  const moved = await signed("move", {
    operationId: "webdav-" + eventId + "-" + sha256("move:" + TARGET).slice(0, 24),
    objectId: "original-source-object", fileId: "original-source-file",
  });
  assert.equal(deleted.metadata.path, moved.metadata.path);
  assert.notEqual(deleted.objectId, moved.objectId);
  assert.notEqual(deleted.fileId, moved.fileId);
  assert.notEqual(deleted.operationId, moved.operationId);
  assert.equal(deleted.authorization.deviceId, moved.authorization.deviceId);
  assert.deepEqual(protocol.decodeMovePayload(
    protocol.decryptPayload(moved, fileKey), fileKey), BYTES);
  const events = [];
  const push = async (operation) => {
    events.push({ kind: "single", operation: exact(operation) });
    return exact(operation);
  };
  const pushBatch = async (pair) => {
    events.push({ kind: "batch", pair: exact(pair) });
    assertSameSignedEnvelopes(pair, [deleted, moved],
      "actual transport must receive the exact signed DELETE then MOVE in order");
    return batchResponse ? batchResponse(pair, { signed, deleted, moved, receiptFor })
      : { objects: exact(pair) };
  };
  const adapter = { list: async () => ({ objects: [] }), push };
  if (!missingCapability) adapter.pushBatch = pushBatch;
  if (filesOnDemand) {
    // This test opens an isolated *real* FOD root but never uses unsigned
    // inventory as proof of historical batch admission.
    adapter.listInventory = async () => ({
      protocolVersion: 2, view: "metadata", objects: [], nextCursor: null,
    });
  }
  const journal = await new SyncJournal(journalPath).open();
  let lastWitnessReceipt;
  const engine = new SyncEngine({
    rootDir: root, snapshotPath, journal, adapter,
    filesOnDemand,
    deviceId: DEVICE, keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: async () => fileKey,
    requireAuthorization: true,
    requireCurrentOutgoingAuthorization: true,
    atomicBatchWitnessPublicKey: witnessPublicKey,
    atomicBatchWitnessScope: "alice:store",
    atomicBatchOwnerIdentity: { accountId: ACCOUNT_ID, storeId: STORE_ID,
      username: "alice", compartmentId: "private" },
    atomicBatchOwnerProvisionerPublicKey: ownerProvisioner.publicKey,
    atomicBatchOwnerProvisioning: ownerProvisioning,
    atomicBatchOwnerProvisionDigest: ownerProvisionDigest,
    atomicBatchWitnessReadback: missingWitnessReadback ? null : async (challenge) => {
      if (onWitnessChallenge) onWitnessChallenge(challenge);
      lastWitnessReceipt = witnessResponse
        ? witnessResponse(challenge, { deleted, moved, receiptFor, legacyReceiptFor })
        : receiptFor([deleted, moved], { nonce: challenge.nonce });
      return lastWitnessReceipt;
    },
    atomicBatchCasFloorPublicKey: casPublicKey,
    atomicBatchCasFloorReadback: missingCasReadback ? null : async (challenge) => casResponse
      ? casResponse(challenge, { deleted, moved, receiptFor, casFloorFor,
        legacyCasFloorFor, lastWitnessReceipt })
      : casFloorFor(lastWitnessReceipt, challenge.nonce),
    currentDeviceAuthorization: () => true,
    authorizeOutgoing: async () => true,
    authorize: async () => true,
    verifyIncoming: async (operation) => verifyAuthorizationProof(
      operation.authorization, operation, {
        username: "alice",
        trustedDevicePublicKeys: { [DEVICE]: publicKey },
        revokedDeviceIds: [],
      }),
    maxRetries: 1,
  });
  await engine.open();
  let unrelated = null;
  if (interleaved) {
    // Reusing an existing DELETE during enqueueMany appends MOVE after an
    // unrelated pending item. Adjacency-based batching would remote-push a
    // destructive DELETE alone and is therefore an intentionally RED case.
    unrelated = await signed("create", {
      operationId: "unrelated-" + crypto.randomUUID(),
      objectId: "unrelated-object", fileId: "unrelated-file",
      target: "unrelated.ct",
    });
    await journal.enqueue(deleted);
    await journal.enqueue(unrelated);
    await journal.enqueueMany([deleted, moved]);
  } else {
    await journal.enqueueMany([deleted, moved]); // actual disk+fsync commit
  }
  const fresh = await new SyncJournal(journalPath).open();
  assertSameSignedEnvelopes(await fresh.recover(), interleaved
    ? [deleted, unrelated, moved] : [deleted, moved],
    "two independently authenticated envelopes must both exist durably");
  assert.deepEqual(fresh.state.seen, []);
  assert.equal(events.length, 0);
  return {
    root, journalPath, journal, engine, events, deleted, moved, signed, unrelated,
    receiptFor, casFloorFor,
    adapter, summary: () => ({ pushed: 0, conflicts: [], offline: false }),
    async reread() { return new SyncJournal(journalPath).open(); },
    async assertBothPending() {
      const disk = await new SyncJournal(journalPath).open();
      assertSameSignedEnvelopes(await disk.recover(), [deleted, moved],
        "failed batch must retain BOTH exact signed envelopes");
      assert.equal(disk.hasSeen(deleted.operationId), false);
      assert.equal(disk.hasSeen(moved.operationId), false);
    },
  };
}

test("an async witness cannot repin the CAS signer, owner scope or readback callbacks", {
  timeout: 120000,
}, async (t) => {
  let attempts = 0;
  const f = await fixture(t, {
    onWitnessChallenge: (challenge) => {
      assert.equal(challenge.scope, "alice:store");
      for (const [field, replacement] of [
        ["atomicBatchCasFloorPublicKey", f.engine.atomicBatchWitnessPublicKey],
        ["atomicBatchWitnessPublicKey", f.engine.atomicBatchCasFloorPublicKey],
        ["atomicBatchWitnessScope", "mallory:store"],
        ["atomicBatchOwnerIdentity", { accountId: OTHER_ACCOUNT_ID,
          storeId: OTHER_STORE_ID, username: "mallory", compartmentId: "private" }],
        ["atomicBatchOwnerProvisionerPublicKey", f.engine.atomicBatchCasFloorPublicKey],
        ["atomicBatchWitnessReadback", async () => null],
        ["atomicBatchCasFloorReadback", async () => null],
      ]) {
        assert.throws(() => { f.engine[field] = replacement; }, TypeError,
          `${field} must remain nonwritable during awaited witness readback`);
        assert.throws(() => {
          Object.defineProperty(f.engine, field, { value: replacement });
        }, TypeError, `${field} must remain nonconfigurable`);
        attempts++;
      }
    },
  });
  await f.engine._pushPending(f.summary());
  assert.equal(attempts, 7);
  assert.equal(f.engine.atomicBatchWitnessScope, "alice:store");
  assert.deepEqual(await (await f.reread()).recover(), []);
});

test("signed pair plus separate pinned synthetic admission witness ACKs both in one transaction", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  const summary = f.summary();
  const originalMarkSeen = f.journal.markSeen.bind(f.journal);
  const originalMarkSeenMany = f.journal.markSeenMany.bind(f.journal);
  let forbiddenSingleAcks = 0;
  let atomicAckCommits = 0;
  f.journal.markSeen = async (...args) => {
    forbiddenSingleAcks++;
    throw Error("BATCH_MUST_NOT_MARK_ONE_SIDE");
  };
  f.journal.markSeenMany = async (entries) => {
    atomicAckCommits++;
    assert.deepEqual(entries.map((item) => item.operationId),
      [f.deleted.operationId, f.moved.operationId]);
    await f.assertBothPending();
    const result = await originalMarkSeenMany(entries);
    const after = await f.reread();
    assert.deepEqual(await after.recover(), [],
      "both entries must transition together in the one durable ACK commit");
    assert.equal(after.hasSeen(f.deleted.operationId), true);
    assert.equal(after.hasSeen(f.moved.operationId), true);
    return result;
  };
  try {
    await f.engine._pushPending(summary);
  } finally {
    f.journal.markSeen = originalMarkSeen;
    f.journal.markSeenMany = originalMarkSeenMany;
  }
  assert.deepEqual(f.events.map((item) => item.kind), ["batch"],
    "never remotely DELETE first, then MOVE in a separate request");
  assert.equal(forbiddenSingleAcks, 0, "must call journal.markSeenMany, never markSeen twice");
  assert.equal(atomicAckCommits, 1, "only one fsync-backed atomic acknowledgement is permitted");
  const disk = await f.reread();
  assert.deepEqual(await disk.recover(), []);
  assert.equal(disk.hasSeen(f.deleted.operationId), true);
  assert.equal(disk.hasSeen(f.moved.operationId), true);
  assert.deepEqual(new Set(disk.state.seen),
    new Set([f.deleted.operationId, f.moved.operationId]));
  assert.equal(summary.pushed, 2);
  assert.deepEqual(summary.conflicts, []);
});

test("issue 66 strict FOD: expired DELETE historical batch cannot release lock after real journal observation and EIO", {
  timeout: 120000,
}, async (t) => {
  // The fixture's signed synthetic witness is test-only; it does NOT grant
  // native RootSession or authenticate production root custody.
  const f = await fixture(t, { deleteExpiresInMs: 30000, filesOnDemand: true });
  const originalNow = Date.now;
  const originalObserve = f.journal.observeAdmission.bind(f.journal);
  let observed = false;
  f.journal.observeAdmission = async (...args) => {
    const result = await originalObserve(...args);
    observed = true;
    throw Object.assign(new Error("historical observed journal fsynced, then EIO"), { code: "EIO" });
  };
  try {
    Date.now = () => f.deleted.authorization.expiresAt + 1;
    assert.ok(Date.now() < f.moved.authorization.expiresAt,
      "MOVE remains fresh even when the DELETE has expired");
    await assert.rejects(f.engine.withMutationLock(() =>
      f.engine.pushAtomicSignedOverwritePair([f.deleted, f.moved], f.summary())),
    { code: "EIO" });
  } finally {
    Date.now = originalNow;
    f.journal.observeAdmission = originalObserve;
  }
  assert.equal(observed, true, "a real local journal commit must precede the injected EIO");
  assert.deepEqual(f.events, [], "historical admission cannot send a new remote POST");
  assert.equal(fs.existsSync(path.join(f.root, ".rootark-sync.lock")), true,
    "an indeterminate durable journal observation must retain the native-required root lock");
  await f.assertBothPending();
});

for (const mode of ["only-signed-echo", "forged-witness", "other-operation-witness",
  "other-account-witness", "other-immutable-account-id", "other-immutable-store-id",
  "other-username-witness", "other-compartment-witness", "legacy-v1-witness",
  "legacy-v1-domain-v2-witness",
  "wrong-envelope-digest", "not-physically-durable",
  "zero-fencing-epoch", "invalid-store-head",
  "missing-independent-readback", "replayed-old-witness-nonce",
  "witness-switching-nonce-getter"]) {
  test("no false durable batch ACK with " + mode, { timeout: 120000 }, async (t) => {
    const f = await fixture(t, {
      batchResponse: (pair) => ({ objects: exact(pair) }),
      missingWitnessReadback: mode === "missing-independent-readback",
      witnessResponse: (challenge, ctx) => {
        if (mode === "only-signed-echo") return null;
        if (mode === "other-operation-witness") return ctx.receiptFor(
          [ctx.deleted, ctx.moved], { nonce: challenge.nonce,
            operationIds: ["other-operation-id", ctx.moved.operationId] });
        if (mode === "other-account-witness") return ctx.receiptFor(
          [ctx.deleted, ctx.moved], { nonce: challenge.nonce, scope: "mallory:store" });
        if (mode === "other-immutable-account-id") return ctx.receiptFor(
          [ctx.deleted, ctx.moved], { nonce: challenge.nonce, accountId: OTHER_ACCOUNT_ID });
        if (mode === "other-immutable-store-id") return ctx.receiptFor(
          [ctx.deleted, ctx.moved], { nonce: challenge.nonce, storeId: OTHER_STORE_ID });
        if (mode === "other-username-witness") return ctx.receiptFor(
          [ctx.deleted, ctx.moved], { nonce: challenge.nonce, username: "mallory" });
        if (mode === "other-compartment-witness") return ctx.receiptFor(
          [ctx.deleted, ctx.moved], { nonce: challenge.nonce, compartmentId: "other" });
        if (mode === "legacy-v1-witness") return ctx.legacyReceiptFor(
          [ctx.deleted, ctx.moved], challenge.nonce);
        if (mode === "legacy-v1-domain-v2-witness") return ctx.legacyReceiptFor(
          [ctx.deleted, ctx.moved], challenge.nonce, true);
        // These statements carry a VALID signature by the pinned test key.
        // Signature validity alone must not authorize false physical or
        // mismatched signed-envelope claims.
        if (mode === "wrong-envelope-digest") return ctx.receiptFor(
          [ctx.deleted, ctx.moved], { nonce: challenge.nonce,
            envelopeDigests: ["0".repeat(64), challenge.envelopeDigests[1]] });
        if (mode === "not-physically-durable") return ctx.receiptFor(
          [ctx.deleted, ctx.moved], { nonce: challenge.nonce, physicalDurable: false });
        if (mode === "zero-fencing-epoch") return ctx.receiptFor(
          [ctx.deleted, ctx.moved], { nonce: challenge.nonce, fencingEpoch: 0 });
        if (mode === "invalid-store-head") return ctx.receiptFor(
          [ctx.deleted, ctx.moved], { nonce: challenge.nonce, storeHeadSha256: "0" });
        if (mode === "replayed-old-witness-nonce") return ctx.receiptFor(
          [ctx.deleted, ctx.moved], { nonce: crypto.randomBytes(32).toString("base64url") });
        if (mode === "witness-switching-nonce-getter") {
          const oldNonce = crypto.randomBytes(32).toString("base64url");
          const receipt = ctx.receiptFor([ctx.deleted, ctx.moved], { nonce: oldNonce });
          let reads = 0;
          Object.defineProperty(receipt.statement, "nonce", {
            enumerable: true,
            get: () => ++reads === 1 ? challenge.nonce : oldNonce,
          });
          return receipt;
        }
        const forged = ctx.receiptFor([ctx.deleted, ctx.moved], { nonce: challenge.nonce });
        forged.signature = Buffer.alloc(64, 42).toString("base64url");
        return forged;
      },
    });
    await assert.rejects(f.engine._pushPending(f.summary()),
      { code: mode === "missing-independent-readback"
        ? "sync_atomic_batch_unavailable" : "sync_atomic_batch_indeterminate" });
    assert.deepEqual(f.events.map((entry) => entry.kind),
      mode === "missing-independent-readback"
        ? [] : ["batch"]);
    await f.assertBothPending();
  });
}

for (const mode of ["missing-cas-readback", "missing-cas-floor",
  "forged-cas-floor", "cas-stale-current-head", "cas-wrong-commit",
  "cas-old-epoch", "cas-not-current", "cas-wrong-scope", "cas-replayed-nonce",
  "cas-other-immutable-account-id", "cas-other-immutable-store-id", "cas-legacy-v1",
  "cas-legacy-v1-domain-v2-shape",
  "cas-switching-head-getter"]) {
  test("no protected batch ACK without fresh independently signed CAS floor: " + mode,
    { timeout: 120000 }, async (t) => {
      const f = await fixture(t, {
        missingCasReadback: mode === "missing-cas-readback",
        casResponse: (challenge, { casFloorFor, legacyCasFloorFor, lastWitnessReceipt }) => {
          assert.ok(lastWitnessReceipt, "CAS readback must follow signed witness verification");
          assert.notEqual(challenge.nonce, lastWitnessReceipt.statement.nonce,
            "CAS current-head challenge must not reuse witness challenge");
          if (mode === "missing-cas-floor") return null;
          const changes = {
            "cas-stale-current-head": { storeHeadSha256: sha256("new-latest-head") },
            "cas-wrong-commit": { commitId: "different-commit-123456789" },
            "cas-old-epoch": { fencingEpoch: lastWitnessReceipt.statement.fencingEpoch + 1 },
            "cas-not-current": { current: false },
            "cas-wrong-scope": { scope: "mallory:store" },
            "cas-replayed-nonce": { nonce: crypto.randomBytes(32).toString("base64url") },
            "cas-other-immutable-account-id": { accountId: OTHER_ACCOUNT_ID },
            "cas-other-immutable-store-id": { storeId: OTHER_STORE_ID },
          };
          if (mode === "cas-legacy-v1") return legacyCasFloorFor(
            lastWitnessReceipt, challenge.nonce);
          if (mode === "cas-legacy-v1-domain-v2-shape") return legacyCasFloorFor(
            lastWitnessReceipt, challenge.nonce, true);
          const result = casFloorFor(lastWitnessReceipt, challenge.nonce,
            changes[mode] || {});
          if (mode === "forged-cas-floor") {
            result.signature = Buffer.alloc(64, 55).toString("base64url");
          }
          if (mode === "cas-switching-head-getter") {
            const staleHead = sha256("stale-signed-cas-head");
            const signedForOldHead = casFloorFor(lastWitnessReceipt, challenge.nonce,
              { storeHeadSha256: staleHead });
            let reads = 0;
            Object.defineProperty(signedForOldHead.statement, "storeHeadSha256", {
              enumerable: true,
              get: () => ++reads === 1
                ? lastWitnessReceipt.statement.storeHeadSha256 : staleHead,
            });
            return signedForOldHead;
          }
          return result;
        },
      });
      await assert.rejects(f.engine._pushPending(f.summary()), {
        code: mode.startsWith("missing-cas-") && mode !== "missing-cas-floor"
          ? "sync_atomic_batch_unavailable" : "sync_atomic_batch_indeterminate",
      });
      assert.deepEqual(f.events.map((event) => event.kind),
        mode === "missing-cas-readback" ? [] : ["batch"]);
      await f.assertBothPending();
    });
}

test("interleaved signed DELETE and MOVE still use exactly ONE remote batch, never individual DELETE", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t, { interleaved: true });
  const disk = await f.reread();
  assert.deepEqual(disk.atomicSignedGroups(), {
    [f.deleted.operationId.slice(7, -25)]: {
      deleteId: f.deleted.operationId, moveId: f.moved.operationId,
    },
  }, "durable group membership must survive independent disk reopen");
  await f.engine._pushPending(f.summary());
  assert.deepEqual(f.events.map((entry) => entry.kind), ["batch", "single"],
    "the existing unrelated CREATE is independent, DELETE and MOVE never are");
  assert.equal(f.events[1].operation.operationId, f.unrelated.operationId);
  const after = await f.reread();
  assert.deepEqual(after.pending(), []);
  assert.deepEqual(after.atomicSignedGroups(), {});
  assert.equal(after.hasSeen(f.deleted.operationId), true);
  assert.equal(after.hasSeen(f.moved.operationId), true);
});

test("direct pullRemote with only one member of pending signed pair fails BEFORE applying or ACKing either", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  let listCalled = 0;
  f.adapter.list = async () => { listCalled++; return { objects: [f.deleted] }; };
  await assert.rejects(f.engine.pullRemote(f.summary()),
    { code: "sync_atomic_batch_indeterminate" });
  assert.equal(listCalled, 0, "partial remote LIST cannot be consulted while pair awaits resolution");
  assert.equal(f.events.length, 0);
  await f.assertBothPending();
});

test("409 followed by fake LIST echo of both signed envelopes NEVER fabricates atomic remote admission", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t, {
    batchResponse: () => { throw Object.assign(new Error("replayed batch"),
      { status: 409, code: "sync_conflict" }); },
    // A server-only echo is not a signed independent physical witness.
    witnessResponse: () => null,
  });
  let readbacks = 0;
  f.adapter.list = async () => {
    readbacks++;
    return { objects: [f.deleted, f.moved] };
  };
  await assert.rejects(f.engine._pushPending(f.summary()),
    { code: "sync_atomic_batch_indeterminate" });
  assert.equal(readbacks, 0,
    "the server may echo old signed bytes in LIST without ever committing them");
  assert.deepEqual(f.events.map((entry) => entry.kind), ["batch"]);
  await f.assertBothPending();
});

test("409 with only one exact remote member retains BOTH signed pending envelopes", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t, {
    batchResponse: () => { throw Object.assign(new Error("batch rejected"),
      { status: 409, code: "sync_conflict" }); },
    witnessResponse: () => null,
  });
  f.adapter.list = async () => ({ objects: [f.deleted] });
  await assert.rejects(f.engine._pushPending(f.summary()),
    { code: "sync_atomic_batch_indeterminate" });
  assert.deepEqual(f.events.map((entry) => entry.kind), ["batch"]);
  await f.assertBothPending();
});

test("lost HTTP ACK then 409 can recover ONLY through fresh independent signed batch readback", {
  timeout: 120000,
}, async (t) => {
  // The signed fixture models a trusted independent physical readback, not
  // real remote storage. The server's POST response is deliberately absent.
  let challenged = 0;
  const f = await fixture(t, {
    batchResponse: () => { throw Object.assign(new Error("already committed"),
      { status: 409, code: "sync_conflict" }); },
    onWitnessChallenge: (challenge) => {
      challenged++;
      assert.deepEqual(challenge.operationIds,
        [f.deleted.operationId, f.moved.operationId]);
    },
  });
  const summary = f.summary();
  await f.engine._pushPending(summary);
  assert.equal(challenged, 1, "409 requires ONE fresh direct witness challenge");
  assert.deepEqual(f.events.map((event) => event.kind), ["batch"]);
  assert.equal(summary.pushed, 2);
  assert.equal(summary.offline, false);
  const disk = await f.reread();
  assert.deepEqual(await disk.recover(), []);
  assert.equal(disk.hasSeen(f.deleted.operationId), true);
  assert.equal(disk.hasSeen(f.moved.operationId), true);
});

test("lost network ACK with missing independent witness remains offline and BOTH pending", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t, {
    batchResponse: () => { throw Object.assign(new Error("connection lost"),
      { code: "ETIMEDOUT" }); },
    witnessResponse: () => null,
  });
  const summary = f.summary();
  await f.engine._pushPending(summary);
  assert.equal(summary.offline, true);
  assert.equal(summary.pushed, 0);
  assert.deepEqual(f.events.map((entry) => entry.kind), ["batch"]);
  await f.assertBothPending();
});

test("expired already-admitted signed pair is readback-only: never POST or re-sign", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  const expiresAt = Math.min(f.deleted.authorization.expiresAt,
    f.moved.authorization.expiresAt);
  const realNow = Date.now;
  f.engine.adapter.pushBatch = () => { throw new Error("EXPIRED_MUST_NEVER_POST"); };
  try {
    // Simulate recovery after the original, genuinely signed pair expires.
    // The journal's original Ed25519 bytes are not rewritten or re-signed.
    Date.now = () => expiresAt + 1;
    const summary = f.summary();
    await f.engine._pushPending(summary);
    assert.equal(summary.pushed, 2);
    assert.equal(summary.offline, false);
  } finally { Date.now = realNow; }
  assert.equal(f.events.length, 0, "historical confirmation cannot issue POST");
  const disk = await f.reread();
  assert.deepEqual(await disk.recover(), []);
  assert.equal(disk.hasSeen(f.deleted.operationId), true);
  assert.equal(disk.hasSeen(f.moved.operationId), true);
});

test("revoked signed pair can verify historical receipt but cannot issue another write", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  f.engine.currentDeviceAuthorization = () => false;
  f.engine.adapter.pushBatch = () => { throw new Error("REVOKED_MUST_NEVER_POST"); };
  const summary = f.summary();
  await f.engine._pushPending(summary);
  assert.equal(summary.pushed, 2);
  assert.equal(f.events.length, 0);
  assert.deepEqual((await f.reread()).pending(), []);
});

test("historical batch readback survives revoked file-key access and rotated epoch", {
  timeout: 120000,
}, async (t) => {
  for (const condition of ["revoked-file-key", "rotated-epoch"]) {
    await t.test(condition, async (innerT) => {
      const f = await fixture(innerT);
      f.engine.currentDeviceAuthorization = () => false;
      f.engine.adapter.pushBatch = () => { throw new Error("HISTORICAL_MUST_NEVER_POST"); };
      if (condition === "revoked-file-key") f.engine.authorize = async () => false;
      else f.engine.keyEpoch = "epoch-rotated";
      const summary = f.summary();
      await f.engine._pushPending(summary);
      assert.equal(summary.pushed, 2);
      assert.equal(f.events.length, 0);
      const disk = await f.reread();
      assert.deepEqual(disk.pending(), []);
      assert.equal(disk.hasSeen(f.deleted.operationId), true);
      assert.equal(disk.hasSeen(f.moved.operationId), true);
      assert.equal(f.engine.snapshot.files[f.moved.metadata.path].hash || null, null,
        "historical ACK without current key must never fabricate plaintext hash");
    });
  }
});

test("remote device revocation 403 after lost ACK needs independent historical witness", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t, {
    batchResponse: () => { throw Object.assign(new Error("device revoked on remote"),
      { status: 403, code: "remote_forbidden" }); },
  });
  const summary = f.summary();
  await f.engine._pushPending(summary);
  assert.equal(summary.pushed, 2);
  assert.deepEqual(f.events.map((entry) => entry.kind), ["batch"]);
  assert.deepEqual((await f.reread()).pending(), []);
});

test("revoked or expired batch WITHOUT physical witness retains both original pending operations", {
  timeout: 120000,
}, async (t) => {
  for (const condition of ["revoked", "expired"]) {
    await t.test(condition, async (innerT) => {
      const f = await fixture(innerT, { witnessResponse: () => null });
      const realNow = Date.now;
      f.engine.adapter.pushBatch = () => { throw new Error("UNAUTHORIZED_POST"); };
      try {
        if (condition === "revoked") f.engine.currentDeviceAuthorization = () => false;
        else Date.now = () => f.deleted.authorization.expiresAt + 1;
        await assert.rejects(f.engine._pushPending(f.summary()),
          { code: "sync_atomic_batch_indeterminate" });
      } finally { Date.now = realNow; }
      assert.equal(f.events.length, 0);
      await f.assertBothPending();
    });
  }
});

for (const condition of ["expired DELETE", "revoked DELETE"]) {
  test("delayed MOVE authorization cannot dispatch batch after " + condition, {
    timeout: 120000,
  }, async (t) => {
    const f = await fixture(t, {
      deleteExpiresInMs: 30000,
      witnessResponse: () => null,
    });
    const realNow = Date.now;
    let moveAuthChecks = 0;
    f.engine.authorizeOutgoing = async (operation) => {
      if (operation.operation === "move") {
        moveAuthChecks++;
        // Change the first member's authority AFTER its awaited local check,
        // but BEFORE the MOVE's final synchronous network dispatch gate.
        if (condition === "expired DELETE") {
          Date.now = () => f.deleted.authorization.expiresAt + 1;
          assert.ok(Date.now() < f.moved.authorization.expiresAt,
            "MOVE remains fresh while DELETE alone has expired");
        } else {
          f.engine.currentDeviceAuthorization = (member) => member.operation !== "delete";
        }
      }
      return true;
    };
    try {
      await assert.rejects(f.engine._pushPending(f.summary()),
        { code: "sync_atomic_batch_indeterminate" });
    } finally { Date.now = realNow; }
    assert.equal(moveAuthChecks, 1,
      "adversarial change must occur inside the second asynchronous authorization");
    assert.equal(f.events.length, 0,
      "do not dispatch either denied DELETE or otherwise-fresh MOVE to the network");
    await f.assertBothPending();
  });
}

test("independently signed standalone WebDAV DELETE uses distinct cryptographic ID namespace and one ordinary push", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  await f.journal.markSeenMany([
    { operationId: f.deleted.operationId }, { operationId: f.moved.operationId },
  ]);
  const eventId = crypto.randomUUID();
  const pathname = "solo-target.ct";
  const signed = await f.signed("delete", {
    operationId: "webdavsolo-" + eventId + "-" + sha256("delete:" + pathname).slice(0, 24),
    target: pathname, objectId: "solo-object", fileId: "solo-file",
  });
  await f.journal.enqueue(signed);
  const outbox = await f.reread();
  assert.deepEqual(outbox.atomicSignedGroups(), {},
    "standalone DELETE must never forge a DELETE+MOVE pair witness");
  await f.engine._pushPending(f.summary());
  assert.deepEqual(f.events.map((entry) => entry.kind), ["single"]);
  assert.equal(f.events[0].operation.operationId, signed.operationId);
  assert.equal((await f.reread()).hasSeen(signed.operationId), true);
});

test("legacy signed WebDAV DELETE orphan after local journal group deletion must NEVER be pushed alone", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  const disk = JSON.parse(await fsp.readFile(f.journalPath, "utf8"));
  assert.ok(Object.keys(disk.atomicSignedGroups).length === 1,
    "positive control must begin with a real fsynced two-entry group");
  // Simulate an adversary/old buggy recovery that strips the MOVE and its
  // group manifest, but leaves the exact genuine Ed25519 DELETE envelope.
  // This is never a legitimate standalone delete: its signed ID still uses
  // the atomic overwrite namespace, not `webdavsolo-`.
  disk.pending = disk.pending.filter((item) => item.operationId === f.deleted.operationId);
  delete disk.committedSigned[f.moved.operationId];
  delete disk.atomicSignedGroups;
  const bytes = Buffer.from(JSON.stringify(disk) + "\n");
  const handle = await fsp.open(f.journalPath, "r+");
  try {
    await handle.truncate(0);
    await handle.writeFile(bytes);
    await handle.sync();
  } finally { await handle.close(); }
  const evidence = await snapshotPinnedJournal(f.journalPath);
  assert.deepEqual(evidence.bytes, bytes,
    "the forged orphan DELETE must be persisted in the original journal inode");
  f.engine.journal = await new SyncJournal(f.journalPath).open();
  assertSameSignedEnvelopes(f.engine.journal.pending(), [f.deleted]);
  await assert.rejects(f.engine._pushPending(f.summary()),
    { code: "sync_atomic_batch_indeterminate" });
  assert.equal(f.events.length, 0, "orphaned DELETE may not reach adapter.push");
  assert.deepEqual((await snapshotPinnedJournal(
    f.journalPath, evidence.identity)).bytes, bytes,
    "fail closed with original suspicious evidence preserved on disk");
});

test("legacy signed WebDAV MOVE orphan after missing DELETE and group must NEVER be pushed alone", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  const disk = JSON.parse(await fsp.readFile(f.journalPath, "utf8"));
  disk.pending = disk.pending.filter((item) => item.operationId === f.moved.operationId);
  delete disk.committedSigned[f.deleted.operationId];
  delete disk.atomicSignedGroups;
  const bytes = Buffer.from(JSON.stringify(disk) + "\n");
  const handle = await fsp.open(f.journalPath, "r+");
  try { await handle.truncate(0); await handle.writeFile(bytes); await handle.sync(); }
  finally { await handle.close(); }
  const evidence = await snapshotPinnedJournal(f.journalPath);
  assert.deepEqual(evidence.bytes, bytes,
    "the forged orphan MOVE must be persisted in the original journal inode");
  f.engine.journal = await new SyncJournal(f.journalPath).open();
  assertSameSignedEnvelopes(f.engine.journal.pending(), [f.moved]);
  await assert.rejects(f.engine._pushPending(f.summary()),
    { code: "sync_atomic_batch_indeterminate" });
  assert.equal(f.events.length, 0, "orphaned MOVE cannot be dispatched without old-target tombstone");
  assert.deepEqual((await snapshotPinnedJournal(
    f.journalPath, evidence.identity)).bytes, bytes);
});

test("new authenticated webdavsolo MOVE remains a legal standalone non-overwrite sync operation", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  await f.journal.markSeenMany([
    { operationId: f.deleted.operationId }, { operationId: f.moved.operationId },
  ]);
  const eventId = crypto.randomUUID();
  const target = "solo-move.ct";
  const signed = await f.signed("move", {
    operationId: "webdavsolo-" + eventId + "-" + sha256("move:" + target).slice(0, 24),
    target, objectId: "solo-moved-object", fileId: "solo-moved-file",
  });
  await f.journal.enqueue(signed);
  assert.deepEqual((await f.reread()).atomicSignedGroups(), {});
  await f.engine._pushPending(f.summary());
  assert.deepEqual(f.events.map((item) => item.kind), ["single"]);
  assert.equal(f.events[0].operation.operationId, signed.operationId);
  assert.equal((await f.reread()).hasSeen(signed.operationId), true);
});

test("journal-only renaming of a signed atomic DELETE into webdavsolo cannot forge a standalone authorization", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  await f.journal.markSeenMany([
    { operationId: f.deleted.operationId }, { operationId: f.moved.operationId },
  ]);
  const forged = { ...f.deleted,
    operationId: f.deleted.operationId.replace(/^webdav-/, "webdavsolo-") };
  assert.notEqual(forged.operationId, f.deleted.operationId);
  assert.equal(forged.authorization.operationId, f.deleted.operationId,
    "attacker cannot replace the original independent Ed25519 signature");
  await f.journal.enqueue(forged);
  const before = await fsp.readFile(f.journalPath);
  await assert.rejects(f.engine._pushPending(f.summary()),
    /Authorization envelope binding mismatch|device authorization|Invalid/);
  assert.equal(f.events.length, 0,
    "tampered local-only namespace must fail before any remote single DELETE");
  assert.deepEqual(await fsp.readFile(f.journalPath), before);
});

test("missing pushBatch capability fails closed: never downgrade paired DELETE→MOVE to split push", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t, { missingCapability: true });
  await assert.rejects(f.engine._pushPending(f.summary()));
  assert.equal(f.events.length, 0,
    "not even the first DELETE may be transmitted without batch capability");
  await f.assertBothPending();
});

for (const corruption of ["second-signed-echo-differs", "wrong-companion-operation"]) {
  test("a single successful-looking batch response with " + corruption +
    " may NEVER ACK either local entry", { timeout: 120000 }, async (t) => {
    const f = await fixture(t, {
      batchResponse: async (pair, ctx) => {
        if (corruption === "second-signed-echo-differs") {
          // Same ID, valid separately signed Ed25519 envelope for different
          // bytes. ID-only checks are provably insufficient.
          const changed = await ctx.signed("move", {
            operationId: ctx.moved.operationId,
            objectId: ctx.moved.objectId, fileId: ctx.moved.fileId,
            plaintext: Buffer.from("ATTACKER_DIFFERENT_SIGNED_MOVE_BYTES"),
          });
          assert.notEqual(changed.authorization.signature,
            ctx.moved.authorization.signature);
          return { objects: [exact(ctx.deleted), changed] };
        }
        const outsider = await ctx.signed("delete", {
          operationId: crypto.randomUUID(),
          objectId: "wrong-companion", fileId: "wrong-companion-file",
          target: TARGET,
        });
        return { objects: [outsider, exact(ctx.moved)] };
      },
    });
    await assert.rejects(f.engine._pushPending(f.summary()),
      "success status is not permission to mark both when one echo differs");
    assert.deepEqual(f.events.map((event) => event.kind), ["batch"],
      "must reach the actual batch callback before rejecting forged ACK");
    await f.assertBothPending();
  });
}

test("transient network failure during batch retains both durable entries and never starts individual push", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t, {
    batchResponse: () => {
      throw Object.assign(Error("simulated network disconnect after batch attempt"),
        { code: "ETIMEDOUT" });
    },
    witnessResponse: () => null,
  });
  const summary = f.summary();
  await f.engine._pushPending(summary);
  assert.equal(summary.offline, true);
  assert.equal(summary.pushed, 0);
  assert.deepEqual(f.events.map((item) => item.kind), ["batch"]);
  await f.assertBothPending();
});

test("unrelated signed standalone create still takes ONE ordinary push, not pushBatch", {
  timeout: 120000,
}, async (t) => {
  const f = await fixture(t);
  // Remove only this private fixture's initial pair with a real atomic
  // journal transition; then independently enqueue a standalone signed file.
  await f.journal.markSeenMany([
    { operationId: f.deleted.operationId },
    { operationId: f.moved.operationId },
  ]);
  const standalone = await f.signed("create", {
    operationId: "independent-" + crypto.randomUUID(),
    target: "independent.ct",
    objectId: "independent-object", fileId: "independent-file",
  });
  await f.journal.enqueue(standalone);
  const summary = f.summary();
  await f.engine._pushPending(summary);
  assert.deepEqual(f.events.map((item) => item.kind), ["single"]);
  assert.equal(f.events[0].operation.operationId, standalone.operationId);
  const disk = await f.reread();
  assert.deepEqual(await disk.recover(), []);
  assert.equal(disk.hasSeen(standalone.operationId), true);
  assert.equal(summary.pushed, 1);
});
