"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");

function queuedOperation(key, deviceId = "device-a") {
  return protocol.createOperation({ operation: "create", objectId: crypto.randomUUID(),
    deviceId, keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId }, metadata: { path: "queued.txt" },
    plaintext: Buffer.from("protected queued content"), fileKey: key });
}

async function fixture(t, adapter, currentDeviceAuthorization, options = {}) {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-sync-queued-revocation-"));
  t.after(() => fsp.rm(rootDir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const engine = await new SyncEngine({ rootDir, adapter: { list: async () => [], ...adapter },
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key, authorizeOutgoing: options.authorizeOutgoing,
    currentDeviceAuthorization, requireCurrentOutgoingAuthorization: true,
    maxRetries: 3 }).open();
  const operation = queuedOperation(key, options.queuedDeviceId);
  await engine.journal.enqueue(operation);
  return { engine, operation };
}

test("strict queued push requires an independently supplied current-device callback", () => {
  assert.throws(() => new SyncEngine({ adapter: { list: async () => [], push: async () => ({ status: 201 }) },
    requireCurrentOutgoingAuthorization: true }), { code: "authorization_required" });
});

test("queued ciphertext stays pending after current device revocation, then resumes only after authorization", async (t) => {
  let revoked = false;
  const calls = [];
  const { engine, operation } = await fixture(t, { push: async (op) => {
    calls.push(op.operationId);
    return { status: 201 };
  } }, (op) => !revoked && op.deviceId === "device-a");
  revoked = true;
  await assert.rejects(engine.pushPending({ pushed: 0, conflicts: [], offline: false }),
    { code: "authorization_rejected" });
  assert.deepEqual(calls, [], "previously signed local journal content cannot reach PUT after revocation");
  assert.deepEqual((await engine.journal.recover()).map((op) => op.operationId), [operation.operationId]);

  revoked = false;
  const summary = { pushed: 0, conflicts: [], offline: false };
  await engine.pushPending(summary);
  assert.equal(summary.pushed, 1);
  assert.deepEqual(calls, [operation.operationId]);
  assert.deepEqual(await engine.journal.recover(), []);
});

test("retry rechecks current authority after a failed PUT; stale first approval cannot authorize retry", async (t) => {
  let revoked = false;
  let checks = 0;
  let pushes = 0;
  const { engine, operation } = await fixture(t, { push: async () => {
    pushes += 1;
    revoked = true;
    throw Object.assign(new Error("network interrupted"), { code: "ECONNREFUSED" });
  } }, () => { checks += 1; return !revoked; });
  await assert.rejects(engine.pushPending({ pushed: 0, conflicts: [], offline: false }),
    { code: "authorization_rejected" });
  assert.equal(pushes, 1, "no second PUT after revocation");
  assert.equal(checks, 2, "the second attempt requires a fresh independent authorization");
  assert.deepEqual((await engine.journal.recover()).map((op) => op.operationId), [operation.operationId]);
});

test("revocation while the old authorization awaits is rejected immediately before PUT", async (t) => {
  let releaseInitialCheck;
  let initiated;
  const started = new Promise((resolve) => { initiated = resolve; });
  let revoked = false;
  let pushes = 0;
  const { engine } = await fixture(t, { push: async () => { pushes += 1; return { status: 201 }; } },
    () => !revoked, { authorizeOutgoing: async () => {
      initiated();
      await new Promise((resolve) => { releaseInitialCheck = resolve; });
      return true;
    } });
  const pending = engine.pushPending({ pushed: 0, conflicts: [], offline: false });
  await Promise.race([started, new Promise((_, reject) => setTimeout(() => reject(new Error("queued authorization was never rechecked")), 500))]);
  revoked = true;
  releaseInitialCheck();
  await assert.rejects(pending, { code: "authorization_rejected" });
  assert.equal(pushes, 0);
});

test("revocation during asynchronous Ed25519 signing denies pre-enqueue authorization", async (t) => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-sync-sign-revocation-"));
  t.after(() => fsp.rm(rootDir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  let releaseSigning;
  let startedSigning;
  const signingStarted = new Promise((resolve) => { startedSigning = resolve; });
  let revoked = false;
  let pushes = 0;
  const engine = await new SyncEngine({
    rootDir, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    adapter: { push: async () => { pushes += 1; return { status: 201 }; }, list: async () => [] },
    fileKeyResolver: () => key, requireCurrentOutgoingAuthorization: true,
    authorizeOutgoing: async () => true,
    currentDeviceAuthorization: () => !revoked,
    authorizationFactory: async (operation) => {
      startedSigning();
      await new Promise((resolve) => { releaseSigning = resolve; });
      return createAuthorizationProof(operation, { username: "alice", privateKey: keys.privateKey, publicKey });
    },
  }).open();
  const operation = engine.enqueueChange({ operation: "create", objectId: crypto.randomUUID(),
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "queued.txt" },
    plaintext: Buffer.from("local content"), fileKey: key });
  await Promise.race([signingStarted, new Promise((_, reject) => setTimeout(() => reject(new Error("signing not reached")), 500))]);
  revoked = true;
  releaseSigning();
  await assert.rejects(operation, { code: "authorization_rejected" });
  assert.deepEqual(await engine.journal.recover(), [], "signed post-revocation operation must not enter the journal");
  assert.equal(pushes, 0);
});

test("independent authorization failures stay closed, preserving journal and rejecting foreign queued device", async (t) => {
  let checks = 0;
  let pushes = 0;
  const { engine, operation } = await fixture(t, { push: async () => { pushes += 1; return { status: 201 }; } },
    () => { checks += 1; return undefined; });
  await assert.rejects(engine.pushPending({ pushed: 0, conflicts: [], offline: false }),
    { code: "authorization_rejected" });
  assert.equal(pushes, 0);
  assert.equal(checks, 1);
  assert.deepEqual((await engine.journal.recover()).map((op) => op.operationId), [operation.operationId]);

  const another = await fixture(t, { push: async () => { pushes += 1; return { status: 201 }; } },
    () => true, { queuedDeviceId: "foreign-device" });
  await assert.rejects(another.engine.pushPending({ pushed: 0, conflicts: [], offline: false }),
    { code: "authorization_rejected" });
  assert.equal(pushes, 0);
});

test("strict final live authorization and HTTP dispatch stay in one continuation across a queued microtask revocation", async (t) => {
  let revoked = false;
  let pushes = 0;
  let authorizedAtDispatch = false;
  const { engine, operation } = await fixture(t, { push: async () => {
    pushes += 1;
    authorizedAtDispatch = !revoked;
    return { status: 201 };
  } }, () => {
    const decision = !revoked;
    queueMicrotask(() => { revoked = true; });
    return decision;
  });
  const summary = { pushed: 0, conflicts: [], offline: false };
  await engine.pushPending(summary);
  assert.equal(pushes, 1);
  assert.equal(authorizedAtDispatch, true,
    "the synchronous push must begin before the callback-scheduled revocation microtask");
  assert.equal(revoked, true);
  assert.equal(summary.pushed, 1);
  assert.deepEqual(await engine.journal.recover(), []);
  assert.equal(operation.deviceId, "device-a");
});

test("strict final authorization rejects asynchronous callbacks without dispatching or dropping queued ciphertext", async (t) => {
  let pushes = 0;
  const { engine, operation } = await fixture(t, { push: async () => {
    pushes += 1;
    return { status: 201 };
  } }, async () => true);
  await assert.rejects(engine.pushPending({ pushed: 0, conflicts: [], offline: false }),
    { code: "authorization_required" });
  assert.equal(pushes, 0);
  assert.deepEqual((await engine.journal.recover()).map((op) => op.operationId), [operation.operationId]);
});

test("callback-thrown local authorization 409 cannot trigger remote-wins recovery or markSeen", async (t) => {
  let pushes = 0;
  const summary = { pushed: 0, conflicts: [], offline: false };
  const { engine, operation } = await fixture(t, { push: async () => {
    pushes += 1;
    return { status: 201 };
  } }, () => {
    throw Object.assign(new Error("local authorization revoked"),
      { code: "authorization_rejected", status: 409, currentRevision: "fabricated" });
  });
  await assert.rejects(engine.pushPending(summary), { code: "authorization_rejected" });
  assert.equal(pushes, 0, "the server never received a PUT");
  assert.deepEqual(summary, { pushed: 0, conflicts: [], offline: false },
    "no local 409 is allowed to masquerade as a remote conflict");
  assert.deepEqual((await engine.journal.recover()).map((op) => op.operationId), [operation.operationId]);
  assert.equal(engine.journal.hasSeen(operation.operationId), false);
  await assert.rejects(fsp.lstat(path.join(engine.rootDir, ".rootark-conflicts")), { code: "ENOENT" });
});

test("async legacy outgoing policy failures with forged HTTP conflicts do not consume the journal", async (t) => {
  let pushes = 0;
  const { engine, operation } = await fixture(t, { push: async () => {
    pushes += 1;
    return { status: 201 };
  } }, () => true, { authorizeOutgoing: async () => {
    throw Object.assign(new Error("locally denied"), { code: "sync_conflict", status: 409 });
  } });
  const summary = { pushed: 0, conflicts: [], offline: false };
  await assert.rejects(engine.pushPending(summary), { code: "authorization_rejected" });
  assert.equal(pushes, 0);
  assert.deepEqual(summary.conflicts, []);
  assert.equal(engine.journal.hasSeen(operation.operationId), false);
  assert.deepEqual((await engine.journal.recover()).map((op) => op.operationId), [operation.operationId]);
});

test("non-strict callers retain compatibility with asynchronous current authorization", async (t) => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-sync-legacy-async-policy-"));
  t.after(() => fsp.rm(rootDir, { recursive: true, force: true }));
  let pushes = 0;
  const engine = new SyncEngine({ rootDir,
    deviceId: "device-a", keyEpoch: "epoch-1",
    adapter: { push: async () => { pushes += 1; return { status: 201 }; }, list: async () => [] },
    currentDeviceAuthorization: async () => true });
  await engine.retryPush({ deviceId: "device-a" });
  assert.equal(pushes, 1);
});
