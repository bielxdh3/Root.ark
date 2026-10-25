"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createOperation, validateOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof,
  verifyHistoricalAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");
const { SyncObjectStore } = require("../src/routes/sync");
const { attestCiphertextOnlyRecords } = require("../src/services/deploymentResilience");

test("expired historical device proof remains readable but cannot authorize a new write", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-historical-sync-auth-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, "sync.json");
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = createOperation({ operation: "create", objectId: "historical-object",
    fileId: "historical-file", versionId: "historical-version", operationId: "historical-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "historical.txt" },
    plaintext: Buffer.from("ciphertext-only"), fileKey: crypto.randomBytes(32) });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: keys.privateKey, publicKey, expiresAt: Date.now() + 5000,
  });
  assert.equal(validateOperation(operation).operationId, operation.operationId);
  const store = await new SyncObjectStore(file).open();
  assert.equal((await store.put("alice", operation)).kind, "stored");
  const now = Date.now;
  try {
    Date.now = () => operation.authorization.expiresAt + 1;
    assert.throws(() => validateOperation(operation), { code: "authorization_expired" });
    const reopened = await new SyncObjectStore(file).open();
    assert.equal(reopened.list("alice").length, 1);
    assert.equal(reopened.list("alice")[0].authorization.signature,
      operation.authorization.signature);
    assert.throws(() => attestCiphertextOnlyRecords([{ ...operation,
      authorization: { ...operation.authorization, signature: "not*base64url" },
    }]), { code: "SYNC_ATTESTATION_FAILED" });
  } finally { Date.now = now; }
});

test("expired signed remote record pulls after restart but revocation and forgery stay denied", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-historical-pull-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = createOperation({ operation: "create", objectId: "historical-pull-object",
    fileId: "historical-pull-file", versionId: "historical-pull-version", operationId: "historical-pull-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "historical-pull.txt" },
    plaintext: Buffer.from("historical bytes"), fileKey: key });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: keys.privateKey, publicKey, expiresAt: Date.now() + 5000,
  });
  const expected = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  const adapter = { async push() { throw Error("unexpected push"); }, async list() { return [operation]; } };
  const now = Date.now;
  try {
    Date.now = () => operation.authorization.expiresAt + 1;
    await assert.rejects(verifyAuthorizationProof(operation.authorization, operation, expected),
      { code: "authorization_expired" });
    const engine = await new SyncEngine({ rootDir: directory, adapter, deviceId: "device-b",
      keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key,
      requireAuthorization: true,
      verifyIncoming: (remote) => verifyHistoricalAuthorizationProof(remote.authorization, remote, expected),
    }).open();
    const summary = { pulled: 0, conflicts: [], offline: false };
    await engine.pullRemote(summary);
    assert.equal(summary.pulled, 1);
    assert.equal(await fs.readFile(path.join(directory, "historical-pull.txt"), "utf8"), "historical bytes");
    const restarted = await new SyncEngine({ rootDir: directory, adapter, deviceId: "device-b",
      keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key,
      requireAuthorization: true,
      verifyIncoming: (remote) => verifyHistoricalAuthorizationProof(remote.authorization, remote, expected),
    }).open();
    assert.equal((await restarted.journal.recover()).length, 0);
    await assert.rejects(verifyHistoricalAuthorizationProof(operation.authorization, operation,
      { ...expected, revokedDeviceIds: ["device-a"] }), { code: "authorization_device_revoked" });
    await assert.rejects(verifyHistoricalAuthorizationProof(operation.authorization,
      { ...operation, metadata: { ...operation.metadata, path: "forged.txt" } }, expected),
    { code: "authorization_scope" });
    await assert.rejects(verifyHistoricalAuthorizationProof(
      { ...operation.authorization, expiresAt: 0 }, operation, expected),
    { code: "invalid_device_authorization" });
    await assert.rejects(verifyHistoricalAuthorizationProof(
      { ...operation.authorization, expiresAt: String(operation.authorization.expiresAt) }, operation, expected),
    { code: "invalid_device_authorization" });
  } finally { Date.now = now; }
});

test("HTTP sync LIST parses expired stored ciphertext without permitting expired POST", async () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = createOperation({ operation: "create", objectId: "http-history",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "old/remote.txt" }, plaintext: Buffer.from("opaque"),
    fileKey: crypto.randomBytes(32) });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: keys.privateKey, publicKey,
    expiresAt: Date.now() + 1000 });
  const requests = [];
  const adapter = createOpaqueSyncAdapter({
    baseUrl: "https://disposable.invalid",
    fetchImpl: async (_url, options) => {
      requests.push(options);
      return { ok: true, status: 200,
        async json() { return options.method === "POST"
          ? operation : { objects: [operation] }; } };
    },
  });
  const now = Date.now;
  try {
    Date.now = () => operation.authorization.expiresAt + 1;
    const listing = await adapter.list();
    assert.equal(listing.objects.length, 1);
    assert.equal(listing.objects[0].authorization.signature,
      operation.authorization.signature);
    assert.equal(await verifyHistoricalAuthorizationProof(operation.authorization,
      listing.objects[0], { username: "alice",
        trustedDevicePublicKeys: { "device-a": publicKey },
        revokedDeviceIds: [] }), true);
    assert.throws(() => adapter.push(operation), /Expired device authorization/);
    assert.equal(requests.length, 1,
      "expired POST must fail locally without contacting the remote store");
  } finally { Date.now = now; }
});

test("an expired remote record needs an exact durable local observation from before expiry", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-local-admission-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = createOperation({ operation: "create",
    objectId: "verified-historical-object", fileId: "verified-historical-file",
    versionId: "verified-historical-version", operationId: "verified-historical-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "already-verified.txt" }, plaintext: Buffer.from("ciphers only"), fileKey: key });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: signer.privateKey, publicKey,
    expiresAt: Date.now() + 1000,
  });
  const expected = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  let remote = operation;
  const adapter = { async push() { throw Error("unexpected push"); },
    async list() { return [remote]; } };
  const verifyIncoming = async (incoming, state = {}) => {
    if (!incoming.authorization) return false;
    if (incoming.authorization.expiresAt <= Date.now() && state.locallyAdmitted !== true) {
      return false;
    }
    return incoming.authorization.expiresAt > Date.now()
      ? verifyAuthorizationProof(incoming.authorization, incoming, expected)
      : verifyHistoricalAuthorizationProof(incoming.authorization, incoming, expected);
  };
  const makeEngine = () => new SyncEngine({ rootDir: directory,
    adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    requireAuthorization: true, verifyIncoming }).open();
  const now = Date.now;
  try {
    Date.now = () => operation.authorization.expiresAt + 1;
    const unknown = await makeEngine();
    await assert.rejects(unknown.pullRemote({ pulled: 0, conflicts: [], offline: false }),
      { code: "remote_authorization_rejected" },
      "an independently signed but first-ever stale operation lacks admission evidence");
    assert.equal(unknown.journal.hasSeen(operation.operationId), false);
    Date.now = () => operation.authorization.expiresAt - 1;
    const fresh = await makeEngine();
    const summary = { pulled: 0, conflicts: [], offline: false };
    await fresh.pullRemote(summary);
    assert.equal(summary.pulled, 1);
    assert.equal(await fs.readFile(path.join(directory, "already-verified.txt"), "utf8"),
      "ciphers only");
    Date.now = () => operation.authorization.expiresAt + 1;
    const restarted = await makeEngine();
    await restarted.verifyIncomingOperation(operation);
    const alternative = createOperation({ operation: "create",
      objectId: operation.objectId, fileId: operation.fileId,
      versionId: operation.versionId, operationId: operation.operationId,
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: 1, deviceId: "device-a" },
      metadata: { path: "another-valid-signature.txt" },
      plaintext: Buffer.from("new content"), fileKey: key });
    Date.now = () => operation.authorization.expiresAt - 1;
    alternative.authorization = await createAuthorizationProof(alternative, {
      username: "alice", privateKey: signer.privateKey, publicKey,
      expiresAt: operation.authorization.expiresAt,
    });
    Date.now = () => operation.authorization.expiresAt + 1;
    await assert.rejects(restarted.verifyIncomingOperation(alternative),
      { code: "remote_authorization_rejected" },
      "matching operation IDs never substitute for byte-identical local admission");
    expected.revokedDeviceIds = ["device-a"];
    await assert.rejects(restarted.verifyIncomingOperation(operation),
      { code: "authorization_device_revoked" },
      "an exact local pin never bypasses current revocation");
  } finally { Date.now = now; }
});

test("crossing expiry during an authenticated pull preserves its already-verified exact pin", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-auth-cross-expiry-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = createOperation({ operation: "create",
    objectId: "cross-expiry-object", operationId: "cross-expiry-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "cross-expiry.txt" }, plaintext: Buffer.from("ok"), fileKey: key });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: signer.privateKey, publicKey,
    expiresAt: Date.now() + 1000 });
  const expected = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  let expireOnVerify = true;
  const adapter = { async push() { throw Error("unexpected push"); },
    async list() { return [operation]; } };
  const verifier = async (incoming, { locallyAdmitted = false } = {}) => {
    const result = locallyAdmitted
      ? await verifyHistoricalAuthorizationProof(incoming.authorization, incoming, expected)
      : await verifyAuthorizationProof(incoming.authorization, incoming, expected);
    if (expireOnVerify) {
      expireOnVerify = false;
      Date.now = () => operation.authorization.expiresAt + 1;
    }
    return result;
  };
  const createEngine = () => new SyncEngine({ rootDir: dir, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key, requireAuthorization: true,
    verifyIncoming: verifier }).open();
  const originalNow = Date.now;
  try {
    Date.now = () => operation.authorization.expiresAt - 1;
    const first = await createEngine();
    await first.pullRemote({ pulled: 0, conflicts: [], offline: false });
    const restarted = await createEngine();
    assert.equal(await restarted.verifyIncomingOperation(operation),
      crypto.createHash("sha256").update(require("../sync-client/rootark-sync-protocol")
        .canonicalJson(operation)).digest("hex"),
      "a verified pre-expiry operation remains authenticated after expiry");
    assert.equal(restarted.journal.hasLocalAdmission(operation.operationId,
      crypto.createHash("sha256").update(require("../sync-client/rootark-sync-protocol")
        .canonicalJson(operation)).digest("hex")), true);
  } finally { Date.now = originalNow; }
});

test("a successful own signed push pins only the exact server-echoed envelope", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-own-outgoing-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = createOperation({ operation: "create",
    objectId: "own-upload-object", operationId: "own-upload-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "own-upload.txt" }, plaintext: Buffer.from("own"), fileKey: key });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: signer.privateKey, publicKey,
    expiresAt: Date.now() + 1000 });
  const expected = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  const adapter = { async push(incoming) { return { ...incoming }; },
    async list() { return [operation]; } };
  const config = { rootDir: root, adapter, keyEpoch: "epoch-1", compartmentId: "private",
    deviceId: "device-a", fileKeyResolver: () => key, requireAuthorization: true,
    authorizationFactory: async () => operation.authorization,
    verifyIncoming: (incoming, { locallyAdmitted = false } = {}) =>
      locallyAdmitted
        ? verifyHistoricalAuthorizationProof(incoming.authorization, incoming, expected)
        : verifyAuthorizationProof(incoming.authorization, incoming, expected) };
  const originalNow = Date.now;
  try {
    Date.now = () => operation.authorization.expiresAt - 1;
    const first = await new SyncEngine(config).open();
    await first.journal.enqueue(operation);
    const summary = { pushed: 0, conflicts: [], offline: false };
    await first.pushPending(summary);
    assert.equal(summary.pushed, 1);
    Date.now = () => operation.authorization.expiresAt + 1;
    const restarted = await new SyncEngine(config).open();
    await restarted.verifyIncomingOperation(operation);
    assert.equal(restarted.journal.hasSeen(operation.operationId), true);
    Date.now = () => operation.authorization.expiresAt - 1;
    const unconfirmedRoot = path.join(root, "unconfirmed-ack");
    adapter.push = async () => ({
      ...operation,
      metadata: { ...operation.metadata, path: "mismatched-ack.txt" },
    });
    const unconfirmed = await new SyncEngine({ ...config,
      rootDir: unconfirmedRoot }).open();
    await unconfirmed.journal.enqueue(operation);
    await unconfirmed.pushPending({ pushed: 0, conflicts: [], offline: false });
    assert.equal(unconfirmed.journal.hasSeen(operation.operationId), true);
    Date.now = () => operation.authorization.expiresAt + 1;
    const unconfirmedRestarted = await new SyncEngine({ ...config,
      rootDir: unconfirmedRoot }).open();
    await assert.rejects(unconfirmedRestarted.verifyIncomingOperation(operation),
      { code: "authorization_expired" },
      "a successful HTTP response with a forged or mismatched echo is not an authenticated local pin");
  } finally { Date.now = originalNow; }
});

test("same-ID signed envelope collision is rejected before remote-only snapshot changes", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-remote-collision-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const build = async (name, content = name) => {
    const operation = createOperation({ operation: "create", objectId: "collision-object",
      operationId: "collision-id", deviceId: "device-a", keyEpoch: "epoch-1",
      compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
      metadata: { path: name }, plaintext: Buffer.from(content), fileKey: key });
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", privateKey: signer.privateKey, publicKey,
      expiresAt: Date.now() + 60000 });
    return operation;
  };
  const first = await build("first.txt");
  const second = await build("second.txt");
  const expected = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  let current = first;
  const adapter = { async list() { return Array.isArray(current) ? current : [current]; },
    async push() { throw Error("unexpected push"); } };
  const make = (selectedPaths) => new SyncEngine({ rootDir: directory, adapter,
    selectedPaths, deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key, requireAuthorization: true,
    verifyIncoming: (incoming) => verifyAuthorizationProof(incoming.authorization, incoming, expected),
  }).open();
  const engine = await make([]);
  await engine.pullRemote({ pulled: 0, conflicts: [], offline: false });
  assert.equal(engine.snapshot.remoteOnly[first.objectId].path, "first.txt");
  current = second;
  await assert.rejects(engine.pullRemote({ pulled: 0, conflicts: [], offline: false }),
    /Conflicting local sync admission evidence/);
  const restarted = await make([]);
  assert.equal(restarted.snapshot.remoteOnly[first.objectId].path, "first.txt",
    "a rejected collision cannot persist an alternative remote-only path");
  assert.equal((await fs.readdir(directory)).includes("second.txt"), false);
  const batchDir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-batch-collision-"));
  t.after(() => fs.rm(batchDir, { recursive: true, force: true }));
  current = [first, second];
  const batch = await new SyncEngine({ rootDir: batchDir, adapter,
    selectedPaths: [], deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key, requireAuthorization: true,
    verifyIncoming: (incoming) => verifyAuthorizationProof(incoming.authorization, incoming, expected),
  }).open();
  await assert.rejects(batch.pullRemote({ pulled: 0, conflicts: [], offline: false }),
    /Conflicting local sync admission evidence/);
  const batchRestarted = await new SyncEngine({ rootDir: batchDir, adapter,
    selectedPaths: [], deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key, requireAuthorization: true,
    verifyIncoming: (incoming) => verifyAuthorizationProof(incoming.authorization, incoming, expected),
  }).open();
  assert.equal(Object.keys(batchRestarted.snapshot.remoteOnly).length, 0,
    "contradictory records in a single response cannot mutate a durable snapshot");
  const pendingDir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-pull-pending-collision-"));
  t.after(() => fs.rm(pendingDir, { recursive: true, force: true }));
  current = second;
  const pendingEngine = await new SyncEngine({ rootDir: pendingDir, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key, requireAuthorization: true,
    verifyIncoming: (incoming) => verifyAuthorizationProof(incoming.authorization, incoming, expected),
  }).open();
  await pendingEngine.journal.enqueue(first);
  await assert.rejects(pendingEngine.pullRemote({ pulled: 0, conflicts: [], offline: false }),
    /Conflicting local sync admission evidence/);
  assert.deepEqual((await pendingEngine.journal.recover()).map((item) => item.operationId),
    [first.operationId], "normal LIST cannot consume another signed pending envelope");
  assert.equal((await fs.readdir(pendingDir)).includes("second.txt"), false);
  const hydrated = await make(null);
  current = await build("first.txt", "attacker replacement");
  await assert.rejects(hydrated.materializeRemote("first.txt"),
    /Conflicting local sync admission evidence/);
  assert.equal((await fs.readdir(directory)).includes("first.txt"), false,
    "a collision must not materialize any files before rejecting");
  current = first;
  await hydrated.materializeRemote("first.txt");
  assert.equal(await fs.readFile(path.join(directory, "first.txt"), "utf8"), "first.txt");
  current = await build("first.txt", "attacker replacement");
  await assert.rejects(hydrated.apply(current), /Conflicting local sync admission evidence/);
  assert.equal(await fs.readFile(path.join(directory, "first.txt"), "utf8"), "first.txt",
    "a rejected collision cannot replace an already materialized local file");
});

test("large excluded ciphertext inventory flushes durable admissions in bounded batches", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-batched-excluded-admission-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operations = [];
  for (let index = 0; index < 132; index += 1) {
    const operation = createOperation({ operation: "create", objectId: `batch-object-${index}`,
      operationId: `batch-op-${index}`, deviceId: "device-a", keyEpoch: "epoch-1",
      compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
      metadata: { path: `remote-${index}.txt` }, plaintext: Buffer.from(`${index}`), fileKey: key });
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", privateKey: signer.privateKey, publicKey,
      expiresAt: Date.now() + 60000 });
    operations.push(operation);
  }
  const expected = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  const config = { rootDir: directory, selectedPaths: [], deviceId: "device-b",
    keyEpoch: "epoch-1", compartmentId: "private", requireAuthorization: true,
    fileKeyResolver: () => key,
    adapter: { async list() { return operations; }, async push() { throw Error("unexpected push"); } },
    verifyIncoming: (incoming, { locallyAdmitted = false } = {}) => locallyAdmitted
      ? verifyHistoricalAuthorizationProof(incoming.authorization, incoming, expected)
      : verifyAuthorizationProof(incoming.authorization, incoming, expected),
  };
  const engine = await new SyncEngine(config).open();
  let snapshotFlushes = 0;
  const originalPersist = engine.persistSnapshot.bind(engine);
  engine.persistSnapshot = async () => { snapshotFlushes += 1; return originalPersist(); };
  await engine.pullRemote({ pulled: 0, conflicts: [], offline: false });
  assert.equal(snapshotFlushes >= 2, true,
    "the observed map must not grow for the entire unbounded server inventory");
  const restarted = await new SyncEngine(config).open();
  assert.equal(Object.keys(restarted.snapshot.remoteOnly).length, operations.length);
  assert.equal(Object.keys(restarted.journal.state.observed).length, 0);
  for (const operation of operations) {
    assert.equal(restarted.journal.hasSeen(operation.operationId), true);
  }
});

test("incoming signed envelope cannot change during asynchronous key resolution", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-mutated-inflight-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const build = async (name) => {
    const item = createOperation({ operation: "create", objectId: "inflight-object",
      operationId: "inflight-id", deviceId: "device-a", keyEpoch: "epoch-1",
      compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
      metadata: { path: name }, plaintext: Buffer.from(name), fileKey: key });
    item.authorization = await createAuthorizationProof(item, {
      username: "alice", privateKey: signer.privateKey, publicKey,
      expiresAt: Date.now() + 60000 });
    return item;
  };
  const original = await build("signed-original.txt");
  const replacement = await build("unsigned-after-check.txt");
  const expected = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  const engine = await new SyncEngine({ rootDir: directory, deviceId: "device-b",
    keyEpoch: "epoch-1", compartmentId: "private", requireAuthorization: true,
    adapter: { async list() { return []; }, async push() { throw Error("unexpected push"); } },
    verifyIncoming: (incoming) => verifyAuthorizationProof(incoming.authorization, incoming, expected),
    fileKeyResolver: async () => {
      Object.assign(original, replacement);
      return key;
    },
  }).open();
  await engine.apply(original);
  assert.equal(await fs.readFile(path.join(directory, "signed-original.txt"), "utf8"),
    "signed-original.txt");
  assert.equal((await fs.readdir(directory)).includes("unsigned-after-check.txt"), false,
    "mutating an external operation during async key resolution cannot change the applied envelope");
});

test("a verified remote conflict winner is pinned after durable materialization", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-remote-conflict-pin-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const build = async (deviceId, operationId, content, filePath = "conflict.txt") => {
    const item = createOperation({ operation: "create", objectId: "conflict-object",
      operationId, deviceId, keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: 1, deviceId }, metadata: { path: filePath },
      plaintext: Buffer.from(content), fileKey: key });
    item.authorization = await createAuthorizationProof(item, {
      username: "alice", privateKey: signer.privateKey, publicKey,
      expiresAt: Date.now() + 1000 });
    return item;
  };
  const local = await build("device-a", "local-conflict-op", "local");
  const remote = await build("device-b", "remote-conflict-op", "remote");
  const remoteExcluded = await build("device-b", "remote-excluded-conflict-op", "remote-only", "remote-only.txt");
  const sameIdRemote = await build("device-b", local.operationId, "same-ID replacement");
  const otherPending = await build("device-a", "other-pending-op", "B_LOCAL", "other.txt");
  const otherRemote = await build("device-b", otherPending.operationId, "B_REMOTE", "other.txt");
  const expected = { username: "alice", trustedDevicePublicKeys: {
    "device-a": publicKey, "device-b": publicKey }, revokedDeviceIds: [] };
  let remoteCurrent = remote;
  const adapter = { async push() { return { status: 409, current: remoteCurrent }; },
    async list() { return [remoteCurrent]; } };
  const make = (rootDir = directory, selectedPaths = null) => new SyncEngine({ rootDir, adapter, selectedPaths,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key, requireAuthorization: true,
    verifyIncoming: (item, { locallyAdmitted = false } = {}) => locallyAdmitted
      ? verifyHistoricalAuthorizationProof(item.authorization, item, expected)
      : verifyAuthorizationProof(item.authorization, item, expected),
  }).open();
  const now = Date.now;
  try {
    Date.now = () => Math.min(local.authorization.expiresAt, remote.authorization.expiresAt) - 1;
    const engine = await make();
    await engine.journal.enqueue(local);
    const summary = { pushed: 0, conflicts: [], offline: false };
    await engine.pushPending(summary);
    assert.equal(summary.conflicts.length, 1);
    assert.equal(await fs.readFile(path.join(directory, "conflict.txt"), "utf8"), "remote");
    assert.equal(engine.journal.hasSeen(remote.operationId), true);
    Date.now = () => remote.authorization.expiresAt + 1;
    const restarted = await make();
    await restarted.verifyIncomingOperation(remote);
    const excludedRoot = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-excluded-conflict-pin-"));
    t.after(() => fs.rm(excludedRoot, { recursive: true, force: true }));
    remoteCurrent = remoteExcluded;
    Date.now = () => Math.min(local.authorization.expiresAt, remoteExcluded.authorization.expiresAt) - 1;
    const excluded = await make(excludedRoot, ["conflict.txt"]);
    await excluded.journal.enqueue(local);
    await excluded.pushPending({ pushed: 0, conflicts: [], offline: false });
    assert.equal(excluded.snapshot.remoteOnly[remoteExcluded.objectId].path, "remote-only.txt");
    assert.equal((await fs.readdir(excludedRoot)).includes("remote-only.txt"), false);
    Date.now = () => remoteExcluded.authorization.expiresAt + 1;
    const excludedRestarted = await make(excludedRoot, ["conflict.txt"]);
    await excludedRestarted.verifyIncomingOperation(remoteExcluded);
    const collisionRoot = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-local-pending-collision-"));
    t.after(() => fs.rm(collisionRoot, { recursive: true, force: true }));
    remoteCurrent = sameIdRemote;
    Date.now = () => Math.min(local.authorization.expiresAt, sameIdRemote.authorization.expiresAt) - 1;
    const collision = await make(collisionRoot);
    await collision.journal.enqueue(local);
    await assert.rejects(collision.pushPending({ pushed: 0, conflicts: [], offline: false }),
      /Conflicting local sync admission evidence/);
    assert.equal((await fs.readdir(collisionRoot)).includes("conflict.txt"), false,
      "a different signed remote envelope cannot reuse a pending local operation ID");
    assert.equal(collision.journal.hasSeen(local.operationId), false);
    const multiPendingRoot = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-other-pending-collision-"));
    t.after(() => fs.rm(multiPendingRoot, { recursive: true, force: true }));
    remoteCurrent = otherRemote;
    Date.now = () => Math.min(local.authorization.expiresAt,
      otherPending.authorization.expiresAt, otherRemote.authorization.expiresAt) - 1;
    const multiPending = await make(multiPendingRoot);
    await multiPending.journal.enqueue(local);
    await multiPending.journal.enqueue(otherPending);
    await assert.rejects(multiPending.pushPending({ pushed: 0, conflicts: [], offline: false }),
      /Conflicting local sync admission evidence/);
    assert.deepEqual((await multiPending.journal.recover()).map((item) => item.operationId),
      [local.operationId, otherPending.operationId],
      "a conflict winner must not delete another queued signed operation sharing its ID");
    assert.equal((await fs.readdir(multiPendingRoot)).includes("other.txt"), false);
  } finally { Date.now = now; }
});

test("verified pre-expiry observation survives final journal write failure after filesystem materialization", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-preobserved-failure-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = createOperation({ operation: "create", objectId: "preobserve-object",
    operationId: "preobserve-id", deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "preobserved.txt" }, plaintext: Buffer.from("verified"), fileKey: key });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: signer.privateKey, publicKey,
    expiresAt: Date.now() + 1000 });
  const expected = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  const make = () => new SyncEngine({ rootDir: directory, deviceId: "device-b",
    keyEpoch: "epoch-1", compartmentId: "private", requireAuthorization: true,
    adapter: { async list() { return [operation]; }, async push() { throw Error("unexpected push"); } },
    fileKeyResolver: () => key,
    verifyIncoming: (incoming, { locallyAdmitted = false } = {}) => locallyAdmitted
      ? verifyHistoricalAuthorizationProof(incoming.authorization, incoming, expected)
      : verifyAuthorizationProof(incoming.authorization, incoming, expected),
  }).open();
  const now = Date.now;
  try {
    Date.now = () => operation.authorization.expiresAt - 1;
    const engine = await make();
    const actualObserve = engine.journal.observeAdmission.bind(engine.journal);
    engine.journal.observeAdmission = async () => { throw Object.assign(new Error("pre-observation full disk"),
      { code: "ENOSPC" }); };
    await assert.rejects(engine.pullRemote({ pulled: 0, conflicts: [], offline: false }),
      { code: "ENOSPC" });
    assert.equal((await fs.readdir(directory)).includes("preobserved.txt"), false,
      "failed pre-observation must reject before writing any local content");
    engine.journal.observeAdmission = actualObserve;
    engine.journal.markSeen = async () => { throw Object.assign(new Error("simulated full disk"),
      { code: "ENOSPC" }); };
    await assert.rejects(engine.pullRemote({ pulled: 0, conflicts: [], offline: false }),
      { code: "ENOSPC" });
    assert.equal(await fs.readFile(path.join(directory, "preobserved.txt"), "utf8"), "verified");
    Date.now = () => operation.authorization.expiresAt + 1;
    const restarted = await make();
    await restarted.verifyIncomingOperation(operation);
    await restarted.pullRemote({ pulled: 0, conflicts: [], offline: false });
    assert.equal(restarted.journal.hasSeen(operation.operationId), true);
    assert.equal(Object.hasOwn(restarted.journal.state.observed, operation.operationId), false,
      "historical replay consumes the prior observation rather than exhausting the durable pre-observation budget");
  } finally { Date.now = now; }
});

test("denied local authorization and invalid AEAD never become historical admission evidence", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-no-unauthorized-preobserve-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = createOperation({ operation: "create", objectId: "denied-object",
    operationId: "denied-id", deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "denied.txt" }, plaintext: Buffer.from("not-yet-authorized"), fileKey: key });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: signer.privateKey, publicKey,
    expiresAt: Date.now() + 1000 });
  const expected = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  let locallyAllowed = false;
  let correctKey = true;
  const make = () => new SyncEngine({ rootDir: directory, deviceId: "device-b",
    keyEpoch: "epoch-1", compartmentId: "private", requireAuthorization: true,
    adapter: { async list() { return [operation]; }, async push() { throw Error("unexpected push"); } },
    authorize: async () => locallyAllowed,
    fileKeyResolver: () => correctKey ? key : crypto.randomBytes(32),
    verifyIncoming: (incoming, { locallyAdmitted = false } = {}) => locallyAdmitted
      ? verifyHistoricalAuthorizationProof(incoming.authorization, incoming, expected)
      : verifyAuthorizationProof(incoming.authorization, incoming, expected),
  }).open();
  const now = Date.now;
  try {
    Date.now = () => operation.authorization.expiresAt - 1;
    const denied = await make();
    await assert.rejects(denied.pullRemote({ pulled: 0, conflicts: [], offline: false }),
      { code: "authorization_rejected" });
    assert.equal(Object.keys(denied.journal.state.observed).length, 0);
    locallyAllowed = true;
    correctKey = false;
    await assert.rejects(denied.pullRemote({ pulled: 0, conflicts: [], offline: false }));
    assert.equal(Object.keys(denied.journal.state.observed).length, 0,
      "authenticated but undecryptable ciphertext cannot reserve history capacity");
    correctKey = true;
    Date.now = () => operation.authorization.expiresAt + 1;
    const restarted = await make();
    await assert.rejects(restarted.pullRemote({ pulled: 0, conflicts: [], offline: false }),
      { code: "authorization_expired" },
      "granting access after expiry cannot turn a previously denied operation into an admitted one");
    assert.equal((await fs.readdir(directory)).includes("denied.txt"), false);
  } finally { Date.now = now; }
});

test("selected-path exclusion still durably witnesses a fresh signed envelope for later re-inclusion", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-excluded-admission-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = createOperation({ operation: "create",
    objectId: "excluded-verified-object", fileId: "excluded-verified-file",
    versionId: "excluded-verified-version", operationId: "excluded-verified-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "from-remote.txt" },
    plaintext: Buffer.from("after-expiry-hydration"), fileKey: key });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: signer.privateKey, publicKey,
    expiresAt: Date.now() + 1000,
  });
  const expected = { username: "alice",
    trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] };
  const adapter = { async list() { return [operation]; }, async push() {
    throw Error("unexpected push"); } };
  const make = (selectedPaths) => new SyncEngine({
    rootDir: directory, selectedPaths, adapter, deviceId: "device-b",
    keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key,
    requireAuthorization: true,
    verifyIncoming: (remote, { locallyAdmitted } = {}) => remote.authorization.expiresAt > Date.now()
      ? verifyAuthorizationProof(remote.authorization, remote, expected)
      : locallyAdmitted === true && verifyHistoricalAuthorizationProof(remote.authorization, remote, expected),
  }).open();
  const before = Date.now;
  try {
    Date.now = () => operation.authorization.expiresAt - 1;
    const excluded = await make([]);
    await excluded.pullRemote({ pulled: 0, conflicts: [], offline: false });
    assert.equal((await fs.readdir(directory)).includes("from-remote.txt"), false);
    assert.equal(excluded.snapshot.remoteOnly[operation.objectId].reason, "excluded");
    Date.now = () => operation.authorization.expiresAt + 1;
    const reinstated = await make(null);
    const summary = { pulled: 0, conflicts: [], offline: false };
    await reinstated.pullRemote(summary);
    assert.equal(summary.pulled, 1);
    assert.equal(await fs.readFile(path.join(directory, "from-remote.txt"), "utf8"),
      "after-expiry-hydration");
  } finally { Date.now = before; }
});
