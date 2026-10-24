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
