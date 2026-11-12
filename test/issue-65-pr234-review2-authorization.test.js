"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const protocol = require("../sync-client/rootark-sync-protocol");
const auth = require("../sync-client/rootark-sync-authorization");
const binding = require("../sync-client/rootark-sync-zk1-physical-binding");

test("stored historical Sync v2 envelope retains signed bytes after expiration", async () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const operation = protocol.createOperation({
    operation: "create", objectId: "object_1", fileId: "file_1",
    versionId: "version_1", deviceId: "device_1",
    compartmentId: "vault", keyEpoch: "epoch-1",
    revision: { counter: 1, deviceId: "device_1" },
    metadata: { path: "notes.txt" }, plaintext: Buffer.from("encrypted fixture"),
    fileKey: crypto.randomBytes(32),
  });
  // Use real elapsed time. The verifier intentionally captures the native
  // clock before attacker-controlled callbacks can replace Date.now.
  const expiresAt = Date.now() + 3000;
  operation.authorization = await auth.createAuthorizationProof(operation, {
    username: "alice", publicKey, privateKey: keys.privateKey, expiresAt,
  });
  const policy = { username: "alice", trustedDevicePublicKeys: {
    device_1: publicKey }, revokedDeviceIds: [] };
  await new Promise((resolve) => setTimeout(resolve,
    Math.max(0, expiresAt - Date.now() + 30)));
  assert.throws(() => protocol.validateOperation(operation), /Expired device authorization/);
  const normalized = protocol.validateStoredOperation(operation);
  assert.equal(normalized.authorization.signature, operation.authorization.signature);
  assert.equal(await auth.verifyHistoricalAuthorizationProof(
    normalized.authorization, normalized, policy), true);
  await assert.rejects(auth.verifyAuthorizationProof(
    normalized.authorization, normalized, policy), /Authorization expired/);
  const bound = binding.envelopeBinding(operation, {
    account_id: crypto.randomBytes(16), compartment_id: Buffer.from("vault"),
    keyring_id: crypto.randomBytes(16),
  }, 0, crypto.randomBytes(32));
  assert.equal(bound.envelope.authorization.signature, operation.authorization.signature);
  await assert.rejects(auth.verifyHistoricalAuthorizationProof(
    normalized.authorization, normalized, { ...policy, revokedDeviceIds: ["device_1"] }),
  (error) => error?.code === "authorization_device_revoked");
  await assert.rejects(auth.verifyHistoricalAuthorizationProof(
    normalized.authorization, { ...normalized, objectId: "forged" }, policy),
  (error) => error?.code === "authorization_scope");
});
