"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { normalizeTrustedDevicePolicy } = require("../sync-client/rootark-sync-v2");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");
const protocol = require("../sync-client/rootark-sync-protocol");

test("CLI requires independent trust pins plus complete explicit revocation state", async () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const spki = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  assert.throws(() => normalizeTrustedDevicePolicy({}), /complete trusted device/);
  assert.throws(() => normalizeTrustedDevicePolicy({
    trustedDevicePublicKeys: { "device-a": spki },
  }), /complete trusted device/);
  assert.throws(() => normalizeTrustedDevicePolicy({
    trustedDevicePublicKeys: { "device-a": "invalid" }, revokedDeviceIds: [],
  }), /Invalid trusted Sync v2 device key/);
  const policy = normalizeTrustedDevicePolicy({
    trustedDevicePublicKeys: { "device-a": spki }, revokedDeviceIds: [],
  });
  assert.equal(policy.trustedDevicePublicKeys["device-a"], spki);
  const operation = protocol.createOperation({ operation: "create",
    objectId: "test-object", fileId: "test-file", versionId: "test-version",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "test.txt" }, plaintext: Buffer.from("data"),
    fileKey: crypto.randomBytes(32) });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: keys.privateKey, publicKey: spki,
  });
  assert.equal(await verifyAuthorizationProof(operation.authorization, operation,
    { username: "alice", ...policy }), true);
  await assert.rejects(verifyAuthorizationProof(operation.authorization, operation,
    { username: "alice", trustedDevicePublicKeys: policy.trustedDevicePublicKeys }),
  { code: "authorization_device_revoked" });
  const revoked = normalizeTrustedDevicePolicy({
    trustedDevicePublicKeys: { "device-a": spki }, revokedDeviceIds: ["device-a"],
  });
  await assert.rejects(verifyAuthorizationProof(operation.authorization, operation,
    { username: "alice", ...revoked }),
  { code: "authorization_device_revoked" });
  const attacker = crypto.generateKeyPairSync("ed25519");
  const forgedKey = attacker.publicKey.export({ type: "spki",
    format: "der" }).toString("base64url");
  const forged = await createAuthorizationProof(operation, {
    username: "alice", privateKey: attacker.privateKey, publicKey: forgedKey,
  });
  await assert.rejects(verifyAuthorizationProof(forged, operation,
    { username: "alice", ...policy }), { code: "authorization_device_untrusted" });
});
