"use strict";

// Real device Ed25519/AEAD envelope tests. DO NOT convert failures to mocks:
// they require exclusive Windows Node22 under the project's process gate.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, assertAuthorizationEnvelopeBinding } =
  require("../sync-client/rootark-sync-authorization");

const pair = crypto.generateKeyPairSync("ed25519");
const publicKey = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64url");

function freshOperation(id) {
  return protocol.createOperation({
    operation: "create", operationId: `operation-${id}`,
    objectId: `object-${id}`, fileId: `file-${id}`,
    versionId: `version-${id}`, deviceId: "device-a",
    keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: `${id}.txt` },
    plaintext: Buffer.from("encrypted bytes, never accepted with a forged digest"),
    fileKey: crypto.randomBytes(32),
  });
}

async function signed(id) {
  const operation = freshOperation(id);
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: pair.privateKey, publicKey,
    expiresAt: Date.now() + 60_000,
  });
  return operation;
}

function corruptBase64(base64) {
  const bytes = Buffer.from(base64, "base64url");
  bytes[0] ^= 1;
  return bytes.toString("base64url");
}

test("signed ciphertext is structurally bound to the authentic AAD, nonce, tag and ciphertext", async () => {
  const original = await signed("immutable-envelope");
  const normalized = protocol.validateFreshSignedOperation(original).authorization;
  assert.equal(JSON.stringify(normalized),
    JSON.stringify(protocol.normalizeAuthorization(original.authorization)),
    "normalization preserves all signed proof fields and their values");
  assert.equal(assertAuthorizationEnvelopeBinding(original.authorization, original), true);

  for (const field of ["ciphertext", "nonce", "tag", "aad"]) {
    const attack = { ...original, [field]: corruptBase64(original[field]) };
    assert.throws(() => protocol.validateFreshSignedOperation(attack),
      { code: "authorization_scope" }, `tampered ${field} cannot inherit the signature`);
    assert.throws(() => protocol.validateOperation(attack),
      { code: "authorization_scope" }, `generic validator cannot silently waive ${field} binding`);
  }

  // The input's AAD is still valid for the modified metadata, but its signed
  // authorization is pinned to the original metadata and digest.
  const retargeted = freshOperation("foreign-envelope");
  const replacement = {
    ...retargeted,
    authorization: original.authorization,
  };
  assert.throws(() => protocol.validateFreshSignedOperation(replacement),
    { code: "authorization_scope" }, "an original proof cannot authorize a fresh encrypted operation");

  // Historical reads may skip the expiry freshness check, but must NEVER
  // skip the digest/metadata binding to the actual stored ciphertext.
  const savedCorruption = { ...original,
    ciphertext: corruptBase64(original.ciphertext) };
  assert.throws(() => protocol.validateStoredOperation(savedCorruption),
    { code: "authorization_scope" }, "a stale-but-signed stored record cannot authenticate altered bytes");
});

test("protected ingress requires proof regardless of presence of untrusted payload flags", async () => {
  const plain = freshOperation("unsigned-forbidden");
  assert.throws(() => protocol.validateFreshSignedOperation(plain),
    { code: "authorization_required" });
  assert.ok(protocol.validateOperation(plain), "legacy structural read remains explicit");
  assert.throws(() => protocol.validateFreshSignedOperation({ ...plain, authorization: undefined }),
    /Invalid device authorization/, "present-but-undefined is not valid signed authorization");
});

test("constructor may never carry previously signed authorization across encryption", async () => {
  const original = await signed("nonce-separation");
  assert.throws(() => protocol.createOperation({
    ...original, plaintext: Buffer.from("modified ciphertext"), fileKey: crypto.randomBytes(32),
  }), { code: "authorization_scope" }, "fresh encryption must happen before authorization");
  assert.throws(() => protocol.createOperation({
    ...original, authorization: undefined, plaintext: Buffer.from("modified"),
    fileKey: crypto.randomBytes(32),
  }), { code: "authorization_scope" }, "even an own undefined proof property is forbidden");
});
