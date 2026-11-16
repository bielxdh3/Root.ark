"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyHistoricalAuthorizationProof,
  verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");

test("P2: real signed authorization rejects alternate base64url encodings of ciphertext and signature", async () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" })
    .toString("base64url");
  const operation = protocol.createOperation({
    operation: "create", objectId: "object-canonical", fileId: "file-canonical",
    versionId: "version-canonical", operationId: "op-canonical",
    deviceId: "device-canonical", compartmentId: "private", keyEpoch: "epoch-1",
    revision: { counter: 1, deviceId: "device-canonical" },
    metadata: { path: "canonical.txt" },
    plaintext: Buffer.from("synthetic canonical ciphertext test"),
    fileKey: crypto.randomBytes(32),
  });
  const proof = await createAuthorizationProof(operation, {
    username: "alice", privateKey: signer.privateKey, publicKey,
    expiresAt: Date.now() + 60_000,
  });
  const policy = { username: "alice", trustedDevicePublicKeys: {
    "device-canonical": publicKey }, revokedDeviceIds: [] };

  assert.equal(await verifyAuthorizationProof(proof, operation, policy), true,
    "an unaltered real Ed25519 authorization must remain accepted");
  assert.equal(await verifyHistoricalAuthorizationProof(proof, operation, policy), true);

  for (const field of ["aad", "ciphertext", "nonce", "tag"]) {
    const alternate = { ...operation, [field]: `${operation[field]}=` };
    assert.ok(Buffer.from(alternate[field], "base64url")
      .equals(Buffer.from(operation[field], "base64url")),
    `${field}: decoder accepts the same raw encrypted bytes despite extra padding`);
    await assert.rejects(verifyHistoricalAuthorizationProof(proof, alternate, policy),
      (error) => error?.code === "invalid_device_authorization",
      `${field}: an alternate encoding must not count as the signed operation`);
  }

  const paddedSignature = { ...proof, signature: `${proof.signature}==` };
  assert.ok(Buffer.from(paddedSignature.signature, "base64url")
    .equals(Buffer.from(proof.signature, "base64url")),
  "the padded signature is byte-identical to the authentic Ed25519 signature");
  await assert.rejects(verifyHistoricalAuthorizationProof(paddedSignature, operation, policy),
    (error) => error?.code === "invalid_device_authorization",
    "malleable signature serialization must not pass historical verification");

  // Unlike rewriting a signed proof, this alternative public-key spelling is
  // genuinely signed and independently pinned with the same noncanonical wire.
  const paddedKey = `${publicKey}=`;
  assert.ok(Buffer.from(paddedKey, "base64url")
    .equals(Buffer.from(publicKey, "base64url")),
  "the alternative Ed25519 SPKI spelling decodes to the same pinned key");
  const paddedKeyProof = await createAuthorizationProof(operation, {
    username: "alice", privateKey: signer.privateKey, publicKey: paddedKey,
    expiresAt: Date.now() + 60_000,
  });
  await assert.rejects(verifyHistoricalAuthorizationProof(paddedKeyProof, operation, {
    ...policy, trustedDevicePublicKeys: { "device-canonical": paddedKey },
  }), (error) => error?.code === "invalid_device_authorization",
  "even a genuinely signed noncanonical SPKI must not be treated as pinned authority");
});

test("P2: genuine Ed25519 zero-byte ciphertext remains valid, but only ciphertext may be empty", async () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" })
    .toString("base64url");
  const operation = protocol.createOperation({
    operation: "create", objectId: "object-empty", fileId: "file-empty",
    versionId: "version-empty", operationId: "op-empty", deviceId: "device-empty",
    compartmentId: "private", keyEpoch: "epoch-1",
    revision: { counter: 1, deviceId: "device-empty" },
    metadata: { path: "empty.txt" }, plaintext: Buffer.alloc(0),
    fileKey: crypto.randomBytes(32),
  });
  assert.equal(operation.ciphertext, "", "real AES-GCM zero-byte file has empty ciphertext");
  assert.ok(["aad", "nonce", "tag"].every((field) => operation[field].length > 0),
    "the authentication context, nonce and tag must remain nonempty");
  const proof = await createAuthorizationProof(operation, {
    username: "alice", publicKey, privateKey: signer.privateKey,
    expiresAt: Date.now() + 60_000,
  });
  const policy = { username: "alice", trustedDevicePublicKeys: {
    "device-empty": publicKey }, revokedDeviceIds: [] };
  assert.equal(await verifyAuthorizationProof(proof, operation, policy), true,
    "a genuine fresh Ed25519 proof for an empty file must verify");
  assert.equal(await verifyHistoricalAuthorizationProof(proof, operation, policy), true,
    "a genuine historical Ed25519 proof for an empty file must verify");

  for (const alternate of ["=", "==", "A"]) {
    assert.ok(Buffer.from(alternate, "base64url")
      .equals(Buffer.from(operation.ciphertext, "base64url")),
    "the malformed encoding is byte-equivalent to the empty ciphertext");
    await assert.rejects(verifyHistoricalAuthorizationProof(proof,
      { ...operation, ciphertext: alternate }, policy),
    (error) => error?.code === "invalid_device_authorization",
    "only the empty string is a canonical zero-byte ciphertext encoding");
  }
  for (const field of ["aad", "nonce", "tag"]) {
    await assert.rejects(verifyHistoricalAuthorizationProof(proof,
      { ...operation, [field]: "" }, policy),
    (error) => error?.code === "invalid_device_authorization",
    `${field}: empty data is never permitted outside ciphertext`);
  }
  await assert.rejects(verifyHistoricalAuthorizationProof({ ...proof, signature: "" },
    operation, policy), (error) => error?.code === "invalid_device_authorization",
  "an empty signature must still be denied");
});
