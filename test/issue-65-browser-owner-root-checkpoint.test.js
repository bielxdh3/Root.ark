"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const z = require("../src/crypto/rootark-zk-1");
const ownerHistory = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const api = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");
const b64 = (value) => Buffer.from(value).toString("base64url");
const random = (n) => crypto.randomBytes(n);
const invalid = /ZK_OWNER_CIPHERTEXT_ROOT_UNVERIFIED/;

async function fixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const privateKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    keys.privateKey.export({ format: "der", type: "pkcs8" }), "Ed25519", false, ["sign"]);
  const publicKey = await crypto.webcrypto.subtle.importKey("spki",
    keys.publicKey.export({ format: "der", type: "spki" }), "Ed25519", false, ["verify"]);
  const scope = { account_id: b64(random(16)),
    compartment_id: b64(Buffer.from("trusted-root-test")), keyring_id: b64(random(16)) };
  const signerKeyId = random(16);
  const manifestDigest = random(32);
  const ownerHistoryCheckpoint = await ownerHistory.signOwnerCheckpoint({
    scope, signerKey: privateKey, signerPublicKey: publicKey,
    signerKeyId, deviceId: "owner-desktop", revision: 7, manifestDigest,
    issuedAt: 1001, previous: null,
  });
  const fields = { scope, signerKey: privateKey, signerKeyId, deviceId: "owner-desktop",
    manifestRevision: 7, manifestDigest, manifestEpoch: 4,
    objectId: b64(random(16)), objectRevision: 3,
    ciphertextEpoch: 2, ciphertextRoot: random(32), issuedAt: 1002 };
  const signed = await api.signOwnerCiphertextRootCheckpoint(fields);
  const pinnedOwner = { scope, deviceId: "owner-desktop", signerKeyId, publicKey };
  const expected = { manifestRevision: fields.manifestRevision,
    manifestDigest, manifestEpoch: fields.manifestEpoch, objectId: fields.objectId,
    objectRevision: fields.objectRevision, ciphertextEpoch: fields.ciphertextEpoch,
    ciphertextRoot: fields.ciphertextRoot };
  return { keys, fields, signed, ownerHistoryCheckpoint, pinnedOwner, expected,
    input: { checkpoint: signed, ownerHistoryCheckpoint,
      previousHistoryProof: null, pinnedOwner, expected } };
}

test("independent Node canonical CBOR and WebCrypto Ed25519 agree on exact ciphertext owner root", async () => {
  const f = await fixture();
  const wire = { ...f.signed };
  const signature = Buffer.from(wire.signature, "base64url");
  delete wire.signature;
  for (const field of ["account_id", "compartment_id", "keyring_id",
    "signer_key_id", "manifest_digest", "ciphertext_root"]) {
    wire[field] = Buffer.from(wire[field], "base64url");
  }
  const signedMessage = Buffer.concat([
    Buffer.from("Root.ark/zk-1/owner-ciphertext-root-checkpoint/v1\0"),
    Buffer.from(await z.encodeDeterministic(wire)),
  ]);
  assert.equal(crypto.verify(null, signedMessage, f.keys.publicKey, signature), true);
  const proof = await api.verifyOwnerCiphertextRootCheckpoint(f.input);
  assert.equal(proof.trustedOwnerSignatureVerified, true);
  assert.equal(proof.liveDeviceRevocationVerified, false);
  assert.equal(proof.authorizesRecovery, false);
  assert.equal(api.assertOwnerCiphertextRootProof({ proof, scope: f.fields.scope,
    deviceId: f.fields.deviceId, manifestRevision: f.fields.manifestRevision,
    manifestDigest: f.fields.manifestDigest, manifestEpoch: f.fields.manifestEpoch,
    objectId: f.fields.objectId,
    objectRevision: f.fields.objectRevision, ciphertextEpoch: f.fields.ciphertextEpoch,
    ciphertextRoot: f.fields.ciphertextRoot }), true);
});

test("forged signer, cross-object/epoch/revision/root/manifest replay and mutable fake proofs fail", async () => {
  const f = await fixture();
  const attacker = crypto.generateKeyPairSync("ed25519");
  const foreignKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    attacker.privateKey.export({ format: "der", type: "pkcs8" }), "Ed25519", false, ["sign"]);
  const foreign = await api.signOwnerCiphertextRootCheckpoint({ ...f.fields, signerKey: foreignKey });
  await assert.rejects(api.verifyOwnerCiphertextRootCheckpoint({
    ...f.input, checkpoint: foreign }), invalid);
  for (const changed of [
    { objectId: b64(random(16)) }, { objectRevision: 4 },
    { ciphertextEpoch: 3 }, { ciphertextRoot: random(32) },
    { manifestRevision: 8 }, { manifestDigest: random(32) },
    { manifestEpoch: 5 },
  ]) {
    await assert.rejects(api.verifyOwnerCiphertextRootCheckpoint({
      ...f.input, expected: { ...f.expected, ...changed },
    }), invalid, Object.keys(changed)[0]);
  }
  await assert.rejects(api.verifyOwnerCiphertextRootCheckpoint({
    ...f.input, checkpoint: { ...f.signed, ciphertext_root: b64(random(32)) },
  }), invalid);
  await assert.rejects(api.verifyOwnerCiphertextRootCheckpoint({
    ...f.input, checkpoint: { ...f.signed, unexpectedServerRoot: b64(random(32)) },
  }), invalid);
  assert.throws(() => api.assertOwnerCiphertextRootProof({
    proof: { trustedOwnerSignatureVerified: true },
    scope: f.fields.scope, deviceId: f.fields.deviceId,
    manifestRevision: f.fields.manifestRevision, manifestDigest: f.fields.manifestDigest,
    manifestEpoch: f.fields.manifestEpoch,
    objectId: f.fields.objectId, objectRevision: f.fields.objectRevision,
    ciphertextEpoch: f.fields.ciphertextEpoch, ciphertextRoot: f.fields.ciphertextRoot,
  }), invalid, "a server-supplied true flag cannot mint an owner-verification proof");
});

test("plain browser UMD verifies the signed owner certificate without Node dependencies", async () => {
  const f = await fixture();
  const context = vm.createContext({
    crypto: crypto.webcrypto, TextEncoder, TextDecoder, btoa, atob,
    Uint8Array, ArrayBuffer,
  });
  for (const script of ["rootark-zk1-owner-signed-checkpoint.js",
    "rootark-zk1-owner-ciphertext-root-checkpoint.js"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../public/client", script), "utf8"),
      context);
  }
  context.raw = f.input;
  const verified = await vm.runInContext(`(() => {
    const data = { checkpoint: { ...raw.checkpoint },
      ownerHistoryCheckpoint: { ...raw.ownerHistoryCheckpoint },
      previousHistoryProof: null,
      pinnedOwner: { ...raw.pinnedOwner, scope: { ...raw.pinnedOwner.scope } },
      expected: { ...raw.expected } };
    return RootarkZk1OwnerCiphertextRootCheckpoint.verifyOwnerCiphertextRootCheckpoint(data);
  })()`, context);
  assert.equal(verified.trustedOwnerSignatureVerified, true);
  assert.equal(verified.authorizesProtectedIo, false);
});
