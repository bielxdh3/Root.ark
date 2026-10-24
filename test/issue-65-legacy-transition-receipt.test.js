"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const api = require("../public/client/rootark-zk1-legacy-transition-receipt");
const b64 = (n) => crypto.randomBytes(n).toString("base64url");
async function fixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const ownerSigningKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    owner.privateKey.export({ type: "pkcs8", format: "der" }), "Ed25519", false, ["sign"]);
  const ownerPublicKey = await crypto.webcrypto.subtle.importKey("spki",
    owner.publicKey.export({ type: "spki", format: "der" }), "Ed25519", true, ["verify"]);
  const receipt = api.createProposal({
    scope: { account_id: b64(16), compartment_id: b64(8), keyring_id: b64(16) },
    legacy: { name: "legacy.txt", folderId: "documents" },
    sourcePin: { version: 2, storedAs: "legacy.txt.v2",
      uploadedAt: "2026-10-22T01:00:00.000Z", size: 7,
      lastModified: "Thu, 22 Oct 2026 01:00:00 GMT", sha256: b64(32), mediaType: "text/plain" },
    target: { object_id: b64(16), version_id: b64(16), revision: 1,
      root: b64(32), ciphertext_sha256: b64(32), epoch: 4 },
    ownerHead: { revision: 7, digest: b64(32), epoch: 4 },
    binding: b64(32), sourceDescriptorDigest: b64(32), issuedAt: 1500, nonce: b64(16),
  });
  const signed = await api.signTransitionReceipt({ proposal: receipt, ownerSigningKey });
  return { receipt, signed, ownerPublicKey, ownerSigningKey };
}
test("offline owner signed transition binds exact legacy revision, ciphertext root, scope and unknown retention", async () => {
  const f = await fixture();
  const approved = await api.verifyTransitionReceipt({ receipt: f.signed,
    expected: f.receipt, ownerPublicKey: f.ownerPublicKey, nowSeconds: 1501 });
  assert.equal(approved.ownerSignatureVerified, true);
  assert.equal(approved.state, "verified-protected");
  assert.equal(approved.canDeleteLegacy, false);
  assert.equal(approved.authorizesCutover, false);
  assert.equal(approved.wholeCorpusVerified, false);
  assert.ok(Object.values(approved.receipt.references).every((value) => value === "unknown"));
});
test("tampered signed receipt, prior head, replays and guessed reference clearance fail closed", async () => {
  const f = await fixture();
  const check = (receipt, expected = f.receipt, nowSeconds = 1501) =>
    api.verifyTransitionReceipt({ receipt, expected,
      ownerPublicKey: f.ownerPublicKey, nowSeconds });
  for (const changed of [
    { ...f.signed, signature: b64(64) },
    { ...f.signed, ownerHead: { ...f.signed.ownerHead, epoch: 2 } },
    { ...f.signed, sourcePin: { ...f.signed.sourcePin, sha256: b64(32) } },
    { ...f.signed, target: { ...f.signed.target, version_id: b64(16) } },
    { ...f.signed, references: { ...f.signed.references, links: "clear" } },
    { ...f.signed, nonce: b64(16) },
  ]) await assert.rejects(check(changed), /ZK_LEGACY_TRANSITION_UNVERIFIED/);
  await assert.rejects(check(f.signed, f.receipt, 1500 + 86401),
    /ZK_LEGACY_TRANSITION_UNVERIFIED/);
  await assert.rejects(check(f.signed, { ...f.receipt,
    target: { ...f.receipt.target, root: b64(32) } }),
  /ZK_LEGACY_TRANSITION_UNVERIFIED/);
});
test("browser UMD offers offline sign/verify without Node globals", async () => {
  const ctx = vm.createContext({ crypto: crypto.webcrypto,
    TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, atob, btoa });
  vm.runInContext(fs.readFileSync(path.resolve(__dirname,
    "../public/client/rootark-zk1-legacy-transition-receipt.js"), "utf8"), ctx);
  assert.equal(vm.runInContext("typeof RootarkZk1LegacyTransitionReceipt.createProposal", ctx), "function");
  assert.equal(vm.runInContext("typeof RootarkZk1LegacyTransitionReceipt.signTransitionReceipt", ctx), "function");
});
