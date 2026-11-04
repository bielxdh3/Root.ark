"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const portable = require("../public/client/rootark-zk1-portable-file-recovery");
function id() { return crypto.randomBytes(16).toString("base64url"); }
function metadata() {
  return { account_id: id(), compartment_id: id(), keyring_id: id(),
    object_id: id(), version_id: id(), parent_version_id: null,
    epoch: 5, kind: "file" };
}
function raw(base64url) { return Buffer.from(base64url, "base64url"); }
async function fixture() {
  const recoverySecret = portable.generateRecoverySecret();
  const meta = metadata();
  const input = new TextEncoder().encode("local plaintext that must never reach the server");
  const bundle = await portable.sealForUserHeldSecret({
    recoverySecret, metadata: meta, name: "private.txt",
    mediaType: "text/plain", data: input,
  });
  return { recoverySecret, meta, input, bundle,
    independentlyPinnedCiphertextRoot: raw(bundle.ciphertextRoot) };
}
function open(f, overrides = {}) {
  return portable.openWithIndependentRoot({
    recoverySecret: f.recoverySecret, bundle: f.bundle,
    expectedMetadata: f.meta,
    independentlyPinnedCiphertextRoot: f.independentlyPinnedCiphertextRoot,
    ...overrides,
  });
}
test("fresh 256-bit user-held offline key reopens authenticated ciphertext without server CEK", async () => {
  const f = await fixture();
  assert.equal(f.recoverySecret.length, 32);
  assert.equal(f.bundle.format, "rootark-zk1-portable-file-recovery/v1");
  assert.deepEqual(Object.keys(f.bundle).sort(), [
    "ciphertextBase64", "ciphertextRoot", "ciphertextSha256", "format",
    "metadata", "objectRevision", "wrap",
  ]);
  assert.ok(!JSON.stringify(f.bundle).includes(Buffer.from(f.recoverySecret).toString("base64url")));
  assert.ok(!JSON.stringify(f.bundle).includes(new TextDecoder().decode(f.input)));
  const output = await open(f);
  assert.equal(output.name, "private.txt");
  assert.equal(output.mediaType, "text/plain");
  assert.deepEqual(output.data, f.input);
  assert.equal(output.ciphertextRootVerifiedAgainstIndependentPin, true);
  assert.equal(output.currentOnlineRevocationVerified, false);
  assert.equal(output.authorizesProductionRestore, false);
  output.data.fill(0);
  f.recoverySecret.fill(0);
});
test("wrong owner-pinned ciphertext root, key, scope or epoch cannot open portable ciphertext", async () => {
  const f = await fixture();
  await assert.rejects(open(f, { independentlyPinnedCiphertextRoot: crypto.randomBytes(32) }),
    /ZK_PORTABLE_FILE_RECOVERY_DENIED/);
  await assert.rejects(open(f, { recoverySecret: crypto.randomBytes(32) }),
    /ZK_PORTABLE_FILE_RECOVERY_DENIED/);
  for (const bad of [
    { ...f.meta, object_id: id() }, { ...f.meta, account_id: id() },
    { ...f.meta, epoch: f.meta.epoch - 1 }, { ...f.meta, version_id: id() },
  ]) await assert.rejects(open(f, { expectedMetadata: bad }),
    /ZK_PORTABLE_FILE_RECOVERY_DENIED/);
});
test("tampered ciphertext, CEK envelope, digest or metadata are rejected before release", async () => {
  const f = await fixture();
  for (const mutated of [
    { ...f.bundle, ciphertextRoot: crypto.randomBytes(32).toString("base64url") },
    { ...f.bundle, ciphertextSha256: crypto.randomBytes(32).toString("base64url") },
    { ...f.bundle, ciphertextBase64: crypto.randomBytes(45).toString("base64url") },
    { ...f.bundle, wrap: { ...f.bundle.wrap,
      sealedCek: crypto.randomBytes(48).toString("base64url") } },
    { ...f.bundle, wrap: { ...f.bundle.wrap,
      nonce: crypto.randomBytes(12).toString("base64url") } },
    { ...f.bundle, wrap: { ...f.bundle.wrap, format: "PBKDF2/unknown" } },
    { ...f.bundle, metadata: { ...f.meta, epoch: 6 } },
    { ...f.bundle, leakedRecoverySecret: "forbidden" },
    { ...f.bundle, ciphertextBase64: "not+canonical" },
  ]) {
    await assert.rejects(open(f, { bundle: mutated }),
      /ZK_PORTABLE_FILE_RECOVERY_DENIED/);
  }
});
test("replayed old encrypted bundle cannot be relabeled as a newer owner-pinned version", async () => {
  const f = await fixture();
  const future = { ...f.meta, version_id: id(), epoch: 6 };
  const newFile = await portable.sealForUserHeldSecret({
    recoverySecret: f.recoverySecret, metadata: future, name: "private-new.txt",
    mediaType: "text/plain", data: new TextEncoder().encode("new version"),
    objectRevision: 2,
  });
  await assert.rejects(open(f, {
    expectedMetadata: future,
    independentlyPinnedCiphertextRoot: raw(newFile.ciphertextRoot),
  }), /ZK_PORTABLE_FILE_RECOVERY_DENIED/);
  const restored = await portable.openWithIndependentRoot({
    recoverySecret: f.recoverySecret, bundle: newFile,
    expectedMetadata: future,
    independentlyPinnedCiphertextRoot: raw(newFile.ciphertextRoot),
  });
  assert.equal(new TextDecoder().decode(restored.data), "new version");
  restored.data.fill(0);
});
test("caller cannot use partial keys, guessed password strings, nested proxies or oversized file", async () => {
  const f = await fixture();
  for (const recoverySecret of ["password", new Uint8Array(31), new Uint8Array(33)]) {
    await assert.rejects(open(f, { recoverySecret }), /ZK_PORTABLE_FILE_RECOVERY_DENIED/);
  }
  await assert.rejects(portable.sealForUserHeldSecret({
    recoverySecret: f.recoverySecret, metadata: f.meta, name: "big.bin",
    mediaType: "application/octet-stream", data: new Uint8Array(2 * 1024 * 1024 + 1),
  }), /ZK_PORTABLE_FILE_RECOVERY_DENIED/);
});
