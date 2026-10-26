"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const fileCrypto = require("../public/client/rootark-dev-vault-crypto");
const emergency = require("../public/client/rootark-dev-vault-emergency");

test("user-held Argon2id emergency package restores the same AES key without any server call", {
  timeout: 120_000,
}, async () => {
  const generated = await fileCrypto.generateRecoveryKey();
  const password = "a long synthetic recovery password 2026!";
  const packageBytes = await emergency.createEmergencyPackage({
    username: "alice", recoveryKey: generated.recoveryKey, password,
  });
  const packageText = JSON.stringify(packageBytes);
  assert.ok(packageText.length < 2000);
  assert.equal(packageText.includes(generated.recoveryKey), false);
  assert.equal(packageText.includes(password), false);
  assert.equal(packageBytes.kdf.name, "argon2id13");
  assert.equal(packageBytes.kdf.opslimit, 3);
  assert.equal(packageBytes.kdf.memlimit, 268435456);
  const recovered = await emergency.openEmergencyPackage({
    username: "alice", packageBytes, password,
  });
  assert.equal(recovered, generated.recoveryKey);
  const restoredKey = await fileCrypto.importRecoveryKey(recovered);
  const id = crypto.randomBytes(16).toString("base64url");
  const envelope = await fileCrypto.encryptFile({
    key: generated.key, username: "alice", id,
    name: "private.txt", mediaType: "text/plain",
    data: new TextEncoder().encode("private document"),
  });
  const output = await fileCrypto.decryptFile({
    key: restoredKey, username: "alice", id, envelope,
  });
  assert.equal(new TextDecoder().decode(output.data), "private document");
});

test("wrong password, changed account, corrupted package and downgraded KDF never recover", {
  timeout: 120_000,
}, async () => {
  const generated = await fileCrypto.generateRecoveryKey();
  const pkg = await emergency.createEmergencyPackage({
    username: "alice", recoveryKey: generated.recoveryKey,
    password: "synthetic correct password 2026!",
  });
  for (const altered of [
    { password: "totally wrong password 2026" },
    { username: "bob" },
    { packageBytes: { ...pkg, kdf: { ...pkg.kdf, memlimit: 8192 } } },
    { packageBytes: { ...pkg, format: "wrong" } },
    { packageBytes: { ...pkg, extra: "secret" } },
    { packageBytes: { ...pkg, ciphertext: crypto.randomBytes(48).toString("base64url") } },
    { packageBytes: { ...pkg, iv: crypto.randomBytes(12).toString("base64url") } },
  ]) {
    await assert.rejects(emergency.openEmergencyPackage({
      username: "alice", password: "synthetic correct password 2026!",
      packageBytes: pkg, ...altered,
    }));
  }
});

test("nonstandard or broken Argon2id fallback must fail closed before creating a package", async () => {
  // Some browser fallbacks can accept the same fixed parameters but derive
  // different bytes. A package must never depend on that broken KDF.
  const fakeSodium = {
    ready: Promise.resolve(),
    crypto_pwhash_ALG_ARGON2ID13: 2,
    crypto_pwhash: () => new Uint8Array(32),
    memzero: (value) => value.fill(0),
  };
  const sandbox = { sodium: fakeSodium, crypto: crypto.webcrypto,
    TextEncoder, Uint8Array, btoa, atob };
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.resolve(__dirname,
    "../public/client/rootark-dev-vault-emergency.js"), "utf8"), sandbox);
  const generated = await fileCrypto.generateRecoveryKey();
  await assert.rejects(sandbox.RootarkDevVaultEmergency.createEmergencyPackage({
    username: "alice", recoveryKey: generated.recoveryKey,
    password: "long synthetic passphrase for a broken KDF",
  }), /Invalid emergency package or passphrase/);
});
