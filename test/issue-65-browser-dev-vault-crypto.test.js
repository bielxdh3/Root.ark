"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const vault = require("../public/client/rootark-dev-vault-crypto");

test("browser WebCrypto round-trip keeps file name, media type and bytes inside ciphertext", async () => {
  const generated = await vault.generateRecoveryKey();
  assert.equal(generated.recoveryKey.length, 43);
  const imported = await vault.importRecoveryKey(generated.recoveryKey);
  const id = crypto.randomBytes(16).toString("base64url");
  const data = new Uint8Array([0, 1, 15, 128, 255]);
  const envelope = await vault.encryptFile({
    key: imported, id, username: "alice", name: "private-report.pdf",
    mediaType: "application/pdf", data,
  });
  assert.equal(JSON.stringify(envelope).includes("private-report.pdf"), false);
  assert.equal(JSON.stringify(envelope).includes("application/pdf"), false);
  assert.deepEqual(Object.keys(envelope).sort(), ["algorithm", "ciphertext", "format", "iv"]);
  const opened = await vault.decryptFile({ key: generated.key, id, username: "alice", envelope });
  assert.equal(opened.name, "private-report.pdf");
  assert.equal(opened.mediaType, "application/pdf");
  assert.deepEqual(opened.data, data);
});

test("tampering, wrong key, username or object ID cannot decrypt", async () => {
  const one = await vault.generateRecoveryKey();
  const two = await vault.generateRecoveryKey();
  const id = crypto.randomBytes(16).toString("base64url");
  const envelope = await vault.encryptFile({
    key: one.key, id, username: "alice", name: "hidden.txt",
    mediaType: "text/plain", data: new TextEncoder().encode("secret"),
  });
  for (const change of [
    { key: two.key },
    { id: crypto.randomBytes(16).toString("base64url") },
    { username: "bob" },
    { envelope: { ...envelope, iv: crypto.randomBytes(12).toString("base64url") } },
    { envelope: { ...envelope, ciphertext: crypto.randomBytes(60).toString("base64url") } },
    { envelope: { ...envelope, algorithm: "AES-128-GCM" } },
    { envelope: { ...envelope, unexpected: "plaintext" } },
  ]) {
    await assert.rejects(vault.decryptFile({
      key: one.key, username: "alice", id, envelope, ...change,
    }));
  }
  assert.deepEqual(Object.keys(one), ["key", "recoveryKey"]);
  assert.equal(one.key.extractable, false);
});

test("rejects invalid recovery secrets, object IDs and oversize plaintext", async () => {
  const generated = await vault.generateRecoveryKey();
  for (const value of ["", "bad", "aaaaaaaaaaaaaaaaaaaaa+", "a".repeat(45)]) {
    await assert.rejects(vault.importRecoveryKey(value));
  }
  await assert.rejects(vault.encryptFile({
    key: generated.key, username: "alice", id: "../..", name: "file",
    mediaType: "text/plain", data: new Uint8Array(3),
  }));
  await assert.rejects(vault.encryptFile({
    key: generated.key, username: "alice",
    id: crypto.randomBytes(16).toString("base64url"), name: "file",
    mediaType: "application/octet-stream", data: new Uint8Array(4 * 1024 * 1024 + 1),
  }));
});

test("key commitment is stable, non-secret, account-scoped and rejects a different valid key", async () => {
  const first = await vault.generateRecoveryKey();
  const second = await vault.generateRecoveryKey();
  const expected = await vault.keyCommitment(first.recoveryKey, "alice");
  assert.match(expected, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(await vault.keyCommitment(first.recoveryKey, "alice"), expected);
  assert.notEqual(await vault.keyCommitment(second.recoveryKey, "alice"), expected);
  assert.notEqual(await vault.keyCommitment(first.recoveryKey, "bob"), expected);
  await assert.rejects(vault.keyCommitment("bad", "alice"));
});

test("migrated ciphertext read-back must round-trip exact original bytes and metadata before success", async () => {
  const generated = await vault.generateRecoveryKey();
  const username = "alice";
  const id = crypto.randomBytes(16).toString("base64url");
  const keyId = await vault.keyCommitment(generated.recoveryKey, username);
  const original = new Uint8Array([0, 1, 3, 124, 255]);
  const name = "selected-legacy-file.txt";
  const mediaType = "text/plain";
  const envelope = await vault.encryptFile({
    key: generated.key, username, id, name, mediaType, data: original,
  });
  const record = { id, keyId, revision: 1, envelope };
  await vault.verifyStoredCopy({ key: generated.key, username, id, keyId,
    expectedEnvelope: envelope, original, name, mediaType, record });
  for (const changed of [
    { record: { ...record, id: crypto.randomBytes(16).toString("base64url") } },
    { record: { ...record, keyId: crypto.randomBytes(32).toString("base64url") } },
    { record: { ...record, envelope: { ...envelope,
      ciphertext: crypto.randomBytes(50).toString("base64url") } } },
    { original: new Uint8Array([0, 1, 3, 124, 254]) },
    { name: "wrong.txt" },
    { mediaType: "application/octet-stream" },
    { record: { ...record, revision: 0 } },
    { record: { ...record, revision: 2 } },
  ]) {
    await assert.rejects(vault.verifyStoredCopy({ key: generated.key,
      username, id, keyId, expectedEnvelope: envelope,
      original, name, mediaType, record, ...changed,
    }));
  }
  assert.deepEqual(original, new Uint8Array([0, 1, 3, 124, 255]),
    "read-back must never modify the source file buffer");
});

test("a different saved device key can never be overwritten silently even if remote vault is empty", () => {
  const existingKeyId = crypto.randomBytes(32).toString("base64url");
  const differentKeyId = crypto.randomBytes(32).toString("base64url");
  assert.equal(vault.canSaveDeviceKey(null, differentKeyId), true);
  assert.equal(vault.canSaveDeviceKey({ keyId: existingKeyId }, existingKeyId), true);
  assert.equal(vault.canSaveDeviceKey({ keyId: existingKeyId }, differentKeyId), false);
  assert.equal(vault.canSaveDeviceKey({ key: {} }, differentKeyId), false,
    "an old key record without identity cannot be overwritten without an explicit forget");
});
