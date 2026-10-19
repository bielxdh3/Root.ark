"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { pbkdf2Async } = require("../services/pbkdf2Async");

const serverSource = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");
const pbkdf2ServiceSource = fs.readFileSync(path.join(__dirname, "..", "services", "pbkdf2Async.js"), "utf8");

function sourceBetween(startMarker, endMarker) {
  const start = serverSource.indexOf(startMarker);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  const end = serverSource.indexOf(endMarker, start);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  return serverSource.slice(start, end);
}

test("encrypted-file request key derivation uses async PBKDF2 without changing parameters", () => {
  const passwordDerivation = sourceBetween("async function deriveKeyFromPassword(", "async function getUserEncryptionKey(");
  const userKeyDerivation = sourceBetween("async function getUserEncryptionKey(", "function encryptBuffer(");

  assert.match(passwordDerivation, /async function deriveKeyFromPassword\(/);
  assert.match(passwordDerivation, /pbkdf2Async\(String\(password \|\| \"\"\), effectiveSalt, ENCRYPTION_ITERATIONS, 32, \"sha256\"\)/);
  assert.match(userKeyDerivation, /async function getUserEncryptionKey\(/);
  assert.match(userKeyDerivation, /pbkdf2Async\(serverSecret, userSalt, ENCRYPTION_ITERATIONS, 32, \"sha256\"\)/);
  assert.doesNotMatch(`${passwordDerivation}\n${userKeyDerivation}`, /pbkdf2Sync/);
  assert.match(pbkdf2ServiceSource, /crypto\.pbkdf2\(/);
  assert.doesNotMatch(pbkdf2ServiceSource, /pbkdf2Sync/);
});

test("encrypted upload and download request paths await asynchronous encryption work", () => {
  const keyResolution = sourceBetween("async function resolveEncryptionKeys(", "async function encryptFileInPlace(");
  const encryption = sourceBetween("async function encryptFileInPlace(", "async function decryptEncryptedFileBuffer(");
  const decryption = sourceBetween("async function decryptEncryptedFileBuffer(", "function getEncryptedAuthorizedUsers(");

  assert.match(keyResolution, /async function resolveEncryptionKeys\(/);
  assert.match(keyResolution, /await getUserEncryptionKey\(/);
  assert.match(keyResolution, /await deriveKeyFromPassword\(/);
  assert.match(encryption, /async function encryptFileInPlace\(/);
  assert.match(encryption, /await resolveEncryptionKeys\(/);
  assert.match(decryption, /async function decryptEncryptedFileBuffer\(/);
  assert.match(decryption, /await getUserEncryptionKey\(/);
  assert.match(decryption, /await deriveKeyFromPassword\(/);

  assert.equal((serverSource.match(/encryptionMetadata = await encryptFileInPlace\(/g) || []).length, 2);
  assert.match(serverSource, /const decrypted = await decryptEncryptedFileBuffer\(/);
});

test("encrypted upload revalidates permission after async key derivation and before replacing staged bytes", () => {
  const encryption = sourceBetween("async function encryptFileInPlace(", "async function decryptEncryptedFileBuffer(");
  const singleUpload = sourceBetween('app.post("/upload",', 'app.put("/file-temporary"');
  const chunkUpload = sourceBetween('app.post("/upload-chunk", authenticate', 'app.post("/upload",');

  assert.match(encryption, /await options\.revalidateBeforeWrite\(\)/);
  assert.match(encryption, /if \(!authorizedToWrite\)/);
  for (const route of [singleUpload, chunkUpload]) {
    assert.match(route, /revalidateBeforeWrite:\s*\(\)\s*=>\s*revalidateEncryptedUploadAuthorization\(req, res, folderId\)/);
  }
});

test("encrypted download revalidates current authorization after decryption and before sending plaintext", () => {
  const download = sourceBetween('app.post("/encrypted-download/:filename"', 'app.post("/encrypted/:filename/grant-access"');
  const decryptAt = download.indexOf("const decrypted = await decryptEncryptedFileBuffer(");
  const revalidateAt = download.indexOf("if (!refreshAuthenticatedUser(req, res)) {", decryptAt);
  const sendAt = download.indexOf("res.send(decrypted);", decryptAt);

  assert.notEqual(decryptAt, -1, "encrypted download must await decryption");
  assert.ok(revalidateAt > decryptAt, "authorization must be refreshed after async decryption");
  assert.ok(sendAt > revalidateAt, "plaintext must not be sent before the refreshed authorization checks");
  assert.match(download.slice(revalidateAt, sendAt), /const currentFolder = getFolderById\(folder\.id\)/);
  assert.match(download.slice(revalidateAt, sendAt), /const currentMetadata = getEncryptedFileMetadata\(folder\.id, name\)/);
  assert.match(download.slice(revalidateAt, sendAt), /canAccessEncryptedFile\(req, currentMetadata\)/);
  assert.match(download.slice(revalidateAt, sendAt), /decrypted\.fill\(0\)/);
});

test("async PBKDF2 preserves the existing password-key bytes and parameter contract", async () => {
  const password = "synthetic-encryption-password";
  const salt = Buffer.from("00112233445566778899aabbccddeeff", "hex");
  const expected = crypto.pbkdf2Sync(password, salt, 100_000, 32, "sha256");
  const actual = await pbkdf2Async(password, salt, 100_000, 32, "sha256");

  assert.deepEqual(actual, expected);
});

test("async PBKDF2 preserves the existing user-key salt and derived bytes", async () => {
  const serverSecret = Buffer.from("synthetic server master key");
  const username = "fixture-owner";
  const salt = crypto.createHash("sha256").update(`${username}:rootark-user-key`).digest();
  const expected = crypto.pbkdf2Sync(serverSecret, salt, 100_000, 32, "sha256");
  const actual = await pbkdf2Async(serverSecret, salt, 100_000, 32, "sha256");

  assert.deepEqual(actual, expected);
});
