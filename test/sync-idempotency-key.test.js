"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, generateIdempotencyKey, verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");

const KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const keys = crypto.generateKeyPairSync("ed25519");
const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");

function operationFor(operationId = "idem-operation") {
  return protocol.createOperation({
    operation: "create", objectId: "idem-object", fileId: "idem-file", versionId: "idem-version", operationId,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "idem.txt" }, plaintext: Buffer.from("payload"), fileKey: crypto.randomBytes(32),
  });
}

async function proofFor(operation, idempotencyKey) {
  return createAuthorizationProof(operation, {
    username: "alice", privateKey: keys.privateKey, publicKey, expiresAt: Date.now() + 60_000,
    ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
  });
}

function keyOfLength(length) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let value = "";
  while (value.length < length) value += alphabet[crypto.randomInt(alphabet.length)];
  return value;
}

function rejectionOf(fn) {
  try { fn(); } catch (error) { return { message: error.message, code: error.code }; }
  throw new Error("expected rejection");
}

test("17-character idempotency key is accepted by the operation validator", async () => {
  const operation = operationFor();
  const proof = await proofFor(operation, "abcdefghijklmnopq");
  assert.equal(proof.idempotencyKey, "abcdefghijklmnopq");
  const result = protocol.createOperation({ ...operation, authorization: proof, plaintext: Buffer.from("payload"), fileKey: crypto.randomBytes(32) });
  assert.equal(result.authorization.idempotencyKey, "abcdefghijklmnopq");
});

test("every idempotency key length from 16 to 40 is accepted", async () => {
  const operation = operationFor();
  for (let length = 16; length <= 40; length += 1) {
    const key = keyOfLength(length);
    const proof = await proofFor(operation, key);
    assert.equal(protocol.normalizeAuthorization(proof).idempotencyKey, key, `length ${length}`);
  }
});

test("boundary lengths 16 and 128 are accepted, 15 and 129 are rejected", async () => {
  const operation = operationFor();
  for (const length of [16, 128]) {
    assert.equal((await proofFor(operation, keyOfLength(length))).idempotencyKey.length, length);
  }
  for (const length of [15, 129]) {
    await assert.rejects(proofFor(operation, keyOfLength(length)), { message: "Invalid device authorization" });
  }
});

test("invalid characters, too short and too long keys are rejected with the same error as before", async () => {
  const operation = operationFor();
  const proof = await proofFor(operation);
  const expected = rejectionOf(() => protocol.normalizeAuthorization({ ...proof, idempotencyKey: "x" }));
  assert.deepEqual(expected, { message: "Invalid device authorization", code: "invalid_operation" });
  const invalid = [
    "short-key-15chr", // 15 characters
    "a".repeat(129),
    "abcdefghijklmnop+qrs", // base64 '+'
    "abcdefghijklmnop/qrs", // base64 '/'
    "abcdefghijklmnopqrs=", // base64 padding
    "abcdefghijklmnop qrs", // space
    "abcdefghijklmnop.qrs", // dot
    "abcdefghijklmnopqrs!",
    "",
  ];
  for (const key of invalid) {
    assert.deepEqual(rejectionOf(() => protocol.normalizeAuthorization({ ...proof, idempotencyKey: key })), expected, JSON.stringify(key));
    await assert.rejects(proofFor(operation, key), { message: "Invalid device authorization" }, JSON.stringify(key));
  }
});

test("generated idempotency keys are always valid 22-character base64url tokens", () => {
  const seen = new Set();
  for (let i = 0; i < 500; i += 1) {
    const key = generateIdempotencyKey();
    assert.match(key, KEY_PATTERN);
    assert.equal(key.length, 22);
    seen.add(key);
  }
  assert.equal(seen.size, 500);
});

test("default proof uses a generated key instead of the operationId", async () => {
  const proof = await proofFor(operationFor("op-with-a-length-of-17"));
  assert.match(proof.idempotencyKey, KEY_PATTERN);
  assert.notEqual(proof.idempotencyKey, "op-with-a-length-of-17");
});

test("signed proof covers the exact idempotency key string", async () => {
  const operation = operationFor();
  const proof = await proofFor(operation, "abcdefghijklmnopq");
  const swapped = { ...proof, idempotencyKey: "zyxwvutsrqponmlkj" };
  await assert.rejects(verifyAuthorizationProof(swapped, operation, { username: "alice" }), { code: "authorization_signature" });
  assert.equal(await verifyAuthorizationProof(proof, operation, { username: "alice" }), true);
});

test("proof with an invalid idempotency key is rejected during verification", async () => {
  const operation = operationFor();
  const proof = await proofFor(operation, "abcdefghijklmnopq");
  await assert.rejects(verifyAuthorizationProof({ ...proof, idempotencyKey: "bad key!" }, operation, { username: "alice" }), { message: "Invalid device authorization" });
});

test("previously accepted 36-character UUID key still validates", async () => {
  const operation = operationFor();
  const uuid = crypto.randomUUID();
  const proof = await proofFor(operation, uuid);
  assert.equal(protocol.normalizeAuthorization(proof).idempotencyKey, uuid);
  assert.equal(await verifyAuthorizationProof(proof, operation, { username: "alice" }), true);
});
