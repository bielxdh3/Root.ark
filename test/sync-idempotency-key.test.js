"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, generateIdempotencyKey, verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");

const KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const keys = crypto.generateKeyPairSync("ed25519");
const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
const trustedAlice = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey } };

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
  // A signed proof must be attached to the ORIGINAL encrypted bytes. Reusing
  // it with a new createOperation() encryption would bind stale ciphertext.
  const result = protocol.validateFreshSignedOperation({ ...operation, authorization: proof });
  assert.equal(result.authorization.idempotencyKey, "abcdefghijklmnopq");
  assert.equal(await verifyAuthorizationProof(result.authorization, result, trustedAlice), true);
});

test("every idempotency key length from 16 to 40 is accepted", async () => {
  const operation = operationFor();
  for (let length = 16; length <= 40; length += 1) {
    const key = keyOfLength(length);
    const proof = await proofFor(operation, key);
    assert.equal(protocol.normalizeAuthorization(proof).idempotencyKey, key, `length ${length}`);
  }
});

test("boundary lengths 16 and 128 are accepted, 17 is accepted, 129 (length % 4 === 1) is rejected", async () => {
  const operation = operationFor();
  for (const length of [16, 17, 128]) {
    assert.equal((await proofFor(operation, keyOfLength(length))).idempotencyKey.length, length);
  }
  await assert.rejects(proofFor(operation, keyOfLength(129)), { message: "Invalid device authorization" });
});

test("invalid characters, too short and too long keys are rejected with the same error as before", async () => {
  const operation = operationFor();
  const proof = await proofFor(operation);
  const expected = rejectionOf(() => protocol.normalizeAuthorization({ ...proof, idempotencyKey: "x" }));
  assert.deepEqual(expected, { message: "Invalid device authorization", code: "invalid_operation" });
  const invalid = [
    "a", // 1 character, length % 4 === 1 and below the canonical minimum
    "a".repeat(129), // length % 4 === 1 and above the canonical maximum
    "a".repeat(194), // above the legacy maximum of 192
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
  await assert.rejects(verifyAuthorizationProof(swapped, operation, trustedAlice), { code: "authorization_signature" });
  assert.equal(await verifyAuthorizationProof(proof, operation, trustedAlice), true);
});

test("proof with an invalid idempotency key is rejected during verification", async () => {
  const operation = operationFor();
  const proof = await proofFor(operation, "abcdefghijklmnopq");
  await assert.rejects(verifyAuthorizationProof({ ...proof, idempotencyKey: "bad key!" }, operation, trustedAlice), { message: "Invalid device authorization" });
});

test("previously accepted 36-character UUID key still validates", async () => {
  const operation = operationFor();
  const uuid = crypto.randomUUID();
  const proof = await proofFor(operation, uuid);
  assert.equal(protocol.normalizeAuthorization(proof).idempotencyKey, uuid);
  assert.equal(await verifyAuthorizationProof(proof, operation, trustedAlice), true);
});

test("historical operationId-derived keys still validate (fixtures per format)", async () => {
  const operation = operationFor();
  const hex24 = (value) => crypto.createHash("sha256").update(value).digest("hex").slice(0, 24);
  const fixtures = {
    "uuid v4 (crypto.randomUUID, 36 chars)": crypto.randomUUID(),
    "webdav composite with uuid (68 chars)": `webdav-${crypto.randomUUID()}-${hex24("a/b.txt")}`,
    "webdav composite with max-length id (192 chars)": `webdav-${"a".repeat(160)}-${hex24("max")}`,
    "short caller-supplied id, 14 chars": "auth-operation",
    "short caller-supplied id, 4 chars": "op-1",
    "caller-supplied id with underscores, 14 chars": "legacy_op_0001",
  };
  assert.equal(fixtures["webdav composite with max-length id (192 chars)"].length, 192);
  assert.equal(fixtures["webdav composite with uuid (68 chars)"].length, 68);
  for (const [name, key] of Object.entries(fixtures)) {
    const proof = await proofFor(operation, key);
    assert.equal(protocol.normalizeAuthorization(proof).idempotencyKey, key, name);
    assert.equal(await verifyAuthorizationProof(proof, operation, trustedAlice), true, name);
  }
});

test("historically rejected key shapes stay rejected", async () => {
  const operation = operationFor();
  const proof = await proofFor(operation);
  for (const key of ["webdav:id.with.dots-0123456789ab", "op:colon:0001", "bad+base64/key=", "x".repeat(193)]) {
    assert.throws(() => protocol.normalizeAuthorization({ ...proof, idempotencyKey: key }), { message: "Invalid device authorization" }, key);
  }
});
