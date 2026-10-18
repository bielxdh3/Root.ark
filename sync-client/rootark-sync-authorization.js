"use strict";

const crypto = require("node:crypto");
const zk = require("../src/crypto/rootark-zk-1");

const PROOF_FIELDS = Object.freeze([
  "schemaVersion", "type", "suite", "protocolVersion", "username", "deviceId", "operationId",
  "objectId", "fileId", "versionId", "operation", "revision", "baseRevision", "keyEpoch",
  "compartmentId", "metadata", "aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest",
  "expiresAt", "replayId", "idempotencyKey", "publicKey", "signature",
]);

function fail(message, code = "invalid_device_authorization") {
  throw Object.assign(new Error(message), { code });
}

// idempotencyKey is an opaque token: validated by charset and length only, never decoded as base64.
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const GENERATED_IDEMPOTENCY_KEY_BYTES = 16;

function isValidIdempotencyKey(value) {
  return typeof value === "string" && IDEMPOTENCY_KEY_PATTERN.test(value);
}

function generateIdempotencyKey() {
  return crypto.randomBytes(GENERATED_IDEMPOTENCY_KEY_BYTES).toString("base64url");
}

function text(value, name) {
  if (typeof value !== "string" || !value || value.length > 512) fail(`Invalid authorization ${name}`);
  return value;
}

function digest(value, name) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) fail(`Invalid authorization ${name}`);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== value) fail(`Invalid authorization ${name}`);
  return bytes;
}

function exact(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((key) => !PROOF_FIELDS.includes(key)) || PROOF_FIELDS.some((key) => !Object.hasOwn(value, key))) fail("Invalid authorization schema");
}

function proofCore(operation, options) {
  const expiresAt = Number(options.expiresAt || Date.now() + 5 * 60 * 1000);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now()) fail("Authorization expired");
  const replayId = options.replayId || crypto.randomBytes(16).toString("base64url");
  const idempotencyKey = options.idempotencyKey === undefined ? generateIdempotencyKey() : options.idempotencyKey;
  if (!isValidIdempotencyKey(idempotencyKey)) fail("Invalid device authorization");
  return {
    schemaVersion: 1,
    type: "rootark-sync-device-authorization-v1",
    suite: zk.SUITE_ID,
    protocolVersion: operation.protocolVersion,
    username: text(options.username, "username"),
    deviceId: text(operation.deviceId, "deviceId"),
    operationId: text(operation.operationId, "operationId"),
    objectId: text(operation.objectId, "objectId"),
    fileId: text(operation.fileId, "fileId"),
    versionId: text(operation.versionId, "versionId"),
    operation: text(operation.operation, "operation"),
    revision: operation.revision,
    baseRevision: operation.baseRevision || null,
    keyEpoch: text(operation.keyEpoch, "keyEpoch"),
    compartmentId: text(operation.compartmentId, "compartmentId"),
    metadata: operation.metadata,
    aadDigest: crypto.createHash("sha256").update(Buffer.from(operation.aad, "base64url")).digest().toString("base64url"),
    ciphertextDigest: crypto.createHash("sha256").update(Buffer.from(operation.ciphertext, "base64url")).digest().toString("base64url"),
    nonceDigest: crypto.createHash("sha256").update(Buffer.from(operation.nonce, "base64url")).digest().toString("base64url"),
    tagDigest: crypto.createHash("sha256").update(Buffer.from(operation.tag, "base64url")).digest().toString("base64url"),
    expiresAt,
    replayId,
    idempotencyKey,
    publicKey: text(options.publicKey, "publicKey"),
    signature: "",
  };
}

async function signedBytes(core) {
  const { signature: _signature, ...unsigned } = core;
  return Buffer.concat([Buffer.from(zk.ASCII.AUTHORIZATION, "ascii"), Buffer.from([0]), await zk.encodeDeterministic(unsigned)]);
}

async function createAuthorizationProof(operation, options = {}) {
  if (!options.privateKey || !options.publicKey) fail("Authorization key material is required");
  const core = proofCore(operation, options);
  core.signature = crypto.sign(null, await signedBytes(core), options.privateKey).toString("base64url");
  return core;
}

async function verifyAuthorizationProof(proof, operation, expected = {}) {
  exact(proof);
  const normalized = { ...proof };
  if (!isValidIdempotencyKey(normalized.idempotencyKey)) fail("Invalid device authorization");
  if (normalized.schemaVersion !== 1 || normalized.type !== "rootark-sync-device-authorization-v1" || normalized.suite !== zk.SUITE_ID) fail("Unsupported authorization proof");
  if (normalized.expiresAt < Date.now()) fail("Authorization expired", "authorization_expired");
  if (normalized.protocolVersion !== operation.protocolVersion || normalized.username !== expected.username || normalized.deviceId !== operation.deviceId) fail("Authorization scope mismatch", "authorization_scope");
  const expectedCore = proofCore(operation, { username: normalized.username, publicKey: normalized.publicKey, expiresAt: normalized.expiresAt, replayId: normalized.replayId, idempotencyKey: normalized.idempotencyKey });
  for (const field of ["operationId", "objectId", "fileId", "versionId", "operation", "revision", "baseRevision", "keyEpoch", "compartmentId", "metadata", "aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest"]) {
    if (JSON.stringify(normalized[field]) !== JSON.stringify(expectedCore[field])) fail("Authorization payload mismatch", "authorization_scope");
  }
  const key = crypto.createPublicKey({ key: Buffer.from(normalized.publicKey, "base64url"), format: "der", type: "spki" });
  if (!crypto.verify(null, await signedBytes(normalized), key, Buffer.from(normalized.signature, "base64url"))) fail("Authorization signature invalid", "authorization_signature");
  return true;
}

module.exports = { PROOF_FIELDS, IDEMPOTENCY_KEY_PATTERN, createAuthorizationProof, generateIdempotencyKey, isValidIdempotencyKey, verifyAuthorizationProof };
