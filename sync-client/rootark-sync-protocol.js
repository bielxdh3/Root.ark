"use strict";

const crypto = require("node:crypto");
const { validatePortableRelativePath } = require("./rootark-sync-paths");

const PROTOCOL_VERSION = 2;
const MAX_ID_LENGTH = 160;
const MAX_METADATA_BYTES = 16 * 1024;
const MOVE_PAYLOAD_MAGIC = Buffer.from("ROOTARK-SYNC-MOVE\0v1\0", "utf8");
const MOVE_PAYLOAD_LENGTH_BYTES = 8;
const MOVE_PAYLOAD_MAC_BYTES = 32;
const OPERATIONS = new Set(["create", "update", "move", "delete"]);
const METADATA_KEYS = [
  "fileId", "versionId", "path", "parentId", "name", "contentType", "size",
  "keyEpoch", "compartmentId", "deviceId", "sourcePath",
];
const METADATA_KEYS_BY_OPERATION = Object.freeze({
  create: new Set(METADATA_KEYS.filter((key) => key !== "sourcePath")),
  update: new Set(METADATA_KEYS.filter((key) => key !== "sourcePath")),
  move: new Set(["fileId", "versionId", "path", "sourcePath", "keyEpoch", "compartmentId", "deviceId"]),
  delete: new Set(["fileId", "versionId", "path", "keyEpoch", "compartmentId", "deviceId"]),
});
const OPERATION_FIELDS = Object.freeze([
  "protocolVersion", "operationId", "objectId", "fileId", "versionId", "operation",
  "revision", "baseRevision", "keyEpoch", "compartmentId", "deviceId", "metadata",
  "tombstone", "ciphertext", "nonce", "tag", "aad", "authorization",
]);
const OPTIONAL_OPERATION_FIELDS = new Set(["authorization"]);
const AUTHORIZATION_FIELDS = Object.freeze([
  "schemaVersion", "type", "suite", "protocolVersion", "username", "deviceId", "operationId",
  "objectId", "fileId", "versionId", "operation", "revision", "baseRevision", "keyEpoch",
  "compartmentId", "metadata", "aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest",
  "expiresAt", "replayId", "idempotencyKey", "publicKey", "signature",
]);

function fail(message, code = "invalid_operation") {
  throw Object.assign(new Error(message), { code });
}

function id(value, name) {
  const result = String(value || "");
  if (!result || result.length > MAX_ID_LENGTH || !/^[A-Za-z0-9._:-]+$/.test(result)) fail(`Invalid ${name}`);
  return result;
}

function revision(value, name = "revision") {
  if (!value || !Number.isSafeInteger(value.counter) || value.counter < 0) fail(`Invalid ${name}`);
  return { counter: value.counter, deviceId: id(value.deviceId, `${name}.deviceId`) };
}

function compareRevisions(left, right) {
  if (!left && !right) return 0;
  if (!left) return -1;
  if (!right) return 1;
  return left.counter - right.counter || left.deviceId.localeCompare(right.deviceId);
}

function canonicalize(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  return Object.keys(value).sort().reduce((result, key) => {
    result[key] = canonicalize(value[key]);
    return result;
  }, {});
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function assertExactKeys(input, allowed, name) {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(input)) {
    if (!allowedSet.has(key)) fail(`Unknown ${name} field: ${key}`);
  }
}

function safeRelativePath(value, name) {
  try { return validatePortableRelativePath(value, `metadata.${name}`); } catch { fail(`Invalid metadata.${name}`); }
}

function normalizeMetadata(input = {}, allowedKeys = METADATA_KEYS) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail("Invalid metadata");
  assertExactKeys(input, allowedKeys, "metadata");
  const result = {};
  for (const key of allowedKeys) {
    if (!Object.hasOwn(input, key) || input[key] === undefined || input[key] === null) continue;
    const value = input[key];
    if (key === "size") {
      if (!Number.isSafeInteger(value) || value < 0) fail("Invalid metadata.size");
      result[key] = value;
    } else if (["path", "sourcePath"].includes(key)) {
      result[key] = safeRelativePath(value, key);
    } else if (["name", "contentType"].includes(key)) {
      const text = String(value);
      if (!text || text.length > 512 || /[\u0000-\u001f\u007f]/.test(text)) fail(`Invalid metadata.${key}`);
      result[key] = text;
    } else {
      result[key] = id(value, `metadata.${key}`);
    }
  }
  if (Buffer.byteLength(canonicalJson(result)) > MAX_METADATA_BYTES) fail("Metadata too large", "payload_too_large");
  return canonicalize(result);
}

function assertFileKey(fileKey) {
  const key = Buffer.isBuffer(fileKey) ? fileKey : Buffer.from(fileKey || []);
  if (key.length !== 32) fail("A 32-byte per-file key is required");
  return key;
}

function aadFor(operation) {
  return canonicalJson({
    protocolVersion: PROTOCOL_VERSION,
    objectId: operation.objectId,
    fileId: operation.fileId,
    versionId: operation.versionId,
    operation: operation.operation,
    revision: operation.revision,
    baseRevision: operation.baseRevision || null,
    keyEpoch: operation.keyEpoch,
    compartmentId: operation.compartmentId,
    deviceId: operation.deviceId,
    metadata: operation.metadata,
    tombstone: operation.tombstone,
  });
}

function normalizeAuthorization(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("Invalid device authorization");
  assertExactKeys(value, AUTHORIZATION_FIELDS, "authorization");
  if (AUTHORIZATION_FIELDS.some((field) => !Object.hasOwn(value, field)) || value.schemaVersion !== 1 || value.type !== "rootark-sync-device-authorization-v1" || value.suite !== "rootark-zk-1" || value.protocolVersion !== PROTOCOL_VERSION) fail("Invalid device authorization");
  if (!Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now()) fail("Expired device authorization", "authorization_expired");
  for (const field of ["aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest", "replayId", "idempotencyKey", "publicKey", "signature"]) {
    if (typeof value[field] !== "string" || !/^[A-Za-z0-9_-]+$/.test(value[field]) || value[field].length % 4 === 1) fail("Invalid device authorization");
  }
  return canonicalize(value);
}

function encryptPayload(operation, plaintext, fileKey) {
  const key = assertFileKey(fileKey);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  const aad = Buffer.from(aadFor(operation), "utf8");
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return {
    ciphertext: ciphertext.toString("base64url"),
    nonce: nonce.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    aad: aad.toString("base64url"),
  };
}

function decodeBase64Url(value, field) {
  if (typeof value !== "string" || (field !== "ciphertext" && !value) || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    fail(`Invalid encrypted field: ${field}`, "invalid_envelope");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) fail(`Invalid encrypted field: ${field}`, "invalid_envelope");
  if (field === "nonce" && decoded.length !== 12 || field === "tag" && decoded.length !== 16) {
    fail(`Invalid encrypted field: ${field}`, "invalid_envelope");
  }
  return decoded;
}

function decryptPayload(operation, fileKey) {
  if (typeof operation.ciphertext !== "string" || !operation.nonce || !operation.tag || !operation.aad) fail("Encrypted payload is incomplete");
  const key = assertFileKey(fileKey);
  const ciphertext = decodeBase64Url(operation.ciphertext, "ciphertext");
  const nonce = decodeBase64Url(operation.nonce, "nonce");
  const tag = decodeBase64Url(operation.tag, "tag");
  const aad = decodeBase64Url(operation.aad, "aad");
  const expectedAad = Buffer.from(aadFor(operation), "utf8");
  if (aad.length !== expectedAad.length || !crypto.timingSafeEqual(aad, expectedAad)) fail("AAD binding mismatch", "aad_mismatch");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function encodeMovePayload(plaintext, fileKey) {
  const key = assertFileKey(fileKey);
  const content = Buffer.from(plaintext ?? []);
  const length = Buffer.alloc(MOVE_PAYLOAD_LENGTH_BYTES);
  length.writeBigUInt64BE(BigInt(content.length));
  const header = Buffer.concat([MOVE_PAYLOAD_MAGIC, length]);
  const mac = crypto.createHmac("sha256", key).update(header).update(content).digest();
  return Buffer.concat([header, mac, content]);
}

function decodeMovePayload(plaintext, fileKey) {
  const payload = Buffer.from(plaintext ?? []);
  if (payload.length < MOVE_PAYLOAD_MAGIC.length || !payload.subarray(0, MOVE_PAYLOAD_MAGIC.length).equals(MOVE_PAYLOAD_MAGIC)) return null;
  const headerSize = MOVE_PAYLOAD_MAGIC.length + MOVE_PAYLOAD_LENGTH_BYTES;
  const contentOffset = headerSize + MOVE_PAYLOAD_MAC_BYTES;
  if (payload.length < contentOffset) return null;
  const header = payload.subarray(0, headerSize);
  const contentLength = payload.readBigUInt64BE(MOVE_PAYLOAD_MAGIC.length);
  if (contentLength > BigInt(Number.MAX_SAFE_INTEGER) || BigInt(payload.length - contentOffset) !== contentLength) return null;
  const mac = payload.subarray(headerSize, contentOffset);
  const content = payload.subarray(contentOffset);
  const expectedMac = crypto.createHmac("sha256", assertFileKey(fileKey)).update(header).update(content).digest();
  if (!crypto.timingSafeEqual(mac, expectedMac)) return null;
  return Buffer.from(content);
}

function createOperation(input = {}) {
  const operation = String(input.operation || "");
  if (!OPERATIONS.has(operation)) fail("Invalid sync operation");
  const objectId = id(input.objectId || crypto.randomUUID(), "objectId");
  const fileId = id(input.fileId || objectId, "fileId");
  const versionId = id(input.versionId || crypto.randomUUID(), "versionId");
  const deviceId = id(input.deviceId, "deviceId");
  const keyEpoch = id(input.keyEpoch, "keyEpoch");
  const compartmentId = id(input.compartmentId, "compartmentId");
  const baseRevision = input.baseRevision == null ? null : revision(input.baseRevision, "baseRevision");
  const result = {
    protocolVersion: PROTOCOL_VERSION,
    operationId: id(input.operationId || crypto.randomUUID(), "operationId"),
    objectId,
    fileId,
    versionId,
    operation,
    revision: revision(input.revision, "revision"),
    baseRevision,
    keyEpoch,
    compartmentId,
    deviceId,
    metadata: normalizeMetadata(
      { ...input.metadata, fileId, versionId, keyEpoch, compartmentId, deviceId },
      METADATA_KEYS_BY_OPERATION[operation],
    ),
    tombstone: operation === "delete",
  };
  const plaintext = input.plaintext === undefined ? Buffer.from("{}", "utf8") : input.plaintext;
  Object.assign(result, encryptPayload(result, plaintext, input.fileKey));
  if (input.authorization !== undefined) result.authorization = normalizeAuthorization(input.authorization);
  return result;
}

function validateOperation(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail("Invalid operation");
  if (input.protocolVersion !== PROTOCOL_VERSION) fail("Unsupported sync protocol version", "invalid_protocol_version");
  assertExactKeys(input, OPERATION_FIELDS, "operation");
  for (const field of OPERATION_FIELDS) {
    if (!OPTIONAL_OPERATION_FIELDS.has(field) && !Object.hasOwn(input, field)) fail(`Missing operation field: ${field}`);
  }
  const operation = createOperation({ ...input, plaintext: Buffer.alloc(0), fileKey: Buffer.alloc(32) });
  if (input.tombstone !== operation.tombstone) fail("Invalid tombstone flag");
  if (!operation.metadata.path) fail("Operation metadata.path is required");
  if (operation.operation === "move" && !operation.metadata.sourcePath) fail("Move metadata.sourcePath is required");
  for (const field of ["ciphertext", "nonce", "tag", "aad"]) {
    if (typeof input[field] !== "string" || (field !== "ciphertext" && !input[field])) fail(`Missing encrypted field: ${field}`);
  }
  decodeBase64Url(input.ciphertext, "ciphertext");
  decodeBase64Url(input.nonce, "nonce");
  decodeBase64Url(input.tag, "tag");
  const aad = decodeBase64Url(input.aad, "aad");
  const expectedAad = Buffer.from(aadFor(operation), "utf8");
  if (aad.length !== expectedAad.length || !crypto.timingSafeEqual(aad, expectedAad)) fail("AAD binding mismatch", "aad_mismatch");
  return { ...operation, ciphertext: input.ciphertext, nonce: input.nonce, tag: input.tag, aad: input.aad };
}

function nextRevision(current, deviceId) {
  const device = id(deviceId, "deviceId");
  return { counter: Math.max(0, Number(current?.counter) || 0) + 1, deviceId: device };
}

module.exports = {
  OPERATION_FIELDS,
  PROTOCOL_VERSION,
  OPERATIONS,
  METADATA_KEYS,
  canonicalJson,
  compareRevisions,
  createOperation,
  decodeMovePayload,
  decryptPayload,
  encodeMovePayload,
  nextRevision,
  normalizeMetadata,
  normalizeAuthorization,
  safeRelativePath,
  validateOperation,
  OPTIONAL_OPERATION_FIELDS,
};
