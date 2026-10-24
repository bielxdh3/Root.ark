"use strict";

// Isolated, opt-in development transport for encrypted browser-owned files.
// NOT a ZK-1 keyring or recovery authority. The server stores only ciphertext.
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");

const MAX_CIPHERTEXT_BYTES = 7 * 1024 * 1024;
const MAX_OBJECTS_PER_OWNER = 1000;
const DEFAULT_OWNER_BYTES = 128 * 1024 * 1024;
const DEFAULT_TOTAL_BYTES = 512 * 1024 * 1024;
const DEFAULT_LIFETIME_IDS_PER_OWNER = 100_000;
const DEFAULT_GLOBAL_IDS = 500_000;
const OBJECT_ID_PATTERN = /^[A-Za-z0-9_-]{22}$/;
const B64U = /^[A-Za-z0-9_-]+$/;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function strictFields(object, fields) {
  if (!object || typeof object !== "object" || Array.isArray(object)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(object))) fail("VAULT_INVALID");
  const actual = Reflect.ownKeys(object);
  if (actual.length !== fields.length || fields.some((k) => !Object.hasOwn(object, k))
    || actual.some((k) => typeof k !== "string" || !fields.includes(k))) fail("VAULT_INVALID");
}
function decode(value, { min = 0, max = MAX_CIPHERTEXT_BYTES } = {}) {
  if (typeof value !== "string" || value.length > Math.ceil(max * 4 / 3) + 4
    || !B64U.test(value) || value.length % 4 === 1) fail("VAULT_INVALID");
  const raw = Buffer.from(value, "base64url");
  if (raw.length < min || raw.length > max || raw.toString("base64url") !== value) fail("VAULT_INVALID");
  return raw;
}
function validateEnvelope(envelope) {
  strictFields(envelope, ["format", "algorithm", "iv", "ciphertext"]);
  if (envelope.format !== "rootark-dev-file-v1" || envelope.algorithm !== "AES-256-GCM") fail("VAULT_INVALID");
  decode(envelope.iv, { min: 12, max: 12 });
  decode(envelope.ciphertext, { min: 16 });
  return JSON.stringify({
    format: envelope.format, algorithm: envelope.algorithm,
    iv: envelope.iv, ciphertext: envelope.ciphertext,
  });
}
function validateOwner(owner) {
  if (typeof owner !== "string" || owner.length < 1 || owner.length > 256
    || /[\u0000-\u001f\u007f]/.test(owner)) fail("VAULT_INVALID");
  return owner;
}
function validateId(id) {
  if (typeof id !== "string" || !OBJECT_ID_PATTERN.test(id)) fail("VAULT_INVALID");
  decode(id, { min: 16, max: 16 });
  return id;
}
function revision(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value >= Number.MAX_SAFE_INTEGER) fail("VAULT_INVALID");
  return value;
}
class OpaqueDevVaultStore {
  constructor(filePath, options = {}) {
    this.maxObjectsPerOwner = options.maxObjectsPerOwner ?? MAX_OBJECTS_PER_OWNER;
    this.maxOwnerBytes = options.maxOwnerBytes ?? DEFAULT_OWNER_BYTES;
    this.maxTotalBytes = options.maxTotalBytes ?? DEFAULT_TOTAL_BYTES;
    this.maxLifetimeIdsPerOwner = options.maxLifetimeIdsPerOwner ?? DEFAULT_LIFETIME_IDS_PER_OWNER;
    this.maxGlobalIds = options.maxGlobalIds ?? DEFAULT_GLOBAL_IDS;
    if (!Number.isSafeInteger(this.maxObjectsPerOwner) || this.maxObjectsPerOwner < 1
      || this.maxObjectsPerOwner > MAX_OBJECTS_PER_OWNER
      || !Number.isSafeInteger(this.maxLifetimeIdsPerOwner)
      || this.maxLifetimeIdsPerOwner < this.maxObjectsPerOwner
      || this.maxLifetimeIdsPerOwner > DEFAULT_LIFETIME_IDS_PER_OWNER
      || !Number.isSafeInteger(this.maxGlobalIds)
      || this.maxGlobalIds < this.maxLifetimeIdsPerOwner
      || this.maxGlobalIds > DEFAULT_GLOBAL_IDS
      || !Number.isSafeInteger(this.maxOwnerBytes) || this.maxOwnerBytes < 1
      || !Number.isSafeInteger(this.maxTotalBytes)
      || this.maxTotalBytes < this.maxOwnerBytes) fail("VAULT_INVALID");
    const absolute = path.resolve(filePath);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    this.db = new Database(absolute);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = FULL");
    this.db.exec("CREATE TABLE IF NOT EXISTS opaque_dev_objects ("
      + "owner TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL, key_id TEXT, "
      + "envelope TEXT, deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0,1)), "
      + "PRIMARY KEY(owner,id))");
    // Preserve any early development rows without guessing which user-held key
    // encrypted them. Keyless legacy rows block new writes while active.
    if (!this.db.pragma("table_info(opaque_dev_objects)")
      .some((column) => column.name === "key_id")) {
      this.db.exec("ALTER TABLE opaque_dev_objects ADD COLUMN key_id TEXT");
    }
    this.findActive = this.db.prepare("SELECT revision,envelope,key_id FROM opaque_dev_objects WHERE owner=? AND id=? AND deleted=0");
    this.listActive = this.db.prepare("SELECT id,revision FROM opaque_dev_objects WHERE owner=? AND deleted=0 ORDER BY id LIMIT ?");
    this.activeKey = this.db.prepare("SELECT key_id FROM opaque_dev_objects WHERE owner=? AND deleted=0 LIMIT 1");
    this.count = this.db.prepare("SELECT COUNT(*) AS count FROM opaque_dev_objects WHERE owner=? AND deleted=0");
    this.findAny = this.db.prepare("SELECT 1 FROM opaque_dev_objects WHERE owner=? AND id=?");
    this.lifetimeCount = this.db.prepare("SELECT COUNT(*) AS count FROM opaque_dev_objects WHERE owner=?");
    this.globalCount = this.db.prepare("SELECT COUNT(*) AS count FROM opaque_dev_objects");
    this.ownerBytes = this.db.prepare("SELECT COALESCE(SUM(LENGTH(envelope)),0) AS bytes FROM opaque_dev_objects WHERE owner=? AND deleted=0");
    this.totalBytes = this.db.prepare("SELECT COALESCE(SUM(LENGTH(envelope)),0) AS bytes FROM opaque_dev_objects WHERE deleted=0");
    this.insert = this.db.prepare("INSERT OR IGNORE INTO opaque_dev_objects(owner,id,revision,envelope,deleted,key_id) VALUES(?,?,1,?,0,?)");
    this.update = this.db.prepare("UPDATE opaque_dev_objects SET revision=revision+1,envelope=?,deleted=? WHERE owner=? AND id=? AND revision=? AND deleted=0");
  }
  checkQuota(owner, replacementByteLength, priorByteLength = 0) {
    const delta = replacementByteLength - priorByteLength;
    if (this.ownerBytes.get(owner).bytes + delta > this.maxOwnerBytes
      || this.totalBytes.get().bytes + delta > this.maxTotalBytes) fail("VAULT_LIMIT");
  }
  activeKeyId(owner) {
    validateOwner(owner);
    const row = this.activeKey.get(owner);
    return row ? row.key_id || "legacy-unbound" : null;
  }
  create(owner, input) {
    validateOwner(owner);
    strictFields(input, ["id", "envelope", "keyId"]);
    const id = validateId(input.id);
    const keyId = input.keyId;
    decode(keyId, { min: 32, max: 32 });
    const serialized = validateEnvelope(input.envelope);
    return this.db.transaction(() => {
      // Tombstones preserve replay rejection but no longer consume the quota
      // for LIVE files. An old ID cannot be resurrected after deletion.
      if (this.findAny.get(owner, id)) fail("VAULT_CONFLICT");
      const activeKey = this.activeKeyId(owner);
      if (activeKey !== null && activeKey !== keyId) fail("VAULT_KEY_MISMATCH");
      if (this.count.get(owner).count >= this.maxObjectsPerOwner) fail("VAULT_LIMIT");
      // Do not delete old tombstones to make space: that would reopen replayed
      // IDs. Bound their permanent metadata growth until a versioned archival
      // and compaction protocol can preserve the same replay guarantees.
      if (this.lifetimeCount.get(owner).count >= this.maxLifetimeIdsPerOwner
        || this.globalCount.get().count >= this.maxGlobalIds) fail("VAULT_LIMIT");
      this.checkQuota(owner, Buffer.byteLength(serialized));
      if (!this.insert.run(owner, id, serialized, keyId).changes) fail("VAULT_CONFLICT");
      return { id, revision: 1 };
    }).immediate();
  }
  list(owner) {
    validateOwner(owner);
    return this.listActive.all(owner, this.maxObjectsPerOwner);
  }
  get(owner, id) {
    validateOwner(owner);
    validateId(id);
    const row = this.findActive.get(owner, id);
    return row ? { id, revision: row.revision, keyId: row.key_id,
      envelope: JSON.parse(row.envelope) } : null;
  }
  replace(owner, input) {
    validateOwner(owner);
    strictFields(input, ["id", "expectedRevision", "envelope", "keyId"]);
    const id = validateId(input.id);
    const keyId = input.keyId;
    decode(keyId, { min: 32, max: 32 });
    const expected = revision(input.expectedRevision);
    const serialized = validateEnvelope(input.envelope);
    return this.db.transaction(() => {
      const current = this.findActive.get(owner, id);
      if (!current) fail("VAULT_NOT_FOUND");
      if (current.key_id !== keyId) fail("VAULT_KEY_MISMATCH");
      this.checkQuota(owner, Buffer.byteLength(serialized), Buffer.byteLength(current.envelope));
      if (!this.update.run(serialized, 0, owner, id, expected).changes) fail("VAULT_CONFLICT");
      return { id, revision: expected + 1 };
    }).immediate();
  }
  remove(owner, input) {
    validateOwner(owner);
    strictFields(input, ["id", "expectedRevision"]);
    const id = validateId(input.id);
    const expected = revision(input.expectedRevision);
    return this.db.transaction(() => {
      if (!this.findActive.get(owner, id)) fail("VAULT_NOT_FOUND");
      if (!this.update.run(null, 1, owner, id, expected).changes) fail("VAULT_CONFLICT");
      return { id, revision: expected + 1, deleted: true };
    }).immediate();
  }
  close() { this.db.close(); }
}
module.exports = { OpaqueDevVaultStore };
