"use strict";

// Local engineering store for PUBLIC, signed zk-1 v2 manifests only.
// A single SQLite database is NOT a shared CAS, independently witnessed
// status authority, or rollback-resistant client high-water mark.
// Do not connect protected-content admission to this class alone.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const z = require("../crypto/rootark-zk-1");
const v2 = require("../crypto/rootark-zk-recovery-manifest-v2");
const limits = require("../crypto/rootark-zk-recovery-history-v2");

const DIGEST_PREFIX = Buffer.from("Root.ark/zk-1/recovery-manifest-digest/v1\0", "ascii");
const DEFAULT_MAX_OWNER_SCOPES = 8;
const DEFAULT_MAX_GLOBAL_SCOPES = 64;
const DEFAULT_MAX_OWNER_BYTES = 128 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function buf(value, min, max) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < min || value.byteLength > max) fail("ZK1_HISTORY_INVALID");
  return Buffer.from(value);
}
function scopeId(accountId, compartmentId, keyringId) {
  const id = buf(accountId, 16, 16);
  const compartment = buf(compartmentId, 1, 128);
  const keyring = buf(keyringId, 16, 16);
  return Buffer.concat([id, Buffer.from([compartment.length]), compartment, keyring]).toString("hex");
}
function ownerId(value) {
  if (typeof value !== "string" || !value.length || value.length > 256
    || /[\u0000-\u001f\u007f]/.test(value)) fail("ZK1_HISTORY_INVALID");
  return value;
}
function digestManifest(raw) {
  return crypto.createHash("sha256").update(DIGEST_PREFIX).update(raw).digest();
}
function same(left, right) {
  return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.length === right.length
    && crypto.timingSafeEqual(left, right);
}
function serialRevision(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail("ZK1_HISTORY_INVALID");
  return value;
}

class Zk1LocalSignedHistoryStore {
  constructor(filename, options = {}) {
    if (typeof filename !== "string" || !filename.length) fail("ZK1_HISTORY_INVALID");
    this.nowSeconds = options.nowSeconds || (() => Math.floor(Date.now() / 1000));
    if (typeof this.nowSeconds !== "function") fail("ZK1_HISTORY_INVALID");
    this.maxScopesPerOwner = options.maxScopesPerOwner ?? DEFAULT_MAX_OWNER_SCOPES;
    this.maxGlobalScopes = options.maxGlobalScopes ?? DEFAULT_MAX_GLOBAL_SCOPES;
    this.maxOwnerBytes = options.maxOwnerBytes ?? DEFAULT_MAX_OWNER_BYTES;
    this.maxTotalBytes = options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;
    if (![this.maxScopesPerOwner, this.maxGlobalScopes,
      this.maxOwnerBytes, this.maxTotalBytes].every(Number.isSafeInteger)
      || this.maxScopesPerOwner < 1 || this.maxScopesPerOwner > DEFAULT_MAX_OWNER_SCOPES
      || this.maxGlobalScopes < this.maxScopesPerOwner
      || this.maxGlobalScopes > DEFAULT_MAX_GLOBAL_SCOPES
      || this.maxOwnerBytes < 1 || this.maxOwnerBytes > DEFAULT_MAX_OWNER_BYTES
      || this.maxTotalBytes < this.maxOwnerBytes
      || this.maxTotalBytes > DEFAULT_MAX_TOTAL_BYTES) fail("ZK1_HISTORY_INVALID");
    const absolute = path.resolve(filename);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    this.db = new Database(absolute);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = FULL");
    this.db.pragma("foreign_keys = ON");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS zk1_local_scope (
        owner TEXT NOT NULL, scope_id TEXT NOT NULL, revision INTEGER NOT NULL,
        digest BLOB NOT NULL, entry_count INTEGER NOT NULL, history_bytes INTEGER NOT NULL,
        PRIMARY KEY (owner,scope_id)
      );
      CREATE TABLE IF NOT EXISTS zk1_local_history (
        owner TEXT NOT NULL, scope_id TEXT NOT NULL, revision INTEGER NOT NULL,
        digest BLOB NOT NULL, operation_id BLOB NOT NULL, manifest_bytes BLOB NOT NULL,
        PRIMARY KEY (owner,scope_id,revision),
        UNIQUE (owner,scope_id,operation_id),
        FOREIGN KEY (owner,scope_id) REFERENCES zk1_local_scope(owner,scope_id)
      );
      CREATE TABLE IF NOT EXISTS zk1_local_identifier (
        owner TEXT NOT NULL, scope_id TEXT NOT NULL, identifier TEXT NOT NULL,
        PRIMARY KEY (owner,scope_id,identifier),
        FOREIGN KEY (owner,scope_id) REFERENCES zk1_local_scope(owner,scope_id)
      );
    `);
    this.findHead = this.db.prepare(
      "SELECT revision,digest,entry_count,history_bytes FROM zk1_local_scope WHERE owner=? AND scope_id=?");
    this.findLatest = this.db.prepare(
      "SELECT manifest_bytes FROM zk1_local_history WHERE owner=? AND scope_id=? ORDER BY revision DESC LIMIT 1");
    this.ownerTotals = this.db.prepare(
      "SELECT COUNT(*) AS scopes, COALESCE(SUM(history_bytes),0) AS bytes FROM zk1_local_scope WHERE owner=?");
    this.globalTotals = this.db.prepare(
      "SELECT COUNT(*) AS scopes, COALESCE(SUM(history_bytes),0) AS bytes FROM zk1_local_scope");
    this.allEntries = this.db.prepare(
      "SELECT revision,digest,manifest_bytes FROM zk1_local_history WHERE owner=? AND scope_id=? ORDER BY revision");
    this.allIdentifiers = this.db.prepare(
      "SELECT identifier FROM zk1_local_identifier WHERE owner=? AND scope_id=?");
    this.createScope = this.db.prepare(
      "INSERT INTO zk1_local_scope(owner,scope_id,revision,digest,entry_count,history_bytes) VALUES (?,?,?,?,?,?)");
    this.updateScope = this.db.prepare(
      "UPDATE zk1_local_scope SET revision=?,digest=?,entry_count=?,history_bytes=? WHERE owner=? AND scope_id=? AND revision=? AND digest=?");
    this.insertEntry = this.db.prepare(
      "INSERT INTO zk1_local_history(owner,scope_id,revision,digest,operation_id,manifest_bytes) VALUES (?,?,?,?,?,?)");
    this.insertIdentifier = this.db.prepare(
      "INSERT INTO zk1_local_identifier(owner,scope_id,identifier) VALUES (?,?,?)");
  }

  async append(input) {
    if (!input || typeof input !== "object" || Array.isArray(input)
      || Reflect.ownKeys(input).length !== 4
      || ["owner", "manifestBytes", "expectedRevision", "expectedDigest"]
        .some((field) => !Object.hasOwn(input, field))) fail("ZK1_HISTORY_INVALID");
    const owner = ownerId(input.owner);
    const raw = buf(input.manifestBytes, 1, limits.MAX_ENTRY_BYTES);
    const expectedRevision = serialRevision(input.expectedRevision);
    const expectedDigest = expectedRevision === 0
      ? (input.expectedDigest === null ? null : fail("ZK1_HISTORY_INVALID"))
      : buf(input.expectedDigest, 32, 32);
    let manifest;
    try {
      manifest = await z.decodeDeterministic(raw);
      const canonical = await z.encodeDeterministic(manifest);
      if (!raw.equals(Buffer.from(canonical))) fail("ZK1_HISTORY_INVALID");
      v2.validateManifestShape(manifest);
    } catch (_) { fail("ZK1_HISTORY_INVALID"); }
    const scope = {
      account_id: Buffer.from(manifest.account_id),
      compartment_id: Buffer.from(manifest.compartment_id),
      keyring_id: Buffer.from(manifest.keyring_id),
    };
    const key = scopeId(scope.account_id, scope.compartment_id, scope.keyring_id);
    let prior;
    let retained;
    let priorBytes;
    let oldIdentifiers;
    const assertStorageQuota = (current) => {
      const accountTotals = this.ownerTotals.get(owner);
      const globalTotals = this.globalTotals.get();
      if ((!current && (accountTotals.scopes >= this.maxScopesPerOwner
        || globalTotals.scopes >= this.maxGlobalScopes))
        || accountTotals.bytes + raw.length > this.maxOwnerBytes
        || globalTotals.bytes + raw.length > this.maxTotalBytes) {
        fail("ZK1_HISTORY_LIMIT");
      }
    };
    // An SQLite read transaction gives head, full history and identifier
    // ledger one coherent view even if another process commits concurrently.
    this.db.transaction(() => {
      prior = this.findHead.get(owner, key);
      if ((!prior && expectedRevision !== 0)
        || (prior && (prior.revision !== expectedRevision
          || !same(prior.digest, expectedDigest)))) fail("ZK1_HISTORY_CONFLICT");
      assertStorageQuota(prior);
      if (prior) {
        // Internal consistency only; full coherent DB rollback still
        // requires an independent freshness witness to detect.
        retained = this.snapshot({ owner, ...scope });
        priorBytes = Buffer.from(this.findLatest.get(owner, key).manifest_bytes);
      }
      oldIdentifiers = this.allIdentifiers.all(owner, key).map((row) => row.identifier);
    })();
    const previousManifest = priorBytes ? await z.decodeDeterministic(priorBytes) : null;
    const oldSet = new Set(oldIdentifiers);
    if (prior) {
      // An append-only digest chain is incomplete evidence if the separate
      // retained-ID table was damaged or surgically pruned. Rebuild the ID
      // inventory from all historical, bounded signed entries before any
      // new mutation. This is an internal consistency check, NOT defense
      // against a full coherent SQLite rollback by the same administrator.
      const rebuilt = new Set();
      for (const bytes of retained.entries) {
        let historic;
        try { historic = await z.decodeDeterministic(bytes); }
        catch (_) { fail("ZK1_HISTORY_CORRUPT"); }
        for (const id of v2.recoveryManifestIdentifiersV2(historic)) rebuilt.add(id);
      }
      if (rebuilt.size !== oldSet.size || [...rebuilt].some((id) => !oldSet.has(id))) {
        fail("ZK1_HISTORY_CORRUPT");
      }
    }
    const proof = await v2.verifyRecoveryTransitionPublicV2({
      previousManifest, nextManifest: manifest, expectedScope: scope,
      retainedIdentifiers: { complete: true, values: oldSet },
    });
    if (!(await v2.isVerifiedRecoveryTransitionPublicProofV2(proof))) fail("ZK1_HISTORY_INVALID");
    const now = this.nowSeconds();
    v2.verifyRecoveryAdmissionWindowV2({
      issuedAt: manifest.operation.issued_at, expiresAt: manifest.operation.expires_at,
      now, clockHealthy: Number.isSafeInteger(now),
    });
    if (BigInt(manifest.revision) > BigInt(Number.MAX_SAFE_INTEGER)) fail("ZK1_HISTORY_INVALID");
    const revision = Number(manifest.revision);
    if (revision !== expectedRevision + 1) fail("ZK1_HISTORY_INVALID");
    const capacity = limits.checkRecoveryHistoryCapacity({
      transitionCount: prior?.entry_count || 0,
      historyBytes: prior?.history_bytes || 0,
      nextEntryBytes: raw.length,
    });
    const digest = Buffer.from(proof.manifestDigest);
    const opId = buf(manifest.operation.operation_id, 16, 16);
    const nextIds = [...proof.identifiers].filter((id) => !oldSet.has(id));
    try {
      this.db.transaction(() => {
        // The public verifier runs asynchronously. Compare again under the
        // SQLite immediate write lock: two concurrent proposals may both
        // have passed crypto, but only one can append revision r+1.
        const current = this.findHead.get(owner, key);
        if ((!current && expectedRevision !== 0)
          || (current && (current.revision !== expectedRevision
            || !same(current.digest, expectedDigest)))) fail("ZK1_HISTORY_CONFLICT");
        assertStorageQuota(current);
        if (!current) this.createScope.run(owner, key, revision, digest,
          capacity.usedTransitions, capacity.usedBytes);
        else if (this.updateScope.run(revision, digest, capacity.usedTransitions,
          capacity.usedBytes, owner, key, expectedRevision, expectedDigest).changes !== 1) {
          fail("ZK1_HISTORY_CONFLICT");
        }
        this.insertEntry.run(owner, key, revision, digest, opId, raw);
        for (const id of nextIds) this.insertIdentifier.run(owner, key, id);
      }).immediate();
    } catch (error) {
      if (error.code === "ZK1_HISTORY_CONFLICT" || error.code === "ZK1_HISTORY_LIMIT") throw error;
      fail("ZK1_HISTORY_INVALID");
    }
    return { revision, digest, capacity };
  }

  snapshot(input) {
    const owner = ownerId(input?.owner);
    const key = scopeId(input?.account_id, input?.compartment_id, input?.keyring_id);
    return this.db.transaction(() => {
      const head = this.findHead.get(owner, key);
      if (!head) return null;
      const rows = this.allEntries.all(owner, key);
      let totalBytes = 0;
      for (let i = 0; i < rows.length; i += 1) {
        const row = rows[i];
        if (row.revision !== i + 1 || !same(digestManifest(row.manifest_bytes), row.digest))
          fail("ZK1_HISTORY_CORRUPT");
        totalBytes += row.manifest_bytes.length;
      }
      if (!rows.length || rows.length !== head.entry_count
        || rows.at(-1).revision !== head.revision
        || !same(rows.at(-1).digest, head.digest)
        || totalBytes !== head.history_bytes) fail("ZK1_HISTORY_CORRUPT");
      return {
        revision: head.revision, digest: Buffer.from(head.digest),
        entries: rows.map((entry) => Buffer.from(entry.manifest_bytes)),
      };
    })();
  }
  async verifyPublicHistory(input) {
    // Must be provided by an independently trusted caller, NOT loaded from
    // this locally writable SQLite database. This proves historical public
    // signatures; it does not prove a fresh, rollback-resistant head.
    if (!input?.baseReceipt || !input?.pinnedWitness
      || !Number.isSafeInteger(input?.now) || input.now < 0) fail("ZK1_HISTORY_UNVERIFIED");
    const archive = this.snapshot(input);
    if (!archive) fail("ZK1_HISTORY_UNVERIFIED");
    try {
      const history = require("../crypto/rootark-zk-recovery-history-v2");
      const manifests = await Promise.all(archive.entries.map((raw) => z.decodeDeterministic(raw)));
      const activationRevisions = manifests.slice(1)
        .filter((manifest) => ["register-package", "replace-package", "compromise-package"]
          .includes(manifest.operation.operation_type))
        .map((manifest) => Number(manifest.revision));
      const supplied = input.packageEnvelopes ?? [];
      if (!Array.isArray(supplied) || supplied.length !== activationRevisions.length
        || supplied.some((item, index) =>
          !item || item.activationRevision !== activationRevisions[index]
          || (!Buffer.isBuffer(item.envelopeBytes)
            && !(item.envelopeBytes instanceof Uint8Array)))) fail("ZK1_HISTORY_UNVERIFIED");
      const verified = await history.verifyRecoveryHistoryPublicV2({
        expectedScope: {
          account_id: buf(input.account_id, 16, 16),
          compartment_id: buf(input.compartment_id, 1, 128),
          keyring_id: buf(input.keyring_id, 16, 16),
        },
        baseManifest: manifests[0],
        baseReceipt: input.baseReceipt,
        pinnedWitness: input.pinnedWitness,
        transitions: archive.entries.slice(1),
        packageEnvelopes: supplied,
        now: input.now,
      });
      if (!(await history.isVerifiedPublicRecoveryHistoryV2(verified))
        || !same(Buffer.from(verified.headDigest), archive.digest)
        || Number(verified.revision) !== archive.revision) fail("ZK1_HISTORY_UNVERIFIED");
      return verified;
    } catch (_) {
      fail("ZK1_HISTORY_UNVERIFIED");
    }
  }
  close() { if (this.db.open) this.db.close(); }
}

module.exports = { Zk1LocalSignedHistoryStore };
