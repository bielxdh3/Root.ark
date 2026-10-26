"use strict";

// An isolated, server-blind *local* content plane. Only sealed bytes cross
// this interface. Each request requires a fresh independently signed witness
// head, the exact manifest at that head and the active device's Ed25519 proof.
// Not installed into legacy routes. Does NOT provide cross-host linearizable
// revocation, external monotonic storage, multi-provider I/O, or production ZK.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteFile,
  assertPrivateSqliteAuthorityDirectory } = require("./zk1PrivateSqlitePath");
const Database = require("better-sqlite3");
const z = require("../crypto/rootark-zk-1");
const manifestV2 = require("../crypto/rootark-zk-recovery-manifest-v2");
const signedHistoryV2 = require("../crypto/rootark-zk-recovery-history-v2");
const { inspectVerifiedWitnessFreshHeadV1 } = require("../crypto/rootark-zk-witness-head-wire-v1");

const DOMAIN = Buffer.from("Root.ark/zk-1/protected-object-operation/v1\0", "ascii");
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const FIELDS = Object.freeze([
  "account_id", "compartment_id", "keyring_id", "device_id", "operation",
  "object_id", "expected_object_revision", "manifest_revision", "manifest_digest",
  "epoch", "nonce", "issued_at", "expires_at", "ciphertext_digest",
]);
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_LIFETIME_OBJECTS = 4096;
const MAX_NONCES = 100_000;
// No automatic archival pruning before a separately reviewed backup policy.
const MAX_VERSION_RECORDS = 4096;
const MAX_VERSION_ARCHIVE_BYTES = 256 * 1024 * 1024;
const MAX_CONCURRENT_SIGNED_HISTORY_CHECKS = 2;
const OWNER_PUT_FENCE_DOMAIN =
  Buffer.from("Root.ark/zk-1/owner-physical-put-fence/v1\0", "ascii");
const OWNER_PUT_FENCE_FIELDS = Object.freeze([
  "type", "signerKeyId", "scopeKey", "nonce", "generation",
  "manifestRevision", "manifestDigest", "deviceId",
  "devicePublicKeySha256", "allowed", "observedAt",
]);

function fail(code = "ZK_CONTENT_DENIED") {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function bytes(input, min, max = min) {
  if ((!Buffer.isBuffer(input) && !(input instanceof Uint8Array))
    || input.byteLength < min || input.byteLength > max) fail();
  return Buffer.from(input);
}
function equal(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length
    && crypto.timingSafeEqual(a, b);
}
function positive(value) {
  if (!Number.isSafeInteger(value) || value < 1) fail();
  return value;
}
function strict(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))
    || Reflect.ownKeys(value).some((field) => !fields.includes(field))) fail();
}
function normalizeScope(input) {
  strict(input, ["account_id", "compartment_id", "keyring_id"]);
  return {
    account_id: bytes(input.account_id, 16),
    compartment_id: bytes(input.compartment_id, 1, 128),
    keyring_id: bytes(input.keyring_id, 16),
  };
}
function scopeKey(scope) {
  return scope.account_id.toString("hex") + ":" + scope.compartment_id.toString("hex")
    + ":" + scope.keyring_id.toString("hex");
}
function canonicalB64(value, length) {
  return typeof value === "string" && Buffer.from(value, "base64url").length === length
    && Buffer.from(value, "base64url").toString("base64url") === value;
}
function assertOwnerFenceIdentity(db, ownerFence, scope) {
  const exists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' "
    + "AND name='zk_content_owner_put_fence'").get();
  // If the operator enabled this mode when the store was created, a later
  // restart cannot silently remove the independently pinned physical gate.
  if (Boolean(exists) !== Boolean(ownerFence)) fail("ZK_CONTENT_IDENTITY_MISMATCH");
  if (!exists) return;
  let row;
  try {
    row = db.prepare("SELECT * FROM zk_content_owner_put_fence WHERE scope=?").get(scope);
  } catch (_) { fail("ZK_CONTENT_IDENTITY_MISMATCH"); }
  if (!row || !equal(row.signer_key_id, ownerFence.keyId)
    || !equal(row.signer_fingerprint, ownerFence.fingerprint)
    || row.minimum_generation !== ownerFence.minimumGeneration
    || !Number.isSafeInteger(row.high_generation)
    || row.high_generation < row.minimum_generation
    || (row.high_digest !== null && (!Buffer.isBuffer(row.high_digest)
      || row.high_digest.length !== 32))) fail("ZK_CONTENT_IDENTITY_MISMATCH");
}
function normalizeAuthorization(value) {
  strict(value, FIELDS);
  const result = {
    account_id: bytes(value.account_id, 16),
    compartment_id: bytes(value.compartment_id, 1, 128),
    keyring_id: bytes(value.keyring_id, 16),
    device_id: value.device_id,
    operation: value.operation,
    object_id: value.object_id,
    expected_object_revision: value.expected_object_revision === null
      ? null : positive(value.expected_object_revision),
    manifest_revision: positive(value.manifest_revision),
    manifest_digest: bytes(value.manifest_digest, 32),
    epoch: positive(value.epoch),
    nonce: bytes(value.nonce, 32),
    issued_at: value.issued_at,
    expires_at: value.expires_at,
    ciphertext_digest: value.ciphertext_digest === null
      ? null : bytes(value.ciphertext_digest, 32),
  };
  if (typeof result.device_id !== "string" || result.device_id.length < 1
    || result.device_id.length > 64 || /[\u0000-\u001f\u007f]/.test(result.device_id)
    || !["put", "get", "catalog-commit", "catalog-read"].includes(result.operation)
    || typeof result.object_id !== "string"
    || !/^[A-Za-z0-9_-]{22}$/.test(result.object_id)
    || Buffer.from(result.object_id, "base64url").toString("base64url") !== result.object_id
    || !Number.isSafeInteger(result.issued_at) || result.issued_at < 0
    || !Number.isSafeInteger(result.expires_at) || result.expires_at <= result.issued_at
    || result.expires_at - result.issued_at > 60
    || (result.operation === "get"
      && (result.ciphertext_digest === null) !== (result.expected_object_revision === null))
    || (["put", "catalog-commit", "catalog-read"].includes(result.operation)
      && result.ciphertext_digest === null)
    || (result.operation === "catalog-read" && result.expected_object_revision === null)) fail();
  return result;
}
async function contentAuthorizationMessageV1(input) {
  return Buffer.concat([DOMAIN, Buffer.from(await z.encodeDeterministic(
    normalizeAuthorization(input),
  ))]);
}
function currentTime(nowSeconds) {
  const now = nowSeconds();
  if (!Number.isSafeInteger(now) || now < 0) fail("ZK_CONTENT_UNAVAILABLE");
  return now;
}

function verifyStoreIdentity(db, expected) {
  let row;
  try {
    // Check schema and identity without modifying SQLite's journal mode or
    // creating any tables. An unrelated pre-existing database is NOT ours.
    const table = db.prepare(`SELECT name FROM sqlite_master
      WHERE type='table' AND name='zk_content_identity'`).get();
    if (!table) fail("ZK_CONTENT_IDENTITY_MISSING");
    row = db.prepare("SELECT * FROM zk_content_identity WHERE id=1").get();
  } catch (error) {
    if (error.code === "ZK_CONTENT_IDENTITY_MISSING") throw error;
    fail("ZK_CONTENT_IDENTITY_MISSING");
  }
  if (!row) fail("ZK_CONTENT_IDENTITY_MISSING");
  if (row.scope !== expected.scope
    || !equal(row.witness_key_id, expected.keyId)
    || !equal(row.witness_fingerprint, expected.fingerprint)
    || row.floor_revision !== expected.revision
    || !equal(row.floor_digest, expected.digest)
    || (expected.signedGenesisDigest === null
      ? row.signed_genesis_digest != null
      : !equal(row.signed_genesis_digest, expected.signedGenesisDigest))) {
    fail("ZK_CONTENT_IDENTITY_MISMATCH");
  }
}

function statIdentity(stat) {
  if (!stat.isFile()) fail("ZK_CONTENT_BOOTSTRAP_REQUIRED");
  return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
}
function fileIdentity(filename) {
  return statIdentity(fs.statSync(filename, { bigint: true }));
}

class Zk1ProtectedObjectStore {
  #ownerPutFence;
  constructor(filename, { witnessProvider, witnessPinned, manifestProvider,
    trustedScope, minimumHead, bootstrapNew = false,
    admissionRequired = false,
    signedHistoryRequired = false, signedHistoryGenesisDigest,
    verifiedHistoryProvider, physicalCommitOwnerFence,
    nowSeconds = () => Math.floor(Date.now() / 1000) } = {}) {
    if (typeof filename !== "string" || !filename || !witnessProvider
      || typeof witnessProvider.freshHead !== "function"
      || typeof manifestProvider !== "function" || typeof nowSeconds !== "function"
      || !(witnessPinned?.publicKey instanceof crypto.KeyObject)
      || witnessPinned.publicKey.type !== "public"
      || witnessPinned.publicKey.asymmetricKeyType !== "ed25519"
      || typeof admissionRequired !== "boolean"
      || typeof signedHistoryRequired !== "boolean"
      || (signedHistoryRequired && typeof verifiedHistoryProvider !== "function")
      || (!signedHistoryRequired && verifiedHistoryProvider !== undefined)
      || (admissionRequired && (typeof witnessProvider.beginIoAdmission !== "function"
        || typeof witnessProvider.finishIoAdmission !== "function"))) fail();
    // The external owner/account authentication boundary must select ONE
    // immutable keyring scope. A watermark for a different account or
    // compartment is not interchangeable with this genesis floor.
    this.trustedScope = normalizeScope(trustedScope);
    this.witnessPinned = Object.freeze({ keyId: bytes(witnessPinned.keyId, 16),
      publicKey: witnessPinned.publicKey });
    if (!minimumHead || !Number.isSafeInteger(minimumHead.revision)
      || minimumHead.revision < 1
      || minimumHead.witnessSequence !== minimumHead.revision) fail();
    this.minimumHead = Object.freeze({ revision: minimumHead.revision,
      witnessSequence: minimumHead.witnessSequence, digest: bytes(minimumHead.digest, 32) });
    this.witnessProvider = witnessProvider;
    // A verifier result is meaningful only under a trusted GENESIS digest:
    // otherwise a compromised CAS could fabricate its own signed chain.
    this.signedHistoryRequired = signedHistoryRequired;
    this.signedHistoryGenesisDigest = signedHistoryRequired
      ? bytes(signedHistoryGenesisDigest, 32) : null;
    this.verifiedHistoryProvider = verifiedHistoryProvider;
    this.inflightSignedHistoryChecks = 0;
    this.admissionRequired = admissionRequired;
    this.manifestProvider = manifestProvider;
    this.nowSeconds = nowSeconds;
    if (physicalCommitOwnerFence !== undefined) {
      if (!signedHistoryRequired || !admissionRequired) fail();
      strict(physicalCommitOwnerFence,
        ["pinnedPublicKey", "pinnedKeyId", "minimumGeneration", "readSignedHead"]);
      const { pinnedPublicKey, pinnedKeyId, minimumGeneration, readSignedHead } =
        physicalCommitOwnerFence;
      if (!(pinnedPublicKey instanceof crypto.KeyObject)
        || pinnedPublicKey.type !== "public"
        || pinnedPublicKey.asymmetricKeyType !== "ed25519"
        || crypto.KeyObject.prototype.equals.call(pinnedPublicKey,
          this.witnessPinned.publicKey)
        || typeof readSignedHead !== "function") fail();
      const rawSigner = Buffer.from(pinnedPublicKey.export({
        type: "spki", format: "der",
      })).subarray(-32);
      this.#ownerPutFence = Object.freeze({
        publicKey: pinnedPublicKey, keyId: bytes(pinnedKeyId, 16),
        rawSigner,
        fingerprint: crypto.createHash("sha256").update(
          pinnedPublicKey.export({ type: "spki", format: "der" })).digest(),
        minimumGeneration: positive(minimumGeneration), readSignedHead,
      });
    }
    const absolute = path.resolve(filename);
    if (bootstrapNew !== true && bootstrapNew !== false) fail();
    const existed = fs.existsSync(absolute);
    if (existed === bootstrapNew) fail("ZK_CONTENT_BOOTSTRAP_REQUIRED");
    if (existed && !fs.lstatSync(absolute).isFile()) fail();
    try {
      if (existed) assertPrivateSqliteFile(absolute);
      else ensurePrivateSqliteDirectory(absolute);
      // SQLite also opens mutable WAL/SHM sidecars by name. A Windows Users
      // Modify/DELETE_CHILD ACE on this directory (or an ancestor) bypasses
      // main-file lstat/fstat checks, including on an otherwise valid restart.
      assertPrivateSqliteAuthorityDirectory(absolute);
    } catch (_) { fail("ZK_CONTENT_BOOTSTRAP_REQUIRED"); }
    const expectedIdentity = {
      scope: scopeKey(this.trustedScope),
      keyId: this.witnessPinned.keyId,
      fingerprint: crypto.createHash("sha256").update(
        this.witnessPinned.publicKey.export({ type: "spki", format: "der" })).digest(),
      revision: this.minimumHead.revision,
      digest: this.minimumHead.digest,
      signedGenesisDigest: this.signedHistoryGenesisDigest,
    };
    let inspectedIdentity;
    if (existed) {
      inspectedIdentity = fileIdentity(absolute);
      // Must complete the preflight on a read-only connection. Opening an
      // unknown SQLite in write mode / enabling WAL mutates foreign data.
      const readonly = new Database(absolute, { readonly: true, fileMustExist: true });
      try {
        verifyStoreIdentity(readonly, expectedIdentity);
        assertOwnerFenceIdentity(readonly, this.#ownerPutFence, expectedIdentity.scope);
        if (!readonly.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='zk_content_version'").get()) {
          // An old opt-in store has already overwritten its previous content.
          // Do not invent complete version history or silently mutate it.
          fail("ZK_CONTENT_VERSION_HISTORY_REQUIRED");
        }
      }
      finally { readonly.close(); }
      if (fileIdentity(absolute) !== inspectedIdentity) {
        fail("ZK_CONTENT_BOOTSTRAP_REQUIRED");
      }
      try { assertPrivateSqliteFile(absolute); } catch (_) { fail("ZK_CONTENT_BOOTSTRAP_REQUIRED"); }
    } else {
      try {
        ensurePrivateSqliteDirectory(absolute);
        assertPrivateSqliteAuthorityDirectory(absolute);
      } catch (_) { fail("ZK_CONTENT_BOOTSTRAP_REQUIRED"); }
      // Never race another bootstrap into overwriting an existing database.
      const fd = fs.openSync(absolute, fs.constants.O_CREAT | fs.constants.O_EXCL
        | fs.constants.O_RDWR, 0o600);
      try { inspectedIdentity = statIdentity(fs.fstatSync(fd, { bigint: true })); }
      finally { fs.closeSync(fd); }
    }
    try {
      assertPrivateSqliteFile(absolute);
      assertPrivateSqliteAuthorityDirectory(absolute);
    } catch (_) { fail("ZK_CONTENT_BOOTSTRAP_REQUIRED"); }
    this.db = new Database(absolute, { fileMustExist: true });
    try {
      try { assertPrivateSqliteFile(absolute); } catch (_) { fail("ZK_CONTENT_BOOTSTRAP_REQUIRED"); }
      // Cover replacement after exclusive creation and before SQLite opens.
      if (fileIdentity(absolute) !== inspectedIdentity) {
        fail("ZK_CONTENT_BOOTSTRAP_REQUIRED");
      }
      // Repeat on the very connection that will perform DDL, before the first
      // mutating statement, to reject a file swapped during the read-only check.
      if (existed) {
        verifyStoreIdentity(this.db, expectedIdentity);
        assertOwnerFenceIdentity(this.db, this.#ownerPutFence, expectedIdentity.scope);
      }
      this.db.pragma("journal_mode = WAL");
      this.db.pragma("synchronous = FULL");
      // SQLite REPLACE implicitly deletes its conflicting row. A DELETE
      // trigger is skipped unless recursive_triggers is enabled per connection.
      this.db.pragma("recursive_triggers = ON");
      if (this.db.pragma("recursive_triggers", { simple: true }) !== 1) {
        fail("ZK_CONTENT_VERSION_HISTORY_CORRUPT");
      }
      this.db.exec(`
      CREATE TABLE IF NOT EXISTS zk_content_identity (
        id INTEGER PRIMARY KEY CHECK(id=1), scope TEXT NOT NULL,
        witness_key_id BLOB NOT NULL, witness_fingerprint BLOB NOT NULL,
        floor_revision INTEGER NOT NULL, floor_digest BLOB NOT NULL,
        signed_genesis_digest BLOB
          CHECK(signed_genesis_digest IS NULL OR length(signed_genesis_digest)=32)
      );
      CREATE TABLE IF NOT EXISTS zk_content_head (
        scope TEXT PRIMARY KEY, revision INTEGER NOT NULL, digest BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS zk_content_nonce (
        scope TEXT NOT NULL, nonce BLOB NOT NULL, expires_at INTEGER,
        PRIMARY KEY(scope,nonce)
      );
      CREATE TABLE IF NOT EXISTS zk_content_clock (
        scope TEXT PRIMARY KEY, last_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS zk_content_object (
        scope TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
        epoch INTEGER NOT NULL, ciphertext BLOB NOT NULL, PRIMARY KEY(scope,id)
      );
      CREATE TABLE IF NOT EXISTS zk_content_version (
        scope TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>=1),
        epoch INTEGER NOT NULL CHECK(epoch>=1), ciphertext BLOB NOT NULL,
        ciphertext_digest BLOB NOT NULL CHECK(length(ciphertext_digest)=32),
        provenance TEXT NOT NULL CHECK(provenance='transactional'),
        PRIMARY KEY(scope,id,revision)
      );
      CREATE TRIGGER IF NOT EXISTS zk_content_version_no_update
        BEFORE UPDATE ON zk_content_version
        BEGIN SELECT RAISE(ABORT,'ZK_CONTENT_VERSION_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS zk_content_version_no_delete
        BEFORE DELETE ON zk_content_version
        BEGIN SELECT RAISE(ABORT,'ZK_CONTENT_VERSION_IMMUTABLE'); END;
    `);
    if (!existed) {
      this.db.prepare(`INSERT INTO zk_content_identity
        (id,scope,witness_key_id,witness_fingerprint,floor_revision,floor_digest,
         signed_genesis_digest)
        VALUES(1,?,?,?,?,?,?)`).run(expectedIdentity.scope, expectedIdentity.keyId,
        expectedIdentity.fingerprint, expectedIdentity.revision, expectedIdentity.digest,
        expectedIdentity.signedGenesisDigest);
      if (this.#ownerPutFence) {
        // Create ONLY on a new, operator-provisioned private store. Neither
        // an existing store nor a restart may opt in/out or switch the signer.
        this.db.exec(`CREATE TABLE zk_content_owner_put_fence (
          scope TEXT PRIMARY KEY, signer_key_id BLOB NOT NULL,
          signer_fingerprint BLOB NOT NULL, minimum_generation INTEGER NOT NULL,
          high_generation INTEGER NOT NULL, high_digest BLOB
        )`);
        this.db.prepare(`INSERT INTO zk_content_owner_put_fence
          (scope,signer_key_id,signer_fingerprint,minimum_generation,high_generation,high_digest)
          VALUES(?,?,?,?,?,NULL)`).run(expectedIdentity.scope, this.#ownerPutFence.keyId,
          this.#ownerPutFence.fingerprint, this.#ownerPutFence.minimumGeneration,
          this.#ownerPutFence.minimumGeneration);
      }
    }
    // Upgrade earlier disposable/local content planes without erasing any
    // durable replay state. Unattributed legacy nonces remain permanently
    // fenced (NULL expires_at), since their lifetimes cannot be reconstructed.
    if (!this.db.prepare("PRAGMA table_info(zk_content_nonce)").all()
      .some((field) => field.name === "expires_at")) {
      this.db.exec("ALTER TABLE zk_content_nonce ADD COLUMN expires_at INTEGER");
    }
    this.db.exec(`CREATE INDEX IF NOT EXISTS zk_content_nonce_expiry
      ON zk_content_nonce(scope, expires_at)`);
    this.getHead = this.db.prepare("SELECT revision,digest FROM zk_content_head WHERE scope=?");
    this.getObject = this.db.prepare("SELECT revision,epoch,ciphertext FROM zk_content_object WHERE scope=? AND id=?");
    this.getVersion = this.db.prepare("SELECT revision,epoch,ciphertext,ciphertext_digest "
      + "FROM zk_content_version WHERE scope=? AND id=? AND revision=?");
    this.getLatestVersion = this.db.prepare("SELECT revision,epoch,ciphertext,ciphertext_digest "
      + "FROM zk_content_version WHERE scope=? AND id=? ORDER BY revision DESC LIMIT 1");
    this.getVersionSpan = this.db.prepare(`SELECT COUNT(*) AS count,
      MIN(revision) AS first, MAX(revision) AS last,
      SUM(CASE WHEN typeof(revision)='integer' THEN 0 ELSE 1 END) AS malformed
      FROM zk_content_version WHERE scope=? AND id=?`);
    this.nonceCount = this.db.prepare("SELECT COUNT(*) AS n FROM zk_content_nonce WHERE scope=?");
    this.objectCount = this.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object WHERE scope=?");
    this.clockRow = this.db.prepare("SELECT last_at FROM zk_content_clock WHERE scope=?");
    this.versionTotals = this.db.prepare("SELECT COUNT(*) AS n, "
      + "COALESCE(SUM(length(ciphertext)),0) AS bytes FROM zk_content_version");
    this.insertVersion = this.db.prepare("INSERT INTO zk_content_version "
      + "(scope,id,revision,epoch,ciphertext,ciphertext_digest,provenance) "
      + "VALUES(?,?,?,?,?,?,'transactional')");
    const initialVersionTotals = this.versionTotals.get();
    if (!initialVersionTotals
      || initialVersionTotals.n > MAX_VERSION_RECORDS
      || initialVersionTotals.bytes > MAX_VERSION_ARCHIVE_BYTES) {
      fail("ZK_CONTENT_VERSION_HISTORY_CORRUPT");
    }
    const versionRows = this.db.prepare("SELECT scope,id,revision,epoch,ciphertext,"
      + "ciphertext_digest FROM zk_content_version ORDER BY scope,id,revision").all();
    let previous = null;
    let totalVersionBytes = 0;
    const latest = new Map();
    for (const entry of versionRows) {
      totalVersionBytes += entry.ciphertext.length;
      if (entry.scope !== expectedIdentity.scope
        || entry.ciphertext.length < 16 || entry.ciphertext.length > MAX_BYTES
        || !equal(crypto.createHash("sha256").update(entry.ciphertext).digest(),
          entry.ciphertext_digest)
        || entry.revision !== (previous && previous.scope === entry.scope
          && previous.id === entry.id ? previous.revision + 1 : 1)) {
        fail("ZK_CONTENT_VERSION_HISTORY_CORRUPT");
      }
      previous = entry;
      latest.set(JSON.stringify([entry.scope, entry.id]), entry);
    }
    if (versionRows.length !== initialVersionTotals.n
      || totalVersionBytes !== initialVersionTotals.bytes) {
      fail("ZK_CONTENT_VERSION_HISTORY_CORRUPT");
    }
    const currentObjects = this.db.prepare(
      "SELECT scope,id,revision,epoch,ciphertext FROM zk_content_object").all();
    if (latest.size !== currentObjects.length
      || currentObjects.some((row) => {
        const tail = latest.get(JSON.stringify([row.scope, row.id]));
        return !tail || tail.revision !== row.revision || tail.epoch !== row.epoch
          || !equal(tail.ciphertext, row.ciphertext);
      })) fail("ZK_CONTENT_VERSION_HISTORY_CORRUPT");
    } catch (error) {
      this.db.close();
      throw error;
    }
  }

  async authorize({ scope, authorization, signature, ciphertext }, operation) {
    const canonicalScope = normalizeScope(scope);
    const request = normalizeAuthorization(authorization);
    const key = scopeKey(canonicalScope);
    if (!equal(canonicalScope.account_id, this.trustedScope.account_id)
      || !equal(canonicalScope.compartment_id, this.trustedScope.compartment_id)
      || !equal(canonicalScope.keyring_id, this.trustedScope.keyring_id)
      || !equal(request.account_id, canonicalScope.account_id)
      || !equal(request.compartment_id, canonicalScope.compartment_id)
      || !equal(request.keyring_id, canonicalScope.keyring_id)
      || request.operation !== operation) fail();
    // A complete owner-signed KEYRING history does not attest the latest
    // ciphertext revision stored in this local SQLite database. In strict
    // mode a mutable latest projection cannot select bytes on the owner's
    // behalf: require the signer to bind the precise archived revision and
    // ciphertext digest. Provenance/total-erasure still require an external
    // independently authenticated per-object commitment ledger.
    if (this.signedHistoryRequired && operation === "get"
      && (request.expected_object_revision === null
        || request.ciphertext_digest === null)) fail();
    const proofSignature = bytes(signature, 64);
    const sealed = operation === "put" ? bytes(ciphertext, 16, MAX_BYTES) : null;
    if (operation === "put" && !equal(crypto.createHash("sha256").update(sealed).digest(),
      request.ciphertext_digest)) fail();
    const now = currentTime(this.nowSeconds);
    if (now < request.issued_at - 5 || now > request.expires_at) fail();
    let manifest, head, nonce, floor, rawManifest;
    try {
      nonce = crypto.randomBytes(32);
      const rawHead = Buffer.from(await this.witnessProvider.freshHead({
        scope: canonicalScope, nonce: Buffer.from(nonce),
      }));
      const row = this.getHead.get(key);
      floor = row && row.revision >= this.minimumHead.revision
        ? { revision: row.revision, witnessSequence: row.revision, digest: row.digest }
        : this.minimumHead;
      await inspectVerifiedWitnessFreshHeadV1({ raw: rawHead, nonce,
        scope: canonicalScope, pinned: this.witnessPinned, minimumHead: floor });
      head = await z.decodeDeterministic(rawHead);
      rawManifest = bytes(await this.manifestProvider(canonicalScope), 1, 262144);
      manifest = await z.decodeDeterministic(rawManifest);
      manifestV2.validateManifestShape(manifest);
      if (!equal(await manifestV2.recoveryManifestDigestV2(manifest),
        Buffer.from(head.current_manifest_digest))) fail();
      if (Number(manifest.revision) !== Number(head.current_revision)) fail();
      if (!equal(request.manifest_digest, Buffer.from(head.current_manifest_digest))
        || request.manifest_revision !== Number(head.current_revision)
        || request.epoch !== Number(manifest.current_epoch)
        || !equal(Buffer.from(manifest.account_id), canonicalScope.account_id)
        || !equal(Buffer.from(manifest.compartment_id), canonicalScope.compartment_id)
        || !equal(Buffer.from(manifest.keyring_id), canonicalScope.keyring_id)
        || Math.abs(Number(head.observed_at) - currentTime(this.nowSeconds)) > 30) fail();
    } catch (_) { fail("ZK_CONTENT_UNAVAILABLE"); }
    // Rejection-only preflight. The latest manifest is UNTRUSTED here:
    // an apparently active key and a valid signature do not authorize I/O
    // until the full owner-rooted signed chain below has been verified.
    const device = manifest.devices.find((entry) => entry.device_id === request.device_id);
    if (!device || device.revoked_at_epoch !== null
      || Number(device.enrolled_epoch) > request.epoch) fail();
    let valid = false;
    try {
      const publicKey = crypto.createPublicKey({
        key: Buffer.concat([ED25519_SPKI, bytes(device.authorization_public_key, 32)]),
        format: "der", type: "spki",
      });
      valid = crypto.verify(null, await contentAuthorizationMessageV1(request),
        publicKey, proofSignature);
    } catch (_) { fail(); }
    if (!valid) fail();
    if (this.signedHistoryRequired) {
      // Bound pre-admission CPU/RAM/network amplification from signed, but
      // ultimately invalid/stale requests. No admission or I/O starts here.
      if (this.inflightSignedHistoryChecks >= MAX_CONCURRENT_SIGNED_HISTORY_CHECKS) {
        fail("ZK_CONTENT_UNAVAILABLE");
      }
      this.inflightSignedHistoryChecks += 1;
      try {
        const proof = await this.verifiedHistoryProvider({
          scope: canonicalScope,
          minimumHead: { revision: floor.revision,
            witnessSequence: floor.witnessSequence, digest: Buffer.from(floor.digest) },
          nonce: Buffer.from(nonce),
        });
        // Unbranded JSON flags never grant approval. Require a privately
        // branded full Ed25519 history, pinned at the trusted genesis and
        // bound to exactly the current signed witness head and CAS manifest.
        if (!await signedHistoryV2.isVerifiedPublicRecoveryHistoryV2(proof)
          || !proof.headManifest || !proof.baseManifest
          || Number(proof.revision) !== Number(head.current_revision)
          || !equal(bytes(proof.headDigest, 32), Buffer.from(head.current_manifest_digest))
          || !equal(await manifestV2.recoveryManifestDigestV2(proof.baseManifest),
            this.signedHistoryGenesisDigest)
          || !equal(Buffer.from(await z.encodeDeterministic(proof.headManifest)),
            rawManifest)) fail();
      } catch (_) {
        fail("ZK_CONTENT_UNAVAILABLE");
      } finally {
        this.inflightSignedHistoryChecks -= 1;
      }
    }
    return { key, request, head, sealed, verifiedHeadManifest: manifest,
      deviceId: device.device_id,
      deviceAuthorizationPublicKey: Buffer.from(device.authorization_public_key),
      authorizationKeyId: Buffer.from(device.authorization_key_id).toString("base64url") };
  }

  #checkOwnerPutFence(key, request, deviceAuthorizationPublicKey, verifiedHeadManifest) {
    const fence = this.#ownerPutFence;
    if (!fence) return;
    // Owner/device Ed25519 history and the physical custodian must have
    // separate key custody; otherwise a compromised device could mint both.
    if (!Buffer.isBuffer(deviceAuthorizationPublicKey)
      || deviceAuthorizationPublicKey.equals(fence.rawSigner)
      || !verifiedHeadManifest || !Array.isArray(verifiedHeadManifest.devices)
      || verifiedHeadManifest.devices.some((device) =>
        Buffer.from(device.authorization_public_key).equals(fence.rawSigner))) {
      fail("ZK_CONTENT_UNAVAILABLE");
    }
    // Called INSIDE the physical SQLite IMMEDIATE transaction, after ALL
    // witness/history/admission awaits. This callback must be a synchronous
    // operator-owned signer backed by an independently monotonic owner state.
    // A Promise is not a physical commit fence.
    const nonce = crypto.randomBytes(32);
    const devicePublicKeySha256 = crypto.createHash("sha256")
      .update(deviceAuthorizationPublicKey).digest();
    let signed;
    try {
      signed = fence.readSignedHead({
        nonce: Buffer.from(nonce), scope: {
          account_id: Buffer.from(this.trustedScope.account_id),
          compartment_id: Buffer.from(this.trustedScope.compartment_id),
          keyring_id: Buffer.from(this.trustedScope.keyring_id),
        }, deviceId: request.device_id,
        devicePublicKeySha256: Buffer.from(devicePublicKeySha256),
      });
    } catch (_) { fail("ZK_CONTENT_UNAVAILABLE"); }
    if (!signed || typeof signed !== "object" || Array.isArray(signed)
      || Reflect.ownKeys(signed).length !== 2
      || !Object.hasOwn(signed, "statement") || !Object.hasOwn(signed, "signature")
      || signed instanceof Promise) fail("ZK_CONTENT_UNAVAILABLE");
    const s = signed.statement;
    if (!s || typeof s !== "object" || Array.isArray(s)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(s))
      || Reflect.ownKeys(s).length !== OWNER_PUT_FENCE_FIELDS.length
      || OWNER_PUT_FENCE_FIELDS.some((field) => {
        const desc = Object.getOwnPropertyDescriptor(s, field);
        return !desc || !Object.hasOwn(desc, "value");
      })) fail("ZK_CONTENT_UNAVAILABLE");
    const now = currentTime(this.nowSeconds);
    if (s.type !== "rootark-zk1-owner-physical-put-fence-v1"
      || s.signerKeyId !== fence.keyId.toString("base64url")
      || s.scopeKey !== key || s.nonce !== nonce.toString("base64url")
      || !Number.isSafeInteger(s.generation)
      || s.generation < fence.minimumGeneration
      // A revoked-and-reenrolled device cannot reuse an old signed PUT
      // even if the owner later enrolls the same key again (owner ABA).
      || s.generation !== request.manifest_revision
      || s.manifestRevision !== request.manifest_revision
      || !canonicalB64(s.manifestDigest, 32)
      || s.manifestDigest !== request.manifest_digest.toString("base64url")
      || s.deviceId !== request.device_id
      || !canonicalB64(s.devicePublicKeySha256, 32)
      || s.devicePublicKeySha256 !== devicePublicKeySha256.toString("base64url")
      || s.allowed !== true || !Number.isSafeInteger(s.observedAt)
      || Math.abs(now - s.observedAt) > 2
      || !Buffer.isBuffer(signed.signature) || signed.signature.length !== 64) {
      fail("ZK_CONTENT_UNAVAILABLE");
    }
    const body = Buffer.concat([OWNER_PUT_FENCE_DOMAIN,
      Buffer.from(JSON.stringify(s), "utf8")]);
    if (!crypto.verify(null, body, fence.publicKey, signed.signature)) {
      fail("ZK_CONTENT_UNAVAILABLE");
    }
    const stored = this.db.prepare(
      "SELECT high_generation,high_digest FROM zk_content_owner_put_fence WHERE scope=?")
      .get(key);
    if (!stored || !Number.isSafeInteger(stored.high_generation)
      || stored.high_generation > s.generation
      || (stored.high_generation === s.generation && stored.high_digest
        && !equal(stored.high_digest, request.manifest_digest))) fail("ZK_CONTENT_UNAVAILABLE");
    if (stored.high_generation < s.generation) {
      this.db.prepare(`UPDATE zk_content_owner_put_fence
        SET high_generation=?,high_digest=? WHERE scope=?`)
        .run(s.generation, request.manifest_digest, key);
    } else if (stored.high_digest === null) {
      this.db.prepare("UPDATE zk_content_owner_put_fence SET high_digest=? WHERE scope=?")
        .run(request.manifest_digest, key);
    }
  }
  perform({ key, request, head, sealed, deviceAuthorizationPublicKey,
    verifiedHeadManifest }, operation) {
    return this.db.transaction(() => {
      if (operation === "put") this.#checkOwnerPutFence(
        key, request, deviceAuthorizationPublicKey, verifiedHeadManifest);
      // Never use the time from the first auth check after an asynchronous
      // network/crypto operation. The request must be valid at the physical
      // read/write effect boundary, not merely when it entered the process.
      const now = currentTime(this.nowSeconds);
      if (now < request.issued_at - 5 || now > request.expires_at) fail();
      const clock = this.clockRow.get(key);
      if (clock && now < clock.last_at) fail("ZK_CONTENT_UNAVAILABLE");
      const known = this.getHead.get(key);
      const minimum = known && known.revision >= this.minimumHead.revision
        ? known : this.minimumHead;
      const revision = Number(head.current_revision);
      const digest = Buffer.from(head.current_manifest_digest);
      if (revision < minimum.revision
        || (revision === minimum.revision && !equal(digest, Buffer.from(minimum.digest)))) {
        fail("ZK_CONTENT_UNAVAILABLE");
      }
      // Reclaim only already expired nonce tombstones. All signed requests
      // have a <=60s lifetime; the persistently monotonic local clock above
      // prevents a time rollback from revalidating a retired nonce.
      this.db.prepare(`DELETE FROM zk_content_nonce
        WHERE scope=? AND expires_at IS NOT NULL AND expires_at < ?`).run(key, now);
      if (this.db.prepare("SELECT 1 FROM zk_content_nonce WHERE scope=? AND nonce=?")
        .get(key, request.nonce)) fail("ZK_CONTENT_REPLAY");
      if (this.nonceCount.get(key).n >= MAX_NONCES) fail("ZK_CONTENT_UNAVAILABLE");
      const row = this.getObject.get(key, request.object_id);
      const tail = this.getLatestVersion.get(key, request.object_id);
      if (Boolean(row) !== Boolean(tail)) fail("ZK_CONTENT_VERSION_HISTORY_CORRUPT");
      if (row) {
        // Under the unique (scope,id,revision) index, N distinct positive
        // integer revisions with min=1/max=N form exactly the full sequence.
        // Check this on each live effect so removal of an older archive row
        // cannot evade the latest-projection/tail parity check until restart.
        const span = this.getVersionSpan.get(key, request.object_id);
        if (span.count !== row.revision || span.first !== 1
          || span.last !== row.revision || span.malformed !== 0) {
          fail("ZK_CONTENT_VERSION_HISTORY_CORRUPT");
        }
        // The mutable current projection is only an index; immutable version
        // rows are the source of truth. A compromised local SQLite writer may
        // alter/rewind/delete the projection after startup. Compare against
        // the absolute LAST archived revision, not a historical row picked
        // using the untrusted projection's current revision.
        if (row.revision !== tail.revision || row.epoch !== tail.epoch
          || row.ciphertext.length !== tail.ciphertext.length
          || !equal(row.ciphertext, tail.ciphertext)
          || !equal(crypto.createHash("sha256").update(tail.ciphertext).digest(),
            tail.ciphertext_digest)) fail("ZK_CONTENT_VERSION_HISTORY_CORRUPT");
      }
      let result;
      if (operation === "get") {
        if (!row) fail("ZK_CONTENT_NOT_FOUND");
        const archived = request.expected_object_revision === null ? null
          : this.getVersion.get(key, request.object_id, request.expected_object_revision);
        if (request.expected_object_revision !== null && !archived) fail("ZK_CONTENT_NOT_FOUND");
        const selected = archived || row;
        if (archived && (!equal(archived.ciphertext_digest, request.ciphertext_digest)
          || !equal(crypto.createHash("sha256").update(archived.ciphertext).digest(),
            archived.ciphertext_digest))) fail("ZK_CONTENT_CONFLICT");
        result = { id: request.object_id, revision: selected.revision,
          epoch: selected.epoch, ciphertext: Buffer.from(selected.ciphertext) };
      } else {
        if (row && row.revision !== request.expected_object_revision) fail("ZK_CONTENT_CONFLICT");
        if (!row && request.expected_object_revision !== null) fail("ZK_CONTENT_CONFLICT");
        if (!row && this.objectCount.get(key).n >= MAX_LIFETIME_OBJECTS) {
          fail("ZK_CONTENT_UNAVAILABLE");
        }
        const nextRevision = row ? row.revision + 1 : 1;
        if (!Number.isSafeInteger(nextRevision)) fail("ZK_CONTENT_UNAVAILABLE");
        const totals = this.versionTotals.get();
        if (totals.n >= MAX_VERSION_RECORDS
          || totals.bytes > MAX_VERSION_ARCHIVE_BYTES - sealed.length) {
          fail("ZK_CONTENT_UNAVAILABLE");
        }
        this.db.prepare(`INSERT INTO zk_content_object(scope,id,revision,epoch,ciphertext)
          VALUES(?,?,?,?,?) ON CONFLICT(scope,id) DO UPDATE SET
          revision=excluded.revision, epoch=excluded.epoch, ciphertext=excluded.ciphertext`)
          .run(key, request.object_id, nextRevision, request.epoch, sealed);
        // The historical ciphertext and the current projection advance under
        // the same SQLite IMMEDIATE transaction. Any history INSERT failure
        // rolls back the updated projection, nonce and head watermark as well.
        this.insertVersion.run(key, request.object_id, nextRevision,
          request.epoch, sealed, request.ciphertext_digest);
        result = { id: request.object_id, revision: nextRevision };
      }
      this.db.prepare("INSERT INTO zk_content_nonce(scope,nonce,expires_at) VALUES(?,?,?)")
        .run(key, request.nonce, request.expires_at);
      this.db.prepare(`INSERT INTO zk_content_clock(scope,last_at) VALUES(?,?)
        ON CONFLICT(scope) DO UPDATE SET last_at=excluded.last_at`).run(key, now);
      this.db.prepare(`INSERT INTO zk_content_head(scope,revision,digest) VALUES(?,?,?)
        ON CONFLICT(scope) DO UPDATE SET revision=excluded.revision,digest=excluded.digest`)
        .run(key, revision, digest);
      return result;
    }).immediate();
  }

  async put(input) {
    if (this.admissionRequired) fail("ZK_CONTENT_GATE_REQUIRED");
    return this.perform(await this.authorize(input, "put"), "put");
  }
  async get(input) {
    if (this.admissionRequired) fail("ZK_CONTENT_GATE_REQUIRED");
    return this.perform(await this.authorize(input, "get"), "get");
  }
  // The local ciphertext can be LOST while the independently signed owner,
  // witness/CAS head and durable replay ledger remain intact. A normal GET
  // would fail ZK_CONTENT_NOT_FOUND before a remote recovery is possible.
  // Burn the signed device challenge and advance the monotonic floor without
  // fabricating a local ciphertext row. Only a signed historical GET is valid.
  #consumeRestoreGet(authenticated, pin) {
    const wanted = pin;
    if (!wanted || typeof wanted !== "object"
      || Reflect.ownKeys(wanted).length !== 5
      || !["objectId", "revision", "epoch", "digest", "operationId"]
        .every((x) => Object.hasOwn(wanted, x))
      || bytes(wanted.operationId, 16).length !== 16) fail();
    const request = authenticated.request;
    if (request.object_id !== wanted.objectId
      || request.expected_object_revision !== positive(wanted.revision)
      || request.epoch < positive(wanted.epoch)
      || !equal(request.ciphertext_digest, bytes(wanted.digest, 32))) fail();
    return this.db.transaction(() => {
      const key = authenticated.key;
      const now = currentTime(this.nowSeconds);
      if (now < request.issued_at - 5 || now > request.expires_at) fail();
      const last = this.clockRow.get(key);
      if (last && now < last.last_at) fail("ZK_CONTENT_UNAVAILABLE");
      const prior = this.getHead.get(key);
      const minimum = prior && prior.revision >= this.minimumHead.revision
        ? prior : this.minimumHead;
      const revision = Number(authenticated.head.current_revision);
      const digest = Buffer.from(authenticated.head.current_manifest_digest);
      if (revision < minimum.revision
        || (revision === minimum.revision && !equal(digest, Buffer.from(minimum.digest)))) {
        fail("ZK_CONTENT_UNAVAILABLE");
      }
      // Remote recovery only when no local ciphertext remains. Existing data
      // must use the normal protected GET with immutable archive verification.
      if (this.getObject.get(key, wanted.objectId)
        || this.getLatestVersion.get(key, wanted.objectId)) fail("ZK_CONTENT_CONFLICT");
      this.db.prepare(`DELETE FROM zk_content_nonce
        WHERE scope=? AND expires_at IS NOT NULL AND expires_at < ?`).run(key, now);
      if (this.db.prepare("SELECT 1 FROM zk_content_nonce WHERE scope=? AND nonce=?")
        .get(key, request.nonce)) fail("ZK_CONTENT_REPLAY");
      if (this.nonceCount.get(key).n >= MAX_NONCES) fail("ZK_CONTENT_UNAVAILABLE");
      this.db.prepare("INSERT INTO zk_content_nonce(scope,nonce,expires_at) VALUES(?,?,?)")
        .run(key, request.nonce, request.expires_at);
      this.db.prepare(`INSERT INTO zk_content_clock(scope,last_at) VALUES(?,?)
        ON CONFLICT(scope) DO UPDATE SET last_at=excluded.last_at`).run(key, now);
      this.db.prepare(`INSERT INTO zk_content_head(scope,revision,digest) VALUES(?,?,?)
        ON CONFLICT(scope) DO UPDATE SET revision=excluded.revision,digest=excluded.digest`)
        .run(key, revision, digest);
    }).immediate();
  }
  async runRestoreGetAdmission(input, pinnedOperation, emit, { abortSignal } = {}) {
    if (!this.admissionRequired || !this.signedHistoryRequired
      || typeof emit !== "function"
      || (abortSignal !== undefined && !(abortSignal instanceof AbortSignal))) {
      fail("ZK_CONTENT_GATE_REQUIRED");
    }
    if (abortSignal?.aborted) fail("ZK_CONTENT_UNAVAILABLE");
    const authenticated = await this.authorize(input, "get");
    return this.#withAdmission(authenticated, "get", () => {
      if (abortSignal?.aborted) fail("ZK_CONTENT_UNAVAILABLE");
      this.#consumeRestoreGet(authenticated, pinnedOperation);
      return emit();
    }, abortSignal);
  }
  async runWithAdmission(input, operation, emit, guard = null) {
    if (typeof emit !== "function" || (guard !== null && typeof guard !== "function")
      || !["put", "get"].includes(operation)) fail();
    const authenticated = await this.authorize(input, operation);
    return this.#withAdmission(authenticated, operation, () => {
      // Account-session authorization is mutable independently of the owner's
      // device witness. A guard supplied by HTTP must run AFTER the admission
      // await and BEFORE a PUT changes durable ciphertext.
      if (guard) guard();
      return emit(this.perform(authenticated, operation));
    });
  }
  // Catalog read/commit use the identical independently witnessed current
  // owner history and device PoP, plus the existing physical I/O gate.
  // Their separate signature domain and effect live in zk1OpaqueCatalog.
  async runCatalogWithAdmission(input, operation, emit, guard = null) {
    if (!this.signedHistoryRequired || typeof emit !== "function"
      || (guard !== null && typeof guard !== "function")
      || !["catalog-commit", "catalog-read"].includes(operation)) fail();
    const authenticated = await this.authorize(input, operation);
    return this.#withAdmission(authenticated,
      operation === "catalog-commit" ? "put" : "get", () => {
        if (guard) guard();
        return emit(authenticated);
      });
  }
  async #withAdmission(authenticated, operation, effect, abortSignal) {
    if (abortSignal?.aborted) fail("ZK_CONTENT_UNAVAILABLE");
    if (!this.admissionRequired) {
      return effect();
    }
    const workerId = crypto.randomBytes(16);
    let admissionId;
    let mayProceed = false;
    const start = { scope: this.trustedScope,
      revision: authenticated.request.manifest_revision,
      digest: authenticated.request.manifest_digest,
      action: operation, objectId: authenticated.request.object_id, workerId };
    try {
      let receipt;
      try { receipt = await this.witnessProvider.beginIoAdmission(start); }
      catch (_) {
        // A lost start ACK must retry with the exact SAME worker identifier:
        // the witness returns the prior active admission idempotently. Never
        // start an unrelated second worker after a transport failure.
        receipt = await this.witnessProvider.beginIoAdmission(start);
      }
      admissionId = bytes(receipt.admissionId, 16);
      if (typeof receipt.proceed !== "boolean") fail("ZK_CONTENT_UNAVAILABLE");
      mayProceed = receipt.proceed;
    } catch (_) { fail("ZK_CONTENT_UNAVAILABLE"); }
    try {
      if (!mayProceed || abortSignal?.aborted) fail("ZK_CONTENT_UNAVAILABLE");
      // The caller's emit() must settle only when response bytes have crossed
      // the trusted application egress boundary, or the socket was closed.
      // The witness refuses to reserve while this admission is ACTIVE.
      return await effect();
    } finally {
      const finish = { scope: this.trustedScope, admissionId, workerId };
      try {
        try { await this.witnessProvider.finishIoAdmission(finish); }
        catch (_) { await this.witnessProvider.finishIoAdmission(finish); }
      } catch (_) {
        // Never silently clear an unknown active worker. A lost finish ACK
        // leaves the durable witness fence closed until reconciliation.
        fail("ZK_CONTENT_UNAVAILABLE");
      }
    }
  }
  close() { if (this.db.open) this.db.close(); }
}

module.exports = { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 };
