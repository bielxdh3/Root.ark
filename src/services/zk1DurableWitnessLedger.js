"use strict";

// Isolated durable witness *engine*. Never mount in Root.ark's application
// process: independence requires a separate operator, transport, custody,
// trust-root bootstrap and physical CAS/egress integration. A signed receipt
// from this store alone NEVER admits protected I/O or recovery.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteFile,
  assertPrivateSqliteAuthorityDirectory } = require("./zk1PrivateSqlitePath");
const Database = require("better-sqlite3");
const { requireImmutableTriggers } = require("./zk1OpaqueCatalogSqliteIntegrity");
const z = require("../crypto/rootark-zk-1");
const { inspectVerifiedCasStatusProofV1 } = require("../crypto/rootark-zk-cas-status-wire-v1");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const RESERVE_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-reservation/v1\0", "ascii");
const COMMIT_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-commit/v1\0", "ascii");
const CANCEL_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-cancel/v1\0", "ascii");
const CATALOG_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-catalog-admission/v1\0", "ascii");
// Policy signer must be independently provisioned. It attests the operator's
// authorization decision; callers cannot self-certify identity or epoch.
const CATALOG_POLICY_DOMAIN = Buffer.from(
  "Root.ark/zk-1/recovery-witness-catalog-policy-grant/v1\0", "ascii");
const CATALOG_POLICY_TYPE = "rootark-recovery-witness-catalog-policy-grant/v1";
const CATALOG_TERMINAL_SEAL_DOMAIN = Buffer.from(
  "Root.ark/zk-1/recovery-witness-catalog-terminal-seal/v1\0", "ascii");
const CATALOG_POLICY_FIELDS = Object.freeze([
  "type", "account_id", "compartment_id", "keyring_id", "operation_id",
  "owner_revision", "owner_digest", "signer_device_id", "epoch", "sequence",
  "catalog_digest", "cas_signer_spki_sha256", "expires_at", "principal",
  "nonce", "issued_at",
]);
// This terminal type is NOT emitted by today's FLOOR service. A generic signed
// floor readHead is not evidence of operation-specific physical finalization.
const FLOOR_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-witness-terminal/v1\0", "ascii");
const FLOOR_TYPE = "rootark-zk1-opaque-catalog-witness-terminal/v1";
const RESERVE_FIELDS = Object.freeze([
  "account_id", "compartment_id", "keyring_id", "reservation_id",
  "operation_id", "expected_revision", "expected_manifest_digest",
  "proposed_revision", "proposed_manifest_digest", "request_digest",
  "package_envelope_digest", "expires_at",
]);
const STATUS_FIELDS = RESERVE_FIELDS.filter((field) => field !== "expires_at");
const MAX_EVENTS_PER_SCOPE = 8192;
// No unsafe ledger pruning: when the immutable catalog evidence budget is
// reached, refuse new admissions and require a separate audited migration.
const MAX_CATALOG_ADMISSIONS_PER_SCOPE = 256;
const PRINCIPAL_FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;
const OBJECT_ID = /^[A-Za-z0-9_-]{22}$/;
function fail(code = "WITNESS_INVALID") {
  const e = new Error(code);
  e.code = code;
  throw e;
}
function bytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length < min || value.length > max) fail();
  return Buffer.from(value);
}
function number(value, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) fail();
  return value;
}
function equal(a, b) {
  return (Buffer.isBuffer(a) || a instanceof Uint8Array)
    && (Buffer.isBuffer(b) || b instanceof Uint8Array)
    && a.length === b.length
    && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function compartmentKey(account, compartment) {
  return account.toString("hex") + ":" + compartment.length.toString(16)
    + ":" + compartment.toString("hex");
}
function normalizeOperation(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || Reflect.ownKeys(input).length !== RESERVE_FIELDS.length
    || RESERVE_FIELDS.some((key) => !Object.hasOwn(input, key))) fail();
  const o = Object.create(null);
  o.account_id = bytes(input.account_id, 16);
  o.compartment_id = bytes(input.compartment_id, 1, 128);
  o.keyring_id = bytes(input.keyring_id, 16);
  o.reservation_id = bytes(input.reservation_id, 16);
  o.operation_id = bytes(input.operation_id, 16);
  o.proposed_manifest_digest = bytes(input.proposed_manifest_digest, 32);
  o.request_digest = bytes(input.request_digest, 32);
  o.package_envelope_digest = input.package_envelope_digest === null
    ? null : bytes(input.package_envelope_digest, 32);
  if ((input.expected_revision === null) !== (input.expected_manifest_digest === null)) fail();
  o.expected_revision = input.expected_revision === null
    ? null : number(input.expected_revision, 1);
  o.expected_manifest_digest = input.expected_manifest_digest === null
    ? null : bytes(input.expected_manifest_digest, 32);
  o.proposed_revision = number(input.proposed_revision, 1);
  if (o.proposed_revision !== (o.expected_revision === null ? 1 : o.expected_revision + 1)) fail();
  o.expires_at = number(input.expires_at);
  return o;
}
function normalizeScope(scope) {
  return {
    account_id: bytes(scope?.account_id, 16),
    compartment_id: bytes(scope?.compartment_id, 1, 128),
    keyring_id: bytes(scope?.keyring_id, 16),
  };
}
function normalizeIoRequest(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || Reflect.ownKeys(input).length !== 7
    || ["scope", "revision", "digest", "action", "objectId", "workerId", "principal"]
      .some((field) => !Object.hasOwn(input, field))) fail("WITNESS_IO_DENIED");
  const scope = normalizeScope(input.scope);
  if (!Number.isSafeInteger(input.revision) || input.revision < 1
    || !["get", "put"].includes(input.action)
    || typeof input.objectId !== "string" || !OBJECT_ID.test(input.objectId)
    || Buffer.from(input.objectId, "base64url").toString("base64url") !== input.objectId
    || typeof input.principal !== "string" || !PRINCIPAL_FINGERPRINT.test(input.principal)) {
    fail("WITNESS_IO_DENIED");
  }
  return { scope, revision: input.revision, digest: bytes(input.digest, 32),
    action: input.action, objectId: input.objectId, workerId: bytes(input.workerId, 16),
    principal: input.principal };
}
function normalizeIoFinish(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || Reflect.ownKeys(input).length !== 4
    || ["scope", "admissionId", "workerId", "principal"]
      .some((field) => !Object.hasOwn(input, field))
    || typeof input.principal !== "string" || !PRINCIPAL_FINGERPRINT.test(input.principal)) {
    fail("WITNESS_IO_DENIED");
  }
  return { scope: normalizeScope(input.scope), admissionId: bytes(input.admissionId, 16),
    workerId: bytes(input.workerId, 16), principal: input.principal };
}

function catalogRequest(input) {
  const fields = ["scope", "ownerRevision", "ownerDigest", "operationId",
    "signerDeviceId", "epoch", "sequence", "catalogDigest",
    "floorCasSignerFingerprint", "expiresAt", "principal", "policyGrant"];
  if (!input || typeof input !== "object" || Array.isArray(input)
    || Reflect.ownKeys(input).length !== fields.length
    || fields.some((field) => !Object.hasOwn(input, field))
    || typeof input.principal !== "string"
    || !PRINCIPAL_FINGERPRINT.test(input.principal)) fail("WITNESS_CATALOG_DENIED");
  return { scope: normalizeScope(input.scope),
    ownerRevision: number(input.ownerRevision, 1),
    ownerDigest: bytes(input.ownerDigest, 32),
    operationId: bytes(input.operationId, 16),
    signerDeviceId: bytes(input.signerDeviceId, 16),
    epoch: number(input.epoch, 1), sequence: number(input.sequence, 1),
    catalogDigest: bytes(input.catalogDigest, 32),
    floorCasSignerFingerprint: bytes(input.floorCasSignerFingerprint, 32),
    expiresAt: number(input.expiresAt), principal: input.principal,
    policyGrant: bytes(input.policyGrant, 1, 4096) };
}

// The seal is written ONLY after a complete FLOOR Ed25519 signature and
// admission binding check. It makes direct SQLite INSERT with unverified
// floor_proof detectable synchronously on startup and while holding the
// same BEGIN IMMEDIATE lock that decides owner revocation/quiescence.
function catalogTerminalSealMessage(row) {
  const fields = ["admission_id", "scope_key", "keyring_id", "operation_id",
    "principal", "owner_revision", "owner_digest", "signer_device_id",
    "epoch", "sequence", "catalog_digest", "cas_fp", "expires_at",
    "floor_nonce", "ticket", "policy_nonce", "policy_grant", "floor_proof"];
  const serialized = fields.map((field) => {
    const value = row[field];
    if (Buffer.isBuffer(value)) return ["bytes", value.toString("base64url")];
    if (typeof value === "string") return ["string", value];
    if (Number.isSafeInteger(value)) return ["integer", value];
    fail("WITNESS_CATALOG_DENIED");
  });
  if (!Buffer.isBuffer(row.admission_id) || row.admission_id.length !== 16
    || !Buffer.isBuffer(row.floor_proof) || row.floor_proof.length < 1
    || row.floor_proof.length > 4096) fail("WITNESS_CATALOG_DENIED");
  return Buffer.concat([CATALOG_TERMINAL_SEAL_DOMAIN,
    Buffer.from(JSON.stringify(serialized))]);
}
function assertCatalogTerminalSeals(db, publicKey) {
  if (!publicKey) return;
  const rows = db.prepare(`SELECT a.*,t.floor_proof,t.terminal_seal
    FROM witness_catalog_terminal t
    LEFT JOIN witness_catalog_admission a ON a.admission_id=t.admission_id`).all();
  for (const row of rows) {
    if (!Buffer.isBuffer(row.terminal_seal) || row.terminal_seal.length !== 64
      || !crypto.verify(null, catalogTerminalSealMessage(row),
        publicKey, row.terminal_seal)) fail("WITNESS_CATALOG_DENIED");
  }
}

function catalogSchema(db, floorFingerprint, policyFingerprint, witnessPublicKey) {
  const entries = new Set(db.prepare("SELECT type,name FROM sqlite_master").all()
    .map(({ type, name }) => `${type}:${name}`));
  const has = entries.has("table:witness_catalog_identity");
  if (!has) {
    if (floorFingerprint !== null || policyFingerprint !== null) fail("WITNESS_CATALOG_DENIED");
    if (entries.has("table:witness_catalog_admission")
      || entries.has("table:witness_catalog_terminal")) fail("WITNESS_CATALOG_DENIED");
    return;
  }
  if (floorFingerprint === null || policyFingerprint === null
    || !entries.has("table:witness_catalog_admission")
    || !entries.has("table:witness_catalog_terminal")) fail("WITNESS_CATALOG_DENIED");
  if (db.pragma("quick_check", { simple: true }) !== "ok") fail("WITNESS_CATALOG_DENIED");
  for (const name of ["catalog_admission_update", "catalog_admission_delete",
    "catalog_terminal_update", "catalog_terminal_delete"]) {
    if (!entries.has(`trigger:${name}`)) fail("WITNESS_CATALOG_DENIED");
  }
  // Merely retaining a trigger NAME is not proof of immutable custody:
  // require its exact operation and target table, not a forged identity hook.
  requireImmutableTriggers(db, [
    ["catalog_admission_update", "witness_catalog_admission", "UPDATE"],
    ["catalog_admission_delete", "witness_catalog_admission", "DELETE"],
    ["catalog_terminal_update", "witness_catalog_terminal", "UPDATE"],
    ["catalog_terminal_delete", "witness_catalog_terminal", "DELETE"],
  ], () => fail("WITNESS_CATALOG_DENIED"));
  const required = {
    witness_catalog_admission: ["admission_id", "scope_key", "keyring_id",
      "operation_id", "principal", "owner_revision", "owner_digest",
      "signer_device_id", "epoch", "sequence", "catalog_digest", "cas_fp",
      "expires_at", "floor_nonce", "ticket", "policy_nonce", "policy_grant"],
    witness_catalog_terminal: ["admission_id", "floor_proof", "terminal_seal"],
  };
  for (const [table, names] of Object.entries(required)) {
    const actual = db.pragma(`table_info(${table})`).map((column) => column.name);
    if (actual.length !== names.length || actual.some((name, i) => name !== names[i])) {
      fail("WITNESS_CATALOG_DENIED");
    }
  }
  const indexes = db.pragma("index_list(witness_catalog_admission)")
    .filter((index) => index.unique === 1)
    .map((index) => {
      const columns = db.pragma(`index_info(${index.name})`)
        .map((column) => column.name);
      return columns.join(",");
    });
  if (!indexes.includes("scope_key,operation_id")
    || !indexes.includes("scope_key,policy_nonce")
    || db.pragma("foreign_key_check").length) fail("WITNESS_CATALOG_DENIED");
  const identityColumns = db.pragma("table_info(witness_catalog_identity)").map((v) => v.name);
  if (identityColumns.join(",") !== "id,floor_fp,policy_fp") fail("WITNESS_CATALOG_DENIED");
  const row = db.prepare("SELECT floor_fp,policy_fp FROM witness_catalog_identity WHERE id=1").get();
  if (!row || !equal(row.floor_fp, floorFingerprint)
    || !equal(row.policy_fp, policyFingerprint)
    || db.prepare("SELECT COUNT(*) AS n FROM witness_catalog_identity").get().n !== 1) {
    fail("WITNESS_CATALOG_DENIED");
  }
  assertCatalogTerminalSeals(db, witnessPublicKey);
}

class Zk1DurableWitnessLedger {
  constructor(filename, {
    witnessKeyId, witnessPrivateKey, statusPinned, statusProvider, nowSeconds,
    bootstrapNew = false, maxEventsPerScope = MAX_EVENTS_PER_SCOPE,
    catalogFloorPublicKey = null, catalogPolicyPublicKey = null,
  } = {}) {
    if (typeof filename !== "string" || !filename
      || !(witnessPrivateKey instanceof crypto.KeyObject)
      || witnessPrivateKey.type !== "private"
      || witnessPrivateKey.asymmetricKeyType !== "ed25519"
      || !(statusPinned?.publicKey instanceof crypto.KeyObject)
      || statusPinned.publicKey.type !== "public"
      || statusPinned.publicKey.asymmetricKeyType !== "ed25519"
      || typeof statusProvider?.getTerminalProof !== "function") fail();
    this.witnessKeyId = bytes(witnessKeyId, 16);
    this.statusKeyId = bytes(statusPinned.keyId, 16);
    this.witnessPrivateKey = witnessPrivateKey;
    if (catalogFloorPublicKey !== null
      && (!(catalogFloorPublicKey instanceof crypto.KeyObject)
        || catalogFloorPublicKey.type !== "public"
        || catalogFloorPublicKey.asymmetricKeyType !== "ed25519")) {
      fail("WITNESS_CATALOG_DENIED");
    }
    if ((catalogFloorPublicKey === null) !== (catalogPolicyPublicKey === null)
      || (catalogPolicyPublicKey !== null
        && (!(catalogPolicyPublicKey instanceof crypto.KeyObject)
          || catalogPolicyPublicKey.type !== "public"
          || catalogPolicyPublicKey.asymmetricKeyType !== "ed25519"))) {
      fail("WITNESS_CATALOG_DENIED");
    }
    this.catalogFloorPublicKey = catalogFloorPublicKey;
    this.catalogPolicyPublicKey = catalogPolicyPublicKey;
    const floorFingerprint = catalogFloorPublicKey === null ? null
      : crypto.createHash("sha256").update(catalogFloorPublicKey.export({
        type: "spki", format: "der" })).digest();
    const policyFingerprint = catalogPolicyPublicKey === null ? null
      : crypto.createHash("sha256").update(catalogPolicyPublicKey.export({
        type: "spki", format: "der" })).digest();
    this.statusPinned = { keyId: this.statusKeyId, publicKey: statusPinned.publicKey };
    this.statusProvider = statusProvider;
    this.nowSeconds = nowSeconds || (() => Math.floor(Date.now() / 1000));
    if (typeof this.nowSeconds !== "function") fail();
    if (!Number.isSafeInteger(maxEventsPerScope) || maxEventsPerScope < 2
      || maxEventsPerScope > MAX_EVENTS_PER_SCOPE || maxEventsPerScope % 2 !== 0) fail();
    this.maxEventsPerScope = maxEventsPerScope;
    const absolute = path.resolve(filename);
    const existed = fs.existsSync(absolute);
    try {
      if (existed) assertPrivateSqliteFile(absolute);
      else ensurePrivateSqliteDirectory(absolute);
      // SQLite opens the database and WAL/SHM sidecars by pathname. On Windows
      // a permissive directory ACL permits replacement despite a pinned file.
      assertPrivateSqliteAuthorityDirectory(absolute);
    } catch (_) { fail("WITNESS_STATE_MISSING"); }
    if (!existed && bootstrapNew !== true) fail("WITNESS_BOOTSTRAP_REQUIRED");
    const publicFingerprint = (publicKey) => crypto.createHash("sha256")
      .update(publicKey.export({ format: "der", type: "spki" })).digest();
    const ownFp = publicFingerprint(crypto.createPublicKey(witnessPrivateKey));
    const statusFp = publicFingerprint(statusPinned.publicKey);
    if (equal(ownFp, statusFp) || equal(this.witnessKeyId, this.statusKeyId)) {
      fail("WITNESS_IDENTITY_CONFLICT");
    }
    if (floorFingerprint !== null
      && (equal(floorFingerprint, ownFp) || equal(floorFingerprint, statusFp)
        || equal(policyFingerprint, ownFp) || equal(policyFingerprint, statusFp)
        || equal(policyFingerprint, floorFingerprint))) {
      fail("WITNESS_CATALOG_DENIED");
    }
    const verifyIdentity = (db) => {
      let row;
      try {
        if (!db.prepare(`SELECT name FROM sqlite_master
          WHERE type='table' AND name='witness_identity'`).get()) fail("WITNESS_STATE_MISSING");
        row = db.prepare("SELECT * FROM witness_identity WHERE id=1").get();
        catalogSchema(db, floorFingerprint, policyFingerprint,
          crypto.createPublicKey(witnessPrivateKey));
      } catch (error) {
        if (["WITNESS_STATE_MISSING", "WITNESS_CATALOG_DENIED"].includes(error.code)) throw error;
        fail("WITNESS_STATE_MISSING");
      }
      if (!row) fail("WITNESS_STATE_MISSING");
      if (!equal(row.key_id, this.witnessKeyId)
        || !equal(row.public_fingerprint, ownFp)
        || !equal(row.status_key_id, this.statusKeyId)
        || !equal(row.status_fingerprint, statusFp)) fail("WITNESS_IDENTITY_MISMATCH");
    };
    const fileIdentity = () => {
      const stat = fs.statSync(absolute, { bigint: true });
      if (!stat.isFile()) fail("WITNESS_STATE_MISSING");
      return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
    };
    let expectedFile;
    if (existed) {
      if (!fs.lstatSync(absolute).isFile()) fail("WITNESS_STATE_MISSING");
      expectedFile = fileIdentity();
      const readonly = new Database(absolute, { readonly: true, fileMustExist: true });
      try { verifyIdentity(readonly); }
      finally { readonly.close(); }
      if (fileIdentity() !== expectedFile) fail("WITNESS_STATE_MISSING");
      try { assertPrivateSqliteFile(absolute); } catch (_) { fail("WITNESS_STATE_MISSING"); }
    } else {
      try {
        ensurePrivateSqliteDirectory(absolute);
        assertPrivateSqliteAuthorityDirectory(absolute);
      } catch (_) { fail("WITNESS_STATE_MISSING"); }
      const fd = fs.openSync(absolute, fs.constants.O_CREAT | fs.constants.O_EXCL
        | fs.constants.O_RDWR, 0o600);
      try {
        const stat = fs.fstatSync(fd, { bigint: true });
        expectedFile = [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
      } finally { fs.closeSync(fd); }
    }
    try {
      assertPrivateSqliteFile(absolute);
      assertPrivateSqliteAuthorityDirectory(absolute);
    } catch (_) { fail("WITNESS_STATE_MISSING"); }
    this.db = new Database(absolute, { fileMustExist: true });
    try {
      try { assertPrivateSqliteFile(absolute); } catch (_) { fail("WITNESS_STATE_MISSING"); }
      if (fileIdentity() !== expectedFile) fail("WITNESS_STATE_MISSING");
      if (existed) {
        verifyIdentity(this.db);
      }
      this.db.pragma("journal_mode = WAL");
      this.db.pragma("synchronous = FULL");
      this.db.exec(`
      CREATE TABLE IF NOT EXISTS witness_identity (
        id INTEGER PRIMARY KEY CHECK(id = 1), key_id BLOB NOT NULL,
        public_fingerprint BLOB NOT NULL, status_key_id BLOB NOT NULL,
        status_fingerprint BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS witness_scope (
        scope_key TEXT PRIMARY KEY, keyring_id BLOB NOT NULL,
        revision INTEGER, digest BLOB, pending_id BLOB, tombstoned INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS witness_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT, scope_key TEXT NOT NULL,
        kind TEXT NOT NULL, reservation_id BLOB NOT NULL, operation_id BLOB NOT NULL,
        envelope BLOB NOT NULL, proof_digest BLOB,
        FOREIGN KEY(scope_key) REFERENCES witness_scope(scope_key)
      );
      CREATE UNIQUE INDEX IF NOT EXISTS witness_reservation_unique
        ON witness_events(reservation_id) WHERE kind = 'reserved';
      CREATE UNIQUE INDEX IF NOT EXISTS witness_operation_unique
        ON witness_events(scope_key,operation_id) WHERE kind = 'reserved';
      CREATE TABLE IF NOT EXISTS witness_io_admission (
        admission_id BLOB PRIMARY KEY, scope_key TEXT NOT NULL, keyring_id BLOB NOT NULL,
        worker_id BLOB NOT NULL, principal TEXT NOT NULL,
        action TEXT NOT NULL CHECK(action IN ('get','put')),
        object_id TEXT NOT NULL, revision INTEGER NOT NULL, digest BLOB NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('active','completed')),
        UNIQUE(scope_key,worker_id),
        FOREIGN KEY(scope_key) REFERENCES witness_scope(scope_key)
      );
      CREATE INDEX IF NOT EXISTS witness_io_active ON witness_io_admission(scope_key,state);
      -- This pre-reservation gate is deliberately local-host only. It is not
      -- a normative signed reservation or a cross-host STOP acknowledgement.
      CREATE TABLE IF NOT EXISTS witness_quiesce (
        scope_key TEXT PRIMARY KEY, operation BLOB NOT NULL,
        started_at INTEGER NOT NULL,
        FOREIGN KEY(scope_key) REFERENCES witness_scope(scope_key)
      );
      CREATE TABLE IF NOT EXISTS witness_clock_floor (
        scope_key TEXT PRIMARY KEY, last_at INTEGER NOT NULL,
        FOREIGN KEY(scope_key) REFERENCES witness_scope(scope_key)
      );
    `);
    this.db.pragma("foreign_keys = ON");
    if (!existed) {
      this.db.prepare("INSERT INTO witness_identity VALUES(1,?,?,?,?)").run(
        this.witnessKeyId, ownFp, this.statusKeyId, statusFp,
      );
        if (floorFingerprint !== null) {
          // Fresh opt-in bootstrap ONLY. Existing witness files without this
          // pinned identity are NEVER implicitly migrated or upgraded.
          this.db.exec(`
            CREATE TABLE witness_catalog_identity (
              id INTEGER PRIMARY KEY CHECK(id=1), floor_fp BLOB NOT NULL,
              policy_fp BLOB NOT NULL
            );
            CREATE TABLE witness_catalog_admission (
              admission_id BLOB PRIMARY KEY, scope_key TEXT NOT NULL,
              keyring_id BLOB NOT NULL, operation_id BLOB NOT NULL,
              principal TEXT NOT NULL, owner_revision INTEGER NOT NULL,
              owner_digest BLOB NOT NULL, signer_device_id BLOB NOT NULL,
              epoch INTEGER NOT NULL, sequence INTEGER NOT NULL,
              catalog_digest BLOB NOT NULL, cas_fp BLOB NOT NULL,
              expires_at INTEGER NOT NULL, floor_nonce BLOB NOT NULL,
              ticket BLOB NOT NULL, policy_nonce BLOB NOT NULL,
              policy_grant BLOB NOT NULL, UNIQUE(scope_key,operation_id),
              UNIQUE(scope_key,policy_nonce),
              FOREIGN KEY(scope_key) REFERENCES witness_scope(scope_key)
            );
            CREATE TABLE witness_catalog_terminal (
              admission_id BLOB PRIMARY KEY, floor_proof BLOB NOT NULL,
              terminal_seal BLOB NOT NULL CHECK(length(terminal_seal)=64),
              FOREIGN KEY(admission_id) REFERENCES witness_catalog_admission(admission_id)
            );
            CREATE TRIGGER catalog_admission_update BEFORE UPDATE ON witness_catalog_admission
              BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
            CREATE TRIGGER catalog_admission_delete BEFORE DELETE ON witness_catalog_admission
              BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
            CREATE TRIGGER catalog_terminal_update BEFORE UPDATE ON witness_catalog_terminal
              BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
            CREATE TRIGGER catalog_terminal_delete BEFORE DELETE ON witness_catalog_terminal
              BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;
          `);
          this.db.prepare("INSERT INTO witness_catalog_identity VALUES(1,?,?)")
            .run(floorFingerprint, policyFingerprint);
        }
    }
      catalogSchema(this.db, floorFingerprint, policyFingerprint,
        crypto.createPublicKey(witnessPrivateKey));
    this.getScope = this.db.prepare("SELECT * FROM witness_scope WHERE scope_key=?");
    this.insertScope = this.db.prepare(
      "INSERT INTO witness_scope(scope_key,keyring_id,revision,digest,pending_id,tombstoned) VALUES(?,?,NULL,NULL,?,0)");
    this.setPending = this.db.prepare(
      "UPDATE witness_scope SET pending_id=? WHERE scope_key=? AND pending_id IS NULL");
    this.insertEvent = this.db.prepare(
      "INSERT INTO witness_events(scope_key,kind,reservation_id,operation_id,envelope,proof_digest) VALUES(?,?,?,?,?,?)");
    this.lastPending = this.db.prepare(
      "SELECT * FROM witness_events WHERE scope_key=? AND kind='reserved' AND reservation_id=? LIMIT 1");
    this.allEvents = this.db.prepare(
      "SELECT * FROM witness_events WHERE scope_key=? ORDER BY event_id LIMIT 8194");
    this.countEvents = this.db.prepare(
      "SELECT COUNT(*) AS count FROM witness_events WHERE scope_key=?");
    this.activeIo = this.db.prepare(
      "SELECT 1 FROM witness_io_admission WHERE scope_key=? AND state='active' LIMIT 1");
    this.ioByWorker = this.db.prepare(
      "SELECT * FROM witness_io_admission WHERE scope_key=? AND worker_id=?");
    this.ioById = this.db.prepare(
      "SELECT * FROM witness_io_admission WHERE admission_id=?");
    this.quiesce = this.db.prepare(
      "SELECT operation FROM witness_quiesce WHERE scope_key=?");
    this.ioActiveCount = this.db.prepare(
      "SELECT COUNT(*) AS n FROM witness_io_admission WHERE scope_key=? AND state='active'");
    this.clockFloor = this.db.prepare(
      "SELECT last_at FROM witness_clock_floor WHERE scope_key=?");
    this.catalogActive = this.catalogFloorPublicKey === null ? null : this.db.prepare(`
      SELECT 1 FROM witness_catalog_admission a
      WHERE a.scope_key=? AND NOT EXISTS (
        SELECT 1 FROM witness_catalog_terminal t WHERE t.admission_id=a.admission_id
      ) LIMIT 1`);
    this.catalogActiveCount = this.catalogFloorPublicKey === null ? null : this.db.prepare(`
      SELECT COUNT(*) AS n FROM witness_catalog_admission a
      WHERE a.scope_key=? AND NOT EXISTS (
        SELECT 1 FROM witness_catalog_terminal t WHERE t.admission_id=a.admission_id
      )`);
    this.catalogWitnessPublicKey = crypto.createPublicKey(witnessPrivateKey);
    } catch (error) {
      this.db.close();
      throw error;
    }
  }

  async sign(unsigned, domain) {
    const canonical = await z.encodeDeterministic(unsigned);
    const signature = crypto.sign(null, Buffer.concat([domain, canonical]), this.witnessPrivateKey);
    return Buffer.from(await z.encodeDeterministic({ ...unsigned, signature }));
  }

  async verifyCatalogPolicy(req) {
    if (!this.catalogPolicyPublicKey) fail("WITNESS_CATALOG_DENIED");
    try {
      const grant = await z.decodeDeterministic(req.policyGrant);
      if (!grant || typeof grant !== "object" || Array.isArray(grant)
        || Reflect.ownKeys(grant).length !== CATALOG_POLICY_FIELDS.length + 1
        || [...CATALOG_POLICY_FIELDS, "signature"].some((field) => !Object.hasOwn(grant, field))) {
        fail("WITNESS_CATALOG_DENIED");
      }
      const { signature, ...body } = grant;
      if (body.type !== CATALOG_POLICY_TYPE
        || !["account_id", "compartment_id", "keyring_id"]
          .every((field) => equal(body[field], req.scope[field]))
        || !equal(body.operation_id, req.operationId)
        || body.owner_revision !== req.ownerRevision
        || !equal(body.owner_digest, req.ownerDigest)
        || !equal(body.signer_device_id, req.signerDeviceId)
        || body.epoch !== req.epoch || body.sequence !== req.sequence
        || !equal(body.catalog_digest, req.catalogDigest)
        || !equal(body.cas_signer_spki_sha256, req.floorCasSignerFingerprint)
        || body.expires_at !== req.expiresAt || body.principal !== req.principal
        || !Number.isSafeInteger(body.issued_at) || body.issued_at < 1
        || body.issued_at >= body.expires_at
        || body.expires_at - body.issued_at > 60
        || !crypto.verify(null, Buffer.concat([CATALOG_POLICY_DOMAIN,
          Buffer.from(await z.encodeDeterministic(body))]),
        this.catalogPolicyPublicKey, bytes(signature, 64))) fail("WITNESS_CATALOG_DENIED");
      return { nonce: bytes(body.nonce, 32), issuedAt: body.issued_at };
    } catch (_) { fail("WITNESS_CATALOG_DENIED"); }
  }

  assertCatalogTerminalIntegrity() {
    if (this.catalogFloorPublicKey) {
      assertCatalogTerminalSeals(this.db, this.catalogWitnessPublicKey);
    }
  }

  async verifyCatalogFloorProof(scope, row, raw) {
    try {
      const proof = await z.decodeDeterministic(bytes(raw, 1, 4096));
      const fields = ["type", "account_id", "compartment_id", "keyring_id",
        "cas_signer_spki_sha256", "sequence", "digest", "nonce", "observed_at",
        "admission_id", "operation_id", "owner_revision", "owner_digest",
        "signer_device_id", "epoch", "expires_at", "signature"];
      if (!proof || typeof proof !== "object" || Array.isArray(proof)
        || Reflect.ownKeys(proof).length !== fields.length
        || fields.some((field) => !Object.hasOwn(proof, field))) {
        fail("WITNESS_CATALOG_DENIED");
      }
      const { signature, ...body } = proof;
      if (body.type !== FLOOR_TYPE
        || !["account_id", "compartment_id", "keyring_id"]
          .every((name) => equal(body[name], scope[name]))
        || !equal(body.cas_signer_spki_sha256, row.cas_fp)
        || !equal(body.admission_id, row.admission_id)
        || !equal(body.operation_id, row.operation_id)
        || body.owner_revision !== row.owner_revision
        || !equal(body.owner_digest, row.owner_digest)
        || !equal(body.signer_device_id, row.signer_device_id)
        || body.epoch !== row.epoch || body.expires_at !== row.expires_at
        || !equal(body.nonce, row.floor_nonce)
        || !equal(body.digest, row.catalog_digest)
        || body.sequence !== row.sequence
        || !Number.isSafeInteger(body.observed_at)
        || body.observed_at > row.expires_at
        || !crypto.verify(null, Buffer.concat([FLOOR_DOMAIN,
          Buffer.from(await z.encodeDeterministic(body))]),
        this.catalogFloorPublicKey, bytes(signature, 64))) {
        fail("WITNESS_CATALOG_DENIED");
      }
      return proof;
    } catch (_) { fail("WITNESS_CATALOG_DENIED"); }
  }

  async verifyCatalogTerminalProofs(scope) {
    if (!this.catalogFloorPublicKey) return;
    const scopeKey = compartmentKey(scope.account_id, scope.compartment_id);
    const terminals = this.db.prepare(`SELECT a.*,t.floor_proof,t.terminal_seal
      FROM witness_catalog_terminal t JOIN witness_catalog_admission a
      ON a.admission_id=t.admission_id WHERE a.scope_key=?`).all(scopeKey);
    for (const row of terminals) {
      // Ed25519 must be checked against the original immutable admission,
      // not inferred from a SQLite row or from the generic FLOOR read head.
      await this.verifyCatalogFloorProof(scope, row, row.floor_proof);
    }
    this.assertCatalogTerminalIntegrity();
  }

  assertClockFloor(key, now) {
    const recorded = this.clockFloor.get(key);
    if (recorded && now < recorded.last_at) fail("WITNESS_CLOCK_ROLLBACK");
  }

  // Local-host reference admission fence. The same durable SQLite write lock
  // serializes admission START/FINISH against reservation. It is NOT a
  // distributed GateAuthority and cannot ensure untrusted workers actually
  // stop before reporting finish. A crash deliberately leaves ACTIVE rows
  // blocking revocation until a proved, authenticated completion.
  async beginIoAdmission(input) {
    const io = normalizeIoRequest(input);
    const { row: checked } = await this.checkedScope(io.scope);
    const key = compartmentKey(io.scope.account_id, io.scope.compartment_id);
    const admissionId = crypto.randomBytes(16);
    return this.db.transaction(() => {
      const head = this.getScope.get(key);
      if (!head || !equal(head.keyring_id, io.scope.keyring_id)
        || head.tombstoned || head.pending_id !== null
        || head.revision !== io.revision || !equal(head.digest, io.digest)
        || head.revision !== checked.revision || !equal(head.digest, checked.digest)
        || checked.pending_id !== null) fail("WITNESS_IO_DENIED");
      this.assertClockFloor(key, number(this.nowSeconds()));
      const quiescing = Boolean(this.quiesce.get(key));
      const old = this.ioByWorker.get(key, io.workerId);
      if (old) {
        if (old.state !== "active" || old.principal !== io.principal
          || old.action !== io.action || old.object_id !== io.objectId
          || old.revision !== io.revision || !equal(old.digest, io.digest)
          || !equal(old.keyring_id, io.scope.keyring_id)) fail("WITNESS_IO_DENIED");
        // A START ACK may be lost immediately before another principal
        // quiesces. Return the identical active worker so it can be FINISHED,
        // but explicitly forbid it from starting I/O after QUIESCING.
        return { admissionId: Buffer.from(old.admission_id), proceed: !quiescing };
      }
      if (quiescing) fail("WITNESS_IO_DENIED");
      this.db.prepare(`INSERT INTO witness_io_admission
        (admission_id,scope_key,keyring_id,worker_id,principal,action,object_id,revision,digest,state)
        VALUES(?,?,?,?,?,?,?,?,?,'active')`).run(admissionId, key,
        io.scope.keyring_id, io.workerId, io.principal, io.action,
        io.objectId, io.revision, io.digest);
      return { admissionId, proceed: true };
    }).immediate();
  }

  async finishIoAdmission(input) {
    const io = normalizeIoFinish(input);
    const key = compartmentKey(io.scope.account_id, io.scope.compartment_id);
    return this.db.transaction(() => {
      const row = this.ioById.get(io.admissionId);
      if (!row || row.scope_key !== key || !equal(row.keyring_id, io.scope.keyring_id)
        || !equal(row.worker_id, io.workerId) || row.principal !== io.principal) {
        fail("WITNESS_IO_DENIED");
      }
      if (row.state === "active") {
        this.db.prepare(`UPDATE witness_io_admission SET state='completed'
          WHERE admission_id=? AND state='active'`).run(io.admissionId);
      }
      return { status: "completed" };
    }).immediate();
  }

  // Opt-in witness-side FIRST HALF of catalog authorization. This is a
  // durable monotonic reservation on the SAME SQLite writer lock as owner
  // revocation. It is NOT a production-ready multi-host CAS/FLOOR protocol:
  // the floor currently does not consume the signed grant.
  async beginCatalogAdmission(input) {
    if (!this.catalogFloorPublicKey || !this.catalogPolicyPublicKey)
      fail("WITNESS_CATALOG_DENIED");
    const req = catalogRequest(input);
    const policy = await this.verifyCatalogPolicy(req);
    const key = compartmentKey(req.scope.account_id, req.scope.compartment_id);
    const { row: checked } = await this.checkedScope(req.scope);
    await this.verifyCatalogTerminalProofs(req.scope);
    const admissionId = crypto.randomBytes(16);
    const floorNonce = crypto.randomBytes(32);
    const ticket = await this.sign({
      type: "rootark-recovery-witness-catalog-admission/v1",
      witness_key_id: this.witnessKeyId, ...req.scope,
      admission_id: admissionId, operation_id: req.operationId,
      owner_revision: req.ownerRevision, owner_digest: req.ownerDigest,
      signer_device_id: req.signerDeviceId, epoch: req.epoch,
      sequence: req.sequence, catalog_digest: req.catalogDigest,
      cas_signer_spki_sha256: req.floorCasSignerFingerprint,
      floor_nonce: floorNonce, expires_at: req.expiresAt,
      principal: req.principal,
    }, CATALOG_DOMAIN);
    return this.db.transaction(() => {
      const now = number(this.nowSeconds());
      this.assertClockFloor(key, now);
      this.assertCatalogTerminalIntegrity();
      const head = this.getScope.get(key);
      const old = this.db.prepare(`SELECT * FROM witness_catalog_admission
        WHERE scope_key=? AND operation_id=?`).get(key, req.operationId);
      if (old) {
        if (old.principal !== req.principal
          || !equal(old.keyring_id, req.scope.keyring_id)
          || old.owner_revision !== req.ownerRevision
          || !equal(old.owner_digest, req.ownerDigest)
          || !equal(old.signer_device_id, req.signerDeviceId)
          || old.epoch !== req.epoch || old.sequence !== req.sequence
          || !equal(old.catalog_digest, req.catalogDigest)
          || !equal(old.cas_fp, req.floorCasSignerFingerprint)
          || old.expires_at !== req.expiresAt
          || !equal(old.policy_nonce, policy.nonce)
          || !equal(old.policy_grant, req.policyGrant)
          || this.db.prepare("SELECT 1 FROM witness_catalog_terminal WHERE admission_id=?")
            .get(old.admission_id)) fail("WITNESS_CATALOG_DENIED");
        // A lost START ACK must recover its original admission ID so the
        // caller can finish/reconcile, even after owner QUIESCING or expiry.
        // Such recovery is NOT a second grant: do not return ticket/nonce
        // when either gate is closed. No DB writes or auto-unquiescence.
        if (!head || head.tombstoned || head.pending_id !== null
          || !equal(head.keyring_id, req.scope.keyring_id)
          || head.revision !== req.ownerRevision || !equal(head.digest, req.ownerDigest)
          || this.quiesce.get(key) || req.expiresAt <= now
          || policy.issuedAt > now + 30 || now - policy.issuedAt > 60
          || checked.revision !== req.ownerRevision
          || !equal(checked.digest, req.ownerDigest)) {
          return { admissionId: Buffer.from(old.admission_id), proceed: false };
        }
        return { admissionId: Buffer.from(old.admission_id),
          floorNonce: Buffer.from(old.floor_nonce), ticket: Buffer.from(old.ticket) };
      }
      if (req.expiresAt <= now || req.expiresAt > now + 60
        || policy.issuedAt > now + 30 || now - policy.issuedAt > 60
        || checked.revision !== req.ownerRevision
        || !equal(checked.digest, req.ownerDigest)
        || !head || head.tombstoned || head.pending_id !== null
        || !equal(head.keyring_id, req.scope.keyring_id)
        || head.revision !== req.ownerRevision || !equal(head.digest, req.ownerDigest)
        || this.quiesce.get(key)) fail("WITNESS_CATALOG_DENIED");
      if (this.catalogActive.get(key)) fail("WITNESS_CATALOG_ACTIVE");
      if (this.db.prepare(`SELECT 1 FROM witness_catalog_admission
        WHERE scope_key=? AND policy_nonce=?`).get(key, policy.nonce)) {
        fail("WITNESS_CATALOG_DENIED");
      }
      if (this.db.prepare("SELECT COUNT(*) AS n FROM witness_catalog_admission WHERE scope_key=?")
        .get(key).n >= MAX_CATALOG_ADMISSIONS_PER_SCOPE) {
        fail("WITNESS_CATALOG_CAPACITY_EXHAUSTED");
      }
      this.db.prepare(`INSERT INTO witness_catalog_admission VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(admissionId, key, req.scope.keyring_id, req.operationId,
          req.principal, req.ownerRevision, req.ownerDigest, req.signerDeviceId,
          req.epoch, req.sequence, req.catalogDigest, req.floorCasSignerFingerprint,
          req.expiresAt, floorNonce, ticket, policy.nonce, req.policyGrant);
      this.db.prepare(`INSERT INTO witness_clock_floor(scope_key,last_at) VALUES (?,?)
        ON CONFLICT(scope_key) DO UPDATE SET last_at=excluded.last_at
        WHERE excluded.last_at>witness_clock_floor.last_at`).run(key, now);
      return { admissionId, floorNonce, ticket };
    }).immediate();
  }

  async completeCatalogAdmission(input) {
    if (!this.catalogFloorPublicKey || !input || typeof input !== "object"
      || Array.isArray(input)
      || Reflect.ownKeys(input).length !== 4
      || !["scope", "admissionId", "principal", "floorProof"]
        .every((key) => Object.hasOwn(input, key))
      || typeof input.principal !== "string"
      || !PRINCIPAL_FINGERPRINT.test(input.principal)) fail("WITNESS_CATALOG_DENIED");
    const scope = normalizeScope(input.scope);
    const key = compartmentKey(scope.account_id, scope.compartment_id);
    const admissionId = bytes(input.admissionId, 16);
    const row = this.db.prepare("SELECT * FROM witness_catalog_admission WHERE admission_id=?")
      .get(admissionId);
    if (!row || row.scope_key !== key || !equal(row.keyring_id, scope.keyring_id)
      || row.principal !== input.principal) fail("WITNESS_CATALOG_DENIED");
    const raw = bytes(input.floorProof, 1, 4096);
    const proof = await this.verifyCatalogFloorProof(scope, row, raw);
    await this.verifyCatalogTerminalProofs(scope);
    return this.db.transaction(() => {
      this.assertCatalogTerminalIntegrity();
      // Exact durable FINISH ACK replay, even after revocation advanced the
      // owner HEAD or the terminal's observation expired. A replay only reads
      // an immutable completed record; it cannot issue a new grant.
      const old = this.db.prepare("SELECT floor_proof FROM witness_catalog_terminal WHERE admission_id=?")
        .get(admissionId);
      if (old) {
        if (!equal(old.floor_proof, raw)) fail("WITNESS_CATALOG_DENIED");
        return { status: "completed" };
      }
      if (Math.abs(proof.observed_at - number(this.nowSeconds())) > 30)
        fail("WITNESS_CATALOG_DENIED");
      const current = this.getScope.get(key);
      if (!current || !equal(current.keyring_id, scope.keyring_id)
        || current.tombstoned || current.pending_id !== null
        || current.revision !== row.owner_revision
        || !equal(current.digest, row.owner_digest)) fail("WITNESS_CATALOG_DENIED");
      this.assertClockFloor(key, number(this.nowSeconds()));
      if (number(this.nowSeconds()) > row.expires_at) fail("WITNESS_CATALOG_DENIED");
      const seal = crypto.sign(null,
        catalogTerminalSealMessage({ ...row, floor_proof: raw }), this.witnessPrivateKey);
      this.db.prepare("INSERT INTO witness_catalog_terminal VALUES(?,?,?)")
        .run(admissionId, raw, seal);
      const now = number(this.nowSeconds());
      this.db.prepare(`INSERT INTO witness_clock_floor(scope_key,last_at) VALUES(?,?)
        ON CONFLICT(scope_key) DO UPDATE SET last_at=excluded.last_at
        WHERE excluded.last_at>witness_clock_floor.last_at`).run(key, now);
      return { status: "completed" };
    }).immediate();
  }

  async prepareQuiesce(input) {
    const op = normalizeOperation(input);
    if (op.expected_revision === null) fail("WITNESS_QUIESCING_INVALID");
    const key = compartmentKey(op.account_id, op.compartment_id);
    // Verify the existing signed event chain before accepting a request that
    // will withhold all subsequent fresh committed-head receipts.
    const { row: checked } = await this.checkedScope(op);
    await this.verifyCatalogTerminalProofs(op);
    const raw = Buffer.from(await z.encodeDeterministic(op));
    return this.db.transaction(() => {
      this.assertCatalogTerminalIntegrity();
      const head = this.getScope.get(key);
      if (!head || head.tombstoned || head.pending_id !== null
        || !equal(head.keyring_id, op.keyring_id)
        || head.revision !== op.expected_revision
        || !equal(head.digest, op.expected_manifest_digest)
        || checked.revision !== head.revision || !equal(checked.digest, head.digest)) {
        fail("WITNESS_QUIESCING_INVALID");
      }
      const existing = this.quiesce.get(key);
      this.assertClockFloor(key, number(this.nowSeconds()));
      if (existing && !equal(existing.operation, raw)) fail("WITNESS_QUIESCING");
      const activeCount = this.ioActiveCount.get(key).n
        + (this.catalogActiveCount?.get(key).n || 0);
      if (existing) {
        return { status: activeCount ? "QUIESCING" : "DRAINED", activeCount };
      }
      const now = number(this.nowSeconds());
      if (op.expires_at <= now || op.expires_at > now + 360) {
        fail("WITNESS_EXPIRED");
      }
      // Even an immediately drained scope must retain its gate. Otherwise a
      // new worker could be admitted after DRAINED but before reserve().
      this.db.prepare("INSERT INTO witness_quiesce(scope_key,operation,started_at) VALUES(?,?,?)")
        .run(key, raw, now);
      return { status: activeCount ? "QUIESCING" : "DRAINED", activeCount };
    }).immediate();
  }

  async cancelExpiredQuiesce(input) {
    const op = normalizeOperation(input);
    if (op.expected_revision === null) fail("WITNESS_QUIESCING_INVALID");
    const key = compartmentKey(op.account_id, op.compartment_id);
    const { row: checked } = await this.checkedScope(op);
    await this.verifyCatalogTerminalProofs(op);
    const raw = Buffer.from(await z.encodeDeterministic(op));
    return this.db.transaction(() => {
      this.assertCatalogTerminalIntegrity();
      const quiescing = this.quiesce.get(key);
      if (!quiescing || !equal(quiescing.operation, raw)) fail("WITNESS_QUIESCING");
      const head = this.getScope.get(key);
      if (!head || head.pending_id !== null || head.tombstoned
        || !equal(head.keyring_id, op.keyring_id)
        || head.revision !== op.expected_revision
        || !equal(head.digest, op.expected_manifest_digest)
        || checked.revision !== head.revision || !equal(checked.digest, head.digest)) {
        fail("WITNESS_QUIESCING_INVALID");
      }
      const now = number(this.nowSeconds());
      this.assertClockFloor(key, now);
      // A quiescing operation has NOT issued a signed witness reservation
      // ticket. Once its deadline and 30s skew bound have passed, it cannot
      // obtain one. Never reopen while a worker is still ACTIVE.
      if (now - op.expires_at < 30) fail("WITNESS_QUIESCE_NOT_EXPIRED");
      if (this.activeIo.get(key)) fail("WITNESS_IO_ACTIVE");
      if (this.catalogActive?.get(key)) fail("WITNESS_CATALOG_ACTIVE");
      if (this.db.prepare("DELETE FROM witness_quiesce WHERE scope_key=? AND operation=?")
        .run(key, raw).changes !== 1) fail("WITNESS_QUIESCING");
      this.db.prepare(`INSERT INTO witness_clock_floor(scope_key,last_at) VALUES(?,?)
        ON CONFLICT(scope_key) DO UPDATE SET last_at=excluded.last_at
        WHERE excluded.last_at>witness_clock_floor.last_at`).run(key, now);
      return { status: "ABORTED_EXPIRED" };
    }).immediate();
  }

  async reserve(input) {
    const op = normalizeOperation(input);
    const key = compartmentKey(op.account_id, op.compartment_id);
    await this.verifyCatalogTerminalProofs(op);
    const currentTime = number(this.nowSeconds());
    if (op.expires_at <= currentTime || op.expires_at > currentTime + 360) {
      // Test fixtures may pass a reservation near expiry; a *new* ticket
      // must always have a safe, bounded future validity window.
      fail("WITNESS_EXPIRED");
    }
    const receipt = {
      type: "rootark-recovery-witness-reservation/v1",
      reservation_id: op.reservation_id, witness_key_id: this.witnessKeyId,
      account_id: op.account_id, compartment_id: op.compartment_id,
      keyring_id: op.keyring_id,
      expected_revision: op.expected_revision,
      expected_manifest_digest: op.expected_manifest_digest,
      proposed_revision: op.proposed_revision,
      proposed_manifest_digest: op.proposed_manifest_digest,
      operation_id: op.operation_id, request_digest: op.request_digest,
      package_envelope_digest: op.package_envelope_digest,
      expires_at: op.expires_at,
    };
    const raw = await this.sign(receipt, RESERVE_DOMAIN);
    const rawOperation = Buffer.from(await z.encodeDeterministic(op));
    // Retain the exact signed reservation, not an unsigned editable copy of
    // the operation. Each later startup/read can validate the event ledger.
    this.db.transaction(() => {
      this.assertCatalogTerminalIntegrity();
      const commitTime = number(this.nowSeconds());
      this.assertClockFloor(key, commitTime);
      if (op.expires_at <= commitTime || op.expires_at > commitTime + 360) {
        fail("WITNESS_EXPIRED");
      }
      const head = this.getScope.get(key);
      if (head && !equal(head.keyring_id, op.keyring_id)) fail("WITNESS_TOMBSTONED");
      if (head?.tombstoned) fail("WITNESS_TOMBSTONED");
      if (head?.pending_id) {
        const pending = this.lastPending.get(key, head.pending_id);
        // An ACK can be lost after a durable reservation. Only the exact
        // originally signed operation is replayable; no mutation or new
        // reservation/event is permitted while pending.
        if (pending && equal(pending.reservation_id, op.reservation_id)
          && equal(pending.operation_id, op.operation_id)
          && equal(pending.envelope, raw)) return;
        fail("WITNESS_PENDING");
      }
      const quiescing = this.quiesce.get(key);
      if (quiescing && !equal(quiescing.operation, rawOperation)) {
        fail("WITNESS_QUIESCING");
      }
      // A reservation cannot enter PENDING while an authenticated worker
      // retains I/O authority. No timeout or restart silently clears it.
      if (this.activeIo.get(key)) fail("WITNESS_IO_ACTIVE");
      if (this.catalogActive?.get(key)) fail("WITNESS_CATALOG_ACTIVE");
      // The exact drained operation atomically replaces its pre-reservation
      // quiescence marker with the durable signed PENDING reservation.
      if (quiescing) this.db.prepare("DELETE FROM witness_quiesce WHERE scope_key=?").run(key);
      // Reservation + terminal completion consume TWO immutable event
      // records. Leave room for the unavoidable resolution, even at cap.
      if (this.countEvents.get(key).count + 2 > this.maxEventsPerScope) {
        fail("WITNESS_CAPACITY_EXHAUSTED");
      }
      if (head) {
        if (head.revision !== op.expected_revision
          || !equal(head.digest, op.expected_manifest_digest)) fail("WITNESS_CONFLICT");
        if (this.setPending.run(op.reservation_id, key).changes !== 1) fail("WITNESS_PENDING");
      } else {
        if (op.expected_revision !== null || op.expected_manifest_digest !== null) fail("WITNESS_CONFLICT");
        this.insertScope.run(key, op.keyring_id, op.reservation_id);
      }
      this.insertEvent.run(key, "reserved", op.reservation_id,
        op.operation_id, raw, null);
    }).immediate();
    return raw;
  }

  async checkedScope(scope) {
    const s = normalizeScope(scope);
    const key = compartmentKey(s.account_id, s.compartment_id);
    // SQLite read snapshot prevents false corruption on concurrent commits.
    const snapshot = this.db.transaction(() => ({
      row: this.getScope.get(key),
      events: this.allEvents.all(key),
    }))();
    const { row, events } = snapshot;
    if (!row || !equal(row.keyring_id, s.keyring_id)) fail("WITNESS_NO_HEAD");
    if (events.length > this.maxEventsPerScope) fail("WITNESS_LEDGER_CORRUPT");
    let revision = null;
    let digest = null;
    let pending = null;
    let tombstoned = 0;
    const publicKey = crypto.createPublicKey(this.witnessPrivateKey);
    for (const event of events) {
      let receipt;
      try { receipt = await z.decodeDeterministic(event.envelope); }
      catch (_) { fail("WITNESS_LEDGER_CORRUPT"); }
      if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)
        || !equal(receipt.reservation_id, event.reservation_id)
        || !equal(receipt.operation_id, event.operation_id)
        || !equal(receipt.account_id, s.account_id)
        || !equal(receipt.compartment_id, s.compartment_id)
        || !equal(receipt.keyring_id, s.keyring_id)) fail("WITNESS_LEDGER_CORRUPT");
      const fields = { ...receipt };
      const signature = fields.signature;
      delete fields.signature;
      const domain = event.kind === "reserved" ? RESERVE_DOMAIN
        : event.kind === "committed" ? COMMIT_DOMAIN
          : event.kind === "cancelled" ? CANCEL_DOMAIN : null;
      if (!domain || !(signature instanceof Uint8Array) || signature.length !== 64
        || !crypto.verify(null, Buffer.concat([domain,
          await z.encodeDeterministic(fields)]), publicKey, Buffer.from(signature))) {
        fail("WITNESS_LEDGER_CORRUPT");
      }
      if (event.kind === "reserved") {
        if (pending || tombstoned || receipt.type !== "rootark-recovery-witness-reservation/v1"
          || receipt.expected_revision !== revision
          || (digest === null ? receipt.expected_manifest_digest !== null
            : !equal(receipt.expected_manifest_digest, digest))
          || receipt.proposed_revision !== (revision === null ? 1 : revision + 1)) {
          fail("WITNESS_LEDGER_CORRUPT");
        }
        pending = receipt;
      } else {
        if (!pending || !equal(pending.reservation_id, receipt.reservation_id)
          || !equal(pending.operation_id, receipt.operation_id)) fail("WITNESS_LEDGER_CORRUPT");
        if (event.kind === "committed") {
          if (receipt.status !== "committed"
            || receipt.type !== "rootark-recovery-witness-commit/v1"
            || receipt.committed_revision !== pending.proposed_revision
            || !equal(receipt.committed_manifest_digest, pending.proposed_manifest_digest)
            || receipt.witness_sequence !== pending.proposed_revision
            || !(event.proof_digest instanceof Buffer)
            || event.proof_digest.length !== 32) fail("WITNESS_LEDGER_CORRUPT");
          revision = pending.proposed_revision;
          digest = Buffer.from(pending.proposed_manifest_digest);
        } else {
          if (receipt.type !== "rootark-recovery-witness-cancel/v1"
            || receipt.status !== "cancelled"
            || !(event.proof_digest instanceof Buffer)
            || !equal(receipt.status_authority_proof_digest, event.proof_digest)) {
            fail("WITNESS_LEDGER_CORRUPT");
          }
          if (revision === null) tombstoned = 1;
        }
        pending = null;
      }
    }
    if ((pending === null) !== (row.pending_id === null)
      || (pending && !equal(pending.reservation_id, row.pending_id))
      || row.revision !== revision || row.tombstoned !== tombstoned
      || (digest === null ? row.digest !== null : !equal(digest, row.digest))) {
      fail("WITNESS_LEDGER_CORRUPT");
    }
    return { row, scope: s, key };
  }

  async freshHead({ scope, nonce }) {
    const s = normalizeScope(scope);
    const challenge = bytes(nonce, 32);
    const { row: head, key } = await this.checkedScope(s);
    if (this.quiesce.get(key)) fail("WITNESS_QUIESCING");
    const pending = Boolean(head.pending_id);
    // A tombstoned first initialize is deliberately not an acceptable
    // committed head and does not permit a second initialize.
    const status = pending ? "pending" : head.revision === null ? "absent" : "committed";
    const signed = await this.sign({
      type: "rootark-recovery-witness-head/v1", witness_key_id: this.witnessKeyId,
      ...s, current_revision: pending ? null : head.revision,
      current_manifest_digest: pending ? null : head.digest,
      witness_sequence: head.revision ?? 0,
      nonce: challenge, observed_at: number(this.nowSeconds()),
      status, pending_reservation_id: pending ? Buffer.from(head.pending_id) : null,
    }, HEAD_DOMAIN);
    // A competing process may reserve while CBOR encodes/signs. Serialize
    // issuance with all writers and reject a no-longer-current snapshot.
    // The linearization point is this immediate write-lock check, not the
    // earlier asynchronous read. This still does NOT replace a physical
    // I/O admission fence or an independent witness transport.
    this.db.transaction(() => {
      if (this.quiesce.get(key)) fail("WITNESS_QUIESCING");
      this.assertClockFloor(key, number(this.nowSeconds()));
      const current = this.getScope.get(key);
      if (!current || !equal(current.keyring_id, head.keyring_id)
        || current.revision !== head.revision
        || current.tombstoned !== head.tombstoned
        || (current.pending_id === null) !== (head.pending_id === null)
        || (head.pending_id && !equal(current.pending_id, head.pending_id))
        || (current.digest === null) !== (head.digest === null)
        || (head.digest && !equal(current.digest, head.digest))) {
        fail("WITNESS_GATE_CHANGED");
      }
    }).immediate();
    return signed;
  }

  async resolve({ scope }) {
    const s = normalizeScope(scope);
    const { key, row: head } = await this.checkedScope(s);
    if (!head.pending_id) fail("WITNESS_NO_PENDING");
    const reserved = this.lastPending.get(key, head.pending_id);
    if (!reserved) fail("WITNESS_UNRESOLVED");
    let op;
    try { op = await z.decodeDeterministic(reserved.envelope); }
    catch (_) { fail("WITNESS_UNRESOLVED"); }
    // The external transport is hostile/mutable. Its input must NEVER
    // alias the signed durable reservation, the local verification context
    // or the unpredictable nonce used by the actual signature verifier.
    const query = Object.create(null);
    for (const field of STATUS_FIELDS) {
      const value = op[field];
      query[field] = value instanceof Uint8Array ? Buffer.from(value) : value;
    }
    const transportQuery = Object.create(null);
    for (const field of STATUS_FIELDS) {
      const value = query[field];
      transportQuery[field] = Buffer.isBuffer(value) ? Buffer.from(value) : value;
    }
    // Generated by this independent witness engine, never provided by the
    // app or reused from a caller request.
    const nonce = crypto.randomBytes(32);
    let raw;
    let verified;
    let terminal;
    try {
      raw = bytes(await this.statusProvider.getTerminalProof({
        query: transportQuery, nonce: Buffer.from(nonce),
      }), 1, 8 * 1024 * 1024);
      verified = await inspectVerifiedCasStatusProofV1({
        raw, query, nonce, pinned: this.statusPinned,
      });
      terminal = await z.decodeDeterministic(raw);
    } catch (_) { fail("WITNESS_UNRESOLVED"); }
    if (verified.verifiedSignatureOnly !== true || verified.authorizesRecovery !== false
      || !["committed", "not-committed-final"].includes(verified.terminal_status)) {
      fail("WITNESS_UNRESOLVED");
    }
    // Fresh challenge signature is necessary but not sufficient: the
    // configured authority's UTC observation must also fit the bounded
    // skew budget. A stale/future status cannot open the pending gate.
    const observedAt = number(terminal.observed_at);
    const witnessNow = number(this.nowSeconds());
    if (Math.abs(observedAt - witnessNow) > 30) fail("WITNESS_UNRESOLVED");
    if (verified.terminal_status === "not-committed-final"
      && witnessNow < op.expires_at + 30) fail("WITNESS_UNRESOLVED");
    const proofDigest = crypto.createHash("sha256").update(raw).digest();
    const committed = verified.terminal_status === "committed";
    const receipt = committed ? {
      type: "rootark-recovery-witness-commit/v1", reservation_id: op.reservation_id,
      account_id: op.account_id, compartment_id: op.compartment_id,
      keyring_id: op.keyring_id, committed_revision: op.proposed_revision,
      committed_manifest_digest: op.proposed_manifest_digest,
      operation_id: op.operation_id, witness_sequence: op.proposed_revision,
      status: "committed",
    } : {
      type: "rootark-recovery-witness-cancel/v1",
      witness_key_id: this.witnessKeyId,
      account_id: op.account_id, compartment_id: op.compartment_id,
      keyring_id: op.keyring_id, reservation_id: op.reservation_id,
      operation_id: op.operation_id, status_authority_proof_digest: proofDigest,
      resolved_at: number(this.nowSeconds()), status: "cancelled",
    };
    const wire = await this.sign(receipt, committed ? COMMIT_DOMAIN : CANCEL_DOMAIN);
    this.db.transaction(() => {
      const row = this.getScope.get(key);
      if (!row || !equal(row.pending_id, op.reservation_id)
        || !equal(row.keyring_id, op.keyring_id)
        || row.revision !== op.expected_revision
        || (row.digest === null ? op.expected_manifest_digest !== null
          : !equal(row.digest, op.expected_manifest_digest))) fail("WITNESS_UNRESOLVED");
      this.db.prepare(
        "UPDATE witness_scope SET revision=?, digest=?, pending_id=NULL, tombstoned=? WHERE scope_key=?",
      ).run(committed ? op.proposed_revision : op.expected_revision,
        committed ? op.proposed_manifest_digest : op.expected_manifest_digest,
        committed ? 0 : row.revision === null ? 1 : row.tombstoned, key);
      this.insertEvent.run(key, committed ? "committed" : "cancelled",
        op.reservation_id, op.operation_id, wire, proofDigest);
    }).immediate();
    // Do not return terminal signed proof as a recoverability claim.
    return { status: committed ? "committed" : "cancelled", receipt: wire };
  }
  close() { if (this.db.open) this.db.close(); }
}

module.exports = { Zk1DurableWitnessLedger };
