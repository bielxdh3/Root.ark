"use strict";

// Standalone local experimental catalog. This does not prove an independent
// operator, rollback-resistant storage, or atomicity with ciphertext writes.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteFile,
  assertPrivateSqliteAuthorityDirectory } = require("./zk1PrivateSqlitePath");
const Database = require("better-sqlite3");
const z = require("../crypto/rootark-zk-1");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");

const ENTRY_TYPE = "rootark-content-inventory-entry/v1";
const ENTRY_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0", "ascii");
const SCHEMA_VERSION = 1;
const MAX_PENDING = 1;
const MAX_TERMINAL = inventory.MAX_ENTRIES;
const IDENTITY_COLUMNS = ["id", "schema_version", "signer_key_id", "signer_fingerprint", "scope_cbor", "genesis_root"];
const HEAD_COLUMNS = ["id", "sequence", "root"];
const OPERATION_COLUMNS = ["operation_id", "request_cbor", "expected_sequence", "expected_root", "status", "sequence", "root"];
const TERMINAL_COLUMNS = ["operation_id", "request_cbor", "proof_cbor"];
const ENTRY_COLUMNS = [
  "sequence", "operation_id", "object_id", "revision", "epoch", "ciphertext_sha256",
  "expected_sequence", "expected_root", "previous_root", "root", "request_digest", "signature",
];
const TABLE_COLUMNS = Object.freeze({
  content_identity: IDENTITY_COLUMNS,
  content_head: HEAD_COLUMNS,
  content_operation: OPERATION_COLUMNS,
  content_terminal_operation: TERMINAL_COLUMNS,
  content_entry: ENTRY_COLUMNS,
});
const REQUIRED_TRIGGERS = Object.freeze([
  "content_identity_no_update", "content_identity_no_delete", "content_head_no_delete",
  "content_entry_no_update", "content_entry_no_delete", "content_operation_no_delete",
  "content_operation_committed_no_update",
]);
const TERMINAL_TRIGGERS = Object.freeze([
  "content_terminal_no_update", "content_terminal_no_delete",
]);

const SCHEMA = `
  CREATE TABLE content_identity (
    id INTEGER PRIMARY KEY CHECK(id=1),
    schema_version INTEGER NOT NULL CHECK(schema_version=1),
    signer_key_id BLOB NOT NULL CHECK(length(signer_key_id)=16),
    signer_fingerprint BLOB NOT NULL CHECK(length(signer_fingerprint)=32),
    scope_cbor BLOB NOT NULL,
    genesis_root BLOB NOT NULL CHECK(length(genesis_root)=32)
  );
  CREATE TABLE content_head (
    id INTEGER PRIMARY KEY CHECK(id=1),
    sequence INTEGER NOT NULL CHECK(sequence>=0),
    root BLOB NOT NULL CHECK(length(root)=32)
  );
  CREATE TABLE content_operation (
    operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=16),
    request_cbor BLOB NOT NULL,
    expected_sequence INTEGER NOT NULL CHECK(expected_sequence>=0),
    expected_root BLOB NOT NULL CHECK(length(expected_root)=32),
    status TEXT NOT NULL CHECK(status IN ('pending','committed')),
    sequence INTEGER UNIQUE,
    root BLOB CHECK(root IS NULL OR length(root)=32),
    CHECK((status='pending' AND sequence IS NULL AND root IS NULL)
      OR (status='committed' AND sequence IS NOT NULL AND root IS NOT NULL))
  );
  CREATE TABLE content_terminal_operation (
    operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=16),
    request_cbor BLOB NOT NULL,
    proof_cbor BLOB NOT NULL
  );
  CREATE TABLE content_entry (
    sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
    operation_id BLOB NOT NULL UNIQUE REFERENCES content_operation(operation_id),
    object_id BLOB NOT NULL CHECK(length(object_id)=16),
    revision INTEGER NOT NULL CHECK(revision>=1),
    epoch INTEGER NOT NULL CHECK(epoch>=0),
    ciphertext_sha256 BLOB NOT NULL CHECK(length(ciphertext_sha256)=32),
    expected_sequence INTEGER NOT NULL CHECK(expected_sequence>=0),
    expected_root BLOB NOT NULL CHECK(length(expected_root)=32),
    previous_root BLOB NOT NULL CHECK(length(previous_root)=32),
    root BLOB NOT NULL CHECK(length(root)=32),
    request_digest BLOB NOT NULL CHECK(length(request_digest)=32),
    signature BLOB NOT NULL CHECK(length(signature)=64),
    UNIQUE(object_id, revision)
  );
  CREATE TRIGGER content_identity_no_update BEFORE UPDATE ON content_identity
    BEGIN SELECT RAISE(ABORT, 'immutable content identity'); END;
  CREATE TRIGGER content_identity_no_delete BEFORE DELETE ON content_identity
    BEGIN SELECT RAISE(ABORT, 'immutable content identity'); END;
  CREATE TRIGGER content_head_no_delete BEFORE DELETE ON content_head
    BEGIN SELECT RAISE(ABORT, 'immutable content head'); END;
  CREATE TRIGGER content_entry_no_update BEFORE UPDATE ON content_entry
    BEGIN SELECT RAISE(ABORT, 'immutable content entry'); END;
  CREATE TRIGGER content_entry_no_delete BEFORE DELETE ON content_entry
    BEGIN SELECT RAISE(ABORT, 'immutable content entry'); END;
  CREATE TRIGGER content_operation_no_delete BEFORE DELETE ON content_operation
    BEGIN SELECT RAISE(ABORT, 'immutable content operation'); END;
  CREATE TRIGGER content_operation_committed_no_update BEFORE UPDATE ON content_operation
    WHEN OLD.status='committed' OR NEW.status<>'committed'
      OR NEW.operation_id IS NOT OLD.operation_id
      OR NEW.request_cbor IS NOT OLD.request_cbor
      OR NEW.expected_sequence IS NOT OLD.expected_sequence
      OR NEW.expected_root IS NOT OLD.expected_root
    BEGIN SELECT RAISE(ABORT, 'immutable committed content operation'); END;
  CREATE TRIGGER content_terminal_no_update BEFORE UPDATE ON content_terminal_operation
    BEGIN SELECT RAISE(ABORT, 'immutable terminal content operation'); END;
  CREATE TRIGGER content_terminal_no_delete BEFORE DELETE ON content_terminal_operation
    BEGIN SELECT RAISE(ABORT, 'immutable terminal content operation'); END;
`;

const TERMINAL_SCHEMA = `
  CREATE TABLE content_terminal_operation (
    operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=16),
    request_cbor BLOB NOT NULL,
    proof_cbor BLOB NOT NULL
  );
  CREATE TRIGGER content_terminal_no_update BEFORE UPDATE ON content_terminal_operation
    BEGIN SELECT RAISE(ABORT, 'immutable terminal content operation'); END;
  CREATE TRIGGER content_terminal_no_delete BEFORE DELETE ON content_terminal_operation
    BEGIN SELECT RAISE(ABORT, 'immutable terminal content operation'); END;
`;

class DurableContentInventoryError extends Error {
  constructor(code) {
    super(code);
    this.name = "DurableContentInventoryError";
    this.code = code;
  }
}

function fail(code) {
  throw new DurableContentInventoryError(code);
}

function bytes(value, length) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) fail("INVENTORY_INVALID_BYTES");
  if (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer) {
    fail("INVENTORY_SHARED_BYTES");
  }
  if (value.byteLength !== length) fail("INVENTORY_INVALID_BYTES");
  return Buffer.from(value);
}

function same(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b)
    && a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest();
}

function exact(value, fields, code = "INVENTORY_OPERATION") {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) fail(code);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || fields.some((field) => !keys.includes(field))) fail(code);
  const result = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail(code);
    result[field] = descriptor.value;
  }
  return result;
}

function operationMap(operation) {
  return {
    operation_id: operation.operation_id,
    expected_sequence: operation.expected_sequence,
    expected_root: operation.expected_root,
    object_id: operation.entry.object_id,
    revision: operation.entry.revision,
    epoch: operation.entry.epoch,
    ciphertext_sha256: operation.entry.ciphertext_sha256,
  };
}

function normalizeOperation(input) {
  const raw = exact(input, [
    "operation_id", "expected_sequence", "expected_root", "object_id", "revision", "epoch", "ciphertext_sha256",
  ]);
  if (!Number.isSafeInteger(raw.expected_sequence) || raw.expected_sequence < 0) fail("INVENTORY_OPERATION");
  return {
    operation_id: bytes(raw.operation_id, 16),
    expected_sequence: raw.expected_sequence,
    expected_root: bytes(raw.expected_root, 32),
    entry: inventory.normalizeEntry({
      object_id: raw.object_id,
      revision: raw.revision,
      epoch: raw.epoch,
      ciphertext_sha256: raw.ciphertext_sha256,
    }),
  };
}

function fingerprint(publicKey) {
  return sha256(publicKey.export({ format: "der", type: "spki" }));
}

function copyRowBytes(value, length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) || value.byteLength !== length) {
    fail("INVENTORY_LEDGER_CORRUPT");
  }
  return Buffer.from(value);
}

function fileIdentity(filename) {
  let stat;
  try { stat = fs.lstatSync(filename, { bigint: true }); } catch (_) { fail("INVENTORY_STATE"); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) fail("INVENTORY_STATE");
  return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
}

function schemaTableNames(db) {
  const where = "name NOT LIKE 'sqlite_%' AND type IN ('table','view','trigger')";
  const maximum = Object.keys(TABLE_COLUMNS).length + REQUIRED_TRIGGERS.length + TERMINAL_TRIGGERS.length;
  const rows = db.prepare(`SELECT type, name FROM sqlite_master WHERE ${where}
    ORDER BY type,name LIMIT ${maximum + 1}`).all();
  if (rows.length > maximum) fail("INVENTORY_STATE");
  return rows;
}

function validateSchema(db) {
  let objects;
  try { objects = schemaTableNames(db); } catch (_) { fail("INVENTORY_STATE"); }
  const actual = objects.map((row) => `${row.type}:${row.name}`).sort();
  const legacyExpected = [
    ...Object.keys(TABLE_COLUMNS).filter((name) => name !== "content_terminal_operation")
      .map((name) => `table:${name}`),
    ...REQUIRED_TRIGGERS.map((name) => `trigger:${name}`),
  ].sort();
  const currentExpected = [
    ...legacyExpected,
    "table:content_terminal_operation",
    ...TERMINAL_TRIGGERS.map((name) => `trigger:${name}`),
  ].sort();
  const hasTerminal = actual.length === currentExpected.length
    && currentExpected.every((name, index) => name === actual[index]);
  const isLegacy = actual.length === legacyExpected.length
    && legacyExpected.every((name, index) => name === actual[index]);
  if (!hasTerminal && !isLegacy) {
    fail("INVENTORY_STATE");
  }
  const columnsToCheck = hasTerminal ? TABLE_COLUMNS : Object.fromEntries(
    Object.entries(TABLE_COLUMNS).filter(([table]) => table !== "content_terminal_operation"),
  );
  for (const [table, columns] of Object.entries(columnsToCheck)) {
    let actualColumns;
    try { actualColumns = db.pragma(`table_info(${table})`).map((row) => row.name); }
    catch (_) { fail("INVENTORY_STATE"); }
    if (actualColumns.length !== columns.length || columns.some((column, index) => actualColumns[index] !== column)) {
      fail("INVENTORY_STATE");
    }
  }
  return hasTerminal;
}

function compareEntries(a, b) {
  const objectOrder = Buffer.compare(a.object_id, b.object_id);
  return objectOrder || a.revision - b.revision;
}

class Zk1DurableContentInventoryLedger {
  static async open(filename, options) {
    const ledger = new Zk1DurableContentInventoryLedger(filename, options);
    try {
      await ledger.initialize();
      return ledger;
    } catch (error) {
      try { ledger.close(); } catch (_) { /* keep the original failure */ }
      throw error;
    }
  }

  constructor(filename, options) {
    const raw = exact(options, ["bootstrapNew", "signerKeyId", "signerPrivateKey", "scope"], "INVENTORY_OPTIONS");
    if (typeof filename !== "string" || !filename || !path.isAbsolute(filename)
      || filename.includes("\0") || typeof raw.bootstrapNew !== "boolean") fail("INVENTORY_OPTIONS");
    if (!(raw.signerPrivateKey instanceof crypto.KeyObject)
      || raw.signerPrivateKey.type !== "private" || raw.signerPrivateKey.asymmetricKeyType !== "ed25519") {
      fail("INVENTORY_SIGNER_KEY");
    }
    this.filename = path.resolve(filename);
    this.bootstrapNew = raw.bootstrapNew;
    this.signerKeyId = bytes(raw.signerKeyId, 16);
    this.privateKey = raw.signerPrivateKey;
    this.publicKey = crypto.createPublicKey(this.privateKey);
    this.keyFingerprint = fingerprint(this.publicKey);
    this.scope = inventory.normalizeScope(raw.scope);
    this.db = null;
    this.closed = false;
    this.scopeCbor = null;
    this.genesisRoot = null;
  }

  async initialize() {
    this.scopeCbor = await z.encodeDeterministic(this.scope);
    this.genesisRoot = await inventory.computeRoot(this.scope, 0, null, []);
    // WAL/SHM files are opened by pathname. Reject unsafe directory ACLs
    // before any SQLite open, CREATE, or schema write.
    this.assertAuthorityDirectory();
    const existed = fs.existsSync(this.filename);
    if (!existed && !this.bootstrapNew) fail("INVENTORY_BOOTSTRAP_REQUIRED");
    if (existed && this.bootstrapNew) fail("INVENTORY_BOOTSTRAP_NEW_ONLY");
    let expectedIdentity;
    let hasTerminal = false;
    if (existed) {
      try {
        assertPrivateSqliteFile(this.filename);
        this.assertAuthorityDirectory();
      } catch (_) { fail("INVENTORY_STATE"); }
      expectedIdentity = fileIdentity(this.filename);
      const readonly = this.openDatabase(true);
      try {
        this.checkPragmas(readonly, false);
        hasTerminal = validateSchema(readonly);
        this.verifyIdentity(readonly);
        if (readonly.pragma("quick_check", { simple: true }) !== "ok") fail("INVENTORY_STATE");
      } catch (error) {
        if (error instanceof DurableContentInventoryError) throw error;
        fail("INVENTORY_STATE");
      } finally { readonly.close(); }
      if (fileIdentity(this.filename) !== expectedIdentity) fail("INVENTORY_STATE");
      try {
        assertPrivateSqliteFile(this.filename);
        this.assertAuthorityDirectory();
      } catch (_) { fail("INVENTORY_STATE"); }
    } else {
      try {
        ensurePrivateSqliteDirectory(this.filename);
        this.assertAuthorityDirectory();
      }
      catch (_) { fail("INVENTORY_STATE"); }
      let fd;
      try {
        fd = fs.openSync(this.filename, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR, 0o600);
      } catch (_) { fail("INVENTORY_STATE"); }
      try { fs.closeSync(fd); } catch (_) { fail("INVENTORY_STATE"); }
      expectedIdentity = fileIdentity(this.filename);
    }
    try {
      assertPrivateSqliteFile(this.filename);
      this.assertAuthorityDirectory();
    } catch (_) { fail("INVENTORY_STATE"); }
    this.db = this.openDatabase(false);
    try {
      assertPrivateSqliteFile(this.filename);
      this.assertAuthorityDirectory();
    } catch (_) { fail("INVENTORY_STATE"); }
    if (fileIdentity(this.filename) !== expectedIdentity) fail("INVENTORY_STATE");
    if (existed) {
      validateSchema(this.db);
      this.verifyIdentity(this.db);
      this.configureWal(this.db);
      if (!hasTerminal) {
        const migrate = this.db.transaction(() => {
          if (!validateSchema(this.db)) this.db.exec(TERMINAL_SCHEMA);
        });
        try { migrate.immediate(); } catch (_) { fail("INVENTORY_STATE"); }
      }
      validateSchema(this.db);
    } else {
      this.configureWal(this.db);
      try { this.db.exec(SCHEMA); } catch (_) { fail("INVENTORY_STATE"); }
      const bootstrap = this.db.transaction(() => {
        this.db.prepare(`INSERT INTO content_identity
          (id,schema_version,signer_key_id,signer_fingerprint,scope_cbor,genesis_root)
          VALUES(1,?,?,?,?,?)`).run(
          SCHEMA_VERSION, this.signerKeyId, this.keyFingerprint, this.scopeCbor, this.genesisRoot,
        );
        this.db.prepare("INSERT INTO content_head(id,sequence,root) VALUES(1,0,?)")
          .run(this.genesisRoot);
      });
      try { bootstrap.immediate(); } catch (_) { fail("INVENTORY_STATE"); }
    }
    this.verifyIdentity(this.db);
    this.checkPragmas(this.db, true);
    await this.loadState();
  }

  openDatabase(readonly) {
    try {
      this.assertAuthorityDirectory();
      return new Database(this.filename, { readonly, fileMustExist: true });
    } catch (_) { fail("INVENTORY_STATE"); }
  }

  assertAuthorityDirectory() {
    try {
      assertPrivateSqliteAuthorityDirectory(this.filename);
    } catch (_) { fail("INVENTORY_STATE"); }
  }

  configureWal(db) {
    try {
      const mode = db.pragma("journal_mode = WAL", { simple: true });
      if (String(mode).toLowerCase() !== "wal") fail("INVENTORY_WAL");
      db.pragma("synchronous = FULL");
      db.pragma("foreign_keys = ON");
      db.pragma("trusted_schema = OFF");
    } catch (error) {
      if (error instanceof DurableContentInventoryError) throw error;
      fail("INVENTORY_WAL");
    }
  }

  checkPragmas(db, configured) {
    try {
      const mode = String(db.pragma("journal_mode", { simple: true })).toLowerCase();
      const synchronous = db.pragma("synchronous", { simple: true });
      const foreignKeys = db.pragma("foreign_keys", { simple: true });
      if (configured && (mode !== "wal" || synchronous !== 2 || foreignKeys !== 1)) fail("INVENTORY_WAL");
      if (!configured && mode !== "wal") fail("INVENTORY_STATE");
    } catch (error) {
      if (error instanceof DurableContentInventoryError) throw error;
      fail("INVENTORY_STATE");
    }
  }

  verifyIdentity(db) {
    let row;
    try {
      const readIdentity = db.transaction(() => {
        const metrics = this.tableMetrics(db, "content_identity", [
          "signer_key_id", "signer_fingerprint", "scope_cbor", "genesis_root",
        ]);
        this.assertTableMetrics(metrics, {
          exactCount: 1,
          blobLimits: {
            signer_key_id: 16,
            signer_fingerprint: 32,
            scope_cbor: this.scopeCbor.length,
            genesis_root: 32,
          },
          code: "INVENTORY_IDENTITY",
        });
        return db.prepare(`SELECT ${IDENTITY_COLUMNS.join(",")}
          FROM content_identity WHERE id=1`).get();
      });
      row = readIdentity.deferred();
    } catch (error) {
      if (error instanceof DurableContentInventoryError) throw error;
      fail("INVENTORY_STATE");
    }
    this.assertIdentityRow(row);
  }

  tableMetrics(db, table, blobColumns, additional = []) {
    const selections = ["COUNT(*) AS row_count"];
    for (const column of blobColumns) {
      selections.push(`COALESCE(MAX(LENGTH(${column})),0) AS max_${column}`);
    }
    selections.push(...additional);
    return db.prepare(`SELECT ${selections.join(",")} FROM ${table}`).get();
  }

  assertTableMetrics(metrics, { maxCount, exactCount, maxPending, blobLimits, code }) {
    if (!metrics || !Number.isSafeInteger(metrics.row_count) || metrics.row_count < 0
      || (maxCount !== undefined && metrics.row_count > maxCount)
      || (exactCount !== undefined && metrics.row_count !== exactCount)) fail(code);
    if (maxPending !== undefined
      && (!Number.isSafeInteger(metrics.pending_count) || metrics.pending_count < 0
        || metrics.pending_count > maxPending)) fail(code);
    for (const [column, limit] of Object.entries(blobLimits)) {
      const length = metrics[`max_${column}`];
      if (!Number.isSafeInteger(length) || length < 0 || length > limit) fail(code);
    }
  }

  assertIdentityRow(row) {
    if (!row || row.schema_version !== SCHEMA_VERSION) fail("INVENTORY_IDENTITY");
    if ((!Buffer.isBuffer(row.scope_cbor) && !(row.scope_cbor instanceof Uint8Array))
      || row.scope_cbor.byteLength !== this.scopeCbor.length
      || !same(copyRowBytes(row.scope_cbor, this.scopeCbor.length), this.scopeCbor)
      || !same(copyRowBytes(row.genesis_root, 32), this.genesisRoot)) fail("INVENTORY_SCOPE");
    if (!same(copyRowBytes(row.signer_key_id, 16), this.signerKeyId)
      || !same(copyRowBytes(row.signer_fingerprint, 32), this.keyFingerprint)) fail("INVENTORY_IDENTITY");
  }

  readOperationRow(db, operationId) {
    const lengths = db.prepare(`SELECT LENGTH(operation_id) AS operation_id_length,
      LENGTH(request_cbor) AS request_length, LENGTH(expected_root) AS expected_root_length,
      LENGTH(root) AS root_length FROM content_operation WHERE operation_id=?`).get(operationId);
    if (!lengths) return null;
    if (lengths.operation_id_length !== 16 || !Number.isSafeInteger(lengths.request_length)
      || lengths.request_length < 1 || lengths.request_length > 1024
      || lengths.expected_root_length !== 32
      || (lengths.root_length !== null && (!Number.isSafeInteger(lengths.root_length)
        || lengths.root_length > 32))) fail("INVENTORY_LEDGER_CORRUPT");
    return db.prepare(`SELECT ${OPERATION_COLUMNS.join(",")} FROM content_operation WHERE operation_id=?`)
      .get(operationId);
  }

  readTerminalRow(db, operationId) {
    const lengths = db.prepare(`SELECT LENGTH(operation_id) AS operation_id_length,
      LENGTH(request_cbor) AS request_length, LENGTH(proof_cbor) AS proof_length
      FROM content_terminal_operation WHERE operation_id=?`).get(operationId);
    if (!lengths) return null;
    if (lengths.operation_id_length !== 16 || !Number.isSafeInteger(lengths.request_length)
      || lengths.request_length < 1 || lengths.request_length > 1024
      || !Number.isSafeInteger(lengths.proof_length) || lengths.proof_length < 1
      || lengths.proof_length > inventory.MAX_TERMINAL_PROOF_BYTES) fail("INVENTORY_LEDGER_CORRUPT");
    return db.prepare(`SELECT ${TERMINAL_COLUMNS.join(",")} FROM content_terminal_operation
      WHERE operation_id=?`).get(operationId);
  }

  readHeadRow(db) {
    const lengths = db.prepare(`SELECT sequence, LENGTH(root) AS root_length
      FROM content_head WHERE id=1`).get();
    if (!lengths || !Number.isSafeInteger(lengths.sequence) || lengths.sequence < 0
      || lengths.root_length !== 32) fail("INVENTORY_LEDGER_CORRUPT");
    return db.prepare(`SELECT ${HEAD_COLUMNS.join(",")} FROM content_head WHERE id=1`).get();
  }

  assertOpen() {
    if (!this.db || this.closed) fail("INVENTORY_CLOSED");
    this.assertAuthorityDirectory();
  }

  async parseRequestBytes(value) {
    if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) || value.byteLength > 1024) {
      fail("INVENTORY_LEDGER_CORRUPT");
    }
    const encoded = copyRowBytes(value, value?.byteLength);
    let decoded;
    try { decoded = await z.decodeDeterministic(encoded); } catch (_) { fail("INVENTORY_LEDGER_CORRUPT"); }
    const raw = exact(decoded, [
      "operation_id", "expected_sequence", "expected_root", "object_id", "revision", "epoch", "ciphertext_sha256",
    ], "INVENTORY_LEDGER_CORRUPT");
    const operation = normalizeOperation(raw);
    const recanonical = await z.encodeDeterministic(operationMap(operation));
    if (!same(recanonical, encoded)) fail("INVENTORY_LEDGER_CORRUPT");
    return { operation, encoded, digest: sha256(encoded) };
  }

  async loadState() {
    this.assertOpen();
    try {
      if (this.db.pragma("quick_check", { simple: true }) !== "ok") fail("INVENTORY_LEDGER_CORRUPT");
      if (this.db.prepare("PRAGMA foreign_key_check").get() !== undefined) fail("INVENTORY_LEDGER_CORRUPT");
    } catch (error) {
      if (error instanceof DurableContentInventoryError) throw error;
      fail("INVENTORY_LEDGER_CORRUPT");
    }
    let captured;
    try {
      const capture = this.db.transaction(() => {
        const metrics = {
          identity: this.tableMetrics(this.db, "content_identity", [
            "signer_key_id", "signer_fingerprint", "scope_cbor", "genesis_root",
          ]),
          head: this.tableMetrics(this.db, "content_head", ["root"]),
          entries: this.tableMetrics(this.db, "content_entry", [
            "operation_id", "object_id", "ciphertext_sha256", "expected_root",
            "previous_root", "root", "request_digest", "signature",
          ]),
          operations: this.tableMetrics(this.db, "content_operation", [
            "operation_id", "request_cbor", "expected_root", "root",
          ], ["COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0) AS pending_count"]),
          terminal: this.tableMetrics(this.db, "content_terminal_operation", [
            "operation_id", "request_cbor", "proof_cbor",
          ]),
        };
        this.assertTableMetrics(metrics.identity, {
          exactCount: 1,
          blobLimits: {
            signer_key_id: 16,
            signer_fingerprint: 32,
            scope_cbor: this.scopeCbor.length,
            genesis_root: 32,
          },
          code: "INVENTORY_LEDGER_CORRUPT",
        });
        this.assertTableMetrics(metrics.head, {
          exactCount: 1, blobLimits: { root: 32 }, code: "INVENTORY_LEDGER_CORRUPT",
        });
        this.assertTableMetrics(metrics.entries, {
          maxCount: inventory.MAX_ENTRIES,
          blobLimits: {
            operation_id: 16, object_id: 16, ciphertext_sha256: 32, expected_root: 32,
            previous_root: 32, root: 32, request_digest: 32, signature: 64,
          },
          code: "INVENTORY_LEDGER_CORRUPT",
        });
        this.assertTableMetrics(metrics.operations, {
          maxCount: inventory.MAX_ENTRIES + MAX_PENDING,
          maxPending: MAX_PENDING,
          blobLimits: { operation_id: 16, request_cbor: 1024, expected_root: 32, root: 32 },
          code: "INVENTORY_LEDGER_CORRUPT",
        });
        this.assertTableMetrics(metrics.terminal, {
          maxCount: MAX_TERMINAL,
          blobLimits: {
            operation_id: 16, request_cbor: 1024,
            proof_cbor: inventory.MAX_TERMINAL_PROOF_BYTES,
          },
          code: "INVENTORY_LEDGER_CORRUPT",
        });
        const identity = this.db.prepare(`SELECT ${IDENTITY_COLUMNS.join(",")}
          FROM content_identity WHERE id=1`).get();
        const head = this.db.prepare(`SELECT ${HEAD_COLUMNS.join(",")} FROM content_head WHERE id=1`).get();
        const rows = this.db.prepare(`SELECT ${ENTRY_COLUMNS.join(",")}
          FROM content_entry ORDER BY sequence`).all();
        const operationRows = this.db.prepare(`SELECT ${OPERATION_COLUMNS.join(",")}
          FROM content_operation ORDER BY operation_id`).all();
        const terminalRows = this.db.prepare(`SELECT ${TERMINAL_COLUMNS.join(",")}
          FROM content_terminal_operation ORDER BY operation_id`).all();
        return { identity, head, rows, operationRows, terminalRows };
      });
      captured = capture.deferred();
    } catch (error) {
      if (error instanceof DurableContentInventoryError) throw error;
      fail("INVENTORY_LEDGER_CORRUPT");
    }
    this.assertIdentityRow(captured.identity);
    const { head, rows, operationRows, terminalRows } = captured;
    if (!head || !Number.isSafeInteger(head.sequence) || head.sequence < 0
      || rows.length > inventory.MAX_ENTRIES
      || operationRows.length > inventory.MAX_ENTRIES + MAX_PENDING
      || terminalRows.length > MAX_TERMINAL) fail("INVENTORY_LEDGER_CORRUPT");

    const operations = new Map();
    let pendingCount = 0;
    for (const row of operationRows) {
      const operationId = copyRowBytes(row.operation_id, 16);
      const key = operationId.toString("hex");
      if (operations.has(key) || !["pending", "committed"].includes(row.status)) fail("INVENTORY_LEDGER_CORRUPT");
      const parsed = await this.parseRequestBytes(row.request_cbor);
      const operation = parsed.operation;
      if (!same(operation.operation_id, operationId)
        || row.expected_sequence !== operation.expected_sequence
        || !same(copyRowBytes(row.expected_root, 32), operation.expected_root)) fail("INVENTORY_LEDGER_CORRUPT");
      if (row.status === "pending") {
        if (row.sequence !== null || row.root !== null) fail("INVENTORY_LEDGER_CORRUPT");
        pendingCount += 1;
        operations.set(key, { ...parsed, status: "pending", sequence: null, root: null, seen: false });
      } else {
        if (!Number.isSafeInteger(row.sequence) || row.sequence < 1 || row.sequence > inventory.MAX_ENTRIES
          || !row.root) fail("INVENTORY_LEDGER_CORRUPT");
        operations.set(key, {
          ...parsed,
          status: "committed",
          sequence: row.sequence,
          root: copyRowBytes(row.root, 32),
          seen: false,
        });
      }
    }
    if (pendingCount > MAX_PENDING) fail("INVENTORY_LEDGER_CORRUPT");

    const entries = [];
    const chronology = new Map();
    let previousRoot = this.genesisRoot;
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      const sequence = index + 1;
      if (row.sequence !== sequence || row.expected_sequence !== sequence - 1) fail("INVENTORY_LEDGER_CORRUPT");
      const operationId = copyRowBytes(row.operation_id, 16);
      const op = operations.get(operationId.toString("hex"));
      if (!op || op.status !== "committed" || op.seen || op.sequence !== sequence) fail("INVENTORY_LEDGER_CORRUPT");
      const tuple = inventory.normalizeEntry({
        object_id: row.object_id,
        revision: row.revision,
        epoch: row.epoch,
        ciphertext_sha256: row.ciphertext_sha256,
      });
      if (!same(tuple.object_id, op.operation.entry.object_id)
        || tuple.revision !== op.operation.entry.revision || tuple.epoch !== op.operation.entry.epoch
        || !same(tuple.ciphertext_sha256, op.operation.entry.ciphertext_sha256)
        || !same(op.root, copyRowBytes(row.root, 32))) fail("INVENTORY_LEDGER_CORRUPT");
      const expectedRoot = copyRowBytes(row.expected_root, 32);
      const rowPreviousRoot = copyRowBytes(row.previous_root, 32);
      const root = copyRowBytes(row.root, 32);
      const requestDigest = copyRowBytes(row.request_digest, 32);
      const signature = copyRowBytes(row.signature, 64);
      if (!same(expectedRoot, previousRoot) || !same(rowPreviousRoot, previousRoot)
        || !same(requestDigest, op.digest) || op.operation.expected_sequence !== sequence - 1
        || !same(op.operation.expected_root, previousRoot)) fail("INVENTORY_LEDGER_CORRUPT");
      const chronologyKey = tuple.object_id.toString("hex");
      const last = chronology.get(chronologyKey);
      if ((!last && tuple.revision !== 1)
        || (last && (tuple.revision !== last.revision + 1 || tuple.epoch < last.epoch))) {
        fail("INVENTORY_LEDGER_CORRUPT");
      }
      chronology.set(chronologyKey, { revision: tuple.revision, epoch: tuple.epoch });
      const unsigned = {
        type: ENTRY_TYPE,
        version: 1,
        signer_key_id: this.signerKeyId,
        scope: this.scope,
        sequence,
        previous_root: previousRoot,
        root,
        operation_id: operationId,
        expected_sequence: sequence - 1,
        expected_root: previousRoot,
        request_digest: requestDigest,
        entry: tuple,
      };
      let valid = false;
      try {
        valid = crypto.verify(null, Buffer.concat([
          ENTRY_DOMAIN,
          await z.encodeDeterministic(unsigned),
        ]), this.publicKey, signature);
      } catch (_) { fail("INVENTORY_LEDGER_CORRUPT"); }
      if (!valid) fail("INVENTORY_LEDGER_CORRUPT");
      op.signedEntry = { ...unsigned, signature: Buffer.from(signature) };
      op.seen = true;
      op.entry = tuple;
      entries.push(tuple);
      previousRoot = root;
    }
    if (operations.size - pendingCount !== rows.length || [...operations.values()].some((op) =>
      op.status === "committed" && !op.seen)) fail("INVENTORY_LEDGER_CORRUPT");
    if (head.sequence !== rows.length) fail("INVENTORY_LEDGER_CORRUPT");
    const headRoot = copyRowBytes(head.root, 32);
    if (!same(headRoot, previousRoot)) fail("INVENTORY_LEDGER_CORRUPT");
    const sorted = entries.slice().sort(compareEntries);
    let calculatedRoot;
    if (rows.length === 0) calculatedRoot = this.genesisRoot;
    else calculatedRoot = await inventory.computeRoot(this.scope, rows.length, previousRootFor(rows), sorted);
    if (!same(calculatedRoot, headRoot)) fail("INVENTORY_LEDGER_CORRUPT");
    const pending = [...operations.values()].filter((op) => op.status === "pending");
    const terminalOperations = new Map();
    for (const row of terminalRows) {
      const operationId = copyRowBytes(row.operation_id, 16);
      const key = operationId.toString("hex");
      if (operations.has(key) || terminalOperations.has(key)) fail("INVENTORY_LEDGER_CORRUPT");
      const parsed = await this.parseRequestBytes(row.request_cbor);
      if (!same(parsed.operation.operation_id, operationId)) fail("INVENTORY_LEDGER_CORRUPT");
      if (!Buffer.isBuffer(row.proof_cbor) || row.proof_cbor.length < 1
        || row.proof_cbor.length > inventory.MAX_TERMINAL_PROOF_BYTES) fail("INVENTORY_LEDGER_CORRUPT");
      let verified;
      try {
        verified = await inventory.verifyTerminalProof({
          serialized: row.proof_cbor,
          pinnedPublicKey: this.publicKey,
          pinnedSignerKeyId: this.signerKeyId,
          expectedScope: this.scope,
          operation: operationMap(parsed.operation),
        });
      } catch (_) { fail("INVENTORY_LEDGER_CORRUPT"); }
      if (verified.outcome !== "NOT_COMMITTED_FINAL") fail("INVENTORY_LEDGER_CORRUPT");
      terminalOperations.set(key, {
        ...parsed,
        status: "not_committed_final",
        reason: verified.reason,
        proof: Buffer.from(row.proof_cbor),
      });
    }
    return {
      sequence: rows.length,
      root: headRoot,
      previousRoot: rows.length === 0 ? null : previousRootFor(rows),
      entries: sorted,
      pending,
      operations,
      terminalOperations,
    };
  }

  async prepareAppend(input) {
    this.assertOpen();
    const operation = normalizeOperation(input);
    const requestBytes = await z.encodeDeterministic(operationMap(operation));
    if (requestBytes.length > 1024) fail("INVENTORY_LIMIT");
    const requestDigest = sha256(requestBytes);
    const key = operation.operation_id;
    const keyHex = key.toString("hex");
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const state = await this.loadState();
      const prior = state.entries.slice().reverse().find((entry) => same(entry.object_id, operation.entry.object_id));
      const priorRevision = prior ? prior.revision : 0;
      const priorEpoch = prior ? prior.epoch : 0;
      let reason = null;
      let blockingOperationId = null;
      if (!state.operations.has(keyHex) && !state.terminalOperations.has(keyHex)) {
        if (state.pending.length) {
          reason = "UNRESOLVED_PENDING";
          blockingOperationId = Buffer.from(state.pending[0].operation.operation_id);
        } else if (operation.expected_sequence !== state.sequence || !same(operation.expected_root, state.root)) {
          reason = "EXPECTED_HEAD_CHANGED";
        } else if (operation.entry.revision !== priorRevision + 1
          || operation.entry.epoch < priorEpoch) {
          reason = "INVALID_CHRONOLOGY";
        }
      }
      const proof = reason ? await inventory.createTerminalProof({
        signerKeyId: this.signerKeyId,
        privateKey: this.privateKey,
        scope: this.scope,
        operation: operationMap(operation),
        observedSequence: state.sequence,
        observedRoot: state.root,
        priorRevision,
        priorEpoch,
        reason,
        blockingOperationId,
      }) : null;
      const insert = this.db.transaction(() => {
        let existing;
        try { existing = this.readOperationRow(this.db, key); }
        catch (error) {
          if (error instanceof DurableContentInventoryError) throw error;
          fail("INVENTORY_LEDGER_CORRUPT");
        }
        if (existing) {
          if (!Buffer.isBuffer(existing.request_cbor) || existing.request_cbor.length > 1024) {
            fail("INVENTORY_LEDGER_CORRUPT");
          }
          if (!same(copyRowBytes(existing.request_cbor, requestBytes.length), requestBytes)) {
            fail("INVENTORY_OPERATION_CONFLICT");
          }
          const known = state.operations.get(keyHex);
          if (!known) return { status: "retry" };
          if (existing.status === "committed") {
            if (known.status !== "committed" || known.sequence !== existing.sequence
              || !same(known.root, copyRowBytes(existing.root, 32))) fail("INVENTORY_LEDGER_CORRUPT");
            return { status: "committed", replay: true, sequence: known.sequence, root: Buffer.from(known.root) };
          }
          if (existing.status !== "pending" || known.status !== "pending") fail("INVENTORY_LEDGER_CORRUPT");
          return { status: "pending", replay: true };
        }
        let terminal;
        try { terminal = this.readTerminalRow(this.db, key); }
        catch (error) {
          if (error instanceof DurableContentInventoryError) throw error;
          fail("INVENTORY_LEDGER_CORRUPT");
        }
        if (terminal) {
          if (!Buffer.isBuffer(terminal.request_cbor) || terminal.request_cbor.length > 1024) {
            fail("INVENTORY_LEDGER_CORRUPT");
          }
          if (!same(copyRowBytes(terminal.request_cbor, requestBytes.length), requestBytes)) {
            fail("INVENTORY_OPERATION_CONFLICT");
          }
          const known = state.terminalOperations.get(keyHex);
          if (!known) return { status: "retry" };
          if (!same(copyRowBytes(terminal.proof_cbor, known.proof.length), known.proof)) {
            fail("INVENTORY_LEDGER_CORRUPT");
          }
          return {
            status: "not_committed_final", replay: true, reason: known.reason, proof: Buffer.from(known.proof),
          };
        }
        if (state.operations.has(keyHex) || state.terminalOperations.has(keyHex)) return { status: "retry" };

        const head = this.readHeadRow(this.db);
        if (!head || !Number.isSafeInteger(head.sequence) || !Buffer.isBuffer(head.root)
          || head.root.length !== 32) fail("INVENTORY_LEDGER_CORRUPT");
        if (head.sequence !== state.sequence || !same(head.root, state.root)) return { status: "retry" };
        const pendingCount = this.db.prepare(
          "SELECT COUNT(*) AS count FROM content_operation WHERE status='pending'",
        ).get().count;
        if (!Number.isSafeInteger(pendingCount) || pendingCount > MAX_PENDING) fail("INVENTORY_LEDGER_CORRUPT");
        if (pendingCount !== state.pending.length) return { status: "retry" };
        if (pendingCount === 1) {
          const livePending = this.db.prepare(
            "SELECT operation_id FROM content_operation WHERE status='pending'",
          ).get();
          if (!livePending || !same(copyRowBytes(livePending.operation_id, 16), blockingOperationId
            || state.pending[0].operation.operation_id)) return { status: "retry" };
        }
        if (reason) {
          const terminalCount = this.db.prepare("SELECT COUNT(*) AS count FROM content_terminal_operation").get().count;
          if (!Number.isSafeInteger(terminalCount) || terminalCount >= MAX_TERMINAL) fail("INVENTORY_LIMIT");
          this.db.prepare(`INSERT INTO content_terminal_operation(operation_id,request_cbor,proof_cbor)
            VALUES(?,?,?)`).run(key, requestBytes, proof);
          return { status: "not_committed_final", replay: false, reason, proof: Buffer.from(proof) };
        }
        this.db.prepare(`INSERT INTO content_operation
          (operation_id,request_cbor,expected_sequence,expected_root,status,sequence,root)
          VALUES(?,?,?,?,'pending',NULL,NULL)`).run(
          key, requestBytes, operation.expected_sequence, operation.expected_root,
        );
        return { status: "pending", replay: false };
      });
      try {
        const result = insert.immediate();
        if (result.status !== "retry") return result;
      } catch (error) {
        if (error instanceof DurableContentInventoryError) throw error;
        fail("INVENTORY_LEDGER_WRITE");
      }
    }
    fail("INVENTORY_STATE_CHANGED");
  }

  async append(input) {
    const operation = normalizeOperation(input);
    const prepared = await this.prepareAppend({
      operation_id: operation.operation_id,
      expected_sequence: operation.expected_sequence,
      expected_root: operation.expected_root,
      ...operation.entry,
    });
    if (prepared.status === "committed" || prepared.status === "not_committed_final") return prepared;
    const result = await this.sealAppend(operation.operation_id);
    if (result.status === "committed" && prepared.replay) return { ...result, replay: true };
    return result;
  }

  async sealAppend(operationIdValue) {
    this.assertOpen();
    const operationId = bytes(operationIdValue, 16);
    const state = await this.loadState();
    const verified = state.operations.get(operationId.toString("hex"));
    if (!verified) fail("INVENTORY_OPERATION_UNKNOWN");
    if (verified.status === "committed") {
      return {
        status: "committed", replay: true, sequence: verified.sequence,
        root: Buffer.from(verified.root),
      };
    }
    if (verified.status !== "pending") fail("INVENTORY_LEDGER_CORRUPT");
    const parsed = verified;
    const operation = parsed.operation;
    if (operation.expected_sequence !== state.sequence || !same(operation.expected_root, state.root)) {
      return { status: "pending", reason: "EXPECTED_HEAD_CHANGED" };
    }
    if (state.sequence >= inventory.MAX_ENTRIES) return { status: "pending", reason: "INVENTORY_LIMIT" };
    const prior = state.entries.filter((entry) => same(entry.object_id, operation.entry.object_id));
    const expectedRevision = prior.length === 0 ? 1 : prior[prior.length - 1].revision + 1;
    if (operation.entry.revision !== expectedRevision
      || (prior.length && operation.entry.epoch < prior[prior.length - 1].epoch)) {
      return { status: "pending", reason: "INVALID_CHRONOLOGY" };
    }
    const entries = state.entries.concat([operation.entry]).sort(compareEntries);
    try { inventory.normalizeEntries(entries); } catch (_) {
      return { status: "pending", reason: "INVALID_CATALOG_TRANSITION" };
    }
    const sequence = state.sequence + 1;
    const previousRoot = Buffer.from(state.root);
    const root = await inventory.computeRoot(this.scope, sequence, previousRoot, entries);
    const unsigned = {
      type: ENTRY_TYPE,
      version: 1,
      signer_key_id: this.signerKeyId,
      scope: this.scope,
      sequence,
      previous_root: previousRoot,
      root,
      operation_id: operation.operation_id,
      expected_sequence: operation.expected_sequence,
      expected_root: operation.expected_root,
      request_digest: parsed.digest,
      entry: operation.entry,
    };
    const signature = crypto.sign(null, Buffer.concat([
      ENTRY_DOMAIN,
      await z.encodeDeterministic(unsigned),
    ]), this.privateKey);
    const seal = this.db.transaction(() => {
      const head = this.readHeadRow(this.db);
      const currentOperation = this.readOperationRow(this.db, operation.operation_id);
      if (!currentOperation
        || !same(copyRowBytes(currentOperation.request_cbor, parsed.encoded.length), parsed.encoded)) {
        fail("INVENTORY_OPERATION_CONFLICT");
      }
      if (currentOperation.status === "committed") return { status: "reconcile" };
      if (currentOperation.status !== "pending") fail("INVENTORY_OPERATION_CONFLICT");
      if (head.sequence !== operation.expected_sequence || !same(copyRowBytes(head.root, 32), operation.expected_root)) {
        return { status: "pending", reason: "EXPECTED_HEAD_CHANGED" };
      }
      this.db.prepare(`INSERT INTO content_entry
        (sequence,operation_id,object_id,revision,epoch,ciphertext_sha256,expected_sequence,
         expected_root,previous_root,root,request_digest,signature)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(
        sequence, operation.operation_id, operation.entry.object_id, operation.entry.revision,
        operation.entry.epoch, operation.entry.ciphertext_sha256, operation.expected_sequence,
        operation.expected_root, previousRoot, root, parsed.digest, signature,
      );
      this.db.prepare("UPDATE content_head SET sequence=?,root=? WHERE id=1").run(sequence, root);
      this.db.prepare(`UPDATE content_operation SET status='committed',sequence=?,root=?
        WHERE operation_id=? AND status='pending'`).run(sequence, root, operation.operation_id);
      return { status: "committed", replay: false, sequence, root: Buffer.from(root) };
    });
    try {
      const result = seal.immediate();
      if (result.status !== "reconcile") return result;
      const confirmed = await this.loadState();
      const committed = confirmed.operations.get(operationId.toString("hex"));
      if (!committed || committed.status !== "committed"
        || !same(committed.encoded, parsed.encoded)) fail("INVENTORY_OPERATION_CONFLICT");
      return {
        status: "committed", replay: true, sequence: committed.sequence,
        root: Buffer.from(committed.root),
      };
    }
    catch (error) {
      if (error instanceof DurableContentInventoryError) throw error;
      return { status: "pending", reason: "SEAL_UNCERTAIN" };
    }
  }

  async getOperationStatus(operationIdValue) {
    this.assertOpen();
    const operationId = bytes(operationIdValue, 16);
    const state = await this.loadState();
    const key = operationId.toString("hex");
    const operation = state.operations.get(key);
    if (!operation) {
      const terminal = state.terminalOperations.get(key);
      if (!terminal) return { status: "unknown" };
      return {
        status: "not_committed_final", reason: terminal.reason, proof: Buffer.from(terminal.proof),
      };
    }
    if (operation.status === "pending") return { status: "pending" };
    if (!operation.signedEntry) fail("INVENTORY_LEDGER_CORRUPT");
    const proof = Buffer.from(await z.encodeDeterministic(operation.signedEntry));
    if (proof.length > inventory.MAX_COMMITTED_PROOF_BYTES) fail("INVENTORY_LIMIT");
    return { status: "committed", sequence: operation.sequence, root: Buffer.from(operation.root), proof };
  }

  async getCommittedProofPage(input) {
    this.assertOpen();
    const raw = exact(input, ["afterSequence", "limit"], "INVENTORY_PAGE_INPUT");
    if (!Number.isSafeInteger(raw.afterSequence) || raw.afterSequence < 0
      || raw.afterSequence > inventory.MAX_ENTRIES
      || !Number.isSafeInteger(raw.limit) || raw.limit < 1 || raw.limit > 16) {
      fail("INVENTORY_PAGE_INPUT");
    }
    const state = await this.loadState();
    if (raw.afterSequence > state.sequence) fail("INVENTORY_PAGE_INPUT");
    if (state.pending.length > 0) return { status: "pending", reason: "UNRESOLVED_INTENT" };
    const last = Math.min(state.sequence, raw.afterSequence + raw.limit);
    const proofs = [];
    for (let sequence = raw.afterSequence + 1; sequence <= last; sequence += 1) {
      const entry = [...state.operations.values()].find((operation) =>
        operation.status === "committed" && operation.sequence === sequence);
      if (!entry?.signedEntry) fail("INVENTORY_LEDGER_CORRUPT");
      const proof = Buffer.from(await z.encodeDeterministic(entry.signedEntry));
      if (proof.length < 1 || proof.length > inventory.MAX_COMMITTED_PROOF_BYTES) fail("INVENTORY_LIMIT");
      proofs.push(proof);
    }
    return { status: "chain_page", afterSequence: raw.afterSequence,
      nextSequence: last, headSequence: state.sequence, proofs };
  }

  async readLocalHead() {
    const state = await this.loadState();
    return { sequence: state.sequence, root: Buffer.from(state.root) };
  }

  async getSnapshot(input) {
    this.assertOpen();
    const raw = exact(input, ["nonce"], "INVENTORY_SNAPSHOT_INPUT");
    const nonce = inventory.normalizeNonce(raw.nonce);
    const state = await this.loadState();
    if (state.pending.length > 0) return { status: "pending", reason: "UNRESOLVED_INTENT" };
    const bytesSigned = await inventory.createSignedSnapshot({
      signerKeyId: this.signerKeyId,
      privateKey: this.privateKey,
      scope: this.scope,
      sequence: state.sequence,
      previousRoot: state.previousRoot,
      entries: state.entries,
      nonce,
    });
    const confirmed = await this.loadState();
    if (confirmed.sequence !== state.sequence || !same(confirmed.root, state.root)
      || confirmed.pending.length !== 0) fail("INVENTORY_STATE_CHANGED");
    return {
      status: "snapshot",
      bytes: bytesSigned,
      sequence: state.sequence,
      root: Buffer.from(state.root),
      previous_root: state.previousRoot === null ? null : Buffer.from(state.previousRoot),
    };
  }

  async query(input) {
    this.assertOpen();
    const required = ["nonce", "requested", "minimumHead", "pinnedPublicKey", "pinnedSignerKeyId"];
    const optional = ["minimumSnapshot"];
    const raw = objectWithOptional(input, required, optional, "INVENTORY_QUERY_INPUT");
    const nonce = inventory.normalizeNonce(raw.nonce);
    const requested = inventory.normalizeRequested(raw.requested);
    const minimumHead = inventory.normalizeMinimumHead(raw.minimumHead);
    const minimumSnapshot = raw.minimumSnapshot === null || raw.minimumSnapshot === undefined
      ? undefined : copySnapshot(raw.minimumSnapshot);
    const pinnedKey = raw.pinnedPublicKey;
    const pinnedSignerKeyId = bytes(raw.pinnedSignerKeyId, 16);
    const snapshot = await this.getSnapshot({ nonce });
    if (snapshot.status === "pending") return snapshot;
    return inventory.verifySnapshot({
      serialized: snapshot.bytes,
      pinnedPublicKey: pinnedKey,
      pinnedSignerKeyId,
      expectedScope: this.scope,
      requested,
      minimumHead,
      minimumSnapshot,
      nonce,
    });
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }
}

function objectWithOptional(value, required, optional, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) fail(code);
  const keys = Reflect.ownKeys(value);
  if (required.some((field) => !keys.includes(field))
    || keys.some((field) => !required.includes(field) && !optional.includes(field))) fail(code);
  const result = Object.create(null);
  for (const field of [...required, ...optional]) {
    if (!keys.includes(field)) {
      result[field] = undefined;
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail(code);
    result[field] = descriptor.value;
  }
  return result;
}

function copySnapshot(value) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) fail("INVENTORY_INVALID_BYTES");
  if (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer) {
    fail("INVENTORY_SHARED_BYTES");
  }
  if (value.byteLength < 1 || value.byteLength > inventory.MAX_SNAPSHOT_BYTES) fail("INVENTORY_LIMIT");
  return Buffer.from(value);
}

function previousRootFor(rows) {
  if (!rows.length) return null;
  return copyRowBytes(rows[rows.length - 1].previous_root, 32);
}

module.exports = {
  Zk1DurableContentInventoryLedger,
  DurableContentInventoryError,
  MAX_PENDING,
};
