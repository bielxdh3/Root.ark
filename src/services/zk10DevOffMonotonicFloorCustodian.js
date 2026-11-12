"use strict";

// DEV-OFF library only. Not a mounted service or proof of off-host custody.
// A separately operated, durable high-water medium is REQUIRED for R1.
// An application-controlled copy of BOTH SQLite files can still be rolled back.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { types: { isProxy } } = require("node:util");
const Database = require("better-sqlite3");
// Invoking a captured intrinsic through `.call` is still dynamic: a malicious
// KeyObject getter can replace Function.prototype.call. Retain native apply.
const SAFE_APPLY = Reflect.apply.bind(Reflect);
// Capture JSON serialization before any caller-owned options, KeyObjects or
// SQLite callbacks execute. Every signed record here is primitive-only.
// A hostile same-realm callback may later replace Object.create with a
// constructor that installs an own toJSON / accessor on signed clones.
const CREATE_NULL_PROTO = Object.create.bind(Object);
const BASE_OBJECT_PROTOTYPE = Object.prototype;
const GET_PROTO = Object.getPrototypeOf.bind(Object);
const GET_OWN_DESCRIPTOR = Object.getOwnPropertyDescriptor.bind(Object);
const DEFINE_PROPERTY = Object.defineProperty.bind(Object);
const HAS_OWN = Object.hasOwn.bind(Object);
const OWN_KEYS = Reflect.ownKeys.bind(Reflect);
const IS_ARRAY = Array.isArray.bind(Array);
const FREEZE = Object.freeze.bind(Object);
const SAFE_INTEGER = Number.isSafeInteger.bind(Number);
const REGEXP_TEST = RegExp.prototype.test;
const ARRAY_MAP = Array.prototype.map;
const ARRAY_EVERY = Array.prototype.every;
const ARRAY_FILTER = Array.prototype.filter;
const STRINGIFY = JSON.stringify.bind(JSON);
const VERIFY = crypto.verify.bind(crypto);
const SIGN = crypto.sign.bind(crypto);
const CREATE_HASH = crypto.createHash.bind(crypto);
const HASH_PROTO = GET_PROTO(CREATE_HASH("sha256"));
const HASH_UPDATE = GET_OWN_DESCRIPTOR(HASH_PROTO, "update").value;
const HASH_DIGEST = GET_OWN_DESCRIPTOR(HASH_PROTO, "digest").value;
const FROM_BUFFER = Buffer.from.bind(Buffer);
const CONCAT_BUFFER = Buffer.concat.bind(Buffer);
const BUFFER_TO_STRING = Buffer.prototype.toString;
const BUFFER_FILL = Buffer.prototype.fill;
const BUFFER_EQUALS = Buffer.prototype.equals;
const IS_BUFFER = Buffer.isBuffer.bind(Buffer);
// A failed physical SQLite pin must stay poisoned even if caller-controlled
// JS mutates WeakMap.prototype.get after a native filesystem failure.
const NATIVE_WEAK_GET = WeakMap.prototype.get;
const NATIVE_WEAK_SET = WeakMap.prototype.set;
const NATIVE_WEAK_DELETE = WeakMap.prototype.delete;
function canonicalFields(fields, source) {
  const wire = CREATE_NULL_PROTO(null);
  // Enumerate only these trusted canonical field names in fixed order. A
  // callback may replace Object.entries/fromEntries AFTER the module loads:
  // such an enumerator cannot turn signed owner A into applied head B.
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    const value = source[field];
    if (value !== null && typeof value !== "string"
      && typeof value !== "number" && typeof value !== "boolean") {
      throw new Error("Nonprimitive signed field");
    }
    wire[field] = value;
  }
  return wire;
}
function signatureBytes(domain, payload, fields) {
  const wire = canonicalFields(fields, payload);
  return CONCAT_BUFFER([domain, FROM_BUFFER(STRINGIFY(wire), "utf8")]);
}
function hash(...chunks) {
  const h = CREATE_HASH("sha256");
  for (let index = 0; index < chunks.length; index += 1) {
    SAFE_APPLY(HASH_UPDATE, h, [chunks[index]]);
  }
  return SAFE_APPLY(HASH_DIGEST, h, ["hex"]);
}
const sha256Hex = hash;

const GENESIS_DOMAIN = FROM_BUFFER("Root.ark/zk10/custodian-owner-genesis/v1\0");
const LEASE_DOMAIN = FROM_BUFFER("Root.ark/zk10/custodian-owner-lease/v1\0");
const FLOOR_DOMAIN = FROM_BUFFER("Root.ark/zk10/external-floor-current/v1\0");
const JOURNAL_DOMAIN = FROM_BUFFER("Root.ark/zk10/custodian-used-lease-journal/v1\0");
const EMPTY_JOURNAL_TIP = sha256Hex(JOURNAL_DOMAIN);
const GENESIS_FIELDS = FREEZE(["type", "sequence", "head_digest", "enrollment_root",
  "immutable_account_id", "identity_digest", "lease_serial"]);
const LEASE_FIELDS = FREEZE(["type", "sequence", "head_digest", "enrollment_root",
  "immutable_account_id", "identity_digest", "operation", "nonce", "lease_id",
  "lease_serial", "issued_at_ms", "lease_expires_at_ms"]);
const REQUEST_FIELDS = FREEZE(["immutable_account_id", "identity_digest", "operation",
  "nonce", "lease_id", "lease_expires_at_ms"]);
const FLOOR_FIELDS = FREEZE(["type", "sequence", "head_digest", "enrollment_root",
  "immutable_account_id", "identity_digest", "operation", "nonce", "lease_id",
  "lease_expires_at_ms", "issued_at_ms", "expires_at_ms"]);
const HEAD_FIELDS = FREEZE(["sequence", "head_digest", "enrollment_root",
  "immutable_account_id", "identity_digest", "lease_serial"]);
const HEX = /^[a-f0-9]{64}$/;
const OPER = /^[a-z][a-z0-9:_-]{0,63}$/;
const NOW = Date.now.bind(Date);
const MONOTONIC_NOW_NS = process.hrtime.bigint.bind(process.hrtime);
const MAX_LEASE_SERIAL = 100_000; // Bounded DEV-OFF journal; no unsafe reset/rotation.
const INTEGER_WIRE_FIELDS = new Set(["sequence", "lease_serial",
  "issued_at_ms", "lease_expires_at_ms"]);
const STORED_FLOOR_FIELDS = FREEZE([...HEAD_FIELDS, "journal_count", "journal_tip"]);
const dbPins = new WeakMap();
// Read real crypto.KeyObject internals, not shadowable instance properties.
// This fixed DER public key only discovers Node's native public-key prototype;
// it is never an accepted signer, owner pin, or trusted custodian identity.
const CREATE_PUBLIC = crypto.createPublicKey.bind(crypto);
const CREATE_PRIVATE = crypto.createPrivateKey.bind(crypto);
const publicKeyFixture = CREATE_PUBLIC({
  key: FROM_BUFFER("302a300506032b6570032100" + "00".repeat(32), "hex"),
  format: "der", type: "spki",
});
const publicKeyPrototype = GET_PROTO(publicKeyFixture);
const nativeKeyHandle = Object.getOwnPropertySymbols(publicKeyFixture)
  .find((symbol) => symbol.description === "kHandle");
const nativeKeyTypeSymbol = Object.getOwnPropertySymbols(publicKeyFixture)
  .find((symbol) => symbol.description === "kKeyType");
const nativeHandlePrototype = Object.getPrototypeOf(publicKeyFixture[nativeKeyHandle]);
const nativeHandleAlgorithm = Object.getOwnPropertyDescriptor(
  nativeHandlePrototype, "getAsymmetricKeyType").value;
const nativeHandleExport = Object.getOwnPropertyDescriptor(
  nativeHandlePrototype, "export").value;
const nativeType = Object.getOwnPropertyDescriptor(crypto.KeyObject.prototype, "type").get;
const nativeAlgorithm = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(publicKeyPrototype), "asymmetricKeyType").get;
const nativePublicExport = Object.getOwnPropertyDescriptor(publicKeyPrototype, "export").value;
// Public and private native exports differ: the private signer must also be
// detached, otherwise a mutable kHandle can advertise B and later sign as A.
// This ephemeral native key is discarded after discovering the prototype.
const privateKeyPrototype = GET_PROTO(
  crypto.generateKeyPairSync("ed25519").privateKey);
const nativePrivateExport = GET_OWN_DESCRIPTOR(privateKeyPrototype, "export").value;
const nativeKeyEquals = crypto.KeyObject.prototype.equals;

function deny() {
  const error = new Error("ZK10_CUSTODIAN_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function strict(value, fields, allowTrustedConfigObjects = false) {
  // Reject proxies before any ownKeys/getPrototypeOf/descriptor hooks:
  // a malicious hook could replace crypto.verify while inspecting a signed
  // owner lease, falsely authorizing the custodian's genuine Ed25519 signer.
  if (value === null || typeof value !== "object" || isProxy(value) || IS_ARRAY(value)
    || (GET_PROTO(value) !== BASE_OBJECT_PROTOTYPE && GET_PROTO(value) !== null)
    || OWN_KEYS(value).length !== fields.length) deny();
  const result = CREATE_NULL_PROTO(null);
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    const descriptor = GET_OWN_DESCRIPTOR(value, field);
    if (!descriptor || !HAS_OWN(descriptor, "value")) deny();
    // GENESIS, LEASE, REQUEST, and persisted HEAD are FLAT scalar schemas.
    // Reject every nested object before signatureBytes/JSON.stringify, never
    // invoke toJSON/getters/Proxy traps during signature authentication.
    if (!allowTrustedConfigObjects && ((field === "sequence" || field === "lease_serial"
      || field === "issued_at_ms" || field === "lease_expires_at_ms")
      ? !SAFE_INTEGER(descriptor.value)
      : typeof descriptor.value !== "string")) deny();
    result[field] = descriptor.value;
  }
  return result;
}
function bytes(value, length) {
  if (typeof value !== "string" || !SAFE_APPLY(REGEXP_TEST, /^[A-Za-z0-9_-]+$/, [value])) deny();
  const decoded = FROM_BUFFER(value, "base64url");
  if (decoded.length !== length || SAFE_APPLY(BUFFER_TO_STRING, decoded, ["base64url"]) !== value) deny();
  return decoded;
}
function validateHead(record) {
  const h = strict(record, HEAD_FIELDS);
  if (!SAFE_INTEGER(h.sequence) || h.sequence < 1 || h.sequence > 1000000
    || !SAFE_INTEGER(h.lease_serial) || h.lease_serial < 0
    || h.lease_serial > MAX_LEASE_SERIAL
    || typeof h.head_digest !== "string" || !SAFE_APPLY(REGEXP_TEST, HEX, [h.head_digest])
    || typeof h.enrollment_root !== "string" || !SAFE_APPLY(REGEXP_TEST, HEX, [h.enrollment_root])
    || typeof h.identity_digest !== "string" || !SAFE_APPLY(REGEXP_TEST, HEX, [h.identity_digest])) deny();
  bytes(h.immutable_account_id, 16);
  return FREEZE(h);
}
function unsignedSigned(wire, fields, type, domain, publicKey) {
  const signed = strict(wire, [...fields, "signature"]);
  const payload = canonicalFields(fields, signed);
  // Nested objects can define toJSON/toString and execute arbitrary JS while
  // signatureBytes serializes them. Reject EVERY nonprimitive field before
  // any signed serialization or regex coercion, including the lease operation.
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    const value = payload[field];
    if (field === "sequence" || field === "lease_serial"
      || field === "issued_at_ms" || field === "lease_expires_at_ms") {
      if (!SAFE_INTEGER(value)) deny();
    } else if (typeof value !== "string") deny();
  }
  if (payload.type !== type || !VERIFY(null, signatureBytes(domain, payload, fields),
    publicKey, bytes(signed.signature, 64))) deny();
  return payload;
}
function keyObject(value, type) {
  if (isProxy(value) || !(value instanceof crypto.KeyObject)
    || GET_PROTO(value) !== (type === "private"
      ? privateKeyPrototype : publicKeyPrototype)) deny();
  const handle = nativeKeyHandle
    && GET_OWN_DESCRIPTOR(value, nativeKeyHandle);
  const typeDescriptor = nativeKeyTypeSymbol
    && GET_OWN_DESCRIPTOR(value, nativeKeyTypeSymbol);
  // Reject a caller-inherited or getter-backed native handle *before* calling
  // intrinsics. Also reject accessor-backed kKeyType: nativeType reads it via
  // ordinary JS property lookup, and an accessor could poison crypto.verify.
  if (!handle || !HAS_OWN(handle, "value")
    || !typeDescriptor || !HAS_OWN(typeDescriptor, "value")
    || typeDescriptor.value !== type
    || !handle.value || typeof handle.value !== "object"
    || isProxy(handle.value)
    || GET_PROTO(handle.value) !== nativeHandlePrototype
    || HAS_OWN(handle.value, "export")
    || HAS_OWN(handle.value, "getAsymmetricKeyType")
    || GET_OWN_DESCRIPTOR(nativeHandlePrototype, "export")?.value
      !== nativeHandleExport
    || GET_OWN_DESCRIPTOR(nativeHandlePrototype, "getAsymmetricKeyType")?.value
      !== nativeHandleAlgorithm
    || SAFE_APPLY(nativeHandleAlgorithm, handle.value, []) !== "ed25519"
    || SAFE_APPLY(nativeType, value, []) !== type
    || SAFE_APPLY(nativeAlgorithm, value, []) !== "ed25519") deny();
  let der;
  try {
    // A caller may shadow methods, and an inherited instance can replace its
    // native kHandle between comparison, bootstrap verification and signing.
    // Import one native DER snapshot into a fresh, exclusively held key.
    const isPrivate = type === "private";
    der = SAFE_APPLY(isPrivate ? nativePrivateExport : nativePublicExport, value,
      [{ format: "der", type: isPrivate ? "pkcs8" : "spki" }]);
    if (!IS_BUFFER(der) || der.length !== (isPrivate ? 48 : 44)) deny();
    const pinned = isPrivate
      ? CREATE_PRIVATE({ key: der, format: "der", type: "pkcs8" })
      : CREATE_PUBLIC({ key: der, format: "der", type: "spki" });
    if (SAFE_APPLY(nativeType, pinned, []) !== type
      || SAFE_APPLY(nativeAlgorithm, pinned, []) !== "ed25519") deny();
    if (!isPrivate && !SAFE_APPLY(BUFFER_EQUALS,
      SAFE_APPLY(nativePublicExport, pinned, [{ format: "der", type: "spki" }]), [der])) deny();
    return pinned;
  } catch (_) { deny(); }
  finally {
    // Do not retain plaintext PKCS8 bytes; only the native private clone is
    // kept for derivation and signing. Never export it to compare roles.
    if (type === "private" && IS_BUFFER(der)) SAFE_APPLY(BUFFER_FILL, der, [0]);
  }
}
function spki(key) {
  return sha256Hex(SAFE_APPLY(nativePublicExport, keyObject(key, "public"),
    [{ format: "der", type: "spki" }]));
}
function safeFileName(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)) deny();
  const absolute = path.resolve(value);
  if (absolute !== value || absolute.includes("\0")) deny();
  // existsSync is FALSE for dangling symlinks: lstat all existing components.
  const root = path.parse(absolute).root;
  const pieces = SAFE_APPLY(ARRAY_FILTER,
    path.dirname(absolute).slice(root.length).split(path.sep), [Boolean]);
  let currentPath = root;
  for (let index = 0; index < pieces.length; index += 1) {
    const piece = pieces[index];
    currentPath = path.join(currentPath, piece);
    const stat = fs.lstatSync(currentPath);
    if (!stat.isDirectory() || stat.isSymbolicLink()) deny();
  }
  let current;
  try { current = fs.lstatSync(absolute); }
  catch (error) { if (error?.code !== "ENOENT") deny(); }
  if (current && (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1)) deny();
  return absolute;
}
function same(a, b) {
  if (!a || !b) return false;
  for (let index = 0; index < STORED_FLOOR_FIELDS.length; index += 1) {
    const field = STORED_FLOOR_FIELDS[index];
    if (a[field] !== b[field]) return false;
  }
  return true;
}
function mapFloor(row) {
  if (!row) return null;
  const head = validateHead(canonicalFields(HEAD_FIELDS, row));
  if (!SAFE_INTEGER(row.journal_count)
    || row.journal_count !== head.lease_serial
    || typeof row.journal_tip !== "string" || !SAFE_APPLY(REGEXP_TEST, HEX, [row.journal_tip])
    || (row.journal_count === 0 && row.journal_tip !== EMPTY_JOURNAL_TIP)) deny();
  return FREEZE({ ...head, journal_count: row.journal_count, journal_tip: row.journal_tip });
}
function nextJournalTip(previousTip, challenge, serial) {
  bytes(challenge.nonce, 32);
  bytes(challenge.lease_id, 16);
  if (!SAFE_APPLY(REGEXP_TEST, HEX, [previousTip]) || !SAFE_INTEGER(serial)
    || serial < 1 || serial > MAX_LEASE_SERIAL) deny();
  const entry = { nonce: challenge.nonce, lease_id: challenge.lease_id, lease_serial: serial };
  return sha256Hex(FROM_BUFFER(previousTip, "hex"),
    signatureBytes(JOURNAL_DOMAIN, entry, ["nonce", "lease_id", "lease_serial"]));
}
function verifyUsedJournal(db, floor) {
  const rows = db.prepare("SELECT nonce, lease_id, lease_serial, chain_tip FROM used_lease ORDER BY lease_serial").all();
  if (rows.length !== floor.journal_count) deny();
  let tip = EMPTY_JOURNAL_TIP;
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    if (row.lease_serial !== index + 1) deny();
    tip = nextJournalTip(tip, row, row.lease_serial);
    if (row.chain_tip !== tip) deny();
  }
  if (tip !== floor.journal_tip) deny();
}
function sameFile(stat, candidate) {
  const one = typeof candidate.nlink === "bigint" ? 1n : 1;
  const zero = typeof stat.ino === "bigint" ? 0n : 0;
  return stat.isFile() && candidate.isFile() && !candidate.isSymbolicLink()
    && candidate.nlink === one && stat.nlink === one
    && stat.ino !== zero && stat.dev === candidate.dev && stat.ino === candidate.ino;
}
function checkDbPin(db) {
  const pin = SAFE_APPLY(NATIVE_WEAK_GET, dbPins, [db]);
  if (!pin || pin.failed) deny();
  try {
    // SQLite has a separate native handle. Keep our file descriptor pinned
    // and recheck its inode against the complete path on every critical use.
    // This is not a native atomic no-reparse SQLite open on Windows.
    safeFileName(pin.file);
    const held = fs.fstatSync(pin.fd, { bigint: true });
    const named = fs.lstatSync(pin.file, { bigint: true });
    if (!sameFile(pin.identity, held) || !sameFile(held, named)
      || held.mode !== pin.identity.mode || named.mode !== pin.identity.mode
      || held.size !== named.size) deny();
  } catch (_) {
    pin.failed = true;
    deny();
  }
}
function closeDb(db) {
  if (!db) return;
  const pin = SAFE_APPLY(NATIVE_WEAK_GET, dbPins, [db]);
  SAFE_APPLY(NATIVE_WEAK_DELETE, dbPins, [db]);
  try { db.close(); }
  finally { if (pin) fs.closeSync(pin.fd); }
}
function openDb(file) {
  let db, descriptor;
  try {
    // SQLite opens its own file handle. Keep a no-follow descriptor open and
    // check the inode plus every parent before and after SQLite opens.
    // A fully hostile local filesystem still requires OS-level isolation.
    safeFileName(file);
    descriptor = fs.openSync(file, fs.constants.O_RDWR | fs.constants.O_CREAT |
      (fs.constants.O_NOFOLLOW || 0), 0o600);
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!sameFile(opened, fs.lstatSync(file, { bigint: true }))) deny();
    db = new Database(file, { timeout: 2000 });
    safeFileName(file);
    if (!sameFile(opened, fs.lstatSync(file, { bigint: true }))) deny();
    db.pragma("journal_mode = DELETE");
    db.pragma("synchronous = EXTRA"); // fsync journal, DB and DELETE-mode journal directory.
    if (db.pragma("synchronous", { simple: true }) !== 3
      || db.pragma("journal_mode", { simple: true }) !== "delete"
      || db.pragma("quick_check", { simple: true }) !== "ok") deny();
    db.exec(`CREATE TABLE IF NOT EXISTS floor (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      sequence INTEGER NOT NULL, head_digest TEXT NOT NULL,
      enrollment_root TEXT NOT NULL, immutable_account_id TEXT NOT NULL,
      identity_digest TEXT NOT NULL, lease_serial INTEGER NOT NULL,
      journal_count INTEGER NOT NULL, journal_tip TEXT NOT NULL,
      owner_spki TEXT NOT NULL, custodian_spki TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS used_lease (
      nonce TEXT NOT NULL UNIQUE, lease_id TEXT NOT NULL UNIQUE,
      lease_serial INTEGER NOT NULL UNIQUE, chain_tip TEXT NOT NULL
    );`);
    safeFileName(file);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!sameFile(opened, after)
      || !sameFile(after, fs.lstatSync(file, { bigint: true }))) deny();
    SAFE_APPLY(NATIVE_WEAK_SET, dbPins,
      [db, { file, fd: descriptor, identity: opened, failed: false }]);
    descriptor = undefined; // Keep the pin until closeDb, not just startup.
    return db;
  } catch (_) {
    try { db?.close(); } catch (_) { /* unavailable */ }
    deny();
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch (_) { deny(); }
    }
  }
}
function read(db, ownerHash, signerHash, primary = false) {
  checkDbPin(db);
  const row = db.prepare("SELECT * FROM floor WHERE singleton = 1").get();
  if (row && (row.owner_spki !== ownerHash || row.custodian_spki !== signerHash)) deny();
  const floor = mapFloor(row);
  if (primary && floor) verifyUsedJournal(db, floor);
  checkDbPin(db);
  return floor;
}
function floorValues(record) {
  // Avoid ArraySpeciesCreate in map() and mutable array iterators in spread:
  // these rows are the actual durable SQLite values bound to signed heads.
  const values = [];
  for (let index = 0; index < STORED_FLOOR_FIELDS.length; index += 1) {
    // Array.prototype[index] can grow an inherited setter after a hostile
    // same-realm callback. Defining a fresh own DATA slot prevents a signed
    // scalar from being silently rewritten during the SQLite parameter copy.
    DEFINE_PROPERTY(values, index, { value: record[STORED_FLOOR_FIELDS[index]],
      writable: true, enumerable: true, configurable: true });
  }
  return values;
}
function insertGenesis(db, head, ownerHash, signerHash) {
  checkDbPin(db);
  db.transaction(() => {
    checkDbPin(db);
    if (db.prepare("SELECT 1 FROM floor").get()) deny();
    checkDbPin(db);
    const statement = db.prepare(`INSERT INTO floor (singleton, sequence, head_digest, enrollment_root,
      immutable_account_id, identity_digest, lease_serial, journal_count, journal_tip,
      owner_spki, custodian_spki)
      VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    const values = floorValues(head);
    DEFINE_PROPERTY(values, values.length, { value: ownerHash,
      writable: true, enumerable: true, configurable: true });
    DEFINE_PROPERTY(values, values.length, { value: signerHash,
      writable: true, enumerable: true, configurable: true });
    SAFE_APPLY(statement.run, statement, values);
    checkDbPin(db);
  }).immediate();
  checkDbPin(db);
}
function advanceDb(db, previous, next, expectedOwner, expectedSigner, challenge, primary) {
  checkDbPin(db);
  db.transaction(() => {
    checkDbPin(db);
    const current = read(db, expectedOwner, expectedSigner, primary);
    if (!same(current, previous)) deny();
    checkDbPin(db);
    const statement = db.prepare(`UPDATE floor SET sequence = ?, head_digest = ?,
      enrollment_root = ?, immutable_account_id = ?, identity_digest = ?,
      lease_serial = ?, journal_count = ?, journal_tip = ?
      WHERE singleton = 1 AND lease_serial = ?`);
    const values = floorValues(next);
    DEFINE_PROPERTY(values, values.length, { value: previous.lease_serial,
      writable: true, enumerable: true, configurable: true });
    const result = SAFE_APPLY(statement.run, statement, values);
    if (result.changes !== 1) deny();
    checkDbPin(db);
    if (primary) {
      db.prepare(`INSERT INTO used_lease (nonce, lease_id, lease_serial, chain_tip)
        VALUES (?, ?, ?, ?)`).run(challenge.nonce, challenge.lease_id,
          next.lease_serial, next.journal_tip);
      checkDbPin(db);
    }
  }).immediate();
  checkDbPin(db);
}

function withBothFloorReservations(anchor, main, operation) {
  // Acquire write reservations in the same order as the normal floor advance.
  // A read of anchor followed by a read of main without BOTH reservations
  // can return a stale state if another writer commits in between.
  let lockedAnchor = false, lockedMain = false;
  let failed = false, result;
  try {
    checkDbPin(anchor);
    checkDbPin(main);
    anchor.exec("BEGIN IMMEDIATE");
    lockedAnchor = true;
    checkDbPin(anchor);
    main.exec("BEGIN IMMEDIATE");
    lockedMain = true;
    checkDbPin(main);
    result = operation();
  } catch (_) {
    failed = true;
  } finally {
    // No writes occur in this reservation. ROLLBACK releases both locks even
    // when signing or the journal verification throws; failed release denies.
    if (lockedMain) {
      try { main.exec("ROLLBACK"); } catch (_) { failed = true; }
    }
    if (lockedAnchor) {
      try { anchor.exec("ROLLBACK"); } catch (_) { failed = true; }
    }
  }
  if (failed) deny();
  return result;
}

function createDevOffZk10MonotonicFloorCustodian(options) {
  let main, anchor;
  try {
    const o = strict(options, ["devOff", "databasePath", "anchorDatabasePath",
      "ownerPublicKey", "custodianPrivateKey", "custodianSpkiSha256", "bootstrap"], true);
    if (o.devOff !== true || process.env.NODE_ENV === "production") deny();
    const owner = keyObject(o.ownerPublicKey, "public");
    const signer = keyObject(o.custodianPrivateKey, "private");
    const signerPublic = keyObject(CREATE_PUBLIC(signer), "public");
    const ownerHash = spki(owner);
    const signerHash = spki(signerPublic);
    if (SAFE_APPLY(nativeKeyEquals, owner, [signerPublic]) || ownerHash === signerHash
      || o.custodianSpkiSha256 !== signerHash) deny();
    const mainPath = safeFileName(o.databasePath);
    const anchorPath = safeFileName(o.anchorDatabasePath);
    if (mainPath.toLowerCase() === anchorPath.toLowerCase()) deny();
    const mainExists = fs.existsSync(mainPath), anchorExists = fs.existsSync(anchorPath);
    if (mainExists !== anchorExists) deny();
    let genesis;
    if (!mainExists) {
      const payload = unsignedSigned(o.bootstrap, GENESIS_FIELDS,
        "rootark-zk10-custodian-owner-genesis/v1", GENESIS_DOMAIN, owner);
      genesis = validateHead(canonicalFields(HEAD_FIELDS, payload));
      if (genesis.lease_serial !== 0) deny();
      genesis = FREEZE({ ...genesis, journal_count: 0, journal_tip: EMPTY_JOURNAL_TIP });
    }
    anchor = openDb(anchorPath);
    main = openDb(mainPath);
    if (!mainExists) {
      // External minimum FIRST. Any interruption before primary commit is
      // permanently fail-closed until independently reconciled.
      insertGenesis(anchor, genesis, ownerHash, signerHash);
      insertGenesis(main, genesis, ownerHash, signerHash);
    }
    let minimum = read(anchor, ownerHash, signerHash);
    if (!minimum || !same(minimum, read(main, ownerHash, signerHash, true))
      || (!mainExists && !same(minimum, genesis))) deny();
    let closed = false, poisoned = false;
    const api = {
      independentOffServerCustodyProven: false,
      retainedMinimum() {
        if (closed || poisoned) deny();
        try {
          // Another legitimate process can advance both SQLite stores while
          // this instance keeps its previous in-memory minimum. A stale
          // snapshot must never be reported as the CURRENT retained floor.
          // The primary journal commitment is checked on every read too.
          return withBothFloorReservations(anchor, main, () => {
            if (!same(minimum, read(anchor, ownerHash, signerHash))
              || !same(minimum, read(main, ownerHash, signerHash, true))) deny();
            return { ...minimum };
          });
        } catch (_) {
          // State changed outside this handle, or an ambiguous read failed.
          // Reopen and revalidate both files before trusting a new minimum.
          poisoned = true;
          deny();
        }
      },
      attest(request, ownerLease) {
        if (closed || poisoned) deny();
        let writeStarted = false;
        try {
          checkDbPin(anchor);
          checkDbPin(main);
          const r = strict(request, REQUEST_FIELDS);
          // No attacker-controlled toJSON or coercion is permitted in a
          // request that will be compared, validated or later signed.
          for (let index = 0; index < REQUEST_FIELDS.length; index += 1) {
            const field = REQUEST_FIELDS[index];
            const value = r[field];
            if (field === "lease_expires_at_ms") {
              if (!SAFE_INTEGER(value)) deny();
            } else if (typeof value !== "string") deny();
          }
          const signed = unsignedSigned(ownerLease, LEASE_FIELDS,
            "rootark-zk10-custodian-owner-lease/v1", LEASE_DOMAIN, owner);
          // A hostile same-realm callback may replace Array.prototype's
          // iterator so a for-of skips every owner-signed request binding.
          // The fixed schema is an own, bounded array: compare every indexed
          // field explicitly instead of relying on an inherited iterator.
          for (let index = 0; index < REQUEST_FIELDS.length; index += 1) {
            const field = REQUEST_FIELDS[index];
            if (r[field] !== signed[field]) deny();
          }
          const nextHead = validateHead(canonicalFields(HEAD_FIELDS, signed));
          // Sample monotonic time before wall time so any intervening delay
          // consumes budget instead of enlarging the owner's signed lease.
          const admittedNs = MONOTONIC_NOW_NS();
          const at = NOW();
          if (!SAFE_INTEGER(at)
            || nextHead.immutable_account_id !== minimum.immutable_account_id
            || nextHead.identity_digest !== minimum.identity_digest
            || nextHead.lease_serial !== minimum.lease_serial + 1
            || nextHead.sequence < minimum.sequence
            || nextHead.sequence > minimum.sequence + 1
            || (nextHead.sequence === minimum.sequence
              && (nextHead.head_digest !== minimum.head_digest
                || nextHead.enrollment_root !== minimum.enrollment_root))
            || !SAFE_APPLY(REGEXP_TEST, OPER, [r.operation])
            || !SAFE_INTEGER(signed.issued_at_ms)
            || signed.issued_at_ms < at - 30_000 || signed.issued_at_ms > at + 1_000
            || !SAFE_INTEGER(r.lease_expires_at_ms)
            || r.lease_expires_at_ms <= at + 100
            || r.lease_expires_at_ms > at + 10_000) deny();
          bytes(r.nonce, 32);
          bytes(r.lease_id, 16);
          const next = FREEZE({ ...nextHead, journal_count: minimum.journal_count + 1,
            journal_tip: nextJournalTip(minimum.journal_tip, r, nextHead.lease_serial) });
          checkDbPin(anchor);
          checkDbPin(main);
          // Check the separate minimum afresh before every admission; a
          // process that observes any externally edited state must stop.
          if (!same(minimum, read(anchor, ownerHash, signerHash))
            || !same(minimum, read(main, ownerHash, signerHash, true))
            || main.prepare("SELECT 1 FROM used_lease WHERE nonce = ? OR lease_id = ?")
              .get(r.nonce, r.lease_id)) deny();
          // Externally retained minimum is advanced BEFORE the primary.
          // A crash between these two commits blocks all future attestations.
          writeStarted = true;
          advanceDb(anchor, minimum, next, ownerHash, signerHash, r, false);
          checkDbPin(anchor);
          checkDbPin(main);
          advanceDb(main, minimum, next, ownerHash, signerHash, r, true);
          checkDbPin(anchor);
          checkDbPin(main);
          minimum = next;
          const issuedAt = NOW();
          if (!SAFE_INTEGER(issuedAt)
            || issuedAt + 100 >= r.lease_expires_at_ms) deny();
          const response = {
            type: "rootark-zk10-external-floor-current/v1",
            sequence: next.sequence, head_digest: next.head_digest,
            enrollment_root: next.enrollment_root,
            immutable_account_id: next.immutable_account_id,
            identity_digest: next.identity_digest,
            operation: r.operation, nonce: r.nonce, lease_id: r.lease_id,
            lease_expires_at_ms: r.lease_expires_at_ms,
            issued_at_ms: issuedAt, expires_at_ms: r.lease_expires_at_ms,
          };
          const floor = canonicalFields(FLOOR_FIELDS, response);
          const signature = withBothFloorReservations(anchor, main, () => {
            if (!same(next, read(anchor, ownerHash, signerHash))
              || !same(next, read(main, ownerHash, signerHash, true))) deny();
            if (NOW() + 100 >= r.lease_expires_at_ms) deny();
            const signedFloor = SAFE_APPLY(BUFFER_TO_STRING,
              SIGN(null, signatureBytes(FLOOR_DOMAIN, floor, FLOOR_FIELDS), signer),
              ["base64url"]);
            if (NOW() + 100 >= r.lease_expires_at_ms) deny();
            if (!same(next, read(anchor, ownerHash, signerHash))
              || !same(next, read(main, ownerHash, signerHash, true))) deny();
            // A synchronous signer hook can reenter retainedMinimum(), fail
            // its nested reservation and poison this instance. Such a failure
            // must never be swallowed into a successful signed CURRENT.
            if (closed || poisoned) deny();
            return signedFloor;
          });
          // Signing and final DB checks can stall after the pre-sign expiry
          // check. Never issue a CURRENT attestation whose owner lease has
          // already expired; its durable nonce is consumed, so fail closed.
          const completedAt = NOW();
          const elapsedNs = MONOTONIC_NOW_NS() - admittedNs;
          // A partial wall-clock rollback can conceal a lease that expired
          // while the synchronous signer was running. The monotonic elapsed
          // budget catches this without trusting a second wall-clock value.
          const remainingNs = (BigInt(r.lease_expires_at_ms) - BigInt(at)) * 1_000_000n;
          if (closed || poisoned || !SAFE_INTEGER(completedAt) || completedAt < issuedAt
            || completedAt + 100 >= r.lease_expires_at_ms
            || elapsedNs < 0n || elapsedNs + 100_000_000n >= remainingNs) deny();
          return { floor: { ...floor, signature } };
        } catch (_) {
          // SQLite fsync/commit ambiguity or unexpected sign failure must not
          // admit another lease on this process without explicit restart.
          if (writeStarted) poisoned = true;
          deny();
        }
      },
      close() {
        if (closed) return;
        closed = true;
        try { closeDb(main); } finally { closeDb(anchor); }
      },
    };
    return FREEZE(api);
  } catch (_) {
    try { closeDb(main); } catch (_) { /* unavailable */ }
    try { closeDb(anchor); } catch (_) { /* unavailable */ }
    deny();
  }
}

module.exports = { createDevOffZk10MonotonicFloorCustodian };
