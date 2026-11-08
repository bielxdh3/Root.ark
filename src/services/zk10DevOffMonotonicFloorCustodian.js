"use strict";

// DEV-OFF library only. Not a mounted service or proof of off-host custody.
// A separately operated, durable high-water medium is REQUIRED for R1.
// An application-controlled copy of BOTH SQLite files can still be rolled back.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const { signatureBytes } = require("../crypto/rootark-zk10-account-cutover-v1");

const GENESIS_DOMAIN = Buffer.from("Root.ark/zk10/custodian-owner-genesis/v1\0");
const LEASE_DOMAIN = Buffer.from("Root.ark/zk10/custodian-owner-lease/v1\0");
const FLOOR_DOMAIN = Buffer.from("Root.ark/zk10/external-floor-current/v1\0");
const JOURNAL_DOMAIN = Buffer.from("Root.ark/zk10/custodian-used-lease-journal/v1\0");
const EMPTY_JOURNAL_TIP = crypto.createHash("sha256").update(JOURNAL_DOMAIN).digest("hex");
const GENESIS_FIELDS = ["type", "sequence", "head_digest", "enrollment_root",
  "immutable_account_id", "identity_digest", "lease_serial"];
const LEASE_FIELDS = ["type", "sequence", "head_digest", "enrollment_root",
  "immutable_account_id", "identity_digest", "operation", "nonce", "lease_id",
  "lease_serial", "issued_at_ms", "lease_expires_at_ms"];
const REQUEST_FIELDS = ["immutable_account_id", "identity_digest", "operation",
  "nonce", "lease_id", "lease_expires_at_ms"];
const FLOOR_FIELDS = ["type", "sequence", "head_digest", "enrollment_root",
  "immutable_account_id", "identity_digest", "operation", "nonce", "lease_id",
  "lease_expires_at_ms", "issued_at_ms", "expires_at_ms"];
const HEAD_FIELDS = ["sequence", "head_digest", "enrollment_root",
  "immutable_account_id", "identity_digest", "lease_serial"];
const HEX = /^[a-f0-9]{64}$/;
const OPER = /^[a-z][a-z0-9:_-]{0,63}$/;
const NOW = Date.now.bind(Date);
const MAX_LEASE_SERIAL = 100_000; // Bounded DEV-OFF journal; no unsafe reset/rotation.
const STORED_FLOOR_FIELDS = [...HEAD_FIELDS, "journal_count", "journal_tip"];
const dbPins = new WeakMap();

function deny() {
  const error = new Error("ZK10_CUSTODIAN_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function strict(value, fields) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length) deny();
  const result = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
    result[field] = descriptor.value;
  }
  return result;
}
function bytes(value, length) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) deny();
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== length || decoded.toString("base64url") !== value) deny();
  return decoded;
}
function validateHead(record) {
  const h = strict(record, HEAD_FIELDS);
  if (!Number.isSafeInteger(h.sequence) || h.sequence < 1 || h.sequence > 1000000
    || !Number.isSafeInteger(h.lease_serial) || h.lease_serial < 0
    || h.lease_serial > MAX_LEASE_SERIAL
    || typeof h.head_digest !== "string" || !HEX.test(h.head_digest)
    || typeof h.enrollment_root !== "string" || !HEX.test(h.enrollment_root)
    || typeof h.identity_digest !== "string" || !HEX.test(h.identity_digest)) deny();
  bytes(h.immutable_account_id, 16);
  return Object.freeze(h);
}
function unsignedSigned(wire, fields, type, domain, publicKey) {
  const signed = strict(wire, [...fields, "signature"]);
  const payload = Object.fromEntries(fields.map(field => [field, signed[field]]));
  if (payload.type !== type || !crypto.verify(null, signatureBytes(domain, payload),
    publicKey, bytes(signed.signature, 64))) deny();
  return payload;
}
function keyObject(value, type) {
  if (!(value instanceof crypto.KeyObject) || value.type !== type
    || value.asymmetricKeyType !== "ed25519") deny();
  return value;
}
function spki(key) {
  return crypto.createHash("sha256")
    .update(keyObject(key, "public").export({ format: "der", type: "spki" }))
    .digest("hex");
}
function safeFileName(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)) deny();
  const absolute = path.resolve(value);
  if (absolute !== value || absolute.includes("\0")) deny();
  // existsSync is FALSE for dangling symlinks: lstat all existing components.
  const root = path.parse(absolute).root;
  const pieces = path.dirname(absolute).slice(root.length).split(path.sep).filter(Boolean);
  let currentPath = root;
  for (const piece of pieces) {
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
  return !!a && !!b && STORED_FLOOR_FIELDS.every(field => a[field] === b[field]);
}
function mapFloor(row) {
  if (!row) return null;
  const head = validateHead(Object.fromEntries(HEAD_FIELDS.map(field => [field, row[field]])));
  if (!Number.isSafeInteger(row.journal_count)
    || row.journal_count !== head.lease_serial
    || typeof row.journal_tip !== "string" || !HEX.test(row.journal_tip)
    || (row.journal_count === 0 && row.journal_tip !== EMPTY_JOURNAL_TIP)) deny();
  return Object.freeze({ ...head, journal_count: row.journal_count, journal_tip: row.journal_tip });
}
function nextJournalTip(previousTip, challenge, serial) {
  bytes(challenge.nonce, 32);
  bytes(challenge.lease_id, 16);
  if (!HEX.test(previousTip) || !Number.isSafeInteger(serial)
    || serial < 1 || serial > MAX_LEASE_SERIAL) deny();
  const entry = { nonce: challenge.nonce, lease_id: challenge.lease_id, lease_serial: serial };
  return crypto.createHash("sha256").update(Buffer.from(previousTip, "hex"))
    .update(signatureBytes(JOURNAL_DOMAIN, entry)).digest("hex");
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
  const pin = dbPins.get(db);
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
  const pin = dbPins.get(db);
  dbPins.delete(db);
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
    dbPins.set(db, { file, fd: descriptor, identity: opened, failed: false });
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
function insertGenesis(db, head, ownerHash, signerHash) {
  checkDbPin(db);
  db.transaction(() => {
    checkDbPin(db);
    if (db.prepare("SELECT 1 FROM floor").get()) deny();
    checkDbPin(db);
    db.prepare(`INSERT INTO floor (singleton, sequence, head_digest, enrollment_root,
      immutable_account_id, identity_digest, lease_serial, journal_count, journal_tip,
      owner_spki, custodian_spki)
      VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(...STORED_FLOOR_FIELDS.map(f => head[f]),
        ownerHash, signerHash);
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
    const result = db.prepare(`UPDATE floor SET sequence = ?, head_digest = ?,
      enrollment_root = ?, immutable_account_id = ?, identity_digest = ?,
      lease_serial = ?, journal_count = ?, journal_tip = ?
      WHERE singleton = 1 AND lease_serial = ?`)
      .run(...STORED_FLOOR_FIELDS.map(f => next[f]), previous.lease_serial);
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

function createDevOffZk10MonotonicFloorCustodian(options) {
  let main, anchor;
  try {
    const o = strict(options, ["devOff", "databasePath", "anchorDatabasePath",
      "ownerPublicKey", "custodianPrivateKey", "custodianSpkiSha256", "bootstrap"]);
    if (o.devOff !== true || process.env.NODE_ENV === "production") deny();
    const owner = keyObject(o.ownerPublicKey, "public");
    const signer = keyObject(o.custodianPrivateKey, "private");
    const ownerHash = spki(owner);
    const signerHash = spki(crypto.createPublicKey(signer));
    if (ownerHash === signerHash || o.custodianSpkiSha256 !== signerHash) deny();
    const mainPath = safeFileName(o.databasePath);
    const anchorPath = safeFileName(o.anchorDatabasePath);
    if (mainPath.toLowerCase() === anchorPath.toLowerCase()) deny();
    const mainExists = fs.existsSync(mainPath), anchorExists = fs.existsSync(anchorPath);
    if (mainExists !== anchorExists) deny();
    let genesis;
    if (!mainExists) {
      const payload = unsignedSigned(o.bootstrap, GENESIS_FIELDS,
        "rootark-zk10-custodian-owner-genesis/v1", GENESIS_DOMAIN, owner);
      genesis = validateHead(Object.fromEntries(HEAD_FIELDS.map(f => [f, payload[f]])));
      if (genesis.lease_serial !== 0) deny();
      genesis = Object.freeze({ ...genesis, journal_count: 0, journal_tip: EMPTY_JOURNAL_TIP });
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
    if (!minimum || !same(minimum, read(main, ownerHash, signerHash, true))) deny();
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
          if (!same(minimum, read(anchor, ownerHash, signerHash))
            || !same(minimum, read(main, ownerHash, signerHash, true))) deny();
          return { ...minimum };
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
          const signed = unsignedSigned(ownerLease, LEASE_FIELDS,
            "rootark-zk10-custodian-owner-lease/v1", LEASE_DOMAIN, owner);
          for (const field of REQUEST_FIELDS) if (r[field] !== signed[field]) deny();
          const nextHead = validateHead(Object.fromEntries(
            HEAD_FIELDS.map(field => [field, signed[field]])));
          const at = NOW();
          if (nextHead.immutable_account_id !== minimum.immutable_account_id
            || nextHead.identity_digest !== minimum.identity_digest
            || nextHead.lease_serial !== minimum.lease_serial + 1
            || nextHead.sequence < minimum.sequence
            || nextHead.sequence > minimum.sequence + 1
            || (nextHead.sequence === minimum.sequence
              && (nextHead.head_digest !== minimum.head_digest
                || nextHead.enrollment_root !== minimum.enrollment_root))
            || !OPER.test(r.operation)
            || !Number.isSafeInteger(signed.issued_at_ms)
            || signed.issued_at_ms < at - 30_000 || signed.issued_at_ms > at + 1_000
            || !Number.isSafeInteger(r.lease_expires_at_ms)
            || r.lease_expires_at_ms <= at + 100
            || r.lease_expires_at_ms > at + 10_000) deny();
          bytes(r.nonce, 32);
          bytes(r.lease_id, 16);
          const next = Object.freeze({ ...nextHead, journal_count: minimum.journal_count + 1,
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
          if (!Number.isSafeInteger(issuedAt)
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
          const floor = Object.fromEntries(FLOOR_FIELDS.map(field => [field, response[field]]));
          const signature = crypto.sign(null, signatureBytes(FLOOR_DOMAIN, floor),
            signer).toString("base64url");
          // Signer hooks are synchronous and may rename files. Never return
          // signed bytes without checking both DB inodes once more.
          checkDbPin(anchor);
          checkDbPin(main);
          // Signing and final DB checks can stall after the pre-sign expiry
          // check. Never issue a CURRENT attestation whose owner lease has
          // already expired; its durable nonce is consumed, so fail closed.
          const completedAt = NOW();
          if (!Number.isSafeInteger(completedAt) || completedAt < issuedAt
            || completedAt + 100 >= r.lease_expires_at_ms) deny();
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
    return Object.freeze(api);
  } catch (_) {
    try { closeDb(main); } catch (_) { /* unavailable */ }
    try { closeDb(anchor); } catch (_) { /* unavailable */ }
    deny();
  }
}

module.exports = { createDevOffZk10MonotonicFloorCustodian };
