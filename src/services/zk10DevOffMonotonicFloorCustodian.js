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
  const parent = path.dirname(absolute);
  const stat = fs.lstatSync(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink()) deny();
  if (fs.existsSync(absolute)) {
    const current = fs.lstatSync(absolute);
    if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1) deny();
  }
  return absolute;
}
function same(a, b) {
  return HEAD_FIELDS.every(field => a[field] === b[field]);
}
function mapFloor(row) {
  if (!row) return null;
  return validateHead(Object.fromEntries(HEAD_FIELDS.map(field => [field, row[field]])));
}
function openDb(file) {
  const db = new Database(file, { timeout: 2000 });
  try {
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
      owner_spki TEXT NOT NULL, custodian_spki TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS used_lease (
      nonce TEXT NOT NULL UNIQUE, lease_id TEXT NOT NULL UNIQUE,
      lease_serial INTEGER NOT NULL UNIQUE
    );`);
    return db;
  } catch (_) {
    try { db.close(); } catch (_) { /* unavailable */ }
    deny();
  }
}
function read(db, ownerHash, signerHash) {
  const row = db.prepare("SELECT * FROM floor WHERE singleton = 1").get();
  if (row && (row.owner_spki !== ownerHash || row.custodian_spki !== signerHash)) deny();
  return mapFloor(row);
}
function insertGenesis(db, head, ownerHash, signerHash) {
  db.transaction(() => {
    if (db.prepare("SELECT 1 FROM floor").get()) deny();
    db.prepare(`INSERT INTO floor (singleton, sequence, head_digest, enrollment_root,
      immutable_account_id, identity_digest, lease_serial, owner_spki, custodian_spki)
      VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)`).run(...HEAD_FIELDS.map(f => head[f]),
      ownerHash, signerHash);
  }).immediate();
}
function advanceDb(db, previous, next, expectedOwner, expectedSigner, challenge, primary) {
  db.transaction(() => {
    const current = read(db, expectedOwner, expectedSigner);
    if (!same(current, previous)) deny();
    const result = db.prepare(`UPDATE floor SET sequence = ?, head_digest = ?,
      enrollment_root = ?, immutable_account_id = ?, identity_digest = ?,
      lease_serial = ? WHERE singleton = 1 AND lease_serial = ?`)
      .run(...HEAD_FIELDS.map(f => next[f]), previous.lease_serial);
    if (result.changes !== 1) deny();
    if (primary) db.prepare(`INSERT INTO used_lease (nonce, lease_id, lease_serial)
      VALUES (?, ?, ?)`).run(challenge.nonce, challenge.lease_id, next.lease_serial);
  }).immediate();
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
    if (!minimum || !same(minimum, read(main, ownerHash, signerHash))) deny();
    let closed = false, poisoned = false;
    const api = {
      independentOffServerCustodyProven: false,
      retainedMinimum() {
        if (closed || poisoned) deny();
        return { ...minimum };
      },
      attest(request, ownerLease) {
        if (closed || poisoned) deny();
        let writeStarted = false;
        try {
          const r = strict(request, REQUEST_FIELDS);
          const signed = unsignedSigned(ownerLease, LEASE_FIELDS,
            "rootark-zk10-custodian-owner-lease/v1", LEASE_DOMAIN, owner);
          for (const field of REQUEST_FIELDS) if (r[field] !== signed[field]) deny();
          const next = validateHead(Object.fromEntries(
            HEAD_FIELDS.map(field => [field, signed[field]])));
          const at = NOW();
          if (next.immutable_account_id !== minimum.immutable_account_id
            || next.identity_digest !== minimum.identity_digest
            || next.lease_serial !== minimum.lease_serial + 1
            || next.sequence < minimum.sequence
            || next.sequence > minimum.sequence + 1
            || (next.sequence === minimum.sequence
              && (next.head_digest !== minimum.head_digest
                || next.enrollment_root !== minimum.enrollment_root))
            || !OPER.test(r.operation)
            || !Number.isSafeInteger(signed.issued_at_ms)
            || signed.issued_at_ms < at - 30_000 || signed.issued_at_ms > at + 1_000
            || !Number.isSafeInteger(r.lease_expires_at_ms)
            || r.lease_expires_at_ms <= at + 100
            || r.lease_expires_at_ms > at + 10_000) deny();
          bytes(r.nonce, 32);
          bytes(r.lease_id, 16);
          // Check the separate minimum afresh before every admission; a
          // process that observes any externally edited state must stop.
          if (!same(minimum, read(anchor, ownerHash, signerHash))
            || !same(minimum, read(main, ownerHash, signerHash))
            || main.prepare("SELECT 1 FROM used_lease WHERE nonce = ? OR lease_id = ?")
              .get(r.nonce, r.lease_id)) deny();
          // Externally retained minimum is advanced BEFORE the primary.
          // A crash between these two commits blocks all future attestations.
          writeStarted = true;
          advanceDb(anchor, minimum, next, ownerHash, signerHash, r, false);
          advanceDb(main, minimum, next, ownerHash, signerHash, r, true);
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
        try { main.close(); } finally { anchor.close(); }
      },
    };
    return Object.freeze(api);
  } catch (_) {
    try { main?.close(); } catch (_) { /* unavailable */ }
    try { anchor?.close(); } catch (_) { /* unavailable */ }
    deny();
  }
}

module.exports = { createDevOffZk10MonotonicFloorCustodian };
