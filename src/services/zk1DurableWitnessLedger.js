"use strict";

// Isolated durable witness *engine*. Never mount in Root.ark's application
// process: independence requires a separate operator, transport, custody,
// trust-root bootstrap and physical CAS/egress integration. A signed receipt
// from this store alone NEVER admits protected I/O or recovery.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const z = require("../crypto/rootark-zk-1");
const { inspectVerifiedCasStatusProofV1 } = require("../crypto/rootark-zk-cas-status-wire-v1");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const RESERVE_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-reservation/v1\0", "ascii");
const COMMIT_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-commit/v1\0", "ascii");
const CANCEL_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-cancel/v1\0", "ascii");
const RESERVE_FIELDS = Object.freeze([
  "account_id", "compartment_id", "keyring_id", "reservation_id",
  "operation_id", "expected_revision", "expected_manifest_digest",
  "proposed_revision", "proposed_manifest_digest", "request_digest",
  "package_envelope_digest", "expires_at",
]);
const STATUS_FIELDS = RESERVE_FIELDS.filter((field) => field !== "expires_at");
const MAX_EVENTS_PER_SCOPE = 8192;
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

class Zk1DurableWitnessLedger {
  constructor(filename, {
    witnessKeyId, witnessPrivateKey, statusPinned, statusProvider, nowSeconds,
    bootstrapNew = false, maxEventsPerScope = MAX_EVENTS_PER_SCOPE,
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
    this.statusPinned = { keyId: this.statusKeyId, publicKey: statusPinned.publicKey };
    this.statusProvider = statusProvider;
    this.nowSeconds = nowSeconds || (() => Math.floor(Date.now() / 1000));
    if (typeof this.nowSeconds !== "function") fail();
    if (!Number.isSafeInteger(maxEventsPerScope) || maxEventsPerScope < 2
      || maxEventsPerScope > MAX_EVENTS_PER_SCOPE || maxEventsPerScope % 2 !== 0) fail();
    this.maxEventsPerScope = maxEventsPerScope;
    const absolute = path.resolve(filename);
    const existed = fs.existsSync(absolute);
    if (!existed && bootstrapNew !== true) fail("WITNESS_BOOTSTRAP_REQUIRED");
    const publicFingerprint = (publicKey) => crypto.createHash("sha256")
      .update(publicKey.export({ format: "der", type: "spki" })).digest();
    const ownFp = publicFingerprint(crypto.createPublicKey(witnessPrivateKey));
    const statusFp = publicFingerprint(statusPinned.publicKey);
    if (equal(ownFp, statusFp) || equal(this.witnessKeyId, this.statusKeyId)) {
      fail("WITNESS_IDENTITY_CONFLICT");
    }
    const verifyIdentity = (db) => {
      let row;
      try {
        if (!db.prepare(`SELECT name FROM sqlite_master
          WHERE type='table' AND name='witness_identity'`).get()) fail("WITNESS_STATE_MISSING");
        row = db.prepare("SELECT * FROM witness_identity WHERE id=1").get();
      } catch (error) {
        if (error.code === "WITNESS_STATE_MISSING") throw error;
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
    } else {
      fs.mkdirSync(path.dirname(absolute), { recursive: true });
      const fd = fs.openSync(absolute, fs.constants.O_CREAT | fs.constants.O_EXCL
        | fs.constants.O_RDWR, 0o600);
      try {
        const stat = fs.fstatSync(fd, { bigint: true });
        expectedFile = [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
      } finally { fs.closeSync(fd); }
    }
    this.db = new Database(absolute, { fileMustExist: true });
    try {
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
    `);
    this.db.pragma("foreign_keys = ON");
    if (!existed) {
      this.db.prepare("INSERT INTO witness_identity VALUES(1,?,?,?,?)").run(
        this.witnessKeyId, ownFp, this.statusKeyId, statusFp,
      );
    }
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

  async reserve(input) {
    const op = normalizeOperation(input);
    const key = compartmentKey(op.account_id, op.compartment_id);
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
    // Retain the exact signed reservation, not an unsigned editable copy of
    // the operation. Each later startup/read can validate the event ledger.
    this.db.transaction(() => {
      const commitTime = number(this.nowSeconds());
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
