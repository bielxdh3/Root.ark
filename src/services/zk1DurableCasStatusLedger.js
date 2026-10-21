"use strict";

// Single-host, durable zk-1 CAS/status engine. This is not a distributed
// provider, independently operated status authority, or content I/O fence.
// Do not route protected content through it until those boundaries exist.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const z = require("../crypto/rootark-zk-1");
const v2 = require("../crypto/rootark-zk-recovery-manifest-v2");
const limits = require("../crypto/rootark-zk-recovery-history-v2");
const { inspectVerifiedWitnessReservationV1 } = require("../crypto/rootark-zk-witness-operation-wire-v1");
const { Zk1CasTerminalAnchor } = require("./zk1CasTerminalAnchor");

const STATUS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-cas-status/v1\0", "ascii");
const TERMINAL_SEAL_DOMAIN = Buffer.from("Root.ark/zk-1/cas-terminal-seal/v1\0", "ascii");
const STATUS_QUERY_FIELDS = Object.freeze([
  "account_id", "compartment_id", "keyring_id", "reservation_id", "operation_id",
  "request_digest", "package_envelope_digest", "expected_revision",
  "expected_manifest_digest", "proposed_revision", "proposed_manifest_digest",
]);
const TICKET_FIELDS = Object.freeze([
  ...STATUS_QUERY_FIELDS, "expires_at",
]);
const BYTE_LENGTHS = Object.freeze({
  account_id: [16, 16], compartment_id: [1, 128], keyring_id: [16, 16],
  reservation_id: [16, 16], operation_id: [16, 16], request_digest: [32, 32],
  package_envelope_digest: [32, 32], expected_manifest_digest: [32, 32],
  proposed_manifest_digest: [32, 32],
});

function fail(code = "CAS_INVALID") {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function asBytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < min || value.byteLength > max) fail();
  return Buffer.from(value);
}
function same(a, b) {
  if (a === null || b === null) return a === b;
  if (Buffer.isBuffer(a) || a instanceof Uint8Array
    || Buffer.isBuffer(b) || b instanceof Uint8Array) {
    return (Buffer.isBuffer(a) || a instanceof Uint8Array)
      && (Buffer.isBuffer(b) || b instanceof Uint8Array)
      && a.byteLength === b.byteLength
      && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }
  return a === b;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((key) => !Object.hasOwn(value, key))
    || Reflect.ownKeys(value).some((key) => !fields.includes(key))) fail();
}
function normalizeQuery(raw) {
  exact(raw, STATUS_QUERY_FIELDS);
  const op = Object.create(null);
  for (const name of STATUS_QUERY_FIELDS) {
    const value = raw[name];
    if (Object.hasOwn(BYTE_LENGTHS, name)) {
      op[name] = value === null && ["package_envelope_digest", "expected_manifest_digest"].includes(name)
        ? null : asBytes(value, ...BYTE_LENGTHS[name]);
    } else if (name === "expected_revision") {
      if (value !== null && (!Number.isSafeInteger(value) || value < 1)) fail();
      op[name] = value;
    } else if (name === "proposed_revision") {
      if (!Number.isSafeInteger(value) || value < 1) fail();
      op[name] = value;
    } else fail();
  }
  if ((op.expected_revision === null) !== (op.expected_manifest_digest === null)
    || op.proposed_revision !== (op.expected_revision === null ? 1 : op.expected_revision + 1)) fail();
  return op;
}
function normalizeTicket(ticket) {
  if (!ticket || typeof ticket !== "object" || Array.isArray(ticket)) fail();
  const query = normalizeQuery(Object.fromEntries(STATUS_QUERY_FIELDS.map((key) => [key, ticket[key]])));
  if (!Number.isSafeInteger(ticket.expires_at) || ticket.expires_at < 0) fail();
  return { query, expires_at: ticket.expires_at };
}
function compartmentKey(op) {
  return op.account_id.toString("hex") + ":" + op.compartment_id.byteLength
    + ":" + op.compartment_id.toString("hex");
}
function identityFingerprint(publicKey) {
  return crypto.createHash("sha256")
    .update(publicKey.export({ format: "der", type: "spki" })).digest();
}

class Zk1DurableCasStatusLedger {
  constructor(filename, { bootstrapNew = false, statusKeyId, statusPrivateKey,
    witnessPinned, nowSeconds, anchorPath } = {}) {
    if (typeof filename !== "string" || !filename
      || !(statusPrivateKey instanceof crypto.KeyObject)
      || statusPrivateKey.type !== "private" || statusPrivateKey.asymmetricKeyType !== "ed25519"
      || !(witnessPinned?.publicKey instanceof crypto.KeyObject)
      || witnessPinned.publicKey.type !== "public"
      || witnessPinned.publicKey.asymmetricKeyType !== "ed25519") fail();
    this.statusKeyId = asBytes(statusKeyId, 16);
    this.witnessKeyId = asBytes(witnessPinned.keyId, 16);
    this.witnessPinned = { keyId: this.witnessKeyId, publicKey: witnessPinned.publicKey };
    this.statusPrivateKey = statusPrivateKey;
    this.statusPublicKey = crypto.createPublicKey(statusPrivateKey);
    this.nowSeconds = nowSeconds || (() => Math.floor(Date.now() / 1000));
    if (typeof this.nowSeconds !== "function") fail();
    const ownFp = identityFingerprint(crypto.createPublicKey(statusPrivateKey));
    const witnessFp = identityFingerprint(witnessPinned.publicKey);
    if (same(ownFp, witnessFp) || same(this.statusKeyId, this.witnessKeyId)) fail("CAS_IDENTITY_CONFLICT");

    const absolute = path.resolve(filename);
    const existed = fs.existsSync(absolute);
    if (!existed && !bootstrapNew) fail("CAS_BOOTSTRAP_REQUIRED");
    if (typeof anchorPath !== "string" || !path.isAbsolute(anchorPath)
      || path.resolve(anchorPath) === absolute) fail("CAS_ANCHOR_REQUIRED");
    const anchorExisted = fs.existsSync(anchorPath);
    if (existed !== anchorExisted) fail("CAS_ANCHOR_STATE_MISMATCH");
    const verifyIdentity = (db) => {
      let row;
      try {
        if (!db.prepare(`SELECT name FROM sqlite_master
          WHERE type='table' AND name='cas_identity'`).get()) fail("CAS_STATE_MISSING");
        row = db.prepare("SELECT * FROM cas_identity WHERE id=1").get();
      } catch (error) {
        if (error.code === "CAS_STATE_MISSING") throw error;
        fail("CAS_STATE_MISSING");
      }
      if (!row) fail("CAS_STATE_MISSING");
      if (!same(row.status_id, this.statusKeyId)
        || !same(row.status_fingerprint, ownFp)
        || !same(row.witness_id, this.witnessKeyId)
        || !same(row.witness_fingerprint, witnessFp)) fail("CAS_IDENTITY_MISMATCH");
    };
    const fileIdentity = () => {
      const stat = fs.statSync(absolute, { bigint: true });
      if (!stat.isFile()) fail("CAS_STATE_MISSING");
      return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");
    };
    let expectedFile;
    if (existed) {
      if (!fs.lstatSync(absolute).isFile()) fail("CAS_STATE_MISSING");
      expectedFile = fileIdentity();
      const readonly = new Database(absolute, { readonly: true, fileMustExist: true });
      try { verifyIdentity(readonly); }
      finally { readonly.close(); }
      // Refuse invalid foreign anchors before any SQLite write-mode open.
      new Zk1CasTerminalAnchor(anchorPath, {
        bootstrapNew: false, statusKeyId: this.statusKeyId, statusPrivateKey,
      });
      if (fileIdentity() !== expectedFile) fail("CAS_STATE_MISSING");
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
      if (fileIdentity() !== expectedFile) fail("CAS_STATE_MISSING");
      if (existed) {
        verifyIdentity(this.db);
      }
      this.db.pragma("journal_mode = WAL");
      this.db.pragma("synchronous = FULL");
      this.db.pragma("foreign_keys = ON");
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS cas_identity (
          id INTEGER PRIMARY KEY CHECK(id=1), status_id BLOB NOT NULL,
          status_fingerprint BLOB NOT NULL, witness_id BLOB NOT NULL,
          witness_fingerprint BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cas_scope (
          scope_key TEXT PRIMARY KEY, keyring_id BLOB NOT NULL, revision INTEGER,
          digest BLOB, pending_id BLOB, transition_count INTEGER NOT NULL DEFAULT 0,
          history_bytes INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS cas_operation (
          reservation_id BLOB PRIMARY KEY, operation_id BLOB NOT NULL UNIQUE,
          scope_key TEXT NOT NULL, signed_ticket BLOB NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('pending','committed','not-committed-final')),
          committed_manifest BLOB, terminal_seal BLOB,
          FOREIGN KEY(scope_key) REFERENCES cas_scope(scope_key)
        );
        CREATE TABLE IF NOT EXISTS cas_transition (
          scope_key TEXT NOT NULL, revision INTEGER NOT NULL,
          digest BLOB NOT NULL, manifest_bytes BLOB NOT NULL,
          PRIMARY KEY(scope_key,revision),
          FOREIGN KEY(scope_key) REFERENCES cas_scope(scope_key)
        );
      `);
      if (!existed) {
        this.db.prepare("INSERT INTO cas_identity VALUES(1,?,?,?,?)")
          .run(this.statusKeyId, ownFp, this.witnessKeyId, witnessFp);
      }
      this.anchor = new Zk1CasTerminalAnchor(anchorPath, {
        bootstrapNew: !existed && bootstrapNew,
        statusKeyId: this.statusKeyId,
        statusPrivateKey,
      });
      this.scopeRow = this.db.prepare("SELECT * FROM cas_scope WHERE scope_key=?");
      this.operationRow = this.db.prepare("SELECT * FROM cas_operation WHERE reservation_id=?");
      this.latestManifest = this.db.prepare(
        "SELECT manifest_bytes FROM cas_transition WHERE scope_key=? ORDER BY revision DESC LIMIT 1");
      this.historyRows = this.db.prepare(
        "SELECT manifest_bytes FROM cas_transition WHERE scope_key=? ORDER BY revision LIMIT 4097");
    } catch (error) {
      this.db.close();
      throw error;
    }
  }

  now() {
    const value = this.nowSeconds();
    if (!Number.isSafeInteger(value) || value < 0) fail("CAS_CLOCK_UNHEALTHY");
    return value;
  }

  async terminalSealMessage(receipt, status, manifestBytes) {
    if (status !== "committed" && status !== "not-committed-final") fail();
    const signedTicket = asBytes(receipt, 1, 4096);
    if (status === "committed" && !manifestBytes) fail();
    if (status === "not-committed-final" && manifestBytes !== null) fail();
    const unsigned = {
      type: "rootark-zk1-cas-terminal-seal/v1",
      status_authority_key_id: this.statusKeyId,
      receipt_digest: crypto.createHash("sha256").update(signedTicket).digest(),
      manifest_digest: manifestBytes === null ? null
        : crypto.createHash("sha256").update(manifestBytes).digest(),
      terminal_status: status,
    };
    return Buffer.concat([TERMINAL_SEAL_DOMAIN, Buffer.from(await z.encodeDeterministic(unsigned))]);
  }

  async signTerminalSeal(receipt, status, manifestBytes = null) {
    return crypto.sign(null, await this.terminalSealMessage(receipt, status, manifestBytes),
      this.statusPrivateKey);
  }

  async assertTerminalSeal(row) {
    if (!row || !Buffer.isBuffer(row.terminal_seal) || row.terminal_seal.byteLength !== 64
      || !Buffer.isBuffer(row.signed_ticket)) fail("CAS_LEDGER_CORRUPT");
    const message = await this.terminalSealMessage(
      row.signed_ticket, row.status, row.status === "committed" ? row.committed_manifest : null,
    );
    if (!crypto.verify(null, message, this.statusPublicKey, row.terminal_seal)) {
      fail("CAS_LEDGER_CORRUPT");
    }
    if (row.status === "not-committed-final" && row.committed_manifest !== null) {
      fail("CAS_LEDGER_CORRUPT");
    }
  }

  assertAnchor(row, op) {
    if (row.status === "pending") {
      if (this.anchor.get(op.reservation_id)) fail("CAS_LEDGER_ROLLBACK");
      return;
    }
    try {
      this.anchor.assertIntent(op, row.signed_ticket, row.status,
        row.status === "committed" ? row.committed_manifest : null);
      this.anchor.assertMatch(op, row.signed_ticket, row.status,
        row.status === "committed" ? row.committed_manifest : null,
        row.terminal_seal);
    } catch (_) { fail("CAS_LEDGER_ROLLBACK"); }
  }

  async verifiedTicket(raw) {
    const snapshot = asBytes(raw, 1, 4096);
    let ticket;
    try { ticket = await z.decodeDeterministic(snapshot); }
    catch (_) { fail(); }
    const { query, expires_at } = normalizeTicket(ticket);
    await inspectVerifiedWitnessReservationV1({
      raw: snapshot, operation: { ...query, expires_at }, pinned: this.witnessPinned,
    });
    return { raw: snapshot, query, expires_at };
  }

  // The witness must reserve first; CAS cannot create a ticket for itself.
  async registerReservation({ receipt }) {
    const ticket = await this.verifiedTicket(receipt);
    const op = ticket.query;
    const scopeKey = compartmentKey(op);
    const independentTerminal = this.anchor.get(op.reservation_id);
    const result = this.db.transaction(() => {
      const previous = this.operationRow.get(op.reservation_id);
      if (previous) {
        if (!same(previous.signed_ticket, ticket.raw) || previous.scope_key !== scopeKey) fail("CAS_CONFLICT");
        return { status: previous.status, terminalRow: previous };
      }
      if (this.now() > ticket.expires_at) fail("CAS_EXPIRED");
      const scope = this.scopeRow.get(scopeKey);
      if (independentTerminal) fail("CAS_LEDGER_ROLLBACK");
      // A fully deleted CAS scope must not permit a *different* witness-
      // signed genesis ticket to re-initialize an already anchored keyring.
      if (op.expected_revision === null && this.anchor.hasScope(op)) {
        fail("CAS_LEDGER_ROLLBACK");
      }
      if (scope && !same(scope.keyring_id, op.keyring_id)) fail("CAS_KEYRING_CONFLICT");
      if (scope && scope.revision === null && op.expected_revision === null
        && this.db.prepare("SELECT 1 FROM cas_operation WHERE scope_key=? AND status='not-committed-final' LIMIT 1")
          .get(scopeKey)) fail("CAS_TOMBSTONED");
      if ((scope?.revision ?? null) !== op.expected_revision
        || !same(scope?.digest ?? null, op.expected_manifest_digest)
        || scope?.pending_id) fail("CAS_CONFLICT");
      if (!scope) {
        this.db.prepare("INSERT INTO cas_scope(scope_key,keyring_id,pending_id) VALUES(?,?,?)")
          .run(scopeKey, op.keyring_id, op.reservation_id);
      } else {
        this.db.prepare("UPDATE cas_scope SET pending_id=? WHERE scope_key=?")
          .run(op.reservation_id, scopeKey);
      }
      this.db.prepare("INSERT INTO cas_operation VALUES(?,?,?,?,'pending',NULL,NULL)")
        .run(op.reservation_id, op.operation_id, scopeKey, ticket.raw);
      return { status: "pending" };
    }).immediate();
    if (result.terminalRow) {
      if (result.status === "pending") {
        if (result.terminalRow.terminal_seal !== null
          || result.terminalRow.committed_manifest !== null) fail("CAS_LEDGER_CORRUPT");
        this.assertAnchor(result.terminalRow, op);
      } else {
        // A terminal ACK is trusted only after the very same signed-status
        // verification and crash-gap anchor recovery as /v1/terminal.
        await this.getTerminalProof({ query: op, nonce: crypto.randomBytes(32) });
      }
    }
    return { status: result.status };
  }

  async commit({ receipt, manifestBytes }) {
    const ticket = await this.verifiedTicket(receipt);
    const op = ticket.query;
    const scopeKey = compartmentKey(op);
    const raw = asBytes(manifestBytes, 1, limits.MAX_ENTRY_BYTES);
    const priorTerminal = this.anchor.get(op.reservation_id);
    const initial = this.db.transaction(() => {
      const existing = this.operationRow.get(op.reservation_id);
      const scope = this.scopeRow.get(scopeKey);
      if (!existing || !same(existing.signed_ticket, ticket.raw) || !scope
        || !same(scope.keyring_id, op.keyring_id)) fail("CAS_NOT_RESERVED");
      if (existing.status === "committed") {
        if (!same(existing.committed_manifest, raw)) fail("CAS_CONFLICT");
        return { alreadyCommitted: true, terminalRow: existing };
      }
      if (existing.status !== "pending") fail("CAS_FENCED");
      if (!same(scope.pending_id, op.reservation_id)) fail("CAS_CONFLICT");
      return {
        scope, previousRaw: this.latestManifest.get(scopeKey)?.manifest_bytes ?? null,
        history: this.historyRows.all(scopeKey).map((row) => Buffer.from(row.manifest_bytes)),
      };
    })();
    if (initial.alreadyCommitted) {
      await this.getTerminalProof({ query: op, nonce: crypto.randomBytes(32) });
      return { status: "committed", replay: true };
    }
    if (priorTerminal) fail("CAS_LEDGER_ROLLBACK");
    // A previously signed, fsynced intent can be resumed after expiry, but
    // only for the *exact* witness ticket and verified manifest. No new
    // intent may be created after expiry.
    const prepared = this.anchor.getIntent(op);
    if (prepared) {
      try { this.anchor.assertIntent(op, ticket.raw, "committed", raw); }
      catch (_) { fail("CAS_LEDGER_ROLLBACK"); }
    } else if (this.now() > ticket.expires_at) fail("CAS_EXPIRED");
    let manifest;
    try { manifest = await z.decodeDeterministic(raw); }
    catch (_) { fail(); }
    if (!same(raw, Buffer.from(await z.encodeDeterministic(manifest)))) fail();
    const previousManifest = initial.previousRaw
      ? await z.decodeDeterministic(initial.previousRaw) : null;
    const retained = new Set();
    for (const bytes of initial.history) {
      for (const identifier of v2.recoveryManifestIdentifiersV2(await z.decodeDeterministic(bytes))) {
        retained.add(identifier);
      }
    }
    let proof;
    try {
      proof = await v2.verifyRecoveryTransitionPublicV2({
        previousManifest, nextManifest: manifest,
        expectedScope: {
          account_id: op.account_id, compartment_id: op.compartment_id, keyring_id: op.keyring_id,
        },
        retainedIdentifiers: { complete: true, values: retained },
      });
    } catch (_) { fail("CAS_INVALID_MANIFEST"); }
    if (!(await v2.isVerifiedRecoveryTransitionPublicProofV2(proof))
      || !same(proof.manifestDigest, op.proposed_manifest_digest)
      || !same(manifest.operation.operation_id, op.operation_id)
      || !same(manifest.operation.request_digest, op.request_digest)
      || Number(manifest.operation.expires_at) !== ticket.expires_at
      || Number(manifest.revision) !== op.proposed_revision
      || (manifest.recovery_authority?.status === "active"
        ? !same(manifest.recovery_authority.package_envelope_digest, op.package_envelope_digest)
        : op.package_envelope_digest !== null)) fail("CAS_INVALID_MANIFEST");
    const capacity = limits.checkRecoveryHistoryCapacity({
      transitionCount: initial.scope.transition_count,
      historyBytes: initial.scope.history_bytes, nextEntryBytes: raw.length,
    });
    const terminalSeal = await this.signTerminalSeal(ticket.raw, "committed", raw);
    this.db.transaction(() => {
      const current = this.scopeRow.get(scopeKey);
      const row = this.operationRow.get(op.reservation_id);
      if (!row || !same(row.signed_ticket, ticket.raw)) fail("CAS_CONFLICT");
      if (row.status === "committed" && same(row.committed_manifest, raw)) return;
      if (row.status !== "pending") fail("CAS_FENCED");
      if (!same(current.pending_id, op.reservation_id)
        || current.revision !== op.expected_revision
        || !same(current.digest, op.expected_manifest_digest)
        || current.transition_count !== initial.scope.transition_count
        || current.history_bytes !== initial.scope.history_bytes) fail("CAS_CONFLICT");
      // Check the deadline and write the signed intent while holding the
      // SQLite write lock. After a valid intent has been durably prepared,
      // crossing the deadline cannot abandon this irreversible decision.
      if (!prepared && this.now() > ticket.expires_at) fail("CAS_EXPIRED");
      this.anchor.prepare(op, ticket.raw, "committed", raw);
      this.db.prepare("INSERT INTO cas_transition VALUES(?,?,?,?)")
        .run(scopeKey, op.proposed_revision, op.proposed_manifest_digest, raw);
      this.db.prepare("UPDATE cas_scope SET revision=?, digest=?, pending_id=NULL, transition_count=?, history_bytes=? WHERE scope_key=?")
        .run(op.proposed_revision, op.proposed_manifest_digest,
          capacity.usedTransitions, capacity.usedBytes, scopeKey);
      this.db.prepare("UPDATE cas_operation SET status='committed', committed_manifest=?, terminal_seal=? WHERE reservation_id=?")
        .run(raw, terminalSeal, op.reservation_id);
    }).immediate();
    // Confirm the prepared outcome only AFTER the durable SQLite transaction.
    // On crash here, exact signed DB evidence + the prepared intent can be
    // safely reconciled by the normal retry/status path.
    await this.anchor.append(op, ticket.raw, "committed", raw, terminalSeal);
    return { status: "committed", replay: false };
  }

  async getTerminalProof({ query, nonce }) {
    const op = normalizeQuery(query);
    const challenge = asBytes(nonce, 32);
    const scopeKey = compartmentKey(op);
    const now = this.now();
    const terminal = this.db.transaction(() => {
      const operation = this.operationRow.get(op.reservation_id);
      const scope = this.scopeRow.get(scopeKey);
      if (!operation || operation.scope_key !== scopeKey || !scope) fail("CAS_UNRESOLVED");
      // Never trust arbitrary status query fields. Compare with the immutable,
      // witness-signed ticket and its original reservation scope.
      const receipt = operation.signed_ticket;
      // The ticket CBOR is validated on registration; no JSON query or
      // application assertion is allowed to create the terminal operation.
      if (!same(operation.operation_id, op.operation_id)) fail("CAS_UNRESOLVED");
      if (operation.status === "pending") {
        return { status: "pending", receipt };
      }
      return { status: operation.status, receipt };
    })();
    const immutableTicket = await this.verifiedTicket(terminal.receipt);
    if (STATUS_QUERY_FIELDS.some((field) => !same(immutableTicket.query[field], op[field]))) {
      fail("CAS_UNRESOLVED");
    }
    if (terminal.status === "pending") {
      if (this.anchor.get(op.reservation_id)) fail("CAS_LEDGER_ROLLBACK");
      const prepared = this.anchor.getIntent(op);
      if (prepared && prepared.status !== "not-committed-final") fail("CAS_LEDGER_ROLLBACK");
      if (this.now() < immutableTicket.expires_at + 30) fail("CAS_UNRESOLVED");
      const signedFence = await this.signTerminalSeal(terminal.receipt, "not-committed-final");
      const didFence = this.db.transaction(() => {
        const current = this.operationRow.get(op.reservation_id);
        const scope = this.scopeRow.get(scopeKey);
        if (current.status !== "pending") return false;
        if (this.now() < immutableTicket.expires_at + 30) fail("CAS_UNRESOLVED");
        if (!same(scope.pending_id, op.reservation_id)
          || scope.revision !== op.expected_revision
          || !same(scope.digest, op.expected_manifest_digest)) fail("CAS_UNRESOLVED");
        this.anchor.prepare(op, terminal.receipt, "not-committed-final", null);
        // This durable fence races COMMIT under the same SQLite write lock.
        // A late or reordered commit cannot cross this terminal boundary.
        this.db.prepare("UPDATE cas_operation SET status='not-committed-final', terminal_seal=? WHERE reservation_id=?")
          .run(signedFence, op.reservation_id);
        this.db.prepare("UPDATE cas_scope SET pending_id=NULL WHERE scope_key=?")
          .run(scopeKey);
        return true;
      }).immediate();
      if (didFence) {
        await this.anchor.append(op, terminal.receipt, "not-committed-final", null, signedFence);
      }
    }
    const { row, scope, transition } = this.db.transaction(() => {
      const current = this.operationRow.get(op.reservation_id);
      const currentScope = this.scopeRow.get(scopeKey);
      const committedTransition = current?.status === "committed"
        ? this.db.prepare("SELECT * FROM cas_transition WHERE scope_key=? AND revision=?")
          .get(scopeKey, op.proposed_revision) : null;
      return { row: current, scope: currentScope, transition: committedTransition };
    })();
    if (row.status !== "committed" && row.status !== "not-committed-final") fail("CAS_UNRESOLVED");
    await this.assertTerminalSeal(row);
    const committed = row.status === "committed";
    if (committed) {
      if (!scope || !transition || !row.committed_manifest
        || !same(transition.digest, op.proposed_manifest_digest)
        || !same(transition.manifest_bytes, row.committed_manifest)
        || scope.revision < op.proposed_revision
        || (scope.revision === op.proposed_revision
          && !same(scope.digest, op.proposed_manifest_digest))) fail("CAS_LEDGER_CORRUPT");
      let digest;
      try {
        const decoded = await z.decodeDeterministic(Buffer.from(transition.manifest_bytes));
        digest = await v2.recoveryManifestDigestV2(decoded);
      } catch (_) { fail("CAS_LEDGER_CORRUPT"); }
      if (!same(digest, op.proposed_manifest_digest)) fail("CAS_LEDGER_CORRUPT");
    } else if (!scope || !same(scope.keyring_id, op.keyring_id)) {
      fail("CAS_LEDGER_CORRUPT");
    }
    if (!this.anchor.get(op.reservation_id)) {
      try {
        this.anchor.assertIntent(op, row.signed_ticket, row.status,
          committed ? row.committed_manifest : null);
      } catch (_) { fail("CAS_LEDGER_ROLLBACK"); }
      await this.anchor.append(op, row.signed_ticket, row.status,
        committed ? row.committed_manifest : null, row.terminal_seal);
    }
    this.assertAnchor(row, op);
    const unsigned = {
      type: "rootark-recovery-cas-status/v1",
      status_authority_key_id: this.statusKeyId,
      ...op,
      observed_revision: committed ? op.proposed_revision : op.expected_revision,
      observed_manifest_digest: committed ? op.proposed_manifest_digest : op.expected_manifest_digest,
      terminal_status: row.status,
      observed_at: now, nonce: challenge,
    };
    const signature = crypto.sign(null, Buffer.concat([STATUS_DOMAIN,
      Buffer.from(await z.encodeDeterministic(unsigned))]), this.statusPrivateKey);
    return Buffer.from(await z.encodeDeterministic({ ...unsigned, signature }));
  }

  async getCommittedManifest({ scope }) {
    // Public manifest retrieval is intentionally distinct from terminality.
    // The caller MUST verify it against a fresh independently signed witness
    // head; CAS HTTP success is NEVER a content authorization decision.
    exact(scope, ["account_id", "compartment_id", "keyring_id"]);
    const identity = {
      account_id: asBytes(scope.account_id, 16),
      compartment_id: asBytes(scope.compartment_id, 1, 128),
      keyring_id: asBytes(scope.keyring_id, 16),
    };
    const key = compartmentKey(identity);
    const state = this.db.transaction(() => {
      const current = this.scopeRow.get(key);
      // Validate persisted size claims with SQL aggregates *before* .all().
      // Otherwise one corrupted/restored SQLite row could allocate arbitrary
      // RAM while merely requesting a bounded history page.
      const manifestSize = this.db.prepare(
        "SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(manifest_bytes)),0) AS total,"
        + " COALESCE(MAX(LENGTH(manifest_bytes)),0) AS largest FROM cas_transition"
        + " WHERE scope_key=?",
      ).get(key);
      const operationSize = this.db.prepare(
        "SELECT COUNT(*) AS n,"
        + " COALESCE(SUM(LENGTH(signed_ticket)),0) AS ticket_bytes,"
        + " COALESCE(MAX(LENGTH(signed_ticket)),0) AS largest_ticket,"
        + " COALESCE(SUM(LENGTH(committed_manifest)),0) AS committed_bytes,"
        + " COALESCE(MAX(LENGTH(committed_manifest)),0) AS largest_commit,"
        + " COALESCE(SUM(LENGTH(terminal_seal)),0) AS seal_bytes,"
        + " COALESCE(MAX(LENGTH(terminal_seal)),0) AS largest_seal"
        + " FROM cas_operation WHERE scope_key=?",
      ).get(key);
      if (!current || current.revision === null || current.pending_id !== null
        || manifestSize.n !== current.revision
        || manifestSize.n > limits.MAX_TRANSITIONS + 1
        || manifestSize.total > limits.MAX_HISTORY_BYTES
        || manifestSize.largest > limits.MAX_ENTRY_BYTES
        || operationSize.n > limits.MAX_TRANSITIONS + 1
        || operationSize.ticket_bytes > (limits.MAX_TRANSITIONS + 1) * 4096
        || operationSize.largest_ticket > 4096
        || operationSize.committed_bytes > limits.MAX_HISTORY_BYTES
        || operationSize.largest_commit > limits.MAX_ENTRY_BYTES
        || operationSize.seal_bytes > (limits.MAX_TRANSITIONS + 1) * 4096
        || operationSize.largest_seal > 4096) fail("CAS_UNRESOLVED");
      return {
        scope: current,
        operations: this.db.prepare("SELECT * FROM cas_operation WHERE scope_key=?").all(key),
        transitions: this.db.prepare("SELECT * FROM cas_transition WHERE scope_key=? ORDER BY revision").all(key),
      };
    })();
    if (!state.scope || !same(state.scope.keyring_id, identity.keyring_id)
      || state.scope.revision === null || state.scope.pending_id !== null
      || state.transitions.length !== state.scope.revision
      || state.operations.length > 4096) fail("CAS_UNRESOLVED");
    // A SQL-only rewind or deletion must not hide an already independently
    // signed terminal event. Compare ALL committed and cancelled terminals,
    // rather than trusting a single latest SQL row.
    const anchored = this.anchor.scopeEvents(identity);
    const terminals = state.operations.filter((row) => row.status !== "pending");
    if (terminals.length !== anchored.length) fail("CAS_LEDGER_ROLLBACK");
    const anchoredIds = new Set(anchored.map((event) => event.reservation));
    if (anchoredIds.size !== anchored.length) fail("CAS_LEDGER_ROLLBACK");
    const committed = new Map();
    for (const row of terminals) {
      const signed = await this.verifiedTicket(row.signed_ticket);
      if (compartmentKey(signed.query) !== key
        || !same(row.reservation_id, signed.query.reservation_id)
        || !same(row.operation_id, signed.query.operation_id)
        || !anchoredIds.has(row.reservation_id.toString("base64url"))) {
        fail("CAS_LEDGER_ROLLBACK");
      }
      await this.assertTerminalSeal(row);
      this.assertAnchor(row, signed.query);
      if (row.status === "committed") {
        if (committed.has(signed.query.proposed_revision)) fail("CAS_LEDGER_CORRUPT");
        committed.set(signed.query.proposed_revision, row);
      }
    }
    if (committed.size !== state.transitions.length) fail("CAS_LEDGER_ROLLBACK");
    for (let index = 0; index < state.transitions.length; index += 1) {
      const item = state.transitions[index];
      const row = committed.get(index + 1);
      if (!row || item.revision !== index + 1
        || !same(row.committed_manifest, item.manifest_bytes)
        || !same(item.digest,
          (await v2.recoveryManifestDigestV2(await z.decodeDeterministic(item.manifest_bytes))))) {
        fail("CAS_LEDGER_CORRUPT");
      }
    }
    const head = state.transitions.at(-1);
    if (!same(state.scope.digest, head.digest)) fail("CAS_LEDGER_CORRUPT");
    return Buffer.from(head.manifest_bytes);
  }

  async getCommittedHistoryPage({ scope, startRevision }) {
    // History bytes are NEVER an authorization response. In particular do
    // NOT fully audit/materialize the 64 MiB CAS status ledger for EACH
    // untrusted page: a small-page client would amplify work quadratically.
    // The client MUST verify the full signature chain, independently pinned
    // base receipt and fresh nonce-bound witness head before trusting bytes.
    exact(scope, ["account_id", "compartment_id", "keyring_id"]);
    if (!Number.isSafeInteger(startRevision)
      || startRevision < 1 || startRevision > limits.MAX_TRANSITIONS + 1) fail();
    const identity = {
      account_id: asBytes(scope.account_id, 16),
      compartment_id: asBytes(scope.compartment_id, 1, 128),
      keyring_id: asBytes(scope.keyring_id, 16),
    };
    const key = compartmentKey(identity);
    const snapshot = this.db.transaction(() => {
      const current = this.scopeRow.get(key);
      if (!current || current.pending_id !== null
        || !same(current.keyring_id, identity.keyring_id)
        || !Number.isSafeInteger(current.revision)
        || current.revision < startRevision
        || current.revision > limits.MAX_TRANSITIONS + 1
        || !Number.isSafeInteger(current.history_bytes)
        || current.history_bytes < 0 || current.history_bytes > limits.MAX_HISTORY_BYTES
        || !Buffer.isBuffer(current.digest) || current.digest.length !== 32) {
        fail("CAS_UNRESOLVED");
      }
      const entries = [];
      let pageBytes = 0;
      // Iterate lazily: .all() could materialize up to 4,097 x 8 MiB,
      // exhausting process memory BEFORE the 8 MiB page bound is checked.
      for (const row of this.db.prepare(
        "SELECT revision,manifest_bytes FROM cas_transition"
        + " WHERE scope_key=? AND revision>=? ORDER BY revision LIMIT 4097",
      ).iterate(key, startRevision)) {
        if (row.revision !== startRevision + entries.length) fail("CAS_LEDGER_CORRUPT");
        const bytes = asBytes(row.manifest_bytes, 1, limits.MAX_ENTRY_BYTES);
        if (pageBytes + bytes.length > limits.MAX_ENTRY_BYTES) break;
        entries.push(bytes);
        pageBytes += bytes.length;
      }
      return { current, entries };
    })();
    if (snapshot.entries.length > limits.MAX_TRANSITIONS + 1) fail("CAS_UNRESOLVED");
    const entries = snapshot.entries;
    if (!entries.length) fail("CAS_UNRESOLVED");
    const nextRevision = startRevision + entries.length;
    return {
      headRevision: snapshot.current.revision,
      headDigest: Buffer.from(snapshot.current.digest),
      startRevision,
      nextRevision: nextRevision <= snapshot.current.revision ? nextRevision : null,
      entries,
    };
  }

  close() { if (this.db.open) this.db.close(); }
}

module.exports = { Zk1DurableCasStatusLedger };
