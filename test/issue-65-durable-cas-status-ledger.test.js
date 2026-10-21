"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const Database = require("better-sqlite3");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { Zk1DurableCasStatusLedger } = require("../src/services/zk1DurableCasStatusLedger");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { inspectVerifiedCasStatusProofV1 } = require("../src/crypto/rootark-zk-cas-status-wire-v1");

const QUERY_FIELDS = [
  "account_id", "compartment_id", "keyring_id", "reservation_id", "operation_id",
  "request_digest", "package_envelope_digest", "expected_revision",
  "expected_manifest_digest", "proposed_revision", "proposed_manifest_digest",
];
async function setup(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-cas-status-"));
  const connections = new Set();
  t.after(() => {
    for (const connection of connections) connection.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const initial = await fixtures.createInitialState(1);
  const manifest = initial.headManifest;
  const manifestBytes = Buffer.from(await z.encodeDeterministic(manifest));
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const statusKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  let clock = 1100;
  const now = () => clock;
  const operation = {
    ...initial.scope,
    reservation_id: crypto.randomBytes(16),
    operation_id: Buffer.from(manifest.operation.operation_id),
    expected_revision: null, expected_manifest_digest: null,
    proposed_revision: 1,
    proposed_manifest_digest: Buffer.from(await v2.recoveryManifestDigestV2(manifest)),
    request_digest: Buffer.from(manifest.operation.request_digest),
    package_envelope_digest: null,
    expires_at: Number(manifest.operation.expires_at),
  };
  const query = Object.fromEntries(QUERY_FIELDS.map((field) => [field, operation[field]]));
  const casFilename = path.join(dir, "cas.sqlite");
  const casOptions = {
    bootstrapNew: true, nowSeconds: now, statusKeyId,
    anchorPath: path.join(dir, "cas-terminal-anchor.log"),
    statusPrivateKey: statusKeys.privateKey,
    witnessPinned: { keyId: witnessKeyId, publicKey: witnessKeys.publicKey },
  };
  const openCas = (options = {}) => {
    const connection = new Zk1DurableCasStatusLedger(casFilename, { ...casOptions, ...options });
    connections.add(connection);
    return connection;
  };
  const cas = openCas();
  const witness = new Zk1DurableWitnessLedger(path.join(dir, "witness.sqlite"), {
    bootstrapNew: true, witnessKeyId,
    witnessPrivateKey: witnessKeys.privateKey,
    statusPinned: { keyId: statusKeyId, publicKey: statusKeys.publicKey },
    statusProvider: cas, nowSeconds: now,
  });
  connections.add(witness);
  const ticket = await witness.reserve(operation);
  return {
    cas, witness, ticket, operation, query, manifest, manifestBytes,
    casOptions, casFilename, openCas, witnessPrivateKey: witnessKeys.privateKey,
    pinnedStatus: { keyId: statusKeyId, publicKey: statusKeys.publicKey },
    setTime(value) { clock = value; },
  };
}

test("real signed v2 manifest advances durable CAS and provides an exact nonce-bound witness status", async (t) => {
  const f = await setup(t);
  await assert.rejects(f.cas.getTerminalProof({ query: f.query, nonce: crypto.randomBytes(32) }),
    /CAS_UNRESOLVED/, "no receipt registration means no status authority");
  assert.deepEqual(await f.cas.registerReservation({ receipt: f.ticket }), { status: "pending" });
  assert.deepEqual(await f.cas.registerReservation({ receipt: f.ticket }), { status: "pending" },
    "lost register ACK must be idempotent");
  await assert.rejects(f.cas.getTerminalProof({ query: f.query, nonce: crypto.randomBytes(32) }),
    /CAS_UNRESOLVED/, "time before the fence boundary is not terminality");
  const committed = await f.cas.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes });
  assert.deepEqual(committed, { status: "committed", replay: false });
  const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
    .map((field) => [field, f.operation[field]]));
  assert.deepEqual(await f.cas.getCommittedManifest({ scope }), f.manifestBytes,
    "only complete, anchored committed manifest bytes may be returned to the independent content gate");
  const result = await f.cas.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes });
  assert.deepEqual(result, { status: "committed", replay: true },
    "lost commit ACK cannot produce a second revision");
  await assert.rejects(f.cas.commit({ receipt: f.ticket,
    manifestBytes: Buffer.from("substitution") }), /CAS_CONFLICT/);
  const nonce = crypto.randomBytes(32);
  const proof = await f.cas.getTerminalProof({ query: f.query, nonce });
  const verified = await inspectVerifiedCasStatusProofV1({
    raw: proof, query: f.query, nonce, pinned: f.pinnedStatus,
  });
  assert.equal(verified.terminal_status, "committed");
  f.setTime(f.operation.expires_at + 3600);
  assert.deepEqual(await f.cas.registerReservation({ receipt: f.ticket }), { status: "committed" },
    "a lost register acknowledgement must be repeatable even after expiry without reopening");
  await assert.rejects(inspectVerifiedCasStatusProofV1({
    raw: proof, query: f.query, nonce: crypto.randomBytes(32), pinned: f.pinnedStatus,
  }), /AUTHORITY_PROOF_INVALID/);
  assert.equal((await f.witness.resolve({ scope: f.operation })).status, "committed");
  const head = await z.decodeDeterministic(await f.witness.freshHead({
    scope: f.operation, nonce: crypto.randomBytes(32),
  }));
  assert.equal(head.status, "committed");
  assert.deepEqual(Buffer.from(head.current_manifest_digest), f.operation.proposed_manifest_digest);
  f.cas.close();
  const reopened = f.openCas({ bootstrapNew: false });
  const afterRestart = await reopened.getTerminalProof({ query: f.query, nonce: crypto.randomBytes(32) });
  assert.equal((await z.decodeDeterministic(afterRestart)).terminal_status, "committed");
  assert.deepEqual(await reopened.getCommittedManifest({ scope }), f.manifestBytes);
});

test("CAS manifest reads cannot hide an anchored commit by deleting its operation row", async (t) => {
  const f = await setup(t);
  const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
    .map((field) => [field, f.operation[field]]));
  await f.cas.registerReservation({ receipt: f.ticket });
  await f.cas.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes });
  assert.deepEqual(await f.cas.getCommittedManifest({ scope }), f.manifestBytes);
  const attack = new Database(f.casFilename);
  attack.prepare("DELETE FROM cas_operation WHERE reservation_id=?")
    .run(f.operation.reservation_id);
  attack.close();
  await assert.rejects(f.cas.getCommittedManifest({ scope }),
    /CAS_LEDGER_ROLLBACK|CAS_LEDGER_CORRUPT/);
});

test("CAS requires a durable final fence after expiry and rejects delayed commit after restart", async (t) => {
  const f = await setup(t);
  await f.cas.registerReservation({ receipt: f.ticket });
  f.setTime(f.operation.expires_at + 29);
  await assert.rejects(f.cas.getTerminalProof({ query: f.query, nonce: crypto.randomBytes(32) }),
    /CAS_UNRESOLVED/);
  f.setTime(f.operation.expires_at + 30);
  const nonce = crypto.randomBytes(32);
  const proof = await f.cas.getTerminalProof({ query: f.query, nonce });
  assert.equal((await inspectVerifiedCasStatusProofV1({
    raw: proof, query: f.query, nonce, pinned: f.pinnedStatus,
  })).terminal_status, "not-committed-final");
  await assert.rejects(f.cas.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes }),
    /CAS_FENCED/);
  assert.equal((await f.witness.resolve({ scope: f.operation })).status, "cancelled");
  f.cas.close();
  const reopened = f.openCas({ bootstrapNew: false });
  const proofAfterRestart = await reopened.getTerminalProof({
    query: f.query, nonce: crypto.randomBytes(32),
  });
  assert.equal((await z.decodeDeterministic(proofAfterRestart)).terminal_status, "not-committed-final");
  assert.deepEqual(await reopened.registerReservation({ receipt: f.ticket }),
    { status: "not-committed-final" }, "exact replay must disclose final fence, never reopen");
  await assert.rejects(reopened.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes }),
    /CAS_FENCED/);
  await assert.rejects(f.witness.reserve({ ...f.operation,
    reservation_id: crypto.randomBytes(16), operation_id: crypto.randomBytes(16),
    expires_at: f.operation.expires_at + 120,
  }), /WITNESS_TOMBSTONED/);
});

test("identity mismatch, changed ticket and status query substitution fail closed", async (t) => {
  const f = await setup(t);
  await assert.rejects(f.cas.registerReservation({ receipt: crypto.randomBytes(250) }));
  await f.cas.registerReservation({ receipt: f.ticket });
  await assert.rejects(f.cas.getTerminalProof({
    query: { ...f.query, proposed_manifest_digest: crypto.randomBytes(32) },
    nonce: crypto.randomBytes(32),
  }), /CAS_UNRESOLVED/);
  f.cas.close();
  assert.throws(() => f.openCas({ bootstrapNew: false,
    statusPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey,
  }), /CAS_IDENTITY_MISMATCH/);
});

test("status authority refuses committed proof when its durable transition has been deleted", async (t) => {
  const f = await setup(t);
  await f.cas.registerReservation({ receipt: f.ticket });
  await f.cas.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes });
  const attacker = new Database(f.casFilename);
  attacker.prepare("DELETE FROM cas_transition").run();
  attacker.close();
  await assert.rejects(f.cas.getTerminalProof({
    query: f.query, nonce: crypto.randomBytes(32),
  }), /CAS_LEDGER_CORRUPT/, "a tampered CAS state must not be re-signed as committed");
});

test("cancelled genesis cannot be re-created by another validly signed witness ticket", async (t) => {
  const f = await setup(t);
  await f.cas.registerReservation({ receipt: f.ticket });
  f.setTime(f.operation.expires_at + 31);
  await f.cas.getTerminalProof({ query: f.query, nonce: crypto.randomBytes(32) });
  const original = await z.decodeDeterministic(f.ticket);
  const { signature: _oldSignature, ...unsigned } = original;
  const next = {
    ...unsigned,
    reservation_id: crypto.randomBytes(16), operation_id: crypto.randomBytes(16),
    request_digest: crypto.randomBytes(32), proposed_manifest_digest: crypto.randomBytes(32),
    expires_at: f.operation.expires_at + 180,
  };
  const signature = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/recovery-witness-reservation/v1\0", "ascii"),
    Buffer.from(await z.encodeDeterministic(next)),
  ]), f.witnessPrivateKey);
  const newReceipt = Buffer.from(await z.encodeDeterministic({ ...next, signature }));
  await assert.rejects(f.cas.registerReservation({ receipt: newReceipt }),
    /CAS_TOMBSTONED|CAS_LEDGER_ROLLBACK/);
});

test("database writer cannot fabricate a coherent committed CAS result and make authority sign it", async (t) => {
  const f = await setup(t);
  await f.cas.registerReservation({ receipt: f.ticket });
  const scope = f.operation.account_id.toString("hex") + ":"
    + f.operation.compartment_id.byteLength + ":"
    + f.operation.compartment_id.toString("hex");
  const writer = new Database(f.casFilename);
  writer.transaction(() => {
    writer.prepare("INSERT INTO cas_transition VALUES (?,?,?,?)")
      .run(scope, 1, f.operation.proposed_manifest_digest, f.manifestBytes);
    writer.prepare("UPDATE cas_scope SET revision=?, digest=?, pending_id=NULL, transition_count=1, history_bytes=? WHERE scope_key=?")
      .run(1, f.operation.proposed_manifest_digest, f.manifestBytes.length, scope);
    writer.prepare("UPDATE cas_operation SET status='committed', committed_manifest=? WHERE reservation_id=?")
      .run(f.manifestBytes, f.operation.reservation_id);
  })();
  writer.close();
  await assert.rejects(f.cas.getTerminalProof({
    query: f.query, nonce: crypto.randomBytes(32),
  }), /CAS_LEDGER_CORRUPT/, "unsigned forged committed rows must not be re-signed as authority proof");
  await assert.rejects(f.witness.resolve({ scope: f.operation }),
    /WITNESS_UNRESOLVED/, "independent witness must not accept fabricated CAS commit");
});

test("database writer cannot fabricate terminal no-commit without a durable authority seal", async (t) => {
  const f = await setup(t);
  await f.cas.registerReservation({ receipt: f.ticket });
  const writer = new Database(f.casFilename);
  writer.transaction(() => {
    writer.prepare("UPDATE cas_operation SET status='not-committed-final' WHERE reservation_id=?")
      .run(f.operation.reservation_id);
    writer.prepare("UPDATE cas_scope SET pending_id=NULL").run();
  })();
  writer.close();
  await assert.rejects(f.cas.getTerminalProof({
    query: f.query, nonce: crypto.randomBytes(32),
  }), /CAS_LEDGER_CORRUPT/, "unsigned forged terminal fence must not close witness");
  await assert.rejects(f.cas.registerReservation({ receipt: f.ticket }),
    /CAS_LEDGER_CORRUPT/, "register replay must never echo forged terminal cancellation");
});

test("lost register ACK cannot be forged into an unsigned committed CAS status", async (t) => {
  const f = await setup(t);
  await f.cas.registerReservation({ receipt: f.ticket });
  const db = new Database(f.casFilename);
  db.prepare("UPDATE cas_operation SET status='committed' WHERE reservation_id=?")
    .run(f.operation.reservation_id);
  db.close();
  await assert.rejects(f.cas.registerReservation({ receipt: f.ticket }),
    /CAS_LEDGER_CORRUPT/, "replay must authenticate durable terminal status before replying");
});

test("rollback of an authentic committed CAS seal cannot regenerate contradictory no-commit proof", async (t) => {
  const f = await setup(t);
  await f.cas.registerReservation({ receipt: f.ticket });
  await f.cas.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes });
  const db = new Database(f.casFilename);
  db.transaction(() => {
    db.prepare("UPDATE cas_operation SET status='pending',committed_manifest=NULL,terminal_seal=NULL WHERE reservation_id=?")
      .run(f.operation.reservation_id);
    db.prepare("UPDATE cas_scope SET revision=NULL,digest=NULL,pending_id=?,transition_count=0,history_bytes=0")
      .run(f.operation.reservation_id);
    db.prepare("DELETE FROM cas_transition").run();
  })();
  db.close();
  f.setTime(f.operation.expires_at + 31);
  await assert.rejects(f.cas.getTerminalProof({
    query: f.query, nonce: crypto.randomBytes(32),
  }), /CAS_LEDGER_ROLLBACK/, "signed terminal outcome must survive SQLite-only rollback");
  await assert.rejects(f.witness.resolve({ scope: f.operation }), /WITNESS_UNRESOLVED/);
  await assert.rejects(f.cas.registerReservation({ receipt: f.ticket }),
    /CAS_LEDGER_ROLLBACK/, "a rolled-back row cannot acknowledge pending state");
  f.cas.close();
  const afterRestart = f.openCas({ bootstrapNew: false });
  await assert.rejects(afterRestart.getTerminalProof({
    query: f.query, nonce: crypto.randomBytes(32),
  }), /CAS_LEDGER_ROLLBACK/, "external terminal continuity persists through signer restart");
});

test("CAS refuses bootstrap on a missing or tampered external terminal anchor", async (t) => {
  const f = await setup(t);
  await f.cas.registerReservation({ receipt: f.ticket });
  await f.cas.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes });
  f.cas.close();
  const anchor = f.casOptions.anchorPath;
  const content = fs.readFileSync(anchor);
  // Append-only continuity record is signed, not merely a JSON checklist.
  const tampered = content.toString("utf8").replace('"status":"committed"',
    '"status":"not-committed-final"');
  assert.notEqual(tampered, content.toString("utf8"));
  fs.writeFileSync(anchor, tampered);
  assert.throws(() => f.openCas({ bootstrapNew: false }), /CAS_ANCHOR_INVALID/);
  fs.writeFileSync(anchor, content);
  fs.unlinkSync(anchor);
  assert.throws(() => f.openCas({ bootstrapNew: false }), /CAS_ANCHOR_STATE_MISMATCH/);
});

test("crash after SQLite commit but before anchor finalization safely reconciles authentic lost ACK", async (t) => {
  const f = await setup(t);
  await f.cas.registerReservation({ receipt: f.ticket });
  f.cas.anchor.append = async () => { throw new Error("SIMULATED_CRASH_AFTER_SQLITE_COMMIT"); };
  await assert.rejects(f.cas.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes }),
    /SIMULATED_CRASH_AFTER_SQLITE_COMMIT/);
  f.cas.close();
  const recovered = f.openCas({ bootstrapNew: false });
  assert.deepEqual(await recovered.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes }),
    { status: "committed", replay: true });
  const proof = await recovered.getTerminalProof({ query: f.query, nonce: crypto.randomBytes(32) });
  assert.equal((await z.decodeDeterministic(proof)).terminal_status, "committed");
});

test("crash then SQLite-only rollback cannot turn a prepared genuine commit into cancellation", async (t) => {
  const f = await setup(t);
  await f.cas.registerReservation({ receipt: f.ticket });
  f.cas.anchor.append = async () => { throw new Error("CRASH_BEFORE_TERMINAL_ANCHOR"); };
  await assert.rejects(f.cas.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes }),
    /CRASH_BEFORE_TERMINAL_ANCHOR/);
  f.cas.close();
  const db = new Database(f.casFilename);
  db.transaction(() => {
    db.prepare("UPDATE cas_operation SET status='pending',committed_manifest=NULL,terminal_seal=NULL WHERE reservation_id=?")
      .run(f.operation.reservation_id);
    db.prepare("UPDATE cas_scope SET revision=NULL,digest=NULL,pending_id=?,transition_count=0,history_bytes=0")
      .run(f.operation.reservation_id);
    db.prepare("DELETE FROM cas_transition").run();
  })();
  db.close();
  const reopened = f.openCas({ bootstrapNew: false });
  f.setTime(f.operation.expires_at + 31);
  await assert.rejects(reopened.getTerminalProof({
    query: f.query, nonce: crypto.randomBytes(32),
  }), /CAS_LEDGER_ROLLBACK/, "precommitted external intent forbids terminal reversal after DB rollback");
});

test("expiry crossing between signed commit preparation and SQLite transaction never strands a legitimate reservation", async (t) => {
  const f = await setup(t);
  await f.cas.registerReservation({ receipt: f.ticket });
  const prepare = f.cas.anchor.prepare.bind(f.cas.anchor);
  f.cas.anchor.prepare = (...args) => {
    const result = prepare(...args);
    f.setTime(f.operation.expires_at + 31);
    return result;
  };
  const outcome = await f.cas.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes });
  assert.equal(outcome.status, "committed");
  f.cas.close();
  const resumed = f.openCas({ bootstrapNew: false });
  const proof = await resumed.getTerminalProof({ query: f.query, nonce: crypto.randomBytes(32) });
  assert.equal((await z.decodeDeterministic(proof)).terminal_status, "committed");
});

test("a valid prepared commitment interrupted before SQLite write can be retried after expiry", async (t) => {
  const f = await setup(t);
  await f.cas.registerReservation({ receipt: f.ticket });
  const prepare = f.cas.anchor.prepare.bind(f.cas.anchor);
  f.cas.anchor.prepare = (...args) => {
    prepare(...args);
    throw new Error("CRASH_AFTER_PREPARE_BEFORE_DB");
  };
  await assert.rejects(f.cas.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes }),
    /CRASH_AFTER_PREPARE_BEFORE_DB/);
  f.cas.close();
  f.setTime(f.operation.expires_at + 31);
  const resumed = f.openCas({ bootstrapNew: false });
  assert.deepEqual(await resumed.commit({ receipt: f.ticket, manifestBytes: f.manifestBytes }),
    { status: "committed", replay: false });
  assert.equal((await z.decodeDeterministic(await resumed.getTerminalProof({
    query: f.query, nonce: crypto.randomBytes(32),
  }))).terminal_status, "committed");
});
