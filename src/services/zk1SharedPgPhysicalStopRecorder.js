"use strict";

// Independent physical STOP evidence recorder. Its PostgreSQL credentials
// MUST be distinct from the isolated gate runtime; this role cannot mutate
// phase/generation or ciphertext and cannot be run inside the web app.
// Cryptographic verification proves the trusted host supervisor made this
// statement. OS exit and provider-stop truth remain the SUPERVISOR's duty.
const crypto = require("node:crypto");
const { verifyZk1PhysicalStopProof } =
  require("../crypto/rootark-zk-physical-stop-proof-v1");
// An instanceof check proves only JS class shape. Only the factory below
// verifies the independently restricted STOP SQL identity before use.
const preflightedRecorders = new WeakSet();

function stopError(code = "ZK_STOP_LEDGER_UNAVAILABLE") {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function bytes(value, length, max = length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length < length || value.length > max) stopError();
  return Buffer.from(value);
}
function scopeKey(scope) {
  if (!scope || typeof scope !== "object" || Array.isArray(scope)
    || Reflect.ownKeys(scope).length !== 3
    || ["account_id", "compartment_id", "keyring_id"]
      .some((k) => !Object.hasOwn(scope, k))) stopError();
  const account = bytes(scope.account_id, 16);
  const compartment = bytes(scope.compartment_id, 1, 128);
  return { key: account.toString("hex") + ":" + compartment.length.toString(16)
    + ":" + compartment.toString("hex"),
  keyringId: bytes(scope.keyring_id, 16) };
}
function pgBytesEqual(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length
    && crypto.timingSafeEqual(a, b);
}

async function verifyZk1StopRuntimePool(pool) {
  if (!pool || typeof pool.connect !== "function") stopError("ZK_STOP_RUNTIME_INVALID");
  let c;
  try {
    c = await pool.connect();
    const { rows, rowCount } = await c.query(`SELECT
      session_user AS session_identity, current_user AS active_identity,
      r.rolcanlogin AS login_ok, r.rolsuper AS superuser,
      r.rolcreatedb AS createdb, r.rolcreaterole AS createrole,
      pg_catalog.pg_has_role(current_user, 'zk1_stop_runtime', 'USAGE') AS stop_role,
      pg_catalog.pg_has_role(current_user, 'zk1_gate_runtime', 'USAGE') AS gate_role,
      pg_catalog.pg_has_role(current_user, 'zk1_chunk_writer_runtime', 'USAGE') AS writer_role,
      pg_catalog.pg_has_role(current_user, 'zk1_gate_runtime', 'MEMBER') AS gate_member,
      pg_catalog.pg_has_role(current_user, 'zk1_chunk_writer_runtime', 'MEMBER') AS writer_member,
      pg_catalog.pg_has_role(current_user, 'zk1_gate_runtime', 'SET') AS can_set_gate,
      pg_catalog.pg_has_role(current_user, 'zk1_chunk_writer_runtime', 'SET') AS can_set_writer,
      pg_catalog.has_schema_privilege(current_user,'zk1_gate','USAGE') AS schema_use,
      pg_catalog.has_schema_privilege(current_user,'zk1_gate','CREATE') AS schema_create,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.physical_stop_receipt',
        'signed_proof','INSERT') AS can_record_stop,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.head',
        'phase','UPDATE') AS can_update_phase,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.admission',
        'state','UPDATE') AS can_update_worker,
      pg_catalog.has_column_privilege(current_user,'zk1_gate.ciphertext_chunk',
        'ciphertext','INSERT') AS can_write_ciphertext,
      pg_catalog.has_table_privilege(current_user,'zk1_gate.physical_stop_receipt',
        'DELETE') AS can_delete_stop
      FROM pg_catalog.pg_roles AS r WHERE r.rolname=current_user`);
    const row = rows?.[0];
    if (rowCount !== 1 || !row
      || row.session_identity !== row.active_identity
      || row.active_identity === "zk1_stop_runtime"
      || row.login_ok !== true || row.superuser !== false
      || row.createdb !== false || row.createrole !== false
      || row.stop_role !== true || row.gate_role !== false
      || row.writer_role !== false || row.gate_member !== false
      || row.writer_member !== false || row.can_set_gate !== false
      || row.can_set_writer !== false
      || row.schema_use !== true || row.schema_create !== false
      || row.can_record_stop !== true || row.can_update_phase !== false
      || row.can_update_worker !== false || row.can_write_ciphertext !== false
      || row.can_delete_stop !== false) stopError("ZK_STOP_RUNTIME_INVALID");
    return Object.freeze({ verified: true, stopRole: row.active_identity });
  } catch (_) { stopError("ZK_STOP_RUNTIME_INVALID"); }
  finally { if (c) c.release(); }
}

class Zk1SharedPgPhysicalStopRecorder {
  constructor({ pool, trustedHostKeyId, trustedHostPublicKey, nowSeconds }) {
    // A verified factory result must not later be redirected to a privileged
    // pool while retaining its private preflight credential brand.
    Object.defineProperty(this, "pool", { value: pool,
      writable: false, configurable: false, enumerable: false });
    this.hostKeyId = bytes(trustedHostKeyId, 16);
    if (!(trustedHostPublicKey instanceof crypto.KeyObject)
      || trustedHostPublicKey.type !== "public"
      || trustedHostPublicKey.asymmetricKeyType !== "ed25519") stopError();
    this.hostPublicKey = trustedHostPublicKey;
    if (typeof nowSeconds !== "function") stopError();
    this.nowSeconds = nowSeconds;
  }

  async record({ signedProof, expected } = {}) {
    // Verify the Ed25519 proof BEFORE touching any live SQL authority.
    const proof = await verifyZk1PhysicalStopProof({ signedProof,
      hostKeyId: this.hostKeyId, hostPublicKey: this.hostPublicKey,
      expected, nowSeconds: this.nowSeconds() });
    const scope = scopeKey(proof.scope);
    let c;
    try {
      c = await this.pool.connect();
      await c.query("BEGIN");
      // PostgreSQL row-lock queries require nominal UPDATE privilege. The
      // separate STOP role can nominally UPDATE only an immutable dummy
      // `stop_lock` column, but the head trigger rejects any UPDATE, even a
      // no-op. This permits a proper FOR UPDATE lock without head mutation.
      const headResult = await c.query(`SELECT keyring_id,phase,require_stop_proof,generation
        FROM zk1_gate.head WHERE scope_key=$1 FOR UPDATE`, [scope.key]);
      const head = headResult.rows[0];
      if (headResult.rowCount !== 1 || !pgBytesEqual(head.keyring_id, scope.keyringId)
        || head.require_stop_proof !== true) stopError();
      // If the STOP ACK was lost *after* the independent proof committed and
      // the gate advanced to PENDING, return the EXACT already-stored proof.
      // Never insert or mutate an admission in this replay path.
      const stored = await c.query(`SELECT signed_proof,proof_digest FROM
        zk1_gate.physical_stop_receipt WHERE admission_id=$1`, [proof.admissionId]);
      if (stored.rowCount !== 0) {
        if (stored.rowCount !== 1
          || !pgBytesEqual(stored.rows[0].signed_proof, proof.signedProof)
          || !pgBytesEqual(stored.rows[0].proof_digest, proof.proofDigest)) stopError();
        await c.query("COMMIT");
        return { status: "STOP_ATTESTED", proofDigest: Buffer.from(proof.proofDigest) };
      }
      if (!["OPEN", "QUIESCING"].includes(head.phase)
        || (head.phase === "OPEN" && BigInt(head.generation) !== BigInt(proof.generation))
        || (head.phase === "QUIESCING"
          && BigInt(head.generation) !== BigInt(proof.generation) + 1n)) stopError();
      const admission = await c.query(`SELECT scope_key,worker_id,principal,generation,state,
        host_key_id,process_epoch,process_pid
        FROM zk1_gate.admission WHERE id=$1`, [proof.admissionId]);
      const row = admission.rows[0];
      if (admission.rowCount !== 1 || !row || row.scope_key !== scope.key
        || !pgBytesEqual(row.worker_id, proof.workerId)
        || row.principal !== proof.principal
        || !pgBytesEqual(row.host_key_id, proof.hostKeyId)
        || !pgBytesEqual(row.process_epoch, proof.processEpoch)
        || BigInt(row.process_pid) !== BigInt(proof.processPid)
        || BigInt(row.generation) !== BigInt(proof.generation)
        || !["ACTIVE", "STOP_REQUESTED"].includes(row.state)) stopError();
      await c.query(`INSERT INTO zk1_gate.physical_stop_receipt
        (admission_id,scope_key,worker_id,generation,host_key_id,
         process_epoch,process_pid,stopped_at,proof_digest,signed_proof)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [proof.admissionId, scope.key, proof.workerId, proof.generation,
        proof.hostKeyId, proof.processEpoch, proof.processPid, proof.stoppedAt,
        proof.proofDigest, proof.signedProof]);
      await c.query("COMMIT");
      return { status: "STOP_ATTESTED", proofDigest: Buffer.from(proof.proofDigest) };
    } catch (error) {
      if (process.env.ROOTARK_ZK1_TEST_PG_URL) {
        process.stderr.write(`STOP_LAB_DIAGNOSTIC ${String(error?.code || "none")}: ${String(error?.message || "none").slice(0, 180)}\n`);
      }
      if (c) { try { await c.query("ROLLBACK"); } catch (_) { /* fail closed */ } }
      stopError();
    } finally { if (c) c.release(); }
  }
}

async function createZk1PhysicalStopRecorder({ pool, trustedHostKeyId,
  trustedHostPublicKey, nowSeconds = () => Math.floor(Date.now() / 1000) } = {}) {
  await verifyZk1StopRuntimePool(pool);
  const recorder = new Zk1SharedPgPhysicalStopRecorder({ pool, trustedHostKeyId,
    trustedHostPublicKey, nowSeconds });
  preflightedRecorders.add(recorder);
  return recorder;
}

function isVerifiedZk1PhysicalStopRecorder(value) {
  return value instanceof Zk1SharedPgPhysicalStopRecorder
    && preflightedRecorders.has(value);
}

module.exports = { verifyZk1StopRuntimePool, createZk1PhysicalStopRecorder,
  Zk1SharedPgPhysicalStopRecorder, isVerifiedZk1PhysicalStopRecorder };
