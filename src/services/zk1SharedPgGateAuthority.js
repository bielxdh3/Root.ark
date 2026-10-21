"use strict";

// Shared PostgreSQL reference GateAuthority + PostgreSQL ciphertext provider.
// One real transactional row lock orders START/QUIESCE/FINISH and each physical
// PostgreSQL chunk WRITE operation, across processes/hosts sharing the PRIMARY.
// Network egress is deliberately NOT implemented: holding a PostgreSQL row
// lock while asynchronously sending bytes is NOT safe on connection loss.
// Other providers need their own physically-enforced fencing adapter.
const crypto = require("node:crypto");
const { verifyZk1PhysicalStopProof } =
  require("../crypto/rootark-zk-physical-stop-proof-v1");

// Only the local operator invokes this factory. The returned token carries no
// mutable host/key/scope records; their deep snapshots live in this closure.
// The token must never be accepted from HTTP, a manifest, or an IPC worker.
const pinnedStopPolicySnapshots = new WeakMap();

function deny(code = "ZK_GATE_DENIED") {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function bytes(value, length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length !== length) deny();
  return Buffer.from(value);
}
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== keys.length
    || keys.some((k) => !Object.hasOwn(value, k))) deny();
}
function scopeOf(scope) {
  exact(scope, ["account_id", "compartment_id", "keyring_id"]);
  const account = bytes(scope.account_id, 16);
  const compartment = scope.compartment_id;
  if ((!Buffer.isBuffer(compartment) && !(compartment instanceof Uint8Array))
    || compartment.length < 1 || compartment.length > 128) deny();
  const part = Buffer.from(compartment);
  return Object.freeze({
    key: account.toString("hex") + ":" + part.length.toString(16)
      + ":" + part.toString("hex"),
    keyringId: bytes(scope.keyring_id, 16),
  });
}
function headMatches(row, expected) {
  return row && row.keyring_id.equals(expected.keyringId);
}
function hostPublicKeyDer(key) {
  if (!(key instanceof crypto.KeyObject) || key.type !== "public"
    || key.asymmetricKeyType !== "ed25519") deny("ZK_GATE_CONFIG_INVALID");
  return Buffer.from(key.export({ type: "spki", format: "der" })).toString("base64");
}
function createZk1OperatorPinnedStopHostPolicy(config) {
  exact(config, ["hosts"]);
  if (!Array.isArray(config.hosts) || config.hosts.length < 2
    || config.hosts.length > 128) deny("ZK_GATE_CONFIG_INVALID");
  const ids = new Set();
  const keys = new Set();
  const hosts = config.hosts.map((entry) => {
    exact(entry, ["hostKeyId", "hostPublicKey", "scopes", "status"]);
    const id = bytes(entry.hostKeyId, 16).toString("hex");
    const keyDer = hostPublicKeyDer(entry.hostPublicKey);
    if (ids.has(id) || keys.has(keyDer)
      || !["active", "verify-only", "revoked"].includes(entry.status)
      || !Array.isArray(entry.scopes) || entry.scopes.length < 1
      || entry.scopes.length > 1024) deny("ZK_GATE_CONFIG_INVALID");
    ids.add(id);
    keys.add(keyDer);
    const allowed = entry.scopes.map((scope) => {
      const s = scopeOf(scope);
      return s.key + ":" + s.keyringId.toString("hex");
    });
    if (new Set(allowed).size !== allowed.length) deny("ZK_GATE_CONFIG_INVALID");
    return Object.freeze({ id, keyDer, status: entry.status,
      allowed: Object.freeze(allowed) });
  });
  const token = Object.freeze(Object.create(null));
  pinnedStopPolicySnapshots.set(token, Object.freeze(hosts));
  return token;
}
function positive(n) {
  if (!Number.isSafeInteger(n) || n < 1) deny();
  return n;
}
function worker(input) {
  const base = ["scope", "workerId", "principal", "action", "objectId",
    "revision", "digest"];
  const supervised = Boolean(input && Object.hasOwn(input, "processEpoch"));
  exact(input, supervised ? [...base, "hostKeyId", "processEpoch", "processPid"] : base);
  const scoped = scopeOf(input.scope);
  if (typeof input.principal !== "string" || input.principal.length < 1
    || input.principal.length > 128 || /[\u0000-\u001f\u007f]/.test(input.principal)
    || !["get", "put"].includes(input.action)
    || typeof input.objectId !== "string" || !/^[a-zA-Z0-9_-]{22}$/.test(input.objectId)
    || Buffer.from(input.objectId, "base64url").toString("base64url") !== input.objectId) deny();
  const process = supervised ? {
    hostKeyId: bytes(input.hostKeyId, 16),
    processEpoch: bytes(input.processEpoch, 16),
    processPid: positive(input.processPid),
  } : null;
  if (process && process.processPid > 0x7fffffff) deny();
  return { ...scoped, workerId: bytes(input.workerId, 16), principal: input.principal,
    action: input.action, objectId: input.objectId, revision: positive(input.revision),
    digest: bytes(input.digest, 32), ...(process || {}) };
}
function matchAdmission(record, input, requireProcess = false) {
  return record && record.worker_id.equals(input.workerId)
    && record.principal === input.principal && record.action === input.action
    && record.object_id === input.objectId && Number(record.revision) === input.revision
    && record.digest.equals(input.digest) && record.scope_key === input.key
    && (!requireProcess || (
      input.hostKeyId && input.processEpoch && input.processPid
      && record.host_key_id?.equals(input.hostKeyId)
      && record.process_epoch?.equals(input.processEpoch)
      && Number(record.process_pid) === input.processPid));
}

class Zk1SharedPgGateAuthority {
  #stopHostPolicy;
  constructor({ pool, stopPinned, stopHostPolicy } = {}) {
    if (!pool || typeof pool.connect !== "function") deny("ZK_GATE_CONFIG_INVALID");
    this.pool = pool;
    if (stopHostPolicy !== undefined) {
      if (stopPinned !== undefined || !pinnedStopPolicySnapshots.has(stopHostPolicy)) {
        deny("ZK_GATE_CONFIG_INVALID");
      }
      this.#stopHostPolicy = pinnedStopPolicySnapshots.get(stopHostPolicy);
    }
    if (stopPinned !== undefined) {
      exact(stopPinned, ["hostKeyId", "hostPublicKey"]);
      if (!(stopPinned.hostPublicKey instanceof crypto.KeyObject)
        || stopPinned.hostPublicKey.type !== "public"
        || stopPinned.hostPublicKey.asymmetricKeyType !== "ed25519") deny("ZK_GATE_CONFIG_INVALID");
      this.stopPinned = Object.freeze({
        hostKeyId: bytes(stopPinned.hostKeyId, 16),
        hostPublicKey: stopPinned.hostPublicKey,
      });
    }
  }
  #policyHost(hostKeyId, scope, allowVerifyOnly = false) {
    if (!this.#stopHostPolicy || !hostKeyId) return null;
    const id = bytes(hostKeyId, 16).toString("hex");
    const host = this.#stopHostPolicy.find((item) => item.id === id);
    if (!host || (host.status !== "active"
      && !(allowVerifyOnly && host.status === "verify-only"))) return null;
    if (scope) {
      const s = scopeOf(scope);
      if (!host.allowed.includes(s.key + ":" + s.keyringId.toString("hex"))) return null;
    }
    return host;
  }
  // Read-only eligibility check for trusted local supervisor/recorder wiring.
  // Scope admission is enforced separately under the authoritative head lock.
  allowsActivePinnedStopHost(hostKeyId, hostPublicKey) {
    if (!this.#stopHostPolicy) return false;
    try {
      const entry = this.#policyHost(hostKeyId);
      return Boolean(entry && entry.keyDer === hostPublicKeyDer(hostPublicKey));
    } catch (_) { return false; }
  }

  async #verifyPhysicalStop(c, admission, scope) {
    // PostgreSQL cannot verify Ed25519 with its built-in SQL functions.
    // Even a separately provisioned STOP SQL role could write random wire
    // bytes and matching sha256 into the receipt table. Verify the pinned
    // independent host's actual signature in the trusted gate process as
    // defense in depth; the DB trigger still independently rejects gate-only
    // FINISHED attempts without a durable STOP record.
    if ((!this.stopPinned && !this.#stopHostPolicy) || !admission?.host_key_id
      || !admission?.process_epoch || !Number.isSafeInteger(Number(admission.process_pid))) {
      deny("ZK_GATE_STOP_PROOF_INVALID");
    }
    const trusted = this.#stopHostPolicy
      ? this.#policyHost(admission.host_key_id, scope, true) : null;
    if (this.#stopHostPolicy && !trusted) deny("ZK_GATE_STOP_PROOF_INVALID");
    const result = await c.query(`SELECT signed_proof,proof_digest,stopped_at
      FROM zk1_gate.physical_stop_receipt WHERE admission_id=$1`, [admission.id]);
    const receipt = result.rows[0];
    if (result.rowCount !== 1 || !receipt) deny("ZK_GATE_STOP_PROOF_INVALID");
    try {
      // The independent STOP recorder checked freshness at its original
      // durable INSERT. On later FINISH/recovery the trusted gate checks the
      // *signed historical fact*, not an arbitrary age threshold that would
      // strand a valid worker after restart or a delayed ACK.
      const verified = await verifyZk1PhysicalStopProof({
        signedProof: receipt.signed_proof,
        hostKeyId: trusted ? Buffer.from(trusted.id, "hex") : this.stopPinned.hostKeyId,
        hostPublicKey: trusted ? crypto.createPublicKey({
          key: Buffer.from(trusted.keyDer, "base64"), format: "der", type: "spki",
        }) : this.stopPinned.hostPublicKey,
        expected: { scope, admissionId: admission.id, workerId: admission.worker_id,
          generation: Number(admission.generation), principal: admission.principal,
          processEpoch: admission.process_epoch, processPid: Number(admission.process_pid) },
        nowSeconds: Number(receipt.stopped_at),
      });
      if (!receipt.proof_digest.equals(verified.proofDigest)
        || !admission.host_key_id.equals(verified.hostKeyId)) {
        deny("ZK_GATE_STOP_PROOF_INVALID");
      }
    } catch (_) { deny("ZK_GATE_STOP_PROOF_INVALID"); }
  }

  async transaction(operation) {
    let connection;
    try {
      connection = await this.pool.connect();
      await connection.query("BEGIN");
      const result = await operation(connection);
      await connection.query("COMMIT");
      return result;
    } catch (error) {
      if (connection) {
        try { await connection.query("ROLLBACK"); } catch (_) { /* fail closed */ }
      }
      if (error?.code && /^ZK_GATE_/.test(error.code)) throw error;
      deny("ZK_GATE_UNAVAILABLE");
    } finally {
      if (connection) connection.release();
    }
  }

  async lockedHead(client, scope) {
    const { rows } = await client.query(
      "SELECT * FROM zk1_gate.head WHERE scope_key=$1 FOR UPDATE", [scope.key]);
    const head = rows[0];
    if (!headMatches(head, scope)) deny("ZK_GATE_UNAVAILABLE");
    return head;
  }

  // Immutable, operator-provisioned scope policy. HTTPS must never treat a
  // local supervisor child as the remote HTTP/PG data-plane executor.
  async requiresTrustedLocalStop(scope) {
    const s = scopeOf(scope);
    try {
      const { rows, rowCount } = await this.pool.query(`SELECT keyring_id,require_stop_proof
        FROM zk1_gate.head WHERE scope_key=$1`, [s.key]);
      if (rowCount !== 1 || !headMatches(rows[0], s)) deny();
      return rows[0].require_stop_proof === true;
    } catch (_) { deny("ZK_GATE_UNAVAILABLE"); }
  }

  async beginIoAdmission(input) {
    const io = worker(input);
    return this.transaction(async (c) => {
      const head = await this.lockedHead(c, io);
      if (head.require_stop_proof !== Boolean(io.hostKeyId)) deny();
      if (head.require_stop_proof && this.#stopHostPolicy
        && !this.#policyHost(io.hostKeyId, input.scope)) deny();
      const found = await c.query(
        "SELECT * FROM zk1_gate.admission WHERE scope_key=$1 AND worker_id=$2",
        [io.key, io.workerId]);
      const existing = found.rows[0];
      if (existing) {
        if (!matchAdmission(existing, io, Boolean(head.require_stop_proof))
          || existing.state === "FINISHED") deny();
        return { admissionId: Buffer.from(existing.id),
          generation: Number(existing.generation),
          proceed: head.phase === "OPEN" && existing.state === "ACTIVE"
            && Number(head.generation) === Number(existing.generation) };
      }
      if (head.phase !== "OPEN" || Number(head.revision) !== io.revision
        || !head.digest.equals(io.digest)) deny();
      const admissionId = crypto.randomBytes(16);
      await c.query(`INSERT INTO zk1_gate.admission
        (id,scope_key,worker_id,principal,action,object_id,revision,digest,
          generation,host_key_id,process_epoch,process_pid,state)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'ACTIVE')`,
      [admissionId, io.key, io.workerId, io.principal, io.action,
        io.objectId, io.revision, io.digest, head.generation,
        io.hostKeyId || null, io.processEpoch || null, io.processPid || null]);
      return { admissionId, generation: Number(head.generation), proceed: true };
    });
  }

  async #authorizeStep(input, effect) {
    if (typeof effect !== "function") deny();
    exact(input, ["scope", "workerId", "principal", "action", "objectId",
      "revision", "digest", "admissionId", "generation"]);
    const io = worker({ scope: input.scope, workerId: input.workerId,
      principal: input.principal, action: input.action, objectId: input.objectId,
      revision: input.revision, digest: input.digest });
    const admissionId = bytes(input.admissionId, 16);
    const generation = positive(input.generation);
    // IMPORTANT: callback is PRIVATE to this class and may ONLY execute SQL
    // effects using the very same PostgreSQL transaction. Never use it for
    // filesystem/cloud writes, socket writes or other external side effects:
    // PostgreSQL may lose the lock on connection failure before JS learns it.
    return this.transaction(async (c) => {
      const head = await this.lockedHead(c, io);
      if (head.phase !== "OPEN" || Number(head.generation) !== generation
        || Number(head.revision) !== io.revision || !head.digest.equals(io.digest)) deny();
      const found = await c.query("SELECT * FROM zk1_gate.admission WHERE id=$1", [admissionId]);
      const entry = found.rows[0];
      if (!matchAdmission(entry, io) || !entry.id.equals(admissionId)
        || entry.state !== "ACTIVE" || Number(entry.generation) !== generation) deny();
      return effect(c, io);
    });
  }

  async putCiphertextChunk(input, chunkIndex, ciphertext) {
    const blob = ciphertext && (Buffer.isBuffer(ciphertext) || ciphertext instanceof Uint8Array)
      ? Buffer.from(ciphertext) : null;
    if (!blob || blob.length < 1 || blob.length > 4 * 1024 * 1024
      || !Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex > 0x7fffffff
      || input?.action !== "put") deny();
    return this.#authorizeStep(input, async (c, io) => {
      const inserted = await c.query(`INSERT INTO zk1_gate.ciphertext_chunk
        (scope_key,object_id,chunk_index,ciphertext) VALUES($1,$2,$3,$4)
        ON CONFLICT DO NOTHING RETURNING chunk_index`,
      [io.key, io.objectId, chunkIndex, blob]);
      if (inserted.rowCount === 1) return { stored: true };
      const old = await c.query(`SELECT ciphertext FROM zk1_gate.ciphertext_chunk
        WHERE scope_key=$1 AND object_id=$2 AND chunk_index=$3`,
      [io.key, io.objectId, chunkIndex]);
      if (old.rowCount !== 1 || !old.rows[0].ciphertext.equals(blob)) deny("ZK_GATE_CHUNK_CONFLICT");
      return { stored: false };
    });
  }

  async beginQuiesce({ scope, operationId, reservationId, revision, digest }) {
    const s = scopeOf(scope);
    const op = bytes(operationId, 16);
    const res = bytes(reservationId, 16);
    const r = positive(revision);
    const d = bytes(digest, 32);
    return this.transaction(async (c) => {
      const head = await this.lockedHead(c, s);
      if (Number(head.revision) !== r || !head.digest.equals(d)) deny();
      if (head.phase !== "OPEN") {
        if (!["QUIESCING", "PENDING"].includes(head.phase) || !head.operation_id.equals(op)
          || !head.reservation_id.equals(res)) deny();
      } else {
        await c.query(`UPDATE zk1_gate.head SET phase='QUIESCING',
          generation=generation+1,operation_id=$2,reservation_id=$3 WHERE scope_key=$1`,
        [s.key, op, res]);
        await c.query(`UPDATE zk1_gate.admission SET state='STOP_REQUESTED'
          WHERE scope_key=$1 AND state='ACTIVE'`, [s.key]);
      }
      const count = await c.query(`SELECT COUNT(*)::int AS active FROM zk1_gate.admission
        WHERE scope_key=$1 AND state<>'FINISHED'`, [s.key]);
      return { state: head.phase === "PENDING" ? "PENDING" : "QUIESCING", generation: Number(head.generation) +
        (head.phase === "OPEN" ? 1 : 0), activeCount: count.rows[0].active };
    });
  }

  async finishIoAdmission({ scope, admissionId, workerId, principal }) {
    const s = scopeOf(scope);
    const id = bytes(admissionId, 16);
    const worker = bytes(workerId, 16);
    if (typeof principal !== "string" || principal.length < 1 || principal.length > 128) deny();
    return this.transaction(async (c) => {
      const head = await this.lockedHead(c, s);
      const found = await c.query("SELECT * FROM zk1_gate.admission WHERE id=$1", [id]);
      const row = found.rows[0];
      if (!row || row.scope_key !== s.key || !row.worker_id.equals(worker)
        || row.principal !== principal) deny();
      if (head.require_stop_proof) await this.#verifyPhysicalStop(c, row, scope);
      if (row.state !== "FINISHED") {
        await c.query("UPDATE zk1_gate.admission SET state='FINISHED' WHERE id=$1", [id]);
      }
      return { status: "FINISHED" };
    });
  }

  async markPending({ scope, operationId, reservationId }) {
    const s = scopeOf(scope);
    const op = bytes(operationId, 16);
    const res = bytes(reservationId, 16);
    return this.transaction(async (c) => {
      const head = await this.lockedHead(c, s);
      if (!["QUIESCING", "PENDING"].includes(head.phase) || !head.operation_id.equals(op)
        || !head.reservation_id.equals(res)) deny();
      if (head.require_stop_proof) {
        const admitted = await c.query("SELECT * FROM zk1_gate.admission WHERE scope_key=$1", [s.key]);
        // A compromised STOP SQL login may have inserted a fabricated row.
        // Revalidate every immutable STOP proof before trusting FINISHED or
        // a previous PENDING state, including after process restart.
        for (const row of admitted.rows) {
          if (row.state !== "FINISHED") deny("ZK_GATE_DRAIN_INCOMPLETE");
          await this.#verifyPhysicalStop(c, row, scope);
        }
      }
      if (head.phase === "PENDING") return { status: "PENDING", generation: Number(head.generation) };
      const active = await c.query(`SELECT COUNT(*)::int AS n FROM zk1_gate.admission
        WHERE scope_key=$1 AND state<>'FINISHED'`, [s.key]);
      if (active.rows[0].n !== 0) deny("ZK_GATE_DRAIN_INCOMPLETE");
      await c.query("UPDATE zk1_gate.head SET phase='PENDING' WHERE scope_key=$1", [s.key]);
      return { status: "PENDING", generation: Number(head.generation) };
    });
  }
}

module.exports = { Zk1SharedPgGateAuthority, createZk1OperatorPinnedStopHostPolicy };
