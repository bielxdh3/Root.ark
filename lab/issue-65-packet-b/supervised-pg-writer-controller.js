"use strict";

// LAB-ONLY operator-side bounded IPC driver. Not exported from production
// runtime, never mounted on HTTPS and not a general SQL execution broker.
// The direct OS child owns the PG socket used for INSERT and its transaction;
// STOP only attests this direct child. NOT provider/cloud/network buffers,
// descendants, multi-host execution or production release authorization.
const { Zk1SharedPgStrictStopOperator } = require("../../src/services/zk1SharedPgStrictStopOperator");

function deny() {
  const e = new Error("ZK_LAB_PG_WRITER_DENIED");
  e.code = e.message;
  throw e;
}
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((f) => !Object.hasOwn(value, f))) deny();
}
function validUrl(raw) {
  if (typeof raw !== "string" || raw.length > 512) deny();
  let url;
  try { url = new URL(raw); } catch (_) { deny(); }
  if (url.protocol !== "postgresql:" || url.hostname !== "127.0.0.1"
    || url.pathname !== "/gatefixture" || !/^[0-9]+$/.test(url.port)
    || !/^zkgatefixture_[a-f0-9]{12}$/.test(decodeURIComponent(url.username))
    || !url.password || url.search || url.hash) deny();
  return raw;
}

class Zk1LabSupervisedPgWriter {
  constructor({ operator, runtimePgUrl } = {}) {
    if (!(operator instanceof Zk1SharedPgStrictStopOperator)) deny();
    this.operator = operator;
    this.pgUrl = validUrl(runtimePgUrl);
    this.session = null;
    this.entry = null;
    this.started = false;
    this.busy = false;
    this.stopping = false;
    this.lastIndex = -1;
    this.heldIndex = null;
    this.heldBytes = null;
  }

  // Exclusive local pre-provisioning. The caller cannot provide host key ID,
  // PID, process epoch, SQL query, admissionId or secret in this interface.
  async begin(io) {
    exact(io, ["scope", "workerId", "principal", "action", "objectId", "revision", "digest"]);
    if (this.started) deny();
    this.started = true;
    this.operator.prepare(io);
    const entry = [...this.operator.entries.values()].find((item) =>
      Buffer.from(item.io.workerId).equals(Buffer.from(io.workerId)));
    if (!entry) deny();
    this.entry = entry;
    // Session storage is keyed by canonical hex, not the IPC token.
    this.session = this.operator.supervisor.sessions.get(
      entry.process.processEpoch.toString("hex"));
    if (!this.session) deny();
    const admitted = await this.operator.beginTrustedLocalAdmission(io);
    if (!admitted.proceed || !entry.bound
      || !entry.bound.admissionId.equals(admitted.admissionId)
      || admitted.generation !== entry.bound.generation) deny();
    const init = { kind: "init", pgUrl: this.pgUrl,
      scope: { account_id: b64(entry.io.scope.account_id),
        compartment_id: b64(entry.io.scope.compartment_id),
        keyring_id: b64(entry.io.scope.keyring_id) },
      workerId: b64(entry.io.workerId), admissionId: b64(admitted.admissionId),
      hostKeyId: b64(entry.process.hostKeyId), processEpoch: b64(entry.process.processEpoch),
      processPid: entry.process.processPid, principal: entry.io.principal,
      action: "put", objectId: entry.io.objectId, revision: entry.io.revision,
      digest: b64(entry.io.digest), generation: admitted.generation };
    const response = await this.#exchange("bootstrapped", init);
    if (response.restrictedRoleVerified !== true || typeof response.inheritedSecrets !== "boolean"
      || response.inheritedSecrets) deny();
    return { admitted, child: this.session.child,
      bootstrap: { restrictedRoleVerified: true, inheritedSecrets: false } };
  }

  async #exchange(wanted, payload) {
    const child = this.session?.child;
    if (!child || !child.connected || this.session.exited || this.session.closed
      || this.session.aborted || child.exitCode !== null || child.signalCode !== null) deny();
    return new Promise((resolve, reject) => {
      const cancel = () => { clearTimeout(timeout); child.off("message", onMessage);
        child.off("close", onClose); child.off("error", onClose); };
      const onClose = () => { cancel(); reject(new Error("ZK_LAB_PG_WRITER_DENIED")); };
      const onMessage = (msg) => {
        if (msg?.kind === "failed") return onClose();
        if (msg?.kind !== wanted) return;
        cancel();
        resolve(msg);
      };
      const timeout = setTimeout(onClose, 4500);
      child.on("message", onMessage);
      child.once("close", onClose);
      child.once("error", onClose);
      try { child.send(payload, (error) => { if (error) onClose(); }); }
      catch (_) { onClose(); }
    });
  }

  async holdChunk(index, bytes) {
    if (!this.entry?.bound || this.stopping || this.busy || !Number.isSafeInteger(index)
      || index <= this.lastIndex || index > 4095
      || (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array))
      || bytes.byteLength < 1 || bytes.byteLength > 4 * 1024 * 1024) deny();
    this.operator.supervisor.assertLive({ processEpoch: this.entry.process.processEpoch });
    // Explicit second gate read prevents operator-side stale generations.
    const replay = await this.operator.beginTrustedLocalAdmission(this.entry.io);
    if (!replay.proceed || !replay.admissionId.equals(this.entry.bound.admissionId)) deny();
    const copy = Buffer.from(bytes);
    this.busy = true;
    const response = await this.#exchange("held", { kind: "hold", index,
      ciphertext: b64(copy) });
    if (response.kind !== "held") deny();
    this.lastIndex = index;
    this.heldIndex = index;
    this.heldBytes = copy;
    return { held: true };
  }

  async releaseChunk() {
    if (!this.busy || this.stopping) deny();
    const response = await this.#exchange("committed", { kind: "release" });
    if (response.kind !== "committed") deny();
    // IPC acknowledgment is not physical storage evidence. Independently
    // re-read exact ciphertext with the preflighted restricted gate pool.
    // An ambiguous or missing PostgreSQL reply must NOT report success.
    let found;
    try {
      const s = this.entry.io.scope;
      const key = s.account_id.toString("hex") + ":"
        + s.compartment_id.length.toString(16) + ":" + s.compartment_id.toString("hex");
      found = await this.operator.gate.pool.query(`SELECT ciphertext FROM zk1_gate.ciphertext_chunk
        WHERE scope_key=$1 AND object_id=$2 AND chunk_index=$3`,
      [key, this.entry.io.objectId, this.heldIndex]);
    } catch (_) { deny(); }
    if (found.rowCount !== 1 || !Buffer.isBuffer(found.rows[0]?.ciphertext)
      || !found.rows[0].ciphertext.equals(this.heldBytes)) deny();
    this.heldBytes = null;
    this.heldIndex = null;
    this.busy = false;
    return { stored: true };
  }

  async stop() {
    if (!this.entry?.bound) deny();
    this.stopping = true;
    return this.operator.finishTrustedLocalAdmission({ scope: this.entry.io.scope,
      admissionId: this.entry.bound.admissionId, workerId: this.entry.io.workerId,
      principal: this.entry.io.principal });
  }
}

module.exports = { Zk1LabSupervisedPgWriter };
