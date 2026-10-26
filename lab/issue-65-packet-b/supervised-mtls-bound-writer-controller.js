"use strict";

// Local lab only. The operator controls the exact direct ChildProcess handle,
// immutable PostgreSQL writer_binding, pinned certificate and independent STOP.
// A request to the child's own mTLS socket cannot choose a scope or authority.
const crypto = require("node:crypto");
const { Zk1SharedPgStrictStopOperator } = require("../../src/services/zk1SharedPgStrictStopOperator");
const { verifyZk1SharedPgRuntimePool } = require("../../src/services/zk1SharedPgGateRuntime");

function deny() {
  const error = new Error("ZK_LAB_MTLS_WRITER_DENIED");
  error.code = error.message;
  throw error;
}
function exact(o, fields) {
  if (!o || typeof o !== "object" || Array.isArray(o)
    || Reflect.ownKeys(o).length !== fields.length
    || fields.some((k) => !Object.hasOwn(o, k))) deny();
}
function bytes(b) {
  if ((!Buffer.isBuffer(b) && !(b instanceof Uint8Array)) || b.length < 1 || b.length > 8192) deny();
  return Buffer.from(b);
}
function writerUrl(raw) {
  if (typeof raw !== "string" || raw.length > 512) deny();
  let url;
  try { url = new URL(raw); } catch (_) { deny(); }
  if (url.protocol !== "postgresql:" || url.hostname !== "127.0.0.1"
    || url.pathname !== "/gatefixture" || !/^[0-9]+$/.test(url.port)
    || !/^zkwriterfixture_[a-f0-9]{12}$/.test(decodeURIComponent(url.username))
    || !url.password || url.search || url.hash) deny();
  return { raw, login: decodeURIComponent(url.username) };
}
const b64 = (b) => Buffer.from(b).toString("base64url");
const scopeKey = (s) => s.account_id.toString("hex") + ":"
  + s.compartment_id.length.toString(16) + ":" + s.compartment_id.toString("hex");

class Zk1LabSupervisedMtlsBoundWriter {
  constructor({ operator, runtimePgUrl, tls, trustedClientCertificate,
    holdBeforeCommit = false } = {}) {
    if (!(operator instanceof Zk1SharedPgStrictStopOperator)) deny();
    exact(tls, ["key", "cert", "ca"]);
    this.tls = { key: bytes(tls.key), cert: bytes(tls.cert), ca: bytes(tls.ca) };
    this.clientCertificate = bytes(trustedClientCertificate);
    let client;
    try { client = new crypto.X509Certificate(this.clientCertificate); }
    catch (_) { deny(); }
    this.clientFingerprint = crypto.createHash("sha256").update(client.raw).digest("hex");
    this.clientPrincipal = this.clientFingerprint.match(/../g).join(":").toUpperCase();
    this.writer = writerUrl(runtimePgUrl);
    if (holdBeforeCommit !== true) deny(); // This milestone tests explicit lock ownership only.
    this.operator = operator;
    this.phase = "new";
    this.holdResolvers = [];
    this.held = false;
  }

  #session() {
    const child = this.session?.child;
    if (!child || !child.connected || this.session.closed || this.session.exited
      || this.session.aborted || child.exitCode !== null || child.signalCode !== null) deny();
    return child;
  }

  async #verify({ index, digest }) {
    try {
      if (!Number.isSafeInteger(index) || index < 0 || index > 4095
        || typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest)
        || this.confirmed) deny();
      const result = await this.operator.gate.pool.query(
        "SELECT ciphertext FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1 AND object_id=$2 AND chunk_index=$3",
        [scopeKey(this.entry.io.scope), this.entry.io.objectId, index]);
      if (result.rowCount !== 1 || !Buffer.isBuffer(result.rows[0]?.ciphertext)
        || crypto.createHash("sha256").update(result.rows[0].ciphertext).digest("hex") !== digest) deny();
      this.confirmed = true;
      this.#session().send({ kind: "confirmed", index });
    } catch (_) {
      // Never return 200 without independent parent-side durable SQL readback.
      try { this.#session().kill("SIGKILL"); } catch (_) { /* fail closed */ }
    }
  }

  async begin(io) {
    exact(io, ["scope", "workerId", "principal", "action", "objectId", "revision", "digest"]);
    // The independently operator-pinned client certificate, not the HTTP
    // request or an unverified caller principal, defines mTLS identity.
    if (this.phase !== "new" || io.action !== "put"
      || io.principal !== this.clientPrincipal) deny();
    await verifyZk1SharedPgRuntimePool(this.operator.gate.pool);
    if (await this.operator.gate.requiresTrustedLocalStop(io.scope) !== true) deny();
    this.phase = "starting";
    try {
      this.operator.prepare(io);
      this.entry = [...this.operator.entries.values()].find((v) =>
        v.io.workerId.equals(Buffer.from(io.workerId)));
      if (!this.entry) deny();
      this.session = this.operator.supervisor.sessions.get(this.entry.process.processEpoch.toString("hex"));
      const admitted = await this.operator.beginTrustedLocalAdmission(io);
      if (!admitted.proceed || !this.entry.bound || admitted.generation !== this.entry.bound.generation
        || !admitted.admissionId.equals(this.entry.bound.admissionId)) deny();
      const s = this.entry.io.scope;
      const bound = await this.operator.gate.pool.query(
        "INSERT INTO zk1_gate.writer_binding"
        + " (writer_login,admission_id,scope_key,object_id,worker_id,generation,process_epoch,process_pid)"
        + " VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        [this.writer.login, admitted.admissionId, scopeKey(s), this.entry.io.objectId,
          this.entry.io.workerId, admitted.generation, this.entry.process.processEpoch,
          this.entry.process.processPid]);
      if (bound.rowCount !== 1) deny();
      const init = { kind: "init", pgUrl: this.writer.raw,
        scope: { account_id: b64(s.account_id), compartment_id: b64(s.compartment_id),
          keyring_id: b64(s.keyring_id) },
        workerId: b64(this.entry.io.workerId), admissionId: b64(admitted.admissionId),
        hostKeyId: b64(this.entry.process.hostKeyId),
        processEpoch: b64(this.entry.process.processEpoch),
        processPid: this.entry.process.processPid, principal: this.entry.io.principal,
        action: "put", objectId: this.entry.io.objectId, revision: this.entry.io.revision,
        digest: b64(this.entry.io.digest), generation: admitted.generation,
        clientFingerprint: this.clientFingerprint,
        tls: { key: b64(this.tls.key), cert: b64(this.tls.cert), ca: b64(this.tls.ca) } };
      this.session.child.on("message", (m) => {
        if (m?.kind === "held" && Number.isSafeInteger(m.index)) {
          this.held = true;
          for (const resolve of this.holdResolvers.splice(0)) resolve();
        } else if (m?.kind === "verify") {
          void this.#verify(m);
        }
      });
      const ready = await this.#exchange("listening", init);
      if (ready.address !== "127.0.0.1" || !Number.isSafeInteger(ready.port)
        || ready.port <= 0 || ready.port > 65535
        || ready.restrictedRoleVerified !== true || ready.inheritedSecrets !== false) deny();
      this.operator.supervisor.assertLive({ processEpoch: this.entry.process.processEpoch });
      this.phase = "open";
      return { port: ready.port, admissionId: Buffer.from(admitted.admissionId),
        generation: admitted.generation, child: this.session.child,
        restrictedRoleVerified: true, inheritedSecrets: false };
    } catch (_) {
      if (this.session && !this.session.closed) this.session.child.kill("SIGKILL");
      deny();
    }
  }

  #exchange(kind, payload) {
    const child = this.#session();
    return new Promise((resolve, reject) => {
      const clear = () => { clearTimeout(timer); child.off("message", onMessage);
        child.off("close", fail); child.off("error", fail); };
      const fail = () => { clear(); reject(new Error("ZK_LAB_MTLS_WRITER_DENIED")); };
      const onMessage = (m) => {
        if (m?.kind === "failed") return fail();
        if (m?.kind !== kind) return;
        clear(); resolve(m);
      };
      const timer = setTimeout(fail, 7000);
      child.on("message", onMessage);
      child.once("close", fail);
      child.once("error", fail);
      child.send(payload, (e) => { if (e) fail(); });
    });
  }

  async waitHeld() {
    if (this.held) return;
    if (this.phase !== "open") deny();
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { reject(new Error("ZK_LAB_MTLS_WRITER_DENIED")); }, 5000);
      this.holdResolvers.push(() => { clearTimeout(timer); resolve(); });
    });
  }

  async releaseHeld() {
    if (!this.held || this.released) deny();
    this.released = true;
    this.#session().send({ kind: "release" });
  }

  async beginQuiesce(operation) {
    if (!this.entry?.bound || (this.phase !== "open" && this.phase !== "quiescing")) deny();
    const s = this.entry.io.scope;
    exact(operation, ["scope", "operationId", "reservationId", "revision", "digest"]);
    exact(operation.scope, ["account_id", "compartment_id", "keyring_id"]);
    if (!["account_id", "compartment_id", "keyring_id"].every((k) =>
      Buffer.from(s[k]).equals(Buffer.from(operation.scope[k])))
      || operation.revision !== this.entry.io.revision
      || !Buffer.from(operation.digest).equals(this.entry.io.digest)) deny();
    const next = { scope: { account_id: Buffer.from(operation.scope.account_id),
      compartment_id: Buffer.from(operation.scope.compartment_id),
      keyring_id: Buffer.from(operation.scope.keyring_id) },
    operationId: Buffer.from(operation.operationId),
    reservationId: Buffer.from(operation.reservationId),
    revision: operation.revision, digest: Buffer.from(operation.digest) };
    if (next.operationId.length !== 16 || next.reservationId.length !== 16) deny();
    if (this.quiescePinned && (!this.quiescePinned.operationId.equals(next.operationId)
      || !this.quiescePinned.reservationId.equals(next.reservationId))) deny();
    if (!this.quiescePinned) this.quiescePinned = next;
    this.phase = "quiescing";
    if (!this.quiescing) this.quiescing = this.operator.gate.beginQuiesce(this.quiescePinned);
    return this.quiescing;
  }

  async finishAfterQuiesce() {
    if (this.phase !== "quiescing" && this.phase !== "finished") deny();
    if (this.phase === "finished") return { status: "FINISHED" };
    if (this.quiescing) {
      const quiesced = await this.quiescing;
      if (quiesced.state !== "QUIESCING") deny();
    }
    const result = await this.operator.finishTrustedLocalAdmission({
      scope: this.entry.io.scope, admissionId: this.entry.bound.admissionId,
      workerId: this.entry.io.workerId, principal: this.entry.io.principal });
    if (result.status !== "FINISHED" || !this.session.exited || !this.session.closed) deny();
    this.phase = "finished";
    return result;
  }
}

module.exports = { Zk1LabSupervisedMtlsBoundWriter };
