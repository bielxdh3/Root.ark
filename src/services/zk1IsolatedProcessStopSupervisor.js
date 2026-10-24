"use strict";

// BOUNDED single-process host supervisor reference. Trust comes from this
// process controlling the launch, an isolated Ed25519 key and genuine Node OS
// ChildProcess `exit` + `close` events. It does NOT supervise descendants,
// remotely mounted provider I/O, or kernel/remote TCP buffers. Only a trusted
// gate operator may bind an admission to a supervised process. Never expose
// this API to untrusted web input.
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const { signZk1PhysicalStopProof } =
  require("../crypto/rootark-zk-physical-stop-proof-v1");

function deny() {
  const error = new Error("ZK_STOP_SUPERVISOR_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function bytes(value, size, max = size) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length < size || value.length > max) deny();
  return Buffer.from(value);
}
function scopeOf(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== 3
    || ["account_id", "compartment_id", "keyring_id"]
      .some((field) => !Object.hasOwn(value, field))) deny();
  return { account_id: bytes(value.account_id, 16),
    compartment_id: bytes(value.compartment_id, 1, 128),
    keyring_id: bytes(value.keyring_id, 16) };
}
function scopeKey(s) {
  return [s.account_id.toString("hex"), s.compartment_id.toString("hex"),
    s.keyring_id.toString("hex")].join(":");
}

class Zk1IsolatedProcessStopSupervisor {
  constructor({ hostKeyId, hostPrivateKey, workerScript, nowSeconds = () =>
    Math.floor(Date.now() / 1000), stopTimeoutMs = 5000 } = {}) {
    this.hostKeyId = bytes(hostKeyId, 16);
    if (!(hostPrivateKey instanceof crypto.KeyObject)
      || hostPrivateKey.type !== "private"
      || hostPrivateKey.asymmetricKeyType !== "ed25519") deny();
    this.hostPrivateKey = hostPrivateKey;
    if (typeof workerScript !== "string" || !require("node:path").isAbsolute(workerScript)
      || !require("node:fs").lstatSync(workerScript).isFile()) deny();
    this.workerScript = require("node:fs").realpathSync(workerScript);
    if (typeof nowSeconds !== "function"
      || !Number.isSafeInteger(stopTimeoutMs)
      || stopTimeoutMs < 50 || stopTimeoutMs > 60000) deny();
    this.nowSeconds = nowSeconds;
    this.stopTimeoutMs = stopTimeoutMs;
    this.sessions = new Map();
  }

  launch({ scope, workerId, principal } = {}) {
    const copiedScope = scopeOf(scope);
    const worker = bytes(workerId, 16);
    if (typeof principal !== "string" || principal.length < 1 || principal.length > 128
      || /[\u0000-\u001f\u007f]/.test(principal)) deny();
    const child = spawn(process.execPath, [this.workerScript], {
      stdio: ["ignore", "ignore", "ignore", "ipc"],
      // Never leak DB URLs, private-key locations, environment secrets or
      // operator credentials from the STOP authority into a worker process.
      windowsHide: true, detached: false,
      env: { NODE_ENV: "test", SystemRoot: process.env.SystemRoot || "" },
    });
    if (!Number.isSafeInteger(child.pid) || child.pid <= 0) deny();
    const epoch = crypto.randomBytes(16);
    const key = epoch.toString("hex");
    const session = { child, scope: copiedScope, workerId: worker,
      principal, processEpoch: epoch, processPid: child.pid,
      exited: false, closed: false, bound: false, stoppedProof: null,
      aborted: false, waiters: [] };
    child.once("exit", () => { session.exited = true; });
    child.once("close", () => {
      session.closed = true;
      for (const resolve of session.waiters.splice(0)) resolve();
    });
    child.once("error", () => { session.aborted = true; });
    this.sessions.set(key, session);
    return Object.freeze({ hostKeyId: Buffer.from(this.hostKeyId),
      processEpoch: Buffer.from(epoch), processPid: child.pid });
  }

  bindAdmission({ processEpoch, admissionId, generation, scope,
    workerId, principal, processPid } = {}) {
    const session = this.sessions.get(bytes(processEpoch, 16).toString("hex"));
    // The exact admission might have committed while the owned child exited.
    // A dead but STILL host-owned ChildProcess must be bound for STOP recovery;
    // subsequent assertLive() will refuse positive I/O admission.
    if (!session || session.bound || session.aborted) deny();
    const candidateScope = scopeOf(scope);
    if (scopeKey(candidateScope) !== scopeKey(session.scope)
      || !crypto.timingSafeEqual(bytes(workerId, 16), session.workerId)
      || principal !== session.principal || processPid !== session.processPid
      || !Number.isSafeInteger(generation) || generation < 1) deny();
    session.admissionId = bytes(admissionId, 16);
    session.generation = generation;
    session.bound = true;
  }

  assertLive({ processEpoch } = {}) {
    const session = this.sessions.get(bytes(processEpoch, 16).toString("hex"));
    if (!session || session.exited || session.closed || session.aborted
      || session.child.exitCode !== null || session.child.signalCode !== null) deny();
    return true;
  }

  async stop({ processEpoch } = {}) {
    const session = this.sessions.get(bytes(processEpoch, 16).toString("hex"));
    if (!session || !session.bound || session.aborted) deny();
    if (session.stoppedProof) return Buffer.from(session.stoppedProof);
    if (session.stopPromise) return Buffer.from(await session.stopPromise);
    // Exactly one STOP signal + close observation + timestamp/signature. A
    // second caller joins the same promise, never kills a PID a second time.
    session.stopPromise = this.#finishObservedStop(session);
    try { return Buffer.from(await session.stopPromise); }
    finally { session.stopPromise = null; }
  }

  async #finishObservedStop(session) {
    if (!session.closed) {
      // Only the host-held handle is targeted; never accept a caller-provided
      // PID and never infer termination merely from a STOP request/IPC ACK.
      if (!session.child.kill("SIGTERM") && !session.exited) deny();
      let timeout;
      try {
        await Promise.race([
          new Promise((resolve) => { session.waiters.push(resolve); }),
          new Promise((_, reject) => {
            timeout = setTimeout(reject, this.stopTimeoutMs, new Error("STOP timeout"));
          }),
        ]);
      } catch (_) { deny(); }
      finally { clearTimeout(timeout); }
    }
    if (!session.exited || !session.closed) deny();
    const stoppedAt = this.nowSeconds();
    if (!Number.isSafeInteger(stoppedAt) || stoppedAt < 1) deny();
    const proof = { type: "rootark-zk1-physical-worker-stop/v1",
      ...session.scope, admission_id: Buffer.from(session.admissionId),
      worker_id: Buffer.from(session.workerId), principal: session.principal,
      generation: session.generation, host_key_id: Buffer.from(this.hostKeyId),
      process_epoch: Buffer.from(session.processEpoch), process_pid: session.processPid,
      stopped_at: stoppedAt, outcome: "kernel-process-handles-closed" };
    session.stoppedProof = Buffer.from(await signZk1PhysicalStopProof({
      proof, privateKey: this.hostPrivateKey }));
    return Buffer.from(session.stoppedProof);
  }

  dispose() {
    for (const session of this.sessions.values()) {
      if (!session.closed && !session.exited) session.child.kill("SIGKILL");
    }
  }
}

module.exports = { Zk1IsolatedProcessStopSupervisor };
