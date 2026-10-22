"use strict";

// LAB ONLY. Local, operator-owned GET experiment. The child owns the actual
// 127.0.0.1 HTTP listening socket; this parent owns the independently pinned
// PostgreSQL GET admission and direct ChildProcess STOP receipt. HTTP requests
// NEVER choose account, compartment, device, revision, generation or worker.
// A per-chunk SQL check alone is not a socket/PG atomic fence; in particular
// a grant may be in flight when QUIESCING commits. Only direct-child exit AND
// close can justify this fixture's subsequent FINISHED/PENDING proof.
const crypto = require("node:crypto");
const { Zk1SharedPgGateAuthority } = require("../../src/services/zk1SharedPgGateAuthority");
const { verifyZk1SharedPgRuntimePool } =
  require("../../src/services/zk1SharedPgGateRuntime");
const { Zk1IsolatedProcessStopSupervisor } =
  require("../../src/services/zk1IsolatedProcessStopSupervisor");
const { isVerifiedZk1PhysicalStopRecorder } =
  require("../../src/services/zk1SharedPgPhysicalStopRecorder");
const { Zk1SharedPgSealedGetReader } =
  require("../../src/services/zk1SharedPgSealedGetReader");
const { Zk1SharedPgWitnessCasEgressGuard } =
  require("../../src/services/zk1SharedPgWitnessCasEgressGuard");

// The legacy experiment intentionally generated random TCP frames or read PG
// ciphertext without a remote witness. Keep it reachable only through the
// explicitly unsafe lab factory, never through the hardened constructor.
const UNSAFE_LAB_CAPABILITY = Symbol("zk1-unsafe-legacy-lab-get-fixture");

function deny() {
  const error = new Error("ZK_LAB_GET_DENIED");
  error.code = error.message;
  throw error;
}
function bytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length < min || value.length > max) deny();
  return Buffer.from(value);
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((key) => !Object.hasOwn(value, key))) deny();
}
function copyIo(input) {
  exact(input, ["scope", "workerId", "principal", "action", "objectId", "revision", "digest"]);
  exact(input.scope, ["account_id", "compartment_id", "keyring_id"]);
  if (input.action !== "get" || typeof input.principal !== "string"
    || !/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i.test(input.principal)
    || typeof input.objectId !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(input.objectId)
    || Buffer.from(input.objectId, "base64url").toString("base64url") !== input.objectId
    || !Number.isSafeInteger(input.revision) || input.revision < 1) deny();
  return { scope: { account_id: bytes(input.scope.account_id, 16),
    compartment_id: bytes(input.scope.compartment_id, 1, 128),
    keyring_id: bytes(input.scope.keyring_id, 16) },
  workerId: bytes(input.workerId, 16), principal: input.principal.toUpperCase(),
  action: "get", objectId: input.objectId, revision: input.revision,
  digest: bytes(input.digest, 32) };
}
function matchesScope(a, b) {
  return a.account_id.equals(b.account_id)
    && a.compartment_id.equals(b.compartment_id) && a.keyring_id.equals(b.keyring_id);
}
function quiesceTuple(operation, io) {
  exact(operation, ["scope", "operationId", "reservationId", "revision", "digest"]);
  exact(operation.scope, ["account_id", "compartment_id", "keyring_id"]);
  const scope = { account_id: bytes(operation.scope.account_id, 16),
    compartment_id: bytes(operation.scope.compartment_id, 1, 128),
    keyring_id: bytes(operation.scope.keyring_id, 16) };
  const digest = bytes(operation.digest, 32);
  if (!matchesScope(scope, io.scope)
    || operation.revision !== io.revision || !digest.equals(io.digest)) deny();
  return { scope, operationId: bytes(operation.operationId, 16),
    reservationId: bytes(operation.reservationId, 16),
    revision: operation.revision, digest };
}
function sameQuiesce(a, b) {
  return matchesScope(a.scope, b.scope)
    && a.operationId.equals(b.operationId)
    && a.reservationId.equals(b.reservationId)
    && a.revision === b.revision && a.digest.equals(b.digest);
}
function pubkeyEquals(a, b) {
  return a?.type === "public" && b?.type === "public"
    && a.asymmetricKeyType === "ed25519" && b.asymmetricKeyType === "ed25519"
    && a.export({ format: "der", type: "spki" }).equals(
      b.export({ format: "der", type: "spki" }));
}
class Zk1LabSupervisedGetEgress {
  #unsafeLegacyLabOnly;
  #continuing = false;
  #quorumFailed = false;
  static createUnsafeLegacyLabFixture(options) {
    if (!options || typeof options !== "object" || Array.isArray(options)) deny();
    // Disjoint entry point for the historical synthetic/PG-only experiments.
    // This is intentionally not a security capability or a production API.
    return new Zk1LabSupervisedGetEgress({ ...options,
      [UNSAFE_LAB_CAPABILITY]: true });
  }

  constructor({ gate, supervisor, recorder, ciphertextReader, expectedRootHash,
    quorumGuard, ...extra } = {}) {
    const unsafeLabOnly = extra[UNSAFE_LAB_CAPABILITY] === true;
    if (Reflect.ownKeys(extra).some((key) => key !== UNSAFE_LAB_CAPABILITY)
      || (Reflect.ownKeys(extra).length > 0 && !unsafeLabOnly)) deny();
    if (!(gate instanceof Zk1SharedPgGateAuthority)
      || !(supervisor instanceof Zk1IsolatedProcessStopSupervisor)
      || !isVerifiedZk1PhysicalStopRecorder(recorder)
      || !gate.stopPinned || !gate.stopPinned.hostKeyId.equals(supervisor.hostKeyId)
      || !recorder.hostKeyId.equals(supervisor.hostKeyId)
      || !pubkeyEquals(gate.stopPinned.hostPublicKey,
        crypto.createPublicKey(supervisor.hostPrivateKey))
      || !pubkeyEquals(recorder.hostPublicKey, gate.stopPinned.hostPublicKey)) deny();
    if ((ciphertextReader === undefined) !== (expectedRootHash === undefined)
      || (ciphertextReader !== undefined && (
        !(ciphertextReader instanceof Zk1SharedPgSealedGetReader)
        || ciphertextReader.gate !== gate))) deny();
    if (quorumGuard !== undefined && (
      !(quorumGuard instanceof Zk1SharedPgWitnessCasEgressGuard)
      || !ciphertextReader || !expectedRootHash)) deny();
    // Every default construction represents a hardened real-PG egress.
    // A reader+root alone (including null guard or opportunistic flags) is
    // insufficient, and a synthetic/no-reader path must be explicit lab code.
    if (unsafeLabOnly ? quorumGuard !== undefined
      : !ciphertextReader || !expectedRootHash
        || !(quorumGuard instanceof Zk1SharedPgWitnessCasEgressGuard)) deny();
    this.gate = gate;
    this.supervisor = supervisor;
    this.recorder = recorder;
    this.ciphertextReader = ciphertextReader;
    this.quorumGuard = quorumGuard;
    this.#unsafeLegacyLabOnly = unsafeLabOnly;
    this.expectedRootHash = expectedRootHash === undefined
      ? null : bytes(expectedRootHash, 32);
    this.phase = "new";
    this.partial = false;
  }

  #send(message) {
    const child = this.session?.child;
    if (!child?.connected || this.session.closed || this.session.exited
      || this.session.aborted || child.exitCode !== null || child.signalCode !== null) deny();
    child.send(message);
  }

  async #readCiphertext(chunkIndex) {
    if (!this.ciphertextReader) return crypto.randomBytes(16384);
    const bytes = await this.ciphertextReader.readChunk({ io: this.io,
      process: this.process, admissionId: this.admissionId,
      generation: this.generation, expectedRootHash: this.expectedRootHash,
      chunkIndex });
    // The disposable child intentionally supports exactly two bounded frames.
    if (!Buffer.isBuffer(bytes) || bytes.length !== 16384) deny();
    return bytes;
  }
  async #verifyQuorum() {
    if (this.#unsafeLegacyLabOnly) return;
    if (this.#quorumFailed) deny();
    try {
      if (!(this.quorumGuard instanceof Zk1SharedPgWitnessCasEgressGuard)) deny();
      await this.quorumGuard.authorize({
        io: this.io, expectedRootHash: this.expectedRootHash });
    } catch (error) {
      // An uncertain remote witness outcome permanently fences this process's
      // GET. Even if mTLS reconnects and a caller mutates public properties,
      // only the existing physical STOP/quiescence path remains admissible.
      this.#quorumFailed = true;
      this.stopping = true;
      // Preserve the independently verified witness-failure contract for
      // operator callers. The child HTTP listener still sends only generic
      // denial responses, and arbitrary underlying failures stay redacted.
      if (error?.code === "ZK_LAB_QUORUM_UNAVAILABLE") throw error;
      deny();
    }
  }

  async #admitGet() {
    const allowed = () => this.phase === "listening" && !this.stopping
      && !this.#quorumFailed && this.session?.bound && !this.session.closed;
    if (!allowed()) return this.#denyIncoming();
    try {
      this.supervisor.assertLive({ processEpoch: this.process.processEpoch });
      // Exact SQL re-read; a caller's token or a prior grant is not authority.
      const decision = await this.gate.beginIoAdmission({ ...this.io,
        hostKeyId: this.process.hostKeyId, processEpoch: this.process.processEpoch,
        processPid: this.process.processPid });
      if (!allowed() || !decision.proceed || !decision.admissionId.equals(this.admissionId)
        || decision.generation !== this.generation) return this.#denyIncoming();
      await this.#verifyQuorum();
      const ciphertext = await this.#readCiphertext(0);
      await this.#verifyQuorum();
      if (!allowed()) return this.#denyIncoming();
      this.supervisor.assertLive({ processEpoch: this.process.processEpoch });
      this.#send({ kind: "grant-get", ciphertextBase64: ciphertext.toString("base64url") });
    } catch (_) { this.#denyIncoming(); }
  }

  #denyIncoming() {
    try { this.#send({ kind: "deny-get" }); } catch (_) { /* fail closed on child exit */ }
  }

  async begin(input) {
    const io = copyIo(input);
    if (this.phase !== "new") deny();
    // The gate must be an independently provisioned restricted PostgreSQL
    // login. A privileged app/superuser pool is never accepted here.
    await verifyZk1SharedPgRuntimePool(this.gate.pool);
    if (this.ciphertextReader) await this.ciphertextReader.preflight();
    // Disconnected or non-strict authority rejects before creating a listener.
    if (await this.gate.requiresTrustedLocalStop(io.scope) !== true) deny();
    this.phase = "starting";
    this.io = io;
    try {
      await this.#verifyQuorum();
      this.process = this.supervisor.launch({ scope: io.scope,
        workerId: io.workerId, principal: io.principal });
      this.session = this.supervisor.sessions.get(this.process.processEpoch.toString("hex"));
      if (!this.session) deny();
      this.session.child.on("message", (message) => {
        if (message?.kind === "get-admit") void this.#admitGet();
        if (message?.kind === "partial" && message.bytes === 16384) {
          this.partial = true;
          if (this.notifyPartial) this.notifyPartial();
        }
      });
      const result = await this.gate.beginIoAdmission({ ...io,
        hostKeyId: this.process.hostKeyId, processEpoch: this.process.processEpoch,
        processPid: this.process.processPid });
      if (!result?.proceed || !Buffer.isBuffer(result.admissionId)
        || result.admissionId.length !== 16 || !Number.isSafeInteger(result.generation)) deny();
      this.supervisor.bindAdmission({ ...this.process, scope: io.scope,
        workerId: io.workerId, principal: io.principal,
        admissionId: result.admissionId, generation: result.generation });
      this.admissionId = Buffer.from(result.admissionId);
      this.generation = result.generation;
      this.token = crypto.randomBytes(32).toString("base64url");
      const opened = new Promise((resolve, reject) => {
        const child = this.session.child;
        const finish = () => {
          clearTimeout(timeout);
          child.off("message", onMessage);
          child.off("close", onClose);
          child.off("error", onClose);
        };
        const onClose = () => { finish(); reject(new Error("ZK_LAB_GET_DENIED")); };
        const onMessage = (msg) => {
          if (msg?.kind !== "listening") return;
          finish();
          if (msg.address !== "127.0.0.1" || !Number.isSafeInteger(msg.port)
            || msg.port < 1 || msg.port > 65535) reject(new Error("ZK_LAB_GET_DENIED"));
          else resolve(msg.port);
        };
        const timeout = setTimeout(onClose, 4000);
        child.on("message", onMessage);
        child.once("close", onClose);
        child.once("error", onClose);
      });
      this.#send({ kind: "init", token: this.token });
      const port = await opened;
      // Reconcile an intervening gate generation change before surfacing URL.
      const current = await this.gate.beginIoAdmission({ ...io,
        hostKeyId: this.process.hostKeyId, processEpoch: this.process.processEpoch,
        processPid: this.process.processPid });
      if (!current.proceed || !current.admissionId.equals(this.admissionId)
        || current.generation !== this.generation) deny();
      await this.#verifyQuorum();
      this.supervisor.assertLive({ processEpoch: this.process.processEpoch });
      this.phase = "listening";
      return Object.freeze({ port, token: this.token,
        admissionId: Buffer.from(this.admissionId), generation: this.generation,
        child: this.session.child });
    } catch (_) {
      if (this.session && !this.session.closed) this.session.child.kill("SIGKILL");
      deny();
    }
  }

  async waitPartial() {
    if (this.partial) return true;
    if (this.phase !== "listening") deny();
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => { this.notifyPartial = null;
        reject(new Error("ZK_LAB_GET_DENIED")); }, 4000);
      this.notifyPartial = () => { clearTimeout(timeout);
        this.notifyPartial = null; resolve(true); };
    });
  }

  async continueResponse() {
    if (this.phase !== "listening" || !this.partial || this.stopping
      || this.#quorumFailed || this.#continuing) deny();
    // Serialize authorization and actual child IPC across concurrent callers.
    // Without this latch, two awaits can both pass the `partial` check and
    // queue duplicate ciphertext frames before either clears the marker.
    this.#continuing = true;
    try {
      this.supervisor.assertLive({ processEpoch: this.process.processEpoch });
      const decision = await this.gate.beginIoAdmission({ ...this.io,
        hostKeyId: this.process.hostKeyId, processEpoch: this.process.processEpoch,
        processPid: this.process.processPid });
      if (this.stopping || !decision.proceed || !decision.admissionId.equals(this.admissionId)
        || decision.generation !== this.generation) deny();
      await this.#verifyQuorum();
      const ciphertext = await this.#readCiphertext(1);
      await this.#verifyQuorum();
      if (this.stopping) deny();
      this.supervisor.assertLive({ processEpoch: this.process.processEpoch });
      this.#send({ kind: "continue", ciphertextBase64: ciphertext.toString("base64url") });
      this.partial = false;
    } finally { this.#continuing = false; }
  }

  async beginQuiesce(operation) {
    if (this.phase !== "listening" && this.phase !== "quiescing") deny();
    const frozen = quiesceTuple(operation, this.io);
    if (this.quiesceInput && !sameQuiesce(this.quiesceInput, frozen)) deny();
    if (!this.quiesceInput) this.quiesceInput = frozen;
    this.stopping = true;
    // The gate's durable transition can race a grant already sent to the
    // child. If COMMIT succeeds but its ACK is lost, remain fail-closed to all
    // egress while allowing only the exact pinned operation/reservation to
    // re-read the authoritative SQL state. Never change to a new reservation.
    if (this.quiesceInFlight) return this.quiesceInFlight;
    this.quiesceInFlight = (async () => {
      const result = await this.gate.beginQuiesce(this.quiesceInput);
      if (result.state !== "QUIESCING") deny();
      this.phase = "quiescing";
      return result;
    })();
    try { return await this.quiesceInFlight; }
    finally { this.quiesceInFlight = null; }
  }

  async finishAfterQuiesce() {
    if (this.phase !== "quiescing" && this.phase !== "finished") deny();
    if (this.phase === "finished") return { status: "FINISHED" };
    if (this.finishing) return this.finishing;
    this.finishing = (async () => {
      const signedProof = await this.supervisor.stop({ processEpoch: this.process.processEpoch });
      if (!this.session.exited || !this.session.closed) deny();
      const expected = { scope: this.io.scope, admissionId: this.admissionId,
        workerId: this.io.workerId, principal: this.io.principal,
        generation: this.generation, processEpoch: this.process.processEpoch,
        processPid: this.process.processPid };
      const recorded = await this.recorder.record({ signedProof, expected });
      if (recorded?.status !== "STOP_ATTESTED") deny();
      const finished = await this.gate.finishIoAdmission({ scope: this.io.scope,
        admissionId: this.admissionId, workerId: this.io.workerId,
        principal: this.io.principal });
      if (finished?.status !== "FINISHED") deny();
      this.phase = "finished";
      return { status: "FINISHED" };
    })();
    try { return await this.finishing; }
    finally { this.finishing = null; }
  }
}

module.exports = { Zk1LabSupervisedGetEgress };
