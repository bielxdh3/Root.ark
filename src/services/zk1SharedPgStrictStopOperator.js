"use strict";

// Opt-in, operator-owned, single-host ChildProcess STOP reference. This is an
// INTERNAL operator API, never a delegated mTLS worker authorization adapter.
// The separate HTTPS listener must refuse strict START/PUT/SEAL/FINISH because
// its HTTPS handler, not this ChildProcess, executes the physical PG effects.
// No fixture child is represented as proof that TLS/provider IO has drained.
const crypto = require("node:crypto");
const { Zk1SharedPgGateAuthority } = require("./zk1SharedPgGateAuthority");
const { Zk1SharedPgPhysicalStopRecorder } = require("./zk1SharedPgPhysicalStopRecorder");
const { Zk1IsolatedProcessStopSupervisor } = require("./zk1IsolatedProcessStopSupervisor");

function deny() {
  const e = new Error("ZK_GATE_DENIED");
  e.code = e.message;
  throw e;
}
function bytes(value, length, max = length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length < length || value.length > max) deny();
  return Buffer.from(value);
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((name) => !Object.hasOwn(value, name))) deny();
}
function identity(input) {
  exact(input, ["scope", "workerId", "principal", "action", "objectId", "revision", "digest"]);
  exact(input.scope, ["account_id", "compartment_id", "keyring_id"]);
  const scope = { account_id: bytes(input.scope.account_id, 16),
    compartment_id: bytes(input.scope.compartment_id, 1, 128),
    keyring_id: bytes(input.scope.keyring_id, 16) };
  if (typeof input.principal !== "string"
    || !/^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/i.test(input.principal)
    || input.action !== "put" || typeof input.objectId !== "string"
    || !/^[A-Za-z0-9_-]{22}$/.test(input.objectId)
    || Buffer.from(input.objectId, "base64url").toString("base64url") !== input.objectId
    || !Number.isSafeInteger(input.revision) || input.revision < 1) deny();
  return { scope, workerId: bytes(input.workerId, 16),
    principal: input.principal.toUpperCase(), action: "put",
    objectId: input.objectId, revision: input.revision, digest: bytes(input.digest, 32) };
}
function keyOf(io) {
  return [io.scope.account_id.toString("hex"), io.scope.compartment_id.toString("hex"),
    io.scope.keyring_id.toString("hex"), io.workerId.toString("hex")].join(":");
}
function same(a, b) {
  return keyOf(a) === keyOf(b) && a.principal === b.principal
    && a.action === b.action && a.objectId === b.objectId
    && a.revision === b.revision && a.digest.equals(b.digest);
}
function pinnedPublicEquals(a, b) {
  return a && b && a.type === "public" && b.type === "public"
    && a.asymmetricKeyType === "ed25519" && b.asymmetricKeyType === "ed25519"
    && a.export({ type: "spki", format: "der" }).equals(b.export({ type: "spki", format: "der" }));
}

class Zk1SharedPgStrictStopOperator {
  constructor({ gate, supervisor, recorder } = {}) {
    if (!(gate instanceof Zk1SharedPgGateAuthority)
      || !(supervisor instanceof Zk1IsolatedProcessStopSupervisor)
      || !(recorder instanceof Zk1SharedPgPhysicalStopRecorder)
      || !gate.stopPinned || !gate.stopPinned.hostKeyId.equals(supervisor.hostKeyId)
      || !recorder.hostKeyId.equals(supervisor.hostKeyId)
      || !pinnedPublicEquals(gate.stopPinned.hostPublicKey,
        crypto.createPublicKey(supervisor.hostPrivateKey))
      || !pinnedPublicEquals(recorder.hostPublicKey, gate.stopPinned.hostPublicKey)) deny();
    this.gate = gate;
    this.supervisor = supervisor;
    this.recorder = recorder;
    this.entries = new Map();
  }

  // Trusted local operator provisions the full expected request BEFORE HTTP
  // START. Prelaunched process is not chosen or created by the HTTP request.
  prepare(input) {
    const io = identity(input);
    const key = keyOf(io);
    if (this.entries.has(key) || this.entries.size >= 1024) deny();
    const process = this.supervisor.launch({ scope: io.scope,
      workerId: io.workerId, principal: io.principal });
    this.entries.set(key, { io, process, bound: null, starting: null,
      finishing: null, stopping: false, finished: false });
    return Object.freeze({ prepared: true });
  }

  // Strict local reference only. The HTTPS server never invokes this method.
  async beginTrustedLocalAdmission(input) {
    const io = identity(input);
    const entry = this.entries.get(keyOf(io));
    if (!entry) deny();
    if (!same(io, entry.io) || entry.stopping || entry.finished) deny();
    if (entry.starting) return entry.starting;
    entry.starting = (async () => {
      this.supervisor.assertLive({ processEpoch: entry.process.processEpoch });
      const admitted = await this.gate.beginIoAdmission({ ...entry.io,
        hostKeyId: entry.process.hostKeyId,
        processEpoch: entry.process.processEpoch, processPid: entry.process.processPid });
      if (!admitted || !Buffer.isBuffer(admitted.admissionId)
        || admitted.admissionId.length !== 16 || !Number.isSafeInteger(admitted.generation)
        || admitted.generation < 1 || typeof admitted.proceed !== "boolean") deny();
      if (entry.bound) {
        if (!entry.bound.admissionId.equals(admitted.admissionId)
          || entry.bound.generation !== admitted.generation) deny();
      } else {
        if (!admitted.proceed) deny();
        this.supervisor.bindAdmission({ scope: entry.io.scope,
          workerId: entry.io.workerId, principal: entry.io.principal,
          processEpoch: entry.process.processEpoch, processPid: entry.process.processPid,
          admissionId: admitted.admissionId, generation: admitted.generation });
        entry.bound = { admissionId: Buffer.from(admitted.admissionId),
          generation: admitted.generation };
      }
      if (admitted.proceed) this.supervisor.assertLive({ processEpoch: entry.process.processEpoch });
      return { admissionId: Buffer.from(admitted.admissionId),
        generation: admitted.generation, proceed: admitted.proceed };
    })();
    try { return await entry.starting; }
    finally { entry.starting = null; }
  }

  // An operator can record the observation of a terminated local fixture
  // process. No untrusted request can invoke this method via HTTPS.
  async finishTrustedLocalAdmission({ scope, admissionId, workerId, principal } = {}) {
    const key = keyOf({ scope: { account_id: bytes(scope?.account_id, 16),
      compartment_id: bytes(scope?.compartment_id, 1, 128),
      keyring_id: bytes(scope?.keyring_id, 16) }, workerId: bytes(workerId, 16) });
    const entry = this.entries.get(key);
    if (!entry) deny();
    if (principal !== entry.io.principal || !entry.bound
      || !bytes(admissionId, 16).equals(entry.bound.admissionId)) deny();
    if (entry.finished) return { status: "FINISHED" };
    if (entry.finishing) return entry.finishing;
    entry.stopping = true;
    entry.finishing = (async () => {
      if (entry.starting) await entry.starting;
      const signedProof = await this.supervisor.stop({ processEpoch: entry.process.processEpoch });
      const expected = { scope: entry.io.scope, admissionId: entry.bound.admissionId,
        workerId: entry.io.workerId, generation: entry.bound.generation,
        principal: entry.io.principal, processEpoch: entry.process.processEpoch,
        processPid: entry.process.processPid };
      const recorded = await this.recorder.record({ signedProof, expected });
      if (!recorded || recorded.status !== "STOP_ATTESTED") deny();
      const result = await this.gate.finishIoAdmission({ scope: entry.io.scope,
        admissionId: entry.bound.admissionId, workerId: entry.io.workerId,
        principal: entry.io.principal });
      if (!result || result.status !== "FINISHED") deny();
      entry.finished = true;
      return { status: "FINISHED" };
    })();
    try { return await entry.finishing; }
    finally { entry.finishing = null; }
  }
}

module.exports = { Zk1SharedPgStrictStopOperator };
