"use strict";

// An independently pinned host supervisor attests that a specific supervised
// process HANDLE has closed. Ed25519 authenticates the supervisor's statement;
// it cannot independently prove remote provider completion, OS descendants,
// or trustworthy behavior of a compromised host/private key.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");

const DOMAIN = Buffer.from("Root.ark/zk-1/physical-worker-stop/v1\0", "ascii");
const TYPE = "rootark-zk1-physical-worker-stop/v1";
const OUTCOME = "kernel-process-handles-closed";
const FIELDS = Object.freeze(["type", "account_id", "compartment_id", "keyring_id",
  "admission_id", "worker_id", "principal", "generation", "host_key_id",
  "process_epoch", "process_pid", "stopped_at", "outcome"]);
const WIRE_FIELDS = Object.freeze([...FIELDS, "signature"]);

function fail() {
  const error = new Error("ZK_STOP_PROOF_INVALID");
  error.code = error.message;
  throw error;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
}
function copyBytes(value, length, max = length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length < length || value.length > max) fail();
  return Buffer.from(value);
}
function integer(value, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail();
  return value;
}
function normalizeProof(value) {
  exact(value, FIELDS);
  if (value.type !== TYPE || value.outcome !== OUTCOME
    || typeof value.principal !== "string" || value.principal.length < 1
    || value.principal.length > 128
    || /[\u0000-\u001f\u007f]/.test(value.principal)) fail();
  return {
    type: TYPE,
    account_id: copyBytes(value.account_id, 16),
    compartment_id: copyBytes(value.compartment_id, 1, 128),
    keyring_id: copyBytes(value.keyring_id, 16),
    admission_id: copyBytes(value.admission_id, 16),
    worker_id: copyBytes(value.worker_id, 16),
    principal: value.principal,
    generation: integer(value.generation, 1),
    host_key_id: copyBytes(value.host_key_id, 16),
    process_epoch: copyBytes(value.process_epoch, 16),
    process_pid: integer(value.process_pid, 1, 0x7fffffff),
    stopped_at: integer(value.stopped_at, 1),
    outcome: OUTCOME,
  };
}
function normalizeExpected(expected) {
  exact(expected, ["scope", "admissionId", "workerId", "generation", "principal",
    "processEpoch", "processPid"]);
  exact(expected.scope, ["account_id", "compartment_id", "keyring_id"]);
  return {
    account_id: copyBytes(expected.scope.account_id, 16),
    compartment_id: copyBytes(expected.scope.compartment_id, 1, 128),
    keyring_id: copyBytes(expected.scope.keyring_id, 16),
    admission_id: copyBytes(expected.admissionId, 16),
    worker_id: copyBytes(expected.workerId, 16),
    generation: integer(expected.generation, 1),
    principal: expected.principal,
    process_epoch: copyBytes(expected.processEpoch, 16),
    process_pid: integer(expected.processPid, 1, 0x7fffffff),
  };
}
function same(a, b) {
  return Buffer.isBuffer(a) || Buffer.isBuffer(b)
    ? Buffer.isBuffer(a) && Buffer.isBuffer(b)
      && a.length === b.length && crypto.timingSafeEqual(a, b)
    : a === b;
}

async function signZk1PhysicalStopProof({ proof, privateKey } = {}) {
  if (!(privateKey instanceof crypto.KeyObject)
    || privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") fail();
  const payload = normalizeProof(proof);
  try {
    const message = Buffer.from(await z.encodeDeterministic(payload));
    const signature = crypto.sign(null, Buffer.concat([DOMAIN, message]), privateKey);
    return Buffer.from(await z.encodeDeterministic({ ...payload, signature }));
  } catch (_) { fail(); }
}

async function verifyZk1PhysicalStopProof({ signedProof, hostKeyId,
  hostPublicKey, expected, nowSeconds } = {}) {
  const wire = copyBytes(signedProof, 100, 4096);
  const pinned = copyBytes(hostKeyId, 16);
  if (!(hostPublicKey instanceof crypto.KeyObject)
    || hostPublicKey.type !== "public"
    || hostPublicKey.asymmetricKeyType !== "ed25519") fail();
  const wanted = normalizeExpected(expected);
  const now = integer(nowSeconds, 1);
  try {
    const parsed = await z.decodeDeterministic(wire);
    exact(parsed, WIRE_FIELDS);
    const signature = copyBytes(parsed.signature, 64);
    const { signature: ignored, ...unsigned } = parsed;
    const normalized = normalizeProof(unsigned);
    if (!same(normalized.host_key_id, pinned)) fail();
    for (const field of Object.keys(wanted)) {
      if (!same(wanted[field], normalized[field])) fail();
    }
    if (Math.abs(normalized.stopped_at - now) > 50) fail();
    const payload = Buffer.from(await z.encodeDeterministic(normalized));
    const canonical = Buffer.from(await z.encodeDeterministic({ ...normalized, signature }));
    if (!wire.equals(canonical)
      || !crypto.verify(null, Buffer.concat([DOMAIN, payload]), hostPublicKey, signature)) fail();
    return Object.freeze({
      scope: { account_id: Buffer.from(normalized.account_id),
        compartment_id: Buffer.from(normalized.compartment_id),
        keyring_id: Buffer.from(normalized.keyring_id) },
      admissionId: Buffer.from(normalized.admission_id),
      workerId: Buffer.from(normalized.worker_id),
      principal: normalized.principal,
      generation: normalized.generation,
      hostKeyId: Buffer.from(normalized.host_key_id),
      processEpoch: Buffer.from(normalized.process_epoch),
      processPid: normalized.process_pid,
      stoppedAt: normalized.stopped_at,
      proofDigest: crypto.createHash("sha256").update(wire).digest(),
      signedProof: Buffer.from(wire),
    });
  } catch (_) { fail(); }
}

module.exports = { signZk1PhysicalStopProof, verifyZk1PhysicalStopProof };
