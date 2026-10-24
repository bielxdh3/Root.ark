"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const path = require("node:path");
const { signZk1PhysicalStopProof, verifyZk1PhysicalStopProof } =
  require("../src/crypto/rootark-zk-physical-stop-proof-v1");
const { Zk1IsolatedProcessStopSupervisor } =
  require("../src/services/zk1IsolatedProcessStopSupervisor");

function sample() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(7), keyring_id: crypto.randomBytes(16) };
  const proof = { type: "rootark-zk1-physical-worker-stop/v1",
    ...scope, admission_id: crypto.randomBytes(16), worker_id: crypto.randomBytes(16),
    principal: "AA:".repeat(31) + "AA", generation: 3, host_key_id: crypto.randomBytes(16),
    process_epoch: crypto.randomBytes(16), process_pid: 1234, stopped_at: 1000,
    outcome: "kernel-process-handles-closed" };
  return { proof, keys };
}

test("Ed25519 STOP receipt binds host/process epoch, worker and exact zk-1 scope", async () => {
  const { proof, keys } = sample();
  const signed = await signZk1PhysicalStopProof({ proof, privateKey: keys.privateKey });
  const checked = await verifyZk1PhysicalStopProof({ signedProof: signed,
    hostKeyId: proof.host_key_id, hostPublicKey: keys.publicKey,
    expected: { scope: { account_id: proof.account_id,
      compartment_id: proof.compartment_id, keyring_id: proof.keyring_id },
      admissionId: proof.admission_id, workerId: proof.worker_id,
      generation: 3, principal: proof.principal, processEpoch: proof.process_epoch,
      processPid: 1234 }, nowSeconds: 1000 });
  assert.deepEqual(checked.admissionId, proof.admission_id);
  assert.deepEqual(checked.processEpoch, proof.process_epoch);
  assert.equal(checked.processPid, 1234);
  assert.equal(checked.stoppedAt, 1000);
  assert.deepEqual(checked.proofDigest, crypto.createHash("sha256").update(signed).digest());
  assert.deepEqual(checked.signedProof, signed);
  await assert.rejects(verifyZk1PhysicalStopProof({ signedProof: signed,
    hostKeyId: crypto.randomBytes(16), hostPublicKey: keys.publicKey,
    expected: { scope: { account_id: proof.account_id,
      compartment_id: proof.compartment_id, keyring_id: proof.keyring_id },
      admissionId: proof.admission_id, workerId: proof.worker_id,
      generation: 3, principal: proof.principal, processEpoch: proof.process_epoch,
      processPid: 1234 }, nowSeconds: 1000 }), /ZK_STOP_PROOF_INVALID/);
  const mutation = await z.decodeDeterministic(signed);
  mutation.process_pid = 9999;
  await assert.rejects(verifyZk1PhysicalStopProof({
    signedProof: Buffer.from(await z.encodeDeterministic(mutation)),
    hostKeyId: proof.host_key_id, hostPublicKey: keys.publicKey,
    expected: { scope: { account_id: proof.account_id,
      compartment_id: proof.compartment_id, keyring_id: proof.keyring_id },
      admissionId: proof.admission_id, workerId: proof.worker_id,
      generation: 3, principal: proof.principal, processEpoch: proof.process_epoch,
      processPid: 1234 }, nowSeconds: 1000 }), /ZK_STOP_PROOF_INVALID/);
});

test("expired, future, wrong-worker, wrong-process, wrong-signing-key STOP receipts all fail closed", async () => {
  const { proof, keys } = sample();
  const wrongKeys = crypto.generateKeyPairSync("ed25519");
  const signed = await signZk1PhysicalStopProof({ proof, privateKey: keys.privateKey });
  const original = { scope: { account_id: proof.account_id,
    compartment_id: proof.compartment_id, keyring_id: proof.keyring_id },
    admissionId: proof.admission_id, workerId: proof.worker_id,
    generation: 3, principal: proof.principal, processEpoch: proof.process_epoch,
    processPid: 1234 };
  const verify = (expected, nowSeconds = 1000, hostPublicKey = keys.publicKey) =>
    verifyZk1PhysicalStopProof({ signedProof: signed, hostKeyId: proof.host_key_id,
      hostPublicKey, expected, nowSeconds });
  await assert.rejects(verify(original, 1051), /ZK_STOP_PROOF_INVALID/);
  await assert.rejects(verify(original, 949), /ZK_STOP_PROOF_INVALID/);
  await assert.rejects(verify({ ...original, workerId: crypto.randomBytes(16) }), /ZK_STOP_PROOF_INVALID/);
  await assert.rejects(verify({ ...original, processEpoch: crypto.randomBytes(16) }), /ZK_STOP_PROOF_INVALID/);
  await assert.rejects(verify({ ...original, processPid: 9999 }), /ZK_STOP_PROOF_INVALID/);
  await assert.rejects(verify(original, 1000, wrongKeys.publicKey), /ZK_STOP_PROOF_INVALID/);
});

test("isolated host signs only after OS-supervised single child actually exits and closes", async (t) => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const hostKeyId = crypto.randomBytes(16);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(7), keyring_id: crypto.randomBytes(16) };
  const workerId = crypto.randomBytes(16);
  const principal = "DD:".repeat(31) + "DD";
  const host = new Zk1IsolatedProcessStopSupervisor({ hostKeyId,
    hostPrivateKey: keys.privateKey,
    workerScript: path.resolve(__dirname, "../lab/issue-65-packet-b/stop-child-worker.js"),
    nowSeconds: () => 900 });
  t.after(() => host.dispose());
  const processBinding = host.launch({ scope, workerId, principal });
  const admissionId = crypto.randomBytes(16);
  const expected = { scope, workerId, principal, admissionId,
    generation: 2, processEpoch: processBinding.processEpoch,
    processPid: processBinding.processPid };
  await assert.rejects(host.stop({ processEpoch: processBinding.processEpoch }),
    /ZK_STOP_SUPERVISOR_UNAVAILABLE/,
    "a process that was never bound to an authenticated admission cannot be attested");
  assert.throws(() => host.bindAdmission({ ...expected,
    processPid: processBinding.processPid + 1 }), /ZK_STOP_SUPERVISOR_UNAVAILABLE/);
  host.bindAdmission(expected);
  assert.throws(() => host.bindAdmission(expected), /ZK_STOP_SUPERVISOR_UNAVAILABLE/,
    "a child may bind to exactly one trusted admission");
  const signed = await host.stop({ processEpoch: processBinding.processEpoch });
  const proof = await verifyZk1PhysicalStopProof({ signedProof: signed,
    hostKeyId, hostPublicKey: keys.publicKey, expected, nowSeconds: 900 });
  assert.equal(proof.processPid, processBinding.processPid);
  assert.deepEqual(await host.stop({ processEpoch: processBinding.processEpoch }), signed,
    "retried STOP returns identical durable wire, never a second signature");
  assert.ok(host.sessions.get(processBinding.processEpoch.toString("hex")).closed);
  assert.ok(host.sessions.get(processBinding.processEpoch.toString("hex")).exited);
});

test("concurrent STOP requests to a single supervised process return exactly one canonical signed receipt", async (t) => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(7), keyring_id: crypto.randomBytes(16) };
  let attestations = 0;
  const host = new Zk1IsolatedProcessStopSupervisor({
    hostKeyId: crypto.randomBytes(16), hostPrivateKey: keys.privateKey,
    workerScript: path.resolve(__dirname, "../lab/issue-65-packet-b/stop-child-worker.js"),
    nowSeconds: () => 900 + (++attestations),
  });
  t.after(() => host.dispose());
  const workerId = crypto.randomBytes(16);
  const principal = "FF:".repeat(31) + "FF";
  const binding = host.launch({ scope, workerId, principal });
  host.bindAdmission({ scope, workerId, principal, processEpoch: binding.processEpoch,
    processPid: binding.processPid, admissionId: crypto.randomBytes(16), generation: 1 });
  const stop = { processEpoch: binding.processEpoch };
  const [first, second, third] = await Promise.all([
    host.stop(stop), host.stop(stop), host.stop(stop),
  ]);
  assert.deepEqual(first, second);
  assert.deepEqual(first, third);
  assert.equal(attestations, 1,
    "a concurrent caller must never receive different STOP times or signature envelopes");
});
