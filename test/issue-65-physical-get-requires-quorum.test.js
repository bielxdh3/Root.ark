"use strict";

// Offline constructor regression. No PostgreSQL, Docker, TLS server or sockets
// are created here: VM-resolved dependencies let us exercise the actual
// controller's fail-closed boundary before a runtime pool is even consulted.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");

function fixture() {
  const filename = process.env.ZK65_GET_CONSTRUCTOR_REGRESSION_SOURCE
    || path.join(__dirname, "../lab/issue-65-packet-b/supervised-get-egress-controller.js");
  class Gate {}
  class Supervisor {}
  class Reader {}
  class Guard { async authorize() { return true; } }
  const host = crypto.generateKeyPairSync("ed25519");
  const hostKeyId = crypto.randomBytes(16);
  const gate = Object.assign(new Gate(), { stopPinned: {
    hostKeyId, hostPublicKey: host.publicKey } });
  const supervisor = Object.assign(new Supervisor(), {
    hostKeyId, hostPrivateKey: host.privateKey });
  const recorder = { hostKeyId, hostPublicKey: host.publicKey };
  const reader = Object.assign(new Reader(), { gate });
  const guard = new Guard();
  const dependencies = {
    "../../src/services/zk1SharedPgGateAuthority": { Zk1SharedPgGateAuthority: Gate },
    "../../src/services/zk1SharedPgGateRuntime": { verifyZk1SharedPgRuntimePool: async () => {} },
    "../../src/services/zk1IsolatedProcessStopSupervisor": { Zk1IsolatedProcessStopSupervisor: Supervisor },
    "../../src/services/zk1SharedPgPhysicalStopRecorder": {
      isVerifiedZk1PhysicalStopRecorder: (candidate) => candidate === recorder },
    "../../src/services/zk1SharedPgSealedGetReader": { Zk1SharedPgSealedGetReader: Reader },
    "../../src/services/zk1SharedPgWitnessCasEgressGuard": {
      Zk1SharedPgWitnessCasEgressGuard: Guard },
  };
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(filename, "utf8"), {
    module, exports: module.exports, Buffer, setTimeout, clearTimeout,
    require(name) {
      if (name === "node:crypto") return crypto;
      if (Object.hasOwn(dependencies, name)) return dependencies[name];
      throw Error("Unexpected fixture import " + name);
    },
  }, { filename });
  return { Controller: module.exports.Zk1LabSupervisedGetEgress,
    gate, supervisor, recorder, reader, guard, root: crypto.randomBytes(32) };
}

test("real physical GET defaults to mandatory owner-SPKI + signed witness guard; untrusted bypass flags fail", () => {
  const { Controller, gate, supervisor, recorder, reader, guard, root } = fixture();
  const base = { gate, supervisor, recorder, ciphertextReader: reader,
    expectedRootHash: root };
  for (const attempt of [base, { ...base, quorumGuard: null },
    { ...base, quorumGuard: false }, { ...base, allowUnverified: true },
    { ...base, legacyLabMode: true }, { ...base, unsafeLegacyLabOnly: true },
    { gate, supervisor, recorder },
  ]) assert.throws(() => new Controller(attempt), /ZK_LAB_GET_DENIED/);
  const guarded = new Controller({ ...base, quorumGuard: guard });
  assert.equal(guarded.quorumGuard, guard);
  guarded.unsafeLegacyLabOnly = true;
  assert.equal(Object.hasOwn(guarded, "unsafeLegacyLabOnly"), true,
    "attempting to set a public flag does not control the private lab capability");
});

test("legacy synthetic/physical path requires disjoint explicit unsafe fixture factory", () => {
  const { Controller, gate, supervisor, recorder, reader, guard, root } = fixture();
  const legacy = Controller.createUnsafeLegacyLabFixture({ gate, supervisor, recorder });
  assert.equal(legacy.ciphertextReader, undefined);
  const oldPhysical = Controller.createUnsafeLegacyLabFixture({ gate, supervisor,
    recorder, ciphertextReader: reader, expectedRootHash: root });
  assert.equal(oldPhysical.ciphertextReader, reader);
  assert.throws(() => Controller.createUnsafeLegacyLabFixture({ gate, supervisor,
    recorder, ciphertextReader: reader, expectedRootHash: root, quorumGuard: guard }),
  /ZK_LAB_GET_DENIED/, "an established guard must never silently downgrade to unsafe mode");
  assert.throws(() => Controller.createUnsafeLegacyLabFixture({ gate, supervisor,
    recorder, allowUnverified: true }), /ZK_LAB_GET_DENIED/);
});

function pendingPhysicalContinuation(f) {
  const { Controller, gate, supervisor, recorder, reader, guard, root } = f;
  const controller = new Controller({ gate, supervisor, recorder,
    ciphertextReader: reader, expectedRootHash: root, quorumGuard: guard });
  const admissionId = crypto.randomBytes(16);
  const processInfo = { hostKeyId: supervisor.hostKeyId,
    processEpoch: crypto.randomBytes(16), processPid: 5193 };
  const sends = [];
  controller.phase = "listening";
  controller.partial = true;
  controller.stopping = false;
  controller.process = processInfo;
  controller.generation = 1;
  controller.admissionId = admissionId;
  controller.io = { scope: { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("test"), keyring_id: crypto.randomBytes(16) },
  workerId: crypto.randomBytes(16), principal: "AB:".repeat(31) + "AB",
  action: "get", objectId: crypto.randomBytes(16).toString("base64url"),
  revision: 7, digest: crypto.randomBytes(32) };
  controller.session = { closed: false, exited: false, aborted: false,
    child: { connected: true, exitCode: null, signalCode: null,
      send: (message) => sends.push(message) } };
  supervisor.assertLive = () => true;
  reader.readChunk = async () => Buffer.alloc(16384, 0xa5);
  return { gate, guard, controller, admissionId, sends };
}

test("concurrent hardened continuation cannot issue two physical ciphertext IPC frames", async () => {
  const f = pendingPhysicalContinuation(fixture());
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  f.gate.beginIoAdmission = async () => {
    await blocked;
    return { proceed: true, admissionId: f.admissionId, generation: 1 };
  };
  const first = f.controller.continueResponse();
  await assert.rejects(f.controller.continueResponse(), /ZK_LAB_GET_DENIED/);
  assert.equal(f.sends.length, 0, "no IPC write before physical gate admission settles");
  release();
  await first;
  assert.equal(f.sends.length, 1, "at most one second frame is emitted");
  assert.equal(f.sends[0].kind, "continue");
  assert.equal(Buffer.from(f.sends[0].ciphertextBase64, "base64url").length, 16384);
  assert.equal(f.controller.partial, false);
});

test("hardened mTLS witness outage rejects continuation before any socket grant", async () => {
  const f = pendingPhysicalContinuation(fixture());
  f.gate.beginIoAdmission = async () => ({ proceed: true,
    admissionId: f.admissionId, generation: 1 });
  f.guard.authorize = async () => { throw Error("mTLS witness partition"); };
  const attempted = await Promise.allSettled([
    f.controller.continueResponse(), f.controller.continueResponse(),
  ]);
  assert.equal(attempted.filter((x) => x.status === "rejected").length, 2);
  assert.equal(f.sends.length, 0, "partition cannot authorize new physical IPC egress");
  assert.equal(f.controller.partial, true);
  assert.equal(f.controller.stopping, true, "witness loss latches permanent GET stop");
  f.guard.authorize = async () => true;
  f.controller.stopping = false;
  await assert.rejects(f.controller.continueResponse(), /ZK_LAB_GET_DENIED/,
    "even a restored witness and forged public stop flag cannot revive fenced GET");
  assert.equal(f.sends.length, 0);
});
