"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const path = require("node:path");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1IsolatedProcessStopSupervisor } = require("../src/services/zk1IsolatedProcessStopSupervisor");
const { createZk1PhysicalStopRecorder } = require("../src/services/zk1SharedPgPhysicalStopRecorder");
const { Zk1LabSupervisedGetEgress } = require("../lab/issue-65-packet-b/supervised-get-egress-controller");

const enabled = Boolean(process.env.ROOTARK_ZK1_TEST_PG_URL
  && process.env.ROOTARK_ZK1_RUNTIME_PG_URL && process.env.ROOTARK_ZK1_STOP_PG_URL);

const key = (scope) => scope.account_id.toString("hex") + ":"
  + scope.compartment_id.length.toString(16) + ":" + scope.compartment_id.toString("hex");

async function context(t) {
  const admin = new Pool({ connectionString: process.env.ROOTARK_ZK1_TEST_PG_URL });
  const runtime = new Pool({ connectionString: process.env.ROOTARK_ZK1_RUNTIME_PG_URL });
  const stop = new Pool({ connectionString: process.env.ROOTARK_ZK1_STOP_PG_URL });
  const scope = { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(9),
    keyring_id: crypto.randomBytes(16) };
  const digest = crypto.randomBytes(32);
  const hostKeys = crypto.generateKeyPairSync("ed25519");
  const hostKeyId = crypto.randomBytes(16);
  const supervisor = new Zk1IsolatedProcessStopSupervisor({ hostKeyId,
    hostPrivateKey: hostKeys.privateKey,
    workerScript: path.resolve(__dirname, "../lab/issue-65-packet-b/supervised-get-egress-child.js"),
    stopTimeoutMs: 5000 });
  t.after(async () => {
    const sessions = [...supervisor.sessions.values()];
    const awaiting = sessions.filter((s) => !s.closed).map((s) => new Promise((resolve) =>
      s.child.once("close", resolve)));
    supervisor.dispose();
    let timer;
    try {
      await Promise.race([Promise.all(awaiting), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("fixture child did not close")), 5000);
      })]);
    } finally { clearTimeout(timer); }
    await Promise.all([admin.end(), runtime.end(), stop.end()]);
  });
  await admin.query(`INSERT INTO zk1_gate.head
    (scope_key,keyring_id,revision,digest,require_stop_proof) VALUES ($1,$2,7,$3,TRUE)`,
  [key(scope), scope.keyring_id, digest]);
  const gate = new Zk1SharedPgGateAuthority({ pool: runtime,
    stopPinned: { hostKeyId, hostPublicKey: hostKeys.publicKey } });
  const recorder = await createZk1PhysicalStopRecorder({ pool: stop,
    trustedHostKeyId: hostKeyId, trustedHostPublicKey: hostKeys.publicKey });
  const controller = new Zk1LabSupervisedGetEgress({ gate, supervisor, recorder });
  const io = { scope, workerId: crypto.randomBytes(16),
    principal: "CB:".repeat(31) + "CB", action: "get",
    objectId: crypto.randomBytes(16).toString("base64url"), revision: 7, digest };
  const reservation = { scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 7, digest };
  return { admin, gate, supervisor, controller, io, reservation, scope };
}

function request(port, token, method = "GET", url = "/fixture-ciphertext") {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port, method, path: url,
      agent: false, headers: { "x-lab-request-token": token } }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode,
        body: Buffer.concat(chunks) }));
      response.on("error", reject);
    });
    req.on("error", reject);
    req.end();
  });
}

function pausedRequest(port, token) {
  return new Promise((resolve, reject) => {
    let gotData = false;
    const req = http.get({ hostname: "127.0.0.1", port,
      path: "/fixture-ciphertext", agent: false,
      headers: { "x-lab-request-token": token } }, (response) => {
      const chunks = [];
      response.once("data", (part) => {
        gotData = true;
        chunks.push(part);
        response.pause(); // Real Node TCP client stops draining the response here.
        resolve({ response, chunks, receivedFirst: part.length,
          drain: () => new Promise((done, fail) => {
            if (response.destroyed || response.complete) {
              done(Buffer.concat(chunks));
              return;
            }
            const settle = () => done(Buffer.concat(chunks));
            response.on("data", (chunk) => chunks.push(chunk));
            response.once("end", settle);
            response.once("close", settle);
            response.once("aborted", settle);
            response.once("error", settle);
            response.resume();
          }) });
      });
      response.once("end", () => { if (!gotData) reject(new Error(
        "fixture responded without ciphertext status=" + response.statusCode)); });
      response.once("error", (e) => { if (!gotData) reject(e); });
    });
    req.once("error", reject);
    req.setTimeout(5000, () => req.destroy(new Error("GET fixture timeout")));
  });
}

test("lab GET requires a separately pinned host, verified STOP recorder and exact trusted GET tuple", {
  skip: !enabled && "disposable PostgreSQL fixture required",
}, async (t) => {
  const c = await context(t);
  const privileged = new Zk1SharedPgGateAuthority({ pool: c.admin,
    stopPinned: c.gate.stopPinned });
  const untrusted = new Zk1LabSupervisedGetEgress({ gate: privileged,
    supervisor: c.supervisor, recorder: c.controller.recorder });
  await assert.rejects(untrusted.begin(c.io), /ZK_GATE_RUNTIME_IDENTITY_INVALID/,
    "superuser/app pool cannot serve as independent GET admission authority");
  const disconnectedGate = new Zk1SharedPgGateAuthority({
    pool: { connect() { throw new Error("synthetic disconnected gate"); } },
    stopPinned: c.gate.stopPinned });
  const disconnected = new Zk1LabSupervisedGetEgress({ gate: disconnectedGate,
    supervisor: c.supervisor, recorder: c.controller.recorder });
  await assert.rejects(disconnected.begin(c.io), /ZK_GATE_RUNTIME_IDENTITY_INVALID/,
    "lost independent gate is a hard GET denial before opening a listener");
  assert.throws(() => new Zk1LabSupervisedGetEgress({ gate: c.gate,
    supervisor: c.supervisor, recorder: {} }), /ZK_LAB_GET_DENIED/);
  await assert.rejects(c.controller.begin({ ...c.io, action: "put" }),
    /ZK_LAB_GET_DENIED/);
  await assert.rejects(c.controller.begin({ ...c.io, processPid: process.pid }),
    /ZK_LAB_GET_DENIED/);
  await assert.rejects(c.controller.begin({ ...c.io, scope: { ...c.scope,
    compartment_id: crypto.randomBytes(9) } }), /ZK_GATE_/);
  assert.equal(c.supervisor.sessions.size, 0,
    "malformed/foreign admissions never launch an egress process");
});

test("real loopback GET partial drain; QUIESCING blocks late grants; exit+close and signed STOP precede FINISHED/PENDING", {
  skip: !enabled && "disposable PostgreSQL fixture required",
}, async (t) => {
  const c = await context(t);
  const { port, token, admissionId, generation, child } = await c.controller.begin(c.io);
  assert.equal(generation, 1);
  assert.equal((await request(port, "wrong-token")).status, 403);
  assert.equal((await request(port, token, "POST")).status, 404);
  assert.equal((await request(port, token, "GET", "/untrusted")).status, 404);

  const stream = await pausedRequest(port, token);
  assert.equal(stream.response.statusCode, 200);
  assert.ok(stream.receivedFirst > 0, "actual receiving TCP peer saw synthetic bytes");
  await c.controller.waitPartial();
  const quiesced = await c.controller.beginQuiesce(c.reservation);
  assert.equal(quiesced.state, "QUIESCING");
  assert.ok(quiesced.activeCount >= 1);
  assert.equal((await request(port, token)).status, 503,
    "late new GET is rejected during QUIESCING while listener still exists");
  const session = [...c.supervisor.sessions.values()][0];
  const old = await c.gate.beginIoAdmission({ ...c.io,
    hostKeyId: c.supervisor.hostKeyId,
    processEpoch: session.processEpoch, processPid: session.processPid });
  assert.equal(old.proceed, false, "old generation cannot be replayed");
  await assert.rejects(c.controller.continueResponse(), /ZK_LAB_GET_DENIED/);
  await assert.rejects(c.gate.finishIoAdmission({ scope: c.scope,
    admissionId, workerId: c.io.workerId, principal: c.io.principal }),
  /ZK_GATE_STOP_PROOF_INVALID/, "operator cannot FINISH with an unclosed egress child");
  await assert.rejects(c.gate.markPending(c.reservation), /ZK_GATE_DRAIN_INCOMPLETE/,
    "no PENDING while direct listener process still owns the socket");
  const stopped = await c.controller.finishAfterQuiesce();
  assert.equal(stopped.status, "FINISHED");
  assert.equal(child.connected, false);
  assert.equal(session.exited, true);
  assert.equal(session.closed, true);
  const proof = await c.admin.query(`SELECT admission_id FROM zk1_gate.physical_stop_receipt
    WHERE admission_id=$1`, [admissionId]);
  assert.equal(proof.rowCount, 1);
  assert.equal((await c.gate.markPending(c.reservation)).status, "PENDING");
  const drained = await stream.drain();
  assert.ok(drained.length > 0 && drained.length < 32768,
    "partial bytes emitted earlier survive stop, withheld continuation never emits");
  await assert.rejects(request(port, token), /ECONNREFUSED|ECONNRESET|socket hang up/,
    "old GET cannot reconnect or resume on the terminated fixture listener");
  await assert.rejects(c.controller.begin(c.io), /ZK_LAB_GET_DENIED/);
});

test("forced SIGKILL of streaming child still requires independently observed OS close before STOP", {
  skip: !enabled && "disposable PostgreSQL fixture required",
}, async (t) => {
  const c = await context(t);
  const { child, port, token } = await c.controller.begin(c.io);
  const stream = await pausedRequest(port, token);
  await c.controller.waitPartial();
  assert.equal((await c.controller.beginQuiesce(c.reservation)).state, "QUIESCING");
  assert.equal(child.kill("SIGKILL"), true);
  await new Promise((resolve) => child.once("close", resolve));
  assert.equal((await c.controller.finishAfterQuiesce()).status, "FINISHED");
  assert.equal((await c.gate.markPending(c.reservation)).status, "PENDING");
  await assert.rejects(c.controller.continueResponse(), /ZK_LAB_GET_DENIED/);
  assert.ok((await stream.drain()).length > 0);
  await assert.rejects(request(port, token), /ECONNREFUSED|ECONNRESET|socket hang up/);
});

test("a live exact GET admits one further chunk, while response completion alone cannot certify STOP", {
  skip: !enabled && "disposable PostgreSQL fixture required",
}, async (t) => {
  const c = await context(t);
  const { port, token, admissionId } = await c.controller.begin(c.io);
  const fetching = request(port, token);
  await c.controller.waitPartial();
  await c.controller.continueResponse();
  const delivered = await fetching;
  assert.equal(delivered.status, 200);
  assert.equal(delivered.body.length, 32768);
  assert.equal((await request(port, token)).status, 503, "single GET stream per fixture worker");
  assert.equal((await c.controller.beginQuiesce(c.reservation)).state, "QUIESCING");
  await assert.rejects(c.gate.finishIoAdmission({ scope: c.scope,
    admissionId, workerId: c.io.workerId, principal: c.io.principal }),
  /ZK_GATE_STOP_PROOF_INVALID/,
  "even a finished HTTP response leaves its owning process alive");
  assert.equal((await c.controller.finishAfterQuiesce()).status, "FINISHED");
  assert.equal((await c.gate.markPending(c.reservation)).status, "PENDING");
});
