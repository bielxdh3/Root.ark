"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const fs = require("node:fs");
const { fork } = require("node:child_process");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1IsolatedProcessStopSupervisor } = require("../src/services/zk1IsolatedProcessStopSupervisor");
const { createZk1PhysicalStopRecorder } = require("../src/services/zk1SharedPgPhysicalStopRecorder");
const { Zk1SharedPgSealedObjectStore } = require("../src/services/zk1SharedPgSealedObjectStore");
const { Zk1SharedPgSealedGetReader } = require("../src/services/zk1SharedPgSealedGetReader");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1LabSupervisedGetEgress } = require("../lab/issue-65-packet-b/supervised-get-egress-controller");
const { Zk1SharedPgWitnessCasEgressGuard } =
  require("../src/services/zk1SharedPgWitnessCasEgressGuard");
const { Zk1WitnessCasAnchorHttpsClient } =
  require("../src/services/zk1WitnessCasAnchorHttpsClient");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const ownerRoots = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");
const ownerHistory = require("../public/client/rootark-zk1-owner-signed-checkpoint");

const enabled = Boolean(process.env.ROOTARK_ZK1_TEST_PG_URL
  && process.env.ROOTARK_ZK1_RUNTIME_PG_URL && process.env.ROOTARK_ZK1_STOP_PG_URL);
// The test requires a genuine native SQLite implementation in the separate
// witness process. A Windows .node addon mounted into WSL cannot load as ELF.
const nativeWitnessSqliteReady = (() => {
  try { const Database = require("better-sqlite3");
    const db = new Database(":memory:"); db.close(); return true; }
  catch (_) { return false; }
})();

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
  const controller = Zk1LabSupervisedGetEgress.createUnsafeLegacyLabFixture({ gate, supervisor, recorder });
  const io = { scope, workerId: crypto.randomBytes(16),
    principal: "CB:".repeat(31) + "CB", action: "get",
    objectId: crypto.randomBytes(16).toString("base64url"), revision: 7, digest };
  const reservation = { scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 7, digest };
  return { admin, runtime, gate, supervisor, controller, io, reservation, scope };
}

async function seedActualSealedCiphertext(c) {
  // The fixtures deliberately keep gate, writer and STOP as distinct
  // privileges. Real bounded ciphertext is persisted, physically sealed and
  // the original supervised PUT process is independently STOP-attested.
  const chunks = [crypto.randomBytes(16384), crypto.randomBytes(16384)];
  const rootHash = computeZk1CiphertextRoot(chunks);
  const put = { ...c.io, action: "put", workerId: crypto.randomBytes(16) };
  const proc = c.supervisor.launch({ scope: c.scope,
    workerId: put.workerId, principal: put.principal });
  const admitted = await c.gate.beginIoAdmission({ ...put, ...proc });
  c.supervisor.bindAdmission({ ...proc, scope: c.scope, workerId: put.workerId,
    principal: put.principal, admissionId: admitted.admissionId,
    generation: admitted.generation });
  for (let i = 0; i < chunks.length; ++i) {
    assert.deepEqual(await c.gate.putCiphertextChunk({ ...put,
      admissionId: admitted.admissionId, generation: admitted.generation }, i, chunks[i]),
    { stored: true });
  }
  const sealed = new Zk1SharedPgSealedObjectStore({ pool: c.runtime });
  assert.equal((await sealed.seal({ ...put, admissionId: admitted.admissionId,
    generation: admitted.generation, expectedChunkCount: 2,
    expectedRootHash: rootHash })).status, "SEALED");
  const signedProof = await c.supervisor.stop({ processEpoch: proc.processEpoch });
  const stopped = await c.controller.recorder.record({ signedProof,
    expected: { scope: c.scope, workerId: put.workerId, principal: put.principal,
      admissionId: admitted.admissionId, generation: admitted.generation,
      processEpoch: proc.processEpoch, processPid: proc.processPid } });
  assert.equal(stopped.status, "STOP_ATTESTED");
  assert.equal((await c.gate.finishIoAdmission({ scope: c.scope,
    workerId: put.workerId, principal: put.principal,
    admissionId: admitted.admissionId })).status, "FINISHED");
  return { chunks, rootHash };
}

function onceChild(child, kind, timeoutMs = 25000) {
  return new Promise((resolve, reject) => {
    let lastStage = "spawn";
    const finish = () => { clearTimeout(timeout); child.off("message", onMessage);
      child.off("exit", onExit); child.off("error", onExit); };
    const onMessage = (message) => {
      if (message?.kind === "stage") { lastStage = message.step; return; }
      if (message?.kind === "failed") { finish(); reject(Error("fixture witness unavailable at " + message.stage)); }
      if (message?.kind === kind) { finish(); resolve(message); }
    };
    const onExit = () => { finish(); reject(Error("fixture witness exited at " + lastStage)); };
    const timeout = setTimeout(onExit, timeoutMs);
    child.on("message", onMessage);
    child.once("exit", onExit);
    child.once("error", onExit);
  });
}

async function isolatedWitness(t) {
  const dir = createPrivateAuthorityFixture("zk65-quorum-witness-");
  generateNativeFixtureCertificates(dir, { caSubject: "Quorum Lab CA",
    servers: ["server"], clients: ["allowed", "denied"] });
  const child = fork(path.join(__dirname, "support/issue-65-mtls-quorum-child.js"), [], {
    stdio: ["ignore", "ignore", "ignore", "ipc"],
    windowsHide: true, execArgv: [],
    env: { NODE_ENV: "test", NODE_PATH: process.env.NODE_PATH || "",
      SystemRoot: process.env.SystemRoot || "" },
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    if (!child.killed) child.disconnect();
    await new Promise((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) return resolve();
      child.once("close", resolve);
      setTimeout(resolve, 5000).unref();
    });
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const ready = onceChild(child, "listening");
  child.send({ kind: "init", dir });
  const started = await ready;
  assert.equal(started.host, "127.0.0.1", "independent mTLS witness binds IPv4 loopback only");
  const read = (name) => fs.readFileSync(path.join(dir, name));
  // The child listens on IPv4 only. Node 22 resolves localhost as IPv6 first
  // on Windows, wasting a failed connect attempt under a bounded TLS deadline.
  // The fixture certificate explicitly contains IP:127.0.0.1 SAN, so using
  // the numeric address keeps BOTH X.509 hostname and fingerprint checks.
  assert.equal(new crypto.X509Certificate(read("server.pem")).checkIP(started.host),
    started.host, "certificate must validate the exact loopback endpoint");
  const config = { endpoint: `https://${started.host}:${started.port}`,
    ca: read("ca.pem"), clientKey: read("allowed.key"),
    clientCert: read("allowed.pem"),
    serverFingerprint256: new crypto.X509Certificate(read("server.pem")).fingerprint256,
    pinnedWitnessPublicKey: crypto.createPublicKey({ key: Buffer.from(started.witnessSpki, "base64url"),
      format: "der", type: "spki" }),
    pinnedWitnessKeyId: Buffer.from(started.witnessKeyId, "base64url"),
    pinnedStatusKeyId: Buffer.from(started.statusKeyId, "base64url"),
    headTimeoutMs: 6000 };
  const client = new Zk1WitnessCasAnchorHttpsClient(config);
  const genesis = await client.freshHead();
  assert.deepEqual(genesis, { sequence: 0, lastHash: "0".repeat(64) });
  return { child, client, config, genesis,
    async advance() { const progressed = onceChild(child, "advanced");
      child.send({ kind: "advance" }); return progressed; } };
}

async function signedRootFor(c, root) {
  const signer = crypto.generateKeyPairSync("ed25519");
  const ownerPublicSpki = signer.publicKey.export({ format: "der", type: "spki" });
  const privateKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    signer.privateKey.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  const publicKey = await crypto.webcrypto.subtle.importKey("spki",
    ownerPublicSpki, "Ed25519", false, ["verify"]);
  const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
    .map((name) => [name, c.scope[name].toString("base64url")]));
  const signerKeyId = crypto.randomBytes(16);
  const ownerHistoryCheckpoint = await ownerHistory.signOwnerCheckpoint({
    scope, signerKey: privateKey, signerPublicKey: publicKey,
    signerKeyId, deviceId: "fixture-owner", revision: c.io.revision,
    manifestDigest: c.io.digest, issuedAt: 101, previous: null });
  const checkpoint = await ownerRoots.signOwnerCiphertextRootCheckpoint({
    scope, signerKey: privateKey, signerKeyId, deviceId: "fixture-owner",
    manifestRevision: c.io.revision, manifestDigest: c.io.digest,
    manifestEpoch: 2, objectId: c.io.objectId,
    objectRevision: c.io.revision, ciphertextEpoch: 1,
    ciphertextRoot: root, issuedAt: 102 });
  return { ownerPublicSpki,
    externallyPinnedOwnerSpkiSha256: crypto.createHash("sha256").update(ownerPublicSpki).digest(),
    ownerProofInput: { checkpoint, ownerHistoryCheckpoint,
      previousHistoryProof: null,
      pinnedOwner: { scope, deviceId: "fixture-owner", signerKeyId,
        publicKey },
      expected: { manifestRevision: c.io.revision, manifestDigest: Buffer.from(c.io.digest),
        manifestEpoch: 2, objectId: c.io.objectId,
        objectRevision: c.io.revision, ciphertextEpoch: 1,
        ciphertextRoot: Buffer.from(root) } } };
}

test("separate OS witness signer retains real mTLS nonce-signed CAS floor and exact external owner SPKI pin", {
  skip: !nativeWitnessSqliteReady && "native witness SQLite addon unavailable in this Node environment",
}, async (t) => {
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("quorum-unit"), keyring_id: crypto.randomBytes(16) };
  const io = { scope, workerId: crypto.randomBytes(16),
    principal: "AB:".repeat(31) + "AB", action: "get",
    objectId: crypto.randomBytes(16).toString("base64url"),
    revision: 7, digest: crypto.randomBytes(32) };
  const root = crypto.randomBytes(32);
  const trust = await signedRootFor({ scope, io }, root);
  const witness = await isolatedWitness(t);
  // All three failures must remain closed despite using a deterministic IPv4
  // transport. A rejected attempt must not poison the valid pinned client.
  const badTlsPin = new Zk1WitnessCasAnchorHttpsClient({ ...witness.config,
    serverFingerprint256: "00:".repeat(31) + "00" });
  await assert.rejects(badTlsPin.freshHead(), /CAS_WITNESS_FLOOR_UNAVAILABLE/,
    "wrong X.509 peer fingerprint must never return a signed floor");
  const badWitnessPin = new Zk1WitnessCasAnchorHttpsClient({ ...witness.config,
    pinnedWitnessPublicKey: crypto.generateKeyPairSync("ed25519").publicKey });
  await assert.rejects(badWitnessPin.freshHead(), /CAS_WITNESS_FLOOR_UNAVAILABLE/,
    "a different Ed25519 witness authority cannot sign the pinned floor");
  const unavailablePort = await new Promise((resolve, reject) => {
    const listener = net.createServer();
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", () => {
      const port = listener.address().port;
      listener.close(() => resolve(port));
    });
  });
  const partitioned = new Zk1WitnessCasAnchorHttpsClient({ ...witness.config,
    endpoint: `https://127.0.0.1:${unavailablePort}`, headTimeoutMs: 1000 });
  await assert.rejects(partitioned.freshHead(), /CAS_WITNESS_FLOOR_UNAVAILABLE/,
    "partitioned loopback witness cannot admit a GET");
  assert.deepEqual(await witness.client.freshHead(witness.genesis), witness.genesis,
    "a valid pinned connection recovers only after a fresh nonce-signed floor");
  const config = { witness: witness.client, witnessFloor: witness.genesis, ...trust };
  const guard = await Zk1SharedPgWitnessCasEgressGuard.establish(config);
  assert.equal(await guard.authorize({ io, expectedRootHash: root }), true);
  const racingTrust = await signedRootFor({ scope, io }, root);
  const changingClient = new Zk1WitnessCasAnchorHttpsClient(witness.config);
  const originalFresh = changingClient.freshHead.bind(changingClient);
  changingClient.freshHead = async (minimum) => {
    const answer = await originalFresh(minimum);
    racingTrust.ownerProofInput.expected.ciphertextRoot.fill(0);
    racingTrust.ownerProofInput.expected.manifestDigest.fill(0);
    racingTrust.ownerProofInput.pinnedOwner.scope.account_id = crypto.randomBytes(16).toString("base64url");
    return answer;
  };
  const raceSafe = await Zk1SharedPgWitnessCasEgressGuard.establish({
    ...racingTrust, witness: changingClient, witnessFloor: witness.genesis });
  assert.equal(await raceSafe.authorize({ io, expectedRootHash: root }), true,
    "caller mutation across a signed-head await cannot retarget verified owner ciphertext");
  for (const attack of [
    { io: { ...io, objectId: crypto.randomBytes(16).toString("base64url") }, expectedRootHash: root },
    { io: { ...io, revision: 8 }, expectedRootHash: root },
    { io: { ...io, scope: { ...scope, keyring_id: crypto.randomBytes(16) } }, expectedRootHash: root },
    { io, expectedRootHash: crypto.randomBytes(32) },
  ]) await assert.rejects(guard.authorize(attack), /ZK_LAB_QUORUM_UNAVAILABLE/);
  assert.equal((await witness.advance()).sequence, 1);
  await assert.rejects(guard.authorize({ io, expectedRootHash: root }),
    /ZK_LAB_QUORUM_UNAVAILABLE/);
  // A caller retaining the client instance must not replace its method with
  // a fake matching floor and bypass the originally pinned TLS/Ed25519 check.
  witness.client.freshHead = async () => ({ ...witness.genesis });
  await assert.rejects(guard.authorize({ io, expectedRootHash: root }),
    /ZK_LAB_QUORUM_UNAVAILABLE/,
    "a replaced witness method cannot reopen egress after a real signed floor advance");
  await assert.rejects(Zk1SharedPgWitnessCasEgressGuard.establish(config),
    /ZK_LAB_QUORUM_UNAVAILABLE/,
    "a replaced witness method cannot bootstrap a stale floor after real advancement");
  class SubstitutedWitness extends Zk1WitnessCasAnchorHttpsClient {
    async freshHead() { return { ...witness.genesis }; }
  }
  await assert.rejects(Zk1SharedPgWitnessCasEgressGuard.establish({ ...config,
    witness: new SubstitutedWitness(witness.config) }),
  /ZK_LAB_QUORUM_UNAVAILABLE/,
  "a subclass method must never impersonate the pinned native floor transport");
});

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
  const untrusted = Zk1LabSupervisedGetEgress.createUnsafeLegacyLabFixture({ gate: privileged,
    supervisor: c.supervisor, recorder: c.controller.recorder });
  await assert.rejects(untrusted.begin(c.io), /ZK_GATE_RUNTIME_IDENTITY_INVALID/,
    "superuser/app pool cannot serve as independent GET admission authority");
  const disconnectedGate = new Zk1SharedPgGateAuthority({
    pool: { connect() { throw new Error("synthetic disconnected gate"); } },
    stopPinned: c.gate.stopPinned });
  const disconnected = Zk1LabSupervisedGetEgress.createUnsafeLegacyLabFixture({ gate: disconnectedGate,
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

test("concurrent continuation admits exactly one second frame before quiescence and physical STOP", {
  skip: !enabled && "disposable PostgreSQL fixture required",
}, async (t) => {
  const c = await context(t);
  const { port, token } = await c.controller.begin(c.io);
  const stream = await pausedRequest(port, token);
  await c.controller.waitPartial();
  const results = await Promise.allSettled([
    c.controller.continueResponse(), c.controller.continueResponse(),
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1,
    "overlapping grant callbacks must not both write the same ciphertext frame");
  assert.equal(results.filter((result) => result.status === "rejected"
    && /ZK_LAB_GET_DENIED/.test(result.reason?.message)).length, 1);
  assert.equal((await stream.drain()).length, 32768,
    "exactly two 16KiB frames may reach the peer");
  assert.equal((await c.controller.beginQuiesce(c.reservation)).state, "QUIESCING");
  await assert.rejects(c.gate.markPending(c.reservation), /ZK_GATE_DRAIN_INCOMPLETE/);
  assert.equal((await c.controller.finishAfterQuiesce()).status, "FINISHED");
  assert.equal((await c.gate.markPending(c.reservation)).status, "PENDING");
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

test("lost ACK after durable QUIESCING retries exact reservation but never reopens egress", {
  skip: !enabled && "disposable PostgreSQL fixture required",
}, async (t) => {
  const c = await context(t);
  const { port, token } = await c.controller.begin(c.io);
  const stream = await pausedRequest(port, token);
  await c.controller.waitPartial();
  const actual = c.gate.beginQuiesce.bind(c.gate);
  let injected = false;
  c.gate.beginQuiesce = async (operation) => {
    const result = await actual(operation);
    if (!injected) {
      injected = true;
      throw new Error("synthetic LOST_QUIESCE_ACK after PG COMMIT");
    }
    return result;
  };
  await assert.rejects(c.controller.beginQuiesce(c.reservation), /LOST_QUIESCE_ACK/,
    "transaction may be committed even though its ACK is lost");
  const durable = await c.admin.query("SELECT phase,operation_id,reservation_id FROM zk1_gate.head WHERE scope_key=$1",
    [key(c.scope)]);
  assert.equal(durable.rows[0].phase, "QUIESCING");
  assert.deepEqual(durable.rows[0].operation_id, c.reservation.operationId);
  await assert.rejects(c.controller.continueResponse(), /ZK_LAB_GET_DENIED/,
    "no further GET bytes may be granted while quiesce ACK is missing");
  assert.equal((await request(port, token)).status, 503,
    "new GET requests must remain blocked until physical STOP");
  await assert.rejects(c.controller.beginQuiesce({
    ...c.reservation, reservationId: crypto.randomBytes(16),
  }), /ZK_LAB_GET_DENIED/,
  "retry with a new reservation must not claim a foreign transition");
  assert.equal((await c.controller.beginQuiesce(c.reservation)).state, "QUIESCING",
    "exact retry must re-read already committed authority state");
  assert.equal((await c.controller.finishAfterQuiesce()).status, "FINISHED");
  assert.equal((await c.gate.markPending(c.reservation)).status, "PENDING");
  assert.ok((await stream.drain()).length > 0);
});

test("physical ciphertext GET defaults to mandatory owner-SPKI and mTLS witness quorum even with correct sealed root", {
  skip: !enabled && "disposable PostgreSQL fixture required",
}, async (t) => {
  const c = await context(t);
  const { rootHash } = await seedActualSealedCiphertext(c);
  const physical = { gate: c.gate, supervisor: c.supervisor,
    recorder: c.controller.recorder,
    ciphertextReader: new Zk1SharedPgSealedGetReader({ gate: c.gate }),
    expectedRootHash: rootHash };
  for (const attempt of [physical,
    { ...physical, quorumGuard: null },
    { ...physical, allowUnverified: true },
    { ...physical, legacyLabMode: true },
  ]) assert.throws(() => new Zk1LabSupervisedGetEgress(attempt),
    /ZK_LAB_GET_DENIED/, "operator-supplied bypass flags never grant physical ciphertext GET");
  assert.equal(c.supervisor.sessions.size, 1,
    "no unauthorized GET worker may start; the seeded PUT worker already STOPPED");
});

test("physical sealed PostgreSQL ciphertext reaches supervised HTTP peer byte-for-byte; forged root fails closed", {
  skip: !enabled && "disposable PostgreSQL fixture required",
}, async (t) => {
  const c = await context(t);
  const { chunks, rootHash } = await seedActualSealedCiphertext(c);
  const reader = new Zk1SharedPgSealedGetReader({ gate: c.gate });
  const wrongRoot = Zk1LabSupervisedGetEgress.createUnsafeLegacyLabFixture({ gate: c.gate,
    supervisor: c.supervisor, recorder: c.controller.recorder,
    ciphertextReader: reader, expectedRootHash: crypto.randomBytes(32) });
  const wrongIo = { ...c.io, workerId: crypto.randomBytes(16) };
  const forged = await wrongRoot.begin(wrongIo);
  assert.equal((await request(forged.port, forged.token)).status, 503,
    "an unverified commitment cannot release even the first physical ciphertext byte");
  const forgedQuiesce = { ...c.reservation };
  // A refused transfer still requires physical STOP before FINISH or PENDING.
  const controller = Zk1LabSupervisedGetEgress.createUnsafeLegacyLabFixture({ gate: c.gate,
    supervisor: c.supervisor, recorder: c.controller.recorder,
    ciphertextReader: reader, expectedRootHash: rootHash });
  const admitted = await controller.begin(c.io);
  const delivered = request(admitted.port, admitted.token);
  await controller.waitPartial();
  await controller.continueResponse();
  const response = await delivered;
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, Buffer.concat(chunks),
    "GET must transfer actual persisted, sealed ciphertext rather than generated bytes");
  await controller.beginQuiesce(forgedQuiesce);
  await wrongRoot.beginQuiesce(forgedQuiesce);
  await Promise.all([controller.finishAfterQuiesce(), wrongRoot.finishAfterQuiesce()]);
  assert.equal((await c.gate.markPending(forgedQuiesce)).status, "PENDING");
});

test("a second PostgreSQL gate host quiesces while real ciphertext GET is partial, fencing continuation", {
  skip: !enabled && "disposable PostgreSQL fixture required",
}, async (t) => {
  const c = await context(t);
  const { chunks, rootHash } = await seedActualSealedCiphertext(c);
  const reader = new Zk1SharedPgSealedGetReader({ gate: c.gate });
  const controller = Zk1LabSupervisedGetEgress.createUnsafeLegacyLabFixture({ gate: c.gate,
    supervisor: c.supervisor, recorder: c.controller.recorder,
    ciphertextReader: reader, expectedRootHash: rootHash });
  const { port, token, admissionId, generation } = await controller.begin(c.io);
  const stream = await pausedRequest(port, token);
  await controller.waitPartial();
  assert.deepEqual(stream.chunks[0], chunks[0], "the TCP peer receives physical ciphertext");
  const remotePool = new Pool({ connectionString: process.env.ROOTARK_ZK1_RUNTIME_PG_URL });
  t.after(() => remotePool.end());
  const remote = new Zk1SharedPgGateAuthority({ pool: remotePool,
    stopPinned: c.gate.stopPinned });
  assert.equal((await remote.beginQuiesce(c.reservation)).state, "QUIESCING");
  const old = await c.gate.beginIoAdmission({ ...c.io,
    hostKeyId: c.supervisor.hostKeyId,
    processEpoch: controller.process.processEpoch, processPid: controller.process.processPid });
  assert.equal(old.proceed, false);
  assert.equal(old.generation, generation);
  assert.deepEqual(old.admissionId, admissionId);
  await assert.rejects(controller.continueResponse(), /ZK_LAB_GET_DENIED/);
  await assert.rejects(reader.readChunk({ io: c.io, process: controller.process,
    admissionId, generation, expectedRootHash: rootHash, chunkIndex: 1 }),
  /ZK_GATE_GET_DENIED/, "a second host's committed generation change disables DB read");
  await assert.rejects(c.gate.markPending(c.reservation), /ZK_GATE_DRAIN_INCOMPLETE/);
  assert.equal((await controller.beginQuiesce(c.reservation)).state, "QUIESCING");
  assert.equal((await controller.finishAfterQuiesce()).status, "FINISHED");
  assert.equal((await remote.markPending(c.reservation)).status, "PENDING");
  assert.deepEqual(await stream.drain(), chunks[0],
    "the next ciphertext chunk is never emitted once the separate host commits QUIESCING");
});

test("GET gate connection loss denies further physical ciphertext; surviving gate can quiesce and record original STOP", {
  skip: !enabled && "disposable PostgreSQL fixture required",
}, async (t) => {
  const c = await context(t);
  const { chunks, rootHash } = await seedActualSealedCiphertext(c);
  const isolatedPool = new Pool({ connectionString: process.env.ROOTARK_ZK1_RUNTIME_PG_URL });
  const isolatedGate = new Zk1SharedPgGateAuthority({ pool: isolatedPool,
    stopPinned: c.gate.stopPinned });
  const controller = Zk1LabSupervisedGetEgress.createUnsafeLegacyLabFixture({ gate: isolatedGate,
    supervisor: c.supervisor, recorder: c.controller.recorder,
    ciphertextReader: new Zk1SharedPgSealedGetReader({ gate: isolatedGate }),
    expectedRootHash: rootHash });
  const { port, token, admissionId, generation } = await controller.begin(c.io);
  const stream = await pausedRequest(port, token);
  await controller.waitPartial();
  assert.deepEqual(stream.chunks[0], chunks[0]);
  // The egress host loses its only gate connection after real bytes were sent;
  // a separately provisioned surviving controller still shares the durable PG.
  await isolatedPool.end();
  await assert.rejects(controller.continueResponse(), /ZK_GATE_UNAVAILABLE|ZK_LAB_GET_DENIED/);
  assert.equal((await c.gate.beginQuiesce(c.reservation)).state, "QUIESCING");
  await assert.rejects(controller.beginQuiesce(c.reservation), /ZK_GATE_UNAVAILABLE/);
  await assert.rejects(c.gate.markPending(c.reservation), /ZK_GATE_DRAIN_INCOMPLETE/);
  const proof = await c.supervisor.stop({ processEpoch: controller.process.processEpoch });
  const recorded = await c.controller.recorder.record({ signedProof: proof, expected: {
    scope: c.scope, admissionId, workerId: c.io.workerId,
    principal: c.io.principal, generation,
    processEpoch: controller.process.processEpoch,
    processPid: controller.process.processPid,
  } });
  assert.equal(recorded.status, "STOP_ATTESTED");
  assert.equal((await c.gate.finishIoAdmission({ scope: c.scope,
    workerId: c.io.workerId, principal: c.io.principal, admissionId })).status, "FINISHED");
  assert.equal((await c.gate.markPending(c.reservation)).status, "PENDING");
  assert.deepEqual(await stream.drain(), chunks[0],
    "a disconnected GET host cannot send its second SQL-validated physical frame");
});

test("independent witness/CAS mTLS process plus externally SPKI-pinned owner history gates real physical ciphertext", {
  skip: !enabled ? "disposable PostgreSQL fixture required"
    : !nativeWitnessSqliteReady && "native witness SQLite addon unavailable in this Node environment",
}, async (t) => {
  const c = await context(t);
  const { chunks, rootHash } = await seedActualSealedCiphertext(c);
  const trust = await signedRootFor(c, rootHash);
  const witness = await isolatedWitness(t);
  const pin = { witness: witness.client, witnessFloor: witness.genesis, ...trust };
  const guard = await Zk1SharedPgWitnessCasEgressGuard.establish(pin);
  await assert.rejects(Zk1SharedPgWitnessCasEgressGuard.establish({ ...pin,
    externallyPinnedOwnerSpkiSha256: crypto.randomBytes(32) }), /ZK_LAB_QUORUM_UNAVAILABLE/,
  "wrong operator SPKI fingerprint must reject before PG/HTTP GET");
  await assert.rejects(Zk1SharedPgWitnessCasEgressGuard.establish({ ...pin,
    ownerProofInput: { ...trust.ownerProofInput,
      checkpoint: { ...trust.ownerProofInput.checkpoint, ciphertext_root:
        crypto.randomBytes(32).toString("base64url") } } }),
  /ZK_LAB_QUORUM_UNAVAILABLE/, "tampered signed historical root is rejected");
  const controller = new Zk1LabSupervisedGetEgress({ gate: c.gate,
    supervisor: c.supervisor, recorder: c.controller.recorder,
    ciphertextReader: new Zk1SharedPgSealedGetReader({ gate: c.gate }),
    expectedRootHash: rootHash, quorumGuard: guard });
  const opened = await controller.begin(c.io);
  assert.ok(opened.child.pid !== witness.child.pid, "GET and witness must have different real OS PIDs");
  const stream = await pausedRequest(opened.port, opened.token);
  await controller.waitPartial();
  assert.deepEqual(stream.chunks[0], chunks[0]);
  assert.equal((await witness.advance()).sequence, 1,
    "real signed CAS append advances the independent SQLite witness floor");
  await assert.rejects(guard.authorize({ io: c.io, expectedRootHash: rootHash }),
    /ZK_LAB_QUORUM_UNAVAILABLE/, "floor change invalidates old trusted grants");
  await assert.rejects(controller.continueResponse(), /ZK_LAB_QUORUM_UNAVAILABLE/,
    "a current PG OPEN head is insufficient after independently signed witness advancement");
  const q = await c.gate.beginQuiesce(c.reservation);
  assert.equal(q.state, "QUIESCING");
  await assert.rejects(c.gate.markPending(c.reservation), /ZK_GATE_DRAIN_INCOMPLETE/);
  assert.equal((await controller.beginQuiesce(c.reservation)).state, "QUIESCING");
  assert.equal((await controller.finishAfterQuiesce()).status, "FINISHED");
  assert.equal((await c.gate.markPending(c.reservation)).status, "PENDING");
  assert.deepEqual(await stream.drain(), chunks[0],
    "no second ciphertext frame reaches a slow client after signed CAS floor changes");
});

test("independent witness mTLS partition and peer-pin substitution deny physical GET admission", {
  skip: !enabled ? "disposable PostgreSQL fixture required"
    : !nativeWitnessSqliteReady && "native witness SQLite addon unavailable in this Node environment",
}, async (t) => {
  const c = await context(t);
  const { rootHash } = await seedActualSealedCiphertext(c);
  const trust = await signedRootFor(c, rootHash);
  const witness = await isolatedWitness(t);
  const pin = { witness: witness.client, witnessFloor: witness.genesis, ...trust };
  await assert.rejects(Zk1SharedPgWitnessCasEgressGuard.establish({ ...pin,
    witness: new Zk1WitnessCasAnchorHttpsClient({ ...witness.config,
      serverFingerprint256: "00:".repeat(31) + "00", headTimeoutMs: 1200 }) }),
  /ZK_LAB_QUORUM_UNAVAILABLE/, "mTLS transport pin cannot be replaced by a valid-looking HTTP body");
  const guard = await Zk1SharedPgWitnessCasEgressGuard.establish(pin);
  witness.child.kill("SIGKILL");
  await new Promise((resolve) => witness.child.once("close", resolve));
  const controller = new Zk1LabSupervisedGetEgress({ gate: c.gate,
    supervisor: c.supervisor, recorder: c.controller.recorder,
    ciphertextReader: new Zk1SharedPgSealedGetReader({ gate: c.gate }),
    expectedRootHash: rootHash, quorumGuard: guard });
  await assert.rejects(controller.begin(c.io), /ZK_LAB_QUORUM_UNAVAILABLE|ZK_LAB_GET_DENIED/);
  assert.equal(c.supervisor.sessions.size, 1,
    "the only supervised process is the already stopped PUT; failed GET never launches socket child");
});

test("hardened GET mid-stream witness partition plus concurrent resumes denies all further bytes until signed STOP", {
  skip: !enabled ? "disposable PostgreSQL fixture required"
    : !nativeWitnessSqliteReady && "native witness SQLite addon unavailable in this Node environment",
}, async (t) => {
  const c = await context(t);
  const { chunks, rootHash } = await seedActualSealedCiphertext(c);
  const witness = await isolatedWitness(t);
  const guard = await Zk1SharedPgWitnessCasEgressGuard.establish({
    witness: witness.client, witnessFloor: witness.genesis,
    ...await signedRootFor(c, rootHash),
  });
  const controller = new Zk1LabSupervisedGetEgress({ gate: c.gate,
    supervisor: c.supervisor, recorder: c.controller.recorder,
    ciphertextReader: new Zk1SharedPgSealedGetReader({ gate: c.gate }),
    expectedRootHash: rootHash, quorumGuard: guard });
  const { port, token, child } = await controller.begin(c.io);
  const stream = await pausedRequest(port, token);
  await controller.waitPartial();
  assert.deepEqual(stream.chunks[0], chunks[0]);
  witness.child.kill("SIGKILL");
  await new Promise((resolve) => witness.child.once("close", resolve));
  const attempts = await Promise.allSettled([
    controller.continueResponse(), controller.continueResponse(),
  ]);
  assert.equal(attempts.filter((item) => item.status === "fulfilled").length, 0);
  assert.equal(attempts.filter((item) => item.status === "rejected").length, 2);
  assert.equal((await c.gate.beginQuiesce(c.reservation)).state, "QUIESCING");
  await assert.rejects(c.gate.markPending(c.reservation), /ZK_GATE_DRAIN_INCOMPLETE/,
    "remote partition does not let the operator mark physical STOP early");
  assert.equal((await controller.beginQuiesce(c.reservation)).state, "QUIESCING");
  assert.equal((await controller.finishAfterQuiesce()).status, "FINISHED");
  assert.equal(child.connected, false);
  assert.equal((await c.gate.markPending(c.reservation)).status, "PENDING");
  assert.deepEqual(await stream.drain(), chunks[0],
    "no ciphertext leaves the real socket after mTLS witness partition");
});
