"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { execFileSync } = require("node:child_process");
const { Pool } = require("pg");
const { createZk1PhysicalStopRecorder } = require("../src/services/zk1SharedPgPhysicalStopRecorder");
const { createIsolatedZk1SharedPgGateServer } = require("../src/services/zk1SharedPgGateRuntime");
const { Zk1IsolatedProcessStopSupervisor } = require("../src/services/zk1IsolatedProcessStopSupervisor");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedPgPhysicalStopRecorder } = require("../src/services/zk1SharedPgPhysicalStopRecorder");
const { Zk1SharedPgStrictStopOperator } = require("../src/services/zk1SharedPgStrictStopOperator");

const adminUrl = process.env.ROOTARK_ZK1_TEST_PG_URL;
const gateUrl = process.env.ROOTARK_ZK1_RUNTIME_PG_URL;
const stopUrl = process.env.ROOTARK_ZK1_STOP_PG_URL;

test("an unverified STOP recorder cannot be supplied directly by a trusted-looking object", (t) => {
  const host = crypto.generateKeyPairSync("ed25519");
  const foreign = crypto.generateKeyPairSync("ed25519");
  const hostKeyId = crypto.randomBytes(16);
  const scope = { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(5),
    keyring_id: crypto.randomBytes(16) };
  const principal = "AB:".repeat(31) + "AB";
  const supervisor = new Zk1IsolatedProcessStopSupervisor({ hostKeyId,
    hostPrivateKey: host.privateKey,
    workerScript: path.resolve(__dirname, "../lab/issue-65-packet-b/stop-child-worker.js") });
  t.after(() => supervisor.dispose());
  const inertPool = { connect() { throw new Error("unexpected DB operation"); } };
  const gate = new Zk1SharedPgGateAuthority({ pool: inertPool,
    stopPinned: { hostKeyId, hostPublicKey: host.publicKey } });
  const recorder = new Zk1SharedPgPhysicalStopRecorder({ pool: inertPool,
    trustedHostKeyId: hostKeyId, trustedHostPublicKey: host.publicKey,
    nowSeconds: () => Math.floor(Date.now() / 1000) });
  const untrusted = new Zk1SharedPgPhysicalStopRecorder({ pool: inertPool,
    trustedHostKeyId: hostKeyId, trustedHostPublicKey: foreign.publicKey,
    nowSeconds: () => Math.floor(Date.now() / 1000) });
  assert.throws(() => new Zk1SharedPgStrictStopOperator({ gate,
    supervisor, recorder: untrusted }), /ZK_GATE_DENIED/,
  "the STOP recorder must trust the same independently pinned Ed25519 host");
  assert.throws(() => new Zk1SharedPgStrictStopOperator({ gate,
    supervisor, recorder }), /ZK_GATE_DENIED/,
  "a raw recorder may use an unverified superuser or dual-role SQL pool");
});

function fixture(dir) {
  const shell = [
    "set -eu",
    'openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=Local Test CA" -days 1 >/dev/null 2>&1',
    'openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" >/dev/null 2>&1',
    'printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext',
    'openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 1 -extfile server.ext >/dev/null 2>&1',
    'for name in allowed denied; do openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=$name" >/dev/null 2>&1; printf "extendedKeyUsage=clientAuth\n" > "$name.ext"; openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$name.pem" -days 1 -extfile "$name.ext" >/dev/null 2>&1; done',
  ].join("\n");
  if (process.platform === "win32") {
    const unix = execFileSync("wsl.exe", ["-e", "wslpath", "-a", dir], { encoding: "utf8" }).trim();
    execFileSync("wsl.exe", ["-e", "bash", "-lc", "cd " + JSON.stringify(unix) + "; " + shell],
      { stdio: "pipe", timeout: 20000 });
  } else {
    execFileSync("bash", ["-lc", shell], { cwd: dir, stdio: "pipe", timeout: 20000 });
  }
  const load = (file) => fs.readFileSync(path.join(dir, file));
  return { ca: load("ca.pem"), serverKey: load("server.key"), serverCert: load("server.pem"),
    allowedKey: load("allowed.key"), allowedCert: load("allowed.pem"),
    deniedKey: load("denied.key"), deniedCert: load("denied.pem") };
}
function send(port, tls, route, json, allowed = true) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(json));
    const request = https.request({ hostname: "localhost", port, path: route, method: "POST",
      ca: tls.ca, key: allowed ? tls.allowedKey : tls.deniedKey,
      cert: allowed ? tls.allowedCert : tls.deniedCert,
      rejectUnauthorized: true, minVersion: "TLSv1.3", agent: false,
      headers: { "content-type": "application/json", "content-length": String(data.length) },
    }, (response) => {
      const parts = [];
      response.on("data", (part) => parts.push(part));
      response.on("end", () => resolve({ status: response.statusCode,
        body: JSON.parse(Buffer.concat(parts).toString("utf8")) }));
    });
    request.on("error", reject);
    request.end(data);
  });
}

test("STRICT mTLS route rejects forged process identity and remote IO; only the operator owns local process STOP", {
  skip: !adminUrl || !gateUrl || !stopUrl
    ? "requires isolated PostgreSQL admin/gate/stop fixture roles" : false,
}, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-strict-stop-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const tls = fixture(dir);
  const admin = new Pool({ connectionString: adminUrl, max: 2, connectionTimeoutMillis: 3000 });
  const gatePool = new Pool({ connectionString: gateUrl, max: 3, connectionTimeoutMillis: 3000 });
  const stopPool = new Pool({ connectionString: stopUrl, max: 2, connectionTimeoutMillis: 3000 });
  t.after(async () => Promise.all([admin.end(), gatePool.end(), stopPool.end()]));
  const scope = { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(7),
    keyring_id: crypto.randomBytes(16) };
  const digest = crypto.randomBytes(32);
  const key = scope.account_id.toString("hex") + ":"
    + scope.compartment_id.length.toString(16) + ":" + scope.compartment_id.toString("hex");
  await admin.query(`INSERT INTO zk1_gate.head
    (scope_key,keyring_id,revision,digest,require_stop_proof) VALUES($1,$2,1,$3,TRUE)`,
  [key, scope.keyring_id, digest]);
  const signer = crypto.generateKeyPairSync("ed25519");
  const hostKeyId = crypto.randomBytes(16);
  const supervisor = new Zk1IsolatedProcessStopSupervisor({ hostKeyId,
    hostPrivateKey: signer.privateKey,
    workerScript: path.resolve(__dirname, "../lab/issue-65-packet-b/stop-child-worker.js") });
  t.after(() => supervisor.dispose());
  const recorder = await createZk1PhysicalStopRecorder({ pool: stopPool,
    trustedHostKeyId: hostKeyId, trustedHostPublicKey: signer.publicKey });
  assert.throws(() => { recorder.pool = admin; }, TypeError,
    "a preflighted recorder cannot swap its STOP SQL pool to a superuser");
  assert.equal(recorder.pool, stopPool);
  for (const forbidden of [admin, gatePool]) {
    await assert.rejects(createZk1PhysicalStopRecorder({ pool: forbidden,
      trustedHostKeyId: hostKeyId, trustedHostPublicKey: signer.publicKey }),
    /ZK_STOP_RUNTIME_INVALID/,
    "STOP identity may never use a superuser or shared gate SQL role");
  }
  const principal = new crypto.X509Certificate(tls.allowedCert).fingerprint256;
  const server = await createIsolatedZk1SharedPgGateServer({ pool: gatePool,
    key: tls.serverKey, cert: tls.serverCert, clientCa: tls.ca,
    principals: { [principal]: { roles: ["admit", "put", "seal", "reserve"],
      scopes: [{ account_id: scope.account_id.toString("base64url"),
        compartment_id: scope.compartment_id.toString("base64url"),
        keyring_id: scope.keyring_id.toString("base64url") }] } },
    stopPinned: { hostKeyId, hostPublicKey: signer.publicKey },
    stopSupervisor: supervisor, stopRecorder: recorder });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;
  const io = { scope, workerId: crypto.randomBytes(16), principal,
    action: "put", objectId: crypto.randomBytes(16).toString("base64url"),
    revision: 1, digest };
  const http = { scope: Object.fromEntries(Object.entries(scope)
    .map(([name, value]) => [name, value.toString("base64url")])),
  workerId: io.workerId.toString("base64url"), action: io.action,
  objectId: io.objectId, revision: 1, digest: digest.toString("base64url") };
  const operator = server.strictStopOperator;
  assert.throws(() => new Zk1SharedPgStrictStopOperator({
    gate: operator.gate, supervisor,
    recorder: new Zk1SharedPgPhysicalStopRecorder({ pool: admin,
      trustedHostKeyId: hostKeyId, trustedHostPublicKey: signer.publicKey,
      nowSeconds: () => Math.floor(Date.now() / 1000) }),
  }), /ZK_GATE_DENIED/,
  "a superuser recorder bypassing the verified factory is rejected");
  assert.equal(typeof operator.prepare, "function");
  assert.equal(typeof operator.beginIoAdmission, "undefined",
    "remote-facing admission hook must never exist on the operator");
  assert.equal((await send(port, tls, "/v1/admission/start", http)).status, 503,
    "strict remote START is non-authorizing even with an authenticated certificate");
  operator.prepare(io);
  await assert.rejects(operator.beginTrustedLocalAdmission({ ...io,
    principal: "BB:".repeat(31) + "BB" }), /ZK_GATE_DENIED/);
  await assert.rejects(operator.beginTrustedLocalAdmission({ ...io,
    digest: crypto.randomBytes(32) }), /ZK_GATE_DENIED/);
  const admitted = await operator.beginTrustedLocalAdmission(io);
  assert.equal(admitted.proceed, true);
  assert.deepEqual(await operator.beginTrustedLocalAdmission(io), admitted);
  assert.equal((await send(port, tls, "/v1/admission/start", { ...http,
    hostKeyId: crypto.randomBytes(16).toString("base64url"),
    processEpoch: crypto.randomBytes(16).toString("base64url"),
    processPid: 1 })).status, 503);
  assert.equal((await send(port, tls, "/v1/admission/start", http, false)).status, 403);
  const admissionId = admitted.admissionId.toString("base64url");
  const write = { ...http, admissionId, generation: admitted.generation,
    chunkIndex: 0, ciphertextBase64: crypto.randomBytes(24).toString("base64url") };
  assert.equal((await send(port, tls, "/v1/chunk/put", write)).status, 503,
    "operator-local admission cannot authorize bytes executed by the HTTP handler");
  const finish = { scope: http.scope, admissionId, workerId: http.workerId };
  assert.equal((await send(port, tls, "/v1/admission/finish", finish)).status, 503,
    "HTTP FINISH cannot claim physical STOP for a process it does not supervise");
  const op = { scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest };
  const reserve = { scope: http.scope, operationId: op.operationId.toString("base64url"),
    reservationId: op.reservationId.toString("base64url"), revision: 1,
    digest: digest.toString("base64url") };
  assert.equal((await send(port, tls, "/v1/quiesce", reserve)).status, 200);
  await assert.rejects(operator.finishTrustedLocalAdmission({ scope,
    admissionId: crypto.randomBytes(16), workerId: io.workerId, principal }), /ZK_GATE_DENIED/);
  const ended = await operator.finishTrustedLocalAdmission({ scope,
    admissionId: admitted.admissionId, workerId: io.workerId, principal });
  assert.deepEqual(ended, { status: "FINISHED" });
  assert.equal((await send(port, tls, "/v1/pending", {
    scope: http.scope, operationId: reserve.operationId,
    reservationId: reserve.reservationId })).body.status, "PENDING");
  const count = await admin.query(`SELECT COUNT(*)::int AS n FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=$1`, [key]);
  assert.equal(count.rows[0].n, 0, "rejected remote writes had no physical effects");

  // The SQL START can durably COMMIT just before its actual host-controlled
  // child dies. The operator must still attach the returned exact admission
  // to that observed handle for a signed STOP, while the caller sees no
  // positive proceed authorization after death.
  const scope2 = { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(7),
    keyring_id: crypto.randomBytes(16) };
  const key2 = scope2.account_id.toString("hex") + ":"
    + scope2.compartment_id.length.toString(16) + ":" + scope2.compartment_id.toString("hex");
  const digest2 = crypto.randomBytes(32);
  await admin.query(`INSERT INTO zk1_gate.head
    (scope_key,keyring_id,revision,digest,require_stop_proof) VALUES($1,$2,1,$3,TRUE)`,
  [key2, scope2.keyring_id, digest2]);
  const io2 = { scope: scope2, workerId: crypto.randomBytes(16), principal,
    action: "put", objectId: crypto.randomBytes(16).toString("base64url"),
    revision: 1, digest: digest2 };
  operator.prepare(io2);
  const entry2 = [...operator.entries.values()].find((candidate) =>
    candidate.io.workerId.equals(io2.workerId));
  const session2 = supervisor.sessions.get(entry2.process.processEpoch.toString("hex"));
  const beginOriginal = operator.gate.beginIoAdmission.bind(operator.gate);
  let killedAfterCommit = false;
  operator.gate.beginIoAdmission = async (value) => {
    const returned = await beginOriginal(value);
    if (!killedAfterCommit) {
      killedAfterCommit = true;
      const row = await admin.query(`SELECT state FROM zk1_gate.admission WHERE id=$1`,
        [returned.admissionId]);
      assert.equal(row.rows[0].state, "ACTIVE", "SQL admission committed before OS death");
      const closed = new Promise((resolve) => session2.child.once("close", resolve));
      assert.equal(session2.child.kill("SIGKILL"), true);
      await closed;
    }
    return returned;
  };
  await assert.rejects(operator.beginTrustedLocalAdmission(io2),
    /ZK_STOP_SUPERVISOR_UNAVAILABLE/,
  "caller must never receive proceed:true after the observed child dies");
  operator.gate.beginIoAdmission = beginOriginal;
  assert.equal(session2.exited && session2.closed, true);
  assert.equal(entry2.bound?.admissionId.length, 16,
    "the original committed admission remains bound for recovery STOP");
  const op2 = { scope: scope2, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest: digest2 };
  assert.equal((await operator.gate.beginQuiesce(op2)).activeCount, 1);
  await operator.finishTrustedLocalAdmission({ scope: scope2,
    workerId: io2.workerId, principal, admissionId: entry2.bound.admissionId });
  assert.equal((await operator.gate.markPending({ scope: scope2,
    operationId: op2.operationId, reservationId: op2.reservationId })).status, "PENDING",
  "independently attested physical STOP must drain the committed orphan");

  // Another adversarial order: START commits, remote QUIESCING closes the
  // generation while the operator is awaiting the first admission receipt.
  const scope3 = { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(7),
    keyring_id: crypto.randomBytes(16) };
  const key3 = scope3.account_id.toString("hex") + ":"
    + scope3.compartment_id.length.toString(16) + ":" + scope3.compartment_id.toString("hex");
  const digest3 = crypto.randomBytes(32);
  await admin.query(`INSERT INTO zk1_gate.head
    (scope_key,keyring_id,revision,digest,require_stop_proof) VALUES($1,$2,1,$3,TRUE)`,
  [key3, scope3.keyring_id, digest3]);
  const io3 = { scope: scope3, workerId: crypto.randomBytes(16), principal,
    action: "put", objectId: crypto.randomBytes(16).toString("base64url"),
    revision: 1, digest: digest3 };
  const op3 = { scope: scope3, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest: digest3 };
  operator.prepare(io3);
  let quiescedAfterCommit = false;
  operator.gate.beginIoAdmission = async (value) => {
    const receipt = await beginOriginal(value);
    if (!quiescedAfterCommit) {
      quiescedAfterCommit = true;
      await operator.gate.beginQuiesce(op3);
    }
    return receipt;
  };
  const replay = await operator.beginTrustedLocalAdmission(io3);
  operator.gate.beginIoAdmission = beginOriginal;
  assert.equal(replay.proceed, false,
    "the original OPEN acknowledgment must not authorize IO after QUIESCING");
  const entry3 = [...operator.entries.values()].find((candidate) =>
    candidate.io.workerId.equals(io3.workerId));
  assert.deepEqual(replay.admissionId, entry3.bound.admissionId);
  await operator.finishTrustedLocalAdmission({ scope: scope3,
    workerId: io3.workerId, admissionId: entry3.bound.admissionId, principal });
  assert.equal((await operator.gate.markPending({ scope: scope3,
    operationId: op3.operationId, reservationId: op3.reservationId })).status,
  "PENDING", "QUIESCING before bind cannot strand a committed admission");
});
