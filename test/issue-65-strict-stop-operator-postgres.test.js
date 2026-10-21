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

test("operator identity is pinned; dead child cannot obtain a strict admission", async (t) => {
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
  const operator = new Zk1SharedPgStrictStopOperator({ gate, supervisor, recorder });
  const io = { scope, workerId: crypto.randomBytes(16), principal,
    action: "put", objectId: crypto.randomBytes(16).toString("base64url"),
    revision: 1, digest: crypto.randomBytes(32) };
  assert.throws(() => operator.prepare({ ...io,
    processPid: 1 }), /ZK_GATE_DENIED/,
  "even the local operator API refuses caller-supplied process identity");
  operator.prepare(io);
  assert.throws(() => operator.prepare(io), /ZK_GATE_DENIED/,
    "replayed trusted provisioning must not spawn another process");
  const entry = [...operator.entries.values()][0];
  const session = supervisor.sessions.get(entry.process.processEpoch.toString("hex"));
  const closed = new Promise((resolve) => session.child.once("close", resolve));
  session.child.kill("SIGKILL");
  await closed;
  assert.throws(() => supervisor.assertLive({ processEpoch: entry.process.processEpoch }),
    /ZK_STOP_SUPERVISOR_UNAVAILABLE/);
  await assert.rejects(operator.beginTrustedLocalAdmission(io),
    /ZK_STOP_SUPERVISOR_UNAVAILABLE/,
  "an exited child cannot race into an admission or create a signed STOP proof");
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
});
