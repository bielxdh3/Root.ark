"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const https = require("node:https");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedPgStrictStopOperator } = require("../src/services/zk1SharedPgStrictStopOperator");
const { Zk1IsolatedProcessStopSupervisor } = require("../src/services/zk1IsolatedProcessStopSupervisor");
const { createZk1PhysicalStopRecorder } = require("../src/services/zk1SharedPgPhysicalStopRecorder");
const { Zk1LabSupervisedMtlsBoundWriter } =
  require("../lab/issue-65-packet-b/supervised-mtls-bound-writer-controller");

const enabled = Boolean(process.env.ROOTARK_ZK1_TEST_PG_URL
  && process.env.ROOTARK_ZK1_RUNTIME_PG_URL
  && process.env.ROOTARK_ZK1_STOP_PG_URL
  && process.env.ROOTARK_ZK1_WRITER_PG_URL);
const keyOf = (s) => s.account_id.toString("hex") + ":"
  + s.compartment_id.length.toString(16) + ":" + s.compartment_id.toString("hex");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function makeCerts(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-mtls-own-child-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const shell = [
    "set -eu",
    'openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=Disposable Writer CA" -days 1 >/dev/null 2>&1',
    'openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" >/dev/null 2>&1',
    'printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext',
    'openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 1 -extfile server.ext >/dev/null 2>&1',
    'for name in allowed denied; do openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=$name" >/dev/null 2>&1; printf "extendedKeyUsage=clientAuth\n" > "$name.ext"; openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$name.pem" -days 1 -extfile "$name.ext" >/dev/null 2>&1; done',
  ].join("\n");
  if (process.platform === "win32") {
    require("./support/issue-65-native-openssl-fixture").generateNativeFixtureCertificates(dir, {
      caSubject: "Disposable Writer CA", servers: ["server"],
      clients: ["allowed", "denied"],
    });
  } else {
    execFileSync("bash", ["-lc", shell], { cwd: dir, timeout: 25000, stdio: "pipe" });
  }
  const read = (name) => fs.readFileSync(path.join(dir, name));
  return { ca: read("ca.pem"), serverCert: read("server.pem"), serverKey: read("server.key"),
    allowedCert: read("allowed.pem"), allowedKey: read("allowed.key"),
    deniedCert: read("denied.pem"), deniedKey: read("denied.key") };
}

async function fixture(t) {
  const certs = makeCerts(t);
  const admin = new Pool({ connectionString: process.env.ROOTARK_ZK1_TEST_PG_URL });
  const runtime = new Pool({ connectionString: process.env.ROOTARK_ZK1_RUNTIME_PG_URL });
  const stopPool = new Pool({ connectionString: process.env.ROOTARK_ZK1_STOP_PG_URL });
  const writerBase = new URL(process.env.ROOTARK_ZK1_WRITER_PG_URL);
  const login = "zkwriterfixture_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  writerBase.username = login;
  writerBase.password = password;
  const scope = { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(8),
    keyring_id: crypto.randomBytes(16) };
  const digest = crypto.randomBytes(32);
  const keys = crypto.generateKeyPairSync("ed25519");
  const hostKeyId = crypto.randomBytes(16);
  const supervisor = new Zk1IsolatedProcessStopSupervisor({ hostKeyId,
    hostPrivateKey: keys.privateKey, stopTimeoutMs: 5000,
    workerScript: path.resolve(__dirname, "../lab/issue-65-packet-b/supervised-mtls-bound-writer-child.js") });
  let roleCreated = false;
  t.after(async () => {
    const unfinished = [...supervisor.sessions.values()].filter((s) => !s.closed);
    const closed = Promise.all(unfinished.map((s) => new Promise((resolve) => s.child.once("close", resolve))));
    supervisor.dispose();
    let timer;
    try {
      await Promise.race([closed, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("unclosed lab worker")), 5000);
      })]);
    } finally { clearTimeout(timer); }
    try { if (roleCreated) await admin.query("DROP ROLE IF EXISTS " + login); }
    finally { await Promise.all([admin.end(), runtime.end(), stopPool.end()]); }
  });
  await admin.query("CREATE ROLE " + login + " LOGIN PASSWORD '" + password + "'");
  roleCreated = true;
  await admin.query("GRANT zk1_chunk_writer_runtime TO " + login);
  await admin.query(`INSERT INTO zk1_gate.head
    (scope_key,keyring_id,revision,digest,require_stop_proof) VALUES($1,$2,1,$3,TRUE)`,
  [keyOf(scope), scope.keyring_id, digest]);
  const gate = new Zk1SharedPgGateAuthority({ pool: runtime,
    stopPinned: { hostKeyId, hostPublicKey: keys.publicKey } });
  const recorder = await createZk1PhysicalStopRecorder({ pool: stopPool,
    trustedHostKeyId: hostKeyId, trustedHostPublicKey: keys.publicKey });
  const operator = new Zk1SharedPgStrictStopOperator({ gate, supervisor, recorder });
  const controller = new Zk1LabSupervisedMtlsBoundWriter({
    operator, runtimePgUrl: writerBase.toString(),
    tls: { key: certs.serverKey, cert: certs.serverCert, ca: certs.ca },
    trustedClientCertificate: certs.allowedCert, holdBeforeCommit: true });
  const certPrincipal = crypto.createHash("sha256")
    .update(new crypto.X509Certificate(certs.allowedCert).raw)
    .digest("hex").match(/../g).join(":").toUpperCase();
  const io = { scope, workerId: crypto.randomBytes(16), principal: certPrincipal,
    action: "put", objectId: crypto.randomBytes(16).toString("base64url"),
    revision: 1, digest };
  const operation = { scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest };
  return { admin, gate, controller, operator, supervisor, io, scope, operation, certs, login };
}

function put(port, certs, kind, index, bytes, extra = {}) {
  const cert = kind === "denied" ? certs.deniedCert : kind === "none" ? undefined : certs.allowedCert;
  const key = kind === "denied" ? certs.deniedKey : kind === "none" ? undefined : certs.allowedKey;
  let req;
  const promise = new Promise((resolve, reject) => {
    req = https.request({ hostname: "127.0.0.1", port, method: "PUT",
      path: "/fixture-chunk/" + index, ca: certs.ca, cert, key, agent: false,
      rejectUnauthorized: true, minVersion: "TLSv1.3",
      headers: { "content-type": "application/octet-stream",
        "content-length": String(bytes.length), ...extra } }, (response) => {
      const chunks = [];
      response.on("data", (b) => chunks.push(b));
      response.on("end", () => resolve({ code: response.statusCode,
        body: Buffer.concat(chunks).toString("utf8") }));
      response.on("error", reject);
    });
    req.on("error", reject);
    req.setTimeout(6000, () => req.destroy(new Error("fixture PUT timeout")));
    req.end(bytes);
  });
  return { promise, abort: () => req?.destroy(new Error("synthetic client abort")) };
}

test("inside-child strict mTLS checks pinned cert and ignores forged identity headers", {
  skip: !enabled && "requires disposable PG18 fixture",
}, async (t) => {
  const c = await fixture(t);
  await assert.rejects(c.controller.begin({ ...c.io, processPid: process.pid }),
    /ZK_LAB_MTLS_WRITER_DENIED/);
  await assert.rejects(c.controller.begin({ ...c.io, principal: "AB:".repeat(31) + "AB" }),
    /ZK_LAB_MTLS_WRITER_DENIED/, "SQL principal must match the pinned cert fingerprint");
  const session = await c.controller.begin(c.io);
  assert.equal(session.inheritedSecrets, false);
  assert.equal(session.restrictedRoleVerified, true);
  const forged = put(session.port, c.certs, "denied", 0, Buffer.from("wrong-cert"),
    { "x-host-pid": String(session.child.pid), "x-admission-generation": "1" });
  const wrong = await forged.promise.catch((e) => e);
  assert.ok(wrong instanceof Error || wrong.code === 403);
  const missing = put(session.port, c.certs, "none", 0, Buffer.from("no-cert"));
  const noCert = await missing.promise.catch((e) => e);
  assert.ok(noCert instanceof Error || noCert.code === 403);
  const payload = crypto.randomBytes(220);
  const request = put(session.port, c.certs, "allowed", 0, payload,
    { "x-host-pid": "999999", "x-account-id": "forged", "x-generation": "999" });
  await c.controller.waitHeld();
  await c.controller.releaseHeld();
  assert.equal((await request.promise).code, 200);
  const actual = await c.admin.query(`SELECT ciphertext FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=$1 AND object_id=$2 AND chunk_index=0`, [keyOf(c.scope), c.io.objectId]);
  assert.equal(actual.rowCount, 1);
  assert.deepEqual(actual.rows[0].ciphertext, payload);
  const repeat = put(session.port, c.certs, "allowed", 0, payload);
  const conflict = await repeat.promise.catch((e) => e);
  assert.ok(conflict instanceof Error || conflict.code !== 200, "replay must not silently report success");
  await c.controller.beginQuiesce(c.operation);
  assert.equal((await c.controller.finishAfterQuiesce()).status, "FINISHED");
  assert.equal((await c.gate.markPending(c.operation)).status, "PENDING");
});

test("physical HEAD lock holds QUIESCING until child SQL COMMIT; late PUT blocked before STOP", {
  skip: !enabled && "requires disposable PG18 fixture",
}, async (t) => {
  const c = await fixture(t);
  const s = await c.controller.begin(c.io);
  const payload = crypto.randomBytes(300);
  const request = put(s.port, c.certs, "allowed", 1, payload);
  await c.controller.waitHeld();
  let quiesced = false;
  const pending = c.controller.beginQuiesce(c.operation).then((r) => {
    quiesced = true;
    return r;
  });
  await sleep(150);
  assert.equal(quiesced, false);
  await assert.rejects(c.controller.beginQuiesce({ ...c.operation,
    reservationId: crypto.randomBytes(16) }), /ZK_LAB_MTLS_WRITER_DENIED/,
  "an already-started quiesce cannot be relabeled as another reservation");
  await c.controller.releaseHeld();
  assert.equal((await request.promise).code, 200);
  assert.equal((await pending).state, "QUIESCING");
  const late = put(s.port, c.certs, "allowed", 2, crypto.randomBytes(30));
  const res = await late.promise.catch((e) => e);
  assert.ok(res instanceof Error || res.code !== 200);
  await assert.rejects(c.gate.markPending(c.operation), /ZK_GATE_DRAIN_INCOMPLETE/);
  await assert.rejects(c.gate.finishIoAdmission({ scope: c.scope,
    admissionId: s.admissionId, workerId: c.io.workerId, principal: c.io.principal }),
  /ZK_GATE_STOP_PROOF_INVALID/);
  assert.equal((await c.controller.finishAfterQuiesce()).status, "FINISHED");
  assert.equal(s.child.connected, false);
  assert.equal((await c.gate.markPending(c.operation)).status, "PENDING");
  const actual = await c.admin.query(`SELECT COUNT(*)::int AS n FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=$1`, [keyOf(c.scope)]);
  assert.equal(actual.rows[0].n, 1);
});

test("TLS client disconnect during held SQL write rolls back; signed child death stops admission", {
  skip: !enabled && "requires disposable PG18 fixture",
}, async (t) => {
  const c = await fixture(t);
  const s = await c.controller.begin(c.io);
  const req = put(s.port, c.certs, "allowed", 0, crypto.randomBytes(170));
  await c.controller.waitHeld();
  req.abort();
  await assert.rejects(req.promise, /synthetic client abort/);
  await c.controller.releaseHeld();
  assert.equal((await c.controller.beginQuiesce(c.operation)).state, "QUIESCING");
  assert.equal((await c.controller.finishAfterQuiesce()).status, "FINISHED");
  assert.equal((await c.gate.markPending(c.operation)).status, "PENDING");
  const count = await c.admin.query(`SELECT COUNT(*)::int AS n FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=$1`, [keyOf(c.scope)]);
  assert.equal(count.rows[0].n, 0);
});

test("SIGKILL mid-flight rolls back physical SQL, releases gate lock, and STOP requires original handle", {
  skip: !enabled && "requires disposable PG18 fixture",
}, async (t) => {
  const c = await fixture(t);
  const s = await c.controller.begin(c.io);
  const req = put(s.port, c.certs, "allowed", 0, crypto.randomBytes(160));
  // Attach the disconnect observer before the OS kill can reject the socket.
  const interrupted = req.promise.catch((error) => error);
  await c.controller.waitHeld();
  let quiesced = false;
  const pending = c.controller.beginQuiesce(c.operation).then((r) => {
    quiesced = true;
    return r;
  });
  await sleep(100);
  assert.equal(quiesced, false);
  const closed = new Promise((resolve) => s.child.once("close", resolve));
  assert.equal(s.child.kill("SIGKILL"), true);
  await closed;
  const interruptedResult = await interrupted;
  assert.ok(interruptedResult instanceof Error || interruptedResult.code !== 200);
  assert.equal((await pending).state, "QUIESCING");
  const count = await c.admin.query(`SELECT COUNT(*)::int AS n FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=$1`, [keyOf(c.scope)]);
  assert.equal(count.rows[0].n, 0);
  const foreign = new Zk1IsolatedProcessStopSupervisor({
    hostKeyId: c.supervisor.hostKeyId, hostPrivateKey: c.supervisor.hostPrivateKey,
    workerScript: path.resolve(__dirname, "../lab/issue-65-packet-b/supervised-mtls-bound-writer-child.js") });
  await assert.rejects(foreign.stop({ processEpoch: c.controller.entry.process.processEpoch }),
    /ZK_STOP_SUPERVISOR_UNAVAILABLE/);
  assert.equal((await c.controller.finishAfterQuiesce()).status, "FINISHED");
  assert.equal((await c.gate.markPending(c.operation)).status, "PENDING");
});
