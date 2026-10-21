"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { fork } = require("node:child_process");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const https = require("node:https");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { createZk1SharedPgGateHttpsServer } = require("../src/services/zk1SharedPgGateHttpsServer");
const { createZk1SharedPgGateHttpsClient } = require("../src/services/zk1SharedPgGateHttpsClient");
const { Zk1SharedPgCiphertextSink } = require("../src/services/zk1SharedPgCiphertextSink");

const url = process.env.ROOTARK_ZK1_TEST_PG_URL;
function randomScope() {
  return { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(9), keyring_id: crypto.randomBytes(16) };
}
function key(scope) {
  return scope.account_id.toString("hex") + ":"
    + scope.compartment_id.length.toString(16) + ":"
    + scope.compartment_id.toString("hex");
}
function context(scope, digest, action, id, principal = "gateway-a") {
  return { scope, digest, revision: 1, action, objectId: id,
    workerId: crypto.randomBytes(16), principal };
}

test("isolated GateAuthority PostgreSQL runtime role is non-login and denies raw destructive SQL", {
  skip: !url && "requires isolated ROOTARK_ZK1_TEST_PG_URL",
}, async (t) => {
  const pool = new Pool({ connectionString: url, max: 1, connectionTimeoutMillis: 3000 });
  t.after(async () => pool.end());
  const role = await pool.query("SELECT rolcanlogin, rolsuper FROM pg_roles WHERE rolname='zk1_gate_runtime'");
  assert.equal(role.rowCount, 1, "operator must be able to assign a dedicated non-login gate-only role");
  assert.equal(role.rows[0].rolcanlogin, false);
  assert.equal(role.rows[0].rolsuper, false);
  const perms = await pool.query(`SELECT
    has_schema_privilege('zk1_gate_runtime','zk1_gate','USAGE') AS schema_use,
    has_schema_privilege('zk1_gate_runtime','zk1_gate','CREATE') AS schema_create,
    has_table_privilege('zk1_gate_runtime','zk1_gate.head','SELECT') AS head_select,
    has_table_privilege('zk1_gate_runtime','zk1_gate.head','UPDATE') AS head_update,
    has_table_privilege('zk1_gate_runtime','zk1_gate.ciphertext_chunk','INSERT') AS chunk_insert,
    has_table_privilege('zk1_gate_runtime','zk1_gate.ciphertext_chunk','DELETE') AS chunk_delete,
    has_table_privilege('zk1_gate_runtime','zk1_gate.ciphertext_chunk','TRUNCATE') AS chunk_truncate`);
  assert.deepEqual(perms.rows[0], { schema_use: true, schema_create: false,
    head_select: true, head_update: true, chunk_insert: true,
    chunk_delete: false, chunk_truncate: false });
});

test("shared PostgreSQL authority protects ciphertext chunk effect and closes all worker generations", {
  skip: !url && "requires isolated ROOTARK_ZK1_TEST_PG_URL",
}, async (t) => {
  const poolA = new Pool({ connectionString: url, max: 4, connectionTimeoutMillis: 3000 });
  const poolB = new Pool({ connectionString: url, max: 4, connectionTimeoutMillis: 3000 });
  t.after(async () => { await Promise.all([poolA.end(), poolB.end()]); });
  const a = new Zk1SharedPgGateAuthority({ pool: poolA });
  const b = new Zk1SharedPgGateAuthority({ pool: poolB });
  const scope = randomScope();
  const other = randomScope();
  const digest = crypto.randomBytes(32);
  for (const identity of [scope, other]) {
    await poolA.query(`INSERT INTO zk1_gate.head
      (scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)`,
    [key(identity), identity.keyring_id, digest]);
  }
  const objectId = crypto.randomBytes(16).toString("base64url");
  const write = context(scope, digest, "put", objectId);
  const first = await a.beginIoAdmission(write);
  assert.equal(first.proceed, true);
  assert.equal(first.generation, 1);
  assert.deepEqual(await b.beginIoAdmission(write), first, "same worker is globally idempotent");
  await assert.rejects(b.beginIoAdmission({ ...write,
    objectId: crypto.randomBytes(16).toString("base64url") }), /ZK_GATE_DENIED/);
  await assert.rejects(b.beginIoAdmission({ ...write, principal: "attacker" }), /ZK_GATE_DENIED/);
  const step = { ...write, admissionId: first.admissionId, generation: first.generation };
  const payload = crypto.randomBytes(128);
  assert.deepEqual(await a.putCiphertextChunk(step, 0, payload), { stored: true });
  assert.deepEqual(await a.putCiphertextChunk(step, 0, payload), { stored: false });
  await assert.rejects(a.putCiphertextChunk(step, 0, crypto.randomBytes(128)),
    /ZK_GATE_CHUNK_CONFLICT/, "ciphertext writes are immutable under the same object identity");

  assert.equal(typeof a.emitCiphertextChunk, "undefined",
    "dangerous network egress callback is not exposed after connection-loss P1");
  assert.equal(typeof a.authorizeStep, "undefined",
    "untrusted external effects must not receive an arbitrary transaction callback");
  await assert.rejects(b.putCiphertextChunk({ ...step, scope: other }, 1, payload), /ZK_GATE_DENIED/);

  const operationId = crypto.randomBytes(16);
  const reservationId = crypto.randomBytes(16);
  const operation = { scope, operationId, reservationId, revision: 1, digest };
  const closed = await b.beginQuiesce(operation);
  assert.deepEqual(closed, { state: "QUIESCING", generation: 2, activeCount: 1 });
  assert.deepEqual(await b.beginQuiesce(operation), closed, "quiesce replays exact tuple only");
  await assert.rejects(a.beginIoAdmission(context(scope, digest, "get", objectId)),
    /ZK_GATE_DENIED/);
  const replay = await a.beginIoAdmission(write);
  assert.equal(replay.proceed, false);
  assert.deepEqual(replay.admissionId, first.admissionId);
  await assert.rejects(a.putCiphertextChunk(step, 1, payload), /ZK_GATE_DENIED/);
  await assert.rejects(b.markPending({ scope, operationId, reservationId }), /ZK_GATE_DRAIN_INCOMPLETE/);
  await a.finishIoAdmission({ scope, admissionId: first.admissionId,
    workerId: write.workerId, principal: write.principal });
  assert.deepEqual(await a.markPending({ scope, operationId, reservationId }),
    { status: "PENDING", generation: 2 });
  await assert.rejects(a.beginIoAdmission(write), /ZK_GATE_DENIED/);
  const actual = await poolA.query("SELECT COUNT(*)::int AS n FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1",
    [key(scope)]);
  assert.equal(actual.rows[0].n, 1, "denied later chunks did not mutate the provider");
});

test("shared gate waits for real physical PostgreSQL INSERT before quiescing", {
  skip: !url && "requires isolated ROOTARK_ZK1_TEST_PG_URL",
}, async (t) => {
  const poolA = new Pool({ connectionString: url, max: 2, connectionTimeoutMillis: 3000 });
  const poolB = new Pool({ connectionString: url, max: 2, connectionTimeoutMillis: 3000 });
  t.after(async () => { await Promise.all([poolA.end(), poolB.end()]); });
  const a = new Zk1SharedPgGateAuthority({ pool: poolA });
  const b = new Zk1SharedPgGateAuthority({ pool: poolB });
  const scope = randomScope();
  const digest = crypto.randomBytes(32);
  await poolA.query("INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)",
    [key(scope), scope.keyring_id, digest]);
  const io = context(scope, digest, "put", crypto.randomBytes(16).toString("base64url"));
  const admitted = await a.beginIoAdmission(io);
  const step = { ...io, admissionId: admitted.admissionId, generation: admitted.generation };
  // Synthetic schema-only trigger pauses the actual production INSERT inside
  // its transaction AFTER the gate's row lock is held. No arbitrary external
  // asynchronous-effect callback exists in the production API.
  await poolA.query(`CREATE FUNCTION zk1_gate.test_hold_chunk() RETURNS trigger
    LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.45); RETURN NEW; END $$`);
  await poolA.query(`CREATE TRIGGER test_hold_chunk BEFORE INSERT ON zk1_gate.ciphertext_chunk
    FOR EACH ROW EXECUTE FUNCTION zk1_gate.test_hold_chunk()`);
  const effect = a.putCiphertextChunk(step, 0, Buffer.from("synthetic-ciphertext"));
  let observed = false;
  for (let i = 0; i < 50; ++i) {
    const activity = await poolB.query(`SELECT COUNT(*)::int AS n FROM pg_stat_activity
      WHERE wait_event='PgSleep' AND query LIKE '%INSERT INTO zk1_gate.ciphertext_chunk%'`);
    if (activity.rows[0].n > 0) { observed = true; break; }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(observed, true, "must observe a real PostgreSQL write held in the gate transaction");
  const operation = { scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest };
  let closed = false;
  const quiescing = b.beginQuiesce(operation).then((x) => { closed = true; return x; });
  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.equal(closed, false, "quiesce cannot overtake an active physical PG effect holding the row lock");
  await effect;
  assert.equal((await quiescing).state, "QUIESCING");
  await assert.rejects(a.putCiphertextChunk(step, 1, Buffer.from("stale")), /ZK_GATE_DENIED/);
  await poolA.query("DROP TRIGGER IF EXISTS test_hold_chunk ON zk1_gate.ciphertext_chunk");
  await poolA.query("DROP FUNCTION IF EXISTS zk1_gate.test_hold_chunk()");
});

function childStep(step) {
  const encode = (bytes) => Buffer.from(bytes).toString("base64url");
  return { ...step, scope: Object.fromEntries(
    Object.entries(step.scope).map(([field, value]) => [field, encode(value)])),
  workerId: encode(step.workerId), digest: encode(step.digest),
  admissionId: encode(step.admissionId) };
}
function untilMessage(child, kind) {
  return new Promise((resolve, reject) => {
    const message = (data) => {
      if (data?.kind === kind) { clean(); resolve(data); }
      else if (data?.kind === "effect-failed") { clean(); reject(new Error("child physical effect failed")); }
    };
    const died = () => { clean(); reject(new Error("child exited before " + kind)); };
    const clean = () => { child.off("message", message); child.off("exit", died); };
    child.on("message", message); child.once("exit", died);
  });
}

test("independent Node process physical transaction is drained before other process closes the shared gate", {
  skip: !url && "requires isolated ROOTARK_ZK1_TEST_PG_URL",
}, async (t) => {
  const pool = new Pool({ connectionString: url, max: 3, connectionTimeoutMillis: 3000 });
  t.after(async () => { await pool.end(); });
  const gate = new Zk1SharedPgGateAuthority({ pool });
  const scope = randomScope();
  const digest = crypto.randomBytes(32);
  await pool.query("INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)",
    [key(scope), scope.keyring_id, digest]);
  const io = context(scope, digest, "put", crypto.randomBytes(16).toString("base64url"));
  const receipt = await gate.beginIoAdmission(io);
  const step = { ...io, admissionId: receipt.admissionId, generation: receipt.generation };
  const spawnWorker = () => fork(path.resolve(__dirname,
    "../lab/issue-65-packet-b/shared-gate-worker.js"), [],
  { env: { ...process.env, ROOTARK_ZK1_TEST_PG_URL: url }, stdio: ["ignore", "ignore", "ignore", "ipc"] });
  const child = spawnWorker();
  t.after(() => { if (child.exitCode === null) child.kill(); });
  const held = untilMessage(child, "effect-held");
  child.send({ kind: "hold-effect", step: childStep(step), index: 0 });
  await held;
  const next = { scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest };
  let closed = false;
  const quiescing = gate.beginQuiesce(next).then((result) => {
    closed = true;
    return result;
  });
  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.equal(closed, false, "a different process cannot close over physical storage effects");
  const completed = untilMessage(child, "effect-complete");
  child.send({ kind: "release-effect" });
  await completed;
  assert.equal((await quiescing).state, "QUIESCING");
  const stored = await pool.query("SELECT COUNT(*)::int AS n FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1",
    [key(scope)]);
  assert.equal(stored.rows[0].n, 1);
  await assert.rejects(gate.putCiphertextChunk(step, 1, Buffer.from("late")), /ZK_GATE_DENIED/);
});

test("abruptly killed worker rolls back uncommitted bytes, then shared authority quiesces", {
  skip: !url && "requires isolated ROOTARK_ZK1_TEST_PG_URL",
}, async (t) => {
  const pool = new Pool({ connectionString: url, max: 3, connectionTimeoutMillis: 3000 });
  t.after(async () => { await pool.end(); });
  const gate = new Zk1SharedPgGateAuthority({ pool });
  const scope = randomScope();
  const digest = crypto.randomBytes(32);
  await pool.query("INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)",
    [key(scope), scope.keyring_id, digest]);
  const io = context(scope, digest, "put", crypto.randomBytes(16).toString("base64url"));
  const receipt = await gate.beginIoAdmission(io);
  const child = fork(path.resolve(__dirname,
    "../lab/issue-65-packet-b/shared-gate-worker.js"), [],
  { env: { ...process.env, ROOTARK_ZK1_TEST_PG_URL: url }, stdio: ["ignore", "ignore", "ignore", "ipc"] });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  const held = untilMessage(child, "effect-held");
  child.send({ kind: "hold-effect", step: childStep({ ...io,
    admissionId: receipt.admissionId, generation: receipt.generation }), index: 0 });
  await held;
  const gone = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGKILL");
  await gone;
  const next = { scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest };
  const quiesced = await gate.beginQuiesce(next);
  assert.equal(quiesced.state, "QUIESCING");
  assert.equal(quiesced.activeCount, 1,
    "process death never implies worker stop or erases durable admission");
  const stored = await pool.query("SELECT COUNT(*)::int AS n FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1",
    [key(scope)]);
  assert.equal(stored.rows[0].n, 0, "aborted physical DB operation must roll back");
  await assert.rejects(gate.markPending({ scope, operationId: next.operationId,
    reservationId: next.reservationId }), /ZK_GATE_DRAIN_INCOMPLETE/);
});

function tlsFixture(dir) {
  const script = [
    "set -eu",
    'openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=Rootark Synthetic Gate CA" -days 1 >/dev/null 2>&1',
    'openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" >/dev/null 2>&1',
    'printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext',
    'openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 1 -extfile server.ext >/dev/null 2>&1',
    'for name in allowed denied; do openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=$name" >/dev/null 2>&1; printf "extendedKeyUsage=clientAuth\n" > "$name.ext"; openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$name.pem" -days 1 -extfile "$name.ext" >/dev/null 2>&1; done',
  ].join("\n");
  if (process.platform === "win32") {
    const dirUnix = execFileSync("wsl.exe", ["-e", "wslpath", "-a", dir], { encoding: "utf8" }).trim();
    execFileSync("wsl.exe", ["-e", "bash", "-lc", "cd " + JSON.stringify(dirUnix) + "; " + script],
      { stdio: "pipe", timeout: 20000 });
  } else {
    execFileSync("bash", ["-lc", script], { cwd: dir, stdio: "pipe", timeout: 20000 });
  }
  const read = (name) => fs.readFileSync(path.join(dir, name));
  return { ca: read("ca.pem"), serverKey: read("server.key"), serverCert: read("server.pem"),
    allowedKey: read("allowed.key"), allowedCert: read("allowed.pem"),
    deniedKey: read("denied.key"), deniedCert: read("denied.pem") };
}
function sendTls(port, tls, pathName, body, permitted = true) {
  return new Promise((resolve, reject) => {
    const bytes = Buffer.from(JSON.stringify(body));
    const request = https.request({ hostname: "localhost", port, path: pathName, method: "POST",
      ca: tls.ca, key: permitted ? tls.allowedKey : tls.deniedKey,
      cert: permitted ? tls.allowedCert : tls.deniedCert,
      rejectUnauthorized: true, minVersion: "TLSv1.3", timeout: 4000,
      headers: { "content-type": "application/json", "content-length": String(bytes.length) },
    }, (res) => {
      const parts = [];
      res.on("data", (part) => parts.push(part));
      res.on("end", () => {
        const raw = Buffer.concat(parts);
        resolve({ status: res.statusCode,
          body: res.headers["content-type"] === "application/octet-stream"
            ? raw : JSON.parse(raw.toString("utf8")) });
      });
    });
    request.on("timeout", () => request.destroy(new Error("synthetic TLS timeout")));
    request.on("error", reject);
    request.end(bytes);
  });
}

test("real mTLS independent gate listener binds every PostgreSQL chunk to scoped client certificate", {
  skip: !url && "requires isolated ROOTARK_ZK1_TEST_PG_URL",
}, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-gate-mtls-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const tls = tlsFixture(dir);
  const pool = new Pool({ connectionString: url, max: 3, connectionTimeoutMillis: 3000 });
  t.after(async () => { await pool.end(); });
  const gate = new Zk1SharedPgGateAuthority({ pool });
  const scope = randomScope();
  const other = randomScope();
  const digest = crypto.randomBytes(32);
  await pool.query("INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)",
    [key(scope), scope.keyring_id, digest]);
  const encode = (value) => Buffer.from(value).toString("base64url");
  const encodeScope = (s) => Object.fromEntries(Object.entries(s).map(([k, v]) => [k, encode(v)]));
  const allowedFingerprint = new crypto.X509Certificate(tls.allowedCert).fingerprint256;
  const server = createZk1SharedPgGateHttpsServer({
    key: tls.serverKey, cert: tls.serverCert, clientCa: tls.ca, gate,
    principals: { [allowedFingerprint]: { roles: ["admit", "put", "reserve"],
      scopes: [encodeScope(scope)] } },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;
  const objectId = encode(crypto.randomBytes(16));
  const workerId = encode(crypto.randomBytes(16));
  const base = { scope: encodeScope(scope), workerId, revision: 1,
    digest: encode(digest), action: "put", objectId };
  assert.equal((await sendTls(port, tls, "/v1/admission/start", base, false)).status, 403);
  assert.equal((await sendTls(port, tls, "/v1/admission/start",
    { ...base, scope: encodeScope(other) })).status, 403);
  const started = await sendTls(port, tls, "/v1/admission/start", base);
  assert.equal(started.status, 201);
  assert.equal(started.body.proceed, true);
  const chunk = crypto.randomBytes(256);
  const put = { ...base, admissionId: started.body.admissionId,
    generation: started.body.generation, chunkIndex: 0, ciphertextBase64: encode(chunk) };
  assert.deepEqual((await sendTls(port, tls, "/v1/chunk/put", put)).body, { stored: true });
  const getRequest = { ...base, action: "get", workerId: encode(crypto.randomBytes(16)) };
  assert.equal((await sendTls(port, tls, "/v1/admission/start", getRequest)).status, 400,
    "no GET admission is issued until egress has a connection-loss-safe physical fence");
  assert.equal((await sendTls(port, tls, "/v1/chunk/get", { ...getRequest,
    admissionId: started.body.admissionId, generation: started.body.generation, chunkIndex: 0 })).status,
  404, "the formerly unsafe network egress route must be absent");
  const op = { scope: encodeScope(scope), operationId: encode(crypto.randomBytes(16)),
    reservationId: encode(crypto.randomBytes(16)), revision: 1, digest: encode(digest) };
  const quiesced = await sendTls(port, tls, "/v1/quiesce", op);
  assert.equal(quiesced.status, 200);
  assert.equal(quiesced.body.state, "QUIESCING");
  assert.equal((await sendTls(port, tls, "/v1/chunk/put", put)).status, 403);
  for (const pair of [[started.body.admissionId, workerId]]) {
    const finished = await sendTls(port, tls, "/v1/admission/finish", {
      scope: encodeScope(scope), admissionId: pair[0], workerId: pair[1] });
    assert.equal(finished.body.status, "FINISHED");
  }
  const pending = await sendTls(port, tls, "/v1/pending", {
    scope: encodeScope(scope), operationId: op.operationId, reservationId: op.reservationId });
  assert.equal(pending.body.status, "PENDING");
});

test("pinned mTLS gate client holds exact physical write admission across remote quiesce and refuses unverified peers", {
  skip: !url && "requires isolated ROOTARK_ZK1_TEST_PG_URL",
}, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-gate-client-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const tls = tlsFixture(dir);
  const pool = new Pool({ connectionString: url, max: 3, connectionTimeoutMillis: 3000 });
  t.after(async () => pool.end());
  const gate = new Zk1SharedPgGateAuthority({ pool });
  const scope = randomScope();
  const digest = crypto.randomBytes(32);
  await pool.query("INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)",
    [key(scope), scope.keyring_id, digest]);
  const fingerprint = new crypto.X509Certificate(tls.allowedCert).fingerprint256;
  const server = createZk1SharedPgGateHttpsServer({ key: tls.serverKey,
    cert: tls.serverCert, clientCa: tls.ca, gate,
    principals: { [fingerprint]: { roles: ["admit", "put", "reserve"],
      scopes: [Object.fromEntries(Object.entries(scope).map(([k, v]) => [k, Buffer.from(v).toString("base64url")]))] } },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = { endpoint: "https://localhost:" + server.address().port,
    ca: tls.ca, clientKey: tls.allowedKey, clientCert: tls.allowedCert,
    serverFingerprint256: new crypto.X509Certificate(tls.serverCert).fingerprint256 };
  const client = createZk1SharedPgGateHttpsClient(config);
  const otherPin = createZk1SharedPgGateHttpsClient({ ...config,
    serverFingerprint256: crypto.randomBytes(32).toString("hex").match(/../g).join(":") });
  const objectId = crypto.randomBytes(16).toString("base64url");
  const workerId = crypto.randomBytes(16);
  const input = { scope, workerId, action: "put", objectId, revision: 1, digest };
  await assert.rejects(otherPin.beginIoAdmission(input), /ZK_GATE_TRANSPORT_UNAVAILABLE/);
  const admitted = await client.beginIoAdmission(input);
  assert.equal(admitted.proceed, true);
  assert.deepEqual(await client.beginIoAdmission(input), admitted);
  const write = { ...input, admissionId: admitted.admissionId,
    generation: admitted.generation };
  const ciphertext = crypto.randomBytes(128);
  assert.deepEqual(await client.putCiphertextChunk(write, 0, ciphertext), { stored: true });
  assert.deepEqual(await client.putCiphertextChunk(write, 0, ciphertext), { stored: false });
  const op = { scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest };
  assert.equal((await client.beginQuiesce(op)).state, "QUIESCING");
  await assert.rejects(client.putCiphertextChunk(write, 1, ciphertext), /ZK_GATE_TRANSPORT_UNAVAILABLE/);
  const replay = await client.beginIoAdmission(input);
  assert.equal(replay.proceed, false);
  assert.deepEqual(replay.admissionId, admitted.admissionId);
  assert.deepEqual(await client.finishIoAdmission({ scope, workerId,
    admissionId: admitted.admissionId }), { status: "FINISHED" });
  assert.equal((await client.markPending({ scope, operationId: op.operationId,
    reservationId: op.reservationId })).status, "PENDING");
  const rows = await pool.query("SELECT ciphertext FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1",
    [key(scope)]);
  assert.equal(rows.rowCount, 1);
  assert.deepEqual(rows.rows[0].ciphertext, ciphertext);
});

test("ciphertext sink retries a lost START/PUT ACK identically and never writes after a concurrent gate close", {
  skip: !url && "requires isolated ROOTARK_ZK1_TEST_PG_URL",
}, async (t) => {
  const pool = new Pool({ connectionString: url, max: 3, connectionTimeoutMillis: 3000 });
  t.after(async () => pool.end());
  const gate = new Zk1SharedPgGateAuthority({ pool });
  const scope = randomScope();
  const digest = crypto.randomBytes(32);
  const objectId = crypto.randomBytes(16).toString("base64url");
  await pool.query("INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)",
    [key(scope), scope.keyring_id, digest]);
  let loseStart = true;
  let losePut = true;
  const client = {
    beginIoAdmission: async (io) => {
      const receipt = await gate.beginIoAdmission({ ...io, principal: "trusted-sink" });
      if (loseStart) { loseStart = false; throw new Error("synthetic START ACK dropped after commit"); }
      return receipt;
    },
    putCiphertextChunk: async (io, index, bytes) => {
      const effect = await gate.putCiphertextChunk({ ...io, principal: "trusted-sink" }, index, bytes);
      if (losePut) { losePut = false; throw new Error("synthetic PUT ACK dropped after commit"); }
      return effect;
    },
    finishIoAdmission: async (io) => gate.finishIoAdmission({ ...io, principal: "trusted-sink" }),
  };
  const sink = new Zk1SharedPgCiphertextSink({ gateClient: client });
  const first = crypto.randomBytes(74);
  const second = crypto.randomBytes(81);
  const op = { scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest };
  async function* payloads() {
    yield first;
    await gate.beginQuiesce(op);
    yield second;
  }
  await assert.rejects(sink.put({ scope, objectId, revision: 1,
    digest, chunks: payloads() }), /ZK_GATE_/,
  "the second chunk cannot cross physical PostgreSQL write boundary after QUIESCING");
  const counts = await pool.query("SELECT chunk_index,ciphertext FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1 ORDER BY chunk_index",
    [key(scope)]);
  assert.equal(counts.rowCount, 1);
  assert.equal(counts.rows[0].chunk_index, 0);
  assert.deepEqual(counts.rows[0].ciphertext, first);
  assert.equal((await gate.markPending({ scope, operationId: op.operationId,
    reservationId: op.reservationId })).status, "PENDING",
  "the sink has finished its original worker even on a denied second chunk");
});
