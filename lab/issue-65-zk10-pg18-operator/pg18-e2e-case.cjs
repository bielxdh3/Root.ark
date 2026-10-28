"use strict";
// Invoked ONLY by run-disposable.js; no ambient app/production database URL.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const { fork, spawnSync } = require("node:child_process");
const { Pool } = require("pg");
const { signOwnerCutover } = require("../../src/crypto/rootark-zk10-account-cutover-v1");
const { generateNativeFixtureCertificates } =
  require("../../test/support/issue-65-native-openssl-fixture");
const { privateAuthorityDirectory } =
  require("../../test/support/issue-65-private-authority-directory");
const { createZk10Pg18Operator } = require("./operator");

const accountId = Buffer.alloc(16, 1).toString("base64url");
const zkAccountId = Buffer.alloc(16, 2).toString("base64url");
const digest = (v) => crypto.createHash("sha256").update(v).digest("hex");
const operatorId = "zk10-disposable-operator";
const identityDigest = digest("independently pinned DEV-only account identity");
const physicalDigest = digest("opaque NOT verified PG physical stop");
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function startChild(filename, args, opts = {}) {
  const child = fork(path.join(__dirname, filename), args, {
    stdio: ["ignore", "pipe", "pipe", "ipc"], windowsHide: true,
    env: { ...process.env, ...opts.env }, serialization: "json",
    execArgv: [], // Never inherit the test runner's --test arguments.
  });
  const issue = { value: "" };
  child.stderr.on("data", (buffer) => {
    const message = String(buffer);
    if (/MODULE_NOT_FOUND/.test(message)) issue.value = "ZK10_CHILD_MODULE_NOT_FOUND";
    else if (/SyntaxError/.test(message)) issue.value = "ZK10_CHILD_SYNTAX_ERROR";
    else if (/ReferenceError/.test(message)) issue.value = "ZK10_CHILD_REFERENCE_ERROR";
    else if (/TypeError/.test(message)) issue.value = "ZK10_CHILD_TYPE_ERROR";
  });
  child.safeIssue = issue;
  return child;
}
function ready(server) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error("ZK10_CHILD_START_TIMEOUT")), 15000);
    function message(m) {
      if (m?.type !== "ready" && m?.type !== "fatal") return;
      clearTimeout(timer); server.off("message", message);
      if (m.type === "ready") resolve(m.port);
      else reject(Error(/^ZK10_[A-Z_]{2,64}$/.test(m.code || "")
        ? m.code : "ZK10_CHILD_FAILED"));
    }
    server.on("message", message);
    server.once("exit", () => {
      clearTimeout(timer); reject(Error("ZK10_CHILD_EARLY_EXIT"));
    });
  });
}
let nextId = 0;
function call(child, method, payload) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null) {
      reject(Error("ZK10_CLIENT_ALREADY_EXITED_"
        + (child.safeIssue.value || child.exitCode))); return;
    }
    const requestId = ++nextId;
    const timer = setTimeout(() => {
      child.off("message", response); child.off("exit", exit);
      reject(Error("ZK10_CLIENT_CALL_TIMEOUT_" + (child.safeIssue.value || "NO_REPLY")));
    }, 15000);
    function exit(code) {
      clearTimeout(timer); child.off("message", response);
      reject(Error("ZK10_CLIENT_EXIT_" + (Number.isInteger(code) ? code : "unknown")));
    }
    function response(m) {
      if (m?.type !== "reply" || m.requestId !== requestId) return;
      clearTimeout(timer); child.off("message", response);
      child.off("exit", exit); resolve(m);
    }
    child.on("message", response);
    child.once("exit", exit);
    child.send({ type: "call", requestId, method, payload });
  });
}
async function stop(child) {
  if (!child || child.exitCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill();
  await exited;
}
async function restartOwnedPostgres() {
  const id = process.env.ROOTARK_ZK10_DEV_PG_CONTAINER;
  if (!/^[0-9a-f]{64}$/.test(id || "")) throw Error("ZK10_UNKNOWN_CONTAINER");
  const info = spawnSync("docker", ["container", "inspect", "--format",
    "{{json .Config.Labels}}", id],
  { encoding: "utf8", windowsHide: true, timeout: 8000 });
  let labels;
  try { labels = JSON.parse(info.stdout); } catch (_) { labels = null; }
  if (info.status !== 0 || labels?.["rootark.lab"] !== "issue65-shared-gate"
    || labels?.["rootark.owner"] !== "disposable-local")
    throw Error("ZK10_FOREIGN_CONTAINER_REFUSED");
  const restart = spawnSync("docker", ["restart", id], {
    encoding: "utf8", windowsHide: true, timeout: 30000 });
  if (restart.status !== 0 || restart.stdout.trim() !== id.slice(0, 12)
    && restart.stdout.trim() !== id) throw Error("ZK10_DISPOSABLE_RESTART_FAILED");
  for (let attempts = 0; attempts < 60; attempts++) {
    const mapped = spawnSync("docker", ["port", id, "5432/tcp"], {
      encoding: "utf8", windowsHide: true, timeout: 3500,
    });
    const portMatch = /^127\.0\.0\.1:(\d{2,5})$/.exec(mapped.stdout.trim());
    if (mapped.status !== 0 || !portMatch || Number(portMatch[1]) < 1024) {
      await delay(200); continue;
    }
    const hostUrl = process.env.ROOTARK_ZK10_DEV_PG_URL.replace(
      /@127\.0\.0\.1:\d+\//, "@127.0.0.1:" + portMatch[1] + "/");
    const check = spawnSync("docker", ["exec", id, "psql", "-X", "-tA",
      "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "gatefixture",
      "-c", "SHOW server_version"], {
      encoding: "utf8", windowsHide: true, timeout: 3500,
    });
    if (check.status === 0 && check.stdout.trim() === "18.6") {
      // docker exec/psql ready does not imply Docker Desktop's loopback port
      // forward has been reattached after a container restart.
      const probe = new Pool({ connectionString: hostUrl,
        max: 1, connectionTimeoutMillis: 700 });
      try {
        const readback = await probe.query("SELECT 1 AS verified");
        if (readback.rows[0]?.verified === 1) return hostUrl;
      } catch (_) { /* retry only the exact disposable loopback fixture */ }
      finally { await probe.end().catch(() => {}); }
    }
    await delay(200);
  }
  throw Error("ZK10_DISPOSABLE_POSTGRES_NOT_READY");
}

test("real PostgreSQL18 CAS, separate mTLS client PIDs, lost ACK, operator+PG restart, signed floor", {
  timeout: 125000,
}, async (t) => {
  const stage = (name) => process.stdout.write("ZK10_DEV_STAGE=" + name + "\n");
  stage("begin");
  const pgUrl = process.env.ROOTARK_ZK10_DEV_PG_URL;
  if (!/^postgresql:\/\/[^\s]+@127\.0\.0\.1:\d+\/gatefixture$/.test(pgUrl || ""))
    throw Error("ZK10_MISSING_VERIFIED_DISPOSABLE_DATABASE");
  const dir = privateAuthorityDirectory("zk10-pg18-w118-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  generateNativeFixtureCertificates(dir, {
    caSubject: "ZK10 PG18 disposable CA", servers: ["authority"],
    clients: ["client", "foreign"] });
  const owner = crypto.generateKeyPairSync("ed25519");
  const operatorKeys = crypto.generateKeyPairSync("ed25519");
  const pem = (key, type) => key.export({ format: "pem", type }).toString();
  const configFile = path.join(dir, "operator-config.json");
  const config = {
    pgUrl, certDir: dir, operatorId, accountId, zkAccountId,
    identityDigest, physicalDigest,
    operatorPrivatePem: pem(operatorKeys.privateKey, "pkcs8"),
    operatorPublicPem: pem(operatorKeys.publicKey, "spki"),
    ownerPublicPem: pem(owner.publicKey, "spki"),
    clientFingerprint256:
      new crypto.X509Certificate(fs.readFileSync(path.join(dir, "client.pem"))).fingerprint256,
    dropCasAckOnce: true, port: 0,
  };
  fs.writeFileSync(configFile, JSON.stringify(config), { flag: "wx", mode: 0o600 });
  const children = new Set();
  t.after(async () => {
    await Promise.all([...children].map(stop));
  });
  let server = startChild("server-child.js", [configFile]);
  children.add(server);
  const port = await ready(server);
  stage("operator-started");
  const pool = new Pool({ connectionString: pgUrl, max: 2 });
  let poolClosed = false;
  t.after(async () => { if (!poolClosed) await pool.end(); });
  const operator = createZk10Pg18Operator({
    pool, operatorId, immutableAccountId: accountId, canonicalZkAccountId: zkAccountId,
    identityDigest, initialPhysicalDigest: physicalDigest,
    operatorPrivateKey: operatorKeys.privateKey,
    operatorPublicKey: operatorKeys.publicKey,
    ownerPublicKey: owner.publicKey,
  });
  const minimum = await operator.minimum();
  stage("minimum");
  assert.equal(minimum.sequence, 1);
  assert.equal(minimum.everEnrolled, false);
  const serverPin = new crypto.X509Certificate(
    fs.readFileSync(path.join(dir, "authority.pem"))).fingerprint256;
  const foreignStatus = await new Promise((resolve, reject) => {
    const body = Buffer.from("{}");
    const request = https.request({
      hostname: "127.0.0.1", port, method: "POST",
      path: "/v1/zk10/current", ca: fs.readFileSync(path.join(dir, "ca.pem")),
      cert: fs.readFileSync(path.join(dir, "foreign.pem")),
      key: fs.readFileSync(path.join(dir, "foreign.key")),
      minVersion: "TLSv1.3", maxVersion: "TLSv1.3", rejectUnauthorized: true,
      headers: { "content-type": "application/json", "content-length": body.length },
    }, (response) => { response.resume(); resolve(response.statusCode); });
    request.on("error", reject); request.end(body);
  });
  assert.equal(foreignStatus, 403,
    "a CA-signed foreign client still fails the exact mTLS client identity pin");
  const clientConfig = {
    certDir: dir, operatorId, accountId, zkAccountId, identityDigest,
    operatorPublicPem: config.operatorPublicPem, ownerPublicPem: config.ownerPublicPem,
    serverPin, port, minimum,
  };
  const a = startChild("client-child.js", []); children.add(a);
  const b = startChild("client-child.js", []); children.add(b);
  assert.ok(a.pid && b.pid && a.pid !== b.pid,
    "client A and B must be different OS processes");
  const clientReady = (child) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error("ZK10_CHILD_READY_TIMEOUT_"
      + (child.safeIssue.value || "NO_READY"))), 5000);
    child.on("message", function onMessage(m) {
      if (m?.type !== "client-ready") return;
      clearTimeout(timer); child.off("message", onMessage); resolve(true);
    });
  });
  await Promise.all([clientReady(a), clientReady(b)]);
  stage("initializing-client-a");
  const aInit = await call(a, "init", clientConfig);
  if (!aInit.ok) throw Error("ZK10_INIT_A_" + String(aInit.code)
    .replace(/[^A-Z0-9_]/gi, "_").slice(0, 75));
  stage("initializing-client-b");
  const bInit = await call(b, "init", clientConfig);
  if (!bInit.ok) throw Error("ZK10_INIT_B_" + String(bInit.code)
    .replace(/[^A-Z0-9_]/gi, "_").slice(0, 75));
  stage("clients-started");
  const initial = await call(a, "readCurrent");
  stage("current");
  assert.equal(initial.ok, true);
  assert.equal(initial.result.status, "never_enrolled");
  const statement = signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: accountId, zk_account_id: zkAccountId,
    generation: 1, previous_cutover_digest: null,
    inventory_head: digest("unverified-disposable-owner-inventory"),
    complete_corpus: true,
    covered_compartments: [Buffer.alloc(16, 3).toString("base64url")],
    legacy_egress_scope: "all", reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced", grants: [],
    suite: "zk1-v2", nonce: crypto.randomBytes(32).toString("base64url"),
    issued_at: Math.floor(Date.now() / 1000),
  }, owner.privateKey);
  const lease = () => ({ ownerStatement: statement,
    leaseId: crypto.randomBytes(16).toString("base64url"),
    fencingEpoch: 7, leaseExpiresAtMs: Date.now() + 9000 });
  const { signature: _unused, ...ownerPayload } = statement;
  const foreignSignature = signOwnerCutover(ownerPayload,
    crypto.generateKeyPairSync("ed25519").privateKey);
  const forgedOwner = await call(b, "submitCutover", {
    ...lease(), ownerStatement: foreignSignature,
  });
  assert.equal(forgedOwner.ok, false);
  assert.equal(forgedOwner.code, "ZK10_EXTERNAL_CAS_UNAVAILABLE");
  assert.equal(forgedOwner.state, "idle");
  assert.equal((await operator.minimum()).sequence, 1,
    "a wrong owner signing key cannot change the PostgreSQL head");
  const first = await call(a, "submitCutover", lease());
  stage("cas");
  assert.equal(first.ok, false, "destroyed ACK must be uncertain");
  assert.equal(first.code, "ZK10_EXTERNAL_CAS_UNCERTAIN");
  assert.equal(first.state, "uncertain");
  const afterCommit = await operator.minimum();
  stage("commit");
  assert.equal(afterCommit.sequence, 2, "real PG committed despite missing ACK");
  assert.equal(afterCommit.everEnrolled, true);
  const repeated = await call(a, "submitCutover", lease());
  assert.equal(repeated.ok, false);
  assert.equal(repeated.code, "ZK10_EXTERNAL_CAS_UNCERTAIN");
  assert.equal((await operator.minimum()).headDigest, afterCommit.headDigest);

  await stop(server); children.delete(server);
  stage("server-stopped");
  await pool.end();
  poolClosed = true;
  config.pgUrl = await restartOwnedPostgres();
  stage("postgres-restarted");
  config.dropCasAckOnce = false; config.port = port;
  fs.writeFileSync(configFile, JSON.stringify(config), { flag: "w", mode: 0o600 });
  // The next OS process reads the protected state from restarted PG WAL/data.
  server = startChild("server-child.js", [configFile]); children.add(server);
  assert.equal(await ready(server), port);
  stage("operator-restarted");
  const reconciled = await call(a, "reconcile");
  stage("reconciled");
  assert.equal(reconciled.ok, true);
  assert.equal(reconciled.result.state, "observed_protected");
  assert.equal(reconciled.result.authorizesProductionCutover, false);
  const fresh = await call(b, "readCurrent");
  stage("fresh-current");
  assert.equal(fresh.ok, true);
  assert.equal(fresh.result.status, "protected_enforced");
  assert.equal(fresh.result.ownerGeneration, 1);
  const denied = await call(b, "submitCutover", lease());
  assert.equal(denied.ok, false, "replayed owner grant cannot commit another generation");
  assert.equal(denied.state, "idle");
  stage("complete");
});
