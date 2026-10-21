"use strict";

// LAB ONLY. This SAME directly supervised ChildProcess owns the mTLS socket,
// the physical PostgreSQL connection, and write_bound_chunk invocation.
// Neither TLS peer nor HTTP input supplies scope/admission/PID/generation.
const crypto = require("node:crypto");
const https = require("node:https");
const { Pool } = require("pg");
const { verifyZk1ChunkWriterRuntimePool } =
  require("../../src/services/zk1SharedPgChunkWriterRuntime");

const fail = () => { throw new Error("ZK_LAB_MTLS_CHILD_DENIED"); };
function decode(value, min, max = min) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) fail();
  const b = Buffer.from(value, "base64url");
  if (b.length < min || b.length > max || b.toString("base64url") !== value) fail();
  return b;
}
function parse(m) {
  if (!m || m.kind !== "init" || m.action !== "put"
    || m.processPid !== process.pid || !Number.isSafeInteger(m.revision)
    || m.revision < 1 || !Number.isSafeInteger(m.generation) || m.generation < 1
    || typeof m.objectId !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(m.objectId)
    || Buffer.from(m.objectId, "base64url").toString("base64url") !== m.objectId
    || typeof m.principal !== "string" || m.principal.length < 1
    || !/^[a-f0-9]{64}$/.test(m.clientFingerprint)
    || typeof m.pgUrl !== "string") fail();
  const url = new URL(m.pgUrl);
  if (url.protocol !== "postgresql:" || url.hostname !== "127.0.0.1"
    || !/^zkwriterfixture_[a-f0-9]{12}$/.test(decodeURIComponent(url.username))
    || !url.password || url.pathname !== "/gatefixture" || !url.port
    || url.search || url.hash) fail();
  const scope = { account_id: decode(m.scope?.account_id, 16),
    compartment_id: decode(m.scope?.compartment_id, 1, 128),
    keyring_id: decode(m.scope?.keyring_id, 16) };
  return { pgUrl: m.pgUrl, scope, scopeKey: scope.account_id.toString("hex") + ":"
    + scope.compartment_id.length.toString(16) + ":" + scope.compartment_id.toString("hex"),
  workerId: decode(m.workerId, 16), admissionId: decode(m.admissionId, 16),
  hostKeyId: decode(m.hostKeyId, 16), processEpoch: decode(m.processEpoch, 16),
  processPid: m.processPid, objectId: m.objectId,
  revision: m.revision, digest: decode(m.digest, 32),
  generation: m.generation, principal: m.principal, fingerprint: m.clientFingerprint,
  tls: { key: decode(m.tls?.key, 1, 8192), cert: decode(m.tls?.cert, 1, 8192),
    ca: decode(m.tls?.ca, 1, 8192) } };
}
let pool;
let expected;
let server;
let phase = "new";
let held = null;
let wake;
let committed = null;
let used = false;
const say = (message) => { if (process.connected) process.send(message); };
function denyResponse(response, status = 503) {
  if (response.destroyed || response.headersSent) return;
  response.writeHead(status, { "content-length": "0", "cache-control": "no-store" });
  response.end();
}
async function writeChunk(index, blob, response) {
  let c;
  try {
    phase = "busy";
    c = await pool.connect();
    await c.query("BEGIN ISOLATION LEVEL READ COMMITTED");
    const preflight = await c.query(`SELECT zk1_gate.verify_chunk_writer_binding(
      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) AS allowed`,
    [expected.scopeKey, expected.admissionId, expected.objectId,
      expected.generation, expected.workerId, expected.processEpoch,
      process.pid, expected.revision, expected.digest,
      expected.scope.keyring_id, expected.principal]);
    if (preflight.rowCount !== 1 || preflight.rows[0]?.allowed !== true) fail();
    const result = await c.query(
      "SELECT zk1_gate.write_bound_chunk($1,$2) AS stored", [index, blob]);
    if (result.rowCount !== 1 || result.rows[0]?.stored !== true) fail();
    phase = "held";
    held = { index, response };
    say({ kind: "held", index });
    await new Promise((resolve) => { wake = resolve; });
    wake = null;
    // A client may disconnect while the SQL transaction still holds HEAD.
    if (response.destroyed || response.writableEnded) fail();
    await c.query("COMMIT");
    c.release();
    c = null;
    phase = "confirming";
    committed = { index, response };
    // No TLS success before independent gate-role SQL readback in the parent.
    say({ kind: "verify", index,
      digest: crypto.createHash("sha256").update(blob).digest("hex") });
  } catch (_) {
    if (c) try { await c.query("ROLLBACK"); } catch (_) { /* fail closed */ }
    phase = "failed";
    denyResponse(response);
  } finally {
    if (c) c.release();
  }
}
function accept(request, response) {
  if (request.method !== "PUT" || !/^\/fixture-chunk\/(?:0|[1-9][0-9]{0,3})$/.test(request.url)) {
    denyResponse(response, 404);
    return;
  }
  const peer = request.socket.getPeerCertificate(true);
  if (!request.client.authorized || !peer?.raw
    || crypto.createHash("sha256").update(peer.raw).digest("hex") !== expected.fingerprint) {
    denyResponse(response, 403);
    return;
  }
  if (phase !== "ready" || used) {
    denyResponse(response);
    return;
  }
  const index = Number(request.url.slice("/fixture-chunk/".length));
  if (index > 4095 || !/^[1-9][0-9]{0,3}$/.test(request.headers["content-length"] || "")) {
    denyResponse(response, 400);
    return;
  }
  const size = Number(request.headers["content-length"]);
  if (size < 1 || size > 4096) {
    denyResponse(response, 413);
    return;
  }
  used = true;
  const chunks = [];
  let received = 0;
  request.on("data", (part) => {
    received += part.length;
    if (received > size) request.destroy();
    else chunks.push(part);
  });
  request.on("end", () => {
    if (received !== size || response.destroyed) return denyResponse(response, 400);
    void writeChunk(index, Buffer.concat(chunks), response);
  });
}
async function init(message) {
  phase = "starting";
  expected = parse(message);
  pool = new Pool({ connectionString: expected.pgUrl, max: 1,
    connectionTimeoutMillis: 3000 });
  await verifyZk1ChunkWriterRuntimePool(pool);
  const inheritedSecrets = Object.keys(process.env).some((k) =>
    /(?:ROOTARK|PG(?:PASSWORD|USER|HOST|DATABASE)|PRIVATE_KEY|SECRET)/i.test(k));
  if (inheritedSecrets) fail();
  server = https.createServer({ key: expected.tls.key, cert: expected.tls.cert,
    ca: expected.tls.ca, requestCert: true, rejectUnauthorized: true,
    minVersion: "TLSv1.3", maxVersion: "TLSv1.3" }, accept);
  server.maxHeadersCount = 12;
  server.headersTimeout = 5000;
  server.requestTimeout = 8000;
  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    if (!address || address.address !== "127.0.0.1") process.exit(2);
    phase = "ready";
    say({ kind: "listening", address: address.address, port: address.port,
      restrictedRoleVerified: true, inheritedSecrets: false });
  });
}
process.on("message", (message) => {
  try {
    if (phase === "new" && message?.kind === "init") {
      void init(message).catch(() => process.exit(2));
      return;
    }
    if (phase === "held" && message?.kind === "release" && wake) {
      wake(); return;
    }
    if (phase === "confirming" && message?.kind === "confirmed"
      && message.index === committed?.index) {
      phase = "finished";
      if (!committed.response.destroyed && !committed.response.writableEnded) {
        committed.response.writeHead(200, { "content-length": "0", "cache-control": "no-store" });
        committed.response.end();
      }
      return;
    }
    process.exit(2);
  } catch (_) { process.exit(2); }
});
process.on("disconnect", () => process.exit(2));
