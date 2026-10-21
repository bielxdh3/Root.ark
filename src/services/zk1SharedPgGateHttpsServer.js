"use strict";

// Isolated mTLS data-plane for the PostgreSQL-only zk-1 reference gate.
// NEVER mount this listener inside Root.ark's normal application server.
// Physical PostgreSQL chunk WRITES are serialized against beginQuiesce. TLS
// ciphertext READ/EGRESS deliberately disabled: PostgreSQL may lose a lock
// under a partition while JavaScript keeps writing response bytes.
const https = require("node:https");

const ROUTES = Object.freeze({
  "/v1/admission/start": "admit",
  "/v1/admission/finish": "admit",
  "/v1/chunk/put": "put",
  "/v1/chunk/seal": "seal",
  "/v1/quiesce": "reserve",
  "/v1/pending": "reserve",
});
const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const B64 = /^[A-Za-z0-9_-]+$/;
function reject(code = "ZK_GATE_API_INVALID") {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function exact(obj, fields) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(obj))
    || Reflect.ownKeys(obj).length !== fields.length
    || fields.some((field) => !Object.hasOwn(obj, field))) reject();
}
function decode(value, min, max = min) {
  if (typeof value !== "string" || !B64.test(value)
    || value.length > Math.ceil(max * 4 / 3) + 4) reject();
  const result = Buffer.from(value, "base64url");
  if (result.length < min || result.length > max
    || result.toString("base64url") !== value) reject();
  return result;
}
function normalizedScope(s) {
  exact(s, ["account_id", "compartment_id", "keyring_id"]);
  return { account_id: decode(s.account_id, 16),
    compartment_id: decode(s.compartment_id, 1, 128),
    keyring_id: decode(s.keyring_id, 16) };
}
function scopeKey(s) {
  return s.account_id.toString("hex") + ":" + s.compartment_id.length.toString(16)
    + ":" + s.compartment_id.toString("hex") + ":" + s.keyring_id.toString("hex");
}
function count(value) {
  if (!Number.isSafeInteger(value) || value < 0) reject();
  return value;
}
function authorizeWorker(body, scope, principal, { step = false } = {}) {
  exact(body, step
    ? ["scope", "workerId", "action", "objectId", "revision", "digest", "admissionId", "generation", "chunkIndex", ...(body.action === "put" ? ["ciphertextBase64"] : [])]
    : ["scope", "workerId", "action", "objectId", "revision", "digest"]);
  if (typeof body.objectId !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(body.objectId)
    || Buffer.from(body.objectId, "base64url").toString("base64url") !== body.objectId
    || !["get", "put"].includes(body.action)) reject();
  const result = { scope, workerId: decode(body.workerId, 16), principal,
    action: body.action, objectId: body.objectId, revision: count(body.revision),
    digest: decode(body.digest, 32) };
  if (result.revision < 1) reject();
  if (step) {
    result.admissionId = decode(body.admissionId, 16);
    result.generation = count(body.generation);
    if (result.generation < 1 || count(body.chunkIndex) > 0x7fffffff) reject();
  }
  return result;
}
function sendJson(res, status, data) {
  if (res.destroyed || res.headersSent) return;
  const raw = Buffer.from(JSON.stringify(data));
  res.writeHead(status, { "content-type": "application/json", "content-length": raw.length,
    "cache-control": "no-store", "x-content-type-options": "nosniff" });
  res.end(raw);
}
async function readJson(req, max) {
  if (req.headers["content-type"] !== "application/json") reject();
  const header = req.headers["content-length"];
  if (header !== undefined && (!/^\d+$/.test(header) || Number(header) > max)) reject();
  const parts = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > max) reject();
    parts.push(chunk);
  }
  if (!total) reject();
  try { return JSON.parse(Buffer.concat(parts).toString("utf8")); }
  catch (_) { reject(); }
}
function makeGrants(principals) {
  if (!principals || typeof principals !== "object" || Array.isArray(principals)
    || Object.keys(principals).length < 1 || Object.keys(principals).length > 128) reject();
  const grants = new Map();
  for (const [fingerprint, grant] of Object.entries(principals)) {
    exact(grant, ["roles", "scopes"]);
    if (!FINGERPRINT.test(fingerprint) || !Array.isArray(grant.roles)
      || grant.roles.length < 1 || grant.roles.some((role) => !Object.values(ROUTES).includes(role))
      || !Array.isArray(grant.scopes) || grant.scopes.length < 1 || grant.scopes.length > 64) reject();
    const key = fingerprint.toUpperCase();
    if (grants.has(key)) reject();
    const scopes = new Set(grant.scopes.map((scope) => scopeKey(normalizedScope(scope))));
    if (scopes.size !== grant.scopes.length) reject();
    grants.set(key, { roles: new Set(grant.roles), scopes });
  }
  return grants;
}
function createZk1SharedPgGateHttpsServer({ key, cert, clientCa, gate,
  sealedStore = null, principals }) {
  if (!key || !cert || !clientCa || !gate
    || (sealedStore !== null && typeof sealedStore.seal !== "function")
    || ["beginIoAdmission", "finishIoAdmission", "putCiphertextChunk",
      "beginQuiesce", "markPending"].some((name) =>
      typeof gate[name] !== "function")) reject();
  const grants = makeGrants(principals);
  return https.createServer({ key, cert, ca: clientCa,
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3" }, async (req, res) => {
    try {
      if (req.method !== "POST" || !Object.hasOwn(ROUTES, req.url)) {
        return sendJson(res, 404, { error: "NOT_FOUND" });
      }
      const peer = req.socket.getPeerCertificate();
      const principal = peer?.fingerprint256?.toUpperCase();
      const grant = principal && grants.get(principal);
      if (!req.socket.authorized || !grant || !grant.roles.has(ROUTES[req.url])) {
        return sendJson(res, 403, { error: "FORBIDDEN" });
      }
      const body = await readJson(req, req.url === "/v1/chunk/put" ? 6 * 1024 * 1024 : 2048);
      const scope = normalizedScope(body.scope);
      if (!grant.scopes.has(scopeKey(scope))) return sendJson(res, 403, { error: "FORBIDDEN" });
      if (req.url === "/v1/admission/start") {
        const io = authorizeWorker(body, scope, principal);
        // There is no safe ciphertext GET/EGRESS adapter yet. Do not issue a
        // GET admission that could be mistaken for egress authorization.
        if (io.action !== "put") reject();
        const receipt = await gate.beginIoAdmission(io);
        return sendJson(res, 201, { admissionId: receipt.admissionId.toString("base64url"),
          generation: receipt.generation, proceed: receipt.proceed });
      }
      if (req.url === "/v1/admission/finish") {
        exact(body, ["scope", "admissionId", "workerId"]);
        const result = await gate.finishIoAdmission({ scope,
          admissionId: decode(body.admissionId, 16), workerId: decode(body.workerId, 16), principal });
        return sendJson(res, 200, result);
      }
      if (req.url === "/v1/chunk/seal") {
        // Only a separately provisioned PostgreSQL-only sealed store can
        // publish a bounded ciphertext root. This mTLS endpoint receives an
        // already OWNER-validated commitment from its trusted gateway; it
        // does not itself authorize any device or publish a ZK manifest.
        if (!sealedStore) return sendJson(res, 503, { error: "ZK_GATE_UNAVAILABLE" });
        exact(body, ["scope", "workerId", "action", "objectId", "revision",
          "digest", "admissionId", "generation", "expectedChunkCount", "expectedRootHash"]);
        const io = authorizeWorker({ scope: body.scope, workerId: body.workerId,
          action: body.action, objectId: body.objectId, revision: body.revision,
          digest: body.digest }, scope, principal);
        if (io.action !== "put" || !Number.isSafeInteger(body.expectedChunkCount)
          || body.expectedChunkCount < 1 || body.expectedChunkCount > 4096
          || !Number.isSafeInteger(body.generation) || body.generation < 1) reject();
        const result = await sealedStore.seal({ ...io,
          admissionId: decode(body.admissionId, 16), generation: body.generation,
          expectedChunkCount: body.expectedChunkCount,
          expectedRootHash: decode(body.expectedRootHash, 32) });
        return sendJson(res, 200, result);
      }
      if (req.url === "/v1/quiesce" || req.url === "/v1/pending") {
        exact(body, ["scope", "operationId", "reservationId", ...(req.url === "/v1/quiesce" ? ["revision", "digest"] : [])]);
        const operation = { scope, operationId: decode(body.operationId, 16),
          reservationId: decode(body.reservationId, 16) };
        const result = req.url === "/v1/quiesce"
          ? await gate.beginQuiesce({ ...operation, revision: count(body.revision),
            digest: decode(body.digest, 32) })
          : await gate.markPending(operation);
        return sendJson(res, 200, result);
      }
      const io = authorizeWorker(body, scope, principal, { step: true });
      if (io.action !== "put") reject();
      if (io.action === "put") {
        const chunk = decode(body.ciphertextBase64, 1, 4 * 1024 * 1024);
        const result = await gate.putCiphertextChunk(io, body.chunkIndex, chunk);
        return sendJson(res, 200, result);
      }
    } catch (error) {
      // An unknown physical outcome is a failure; never turn it into an
      // application-level positive authorization. Do not leak PG internals.
      if (!res.headersSent && !res.destroyed) {
        const status = error?.code === "ZK_GATE_DENIED" ? 403
          : error?.code === "ZK_GATE_CHUNK_CONFLICT" ? 409
            : error?.code === "ZK_GATE_API_INVALID" ? 400 : 503;
        sendJson(res, status, { error: status === 503 ? "ZK_GATE_UNAVAILABLE" : error.code });
      } else if (!res.destroyed && !res.writableEnded) res.destroy();
    }
  });
}
module.exports = { createZk1SharedPgGateHttpsServer };
