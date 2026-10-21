"use strict";

// Separate process boundary for the zk-1 CAS/status ENGINE. Operators must
// provision different pinned credentials for status, witness and writers;
// this transport alone is not an independent distributed CAS or I/O gate.
const https = require("node:https");

const MAX_METADATA_BYTES = 4096;
const MAX_COMMIT_BODY_BYTES = 12 * 1024 * 1024;
const B64U = /^[A-Za-z0-9_-]+$/;
const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const ROUTE_ROLES = Object.freeze({
  "/v1/register": "register", "/v1/commit": "commit", "/v1/terminal": "terminal",
  "/v1/manifest": "manifest",
});
const SCOPE_FIELDS = Object.freeze(["account_id", "compartment_id", "keyring_id"]);
const QUERY_FIELDS = Object.freeze([
  ...SCOPE_FIELDS, "reservation_id", "operation_id", "request_digest",
  "package_envelope_digest", "expected_revision", "expected_manifest_digest",
  "proposed_revision", "proposed_manifest_digest",
]);
const BYTES = Object.freeze({
  account_id: [16, 16], compartment_id: [1, 128], keyring_id: [16, 16],
  reservation_id: [16, 16], operation_id: [16, 16], request_digest: [32, 32],
  package_envelope_digest: [32, 32], expected_manifest_digest: [32, 32],
  proposed_manifest_digest: [32, 32], nonce: [32, 32],
});
function invalid() {
  const e = new Error("CAS_HTTP_INVALID");
  e.code = "CAS_HTTP_INVALID";
  throw e;
}
function exact(o, fields) {
  if (!o || typeof o !== "object" || Array.isArray(o)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(o))
    || Reflect.ownKeys(o).length !== fields.length
    || fields.some((f) => !Object.hasOwn(o, f))
    || Reflect.ownKeys(o).some((f) => !fields.includes(f))) invalid();
}
function decode(value, [min, max]) {
  if (typeof value !== "string" || !B64U.test(value) || value.length > (max * 2 + 4)) invalid();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.byteLength < min || bytes.byteLength > max
    || bytes.toString("base64url") !== value) invalid();
  return bytes;
}
function scopeKey(scope) {
  return scope.account_id.toString("hex") + ":" + scope.compartment_id.byteLength + ":"
    + scope.compartment_id.toString("hex") + ":" + scope.keyring_id.toString("hex");
}
function normalize(raw, fields) {
  exact(raw, fields);
  const o = Object.create(null);
  for (const field of fields) {
    const value = raw[field];
    if (Object.hasOwn(BYTES, field)) {
      o[field] = value === null
        && ["package_envelope_digest", "expected_manifest_digest"].includes(field)
        ? null : decode(value, BYTES[field]);
    } else if (field === "expected_revision") {
      if (value !== null && (!Number.isSafeInteger(value) || value < 1)) invalid();
      o[field] = value;
    } else if (field === "proposed_revision") {
      if (!Number.isSafeInteger(value) || value < 1) invalid();
      o[field] = value;
    } else invalid();
  }
  return o;
}
async function readJson(req, maxBytes) {
  if (req.headers["content-type"] !== "application/json") invalid();
  const length = req.headers["content-length"];
  if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > maxBytes)) invalid();
  const parts = [];
  let total = 0;
  for await (const part of req) {
    total += part.byteLength;
    if (total > maxBytes) invalid();
    parts.push(part);
  }
  if (!total) invalid();
  try { return JSON.parse(Buffer.concat(parts).toString("utf8")); }
  catch (_) { invalid(); }
}
function respond(res, status, object) {
  const body = Buffer.from(JSON.stringify(object), "utf8");
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(body.byteLength),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(body);
}
function createZk1CasStatusHttpsServer({ key, cert, clientCa, ledger, principals }) {
  if (!key || !cert || !clientCa || !ledger
    || typeof ledger.registerReservation !== "function"
    || typeof ledger.commit !== "function" || typeof ledger.getTerminalProof !== "function"
    || typeof ledger.getCommittedManifest !== "function"
    || !principals || typeof principals !== "object"
    || Object.keys(principals).length < 1 || Object.keys(principals).length > 128) invalid();
  const allowed = new Map();
  for (const [fingerprint, config] of Object.entries(principals)) {
    exact(config, ["roles", "scopes"]);
    if (!FINGERPRINT.test(fingerprint) || !Array.isArray(config.roles)
      || !config.roles.length || config.roles.length > 4
      || new Set(config.roles).size !== config.roles.length
      || config.roles.some((role) => !Object.values(ROUTE_ROLES).includes(role))
      || !Array.isArray(config.scopes) || !config.scopes.length || config.scopes.length > 64) invalid();
    const scopes = new Set(config.scopes.map((scope) => scopeKey(normalize(scope, SCOPE_FIELDS))));
    if (scopes.size !== config.scopes.length || allowed.has(fingerprint.toUpperCase())) invalid();
    allowed.set(fingerprint.toUpperCase(), { roles: new Set(config.roles), scopes });
  }
  const server = https.createServer({
    key, cert, ca: clientCa, requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, async (req, res) => {
    try {
      if (req.method !== "POST" || !Object.hasOwn(ROUTE_ROLES, req.url)) {
        return respond(res, 404, { error: "NOT_FOUND" });
      }
      const peer = req.socket.getPeerCertificate();
      const grant = peer?.fingerprint256 && allowed.get(peer.fingerprint256.toUpperCase());
      if (!req.socket.authorized || !grant || !grant.roles.has(ROUTE_ROLES[req.url])) {
        return respond(res, 403, { error: "FORBIDDEN" });
      }
      const body = await readJson(req, req.url === "/v1/commit"
        ? MAX_COMMIT_BODY_BYTES : MAX_METADATA_BYTES);
      if (req.url === "/v1/manifest") {
        exact(body, ["scope"]);
        const scope = normalize(body.scope, SCOPE_FIELDS);
        if (!grant.scopes.has(scopeKey(scope))) return respond(res, 403, { error: "FORBIDDEN" });
        const manifest = await ledger.getCommittedManifest({ scope });
        return respond(res, 200, { manifestBase64: Buffer.from(manifest).toString("base64url") });
      }
      if (req.url === "/v1/terminal") {
        exact(body, ["query", "nonce"]);
        const query = normalize(body.query, QUERY_FIELDS);
        if (!grant.scopes.has(scopeKey(query))) return respond(res, 403, { error: "FORBIDDEN" });
        const receipt = await ledger.getTerminalProof({ query, nonce: decode(body.nonce, BYTES.nonce) });
        return respond(res, 200, { proofBase64: Buffer.from(receipt).toString("base64url") });
      }
      exact(body, req.url === "/v1/register" ? ["receiptBase64"]
        : ["receiptBase64", "manifestBase64"]);
      const receipt = decode(body.receiptBase64, [1, 4096]);
      // Decode and verify the *signed* receipt before accepting its scope.
      // The ledger will verify again at its transaction boundary.
      const ticket = await ledger.verifiedTicket(receipt);
      if (!grant.scopes.has(scopeKey(ticket.query))) return respond(res, 403, { error: "FORBIDDEN" });
      if (req.url === "/v1/register") {
        const outcome = await ledger.registerReservation({ receipt });
        return respond(res, 200, { status: outcome.status, authority: "CAS_ENGINE_ONLY" });
      }
      const manifestBytes = decode(body.manifestBase64, [1, 8 * 1024 * 1024]);
      const result = await ledger.commit({ receipt, manifestBytes });
      return respond(res, 200, { status: result.status, replay: result.replay,
        authority: "CAS_ENGINE_ONLY" });
    } catch (error) {
      if (res.headersSent || res.destroyed) return;
      const status = error?.code === "CAS_HTTP_INVALID" || error?.code === "CAS_INVALID"
        ? 400 : ["CAS_CONFLICT", "CAS_FENCED", "CAS_TOMBSTONED", "CAS_EXPIRED",
          "CAS_KEYRING_CONFLICT", "CAS_NOT_RESERVED", "CAS_INVALID_MANIFEST"]
          .includes(error?.code) ? 409 : 503;
      return respond(res, status, { error: status === 400 ? "INVALID_REQUEST"
        : status === 409 ? "CAS_CONFLICT" : "CAS_UNAVAILABLE" });
    }
  });
  server.headersTimeout = 5000;
  server.requestTimeout = 10000;
  server.timeout = 10000;
  server.keepAliveTimeout = 1000;
  return server;
}

function drainZk1CasStatusHttpsServer(server, { deadlineMs = 2000 } = {}) {
  if (!server || typeof server.close !== "function"
    || !Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 10000) invalid();
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(() => server.closeAllConnections(), deadlineMs);
    deadline.unref();
    server.close((error) => {
      clearTimeout(deadline);
      if (error) reject(error);
      else resolve();
    });
    server.closeIdleConnections();
  });
}

module.exports = { createZk1CasStatusHttpsServer, drainZk1CasStatusHttpsServer };
