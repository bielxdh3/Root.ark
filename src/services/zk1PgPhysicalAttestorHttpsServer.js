"use strict";

// Isolated TLS1.3 mTLS endpoint. Deploy in a process with a read-only PG
// attestor login and a PRIVATE Ed25519 key unavailable to the ciphertext
// writer/witness. This server must never be mounted in the normal app.
const https = require("node:https");
const crypto = require("node:crypto");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("./zk1SharedPgPhysicalCiphertextVerifier");
const { signCommittedPhysicalReadback } =
  require("../crypto/rootark-zk-pg-physical-attestation-v1");

const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const B64 = /^[A-Za-z0-9_-]+$/;
function deny() { throw new Error("ZK_PHYSICAL_ATTESTOR_INVALID"); }
function exact(v, fields) {
  if (!v || typeof v !== "object" || Array.isArray(v)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(v))
    || Reflect.ownKeys(v).length !== fields.length
    || fields.some((field) => !Object.hasOwn(v, field))) deny();
}
function decode(v, size, max = size) {
  if (typeof v !== "string" || !B64.test(v)
    || v.length > Math.ceil(max * 4 / 3) + 4) deny();
  const data = Buffer.from(v, "base64url");
  if (data.length < size || data.length > max || data.toString("base64url") !== v) deny();
  return data;
}
function positive(v, min = 0) {
  if (!Number.isSafeInteger(v) || v < min) deny();
  return v;
}
function scopeOf(s) {
  exact(s, ["account_id", "compartment_id", "keyring_id"]);
  return { account_id: decode(s.account_id, 16),
    compartment_id: decode(s.compartment_id, 1, 128),
    keyring_id: decode(s.keyring_id, 16) };
}
function operationOf(o) {
  exact(o, ["operation_id", "expected_sequence", "expected_root", "object_id",
    "revision", "epoch", "ciphertext_sha256"]);
  return { operation_id: decode(o.operation_id, 16),
    expected_sequence: positive(o.expected_sequence), expected_root: decode(o.expected_root, 32),
    object_id: decode(o.object_id, 16), revision: positive(o.revision, 1),
    epoch: positive(o.epoch), ciphertext_sha256: decode(o.ciphertext_sha256, 32) };
}
function scopeKey(s) {
  return [s.account_id.toString("hex"), s.compartment_id.length.toString(16),
    s.compartment_id.toString("hex"), s.keyring_id.toString("hex")].join(":");
}
function authorizedPrincipals(principals) {
  if (!principals || typeof principals !== "object" || Array.isArray(principals)
    || Object.keys(principals).length < 1 || Object.keys(principals).length > 32) deny();
  const grants = new Map();
  for (const [fingerprint, scopes] of Object.entries(principals)) {
    if (!FINGERPRINT.test(fingerprint) || !Array.isArray(scopes)
      || scopes.length < 1 || scopes.length > 64) deny();
    const pin = fingerprint.toUpperCase();
    if (grants.has(pin)) deny();
    const set = new Set(scopes.map((s) => scopeKey({
      account_id: Buffer.from(s.account_id), compartment_id: Buffer.from(s.compartment_id),
      keyring_id: Buffer.from(s.keyring_id) })));
    if (set.size !== scopes.length) deny();
    grants.set(pin, set);
  }
  return grants;
}
function send(res, status, value) {
  if (res.destroyed || res.headersSent) return;
  const raw = Buffer.from(JSON.stringify(value), "utf8");
  res.writeHead(status, { "content-type": "application/json", "content-length": raw.length,
    "cache-control": "no-store", "x-content-type-options": "nosniff" });
  res.end(raw);
}
async function bodyOf(req) {
  if (req.headers["content-type"] !== "application/json") deny();
  const length = req.headers["content-length"];
  if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > 2048)) deny();
  let lengthSoFar = 0;
  const chunks = [];
  for await (const chunk of req) {
    lengthSoFar += chunk.length;
    if (lengthSoFar > 2048) deny();
    chunks.push(chunk);
  }
  if (!lengthSoFar) deny();
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch (_) { deny(); }
}

function createZk1PgPhysicalAttestorHttpsServer({ key, cert, clientCa,
  signerPrivateKey, verifier, principals } = {}) {
  if (!key || !cert || !clientCa
    || !(signerPrivateKey instanceof crypto.KeyObject)
    || signerPrivateKey.type !== "private" || signerPrivateKey.asymmetricKeyType !== "ed25519"
    || !(verifier instanceof Zk1SharedPgPhysicalCiphertextVerifier)) deny();
  const grants = authorizedPrincipals(principals);
  // Admission is bound to the already authenticated TLS identity, before
  // parsing input or opening read-only PG sessions. A single principal cannot
  // exhaust the independent attestor through simultaneous WAL barriers.
  const active = new Set();
  const server = https.createServer({ key, cert, ca: clientCa, requestCert: true,
    rejectUnauthorized: true, minVersion: "TLSv1.3" }, async (req, res) => {
    try {
      const fingerprint = req.socket.getPeerCertificate()?.fingerprint256?.toUpperCase();
      if (!req.socket.authorized || !fingerprint || !grants.has(fingerprint)) {
        return send(res, 403, { error: "FORBIDDEN" });
      }
      if (req.method !== "POST" || req.url !== "/v1/physical/attest") {
        return send(res, 404, { error: "NOT_FOUND" });
      }
      if (active.has(fingerprint) || active.size >= 8) {
        return send(res, 503, { error: "ZK_PHYSICAL_ATTESTOR_BUSY" });
      }
      active.add(fingerprint);
      try {
        const body = await bodyOf(req);
        exact(body, ["scope", "operation", "nonce"]);
        const scope = scopeOf(body.scope);
        if (!grants.get(fingerprint).has(scopeKey(scope))) {
          return send(res, 403, { error: "FORBIDDEN" });
        }
        const operation = operationOf(body.operation);
        const nonce = decode(body.nonce, 32);
        const readback = await verifier.verifyCommittedInventoryOperation({ scope, operation });
        const signed = await signCommittedPhysicalReadback({ scope, operation, readback,
          nonce, issuedAt: Math.floor(Date.now() / 1000) }, signerPrivateKey);
        return send(res, 200, { proof: signed.toString("base64url") });
      } finally { active.delete(fingerprint); }
    } catch (_) {
      return send(res, 503, { error: "ZK_PHYSICAL_ATTESTOR_UNAVAILABLE" });
    }
  });
  server.maxConnections = 16;
  server.headersTimeout = 5000;
  server.requestTimeout = 8000;
  server.timeout = 8000;
  server.keepAliveTimeout = 1000;
  server.maxHeadersCount = 32;
  return server;
}

module.exports = { createZk1PgPhysicalAttestorHttpsServer };
