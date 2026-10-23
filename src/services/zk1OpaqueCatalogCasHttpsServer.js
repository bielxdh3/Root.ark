"use strict";

// Dedicated externally operated opt-in HTTPS authority. TLS identifies a
// separately provisioned client; signed CBOR authenticates a durable CAS head.
const https = require("node:https");
const { Zk1OpaqueCatalogCasLedger } = require("./zk1OpaqueCatalogCasLedger");
const FINGERPRINT = /^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/i;
const MAX_BODY = 3 * 1024 * 1024;
function fail() { throw new Error("ZK_OPAQUE_CAS_HTTP_UNAVAILABLE"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
}
function b64(value, min, max = min) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) fail();
  const result = Buffer.from(value, "base64url");
  if (result.length < min || result.length > max
    || result.toString("base64url") !== value) fail();
  return result;
}
function scopeFrom(value) {
  exact(value, ["account_id", "compartment_id", "keyring_id"]);
  return { account_id: b64(value.account_id, 16),
    compartment_id: b64(value.compartment_id, 1, 128),
    keyring_id: b64(value.keyring_id, 16) };
}
async function payload(req) {
  if (req.headers["content-type"] !== "application/json"
    || (req.headers["content-length"] !== undefined
      && (!/^\d+$/.test(req.headers["content-length"])
        || Number(req.headers["content-length"]) > MAX_BODY))) fail();
  let total = 0;
  const parts = [];
  for await (const part of req) {
    total += part.length;
    if (total > MAX_BODY) fail();
    parts.push(part);
  }
  if (!total) fail();
  try { return JSON.parse(Buffer.concat(parts).toString("utf8")); }
  catch (_) { fail(); }
}
function reply(res, status, body) {
  if (res.destroyed || res.headersSent) return;
  const raw = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { "content-type": "application/json",
    "content-length": raw.length, "cache-control": "no-store",
    "x-content-type-options": "nosniff" });
  res.end(raw);
}
function createZk1OpaqueCatalogCasHttpsServer({ key, cert, clientCa,
  authorizedClientFingerprint256, ledger,
  testOnlyDropCasAckOnce = false }) {
  if (!(ledger instanceof Zk1OpaqueCatalogCasLedger)
    || !key || !cert || !clientCa
    || typeof authorizedClientFingerprint256 !== "string"
    || !FINGERPRINT.test(authorizedClientFingerprint256)
    || (testOnlyDropCasAckOnce !== false && process.env.NODE_ENV !== "test")) fail();
  const pin = authorizedClientFingerprint256.toUpperCase();
  let dropAck = testOnlyDropCasAckOnce === true;
  const server = https.createServer({
    key, cert, ca: clientCa, requestCert: true,
    rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, async (req, res) => {
    try {
      const peer = req.socket.getPeerCertificate();
      if (!req.socket.authorized || peer?.fingerprint256?.toUpperCase() !== pin) {
        return reply(res, 403, { error: "FORBIDDEN" });
      }
      if (req.method !== "POST" || !["/v1/head", "/v1/cas"].includes(req.url)) {
        return reply(res, 404, { error: "NOT_FOUND" });
      }
      const body = await payload(req);
      let result;
      if (req.url === "/v1/head") {
        exact(body, ["scope", "nonce"]);
        result = await ledger.readHead({ scope: scopeFrom(body.scope),
          nonce: b64(body.nonce, 32) });
      } else {
        exact(body, ["scope", "expectedSequence", "expectedDigest",
          "nextSequence", "nextDigest", "nonce", "headBytes", "headSignature", "pageBodies"]);
        if (!Array.isArray(body.pageBodies) || body.pageBodies.length > 128) fail();
        result = await ledger.compareAndSwap({
          scope: scopeFrom(body.scope), expectedSequence: body.expectedSequence,
          expectedDigest: b64(body.expectedDigest, 32),
          nextSequence: body.nextSequence, nextDigest: b64(body.nextDigest, 32),
          nonce: b64(body.nonce, 32),
          headBytes: b64(body.headBytes, 1, 16384),
          headSignature: b64(body.headSignature, 64),
          pageBodies: body.pageBodies.map((v) => b64(v, 1, 16384)),
        });
        // Test-only fault injection: SQLite FULL commit has already completed
        // but the HTTPS reply is lost. Reconcile must use a NEW signed read.
        if (dropAck) {
          dropAck = false;
          req.socket.destroy();
          return;
        }
      }
      reply(res, 200, { proofBase64: result.toString("base64url") });
    } catch (error) {
      const status = ["ZK_OPAQUE_CAS_CONFLICT", "ZK_OPAQUE_CAS_REPLAY"].includes(error?.code)
        ? 409 : 503;
      reply(res, status, { error: status === 409 ? "CAS_CONFLICT" : "CAS_UNAVAILABLE" });
    }
  });
  server.headersTimeout = 5000;
  server.requestTimeout = 5000;
  server.timeout = 5000;
  server.keepAliveTimeout = 1000;
  return server;
}
module.exports = { createZk1OpaqueCatalogCasHttpsServer };
