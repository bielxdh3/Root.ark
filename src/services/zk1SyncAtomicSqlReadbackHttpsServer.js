"use strict";

// DEV-OFF / NON-AUTHORIZING: isolated mTLS read-only PostgreSQL evidence.
// This is NEVER an independent physical WAL/fsync witness or a CAS authority.
// The response deliberately cannot satisfy SyncEngine's signed v2 ACK schema.
const https = require("node:https");
const { createZk1SyncPgBatchIndependentReadback } =
  require("./zk1SyncPgBatchIndependentReadback");

const ROUTE = "/v2/sync-atomic/sql-observe";
const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SCOPE = /^[A-Za-z0-9._:-]{1,256}$/;
const OP = /^[A-Za-z0-9._:-]{1,160}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const MAX_BODY = 4096;
const MAX_PENDING_READS = 8;
const DEFAULT_OBSERVE_TIMEOUT_MS = 6000;

function fail() { throw new Error("SYNC_ATOMIC_SQL_OBSERVE_INVALID"); }
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length
    || keys.some((key) => !Object.hasOwn(value, key))) fail();
}
function binding(value) {
  exact(value, ["scope", "accountId", "storeId"]);
  if (typeof value.scope !== "string" || !SCOPE.test(value.scope)
    || typeof value.accountId !== "string" || !UUID.test(value.accountId)
    || typeof value.storeId !== "string" || !UUID.test(value.storeId)) fail();
  return [value.scope, value.accountId, value.storeId].join("\0");
}
function grantsFor(principals) {
  if (!principals || typeof principals !== "object" || Array.isArray(principals)
    || Object.keys(principals).length < 1 || Object.keys(principals).length > 32) fail();
  const grants = new Map();
  for (const [fingerprint, scopes] of Object.entries(principals)) {
    if (!FINGERPRINT.test(fingerprint) || !Array.isArray(scopes)
      || scopes.length < 1 || scopes.length > 64) fail();
    const pin = fingerprint.toUpperCase();
    if (grants.has(pin)) fail();
    const bindings = new Set(scopes.map(binding));
    if (bindings.size !== scopes.length) fail();
    grants.set(pin, bindings);
  }
  return grants;
}
function respond(res, status, payload) {
  if (res.destroyed || res.headersSent) return;
  const bytes = Buffer.from(JSON.stringify(payload), "utf8");
  res.writeHead(status, { "content-type": "application/json",
    "content-length": String(bytes.length), "cache-control": "no-store",
    "x-content-type-options": "nosniff" });
  res.end(bytes);
}
async function bodyOf(req) {
  if (req.headers["content-type"] !== "application/json") fail();
  const provided = req.headers["content-length"];
  if (provided !== undefined && (!/^\d+$/.test(provided)
    || Number(provided) < 1 || Number(provided) > MAX_BODY)) fail();
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) fail();
    chunks.push(chunk);
  }
  if (!size) fail();
  let value;
  try { value = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { fail(); }
  exact(value, ["scope", "accountId", "storeId", "nonce",
    "operationIds", "envelopeDigests"]);
  binding({ scope: value.scope, accountId: value.accountId, storeId: value.storeId });
  if (typeof value.nonce !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.nonce)
    || Buffer.from(value.nonce, "base64url").length !== 32
    || Buffer.from(value.nonce, "base64url").toString("base64url") !== value.nonce) fail();
  if (!Array.isArray(value.operationIds) || value.operationIds.length !== 2
    || value.operationIds.some((item) => typeof item !== "string" || !OP.test(item))
    || value.operationIds[0] === value.operationIds[1]) fail();
  if (!Array.isArray(value.envelopeDigests) || value.envelopeDigests.length !== 2
    || value.envelopeDigests.some((item) => typeof item !== "string" || !DIGEST.test(item))) fail();
  return value;
}

function createZk1SyncAtomicSqlReadbackHttpsServer({ key, cert, clientCa,
  attestorPool, principals, observationTimeoutMs = DEFAULT_OBSERVE_TIMEOUT_MS } = {}) {
  if (!key || !cert || !clientCa || !attestorPool
    || typeof attestorPool.connect !== "function"
    || !Number.isSafeInteger(observationTimeoutMs)
    || observationTimeoutMs < 50 || observationTimeoutMs > 7000) fail();
  const grants = grantsFor(principals);
  const readback = createZk1SyncPgBatchIndependentReadback({ attestorPool });
  const active = new Set();
  // A timeout ends the HTTP observation, NOT the underlying PostgreSQL call.
  // Retain unresolved work in a bounded set until it really settles, so an
  // unavailable attestor cannot accumulate unlimited queued connections.
  const pendingReads = new Set();
  // A timed-out fingerprint must not monopolize all pending slots by retrying:
  // its first unresolved query continues to consume that principal's quota.
  const pendingByFingerprint = new Map();
  const server = https.createServer({ key, cert, ca: clientCa,
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
    handshakeTimeout: 3000 }, async (req, res) => {
    const peer = req.socket.getPeerCertificate();
    const fingerprint = peer?.fingerprint256?.toUpperCase();
    if (!req.socket.authorized || !fingerprint || !grants.has(fingerprint)) {
      return respond(res, 403, { error: "FORBIDDEN" });
    }
    if (req.method !== "POST" || req.url !== ROUTE) {
      return respond(res, 404, { error: "NOT_FOUND" });
    }
    if (active.has(fingerprint) || pendingByFingerprint.has(fingerprint)
      || active.size >= 8) {
      return respond(res, 503, { error: "SYNC_ATOMIC_SQL_OBSERVE_BUSY" });
    }
    active.add(fingerprint);
    try {
      const challenge = await bodyOf(req);
      // bodyOf validates all six challenge fields; authorization binds only
      // the exact immutable identity tuple, never the request's other fields.
      const accountStore = binding({
        scope: challenge.scope, accountId: challenge.accountId, storeId: challenge.storeId,
      });
      if (!grants.get(fingerprint).has(accountStore)) {
        return respond(res, 403, { error: "FORBIDDEN" });
      }
      if (pendingReads.size >= MAX_PENDING_READS) {
        return respond(res, 503, { error: "SYNC_ATOMIC_SQL_OBSERVE_BUSY" });
      }
      const inFlight = Promise.resolve().then(() => readback.verifyCurrentSignedPair({
        scope: challenge.scope, operationIds: challenge.operationIds,
        envelopeDigests: challenge.envelopeDigests,
      }));
      pendingReads.add(inFlight);
      pendingByFingerprint.set(fingerprint, inFlight);
      const settled = () => {
        pendingReads.delete(inFlight);
        if (pendingByFingerprint.get(fingerprint) === inFlight) {
          pendingByFingerprint.delete(fingerprint);
        }
      };
      inFlight.then(settled, settled);
      let timeout;
      let observed;
      try {
        observed = await Promise.race([inFlight, new Promise((_, reject) => {
          timeout = setTimeout(() => reject(new Error("SQL_OBSERVATION_TIMEOUT")),
            observationTimeoutMs);
        })]);
      } finally {
        clearTimeout(timeout);
      }
      if (!observed || observed.scope !== challenge.scope
        || observed.localPgRowsConsistent !== true
        || observed.witnessVerified !== false || observed.clientAckAuthorized !== false
        || typeof observed.commitId !== "string"
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(observed.commitId)
        || !Number.isSafeInteger(observed.sequence) || observed.sequence < 1
        || typeof observed.head !== "string" || !DIGEST.test(observed.head)
        || !Array.isArray(observed.operationIds) || !Array.isArray(observed.envelopeDigests)
        || observed.operationIds.length !== 2 || observed.envelopeDigests.length !== 2
        || observed.operationIds.some((id, i) => id !== challenge.operationIds[i]
          || observed.envelopeDigests[i] !== challenge.envelopeDigests[i])) fail();
      // No response from this service can become atomicAdmission: there is
      // NO statement, Ed25519 signature, physicalDurable=true or CAS floor.
      return respond(res, 200, { kind: "SYNC_ATOMIC_SQL_ROWS_ONLY_DEV_OFF",
        scope: challenge.scope, accountId: challenge.accountId,
        storeId: challenge.storeId, nonce: challenge.nonce,
        commitId: observed.commitId, sequence: observed.sequence,
        storeHeadSha256: observed.head,
        operationIds: observed.operationIds,
        envelopeDigests: observed.envelopeDigests,
        localPgRowsConsistent: observed.localPgRowsConsistent === true,
        witnessVerified: false, physicalDurable: false,
        clientAckAuthorized: false });
    } catch (reason) {
      if (reason?.message === "SYNC_ATOMIC_SQL_OBSERVE_INVALID") {
        return respond(res, 400, { error: "INVALID_REQUEST" });
      }
      return respond(res, 503, { error: "SYNC_ATOMIC_SQL_OBSERVE_UNAVAILABLE" });
    } finally {
      active.delete(fingerprint);
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

module.exports = { createZk1SyncAtomicSqlReadbackHttpsServer };
