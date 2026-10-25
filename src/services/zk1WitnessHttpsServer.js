"use strict";

// Separate-process HTTPS transport for the isolated zk-1 witness engine.
// This is NOT an application route and MUST NEVER be mounted in server.js.
// mTLS authenticates configured service principals, not individual Root.ark
// users; only a separately governed CAS/admission protocol could authorize
// protected content. Not a substitute for independent operator custody.
const https = require("node:https");
const crypto = require("node:crypto");
const z = require("../crypto/rootark-zk-1");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");

const MAX_BODY_BYTES = 4096;
const GENESIS_DOMAIN = Buffer.from("Root.ark/zk-1/witness-genesis-authorization/v1\0", "ascii");
const B64U = /^[A-Za-z0-9_-]+$/;
const ROLES = Object.freeze({
  "/v1/head": "head",
  "/v1/reserve": "reserve",
  "/v1/resolve": "resolve",
  "/v1/quiesce": "reserve",
  "/v1/quiesce/cancel-expired": "reserve",
  "/v1/admission/start": "admit",
  "/v1/admission/finish": "admit",
  "/v1/cas-anchor/head": "cas-anchor",
  "/v1/cas-anchor/advance": "cas-anchor",
  "/v1/cas-anchor/historical-admit": "cas-historical-admit",
});
const SCOPE_FIELDS = Object.freeze(["account_id", "compartment_id", "keyring_id"]);
const OP_FIELDS = Object.freeze([
  ...SCOPE_FIELDS, "reservation_id", "operation_id", "expected_revision",
  "expected_manifest_digest", "proposed_revision", "proposed_manifest_digest",
  "request_digest", "package_envelope_digest", "expires_at",
]);
const BYTE_FIELDS = Object.freeze({
  account_id: [16, 16], compartment_id: [1, 128], keyring_id: [16, 16],
  reservation_id: [16, 16], operation_id: [16, 16],
  expected_manifest_digest: [32, 32], proposed_manifest_digest: [32, 32],
  request_digest: [32, 32], package_envelope_digest: [32, 32],
  nonce: [32, 32],
  workerId: [16, 16], admissionId: [16, 16], digest: [32, 32],
});
const IO_START = ["scope", "revision", "digest", "action", "objectId", "workerId"];
const IO_FINISH = ["scope", "admissionId", "workerId"];
function invalid() {
  const e = new Error("WITNESS_API_INVALID");
  e.code = "WITNESS_API_INVALID";
  throw e;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((name) => !Object.hasOwn(value, name))
    || Reflect.ownKeys(value).some((name) => !fields.includes(name))) invalid();
}
function decode(value, [min, max]) {
  if (typeof value !== "string" || !B64U.test(value)
    || value.length === 0 || value.length % 4 === 1
    || value.length > Math.ceil(max * 4 / 3) + 4) invalid();
  const raw = Buffer.from(value, "base64url");
  if (raw.length < min || raw.length > max || raw.toString("base64url") !== value) invalid();
  return raw;
}
function normalize(raw, fields) {
  exact(raw, fields);
  const result = {};
  for (const name of fields) {
    const value = raw[name];
    if (Object.hasOwn(BYTE_FIELDS, name)) {
      result[name] = value === null
        && (name === "expected_manifest_digest" || name === "package_envelope_digest")
        ? null : decode(value, BYTE_FIELDS[name]);
    } else if (name === "expected_revision") {
      if (value !== null && (!Number.isSafeInteger(value) || value < 1)) invalid();
      result[name] = value;
    } else if (name === "proposed_revision" || name === "expires_at") {
      if (!Number.isSafeInteger(value) || value < (name === "proposed_revision" ? 1 : 0)) invalid();
      result[name] = value;
    } else invalid();
  }
  return result;
}
function scopeKey(scope) {
  return scope.account_id.toString("hex") + ":" + scope.compartment_id.length
    + ":" + scope.compartment_id.toString("hex") + ":" + scope.keyring_id.toString("hex");
}
function write(res, status, value) {
  const raw = Buffer.from(JSON.stringify(value), "utf8");
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-length": String(raw.length),
  });
  res.end(raw);
}
async function readBoundedJson(req, maxBodyBytes = MAX_BODY_BYTES) {
  if (req.headers["content-type"] !== "application/json") invalid();
  const length = req.headers["content-length"];
  if (length !== undefined && (!/^\d+$/.test(length)
    || Number(length) > maxBodyBytes)) invalid();
  const parts = [];
  let total = 0;
  for await (const part of req) {
    total += part.length;
    if (total > maxBodyBytes) invalid();
    parts.push(part);
  }
  if (total === 0) invalid();
  try { return JSON.parse(Buffer.concat(parts).toString("utf8")); }
  catch (_) { invalid(); }
}

// Signal handling must never wait forever for an authenticated peer that
// deliberately leaves a request body unfinished. Stop accepting new requests,
// allow in-flight work a short grace period, then terminate remaining HTTP
// connections. The durable ledger's caller closes it only after this drain.
function drainZk1WitnessHttpsServer(server, { deadlineMs = 1500 } = {}) {
  if (!server || typeof server.close !== "function"
    || typeof server.closeAllConnections !== "function"
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

function createZk1WitnessHttpsServer({ key, cert, clientCa, ledger, principals,
  casAnchorFloor = null }) {
  if (!key || !cert || !clientCa || !ledger
    || typeof ledger.reserve !== "function" || typeof ledger.freshHead !== "function"
    || typeof ledger.resolve !== "function"
    || typeof ledger.prepareQuiesce !== "function"
    || typeof ledger.cancelExpiredQuiesce !== "function"
    || typeof ledger.beginIoAdmission !== "function"
    || typeof ledger.finishIoAdmission !== "function"
    || !principals || typeof principals !== "object"
    || Object.keys(principals).length === 0) invalid();
  const authorized = new Map();
  if (Object.keys(principals).length > 128) invalid();
  for (const [fingerprint, settings] of Object.entries(principals)) {
    exact(settings, Object.hasOwn(settings, "initializeKeys")
      ? ["roles", "scopes", "initializeKeys"] : ["roles", "scopes"]);
    const { roles, scopes, initializeKeys = [] } = settings;
    if (!/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i.test(fingerprint)
      || !Array.isArray(roles) || roles.length === 0
      || roles.some((role) => !Object.values(ROLES).includes(role))
      || !Array.isArray(scopes) || scopes.length > 64
      || !Array.isArray(initializeKeys) || initializeKeys.length > 64
      || (initializeKeys.length > 0 && !roles.includes("reserve"))) invalid();
    // This principal can advance the GLOBAL CAS terminal high-water. Never
    // co-grant it a content/recovery reserve/head/IO role, and never silently
    // accept it when the separate witness-owned floor is not configured.
    if (roles.includes("cas-historical-admit")
      ? roles.length !== 1 || scopes.length < 1 || initializeKeys.length !== 0
        || !casAnchorFloor || !casAnchorFloor.requiresPhysicalAttestation
        || casAnchorFloor.supportsClientHistoricalNonce !== true
        || typeof casAnchorFloor.issueSyncHistoricalAdmission !== "function"
      : roles.includes("cas-anchor")
      ? roles.length !== 1 || scopes.length !== 0 || initializeKeys.length !== 0
        || !casAnchorFloor || typeof casAnchorFloor.advance !== "function"
        || typeof casAnchorFloor.freshHeadAsync !== "function"
      : scopes.length === 0) invalid();
    const scoped = new Set(scopes.map((scope) => scopeKey(normalize(scope, SCOPE_FIELDS))));
    if (scoped.size !== scopes.length) invalid();
    const initializers = new Map();
    for (const init of initializeKeys) {
      exact(init, ["scope", "publicKeyPem"]);
      const key = scopeKey(normalize(init.scope, SCOPE_FIELDS));
      if (!scoped.has(key) || initializers.has(key)
        || typeof init.publicKeyPem !== "string"
        || init.publicKeyPem.length > 2048
        || !/^-----BEGIN PUBLIC KEY-----\r?\n/.test(init.publicKeyPem)) invalid();
      let publicKey;
      try { publicKey = crypto.createPublicKey(init.publicKeyPem); }
      catch (_) { invalid(); }
      if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") invalid();
      initializers.set(key, publicKey);
    }
    if (authorized.has(fingerprint.toUpperCase())) invalid();
    authorized.set(fingerprint.toUpperCase(), {
      roles: new Set(roles), scopes: scoped, initializers,
    });
  }
  const server = https.createServer({
    key, cert, ca: clientCa, minVersion: "TLSv1.3",
    requestCert: true, rejectUnauthorized: true,
  }, async (req, res) => {
    try {
      if (req.method !== "POST" || !Object.hasOwn(ROLES, req.url)) {
        return write(res, 404, { error: "NOT_FOUND" });
      }
      const peer = req.socket.getPeerCertificate();
      const granted = peer?.fingerprint256 && authorized.get(peer.fingerprint256.toUpperCase());
      if (!req.socket.authorized || !granted || !granted.roles.has(ROLES[req.url])) {
        // Refuse before buffering any externally supplied JSON.
        return write(res, 403, { error: "FORBIDDEN" });
      }
      const body = await readBoundedJson(req,
        req.url === "/v1/cas-anchor/historical-admit"
          ? 12 * 1024 * 1024
          : req.url === "/v1/cas-anchor/advance"
          ? (casAnchorFloor?.requiresPhysicalAttestation ? 96 * 1024 : 40 * 1024)
          : MAX_BODY_BYTES);
      if (req.url === "/v1/cas-anchor/historical-admit") {
        if (casAnchorFloor?.supportsClientHistoricalNonce !== true) invalid();
        exact(body, ["envelope", "scope", "expectedSequence", "expectedRoot",
          "inventoryReceipt", "nonce"]);
        const scope = normalize(body.scope, SCOPE_FIELDS);
        if (!granted.scopes.has(scopeKey(scope))) {
          return write(res, 403, { error: "FORBIDDEN" });
        }
        const nonce = decode(body.nonce, BYTE_FIELDS.nonce);
        if (!Number.isSafeInteger(body.expectedSequence) || body.expectedSequence < 0) invalid();
        const input = { envelope: body.envelope, scope,
          expectedSequence: body.expectedSequence,
          expectedRoot: decode(body.expectedRoot, [32, 32]),
          inventoryReceipt: decode(body.inventoryReceipt,
            [1, inventory.MAX_COMMITTED_PROOF_BYTES]), nonce };
        const issued = await casAnchorFloor.issueSyncHistoricalAdmission(input);
        // A mismatched reply must never be delivered as proof of the caller's
        // fresh challenge, even if the witness signed a different nonce.
        if (!issued?.admission || !issued?.freshFloor
          || issued.freshFloor.type !== "rootark-zk1-witness-cas-physical-floor/v2"
          || issued.freshFloor.nonce !== nonce.toString("base64url")
          || issued.admission.witnessSequence !== issued.freshFloor.sequence
          || issued.admission.witnessLastHash !== issued.freshFloor.lastHash
          || issued.admission.witnessPhysicalFenceDigest
            !== issued.freshFloor.physicalFenceDigest) invalid();
        return write(res, 200, { admission: issued.admission,
          freshFloor: issued.freshFloor,
          authority: "WITNESS_SYNC_HISTORICAL_ADMISSION_V1" });
      }
      if (req.url === "/v1/cas-anchor/head") {
        exact(body, ["nonce"]);
        const head = await casAnchorFloor.freshHeadAsync({ nonce: decode(body.nonce, BYTE_FIELDS.nonce) });
        return write(res, 200, { head, authority: "WITNESS_CAS_ANCHOR_FLOOR_V1" });
      }
      if (req.url === "/v1/cas-anchor/advance") {
        const strict = casAnchorFloor.requiresPhysicalAttestation;
        exact(body, strict ? ["records", "evidence"] : ["records"]);
        // Legacy signed-status-only requests cannot downgrade an independent
        // floor enrolled in mandatory physical PG admission mode.
        const result = strict
          ? await casAnchorFloor.advanceAttested({
            records: body.records, evidence: body.evidence,
          })
          : casAnchorFloor.advance({ records: body.records });
        return write(res, 200, { sequence: result.sequence,
          lastHash: result.lastHash, authority: "WITNESS_CAS_ANCHOR_FLOOR_V1" });
      }
      if (req.url === "/v1/quiesce" || req.url === "/v1/quiesce/cancel-expired") {
        exact(body, ["operation"]);
        const operation = normalize(body.operation, OP_FIELDS);
        if (!granted.scopes.has(scopeKey(operation))) {
          return write(res, 403, { error: "FORBIDDEN" });
        }
        // Genesis cannot quiesce a prior I/O worker. An operation may only
        // transition to QUIESCING under the existing scoped reserve principal.
        if (operation.expected_revision === null) {
          return write(res, 403, { error: "FORBIDDEN" });
        }
        if (req.url === "/v1/quiesce/cancel-expired") {
          const result = await ledger.cancelExpiredQuiesce(operation);
          return write(res, 200, { status: result.status,
            authority: "WITNESS_IO_GATE_LOCAL_V1" });
        }
        const result = await ledger.prepareQuiesce(operation);
        return write(res, 200, { status: result.status,
          activeCount: result.activeCount, authority: "WITNESS_IO_GATE_LOCAL_V1" });
      }
      if (req.url === "/v1/admission/start" || req.url === "/v1/admission/finish") {
        const starting = req.url.endsWith("/start");
        exact(body, starting ? IO_START : IO_FINISH);
        const scope = normalize(body.scope, SCOPE_FIELDS);
        if (!granted.scopes.has(scopeKey(scope))) {
          return write(res, 403, { error: "FORBIDDEN" });
        }
        const workerId = decode(body.workerId, BYTE_FIELDS.workerId);
        // The authenticated mTLS principal is bound at the witness, never
        // accepted as an untrusted JSON field from the gateway.
        const principal = peer.fingerprint256.toUpperCase();
        if (starting) {
          if (!Number.isSafeInteger(body.revision) || body.revision < 1
            || !["get", "put"].includes(body.action)
            || typeof body.objectId !== "string"
            || !/^[A-Za-z0-9_-]{22}$/.test(body.objectId)
            || Buffer.from(body.objectId, "base64url").toString("base64url") !== body.objectId) {
            invalid();
          }
          const receipt = await ledger.beginIoAdmission({ scope,
            revision: body.revision, digest: decode(body.digest, BYTE_FIELDS.digest),
            action: body.action, objectId: body.objectId, workerId, principal });
          return write(res, 201, { admissionId: Buffer.from(receipt.admissionId).toString("base64url"),
            proceed: receipt.proceed === true, authority: "WITNESS_IO_GATE_LOCAL_V1" });
        }
        const result = await ledger.finishIoAdmission({ scope,
          admissionId: decode(body.admissionId, BYTE_FIELDS.admissionId),
          workerId, principal });
        return write(res, 200, { status: result.status, authority: "WITNESS_IO_GATE_LOCAL_V1" });
      }
      if (req.url === "/v1/reserve") {
        const operation = normalize(body.operation, OP_FIELDS);
        if (!granted.scopes.has(scopeKey(operation))) {
          return write(res, 403, { error: "FORBIDDEN" });
        }
        if (operation.expected_revision === null) {
          // Genesis is irreversible on terminal cancellation. A compromised
          // role-bearing mTLS transport client must not be able to pick the
          // initial manifest or tombstone a keyring without an independently
          // pinned Ed25519 owner/provisioner authorization over the exact op.
          const publicKey = granted.initializers.get(scopeKey(operation));
          if (!publicKey || typeof body.initializeSignature !== "string") {
            return write(res, 403, { error: "FORBIDDEN" });
          }
          exact(body, ["operation", "initializeSignature"]);
          let signature;
          try { signature = decode(body.initializeSignature, [64, 64]); }
          catch (_) { return write(res, 403, { error: "FORBIDDEN" }); }
          const signedBytes = await z.encodeDeterministic(operation);
          if (!crypto.verify(null, Buffer.concat([GENESIS_DOMAIN,
            Buffer.from(signedBytes)]), publicKey, signature)) {
            return write(res, 403, { error: "FORBIDDEN" });
          }
        } else {
          exact(body, ["operation"]);
        }
        const ticket = await ledger.reserve(operation);
        return write(res, 201, {
          receiptBase64: Buffer.from(ticket).toString("base64url"),
          authority: "WITNESS_ENGINE_ONLY",
        });
      }
      if (req.url === "/v1/head") {
        exact(body, ["scope", "nonce"]);
        const scope = normalize(body.scope, SCOPE_FIELDS);
        if (!granted.scopes.has(scopeKey(scope))) {
          return write(res, 403, { error: "FORBIDDEN" });
        }
        const receipt = await ledger.freshHead({
          scope,
          nonce: decode(body.nonce, BYTE_FIELDS.nonce),
        });
        return write(res, 200, {
          receiptBase64: Buffer.from(receipt).toString("base64url"),
          authority: "WITNESS_ENGINE_ONLY",
        });
      }
      exact(body, ["scope"]);
      const scope = normalize(body.scope, SCOPE_FIELDS);
      if (!granted.scopes.has(scopeKey(scope))) {
        return write(res, 403, { error: "FORBIDDEN" });
      }
      const resolved = await ledger.resolve({ scope });
      return write(res, 200, {
        status: resolved.status,
        receiptBase64: Buffer.from(resolved.receipt).toString("base64url"),
        authority: "WITNESS_ENGINE_ONLY",
      });
    } catch (error) {
      if (res.headersSent || res.destroyed) return;
      const code = error?.code;
      const status = code === "WITNESS_API_INVALID" || code === "WITNESS_INVALID" ? 400
        : code === "WITNESS_IO_DENIED" ? 403
        : code === "WITNESS_NO_HEAD" || code === "WITNESS_NO_PENDING" ? 404
          : code === "WITNESS_PENDING" || code === "WITNESS_CONFLICT"
            || code === "WITNESS_TOMBSTONED" || code === "WITNESS_EXPIRED"
            || code === "WITNESS_CAPACITY_EXHAUSTED" || code === "WITNESS_IO_ACTIVE"
            || code === "WITNESS_QUIESCING"
            || code === "WITNESS_QUIESCE_NOT_EXPIRED" ? 409 : 503;
      return write(res, status, {
        error: status === 503 ? "WITNESS_UNAVAILABLE"
          : status === 400 ? "WITNESS_INVALID_REQUEST"
            : status === 404 ? "NOT_FOUND" : "WITNESS_CONFLICT",
      });
    }
  });
  // Bound slowloris requests even when the operator does not stop the service.
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  server.timeout = 5000;
  server.keepAliveTimeout = 1000;
  return server;
}

module.exports = { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer };
