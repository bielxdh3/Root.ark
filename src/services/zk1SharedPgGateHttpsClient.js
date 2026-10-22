"use strict";

// Opt-in reference client for the separately operated PostgreSQL-only gate.
// It performs ONLY admission, PostgreSQL ciphertext writes and quiescence.
// No GET/egress operation is exposed: a remote lock check followed by socket
// emission would not fence bytes during PostgreSQL connection loss.
const https = require("node:https");
const tls = require("node:tls");
const net = require("node:net");

const FINGERPRINT = /^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/i;
const OBJECT_ID = /^[A-Za-z0-9_-]{22}$/;
function unavailable() {
  const error = new Error("ZK_GATE_TRANSPORT_UNAVAILABLE");
  error.code = "ZK_GATE_TRANSPORT_UNAVAILABLE";
  throw error;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((key) => !Object.hasOwn(value, key))) unavailable();
}
function encode(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length < min || value.length > max) unavailable();
  return Buffer.from(value).toString("base64url");
}
function decode(value, length) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
    || value.length > Math.ceil(length * 4 / 3) + 3) unavailable();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== length || bytes.toString("base64url") !== value) unavailable();
  return bytes;
}
function positive(n) {
  if (!Number.isSafeInteger(n) || n < 1) unavailable();
  return n;
}
function normalizedScope(input) {
  exact(input, ["account_id", "compartment_id", "keyring_id"]);
  return { account_id: encode(input.account_id, 16),
    compartment_id: encode(input.compartment_id, 1, 128),
    keyring_id: encode(input.keyring_id, 16) };
}
function worker(input) {
  exact(input, ["scope", "workerId", "action", "objectId", "revision", "digest"]);
  if (input.action !== "put" || typeof input.objectId !== "string"
    || !OBJECT_ID.test(input.objectId)
    || Buffer.from(input.objectId, "base64url").toString("base64url") !== input.objectId) unavailable();
  return { scope: normalizedScope(input.scope), workerId: encode(input.workerId, 16),
    action: "put", objectId: input.objectId, revision: positive(input.revision),
    digest: encode(input.digest, 32) };
}
function operation(input, pending) {
  exact(input, pending
    ? ["scope", "operationId", "reservationId"]
    : ["scope", "operationId", "reservationId", "revision", "digest"]);
  const body = { scope: normalizedScope(input.scope),
    operationId: encode(input.operationId, 16), reservationId: encode(input.reservationId, 16) };
  if (!pending) {
    body.revision = positive(input.revision);
    body.digest = encode(input.digest, 32);
  }
  return body;
}

function createZk1SharedPgGateHttpsClient({ endpoint, ca, clientKey, clientCert,
  serverFingerprint256, timeoutMs = 15000 } = {}) {
  let url;
  try { url = new URL(endpoint); } catch (_) { unavailable(); }
  if (url.protocol !== "https:" || !url.hostname || !url.port
    || url.username || url.password || url.search || url.hash
    || !["", "/"].includes(url.pathname)
    || !ca || !clientKey || !clientCert || !FINGERPRINT.test(serverFingerprint256)
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) unavailable();
  const pin = serverFingerprint256.toUpperCase();

  function send(path, body, fields, expectedStatus = 200) {
    let payload;
    try { payload = Buffer.from(JSON.stringify(body), "utf8"); } catch (_) { unavailable(); }
    if (payload.length > 6 * 1024 * 1024 || payload.length < 1) unavailable();
    return new Promise((resolve, reject) => {
      let done = false;
      let wallTimer;
      let request;
      const fail = () => {
        if (done) return;
        done = true;
        clearTimeout(wallTimer);
        request?.destroy();
        const error = new Error("ZK_GATE_TRANSPORT_UNAVAILABLE");
        error.code = "ZK_GATE_TRANSPORT_UNAVAILABLE";
        reject(error);
      };
      request = https.request({ hostname: url.hostname, port: url.port,
        path, method: "POST", ca, key: clientKey, cert: clientCert,
        // A shared https.globalAgent can reuse a TLS socket authenticated
        // under ANOTHER client's pin, skipping checkServerIdentity entirely.
        // One socket per request makes verification of this exact pin
        // unconditional (including after successful calls by other clients).
        agent: false,
        rejectUnauthorized: true, minVersion: "TLSv1.3",
        servername: net.isIP(url.hostname) ? "" : url.hostname,
        checkServerIdentity(host, cert) {
          const nameError = tls.checkServerIdentity(host, cert);
          if (nameError) return nameError;
          if (!cert.fingerprint256 || cert.fingerprint256.toUpperCase() !== pin) {
            return new Error("ZK_GATE_PEER_NOT_PINNED");
          }
          return undefined;
        }, timeout: timeoutMs,
        headers: { "content-type": "application/json", accept: "application/json",
          "content-length": String(payload.length) },
      }, (response) => {
        if (response.statusCode !== expectedStatus
          || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers["content-type"] || "")) {
          response.resume(); fail(); return;
        }
        const chunks = [];
        let size = 0;
        response.on("data", (chunk) => {
          size += chunk.length;
          if (size > 2048) { response.destroy(); fail(); }
          else chunks.push(chunk);
        });
        response.on("error", fail);
        response.on("end", () => {
          if (done) return;
          try {
            const result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            exact(result, fields);
            done = true;
            clearTimeout(wallTimer);
            resolve(result);
          } catch (_) { fail(); }
        });
      });
      // Node HTTPS timeout is a socket-IDLE timer: an authenticated peer
      // sending one byte at a time can keep a gate operation pending forever.
      // A separate hard deadline bounds the entire mTLS request/response,
      // including TLS handshake, chunk streams and response parsing.
      wallTimer = setTimeout(fail, timeoutMs);
      request.on("error", fail);
      request.on("timeout", fail);
      request.end(payload);
    });
  }
  return Object.freeze({
    async beginIoAdmission(input) {
      const result = await send("/v1/admission/start", worker(input),
        ["admissionId", "generation", "proceed"], 201);
      if (typeof result.proceed !== "boolean") unavailable();
      return { admissionId: decode(result.admissionId, 16),
        generation: positive(result.generation), proceed: result.proceed };
    },
    async putCiphertextChunk(input, chunkIndex, ciphertext) {
      const base = worker({ scope: input?.scope, workerId: input?.workerId,
        action: input?.action, objectId: input?.objectId, revision: input?.revision,
        digest: input?.digest });
      if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0
        || chunkIndex > 0x7fffffff) unavailable();
      const body = { ...base, admissionId: encode(input.admissionId, 16),
        generation: positive(input.generation), chunkIndex,
        ciphertextBase64: encode(ciphertext, 1, 4 * 1024 * 1024) };
      const result = await send("/v1/chunk/put", body, ["stored"]);
      if (typeof result.stored !== "boolean") unavailable();
      return result;
    },
    async sealCiphertextObject(input, expectedChunkCount, expectedRootHash) {
      const base = worker({ scope: input?.scope, workerId: input?.workerId,
        action: input?.action, objectId: input?.objectId, revision: input?.revision,
        digest: input?.digest });
      if (!Number.isSafeInteger(expectedChunkCount)
        || expectedChunkCount < 1 || expectedChunkCount > 4096) unavailable();
      // expectedRootHash MUST have been independently authenticated by the
      // owner/device. The storage service never self-signs this commitment.
      const body = { ...base, admissionId: encode(input.admissionId, 16),
        generation: positive(input.generation), expectedChunkCount,
        expectedRootHash: encode(expectedRootHash, 32) };
      const result = await send("/v1/chunk/seal", body, ["status", "chunkCount"]);
      if (result.status !== "SEALED" || result.chunkCount !== expectedChunkCount) unavailable();
      return { status: "SEALED", chunkCount: result.chunkCount };
    },
    async finishIoAdmission(input) {
      exact(input, ["scope", "workerId", "admissionId"]);
      const result = await send("/v1/admission/finish", {
        scope: normalizedScope(input.scope), workerId: encode(input.workerId, 16),
        admissionId: encode(input.admissionId, 16) }, ["status"]);
      if (result.status !== "FINISHED") unavailable();
      return result;
    },
    async beginQuiesce(input) {
      const result = await send("/v1/quiesce", operation(input, false),
        ["state", "generation", "activeCount"]);
      if (result.state !== "QUIESCING" || !Number.isSafeInteger(result.activeCount)
        || result.activeCount < 0) unavailable();
      positive(result.generation);
      return result;
    },
    async markPending(input) {
      const result = await send("/v1/pending", operation(input, true),
        ["status", "generation"]);
      if (result.status !== "PENDING") unavailable();
      positive(result.generation);
      return result;
    },
  });
}

module.exports = { createZk1SharedPgGateHttpsClient };
