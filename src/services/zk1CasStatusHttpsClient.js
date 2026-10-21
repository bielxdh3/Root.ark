"use strict";

// Direct, fixed-endpoint CAS terminal-status transport. The configured
// status authority's Ed25519 SIGNING key is separately verified by the
// witness ledger; this mTLS channel pins the HTTP peer and never treats an
// HTTP 200 as proof of a committed operation.
const https = require("node:https");
const tls = require("node:tls");

const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const B64U = /^[A-Za-z0-9_-]+$/;
const BYTE_FIELDS = Object.freeze({
  account_id: [16, 16], compartment_id: [1, 128], keyring_id: [16, 16],
  reservation_id: [16, 16], operation_id: [16, 16], request_digest: [32, 32],
  package_envelope_digest: [32, 32], expected_manifest_digest: [32, 32],
  proposed_manifest_digest: [32, 32],
});
const QUERY_FIELDS = Object.freeze([
  "account_id", "compartment_id", "keyring_id", "reservation_id", "operation_id",
  "request_digest", "package_envelope_digest", "expected_revision",
  "expected_manifest_digest", "proposed_revision", "proposed_manifest_digest",
]);
function fail() {
  const error = new Error("CAS_STATUS_TRANSPORT_UNAVAILABLE");
  error.code = "CAS_STATUS_TRANSPORT_UNAVAILABLE";
  throw error;
}
function encodeByte(raw, min, max) {
  if ((!Buffer.isBuffer(raw) && !(raw instanceof Uint8Array))
    || raw.byteLength < min || raw.byteLength > max) fail();
  return Buffer.from(raw).toString("base64url");
}
function createZk1CasStatusHttpsClient({
  endpoint, ca, clientKey, clientCert, serverFingerprint256,
  timeoutMs = 3000,
}) {
  let url;
  try { url = new URL(endpoint); }
  catch (_) { fail(); }
  if (url.protocol !== "https:" || !url.hostname || !url.port
    || url.username || url.password || url.search || url.hash
    || url.pathname !== "/v1/terminal"
    || !ca || !clientKey || !clientCert
    || !FINGERPRINT.test(serverFingerprint256)
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) fail();
  const peerFingerprint = serverFingerprint256.toUpperCase();
  return Object.freeze({
    getTerminalProof({ query, nonce }) {
      if (!query || typeof query !== "object" || Array.isArray(query)
        || Reflect.ownKeys(query).length !== QUERY_FIELDS.length
        || QUERY_FIELDS.some((field) => !Object.hasOwn(query, field))) fail();
      const safeQuery = {};
      for (const field of QUERY_FIELDS) {
        const value = query[field];
        if (Object.hasOwn(BYTE_FIELDS, field)) {
          safeQuery[field] = value === null
            && ["package_envelope_digest", "expected_manifest_digest"].includes(field)
            ? null : encodeByte(value, ...BYTE_FIELDS[field]);
        } else if (field === "expected_revision") {
          if (value !== null && (!Number.isSafeInteger(value) || value < 1)) fail();
          safeQuery[field] = value;
        } else if (field === "proposed_revision") {
          if (!Number.isSafeInteger(value) || value < 1) fail();
          safeQuery[field] = value;
        } else fail();
      }
      const body = Buffer.from(JSON.stringify({
        query: safeQuery, nonce: encodeByte(nonce, 32, 32),
      }));
      if (body.length > 4096) fail();
      return new Promise((resolve, reject) => {
        const rejectGeneric = () => reject(new Error("CAS_STATUS_TRANSPORT_UNAVAILABLE"));
        const request = https.request({
          hostname: url.hostname, port: url.port,
          path: url.pathname, method: "POST",
          ca, cert: clientCert, key: clientKey,
          rejectUnauthorized: true, minVersion: "TLSv1.3",
          servername: url.hostname,
          checkServerIdentity(hostname, peer) {
            const hostError = tls.checkServerIdentity(hostname, peer);
            if (hostError) return hostError;
            if (!peer.fingerprint256
              || peer.fingerprint256.toUpperCase() !== peerFingerprint) {
              return new Error("CAS_STATUS_PEER_NOT_PINNED");
            }
            return undefined;
          },
          timeout: timeoutMs,
          headers: {
            "content-type": "application/json",
            "content-length": String(body.length),
            "accept": "application/json",
          },
        }, (response) => {
          if (response.statusCode !== 200
            || response.headers["content-type"] !== "application/json") {
            response.resume();
            rejectGeneric();
            return;
          }
          let size = 0;
          const received = [];
          response.on("data", (part) => {
            size += part.length;
            if (size > 8192) {
              request.destroy();
              rejectGeneric();
            } else received.push(part);
          });
          response.on("end", () => {
            try {
              const object = JSON.parse(Buffer.concat(received).toString("utf8"));
              if (!object || typeof object !== "object" || Array.isArray(object)
                || Reflect.ownKeys(object).length !== 1
                || !Object.hasOwn(object, "proofBase64")
                || typeof object.proofBase64 !== "string"
                || !B64U.test(object.proofBase64)) fail();
              const raw = Buffer.from(object.proofBase64, "base64url");
              if (!raw.length || raw.length > 6144
                || raw.toString("base64url") !== object.proofBase64) fail();
              resolve(raw);
            } catch (_) { rejectGeneric(); }
          });
          response.on("error", rejectGeneric);
        });
        request.on("timeout", () => request.destroy());
        request.on("error", rejectGeneric);
        request.end(body);
      });
    },
  });
}

module.exports = { createZk1CasStatusHttpsClient };
