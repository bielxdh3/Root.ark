"use strict";

// Strict, pinned mTLS transport for the standalone zk-1 witness. All receipts
// remain UNTRUSTED BYTES until callers verify the separate Ed25519 witness
// signing identity, nonce, floor, scope and expected transition.
const https = require("node:https");
const tls = require("node:tls");

const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const B64U = /^[A-Za-z0-9_-]+$/;
const SCOPE = Object.freeze(["account_id", "compartment_id", "keyring_id"]);
const OPERATION = Object.freeze([
  ...SCOPE, "reservation_id", "operation_id", "expected_revision",
  "expected_manifest_digest", "proposed_revision", "proposed_manifest_digest",
  "request_digest", "package_envelope_digest", "expires_at",
]);
const SIZES = Object.freeze({
  account_id: [16, 16], compartment_id: [1, 128], keyring_id: [16, 16],
  reservation_id: [16, 16], operation_id: [16, 16],
  expected_manifest_digest: [32, 32], proposed_manifest_digest: [32, 32],
  request_digest: [32, 32], package_envelope_digest: [32, 32], nonce: [32, 32],
});
function fail() {
  const err = new Error("WITNESS_TRANSPORT_UNAVAILABLE");
  err.code = "WITNESS_TRANSPORT_UNAVAILABLE";
  throw err;
}
function b64(bytes, [min, max]) {
  if ((!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array))
    || bytes.byteLength < min || bytes.byteLength > max) fail();
  return Buffer.from(bytes).toString("base64url");
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((key) => !Object.hasOwn(value, key))
    || Reflect.ownKeys(value).some((key) => !fields.includes(key))) fail();
}
function normalize(value, fields) {
  exact(value, fields);
  const output = {};
  for (const name of fields) {
    const item = value[name];
    if (Object.hasOwn(SIZES, name)) {
      output[name] = item === null
        && ["expected_manifest_digest", "package_envelope_digest"].includes(name)
        ? null : b64(item, SIZES[name]);
    } else if (name === "expected_revision") {
      if (item !== null && (!Number.isSafeInteger(item) || item < 1)) fail();
      output[name] = item;
    } else if (["proposed_revision", "expires_at"].includes(name)) {
      if (!Number.isSafeInteger(item) || item < (name === "expires_at" ? 0 : 1)) fail();
      output[name] = item;
    } else fail();
  }
  if (fields === OPERATION && ((value.expected_revision === null)
    !== (value.expected_manifest_digest === null)
    || value.proposed_revision !== (value.expected_revision === null
      ? 1 : value.expected_revision + 1))) fail();
  return output;
}
function canonicalReceipt(encoded) {
  if (typeof encoded !== "string" || !B64U.test(encoded) || encoded.length > 10924) fail();
  const bytes = Buffer.from(encoded, "base64url");
  if (!bytes.length || bytes.length > 8192 || bytes.toString("base64url") !== encoded) fail();
  return bytes;
}
function createZk1WitnessHttpsClient({
  endpoint, ca, clientKey, clientCert, serverFingerprint256, timeoutMs = 3000,
}) {
  let url;
  try { url = new URL(endpoint); }
  catch (_) { fail(); }
  if (url.protocol !== "https:" || !url.hostname || !url.port
    || url.username || url.password || url.search || url.hash
    || (url.pathname !== "/" && url.pathname !== "")
    || !ca || !clientKey || !clientCert || !FINGERPRINT.test(serverFingerprint256)
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) fail();
  const pinned = serverFingerprint256.toUpperCase();
  function send(path, body) {
    const payload = Buffer.from(JSON.stringify(body), "utf8");
    if (payload.length > 4096) fail();
    return new Promise((resolve, reject) => {
      let completed = false;
      const unavailable = () => {
        if (completed) return;
        completed = true;
        reject(new Error("WITNESS_TRANSPORT_UNAVAILABLE"));
      };
      const request = https.request({
        hostname: url.hostname, port: url.port, path, method: "POST",
        ca, key: clientKey, cert: clientCert, rejectUnauthorized: true,
        minVersion: "TLSv1.3", servername: url.hostname,
        checkServerIdentity(hostname, peer) {
          const nameError = tls.checkServerIdentity(hostname, peer);
          if (nameError) return nameError;
          if (!peer.fingerprint256 || peer.fingerprint256.toUpperCase() !== pinned) {
            return new Error("WITNESS_PEER_NOT_PINNED");
          }
          return undefined;
        },
        timeout: timeoutMs,
        headers: { "content-type": "application/json",
          "content-length": String(payload.length), accept: "application/json" },
      }, (response) => {
        if (![200, 201].includes(response.statusCode)
          || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers["content-type"] || "")) {
          response.resume();
          unavailable();
          return;
        }
        let length = 0;
        const chunks = [];
        response.on("data", (part) => {
          length += part.length;
          if (length > 12000) { request.destroy(); unavailable(); }
          else chunks.push(part);
        });
        response.on("end", () => {
          try {
            if (completed) return;
            const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            exact(parsed, path === "/v1/resolve"
              ? ["status", "receiptBase64", "authority"]
              : ["receiptBase64", "authority"]);
            if (parsed.authority !== "WITNESS_ENGINE_ONLY") fail();
            if (path === "/v1/resolve" && !["committed", "cancelled"].includes(parsed.status)) fail();
            const receipt = canonicalReceipt(parsed.receiptBase64);
            completed = true;
            resolve(path === "/v1/resolve" ? { status: parsed.status, receipt } : receipt);
          } catch (_) { unavailable(); }
        });
        response.on("error", unavailable);
      });
      request.on("timeout", () => request.destroy());
      request.on("error", unavailable);
      request.end(payload);
    });
  }
  return Object.freeze({
    freshHead({ scope, nonce }) {
      return send("/v1/head", { scope: normalize(scope, SCOPE), nonce: b64(nonce, SIZES.nonce) });
    },
    reserve({ operation, initializeSignature }) {
      const normalized = normalize(operation, OPERATION);
      const body = { operation: normalized };
      if (operation.expected_revision === null) {
        body.initializeSignature = b64(initializeSignature, [64, 64]);
      } else if (initializeSignature !== undefined) fail();
      return send("/v1/reserve", body);
    },
    resolve({ scope }) { return send("/v1/resolve", { scope: normalize(scope, SCOPE) }); },
  });
}

module.exports = { createZk1WitnessHttpsClient };
