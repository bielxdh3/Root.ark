"use strict";

// A pinned, independent CAS *public manifest* transport; returned bytes are
// UNTRUSTED until reconciled with the separately signed fresh witness head.
const https = require("node:https");
const tls = require("node:tls");

const PIN = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const B64 = /^[A-Za-z0-9_-]+$/;
function fail() {
  const e = new Error("CAS_MANIFEST_TRANSPORT_UNAVAILABLE");
  e.code = "CAS_MANIFEST_TRANSPORT_UNAVAILABLE";
  throw e;
}
function bytes(input, min, max = min) {
  if ((!Buffer.isBuffer(input) && !(input instanceof Uint8Array))
    || input.byteLength < min || input.byteLength > max) fail();
  return Buffer.from(input).toString("base64url");
}
function exact(value, names) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== names.length
    || names.some((name) => !Object.hasOwn(value, name))
    || Reflect.ownKeys(value).some((name) => !names.includes(name))) fail();
}
function createZk1CasManifestHttpsClient({
  endpoint, ca, clientKey, clientCert, serverFingerprint256, timeoutMs = 3000,
} = {}) {
  let url;
  try { url = new URL(endpoint); } catch (_) { fail(); }
  if (url.protocol !== "https:" || !url.hostname || !url.port
    || url.pathname !== "/v1/manifest" || url.username || url.password || url.search || url.hash
    || !ca || !clientKey || !clientCert || !PIN.test(serverFingerprint256)
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) fail();
  const pin = serverFingerprint256.toUpperCase();
  return Object.freeze({
    getCommittedManifest({ scope } = {}) {
      exact(scope, ["account_id", "compartment_id", "keyring_id"]);
      const body = Buffer.from(JSON.stringify({ scope: {
        account_id: bytes(scope.account_id, 16),
        compartment_id: bytes(scope.compartment_id, 1, 128),
        keyring_id: bytes(scope.keyring_id, 16),
      } }));
      return new Promise((resolve, reject) => {
        let completed = false;
        const unavailable = () => {
          if (!completed) { completed = true; reject(new Error("CAS_MANIFEST_TRANSPORT_UNAVAILABLE")); }
        };
        const request = https.request({
          hostname: url.hostname, port: url.port, method: "POST", path: url.pathname,
          agent: false, // do not reuse a socket authenticated under another TLS pin
          ca, cert: clientCert, key: clientKey, rejectUnauthorized: true,
          minVersion: "TLSv1.3", servername: url.hostname,
          checkServerIdentity(hostname, peer) {
            const failure = tls.checkServerIdentity(hostname, peer);
            if (failure) return failure;
            if (!peer.fingerprint256 || peer.fingerprint256.toUpperCase() !== pin) {
              return new Error("CAS_MANIFEST_PEER_UNPINNED");
            }
            return undefined;
          },
          timeout: timeoutMs,
          headers: { "content-type": "application/json", "accept": "application/json",
            "content-length": String(body.byteLength) },
        }, (response) => {
          if (response.statusCode !== 200 || response.headers["content-type"] !== "application/json") {
            response.resume();
            unavailable();
            return;
          }
          let length = 0;
          const chunks = [];
          response.on("data", (part) => {
            length += part.length;
            if (length > 12 * 1024 * 1024) { request.destroy(); unavailable(); }
            else chunks.push(part);
          });
          response.on("end", () => {
            if (completed) return;
            try {
              const result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
              exact(result, ["manifestBase64"]);
              const value = result.manifestBase64;
              if (typeof value !== "string" || value.length > 11 * 1024 * 1024
                || !B64.test(value)) fail();
              const raw = Buffer.from(value, "base64url");
              if (raw.length < 1 || raw.length > 8 * 1024 * 1024
                || raw.toString("base64url") !== value) fail();
              completed = true;
              resolve(raw);
            } catch (_) { unavailable(); }
          });
          response.on("error", unavailable);
        });
        request.on("timeout", () => request.destroy());
        request.on("error", unavailable);
        request.end(body);
      });
    },
  });
}

module.exports = { createZk1CasManifestHttpsClient };
