"use strict";

// mTLS transport only. The authoritative caller MUST verify the returned
// Ed25519 proof against an independently retained attestor key and nonce.
const https = require("node:https");
const tls = require("node:tls");
const net = require("node:net");

const PIN = /^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/i;
function deny() {
  const e = new Error("ZK_PHYSICAL_ATTESTOR_TRANSPORT_UNAVAILABLE");
  e.code = e.message;
  throw e;
}
function exact(v, fields) {
  if (!v || typeof v !== "object" || Array.isArray(v)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(v))
    || Reflect.ownKeys(v).length !== fields.length
    || fields.some((f) => !Object.hasOwn(v, f))) deny();
}
function enc(v, size, max = size) {
  if ((!Buffer.isBuffer(v) && !(v instanceof Uint8Array))
    || v.length < size || v.length > max) deny();
  return Buffer.from(v).toString("base64url");
}
function count(n, min = 0) {
  if (!Number.isSafeInteger(n) || n < min) deny();
  return n;
}
function toWire({ scope, operation, nonce }) {
  exact(scope, ["account_id", "compartment_id", "keyring_id"]);
  exact(operation, ["operation_id", "expected_sequence", "expected_root", "object_id",
    "revision", "epoch", "ciphertext_sha256"]);
  return { scope: { account_id: enc(scope.account_id, 16),
    compartment_id: enc(scope.compartment_id, 1, 128),
    keyring_id: enc(scope.keyring_id, 16) },
  operation: { operation_id: enc(operation.operation_id, 16),
    expected_sequence: count(operation.expected_sequence),
    expected_root: enc(operation.expected_root, 32), object_id: enc(operation.object_id, 16),
    revision: count(operation.revision, 1), epoch: count(operation.epoch),
    ciphertext_sha256: enc(operation.ciphertext_sha256, 32) }, nonce: enc(nonce, 32) };
}
function createZk1PgPhysicalAttestorHttpsClient({ endpoint, ca, clientKey, clientCert,
  serverFingerprint256, timeoutMs = 12000 } = {}) {
  let url;
  try { url = new URL(endpoint); } catch (_) { deny(); }
  if (url.protocol !== "https:" || !url.hostname || !url.port
    || url.username || url.password || url.search || url.hash
    || !["", "/"].includes(url.pathname)
    || !ca || !clientKey || !clientCert || !PIN.test(serverFingerprint256)
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) deny();
  const pin = serverFingerprint256.toUpperCase();
  return Object.freeze({
    requestAttestation(input) {
      const wire = toWire(input);
      const payload = Buffer.from(JSON.stringify(wire), "utf8");
      if (payload.length > 2048) deny();
      return new Promise((resolve, reject) => {
        let done = false;
        let request;
        let timer;
        const fail = () => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          request?.destroy();
          reject(new Error("ZK_PHYSICAL_ATTESTOR_TRANSPORT_UNAVAILABLE"));
        };
        request = https.request({ hostname: url.hostname, port: url.port,
          path: "/v1/physical/attest", method: "POST", ca, key: clientKey, cert: clientCert,
          agent: false, rejectUnauthorized: true, minVersion: "TLSv1.3",
          servername: net.isIP(url.hostname) ? "" : url.hostname,
          checkServerIdentity(host, peer) {
            const error = tls.checkServerIdentity(host, peer);
            if (error) return error;
            return peer.fingerprint256?.toUpperCase() === pin
              ? undefined : Error("ZK_PHYSICAL_ATTESTOR_PEER_NOT_PINNED");
          }, timeout: timeoutMs,
          headers: { "content-type": "application/json", accept: "application/json",
            "content-length": String(payload.length) },
        }, (response) => {
          if (response.statusCode !== 200
            || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers["content-type"] || "")) {
            response.resume(); fail(); return;
          }
          const chunks = [];
          let length = 0;
          response.on("data", (part) => {
            length += part.length;
            if (length > 4096) { response.destroy(); fail(); }
            else chunks.push(part);
          });
          response.on("error", fail);
          response.on("end", () => {
            if (done) return;
            try {
              const data = JSON.parse(Buffer.concat(chunks).toString("utf8"));
              exact(data, ["proof"]);
              if (typeof data.proof !== "string" || !/^[A-Za-z0-9_-]+$/.test(data.proof)) deny();
              const raw = Buffer.from(data.proof, "base64url");
              if (!raw.length || raw.length > 2048 || raw.toString("base64url") !== data.proof) deny();
              done = true;
              clearTimeout(timer);
              resolve(raw);
            } catch (_) { fail(); }
          });
        });
        timer = setTimeout(fail, timeoutMs);
        request.on("error", fail);
        request.on("timeout", fail);
        request.end(payload);
      });
    },
  });
}

module.exports = { createZk1PgPhysicalAttestorHttpsClient };
