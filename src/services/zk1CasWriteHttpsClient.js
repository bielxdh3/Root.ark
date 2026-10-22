"use strict";

// Scoped mTLS transport for CAS reservation registration and signed public
// manifest submission. A successful HTTP acknowledgement is NOT a terminal
// proof, epoch grant or protected-content I/O authorization. The independent
// witness must verify signed CAS status before protected state is trusted.
const https = require("node:https");
const tls = require("node:tls");

const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const B64U = /^[A-Za-z0-9_-]+$/;
const MAX_MANIFEST_BYTES = 8 * 1024 * 1024;
function fail() {
  const err = new Error("CAS_WRITE_TRANSPORT_UNAVAILABLE");
  err.code = "CAS_WRITE_TRANSPORT_UNAVAILABLE";
  throw err;
}
function byteField(value, max) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < 1 || value.byteLength > max) fail();
  return Buffer.from(value).toString("base64url");
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))
    || Reflect.ownKeys(value).some((field) => !fields.includes(field))) fail();
}
function createZk1CasWriteHttpsClient({
  endpoint, ca, clientKey, clientCert, serverFingerprint256,
  timeoutMs = 5000,
}) {
  let url;
  try { url = new URL(endpoint); }
  catch (_) { fail(); }
  if (url.protocol !== "https:" || !url.hostname || !url.port || url.username
    || url.password || url.search || url.hash
    || !["", "/"].includes(url.pathname) || !ca || !clientKey || !clientCert
    || !FINGERPRINT.test(serverFingerprint256)
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 15000) fail();
  const fingerprint = serverFingerprint256.toUpperCase();
  function request(path, payload) {
    const encoded = Buffer.from(JSON.stringify(payload), "utf8");
    if (encoded.byteLength > 12 * 1024 * 1024) fail();
    return new Promise((resolve, reject) => {
      let finished = false;
      let req;
      let deadline;
      const unavailable = () => {
        if (finished) return;
        finished = true;
        clearTimeout(deadline);
        req?.destroy();
        reject(new Error("CAS_WRITE_TRANSPORT_UNAVAILABLE"));
      };
      req = https.request({
        hostname: url.hostname, port: url.port, path, method: "POST",
        agent: false, // never borrow a socket verified by another writer pin
        ca, key: clientKey, cert: clientCert, rejectUnauthorized: true,
        minVersion: "TLSv1.3", servername: url.hostname,
        checkServerIdentity(hostname, peer) {
          const hostFailure = tls.checkServerIdentity(hostname, peer);
          if (hostFailure) return hostFailure;
          if (!peer.fingerprint256 || peer.fingerprint256.toUpperCase() !== fingerprint) {
            return new Error("CAS_WRITE_SERVER_NOT_PINNED");
          }
          return undefined;
        },
        timeout: timeoutMs,
        headers: {
          "content-type": "application/json",
          "content-length": String(encoded.byteLength),
          accept: "application/json",
        },
      }, (res) => {
        if (res.statusCode !== 200
          || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(res.headers["content-type"] || "")) {
          res.resume();
          unavailable();
          return;
        }
        let length = 0;
        const chunks = [];
        res.on("data", (part) => {
          length += part.byteLength;
          if (length > 1024) { req.destroy(); unavailable(); }
          else chunks.push(part);
        });
        res.on("end", () => {
          if (finished) return;
          try {
            const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            exact(body, path === "/v1/commit"
              ? ["status", "replay", "authority"] : ["status", "authority"]);
            if (body.authority !== "CAS_ENGINE_ONLY"
              || !["pending", "committed", "not-committed-final"].includes(body.status)) fail();
            if (path === "/v1/commit"
              && (body.status !== "committed" || typeof body.replay !== "boolean")) fail();
            finished = true;
            clearTimeout(deadline);
            resolve(path === "/v1/commit"
              ? { status: body.status, replay: body.replay } : { status: body.status });
          } catch (_) { unavailable(); }
        });
        res.on("error", unavailable);
      });
      // Socket timeout measures IDLE time, so a pinned peer can send a byte
      // each interval and hold a recovery write open indefinitely. Bound the
      // entire TLS handshake, request body, and response by one deadline.
      deadline = setTimeout(unavailable, timeoutMs);
      req.on("timeout", unavailable);
      req.on("error", unavailable);
      req.end(encoded);
    });
  }
  return Object.freeze({
    register({ receipt }) {
      return request("/v1/register", { receiptBase64: byteField(receipt, 4096) });
    },
    commit({ receipt, manifestBytes }) {
      return request("/v1/commit", {
        receiptBase64: byteField(receipt, 4096),
        manifestBase64: byteField(manifestBytes, MAX_MANIFEST_BYTES),
      });
    },
  });
}

module.exports = { createZk1CasWriteHttpsClient };
