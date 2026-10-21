"use strict";

// A pinned, independent CAS *public manifest* transport; returned bytes are
// UNTRUSTED until reconciled with the separately signed fresh witness head.
const https = require("node:https");
const tls = require("node:tls");
const { performance } = require("node:perf_hooks");

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
  endpoint, ca, clientKey, clientCert, serverFingerprint256, timeoutMs = 15000,
  historyDeadlineMs = 120000,
} = {}) {
  let url;
  try { url = new URL(endpoint); } catch (_) { fail(); }
  if (url.protocol !== "https:" || !url.hostname || !url.port
    || url.pathname !== "/v1/manifest" || url.username || url.password || url.search || url.hash
    || !ca || !clientKey || !clientCert || !PIN.test(serverFingerprint256)
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000
    || !Number.isSafeInteger(historyDeadlineMs)
    || historyDeadlineMs < 100 || historyDeadlineMs > 300000) fail();
  const pin = serverFingerprint256.toUpperCase();
  function fetchResource(scope, startRevision, absoluteDeadline) {
      const history = startRevision !== undefined;
      if (history && (!Number.isSafeInteger(startRevision)
        || startRevision < 1 || startRevision > 4097)) fail();
      exact(scope, ["account_id", "compartment_id", "keyring_id"]);
      const body = Buffer.from(JSON.stringify({ scope: {
        account_id: bytes(scope.account_id, 16),
        compartment_id: bytes(scope.compartment_id, 1, 128),
        keyring_id: bytes(scope.keyring_id, 16),
      }, ...(history ? { startRevision } : {}) }));
      // https.request's socket timeout is an IDLE timeout: receiving one byte
      // before each interval can keep it alive forever. Bound real elapsed
      // time and share a monotonic deadline across sequential history pages.
      const remaining = absoluteDeadline === undefined
        ? timeoutMs : Math.floor(absoluteDeadline - performance.now());
      if (!Number.isSafeInteger(remaining) || remaining <= 0) fail();
      const wallTimeout = Math.min(timeoutMs, remaining);
      return new Promise((resolve, reject) => {
        let completed = false;
        let request;
        let wallTimer;
        const unavailable = () => {
          if (!completed) {
            completed = true;
            clearTimeout(wallTimer);
            request?.destroy();
            reject(new Error("CAS_MANIFEST_TRANSPORT_UNAVAILABLE"));
          }
        };
        const complete = (value) => {
          if (completed) return;
          completed = true;
          clearTimeout(wallTimer);
          resolve(value);
        };
        request = https.request({
          hostname: url.hostname, port: url.port, method: "POST",
          path: history ? "/v1/history" : url.pathname,
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
          timeout: wallTimeout,
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
              if (history) {
                exact(result, ["headRevision", "headDigest", "startRevision",
                  "nextRevision", "entriesBase64"]);
                if (!Number.isSafeInteger(result.headRevision)
                  || result.headRevision < startRevision || result.headRevision > 4097
                  || result.startRevision !== startRevision
                  || (result.nextRevision !== null
                    && (!Number.isSafeInteger(result.nextRevision)
                      || result.nextRevision > result.headRevision
                      || result.nextRevision <= startRevision))
                  || typeof result.headDigest !== "string"
                  || !B64.test(result.headDigest)
                  || !Array.isArray(result.entriesBase64)
                  || result.entriesBase64.length < 1
                  || result.entriesBase64.length > 4097) fail();
                const headDigest = Buffer.from(result.headDigest, "base64url");
                if (headDigest.length !== 32
                  || headDigest.toString("base64url") !== result.headDigest) fail();
                let total = 0;
                const entries = result.entriesBase64.map((entry) => {
                  if (typeof entry !== "string" || !B64.test(entry)
                    || entry.length > 11 * 1024 * 1024) fail();
                  const raw = Buffer.from(entry, "base64url");
                  total += raw.length;
                  if (!raw.length || total > 8 * 1024 * 1024
                    || raw.toString("base64url") !== entry) fail();
                  return raw;
                });
                const end = startRevision + entries.length - 1;
                if (end > result.headRevision
                  || (result.nextRevision === null) !== (end === result.headRevision)
                  || (result.nextRevision !== null && result.nextRevision !== end + 1)) fail();
                complete({ headRevision: result.headRevision, headDigest,
                  startRevision, nextRevision: result.nextRevision, entries });
                return;
              }
              exact(result, ["manifestBase64"]);
              const value = result.manifestBase64;
              if (typeof value !== "string" || value.length > 11 * 1024 * 1024
                || !B64.test(value)) fail();
              const raw = Buffer.from(value, "base64url");
              if (raw.length < 1 || raw.length > 8 * 1024 * 1024
                || raw.toString("base64url") !== value) fail();
              complete(raw);
            } catch (_) { unavailable(); }
          });
          response.on("error", unavailable);
        });
        wallTimer = setTimeout(unavailable, wallTimeout);
        request.on("timeout", unavailable);
        request.on("error", unavailable);
        request.end(body);
      });
  }
  return Object.freeze({
    getCommittedManifest({ scope } = {}) { return fetchResource(scope); },
    getCommittedHistoryPage({ scope, startRevision } = {}) {
      return fetchResource(scope, startRevision);
    },
    async getCommittedHistory({ scope } = {}) {
      // Transport convenience only: pages are still UNTRUSTED signed bytes.
      // A separate public-chain verifier and fresh witness must authenticate
      // the full chain before any dependent admission.
      // All page requests MUST address exactly the same owner-selected scope.
      // Snapshot caller-owned arrays before the first await so concurrent
      // mutation cannot redirect later pages to a different keyring.
      exact(scope, ["account_id", "compartment_id", "keyring_id"]);
      const pinnedScope = {
        account_id: Buffer.from(bytes(scope.account_id, 16), "base64url"),
        compartment_id: Buffer.from(bytes(scope.compartment_id, 1, 128), "base64url"),
        keyring_id: Buffer.from(bytes(scope.keyring_id, 16), "base64url"),
      };
      let startRevision = 1;
      let headRevision;
      let headDigest;
      const entries = [];
      let total = 0;
      const absoluteDeadline = performance.now() + historyDeadlineMs;
      for (let pageCount = 0; pageCount <= 4096; pageCount += 1) {
        const page = await fetchResource(pinnedScope, startRevision, absoluteDeadline);
        if (pageCount === 0) {
          headRevision = page.headRevision;
          headDigest = Buffer.from(page.headDigest);
        } else if (page.headRevision !== headRevision
          || !page.headDigest.equals(headDigest)) fail();
        for (const item of page.entries) {
          total += item.length;
          if (total > 64 * 1024 * 1024 || entries.length >= 4097) fail();
          entries.push(Buffer.from(item));
        }
        if (page.nextRevision === null) {
          if (entries.length !== headRevision) fail();
          return { headRevision, headDigest, entries };
        }
        if (page.nextRevision <= startRevision
          || page.nextRevision !== entries.length + 1) fail();
        startRevision = page.nextRevision;
      }
      fail();
    },
  });
}

module.exports = { createZk1CasManifestHttpsClient };
