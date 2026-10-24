"use strict";

// CAS operator's client of the independently administered witness-owned
// monotonic journal floor. A response is accepted only under pinned mTLS,
// witness Ed25519 signature, request nonce and pinned status signer identity.
const https = require("node:https");
const tls = require("node:tls");
const net = require("node:net");
const crypto = require("node:crypto");
const { verifyFreshWitnessCasFloor } = require("./zk1WitnessCasAnchorFloor");
const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const ZERO = "0".repeat(64);
function fail() {
  const error = new Error("CAS_WITNESS_FLOOR_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function exact(input, keys) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
    || Reflect.ownKeys(input).length !== keys.length
    || keys.some((k) => !Object.hasOwn(input, k))) fail();
}
class Zk1WitnessCasAnchorHttpsClient {
  #url;
  #tls;
  #pinned;
  #pinnedWitness;
  #witnessKeyId;
  #statusKeyId;
  #timeout;
  #headTimeout;
  constructor({ endpoint, ca, clientKey, clientCert, serverFingerprint256,
    pinnedWitnessPublicKey, pinnedWitnessKeyId, pinnedStatusKeyId,
    timeoutMs = 5000, headTimeoutMs = 9000 } = {}) {
    try { this.#url = new URL(endpoint); }
    catch (_) { fail(); }
    if (this.#url.protocol !== "https:" || !this.#url.hostname || !this.#url.port
      || this.#url.username || this.#url.password || this.#url.search || this.#url.hash
      || (this.#url.pathname !== "/" && this.#url.pathname !== "")
      || !ca || !clientKey || !clientCert || !FINGERPRINT.test(serverFingerprint256)
      || !(pinnedWitnessPublicKey instanceof crypto.KeyObject)
      || pinnedWitnessPublicKey.type !== "public"
      || pinnedWitnessPublicKey.asymmetricKeyType !== "ed25519"
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000
      || !Number.isSafeInteger(headTimeoutMs) || headTimeoutMs < 100
      || headTimeoutMs > 10000) fail();
    if ((!Buffer.isBuffer(pinnedWitnessKeyId) && !(pinnedWitnessKeyId instanceof Uint8Array))
      || pinnedWitnessKeyId.byteLength !== 16
      || (!Buffer.isBuffer(pinnedStatusKeyId) && !(pinnedStatusKeyId instanceof Uint8Array))
      || pinnedStatusKeyId.byteLength !== 16) fail();
    this.#tls = { ca: Buffer.from(ca), key: Buffer.from(clientKey),
      cert: Buffer.from(clientCert) };
    this.#pinned = serverFingerprint256.toUpperCase();
    this.#pinnedWitness = pinnedWitnessPublicKey;
    this.#witnessKeyId = Buffer.from(pinnedWitnessKeyId);
    this.#statusKeyId = Buffer.from(pinnedStatusKeyId);
    this.#timeout = timeoutMs;
    // A full signed witness-floor verification may scan 100k immutable events
    // off-thread. Only that endpoint receives a larger bounded budget; the
    // untrusted /advance ACK keeps the regular 5s default and never authorizes.
    this.#headTimeout = headTimeoutMs;
  }
  async #send(urlPath, body, timeoutMs = this.#timeout) {
    const payload = Buffer.from(JSON.stringify(body), "utf8");
    if (payload.length < 2 || payload.length > (urlPath.endsWith("/advance") ? 96 * 1024 : 4096)) fail();
    try {
      return await new Promise((resolve, reject) => {
        let ended = false;
        const done = (error, result) => {
          if (ended) return;
          ended = true;
          clearTimeout(deadline);
          if (error) reject(error);
          else resolve(result);
        };
        const request = https.request({ hostname: this.#url.hostname, port: this.#url.port,
          path: urlPath, method: "POST", agent: false, ...this.#tls,
          rejectUnauthorized: true, minVersion: "TLSv1.3",
          servername: net.isIP(this.#url.hostname) ? "" : this.#url.hostname,
          checkServerIdentity: (hostname, peer) => {
            const invalid = tls.checkServerIdentity(hostname, peer);
            if (invalid) return invalid;
            return peer.fingerprint256?.toUpperCase() === this.#pinned
              ? undefined : new Error("CAS_WITNESS_PEER_INVALID");
          },
          headers: { "content-type": "application/json", accept: "application/json",
            "content-length": String(payload.length) },
        }, (response) => {
          if (response.statusCode !== 200
            || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers["content-type"] || "")) {
            response.resume();
            return done(new Error("CAS_WITNESS_FLOOR_UNAVAILABLE"));
          }
          const parts = [];
          let length = 0;
          response.on("data", (part) => {
            length += part.length;
            if (length > 2048) {
              request.destroy();
              done(new Error("CAS_WITNESS_FLOOR_UNAVAILABLE"));
            } else parts.push(part);
          });
          response.on("error", (error) => done(error));
          response.on("end", () => {
            try { done(null, JSON.parse(Buffer.concat(parts).toString("utf8"))); }
            catch (error) { done(error); }
          });
        });
        const deadline = setTimeout(() => request.destroy(
          new Error("CAS_WITNESS_FLOOR_UNAVAILABLE")), timeoutMs);
        request.on("error", (error) => done(error));
        request.end(payload);
      });
    } catch (_) { fail(); }
  }
  async freshHead(minimumHead) {
    const nonce = crypto.randomBytes(32);
    const answer = await this.#send("/v1/cas-anchor/head", {
      nonce: nonce.toString("base64url"),
    }, this.#headTimeout);
    try {
      exact(answer, ["head", "authority"]);
      if (answer.authority !== "WITNESS_CAS_ANCHOR_FLOOR_V1") fail();
      return verifyFreshWitnessCasFloor({ signed: answer.head, nonce,
        pinnedWitnessPublicKey: this.#pinnedWitness,
        pinnedWitnessKeyId: this.#witnessKeyId,
        pinnedStatusKeyId: this.#statusKeyId,
        minimumHead });
    } catch (_) { fail(); }
  }
  async advanceSignedRecords(records, evidence = undefined) {
    if (!Array.isArray(records) || !records.length || records.length > 16
      || Reflect.ownKeys(records).length !== records.length + 1) fail();
    const snapshot = [];
    for (let i = 0; i < records.length; i += 1) {
      const d = Object.getOwnPropertyDescriptor(records, String(i));
      if (!d || !Object.hasOwn(d, "value") || typeof d.value !== "string"
        || d.value.length < 100 || d.value.length > 2048) fail();
      snapshot.push(d.value);
    }
    let attested = undefined;
    if (evidence !== undefined) {
      if (!Array.isArray(evidence) || evidence.length !== snapshot.length
        || Reflect.ownKeys(evidence).length !== evidence.length + 1) fail();
      // Only JSON-data evidence crosses this interface. The witness performs
      // the actual fresh-nonce PG readback, signature and chain verification.
      try { attested = JSON.parse(JSON.stringify(evidence)); }
      catch (_) { fail(); }
      if (!Array.isArray(attested) || attested.length !== snapshot.length) fail();
    }
    const response = await this.#send("/v1/cas-anchor/advance", {
      records: snapshot, ...(attested ? { evidence: attested } : {}),
    });
    try {
      exact(response, ["sequence", "lastHash", "authority"]);
      if (response.authority !== "WITNESS_CAS_ANCHOR_FLOOR_V1"
        || !Number.isSafeInteger(response.sequence) || response.sequence < 1
        || response.sequence > 100000
        || typeof response.lastHash !== "string"
        || !/^[a-f0-9]{64}$/.test(response.lastHash)) fail();
    } catch (_) { fail(); }
    // The unsigned transport ACK is NOT proof of durable witness progress.
    // CAS callers must independently check a fresh nonce-bound signed head.
    return false;
  }
}
module.exports = { Zk1WitnessCasAnchorHttpsClient };
