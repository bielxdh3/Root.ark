"use strict";

// Client pins the independent Ed25519 signer separately from mTLS transport.
// Transport errors after CAS submission are UNCERTAIN, never negative ACK.
const https = require("node:https");
const tls = require("node:tls");
const net = require("node:net");
const crypto = require("node:crypto");
const z = require("../crypto/rootark-zk-1");
const { catalogCasDomain } = require("./zk1OpaqueCatalog");

const CAS_TYPE = "rootark-zk1-opaque-catalog-cas/v1";
const FIELDS = ["type", "account_id", "compartment_id", "keyring_id",
  "sequence", "digest", "nonce", "observed_at"];
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const PIN = /^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/i;
function fail(code = "ZK_OPAQUE_CAS_TRANSPORT_UNAVAILABLE") {
  const error = new Error(code); error.code = code; throw error;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
}
function bytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < min || value.byteLength > max) fail();
  return Buffer.from(value);
}
function same(a, b) { return a.length === b.length && crypto.timingSafeEqual(a, b); }
function encodeScope(scope) {
  exact(scope, SCOPE);
  return Object.fromEntries(SCOPE.map((key) =>
    [key, bytes(scope[key], key === "compartment_id" ? 1 : 16,
      key === "compartment_id" ? 128 : 16).toString("base64url")]));
}
function decodeProof(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) fail();
  const data = Buffer.from(value, "base64url");
  if (!data.length || data.length > 8192 || data.toString("base64url") !== value) fail();
  return data;
}
async function verifyProof(raw, expected, publicKey) {
  const decoded = await z.decodeDeterministic(raw);
  exact(decoded, [...FIELDS, "signature"]);
  const { signature, ...statement } = decoded;
  exact(statement, FIELDS);
  if (statement.type !== CAS_TYPE || statement.sequence < 0
    || statement.sequence > 128 || !Number.isSafeInteger(statement.sequence)
    || !Number.isSafeInteger(statement.observed_at)
    || Math.abs(statement.observed_at - Math.floor(Date.now() / 1000)) > 30
    || !same(bytes(statement.nonce, 32), expected.nonce)
    || !SCOPE.every((key) => same(bytes(statement[key],
      key === "compartment_id" ? 1 : 16,
      key === "compartment_id" ? 128 : 16), expected.scope[key]))
    || (statement.sequence === 0 && !same(bytes(statement.digest, 32), Buffer.alloc(32)))
    || !crypto.verify(null, Buffer.concat([catalogCasDomain,
      Buffer.from(await z.encodeDeterministic(statement))]), publicKey, bytes(signature, 64))) fail();
  return { sequence: statement.sequence, digest: bytes(statement.digest, 32), proof: raw };
}
function createZk1OpaqueCatalogCasHttpsClient({
  endpoint, ca, clientKey, clientCert, serverFingerprint256,
  authorityPublicKey, timeoutMs = 3000,
}) {
  let url;
  try { url = new URL(endpoint); } catch (_) { fail(); }
  if (url.protocol !== "https:" || !url.hostname || !url.port
    || url.username || url.password || url.search || url.hash || url.pathname !== "/"
    || !ca || !clientKey || !clientCert || !PIN.test(serverFingerprint256)
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000
    || !(authorityPublicKey instanceof crypto.KeyObject)
    || authorityPublicKey.type !== "public"
    || authorityPublicKey.asymmetricKeyType !== "ed25519") fail();
  const pin = serverFingerprint256.toUpperCase();
  async function request(route, body, expected, uncertain = false) {
    const payload = Buffer.from(JSON.stringify(body));
    if (payload.length > 3 * 1024 * 1024) fail();
    const received = await new Promise((resolve, reject) => {
      let completed = false;
      const finish = (error, value) => {
        if (completed) return;
        completed = true;
        clearTimeout(timer);
        if (error) { req.destroy(); reject(error); }
        else resolve(value);
      };
      const req = https.request({
        hostname: url.hostname, port: url.port, path: route, method: "POST",
        agent: false, ca, key: clientKey, cert: clientCert,
        rejectUnauthorized: true, minVersion: "TLSv1.3",
        servername: net.isIP(url.hostname) ? "" : url.hostname,
        checkServerIdentity(host, cert) {
          const invalid = tls.checkServerIdentity(host, cert);
          if (invalid) return invalid;
          return cert.fingerprint256?.toUpperCase() === pin ? undefined
            : new Error("ZK_OPAQUE_CAS_PEER_NOT_PINNED");
        },
        headers: { "content-type": "application/json",
          "content-length": payload.length, "accept": "application/json" },
      }, (response) => {
        if (response.statusCode !== 200
          || response.headers["content-type"] !== "application/json") {
          response.resume(); finish(failError()); return;
        }
        let total = 0;
        const parts = [];
        response.on("data", (part) => {
          total += part.length;
          if (total > 8192) finish(failError());
          else parts.push(part);
        });
        response.on("error", () => finish(failError()));
        response.on("end", () => {
          try {
            const data = JSON.parse(Buffer.concat(parts).toString("utf8"));
            exact(data, ["proofBase64"]);
            finish(null, decodeProof(data.proofBase64));
          } catch (_) { finish(failError()); }
        });
      });
      const timer = setTimeout(() => finish(failError()), timeoutMs);
      req.on("error", () => finish(failError()));
      req.end(payload);
    }).catch(() => fail(uncertain
      ? "ZK_OPAQUE_CAS_ACK_UNCERTAIN" : "ZK_OPAQUE_CAS_TRANSPORT_UNAVAILABLE"));
    let proof;
    try { proof = await verifyProof(received, expected, authorityPublicKey); }
    catch (_) { fail(uncertain ? "ZK_OPAQUE_CAS_ACK_UNCERTAIN" : "ZK_OPAQUE_CAS_TRANSPORT_UNAVAILABLE"); }
    return proof;
  }
  const failError = () => new Error("ZK_OPAQUE_CAS_TRANSPORT_UNAVAILABLE");
  return Object.freeze({
    publicKey: authorityPublicKey,
    async readHead({ scope, nonce }) {
      const scopeBytes = Object.fromEntries(SCOPE.map((key) =>
        [key, bytes(scope[key], key === "compartment_id" ? 1 : 16,
          key === "compartment_id" ? 128 : 16)]));
      const challenge = bytes(nonce, 32);
      const result = await request("/v1/head", { scope: encodeScope(scopeBytes),
        nonce: challenge.toString("base64url") }, { scope: scopeBytes, nonce: challenge });
      return result.proof;
    },
    async compareAndSwap({ scope, expectedSequence, expectedDigest, nextSequence,
      nextDigest, nonce, headBytes, headSignature, pageBodies }) {
      const scopeBytes = Object.fromEntries(SCOPE.map((key) =>
        [key, bytes(scope[key], key === "compartment_id" ? 1 : 16,
          key === "compartment_id" ? 128 : 16)]));
      const challenge = bytes(nonce, 32);
      if (!Number.isSafeInteger(expectedSequence) || expectedSequence < 0
        || expectedSequence >= 128 || nextSequence !== expectedSequence + 1
        || !Array.isArray(pageBodies) || pageBodies.length > 128) fail();
      const result = await request("/v1/cas", {
        scope: encodeScope(scopeBytes), expectedSequence,
        expectedDigest: bytes(expectedDigest, 32).toString("base64url"),
        nextSequence, nextDigest: bytes(nextDigest, 32).toString("base64url"),
        nonce: challenge.toString("base64url"),
        headBytes: bytes(headBytes, 1, 16384).toString("base64url"),
        headSignature: bytes(headSignature, 64).toString("base64url"),
        pageBodies: pageBodies.map((body) => bytes(body, 1, 16384).toString("base64url")),
      }, { scope: scopeBytes, nonce: challenge }, true);
      if (result.sequence !== nextSequence || !same(result.digest, bytes(nextDigest, 32))) {
        fail("ZK_OPAQUE_CAS_ACK_UNCERTAIN");
      }
      return result.proof;
    },
    async reconcile({ scope, nonce, expectedSequence, expectedDigest,
      nextSequence, nextDigest }) {
      const proof = await this.readHead({ scope, nonce });
      const scopeBytes = Object.fromEntries(SCOPE.map((key) =>
        [key, bytes(scope[key], key === "compartment_id" ? 1 : 16,
          key === "compartment_id" ? 128 : 16)]));
      const head = await verifyProof(proof,
        { scope: scopeBytes, nonce: bytes(nonce, 32) }, authorityPublicKey);
      const committed = head.sequence === nextSequence
        && same(head.digest, bytes(nextDigest, 32));
      const notCommitted = head.sequence === expectedSequence
        && same(head.digest, bytes(expectedDigest, 32));
      return Object.freeze({
        outcome: committed ? "CAS_COMMITTED_LOCAL_DURABLE"
          : notCommitted ? "CAS_NOT_COMMITTED_AT_READ" : "CAS_HEAD_CONFLICT",
        sequence: head.sequence, digest: head.digest, proof,
        remoteCloudDurabilityProven: false, localCatalogPublished: false,
      });
    },
  });
}
module.exports = { createZk1OpaqueCatalogCasHttpsClient };
