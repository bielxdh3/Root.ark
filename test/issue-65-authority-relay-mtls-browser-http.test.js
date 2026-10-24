"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const express = require("express");
const z = require("../src/crypto/rootark-zk-1");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { createZk1WitnessHttpsClient } =
  require("../src/services/zk1WitnessHttpsClient");
const { createZk1OpaqueCatalogCasHttpsClient } =
  require("../src/services/zk1OpaqueCatalogCasHttpsClient");
const { registerZk1ProtectedObjectRoutes } =
  require("../src/routes/zk1ProtectedObjectRoutes");
const browser = require("../public/client/rootark-zk1-browser-authority-head-relay");
const b64 = (v) => Buffer.from(v).toString("base64url");
const spki = (key) => key.export({ type: "spki", format: "der" });
const digest = (v) => crypto.createHash("sha256").update(v).digest();
const witnessDomain = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const casDomain = Buffer.from("Root.ark/zk-1/opaque-catalog-cas/v1\0");

test("browser/HTTP relay verifies real pinned mTLS witness and CAS signed heads; unknown CAS ACK reconciles by fresh signed read", {
  timeout: 45000,
}, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-proof-relay-mtls-"));
  generateNativeFixtureCertificates(dir, { caSubject: "Proof Relay Lab",
    servers: ["witness", "cas"], clients: ["trusted", "foreign"] });
  const cert = (name) => fs.readFileSync(path.join(dir, name));
  const keys = { witness: crypto.generateKeyPairSync("ed25519"),
    cas: crypto.generateKeyPairSync("ed25519") };
  const witnessKeyId = crypto.randomBytes(16);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("proof-relay-scope"),
    keyring_id: crypto.randomBytes(16) };
  const wireScope = Object.fromEntries(Object.entries(scope).map(([k, v]) => [k, b64(v)]));
  const ownerDigest = crypto.randomBytes(32);
  let sequence = 0, currentDigest = Buffer.alloc(32);
  let witnessRequests = 0, casRequests = 0;
  const now = () => Math.floor(Date.now() / 1000);
  async function sign(fields, domain, privateKey) {
    return z.encodeDeterministic({ ...fields,
      signature: crypto.sign(null, Buffer.concat([domain,
        Buffer.from(await z.encodeDeterministic(fields))]), privateKey) });
  }
  function external(which) {
    const service = https.createServer({ key: cert(which + ".key"),
      cert: cert(which + ".pem"), ca: cert("ca.pem"), requestCert: true,
      rejectUnauthorized: true, minVersion: "TLSv1.3" }, async (req, res) => {
      try {
        const fingerprint = new crypto.X509Certificate(cert("trusted.pem")).fingerprint256;
        if (!req.socket.authorized
          || req.socket.getPeerCertificate()?.fingerprint256 !== fingerprint
          || req.method !== "POST" || req.url !== "/v1/head") throw Error("peer");
        let size = 0; const parts = [];
        for await (const piece of req) {
          size += piece.length;
          if (size > 4096) throw Error("oversize");
          parts.push(piece);
        }
        const body = JSON.parse(Buffer.concat(parts).toString("utf8"));
        if (!body.scope || typeof body.nonce !== "string"
          || Object.keys(body).sort().join(",") !== "nonce,scope"
          || !["account_id", "compartment_id", "keyring_id"].every((k) =>
            body.scope[k] === wireScope[k])) throw Error("scope");
        const nonce = Buffer.from(body.nonce, "base64url");
        if (nonce.length !== 32 || b64(nonce) !== body.nonce) throw Error("nonce");
        const statement = which === "witness"
          ? { type: "rootark-recovery-witness-head/v1", witness_key_id: witnessKeyId,
            ...scope, current_revision: 1, current_manifest_digest: ownerDigest,
            witness_sequence: 1, nonce, observed_at: now(),
            status: "committed", pending_reservation_id: null }
          : { type: "rootark-zk1-opaque-catalog-cas/v1", ...scope,
            sequence, digest: currentDigest, nonce, observed_at: now() };
        if (which === "witness") witnessRequests++;
        else casRequests++;
        const raw = await sign(statement,
          which === "witness" ? witnessDomain : casDomain, keys[which].privateKey);
        const result = JSON.stringify(which === "witness"
          ? { receiptBase64: b64(raw), authority: "WITNESS_ENGINE_ONLY" }
          : { proofBase64: b64(raw) });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(result);
      } catch (_) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end("{}");
      }
    });
    return service;
  }
  const witnessService = external("witness"), casService = external("cas");
  await Promise.all([new Promise((resolve) => witnessService.listen(0, "127.0.0.1", resolve)),
    new Promise((resolve) => casService.listen(0, "127.0.0.1", resolve))]);
  const close = (server) => new Promise((resolve) => server.close(resolve));
  const tlsConfig = (kind, server) => ({ endpoint:
    "https://localhost:" + server.address().port + "/",
    ca: cert("ca.pem"), clientKey: cert("trusted.key"),
    clientCert: cert("trusted.pem"),
    serverFingerprint256: new crypto.X509Certificate(cert(kind + ".pem")).fingerprint256 });
  const witness = createZk1WitnessHttpsClient(tlsConfig("witness", witnessService));
  const cas = createZk1OpaqueCatalogCasHttpsClient({
    ...tlsConfig("cas", casService), authorityPublicKey: keys.cas.publicKey });
  const store = { get() {}, put() {}, signedHistoryRequired: true,
    witnessProvider: witness,
    witnessPinned: { keyId: witnessKeyId, publicKey: keys.witness.publicKey },
    minimumHead: { revision: 1, witnessSequence: 1, digest: ownerDigest }, nowSeconds: now };
  const opaqueCatalog = { store, commit() {}, read() {}, authority: cas };
  const app = express();
  registerZk1ProtectedObjectRoutes({
    app, store, opaqueCatalog,
    authenticate: (req, _res, next) => { req.user = { username: "owner",
      sessionVersion: 1 }; next(); },
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => scope,
  });
  const api = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => api.once("listening", resolve));
  t.after(async () => {
    await Promise.all([close(api), close(witnessService), close(casService)]);
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });
  const origin = "http://127.0.0.1:" + api.address().port + "/";
  const relay = await browser.createProbes({ origin,
    fetchImpl: (url, options) => fetch(url, options),
    assertLive: () => {}, csrfToken: () => "isolated-test",
    ownerWitnessKeyRaw: new Uint8Array(spki(keys.witness.publicKey).subarray(-32)),
    ownerWitnessSpkiSha256: new Uint8Array(digest(spki(keys.witness.publicKey))),
    ownerWitnessKeyId: new Uint8Array(witnessKeyId),
    catalogAuthorityKeyRaw: new Uint8Array(spki(keys.cas.publicKey).subarray(-32)),
    catalogAuthoritySpkiSha256: new Uint8Array(digest(spki(keys.cas.publicKey))) });
  const witnessProof = await relay.ownerWitnessProbe({ scope: wireScope,
    nonce: crypto.randomBytes(32) });
  const casProof = await relay.catalogProbe({ scope: wireScope,
    nonce: crypto.randomBytes(32) });
  assert.equal((await z.decodeDeterministic(Buffer.from(witnessProof))).current_revision, 1);
  assert.equal((await z.decodeDeterministic(Buffer.from(casProof))).sequence, 0);
  assert.equal(witnessRequests, 1); assert.equal(casRequests, 1);
  // Model an unknown CAS write ACK: an independent authority may already
  // have advanced. Only the pinned mTLS fresh HEAD decides the outcome.
  const nextDigest = crypto.randomBytes(32);
  sequence = 1; currentDigest = nextDigest;
  const reconciled = await cas.reconcile({ scope, nonce: crypto.randomBytes(32),
    expectedSequence: 0, expectedDigest: Buffer.alloc(32), nextSequence: 1,
    nextDigest });
  assert.equal(reconciled.outcome, "CAS_COMMITTED_LOCAL_DURABLE");
  assert.equal(reconciled.localCatalogPublished, false);
  assert.equal(reconciled.remoteCloudDurabilityProven, false);
  const fresh = await z.decodeDeterministic(Buffer.from(await relay.catalogProbe({
    scope: wireScope, nonce: crypto.randomBytes(32) })));
  assert.equal(fresh.sequence, 1);
  await assert.rejects(createZk1OpaqueCatalogCasHttpsClient({
    ...tlsConfig("cas", casService), serverFingerprint256: "00:".repeat(31) + "00",
    authorityPublicKey: keys.cas.publicKey }).readHead({ scope,
    nonce: crypto.randomBytes(32) }), /ZK_OPAQUE_CAS_TRANSPORT_UNAVAILABLE/);
  await assert.rejects(createZk1WitnessHttpsClient({
    ...tlsConfig("witness", witnessService), clientKey: cert("foreign.key"),
    clientCert: cert("foreign.pem") }).freshHead({ scope,
    nonce: crypto.randomBytes(32) }), /WITNESS_TRANSPORT_UNAVAILABLE/);
});
