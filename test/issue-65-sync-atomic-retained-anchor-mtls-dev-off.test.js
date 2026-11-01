"use strict";

// REAL TLS 1.3/mTLS sockets, private native OpenSSL certificate fixtures,
// SQLite WAL/FULL anchor, and Ed25519. Still DEV-OFF and NOT physical custody.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const https = require("node:https");
const fs = require("node:fs");
const path = require("node:path");
const { Zk1SyncAtomicRetainedAnchorDevOff } = require(
  "../src/services/zk1SyncAtomicRetainedAnchorDevOff");
const { GENESIS } = require("../src/services/zk1SyncAtomicCasFloorLedgerDevOff");
const { createZk1SyncAtomicRetainedAnchorHttpsServerDevOff,
  createZk1SyncAtomicRetainedAnchorHttpsClientDevOff } = require(
  "../src/services/zk1SyncAtomicRetainedAnchorHttpsDevOff");
const { createPrivateAuthorityFixture } = require(
  "./support/issue-65-private-authority-fixture");
const { generateNativeFixtureCertificates } = require(
  "./support/issue-65-native-openssl-fixture");

const denied = { code: "SYNC_ATOMIC_RETAINED_HTTPS_DEV_OFF_DENIED" };
const nonce = () => crypto.randomBytes(32).toString("base64url");
const head = () => crypto.randomBytes(32).toString("hex");

async function fixture(t) {
  const dir = createPrivateAuthorityFixture("zk65-sync-v2-mtls-");
  generateNativeFixtureCertificates(dir, { caSubject: "Rootark Sync V2 Test CA",
    servers: ["anchor-server"], clients: ["reader", "writer", "outsider"] });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const certificate = (name) => read(`${name}.pem`);
  const ca = read("ca.pem");
  const fingerprint = (name) =>
    new crypto.X509Certificate(certificate(name)).fingerprint256.toUpperCase();
  const owner = { scope: "alice:protected", accountId: crypto.randomUUID(),
    storeId: crypto.randomUUID() };
  const signer = crypto.generateKeyPairSync("ed25519");
  const anchor = new Zk1SyncAtomicRetainedAnchorDevOff({
    filename: path.join(dir, "retained.sqlite"), bootstrapNew: true,
    ownerBindings: [owner], trustedMinimumHeads: [{ scope: owner.scope,
      sequence: 0, headHash: GENESIS }], signerPrivateKey: signer.privateKey,
  });
  const server = createZk1SyncAtomicRetainedAnchorHttpsServerDevOff({
    key: read("anchor-server.key"), cert: certificate("anchor-server"), clientCa: ca,
    anchor, principals: {
      [fingerprint("reader")]: [{ scope: owner.scope, canAdvance: false }],
      [fingerprint("writer")]: [{ scope: owner.scope, canAdvance: true }],
    },
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    anchor.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const base = { hostname: "127.0.0.1", servername: "localhost",
    port: server.address().port, ca,
    pinnedServerFingerprint: fingerprint("anchor-server"),
    anchorPublicKey: signer.publicKey };
  function client(role, overrides = {}) {
    return createZk1SyncAtomicRetainedAnchorHttpsClientDevOff({ ...base,
      cert: certificate(role), key: read(`${role}.key`), ...overrides });
  }
  return { dir, server, anchor, owner, signer, base, client,
    fingerprint, certificate, read };
}

test("real Sync v2 retained-anchor mTLS signs a fresh head and confirms durable CAS by second signed read", async (t) => {
  const f = await fixture(t);
  const reader = f.client("reader");
  const writer = f.client("writer");
  const challenge = nonce();
  const genesis = await reader.readSignedHead({ scope: f.owner.scope, nonce: challenge });
  assert.equal(genesis.statement.sequence, 0);
  assert.equal(genesis.statement.nonce, challenge);
  assert.equal(genesis.statement.headHash, GENESIS);
  assert.equal(Object.hasOwn(genesis.statement, "physicalDurable"), false);
  assert.equal(Object.hasOwn(genesis.statement, "clientAckAuthorized"), false);
  const next = head();
  assert.equal(await writer.compareAndAdvance({ scope: f.owner.scope,
    expectedSequence: 0, expectedHeadHash: GENESIS,
    sequence: 1, headHash: next }), true);
  assert.equal((await reader.readSignedHead({ scope: f.owner.scope,
    nonce: nonce() })).statement.headHash, next);
  assert.equal(await writer.compareAndAdvance({ scope: f.owner.scope,
    expectedSequence: 0, expectedHeadHash: GENESIS,
    sequence: 1, headHash: head() }), false,
  "a stale compare cannot overwrite a real signed retained head");
});

test("Sync v2 mTLS denies reader writes, unlisted certificates, and unauthorized scopes", async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.client("reader").compareAndAdvance({
    scope: f.owner.scope, expectedSequence: 0,
    expectedHeadHash: GENESIS, sequence: 1, headHash: head(),
  }), denied);
  await assert.rejects(f.client("outsider").readSignedHead({
    scope: f.owner.scope, nonce: nonce(),
  }), denied, "valid CA does not grant a client any operator role");
  await assert.rejects(f.client("writer").readSignedHead({
    scope: "mallory:foreign", nonce: nonce(),
  }), denied);
  assert.equal(f.anchor.readSignedHead({ scope: f.owner.scope,
    nonce: nonce() }).statement.sequence, 0,
  "no denied request may advance the owner CAS floor");
});

test("Sync v2 mTLS client requires pinned TLS server identity AND pinned Ed25519 receipt signer", async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.client("reader", {
    pinnedServerFingerprint: f.fingerprint("writer"),
  }).readSignedHead({ scope: f.owner.scope, nonce: nonce() }), denied);
  await assert.rejects(f.client("reader", {
    anchorPublicKey: crypto.generateKeyPairSync("ed25519").publicKey,
  }).readSignedHead({ scope: f.owner.scope, nonce: nonce() }), denied);
  // No client certificate: mutual TLS must fail before HTTP auth headers.
  await assert.rejects(new Promise((resolve, reject) => {
    const request = https.request({ hostname: "127.0.0.1", port: f.base.port,
      servername: "localhost", ca: f.base.ca, minVersion: "TLSv1.3",
      rejectUnauthorized: true, agent: false, method: "POST",
      path: "/v2/sync-atomic/retained/head" }, resolve);
    request.on("error", reject);
    request.end(JSON.stringify({ scope: f.owner.scope, nonce: nonce() }));
  }), "a client lacking a real mTLS certificate must not receive an HTTP receipt");
});

test("Sync v2 mTLS never accepts input injection or exposes a physical ACK endpoint", async (t) => {
  const f = await fixture(t);
  const client = f.client("writer");
  await assert.rejects(client.readSignedHead({ scope: f.owner.scope,
    nonce: nonce(), physicalDurable: true }), denied);
  await assert.rejects(client.compareAndAdvance({ scope: f.owner.scope,
    expectedSequence: 0, expectedHeadHash: GENESIS, sequence: 2,
    headHash: head() }), denied);
  await assert.rejects(client.compareAndAdvance({ scope: f.owner.scope,
    expectedSequence: 0, expectedHeadHash: GENESIS, sequence: 1,
    headHash: head(), clientAckAuthorized: true }), denied);
  assert.equal(f.anchor.readSignedHead({ scope: f.owner.scope,
    nonce: nonce() }).statement.sequence, 0);
});

test("Sync v2 mTLS bounds total elapsed time even when a pinned peer trickles HTTP bytes", async (t) => {
  const f = await fixture(t);
  const dripServer = https.createServer({
    key: f.read("anchor-server.key"), cert: f.certificate("anchor-server"),
    ca: f.base.ca, requestCert: true, rejectUnauthorized: true,
    minVersion: "TLSv1.3",
  }, (req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.write("{");
    // Every write refreshes Node's idle socket timeout, but must never
    // extend the client's total operation deadline.
    const drip = setInterval(() => {
      if (!res.destroyed) res.write(" ");
    }, 30);
    res.on("close", () => clearInterval(drip));
  });
  await new Promise((resolve, reject) => {
    dripServer.once("error", reject);
    dripServer.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    dripServer.closeAllConnections();
    await new Promise((resolve) => dripServer.close(resolve));
  });
  const reader = f.client("reader", { port: dripServer.address().port,
    timeoutMs: 350 });
  const started = Date.now();
  await assert.rejects(reader.readSignedHead({ scope: f.owner.scope,
    nonce: nonce() }), denied);
  assert.ok(Date.now() - started < 3000,
    "a continuously responsive peer must not defeat the total deadline");
});
