"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const crypto = require("node:crypto");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { signCommittedPhysicalReadback } =
  require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { createZk1ContentInventoryHttpsServer } =
  require("../src/services/zk1ContentInventoryHttpsServer");

const random = (n) => crypto.randomBytes(n);
const wire = (obj) => Object.fromEntries(Object.entries(obj).map(([field, value]) =>
  [field, Buffer.isBuffer(value) ? value.toString("base64url") : value]));

test("strict inventory mTLS append needs independent fresh physical Ed25519 readback before signing", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-inventory-attestor-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  generateNativeFixtureCertificates(dir, { caSubject: "ZK65 inventory attestor",
    servers: ["attestor"], clients: ["allowed"] });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const scope = { account_id: random(16), compartment_id: Buffer.from("vault"),
    keyring_id: random(16) };
  const operation = { operation_id: random(16), expected_sequence: 0,
    expected_root: random(32), object_id: random(16), revision: 1, epoch: 1,
    ciphertext_sha256: random(32) };
  const readback = { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
    walFlushConfirmed: true, generation: 2, admissionId: random(16),
    operationId: Buffer.from(operation.operation_id), revision: 1, epoch: 1,
    expectedInventorySequence: 0, expectedInventoryRoot: Buffer.from(operation.expected_root),
    digest: random(32), root: random(32), chunkCount: 1,
    ciphertextSha256: Buffer.from(operation.ciphertext_sha256),
    authorizesIo: false, provesIndependentOperator: false };
  const trusted = crypto.generateKeyPairSync("ed25519");
  const writer = crypto.generateKeyPairSync("ed25519");
  const issuer = async ({ scope: requestedScope, operation: requestedOp, nonce }, key) =>
    signCommittedPhysicalReadback({ scope: requestedScope, operation: requestedOp,
      readback, nonce, issuedAt: Math.floor(Date.now() / 1000) }, key);
  const ledger = { scope, publicKey: writer.publicKey, appendCount: 0,
    async append() { this.appendCount += 1; return { status: "pending", reason: "SEAL_UNCERTAIN" }; },
    async getOperationStatus() { return { status: "pending" }; },
    async getSnapshot() { return { status: "pending" }; } };
  const grant = { [new crypto.X509Certificate(read("allowed.pem")).fingerprint256]: {
    roles: ["append"], scopes: [wire(scope)] } };
  const post = async (port) => new Promise((resolve, reject) => {
    const body = JSON.stringify({ scope: wire(scope), operation: wire(operation),
      nonce: random(32).toString("base64url") });
    const request = https.request({ hostname: "localhost", port, path: "/v1/inventory/append",
      method: "POST", ca: read("ca.pem"), key: read("allowed.key"),
      cert: read("allowed.pem"), headers: { "content-type": "application/json",
        "content-length": Buffer.byteLength(body) } }, (response) => {
      const chunks = [];
      response.on("data", (part) => chunks.push(part));
      response.on("end", () => resolve({ status: response.statusCode,
        body: JSON.parse(Buffer.concat(chunks).toString("utf8")) }));
    });
    request.on("error", reject);
    request.end(body);
  });
  const serve = async (pin, client) => {
    const server = createZk1ContentInventoryHttpsServer({
      key: read("attestor.key"), cert: read("attestor.pem"), clientCa: read("ca.pem"),
      ledger, principals: grant, physicalAttestorClient: client,
      pinnedPhysicalAttestorPublicKey: pin,
      pinnedInventorySignerPublicKey: writer.publicKey });
    t.after(async () => {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(() => resolve()));
    });
    await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", (error) =>
      error ? reject(error) : resolve()));
    return server;
  };
  const client = { requestAttestation: (request) => issuer(request, trusted.privateKey) };
  assert.throws(() => createZk1ContentInventoryHttpsServer({
    key: read("attestor.key"), cert: read("attestor.pem"), clientCa: read("ca.pem"),
    ledger, principals: grant, physicalAttestorClient: client,
    pinnedPhysicalAttestorPublicKey: trusted.publicKey,
  }), /INVENTORY_HTTP_INVALID/, "strict mode needs an out-of-band inventory signer pin");
  assert.throws(() => createZk1ContentInventoryHttpsServer({
    key: read("attestor.key"), cert: read("attestor.pem"), clientCa: read("ca.pem"),
    ledger: { ...ledger, publicKey: trusted.publicKey }, principals: grant,
    physicalAttestorClient: client, pinnedPhysicalAttestorPublicKey: trusted.publicKey,
    pinnedInventorySignerPublicKey: trusted.publicKey,
  }), /INVENTORY_HTTP_INVALID/, "inventory signer may not masquerade as physical attestor");
  assert.throws(() => createZk1ContentInventoryHttpsServer({
    key: read("attestor.key"), cert: read("attestor.pem"), clientCa: read("ca.pem"),
    ledger: { ...ledger, publicKey: undefined }, principals: grant,
    physicalAttestorClient: client, pinnedPhysicalAttestorPublicKey: trusted.publicKey,
    pinnedInventorySignerPublicKey: writer.publicKey,
  }), /INVENTORY_HTTP_INVALID/, "strict mode needs a verifiable inventory signer identity");
  assert.throws(() => createZk1ContentInventoryHttpsServer({
    key: read("attestor.key"), cert: read("attestor.pem"), clientCa: read("ca.pem"),
    ledger: { ...ledger, publicKey: crypto.generateKeyPairSync("ed25519").publicKey },
    principals: grant, physicalAttestorClient: client,
    pinnedPhysicalAttestorPublicKey: trusted.publicKey,
    pinnedInventorySignerPublicKey: writer.publicKey,
  }), /INVENTORY_HTTP_INVALID/, "a facade cannot substitute a different inventory identity");
  const validServer = await serve(trusted.publicKey, client);
  const accepted = await post(validServer.address().port);
  assert.deepEqual(accepted, { status: 200, body: { status: "pending",
    reason: "SEAL_UNCERTAIN", operationId: operation.operation_id.toString("base64url") } });
  assert.equal(ledger.appendCount, 1);
  await new Promise((resolve) => validServer.close(resolve));

  const forgedClient = { requestAttestation: (request) => issuer(request, writer.privateKey) };
  const forgedServer = await serve(trusted.publicKey, forgedClient);
  const rejected = await post(forgedServer.address().port);
  assert.equal(rejected.status, 503);
  assert.equal(ledger.appendCount, 1, "writer key cannot advance inventory");
  await new Promise((resolve) => forgedServer.close(resolve));

  let captured;
  const replayClient = { async requestAttestation(request) {
    if (!captured) captured = await issuer(request, trusted.privateKey);
    return captured;
  } };
  const replayServer = await serve(trusted.publicKey, replayClient);
  assert.equal((await post(replayServer.address().port)).status, 200);
  assert.equal((await post(replayServer.address().port)).status, 503,
    "old attestation must not satisfy a fresh inventory challenge");
  assert.equal(ledger.appendCount, 2);
  await new Promise((resolve) => replayServer.close(resolve));
});
