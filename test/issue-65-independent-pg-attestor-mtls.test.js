"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { createZk1PgPhysicalAttestorHttpsClient } =
  require("../src/services/zk1PgPhysicalAttestorHttpsClient");
const { verifyCommittedPhysicalReadback } =
  require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { Zk1PgPhysicalInventoryBridge } = require("../src/services/zk1PgPhysicalInventoryBridge");
const { Zk1SharedPgCiphertextSink } = require("../src/services/zk1SharedPgCiphertextSink");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../src/services/zk1SharedPgPhysicalCiphertextVerifier");
const { Zk1SharedPgPhysicalInventoryIntent } =
  require("../src/services/zk1SharedPgPhysicalInventoryIntent");
const { Zk1DurableContentInventoryLedger } =
  require("../src/services/zk1DurableContentInventoryLedger");

const b64 = (b) => Buffer.from(b).toString("base64url");
const random = (n) => crypto.randomBytes(n);

test("separate-process mTLS attestor signs WAL readback, denies foreign principal/scope and stale pin", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-pg-attestor-mtls-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  generateNativeFixtureCertificates(dir, { caSubject: "ZK65 Physical Fixture",
    servers: ["attestor"], clients: ["allowed", "denied"] });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const signer = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: random(16), compartment_id: Buffer.from("vault"),
    keyring_id: random(16) };
  const operation = { operation_id: random(16), expected_sequence: 2,
    expected_root: random(32), object_id: random(16), revision: 4, epoch: 6,
    ciphertext_sha256: random(32) };
  const readback = { digest: random(32), root: random(32), chunks: 2 };
  const jsonScope = Object.fromEntries(Object.entries(scope).map(([k, v]) => [k, b64(v)]));
  const jsonOperation = Object.fromEntries(Object.entries(operation).map(([k, v]) =>
    [k, Buffer.isBuffer(v) ? b64(v) : v]));
  const cfg = { caPath: path.join(dir, "ca.pem"),
    serverKeyPath: path.join(dir, "attestor.key"),
    serverCertPath: path.join(dir, "attestor.pem"),
    signerKeyPath: path.join(dir, "signer.key"),
    allowedFingerprint: new crypto.X509Certificate(read("allowed.pem")).fingerprint256,
    scope: jsonScope, operation: jsonOperation,
    digest: b64(readback.digest), root: b64(readback.root), chunks: readback.chunks,
    readbackDelayMs: 300 };
  fs.writeFileSync(cfg.signerKeyPath,
    signer.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  const cfgPath = path.join(dir, "config.json");
  fs.writeFileSync(cfgPath, JSON.stringify(cfg), { mode: 0o600 });
  const child = spawn(process.execPath,
    [path.join(__dirname, "../lab/issue-65-packet-b/pg-physical-attestor-child.js"), cfgPath],
    { stdio: ["ignore", "pipe", "pipe", "ipc"], windowsHide: true,
      env: { ...process.env, NODE_ENV: "test" } });
  t.after(() => { if (!child.killed) child.kill(); });
  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("fixture child startup timed out")), 15000);
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error("fixture child exited " + code)));
    child.once("message", (message) => {
      clearTimeout(timer);
      if (!Number.isSafeInteger(message?.port) || message.port < 1) reject(new Error("bad child port"));
      else resolve(message.port);
    });
  });
  const endpoint = `https://localhost:${port}`;
  const base = { endpoint, ca: read("ca.pem"), clientKey: read("allowed.key"),
    clientCert: read("allowed.pem"),
    serverFingerprint256: new crypto.X509Certificate(read("attestor.pem")).fingerprint256,
    timeoutMs: 8000 };
  const client = createZk1PgPhysicalAttestorHttpsClient(base);
  const nonce = random(32);
  const raw = await client.requestAttestation({ scope, operation, nonce });
  const expected = { digest: readback.digest, root: readback.root, chunks: 2 };
  const pinned = { scope, operation, expected, nonce,
    pinnedPublicKey: signer.publicKey, nowSeconds: Math.floor(Date.now() / 1000) };
  const verified = await verifyCommittedPhysicalReadback(raw, pinned);
  assert.equal(verified.walFlushConfirmed, true);
  assert.equal(verified.authorizesIo, false);
  // A compromised authorized mTLS identity must not fan out into
  // unbounded concurrent PostgreSQL reads and WAL flush barriers.
  const concurrent = await Promise.allSettled([0, 1, 2].map(() =>
    client.requestAttestation({ scope, operation, nonce: random(32) })));
  assert.equal(concurrent.filter((item) => item.status === "fulfilled").length, 1);
  assert.equal(concurrent.filter((item) => item.status === "rejected").length, 2);
  // Exercise the actual inventory bridge across the HTTPS/process boundary,
  // while explicitly keeping the physical PG readback synthetic in this test.
  const mockOf = (Class) => Object.create(Class.prototype);
  const localVerifier = mockOf(Zk1SharedPgPhysicalCiphertextVerifier);
  localVerifier.verifyExact = () => { throw new Error("untrusted local verifier"); };
  const ledger = mockOf(Zk1DurableContentInventoryLedger);
  ledger.scope = scope;
  ledger.getOperationStatus = async () => ({ status: "pending" });
  const bridge = new Zk1PgPhysicalInventoryBridge({
    sink: mockOf(Zk1SharedPgCiphertextSink), verifier: localVerifier,
    intentAuthority: mockOf(Zk1SharedPgPhysicalInventoryIntent), ledger,
    pinnedPublicKey: crypto.generateKeyPairSync("ed25519").publicKey,
    pinnedSignerKeyId: random(16), attestorClient: client,
    pinnedPhysicalAttestorPublicKey: signer.publicKey,
  });
  assert.deepEqual(await bridge.reconcile({ scope, operation, digest: readback.digest,
    expectedRootHash: readback.root, expectedChunkCount: 2 }),
  { status: "pending", authorizesIo: false });
  await assert.rejects(verifyCommittedPhysicalReadback(raw,
    { ...pinned, nonce: random(32) }), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  await assert.rejects(verifyCommittedPhysicalReadback(raw,
    { ...pinned, pinnedPublicKey: crypto.generateKeyPairSync("ed25519").publicKey }),
  /ZK_PHYSICAL_ATTESTATION_DENIED/);
  await assert.rejects(client.requestAttestation({ scope: { ...scope,
    keyring_id: random(16) }, operation, nonce: random(32) }), /ZK_PHYSICAL_ATTESTOR_TRANSPORT_UNAVAILABLE/);
  const stranger = createZk1PgPhysicalAttestorHttpsClient({ ...base,
    clientKey: read("denied.key"), clientCert: read("denied.pem") });
  await assert.rejects(stranger.requestAttestation({ scope, operation, nonce: random(32) }),
  /ZK_PHYSICAL_ATTESTOR_TRANSPORT_UNAVAILABLE/);
  const wrongPeer = createZk1PgPhysicalAttestorHttpsClient({ ...base,
    serverFingerprint256: new crypto.X509Certificate(read("denied.pem")).fingerprint256 });
  await assert.rejects(wrongPeer.requestAttestation({ scope, operation, nonce: random(32) }),
  /ZK_PHYSICAL_ATTESTOR_TRANSPORT_UNAVAILABLE/);
});
