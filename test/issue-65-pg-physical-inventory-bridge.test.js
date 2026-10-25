"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const https = require("node:https");
const { Readable } = require("node:stream");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { Pool } = require("pg");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedPgSealedObjectStore } = require("../src/services/zk1SharedPgSealedObjectStore");
const { Zk1SharedPgCiphertextSink } = require("../src/services/zk1SharedPgCiphertextSink");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../src/services/zk1SharedPgPhysicalCiphertextVerifier");
const { Zk1SharedPgPhysicalInventoryIntent } =
  require("../src/services/zk1SharedPgPhysicalInventoryIntent");
const { Zk1DurableContentInventoryLedger } =
  require("../src/services/zk1DurableContentInventoryLedger");
const { Zk1PgPhysicalInventoryBridge } =
  require("../src/services/zk1PgPhysicalInventoryBridge");
const { createCloudStorage } = require("../services/cloudStorage");
const { Zk1CloudCiphertextReadbackVerifier, zk1CloudCopyAddress } =
  require("../src/services/zk1CloudCiphertextReadbackVerifier");
const { Zk1CloudCiphertextCopyPublisher } =
  require("../src/services/zk1CloudCiphertextCopyPublisher");
const { createZk1ContentInventoryHttpsServer,
  drainZk1ContentInventoryHttpsServer } =
  require("../src/services/zk1ContentInventoryHttpsServer");
const { createZk1ContentInventoryHttpsClient } =
  require("../src/services/zk1ContentInventoryHttpsClient");
const { createZk1PgPhysicalAttestorHttpsClient } =
  require("../src/services/zk1PgPhysicalAttestorHttpsClient");
const { verifyCommittedPhysicalReadback } =
  require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { Zk1WitnessCasPhysicalAdmission } =
  require("../src/services/zk1WitnessCasPhysicalAdmission");
const { Zk1WitnessCasAnchorFloor, verifyFreshWitnessCasFloor } =
  require("../src/services/zk1WitnessCasAnchorFloor");
const { Zk1CasTerminalAnchor } =
  require("../src/services/zk1CasTerminalAnchor");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");

const enabled = Boolean(process.env.ROOTARK_ZK1_TEST_PG_URL
  && process.env.ROOTARK_ZK1_RUNTIME_PG_URL
  && process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);

test("real PG18 child read-only attestor binds strict mTLS signed chain across restart", {
  skip: !enabled && "requires isolated PostgreSQL 18 and distinct restricted SQL roles",
}, async (t) => {
  const f = await fixture(t);
  const minimumHead = await f.ledger.readLocalHead();
  const minimumSnapshot = (await f.ledger.getSnapshot({ nonce: crypto.randomBytes(32) })).bytes;
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-real-pg-attestor-chain-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  generateNativeFixtureCertificates(dir, { caSubject: "ZK65 real PG18 chain lab",
    servers: ["attestor", "inventory"], clients: ["inventory-service", "reader", "witness"] });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const physicalSigner = crypto.generateKeyPairSync("ed25519");
  assert.equal(crypto.KeyObject.prototype.equals.call(physicalSigner.publicKey,
    f.keys.publicKey), false);
  fs.writeFileSync(path.join(dir, "physical-signer.key"),
    physicalSigner.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  const wireScope = Object.fromEntries(Object.entries(f.scope).map(([key, value]) =>
    [key, value.toString("base64url")]));
  const wireOperation = Object.fromEntries(Object.entries(f.op).map(([key, value]) =>
    [key, Buffer.isBuffer(value) ? value.toString("base64url") : value]));
  const cfg = { useRealPg: true, scope: wireScope, operation: wireOperation,
    digest: f.digest.toString("base64url"), root: f.root.toString("base64url"),
    chunks: f.chunks.length, caPath: path.join(dir, "ca.pem"),
    serverKeyPath: path.join(dir, "attestor.key"),
    serverCertPath: path.join(dir, "attestor.pem"),
    signerKeyPath: path.join(dir, "physical-signer.key"),
    allowedFingerprint: new crypto.X509Certificate(read("inventory-service.pem")).fingerprint256,
    additionalFingerprint: new crypto.X509Certificate(read("witness.pem")).fingerprint256 };
  const cfgPath = path.join(dir, "child.json");
  fs.writeFileSync(cfgPath, JSON.stringify(cfg), { mode: 0o600 });
  const child = spawn(process.execPath,
    [path.join(__dirname, "../lab/issue-65-packet-b/pg-physical-attestor-child.js"), cfgPath],
    { stdio: ["ignore", "ignore", "pipe", "ipc"], windowsHide: true,
      env: { NODE_ENV: "test", PATH: process.env.PATH,
        SystemRoot: process.env.SystemRoot,
        ROOTARK_ZK1_ATTESTOR_PG_URL: process.env.ROOTARK_ZK1_ATTESTOR_PG_URL } });
  t.after(async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const exited = new Promise((resolve) => child.once("exit", resolve));
    child.kill("SIGTERM");
    const timer = setTimeout(() => child.kill("SIGKILL"), 5000);
    try { await exited; } finally { clearTimeout(timer); }
  });
  let childError = "";
  child.stderr.on("data", (bytes) => {
    childError = (childError + bytes.toString()).slice(-1024);
  });
  const physicalPort = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("real PG attestor child timeout")), 15000);
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`real PG attestor child exited ${code}: ${childError}`)));
    child.once("message", (message) => {
      clearTimeout(timer);
      if (!Number.isSafeInteger(message?.port) || message.port < 1) reject(new Error("invalid attestor port"));
      else resolve(message.port);
    });
  });
  const attestorClient = createZk1PgPhysicalAttestorHttpsClient({
    endpoint: `https://localhost:${physicalPort}`, ca: read("ca.pem"),
    clientKey: read("inventory-service.key"), clientCert: read("inventory-service.pem"),
    serverFingerprint256: new crypto.X509Certificate(read("attestor.pem")).fingerprint256,
  });
  const nonce = crypto.randomBytes(32);
  const physical = await attestorClient.requestAttestation({
    scope: f.scope, operation: f.op, nonce });
  const verifiedPhysical = await verifyCommittedPhysicalReadback(physical, {
    scope: f.scope, operation: f.op, expected: {
      digest: f.digest, root: f.root, chunks: f.chunks.length }, nonce,
    pinnedPublicKey: physicalSigner.publicKey,
    nowSeconds: Math.floor(Date.now() / 1000),
  });
  assert.equal(verifiedPhysical.walFlushConfirmed, true);
  await assert.rejects(verifyCommittedPhysicalReadback(physical, {
    scope: f.scope, operation: f.op, expected: undefined,
    nonce: crypto.randomBytes(32), pinnedPublicKey: physicalSigner.publicKey,
    nowSeconds: Math.floor(Date.now() / 1000),
  }), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  let server;
  const startInventory = async () => {
    server = createZk1ContentInventoryHttpsServer({
      key: read("inventory.key"), cert: read("inventory.pem"), clientCa: read("ca.pem"),
      ledger: f.ledger, physicalAttestorClient: attestorClient,
      pinnedPhysicalAttestorPublicKey: physicalSigner.publicKey,
      pinnedInventorySignerPublicKey: f.keys.publicKey,
      principals: { [new crypto.X509Certificate(read("reader.pem")).fingerprint256]: {
        roles: ["read", "status"], scopes: [wireScope] } },
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    return createZk1ContentInventoryHttpsClient({
      endpoint: `https://localhost:${server.address().port}`, ca: read("ca.pem"),
      clientKey: read("reader.key"), clientCert: read("reader.pem"),
      serverFingerprint256: new crypto.X509Certificate(read("inventory.pem")).fingerprint256,
      inventoryPublicKey: f.keys.publicKey, inventorySignerKeyId: f.signerKeyId,
      physicalAttestorPublicKey: physicalSigner.publicKey,
    });
  };
  t.after(async () => { if (server?.listening) await drainZk1ContentInventoryHttpsServer(server); });
  const input = { scope: f.scope, nonce: crypto.randomBytes(32),
    requested: { object_id: f.op.object_id, revision: f.op.revision,
      epoch: f.op.epoch, ciphertext_sha256: f.op.ciphertext_sha256 },
    minimumHead, minimumSnapshot, includeVerifiedProofChain: true };
  let reader = await startInventory();
  const first = await reader.getVerifiedSnapshotWithChain(input);
  assert.equal(first.independentPhysicalChainVerified, true);
  assert.equal(first.authenticatedProofChain.length, 1);
  assert.equal(first.authenticatedPhysicalProofChain.length, 1);
  const status = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const owner = crypto.generateKeyPairSync("ed25519");
  const statusKeyId = crypto.randomBytes(16);
  const witnessKeyId = crypto.randomBytes(16);
  const anchor = new Zk1CasTerminalAnchor(path.join(dir, "cas-anchor.log"), {
    bootstrapNew: true, statusKeyId, statusPrivateKey: status.privateKey });
  const reservation = crypto.randomBytes(16);
  const query = { ...f.scope, reservation_id: reservation };
  const ticket = crypto.randomBytes(80), manifest = crypto.randomBytes(120);
  anchor.prepare(query, ticket, "committed", manifest);
  await anchor.append(query, ticket, "committed", manifest, crypto.randomBytes(64));
  const record = fs.readFileSync(anchor.filename, "utf8").trimEnd().split("\n").at(-1);
  const recordHash = crypto.createHash("sha256").update(record).digest("hex");
  const admissionScope = f.scope.account_id.toString("hex") + ":"
    + f.scope.compartment_id.length + ":" + f.scope.compartment_id.toString("hex")
    + ":" + f.scope.keyring_id.toString("hex");
  const committed = await f.ledger.getOperationStatus(f.op.operation_id);
  assert.equal(committed.status, "committed");
  const binding = { recordHash, scope: wireScope, operation: wireOperation,
    inventoryReceipt: committed.proof.toString("base64url") };
  const evidence = { ...binding, ownerSignature: crypto.sign(null,
    Buffer.concat([Buffer.from("Root.ark/zk-1/cas-witness-physical-owner-binding/v1\0"),
      Buffer.from(JSON.stringify(binding))]), owner.privateKey).toString("base64url") };
  const witnessAttestorClient = createZk1PgPhysicalAttestorHttpsClient({
    endpoint: `https://localhost:${physicalPort}`, ca: read("ca.pem"),
    clientKey: read("witness.key"), clientCert: read("witness.pem"),
    serverFingerprint256: new crypto.X509Certificate(read("attestor.pem")).fingerprint256,
  });
  const unauthorizedAttestorClient = createZk1PgPhysicalAttestorHttpsClient({
    endpoint: `https://localhost:${physicalPort}`, ca: read("ca.pem"),
    clientKey: read("reader.key"), clientCert: read("reader.pem"),
    serverFingerprint256: new crypto.X509Certificate(read("attestor.pem")).fingerprint256,
  });
  await assert.rejects(unauthorizedAttestorClient.requestAttestation({
    scope: f.scope, operation: f.op, nonce: crypto.randomBytes(32),
  }), /ZK_PHYSICAL_ATTESTOR_TRANSPORT_UNAVAILABLE/,
  "a reader mTLS identity cannot challenge the independent PG attestor");
  const admission = new Zk1WitnessCasPhysicalAdmission({
    pinnedOwnerPublicKey: owner.publicKey,
    pinnedInventoryPublicKey: f.keys.publicKey,
    pinnedInventorySignerKeyId: f.signerKeyId,
    pinnedPhysicalAttestorPublicKey: physicalSigner.publicKey,
    physicalAttestorClient: witnessAttestorClient, inventoryClient: reader,
    trustedMinimumInventoryHead: minimumHead,
    trustedMinimumInventorySnapshot: minimumSnapshot,
  });
  const floorPath = path.join(dir, "witness-floor.sqlite");
  let floor = new Zk1WitnessCasAnchorFloor(floorPath, {
    bootstrapNew: true, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission });
  t.after(() => floor.close());
  const witnessed = await floor.advanceAttested({ records: [record], evidence: [evidence] });
  assert.equal(witnessed.sequence, 1,
    "independently challenged real PG readback must precede witness floor advance");
  const witnessNonce = crypto.randomBytes(32);
  const checkedFloor = verifyFreshWitnessCasFloor({
    signed: floor.freshHead({ nonce: witnessNonce }), nonce: witnessNonce,
    pinnedWitnessPublicKey: witness.publicKey,
    pinnedWitnessKeyId: witnessKeyId, pinnedStatusKeyId: statusKeyId,
    requirePhysicalAdmission: true,
  });
  floor.close();
  assert.throws(() => new Zk1WitnessCasAnchorFloor(floorPath, {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "restart cannot trust the on-disk SQLite floor as its own rollback oracle");
  floor = new Zk1WitnessCasAnchorFloor(floorPath, {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission,
    trustedMinimumHead: { ...witnessed,
      physicalFenceDigest: checkedFloor.physicalFenceDigest },
  });
  assert.deepEqual(floor.head(), witnessed);
  await drainZk1ContentInventoryHttpsServer(server);
  await f.restart();
  reader = await startInventory();
  const again = await reader.getVerifiedSnapshotWithChain({
    ...input, nonce: crypto.randomBytes(32) });
  assert.equal(again.independentPhysicalChainVerified, true);
  assert.equal(again.authenticatedPhysicalProofChain.length, 1);
  assert.notDeepEqual(again.authenticatedPhysicalProofChain[0],
    first.authenticatedPhysicalProofChain[0], "restart must re-read PG under a new challenge");
});

async function fixture(t, { strictPhysicalIntent = true } = {}) {
  const admin = new Pool({ connectionString: process.env.ROOTARK_ZK1_TEST_PG_URL,
    max: 2, connectionTimeoutMillis: 2500 });
  const gatePool = new Pool({ connectionString: process.env.ROOTARK_ZK1_RUNTIME_PG_URL,
    max: 2, connectionTimeoutMillis: 2500 });
  // A separate PG connection pool independently re-reads the physically
  // committed ciphertext; it has no INSERT/UPDATE/DELETE privileges.
  const proofPool = new Pool({ connectionString: process.env.ROOTARK_ZK1_ATTESTOR_PG_URL,
    max: 2, connectionTimeoutMillis: 2500 });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-physical-inventory-"));
  const dbPath = path.join(dir, "signed-inventory.sqlite");
  const keys = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = crypto.randomBytes(16);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(8), keyring_id: crypto.randomBytes(16) };
  const digest = crypto.randomBytes(32);
  const key = scope.account_id.toString("hex") + ":"
    + scope.compartment_id.length.toString(16) + ":" + scope.compartment_id.toString("hex");
  await admin.query(`INSERT INTO zk1_gate.head
    (scope_key,keyring_id,revision,digest,require_physical_inventory_intent)
    VALUES($1,$2,1,$3,$4)`,
    [key, scope.keyring_id, digest, strictPhysicalIntent]);
  let ledger = await Zk1DurableContentInventoryLedger.open(dbPath, {
    bootstrapNew: true, signerKeyId, signerPrivateKey: keys.privateKey, scope,
  });
  const gate = new Zk1SharedPgGateAuthority({ pool: gatePool });
  const sealedStore = new Zk1SharedPgSealedObjectStore({ pool: gatePool });
  const calls = [];
  const principal = "physical-inventory-lab";
  const gateClient = {
    beginIoAdmission: async (op) => {
      calls.push("begin");
      return gate.beginIoAdmission({ ...op, principal });
    },
    putCiphertextChunk: async (op, index, bytes) => {
      calls.push("chunk");
      return gate.putCiphertextChunk({ ...op, principal }, index, bytes);
    },
    sealCiphertextObject: async (op, count, root) => {
      calls.push("seal");
      return sealedStore.seal({ ...op, principal, expectedChunkCount: count,
        expectedRootHash: root });
    },
    finishIoAdmission: async (op) => {
      calls.push("finish");
      return gate.finishIoAdmission({ ...op, principal });
    },
  };
  const verifier = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: proofPool });
  const intentAuthority = new Zk1SharedPgPhysicalInventoryIntent({ pool: gatePool });
  const sink = new Zk1SharedPgCiphertextSink({ gateClient });
  const bridge = (trustedInventoryFloor) => new Zk1PgPhysicalInventoryBridge({
    sink, verifier, intentAuthority, ledger, pinnedPublicKey: keys.publicKey,
    pinnedSignerKeyId: signerKeyId, trustedInventoryFloor });
  t.after(async () => {
    try { ledger.close(); } catch (_) {}
    await Promise.all([admin.end(), gatePool.end(), proofPool.end()]);
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 });
  });
  const chunks = [crypto.randomBytes(100), crypto.randomBytes(66)];
  const objectId = crypto.randomBytes(16);
  const ciphertext = Buffer.concat(chunks);
  const root = computeZk1CiphertextRoot(chunks);
  const op = { operation_id: crypto.randomBytes(16), expected_sequence: 0,
    expected_root: (await ledger.readLocalHead()).root,
    object_id: objectId, revision: 1, epoch: 1,
    ciphertext_sha256: crypto.createHash("sha256").update(ciphertext).digest() };
  const physical = { scope, operation: op, digest, chunks,
    expectedRootHash: root, expectedChunkCount: chunks.length };
  const noChunks = () => ({ scope, operation: op, digest,
    expectedRootHash: root, expectedChunkCount: chunks.length });
  return { admin, gate, gatePool, proofPool, intentAuthority, sealedStore, calls, verifier, bridge,
    physical, noChunks,
    scope, key, op, root, chunks, digest, keys, signerKeyId, restart: async () => {
      ledger.close();
      ledger = await Zk1DurableContentInventoryLedger.open(dbPath, {
        bootstrapNew: false, signerKeyId, signerPrivateKey: keys.privateKey, scope,
      });
      return bridge();
    }, get ledger() { return ledger; } };
}

test("real PostgreSQL seal is physically reread before exact Ed25519 inventory commit, replay survives restart", {
  skip: !enabled && "requires a disposable restricted PG18 gate fixture",
}, async (t) => {
  const f = await fixture(t);
  const result = await f.bridge().putAndAttest(f.physical);
  assert.equal(result.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  assert.equal(result.authorizesIo, false);
  assert.equal(result.externalProviderDurabilityProven, false);
  assert.equal(result.localPgWalFlushConfirmed, true);
  assert.equal(result.independentlyAnchoredFloorProven, false);
  assert.deepEqual(result.verifiedReceipt.operationId, f.op.operation_id);
  const bound = await f.admin.query(`SELECT operation_id,expected_inventory_root,
    expected_inventory_sequence,ciphertext_sha256,expected_root_hash
    FROM zk1_gate.physical_inventory_intent WHERE scope_key=$1 AND object_id=$2`,
  [f.key, f.op.object_id.toString("base64url")]);
  assert.equal(bound.rowCount, 1);
  assert.deepEqual(bound.rows[0].operation_id, f.op.operation_id);
  assert.deepEqual(bound.rows[0].ciphertext_sha256, f.op.ciphertext_sha256);
  assert.deepEqual(result.verifiedReceipt.tuple.ciphertext_sha256, f.op.ciphertext_sha256);
  assert.deepEqual(f.calls, ["begin", "chunk", "chunk", "seal", "finish"]);
  const exactRow = await f.admin.query(`SELECT root_hash,generation,expected_chunks
    FROM zk1_gate.sealed_object WHERE scope_key=$1 AND object_id=$2`,
  [f.key, f.op.object_id.toString("base64url")]);
  assert.equal(exactRow.rowCount, 1);
  assert.deepEqual(exactRow.rows[0].root_hash, f.root);
  assert.equal(exactRow.rows[0].expected_chunks, 2);
  const again = await f.bridge().putAndAttest(f.physical);
  assert.equal(again.status, result.status);
  assert.deepEqual(f.calls, ["begin", "chunk", "chunk", "seal", "finish"],
    "an exact signed replay must never launch a new physical PUT admission");
  const restarted = await f.restart();
  const recovered = await restarted.reconcile(f.noChunks());
  assert.equal(recovered.status, result.status);
  assert.equal(recovered.sequence, result.sequence);
  assert.deepEqual(recovered.root, result.root);
  await assert.rejects(restarted.reconcile({ ...f.noChunks(),
    operation: { ...f.op, operation_id: crypto.randomBytes(16) } }),
  /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "a different operation ID now fails at the durable physical prewrite binding");
});

test("non-strict legacy scopes refuse signed physical bridge before any physical write", {
  skip: !enabled && "requires disposable PostgreSQL 18 and restricted runtime",
}, async (t) => {
  const f = await fixture(t, { strictPhysicalIntent: false });
  await assert.rejects(f.bridge().putAndAttest(f.physical),
    /ZK_PHYSICAL_INTENT_UNAVAILABLE/,
    "opt-in physical intent is mandatory before a bridge opens any PUT admission");
  assert.deepEqual(f.calls, [], "legacy scope denial cannot touch the physical writer");
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown");
  const objectId = f.op.object_id.toString("base64url");
  for (const table of ["physical_inventory_intent", "physical_inventory_admission",
    "ciphertext_chunk", "sealed_object"]) {
    const result = await f.admin.query(`SELECT COUNT(*)::int AS count
      FROM zk1_gate.${table} WHERE scope_key=$1 AND object_id=$2`, [f.key, objectId]);
    assert.equal(result.rows[0].count, 0, `non-strict scope must not create ${table}`);
  }
});

test("PG signed inventory bridge requires the pinned owner floor and complete signed intervening history", {
  skip: !enabled && "requires real disposable PostgreSQL 18 and restricted attestor",
}, async (t) => {
  const f = await fixture(t);
  const genesis = await f.ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const trustedFloor = { minimumHead: { sequence: 0,
    root: Buffer.from(f.op.expected_root) }, minimumSnapshot: Buffer.from(genesis.bytes) };
  const bridge = f.bridge(trustedFloor);
  // Floor is copied at construction; caller-owned arrays cannot be rewritten
  // asynchronously to downgrade the pinned rollback boundary.
  trustedFloor.minimumHead.root.fill(0xaa);
  trustedFloor.minimumSnapshot.fill(0xbb);
  bridge.trustedInventoryFloor = undefined;
  bridge._trustedInventoryFloor = null;
  assert.equal(Object.hasOwn(bridge, "trustedInventoryFloor"), true,
    "a synthetic public shadow does not retarget the private trusted floor");
  const first = await bridge.putAndAttest(f.physical);
  assert.equal(first.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const laterOp = { ...f.op, object_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), expected_sequence: first.sequence,
    expected_root: Buffer.from(first.root) };
  const later = await bridge.putAndAttest({ ...f.physical, operation: laterOp });
  assert.equal(later.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  assert.equal(later.sequence, 2);
  const originalPage = f.ledger.getCommittedProofPage.bind(f.ledger);
  f.ledger.getCommittedProofPage = async (input) => {
    const page = await originalPage(input);
    if (page.status !== "chain_page" || page.proofs.length === 0) return page;
    const forged = Buffer.from(page.proofs[0]);
    forged[forged.length - 1] ^= 0x01;
    return { ...page, proofs: [forged, ...page.proofs.slice(1)] };
  };
  await assert.rejects(bridge.reconcile({ scope: f.scope, operation: laterOp,
    digest: f.digest, expectedRootHash: f.root, expectedChunkCount: f.chunks.length }),
  /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "a gap or forged history cannot cross a pinned owner floor even if PG bytes match");
  f.ledger.getCommittedProofPage = originalPage;
  const recovered = await bridge.reconcile({ scope: f.scope, operation: laterOp,
    digest: f.digest, expectedRootHash: f.root, expectedChunkCount: f.chunks.length });
  assert.equal(recovered.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
});

test("PG owner floor refuses reverted or foreign inventory before any physical intent or PUT", {
  skip: !enabled && "requires disposable PostgreSQL 18 and restricted attestor",
}, async (t) => {
  const f = await fixture(t);
  const base = await f.ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  for (const head of [
    { sequence: 1, root: crypto.randomBytes(32) },
    { sequence: 0, root: crypto.randomBytes(32) },
  ]) {
    const bridge = f.bridge({ minimumHead: head,
      minimumSnapshot: base.bytes });
    await assert.rejects(bridge.putAndAttest(f.physical),
      /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  }
  assert.deepEqual(f.calls, [], "stale/foreign owner floor must deny before worker admission");
  const count = await f.admin.query(`SELECT COUNT(*)::integer AS n
    FROM zk1_gate.physical_inventory_intent WHERE scope_key=$1`, [f.key]);
  assert.equal(count.rows[0].n, 0, "no physical reservation after floor denial");
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown");
});

test("signed PG ciphertext and separately pinned cloud GET must both match exact immutable operation", {
  skip: !enabled && "requires disposable PostgreSQL 18 and fake S3 readback",
}, async (t) => {
  const f = await fixture(t);
  const signed = await f.bridge().putAndAttest(f.physical);
  assert.equal(signed.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const addr = zk1CloudCopyAddress({ scope: f.scope, operationId: f.op.operation_id });
  let remote = Buffer.concat(f.chunks);
  let readerPrincipal = "cloud-readback-pinned-fixture-A";
  let reads = 0;
  let mutateLocalAfterCloudStart = false;
  const cloudReader = createCloudStorage({
    provider: "s3", prefix: "rootark-physical-pg-fixture", s3: { bucket: "readback-fixture" },
    resolvePrincipalIdentity: async () => readerPrincipal,
    createS3Client: async () => ({ send: async (cmd) => {
      reads += 1;
      if (cmd.constructor.name !== "GetObjectCommand"
        || cmd.input.Key !== cloudReader.key(addr.folder, addr.name, "uploads")
        || !remote) throw new Error("missing expected opaque cloud object");
      if (mutateLocalAfterCloudStart) {
        mutateLocalAfterCloudStart = false;
        await f.admin.query(`UPDATE zk1_gate.ciphertext_chunk SET ciphertext=$1
          WHERE scope_key=$2 AND object_id=$3 AND chunk_index=0`,
        [crypto.randomBytes(f.chunks[0].length), f.key, f.op.object_id.toString("base64url")]);
      }
      return { Body: Readable.from([remote]) };
    } }),
  });
  const expectedReaderContext = await cloudReader.resolveInventoryContext();
  const cloudVerifier = new Zk1CloudCiphertextReadbackVerifier({
    cloudReader, expectedProvider: "s3", expectedReaderContext,
  });
  const args = { physical: f.noChunks(), cloudVerifier,
    chunkLengths: f.chunks.map((chunk) => chunk.length) };
  const result = await f.bridge().reconcileCloudCopy(args);
  assert.equal(result.status, "PG_SIGNED_AND_CLOUD_BYTES_REREAD");
  assert.equal(result.remoteReadbackMatched, true);
  assert.equal(result.localPgWalFlushConfirmed, true);
  assert.equal(result.externalProviderDurabilityProven, false);
  assert.equal(result.authorizesIo, false);
  assert.ok(reads > 0);
  // Two valid signed physical operations must never be mixed by an input
  // mutated after the cloud reconciliation captured its exact operation A.
  const other = { ...f.op, object_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), expected_sequence: signed.sequence,
    expected_root: Buffer.from(signed.root) };
  assert.equal((await f.bridge().putAndAttest({ ...f.physical, operation: other })).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const changingPhysical = f.noChunks();
  const observedOperations = [];
  const physicalVerifier = f.verifier.verifyExact.bind(f.verifier);
  f.verifier.verifyExact = async (input) => {
    observedOperations.push(Buffer.from(input.operationId));
    return physicalVerifier(input);
  };
  const changingLengths = new Proxy(f.chunks.map((chunk) => chunk.length), {
    get(target, key, receiver) {
      if (key === "length") changingPhysical.operation = other;
      return Reflect.get(target, key, receiver);
    },
  });
  const pinned = await f.bridge().reconcileCloudCopy({
    physical: changingPhysical, cloudVerifier, chunkLengths: changingLengths,
  });
  assert.deepEqual(pinned.operationId, f.op.operation_id);
  assert.ok(observedOperations.length >= 2);
  assert.ok(observedOperations.every((operationId) => operationId.equals(f.op.operation_id)),
    "both fresh PG proofs must authenticate original operation A, never mutated operation B");
  f.verifier.verifyExact = physicalVerifier;
  remote = crypto.randomBytes(remote.length);
  await assert.rejects(f.bridge().reconcileCloudCopy(args),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "a valid historical signed receipt cannot certify a corrupted external copy");
  remote = Buffer.concat(f.chunks);
  readerPrincipal = "cloud-readback-different-principal";
  await assert.rejects(f.bridge().reconcileCloudCopy(args),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  readerPrincipal = "cloud-readback-pinned-fixture-A";
  mutateLocalAfterCloudStart = true;
  await assert.rejects(f.bridge().reconcileCloudCopy(args),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "a locally corrupted ciphertext between initial PG proof and remote GET must be denied by the final PG reread");
  await f.admin.query(`UPDATE zk1_gate.ciphertext_chunk SET ciphertext=$1
    WHERE scope_key=$2 AND object_id=$3 AND chunk_index=0`,
  [f.chunks[0], f.key, f.op.object_id.toString("base64url")]);
  await f.admin.query(`UPDATE zk1_gate.ciphertext_chunk SET ciphertext=$1
    WHERE scope_key=$2 AND object_id=$3 AND chunk_index=0`,
  [crypto.randomBytes(f.chunks[0].length), f.key, f.op.object_id.toString("base64url")]);
  const before = reads;
  await assert.rejects(f.bridge().reconcileCloudCopy(args),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "a bad local physical seal must deny before contacting a cloud reader");
  assert.equal(reads, before);
});

test("real sealed PG operation permits only nonauthorizing bounded S3 PUT plus independent GET replay", {
  skip: !enabled && "requires disposable PostgreSQL 18 and synthetic cloud GET/PUT",
}, async (t) => {
  const f = await fixture(t);
  const cloud = new Map();
  let puts = 0;
  let gets = 0;
  let tamperRemotePut = false;
  const makeStore = (principal) => createCloudStorage({
    provider: "s3", prefix: "rootark-physical-put-fixture",
    s3: { bucket: "disposable-sealed-copy" },
    resolvePrincipalIdentity: async () => principal,
    createS3Client: async () => ({ send: async (cmd) => {
      assert.equal(cmd.input.Bucket, "disposable-sealed-copy");
      if (cmd.constructor.name === "PutObjectCommand") {
        puts += 1;
        const bytes = [];
        if (Buffer.isBuffer(cmd.input.Body)) bytes.push(Buffer.from(cmd.input.Body));
        else for await (const chunk of cmd.input.Body) bytes.push(Buffer.from(chunk));
        const combined = Buffer.concat(bytes);
        assert.equal(cmd.input.ContentLength, combined.length);
        cloud.set(cmd.input.Key, tamperRemotePut ? Buffer.alloc(combined.length, 0x3a) : combined);
        return { ETag: '"fixture-etag-nonproof"' };
      }
      if (cmd.constructor.name === "GetObjectCommand") {
        gets += 1;
        const contents = cloud.get(cmd.input.Key);
        if (!contents) throw new Error("cloud object missing");
        return { Body: Readable.from([contents]) };
      }
      throw new Error("must not invoke delete/list/permission changes");
    } }),
  });
  const writer = makeStore("scoped-copy-writer");
  const reader = makeStore("distinct-scoped-copy-reader");
  const cloudPublisher = new Zk1CloudCiphertextCopyPublisher({ cloudWriter: writer,
    expectedProvider: "s3", expectedWriterContext: await writer.resolveInventoryContext() });
  const cloudVerifier = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: reader,
    expectedProvider: "s3", expectedReaderContext: await reader.resolveInventoryContext() });
  const args = { physical: f.noChunks(), chunks: f.chunks, cloudPublisher, cloudVerifier };
  await assert.rejects(f.bridge().publishAndReconcileCloudCopy(args),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "no external PUT can start before the PG operation has a signed sealed receipt");
  assert.equal(puts, 0);
  await f.bridge().putAndAttest(f.physical);
  const copied = await f.bridge().publishAndReconcileCloudCopy(args);
  assert.equal(copied.status, "PG_SIGNED_AND_EXTERNAL_COPY_REREAD");
  assert.deepEqual(copied.operationId, f.op.operation_id);
  assert.equal(copied.authorizesIo, false);
  assert.equal(copied.externalProviderDurabilityProven, false);
  assert.equal(copied.independentRemoteIoFenceProven, false);
  assert.equal(copied.byteLength, Buffer.concat(f.chunks).length);
  assert.equal(puts, 1);
  assert.ok(gets >= 1);
  const addr = zk1CloudCopyAddress({ scope: f.scope, operationId: f.op.operation_id });
  assert.deepEqual(cloud.get(writer.key(addr.folder, addr.name, "uploads")),
    Buffer.concat(f.chunks));
  await assert.rejects(f.bridge().publishAndReconcileCloudCopy({ ...args,
    chunks: [Buffer.alloc(f.chunks[0].length), f.chunks[1]] }),
  /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  assert.equal(puts, 1, "wrong ciphertext chunks must be refused before provider PUT");
  tamperRemotePut = true;
  await assert.rejects(f.bridge().publishAndReconcileCloudCopy(args),
  /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "cloud PUT ACK alone is never signed external durability or accepted without GET");
  assert.equal(puts, 2);
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "committed",
    "a bad cloud copy must not erase the valid historical signed local receipt");
  tamperRemotePut = false;
  const exactRead = cloudVerifier.verifyExact.bind(cloudVerifier);
  cloudVerifier.verifyExact = async (input) => ({ ...await exactRead(input),
    providerFileId: "unrelated-physical-copy" });
  await assert.rejects(f.bridge().publishAndReconcileCloudCopy(args),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "even authentic PG, receipt and remote bytes cannot authorize a copy whose GET identity disagrees with PUT");
  cloudVerifier.verifyExact = exactRead;
});

test("one real signed PG operation requires independent S3 and Drive copy rereads, rejecting later first-copy corruption", {
  skip: !enabled && "requires disposable PostgreSQL 18 and synthetic S3 + Google Drive",
}, async (t) => {
  const f = await fixture(t);
  const address = zk1CloudCopyAddress({ scope: f.scope, operationId: f.op.operation_id });
  const filename = "pinned-two-provider-file";
  const expected = Buffer.concat(f.chunks);
  let s3Bytes = null;
  let driveBytes = null;
  let overwriteS3DuringDrive = false;
  let s3Puts = 0;
  let drivePuts = 0;
  const config = (provider, principal) => {
    const base = { provider, prefix: "zk1-two-provider-physical-fixture",
      resolvePrincipalIdentity: async () => `${provider}-${principal}` };
    if (provider === "s3") {
      base.s3 = { bucket: "synthetic-two-provider-bucket" };
      base.createS3Client = async () => ({ send: async (cmd) => {
        if (cmd.constructor.name === "PutObjectCommand") {
          s3Puts += 1;
          const collected = [];
          if (Buffer.isBuffer(cmd.input.Body)) collected.push(Buffer.from(cmd.input.Body));
          else for await (const data of cmd.input.Body) collected.push(Buffer.from(data));
          s3Bytes = Buffer.concat(collected);
          return { ETag: "nonproof" };
        }
        if (cmd.constructor.name === "GetObjectCommand") {
          if (!s3Bytes) throw new Error("missing S3 ciphertext");
          return { Body: Readable.from([s3Bytes]) };
        }
        throw new Error("non-opaque provider effect forbidden");
      } });
    } else {
      base.gdrive = { folderId: "independent-drive-fixture-parent" };
      const metadata = () => ({ id: filename,
        parents: ["independent-drive-fixture-parent"],
        appProperties: {
          rootArkKey: `zk1-two-provider-physical-fixture/uploads/${address.folder}/${address.name}`,
          rootArkFolderId: address.folder, rootArkArea: "uploads",
        } });
      base.createGoogleDriveClient = async () => ({ files: {
        get: async ({ fileId, alt }) => {
          if (fileId !== filename || !driveBytes) {
            throw Object.assign(new Error("not found"), { status: 404 });
          }
          return alt === "media" ? { data: Readable.from([driveBytes]) }
            : { data: metadata() };
        },
        list: async () => ({ data: { files: driveBytes ? [metadata()] : [] } }),
        create: async ({ requestBody, media }) => {
          assert.equal(requestBody.id, filename);
          drivePuts += 1;
          const pieces = [];
          for await (const data of media.body) pieces.push(Buffer.from(data));
          driveBytes = Buffer.concat(pieces);
          if (overwriteS3DuringDrive) s3Bytes = Buffer.alloc(expected.length, 0x91);
          return { data: { id: filename } };
        },
        update: async ({ fileId, media }) => {
          assert.equal(fileId, filename);
          drivePuts += 1;
          const pieces = [];
          for await (const data of media.body) pieces.push(Buffer.from(data));
          driveBytes = Buffer.concat(pieces);
          if (overwriteS3DuringDrive) s3Bytes = Buffer.alloc(expected.length, 0x91);
          return { data: { id: filename } };
        },
      } });
    }
    return createCloudStorage(base);
  };
  const makeTarget = async (provider) => {
    const writer = config(provider, "write-only");
    const reader = config(provider, "reader-only");
    return {
      cloudPublisher: new Zk1CloudCiphertextCopyPublisher({
        cloudWriter: writer, expectedProvider: provider,
        expectedWriterContext: await writer.resolveInventoryContext(),
        pinnedDriveFileId: provider === "gdrive" ? filename : null,
      }),
      cloudVerifier: new Zk1CloudCiphertextReadbackVerifier({
        cloudReader: reader, expectedProvider: provider,
        expectedReaderContext: await reader.resolveInventoryContext(),
        pinnedDriveFileId: provider === "gdrive" ? filename : null,
      }),
    };
  };
  const s3 = await makeTarget("s3");
  const drive = await makeTarget("gdrive");
  const bridge = f.bridge();
  const args = { physical: f.noChunks(), chunks: f.chunks, copies: [s3, drive] };
  await assert.rejects(bridge.publishAndReconcileCloudCopies(args),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "two cloud PUTs must be refused before exact signed local PG proof");
  assert.equal(s3Puts + drivePuts, 0);
  await f.bridge().putAndAttest(f.physical);
  await assert.rejects(bridge.publishAndReconcileCloudCopies({ ...args, copies: [s3, s3] }),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "two copies of the same S3 authority cannot masquerade as two providers");
  assert.equal(s3Puts + drivePuts, 0);
  overwriteS3DuringDrive = true;
  await assert.rejects(bridge.publishAndReconcileCloudCopies(args),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "Drive PUT tampering with already-verified S3 copy must fail the second full readback");
  assert.deepEqual(driveBytes, expected);
  assert.notDeepEqual(s3Bytes, expected);
  overwriteS3DuringDrive = false;
  const outcome = await bridge.publishAndReconcileCloudCopies(args);
  assert.equal(outcome.status, "PG_SIGNED_AND_TWO_CLOUD_COPIES_REREAD");
  assert.deepEqual(outcome.providers, ["s3", "gdrive"]);
  assert.equal(outcome.providerCount, 2);
  assert.equal(outcome.authorizesIo, false);
  assert.equal(outcome.externalProviderDurabilityProven, false);
  assert.equal(outcome.independentRemoteIoFenceProven, false);
  assert.equal(outcome.atomicCrossProviderCommitProven, false);
  assert.deepEqual(s3Bytes, expected);
  assert.deepEqual(driveBytes, expected);
  let webdavBytes = null;
  let webdavPuts = 0;
  let corruptWebdavOnPut = false;
  const webdavContext = crypto.createHash("sha256")
    .update("disposable-three-provider-webdav-context").digest("hex");
  const webdavKey = (folder, name, area) => {
    assert.equal(area, "uploads");
    return `zk1-three-provider-fixture/uploads/${folder}/${name}`;
  };
  const webdavPublisher = new Zk1CloudCiphertextCopyPublisher({
    cloudWriter: {
      enabled: () => true,
      status: () => ({ provider: "webdav" }),
      resolveInventoryContext: async () => webdavContext,
      key: webdavKey,
      async upload(staged, folder, name, area, opts) {
        webdavPuts += 1;
        assert.equal(opts.zk1BoundedBytes, expected.length);
        webdavKey(folder, name, area);
        webdavBytes = corruptWebdavOnPut
          ? Buffer.alloc(expected.length, 0xaa) : fs.readFileSync(staged);
        return { provider: "webdav", key: webdavKey(folder, name, area) };
      },
    },
    expectedProvider: "webdav", expectedWriterContext: webdavContext,
  });
  const webdavVerifier = new Zk1CloudCiphertextReadbackVerifier({
    cloudReader: {
      enabled: () => true,
      status: () => ({ provider: "webdav" }),
      resolveInventoryContext: async () => webdavContext,
      key: webdavKey,
      async download(folder, name, destination, area, publish, opts) {
        webdavKey(folder, name, area);
        assert.ok(webdavBytes);
        assert.equal(opts.maxBytes, expected.length);
        if (!publish()) return false;
        fs.writeFileSync(destination, webdavBytes, { flag: "wx", mode: 0o600 });
        return true;
      },
    },
    expectedProvider: "webdav", expectedReaderContext: webdavContext,
  });
  const webdav = { cloudPublisher: webdavPublisher, cloudVerifier: webdavVerifier };
  await assert.rejects(bridge.publishAndReconcileCloudCopies({ ...args,
    copies: [s3, drive, s3] }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "all third-provider identities must be prechecked before any writes");
  assert.equal(webdavPuts, 0);
  const allThree = { ...args, copies: [s3, drive, webdav] };
  const combined = await bridge.publishAndReconcileCloudCopies(allThree);
  assert.equal(combined.status, "PG_SIGNED_AND_THREE_CLOUD_COPIES_REREAD");
  assert.deepEqual(combined.providers, ["s3", "gdrive", "webdav"]);
  assert.equal(combined.providerCount, 3);
  assert.equal(combined.authorizesIo, false);
  assert.equal(combined.externalProviderDurabilityProven, false);
  assert.equal(combined.independentRemoteIoFenceProven, false);
  assert.equal(combined.atomicCrossProviderCommitProven, false);
  assert.equal(webdavPuts, 1);
  assert.deepEqual(webdavBytes, expected);
  corruptWebdavOnPut = true;
  await assert.rejects(bridge.publishAndReconcileCloudCopies(allThree),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "a remote provider that changes during reconciliation cannot be counted as a current copy");
  corruptWebdavOnPut = false;
  const beforeFailure = s3Puts + drivePuts;
  await assert.rejects(bridge.publishAndReconcileCloudCopies({ ...args,
    chunks: [Buffer.alloc(f.chunks[0].length), f.chunks[1]] }),
  /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  assert.equal(s3Puts + drivePuts, beforeFailure,
    "invalid local chunks cannot start cloud effects on either provider");
});

test("mTLS signed inventory append requires real strict physical PG readback and WAL", {
  skip: !enabled && "requires disposable PostgreSQL 18 and native OpenSSL",
}, async (t) => {
  const f = await fixture(t);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-pg-mtls-"));
  generateNativeFixtureCertificates(dir, {
    caSubject: "Rootark physical pg lab", servers: ["inventory"], clients: ["writer"],
  });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const cert = read("writer.pem");
  const jsonScope = Object.fromEntries(Object.entries(f.scope).map(([name, value]) =>
    [name, value.toString("base64url")]));
  const server = createZk1ContentInventoryHttpsServer({
    key: read("inventory.key"), cert: read("inventory.pem"), clientCa: read("ca.pem"),
    ledger: f.ledger, physicalVerifier: f.verifier,
    principals: {
      [new crypto.X509Certificate(cert).fingerprint256]: {
        roles: ["append"], scopes: [jsonScope],
      },
    },
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    await drainZk1ContentInventoryHttpsServer(server);
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 });
  });
  const body = Buffer.from(JSON.stringify({
    scope: jsonScope,
    operation: Object.fromEntries(Object.entries(f.op).map(([name, value]) =>
      [name, Buffer.isBuffer(value) ? value.toString("base64url") : value])),
    nonce: crypto.randomBytes(32).toString("base64url"),
  }));
  const append = () => new Promise((resolve, reject) => {
    const request = https.request({
      hostname: "127.0.0.1", servername: "localhost", port: server.address().port,
      path: "/v1/inventory/append", method: "POST", agent: false,
      ca: read("ca.pem"), cert, key: read("writer.key"),
      minVersion: "TLSv1.3", rejectUnauthorized: true,
      headers: { "content-type": "application/json", "content-length": String(body.length) },
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()),
      }));
      response.on("error", reject);
    });
    request.on("error", reject);
    request.end(body);
  });

  const absent = await append();
  assert.equal(absent.status, 503, "mTLS append cannot sign without physical bytes");
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown");
  assert.deepEqual(f.calls, [], "mTLS append must never self-provision a writer");

  assert.equal((await f.intentAuthority.reserveExact(f.noChunks())).status,
    "IMMUTABLE_PREWRITE_INTENT");
  const stored = await f.bridge().sink.putSealed({
    scope: f.scope, objectId: f.op.object_id.toString("base64url"),
    revision: f.op.revision, digest: f.digest, chunks: f.chunks,
    expectedRootHash: f.root, expectedChunkCount: f.chunks.length,
  });
  assert.equal(stored.status, "SEALED");
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown");
  // A legitimate but compromised append cert must not expand one operation
  // into unbounded simultaneous physical readbacks of the same 64 MiB object.
  // Delay the *real* verifier before it does PG I/O; the second request must
  // fail promptly and never append/sign while the first owns the lease.
  const originalVerify = f.verifier.verifyCommittedInventoryOperation.bind(f.verifier);
  let signalEntered;
  const entered = new Promise((resolve) => { signalEntered = resolve; });
  let releaseFirst;
  const holdFirst = new Promise((resolve) => { releaseFirst = resolve; });
  let firstCall = true;
  f.verifier.verifyCommittedInventoryOperation = async (input) => {
    if (firstCall) {
      firstCall = false;
      signalEntered();
      await holdFirst;
    }
    return originalVerify(input);
  };
  const firstAppend = append();
  await entered;
  try {
    const refused = await append();
    assert.equal(refused.status, 503,
      "replaying a single mTLS certificate cannot fan out concurrent physical readbacks");
    assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown",
      "rejected parallel request must not sign anything while first is held");
  } finally { releaseFirst(); }
  const committed = await firstAppend;
  f.verifier.verifyCommittedInventoryOperation = originalVerify;
  assert.equal(committed.status, 200);
  assert.equal(committed.body.status, "committed");
  assert.equal(committed.body.operationId, f.op.operation_id.toString("base64url"));
  assert.ok(committed.body.proofBase64?.length > 100);
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "committed");

  await f.admin.query(`UPDATE zk1_gate.ciphertext_chunk SET ciphertext=$1
    WHERE scope_key=$2 AND object_id=$3 AND chunk_index=0`,
  [crypto.randomBytes(f.chunks[0].length), f.key, f.op.object_id.toString("base64url")]);
  let physicalChecksAfterCorruption = 0;
  f.verifier.verifyCommittedInventoryOperation = async (input) => {
    physicalChecksAfterCorruption += 1;
    return originalVerify(input);
  };
  assert.equal((await append()).status, 503,
    "authentic earlier signed receipt cannot bypass a corrupted physical provider");
  for (let i = 0; i < 8; i += 1) {
    assert.equal((await append()).status, 503,
      "rapid replay attempts never turn corrupted ciphertext into a valid receipt");
  }
  assert.equal(physicalChecksAfterCorruption, 2,
    "bounded per-certificate minute budget rejects replay flooding before PG readback");
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "committed",
    "failure preserves historical signed evidence instead of rewriting it");
});

test("mTLS committed-operation status needs fresh physical PG proof, not historical signature", {
  skip: !enabled && "requires disposable PostgreSQL 18 and native OpenSSL",
}, async (t) => {
  const f = await fixture(t);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-pg-status-"));
  generateNativeFixtureCertificates(dir, {
    caSubject: "Rootark physical status lab", servers: ["inventory"], clients: ["status"],
  });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const cert = read("status.pem");
  const jsonScope = Object.fromEntries(Object.entries(f.scope).map(([name, value]) =>
    [name, value.toString("base64url")]));
  const server = createZk1ContentInventoryHttpsServer({
    key: read("inventory.key"), cert: read("inventory.pem"), clientCa: read("ca.pem"),
    ledger: f.ledger, physicalVerifier: f.verifier,
    principals: {
      [new crypto.X509Certificate(cert).fingerprint256]: {
        roles: ["status"], scopes: [jsonScope],
      },
    },
  });
  const originalPhysicalCheck = f.verifier.verifyCommittedInventoryOperation.bind(f.verifier);
  let physicalStatusChecks = 0;
  f.verifier.verifyCommittedInventoryOperation = async (input) => {
    physicalStatusChecks += 1;
    return originalPhysicalCheck(input);
  };
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    await drainZk1ContentInventoryHttpsServer(server);
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 });
  });
  const client = createZk1ContentInventoryHttpsClient({
    endpoint: `https://localhost:${server.address().port}/`,
    ca: read("ca.pem"), clientKey: read("status.key"), clientCert: cert,
    serverFingerprint256: new crypto.X509Certificate(read("inventory.pem")).fingerprint256,
    inventoryPublicKey: f.keys.publicKey, inventorySignerKeyId: f.signerKeyId,
    wallTimeoutMs: 10000,
  });
  const request = { scope: f.scope, operation: f.op };
  assert.equal((await client.getOperationStatus(request)).status, "unknown");
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const good = await client.getOperationStatus(request);
  assert.equal(good.status, "committed");
  assert.equal(good.signedLedgerOperationCommitted, true);
  assert.equal(good.authorizesIo, false);
  assert.equal(good.externalDurabilityProven, false);
  assert.equal(physicalStatusChecks, 1);
  await f.admin.query(`UPDATE zk1_gate.ciphertext_chunk SET ciphertext=$1
    WHERE scope_key=$2 AND object_id=$3 AND chunk_index=0`,
  [crypto.randomBytes(f.chunks[0].length), f.key, f.op.object_id.toString("base64url")]);
  await assert.rejects(client.getOperationStatus(request), /INVENTORY_HTTP_UNAVAILABLE/,
    "valid signed receipt cannot turn corrupted physical bytes into a positive status");
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "committed",
    "the historical signed event must remain intact after physical corruption");
  await f.admin.query(`UPDATE zk1_gate.ciphertext_chunk SET ciphertext=$1
    WHERE scope_key=$2 AND object_id=$3 AND chunk_index=0`,
  [f.chunks[0], f.key, f.op.object_id.toString("base64url")]);
  const op = { scope: f.scope, revision: 1, digest: f.digest,
    operationId: crypto.randomBytes(16), reservationId: crypto.randomBytes(16) };
  assert.equal((await f.gate.beginQuiesce(op)).activeCount, 0);
  assert.equal((await f.gate.markPending(op)).status, "PENDING");
  await assert.rejects(client.getOperationStatus(request), /INVENTORY_HTTP_UNAVAILABLE/,
    "restored bytes cannot bypass a newer physical generation fence");
  assert.equal(physicalStatusChecks, 3,
    "the fourth status attempt, including the earlier unknown ID, ran one last physical proof");
  const originalStatusLookup = f.ledger.getOperationStatus.bind(f.ledger);
  let ledgerStatusLookups = 0;
  f.ledger.getOperationStatus = async (...args) => {
    ledgerStatusLookups += 1;
    return originalStatusLookup(...args);
  };
  await assert.rejects(client.getOperationStatus({ scope: f.scope,
    operation: { ...f.op, operation_id: crypto.randomBytes(16) } }),
  /INVENTORY_HTTP_UNAVAILABLE/);
  assert.equal(ledgerStatusLookups, 0,
    "flooding unknown operation IDs cannot bypass the quota to trigger catalog reads");
  await assert.rejects(client.getOperationStatus(request), /INVENTORY_HTTP_UNAVAILABLE/);
  assert.equal(physicalStatusChecks, 3,
    "a fifth status replay cannot bypass the mTLS certificate's readback quota");
});

test("unverified physical write, partial seal, and generation fencing never publish a signed success", {
  skip: !enabled && "requires a disposable restricted PG18 gate fixture",
}, async (t) => {
  const f = await fixture(t);
  const originalVerifier = f.verifier.verifyExact.bind(f.verifier);
  let failReadback = true;
  f.verifier.verifyExact = async (...args) => {
    if (failReadback) throw new Error("synthetic independent readback unavailable");
    return originalVerifier(...args);
  };
  await assert.rejects(f.bridge().putAndAttest(f.physical),
    /synthetic independent readback unavailable/,
    "successful PostgreSQL SEALED response is insufficient to attest the signed inventory");
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown",
    "physical sealed bytes must be left intact for recovery, not falsely signed");
  failReadback = false;
  const reconciled = await f.bridge().publishExisting(f.noChunks());
  assert.equal(reconciled.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY",
    "restart can sign after separately verifying genuine physical commit");
  const op = { scope: f.scope, revision: 1, digest: f.digest,
    operationId: crypto.randomBytes(16), reservationId: crypto.randomBytes(16) };
  assert.equal((await f.gate.beginQuiesce(op)).activeCount, 0);
  assert.equal((await f.gate.markPending(op)).status, "PENDING");
  await assert.rejects(f.bridge().reconcile(f.noChunks()), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "signed historical inventory and ciphertext still on disk cannot bypass the newer fenced generation");
});

test("wrong owner-verified chunk hash rejects before physical IO and DB access", {
  skip: !enabled && "requires a disposable restricted PG18 gate fixture",
}, async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.bridge().putAndAttest({ ...f.physical,
    chunks: [Buffer.from("wrong"), Buffer.from("payload")] }),
  /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  assert.deepEqual(f.calls, []);
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown");
});

test("attestor has physical SELECT only; gate, writer and superuser cannot masquerade as attestor", {
  skip: !enabled && "requires disposable read-only attestor and gate roles",
}, async (t) => {
  const f = await fixture(t);
  const checks = await f.proofPool.query(`SELECT
    pg_catalog.has_table_privilege(current_user,'zk1_gate.head','UPDATE') AS can_update_head,
    pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','INSERT') AS can_insert,
    pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','DELETE') AS can_delete,
    pg_catalog.pg_has_role(current_user,'zk1_gate_runtime','MEMBER') AS gate_member,
    pg_catalog.pg_has_role(current_user,'zk1_stop_runtime','MEMBER') AS stop_member,
    pg_catalog.pg_has_role(current_user,'zk1_chunk_writer_runtime','MEMBER') AS writer_member`);
  assert.equal(checks.rowCount, 1);
  assert.deepEqual(checks.rows[0], {
    can_update_head: false, can_insert: false, can_delete: false,
    gate_member: false, stop_member: false, writer_member: false,
  });
  assert.equal((await f.proofPool.query("SELECT COUNT(*)::integer AS n FROM zk1_gate.head"))
    .rows[0].n > 0, true);
  await assert.rejects(f.proofPool.query("UPDATE zk1_gate.head SET phase='OPEN' WHERE false"),
    /permission denied/);
  const privileged = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: f.gatePool });
  await assert.rejects(privileged.verifyExact({
    scope: f.scope, objectId: f.op.object_id.toString("base64url"),
    revision: 1, digest: f.digest, expectedRootHash: f.root,
    expectedChunkCount: 2, expectedSha256: f.op.ciphertext_sha256,
    operationId: f.op.operation_id, expectedInventorySequence: f.op.expected_sequence,
    expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch,
  }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
});

test("superuser-altered physical ciphertext is detected despite an authentic earlier Ed25519 receipt", {
  skip: !enabled && "requires disposable PG18 with a restricted attestor",
}, async (t) => {
  const f = await fixture(t);
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  await f.admin.query(`UPDATE zk1_gate.ciphertext_chunk SET ciphertext=$1
    WHERE scope_key=$2 AND object_id=$3 AND chunk_index=1`,
  [crypto.randomBytes(66), f.key, f.op.object_id.toString("base64url")]);
  await assert.rejects(f.bridge().reconcile(f.noChunks()),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "a previously valid signed inventory cannot mask later physical corruption");
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "committed",
    "the signature remains historical evidence, NOT physical release authorization");
});

test("a partially inserted chunk stream never causes an Ed25519 signed inventory success", {
  skip: !enabled && "requires disposable PG18 with a restricted attestor",
}, async (t) => {
  const f = await fixture(t);
  const originalPut = f.bridge().sink.gate.putCiphertextChunk;
  f.bridge().sink.gate.putCiphertextChunk = async (op, index, chunk) => {
    if (index === 1) throw new Error("simulated persistent physical provider outage");
    return originalPut(op, index, chunk);
  };
  await assert.rejects(f.bridge().putAndAttest(f.physical),
    /ZK_GATE_SINK_UNAVAILABLE/);
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown");
  const chunks = await f.admin.query(`SELECT chunk_index FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=$1 AND object_id=$2`, [f.key, f.op.object_id.toString("base64url")]);
  assert.equal(chunks.rowCount, 1);
  assert.equal(chunks.rows[0].chunk_index, 0);
  const seal = await f.admin.query(`SELECT 1 FROM zk1_gate.sealed_object
    WHERE scope_key=$1 AND object_id=$2`, [f.key, f.op.object_id.toString("base64url")]);
  assert.equal(seal.rowCount, 0, "partial storage must have no SEALED evidence");
  await assert.rejects(f.bridge().publishExisting(f.noChunks()),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "disconnected or incomplete provider cannot be reconstructed as signed success");
});

test("read-only attestor rejects a poisoned column-level INSERT grant hidden from table-level preflight", {
  skip: !enabled && "requires disposable PostgreSQL attestor role",
}, async (t) => {
  const f = await fixture(t);
  const login = "zkattestorpoison_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  await f.admin.query(`CREATE ROLE ${login} LOGIN PASSWORD '${password}'`);
  await f.admin.query(`GRANT zk1_physical_attestor_runtime TO ${login}`);
  await f.admin.query(`GRANT INSERT(ciphertext) ON zk1_gate.ciphertext_chunk TO ${login}`);
  const url = new URL(process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
  url.username = login;
  url.password = password;
  const poisonedPool = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 2500 });
  try {
    const granted = await poisonedPool.query(`SELECT
      pg_catalog.has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','INSERT') AS table_insert,
      pg_catalog.has_any_column_privilege(current_user,'zk1_gate.ciphertext_chunk','INSERT') AS column_insert`);
    assert.deepEqual(granted.rows[0], { table_insert: false, column_insert: true });
    const verifier = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: poisonedPool });
    await assert.rejects(verifier.verifyExact({
      scope: f.scope, objectId: f.op.object_id.toString("base64url"),
      revision: 1, digest: f.digest, expectedRootHash: f.root,
      expectedChunkCount: 2, expectedSha256: f.op.ciphertext_sha256,
    operationId: f.op.operation_id, expectedInventorySequence: f.op.expected_sequence,
    expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch,
    }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "a read-only identity is invalid if any dormant column-level writer grant exists");
  } finally {
    // Run this before fixture(t)'s after hook closes the admin pool. Exact
    // disposable login only, never broad cleanup.
    await poisonedPool.end();
    await f.admin.query(`REVOKE INSERT(ciphertext) ON zk1_gate.ciphertext_chunk FROM ${login}`);
    await f.admin.query(`REVOKE zk1_physical_attestor_runtime FROM ${login}`);
    await f.admin.query(`DROP ROLE ${login}`);
  }
});

test("physical attestor rejects separately poisoned TRUNCATE/DELETE privileges before touching bytes", {
  skip: !enabled && "requires disposable PostgreSQL attestor role",
}, async (t) => {
  const f = await fixture(t);
  const login = "zkattestordestruct_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  const objectId = f.op.object_id.toString("base64url");
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  await f.admin.query(`CREATE ROLE ${login} LOGIN PASSWORD '${password}'`);
  await f.admin.query(`GRANT zk1_physical_attestor_runtime TO ${login}`);
  // Runtime-role REVOKE cannot erase a direct poisoned LOGIN grant. TRUNCATE
  // bypasses BEFORE DELETE triggers and is more powerful than a read-only
  // physical proof identity can ever possess.
  await f.admin.query(`GRANT TRUNCATE ON zk1_gate.physical_inventory_intent TO ${login}`);
  await f.admin.query(`GRANT DELETE ON zk1_gate.sealed_object TO ${login}`);
  const url = new URL(process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
  url.username = login;
  url.password = password;
  const poisonedPool = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 2500 });
  try {
    const check = await poisonedPool.query(`SELECT
      pg_catalog.has_table_privilege(current_user,'zk1_gate.physical_inventory_intent','TRUNCATE') AS truncate_intent,
      pg_catalog.has_table_privilege(current_user,'zk1_gate.sealed_object','DELETE') AS delete_seal`);
    assert.deepEqual(check.rows[0], { truncate_intent: true, delete_seal: true });
    const verifier = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: poisonedPool });
    await assert.rejects(verifier.verifyExact({
      scope: f.scope, objectId, revision: 1, digest: f.digest,
      expectedRootHash: f.root, expectedChunkCount: f.chunks.length,
      expectedSha256: f.op.ciphertext_sha256, operationId: f.op.operation_id,
      expectedInventorySequence: f.op.expected_sequence,
      expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch,
    }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "destructive powers must invalidate physical readback even if bytes are intact");
    assert.equal((await f.admin.query(`SELECT COUNT(*)::integer AS n
      FROM zk1_gate.physical_inventory_intent
      WHERE scope_key=$1 AND object_id=$2`, [f.key, objectId])).rows[0].n, 1);
  } finally {
    await poisonedPool.end();
    await f.admin.query(`REVOKE TRUNCATE ON zk1_gate.physical_inventory_intent FROM ${login}`);
    await f.admin.query(`REVOKE DELETE ON zk1_gate.sealed_object FROM ${login}`);
    await f.admin.query(`REVOKE zk1_physical_attestor_runtime FROM ${login}`);
    await f.admin.query(`DROP ROLE ${login}`);
  }
});

test("physical attestor separately rejects poisoned admission UPDATE and head INSERT grants", {
  skip: !enabled && "requires disposable PostgreSQL attestor role",
}, async (t) => {
  const f = await fixture(t);
  const login = "zkattestorgatepoison_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  await f.admin.query(`CREATE ROLE ${login} LOGIN PASSWORD '${password}'`);
  await f.admin.query(`GRANT zk1_physical_attestor_runtime TO ${login}`);
  const url = new URL(process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
  url.username = login;
  url.password = password;
  const poisonedPool = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 2500 });
  const verify = () => new Zk1SharedPgPhysicalCiphertextVerifier({ pool: poisonedPool })
    .verifyExact({ scope: f.scope, objectId: f.op.object_id.toString("base64url"),
      revision: 1, digest: f.digest, expectedRootHash: f.root,
      expectedChunkCount: f.chunks.length, expectedSha256: f.op.ciphertext_sha256,
      operationId: f.op.operation_id, expectedInventorySequence: f.op.expected_sequence,
      expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch });
  try {
    await f.admin.query(`GRANT UPDATE(state) ON zk1_gate.admission TO ${login}`);
    assert.equal((await poisonedPool.query(`SELECT
      pg_catalog.has_any_column_privilege(current_user,'zk1_gate.admission','UPDATE') AS capability`))
      .rows[0].capability, true);
    await assert.rejects(verify(), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
      "a login able to finish or alter admissions is not a read-only physical attestor");
    await f.admin.query(`REVOKE UPDATE(state) ON zk1_gate.admission FROM ${login}`);
    await f.admin.query(`GRANT INSERT(scope_key,keyring_id,revision,digest)
      ON zk1_gate.head TO ${login}`);
    assert.equal((await poisonedPool.query(`SELECT
      pg_catalog.has_any_column_privilege(current_user,'zk1_gate.head','INSERT') AS capability`))
      .rows[0].capability, true);
    await assert.rejects(verify(), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
      "a login able to provision fabricated gate heads cannot attest ciphertext");
  } finally {
    await poisonedPool.end();
    await f.admin.query(`REVOKE UPDATE(state) ON zk1_gate.admission FROM ${login}`);
    await f.admin.query(`REVOKE INSERT(scope_key,keyring_id,revision,digest)
      ON zk1_gate.head FROM ${login}`);
    await f.admin.query(`REVOKE zk1_physical_attestor_runtime FROM ${login}`);
    await f.admin.query(`DROP ROLE ${login}`);
  }
});

test("physical attestor rejects destructive SET ROLE reachability hidden behind NOINHERIT", {
  skip: !enabled && "requires disposable PostgreSQL 18 membership options",
}, async (t) => {
  const f = await fixture(t);
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const login = "zkattestorswitch_" + crypto.randomBytes(6).toString("hex");
  const hidden = "zkhiddenwriter_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  await f.admin.query(`CREATE ROLE ${hidden} NOLOGIN NOINHERIT`);
  await f.admin.query(`CREATE ROLE ${login} LOGIN INHERIT PASSWORD '${password}'`);
  await f.admin.query(`GRANT zk1_physical_attestor_runtime TO ${login}`);
  await f.admin.query(`GRANT USAGE ON SCHEMA zk1_gate TO ${hidden}`);
  await f.admin.query(`GRANT TRUNCATE ON zk1_gate.physical_inventory_intent TO ${hidden}`);
  // Deliberately no inherited DML: existing direct-login privilege preflight
  // will report false until SET ROLE switches to the hidden destructive role.
  await f.admin.query(`GRANT ${hidden} TO ${login} WITH INHERIT FALSE, SET TRUE`);
  const url = new URL(process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
  url.username = login;
  url.password = password;
  const poisonedPool = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 2500 });
  try {
    const c = await poisonedPool.connect();
    try {
      const before = await c.query(`SELECT
        pg_catalog.has_table_privilege(current_user,
          'zk1_gate.physical_inventory_intent','TRUNCATE') AS direct_power,
        pg_catalog.pg_has_role(current_user,'zk1_physical_attestor_runtime','USAGE') AS normal_attestor,
        pg_catalog.pg_has_role(current_user,$1,'SET') AS may_set_role`, [hidden]);
      assert.deepEqual(before.rows[0],
        { direct_power: false, normal_attestor: true, may_set_role: true });
      await c.query(`SET ROLE ${hidden}`);
      const after = await c.query(`SELECT pg_catalog.has_table_privilege(current_user,
        'zk1_gate.physical_inventory_intent','TRUNCATE') AS gained_power`);
      assert.equal(after.rows[0].gained_power, true,
        "the poisoned login really can obtain TRUNCATE via SET ROLE");
      await c.query("RESET ROLE");
    } finally {
      c.release();
    }
    const verifier = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: poisonedPool });
    await assert.rejects(verifier.verifyExact({
      scope: f.scope, objectId: f.op.object_id.toString("base64url"),
      revision: 1, digest: f.digest, expectedRootHash: f.root,
      expectedChunkCount: f.chunks.length, expectedSha256: f.op.ciphertext_sha256,
      operationId: f.op.operation_id, expectedInventorySequence: f.op.expected_sequence,
      expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch,
    }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "read-only attestation must fail if its login can SET ROLE into destructive privilege");
    assert.equal((await f.admin.query(`SELECT COUNT(*)::integer AS n FROM
      zk1_gate.physical_inventory_intent WHERE scope_key=$1`, [f.key])).rows[0].n, 1,
    "the proof must not mutate owner physical evidence");
  } finally {
    await poisonedPool.end();
    await f.admin.query(`REVOKE ${hidden} FROM ${login}`);
    await f.admin.query(`REVOKE zk1_physical_attestor_runtime FROM ${login}`);
    await f.admin.query(`REVOKE TRUNCATE ON zk1_gate.physical_inventory_intent FROM ${hidden}`);
    await f.admin.query(`REVOKE USAGE ON SCHEMA zk1_gate FROM ${hidden}`);
    await f.admin.query(`DROP ROLE ${login}`);
    await f.admin.query(`DROP ROLE ${hidden}`);
  }
});

test("physical attestor refuses schema CREATE and table MAINTAIN grants on its SQL identity", {
  skip: !enabled && "requires disposable PostgreSQL 18 MAINTAIN capability",
}, async (t) => {
  const f = await fixture(t);
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const login = "zkattestorddl_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  await f.admin.query(`CREATE ROLE ${login} LOGIN PASSWORD '${password}'`);
  await f.admin.query(`GRANT zk1_physical_attestor_runtime TO ${login}`);
  const url = new URL(process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
  url.username = login;
  url.password = password;
  const poisonedPool = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 2500 });
  const verify = () => new Zk1SharedPgPhysicalCiphertextVerifier({ pool: poisonedPool })
    .verifyExact({ scope: f.scope,
      objectId: f.op.object_id.toString("base64url"), revision: 1,
      digest: f.digest, expectedRootHash: f.root,
      expectedChunkCount: f.chunks.length, expectedSha256: f.op.ciphertext_sha256,
      operationId: f.op.operation_id, expectedInventorySequence: f.op.expected_sequence,
      expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch });
  try {
    await f.admin.query(`GRANT MAINTAIN ON zk1_gate.sealed_object TO ${login}`);
    assert.equal((await poisonedPool.query(`SELECT pg_catalog.has_table_privilege(
      current_user,'zk1_gate.sealed_object','MAINTAIN') AS capability`)).rows[0].capability,
    true);
    await assert.rejects(verify(), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
      "VACUUM/REINDEX/CLUSTER capability is not strictly read-only");
    await f.admin.query(`REVOKE MAINTAIN ON zk1_gate.sealed_object FROM ${login}`);
    await f.admin.query(`GRANT CREATE ON SCHEMA zk1_gate TO ${login}`);
    assert.equal((await poisonedPool.query(`SELECT pg_catalog.has_schema_privilege(
      current_user,'zk1_gate','CREATE') AS capability`)).rows[0].capability, true);
    await assert.rejects(verify(), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
      "ability to create objects in the protected schema is not read-only");
  } finally {
    await poisonedPool.end();
    await f.admin.query(`REVOKE MAINTAIN ON zk1_gate.sealed_object FROM ${login}`);
    await f.admin.query(`REVOKE CREATE ON SCHEMA zk1_gate FROM ${login}`);
    await f.admin.query(`REVOKE zk1_physical_attestor_runtime FROM ${login}`);
    await f.admin.query(`DROP ROLE ${login}`);
  }
});

test("physical attestor rejects indirect privileged PostgreSQL OS role without executing commands", {
  skip: !enabled && "requires disposable PostgreSQL 18 predefined role membership",
}, async (t) => {
  const f = await fixture(t);
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const login = "zkattestorescape_" + crypto.randomBytes(6).toString("hex");
  const hidden = "zkhostrole_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  await f.admin.query(`CREATE ROLE ${hidden} NOLOGIN NOINHERIT`);
  await f.admin.query(`CREATE ROLE ${login} LOGIN PASSWORD '${password}'`);
  await f.admin.query(`GRANT zk1_physical_attestor_runtime TO ${login}`);
  await f.admin.query(`GRANT pg_execute_server_program TO ${hidden}
    WITH INHERIT FALSE, SET TRUE`);
  await f.admin.query(`GRANT ${hidden} TO ${login} WITH INHERIT FALSE, SET TRUE`);
  const url = new URL(process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
  url.username = login;
  url.password = password;
  const poisonedPool = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 2500 });
  try {
    const observed = await poisonedPool.query(`SELECT
      pg_catalog.pg_has_role(current_user,'pg_execute_server_program','USAGE') AS effective,
      pg_catalog.pg_has_role(current_user,'pg_execute_server_program','SET') AS reachable`);
    assert.deepEqual(observed.rows[0], { effective: false, reachable: true },
      "a non-inherited predefined role grants dangerous future SET ROLE powers");
    // NEVER actually run COPY TO PROGRAM, filesystem writes, shell or remote
    // services. Prove the privilege graph only, then require verifier denial.
    const verifier = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: poisonedPool });
    await assert.rejects(verifier.verifyExact({
      scope: f.scope, objectId: f.op.object_id.toString("base64url"),
      revision: 1, digest: f.digest, expectedRootHash: f.root,
      expectedChunkCount: f.chunks.length, expectedSha256: f.op.ciphertext_sha256,
      operationId: f.op.operation_id, expectedInventorySequence: f.op.expected_sequence,
      expectedInventoryRoot: f.op.expected_root, epoch: f.op.epoch,
    }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "predefined PostgreSQL execution powers invalidate read-only physical attestation");
  } finally {
    await poisonedPool.end();
    await f.admin.query(`REVOKE ${hidden} FROM ${login}`);
    await f.admin.query(`REVOKE zk1_physical_attestor_runtime FROM ${login}`);
    await f.admin.query(`REVOKE pg_execute_server_program FROM ${hidden}`);
    await f.admin.query(`DROP ROLE ${login}`);
    await f.admin.query(`DROP ROLE ${hidden}`);
  }
});

test("a different physical scope cannot poison the fixed-scope Ed25519 inventory before rejection", {
  skip: !enabled && "requires disposable PostgreSQL 18 lab",
}, async (t) => {
  const f = await fixture(t);
  const foreign = { ...f.scope, compartment_id: crypto.randomBytes(8) };
  await assert.rejects(f.bridge().putAndAttest({ ...f.physical, scope: foreign }),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  await assert.rejects(f.bridge().publishExisting({ ...f.noChunks(), scope: foreign }),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  assert.deepEqual(f.calls, []);
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown",
    "cross-scope failure must never leave a signed local SQLite commit");
  const row = await f.admin.query(`SELECT 1 FROM zk1_gate.physical_inventory_intent
    WHERE scope_key=$1 AND object_id=$2`, [f.key, f.op.object_id.toString("base64url")]);
  assert.equal(row.rowCount, 0, "scope denial also precedes the physical PREWRITE bind");
});

test("immutable prewrite intent cannot be relabeled to another operation after physical seal", {
  skip: !enabled && "requires disposable PostgreSQL 18 lab",
}, async (t) => {
  const f = await fixture(t);
  const status = await f.bridge().putAndAttest(f.physical);
  assert.equal(status.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const relabeled = { ...f.op, operation_id: crypto.randomBytes(16) };
  await assert.rejects(f.bridge().publishExisting({
    ...f.noChunks(), operation: relabeled,
  }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "a SEALED object cannot be given a different physical operation ID");
  await assert.rejects(f.intentAuthority.reserveExact({
    ...f.noChunks(), operation: relabeled,
  }), /ZK_PHYSICAL_INTENT_UNAVAILABLE/,
  "immutable first-writer physical reservation denies conflicting retransmission");
  assert.equal((await f.ledger.getOperationStatus(relabeled.operation_id)).status, "unknown");
});

test("operator WAL barrier flushes an independently async-committed PG transaction", {
  skip: !enabled && "requires disposable PostgreSQL 18 lab",
}, async (t) => {
  const f = await fixture(t);
  const other = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(8), keyring_id: crypto.randomBytes(16) };
  const key = other.account_id.toString("hex") + ":"
    + other.compartment_id.length.toString(16) + ":" + other.compartment_id.toString("hex");
  const c = await f.admin.connect();
  try {
    await c.query("BEGIN");
    await c.query("SET LOCAL synchronous_commit = off");
    await c.query(`INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest)
      VALUES($1,$2,1,$3)`, [key, other.keyring_id, crypto.randomBytes(32)]);
    await c.query("COMMIT");
  } finally { c.release(); }
  const barrier = await f.proofPool.query(
    "SELECT zk1_gate.physical_inventory_wal_flush_barrier() AS flushed");
  assert.equal(barrier.rows[0]?.flushed, true,
    "flush fence must not depend on a separate writer session's synchronous_commit");
  assert.equal((await f.proofPool.query(
    "SELECT 1 FROM zk1_gate.head WHERE scope_key=$1", [key])).rowCount, 1);
});

test("strict PG SQL trigger blocks gate role raw chunks without exact immutable operation intent", {
  skip: !enabled && "requires disposable PG18",
}, async (t) => {
  const f = await fixture(t);
  const objectId = f.op.object_id.toString("base64url");
  const workerId = crypto.randomBytes(16);
  const principal = "strict-raw-sql-adversary";
  await assert.rejects(f.gate.beginIoAdmission({
    scope: f.scope, workerId, principal, action: "put",
    objectId, revision: 1, digest: f.digest,
  }), /ZK_GATE_UNAVAILABLE/,
  "an admission cannot precede its immutable operation intent on strict scope");
  const prewrite = await f.intentAuthority.reserveExact(f.noChunks());
  assert.equal(prewrite.status, "IMMUTABLE_PREWRITE_INTENT");
  const started = await f.gate.beginIoAdmission({
    scope: f.scope, workerId, principal, action: "put",
    objectId, revision: 1, digest: f.digest,
  });
  assert.equal(started.proceed, true);
  const directPut = (index, object = objectId) => f.gatePool.query(
    `INSERT INTO zk1_gate.ciphertext_chunk(scope_key,object_id,chunk_index,ciphertext)
      VALUES($1,$2,$3,$4)`, [f.key, object, index, f.chunks[0]]);
  const binding = await f.admin.query(`SELECT operation_id,admission_id FROM
    zk1_gate.physical_inventory_admission WHERE scope_key=$1 AND object_id=$2`,
  [f.key, objectId]);
  assert.equal(binding.rowCount, 1);
  assert.deepEqual(binding.rows[0].operation_id, f.op.operation_id);
  assert.deepEqual(binding.rows[0].admission_id, started.admissionId);
  const count = await f.admin.query(
    "SELECT COUNT(*)::integer AS n FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1", [f.key]);
  assert.equal(count.rows[0].n, 0);
  await assert.rejects(f.gate.beginIoAdmission({
    scope: f.scope, workerId: crypto.randomBytes(16),
    principal: "other-admission", action: "put",
    objectId, revision: 1, digest: f.digest,
  }), /ZK_GATE_UNAVAILABLE/,
  "second admission must not usurp the immutable operation binding");
  await assert.rejects(f.admin.query(`UPDATE zk1_gate.physical_inventory_admission
    SET admission_id=$1 WHERE scope_key=$2 AND object_id=$3`,
  [crypto.randomBytes(16), f.key, objectId]), /physical admission binding is immutable/i);
  await assert.rejects(directPut(f.chunks.length), /strict chunk requires exact prewrite/i,
    "even a privileged gate login cannot exceed the operation-intent chunk boundary");
  await assert.rejects(directPut(0, crypto.randomBytes(16).toString("base64url")),
    /strict chunk requires exact prewrite/i,
    "a valid admission cannot retarget another unbound object");
  await assert.rejects(f.gatePool.query(
    `INSERT INTO zk1_gate.sealed_object
      (scope_key,object_id,revision,digest,generation,admission_id,expected_chunks,root_hash)
      VALUES($1,$2,1,$3,$4,$5,$6,$7)`,
    [f.key, objectId, f.digest, started.generation, started.admissionId,
      f.chunks.length + 1, f.root]), /strict seal requires exact prewrite/i);
  await f.admin.query("SELECT 1");
  await assert.rejects(f.admin.query(`UPDATE zk1_gate.head
    SET require_physical_inventory_intent=FALSE WHERE scope_key=$1`, [f.key]),
  /gate head identity is immutable/i,
  "an operator cannot downgrade strict physical intent after provisioning");
  await assert.rejects(f.admin.query(`UPDATE zk1_gate.physical_inventory_intent
    SET operation_id=$1 WHERE scope_key=$2 AND object_id=$3`,
  [crypto.randomBytes(16), f.key, objectId]), /physical inventory intent is immutable/i);
  await directPut(0);
  assert.equal((await f.admin.query(`SELECT COUNT(*)::integer AS n
    FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1`, [f.key])).rows[0].n, 1);
});

test("strict physical operation reservation races quiesce and forbids obsolete generation write", {
  skip: !enabled && "requires disposable PG18",
}, async (t) => {
  const f = await fixture(t);
  const guard = await f.admin.connect();
  await guard.query("BEGIN");
  try {
    await guard.query("SELECT 1 FROM zk1_gate.head WHERE scope_key=$1 FOR UPDATE", [f.key]);
    const pending = f.intentAuthority.reserveExact(f.noChunks());
    // Already blocked by independent PG row lock. Quiesce goes after the
    // initial committed intent, then generation must permanently advance.
    await guard.query("COMMIT");
    assert.equal((await pending).status, "IMMUTABLE_PREWRITE_INTENT");
  } finally {
    try { await guard.query("ROLLBACK"); } catch (_) {}
    guard.release();
  }
  const fenced = { scope: f.scope, revision: 1, digest: f.digest,
    operationId: crypto.randomBytes(16), reservationId: crypto.randomBytes(16) };
  assert.equal((await f.gate.beginQuiesce(fenced)).activeCount, 0);
  await assert.rejects(f.intentAuthority.reserveExact(f.noChunks()), /ZK_PHYSICAL_INTENT_UNAVAILABLE/,
    "a previous-generation operation is not reopened by a replayed reserve");
  await assert.rejects(f.gate.beginIoAdmission({
    scope: f.scope, workerId: crypto.randomBytes(16), principal: "obsolete-physical",
    action: "put", objectId: f.op.object_id.toString("base64url"),
    revision: 1, digest: f.digest,
  }), /ZK_GATE_DENIED/,
  "a previous gate generation cannot mint any new physical writer");
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "unknown",
    "an orphan prewrite intent must never be promoted to signed ciphertext");
});

test("strict SQL seal persists the exact immutable physical operation ID, not a caller-chosen substitute", {
  skip: !enabled && "requires disposable PG18",
}, async (t) => {
  const f = await fixture(t);
  assert.equal((await f.bridge().putAndAttest(f.physical)).status,
    "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  const row = await f.admin.query(`SELECT operation_id FROM zk1_gate.sealed_object
    WHERE scope_key=$1 AND object_id=$2`, [f.key, f.op.object_id.toString("base64url")]);
  assert.equal(row.rowCount, 1);
  assert.deepEqual(row.rows[0].operation_id, f.op.operation_id);
  // The signed catalog cannot authorize after a physical superuser rewrites
  // even the apparently matching bytes' operation binding.
  await f.admin.query(`UPDATE zk1_gate.sealed_object SET operation_id=$1
    WHERE scope_key=$2 AND object_id=$3`,
  [crypto.randomBytes(16), f.key, f.op.object_id.toString("base64url")]);
  await assert.rejects(f.bridge().reconcile(f.noChunks()),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  assert.equal((await f.ledger.getOperationStatus(f.op.operation_id)).status, "committed",
    "a historical signature survives tampering but does not prove current physical bytes");
});
