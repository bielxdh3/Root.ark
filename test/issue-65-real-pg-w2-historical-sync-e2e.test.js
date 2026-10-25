"use strict";

// Opt-in, disposable PostgreSQL 18 + independently spawned attestor + real
// witness SQLite issuer + dedicated historical mTLS + strict Sync v2 consumer.
// No remote/cloud persistence, independent host custody or production claims.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { test } = require("node:test");
const { Pool } = require("pg");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { createSyncV2HistoricalEvidenceProvider } =
  require("../sync-client/rootark-sync-v2-historical-evidence-provider");
const { physicalWriteRequest,
  verifySyncV2HistoricalWitnessAdmission } =
  require("../sync-client/rootark-sync-zk1-physical-binding");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedPgSealedObjectStore } = require("../src/services/zk1SharedPgSealedObjectStore");
const { Zk1SharedPgCiphertextSink } = require("../src/services/zk1SharedPgCiphertextSink");
const { Zk1SharedPgPhysicalInventoryIntent } =
  require("../src/services/zk1SharedPgPhysicalInventoryIntent");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../src/services/zk1SharedPgPhysicalCiphertextVerifier");
const { Zk1PgPhysicalInventoryBridge } = require("../src/services/zk1PgPhysicalInventoryBridge");
const { Zk1DurableContentInventoryLedger } =
  require("../src/services/zk1DurableContentInventoryLedger");
const { createZk1PgPhysicalAttestorHttpsClient } =
  require("../src/services/zk1PgPhysicalAttestorHttpsClient");
const { createZk1ContentInventoryHttpsServer, drainZk1ContentInventoryHttpsServer } =
  require("../src/services/zk1ContentInventoryHttpsServer");
const { createZk1ContentInventoryHttpsClient } =
  require("../src/services/zk1ContentInventoryHttpsClient");
const { Zk1WitnessCasPhysicalAdmission } =
  require("../src/services/zk1WitnessCasPhysicalAdmission");
const { Zk1WitnessCasAnchorFloor, verifyFreshWitnessCasFloor } =
  require("../src/services/zk1WitnessCasAnchorFloor");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");
const { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer } =
  require("../src/services/zk1WitnessHttpsServer");
const { configure: configureStandaloneHistoricalWitness,
  serve: serveStandaloneHistoricalWitness } =
  require("../scripts/zk1-witness-standalone");

const enabled = Boolean(process.env.ROOTARK_ZK1_TEST_PG_URL
  && process.env.ROOTARK_ZK1_RUNTIME_PG_URL
  && process.env.ROOTARK_ZK1_ATTESTOR_PG_URL);
const random = (n) => crypto.randomBytes(n);
const b64 = (v) => Buffer.from(v).toString("base64url");
const wire = (v) => Object.fromEntries(Object.entries(v).map(([key, value]) =>
  [key, Buffer.isBuffer(value) ? b64(value) : value]));
const fingerprint = (bytes) => new crypto.X509Certificate(bytes).fingerprint256;

function startChild(cleanups, file, config, configFile) {
  fs.writeFileSync(configFile, JSON.stringify(config), { mode: 0o600 });
  const child = spawn(process.execPath, [file, configFile], {
    windowsHide: true, stdio: ["ignore", "ignore", "pipe", "ipc"],
    env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot,
      NODE_ENV: "test",
      ROOTARK_ZK1_ATTESTOR_PG_URL: process.env.ROOTARK_ZK1_ATTESTOR_PG_URL,
      NODE_PATH: process.env.NODE_PATH },
  });
  cleanups.push(async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const exited = new Promise((resolve) => child.once("exit", resolve));
    child.kill("SIGTERM");
    const fallback = setTimeout(() => child.kill("SIGKILL"), 5000);
    try { await exited; } finally { clearTimeout(fallback); }
  });
  let stderr = "";
  child.stderr.on("data", (data) => { stderr = (stderr + data.toString()).slice(-500); });
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(Error("PG attestor child startup timed out")), 15000);
    child.once("error", (e) => { clearTimeout(timeout); reject(e); });
    child.once("exit", (code) => {
      clearTimeout(timeout);
      reject(Error("PG attestor child exit " + code + ": " + stderr));
    });
    child.once("message", (v) => {
      clearTimeout(timeout);
      if (!Number.isSafeInteger(v?.port) || v.port < 1) reject(Error("invalid child port"));
      else resolve(v.port);
    });
  });
}

function postHistorical(port, read, who, body, {
  route = "/v1/cas-anchor/historical-admit", dropAck = false,
} = {}) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body));
    const request = https.request({
      hostname: "127.0.0.1", servername: "localhost", port,
      minVersion: "TLSv1.3", rejectUnauthorized: true, method: "POST",
      path: route,
      ca: read("ca.pem"), cert: read(who + ".pem"), key: read(who + ".key"),
      headers: { "content-type": "application/json", "content-length": payload.length },
    }, (response) => {
      if (dropAck) {
        // Headers arrive only AFTER the SQLite FULL commit. Simulate a lost
        // response body without giving the application its signed receipt.
        response.destroy();
        resolve({ status: "DROPPED" });
        return;
      }
      const parts = [];
      response.on("data", (chunk) => parts.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode,
        body: JSON.parse(Buffer.concat(parts).toString("utf8")) }));
    });
    request.once("error", reject);
    request.end(payload);
  });
}

test("PG18 WAL readback -> separate mTLS attestor -> signed inventory -> W2 SQLite historical issuer -> strict Sync v2", {
  skip: !enabled && "not covered: requires disposable PostgreSQL 18 with admin, gate and read-only attestor logins",
}, async (t) => {
  const dir = require("./support/issue-65-private-authority-fixture")
    .createPrivateAuthorityFixture("zk65-real-w2-pg-e2e-");
  const cleanups = [];
  t.after(async () => {
    let failure;
    for (const cleanup of cleanups.reverse()) {
      try { await cleanup(); } catch (error) { failure ||= error; }
    }
    try {
      fs.rmSync(dir, { recursive: true, force: true,
        maxRetries: 10, retryDelay: 100 });
    } catch (error) { failure ||= error; }
    if (failure) throw failure;
  });
  const admin = new Pool({ connectionString: process.env.ROOTARK_ZK1_TEST_PG_URL, max: 1 });
  const gatePool = new Pool({ connectionString: process.env.ROOTARK_ZK1_RUNTIME_PG_URL, max: 2 });
  const proofPool = new Pool({ connectionString: process.env.ROOTARK_ZK1_ATTESTOR_PG_URL, max: 1 });
  cleanups.push(async () => Promise.all([admin.end(), gatePool.end(), proofPool.end()]));
  const version = await admin.query("SHOW server_version");
  assert.match(version.rows[0].server_version, /^18\./, "test must use PostgreSQL 18");
  const [attestorIdentity, gateIdentity] = await Promise.all([
    proofPool.query("SELECT current_user AS role_name, " +
      "has_table_privilege(current_user,'zk1_gate.ciphertext_chunk'," +
      "'INSERT,UPDATE,DELETE') AS can_write"),
    gatePool.query("SELECT current_user AS role_name"),
  ]);
  assert.notEqual(attestorIdentity.rows[0].role_name,
    gateIdentity.rows[0].role_name, "attestor and gate use distinct SQL login roles");
  assert.equal(attestorIdentity.rows[0].can_write, false,
    "attestor login has no direct ciphertext INSERT/UPDATE/DELETE capability");

  const scope = { account_id: random(16), compartment_id: Buffer.from("private"),
    keyring_id: random(16) };
  const scopeKey = scope.account_id.toString("hex") + ":" +
    scope.compartment_id.length.toString(16) + ":" + scope.compartment_id.toString("hex");
  const digest = random(32);
  await admin.query("INSERT INTO zk1_gate.head" +
    " (scope_key,keyring_id,revision,digest,require_physical_inventory_intent)" +
    " VALUES($1,$2,1,$3,TRUE)", [scopeKey, scope.keyring_id, digest]);
  const inventoryKeys = crypto.generateKeyPairSync("ed25519");
  const inventoryKeyId = random(16);
  const ledger = await Zk1DurableContentInventoryLedger.open(path.join(dir, "inventory.sqlite"), {
    bootstrapNew: true, signerKeyId: inventoryKeyId,
    signerPrivateKey: inventoryKeys.privateKey, scope,
  });
  cleanups.push(() => ledger.close());
  const minimumHead = await ledger.readLocalHead();
  const minimumSnapshot = (await ledger.getSnapshot({ nonce: random(32) })).bytes;
  const deviceKeys = crypto.generateKeyPairSync("ed25519");
  const deviceSpki = b64(deviceKeys.publicKey.export({ type: "spki", format: "der" }));
  const policy = { username: "alice", trustedDevicePublicKeys: { "device-a": deviceSpki },
    revokedDeviceIds: [] };
  const createEnvelope = async (contents) => {
    const envelope = createOperation({ operation: "create",
      operationId: "pg18-historical-op", objectId: "pg18-historical-object",
      deviceId: "device-a", compartmentId: "private", keyEpoch: "epoch-1",
      revision: { counter: 1, deviceId: "device-a" },
      metadata: { path: "encrypted/pg18.dat" }, plaintext: Buffer.from(contents),
      fileKey: random(32) });
    envelope.authorization = await createAuthorizationProof(envelope, {
      username: "alice", privateKey: deviceKeys.privateKey,
      publicKey: deviceSpki, expiresAt: Date.now() + 120000 });
    return envelope;
  };
  const envelope = await createEnvelope("opaque encrypted data v1");
  const physical = await physicalWriteRequest(envelope, scope, minimumHead.sequence,
    minimumHead.root, digest, policy);
  const gate = new Zk1SharedPgGateAuthority({ pool: gatePool });
  const sealed = new Zk1SharedPgSealedObjectStore({ pool: gatePool });
  const gateClient = {
    beginIoAdmission: (op) => gate.beginIoAdmission({ ...op, principal: "pg18-w12-lab" }),
    putCiphertextChunk: (op, index, bytes) =>
      gate.putCiphertextChunk({ ...op, principal: "pg18-w12-lab" }, index, bytes),
    sealCiphertextObject: (op, count, root) => sealed.seal({ ...op,
      principal: "pg18-w12-lab", expectedChunkCount: count, expectedRootHash: root }),
    finishIoAdmission: (op) => gate.finishIoAdmission({ ...op, principal: "pg18-w12-lab" }),
  };
  const bridge = new Zk1PgPhysicalInventoryBridge({
    sink: new Zk1SharedPgCiphertextSink({ gateClient }),
    verifier: new Zk1SharedPgPhysicalCiphertextVerifier({ pool: proofPool }),
    intentAuthority: new Zk1SharedPgPhysicalInventoryIntent({ pool: gatePool }),
    ledger, pinnedPublicKey: inventoryKeys.publicKey, pinnedSignerKeyId: inventoryKeyId,
  });
  const published = await bridge.putAndAttest(physical);
  assert.equal(published.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  assert.equal(published.localPgWalFlushConfirmed, true);
  const committed = await ledger.getOperationStatus(physical.operation.operation_id);
  assert.equal(committed.status, "committed");
  const persisted = await admin.query("SELECT generation,expected_chunks FROM zk1_gate.sealed_object" +
    " WHERE scope_key=$1 AND object_id=$2",
  [scopeKey, b64(physical.operation.object_id)]);
  assert.equal(persisted.rowCount, 1);
  assert.equal(persisted.rows[0].expected_chunks, physical.chunks.length);

  generateNativeFixtureCertificates(dir, { caSubject: "ZK65 real PG W2 historical E2E",
    servers: ["attestor", "inventory", "witness"],
    clients: ["inventory-service", "reader", "witness-pg", "historical", "denied"] });
  for (const name of fs.readdirSync(dir)) {
    if (/\.(?:pem|key)$/.test(name)) fs.chmodSync(path.join(dir, name), 0o600);
  }
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const physicalSigner = crypto.generateKeyPairSync("ed25519");
  assert.equal(crypto.KeyObject.prototype.equals.call(physicalSigner.publicKey,
    inventoryKeys.publicKey), false, "attestor and inventory signer identities differ");
  const signerPath = path.join(dir, "attestor-signer.key");
  fs.writeFileSync(signerPath, physicalSigner.privateKey.export({
    type: "pkcs8", format: "pem" }), { mode: 0o600 });
  const cfg = { useRealPg: true, scope: wire(scope), operation: wire(physical.operation),
    digest: b64(digest), root: b64(physical.expectedRootHash),
    chunks: physical.expectedChunkCount, caPath: path.join(dir, "ca.pem"),
    serverKeyPath: path.join(dir, "attestor.key"),
    serverCertPath: path.join(dir, "attestor.pem"), signerKeyPath: signerPath,
    allowedFingerprint: fingerprint(read("inventory-service.pem")),
    additionalFingerprint: fingerprint(read("witness-pg.pem")) };
  const attestorPort = await startChild(cleanups,
    path.join(__dirname, "../lab/issue-65-packet-b/pg-physical-attestor-child.js"),
    cfg, path.join(dir, "attestor-child.json"));
  const physicalClient = (cert) => createZk1PgPhysicalAttestorHttpsClient({
    endpoint: `https://localhost:${attestorPort}`, ca: read("ca.pem"),
    clientCert: read(cert + ".pem"), clientKey: read(cert + ".key"),
    serverFingerprint256: fingerprint(read("attestor.pem")),
  });
  // Actual failed SQL readback: the operation was never physically written.
  // A separately authenticated client cannot invent a PG row with a signature.
  await assert.rejects(physicalClient("witness-pg").requestAttestation({
    scope, operation: { ...physical.operation, operation_id: random(16) }, nonce: random(32),
  }), /ZK_PHYSICAL_ATTESTOR_TRANSPORT_UNAVAILABLE/);
  await assert.rejects(physicalClient("denied").requestAttestation({
    scope, operation: physical.operation, nonce: random(32),
  }), /ZK_PHYSICAL_ATTESTOR_TRANSPORT_UNAVAILABLE/);

  const inventoryServer = createZk1ContentInventoryHttpsServer({
    key: read("inventory.key"), cert: read("inventory.pem"), clientCa: read("ca.pem"),
    ledger, physicalAttestorClient: physicalClient("inventory-service"),
    pinnedPhysicalAttestorPublicKey: physicalSigner.publicKey,
    pinnedInventorySignerPublicKey: inventoryKeys.publicKey,
    principals: { [fingerprint(read("reader.pem"))]: {
      roles: ["read", "status"], scopes: [wire(scope)] } },
  });
  await new Promise((resolve) => inventoryServer.listen(0, "127.0.0.1", resolve));
  cleanups.push(() => drainZk1ContentInventoryHttpsServer(inventoryServer));
  const inventoryReader = createZk1ContentInventoryHttpsClient({
    endpoint: `https://localhost:${inventoryServer.address().port}`,
    ca: read("ca.pem"), clientKey: read("reader.key"), clientCert: read("reader.pem"),
    serverFingerprint256: fingerprint(read("inventory.pem")),
    inventoryPublicKey: inventoryKeys.publicKey, inventorySignerKeyId: inventoryKeyId,
    physicalAttestorPublicKey: physicalSigner.publicKey,
  });
  const owner = crypto.generateKeyPairSync("ed25519");
  const status = crypto.generateKeyPairSync("ed25519");
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = random(16), statusKeyId = random(16);
  const admission = new Zk1WitnessCasPhysicalAdmission({
    pinnedOwnerPublicKey: owner.publicKey,
    pinnedInventoryPublicKey: inventoryKeys.publicKey,
    pinnedInventorySignerKeyId: inventoryKeyId,
    pinnedPhysicalAttestorPublicKey: physicalSigner.publicKey,
    physicalAttestorClient: physicalClient("witness-pg"),
    inventoryClient: inventoryReader, trustedMinimumInventoryHead: minimumHead,
    trustedMinimumInventorySnapshot: minimumSnapshot,
  });
  const witnessPath = path.join(dir, "witness.sqlite");
  const witnessSigningPath = path.join(dir, "witness-signing.key");
  const statusPublicPath = path.join(dir, "status-verifier.pub");
  fs.writeFileSync(witnessSigningPath, witnessKeys.privateKey.export({
    type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(statusPublicPath, status.publicKey.export({
    type: "spki", format: "pem" }), { mode: 0o600 });
  const genesisFloor = { sequence: 0, lastHash: "0".repeat(64) };
  const config = {
    bootstrapNew: true, listenHost: "127.0.0.1", listenPort: 0,
    dbPath: path.join(dir, "witness-general.sqlite"),
    witnessKeyId: b64(witnessKeyId), witnessPrivateKeyPath: witnessSigningPath,
    statusKeyId: b64(statusKeyId), statusPublicKeyPath: statusPublicPath,
    serverKeyPath: path.join(dir, "witness.key"),
    serverCertPath: path.join(dir, "witness.pem"),
    clientCaPath: path.join(dir, "ca.pem"),
    // Mutable JSON NEVER contains the privileged historical principal.
    principals: { [fingerprint(read("denied.pem"))]: {
      roles: ["head"], scopes: [wire(scope)] } },
    cas: { endpoint: "https://localhost:44444/v1/terminal",
      caPath: path.join(dir, "ca.pem"), clientKeyPath: path.join(dir, "denied.key"),
      clientCertPath: path.join(dir, "denied.pem"),
      serverFingerprint256: fingerprint(read("witness.pem")) },
    casAnchorFloor: { dbPath: witnessPath, trustedMinimumHead: genesisFloor },
  };
  const trustedHistorical = {
    physicalAdmission: admission,
    witnessPublicKey: witnessKeys.publicKey,
    statusPublicKey: status.publicKey,
    trustedMinimumHead: { ...genesisFloor,
      physicalFenceDigest: crypto.createHash("sha256").update("").digest("hex") },
    trustedHistoricalAdmissionHead: { sequence: 0, lastHash: "0".repeat(64) },
    trustedSyncDevicePolicyProvider: () => ({ username: policy.username,
      trustedDevicePublicKeys: { ...policy.trustedDevicePublicKeys },
      revokedDeviceIds: [...policy.revokedDeviceIds] }),
    principals: { [fingerprint(read("historical.pem"))]: {
      roles: ["cas-historical-admit"], scopes: [wire(scope)] } },
  };
  assert.throws(() => configureStandaloneHistoricalWitness({ ...config,
    casAnchorFloor: undefined }, { historicalAuthority: trustedHistorical }),
  /WITNESS_STARTUP_FAILED|WITNESS_API_INVALID/,
  "external issuer enrollment cannot be silently disabled by removing JSON casAnchorFloor");
  assert.equal(fs.existsSync(config.dbPath), false);
  assert.throws(() => configureStandaloneHistoricalWitness({ ...config,
    principals: { ...config.principals, ...trustedHistorical.principals } }),
  /WITNESS_STARTUP_FAILED/,
  "JSON-only historical principal cannot become authority, even with valid keys on disk");
  assert.equal(fs.existsSync(config.dbPath), false);
  assert.throws(() => configureStandaloneHistoricalWitness(config, {
    historicalAuthority: { ...trustedHistorical,
      witnessPublicKey: crypto.generateKeyPairSync("ed25519").publicKey } }),
  /WITNESS_STARTUP_FAILED/,
  "external independent identity pin rejects a substituted witness signing key");
  assert.throws(() => configureStandaloneHistoricalWitness(config, {
    historicalAuthority: { ...trustedHistorical,
      trustedMinimumHead: { ...trustedHistorical.trustedMinimumHead,
        lastHash: "f".repeat(64) } } }),
  /WITNESS_STARTUP_FAILED/,
  "editable JSON head cannot silently override externally held floor minimum");
  assert.throws(() => configureStandaloneHistoricalWitness(config, {
    historicalAuthority: { ...trustedHistorical,
      trustedHistoricalAdmissionHead: { sequence: 1, lastHash: "f".repeat(64) } } }),
  /WITNESS_STARTUP_FAILED/,
  "bootstrap cannot install independently claimed nonzero historical high-water");
  assert.equal(fs.existsSync(config.dbPath), false);
  for (const needed of [config.cas.caPath, config.cas.clientKeyPath,
    config.cas.clientCertPath, config.witnessPrivateKeyPath]) {
    assert.ok(fs.existsSync(needed) && fs.statSync(needed).size > 0,
      "standalone fixture requires existing certificate and signer files");
  }
  const { floor: witness, ledger: standaloneLedger, server: witnessServer } =
    serveStandaloneHistoricalWitness(config, { historicalAuthority: trustedHistorical });
  cleanups.push(() => standaloneLedger.close());
  cleanups.push(() => witness.close());
  assert.equal(witness.supportsClientHistoricalNonce, true);
  const anchor = new Zk1CasTerminalAnchor(path.join(dir, "cas-anchor.log"), {
    bootstrapNew: true, statusKeyId, statusPrivateKey: status.privateKey });
  const reservation = random(16);
  const query = { ...scope, reservation_id: reservation };
  const ticket = random(80), manifest = random(120);
  anchor.prepare(query, ticket, "committed", manifest);
  await anchor.append(query, ticket, "committed", manifest, random(64));
  const record = fs.readFileSync(anchor.filename, "utf8").trimEnd().split("\n").at(-1);
  const binding = { recordHash: crypto.createHash("sha256").update(record).digest("hex"),
    scope: wire(scope), operation: wire(physical.operation),
    inventoryReceipt: b64(committed.proof) };
  const evidence = { ...binding, ownerSignature: b64(crypto.sign(null,
    Buffer.concat([Buffer.from("Root.ark/zk-1/cas-witness-physical-owner-binding/v1\0"),
      Buffer.from(JSON.stringify(binding))]), owner.privateKey)) };
  const witnessed = await witness.advanceAttested({ records: [record], evidence: [evidence] });
  assert.equal(witnessed.sequence, 1);
  const challengeForFloor = random(32);
  const trustedMinimumFloor = verifyFreshWitnessCasFloor({
    signed: witness.freshHead({ nonce: challengeForFloor }), nonce: challengeForFloor,
    pinnedWitnessPublicKey: witnessKeys.publicKey,
    pinnedWitnessKeyId: witnessKeyId, pinnedStatusKeyId: statusKeyId,
    requirePhysicalAdmission: true,
  });
  if (!witnessServer.listening) {
    await new Promise((resolve, reject) => {
      witnessServer.once("listening", resolve);
      witnessServer.once("error", reject);
    });
  }
  cleanups.push(() => drainZk1WitnessHttpsServer(witnessServer));
  const body = (candidate, nonce) => ({
    envelope: candidate, scope: wire(scope),
    expectedSequence: minimumHead.sequence, expectedRoot: b64(minimumHead.root),
    inventoryReceipt: b64(committed.proof), nonce: b64(nonce),
  });
  const port = witnessServer.address().port;
  const challenge = random(32);
  assert.equal((await postHistorical(port, read, "denied", body(envelope, challenge))).status, 403);
  const changed = await createEnvelope("changed envelope ciphertext after independent PG seal");
  const rejected = await postHistorical(port, read, "historical", body(changed, random(32)));
  assert.notEqual(rejected.status, 200, "real W2 must reject a physically absent ciphertext");
  assert.equal(witness.historicalAdmissionHead().sequence, 0,
    "failed PG challenge cannot create a durable SQLite historical admission");
  const lost = await postHistorical(port, read, "historical", body(envelope, challenge),
    { dropAck: true });
  assert.equal(lost.status, "DROPPED", "client never receives the signed receipt body");
  assert.equal(witness.historicalAdmissionHead().sequence, 1,
    "witness persisted original admission before HTTPS response was lost");
  const recoveryChallenge = random(32);
  const clientProvider = createSyncV2HistoricalEvidenceProvider({
    endpoint: `https://127.0.0.1:${port}`,
    ca: read("ca.pem"), clientKey: read("historical.key"),
    clientCert: read("historical.pem"),
    serverFingerprint256: fingerprint(read("witness.pem")),
    trustedInventoryEvidenceProvider: async () => ({
      scope, expectedSequence: minimumHead.sequence,
      expectedRoot: minimumHead.root, receipt: committed.proof,
    }),
    pinnedInventoryPublicKey: inventoryKeys.publicKey,
    pinnedInventorySignerKeyId: inventoryKeyId,
  });
  const recoveredClientProof = await clientProvider(envelope, {
    nonce: recoveryChallenge, recovery: true,
  });
  const accepted = { body: {
    admission: recoveredClientProof.admission,
    freshFloor: recoveredClientProof.freshFloor,
    physicalAttestation: recoveredClientProof.physicalAttestation.toString("base64url"),
  } };
  assert.equal(accepted.body.freshFloor.nonce, b64(recoveryChallenge),
    "real Sync client adapter re-proves FULL durable original with new PG challenge");
  assert.equal(witness.historicalAdmissionHead().sequence, 1);
  assert.deepEqual(witness.historicalAdmissionForOperation(
    physical.operation.operation_id).admission, accepted.body.admission,
  "SQLite persisted the exact signed admission");
  const strict = (nonce, extra = {}) => verifySyncV2HistoricalWitnessAdmission({
    envelope, scope, expectedSequence: minimumHead.sequence, expectedRoot: minimumHead.root,
    receipt: committed.proof,
    physicalAttestation: Buffer.from(accepted.body.physicalAttestation, "base64url"),
    nonce, pinnedInventoryPublicKey: inventoryKeys.publicKey,
    pinnedInventorySignerKeyId: inventoryKeyId,
    pinnedPhysicalAttestorPublicKey: physicalSigner.publicKey,
    localTrustedDevicePolicy: policy,
    trustedCurrentDevicePolicyProvider: () => ({ username: policy.username,
      trustedDevicePublicKeys: { ...policy.trustedDevicePublicKeys },
      revokedDeviceIds: [...policy.revokedDeviceIds] }),
    admission: accepted.body.admission, freshFloor: accepted.body.freshFloor,
    pinnedWitnessPublicKey: witnessKeys.publicKey,
    witnessKeyId, statusKeyId, trustedMinimumFloor, ...extra,
  });
  const verified = await strict(recoveryChallenge);
  assert.equal(verified.authorizesHistoricalRead, true);
  assert.equal(verified.localPgReadbackVerified, true);
  assert.equal(verified.externalDurabilityProven, false);
  assert.equal(verified.authorizesIo, false);
  await assert.rejects(strict(challenge, {
    trustedCurrentDevicePolicyProvider: () => ({ username: policy.username,
      trustedDevicePublicKeys: { ...policy.trustedDevicePublicKeys },
      revokedDeviceIds: ["device-a"] }),
  }), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/,
  "current independent revocation must reject otherwise valid PG18 historical proofs");
  await assert.rejects(strict(random(32)), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/,
    "another nonce cannot reuse the true PG18 attestation or signed W2 floor");
  await assert.rejects(strict(challenge), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/,
    "lost original challenge cannot reuse recovered signed physical proof");
  const replay = await postHistorical(port, read, "historical", body(envelope, challenge));
  assert.notEqual(replay.status, 200, "durable SQLite issuer must deny duplicate operation");
  assert.equal(witness.historicalAdmissionHead().sequence, 1);
});
