"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const { spawn } = require("node:child_process");
const z = require("../src/crypto/rootark-zk-1");
const ownerManifest = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { createAuthenticatedOpaqueCatalogArchiveV2 } =
  require("../src/crypto/rootark-zk1-opaque-catalog-checkpoint-v2");
const { Zk1OpaqueCatalogCasLedger } =
  require("../src/services/zk1OpaqueCatalogCasLedger");
const { createZk1OpaqueCatalogCasHttpsServer } =
  require("../src/services/zk1OpaqueCatalogCasHttpsServer");
const { createZk1OpaqueCatalogCasHttpsClient } =
  require("../src/services/zk1OpaqueCatalogCasHttpsClient");
const { Zk1OpaqueCatalogIndependentFloorLedger,
  createZk1OpaqueCatalogIndependentFloorHttpsClient,
  createZk1OpaqueCatalogIndependentFloorHttpsServer } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { OpaqueCheckpointV2Authority,
  createOpaqueCheckpointV2HttpsServer, createOpaqueCheckpointV2HttpsClient,
  signCheckpointOwnerApprovalV2, createOpaqueCheckpointV2Coordinator } =
  require("../src/services/zk1OpaqueCheckpointV2Remote");
const { Zk1OpaqueCheckpointV2Client } =
  require("../src/services/zk1OpaqueCheckpointV2Client");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");

const PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const BASE_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-base/v1\0");
const WITNESS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");
const fp = (key) => crypto.createHash("sha256")
  .update(key.export({ type: "spki", format: "der" })).digest();
const hd = (raw, signature) => crypto.createHash("sha256")
  .update(HEAD_DOMAIN).update(raw).update(signature).digest();
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const encoded = (val) => Buffer.from(val).toString("base64url");
const keyFromDevice = (device) => crypto.createPublicKey({
  key: Buffer.concat([PREFIX, Buffer.from(device.authorization_public_key)]),
  format: "der", type: "spki",
});

test("v2 independent durable endorsements: authenticated 128->129, mTLS, owner revocation, uncertain commit ACK, restart", {
  timeout: 150000,
}, async (t) => {
  const cleanupServers = [];
  const cleanupDatabases = [];
  try {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-checkpoint-v2-remote-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  generateNativeFixtureCertificates(dir, { caSubject: "ZK65 Checkpoint Remote",
    servers: ["v1cas", "v1floor", "v2cas", "v2floor"],
    clients: ["client"] });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const x509 = (name) => new crypto.X509Certificate(read(name)).fingerprint256;
  const state = await fixtures.createInitialState(1);
  const scope = state.scope;
  const witness = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const genesis = await ownerManifest.recoveryManifestDigestV2(state.baseManifest);
  const signedBase = { type: "rootark-recovery-witness-base/v1",
    witness_key_id: witnessKeyId, ...scope, revision: 1,
    manifest_digest: genesis, witness_sequence: 1,
    nonce: crypto.randomBytes(32), observed_at: 1000, status: "committed" };
  state.baseReceipt = { ...signedBase, signature: crypto.sign(null,
    Buffer.concat([BASE_DOMAIN, await z.encodeDeterministic(signedBase)]),
    witness.privateKey) };
  state.pinnedWitness = { keyId: witnessKeyId, publicKey: witness.publicKey };
  await fixtures.appendDeviceEnrollment(state, 1);
  const keys = (device) => state.actors.get(
    Buffer.from(device.authorization_key_id).toString("hex"));
  const deviceA = state.headManifest.devices[0];
  const deviceB = state.headManifest.devices[1];
  const signerA = keyFromDevice(deviceA);
  const signerB = keyFromDevice(deviceB);
  const v1CasKeys = crypto.generateKeyPairSync("ed25519");
  const v1FloorKeys = crypto.generateKeyPairSync("ed25519");
  const v2CasKeys = crypto.generateKeyPairSync("ed25519");
  const v2FloorKeys = crypto.generateKeyPairSync("ed25519");
  // The owner's checkpoint approval key is B's *currently authorized*
  // Ed25519 device key in the independent owner-rooted recovery history.
  const owner = { privateKey: keys(deviceB), publicKey: signerB };
  const checkpoint = crypto.generateKeyPairSync("ed25519");
  const revoked = crypto.generateKeyPairSync("ed25519");
  const initialManifest = state.headManifest;
  const now = () => Math.floor(Date.now() / 1000);
  async function witnessed(nonce) {
    const manifest = state.headManifest;
    const body = { type: "rootark-recovery-witness-head/v1",
      witness_key_id: witnessKeyId, ...scope,
      current_revision: manifest.revision,
      current_manifest_digest: await ownerManifest.recoveryManifestDigestV2(manifest),
      witness_sequence: manifest.revision, nonce, observed_at: now(),
      status: "committed", pending_reservation_id: null };
    return z.encodeDeterministic({ ...body, signature: crypto.sign(null,
      Buffer.concat([WITNESS_DOMAIN, await z.encodeDeterministic(body)]),
      witness.privateKey) });
  }
  async function evidence() {
    return Buffer.from(await z.encodeDeterministic({
      baseManifest: state.baseManifest, baseReceipt: state.baseReceipt,
      transitions: state.transitions,
      packageEnvelopes: state.packageEnvelopes,
      witnessHeadRaw: await witnessed(crypto.randomBytes(32)),
    }));
  }
  const trust = { genesisDigest: genesis, pinnedWitness: state.pinnedWitness,
    minimumHead: { revision: 1, witnessSequence: 1, digest: genesis },
    freshWitnessHead: ({ nonce }) => witnessed(nonce) };
  function mkFloorClient(keys, casKeys, server) {
    return createZk1OpaqueCatalogIndependentFloorHttpsClient({
      endpoint: "https://127.0.0.1:" + server.address().port + "/",
      ca: read("ca.pem"), clientKey: read("client.key"),
      clientCert: read("client.pem"), serverFingerprint256: x509("v1floor.pem"),
      floorPublicKey: keys.publicKey, casSignerPublicKey: casKeys.publicKey,
      trustedScope: scope,
    });
  }
  const floorLedger = new Zk1OpaqueCatalogIndependentFloorLedger(
    path.join(dir, "v1-floor.sqlite"), { bootstrapNew: true, trustedScope: scope,
      signingPrivateKey: v1FloorKeys.privateKey, casSignerPublicKey: v1CasKeys.publicKey,
      catalogSignerPublicKey: signerA });
  cleanupDatabases.push(floorLedger);
  const floorServer = createZk1OpaqueCatalogIndependentFloorHttpsServer({
    ledger: floorLedger, key: read("v1floor.key"), cert: read("v1floor.pem"),
    clientCa: read("ca.pem"), authorizedClientFingerprint256: x509("client.pem") });
  await new Promise((resolve) => floorServer.listen(0, "127.0.0.1", resolve));
  cleanupServers.push(floorServer);
  t.after(() => {
    floorServer.closeAllConnections(); floorServer.close(); floorLedger.close();
  });
  const v1Floor = mkFloorClient(v1FloorKeys, v1CasKeys, floorServer);
  const casLedger = new Zk1OpaqueCatalogCasLedger(
    path.join(dir, "v1-cas.sqlite"), { bootstrapNew: true,
      signingPrivateKey: v1CasKeys.privateKey, catalogSignerPublicKey: signerA,
      trustedScope: scope, minimumHead: { sequence: 0, digest: Buffer.alloc(32) },
      independentFloor: v1Floor });
  await casLedger.ready;
  cleanupDatabases.push(casLedger);
  const casServer = createZk1OpaqueCatalogCasHttpsServer({
    ledger: casLedger, key: read("v1cas.key"), cert: read("v1cas.pem"),
    clientCa: read("ca.pem"), authorizedClientFingerprint256: x509("client.pem") });
  await new Promise((resolve) => casServer.listen(0, "127.0.0.1", resolve));
  cleanupServers.push(casServer);
  t.after(() => { casServer.closeAllConnections(); casServer.close(); casLedger.close(); });
  const v1Cas = createZk1OpaqueCatalogCasHttpsClient({
    endpoint: "https://127.0.0.1:" + casServer.address().port + "/",
    ca: read("ca.pem"), clientKey: read("client.key"),
    clientCert: read("client.pem"), serverFingerprint256: x509("v1cas.pem"),
    authorityPublicKey: v1CasKeys.publicKey });

  // Real durable v1 monotonic history to absolute 128, not a forged bootstrap.
  let previousDigest = Buffer.alloc(32);
  let lastHead;
  for (let seq = 1; seq <= 128; seq++) {
    const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
      sequence: seq, previous_digest: previousDigest,
      manifest_revision: 1, manifest_digest: crypto.randomBytes(32),
      epoch: 1, signer_device_id: deviceA.device_id,
      total_count: 0, page_digests: [], issued_at: now() };
    const head = Buffer.from(await z.encodeDeterministic(header));
    const signature = crypto.sign(null, Buffer.concat([HEAD_DOMAIN, head]), keys(deviceA));
    const digest = hd(head, signature);
    await v1Cas.compareAndSwap({ scope, expectedSequence: seq - 1,
      expectedDigest: previousDigest, nextSequence: seq, nextDigest: digest,
      headBytes: head, headSignature: signature, pageBodies: [],
      nonce: crypto.randomBytes(32) });
    previousDigest = digest;
    lastHead = { header: head, signature, sequence: seq, page_bodies: [] };
  }
  assert.equal(floorLedger.inspect().sequence, 128);
  console.error("STAGE: v1-128 committed");
  const oldDigest = previousDigest;
  const checkpoint128 = await createAuthenticatedOpaqueCatalogArchiveV2({
    scope, records: [lastHead], previousSequence: 127,
    previousDigest: (await z.decodeDeterministic(lastHead.header)).previous_digest,
    previousCheckpointDigest: crypto.randomBytes(32),
    resolveCatalogSigner: async () => signerA,
    checkpointPrivateKey: checkpoint.privateKey, issuedAt: now() });
  const oldCheckpoint = checkpoint128.checkpointDigest;
  await fixtures.appendDeviceRevocation(state, deviceA.device_id);
  // B is enrolled and active, A is owner-revoked at the later epoch.
  assert.equal(state.headManifest.devices.find((d) =>
    d.device_id === deviceA.device_id).revoked_at_epoch !== null, true);
  const nextHeader = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
    sequence: 129, previous_digest: oldDigest,
    manifest_revision: Number(state.headManifest.revision),
    manifest_digest: await ownerManifest.recoveryManifestDigestV2(state.headManifest),
    epoch: Number(state.headManifest.current_epoch),
    signer_device_id: deviceB.device_id,
    total_count: 0, page_digests: [], issued_at: now() };
  const nextRaw = Buffer.from(await z.encodeDeterministic(nextHeader));
  const nextSig = crypto.sign(null, Buffer.concat([HEAD_DOMAIN, nextRaw]), keys(deviceB));
  const newDigest = hd(nextRaw, nextSig);
  const records = [{ header: nextRaw, signature: nextSig, sequence: 129, page_bodies: [] }];
  const checkpoint129 = await createAuthenticatedOpaqueCatalogArchiveV2({
    scope, records, previousSequence: 128, previousDigest: oldDigest,
    previousCheckpointDigest: oldCheckpoint,
    resolveCatalogSigner: async () => signerB,
    checkpointPrivateKey: checkpoint.privateKey, issuedAt: now() });
  async function makeIntent(operationId = crypto.randomBytes(32), alter = {}) {
    const approval = { type: "rootark-opaque-checkpoint-remote-owner-approval/v2",
      ...scope, operation_id: operationId, checkpoint_digest: checkpoint129.checkpointDigest,
      previous_sequence: 128, previous_digest: oldDigest,
      previous_checkpoint_digest: oldCheckpoint, final_sequence: 129,
      final_digest: newDigest, cas_signer_fp: fp(v2CasKeys.publicKey),
      floor_signer_fp: fp(v2FloorKeys.publicKey),
      checkpoint_signer_fp: fp(checkpoint.publicKey), issued_at: now(), ...alter };
    const signed = await signCheckpointOwnerApprovalV2(approval, owner.privateKey);
    return Buffer.from(await z.encodeDeterministic({
      type: "rootark-opaque-checkpoint-remote-intent/v2", ...scope,
      operation_id: operationId, checkpoint_bytes: checkpoint129.checkpointBytes,
      checkpoint_signature: checkpoint129.checkpointSignature,
      records, previous_sequence: 128, previous_digest: oldDigest,
      previous_checkpoint_digest: oldCheckpoint,
      owner_approval: signed.raw, owner_signature: signed.signature,
      owner_evidence: await evidence(),
    }));
  }
  const intent = await makeIntent();
  const authorityOptions = { scope, checkpointPublicKey: checkpoint.publicKey,
    casSignerPublicKey: v2CasKeys.publicKey,
    floorSignerPublicKey: v2FloorKeys.publicKey,
    ownerPublicKey: owner.publicKey, ownerTrust: trust,
    baseDigest: oldDigest, baseCheckpoint: oldCheckpoint };
  let floor2 = new OpaqueCheckpointV2Authority(path.join(dir, "v2-floor.sqlite"), {
    ...authorityOptions, role: "FLOOR", bootstrapNew: true,
    signingPrivateKey: v2FloorKeys.privateKey });
  let cas2 = new OpaqueCheckpointV2Authority(path.join(dir, "v2-cas.sqlite"), {
    ...authorityOptions, role: "CAS", bootstrapNew: true,
    signingPrivateKey: v2CasKeys.privateKey });
  t.after(() => { floor2.close(); cas2.close(); });
  cleanupDatabases.push(floor2, cas2);
  let floor2Server, cas2Server;
  async function serveV2({ restart = false, dropCommit = false }) {
    floor2Server = createOpaqueCheckpointV2HttpsServer({
      ledger: floor2, tlsKey: read("v2floor.key"), tlsCert: read("v2floor.pem"),
      clientCa: read("ca.pem"), clientFingerprint256: x509("client.pem") });
    cas2Server = createOpaqueCheckpointV2HttpsServer({
      ledger: cas2, tlsKey: read("v2cas.key"), tlsCert: read("v2cas.pem"),
      clientCa: read("ca.pem"), clientFingerprint256: x509("client.pem"),
      dropAfterCommitOnce: dropCommit });
    for (const server of [floor2Server, cas2Server])
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    cleanupServers.push(floor2Server, cas2Server);
    const common = { ca: read("ca.pem"), clientKey: read("client.key"),
      clientCert: read("client.pem"), casPublicKey: v2CasKeys.publicKey,
      floorPublicKey: v2FloorKeys.publicKey, scope };
    const floorClient = createOpaqueCheckpointV2HttpsClient({
      ...common, endpoint: "https://127.0.0.1:" + floor2Server.address().port + "/",
      authorityPublicKey: v2FloorKeys.publicKey,
      serverFingerprint256: x509("v2floor.pem") });
    const casClient = createOpaqueCheckpointV2HttpsClient({
      ...common, endpoint: "https://127.0.0.1:" + cas2Server.address().port + "/",
      authorityPublicKey: v2CasKeys.publicKey,
      serverFingerprint256: x509("v2cas.pem") });
    const coordinator = createOpaqueCheckpointV2Coordinator({
      casClient, floorClient, v1CasClient: v1Cas, v1FloorClient: v1Floor,
      trustedScope: scope, expectedV1Digest: oldDigest,
      expectedV1Checkpoint: oldCheckpoint });
    return { coordinator, floorClient, casClient };
  }
  async function stopV2() {
    for (const server of [floor2Server, cas2Server]) {
      server.closeAllConnections(); server.close();
    }
    floor2.close(); cas2.close();
  }
  let handles = await serveV2({ dropCommit: true });
  assert.throws(() => createOpaqueCheckpointV2Coordinator({
    casClient: { role: "CAS", publicKey: v2CasKeys.publicKey,
      head: async () => ({ state: "FINALIZED", sequence: 129 }) },
    floorClient: handles.floorClient, trustedScope: scope,
    expectedV1Digest: oldDigest, expectedV1Checkpoint: oldCheckpoint,
    v1CasClient: v1Cas, v1FloorClient: v1Floor,
  }), /ZK_CHECKPOINT_V2_UNAVAILABLE/,
  "injected fake CAS client cannot manufacture a finalized global checkpoint");
  const clientOptions = (endpoints, journalPath, bootstrapNew) => ({
    journalPath, bootstrapNew, trustedScope: scope,
    expectedV1Digest: oldDigest, expectedV1Checkpoint: oldCheckpoint,
    v1CasClient: v1Cas, v1FloorClient: v1Floor,
    casClient: endpoints.casClient, floorClient: endpoints.floorClient,
    checkpointPublicKey: checkpoint.publicKey, ownerPublicKey: owner.publicKey,
    catalogPublicKey: signerB, ownerTrust: trust,
  });
  const journal = path.join(dir, "v2-device-rollover.sqlite");
  let client = new Zk1OpaqueCheckpointV2Client(clientOptions(handles, journal, true));
  t.after(() => client.close());
  await assert.rejects(client.read(), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
    "unsigned local sequence bump must never provide a v2 read");
  // Cryptographically valid-but-revoked device A must not authorize seq129,
  // even if the newly enrolled B independently signs the owner approval.
  const retiredHeader = { ...nextHeader, signer_device_id: deviceA.device_id };
  const retiredBytes = Buffer.from(await z.encodeDeterministic(retiredHeader));
  const retiredSignature = crypto.sign(null, Buffer.concat([HEAD_DOMAIN, retiredBytes]),
    keys(deviceA));
  const retiredRecord = { sequence: 129, header: retiredBytes,
    signature: retiredSignature, page_bodies: [] };
  const retiredCheckpoint = await createAuthenticatedOpaqueCatalogArchiveV2({
    scope, records: [retiredRecord], previousSequence: 128, previousDigest: oldDigest,
    previousCheckpointDigest: oldCheckpoint, resolveCatalogSigner: async () => signerA,
    checkpointPrivateKey: checkpoint.privateKey, issuedAt: now() });
  const retiredApproval = await signCheckpointOwnerApprovalV2({
    type: "rootark-opaque-checkpoint-remote-owner-approval/v2", ...scope,
    operation_id: crypto.randomBytes(32),
    checkpoint_digest: retiredCheckpoint.checkpointDigest, previous_sequence: 128,
    previous_digest: oldDigest, previous_checkpoint_digest: oldCheckpoint,
    final_sequence: 129, final_digest: hd(retiredBytes, retiredSignature),
    cas_signer_fp: fp(v2CasKeys.publicKey), floor_signer_fp: fp(v2FloorKeys.publicKey),
    checkpoint_signer_fp: fp(checkpoint.publicKey), issued_at: now(),
  }, owner.privateKey);
  const forged = await z.decodeDeterministic(intent);
  forged.operation_id = (await z.decodeDeterministic(retiredApproval.raw)).operation_id;
  forged.records = [retiredRecord];
  forged.checkpoint_bytes = retiredCheckpoint.checkpointBytes;
  forged.checkpoint_signature = retiredCheckpoint.checkpointSignature;
  forged.owner_approval = retiredApproval.raw;
  forged.owner_signature = retiredApproval.signature;
  await assert.rejects(handles.floorClient.prepare(
    Buffer.from(await z.encodeDeterministic(forged))), /ACK_UNCERTAIN/);
  assert.equal((await handles.floorClient.head()).state, "V1_BASELINE");
  const wrongOwner = await z.decodeDeterministic(intent);
  wrongOwner.owner_signature = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/opaque-checkpoint-remote/owner-approval/v2\0"),
    wrongOwner.owner_approval]), revoked.privateKey);
  await assert.rejects(handles.floorClient.prepare(
    Buffer.from(await z.encodeDeterministic(wrongOwner))), /ACK_UNCERTAIN/);
  assert.equal((await handles.floorClient.head()).state, "V1_BASELINE");
  console.error("STAGE: v2 clients started, forged signer denied");
  t.after(() => {
    for (const server of [floor2Server, cas2Server])
      if (server.listening) { server.closeAllConnections(); server.close(); }
  });
  await assert.rejects(client.publishSignedIntent(intent), /ACK_UNCERTAIN/);
  console.error("STAGE: dropped ACK verified");
  assert.equal((await handles.floorClient.head()).state, "PREPARED");
  assert.equal((await handles.casClient.head()).state, "CAS_COMMITTED");
  await stopV2();
  floor2 = new OpaqueCheckpointV2Authority(path.join(dir, "v2-floor.sqlite"), {
    ...authorityOptions, role: "FLOOR", bootstrapNew: false,
    signingPrivateKey: v2FloorKeys.privateKey });
  cas2 = new OpaqueCheckpointV2Authority(path.join(dir, "v2-cas.sqlite"), {
    ...authorityOptions, role: "CAS", bootstrapNew: false,
    signingPrivateKey: v2CasKeys.privateKey });
  handles = await serveV2({});
  console.error("STAGE: v2 authorities restarted");
  client.close();
  client = new Zk1OpaqueCheckpointV2Client(clientOptions(handles, journal, false));
  const recovered = await client.recover();
  assert.equal(recovered.sequence, 129);
  assert.equal(recovered.state, "V2_BOTH_FINALIZED");
  assert.deepEqual(recovered.digest, newDigest);
  assert.deepEqual(recovered.checkpointDigest, checkpoint129.checkpointDigest);
  assert.equal((await client.read()).sequence, 129);
  const finished = await handles.coordinator.reconcile(intent);
  assert.equal(finished.finalSequence, 129);
  assert.equal(finished.outcome, "V2_CHECKPOINT_BOTH_FINALIZED_LOCAL_ONLY");
  assert.equal(finished.atomicCrossDatabaseTransactionProven, false);
  assert.equal((await handles.casClient.head()).state, "FINALIZED");
  assert.equal((await handles.floorClient.head()).state, "FINALIZED");
  assert.equal((await handles.coordinator.readConsistent(intent)).sequence, 129);
  await assert.rejects(handles.coordinator.publish(await makeIntent()),
    /CONFLICT/);
  assert.deepEqual((await handles.coordinator.reconcile(intent)).outcome, finished.outcome);
  const differentKey = crypto.generateKeyPairSync("ed25519");
  assert.throws(() => new Zk1OpaqueCheckpointV2Client({
    ...clientOptions(handles, journal, false),
    ownerPublicKey: differentKey.publicKey,
  }), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
  "restart cannot silently accept an owner or endpoint-signing key substitution");
  const tamperedJournalPath = path.join(dir, "v2-tampered-device.sqlite");
  const copySource = new Database(journal, { readonly: true, fileMustExist: true });
  await copySource.backup(tamperedJournalPath);
  copySource.close();
  if (process.platform !== "win32") fs.chmodSync(tamperedJournalPath, 0o600);
  const attacked = new Database(tamperedJournalPath);
  attacked.exec("DROP TRIGGER intent_immutable_update");
  const edited = await z.decodeDeterministic(intent);
  edited.owner_signature = crypto.randomBytes(64);
  attacked.prepare("UPDATE intent SET bytes=? WHERE id=1")
    .run(Buffer.from(await z.encodeDeterministic(edited)));
  attacked.exec(`CREATE TRIGGER intent_immutable_update BEFORE UPDATE ON intent
    BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;`);
  attacked.close();
  const contaminated = new Zk1OpaqueCheckpointV2Client(
    clientOptions(handles, tamperedJournalPath, false));
  await assert.rejects(contaminated.read(), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
    "locally altered checkpoint approval must never inherit valid remote finalization");
  contaminated.close();
  // Actual v1 authorities remain immutable: 128 is not promoted in their DBs.
  assert.equal((await z.decodeDeterministic(await v1Cas.readHead({
    scope, nonce: crypto.randomBytes(32) }))).sequence, 128);
  assert.equal(floorLedger.inspect().sequence, 128);
  await stopV2();
  await assert.rejects(client.read(), /ZK_CHECKPOINT_V2_ACK_UNCERTAIN/,
    "offline CAS/floor must fence metadata read even after local recovery");
  // A second integration uses two separate OS processes and two new SQLite
  // stores. These are loopback hosts; not claimed to be physically independent.
  const putKey = (name, value) => fs.writeFileSync(path.join(dir, name),
    value.export({ format: "pem", type: value.type === "private" ? "pkcs8" : "spki" }));
  putKey("fixture-witness.key", witness.privateKey);
  putKey("fixture-v2cas.key", v2CasKeys.privateKey);
  putKey("fixture-v2floor.key", v2FloorKeys.privateKey);
  putKey("fixture-v2cas.pub", v2CasKeys.publicKey);
  putKey("fixture-v2floor.pub", v2FloorKeys.publicKey);
  putKey("fixture-owner.pub", owner.publicKey);
  putKey("fixture-checkpoint.pub", checkpoint.publicKey);
  const wireScope = Object.fromEntries(Object.entries(scope)
    .map(([name, value]) => [name, encoded(value)]));
  const childFile = path.join(__dirname, "..", "lab", "issue-65-packet-b",
    "issue-65-checkpoint-v2-authority-child.js");
  const processes = [];
  async function startProcess(role) {
    const configFile = path.join(dir, role + "-child.json");
    fs.writeFileSync(configFile, JSON.stringify({
      role, bootstrapNew: true, dir, scope: wireScope,
      witnessKeyId: encoded(witnessKeyId), genesis: encoded(genesis),
      liveRevision: Number(state.headManifest.revision),
      liveManifestDigest: encoded(await ownerManifest.recoveryManifestDigestV2(
        state.headManifest)), oldDigest: encoded(oldDigest),
      oldCheckpoint: encoded(oldCheckpoint),
    }));
    const proc = spawn(process.execPath, [childFile, configFile], {
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      cwd: path.join(__dirname, ".."), windowsHide: true, env: process.env,
    });
    processes.push(proc);
    return new Promise((resolve, reject) => {
      let stderr = "";
      proc.stderr.on("data", (part) => { stderr += part; });
      proc.on("message", (message) => {
        if (message.error) reject(new Error(role + ": " + message.error + " " + stderr));
        else if (message.port) resolve({ proc, port: message.port });
      });
      proc.on("error", reject);
      proc.on("exit", (code) => {
        if (code !== 0) reject(new Error(role + " exited " + code + ": " + stderr));
      });
    });
  }
  async function stopProcess(proc) {
    if (proc.exitCode !== null) return;
    proc.send("stop");
    await new Promise((resolve, reject) => {
      proc.once("exit", resolve);
      proc.once("error", reject);
    });
  }
  try {
    const floorProc = await startProcess("FLOOR");
    const casProc = await startProcess("CAS");
    const common = { ca: read("ca.pem"), clientKey: read("client.key"),
      clientCert: read("client.pem"), casPublicKey: v2CasKeys.publicKey,
      floorPublicKey: v2FloorKeys.publicKey, scope };
    const remoteFloor = createOpaqueCheckpointV2HttpsClient({
      ...common, endpoint: "https://127.0.0.1:" + floorProc.port + "/",
      serverFingerprint256: x509("v2floor.pem"),
      authorityPublicKey: v2FloorKeys.publicKey });
    const remoteCas = createOpaqueCheckpointV2HttpsClient({
      ...common, endpoint: "https://127.0.0.1:" + casProc.port + "/",
      serverFingerprint256: x509("v2cas.pem"),
      authorityPublicKey: v2CasKeys.publicKey });
    const remoteCoordinator = createOpaqueCheckpointV2Coordinator({
      floorClient: remoteFloor, casClient: remoteCas,
      v1CasClient: v1Cas, v1FloorClient: v1Floor,
      trustedScope: scope, expectedV1Digest: oldDigest,
      expectedV1Checkpoint: oldCheckpoint });
    const remoteEndpoints = { casClient: remoteCas, floorClient: remoteFloor };
    const remoteJournal = path.join(dir, "v2-device-fresh-publish.sqlite");
    const remoteDevice = new Zk1OpaqueCheckpointV2Client(
      clientOptions(remoteEndpoints, remoteJournal, true));
    try {
      // Device constructs a canonical signed 129 intent; the separate OS
      // processes accept it only after independently authenticating the V1 128
      // terminal and live owner-rooted witness.
      const original = await z.decodeDeterministic(intent);
      const signedApproval = await z.decodeDeterministic(original.owner_approval);
      const signedCheckpoint = await z.decodeDeterministic(original.checkpoint_bytes);
      const [published, competitor] = await Promise.all([
        remoteDevice.publish({ record: records[0],
          checkpointPrivateKey: checkpoint.privateKey,
          ownerPrivateKey: owner.privateKey, ownerEvidence: original.owner_evidence,
          operationId: original.operation_id,
          issuedAt: signedCheckpoint.issued_at,
          ownerIssuedAt: signedApproval.issued_at }),
        remoteCoordinator.publish(intent),
      ]);
      assert.equal(published.sequence, 129);
      assert.equal(competitor.finalSequence, 129);
      assert.deepEqual(published.checkpointDigest, checkpoint129.checkpointDigest);
      assert.equal((await remoteDevice.read()).sequence, 129);
    } finally { remoteDevice.close(); }
    assert.equal((await remoteFloor.head()).state, "FINALIZED");
    assert.equal((await remoteCas.head()).state, "FINALIZED");
    await Promise.all([stopProcess(casProc.proc), stopProcess(floorProc.proc)]);
  } finally {
    for (const proc of processes) if (proc.exitCode === null) proc.kill();
  }
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  } catch (error) {
    console.error("CHECKPOINT-V2-REMOTE-FAIL:", error?.stack || error);
    for (const server of cleanupServers) {
      if (server.listening) {
        server.closeAllConnections();
        server.close();
      }
    }
    for (const db of cleanupDatabases) {
      try { db.close(); } catch (_) { /* best effort failure teardown */ }
    }
    throw error;
  }
});
