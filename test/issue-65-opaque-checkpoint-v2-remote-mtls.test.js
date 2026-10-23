"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const { spawn } = require("node:child_process");
const vm = require("node:vm");
const express = require("express");
const { registerZk1ProtectedObjectRoutes } =
  require("../src/routes/zk1ProtectedObjectRoutes");
const browserV2 = require("../public/client/rootark-zk1-browser-authority-head-relay");
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
const { realEdge } = require("./support/issue-65-checkpoint-v2-real-edge");

const PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const BASE_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-base/v1\0");
const WITNESS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");
const fp = (key) => crypto.createHash("sha256")
  .update(key.export({ type: "spki", format: "der" })).digest();
const rawPublicForGrant = (key) => key.export({ type: "spki", format: "der" }).subarray(-32);
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
  const storedCiphertext = Buffer.from("Synthetic opaque ciphertext from a verified V2 historical revision.");
  let servedCiphertext = Buffer.from(storedCiphertext);
  let contentReads = 0;
  const encryptedRecord = { object_id: encoded(crypto.randomBytes(16)),
    revision: 1, epoch: Number(state.headManifest.current_epoch),
    ciphertext_digest: crypto.createHash("sha256").update(storedCiphertext).digest(),
    metadata_ciphertext: crypto.randomBytes(284) };
  const encryptedPage = Buffer.from(await z.encodeDeterministic([encryptedRecord]));
  const encryptedPageDigest = crypto.createHash("sha256")
    .update(Buffer.from("Root.ark/zk-1/opaque-catalog-page/v1\0"))
    .update(encryptedPage).digest();
  const nextHeader = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
    sequence: 129, previous_digest: oldDigest,
    manifest_revision: Number(state.headManifest.revision),
    manifest_digest: await ownerManifest.recoveryManifestDigestV2(state.headManifest),
    epoch: Number(state.headManifest.current_epoch),
    signer_device_id: deviceB.device_id,
    total_count: 1, page_digests: [encryptedPageDigest], issued_at: now() };
  const nextRaw = Buffer.from(await z.encodeDeterministic(nextHeader));
  const nextSig = crypto.sign(null, Buffer.concat([HEAD_DOMAIN, nextRaw]), keys(deviceB));
  const newDigest = hd(nextRaw, nextSig);
  const records = [{ header: nextRaw, signature: nextSig, sequence: 129,
    page_bodies: [encryptedPage] }];
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
  let journal = path.join(dir, "v2-device-rollover.sqlite");
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
    signature: retiredSignature, page_bodies: [encryptedPage] };
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
  const uncertainSource = path.join(dir, "v2-pending-129-original.sqlite");
  const pendingBackup = new Database(journal, { readonly: true, fileMustExist: true });
  await pendingBackup.backup(uncertainSource);
  pendingBackup.close();
  const pendingLegacy = new Database(uncertainSource);
  pendingLegacy.exec(`DROP TRIGGER successors_immutable_update;
    DROP TRIGGER successors_immutable_delete;
    DROP TRIGGER successors_no_gap;
    DROP TABLE successors;`);
  pendingLegacy.close();
  const uncertainTarget = path.join(dir, "v2-pending-129-upgraded.sqlite");
  await assert.rejects(Zk1OpaqueCheckpointV2Client.migrateLegacy129({
    ...clientOptions(handles, uncertainTarget, false),
    legacyJournalPath: uncertainSource, migrationOptIn: true,
    ownerPrivateKey: owner.privateKey,
  }), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
  "durable pending #129 with lost CAS ACK must never be admitted as FINALIZED");
  assert.equal(fs.existsSync(uncertainTarget), false,
    "uncertain remote publication cannot create a successor-authorized journal");
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
  // Original pre-130 #129 device format has only identity/intent and two
  // immutable intent triggers. Upgrade only into a NEW device journal after
  // fresh owner authority and both signed independent finalized heads.
  const old129 = path.join(dir, "v2-original-129.sqlite");
  const snapshot129 = new Database(journal, { readonly: true, fileMustExist: true });
  await snapshot129.backup(old129);
  snapshot129.close();
  const legacy129 = new Database(old129);
  legacy129.exec(`DROP TRIGGER successors_immutable_update;
    DROP TRIGGER successors_immutable_delete;
    DROP TRIGGER successors_no_gap;
    DROP TABLE successors;`);
  legacy129.close();
  if (process.platform !== "win32") fs.chmodSync(old129, 0o600);
  const original129 = fs.readFileSync(old129);
  const preUpdateReopen = path.join(dir, "v2-old-reopen-fails.sqlite");
  fs.copyFileSync(old129, preUpdateReopen);
  assert.throws(() => new Zk1OpaqueCheckpointV2Client(
    clientOptions(handles, preUpdateReopen, false)),
  /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
  "RED: previously shipped valid #129 lacks the new successors schema");
  const migratedJournal = path.join(dir, "v2-owner-migrated-130.sqlite");
  const optIn = (source, destination, additional = {}) => ({
    ...clientOptions(handles, destination, false), legacyJournalPath: source,
    migrationOptIn: true, ownerPrivateKey: owner.privateKey, ...additional,
  });
  await assert.rejects(Zk1OpaqueCheckpointV2Client.migrateLegacy129(
    optIn(old129, migratedJournal, { migrationOptIn: false })),
  /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/, "implicit schema upgrade denied");
  await assert.rejects(Zk1OpaqueCheckpointV2Client.migrateLegacy129(
    optIn(old129, migratedJournal, { ownerPrivateKey: revoked.privateKey })),
  /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/, "another signing key cannot authorize migration");
  const swapped129 = path.join(dir, "v2-swapped-129.sqlite");
  fs.copyFileSync(old129, swapped129);
  const swappedDb = new Database(swapped129);
  swappedDb.exec("DROP TRIGGER intent_immutable_update");
  swappedDb.prepare("UPDATE identity SET pins=? WHERE id=1")
    .run(crypto.randomBytes(160));
  swappedDb.exec(`CREATE TRIGGER intent_immutable_update BEFORE UPDATE ON intent
    BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;`);
  swappedDb.close();
  await assert.rejects(Zk1OpaqueCheckpointV2Client.migrateLegacy129(
    optIn(swapped129, migratedJournal)), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
  "a swapped pre-update identity must be denied before publishing a destination");
  const mutable129 = path.join(dir, "v2-mutable-129.sqlite");
  fs.copyFileSync(old129, mutable129);
  const mutableDb = new Database(mutable129);
  mutableDb.exec(`DROP TRIGGER intent_immutable_update;
    CREATE TRIGGER intent_immutable_update BEFORE UPDATE ON intent
    WHEN 0 BEGIN SELECT 1; END;`);
  mutableDb.close();
  await assert.rejects(Zk1OpaqueCheckpointV2Client.migrateLegacy129(
    optIn(mutable129, migratedJournal)), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
  "forged old trigger is not immutable journal evidence");
  const walTamper129 = path.join(dir, "v2-wal-tamper-129.sqlite");
  fs.copyFileSync(old129, walTamper129);
  const uncheckpointed = new Database(walTamper129);
  uncheckpointed.pragma("journal_mode = WAL");
  uncheckpointed.pragma("wal_autocheckpoint = 0");
  uncheckpointed.pragma("user_version = 1");
  try {
    assert.equal(fs.existsSync(walTamper129 + "-wal"), true);
    await assert.rejects(Zk1OpaqueCheckpointV2Client.migrateLegacy129(
      optIn(walTamper129, migratedJournal)), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
    "uncheckpointed malicious WAL must be included in read-only validation");
  } finally { uncheckpointed.close(); }
  const forged129 = path.join(dir, "v2-forged-owner-129.sqlite");
  fs.copyFileSync(old129, forged129);
  const forged129Db = new Database(forged129);
  forged129Db.exec("DROP TRIGGER intent_immutable_update");
  const forgedIntent129 = await z.decodeDeterministic(intent);
  forgedIntent129.owner_signature = crypto.randomBytes(64);
  forged129Db.prepare("UPDATE intent SET bytes=? WHERE id=1")
    .run(Buffer.from(await z.encodeDeterministic(forgedIntent129)));
  forged129Db.exec(`CREATE TRIGGER intent_immutable_update BEFORE UPDATE ON intent
    BEGIN SELECT RAISE(ABORT,'IMMUTABLE'); END;`);
  forged129Db.close();
  await assert.rejects(Zk1OpaqueCheckpointV2Client.migrateLegacy129(
    optIn(forged129, migratedJournal)), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
  "same local identity cannot bless tampered owner signature");
  assert.equal(fs.existsSync(migratedJournal), false);
  let migrated;
  if (process.platform === "win32") {
    // Native directory fsync returns EPERM on Windows. The opt-in migration
    // must refuse to create a destination instead of claiming crash safety.
    await assert.rejects(Zk1OpaqueCheckpointV2Client.migrateLegacy129(
      optIn(old129, migratedJournal)), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/);
    assert.equal(fs.existsSync(migratedJournal), false);
  } else {
    migrated = await Zk1OpaqueCheckpointV2Client.migrateLegacy129(
      optIn(old129, migratedJournal));
  }
  assert.deepEqual(fs.readFileSync(old129), original129,
    "migration does not modify the old SQLite database");
  assert.equal(fs.existsSync(old129 + "-wal"), false);
  assert.equal(fs.existsSync(old129 + "-shm"), false);
  if (migrated) {
    assert.equal((await migrated.read()).sequence, 129);
    assert.deepEqual(await migrated.exportSignedIntents(), [intent]);
    assert.equal(fs.existsSync(migratedJournal), true);
    const migratedProbe = new Database(migratedJournal, { readonly: true });
    assert.equal(migratedProbe.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='successors'").get().name,
    "successors");
    migratedProbe.close();
    await assert.rejects(Zk1OpaqueCheckpointV2Client.migrateLegacy129(
      optIn(old129, migratedJournal)), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
    "migration never overwrites a pre-existing destination or replays admission");
    client.close();
    client = migrated;
    journal = migratedJournal;
  }
  // Same-origin authenticated session relay -> independent V2 mTLS providers
  // -> browser verifies both fresh Ed25519 receipts and the owner-approved
  // single-record 129 archive. No Node/SQLite APIs enter the browser client.
  const web = express();
  const relayUser = { username: "fixture", sessionVersion: 7 };
  let currentSession = 7;
  web.use((req, _res, next) => { req.user = { ...relayUser, sessionVersion: currentSession }; next(); });
  registerZk1ProtectedObjectRoutes({
    app: web, environment: "test", store: {
      signedHistoryRequired: true,
      put() {}, get() {},
      async runWithAdmission(request, operation, respond) {
        assert.equal(operation, "get");
        const signed = request.authorization;
        assert.equal(signed.operation, "get");
        assert.equal(signed.object_id, encryptedRecord.object_id);
        assert.equal(signed.expected_object_revision, encryptedRecord.revision);
        assert.equal(signed.epoch, encryptedRecord.epoch);
        assert.deepEqual(Buffer.from(signed.ciphertext_digest), encryptedRecord.ciphertext_digest);
        assert.deepEqual(Buffer.from(signed.manifest_digest), nextHeader.manifest_digest);
        assert.equal(crypto.verify(null, Buffer.concat([Buffer.from(
          "Root.ark/zk-1/protected-object-operation/v1\0"),
        Buffer.from(await z.encodeDeterministic(signed))]), owner.publicKey, request.signature), true);
        contentReads++;
        return respond({ id: encryptedRecord.object_id,
          revision: encryptedRecord.revision, epoch: encryptedRecord.epoch,
          ciphertext: servedCiphertext });
      },
    },
    authenticate: (req, _res, next) => { req.user = {
      username: "fixture", sessionVersion: currentSession,
    }; next(); },
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => scope,
    opaqueCheckpointV2: { casClient: handles.casClient, floorClient: handles.floorClient },
  });
  const webServer = await new Promise((resolve) => {
    const created = web.listen(0, "127.0.0.1", () => resolve(created));
  });
  try {
    const siteOrigin = "http://127.0.0.1:" + webServer.address().port + "/";
    const v2Input = {
      origin: siteOrigin, fetchImpl: fetch, assertLive: () => {},
      csrfToken: () => "fixture-csrf",
      scope: Object.fromEntries(Object.entries(scope).map(([name, v]) => [name, encoded(v)])),
      previousDigest: new Uint8Array(oldDigest),
      previousCheckpointDigest: new Uint8Array(oldCheckpoint),
      ownerRevision: Number(state.headManifest.revision),
      ownerDigest: new Uint8Array(await ownerManifest.recoveryManifestDigestV2(
        state.headManifest)),
      ownerEpoch: Number(state.headManifest.current_epoch),
      ownerDeviceId: deviceB.device_id, signedIntent: new Uint8Array(intent),
      casKeyRaw: new Uint8Array(v2CasKeys.publicKey.export({ type: "spki", format: "der" }).subarray(-32)),
      casSpkiPin: new Uint8Array(fp(v2CasKeys.publicKey)),
      floorKeyRaw: new Uint8Array(v2FloorKeys.publicKey.export({ type: "spki", format: "der" }).subarray(-32)),
      floorSpkiPin: new Uint8Array(fp(v2FloorKeys.publicKey)),
      checkpointKeyRaw: new Uint8Array(checkpoint.publicKey.export({ type: "spki", format: "der" }).subarray(-32)),
      checkpointSpkiPin: new Uint8Array(fp(checkpoint.publicKey)),
      deviceKeyRaw: new Uint8Array(owner.publicKey.export({ type: "spki", format: "der" }).subarray(-32)),
      deviceSpkiPin: new Uint8Array(fp(owner.publicKey)),
    };
    const confirmedV2 = await browserV2.readFinalizedV2(v2Input);
    assert.equal(confirmedV2.sequence, 129);
    assert.equal(confirmedV2.independentlyFinalized, true);
    assert.equal(confirmedV2.productionDurabilityProven, false);
    assert.equal(confirmedV2.totalCount, 1);
    assert.equal(confirmedV2.rows[0].objectId, encryptedRecord.object_id);
    const activePrivate = await crypto.webcrypto.subtle.importKey("pkcs8",
      owner.privateKey.export({ type: "pkcs8", format: "der" }),
      "Ed25519", false, ["sign"]);
    const revokedPrivate = await crypto.webcrypto.subtle.importKey("pkcs8",
      keys(deviceA).export({ type: "pkcs8", format: "der" }),
      "Ed25519", false, ["sign"]);
    assert.equal(contentReads, 0);
    await assert.rejects(browserV2.getFinalizedV2Ciphertext({ ...confirmedV2 }, 0, activePrivate),
      /UNVERIFIED/, "a copied unbranded V2 inventory cannot authorize a GET");
    await assert.rejects(browserV2.getFinalizedV2Ciphertext(confirmedV2, 0, revokedPrivate),
      /UNVERIFIED/, "an old device cannot sign a GET using the current pinned key");
    assert.equal(contentReads, 0, "no GET before matching live device proof");
    const retrieved = await browserV2.getFinalizedV2Ciphertext(confirmedV2, 0, activePrivate);
    assert.deepEqual(Buffer.from(retrieved.ciphertextBase64, "base64url"), storedCiphertext);
    assert.equal(retrieved.objectId, encryptedRecord.object_id);
    assert.equal(retrieved.revision, 1);
    assert.equal(retrieved.productionDurabilityProven, false);
    assert.equal(contentReads, 1);
    servedCiphertext = Buffer.from(storedCiphertext);
    servedCiphertext[0] ^= 0xff;
    await assert.rejects(browserV2.getFinalizedV2Ciphertext(confirmedV2, 0, activePrivate),
      /UNVERIFIED/, "compromised storage bytes must match the signed V2 row digest");
    servedCiphertext = Buffer.from(storedCiphertext);
    await assert.rejects(browserV2.getFinalizedV2Ciphertext(confirmedV2, 1, activePrivate),
      /UNVERIFIED/, "a row outside the verified signed checkpoint cannot be fetched");
    let sessionToken = "fixture-csrf";
    const currentSessionRead = await browserV2.readFinalizedV2({
      ...v2Input, csrfToken: () => sessionToken,
    });
    sessionToken = "different-session";
    const priorReads = contentReads;
    await assert.rejects(browserV2.getFinalizedV2Ciphertext(
      currentSessionRead, 0, activePrivate), /UNVERIFIED/,
    "a saved verified inventory loses GET permission on session switch");
    assert.equal(contentReads, priorReads);
    let storedResponse = null;
    assert.equal((await browserV2.readFinalizedV2({
      ...v2Input,
      fetchImpl: async (...args) => {
        const valid = await fetch(...args);
        storedResponse = await valid.text();
        return new Response(storedResponse, {
          status: valid.status, headers: { "content-type": "application/json" },
        });
      },
    })).sequence, 129);
    await assert.rejects(browserV2.readFinalizedV2({
      ...v2Input,
      fetchImpl: async () => new Response(storedResponse, {
        status: 200, headers: { "content-type": "application/json" },
      }),
    }), /UNVERIFIED/, "a perfectly signed cached dual proof cannot answer a fresh browser challenge");
    await assert.rejects(browserV2.readFinalizedV2({
      ...v2Input,
      ownerRevision: v2Input.ownerRevision - 1,
    }), /UNVERIFIED/, "historical owner manifest is never treated as current");
    const changed = await z.decodeDeterministic(intent);
    changed.owner_signature = crypto.randomBytes(64);
    await assert.rejects(browserV2.readFinalizedV2({
      ...v2Input, signedIntent: new Uint8Array(await z.encodeDeterministic(changed)),
    }), /UNVERIFIED/, "forged owner approval is denied before relay");
    await assert.rejects(browserV2.readFinalizedV2({
      ...v2Input, casSpkiPin: new Uint8Array(crypto.randomBytes(32)),
    }), /UNVERIFIED/, "independently pinned CAS signer cannot change");
    await assert.rejects(browserV2.readFinalizedV2({
      ...v2Input, previousDigest: new Uint8Array(crypto.randomBytes(32)),
    }), /UNVERIFIED/, "old V1 128 predecessor pin cannot roll back or fork");
    let switched = false;
    await assert.rejects(browserV2.readFinalizedV2({
      ...v2Input, csrfToken: () => switched ? "new-session" : "fixture-csrf",
      fetchImpl: async (...args) => { const response = await fetch(...args);
        switched = true; return response; },
    }), /UNVERIFIED/, "session switch during relay must fail closed");
    const vmContext = { crypto: crypto.webcrypto, TextEncoder, TextDecoder,
      Uint8Array, ArrayBuffer, URL, btoa, atob, AbortController, setTimeout,
      clearTimeout, Date, Promise };
    vmContext.globalThis = vmContext;
    vm.runInNewContext(fs.readFileSync(path.join(__dirname,
      "../public/client/rootark-zk1-protected-http-client.js"), "utf8"),
    vmContext, { timeout: 1000 });
    vm.runInNewContext(fs.readFileSync(path.join(__dirname,
      "../public/client/rootark-zk1-browser-authority-head-relay.js"), "utf8"),
    vmContext, { timeout: 1000 });
    assert.equal(typeof vmContext.RootarkZk1BrowserAuthorityHeadRelay.readFinalizedV2, "function");
    const browserSnapshot = await vmContext.RootarkZk1BrowserAuthorityHeadRelay.readFinalizedV2(
      Object.assign(Object.create(null), v2Input, {
        scope: Object.assign(Object.create(null), v2Input.scope),
      }));
    assert.equal(browserSnapshot.sequence, 129,
      "Edge-like VM uses browser WebCrypto and same-origin relay");
    const vmDownload = await vmContext.RootarkZk1BrowserAuthorityHeadRelay
      .getFinalizedV2Ciphertext(browserSnapshot, 0, activePrivate);
    assert.deepEqual(Buffer.from(vmDownload.ciphertextBase64, "base64url"), storedCiphertext,
      "browser VM GET verifies the exact signed V2 commitment");
  } finally {
    await new Promise((resolve) => webServer.close(resolve));
  }
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
  // Signed successive V2 checkpoints use the same immutable V1 terminal and
  // distinct owner approvals, checkpoint signatures and CAS/floor receipts.
  const ownerEvidence = (await z.decodeDeterministic(intent)).owner_evidence;
  async function successorRecord(sequence, previousDigest) {
    const header = { ...nextHeader, sequence, previous_digest: previousDigest,
      issued_at: now() };
    const raw = Buffer.from(await z.encodeDeterministic(header));
    const signature = crypto.sign(null, Buffer.concat([HEAD_DOMAIN, raw]), keys(deviceB));
    return { sequence, record: { sequence, header: raw, signature,
      page_bodies: [encryptedPage] }, digest: hd(raw, signature) };
  }
  const next130 = await successorRecord(130, newDigest);
  const publishSuccessor = (record) => client.publish({ record,
    checkpointPrivateKey: checkpoint.privateKey, ownerPrivateKey: owner.privateKey,
    ownerEvidence });
  await assert.rejects(publishSuccessor((await successorRecord(131, newDigest)).record),
    /ZK_OPAQUE_CHECKPOINT_V2_UNVERIFIED/,
    "a skipped sequence is never admitted by merely increasing the ceiling");
  const published130 = await publishSuccessor(next130.record);
  assert.equal(published130.sequence, 130);
  assert.deepEqual(published130.digest, next130.digest);
  const rollbackTarget = path.join(dir, "v2-replay-older-129.sqlite");
  await assert.rejects(Zk1OpaqueCheckpointV2Client.migrateLegacy129(
    optIn(old129, rollbackTarget)), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
  "previously genuine #129 cannot overwrite signed independent 130 or reconcile a lost ACK");
  assert.equal(fs.existsSync(rollbackTarget), false);
  assert.equal((await handles.casClient.head()).sequence, 130);
  assert.equal((await handles.floorClient.head()).sequence, 130);
  await assert.rejects(client.publishSignedIntent(intent),
    /ZK_CHECKPOINT_V2_(?:CLIENT_)?UNAVAILABLE/,
    "replaying the 129 owner intent cannot advance or rewind the journal");
  await assert.rejects(publishSuccessor((await successorRecord(131, oldDigest)).record),
    /ZK_OPAQUE_CHECKPOINT_V2_UNVERIFIED/,
    "a valid signer cannot fork the signed predecessor digest");
  await stopV2();
  floor2 = new OpaqueCheckpointV2Authority(path.join(dir, "v2-floor.sqlite"), {
    ...authorityOptions, role: "FLOOR", bootstrapNew: false,
    signingPrivateKey: v2FloorKeys.privateKey });
  cas2 = new OpaqueCheckpointV2Authority(path.join(dir, "v2-cas.sqlite"), {
    ...authorityOptions, role: "CAS", bootstrapNew: false,
    signingPrivateKey: v2CasKeys.privateKey });
  handles = await serveV2({});
  client.close();
  client = new Zk1OpaqueCheckpointV2Client(clientOptions(handles, journal, false));
  assert.equal((await client.read()).sequence, 130,
    "the complete 129->130 locally durable chain survives restart");
  const next131 = await successorRecord(131, next130.digest);
  const published131 = await publishSuccessor(next131.record);
  assert.equal(published131.sequence, 131);
  assert.equal((await handles.casClient.head()).sequence, 131);
  assert.equal((await handles.floorClient.head()).sequence, 131);
  const signedHistory = await client.exportSignedIntents();
  assert.equal(signedHistory.length, 3);
  // Normal same-origin browser opt-in over REAL pinned mTLS CAS/FLOOR heads.
  // The server authenticates the session/permissions on both HEAD and GET;
  // imported chain/owner key pins come exclusively from the local test device.
  const grantSigner = crypto.generateKeyPairSync("ed25519");
  const grantFields = ["schema", "account_id", "compartment_id", "keyring_id",
    "device_id", "authorization_key_id", "authorization_public_key",
    "manifest_revision", "manifest_digest", "current_epoch", "enrolled_epoch",
    "revoked_at_epoch"];
  const grantStatement = {
    schema: "rootark-zk1-browser-owner-device-grant/v1",
    ...Object.fromEntries(Object.entries(scope).map(([k, v]) => [k, encoded(v)])),
    device_id: deviceB.device_id, authorization_key_id: encoded(crypto.randomBytes(16)),
    authorization_public_key: encoded(rawPublicForGrant(owner.publicKey)),
    manifest_revision: Number(state.headManifest.revision),
    manifest_digest: encoded(await ownerManifest.recoveryManifestDigestV2(state.headManifest)),
    current_epoch: Number(state.headManifest.current_epoch), enrolled_epoch: 1,
    revoked_at_epoch: null,
  };
  const grant = { ...grantStatement,
    signature: encoded(crypto.sign(null, Buffer.concat([
      Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
      Buffer.from(JSON.stringify(Object.fromEntries(grantFields.map((n) =>
        [n, grantStatement[n]])))),
    ]), grantSigner.privateKey)) };
  const bridge = express();
  let bridgeSession = 11;
  let bridgeReads = 0;
  let bridgeCiphertext = Buffer.from(storedCiphertext);
  const relayScript = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-browser-authority-head-relay.js"), "utf8");
  const httpScript = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-protected-http-client.js"), "utf8");
  bridge.get("/checkpoint-v2-browser-test", (_req, res) => res.type("html").send(
    '<!doctype html><meta charset="utf-8"><script src="/test-content-http.js"></script>'
    + '<script src="/test-v2-head.js"></script><main>fixture</main>'));
  bridge.get("/test-content-http.js", (_req, res) => res.type("js").send(httpScript));
  bridge.get("/test-v2-head.js", (_req, res) => res.type("js").send(relayScript));
  registerZk1ProtectedObjectRoutes({ app: bridge, environment: "test",
    store: { signedHistoryRequired: true, put() {}, get() {},
      async runWithAdmission(request, operation, respond) {
        assert.equal(operation, "get");
        assert.equal(request.authorization.object_id, encryptedRecord.object_id);
        assert.equal(request.authorization.expected_object_revision, 1);
        assert.deepEqual(Buffer.from(request.authorization.ciphertext_digest),
          encryptedRecord.ciphertext_digest);
        bridgeReads++;
        return respond({ id: encryptedRecord.object_id, revision: 1,
          epoch: encryptedRecord.epoch, ciphertext: bridgeCiphertext });
      },
    },
    authenticate: (req, _res, next) => {
      req.user = { username: "fixture", sessionVersion: bridgeSession }; next();
    },
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => scope,
    opaqueCheckpointV2: { casClient: handles.casClient, floorClient: handles.floorClient },
  });
  const bridgeServer = await new Promise((resolve) => {
    const instance = bridge.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(() => { if (bridgeServer.listening) bridgeServer.close(); });
  const bridgeOrigin = "http://127.0.0.1:" + bridgeServer.address().port + "/";
  const bridgeInput = {
    origin: bridgeOrigin, fetchImpl: fetch, assertLive: () => {},
    csrfToken: () => "checkpoint-csrf", scope: Object.fromEntries(
      Object.entries(scope).map(([name, value]) => [name, encoded(value)])),
    previousDigest: new Uint8Array(oldDigest),
    previousCheckpointDigest: new Uint8Array(oldCheckpoint),
    ownerRevision: Number(state.headManifest.revision),
    ownerDigest: new Uint8Array(await ownerManifest.recoveryManifestDigestV2(state.headManifest)),
    ownerEpoch: Number(state.headManifest.current_epoch),
    ownerDeviceId: deviceB.device_id,
    signedIntent: new Uint8Array(signedHistory[2]),
    signedIntents: signedHistory.map((value) => new Uint8Array(value)),
    casKeyRaw: new Uint8Array(rawPublicForGrant(v2CasKeys.publicKey)),
    casSpkiPin: new Uint8Array(fp(v2CasKeys.publicKey)),
    floorKeyRaw: new Uint8Array(rawPublicForGrant(v2FloorKeys.publicKey)),
    floorSpkiPin: new Uint8Array(fp(v2FloorKeys.publicKey)),
    checkpointKeyRaw: new Uint8Array(rawPublicForGrant(checkpoint.publicKey)),
    checkpointSpkiPin: new Uint8Array(fp(checkpoint.publicKey)),
    deviceKeyRaw: new Uint8Array(rawPublicForGrant(owner.publicKey)),
    deviceSpkiPin: new Uint8Array(fp(owner.publicKey)),
    signedDeviceGrant: grant,
    ownerKeyRaw: new Uint8Array(rawPublicForGrant(grantSigner.publicKey)),
    ownerSpkiPin: new Uint8Array(fp(grantSigner.publicKey)),
  };
  const verified131 = await browserV2.readFinalizedV2(bridgeInput);
  assert.equal(verified131.sequence, 131);
  const privateEdge = await crypto.webcrypto.subtle.importKey("pkcs8",
    owner.privateKey.export({ type: "pkcs8", format: "der" }),
    "Ed25519", false, ["sign"]);
  assert.deepEqual(Buffer.from((await browserV2.getFinalizedV2Ciphertext(
    verified131, 0, privateEdge)).ciphertextBase64, "base64url"), storedCiphertext);
  assert.equal(bridgeReads, 1);
  const truncated131 = [signedHistory[0], signedHistory[2]].map((r) => new Uint8Array(r));
  await assert.rejects(browserV2.readFinalizedV2({ ...bridgeInput,
    signedIntents: truncated131 }), /UNVERIFIED/,
  "unsigned gap from 129 directly to 131 cannot be read");
  await assert.rejects(browserV2.readFinalizedV2({ ...bridgeInput,
    signedIntents: signedHistory.slice(0, 2).map((r) => new Uint8Array(r)),
    signedIntent: new Uint8Array(signedHistory[1]) }), /UNVERIFIED/,
  "valid 130 signed history must not conceal the live 131 head");
  const replacedProof = await z.decodeDeterministic(signedHistory[2]);
  const replayCas = await z.decodeDeterministic(replacedProof.predecessor_cas_receipt);
  replayCas.signature = crypto.randomBytes(64);
  replacedProof.predecessor_cas_receipt = Buffer.from(
    await z.encodeDeterministic(replayCas));
  await assert.rejects(browserV2.readFinalizedV2({ ...bridgeInput,
    signedIntents: [...signedHistory.slice(0, 2),
      await z.encodeDeterministic(replacedProof)].map((r) => new Uint8Array(r)),
    signedIntent: new Uint8Array(await z.encodeDeterministic(replacedProof)),
  }), /UNVERIFIED/, "forged predecessor CAS endorsement fails closed");
  await assert.rejects(browserV2.readFinalizedV2({ ...bridgeInput,
    signedDeviceGrant: { ...grant, signature: encoded(crypto.randomBytes(64)) },
  }), /UNVERIFIED/, "a forged current owner grant cannot authorize 131");
  let bridgeCsrf = "checkpoint-csrf";
  await assert.rejects(browserV2.readFinalizedV2({ ...bridgeInput,
    csrfToken: () => bridgeCsrf,
    fetchImpl: async (...args) => { const response = await fetch(...args);
      bridgeSession++; bridgeCsrf = "replaced-session"; return response; },
  }), /UNVERIFIED/, "session switch during authenticated final heads is denied");
  bridgeCiphertext = Buffer.from(storedCiphertext);
  bridgeCiphertext[0] ^= 0xff;
  await assert.rejects(browserV2.getFinalizedV2Ciphertext(verified131, 0, privateEdge),
    /UNVERIFIED/, "GET still checks the latest signed ciphertext digest");
  bridgeCiphertext = Buffer.from(storedCiphertext);
  const edge = await realEdge(t, bridgeOrigin);
  const edgeWire = { ...bridgeInput,
    previousDigest: encoded(oldDigest), previousCheckpointDigest: encoded(oldCheckpoint),
    ownerDigest: encoded(bridgeInput.ownerDigest),
    signedIntent: encoded(signedHistory[2]),
    signedIntents: signedHistory.map(encoded),
    casKeyRaw: encoded(bridgeInput.casKeyRaw), casSpkiPin: encoded(bridgeInput.casSpkiPin),
    floorKeyRaw: encoded(bridgeInput.floorKeyRaw), floorSpkiPin: encoded(bridgeInput.floorSpkiPin),
    checkpointKeyRaw: encoded(bridgeInput.checkpointKeyRaw),
    checkpointSpkiPin: encoded(bridgeInput.checkpointSpkiPin),
    deviceKeyRaw: encoded(bridgeInput.deviceKeyRaw), deviceSpkiPin: encoded(bridgeInput.deviceSpkiPin),
    ownerKeyRaw: encoded(bridgeInput.ownerKeyRaw), ownerSpkiPin: encoded(bridgeInput.ownerSpkiPin),
  };
  const edgePrivate = encoded(owner.privateKey.export({ type: "pkcs8", format: "der" }));
  const edgeResult = await edge.evaluate(`(async () => {
    const wire=${JSON.stringify(edgeWire)};
    const toBytes=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')
      .padEnd(Math.ceil(s.length/4)*4,'=')),c=>c.charCodeAt(0));
    const names=['previousDigest','previousCheckpointDigest','ownerDigest','signedIntent',
      'casKeyRaw','casSpkiPin','floorKeyRaw','floorSpkiPin','checkpointKeyRaw',
      'checkpointSpkiPin','deviceKeyRaw','deviceSpkiPin','ownerKeyRaw','ownerSpkiPin'];
    for(const name of names) wire[name]=toBytes(wire[name]);
    wire.signedIntents=wire.signedIntents.map(toBytes);
    wire.origin=location.origin+'/'; wire.fetchImpl=fetch.bind(window);
    wire.csrfToken=()=>window.__csrf||'checkpoint-csrf';
    wire.assertLive=()=>{if(window.__dead)throw Error('logout')};
    window.__config=wire;
    const v2=window.RootarkZk1BrowserAuthorityHeadRelay;
    window.__verified=await v2.readFinalizedV2(wire);
    const privateKey=await crypto.subtle.importKey('pkcs8',toBytes(${JSON.stringify(edgePrivate)}),
      'Ed25519',false,['sign']);
    window.__privateKey=privateKey;
    const file=await v2.getFinalizedV2Ciphertext(window.__verified,0,privateKey);
    return {sequence:window.__verified.sequence, fetched:file.ciphertextBase64};
  })()`);
  assert.equal(edgeResult.sequence, 131);
  assert.deepEqual(Buffer.from(edgeResult.fetched, "base64url"), storedCiphertext);
  assert.equal(await edge.evaluate(`(async()=>{
    const v2=window.RootarkZk1BrowserAuthorityHeadRelay;
    try{await v2.readFinalizedV2({...window.__config,
      signedIntents:window.__config.signedIntents.slice(0,2),
      signedIntent:window.__config.signedIntents[1]});return 'accepted'}
    catch(e){return e.message}
  })()`), "ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED");
  assert.equal(await edge.evaluate(`(async()=>{
    const v2=window.RootarkZk1BrowserAuthorityHeadRelay;
    try{await v2.readFinalizedV2({...window.__config,
      signedDeviceGrant:{...window.__config.signedDeviceGrant,
        revoked_at_epoch:window.__config.ownerEpoch}});return 'accepted'}
    catch(e){return e.message}
  })()`), "ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED",
  "REAL Edge refuses a revoked owner-device grant");
  assert.equal(await edge.evaluate(`(async()=>{
    window.__csrf='session-switched';
    try{await window.RootarkZk1BrowserAuthorityHeadRelay
      .getFinalizedV2Ciphertext(window.__verified,0,window.__privateKey);return 'accepted'}
    catch(e){return e.message}
  })()`), "ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED");
  const second = new Zk1OpaqueCheckpointV2Client(clientOptions(handles,
    path.join(dir, "v2-second-device.sqlite"), true));
  try {
    await second.importSignedIntent(signedHistory[0]);
    await assert.rejects(second.read(), /ZK_CHECKPOINT_V2_CONFLICT/,
      "a second device with only 129 cannot accept rollback from remote 131");
    const alteredEndorsement = await z.decodeDeterministic(signedHistory[1]);
    const spoofedCas = await z.decodeDeterministic(
      alteredEndorsement.predecessor_cas_receipt);
    spoofedCas.signature = crypto.randomBytes(64);
    alteredEndorsement.predecessor_cas_receipt = Buffer.from(
      await z.encodeDeterministic(spoofedCas));
    await assert.rejects(second.importSignedIntent(Buffer.from(
      await z.encodeDeterministic(alteredEndorsement))),
    /ZK_CHECKPOINT_V2_UNAVAILABLE/,
    "successor requires the actual CAS signed FINALIZED predecessor proof");
    await second.importSignedIntent(signedHistory[1]);
    await second.importSignedIntent(signedHistory[2]);
    assert.equal((await second.read()).sequence, 131);
    await assert.rejects(second.importSignedIntent(signedHistory[2]),
      /ZK_CHECKPOINT_V2_UNAVAILABLE/,
      "replayed owner intent cannot duplicate an imported checkpoint");
    const forgedIntent = await z.decodeDeterministic(signedHistory[2]);
    forgedIntent.owner_signature = crypto.randomBytes(64);
    await assert.rejects(second.importSignedIntent(Buffer.from(
      await z.encodeDeterministic(forgedIntent))), /ZK_CHECKPOINT_V2_UNAVAILABLE/);
  } finally { second.close(); }
  const forgedSuccessorDb = path.join(dir, "v2-forged-successor-trigger.sqlite");
  const sourceJournal = new Database(journal, { readonly: true, fileMustExist: true });
  await sourceJournal.backup(forgedSuccessorDb);
  sourceJournal.close();
  if (process.platform !== "win32") fs.chmodSync(forgedSuccessorDb, 0o600);
  const forgedDb = new Database(forgedSuccessorDb);
  forgedDb.exec(`DROP TRIGGER successors_no_gap;
    CREATE TRIGGER successors_no_gap BEFORE INSERT ON successors
    BEGIN SELECT 1; END;`);
  forgedDb.close();
  assert.throws(() => new Zk1OpaqueCheckpointV2Client(
    clientOptions(handles, forgedSuccessorDb, false)),
  /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
  "a forged local append guard must fail closed on restart");
  // A valid but superseded 131 snapshot loses GET authorization as soon as
  // BOTH pinned authorities have independently finalized a signed 132 head.
  const next132 = await successorRecord(132, next131.digest);
  assert.equal((await publishSuccessor(next132.record)).sequence, 132);
  const priorBridgeReads = bridgeReads;
  await assert.rejects(browserV2.getFinalizedV2Ciphertext(verified131, 0, privateEdge),
    /UNVERIFIED/, "a superseded checkpoint loses GET authorization");
  assert.equal(bridgeReads, priorBridgeReads,
    "superseded head must stop GET before reaching content storage");
  assert.equal(await edge.evaluate(`(async()=>{
    window.__csrf='checkpoint-csrf';
    try{await window.RootarkZk1BrowserAuthorityHeadRelay
      .getFinalizedV2Ciphertext(window.__verified,0,window.__privateKey);return 'accepted'}
    catch(e){return e.message}
  })()`), "ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED",
  "REAL Edge cannot download after another independently finalized head");
  await new Promise((resolve) => bridgeServer.close(resolve));
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
