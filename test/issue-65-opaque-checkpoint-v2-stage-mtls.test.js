"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const z = require("../src/crypto/rootark-zk-1");
const { catalogHeadDigest } = require("../src/services/zk1OpaqueCatalog");
const { Zk1OpaqueCatalogCasLedger } =
  require("../src/services/zk1OpaqueCatalogCasLedger");
const { createZk1OpaqueCatalogCasHttpsServer } =
  require("../src/services/zk1OpaqueCatalogCasHttpsServer");
const { createZk1OpaqueCatalogCasHttpsClient } =
  require("../src/services/zk1OpaqueCatalogCasHttpsClient");
const { Zk1OpaqueCatalogIndependentFloorLedger,
  createZk1OpaqueCatalogIndependentFloorHttpsServer,
  createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { createAuthenticatedOpaqueCatalogArchiveV2: create } =
  require("../src/crypto/rootark-zk1-opaque-catalog-checkpoint-v2");
const { Zk1OpaqueCatalogCheckpointV2Stage: Stage,
  createSignedOpaqueCheckpointOwnerApprovalV2: ownerSign } =
  require("../src/services/zk1OpaqueCatalogCheckpointV2Stage");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const HEAD = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");
const fp = (publicKey) => crypto.createHash("sha256")
  .update(publicKey.export({ type: "spki", format: "der" })).digest();
const err = (code) => ({ code });

test("signed v2 checkpoint local staging with independent CAS+floor mTLS, SQLite restart, owner, uncertain ACK and competing writers", {
  timeout: 120000,
}, async (t) => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-checkpoint-stage-"));
  if (process.platform !== "win32") fs.chmodSync(folder, 0o700);
  generateNativeFixtureCertificates(folder, {
    caSubject: "ZK65 staging fixtures", servers: ["cas", "floor"], clients: ["client"],
  });
  const file = (name) => fs.readFileSync(path.join(folder, name));
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("staged-mtls"),
    keyring_id: crypto.randomBytes(16) };
  const owner = crypto.generateKeyPairSync("ed25519");
  const checkpoint = crypto.generateKeyPairSync("ed25519");
  const device = crypto.generateKeyPairSync("ed25519");
  const casKeys = crypto.generateKeyPairSync("ed25519");
  const floorKeys = crypto.generateKeyPairSync("ed25519");
  const attacker = crypto.generateKeyPairSync("ed25519");
  const clientFingerprint = new crypto.X509Certificate(file("client.pem")).fingerprint256;
  const floorLedger = new Zk1OpaqueCatalogIndependentFloorLedger(
    path.join(folder, "floor.sqlite"), {
      bootstrapNew: true, trustedScope: scope, signingPrivateKey: floorKeys.privateKey,
      casSignerPublicKey: casKeys.publicKey,
      catalogSignerPublicKey: device.publicKey,
    });
  const floorServer = createZk1OpaqueCatalogIndependentFloorHttpsServer({
    ledger: floorLedger, key: file("floor.key"), cert: file("floor.pem"),
    clientCa: file("ca.pem"), authorizedClientFingerprint256: clientFingerprint,
  });
  await new Promise((resolve) => floorServer.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    if (floorServer.listening) {
      floorServer.closeAllConnections(); floorServer.close();
    }
    floorLedger.close();
  });
  const floorClient = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: "https://127.0.0.1:" + floorServer.address().port + "/",
    ca: file("ca.pem"), clientKey: file("client.key"),
    clientCert: file("client.pem"),
    serverFingerprint256: new crypto.X509Certificate(file("floor.pem")).fingerprint256,
    floorPublicKey: floorKeys.publicKey, casSignerPublicKey: casKeys.publicKey,
    trustedScope: scope,
  });
  const casLedger = new Zk1OpaqueCatalogCasLedger(
    path.join(folder, "cas.sqlite"), {
      bootstrapNew: true, signingPrivateKey: casKeys.privateKey,
      catalogSignerPublicKey: device.publicKey, trustedScope: scope,
      minimumHead: { sequence: 0, digest: Buffer.alloc(32) },
      independentFloor: floorClient,
    });
  await casLedger.ready;
  const casServer = createZk1OpaqueCatalogCasHttpsServer({
    ledger: casLedger, key: file("cas.key"), cert: file("cas.pem"),
    clientCa: file("ca.pem"), authorizedClientFingerprint256: clientFingerprint,
  });
  await new Promise((resolve) => casServer.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    if (casServer.listening) {
      casServer.closeAllConnections(); casServer.close();
    }
    casLedger.close();
  });
  const casClient = createZk1OpaqueCatalogCasHttpsClient({
    endpoint: "https://127.0.0.1:" + casServer.address().port + "/",
    ca: file("ca.pem"), clientKey: file("client.key"),
    clientCert: file("client.pem"),
    serverFingerprint256: new crypto.X509Certificate(file("cas.pem")).fingerprint256,
    authorityPublicKey: casKeys.publicKey,
  });
  const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
    sequence: 1, previous_digest: Buffer.alloc(32),
    manifest_revision: 1, manifest_digest: crypto.randomBytes(32),
    epoch: 1, signer_device_id: "device", total_count: 0,
    page_digests: [], issued_at: Math.floor(Date.now() / 1000) };
  const rawHead = Buffer.from(await z.encodeDeterministic(header));
  const headSignature = crypto.sign(null, Buffer.concat([HEAD, rawHead]), device.privateKey);
  const digest = catalogHeadDigest(rawHead, headSignature);
  const written = await casClient.compareAndSwap({ scope, expectedSequence: 0,
    expectedDigest: Buffer.alloc(32), nextSequence: 1, nextDigest: digest,
    nonce: crypto.randomBytes(32), headBytes: rawHead, headSignature,
    pageBodies: [] });
  assert.ok(written.length);
  assert.deepEqual(floorLedger.inspect(), { sequence: 1, digest });
  const records = [{ sequence: 1, header: rawHead, signature: headSignature,
    page_bodies: [] }];
  const params = { scope, records, previousSequence: 0,
    previousDigest: Buffer.alloc(32), previousCheckpointDigest: Buffer.alloc(32),
    resolveCatalogSigner: async () => device.publicKey };
  const archive = await create({ ...params,
    checkpointPrivateKey: checkpoint.privateKey,
    issuedAt: Math.floor(Date.now() / 1000) });
  const approvalTemplate = {
    type: "rootark-zk1-opaque-catalog-checkpoint-owner-approval/v2", ...scope,
    checkpoint_digest: archive.checkpointDigest, previous_sequence: 0,
    previous_checkpoint_digest: Buffer.alloc(32), final_sequence: 1,
    final_digest: digest, cas_signer_spki_sha256: fp(casKeys.publicKey),
    floor_signer_spki_sha256: fp(floorKeys.publicKey),
    checkpoint_signer_spki_sha256: fp(checkpoint.publicKey),
    nonce: crypto.randomBytes(32), issued_at: Math.floor(Date.now() / 1000),
  };
  const approval = await ownerSign(approvalTemplate, owner.privateKey);
  const candidate = { checkpointBytes: archive.checkpointBytes,
    checkpointSignature: archive.checkpointSignature, records,
    previousSequence: 0, previousDigest: Buffer.alloc(32),
    previousCheckpointDigest: Buffer.alloc(32),
    ownerApprovalBytes: approval.approvalBytes,
    ownerApprovalSignature: approval.approvalSignature };
  const database = path.join(folder, "stage.sqlite");
  const stageOptions = { trustedScope: scope, ownerPublicKey: owner.publicKey,
    checkpointPublicKey: checkpoint.publicKey, casClient, floorClient,
    resolveCatalogSigner: params.resolveCatalogSigner };
  // The first CAS read fails after a fully durable local PENDING intent.
  const firstRealRead = casClient.readHead.bind(casClient);
  let drop = true;
  const flakyCasClient = { publicKey: casClient.publicKey,
    readHead: async (args) => {
      if (drop) { drop = false; throw new Error("SIMULATED_DISCONNECT"); }
      return firstRealRead(args);
    } };
  let stage = new Stage(database, { ...stageOptions,
    casClient: flakyCasClient, bootstrapNew: true });
  t.after(() => { if (stage.db.open) stage.close(); });
  t.after(() => fs.rmSync(folder, { recursive: true, force: true, maxRetries: 5 }));
  assert.equal((await stage.audit()).count, 0);
  await assert.rejects(stage.stage(candidate), err("ZK_OPAQUE_CHECKPOINT_STAGE_ACK_UNCERTAIN"));
  const pending = await stage.audit();
  assert.equal(pending.count, 1);
  assert.equal(pending.pending, true);
  assert.equal(pending.lastSequence, 1);
  stage.close();
  stage = new Stage(database, { ...stageOptions, bootstrapNew: false });
  const staged = await stage.reconcilePending();
  assert.equal(staged.outcome, "LOCAL_STAGED_NOT_PUBLISHED");
  assert.equal(staged.publishedV2, false);
  assert.equal(staged.remoteCloudDurabilityProven, false);
  assert.equal((await stage.audit()).pending, false);
  assert.deepEqual((await stage.revalidateRemote(1)).checkpointDigest,
    archive.checkpointDigest);
  const replayNonce = crypto.randomBytes(32);
  const replay = await casClient.readHead({ scope, nonce: replayNonce });
  const replayProbe = new Stage(database, { ...stageOptions,
    casClient: { publicKey: casClient.publicKey, readHead: async () => replay },
    bootstrapNew: false });
  await assert.rejects(replayProbe.revalidateRemote(1),
    err("ZK_OPAQUE_CHECKPOINT_STAGE_AUTHORITY_CONFLICT"));
  replayProbe.close();

  // Another process/connection opens the same immutable staged SQLite ledger.
  const peer = new Stage(database, { ...stageOptions, bootstrapNew: false });
  t.after(() => { if (peer.db.open) peer.close(); });
  assert.equal((await peer.audit()).count, 1);
  const concurrent = await Promise.all([stage.stage(candidate), peer.stage(candidate)]);
  assert.ok(concurrent.every((outcome) => outcome.outcome ===
    "LOCAL_STAGED_NOT_PUBLISHED"));
  assert.equal((await stage.audit()).count, 1);

  // Independent Windows processes compete over one new SQLite stage while
  // the CAS and floor remain separate HTTPS/mTLS authority stores.
  const multiprocessDb = path.join(folder, "stage-multiprocess.sqlite");
  const preopened = new Stage(multiprocessDb, { ...stageOptions, bootstrapNew: true });
  preopened.close();
  const candidateFile = path.join(folder, "stage-candidate.cbor");
  fs.writeFileSync(candidateFile, await z.encodeDeterministic(candidate));
  const configFile = path.join(folder, "stage-process.json");
  const config = {
    stageDb: multiprocessDb, candidate: candidateFile, directory: folder,
    scope: Object.fromEntries(Object.entries(scope)
      .map(([name, value]) => [name, value.toString("base64url")])),
    casEndpoint: "https://127.0.0.1:" + casServer.address().port + "/",
    floorEndpoint: "https://127.0.0.1:" + floorServer.address().port + "/",
    casFingerprint: new crypto.X509Certificate(file("cas.pem")).fingerprint256,
    floorFingerprint: new crypto.X509Certificate(file("floor.pem")).fingerprint256,
    casSignerPem: casKeys.publicKey.export({ type: "spki", format: "pem" }),
    floorSignerPem: floorKeys.publicKey.export({ type: "spki", format: "pem" }),
    checkpointSignerPem: checkpoint.publicKey.export({ type: "spki", format: "pem" }),
    ownerSignerPem: owner.publicKey.export({ type: "spki", format: "pem" }),
    deviceSignerPem: device.publicKey.export({ type: "spki", format: "pem" }),
  };
  fs.writeFileSync(configFile, JSON.stringify(config));
  const childFile = path.join(__dirname, "..", "lab", "issue-65-packet-b",
    "issue-65-checkpoint-stage-child.js");
  const forkOnce = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [childFile, configFile], {
      cwd: path.join(__dirname, ".."), windowsHide: true,
      env: process.env, stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "", error = "";
    child.stdout.on("data", (part) => { out += part; });
    child.stderr.on("data", (part) => { error += part; });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code !== 0) reject(new Error("child-failure: " + out + error));
      else { try { resolve(JSON.parse(out)); } catch (parseError) { reject(parseError); } }
    });
  });
  const [firstChild, secondChild] = await Promise.all([forkOnce(), forkOnce()]);
  assert.deepEqual([firstChild.outcome, secondChild.outcome],
    ["LOCAL_STAGED_NOT_PUBLISHED", "LOCAL_STAGED_NOT_PUBLISHED"]);
  const checkedMulti = new Stage(multiprocessDb, { ...stageOptions,
    bootstrapNew: false });
  assert.deepEqual({ count: (await checkedMulti.audit()).count,
    pending: (await checkedMulti.audit()).pending }, { count: 1, pending: false });
  checkedMulti.close();
  const alternateArchive = await create({ ...params,
    checkpointPrivateKey: checkpoint.privateKey,
    issuedAt: Math.floor(Date.now() / 1000) + 1 });
  const alternateApproval = await ownerSign({ ...approvalTemplate,
    checkpoint_digest: alternateArchive.checkpointDigest,
    nonce: crypto.randomBytes(32) }, owner.privateKey);
  await assert.rejects(peer.stage({ ...candidate,
    checkpointBytes: alternateArchive.checkpointBytes,
    checkpointSignature: alternateArchive.checkpointSignature,
    ownerApprovalBytes: alternateApproval.approvalBytes,
    ownerApprovalSignature: alternateApproval.approvalSignature }),
  err("ZK_OPAQUE_CHECKPOINT_STAGE_DENIED"));

  // Poisoned and downgraded approvals must never update the staged row.
  await assert.rejects(stage.stage({ ...candidate,
    ownerApprovalSignature: crypto.sign(null, approval.approvalBytes,
      attacker.privateKey) }), err("ZK_OPAQUE_CHECKPOINT_STAGE_DENIED"));
  await assert.rejects(stage.stage({ ...candidate,
    checkpointSignature: crypto.sign(null, archive.checkpointBytes,
      attacker.privateKey) }), err("ZK_OPAQUE_CHECKPOINT_V2_UNVERIFIED"));
  await assert.rejects(stage.stage({ ...candidate,
    records: [{ ...records[0], signature: crypto.randomBytes(64) }] }),
  err("ZK_OPAQUE_CHECKPOINT_V2_UNVERIFIED"));
  await assert.rejects(stage.stage({ ...candidate,
    previousSequence: 128 }), err("ZK_OPAQUE_CHECKPOINT_V2_UNVERIFIED"));
  await assert.rejects(stage.stage({ ...candidate,
    ownerApprovalBytes: Buffer.from(approval.approvalBytes).subarray(0, 2) }),
  err("ZK_OPAQUE_CHECKPOINT_STAGE_DENIED"));
  assert.throws(() => new Stage(database, { ...stageOptions,
    bootstrapNew: false, ownerPublicKey: attacker.publicKey }),
  err("ZK_OPAQUE_CHECKPOINT_STAGE_DENIED"));
  assert.throws(() => new Stage(database, { ...stageOptions,
    bootstrapNew: false, checkpointPublicKey: owner.publicKey }),
  err("ZK_OPAQUE_CHECKPOINT_STAGE_DENIED"));
  assert.throws(() => stage.db.prepare(
    "DELETE FROM checkpoint_stages WHERE final_sequence=1").run());
  assert.throws(() => stage.db.prepare(
    "UPDATE checkpoint_stages SET payload=? WHERE final_sequence=1")
    .run(crypto.randomBytes(32)));

  // Actual CAS/floor heads remain v1 sequence 1; no v2 remote mutation occurs.
  assert.equal((await z.decodeDeterministic(await casClient.readHead({
    scope, nonce: crypto.randomBytes(32) }))).sequence, 1);
  assert.equal(floorLedger.inspect().sequence, 1);
  assert.equal((await stage.audit()).count, 1);
  const bogusNext = { ...candidate, previousSequence: 128 };
  await assert.rejects(peer.stage(bogusNext),
    err("ZK_OPAQUE_CHECKPOINT_V2_UNVERIFIED"));
  // Validly signed 129 data is still prohibited by the STAGING ceiling.
  const priorDigest = crypto.randomBytes(32);
  const priorCheckpoint = crypto.randomBytes(32);
  const header129 = { ...header, sequence: 129, previous_digest: priorDigest };
  const raw129 = Buffer.from(await z.encodeDeterministic(header129));
  const signature129 = crypto.sign(null, Buffer.concat([HEAD, raw129]),
    device.privateKey);
  const digest129 = catalogHeadDigest(raw129, signature129);
  const archive129 = await create({ ...params, records: [{
    sequence: 129, header: raw129, signature: signature129, page_bodies: [],
  }], previousSequence: 128, previousDigest: priorDigest,
  previousCheckpointDigest: priorCheckpoint,
  checkpointPrivateKey: checkpoint.privateKey,
  issuedAt: Math.floor(Date.now() / 1000) });
  const approval129 = { ...approvalTemplate,
    previous_sequence: 128, previous_checkpoint_digest: priorCheckpoint,
    final_sequence: 129, final_digest: digest129,
    checkpoint_digest: archive129.checkpointDigest,
    nonce: crypto.randomBytes(32) };
  const ownerApproval129 = Buffer.from(await z.encodeDeterministic(approval129));
  const ownerSignature129 = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-owner-approval/v2\0"),
    ownerApproval129]), owner.privateKey);
  await assert.rejects(peer.stage({ ...candidate,
    checkpointBytes: archive129.checkpointBytes,
    checkpointSignature: archive129.checkpointSignature,
    records: archive129.records,
    previousSequence: 128, previousDigest: priorDigest,
    previousCheckpointDigest: priorCheckpoint,
    ownerApprovalBytes: ownerApproval129,
    ownerApprovalSignature: ownerSignature129 }),
  err("ZK_OPAQUE_CHECKPOINT_STAGE_DENIED"));
  stage.close(); peer.close();
  const restarted = new Stage(database, { ...stageOptions, bootstrapNew: false });
  t.after(() => { if (restarted.db.open) restarted.close(); });
  assert.equal((await restarted.audit()).lastSequence, 1);
  assert.equal((await restarted.revalidateRemote(1)).publishedV2, false);
  restarted.close();
});
