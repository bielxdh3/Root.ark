"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const http = require("node:http");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const z = require("../src/crypto/rootark-zk-1");
const { createAuthenticatedOpaqueCatalogArchiveV2 } =
  require("../src/crypto/rootark-zk1-opaque-catalog-checkpoint-v2");
const { verifyRolloverPreflight, OWNER_DOMAIN } =
  require("../src/services/zk1OpaqueCatalogV1RolloverPreflight");
const { catalogCasDomain } = require("../src/services/zk1OpaqueCatalog");
const { Zk1OpaqueCatalogCasLedger } = require("../src/services/zk1OpaqueCatalogCasLedger");
const { createZk1OpaqueCatalogCasHttpsServer } =
  require("../src/services/zk1OpaqueCatalogCasHttpsServer");
const { createZk1OpaqueCatalogCasHttpsClient } =
  require("../src/services/zk1OpaqueCatalogCasHttpsClient");
const { Zk1OpaqueCatalogIndependentFloorLedger,
  createZk1OpaqueCatalogIndependentFloorHttpsServer,
  createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { OpaqueCheckpointV2Authority, createOpaqueCheckpointV2HttpsServer,
  createOpaqueCheckpointV2HttpsClient, createOpaqueCheckpointV2Coordinator } =
  require("../src/services/zk1OpaqueCheckpointV2Remote");
const { Zk1OpaqueCheckpointV2Client } =
  require("../src/services/zk1OpaqueCheckpointV2Client");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { privateAuthorityDirectory } =
  require("./support/issue-65-private-authority-directory");
const browser = require("../public/client/rootark-zk1-opaque-v1-v2-handoff-preflight");
const HEAD = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");
const FLOOR = Buffer.from("Root.ark/zk-1/opaque-catalog-independent-floor/v1\0");
const digest = (d, ...parts) => {
  const h = crypto.createHash("sha256").update(d);
  for (const p of parts) h.update(p);
  return h.digest();
};
const id = (key) => digest(Buffer.alloc(0), key.export({ format: "der", type: "spki" }));
const b64 = (v) => Buffer.from(v).toString("base64url");
const pair = () => crypto.generateKeyPairSync("ed25519");
const signed = async (domain, body, privateKey) =>
  Buffer.from(await z.encodeDeterministic({ ...body, signature:
    crypto.sign(null, Buffer.concat([domain,
      Buffer.from(await z.encodeDeterministic(body))]), privateKey) }));
let fixture;
async function build() {
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("rollover-128"), keyring_id: crypto.randomBytes(16) };
  const catalog = pair(), checkpoint = pair(), owner = pair();
  const v1Cas = pair(), v1Floor = pair(), v2Cas = pair(), v2Floor = pair();
  const ownerHead = { revision: 8, digest: crypto.randomBytes(32), epoch: 4 };
  const archiveOwnerDigest = crypto.randomBytes(32);
  let current = Buffer.alloc(32);
  const records128 = [];
  for (let sequence = 1; sequence <= 128; sequence++) {
    const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
      sequence, previous_digest: current, manifest_revision: 7,
      manifest_digest: archiveOwnerDigest, epoch: 3, signer_device_id: "device-zk",
      total_count: 0, page_digests: [], issued_at: Math.floor(Date.now() / 1000) };
    const raw = Buffer.from(await z.encodeDeterministic(header));
    const signature = crypto.sign(null, Buffer.concat([HEAD, raw]), catalog.privateKey);
    records128.push({ sequence, header: raw, signature, page_bodies: [] });
    current = digest(HEAD, raw, signature);
  }
  const archive = await createAuthenticatedOpaqueCatalogArchiveV2({
    scope, records: records128, previousSequence: 0, previousDigest: Buffer.alloc(32),
    previousCheckpointDigest: Buffer.alloc(32),
    resolveCatalogSigner: async () => catalog.publicKey,
    checkpointPrivateKey: checkpoint.privateKey, issuedAt: Math.floor(Date.now() / 1000),
  });
  const checkpointBody = await z.decodeDeterministic(archive.checkpointBytes);
  const now = Math.floor(Date.now() / 1000);
  const handoff = { type: "rootark-zk1-opaque-v1-v2-owner-rollover-handoff/v1",
    ...Object.fromEntries(Object.entries(scope).map(([k, v]) => [k, b64(v)])),
    v1_sequence: 128, v1_digest: b64(current),
    v1_archive_root: b64(checkpointBody.archive_root),
    v1_archive_checkpoint: b64(archive.checkpointDigest),
    v2_cas_spki_sha256: b64(id(v2Cas.publicKey)),
    v2_floor_spki_sha256: b64(id(v2Floor.publicKey)),
    v2_checkpoint_spki_sha256: b64(id(checkpoint.publicKey)),
    owner_revision: ownerHead.revision, owner_digest: b64(ownerHead.digest),
    owner_epoch: 4, next_epoch: 4, nonce: b64(crypto.randomBytes(32)),
    issued_at: now - 2, expires_at: now + 120 };
  const ownerSignature = crypto.sign(null, Buffer.concat([OWNER_DOMAIN,
    Buffer.from(JSON.stringify(handoff))]), owner.privateKey);
  const state = { current, changedCas: false, changedFloor: false,
    signedReceiptBad: false, repeatNonce: null, rollbackOnSecond: false,
    casReads: 0 };
  const v1CasClient = { async readHead({ scope: received, nonce }) {
    assert.deepEqual(received, scope);
    state.casReads++;
    const rollback = state.changedCas || (state.rollbackOnSecond && state.casReads >= 2);
    const body = { type: "rootark-zk1-opaque-catalog-cas/v1", ...scope,
      sequence: rollback ? 127 : 128,
      digest: rollback ? crypto.randomBytes(32) : current,
      nonce: state.repeatNonce || nonce, observed_at: now };
    const raw = await signed(catalogCasDomain, body, v1Cas.privateKey);
    if (state.signedReceiptBad) raw[raw.length - 1] ^= 1;
    return raw;
  } };
  const v1FloorClient = { async readHead() {
    const body = { type: "rootark-zk1-opaque-catalog-independent-floor/v1",
      ...scope, cas_signer_spki_sha256: id(v1Cas.publicKey),
      sequence: state.changedFloor ? 127 : 128,
      digest: state.changedFloor ? crypto.randomBytes(32) : current,
      nonce: crypto.randomBytes(32), observed_at: now };
    return { sequence: body.sequence, digest: body.digest,
      proof: await signed(FLOOR, body, v1Floor.privateKey) };
  } };
  const options = { scope, records128, stateDigest: current,
    archiveCheckpointBytes: archive.checkpointBytes,
    archiveCheckpointSignature: archive.checkpointSignature,
    v2PredecessorCheckpointPin: b64(archive.checkpointDigest),
    checkpointKey: checkpoint.publicKey,
    resolveCatalogSigner: async () => catalog.publicKey,
    v1CasClient, v1FloorClient, v1CasKey: v1Cas.publicKey,
    v1FloorKey: v1Floor.publicKey, v2CasKey: v2Cas.publicKey,
    v2FloorKey: v2Floor.publicKey, v2CheckpointKey: checkpoint.publicKey,
    ownerKey: owner.publicKey, ownerHead, handoff, ownerSignature,
    independentSpkiPins: { v1Cas: b64(id(v1Cas.publicKey)),
      v1Floor: b64(id(v1Floor.publicKey)), v2Cas: b64(id(v2Cas.publicKey)),
      v2Floor: b64(id(v2Floor.publicKey)),
      archiveCheckpoint: b64(id(checkpoint.publicKey)),
      v2Checkpoint: b64(id(checkpoint.publicKey)),
      owner: b64(id(owner.publicKey)) } };
  const browserInput = { handoff, ownerSignature: b64(ownerSignature),
    ownerPublicKeyRaw: b64(owner.publicKey.export({ type: "spki", format: "der" }).subarray(-32)),
    ownerSpkiSha256: b64(id(owner.publicKey)),
    scope: Object.fromEntries(Object.entries(scope).map(([k, v]) => [k, b64(v)])),
    ownerHead: { revision: ownerHead.revision, digest: b64(ownerHead.digest), epoch: ownerHead.epoch },
    v1Digest: b64(current), archiveRoot: b64(checkpointBody.archive_root),
    archiveCheckpoint: b64(archive.checkpointDigest),
    v2PredecessorCheckpointPin: b64(archive.checkpointDigest),
    v2CasSpkiSha256: b64(id(v2Cas.publicKey)),
    v2FloorSpkiSha256: b64(id(v2Floor.publicKey)),
    v2CheckpointSpkiSha256: b64(id(checkpoint.publicKey)) };
  return { options, state, browserInput, v2Cas, v2Floor, v1Cas, v1Floor,
    catalog, checkpoint, owner };
}
test("authenticated 128-head archival rollover preflight is read-only; adversarial fails closed", {
  timeout: 90000 }, async () => {
  const { options, state, browserInput } = await build();
  fixture = browserInput;
  const value = await verifyRolloverPreflight(options);
  assert.equal(value.state, "V1_128_ARCHIVED_OWNER_HANDOFF_VERIFIED_READ_ONLY");
  assert.equal(value.archivesRetained, 128);
  assert.equal(value.v2WriteAuthorized, false);
  assert.equal(value.v1ResetAuthorized, false);
  assert.equal((await browser.verifyOwnerHandoff(browserInput)).nextEpoch, 4);
  const denies = (opts) => assert.rejects(verifyRolloverPreflight(opts),
    { code: "ZK_V1_V2_ROLLOVER_PREFLIGHT_DENIED" });
  await denies({ ...options, records128: options.records128.slice(1) });
  await denies({ ...options, records128: options.records128.map((r, i) =>
    i === 70 ? { ...r, signature: crypto.randomBytes(64) } : r) });
  await denies({ ...options, records128: [...options.records128.slice(0, 127),
    options.records128[126]] });
  await denies({ ...options, ownerSignature: crypto.randomBytes(64) });
  await denies({ ...options, v2PredecessorCheckpointPin: b64(crypto.randomBytes(32)) });
  await denies({ ...options, independentSpkiPins: { ...options.independentSpkiPins,
    owner: b64(crypto.randomBytes(32)) } });
  await denies({ ...options, handoff: { ...options.handoff, next_epoch: 2 } });
  await denies({ ...options, handoff: { ...options.handoff,
    v2_cas_spki_sha256: b64(crypto.randomBytes(32)) } });
  await denies({ ...options, handoff: { ...options.handoff,
    expires_at: Math.floor(Date.now() / 1000) - 1 } });
  await denies({ ...options, ownerHead: { ...options.ownerHead, epoch: 3 } });
  await denies({ ...options, v2FloorKey: options.v2CasKey });
  state.changedCas = true;
  await denies(options);
  state.changedCas = false; state.changedFloor = true;
  await denies(options);
  state.changedFloor = false; state.signedReceiptBad = true;
  await denies(options);
  state.signedReceiptBad = false; state.repeatNonce = crypto.randomBytes(32);
  await denies(options);
  state.repeatNonce = null; state.casReads = 0; state.rollbackOnSecond = true;
  await denies(options);
  for (const input of [
    { ...browserInput, handoff: { ...browserInput.handoff, next_epoch: 1 } },
    { ...browserInput, ownerSignature: b64(crypto.randomBytes(64)) },
    { ...browserInput, ownerSpkiSha256: b64(crypto.randomBytes(32)) },
    { ...browserInput, archiveRoot: b64(crypto.randomBytes(32)) },
    { ...browserInput, handoff: { ...browserInput.handoff,
      issued_at: Math.floor(Date.now() / 1000) - 600,
      expires_at: Math.floor(Date.now() / 1000) - 300 } },
  ]) await assert.rejects(browser.verifyOwnerHandoff(input), /UNVERIFIED/);
});
test("real Edge verifies owner V1 #128 -> V2 epoch handoff under strict CSP/loopback", {
  timeout: 60000 }, async (t) => {
  const edge = ["C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe"].find(fs.existsSync);
  if (!edge) { t.skip("Microsoft Edge unavailable"); return; }
  const input = fixture || (await build()).browserInput;
  const js = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-opaque-v1-v2-handoff-preflight.js"), "utf8");
  const runner = "addEventListener('load',async()=>{const node=document.getElementById('result');"
    + "try{const result=await RootarkZk1OpaqueV1V2HandoffPreflight.verifyOwnerHandoff("
    + JSON.stringify(input) + ");if(result.v2WriteAuthorized!==false)"
    + "throw Error('WRITER_ENABLED');await RootarkZk1OpaqueV1V2HandoffPreflight."
    + "verifyOwnerHandoff({..."+JSON.stringify(input)+",ownerSignature:'forged'}).then("
    + "()=>{throw Error('FORGERY_ACCEPTED')},()=>{});node.textContent='EDGE_ROLLOVER_PASS'}"
    + "catch(e){node.textContent='EDGE_ROLLOVER_FAIL:'+e.message}});";
  const server = http.createServer((req, res) => {
    res.setHeader("Content-Security-Policy",
      "default-src 'none'; script-src 'self'; connect-src 'none'");
    const src = req.url === "/handoff.js" ? js : req.url === "/runner.js" ? runner
      : req.url === "/" ? "<output id='result'>PENDING</output>"
        + "<script src='/handoff.js'></script><script src='/runner.js'></script>" : null;
    res.writeHead(src ? 200 : 404, { "content-type": req.url === "/"
      ? "text/html; charset=utf-8" : "text/javascript; charset=utf-8" });
    res.end(src || "");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-128-handoff-edge-"));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(folder, { recursive: true, force: true, maxRetries: 3 });
  });
  const origin = "http://127.0.0.1:" + server.address().port;
  const response = await promisify(execFile)(edge, ["--headless=new",
    "--disable-gpu", "--no-first-run", "--disable-extensions",
    "--no-default-browser-check", "--virtual-time-budget=12000",
    "--user-data-dir=" + path.join(folder, "edge-profile"),
    "--dump-dom", origin], { timeout: 35000, windowsHide: true,
    maxBuffer: 1024 * 1024 });
  assert.match(response.stdout, /EDGE_ROLLOVER_PASS/);
  assert.doesNotMatch(response.stdout, /EDGE_ROLLOVER_FAIL/);
});

test("real V2 CAS and FLOOR mTLS baseline refuses last-head-only checkpoint and missing full-128 owner proof", {
  timeout: 120000 }, async (t) => {
  const { options, v2Cas, v2Floor, v1Cas, v1Floor, catalog, checkpoint, owner } = await build();
  const folder = privateAuthorityDirectory("zk65-128-gate-mtls-");
  if (process.platform !== "win32") fs.chmodSync(folder, 0o700);
  generateNativeFixtureCertificates(folder, {
    caSubject: "ZK65 full archive mTLS",
    servers: ["cas", "floor", "v1cas", "v1floor"], clients: ["client"],
  });
  const file = (name) => fs.readFileSync(path.join(folder, name));
  const fpCert = (name) => new crypto.X509Certificate(file(name)).fingerprint256;
  const v1FloorLedger = new Zk1OpaqueCatalogIndependentFloorLedger(
    path.join(folder, "v1floor.sqlite"), { bootstrapNew: true,
      trustedScope: options.scope, signingPrivateKey: v1Floor.privateKey,
      casSignerPublicKey: v1Cas.publicKey,
      catalogSignerPublicKey: catalog.publicKey });
  const v1FloorServer = createZk1OpaqueCatalogIndependentFloorHttpsServer({
    ledger: v1FloorLedger, key: file("v1floor.key"), cert: file("v1floor.pem"),
    clientCa: file("ca.pem"), authorizedClientFingerprint256: fpCert("client.pem") });
  await new Promise((resolve) => v1FloorServer.listen(0, "127.0.0.1", resolve));
  const v1FloorClient = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: `https://127.0.0.1:${v1FloorServer.address().port}/`,
    ca: file("ca.pem"), clientKey: file("client.key"), clientCert: file("client.pem"),
    serverFingerprint256: fpCert("v1floor.pem"), floorPublicKey: v1Floor.publicKey,
    casSignerPublicKey: v1Cas.publicKey, trustedScope: options.scope });
  const v1CasLedger = new Zk1OpaqueCatalogCasLedger(path.join(folder, "v1cas.sqlite"), {
    bootstrapNew: true, signingPrivateKey: v1Cas.privateKey,
    catalogSignerPublicKey: catalog.publicKey, trustedScope: options.scope,
    minimumHead: { sequence: 0, digest: Buffer.alloc(32) },
    independentFloor: v1FloorClient });
  await v1CasLedger.ready;
  const v1CasServer = createZk1OpaqueCatalogCasHttpsServer({
    ledger: v1CasLedger, key: file("v1cas.key"), cert: file("v1cas.pem"),
    clientCa: file("ca.pem"), authorizedClientFingerprint256: fpCert("client.pem") });
  await new Promise((resolve) => v1CasServer.listen(0, "127.0.0.1", resolve));
  const v1CasClient = createZk1OpaqueCatalogCasHttpsClient({
    endpoint: `https://127.0.0.1:${v1CasServer.address().port}/`,
    ca: file("ca.pem"), clientKey: file("client.key"), clientCert: file("client.pem"),
    serverFingerprint256: fpCert("v1cas.pem"), authorityPublicKey: v1Cas.publicKey });
  t.after(() => {
    for (const server of [v1CasServer, v1FloorServer]) {
      if (server.listening) { server.closeAllConnections(); server.close(); }
    }
    v1CasLedger.close(); v1FloorLedger.close();
    fs.rmSync(folder, { recursive: true, force: true, maxRetries: 5 });
  });
  let previous = Buffer.alloc(32);
  for (const record of options.records128) {
    const nextDigest = digest(HEAD, record.header, record.signature);
    await v1CasClient.compareAndSwap({ scope: options.scope,
      expectedSequence: record.sequence - 1, expectedDigest: previous,
      nextSequence: record.sequence, nextDigest, nonce: crypto.randomBytes(32),
      headBytes: record.header, headSignature: record.signature, pageBodies: [] });
    previous = nextDigest;
  }
  assert.equal(v1FloorLedger.inspect().sequence, 128);
  const fullCheckpoint = Buffer.from(options.archiveCheckpointBytes);
  const fullDigest = digest(Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-digest/v2\0"),
    fullCheckpoint, options.archiveCheckpointSignature);
  async function withAuthorities(baseCheckpoint, action, enforceAuthorityProof = false,
    signedOwnerWitness = false) {
    const trust = { genesisDigest: crypto.randomBytes(32),
      pinnedWitness: { publicKey: pair().publicKey, keyId: crypto.randomBytes(16) },
      minimumHead: { revision: 8, digest: options.ownerHead.digest, epoch: 4 },
      freshWitnessHead: async () => { throw new Error("NO_OWNER_WRITE_PROOF"); } };
    let liveOwnerDigest = options.ownerHead.digest;
    let liveOwnerRevision = 8;
    if (enforceAuthorityProof || signedOwnerWitness) {
      const witness = pair(), keyId = crypto.randomBytes(16);
      trust.pinnedWitness = { publicKey: witness.publicKey, keyId };
      trust.minimumHead = { revision: 8, witnessSequence: 8,
        digest: options.ownerHead.digest };
      trust.freshWitnessHead = async ({ scope, nonce }) => signed(Buffer.from(
        "Root.ark/zk-1/recovery-witness-head/v1\0"), {
        type: "rootark-recovery-witness-head/v1", witness_key_id: keyId, ...scope,
        current_revision: liveOwnerRevision, current_manifest_digest: liveOwnerDigest,
        witness_sequence: liveOwnerRevision, nonce, observed_at: Math.floor(Date.now() / 1000),
        status: "committed", pending_reservation_id: null }, witness.privateKey);
    }
    const authorityProof = enforceAuthorityProof ? {
      requireFullV1ArchiveRollover: true,
      fullV1ArchiveRollover: { ...options, v1CasClient, v1FloorClient },
    } : {};
    const casDb = path.join(folder, `cas-${crypto.randomBytes(5).toString('hex')}.sqlite`);
    const floorDb = path.join(folder, `floor-${crypto.randomBytes(5).toString('hex')}.sqlite`);
    const cas = new OpaqueCheckpointV2Authority(path.join(folder,
      path.basename(casDb)), {
      role: "CAS", bootstrapNew: true, scope: options.scope,
      signingPrivateKey: v2Cas.privateKey, casSignerPublicKey: v2Cas.publicKey,
      floorSignerPublicKey: v2Floor.publicKey, checkpointPublicKey: options.checkpointKey,
      ownerPublicKey: options.ownerKey, ownerTrust: trust,
      baseDigest: options.stateDigest,
      baseCheckpoint, ...authorityProof });
    const floor = new OpaqueCheckpointV2Authority(path.join(folder,
      path.basename(floorDb)), {
      role: "FLOOR", bootstrapNew: true, scope: options.scope,
      signingPrivateKey: v2Floor.privateKey, casSignerPublicKey: v2Cas.publicKey,
      floorSignerPublicKey: v2Floor.publicKey, checkpointPublicKey: options.checkpointKey,
      ownerPublicKey: options.ownerKey, ownerTrust: trust,
      baseDigest: options.stateDigest, baseCheckpoint, ...authorityProof });
    const servers = [
      createOpaqueCheckpointV2HttpsServer({ ledger: cas, tlsKey: file("cas.key"),
        tlsCert: file("cas.pem"), clientCa: file("ca.pem"),
        clientFingerprint256: fpCert("client.pem") }),
      createOpaqueCheckpointV2HttpsServer({ ledger: floor, tlsKey: file("floor.key"),
        tlsCert: file("floor.pem"), clientCa: file("ca.pem"),
        clientFingerprint256: fpCert("client.pem") }),
    ];
    try {
      for (const server of servers)
        await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      const clients = servers.map((server, i) => createOpaqueCheckpointV2HttpsClient({
        endpoint: `https://127.0.0.1:${server.address().port}/`,
        ca: file("ca.pem"), clientKey: file("client.key"), clientCert: file("client.pem"),
        serverFingerprint256: fpCert(i ? "floor.pem" : "cas.pem"),
        authorityPublicKey: i ? v2Floor.publicKey : v2Cas.publicKey,
        casPublicKey: v2Cas.publicKey, floorPublicKey: v2Floor.publicKey,
        scope: options.scope,
      }));
      await action(...clients, trust, { cas, floor, authorityProof,
        casDb, floorDb, setLiveOwnerDigest: (digest) => {
          liveOwnerDigest = digest;
          liveOwnerRevision = digest.equals(options.ownerHead.digest) ? 8 : 9;
        } });
    } finally {
      for (const server of servers) {
        if (server.listening) { server.closeAllConnections(); server.close(); }
      }
      cas.close(); floor.close();
    }
  }
  await withAuthorities(fullDigest, async (casClient, floorClient, trust) => {
    const shared = { casClient, floorClient, trustedScope: options.scope,
      expectedV1Digest: options.stateDigest, expectedV1Checkpoint: fullDigest,
      v1CasClient, v1FloorClient,
      pinnedOwnerPublicKey: options.ownerKey,
      pinnedCheckpointPublicKey: options.checkpointKey };
    assert.throws(() => createOpaqueCheckpointV2Coordinator({ ...shared,
      requireFullV1ArchiveRollover: true }), /ZK_CHECKPOINT_V2/);
    const guarded = createOpaqueCheckpointV2Coordinator({ ...shared,
      requireFullV1ArchiveRollover: true, fullV1ArchiveRollover: {
        ...options, v1CasClient, v1FloorClient } });
    const result = await guarded.verifyFullArchiveBaseline();
    assert.equal(result.sequence, 128);
    assert.equal(result.v2WriteAuthorized, false);
    const impostor = pair();
    const fakeOwnerRollover = {
      ...options, v1CasClient, v1FloorClient,
      ownerKey: impostor.publicKey,
      ownerSignature: crypto.sign(null, Buffer.concat([OWNER_DOMAIN,
        Buffer.from(JSON.stringify(options.handoff))]), impostor.privateKey),
      independentSpkiPins: { ...options.independentSpkiPins,
        owner: b64(id(impostor.publicKey)) },
    };
    // Without independent V2 trust bindings, the unchanged genuine 128-head
    // archive would authenticate this replacement self-signed owner handoff.
    assert.equal((await verifyRolloverPreflight(fakeOwnerRollover)).sequence, 128);
    const impostorOwnerCoordinator = createOpaqueCheckpointV2Coordinator({
      ...shared, requireFullV1ArchiveRollover: true,
      fullV1ArchiveRollover: fakeOwnerRollover });
    await assert.rejects(impostorOwnerCoordinator.verifyFullArchiveBaseline(),
      /ZK_CHECKPOINT_V2_FULL_ARCHIVE_UNVERIFIED/,
      "a self-signed handoff from a foreign owner cannot authorize strict admission");
    const substitutedCheckpoint = pair();
    const changedCheckpointHandoff = { ...options.handoff,
      v2_checkpoint_spki_sha256: b64(id(substitutedCheckpoint.publicKey)) };
    const fakeCheckpointRollover = {
      ...options, v1CasClient, v1FloorClient,
      v2CheckpointKey: substitutedCheckpoint.publicKey,
      handoff: changedCheckpointHandoff,
      ownerSignature: crypto.sign(null, Buffer.concat([OWNER_DOMAIN,
        Buffer.from(JSON.stringify(changedCheckpointHandoff))]), owner.privateKey),
      independentSpkiPins: { ...options.independentSpkiPins,
        v2Checkpoint: b64(id(substitutedCheckpoint.publicKey)) },
    };
    assert.equal((await verifyRolloverPreflight(fakeCheckpointRollover)).sequence, 128);
    const swappedCheckpointCoordinator = createOpaqueCheckpointV2Coordinator({
      ...shared, requireFullV1ArchiveRollover: true,
      fullV1ArchiveRollover: fakeCheckpointRollover });
    await assert.rejects(swappedCheckpointCoordinator.verifyFullArchiveBaseline(),
      /ZK_CHECKPOINT_V2_FULL_ARCHIVE_UNVERIFIED/,
      "a claimant cannot substitute the V2 checkpoint signer in a genuine archive handoff");
    assert.equal((await casClient.head()).state, "V1_BASELINE");
    assert.equal((await floorClient.head()).state, "V1_BASELINE");
    const journalPath = path.join(folder, "strict-128-client.sqlite");
    const clientArgs = { journalPath, trustedScope: options.scope,
      expectedV1Digest: options.stateDigest, expectedV1Checkpoint: fullDigest,
      v1CasClient, v1FloorClient, casClient, floorClient,
      checkpointPublicKey: options.checkpointKey, ownerPublicKey: options.ownerKey,
      catalogPublicKey: catalog.publicKey, ownerTrust: trust };
    const strict = new Zk1OpaqueCheckpointV2Client({ ...clientArgs,
      bootstrapNew: true, requireFullV1ArchiveRollover: true,
      fullV1ArchiveRollover: { ...options, v1CasClient, v1FloorClient } });
    strict.close();
    assert.throws(() => new Zk1OpaqueCheckpointV2Client({ ...clientArgs,
      bootstrapNew: false }), /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE/,
    "a strict journal cannot restart with its 128-head guard removed");
  });
  await withAuthorities(fullDigest, async (casClient, floorClient, _trust, context) => {
    const nonce = crypto.randomBytes(32), raw = Buffer.from([0xa0]);
    await assert.rejects(context.floor.prepare(raw, nonce),
      /ZK_CHECKPOINT_V2/,
      'legacy direct FLOOR still authenticates every submitted V2 intent');
    await assert.rejects(context.cas.commit(raw, Buffer.alloc(64), nonce),
      /ZK_CHECKPOINT_V2/,
      'legacy direct CAS still authenticates every submitted V2 intent');
    await assert.rejects(context.floor.finalize(Buffer.alloc(64), nonce),
      /ZK_CHECKPOINT_V2/,
      'legacy FLOOR cannot finalize nonexistent pending intent');
    await assert.rejects(context.cas.attestFinalized(Buffer.alloc(64), nonce),
      /ZK_CHECKPOINT_V2/,
      'legacy CAS cannot attest nonexistent pending intent');
    await assert.rejects(floorClient.prepare(raw), /ZK_CHECKPOINT_V2/,
      'real mTLS direct request rejects the unguarded rollover');
    assert.equal((await casClient.head()).state, 'V1_BASELINE');
    assert.equal((await floorClient.head()).state, 'V1_BASELINE');
  });
  // Strict admission is now independently enforced by BOTH mTLS servers,
  // not just by the coordinator used by a well-behaved browser.
  await withAuthorities(fullDigest, async (casClient, floorClient, trust, context) => {
    const { cas, floor, authorityProof } = context;
    const badIntent = Buffer.from([0xa0]), nonce = crypto.randomBytes(32);
    const ownerProof = authorityProof.fullV1ArchiveRollover;
    const originalSignature = ownerProof.ownerSignature;
    ownerProof.ownerSignature = crypto.randomBytes(64);
    await assert.rejects(floor.prepare(badIntent, nonce),
      { code: 'ZK_V1_V2_ROLLOVER_PREFLIGHT_DENIED' },
      'direct FLOOR mutation fails on forged owner rollover');
    await assert.rejects(cas.commit(badIntent, Buffer.alloc(64), nonce),
      { code: 'ZK_V1_V2_ROLLOVER_PREFLIGHT_DENIED' },
      'direct CAS mutation fails on forged owner rollover');
    await assert.rejects(floorClient.prepare(badIntent),
      /ZK_CHECKPOINT_V2/, 'mTLS direct ingress fails closed');
    assert.equal((await floorClient.head()).state, 'V1_BASELINE');
    assert.equal((await casClient.head()).state, 'V1_BASELINE');
    ownerProof.ownerSignature = originalSignature;
    const old = ownerProof.handoff;
    ownerProof.handoff = { ...old, expires_at: Math.floor(Date.now() / 1000) - 1 };
    await assert.rejects(floor.prepare(badIntent, nonce),
      { code: 'ZK_V1_V2_ROLLOVER_PREFLIGHT_DENIED' },
      'expired signed owner handoff cannot authorize new writes');
    const now = Math.floor(Date.now() / 1000);
    const renewedHandoff = { ...old, nonce: b64(crypto.randomBytes(32)),
      issued_at: now, expires_at: now + 180 };
    const renewedSignature = crypto.sign(null, Buffer.concat([OWNER_DOMAIN,
      Buffer.from(JSON.stringify(renewedHandoff))]), owner.privateKey);
    const renewal = await floor.renewFullV1ArchiveOwnerHandoff({
      handoff: renewedHandoff, ownerSignature: renewedSignature,
      ownerHead: options.ownerHead });
    assert.equal(renewal.renewed, true);
    assert.equal(renewal.v2WriteAuthorized, false);
    await assert.rejects(floor.prepare(badIntent, nonce),
      (error) => error.code !== 'ZK_V1_V2_ROLLOVER_PREFLIGHT_DENIED',
      'renewal reaches genuine signed V2 intent verification instead of preflight denial');
    context.setLiveOwnerDigest(crypto.randomBytes(32));
    await assert.rejects(floor.prepare(badIntent, nonce),
      { code: 'ZK_CHECKPOINT_V2_OWNER_ROLLOVER_STALE' },
      'new independently signed owner head fences a previously valid grant');
    context.setLiveOwnerDigest(options.ownerHead.digest);
    await assert.rejects(floor.renewFullV1ArchiveOwnerHandoff({
      handoff: { ...renewedHandoff, next_epoch: 3 },
      ownerSignature: renewedSignature, ownerHead: options.ownerHead }),
      { code: 'ZK_V1_V2_ROLLOVER_PREFLIGHT_DENIED' });
    // Failed renewal must leave the last independently verified handoff active.
    await assert.rejects(floor.prepare(badIntent, nonce),
      (error) => error.code !== 'ZK_V1_V2_ROLLOVER_PREFLIGHT_DENIED');
    // Signed 128-root obligation is immutable across a SQLite WAL/FULL restart.
    const floorArgs = { role: 'FLOOR', bootstrapNew: false,
      scope: options.scope, signingPrivateKey: v2Floor.privateKey,
      casSignerPublicKey: v2Cas.publicKey, floorSignerPublicKey: v2Floor.publicKey,
      checkpointPublicKey: options.checkpointKey, ownerPublicKey: options.ownerKey,
      ownerTrust: trust, baseDigest: options.stateDigest, baseCheckpoint: fullDigest };
    assert.throws(() => new OpaqueCheckpointV2Authority(context.floorDb, floorArgs),
      /ZK_CHECKPOINT_V2_/,
      'removing strict mode must fail before writable SQLite open');
    floor.close();
    const restartedProof = { ...options, v1CasClient, v1FloorClient,
      handoff: renewedHandoff, ownerSignature: renewedSignature };
    const restarted = new OpaqueCheckpointV2Authority(context.floorDb, {
      ...floorArgs, requireFullV1ArchiveRollover: true,
      fullV1ArchiveRollover: restartedProof });
    try {
      assert.equal((await restarted.head(nonce)).state, 'V1_BASELINE');
      await assert.rejects(restarted.prepare(badIntent, nonce),
        (error) => error.code !== 'ZK_V1_V2_ROLLOVER_PREFLIGHT_DENIED');
      assert.equal((await restarted.head(nonce)).sequence, 128);
    } finally { restarted.close(); }
  }, true);
  const lastHead = options.records128[127];
  const header128 = await z.decodeDeterministic(lastHead.header);
  const oneHeadOnly = await createAuthenticatedOpaqueCatalogArchiveV2({
    scope: options.scope, records: [lastHead], previousSequence: 127,
    previousDigest: header128.previous_digest,
    previousCheckpointDigest: crypto.randomBytes(32),
    resolveCatalogSigner: async () => catalog.publicKey,
    checkpointPrivateKey: checkpoint.privateKey,
    issuedAt: Math.floor(Date.now() / 1000) });
  assert.notDeepEqual(oneHeadOnly.checkpointDigest, fullDigest);
  await withAuthorities(oneHeadOnly.checkpointDigest, async (casClient, floorClient, trust, context) => {
    const guarded = createOpaqueCheckpointV2Coordinator({
      casClient, floorClient, trustedScope: options.scope,
      expectedV1Digest: options.stateDigest, expectedV1Checkpoint: fullDigest,
      v1CasClient, v1FloorClient,
      pinnedOwnerPublicKey: options.ownerKey,
      pinnedCheckpointPublicKey: options.checkpointKey,
      requireFullV1ArchiveRollover: true, fullV1ArchiveRollover: {
        ...options, v1CasClient, v1FloorClient } });
    await assert.rejects(guarded.verifyFullArchiveBaseline(), /ZK_CHECKPOINT_V2/);
    await assert.rejects(guarded.publish(Buffer.from([0xa0])),
      { code: "ZK_CHECKPOINT_V2_FULL_ARCHIVE_BASELINE_CONFLICT" },
      "last-head-only V2 baseline cannot enter the strict writer path");
    const local = new Zk1OpaqueCheckpointV2Client({
      journalPath: path.join(folder, "bad-baseline-client.sqlite"), bootstrapNew: true,
      trustedScope: options.scope, expectedV1Digest: options.stateDigest,
      expectedV1Checkpoint: fullDigest,
      v1CasClient, v1FloorClient, casClient, floorClient,
      checkpointPublicKey: options.checkpointKey, ownerPublicKey: options.ownerKey,
      catalogPublicKey: catalog.publicKey, ownerTrust: trust,
      requireFullV1ArchiveRollover: true, fullV1ArchiveRollover: {
        ...options, v1CasClient, v1FloorClient },
    });
    try {
      await assert.rejects(local.importSignedIntent(Buffer.from([0xa0])),
        { code: "ZK_CHECKPOINT_V2_FULL_ARCHIVE_BASELINE_CONFLICT" },
        "even local immutable V2 journal admission must wait for a full baseline");
      assert.deepEqual(await local.exportSignedIntents(), []);
    } finally { local.close(); }
    assert.equal((await casClient.head()).state, "V1_BASELINE");
    assert.equal((await floorClient.head()).state, "V1_BASELINE");
    const legacyCasHead = await casClient.head();
    const legacyFloorHead = await floorClient.head();
    assert.equal(legacyCasHead.sequence, legacyFloorHead.sequence);
    // Separate owner approval must name BOTH non-equivalent checkpoint roots.
    const statement = {
      type: 'rootark-opaque-checkpoint-v2-legacy-archive-migration/v1',
      ...Object.fromEntries(Object.entries(options.scope).map(([name, value]) =>
        [name, b64(value)])),
      legacy_base_digest: b64(options.stateDigest),
      legacy_base_checkpoint: b64(oneHeadOnly.checkpointDigest),
      legacy_sequence: 128,
      legacy_head_digest: b64(options.stateDigest),
      legacy_checkpoint_digest: b64(oneHeadOnly.checkpointDigest),
      legacy_operation_id: b64(Buffer.alloc(32)),
      full_archive_root: options.handoff.v1_archive_root,
      full_archive_checkpoint: b64(fullDigest),
      cas_signer_fp: b64(id(v2Cas.publicKey)),
      floor_signer_fp: b64(id(v2Floor.publicKey)),
      owner_revision: options.ownerHead.revision,
      owner_digest: b64(options.ownerHead.digest),
      owner_epoch: options.ownerHead.epoch,
      nonce: b64(crypto.randomBytes(32)),
      issued_at: Math.floor(Date.now() / 1000),
      expires_at: Math.floor(Date.now() / 1000) + 180,
    };
    const signedConsent = crypto.sign(null, Buffer.concat([Buffer.from(
      'Root.ark/zk-1/opaque-checkpoint-v2-legacy-archive-migration/v1\0'),
      Buffer.from(JSON.stringify(statement))]), owner.privateKey);
    const fullProof = { ...options, v1CasClient, v1FloorClient };
    const floorArgs = { fullV1ArchiveRollover: fullProof, ownerConsent: statement,
      ownerSignature: signedConsent, peerClient: casClient };
    await assert.rejects(context.floor.stageLegacyArchiveMigration({
      ...floorArgs, fullV1ArchiveRollover: null,
    }), /ZK_CHECKPOINT_V2_/, 'missing full128 archive cannot stage a legacy migration');
    await assert.rejects(context.floor.stageLegacyArchiveMigration({
      ...floorArgs, ownerSignature: crypto.randomBytes(64),
    }), /ZK_CHECKPOINT_V2_/, 'foreign owner consent must not stage');
    await assert.rejects(context.floor.stageLegacyArchiveMigration({
      ...floorArgs, ownerConsent: { ...statement,
        legacy_base_checkpoint: statement.full_archive_checkpoint },
    }), /ZK_CHECKPOINT_V2_/, 'legacy predecessor cannot be silently replaced by full128');
    const stagedFloor = await context.floor.stageLegacyArchiveMigration(floorArgs);
    assert.equal(stagedFloor.state, 'LEGACY_ARCHIVE_MIGRATION_STAGED_READ_ONLY');
    assert.equal(stagedFloor.v2WriteAuthorized, false);
    assert.notEqual(statement.legacy_base_checkpoint, statement.full_archive_checkpoint);
    await assert.rejects(context.floor.prepare(Buffer.from([0xa0]), crypto.randomBytes(32)),
      { code: 'ZK_CHECKPOINT_V2_LEGACY_MIGRATION_PENDING' });
    const stagedCas = await context.cas.stageLegacyArchiveMigration({
      ...floorArgs, peerClient: floorClient });
    assert.equal(stagedCas.state, stagedFloor.state);
    await assert.rejects(context.cas.commit(Buffer.from([0xa0]), Buffer.alloc(64),
      crypto.randomBytes(32)), { code: 'ZK_CHECKPOINT_V2_LEGACY_MIGRATION_PENDING' });
    await assert.rejects(floorClient.prepare(Buffer.from([0xa0])),
      /ZK_CHECKPOINT_V2_ACK_UNCERTAIN/, 'direct mTLS cannot downgrade staged FLOOR');
    const sql = new Database(context.floorDb);
    try {
      assert.throws(() => sql.exec('DELETE FROM legacy_archive_migration_stage'),
        /LEGACY_MIGRATION_LOCKED/, 'migration marker is immutable');
      assert.throws(() => sql.exec('UPDATE legacy_archive_migration_stage SET id=1'),
        /LEGACY_MIGRATION_LOCKED/, 'migration marker cannot be silently repinned');
      assert.throws(() => sql.exec(`INSERT INTO transitions
        (sequence,intent_hash,operation_id,checkpoint_digest,final_digest,intent,
          signer_spki,state) VALUES(129,zeroblob(32),zeroblob(32),zeroblob(32),
          zeroblob(32),x'00',zeroblob(44),'PREPARED')`),
        /LEGACY_MIGRATION_PENDING/,
      'even an older writer process must be fenced by native SQLite trigger');
    } finally { sql.close(); }
    const savedHead = await floorClient.head();
    context.floor.close();
    const restartedFloor = new OpaqueCheckpointV2Authority(context.floorDb, {
      role: 'FLOOR', bootstrapNew: false, scope: options.scope,
      signingPrivateKey: v2Floor.privateKey,
      casSignerPublicKey: v2Cas.publicKey,
      floorSignerPublicKey: v2Floor.publicKey,
      checkpointPublicKey: options.checkpointKey, ownerPublicKey: options.ownerKey,
      ownerTrust: trust, baseDigest: options.stateDigest,
      baseCheckpoint: oneHeadOnly.checkpointDigest,
    });
    try {
      assert.equal((await restartedFloor.head(crypto.randomBytes(32))).sequence,
        savedHead.sequence, 'old signed V2 history stays available after restart');
      await assert.rejects(restartedFloor.prepare(Buffer.from([0xa0]),
        crypto.randomBytes(32)),
      { code: 'ZK_CHECKPOINT_V2_LEGACY_MIGRATION_PENDING' },
      'operator cannot restart without migration argument and resume legacy writes');
    } finally { restartedFloor.close(); }
    const tampered = path.join(folder, 'staged-fence-forged-trigger.sqlite');
    fs.copyFileSync(context.floorDb, tampered);
    const editor = new Database(tampered);
    try {
      editor.exec(`DROP TRIGGER legacy_archive_stage_block_transition_insert;
        CREATE TRIGGER legacy_archive_stage_block_transition_insert
        BEFORE INSERT ON transitions BEGIN SELECT 1; END;`);
    } finally { editor.close(); }
    const forged = new OpaqueCheckpointV2Authority(tampered, {
      role: 'FLOOR', bootstrapNew: false, scope: options.scope,
      signingPrivateKey: v2Floor.privateKey,
      casSignerPublicKey: v2Cas.publicKey,
      floorSignerPublicKey: v2Floor.publicKey,
      checkpointPublicKey: options.checkpointKey, ownerPublicKey: options.ownerKey,
      ownerTrust: trust, baseDigest: options.stateDigest,
      baseCheckpoint: oneHeadOnly.checkpointDigest,
    });
    try {
      await assert.rejects(forged.prepare(Buffer.from([0xa0]),
        crypto.randomBytes(32)), { code: 'ZK_CHECKPOINT_V2_UNAVAILABLE' },
      'a same-name but no-op SQLite write fence must fail closed');
    } finally { forged.close(); }
    assert.equal((await casClient.head()).state, 'V1_BASELINE');
  }, false, true);
});
