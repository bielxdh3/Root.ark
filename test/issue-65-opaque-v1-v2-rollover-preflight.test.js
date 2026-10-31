"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const http = require("node:http");
const { execFile, fork } = require("node:child_process");
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
  createOpaqueCheckpointV2HttpsClient, createOpaqueCheckpointV2Coordinator,
  verifyLegacyArchiveDualReadback, inspectLegacyArchiveReadback } =
  require("../src/services/zk1OpaqueCheckpointV2Remote");
const { Zk1OpaqueCheckpointV2Client } =
  require("../src/services/zk1OpaqueCheckpointV2Client");
const { Zk1LegacyArchiveStageWitness } =
  require("../src/services/zk1LegacyArchiveStageWitness");
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
function witnessChild(setup, action, options = {}) {
  return new Promise((resolve, reject) => {
    const child = fork(path.join(__dirname, "..", "scripts", "fixtures", "issue-65-stage-witness-child.js"),
      [], { windowsHide: true, stdio: ["ignore", "ignore", "pipe", "ipc"] });
    let answer;
    child.once("message", (message) => { answer = message; });
    child.once("error", reject);
    child.once("exit", (code) => answer ? resolve(answer)
      : reject(Error(`WITNESS_CHILD_EXIT_${code}`)));
    child.send({ setup, action, ...options });
  });
}
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
  const { options, v2Cas, v2Floor, v1Cas, v1Floor,
    catalog, checkpoint, owner } = await build();
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
  // A real V1 CAS admission checks issued_at against a strict 60-second
  // window. Sign each of 128 dependent heads immediately before the actual
  // authenticated mTLS write, not before the entire potentially slow test.
  const liveRecords = [];
  let previous = Buffer.alloc(32);
  for (const record of options.records128) {
    const head = { ...(await z.decodeDeterministic(record.header)),
      previous_digest: Buffer.from(previous),
      issued_at: Math.floor(Date.now() / 1000) };
    const header = Buffer.from(await z.encodeDeterministic(head));
    const signature = crypto.sign(null, Buffer.concat([HEAD, header]), catalog.privateKey);
    const nextDigest = digest(HEAD, header, signature);
    const receipt = await v1CasClient.compareAndSwap({ scope: options.scope,
      expectedSequence: record.sequence - 1, expectedDigest: previous,
      nextSequence: record.sequence, nextDigest, nonce: crypto.randomBytes(32),
      headBytes: header, headSignature: signature, pageBodies: [] });
    assert.ok(Buffer.isBuffer(receipt), `signed real mTLS CAS receipt #${record.sequence}`);
    liveRecords.push({ sequence: record.sequence, header, signature, page_bodies: [] });
    previous = nextDigest;
  }
  assert.equal(liveRecords.length, 128);
  assert.deepEqual(v1FloorLedger.inspect(), { sequence: 128, digest: previous });
  const liveArchive = await createAuthenticatedOpaqueCatalogArchiveV2({
    scope: options.scope, records: liveRecords, previousSequence: 0,
    previousDigest: Buffer.alloc(32), previousCheckpointDigest: Buffer.alloc(32),
    resolveCatalogSigner: async () => catalog.publicKey,
    checkpointPrivateKey: checkpoint.privateKey,
    issuedAt: Math.floor(Date.now() / 1000) });
  const liveCheckpoint = await z.decodeDeterministic(liveArchive.checkpointBytes);
  const now = Math.floor(Date.now() / 1000);
  const liveHandoff = { ...options.handoff, v1_digest: b64(previous),
    v1_archive_root: b64(liveCheckpoint.archive_root),
    v1_archive_checkpoint: b64(liveArchive.checkpointDigest),
    issued_at: now - 2, expires_at: now + 120 };
  const liveOwnerSignature = crypto.sign(null, Buffer.concat([OWNER_DOMAIN,
    Buffer.from(JSON.stringify(liveHandoff))]), owner.privateKey);
  Object.assign(options, { records128: liveRecords, stateDigest: Buffer.from(previous),
    archiveCheckpointBytes: liveArchive.checkpointBytes,
    archiveCheckpointSignature: liveArchive.checkpointSignature,
    v2PredecessorCheckpointPin: b64(liveArchive.checkpointDigest),
    handoff: liveHandoff, ownerSignature: liveOwnerSignature });
  assert.equal((await verifyRolloverPreflight({ ...options, v1CasClient,
    v1FloorClient })).archivesRetained, 128);
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
    const readback = { fullV1ArchiveRollover: fullProof, ownerConsent: statement,
      ownerSignature: signedConsent, casClient, floorClient, ownerTrust: trust,
      operatorPins: { ownerPublicKey: owner.publicKey,
        archiveCheckpointPublicKey: checkpoint.publicKey,
        v1CasPublicKey: v1Cas.publicKey, v1FloorPublicKey: v1Floor.publicKey,
        v2CasPublicKey: v2Cas.publicKey, v2FloorPublicKey: v2Floor.publicKey } };
    await assert.rejects(verifyLegacyArchiveDualReadback(readback),
      /ZK_CHECKPOINT_V2_/, 'readback requires independently signed stage on BOTH authorities');
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
    await assert.rejects(verifyLegacyArchiveDualReadback(readback),
      /ZK_CHECKPOINT_V2_/, 'one staged authority cannot masquerade as dual stage');
    assert.notEqual(statement.legacy_base_checkpoint, statement.full_archive_checkpoint);
    await assert.rejects(context.floor.prepare(Buffer.from([0xa0]), crypto.randomBytes(32)),
      { code: 'ZK_CHECKPOINT_V2_LEGACY_MIGRATION_PENDING' });
    const stagedCas = await context.cas.stageLegacyArchiveMigration({
      ...floorArgs, peerClient: floorClient });
    assert.equal(stagedCas.state, stagedFloor.state);
    const verified = await verifyLegacyArchiveDualReadback(readback);
    assert.equal(verified.state, 'LEGACY_DUAL_ARCHIVE_SIGNED_READBACK_ONLY');
    assert.equal(verified.legacySequence, 128);
    assert.equal(verified.v2WriteAuthorized, false);
    assert.equal(verified.restoreAuthorized, false);
    assert.equal(verified.independentMonotonicStageWitnessProven, false);
    const candidate = verified.witnessCandidate;
    assert.ok(Object.isFrozen(candidate));
    const subjectRaw = Buffer.from(candidate.subject, 'base64url');
    const subject = await z.decodeDeterministic(subjectRaw);
    assert.equal(subject.type,
      'rootark-opaque-checkpoint-v2-legacy-stage-witness-subject/v1');
    assert.equal(subject.legacy_sequence, 128);
    assert.equal(subject.owner_revision, options.ownerHead.revision);
    assert.ok(Buffer.from(subject.owner_consent_hash).equals(digest(
      Buffer.from('Root.ark/zk-1/opaque-checkpoint-v2-legacy-archive-migration/v1\0'),
      Buffer.from(JSON.stringify(statement)), signedConsent)));
    assert.equal(candidate.subjectDigest, b64(digest(Buffer.from(
      'Root.ark/zk-1/opaque-checkpoint-v2-legacy-stage-witness-subject/v1\0'),
    subjectRaw)), 'independent witness can recompute a domain-separated subject');
    for (const [encoded, signer, role] of [
      [candidate.casSignedStage, v2Cas.publicKey, 'CAS'],
      [candidate.floorSignedStage, v2Floor.publicKey, 'FLOOR'],
    ]) {
      const raw = Buffer.from(encoded, 'base64url');
      const signedStage = await z.decodeDeterministic(raw);
      const independentlyChecked = await inspectLegacyArchiveReadback(raw, {
        scope: options.scope, signer, role, casFp: id(v2Cas.publicKey),
        floorFp: id(v2Floor.publicKey), nonce: signedStage.nonce,
      });
      assert.ok(Buffer.from(independentlyChecked.owner_consent_hash).equals(
        subject.owner_consent_hash), 'both stage signatures bind the same consent');
    }
    const rerun = await verifyLegacyArchiveDualReadback(readback);
    assert.equal(rerun.witnessCandidate.subjectDigest, candidate.subjectDigest,
      'fresh TLS nonces must not change immutable monotonic witness subject');
    assert.notEqual(rerun.witnessCandidate.casSignedStage, candidate.casSignedStage,
      'export must carry a new signed live readback, not replay old receipts');
    assert.equal(rerun.destructiveCutoverAuthorized, false);
    // A separate witness key and private ledger accept the opt-in evidence.
    // Genuine V1/V2 HTTPS, consent and signed owner witness are revalidated
    // before the witness appends; only local monotonic evidence is acknowledged.
    const witnessSigner = pair();
    const witnessDb = path.join(folder, 'independent-legacy-stage-witness.sqlite');
    const trustedOwnerWitness = {
      pinnedWitness: { publicKey: trust.pinnedWitness.publicKey,
        keyId: Buffer.from(trust.pinnedWitness.keyId) },
      minimumHead: { revision: trust.minimumHead.revision,
        witnessSequence: trust.minimumHead.witnessSequence,
        digest: Buffer.from(trust.minimumHead.digest) },
    };
    const witnessSetup = {
      filename: witnessDb,
      privateKey: b64(witnessSigner.privateKey.export({ format: 'der', type: 'pkcs8' })),
      publicKey: b64(witnessSigner.publicKey.export({ format: 'der', type: 'spki' })),
      scope: Object.fromEntries(Object.entries(options.scope).map(([name, value]) =>
        [name, b64(value)])),
      pins: Object.fromEntries(Object.entries(readback.operatorPins).map(([name, value]) =>
        [name, b64(value.export({ format: 'der', type: 'spki' }))])),
      ownerWitness: {
        publicKey: b64(trustedOwnerWitness.pinnedWitness.publicKey.export({ format: 'der', type: 'spki' })),
        keyId: b64(trustedOwnerWitness.pinnedWitness.keyId),
        minimumHead: { revision: trustedOwnerWitness.minimumHead.revision,
          witnessSequence: trustedOwnerWitness.minimumHead.witnessSequence,
          digest: b64(trustedOwnerWitness.minimumHead.digest) },
      },
    };
    const offlineWitnessDb = path.join(folder, 'independent-offline-forgery.sqlite');
    // A pathname existence probe cannot reserve a SQLite witness filename.
    // The native O_CREAT|O_EXCL open is the one atomic bootstrap authority.
    const oldExists = fs.existsSync;
    let prematureNameChecks = 0;
    fs.existsSync = function(name, ...args) {
      if (name === offlineWitnessDb) prematureNameChecks++;
      return oldExists.call(fs, name, ...args);
    };
    let offlineWitness;
    try {
      offlineWitness = new Zk1LegacyArchiveStageWitness({
        filename: offlineWitnessDb,
        bootstrapNew: true, privateKey: witnessSigner.privateKey,
        witnessPublicKey: witnessSigner.publicKey, trustedScope: options.scope,
        operatorPins: readback.operatorPins, trustedOwnerWitness });
    } finally { fs.existsSync = oldExists; }
    assert.equal(prematureNameChecks, 0,
      'witness bootstrap must atomically create its new ledger without check-then-open');
    try {
      const forgedSubjectRaw = Buffer.from(await z.encodeDeterministic({
        ...subject, owner_revision: subject.owner_revision + 9,
        owner_epoch: subject.owner_epoch + 3,
        owner_digest: crypto.randomBytes(32) }));
      const forgedCandidate = { ...candidate,
        subject: b64(forgedSubjectRaw),
        subjectDigest: b64(digest(Buffer.from(
          'Root.ark/zk-1/opaque-checkpoint-v2-legacy-stage-witness-subject/v1\0'),
        forgedSubjectRaw)) };
      await assert.rejects(offlineWitness.stageSignedEvidence({
        candidate: forgedCandidate, expectedHead: null }),
      /ZK_LEGACY_STAGE_WITNESS_DENIED/,
      'forged owner revision/epoch/digest with genuine CAS/FLOOR signatures cannot be STAGED');
      assert.equal(offlineWitness.audit(), null,
        'rejected offline assertion must not leave a signed stage on disk');
      await assert.rejects(offlineWitness.stageSignedEvidence({
        candidate, expectedHead: null }),
      /ZK_LEGACY_STAGE_WITNESS_DENIED/,
      'even matching offline owner assertions lack nonce-fresh owner provenance');
    } finally { offlineWitness.close(); }
    const offlineRestart = new Zk1LegacyArchiveStageWitness({
      filename: offlineWitnessDb, bootstrapNew: false,
      privateKey: witnessSigner.privateKey,
      witnessPublicKey: witnessSigner.publicKey, trustedScope: options.scope,
      operatorPins: readback.operatorPins, trustedOwnerWitness });
    try {
      assert.equal(offlineRestart.audit(), null,
        'process restart must not recover a witness-signed forged offline stage');
    } finally { offlineRestart.close(); }
    const witness = new Zk1LegacyArchiveStageWitness({
      filename: witnessDb, bootstrapNew: true,
      privateKey: witnessSigner.privateKey, witnessPublicKey: witnessSigner.publicKey,
      trustedScope: options.scope, operatorPins: readback.operatorPins,
      trustedOwnerWitness });
    await assert.rejects(witness.stageFromLiveReadback({
      readbackInput: { ...readback, ownerTrust: { ...trust,
        minimumHead: { ...trust.minimumHead, witnessSequence: 7 } } },
      expectedHead: null }), /ZK_LEGACY_STAGE_WITNESS_DENIED/,
    'caller cannot lower independently pinned owner witness minimum');
    await assert.rejects(witness.stageFromLiveReadback({
      readbackInput: { ...readback, ownerTrust: { ...trust,
        pinnedWitness: { ...trust.pinnedWitness, keyId: crypto.randomBytes(16) } } },
      expectedHead: null }), /ZK_LEGACY_STAGE_WITNESS_DENIED/,
    'caller cannot swap current-owner witness key identity');
    assert.equal(witness.audit(), null,
      'rejected witness trust substitution does not persist a ledger record');
    const raceWitness = new Zk1LegacyArchiveStageWitness({
      filename: path.join(folder, 'independent-stage-owner-race.sqlite'),
      bootstrapNew: true, privateKey: witnessSigner.privateKey,
      witnessPublicKey: witnessSigner.publicKey, trustedScope: options.scope,
      operatorPins: readback.operatorPins, trustedOwnerWitness });
    const originalFreshWitness = trust.freshWitnessHead;
    let ownerReadbacks = 0;
    trust.freshWitnessHead = async (...args) => {
      const signedHead = await originalFreshWitness(...args);
      if (++ownerReadbacks === 2) context.setLiveOwnerDigest(crypto.randomBytes(32));
      return signedHead;
    };
    try {
      await assert.rejects(raceWitness.stageFromLiveReadback({
        readbackInput: readback, expectedHead: null }),
      /ZK_LEGACY_STAGE_WITNESS_DENIED/,
      'owner revocation after first final witness read must block ledger append');
      assert.ok(ownerReadbacks >= 3,
        'must reach the second full live check after the first owner witness');
      assert.equal(raceWitness.audit(), null);
    } finally {
      trust.freshWitnessHead = originalFreshWitness;
      context.setLiveOwnerDigest(options.ownerHead.digest);
      raceWitness.close();
    }
    const fakeSigner = pair();
    const fakeKeyId = crypto.randomBytes(16);
    const rogueDb = path.join(folder, 'independent-stage-rogue-witness.sqlite');
    const rogueStage = new Zk1LegacyArchiveStageWitness({
      filename: rogueDb, bootstrapNew: true, privateKey: witnessSigner.privateKey,
      witnessPublicKey: witnessSigner.publicKey, trustedScope: options.scope,
      operatorPins: readback.operatorPins, trustedOwnerWitness });
    context.setLiveOwnerDigest(crypto.randomBytes(32));
    try {
      const counterfeit = { ...trust,
        pinnedWitness: { publicKey: fakeSigner.publicKey, keyId: fakeKeyId },
        minimumHead: { revision: 8, witnessSequence: 8,
          digest: options.ownerHead.digest },
        freshWitnessHead: async ({ scope, nonce }) => signed(Buffer.from(
          'Root.ark/zk-1/recovery-witness-head/v1\0'), {
          type: 'rootark-recovery-witness-head/v1', witness_key_id: fakeKeyId,
          ...scope, current_revision: 8,
          current_manifest_digest: options.ownerHead.digest,
          witness_sequence: 8, nonce, observed_at: Math.floor(Date.now() / 1000),
          status: 'committed', pending_reservation_id: null,
        }, fakeSigner.privateKey) };
      await assert.rejects(rogueStage.stageFromLiveReadback({
        readbackInput: { ...readback, ownerTrust: counterfeit }, expectedHead: null }),
      /ZK_LEGACY_STAGE_WITNESS_DENIED/,
      'caller-supplied fake witness signer cannot re-stage old owner after real revocation');
      assert.equal(rogueStage.audit(), null);
    } finally {
      context.setLiveOwnerDigest(options.ownerHead.digest);
      rogueStage.close();
    }
    let liveStage;
    try {
      liveStage = await witness.stageFromLiveReadback({
        readbackInput: readback, expectedHead: null });
      assert.equal(liveStage.state, 'LIVE_READBACK_STAGE_RECORDED');
      assert.equal(liveStage.v2WriteAuthorized, false);
      assert.equal(liveStage.destructiveCutoverAuthorized, false);
      assert.equal(liveStage.independentMonotonicStageWitnessProven, false);
      assert.equal(witness.audit().generation, 1);
      assert.equal(liveStage.head.provenance, 'LIVE_OWNER_V1_V2_READBACK',
        'live owner provenance is inside the signed stage head');
      await assert.rejects(witness.stageSignedEvidence({ candidate: {
        ...candidate, casSignedStage: b64(crypto.randomBytes(80)) },
      expectedHead: liveStage.head }), /ZK_LEGACY_STAGE_WITNESS_DENIED/,
      'a forged stage response cannot advance the independent ledger');
    } finally { witness.close(); }
    const snapshot = path.join(folder, 'witness-generation-one.snapshot');
    const initialChild = await witnessChild(witnessSetup, 'audit', {
      minimumHead: liveStage.head });
    assert.equal(initialChild.ok, true);
    assert.throws(() => new Zk1LegacyArchiveStageWitness({
      filename: witnessDb, bootstrapNew: false,
      privateKey: witnessSigner.privateKey, witnessPublicKey: witnessSigner.publicKey,
      trustedScope: options.scope, operatorPins: readback.operatorPins,
      trustedOwnerWitness: { ...trustedOwnerWitness,
        minimumHead: { ...trustedOwnerWitness.minimumHead, witnessSequence: 7 } },
    }), /ZK_LEGACY_STAGE_WITNESS_DENIED/,
    'restart must not reinterpret signed receipts under weaker owner floor');
    assert.deepEqual(initialChild.output, liveStage.head,
      'signed witness head survives a separate-process restart');
    assert.equal(initialChild.output.provenance, 'LIVE_OWNER_V1_V2_READBACK');
    const backup = await witnessChild(witnessSetup, 'snapshot', { snapshot });
    assert.equal(backup.ok, true);
    // SQLite backup() can create a 0644 snapshot on Linux. Keep the disposable
    // archive private before restoring it into the strict witness authority.
    fs.chmodSync(snapshot, 0o600);
    const concurrentWithdraw = await Promise.all([1, 2].map(() =>
      witnessChild(witnessSetup, 'withdraw', { expectedHead: liveStage.head })));
    assert.equal(concurrentWithdraw.filter((entry) => entry.ok).length, 1,
      'only one process can consume a signed fencing generation');
    const withdrawn = concurrentWithdraw.find((entry) => entry.ok).output;
    assert.equal(withdrawn.head.generation, 2);
    assert.equal(withdrawn.state, 'STAGE_EVIDENCE_WITHDRAWN');
    assert.equal(withdrawn.restoreAuthorized, false);
    const stale = await witnessChild(witnessSetup, 'stage', {
      candidate, expectedHead: liveStage.head });
    assert.deepEqual(stale, { ok: false, code: 'ZK_LEGACY_STAGE_WITNESS_DENIED' },
      'withdrawn stage cannot replay a stale receipt even across processes');
    const concurrentStage = await Promise.all([1, 2].map(() =>
      witnessChild(witnessSetup, 'stage', { candidate: rerun.witnessCandidate,
        expectedHead: withdrawn.head })));
    assert.equal(concurrentStage.filter((entry) => entry.ok).length, 0,
      'offline CAS after withdrawal must never promote stale signatures to live stage');
    assert.equal((await witnessChild(witnessSetup, 'audit')).output.action, 'WITHDRAWN');
    const freshStageWitness = new Zk1LegacyArchiveStageWitness({
      filename: witnessDb, bootstrapNew: false,
      privateKey: witnessSigner.privateKey, witnessPublicKey: witnessSigner.publicKey,
      trustedScope: options.scope, operatorPins: readback.operatorPins,
      trustedOwnerWitness });
    let newerHead;
    try {
      const restaged = await freshStageWitness.stageFromLiveReadback({
        readbackInput: readback, expectedHead: withdrawn.head });
      assert.equal(restaged.state, 'LIVE_READBACK_STAGE_RECORDED');
      newerHead = restaged.head;
    } finally { freshStageWitness.close(); }
    assert.equal(newerHead.generation, 3);
    assert.equal(newerHead.provenance, 'LIVE_OWNER_V1_V2_READBACK');
    assert.equal(newerHead.previousHash, withdrawn.head.hash);
    assert.equal((await witnessChild(witnessSetup, 'audit', {
      minimumHead: newerHead })).ok, true);
    assert.equal(fs.existsSync(witnessDb + '-wal'), false,
      'closed writer must checkpoint before offline operator snapshot restore');
    fs.copyFileSync(snapshot, witnessDb);
    fs.chmodSync(witnessDb, 0o600);
    const rolledWitness = await witnessChild(witnessSetup, 'audit', {
      minimumHead: newerHead });
    assert.equal(rolledWitness.ok, false,
      'externally retained signed minimum generation detects restored old DB');
    const impostor = pair();
    assert.throws(() => new Zk1LegacyArchiveStageWitness({
      filename: witnessDb, bootstrapNew: false,
      privateKey: witnessSigner.privateKey, witnessPublicKey: witnessSigner.publicKey,
      trustedScope: options.scope,
      operatorPins: { ...readback.operatorPins,
        ownerPublicKey: impostor.publicKey },
      trustedOwnerWitness,
    }), /ZK_LEGACY_STAGE_WITNESS_DENIED/,
    'an old signed ledger may not be reinterpreted under a new owner pin');
    const forgedTrigger = new Database(witnessDb);
    try {
      forgedTrigger.exec(`DROP TRIGGER receipts_sequential;
        CREATE TRIGGER receipts_sequential BEFORE INSERT ON stage_receipts
        BEGIN SELECT 1; END;`);
    } finally { forgedTrigger.close(); }
    assert.equal((await witnessChild(witnessSetup, 'audit')).ok, false,
      'a same-name no-op SQLite CAS trigger must fail on restart');
    assert.equal((await casClient.head()).state, 'V1_BASELINE');
    assert.equal((await floorClient.head()).state, 'V1_BASELINE');
    // Revoke at the asynchronous CBOR subject generation boundary, after
    // signed remote stage reads. The last owner witness must observe this.
    const originalEncode = z.encodeDeterministic;
    let delayedSubjectEncodings = 0;
    z.encodeDeterministic = async (...args) => {
      if (args[0]?.type ===
        'rootark-opaque-checkpoint-v2-legacy-stage-witness-subject/v1') {
        delayedSubjectEncodings++;
        await new Promise((resolve) => setImmediate(() => {
          context.setLiveOwnerDigest(crypto.randomBytes(32));
          resolve();
        }));
      }
      return originalEncode(...args);
    };
    try {
      await assert.rejects(verifyLegacyArchiveDualReadback(readback),
        /ZK_CHECKPOINT_V2_LEGACY_READBACK_UNVERIFIED/,
      'revocation during awaited witness subject encoding must fence readback');
      assert.equal(delayedSubjectEncodings, 1,
        'adversarial test must reach actual subject encoding await');
    } finally {
      z.encodeDeterministic = originalEncode;
      context.setLiveOwnerDigest(options.ownerHead.digest);
    }
    await assert.rejects(verifyLegacyArchiveDualReadback({ ...readback,
      ownerSignature: crypto.randomBytes(64) }), /ZK_CHECKPOINT_V2_/,
    'owner consent signature must be bound to both authority stage receipts');
    await assert.rejects(verifyLegacyArchiveDualReadback({
      ...readback, operatorPins: undefined }), /ZK_CHECKPOINT_V2_/,
    'self-declared handoff pins never replace operator-custodied keys');
    await assert.rejects(verifyLegacyArchiveDualReadback({
      ...readback, operatorPins: { ...readback.operatorPins,
        ownerPublicKey: pair().publicKey } }), /ZK_CHECKPOINT_V2_/,
    'a foreign owner key cannot be introduced by rollover metadata');
    await assert.rejects(verifyLegacyArchiveDualReadback({ ...readback,
      ownerConsent: { ...statement, full_archive_root: b64(crypto.randomBytes(32)) } }),
    /ZK_CHECKPOINT_V2_/, 'cannot substitute an independently signed full archive');
    await assert.rejects(verifyLegacyArchiveDualReadback({ ...readback,
      fullV1ArchiveRollover: { ...fullProof, independentSpkiPins: {
        ...fullProof.independentSpkiPins, owner: b64(crypto.randomBytes(32)) } } }),
    /ZK_CHECKPOINT_V2_/, 'must reject foreign out-of-band owner pin');
    context.setLiveOwnerDigest(crypto.randomBytes(32));
    await assert.rejects(verifyLegacyArchiveDualReadback(readback),
      /ZK_CHECKPOINT_V2_/, 'owner witness epoch advancement fences stale archive readback');
    context.setLiveOwnerDigest(options.ownerHead.digest);
    // Real TLS readback number two finishes AFTER the first fresh owner
    // witness. A revocation committed in that window must be detected
    // before a readback report claims to reflect the current owner state.
    const originalFloorReadback = context.floor.legacyArchiveReadback.bind(context.floor);
    let floorReadbacks = 0;
    context.floor.legacyArchiveReadback = async (...args) => {
      const result = await originalFloorReadback(...args);
      if (++floorReadbacks === 2) context.setLiveOwnerDigest(crypto.randomBytes(32));
      return result;
    };
    try {
      await assert.rejects(verifyLegacyArchiveDualReadback(readback),
        /ZK_CHECKPOINT_V2_LEGACY_READBACK_UNVERIFIED/,
      'witnessed revocation during the second genuine HTTPS stage read must fence readback');
      assert.ok(floorReadbacks >= 2);
    } finally {
      context.floor.legacyArchiveReadback = originalFloorReadback;
      context.setLiveOwnerDigest(options.ownerHead.digest);
    }
    await assert.rejects(verifyLegacyArchiveDualReadback({ ...readback,
      fullV1ArchiveRollover: { ...fullProof, v1CasClient: options.v1CasClient } }),
      /ZK_CHECKPOINT_V2_/, 'in-memory provider cannot replace the pinned V1 HTTPS client');
    const challenge = crypto.randomBytes(32);
    const floorReceipt = await floorClient.legacyArchiveReadback(challenge);
    assert.equal(floorReceipt.role, 'FLOOR');
    const altered = Buffer.from(floorReceipt.raw);
    altered[altered.length - 1] ^= 1;
    await assert.rejects(inspectLegacyArchiveReadback(altered, {
      scope: options.scope, signer: v2Floor.publicKey, role: 'FLOOR',
      casFp: id(v2Cas.publicKey), floorFp: id(v2Floor.publicKey),
      nonce: challenge }), /ZK_CHECKPOINT_V2_/,
    'tampering the FLOOR readback signature is rejected');
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
