"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");
const { fork } = require("node:child_process");
const Database = require("better-sqlite3");
const z = require("../src/crypto/rootark-zk-1");
const { Zk1OpaqueCatalog, catalogHeadDigest, catalogOperationObjectId } =
  require("../src/services/zk1OpaqueCatalog");
const { createZk1OpaqueCatalogCasHttpsClient } =
  require("../src/services/zk1OpaqueCatalogCasHttpsClient");
const { createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { privateAuthorityDirectory } =
  require("./support/issue-65-private-authority-directory");

const b64 = (v) => Buffer.from(v).toString("base64url");
const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");
const PAGE_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-page/v1\0");
const fixtureScript = path.resolve(__dirname, "support/issue-65-opaque-cas-child.js");
const read = (p) => fs.readFileSync(p);
const exited = (process) => process.exitCode !== null
  ? Promise.resolve() : new Promise((resolve) => process.once("exit", resolve));
const wait = (child, event, timeoutMs = 10000) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => { child.kill(); reject(new Error("CHILD_TIMEOUT")); }, timeoutMs);
  const onMessage = (msg) => {
    if (!Object.hasOwn(msg, event) && !Object.hasOwn(msg, "startupError")) return;
    clearTimeout(timer); child.off("exit", onExit); child.off("message", onMessage);
    if (msg.startupError) reject(new Error(msg.startupError));
    else resolve(msg);
  };
  const onExit = (code) => {
    clearTimeout(timer); child.off("message", onMessage);
    reject(new Error("CHILD_EXIT_" + code));
  };
  child.on("message", onMessage);
  child.on("exit", onExit);
});
function child(mode, configPath, fixturePath) {
  return fork(fixtureScript, [mode, configPath, ...(fixturePath ? [fixturePath] : [])], {
    execArgv: [], stdio: ["ignore", "ignore", "ignore", "ipc"],
    windowsHide: true, env: { ...process.env, NODE_ENV: "test" },
  });
}

test("external opaque catalog CAS: real mTLS processes, atomic competition, signer proof, replay, restart, uncertain ACK and rollback", {
  timeout: 75000,
}, async (t) => {
  const dir = privateAuthorityDirectory("zk1-opaque-remote-cas-");
  generateNativeFixtureCertificates(dir, { caSubject: "Opaque Catalog CAS Fixture",
    servers: ["server", "floor"], clients: ["client", "foreign"] });
  const authorityKeys = crypto.generateKeyPairSync("ed25519");
  const floorKeys = crypto.generateKeyPairSync("ed25519");
  const deviceKeys = crypto.generateKeyPairSync("ed25519");
  const foreignKeys = crypto.generateKeyPairSync("ed25519");
  const writePem = (name, value) => fs.writeFileSync(path.join(dir, name), value, {
    flag: "wx", mode: 0o600,
  });
  writePem("authority.key.pem", authorityKeys.privateKey.export({ type: "pkcs8", format: "pem" }));
  writePem("authority.pub.pem", authorityKeys.publicKey.export({ type: "spki", format: "pem" }));
  writePem("floor.key.pem", floorKeys.privateKey.export({ type: "pkcs8", format: "pem" }));
  writePem("floor.pub.pem", floorKeys.publicKey.export({ type: "spki", format: "pem" }));
  writePem("device.pub.pem", deviceKeys.publicKey.export({ type: "spki", format: "pem" }));
  const tlsFingerprint = new crypto.X509Certificate(read(path.join(dir, "server.pem"))).fingerprint256;
  const floorFingerprint = new crypto.X509Certificate(read(path.join(dir, "floor.pem"))).fingerprint256;
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("remote-cas-lab"), keyring_id: crypto.randomBytes(16) };
  const wireScope = Object.fromEntries(Object.entries(scope).map(([k, v]) => [k, b64(v)]));
  const dbPath = path.join(dir, "authority.sqlite");
  const cfg = {
    dbPath, bootstrapNew: true, scope: wireScope,
    floorDbPath: path.join(dir, "independently-administered-floor.sqlite"),
    floorBootstrapNew: true, floorKeyPath: path.join(dir, "floor.key.pem"),
    floorPublicKeyPath: path.join(dir, "floor.pub.pem"),
    floorServerKeyPath: path.join(dir, "floor.key"),
    floorServerCertPath: path.join(dir, "floor.pem"),
    floorServerFingerprint256: floorFingerprint, floorDropAckOnce: false,
    minimumSequence: 0, minimumDigest: b64(Buffer.alloc(32)),
    authorityKeyPath: path.join(dir, "authority.key.pem"),
    authorityPublicKeyPath: path.join(dir, "authority.pub.pem"),
    catalogPublicKeyPath: path.join(dir, "device.pub.pem"),
    caPath: path.join(dir, "ca.pem"),
    serverKeyPath: path.join(dir, "server.key"),
    serverCertPath: path.join(dir, "server.pem"),
    clientKeyPath: path.join(dir, "client.key"),
    clientCertPath: path.join(dir, "client.pem"),
    serverFingerprint256: tlsFingerprint, timeoutMs: 1500, dropAckOnce: false,
  };
  const cfgPath = path.join(dir, "config.json");
  const writeConfig = () => fs.writeFileSync(cfgPath, JSON.stringify(cfg), { mode: 0o600 });
  let server = null; let floorServer = null;
  async function launchFloor() {
    writeConfig();
    floorServer = child("floor", cfgPath);
    const ready = await wait(floorServer, "port");
    cfg.floorEndpoint = "https://127.0.0.1:" + ready.port + "/";
    writeConfig();
  }
  async function launch() {
    writeConfig();
    server = child("server", cfgPath);
    const ready = await wait(server, "port");
    cfg.endpoint = "https://127.0.0.1:" + ready.port + "/";
    writeConfig();
  }
  async function stop() {
    if (!server) return;
    const exiting = wait(server, "stopped", 10000);
    server.send("stop");
    await exiting;
    await exited(server);
    server = null;
  }
  async function stopFloor() {
    if (!floorServer) return;
    const exiting = wait(floorServer, "stopped", 10000);
    floorServer.send("stop");
    await exiting;
    await exited(floorServer);
    floorServer = null;
  }
  t.after(async () => {
    if (server) { try { await stop(); } catch (_) { server.kill(); } }
    if (floorServer) { try { await stopFloor(); } catch (_) { floorServer.kill(); } }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  let inherited = null;
  const build = async (sequence, previousDigest, signer = deviceKeys.privateKey,
    nonce = crypto.randomBytes(32)) => {
    const ciphertext = inherited?.ciphertext || crypto.randomBytes(64);
    const item = inherited?.item || {
      object_id: b64(crypto.randomBytes(16)), revision: 1, epoch: 1,
      ciphertext_digest: crypto.createHash("sha256").update(ciphertext).digest(),
      metadata_ciphertext: crypto.randomBytes(284) };
    const pageBody = Buffer.from(await z.encodeDeterministic([item]));
    const pageDigest = crypto.createHash("sha256").update(PAGE_DOMAIN).update(pageBody).digest();
    const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
      sequence, previous_digest: previousDigest, manifest_revision: 1,
      manifest_digest: crypto.randomBytes(32), epoch: 1,
      signer_device_id: "owner-device", total_count: 1, page_digests: [pageDigest],
      issued_at: Math.floor(Date.now() / 1000) };
    const headBytes = Buffer.from(await z.encodeDeterministic(header));
    const signature = crypto.sign(null, Buffer.concat([HEAD_DOMAIN, headBytes]), signer);
    const digest = catalogHeadDigest(headBytes, signature);
    return { expectedSequence: sequence - 1, expectedDigest: b64(previousDigest),
      nextSequence: sequence, nextDigest: b64(digest), nonce: b64(nonce),
      headBytes: b64(headBytes), headSignature: b64(signature), pageBodies: [b64(pageBody)],
      ciphertextBase64: b64(ciphertext) };
  };
  const inputs = (raw) => ({
    scope, expectedSequence: raw.expectedSequence,
    expectedDigest: Buffer.from(raw.expectedDigest, "base64url"),
    nextSequence: raw.nextSequence, nextDigest: Buffer.from(raw.nextDigest, "base64url"),
    nonce: Buffer.from(raw.nonce, "base64url"),
    headBytes: Buffer.from(raw.headBytes, "base64url"),
    headSignature: Buffer.from(raw.headSignature, "base64url"),
    pageBodies: raw.pageBodies.map((part) => Buffer.from(part, "base64url")),
  });
  const client = () => createZk1OpaqueCatalogCasHttpsClient({
    endpoint: cfg.endpoint, ca: read(cfg.caPath),
    clientKey: read(cfg.clientKeyPath), clientCert: read(cfg.clientCertPath),
    serverFingerprint256: tlsFingerprint, authorityPublicKey: authorityKeys.publicKey,
    timeoutMs: 1500,
  });
  const floorClient = () => createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: cfg.floorEndpoint, ca: read(cfg.caPath),
    clientKey: read(cfg.clientKeyPath), clientCert: read(cfg.clientCertPath),
    serverFingerprint256: floorFingerprint,
    floorPublicKey: floorKeys.publicKey,
    casSignerPublicKey: authorityKeys.publicKey, trustedScope: scope,
    timeoutMs: 1500,
  });
  await launchFloor();
  await launch();
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(cfg.floorDbPath).mode & 0o777, 0o600,
      "independent floor SQLite must bootstrap with POSIX mode 0600");
    assert.equal(fs.statSync(cfg.dbPath).mode & 0o777, 0o600,
      "CAS SQLite must bootstrap with POSIX mode 0600");
  }
  const genesis = await client().readHead({ scope, nonce: crypto.randomBytes(32) });
  const parsed = await z.decodeDeterministic(genesis);
  assert.equal(parsed.sequence, 0);
  assert.deepEqual(Buffer.from(parsed.digest), Buffer.alloc(32));

  const a = await build(1, Buffer.alloc(32));
  const b = await build(1, Buffer.alloc(32));
  const aPath = path.join(dir, "writer-a.json");
  const bPath = path.join(dir, "writer-b.json");
  fs.writeFileSync(aPath, JSON.stringify(a), { mode: 0o600 });
  fs.writeFileSync(bPath, JSON.stringify(b), { mode: 0o600 });
  const childA = child("writer", cfgPath, aPath);
  const childB = child("writer", cfgPath, bPath);
  const results = await Promise.all([wait(childA, "outcome"), wait(childB, "outcome")]);
  await Promise.all([exited(childA), exited(childB)]);
  assert.equal(results.filter((r) => r.outcome === "COMMITTED").length, 1,
    "exactly one independent OS writer may atomically win a genesis CAS: " + JSON.stringify(results));
  const winner = results[0].outcome === "COMMITTED" ? a : b;
  inherited = { item: (await z.decodeDeterministic(
    Buffer.from(winner.pageBodies[0], "base64url")))[0],
  ciphertext: Buffer.from(winner.ciphertextBase64, "base64url") };
  const headDigest = Buffer.from(winner.nextDigest, "base64url");
  const latest = await z.decodeDeterministic(await client().readHead({
    scope, nonce: crypto.randomBytes(32),
  }));
  assert.equal(latest.sequence, 1);
  assert.deepEqual(Buffer.from(latest.digest), headDigest);
  if (process.platform !== "win32") {
    const stat = fs.statSync(dbPath);
    assert.equal(stat.mode & 0o077, 0,
      "new CAS SQLite must be private before restart on POSIX hosts");
  }
  const disk = new Database(dbPath, { readonly: true, fileMustExist: true });
  const stored = disk.prepare("SELECT * FROM snapshots WHERE sequence=1").get();
  assert.deepEqual(stored.header, Buffer.from(winner.headBytes, "base64url"));
  assert.deepEqual(stored.signature, Buffer.from(winner.headSignature, "base64url"));
  assert.deepEqual(JSON.parse(stored.pages.toString()), winner.pageBodies,
    "authority committed the actual independently checked opaque page bytes");
  disk.close();
  const independent = new Database(cfg.floorDbPath, { readonly: true, fileMustExist: true });
  const independentHead = independent.prepare("SELECT * FROM floor").get();
  assert.equal(independentHead.sequence, 1);
  assert.deepEqual(independentHead.digest, headDigest);
  independent.close();
  // The independent floor has deliberately destroyed its first successful
  // CAS acknowledgement. Receipt is valid only because the catalog process
  // recovered a FRESH signed floor/head proof with the matching digest.

  const forged = await build(2, headDigest, foreignKeys.privateKey);
  await assert.rejects(client().compareAndSwap(inputs(forged)), /ZK_OPAQUE_CAS_ACK_UNCERTAIN/);
  const tampered = await build(2, headDigest);
  tampered.nextDigest = b64(crypto.randomBytes(32));
  await assert.rejects(client().compareAndSwap(inputs(tampered)), /ZK_OPAQUE_CAS_ACK_UNCERTAIN/);
  const replay = await build(2, headDigest, deviceKeys.privateKey,
    Buffer.from(winner.nonce, "base64url"));
  await assert.rejects(client().compareAndSwap(inputs(replay)), /ZK_OPAQUE_CAS_ACK_UNCERTAIN/);
  assert.equal((await z.decodeDeterministic(await client().readHead({
    scope, nonce: crypto.randomBytes(32),
  }))).sequence, 1);

  // A TLS session that starts writing a CAS and disconnects before completing
  // its declared body MUST NOT enter a SQLite transaction.
  await new Promise((resolve) => {
    const request = https.request({
      hostname: "127.0.0.1", port: new URL(cfg.endpoint).port, method: "POST",
      path: "/v1/cas", rejectUnauthorized: true, ca: read(cfg.caPath),
      cert: read(cfg.clientCertPath), key: read(cfg.clientKeyPath),
      headers: { "content-type": "application/json", "content-length": "300" },
    });
    request.on("error", () => resolve());
    request.on("socket", (socket) => socket.once("secureConnect", () => {
      request.write('{"scope":'); request.destroy();
    }));
    request.end();
  });
  assert.equal((await z.decodeDeterministic(await client().readHead({
    scope, nonce: crypto.randomBytes(32),
  }))).sequence, 1);
  await assert.rejects(createZk1OpaqueCatalogCasHttpsClient({
    endpoint: cfg.endpoint, ca: read(cfg.caPath), clientKey: read(cfg.clientKeyPath),
    clientCert: read(cfg.clientCertPath), serverFingerprint256: "00:".repeat(31) + "00",
    authorityPublicKey: authorityKeys.publicKey, timeoutMs: 1000,
  }).readHead({ scope, nonce: crypto.randomBytes(32) }), /UNAVAILABLE/);
  await assert.rejects(createZk1OpaqueCatalogCasHttpsClient({
    endpoint: cfg.endpoint, ca: read(cfg.caPath), clientKey: read(cfg.clientKeyPath),
    clientCert: read(cfg.clientCertPath), serverFingerprint256: tlsFingerprint,
    authorityPublicKey: foreignKeys.publicKey, timeoutMs: 1000,
  }).readHead({ scope, nonce: crypto.randomBytes(32) }), /UNAVAILABLE/);
  await assert.rejects(createZk1OpaqueCatalogCasHttpsClient({
    endpoint: cfg.endpoint, ca: read(cfg.caPath),
    clientKey: read(path.join(dir, "foreign.key")),
    clientCert: read(path.join(dir, "foreign.pem")),
    serverFingerprint256: tlsFingerprint, authorityPublicKey: authorityKeys.publicKey,
    timeoutMs: 1000,
  }).readHead({ scope, nonce: crypto.randomBytes(32) }), /UNAVAILABLE/,
  "same trusted CA is insufficient without independently pinned mTLS client cert");

  await stop();
  await stopFloor();
  cfg.floorBootstrapNew = false;
  cfg.floorDropAckOnce = true;
  await launchFloor();
  cfg.bootstrapNew = false;
  // Keep the operator's STATIC startup floor at zero: the independently
  // signed remote floor must still reject an old local SQLite after restart.
  cfg.minimumSequence = 0; cfg.minimumDigest = b64(Buffer.alloc(32));
  cfg.dropAckOnce = true;
  await launch();
  const afterRestart = await z.decodeDeterministic(await client().readHead({
    scope, nonce: crypto.randomBytes(32),
  }));
  assert.equal(afterRestart.sequence, 1);

  const uncertain = await build(2, headDigest);
  const uncertainPath = path.join(dir, "writer-lost-ack.json");
  fs.writeFileSync(uncertainPath, JSON.stringify(uncertain), { mode: 0o600 });
  const crashedWriter = child("writer", cfgPath, uncertainPath);
  assert.equal((await wait(crashedWriter, "outcome")).outcome, "ZK_OPAQUE_CAS_ACK_UNCERTAIN");
  await exited(crashedWriter);
  // The INDEPENDENT floor drops its ACK after FULL commit. CAS must perform
  // a fresh signed read, discover the exact committed digest, and only then
  // allow the catalog ACK (which this fixture independently drops too).
  const floorHead = await floorClient().readHead({ scope });
  assert.equal(floorHead.sequence, 2);
  assert.deepEqual(floorHead.digest, Buffer.from(uncertain.nextDigest, "base64url"));
  const reconciliation = await client().reconcile({
    scope, nonce: crypto.randomBytes(32), expectedSequence: 1,
    expectedDigest: headDigest, nextSequence: 2,
    nextDigest: Buffer.from(uncertain.nextDigest, "base64url"),
  });
  assert.equal(reconciliation.outcome, "CAS_COMMITTED_LOCAL_DURABLE");
  assert.equal(reconciliation.localCatalogPublished, false);
  assert.equal(reconciliation.remoteCloudDurabilityProven, false);
  const challenge = crypto.randomBytes(32);
  const remoteSigned = await client().fetchSnapshot({ scope, sequence: 2, nonce: challenge });
  const fetched = await z.decodeDeterministic(remoteSigned);
  assert.deepEqual(Buffer.from(fetched.nonce), challenge);
  assert.deepEqual(Buffer.from(fetched.digest),
    Buffer.from(uncertain.nextDigest, "base64url"));
  assert.deepEqual(Buffer.from(fetched.header), Buffer.from(uncertain.headBytes, "base64url"));
  assert.deepEqual(fetched.page_bodies.map(b64), uncertain.pageBodies);
  const { signature: fetchSignature, ...fetchStatement } = fetched;
  assert.ok(crypto.verify(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/opaque-catalog-snapshot-fetch/v1\0"),
    Buffer.from(await z.encodeDeterministic(fetchStatement))]),
  authorityKeys.publicKey, fetchSignature), "independent Ed25519 snapshot proof");
  // The writer exited after the independent FULL SQLite commit without an
  // ACK. Reopen a DIFFERENT app SQLite process state with only snapshot N-1:
  // the first authenticated catalog read must restore N from remote signed
  // bytes, never issue a second CAS.
  const localPath = path.join(dir, "app-after-crash.sqlite");
  const appKey = Object.values(scope).map((v) => v.toString("hex")).join(":");
  const setup = new Database(localPath);
  setup.exec(`CREATE TABLE zk_content_version (
    scope TEXT, id TEXT, revision INTEGER, epoch INTEGER, ciphertext BLOB,
    ciphertext_digest BLOB);
    CREATE TABLE zk_content_nonce (scope TEXT, nonce BLOB, expires_at INTEGER,
      PRIMARY KEY(scope,nonce));
    CREATE TABLE zk_content_clock (scope TEXT PRIMARY KEY, last_at INTEGER);
    CREATE TABLE zk_content_head (scope TEXT PRIMARY KEY, revision INTEGER, digest BLOB);`);
  setup.prepare("INSERT INTO zk_content_version VALUES (?,?,?,?,?,?)").run(
    appKey, (await z.decodeDeterministic(Buffer.from(uncertain.pageBodies[0], "base64url")))[0].object_id,
    1, 1, Buffer.from(uncertain.ciphertextBase64, "base64url"),
    (await z.decodeDeterministic(Buffer.from(uncertain.pageBodies[0], "base64url")))[0].ciphertext_digest);
  // Emulate the locally acknowledged N-1 data without sharing the remote DB.
  setup.exec(`CREATE TABLE zk_content_catalog_head (
    scope TEXT PRIMARY KEY, sequence INTEGER NOT NULL, digest BLOB NOT NULL);
    CREATE TABLE zk_content_catalog_snapshot (
    scope TEXT NOT NULL, sequence INTEGER NOT NULL, digest BLOB NOT NULL,
    header BLOB NOT NULL, signature BLOB NOT NULL, PRIMARY KEY(scope,sequence));
    CREATE TABLE zk_content_catalog_page (
    scope TEXT NOT NULL, sequence INTEGER NOT NULL, page INTEGER NOT NULL,
    body BLOB NOT NULL, PRIMARY KEY(scope,sequence,page));`);
  setup.prepare("INSERT INTO zk_content_catalog_head VALUES (?,?,?)")
    .run(appKey, 1, headDigest);
  setup.prepare("INSERT INTO zk_content_catalog_snapshot VALUES (?,?,?,?,?)")
    .run(appKey, 1, headDigest, Buffer.from(winner.headBytes, "base64url"),
      Buffer.from(winner.headSignature, "base64url"));
  setup.prepare("INSERT INTO zk_content_catalog_page VALUES (?,?,?,?)")
    .run(appKey, 1, 0, Buffer.from(winner.pageBodies[0], "base64url"));
  setup.close(); // abrupt app process exit after CAS, before local snapshot N
  const localDb = new Database(localPath);
  const remoteHeader = await z.decodeDeterministic(Buffer.from(uncertain.headBytes, "base64url"));
  const manifestDevice = { device_id: "owner-device", enrolled_epoch: 1,
    revoked_at_epoch: null, authorization_public_key:
      deviceKeys.publicKey.export({ type: "spki", format: "der" }).subarray(-32) };
  const fixedNonce = crypto.randomBytes(32);
  const now = () => Math.floor(Date.now() / 1000);
  const fakeStore = {
    signedHistoryRequired: true, admissionRequired: true, db: localDb,
    trustedScope: scope, nowSeconds: now,
    minimumHead: { revision: 1, digest: Buffer.from(remoteHeader.manifest_digest) },
    clockRow: localDb.prepare("SELECT last_at FROM zk_content_clock WHERE scope=?"),
    getHead: localDb.prepare("SELECT revision,digest FROM zk_content_head WHERE scope=?"),
    nonceCount: localDb.prepare("SELECT COUNT(*) AS n FROM zk_content_nonce WHERE scope=?"),
    async runCatalogWithAdmission(_input, operation, effect) {
      assert.equal(operation, "catalog-read");
      return effect({ key: appKey,
        request: { object_id: catalogOperationObjectId(scope, "catalog-read", 0),
          expected_object_revision: 2,
          ciphertext_digest: Buffer.from(uncertain.nextDigest, "base64url"),
          manifest_revision: 1, manifest_digest: Buffer.from(remoteHeader.manifest_digest),
          epoch: 1, nonce: fixedNonce, issued_at: now(), expires_at: now() + 30 },
        head: { current_revision: 1,
          current_manifest_digest: Buffer.from(remoteHeader.manifest_digest) },
        verifiedHeadManifest: { revision: 1, current_epoch: 1, devices: [manifestDevice] } });
    },
  };
  let independentFetches = 0;
  let independentWrites = 0;
  let mutateFetch = null;
  const authority = {
    publicKey: authorityKeys.publicKey,
    readHead: (...args) => client().readHead(...args),
    async fetchSnapshot(args) {
      independentFetches++;
      const signed = await client().fetchSnapshot(args);
      return mutateFetch ? mutateFetch(signed) : signed;
    },
    compareAndSwap() { independentWrites++; throw Error("UNEXPECTED_RE_CAS"); },
  };
  const catalog = new Zk1OpaqueCatalog({ store: fakeStore, authority });
  const readCatalog = () => catalog.read({ scope, authorization: {}, signature: Buffer.alloc(64),
    pageIndex: 0 });
  const savedSigned = await z.decodeDeterministic(remoteSigned);
  mutateFetch = async () => {
    const forged = { ...savedSigned, signature: crypto.randomBytes(64) };
    return z.encodeDeterministic(forged);
  };
  await assert.rejects(readCatalog(), /ZK_CATALOG_UNAVAILABLE/,
    "signed CAS snapshot fetch cannot be forged");
  mutateFetch = async () => z.encodeDeterministic({
    ...savedSigned, compartment_id: Buffer.from("wrong-scope") });
  await assert.rejects(readCatalog(), /ZK_CATALOG_UNAVAILABLE/,
    "same signed head with wrong scope is unusable");
  // Even the independent CAS signer cannot replace a page: the original
  // owner device header binds its exact canonical-CBOR SHA-256 page digest.
  mutateFetch = async () => {
    const changedBody = Buffer.from(savedSigned.page_bodies[0]);
    changedBody[0] ^= 0x01;
    const { signature: _prior, ...statement } = savedSigned;
    const forged = { ...statement, page_bodies: [changedBody] };
    const signature = crypto.sign(null, Buffer.concat([
      Buffer.from("Root.ark/zk-1/opaque-catalog-snapshot-fetch/v1\0"),
      Buffer.from(await z.encodeDeterministic(forged))]), authorityKeys.privateKey);
    return z.encodeDeterministic({ ...forged, signature });
  };
  await assert.rejects(readCatalog(), /ZK_CATALOG_UNAVAILABLE/,
    "valid CAS signer with altered body still fails owner signed page digest");
  mutateFetch = null;
  localDb.prepare("UPDATE zk_content_version SET ciphertext_digest=? WHERE scope=?")
    .run(crypto.randomBytes(32), appKey);
  await assert.rejects(readCatalog(), /ZK_CATALOG_UNAVAILABLE/,
    "physical immutable version archive must match every signed entry");
  const latestPage = await z.decodeDeterministic(Buffer.from(uncertain.pageBodies[0], "base64url"));
  localDb.prepare("UPDATE zk_content_version SET ciphertext_digest=? WHERE scope=?")
    .run(latestPage[0].ciphertext_digest, appKey);
  manifestDevice.revoked_at_epoch = 1;
  await assert.rejects(readCatalog(), /ZK_CATALOG_(DENIED|UNAVAILABLE)/,
    "revoked owner V2 signer cannot reconcile an authenticated CAS snapshot");
  manifestDevice.revoked_at_epoch = null;
  localDb.prepare("UPDATE zk_content_catalog_head SET digest=? WHERE scope=?")
    .run(crypto.randomBytes(32), appKey);
  await assert.rejects(readCatalog(), /ZK_CATALOG_UNAVAILABLE/,
    "local fork of the signed predecessor never repairs from external head");
  localDb.prepare("UPDATE zk_content_catalog_head SET digest=? WHERE scope=?")
    .run(headDigest, appKey);
  assert.equal(localDb.prepare("SELECT COUNT(*) n FROM zk_content_catalog_snapshot").get().n, 1,
    "no untrusted snapshot was inserted");
  const recovered = await readCatalog();
  assert.equal(recovered.sequence, 2);
  assert.deepEqual(recovered.entries[0].ciphertextDigestBase64, b64(latestPage[0].ciphertext_digest));
  assert.ok(independentFetches >= 4);
  assert.equal(independentWrites, 0, "recovery never tries to re-CAS a committed head");
  assert.equal(localDb.prepare("SELECT COUNT(*) n FROM zk_content_catalog_snapshot").get().n, 2);
  assert.deepEqual(localDb.prepare("SELECT digest FROM zk_content_catalog_head WHERE scope=?")
    .get(appKey).digest, Buffer.from(uncertain.nextDigest, "base64url"));
  const rollbackAuthority = {
    ...authority,
    async readHead({ nonce }) {
      const statement = { type: "rootark-zk1-opaque-catalog-cas/v1", ...scope,
        sequence: 1, digest: headDigest, nonce,
        observed_at: now() };
      return z.encodeDeterministic({ ...statement,
        signature: crypto.sign(null, Buffer.concat([
          Buffer.from("Root.ark/zk-1/opaque-catalog-cas/v1\0"),
          Buffer.from(await z.encodeDeterministic(statement))]), authorityKeys.privateKey) });
    },
  };
  const rollbackCatalog = new Zk1OpaqueCatalog({ store: fakeStore, authority: rollbackAuthority });
  await assert.rejects(rollbackCatalog.read({
    scope, authorization: {}, signature: Buffer.alloc(64), pageIndex: 0,
  }), /ZK_CATALOG_UNAVAILABLE/,
  "even a correctly signed but rolled-back CAS head cannot rewrite local N");
  await assert.rejects(readCatalog(), /ZK_CATALOG_REPLAY/,
    "persisted device nonce remains consumed across recovery");
  localDb.prepare("UPDATE zk_content_catalog_head SET digest=? WHERE scope=?")
    .run(crypto.randomBytes(32), appKey);
  await assert.rejects(readCatalog(), /ZK_CATALOG_UNAVAILABLE/,
    "altered local contents are never silently repaired");
  localDb.close();
  const losingReconcile = await client().reconcile({
    scope, nonce: crypto.randomBytes(32), expectedSequence: 1,
    expectedDigest: headDigest, nextSequence: 2, nextDigest: crypto.randomBytes(32),
  });
  assert.equal(losingReconcile.outcome, "CAS_HEAD_CONFLICT");
  await stop();
  cfg.dropAckOnce = false;
  cfg.minimumSequence = 0; cfg.minimumDigest = b64(Buffer.alloc(32));
  await launch();
  assert.equal((await z.decodeDeterministic(await client().readHead({
    scope, nonce: crypto.randomBytes(32),
  }))).sequence, 2);
  // Power loss window: a separate process exits immediately after local FULL
  // commit of seq3, before it can contact the independently operated floor.
  await stop();
  cfg.crashAfterLocalCommitOnce = true;
  await launch();
  const third = await build(3, Buffer.from(uncertain.nextDigest, "base64url"));
  await assert.rejects(client().compareAndSwap(inputs(third)), /ZK_OPAQUE_CAS_ACK_UNCERTAIN/);
  await exited(server);
  server = null;
  const unconfirmed = new Database(dbPath, { readonly: true, fileMustExist: true });
  assert.equal(unconfirmed.prepare("SELECT sequence FROM heads").get().sequence, 3);
  unconfirmed.close();
  cfg.crashAfterLocalCommitOnce = false;
  await launch();
  const afterPowerLoss = await z.decodeDeterministic(await client().readHead({
    scope, nonce: crypto.randomBytes(32),
  }));
  assert.equal(afterPowerLoss.sequence, 3);
  assert.deepEqual(Buffer.from(afterPowerLoss.digest), Buffer.from(third.nextDigest, "base64url"));
  const recoveredFloor = new Database(cfg.floorDbPath, { readonly: true, fileMustExist: true });
  assert.equal(recoveredFloor.prepare("SELECT sequence FROM floor").get().sequence, 3);
  recoveredFloor.close();
  await stopFloor();
  await assert.rejects(client().readHead({
    scope, nonce: crypto.randomBytes(32),
  }), /ZK_OPAQUE_CAS_TRANSPORT_UNAVAILABLE/);
  await stop();
  cfg.floorBootstrapNew = false;
  cfg.floorDropAckOnce = false;
  await launchFloor();

  // Test floor identity and loss while the local CAS SQLite is still valid.
  // The later rollback test deliberately damages immutable triggers; with
  // fail-closed read-only preflight that corruption is rejected first.
  const fake = crypto.generateKeyPairSync("ed25519");
  writePem("forged-floor.pub.pem", fake.publicKey.export({ type: "spki", format: "pem" }));
  cfg.floorPublicKeyPath = path.join(dir, "forged-floor.pub.pem");
  writeConfig();
  const forgedFloor = child("server", cfgPath);
  await assert.rejects(wait(forgedFloor, "startupError"), /ZK_OPAQUE_FLOOR_UNAVAILABLE/);
  await exited(forgedFloor);
  cfg.floorPublicKeyPath = path.join(dir, "floor.pub.pem");
  await stopFloor();
  writeConfig();
  const unavailable = child("server", cfgPath);
  await assert.rejects(wait(unavailable, "startupError"), /ZK_OPAQUE_FLOOR_UNAVAILABLE/);
  await exited(unavailable);
  await launchFloor();

  // Simulate compromised SQLite rollback while unchanged startup config still
  // names ZERO. Only the separate floor process knows the committed seq3.
  const rewound = new Database(dbPath);
  rewound.exec("DROP TRIGGER immutable_opaque_snapshot_update");
  rewound.exec("DROP TRIGGER immutable_opaque_snapshot_delete");
  rewound.exec("DELETE FROM snapshots; DELETE FROM heads;");
  rewound.pragma("wal_checkpoint(TRUNCATE)");
  rewound.close();
  writeConfig();
  const rejected = child("server", cfgPath);
  await assert.rejects(wait(rejected, "startupError"), /ZK_OPAQUE_CAS_UNAVAILABLE/);
  await exited(rejected);
  await stopFloor();
});
