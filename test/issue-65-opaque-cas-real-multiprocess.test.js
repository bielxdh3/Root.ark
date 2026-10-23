"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { fork } = require("node:child_process");
const Database = require("better-sqlite3");
const z = require("../src/crypto/rootark-zk-1");
const { catalogHeadDigest } = require("../src/services/zk1OpaqueCatalog");
const { createZk1OpaqueCatalogCasHttpsClient } =
  require("../src/services/zk1OpaqueCatalogCasHttpsClient");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-opaque-remote-cas-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  generateNativeFixtureCertificates(dir, { caSubject: "Opaque Catalog CAS Fixture",
    servers: ["server"], clients: ["client", "foreign"] });
  const authorityKeys = crypto.generateKeyPairSync("ed25519");
  const deviceKeys = crypto.generateKeyPairSync("ed25519");
  const foreignKeys = crypto.generateKeyPairSync("ed25519");
  const writePem = (name, value) => fs.writeFileSync(path.join(dir, name), value, {
    flag: "wx", mode: 0o600,
  });
  writePem("authority.key.pem", authorityKeys.privateKey.export({ type: "pkcs8", format: "pem" }));
  writePem("authority.pub.pem", authorityKeys.publicKey.export({ type: "spki", format: "pem" }));
  writePem("device.pub.pem", deviceKeys.publicKey.export({ type: "spki", format: "pem" }));
  const tlsFingerprint = new crypto.X509Certificate(read(path.join(dir, "server.pem"))).fingerprint256;
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("remote-cas-lab"), keyring_id: crypto.randomBytes(16) };
  const wireScope = Object.fromEntries(Object.entries(scope).map(([k, v]) => [k, b64(v)]));
  const dbPath = path.join(dir, "authority.sqlite");
  const cfg = {
    dbPath, bootstrapNew: true, scope: wireScope,
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
  let server = null;
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
  t.after(async () => {
    if (server) { try { await stop(); } catch (_) { server.kill(); } }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  const build = async (sequence, previousDigest, signer = deviceKeys.privateKey,
    nonce = crypto.randomBytes(32)) => {
    const pageBody = Buffer.from(await z.encodeDeterministic([{
      object_id: b64(crypto.randomBytes(16)), revision: 1, epoch: 1,
      ciphertext_digest: crypto.randomBytes(32),
      metadata_ciphertext: crypto.randomBytes(284),
    }]));
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
      headBytes: b64(headBytes), headSignature: b64(signature), pageBodies: [b64(pageBody)] };
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
  await launch();
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
  const headDigest = Buffer.from(winner.nextDigest, "base64url");
  const latest = await z.decodeDeterministic(await client().readHead({
    scope, nonce: crypto.randomBytes(32),
  }));
  assert.equal(latest.sequence, 1);
  assert.deepEqual(Buffer.from(latest.digest), headDigest);
  const disk = new Database(dbPath, { readonly: true, fileMustExist: true });
  const stored = disk.prepare("SELECT * FROM snapshots WHERE sequence=1").get();
  assert.deepEqual(stored.header, Buffer.from(winner.headBytes, "base64url"));
  assert.deepEqual(stored.signature, Buffer.from(winner.headSignature, "base64url"));
  assert.deepEqual(JSON.parse(stored.pages.toString()), winner.pageBodies,
    "authority committed the actual independently checked opaque page bytes");
  disk.close();

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
  cfg.bootstrapNew = false;
  cfg.minimumSequence = 1; cfg.minimumDigest = b64(headDigest);
  cfg.dropAckOnce = true;
  await launch();
  const afterRestart = await z.decodeDeterministic(await client().readHead({
    scope, nonce: crypto.randomBytes(32),
  }));
  assert.equal(afterRestart.sequence, 1);

  const uncertain = await build(2, headDigest);
  await assert.rejects(client().compareAndSwap(inputs(uncertain)), /ZK_OPAQUE_CAS_ACK_UNCERTAIN/);
  const reconciliation = await client().reconcile({
    scope, nonce: crypto.randomBytes(32), expectedSequence: 1,
    expectedDigest: headDigest, nextSequence: 2,
    nextDigest: Buffer.from(uncertain.nextDigest, "base64url"),
  });
  assert.equal(reconciliation.outcome, "CAS_COMMITTED_LOCAL_DURABLE");
  assert.equal(reconciliation.localCatalogPublished, false);
  assert.equal(reconciliation.remoteCloudDurabilityProven, false);
  const losingReconcile = await client().reconcile({
    scope, nonce: crypto.randomBytes(32), expectedSequence: 1,
    expectedDigest: headDigest, nextSequence: 2, nextDigest: crypto.randomBytes(32),
  });
  assert.equal(losingReconcile.outcome, "CAS_HEAD_CONFLICT");
  await stop();
  cfg.dropAckOnce = false;
  cfg.minimumSequence = 2; cfg.minimumDigest = uncertain.nextDigest;
  await launch();
  assert.equal((await z.decodeDeterministic(await client().readHead({
    scope, nonce: crypto.randomBytes(32),
  }))).sequence, 2);
  await stop();

  // Simulate compromised SQLite rollback without changing the external
  // operator's independently retained 2/digest floor.
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
});
