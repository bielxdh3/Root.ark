"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const test = require("node:test");
const express = require("express");
const Database = require("better-sqlite3");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const manifestV2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const { registerZk1ProtectedContentFromConfig } = require("../src/services/zk1ProtectedContentBootstrap");

test("app opt-in requires independently provisioned roots, explicit genesis and authenticated owner binding", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-bootstrap-"));
  const objects = [];
  t.after(() => {
    for (const store of objects) store.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const witness = crypto.generateKeyPairSync("ed25519");
  const signing = path.join(dir, "witness-public.pem");
  fs.writeFileSync(signing, witness.publicKey.export({ format: "pem", type: "spki" }));
  const dummyTlsPaths = ["ca.pem", "client.key", "client.crt",
    "cas-client.key", "cas-client.crt"];
  fs.writeFileSync(path.join(dir, "ca.pem"), "test-fixture-only-ca");
  for (const basename of ["client", "cas-client"]) {
    const pair = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { format: "pem", type: "spki" },
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
    });
    fs.writeFileSync(path.join(dir, basename + ".key"), pair.privateKey);
    const args = ["req", "-new", "-x509", "-key", basename + ".key",
      "-out", basename + ".crt", "-days", "1", "-subj", "/CN=" + basename];
    if (process.platform === "win32") {
      const wd = execFileSync("wsl.exe", ["-e", "wslpath", "-a", dir],
        { encoding: "utf8" }).trim();
      execFileSync("wsl.exe", ["-e", "bash", "-lc", "cd " + JSON.stringify(wd)
        + "; openssl " + args.map((x) => JSON.stringify(x)).join(" ")],
      { stdio: "pipe", timeout: 20000 });
    } else {
      execFileSync("openssl", args, { cwd: dir, stdio: "pipe", timeout: 20000 });
    }
  }
  const scope = { account_id: crypto.randomBytes(16).toString("base64url"),
    compartment_id: Buffer.from("test-compartment").toString("base64url"),
    keyring_id: crypto.randomBytes(16).toString("base64url") };
  const endpoint = (service) => ({
    endpoint: `https://localhost:4433${service === "cas" ? "/v1/manifest" : "/"}`,
    caPath: path.join(dir, "ca.pem"),
    clientKeyPath: path.join(dir, service === "cas" ? "cas-client.key" : "client.key"),
    clientCertPath: path.join(dir, service === "cas" ? "cas-client.crt" : "client.crt"),
    serverFingerprint256: service === "cas" ? "BB:".repeat(31) + "BB"
      : "AA:".repeat(31) + "AA",
    ...(service === "witness" ? { signingKeyId: crypto.randomBytes(16).toString("base64url"),
      signingPublicKeyPath: signing } : {}),
  });
  const data = {
    version: 1, bootstrapNew: true, username: "test-owner",
    contentDbPath: path.join(dir, "content.sqlite"), scope,
    minimumHead: { revision: 1, digest: crypto.randomBytes(32).toString("base64url") },
    witness: endpoint("witness"), cas: endpoint("cas"),
  };
  const configPath = path.join(dir, "zk-content.json");
  const write = (value) => fs.writeFileSync(configPath, JSON.stringify(value));
  const snapshot = (filename) => ["", "-wal", "-shm", "-journal"].map((suffix) => {
    const file = filename + suffix;
    return fs.existsSync(file)
      ? crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex")
      : null;
  });
  function configure(value, options = {}) {
    write(value);
    const app = express();
    app.use(express.json({ limit: "7mb" }));
    const authenticate = (req, res, next) => {
      if (!req.headers.authorization) return res.sendStatus(401);
      req.user = { username: req.headers.authorization.slice(7) };
      next();
    };
    const store = registerZk1ProtectedContentFromConfig({ app, authenticate,
      requirePermission: () => (_req, _res, next) => next(),
      configPath, environment: options.environment ?? "test" });
    objects.push(store);
    return app;
  }
  assert.throws(() => configure({ ...data, witness: { ...data.witness,
    signingPublicKeyPath: undefined } }), /ZK_CONTENT_BOOTSTRAP_INVALID/);
  assert.throws(() => configure({ ...data, cas: { ...data.cas,
    serverFingerprint256: data.witness.serverFingerprint256 } }),
  /ZK_CONTENT_BOOTSTRAP_INVALID/, "same certificate pin cannot designate two independent authorities");
  assert.throws(() => configure({ ...data, cas: { ...data.cas,
    clientKeyPath: data.witness.clientKeyPath,
    clientCertPath: data.witness.clientCertPath } }),
  /ZK_CONTENT_BOOTSTRAP_INVALID/, "CAS and witness need separately provisioned client credentials");
  assert.throws(() => configure({ ...data, cas: { ...data.cas,
    clientKeyPath: data.witness.clientKeyPath } }), /ZK_CONTENT_BOOTSTRAP_INVALID/,
  "reusing just the witness private key mismatches the CAS certificate");
  assert.throws(() => configure({ ...data, cas: { ...data.cas,
    clientCertPath: data.witness.clientCertPath } }), /ZK_CONTENT_BOOTSTRAP_INVALID/,
  "reusing just the witness certificate mismatches the CAS private key");
  const aliasedKey = path.join(dir, "cas-aliased-client.key");
  const aliasedCert = path.join(dir, "cas-aliased-client.crt");
  fs.writeFileSync(aliasedKey, "\n" + fs.readFileSync(data.witness.clientKeyPath, "utf8"));
  fs.writeFileSync(aliasedCert, "\n" + fs.readFileSync(data.witness.clientCertPath, "utf8"));
  assert.deepEqual(crypto.createPublicKey(crypto.createPrivateKey(
    fs.readFileSync(aliasedKey))).export({ type: "spki", format: "der" }),
  crypto.createPublicKey(crypto.createPrivateKey(
    fs.readFileSync(data.witness.clientKeyPath))).export({ type: "spki", format: "der" }));
  assert.deepEqual(new crypto.X509Certificate(fs.readFileSync(aliasedCert)).raw,
    new crypto.X509Certificate(fs.readFileSync(data.witness.clientCertPath)).raw);
  assert.throws(() => configure({ ...data, cas: { ...data.cas,
    clientKeyPath: aliasedKey, clientCertPath: aliasedCert } }),
  /ZK_CONTENT_BOOTSTRAP_INVALID/,
  "semantically identical PEMs with distinct bytes/paths are still the SAME TLS principal");
  assert.equal(fs.existsSync(data.contentDbPath), false,
    "any invalid authority bootstrap must refuse before creating the content database");
  assert.throws(() => configure({ ...data, bootstrapNew: false }), /ZK_CONTENT_BOOTSTRAP_REQUIRED/);
  assert.throws(() => configure(data, { environment: "production" }), /ZK_CONTENT_BOOTSTRAP_INVALID/);
  const unrelated = path.join(dir, "unrelated.sqlite");
  const foreign = new Database(unrelated);
  foreign.exec("CREATE TABLE real_user_rows (id INTEGER PRIMARY KEY, data TEXT NOT NULL);");
  foreign.prepare("INSERT INTO real_user_rows(id,data) VALUES(1,?)").run("keep-this-data");
  foreign.close();
  const before = snapshot(unrelated);
  assert.throws(() => configure({ ...data, bootstrapNew: false,
    contentDbPath: unrelated }), /ZK_CONTENT_IDENTITY_MISSING/);
  assert.deepEqual(snapshot(unrelated), before,
    "mispointed startup must not modify a foreign SQLite file or its journal sidecars");
  const corrupt = path.join(dir, "corrupt.sqlite");
  fs.writeFileSync(corrupt, Buffer.from("unrelated-invalid-sqlite-fixture"));
  const corruptBefore = snapshot(corrupt);
  assert.throws(() => configure({ ...data, bootstrapNew: false,
    contentDbPath: corrupt }));
  assert.deepEqual(snapshot(corrupt), corruptBefore,
    "invalid database must not be repaired or modified during an identity preflight");
  assert.throws(() => configure({ ...data, bootstrapNew: true,
    contentDbPath: unrelated }), /ZK_CONTENT_BOOTSTRAP_REQUIRED/);
  assert.deepEqual(snapshot(unrelated), before,
    "bootstrapNew must never clobber existing SQLite files");
  const raced = path.join(dir, "bootstrap-raced.sqlite");
  const foreignForSwap = path.join(dir, "bootstrap-swap-foreign.sqlite");
  const swapSource = new Database(foreignForSwap);
  swapSource.exec("CREATE TABLE sensitive_foreign_rows (id INTEGER PRIMARY KEY, data TEXT)");
  swapSource.prepare("INSERT INTO sensitive_foreign_rows(data) VALUES(?)").run("keep-private-fixture");
  swapSource.close();
  const foreignSnapshot = snapshot(foreignForSwap);
  const originalClose = fs.closeSync;
  let swapped = false;
  try {
    // Synthetic adversarial file swap at the exact O_EXCL close -> SQLite
    // open boundary. The guard must pin the identity of the original fd.
    fs.closeSync = (fd) => {
      originalClose(fd);
      if (!swapped && fs.existsSync(raced)) {
        fs.renameSync(raced, path.join(dir, "orphaned-exclusive-empty.sqlite"));
        fs.renameSync(foreignForSwap, raced);
        swapped = true;
      }
    };
    assert.throws(() => configure({ ...data, contentDbPath: raced }),
      /ZK_CONTENT_BOOTSTRAP_REQUIRED/);
  } finally { fs.closeSync = originalClose; }
  assert.equal(swapped, true, "fixture must actually swap SQLite files");
  assert.deepEqual(snapshot(raced), foreignSnapshot,
    "swapped foreign SQLite must remain bit-for-bit unchanged");
  const signedState = await fixtures.createInitialState(1);
  const signedGenesisDigest = await manifestV2.recoveryManifestDigestV2(signedState.baseManifest);
  const signedBasePath = path.join(dir, "trusted-base-receipt.json");
  const encodedBase = Object.fromEntries(Object.entries(signedState.baseReceipt).map(
    ([name, value]) => [name, Buffer.isBuffer(value)
      ? value.toString("base64url") : value]));
  fs.writeFileSync(signedBasePath, JSON.stringify(encodedBase));
  const basePublicKeyPath = path.join(dir, "trusted-base-witness.pem");
  fs.writeFileSync(basePublicKeyPath, signedState.pinnedWitness.publicKey.export({
    format: "pem", type: "spki",
  }));
  const v2Data = {
    ...data, version: 2,
    contentDbPath: path.join(dir, "strict-signed-history.sqlite"),
    scope: Object.fromEntries(Object.entries(signedState.scope).map(
      ([name, bytes]) => [name, bytes.toString("base64url")])),
    minimumHead: { revision: 1, digest: signedGenesisDigest.toString("base64url") },
    signedHistory: {
      genesisDigest: signedGenesisDigest.toString("base64url"),
      baseReceiptPath: signedBasePath,
      baseWitnessKeyId: signedState.pinnedWitness.keyId.toString("base64url"),
      baseWitnessPublicKeyPath: basePublicKeyPath,
      packageEnvelopes: [],
    },
  };
  assert.throws(() => configure({ ...v2Data, signedHistory: {
    ...v2Data.signedHistory, baseReceiptPath: path.join(dir, "missing.json"),
  } }), /ZK_CONTENT_BOOTSTRAP_INVALID/);
  assert.equal(fs.existsSync(v2Data.contentDbPath), false,
    "missing independently supplied signed-history roots may not create the store");
  configure(v2Data);
  assert.equal(objects.at(-1).signedHistoryRequired, true,
    "versioned opt-in must require the owner-rooted signed chain on every operation");
  assert.equal(typeof objects.at(-1).verifiedHistoryProvider, "function");
  assert.equal(objects.at(-1).signedHistoryGenesisDigest.toString("hex"),
    signedGenesisDigest.toString("hex"));
  const tuned = { ...v2Data,
    contentDbPath: path.join(dir, "strict-slow-link-history.sqlite"),
    cas: { ...v2Data.cas, timeoutMs: 22000, historyDeadlineMs: 180000 } };
  for (const [field, value] of [["timeoutMs", 30001],
    ["historyDeadlineMs", 300001], ["timeoutMs", 0],
    ["historyDeadlineMs", "180000"]]) {
    assert.throws(() => configure({ ...tuned, cas: { ...tuned.cas, [field]: value } }),
      /ZK_CONTENT_BOOTSTRAP_INVALID/,
      "unbounded or mistyped CAS hard deadlines must fail before SQLite creation");
  }
  assert.equal(fs.existsSync(tuned.contentDbPath), false);
  configure(tuned);
  assert.equal(objects.at(-1).signedHistoryRequired, true,
    "strict development opt-in must accept bounded CAS deadline tuning");
  const app = configure(data);
  const listener = await new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => resolve(server));
  });
  t.after(() => new Promise((resolve) => listener.close(resolve)));
  const url = `http://127.0.0.1:${listener.address().port}/zk-1/v1/content/read`;
  const post = (username) => fetch(url, { method: "POST",
    headers: { "content-type": "application/json", ...(username ? {
      authorization: "Bearer " + username,
    } : {}) }, body: JSON.stringify({}) });
  assert.equal((await post(null)).status, 401);
  assert.equal((await post("another-user")).status, 403);
  const owner = await post("test-owner");
  assert.equal(owner.status, 403, "no unsigned or incomplete request can open ciphertext");
  // Restart may never generate a new identity or replace the persisted floor.
  assert.throws(() => configure(data), /ZK_CONTENT_BOOTSTRAP_REQUIRED/);
  const contentBeforeMismatch = snapshot(data.contentDbPath);
  assert.throws(() => configure({ ...data, bootstrapNew: false,
    minimumHead: { ...data.minimumHead,
      digest: crypto.randomBytes(32).toString("base64url") },
  }), /ZK_CONTENT_IDENTITY_MISMATCH/);
  // SQLite legitimately updates the -shm coordination file when inspecting a
  // live WAL database; protect durable DB and WAL bytes, not ephemeral locks.
  assert.deepEqual(snapshot(data.contentDbPath).filter((_, i) => i !== 2),
    contentBeforeMismatch.filter((_, i) => i !== 2),
    "rejected root identity must not mutate durable DB or WAL data");
  assert.doesNotThrow(() => configure({ ...data, bootstrapNew: false }));
});
