"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const test = require("node:test");
const express = require("express");
const Database = require("better-sqlite3");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const manifestV2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const { registerZk1ProtectedContentFromConfig } = require("../src/services/zk1ProtectedContentBootstrap");
const { readAuthorityPinnedFile } = require("../src/services/zk1AuthorityPinnedFile");
const { createWindowsLocalWebDavAclVerifier, TRUSTED_POWERSHELL } =
  require("../services/chunkUploadWindowsAcl");
const { createWindowsSynchronousPrivateAclVerifier } =
  require("../src/services/zk1WindowsSynchronousPrivateAclVerifier");

test("synchronous resident ACL verifier still enforces private directory mode", {
  skip: process.platform !== "win32", timeout: 30000,
}, (t) => {
  const dir = createPrivateAuthorityFixture("rootark-zk1-native-dir-");
  const verifier = createWindowsSynchronousPrivateAclVerifier();
  t.after(() => {
    verifier.stop();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  verifier.verify(dir);
  execFileSync(path.join(process.env.SystemRoot, "System32", "icacls.exe"),
    [dir, "/grant", "*S-1-5-32-545:M"], { stdio: "pipe", timeout: 20000 });
  assert.throws(() => verifier.verify(dir),
    "original synchronous private-directory action must still reject Users:Modify");
});

test("synchronous native authority verifier denies stopped sessions and rechecks after restart", {
  skip: process.platform !== "win32", timeout: 30000,
}, (t) => {
  const dir = createPrivateAuthorityFixture("rootark-zk1-native-lifecycle-");
  const file = path.join(dir, "private.json");
  fs.writeFileSync(file, "private-synthetic-fixture", { mode: 0o600 });
  const stopped = createWindowsSynchronousPrivateAclVerifier();
  stopped.stop();
  assert.throws(() => stopped.verifyAuthorityFile(file),
    "stopped verifier must never authorize or start a worker");
  const first = createWindowsSynchronousPrivateAclVerifier();
  const restarted = createWindowsSynchronousPrivateAclVerifier();
  t.after(() => {
    first.stop();
    restarted.stop();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  first.verifyAuthorityFile(file);
  assert.throws(() => first.verifyAuthorityFile(path.join(dir, "not-present.json")),
    "an invalid pathname must fail closed");
  first.verifyAuthorityFile(file);
  first.stop();
  assert.throws(() => first.verifyAuthorityFile(file),
    "an already-started session must remain denied after stop");
  restarted.verifyAuthorityFile(file);
  execFileSync(path.join(process.env.SystemRoot, "System32", "icacls.exe"),
    [file, "/grant", "*S-1-5-32-545:R"], { stdio: "pipe", timeout: 20000 });
  assert.throws(() => restarted.verifyAuthorityFile(file),
    "restart may not reuse an old authority ACL verdict");
});

test("crashed Windows native authority process cannot reuse an old ACL approval", {
  skip: process.platform !== "win32", timeout: 30000,
}, async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-zk1-native-failure-");
  const file = path.join(dir, "authority.json");
  fs.writeFileSync(file, "private-synthetic-fixture", { mode: 0o600 });
  const verifier = createWindowsSynchronousPrivateAclVerifier();
  t.after(() => {
    verifier.stop();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  verifier.verifyAuthorityFile(file);
  // Identify ONLY this Node test process's encoded native verifier child.
  // The probe PowerShell itself has a plain -Command and is not selected.
  const childList = execFileSync(TRUSTED_POWERSHELL, [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
    `Get-CimInstance Win32_Process -Filter 'ParentProcessId = ${process.pid}' | `
      + "Where-Object { $_.ProcessId -ne $PID -and $_.Name -eq 'powershell.exe' -and $_.CommandLine -match '-EncodedCommand' } | "
      + "Select-Object -ExpandProperty ProcessId",
  ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 20000 })
    .trim().split(/\s+/).filter(Boolean).map(Number);
  assert.equal(childList.length, 1, "must target exactly our resident native process");
  assert.ok(Number.isSafeInteger(childList[0]) && childList[0] > 0);
  process.kill(childList[0]);
  execFileSync(path.join(process.env.SystemRoot, "System32", "icacls.exe"),
    [file, "/grant", "*S-1-5-32-545:R"], { stdio: "pipe", timeout: 20000 });
  await new Promise((resolve) => setTimeout(resolve, 250));
  assert.throws(() => verifier.verifyAuthorityFile(file),
    "worker process crash must not authorize a now-untrusted private leaf");
});

test("resident Windows authority verifier uses strict fresh authority ACLs on every file", {
  skip: process.platform !== "win32", timeout: 30000,
}, async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-zk1-native-authority-");
  const verifier = createWindowsLocalWebDavAclVerifier();
  t.after(() => {
    verifier.stop();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const good = path.join(dir, "good.json");
  const exposed = path.join(dir, "untrusted-read.json");
  const replaced = path.join(dir, "substitutable.json");
  for (const file of [good, exposed, replaced]) {
    fs.writeFileSync(file, "private-authority-fixture", { mode: 0o600 });
  }
  const grant = (file, access) => execFileSync(
    path.join(process.env.SystemRoot, "System32", "icacls.exe"),
    [file, "/grant", `*S-1-5-32-545:${access}`],
    { stdio: "pipe", timeout: 20000 });
  assert.equal(typeof verifier.verifyAuthorityFile, "function");
  await verifier.verifyAuthorityFile(good);
  grant(exposed, "R");
  await assert.rejects(verifier.verifyAuthorityFile(exposed),
    "authority leaf with Users:Read must be rejected despite its valid owner");
  const unsafe = path.join(dir, "ancestor-users-modify");
  fs.mkdirSync(unsafe);
  fs.renameSync(replaced, path.join(unsafe, "substitutable.json"));
  grant(unsafe, "M");
  await assert.rejects(verifier.verifyAuthorityFile(path.join(unsafe, "substitutable.json")),
    "DELETE_CHILD on ancestor invalidates even an owner-only leaf");
  grant(good, "R");
  await assert.rejects(verifier.verifyAuthorityFile(good),
    "an earlier successful ACL verdict must never authorize a later modified file");
});

test("authority bootstrap reader keeps the 64 KiB default and explicit 8 MiB envelope limit", (t) => {
  const dir = createPrivateAuthorityFixture("rootark-zk1-bounded-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const filename = path.join(dir, "private-envelope.bin");
  fs.writeFileSync(filename, Buffer.alloc(65537, 0x61), { mode: 0o600 });
  assert.throws(() => readAuthorityPinnedFile(filename), /ZK_AUTHORITY_FILE_UNTRUSTED/);
  assert.equal(readAuthorityPinnedFile(filename, 8 * 1024 * 1024).length, 65537);
  fs.writeFileSync(filename, Buffer.alloc(8 * 1024 * 1024, 0x62), { mode: 0o600 });
  assert.equal(readAuthorityPinnedFile(filename, 8 * 1024 * 1024).length, 8 * 1024 * 1024);
  fs.appendFileSync(filename, Buffer.from([0x63]));
  assert.throws(() => readAuthorityPinnedFile(filename, 8 * 1024 * 1024),
    /ZK_AUTHORITY_FILE_UNTRUSTED/);
  assert.throws(() => readAuthorityPinnedFile(filename, 8 * 1024 * 1024 + 1),
    /ZK_AUTHORITY_FILE_UNTRUSTED/);
});

test("app opt-in requires independently provisioned roots, explicit genesis and authenticated owner binding", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-zk1-bootstrap-");
  const objects = [];
  t.after(() => {
    for (const store of objects) store.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const witness = crypto.generateKeyPairSync("ed25519");
  const signing = path.join(dir, "witness-public.pem");
  fs.writeFileSync(signing, witness.publicKey.export({ format: "pem", type: "spki" }),
    { mode: 0o600 });
  const dummyTlsPaths = ["ca.pem", "client.key", "client.crt",
    "cas-client.key", "cas-client.crt"];
  fs.writeFileSync(path.join(dir, "ca.pem"), "test-fixture-only-ca", { mode: 0o600 });
  for (const basename of ["client", "cas-client"]) {
    const pair = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { format: "pem", type: "spki" },
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
    });
    fs.writeFileSync(path.join(dir, basename + ".key"), pair.privateKey,
      { mode: 0o600 });
    const args = ["req", "-new", "-x509", "-key", basename + ".key",
      "-out", basename + ".crt", "-days", "1", "-subj", "/CN=" + basename];
    if (process.platform === "win32") {
      require("./support/issue-65-native-openssl-fixture").runNativeOpenSsl(dir, args);
    } else {
      execFileSync("openssl", args, { cwd: dir, stdio: "pipe", timeout: 20000 });
    }
    fs.chmodSync(path.join(dir, basename + ".crt"), 0o600);
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
  const write = (value) => fs.writeFileSync(configPath, JSON.stringify(value),
    { mode: 0o600 });
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
  {
    // An attacker needs only DELETE_CHILD/Modify on the parent to replace an
    // otherwise private config leaf before this process starts. Exercise the
    // actual startup API and verify that nothing gets created on rejection.
    const hostileFixture = createPrivateAuthorityFixture("rootark-zk1-hostile-");
    t.after(() => fs.rmSync(hostileFixture, { recursive: true, force: true }));
    const untrustedParent = path.join(hostileFixture, "less-privileged-writable-ancestor");
    fs.mkdirSync(untrustedParent, { mode: 0o700 });
    const untrustedConfig = path.join(untrustedParent, "zk-content.json");
    const mustStayAbsent = path.join(dir, "untrusted-ancestor-must-not-create.sqlite");
    fs.writeFileSync(untrustedConfig, JSON.stringify({ ...data,
      contentDbPath: mustStayAbsent }), { mode: 0o600 });
    if (process.platform === "win32") {
      // Grant Users Modify on the directory only; the config file remains
      // private, but a member of Users can replace its name via DELETE_CHILD.
      execFileSync(path.join(process.env.SystemRoot, "System32", "icacls.exe"),
        [untrustedParent, "/grant", "*S-1-5-32-545:M"], { stdio: "pipe", timeout: 20000 });
    } else fs.chmodSync(untrustedParent, 0o777);
    assert.throws(() => {
      const store = registerZk1ProtectedContentFromConfig({
        app: express(), authenticate: (_req, _res, next) => next(),
        requirePermission: () => (_req, _res, next) => next(),
        configPath: untrustedConfig, environment: "test",
      });
      objects.push(store);
    }, /ZK_CONTENT_BOOTSTRAP_INVALID/,
    "startup must refuse a valid operator config beneath an attacker-writable ancestor");
    assert.equal(fs.existsSync(mustStayAbsent), false,
      "untrusted config must not instantiate the protected store");
  }
  {
    const originalOpen = fs.openSync;
    const replacement = path.join(dir, "replacement-config.json");
    const prior = path.join(dir, "swapped-old-config.json");
    fs.writeFileSync(replacement, JSON.stringify(data), { mode: 0o600 });
    let swappedConfig = false;
    try {
      fs.openSync = (filename, flags, ...rest) => {
        if (!swappedConfig && filename === configPath && typeof flags === "number") {
          fs.renameSync(configPath, prior);
          fs.renameSync(replacement, configPath);
          swappedConfig = true;
        }
        return originalOpen(filename, flags, ...rest);
      };
      assert.throws(() => configure(data), /ZK_CONTENT_BOOTSTRAP_INVALID/,
        "file identity changed between lstat and descriptor open must refuse");
    } finally {
      fs.openSync = originalOpen;
    }
    assert.equal(swappedConfig, true,
      "adversarial fixture must replace a valid config with an equally valid different inode");
    assert.equal(fs.existsSync(data.contentDbPath), false,
      "file identity swap may not create the protected content database");
  }
  {
    const originalRead = fs.readSync;
    const previous = path.join(dir, "post-read-old-config.json");
    const replacement = path.join(dir, "post-read-new-config.json");
    fs.writeFileSync(configPath, JSON.stringify(data), { mode: 0o600 });
    fs.writeFileSync(replacement, JSON.stringify(data), { mode: 0o600 });
    const identity = fs.lstatSync(configPath, { bigint: true });
    let swappedAfterRead = false;
    try {
      fs.readSync = (descriptor, ...args) => {
        const count = originalRead(descriptor, ...args);
        const opened = fs.fstatSync(descriptor, { bigint: true });
        if (!swappedAfterRead && opened.dev === identity.dev && opened.ino === identity.ino) {
          fs.renameSync(configPath, previous);
          fs.renameSync(replacement, configPath);
          swappedAfterRead = true;
        }
        return count;
      };
      assert.throws(() => configure(data), /ZK_CONTENT_BOOTSTRAP_INVALID/,
        "config replaced after descriptor read but before path confirmation must refuse");
    } finally {
      fs.readSync = originalRead;
    }
    assert.equal(swappedAfterRead, true);
    assert.equal(fs.existsSync(data.contentDbPath), false);
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
  fs.writeFileSync(aliasedKey, "\n" + fs.readFileSync(data.witness.clientKeyPath, "utf8"),
    { mode: 0o600 });
  fs.writeFileSync(aliasedCert, "\n" + fs.readFileSync(data.witness.clientCertPath, "utf8"),
    { mode: 0o600 });
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
  // Permit the file-identity preflight to inspect this *private* but foreign
  // SQLite. A default-mode SQLite file may first be rejected for unsafe POSIX
  // permissions, which is also fail-closed but tests a different boundary.
  fs.chmodSync(unrelated, 0o600);
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
  fs.writeFileSync(signedBasePath, JSON.stringify(encodedBase), { mode: 0o600 });
  const basePublicKeyPath = path.join(dir, "trusted-base-witness.pem");
  fs.writeFileSync(basePublicKeyPath, signedState.pinnedWitness.publicKey.export({
    format: "pem", type: "spki",
  }), { mode: 0o600 });
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
