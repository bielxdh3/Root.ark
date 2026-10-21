"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const express = require("express");
const Database = require("better-sqlite3");
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
  const dummyTlsPaths = ["ca.pem", "client.key", "client.crt"];
  for (const name of dummyTlsPaths) fs.writeFileSync(path.join(dir, name), "test-fixture-only");
  const scope = { account_id: crypto.randomBytes(16).toString("base64url"),
    compartment_id: Buffer.from("test-compartment").toString("base64url"),
    keyring_id: crypto.randomBytes(16).toString("base64url") };
  const endpoint = (service) => ({
    endpoint: `https://localhost:4433${service === "cas" ? "/v1/manifest" : "/"}`,
    caPath: path.join(dir, "ca.pem"), clientKeyPath: path.join(dir, "client.key"),
    clientCertPath: path.join(dir, "client.crt"),
    serverFingerprint256: "AA:".repeat(31) + "AA",
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
