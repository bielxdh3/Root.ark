"use strict";

const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const client = require("../public/client/rootark-dev-vault-crypto");
const migration = require("../public/client/rootark-dev-vault-migration");
const z = require("../src/crypto/rootark-zk-1");
const signedManifest = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const zkFixtures = require("./support/issue-65-recovery-v2-fixtures");

const ROOT = path.resolve(__dirname, "..");
// This test boots the entire Express app from a disposable directory. On WSL
// with an /mnt Windows checkout, measured cold startup was ~18s alone and
// exceeded 20s with concurrent test workers. Preserve a startup deadline
// appropriate to that measured filesystem overhead, not the unit-test clock.
const SLOW_MOUNT = process.platform === "linux" && ROOT.startsWith("/mnt/");
const STARTUP_LIMIT_MS = SLOW_MOUNT ? 60_000 : 20_000;
function freePort() {
  return new Promise((resolve, reject) => {
    const listener = net.createServer();
    listener.on("error", reject);
    listener.listen(0, "127.0.0.1", () => {
      const { port } = listener.address();
      listener.close((error) => error ? reject(error) : resolve(port));
    });
  });
}
function call(port, requestPath, method = "GET", payload = undefined, headers = {}) {
  const body = payload === undefined ? "" : JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method,
      headers: { ...(payload === undefined ? {} : {
        "content-type": "application/json", "content-length": Buffer.byteLength(body),
      }), ...headers } }, (res) => {
      const parts = [];
      res.on("data", (chunk) => parts.push(chunk));
      res.on("end", () => {
        const raw = Buffer.concat(parts).toString("utf8");
        let json;
        try { json = JSON.parse(raw); } catch { json = raw; }
        resolve({ status: res.statusCode, json, headers: res.headers });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}
async function waitForReady(port, processChild) {
  const deadline = Date.now() + STARTUP_LIMIT_MS;
  while (Date.now() < deadline) {
    if (processChild.exitCode !== null) throw new Error("Server process exited");
    try {
      const response = await call(port, "/login.html");
      if (response.status === 200) return;
    } catch (_) { /* not ready */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Server startup timed out");
}
async function stop(child) {
  if (child.exitCode !== null) return;
  const done = new Promise((resolve) => child.once("exit", resolve));
  child.kill();
  await Promise.race([done, new Promise((resolve) => setTimeout(resolve, 3000))]);
  if (child.exitCode === null) {
    child.kill("SIGKILL");
    await done;
  }
}
async function session(port, username, password) {
  const login = await call(port, "/auth/login", "POST", { username, password });
  assert.equal(login.status, 200, JSON.stringify(login.json));
  const cookies = login.headers["set-cookie"].map((entry) => entry.split(";", 1)[0]);
  return {
    cookie: cookies.join("; "),
    origin: "http://127.0.0.1:" + port,
    csrf: cookies.find((entry) => entry.startsWith("rootark_csrf=")).slice("rootark_csrf=".length),
  };
}
function headers(session, csrf = true) {
  return { cookie: session.cookie, ...(csrf
    ? { origin: session.origin, "x-csrf-token": session.csrf } : {}) };
}

test("real server opt-in encrypt→HTTP→SQLite→decrypt round-trip, account isolation and CSRF", {
  timeout: SLOW_MOUNT ? 90_000 : 60_000,
}, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue65-e2e-"));
  const data = path.join(directory, "data");
  for (const folder of ["data", "temp", "uploads"]) fs.mkdirSync(path.join(directory, folder));
  const legacyBytes = Uint8Array.from([65, 0, 66, 10, 255]);
  fs.writeFileSync(path.join(directory, "uploads", "legacy-synthetic.txt"), legacyBytes);
  fs.symlinkSync(path.join(ROOT, "public"), path.join(directory, "public"), "junction");
  const password = crypto.randomBytes(18).toString("base64url");
  const users = ["alice", "bob"].map((username) => ({
    username, password: bcrypt.hashSync(password, 10),
    role: "user", sessionVersion: 0, permissions: { upload: true, listFiles: true },
  }));
  fs.writeFileSync(path.join(data, "users.local.json"), JSON.stringify(users));
  const port = await freePort();
  const env = { ...process.env, PORT: String(port), DB_ENABLED: "false",
    NODE_ENV: "test", JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    ROOTARK_ZK_DEV_VAULT_ENABLED: "true",
    ROOTARK_ZK_DEV_VAULT_DB: path.join(data, "vault.sqlite"), CLOUD_STORAGE_PROVIDER: "local" };
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    cwd: directory, env, stdio: "ignore", windowsHide: true,
  });
  t.after(async () => { await stop(child); fs.rmSync(directory, { recursive: true, force: true,
    maxRetries: 12, retryDelay: 100 }); });
  await waitForReady(port, child);
  assert.equal((await call(port, "/zk-dev/v1/session")).status, 401);
  assert.equal((await call(port, "/zk-dev/v1/zk1-history/head")).status, 401,
    "local signed manifest archive must be inaccessible without app authentication");
  assert.equal((await call(port, "/zk-dev/v1/zk1-history", "POST", {
    account: "alice", manifestBase64: "A".repeat(150_000),
    expectedRevision: 0, expectedDigest: null,
  })).status, 401,
  "large exceptional manifest bodies must be denied before JSON parsing when unauthenticated");
  const devPage = await call(port, "/zk-dev-vault.html");
  assert.equal(devPage.status, 200);
  assert.match(devPage.headers["content-security-policy"] || "",
    /script-src 'self' 'wasm-unsafe-eval'/,
    "Argon2id browser WASM must be permitted only on the opt-in vault page");
  assert.doesNotMatch(devPage.headers["content-security-policy"] || "",
    /(?:^|\s)'unsafe-eval'(?:\s|;|$)/,
    "ordinary JavaScript eval must stay disabled");
  const legacyLogin = await call(port, "/login.html");
  assert.doesNotMatch(legacyLogin.headers["content-security-policy"] || "",
    /wasm-unsafe-eval/,
    "the legacy app must not gain the vault's WASM allowance");
  const alice = await session(port, "alice", password);
  const bob = await session(port, "bob", password);
  assert.equal((await call(port, "/zk-dev/v1/zk1-history/head",
    "GET", undefined, headers(alice))).status, 400,
  "local signed history route is mounted but refuses incomplete scope");
  const overDefaultJsonLimit = await call(port, "/zk-dev/v1/zk1-history", "POST", {
    account: "alice", manifestBase64: "A".repeat(150_000),
    expectedRevision: 0, expectedDigest: null,
  }, headers(alice));
  assert.equal(overDefaultJsonLimit.status, 400,
    "the signed-manifest route must parse bounded v2 envelopes larger than legacy 100 KiB JSON; then reject malformed CBOR");
  const zkState = await zkFixtures.createInitialState(1);
  const zkCore = await z.decodeDeterministic(await z.encodeDeterministic(zkState.headManifest));
  delete zkCore.mac;
  delete zkCore.actor_signature;
  const signingNow = Math.floor(Date.now() / 1000);
  zkCore.operation.issued_at = signingNow - 1;
  zkCore.operation.expires_at = signingNow + 240;
  zkCore.operation.request_digest = await signedManifest.expectedRecoveryRequestDigestV2(null, zkCore);
  const signed = await signedManifest.signRecoveryTransitionV2({
    proposedCore: zkCore,
    actorPrivateKey: zkState.actors.get(Buffer.from(zkCore.operation.actor_key_id).toString("hex")),
    manifestMacKey: zkState.epochKeys[0].key,
    now: signingNow, clockHealthy: true,
  });
  const signedRaw = Buffer.from(await z.encodeDeterministic(signed));
  const signedAppend = await call(port, "/zk-dev/v1/zk1-history", "POST", {
    account: "alice", manifestBase64: signedRaw.toString("base64url"),
    expectedRevision: 0, expectedDigest: null,
  }, headers(alice));
  assert.equal(signedAppend.status, 201, JSON.stringify(signedAppend.json));
  assert.equal(signedAppend.json.authority, "LOCAL_ONLY_UNWITNESSED");
  const historyQuery = new URLSearchParams({
    accountId: Buffer.from(zkState.scope.account_id).toString("base64url"),
    compartmentId: Buffer.from(zkState.scope.compartment_id).toString("base64url"),
    keyringId: Buffer.from(zkState.scope.keyring_id).toString("base64url"),
  }).toString();
  assert.equal((await call(port, "/zk-dev/v1/zk1-history/head?" + historyQuery,
    "GET", undefined, headers(alice))).json.revision, 1);
  const signedReplayed = await call(port, "/zk-dev/v1/zk1-history", "POST", {
    account: "alice", manifestBase64: signedRaw.toString("base64url"),
    expectedRevision: 0, expectedDigest: null,
  }, headers(alice));
  assert.equal(signedReplayed.status, 409);
  const legacyFetched = await migration.readLegacyPlaintext({
    name: "legacy-synthetic.txt",
    fetchImpl: (route, options) => fetch("http://127.0.0.1:" + port + route, {
      ...options, headers: { ...options.headers, cookie: alice.cookie,
        origin: alice.origin, "sec-fetch-site": "same-origin" },
    }),
  });
  assert.deepEqual(legacyFetched.data, legacyBytes,
    "real legacy GET must preserve source bytes for explicit browser-side encryption");
  assert.equal((await call(port, "/zk-dev/v1/session", "GET", undefined, headers(alice))).json.username, "alice");
  const key = await client.generateRecoveryKey();
  const keyId = await client.keyCommitment(key.recoveryKey, "alice");
  const objId = crypto.randomBytes(16).toString("base64url");
  const original = new TextEncoder().encode("private test document\n");
  const envelope = await client.encryptFile({ key: key.key, id: objId,
    username: "alice", name: "strictly-secret-name.txt", mediaType: "text/plain", data: original });
  assert.equal((await call(port, "/zk-dev/v1/objects", "POST",
    { account: "alice", id: objId, envelope, keyId }, headers(alice, false))).status, 403);
  const uploaded = await call(port, "/zk-dev/v1/objects", "POST",
    { account: "alice", id: objId, envelope, keyId }, headers(alice));
  assert.equal(uploaded.status, 201, JSON.stringify(uploaded.json));
  assert.equal((await call(port, "/zk-dev/v1/session", "GET", undefined,
    headers(alice))).json.activeKeyId, keyId);
  const incompatibleKey = await client.generateRecoveryKey();
  const incompatibleId = crypto.randomBytes(16).toString("base64url");
  const incompatibleEnvelope = await client.encryptFile({
    key: incompatibleKey.key, id: incompatibleId, username: "alice",
    name: "other-key.txt", mediaType: "text/plain",
    data: new TextEncoder().encode("wrong key"),
  });
  assert.equal((await call(port, "/zk-dev/v1/objects", "POST", {
    account: "alice", id: incompatibleId, envelope: incompatibleEnvelope,
    keyId: await client.keyCommitment(incompatibleKey.recoveryKey, "alice"),
  }, headers(alice))).status, 409, "the server must not mix incompatible keys under one account");
  assert.equal((await call(port, "/zk-dev/v1/objects", "POST",
    { account: "alice", id: crypto.randomBytes(16).toString("base64url"), envelope, keyId },
    headers(bob))).status, 409, "session swap must never store Alice-bound bytes in Bob account");
  assert.equal((await call(port, "/zk-dev/v1/objects/" + objId, "GET", undefined, headers(bob))).status, 404);
  const remote = await call(port, "/zk-dev/v1/objects/" + objId, "GET", undefined, headers(alice));
  assert.equal(remote.status, 200);
  assert.equal(JSON.stringify(remote.json).includes("strictly-secret-name"), false);
  assert.equal(await client.verifyStoredCopy({
    key: key.key, username: "alice", id: objId, keyId,
    expectedEnvelope: envelope, original,
    name: "strictly-secret-name.txt", mediaType: "text/plain",
    record: remote.json,
  }), true, "real HTTP/SQLite read-back must verify the exact encrypted file before success");
  const decrypted = await client.decryptFile({ key: key.key, id: objId,
    username: "alice", envelope: remote.json.envelope });
  assert.equal(decrypted.name, "strictly-secret-name.txt");
  assert.deepEqual(decrypted.data, original);
  const migratedId = crypto.randomBytes(16).toString("base64url");
  const migratedEnvelope = await client.encryptFile({
    key: key.key, username: "alice", id: migratedId,
    name: legacyFetched.name, mediaType: legacyFetched.mediaType,
    data: legacyFetched.data,
  });
  assert.equal((await call(port, "/zk-dev/v1/objects", "POST", {
    account: "alice", id: migratedId, envelope: migratedEnvelope, keyId,
  }, headers(alice))).status, 201, "real legacy plaintext should be copied as ciphertext");
  const rereadMigration = await call(port,
    "/zk-dev/v1/objects/" + migratedId, "GET", undefined, headers(alice));
  assert.equal(rereadMigration.status, 200);
  assert.equal(await client.verifyStoredCopy({
    key: key.key, username: "alice", id: migratedId, keyId,
    expectedEnvelope: migratedEnvelope, original: legacyFetched.data,
    name: legacyFetched.name, mediaType: legacyFetched.mediaType,
    record: rereadMigration.json,
  }), true);
  assert.deepEqual(fs.readFileSync(path.join(directory, "uploads", "legacy-synthetic.txt")),
    Buffer.from(legacyBytes), "legacy source must never be modified or removed by the new copy");
  await assert.rejects(client.decryptFile({ key: key.key, id: objId,
    username: "bob", envelope: remote.json.envelope }));
  const invalid = await call(port, "/zk-dev/v1/objects", "POST", {
    account: "alice", id: crypto.randomBytes(16).toString("base64url"),
    envelope, keyId, filename: "server-must-not-receive.txt",
  }, headers(alice));
  assert.equal(invalid.status, 400);
  const db = fs.readFileSync(path.join(data, "vault.sqlite"));
  assert.equal(db.includes(Buffer.from("strictly-secret-name.txt")), false);
});
