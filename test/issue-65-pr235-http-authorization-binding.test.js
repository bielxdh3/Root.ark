"use strict";

// This is an actual Express/HTTP, device-key and durable SyncObjectStore
// regression, not a direct validator/mocked-store assertion. Execute only
// during the exclusive Windows Node22 test gate.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const fsSync = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const express = require("express");
const { runMigrations } = require("../db/migrations");
const { closeDb, getDb, getOpenDatabasePath } = require("../db");
const usersRepository = require("../repositories/usersRepository");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
const { assertPrivateSqliteAuthorityDirectory } =
  require("../src/services/zk1PrivateSqlitePath");
const { SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");
const { canonicalJson, createOperation, validateFreshSignedOperation, validateStoredOperation } =
  require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyHistoricalAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");

function isolatedDirectory(prefix) {
  if (process.platform !== "win32") {
    return fsSync.mkdtempSync(path.join(os.tmpdir(), prefix));
  }
  // Windows TEMP inherits overly broad rights for a strict atomic store.
  // Use the same disposable private ACL ancestry as the existing strict tests.
  const directory = path.join(process.env.LOCALAPPDATA,
    prefix + crypto.randomBytes(16).toString("hex"));
  // Native CREATE accepts an existing protected root. A test must NOT adopt
  // then recursively DELETE another owner's pre-existing directory. Require
  // an unpredictable fresh name absent before native protected creation.
  if (fsSync.existsSync(directory)) throw Error("SYNC_HTTP_FIXTURE_ROOT_PREEXISTS");
  ensureWindowsChunkUploadRoot(directory);
  return directory;
}

function httpPost(port, operation) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify(operation));
    const req = http.request({ hostname: "127.0.0.1", port,
      path: "/sync/v1/objects", method: "POST",
      headers: { "content-type": "application/json", "content-length": body.length } },
    (res) => {
      const parts = [];
      res.on("data", (part) => parts.push(part));
      res.on("end", () => resolve({ status: res.statusCode,
        body: Buffer.concat(parts).toString("utf8") }));
    });
    req.on("error", reject);
    req.setTimeout(15_000, () => req.destroy(new Error("Sync HTTP admission timed out")));
    req.end(body);
  });
}

function corruptBase64(value) {
  const bytes = Buffer.from(value, "base64url");
  assert.ok(bytes.length > 0, "attack must alter an existing real encrypted byte");
  bytes[0] ^= 1;
  return bytes.toString("base64url");
}

function assertOpenedNativeSqliteAt(expectedPath, pinned) {
  const db = getDb();
  const main = db.pragma("database_list").find((row) => row.name === "main");
  const same = (a, b) => path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase();
  assert.ok(main && main.file && same(main.file, expectedPath),
    "native SQLite PRAGMA database_list MUST target only our isolated fixture");
  const info = fsSync.lstatSync(expectedPath, { bigint: true });
  assert.ok(info.isFile() && !info.isSymbolicLink() && info.nlink === 1n,
    "fixture SQLite main file must be the single-link native file reserved by this test");
  assert.equal(info.dev, pinned.dev, "SQLite main file device cannot change");
  assert.equal(info.ino, pinned.ino, "SQLite main file inode cannot change");
  assert.ok(same(fsSync.realpathSync.native(expectedPath), expectedPath),
    "fixture SQLite path must not redirect through reparse links");
  return db;
}

test("protected HTTP ingress rejects tampered signed bytes before durable store/epoch mutation and across restart", async (t) => {
  assert.equal(getOpenDatabasePath(), null,
    "integration fixture requires an EXCLUSIVE process with no pre-existing SQLite singleton");
  let accountDirectory;
  let objectDirectory;
  const previous = Object.fromEntries(["DB_ENABLED", "DATABASE_URL", "DB_WRITE_LEGACY_JSON"]
    .map((name) => [name, process.env[name]]));
  let server;
  t.after(async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
    closeDb();
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    if (objectDirectory) await fs.rm(objectDirectory, { recursive: true, force: true });
    if (accountDirectory) await fs.rm(accountDirectory, { recursive: true, force: true });
  });

  accountDirectory = isolatedDirectory("zk65-pr235-accounts-");
  objectDirectory = isolatedDirectory("zk65-pr235-objects-");
  const databasePath = path.join(accountDirectory, "accounts.sqlite");
  const storagePath = path.join(objectDirectory, "objects.json");

  // The database may be opened and journalled by getDb() BEFORE migrations.
  // Fail closed BEFORE that first native open, so even a pre-seeded hardlink,
  // symlink, junction or unexpectedly writable ancestor cannot be touched.
  assertPrivateSqliteAuthorityDirectory(databasePath);
  assert.equal(fsSync.existsSync(databasePath), false,
    "new isolated fixture must never adopt an existing SQLite file");
  let reserved;
  let pinned;
  try {
    reserved = fsSync.openSync(databasePath, fsSync.constants.O_CREAT
      | fsSync.constants.O_EXCL | fsSync.constants.O_WRONLY
      | (fsSync.constants.O_NOFOLLOW || 0), 0o600);
    pinned = fsSync.fstatSync(reserved, { bigint: true });
    assert.ok(pinned.isFile() && pinned.nlink === 1n,
      "no shared/hardlinked SQLite inode may be adopted for a test");
  } finally {
    if (reserved !== undefined) fsSync.closeSync(reserved);
  }
  assertPrivateSqliteAuthorityDirectory(databasePath);

  process.env.DB_ENABLED = "true";
  process.env.DB_WRITE_LEGACY_JSON = "false";
  process.env.DATABASE_URL = databasePath;
  // Native SQLite opens/creates ONLY our private fixture before migrations.
  // A preexisting process-wide account DB is forbidden above; even a stale
  // cached path or junction cannot receive the user fixture's saveUsers().
  assertOpenedNativeSqliteAt(databasePath, pinned);
  runMigrations({ backup: false });
  assert.equal(getOpenDatabasePath(), databasePath,
    "must verify the real opened native SQLite file BEFORE writing fixture users");
  assertOpenedNativeSqliteAt(databasePath, pinned);
  usersRepository.saveUsers([{ username: "alice", role: "user", password: "fixture",
    sessionVersion: 0, permissions: { upload: true, delete: true } }]);

  const app = express();
  app.use(express.json({ limit: "9mb" }));
  const routes = registerSyncRoutes({ app, storagePath,
    atomicDeviceRegistry: true, requireDeviceAuthorization: true,
    authenticate: (req, _res, next) => {
      req.user = { username: "alice", role: "user", sessionVersion: 0,
        permissions: { upload: true, delete: true } };
      next();
    },
    requirePermission: () => (_req, _res, next) => next(),
  });
  await routes.ready;

  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" })
    .toString("base64url");
  assert.deepEqual(await routes.store.enrollDevice({ username: "alice",
    deviceId: "device-a", publicKey, expectedEpoch: 0 }), { epoch: 1 });

  server = await new Promise((resolve) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  const port = server.address().port;
  const signed = async (name) => {
    const operation = createOperation({ operation: "create",
      operationId: `operation-${name}`, objectId: `object-${name}`,
      fileId: `file-${name}`, versionId: `version-${name}`,
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: 1, deviceId: "device-a" },
      metadata: { path: `${name}.txt` },
      plaintext: Buffer.from(`real encrypted payload: ${name}`),
      fileKey: crypto.randomBytes(32) });
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", publicKey, privateKey: pair.privateKey,
      expiresAt: Date.now() + 60_000,
    });
    return operation;
  };

  const admitted = await signed("admitted");
  assert.equal((await httpPost(port, admitted)).status, 201,
    "positive control requires actual signed HTTP admission and fsynced JSON");
  assert.equal(routes.store.list("alice").length, 1);
  assert.ok(validateStoredOperation(admitted), "legitimate signed stored record remains readable");
  const baseline = await fs.readFile(storagePath);
  const baselineEpoch = routes.store.atomicRegistryEpoch();
  assert.equal(baselineEpoch, 1);

  const replay = await httpPost(port, admitted);
  assert.equal(replay.status, 409, "a second real HTTP request may not replay an admitted signed operation");
  assert.deepEqual(await fs.readFile(storagePath), baseline,
    "replay cannot add durable history, advance epoch or change objects");

  for (const field of ["ciphertext", "nonce", "tag", "aad"]) {
    const authentic = await signed(`tamper-${field}`);
    const forged = { ...authentic, [field]: corruptBase64(authentic[field]) };
    const response = await httpPost(port, forged);
    assert.equal(response.status, 403, `${field} digest substitution must fail at HTTP ingress`);
    assert.deepEqual(await fs.readFile(storagePath), baseline,
      `${field} attack cannot alter persisted objects, seen/replay IDs or registry`);
    assert.deepEqual(routes.store.list("alice").map((item) => item.objectId),
      ["object-admitted"]);
    assert.equal(routes.store.atomicRegistryEpoch(), baselineEpoch);
  }

  const missing = await signed("missing-proof");
  const missingResponse = await httpPost(port, { ...missing, authorization: null });
  assert.ok([400, 403].includes(missingResponse.status),
    "missing signed grant must be rejected");
  assert.deepEqual(await fs.readFile(storagePath), baseline,
    "missing signed grant cannot mutate the durable object store");

  // Make metadata and AAD mutually consistent. This avoids passing a test
  // merely because the AAD parser notices an unrelated malformed envelope.
  const wrongMetadata = await signed("wrong-metadata");
  const retargetedMetadata = { ...wrongMetadata.metadata, path: "changed.txt" };
  const oldAad = JSON.parse(Buffer.from(wrongMetadata.aad, "base64url").toString("utf8"));
  const retargeted = { ...wrongMetadata, metadata: retargetedMetadata,
    aad: Buffer.from(canonicalJson({ ...oldAad, metadata: retargetedMetadata }), "utf8")
      .toString("base64url") };
  const retargetedResponse = await httpPost(port, retargeted);
  assert.equal(retargetedResponse.status, 403,
    "internally valid AAD with a stale signed scope must fail authentication");
  assert.deepEqual(await fs.readFile(storagePath), baseline,
    "retargeted signed scope cannot mutate the durable object store");

  // Structural SHA256 binding does not itself authenticate the device.
  // Exercise both independent trust decisions: signature validity and
  // the previously enrolled public key stored under the atomic write lock.
  const signedWithOriginalKey = await signed("forged-signature");
  const mutatedSignature = {
    ...signedWithOriginalKey,
    authorization: { ...signedWithOriginalKey.authorization,
      signature: corruptBase64(signedWithOriginalKey.authorization.signature) },
  };
  assert.equal((await httpPost(port, mutatedSignature)).status, 403,
    "structurally matching ciphertext with invalid Ed25519 signature must fail");
  assert.deepEqual(await fs.readFile(storagePath), baseline,
    "invalid signature must not persist ciphertext or replay IDs");

  const attacker = crypto.generateKeyPairSync("ed25519");
  const attackerPublicKey = attacker.publicKey.export({ type: "spki", format: "der" })
    .toString("base64url");
  const untrusted = await signed("untrusted-key");
  untrusted.authorization = await createAuthorizationProof(untrusted, {
    username: "alice", publicKey: attackerPublicKey, privateKey: attacker.privateKey,
    expiresAt: Date.now() + 60_000,
  });
  assert.equal((await httpPost(port, untrusted)).status, 403,
    "a valid Ed25519 signature from a non-enrolled key must not self-enroll");
  assert.deepEqual(await fs.readFile(storagePath), baseline,
    "untrusted device key must not persist ciphertext or mutate registry");

  // Revoke the trusted device in the SAME durable JSON authority as the
  // accepted object. An entirely new, correctly signed payload must fail
  // after the revocation commit, not merely because of a duplicate opId.
  const postRevocation = await signed("post-revocation");
  assert.deepEqual(await routes.store.revokeDevice({ username: "alice",
    deviceId: "device-a", expectedEpoch: baselineEpoch }), { epoch: 2 });
  const revokedBaseline = await fs.readFile(storagePath);
  const revoked = await httpPost(port, postRevocation);
  assert.equal(revoked.status, 403, "revoked pinned device cannot authorize new HTTP persistence");
  assert.deepEqual(await fs.readFile(storagePath), revokedBaseline,
    "a signed request by a revoked device must not alter durable history");
  assert.equal(routes.store.atomicRegistryEpoch(), 2);
  // Also sign *after* revocation using the genuine old private key. A
  // still-cryptographically-valid, not-yet-expired signature must not be
  // mistaken for a NEW device authorization just because it is recent.
  const newlySignedByRevoked = await signed("signed-after-revocation");
  assert.equal((await httpPost(port, newlySignedByRevoked)).status, 403,
    "current durable device authority overrides a fresh Ed25519 signature");
  assert.deepEqual(await fs.readFile(storagePath), revokedBaseline);
  assert.equal(routes.store.atomicRegistryEpoch(), 2);

  // Close the REAL account SQLite connection (WAL/FULL), reopen the same
  // native file, and verify persisted account identity before reloading the
  // independently fsynced ciphertext object history. Recreating only the
  // in-memory SyncObjectStore would miss a broken SQLite recovery boundary.
  const beforeSqliteRestart = usersRepository.loadUsers().find(
    (user) => user.username === "alice");
  assert.ok(beforeSqliteRestart);
  closeDb();
  assert.equal(getOpenDatabasePath(), null, "old WAL/FULL SQLite handle must truly close");
  runMigrations({ backup: false });
  assert.equal(getOpenDatabasePath(), databasePath,
    "restart must open the original isolated SQLite path, not a stale singleton");
  assertOpenedNativeSqliteAt(databasePath, pinned);
  const afterSqliteRestart = usersRepository.loadUsers().find(
    (user) => user.username === "alice");
  assert.ok(afterSqliteRestart, "SQLite WAL restart must preserve authenticated account");
  assert.equal(afterSqliteRestart.storageRevision, beforeSqliteRestart.storageRevision);
  assert.deepEqual(afterSqliteRestart.permissions, beforeSqliteRestart.permissions);
  assert.equal(afterSqliteRestart.sessionVersion, beforeSqliteRestart.sessionVersion);
  assert.deepEqual(await fs.readFile(storagePath), revokedBaseline,
    "opening SQLite must not change independently persisted ciphertext history");

  const restarted = await new SyncObjectStore(storagePath,
    { atomicDeviceRegistry: true }).open();
  assert.equal(restarted.atomicRegistryEpoch(), 2,
    "revocation must remain durably fenced after restart");
  const persisted = restarted.list("alice");
  assert.deepEqual(persisted.map((item) => item.objectId),
    ["object-admitted"], "restart cannot revive rejected ciphertext");
  assert.deepEqual(await fs.readFile(storagePath), revokedBaseline,
    "read-only restart must not mutate the store");

  // Rebind the REAL HTTP route to a new persisted object-store instance,
  // not merely a direct in-memory read after SQLite reconnect. The old
  // listener is genuinely closed first and fresh HTTP requests must pass
  // through the reloaded durable registry and authorization boundary.
  await new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeIdleConnections?.();
    server.closeAllConnections?.();
  });
  server = undefined;
  const restartApp = express();
  restartApp.use(express.json({ limit: "9mb" }));
  const restartedRoutes = registerSyncRoutes({
    app: restartApp, storagePath,
    atomicDeviceRegistry: true, requireDeviceAuthorization: true,
    authenticate: (req, _res, next) => {
      req.user = { username: "alice", role: "user", sessionVersion: 0,
        permissions: { upload: true, delete: true } };
      next();
    },
    requirePermission: () => (_req, _res, next) => next(),
  });
  await restartedRoutes.ready;
  assert.equal(restartedRoutes.store.atomicRegistryEpoch(), 2);
  server = await new Promise((resolve) => {
    const listener = restartApp.listen(0, "127.0.0.1", () => resolve(listener));
  });
  const restartPort = server.address().port;
  assert.equal((await httpPost(restartPort, await signed("after-real-http-rebind"))).status, 403,
    "freshly signed revoked device must remain denied through a REBOUND HTTP route");
  assert.deepEqual(await fs.readFile(storagePath), revokedBaseline,
    "rebound HTTP authority must not persist a revoked operation");

  // Genuine persisted historical Ed25519 records remain verifiable even
  // after the ingress lease expires; this API must never grant fresh writes.
  const actualNow = Date.now;
  try {
    Date.now = () => admitted.authorization.expiresAt + 1;
    assert.ok(validateStoredOperation(persisted[0]));
    assert.equal(await verifyHistoricalAuthorizationProof(
      persisted[0].authorization, persisted[0], {
        username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
        revokedDeviceIds: [],
      }), true);
    assert.throws(() => validateFreshSignedOperation(persisted[0]),
      { code: "authorization_expired" },
      "expired persisted grants must never become fresh admissions");
  } finally {
    Date.now = actualNow;
  }
});
