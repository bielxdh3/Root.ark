"use strict";

// Captures real Root.ark wire responses for issue #64 (Android client contract).
// It runs the actual route handlers (src/routes/sync.js, src/routes/auth.js) in-process
// and builds requests with the actual protocol builders (sync-client/*).
// Usage: node scripts/issue-64-android-fixtures.js --write
// Writes android/core/src/test/resources/server-responses.json.
// Tokens and challenge ids are replaced with a placeholder; no key material is stored.

const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { registerSyncRoutes } = require("../src/routes/sync");
const registerAuthRoutes = require("../src/routes/auth");
const totp = require("../src/services/totp");
const { runMigrations } = require("../db/migrations");
const { closeDb } = require("../db");
const usersRepository = require("../repositories/usersRepository");
const { createPrivateAuthorityFixture } =
  require("../test/support/issue-65-private-authority-fixture");

const FIXTURE_PATH = path.join(__dirname, "..", "android", "core", "src", "test", "resources", "server-responses.json");
const REDACTED = "<redacted>";

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function call(base, method, urlPath, body) {
  const response = await fetch(base + urlPath, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

function expectStatus(result, status, label) {
  if (result.status !== status) throw new Error(`${label}: expected HTTP ${status}, got ${result.status} ${JSON.stringify(result.body)}`);
  return result;
}

function redact(body) {
  const copy = { ...body };
  for (const key of ["token", "challengeId"]) if (typeof copy[key] === "string") copy[key] = REDACTED;
  return copy;
}

async function captureSync(responses) {
  const dir = createPrivateAuthorityFixture("rootark-issue64-sync-");
  const oldEnv = { DB_ENABLED: process.env.DB_ENABLED,
    DATABASE_URL: process.env.DATABASE_URL, DB_WRITE_LEGACY_JSON: process.env.DB_WRITE_LEGACY_JSON };
  process.env.DB_ENABLED = "true";
  process.env.DB_WRITE_LEGACY_JSON = "false";
  process.env.DATABASE_URL = path.join(dir, "accounts.sqlite");
  try {
    runMigrations({ backup: false });
    usersRepository.saveUsers([{ username: "alice", password: "fixture-only-hash", role: "user",
      sessionVersion: 0, permissions: { upload: true, delete: true } }]);
  } catch (error) {
    closeDb();
    for (const [key, value] of Object.entries(oldEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await fsp.rm(dir, { recursive: true, force: true });
    throw error;
  }
  let server;
  try {
  const app = express();
  app.use(express.json({ limit: "9mb" }));
  // The captured happy-path tombstone is issued by an account authorized to delete.
  const authenticate = (req, _res, next) => { req.user = { username: "alice", role: "user",
    sessionVersion: 0, permissions: { upload: true, delete: true } }; next(); };
  const requirePermission = () => (_req, _res, next) => next();
  const route = registerSyncRoutes({ app, authenticate, requirePermission,
    storagePath: path.join(dir, "objects.json"),
    atomicDeviceRegistry: true, requireDeviceAuthorization: true });
  await route.ready;
  server = await listen(app);
  const base = `http://127.0.0.1:${server.address().port}`;
    const fileKey = crypto.randomBytes(32);
    const keys = crypto.generateKeyPairSync("ed25519");
    const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
    const deviceId = "fixture-device-a";
    await route.store.enrollDevice({ username: "alice", deviceId, publicKey, expectedEpoch: 0 });
    // Every captured write is signed and enrolled. Only the wire shape is
    // committed, never any private key or reusable credential.
    const signed = async (operation) => ({ ...operation, authorization: await createAuthorizationProof(operation, {
      username: "alice", privateKey: keys.privateKey, publicKey,
      expiresAt: Date.now() + 60_000,
      idempotencyKey: crypto.createHash("sha256").update(operation.operationId).digest("base64url"),
    }) });
    const common = {
      objectId: "fixture-object-1", fileId: "fixture-file-1", versionId: "fixture-version-1",
      deviceId, keyEpoch: "epoch-1", compartmentId: "private", fileKey,
    };

    const create = protocol.createOperation({
      ...common, operation: "create", operationId: "fixture-op-create", revision: { counter: 1, deviceId },
      metadata: { path: "docs/readme.txt", name: "readme.txt", contentType: "text/plain", size: 5, parentId: "root" },
      plaintext: Buffer.from("hello"),
    });
    const createBody = await signed(create);
    const created = expectStatus(await call(base, "POST", "/sync/v1/objects", createBody), 201, "create");
    responses["sync.post.201"] = created;

    responses["sync.post.409.replay"] = expectStatus(await call(base, "POST", "/sync/v1/objects", createBody), 409, "replay");
    responses["sync.post.400.invalid"] = expectStatus(await call(base, "POST", "/sync/v1/objects", { foo: 1 }), 400, "invalid");
    responses["sync.list.200"] = expectStatus(await call(base, "GET", "/sync/v1/objects", undefined), 200, "list");
    responses["sync.get.200"] = expectStatus(await call(base, "GET", "/sync/v1/objects/fixture-object-1", undefined), 200, "get");
    responses["sync.get.404"] = expectStatus(await call(base, "GET", "/sync/v1/objects/missing-object", undefined), 404, "get missing");

    const update = protocol.createOperation({
      ...common, operation: "update", operationId: "fixture-op-update", revision: { counter: 2, deviceId },
      baseRevision: { counter: 1, deviceId }, metadata: { path: "docs/readme.txt", name: "readme.txt", contentType: "text/plain", size: 6 },
      plaintext: Buffer.from("hello!"),
    });
    responses["sync.put.200.update"] = expectStatus(await call(base, "PUT", "/sync/v1/objects/fixture-object-1", await signed(update)), 200, "update");

    const stale = protocol.createOperation({
      ...common, operation: "update", operationId: "fixture-op-stale", revision: { counter: 2, deviceId },
      baseRevision: { counter: 2, deviceId }, metadata: { path: "docs/readme.txt", name: "readme.txt", contentType: "text/plain", size: 6 },
      plaintext: Buffer.from("stale"),
    });
    responses["sync.put.409.stale"] = expectStatus(await call(base, "PUT", "/sync/v1/objects/fixture-object-1", await signed(stale)), 409, "stale");

    const conflict = protocol.createOperation({
      ...common, operation: "update", operationId: "fixture-op-conflict", revision: { counter: 3, deviceId },
      baseRevision: { counter: 1, deviceId }, metadata: { path: "docs/readme.txt", name: "readme.txt", contentType: "text/plain", size: 6 },
      plaintext: Buffer.from("conflict"),
    });
    responses["sync.put.409.base"] = expectStatus(await call(base, "PUT", "/sync/v1/objects/fixture-object-1", await signed(conflict)), 409, "base conflict");

    const move = protocol.createOperation({
      ...common, operation: "move", operationId: "fixture-op-move", revision: { counter: 3, deviceId },
      baseRevision: { counter: 2, deviceId }, metadata: { path: "docs/moved.txt", sourcePath: "docs/readme.txt" },
      plaintext: Buffer.from(""),
    });
    responses["sync.put.200.move"] = expectStatus(await call(base, "PUT", "/sync/v1/objects/fixture-object-1", await signed(move)), 200, "move");

    const remove = protocol.createOperation({
      ...common, operation: "delete", operationId: "fixture-op-delete", revision: { counter: 4, deviceId },
      baseRevision: { counter: 3, deviceId }, metadata: { path: "docs/moved.txt" }, plaintext: Buffer.from(""),
    });
    responses["sync.delete.200"] = expectStatus(await call(base, "DELETE", "/sync/v1/objects/fixture-object-1", await signed(remove)), 200, "delete");

    return { createBody };
  } finally {
    try {
      if (server) await closeServer(server);
    } finally {
      closeDb();
      for (const [key, value] of Object.entries(oldEnv)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      await fsp.rm(dir, { recursive: true, force: true });
    }
  }
}

async function captureAuth(responses) {
  const jwtSecret = crypto.randomBytes(32).toString("base64url");
  const totpKey = crypto.randomBytes(32);
  const password = crypto.randomBytes(12).toString("base64url");
  const passwordHash = bcrypt.hashSync(password, 4);
  const bobSecret = totp.generateSecret();
  const users = [
    { username: "alice", role: "user", password: passwordHash, permissions: {}, sessionVersion: 0 },
    {
      username: "bob", role: "user", password: passwordHash, permissions: {}, sessionVersion: 0,
      totpEnabled: true, totpSecret: totp.encryptSecret(bobSecret, totpKey, "Root.ark/TOTP/bob"),
    },
    { username: "carol", role: "user", password: passwordHash, permissions: {}, sessionVersion: 0 },
  ];
  const baseKeys = {
    upload: false, approve: false, delete: false, listFiles: true, listPending: false, manageUsers: false,
    createFolders: false, viewAnalytics: false, viewAuditLogs: false, manageBackups: false, manageTrash: false,
  };
  const context = {
    authenticate: (_req, _res, next) => next(),
    auditLog() {},
    checkAnomalies() {},
    logAnalyticsEvent() {},
    getAuditActor: (_req, username) => ({ username, ip: "127.0.0.1" }),
    bcrypt,
    jwt,
    jwtSecret,
    loadUsers: () => users,
    saveUsers: () => {},
    getTotpKey: () => totpKey,
    // Stub with the same key set as server.js getBasePermissions(); server.js does not export it.
    normalizeUserPermissions: (user = {}) => ({ ...baseKeys, ...(user.permissions || {}) }),
    qrcode: null,
    requirePermission: () => (_req, _res, next) => next(),
    sessionCookieOptions: { httpOnly: true, sameSite: "strict", path: "/" },
  };
  const app = express();
  app.use(express.json());
  registerAuthRoutes(app, context);
  const server = await listen(app);
  const base = `http://127.0.0.1:${server.address().port}`;
  const previousPolicy = process.env.TOTP_POLICY;
  try {
    const ok = expectStatus(await call(base, "POST", "/auth/login", { username: "alice", password }), 200, "login");
    responses["login.200.authenticated"] = { status: ok.status, body: redact(ok.body) };

    responses["login.401.invalid"] = expectStatus(await call(base, "POST", "/auth/login", { username: "alice", password: `${password}x` }), 401, "login invalid");

    const challenge = expectStatus(await call(base, "POST", "/auth/login", { username: "bob", password }), 200, "challenge");
    const code = totp.hotp(bobSecret, Math.floor(Date.now() / 1000 / totp.PERIOD_SECONDS));
    const twoFactor = expectStatus(await call(base, "POST", "/auth/login/2fa", { challengeId: challenge.body.challengeId, code }), 200, "2fa");
    responses["login.2fa.200"] = { status: twoFactor.status, body: redact(twoFactor.body) };
    responses["login.200.challenge"] = { status: challenge.status, body: redact(challenge.body) };

    const challenge2 = expectStatus(await call(base, "POST", "/auth/login", { username: "bob", password }), 200, "challenge 2");
    responses["login.2fa.401"] = expectStatus(await call(base, "POST", "/auth/login/2fa", { challengeId: challenge2.body.challengeId, code: "000000" }), 401, "2fa invalid");

    process.env.TOTP_POLICY = "global-required";
    const enrollment = expectStatus(await call(base, "POST", "/auth/login", { username: "carol", password }), 403, "enrollment");
    responses["login.403.enrollment"] = { status: enrollment.status, body: redact(enrollment.body) };
  } finally {
    if (previousPolicy === undefined) delete process.env.TOTP_POLICY;
    else process.env.TOTP_POLICY = previousPolicy;
    await closeServer(server);
  }
}

async function generateFixtures() {
  const responses = {};
  const { createBody } = await captureSync(responses);
  await captureAuth(responses);

  const createdRecord = responses["sync.post.201"].body;
  const moveRecord = responses["sync.put.200.move"].body;
  const classes = {
    SyncRevision: createdRecord.revision,
    // Union of the create and move metadata allow-lists (every SyncMetadata key appears in one of them).
    SyncMetadata: { ...createdRecord.metadata, ...moveRecord.metadata },
    SyncAuthorizationProof: createdRecord.authorization,
    SyncOperationRequest: createBody,
    SyncRecord: createdRecord,
    SyncListResponse: responses["sync.list.200"].body,
    SyncConflict: responses["sync.put.409.stale"].body,
    Authenticated: responses["login.200.authenticated"].body,
    ChallengeRequired: responses["login.200.challenge"].body,
    EnrollmentRequired: responses["login.403.enrollment"].body,
  };
  return { generatedBy: "scripts/issue-64-android-fixtures.js", responses, classes };
}

module.exports = { FIXTURE_PATH, generateFixtures };

if (require.main === module) {
  generateFixtures().then(async (fixture) => {
    const text = `${JSON.stringify(fixture, null, 2)}\n`;
    if (process.argv.includes("--write")) {
      await fsp.writeFile(FIXTURE_PATH, text);
      process.stdout.write(`wrote ${path.relative(process.cwd(), FIXTURE_PATH)}\n`);
    } else {
      process.stdout.write(text);
    }
  }).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
