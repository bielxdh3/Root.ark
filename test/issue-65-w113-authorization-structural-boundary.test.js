"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");

function operation(suffix = "fixture") {
  return protocol.createOperation({ operation: "create", objectId: `object-${suffix}`,
    fileId: `file-${suffix}`, versionId: `version-${suffix}`, operationId: `op-${suffix}`,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: `${suffix}.txt` },
    plaintext: Buffer.from("encrypted fixture"), fileKey: crypto.randomBytes(32) });
}

test("a local encryption constructor must never import externally supplied authorization", async () => {
  const plain = operation("constructor");
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const proof = await createAuthorizationProof(plain, {
    username: "alice", publicKey, privateKey: signer.privateKey });
  assert.throws(() => protocol.createOperation({ ...plain,
    authorization: proof, plaintext: Buffer.from("different bytes"), fileKey: crypto.randomBytes(32) }),
  /authorization/i, "an untrusted caller's proof must not survive a new encryption operation");
});

test("fresh and stored parsers bind proof identity and digests to actual envelope bytes", async () => {
  const plain = operation("binding");
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const proof = await createAuthorizationProof(plain, {
    username: "alice", publicKey, privateKey: signer.privateKey,
    expiresAt: Date.now() + 60_000 });
  const signed = { ...plain, authorization: proof };
  assert.equal(protocol.canonicalJson(protocol.validateOperation(signed).authorization),
    protocol.canonicalJson(proof),
    "valid signed evidence keeps the same canonical fields");
  assert.equal(protocol.canonicalJson(protocol.validateFreshSignedOperation(signed).authorization),
    protocol.canonicalJson(proof), "strict ingress requires a proof-shaped, bound envelope");
  assert.throws(() => protocol.validateFreshSignedOperation(plain), /authorization/i,
    "trusted strict ingress must not accept an unsigned legacy operation");
  assert.equal(await verifyAuthorizationProof(proof, signed, {
    username: "alice", trustedDevicePublicKeys: { "device-a": publicKey } }), true);

  for (const [label, value] of [
    ["ciphertext", { ...signed, ciphertext: Buffer.from("tampered ciphertext").toString("base64url") }],
    ["operationId", { ...signed, authorization: { ...proof, operationId: "another-operation" } }],
    ["digest", { ...signed, authorization: { ...proof, aadDigest: crypto.randomBytes(32).toString("base64url") } }],
    ["scope", { ...signed, authorization: { ...proof, deviceId: "foreign-device" } }],
  ]) {
    assert.throws(() => protocol.validateOperation(value), /authorization/i, `${label} must be refused before an ingress mutation`);
    assert.throws(() => protocol.validateStoredOperation(value), /authorization/i, `${label} must not become historical admission evidence`);
  }
  const expired = { ...signed, authorization: { ...proof, expiresAt: 1 } };
  assert.throws(() => protocol.validateOperation(expired), /authorization/i);
  assert.equal(protocol.validateStoredOperation(expired).authorization.expiresAt, 1,
    "history parser permits expiry but must not claim the operation was durably authorized");
  assert.equal(Object.hasOwn(protocol.validateOperation(plain), "authorization"), false,
    "unsigned-only legacy operations retain wire compatibility");
});

test("real protected HTTP ingress rejects a bound-digest mismatch BEFORE the write transaction", async (t) => {
  const fs = require("node:fs");
  const path = require("node:path");
  const express = require("express");
  const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");
  const { runMigrations } = require("../db/migrations");
  const { closeDb } = require("../db");
  const usersRepository = require("../repositories/usersRepository");
  const { registerSyncRoutes } = require("../src/routes/sync");
  const directory = createPrivateAuthorityFixture("rootark-w113-signed-ingress-");
  const old = { DB_ENABLED: process.env.DB_ENABLED, DATABASE_URL: process.env.DATABASE_URL,
    DB_WRITE_LEGACY_JSON: process.env.DB_WRITE_LEGACY_JSON };
  process.env.DB_ENABLED = "true";
  process.env.DB_WRITE_LEGACY_JSON = "false";
  process.env.DATABASE_URL = path.join(directory, "accounts.sqlite");
  t.after(() => {
    closeDb();
    for (const [name, value] of Object.entries(old)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    fs.rmSync(directory, { recursive: true, force: true });
  });
  runMigrations({ backup: false });
  usersRepository.saveUsers([{ username: "alice", role: "user", sessionVersion: 0,
    password: "fixture", permissions: { upload: true, delete: true } }]);
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  const routes = registerSyncRoutes({ app, storagePath: path.join(directory, "objects.json"),
    atomicDeviceRegistry: true, requireDeviceAuthorization: true,
    authenticate: (req, _res, next) => {
      req.user = { username: "alice", sessionVersion: 0,
        permissions: { upload: true, delete: true } };
      next();
    },
    requirePermission: () => (_req, _res, next) => next(),
  });
  await routes.ready;
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  await routes.store.enrollDevice({ username: "alice", deviceId: "device-a",
    publicKey, expectedEpoch: 0 });
  let putCalls = 0;
  const nativePut = routes.store.put.bind(routes.store);
  routes.store.put = (...args) => { putCalls++; return nativePut(...args); };
  const server = await new Promise((resolve) => {
    const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const send = async (body) => fetch(`http://127.0.0.1:${server.address().port}/sync/v1/objects`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  const plain = operation("http");
  const authorization = await createAuthorizationProof(plain, {
    username: "alice", publicKey, privateKey: signer.privateKey });
  const signed = { ...plain, authorization };
  const tampered = { ...signed,
    ciphertext: Buffer.from("different encrypted bytes").toString("base64url") };
  assert.equal((await send(tampered)).status, 403);
  assert.equal(putCalls, 0, "invalid binding must never enter a storage transaction");
  assert.deepEqual(routes.store.list("alice"), []);
  assert.equal((await send({ ...plain, operationId: "unsigned-strict" })).status, 403);
  assert.equal(putCalls, 0, "unsigned operation must not reach strict storage");
  assert.equal((await send(signed)).status, 201, "real independently pinned Ed25519 proof still works");
  assert.equal(putCalls, 1);
});
