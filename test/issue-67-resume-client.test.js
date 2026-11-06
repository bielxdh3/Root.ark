"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { Readable } = require("node:stream");
const express = require("express");
const bcrypt = require("bcryptjs");

const protocol = require("../sync-client/rootark-sync-protocol");
const { SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");
const { createSyncBurstGuard } = require("../src/services/syncBurstGuard");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");
const { writePrivateSyncConfig } = require("../sync-client/rootark-sync-private-config");
const { readResumeCredentials } = require("../sync-client/rootark-sync-v2");

const CLI = path.resolve(__dirname, "../sync-client/rootark-sync-v2.js");
const PASSWORD = "secret-resume-password";

function runResume(config, target, credentials) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, "resume", "--config", config,
      "--device-id", target, "--credentials-stdin"], {
      windowsHide: true, stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => child.kill(), 12000);
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
    child.once("close", (status) => {
      clearTimeout(timeout);
      resolve({ status, stdout, stderr });
    });
    child.stdin.end(credentials);
  });
}

function runPauses(config) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, "pauses", "--config", config], {
      windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => child.kill(), 12000);
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
    child.once("close", (status) => {
      clearTimeout(timeout);
      resolve({ status, stdout, stderr });
    });
  });
}

function operation(index, kind, parent, key) {
  return protocol.createOperation({
    operation: kind, objectId: `object-${index}`, fileId: `file-${index}`,
    versionId: `version-${index}-${kind}`, operationId: `${kind}-${index}`,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: kind === "create" ? 1 : 2, deviceId: "device-a" },
    baseRevision: parent?.revision || null, metadata: { path: `file-${index}.txt` },
    plaintext: kind === "create" ? Buffer.from("owner data") : undefined, fileKey: key,
  });
}

test("#67: real burst pause can be reviewed and resumed by other device through CLI without leaking credentials", async (t) => {
  const root = createPrivateAuthorityFixture("rootark-67-resume-client-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const storagePath = path.join(root, "objects.json");
  const app = express();
  app.use("/sync/v1", express.json());
  const passwordHash = bcrypt.hashSync(PASSWORD, 4);
  const user = { username: "alice", password: passwordHash, sessionVersion: 0 };
  let currentUsername = "alice";
  let mayUpload = true;
  const authenticate = (req, res, next) => {
    if (req.get("authorization") !== "Bearer test-resume-token") {
      return res.status(401).json({ error: "Denied" });
    }
    req.user = { username: currentUsername, permissions: { upload: mayUpload, delete: true, listFiles: true } };
    next();
  };
  const routes = registerSyncRoutes({ app, storagePath, authenticate,
    requirePermission: (name) => (req, res, next) => req.user.permissions[name]
      ? next() : res.status(403).json({ error: "Denied" }), bcrypt,
    loadUsers: () => [{ ...user }], saveUsers: () => {},
    burstGuard: createSyncBurstGuard({ maxDestructive: 1, windowMs: 600000, env: {} }),
  });
  await routes.ready;
  const server = await new Promise((resolve) => {
    const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const adapter = createOpaqueSyncAdapter({ baseUrl,
    fetchImpl: (url, options) => fetch(url, { ...options,
      headers: { ...options.headers, Authorization: "Bearer test-resume-token" } }),
  });
  const key = crypto.randomBytes(32);
  for (const i of [1, 2]) {
    const created = operation(i, "create", null, key);
    assert.equal((await adapter.push(created)).protocolVersion, 2);
    const deleted = operation(i, "delete", created, key);
    if (i === 1) assert.equal((await adapter.push(deleted)).protocolVersion, 2);
    else await assert.rejects(adapter.push(deleted), (error) => error.status === 423);
  }
  const config = path.join(root, "sync-config.json");
  await writePrivateSyncConfig(config, JSON.stringify({ serverUrl: baseUrl,
    username: "alice", token: "test-resume-token", deviceId: "device-b" }));
  const paused = await adapter.pausedDevices();
  const rawPauseResponse = await fetch(`${baseUrl}/sync/v1/devices/paused`, {
    headers: { Authorization: "Bearer test-resume-token" },
  });
  assert.equal(rawPauseResponse.status, 200);
  assert.equal(rawPauseResponse.headers.get("cache-control"), "no-store");
  assert.doesNotMatch(await rawPauseResponse.text(), /pauseNonce|codeMac|resumeIntent|password|ciphertext|test-resume-token/i);
  assert.deepEqual(paused, { protocolVersion: 2, pausedDevices: [{
    deviceId: "device-a", reason: "destructive_burst", limit: 1,
    windowMs: 600000, pausedAt: paused.pausedDevices[0].pausedAt,
  }] });
  assert.match(paused.pausedDevices[0].pausedAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.doesNotMatch(JSON.stringify(paused), /pauseNonce|authorization|token|ciphertext|password/i);
  assert.deepEqual(JSON.parse((await runPauses(config)).stdout), paused);
  currentUsername = "bob";
  assert.deepEqual(await adapter.pausedDevices(), { protocolVersion: 2, pausedDevices: [] });
  currentUsername = "alice";
  mayUpload = false;
  await assert.rejects(adapter.pausedDevices(), (error) => error.status === 403);
  mayUpload = true;
  await assert.rejects(createOpaqueSyncAdapter({ baseUrl }).pausedDevices(),
    (error) => error.status === 401);
  const credentials = JSON.stringify({ password: PASSWORD });
  const denied = await runResume(config, "device-a", JSON.stringify({ password: "wrong-password" }));
  assert.notEqual(denied.status, 0);
  assert.doesNotMatch(denied.stderr + denied.stdout, /wrong-password|test-resume-token/);
  assert.equal(routes.store.pauseFence("alice", "device-a") !== null, true);

  const resumed = await runResume(config, "device-a", credentials);
  assert.equal(resumed.status, 0, resumed.stderr);
  assert.deepEqual(JSON.parse(resumed.stdout), {
    protocolVersion: 2, deviceId: "device-a", paused: false, wasPaused: true,
  });
  assert.doesNotMatch(resumed.stdout + resumed.stderr, /secret-resume-password|test-resume-token/);
  assert.equal(routes.store.pauseFence("alice", "device-a"), null);
  assert.deepEqual(await adapter.pausedDevices(), { protocolVersion: 2, pausedDevices: [] });
  const again = await runResume(config, "device-a", credentials);
  assert.equal(JSON.parse(again.stdout).wasPaused, false);
});

test("#67: resume adapter refuses self-resume, unsafe ids, missing password and forged success", async () => {
  const requests = [];
  const adapter = createOpaqueSyncAdapter({ baseUrl: "https://example.invalid",
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return { ok: true, status: 200, json: async () => ({
        protocolVersion: 2, deviceId: "other-device", paused: false, wasPaused: true,
      }) };
    },
  });
  await assert.rejects(adapter.resumeDevice("../device", { deviceId: "me", password: PASSWORD }), /id/i);
  await assert.rejects(adapter.resumeDevice("me", { deviceId: "me", password: PASSWORD }), /device|self/i);
  await assert.rejects(adapter.resumeDevice("other-device", { deviceId: "me" }), /password/i);
  assert.equal(requests.length, 0);
  assert.deepEqual(await adapter.resumeDevice("other-device", { deviceId: "me", password: PASSWORD }), {
    protocolVersion: 2, deviceId: "other-device", paused: false, wasPaused: true,
  });
  assert.equal(requests[0].options.redirect, "error");
  assert.equal(requests[0].options.method, "POST");
  const body = JSON.parse(requests[0].options.body);
  assert.deepEqual(body, { deviceId: "me", password: PASSWORD });
  await adapter.resumeDevice("other-device", { deviceId: "me", password: PASSWORD, code: "123456" });
  assert.deepEqual(JSON.parse(requests[1].options.body), {
    deviceId: "me", password: PASSWORD, code: "123456",
  });
  const forged = createOpaqueSyncAdapter({ baseUrl: "https://example.invalid",
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({
      protocolVersion: 2, deviceId: "different-device", paused: false, wasPaused: true,
    }) }),
  });
  await assert.rejects(forged.resumeDevice("other-device", {
    deviceId: "me", password: PASSWORD,
  }), /resume response/i);
});

test("#67: private credential stdin rejects oversize, unexpected keys and malformed JSON", async () => {
  await assert.rejects(readResumeCredentials(Readable.from([Buffer.alloc(2049, 32)])), /credentials/i);
  await assert.rejects(readResumeCredentials(Readable.from(['{"password":"ok","key":"leak"}'])), /credentials/i);
  await assert.rejects(readResumeCredentials(Readable.from(['{"password":42}'])), /credentials/i);
  await assert.rejects(readResumeCredentials(Readable.from(['broken-json'])), /credentials/i);
  assert.deepEqual(await readResumeCredentials(Readable.from(['{"password":"ok","code":"123456"}'])),
    { password: "ok", code: "123456" });
});

test("#67: adapter refuses malformed, unexpected, oversized or duplicate paused-device inventories", async () => {
  let payload = { protocolVersion: 2, pausedDevices: [{
    deviceId: "device-a", pausedAt: new Date().toISOString(),
    reason: "destructive_burst", limit: 10, windowMs: 60000,
  }] };
  const adapter = createOpaqueSyncAdapter({ baseUrl: "https://example.invalid",
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => payload }),
  });
  assert.deepEqual(await adapter.pausedDevices(), payload);
  payload = { ...payload, pausedDevices: [{ ...payload.pausedDevices[0], pauseNonce: "should-not-leak" }] };
  await assert.rejects(adapter.pausedDevices(), /paused/i);
  payload = { protocolVersion: 2, pausedDevices: Array(1025).fill({
    deviceId: "device-a", pausedAt: new Date().toISOString(),
    reason: "destructive_burst", limit: 10, windowMs: 60000,
  }) };
  await assert.rejects(adapter.pausedDevices(), /paused/i);
  payload.pausedDevices = [payload.pausedDevices[0], payload.pausedDevices[0]];
  await assert.rejects(adapter.pausedDevices(), /paused/i);
});
