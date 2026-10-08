"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { SyncObjectStore } = require("../src/routes/sync");
const resilience = require("../src/services/deploymentResilience");

function validConfig(masterKeyFile) {
  return resilience.getDeploymentReadiness({
    env: { NODE_ENV: "production", JWT_SECRET: crypto.randomBytes(32).toString("hex"), TOTP_POLICY: "optional" },
    masterKeyFile,
    cloudStatus: { provider: "local", enabled: false },
    validateTotp: () => ({ mode: "optional" }),
  });
}

test("readiness fails closed for missing critical configuration and accepts a complete local profile", () => {
  const missing = resilience.getDeploymentReadiness({
    env: { JWT_SECRET: "short" },
    cloudStatus: { provider: "local", enabled: false },
    validateTotp: () => ({ mode: "optional" }),
  });
  assert.equal(missing.ok, false);
  assert.deepEqual(missing.checks, { jwt: "missing_or_invalid", totp: "missing_or_invalid", sessionCookie: "missing_or_invalid", masterKey: "missing_or_invalid", provider: "ok" });

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-phase14-config-"));
  try {
    const masterKeyFile = path.join(directory, "master.key");
    fs.writeFileSync(masterKeyFile, "a".repeat(64));
    assert.equal(validConfig(masterKeyFile).ok, true);
    assert.equal(resilience.getDeploymentReadiness({ env: { JWT_SECRET: "x".repeat(32), TOTP_POLICY: "optional" }, masterKeyFile, cloudStatus: { provider: "s3", enabled: true, s3: {} }, validateTotp: () => ({}) }).checks.provider, "missing_or_invalid");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("deployment readiness fails when the session cookie would not be Secure", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-session-cookie-readiness-"));
  try {
    const masterKeyFile = path.join(directory, "master.key");
    fs.writeFileSync(masterKeyFile, "b".repeat(64));
    const env = { NODE_ENV: "development", JWT_SECRET: crypto.randomBytes(32).toString("hex"), TOTP_POLICY: "optional" };
    const insecure = resilience.getDeploymentReadiness({ env, masterKeyFile, cloudStatus: { provider: "local", enabled: false }, validateTotp: () => ({ mode: "optional" }) });
    assert.equal(insecure.ok, false);
    assert.equal(insecure.checks.sessionCookie, "missing_or_invalid");
    assert.equal(resilience.getDeploymentReadiness({ env: { ...env, SESSION_COOKIE_SECURE: "true" }, masterKeyFile, cloudStatus: { provider: "local", enabled: false }, validateTotp: () => ({ mode: "optional" }) }).checks.sessionCookie, "ok");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("provider errors are bounded to safe categories without provider secrets", () => {
  const error = resilience.normalizeProviderError(Object.assign(new Error("token=provider-secret"), { name: "TimeoutError" }));
  assert.equal(error.code, "provider_timeout");
  assert.equal(error.message.includes("provider-secret"), false);
  assert.equal(resilience.normalizeProviderError(Object.assign(new Error("private"), { code: "unexpected-private-code" })).code, "provider_error");
});

test("retry attempts are bounded and cancellation stops backoff", async () => {
  let attempts = 0;
  await assert.rejects(
    resilience.retryWithBackoff(async () => {
      attempts += 1;
      throw Object.assign(new Error("offline"), { code: "ETIMEDOUT" });
    }, { maxAttempts: 3, baseDelayMs: 0 }),
    { code: "ETIMEDOUT" },
  );
  assert.equal(attempts, 3);

  const controller = new AbortController();
  const pending = resilience.retryWithBackoff(async () => { throw Object.assign(new Error("offline"), { code: "ETIMEDOUT" }); }, { maxAttempts: 10, baseDelayMs: 50, signal: controller.signal });
  setTimeout(() => controller.abort(), 5);
  await assert.rejects(pending, { code: "operation_cancelled" });
});

test("idempotency helper shares an in-flight result", async () => {
  const store = new Map();
  let calls = 0;
  const key = resilience.createIdempotencyKey({ operation: "upload", id: "object-1" });
  const values = await Promise.all([
    resilience.runIdempotent(key, async () => { calls += 1; return "stored"; }, store),
    resilience.runIdempotent(key, async () => { calls += 1; return "duplicate"; }, store),
  ]);
  assert.deepEqual(values, ["stored", "stored"]);
  assert.equal(calls, 1);
});

test("ciphertext-only attestation rejects plaintext/key fields and corrupt protected bytes", () => {
  const record = createOperation({
    operation: "create",
    objectId: "object-1",
    fileId: "file-1",
    versionId: "version-1",
    operationId: "operation-1",
    revision: { counter: 1, deviceId: "device-1" },
    keyEpoch: "epoch-1",
    compartmentId: "compartment-1",
    deviceId: "device-1",
    metadata: { path: "phase14/attestation.txt" },
    plaintext: "ciphertext only",
    fileKey: crypto.randomBytes(32),
  });
  assert.equal(resilience.attestCiphertextOnlyRecords([record]).ok, true);
  assert.throws(() => resilience.attestCiphertextOnlyRecords([{ ...record, ciphertext: "*" }]), { code: "SYNC_ATTESTATION_FAILED" });
  assert.throws(() => resilience.attestCiphertextOnlyRecords([{ ...record, plaintext: "leaked" }]), { code: "SYNC_ATTESTATION_FAILED" });
  assert.throws(() => resilience.attestCiphertextOnlyRecords([{ ...record, fileKey: "leaked" }]), { code: "SYNC_ATTESTATION_FAILED" });
});

test("sync store restart re-attests records and rejects a corrupt persisted ciphertext record", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-phase14-sync-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "sync-objects.json");
  const store = await new SyncObjectStore(filePath).open();
  const record = createOperation({
    operation: "create", objectId: "object-2", fileId: "file-2", versionId: "version-2", operationId: "operation-2",
    revision: { counter: 1, deviceId: "device-2" }, keyEpoch: "epoch-2", compartmentId: "compartment-2", deviceId: "device-2",
    metadata: { path: "phase14/restart.txt" },
    plaintext: "restart-safe", fileKey: crypto.randomBytes(32),
  });
  await store.put("alice", record);
  await new SyncObjectStore(filePath).open();
  const state = JSON.parse(fs.readFileSync(filePath, "utf8"));
  state.users.alice.objects["object-2"].nonce = "bad";
  fs.writeFileSync(filePath, JSON.stringify(state));
  await assert.rejects(new SyncObjectStore(filePath).open(), { code: "SYNC_ATTESTATION_FAILED" });
});

test("health/readiness and observability outputs are sanitized", () => {
  const routes = {};
  const app = { get(route, ...handlers) { routes[route] = handlers.at(-1); } };
  resilience.registerReadinessRoutes(app, { getReadiness: () => ({ ok: false, checks: { jwt: "missing_or_invalid" }, provider: { provider: "s3", configured: false } }) });
  const response = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(value) { this.value = value; } };
  routes["/ready"]({}, response);
  assert.equal(response.statusCode, 503);
  assert.equal(response.value.provider.path, undefined);
  routes["/health"]({}, response);
  assert.deepEqual(response.value, { status: "ok", service: "rootark" });

  const sanitized = resilience.sanitizeLogValue({ token: "secret-token", path: "C:\\private\\data", nested: { password: "pw" }, message: "Bearer abc" });
  assert.deepEqual(sanitized, { token: "[REDACTED]", path: "[REDACTED]", nested: { password: "[REDACTED]" }, message: "Bearer [REDACTED]" });
  assert.deepEqual(resilience.sanitizeMetricLabels({ provider: "s3", "bad-label": "ignored", token: "secret" }), { provider: "s3", token: "[REDACTED]" });
});
