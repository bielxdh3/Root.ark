"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const { canonicalJson, validateOperation } = require("../../sync-client/rootark-sync-protocol");

const SAFE_PROVIDER_CODES = new Set([
  "configuration", "unsupported_provider", "invalid_path", "invalid_prefix", "foreign_prefix",
  "invalid_inventory_key", "invalid_inventory_metadata", "invalid_inventory_identity",
  "outside_configured_parent", "duplicate_inventory_identity", "partial_delete", "provider_timeout",
  "provider_cancelled", "provider_error", "not_found", "missing_object",
]);
const SAFE_PROVIDER_MESSAGES = {
  configuration: "Provider configuration is incomplete",
  unsupported_provider: "Provider is not supported",
  invalid_path: "Provider path is invalid",
  invalid_prefix: "Provider prefix is invalid",
  foreign_prefix: "Provider object is outside the configured prefix",
  invalid_inventory_key: "Provider inventory is invalid",
  invalid_inventory_metadata: "Provider metadata does not match configured inventory",
  invalid_inventory_identity: "Provider identity is invalid",
  outside_configured_parent: "Provider object is outside the configured parent",
  duplicate_inventory_identity: "Provider inventory contains a duplicate identity",
  partial_delete: "Provider deletion was incomplete",
  provider_timeout: "Provider request timed out",
  provider_cancelled: "Provider request was cancelled",
  provider_error: "Provider operation failed",
  not_found: "Provider object was not found",
  missing_object: "Provider object was not found",
};
const REDACTED = "[REDACTED]";

function safeProviderCode(error) {
  const code = String(error?.code || "");
  if (["AbortError", "ABORT_ERR", "ECONNABORTED"].includes(code) || error?.name === "AbortError") return "provider_cancelled";
  if (["TimeoutError", "ETIMEDOUT", "ESOCKETTIMEDOUT"].includes(code) || /timeout/i.test(String(error?.name || ""))) return "provider_timeout";
  return SAFE_PROVIDER_CODES.has(code) ? code : "provider_error";
}

function normalizeProviderError(error) {
  const code = safeProviderCode(error);
  const normalized = new Error(SAFE_PROVIDER_MESSAGES[code]);
  normalized.code = code;
  normalized.retryable = ["provider_timeout", "provider_error", "partial_delete"].includes(code);
  return normalized;
}

function cancellationError() {
  const error = new Error("Operation cancelled");
  error.code = "operation_cancelled";
  return error;
}

function boundedInteger(value, fallback, minimum, maximum) {
  const number = Number(value);
  return Number.isSafeInteger(number) ? Math.max(minimum, Math.min(maximum, number)) : fallback;
}

function retryDelay(attempt, baseDelayMs, maxDelayMs) {
  return Math.min(maxDelayMs, baseDelayMs * (2 ** Math.max(0, attempt - 1)));
}

function waitForRetry(delayMs, signal) {
  if (signal?.aborted) return Promise.reject(cancellationError());
  return new Promise((resolve, reject) => {
    const timer = setTimeout(done, delayMs);
    function done() {
      signal?.removeEventListener("abort", abort);
      resolve();
    }
    function abort() {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      reject(cancellationError());
    }
    signal?.addEventListener("abort", abort, { once: true });
  });
}

async function retryWithBackoff(operation, options = {}) {
  const maxAttempts = boundedInteger(options.maxAttempts, 3, 1, 10);
  const baseDelayMs = boundedInteger(options.baseDelayMs, 100, 0, 60 * 1000);
  const maxDelayMs = boundedInteger(options.maxDelayMs, 60 * 1000, baseDelayMs, 60 * 1000);
  const shouldRetry = options.shouldRetry || ((error) => normalizeProviderError(error).retryable);
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    if (options.signal?.aborted) throw cancellationError();
    try {
      return await operation(attempt);
    } catch (error) {
      if (attempt >= maxAttempts || !shouldRetry(error, attempt)) throw error;
      await waitForRetry(retryDelay(attempt, baseDelayMs, maxDelayMs), options.signal);
    }
  }
  throw new Error("Retry operation did not complete");
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") return Object.keys(value).sort().reduce((result, key) => {
    result[key] = stableValue(value[key]);
    return result;
  }, {});
  return value;
}

function createIdempotencyKey(value) {
  return `rootark-${crypto.createHash("sha256").update(canonicalJson(stableValue(value))).digest("hex")}`;
}

async function runIdempotent(key, operation, store = new Map()) {
  const identity = String(key || "");
  if (!identity) throw new Error("Idempotency key is required");
  if (store.has(identity)) return store.get(identity);
  const result = Promise.resolve().then(operation);
  store.set(identity, result);
  try {
    return await result;
  } catch (error) {
    store.delete(identity);
    throw error;
  }
}

function hasSensitiveField(name) {
  return /^(?:plaintext|file_?key|key|key_?material|private_?key|secret|password|token|authorization|cookie|credential)s?$/i.test(String(name));
}

function sanitizeLogValue(value, fieldName = "") {
  if (hasSensitiveField(fieldName)) return REDACTED;
  if (typeof value === "string") {
    return value
      .replace(/Bearer\s+[^\s]+/gi, `Bearer ${REDACTED}`)
      .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, REDACTED)
      .replace(/(?:[A-Za-z]:[\\/]|\/)[^\s,;]+/g, REDACTED);
  }
  if (Array.isArray(value)) return value.map((item) => sanitizeLogValue(item));
  if (value && typeof value === "object") return Object.keys(value).reduce((result, key) => {
    result[key] = sanitizeLogValue(value[key], key);
    return result;
  }, {});
  return value;
}

function sanitizeMetricLabels(labels = {}) {
  return Object.keys(labels).sort().reduce((result, key) => {
    if (/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(key)) result[key] = String(sanitizeLogValue(labels[key], key)).slice(0, 120);
    return result;
  }, {});
}

function decodeBase64Url(value, field) {
  if (typeof value !== "string" || (field !== "ciphertext" && !value) || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    throw Object.assign(new Error("Protected sync attestation failed"), { code: "SYNC_ATTESTATION_FAILED" });
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) throw Object.assign(new Error("Protected sync attestation failed"), { code: "SYNC_ATTESTATION_FAILED" });
  if (field === "nonce" && decoded.length !== 12 || field === "tag" && decoded.length !== 16) {
    throw Object.assign(new Error("Protected sync attestation failed"), { code: "SYNC_ATTESTATION_FAILED" });
  }
  return decoded;
}

function assertNoProtectedSecrets(value) {
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (hasSensitiveField(key)) throw Object.assign(new Error("Protected sync attestation failed"), { code: "SYNC_ATTESTATION_FAILED" });
    assertNoProtectedSecrets(child);
  }
}

function expectedAad(record) {
  return canonicalJson({
    protocolVersion: record.protocolVersion,
    objectId: record.objectId,
    fileId: record.fileId,
    versionId: record.versionId,
    operation: record.operation,
    revision: record.revision,
    baseRevision: record.baseRevision || null,
    keyEpoch: record.keyEpoch,
    compartmentId: record.compartmentId,
    deviceId: record.deviceId,
    metadata: record.metadata,
    tombstone: record.tombstone,
  });
}

function attestCiphertextOnlyRecords(records) {
  if (!Array.isArray(records)) throw Object.assign(new Error("Protected sync attestation failed"), { code: "SYNC_ATTESTATION_FAILED" });
  for (const record of records) {
    assertNoProtectedSecrets(record);
    let normalized;
    try { normalized = validateOperation(record); } catch { throw Object.assign(new Error("Protected sync attestation failed"), { code: "SYNC_ATTESTATION_FAILED" }); }
    decodeBase64Url(normalized.ciphertext, "ciphertext");
    decodeBase64Url(normalized.nonce, "nonce");
    decodeBase64Url(normalized.tag, "tag");
    const aad = decodeBase64Url(normalized.aad, "aad").toString("utf8");
    if (aad !== expectedAad(normalized)) throw Object.assign(new Error("Protected sync attestation failed"), { code: "SYNC_ATTESTATION_FAILED" });
  }
  return { ok: true, count: records.length, digest: crypto.createHash("sha256").update(canonicalJson(stableValue(records))).digest("hex") };
}

function attestCiphertextOnlySyncState(state) {
  if (!state || ![1, 2].includes(state.version) || !state.users || typeof state.users !== "object") {
    throw Object.assign(new Error("Protected sync attestation failed"), { code: "SYNC_ATTESTATION_FAILED" });
  }
  const records = [];
  for (const user of Object.values(state.users)) {
    if (!user || typeof user !== "object" || !user.objects || typeof user.objects !== "object") {
      throw Object.assign(new Error("Protected sync attestation failed"), { code: "SYNC_ATTESTATION_FAILED" });
    }
    records.push(...Object.values(user.objects));
    for (const history of Object.values(user.versions || {})) {
      if (!Array.isArray(history)) throw Object.assign(new Error("Protected sync attestation failed"), { code: "SYNC_ATTESTATION_FAILED" });
      records.push(...history);
    }
  }
  return attestCiphertextOnlyRecords(records);
}

async function attestCiphertextOnlyArchive(zip) {
  const entry = zip.files.find((item) => item.path === "data/sync-objects.json");
  if (!entry) return { ok: true, count: 0, checked: false };
  let state;
  try { state = JSON.parse((await entry.buffer()).toString("utf8")); } catch { throw Object.assign(new Error("Protected sync attestation failed"), { code: "SYNC_ATTESTATION_FAILED" }); }
  return { ...attestCiphertextOnlySyncState(state), checked: true };
}

function attestCiphertextOnlyFile(filePath) {
  let state;
  try { state = JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { throw Object.assign(new Error("Protected sync attestation failed"), { code: "SYNC_ATTESTATION_FAILED" }); }
  return attestCiphertextOnlySyncState(state);
}

function validateMasterKey(env, masterKeyFile) {
  const configured = String(env.SERVER_MASTER_KEY || "").trim();
  const validBase64 = /^[A-Za-z0-9+/]+={0,2}$/.test(configured) && configured.length % 4 === 0 && Buffer.from(configured, "base64").length === 32;
  if (/^[a-f0-9]{64}$/i.test(configured) || validBase64) return true;
  if (!masterKeyFile || !fs.existsSync(masterKeyFile)) return false;
  try { return /^[a-f0-9]{64}$/i.test(fs.readFileSync(masterKeyFile, "utf8").trim()); } catch { return false; }
}

function isSessionCookieSecure(env = process.env) {
  if (env.SESSION_COOKIE_SECURE !== undefined) return env.SESSION_COOKIE_SECURE === "true";
  return env.NODE_ENV === "production";
}

function getDeploymentReadiness({ env = process.env, masterKeyFile, cloudStatus = {}, validateTotp } = {}) {
  const checks = {
    jwt: String(env.JWT_SECRET || "").length >= 32 && env.JWT_SECRET !== "rootark_secret_change_in_production",
    totp: Object.hasOwn(env, "TOTP_POLICY") && typeof validateTotp === "function",
    sessionCookie: isSessionCookieSecure(env),
    masterKey: validateMasterKey(env, masterKeyFile),
    provider: true,
  };
  try { if (checks.totp) validateTotp(env); } catch { checks.totp = false; }
  const provider = String(cloudStatus.provider || "local").toLowerCase();
  if (!["local", "s3", "gdrive"].includes(provider)) checks.provider = false;
  if (provider === "s3") checks.provider = Boolean(cloudStatus.s3?.bucketConfigured);
  if (provider === "gdrive") checks.provider = Boolean(cloudStatus.gdrive?.folderConfigured && cloudStatus.gdrive?.credentialsConfigured);
  return {
    ok: Object.values(checks).every(Boolean),
    checks: Object.fromEntries(Object.entries(checks).map(([key, value]) => [key, value ? "ok" : "missing_or_invalid"])),
    provider: { provider, enabled: Boolean(cloudStatus.enabled), configured: checks.provider },
  };
}

function registerReadinessRoutes(app, options = {}) {
  const getReadiness = options.getReadiness || (() => ({ ok: true, checks: {}, provider: { provider: "local", enabled: false, configured: true } }));
  app.get(options.healthPath || "/health", (_req, res) => res.status(200).json({ status: "ok", service: "rootark" }));
  app.get(options.readinessPath || "/ready", (_req, res) => {
    let readiness;
    try { readiness = getReadiness(); } catch { readiness = { ok: false, checks: { configuration: "unavailable" }, provider: { provider: "unknown", enabled: false, configured: false } }; }
    res.status(readiness.ok ? 200 : 503).json({ status: readiness.ok ? "ready" : "not_ready", ...readiness });
  });
}

module.exports = {
  attestCiphertextOnlyArchive,
  attestCiphertextOnlyFile,
  attestCiphertextOnlyRecords,
  attestCiphertextOnlySyncState,
  createIdempotencyKey,
  getDeploymentReadiness,
  isSessionCookieSecure,
  normalizeProviderError,
  registerReadinessRoutes,
  retryWithBackoff,
  runIdempotent,
  sanitizeLogValue,
  sanitizeMetricLabels,
};
