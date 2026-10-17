"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");
const { PROTOCOL_VERSION, compareRevisions, validateOperation } = require("../../sync-client/rootark-sync-protocol");
const { verifyAuthorizationProof } = require("../../sync-client/rootark-sync-authorization");
const { attestCiphertextOnlySyncState } = require("../services/deploymentResilience");
const { createSyncBurstGuard } = require("../services/syncBurstGuard");

const STORE_VERSION = 2;
const MAX_HISTORY_PER_OBJECT = 32;
const MAX_SEEN_OPERATIONS = 10000;
const MAX_REQUEST_BYTES = 9 * 1024 * 1024;
const MAX_CIPHERTEXT_BYTES = 8 * 1024 * 1024;
const WINDOWS_RENAME_MAX_ATTEMPTS = 3;
const WINDOWS_RENAME_RETRY_DELAY_MS = 10;

function isUnsupportedDirectorySync(error) {
  return ["EINVAL", "ENOTSUP"].includes(error?.code)
    || (process.platform === "win32" && error?.code === "EPERM");
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await fs.open(directory, "r");
    await handle.sync();
  } catch (error) {
    if (!isUnsupportedDirectorySync(error)) throw error;
  } finally {
    if (handle) await handle.close();
  }
}

async function renameWithRetry(source, destination) {
  for (let attempt = 1; attempt <= WINDOWS_RENAME_MAX_ATTEMPTS; attempt += 1) {
    try {
      await fs.rename(source, destination);
      return;
    } catch (error) {
      if (process.platform !== "win32" || error?.code !== "EPERM" || attempt === WINDOWS_RENAME_MAX_ATTEMPTS) throw error;
      await new Promise((resolve) => setTimeout(resolve, WINDOWS_RENAME_RETRY_DELAY_MS));
    }
  }
}

function errorResponse(res, status, error, extra = {}) {
  return res.status(status).json({ error, ...extra });
}

async function durableWrite(filePath, value) {
  const directory = path.dirname(filePath);
  await fs.mkdir(directory, { recursive: true });
  const temporary = `${filePath}.tmp-${process.pid}-${Math.random().toString(16).slice(2)}`;
  const handle = await fs.open(temporary, "w", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await renameWithRetry(temporary, filePath);
  } catch (error) {
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
  await syncDirectory(directory);
}

function publicRecord(record) {
  return {
    protocolVersion: record.protocolVersion,
    operationId: record.operationId,
    objectId: record.objectId,
    fileId: record.fileId,
    versionId: record.versionId,
    operation: record.operation,
    revision: record.revision,
    baseRevision: record.baseRevision,
    keyEpoch: record.keyEpoch,
    compartmentId: record.compartmentId,
    deviceId: record.deviceId,
    metadata: record.metadata,
    tombstone: Boolean(record.tombstone),
    ciphertext: record.ciphertext ?? null,
    nonce: record.nonce ?? null,
    tag: record.tag ?? null,
    aad: record.aad ?? null,
    ...(record.authorization ? { authorization: record.authorization } : {}),
  };
}

class SyncObjectStore {
  constructor(filePath, { burstGuard = createSyncBurstGuard() } = {}) {
    this.filePath = path.resolve(filePath);
    this.state = { version: STORE_VERSION, users: {} };
    this.queue = Promise.resolve();
    this.burstGuard = burstGuard;
  }

  async open() {
    try {
      this.state = JSON.parse(await fs.readFile(this.filePath, "utf8"));
      if (![1, STORE_VERSION].includes(this.state.version) || !this.state.users || typeof this.state.users !== "object") throw new Error("Invalid sync object store");
      if (this.state.version === 1) {
        this.state.version = STORE_VERSION;
        for (const user of Object.values(this.state.users)) {
          user.versions ||= {};
          user.revisions ||= {};
          user.seen ||= {};
          for (const [objectId, record] of Object.entries(user.objects || {})) {
            user.versions[objectId] ||= [record];
            user.revisions[objectId] ||= record.revision;
          }
        }
        await durableWrite(this.filePath, this.state);
      }
      attestCiphertextOnlySyncState(this.state);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await durableWrite(this.filePath, this.state);
    }
    return this;
  }

  async transact(mutator) {
    let result;
    this.queue = this.queue.then(async () => {
      const next = JSON.parse(JSON.stringify(this.state));
      result = await mutator(next);
      await durableWrite(this.filePath, next);
      this.state = next;
    });
    await this.queue;
    return result;
  }

  user(next, username) {
    const current = next.users[username] || { objects: {}, versions: {}, revisions: {}, seen: {} };
    current.objects ||= {};
    current.versions ||= {};
    current.revisions ||= {};
    current.seen ||= {};
    next.users[username] = current;
    return current;
  }

  async put(username, input) {
    return this.transact((next) => {
      const user = this.user(next, username);
      if (user.seen[input.operationId]) return { kind: "replay", record: null };
      const current = user.objects[input.objectId] || null;
      // Destructive = delete, or any non-create operation that replaces an existing object's state.
      const destructive = Boolean(input.tombstone) || input.operation === "delete" || (input.operation !== "create" && Boolean(current));
      if (destructive && user.pausedDevices?.[input.deviceId]) return { kind: "paused", newlyPaused: false, deviceId: input.deviceId };
      if (input.operation === "create" && current) return { kind: "conflict", current };
      if (input.operation !== "create" && !current) return { kind: "conflict", current: null };
      if (current && input.baseRevision && compareRevisions(input.baseRevision, current.revision) !== 0) return { kind: "conflict", current };
      if (current && !input.baseRevision) return { kind: "conflict", current };
      if (current && compareRevisions(input.revision, current.revision) <= 0) return { kind: "stale", current };
      if (destructive) {
        const burst = this.burstGuard.recordDestructive(username, input.deviceId);
        if (burst.exceeded) {
          user.pausedDevices ||= {};
          user.pausedDevices[input.deviceId] = { pausedAt: new Date().toISOString(), reason: "destructive_burst", limit: burst.limit, windowMs: burst.windowMs };
          return { kind: "paused", newlyPaused: true, deviceId: input.deviceId, limit: burst.limit, windowMs: burst.windowMs };
        }
      }
      const record = publicRecord(input);
      user.objects[input.objectId] = record;
      user.versions[input.objectId] = [...(user.versions[input.objectId] || []), record].slice(-MAX_HISTORY_PER_OBJECT);
      user.revisions[input.objectId] = input.revision;
      user.seen[input.operationId] = true;
      const seenIds = Object.keys(user.seen);
      for (const oldId of seenIds.slice(0, Math.max(0, seenIds.length - MAX_SEEN_OPERATIONS))) delete user.seen[oldId];
      return { kind: "stored", record };
    });
  }

  async resumeDevice(username, deviceId) {
    let wasPaused = false;
    await this.transact((next) => {
      const user = this.user(next, username);
      wasPaused = Boolean(user.pausedDevices?.[deviceId]);
      if (wasPaused) delete user.pausedDevices[deviceId];
      return wasPaused;
    });
    this.burstGuard.reset(username, deviceId);
    return { wasPaused };
  }

  isDevicePaused(username, deviceId) {
    return Boolean(this.state.users[username]?.pausedDevices?.[deviceId]);
  }

  list(username, objectId = null) {
    const user = this.state.users[username] || { objects: {} };
    if (objectId) return user.objects[objectId] ? [publicRecord(user.objects[objectId])] : [];
    return Object.values(user.objects).map(publicRecord);
  }

  history(username, objectId) {
    const user = this.state.users[username] || { versions: {} };
    return (user.versions?.[objectId] || []).map(publicRecord);
  }
}

const MAX_DEVICE_ID_LENGTH = 256;
const RESUME_MAX_FAILED_ATTEMPTS = 5;
const RESUME_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const RESUME_TRACKED_USERS_MAX = 10000;
// Same public placeholder hash used by the auth route so unknown users cost one bcrypt compare too.
const DUMMY_PASSWORD_HASH = "$2a$10$C8U56P8wZK.G7zWKmqF88e3f64PIxJ1xdTJN9WxiHcSVkYCfaSeDG";

function registerSyncRoutes({ app, authenticate, requirePermission, storagePath = process.env.SYNC_OBJECTS_FILE || "./data/sync-objects.json", deviceAuthorization = null, requireDeviceAuthorization = false, deviceRegistryPath = process.env.SYNC_DEVICE_REGISTRY || "", burstGuard = null, auditLog = null, bcrypt = null, loadUsers = null }) {
  const audit = (eventType, req, deviceId, action, result, details = {}) => {
    if (typeof auditLog !== "function") return;
    auditLog(eventType, { username: req.user?.username, role: req.user?.role }, { type: "sync_device", id: String(deviceId).slice(0, 200) }, action, result, details);
  };
  // In-memory, per-user resume re-authentication limiter. `count` is confirmed wrong passwords;
  // `pending` is password checks in flight. Both count toward the limit, and a reservation is taken
  // synchronously before any await, so parallel requests cannot all pass the check.
  const resumeFailures = new Map();
  const reserveResumeAttempt = (username) => {
    const now = Date.now();
    let state = resumeFailures.get(username);
    if (state && now - state.windowStart >= RESUME_ATTEMPT_WINDOW_MS) { resumeFailures.delete(username); state = null; }
    if (state && state.count + state.pending >= RESUME_MAX_FAILED_ATTEMPTS) {
      return { state: null, retryAfter: Math.ceil((state.windowStart + RESUME_ATTEMPT_WINDOW_MS - now) / 1000) };
    }
    if (!state) {
      if (resumeFailures.size >= RESUME_TRACKED_USERS_MAX) resumeFailures.delete(resumeFailures.keys().next().value);
      state = { count: 0, pending: 0, windowStart: now };
      resumeFailures.set(username, state);
    }
    state.pending += 1;
    return { state, retryAfter: 0 };
  };
  const verifyRegisteredDevice = deviceAuthorization || (deviceRegistryPath ? async ({ username, operation, proof }) => {
    let registry;
    try { registry = JSON.parse(await fs.readFile(deviceRegistryPath, "utf8")); } catch { return false; }
    const record = registry?.devices?.[operation.deviceId];
    if (!record || record.username !== username || record.revoked || record.active === false || record.publicKey !== proof.publicKey) return false;
    return verifyAuthorizationProof(proof, operation, { username });
  } : null);
  const store = new SyncObjectStore(storagePath, { burstGuard: burstGuard || createSyncBurstGuard() });
  const ready = store.open();
  const sizeGuard = (req, res, next) => {
    const length = Number(req.headers["content-length"]);
    if (Number.isSafeInteger(length) && length > MAX_REQUEST_BYTES) return errorResponse(res, 413, "Sync payload too large");
    next();
  };
  const write = async (req, res, input) => {
    await ready;
    const payload = input === undefined ? req.body : input;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) return errorResponse(res, 400, "Invalid sync payload");
    if (Object.hasOwn(payload, "plaintext") || Object.hasOwn(payload, "fileKey")) return errorResponse(res, 400, "Plaintext and keys are not accepted");
    if (typeof payload.ciphertext === "string" && Buffer.byteLength(payload.ciphertext, "base64url") > MAX_CIPHERTEXT_BYTES) return errorResponse(res, 413, "Ciphertext too large");
    let operation;
    try { operation = validateOperation(payload); } catch (error) { return errorResponse(res, error.code === "payload_too_large" ? 413 : error.code?.startsWith("authorization") ? 403 : 400, "Invalid sync operation"); }
    if (requireDeviceAuthorization || verifyRegisteredDevice) {
      if (typeof verifyRegisteredDevice !== "function" || !operation.authorization) return errorResponse(res, 403, "Sync device authorization required");
      try {
        if (await verifyRegisteredDevice({ username: req.user.username, operation, proof: operation.authorization }) !== true) return errorResponse(res, 403, "Sync device authorization rejected");
      } catch { return errorResponse(res, 403, "Sync device authorization rejected"); }
    }
    const result = await store.put(req.user.username, operation);
    if (result.kind === "paused") {
      if (result.newlyPaused) audit("sync.burst.paused", req, result.deviceId, "paused", "partial", { limit: result.limit, windowMs: result.windowMs });
      return errorResponse(res, 423, "sync_burst_paused", { code: "sync_burst_paused", deviceId: result.deviceId });
    }
    if (result.kind === "replay") return errorResponse(res, 409, "Replay rejected");
    if (result.kind === "stale") return errorResponse(res, 409, "Stale revision rejected", { currentRevision: result.current.revision, current: publicRecord(result.current) });
    if (result.kind === "conflict") return errorResponse(res, 409, "Base revision conflict", { currentRevision: result.current?.revision || null, current: result.current ? publicRecord(result.current) : null });
    return res.status(req.method === "POST" ? 201 : 200).json(publicRecord(result.record));
  };

  app.get("/sync/v1/objects", authenticate, requirePermission("listFiles"), async (req, res) => {
    await ready;
    res.json({ protocolVersion: PROTOCOL_VERSION, objects: store.list(req.user.username, req.query.objectId ? String(req.query.objectId) : null) });
  });
  app.get("/sync/v1/objects/:objectId", authenticate, requirePermission("listFiles"), async (req, res) => {
    await ready;
    const objects = store.list(req.user.username, req.params.objectId);
    if (!objects.length) return errorResponse(res, 404, "Sync object not found");
    res.json(objects[0]);
  });
  app.post("/sync/v1/objects", sizeGuard, authenticate, requirePermission("upload"), (req, res) => write(req, res));
  app.put("/sync/v1/objects/:objectId", sizeGuard, authenticate, requirePermission("upload"), (req, res) => {
    if (req.body?.objectId && req.body.objectId !== req.params.objectId) return errorResponse(res, 400, "Object id mismatch");
    return write(req, res);
  });
  app.delete("/sync/v1/objects/:objectId", sizeGuard, authenticate, requirePermission("upload"), (req, res) => {
    if (req.body?.objectId && req.body.objectId !== req.params.objectId) return errorResponse(res, 400, "Object id mismatch");
    return write(req, res, { ...req.body, objectId: req.params.objectId, operation: "delete", tombstone: true });
  });
  app.post("/sync/v1/devices/:deviceId/resume", authenticate, requirePermission("upload"), async (req, res) => {
    await ready;
    const deviceId = req.params.deviceId;
    if (!deviceId || deviceId.length > MAX_DEVICE_ID_LENGTH) return errorResponse(res, 400, "Invalid sync device id");
    const username = req.user.username;
    const body = req.body && typeof req.body === "object" ? req.body : {};
    // Convenience check only, NOT a security boundary: the caller declares its device in the body, which a
    // compromised device can omit or forge. The password re-authentication below is the actual barrier.
    if (typeof body.deviceId === "string" && body.deviceId === deviceId) {
      audit("sync.device.resume.failed", req, deviceId, "resume", "failure", { reason: "self_resume" });
      return errorResponse(res, 403, "Paused device cannot resume itself");
    }
    if (!bcrypt || typeof loadUsers !== "function") return errorResponse(res, 503, "Sync re-authentication unavailable");
    if (typeof body.password !== "string" || !body.password) return errorResponse(res, 400, "Password required");
    // Reserve synchronously (no await since the limit check): concurrent requests see this reservation.
    const reservation = reserveResumeAttempt(username);
    if (reservation.retryAfter) {
      res.setHeader("Retry-After", String(reservation.retryAfter));
      return errorResponse(res, 429, "Too many failed re-authentication attempts");
    }
    const state = reservation.state;
    try {
      const users = await loadUsers();
      const user = Array.isArray(users) ? users.find((entry) => entry?.username === username) : null;
      const hasPassword = Boolean(user && !user.disabled && typeof user.password === "string" && user.password);
      const matches = await bcrypt.compare(body.password, hasPassword ? user.password : DUMMY_PASSWORD_HASH);
      if (!hasPassword || !matches) {
        state.count += 1;
        audit("sync.device.resume.failed", req, deviceId, "resume", "failure", { reason: "reauth_failed" });
        return errorResponse(res, 401, "Re-authentication failed");
      }
      state.count = 0;
      const { wasPaused } = await store.resumeDevice(username, deviceId);
      if (wasPaused) audit("sync.device.resumed", req, deviceId, "resumed", "success", {});
      return res.json({ protocolVersion: PROTOCOL_VERSION, deviceId, paused: false, wasPaused });
    } finally {
      // Releases the reservation. An internal error is not counted as a wrong password.
      state.pending -= 1;
    }
  });
  return { store, ready };
}

module.exports = { MAX_CIPHERTEXT_BYTES, MAX_REQUEST_BYTES, SyncObjectStore, registerSyncRoutes };
