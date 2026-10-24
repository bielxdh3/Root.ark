"use strict";

const fs = require("node:fs/promises");
const crypto = require("node:crypto");
const path = require("node:path");
const { PROTOCOL_VERSION, compareRevisions, validateOperation } = require("../../sync-client/rootark-sync-protocol");
const { verifyAuthorizationProof } = require("../../sync-client/rootark-sync-authorization");
const { attestCiphertextOnlySyncState } = require("../services/deploymentResilience");
const { createSyncBurstGuard } = require("../services/syncBurstGuard");
const { DEFAULT_WINDOW, decryptSecret, normalizeOtp, verifyRecoveryCodeAsync, verifyTotp } = require("../services/totp");
const { authorizationDigest } = require("../services/syncResumeAccountProof");

const STORE_VERSION = 2;
const MAX_HISTORY_PER_OBJECT = 32;
const MAX_SEEN_OPERATIONS = 10000;
const MAX_REQUEST_BYTES = 9 * 1024 * 1024;
const MAX_CIPHERTEXT_BYTES = 8 * 1024 * 1024;
const WINDOWS_RENAME_MAX_ATTEMPTS = 3;
const WINDOWS_RENAME_RETRY_DELAY_MS = 10;
const SYNC_LOCK_WAIT_MS = 2000;

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

function indeterminateCommitError() {
  const error = new Error("Sync commit state is indeterminate; restart and verify disk state before continuing");
  error.code = "SYNC_COMMIT_INDETERMINATE";
  return error;
}

// JSON records are ordinary objects after JSON.parse: reserved account,
// operation, and object identifiers must never resolve inherited properties
// or invoke the __proto__ setter while persisting tenant-owned entries.
function ownRecord(record, key) {
  return record && Object.hasOwn(record, key) ? record[key] : undefined;
}
function setOwnRecord(record, key, value) {
  Object.defineProperty(record, key, {
    value, enumerable: true, configurable: true, writable: true,
  });
}
function ensureOwnMap(record, key) {
  let value = ownRecord(record, key);
  if (!value) {
    value = {};
    setOwnRecord(record, key, value);
  }
  return value;
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
  try {
    await syncDirectory(directory);
  } catch (error) {
    // rename() already replaced the destination. The new contents may be
    // visible even though the directory durability barrier was not confirmed.
    // Never schedule a write from the previous in-memory state over them.
    const ambiguous = new Error("Sync commit may have been renamed without a durable directory barrier", { cause: error });
    ambiguous.code = error?.code || "SYNC_COMMIT_INDETERMINATE";
    ambiguous.syncCommitIndeterminate = true;
    throw ambiguous;
  }
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

const DEFAULT_RECOVERY_RETENTION_MS = 24 * 60 * 60 * 1000;

// Async, non-mutating proof verification. The proof is committed against freshly loaded user data after
// scrypt completes so concurrent resume requests cannot both consume the same TOTP step or recovery code.
async function verifySecondFactor(user, code, key) {
  const otp = normalizeOtp(code);
  if (otp) {
    const secret = decryptSecret(user.totpSecret, key, `Root.ark/TOTP/${user.username}`);
    const step = verifyTotp(secret, otp, { window: DEFAULT_WINDOW });
    if (step === null || (Number.isSafeInteger(user.totpLastUsedStep) && step <= user.totpLastUsedStep)) return null;
    return { type: "totp", step, secretRecord: JSON.stringify(user.totpSecret) };
  }
  if (!Array.isArray(user.totpRecoveryHashes)) return null;
  for (const hash of [...user.totpRecoveryHashes]) {
    if (await verifyRecoveryCodeAsync(code, hash)) return { type: "recovery", hash };
  }
  return null;
}

// Synchronous single-use enforcement on the fresh user record immediately before persistence.
function commitSecondFactorProof(target, proof) {
  if (!target || !proof) return false;
  if (proof.type === "totp") {
    if (JSON.stringify(target.totpSecret) !== proof.secretRecord) return false;
    if (Number.isSafeInteger(target.totpLastUsedStep) && proof.step <= target.totpLastUsedStep) return false;
    target.totpLastUsedStep = proof.step;
    return true;
  }
  if (proof.type === "recovery") {
    if (!Array.isArray(target.totpRecoveryHashes)) return false;
    const index = target.totpRecoveryHashes.indexOf(proof.hash);
    if (index === -1) return false;
    target.totpRecoveryHashes.splice(index, 1);
    return true;
  }
  return false;
}

// The sync store and the account store are distinct durable files. A verified factor
// must first acquire an immutable, MAC-bound resume intent in the sync store. If
// account persistence succeeds but the final sync write fails, the SAME factor can
// complete this specific pause after restart; it cannot authorize a later pause.
function resumeCodeMac(key, username, deviceId, pauseFence, code, intent) {
  return crypto.createHmac("sha256", key)
    .update("Root.ark/sync-resume-intent/v1\0")
    .update(JSON.stringify([username, deviceId, pauseFence, code,
      intent.version, intent.passwordHash, intent.sessionVersion, intent.secretDigest,
      intent.authorizationDigest,
      intent.proof, intent.expectedReplayDigest]))
    .digest("hex");
}

function equalMac(left, right) {
  return typeof left === "string" && typeof right === "string"
    && /^[0-9a-f]{64}$/.test(left) && /^[0-9a-f]{64}$/.test(right)
    && crypto.timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function secondFactorReplayDigest(user) {
  return crypto.createHash("sha256").update(JSON.stringify([
    user.totpRecoveryHashes, user.totpLastUsedStep ?? null, user.totpSecret,
  ])).digest("hex");
}

function positiveEnvInteger(value, fallback) {
  const number = Number(value);
  return value !== undefined && value !== "" && Number.isSafeInteger(number) && number > 0 ? number : fallback;
}

// Pause keys carry a prefix so client-supplied device ids (e.g. "constructor", "__proto__") never hit Object.prototype.
function pausedKey(deviceId) {
  return `d:${String(deviceId)}`;
}

function isPausedDevice(user, deviceId) {
  const pausedDevices = ownRecord(user, "pausedDevices");
  return Boolean(pausedDevices && Object.hasOwn(pausedDevices, pausedKey(deviceId)));
}

// Keeps the newest cap-1 versions plus the newest pre-window checkpoint (the last version whose store time is
// older than the retention cutoff). Versions created by a currently paused device are never pruned.
// `times` is a parallel array of store timestamps kept outside the records (records are attested strictly).
function pruneObjectHistory(history, times, cutoff, pausedDevices) {
  if (history.length <= MAX_HISTORY_PER_OBJECT) return { versions: history, times };
  const recentStart = history.length - (MAX_HISTORY_PER_OBJECT - 1);
  // Anchor: newest version older than the retention window; if every version is inside the window,
  // the oldest version in history (so the earliest recovery point is never dropped).
  let checkpoint = -1;
  for (let index = recentStart - 1; index >= 0; index -= 1) {
    if (times[index] < cutoff) { checkpoint = index; break; }
  }
  if (checkpoint === -1) checkpoint = 0;
  const keep = (index) => index >= recentStart || index === checkpoint || Object.hasOwn(pausedDevices, pausedKey(history[index].deviceId));
  return {
    versions: history.filter((_, index) => keep(index)),
    times: times.filter((_, index) => keep(index)),
  };
}

class SyncObjectStore {
  constructor(filePath, { burstGuard = createSyncBurstGuard(), retentionMs = DEFAULT_RECOVERY_RETENTION_MS, now = () => Date.now() } = {}) {
    this.filePath = path.resolve(filePath);
    this.state = { version: STORE_VERSION, users: {} };
    this.queue = Promise.resolve();
    this.commitIndeterminate = false;
    this.burstGuard = burstGuard;
    this.retentionMs = retentionMs;
    this.now = now;
  }

  // Exclusive-create on the SAME local filesystem fences independent Node
  // processes. Never break an orphaned lock automatically: doing so after a
  // slow fsync or suspend would reintroduce split-brain writes. A crashed
  // writer therefore requires explicit operator recovery and remains NO-GO.
  async withWriteLock(callback) {
    const lockPath = `${this.filePath}.writer-lock`;
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    const deadline = Date.now() + SYNC_LOCK_WAIT_MS;
    let handle;
    while (!handle) {
      try {
        handle = await fs.open(lockPath, "wx", 0o600);
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        if (Date.now() >= deadline) {
          throw Object.assign(new Error("Independent sync writer lock is busy or orphaned"), { code: "SYNC_STORE_LOCK_BUSY" });
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    }
    try {
      return await callback();
    } finally {
      try {
        await handle.close();
        await fs.unlink(lockPath);
      } catch (error) {
        this.commitIndeterminate = true;
        throw new Error("Sync writer lock release failed; restart and investigate before writing", { cause: error });
      }
    }
  }

  async readCurrentState() {
    const current = JSON.parse(await fs.readFile(this.filePath, "utf8"));
    if (![1, STORE_VERSION].includes(current.version) || !current.users || typeof current.users !== "object" || Array.isArray(current.users)) {
      throw new Error("Invalid sync object store");
    }
    attestCiphertextOnlySyncState(current);
    return current;
  }

  async open() {
    await this.withWriteLock(async () => {
      try {
        this.state = await this.readCurrentState();
        if (this.state.version === 1) {
          this.state.version = STORE_VERSION;
          for (const user of Object.values(this.state.users)) {
            const objects = ensureOwnMap(user, "objects");
            const versions = ensureOwnMap(user, "versions");
            const revisions = ensureOwnMap(user, "revisions");
            ensureOwnMap(user, "seen");
            for (const [objectId, record] of Object.entries(objects)) {
              if (!ownRecord(versions, objectId)) setOwnRecord(versions, objectId, [record]);
              if (!ownRecord(revisions, objectId)) setOwnRecord(revisions, objectId, record.revision);
            }
          }
          await durableWrite(this.filePath, this.state);
        }
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
        await durableWrite(this.filePath, this.state);
      }
    });
    return this;
  }

  async transact(mutator) {
    let result;
    // A failed mutator or fsync must reject its own caller, but must not
    // permanently poison every later transaction on this store instance.
    // State advances only after durableWrite succeeds; recover only the
    // scheduling chain, never the failed mutation or its result.
    this.queue = this.queue.catch(() => {}).then(async () => {
      if (this.commitIndeterminate) throw indeterminateCommitError();
      await this.withWriteLock(async () => {
        // Refresh *inside* the process-external lock: a sibling may have
        // advanced pause fences, committed resume intents or object revisions.
        const next = JSON.parse(JSON.stringify(await this.readCurrentState()));
        result = await mutator(next);
        try {
          await durableWrite(this.filePath, next);
        } catch (error) {
          if (error?.syncCommitIndeterminate === true) this.commitIndeterminate = true;
          throw error;
        }
        this.state = next;
      });
    });
    await this.queue;
    return result;
  }

  async assertWritable() {
    // Exercise the SAME queued durable-rename/fsync path used by resumeDevice.
    // A mere commitIndeterminate check misses an already locked/read-only store.
    await this.transact(() => undefined);
  }

  user(next, username) {
    const current = ownRecord(next.users, username)
      || { objects: {}, versions: {}, revisions: {}, seen: {} };
    for (const key of ["objects", "versions", "revisions", "seen", "versionTimes"]) ensureOwnMap(current, key);
    setOwnRecord(next.users, username, current);
    return current;
  }

  async put(username, input) {
    return this.transact((next) => {
      const at = this.now();
      const user = this.user(next, username);
      if (ownRecord(user.seen, input.operationId)) return { kind: "replay", record: null };
      const current = ownRecord(user.objects, input.objectId) || null;
      // Destructive = delete, or any non-create operation that replaces an existing object's state.
      const destructive = Boolean(input.tombstone) || input.operation === "delete" || (input.operation !== "create" && Boolean(current));
      if (destructive && isPausedDevice(user, input.deviceId)) return { kind: "paused", newlyPaused: false, deviceId: input.deviceId };
      if (input.operation === "create" && current) return { kind: "conflict", current };
      if (input.operation !== "create" && !current) return { kind: "conflict", current: null };
      if (current && input.baseRevision && compareRevisions(input.baseRevision, current.revision) !== 0) return { kind: "conflict", current };
      if (current && !input.baseRevision) return { kind: "conflict", current };
      if (current && compareRevisions(input.revision, current.revision) <= 0) return { kind: "stale", current };
      if (destructive) {
        const burst = this.burstGuard.recordDestructive(username, input.deviceId, input.objectId, at);
        if (burst.exceeded) {
          ensureOwnMap(user, "pausedDevices");
          user.pausedDevices[pausedKey(input.deviceId)] = { pausedAt: new Date(at).toISOString(), pauseNonce: crypto.randomUUID(), reason: burst.objectExceeded ? "object_burst" : "destructive_burst", limit: burst.limit, windowMs: burst.windowMs };
          return { kind: "paused", newlyPaused: true, deviceId: input.deviceId, limit: burst.limit, windowMs: burst.windowMs, objectLimit: burst.objectLimit };
        }
      }
      const record = publicRecord(input);
      setOwnRecord(user.objects, input.objectId, record);
      // Legacy history without timestamps is padded with 0 (treated as older than any retention cutoff).
      const previousVersions = ownRecord(user.versions, input.objectId) || [];
      const previousTimes = ownRecord(user.versionTimes, input.objectId) || [];
      const padding = Array(Math.max(0, previousVersions.length - previousTimes.length)).fill(0);
      const pruned = pruneObjectHistory([...previousVersions, record], [...padding, ...previousTimes, at], at - this.retentionMs, ownRecord(user, "pausedDevices") || {});
      setOwnRecord(user.versions, input.objectId, pruned.versions);
      user.versionTimes ||= {};
      setOwnRecord(user.versionTimes, input.objectId, pruned.times);
      setOwnRecord(user.revisions, input.objectId, input.revision);
      setOwnRecord(user.seen, input.operationId, true);
      const seenIds = Object.keys(user.seen);
      for (const oldId of seenIds.slice(0, Math.max(0, seenIds.length - MAX_SEEN_OPERATIONS))) delete user.seen[oldId];
      return { kind: "stored", record };
    });
  }

  async resumeDevice(username, deviceId) {
    let wasPaused = false;
    await this.transact((next) => {
      const user = this.user(next, username);
      wasPaused = isPausedDevice(user, deviceId);
      if (wasPaused) delete user.pausedDevices[pausedKey(deviceId)];
      return wasPaused;
    });
    this.burstGuard.reset(username, deviceId);
    return { wasPaused };
  }

  pauseFence(username, deviceId) {
    if (this.commitIndeterminate) throw indeterminateCommitError();
    const user = ownRecord(this.state.users, username) || {};
    const pause = ownRecord(ownRecord(user, "pausedDevices"), pausedKey(deviceId));
    return pause ? (pause.pauseNonce || JSON.stringify(pause)) : null;
  }

  pendingResume(username) {
    if (this.commitIndeterminate) throw indeterminateCommitError();
    return ownRecord(ownRecord(this.state.users, username), "resumeIntent") || null;
  }

  async stageResume(username, intent) {
    return this.transact((next) => {
      const user = this.user(next, username);
      if (ownRecord(user, "resumeIntent")) {
        throw Object.assign(new Error("A sync resume intent is already pending"), { code: "SYNC_RESUME_PENDING" });
      }
      const pause = ownRecord(user.pausedDevices, pausedKey(intent.deviceId));
      const fence = pause ? (pause.pauseNonce || JSON.stringify(pause)) : null;
      if (fence !== intent.pauseFence) throw new Error("Sync pause changed during resume");
      user.resumeIntent = intent;
    });
  }

  async finishStagedResume(username, intent) {
    let wasPaused = false;
    await this.transact((next) => {
      const user = this.user(next, username);
      const current = ownRecord(user, "resumeIntent");
      if (!current || !equalMac(current.codeMac, intent.codeMac)
        || current.deviceId !== intent.deviceId || current.pauseFence !== intent.pauseFence) {
        throw new Error("Sync resume intent mismatch");
      }
      const pause = ownRecord(user.pausedDevices, pausedKey(intent.deviceId));
      const fence = pause ? (pause.pauseNonce || JSON.stringify(pause)) : null;
      if (fence !== intent.pauseFence) throw new Error("Sync pause changed before finalization");
      wasPaused = Boolean(pause);
      if (wasPaused) delete user.pausedDevices[pausedKey(intent.deviceId)];
      delete user.resumeIntent;
    });
    this.burstGuard.reset(username, intent.deviceId);
    return { wasPaused };
  }

  isDevicePaused(username, deviceId) {
    if (this.commitIndeterminate) throw indeterminateCommitError();
    return isPausedDevice(ownRecord(this.state.users, username) || {}, deviceId);
  }

  list(username, objectId = null) {
    if (this.commitIndeterminate) throw indeterminateCommitError();
    const user = ownRecord(this.state.users, username) || { objects: {} };
    const objects = ownRecord(user, "objects") || {};
    if (objectId) {
      const record = ownRecord(objects, objectId);
      return record ? [publicRecord(record)] : [];
    }
    return Object.values(objects).map(publicRecord);
  }

  history(username, objectId) {
    if (this.commitIndeterminate) throw indeterminateCommitError();
    const user = ownRecord(this.state.users, username) || { versions: {} };
    const versions = ownRecord(user, "versions") || {};
    return (ownRecord(versions, objectId) || []).map(publicRecord);
  }
}

const MAX_DEVICE_ID_LENGTH = 256;
const RESUME_MAX_FAILED_ATTEMPTS = 5;
const RESUME_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const RESUME_TRACKED_USERS_MAX = 10000;
// Same public placeholder hash used by the auth route so unknown users cost one bcrypt compare too.
const DUMMY_PASSWORD_HASH = "$2a$10$C8U56P8wZK.G7zWKmqF88e3f64PIxJ1xdTJN9WxiHcSVkYCfaSeDG";

function registerSyncRoutes({ app, authenticate, requirePermission, storagePath = process.env.SYNC_OBJECTS_FILE || "./data/sync-objects.json", deviceAuthorization = null, requireDeviceAuthorization = false, deviceRegistryPath = process.env.SYNC_DEVICE_REGISTRY || "", burstGuard = null, auditLog = null, bcrypt = null, loadUsers = null, saveUsers = null, commitSyncResumeProof = null, getTotpKey = null }) {
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
  const findUser = async (username) => {
    const users = await loadUsers();
    return Array.isArray(users) ? users.find((entry) => entry?.username === username) || null : null;
  };
  const verifyRegisteredDevice = deviceAuthorization ||(deviceRegistryPath ? async ({ username, operation, proof }) => {
    let registry;
    try { registry = JSON.parse(await fs.readFile(deviceRegistryPath, "utf8")); } catch { return false; }
    const record = registry?.devices?.[operation.deviceId];
    if (!record || record.username !== username || record.revoked || record.active === false || record.publicKey !== proof.publicKey) return false;
    return verifyAuthorizationProof(proof, operation, {
      username, trustedDevicePublicKeys: { [operation.deviceId]: record.publicKey },
    });
  } : null);
  const retentionMs = positiveEnvInteger(process.env.SYNC_RECOVERY_RETENTION_MS, DEFAULT_RECOVERY_RETENTION_MS);
  const store = new SyncObjectStore(storagePath, { burstGuard: burstGuard || createSyncBurstGuard(), retentionMs });
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
    let result;
    try {
      result = await store.put(req.user.username, operation);
    } catch (error) {
      if (error?.code === "SYNC_COMMIT_INDETERMINATE" || store.commitIndeterminate) {
        return errorResponse(res, 503, "sync_commit_indeterminate", { code: "SYNC_COMMIT_INDETERMINATE" });
      }
      throw error;
    }
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
    if (store.commitIndeterminate) return errorResponse(res, 503, "sync_commit_indeterminate", { code: "SYNC_COMMIT_INDETERMINATE" });
    res.json({ protocolVersion: PROTOCOL_VERSION, objects: store.list(req.user.username, req.query.objectId ? String(req.query.objectId) : null) });
  });
  app.get("/sync/v1/objects/:objectId", authenticate, requirePermission("listFiles"), async (req, res) => {
    await ready;
    if (store.commitIndeterminate) return errorResponse(res, 503, "sync_commit_indeterminate", { code: "SYNC_COMMIT_INDETERMINATE" });
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
    if (store.commitIndeterminate) return errorResponse(res, 503, "sync_commit_indeterminate", { code: "SYNC_COMMIT_INDETERMINATE" });
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
    const fail = (reason) => {
      state.count += 1;
      audit("sync.device.resume.failed", req, deviceId, "resume", "failure", { reason });
      return errorResponse(res, 401, "Re-authentication failed");
    };
    try {
      const snapshot = await findUser(username);
      const hasPassword = Boolean(snapshot && !snapshot.disabled && typeof snapshot.password === "string" && snapshot.password);
      const matches = await bcrypt.compare(body.password, hasPassword ? snapshot.password : DUMMY_PASSWORD_HASH);
      if (store.commitIndeterminate) return errorResponse(res, 503, "sync_commit_indeterminate", { code: "SYNC_COMMIT_INDETERMINATE" });
      if (!hasPassword || !matches) return fail("reauth_failed");
      const checkedHash = snapshot.password;
      const checkedSessionVersion = snapshot.sessionVersion || 0;
      // Re-load after the awaits above and revalidate; the account may have changed meanwhile.
      const users = loadUsers();
      const user = Array.isArray(users) ? users.find((entry) => entry?.username === username) : null;
      if (!user || user.disabled || user.password !== checkedHash || (user.sessionVersion || 0) !== checkedSessionVersion) {
        return errorResponse(res, 401, "Re-authentication failed");
      }
      let stagedResume = null;
      if (user.totpEnabled) {
        // Fail closed: 2FA is required but the key or the persistence helper is not available.
        if (typeof getTotpKey !== "function" || typeof commitSyncResumeProof !== "function") return errorResponse(res, 503, "Sync re-authentication unavailable");
        let key;
        try { key = getTotpKey(); } catch { return errorResponse(res, 503, "Sync re-authentication unavailable"); }
        if (!Buffer.isBuffer(key) || key.length !== 32) return errorResponse(res, 503, "Sync re-authentication unavailable");
        // A recovery code is irreversibly consumed by saveUsers below. Refuse
        // to spend it if the sync store cannot currently commit a durable write.
        try { await store.assertWritable(); } catch {
          return errorResponse(res, 503, store.commitIndeterminate ? "sync_commit_indeterminate" : "Sync re-authentication unavailable",
            store.commitIndeterminate ? { code: "SYNC_COMMIT_INDETERMINATE" } : {});
        }
        const pending = store.pendingResume(username);
        const pauseFence = store.pauseFence(username, deviceId);
        if (pending && (pending.deviceId !== deviceId || pending.pauseFence !== pauseFence
          || pending.version !== 2
          || pending.passwordHash !== checkedHash || pending.sessionVersion !== checkedSessionVersion
          || typeof body.code !== "string" || body.code.length > 256
          || !equalMac(pending.codeMac, resumeCodeMac(key, username, deviceId, pauseFence, body.code, pending)))) {
          return fail("pending_resume_mismatch");
        }
        let proof = null;
        if (!pending) {
          try { proof = await verifySecondFactor(user, body.code, key); } catch { return errorResponse(res, 503, "Sync re-authentication unavailable"); }
          if (store.commitIndeterminate) return errorResponse(res, 503, "sync_commit_indeterminate", { code: "SYNC_COMMIT_INDETERMINATE" });
          if (!proof) return fail("second_factor_failed");
        }
        // Re-load after async recovery-code verification and revalidate the account before committing replay state.
        const freshUsers = loadUsers();
        const freshUser = Array.isArray(freshUsers) ? freshUsers.find((entry) => entry?.username === username) : null;
        if (!freshUser || freshUser.disabled || freshUser.password !== checkedHash || (freshUser.sessionVersion || 0) !== checkedSessionVersion || !freshUser.totpEnabled) {
          return errorResponse(res, 401, "Re-authentication failed");
        }
        const secretDigest = crypto.createHash("sha256").update(JSON.stringify(freshUser.totpSecret)).digest("hex");
        if (pending && (secretDigest !== pending.secretDigest
          || authorizationDigest(freshUser) !== pending.authorizationDigest)) return fail("second_factor_or_authority_rotated");
        if (pending) {
          stagedResume = pending;
        } else {
          if (!commitSecondFactorProof(freshUser, proof)) return fail("second_factor_failed");
          stagedResume = {
            version: 2, deviceId, pauseFence,
            passwordHash: checkedHash, sessionVersion: checkedSessionVersion, secretDigest,
            authorizationDigest: authorizationDigest(freshUser),
            proof: proof.type === "recovery" ? { type: "recovery", hash: proof.hash } : { type: "totp", step: proof.step },
            expectedReplayDigest: secondFactorReplayDigest(freshUser),
          };
          stagedResume.codeMac = resumeCodeMac(key, username, deviceId, pauseFence, body.code, stagedResume);
          // Prepare an immutable durable intent *before* spending the factor.
          try { await store.stageResume(username, stagedResume); } catch (error) {
            // A concurrent valid factor cannot overtake an already staged
            // single-use proof, even if both verified before the first commit.
            if (error?.code === "SYNC_RESUME_PENDING") return fail("concurrent_resume_pending");
            return errorResponse(res, 503, store.commitIndeterminate ? "sync_commit_indeterminate" : "Sync re-authentication unavailable",
              store.commitIndeterminate ? { code: "SYNC_COMMIT_INDETERMINATE" } : {});
          }
        }
        // This is an atomic, selective account-store CAS. In SQLite the proof
        // is applied inside BEGIN IMMEDIATE against the CURRENT user row.
        // Never persist freshUsers: it was read before stageResume's await and
        // can be obsolete after administrative revocation or password rotation.
        let accountCommit;
        try {
          accountCommit = commitSyncResumeProof({
            username, passwordHash: checkedHash, sessionVersion: checkedSessionVersion,
            secretDigest: stagedResume.secretDigest,
            authorizationDigest: stagedResume.authorizationDigest,
            deviceId: stagedResume.deviceId, pauseFence: stagedResume.pauseFence,
            codeMac: stagedResume.codeMac,
            proof: stagedResume.proof,
            expectedReplayDigest: stagedResume.expectedReplayDigest,
          });
          if (accountCommit && typeof accountCommit.then === "function") throw new Error("Async account CAS forbidden");
        } catch { return errorResponse(res, 503, "Sync re-authentication unavailable"); }
        if (accountCommit !== "committed" && accountCommit !== "already") return fail("account_state_changed");
      }
      // Staged intent fences the exact pause nonce. If final persistence fails,
      // it stays paused and the MAC-bound intent survives restart for retry.
      let wasPaused;
      try {
        ({ wasPaused } = stagedResume
          ? await store.finishStagedResume(username, stagedResume)
          : await store.resumeDevice(username, deviceId));
      } catch {
        return errorResponse(res, 503, store.commitIndeterminate ? "sync_commit_indeterminate" : "Sync re-authentication unavailable",
          store.commitIndeterminate ? { code: "SYNC_COMMIT_INDETERMINATE" } : {});
      }
      state.count = 0;
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
