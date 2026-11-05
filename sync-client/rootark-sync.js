#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const readline = require("readline");
const os = require("node:os");
const { normalizeTrustedSyncServerUrl } = require("./rootark-sync-transport-policy");
const { writePrivateSyncConfig, readPrivateSyncConfig } =
  require("./rootark-sync-private-config");
const { privateSyncStatePath, assertStateSeparateFromConfig,
  readPrivateSyncState, writePrivateSyncState,
  inspectHistoricalSyncState } = require("./rootark-sync-private-state");
const { acquirePrivateSyncStateLock } =
  require("./rootark-sync-private-lock");

// Bearer credentials must not default to a potentially group-writable CWD.
// A fresh private child of the user config home gets a protected ACL/mode
// before the first credential is written. A custom --config path still works
// only when its containing directory meets that same security boundary.
const USER_CONFIG_HOME = process.platform === "win32"
  ? (process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming"))
  : (process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"));
const DEFAULT_CONFIG_PATH = path.resolve(USER_CONFIG_HOME, "Rootark", "sync", "config.json");
const LEGACY_CWD_CONFIG_PATH = path.resolve(process.cwd(), ".rootark-sync.json");
const STATE_FILE_NAME = ".rootark-sync-state.json";
const DEFAULT_DEBOUNCE_MS = 2500;
const DEFAULT_SCAN_INTERVAL_MS = 5000;
const DEFAULT_STABILITY_MS = 1200;
const DEFAULT_RETRIES = 3;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_CONCURRENT_SYNCS = 4;

const IGNORE_DIRECTORY_NAMES = new Set(["node_modules", ".git"]);
const IGNORE_FILE_NAMES = new Set([STATE_FILE_NAME, ".rootark-sync.json", ".env"]);
const IGNORE_EXTENSIONS = new Set([".key", ".pem", ".tmp", ".part", ".crdownload", ".log"]);

function nowIso() {
  return new Date().toISOString();
}

function log(message) {
  console.log(`[${nowIso()}] ${message}`);
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      args._.push(item);
      continue;
    }

    const key = item.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      args[key] = true;
    } else {
      args[key] = next;
      index += 1;
    }
  }
  return args;
}

function createPrompt() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const question = (label, defaultValue = "") => new Promise((resolve) => {
    const suffix = defaultValue ? ` (${defaultValue})` : "";
    rl.question(`${label}${suffix}: `, (answer) => resolve(answer.trim() || defaultValue));
  });
  return { rl, question };
}

async function fileExists(filePath) {
  try {
    await fsp.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function normalizeServerUrl(serverUrl) {
  return normalizeTrustedSyncServerUrl(serverUrl);
}

function safeResolveInside(rootDir, targetPath) {
  const root = path.resolve(rootDir);
  const resolved = path.resolve(targetPath);
  const relative = path.relative(root, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) return null;
  return resolved;
}

function shouldIgnore(relativePath, stats) {
  const parts = relativePath.split(path.sep).filter(Boolean);
  if (parts.some((part) => IGNORE_DIRECTORY_NAMES.has(part))) return true;

  const baseName = path.basename(relativePath);
  if (!baseName || baseName.startsWith("~$")) return true;
  if (baseName.startsWith(".rootark-sync")) return true;
  if (IGNORE_FILE_NAMES.has(baseName)) return true;
  if (IGNORE_EXTENSIONS.has(path.extname(baseName).toLowerCase())) return true;
  if (stats?.isDirectory?.()) return false;
  return false;
}

async function loadConfig(configPath) {
  const config = await readPrivateSyncConfig(configPath, null);
  if (!config) throw new Error(`Config nao encontrada: ${configPath}. Rode npm run sync:init primeiro.`);
  assertLegacySyncConfig(config);
  config.serverUrl = normalizeServerUrl(config.serverUrl);
  config.localFolder = path.resolve(config.localFolder || "");
  config.targetFolderId = config.targetFolderId || "root";
  config.debounceMs = Number(config.debounceMs) || DEFAULT_DEBOUNCE_MS;
  config.scanIntervalMs = Number(config.scanIntervalMs) || DEFAULT_SCAN_INTERVAL_MS;
  config.stabilityMs = Number(config.stabilityMs) || DEFAULT_STABILITY_MS;
  config.retryLimit = Number(config.retryLimit) || DEFAULT_RETRIES;
  config.autoApprove = Boolean(config.autoApprove);
  return config;
}

function assertLegacySyncConfig(config) {
  // Both CLIs have historically used .rootark-sync.json, but protocol v2
  // stores an independently provisioned device trust policy there. The
  // legacy login flow must never overwrite or interpret that policy as its
  // own config, even when an operator explicitly supplies --config.
  if (config && typeof config === "object" && !Array.isArray(config)
    && (Object.hasOwn(config, "trustedDevicePublicKeys")
      || Object.hasOwn(config, "revokedDeviceIds"))) {
    throw new Error("SYNC_LEGACY_CONFIG_IS_V2: use a separate private --config for the legacy development uploader");
  }
}

async function configNamePresent(configPath) {
  // fs.access/stat follows symlinks and treats permission failures as
  // absence. A dangling link or unreadable config is PRESENT but unsafe;
  // never fall through to another config or accept an untrusted new default.
  try { await fsp.lstat(configPath); return true; }
  catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

async function selectSyncConfigPath(requested, { reusePrivateLegacy = false } = {}) {
  if (requested) return path.resolve(requested);
  // Keep previously initialized legacy clients functional only when the old
  // pathname meets the NEW private-config read boundary; this fallback is
  // strictly for legacy START. Legacy INIT must not overwrite a v2 config
  // whose separate trusted device policy shares the historical CWD filename.
  if (await configNamePresent(DEFAULT_CONFIG_PATH)) return DEFAULT_CONFIG_PATH;
  if (reusePrivateLegacy && LEGACY_CWD_CONFIG_PATH !== DEFAULT_CONFIG_PATH
    && await configNamePresent(LEGACY_CWD_CONFIG_PATH)) {
    try {
      const oldConfig = await readPrivateSyncConfig(LEGACY_CWD_CONFIG_PATH, null);
      assertLegacySyncConfig(oldConfig);
    } catch (error) {
      if (error?.message?.startsWith("SYNC_LEGACY_CONFIG_IS_V2")) throw error;
      throw new Error("SYNC_LEGACY_CONFIG_UNSAFE: existing .rootark-sync.json must be moved securely or reinitialized with rotated credentials in a private config directory");
    }
    return LEGACY_CWD_CONFIG_PATH;
  }
  return DEFAULT_CONFIG_PATH;
}

async function saveConfig(configPath, config) {
  const safeConfig = { ...config };
  delete safeConfig.password;
  assertStateSeparateFromConfig(configPath, safeConfig);
  await writePrivateSyncConfig(configPath, `${JSON.stringify(safeConfig, null, 2)}\n`);
}

async function login(serverUrl, username, password) {
  const response = await fetch(`${serverUrl}/auth/login`, {
    method: "POST",
    redirect: "error",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.token) {
    throw new Error(payload.error || "Login nao concluido");
  }
  return payload;
}

async function ensureToken(config, configPath, passwordProvider = null) {
  if (config.token) return config.token;
  const password = passwordProvider ? await passwordProvider() : process.env.ROOTARK_SYNC_PASSWORD;
  if (!password) throw new Error("Token ausente. Rode sync:init ou informe ROOTARK_SYNC_PASSWORD para reautenticar.");
  const payload = await login(config.serverUrl, config.username, password);
  config.token = payload.token;
  config.permissions = payload.permissions || config.permissions || {};
  await saveConfig(configPath, config);
  return config.token;
}

async function authFetch(config, configPath, urlPath, options = {}) {
  const token = await ensureToken(config, configPath, options.passwordProvider);
  const response = await fetch(`${config.serverUrl}${urlPath}`, {
    ...options,
    redirect: "error",
    headers: {
      Authorization: `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });

  if (response.status === 401 && options.passwordProvider) {
    config.token = "";
    const freshToken = await ensureToken(config, configPath, options.passwordProvider);
    return fetch(`${config.serverUrl}${urlPath}`, {
      ...options,
      redirect: "error",
      headers: {
        Authorization: `Bearer ${freshToken}`,
        ...(options.headers || {}),
      },
    });
  }

  return response;
}

async function listRemoteFiles(config, configPath, passwordProvider) {
  const response = await authFetch(config, configPath, `/list?folderId=${encodeURIComponent(config.targetFolderId)}`, {
    passwordProvider,
  });
  const payload = await response.json().catch(() => []);
  if (!response.ok) throw new Error(payload.error || "Nao foi possivel listar arquivos remotos");
  return Array.isArray(payload) ? payload : Array.isArray(payload.items) ? payload.items : Array.isArray(payload.value) ? payload.value : [];
}

async function approveRemoteFile(config, configPath, fileName, passwordProvider) {
  const response = await authFetch(config, configPath, `/approve/${encodeURIComponent(fileName)}?folderId=${encodeURIComponent(config.targetFolderId)}`, {
    method: "POST",
    passwordProvider,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Nao foi possivel aprovar ${fileName}`);
  return payload;
}

async function isSafeLocalFile(rootDir, filePath) {
  const root = path.resolve(rootDir);
  const candidate = safeResolveInside(root, filePath);
  if (!candidate || candidate === root) return false;
  const canonicalRoot = await fsp.realpath(root);
  const canonicalTarget = await fsp.realpath(candidate);
  if (!safeResolveInside(canonicalRoot, canonicalTarget)) return false;
  for (let current = candidate; current !== root; current = path.dirname(current)) {
    if ((await fsp.lstat(current)).isSymbolicLink()) return false;
  }
  return true;
}

async function openPinnedLocalSnapshot(filePath, expectedStat) {
  // Encapsulate the authority acquisition: O_NOFOLLOW rejects POSIX leaf
  // symlinks at open, and the first fstat must match the already validated
  // pathname identity before the descriptor is allowed to supply any bytes.
  const handle = await fsp.open(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  let admitted = false;
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size > MAX_FILE_BYTES ||
        opened.dev !== expectedStat.dev || opened.ino !== expectedStat.ino) return null;
    admitted = true;
    return { handle, opened };
  } finally {
    if (!admitted) await handle.close();
  }
}

async function getStableFileInfo(filePath, waitMs, rootDir) {
  if (!(await isSafeLocalFile(rootDir, filePath))) return null;
  const first = await fsp.lstat(filePath);
  if (!first.isFile()) return null;
  await new Promise((resolve) => setTimeout(resolve, waitMs));
  if (!(await isSafeLocalFile(rootDir, filePath))) return null;
  const second = await fsp.lstat(filePath);
  if (!second.isFile()) return null;
  if (first.size !== second.size || first.mtimeMs !== second.mtimeMs) return null;
  // Keep the legacy oversized-file failure/retry reporting without reading it.
  if (second.size > MAX_FILE_BYTES) return {
    size: second.size, mtimeMs: second.mtimeMs, hash: null, bytes: null,
  };
  const pinned = await openPinnedLocalSnapshot(filePath, second);
  if (!pinned) return null;
  const { handle, opened } = pinned;
  try {
    // FileHandle.readFile internally sizes its allocation from a fresh stat.
    // A writer could grow the same opened inode after our size check, so use
    // bounded reads from that descriptor and reject any growth past the cap.
    const chunks = [];
    let size = 0;
    while (size <= MAX_FILE_BYTES) {
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, MAX_FILE_BYTES + 1 - size));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (!bytesRead) break;
      size += bytesRead;
      chunks.push(chunk.subarray(0, bytesRead));
    }
    if (size > MAX_FILE_BYTES) return null;
    const bytes = Buffer.concat(chunks, size);
    const finalStat = await handle.stat();
    if (!finalStat.isFile() || bytes.length !== finalStat.size ||
        opened.size !== finalStat.size || opened.mtimeMs !== finalStat.mtimeMs ||
        !(await isSafeLocalFile(rootDir, filePath))) return null;
    const finalPath = await fsp.lstat(filePath);
    if (!finalPath.isFile() || finalPath.dev !== finalStat.dev || finalPath.ino !== finalStat.ino) return null;
    return { size: finalStat.size, mtimeMs: finalStat.mtimeMs,
      hash: crypto.createHash("sha256").update(bytes).digest("hex"), bytes };
  } finally {
    await handle.close();
  }
}

async function scanFiles(rootDir) {
  const result = [];

  async function walk(currentDir) {
    const entries = await fsp.readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const safePath = safeResolveInside(rootDir, fullPath);
      if (!safePath || entry.isSymbolicLink()) continue;
      const relativePath = path.relative(rootDir, safePath);
      const stats = await fsp.lstat(safePath).catch(() => null);
      if (!stats || shouldIgnore(relativePath, stats)) continue;

      if (stats.isDirectory()) {
        await walk(safePath);
      } else if (stats.isFile()) {
        result.push({ fullPath: safePath, relativePath, stats });
      }
    }
  }

  await walk(rootDir);
  return result;
}

async function uploadFile(config, configPath, bytes, relativePath, stateEntry, passwordProvider) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_FILE_BYTES) {
    throw new Error(`Arquivo maior que ${Math.round(MAX_FILE_BYTES / 1024 / 1024)} MB ainda nao e suportado pelo cliente MVP`);
  }

  const fileName = path.basename(relativePath);
  const remoteFiles = await listRemoteFiles(config, configPath, passwordProvider).catch(() => []);
  const remoteExists = remoteFiles.some((file) => file.name === fileName);
  const formData = new FormData();
  formData.append("file", new Blob([bytes]), fileName);
  formData.append("encryptionLevel", "none");
  if (remoteExists || stateEntry?.remoteFileName === fileName) {
    formData.append("versionComment", `Root.ark Sync update ${nowIso()}`);
  }

  const response = await authFetch(config, configPath, `/upload?folderId=${encodeURIComponent(config.targetFolderId)}`, {
    method: "POST",
    body: formData,
    passwordProvider,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Upload falhou: ${fileName}`);

  if (config.autoApprove) {
    await approveRemoteFile(config, configPath, payload.fileName || fileName, passwordProvider);
  }

  return {
    remoteFileName: payload.fileName || fileName,
    uploadResponse: payload,
  };
}

class SyncClient {
  constructor(configPath, config, options = {}) {
    this.configPath = configPath;
    this.config = config;
    this.once = Boolean(options.once);
    this.passwordProvider = options.passwordProvider || null;
    this.statePath = assertStateSeparateFromConfig(this.configPath, this.config);
    this.state = { files: Object.create(null) };
    this.stateSaveQueue = Promise.resolve();
    this.stateLock = null;
    this.pending = new Map();
    this.running = false;
    this.scanTimer = null;
    this.idleResolvers = [];
    this.activeSyncTasks = 0;
    this.activeSyncSlots = 0;
    this.syncSlotWaiters = [];
  }

  async init() {
    // Per-process saveState serialization is insufficient when two CLIs share
    // the same protected state identity: each otherwise reads a stale cache
    // and may overwrite the other's successful acknowledgement. The lock must
    // be held BEFORE readPrivateSyncState until process exit, including
    // unbounded in-flight HTTP uploads or async state writes.
    this.stateLock = acquirePrivateSyncStateLock(this.statePath);
    try {
      const safeFolder = path.resolve(this.config.localFolder);
      await fsp.mkdir(safeFolder, { recursive: true });
      this.config.localFolder = safeFolder;
      this.state = await readPrivateSyncState(this.statePath, this.config);
      // No migration of unauthenticated `uploaded` flags: it could skip real
      // uploads. Retain historical state in place, inspect without writing,
      // and rebuild a private cache from real uploads on this invocation.
      const legacy = await inspectHistoricalSyncState(safeFolder);
      if (legacy.present) {
        log(`Estado legado preservado sem importacao: ${path.join(safeFolder, STATE_FILE_NAME)} (${legacy.status}). A primeira varredura refaz uploads sem confiar em marcadores antigos.`);
      }
      await ensureToken(this.config, this.configPath, this.passwordProvider);
    } catch (error) {
      this.stateLock.release();
      this.stateLock = null;
      throw error;
    }
  }

  saveState() {
    // Four concurrent per-file syncs must never reuse the same temporary
    // filename or race to publish stale snapshots of this shared state.
    const next = this.stateSaveQueue.then(() =>
      writePrivateSyncState(this.statePath, this.state, this.config));
    this.stateSaveQueue = next.catch(() => {});
    return next;
  }

  schedule(relativePath, reason = "change") {
    const fullPath = safeResolveInside(this.config.localFolder, path.join(this.config.localFolder, relativePath));
    if (!fullPath) return;
    clearTimeout(this.pending.get(relativePath));
    this.pending.set(relativePath, setTimeout(async () => {
      this.activeSyncTasks++;
      this.pending.delete(relativePath);
      try {
        await this.syncOne(fullPath, relativePath, reason).catch((error) => {
          log(`ERRO ${relativePath}: ${error.message}`);
        });
      } finally {
        this.activeSyncTasks--;
        this.resolveIdleIfNeeded();
      }
    }, this.config.debounceMs));
  }

  async scanAndSchedule(reason = "scan") {
    const files = await scanFiles(this.config.localFolder);
    for (const file of files) {
      // A different local principal may change bytes within a shared source
      // folder and restore size/mtime. Metadata alone cannot authorize an
      // `uploaded` cache hit; syncOne verifies a pinned snapshot SHA-256
      // before deciding to omit the upload. Do not reset an in-flight debounce
      // on every interval scan (especially when interval < debounce).
      if (this.pending.has(file.relativePath)) continue;
      this.schedule(file.relativePath, reason);
    }
    this.resolveIdleIfNeeded();
  }

  async acquireSyncSlot() {
    // Only a bounded number of per-file snapshots may remain resident while
    // uploads wait for the remote server or retry/backoff to complete.
    if (this.activeSyncSlots < MAX_CONCURRENT_SYNCS) this.activeSyncSlots++;
    else await new Promise((resolve) => this.syncSlotWaiters.push(resolve));
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const next = this.syncSlotWaiters.shift();
      if (next) next();
      else this.activeSyncSlots--;
    };
  }

  async syncOne(filePath, relativePath, reason) {
    const release = await this.acquireSyncSlot();
    try { return await this.syncOneWithSlot(filePath, relativePath, reason); }
    finally { release(); }
  }

  async syncOneWithSlot(filePath, relativePath, reason) {
    const safePath = safeResolveInside(this.config.localFolder, filePath);
    if (!safePath) throw new Error("Caminho fora da pasta sincronizada bloqueado");
    if (!(await fileExists(safePath))) return;

    const info = await getStableFileInfo(safePath, this.config.stabilityMs, this.config.localFolder);
    if (!info) {
      this.schedule(relativePath, "not-stable");
      return;
    }

    const previous = this.state.files[relativePath];
    if (
      previous &&
      previous.hash === info.hash &&
      previous.size === info.size &&
      previous.lastStatus === "uploaded"
    ) {
      return;
    }

    let lastError = null;
    for (let attempt = 1; attempt <= this.config.retryLimit; attempt += 1) {
      try {
        log(`Enviando ${relativePath} (${reason}, tentativa ${attempt})`);
        const uploaded = await uploadFile(this.config, this.configPath, info.bytes, relativePath, previous, this.passwordProvider);
        this.state.files[relativePath] = {
          relativePath,
          remoteFileName: uploaded.remoteFileName,
          size: info.size,
          mtimeMs: info.mtimeMs,
          hash: info.hash,
          lastStatus: "uploaded",
          lastUploadedAt: nowIso(),
        };
        await this.saveState();
        log(`OK ${relativePath} -> ${uploaded.remoteFileName}${this.config.autoApprove ? " (aprovado)" : " (pendente)"}`);
        return;
      } catch (error) {
        lastError = error;
        await new Promise((resolve) => setTimeout(resolve, 700 * attempt));
      }
    }

    this.state.files[relativePath] = {
      ...(this.state.files[relativePath] || { relativePath }),
      size: info.size,
      mtimeMs: info.mtimeMs,
      hash: info.hash,
      lastStatus: "failed",
      lastError: lastError?.message || "Upload falhou",
      lastTriedAt: nowIso(),
    };
    await this.saveState();
    throw lastError || new Error("Upload falhou");
  }

  startWatcher() {
    try {
      fs.watch(this.config.localFolder, { recursive: true }, (eventType, fileName) => {
        if (!fileName) return;
        const relativePath = path.normalize(String(fileName));
        const fullPath = path.join(this.config.localFolder, relativePath);
        fsp.stat(fullPath).then((stats) => {
          if (!stats.isFile() || shouldIgnore(relativePath, stats)) return;
          this.schedule(relativePath, eventType);
        }).catch(() => {});
      });
      log("Watcher ativo");
    } catch (error) {
      log(`Watcher nativo indisponivel, usando varredura periodica: ${error.message}`);
    }
  }

  resolveIdleIfNeeded() {
    if (this.pending.size > 0 || this.activeSyncTasks > 0) return;
    const resolvers = this.idleResolvers.splice(0);
    resolvers.forEach((resolve) => resolve());
  }

  waitForIdle(timeoutMs = 30000) {
    if (this.pending.size === 0 && this.activeSyncTasks === 0) return Promise.resolve();
    return new Promise((resolve) => {
      const timer = setTimeout(resolve, timeoutMs);
      this.idleResolvers.push(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  async start() {
    await this.init();
    this.running = true;
    log(`Sync iniciado: ${this.config.localFolder} -> ${this.config.serverUrl} / folderId=${this.config.targetFolderId}`);
    await this.scanAndSchedule("initial");
    if (this.once) {
      await this.waitForIdle(Math.max(30000, this.config.debounceMs + this.config.stabilityMs + 10000));
      log("Sync --once concluido");
      return;
    }

    this.startWatcher();
    this.scanTimer = setInterval(() => {
      this.scanAndSchedule("interval").catch((error) => log(`Erro na varredura: ${error.message}`));
    }, this.config.scanIntervalMs);
  }

  stop() {
    this.running = false;
    if (this.scanTimer) clearInterval(this.scanTimer);
    for (const timer of this.pending.values()) clearTimeout(timer);
    this.pending.clear();
  }
}

async function initCommand(args) {
  const configPath = await selectSyncConfigPath(args.config);
  // Validate directory, ACL and opened config inode BEFORE prompting or
  // sending a password. Previously an attacker-owned symlink/JSON could set
  // the login URL while the write-time security check ran only afterwards.
  const existing = await readPrivateSyncConfig(configPath, {}, { createParent: true });
  assertLegacySyncConfig(existing);
  const { rl, question } = createPrompt();
  try {
    const serverUrl = normalizeServerUrl(args.server || await question("Root.ark URL", existing.serverUrl || "http://localhost:3000"));
    const username = args.username || await question("Usuario", existing.username || "");
    const password = args.password || process.env.ROOTARK_SYNC_PASSWORD || await question("Senha (nao sera salva)");
    const localFolder = path.resolve(args.folder || await question("Pasta local", existing.localFolder || path.resolve("rootark-sync-folder")));
    const targetFolderId = args["folder-id"] || await question("Root.ark folderId", existing.targetFolderId || "root");
    const autoApprove = args["auto-approve"] === true || String(args["auto-approve"] || existing.autoApprove || "false") === "true";

    if (!username || !password) throw new Error("Usuario e senha sao obrigatorios para gerar token");
    await fsp.mkdir(localFolder, { recursive: true });
    const loginPayload = await login(serverUrl, username, password);
    const deviceId = existing.deviceId || `legacy-dev-${crypto.randomUUID()}`;
    const keyEpoch = existing.keyEpoch || "epoch-1";
    await saveConfig(configPath, {
      serverUrl,
      username,
      token: loginPayload.token,
      permissions: loginPayload.permissions || {},
      localFolder,
      targetFolderId,
      deviceId,
      keyEpoch,
      autoApprove,
      debounceMs: Number(args.debounce) || existing.debounceMs || DEFAULT_DEBOUNCE_MS,
      scanIntervalMs: Number(args.interval) || existing.scanIntervalMs || DEFAULT_SCAN_INTERVAL_MS,
      stabilityMs: Number(args.stability) || existing.stabilityMs || DEFAULT_STABILITY_MS,
      retryLimit: Number(args.retries) || existing.retryLimit || DEFAULT_RETRIES,
      createdAt: existing.createdAt || nowIso(),
      updatedAt: nowIso(),
    });
    log(`Config salva em ${configPath}`);
    log(`Estado privado sera salvo em ${privateSyncStatePath(configPath, { serverUrl, username, localFolder, targetFolderId, deviceId, keyEpoch })}`);
  } finally {
    rl.close();
  }
}

async function startCommand(args) {
  if (args["legacy-development-opt-in"] !== true) throw new Error("Legacy uploader is development-only; use npm run sync:start for protocol v2");
  const configPath = await selectSyncConfigPath(args.config, { reusePrivateLegacy: true });
  const config = await loadConfig(configPath);
  if (args["auto-approve"] !== undefined) config.autoApprove = args["auto-approve"] === true || args["auto-approve"] === "true";
  const passwordProvider = async () => {
    if (args.password) return args.password;
    if (process.env.ROOTARK_SYNC_PASSWORD) return process.env.ROOTARK_SYNC_PASSWORD;
    const { rl, question } = createPrompt();
    try {
      return await question("Senha para renovar login");
    } finally {
      rl.close();
    }
  };
  const client = new SyncClient(configPath, config, {
    once: Boolean(args.once),
    passwordProvider,
  });
  process.on("SIGINT", () => {
    client.stop();
    log("Sync parado");
    process.exit(0);
  });
  await client.start();
}

async function main() {
  const [command = "help", ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);
  if (command === "init") return initCommand(args);
  if (command === "start") return startCommand(args);

  console.log(`Root.ark Sync MVP (legacy development uploader)

Comandos:
  npm run sync:init                         # legacy init, no v2 device provisioning
  npm run sync:start:legacy-dev             # legacy uploader, dev opt-in only
  npm run sync:start                        # separate protocol v2 client

Opcoes uteis:
  --config <private-config-path>            # owner-only directory and file required
  --server http://localhost:3000
  --username admin
  --folder C:\\RootArkSync
  --folder-id root
  --auto-approve true
  --once

Variavel opcional para reautenticacao sem salvar senha:
  ROOTARK_SYNC_PASSWORD=senha

Configuracao legacy padrao: ${DEFAULT_CONFIG_PATH}
Uma .rootark-sync.json antiga no CWD so e reutilizada se ja for privada.
Se for insegura, mova-a com cuidado para uma pasta privada ou reinicialize
o cliente com credenciais rotacionadas. Nao copie tokens para diretorios publicos.
Estado local: .rootark-sync-state-<sha256>.json ao lado da config privada (ate 16 MiB).
O antigo .rootark-sync-state.json na pasta sincronizada e mantido sem importacao;
a primeira execucao refaz uploads e pode criar novas versoes no servidor.
`);
}

main().catch((error) => {
  console.error(`[${nowIso()}] ERRO: ${error.message}`);
  process.exit(1);
});
