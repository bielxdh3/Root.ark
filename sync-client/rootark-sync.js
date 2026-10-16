#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const readline = require("readline");

const DEFAULT_CONFIG_PATH = path.resolve(process.cwd(), ".rootark-sync.json");
const STATE_FILE_NAME = ".rootark-sync-state.json";
const DEFAULT_DEBOUNCE_MS = 2500;
const DEFAULT_SCAN_INTERVAL_MS = 5000;
const DEFAULT_STABILITY_MS = 1200;
const DEFAULT_RETRIES = 3;
const MAX_FILE_BYTES = 8 * 1024 * 1024;

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
  return String(serverUrl || "").trim().replace(/\/+$/, "");
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

async function readJson(filePath, fallback) {
  try {
    return JSON.parse(await fsp.readFile(filePath, "utf8"));
  } catch {
    return fallback;
  }
}

async function writeJsonAtomic(filePath, data) {
  await fsp.mkdir(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.tmp-${process.pid}`;
  await fsp.writeFile(tempPath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
  await fsp.rename(tempPath, filePath);
}

async function loadConfig(configPath) {
  const config = await readJson(configPath, null);
  if (!config) throw new Error(`Config nao encontrada: ${configPath}. Rode npm run sync:init primeiro.`);
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

async function saveConfig(configPath, config) {
  const safeConfig = { ...config };
  delete safeConfig.password;
  await writeJsonAtomic(configPath, safeConfig);
}

async function login(serverUrl, username, password) {
  const response = await fetch(`${serverUrl}/auth/login`, {
    method: "POST",
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

async function hashFile(filePath) {
  const hash = crypto.createHash("sha256");
  const stream = fs.createReadStream(filePath);
  await new Promise((resolve, reject) => {
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return hash.digest("hex");
}

async function getStableFileInfo(filePath, waitMs) {
  const first = await fsp.stat(filePath);
  if (!first.isFile()) return null;
  await new Promise((resolve) => setTimeout(resolve, waitMs));
  const second = await fsp.stat(filePath);
  if (!second.isFile()) return null;
  if (first.size !== second.size || first.mtimeMs !== second.mtimeMs) return null;
  return {
    size: second.size,
    mtimeMs: second.mtimeMs,
    hash: await hashFile(filePath),
  };
}

async function scanFiles(rootDir) {
  const result = [];

  async function walk(currentDir) {
    const entries = await fsp.readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const safePath = safeResolveInside(rootDir, fullPath);
      if (!safePath) continue;
      const relativePath = path.relative(rootDir, safePath);
      const stats = await fsp.stat(safePath).catch(() => null);
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

async function uploadFile(config, configPath, filePath, relativePath, stateEntry, passwordProvider) {
  const stats = await fsp.stat(filePath);
  if (stats.size > MAX_FILE_BYTES) {
    throw new Error(`Arquivo maior que ${Math.round(MAX_FILE_BYTES / 1024 / 1024)} MB ainda nao e suportado pelo cliente MVP`);
  }

  const fileName = path.basename(relativePath);
  const remoteFiles = await listRemoteFiles(config, configPath, passwordProvider).catch(() => []);
  const remoteExists = remoteFiles.some((file) => file.name === fileName);
  const formData = new FormData();
  const buffer = await fsp.readFile(filePath);
  formData.append("file", new Blob([buffer]), fileName);
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
    this.statePath = path.join(this.config.localFolder, STATE_FILE_NAME);
    this.state = { files: {} };
    this.pending = new Map();
    this.running = false;
    this.scanTimer = null;
    this.idleResolvers = [];
  }

  async init() {
    const safeFolder = path.resolve(this.config.localFolder);
    await fsp.mkdir(safeFolder, { recursive: true });
    this.config.localFolder = safeFolder;
    this.state = await readJson(this.statePath, { files: {} });
    if (!this.state.files || typeof this.state.files !== "object") this.state = { files: {} };
    await ensureToken(this.config, this.configPath, this.passwordProvider);
  }

  async saveState() {
    await writeJsonAtomic(this.statePath, this.state);
  }

  schedule(relativePath, reason = "change") {
    const fullPath = safeResolveInside(this.config.localFolder, path.join(this.config.localFolder, relativePath));
    if (!fullPath) return;
    clearTimeout(this.pending.get(relativePath));
    this.pending.set(relativePath, setTimeout(async () => {
      this.pending.delete(relativePath);
      await this.syncOne(fullPath, relativePath, reason).catch((error) => {
        log(`ERRO ${relativePath}: ${error.message}`);
      });
      this.resolveIdleIfNeeded();
    }, this.config.debounceMs));
  }

  async scanAndSchedule(reason = "scan") {
    const files = await scanFiles(this.config.localFolder);
    for (const file of files) {
      const stateEntry = this.state.files[file.relativePath];
      if (
        stateEntry &&
        stateEntry.size === file.stats.size &&
        stateEntry.mtimeMs === file.stats.mtimeMs &&
        stateEntry.lastStatus === "uploaded"
      ) {
        continue;
      }
      this.schedule(file.relativePath, reason);
    }
    this.resolveIdleIfNeeded();
  }

  async syncOne(filePath, relativePath, reason) {
    const safePath = safeResolveInside(this.config.localFolder, filePath);
    if (!safePath) throw new Error("Caminho fora da pasta sincronizada bloqueado");
    if (!(await fileExists(safePath))) return;

    const info = await getStableFileInfo(safePath, this.config.stabilityMs);
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
        const uploaded = await uploadFile(this.config, this.configPath, safePath, relativePath, previous, this.passwordProvider);
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
    if (this.pending.size > 0) return;
    const resolvers = this.idleResolvers.splice(0);
    resolvers.forEach((resolve) => resolve());
  }

  waitForIdle(timeoutMs = 30000) {
    if (this.pending.size === 0) return Promise.resolve();
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
  const configPath = path.resolve(args.config || DEFAULT_CONFIG_PATH);
  const existing = await readJson(configPath, {});
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
    await saveConfig(configPath, {
      serverUrl,
      username,
      token: loginPayload.token,
      permissions: loginPayload.permissions || {},
      localFolder,
      targetFolderId,
      deviceId: existing.deviceId || `legacy-dev-${crypto.randomUUID()}`,
      keyEpoch: existing.keyEpoch || "epoch-1",
      autoApprove,
      debounceMs: Number(args.debounce) || existing.debounceMs || DEFAULT_DEBOUNCE_MS,
      scanIntervalMs: Number(args.interval) || existing.scanIntervalMs || DEFAULT_SCAN_INTERVAL_MS,
      stabilityMs: Number(args.stability) || existing.stabilityMs || DEFAULT_STABILITY_MS,
      retryLimit: Number(args.retries) || existing.retryLimit || DEFAULT_RETRIES,
      createdAt: existing.createdAt || nowIso(),
      updatedAt: nowIso(),
    });
    log(`Config salva em ${configPath}`);
    log(`Estado sera salvo em ${path.join(localFolder, STATE_FILE_NAME)}`);
  } finally {
    rl.close();
  }
}

async function startCommand(args) {
  if (args["legacy-development-opt-in"] !== true) throw new Error("Legacy uploader is development-only; use npm run sync:start for protocol v2");
  const configPath = path.resolve(args.config || DEFAULT_CONFIG_PATH);
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

  console.log(`Root.ark Sync MVP

Comandos:
  npm run sync:init
  npm run sync:start

Opcoes uteis:
  --config .rootark-sync.json
  --server http://localhost:3000
  --username admin
  --folder C:\\RootArkSync
  --folder-id root
  --auto-approve true
  --once

Variavel opcional para reautenticacao sem salvar senha:
  ROOTARK_SYNC_PASSWORD=senha
`);
}

main().catch((error) => {
  console.error(`[${nowIso()}] ERRO: ${error.message}`);
  process.exit(1);
});
