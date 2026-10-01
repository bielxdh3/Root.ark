"use strict";

const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { SyncEngine } = require("./rootark-sync-engine");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");
const { createAuthorizationProof } = require("./rootark-sync-authorization");

const DEFAULT_CONFIG = path.resolve(process.cwd(), ".rootark-sync.json");

function args(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) continue;
    const key = item.slice(2);
    const value = argv[index + 1];
    result[key] = value && !value.startsWith("--") ? value : true;
    if (result[key] !== true) index += 1;
  }
  return result;
}

async function readConfig(filePath) {
  const config = JSON.parse(await fsp.readFile(filePath, "utf8"));
  if (!config.serverUrl || !config.localFolder || !config.token || !config.username || !config.deviceId || !config.keyEpoch) throw new Error("Sync v2 requires serverUrl, username, localFolder, token, deviceId, and keyEpoch");
  const master = process.env.ROOTARK_SYNC_FILE_KEY;
  const fileKey = master ? Buffer.from(master, "base64url") : null;
  if (!fileKey || fileKey.length !== 32) throw new Error("ROOTARK_SYNC_FILE_KEY must be a 32-byte base64url key held only in memory");
  const privateKeyBytes = process.env.ROOTARK_SYNC_DEVICE_PRIVATE_KEY ? Buffer.from(process.env.ROOTARK_SYNC_DEVICE_PRIVATE_KEY, "base64url") : null;
  const publicKey = process.env.ROOTARK_SYNC_DEVICE_PUBLIC_KEY || "";
  if (!privateKeyBytes || !publicKey) throw new Error("Sync v2 requires device signing keys held only in memory");
  return { ...config, serverUrl: String(config.serverUrl).replace(/\/+$/, ""), localFolder: path.resolve(config.localFolder), fileKey, privateKey: crypto.createPrivateKey({ key: privateKeyBytes, format: "der", type: "pkcs8" }), publicKey };
}

function fileKeyResolver(master, fallbackEpoch) {
  return (operation) => crypto.createHmac("sha256", master).update(`${operation.fileId || operation.objectId}\0${operation.keyEpoch || fallbackEpoch}`, "utf8").digest();
}

async function start(options = {}) {
  const configPath = path.resolve(options.config || DEFAULT_CONFIG);
  const config = await readConfig(configPath);
  const adapter = createOpaqueSyncAdapter({
    baseUrl: config.serverUrl,
    fetchImpl: (url, request = {}) => fetch(url, { ...request, headers: { Authorization: `Bearer ${config.token}`, ...(request.headers || {}) } }),
  });
  const engine = await new SyncEngine({
    rootDir: config.localFolder,
    adapter,
    selectedPaths: config.selectedPaths,
    deviceId: config.deviceId,
    keyEpoch: config.keyEpoch,
    compartmentId: config.compartmentId || "private",
    fileKeyResolver: fileKeyResolver(config.fileKey, config.keyEpoch),
    authorize: async (operation) => operation.keyEpoch === config.keyEpoch,
    authorizeOutgoing: async (operation) => config.deviceRevoked !== true && operation.deviceId === config.deviceId,
    verifyIncoming: async (operation) => operation.authorization
      ? verifyAuthorizationProof(operation.authorization, operation, { username: config.username })
      : false,
    authorizationFactory: (operation) => createAuthorizationProof(operation, { username: config.username, privateKey: config.privateKey, publicKey: config.publicKey }),
    requireAuthorization: true,
  }).open();
  const once = options.once === true || options.once === "true";
  do {
    const summary = await engine.syncOnce();
    console.log(JSON.stringify({ pushed: summary.pushed, pulled: summary.pulled, conflicts: summary.conflicts.length, offline: summary.offline }));
    if (!once) await new Promise((resolve) => setTimeout(resolve, Number(config.scanIntervalMs) || 5000));
  } while (!once);
  return engine;
}

if (require.main === module) {
  const [command = "help", ...rest] = process.argv.slice(2);
  if (command === "start") start({ ...args(rest) }).catch((error) => { console.error(`Sync v2 failed: ${error.message}`); process.exitCode = 1; });
  else console.log("Root.ark Sync v2\n\nUse: npm run sync:start -- --config .rootark-sync.json --once");
}

module.exports = { fileKeyResolver, start };
