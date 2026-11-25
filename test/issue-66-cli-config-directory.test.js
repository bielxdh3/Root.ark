"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.resolve(__dirname, "../sync-client/rootark-sync-v2.js"), "utf8");
const begin = source.indexOf("async function readConfig(filePath) {");
const end = source.indexOf("\nfunction fileKeyResolver(", begin);
assert.ok(begin !== -1 && end > begin, "Read the actual CLI private config resolver, not a duplicate test implementation");

function createReadConfig(privateConfig) {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const context = vm.createContext({
    path,
    Buffer,
    crypto,
    process: { env: {
      ROOTARK_SYNC_FILE_KEY: crypto.randomBytes(32).toString("base64url"),
      ROOTARK_SYNC_DEVICE_PRIVATE_KEY: keyPair.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"),
      ROOTARK_SYNC_DEVICE_PUBLIC_KEY: keyPair.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
    } },
    readPrivateV2Config: () => privateConfig,
    normalizeTrustedDevicePolicy: () => ({}),
    normalizeTrustedSyncServerUrl: (url) => url,
  });
  return vm.runInContext(`${source.slice(begin, end)}\nreadConfig`, context);
}

test("#66 CLI resolves localFolder relative to the private config directory, not its process cwd", async () => {
  const base = path.join(os.tmpdir(), `rootark-issue66-config-${crypto.randomUUID()}`);
  const configPath = path.join(base, "private-authority", "sync.json");
  const readConfig = createReadConfig({
    serverUrl: "https://sync.invalid", username: "alice", localFolder: "sync-data",
    token: "fixture", deviceId: "device-a", keyEpoch: "epoch-a",
  });
  const resolved = await readConfig(configPath);
  assert.equal(resolved.localFolder, path.join(base, "private-authority", "sync-data"));
  assert.notEqual(resolved.localFolder, path.resolve("sync-data"), "never resolve against the caller's process cwd");
});

test("#66 CLI preserves a fully qualified localFolder", async () => {
  const absoluteRoot = path.join(os.tmpdir(), `rootark-issue66-absolute-${crypto.randomUUID()}`);
  const readConfig = createReadConfig({
    serverUrl: "https://sync.invalid", username: "alice", localFolder: absoluteRoot,
    token: "fixture", deviceId: "device-a", keyEpoch: "epoch-a",
  });
  const resolved = await readConfig(path.join(os.tmpdir(), "private", "sync.json"));
  assert.equal(resolved.localFolder, absoluteRoot);
});
