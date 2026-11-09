"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");

function adapter(calls) {
  return {
    async push() { calls.push("push"); throw Error("NETWORK_NOT_AUTHORIZED"); },
    async list() { calls.push("list"); throw Error("NETWORK_NOT_AUTHORIZED"); },
    async listInventory() { calls.push("inventory"); throw Error("NETWORK_NOT_AUTHORIZED"); },
  };
}

async function makeRoot(t, required) {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-native-gate-"));
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const root = path.join(parent, "consumer");
  await fs.mkdir(root);
  const canary = path.join(root, "café-中-😀.txt");
  await fs.writeFile(canary, "RETAIN_SIGNED_LOCAL_BYTES");
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const snapshot = required
    ? { version: 2, files: {}, remoteOnly: {}, evictionLedgerRequired: true,
      evictionLedgerEpoch: crypto.randomUUID() }
    : { version: 1, files: {}, remoteOnly: {} };
  const exactBytes = Buffer.from(JSON.stringify(snapshot));
  await fs.writeFile(snapshotPath, exactBytes);
  return { root, snapshotPath, exactBytes, canary };
}

test("#66 required-v2 Files On-Demand cold recovery cannot fall back to pathname IO or a JS-supplied native authority", async (t) => {
  const { root, snapshotPath, exactBytes, canary } = await makeRoot(t, true);
  const calls = [];
  let forgedTouched = 0;
  const forged = new Proxy({}, {
    get() { forgedTouched++; throw Error("FORGED_NATIVE_READ"); },
    ownKeys() { forgedTouched++; throw Error("FORGED_NATIVE_ENUM"); },
  });
  const engine = new SyncEngine({ rootDir: root, adapter: adapter(calls),
    filesOnDemand: true, deviceId: "device-b", fileKeyResolver: () => Buffer.alloc(32),
    nativeRootSession: forged, requireNativeRootRecovery: false,
  });
  assert.equal(engine.requireNativeRootRecovery, true,
    "Files On-Demand must mandate the strict root recovery gate despite a false opt-out");
  assert.throws(() => { engine.requireNativeRootRecovery = false; }, TypeError,
    "a callback must not change native recovery requirement at runtime");
  await assert.rejects(engine.open(), { code: "root_session_native_unavailable" });
  assert.deepEqual(calls, [], "the blocked recovery must not make outbound operations");
  assert.equal(forgedTouched, 0, "no caller-provided JavaScript object is native root authority");
  assert.deepEqual(await fs.readFile(snapshotPath), exactBytes,
    "required-v2 must remain on disk for independent operator recovery");
  assert.equal(await fs.readFile(canary, "utf8"), "RETAIN_SIGNED_LOCAL_BYTES");
  assert.equal((await fs.readdir(root)).includes(".rootark-trash"), false,
    "guard must block before creating or inspecting an untrusted trash tree");
});

test("#66 an explicit native-recovery requirement rejects required-v2 even without Files On-Demand", async (t) => {
  const { root, snapshotPath, exactBytes } = await makeRoot(t, true);
  const calls = [];
  const engine = new SyncEngine({ rootDir: root, adapter: adapter(calls),
    requireNativeRootRecovery: true, fileKeyResolver: () => Buffer.alloc(32),
  });
  await assert.rejects(engine.open(), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fs.readFile(snapshotPath), exactBytes);
  assert.deepEqual(calls, []);
  await assert.rejects(engine.recoverUnstartedEvictionLedger(),
    { code: "root_session_native_unavailable" },
    "a direct call must not bypass the native replay boundary");
});

test("#66 an ordinary v1 Files On-Demand open is not incorrectly classified as required-v2 replay", async (t) => {
  const { root, canary } = await makeRoot(t, false);
  const calls = [];
  const engine = new SyncEngine({ rootDir: root, adapter: adapter(calls),
    filesOnDemand: true, fileKeyResolver: () => Buffer.alloc(32),
  });
  await engine.open();
  assert.equal(engine.snapshot.version, 1);
  assert.equal(await fs.readFile(canary, "utf8"), "RETAIN_SIGNED_LOCAL_BYTES");
  assert.deepEqual(calls, []);
});
