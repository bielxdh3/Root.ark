"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");

function adapter(calls) {
  return {
    async push() { calls.push("push"); throw Error("NETWORK_NOT_AUTHORIZED"); },
    async list() { calls.push("list"); throw Error("NETWORK_NOT_AUTHORIZED"); },
    async listInventory() { calls.push("inventory"); throw Error("NETWORK_NOT_AUTHORIZED"); },
  };
}

async function makeRoot(_t, required) {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-native-gate-"));
  // Keep only newly created disposable fixtures for inspection: a hostile
  // same-UID process could otherwise replace a TEMP ancestor before a
  // pathname-based recursive teardown and redirect it into foreign data.
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

test("#66 a mutable Files On-Demand flag cannot bypass required native recovery on a preexisting engine", async (t) => {
  const { root, snapshotPath, exactBytes } = await makeRoot(t, true);
  const calls = [];
  const engine = new SyncEngine({ rootDir: root, adapter: adapter(calls),
    filesOnDemand: false, fileKeyResolver: () => Buffer.alloc(32),
  });
  assert.throws(() => { engine.filesOnDemand = true; }, TypeError,
    "runtime mode cannot change after native recovery policy was captured");
  assert.equal(engine.filesOnDemand, false);
  assert.deepEqual(await fs.readFile(snapshotPath), exactBytes);
  assert.deepEqual(calls, []);
});

test("#66 an overridden engine method or prototype hook cannot waive native-required recovery", async (t) => {
  const { root, snapshotPath, exactBytes, canary } = await makeRoot(t, true);
  const calls = [];
  const engine = new SyncEngine({ rootDir: root, adapter: adapter(calls),
    filesOnDemand: true, fileKeyResolver: () => Buffer.alloc(32),
  });
  let invoked = 0;
  engine.denyUntrustedEvictionReplay = () => { invoked++; };
  await assert.rejects(engine.open(), { code: "root_session_native_unavailable" });
  await assert.rejects(engine.recoverUnstartedEvictionLedger(),
    { code: "root_session_native_unavailable" });
  assert.equal(invoked, 0, "userland override cannot influence a private native trust boundary");
  assert.deepEqual(await fs.readFile(snapshotPath), exactBytes);
  assert.equal(await fs.readFile(canary, "utf8"), "RETAIN_SIGNED_LOCAL_BYTES");
  assert.deepEqual(calls, []);
});

test("#66 strict native recovery rejects a real nonempty PREPARE ledger even if a stale snapshot says not required", async () => {
  // Real signed/local adapter fixtures, never a network request or a fake
  // JSON PREPARE that accidentally fails parser validation before the gate.
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-native-ledger-"));
  // Preserve disposable directory: recursive pathname teardown is unsafe
  // under the same-UID ancestor replacement threat this PR investigates.
  const store = await new SyncObjectStore(path.join(parent, "objects.json")).open();
  const key = crypto.randomBytes(32);
  const calls = [];
  const adapter = {
    async push(operation) {
      calls.push({ kind: "push", operation: operation.operation, tombstone: operation.tombstone });
      return { status: 201, record: (await store.put("alice", operation)).record };
    },
    async list(id = "") {
      calls.push({ kind: "list" });
      return store.list("alice", id || null);
    },
    async listInventory() { throw Error("NETWORK_NOT_AUTHORIZED"); },
  };
  const create = async (root, excludedPaths = [], filesOnDemand = false) =>
    new SyncEngine({ rootDir: root, adapter,
      deviceId: root.endsWith("source") ? "device-a" : "device-b",
      keyEpoch: "epoch-1", compartmentId: "private", excludedPaths,
      filesOnDemand, fileKeyResolver: () => key,
    }).open();
  const source = path.join(parent, "source");
  const root = path.join(parent, "device");
  await fs.mkdir(path.join(source, "PRIVATE"), { recursive: true });
  await fs.writeFile(path.join(source, "PRIVATE", "café-中-😀.txt"), "SIGNED_LOCAL_BYTES");
  await (await create(source)).syncOnce();
  const imported = await create(root);
  await imported.syncOnce();
  imported.snapshot.excludedPaths = ["private"];
  imported.snapshot.excludedPathsCasefoldVersion = 1;
  await imported.persistSnapshot();
  const staging = await create(root, ["private"]);
  const originalStage = staging.stageExisting.bind(staging);
  staging.stageExisting = async (target) => {
    await originalStage(target);
    throw Object.assign(new Error("INJECTED_AFTER_DURABLE_PREPARE"), { code: "EIO" });
  };
  await assert.rejects(staging.syncOnce(), { code: "eviction_restore_failed" });
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const ledgerDir = path.join(root, ".rootark-sync-evictions");
  const ledger = await fs.readdir(ledgerDir);
  assert.equal(ledger.filter((name) => name.endsWith(".prepare.json")).length, 1,
    "regression must exercise a real, validated, nonempty PREPARE ledger");
  const disk = JSON.parse(await fs.readFile(snapshotPath, "utf8"));
  assert.equal(disk.evictionLedgerRequired, true);
  disk.evictionLedgerRequired = false; // hostile/stale snapshot inconsistency
  const patched = Buffer.from(JSON.stringify(disk));
  await fs.writeFile(snapshotPath, patched);
  const callsBefore = calls.length;
  const strict = new SyncEngine({ rootDir: root, adapter,
    filesOnDemand: true, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
  });
  await assert.rejects(strict.open(), { code: "root_session_native_unavailable" });
  assert.equal(calls.length, callsBefore, "no remote DELETE or LIST after refusing replay");
  assert.deepEqual(await fs.readFile(snapshotPath), patched,
    "a blocked strict replay must preserve the exact stale on-disk snapshot");
  assert.deepEqual(await fs.readdir(ledgerDir), ledger,
    "a blocked strict replay must not compact or mutate the physical PREPARE");
  assert.equal(store.list("alice").filter((item) => item.tombstone).length, 0,
    "server-side signed records must retain zero DELETE tombstones");
});

test("#66 replacing the entire replay method cannot evade a required-v2 native gate", async (t) => {
  const { root, snapshotPath, exactBytes, canary } = await makeRoot(t, true);
  const calls = [];
  const engine = new SyncEngine({ rootDir: root, adapter: adapter(calls),
    filesOnDemand: true, fileKeyResolver: () => Buffer.alloc(32),
  });
  let forgedReplayCalls = 0;
  engine.replayEvictionLedger = async () => {
    forgedReplayCalls++;
    engine.snapshot.evictionLedgerRequired = false;
    await engine.persistSnapshot();
  };
  await assert.rejects(engine.open(), { code: "root_session_native_unavailable" });
  assert.equal(forgedReplayCalls, 0, "a caller may not redirect the built-in replay guard");
  assert.deepEqual(await fs.readFile(snapshotPath), exactBytes);
  assert.equal(await fs.readFile(canary, "utf8"), "RETAIN_SIGNED_LOCAL_BYTES");
  assert.deepEqual(calls, []);
});

test("#66 strict restart cannot reuse a mutable in-memory snapshot after a denied required-v2 open", async (t) => {
  const { root, snapshotPath, exactBytes, canary } = await makeRoot(t, true);
  const calls = [];
  const engine = new SyncEngine({ rootDir: root, adapter: adapter(calls),
    filesOnDemand: true, fileKeyResolver: () => Buffer.alloc(32),
  });
  await assert.rejects(engine.open(), { code: "root_session_native_unavailable" });
  engine.snapshot.evictionLedgerRequired = false;
  // Disk still has true: never trust the cached mutable JS snapshot version.
  await assert.rejects(engine.open(), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fs.readFile(snapshotPath), exactBytes);
  assert.equal(await fs.readFile(canary, "utf8"), "RETAIN_SIGNED_LOCAL_BYTES");
  assert.deepEqual(calls, []);
});

test("#66 public _open override cannot suppress native-required replay on open or syncOnce", async (t) => {
  const { root, snapshotPath, exactBytes } = await makeRoot(t, true);
  const calls = [];
  const engine = new SyncEngine({ rootDir: root, adapter: adapter(calls),
    filesOnDemand: true, fileKeyResolver: () => Buffer.alloc(32),
  });
  let hijacked = 0;
  engine._open = async () => {
    hijacked++;
    engine.snapshot.evictionLedgerRequired = false;
    engine.opened = true;
  };
  await assert.rejects(engine.open(), { code: "root_session_native_unavailable" });
  await assert.rejects(engine.syncOnce(), { code: "root_session_native_unavailable" });
  assert.equal(hijacked, 0);
  assert.deepEqual(await fs.readFile(snapshotPath), exactBytes);
  assert.deepEqual(calls, []);
});
