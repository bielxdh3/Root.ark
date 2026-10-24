"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { fork } = require("node:child_process");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { SyncObjectStore } = require("../src/routes/sync");
const { createSyncBurstGuard } = require("../src/services/syncBurstGuard");
const protocol = require("../sync-client/rootark-sync-protocol");

test("an older process reads the committed peer inventory and pause fence", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-fresh-read-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "objects.json");
  const old = await new SyncObjectStore(file).open();
  const peer = await new SyncObjectStore(file).open();
  const operation = protocol.createOperation({ operation: "create", objectId: "peer-object",
    fileId: "peer-file", versionId: "peer-version", operationId: "peer-op",
    deviceId: "peer-device", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "peer-device" }, metadata: { path: "peer.txt" },
    plaintext: Buffer.from("ciphertext-only"), fileKey: crypto.randomBytes(32) });
  assert.equal((await peer.put("alice", operation)).kind, "stored");
  await peer.transact((next) => {
    const user = peer.user(next, "alice");
    user.pausedDevices = { "d:peer-device": { pauseNonce: "peer-fence" } };
    user.resumeIntent = { deviceId: "peer-device", pauseFence: "peer-fence" };
  });
  assert.equal(old.list("alice")[0]?.operationId, "peer-op");
  assert.equal(old.history("alice", "peer-object")[0]?.operationId, "peer-op");
  assert.equal(old.isDevicePaused("alice", "peer-device"), true);
  assert.equal(old.pauseFence("alice", "peer-device"), "peer-fence");
  assert.equal(old.pendingResume("alice")?.pauseFence, "peer-fence");
});

test("alternating processes cannot evade the persisted destructive burst fence", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-durable-burst-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "objects.json");
  const makeStore = () => new SyncObjectStore(file, { burstGuard: createSyncBurstGuard({
    maxDestructive: 2, maxPerObject: 99, windowMs: 600000, env: {},
  }) });
  const a = await makeStore().open();
  const b = await makeStore().open();
  const key = crypto.randomBytes(32);
  const operation = (counter) => protocol.createOperation({
    operation: counter === 1 ? "create" : "update", objectId: "shared-object",
    fileId: "shared-file", versionId: `version-${counter}`, operationId: `operation-${counter}`,
    deviceId: "same-device", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter, deviceId: "same-device" },
    ...(counter > 1 ? { baseRevision: { counter: counter - 1, deviceId: "same-device" } } : {}),
    metadata: { path: "shared.txt" }, plaintext: Buffer.from(`version-${counter}`), fileKey: key,
  });
  assert.equal((await a.put("alice", operation(1))).kind, "stored");
  assert.equal((await a.put("alice", operation(2))).kind, "stored");
  assert.equal((await b.put("alice", operation(3))).kind, "stored");
  assert.equal((await a.put("alice", operation(4))).kind, "paused");
  assert.equal((await makeStore().open()).isDevicePaused("alice", "same-device"), true);
});

test("expired device burst buckets release capacity for a new device", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-burst-expiry-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  let clock = 10000;
  const store = await new SyncObjectStore(path.join(dir, "objects.json"), {
    now: () => clock,
    burstGuard: createSyncBurstGuard({ maxDestructive: 1, maxPerObject: 1,
      maxKeys: 2, windowMs: 1000, env: {} }),
  }).open();
  const key = crypto.randomBytes(32);
  const operation = (device, revision) => protocol.createOperation({
    operation: revision === 1 ? "create" : "update", objectId: `object-${device}`,
    fileId: `file-${device}`, versionId: `${device}-${revision}`,
    operationId: `operation-${device}-${revision}`, deviceId: device,
    keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: revision, deviceId: device },
    ...(revision > 1 ? { baseRevision: { counter: revision - 1, deviceId: device } } : {}),
    metadata: { path: `${device}.txt` }, plaintext: Buffer.from(device), fileKey: key,
  });
  for (const device of ["a", "b"]) {
    assert.equal((await store.put("alice", operation(device, 1))).kind, "stored");
    assert.equal((await store.put("alice", operation(device, 2))).kind, "stored");
  }
  clock += 1001;
  assert.equal((await store.put("alice", operation("c", 1))).kind, "stored");
  assert.equal((await store.put("alice", operation("c", 2))).kind, "stored");
});

test("two independently opened sync stores preserve both commits after stale instance writes", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-process-fence-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "objects.json");
  const first = await new SyncObjectStore(file).open();
  const second = await new SyncObjectStore(file).open();
  await first.transact((next) => { first.user(next, "alice").testIteration = 1; });
  await second.transact((next) => { second.user(next, "bob").testIteration = 1; });
  const stored = JSON.parse(await fs.readFile(file, "utf8"));
  assert.equal(stored.users.alice.testIteration, 1);
  assert.equal(stored.users.bob.testIteration, 1);
});

test("separate Node processes fence concurrent sync JSON writes and keep a monotonic result", { timeout: 20_000 }, async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-child-fence-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "objects.json");
  const fixture = path.join(__dirname, "..", "scripts", "fixtures", "sync-store-concurrent-child.js");
  const children = ["alice", "bob"].map((id) => fork(fixture, [file, id], { stdio: ["ignore", "pipe", "pipe", "ipc"], execArgv: [] }));
  t.after(() => children.forEach((child) => { if (child.exitCode === null) child.kill(); }));
  const results = children.map((child) => new Promise((resolve, reject) => {
    let output = "";
    child.stderr.on("data", (chunk) => { output += chunk.toString(); });
    child.on("message", (message) => {
      if (message?.type === "ready") child.send({ type: "go" });
      if (message?.type === "done") resolve();
    });
    child.on("exit", (code) => { if (code !== 0) reject(new Error(`child exit ${code}: ${output}`)); });
    child.on("error", reject);
  }));
  await Promise.all(results);
  const stored = JSON.parse(await fs.readFile(file, "utf8"));
  assert.equal(stored.users.alice.testIteration, 7);
  assert.equal(stored.users.bob.testIteration, 7);
});

test("an orphaned writer lock fails closed across restart without replacing the on-disk inventory", { timeout: 10_000 }, async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-orphan-lock-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "objects.json");
  const first = await new SyncObjectStore(file).open();
  await first.transact((next) => { first.user(next, "alice").testIteration = 0; });
  const before = await fs.readFile(file, "utf8");
  const handle = await fs.open(`${file}.writer-lock`, "wx");
  await handle.close(); // Simulates a crashed owner; no automatic stale-lock steal.
  const restarted = new SyncObjectStore(file);
  await assert.rejects(restarted.open(), { code: "SYNC_STORE_LOCK_BUSY" });
  await assert.rejects(first.transact((next) => { first.user(next, "alice").testIteration = 1; }), { code: "SYNC_STORE_LOCK_BUSY" });
  assert.equal(await fs.readFile(file, "utf8"), before);
  assert.equal((await fs.readdir(dir)).filter((name) => name.endsWith(".writer-lock")).length, 1);
});
