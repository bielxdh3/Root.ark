"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");

async function adapterFor(store, username, state) {
  return {
    async push(operation) {
      if (state.offline) throw Object.assign(new Error("offline"), { code: "offline" });
      const result = await store.put(username, operation);
      if (result.kind === "conflict" || result.kind === "stale") return { status: 409, currentRevision: result.current?.revision || null, current: result.current };
      if (result.kind === "replay") return { status: 409 };
      return { status: 201, record: result.record };
    },
    async list(objectId = "") {
      if (state.offline) throw Object.assign(new Error("offline"), { code: "offline" });
      return store.list(username, objectId || null);
    },
  };
}

async function engine(rootDir, adapter, key, options = {}) {
  return new SyncEngine({
    rootDir, adapter, deviceId: options.deviceId || "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: options.selectedPaths, excludedPaths: options.excludedPaths,
  }).open();
}

async function exists(filePath) {
  return fsp.lstat(filePath).then(() => true, () => false);
}

async function seed(dir, adapter, key, files) {
  const source = path.join(dir, "source");
  for (const [relative, body] of Object.entries(files)) {
    await fsp.mkdir(path.dirname(path.join(source, relative)), { recursive: true });
    await fsp.writeFile(path.join(source, relative), body);
  }
  await (await engine(source, adapter, key)).syncOnce();
}

function recordFor(store, relative) {
  return store.list("alice").find((record) => record.metadata.path === relative);
}

test("issue 66: excluded folders are not downloaded and keep their remote records", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-pull-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  await seed(dir, adapter, key, { "private/secret.txt": "secret", "shared/open.txt": "open" });
  const before = recordFor(store, "private/secret.txt");

  const root = path.join(dir, "device");
  const sync = await engine(root, adapter, key, { deviceId: "device-b", excludedPaths: ["private"] });
  const summary = await sync.syncOnce();

  assert.equal(await fsp.readFile(path.join(root, "shared", "open.txt"), "utf8"), "open");
  assert.equal(await exists(path.join(root, "private", "secret.txt")), false);
  assert.equal(sync.snapshot.remoteOnly[before.objectId].reason, "excluded");
  assert.deepEqual(sync.snapshot.excludedPaths, ["private"]);
  assert.equal(summary.pushed, 0);
  assert.equal(recordFor(store, "private/secret.txt").tombstone, false);
});

test("issue 66: excluded folders are never uploaded or deleted remotely on push", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-push-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  await seed(dir, adapter, key, { "private/secret.txt": "secret" });
  const before = recordFor(store, "private/secret.txt");

  const root = path.join(dir, "device");
  const sync = await engine(root, adapter, key, { deviceId: "device-b", excludedPaths: ["private"] });
  await fsp.mkdir(path.join(root, "private"), { recursive: true });
  await fsp.writeFile(path.join(root, "private", "local-only.txt"), "not for remote");
  const summary = await sync.syncOnce();

  assert.equal(summary.pushed, 0);
  assert.equal(recordFor(store, "private/local-only.txt"), undefined);
  assert.equal(recordFor(store, "private/secret.txt").tombstone, false);
  assert.equal(recordFor(store, "private/secret.txt").operationId, before.operationId);
});

test("issue 66: switching a folder to excluded evicts the clean local copy and keeps the remote object", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-switch-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  await seed(dir, adapter, key, { "private/secret.txt": "secret", "shared/open.txt": "open" });

  const root = path.join(dir, "device");
  await (await engine(root, adapter, key, { deviceId: "device-b" })).syncOnce();
  const before = recordFor(store, "private/secret.txt");
  assert.equal(await fsp.readFile(path.join(root, "private", "secret.txt"), "utf8"), "secret");

  const sync = await engine(root, adapter, key, { deviceId: "device-b", excludedPaths: ["private"] });
  const summary = await sync.syncOnce();

  assert.deepEqual(summary.excluded, { evicted: 1, released: 0, kept: [], failed: [] });
  assert.equal(await exists(path.join(root, "private", "secret.txt")), false);
  assert.equal(await fsp.readFile(path.join(root, "shared", "open.txt"), "utf8"), "open");
  const after = recordFor(store, "private/secret.txt");
  assert.equal(after.tombstone, false);
  assert.equal(after.operationId, before.operationId);
  assert.equal(sync.snapshot.remoteOnly[before.objectId].reason, "evicted");
  assert.equal(sync.snapshot.files["private/secret.txt"], undefined);
});

test("issue 66: a locally edited file in a newly excluded folder is kept and reported", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-kept-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  await seed(dir, adapter, key, { "private/secret.txt": "secret" });

  const root = path.join(dir, "device");
  await (await engine(root, adapter, key, { deviceId: "device-b" })).syncOnce();
  const before = recordFor(store, "private/secret.txt");
  await fsp.writeFile(path.join(root, "private", "secret.txt"), "local edit");

  const sync = await engine(root, adapter, key, { deviceId: "device-b", excludedPaths: ["private"] });
  const summary = await sync.syncOnce();

  assert.equal(await fsp.readFile(path.join(root, "private", "secret.txt"), "utf8"), "local edit");
  assert.deepEqual(summary.excluded, { evicted: 0, released: 0, kept: [{ path: "private/secret.txt", code: "local_changes_pending" }], failed: [] });
  assert.equal(summary.pushed, 0);
  assert.equal(recordFor(store, "private/secret.txt").operationId, before.operationId);
  assert.equal(recordFor(store, "private/secret.txt").tombstone, false);
});

test("issue 66: a folder excluded while its local copy is absent is released without a remote delete, then re-included", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-release-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  await seed(dir, adapter, key, { "private/secret.txt": "secret" });

  const root = path.join(dir, "device");
  await (await engine(root, adapter, key, { deviceId: "device-b" })).syncOnce();
  const before = recordFor(store, "private/secret.txt");
  await fsp.rm(path.join(root, "private", "secret.txt"));

  const sync = await engine(root, adapter, key, { deviceId: "device-b", excludedPaths: ["private"] });
  const summary = await sync.syncOnce();
  assert.deepEqual(summary.excluded, { evicted: 0, released: 1, kept: [], failed: [] });
  assert.equal(summary.pushed, 0);
  assert.equal(recordFor(store, "private/secret.txt").tombstone, false);
  assert.equal(sync.snapshot.remoteOnly[before.objectId].reason, "excluded");

  const reincluded = await engine(root, adapter, key, { deviceId: "device-b" });
  await reincluded.syncOnce();
  assert.equal(await fsp.readFile(path.join(root, "private", "secret.txt"), "utf8"), "secret");
  assert.equal(recordFor(store, "private/secret.txt").tombstone, false);
});

test("issue 66: excluded paths are validated and match whole path segments only", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-validate-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  const rootDir = path.join(dir, "device");
  const base = { rootDir, adapter, deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key };

  for (const unsafe of ["../escape", "/absolute", "a\\b", "a//b", ".rootark-sync.json", "CON", "trailing.", "x%2e"]) {
    assert.throws(() => new SyncEngine({ ...base, excludedPaths: [unsafe] }), (error) => error.code === "unsafe_path", unsafe);
  }
  assert.throws(() => new SyncEngine({ ...base, excludedPaths: "private" }), { code: "invalid_excluded_paths" });

  await seed(dir, adapter, key, { "private/secret.txt": "secret" });
  await (await engine(rootDir, adapter, key, { deviceId: "device-b", excludedPaths: ["priv"] })).syncOnce();
  assert.equal(await fsp.readFile(path.join(rootDir, "private", "secret.txt"), "utf8"), "secret");
});

async function exclusionFixture(t, name) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), `rootark-issue66-${name}-`));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  await seed(dir, adapter, key, { "private/secret.txt": "secret" });
  const root = path.join(dir, "device");
  await (await engine(root, adapter, key, { deviceId: "device-b" })).syncOnce();
  const before = recordFor(store, "private/secret.txt");
  return { key, store, adapter, root, before, localPath: path.join(root, "private", "secret.txt") };
}

function blockTrashRenames(t, failures) {
  const originalRename = fsp.rename;
  const state = { count: 0 };
  fsp.rename = async function injectedRename(from, to, ...rest) {
    if (String(to).includes(`${path.sep}.rootark-trash${path.sep}`)) {
      state.count += 1;
      if (state.count <= failures) throw Object.assign(new Error("injected EBUSY"), { code: "EBUSY" });
    }
    return originalRename.call(fsp, from, to, ...rest);
  };
  const restore = () => { fsp.rename = originalRename; };
  t.after(restore);
  return { state, restore };
}

test("issue 66: a transient eviction failure is retried on a later sync after restart", async (t) => {
  const { key, store, adapter, root, before, localPath } = await exclusionFixture(t, "retry-transient");
  const blocker = blockTrashRenames(t, 1);
  const first = await engine(root, adapter, key, { deviceId: "device-b", excludedPaths: ["private"] });
  const firstSummary = await first.syncOnce();
  blocker.restore();
  assert.deepEqual(firstSummary.excluded, { evicted: 0, released: 0, kept: [{ path: "private/secret.txt", code: "EBUSY" }], failed: [] });
  assert.equal(first.snapshot.pendingEvictions[before.objectId].attempts, 1);
  assert.equal(await fsp.readFile(localPath, "utf8"), "secret");

  const second = await engine(root, adapter, key, { deviceId: "device-b", excludedPaths: ["private"] });
  const secondSummary = await second.syncOnce();
  assert.deepEqual(secondSummary.excluded, { evicted: 1, released: 0, kept: [], failed: [] });
  assert.equal(await exists(localPath), false);
  assert.equal(second.snapshot.pendingEvictions, undefined);
  assert.equal(recordFor(store, "private/secret.txt").tombstone, false);
});

test("issue 66: a permanent eviction failure stops after the attempt bound and is reported, not looped", async (t) => {
  const { key, store, adapter, root, before, localPath } = await exclusionFixture(t, "retry-permanent");
  const blocker = blockTrashRenames(t, Number.POSITIVE_INFINITY);
  const reports = [];
  for (let cycle = 0; cycle < 6; cycle += 1) {
    const sync = await engine(root, adapter, key, { deviceId: "device-b", excludedPaths: ["private"] });
    reports.push((await sync.syncOnce()).excluded);
  }
  blocker.restore();
  assert.equal(blocker.state.count, 3);
  assert.deepEqual(reports[0].kept, [{ path: "private/secret.txt", code: "EBUSY" }]);
  assert.deepEqual(reports[2].failed, [{ path: "private/secret.txt", code: "EBUSY" }]);
  assert.deepEqual(reports[5].failed, [{ path: "private/secret.txt", code: "EBUSY" }]);
  assert.equal(await fsp.readFile(localPath, "utf8"), "secret");
  assert.equal(recordFor(store, "private/secret.txt").tombstone, false);
  assert.equal(recordFor(store, "private/secret.txt").operationId, before.operationId);
});

test("issue 66: a locally edited excluded file is reported once and never retried", async (t) => {
  const { key, store, adapter, root, localPath } = await exclusionFixture(t, "retry-local-edit");
  await fsp.writeFile(localPath, "local edit");
  const blocker = blockTrashRenames(t, 0);
  const first = await engine(root, adapter, key, { deviceId: "device-b", excludedPaths: ["private"] });
  const firstSummary = await first.syncOnce();
  const second = await engine(root, adapter, key, { deviceId: "device-b", excludedPaths: ["private"] });
  const secondSummary = await second.syncOnce();
  blocker.restore();
  assert.deepEqual(firstSummary.excluded.kept, [{ path: "private/secret.txt", code: "local_changes_pending" }]);
  assert.equal(first.snapshot.pendingEvictions, undefined);
  assert.equal(secondSummary.excluded, undefined);
  assert.equal(blocker.state.count, 0);
  assert.equal(await fsp.readFile(localPath, "utf8"), "local edit");
  assert.equal(recordFor(store, "private/secret.txt").tombstone, false);
});
