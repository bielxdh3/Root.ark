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

test("issue 66 W22 P2: portable case alias of excluded folder never uploads local bytes after restart", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-posix-excluded-egress-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  const root = path.join(dir, "device");
  await fsp.mkdir(path.join(root, "PRIVATE"), { recursive: true });
  await fsp.writeFile(path.join(root, "PRIVATE", "secret.txt"), "local confidential bytes");
  await fsp.mkdir(path.join(root, "public"), { recursive: true });
  await fsp.writeFile(path.join(root, "public", "safe.txt"), "public bytes");

  for (let restart = 0; restart < 2; restart += 1) {
    const client = await engine(root, adapter, key, { excludedPaths: ["private"] });
    const summary = await client.syncOnce();
    assert.equal(summary.pushed, restart === 0 ? 1 : 0,
      "only the non-excluded public file may be uploaded, including after restart");
    assert.equal(recordFor(store, "PRIVATE/secret.txt"), undefined);
    assert.equal(await fsp.readFile(path.join(root, "PRIVATE", "secret.txt"), "utf8"),
      "local confidential bytes");
  }
  assert.equal(recordFor(store, "public/safe.txt")?.tombstone, false);
});

test("issue 66 W22 P2: portable excluded case aliases are remote-only and never hydrated", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-posix-excluded-ingress-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  await seed(dir, adapter, key, { "PRIVATE/secret.txt": "remote confidential bytes", "public/safe.txt": "public bytes" });
  const remote = recordFor(store, "PRIVATE/secret.txt");
  const root = path.join(dir, "device");

  for (let restart = 0; restart < 2; restart += 1) {
    const client = await engine(root, adapter, key, { excludedPaths: ["private"] });
    const summary = await client.syncOnce();
    assert.equal(summary.pushed, 0);
    assert.equal(await exists(path.join(root, "PRIVATE", "secret.txt")), false);
    assert.equal(client.snapshot.remoteOnly[remote.objectId].reason, "excluded");
    assert.equal(await fsp.readFile(path.join(root, "public", "safe.txt"), "utf8"), "public bytes");
  }
  assert.equal(recordFor(store, "PRIVATE/secret.txt")?.tombstone, false);
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

test("issue 66 W22 P2: legacy persisted exclusion migrates tracked case aliases once, preserving edited and pinned bytes", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-exclusion-upgrade-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  await seed(dir, adapter, key, {
    "PRIVATE/clean.txt": "verified unchanged bytes",
    "PRIVATE/dirty.txt": "verified original bytes",
    "PRIVATE/pinned.txt": "verified pinned bytes",
    "public/open.txt": "allowed bytes",
  });
  const root = path.join(dir, "device");
  const legacy = await engine(root, adapter, key, { deviceId: "device-b" });
  await legacy.syncOnce();
  const tracked = legacy.snapshot.files["PRIVATE/pinned.txt"];
  const pinId = crypto.createHash("sha256").update(tracked.objectId, "utf8").digest("hex");
  legacy.snapshot.pinnedFiles = { [pinId]: {
    objectId: tracked.objectId, fileId: tracked.fileId, path: "PRIVATE/pinned.txt",
  } };
  // Before the portable DENY upgrade, this policy was considered applied:
  // the case-distinct file remained tracked and physically present on POSIX.
  legacy.snapshot.excludedPaths = ["private"];
  await legacy.persistSnapshot();
  await fsp.writeFile(path.join(root, "PRIVATE", "dirty.txt"), "unsynced confidential edits");
  const original = recordFor(store, "PRIVATE/clean.txt");

  const upgraded = await engine(root, adapter, key, {
    deviceId: "device-b", excludedPaths: ["private"],
  });
  const summary = await upgraded.syncOnce();
  assert.equal(summary.excluded.evicted, 1, "unchanged legacy alias must be evicted");
  assert.ok(summary.excluded.kept.some((item) =>
    item.path === "PRIVATE/dirty.txt" && item.code === "local_changes_pending"));
  assert.ok(summary.excluded.kept.some((item) =>
    item.path === "PRIVATE/pinned.txt" && item.code === "file_pinned"));
  assert.equal(await exists(path.join(root, "PRIVATE", "clean.txt")), false);
  assert.equal(await fsp.readFile(path.join(root, "PRIVATE", "dirty.txt"), "utf8"),
    "unsynced confidential edits");
  assert.equal(await fsp.readFile(path.join(root, "PRIVATE", "pinned.txt"), "utf8"),
    "verified pinned bytes");
  assert.equal(await fsp.readFile(path.join(root, "public", "open.txt"), "utf8"), "allowed bytes");
  assert.equal(upgraded.snapshot.remoteOnly[original.objectId].reason, "evicted");
  assert.equal(recordFor(store, "PRIVATE/clean.txt")?.operationId, original.operationId,
    "policy migration must never issue remote DELETE");
  assert.equal(upgraded.snapshot.excludedPathsCasefoldVersion, 2);

  const restarted = await engine(root, adapter, key, {
    deviceId: "device-b", excludedPaths: ["private"],
  });
  const repeated = await restarted.syncOnce();
  assert.equal(repeated.excluded, undefined, "completed migration must not retry dirty or pinned files forever");
  assert.equal(repeated.pushed, 0);
  assert.equal(await fsp.readFile(path.join(root, "PRIVATE", "dirty.txt"), "utf8"),
    "unsynced confidential edits");
});

test("issue 66 P2: legacy dirty case alias is evicted after its bytes are restored, without polling unchanged content", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-casefold-dirty-revert-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  const originalBytes = "verified original confidential bytes";
  await seed(dir, adapter, key, { "PRIVATE/secret.txt": originalBytes });

  const root = path.join(dir, "device");
  const original = await engine(root, adapter, key, { deviceId: "device-b" });
  await original.syncOnce();
  const tracked = original.snapshot.files["PRIVATE/secret.txt"];
  const remoteBefore = recordFor(store, "PRIVATE/secret.txt");
  original.snapshot.excludedPaths = ["private"];
  await original.persistSnapshot();
  const localPath = path.join(root, "PRIVATE", "secret.txt");
  await fsp.writeFile(localPath, "unsynced changes retained for the owner");

  const upgraded = await engine(root, adapter, key, {
    deviceId: "device-b", excludedPaths: ["private"],
  });
  const first = await upgraded.syncOnce();
  assert.deepEqual(first.excluded.kept, [{ path: "PRIVATE/secret.txt", code: "local_changes_pending" }]);
  assert.equal(upgraded.snapshot.excludedPathsCasefoldVersion, 2);
  assert.equal(upgraded.snapshot.pendingEvictions?.[tracked.objectId]?.code, "local_changes_pending",
    "the migration must retain durable intent to evict if the local bytes become clean");

  // A still-dirty excluded file should not be repeatedly read and hashed on
  // every ordinary sync. A metadata-only change check is sufficient here.
  const originalOpen = fsp.open;
  let reopenedLocalBytes = 0;
  fsp.open = async function inspectedOpen(filename, ...args) {
    if (path.resolve(String(filename)) === path.resolve(localPath)) reopenedLocalBytes += 1;
    return originalOpen.call(fsp, filename, ...args);
  };
  try {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const unchanged = await engine(root, adapter, key, {
        deviceId: "device-b", excludedPaths: ["private"],
      });
      const again = await unchanged.syncOnce();
      assert.equal(again.excluded, undefined, "unchanged dirty bytes should require no new eviction attempt");
    }
  } finally {
    fsp.open = originalOpen;
  }
  assert.equal(reopenedLocalBytes, 0);
  assert.equal(await fsp.readFile(localPath, "utf8"), "unsynced changes retained for the owner");

  await fsp.writeFile(localPath, "a second changed local version is also private");
  const editedAgain = await engine(root, adapter, key, {
    deviceId: "device-b", excludedPaths: ["private"],
  });
  const stillDirty = await editedAgain.syncOnce();
  assert.deepEqual(stillDirty.excluded.kept, [{ path: "PRIVATE/secret.txt", code: "local_changes_pending" }]);
  assert.equal(await fsp.readFile(localPath, "utf8"), "a second changed local version is also private");

  await fsp.writeFile(localPath, originalBytes);
  const restored = await engine(root, adapter, key, {
    deviceId: "device-b", excludedPaths: ["private"],
  });
  const recovered = await restored.syncOnce();
  assert.equal(recovered.excluded.evicted, 1, "restored verified bytes must be evicted on restart");
  assert.equal(recovered.pushed, 0);
  assert.equal(await exists(localPath), false);
  assert.equal(restored.snapshot.pendingEvictions, undefined);
  assert.equal(restored.snapshot.remoteOnly[tracked.objectId].reason, "evicted");
  const remoteAfter = recordFor(store, "PRIVATE/secret.txt");
  assert.equal(remoteAfter.operationId, remoteBefore.operationId);
  assert.equal(remoteAfter.tombstone, false, "no remote DELETE is permitted by a local exclusion");

  const restarted = await engine(root, adapter, key, {
    deviceId: "device-b", excludedPaths: ["private"],
  });
  assert.equal((await restarted.syncOnce()).excluded, undefined);
  assert.equal(await exists(localPath), false);
});

test("issue 66 P2: previously completed v1 migration rechecks stranded local case alias", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-casefold-v1-upgrade-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  const verified = "unchanged signed remote bytes";
  await seed(dir, adapter, key, { "PRIVATE/secret.txt": verified });

  const root = path.join(dir, "device");
  const original = await engine(root, adapter, key, { deviceId: "device-b" });
  await original.syncOnce();
  const tracked = original.snapshot.files["PRIVATE/secret.txt"];
  const remoteBefore = recordFor(store, "PRIVATE/secret.txt");
  const localPath = path.join(root, "PRIVATE", "secret.txt");
  await fsp.writeFile(localPath, "uncommitted private changes");
  // v1 incorrectly recorded completion even though a dirty file was kept.
  original.snapshot.excludedPaths = ["private"];
  original.snapshot.excludedPathsCasefoldVersion = 1;
  await original.persistSnapshot();

  const resumed = await engine(root, adapter, key, {
    deviceId: "device-b", excludedPaths: ["private"],
  });
  const upgraded = await resumed.syncOnce();
  assert.deepEqual(upgraded.excluded.kept, [{ path: "PRIVATE/secret.txt", code: "local_changes_pending" }]);
  assert.equal(resumed.snapshot.excludedPathsCasefoldVersion, 2);
  assert.equal(resumed.snapshot.pendingEvictions?.[tracked.objectId]?.code, "local_changes_pending");
  assert.equal(await fsp.readFile(localPath, "utf8"), "uncommitted private changes");

  await fsp.writeFile(localPath, verified);
  const restart = await engine(root, adapter, key, {
    deviceId: "device-b", excludedPaths: ["private"],
  });
  const clean = await restart.syncOnce();
  assert.equal(clean.excluded.evicted, 1);
  assert.equal(clean.pushed, 0);
  assert.equal(await exists(localPath), false);
  assert.equal(recordFor(store, "PRIVATE/secret.txt").operationId, remoteBefore.operationId);
  assert.equal(recordFor(store, "PRIVATE/secret.txt").tombstone, false);
});

test("issue 66 P2: casefold migration retries eviction when a guarded sync operation settles", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-casefold-pending-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  await seed(dir, adapter, key, { "PRIVATE/secret.txt": "remote confirmed data" });
  const root = path.join(dir, "device");
  const legacy = await engine(root, adapter, key, { deviceId: "device-b" });
  await legacy.syncOnce();
  const prior = legacy.snapshot.files["PRIVATE/secret.txt"];
  const remoteBefore = recordFor(store, "PRIVATE/secret.txt");
  const pending = await legacy.buildOperation({
    operation: "update", objectId: prior.objectId, fileId: prior.fileId,
    versionId: crypto.randomUUID(), baseRevision: prior.revision,
    revision: { counter: (prior.revision?.counter || 0) + 1, deviceId: "device-b" },
    metadata: { path: "PRIVATE/secret.txt", name: "secret.txt", size: 12 },
    plaintext: Buffer.from("local pending"), fileKey: key,
  });
  await legacy.journal.enqueue(pending);
  legacy.snapshot.excludedPaths = ["private"];
  legacy.snapshot.excludedPathsCasefoldVersion = 1;
  await legacy.persistSnapshot();

  const upgraded = await engine(root, adapter, key, {
    deviceId: "device-b", excludedPaths: ["private"],
  });
  const initially = await upgraded.syncOnce();
  assert.deepEqual(initially.excluded.kept, [{ path: "PRIVATE/secret.txt", code: "sync_operation_pending" }]);
  assert.equal(upgraded.snapshot.pendingEvictions?.[prior.objectId]?.code, "sync_operation_pending");
  assert.equal(await exists(path.join(root, "PRIVATE", "secret.txt")), true);

  // Independently settle the already queued local operation, as an explicit
  // owner action would do. Excluded writes must never be pushed remotely.
  await upgraded.journal.markSeen(pending.operationId);
  const restarted = await engine(root, adapter, key, {
    deviceId: "device-b", excludedPaths: ["private"],
  });
  const resumed = await restarted.syncOnce();
  assert.equal(resumed.excluded.evicted, 1);
  assert.equal(resumed.pushed, 0);
  assert.equal(await exists(path.join(root, "PRIVATE", "secret.txt")), false);
  assert.equal(recordFor(store, "PRIVATE/secret.txt").operationId, remoteBefore.operationId);
  assert.equal(recordFor(store, "PRIVATE/secret.txt").tombstone, false);
});

test("issue 66 W22 P2: old case-alias retry remains bounded after a transient eviction failure and restart", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-exclusion-retry-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  await seed(dir, adapter, key, { "PRIVATE/secret.txt": "verified confidential bytes" });
  const root = path.join(dir, "device");
  const legacy = await engine(root, adapter, key, { deviceId: "device-b" });
  await legacy.syncOnce();
  legacy.snapshot.excludedPaths = ["private"];
  await legacy.persistSnapshot();
  const marker = blockTrashRenames(t, Number.POSITIVE_INFINITY);
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const restarted = await engine(root, adapter, key, {
      deviceId: "device-b", excludedPaths: ["private"],
    });
    const summary = await restarted.syncOnce();
    assert.equal(restarted.snapshot.excludedPathsCasefoldVersion, 2);
    assert.equal(marker.state.count, Math.min(3, attempt));
    if (attempt >= 3) {
      assert.equal(summary.excluded.failed[0].code, "EBUSY");
    }
  }
  marker.restore();
  assert.equal(await fsp.readFile(path.join(root, "PRIVATE", "secret.txt"), "utf8"),
    "verified confidential bytes", "a failed eviction must preserve the local bytes");
  assert.equal(recordFor(store, "PRIVATE/secret.txt")?.tombstone, false);
});

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

test("issue 66: a locally edited excluded file is retained and watched without repeat eviction attempts", async (t) => {
  const { key, store, adapter, root, before, localPath } = await exclusionFixture(t, "retry-local-edit");
  await fsp.writeFile(localPath, "local edit");
  const blocker = blockTrashRenames(t, 0);
  const first = await engine(root, adapter, key, { deviceId: "device-b", excludedPaths: ["private"] });
  const firstSummary = await first.syncOnce();
  const second = await engine(root, adapter, key, { deviceId: "device-b", excludedPaths: ["private"] });
  const secondSummary = await second.syncOnce();
  blocker.restore();
  assert.deepEqual(firstSummary.excluded.kept, [{ path: "private/secret.txt", code: "local_changes_pending" }]);
  assert.equal(first.snapshot.pendingEvictions[before.objectId].code, "local_changes_pending");
  assert.equal(secondSummary.excluded, undefined);
  assert.equal(second.snapshot.pendingEvictions[before.objectId].localVersionStamp,
    first.snapshot.pendingEvictions[before.objectId].localVersionStamp);
  assert.equal(blocker.state.count, 0);
  assert.equal(await fsp.readFile(localPath, "utf8"), "local edit");
  assert.equal(recordFor(store, "private/secret.txt").tombstone, false);
});
