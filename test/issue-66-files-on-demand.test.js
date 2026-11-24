"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

async function setup(t, files) {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-on-demand-"));
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(directory, "objects.json")).open();
  const state = { offline: false, fullReads: [], inventoryReads: 0, pushes: 0 };
  const adapter = {
    async push(operation) {
      if (state.offline) throw Object.assign(new Error("offline"), { code: "offline" });
      state.pushes++;
      const result = await store.put("alice", operation);
      return { status: 201, record: result.record };
    },
    async list(objectId = "") {
      if (state.offline) throw Object.assign(new Error("offline"), { code: "offline" });
      state.fullReads.push(objectId || "ALL");
      return store.list("alice", objectId || null);
    },
    async listInventory({ limit = 64, cursor = null } = {}) {
      if (state.offline) throw Object.assign(new Error("offline"), { code: "offline" });
      state.inventoryReads++;
      const inventory = store.list("alice")
        .sort((a, b) => a.objectId.localeCompare(b.objectId))
        .map(({ ciphertext, nonce, tag, aad, authorization, ...record }) => record);
      const start = cursor === null ? 0 : Number(cursor);
      return { protocolVersion: 2, view: "metadata", objects: inventory.slice(start, start + limit),
        nextCursor: start + limit < inventory.length ? String(start + limit) : null };
    },
  };
  const source = path.join(directory, "source");
  for (const [relative, body] of Object.entries(files)) {
    await fsp.mkdir(path.dirname(path.join(source, relative)), { recursive: true });
    await fsp.writeFile(path.join(source, relative), body);
  }
  const writer = await new SyncEngine({
    rootDir: source, adapter, deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
  }).open();
  await writer.syncOnce();
  state.fullReads.length = 0;
  state.inventoryReads = 0;
  state.pushes = 0;
  const root = path.join(directory, "consumer");
  const open = (selectedPaths = ["docs"]) => new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key, selectedPaths,
    filesOnDemand: true,
  }).open();
  return { root, source, writer, open, adapter, state, store, key };
}

async function exists(filePath) {
  return fsp.stat(filePath).then(() => true, () => false);
}

test("issue 66 P2: successful FOD hydration removes private plaintext temporary", async (t) => {
  const { root, open, state } = await setup(t, { "docs/hydrate.txt": "signed remote content" });
  const consumer = await open();
  assert.equal(await consumer.materializeRemote("docs/hydrate.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "hydrate.txt"), "utf8"), "signed remote content");
  assert.deepEqual(await fsp.readdir(path.join(root, ".rootark-trash")), [],
    "verified success must not retain a private hydration hardlink");
  assert.deepEqual((await fsp.readdir(path.join(root, "docs"))).filter((name) => name.includes(".tmp-")), []);
  assert.equal(state.pushes, 0, "hydration must not create a remote upload");
});

test("issue 66 P2: verified repeated FOD CREATE is idempotent without staging clean bytes", async (t) => {
  const { root, open, state } = await setup(t, { "docs/repeat.txt": "signed creation bytes" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/repeat.txt"), true);
  const original = structuredClone(client.snapshot.files["docs/repeat.txt"]);
  assert.ok(original && !original.deleted && original.objectId && original.fileId);
  const originalBytes = await fsp.readFile(path.join(root, "docs", "repeat.txt"));
  assert.equal(await client.materializeRemote("docs/repeat.txt"), true,
    "a second authenticated read must not treat the clean cached pathname as an intruder");
  assert.deepEqual(client.snapshot.files["docs/repeat.txt"], original,
    "idempotence may not rewrite revision, object/file identity or hash");
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "repeat.txt")), originalBytes);
  assert.deepEqual(await fsp.readdir(path.join(root, ".rootark-trash")), [],
    "an authenticated no-op must not stage or replace the clean cache");
  assert.deepEqual(await client.journal.recover(), [], "no local CREATE outbox");
  assert.equal(state.pushes, 0);
});

test("issue 66 P2: first FOD CREATE cleanup failure cannot mint an untracked local CREATE", async (t) => {
  const { root, open, state } = await setup(t, { "docs/first.txt": "authenticated remote bytes" });
  const consumer = await open();
  const originalRm = fsp.rm;
  let cleanupAttempts = 0;
  fsp.rm = async (file, ...args) => {
    if (/^hydrate-[a-f0-9-]{36}\.tmp$/.test(path.basename(String(file)))) {
      cleanupAttempts++;
      throw Object.assign(new Error("simulated FOD CREATE cleanup EPERM"), { code: "EPERM" });
    }
    return originalRm(file, ...args);
  };
  try {
    await assert.rejects(consumer.materializeRemote("docs/first.txt"),
      (error) => error.code === "EPERM");
  } finally { fsp.rm = originalRm; }
  assert.equal(cleanupAttempts, 1, "must have reached the actual unlink after publication");
  const target = path.join(root, "docs", "first.txt");
  assert.equal(await fsp.readFile(target, "utf8"), "authenticated remote bytes");
  assert.equal((await fsp.lstat(target)).nlink, 2,
    "failed post-link cleanup must leave a physical hardlink guard, not an ordinary nlink=1 file");
  assert.equal(consumer.snapshot.files["docs/first.txt"]?.hash,
    crypto.createHash("sha256").update("authenticated remote bytes").digest("hex"),
    "the signed identity must be durably recorded before cleanup is attempted");
  assert.equal((await fsp.readdir(path.join(root, "docs")))
    .some((name) => name.includes(".tmp-")), false);
  assert.equal((await fsp.readdir(path.join(root, ".rootark-trash")))
    .filter((name) => /^hydrate-[a-f0-9-]{36}\.tmp$/.test(name)).length, 1);
  await assert.rejects(consumer.scanFiles(), (error) => error.code === "unsafe_path",
    "hardlink remains nlink=2 until evidence is resolved; never scan it as local CREATE");
  await assert.rejects(consumer.reconcileLocal(), (error) => error.code === "unsafe_path");
  assert.deepEqual(await consumer.journal.recover(), [], "no synthesized local CREATE outbox");
  assert.equal(state.pushes, 0, "no local upload may escape after cleanup failure");
  const restarted = await open();
  assert.equal(restarted.snapshot.files["docs/first.txt"]?.objectId,
    consumer.snapshot.files["docs/first.txt"].objectId,
    "cleanup failure after durable snapshot must keep its signed identity across restart");
  await assert.rejects(restarted.reconcileLocal(), { code: "unsafe_path" });
  assert.deepEqual(await restarted.journal.recover(), []);
});

test("issue 66 P2 RED: crash after FOD CREATE publication cannot enqueue local CREATE on restart", async (t) => {
  const body = "remote-authenticated-only; never a local user CREATE";
  const relative = "docs/postlink-crash.txt";
  const { root, open, state } = await setup(t, { [relative]: body });
  const consumer = await open();
  const target = path.join(root, "docs", "postlink-crash.txt");
  const originalPersist = consumer.persistSnapshot.bind(consumer);
  let injectedAfterPhysicalPublication = 0;

  // Simulate power loss at the REAL snapshot durability boundary, after the
  // signed remote ciphertext has materialized as a visible file. Do not fake
  // a local file or manufacture a journal entry: exercise the actual hardlink,
  // cleanup, restart and reconcile code paths.
  consumer.persistSnapshot = async (...args) => {
    if (!(await exists(target))) return originalPersist(...args);
    assert.equal(await fsp.readFile(target, "utf8"), body,
      "injection must follow real authenticated physical publication");
    injectedAfterPhysicalPublication++;
    throw Object.assign(new Error("injected crash before FOD snapshot fsync"), { code: "EIO" });
  };
  try {
    await assert.rejects(consumer.materializeRemote(relative),
      (error) => error.code === "EIO" && /before FOD snapshot fsync/.test(error.message));
  } finally {
    consumer.persistSnapshot = originalPersist;
  }
  assert.equal(injectedAfterPhysicalPublication, 1,
    "test must cross exactly one physical-publication-before-snapshot window");
  assert.equal(await fsp.readFile(target, "utf8"), body,
    "a crash may not destroy the signed remote content");

  // Reopening discards the prior instance's in-memory rememberOperation().
  // The pre-fix baseline removes the private link before durable snapshot,
  // leaving a nlink=1 target that turns into an unsolicited CREATE. The fix
  // must retain nlink=2 until the snapshot is safely written.
  const restarted = await open();
  assert.equal(restarted.snapshot.files[relative], undefined,
    "failed snapshot fsync must not create a durable signed cache entry");
  let scanErrorCode = null;
  try { await restarted.scanFiles(); }
  catch (error) { scanErrorCode = error.code; if (error.code !== "unsafe_path") throw error; }
  let reconcileErrorCode = null;
  try { await restarted.reconcileLocal(); }
  catch (error) { reconcileErrorCode = error.code; if (error.code !== "unsafe_path") throw error; }
  const pending = await restarted.journal.recover();
  const synthesizedCreates = pending.filter((item) => item.operation === "create"
    && item.metadata?.path === relative);
  // On the pre-fix HEAD, the calls above really enqueue the unsolicited
  // CREATE; assert that fact FIRST so the RED demonstrates the bad effect,
  // rather than short-circuiting on a missing nlink=2 guard assertion.
  assert.deepEqual(synthesizedCreates, [],
    "RED on ccbc028b: restart reconciliation must NOT enqueue a user CREATE for remotely hydrated bytes");
  assert.equal((await fsp.lstat(target)).nlink, 2,
    "a crash after publication must leave a private hardlink guard");
  assert.equal(scanErrorCode, "unsafe_path",
    "a remote orphan with retained private alias must be refused by the sync scanner");
  assert.equal(reconcileErrorCode, "unsafe_path",
    "restart reconciliation must fail closed before creating any local operation");
  assert.equal(state.pushes, 0, "no remote upload may occur after interrupted hydration");
});

test("issue 66 P2: CREATE and UPDATE retain private hardlink until signed snapshot is durable", async (t) => {
  const relative = "docs/durable.txt";
  const { root, source, writer, open, state } = await setup(t,
    { [relative]: "version 1 signed by remote" });
  const consumer = await open();
  const target = path.join(root, "docs", "durable.txt");
  const trashDir = path.join(root, ".rootark-trash");
  const originalPersist = consumer.persistSnapshot.bind(consumer);
  let verifiedAtPersist = 0;
  consumer.persistSnapshot = async (...args) => {
    if (await exists(target)) {
      const aliases = (await fsp.readdir(trashDir)).filter((name) =>
        /^hydrate-[a-f0-9-]{36}\.tmp$/.test(name));
      assert.equal(aliases.length, 1,
        "a real private hydration alias must remain through snapshot persistence");
      assert.equal((await fsp.lstat(target)).nlink, 2,
        "published bytes must remain unscannable until signed identity is durable");
      verifiedAtPersist++;
    }
    return originalPersist(...args);
  };
  assert.equal(await consumer.materializeRemote(relative), true);
  const first = structuredClone(consumer.snapshot.files[relative]);
  assert.equal(verifiedAtPersist, 1);
  assert.equal((await fsp.lstat(target)).nlink, 1,
    "successful snapshot persist must be followed by private-alias removal");
  assert.deepEqual((await fsp.readdir(trashDir)).filter((name) => name.startsWith("hydrate-")), []);
  await fsp.writeFile(path.join(source, relative), "version 2 signed by remote");
  await writer.syncOnce();
  state.pushes = 0;
  assert.equal(await consumer.materializeRemote(relative), true);
  assert.equal(verifiedAtPersist, 2, "UPDATE must obey the same durable-publication ordering");
  assert.notEqual(consumer.snapshot.files[relative].versionId, first.versionId);
  assert.equal(await fsp.readFile(target, "utf8"), "version 2 signed by remote");
  assert.equal((await fsp.lstat(target)).nlink, 1);
  assert.deepEqual((await fsp.readdir(trashDir)).filter((name) => name.startsWith("hydrate-")), []);
  const restarted = await open();
  await restarted.reconcileLocal();
  assert.deepEqual(await restarted.journal.recover(), []);
  assert.equal(state.pushes, 0);
});

test("issue 66 P2: hydration cleanup EPERM cannot return success or leak syncable CREATE", async (t) => {
  const { root, source, writer, open, state } = await setup(t,
    { "docs/cleanup.txt": "signed remote content" });
  const consumer = await open();
  assert.equal(await consumer.materializeRemote("docs/cleanup.txt"), true);
  const previousSnapshot = structuredClone(consumer.snapshot.files["docs/cleanup.txt"]);
  await fsp.writeFile(path.join(source, "docs", "cleanup.txt"), "new signed remote content");
  await writer.syncOnce();
  state.pushes = 0;
  const originalRm = fsp.rm;
  let intercepted = 0;
  fsp.rm = async (file, ...rest) => {
    if (path.basename(String(file)).startsWith("hydrate-")) {
      intercepted++;
      throw Object.assign(new Error("simulated hydration cleanup denied"), { code: "EPERM" });
    }
    return originalRm(file, ...rest);
  };
  try {
    await assert.rejects(consumer.materializeRemote("docs/cleanup.txt"),
      (error) => error.code === "EPERM",
      "failing finally/unlink must propagate without falsely reporting hydration success");
  } finally { fsp.rm = originalRm; }
  assert.equal(intercepted, 1, "the real private cleanup call must have been reached");
  assert.notEqual(consumer.snapshot.files["docs/cleanup.txt"]?.versionId, previousSnapshot.versionId,
    "signed UPDATE snapshot must be durable before attempting private alias cleanup");
  const restarted = await open();
  assert.deepEqual(restarted.snapshot.files["docs/cleanup.txt"],
    consumer.snapshot.files["docs/cleanup.txt"], "restart must retain the signed UPDATE identity");
  assert.equal(state.pushes, 0);
  assert.deepEqual((await fsp.readdir(path.join(root, "docs"))).filter((name) => name.includes(".tmp-")), []);
  const trashDir = path.join(root, ".rootark-trash");
  const trashNames = await fsp.readdir(trashDir);
  assert.equal(trashNames.filter((name) => /^hydrate-[a-f0-9-]{36}\.tmp$/.test(name)).length, 1);
  const olderCache = await Promise.all(trashNames
    .filter((name) => !/^hydrate-[a-f0-9-]{36}\.tmp$/.test(name))
    .map((name) => fsp.readFile(path.join(trashDir, name), "utf8")));
  assert.ok(olderCache.includes("signed remote content"),
    "previous clean cached bytes must remain recoverable after failed hydration cleanup");
  assert.equal(await fsp.readFile(path.join(root, "docs", "cleanup.txt"), "utf8"),
    "new signed remote content", "new materialization is not destroyed on cleanup failure");
  await assert.rejects(consumer.scanFiles(), (error) => error.code === "unsafe_path",
    "hardlinked target with an unresolved private alias must fail closed");
  await assert.rejects(restarted.reconcileLocal(), { code: "unsafe_path" });
  assert.deepEqual(await restarted.journal.recover(), []);
});

test("issue 66 P2: interrupted FOD temp write is never scanned as ordinary CREATE", async (t) => {
  const { root, open, state } = await setup(t, { "docs/interrupted.txt": "signed remote content" });
  const consumer = await open();
  const originalWrite = fsp.writeFile;
  const originalRm = fsp.rm;
  let intercepted = 0;
  let cleanupSuppressed = 0;
  // Model a process halt before its finally/unlink can complete: retaining
  // the actual already-written temporary instead of manufacturing a fixture.
  fsp.rm = async (file, ...rest) => {
    if (/^(hydrate-[a-f0-9-]{36}\.tmp|interrupted\.txt\.tmp-)/
      .test(path.basename(String(file)))) {
      cleanupSuppressed++;
      return;
    }
    return originalRm(file, ...rest);
  };
  fsp.writeFile = async (file, data, ...rest) => {
    if ((/^hydrate-[a-f0-9-]{36}\.tmp$/.test(path.basename(String(file)))
      || /^interrupted\.txt\.tmp-/.test(path.basename(String(file))))
      && Buffer.isBuffer(data)) {
      await originalWrite(file, data, ...rest);
      intercepted++;
      throw new Error("simulated interruption immediately after private temp write");
    }
    return originalWrite(file, data, ...rest);
  };
  try {
    await assert.rejects(consumer.materializeRemote("docs/interrupted.txt"), /simulated interruption/);
  } finally {
    fsp.writeFile = originalWrite;
    fsp.rm = originalRm;
  }
  assert.equal(intercepted, 1);
  assert.equal(cleanupSuppressed, 1);
  assert.equal(state.pushes, 0);
  assert.deepEqual((await fsp.readdir(path.join(root, "docs"))).filter((name) => name.includes(".tmp-")), []);
  assert.equal((await fsp.readdir(path.join(root, ".rootark-trash")))
    .filter((name) => /^hydrate-[a-f0-9-]{36}\.tmp$/.test(name)).length, 1);
  const scanned = await consumer.scanFiles();
  assert.equal(scanned["docs/interrupted.txt"], undefined);
  assert.equal(Object.keys(scanned).some((name) => name.includes(".tmp-")
    || name.startsWith(".rootark-trash")), false,
  "uncommitted plaintext residue must be outside the sync inventory");
});

async function seedRemote(store, key, relative, objectId = `external-${crypto.randomUUID()}`) {
  const operation = protocol.createOperation({
    operation: "create", objectId, fileId: `file-${crypto.randomUUID()}`,
    versionId: `version-${crypto.randomUUID()}`, operationId: `operation-${crypto.randomUUID()}`,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: relative, name: path.posix.basename(relative), size: 15 },
    plaintext: Buffer.from("remote original"), fileKey: key,
  });
  assert.equal((await store.put("alice", operation)).kind, "stored");
  return operation;
}

test("issue 66 P2: a fresh local CREATE cannot duplicate an existing remote opaque path", async (t) => {
  const { root, open, store, key, state } = await setup(t, {});
  const remote = await seedRemote(store, key, "docs/collision.txt");
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "collision.txt"), "different local content");
  const client = await open();
  await assert.rejects(client.syncOnce(), { code: "remote_path_collision" });
  assert.equal(state.pushes, 0, "no CREATE may be sent before remote-path preflight");
  assert.equal(state.fullReads.length, 0, "preflight must not fetch the full ciphertext inventory");
  assert.equal(store.list("alice").length, 1);
  assert.equal(store.list("alice")[0].operationId, remote.operationId);
  assert.equal(await fsp.readFile(path.join(root, "docs", "collision.txt"), "utf8"), "different local content");
  await assert.rejects(client.materializeRemote("docs/collision.txt"), { code: "local_changes_pending" });
  const resumed = await open();
  await assert.rejects(resumed.syncOnce(), { code: "remote_path_collision" });
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 1);
});

test("issue 66 P2: tombstoned remote path does not block a new Files On-Demand CREATE", async (t) => {
  const { root, open, store, key, state } = await setup(t, {});
  const original = await seedRemote(store, key, "docs/reused.txt");
  const removed = protocol.createOperation({
    operation: "delete", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: original.revision,
    metadata: { path: "docs/reused.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", removed)).kind, "stored");
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "reused.txt"), "new independent local file");
  const client = await open();
  const summary = await client.syncOnce();
  assert.equal(summary.pushed, 1);
  assert.equal(state.pushes, 1);
  assert.equal((await client.journal.recover()).length, 0);
  const versions = store.list("alice");
  assert.equal(versions.filter((record) => !record.tombstone && record.metadata.path === "docs/reused.txt").length, 1);
  assert.equal(versions.filter((record) => record.tombstone).length, 1);
});

test("issue 66 P2: an offline CREATE stays queued; reconnect rechecks remote identity before push", async (t) => {
  const { root, open, store, state, key } = await setup(t, {});
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "collision.txt"), "local offline version");
  state.offline = true;
  const offline = await open();
  assert.equal((await offline.syncOnce()).offline, true);
  assert.equal(state.pushes, 0);
  assert.equal((await offline.journal.recover()).length, 1);
  await seedRemote(store, key, "docs/collision.txt");
  state.offline = false;
  const restarted = await open();
  await assert.rejects(restarted.syncOnce(), { code: "remote_path_collision" });
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 1);
  assert.equal((await restarted.journal.recover()).length, 1);
});

test("issue 66 P2: stale or invalid paged inventory fails closed before CREATE, then retries", async (t) => {
  const { root, open, adapter, store, key, state } = await setup(t, {});
  await seedRemote(store, key, "docs/other.txt");
  await seedRemote(store, key, "docs/collision.txt");
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "collision.txt"), "local same path");
  const listInventory = adapter.listInventory;
  adapter.listInventory = async (params) => {
    const page = await listInventory({ ...params, limit: 1 });
    if (params.cursor !== null) throw Object.assign(new Error("stale inventory cursor"), { status: 409 });
    return page;
  };
  const client = await open();
  await assert.rejects(client.syncOnce(), { code: "inventory_changed" });
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 2);
  assert.equal((await client.journal.recover()).length, 1,
    "stale inventory must not consume or mark the queued CREATE seen");
  adapter.listInventory = listInventory;
  await assert.rejects((await open()).syncOnce(), { code: "remote_path_collision" });
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 2);
});

test("issue 66 P2: unrelated local CREATE still publishes after a clean metadata preflight", async (t) => {
  const { root, open, store, key, state } = await setup(t, {});
  await seedRemote(store, key, "docs/existing.txt");
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "new.txt"), "brand new");
  const client = await open();
  const summary = await client.syncOnce();
  assert.equal(summary.pushed, 1);
  assert.equal(state.pushes, 1);
  assert.equal(state.fullReads.length, 0);
  assert.deepEqual(store.list("alice").map((r) => r.metadata.path).sort(),
    ["docs/existing.txt", "docs/new.txt"]);
});

test("issue 66: lazy sync pages metadata and hydrates only the selected signed object", async (t) => {
  const { root, open, state, store } = await setup(t, {
    "docs/a.txt": "first payload", "docs/b.txt": "second payload", "private/secret.txt": "private",
  });
  const client = await open();
  const summary = await client.syncOnce();
  assert.equal(summary.pulled, 0);
  assert.equal(summary.available, 2);
  assert.ok(state.inventoryReads >= 1);
  assert.deepEqual(state.fullReads, []);
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  assert.equal(await exists(path.join(root, "docs", "b.txt")), false);
  const listing = await client.browseRemoteInventory({ limit: 2 });
  assert.equal(listing.objects.length, 2);
  assert.equal(listing.objects.every((record) =>
    record.selectedOnDevice === record.metadata.path.startsWith("docs/")), true);
  assert.equal(Object.keys(client.snapshot.remoteOnly).length, 0, "unsigned inventory cannot create durable pins");

  assert.equal(await client.materializeRemote("docs/b.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "b.txt"), "utf8"), "second payload");
  const objectId = store.list("alice").find((item) => item.metadata.path === "docs/b.txt").objectId;
  assert.deepEqual(state.fullReads, [objectId]);
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  await assert.rejects(client.materializeRemote("private/secret.txt"), { code: "path_not_selected" });

  state.offline = true;
  assert.equal((await client.syncOnce()).offline, true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "b.txt"), "utf8"), "second payload");
  assert.equal(store.list("alice").every((item) => item.tombstone === false), true);
});

test("issue 66: forged inventory, races, and preexisting local data fail closed", async (t) => {
  const { root, open, adapter, state } = await setup(t, { "docs/a.txt": "authentic" });
  const client = await open();
  const listInventory = adapter.listInventory;
  adapter.listInventory = async (request) => {
    const result = await listInventory(request);
    return { ...result, objects: result.objects.map((item) => ({
      ...item, versionId: "forged-version",
    })) };
  };
  await assert.rejects(client.materializeRemote("docs/a.txt"), { code: "inventory_changed" });
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  adapter.listInventory = listInventory;

  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "a.txt"), "unsynced local data");
  await assert.rejects(client.materializeRemote("docs/a.txt"), { code: "local_changes_pending" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "a.txt"), "utf8"), "unsynced local data");
  await fsp.unlink(path.join(root, "docs", "a.txt"));

  const originalList = adapter.list;
  adapter.list = async (id) => (await originalList(id)).map((operation) => ({
    ...operation, ciphertext: Buffer.from("corrupt encrypted bytes").toString("base64url"),
  }));
  await assert.rejects(client.materializeRemote("docs/a.txt"));
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  assert.equal(Object.keys(client.snapshot.files).length, 0);
  assert.ok(state.fullReads.length > 0);
});

test("issue 66: duplicate inventory paths refuse ambiguous hydration", async (t) => {
  const { root, open, adapter, state } = await setup(t, {
    "docs/a.txt": "one", "docs/b.txt": "two",
  });
  const listInventory = adapter.listInventory;
  adapter.listInventory = async (request) => {
    const page = await listInventory(request);
    return { ...page, objects: page.objects.map((entry) => ({
      ...entry, metadata: { ...entry.metadata, path: "docs/a.txt" },
    })) };
  };
  const client = await open();
  await assert.rejects(client.materializeRemote("docs/a.txt"), { code: "remote_object_ambiguous" });
  assert.deepEqual(state.fullReads, []);
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
});

test("issue 66: hydration finds a file on later inventory pages without downloading siblings", async (t) => {
  const { root, open, adapter, state } = await setup(t, {
    "docs/a.txt": "one", "docs/b.txt": "two", "docs/c.txt": "three",
  });
  const listInventory = adapter.listInventory;
  adapter.listInventory = (request) => listInventory({ ...request, limit: 1 });
  const client = await open();
  assert.equal((await client.syncOnce()).available, 3);
  assert.equal(await client.materializeRemote("docs/c.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "c.txt"), "utf8"), "three");
  assert.equal(state.fullReads.length, 1);
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
});

test("issue 66: verified cache eviction survives offline and hydrates again after reconnect", async (t) => {
  const { root, open, store, state } = await setup(t, { "docs/cache.txt": "cache me" });
  const client = await open();
  await client.materializeRemote("docs/cache.txt");
  const before = store.list("alice")[0];
  assert.equal(await client.evictLocal("docs/cache.txt"), true);
  assert.equal(await exists(path.join(root, "docs", "cache.txt")), false);
  state.offline = true;
  assert.equal((await client.syncOnce()).offline, true);
  await assert.rejects(client.materializeRemote("docs/cache.txt"), { code: "offline" });
  assert.equal(client.snapshot.remoteOnly[before.objectId].reason, "evicted");
  assert.equal(store.list("alice")[0].operationId, before.operationId);
  state.offline = false;
  const restarted = await open();
  assert.equal(await restarted.materializeRemote("docs/cache.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "cache.txt"), "utf8"), "cache me");
  assert.equal(restarted.snapshot.remoteOnly[before.objectId], undefined);
});

test("issue 66 P2: verified evicted A can hydrate a later remote MOVE at B", async (t) => {
  const { root, open, store, key, adapter } = await setup(t,
    { "docs/a.txt": "original verified bytes" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/a.txt"), true);
  const earlier = store.list("alice")[0];
  assert.equal(await client.evictLocal("docs/a.txt"), true);
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  const moved = protocol.createOperation({
    operation: "move", objectId: earlier.objectId, fileId: earlier.fileId,
    versionId: `moved-${crypto.randomUUID()}`, operationId: `moved-${crypto.randomUUID()}`,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: earlier.revision,
    revision: { counter: earlier.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/b.txt", sourcePath: "docs/a.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("original verified bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const inventory = await client.syncOnce();
  assert.equal(inventory.available, 1);
  assert.equal(store.list("alice").find((item) => item.objectId === earlier.objectId).operationId,
    moved.operationId, "local reconciliation may publish a directory, never replace the remote moved file");
  const originalInventory = adapter.listInventory;
  adapter.listInventory = async (options) => {
    const page = await originalInventory(options);
    return { ...page, objects: page.objects.map((row) => row.objectId === earlier.objectId
      ? { ...row, fileId: "unrelated-file" } : row) };
  };
  await assert.rejects(client.materializeRemote("docs/b.txt"),
    { code: "remote_object_changed" },
    "an advisory MOVE that changes the evicted file identity cannot rebind the cache");
  adapter.listInventory = originalInventory;
  await fsp.writeFile(path.join(root, "docs", "b.txt"), "offline independent local bytes");
  await assert.rejects(client.materializeRemote("docs/b.txt"),
    { code: "local_changes_pending" },
    "hydrating a verified remote MOVE must never overwrite an untracked destination");
  assert.equal(await fsp.readFile(path.join(root, "docs", "b.txt"), "utf8"),
    "offline independent local bytes");
  await fsp.unlink(path.join(root, "docs", "b.txt"));
  assert.equal(await client.materializeRemote("docs/b.txt"), true,
    "new destination must recover from the AEAD MOVE payload after A was evicted");
  assert.equal(await fsp.readFile(path.join(root, "docs", "b.txt"), "utf8"),
    "original verified bytes");
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  assert.equal(client.snapshot.files["docs/b.txt"].objectId, earlier.objectId);
  assert.equal(client.snapshot.remoteOnly[earlier.objectId], undefined);
  assert.equal((await client.journal.recover()).length, 0);
});

test("issue 66 #263 P2: evicted A hydrates an authenticated MOVE then UPDATE at B", async (t) => {
  const { root, store, key, adapter } = await setup(t,
    { "docs/a.txt": "original evicted bytes" });
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trust = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] };
  const originalList = adapter.list.bind(adapter);
  const signedByOperationId = new Map();
  adapter.list = async (objectId) => Promise.all((await originalList(objectId)).map(async (entry) => {
    if (!signedByOperationId.has(entry.operationId)) {
      signedByOperationId.set(entry.operationId, {
        ...entry, authorization: await createAuthorizationProof(entry, {
          username: "alice", publicKey, privateKey: signer.privateKey, expiresAt: Date.now() + 60000,
        }),
      });
    }
    return signedByOperationId.get(entry.operationId);
  }));
  let verified = 0;
  const client = await new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: async (operation) => {
      const result = await verifyAuthorizationProof(operation.authorization, operation, trust);
      if (result) verified++;
      return result;
    },
  }).open();
  assert.equal(await client.materializeRemote("docs/a.txt"), true);
  const first = store.list("alice")[0];
  assert.equal(await client.evictLocal("docs/a.txt"), true);
  const moved = protocol.createOperation({
    operation: "move", objectId: first.objectId, fileId: first.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: first.revision,
    revision: { counter: first.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/b.txt", sourcePath: "docs/a.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("original evicted bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const updated = protocol.createOperation({
    operation: "update", objectId: first.objectId, fileId: first.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: moved.revision,
    revision: { counter: moved.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/b.txt" },
    plaintext: Buffer.from("authenticated B"), fileKey: key,
  });
  assert.equal((await store.put("alice", updated)).kind, "stored");
  const realInventory = adapter.listInventory;
  adapter.listInventory = async (options) => {
    const page = await realInventory(options);
    return { ...page, objects: page.objects.map((row) => row.objectId === first.objectId
      ? { ...row, fileId: "forged-unrelated-file" } : row) };
  };
  await assert.rejects(client.materializeRemote("docs/b.txt"),
    { code: "remote_object_changed" }, "a changed file identity cannot relocate evicted cache");
  assert.equal(await exists(path.join(root, "docs", "b.txt")), false);
  adapter.listInventory = realInventory;
  assert.equal(await client.materializeRemote("docs/b.txt"), true);
  assert.ok(verified >= 2, "initial A and relocated UPDATE B require actual trusted Ed25519 verification");
  assert.equal(await fsp.readFile(path.join(root, "docs", "b.txt"), "utf8"), "authenticated B");
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  assert.equal(client.snapshot.files["docs/b.txt"].versionId, updated.versionId);
  assert.equal(client.snapshot.remoteOnly[first.objectId], undefined);
});

test("issue 66: refreshes clean cached bytes, preserves dirty cached bytes", async (t) => {
  const { root, source, writer, open } = await setup(t, { "docs/version.txt": "version one" });
  const client = await open();
  await client.materializeRemote("docs/version.txt");
  await fsp.writeFile(path.join(source, "docs", "version.txt"), "version two");
  await writer.syncOnce();
  assert.equal(await client.materializeRemote("docs/version.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "version.txt"), "utf8"), "version two");

  await fsp.writeFile(path.join(root, "docs", "version.txt"), "offline local changes");
  await fsp.writeFile(path.join(source, "docs", "version.txt"), "version three");
  await writer.syncOnce();
  await assert.rejects(client.materializeRemote("docs/version.txt"), { code: "local_changes_pending" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "version.txt"), "utf8"), "offline local changes");
});

test("issue 66: local changes during remote fetch cannot be overwritten", async (t) => {
  const { root, source, writer, open, adapter } = await setup(t, { "docs/race.txt": "clean cached" });
  const client = await open();
  await client.materializeRemote("docs/race.txt");
  await fsp.writeFile(path.join(source, "docs", "race.txt"), "new remote version");
  await writer.syncOnce();
  const oldList = adapter.list;
  adapter.list = async (objectId) => {
    const response = await oldList(objectId);
    await fsp.writeFile(path.join(root, "docs", "race.txt"), "edited during network request");
    return response;
  };
  await assert.rejects(client.materializeRemote("docs/race.txt"), { code: "local_changes_pending" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "race.txt"), "utf8"), "edited during network request");
});

test("issue 66 #263 P2: UPDATE same-path stage-time local edit is not overwritten", async (t) => {
  const { root, source, writer, open, state } = await setup(t,
    { "docs/stage-race.txt": "clean cached A" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/stage-race.txt"), true);
  const target = path.join(root, "docs", "stage-race.txt");
  const prior = structuredClone(client.snapshot.files["docs/stage-race.txt"]);
  await fsp.writeFile(path.join(source, "docs", "stage-race.txt"), "authenticated B");
  await writer.syncOnce();
  state.pushes = 0;
  const actualStage = client.stageExisting.bind(client);
  let stagedTarget = 0;
  client.stageExisting = async (filePath) => {
    if (filePath === target) {
      stagedTarget++;
      await fsp.writeFile(target, "edited exactly before rename");
    }
    return actualStage(filePath);
  };
  await assert.rejects(client.materializeRemote("docs/stage-race.txt"),
    { code: "local_changes_pending" });
  assert.equal(stagedTarget, 1, "race must exercise the target staging boundary");
  assert.equal(await fsp.readFile(target, "utf8"), "edited exactly before rename");
  assert.deepEqual(client.snapshot.files["docs/stage-race.txt"], prior,
    "failed UPDATE must leave the local tracked revision unchanged");
  assert.equal(state.pushes, 0, "recovery must not push a replacement CREATE");
});

test("issue 66 #263 P2: UPDATE rejects same-inode writes between staged stat observations", async (t) => {
  const { root, source, writer, open } = await setup(t,
    { "docs/version-race.txt": "original clean version A" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/version-race.txt"), true);
  const target = path.join(root, "docs", "version-race.txt");
  const previous = structuredClone(client.snapshot.files["docs/version-race.txt"]);
  await fsp.writeFile(path.join(source, "docs", "version-race.txt"), "remote verified version B");
  await writer.syncOnce();
  const realOpen = fsp.open;
  let stagedHandleStats = 0;
  let injected = 0;
  fsp.open = async (filename, ...options) => {
    const handle = await realOpen(filename, ...options);
    const stagedPath = String(filename);
    if (stagedPath.startsWith(path.join(root, ".rootark-trash") + path.sep)) {
      const realStat = handle.stat.bind(handle);
      handle.stat = async (...statOptions) => {
        const observed = await realStat(...statOptions);
        stagedHandleStats++;
        if (stagedHandleStats === 2) {
          // Return the pre-edit handle stat, but alter the same inode before
          // the subsequent staged-path lstat. Identity alone still matches;
          // only a final version comparison detects this write.
          injected++;
          await fsp.writeFile(stagedPath,
            "concurrent local write after staged handle.readFile with different size");
        }
        return observed;
      };
    }
    return handle;
  };
  try {
    await assert.rejects(client.materializeRemote("docs/version-race.txt"),
      { code: "local_changes_pending" });
  } finally { fsp.open = realOpen; }
  assert.equal(injected, 1, "race must occur after the real second handle.stat and before final path lstat");
  assert.equal(await fsp.readFile(target, "utf8"),
    "concurrent local write after staged handle.readFile with different size",
    "the local writer's post-read bytes must be restored rather than overwritten");
  assert.deepEqual(client.snapshot.files["docs/version-race.txt"], previous);
});

test("issue 66 #263 P2: UPDATE refuses a local file recreated after verified staging", async (t) => {
  const { root, source, writer, open } = await setup(t, { "docs/recreated.txt": "cached version A" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/recreated.txt"), true);
  const previous = structuredClone(client.snapshot.files["docs/recreated.txt"]);
  await fsp.writeFile(path.join(source, "docs", "recreated.txt"), "remote version B");
  await writer.syncOnce();
  const target = path.join(root, "docs", "recreated.txt");
  const actualStage = client.stageCleanTrackedFile.bind(client);
  let postStageRaces = 0;
  client.stageCleanTrackedFile = async (relativePath, tracked) => {
    const staged = await actualStage(relativePath, tracked);
    if (relativePath === "docs/recreated.txt") {
      postStageRaces++;
      await fsp.writeFile(target, "new local writer after stage");
    }
    return staged;
  };
  await assert.rejects(client.materializeRemote("docs/recreated.txt"),
    { code: "local_changes_pending" });
  assert.equal(postStageRaces, 1, "the race must occur after the real verified staging");
  assert.equal(await fsp.readFile(target, "utf8"), "new local writer after stage",
    "exclusive publication cannot overwrite the recreated destination");
  assert.deepEqual(client.snapshot.files["docs/recreated.txt"], previous);
  const trash = path.join(root, ".rootark-trash");
  const preserved = await Promise.all((await fsp.readdir(trash)).map(
    async (file) => fsp.readFile(path.join(trash, file), "utf8")));
  assert.ok(preserved.includes("cached version A"), "old clean tracked bytes must remain recoverable");
});

test("issue 66 #263 P2: UPDATE refuses deletion after clean preflight before target stage", async (t) => {
  const { root, source, writer, open } = await setup(t, { "docs/late-delete.txt": "cached A" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/late-delete.txt"), true);
  const before = structuredClone(client.snapshot.files["docs/late-delete.txt"]);
  await fsp.writeFile(path.join(source, "docs", "late-delete.txt"), "remote version B");
  await writer.syncOnce();
  const target = path.join(root, "docs", "late-delete.txt");
  const originalApply = client._apply.bind(client);
  let removedAfterPreflight = 0;
  client._apply = (operation, summary, beforeWrite, tombstone) => originalApply(operation, summary,
    async () => {
      await beforeWrite();
      if (operation.operation === "update" && removedAfterPreflight === 0) {
        removedAfterPreflight++;
        await fsp.unlink(target);
      }
    }, tombstone);
  await assert.rejects(client.materializeRemote("docs/late-delete.txt"),
    { code: "local_changes_pending" });
  assert.equal(removedAfterPreflight, 1, "local deletion must occur after final verified preflight");
  assert.equal(await exists(target), false,
    "remote data cannot silently replace the user's local deletion");
  assert.deepEqual(client.snapshot.files["docs/late-delete.txt"], before);
});

test("issue 66: a remote MOVE must not relocate unsynced local source bytes", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/original.txt": "original verified bytes" });
  const client = await open();
  await client.materializeRemote("docs/original.txt");
  const before = store.list("alice")[0];
  const move = protocol.createOperation({
    operation: "move", objectId: before.objectId, fileId: before.fileId,
    versionId: "on-demand-move-v2", operationId: "on-demand-move-v2-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: before.revision, revision: { counter: before.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/renamed.txt", sourcePath: "docs/original.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("original verified bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", move)).kind, "stored");
  await fsp.writeFile(path.join(root, "docs", "original.txt"), "unsynced edits");
  await assert.rejects(client.materializeRemote("docs/renamed.txt"), { code: "local_changes_pending" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "original.txt"), "utf8"), "unsynced edits");
  assert.equal(await exists(path.join(root, "docs", "renamed.txt")), false);
});

test("issue 66 P2 signed MOVE: fileId rotation cannot erase an unsynced local deletion", async (t) => {
  const dir = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA, "rootark-signed-move-rotation-" + crypto.randomBytes(8).toString("hex"))
    : await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-signed-move-rotation-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(dir);
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const root = path.join(dir, "client");
  const store = await new SyncObjectStore(path.join(dir, "objects.json"),
    { atomicDeviceRegistry: true }).open();
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trust = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  await store.enrollDevice({ username: "alice", deviceId: "device-a", publicKey, expectedEpoch: 0 });
  const sign = async (op) => {
    const signed = { ...op, authorization: await createAuthorizationProof(op, {
      username: "alice", publicKey, privateKey: signer.privateKey,
      expiresAt: Date.now() + 60_000,
    }) };
    assert.equal(await verifyAuthorizationProof(signed.authorization, signed, trust), true);
    return signed;
  };
  const objectId = "obj-" + crypto.randomUUID();
  const fileId = "file-old-" + crypto.randomUUID();
  const create = await sign(protocol.createOperation({
    operation: "create", objectId, fileId, versionId: crypto.randomUUID(),
    operationId: crypto.randomUUID(), deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "docs/source.txt" }, plaintext: Buffer.from("cached A"),
    fileKey: key,
  }));
  assert.equal((await store.put("alice", create)).kind, "stored");
  const adapter = {
    async push(operation) { return (await store.put("alice", operation)).record; },
    async list(objectId = "") { return store.list("alice", objectId || null); },
    async listInventory() {
      const objects = store.list("alice").map(
        ({ ciphertext, nonce, tag, aad, authorization, ...record }) => record);
      return { protocolVersion: 2, view: "metadata", objects, nextCursor: null };
    },
  };
  let verified = 0;
  const client = await new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: async (op) => {
      const accepted = await verifyAuthorizationProof(op.authorization, op, trust);
      if (accepted) verified += 1;
      return accepted;
    },
  }).open();
  assert.equal(await client.materializeRemote("docs/source.txt"), true);
  assert.ok(verified >= 1, "real signed CREATE must pass through strict verification");
  await fsp.unlink(path.join(root, "docs", "source.txt"));
  assert.equal(client.snapshot.files["docs/source.txt"].fileId, fileId);

  const nextFileId = "file-new-" + crypto.randomUUID();
  const update = await sign(protocol.createOperation({
    operation: "update", objectId, fileId: nextFileId, versionId: crypto.randomUUID(),
    operationId: crypto.randomUUID(), deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", baseRevision: create.revision,
    revision: { counter: 2, deviceId: "device-a" },
    metadata: { path: "docs/source.txt" }, plaintext: Buffer.from("remote B"),
    fileKey: key,
  }));
  assert.equal((await store.put("alice", update)).kind, "stored",
    "real atomic device registry must accept the signed fileId rotation");
  const move = await sign(protocol.createOperation({
    operation: "move", objectId, fileId: nextFileId, versionId: crypto.randomUUID(),
    operationId: crypto.randomUUID(), deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", baseRevision: update.revision,
    revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "docs/moved.txt", sourcePath: "docs/source.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("remote B"), key), fileKey: key,
  }));
  assert.equal((await store.put("alice", move)).kind, "stored",
    "MOVE must be signed and admitted after signed UPDATE under real atomic registry");
  await assert.rejects(client.materializeRemote("docs/moved.txt"),
    { code: "local_changes_pending" },
    "a stale tracked objectId may not lose an unsynced deletion via fileId rotation");
  assert.equal(await exists(path.join(root, "docs", "moved.txt")), false);
  assert.equal(client.snapshot.files["docs/source.txt"].fileId, fileId);
  assert.equal(client.snapshot.files["docs/moved.txt"], undefined);
  assert.deepEqual(await client.journal.recover(), []);
  assert.equal(store.list("alice", objectId)[0].operationId, move.operationId);
});

for (const explicitlyEvicted of [false, true]) {
test("issue 66 P2 signed MOVE: " + (explicitlyEvicted ? "explicit eviction can move" : "missing tracked source preserves local deletion"), async (t) => {
  const content = Buffer.from("genuine Ed25519 signed MOVE payload");
  const { root, adapter, store, key } = await setup(t, { "docs/source.txt": content });
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trust = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  const signed = new Map();
  const sign = async (op) => {
    if (!signed.has(op.operationId)) {
      signed.set(op.operationId, { ...op, authorization: await createAuthorizationProof(op,
        { username: "alice", publicKey, privateKey: signer.privateKey, expiresAt: Date.now() + 60000 }) });
    }
    return signed.get(op.operationId);
  };
  const strictAdapter = { ...adapter,
    list: async (objectId) => Promise.all((await adapter.list(objectId)).map(sign)) };
  let verified = 0;
  const client = await new SyncEngine({
    rootDir: root, adapter: strictAdapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: async (op) => {
      const result = await verifyAuthorizationProof(op.authorization, op, trust);
      if (result) verified++;
      return result;
    },
  }).open();
  assert.equal(await client.materializeRemote("docs/source.txt"), true);
  const prior = store.list("alice")[0];
  if (explicitlyEvicted) {
    assert.equal(await client.evictLocal("docs/source.txt"), true);
    assert.equal(client.snapshot.remoteOnly[prior.objectId].reason, "evicted");
  } else {
    await fsp.unlink(path.join(root, "docs", "source.txt"));
    assert.equal(client.snapshot.files["docs/source.txt"].objectId, prior.objectId);
  }
  const moved = protocol.createOperation({
    operation: "move", objectId: prior.objectId, fileId: prior.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: prior.revision,
    revision: { counter: prior.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/moved.txt", sourcePath: "docs/source.txt" },
    plaintext: protocol.encodeMovePayload(content, key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  assert.equal(await verifyAuthorizationProof((await sign(moved)).authorization,
    await sign(moved), trust), true, "genuine owner-signed MOVE proof");
  if (explicitlyEvicted) {
    assert.equal(await client.materializeRemote("docs/moved.txt"), true);
    assert.deepEqual(await fsp.readFile(path.join(root, "docs", "moved.txt")), content);
  } else {
    await assert.rejects(client.materializeRemote("docs/moved.txt"),
      { code: "local_changes_pending" });
    assert.equal(await exists(path.join(root, "docs", "moved.txt")), false);
    assert.equal(client.snapshot.files["docs/source.txt"].objectId, prior.objectId);
    assert.equal(client.snapshot.files["docs/moved.txt"], undefined);
    assert.deepEqual(await client.journal.recover(), []);
  }
  assert.ok(verified >= (explicitlyEvicted ? 2 : 1), "strict Ed25519 verifier must authenticate every operation reaching admission");
});
}

test("issue 66: a clean cached source can be hydrated through a verified remote MOVE", async (t) => {
  const { root, open, store, key, state } = await setup(t, { "docs/original.txt": "signed move bytes" });
  const client = await open();
  await client.materializeRemote("docs/original.txt");
  const before = store.list("alice")[0];
  assert.equal((await store.put("alice", protocol.createOperation({
    operation: "move", objectId: before.objectId, fileId: before.fileId,
    versionId: "on-demand-good-move", operationId: "on-demand-good-move-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: before.revision, revision: { counter: before.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/renamed.txt", sourcePath: "docs/original.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("signed move bytes"), key), fileKey: key,
  }))).kind, "stored");
  const target = path.join(root, "docs", "renamed.txt");
  const originalPersist = client.persistSnapshot.bind(client);
  let persistedWithGuard = 0;
  client.persistSnapshot = async (...args) => {
    if (await exists(target)) {
      const aliases = (await fsp.readdir(path.join(root, ".rootark-trash")))
        .filter((name) => name.startsWith(".rootark-move-"));
      assert.equal(aliases.length, 1, "MOVE must retain its actual private publication alias");
      assert.equal((await fsp.lstat(target)).nlink, 2,
        "MOVE must be unscannable until its signed snapshot is durable");
      persistedWithGuard++;
    }
    return originalPersist(...args);
  };
  assert.equal(await client.materializeRemote("docs/renamed.txt"), true);
  assert.equal(persistedWithGuard, 1);
  assert.equal(await fsp.readFile(path.join(root, "docs", "renamed.txt"), "utf8"), "signed move bytes");
  assert.equal(await exists(path.join(root, "docs", "original.txt")), false);
  assert.equal((await fsp.lstat(target)).nlink, 1);
  assert.deepEqual((await fsp.readdir(path.join(root, ".rootark-trash")))
    .filter((name) => name.startsWith(".rootark-move-")), []);
  const restarted = await open();
  await restarted.reconcileLocal();
  assert.deepEqual(await restarted.journal.recover(), []);
  assert.equal(state.pushes, 0);
});

test("issue 66 P2: crash after signed FOD MOVE publication remains guarded across restart", async (t) => {
  const { root, open, store, key, state } = await setup(t,
    { "docs/original.txt": "old signed bytes" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/original.txt"), true);
  const before = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: before.objectId, fileId: before.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: before.revision,
    revision: { counter: before.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/renamed.txt", sourcePath: "docs/original.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("new signed move bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const target = path.join(root, "docs", "renamed.txt");
  let injected = 0;
  client.persistSnapshot = async () => {
    assert.equal(await fsp.readFile(target, "utf8"), "new signed move bytes");
    injected++;
    throw Object.assign(new Error("injected FOD MOVE post-link crash"), { code: "EIO" });
  };
  await assert.rejects(client.materializeRemote("docs/renamed.txt"), { code: "EIO" });
  assert.equal(injected, 1, "must reach snapshot boundary after real MOVE publication");
  assert.equal((await fsp.lstat(target)).nlink, 2);
  const oldCopies = await Promise.all((await fsp.readdir(path.join(root, ".rootark-trash")))
    .filter((name) => !name.startsWith(".rootark-move-"))
    .map((name) => fsp.readFile(path.join(root, ".rootark-trash", name), "utf8")));
  assert.ok(oldCopies.includes("old signed bytes"), "staged source remains recoverable after crash");
  const restarted = await open();
  assert.equal(restarted.snapshot.files["docs/renamed.txt"], undefined);
  await assert.rejects(restarted.scanFiles(), { code: "unsafe_path" });
  await assert.rejects(restarted.reconcileLocal(), { code: "unsafe_path" });
  assert.deepEqual(await restarted.journal.recover(), []);
  assert.equal(state.pushes, 0);
});

test("issue 66 P2: verified FOD MOVE cleanup failure cannot claim hydration success", async (t) => {
  const { root, open, store, key, state } = await setup(t,
    { "docs/original.txt": "signed move bytes" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/original.txt"), true);
  const before = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: before.objectId, fileId: before.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: before.revision, revision: {
      counter: before.revision.counter + 1, deviceId: "device-a",
    },
    metadata: { path: "docs/renamed.txt", sourcePath: "docs/original.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("signed move bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const originalRm = fsp.rm;
  let intercepted = 0;
  fsp.rm = async (file, ...rest) => {
    if (path.basename(String(file)).startsWith(".rootark-move-")) {
      intercepted++;
      throw Object.assign(new Error("simulated FOD MOVE unlink denial"), { code: "EPERM" });
    }
    return originalRm(file, ...rest);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/renamed.txt"),
      (error) => error.code === "EPERM");
  } finally { fsp.rm = originalRm; }
  assert.equal(intercepted, 1);
  assert.equal(state.pushes, 0);
  assert.equal(await exists(path.join(root, "docs", "original.txt")), false,
    "signed MOVE source is staged until the new signed snapshot is durable");
  assert.equal(await fsp.readFile(path.join(root, "docs", "renamed.txt"), "utf8"),
    "signed move bytes", "newly linked bytes must not be silently destroyed");
  assert.equal(client.snapshot.files["docs/renamed.txt"]?.versionId, moved.versionId,
    "MOVE identity must be durably recorded before final alias cleanup");
  assert.equal((await fsp.lstat(path.join(root, "docs", "renamed.txt"))).nlink, 2,
    "failed cleanup must leave the MOVE destination unscannable");
  assert.equal((await fsp.readdir(path.join(root, "docs")))
    .filter((name) => name.startsWith(".rootark-move-")).length, 0,
    "verified MOVE may not leak plaintext staging into the syncable path");
  const trashNames = await fsp.readdir(path.join(root, ".rootark-trash"));
  assert.equal(trashNames.filter((name) => name.startsWith(".rootark-move-")).length, 1,
    "unremoved private temp must remain outside inventory");
  const olderCopies = await Promise.all(trashNames.filter((name) =>
    !name.startsWith(".rootark-move-")).map((name) =>
    fsp.readFile(path.join(root, ".rootark-trash", name), "utf8")));
  assert.ok(olderCopies.includes("signed move bytes"),
    "old cached source must stay recoverable in private trash after cleanup failure");
  const restarted = await open();
  assert.equal(restarted.snapshot.files["docs/renamed.txt"]?.versionId, moved.versionId);
  await assert.rejects(restarted.reconcileLocal(), { code: "unsafe_path" });
  assert.deepEqual(await restarted.journal.recover(), []);
});

test("issue 66 P2: interrupted FOD MOVE plaintext write stays outside sync inventory", async (t) => {
  const { root, open, store, key, state } = await setup(t,
    { "docs/from.txt": "clean authenticated bytes" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/from.txt"), true);
  const prior = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: prior.objectId, fileId: prior.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: prior.revision,
    revision: { counter: prior.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/to.txt", sourcePath: "docs/from.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("clean authenticated bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const originalWrite = fsp.writeFile;
  const originalRm = fsp.rm;
  let wrote = 0;
  let leftBehind = 0;
  fsp.writeFile = async (file, data, ...args) => {
    if (path.basename(String(file)).startsWith(".rootark-move-") && Buffer.isBuffer(data)) {
      await originalWrite(file, data, ...args);
      wrote += 1;
      throw new Error("simulated MOVE process death immediately after temp write");
    }
    return originalWrite(file, data, ...args);
  };
  fsp.rm = async (file, ...args) => {
    if (path.basename(String(file)).startsWith(".rootark-move-")) {
      leftBehind += 1;
      return;
    }
    return originalRm(file, ...args);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/to.txt"), /simulated MOVE process death/);
  } finally {
    fsp.writeFile = originalWrite;
    fsp.rm = originalRm;
  }
  assert.equal(wrote, 1);
  assert.equal(leftBehind, 1);
  assert.equal(await fsp.readFile(path.join(root, "docs", "from.txt"), "utf8"),
    "clean authenticated bytes", "failed MOVE must restore clean original bytes");
  assert.equal(await exists(path.join(root, "docs", "to.txt")), false);
  assert.equal((await fsp.readdir(path.join(root, "docs")))
    .filter((name) => name.startsWith(".rootark-move-")).length, 0);
  assert.equal((await fsp.readdir(path.join(root, ".rootark-trash")))
    .filter((name) => name.startsWith(".rootark-move-")).length, 1);
  const scan = await client.scanFiles();
  assert.equal(Object.keys(scan).some((name) => name.includes(".rootark-move-")), false);
  assert.equal(state.pushes, 0);
});

test("issue 66 #263 P2: MOVE returns to a clean cached destination without treating it as untracked", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/b.txt": "clean cached revision A" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/b.txt"), true);
  const first = store.list("alice")[0];
  const update = protocol.createOperation({
    operation: "update", objectId: first.objectId, fileId: first.fileId,
    operationId: crypto.randomUUID(), versionId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: first.revision,
    revision: { counter: first.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/b.txt" }, plaintext: Buffer.from("revision B"), fileKey: key,
  });
  assert.equal((await store.put("alice", update)).kind, "stored");
  const toC = protocol.createOperation({
    operation: "move", objectId: first.objectId, fileId: first.fileId,
    operationId: crypto.randomUUID(), versionId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: update.revision,
    revision: { counter: update.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/c.txt", sourcePath: "docs/b.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("revision B"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", toC)).kind, "stored");
  const backToB = protocol.createOperation({
    operation: "move", objectId: first.objectId, fileId: first.fileId,
    operationId: crypto.randomUUID(), versionId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: toC.revision,
    revision: { counter: toC.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/b.txt", sourcePath: "docs/c.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("revision C now back at B"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", backToB)).kind, "stored");
  assert.equal(await client.materializeRemote("docs/b.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "b.txt"), "utf8"),
    "revision C now back at B");
  assert.equal(client.snapshot.files["docs/b.txt"].versionId, backToB.versionId);
  assert.equal(await exists(path.join(root, "docs", "c.txt")), false);
  const oldVersions = await Promise.all((await fsp.readdir(path.join(root, ".rootark-trash")))
    .map(async (entry) => fsp.readFile(path.join(root, ".rootark-trash", entry), "utf8")));
  assert.ok(oldVersions.includes("clean cached revision A"), "old clean destination must survive in trash");
  assert.equal(await client.materializeRemote("docs/b.txt"), true,
    "a second authenticated materialization of the same MOVE must be idempotent");
  assert.equal(await fsp.readFile(path.join(root, "docs", "b.txt"), "utf8"),
    "revision C now back at B");
});

test("issue 66 #263 P2: authenticated signed MOVE publishes B after remote UPDATE and preserves clean A", async (t) => {
  const { root, adapter, store, key } = await setup(t, { "docs/old.txt": "cached revision A" });
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trust = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] };
  const originalList = adapter.list.bind(adapter);
  const signedByOperationId = new Map();
  let verified = 0;
  adapter.list = async (objectId) => Promise.all((await originalList(objectId)).map(async (entry) => {
    if (!signedByOperationId.has(entry.operationId)) {
      signedByOperationId.set(entry.operationId, {
        ...entry, authorization: await createAuthorizationProof(entry, {
          username: "alice", publicKey, privateKey: signer.privateKey,
          expiresAt: Date.now() + 60000,
        }),
      });
    }
    return signedByOperationId.get(entry.operationId);
  }));
  const client = await new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: async (operation) => {
      const result = await verifyAuthorizationProof(operation.authorization, operation, trust);
      if (result) verified++;
      return result;
    },
  }).open();
  assert.equal(await client.materializeRemote("docs/old.txt"), true);
  const first = store.list("alice")[0];
  const updated = protocol.createOperation({
    operation: "update", objectId: first.objectId, fileId: first.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: first.revision,
    revision: { counter: first.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/old.txt" }, plaintext: Buffer.from("remote revision B"), fileKey: key,
  });
  assert.equal((await store.put("alice", updated)).kind, "stored");
  const moved = protocol.createOperation({
    operation: "move", objectId: first.objectId, fileId: first.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: updated.revision,
    revision: { counter: updated.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("remote revision B"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  assert.equal(await client.materializeRemote("docs/new.txt"), true);
  assert.ok(verified >= 2, "both initial CREATE and moved B must pass trusted Ed25519 verification");
  assert.equal(await fsp.readFile(path.join(root, "docs", "new.txt"), "utf8"), "remote revision B");
  assert.equal(await exists(path.join(root, "docs", "old.txt")), false);
  const trash = path.join(root, ".rootark-trash");
  const preserved = await Promise.all((await fsp.readdir(trash)).map(
    async (file) => fsp.readFile(path.join(trash, file), "utf8")));
  assert.ok(preserved.includes("cached revision A"), "clean old revision A must remain recoverable in trash");
  assert.equal(client.snapshot.files["docs/new.txt"].versionId, moved.versionId);
  assert.equal(client.snapshot.files["docs/old.txt"], undefined);
  assert.deepEqual(await client.journal.recover(), []);
});

test("issue 66 #263 P2: MOVE staging cannot overwrite a racing local destination", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/old.txt": "safe cached A" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/old.txt"), true);
  const first = store.list("alice")[0];
  const move = protocol.createOperation({
    operation: "move", objectId: first.objectId, fileId: first.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: first.revision,
    revision: { counter: first.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("remote B"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", move)).kind, "stored");
  const sourcePath = path.join(root, "docs", "old.txt");
  const destinationPath = path.join(root, "docs", "new.txt");
  const originalStage = client.stageExisting.bind(client);
  let sourceStaged = 0;
  client.stageExisting = async (target) => {
    if (target === sourcePath) {
      sourceStaged++;
      await fsp.writeFile(destinationPath, "racing local destination");
    }
    return originalStage(target);
  };
  await assert.rejects(client.materializeRemote("docs/new.txt"), { code: "local_changes_pending" });
  assert.equal(sourceStaged, 1, "race must occur during verified source staging");
  assert.equal(await fsp.readFile(sourcePath, "utf8"), "safe cached A",
    "the clean source must be restored after a blocked publication");
  assert.equal(await fsp.readFile(destinationPath, "utf8"), "racing local destination");
  assert.equal(client.snapshot.files["docs/old.txt"].versionId, first.versionId);
  assert.equal(client.snapshot.files["docs/new.txt"], undefined);
  assert.equal(client.journal.hasSeen(move.operationId), false);
});

test("issue 66 #263 P2: MOVE publication refuses a destination created after staging", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/old.txt": "clean cached A" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/old.txt"), true);
  const first = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: first.objectId, fileId: first.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: first.revision,
    revision: { counter: first.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("verified B"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const destination = path.join(root, "docs", "new.txt");
  const originalLink = fsp.link;
  let lateWriter = 0;
  fsp.link = async (from, to) => {
    if (to === destination && lateWriter === 0) {
      lateWriter++;
      await fsp.writeFile(destination, "local file after empty check");
    }
    return originalLink(from, to);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/new.txt"),
      { code: "local_changes_pending" });
  } finally { fsp.link = originalLink; }
  assert.equal(lateWriter, 1, "late local writer must race the exclusive publication itself");
  assert.equal(await fsp.readFile(destination, "utf8"), "local file after empty check");
  assert.equal(await fsp.readFile(path.join(root, "docs", "old.txt"), "utf8"), "clean cached A");
  assert.equal(client.snapshot.files["docs/new.txt"], undefined);
  assert.equal(client.snapshot.files["docs/old.txt"].versionId, first.versionId);
  assert.equal(client.journal.hasSeen(moved.operationId), false);
});

test("issue 66 #263 P2: evicted MOVE refuses a destination created after preflight", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/source.txt": "evicted A" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/source.txt"), true);
  const original = store.list("alice")[0];
  assert.equal(await client.evictLocal("docs/source.txt"), true);
  const move = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/destination.txt", sourcePath: "docs/source.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("remote B"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", move)).kind, "stored");
  const destination = path.join(root, "docs", "destination.txt");
  const actualApply = client._apply.bind(client);
  let raced = 0;
  client._apply = (op, summary, beforeWrite, tombstoneSource) => actualApply(op, summary,
    async () => {
      await beforeWrite();
      if (op.operation === "move" && raced === 0) {
        raced++;
        await fsp.writeFile(destination, "new local file after preflight");
      }
    }, tombstoneSource);
  await assert.rejects(client.materializeRemote("docs/destination.txt"),
    { code: "local_changes_pending" });
  assert.equal(raced, 1, "new local destination must arrive after the verified preflight");
  assert.equal(await fsp.readFile(destination, "utf8"), "new local file after preflight");
  assert.equal(client.snapshot.remoteOnly[original.objectId].reason, "evicted");
  assert.equal(client.snapshot.files["docs/destination.txt"], undefined);
  assert.equal(client.journal.hasSeen(move.operationId), false);
});

test("issue 66 #263 P2: restoration cannot clobber a file recreated after its existence check", async (t) => {
  const { root, open } = await setup(t, { "docs/source.txt": "original staged cache" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/source.txt"), true);
  const source = path.join(root, "docs", "source.txt");
  const staged = await client.stageExisting(source);
  assert.ok(staged, "positive setup must stage the actual cached file to trash");
  assert.equal(await exists(source), false);
  const originalLink = fsp.link;
  const originalRename = fsp.rename;
  let recreated = 0;
  const race = async (operation, from, to) => {
    if (from === staged && to === source && recreated === 0) {
      recreated++;
      await fsp.writeFile(source, "recreated by local writer");
    }
    return operation(from, to);
  };
  fsp.link = (from, to) => race(originalLink, from, to);
  fsp.rename = (from, to) => race(originalRename, from, to);
  try {
    await assert.rejects(client.restoreStagedTrackedFile("docs/source.txt", staged),
      { code: "local_changes_pending" });
  } finally {
    fsp.link = originalLink;
    fsp.rename = originalRename;
  }
  assert.equal(recreated, 1, "race must occur at the actual filesystem publication call");
  assert.equal(await fsp.readFile(source, "utf8"), "recreated by local writer");
  assert.equal(await fsp.readFile(staged, "utf8"), "original staged cache",
    "old staged bytes must survive collision for recovery");
});

for (const changedFileId of [false, true]) {
test(`issue 66 #263 P2: signed old inventory cannot roll back newer object with ${changedFileId ? "changed" : "stable"} fileId`, async (t) => {
  const { root, source, writer, store, key, adapter } = await setup(t,
    { "docs/replay.txt": "authentic revision A" });
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trust = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  const expiry = Date.now() + 60_000;
  const signed = new Map();
  const sign = async (operation) => {
    if (!signed.has(operation.operationId)) {
      signed.set(operation.operationId, {
        ...operation, authorization: await createAuthorizationProof(operation,
          { username: "alice", publicKey, privateKey: pair.privateKey, expiresAt: expiry }),
      });
    }
    return signed.get(operation.operationId);
  };
  const liveList = adapter.list.bind(adapter);
  const strictAdapter = { ...adapter,
    list: async (objectId) => Promise.all((await liveList(objectId)).map(sign)),
  };
  const client = await new SyncEngine({
    rootDir: root, adapter: strictAdapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: (operation) => verifyAuthorizationProof(
      operation.authorization, operation, trust),
  }).open();
  assert.equal(await client.materializeRemote("docs/replay.txt"), true);
  const revisionA = await sign(store.list("alice")[0]);
  assert.equal(await verifyAuthorizationProof(revisionA.authorization, revisionA, trust), true);
  const firstSnapshot = client.snapshot.files["docs/replay.txt"];

  if (changedFileId) {
    assert.equal(await client.evictLocal("docs/replay.txt"), true,
      "evict authentic A before the signed successor replaces its file identity");
    const next = protocol.createOperation({
      operation: "update", objectId: revisionA.objectId,
      fileId: `new-file-${crypto.randomUUID()}`,
      versionId: `new-version-${crypto.randomUUID()}`,
      operationId: `new-operation-${crypto.randomUUID()}`,
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
      baseRevision: revisionA.revision,
      revision: { counter: revisionA.revision.counter + 1, deviceId: "device-a" },
      metadata: { path: "docs/replay.txt" },
      plaintext: Buffer.from("authentic revision B"), fileKey: key,
    });
    assert.equal((await store.put("alice", next)).kind, "stored",
      "real legacy fixture store preserves a newer revision with changed fileId");
    assert.equal(await verifyAuthorizationProof((await sign(next)).authorization,
      await sign(next), trust), true,
    "client admission later receives genuine Ed25519-signed B, not a forged metadata claim");
  } else {
    await fsp.writeFile(path.join(source, "docs", "replay.txt"), "authentic revision B");
    await writer.syncOnce();
  }
  const revisionB = await sign(store.list("alice")[0]);
  assert.equal(await verifyAuthorizationProof(revisionB.authorization, revisionB, trust), true);
  assert.equal(revisionB.objectId, revisionA.objectId);
  assert.equal(revisionB.fileId === revisionA.fileId, !changedFileId);
  assert.ok(protocol.compareRevisions(revisionB.revision, revisionA.revision) > 0);
  assert.equal(await client.materializeRemote("docs/replay.txt"), true);
  const before = client.snapshot.files["docs/replay.txt"];
  assert.ok(protocol.compareRevisions(before.revision, firstSnapshot.revision) > 0);
  assert.equal(await fsp.readFile(path.join(root, "docs", "replay.txt"), "utf8"),
    "authentic revision B");

  // Replaying A involves a GENUINE owner-enrolled Ed25519 signature over the
  // old full ciphertext, together with internally consistent old inventory.
  // It is not a tampered AAD/invalid-signature canary.
  const { ciphertext, nonce, tag, aad, authorization, ...oldInventory } = revisionA;
  const liveSignedList = strictAdapter.list;
  const liveInventory = strictAdapter.listInventory;
  assert.equal(await client.evictLocal("docs/replay.txt"), true,
    "positive setup: current B is durably evicted with a pinned revision floor");
  const evictedB = { ...client.snapshot.remoteOnly[revisionB.objectId] };
  assert.equal(protocol.compareRevisions(evictedB.revision, revisionB.revision), 0);
  strictAdapter.listInventory = async () => ({ protocolVersion: 2, view: "metadata",
    objects: [oldInventory], nextCursor: null });
  strictAdapter.list = async () => [revisionA];
  await assert.rejects(client.materializeRemote("docs/replay.txt"),
    { code: "remote_rollback_detected" },
    "same genuinely signed replay A must also be rejected against an evicted B marker");
  assert.deepEqual(client.snapshot.remoteOnly[revisionB.objectId], evictedB);
  assert.equal(await exists(path.join(root, "docs", "replay.txt")), false);

  strictAdapter.listInventory = liveInventory;
  strictAdapter.list = liveSignedList;
  assert.equal(await client.materializeRemote("docs/replay.txt"), true,
    "positive control: rehydration of exactly the same signed B revision after eviction succeeds");
  assert.equal(client.snapshot.remoteOnly[revisionB.objectId], undefined);
  strictAdapter.listInventory = async () => ({ protocolVersion: 2, view: "metadata",
    objects: [oldInventory], nextCursor: null });
  strictAdapter.list = async () => [revisionA];
  await assert.rejects(client.materializeRemote("docs/replay.txt"),
    { code: changedFileId ? "local_changes_pending" : "remote_rollback_detected" },
    "historically valid Ed25519 A must not replace B, even if A's fileId changed");
  assert.equal(await fsp.readFile(path.join(root, "docs", "replay.txt"), "utf8"),
    "authentic revision B");
  assert.deepEqual(client.snapshot.files["docs/replay.txt"], before,
    "replayed old inventory cannot lower the durable local revision");
});
}

test("issue 66 #263 P2: UPDATE after remote MOVE retires the old clean cached path", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/old.txt": "initial bytes" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/old.txt"), true);
  const original = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("initial bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const updated = protocol.createOperation({
    operation: "update", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: moved.revision,
    revision: { counter: moved.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt" },
    plaintext: Buffer.from("new bytes"), fileKey: key,
  });
  assert.equal((await store.put("alice", updated)).kind, "stored");
  assert.equal(await client.materializeRemote("docs/new.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "new.txt"), "utf8"), "new bytes");
  assert.equal(await exists(path.join(root, "docs", "old.txt")), false);
  assert.equal(client.snapshot.files["docs/old.txt"], undefined);
  assert.equal(client.snapshot.files["docs/new.txt"].objectId, original.objectId);
  assert.deepEqual(await client.journal.recover(), []);
});

for (const localChange of ["dirty", "missing"]) {
test(`issue 66 #263 P2: relocated UPDATE preserves ${localChange} source`, async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/old.txt": "initial bytes" });
  const client = await open();
  await client.materializeRemote("docs/old.txt");
  const original = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("initial bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const updated = protocol.createOperation({
    operation: "update", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: moved.revision,
    revision: { counter: moved.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt" },
    plaintext: Buffer.from("new bytes"), fileKey: key,
  });
  assert.equal((await store.put("alice", updated)).kind, "stored");
  if (localChange === "dirty") await fsp.writeFile(path.join(root, "docs", "old.txt"), "local edit");
  else await fsp.unlink(path.join(root, "docs", "old.txt"));
  await assert.rejects(client.materializeRemote("docs/new.txt"), { code: "local_changes_pending" });
  assert.equal(await exists(path.join(root, "docs", "new.txt")), false);
  assert.equal(client.snapshot.files["docs/old.txt"].objectId, original.objectId);
  assert.equal(await exists(path.join(root, "docs", "old.txt")), localChange === "dirty");
  if (localChange === "dirty") assert.equal(await fsp.readFile(path.join(root, "docs", "old.txt"), "utf8"), "local edit");
});
}

test("issue 66 #263 P2: verified remote tombstone invalidates a clean hydrated cache", async (t) => {
  const { root, open, store, key, state } = await setup(t, { "docs/gone.txt": "cached bytes" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/gone.txt"), true);
  const prior = store.list("alice")[0];
  const deleted = protocol.createOperation({
    operation: "delete", objectId: prior.objectId, fileId: prior.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: prior.revision,
    revision: { counter: prior.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/gone.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", deleted)).kind, "stored");
  const summary = await client.syncOnce();
  assert.equal(summary.available, 0);
  assert.equal(state.pushes, 0);
  assert.equal(await exists(path.join(root, "docs", "gone.txt")), false);
  assert.equal(client.snapshot.files["docs/gone.txt"]?.deleted, true);
  assert.deepEqual(await client.journal.recover(), []);
});

for (const localChange of ["dirty", "missing"]) {
test(`issue 66 #263 P2: ${localChange} cache refuses remote tombstone even on explicit refresh`, async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/gone.txt": "cached bytes" });
  const client = await open();
  await client.materializeRemote("docs/gone.txt");
  const prior = store.list("alice")[0];
  const deleted = protocol.createOperation({
    operation: "delete", objectId: prior.objectId, fileId: prior.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: prior.revision,
    revision: { counter: prior.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/gone.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", deleted)).kind, "stored");
  if (localChange === "dirty") await fsp.writeFile(path.join(root, "docs", "gone.txt"), "unsynced local edit");
  else await fsp.unlink(path.join(root, "docs", "gone.txt"));
  await assert.rejects(client.materializeRemote("docs/gone.txt"), { code: "local_changes_pending" });
  assert.equal(await exists(path.join(root, "docs", "gone.txt")), localChange === "dirty");
  if (localChange === "dirty") assert.equal(await fsp.readFile(path.join(root, "docs", "gone.txt"), "utf8"), "unsynced local edit");
  assert.equal(client.snapshot.files["docs/gone.txt"].objectId, prior.objectId);
});
}

test("issue 66 #263 P2: forged tombstone inventory cannot evict an authentic cached object", async (t) => {
  const { root, open, store, adapter } = await setup(t, { "docs/preserved.txt": "live authenticated ciphertext" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/preserved.txt"), true);
  const prior = store.list("alice")[0];
  const actualInventory = adapter.listInventory;
  adapter.listInventory = async (options) => {
    const page = await actualInventory(options);
    return { ...page, objects: page.objects.map((entry) => entry.objectId === prior.objectId
      ? { ...entry, tombstone: true, operation: "delete" } : entry) };
  };
  await assert.rejects(client.syncOnce(), { code: "inventory_changed" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "preserved.txt"), "utf8"), "live authenticated ciphertext");
  assert.equal(client.snapshot.files["docs/preserved.txt"].deleted, false);
});

for (const mutation of ["dirty", "missing"]) {
test(`issue 66 #263 reviewer P2 A: UPDATE relocation source becomes ${mutation} during staging`, async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/old.txt": "cached pre-move" });
  const client = await open();
  await client.materializeRemote("docs/old.txt");
  const first = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: first.objectId, fileId: first.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: first.revision, revision: { counter: first.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("cached pre-move"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const updated = protocol.createOperation({
    operation: "update", objectId: first.objectId, fileId: first.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: moved.revision, revision: { counter: moved.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt" }, plaintext: Buffer.from("remote update"), fileKey: key,
  });
  assert.equal((await store.put("alice", updated)).kind, "stored");
  const sourcePath = path.join(root, "docs", "old.txt");
  const destinationPath = path.join(root, "docs", "new.txt");
  const actualStage = client.stageExisting.bind(client);
  let destinationPresentWhenSourceStaged = null;
  client.stageExisting = async (target) => {
    if (target === sourcePath) {
      destinationPresentWhenSourceStaged = await exists(destinationPath);
      if (mutation === "dirty") await fsp.writeFile(sourcePath, "local racing edit");
      else await fsp.unlink(sourcePath);
    }
    return actualStage(target);
  };
  await assert.rejects(client.materializeRemote("docs/new.txt"), { code: "local_changes_pending" });
  assert.equal(destinationPresentWhenSourceStaged, false, "source must be staged before publishing destination");
  assert.equal(await exists(destinationPath), false, "failed reconciliation cannot leave orphan destination");
  assert.equal(await exists(sourcePath), mutation === "dirty");
  if (mutation === "dirty") {
    assert.equal(await fsp.readFile(sourcePath, "utf8"), "local racing edit",
      "concurrent local changes must be restored from trash");
  }
  assert.equal(client.snapshot.files["docs/old.txt"].objectId, first.objectId);
  assert.equal(client.snapshot.files["docs/new.txt"], undefined);
  assert.equal((await client.journal.recover()).length, 0);
});
}

test("issue 66 #263 reviewer P2 B: authenticated rotated-fileId tombstone retires cache by object identity", async (t) => {
  const { root, adapter, store, key } = await setup(t, { "docs/rotated.txt": "original cache" });
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trust = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] };
  const originalList = adapter.list;
  const authorizationExpiresAt = Date.now() + 60_000;
  adapter.list = async (objectId) => Promise.all((await originalList(objectId)).map(async (record) => ({
    ...record,
    authorization: await createAuthorizationProof(record, {
      username: "alice", publicKey, privateKey: pair.privateKey,
      expiresAt: authorizationExpiresAt,
    }),
  })));
  const client = await new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key, selectedPaths: ["docs"],
    filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: (operation) => verifyAuthorizationProof(operation.authorization, operation, trust),
  }).open();
  await client.materializeRemote("docs/rotated.txt");
  const first = store.list("alice")[0];
  const changedFileId = `file-rotated-${crypto.randomUUID()}`;
  const deleted = protocol.createOperation({
    operation: "delete", objectId: first.objectId, fileId: changedFileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: first.revision, revision: { counter: first.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/rotated.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", deleted)).kind, "stored");
  assert.equal((await client.syncOnce()).available, 0);
  assert.equal(await exists(path.join(root, "docs", "rotated.txt")), false);
  assert.equal(client.snapshot.files["docs/rotated.txt"].deleted, true);
  assert.equal(client.snapshot.files["docs/rotated.txt"].fileId, changedFileId);
  assert.equal(client.journal.hasSeen(deleted.operationId), true);
});

test("issue 66 #263 reviewer P2 C: tombstone stage-time edit restores dirty cache and keeps snapshot active", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/race-delete.txt": "cached for deletion" });
  const client = await open();
  await client.materializeRemote("docs/race-delete.txt");
  const first = store.list("alice")[0];
  const deleted = protocol.createOperation({
    operation: "delete", objectId: first.objectId, fileId: first.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: first.revision, revision: { counter: first.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/race-delete.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", deleted)).kind, "stored");
  const sourcePath = path.join(root, "docs", "race-delete.txt");
  const actualStage = client.stageExisting.bind(client);
  let staged = false;
  client.stageExisting = async (target) => {
    if (target === sourcePath) {
      staged = true;
      await fsp.writeFile(sourcePath, "changed between clean hash and stage");
    }
    return actualStage(target);
  };
  await assert.rejects(client.materializeRemote("docs/race-delete.txt"), { code: "local_changes_pending" });
  assert.equal(staged, true, "test must race the real staging call, not just the precheck");
  assert.equal(await fsp.readFile(sourcePath, "utf8"), "changed between clean hash and stage");
  assert.equal(client.snapshot.files["docs/race-delete.txt"].deleted, false);
  assert.equal(client.journal.hasSeen(deleted.operationId), false);
});

test("#263 P2: authenticated tombstone and new live identity at one path allow clean rehydration", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/reused.txt": "previous local bytes" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/reused.txt"), true);
  const original = store.list("alice")[0];
  const tombstone = protocol.createOperation({
    operation: "delete", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/reused.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", tombstone)).kind, "stored");
  const replacement = await seedRemote(store, key, "docs/reused.txt");
  assert.notEqual(replacement.objectId, original.objectId);

  assert.equal(await client.materializeRemote("docs/reused.txt"), true,
    "verified old tombstone must retire the old cache before the new live identity is hydrated");
  assert.equal(await fsp.readFile(path.join(root, "docs", "reused.txt"), "utf8"), "remote original");
  assert.equal(client.snapshot.files["docs/reused.txt"].objectId, replacement.objectId);
  assert.equal(client.journal.hasSeen(tombstone.operationId), true);
});

test("#263 P2: one dirty tombstone cache does not suppress reconciliation of another clean cache", async (t) => {
  const { root, open, store, key } = await setup(t, {
    "docs/a-dirty.txt": "first local cache", "docs/z-clean.txt": "second local cache",
  });
  const client = await open();
  await client.materializeRemote("docs/a-dirty.txt");
  await client.materializeRemote("docs/z-clean.txt");
  const before = store.list("alice");
  for (const record of before) {
    const tombstone = protocol.createOperation({
      operation: "delete", objectId: record.objectId, fileId: record.fileId,
      versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
      baseRevision: record.revision,
      revision: { counter: record.revision.counter + 1, deviceId: "device-a" },
      metadata: { path: record.metadata.path }, fileKey: key,
    });
    assert.equal((await store.put("alice", tombstone)).kind, "stored");
  }
  await fsp.writeFile(path.join(root, "docs", "a-dirty.txt"), "unsynced local change");
  // Isolate the background tombstone sweep from its earlier local-change
  // enqueue: the real signed reconciliation and disk writes still execute.
  client._reconcileLocal = async () => {};
  const result = await client.syncOnce();
  assert.equal(result.pulled, 1);
  assert.equal(await fsp.readFile(path.join(root, "docs", "a-dirty.txt"), "utf8"), "unsynced local change");
  assert.equal(client.snapshot.files["docs/a-dirty.txt"].deleted, false);
  assert.equal(await exists(path.join(root, "docs", "z-clean.txt")), false);
  assert.equal(client.snapshot.files["docs/z-clean.txt"].deleted, true);
});

test("#263 P2: moved then deleted out-of-scope object only retires its selected cached path", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/old.txt": "cached tracked identity" });
  const client = await open();
  await client.materializeRemote("docs/old.txt");
  const original = store.list("alice")[0];
  const move = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "private/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("cached tracked identity"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", move)).kind, "stored");
  const deleted = protocol.createOperation({
    operation: "delete", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: move.revision,
    revision: { counter: move.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "private/new.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", deleted)).kind, "stored");

  assert.equal((await client.syncOnce()).pulled, 1);
  assert.equal(await exists(path.join(root, "docs", "old.txt")), false);
  assert.equal(client.snapshot.files["docs/old.txt"].deleted, true);
  assert.equal(client.snapshot.files["private/new.txt"], undefined,
    "no unselected destination can gain a durable local tombstone from a relocated delete");
});

test("#263 P2: pending operation on relocated source discovered after inventory fetch blocks UPDATE", async (t) => {
  const { root, open, store, key, adapter } = await setup(t,
    { "docs/old.txt": "cached source" });
  const client = await open();
  await client.materializeRemote("docs/old.txt");
  const original = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("cached source"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const update = protocol.createOperation({
    operation: "update", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: moved.revision,
    revision: { counter: moved.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt" }, plaintext: Buffer.from("remote updated"), fileKey: key,
  });
  assert.equal((await store.put("alice", update)).kind, "stored");
  let injected = false;
  const realList = adapter.list;
  adapter.list = async (objectId) => {
    const records = await realList(objectId);
    if (!injected && objectId === original.objectId) {
      injected = true;
      await client.journal.enqueue(protocol.createOperation({
        operation: "move", objectId: `other-${crypto.randomUUID()}`,
        fileId: `other-${crypto.randomUUID()}`,
        versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
        deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
        revision: { counter: 1, deviceId: "device-b" },
        metadata: { path: "docs/elsewhere.txt",
          sourcePath: process.platform === "win32" ? "DOCS/OLD.TXT" : "docs/old.txt" },
        plaintext: protocol.encodeMovePayload(Buffer.from("other bytes"), key), fileKey: key,
      }));
    }
    return records;
  };

  await assert.rejects(client.materializeRemote("docs/new.txt"), { code: "sync_operation_pending" });
  assert.equal(injected, true, "pending source operation must be inserted after initial preflight");
  assert.equal(await exists(path.join(root, "docs", "new.txt")), false);
  assert.equal(await fsp.readFile(path.join(root, "docs", "old.txt"), "utf8"), "cached source");
  assert.equal(client.snapshot.files["docs/old.txt"].objectId, original.objectId);
});

test("#263 P2: remote MOVE cannot relocate cached source with a newly pending local operation", async (t) => {
  const { root, open, store, key, adapter } = await setup(t,
    { "docs/old.txt": "cached source for MOVE" });
  const client = await open();
  await client.materializeRemote("docs/old.txt");
  const original = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("cached source for MOVE"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const realList = adapter.list;
  let injected = false;
  adapter.list = async (objectId) => {
    const records = await realList(objectId);
    if (objectId === original.objectId && !injected) {
      injected = true;
      await client.journal.enqueue(protocol.createOperation({
        operation: "move", objectId: `other-${crypto.randomUUID()}`,
        fileId: `other-${crypto.randomUUID()}`,
        versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
        deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
        revision: { counter: 1, deviceId: "device-b" },
        metadata: { path: "docs/elsewhere.txt",
          sourcePath: process.platform === "win32" ? "DOCS/OLD.TXT" : "docs/old.txt" },
        plaintext: protocol.encodeMovePayload(Buffer.from("other bytes"), key), fileKey: key,
      }));
    }
    return records;
  };

  await assert.rejects(client.materializeRemote("docs/new.txt"), { code: "sync_operation_pending" });
  assert.equal(injected, true, "injection must happen after initial pending preflight");
  assert.equal(await exists(path.join(root, "docs", "new.txt")), false);
  assert.equal(await fsp.readFile(path.join(root, "docs", "old.txt"), "utf8"), "cached source for MOVE");
  assert.equal(client.snapshot.files["docs/old.txt"].objectId, original.objectId);
});

test("#263 P2 RED: evicting last child of hydration-created parent folder does not cause remote_path_collision", async (t) => {
  const { source, writer, open } = await setup(t, {});
  await fsp.mkdir(path.join(source, "docs"), { recursive: true });
  await writer.syncOnce();
  await fsp.writeFile(path.join(source, "docs", "child.txt"), "child bytes");
  await writer.syncOnce();
  const consumer = await open(["docs"]);
  assert.equal(await consumer.materializeRemote("docs/child.txt"), true);
  assert.equal(await consumer.evictLocal("docs/child.txt"), true);
  await consumer.syncOnce();
  assert.equal((await consumer.journal.recover()).length, 0,
    "evicting last child of hydration-created parent must not enqueue an orphan directory CREATE");
});
