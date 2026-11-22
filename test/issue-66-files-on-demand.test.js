"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

// Preserve the original physical fault oracles for when a real native provider
// exists. They must never count as passing native I/O tests while RootSession
// deliberately denies publication before the tested rename/fsync boundary.
const NATIVE_PUBLISH_PENDING = "Native RootSession publication is disabled; physical fault oracle pending";
const nativeTest = (name, body) => test(name, { skip: NATIVE_PUBLISH_PENDING }, body);

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
  const open = (selectedPaths = ["docs"], filesOnDemand = true) => new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key, selectedPaths,
    filesOnDemand,
  }).open();
  const openCached = (...relativePaths) =>
    openPreexistingCachedFodFixture({ root, source, writer, open, adapter, key }, relativePaths);
  const seedCached = (...relativePaths) =>
    openPreexistingCachedFodFixture({ root, source, writer, open, adapter, key }, relativePaths, false);
  return { root, source, writer, open, openCached, seedCached, adapter, state, store, key };
}

async function exists(filePath) {
  return fsp.stat(filePath).then(() => true, () => false);
}

// Seed an explicitly preexisting cache without invoking the native-disabled
// inbound publisher. Authenticate every remote ciphertext before writing any
// local fixture bytes; a tampered remote record must not create a cache.
async function openPreexistingCachedFodFixture({ root, source, writer, open, adapter, key }, relativePaths, openFod = true) {
  const verified = [];
  for (const relative of relativePaths) {
    const tracked = writer.snapshot.files[relative];
    assert.ok(tracked && !tracked.deleted, `writer must track ${relative}`);
    const records = await adapter.list(tracked.objectId);
    const record = records.find((item) => item.objectId === tracked.objectId
      && item.fileId === tracked.fileId && item.versionId === tracked.versionId);
    assert.ok(record, `remote cache source must exist for ${relative}`);
    const bytes = protocol.decryptPayload(record, key);
    assert.deepEqual(bytes, await fsp.readFile(path.join(source, relative)));
    assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), tracked.hash);
    verified.push({ relative, bytes, tracked });
  }
  const snapshot = { ...writer.snapshot, files: Object.fromEntries(
    verified.map(({ relative, tracked }) => [relative, tracked])) };
  await fsp.mkdir(root, { recursive: true });
  for (const { relative, bytes } of verified) {
    const target = path.join(root, relative);
    await fsp.mkdir(path.dirname(target), { recursive: true });
    await fsp.writeFile(target, bytes, { flag: "wx" });
  }
  await fsp.writeFile(path.join(root, ".rootark-sync-index.json"), JSON.stringify(snapshot), { flag: "wx" });
  if (!openFod) return snapshot;
  const reopened = await open();
  for (const relative of relativePaths) {
    assert.deepEqual(reopened.snapshot.files[relative], snapshot.files[relative],
      "reopened FOD cache must retain the authenticated preexisting record");
    assert.deepEqual(await fsp.readFile(path.join(root, relative)),
      await fsp.readFile(path.join(source, relative)),
      "reopened FOD cache must retain the verified source bytes");
  }
  return reopened;
}

test("issue 66: preexisting FOD cache fixture refuses unauthenticated remote bytes", async (t) => {
  const { root, adapter, openCached, store } = await setup(t,
    { "docs/protected.txt": "authenticated cache content" });
  const originalRecords = JSON.stringify(store.list("alice"));
  const originalList = adapter.list;
  adapter.list = async (objectId) => (await originalList(objectId)).map((record) => {
    if (record.metadata?.path !== "docs/protected.txt") return record;
    const first = record.ciphertext[0] === "A" ? "B" : "A";
    return { ...record, ciphertext: first + record.ciphertext.slice(1) };
  });
  await assert.rejects(openCached("docs/protected.txt"), (error) => {
    assert.notEqual(error.code, "root_session_native_unavailable",
      "real legacy sync must reject altered ciphertext before native FOD is enabled");
    assert.match(String(error.message), /unable to authenticate data/i,
      "the fixture must reach AES-GCM authentication, not fail on unrelated setup");
    return true;
  });
  assert.equal(await exists(path.join(root, "docs", "protected.txt")), false);
  assert.equal(await exists(path.join(root, ".rootark-sync-ever-fod")), false);
  assert.equal(JSON.stringify(store.list("alice")), originalRecords,
    "the remote source record must remain unchanged by a failed fixture");
});

nativeTest("issue 66 P2: successful FOD hydration removes private plaintext temporary", async (t) => {
  const { root, open, state } = await setup(t, { "docs/hydrate.txt": "signed remote content" });
  const consumer = await open();
  assert.equal(await consumer.materializeRemote("docs/hydrate.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "hydrate.txt"), "utf8"), "signed remote content");
  assert.deepEqual(await fsp.readdir(path.join(root, ".rootark-trash")), [],
    "verified success must not retain a private hydration hardlink");
  assert.deepEqual((await fsp.readdir(path.join(root, "docs"))).filter((name) => name.includes(".tmp-")), []);
  assert.equal(state.pushes, 0, "hydration must not create a remote upload");
});

nativeTest("issue 66 P2: verified repeated FOD CREATE is idempotent without staging clean bytes", async (t) => {
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

nativeTest("issue 66 P2: first FOD CREATE cleanup failure cannot mint an untracked local CREATE", async (t) => {
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

nativeTest("issue 66 P2 RED: crash after FOD CREATE publication cannot enqueue local CREATE on restart", async (t) => {
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

nativeTest("issue 66 P2: CREATE and UPDATE retain private hardlink until signed snapshot is durable", async (t) => {
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

nativeTest("issue 66 P2: hydration cleanup EPERM cannot return success or leak syncable CREATE", async (t) => {
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

nativeTest("issue 66 P2: interrupted FOD temp write is never scanned as ordinary CREATE", async (t) => {
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

test("issue 66: lazy sync pages metadata and denies publication without native custody", async (t) => {
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

  await assert.rejects(client.materializeRemote("docs/b.txt"),
    { code: "root_session_native_unavailable" });
  assert.equal(await exists(path.join(root, "docs", "b.txt")), false);
  const objectId = store.list("alice").find((item) => item.metadata.path === "docs/b.txt").objectId;
  assert.deepEqual(state.fullReads, [objectId]);
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  await assert.rejects(client.materializeRemote("private/secret.txt"), { code: "path_not_selected" });

  state.offline = true;
  assert.equal((await client.syncOnce()).offline, true);
  assert.equal(await exists(path.join(root, "docs", "b.txt")), false);
  assert.equal(Object.keys(client.snapshot.files).length, 0);
  assert.deepEqual(await client.journal.recover(), []);
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

test("issue 66: pagination finds later inventory entries but native-required publish stays blocked", async (t) => {
  const { root, open, adapter, state } = await setup(t, {
    "docs/a.txt": "one", "docs/b.txt": "two", "docs/c.txt": "three",
  });
  const listInventory = adapter.listInventory;
  adapter.listInventory = (request) => listInventory({ ...request, limit: 1 });
  const client = await open();
  assert.equal((await client.syncOnce()).available, 3);
  await assert.rejects(client.materializeRemote("docs/c.txt"),
    { code: "root_session_native_unavailable" });
  assert.equal(await exists(path.join(root, "docs", "c.txt")), false);
  assert.equal(state.fullReads.length, 1);
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
});

test("issue 66: Files On-Demand refuses destructive cache eviction without native root custody", async (t) => {
  const { root, open, openCached, store, state } = await setup(t, { "docs/cache.txt": "cache me" });
  const client = await openCached("docs/cache.txt");
  const before = store.list("alice")[0];
  const beforeSnapshot = JSON.stringify(client.snapshot);
  const beforeFullReads = state.fullReads.length;
  await assert.rejects(client.evictLocal("docs/cache.txt"),
    { code: "root_session_native_unavailable" });
  // A direct internal call, including the batchDurable variant, must never
  // turn an unavailable native authority into pathname-based deletion.
  await assert.rejects(client._evictLocal("docs/cache.txt", null, null, true),
    { code: "root_session_native_unavailable" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "cache.txt"), "utf8"), "cache me");
  assert.equal(JSON.stringify(client.snapshot), beforeSnapshot,
    "rejected eviction cannot alter tracked or remote-only durable intent");
  assert.equal(state.fullReads.length, beforeFullReads,
    "rejected eviction must not query remote state before rejecting unsafe I/O");
  assert.equal((await fsp.readdir(root)).includes(".rootark-trash"), false);
  assert.equal((await fsp.readdir(root)).includes(".rootark-sync-evictions"), false);
  assert.equal(store.list("alice")[0].operationId, before.operationId);
  state.offline = true;
  assert.equal((await client.syncOnce()).offline, true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "cache.txt"), "utf8"), "cache me");
  assert.equal(store.list("alice")[0].operationId, before.operationId);
  state.offline = false;
  const restarted = await open();
  assert.equal(restarted.snapshot.remoteOnly[before.objectId], undefined);
  assert.equal(await fsp.readFile(path.join(root, "docs", "cache.txt"), "utf8"), "cache me");
});

test("issue 66: automatic excluded cache migration refuses legacy eviction before snapshot mutation", async (t) => {
  const { root, openCached, adapter, store, state, key } = await setup(t,
    { "docs/cache.txt": "retain exact Unicode café-中-😀 bytes" });
  await openCached("docs/cache.txt");
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const oldSnapshot = await fsp.readFile(snapshotPath);
  const oldFile = await fsp.readFile(path.join(root, "docs", "cache.txt"));
  const oldRecords = JSON.stringify(store.list("alice"));
  const oldState = { pushes: state.pushes, fullReads: state.fullReads.length,
    inventoryReads: state.inventoryReads };
  const excluded = new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs"], excludedPaths: ["docs/cache.txt"],
    filesOnDemand: true, fileKeyResolver: () => key,
  });
  await excluded.open();
  await assert.rejects(excluded.syncOnce(), { code: "root_session_native_unavailable" },
    "automatic exclusion must never turn an unsafe native denial into persisted failure or remote-only state");
  assert.deepEqual(await fsp.readFile(snapshotPath), oldSnapshot);
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "cache.txt")), oldFile);
  assert.equal(JSON.stringify(store.list("alice")), oldRecords);
  assert.equal(state.pushes, oldState.pushes);
  assert.equal(state.fullReads.length, oldState.fullReads);
  assert.equal(state.inventoryReads, oldState.inventoryReads);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
  assert.equal(await exists(path.join(root, ".rootark-sync-evictions")), false);
});

test("issue 66: Files On-Demand cannot sign remote DELETE merely because a cached pathname vanishes", async (t) => {
  const { root, openCached, store, state } = await setup(t, { "docs/café-中-😀.txt": "trusted cached bytes" });
  const client = await openCached("docs/café-中-😀.txt");
  const original = await fsp.readFile(path.join(root, "docs", "café-中-😀.txt"));
  const originalSnapshot = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const originalRemote = JSON.stringify(store.list("alice"));
  const originalPushes = state.pushes;
  await fsp.rename(path.join(root, "docs", "café-中-😀.txt"),
    path.join(root, "docs", "temporarily-missing.txt"));

  await assert.rejects(client.syncOnce(), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "temporarily-missing.txt")), original);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), originalSnapshot);
  assert.equal(JSON.stringify(store.list("alice")), originalRemote);
  assert.equal(state.pushes, originalPushes);
  assert.equal((await client.journal.recover()).length, 0, "no signed DELETE or CREATE was queued");
});

test("issue 66: Files On-Demand WebDAV translation never signs pathname-derived DELETE", async (t) => {
  const { root, openCached, store, state } = await setup(t, { "docs/item.txt": "trusted cached bytes" });
  const client = await openCached("docs/item.txt");
  const originalSnapshot = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const originalRemote = JSON.stringify(store.list("alice"));
  await fsp.unlink(path.join(root, "docs", "item.txt"));

  await assert.rejects(client.translateWebDavMutation({
    kind: "delete", operationId: crypto.randomUUID(), source: "/docs/item.txt",
  }), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), originalSnapshot);
  assert.equal(JSON.stringify(store.list("alice")), originalRemote);
  assert.equal(state.pushes, 0);
  assert.equal((await client.journal.recover()).length, 0);
});

test("issue 66: cold WebDAV translation under a foreign root lock cannot create the FOD mode marker", async (t) => {
  const { root, adapter, key, state } = await setup(t, {
    "docs/remote.txt": "signed remote source",
  });
  await fsp.mkdir(root, { recursive: true });
  const rootLock = path.join(root, ".rootark-sync.lock");
  await fsp.mkdir(rootLock, { mode: 0o700 });
  const cold = new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true,
  });
  await assert.rejects(cold.translateWebDavMutation({
    operationId: crypto.randomUUID(), kind: "put", path: "/docs/remote.txt",
  }), { code: "sync_root_busy" });
  assert.equal(await exists(path.join(root, ".rootark-sync-ever-fod")), false,
    "the cold translator must not publish a marker without owning the real root lock");
  assert.equal(await exists(path.join(root, ".rootark-sync-index.json")), false);
  assert.equal(await exists(path.join(root, ".rootark-sync-journal.json")), false);
  assert.equal(await exists(rootLock), true);
  assert.equal(state.pushes, 0);
  assert.equal(state.inventoryReads, 0);
});

test("issue 66: unsupported pin and signed batch preflight cannot leave a false physical root lock", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/cache.txt": "authenticated remote content",
  });
nativeTest("issue 66 P2: verified evicted A can hydrate a later remote MOVE at B", async (t) => {
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

nativeTest("issue 66 #263 P2: evicted A hydrates an authenticated MOVE then UPDATE at B", async (t) => {
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

  const client = await open();
  await assert.rejects(client.pinLocal("docs/cache.txt"),
    { code: "authorization_required" });
  await assert.rejects(client.withMutationLock(() =>
    client.pushAtomicSignedOverwritePair([], { pushed: 0 })),
    { code: "sync_atomic_batch_unavailable" });
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false,
    "side-effect-free policy denials must not poison future physical ownership");
  const reopened = await open();
  assert.equal((await reopened.pinStatus("docs/cache.txt")).pinned, false);
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false);
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 1);
});

test("issue 66: rejected native-required excluded-cache migration never leaves a spurious physical lock", async (t) => {
  const { root, open, openCached, state } = await setup(t, {
    "docs/cache.txt": "verified cached bytes",
  });
  const client = await openCached("docs/cache.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const before = await fsp.readFile(snapshot);
  client.excludedPaths = ["docs"];
  await assert.rejects(client.withMutationLock(() => client._applyExcludedPaths()),
    { code: "root_session_native_unavailable" });
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false,
    "a native-custody refusal before legacy eviction must not poison the root");
  assert.deepEqual(await fsp.readFile(snapshot), before);
  assert.equal(await fsp.readFile(path.join(root, "docs", "cache.txt"), "utf8"),
    "verified cached bytes");
  const reopened = await open();
  assert.equal((await reopened.pinStatus("docs/cache.txt")).pinned, false);
  assert.equal(state.pushes, 0);
});

test("issue 66: direct Files On-Demand outbox cannot enqueue a signed DELETE", async (t) => {
  const { open, store, key, state } = await setup(t, { "docs/remote.txt": "signed original" });
  const client = await open();
  const remote = store.list("alice")[0];
  const originalRemote = JSON.stringify(store.list("alice"));
  await assert.rejects(client.enqueueChange({
    operation: "delete", objectId: remote.objectId, fileId: remote.fileId,
    versionId: crypto.randomUUID(), baseRevision: remote.revision,
    revision: { counter: 2, deviceId: "device-b" },
    metadata: { path: "docs/remote.txt" }, fileKey: key,
  }), { code: "root_session_native_unavailable" });
  assert.equal((await client.journal.recover()).length, 0);
  assert.equal(JSON.stringify(store.list("alice")), originalRemote);
  assert.equal(state.pushes, 0);
});

test("issue 66: a previous non-FOD signed DELETE in a durable journal cannot be pushed by FOD", async (t) => {
  const { root, open, seedCached, store, adapter, key, state } = await setup(t,
    { "docs/retained.txt": "retain remote and local" });
  await seedCached("docs/retained.txt");
  // A genuine pre-FOD outbox must precede the first FOD open. Opening a
  // non-FOD writer after FOD activation is now deliberately forbidden.
  const legacy = await new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key,
  }).open();
  const remote = store.list("alice")[0];
  await legacy.enqueueChange({
    operation: "delete", objectId: remote.objectId, fileId: remote.fileId,
    versionId: crypto.randomUUID(), baseRevision: remote.revision,
    revision: { counter: 2, deviceId: "device-b" },
    metadata: { path: "docs/retained.txt" }, fileKey: key,
  });
  const pendingBefore = (await legacy.journal.recover()).map((item) => item.operationId);
  const remoteBefore = JSON.stringify(store.list("alice"));
  const reopened = await open();
  const snapshotBefore = JSON.parse(await fsp.readFile(path.join(root, ".rootark-sync-index.json")));
  await assert.rejects(reopened.syncOnce(), { code: "root_session_native_unavailable" });
  assert.deepEqual((await reopened.journal.recover()).map((item) => item.operationId), pendingBefore);
  const snapshotAfter = JSON.parse(await fsp.readFile(path.join(root, ".rootark-sync-index.json")));
  assert.deepEqual(snapshotAfter.files, snapshotBefore.files);
  assert.deepEqual(snapshotAfter.remoteOnly, snapshotBefore.remoteOnly);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.pushes, 0);
  assert.equal(await fsp.readFile(path.join(root, "docs", "retained.txt"), "utf8"), "retain remote and local");
});

test("issue 66: FOD public staging denies before probing an outside-root path", async (t) => {
  const { root, open } = await setup(t, {});
  const client = await open();
  const outside = path.join(path.dirname(root), "independent-outside-witness.txt");
  const bytes = Buffer.from("outside source must remain unchanged");
  await fsp.writeFile(outside, bytes);

  await assert.rejects(client.stageExisting(outside), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(outside), bytes);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: public staging cannot relocate an in-root cached FOD file without native custody", async (t) => {
  const { root, openCached, store } = await setup(t, { "docs/retained.txt": "protected FOD cache" });
  const client = await openCached("docs/retained.txt");
  const target = path.join(root, "docs", "retained.txt");
  const bytesBefore = await fsp.readFile(target);
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const remoteBefore = JSON.stringify(store.list("alice"));
  await assert.rejects(client.stageExisting(target), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(target), bytesBefore);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: direct incoming DELETE must not stage materialized FOD bytes without native custody", async (t) => {
  const { root, openCached, store, key } = await setup(t,
    { "docs/retained.txt": "verified cached owner bytes" });
  const client = await openCached("docs/retained.txt");
  const original = store.list("alice")[0];
  const originalBytes = await fsp.readFile(path.join(root, "docs", "retained.txt"));
  const originalSnapshot = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const remoteDelete = protocol.createOperation({
    operation: "delete", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    baseRevision: original.revision, metadata: { path: "docs/retained.txt" }, fileKey: key,
  });

  await assert.rejects(client.apply(remoteDelete), { code: "root_session_native_unavailable" });
  await assert.rejects(client._apply(remoteDelete), { code: "sync_root_busy" },
    "private direct apply must not bypass the physical mutation lock");
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "retained.txt")), originalBytes);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), originalSnapshot);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: Files On-Demand WebDAV MOVE translation denies before any local scan", async (t) => {
  const { root, openCached, store, state } = await setup(t, { "docs/a.txt": "retained signed bytes" });
  const client = await openCached("docs/a.txt");
  const originalBytes = await fsp.readFile(path.join(root, "docs", "a.txt"));
  const originalSnapshot = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const remoteBefore = JSON.stringify(store.list("alice"));
  const readsBefore = state.fullReads.length;

  await assert.rejects(client.translateWebDavMutation({
    kind: "move", operationId: crypto.randomUUID(),
    source: "/docs/a.txt", destination: "/docs/b.txt",
  }), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "a.txt")), originalBytes);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), originalSnapshot);
  assert.equal(await exists(path.join(root, "docs", "b.txt")), false);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.fullReads.length, readsBefore);
});

test("issue 66: out-of-scope remote DELETE cannot stage an in-scope FOD cache origin", async (t) => {
  const { root, openCached, store, key } = await setup(t,
    { "docs/retained.txt": "same cache origin must remain" });
  const client = await openCached("docs/retained.txt");
  const original = store.list("alice")[0];
  const bytesBefore = await fsp.readFile(path.join(root, "docs", "retained.txt"));
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const tombstone = protocol.createOperation({
    operation: "delete", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    baseRevision: original.revision, metadata: { path: "outside/retained.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", tombstone)).kind, "stored");

  await assert.rejects(client.pullRemote({ conflicts: [] }), { code: "root_session_native_unavailable" });
  await assert.rejects(client.reconcileOutOfScopeMove(tombstone, { conflicts: [] }),
    { code: "root_session_native_unavailable" }, "direct reconcile must not bypass the pull fence");
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "retained.txt")), bytesBefore);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: out-of-scope remote MOVE cannot rename a tracked FOD origin without native custody", async (t) => {
  const { root, openCached, store, key } = await setup(t,
    { "docs/café-中-😀.txt": "origin must survive MOVE outside selected scope" });
  const client = await openCached("docs/café-中-😀.txt");
  const original = store.list("alice")[0];
  const filePath = path.join(root, "docs", "café-中-😀.txt");
  const bytesBefore = await fsp.readFile(filePath);
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const moved = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    baseRevision: original.revision,
    metadata: { path: "outside/café-中-😀.txt", sourcePath: "docs/café-中-😀.txt" },
    plaintext: protocol.encodeMovePayload(bytesBefore, key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");

  await assert.rejects(client.pullRemote({ conflicts: [] }), { code: "root_session_native_unavailable" });
  await assert.rejects(client.reconcileOutOfScopeMove(moved, { conflicts: [] }),
    { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(filePath), bytesBefore);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: replacing public preflight cannot bypass direct out-of-scope FOD DELETE denial", async (t) => {
  const { root, openCached, store, key } = await setup(t,
    { "docs/retained.txt": "must never be staged by a shadowed method" });
  const client = await openCached("docs/retained.txt");
  const remote = store.list("alice")[0];
  const cachePath = path.join(root, "docs", "retained.txt");
  const originalBytes = await fsp.readFile(cachePath);
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const originalSnapshot = await fsp.readFile(snapshotPath);
  const tombstone = protocol.createOperation({
    operation: "delete", objectId: remote.objectId, fileId: remote.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: remote.revision.counter + 1, deviceId: "device-a" },
    baseRevision: remote.revision, metadata: { path: "outside/retained.txt" }, fileKey: key,
  });
  let hijacked = 0;
  client.preflightOutOfScopeMove = () => {
    hijacked += 1;
    return { sourcePath: "docs/retained.txt", prior: client.snapshot.files["docs/retained.txt"],
      tombstone: true, directoryRecord: false };
  };

  await assert.rejects(client.reconcileOutOfScopeMove(tombstone, { conflicts: [] }),
    { code: "root_session_native_unavailable" });
  assert.equal(hijacked, 0, "a replaced public preflight must never supply destructive authority");
  assert.deepEqual(await fsp.readFile(cachePath), originalBytes);
  assert.deepEqual(await fsp.readFile(snapshotPath), originalSnapshot);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: Proxy preflight interception cannot bypass FOD remote pull denial", async (t) => {
  const { root, openCached, store, key } = await setup(t,
    { "docs/café-中-😀.txt": "proxy must not stage owner bytes" });
  const client = await openCached("docs/café-中-😀.txt");
  const remote = store.list("alice")[0];
  const cachePath = path.join(root, "docs", "café-中-😀.txt");
  const originalBytes = await fsp.readFile(cachePath);
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const originalSnapshot = await fsp.readFile(snapshotPath);
  const tombstone = protocol.createOperation({
    operation: "delete", objectId: remote.objectId, fileId: remote.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: remote.revision.counter + 1, deviceId: "device-a" },
    baseRevision: remote.revision, metadata: { path: "outside/café-中-😀.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", tombstone)).kind, "stored");
  let hijacked = 0;
  const proxied = new Proxy(client, {
    get(target, property, receiver) {
      if (property === "preflightOutOfScopeMove") {
        return () => {
          hijacked += 1;
          return { sourcePath: "docs/café-中-😀.txt",
            prior: target.snapshot.files["docs/café-中-😀.txt"],
            tombstone: true, directoryRecord: false };
        };
      }
      return Reflect.get(target, property, receiver);
    },
  });

  await assert.rejects(proxied.pullRemote({ conflicts: [] }),
    { code: "root_session_native_unavailable" });
  assert.equal(hijacked, 0, "Proxy method interception must not direct path staging");
  assert.deepEqual(await fsp.readFile(cachePath), originalBytes);
  assert.deepEqual(await fsp.readFile(snapshotPath), originalSnapshot);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: a FOD root retains its mode across non-FOD restart and custom snapshot paths", async (t) => {
  const { root, open, openCached, adapter, store, key, state } = await setup(t,
    { "docs/cache.txt": "mode must remain bound to this physical root" });
  const client = await openCached("docs/cache.txt");
  const cachedPath = path.join(root, "docs", "cache.txt");
  const original = await fsp.readFile(cachedPath);
  const originalStore = JSON.stringify(store.list("alice"));
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  const markerPath = path.join(root, ".rootark-sync-ever-fod");
  // Preserve the explicit regular-file assertion without reopening a mutable
  // pathname after the check (the old stat(path) -> readFile(path) was racy).
  const markerHandle = await fsp.open(markerPath, fs.constants.O_RDONLY
    | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  try {
    const before = await markerHandle.stat({ bigint: true });
    assert.equal(before.isFile(), true, "FOD must create a regular-file root marker");
    assert.equal(before.nlink, 1n, "a marker hardlink cannot be root-mode authority");
    const expectedMarker = Buffer.from("rootark-sync-ever-fod-v1\n");
    const bounded = Buffer.alloc(expectedMarker.length + 1);
    let bytesRead = 0;
    while (bytesRead < bounded.length) {
      const result = await markerHandle.read(bounded, bytesRead,
        bounded.length - bytesRead, bytesRead);
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
    }
    assert.equal(bytesRead, expectedMarker.length, "marker must match exact bounded bytes");
    assert.deepEqual(bounded.subarray(0, bytesRead), expectedMarker);
    const after = await markerHandle.stat({ bigint: true });
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
  } finally { await markerHandle.close(); }
  const nonFod = new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs"], fileKeyResolver: () => key,
  });
  await assert.rejects(nonFod.open(), { code: "root_mode_fod_required" });
  await assert.rejects(nonFod.evictLocal("docs/cache.txt"), { code: "root_mode_fod_required" });
  assert.deepEqual(await fsp.readFile(cachedPath), original);
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), originalStore);
  assert.equal(state.pushes, 0);

  const alternateSnapshot = path.join(path.dirname(root), "alternate-fod-index.json");
  const otherRoot = path.join(path.dirname(root), "custom-snapshot-root");
  const customFod = await new SyncEngine({ rootDir: otherRoot, snapshotPath: alternateSnapshot,
    adapter, deviceId: "device-c", keyEpoch: "epoch-1", compartmentId: "private",
    filesOnDemand: true, fileKeyResolver: () => key,
  }).open();
  assert.equal(customFod.filesOnDemand, true);
  assert.equal((await fsp.stat(path.join(otherRoot, ".rootark-sync-ever-fod"))).isFile(), true);
  assert.equal(Object.hasOwn(await customFod.scanFiles(), ".rootark-sync-ever-fod"), false,
    "the mode marker must never be synchronized as an ordinary file");
  assert.equal(await exists(path.join(otherRoot, ".rootark-sync-index.json")), false);
  const differentSnapshot = path.join(path.dirname(root), "other-new-index.json");
  await assert.rejects(new SyncEngine({ rootDir: otherRoot, snapshotPath: differentSnapshot,
    adapter, deviceId: "device-c", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key,
  }).open(), { code: "root_mode_fod_required" });
  assert.equal(await exists(differentSnapshot), false,
    "mode denial must precede creating an alternate snapshot");
});

test("issue 66: an already-open non-FOD engine cannot evict after another instance marks FOD", async (t) => {
  const { root, open, seedCached, adapter, store, key, state } = await setup(t,
    { "docs/retained.txt": "bytes of owner must never be evicted" });
  await seedCached("docs/retained.txt");
  const legacy = await new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs"], fileKeyResolver: () => key,
  }).open();
  assert.equal(await exists(path.join(root, ".rootark-sync-ever-fod")), false,
    "ordinary non-FOD operations must not set the marker");
  assert.equal(await fsp.readFile(path.join(root, "docs", "retained.txt"), "utf8"),
    "bytes of owner must never be evicted");
  const fod = await open();
  assert.equal(fod.filesOnDemand, true);
  const cachedPath = path.join(root, "docs", "retained.txt");
  const original = await fsp.readFile(cachedPath);
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const remoteBefore = JSON.stringify(store.list("alice"));
  await assert.rejects(legacy.evictLocal("docs/retained.txt"),
    { code: "root_mode_fod_required" });
  await assert.rejects(legacy.syncOnce(), { code: "root_mode_fod_required" });
  await assert.rejects(legacy.stageExisting(cachedPath), { code: "root_mode_fod_required" },
    "a direct stage helper must also honor the durable root-mode marker");
  await assert.rejects(legacy._reconcileLocal(), { code: "root_mode_fod_required" });
  await assert.rejects(legacy._pushPending({ pushed: 0, conflicts: [], offline: false }),
    { code: "root_mode_fod_required" });
  await assert.rejects(legacy._apply({ operation: "delete" }), { code: "root_mode_fod_required" });
  await assert.rejects(legacy.persistSnapshot(), { code: "root_mode_fod_required" });
  assert.deepEqual(await fsp.readFile(cachedPath), original);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.pushes, 0);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: direct recoverConflict cannot write after another engine marks FOD", async (t) => {
  const { root, open, seedCached, adapter, store, key } = await setup(t,
    { "docs/retained.txt": "protected content" });
  await seedCached("docs/retained.txt");
  const legacy = await new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key,
  }).open();
  assert.equal(await fsp.readFile(path.join(root, "docs", "retained.txt"), "utf8"),
    "protected content");
  const fod = await open();
  assert.equal(fod.filesOnDemand, true);
  const original = store.list("alice")[0];
  const cachedPath = path.join(root, "docs", "retained.txt");
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const bytesBefore = await fsp.readFile(cachedPath);
  const snapshotBefore = await fsp.readFile(snapshotPath);
  const conflict = protocol.createOperation({
    operation: "update", objectId: original.objectId, fileId: original.fileId,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    baseRevision: original.revision, metadata: { path: "docs/retained.txt" },
    plaintext: Buffer.from("should not create a recovery file"), fileKey: key,
  });
  const summary = { conflicts: [], conflictRecovery: 0 };
  await assert.rejects(legacy.recoverConflict(conflict, summary), { code: "root_mode_fod_required" });
  assert.deepEqual(await fsp.readFile(cachedPath), bytesBefore);
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(summary.conflictRecovery, 0);
  assert.equal(await exists(path.join(root, ".rootark-conflicts")), false);
});

test("issue 66: direct prune cannot remove empty tracked-root ancestors after FOD activation", async (t) => {
  const { root, open, adapter, key } = await setup(t, {});
  const legacy = await new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key,
  }).open();
  const empty = path.join(root, "untracked", "nested");
  await fsp.mkdir(empty, { recursive: true });
  const fod = await open();
  const marker = await fsp.readFile(path.join(root, ".rootark-sync-ever-fod"));
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  await assert.rejects(legacy.pruneEmptyUntrackedParents(empty), { code: "root_mode_fod_required" });
  assert.equal((await fsp.stat(empty)).isDirectory(), true);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-ever-fod")), marker);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(fod.filesOnDemand, true);
});

test("issue 66: shared protocol and WebDAV reject ever-FOD marker metadata", async (t) => {
  const { root, open, store, key, state } = await setup(t, {});
  const client = await open();
  const markerPath = path.join(root, ".rootark-sync-ever-fod");
  const originalMarker = await fsp.readFile(markerPath);
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const remoteBefore = JSON.stringify(store.list("alice"));
  const readsBefore = state.fullReads.length;
  for (const name of [".rootark-sync-ever-fod", ".ROOTARK-SYNC-EVER-FOD",
    "docs/.rootark-sync-ever-fod"]) {
    assert.throws(() => protocol.safeRelativePath(name, "path"), { code: "invalid_operation" });
    assert.throws(() => protocol.createOperation({ operation: "create",
      deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: 1, deviceId: "device-b" }, metadata: { path: name },
      plaintext: Buffer.from("not allowed"), fileKey: key,
    }), { code: "invalid_operation" });
  }
  await assert.rejects(client.translateWebDavMutation({
    kind: "put", operationId: crypto.randomUUID(), path: "/.rootark-sync-ever-fod",
  }), { code: "invalid_operation" });
  assert.deepEqual(await fsp.readFile(markerPath), originalMarker);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.fullReads.length, readsBefore);
});

test("issue 66: malformed ever-FOD root marker fails closed without writing a snapshot", async (t) => {
  const { root, adapter, key } = await setup(t, {});
  await fsp.mkdir(root, { recursive: true });
  const markerPath = path.join(root, ".rootark-sync-ever-fod");
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  for (const malformed of ["{", "{}", '{"version":999}']) {
    await fsp.writeFile(markerPath, malformed, "utf8");
    for (const filesOnDemand of [false, true]) {
      const engine = new SyncEngine({ rootDir: root, adapter,
        deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
        fileKeyResolver: () => key, filesOnDemand,
      });
      await assert.rejects(engine.open(), { code: "root_mode_marker_invalid" });
      assert.equal(await exists(snapshotPath), false);
    }
  }
});

test("issue 66: a multiply-linked ever-FOD marker cannot authorize a root mode", async (t) => {
  const { root, open, adapter, key } = await setup(t, {});
  await open();
  const marker = path.join(root, ".rootark-sync-ever-fod");
  const alias = path.join(root, "marker-hardlink-outside-sync");
  await fsp.link(marker, alias);
  const original = await fsp.readFile(marker);
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  await assert.rejects(new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key,
  }).open(), { code: "root_mode_marker_invalid" });
  assert.deepEqual(await fsp.readFile(marker), original);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
});

test("issue 66: cold FOD snapshot cannot accept a foreign inode rebound after its initial stat", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/keep.txt": "signed remote content",
  });
  await open();
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const parked = path.join(root, "parked-original-index-for-adversarial-test");
  const originalBytes = await fsp.readFile(snapshot);
  const injected = JSON.parse(originalBytes);
  injected.excludedPaths = ["docs"];
  const foreignBytes = Buffer.from(JSON.stringify(injected));
  const remoteBefore = JSON.stringify(store.list("alice"));
  const pushesBefore = state.pushes;
  const originalLstat = fsp.lstat;
  const originalRename = fsp.rename;
  let physicallySwapped = false;
  // The vulnerable version lstat()ed the original index and then reopened
  // its NAME with readFile(). This callback makes that second read follow
  // a different, valid JSON inode, rather than the original checked file.
  fsp.lstat = async (requested, ...args) => {
    const prior = await originalLstat(requested, ...args);
    if (!physicallySwapped && path.resolve(String(requested)) === snapshot) {
      physicallySwapped = true;
      await originalRename(snapshot, parked);
      const foreign = await fsp.open(snapshot, "wx", 0o600);
      try {
        await foreign.writeFile(foreignBytes);
        await foreign.sync();
      } finally { await foreign.close(); }
    }
    return prior;
  };
  try {
    await assert.rejects(open(), { code: "invalid_snapshot" },
      "a replacement index must not be accepted as the previously checked inode");
  } finally {
    fsp.lstat = originalLstat;
  }
  assert.equal(physicallySwapped, true, "the OS must physically change the index inode");
  assert.deepEqual(await fsp.readFile(parked), originalBytes);
  assert.deepEqual(await fsp.readFile(snapshot), foreignBytes,
    "the test must not silently destroy the foreign file");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false,
    "a rejected read-only cold snapshot cannot invent a mutating transaction");
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.pushes, pushesBefore);
});

test("issue 66: cold FOD journal read cannot accept a foreign pathname-rebound inode", async (t) => {
  const { root, open, store, state } = await setup(t, {});
  await open();
  const journal = path.join(root, ".rootark-sync-journal.json");
  const parked = path.join(root, "parked-original-journal-for-adversarial-test");
  const originalBytes = await fsp.readFile(journal);
  const injected = JSON.parse(originalBytes);
  injected.seen.push(`foreign-seen-${crypto.randomUUID()}`);
  const foreignBytes = Buffer.from(JSON.stringify(injected));
  const remoteBefore = JSON.stringify(store.list("alice"));
  const pushesBefore = state.pushes;
  const originalLstat = fsp.lstat;
  const originalReadFile = fsp.readFile;
  const originalRename = fsp.rename;
  let physicallySwapped = false;
  const swapToForeign = async () => {
    physicallySwapped = true;
    await originalRename(journal, parked);
    const foreign = await fsp.open(journal, "wx", 0o600);
    try {
      await foreign.writeFile(foreignBytes);
      await foreign.sync();
    } finally { await foreign.close(); }
  };
  // Old code opens journal by mutable name through readFile(path). The new
  // reader acquires a held FD first and must detect a rebound after lstat.
  // Both branches do a REAL filesystem substitution, not a mock byte return.
  fsp.readFile = async (requested, ...args) => {
    if (!physicallySwapped && path.resolve(String(requested)) === journal) {
      await swapToForeign();
    }
    return originalReadFile(requested, ...args);
  };
  fsp.lstat = async (requested, ...args) => {
    const previous = await originalLstat(requested, ...args);
    if (!physicallySwapped && path.resolve(String(requested)) === journal) {
      await swapToForeign();
    }
    return previous;
  };
  try {
    await assert.rejects(open(), { code: "invalid_sync_journal" },
      "a different journal inode must not supply signed replay/seen authority");
  } finally {
    fsp.lstat = originalLstat;
    fsp.readFile = originalReadFile;
  }
  assert.equal(physicallySwapped, true);
  assert.deepEqual(await fsp.readFile(parked), originalBytes);
  assert.deepEqual(await fsp.readFile(journal), foreignBytes);
  const originalStats = await fsp.lstat(parked, { bigint: true });
  const foreignStats = await fsp.lstat(journal, { bigint: true });
  assert.notEqual(originalStats.ino, foreignStats.ino,
    "the test must distinguish a different physical file, not just changed contents");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "an indeterminate cold journal must retain the physical root lock");
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.pushes, pushesBefore);
});

test("issue 66: cold FOD journal bootstrap never renames over a foreign inode planted after ENOENT", async (t) => {
  const { root, adapter, key, store, state } = await setup(t, {});
  await fsp.mkdir(root, { recursive: true });
  const journal = path.join(root, ".rootark-sync-journal.json");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const foreignBytes = Buffer.from("FOREIGN_JOURNAL_MUST_NOT_BE_OVERWRITTEN");
  const storeBefore = JSON.stringify(store.list("alice"));
  const pushesBefore = state.pushes;
  const originalOpen = fsp.open;
  const originalRename = fsp.rename;
  let planted = false;
  let overwriteAttempted = false;
  // The first real read-only open yields ENOENT. A concurrent same-principal
  // writer EXCLUSIVELY creates and syncs a different inode before the caller
  // handles ENOENT; a subsequent rename(temp, journal) would destroy it.
  fsp.open = async (candidate, ...args) => {
    try {
      return await originalOpen(candidate, ...args);
    } catch (error) {
      if (!planted && error.code === "ENOENT"
        && path.resolve(String(candidate)) === journal) {
        planted = true;
        const foreign = await originalOpen(journal, "wx", 0o600);
        try {
          await foreign.writeFile(foreignBytes);
          await foreign.sync();
        } finally { await foreign.close(); }
      }
      throw error;
    }
  };
  fsp.rename = async (source, destination, ...args) => {
    if (path.resolve(String(destination)) === journal) {
      overwriteAttempted = true;
      // Intercept before destruction. The real foreign inode was already
      // created+fsynced, so this is a physical, non-destructive RED proof.
      throw Object.assign(new Error("unsafe replace-capable journal bootstrap"), { code: "EIO" });
    }
    return originalRename(source, destination, ...args);
  };
  const client = new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key, filesOnDemand: true,
  });
  try {
    await assert.rejects(client.open(), { code: "invalid_sync_journal" },
      "late foreign bootstrap ownership must fail closed without attempting replacement");
  } finally {
    fsp.open = originalOpen;
    fsp.rename = originalRename;
  }
  assert.equal(planted, true, "a real foreign inode must win the journal name after ENOENT");
  assert.equal(overwriteAttempted, false, "bootstrap must never call replace-capable rename");
  const held = await originalOpen(journal, "r");
  try {
    const before = await held.stat({ bigint: true });
    assert.equal(before.isFile(), true);
    assert.deepEqual(await held.readFile(), foreignBytes);
    const after = await held.stat({ bigint: true });
    assert.equal(after.ino, before.ino);
    assert.equal(after.size, before.size);
  } finally { await held.close(); }
  assert.equal(await exists(snapshot), false, "failed bootstrap must not create authoritative snapshot");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "an uncertain cold journal bootstrap must retain its physical root lock");
  assert.equal(JSON.stringify(store.list("alice")), storeBefore);
  assert.equal(state.pushes, pushesBefore);
});

for (const control of ["snapshot", "journal"]) {
  test(`issue 66: cold ${control} read remains bounded when its opened inode grows concurrently`, async (t) => {
    const { root, open, state, store } = await setup(t, {});
    await open();
    const target = path.join(root, control === "snapshot"
      ? ".rootark-sync-index.json" : ".rootark-sync-journal.json");
    // The attacker retains its OWN original inode handle; it never relies on
    // stat(path) then opening the same path after a potential replacement.
    const nativeOpen = fsp.open;
    const nativeLstat = fsp.lstat;
    const adversary = await nativeOpen(target, fs.constants.O_RDWR);
    const originalLength = (await adversary.readFile()).length;
    const remoteBefore = JSON.stringify(store.list("alice"));
    const pushesBefore = state.pushes;
    let growthInjected = false;
    let boundedReadCalls = 0;
    let unboundedReadCalls = 0;
    let requestedBytes = 0;
    fsp.open = async (filePath, ...args) => {
      const handle = await nativeOpen(filePath, ...args);
      if (path.resolve(String(filePath)) === target) {
        const nativeRead = handle.read.bind(handle);
        const nativeReadFile = handle.readFile.bind(handle);
        handle.read = async (...readArgs) => {
          boundedReadCalls += 1;
          requestedBytes += readArgs[2];
          return nativeRead(...readArgs);
        };
        handle.readFile = async (...readArgs) => {
          unboundedReadCalls += 1;
          return nativeReadFile(...readArgs);
        };
      }
      return handle;
    };
    fsp.lstat = async (filePath, ...args) => {
      const named = await nativeLstat(filePath, ...args);
      if (!growthInjected && path.resolve(String(filePath)) === target) {
        growthInjected = true;
        // Real sparse growth of the SAME inode, immediately after the victim
        // has observed its initial version/size and before any payload read.
        await adversary.truncate(originalLength + (1024 * 1024));
        await adversary.sync();
      }
      return named;
    };
    try {
      await assert.rejects(open(), { code: control === "snapshot"
        ? "invalid_snapshot" : "invalid_sync_journal" });
    } finally {
      fsp.lstat = nativeLstat;
      fsp.open = nativeOpen;
      await adversary.close();
    }
    assert.equal(growthInjected, true, "a genuine same-inode expansion is required");
    assert.ok(boundedReadCalls >= 1, "the cold reader must consume held positional reads");
    assert.equal(unboundedReadCalls, 0,
      "FileHandle.readFile could read arbitrarily many concurrently appended bytes");
    assert.ok(requestedBytes <= originalLength + 1,
      "the original observed size plus one detection byte is the strict read budget");
    assert.equal(state.pushes, pushesBefore);
    assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  });
}

test("issue 66: a physically rebound FOD marker never authorizes a foreign inode", async (t) => {
  const { root, open, adapter, key, state, store } = await setup(t, {
    "docs/keep.txt": "protected remote content",
  });
  await open();
  const marker = path.join(root, ".rootark-sync-ever-fod");
  const parked = path.join(root, "parked-original-marker-for-adversarial-test");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const expectedMarker = "rootark-sync-ever-fod-v1\n";
  const markerBefore = await fsp.open(marker, fs.constants.O_RDONLY
    | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  let before;
  try { before = await markerBefore.stat({ bigint: true }); }
  finally { await markerBefore.close(); }
  const snapshotBefore = await fsp.readFile(snapshot);
  const storeBefore = JSON.stringify(store.list("alice"));
  const pushesBefore = state.pushes;
  const originalLstat = fsp.lstat;
  const originalRename = fsp.rename;
  let swapped = false;
  // The old implementation used lstat(marker), then a fresh readFile(marker).
  // Physically rebind that same name immediately after the successful lstat.
  // A pathname second read would wrongly accept identical foreign bytes.
  fsp.lstat = async (requested, ...args) => {
    const result = await originalLstat(requested, ...args);
    if (!swapped && path.resolve(String(requested)) === path.resolve(marker)) {
      swapped = true;
      await originalRename(marker, parked);
      await fsp.writeFile(marker, expectedMarker, { flag: "wx" });
    }
    return result;
  };
  try {
    await assert.rejects(new SyncEngine({ rootDir: root, adapter,
      deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
      fileKeyResolver: () => key, filesOnDemand: true,
    }).open(), { code: "root_mode_marker_invalid" });
  } finally { fsp.lstat = originalLstat; }
  assert.equal(swapped, true, "the physical inode replacement must have happened");
  // Read each inode from its own held descriptor, not via another pathname
  // lookup following a lstat. The proof must not recreate the CodeQL race.
  const heldEvidence = async (entry) => {
    const handle = await fsp.open(entry, fs.constants.O_RDONLY
      | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
    try {
      const stats = await handle.stat({ bigint: true });
      const bytes = await handle.readFile("utf8");
      return { stats, bytes };
    } finally { await handle.close(); }
  };
  const foreign = await heldEvidence(marker);
  const parkedOriginal = await heldEvidence(parked);
  assert.equal(parkedOriginal.stats.ino, before.ino, "original opened inode is retained");
  assert.notEqual(foreign.stats.ino, before.ino, "foreign equal-byte inode must remain distinct");
  assert.equal(foreign.bytes, expectedMarker);
  assert.equal(parkedOriginal.bytes, expectedMarker);
  assert.deepEqual(await fsp.readFile(snapshot), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), storeBefore);
  assert.equal(state.pushes, pushesBefore, "a failed root-mode admission must not push a signed operation");
});

test("issue 66: ambiguous FOD publish retains foreign temporary and quarantines the root", { skip: NATIVE_PUBLISH_PENDING }, async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "authenticated recovery payload",
  });
  const client = await open();
  // Keep the parent pre-existing: even then, a failed publication attempt
  // cannot prove the target was never mutated. Retain the root lock; an
  // untrusted cold opener cannot authorize a retry from mutable pathnames.
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  const target = path.join(root, "docs", "restore.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshot);
  const storeBefore = JSON.stringify(store.list("alice"));
  const pushesBefore = state.pushes;
  const foreignBytes = "foreign temporary must never be removed";
  const parked = path.join(path.dirname(root), "parked-original-inbound-for-adversarial-test");
  const originalRename = fsp.rename;
  const originalRm = fsp.rm;
  let planted = false;
  let attemptedForeignRemoval = false;
  let temporary = null;
  let sameVolumeParent = false;
  fsp.rename = async (source, destination, ...rest) => {
    if (!planted && path.resolve(String(destination)) === path.resolve(target)
      && String(source).includes(".tmp-")) {
      sameVolumeParent = path.dirname(path.resolve(String(source))) === path.dirname(path.resolve(target));
      await originalRename(source, parked);
      await fsp.writeFile(source, foreignBytes, { flag: "wx" });
      planted = true;
      temporary = String(source);
      throw Object.assign(new Error("physical inbound publish EIO after temp replacement"), { code: "EIO" });
    }
    return originalRename(source, destination, ...rest);
  };
  fsp.rm = async (candidate, options) => {
    if (planted && path.resolve(String(candidate)) === path.resolve(temporary)) {
      attemptedForeignRemoval = true;
      // Trap only the destructive syscall, retaining the physical foreign
      // inode for assertions; the rest of the transaction is real NTFS/ext4.
      return;
    }
    return originalRm(candidate, options);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/restore.txt"), { code: "EIO" });
  } finally {
    fsp.rename = originalRename;
    fsp.rm = originalRm;
  }
  assert.equal(planted, true, "real inbound temp must be moved and physically replaced");
  assert.equal(sameVolumeParent, true,
    "an incoming temp must share its destination directory for nested mount support");
  assert.equal(attemptedForeignRemoval, false,
    "failed publish must not issue pathname rm against a substituted foreign inode");
  assert.equal(await fsp.readFile(temporary, "utf8"), foreignBytes);
  assert.equal(await fsp.readFile(parked, "utf8"), "authenticated recovery payload");
  assert.equal(await exists(target), false, "failed incoming hydration must not claim a local cache");
  assert.deepEqual(await fsp.readFile(snapshot), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), storeBefore);
  assert.equal(state.pushes, pushesBefore, "inbound failure may not publish a signed operation");
  assert.equal(path.basename(temporary).startsWith(".rootark-sync-index.json.tmp-inbound-"), true,
    "a failed inbound write must leave inert reserved debris, never a user-path temp name");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "ambiguous attempted publish must hold custody even with a pre-existing parent");
  await assert.rejects(client._reconcileLocal(), { code: "sync_inbound_indeterminate" });
  await assert.rejects(open(), { code: "sync_root_busy" });
  assert.equal(await exists(target), false,
    "do not manufacture an authorized target or claim an unsafe cold retry");
  assert.equal(await fsp.readFile(temporary, "utf8"), foreignBytes);
  assert.equal(JSON.stringify(store.list("alice")), storeBefore);
  assert.equal(state.pushes, pushesBefore, "blocked cold retry may not sign a foreign temp or delete");
});

test("issue 66: new FOD parent remains locked when inbound payload rename fails", { skip: NATIVE_PUBLISH_PENDING }, async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "inbound payload denied before final rename",
  });
  const client = await open();
  const parent = path.join(root, "docs");
  const target = path.join(parent, "restore.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const oldSnapshot = await fsp.readFile(snapshot);
  const beforeStore = JSON.stringify(store.list("alice"));
  const originalRename = fsp.rename;
  let intercepted = false;
  fsp.rename = async (source, dest, ...args) => {
    if (!intercepted && path.resolve(String(dest)) === path.resolve(target)
      && String(source).includes(".tmp-inbound-")) {
      intercepted = true;
      throw Object.assign(new Error("injected pre-rename EIO"), { code: "EIO" });
    }
    return originalRename(source, dest, ...args);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/restore.txt"), { code: "EIO" });
  } finally {
    fsp.rename = originalRename;
  }
  assert.equal(intercepted, true, "the parent must be created before final payload rename");
  assert.equal((await fsp.lstat(parent)).isDirectory(), true);
  assert.equal(await exists(target), false);
  assert.deepEqual(await fsp.readFile(snapshot), oldSnapshot);
  await assert.rejects(client.pruneEmptyUntrackedParents(parent),
    { code: "sync_inbound_indeterminate" });
  assert.equal((await fsp.lstat(parent)).isDirectory(), true,
    "a direct cleanup caller must not remove the quarantined ancestor");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "new uncheckpointed parent must retain the cross-process root lock");
  await assert.rejects(open(), { code: "sync_root_busy" });
  assert.equal(state.pushes, 0);
  assert.equal(JSON.stringify(store.list("alice")), beforeStore);
});

test("issue 66: recursive FOD parent mkdir partial EIO cannot free cold lock", { skip: NATIVE_PUBLISH_PENDING }, async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/sub/restore.txt": "remote bytes after a partial ancestor mkdir",
  });
  const client = await open();
  const firstAncestor = path.join(root, "docs");
  const requestedParent = path.join(firstAncestor, "sub");
  const target = path.join(requestedParent, "restore.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const oldSnapshot = await fsp.readFile(snapshot);
  const oldStore = JSON.stringify(store.list("alice"));
  const originalMkdir = fsp.mkdir;
  let createdRealAncestor = false;
  let injectedPartialError = false;
  fsp.mkdir = async (candidate, options, ...extra) => {
    if (!injectedPartialError && path.resolve(String(candidate)) === path.resolve(requestedParent)
      && options?.recursive === true) {
      // Real OS mkdir for the first component; the recursive call then
      // fails at the next segment instead of returning its created path.
      await originalMkdir(firstAncestor, { recursive: false });
      createdRealAncestor = true;
      injectedPartialError = true;
      throw Object.assign(new Error("physical first ancestor followed by EIO"), { code: "EIO" });
    }
    return originalMkdir(candidate, options, ...extra);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/sub/restore.txt"), { code: "EIO" });
  } finally {
    fsp.mkdir = originalMkdir;
  }
  assert.equal(createdRealAncestor, true, "real ancestor must be created before the recursive EIO");
  assert.equal(injectedPartialError, true);
  assert.equal((await fsp.lstat(firstAncestor)).isDirectory(), true);
  assert.equal(await exists(requestedParent), false);
  assert.equal(await exists(target), false);
  assert.deepEqual(await fsp.readFile(snapshot), oldSnapshot);
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "partial recursive mkdir must quarantine the root, not authorize a cold local CREATE");
  await assert.rejects(open(), { code: "sync_root_busy" });
  const diskJournal = JSON.parse(await fsp.readFile(path.join(root, ".rootark-sync-journal.json"), "utf8"));
  assert.deepEqual(diskJournal.pending, []);
  assert.equal(state.pushes, 0, "no outbound push is asserted or fabricated by this fixture");
  assert.equal(JSON.stringify(store.list("alice")), oldStore);
});

test("issue 66: physical post-publish FOD crash retains lock and stops cold outbound reconcile", { skip: NATIVE_PUBLISH_PENDING }, async (t) => {
  const { root, open, store, state, key } = await setup(t, {
    "docs/restore.txt": "remote fixture bytes after abrupt exit",
  });
  await open();
  const target = path.join(root, "docs", "restore.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const beforeSnapshot = await fsp.readFile(snapshot);
  const beforeStore = JSON.stringify(store.list("alice"));
  const childProgram = [
    '"use strict";',
    'const fs=require("node:fs");',
    'const fsp=require("node:fs/promises");',
    'const path=require("node:path");',
    '(async()=>{',
    'const input=JSON.parse(process.env.ROOTARK_ISSUE66_CRASH_TEST);',
    'const {SyncEngine}=require(input.engine);',
    'const {SyncObjectStore}=require(input.storeModule);',
    'const store=await new SyncObjectStore(input.storeFile).open();',
    'const adapter={list:async(id="")=>store.list("alice",id||null),',
    'listInventory:async()=>({protocolVersion:2,view:"metadata",objects:[],nextCursor:null}),',
    'push:async()=>{throw Error("unexpected outbound during inbound child")}};',
    'const client=await new SyncEngine({rootDir:input.root,adapter,deviceId:"device-b",',
    'keyEpoch:"epoch-1",compartmentId:"private",fileKeyResolver:()=>Buffer.from(input.key,"hex"),',
    'selectedPaths:["docs"],filesOnDemand:true}).open();',
    'const operation=store.list("alice").find(x=>x.metadata?.path==="docs/restore.txt");',
    'if(!operation)throw Error("remote fixture record missing");',
    'const originalRename=fsp.rename;',
    'fsp.rename=async(source,destination,...args)=>{',
    'const result=await originalRename(source,destination,...args);',
    'if(String(source).includes(".tmp-inbound-") &&',
    'path.resolve(String(destination))===path.resolve(input.target)){',
    'fs.writeSync(1,"POST_PUBLISH_PHYSICAL_RENAME\\n");',
    'process.kill(process.pid,"SIGKILL");',
    'throw Error("native immediate termination unexpectedly returned");',
    '}',
    'return result;',
    '};',
    'await client.apply(operation);',
    'process.exit(67);',
    '})().catch(e=>{fs.writeSync(2,String(e.stack||e));process.exit(68)});',
  ].join("\n");
  const child = spawnSync(process.execPath, ["-e", childProgram], {
    timeout: 15000, encoding: "utf8", maxBuffer: 8192,
    env: {
      ...process.env,
      ROOTARK_ISSUE66_CRASH_TEST: JSON.stringify({
        engine: path.join(__dirname, "..", "sync-client", "rootark-sync-engine.js"),
        storeModule: path.join(__dirname, "..", "src", "routes", "sync.js"),
        storeFile: path.join(path.dirname(root), "objects.json"),
        root, target, key: key.toString("hex"),
      }),
    },
  });
  assert.match(child.stdout, /POST_PUBLISH_PHYSICAL_RENAME/,
    `must reach physical rename before crash, stderr=${child.stderr}`);
  assert.equal(child.error, undefined, "subprocess must not time out or fail to spawn");
  assert.equal(child.stderr, "", "failure/exception path must never pass as a crash");
  if (process.platform === "win32") {
    assert.equal(Number.isInteger(child.status), true);
    assert.equal([0, 67, 68].includes(child.status), false,
      "Windows must terminate by SIGKILL, not the child normal/failure exits");
  } else {
    assert.equal(child.signal, "SIGKILL", "POSIX must observe a real SIGKILL termination");
  }
  assert.equal(await fsp.readFile(target, "utf8"), "remote fixture bytes after abrupt exit");
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot,
    "the original snapshot is physically older than published payload");
  assert.equal(JSON.stringify(store.list("alice")), beforeStore);
  // A real abnormal process termination leaves the preexisting root lock.
  // Cold open MUST stop here; never simulate a custodian or unlink this
  // security lock from a same-UID/SID writable path to force a fake replay.
  await assert.rejects(open(), { code: "sync_root_busy" });
  assert.equal(state.pushes, 0, "cold lock prevents an untracked outbound CREATE");
  const diskJournal = JSON.parse(await fsp.readFile(
    path.join(root, ".rootark-sync-journal.json"), "utf8"));
  assert.equal(diskJournal.pending.length, 0,
    "failed cold admission cannot enqueue any new outbound CREATE");
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot);
  assert.equal(JSON.stringify(store.list("alice")), beforeStore);
});

test("issue 66: FOD post-publish snapshot EIO retains root lock before any outbound reconcile", { skip: NATIVE_PUBLISH_PENDING }, async (t) => {
  const { root, open, store, state, adapter } = await setup(t, {
    "docs/recover.txt": "remote file published before a failed checkpoint",
  });
  const client = await open();
  const target = path.join(root, "docs", "recover.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const beforeSnapshot = await fsp.readFile(snapshot);
  const beforeStore = JSON.stringify(store.list("alice"));
  const originalRename = fsp.rename;
  let published = false;
  let injected = false;
  fsp.rename = async (source, destination, ...args) => {
    const dest = path.resolve(String(destination));
    if (dest === path.resolve(target) && String(source).includes(".tmp-inbound-")) {
      const result = await originalRename(source, destination, ...args);
      published = true; // the kernel really renamed the payload inode
      return result;
    }
    if (published && !injected && dest === path.resolve(snapshot)
      && String(source).includes(".tmp-")) {
      injected = true;
      throw Object.assign(new Error("durable snapshot publish injected EIO"), { code: "EIO" });
    }
    return originalRename(source, destination, ...args);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/recover.txt"), { code: "EIO" });
  } finally {
    fsp.rename = originalRename;
  }
  assert.equal(published, true, "the inbound file must have been physically published");
  assert.equal(injected, true, "EIO must land in the later snapshot rename, not the payload");
  assert.equal(await fsp.readFile(target, "utf8"),
    "remote file published before a failed checkpoint");
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot,
    "the cache content and durable snapshot must disagree at this test boundary");
  // Public locking is not the only entry point. The module-private negative
  // latch must also reject direct internal method calls before scanning or
  // attempting outbound signed mutation, even if a caller overwrites fields.
  client.inboundPublicationIndeterminate = false;
  await assert.rejects(client._reconcileLocal(), { code: "sync_inbound_indeterminate" });
  await assert.rejects(client._pushPending({ pushed: 0 }), { code: "sync_inbound_indeterminate" });
  await assert.rejects(client.translateWebDavMutation({
    kind: "put", path: "/docs/recover.txt", operationId: "post-publish-eio-webdav",
  }), { code: "sync_inbound_indeterminate" });
  await assert.rejects(client._enqueueChange({ operation: "create" }),
    { code: "sync_inbound_indeterminate" });
  await assert.rejects(client._open(), { code: "sync_inbound_indeterminate" });
  await assert.rejects(client.recoverConflict(store.list("alice")[0], {}),
    { code: "sync_inbound_indeterminate" });
  const originalPush = adapter.push;
  let unsafeDispatchAttempted = false;
  adapter.push = async () => {
    unsafeDispatchAttempted = true;
    throw Object.assign(new Error("unexpected outbound after EIO"), { code: "unsafe_dispatch" });
  };
  try {
    await assert.rejects(client.retryPush(store.list("alice")[0]),
      { code: "sync_inbound_indeterminate" });
  } finally {
    adapter.push = originalPush;
  }
  assert.equal(unsafeDispatchAttempted, false,
    "direct retryPush may not reach HTTP after the root became indeterminate");
  await assert.rejects(client.syncOnce(), { code: "sync_root_busy" });
  await assert.rejects(open(), { code: "sync_root_busy" });
  assert.equal(state.pushes, 0, "no uncertain cache may be enqueued or dispatched as outbound CREATE");
  const diskJournal = JSON.parse(await fsp.readFile(path.join(root, ".rootark-sync-journal.json"), "utf8"));
  assert.equal(diskJournal.pending.length, 0);
  assert.equal(JSON.stringify(store.list("alice")), beforeStore);
});

test("issue 66: inbound FOD rename completion followed by EIO retains lock before cold reconcile", { skip: NATIVE_PUBLISH_PENDING }, async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "remote authenticated content after a late native error",
  });
  const client = await open();
  const parent = path.join(root, "docs");
  await fsp.mkdir(parent, { recursive: true });
  const target = path.join(parent, "restore.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const oldSnapshot = await fsp.readFile(snapshot);
  const oldStore = JSON.stringify(store.list("alice"));
  const originalRename = fsp.rename;
  let published = false;
  fsp.rename = async (source, destination, ...args) => {
    if (!published && path.resolve(String(destination)) === path.resolve(target)
      && String(source).includes(".tmp-inbound-")) {
      await originalRename(source, destination, ...args);
      published = true; // Kernel has physically completed the target rename.
      throw Object.assign(new Error("injected EIO after real inbound publish"), { code: "EIO" });
    }
    return originalRename(source, destination, ...args);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/restore.txt"), { code: "EIO" });
  } finally {
    fsp.rename = originalRename;
  }
  assert.equal(published, true, "must reach a real successful OS rename before injected EIO");
  assert.equal(await fsp.readFile(target, "utf8"),
    "remote authenticated content after a late native error");
  assert.deepEqual(await fsp.readFile(snapshot), oldSnapshot,
    "the durable checkpoint must remain older than the physical payload");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "the publisher's uncertain completion must never release the process lock");
  await assert.rejects(client._reconcileLocal(), { code: "sync_inbound_indeterminate" });
  await assert.rejects(client.syncOnce(), { code: "sync_root_busy" });
  await assert.rejects(open(), { code: "sync_root_busy" });
  const journal = JSON.parse(await fsp.readFile(path.join(root, ".rootark-sync-journal.json"), "utf8"));
  assert.deepEqual(journal.pending, []);
  assert.equal(state.pushes, 0, "there is no evidence of an outbound signed CREATE");
  assert.equal(JSON.stringify(store.list("alice")), oldStore);
});

test("issue 66: native-required direct inbound _apply cannot bypass an occupied physical root lock", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "signed remote cache bytes",
  });
  const client = await open();
  const op = store.list("alice").find((entry) => entry.metadata?.path === "docs/restore.txt");
  assert.ok(op, "fixture must contain a real signed remote operation");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const beforeSnapshot = await fsp.readFile(snapshot);
  const beforeRemote = JSON.stringify(store.list("alice"));
  const lock = path.join(root, ".rootark-sync.lock");
  // A different process's exclusive mkdir is represented by the actual
  // kernel directory. This test never unlinks someone else's lock.
  await fsp.mkdir(lock, { mode: 0o700 });
  await assert.rejects(client._apply(op), { code: "sync_root_busy" });
  await assert.rejects(client.apply(op), { code: "sync_root_busy" });
  assert.equal(await exists(path.join(root, "docs", "restore.txt")), false,
    "no target may be created by bypassing the owner of the physical lock");
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot);
  assert.deepEqual(await client.journal.recover(), []);
  assert.equal(state.pushes, 0);
  assert.equal(JSON.stringify(store.list("alice")), beforeRemote);
});

test("issue 66: native-required private hydration and reconcile require the physical mutation context", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "signed remote cache bytes",
  });
  const client = await open();
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const beforeSnapshot = await fsp.readFile(snapshot);
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client._materializeOnDemand("docs/restore.txt"),
    { code: "sync_root_busy" });
  await assert.rejects(client._reconcileLocal(), { code: "sync_root_busy" });
  assert.equal(await exists(path.join(root, "docs", "restore.txt")), false);
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot);
  assert.deepEqual(await client.journal.recover(), []);
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 1);
});

test("issue 66: an escaped stale AsyncLocalStorage callback cannot reuse a released native-required lock", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "remote bytes protected by physical lock",
  });
  const client = await open();
  const operation = store.list("alice").find((entry) => entry.metadata?.path === "docs/restore.txt");
  assert.ok(operation);
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const beforeSnapshot = await fsp.readFile(snapshot);
  let releaseCallback;
  const trigger = new Promise((resolve) => { releaseCallback = resolve; });
  let escaped;
  await client.withMutationLock(async () => {
    // Registration happens INSIDE the AsyncLocalStorage context, but the
    // operation will execute after withMutationLock has already released
    // the physical lock. An equality-only context guard is a false authority.
    escaped = trigger.then(() => client._apply(operation));
  });
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false);
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  releaseCallback();
  await assert.rejects(escaped, { code: "sync_root_busy" });
  assert.equal(await exists(path.join(root, "docs", "restore.txt")), false);
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot);
  assert.deepEqual(await client.journal.recover(), []);
  assert.equal(state.pushes, 0);
});

test("issue 66: direct native-required outbound retry and conflict recovery cannot bypass a physical lock", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "authenticated remote bytes",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const remoteBefore = JSON.stringify(store.list("alice"));
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshot);
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client.retryPush(operation), { code: "sync_root_busy" });
  await assert.rejects(client.recoverConflict(operation, { conflicts: [] }),
    { code: "sync_root_busy" });
  assert.equal(await exists(path.join(root, ".rootark-conflicts")), false);
  assert.equal(state.pushes, 0, "no outbound signed PUT may bypass the lock owner");
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.deepEqual(await fsp.readFile(snapshot), snapshotBefore);
});

test("issue 66: a replaced JavaScript authorization method cannot dispatch a native-required signed DELETE retry", async (t) => {
  const { root, open, store, adapter, state } = await setup(t, {
    "docs/restore.txt": "signed remote bytes",
  });
  const client = await open();
  const operation = { ...store.list("alice")[0],
    operation: "delete", tombstone: true };
  const remoteRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-retry-remote-"));
  t.after(() => fsp.rm(remoteRoot, { recursive: true, force: true }));
  const remoteProof = path.join(remoteRoot, "forbidden-signed-delete.bin");
  const originalAuthorization = client.assertOutgoingAuthorized;
  const originalPush = adapter.push;
  let physicallyDispatched = false;
  // An attacker who controls a writable JS instance method must not become
  // the independent native-custody or outbound signed-DELETE authority.
  client.assertOutgoingAuthorized = async (_record, authorizedAction = null) =>
    authorizedAction ? authorizedAction() : true;
  adapter.push = async () => {
    const held = await fsp.open(remoteProof, "wx", 0o600);
    try {
      await held.writeFile("UNAUTHORIZED_REMOTE_DELETE_DISPATCHED");
      await held.sync();
      physicallyDispatched = true;
    } finally {
      await held.close();
    }
    return { status: 201 };
  };
  try {
    await assert.rejects(client.withMutationLock(() => client.retryPush(operation)),
      { code: "root_session_native_unavailable" },
      "module-private native custody denial must survive a writable JS method override");
  } finally {
    client.assertOutgoingAuthorized = originalAuthorization;
    adapter.push = originalPush;
  }
  assert.equal(physicallyDispatched, false);
  assert.equal(await exists(remoteProof), false,
    "no outbound adapter may commit even a disposable physical remote record");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false,
    "a pure pre-dispatch negative gate must not poison the real process lock");
  assert.equal(state.pushes, 0);
});

test("issue 66: native-required retry cannot dispatch a freshly signed DELETE swapped into a signed CREATE during async authorization", async (t) => {
  const { root, open, adapter, key, state } = await setup(t, {});
  const client = await open();
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ type: "spki", format: "der" })
    .toString("base64url");
  const identity = { objectId: "signed-object-" + crypto.randomUUID(),
    fileId: "signed-file-" + crypto.randomUUID(), deviceId: "device-a",
    keyEpoch: "epoch-1", compartmentId: "private" };
  const signed = async (verb, counter) => {
    const op = protocol.createOperation({
      ...identity, operation: verb, versionId: crypto.randomUUID(),
      operationId: crypto.randomUUID(),
      revision: { counter, deviceId: "device-a" },
      baseRevision: counter === 1 ? null : { counter: 1, deviceId: "device-a" },
      metadata: verb === "create"
        ? { path: "docs/signed.txt", name: "signed.txt", size: 13 }
        : { path: "docs/signed.txt" },
      plaintext: verb === "create" ? Buffer.from("SIGNED_CREATE") : Buffer.from("{}"),
      fileKey: key,
    });
    op.authorization = await createAuthorizationProof(op, {
      username: "alice", privateKey: signer.privateKey, publicKey,
      expiresAt: Date.now() + 60000,
    });
    assert.equal(await verifyAuthorizationProof(op.authorization, op, {
      username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
      revokedDeviceIds: [],
    }), true);
    return op;
  };
  const originalCreate = await signed("create", 1);
  const actualSignedDelete = await signed("delete", 2);
  const mutable = JSON.parse(protocol.canonicalJson(originalCreate));
  const originalAuthorization = client.assertOutgoingAuthorized;
  const originalPush = adapter.push;
  const remoteDirectory = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-delete-aba-"));
  t.after(() => fsp.rm(remoteDirectory, { recursive: true, force: true }));
  const remoteProof = path.join(remoteDirectory, "remote-signed-delete.bin");
  let dispatched;
  client.assertOutgoingAuthorized = async (_op, action = null) => {
    // A caller-owned signed CREATE may be replaced with an independently
    // valid signed DELETE after the initial guard but before the callback.
    for (const field of Object.keys(mutable)) delete mutable[field];
    Object.assign(mutable, JSON.parse(protocol.canonicalJson(actualSignedDelete)));
    return action ? action() : true;
  };
  adapter.push = async (sent) => {
    dispatched = JSON.parse(protocol.canonicalJson(sent));
    const handle = await fsp.open(remoteProof, "wx", 0o600);
    try {
      await handle.writeFile(protocol.canonicalJson(dispatched));
      await handle.sync();
    } finally { await handle.close(); }
    return { status: 201 };
  };
  try {
    await assert.rejects(client.withMutationLock(() => client.retryPush(mutable)),
      { code: "invalid_snapshot" },
      "the caller-owned signed envelope must stay immutable through authorization and dispatch");
  } finally {
    client.assertOutgoingAuthorized = originalAuthorization;
    adapter.push = originalPush;
  }
  assert.equal(dispatched, undefined,
    "even a valid signed DELETE may not reach the adapter after a mutable CREATE preflight");
  assert.equal(await exists(remoteProof), false);
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false,
    "an aborted pre-dispatch race must not invent an indeterminate physical write");
  assert.equal(state.pushes, 0);

  // Stronger synchronous last-use attack: the final signed-envelope check
  // has already completed when JavaScript resolves adapter.push. A getter can
  // swap the caller-owned object to a genuinely signed DELETE at that instant
  // without any await or microtask. The transport must never see that inode
  // delete and the enclosing root lock must not become a false authority.
  const getterRebound = JSON.parse(protocol.canonicalJson(originalCreate));
  const priorPushDescriptor = Object.getOwnPropertyDescriptor(adapter, "push");
  dispatched = undefined;
  client.assertOutgoingAuthorized = async (_op, action = null) =>
    action ? action() : true;
  Object.defineProperty(adapter, "push", {
    configurable: true,
    get() {
      for (const field of Object.keys(getterRebound)) delete getterRebound[field];
      Object.assign(getterRebound, JSON.parse(protocol.canonicalJson(actualSignedDelete)));
      return async (sent) => {
        dispatched = JSON.parse(protocol.canonicalJson(sent));
        const handle = await fsp.open(remoteProof, "wx", 0o600);
        try {
          await handle.writeFile(protocol.canonicalJson(dispatched));
          await handle.sync();
        } finally { await handle.close(); }
        return { status: 201 };
      };
    },
  });
  try {
    await assert.rejects(client.withMutationLock(() => client.retryPush(getterRebound)),
      { code: "invalid_snapshot" },
      "synchronous adapter getter substitution must not reach the outbound transport");
  } finally {
    client.assertOutgoingAuthorized = originalAuthorization;
    if (priorPushDescriptor) Object.defineProperty(adapter, "push", priorPushDescriptor);
    else delete adapter.push;
  }
  assert.equal(dispatched, undefined, "the signed foreign DELETE must never reach the adapter");
  assert.equal(await exists(remoteProof), false);
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false);
  assert.equal(state.pushes, 0);

  // A correctly authorized CREATE must still reach the adapter with exactly
  // its signed bytes, but never with the caller's mutable object identity.
  const legitimateCreate = JSON.parse(protocol.canonicalJson(originalCreate));
  const createProof = path.join(remoteDirectory, "legitimate-signed-create.bin");
  const savedPushDescriptor = Object.getOwnPropertyDescriptor(adapter, "push");
  let receivedCreate;
  client.assertOutgoingAuthorized = async (_op, action = null) =>
    action ? action() : true;
  adapter.push = async (sent) => {
    assert.notStrictEqual(sent, legitimateCreate);
    assert.notStrictEqual(sent.metadata, legitimateCreate.metadata);
    assert.notStrictEqual(sent.authorization, legitimateCreate.authorization);
    receivedCreate = JSON.parse(protocol.canonicalJson(sent));
    const handle = await fsp.open(createProof, "wx", 0o600);
    try {
      await handle.writeFile(protocol.canonicalJson(receivedCreate));
      await handle.sync();
    } finally { await handle.close(); }
    return { status: 201 };
  };
  try {
    await client.withMutationLock(() => client.retryPush(legitimateCreate));
  } finally {
    client.assertOutgoingAuthorized = originalAuthorization;
    if (savedPushDescriptor) Object.defineProperty(adapter, "push", savedPushDescriptor);
    else delete adapter.push;
  }
  assert.equal(protocol.canonicalJson(receivedCreate), protocol.canonicalJson(originalCreate));
  assert.equal(await verifyAuthorizationProof(receivedCreate.authorization, receivedCreate, {
    username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [],
  }), true);
  assert.equal(await exists(createProof), true);
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false);
});

test("issue 66: a started but unawaited native-required _apply keeps the physical lock through all awaited I/O", { skip: NATIVE_PUBLISH_PENDING }, async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "remote content behind deferred key resolver",
  });
  const client = await open();
  const operation = store.list("alice").find((entry) => entry.metadata?.path === "docs/restore.txt");
  assert.ok(operation);
  const physicalLock = path.join(root, ".rootark-sync.lock");
  const originalKeyFor = client.keyFor.bind(client);
  let releaseKey;
  let enteredKey;
  const deferredKey = new Promise((resolve) => { releaseKey = resolve; });
  const keyStarted = new Promise((resolve) => { enteredKey = resolve; });
  client.keyFor = async (...args) => {
    enteredKey();
    await deferredKey;
    return originalKeyFor(...args);
  };
  let pendingApply;
  let outerSettled = false;
  const owner = client.withMutationLock(async () => {
    pendingApply = client._apply(operation);
    await keyStarted;
    // Deliberately return without awaiting the started _apply.
  }).then(() => { outerSettled = true; });
  await keyStarted;
  // Give the original owner's async finally a complete event-loop turn. The
  // lock must be retained even when the callback has already returned.
  await new Promise((resolve) => setImmediate(resolve));
  const stillHeld = await exists(physicalLock);
  const prematurelySettled = outerSettled;
  releaseKey();
  await Promise.all([owner, pendingApply]);
  assert.equal(stillHeld, true,
    "a live native-required mutation must retain the real process lock across deferred key I/O");
  assert.equal(prematurelySettled, false,
    "withMutationLock may not settle before an in-flight private mutation");
  assert.equal(await exists(physicalLock), false,
    "the physical lock may be retired only AFTER the complete inbound transaction");
  assert.equal(await fsp.readFile(path.join(root, "docs", "restore.txt"), "utf8"),
    "remote content behind deferred key resolver");
  assert.equal(state.pushes, 0);
});

test("issue 66: a started unawaited native-required outbound retry holds its lock until adapter I/O finishes", async (t) => {
  const { root, open, store, adapter, state } = await setup(t, {
    "docs/restore.txt": "remote outbound test fixture",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const rootLock = path.join(root, ".rootark-sync.lock");
  let releaseDispatch;
  let dispatchStarted;
  let dispatchCalls = 0;
  const dispatchGate = new Promise((resolve) => { releaseDispatch = resolve; });
  const entered = new Promise((resolve) => { dispatchStarted = resolve; });
  const originalPush = adapter.push;
  adapter.push = async () => {
    dispatchCalls += 1;
    dispatchStarted();
    await dispatchGate;
    return { status: 201 };
  };
  let pendingRetry;
  let ownerSettled = false;
  try {
    const owner = client.withMutationLock(async () => {
      pendingRetry = client.retryPush(operation);
      await entered;
      // Intentionally return before the private outbound request completes.
    }).then(() => { ownerSettled = true; });
    await entered;
    await new Promise((resolve) => setImmediate(resolve));
    const heldWhileDispatchPending = await exists(rootLock);
    const prematureOwnerCompletion = ownerSettled;
    releaseDispatch();
    await Promise.all([owner, pendingRetry]);
    assert.equal(heldWhileDispatchPending, true,
      "cross-process root exclusion must cover a started outbound request");
    assert.equal(prematureOwnerCompletion, false);
    assert.equal(await exists(rootLock), false);
    assert.equal(dispatchCalls, 1);
    assert.equal(state.pushes, 0, "fixture's real remote writer must never run");
  } finally {
    releaseDispatch();
    adapter.push = originalPush;
  }
});

test("issue 66: direct native-required cold open and snapshot persistence cannot bypass the physical root lock", async (t) => {
  const { root, open, state, store } = await setup(t, {
    "docs/restore.txt": "cache fixture never admitted without the physical lock",
  });
  const client = await open();
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  const remoteBefore = JSON.stringify(store.list("alice"));
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client._open(), { code: "sync_root_busy" });
  await assert.rejects(client.persistSnapshot(), { code: "sync_root_busy" });
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(await exists(path.join(root, "docs", "restore.txt")), false);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.pushes, 0);
});

test("issue 66: direct cold private _materializeRemote cannot create a root marker before acquiring the physical lock", async (t) => {
  const { root, adapter, key, state } = await setup(t, {
    "docs/restore.txt": "remote cold inventory fixture",
  });
  const client = new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true,
  });
  await fsp.mkdir(root, { recursive: true });
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client._materializeRemote("docs/restore.txt"),
    { code: "sync_root_busy" });
  for (const leaf of [".rootark-sync-ever-fod", ".rootark-sync-index.json",
    ".rootark-sync-journal.json", "docs"]) {
    assert.equal(await exists(path.join(root, leaf)), false,
      `private cold path must not create ${leaf} under an unowned lock`);
  }
  assert.equal(state.pushes, 0);
  assert.equal(state.inventoryReads, 0, "deny before contacting remote inventory");
});

test("issue 66: an unawaited inbound publish that physically renames then fails cannot make its lock owner succeed", { skip: NATIVE_PUBLISH_PENDING }, async (t) => {
  const payload = "published physical bytes before injected EIO";
  const { root, open, store, state } = await setup(t, { "docs/restore.txt": payload });
  const client = await open();
  const operation = store.list("alice").find((entry) => entry.metadata?.path === "docs/restore.txt");
  assert.ok(operation);
  const target = path.join(root, "docs", "restore.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshot);
  const originalKeyFor = client.keyFor.bind(client);
  const originalRename = fsp.rename;
  let keyEntered;
  let releaseKey;
  const entered = new Promise((resolve) => { keyEntered = resolve; });
  const gate = new Promise((resolve) => { releaseKey = resolve; });
  client.keyFor = async (...args) => {
    keyEntered();
    await gate;
    return originalKeyFor(...args);
  };
  let physicallyPublished = false;
  fsp.rename = async (source, destination, ...args) => {
    if (!physicallyPublished && String(source).includes(".tmp-inbound-")
      && path.resolve(String(destination)) === path.resolve(target)) {
      await originalRename(source, destination, ...args);
      physicallyPublished = true;
      throw Object.assign(new Error("physical inbound rename completed then EIO"), { code: "EIO" });
    }
    return originalRename(source, destination, ...args);
  };
  let detached;
  try {
    const owner = client.withMutationLock(async () => {
      detached = client._apply(operation);
      await entered;
      // Return without awaiting the started private physical publication.
    });
    await entered;
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true);
    releaseKey();
    await assert.rejects(owner, { code: "EIO" },
      "outer lock owner must not report SUCCESS after detached publisher EIO");
    // Attach the caller observer only AFTER the owner has observed the error:
    // the trusted internal observer must prevent an unhandled Node rejection.
    await assert.rejects(detached, { code: "EIO" });
  } finally {
    releaseKey();
    fsp.rename = originalRename;
  }
  assert.equal(physicallyPublished, true);
  assert.equal(await fsp.readFile(target, "utf8"), payload);
  assert.deepEqual(await fsp.readFile(snapshot), snapshotBefore);
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "ambiguous physical completion must quarantine the real process lock");
  assert.equal(state.pushes, 0);
  await assert.rejects(open(), { code: "sync_root_busy" });
});

test("issue 66: an unawaited outbound adapter failure cannot make the physical lock owner succeed", async (t) => {
  const { root, open, store, state, adapter } = await setup(t, {
    "docs/restore.txt": "remote owned bytes",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const originalPush = adapter.push;
  let dispatchEntered;
  let releaseDispatch;
  const entered = new Promise((resolve) => { dispatchEntered = resolve; });
  const gate = new Promise((resolve) => { releaseDispatch = resolve; });
  adapter.push = async () => {
    dispatchEntered();
    await gate;
    throw Object.assign(new Error("injected unresolved remote acknowledgement"),
      { code: "authorization_rejected" });
  };
  let detached;
  try {
    const owner = client.withMutationLock(async () => {
      detached = client.retryPush(operation);
      await entered;
    });
    await entered;
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true);
    releaseDispatch();
    await assert.rejects(owner, { code: "authorization_rejected" });
    await assert.rejects(detached, { code: "authorization_rejected" });
  } finally {
    releaseDispatch();
    adapter.push = originalPush;
  }
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "detached ambiguous outgoing I/O must not retire its owner's physical lock");
  assert.equal(state.pushes, 0, "the fixture's real remote writer must not execute");
});

test("issue 66: an already-settled unawaited private retry failure still blocks the owner's success", async (t) => {
  const { root, open, store, state, adapter } = await setup(t, {
    "docs/restore.txt": "signed remote retry failure",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const lock = path.join(root, ".rootark-sync.lock");
  const originalPush = adapter.push;
  let entered;
  const pushEntered = new Promise((resolve) => { entered = resolve; });
  adapter.push = async () => {
    entered();
    throw Object.assign(new Error("remote commit has unknown outcome"), { code: "EIO" });
  };
  let unawaited;
  try {
    const owner = client.withMutationLock(async () => {
      unawaited = client.retryPush(operation);
      await pushEntered;
      // The rejected private promise FINISHES before the owner callback
      // returns. Its ticket is no longer in the active inFlight set.
      await new Promise((resolve) => setImmediate(resolve));
    });
    await assert.rejects(owner, { code: "EIO" },
      "a failed private operation must not vanish when its ticket settled early");
    await assert.rejects(unawaited, { code: "EIO" });
  } finally {
    adapter.push = originalPush;
  }
  assert.equal(await exists(lock), true,
    "a detached failed remote request must keep the real physical lock");
  assert.equal(state.pushes, 0);
  await assert.rejects(open(), { code: "sync_root_busy" });
});

test("issue 66: an owner that throws cannot release the lock after a different detached error has settled", async (t) => {
  const { root, open, store, adapter, state } = await setup(t, {
    "docs/restore.txt": "signed remote operation",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const oldPush = adapter.push;
  let entered;
  const dispatched = new Promise((resolve) => { entered = resolve; });
  adapter.push = async () => {
    entered();
    throw Object.assign(new Error("ambiguous detached remote I/O"), { code: "EIO" });
  };
  let child;
  try {
    const owner = client.withMutationLock(async () => {
      child = client.retryPush(operation);
      await dispatched;
      // The detached EIO finishes before the owner's independent rejection.
      await new Promise((resolve) => setImmediate(resolve));
      throw Object.assign(new Error("independent owner failure"), { code: "owner_abort" });
    });
    await assert.rejects(owner, { code: "owner_abort" },
      "the primary owner error must remain intact");
    await assert.rejects(child, { code: "EIO" });
  } finally {
    adapter.push = oldPush;
  }
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "an independently failed owner must still quarantine earlier detached I/O");
  assert.equal(state.pushes, 0);
  await assert.rejects(open(), { code: "sync_root_busy" });
});

test("issue 66: identical Error objects from two independent outbound attempts cannot release a detached root lock", async (t) => {
  const { root, open, store, adapter, state } = await setup(t, {
    "docs/restore.txt": "signed remote operation",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const sharedError = Object.assign(new Error("ambiguous shared adapter error"), { code: "EIO" });
  const originalPush = adapter.push;
  let sent = 0;
  let firstEntered;
  const firstDispatch = new Promise((resolve) => { firstEntered = resolve; });
  adapter.push = async () => {
    sent += 1;
    if (sent === 1) firstEntered();
    throw sharedError;
  };
  let detached;
  try {
    const owner = client.withMutationLock(async () => {
      detached = client.retryPush(operation);
      await firstDispatch;
      // First detached operation settles before a SECOND trusted awaited
      // operation propagates the EXACT SAME Error object to the owner.
      await new Promise((resolve) => setImmediate(resolve));
      await client.retryPush(operation);
    });
    await assert.rejects(owner, (error) => error === sharedError);
    await assert.rejects(detached, (error) => error === sharedError);
  } finally {
    adapter.push = originalPush;
  }
  assert.equal(sent, 2, "the two physical dispatches must have independent tickets");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "Error object identity cannot authorize releasing a lock after detached I/O");
  assert.equal(state.pushes, 0);
  await assert.rejects(open(), { code: "sync_root_busy" });
});

test("issue 66: adapter-reported offline after outbound entry cannot prove a safe no-write release", async (t) => {
  const { root, open, adapter, store, state } = await setup(t, {});
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "new.txt"), "local queued bytes");
  const originalPush = adapter.push;
  adapter.push = async () => {
    throw Object.assign(new Error("unverified offline after adapter dispatch"), { code: "offline" });
  };
  const client = await open();
  try {
    await assert.rejects(client.syncOnce(), { code: "offline" });
    assert.equal(state.pushes, 0);
    assert.equal((await client.journal.recover()).length, 1);
    assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
      "an adapter's unauthenticated error code cannot prove no remote write");
  } finally {
    adapter.push = originalPush;
  }
  assert.equal(store.list("alice").length, 0);
  await assert.rejects(open(), { code: "sync_root_busy" });
});

test("issue 66: remote COMMIT followed by lost ACK keeps native-required lock under ETIMEDOUT", async (t) => {
  const { root, open, adapter, store, state } = await setup(t, {});
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "lost-ack.txt"), "physical remote commit");
  const originalPush = adapter.push;
  let acknowledgedByStore = false;
  adapter.push = async (operation) => {
    const result = await originalPush(operation);
    assert.equal(result.status, 201);
    acknowledgedByStore = true;
    throw Object.assign(new Error("network timeout after remote commit"), { code: "ETIMEDOUT" });
  };
  const client = await open();
  try {
    await assert.rejects(client.syncOnce(), { code: "ETIMEDOUT" });
  } finally {
    adapter.push = originalPush;
  }
  assert.equal(acknowledgedByStore, true, "real in-memory server must have committed before lost ACK");
  assert.equal(store.list("alice").filter((entry) =>
    entry.metadata?.path === "docs/lost-ack.txt").length, 1);
  assert.ok(state.pushes >= 1, "adapter must have performed real remote writes");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true);
  await assert.rejects(open(), { code: "sync_root_busy" });
});

test("issue 66: cold FOD mode marker fsync followed by EIO cannot release the physical lock", async (t) => {
  const { root, open, state } = await setup(t, {
    "docs/restore.txt": "signed remote bytes",
  });
  const originalOpen = fsp.open;
  let physicallySynced = false;
  fsp.open = async (file, flags, ...args) => {
    const handle = await originalOpen(file, flags, ...args);
    if (path.basename(String(file)) === ".rootark-sync-ever-fod" && flags === "wx") {
      const actualSync = handle.sync.bind(handle);
      handle.sync = async () => {
        await actualSync();
        physicallySynced = true;
        throw Object.assign(new Error("marker fsync completed then EIO"), { code: "EIO" });
      };
    }
    return handle;
  };
  try {
    await assert.rejects(open(), { code: "EIO" });
  } finally {
    fsp.open = originalOpen;
  }
  assert.equal(physicallySynced, true, "the real marker fsync must precede injected failure");
  assert.equal(await fsp.readFile(path.join(root, ".rootark-sync-ever-fod"), "utf8"),
    "rootark-sync-ever-fod-v1\n");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "an indeterminate cold admission must leave the physical lock acquired");
  assert.equal(state.pushes, 0);
  await assert.rejects(open(), { code: "sync_root_busy" });
});

test("issue 66: durable signed inbound seen write followed by EIO keeps the physical root lock", { skip: NATIVE_PUBLISH_PENDING }, async (t) => {
  const { root, open, state } = await setup(t, {
    "docs/restore.txt": "original authenticated remote payload",
  });
  const client = await open();
  const originalMarkSeen = client.journal.markSeen.bind(client.journal);
  let written = false;
  client.journal.markSeen = async (...args) => {
    const result = await originalMarkSeen(...args);
    written = true;
    throw Object.assign(new Error("durable markSeen returned EIO after real write"), { code: "EIO" });
  };
  try {
    await assert.rejects(client.materializeRemote("docs/restore.txt"), { code: "EIO" });
  } finally {
    client.journal.markSeen = originalMarkSeen;
  }
  assert.equal(written, true, "the real journal I/O must complete before injected EIO");
  assert.equal(await fsp.readFile(path.join(root, "docs", "restore.txt"), "utf8"),
    "original authenticated remote payload");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "an uncertain post-journal syscall result cannot release the root");
  assert.equal(state.pushes, 0);
  await assert.rejects(open(), { code: "sync_root_busy" });
});

test("issue 66: real local enqueue followed by EIO cannot release the native-required root lock", async (t) => {
  const { root, open, state } = await setup(t, {});
  const client = await open();
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "new.txt"), "local bytes without a trusted ACK");
  const originalEnqueue = client.journal.enqueue.bind(client.journal);
  let enqueued = false;
  client.journal.enqueue = async (...args) => {
    const result = await originalEnqueue(...args);
    enqueued = true;
    throw Object.assign(new Error("journal enqueue completed then EIO"), { code: "EIO" });
  };
  try {
    await assert.rejects(client.reconcileLocal(), { code: "EIO" });
  } finally {
    client.journal.enqueue = originalEnqueue;
  }
  assert.equal(enqueued, true);
  assert.equal((await client.journal.recover()).length, 1);
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true);
  assert.equal(state.pushes, 0);
  await assert.rejects(open(), { code: "sync_root_busy" });
});

test("issue 66: direct private signed batch and out-of-scope reconciliation must not bypass a foreign lock", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "private/excluded.txt": "signed remote bytes",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  const remoteBefore = JSON.stringify(store.list("alice"));
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client.reconcileOutOfScopeMove(operation, { conflicts: [] }),
    { code: "sync_root_busy" });
  await assert.rejects(client.pushAtomicSignedOverwritePair([operation, operation],
    { pushed: 0 }), { code: "sync_root_busy" });
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.pushes, 0);
  assert.equal(await exists(path.join(root, "private", "excluded.txt")), false);
});

test("issue 66: direct private eviction, staging and ledger replay cannot probe past a foreign lock", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/cache.txt": "signed remote cache bytes",
  });
  const client = await open();
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client.stageExisting(path.join(root, "docs", "cache.txt")),
    { code: "root_session_native_unavailable" });
  await assert.rejects(client._evictLocal("docs/cache.txt"),
    { code: "root_session_native_unavailable" });
  await assert.rejects(client.replayEvictionLedger(), { code: "sync_root_busy" });
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 1);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: native-required private pull, push, enqueue and prune deny before reading or mutating", async (t) => {
  const { root, open, state, store } = await setup(t, {
    "docs/restore.txt": "authenticated remote bytes",
  });
  const client = await open();
  const empty = path.join(root, "docs", "nested-empty");
  await fsp.mkdir(empty, { recursive: true });
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshot);
  const readsBefore = state.fullReads.length;
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client._pullRemote({ pulled: 0, offline: false }),
    { code: "sync_root_busy" });
  await assert.rejects(client._pushPending({ pushed: 0 }),
    { code: "sync_root_busy" });
  await assert.rejects(client._enqueueChange({ operation: "create" }),
    { code: "sync_root_busy" });
  await assert.rejects(client.pruneEmptyUntrackedParents(empty),
    { code: "sync_root_busy" });
  assert.equal(await exists(empty), true, "a foreign lock must prevent rmdir of an untracked parent");
  assert.equal(state.fullReads.length, readsBefore,
    "direct pull must refuse before network inventory or full-content fetch");
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 1);
  assert.deepEqual(await fsp.readFile(snapshot), snapshotBefore);
});

test("issue 66: equal-byte foreign inbound stage cannot authorize a successful FOD publish", { skip: NATIVE_PUBLISH_PENDING }, async (t) => {
  const payload = "remote source payload with identical foreign bytes";
  const { root, open, store, state } = await setup(t, { "docs/restore.txt": payload });
  const client = await open();
  const parent = path.join(root, "docs");
  await fsp.mkdir(parent, { recursive: true });
  const target = path.join(parent, "restore.txt");
  const parked = path.join(path.dirname(root), "original-inbound-stage-parked");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const oldSnapshot = await fsp.readFile(snapshot);
  const storeBefore = JSON.stringify(store.list("alice"));
  const originalOpen = fsp.open;
  const originalRename = fsp.rename;
  const heldFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  const observeOpened = async (handle) => {
    const before = await handle.stat({ bigint: true });
    assert.equal(before.isFile(), true);
    assert.ok(before.ino > 0n && before.size <= BigInt(Buffer.byteLength(payload)));
    const bytes = Buffer.alloc(Buffer.byteLength(payload) + 1);
    let count = 0;
    while (count < bytes.length) {
      const { bytesRead } = await handle.read(bytes, count, bytes.length - count, count);
      if (!bytesRead) break;
      count += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    assert.equal(after.size, before.size);
    assert.equal(after.mtimeNs, before.mtimeNs);
    assert.equal(BigInt(count), before.size);
    return { stat: before, bytes: bytes.subarray(0, count).toString("utf8") };
  };
  let publisherHandle;
  let foreignHandle;
  let parkedHandle;
  let publishedHandle;
  let originalInode;
  let foreignInode;
  let physicallyPublished = false;
  fsp.open = async (file, flags, ...args) => {
    const handle = await originalOpen(file, flags, ...args);
    if (!publisherHandle && typeof flags === "number" && (flags & fs.constants.O_EXCL)
      && String(file).includes(".tmp-inbound-")) publisherHandle = handle;
    return handle;
  };
  fsp.rename = async (source, destination, ...args) => {
    if (!physicallyPublished && path.resolve(String(destination)) === path.resolve(target)
      && String(source).includes(".tmp-inbound-")) {
      assert.ok(publisherHandle, "the producer must retain its exact opened stage handle");
      originalInode = await publisherHandle.stat({ bigint: true });
      assert.equal(originalInode.isFile(), true);
      await originalRename(source, parked);
      foreignHandle = await fsp.open(source, fs.constants.O_RDWR | fs.constants.O_CREAT
        | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
      await foreignHandle.writeFile(payload);
      await foreignHandle.sync();
      foreignInode = (await observeOpened(foreignHandle)).stat;
      assert.equal(originalInode.dev === foreignInode.dev
        && originalInode.ino === foreignInode.ino, false,
        "physical replacement must be a different inode despite byte equality");
      await originalRename(source, destination, ...args);
      physicallyPublished = true;
      const stillHeld = await publisherHandle.stat({ bigint: true });
      assert.equal(stillHeld.dev, originalInode.dev);
      assert.equal(stillHeld.ino, originalInode.ino,
        "the same original publisher inode must remain opened after foreign publication");
      return;
    }
    return originalRename(source, destination, ...args);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/restore.txt"),
      { code: "invalid_snapshot" });
    assert.equal(physicallyPublished, true,
      "test must cause a REAL kernel rename of foreign source bytes into the target");
    parkedHandle = await fsp.open(parked, heldFlags);
    publishedHandle = await fsp.open(target, heldFlags);
    const parkedProof = await observeOpened(parkedHandle);
    const publishedProof = await observeOpened(publishedHandle);
    assert.equal(parkedProof.stat.dev, originalInode.dev);
    assert.equal(parkedProof.stat.ino, originalInode.ino,
      "parked name must bind to the original opened stage inode");
    assert.equal(publishedProof.stat.dev, foreignInode.dev);
    assert.equal(publishedProof.stat.ino, foreignInode.ino,
      "published name must bind to the actual opened foreign inode");
    assert.equal(publishedProof.bytes, payload,
      "the same opened foreign inode must contain the byte-identical payload");
    assert.equal(parkedProof.bytes, payload);
    assert.equal((await observeOpened(foreignHandle)).bytes, payload);
    assert.deepEqual(await fsp.readFile(snapshot), oldSnapshot,
      "the untrusted replacement must not become durably authenticated metadata");
    assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true);
    await assert.rejects(client._reconcileLocal(), { code: "sync_inbound_indeterminate" });
    await assert.rejects(open(), { code: "sync_root_busy" });
    assert.equal(state.pushes, 0);
    assert.equal(JSON.stringify(store.list("alice")), storeBefore);
  } finally {
    fsp.rename = originalRename;
    fsp.open = originalOpen;
    if (publishedHandle) await publishedHandle.close();
    if (parkedHandle) await parkedHandle.close();
    if (foreignHandle) await foreignHandle.close();
  }
});

test("issue 66: signed FOD directory CREATE followed by snapshot EIO keeps cold root locked", { skip: NATIVE_PUBLISH_PENDING }, async (t) => {
  const { root, adapter, store, state, key } = await setup(t, {});
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trusted = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] };
  const engineOptions = {
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: (op) => verifyAuthorizationProof(op.authorization, op, trusted),
  };
  const client = await new SyncEngine(engineOptions).open();
  const directory = path.join(root, "docs");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const oldSnapshot = await fsp.readFile(snapshot);
  const operation = protocol.createOperation({
    operation: "create", objectId: `object-${crypto.randomUUID()}`,
    fileId: `file-${crypto.randomUUID()}`, versionId: crypto.randomUUID(),
    operationId: crypto.randomUUID(), deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
    baseRevision: null, metadata: { path: "docs", name: "docs", size: 0,
      contentType: "inode/directory" }, plaintext: Buffer.alloc(0), fileKey: key,
  });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: signer.privateKey, publicKey,
    expiresAt: Date.now() + 60_000,
  });
  const oldStore = JSON.stringify(store.list("alice"));
  const originalMkdir = fsp.mkdir;
  const originalRename = fsp.rename;
  let physicallyCreated = false;
  let snapshotEio = false;
  fsp.mkdir = async (candidate, ...args) => {
    const result = await originalMkdir(candidate, ...args);
    if (path.resolve(String(candidate)) === path.resolve(directory)) physicallyCreated = true;
    return result;
  };
  fsp.rename = async (source, target, ...args) => {
    if (physicallyCreated && !snapshotEio && path.resolve(String(target)) === path.resolve(snapshot)
      && String(source).includes(".tmp-")) {
      snapshotEio = true;
      throw Object.assign(new Error("injected snapshot publish EIO after mkdir"), { code: "EIO" });
    }
    return originalRename(source, target, ...args);
  };
  try {
    await assert.rejects(client.apply(operation), { code: "EIO" });
  } finally {
    fsp.mkdir = originalMkdir;
    fsp.rename = originalRename;
  }
  assert.equal(physicallyCreated, true, "the physical signed directory CREATE must actually execute");
  assert.equal(snapshotEio, true, "EIO must happen at the later snapshot, not before mkdir");
  assert.equal((await fsp.lstat(directory)).isDirectory(), true);
  assert.deepEqual(await fsp.readFile(snapshot), oldSnapshot,
    "the durable snapshot must not claim the newly created directory");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "indeterminate physical directory CREATE must retain the process lock");
  await assert.rejects(new SyncEngine(engineOptions).open(), { code: "sync_root_busy" });
  assert.equal(state.pushes, 0, "no outbound push is observed; this does not prove an upload attempt");
  const journal = JSON.parse(await fsp.readFile(path.join(root, ".rootark-sync-journal.json"), "utf8"));
  assert.deepEqual(journal.pending, [], "a fresh local CREATE must not have been enqueued");
  assert.equal(JSON.stringify(store.list("alice")), oldStore);
});

test("issue 66: signed FOD directory UPDATE cannot relocate cached subtree without native custody", { skip: NATIVE_PUBLISH_PENDING }, async (t) => {
  const { root, adapter, store, state, key } = await setup(t, {});
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trusted = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] };
  const client = await new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: (op) => verifyAuthorizationProof(op.authorization, op, trusted),
  }).open();
  const objectId = `dir-${crypto.randomUUID()}`;
  const fileId = `file-${crypto.randomUUID()}`;
  const signedDirectory = async (verb, relative, revisionCounter, baseRevision = null) => {
    const operation = protocol.createOperation({
      operation: verb, objectId, fileId, versionId: crypto.randomUUID(),
      operationId: crypto.randomUUID(), deviceId: "device-a", keyEpoch: "epoch-1",
      compartmentId: "private", revision: { counter: revisionCounter, deviceId: "device-a" },
      baseRevision, metadata: { path: relative, name: path.posix.basename(relative), size: 0,
        contentType: "inode/directory" }, plaintext: Buffer.alloc(0), fileKey: key,
    });
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", privateKey: signer.privateKey, publicKey,
      expiresAt: Date.now() + 60_000,
    });
    assert.equal(await verifyAuthorizationProof(operation.authorization, operation, trusted), true);
    return operation;
  };
  const created = await signedDirectory("create", "docs/old", 1);
  await client.apply(created);
  const oldDirectory = path.join(root, "docs", "old");
  const newDirectory = path.join(root, "docs", "new");
  const sentinel = path.join(oldDirectory, "original-cache-sentinel.bin");
  const sentinelBytes = Buffer.from("ORIGINAL_DIRECTORY_CACHE_INODE");
  // Retain the ORIGINAL exclusive inode through the signed UPDATE. Track
  // attempted renames before the kernel syscall, so a Windows sharing denial
  // cannot accidentally make this negative custody test pass.
  const held = await fsp.open(sentinel, "wx+", 0o600);
  t.after(() => held.close());
  let originalSentinel;
  await held.writeFile(sentinelBytes);
  await held.sync();
  originalSentinel = await held.stat({ bigint: true });
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const journal = path.join(root, ".rootark-sync-journal.json");
  const snapshotBefore = await fsp.readFile(snapshot);
  const journalBefore = await fsp.readFile(journal);
  const pushesBefore = state.pushes;
  const remoteBefore = JSON.stringify(store.list("alice"));
  const updated = await signedDirectory("update", "docs/new", 2, created.revision);
  const originalRename = fsp.rename;
  let attemptedDirectoryRename = false;
  let physicallyRenamedDirectory = false;
  fsp.rename = async (from, to, ...args) => {
    const isDirectoryUpdate = path.resolve(String(from)) === oldDirectory
      && path.resolve(String(to)) === newDirectory;
    if (isDirectoryUpdate) attemptedDirectoryRename = true;
    const result = await originalRename(from, to, ...args);
    if (isDirectoryUpdate) physicallyRenamedDirectory = true;
    return result;
  };
  try {
    await assert.rejects(client.apply(updated), { code: "root_session_native_unavailable" },
      "signed UPDATE cannot authorize physical directory rename via legacy pathname code");
  } finally { fsp.rename = originalRename; }
  assert.equal(physicallyRenamedDirectory, false,
    "the kernel must never complete a legacy directory rename in native-required mode");
  assert.equal(attemptedDirectoryRename, false,
    "even a blocked or EBUSY native rename attempt cannot count as an authorization denial");
  // An originally opened handle needs NO pathname reopen after its first
  // fstat. Read the same inode at an explicit offset (the write advanced the
  // file position) and compare pre/post FD metadata and the visible name.
  const before = await held.stat({ bigint: true });
  const buffer = Buffer.alloc(sentinelBytes.length + 1);
  const { bytesRead } = await held.read(buffer, 0, buffer.length, 0);
  const after = await held.stat({ bigint: true });
  const named = await fsp.lstat(sentinel, { bigint: true });
  assert.equal(before.isFile(), true);
  assert.equal(before.dev, originalSentinel.dev);
  assert.equal(before.ino, originalSentinel.ino);
  assert.equal(before.size, originalSentinel.size);
  assert.equal(after.dev, before.dev);
  assert.equal(after.ino, before.ino);
  assert.equal(after.size, before.size);
  assert.equal(named.dev, originalSentinel.dev);
  assert.equal(named.ino, originalSentinel.ino);
  assert.equal(bytesRead, sentinelBytes.length);
  assert.deepEqual(buffer.subarray(0, bytesRead), sentinelBytes);
  assert.equal((await fsp.lstat(oldDirectory)).isDirectory(), true);
  assert.equal(await exists(newDirectory), false);
  assert.deepEqual(await fsp.readFile(snapshot), snapshotBefore);
  assert.deepEqual(await fsp.readFile(journal), journalBefore,
    "the negative gate must run before durable signed admission");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false);
  assert.equal(state.pushes, pushesBefore);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
});

test("issue 66: a dangling ever-FOD symlink is invalid, never an absent root marker", async (t) => {
  const { root, adapter, key } = await setup(t, {});
  await fsp.mkdir(root, { recursive: true });
  const marker = path.join(root, ".rootark-sync-ever-fod");
  try { await fsp.symlink("nonexistent-target", marker, "file"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) { t.skip("symlink creation unavailable"); return; }
    throw error;
  }
  await assert.rejects(new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key,
  }).open(), { code: "root_mode_marker_invalid" });
  assert.equal(await exists(path.join(root, ".rootark-sync-index.json")), false);
});

test("issue 66: held marker inspection uses bounded FD reads under physical concurrent growth", async (t) => {
  const { root, open, adapter, key } = await setup(t, {});
  await open();
  if (process.platform === "linux" && process.env.ROOTARK_ISSUE66_FIFO_REQUIRE_EXT4 === "1") {
    assert.match(process.version, /^v22\./);
    assert.equal((await fsp.statfs(root)).type, 0xef53,
      "explicit marker growth race must be exercised on physical ext4");
  }
  const marker = path.join(root, ".rootark-sync-ever-fod");
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  const originalSize = (await fsp.stat(marker)).size;
  const originalOpen = fsp.open;
  let unboundedRead = false;
  let mutated = false;
  let reads = 0;
  let maxRequested = 0;
  let totalReturned = 0;
  fsp.open = async (...args) => {
    const handle = await originalOpen(...args);
    if (args[0] === marker) {
      const actualRead = handle.read.bind(handle);
      handle.readFile = async () => {
        unboundedRead = true;
        throw new Error("UNBOUNDED_MARKER_READ_FORBIDDEN");
      };
      handle.read = async (buffer, offset, length, position) => {
        reads++;
        maxRequested = Math.max(maxRequested, length);
        if (!mutated) {
          mutated = true;
          await fsp.appendFile(marker, Buffer.alloc(256 * 1024, 0x41));
        }
        const result = await actualRead(buffer, offset, length, position);
        totalReturned += result.bytesRead;
        return result;
      };
    }
    return handle;
  };
  try {
    await assert.rejects(new SyncEngine({ rootDir: root, adapter,
      deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
      fileKeyResolver: () => key,
    }).open(), { code: "root_mode_marker_invalid" });
  } finally { fsp.open = originalOpen; }
  assert.equal(unboundedRead, false, "marker admission may not call FileHandle.readFile");
  assert.equal(mutated, true, "the race must modify the physical marker during FD read");
  assert.ok(reads > 0 && maxRequested <= originalSize + 1,
    `untrusted marker read must be capped to expected bytes + 1; observed ${maxRequested}`);
  assert.ok(totalReturned <= originalSize + 1,
    `aggregate marker bytes read must be bounded; observed ${totalReturned}`);
  assert.equal((await fsp.stat(marker)).size, originalSize + 256 * 1024);
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
});

test("issue 66: FIFO root marker fails closed in bounded cold subprocess opens and later legitimate recovery", { skip: process.platform !== "linux" }, async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-ever-fod-fifo-"));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  // CI may use overlayfs/tmpfs: require *physical* ext4 and Node22 only for
  // an explicit physical-custody run, without making ordinary hosted CI fail.
  if (process.env.ROOTARK_ISSUE66_FIFO_REQUIRE_EXT4 === "1") {
    assert.match(process.version, /^v22\./);
    assert.equal((await fsp.statfs(root)).type, 0xef53,
      "explicit FIFO physical run must actually use Linux ext4");
  }
  const marker = path.join(root, ".rootark-sync-ever-fod");
  const made = spawnSync("/usr/bin/mkfifo", [marker], { timeout: 1500, encoding: "utf8" });
  assert.equal(made.status, 0, made.stderr);
  const childSource = [
    "const { SyncEngine } = require(process.argv[1]);",
    "const rootDir = process.argv[2];",
    "const filesOnDemand = process.argv[3] === 'fod';",
    "new SyncEngine({ rootDir, deviceId: 'fifo-test-device', keyEpoch: 'epoch-1',",
    "compartmentId: 'private', filesOnDemand, fileKeyResolver: () => Buffer.alloc(32),",
    "adapter: { list: async () => [], listInventory: async () => ({protocolVersion:2, view:'metadata', objects:[], nextCursor:null}), push: async () => ({status: 201}) } }).open()",
    ".then(() => { process.stdout.write('OPEN_OK\\n'); process.exit(0); })",
    ".catch((error) => { process.stdout.write('DENIED:' + error.code + '\\n'); process.exit(2); });",
  ].join("\n");
  const reopen = (mode) => spawnSync(process.execPath,
    ["-e", childSource, require.resolve("../sync-client/rootark-sync-engine"), root, mode],
    { timeout: 8000, encoding: "utf8" });
  for (const mode of ["legacy", "fod"]) {
    const denied = reopen(mode);
    assert.equal(denied.error?.code, undefined, `FIFO marker must not hang ${mode} cold open`);
    assert.equal(denied.status, 2, denied.stderr);
    assert.match(denied.stdout, /DENIED:root_mode_marker_invalid/);
  }
  assert.equal(await fsp.stat(marker).then((s) => s.isFIFO()), true);
  assert.equal(await fsp.stat(path.join(root, ".rootark-sync-index.json")).then(() => true, () => false), false);
  await fsp.unlink(marker);
  const recovered = reopen("fod");
  assert.equal(recovered.error?.code, undefined);
  assert.equal(recovered.status, 0, recovered.stderr);
  assert.match(recovered.stdout, /OPEN_OK/);
  const coldReopen = reopen("fod");
  assert.equal(coldReopen.status, 0, coldReopen.stderr);
  assert.match(coldReopen.stdout, /OPEN_OK/);
  const downgrade = reopen("legacy");
  assert.equal(downgrade.status, 2, downgrade.stderr);
  assert.match(downgrade.stdout, /DENIED:root_mode_fod_required/);
});

test("issue 66: refuses unsafe cached refresh and preserves dirty cached bytes", async (t) => {
  const { root, source, writer, openCached } = await setup(t, { "docs/version.txt": "version one" });
  const client = await openCached("docs/version.txt");
  await fsp.writeFile(path.join(source, "docs", "version.txt"), "version two");
  await writer.syncOnce();
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  await assert.rejects(client.materializeRemote("docs/version.txt"), { code: "root_session_native_unavailable" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "version.txt"), "utf8"), "version one");
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);

  await fsp.writeFile(path.join(root, "docs", "version.txt"), "offline local changes");
  await fsp.writeFile(path.join(source, "docs", "version.txt"), "version three");
  await writer.syncOnce();
  await assert.rejects(client.materializeRemote("docs/version.txt"), { code: "local_changes_pending" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "version.txt"), "utf8"), "offline local changes");
});

test("issue 66: native-required fetch denial preserves a concurrent local edit", async (t) => {
  const { root, source, writer, openCached, adapter } = await setup(t, { "docs/race.txt": "clean cached" });
  const client = await openCached("docs/race.txt");
  await fsp.writeFile(path.join(source, "docs", "race.txt"), "new remote version");
  await writer.syncOnce();
  const oldList = adapter.list;
  adapter.list = async (objectId) => {
    const response = await oldList(objectId);
    await fsp.writeFile(path.join(root, "docs", "race.txt"), "edited during network request");
    return response;
  };
  await assert.rejects(client.materializeRemote("docs/race.txt"),
    { code: "local_changes_pending" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "race.txt"), "utf8"), "edited during network request");
});

nativeTest("issue 66 #263 P2: UPDATE same-path stage-time local edit is not overwritten", async (t) => {
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

nativeTest("issue 66 #263 P2: UPDATE rejects same-inode writes between staged stat observations", async (t) => {
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

nativeTest("issue 66 #263 P2: UPDATE refuses a local file recreated after verified staging", async (t) => {
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

nativeTest("issue 66 #263 P2: UPDATE refuses deletion after clean preflight before target stage", async (t) => {
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
  const { root, openCached, store, key } = await setup(t, { "docs/original.txt": "original verified bytes" });
  const client = await openCached("docs/original.txt");
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

nativeTest("issue 66 P2 signed MOVE: fileId rotation cannot erase an unsynced local deletion", async (t) => {
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
nativeTest("issue 66 P2 signed MOVE: " + (explicitlyEvicted ? "explicit eviction can move" : "missing tracked source preserves local deletion"), async (t) => {
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

test("issue 66: even a clean cached source cannot be renamed by legacy FOD MOVE without native custody", async (t) => {
  const { root, openCached, store, key } = await setup(t, { "docs/original.txt": "signed move bytes" });
  const client = await openCached("docs/original.txt");
  const before = store.list("alice")[0];
  const move = protocol.createOperation({
    operation: "move", objectId: before.objectId, fileId: before.fileId,
    versionId: "on-demand-good-move", operationId: "on-demand-good-move-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: before.revision, revision: { counter: before.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/renamed.txt", sourcePath: "docs/original.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("signed move bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", move)).kind, "stored");
  const originalBytes = await fsp.readFile(path.join(root, "docs", "original.txt"));
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const remoteBefore = JSON.stringify(store.list("alice"));
  const pendingBefore = (await client.journal.recover()).map((item) => item.operationId);
  await assert.rejects(client.apply(move), { code: "root_session_native_unavailable" });
  await assert.rejects(client.materializeRemote("docs/renamed.txt"), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "original.txt")), originalBytes);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(await exists(path.join(root, "docs", "renamed.txt")), false);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
  assert.deepEqual((await client.journal.recover()).map((item) => item.operationId), pendingBefore);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
});

nativeTest("issue 66: a clean cached source can be hydrated through a verified remote MOVE", async (t) => {
  const { root, open, store, key, state } = await setup(t, { "docs/original.txt": "signed move bytes" });
  const client = await open();
  await client.materializeRemote("docs/original.txt");
  const before = store.list("alice")[0];
  const move = protocol.createOperation({
    operation: "move", objectId: before.objectId, fileId: before.fileId,
    versionId: "on-demand-good-move", operationId: "on-demand-good-move-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: before.revision,
    revision: { counter: before.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/renamed.txt", sourcePath: "docs/original.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("signed move bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", move)).kind, "stored");
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


nativeTest("issue 66 P2: crash after signed FOD MOVE publication remains guarded across restart", async (t) => {
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

nativeTest("issue 66 P2: verified FOD MOVE cleanup failure cannot claim hydration success", async (t) => {
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

nativeTest("issue 66 P2: interrupted FOD MOVE plaintext write stays outside sync inventory", async (t) => {
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

nativeTest("issue 66 #263 P2: MOVE returns to a clean cached destination without treating it as untracked", async (t) => {
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

nativeTest("issue 66 #263 P2: authenticated signed MOVE publishes B after remote UPDATE and preserves clean A", async (t) => {
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

nativeTest("issue 66 #263 P2: MOVE staging cannot overwrite a racing local destination", async (t) => {
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

nativeTest("issue 66 #263 P2: MOVE publication refuses a destination created after staging", async (t) => {
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

nativeTest("issue 66 #263 P2: evicted MOVE refuses a destination created after preflight", async (t) => {
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

nativeTest("issue 66 #263 P2: restoration cannot clobber a file recreated after its existence check", async (t) => {
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
nativeTest(`issue 66 #263 P2: signed old inventory cannot roll back newer object with ${changedFileId ? "changed" : "stable"} fileId`, async (t) => {
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

nativeTest("issue 66 #263 P2: UPDATE after remote MOVE retires the old clean cached path", async (t) => {
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
nativeTest(`issue 66 #263 P2: relocated UPDATE preserves ${localChange} source`, async (t) => {
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

nativeTest("issue 66 #263 P2: verified remote tombstone invalidates a clean hydrated cache", async (t) => {
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
nativeTest(`issue 66 #263 P2: ${localChange} cache refuses remote tombstone even on explicit refresh`, async (t) => {
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

nativeTest("issue 66 #263 P2: forged tombstone inventory cannot evict an authentic cached object", async (t) => {
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
nativeTest(`issue 66 #263 reviewer P2 A: UPDATE relocation source becomes ${mutation} during staging`, async (t) => {
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

nativeTest("issue 66 #263 reviewer P2 B: authenticated rotated-fileId tombstone retires cache by object identity", async (t) => {
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

nativeTest("issue 66 #263 reviewer P2 C: tombstone stage-time edit restores dirty cache and keeps snapshot active", async (t) => {
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

nativeTest("#263 P2: authenticated tombstone and new live identity at one path allow clean rehydration", async (t) => {
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

nativeTest("#263 P2: one dirty tombstone cache does not suppress reconciliation of another clean cache", async (t) => {
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

nativeTest("#263 P2: moved then deleted out-of-scope object only retires its selected cached path", async (t) => {
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

nativeTest("#263 P2: pending operation on relocated source discovered after inventory fetch blocks UPDATE", async (t) => {
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

nativeTest("#263 P2: remote MOVE cannot relocate cached source with a newly pending local operation", async (t) => {
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

test("issue 66: verified signed MOVE is rejected before unavailable native first hydration", async (t) => {
  const { root, adapter, store, key, state } = await setup(t, { "docs/original.txt": "verified first hydration" });
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trusted = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] };
  let verified = 0;
  const client = await new SyncEngine({ rootDir: root, adapter, deviceId: "device-b",
    keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: async (op) => {
      verified++;
      return verifyAuthorizationProof(op.authorization, op, trusted);
    },
  }).open();
  const original = store.list("alice")[0];
  const move = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: "first-hydration-move", operationId: "first-hydration-move-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/original.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("verified first hydration"), key), fileKey: key,
  });
  move.authorization = await createAuthorizationProof(move, {
    username: "alice", privateKey: pair.privateKey, publicKey, expiresAt: Date.now() + 60_000,
  });
  // Store the ciphertext in the fixture's non-protected object store; supply
  // the signed envelope through the inbound adapter so strict verification
  // is exercised without forging a protected atomic device-registry write.
  const unsigned = { ...move };
  delete unsigned.authorization;
  assert.equal((await store.put("alice", unsigned)).kind, "stored");
  const listFromStore = adapter.list;
  adapter.list = async (objectId) => (await listFromStore(objectId))
    .map((record) => record.operationId === move.operationId ? move : record);
  assert.equal(await exists(path.join(root, "docs", "original.txt")), false);
  assert.equal(await exists(path.join(root, "docs", "new.txt")), false);
  const remoteBefore = JSON.stringify(store.list("alice"));
  await assert.rejects(client.materializeRemote("docs/new.txt"),
    { code: "root_session_native_unavailable" });
  assert.ok(verified > 0, "real Ed25519 pinned-key verifier must run");
  assert.equal(client.journal.hasSeen(move.operationId), false);
  assert.deepEqual(await client.journal.recover(), []);
  assert.equal(await exists(path.join(root, "docs", "new.txt")), false);
  assert.equal(await exists(path.join(root, "docs", "original.txt")), false);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.pushes, 0);
  const reopened = await new SyncEngine({ rootDir: root, adapter, deviceId: "device-b",
    keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: async (op) => verifyAuthorizationProof(op.authorization, op, trusted),
  }).open();
  assert.equal(reopened.snapshot.files["docs/new.txt"], undefined);
  assert.equal(reopened.journal.hasSeen(move.operationId), false);
});

// These are outstanding product acceptance cases. Keep them visibly pending:
// denying legacy pathname publication is not positive native hydration proof.
test.todo("issue 66: native FOD hydrates one selected signed object on open without downloading siblings");
test.todo("issue 66: native FOD hydrates a later metadata page without fetching siblings");
test.todo("issue 66: native FOD verifies signed MOVE and publishes first hydration with cold-reopen persistence");
test.todo("issue 66: native FOD detects a late dirty-cache write at the held-handle publication boundary");
