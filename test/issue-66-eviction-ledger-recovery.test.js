"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { fork } = require("node:child_process");
const test = require("node:test");

const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");
const protocol = require("../sync-client/rootark-sync-protocol");
const { validatePortableRelativePath } = require("../sync-client/rootark-sync-paths");

test("issue 66: durable eviction ledger is an internal namespace for both outbound and signed inbound paths", () => {
  for (const pathValue of [".rootark-sync-evictions/secret.prepare.json",
    ".ROOTARK-SYNC-EVICTIONS/secret.commit.json"]) {
    assert.throws(() => validatePortableRelativePath(pathValue), { code: "unsafe_path" });
    assert.throws(() => protocol.safeRelativePath(pathValue, "path"));
  }
});

async function fixture(t, name) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), `rootark-issue66-eviction-crash-${name}-`));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const storePath = path.join(dir, "objects.json");
  const store = await new SyncObjectStore(storePath).open();
  let writes = 0;
  const adapter = {
    async push(op) { writes += 1; return { status: 201, record: (await store.put("alice", op)).record }; },
    async list(objectId = "") { return store.list("alice", objectId || null); },
  };
  const create = async (root, options = {}) => new SyncEngine({
    rootDir: root, adapter, deviceId: options.deviceId || "device-b",
    keyEpoch: "epoch-1", compartmentId: "private",
    excludedPaths: options.excludedPaths || [], fileKeyResolver: () => key,
  }).open();
  const root = path.join(dir, "device");
  const source = path.join(dir, "source");
  const local = path.join(root, "PRIVATE", "secret.txt");
  await fsp.mkdir(path.join(source, "PRIVATE"), { recursive: true });
  await fsp.writeFile(path.join(source, "PRIVATE", "secret.txt"), "verified original owner bytes");
  await (await create(source, { deviceId: "device-a" })).syncOnce();
  const legacy = await create(root);
  await legacy.syncOnce();
  const signed = store.list("alice")[0];
  legacy.snapshot.excludedPaths = ["private"];
  legacy.snapshot.excludedPathsCasefoldVersion = 1;
  await legacy.persistSnapshot();
  return { root, local, dir, key, storePath, store, signed, adapter, create,
    get writes() { return writes; } };
}

test("issue 66: hard process crash after fsynced PREPARE and stage replays remote-only before reconcile", { timeout: 30000 }, async (t) => {
  const f = await fixture(t, "real-stage");
  const beforeWrites = f.writes;
  const child = fork(path.join(__dirname, "support", "issue-66-eviction-crash-child.js"), [], {
    stdio: ["ignore", "ignore", "ignore", "ipc"], execPath: process.execPath,
  });
  t.after(() => { if (!child.killed) child.kill(); });
  const exit = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { child.kill(); reject(new Error("crash fixture child did not exit")); }, 25000);
    child.once("exit", (code) => { clearTimeout(timeout); resolve(code); });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
  });
  child.send({ fixture: "issue66-eviction-crash-v1", root: f.root,
    storePath: f.storePath, fixtureKey: f.key.toString("base64") });
  assert.equal(await exit, 79, "child must terminate after real local stage, not simulate an exception");
  await assert.rejects(fsp.lstat(f.local), { code: "ENOENT" });
  const ledger = path.join(f.root, ".rootark-sync-evictions");
  const records = await fsp.readdir(ledger);
  assert.equal(records.filter((p) => p.endsWith(".prepare.json")).length, 1);
  assert.equal(records.filter((p) => p.endsWith(".commit.json")).length, 0);
  const old = JSON.parse(await fsp.readFile(path.join(f.root, ".rootark-sync-index.json"), "utf8"));
  assert.ok(old.files["PRIVATE/secret.txt"], "the last checkpoint predates the hard crash");
  assert.equal(old.version, 2, "the crash must occur after the old-client downgrade fence is durable");

  // A force-killed process intentionally leaves its exclusive mkdir lock.
  // This removal is confined to the disposable fixture root; production
  // stale locks require explicit authenticated operator recovery.
  await fsp.rmdir(path.join(f.root, ".rootark-sync.lock"));
  const restored = await f.create(f.root, { excludedPaths: ["private"] });
  assert.equal(restored.snapshot.files["PRIVATE/secret.txt"], undefined);
  assert.equal(restored.snapshot.remoteOnly[f.signed.objectId]?.reason, "evicted");
  assert.equal((await fsp.readdir(ledger)).length, 0);
  await restored.syncOnce();
  assert.equal(f.writes, beforeWrites, "replay and reconcile must never push remote DELETE");
  assert.equal(f.store.list("alice")[0].operationId, f.signed.operationId);
  assert.equal(f.store.list("alice")[0].tombstone, false);
});

test("issue 66: COMMIT before failed whole-snapshot fsync is replayed without repeating unlink", async (t) => {
  const f = await fixture(t, "commit-replay");
  const sync = await f.create(f.root, { excludedPaths: ["private"] });
  const original = sync.persistSnapshot.bind(sync);
  sync.persistSnapshot = async () => {
    const ledger = path.join(f.root, ".rootark-sync-evictions");
    const names = await fsp.readdir(ledger).catch((error) => error.code === "ENOENT" ? [] : Promise.reject(error));
    if (names.some((name) => name.endsWith(".commit.json"))) {
      throw Object.assign(new Error("injected final snapshot EIO"), { code: "EIO" });
    }
    return original(); // The old-client version fence must commit first.
  };
  await assert.rejects(sync.syncOnce(), { code: "EIO" });
  sync.persistSnapshot = original;
  const entries = await fsp.readdir(path.join(f.root, ".rootark-sync-evictions"));
  assert.equal(entries.filter((x) => x.endsWith(".commit.json")).length, 1);
  await assert.rejects(fsp.lstat(f.local), { code: "ENOENT" });
  const before = f.writes;
  const restarted = await f.create(f.root, { excludedPaths: ["private"] });
  assert.equal(restarted.snapshot.files["PRIVATE/secret.txt"], undefined);
  assert.equal(restarted.snapshot.remoteOnly[f.signed.objectId]?.reason, "evicted");
  assert.equal((await fsp.readdir(path.join(f.root, ".rootark-sync-evictions"))).length, 0);
  await restarted.syncOnce();
  assert.equal(f.writes, before);
});

test("issue 66: PREPARE with failed stage/EIO replays a PRESENT local file without unsafe unlink", async (t) => {
  const f = await fixture(t, "prepare-present");
  const before = f.writes;
  const sync = await f.create(f.root, { excludedPaths: ["private"] });
  sync.stageExisting = async () => { throw Object.assign(new Error("injected rename EIO"), { code: "EIO" }); };
  const original = sync.persistSnapshot.bind(sync);
  sync.persistSnapshot = async () => {
    const ledger = path.join(f.root, ".rootark-sync-evictions");
    const names = await fsp.readdir(ledger).catch((error) => error.code === "ENOENT" ? [] : Promise.reject(error));
    if (names.some((name) => name.endsWith(".prepare.json"))) {
      throw Object.assign(new Error("injected final snapshot EIO"), { code: "EIO" });
    }
    return original();
  };
  await assert.rejects(sync.syncOnce(), { code: "EIO" });
  assert.equal(await fsp.readFile(f.local, "utf8"), "verified original owner bytes");
  const ledger = path.join(f.root, ".rootark-sync-evictions");
  assert.equal((await fsp.readdir(ledger)).filter((x) => x.endsWith(".prepare.json")).length, 1);
  const restarted = await f.create(f.root, { excludedPaths: ["private"] });
  assert.ok(restarted.snapshot.files["PRIVATE/secret.txt"], "PREPARE alone must preserve present local bytes");
  assert.equal(restarted.snapshot.pendingEvictions[f.signed.objectId]?.code, "sync_operation_pending");
  assert.equal(await fsp.readFile(f.local, "utf8"), "verified original owner bytes");
  assert.equal((await fsp.readdir(ledger)).length, 0);
  assert.equal((await restarted.syncOnce()).excluded.evicted, 1,
    "a subsequent full signed verification can safely remove the restored clean file");
  assert.equal(f.writes, before);
  assert.equal(f.store.list("alice")[0].tombstone, false);
});

test("issue 66: EIO during stage is reported and preserves signed bytes and remote history", async (t) => {
  const f = await fixture(t, "stage-rollback");
  const sync = await f.create(f.root, { excludedPaths: ["private"] });
  const before = f.writes;
  sync.stageExisting = async () => { throw Object.assign(new Error("injected EIO"), { code: "EIO" }); };
  const result = await sync.syncOnce();
  assert.deepEqual(result.excluded.failed, [{ path: "PRIVATE/secret.txt", code: "EIO" }]);
  assert.equal(await fsp.readFile(f.local, "utf8"), "verified original owner bytes");
  assert.equal(f.writes, before);
  assert.equal((await fsp.readdir(path.join(f.root, ".rootark-sync-evictions"))).length, 0);
  assert.equal(f.store.list("alice")[0].operationId, f.signed.operationId);
  assert.equal(f.store.list("alice")[0].tombstone, false);
});

test("issue 66: stage succeeded but returned EIO keeps durable eviction evidence", async (t) => {
  const f = await fixture(t, "stage-then-error");
  const sync = await f.create(f.root, { excludedPaths: ["private"] });
  const stage = sync.stageExisting.bind(sync);
  sync.stageExisting = async (target) => {
    await stage(target);
    throw Object.assign(new Error("EIO after staging"), { code: "EIO" });
  };
  const before = f.writes;
  await assert.rejects(sync.syncOnce(), { code: "eviction_restore_failed" });
  await assert.rejects(fsp.lstat(f.local), { code: "ENOENT" });
  assert.equal((await fsp.readdir(path.join(f.root, ".rootark-sync-evictions")))
    .filter((name) => name.endsWith(".prepare.json")).length, 1);
  const recovered = await f.create(f.root, { excludedPaths: ["private"] });
  assert.equal(recovered.snapshot.remoteOnly[f.signed.objectId]?.reason, "evicted");
  await recovered.syncOnce();
  assert.equal(f.writes, before, "no inferred remote DELETE after a failed staged rename");
  assert.equal(f.store.list("alice")[0].tombstone, false);
});

test("issue 66: missing current remote evidence blocks eviction replay before DELETE", async (t) => {
  const f = await fixture(t, "unavailable-replay-source");
  const sync = await f.create(f.root, { excludedPaths: ["private"] });
  const stage = sync.stageExisting.bind(sync);
  sync.stageExisting = async (target) => {
    await stage(target);
    throw Object.assign(new Error("stage returned EIO"), { code: "EIO" });
  };
  await assert.rejects(sync.syncOnce(), { code: "eviction_restore_failed" });
  const before = f.writes;
  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId ? [] : originalList(objectId);
  await assert.rejects(f.create(f.root, { excludedPaths: ["private"] }), { code: "invalid_snapshot" });
  assert.equal(f.writes, before, "an unauthenticated replay must never start an outbound mutation");
  f.adapter.list = originalList;
  const recovered = await f.create(f.root, { excludedPaths: ["private"] });
  assert.equal(recovered.snapshot.remoteOnly[f.signed.objectId]?.reason, "evicted");
});

test("issue 66: missing ledger head or PREPARE sequence fails closed", async (t) => {
  for (const missing of ["head", "prepare"]) {
    const f = await fixture(t, `missing-${missing}`);
    const sync = await f.create(f.root, { excludedPaths: ["private"] });
    const stage = sync.stageExisting.bind(sync);
    sync.stageExisting = async (target) => {
      await stage(target);
      throw Object.assign(new Error("stage returned EIO"), { code: "EIO" });
    };
    await assert.rejects(sync.syncOnce(), { code: "eviction_restore_failed" });
    const directory = path.join(f.root, ".rootark-sync-evictions");
    const names = await fsp.readdir(directory);
    const name = missing === "head" ? "head.json" : names.find((entry) => entry.endsWith(".prepare.json"));
    assert.ok(name, `missing ${missing} test requires real durable evidence`);
    await fsp.unlink(path.join(directory, name));
    const before = f.writes;
    await assert.rejects(f.create(f.root, { excludedPaths: ["private"] }), { code: "invalid_snapshot" });
    assert.equal(f.writes, before);
  }
});

test("issue 66: failed physical restore preserves PREPARE until restart and never removes new dirty bytes", async (t) => {
  const f = await fixture(t, "restore-conflict");
  const sync = await f.create(f.root, { excludedPaths: ["private"] });
  const stage = sync.stageExisting.bind(sync);
  sync.stageExisting = async (target) => {
    const staged = await stage(target);
    await fsp.writeFile(staged, "staged data was changed");
    await fsp.writeFile(target, "new unverified local content");
    return staged;
  };
  const before = f.writes;
  await assert.rejects(sync.syncOnce(), { code: "eviction_restore_failed" });
  assert.equal(await fsp.readFile(f.local, "utf8"), "new unverified local content");
  const ledger = path.join(f.root, ".rootark-sync-evictions");
  assert.equal((await fsp.readdir(ledger)).filter((x) => x.endsWith(".prepare.json")).length, 1,
    "do not compact away the sole durable PREPARE after physical rollback fails");
  const restarted = await f.create(f.root, { excludedPaths: ["private"] });
  assert.ok(restarted.snapshot.files["PRIVATE/secret.txt"]);
  assert.equal(await fsp.readFile(f.local, "utf8"), "new unverified local content");
  assert.equal(restarted.snapshot.pendingEvictions[f.signed.objectId].code, "sync_operation_pending");
  assert.deepEqual((await restarted.syncOnce()).excluded.kept,
    [{ path: "PRIVATE/secret.txt", code: "local_changes_pending" }]);
  assert.equal(f.writes, before);
  assert.equal(f.store.list("alice")[0].operationId, f.signed.operationId);
  assert.equal(f.store.list("alice")[0].tombstone, false);
});

test("issue 66: torn PREPARE and orphan COMMIT fail closed before any reconciliation", async (t) => {
  for (const torn of ["prepare", "commit"]) {
    const f = await fixture(t, `torn-${torn}`);
    const journalDir = path.join(f.root, ".rootark-sync-evictions");
    await fsp.mkdir(journalDir);
    const digest = crypto.createHash("sha256").update("forged-object").digest("hex");
    const filename = path.join(journalDir, `${digest}.${torn}.json`);
    await fsp.writeFile(filename, torn === "prepare" ? "{incomplete" : '{"version":1}');
    const before = f.writes;
    await assert.rejects(f.create(f.root, { excludedPaths: ["private"] }), { code: "invalid_snapshot" });
    assert.equal(await fsp.readFile(f.local, "utf8"), "verified original owner bytes");
    assert.equal(f.writes, before);
    assert.equal(f.store.list("alice")[0].operationId, f.signed.operationId);
  }
});

test("issue 66 POSIX: symlinked journal record fails closed without reading its target", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX symlink guard");
  const f = await fixture(t, "ledger-symlink");
  const ledger = path.join(f.root, ".rootark-sync-evictions");
  await fsp.mkdir(ledger);
  const external = path.join(f.dir, "outside-sentinel");
  await fsp.writeFile(external, "private sentinel must not be followed");
  const digest = crypto.createHash("sha256").update("forged-symlink").digest("hex");
  await fsp.symlink(external, path.join(ledger, `${digest}.prepare.json`));
  const prior = f.writes;
  await assert.rejects(f.create(f.root, { excludedPaths: ["private"] }), { code: "invalid_snapshot" });
  assert.equal(await fsp.readFile(external, "utf8"), "private sentinel must not be followed");
  assert.equal(await fsp.readFile(f.local, "utf8"), "verified original owner bytes");
  assert.equal(f.writes, prior);
});
