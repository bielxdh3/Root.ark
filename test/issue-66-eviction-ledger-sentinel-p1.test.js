"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");

// Exercise the signed protected store and actual cache stage. A missing
// protected local cache must never become an outbound signed tombstone.
async function fixture(t, name) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), `rootark-issue66-required-ledger-${name}-`));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  let writes = 0;
  const outbound = [];
  const adapter = {
    async push(operation) {
      writes += 1;
      outbound.push({ operation: operation.operation, path: operation.metadata?.path, tombstone: operation.tombstone });
      return { status: 201, record: (await store.put("alice", operation)).record };
    },
    async list(objectId = "") { return store.list("alice", objectId || null); },
  };
  const create = async (root, excludedPaths = []) => new SyncEngine({
    rootDir: root, adapter, deviceId: root.endsWith("source") ? "device-a" : "device-b",
    keyEpoch: "epoch-1", compartmentId: "private", excludedPaths,
    fileKeyResolver: () => key,
  }).open();
  const source = path.join(dir, "source");
  const root = path.join(dir, "device");
  const local = path.join(root, "PRIVATE", "secret.txt");
  const ledger = path.join(root, ".rootark-sync-evictions");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  await fsp.mkdir(path.join(source, "PRIVATE"), { recursive: true });
  await fsp.writeFile(path.join(source, "PRIVATE", "secret.txt"), "original authenticated bytes");
  await (await create(source)).syncOnce();
  const device = await create(root);
  await device.syncOnce();
  const signed = store.list("alice")[0];
  device.snapshot.excludedPaths = ["private"];
  device.snapshot.excludedPathsCasefoldVersion = 1;
  await device.persistSnapshot();
  return { create, root, local, ledger, snapshot, store, signed,
    outbound,
    get writes() { return writes; } };
}

async function stageThenFail(f, assertGuard = true) {
  const sync = await f.create(f.root, ["private"]);
  const original = sync.stageExisting.bind(sync);
  sync.stageExisting = async (target) => {
    await original(target);
    throw Object.assign(new Error("injected EIO after physical stage"), { code: "EIO" });
  };
  await assert.rejects(sync.syncOnce(), { code: "eviction_restore_failed" });
  await assert.rejects(fsp.lstat(f.local), { code: "ENOENT" });
  const names = await fsp.readdir(f.ledger);
  assert.equal(names.filter((x) => x.endsWith(".prepare.json")).length, 1);
  const disk = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(disk.version, 2);
  if (assertGuard) {
    assert.equal(disk.evictionLedgerRequired, true,
      "durable snapshot must demand its journal after any physical cache stage");
  }
}

function assertRemoteIntact(f, beforeWrites) {
  assert.ok(f.outbound.slice(beforeWrites).every((op) => op.operation !== "delete" && !op.tombstone),
    `must not submit a signed DELETE: ${JSON.stringify(f.outbound.slice(beforeWrites))}`);
  assert.equal(f.store.list("alice").filter((entry) => entry.tombstone).length, 0,
    "the real protected server must contain zero signed tombstones");
  const remote = f.store.list("alice", f.signed.objectId)[0];
  assert.equal(remote.operationId, f.signed.operationId);
  assert.equal(remote.tombstone, false);
}

test("issue 66 P1: whole active ledger loss and exclusion reset reject before signed DELETE", async (t) => {
  for (const mutation of ["removed", "empty-directory", "renamed-archive"]) {
    const f = await fixture(t, `whole-${mutation}`);
    await stageThenFail(f, false);
    if (mutation === "removed") await fsp.rm(f.ledger, { recursive: true });
    if (mutation === "empty-directory") {
      await fsp.rm(f.ledger, { recursive: true });
      await fsp.mkdir(f.ledger);
    }
    if (mutation === "renamed-archive") {
      await fsp.rename(f.ledger, `${f.ledger}-archive-orphan`);
    }
    const beforeWrites = f.writes;
    let error;
    try {
      const restarted = await f.create(f.root, []);
      await restarted.syncOnce();
    } catch (cause) { error = cause; }
    assertRemoteIntact(f, beforeWrites);
    assert.equal(error?.code, "invalid_snapshot",
      `lost ledger ${mutation} with exclusions=[] must fail closed`);
  }
});

test("issue 66 P1: missing active journal rejects even when exclusions remain", async (t) => {
  const f = await fixture(t, "unchanged-policy");
  await stageThenFail(f);
  await fsp.rm(f.ledger, { recursive: true });
  const beforeWrites = f.writes;
  await assert.rejects(f.create(f.root, ["private"]), { code: "invalid_snapshot" });
  assertRemoteIntact(f, beforeWrites);
});

test("issue 66 P1: active checkpoint rejects lost or inconsistent epoch sentinel", async (t) => {
  for (const mutation of ["required-absent", "required-invalid", "epoch-mismatch"]) {
    const f = await fixture(t, `epoch-${mutation}`);
    await stageThenFail(f);
    const snapshot = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
    if (mutation === "required-absent") delete snapshot.evictionLedgerRequired;
    if (mutation === "required-invalid") snapshot.evictionLedgerRequired = "false";
    if (mutation === "epoch-mismatch") snapshot.evictionLedgerEpoch = crypto.randomUUID();
    await fsp.writeFile(f.snapshot, JSON.stringify(snapshot));
    const beforeWrites = f.writes;
    await assert.rejects(f.create(f.root, []), { code: "invalid_snapshot" });
    assertRemoteIntact(f, beforeWrites);
  }
});

test("issue 66 P1: failed compaction leaves active guard, real PREPARE and original remote version", async (t) => {
  const f = await fixture(t, "checkpoint-EIO");
  const sync = await f.create(f.root, ["private"]);
  const persist = sync.persistSnapshot.bind(sync);
  sync.persistSnapshot = async () => {
    if (sync.snapshot.evictionLedgerRequired === false) {
      throw Object.assign(new Error("injected durable checkpoint EIO"), { code: "EIO" });
    }
    return persist();
  };
  await assert.rejects(sync.syncOnce(), { code: "EIO" });
  await assert.rejects(fsp.lstat(f.local), { code: "ENOENT" });
  const disk = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(disk.evictionLedgerRequired, true);
  assert.equal((await fsp.readdir(f.ledger)).filter((x) => x.endsWith(".commit.json")).length, 1);
  const beforeWrites = f.writes;
  const restored = await f.create(f.root, []);
  assert.equal(restored.snapshot.remoteOnly[f.signed.objectId]?.reason, "evicted");
  await restored.syncOnce();
  assertRemoteIntact(f, beforeWrites);
});

test("issue 66 P1: complete checkpoint retires guard and permits empty ledger restart", async (t) => {
  const f = await fixture(t, "compacted");
  const sync = await f.create(f.root, ["private"]);
  assert.equal((await sync.syncOnce()).excluded.evicted, 1);
  const disk = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(disk.evictionLedgerRequired, false);
  assert.equal(disk.remoteOnly[f.signed.objectId]?.reason, "evicted");
  assert.deepEqual(await fsp.readdir(f.ledger), []);
  const beforeWrites = f.writes;
  await fsp.rmdir(f.ledger);
  const reopened = await f.create(f.root, []);
  await reopened.syncOnce();
  assertRemoteIntact(f, beforeWrites);
});

test("issue 66 P1: legacy v2 checkpoint without an explicit required flag cannot silently authorize DELETE", async (t) => {
  const f = await fixture(t, "legacy-v2-unmarked");
  const sync = await f.create(f.root, ["private"]);
  assert.equal((await sync.syncOnce()).excluded.evicted, 1);
  const disk = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(disk.version, 2);
  assert.equal(disk.evictionLedgerRequired, false);
  delete disk.evictionLedgerRequired; // persisted by the vulnerable previous version
  await fsp.writeFile(f.snapshot, JSON.stringify(disk));
  const beforeWrites = f.writes;
  let error;
  try {
    const restarted = await f.create(f.root, []);
    await restarted.syncOnce();
  } catch (cause) { error = cause; }
  assertRemoteIntact(f, beforeWrites);
  assert.equal(error?.code, "invalid_snapshot");
});

test("issue 66 P1: crash after compacted checkpoint but before ledger retirement replays safely", async (t) => {
  const f = await fixture(t, "durable-before-archive");
  const sync = await f.create(f.root, ["private"]);
  const originalRename = fsp.rename;
  let blockedArchive = false;
  fsp.rename = async (source, destination) => {
    let exactRootParent = false;
    if (path.basename(String(source)) === ".rootark-sync-evictions"
      && path.basename(String(destination)).startsWith(".rootark-sync-evictions-archive-")) {
      try {
        exactRootParent = path.resolve(await fsp.realpath(path.dirname(String(source))))
          === path.resolve(await fsp.realpath(f.root));
      } catch { /* Unresolved parent must not pretend to exercise a physical rename. */ }
    }
    if (exactRootParent) {
      blockedArchive = true;
      throw Object.assign(new Error("simulated post-checkpoint archive EIO"), { code: "EIO" });
    }
    return originalRename(source, destination);
  };
  try {
    await assert.rejects(sync.syncOnce(), { code: "EIO" });
  } finally {
    fsp.rename = originalRename;
  }
  assert.equal(blockedArchive, true, "the injection must run after the full checkpoint");
  const checkpoint = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(checkpoint.evictionLedgerRequired, false,
    "only a complete durable checkpoint may release the active guard");
  assert.equal(checkpoint.remoteOnly[f.signed.objectId]?.reason, "evicted");
  assert.ok((await fsp.readdir(f.ledger)).some((entry) => entry.endsWith(".prepare.json")));
  const beforeWrites = f.writes;
  const recovered = await f.create(f.root, ["private"]);
  assert.equal(recovered.snapshot.remoteOnly[f.signed.objectId]?.reason, "evicted");
  assert.deepEqual(await fsp.readdir(f.ledger), []);
  await recovered.syncOnce();
  assertRemoteIntact(f, beforeWrites);
});

test("issue 66 P1: pre-PREPARE snapshot upgrade EIO does not move bytes or relax old-client fence", async (t) => {
  const f = await fixture(t, "upgrade-EIO");
  const sync = await f.create(f.root, ["private"]);
  const originalPersist = sync.persistSnapshot.bind(sync);
  let refusedUpgrade = false;
  sync.persistSnapshot = async () => {
    if (sync.snapshot.version === 2 && sync.snapshot.evictionLedgerRequired === true) {
      refusedUpgrade = true;
      throw Object.assign(new Error("simulated upgrade snapshot fsync EIO"), { code: "EIO" });
    }
    return originalPersist();
  };
  const result = await sync.syncOnce();
  assert.equal(refusedUpgrade, true, "must reach the v2 upgrade before PREPARE");
  assert.deepEqual(result.excluded.failed, [{ path: "PRIVATE/secret.txt", code: "EIO" }]);
  assert.equal(await fsp.readFile(f.local, "utf8"), "original authenticated bytes");
  const checkpoint = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(checkpoint.version, 1, "failed pre-PREPARE migration cannot write a v2 fence");
  assert.equal(checkpoint.evictionLedgerRequired, undefined);
  // The new pre-PREPARE protocol deliberately leaves a durable zero-sequence
  // genesis after a failed snapshot upgrade. It is safe to reuse on retry.
  await assert.rejects(fsp.lstat(f.ledger), { code: "ENOENT" },
    "v1 must not see a new internal ledger before the downgrade fence is durable");
  const staged = (await fsp.readdir(path.join(f.root, ".rootark-trash")))
    .filter((name) => name === ".rootark-eviction-genesis-head.json");
  assert.deepEqual(staged, [".rootark-eviction-genesis-head.json"]);
  const genesis = JSON.parse(await fsp.readFile(
    path.join(f.root, ".rootark-trash", staged[0]), "utf8"));
  assert.equal(genesis.sequence, 0);
  assert.equal(genesis.digest, "0".repeat(64));
  const beforeWrites = f.writes;
  const restarted = await f.create(f.root, []);
  await restarted.syncOnce();
  assertRemoteIntact(f, beforeWrites);
});
