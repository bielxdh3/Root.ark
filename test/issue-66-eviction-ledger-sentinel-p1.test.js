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

test("issue 66: orphan archive after durable compaction refuses unauthenticated cold open", {
  skip: process.platform !== "linux" && "Linux rootfd archive crash window",
}, async (t) => {
  const f = await fixture(t, "post-archive-rename-crash");
  const sync = await f.create(f.root, ["private"]);
  const originalRename = fsp.rename;
  let archived = null;
  fsp.rename = async (source, destination, ...args) => {
    if (!archived && path.basename(String(source)) === ".rootark-sync-evictions"
      && path.basename(String(destination)).startsWith(".rootark-sync-evictions-archive-")) {
      const actualParent = await fsp.realpath(path.dirname(String(source)));
      if (path.resolve(actualParent) === path.resolve(await fsp.realpath(f.root))) {
        await originalRename(source, destination, ...args);
        archived = path.join(f.root, path.basename(String(destination)));
        throw Object.assign(new Error("injected hard-crash boundary after archived rename"), { code: "EIO" });
      }
    }
    return originalRename(source, destination, ...args);
  };
  try { await assert.rejects(sync.syncOnce(), { code: "EIO" }); }
  finally { fsp.rename = originalRename; }
  assert.ok(archived, "must exercise the exact post-rename / pre-fsync archive boundary");
  assert.ok((await fsp.readdir(archived)).some((name) => name.endsWith(".prepare.json")));
  await assert.rejects(fsp.lstat(f.ledger), { code: "ENOENT" });
  const checkpoint = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(checkpoint.evictionLedgerRequired, false,
    "the full snapshot must already be durable when archive publication fails");
  const beforeWrites = f.writes;
  await assert.rejects(f.create(f.root, ["private"]), { code: "invalid_snapshot" });
  assertRemoteIntact(f, beforeWrites);
  assert.ok((await fsp.readdir(archived)).some((name) => name.endsWith(".prepare.json")),
    "fail-closed cold open must not erase an indeterminate archive");
});

test("issue 66: Windows NTFS cold replay refuses a real orphaned ledger archive", {
  skip: process.platform !== "win32" && "Windows NTFS legacy archive cold-open regression",
}, async (t) => {
  const f = await fixture(t, "windows-post-archive-rename");
  const sync = await f.create(f.root, ["private"]);
  const originalRename = fsp.rename;
  let archived = null;
  fsp.rename = async (source, destination, ...args) => {
    if (!archived && path.basename(String(source)) === ".rootark-sync-evictions"
      && path.basename(String(destination)).startsWith(".rootark-sync-evictions-archive-")
      && path.resolve(path.dirname(String(source))) === path.resolve(f.root)) {
      await originalRename(source, destination, ...args);
      archived = path.join(f.root, path.basename(String(destination)));
      throw Object.assign(new Error("simulated post-rename NTFS failure"), { code: "EIO" });
    }
    return originalRename(source, destination, ...args);
  };
  try { await assert.rejects(sync.syncOnce(), { code: "EIO" }); }
  finally { fsp.rename = originalRename; }
  assert.ok(archived, "must actually rename the ledger before failure");
  const entries = (await fsp.readdir(archived)).sort();
  assert.ok(entries.some((name) => name.endsWith(".prepare.json")));
  const saved = new Map(await Promise.all(entries.map(async (name) =>
    [name, await fsp.readFile(path.join(archived, name))])));
  await assert.rejects(fsp.lstat(f.ledger), { code: "ENOENT" });
  const checkpoint = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(checkpoint.evictionLedgerRequired, false);
  assert.equal(checkpoint.remoteOnly[f.signed.objectId]?.reason, "evicted");
  const beforeWrites = f.writes;
  await assert.rejects(f.create(f.root, []), (error) =>
    error?.code === "invalid_snapshot"
      && /Orphaned eviction archive needs independent recovery/.test(error.message));
  assertRemoteIntact(f, beforeWrites);
  assert.deepEqual((await fsp.readdir(archived)).sort(), entries);
  for (const [name, bytes] of saved) {
    assert.deepEqual(await fsp.readFile(path.join(archived, name)), bytes,
      `cold rejection must preserve original archived NTFS record ${name}`);
  }
});

test("issue 66: Windows retirement must never delete a substituted foreign archive", {
  skip: process.platform !== "win32" && "requires real NTFS directory swap",
}, async (t) => {
  const f = await fixture(t, "win-foreign-archive-retirement");
  const sync = await f.create(f.root, ["private"]);
  const foreign = path.join(path.dirname(f.root), "attacker-ledger");
  const parked = path.join(f.root, ".rootark-sync-evictions-parked");
  await fsp.mkdir(foreign);
  const originalRename = fsp.rename;
  const originalUnlink = fsp.unlink;
  let injected = false;
  let archive = null;
  let attemptedForeignUnlink = false;
  let foreignBefore;
  let foreignBytes;
  fsp.rename = async (source, dest, ...args) => {
    if (!injected && path.basename(String(source)) === ".rootark-sync-evictions"
      && path.basename(String(dest)).startsWith(".rootark-sync-evictions-archive-")
      && path.resolve(path.dirname(String(source))) === path.resolve(f.root)) {
      injected = true;
      const names = await fsp.readdir(f.ledger);
      assert.ok(names.some((name) => name.endsWith(".prepare.json")));
      assert.ok(names.some((name) => name.endsWith(".commit.json")));
      for (const name of names) {
        await fsp.writeFile(path.join(foreign, name), `FOREIGN_${name}`, { flag: "wx" });
      }
      await fsp.writeFile(path.join(foreign, "FOREIGN_SENTINEL"), "attacker bytes", { flag: "wx" });
      foreignBefore = (await fsp.readdir(foreign)).sort();
      foreignBytes = new Map(await Promise.all(foreignBefore.map(async (name) =>
        [name, await fsp.readFile(path.join(foreign, name))])));
      await originalRename(f.ledger, parked);
      await originalRename(foreign, f.ledger);
      archive = String(dest);
    }
    return originalRename(source, dest, ...args);
  };
  fsp.unlink = async (requested, ...args) => {
    // Prevent even the original vulnerable code from actually deleting the
    // disposable foreign records. This is an observation of the real target.
    if (injected && archive
      && path.resolve(path.dirname(String(requested))) === path.resolve(archive)) {
      attemptedForeignUnlink = true;
      throw Object.assign(new Error("foreign deletion intercepted"), { code: "EACCES" });
    }
    return originalUnlink(requested, ...args);
  };
  const beforeWrites = f.writes;
  let failure;
  try { await sync.syncOnce(); } catch (error) { failure = error; }
  finally {
    fsp.rename = originalRename;
    fsp.unlink = originalUnlink;
    if (injected && archive) {
      await originalRename(archive, foreign);
      // The vulnerable path creates a fresh empty active ledger before it
      // attempts the unsafe archive unlink. Restore the original only after
      // removing that *test-owned empty* directory, never any contents.
      try {
        const visible = await fsp.lstat(f.ledger);
        if (!visible.isDirectory() || (await fsp.readdir(f.ledger)).length) {
          throw new Error("refusing to remove nonempty test ledger during recovery");
        }
        await fsp.rmdir(f.ledger);
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      await originalRename(parked, f.ledger);
    }
  }
  assert.equal(injected, true, "the real directory retirement boundary must be exercised");
  assert.equal(attemptedForeignUnlink, false, "no DELETE syscall may target a swapped archive");
  assert.equal(failure?.code, "invalid_snapshot");
  assert.match(failure.message, /Eviction ledger archive identity is indeterminate/);
  assert.deepEqual((await fsp.readdir(foreign)).sort(), foreignBefore);
  for (const [name, bytes] of foreignBytes) {
    assert.deepEqual(await fsp.readFile(path.join(foreign, name)), bytes,
      `no foreign archive bytes may be deleted or changed: ${name}`);
  }
  assertRemoteIntact(f, beforeWrites);
});

test("issue 66: Windows retirement rechecks archived identity immediately before first unlink", {
  skip: process.platform !== "win32" && "requires Windows NTFS archive rename",
}, async (t) => {
  const f = await fixture(t, "win-post-rename-archive-swap");
  const sync = await f.create(f.root, ["private"]);
  const foreign = path.join(path.dirname(f.root), "attacker-archive");
  const parked = path.join(f.root, ".rootark-sync-evictions-parked");
  await fsp.mkdir(foreign);
  const originalRename = fsp.rename;
  const originalMkdir = fsp.mkdir;
  const originalUnlink = fsp.unlink;
  let archive = null;
  let substituted = false;
  let attemptedForeignUnlink = false;
  let foreignBefore;
  let foreignBytes;
  fsp.rename = async (source, dest, ...args) => {
    if (!archive && path.basename(String(source)) === ".rootark-sync-evictions"
      && path.basename(String(dest)).startsWith(".rootark-sync-evictions-archive-")
      && path.resolve(path.dirname(String(source))) === path.resolve(f.root)) {
      archive = String(dest);
    }
    return originalRename(source, dest, ...args);
  };
  fsp.mkdir = async (requested, ...args) => {
    if (archive && !substituted && path.resolve(String(requested)) === path.resolve(f.ledger)) {
      substituted = true;
      const names = await fsp.readdir(archive);
      assert.ok(names.some((name) => name.endsWith(".prepare.json")));
      for (const name of names) {
        await fsp.writeFile(path.join(foreign, name), `FOREIGN_${name}`, { flag: "wx" });
      }
      foreignBefore = (await fsp.readdir(foreign)).sort();
      foreignBytes = new Map(await Promise.all(foreignBefore.map(async (name) =>
        [name, await fsp.readFile(path.join(foreign, name))])));
      await originalRename(archive, parked);
      await originalRename(foreign, archive);
    }
    return originalMkdir(requested, ...args);
  };
  fsp.unlink = async (requested, ...args) => {
    if (substituted && archive
      && path.resolve(path.dirname(String(requested))) === path.resolve(archive)) {
      attemptedForeignUnlink = true;
      throw Object.assign(new Error("foreign archive delete intercepted"), { code: "EACCES" });
    }
    return originalUnlink(requested, ...args);
  };
  const beforeWrites = f.writes;
  let failure;
  try { await sync.syncOnce(); } catch (error) { failure = error; }
  finally {
    fsp.rename = originalRename;
    fsp.mkdir = originalMkdir;
    fsp.unlink = originalUnlink;
    if (substituted) {
      await originalRename(archive, foreign);
      // Only ever remove a verified empty, disposable test ledger.
      const visible = await fsp.lstat(f.ledger);
      if (!visible.isDirectory() || (await fsp.readdir(f.ledger)).length) {
        throw new Error("refusing to remove nonempty test ledger");
      }
      await fsp.rmdir(f.ledger);
      await originalRename(parked, f.ledger);
    }
  }
  assert.equal(substituted, true, "must swap after genuine rename and before cleanup unlink");
  assert.equal(attemptedForeignUnlink, false, "the original archive inode must be reverified");
  assert.equal(failure?.code, "invalid_snapshot");
  assert.match(failure.message, /Eviction ledger archive identity is indeterminate/);
  assert.deepEqual((await fsp.readdir(foreign)).sort(), foreignBefore);
  for (const [name, bytes] of foreignBytes) {
    assert.deepEqual(await fsp.readFile(path.join(foreign, name)), bytes);
  }
  assertRemoteIntact(f, beforeWrites);
});

for (const leafKind of ["commit", "prepare", "head"]) {
test(`issue 66: Windows retirement refuses substituted ${leafKind} leaf inside the original archive`, {
  skip: process.platform !== "win32" && "requires NTFS record substitution in the retained archive",
}, async (t) => {
  const f = await fixture(t, `win-archive-leaf-swap-${leafKind}`);
  const sync = await f.create(f.root, ["private"]);
  const originalRename = fsp.rename;
  const originalMkdir = fsp.mkdir;
  const originalUnlink = fsp.unlink;
  const parked = path.join(f.root, `.original-${leafKind}-parked`);
  const foreignSaved = path.join(path.dirname(f.root), "foreign-record-preserved");
  const foreignBytes = Buffer.from("FOREIGN_RECORD_BYTES_NOT_AUTHORIZED_FOR_DELETE");
  let archive = null;
  let record = null;
  let substituted = false;
  let attemptedForeignUnlink = false;
  fsp.rename = async (source, dest, ...args) => {
    if (!archive && path.basename(String(source)) === ".rootark-sync-evictions"
      && path.basename(String(dest)).startsWith(".rootark-sync-evictions-archive-")
      && path.resolve(path.dirname(String(source))) === path.resolve(f.root)) {
      archive = String(dest);
    }
    return originalRename(source, dest, ...args);
  };
  fsp.mkdir = async (requested, ...args) => {
    if (archive && !substituted && path.resolve(String(requested)) === path.resolve(f.ledger)) {
      const names = await fsp.readdir(archive);
      record = leafKind === "head" ? "head.json"
        : names.find((name) => name.endsWith(`.${leafKind}.json`));
      assert.ok(record && names.includes(record),
        `real durable ${leafKind} must exist before retirement`);
      await originalRename(path.join(archive, record), parked);
      await fsp.writeFile(path.join(archive, record), foreignBytes, { flag: "wx" });
      substituted = true;
    }
    return originalMkdir(requested, ...args);
  };
  fsp.unlink = async (requested, ...args) => {
    if (substituted && archive && record
      && path.resolve(String(requested)) === path.resolve(path.join(archive, record))) {
      attemptedForeignUnlink = true;
      // Observe the true syscall target, and never actually delete foreign
      // bytes even when running this test against its vulnerable parent.
      throw Object.assign(new Error("foreign record unlink intercepted"), { code: "EACCES" });
    }
    return originalUnlink(requested, ...args);
  };
  const beforeWrites = f.writes;
  let failure;
  try { await sync.syncOnce(); } catch (error) { failure = error; }
  finally {
    fsp.rename = originalRename;
    fsp.mkdir = originalMkdir;
    fsp.unlink = originalUnlink;
    if (substituted) {
      await originalRename(path.join(archive, record), foreignSaved);
      await originalRename(parked, path.join(archive, record));
      const active = await fsp.lstat(f.ledger);
      if (!active.isDirectory() || (await fsp.readdir(f.ledger)).length !== 0) {
        throw new Error("Refusing to modify nonempty disposable active ledger");
      }
      await fsp.rmdir(f.ledger);
      await originalRename(archive, f.ledger);
    }
  }
  assert.equal(substituted, true, `must substitute a real ${leafKind} after archive rename`);
  assert.equal(attemptedForeignUnlink, false, "no unlink may target an unverified record inode");
  assert.equal(failure?.code, "invalid_snapshot");
  assert.match(failure.message, /Eviction ledger record identity changed before removal/);
  assert.deepEqual(await fsp.readFile(foreignSaved), foreignBytes,
    "the substituted foreign record bytes must remain exactly intact");
  assertRemoteIntact(f, beforeWrites);
});
}

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

for (const leafKind of ["commit", "prepare", "head"]) {
test(`issue 66: Linux retained-ledger cleanup must refuse a substituted ${leafKind} inode`, {
  skip: process.platform !== "linux" && "requires Linux held ledger dirfd and physical ext4 leaf swap",
}, async (t) => {
  const f = await fixture(t, `linux-foreign-archive-${leafKind}`);
  const sync = await f.create(f.root, ["private"]);
  const originalMkdir = fsp.mkdir;
  const originalUnlink = fsp.unlink;
  const originalRename = fsp.rename;
  const parked = path.join(f.root, `.original-${leafKind}-parked`);
  const foreignSaved = path.join(path.dirname(f.root), `foreign-${leafKind}-preserved`);
  const foreignBytes = Buffer.from(`FOREIGN_LINUX_${leafKind}_MUST_NOT_BE_REMOVED`);
  let archive = null;
  let record = null;
  let substituted = false;
  let attemptedForeignUnlink = false;
  fsp.mkdir = async (requested, ...args) => {
    if (!substituted && path.basename(String(requested)) === ".rootark-sync-evictions") {
      const archives = (await fsp.readdir(f.root)).filter((name) =>
        name.startsWith(".rootark-sync-evictions-archive-"));
      if (archives.length === 1) {
        archive = path.join(f.root, archives[0]);
        const names = await fsp.readdir(archive);
        record = leafKind === "head" ? "head.json"
          : names.find((name) => name.endsWith(`.${leafKind}.json`));
        assert.ok(record && names.includes(record),
          `the original durable ${leafKind} must exist`);
        await originalRename(path.join(archive, record), parked);
        await fsp.writeFile(path.join(archive, record), foreignBytes, { flag: "wx" });
        substituted = true;
      }
    }
    return originalMkdir(requested, ...args);
  };
  fsp.unlink = async (requested, ...args) => {
    if (substituted && path.basename(String(requested)) === record) {
      const physicalParent = await fsp.realpath(path.dirname(String(requested)));
      if (path.resolve(physicalParent) === path.resolve(archive)) {
        attemptedForeignUnlink = true;
        // Intercept the real /proc/self/fd/N/<leaf> request before any foreign
        // inode is destroyed by the intentionally vulnerable RED baseline.
        throw Object.assign(new Error("foreign held-dirfd unlink intercepted"), { code: "EACCES" });
      }
    }
    return originalUnlink(requested, ...args);
  };
  const beforeWrites = f.writes;
  let failure;
  try { await sync.syncOnce(); } catch (error) { failure = error; }
  finally {
    fsp.mkdir = originalMkdir;
    fsp.unlink = originalUnlink;
    if (substituted) {
      await originalRename(path.join(archive, record), foreignSaved);
      await originalRename(parked, path.join(archive, record));
      const active = await fsp.lstat(f.ledger);
      if (!active.isDirectory() || (await fsp.readdir(f.ledger)).length) {
        throw new Error("Refusing to clean nonempty disposable active ledger");
      }
      await fsp.rmdir(f.ledger);
      await originalRename(archive, f.ledger);
    }
  }
  assert.equal(substituted, true, "must physically substitute a record in the held original ledger");
  assert.equal(attemptedForeignUnlink, false, "no held-dirfd unlink may target a substituted inode");
  assert.equal(failure?.code, "invalid_snapshot");
  assert.match(failure.message, /Eviction ledger record identity changed before removal/);
  assert.deepEqual(await fsp.readFile(foreignSaved), foreignBytes);
  assertRemoteIntact(f, beforeWrites);
});
}
