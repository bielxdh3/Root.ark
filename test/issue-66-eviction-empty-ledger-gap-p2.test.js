"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { validatePortableRelativePath } = require("../sync-client/rootark-sync-paths");
const { SyncObjectStore } = require("../src/routes/sync");

async function fixture(t, name, twoFiles = false) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), `rootark-issue66-gap-${name}-`));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const storePath = path.join(dir, "server.json");
  const store = await new SyncObjectStore(storePath).open();
  const outbound = [];
  const adapter = {
    async push(operation) {
      outbound.push({ operation: operation.operation, tombstone: operation.tombstone,
        path: operation.metadata?.path });
      return { status: 201, record: (await store.put("alice", operation)).record };
    },
    async list(objectId = "") { return store.list("alice", objectId || null); },
  };
  const create = async (root, excludedPaths = [], extra = {}) => new SyncEngine({
    rootDir: root, adapter, deviceId: root.endsWith("source") ? "device-a" : "device-b",
    keyEpoch: "epoch-1", compartmentId: "private", excludedPaths,
    fileKeyResolver: () => key, ...extra,
  }).open();
  const root = path.join(dir, "device");
  const source = path.join(dir, "source");
  const local = path.join(root, "PRIVATE", "secret.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const ledger = path.join(root, ".rootark-sync-evictions");
  await fsp.mkdir(path.join(source, "PRIVATE"), { recursive: true });
  await fsp.writeFile(path.join(source, "PRIVATE", "secret.txt"), "authenticated server file");
  if (twoFiles) {
    await fsp.writeFile(path.join(source, "PRIVATE", "second.txt"), "second authenticated server file");
  }
  await (await create(source)).syncOnce();
  const initial = await create(root);
  await initial.syncOnce();
  const signed = store.list("alice").find((entry) => entry.metadata.path === "PRIVATE/secret.txt");
  assert.ok(signed && !signed.tombstone, "fixture requires protected signed server object");
  initial.snapshot.excludedPaths = ["private"];
  initial.snapshot.excludedPathsCasefoldVersion = 1;
  await initial.persistSnapshot();
  return { dir, root, source, local, snapshot, ledger, storePath, store,
    signed, create, outbound, key };
}

test("issue 66: Linux snapshot post-rename fsync EIO recovers without signed deletion", {
  skip: process.platform !== "linux" && "requires POSIX directory sync after a real rename",
}, async (t) => {
  const f = await fixture(t, "snapshot-post-rename-fsync-fault");
  const sync = await f.create(f.root, ["private"]);
  const before = f.outbound.length;
  const originalRename = fsp.rename;
  const originalOpen = fsp.open;
  let renamed = false;
  let failedDirSync = false;
  let observedError;
  try {
    fsp.rename = async (source, destination, ...args) => {
      let targetIsRequiredV2 = false;
      if (path.resolve(String(destination)) === path.resolve(f.snapshot)
        && String(source).startsWith(f.snapshot + ".tmp-")) {
        const candidate = JSON.parse(await fsp.readFile(String(source), "utf8"));
        targetIsRequiredV2 = candidate.version === 2 && candidate.evictionLedgerRequired === true;
      }
      const result = await originalRename(source, destination, ...args);
      if (targetIsRequiredV2) renamed = true;
      return result;
    };
    fsp.open = async (requested, ...args) => {
      const handle = await originalOpen(requested, ...args);
      if (renamed && !failedDirSync
        && path.resolve(String(requested)) === path.resolve(f.root)
        && args[0] === 0 /* Linux fs.constants.O_RDONLY */) {
        handle.sync = async () => {
          failedDirSync = true;
          throw Object.assign(new Error("injected EIO only AFTER real snapshot rename"), { code: "EIO" });
        };
      }
      return handle;
    };
    try { await sync.syncOnce(); } catch (error) { observedError = error; }
  } finally {
    fsp.rename = originalRename;
    fsp.open = originalOpen;
  }
  assert.equal(renamed, true, "real O_EXCL temporary must have been renamed to snapshot");
  assert.equal(failedDirSync, true, "fault must occur in the post-rename parent fsync");
  assert.equal(observedError?.code, "invalid_snapshot",
    "a physically published snapshot with uncertain durability must abort the full sync pass");
  assert.equal(observedError?.cause?.code, "EIO",
    "the original directory sync fault must remain inspectable as the cause");
  assert.equal(sync.opened, false, "the old in-memory engine must require a verified cold reopen");
  assert.equal(sync.snapshotDiskRevision, null);
  const newDisk = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(newDisk.version, 2);
  assert.equal(newDisk.evictionLedgerRequired, true,
    "the installed v2 snapshot cannot be overwritten by an unreviewed v1 rollback");
  const staged = path.join(f.root, ".rootark-trash", ".rootark-eviction-genesis-head.json");
  assert.ok((await fsp.lstat(staged)).isFile(), "genesis must remain staged on disk");
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  const fresh = await f.create(f.root, []);
  await fresh.syncOnce();
  verifyNoSignedDelete(f, before);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
});

test("issue 66: an indeterminate published v2 snapshot aborts before signed reconciliation", {
  skip: process.platform !== "linux" && "requires POSIX post-rename parent directory fsync",
}, async (t) => {
  const f = await fixture(t, "published-snapshot-reconcile-abort", true);
  const sync = await f.create(f.root, ["private"]);
  const beforeWrites = f.outbound.length;
  const originalRename = fsp.rename;
  const originalOpen = fsp.open;
  let renamedRequiredV2 = false;
  let failedDirSync = false;
  let attemptedReconcile = false;
  let observed;
  // On the vulnerable parent a per-object EIO is merely placed in the
  // exclusion report and the sync moves on to _reconcileLocal(). Intercept
  // that call before any remote operation is built or signed.
  sync._reconcileLocal = async () => {
    attemptedReconcile = true;
    throw Object.assign(new Error("reconcile after metadata EIO intercepted"), {
      code: "UNSAFE_RECONCILE_INTERCEPTED",
    });
  };
  try {
    fsp.rename = async (source, destination, ...args) => {
      let requiredV2 = false;
      if (path.resolve(String(destination)) === path.resolve(f.snapshot)
        && String(source).startsWith(f.snapshot + ".tmp-")) {
        const candidate = JSON.parse(await fsp.readFile(String(source), "utf8"));
        requiredV2 = candidate.version === 2 && candidate.evictionLedgerRequired === true;
      }
      const result = await originalRename(source, destination, ...args);
      if (requiredV2) renamedRequiredV2 = true;
      return result;
    };
    fsp.open = async (requested, ...args) => {
      const handle = await originalOpen(requested, ...args);
      if (renamedRequiredV2 && !failedDirSync
        && path.resolve(String(requested)) === path.resolve(f.root)
        && args[0] === 0 /* O_RDONLY parent directory */) {
        handle.sync = async () => {
          failedDirSync = true;
          throw Object.assign(new Error("real snapshot rename succeeded but parent fsync EIO"), { code: "EIO" });
        };
      }
      return handle;
    };
    try { await sync.syncOnce(); } catch (error) { observed = error; }
  } finally {
    fsp.rename = originalRename;
    fsp.open = originalOpen;
  }
  assert.equal(renamedRequiredV2, true, "real required-v2 snapshot rename must happen");
  assert.equal(failedDirSync, true, "fault must occur after published snapshot rename");
  assert.equal(attemptedReconcile, false,
    "no signed reconciliation may run until the indeterminate snapshot is reopened");
  assert.equal(observed?.code, "invalid_snapshot",
    "durability-indeterminate metadata error must abort the entire pass");
  assert.equal(observed?.cause?.code, "EIO",
    "the original physical post-rename directory sync fault must be retained");
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  assert.equal(await fsp.readFile(path.join(f.root, "PRIVATE", "second.txt"), "utf8"),
    "second authenticated server file");
  verifyNoSignedDelete(f, beforeWrites);
});

test("issue 66: Linux PREPARE HEAD post-rename fsync EIO replays without signed deletion", {
  skip: process.platform !== "linux" && "requires real Linux ledger directory fsync after rename",
}, async (t) => {
  const f = await fixture(t, "head-post-rename-fsync-fault");
  const sync = await f.create(f.root, ["private"]);
  const before = f.outbound.length;
  const originalRename = fsp.rename;
  const originalOpen = fsp.open;
  let renamedHead = false;
  let failedHeadSync = false;
  let report;
  let thrown;
  try {
    fsp.rename = async (source, destination, ...args) => {
      const result = await originalRename(source, destination, ...args);
      if (path.basename(String(destination)) === "head.json"
        && path.basename(String(source)).startsWith("head.json.tmp-")) {
        const actualParent = await fsp.realpath(path.dirname(String(destination)));
        if (path.resolve(actualParent) === path.resolve(f.ledger)) renamedHead = true;
      }
      return result;
    };
    fsp.open = async (requested, ...args) => {
      const handle = await originalOpen(requested, ...args);
      if (renamedHead && !failedHeadSync
        && args[0] === 0 /* O_RDONLY directory flush */) {
        const actualParent = await fsp.realpath(String(requested));
        if (path.resolve(actualParent) === path.resolve(f.ledger)) {
          handle.sync = async () => {
            failedHeadSync = true;
            throw Object.assign(new Error("post-HEAD-rename directory sync EIO"), { code: "EIO" });
          };
        }
      }
      return handle;
    };
    try { report = await sync.syncOnce(); } catch (error) { thrown = error; }
  } finally {
    fsp.rename = originalRename;
    fsp.open = originalOpen;
  }
  assert.equal(renamedHead, true, "HEAD must first be physically replaced by a real rename");
  assert.equal(failedHeadSync, true, "the precise HEAD parent fsync must receive injected EIO");
  assert.ok(thrown || report?.excluded?.failed?.length,
    "an indeterminate HEAD directory flush cannot report successful exclusion");
  const persisted = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(persisted.version, 2);
  assert.equal(persisted.evictionLedgerRequired, true,
    "the durable snapshot guard must not be cleared on uncertain PREPARE HEAD");
  assert.equal((await fsp.readdir(f.ledger)).filter((x) => x.endsWith(".prepare.json")).length, 1);
  const head = JSON.parse(await fsp.readFile(path.join(f.ledger, "head.json"), "utf8"));
  assert.equal(head.sequence, 1, "the renamed HEAD may already be physically visible despite EIO");
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file",
    "physical cache remains because stage never started");
  const fresh = await f.create(f.root, []);
  await fresh.syncOnce();
  verifyNoSignedDelete(f, before);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
});

test("issue 66: Linux completed v2 checkpoint post-rename fsync EIO never signs a deletion", {
  skip: process.platform !== "linux" && "requires POSIX parent directory fsync after v2 checkpoint rename",
}, async (t) => {
  const f = await fixture(t, "v2-compaction-post-rename-fsync");
  const sync = await f.create(f.root, ["private"]);
  const originalRename = fsp.rename;
  const originalOpen = fsp.open;
  const before = f.outbound.length;
  let renamedComplete = false;
  let failedCompleteSync = false;
  let report;
  let thrown;
  try {
    fsp.rename = async (source, destination, ...args) => {
      let completed = false;
      if (path.resolve(String(destination)) === path.resolve(f.snapshot)
        && String(source).startsWith(f.snapshot + ".tmp-")) {
        const candidate = JSON.parse(await fsp.readFile(String(source), "utf8"));
        completed = candidate.version === 2 && candidate.evictionLedgerRequired === false;
      }
      const result = await originalRename(source, destination, ...args);
      if (completed) renamedComplete = true;
      return result;
    };
    fsp.open = async (requested, ...args) => {
      const handle = await originalOpen(requested, ...args);
      if (renamedComplete && !failedCompleteSync
        && path.resolve(String(requested)) === path.resolve(f.root)
        && args[0] === 0 /* O_RDONLY directory fsync */) {
        handle.sync = async () => {
          failedCompleteSync = true;
          throw Object.assign(new Error("post-v2-full-checkpoint directory EIO"), { code: "EIO" });
        };
      }
      return handle;
    };
    try { report = await sync.syncOnce(); } catch (error) { thrown = error; }
  } finally {
    fsp.rename = originalRename;
    fsp.open = originalOpen;
  }
  assert.equal(renamedComplete, true, "a real v2 required=false snapshot rename must complete");
  assert.equal(failedCompleteSync, true, "the subsequent parent directory fsync must receive EIO");
  assert.ok(thrown || report?.excluded?.failed?.length,
    "post-rename fsync failure must not report an unqualified successful eviction");
  const disk = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(disk.version, 2);
  assert.equal(disk.evictionLedgerRequired, false,
    "the freshly installed snapshot may be visible despite durability EIO");
  await assert.rejects(fsp.lstat(f.local), { code: "ENOENT" });
  const journalNames = await fsp.readdir(f.ledger);
  assert.ok(journalNames.some((name) => name.endsWith(".prepare.json")));
  assert.ok(journalNames.some((name) => name.endsWith(".commit.json")));
  // Reacquire and reconcile from a truly separate OS process, not merely a
  // fresh JavaScript SyncEngine instance in the process that injected EIO.
  const coldSource = String.raw`
"use strict";
const { SyncEngine } = require(process.argv[1]);
const { SyncObjectStore } = require(process.argv[2]);
(async () => {
  const store = await new SyncObjectStore(process.argv[4]).open();
  let allowedDirectoryCreates = 0;
  const recovered = await new SyncEngine({
    rootDir: process.argv[3],
    adapter: {
      async list(objectId = "") { return store.list("alice", objectId || null); },
      async push(operation) {
        // Resetting exclusions can legitimately publish the non-sensitive
        // parent directory. Never permit a DELETE or a formerly evicted
        // cache file to become a new outbound operation in this cold replay.
        if (operation?.operation !== "create" || operation?.tombstone
          || operation?.metadata?.path !== "PRIVATE"
          || operation?.metadata?.contentType !== "inode/directory"
          || allowedDirectoryCreates !== 0) {
          process.stderr.write("FORBIDDEN_REPLAY_OUTBOUND_" + JSON.stringify({
            operation: operation?.operation, tombstone: operation?.tombstone,
            path: operation?.metadata?.path, contentType: operation?.metadata?.contentType,
          }));
          process.exit(91);
        }
        allowedDirectoryCreates += 1;
        return { status: 201, record: (await store.put("alice", operation)).record };
      },
    },
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    excludedPaths: [], fileKeyResolver: () => Buffer.from(process.argv[5], "base64"),
  }).open();
  await recovered.syncOnce();
  if (allowedDirectoryCreates !== 1) process.exit(96);
  if (recovered.snapshot.remoteOnly[process.argv[6]]?.reason !== "evicted") process.exit(95);
  process.stdout.write("ROOTARK_REQUIRED_V2_COLD_REPLAY_OK");
})().catch((error) => {
  process.stderr.write(String(error?.stack ?? error));
  process.exit(94);
});
`;
  const child = spawn(process.execPath, [
    "-e", coldSource, require.resolve("../sync-client/rootark-sync-engine"),
    require.resolve("../src/routes/sync"), f.root, f.storePath, f.key.toString("base64"),
    f.signed.objectId,
  ], { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (data) => { stdout += data.toString(); });
  child.stderr.on("data", (data) => { stderr += data.toString(); });
  const exitCode = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill(); reject(new Error("cold recovery subprocess timed out"));
    }, 30000);
    child.once("close", (code) => { clearTimeout(timeout); resolve(code); });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
  });
  assert.equal(exitCode, 0, "cold recovery must succeed with no outbound signed write: " + stderr);
  assert.equal(stdout, "ROOTARK_REQUIRED_V2_COLD_REPLAY_OK");
  const diskStore = await new SyncObjectStore(f.storePath).open();
  assert.equal(diskStore.list("alice").filter((item) => item.tombstone).length, 0,
    "a truly fresh process may not create a signed tombstone in the durable server store");
  const originalRemote = diskStore.list("alice", f.signed.objectId)[0];
  assert.equal(originalRemote?.operationId, f.signed.operationId,
    "cold reconciliation must not replace the original protected server object");
  assert.equal(originalRemote?.tombstone, false);
  verifyNoSignedDelete(f, before);
});

test("issue 66: failed required-v2 snapshot publication must not unlink a swapped temporary inode", async (t) => {
  const f = await fixture(t, "snapshot-failed-rename-foreign-temp");
  const sync = await f.create(f.root, ["private"]);
  const priorDisk = await fsp.readFile(f.snapshot);
  const foreign = Buffer.from("FOREIGN_SNAPSHOT_TEMP_NEVER_UNLINK");
  const parked = path.join(f.dir, "original-snapshot-temp-parked");
  const originalRename = fsp.rename;
  const originalRm = fsp.rm;
  let planted = null;
  let attemptedForeignRemoval = false;
  const beforeWrites = f.outbound.length;
  try {
    fsp.rename = async (source, destination, ...args) => {
      if (!planted && path.resolve(String(destination)) === path.resolve(f.snapshot)
        && String(source).startsWith(f.snapshot + ".tmp-")) {
        planted = String(source);
        await originalRename(source, parked);
        await fsp.writeFile(source, foreign, { flag: "wx" });
        throw Object.assign(new Error("physical snapshot temporary changed before rename"), { code: "EIO" });
      }
      return originalRename(source, destination, ...args);
    };
    fsp.rm = async (requested, ...args) => {
      if (planted && path.resolve(String(requested)) === path.resolve(planted)) {
        attemptedForeignRemoval = true;
        // Intercept before any foreign bytes are destroyed.
        throw Object.assign(new Error("foreign snapshot removal intercepted"), { code: "EACCES" });
      }
      return originalRm(requested, ...args);
    };
    await assert.rejects(sync.persistSnapshot(), { code: "EIO" });
  } finally {
    fsp.rename = originalRename;
    fsp.rm = originalRm;
  }
  assert.ok(planted, "must physically substitute a real O_EXCL temporary after close");
  assert.equal(attemptedForeignRemoval, false,
    "a failed snapshot rename must never remove a foreign substituted name");
  assert.deepEqual(await fsp.readFile(planted), foreign);
  assert.equal((await fsp.lstat(planted)).nlink, 1);
  assert.ok((await fsp.lstat(parked)).isFile());
  assert.deepEqual(await fsp.readFile(f.snapshot), priorDisk);
  // A preserved orphan MUST NOT turn into an ordinary remote sync upload,
  // nor be mistaken for a previously authenticated cache entry.
  const journalOrphan = path.join(f.root,
    ".rootark-sync-journal.json.tmp-123-00000000-0000-4000-8000-000000000066");
  await fsp.writeFile(journalOrphan, "UNCOMMITTED_JOURNAL_TEMP", { flag: "wx" });
  const scan = await sync.scanFiles();
  assert.equal(Object.hasOwn(scan, path.basename(planted)), false,
    "failed snapshot temporary must remain internal and never sync");
  assert.equal(Object.hasOwn(scan, path.basename(journalOrphan)), false,
    "failed journal temporary must remain internal and never sync");
  const physical = await sync.scanPhysicalCacheForEvictionRecovery();
  assert.equal(Object.hasOwn(physical, path.basename(planted)), false,
    "required-v2 physical cache proof must not treat temp debris as local user data");
  assert.equal(Object.hasOwn(physical, path.basename(journalOrphan)), false,
    "required-v2 physical recovery must ignore uncommitted journal temp debris");
  const cold = await f.create(f.root, ["private"]);
  const recovery = await cold.syncOnce();
  assert.equal(recovery.excluded.evicted, 1,
    "legitimate exclusion recovery must still work with inert temp debris");
  verifyNoSignedDelete(f, beforeWrites);
});

test("issue 66: previously tracked control-temp names must never become signed DELETE after namespace reservation", async (t) => {
  const f = await fixture(t, "historical-control-temp-user-names");
  const active = await f.create(f.root, []);
  const names = [
    ".rootark-sync-index.json.tmp-legacy-user-file",
    ".rootark-sync-journal.json.tmp-legacy-user-file",
  ];
  const foreign = Buffer.from("HISTORICALLY_TRACKED_USER_BYTES_MUST_NOT_BE_REMOTELY_DELETED");
  const exemplar = active.snapshot.files["PRIVATE/secret.txt"];
  assert.ok(exemplar && !exemplar.deleted, "test requires a real tracked signed local file");
  for (const name of names) {
    await fsp.writeFile(path.join(f.root, name), foreign, { flag: "wx" });
    active.snapshot.files[name] = {
      ...exemplar,
      objectId: "object-" + crypto.randomUUID().replace(/-/g, ""),
      fileId: "file-" + crypto.randomUUID().replace(/-/g, ""),
    };
  }
  await active.persistSnapshot();
  const before = f.outbound.length;
  let attemptedSignedDelete = false;
  let failure;
  try {
    const restarted = await f.create(f.root, []);
    const original = restarted.assertOutgoingAuthorized.bind(restarted);
    restarted.assertOutgoingAuthorized = async (operation, enqueue) => {
      if (operation.operation === "delete" && names.includes(operation.metadata?.path)) {
        attemptedSignedDelete = true;
        // The previous code would submit a tombstone for an existing user
        // inode. Abort BEFORE journal enqueue or outbound push, preserving
        // the fixture's genuine protected remote content.
        throw Object.assign(new Error("historical user deletion intercepted"), { code: "EACCES" });
      }
      return original(operation, enqueue);
    };
    await restarted._reconcileLocal();
  } catch (error) { failure = error; }
  assert.equal(attemptedSignedDelete, false,
    "reserved-name migration must deny rather than queue a signed DELETE");
  assert.equal(failure?.code, "invalid_snapshot",
    "a historical tracked collision must fail closed before ordinary sync");
  for (const name of names) {
    assert.deepEqual(await fsp.readFile(path.join(f.root, name)), foreign);
    assert.throws(() => validatePortableRelativePath(name), { code: "unsafe_path" },
      "new metadata must not allocate a formerly user-legal reserved name");
  }
  verifyNoSignedDelete(f, before);
});

test("issue 66: nested historically tracked control-temp path cannot generate signed DELETE", async (t) => {
  const f = await fixture(t, "historical-nested-control-temp-user-names");
  const active = await f.create(f.root, []);
  const names = [
    "docs/.rootark-sync-index.json.tmp-legacy-nested-user-file",
    "docs/.rootark-sync-journal.json.tmp-legacy-nested-user-file",
  ];
  const foreign = Buffer.from("REAL_OLD_NESTED_USER_FILE_MUST_NOT_BECOME_REMOTE_DELETE");
  await fsp.mkdir(path.join(f.root, "docs"), { recursive: true });
  const prior = active.snapshot.files["PRIVATE/secret.txt"];
  assert.ok(prior && !prior.deleted);
  for (const relative of names) {
    await fsp.writeFile(path.join(f.root, relative), foreign, { flag: "wx" });
    active.snapshot.files[relative] = {
      ...prior,
      objectId: "object-" + crypto.randomUUID().replace(/-/g, ""),
      fileId: "file-" + crypto.randomUUID().replace(/-/g, ""),
    };
  }
  await active.persistSnapshot();
  const before = f.outbound.length;
  let attempted = false;
  let error;
  try {
    const cold = await f.create(f.root, []);
    const originallyAuthorized = cold.assertOutgoingAuthorized.bind(cold);
    cold.assertOutgoingAuthorized = async (operation, enqueue) => {
      if (operation.operation === "delete" && names.includes(operation.metadata?.path)) {
        attempted = true;
        // Stop a would-be tombstone before durable journal admission.
        throw Object.assign(new Error("nested historical tombstone intercepted"), { code: "EACCES" });
      }
      return originallyAuthorized(operation, enqueue);
    };
    await cold._reconcileLocal();
  } catch (cause) { error = cause; }
  assert.equal(attempted, false, "no nested historical user file may generate signed DELETE");
  assert.equal(error?.code, "invalid_snapshot", "legacy nested control name must fail closed");
  for (const relative of names) {
    assert.deepEqual(await fsp.readFile(path.join(f.root, relative)), foreign);
    assert.throws(() => validatePortableRelativePath(relative), { code: "unsafe_path" });
  }
  verifyNoSignedDelete(f, before);
});

test("issue 66: an already-open engine refuses a newly discovered nested historic control-temp collision", async (t) => {
  const f = await fixture(t, "in-memory-nested-historical-control-temp");
  const engine = await f.create(f.root, []);
  const relative = "docs/.rootark-sync-index.json.tmp-already-open-user-file";
  await fsp.mkdir(path.join(f.root, "docs"), { recursive: true });
  const foreign = Buffer.from("OPEN_ENGINE_HISTORICAL_USER_FILE");
  await fsp.writeFile(path.join(f.root, relative), foreign, { flag: "wx" });
  const exemplar = engine.snapshot.files["PRIVATE/secret.txt"];
  assert.ok(exemplar && !exemplar.deleted);
  engine.snapshot.files[relative] = {
    ...exemplar,
    objectId: "object-" + crypto.randomUUID().replace(/-/g, ""),
    fileId: "file-" + crypto.randomUUID().replace(/-/g, ""),
  };
  const original = engine.assertOutgoingAuthorized.bind(engine);
  let attempted = false;
  engine.assertOutgoingAuthorized = async (operation, enqueue) => {
    if (operation.operation === "delete" && operation.metadata?.path === relative) {
      attempted = true;
      throw Object.assign(new Error("outgoing nested tombstone blocked by test"), { code: "EACCES" });
    }
    return original(operation, enqueue);
  };
  const before = f.outbound.length;
  await assert.rejects(engine._reconcileLocal(), { code: "invalid_snapshot" },
    "an already-open engine must deny this historical collision before any signed operation");
  assert.equal(attempted, false);
  assert.deepEqual(await fsp.readFile(path.join(f.root, relative)), foreign);
  verifyNoSignedDelete(f, before);
});

test("issue 66: configured root-local snapshot and journal filenames and orphans stay internal", async (t) => {
  const f = await fixture(t, "custom-root-control-filenames");
  const snapshotPath = path.join(f.root, "custom-root-index.json");
  const journalPath = path.join(f.root, "custom-root-journal.json");
  // Use a genuine previously persisted snapshot, not a manufactured empty
  // object that could accidentally conceal a cache reconciliation failure.
  await fsp.writeFile(snapshotPath, await fsp.readFile(f.snapshot), { flag: "wx" });
  const sync = await f.create(f.root, [], { snapshotPath, journalPath });
  const snapshotOrphan = snapshotPath + ".tmp-101-00000000-0000-4000-8000-000000000066";
  const journalOrphan = journalPath + ".tmp-102-00000000-0000-4000-8000-000000000066";
  await fsp.writeFile(snapshotOrphan, "CUSTOM_INERT_SNAPSHOT", { flag: "wx" });
  await fsp.writeFile(journalOrphan, "CUSTOM_INERT_JOURNAL", { flag: "wx" });
  const internals = [snapshotPath, journalPath, snapshotOrphan, journalOrphan];
  for (const listing of [await sync.scanFiles(), await sync.scanPhysicalCacheForEvictionRecovery()]) {
    assert.ok(Object.hasOwn(listing, "PRIVATE/secret.txt"),
      "the signed legitimate cache still participates in the physical proof");
    for (const internal of internals) {
      assert.equal(Object.hasOwn(listing, path.basename(internal)), false,
        "a custom in-root control name or orphan must never become a synced user object");
    }
  }
  const before = f.outbound.length;
  const cold = await f.create(f.root, [], { snapshotPath, journalPath });
  await cold.syncOnce();
  verifyNoSignedDelete(f, before);
  for (const internal of internals) assert.ok((await fsp.lstat(internal)).isFile());
  const unsupportedNested = path.join(f.root, "user-folder", "state.json");
  await assert.rejects(f.create(f.root, [], { snapshotPath: unsupportedNested, journalPath }),
    { code: "unsafe_path" }, "nested custom state cannot be treated as user content");
  await assert.rejects(fsp.lstat(unsupportedNested), { code: "ENOENT" });
});

async function fillLegitimateTrash(root, count = 16385) {
  const directory = path.join(root, ".rootark-trash");
  await fsp.mkdir(directory, { recursive: true });
  // Real, distinct directory entries. 256 concurrent creations keep the
  // regression practical on both Windows NTFS and native WSL ext4.
  for (let offset = 0; offset < count; offset += 256) {
    await Promise.all(Array.from({ length: Math.min(256, count - offset) }, (_, index) =>
      fsp.writeFile(path.join(directory, `staged-cache-${String(offset + index).padStart(6, "0")}`),
        "", { flag: "wx" })));
  }
  assert.equal((await fsp.readdir(directory)).length, count);
}

test("issue 66 P2: ordinary v1 and completed v2 boot with >16384 legitimate trash entries", async (t) => {
  for (const state of ["v1", "v2-completed"]) {
    const f = await fixture(t, `large-trash-${state}`);
    if (state === "v2-completed") {
      const sync = await f.create(f.root, ["private"]);
      assert.equal((await sync.syncOnce()).excluded.evicted, 1);
      const disk = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
      assert.equal(disk.version, 2);
      assert.equal(disk.evictionLedgerRequired, false);
    } else {
      assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).version, 1);
    }
    await fillLegitimateTrash(f.root);
    const before = f.outbound.length;
    const restarted = await f.create(f.root, []);
    assert.equal(restarted.snapshot.version, state === "v1" ? 1 : 2);
    assert.equal(restarted.snapshot.evictionLedgerRequired, state === "v1" ? undefined : false);
    await restarted.syncOnce();
    verifyNoSignedDelete(f, before);
  }
});

test("issue 66 P2: large legitimate trash does not prevent first signed v1 exclusion migration", async (t) => {
  const f = await fixture(t, "large-trash-first-migration");
  await fillLegitimateTrash(f.root);
  const before = f.outbound.length;
  const sync = await f.create(f.root, ["private"]);
  const report = await sync.syncOnce();
  assert.equal(report.excluded.evicted, 1);
  const disk = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(disk.version, 2);
  assert.equal(disk.evictionLedgerRequired, false);
  verifyNoSignedDelete(f, before);
});

test("issue 66 P2: retained zero-genesis head after recovered checkpoint permits later large trash", async (t) => {
  const f = await fixture(t, "large-trash-after-zero-head-recovery");
  await prePrepareCrash(f);
  const recovered = await f.create(f.root, []);
  assert.equal(recovered.snapshot.evictionLedgerRequired, false);
  assert.deepEqual(await fsp.readdir(f.ledger), ["head.json"],
    "regression requires a retained zero-sequence active head after safe recovery");
  await fillLegitimateTrash(f.root);
  const before = f.outbound.length;
  const restarted = await f.create(f.root, []);
  assert.equal(restarted.snapshot.evictionLedgerRequired, false);
  await restarted.syncOnce();
  verifyNoSignedDelete(f, before);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
});

test("issue 66 P2: a large trash directory cannot conceal a case-alias genesis marker", async (t) => {
  const f = await fixture(t, "large-trash-ambiguous-genesis");
  await fillLegitimateTrash(f.root);
  const alias = path.join(f.root, ".rootark-trash", ".ROOTARK-EVICTION-GENESIS-HEAD.JSON");
  await fsp.writeFile(alias, "forged genesis marker", { flag: "wx" });
  const before = f.outbound.length;
  const sync = await f.create(f.root, ["private"]);
  await assert.rejects(sync.syncOnce(), (error) =>
    error?.code === "invalid_snapshot" && /Ambiguous staged eviction genesis/.test(error.message));
  verifyNoSignedDelete(f, before);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
});

test("issue 66 P2: retained active zero head cannot migrate over a competing staged genesis", async (t) => {
  const f = await fixture(t, "competing-staged-and-active-zero-head");
  await prePrepareCrash(f);
  const recovered = await f.create(f.root, []);
  assert.equal(recovered.snapshot.evictionLedgerRequired, false);
  const headFile = path.join(f.ledger, "head.json");
  assert.deepEqual(await fsp.readdir(f.ledger), ["head.json"]);
  const stagedFile = path.join(f.root, ".rootark-trash", ".rootark-eviction-genesis-head.json");
  await fsp.copyFile(headFile, stagedFile);
  const before = f.outbound.length;
  const migration = await f.create(f.root, ["private"]);
  await assert.rejects(migration.syncOnce(), { code: "invalid_snapshot" });
  verifyNoSignedDelete(f, before);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
});

test("issue 66: required-v2 cold recovery treats nested inbound orphan as inert, not arbitrary directory", async (t) => {
  for (const kind of ["file", "directory"]) {
    const f = await fixture(t, `nested-inbound-orphan-${kind}`);
    // A genuinely separate process exits after the required-v2 checkpoint,
    // before PREPARE. The recovery scanner then sees an authentic cache plus
    // a synthetic failure-path inbound artifact inside the selected subtree.
    await prePrepareCrash(f, false, true);
    const orphan = path.join(f.root, "PRIVATE",
      `.rootark-sync-index.json.tmp-inbound-123-${crypto.randomUUID()}`);
    if (kind === "file") await fsp.writeFile(orphan, "inert incomplete incoming payload", { flag: "wx" });
    else await fsp.mkdir(orphan);
    const before = f.outbound.length;
    if (kind === "file") {
      const recovered = await f.create(f.root, ["private"]);
      assert.equal(recovered.snapshot.evictionLedgerRequired, false,
        "an inert nested temp must not prevent legitimate required-v2 cold recovery");
      assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file",
        "cold recovery must preserve original bytes before voluntary exclusion");
      await recovered.syncOnce();
      assert.equal(await fsp.readFile(orphan, "utf8"), "inert incomplete incoming payload");
      assert.equal(recovered.snapshot.remoteOnly[f.signed.objectId]?.reason, "evicted",
        "the legitimate selected exclusion must still complete without signing DELETE");
    } else {
      await assert.rejects(f.create(f.root, ["private"]), { code: "invalid_snapshot" },
        "a directory disguised as an inbound temp is not valid disposable evidence");
      assert.equal((await fsp.lstat(orphan)).isDirectory(), true);
    }
    verifyNoSignedDelete(f, before);
  }
});

test("issue 66 P2: hard crash with >16384 preexisting trash entries recovers required-v2 before PREPARE", async (t) => {
  for (const stage of ["staged", "active"]) {
    const f = await fixture(t, `large-trash-required-recovery-${stage}`);
    await fillLegitimateTrash(f.root);
    const before = f.outbound.length;
    await prePrepareCrash(f, false, stage === "staged");
    const diskBefore = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
    assert.equal(diskBefore.evictionLedgerRequired, true);
    const recovered = await f.create(f.root, ["private"]);
    assert.equal(recovered.snapshot.evictionLedgerRequired, false,
      "intact required-v2 zero-PREPARE cache must be recoverable despite 16k+ unrelated trash entries");
    assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
    await recovered.syncOnce();
    verifyNoSignedDelete(f, before);
  }
});

test("issue 66: staged genesis must enumerate the held trash, not a swapped path", {
  skip: process.platform !== "linux" && "Linux procfd directory anchors are required",
}, async (t) => {
  const f = await fixture(t, "held-trash-parent-race");
  await prePrepareCrash(f, false, true);
  const trash = path.join(f.root, ".rootark-trash");
  const displaced = path.join(f.root, ".rootark-trash-parked");
  const attacker = path.join(f.dir, "attacker-trash");
  await fsp.mkdir(attacker);
  await fsp.writeFile(path.join(attacker, "ATTACKER_SENTINEL"), "never enumerate this");
  const originalOpendir = fsp.opendir;
  let injected = false;
  let attackerEnumerated = false;
  fsp.opendir = async (directory, ...args) => {
    const requested = String(directory);
    if (!injected && (requested === trash || /^\/proc\/self\/fd\/\d+$/.test(requested))) {
      injected = true;
      // Real ext4 namespace race: replace the visible trash name immediately
      // before enumeration; only the previously held inode may be enumerated.
      await fsp.rename(trash, displaced);
      await fsp.symlink(attacker, trash, "dir");
      const opened = await originalOpendir(directory, ...args);
      const first = await opened.read();
      attackerEnumerated = first?.name === "ATTACKER_SENTINEL";
      return opened;
    }
    return originalOpendir(directory, ...args);
  };
  try {
    await assert.rejects(f.create(f.root, ["private"]),
      (error) => error.code === "invalid_snapshot" || error.code === "unsafe_path");
    assert.equal(injected, true, "recovery must physically enumerate staged trash");
    assert.equal(attackerEnumerated, false, "a swapped pathname must never be enumerated");
  } finally {
    fsp.opendir = originalOpendir;
    if (injected) {
      await fsp.unlink(trash);
      await fsp.rename(displaced, trash);
    }
  }
});

test("issue 66: Linux recovery must not enumerate a ledger directory replaced after validation", {
  skip: process.platform !== "linux" && "Linux held ledger dirfd required",
}, async (t) => {
  const f = await fixture(t, "held-ledger-parent-race");
  await prePrepareCrash(f);
  const originalLedger = f.ledger;
  const displaced = path.join(f.root, ".rootark-sync-evictions-displaced");
  const attacker = path.join(f.dir, "attacker-ledger");
  await fsp.mkdir(attacker);
  await fsp.writeFile(path.join(attacker, "ATTACKER_SENTINEL"), "foreign data, never enumerate");
  const originalReaddir = fsp.readdir;
  const originalOpendir = fsp.opendir;
  let injected = false;
  let attackerEnumerated = false;
  const ledgerRequest = async (requested) => {
    const requestedName = String(requested);
    if (requestedName === originalLedger) return true;
    if (!/^\/proc\/self\/fd\/\d+$/.test(requestedName)) return false;
    try { return path.resolve(await fsp.realpath(requested)) === path.resolve(originalLedger); }
    catch { return false; }
  };
  const inject = async (requested) => {
    if (!injected && await ledgerRequest(requested)) {
      injected = true;
      await fsp.rename(originalLedger, displaced);
      await fsp.symlink(attacker, originalLedger, "dir");
    }
  };
  fsp.readdir = async (requested, ...args) => {
    await inject(requested);
    const names = await originalReaddir(requested, ...args);
    if (injected && names.includes("ATTACKER_SENTINEL")) attackerEnumerated = true;
    return names;
  };
  fsp.opendir = async (requested, ...args) => {
    const isLedger = await ledgerRequest(requested);
    if (isLedger) await inject(requested);
    const dir = await originalOpendir(requested, ...args);
    if (!isLedger) return dir;
    return {
      async *[Symbol.asyncIterator]() {
        for await (const entry of dir) {
          if (entry.name === "ATTACKER_SENTINEL") attackerEnumerated = true;
          yield entry;
        }
      },
    };
  };
  const before = f.outbound.length;
  try {
    await assert.rejects(f.create(f.root, ["private"]),
      (error) => ["invalid_snapshot", "unsafe_path"].includes(error?.code));
  } finally {
    fsp.readdir = originalReaddir;
    fsp.opendir = originalOpendir;
    if (injected) {
      await fsp.unlink(originalLedger);
      await fsp.rename(displaced, originalLedger);
    }
  }
  assert.equal(injected, true, "the ledger reader must reach a real directory enumeration");
  assert.equal(attackerEnumerated, false, "the reader must never enumerate the swapped-in directory");
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  verifyNoSignedDelete(f, before);
});

test("issue 66: eviction recovery streams ledger names instead of an unbounded readdir", async (t) => {
  const f = await fixture(t, "stream-held-ledger-names");
  await prePrepareCrash(f);
  const originalReaddir = fsp.readdir;
  let unboundedLedgerReads = 0;
  fsp.readdir = async (requested, ...args) => {
    let ledger = String(requested) === f.ledger;
    if (!ledger && /^\/proc\/self\/fd\/\d+$/.test(String(requested))) {
      try { ledger = path.resolve(await fsp.realpath(requested)) === path.resolve(f.ledger); }
      catch { /* Non-ledger procfd handled normally. */ }
    }
    if (ledger) {
      unboundedLedgerReads += 1;
      throw new Error("Unbounded ledger enumeration is prohibited");
    }
    return originalReaddir(requested, ...args);
  };
  const before = f.outbound.length;
  try {
    const recovered = await f.create(f.root, ["private"]);
    assert.equal(recovered.snapshot.evictionLedgerRequired, false);
  } finally { fsp.readdir = originalReaddir; }
  assert.equal(unboundedLedgerReads, 0, "ledger names must be streamed with a finite cap");
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  verifyNoSignedDelete(f, before);
});

test("issue 66: ledger name stream rejects excess entries without materializing the tail", async (t) => {
  const f = await fixture(t, "bounded-ledger-name-stream");
  await prePrepareCrash(f);
  const originalOpendir = fsp.opendir;
  let yielded = 0;
  let boundedEnumeratorUsed = false;
  fsp.opendir = async (requested, ...args) => {
    let ledger = String(requested) === f.ledger;
    if (!ledger && /^\/proc\/self\/fd\/\d+$/.test(String(requested))) {
      try { ledger = path.resolve(await fsp.realpath(requested)) === path.resolve(f.ledger); }
      catch { /* Preserve other procfd reads. */ }
    }
    if (!ledger) return originalOpendir(requested, ...args);
    boundedEnumeratorUsed = true;
    return {
      async *[Symbol.asyncIterator]() {
        // No huge physical fixture needed for this capacity boundary: the
        // real ledger root/head exist, and only the name source is injected.
        for (let i = 0; i < 32770; i++) {
          yielded++;
          yield { name: `untrusted-name-${i}` };
        }
        throw new Error("Name stream illegally consumed beyond the cap");
      },
    };
  };
  const before = f.outbound.length;
  try {
    await assert.rejects(f.create(f.root, ["private"]), (error) =>
      error?.code === "invalid_snapshot" && /capacity exceeded/.test(error.message));
  } finally { fsp.opendir = originalOpendir; }
  assert.equal(boundedEnumeratorUsed, true);
  assert.equal(yielded, 32770, "must stop at max+1, not consume additional entries");
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  verifyNoSignedDelete(f, before);
});

test("issue 66: Linux PREPARE cannot write into foreign ledger after a real directory substitution", {
  skip: process.platform !== "linux" && "requires Linux held descriptor and real symlink substitution",
}, async (t) => {
  const f = await fixture(t, "foreign-prepare-substitution");
  const foreign = path.join(f.dir, "foreign-ledger");
  const parked = path.join(f.root, ".rootark-sync-evictions-parked");
  await fsp.mkdir(foreign);
  await fsp.writeFile(path.join(foreign, "FOREIGN_SENTINEL"), "foreign bytes stay intact");
  const sync = await f.create(f.root, ["private"]);
  const originalOpen = fsp.open;
  let substituted = false;
  fsp.open = async (requested, ...args) => {
    if (!substituted && /[a-f0-9]{64}\.prepare\.json$/.test(String(requested))) {
      substituted = true;
      // Reproduce a real same-UID pathname replacement at the precise
      // syscall that would create a durable PREPARE; no mock directory data.
      await fsp.rename(f.ledger, parked);
      await fsp.symlink(foreign, f.ledger, "dir");
    }
    return originalOpen(requested, ...args);
  };
  const before = f.outbound.length;
  try {
    await assert.rejects(sync.syncOnce(), (error) =>
      ["invalid_snapshot", "unsafe_path", "root_session_native_unavailable"].includes(error?.code),
    "a substituted ledger must deny eviction instead of completing");
  } finally {
    fsp.open = originalOpen;
    if (substituted) {
      await fsp.unlink(f.ledger);
      await fsp.rename(parked, f.ledger);
    }
  }
  assert.equal(substituted, true, "the test must hit the physical PREPARE creation boundary");
  assert.deepEqual(await fsp.readdir(foreign), ["FOREIGN_SENTINEL"],
    "no PREPARE, HEAD or temporary file may be created outside the held ledger");
  assert.equal(await fsp.readFile(path.join(foreign, "FOREIGN_SENTINEL"), "utf8"),
    "foreign bytes stay intact");
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  verifyNoSignedDelete(f, before);
});

test("issue 66: Linux COMMIT cannot write into foreign ledger after a real directory substitution", {
  skip: process.platform !== "linux" && "requires Linux held descriptor and real symlink substitution",
}, async (t) => {
  const f = await fixture(t, "foreign-commit-substitution");
  const foreign = path.join(f.dir, "foreign-ledger");
  const parked = path.join(f.root, ".rootark-sync-evictions-parked");
  await fsp.mkdir(foreign);
  await fsp.writeFile(path.join(foreign, "FOREIGN_SENTINEL"), "foreign bytes stay intact");
  const sync = await f.create(f.root, ["private"]);
  const originalOpen = fsp.open;
  let substituted = false;
  fsp.open = async (requested, ...args) => {
    if (!substituted && /[a-f0-9]{64}\.commit\.json$/.test(String(requested))) {
      substituted = true;
      await fsp.rename(f.ledger, parked);
      await fsp.symlink(foreign, f.ledger, "dir");
    }
    return originalOpen(requested, ...args);
  };
  const before = f.outbound.length;
  try {
    await assert.rejects(sync.syncOnce(), (error) =>
      ["invalid_snapshot", "unsafe_path", "root_session_native_unavailable"].includes(error?.code),
    "a substituted ledger must not commit eviction through a foreign directory");
  } finally {
    fsp.open = originalOpen;
    if (substituted) {
      await fsp.unlink(f.ledger);
      await fsp.rename(parked, f.ledger);
    }
  }
  assert.equal(substituted, true, "test must hit the actual COMMIT creation boundary");
  assert.deepEqual(await fsp.readdir(foreign), ["FOREIGN_SENTINEL"],
    "COMMIT must be bound to the original ledger, never the foreign directory");
  assert.equal(await fsp.readFile(path.join(foreign, "FOREIGN_SENTINEL"), "utf8"),
    "foreign bytes stay intact");
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true,
    "an uncertain COMMIT must retain the required-v2 recovery marker");
  verifyNoSignedDelete(f, before);
});

test("issue 66: Linux ledger retirement cannot delete files through a substituted archive symlink", {
  skip: process.platform !== "linux" && "Linux rooted retirement must exclude a foreign symlink",
}, async (t) => {
  const f = await fixture(t, "foreign-ledger-retirement");
  const foreign = path.join(f.dir, "foreign-ledger");
  const parked = path.join(f.root, ".rootark-sync-evictions-parked");
  await fsp.mkdir(foreign);
  const foreignReal = await fsp.realpath(foreign);
  await fsp.writeFile(path.join(foreign, "FOREIGN_SENTINEL"), "leave foreign bytes intact");
  const sync = await f.create(f.root, ["private"]);
  const originalRename = fsp.rename;
  const originalUnlink = fsp.unlink;
  let swapped = false;
  let attemptedForeignUnlink = false;
  let archiveVisible = null;
  let foreignNames = null;
  fsp.rename = async (source, destination, ...args) => {
    const sourceName = path.basename(String(source));
    const destinationName = path.basename(String(destination));
    if (!swapped && sourceName === ".rootark-sync-evictions"
      && destinationName.startsWith(".rootark-sync-evictions-archive-")) {
      swapped = true;
      archiveVisible = path.join(f.root, destinationName);
      const names = await fsp.readdir(f.ledger);
      assert.ok(names.some((name) => name.endsWith(".prepare.json")));
      assert.ok(names.some((name) => name.endsWith(".commit.json")));
      for (const name of names) {
        await fsp.writeFile(path.join(foreign, name), `FOREIGN ${name}`, { flag: "wx" });
      }
      foreignNames = (await fsp.readdir(foreign)).sort();
      await originalRename(f.ledger, parked);
      await fsp.symlink(foreign, f.ledger, "dir");
    }
    return originalRename(source, destination, ...args);
  };
  fsp.unlink = async (target, ...args) => {
    if (swapped) {
      let resolvedParent;
      try { resolvedParent = await fsp.realpath(path.dirname(String(target))); }
      catch (error) { if (error.code !== "ENOENT") throw error; }
      // Works for BOTH pathname archives and /proc/self/fd/<dirfd> children.
      // Guard the actual physical parent, not its textual basename: a wrong
      // held descriptor must also be intercepted before it can delete bytes.
      if (resolvedParent && path.resolve(resolvedParent) === path.resolve(foreignReal)) {
        attemptedForeignUnlink = true;
        throw Object.assign(new Error("foreign archive unlink blocked by test"),
          { code: "EACCES" });
      }
    }
    return originalUnlink(target, ...args);
  };
  const before = f.outbound.length;
  try {
    await assert.rejects(sync.syncOnce(), (error) =>
      error?.code === "invalid_snapshot"
        && /archive identity is indeterminate/.test(error.message),
    "a substituted archive must be rejected by exact identity, not incidental errors");
  } finally {
    fsp.rename = originalRename;
    fsp.unlink = originalUnlink;
    if (swapped) {
      if (archiveVisible) {
        try {
          const stat = await fsp.lstat(archiveVisible);
          if (stat.isSymbolicLink()) await fsp.unlink(archiveVisible);
        } catch (error) { if (error.code !== "ENOENT") throw error; }
      }
      try {
        const stat = await fsp.lstat(f.ledger);
        if (stat.isSymbolicLink()) await fsp.unlink(f.ledger);
        else if (stat.isDirectory() && !(await fsp.readdir(f.ledger)).length) {
          await fsp.rmdir(f.ledger);
        }
      } catch (error) { if (error.code !== "ENOENT") throw error; }
      await fsp.rename(parked, f.ledger);
    }
  }
  assert.equal(swapped, true, "the test must reach the actual archive rename");
  assert.equal(attemptedForeignUnlink, false,
    "the engine must never attempt to delete a foreign entry through an archive symlink");
  assert.deepEqual((await fsp.readdir(foreign)).sort(), foreignNames);
  for (const name of foreignNames) {
    assert.equal(await fsp.readFile(path.join(foreign, name), "utf8"),
      name === "FOREIGN_SENTINEL" ? "leave foreign bytes intact" : `FOREIGN ${name}`);
  }
  verifyNoSignedDelete(f, before);
});

test("issue 66: legitimate Linux ledger retirement leaves no orphan archive after a durable eviction", {
  skip: process.platform !== "linux" && "Linux held-directory retirement",
}, async (t) => {
  const f = await fixture(t, "successful-held-ledger-retirement");
  const before = f.outbound.length;
  const sync = await f.create(f.root, ["private"]);
  const report = await sync.syncOnce();
  assert.equal(report.excluded.evicted, 1);
  assert.deepEqual(await fsp.readdir(f.ledger), [],
    "a successful durable compaction must leave a fresh empty active ledger");
  assert.deepEqual((await fsp.readdir(f.root)).filter((name) =>
    name.startsWith(".rootark-sync-evictions-archive-")), [],
  "no archive may remain after successful held-directory cleanup");
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, false);
  verifyNoSignedDelete(f, before);
});

test("issue 66 P2: required v2 refuses a staged case-alias hidden among >16384 trash entries", async (t) => {
  const f = await fixture(t, "large-trash-required");
  await fillLegitimateTrash(f.root);
  await prePrepareCrash(f, false, true);
  const stage = path.join(f.root, ".rootark-trash", ".rootark-eviction-genesis-head.json");
  const alias = path.join(f.root, ".rootark-trash", ".ROOTARK-EVICTION-GENESIS-HEAD.JSON");
  if (process.platform === "win32") {
    // On ordinary NTFS the alternate spelling is the same physical entry.
    await fsp.rename(stage, alias);
  } else {
    await fsp.writeFile(alias, "forged case alias", { flag: "wx" });
  }
  const before = f.outbound.length;
  await assert.rejects(f.create(f.root, ["private"]), { code: "invalid_snapshot" });
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  verifyNoSignedDelete(f, before);
});

test("issue 66 P2: large-trash required-v2 recovery still rejects missing tracked bytes", async (t) => {
  const f = await fixture(t, "large-trash-tracked-missing");
  await fillLegitimateTrash(f.root);
  await prePrepareCrash(f);
  await fsp.unlink(f.local);
  const before = f.outbound.length;
  await assert.rejects(f.create(f.root, ["private"]), { code: "invalid_snapshot" });
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  verifyNoSignedDelete(f, before);
});

test("issue 66 P2 POSIX: required-v2 rejects a linked stage marker and renamed trash ancestry", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX symlinks and ancestry replacement");
  const f = await fixture(t, "linked-required-stage");
  await fillLegitimateTrash(f.root);
  await prePrepareCrash(f, false, true);
  const trash = path.join(f.root, ".rootark-trash");
  const head = path.join(trash, ".rootark-eviction-genesis-head.json");
  const savedHead = path.join(trash, "untrusted-head-copy.json");
  await fsp.rename(head, savedHead);
  await fsp.symlink(savedHead, head);
  const before = f.outbound.length;
  await assert.rejects(f.create(f.root, ["private"]), { code: "invalid_snapshot" });
  await fsp.unlink(head);
  await fsp.rename(savedHead, head);
  const renamedTrash = path.join(f.dir, "outside-renamed-trash");
  await fsp.rename(trash, renamedTrash);
  await fsp.symlink(renamedTrash, trash, "dir");
  await assert.rejects(f.create(f.root, ["private"]), { code: "unsafe_path" });
  verifyNoSignedDelete(f, before);
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
});

test("issue 66 P2: replacing staged genesis parent after complete iteration cannot forge anchored recovery", async (t) => {
  const f = await fixture(t, "renamed-stage-parent-during-proof");
  await prePrepareCrash(f, false, true);
  const trash = path.join(f.root, ".rootark-trash");
  const moved = path.join(f.root, ".rootark-trash-moved-by-host");
  const marker = ".rootark-eviction-genesis-head.json";
  const originalOpendir = fsp.opendir;
  let swapped = false;
  fsp.opendir = async (...args) => {
    const dir = await originalOpendir(...args);
    // Linux now enumerates through the held trash FD; preserve the physical
    // post-iteration swap regression on that route as well as Windows paths.
    if (path.resolve(args[0]) !== path.resolve(trash)
      && !/^\/proc\/self\/fd\/\d+$/.test(String(args[0]))) return dir;
    return {
      async *[Symbol.asyncIterator]() {
        for await (const entry of dir) yield entry;
        // Deliberately swap after enumeration but before the reader can open
        // a byte-identical head at the same path. No symlinks are involved.
        await fsp.rename(trash, moved);
        await fsp.mkdir(trash);
        await fsp.copyFile(path.join(moved, marker), path.join(trash, marker));
        swapped = true;
      },
    };
  };
  const before = f.outbound.length;
  try {
    await assert.rejects(f.create(f.root, ["private"]), { code: "invalid_snapshot" });
  } finally {
    fsp.opendir = originalOpendir;
  }
  assert.equal(swapped, true);
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  verifyNoSignedDelete(f, before);
});

test("issue 66: Linux genesis stage must not write through a replaced trash directory", {
  skip: process.platform !== "linux" && "Linux held trash descriptor required",
}, async (t) => {
  const f = await fixture(t, "genesis-stage-foreign-write");
  const trash = path.join(f.root, ".rootark-trash");
  const parked = path.join(f.root, ".rootark-trash-parked");
  const foreign = path.join(f.dir, "foreign-trash");
  await fsp.mkdir(foreign);
  await fsp.writeFile(path.join(foreign, "FOREIGN_SENTINEL"), "must stay intact");
  const originalOpen = fsp.open;
  let substituted = false;
  fsp.open = async (requested, ...args) => {
    if (!substituted && path.basename(String(requested))
      .startsWith(".rootark-eviction-genesis-head.json.tmp-")) {
      substituted = true;
      await fsp.rename(trash, parked);
      await fsp.symlink(foreign, trash, "dir");
    }
    return originalOpen(requested, ...args);
  };
  const sync = await f.create(f.root, ["private"]);
  const before = f.outbound.length;
  let failure;
  try { await sync.syncOnce(); } catch (error) { failure = error; }
  finally {
    fsp.open = originalOpen;
    if (substituted) {
      await fsp.unlink(trash);
      await fsp.rename(parked, trash);
    }
  }
  assert.equal(substituted, true, "the real genesis temporary create must be reached");
  assert.deepEqual(await fsp.readdir(foreign), ["FOREIGN_SENTINEL"],
    "no temporary or durable genesis may appear in attacker-controlled trash");
  assert.equal(failure?.code, "invalid_snapshot", "stage must fail closed on a changed held parent");
  assert.match(failure.message, /Staged genesis parent changed during creation/);
  assert.equal(await fsp.readFile(path.join(foreign, "FOREIGN_SENTINEL"), "utf8"), "must stay intact");
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  verifyNoSignedDelete(f, before);
});

test("issue 66: staged genesis creation never overwrites a competing reserved head", async (t) => {
  const f = await fixture(t, "genesis-stage-atomic-no-replace");
  const stage = path.join(f.root, ".rootark-trash", ".rootark-eviction-genesis-head.json");
  const foreign = Buffer.from("FOREIGN_STAGED_HEAD_MUST_STAY");
  const sync = await f.create(f.root, ["private"]);
  const originalRename = fsp.rename;
  const originalLink = fsp.link;
  let injected = false;
  let attemptedOverwrite = false;
  const isStagePublish = (source, destination) =>
    path.basename(String(destination)) === ".rootark-eviction-genesis-head.json"
      && path.basename(String(source))
        .startsWith(".rootark-eviction-genesis-head.json.tmp-");
  const inject = async (source, destination) => {
    if (!injected && isStagePublish(source, destination)) {
      injected = true;
      await fsp.writeFile(stage, foreign, { flag: "wx" });
    }
  };
  fsp.rename = async (source, destination, ...args) => {
    await inject(source, destination);
    if (isStagePublish(source, destination)) {
      // A normal rename would destroy the competing file. Intercept the
      // actual original syscall boundary BEFORE any foreign data loss.
      attemptedOverwrite = true;
      throw Object.assign(new Error("destructive stage rename intercepted"), { code: "EACCES" });
    }
    return originalRename(source, destination, ...args);
  };
  fsp.link = async (source, destination, ...args) => {
    await inject(source, destination);
    return originalLink(source, destination, ...args);
  };
  const before = f.outbound.length;
  let failure;
  try { await sync.syncOnce(); } catch (error) { failure = error; }
  finally {
    fsp.rename = originalRename;
    fsp.link = originalLink;
  }
  assert.equal(injected, true, "the real genesis stage publication boundary must be reached");
  assert.equal(attemptedOverwrite, false, "a staging writer must never attempt a destructive rename");
  assert.equal(failure?.code, "invalid_snapshot",
    "an existing staged genesis must fail closed, not be silently replaced");
  assert.match(failure.message, /Existing staged genesis blocks exclusive creation/);
  assert.deepEqual(await fsp.readFile(stage), foreign,
    "the originally competing staged-head bytes must stay untouched");
  const inertTemps = (await fsp.readdir(path.dirname(stage))).filter((name) =>
    name.startsWith(".rootark-eviction-genesis-head.json.tmp-"));
  assert.equal(inertTemps.length, 1,
    "failure must preserve the unlinked temp for safe independent review, not unlink an uncertain pathname");
  assert.equal((await fsp.stat(path.join(path.dirname(stage), inertTemps[0]))).nlink, 1);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  verifyNoSignedDelete(f, before);
});

test("issue 66: hard exit after exclusive genesis stage link leaves ambiguous names fail-closed", {
  skip: !["linux", "win32"].includes(process.platform)
    && "requires actual Linux ext4 or Windows NTFS linked staging",
}, async (t) => {
  const f = await fixture(t, "genesis-stage-double-link-crash");
  const childSource = String.raw`
"use strict";
const fsp = require("node:fs/promises");
const path = require("node:path");
const { SyncEngine } = require(process.argv[1]);
const { SyncObjectStore } = require(process.argv[2]);
const originalLink = fsp.link;
fsp.link = async (...args) => {
  const result = await originalLink(...args);
  if (path.basename(String(args[0])).startsWith(".rootark-eviction-genesis-head.json.tmp-")
    && path.basename(String(args[1])) === ".rootark-eviction-genesis-head.json") {
    process.exit(74); // genuine hard exit after first link, before temp unlink
  }
  return result;
};
(async () => {
  const store = await new SyncObjectStore(process.argv[4]).open();
  const sync = await new SyncEngine({
    rootDir: process.argv[3],
    adapter: {
      async list(objectId = "") { return store.list("alice", objectId || null); },
      async push() { process.exit(94); },
    },
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    excludedPaths: ["private"], fileKeyResolver: () => Buffer.from(process.argv[5], "base64"),
  }).open();
  await sync.syncOnce();
  process.exit(92);
})().catch((error) => {
  process.stderr.write(String(error?.message ?? error));
  process.exit(93);
});
`;
  const child = spawn(process.execPath, [
    "-e", childSource, require.resolve("../sync-client/rootark-sync-engine"),
    require.resolve("../src/routes/sync"), f.root, f.storePath, f.key.toString("base64"),
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let err = "";
  child.stderr.on("data", (bytes) => { err += bytes.toString(); });
  const exit = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill(); reject(new Error("stage link hard-exit child timeout"));
    }, 30000);
    child.once("exit", (code) => { clearTimeout(timeout); resolve(code); });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
  });
  assert.equal(exit, 74, `real child must exit exactly after staging link: ${err}`);
  const trash = path.join(f.root, ".rootark-trash");
  const stage = path.join(trash, ".rootark-eviction-genesis-head.json");
  const temps = (await fsp.readdir(trash)).filter((name) =>
    name.startsWith(".rootark-eviction-genesis-head.json.tmp-"));
  assert.equal(temps.length, 1, "post-link hard crash must retain a unique temp name");
  const temp = path.join(trash, temps[0]);
  assert.deepEqual(await fsp.readFile(stage), await fsp.readFile(temp));
  assert.equal((await fsp.stat(stage)).nlink, 2);
  assert.equal((await fsp.stat(temp)).nlink, 2);
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).version, 1,
    "a crash during genesis stage must not silently upgrade the durable snapshot");
  // This lock belongs exclusively to the dead disposable fixture process.
  await fsp.rmdir(path.join(f.root, ".rootark-sync.lock"));
  const before = f.outbound.length;
  const reopened = await f.create(f.root, ["private"]);
  await assert.rejects(reopened.syncOnce(), (error) =>
    error?.code === "invalid_snapshot" && /Unreadable staged eviction genesis head/.test(error.message));
  assert.deepEqual(await fsp.readFile(stage), await fsp.readFile(temp),
    "a refused restart must preserve both original stage names");
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  verifyNoSignedDelete(f, before);
});

test("issue 66: Linux genesis promotion cannot overwrite a foreign ledger head", {
  skip: process.platform !== "linux" && "Linux held ledger descriptor required",
}, async (t) => {
  const f = await fixture(t, "genesis-promotion-foreign-write");
  const parked = path.join(f.root, ".rootark-sync-evictions-parked");
  const foreign = path.join(f.dir, "foreign-ledger-promotion");
  await fsp.mkdir(foreign);
  await fsp.writeFile(path.join(foreign, "head.json"), "FOREIGN_HEAD_STAYS");
  const originalRename = fsp.rename;
  const originalLink = fsp.link;
  let substituted = false;
  const inject = async (source, destination) => {
    if (!substituted && path.basename(String(source)) === ".rootark-eviction-genesis-head.json"
      && path.basename(String(destination)) === "head.json") {
      substituted = true;
      await originalRename(f.ledger, parked);
      await fsp.symlink(foreign, f.ledger, "dir");
    }
  };
  fsp.rename = async (source, destination, ...args) => {
    await inject(source, destination);
    return originalRename(source, destination, ...args);
  };
  fsp.link = async (source, destination, ...args) => {
    await inject(source, destination);
    return originalLink(source, destination, ...args);
  };
  const sync = await f.create(f.root, ["private"]);
  const before = f.outbound.length;
  let failure;
  try { await sync.syncOnce(); } catch (error) { failure = error; }
  finally {
    fsp.rename = originalRename;
    fsp.link = originalLink;
    if (substituted) {
      await fsp.unlink(f.ledger);
      await fsp.rename(parked, f.ledger);
    }
  }
  assert.equal(substituted, true, "the real genesis promotion boundary must be reached");
  assert.equal(await fsp.readFile(path.join(foreign, "head.json"), "utf8"),
    "FOREIGN_HEAD_STAYS", "a competing foreign head must never be overwritten");
  assert.equal(failure?.code, "invalid_snapshot",
    "an adversarial head publication must fail with an explicit snapshot-denial error");
  assert.match(failure.message, /Genesis publication parent changed/);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  verifyNoSignedDelete(f, before);
});

test("issue 66: crash after exclusive genesis link but before retiring stage fails closed", {
  skip: !["linux", "win32"].includes(process.platform)
    && "Windows NTFS or Linux ext4 exclusive genesis publication and hard crash",
}, async (t) => {
  const f = await fixture(t, "genesis-linked-before-unlink-crash");
  const childSource = String.raw`
"use strict";
const fsp = require("node:fs/promises");
const path = require("node:path");
const { SyncEngine } = require(process.argv[1]);
const { SyncObjectStore } = require(process.argv[2]);
const originalLink = fsp.link;
fsp.link = async (...args) => {
  const result = await originalLink(...args);
  if (path.basename(String(args[0])) === ".rootark-eviction-genesis-head.json"
    && path.basename(String(args[1])) === "head.json") process.exit(75);
  return result;
};
(async () => {
  const store = await new SyncObjectStore(process.argv[4]).open();
  const sync = await new SyncEngine({
    rootDir: process.argv[3],
    adapter: {
      async list(objectId = "") { return store.list("alice", objectId || null); },
      async push() { process.exit(94); },
    },
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    excludedPaths: ["private"], fileKeyResolver: () => Buffer.from(process.argv[5], "base64"),
  }).open();
  await sync.syncOnce();
  process.exit(92);
})().catch(() => process.exit(93));
`;
  const child = spawn(process.execPath, [
    "-e", childSource, require.resolve("../sync-client/rootark-sync-engine"),
    require.resolve("../src/routes/sync"), f.root, f.storePath, f.key.toString("base64"),
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let err = "";
  child.stderr.on("data", (bytes) => { err += bytes.toString(); });
  const exit = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { child.kill(); reject(new Error("genesis link crash child timed out")); }, 30000);
    child.once("exit", (code) => { clearTimeout(timeout); resolve(code); });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
  });
  assert.equal(exit, 75, `must crash after the exact exclusive publication link, got ${exit}: ${err}`);
  const staged = path.join(f.root, ".rootark-trash", ".rootark-eviction-genesis-head.json");
  const active = path.join(f.ledger, "head.json");
  assert.deepEqual(await fsp.readFile(active), await fsp.readFile(staged),
    "a crash leaves identical linked bytes, not an authorized committed recovery");
  assert.equal((await fsp.stat(active)).nlink, 2, "proof must use the actual same-inode linked stage");
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  await fsp.rmdir(path.join(f.root, ".rootark-sync.lock"));
  const before = f.outbound.length;
  await assert.rejects(f.create(f.root, ["private"]), { code: "invalid_snapshot" });
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  verifyNoSignedDelete(f, before);
});

test("issue 66: exclusive Linux genesis publication never overwrites a competing head", {
  skip: process.platform !== "linux" && "Linux exclusive hard-link publication",
}, async (t) => {
  const f = await fixture(t, "genesis-competing-head");
  const headPath = path.join(f.ledger, "head.json");
  const originalLink = fsp.link;
  let injected = false;
  fsp.link = async (source, destination, ...args) => {
    if (!injected && path.basename(String(source)) === ".rootark-eviction-genesis-head.json"
      && path.basename(String(destination)) === "head.json") {
      injected = true;
      await fsp.writeFile(headPath, "FOREIGN_HEAD_NO_REPLACE", { flag: "wx" });
    }
    return originalLink(source, destination, ...args);
  };
  const sync = await f.create(f.root, ["private"]);
  const before = f.outbound.length;
  try {
    await assert.rejects(sync.syncOnce(), (error) =>
      error?.code === "invalid_snapshot"
        && /Existing genesis head blocks exclusive publication/.test(error.message));
  } finally { fsp.link = originalLink; }
  assert.equal(injected, true);
  assert.equal(await fsp.readFile(headPath, "utf8"), "FOREIGN_HEAD_NO_REPLACE");
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  verifyNoSignedDelete(f, before);
});

test("issue 66: Windows NTFS genesis publication cannot overwrite a competing head", {
  skip: process.platform !== "win32" && "Windows NTFS exclusive genesis head publication",
}, async (t) => {
  const f = await fixture(t, "windows-competing-genesis-head");
  const headPath = path.join(f.ledger, "head.json");
  const originalRename = fsp.rename;
  const originalLink = fsp.link;
  let injected = false;
  let foreignHeadOverwritten = false;
  const inject = async (source, destination) => {
    if (!injected && path.basename(String(source)) === ".rootark-eviction-genesis-head.json"
      && path.basename(String(destination)) === "head.json") {
      injected = true;
      await fsp.writeFile(headPath, "FOREIGN_HEAD_MUST_NOT_CHANGE", { flag: "wx" });
    }
  };
  fsp.rename = async (source, destination, ...args) => {
    await inject(source, destination);
    const result = await originalRename(source, destination, ...args);
    if (path.basename(String(source)) === ".rootark-eviction-genesis-head.json"
      && path.basename(String(destination)) === "head.json") {
      foreignHeadOverwritten = (await fsp.readFile(headPath, "utf8"))
        !== "FOREIGN_HEAD_MUST_NOT_CHANGE";
    }
    return result;
  };
  fsp.link = async (source, destination, ...args) => {
    await inject(source, destination);
    return originalLink(source, destination, ...args);
  };
  const sync = await f.create(f.root, ["private"]);
  const before = f.outbound.length;
  let failure;
  try { await sync.syncOnce(); } catch (error) { failure = error; }
  finally {
    fsp.rename = originalRename;
    fsp.link = originalLink;
  }
  assert.equal(injected, true, "must reach the real genesis head publication syscall");
  assert.equal(foreignHeadOverwritten, false,
    "no publication syscall may overwrite the competing head, even if later cleanup removes it");
  assert.equal(await fsp.readFile(headPath, "utf8"), "FOREIGN_HEAD_MUST_NOT_CHANGE",
    "Windows must not overwrite a competing head with an untrusted rename");
  assert.equal(failure?.code, "invalid_snapshot",
    "an existing head must deny publication instead of completing the eviction");
  assert.match(failure.message, /Existing genesis head blocks exclusive publication/);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  verifyNoSignedDelete(f, before);
});

test("issue 66: Windows staged genesis publication reads bounded bytes from a held file, not readFile", {
  skip: process.platform !== "win32" && "Windows NTFS staged-head held read",
}, async (t) => {
  const f = await fixture(t, "windows-held-stage-read");
  const originalReadFile = fsp.readFile;
  let unboundedCalls = 0;
  fsp.readFile = async (filePath, ...args) => {
    if (path.basename(String(filePath)) === ".rootark-eviction-genesis-head.json") {
      unboundedCalls++;
      throw Object.assign(new Error("unbounded staged genesis read forbidden"), { code: "EMSGSIZE" });
    }
    return originalReadFile(filePath, ...args);
  };
  const sync = await f.create(f.root, ["private"]);
  const before = f.outbound.length;
  let report;
  try { report = await sync.syncOnce(); }
  finally { fsp.readFile = originalReadFile; }
  assert.equal(unboundedCalls, 0, "publication must keep and read a bounded file descriptor");
  assert.equal(report.excluded.evicted, 1, "legitimate Windows genesis still commits");
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, false);
  verifyNoSignedDelete(f, before);
});

test("issue 66: Windows staged genesis growth before held open denies publication", {
  skip: process.platform !== "win32" && "Windows NTFS held staged-head growth regression",
}, async (t) => {
  const f = await fixture(t, "windows-stage-grows-before-held-open");
  const originalOpen = fsp.open;
  let grown = false;
  fsp.open = async (requested, ...args) => {
    if (!grown && path.basename(String(requested))
      === ".rootark-eviction-genesis-head.json") {
      grown = true;
      // The actual NTFS staged file changes after the pathname size
      // precheck but before acquiring the descriptor used for publication.
      await fsp.appendFile(String(requested), Buffer.alloc(8193));
    }
    return originalOpen(requested, ...args);
  };
  const sync = await f.create(f.root, ["private"]);
  const before = f.outbound.length;
  let failure;
  try { await sync.syncOnce(); } catch (error) { failure = error; }
  finally { fsp.open = originalOpen; }
  assert.equal(grown, true, "the real staged-head descriptor acquisition must be exercised");
  assert.equal(failure?.code, "invalid_snapshot");
  assert.match(failure.message, /Staged genesis changed before publication/);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  verifyNoSignedDelete(f, before);
});

test("issue 66: replaced Linux staged genesis leaf cannot become an authorized active head", {
  skip: process.platform !== "linux" && "Linux nofollow staged-head publication",
}, async (t) => {
  const f = await fixture(t, "genesis-stage-leaf-symlink");
  const foreign = path.join(f.dir, "foreign-genesis-data");
  await fsp.writeFile(foreign, "FOREIGN_BYTES_MUST_STAY");
  const originalLink = fsp.link;
  let injected = false;
  fsp.link = async (source, destination, ...args) => {
    if (!injected && path.basename(String(source)) === ".rootark-eviction-genesis-head.json"
      && path.basename(String(destination)) === "head.json") {
      injected = true;
      await fsp.rename(source, `${source}.parked`);
      await fsp.symlink(foreign, source);
    }
    return originalLink(source, destination, ...args);
  };
  const sync = await f.create(f.root, ["private"]);
  const before = f.outbound.length;
  try {
    await assert.rejects(sync.syncOnce(), (error) =>
      error?.code === "invalid_snapshot"
        && /Indeterminate exclusive genesis publication/.test(error.message));
  } finally { fsp.link = originalLink; }
  assert.equal(injected, true);
  assert.equal(await fsp.readFile(foreign, "utf8"), "FOREIGN_BYTES_MUST_STAY");
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  verifyNoSignedDelete(f, before);
});

test("issue 66: genesis promotion must not unlink a substituted stage after exclusive link", {
  skip: !["linux", "win32"].includes(process.platform)
    && "requires original-byte Linux ext4 or Windows NTFS stage substitution",
}, async (t) => {
  const f = await fixture(t, "genesis-post-link-stage-swap");
  const stage = path.join(f.root, ".rootark-trash", ".rootark-eviction-genesis-head.json");
  const parked = path.join(f.root, ".original-genesis-stage-parked");
  const foreignSaved = path.join(f.dir, "foreign-genesis-stage-preserved");
  const foreign = Buffer.from("FOREIGN_POST_LINK_STAGE_MUST_SURVIVE");
  const originalLink = fsp.link;
  const originalLstat = fsp.lstat;
  const originalRename = fsp.rename;
  const originalUnlink = fsp.unlink;
  let linked = false;
  let swapped = false;
  let attemptedForeignUnlink = false;
  fsp.link = async (source, destination, ...args) => {
    const result = await originalLink(source, destination, ...args);
    if (path.basename(String(source)) === ".rootark-eviction-genesis-head.json"
      && path.basename(String(destination)) === "head.json") {
      linked = true;
    }
    return result;
  };
  fsp.lstat = async (requested, ...args) => {
    const stat = await originalLstat(requested, ...args);
    if (linked && !swapped && (
      process.platform === "linux"
        ? path.resolve(String(requested)) === path.resolve(f.root)
        : path.resolve(String(requested)) === path.resolve(stage)
    )) {
      // Swap the true staged entry AFTER the previous identity inspection
      // and AFTER publication, before the real final unlink boundary.
      await originalRename(stage, parked);
      await fsp.writeFile(stage, foreign, { flag: "wx" });
      swapped = true;
    }
    return stat;
  };
  fsp.unlink = async (requested, ...args) => {
    if (swapped && path.basename(String(requested)) === path.basename(stage)) {
      const parent = await fsp.realpath(path.dirname(String(requested)));
      const expected = await fsp.realpath(path.dirname(stage));
      if (path.resolve(parent) === path.resolve(expected)) {
        attemptedForeignUnlink = true;
        throw Object.assign(new Error("foreign staged unlink intercepted"), { code: "EACCES" });
      }
    }
    return originalUnlink(requested, ...args);
  };
  const sync = await f.create(f.root, ["private"]);
  const before = f.outbound.length;
  let failure;
  try { await sync.syncOnce(); } catch (error) { failure = error; }
  finally {
    fsp.link = originalLink;
    fsp.lstat = originalLstat;
    fsp.unlink = originalUnlink;
    if (swapped) {
      await originalRename(stage, foreignSaved);
      await originalRename(parked, stage);
    }
  }
  assert.equal(linked, true, "real genesis publication must create the exclusive head link");
  assert.equal(swapped, true, "real physical stage substitution must run after link");
  assert.equal(attemptedForeignUnlink, false,
    "no final stage unlink may target a file substituted after publication");
  assert.equal(failure?.code, "invalid_snapshot");
  assert.match(failure.message, /Staged genesis changed before final unlink/);
  assert.deepEqual(await fsp.readFile(foreignSaved), foreign);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  verifyNoSignedDelete(f, before);
});

function verifyNoSignedDelete(f, from = 0) {
  assert.equal(f.outbound.slice(from).filter((entry) => entry.operation === "delete" || entry.tombstone).length,
    0, "an uncertain ledger must never authorize a signed DELETE");
  assert.equal(f.store.list("alice").filter((entry) => entry.tombstone).length,
    0, "the real protected server has no signed tombstones");
  const row = f.store.list("alice", f.signed.objectId)[0];
  assert.equal(row.operationId, f.signed.operationId);
  assert.equal(row.tombstone, false);
}

async function prePrepareCrash(f, crashBeforeSnapshot = false,
  crashBeforePromotion = false, crashBeforeGenesis = false) {
  // Hard exit in a separate Node22 process either after durable genesis but
  // before the required checkpoint, or after that checkpoint before PREPARE.
  const childSource = String.raw`
"use strict";
const fsp = require("node:fs/promises");
const path = require("node:path");
const { SyncEngine } = require(process.argv[1]);
const { SyncObjectStore } = require(process.argv[2]);
const root = process.argv[3], storePath = process.argv[4];
const key = Buffer.from(process.argv[5], "base64");
const originalOpen = fsp.open;
fsp.open = async (...args) => {
  if (String(args[0]).endsWith(".prepare.json")) {
    process.exit(79);
  }
  return originalOpen(...args);
};
const originalRename = fsp.rename;
fsp.rename = async (...args) => {
  if (process.argv[6] === "before-genesis"
    && path.basename(String(args[1])) === ".rootark-eviction-genesis-head.json"
    && path.basename(String(args[0])).startsWith(".rootark-eviction-genesis-head.json.tmp-")) {
    process.exit(76);
  }
  if (process.argv[6] === "genesis-only"
    && path.resolve(args[1]) === path.join(root, ".rootark-sync-index.json")) {
    process.exit(78);
  }
  if (process.argv[6] === "before-promotion"
    && path.resolve(args[1]) === path.join(root, ".rootark-sync-evictions", "head.json")) {
    process.exit(77);
  }
  return originalRename(...args);
};
const originalLink = fsp.link;
fsp.link = async (...args) => {
  if (process.argv[6] === "before-genesis"
    && path.basename(String(args[1])) === ".rootark-eviction-genesis-head.json"
    && path.basename(String(args[0])).startsWith(".rootark-eviction-genesis-head.json.tmp-")) {
    // With exclusive stage publication this is the syscall BEFORE the
    // reserved stage name appears. Crash here must keep the v1 fence.
    process.exit(76);
  }
  if (process.argv[6] === "before-promotion"
    && path.basename(String(args[0])) === ".rootark-eviction-genesis-head.json"
    && path.basename(String(args[1])) === "head.json") {
    process.exit(77);
  }
  return originalLink(...args);
};
(async () => {
  const store = await new SyncObjectStore(storePath).open();
  const adapter = {
    async list(objectId = "") { return store.list("alice", objectId || null); },
    async push() { process.exit(94); },
  };
  const sync = await new SyncEngine({ rootDir: root, adapter, deviceId: "device-b",
    keyEpoch: "epoch-1", compartmentId: "private",
    excludedPaths: ["private"], fileKeyResolver: () => key }).open();
  await sync.syncOnce();
  process.exit(92);
})().catch(() => process.exit(93));
`;
  const child = spawn(process.execPath, [
    "-e", childSource,
    require.resolve("../sync-client/rootark-sync-engine"),
    require.resolve("../src/routes/sync"),
    f.root, f.storePath, f.key.toString("base64"),
    crashBeforeGenesis ? "before-genesis" : crashBeforeSnapshot ? "genesis-only"
      : crashBeforePromotion ? "before-promotion" : "after-checkpoint",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let err = "";
  child.stderr.on("data", (data) => { err += data.toString(); });
  const exit = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { child.kill(); reject(new Error("crash interval child timed out")); }, 30000);
    child.once("exit", (code) => { clearTimeout(timeout); resolve(code); });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
  });
  assert.equal(exit, crashBeforeGenesis ? 76 : crashBeforeSnapshot ? 78
    : crashBeforePromotion ? 77 : 79,
    `child must hard-exit at its verified checkpoint boundary, got ${exit}: ${err}`);
  const disk = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(disk.version, crashBeforeSnapshot || crashBeforeGenesis ? 1 : 2);
  assert.equal(disk.evictionLedgerRequired, crashBeforeSnapshot || crashBeforeGenesis
    ? undefined : true);
  assert.ok(disk.files["PRIVATE/secret.txt"]);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  if (crashBeforeGenesis) {
    await assert.rejects(fsp.lstat(f.ledger), { code: "ENOENT" });
    await assert.rejects(fsp.lstat(path.join(f.root, ".rootark-trash",
      ".rootark-eviction-genesis-head.json")), { code: "ENOENT" });
    await fsp.rmdir(path.join(f.root, ".rootark-sync.lock"));
    return;
  }
  let headFile;
  if (crashBeforeSnapshot || crashBeforePromotion) {
    if (crashBeforeSnapshot) await assert.rejects(fsp.lstat(f.ledger), { code: "ENOENT" });
    else assert.deepEqual(await fsp.readdir(f.ledger), []);
    const trash = path.join(f.root, ".rootark-trash");
    headFile = path.join(trash, ".rootark-eviction-genesis-head.json");
    assert.ok((await fsp.readdir(trash)).includes(".rootark-eviction-genesis-head.json"),
      "pre-v2 genesis must stay hidden from v1 clients");
  } else {
    assert.deepEqual(await fsp.readdir(f.ledger), ["head.json"]);
    headFile = path.join(f.ledger, "head.json");
  }
  const head = JSON.parse(await fsp.readFile(headFile, "utf8"));
  assert.equal(head.sequence, 0);
  assert.equal(head.digest, "0".repeat(64));
  if (!crashBeforeSnapshot) assert.equal(head.epoch, disk.evictionLedgerEpoch);
  // Exclusively the disposable test root's orphaned process marker is removed.
  await fsp.rmdir(path.join(f.root, ".rootark-sync.lock"));
}

test("issue 66 P2: real process crash after durable genesis and required-v2 fsync recovers exact clean files", async (t) => {
  const f = await fixture(t, "after-checkpoint");
  await prePrepareCrash(f);
  const before = f.outbound.length;
  const restarted = await f.create(f.root, []);
  assert.equal(restarted.snapshot.evictionLedgerRequired, false,
    "recovery must durably retire a provably PREPARE-less required marker");
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, false);
  await restarted.syncOnce();
  verifyNoSignedDelete(f, before);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
});

test("issue 66 P2: post-crash recovery verifies excluded physical bytes with unchanged exclusion policy", async (t) => {
  const f = await fixture(t, "same-exclusions");
  await prePrepareCrash(f);
  const before = f.outbound.length;
  const restored = await f.create(f.root, ["private"]);
  assert.equal(restored.snapshot.evictionLedgerRequired, false);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  await restored.syncOnce();
  verifyNoSignedDelete(f, before);
});

test("issue 66 P2: recovery physical proof ignores selectedPaths restrictions and excludes", async (t) => {
  const f = await fixture(t, "restricted-scope", true);
  await prePrepareCrash(f);
  const before = f.outbound.length;
  const restored = await f.create(f.root, ["private"], { selectedPaths: ["unrelated"] });
  assert.equal(restored.snapshot.evictionLedgerRequired, false);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
  assert.equal(await fsp.readFile(path.join(f.root, "PRIVATE", "second.txt"), "utf8"),
    "second authenticated server file");
  await restored.syncOnce();
  verifyNoSignedDelete(f, before);
});

test("issue 66 P2: same exclusions cannot conceal missing, altered or casefold-aliased tracked bytes", async (t) => {
  for (const mutation of ["missing", "dirty", "casefold"]) {
    if (mutation === "casefold" && process.platform === "win32") continue;
    const f = await fixture(t, `policy-negative-${mutation}`);
    await prePrepareCrash(f);
    if (mutation === "missing") await fsp.unlink(f.local);
    if (mutation === "dirty") await fsp.writeFile(f.local, "new unsigned content");
    if (mutation === "casefold") {
      await fsp.rename(f.local, path.join(f.root, "PRIVATE", "SECRET.txt"));
    }
    const before = f.outbound.length;
    await assert.rejects(f.create(f.root, ["private"], { selectedPaths: ["other"] }),
      { code: "invalid_snapshot" });
    verifyNoSignedDelete(f, before);
    assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  }
});

test("issue 66 P2: untracked content within an excluded directory cannot pass recovery proof", async (t) => {
  const f = await fixture(t, "untracked-inside-excluded");
  await prePrepareCrash(f);
  await fsp.writeFile(path.join(f.root, "PRIVATE", "unexpected.txt"), "untracked excluded content");
  const before = f.outbound.length;
  await assert.rejects(f.create(f.root, ["private"], { selectedPaths: ["other"] }),
    { code: "invalid_snapshot" });
  verifyNoSignedDelete(f, before);
});

test("issue 66 P2 POSIX: excluded symlink and duplicate casefold names cannot attest clean recovery", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX symlink and duplicate-case physical paths");
  for (const mutation of ["tracked-symlink", "untracked-symlink", "duplicate-case"]) {
    const f = await fixture(t, `unsafe-physical-${mutation}`);
    await prePrepareCrash(f);
    if (mutation === "tracked-symlink") {
      const outside = path.join(f.dir, "outside.txt");
      await fsp.writeFile(outside, "authenticated server file");
      await fsp.unlink(f.local);
      await fsp.symlink(outside, f.local);
    }
    if (mutation === "untracked-symlink") {
      await fsp.symlink(f.local, path.join(f.root, "PRIVATE", "untracked-link.txt"));
    }
    if (mutation === "duplicate-case") {
      await fsp.writeFile(path.join(f.root, "PRIVATE", "SECRET.txt"), "authenticated server file");
    }
    const before = f.outbound.length;
    await assert.rejects(f.create(f.root, ["private"], { selectedPaths: ["unrelated"] }),
      { code: "invalid_snapshot" });
    verifyNoSignedDelete(f, before);
    assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  }
});

test("issue 66 P2: crash after fsynced genesis but before v2 checkpoint leaves usable v1", async (t) => {
  const f = await fixture(t, "orphan-before-v2");
  await prePrepareCrash(f, true);
  const before = f.outbound.length;
  const restarted = await f.create(f.root, ["private"]);
  assert.equal(restarted.snapshot.version, 1, "an orphan genesis must not downgrade or forge a v2 checkpoint");
  const result = await restarted.syncOnce();
  assert.equal(result.excluded.evicted, 1);
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, false);
  verifyNoSignedDelete(f, before);
});

test("issue 66 P2: crash while atomically staging genesis leaves only v1-internal temporary bytes", async (t) => {
  const f = await fixture(t, "before-atomic-genesis");
  await prePrepareCrash(f, false, false, true);
  const before = f.outbound.length;
  const recovered = await f.create(f.root, ["private"]);
  const result = await recovered.syncOnce();
  assert.equal(result.excluded.evicted, 1);
  verifyNoSignedDelete(f, before);
});

test("issue 66 P2: crash after v2 fsync but before hidden genesis promotion recovers clean bytes", async (t) => {
  const f = await fixture(t, "between-checkpoint-promotion");
  await prePrepareCrash(f, false, true);
  const before = f.outbound.length;
  const restored = await f.create(f.root, []);
  assert.equal(restored.snapshot.evictionLedgerRequired, false);
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, false);
  await restored.syncOnce();
  verifyNoSignedDelete(f, before);
});

test("issue 66 P2: required v2 refuses missing or mismatched genesis even if every tracked file is clean", async (t) => {
  for (const mutation of ["missing-head", "wrong-epoch", "missing-ledger"]) {
    const f = await fixture(t, `lost-genesis-${mutation}`);
    await prePrepareCrash(f);
    if (mutation === "missing-head") await fsp.unlink(path.join(f.ledger, "head.json"));
    if (mutation === "missing-ledger") await fsp.rm(f.ledger, { recursive: true });
    if (mutation === "wrong-epoch") {
      await fsp.writeFile(path.join(f.ledger, "head.json"),
        JSON.stringify({ epoch: crypto.randomUUID(), sequence: 0, digest: "0".repeat(64) }));
    }
    const before = f.outbound.length;
    await assert.rejects(f.create(f.root, []), { code: "invalid_snapshot" });
    verifyNoSignedDelete(f, before);
    assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  }
});

test("issue 66 P2: missing or altered tracked bytes fail closed when the active ledger vanished", async (t) => {
  for (const mutation of ["missing", "dirty", "different-file"]) {
    const f = await fixture(t, `negative-${mutation}`);
    await prePrepareCrash(f);
    if (mutation === "missing") await fsp.unlink(f.local);
    if (mutation === "dirty") await fsp.writeFile(f.local, "unapproved local changes");
    if (mutation === "different-file") {
      await fsp.unlink(f.local);
      await fsp.writeFile(f.local, "unapproved replacement");
    }
    const before = f.outbound.length;
    await assert.rejects(f.create(f.root, []), { code: "invalid_snapshot" });
    verifyNoSignedDelete(f, before);
    assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  }
});

test("issue 66 P2: every tracked physical file must pass the hash proof, not only the first candidate", async (t) => {
  const f = await fixture(t, "second-file-missing", true);
  await prePrepareCrash(f);
  const disk = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.ok(disk.files["PRIVATE/secret.txt"]);
  assert.ok(disk.files["PRIVATE/second.txt"]);
  await fsp.unlink(path.join(f.root, "PRIVATE", "second.txt"));
  const before = f.outbound.length;
  await assert.rejects(f.create(f.root, []), { code: "invalid_snapshot" });
  verifyNoSignedDelete(f, before);
  assert.equal(await fsp.readFile(f.local, "utf8"), "authenticated server file");
});

test("issue 66 P2: a forged empty genesis cannot replace a lost post-PREPARE staged ledger", async (t) => {
  const f = await fixture(t, "forged-empty-after-real-stage");
  const sync = await f.create(f.root, ["private"]);
  const originalStage = sync.stageExisting.bind(sync);
  sync.stageExisting = async (target) => {
    await originalStage(target);
    throw Object.assign(new Error("EIO after physical stage"), { code: "EIO" });
  };
  await assert.rejects(sync.syncOnce(), { code: "eviction_restore_failed" });
  await assert.rejects(fsp.lstat(f.local), { code: "ENOENT" });
  const disk = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
  assert.equal(disk.evictionLedgerRequired, true);
  assert.ok((await fsp.readdir(f.ledger)).some((name) => name.endsWith(".prepare.json")));
  await fsp.rm(f.ledger, { recursive: true });
  await fsp.mkdir(f.ledger);
  await fsp.writeFile(path.join(f.ledger, "head.json"), JSON.stringify({
    epoch: disk.evictionLedgerEpoch, sequence: 0, digest: "0".repeat(64),
  }));
  const before = f.outbound.length;
  await assert.rejects(f.create(f.root, []), { code: "invalid_snapshot" });
  verifyNoSignedDelete(f, before);
});

test("issue 66 P2: empty ledger recovery refuses unexpected local content and partial head/records", async (t) => {
  for (const mutation of ["untracked", "head", "torn-prepare", "orphan-commit"]) {
    const f = await fixture(t, `partial-${mutation}`);
    await prePrepareCrash(f);
    if (mutation === "untracked") await fsp.writeFile(path.join(f.root, "other.txt"), "untracked");
    if (mutation === "head") {
      const disk = JSON.parse(await fsp.readFile(f.snapshot, "utf8"));
      await fsp.writeFile(path.join(f.ledger, "head.json"), JSON.stringify({
        epoch: disk.evictionLedgerEpoch, sequence: 1, digest: "0".repeat(64),
      }));
    }
    if (mutation === "torn-prepare" || mutation === "orphan-commit") {
      const name = crypto.createHash("sha256").update("fixture").digest("hex");
      await fsp.writeFile(path.join(f.ledger,
        `${name}.${mutation === "torn-prepare" ? "prepare" : "commit"}.json`), "{incomplete");
    }
    const before = f.outbound.length;
    await assert.rejects(f.create(f.root, []), { code: "invalid_snapshot" });
    verifyNoSignedDelete(f, before);
  }
});

test("issue 66 P2 POSIX: portable casefold alias is not proof of retained tracked bytes", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX independent physical case aliases");
  const f = await fixture(t, "alias");
  await prePrepareCrash(f);
  await fsp.writeFile(path.join(f.root, "PRIVATE", "SECRET.txt"), "authenticated server file");
  const before = f.outbound.length;
  await assert.rejects(f.create(f.root, []), { code: "invalid_snapshot" });
  verifyNoSignedDelete(f, before);
});

test("issue 66 P2: failed durability of the empty-ledger recovery retains the required marker", async (t) => {
  const f = await fixture(t, "recovery-EIO");
  await prePrepareCrash(f);
  const originalRename = fsp.rename;
  let rejected = false;
  fsp.rename = async (source, destination) => {
    if (destination === f.snapshot && source.startsWith(`${f.snapshot}.tmp-`)) {
      rejected = true;
      throw Object.assign(new Error("injected recovery checkpoint EIO"), { code: "EIO" });
    }
    return originalRename(source, destination);
  };
  try { await assert.rejects(f.create(f.root, []), { code: "EIO" }); }
  finally { fsp.rename = originalRename; }
  assert.equal(rejected, true);
  assert.equal((JSON.parse(await fsp.readFile(f.snapshot, "utf8"))).evictionLedgerRequired, true);
  const before = f.outbound.length;
  const recovered = await f.create(f.root, []);
  assert.equal(recovered.snapshot.evictionLedgerRequired, false);
  await recovered.syncOnce();
  verifyNoSignedDelete(f, before);
});
