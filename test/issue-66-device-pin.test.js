"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");

async function fixture(t) {
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-device-pin-"));
  t.after(() => fsp.rm(tmp, { recursive: true, force: true }));
  const rootDir = path.join(tmp, "device");
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trusted = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] };
  const state = { offline: false, fullReads: [], inventoryReads: 0, pushes: 0, records: new Map() };
  async function remote(kind, objectId, relative, plaintext, counter = 1, sourcePath, contentType) {
    const previous = state.records.get(objectId);
    const op = protocol.createOperation({
      operation: kind, objectId, fileId: previous?.fileId || `file-${objectId}`,
      versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter, deviceId: "device-a" },
      baseRevision: counter === 1 ? null : previous.revision,
      metadata: { path: relative, ...(sourcePath ? { sourcePath } : {}),
        ...(contentType ? { contentType } : {}) },
      plaintext: kind === "move" ? protocol.encodeMovePayload(Buffer.from(plaintext), key)
        : Buffer.from(plaintext), fileKey: key,
    });
    op.authorization = await createAuthorizationProof(op, {
      username: "alice", privateKey: signer.privateKey, publicKey, expiresAt: Date.now() + 60_000,
    });
    state.records.set(objectId, op);
    return op;
  }
  await remote("create", "object-a", "docs/a.txt", "authenticated remote bytes");
  const adapter = {
    async listInventory() {
      if (state.offline) throw Object.assign(new Error("offline"), { code: "offline" });
      state.inventoryReads++;
      return { protocolVersion: 2, view: "metadata", objects: [...state.records.values()]
        .map(({ authorization, ciphertext, nonce, tag, aad, ...item }) => item), nextCursor: null };
    },
    async list(objectId) {
      if (state.offline) throw Object.assign(new Error("offline"), { code: "offline" });
      state.fullReads.push(objectId);
      return [...state.records.values()].filter((op) => op.objectId === objectId);
    },
    async push(operation) {
      state.pushes++;
      throw Object.assign(new Error("outgoing push forbidden in pin fixture"), { code: "push_unexpected" });
    },
  };
  const open = (excludedPaths = [], requireAuthorization = true, filesOnDemand = true,
    selectedPaths = ["docs"]) => new SyncEngine({
    rootDir, adapter, deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", selectedPaths, excludedPaths, filesOnDemand,
    fileKeyResolver: () => key, requireAuthorization,
    verifyIncoming: requireAuthorization
      ? async (operation) => verifyAuthorizationProof(operation.authorization, operation, trusted) : null,
    authorizationFactory: (operation) => createAuthorizationProof(operation, {
      username: "alice", privateKey: signer.privateKey, publicKey, expiresAt: Date.now() + 60_000,
    }),
  }).open();
  return { rootDir, open, adapter, state, remote };
}

test("issue 66: pin hydrates signed file, survives restart/offline and blocks explicit eviction; unpin retains bytes", async (t) => {
  const { rootDir, open, state } = await fixture(t);
  const engine = await open();
  assert.deepEqual(await engine.pinStatus("docs/a.txt"), {
    path: "docs/a.txt", pinned: false, localPresent: false, objectId: null,
  });
  assert.equal((await engine.pinLocal("docs/a.txt")).pinned, true);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  assert.deepEqual(state.fullReads, ["object-a"]);
  state.offline = true;
  const restarted = await open();
  const inventoryReads = state.inventoryReads;
  assert.deepEqual(await restarted.pinStatus("docs/a.txt"), {
    path: "docs/a.txt", pinned: true, localPresent: true, objectId: "object-a",
  });
  assert.equal(state.inventoryReads, inventoryReads, "local pin status must work without a network call");
  await assert.rejects(restarted.evictLocal("docs/a.txt"), { code: "file_pinned" });
  assert.equal((await restarted.unpinLocal("docs/a.txt")).pinned, false);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  state.offline = false;
  const after = await open();
  assert.equal((await after.pinStatus("docs/a.txt")).pinned, false);
  assert.equal(await after.evictLocal("docs/a.txt"), true);
  assert.equal(state.pushes, 0);
});

test("issue 66: exclusion cannot evict a pinned file, and a missing pinned file cannot cause remote DELETE", async (t) => {
  const { rootDir, open, state } = await fixture(t);
  const pinned = await open();
  await pinned.pinLocal("docs/a.txt");
  const excluded = await open(["docs"]);
  const summary = await excluded.syncOnce();
  assert.deepEqual(summary.excluded.kept, [{ path: "docs/a.txt", code: "file_pinned" }]);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  await fsp.unlink(path.join(rootDir, "docs/a.txt"));
  const restarted = await open();
  await assert.rejects(restarted.syncOnce(), { code: "pinned_file_missing" });
  assert.equal(state.pushes, 0, "a missing pinned local file must never generate a remote tombstone");
  assert.equal((await restarted.pinStatus("docs/a.txt")).pinned, true);
});

test("issue 66 P2 RED: missing pinned descendant cannot leave an ancestor DELETE in signed outbox", async (t) => {
  const { rootDir, open, state, remote } = await fixture(t);
  const client = await open();
  await client.apply(await remote("create", "object-directory", "docs", "", 1,
    undefined, "inode/directory"));
  await client.pinLocal("docs/a.txt");
  assert.deepEqual(Object.keys(client.snapshot.files).slice(0, 2), ["docs", "docs/a.txt"],
    "tracked directory must precede its pinned child to reproduce the ordering hazard");
  const priorFiles = structuredClone(client.snapshot.files);
  const beforeJournal = await fsp.readFile(client.journal.filePath);
  const snapshotPath = path.join(rootDir, ".rootark-sync-index.json");
  const beforeDisk = await fsp.readFile(snapshotPath);

  await fsp.rm(path.join(rootDir, "docs"), { recursive: true, force: true });
  await assert.rejects(client.reconcileLocal(), { code: "pinned_file_missing" });
  assert.deepEqual(await fsp.readFile(client.journal.filePath), beforeJournal,
    "failed pinned descendant preflight cannot durably enqueue ancestor DELETE");
  assert.deepEqual(client.snapshot.files, priorFiles,
    "failed reconciliation cannot stage a directory tombstone even in memory");
  assert.deepEqual(await fsp.readFile(snapshotPath), beforeDisk);
  assert.equal((await client.journal.recover()).some((op) => op.operation === "delete"
    && op.metadata?.path === "docs"), false, "no delayed ancestor DELETE may be dispatched");
  await fsp.mkdir(path.join(rootDir, "docs"), { recursive: true });
  await fsp.writeFile(path.join(rootDir, "docs/a.txt"), "authenticated remote bytes");
  await (await open()).syncOnce();
  assert.equal(state.pushes, 0, "restoring the missing pin must not transmit any latent directory tombstone");
});

test("issue 66 P2 RED: enqueueChange rejects pinned DELETE without poisoning restart snapshot", async (t) => {
  const { rootDir, open, state } = await fixture(t);
  const client = await open();
  await client.pinLocal("docs/a.txt");
  const prior = client.snapshot.files["docs/a.txt"];
  assert.equal((await client.pinStatus("docs/a.txt")).pinned, true);
  const snapshotPath = path.join(rootDir, ".rootark-sync-index.json");
  const beforeDisk = await fsp.readFile(snapshotPath);
  const beforeJournal = await fsp.readFile(client.journal.filePath);

  await assert.rejects(client.enqueueChange({ operation: "delete",
    objectId: prior.objectId, fileId: prior.fileId,
    versionId: crypto.randomUUID(), baseRevision: prior.revision,
    revision: { counter: prior.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/a.txt" } }), { code: "file_pinned" });
  assert.deepEqual(await fsp.readFile(client.journal.filePath), beforeJournal,
    "public enqueue entry point cannot persist a forbidden signed DELETE");
  assert.deepEqual(await fsp.readFile(snapshotPath), beforeDisk,
    "failed public enqueue must preserve a reopenable pinned snapshot");
  assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, true,
    "a rejected local mutation may not poison CLI pin status after restart");
  assert.equal(state.pushes, 0);
});

test("issue 66 P2 peer RED: excluded missing pinned child cannot enqueue selected ancestor DELETE", async (t) => {
  const { rootDir, open, remote } = await fixture(t);
  const initial = await open();
  await initial.apply(await remote("create", "object-directory", "docs", "", 1,
    undefined, "inode/directory"));
  await initial.pinLocal("docs/a.txt");
  const excluded = await open(["docs/a.txt"]);
  const priorJournal = await fsp.readFile(excluded.journal.filePath);
  const priorSnapshot = await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json"));
  await fsp.rm(path.join(rootDir, "docs"), { recursive: true, force: true });
  await assert.rejects(excluded.reconcileLocal(), { code: "pinned_file_missing" },
    "excluding a pinned child must not authorize the selected parent deletion");
  assert.deepEqual(await fsp.readFile(excluded.journal.filePath), priorJournal,
    "no delayed ancestor DELETE may be signed while the child is missing");
  assert.deepEqual(await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json")), priorSnapshot);
  assert.equal((await excluded.journal.recover()).some((operation) =>
    operation.operation === "delete" && operation.metadata?.path === "docs"), false);
});

test("issue 66 P2 peer RED: direct directory CREATE cannot replace pinned ancestor identity", async (t) => {
  const { rootDir, open, remote } = await fixture(t);
  const client = await open();
  await client.apply(await remote("create", "object-directory", "docs", "", 1,
    undefined, "inode/directory"));
  await client.pinLocal("docs/a.txt");
  const priorJournal = await fsp.readFile(client.journal.filePath);
  const priorSnapshot = await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json"));
  await assert.rejects(client.enqueueChange({ operation: "create", objectId: "other-directory",
    fileId: "other-file", versionId: crypto.randomUUID(), baseRevision: null,
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "docs", contentType: "inode/directory" }, plaintext: Buffer.alloc(0) }),
  { code: "file_pinned" }, "pinned child must not tolerate a conflicting parent directory identity");
  assert.deepEqual(await fsp.readFile(client.journal.filePath), priorJournal);
  assert.deepEqual(await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json")), priorSnapshot);
  assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, true);
});

test("issue 66 P2 peer RED: pending pinned UPDATE cannot hide a missing child before ancestor DELETE", async (t) => {
  const { rootDir, open, remote, state } = await fixture(t);
  const client = await open();
  await client.apply(await remote("create", "object-directory", "docs", "", 1,
    undefined, "inode/directory"));
  await client.pinLocal("docs/a.txt");
  const prior = client.snapshot.files["docs/a.txt"];
  await client.enqueueChange({ operation: "update", objectId: prior.objectId,
    fileId: prior.fileId, versionId: crypto.randomUUID(),
    baseRevision: prior.revision,
    revision: { counter: prior.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/a.txt" }, plaintext: Buffer.from("pending signed update") });
  assert.equal((await client.journal.recover()).some((op) => op.operation === "update"
    && op.metadata?.path === "docs/a.txt"), true,
  "fixture must contain a genuine signed pending child UPDATE");
  const beforeJournal = await fsp.readFile(client.journal.filePath);
  const indexPath = path.join(rootDir, ".rootark-sync-index.json");
  const beforeIndex = await fsp.readFile(indexPath);
  const beforeFiles = structuredClone(client.snapshot.files);

  await fsp.rm(path.join(rootDir, "docs"), { recursive: true, force: true });
  await assert.rejects(client.reconcileLocal(), { code: "pinned_file_missing" },
    "a pending UPDATE cannot exempt a missing pin when its tracked parent is deleted");
  assert.deepEqual(await fsp.readFile(client.journal.filePath), beforeJournal,
    "the failed group preflight preserves only the existing signed UPDATE");
  assert.deepEqual(await fsp.readFile(indexPath), beforeIndex);
  assert.deepEqual(client.snapshot.files, beforeFiles);
  assert.equal((await client.journal.recover()).some((op) => op.operation === "delete"
    && op.metadata?.path === "docs"), false);
  assert.equal(state.pushes, 0);
});

test("issue 66 P2 peer RED: case-alias directory CREATE cannot adopt a pinned descendant", async (t) => {
  const { rootDir, open, remote } = await fixture(t);
  const client = await open();
  await client.apply(await remote("create", "object-directory", "docs", "", 1,
    undefined, "inode/directory"));
  await client.pinLocal("docs/a.txt");
  const tracked = client.snapshot.files.docs;
  assert.ok(tracked?.directory);
  const beforeJournal = await fsp.readFile(client.journal.filePath);
  const indexPath = path.join(rootDir, ".rootark-sync-index.json");
  const beforeIndex = await fsp.readFile(indexPath);
  await assert.rejects(client.enqueueChange({ operation: "create",
    objectId: tracked.objectId, fileId: tracked.fileId,
    versionId: crypto.randomUUID(), baseRevision: null,
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "DOCS", contentType: "inode/directory" },
    plaintext: Buffer.alloc(0) }), { code: "file_pinned" },
  "matching object identity cannot authorize an alternate-case ancestor of a pin");
  assert.deepEqual(await fsp.readFile(client.journal.filePath), beforeJournal);
  assert.deepEqual(await fsp.readFile(indexPath), beforeIndex);
  assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, true);
});

test("issue 66: a real untracked ancestor can be enrolled without replacing a pinned file", async (t) => {
  const { rootDir, open } = await fixture(t);
  const client = await open();
  await client.pinLocal("docs/a.txt");
  assert.equal(client.snapshot.files.docs, undefined,
    "hydrating the child can create a physical parent before its sync identity arrives");
  assert.equal((await fsp.lstat(path.join(rootDir, "docs"))).isDirectory(), true);
  const operation = await client.enqueueChange({ operation: "create",
    objectId: "directory-object", fileId: "directory-file", versionId: crypto.randomUUID(),
    baseRevision: null, revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "docs", contentType: "inode/directory" },
    plaintext: Buffer.alloc(0) });
  assert.equal(operation.operation, "create");
  assert.equal(client.snapshot.files.docs.objectId, "directory-object");
  assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, true);
});

test("issue 66: excluded file is evicted after explicit unpin, without remote DELETE", async (t) => {
  const { rootDir, open, state } = await fixture(t);
  await (await open()).pinLocal("docs/a.txt");
  const excluded = await open(["docs"]);
  assert.equal((await excluded.syncOnce()).excluded.kept[0].code, "file_pinned");
  assert.equal((await excluded.unpinLocal("docs/a.txt")).applied, true);
  const restarted = await open(["docs"]);
  assert.equal((await restarted.syncOnce()).excluded.evicted, 1);
  assert.equal(await fsp.stat(path.join(rootDir, "docs/a.txt")).then(() => true, () => false), false);
  assert.equal(state.pushes, 0);
  assert.equal(state.records.get("object-a").tombstone, false);
});

test("issue 66: an independently signed remote DELETE cannot silently remove pinned local bytes", async (t) => {
  const { rootDir, open, remote, state } = await fixture(t);
  const client = await open();
  await client.pinLocal("docs/a.txt");
  const deletion = await remote("delete", "object-a", "docs/a.txt", "", 2);
  await assert.rejects(client.apply(deletion), { code: "file_pinned" });
  assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, true);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  assert.equal(state.pushes, 0);
});

test("issue 66: unsigned/tampered ciphertext cannot establish a pin and invalid persisted pin fails closed", async (t) => {
  const { rootDir, open, state } = await fixture(t);
  const bad = state.records.get("object-a");
  state.records.set("object-a", { ...bad, ciphertext: Buffer.from("forged ciphertext").toString("base64url") });
  const engine = await open();
  await assert.rejects(engine.pinLocal("docs/a.txt"));
  assert.equal((await engine.pinStatus("docs/a.txt")).pinned, false);
  assert.equal(await fsp.stat(path.join(rootDir, "docs/a.txt")).then(() => true, () => false), false);
  const snapshot = path.join(rootDir, ".rootark-sync-index.json");
  const persisted = JSON.parse(await fsp.readFile(snapshot, "utf8"));
  persisted.pinnedFiles = { "object-a": { objectId: "object-other", path: "../escape", fileId: "file-object-a" } };
  await fsp.writeFile(snapshot, JSON.stringify(persisted));
  await assert.rejects(open(), { code: "invalid_snapshot" });
});

test("issue 66: direct non-strict engine cannot pin without independently trusted signed verification", async (t) => {
  const { open, state } = await fixture(t);
  const nonStrict = await open([], false);
  await assert.rejects(nonStrict.pinLocal("docs/a.txt"), { code: "authorization_required" });
  assert.equal(state.fullReads.length, 0);
  assert.equal(state.inventoryReads, 0);
  assert.equal((await nonStrict.pinStatus("docs/a.txt")).pinned, false);
});

test("issue 66 P2 POSIX: signed legacy case-alias files cannot create a second device pin or poison restart", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX case-distinct filesystem regression; Windows coverage in shared tests");
  const { rootDir, open, state, remote } = await fixture(t);
  await remote("create", "object-b", "Docs/A.txt", "independent signed legacy bytes");
  const client = await open([], true, true, ["docs", "Docs"]);
  // Legacy distinct signed objects exist despite the current protected
  // CREATE server guard: neither one's local bytes may be discarded.
  assert.equal(await client.materializeRemote("Docs/A.txt"), true);
  assert.equal((await client.pinLocal("docs/a.txt")).objectId, "object-a");
  const before = await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json"), "utf8");
  assert.equal((await client.pinStatus("Docs/A.txt")).pinned, false,
    "POSIX status must not alias a case-distinct pinned path");
  assert.equal((await client.unpinLocal("Docs/A.txt")).applied, false,
    "POSIX unpin must not affect a different case-distinct pin");
  await assert.rejects(client.pinLocal("Docs/A.txt"), { code: "pinned_path_alias" },
    "a second portable-case alias must be rejected before snapshot persistence");
  assert.equal(await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json"), "utf8"), before,
    "denied second pin must not alter the durable first pin");
  const resumed = await open([], true, true, ["docs", "Docs"]);
  assert.equal((await resumed.pinStatus("docs/a.txt")).pinned, true);
  assert.equal((await resumed.pinStatus("Docs/A.txt")).pinned, false);
  assert.deepEqual((await resumed.pinStatus()).files.map((item) => item.path), ["docs/a.txt"]);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  assert.equal(await fsp.readFile(path.join(rootDir, "Docs/A.txt"), "utf8"), "independent signed legacy bytes");
  assert.equal(state.pushes, 0);
});

// Force the exact post-rename directory durability barrier to fail, not an
// early JSON write: at this point the new snapshot is already visible on disk.
function interceptSnapshotDirectoryFsync(t, directory, failures, enabled = () => true) {
  const realOpen = fsp.open;
  let injected = 0;
  fsp.open = async (...args) => {
    const handle = await realOpen(...args);
    if (String(args[0]) !== directory || args[1] !== fs.constants.O_RDONLY
      || injected >= failures || !enabled()) return handle;
    injected++;
    return {
      close: () => handle.close(),
      sync: async () => { throw Object.assign(new Error("injected EIO after durable rename"), { code: "EIO" }); },
    };
  };
  t.after(() => { fsp.open = realOpen; });
  return { restore: () => { fsp.open = realOpen; }, count: () => injected };
}

// Cross-platform equivalent of a post-rename fsync/lstat failure: first let
// the REAL durable snapshot transaction finish, then throw as its caller
// resumes. This proves a failed PIN cannot leave opposite policies in memory
// and on disk even where Windows does not support directory fsync.
function failAfterDurablePinCommit(t, client, count) {
  const original = client.persistSnapshot;
  let injected = 0;
  let armed = false;
  client.persistSnapshot = async function (...args) {
    const result = await original.apply(this, args);
    armed ||= Object.values(client.snapshot.pinnedFiles || {}).some((pin) => pin.objectId === "object-a");
    if (armed && injected < count) {
      injected++;
      throw Object.assign(new Error("simulated failure after real PIN disk commit"), { code: "EIO" });
    }
    return result;
  };
  t.after(() => { client.persistSnapshot = original; });
  return { count: () => injected };
}

test("issue 66 P2 cross-platform: completed PIN disk write then thrown EIO rolls back durably", async (t) => {
  const { rootDir, open, state } = await fixture(t);
  const client = await open();
  const injected = failAfterDurablePinCommit(t, client, 1);
  await assert.rejects(client.pinLocal("docs/a.txt"), { code: "EIO" });
  assert.equal(injected.count(), 1, "must throw after first real pinned snapshot was written");
  assert.equal((await client.pinStatus("docs/a.txt")).pinned, false);
  const onDisk = JSON.parse(await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json"), "utf8"));
  assert.deepEqual(onDisk.pinnedFiles || {}, {},
    "failed pin may not persist a policy the process denies");
  assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, false);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  assert.equal(state.pushes, 0);
});

test("issue 66 P2 cross-platform: failed PIN rollback holds recovery lock", async (t) => {
  const { rootDir, open, state } = await fixture(t);
  const client = await open();
  const injected = failAfterDurablePinCommit(t, client, 2);
  await assert.rejects(client.pinLocal("docs/a.txt"), { code: "pinned_policy_indeterminate" });
  assert.equal(injected.count(), 2, "failed initial PIN and failed compensation both write to disk");
  await assert.rejects(client.evictLocal("docs/a.txt"), { code: "sync_root_busy" });
  await assert.rejects(open(), { code: "sync_root_busy" });
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  assert.equal(state.pushes, 0);
});

test("issue 66 P2: failed post-rename PIN fsync compensates disk and memory together", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX directory fsync failure boundary");
  const { rootDir, open, state } = await fixture(t);
  const client = await open();
  // Reach the actual pin-policy commit, not an earlier signed hydration fsync.
  let armed = false;
  const injector = interceptSnapshotDirectoryFsync(t, rootDir, 1, () => {
    armed ||= Object.values(client.snapshot.pinnedFiles || {}).some((pin) => pin.objectId === "object-a");
    return armed;
  });
  try {
    await assert.rejects(client.pinLocal("docs/a.txt"), { code: "EIO" });
    assert.equal(injector.count(), 1, "the failed barrier followed the pinned snapshot rename");
  } finally { injector.restore(); }
  assert.equal((await client.pinStatus("docs/a.txt")).pinned, false,
    "a failed pin cannot leave a phantom in-memory retention policy");
  const resumed = await open();
  assert.equal((await resumed.pinStatus("docs/a.txt")).pinned, false,
    "post-rename failure must not leave a different durable retention policy");
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes", "failed pin compensation must preserve hydrated bytes");
  assert.equal(state.pushes, 0);
});

test("issue 66 P2: failed PIN compensation quarantines the root before a local eviction", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX directory fsync failure boundary");
  const { rootDir, open, state } = await fixture(t);
  const client = await open();
  let armed = false;
  const injector = interceptSnapshotDirectoryFsync(t, rootDir, 2, () => {
    armed ||= Object.values(client.snapshot.pinnedFiles || {}).some((pin) => pin.objectId === "object-a");
    return armed;
  });
  try {
    await assert.rejects(client.pinLocal("docs/a.txt"), { code: "pinned_policy_indeterminate" });
    assert.equal(injector.count(), 2, "both PIN commit and compensation failed after rename");
  } finally { injector.restore(); }
  await assert.rejects(client.evictLocal("docs/a.txt"), { code: "sync_root_busy" },
    "the same process must not evict while its retained PIN is indeterminate");
  await assert.rejects(open(), { code: "sync_root_busy" },
    "a second process must not assume the partially committed PIN was removed");
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes");
  assert.equal(state.pushes, 0);
});

test("issue 66 P2 POSIX: post-rename unpin fsync EIO compensates durable pin before allowing restart", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX directory fsync failure boundary");
  const { rootDir, open, state } = await fixture(t);
  const client = await open();
  await client.pinLocal("docs/a.txt");
  const injector = interceptSnapshotDirectoryFsync(t, rootDir, 1);
  try {
    await assert.rejects(client.unpinLocal("docs/a.txt"), { code: "EIO" });
    assert.equal(injector.count(), 1, "failure must hit AFTER rename, before directory fsync");
  } finally { injector.restore(); }
  const resumed = await open();
  assert.equal((await resumed.pinStatus("docs/a.txt")).pinned, true,
    "a failed unpin cannot silently become effective on restart");
  await assert.rejects(resumed.evictLocal("docs/a.txt"), { code: "file_pinned" });
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  assert.equal(state.pushes, 0);
});

test("issue 66 P2 POSIX: indeterminate unpin plus failed compensation quarantines root on restart", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX directory fsync failure boundary");
  const { rootDir, open, state } = await fixture(t);
  const client = await open();
  await client.pinLocal("docs/a.txt");
  const injector = interceptSnapshotDirectoryFsync(t, rootDir, 2);
  try {
    await assert.rejects(client.unpinLocal("docs/a.txt"), { code: "pinned_policy_indeterminate" });
    assert.equal(injector.count(), 2, "both the unpin and its compensation were non-durable");
  } finally { injector.restore(); }
  await assert.rejects(open(), { code: "sync_root_busy" },
    "a failed rollback must retain the root process-lock marker for explicit recovery");
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  assert.equal(state.pushes, 0);
});

test("issue 66 P2: signed other-object MOVE/CREATE/UPDATE cannot overwrite a pinned destination", async (t) => {
  const { rootDir, open, remote, state } = await fixture(t);
  const pinned = await open();
  await pinned.pinLocal("docs/a.txt");
  const source = await remote("create", "object-b", "docs/b.txt", "other signed original bytes");
  await pinned.apply(source);
  const moved = await remote("move", "object-b", "docs/a.txt", "other signed original bytes", 2, "docs/b.txt");
  // Retention must be enforced even by direct apply() in a client reopened
  // with Files-On-Demand disabled (not just hydrate/evict CLI operations).
  const nonFod = await open([], true, false);
  await assert.rejects(nonFod.apply(moved), { code: "file_pinned" });
  await assert.rejects(nonFod.apply(await remote("update", "object-b", "docs/a.txt",
    "other signed edit", 3)), { code: "file_pinned" });
  await assert.rejects(nonFod.apply(await remote("create", "object-c", "docs/a.txt",
    "other signed create")), { code: "file_pinned" });
  const restarted = await open();
  assert.equal((await restarted.pinStatus("docs/a.txt")).pinned, true);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/b.txt"), "utf8"), "other signed original bytes");
  assert.equal(state.pushes, 0);
});

test("issue 66 P2: signed other-object ancestor mutations cannot stage a directory containing a pinned file", async (t) => {
  for (const action of ["delete", "create", "update", "move"]) {
    for (const ancestorPath of ["docs", "Docs"]) {
      await t.test(`${action} at ${ancestorPath} refuses before journal or filesystem mutation`, async (subtest) => {
        const { rootDir, open, remote, state } = await fixture(subtest);
        const client = await open();
        if (action === "delete") {
          const directory = await remote("create", "other-directory", "docs", "", 1,
            undefined, "inode/directory");
          await client.apply(directory);
        }
        if (["update", "move"].includes(action)) {
          await client.apply(await remote("create", "object-b", "docs/b.txt", "other signed bytes"));
        }
        await client.pinLocal("docs/a.txt");
        const original = await fsp.readFile(path.join(rootDir, "docs/a.txt"));
        const snapshotPath = path.join(rootDir, ".rootark-sync-index.json");
        const beforeSnapshot = await fsp.readFile(snapshotPath);
        const beforeJournal = await fsp.readFile(client.journal.filePath);

        const operation = action === "delete"
          ? await remote("delete", "other-directory", ancestorPath, "", 2)
          : action === "move"
            ? await remote("move", "object-b", ancestorPath, "other signed bytes", 2, "docs/b.txt")
            : action === "update"
              ? await remote("update", "object-b", ancestorPath, "other signed replacement", 2)
              : await remote("create", "object-c", ancestorPath, "other signed replacement");
        await assert.rejects(client.apply(operation), { code: "file_pinned" });
        assert.deepEqual(await fsp.readFile(client.journal.filePath), beforeJournal,
          "rejected signed ancestor must not be observed or enqueued");
        assert.deepEqual(await fsp.readFile(snapshotPath), beforeSnapshot,
          "rejected signed ancestor must not persist any snapshot change");
        assert.deepEqual(await fsp.readFile(path.join(rootDir, "docs/a.txt")), original,
          "pinned descendant bytes must survive the rejected ancestor replacement");
        assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, true);
        assert.equal(state.pushes, 0);
      });
    }
  }
});

test("issue 66 P2: signed relocation of a tracked ancestor cannot move a pinned subtree", async (t) => {
  for (const action of ["move", "update"]) {
    await t.test(`${action} of tracked docs refuses before any journal observation`, async (subtest) => {
      const { rootDir, open, remote } = await fixture(subtest);
      const client = await open();
      await client.apply(await remote("create", "other-directory", "docs", "", 1,
        undefined, "inode/directory"));
      await client.pinLocal("docs/a.txt");
      const priorJournal = await fsp.readFile(client.journal.filePath);
      const priorSnapshot = await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json"));
      const operation = action === "move"
        ? await remote("move", "other-directory", "archived", "", 2, "docs")
        : await remote("update", "other-directory", "archived", "", 2,
          undefined, "inode/directory");
      await assert.rejects(client.apply(operation), { code: "file_pinned" });
      assert.deepEqual(await fsp.readFile(client.journal.filePath), priorJournal);
      assert.deepEqual(await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json")), priorSnapshot);
      assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
        "authenticated remote bytes");
      assert.equal(await fsp.stat(path.join(rootDir, "archived")).then(() => true, () => false), false);
    });
  }
});

test("issue 66 P2: a sibling path must not be mistaken for an ancestor of a pinned file", async (t) => {
  const { rootDir, open, remote } = await fixture(t);
  const client = await open();
  await client.pinLocal("docs/a.txt");
  await client.apply(await remote("create", "object-sibling", "docs-old", "signed sibling bytes"));
  assert.equal(await fsp.readFile(path.join(rootDir, "docs-old"), "utf8"), "signed sibling bytes");
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes");
});

test("issue 66: failed local pin journal commit never claims pin; a verified MOVE retains pinned identity", async (t) => {
  const { rootDir, open, remote, state } = await fixture(t);
  const engine = await open();
  const originalPersist = engine.persistSnapshot.bind(engine);
  let failed = false;
  engine.persistSnapshot = async () => {
    if (Object.values(engine.snapshot.pinnedFiles || {}).some((pin) => pin.objectId === "object-a") && !failed) {
      failed = true;
      throw Object.assign(new Error("simulated disk error"), { code: "EIO" });
    }
    return originalPersist();
  };
  await assert.rejects(engine.pinLocal("docs/a.txt"), { code: "EIO" });
  const reopened = await open();
  assert.equal((await reopened.pinStatus("docs/a.txt")).pinned, false);
  await reopened.pinLocal("docs/a.txt");
  await remote("move", "object-a", "docs/moved.txt", "authenticated remote bytes", 2, "docs/a.txt");
  assert.equal(await reopened.materializeRemote("docs/moved.txt"), true);
  const moveStatus = await (await open()).pinStatus("docs/moved.txt");
  assert.equal(moveStatus.pinned, true, "verified identity transfer must keep pin across MOVE and restart");
  await assert.rejects((await open()).evictLocal("docs/moved.txt"), { code: "file_pinned" });
  assert.equal(state.pushes, 0);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/moved.txt"), "utf8"), "authenticated remote bytes");
});

test("issue 66 #278 P1: FOD-off signed out-of-scope MOVE cannot discard offline pinned bytes or consume admission", async (t) => {
  const { rootDir, open, remote, state, adapter } = await fixture(t);
  await (await open()).pinLocal("docs/a.txt");
  const client = await open([], true, false, ["docs/a.txt"]);
  const move = await remote("move", "object-a", "archive/a.txt", "authenticated remote bytes", 2, "docs/a.txt");
  // The FOD fixture normally exposes full envelopes only by object ID;
  // a legacy FOD-disabled pull lists every signed envelope.
  const originalList = adapter.list;
  adapter.list = async (objectId) => objectId === undefined
    ? [...state.records.values()] : originalList(objectId);
  assert.equal(client.operationDestinationIsSelected(move), false);
  assert.ok(client.snapshot.files["docs/a.txt"]);
  assert.throws(() => client.preflightOutOfScopeMove(move), { code: "file_pinned" });
  const journalBefore = await fsp.readFile(client.journal.filePath);
  const snapshotFile = path.join(rootDir, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotFile);
  await assert.rejects(client.syncOnce(), { code: "file_pinned" });
  assert.deepEqual(await fsp.readFile(client.journal.filePath), journalBefore,
    "reject before signed admission pre-observation");
  const afterSnapshot = JSON.parse(await fsp.readFile(snapshotFile, "utf8"));
  const beforeParsed = JSON.parse(snapshotBefore.toString("utf8"));
  assert.deepEqual(afterSnapshot.files, beforeParsed.files,
    "reject before untracking the pinned source");
  assert.deepEqual(afterSnapshot.pinnedFiles, beforeParsed.pinnedFiles);
  assert.deepEqual(afterSnapshot.remoteOnly, beforeParsed.remoteOnly);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  assert.equal(fs.existsSync(path.join(rootDir, "archive/a.txt")), false);
  assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, true);
  assert.equal(state.pushes, 0);
});

test("issue 66 #278 P2: pinned regular file rejects same-identity directory UPDATE before mutation", async (t) => {
  const { rootDir, open, remote } = await fixture(t);
  await (await open()).pinLocal("docs/a.txt");
  const client = await open([], true, false);
  const signed = await remote("update", "object-a", "docs/a.txt", "", 2,
    undefined, "inode/directory");
  const beforeJournal = await fsp.readFile(client.journal.filePath);
  const snapshotFile = path.join(rootDir, ".rootark-sync-index.json");
  const beforeSnapshot = await fsp.readFile(snapshotFile);
  await assert.rejects(client.apply(signed), { code: "file_pinned" });
  assert.deepEqual(await fsp.readFile(client.journal.filePath), beforeJournal);
  assert.deepEqual(await fsp.readFile(snapshotFile), beforeSnapshot);
  assert.equal((await fsp.stat(path.join(rootDir, "docs/a.txt"))).isFile(), true);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, true);
});

test("issue 66 #278 P2: local regular-to-directory replacement cannot corrupt pinned snapshot", async (t) => {
  const { rootDir, open } = await fixture(t);
  await (await open()).pinLocal("docs/a.txt");
  const client = await open([], true, false);
  const original = await fsp.readFile(path.join(rootDir, "docs/a.txt"));
  const snapshotFile = path.join(rootDir, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotFile);
  const journalBefore = await fsp.readFile(client.journal.filePath);
  await fsp.unlink(path.join(rootDir, "docs/a.txt"));
  await fsp.mkdir(path.join(rootDir, "docs/a.txt"));
  await assert.rejects(client.reconcileLocal(), { code: "file_pinned" });
  assert.deepEqual(await fsp.readFile(snapshotFile), snapshotBefore);
  assert.deepEqual(await fsp.readFile(client.journal.filePath), journalBefore);
  await fsp.rmdir(path.join(rootDir, "docs/a.txt"));
  await fsp.writeFile(path.join(rootDir, "docs/a.txt"), original);
  assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, true,
    "durable index remains valid after safe local repair and restart");
});

test("issue 66 #278 P2: signed CREATE of existing matching ancestor directory preserves pinned child", async (t) => {
  const { rootDir, open, remote } = await fixture(t);
  await (await open()).pinLocal("docs/a.txt");
  const client = await open([], true, false);
  const signed = await remote("create", "directory-docs", "docs", "", 1,
    undefined, "inode/directory");
  await client.apply(signed);
  assert.equal((await fsp.stat(path.join(rootDir, "docs"))).isDirectory(), true);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  const restarted = await open();
  assert.equal((await restarted.pinStatus("docs/a.txt")).pinned, true);
  assert.equal(restarted.snapshot.files.docs.directory, true);
  assert.equal(restarted.snapshot.files.docs.objectId, "directory-docs");
});

test("issue 66 #278 P2: ancestor CREATE cannot replace tracked directory identity of pinned child", async (t) => {
  const { rootDir, open, remote } = await fixture(t);
  await (await open()).pinLocal("docs/a.txt");
  const client = await open([], true, false);
  await client.apply(await remote("create", "directory-docs", "docs", "", 1,
    undefined, "inode/directory"));
  const snapshotFile = path.join(rootDir, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotFile);
  const journalBefore = await fsp.readFile(client.journal.filePath);
  await assert.rejects(client.apply(await remote("create", "impostor-directory",
    "docs", "", 1, undefined, "inode/directory")), { code: "file_pinned" });
  assert.deepEqual(await fsp.readFile(snapshotFile), snapshotBefore);
  assert.deepEqual(await fsp.readFile(client.journal.filePath), journalBefore);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes");
  assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, true);
});

test("issue 66 #278 POSIX: case-distinct existing ancestor cannot launder a pinned directory CREATE", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX case-distinct directory invariant");
  const { rootDir, open, remote } = await fixture(t);
  await (await open()).pinLocal("docs/a.txt");
  const client = await open([], true, false);
  await fsp.mkdir(path.join(rootDir, "Docs"));
  const snapshotFile = path.join(rootDir, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotFile);
  const journalBefore = await fsp.readFile(client.journal.filePath);
  await assert.rejects(client.apply(await remote("create", "alias-directory",
    "Docs", "", 1, undefined, "inode/directory")), { code: "file_pinned" });
  assert.deepEqual(await fsp.readFile(snapshotFile), snapshotBefore);
  assert.deepEqual(await fsp.readFile(client.journal.filePath), journalBefore);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes");
});

test("issue 66 #278 P2: pinStatus listing passes known pins without quadratic rescan", async (t) => {
  const { rootDir, open } = await fixture(t);
  const client = await open();
  const count = 128;
  await fsp.mkdir(path.join(rootDir, "docs"), { recursive: true });
  client.snapshot.pinnedFiles ||= {};
  for (let i = 0; i < count; i++) {
    const relative = `docs/pin-${i}.txt`;
    await fsp.writeFile(path.join(rootDir, relative), "");
    client.snapshot.pinnedFiles[`object-list-${i}`] = {
      objectId: `object-list-${i}`, fileId: `file-list-${i}`, path: relative,
    };
  }
  const pinnedObject = client.snapshot.pinnedFiles;
  const realValues = Object.values;
  let scans = 0;
  Object.values = function (obj) {
    if (obj === pinnedObject) scans++;
    return realValues(obj);
  };
  try {
    const result = await client.pinStatus();
    assert.equal(result.files.length, count);
    assert.equal(result.files.every((item) => item.pinned && item.localPresent), true);
    assert.ok(scans <= 2, `pinStatus made ${scans} full pinnedFiles scans for ${count} entries`);
  } finally {
    Object.values = realValues;
  }
});

test("issue 66 #278 P2 RED: relocating UPDATE carries device pin forward without invalid_snapshot", async (t) => {
  const { rootDir, open, remote } = await fixture(t);
  const client = await open();
  assert.equal((await client.pinLocal("docs/a.txt")).pinned, true);
  await remote("move", "object-a", "docs/b.txt", "authenticated remote bytes", 2, "docs/a.txt");
  await remote("update", "object-a", "docs/b.txt", "relocated updated bytes", 3);
  assert.equal(await client.materializeRemote("docs/b.txt"), true);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/b.txt"), "utf8"), "relocated updated bytes");
  const reopened = await open();
  assert.deepEqual(await reopened.pinStatus("docs/b.txt"), {
    path: "docs/b.txt", pinned: true, localPresent: true, objectId: "object-a",
  });
});

test("issue 66 #278 P2 RED: rotated-fileId tombstone cannot delete a pinned file", async (t) => {
  const { rootDir, open, state, remote } = await fixture(t);
  const client = await open();
  assert.equal((await client.pinLocal("docs/a.txt")).pinned, true);
  const previous = state.records.get("object-a");
  state.records.set("object-a", { ...previous, fileId: "file-rotated-a" });
  const tombstone = await remote("delete", "object-a", "docs/a.txt", "", 2);
  await assert.rejects(client._reconcileOnDemandTombstone(tombstone), { code: "file_pinned" });
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes");
  const reopened = await open();
  assert.deepEqual(await reopened.pinStatus("docs/a.txt"), {
    path: "docs/a.txt", pinned: true, localPresent: true, objectId: "object-a",
  });
});

test("issue 66 #278 P2 RED: translateWebDavMutation and _pushPending reject outgoing deletes of pinned files", async (t) => {
  const { rootDir, open, state } = await fixture(t);
  const client = await open();
  assert.equal((await client.pinLocal("docs/a.txt")).pinned, true);
  // 1. translateWebDavMutation must reject DELETE of a pinned file before journal admission.
  await fsp.unlink(path.join(rootDir, "docs/a.txt"));
  await assert.rejects(
    client.translateWebDavMutation({ operationId: "wd-del-pinned", kind: "delete", path: "docs/a.txt" }),
    { code: "file_pinned" },
  );
  // Restore pinned file and simulate a pre-existing incompatible DELETE queued in outbox.
  await fsp.writeFile(path.join(rootDir, "docs/a.txt"), "authenticated remote bytes");
  const prior = client.snapshot.files["docs/a.txt"];
  const key = await client.fileKeyResolver({ ...prior, path: "docs/a.txt", keyEpoch: client.keyEpoch });
  const staleDelete = await client.buildOperation({
    operation: "delete", objectId: prior.objectId, fileId: prior.fileId,
    versionId: crypto.randomUUID(), operationId: "webdavsolo-stale-del",
    baseRevision: prior.revision,
    revision: { counter: (prior.revision?.counter || 0) + 1, deviceId: client.deviceId },
    metadata: { path: "docs/a.txt" },
    plaintext: Buffer.alloc(0), fileKey: key,
  });
  await client.journal.enqueueMany([staleDelete]);
  const pushesBefore = state.pushes;
  await assert.rejects(client.syncOnce(), { code: "file_pinned" });
  assert.equal(state.pushes, pushesBefore, "_pushPending must not transmit an incompatible pinned DELETE");
  const reopened = await open();
  assert.deepEqual(await reopened.pinStatus("docs/a.txt"), {
    path: "docs/a.txt", pinned: true, localPresent: true, objectId: "object-a",
  });
});
