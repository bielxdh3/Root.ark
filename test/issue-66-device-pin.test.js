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
  return { rootDir, open, adapter, state, remote, trusted };
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

test("issue 66 P2: signed MOVE outside selected paths cannot evict a pinned origin across restart", async (t) => {
  const { rootDir, open, remote, state, trusted } = await fixture(t);
  const client = await open();
  await client.pinLocal("docs/a.txt");
  // A previously pinned root may later reopen with Files-On-Demand disabled.
  // That switches to the ordinary signed LIST reconciliation path.
  const eager = await open([], true, false, ["docs"]);
  const beforeIndex = await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json"));
  const beforeJournal = await fsp.readFile(eager.journal.filePath);
  const signedMove = await remote("move", "object-a", "outside/a.txt",
    "authenticated remote bytes", 2, "docs/a.txt");
  assert.equal(await verifyAuthorizationProof(signedMove.authorization, signedMove, trusted),
    true, "the remote MOVE is authentically signed");
  // This fixture's default LIST is object-filtered. Model the real unscoped
  // signed LIST used by pullRemote without bypassing envelope verification.
  const listOne = eager.adapter.list.bind(eager.adapter);
  eager.adapter.list = async (objectId) => objectId === undefined
    ? [...state.records.values()] : listOne(objectId);
  await assert.rejects(eager.pullRemote({ pushed: 0, pulled: 0, applied: 0,
    conflicts: [], offline: false }), { code: "file_pinned" });
  assert.deepEqual(await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json")), beforeIndex,
    "rejected reconciliation must not remove the durable pin or tracked origin");
  const priorJournal = JSON.parse(beforeJournal.toString("utf8"));
  const afterJournal = JSON.parse(await fsp.readFile(eager.journal.filePath, "utf8"));
  assert.deepEqual(afterJournal.pending, priorJournal.pending,
    "rejected reconciliation cannot enqueue a mutation");
  assert.deepEqual(afterJournal.seen, priorJournal.seen,
    "a verified but blocked MOVE cannot become applied or seen");
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes");
  const restarted = await open();
  assert.equal((await restarted.pinStatus("docs/a.txt")).pinned, true);
  await assert.rejects(restarted.pullRemote({ pushed: 0, pulled: 0, applied: 0,
    conflicts: [], offline: false }), { code: "file_pinned" },
  "a restarted client must not consume the previously rejected signed MOVE");
  assert.equal(state.pushes, 0);
});

test("issue 66 P2: signed out-of-scope directory relocation cannot drop a pinned descendant", async (t) => {
  const { rootDir, open, remote, adapter, state, trusted } = await fixture(t);
  const client = await open();
  await client.apply(await remote("create", "directory-object", "docs", "", 1,
    undefined, "inode/directory"));
  await client.pinLocal("docs/a.txt");
  const beforeIndex = await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json"));
  const movedDirectory = await remote("update", "directory-object", "archive", "", 2,
    undefined, "inode/directory");
  assert.equal(await verifyAuthorizationProof(movedDirectory.authorization,
    movedDirectory, trusted), true);
  const originalList = adapter.list.bind(adapter);
  adapter.list = async (objectId) => objectId === undefined
    ? [movedDirectory] : originalList(objectId);
  const eager = await open([], true, false, ["docs"]);
  await assert.rejects(eager.pullRemote({ pushed: 0, pulled: 0, applied: 0,
    conflicts: [], offline: false }), { code: "file_pinned" });
  assert.deepEqual(await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json")),
    beforeIndex);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes");
  assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, true);
  assert.equal(state.pushes, 0);
});

test("issue 66 P2: explicit unpin permits a signed out-of-scope MOVE without remote DELETE", async (t) => {
  const { rootDir, open, remote, adapter, state } = await fixture(t);
  const client = await open();
  await client.pinLocal("docs/a.txt");
  await client.unpinLocal("docs/a.txt");
  const moved = await remote("move", "object-a", "outside/a.txt",
    "authenticated remote bytes", 2, "docs/a.txt");
  const originalList = adapter.list.bind(adapter);
  adapter.list = async (objectId) => objectId === undefined ? [moved] : originalList(objectId);
  const eager = await open([], true, false, ["docs"]);
  await eager.pullRemote({ pushed: 0, pulled: 0, applied: 0,
    conflicts: [], offline: false });
  assert.equal(fs.existsSync(path.join(rootDir, "docs/a.txt")), false);
  assert.equal((await (await open()).pinStatus("docs/a.txt")).pinned, false);
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
function interceptSnapshotDirectoryFsync(t, directory, failures) {
  const realOpen = fsp.open;
  let injected = 0;
  fsp.open = async (...args) => {
    const handle = await realOpen(...args);
    if (String(args[0]) !== directory || args[1] !== fs.constants.O_RDONLY
      || injected >= failures) return handle;
    injected++;
    return {
      close: () => handle.close(),
      sync: async () => { throw Object.assign(new Error("injected EIO after durable rename"), { code: "EIO" }); },
    };
  };
  t.after(() => { fsp.open = realOpen; });
  return { restore: () => { fsp.open = realOpen; }, count: () => injected };
}

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
