"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const childProcess = require("node:child_process");
const { spawnSync } = childProcess;
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { syncCycleReport, assertOneShotSyncComplete } = require("../sync-client/rootark-sync-v2");

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
  assert.deepEqual(afterJournal.observed, priorJournal.observed,
    "a pinned-rejected signed MOVE must not consume a durable pre-admission slot");
  assert.deepEqual(afterJournal.admitted, priorJournal.admitted,
    "a pinned-rejected signed MOVE must not establish signed admission");
  assert.equal(eager.journal.hasLocalAdmission(signedMove.operationId,
    crypto.createHash("sha256").update(protocol.canonicalJson(signedMove)).digest("hex")), false);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes");
  const restarted = await open();
  assert.equal((await restarted.pinStatus("docs/a.txt")).pinned, true);
  await assert.rejects(restarted.pullRemote({ pushed: 0, pulled: 0, applied: 0,
    conflicts: [], offline: false }), { code: "file_pinned" },
  "a restarted client must not consume the previously rejected signed MOVE");
  const afterRestartJournal = JSON.parse(await fsp.readFile(restarted.journal.filePath, "utf8"));
  assert.deepEqual(afterRestartJournal.observed, priorJournal.observed,
    "retrying after restart cannot reserve rejected operation IDs");
  assert.deepEqual(afterRestartJournal.admitted, priorJournal.admitted);
  for (let counter = 3; counter <= 5; counter++) {
    const denied = await remote("move", "object-a", `outside/attempt-${counter}.txt`,
      "authenticated remote bytes", counter, "docs/a.txt");
    assert.equal(await verifyAuthorizationProof(denied.authorization, denied, trusted), true);
    await assert.rejects(restarted.pullRemote({ pushed: 0, pulled: 0, applied: 0,
      conflicts: [], offline: false }), { code: "file_pinned" });
    const repeatedJournal = JSON.parse(await fsp.readFile(restarted.journal.filePath, "utf8"));
    assert.deepEqual(repeatedJournal.observed, priorJournal.observed,
      "distinct signed rejected MOVE IDs cannot exhaust the observed journal window");
    assert.deepEqual(repeatedJournal.admitted, priorJournal.admitted);
  }
  assert.equal(state.pushes, 0);
});

test("issue 66 P2: signed out-of-scope directory relocation cannot drop a pinned descendant", async (t) => {
  const { rootDir, open, remote, adapter, state, trusted } = await fixture(t);
  const client = await open();
  await client.apply(await remote("create", "directory-object", "docs", "", 1,
    undefined, "inode/directory"));
  await client.pinLocal("docs/a.txt");
  const beforeIndex = await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json"));
  const beforeJournal = JSON.parse(await fsp.readFile(client.journal.filePath, "utf8"));
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
  assert.deepEqual(JSON.parse(await fsp.readFile(eager.journal.filePath, "utf8")).observed, beforeJournal.observed,
    "rejected directory relocation must not reserve a signed observation");
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
  const journal = JSON.parse(await fsp.readFile(eager.journal.filePath, "utf8"));
  const digest = crypto.createHash("sha256").update(protocol.canonicalJson(moved)).digest("hex");
  assert.equal(journal.admitted[moved.operationId], digest,
    "allowed signed MOVE must persist exact admission after pre-observation");
  assert.equal(Object.hasOwn(journal.observed, moved.operationId), false,
    "a completed signed MOVE must promote its observation to admitted");
  assert.equal((await (await open()).journal.hasLocalAdmission(moved.operationId, digest)), true,
    "signed MOVE admission survives restart");
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

test("issue 66 #292 P1: untrusted Ed25519 B out-of-scope MOVE must fail authentication before pin preflight", async (t) => {
  const { rootDir, open, remote, state, adapter, trusted } = await fixture(t);
  await (await open()).pinLocal("docs/a.txt");
  const client = await open([], true, false, ["docs/a.txt"]);
  const valid = await remote("move", "object-a", "archive/a.txt",
    "authenticated remote bytes", 2, "docs/a.txt");
  assert.equal(await verifyAuthorizationProof(valid.authorization, valid, trusted), true,
    "positive control: the pin conflict on a genuinely signed A MOVE remains enforced");
  const rogue = crypto.generateKeyPairSync("ed25519");
  const rogueKey = rogue.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const forged = { ...valid, authorization: await createAuthorizationProof(valid, {
    username: "alice", privateKey: rogue.privateKey, publicKey: rogueKey,
    expiresAt: Date.now() + 60_000,
  }) };
  await assert.rejects(verifyAuthorizationProof(forged.authorization, forged, trusted),
    { code: "authorization_device_untrusted" },
    "negative control: valid Ed25519 B must not authenticate as pinned A");
  const originalList = adapter.list;
  adapter.list = async (objectId) => objectId === undefined ? [forged] : originalList(objectId);
  const journalBefore = await fsp.readFile(client.journal.filePath);
  const snapshotBefore = await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json"));
  await assert.rejects(client.pullRemote({ pushed: 0, pulled: 0, applied: 0,
    conflicts: [], offline: false }), { code: "authorization_device_untrusted" },
  "unsigned/untrusted remote ciphertext must never invoke the local pin-denial oracle");
  assert.deepEqual(await fsp.readFile(client.journal.filePath), journalBefore,
    "rejected B signature cannot consume admission slots");
  assert.deepEqual(await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"), "authenticated remote bytes");
  adapter.list = async (objectId) => objectId === undefined ? [valid] : originalList(objectId);
  await assert.rejects(client.pullRemote({ pushed: 0, pulled: 0, applied: 0,
    conflicts: [], offline: false }), { code: "file_pinned" },
  "a genuinely signed A MOVE is still denied by the physical pinned-origin guard");
  assert.deepEqual(await fsp.readFile(client.journal.filePath), journalBefore,
    "valid but pin-blocked MOVE must not consume admission slots either");
  assert.equal(state.pushes, 0);
});

test("issue 66 #292 P1: untrusted 409 conflict current cannot probe pinned origin before Ed25519 authentication", async (t) => {
  const { rootDir, open, remote, adapter, trusted, state } = await fixture(t);
  await (await open()).pinLocal("docs/a.txt");
  const client = await open([], true, false, ["docs"]);
  const pending = await remote("create", "object-a", "docs/pending.txt", "local signed pending", 1);
  assert.equal(await verifyAuthorizationProof(pending.authorization, pending, trusted), true);
  await client.journal.enqueue(pending);
  const winnerA = await remote("move", "object-a", "archive/a.txt",
    "authenticated remote bytes", 2, "docs/a.txt");
  assert.equal(await verifyAuthorizationProof(winnerA.authorization, winnerA, trusted), true);
  const rogue = crypto.generateKeyPairSync("ed25519");
  const rogueKey = rogue.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const winnerB = { ...winnerA, authorization: await createAuthorizationProof(winnerA, {
    username: "alice", privateKey: rogue.privateKey, publicKey: rogueKey,
    expiresAt: Date.now() + 60_000,
  }) };
  await assert.rejects(verifyAuthorizationProof(winnerB.authorization, winnerB, trusted),
    { code: "authorization_device_untrusted" });
  let outboundRequests = 0;
  adapter.push = async (operation) => {
    assert.equal(operation.operationId, pending.operationId);
    outboundRequests++;
    return { status: 409, current: winnerB, currentRevision: winnerB.revision };
  };
  const journalBefore = await fsp.readFile(client.journal.filePath);
  const indexFile = path.join(rootDir, ".rootark-sync-index.json");
  const indexBefore = await fsp.readFile(indexFile);
  const summary = () => ({ pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false });
  await assert.rejects(client.pushPending(summary()), { code: "authorization_device_untrusted" },
    "a forged B in a 409 reply must not reach file_pinned or remote-wins recovery");
  assert.equal(outboundRequests, 1, "the signed A pending operation was really dispatched once");
  assert.deepEqual(await fsp.readFile(client.journal.filePath), journalBefore,
    "untrusted conflict reply cannot consume signed pending or admission");
  assert.deepEqual(await fsp.readFile(indexFile), indexBefore);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes");
  assert.equal(fs.existsSync(path.join(rootDir, ".rootark-conflicts")), false,
    "untrusted conflict reply must not write recovery artifacts");
  adapter.push = async () => ({ status: 409, current: winnerA, currentRevision: winnerA.revision });
  await assert.rejects(client.pushPending(summary()), { code: "file_pinned" },
    "genuinely owner/device-signed A must retain physical pin protection");
  assert.deepEqual(await fsp.readFile(client.journal.filePath), journalBefore);
  assert.equal(state.pushes, 0);
});

test("issue 66 #292 P1: forged selected 409 winner cannot write recovery artifact before authorization", async (t) => {
  const { rootDir, open, remote, adapter, trusted } = await fixture(t);
  const client = await open([], true, false, ["docs"]);
  const localA = await remote("create", "object-local", "docs/local.txt", "signed local outbox", 1);
  await client.journal.enqueue(localA);
  const winnerA = await remote("create", "object-local", "docs/winner.txt",
    "authentic signed remote ciphertext", 1);
  assert.equal(await verifyAuthorizationProof(winnerA.authorization, winnerA, trusted), true,
    "positive control: a genuine A recipient/roster authorization verifies");
  const rogue = crypto.generateKeyPairSync("ed25519");
  const roguePublic = rogue.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const winnerB = { ...winnerA, authorization: await createAuthorizationProof(winnerA, {
    username: "alice", privateKey: rogue.privateKey, publicKey: roguePublic,
    expiresAt: Date.now() + 60_000,
  }) };
  await assert.rejects(verifyAuthorizationProof(winnerB.authorization, winnerB, trusted),
    { code: "authorization_device_untrusted" },
    "negative control: genuinely signed B must not inherit A trust");
  let dispatched = 0;
  adapter.push = async (operation) => {
    assert.equal(operation.operationId, localA.operationId);
    dispatched++;
    return { status: 409, current: winnerB, currentRevision: winnerB.revision };
  };
  const journalBefore = await fsp.readFile(client.journal.filePath);
  const snapshotPath = path.join(rootDir, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  const summary = { pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false };
  await assert.rejects(client.pushPending(summary), { code: "authorization_device_untrusted" },
    "untrusted selected winner is rejected locally, regardless of 409 server response");
  assert.equal(dispatched, 1, "signed local operation reached real 409 handler");
  assert.deepEqual(summary.conflicts, [],
    "forged remote winner may not record a successful conflict policy decision");
  assert.equal(fs.existsSync(path.join(rootDir, ".rootark-conflicts")), false,
    "unauthenticated winner may not force plaintext conflict-recovery artifact to disk");
  assert.deepEqual(await fsp.readFile(client.journal.filePath), journalBefore);
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(client.journal.hasSeen(localA.operationId), false,
    "forged 409 must not discard signed pending outbox");
});

test("issue 66 #292 P1: unsigned 409 without current winner keeps signed outbox for retry", async (t) => {
  const { rootDir, open, remote, adapter, trusted } = await fixture(t);
  const client = await open([], true, false, ["docs"]);
  const localA = await remote("create", "object-local", "docs/local.txt", "locally signed data", 1);
  assert.equal(await verifyAuthorizationProof(localA.authorization, localA, trusted), true,
    "positive control: pending operation has valid Ed25519 trusted device signature");
  await client.journal.enqueue(localA);
  let pushes = 0;
  adapter.push = async () => { pushes++; return { status: 409 }; };
  const journalBefore = await fsp.readFile(client.journal.filePath);
  const snapshotPath = path.join(rootDir, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  const summary = { pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false };
  await assert.rejects(client.pushPending(summary), { code: "remote_authorization_rejected" },
    "a bare 409 is not a cryptographically authenticated remote winner/receipt");
  assert.equal(pushes, 1, "pending signed A dispatched before 409");
  assert.deepEqual(summary.conflicts, []);
  assert.equal(fs.existsSync(path.join(rootDir, ".rootark-conflicts")), false);
  assert.deepEqual(await fsp.readFile(client.journal.filePath), journalBefore);
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(client.journal.hasSeen(localA.operationId), false,
    "unsigned 409 cannot consume the only pending copy of a signed operation");
});

test("issue 66 #292 P1: genuinely trusted but unrelated 409 winner cannot discard pending object", async (t) => {
  const { rootDir, open, remote, adapter, trusted } = await fixture(t);
  const client = await open([], true, false, ["docs"]);
  const pending = await remote("create", "object-local", "docs/local.txt", "signed local pending", 1);
  const unrelated = await remote("create", "object-foreign", "docs/foreign.txt", "signed foreign object", 1);
  assert.equal(await verifyAuthorizationProof(pending.authorization, pending, trusted), true);
  assert.equal(await verifyAuthorizationProof(unrelated.authorization, unrelated, trusted), true,
    "attacker replays a genuinely trusted A signature rather than forging B");
  assert.notEqual(unrelated.objectId, pending.objectId);
  assert.notEqual(unrelated.fileId, pending.fileId);
  await client.journal.enqueue(pending);
  const journalBefore = await fsp.readFile(client.journal.filePath);
  const snapshotPath = path.join(rootDir, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  let sent = 0;
  adapter.push = async (operation) => {
    assert.equal(operation.operationId, pending.operationId);
    sent += 1;
    return { status: 409, current: unrelated, currentRevision: unrelated.revision };
  };
  const summary = { pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false };
  await assert.rejects(client.pushPending(summary), { code: "remote_authorization_rejected" },
    "valid signature for foreign object is not a conflict authorization for local object");
  assert.equal(sent, 1, "the signed pending operation reached 409 handling");
  assert.deepEqual(summary.conflicts, []);
  assert.equal(summary.pushed, 0);
  assert.equal(fs.existsSync(path.join(rootDir, ".rootark-conflicts")), false,
    "unrelated winner must not dump local pending plaintext");
  assert.deepEqual(await fsp.readFile(client.journal.filePath), journalBefore,
    "replayed unrelated winner must not acknowledge/drop pending outbox");
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(client.journal.hasSeen(pending.operationId), false);
});

for (const winnerMode of ["signed pending echo", "signed prior revision replay"]) {
  test(`issue 66 #292 P1: unwitnessed 409 ${winnerMode} preserves signed outbox`, async (t) => {
    const { rootDir, open, remote, adapter, trusted } = await fixture(t);
    const client = await open([], true, false, ["docs"]);
    const prior = await remote("create", "object-local", "docs/local.txt", "prior signed bytes", 1);
    const pending = winnerMode === "signed pending echo" ? prior
      : await remote("update", "object-local", "docs/local.txt", "new signed bytes", 2);
    const claimedWinner = winnerMode === "signed pending echo" ? pending : prior;
    assert.equal(await verifyAuthorizationProof(pending.authorization, pending, trusted), true,
      "pending uses genuine enrolled Ed25519 A");
    assert.equal(await verifyAuthorizationProof(claimedWinner.authorization, claimedWinner, trusted), true,
      "server-supplied current has a valid genuine Ed25519 A signature too");
    assert.equal(claimedWinner.objectId, pending.objectId);
    assert.equal(claimedWinner.fileId, pending.fileId);
    assert.equal(claimedWinner.compartmentId, pending.compartmentId);
    await client.journal.enqueue(pending);
    const beforeJournal = await fsp.readFile(client.journal.filePath);
    const snapshotPath = path.join(rootDir, ".rootark-sync-index.json");
    const beforeSnapshot = await fsp.readFile(snapshotPath);
    let outbound = 0;
    adapter.push = async (operation) => {
      assert.equal(operation.operationId, pending.operationId);
      outbound++;
      return { status: 409, current: claimedWinner, currentRevision: claimedWinner.revision };
    };
    const summary = { pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false };
    await assert.rejects(client.pushPending(summary), { code: "remote_admission_unproven" },
      "signed remote ciphertext alone cannot prove the server committed the winner");
    assert.equal(outbound, 1, "the malicious HTTP 409 is reached through real signed push");
    assert.deepEqual(summary.conflicts, []);
    assert.equal(summary.pushed, 0);
    assert.equal(fs.existsSync(path.join(rootDir, ".rootark-conflicts")), false,
      "409 cannot create a plaintext recovery artifact before independent commitment evidence");
    assert.deepEqual(await fsp.readFile(client.journal.filePath), beforeJournal);
    assert.deepEqual(await fsp.readFile(snapshotPath), beforeSnapshot);
    assert.equal(client.journal.hasSeen(pending.operationId), false);
  });
}

test("issue 66 #292 P2: a real committed same-identity 409 cannot block disjoint push and pull", async (t) => {
  const { rootDir, open, remote, adapter, state, trusted } = await fixture(t);
  const client = await open([], true, false, ["docs"]);
  adapter.list = async (objectId) => objectId === undefined
    ? [...state.records.values()].map((record) => structuredClone(record))
    : [...state.records.values()].filter((record) => record.objectId === objectId)
      .map((record) => structuredClone(record));
  const summary = () => ({ pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false });
  await client.pullRemote(summary());
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes", "positive control: initial signed remote content is materialized");
  const initial = state.records.get("object-a");
  const pending = await remote("update", "object-a", "docs/a.txt", "local uncommitted bytes", 2);
  state.records.set("object-a", initial);
  const committedCurrent = await remote("update", "object-a", "docs/a.txt",
    "separately committed signed bytes", 2);
  assert.equal(await verifyAuthorizationProof(pending.authorization, pending, trusted), true);
  assert.equal(await verifyAuthorizationProof(committedCurrent.authorization, committedCurrent, trusted), true);
  assert.equal(pending.objectId, committedCurrent.objectId);
  assert.equal(pending.fileId, committedCurrent.fileId);
  assert.equal(pending.compartmentId, committedCurrent.compartmentId);
  assert.equal(protocol.compareRevisions(pending.baseRevision, initial.revision), 0);
  assert.equal(protocol.compareRevisions(committedCurrent.baseRevision, initial.revision), 0);
  assert.notEqual(pending.operationId, committedCurrent.operationId);
  assert.equal(state.records.get("object-a").operationId, committedCurrent.operationId,
    "the fake server really stores the other committed head, not just a replay in a 409 response");

  const unrelatedPending = await remote("create", "object-b", "docs/b.txt", "disjoint local bytes");
  state.records.delete("object-b");
  const unrelatedRemote = await remote("create", "object-c", "docs/c.txt", "disjoint remote bytes");
  assert.equal(await verifyAuthorizationProof(unrelatedRemote.authorization, unrelatedRemote, trusted), true);
  // Real local bytes accompany B's signed queued CREATE; a later scan must
  // not invent a missing-file DELETE just to satisfy the test.
  await fsp.writeFile(path.join(rootDir, "docs/b.txt"), "disjoint local bytes");
  const collidingPending = await remote("create", "object-d", "docs/a.txt", "foreign path collision");
  state.records.delete("object-d");
  await client.journal.enqueue(pending);
  await client.journal.enqueue(unrelatedPending);
  await client.journal.enqueue(collidingPending);
  const before = JSON.parse(await fsp.readFile(client.journal.filePath, "utf8"));
  let disputedPushes = 0;
  let independentPushes = 0;
  adapter.push = async (outgoing) => {
    if (outgoing.operationId === pending.operationId) {
      disputedPushes++;
      assert.equal(state.records.get("object-a").operationId, committedCurrent.operationId);
      return { status: 409, current: structuredClone(committedCurrent),
        currentRevision: committedCurrent.revision };
    }
    assert.equal(outgoing.operationId, unrelatedPending.operationId,
      "only a disjoint, independently signed outbox operation may pass the denied 409");
    independentPushes++;
    state.records.set("object-b", structuredClone(outgoing));
    return structuredClone(outgoing);
  };

  const first = await client.syncOnce();
  assert.equal(disputedPushes, 1, "real signed pending A was dispatched and received a 409");
  assert.equal(independentPushes, 1, "unrelated signed B must not be starved behind A");
  assert.equal(first.pushed, 1);
  assert.equal(first.pulled, 1, "a disjoint signed server C should still hydrate safely");
  assert.equal(first.offline, false);
  assert.equal(first.indeterminate, 1, "the unsafe-to-acknowledge 409 must remain explicitly unresolved");
  assert.deepEqual((await client.journal.recover()).map((item) => item.operationId),
    [pending.operationId, collidingPending.operationId],
    "A and a different object targeting the same path stay pending; B leaves normally");
  assert.equal(client.journal.hasSeen(committedCurrent.operationId), false,
    "the 409 winner must not become locally admitted from an untrusted LIST");
  assert.equal(client.journal.hasSeen(pending.operationId), false);
  const after = JSON.parse(await fsp.readFile(client.journal.filePath, "utf8"));
  assert.equal(after.observed[committedCurrent.operationId], undefined);
  assert.equal(after.admitted[committedCurrent.operationId], undefined);
  assert.deepEqual(after.pending.find((item) => item.operationId === pending.operationId),
    before.pending.find((item) => item.operationId === pending.operationId),
    "pending signed A remains byte-for-byte identical to its original durable envelope");
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes", "unwitnessed CURRENT cannot overwrite local content");
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/c.txt"), "utf8"),
    "disjoint remote bytes");
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/b.txt"), "utf8"),
    "disjoint local bytes");
  assert.equal(fs.existsSync(path.join(rootDir, ".rootark-conflicts")), false,
    "unwitnessed 409 cannot create plaintext conflict artifacts");

  const second = await client.syncOnce();
  assert.equal(second.indeterminate, 1);
  assert.equal(disputedPushes, 2, "the ambiguous signed A retries on the next cycle");
  assert.equal(independentPushes, 1, "already admitted disjoint B must not re-POST");
  assert.equal((await client.journal.recover()).length, 2);
});

test("issue 66 #292 P2: one-shot CLI reports unresolved CAS and cannot exit successfully", () => {
  const report = syncCycleReport({ pushed: 1, pulled: 1, conflicts: [], offline: false,
    indeterminate: 1 }, true);
  assert.deepEqual(report, { pushed: 1, pulled: 1, conflicts: 0, offline: false,
    indeterminate: 1 }, "deferred Files-On-Demand inventory must not be misreported as zero available");
  assert.throws(() => assertOneShotSyncComplete(report), { code: "remote_admission_unproven" },
    "a successful independent push must not conceal the unresolved signed 409 in --once");
  assert.doesNotThrow(() => assertOneShotSyncComplete(syncCycleReport({
    pushed: 1, pulled: 1, conflicts: [], offline: false, available: 3,
  }, true)));
  assert.deepEqual(syncCycleReport({ pushed: 0, pulled: 0, conflicts: [],
    offline: true }, true), { pushed: 0, pulled: 0, available: 0, conflicts: 0,
    offline: true }, "ordinary offline FOD cycles retain their preexisting available:0 field");
});

test("issue 66 #292 P2 FOD: manual hydration and restart cannot enter a signed-409 directory", async (t) => {
  const { rootDir, open, remote, adapter, state, trusted } = await fixture(t);
  state.records.delete("object-a");
  const dirRelative = "docs/managed-directory";
  const dir = await remote("create", "object-dir-a", dirRelative, "", 1,
    undefined, "inode/directory");
  const client = await open([], true, true, ["docs"]);
  await client.apply(dir);
  assert.equal((await fsp.stat(path.join(rootDir, dirRelative))).isDirectory(), true);
  assert.equal(client.snapshot.files[dirRelative].objectId, dir.objectId);

  const pendingA = await remote("update", "object-dir-a", dirRelative, "", 2,
    undefined, "inode/directory");
  state.records.set("object-dir-a", dir);
  const signedCurrent = await remote("update", "object-dir-a", dirRelative, "", 2,
    undefined, "inode/directory");
  assert.equal(await verifyAuthorizationProof(pendingA.authorization, pendingA, trusted), true);
  assert.equal(await verifyAuthorizationProof(signedCurrent.authorization, signedCurrent, trusted), true);
  const disputedChild = "docs/managed-directory/child.txt";
  const incomingChild = await remote("create", "object-child-b", disputedChild, "signed child bytes");
  assert.equal(await verifyAuthorizationProof(incomingChild.authorization, incomingChild, trusted), true);
  await client.journal.enqueue(pendingA);
  let signed409 = 0;
  adapter.push = async (operation) => {
    assert.equal(operation.operationId, pendingA.operationId,
      "no unrelated operation may be sent before signed A's 409");
    signed409++;
    return { status: 409, current: structuredClone(signedCurrent),
      currentRevision: signedCurrent.revision };
  };
  const summary = await client.syncOnce();
  assert.equal(signed409, 1);
  assert.equal(summary.indeterminate, 1);
  assert.equal(summary.available, undefined, "syncOnce must defer metadata inventory");
  assert.equal(state.inventoryReads, 0, "no metadata query within the ambiguous sync cycle");
  assert.equal((await client.journal.recover())[0].operationId, pendingA.operationId);

  // Explicit hydrate starts a separate entrypoint after syncOnce returned.
  // Inventory and the complete signed B envelope must actually be fetched.
  // The old exact-path-only pending fence could not catch directory ancestry.
  await assert.rejects(client.materializeRemote(disputedChild), {
    code: "sync_operation_pending",
  });
  assert.ok(state.inventoryReads > 0, "the separate hydration entrypoint really consulted inventory");
  assert.ok(state.fullReads.includes(incomingChild.objectId),
    "it also fetched the real signed B, not merely an invented path");
  assert.equal(fs.existsSync(path.join(rootDir, disputedChild)), false);
  assert.equal(client.journal.hasSeen(incomingChild.operationId), false);
  assert.deepEqual((await client.journal.recover()).map((entry) => entry.operationId),
    [pendingA.operationId]);

  const restarted = await open([], true, true, ["docs"]);
  const priorReads = state.fullReads.length;
  await assert.rejects(restarted.materializeRemote(disputedChild), {
    code: "sync_operation_pending",
  });
  assert.ok(state.fullReads.length > priorReads, "restart must re-read the signed B and durable A");
  assert.equal(fs.existsSync(path.join(rootDir, disputedChild)), false);
  assert.equal(restarted.journal.hasSeen(signedCurrent.operationId), false);
  assert.equal(restarted.journal.hasSeen(incomingChild.operationId), false);

  // The same pending A must not stall a genuinely unrelated signed file.
  const independent = await remote("create", "object-unrelated-c", "docs/unrelated.txt",
    "independent verified bytes");
  assert.equal(await restarted.materializeRemote("docs/unrelated.txt"), true);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/unrelated.txt"), "utf8"),
    "independent verified bytes");
  assert.equal(restarted.journal.hasSeen(independent.operationId), true);
  assert.deepEqual((await restarted.journal.recover()).map((entry) => entry.operationId),
    [pendingA.operationId], "independently admitted C cannot clear disputed signed A");
});

test("issue 66 #292 P2: remote-only tombstone cannot pre-observe across a signed-409 directory", async (t) => {
  const { rootDir, open, remote, adapter, state, trusted } = await fixture(t);
  state.records.delete("object-a");
  const dirRelative = "docs/managed-directory";
  const dir = await remote("create", "object-dir-a", dirRelative, "", 1,
    undefined, "inode/directory");
  const client = await open([], true, false, ["docs"]);
  await client.apply(dir);
  const pendingA = await remote("update", "object-dir-a", dirRelative, "", 2,
    undefined, "inode/directory");
  state.records.set("object-dir-a", dir);
  const signedCurrent = await remote("update", "object-dir-a", dirRelative, "", 2,
    undefined, "inode/directory");
  const childRelative = "docs/managed-directory/child.txt";
  await remote("create", "object-child-b", childRelative, "previous remote bytes");
  const incomingTombstone = await remote("delete", "object-child-b", childRelative, "", 2);
  assert.equal(incomingTombstone.tombstone, true);
  assert.equal(await verifyAuthorizationProof(incomingTombstone.authorization,
    incomingTombstone, trusted), true);
  client.rememberRemoteOnly(incomingTombstone, "excluded");
  await client.persistSnapshot();
  await client.journal.enqueue(pendingA);
  adapter.push = async (operation) => {
    assert.equal(operation.operationId, pendingA.operationId);
    return { status: 409, current: structuredClone(signedCurrent),
      currentRevision: signedCurrent.revision };
  };
  const summary = await client.syncOnce();
  assert.equal(summary.indeterminate, 1);
  assert.equal(client.journal.hasSeen(incomingTombstone.operationId), false);
  const beforeJournal = await fsp.readFile(client.journal.filePath);
  const beforeSnapshot = await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json"));
  const beforeRemoteOnly = structuredClone(client.snapshot.remoteOnly);

  // Non-FOD materializeRemote previously verified this signed tombstone,
  // pre-observed its admission and persisted remoteOnly BEFORE considering
  // whether a durable local A at the ancestor was still disputed.
  await assert.rejects(client.materializeRemote(childRelative), {
    code: "sync_operation_pending",
  });
  assert.ok(state.fullReads.includes(incomingTombstone.objectId),
    "the actual signed B tombstone must have been fetched");
  assert.deepEqual(await fsp.readFile(client.journal.filePath), beforeJournal,
    "no signed B admission pre-observation or A outbox discard is allowed");
  assert.deepEqual(await fsp.readFile(path.join(rootDir, ".rootark-sync-index.json")),
    beforeSnapshot, "no remote-only mutation may be persisted");
  assert.deepEqual(client.snapshot.remoteOnly, beforeRemoteOnly);
  assert.equal(client.journal.hasSeen(incomingTombstone.operationId), false);
  assert.deepEqual((await client.journal.recover()).map((item) => item.operationId),
    [pendingA.operationId]);
  assert.equal(fs.existsSync(path.join(rootDir, childRelative)), false);
});

test("issue 66 #292 P2 FOD Windows: physical 8.3 ancestor blocks manual hydration", async (t) => {
  if (process.platform !== "win32") {
    t.skip("Real 8.3 alias requires Windows");
    return;
  }
  const { rootDir, open, remote, adapter, state, trusted } = await fixture(t);
  state.records.delete("object-a");
  const dirRelative = "docs/longdirectoryname";
  const dir = await remote("create", "object-long-dir", dirRelative, "", 1,
    undefined, "inode/directory");
  const client = await open([], true, true, ["docs"]);
  await client.apply(dir);
  const longAbsolute = path.join(rootDir, dirRelative);
  const shortResult = spawnSync("cmd.exe", ["/d", "/q"], {
    input: `for %I in ("${longAbsolute}") do @echo %~sI\r\nexit\r\n`,
    encoding: "utf8",
  });
  const shortAbsolute = shortResult.stdout.trim().split(/\r?\n/).at(-1);
  if (shortResult.status !== 0 || !shortAbsolute || !path.basename(shortAbsolute).includes("~")
    || path.basename(shortAbsolute).toLowerCase() === path.basename(longAbsolute).toLowerCase()) {
    t.skip("The volume does not expose a usable 8.3 directory alias");
    return;
  }
  const originalStats = await fsp.stat(longAbsolute, { bigint: true });
  const aliasStats = await fsp.stat(shortAbsolute, { bigint: true });
  assert.equal(aliasStats.dev, originalStats.dev);
  assert.equal(aliasStats.ino, originalStats.ino, "verified physical 8.3 directory alias");
  assert.notEqual(originalStats.ino, 0n);
  assert.equal(fs.realpathSync.native(shortAbsolute).toLowerCase(),
    fs.realpathSync.native(longAbsolute).toLowerCase());

  const pendingA = await remote("update", "object-long-dir", dirRelative, "", 2,
    undefined, "inode/directory");
  state.records.set("object-long-dir", dir);
  const signedCurrent = await remote("update", "object-long-dir", dirRelative, "", 2,
    undefined, "inode/directory");
  assert.equal(await verifyAuthorizationProof(signedCurrent.authorization, signedCurrent, trusted), true);
  const childRelative = `docs/${path.basename(shortAbsolute)}/new-child.txt`;
  const incomingChild = await remote("create", "object-short-child", childRelative,
    "signed short-name child bytes");
  await client.journal.enqueue(pendingA);
  let conflictCalls = 0;
  adapter.push = async (operation) => {
    assert.equal(operation.operationId, pendingA.operationId);
    conflictCalls++;
    return { status: 409, current: structuredClone(signedCurrent),
      currentRevision: signedCurrent.revision };
  };
  const summary = await client.syncOnce();
  assert.equal(conflictCalls, 1);
  assert.equal(summary.indeterminate, 1);
  assert.equal(summary.available, undefined);
  await assert.rejects(client.materializeRemote(childRelative), {
    code: "sync_operation_pending",
  });
  assert.ok(state.fullReads.includes(incomingChild.objectId));
  assert.equal(fs.existsSync(path.join(rootDir, childRelative)), false);
  assert.equal(client.journal.hasSeen(incomingChild.operationId), false);
  assert.deepEqual((await client.journal.recover()).map((item) => item.operationId),
    [pendingA.operationId]);
});

test("issue 66 #292 P2: rotated fileId cannot abandon an older snapshot path after signed 409", async (t) => {
  const { rootDir, open, remote, adapter, state, trusted } = await fixture(t);
  const client = await open([], true, false, ["docs"]);
  adapter.list = async (objectId) => objectId === undefined
    ? [...state.records.values()].map((item) => structuredClone(item))
    : [...state.records.values()].filter((item) => item.objectId === objectId)
      .map((item) => structuredClone(item));
  await client.pullRemote({ pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false });
  const prior = state.records.get("object-a");
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes");
  assert.equal(client.snapshot.files["docs/a.txt"].fileId, prior.fileId);
  const rotatedFileId = "file-rotated-object-a";
  assert.notEqual(rotatedFileId, prior.fileId);
  // Construct genuine signed A envelopes, but deliberately rotate the same
  // object's fileId and rename its pending destination. The old local
  // snapshot identity must remain in A's quarantine scope.
  state.records.set("object-a", { ...prior, fileId: rotatedFileId });
  const pendingA = await remote("update", "object-a", "docs/new.txt", "new pending A", 2);
  state.records.set("object-a", { ...prior, fileId: rotatedFileId });
  const signedCurrent = await remote("update", "object-a", "docs/new.txt",
    "independently committed different A", 2);
  assert.equal(pendingA.fileId, rotatedFileId);
  assert.equal(signedCurrent.fileId, rotatedFileId);
  assert.equal(await verifyAuthorizationProof(signedCurrent.authorization, signedCurrent, trusted), true);
  assert.equal(await verifyAuthorizationProof(pendingA.authorization, pendingA, trusted), true);
  assert.notEqual(pendingA.metadata.path, "docs/a.txt");

  const pendingB = await remote("create", "object-old-path-b", "docs/a.txt", "unrelated B");
  state.records.delete("object-old-path-b");
  const incomingC = await remote("create", "object-old-path-c", "docs/a.txt", "unrelated C");
  assert.equal(await verifyAuthorizationProof(incomingC.authorization, incomingC, trusted), true);
  await client.journal.enqueue(pendingA);
  await client.journal.enqueue(pendingB);
  let deniedA = 0;
  let oldPathB = 0;
  adapter.push = async (operation) => {
    if (operation.operationId === pendingA.operationId) {
      deniedA++;
      return { status: 409, current: structuredClone(signedCurrent),
        currentRevision: signedCurrent.revision };
    }
    oldPathB++;
    return structuredClone(operation);
  };
  const summary = await client.syncOnce();
  assert.equal(deniedA, 1, "genuine same-object rotated signed A must reach the 409");
  assert.equal(oldPathB, 0,
    "distinct object B at OLD tracked pathname cannot POST after new-fileId A 409");
  assert.equal(summary.indeterminate, 1);
  assert.equal(summary.pushed, 0);
  assert.equal(summary.pulled, 0,
    "distinct signed C at old tracked pathname cannot be hydrated under unresolved 409");
  assert.deepEqual((await client.journal.recover()).map((item) => item.operationId),
    [pendingA.operationId, pendingB.operationId]);
  assert.equal(client.journal.hasSeen(signedCurrent.operationId), false);
  assert.equal(client.journal.hasSeen(incomingC.operationId), false);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes");
  assert.equal(fs.existsSync(path.join(rootDir, "docs/new.txt")), false);
  assert.equal(fs.existsSync(path.join(rootDir, ".rootark-conflicts")), false);
});

test("issue 66 #292 P2 POSIX: realpath delay cannot hide a late hardlink swap", {
  skip: process.platform === "win32",
}, async (t) => {
  const { rootDir, open, remote, adapter, state, trusted } = await fixture(t);
  const client = await open([], true, false, ["docs"]);
  const original = state.records.get("object-a");
  // The fixture's object-filtered LIST does not materialize on pullRemote().
  // Apply the real signed CREATE so the alias test exercises a tracked inode.
  await client.apply(original);
  const aPath = path.join(rootDir, "docs/a.txt");
  const bPath = path.join(rootDir, "docs/b.txt");
  const bContents = "separate local B before realpath";
  await fsp.writeFile(bPath, bContents);
  const initialB = await fsp.stat(bPath, { bigint: true });
  const pendingA = await remote("update", "object-a", "docs/a.txt", "uncommitted A", 2);
  state.records.set("object-a", original);
  const signedCurrent = await remote("update", "object-a", "docs/a.txt",
    "different committed A", 2);
  assert.equal(await verifyAuthorizationProof(signedCurrent.authorization, signedCurrent, trusted), true);
  const pendingB = await remote("create", "object-b", "docs/b.txt", bContents);
  state.records.delete("object-b");
  await client.journal.enqueue(pendingA);
  await client.journal.enqueue(pendingB);

  const originalRealpath = fsp.realpath;
  let swaps = 0;
  let realpathCalls = 0;
  let postsB = 0;
  adapter.push = async (operation) => {
    if (operation.operationId === pendingA.operationId) {
      // Install the deterministic hook only after reconcileLocal completed.
      t.mock.method(fsp, "realpath", async (target, ...options) => {
        realpathCalls++;
        if (target === bPath && swaps === 0) {
          const before = await fsp.lstat(bPath, { bigint: true });
          assert.equal(before.ino, initialB.ino,
            "B must first have been observed as physically distinct");
          await fsp.unlink(bPath);
          await fsp.link(aPath, bPath);
          const after = await fsp.lstat(bPath, { bigint: true });
          assert.notEqual(after.ino, before.ino,
            "a real hardlink replaced B between lstat and realpath");
          assert.equal(after.ino, (await fsp.lstat(aPath, { bigint: true })).ino);
          swaps++;
        }
        return originalRealpath(target, ...options);
      });
      return { status: 409, current: structuredClone(signedCurrent),
        currentRevision: signedCurrent.revision };
    }
    postsB++;
    return structuredClone(operation);
  };
  const summary = await client.syncOnce();
  assert.equal(swaps, 1, "realpath hook must perform the adversarial replacement");
  assert.ok(realpathCalls >= 1, "actual async scope realpath must have been reached");
  assert.equal(postsB, 0,
    "stale lstat identity must not let B POST after a realpath-time hardlink swap");
  assert.equal(summary.indeterminate, 1);
  assert.equal(summary.pushed, 0);
  assert.deepEqual((await client.journal.recover()).map((item) => item.operationId),
    [pendingA.operationId, pendingB.operationId]);
  assert.equal(client.journal.hasSeen(signedCurrent.operationId), false);
  assert.equal(await fsp.readFile(aPath, "utf8"), "authenticated remote bytes");
  assert.equal(await fsp.readFile(bPath, "utf8"), "authenticated remote bytes");
});

for (const aliasType of ["hardlink", "symlink"]) {
test(`issue 66 #292 P2 POSIX: real ${aliasType} alias cannot advance signed 409 push or pull`, {
  skip: process.platform === "win32",
}, async (t) => {
  const { rootDir, open, remote, adapter, state, trusted } = await fixture(t);
  const client = await open([], true, false, ["docs"]);
  const original = state.records.get("object-a");
  await client.apply(original);
  const aPath = path.join(rootDir, "docs/a.txt");
  const bPath = path.join(rootDir, "docs/b.txt");
  const dPath = path.join(rootDir, "docs/d.txt");
  assert.equal(await fsp.readFile(aPath, "utf8"), "authenticated remote bytes");

  // Pull uses the signed unscoped LIST, while this fixture's default
  // list(objectId) is one-object-only. Without the explicit LIST both E
  // and C disappear and the test cannot prove independent E progressed.
  const listOne = adapter.list.bind(adapter);
  adapter.list = async (objectId) => objectId === undefined
    ? [...state.records.values()] : listOne(objectId);

  const pendingA = await remote("update", "object-a", "docs/a.txt", "uncommitted A", 2);
  state.records.set("object-a", original);
  const signedCurrent = await remote("update", "object-a", "docs/a.txt",
    "independently committed A", 2);
  assert.equal(await verifyAuthorizationProof(signedCurrent.authorization, signedCurrent, trusted), true);
  const pendingB = await remote("create", "object-b", "docs/b.txt", "signed local B");
  state.records.delete("object-b");
  const pendingD = await remote("create", "object-d", "docs/d.txt", "truly unrelated D");
  state.records.delete("object-d");
  const incomingC = await remote("create", "object-c", "docs/b.txt", "signed remote C");
  const incomingE = await remote("create", "object-e", "docs/e.txt", "unrelated remote E");
  assert.equal(await verifyAuthorizationProof(incomingC.authorization, incomingC, trusted), true);
  assert.equal(await verifyAuthorizationProof(incomingE.authorization, incomingE, trusted), true);
  await fsp.writeFile(bPath, "signed local B");
  await fsp.writeFile(dPath, "truly unrelated D");
  const independentBefore = await fsp.stat(dPath, { bigint: true });
  await client.journal.enqueue(pendingA);
  await client.journal.enqueue(pendingB);
  await client.journal.enqueue(pendingD);

  let deniedA = 0;
  let aliasB = 0;
  let independentD = 0;
  adapter.push = async (operation) => {
    if (operation.operationId === pendingA.operationId) {
      deniedA++;
      // The hostile local replacement happens only AFTER syncOnce's
      // reconcileLocal scan. Before this point both files were independent,
      // so the physical scope guard itself must prevent the alias dispatch.
      await fsp.unlink(bPath);
      if (aliasType === "hardlink") await fsp.link(aPath, bPath);
      else await fsp.symlink(aPath, bPath);
      const a = await fsp.stat(aPath, { bigint: true });
      const b = await fsp.stat(bPath, { bigint: true });
      assert.equal(a.dev, b.dev);
      assert.equal(a.ino, b.ino, "real POSIX alias is installed before disjointness check");
      assert.notEqual(a.ino, 0n);
      if (aliasType === "hardlink") {
        assert.equal(a.nlink, 2n);
        assert.equal(b.nlink, 2n);
      } else {
        assert.equal((await fsp.lstat(bPath)).isSymbolicLink(), true);
      }
      return { status: 409, current: structuredClone(signedCurrent),
        currentRevision: signedCurrent.revision };
    }
    if (operation.operationId === pendingB.operationId) {
      aliasB++;
      return structuredClone(operation);
    }
    assert.equal(operation.operationId, pendingD.operationId);
    independentD++;
    state.records.set("object-d", structuredClone(operation));
    return structuredClone(operation);
  };

  const summary = await client.syncOnce();
  assert.equal(deniedA, 1, "genuine signed A must reach the ambiguous 409");
  assert.equal(aliasB, 0, "signed B must not POST into A's physical inode through an alias");
  assert.equal(independentD, 1, "physically disjoint D must remain usable on POSIX");
  assert.equal(summary.indeterminate, 1);
  assert.equal(summary.pushed, 1);
  assert.equal(summary.pulled, 1, "independent signed remote E must still hydrate");
  assert.deepEqual((await client.journal.recover()).map((entry) => entry.operationId),
    [pendingA.operationId, pendingB.operationId],
    "uncertain A and its physically aliased B stay durably queued");
  assert.equal(client.journal.hasSeen(signedCurrent.operationId), false);
  assert.equal(client.journal.hasSeen(incomingC.operationId), false,
    "untrusted LIST C must not admit the alias to A's disputed physical file");
  assert.equal((await fsp.stat(dPath, { bigint: true })).ino, independentBefore.ino);
  assert.equal(await fsp.readFile(aPath, "utf8"), "authenticated remote bytes");
  assert.equal(await fsp.readFile(bPath, "utf8"), "authenticated remote bytes");
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/e.txt"), "utf8"), "unrelated remote E");
  assert.equal(fs.existsSync(path.join(rootDir, ".rootark-conflicts")), false);
});
}

test("issue 66 #292 P2 Windows: unavailable or rejecting native reparse probe cannot grant disjointness", {
  skip: process.platform !== "win32",
}, async (t) => {
  const { rootDir, open, remote, adapter, state, trusted } = await fixture(t);
  const client = await open([], true, false, ["docs"]);
  const original = state.records.get("object-a");
  await client.apply(original);
  const listOne = adapter.list.bind(adapter);
  adapter.list = async (objectId) => objectId === undefined
    ? [...state.records.values()] : listOne(objectId);
  const pendingA = await remote("update", "object-a", "docs/a.txt", "uncommitted A", 2);
  state.records.set("object-a", original);
  const signedCurrent = await remote("update", "object-a", "docs/a.txt",
    "independently committed A", 2);
  assert.equal(await verifyAuthorizationProof(signedCurrent.authorization, signedCurrent, trusted), true);
  const pendingB = await remote("create", "object-b", "docs/b.txt", "separate B");
  state.records.delete("object-b");
  const incomingC = await remote("create", "object-c", "docs/c.txt", "separate C");
  await fsp.writeFile(path.join(rootDir, "docs/b.txt"), "separate B");
  const a = await fsp.stat(path.join(rootDir, "docs/a.txt"), { bigint: true });
  const b = await fsp.stat(path.join(rootDir, "docs/b.txt"), { bigint: true });
  assert.notEqual(a.ino, b.ino, "the deliberately disjoint files must have distinct file IDs");
  await client.journal.enqueue(pendingA);
  await client.journal.enqueue(pendingB);

  let probes = 0;
  // Simulate the native verifier's ReparsePoint exit (code 4), not a
  // fabricated reparse inode. A genuine generic OneDrive/ProjFS fixture
  // requires platform facilities not assumed available to the test host.
  t.mock.method(childProcess, "execFile", (_file, args, _options, callback) => {
    probes++;
    assert.equal(args.includes("-EncodedCommand"), true,
      "paths must be encoded, not evaluated as attacker-controlled PowerShell source");
    callback(Object.assign(new Error("native reparse attributes not safe"), { code: 4 }));
  });
  let disputedPushes = 0;
  let disjointPushes = 0;
  adapter.push = async (operation) => {
    if (operation.operationId === pendingA.operationId) {
      disputedPushes++;
      return { status: 409, current: structuredClone(signedCurrent),
        currentRevision: signedCurrent.revision };
    }
    disjointPushes++;
    return structuredClone(operation);
  };
  const summary = await client.syncOnce();
  assert.equal(disputedPushes, 1, "the signed conflict must trigger the physical scope probe");
  assert.ok(probes > 0, "native file-attribute verification must really be consulted");
  assert.equal(disjointPushes, 0, "UNKNOWN reparse status must not authorize even a distinct file");
  assert.equal(summary.indeterminate, 1);
  assert.equal(summary.pushed, 0);
  assert.equal(summary.pulled, 0, "uncertain native attributes must also block signed LIST");
  assert.deepEqual((await client.journal.recover()).map((entry) => entry.operationId),
    [pendingA.operationId, pendingB.operationId]);
  assert.equal(client.journal.hasSeen(signedCurrent.operationId), false);
  assert.equal(client.journal.hasSeen(incomingC.operationId), false);
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/a.txt"), "utf8"),
    "authenticated remote bytes");
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/b.txt"), "utf8"), "separate B");
  assert.equal(fs.existsSync(path.join(rootDir, ".rootark-conflicts")), false);
});

test("issue 66 #292 P2 Windows: real NTFS 8.3 alias cannot escape an unresolved signed 409", async (t) => {
  if (process.platform !== "win32") {
    t.skip("NTFS 8.3 aliases require Windows");
    return;
  }
  const { rootDir, open, remote, adapter, state, trusted } = await fixture(t);
  state.records.delete("object-a");
  const longRelative = "docs/longfilename.txt";
  const initial = await remote("create", "object-physical-a", longRelative, "signed original bytes");
  const client = await open([], true, false, ["docs"]);
  await client.apply(initial);
  const longAbsolute = path.join(rootDir, "docs", "longfilename.txt");
  assert.equal(await fsp.readFile(longAbsolute, "utf8"), "signed original bytes");
  // Ask Windows itself for the existing file's real short pathname, rather
  // than forging a tilde spelling that may not exist on this volume.
  const shortResult = spawnSync("cmd.exe", ["/d", "/q"], {
    input: `for %I in ("${longAbsolute}") do @echo %~sI\r\nexit\r\n`,
    encoding: "utf8",
  });
  const shortAbsolute = shortResult.stdout.trim().split(/\r?\n/).at(-1);
  if (shortResult.status !== 0 || !shortAbsolute
    || !path.basename(shortAbsolute).includes("~")
    || path.basename(shortAbsolute).toLowerCase() === path.basename(longAbsolute).toLowerCase()) {
    t.skip("The runtime volume does not expose an 8.3 short filename");
    return;
  }
  const longStat = await fsp.stat(longAbsolute, { bigint: true });
  const shortStat = await fsp.stat(shortAbsolute, { bigint: true });
  assert.equal(shortStat.dev, longStat.dev);
  assert.equal(shortStat.ino, longStat.ino);
  assert.notEqual(shortStat.ino, 0n, "physical alias needs a stable NTFS file ID");
  const shortRelative = `docs/${path.basename(shortAbsolute)}`;
  assert.notEqual(shortRelative.toLowerCase(), longRelative.toLowerCase());
  assert.equal(fs.realpathSync.native(shortAbsolute).toLowerCase(),
    fs.realpathSync.native(longAbsolute).toLowerCase(),
    "the Windows short name must resolve to exactly the same physical file");

  const pendingA = await remote("update", "object-physical-a", longRelative, "uncommitted A", 2);
  state.records.set("object-physical-a", initial);
  const signedCurrent = await remote("update", "object-physical-a", longRelative,
    "different committed A", 2);
  assert.equal(await verifyAuthorizationProof(signedCurrent.authorization, signedCurrent, trusted), true);
  const pendingAlias = await remote("create", "object-foreign-push", shortRelative, "foreign push bytes");
  state.records.delete("object-foreign-push");
  const incomingAlias = await remote("create", "object-foreign-pull", shortRelative, "foreign pull bytes");
  assert.equal(await verifyAuthorizationProof(incomingAlias.authorization, incomingAlias, trusted), true);
  const listOne = adapter.list.bind(adapter);
  adapter.list = async (objectId) => objectId === undefined
    ? [...state.records.values()] : listOne(objectId);
  await client.journal.enqueue(pendingA);
  await client.journal.enqueue(pendingAlias);
  const beforePending = (await client.journal.recover()).map((item) => item.operationId);
  let disputedPushes = 0;
  let aliasPushes = 0;
  adapter.push = async (operation) => {
    if (operation.operationId === pendingA.operationId) {
      disputedPushes++;
      return { status: 409, current: structuredClone(signedCurrent),
        currentRevision: signedCurrent.revision };
    }
    aliasPushes++;
    return structuredClone(operation);
  };
  const summary = await client.syncOnce();
  assert.equal(disputedPushes, 1, "the real signed A must actually reach the 409");
  assert.equal(aliasPushes, 0,
    "different signed B cannot POST to A's identical physical NTFS file via its 8.3 alias");
  assert.equal(summary.indeterminate, 1);
  assert.equal(summary.pushed, 0);
  assert.equal(summary.pulled, 0,
    "untrusted signed LIST C cannot hydrate the same physical NTFS file under its 8.3 name");
  assert.deepEqual((await client.journal.recover()).map((item) => item.operationId), beforePending,
    "both signed pending envelopes remain available for independent reconciliation");
  assert.equal(client.journal.hasSeen(signedCurrent.operationId), false,
    "signed CURRENT alone cannot become an admission receipt");
  assert.equal(client.journal.hasSeen(incomingAlias.operationId), false);
  assert.equal(await fsp.readFile(longAbsolute, "utf8"), "signed original bytes",
    "neither the disputed CURRENT nor the alias must overwrite the verified local file");
  assert.equal(fs.existsSync(path.join(rootDir, ".rootark-conflicts")), false);
});

test("issue 66 #292 P2 Windows: 8.3 ancestor aliases block a missing child after signed 409", async (t) => {
  if (process.platform !== "win32") {
    t.skip("NTFS 8.3 directory aliases require Windows");
    return;
  }
  const { rootDir, open, remote, adapter, state, trusted } = await fixture(t);
  state.records.delete("object-a");
  const longDir = "docs/longdirectoryname";
  const initialDir = await remote("create", "object-long-dir", longDir, "", 1,
    undefined, "inode/directory");
  const client = await open([], true, false, ["docs"]);
  await client.apply(initialDir);
  const longAbsolute = path.join(rootDir, "docs", "longdirectoryname");
  assert.equal((await fsp.stat(longAbsolute)).isDirectory(), true);
  const shortResult = spawnSync("cmd.exe", ["/d", "/q"], {
    input: `for %I in ("${longAbsolute}") do @echo %~sI\r\nexit\r\n`,
    encoding: "utf8",
  });
  const shortAbsolute = shortResult.stdout.trim().split(/\r?\n/).at(-1);
  if (shortResult.status !== 0 || !shortAbsolute || !path.basename(shortAbsolute).includes("~")
    || path.basename(shortAbsolute).toLowerCase() === path.basename(longAbsolute).toLowerCase()) {
    t.skip("The runtime volume does not expose an 8.3 directory alias");
    return;
  }
  const canonical = fs.realpathSync.native(longAbsolute);
  assert.equal(fs.realpathSync.native(shortAbsolute).toLowerCase(), canonical.toLowerCase());
  const longStats = await fsp.stat(longAbsolute, { bigint: true });
  const shortStats = await fsp.stat(shortAbsolute, { bigint: true });
  assert.equal(shortStats.dev, longStats.dev);
  assert.equal(shortStats.ino, longStats.ino);
  assert.notEqual(longStats.ino, 0n);
  const missingChild = `docs/${path.basename(shortAbsolute)}/new-child.txt`;
  assert.equal(fs.existsSync(path.join(rootDir, missingChild)), false,
    "the child itself must be missing while its parent is a real 8.3 alias");

  const pendingDir = await remote("update", "object-long-dir", longDir, "", 2,
    undefined, "inode/directory");
  state.records.set("object-long-dir", initialDir);
  const signedCurrent = await remote("update", "object-long-dir", longDir, "", 2,
    undefined, "inode/directory");
  assert.equal(await verifyAuthorizationProof(signedCurrent.authorization, signedCurrent, trusted), true);
  const pendingChild = await remote("create", "object-child-push", missingChild, "unsent child bytes");
  state.records.delete("object-child-push");
  const incomingChild = await remote("create", "object-child-pull", missingChild, "untrusted child bytes");
  const listOne = adapter.list.bind(adapter);
  adapter.list = async (objectId) => objectId === undefined
    ? [...state.records.values()] : listOne(objectId);
  await client.journal.enqueue(pendingDir);
  await client.journal.enqueue(pendingChild);
  let rejectedDirPushes = 0;
  let childPushes = 0;
  adapter.push = async (operation) => {
    if (operation.operationId === pendingDir.operationId) {
      rejectedDirPushes++;
      return { status: 409, current: structuredClone(signedCurrent),
        currentRevision: signedCurrent.revision };
    }
    childPushes++;
    return structuredClone(operation);
  };
  const summary = await client.syncOnce();
  assert.equal(rejectedDirPushes, 1, "the signed directory operation must reach a real 409");
  assert.equal(childPushes, 0,
    "a missing child under the short directory alias overlaps the disputed physical directory");
  assert.equal(summary.indeterminate, 1);
  assert.equal(summary.pushed, 0);
  assert.equal(summary.pulled, 0);
  assert.deepEqual((await client.journal.recover()).map((item) => item.operationId),
    [pendingDir.operationId, pendingChild.operationId]);
  assert.equal(client.journal.hasSeen(signedCurrent.operationId), false);
  assert.equal(client.journal.hasSeen(incomingChild.operationId), false);
  assert.equal(fs.existsSync(path.join(rootDir, missingChild)), false,
    "the signed remote child must not be materialized through the short parent alias");
  assert.equal((await fsp.stat(longAbsolute)).isDirectory(), true);
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

test("issue 66 #292 P2 RED: rotated-fileId 409 winner quarantines same-object conflict without blocking disjoint sync", async (t) => {
  const { rootDir, open, remote, adapter, state } = await fixture(t);
  const client = await open([], true, false, ["docs"]);
  adapter.list = async (objectId) => objectId === undefined
    ? [...state.records.values()].map((record) => structuredClone(record))
    : [...state.records.values()].filter((record) => record.objectId === objectId)
      .map((record) => structuredClone(record));
  await client.pullRemote({ pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false });
  const initial = state.records.get("object-a");
  const pending = await remote("update", "object-a", "docs/a.txt", "local uncommitted bytes", 2);
  state.records.set("object-a", { ...initial, fileId: "file-rotated-a" });
  const committedCurrent = await remote("update", "object-a", "docs/a.txt",
    "rotated-fileId committed bytes", 2);
  assert.notEqual(pending.fileId, committedCurrent.fileId);
  assert.equal(pending.objectId, committedCurrent.objectId);
  assert.equal(pending.compartmentId, committedCurrent.compartmentId);

  const unrelatedPending = await remote("create", "object-b", "docs/b.txt", "disjoint local bytes");
  state.records.delete("object-b");
  const unrelatedRemote = await remote("create", "object-c", "docs/c.txt", "disjoint remote bytes");
  await fsp.writeFile(path.join(rootDir, "docs/b.txt"), "disjoint local bytes");
  await client.journal.enqueue(pending);
  await client.journal.enqueue(unrelatedPending);

  adapter.push = async (outgoing) => {
    if (outgoing.operationId === pending.operationId) {
      return { status: 409, current: structuredClone(committedCurrent),
        currentRevision: committedCurrent.revision };
    }
    state.records.set("object-b", structuredClone(outgoing));
    return structuredClone(outgoing);
  };

  const summary = await client.syncOnce();
  assert.equal(summary.pushed, 1);
  assert.equal(summary.pulled, 1);
  assert.equal(summary.indeterminate, 1);
  assert.deepEqual((await client.journal.recover()).map((item) => item.operationId),
    [pending.operationId]);
  assert.equal(client.journal.hasSeen(committedCurrent.operationId), false);
});

test("issue 66 #292 P2 RED: pending ancestor directory op blocks Files On-Demand tombstone reconciliation", async (t) => {
  const { rootDir, open, remote, adapter, state } = await fixture(t);
  const client = await open([], true, true, ["docs"]);
  adapter.list = async (objectId) => objectId === undefined
    ? [...state.records.values()].map((record) => structuredClone(record))
    : [...state.records.values()].filter((record) => record.objectId === objectId)
      .map((record) => structuredClone(record));
  await remote("create", "object-child", "docs/sub/child.txt", "cached child bytes", 1);
  await client.pullRemote({ pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false });
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/sub/child.txt"), "utf8"),
    "cached child bytes");

  const pendingDirOp = await remote("delete", "dir-sub", "docs/sub", "", 1);
  state.records.delete("dir-sub");
  await client.journal.enqueue(pendingDirOp);

  const childTombstone = await remote("delete", "object-child", "docs/sub/child.txt", "", 2);
  await assert.rejects(client.materializeRemote("docs/sub/child.txt"),
    { code: "sync_operation_pending" });
  assert.equal(await fsp.readFile(path.join(rootDir, "docs/sub/child.txt"), "utf8"),
    "cached child bytes", "tombstone must not delete child while ancestor directory op is pending");
  assert.equal(client.journal.hasSeen(childTombstone.operationId), false,
    "blocked tombstone must not be marked seen");
});
