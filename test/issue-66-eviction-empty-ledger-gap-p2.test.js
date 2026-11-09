"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
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
    && path.resolve(args[1]) === path.join(root, ".rootark-trash",
      ".rootark-eviction-genesis-head.json")) {
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
