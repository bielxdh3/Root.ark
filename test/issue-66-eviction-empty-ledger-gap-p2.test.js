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
