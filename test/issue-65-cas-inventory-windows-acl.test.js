"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { ensureWindowsChunkUploadRoot } =
  require("../services/chunkUploadWindowsAcl");
const { Zk1DurableCasStatusLedger } = require("../src/services/zk1DurableCasStatusLedger");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");
const { Zk1DurableContentInventoryLedger } =
  require("../src/services/zk1DurableContentInventoryLedger");
const { Zk1OpaqueCatalogCasLedger } =
  require("../src/services/zk1OpaqueCatalogCasLedger");
const { createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { Zk1V2CheckpointRemoteFloor } =
  require("../src/services/zk1V2CheckpointRemoteFloor");
const Database = require("better-sqlite3");

function fixture(t) {
  const root = createPrivateAuthorityFixture("rootark-cas-inventory-acl-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  return root;
}
function grantUsersModify(directory) {
  execFileSync("C:\\Windows\\System32\\icacls.exe", [
    directory, "/grant", "*S-1-5-32-545:(OI)(CI)M",
  ], { windowsHide: true, stdio: "ignore" });
}
function casOptions(root) {
  const status = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  return {
    bootstrapNew: true,
    statusKeyId: crypto.randomBytes(16),
    statusPrivateKey: status.privateKey,
    witnessPinned: { keyId: crypto.randomBytes(16), publicKey: witness.publicKey },
    anchorPath: path.join(root, "terminal.log"),
  };
}
function inventoryOptions(bootstrapNew) {
  return {
    bootstrapNew, signerKeyId: crypto.randomBytes(16),
    signerPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey,
    scope: { account_id: crypto.randomBytes(16),
      compartment_id: Buffer.from("main"), keyring_id: crypto.randomBytes(16) },
  };
}
function opaqueOptions() {
  const signing = crypto.generateKeyPairSync("ed25519");
  const catalog = crypto.generateKeyPairSync("ed25519");
  const floor = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("main"), keyring_id: crypto.randomBytes(16) };
  const independentFloor = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: "https://127.0.0.1:65534/", ca: Buffer.from("test"),
    clientKey: Buffer.from("test"), clientCert: Buffer.from("test"),
    serverFingerprint256: Array(32).fill("AA").join(":"),
    floorPublicKey: floor.publicKey, casSignerPublicKey: signing.publicKey,
    trustedScope: scope,
  });
  return { bootstrapNew: true, signingPrivateKey: signing.privateKey,
    catalogSignerPublicKey: catalog.publicKey, trustedScope: scope,
    minimumHead: { sequence: 0, digest: Buffer.alloc(32) }, independentFloor };
}
function v2FloorOptions() {
  const pairs = Array.from({ length: 4 }, () => crypto.generateKeyPairSync("ed25519"));
  return {
    bootstrapNew: true,
    scope: { account_id: crypto.randomBytes(16),
      compartment_id: Buffer.from("main"), keyring_id: crypto.randomBytes(16) },
    casPublicKey: pairs[0].publicKey, floorPublicKey: pairs[1].publicKey,
    ownerPublicKey: pairs[2].publicKey, witnessPrivateKey: pairs[3].privateKey,
    baseHeadDigest: crypto.randomBytes(32),
    baseCheckpointDigest: crypto.randomBytes(32),
  };
}

test("Windows CAS rejects Users Modify on bootstrap, restart and live reads", {
  skip: process.platform !== "win32",
}, async (t) => {
  const root = fixture(t);
  // A safe explicitly protected fixture is accepted before the DACL is weakened.
  const options = casOptions(root);
  const file = path.join(root, "cas.sqlite");
  const original = new Zk1DurableCasStatusLedger(file, options);
  original.close();
  const live = new Zk1DurableCasStatusLedger(file, { ...options, bootstrapNew: false });
  grantUsersModify(root);
  await assert.rejects(live.getCommittedHistoryPage({
    scope: { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("main"),
      keyring_id: crypto.randomBytes(16) }, startRevision: 1,
  }), /CAS_STATE_MISSING/);
  live.close();
  assert.throws(() => new Zk1DurableCasStatusLedger(file, {
    ...options, bootstrapNew: false,
  }), /CAS_STATE_MISSING|CAS_ANCHOR_INVALID/);
  const fresh = path.join(root, "new-cas.sqlite");
  assert.throws(() => new Zk1DurableCasStatusLedger(fresh, {
    ...options, anchorPath: path.join(root, "new-terminal.log"),
  }), /CAS_STATE_MISSING|CAS_ANCHOR_INVALID/);
  assert.equal(fs.existsSync(fresh), false);
  assert.equal(fs.existsSync(path.join(root, "new-terminal.log")), false);
});

test("Windows terminal anchor refuses Users Modify before bootstrap and restart", {
  skip: process.platform !== "win32",
}, (t) => {
  const root = fixture(t);
  const options = { bootstrapNew: true, statusKeyId: crypto.randomBytes(16),
    statusPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey };
  const file = path.join(root, "anchor.log");
  const anchor = new Zk1CasTerminalAnchor(file, options);
  assert.equal(anchor.headCheckpoint().sequence, 0);
  grantUsersModify(root);
  assert.throws(() => anchor.headCheckpoint(), /CAS_ANCHOR_INVALID/);
  assert.throws(() => new Zk1CasTerminalAnchor(file, {
    ...options, bootstrapNew: false,
  }), /CAS_ANCHOR_INVALID/);
  const fresh = path.join(root, "new-anchor.log");
  assert.throws(() => new Zk1CasTerminalAnchor(fresh, options), /CAS_ANCHOR_INVALID/);
  assert.equal(fs.existsSync(fresh), false);
});

test("Windows inventory refuses Users Modify on bootstrap and restart", {
  skip: process.platform !== "win32",
}, async (t) => {
  const root = fixture(t);
  const file = path.join(root, "inventory.sqlite");
  const options = inventoryOptions(true);
  const original = await Zk1DurableContentInventoryLedger.open(file, options);
  original.close();
  const live = await Zk1DurableContentInventoryLedger.open(file, {
    ...options, bootstrapNew: false,
  });
  grantUsersModify(root);
  await assert.rejects(live.readLocalHead(), /INVENTORY_STATE/);
  live.close();
  await assert.rejects(Zk1DurableContentInventoryLedger.open(file, {
    ...options, bootstrapNew: false,
  }), /INVENTORY_STATE/);
  const fresh = path.join(root, "new-inventory.sqlite");
  await assert.rejects(Zk1DurableContentInventoryLedger.open(fresh, {
    ...options, bootstrapNew: true,
  }), /INVENTORY_STATE/);
  assert.equal(fs.existsSync(fresh), false);
});

test("Windows inventory close fences native ACL verification pending on an older SQLite handle", {
  skip: process.platform !== "win32",
}, async (t) => {
  const root = fixture(t);
  const file = path.join(root, "closed-pending.sqlite");
  const ledger = await Zk1DurableContentInventoryLedger.open(file, inventoryOptions(true));
  let notifyEntered;
  const entered = new Promise((resolve) => { notifyEntered = resolve; });
  let release;
  // Model the boundary precisely: even an old successful native verdict cannot
  // authorize a SQLite read once its owner closed the underlying handle.
  ledger.privateAclVerifier.verify = () => new Promise((resolve) => {
    release = resolve;
    notifyEntered();
  });
  const pending = ledger.readLocalHead();
  await entered;
  ledger.close();
  release();
  await assert.rejects(pending, { code: "INVENTORY_CLOSED" });
  const reopened = await Zk1DurableContentInventoryLedger.open(file,
    { ...inventoryOptions(false), bootstrapNew: false,
      signerPrivateKey: ledger.privateKey, signerKeyId: ledger.signerKeyId,
      scope: ledger.scope });
  try { assert.equal((await reopened.readLocalHead()).sequence, 0); }
  finally { reopened.close(); }
});

test("Windows opaque catalog CAS rejects Users Modify on bootstrap and restart", {
  skip: process.platform !== "win32",
}, (t) => {
  const root = fixture(t);
  const file = path.join(root, "opaque.sqlite");
  const options = opaqueOptions();
  const original = new Zk1OpaqueCatalogCasLedger(file, options);
  original.ready.catch(() => {}); // unreachable fixture endpoint
  original.close();
  grantUsersModify(root);
  assert.throws(() => new Zk1OpaqueCatalogCasLedger(file, {
    ...options, bootstrapNew: false,
  }), /ZK_OPAQUE_CAS_UNAVAILABLE/);
  const fresh = path.join(root, "new-opaque.sqlite");
  assert.throws(() => new Zk1OpaqueCatalogCasLedger(fresh, options),
    /ZK_OPAQUE_CAS_UNAVAILABLE/);
  assert.equal(fs.existsSync(fresh), false);
});

test("Windows V2 checkpoint floor refuses Users Modify on bootstrap and restart", {
  skip: process.platform !== "win32",
}, (t) => {
  const root = fixture(t);
  const file = path.join(root, "v2-floor.sqlite");
  const options = v2FloorOptions();
  const first = new Zk1V2CheckpointRemoteFloor(file, options);
  first.close();
  grantUsersModify(root);
  assert.throws(() => new Zk1V2CheckpointRemoteFloor(file, {
    ...options, bootstrapNew: false,
  }), /ZK_V2_INDEPENDENT_FLOOR_DENIED/);
  const fresh = path.join(root, "new-v2-floor.sqlite");
  assert.throws(() => new Zk1V2CheckpointRemoteFloor(fresh, options),
    /ZK_V2_INDEPENDENT_FLOOR_DENIED/);
  assert.equal(fs.existsSync(fresh), false);
});

test("V2 checkpoint floor rejects foreign SQLite before WAL or schema writes", (t) => {
  const root = fixture(t);
  const file = path.join(root, "foreign-floor.sqlite");
  const foreign = new Database(file);
  foreign.exec("CREATE TABLE foreign_identity(id INTEGER PRIMARY KEY, marker TEXT)");
  foreign.prepare("INSERT INTO foreign_identity VALUES(1,'UNTOUCHED')").run();
  foreign.close();
  const digest = () => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  const before = digest();
  assert.throws(() => new Zk1V2CheckpointRemoteFloor(file, {
    ...v2FloorOptions(), bootstrapNew: false,
  }), /ZK_V2_INDEPENDENT_FLOOR_DENIED/);
  assert.equal(digest(), before, "foreign SQLite bytes must remain unchanged");
  const readonly = new Database(file, { readonly: true, fileMustExist: true });
  try {
    assert.deepEqual(readonly.prepare("SELECT name FROM sqlite_master WHERE type='table'").all(),
      [{ name: "foreign_identity" }]);
    assert.equal(readonly.prepare("SELECT marker FROM foreign_identity").get().marker, "UNTOUCHED");
  } finally { readonly.close(); }
});

function persistedFiles(filename) {
  return Object.fromEntries(["", "-wal", "-shm"].map((suffix) => {
    const name = filename + suffix;
    return [suffix || "db", fs.existsSync(name)
      ? crypto.createHash("sha256").update(fs.readFileSync(name)).digest("hex") : null];
  }));
}

test("Windows V2 rejects foreign WAL SQLite without altering existing SHM with live writer", {
  skip: process.platform !== "win32",
}, (t) => {
  const root = fixture(t);
  const file = path.join(root, "foreign-live-wal.sqlite");
  const writer = new Database(file);
  try {
    assert.equal(writer.pragma("journal_mode = WAL", { simple: true }), "wal");
    writer.exec("CREATE TABLE foreign_identity(id INTEGER PRIMARY KEY, marker TEXT)");
    writer.prepare("INSERT INTO foreign_identity VALUES(1,'UNTOUCHED')").run();
    assert.equal(fs.existsSync(file + "-wal"), true);
    assert.equal(fs.existsSync(file + "-shm"), true);
    const before = persistedFiles(file);
    assert.throws(() => new Zk1V2CheckpointRemoteFloor(file, {
      ...v2FloorOptions(), bootstrapNew: false,
    }), /ZK_V2_INDEPENDENT_FLOOR_DENIED/);
    assert.deepEqual(persistedFiles(file), before,
      "foreign main, WAL and existing SHM must remain bit identical");
    assert.equal(writer.prepare("SELECT marker FROM foreign_identity").get().marker, "UNTOUCHED");
  } finally { writer.close(); }
});

test("Windows V2 rejects orphan foreign WAL without creating missing SHM", {
  skip: process.platform !== "win32",
}, (t) => {
  const root = fixture(t);
  const file = path.join(root, "foreign-orphan-wal.sqlite");
  const child = String.raw`const Database=require("better-sqlite3");
const db=new Database(process.argv[1]);
db.pragma("journal_mode = WAL");
db.exec("CREATE TABLE foreign_identity(id INTEGER PRIMARY KEY, marker TEXT)");
db.prepare("INSERT INTO foreign_identity VALUES(1,'UNTOUCHED')").run();
process.exit(0);`;
  execFileSync(process.execPath, ["-e", child, file], { stdio: "pipe" });
  assert.equal(fs.existsSync(file + "-wal"), true);
  if (fs.existsSync(file + "-shm")) fs.unlinkSync(file + "-shm");
  assert.equal(fs.existsSync(file + "-shm"), false);
  const before = persistedFiles(file);
  assert.throws(() => new Zk1V2CheckpointRemoteFloor(file, {
    ...v2FloorOptions(), bootstrapNew: false,
  }), /ZK_V2_INDEPENDENT_FLOOR_DENIED/);
  assert.deepEqual(persistedFiles(file), before,
    "orphan WAL must remain unchanged and foreign SHM must stay absent");
});

test("Windows V2 reopens authentic WAL floor with uncheckpointed identity", {
  skip: process.platform !== "win32",
}, (t) => {
  const root = fixture(t);
  const file = path.join(root, "authentic-v2.sqlite");
  const options = v2FloorOptions();
  const original = new Zk1V2CheckpointRemoteFloor(file, options);
  try {
    assert.equal(fs.existsSync(file + "-wal"), true);
    assert.ok(fs.statSync(file + "-wal").size > 0, "bootstrap identity resides in WAL");
    const restarted = new Zk1V2CheckpointRemoteFloor(file, {
      ...options, bootstrapNew: false,
    });
    restarted.close();
  } finally { original.close(); }
});

test("Windows V2 reopens authentic orphan WAL with no preexisting SHM", {
  skip: process.platform !== "win32",
}, (t) => {
  const root = fixture(t);
  const file = path.join(root, "authentic-orphan-v2.sqlite");
  const options = v2FloorOptions();
  const original = new Zk1V2CheckpointRemoteFloor(file, options);
  const dbBytes = fs.readFileSync(file);
  const walBytes = fs.readFileSync(file + "-wal");
  assert.ok(walBytes.length > 32);
  original.close();
  // Restore the exact disposable pre-checkpoint state after SQLite's clean
  // close; a crashed authority can leave the same WAL with no WAL-index.
  fs.writeFileSync(file, dbBytes);
  fs.writeFileSync(file + "-wal", walBytes);
  fs.rmSync(file + "-shm", { force: true });
  assert.equal(fs.existsSync(file + "-shm"), false);
  const restarted = new Zk1V2CheckpointRemoteFloor(file, {
    ...options, bootstrapNew: false,
  });
  restarted.close();
});

test("Windows CAS and inventory reject a junction installed before admission without foreign writes", {
  skip: process.platform !== "win32",
}, async (t) => {
  const root = fixture(t);
  const outside = path.join(root, "foreign");
  fs.mkdirSync(outside);
  const sentinel = path.join(outside, "sentinel");
  fs.writeFileSync(sentinel, "FOREIGN-UNCHANGED");
  const junction = path.join(root, "replacement");
  fs.symlinkSync(outside, junction, "junction");
  const opts = casOptions(junction);
  assert.throws(() => new Zk1DurableCasStatusLedger(path.join(junction, "cas.sqlite"), opts),
    /CAS_STATE_MISSING/);
  assert.throws(() => new Zk1CasTerminalAnchor(path.join(junction, "anchor.log"),
    { bootstrapNew: true, statusKeyId: opts.statusKeyId,
      statusPrivateKey: opts.statusPrivateKey }), /CAS_ANCHOR_INVALID/);
  await assert.rejects(Zk1DurableContentInventoryLedger.open(
    path.join(junction, "inventory.sqlite"), inventoryOptions(true)), /INVENTORY_STATE/);
  assert.throws(() => new Zk1OpaqueCatalogCasLedger(
    path.join(junction, "opaque.sqlite"), opaqueOptions()), /ZK_OPAQUE_CAS_UNAVAILABLE/);
  assert.throws(() => new Zk1V2CheckpointRemoteFloor(
    path.join(junction, "v2-floor.sqlite"), v2FloorOptions()),
  /ZK_V2_INDEPENDENT_FLOOR_DENIED|UNTRUSTED_SQLITE_PATH/);
  assert.equal(fs.readFileSync(sentinel, "utf8"), "FOREIGN-UNCHANGED");
  for (const file of ["cas.sqlite", "terminal.log", "anchor.log", "inventory.sqlite",
    "opaque.sqlite", "v2-floor.sqlite"]) {
    assert.equal(fs.existsSync(path.join(outside, file)), false, file);
  }
});

test("Windows pre-open ancestor junction swap refuses CAS and V2 foreign writes", {
  skip: process.platform !== "win32",
}, (t) => {
  const root = fixture(t);
  const foreign = path.join(root, "foreign-target");
  ensureWindowsChunkUploadRoot(foreign);
  fs.writeFileSync(path.join(foreign, "sentinel"), "FOREIGN-INTACT");
  for (const [name, open] of [
    ["cas", (filename) => new Zk1DurableCasStatusLedger(filename,
      casOptions(path.dirname(filename)))],
    ["v2", (filename) => new Zk1V2CheckpointRemoteFloor(filename, v2FloorOptions())],
  ]) {
    const parent = path.join(root, name + "-candidate");
    const moved = path.join(root, name + "-moved");
    ensureWindowsChunkUploadRoot(parent);
    const target = path.join(parent, name + ".sqlite");
    const originalExists = fs.existsSync;
    let swapped = false;
    try {
      fs.existsSync = function (candidate) {
        const exists = originalExists.apply(this, arguments);
        if (!swapped && candidate === target) {
          swapped = true;
          fs.renameSync(parent, moved);
          fs.symlinkSync(foreign, parent, "junction");
        }
        return exists;
      };
      assert.throws(() => open(target), /CAS_STATE_MISSING|ZK_V2_INDEPENDENT_FLOOR_DENIED/);
    } finally {
      fs.existsSync = originalExists;
    }
    assert.equal(swapped, true);
    assert.equal(fs.existsSync(path.join(foreign, name + ".sqlite")), false);
  }
  assert.equal(fs.readFileSync(path.join(foreign, "sentinel"), "utf8"), "FOREIGN-INTACT");
});
