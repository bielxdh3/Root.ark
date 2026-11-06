"use strict";

// A concurrent creator may publish an existing database between the decision
// to bootstrap and our O_EXCL open. Do not trust a stale pathname probe, and
// never write to a competing, unverified SQLite authority.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { Zk1SyncAtomicRetainedAnchorDevOff } =
  require("../src/services/zk1SyncAtomicRetainedAnchorDevOff");
const { GENESIS } = require("../src/services/zk1SyncAtomicCasFloorLedgerDevOff");

function fixture(t) {
  const dir = createPrivateAuthorityFixture("zk65-codeql464-atomic-");
  const keys = crypto.generateKeyPairSync("ed25519");
  const scope = "codeql464:anchor";
  const options = {
    filename: path.join(dir, "anchor.sqlite"),
    bootstrapNew: true,
    signerPrivateKey: keys.privateKey,
    ownerBindings: [{ scope, accountId: crypto.randomUUID(),
      storeId: crypto.randomUUID() }],
    trustedMinimumHeads: [{ scope, sequence: 0, headHash: GENESIS }],
  };
  t.after(() => fs.rmSync(dir, { recursive: true, force: true,
    maxRetries: 10, retryDelay: 100 }));
  return { dir, options };
}

function withCompetingCreate(filename, publish, action) {
  const originalOpen = fs.openSync;
  let injected = false;
  fs.openSync = function (candidate, flags, ...args) {
    if (!injected && candidate === filename && typeof flags === "number"
      && (flags & fs.constants.O_CREAT) && (flags & fs.constants.O_EXCL)) {
      injected = true;
      publish();
    }
    return originalOpen.call(fs, candidate, flags, ...args);
  };
  try {
    action();
    assert.equal(injected, true, "the competing creator must win before O_EXCL");
  } finally { fs.openSync = originalOpen; }
}

test("CodeQL #464: concurrently published authenticated SQLite is validated, never overwritten", (t) => {
  const f = fixture(t);
  const seed = path.join(f.dir, "valid-seed.sqlite");
  const first = new Zk1SyncAtomicRetainedAnchorDevOff({
    ...f.options, filename: seed,
  });
  first.close();
  assert.equal(fs.existsSync(f.options.filename), false);
  const before = fs.readFileSync(seed);
  withCompetingCreate(f.options.filename,
    () => fs.copyFileSync(seed, f.options.filename), () => {
      const admitted = new Zk1SyncAtomicRetainedAnchorDevOff(f.options);
      admitted.close();
    });
  assert.equal(fs.readFileSync(f.options.filename).subarray(0, 16)
    .equals(before.subarray(0, 16)), true, "existing authority must remain SQLite");
});

test("CodeQL #464: concurrently planted foreign file is never adopted or modified", (t) => {
  const f = fixture(t);
  const foreign = Buffer.from("not-an-authorized-sqlite-database");
  withCompetingCreate(f.options.filename,
    () => fs.writeFileSync(f.options.filename, foreign,
      { flag: "wx", mode: 0o600 }), () => {
      assert.throws(() => new Zk1SyncAtomicRetainedAnchorDevOff(f.options),
        { code: "SYNC_ATOMIC_RETAINED_ANCHOR_DEV_OFF_DENIED" });
    });
  assert.deepEqual(fs.readFileSync(f.options.filename), foreign,
    "untrusted data must not receive a SQLite schema or WAL mutation");
  assert.equal(fs.existsSync(f.options.filename + "-wal"), false);
  assert.equal(fs.existsSync(f.options.filename + "-shm"), false);
});

test("CodeQL #464: existing SQLite is not processed as new directory bootstrap", {
  skip: process.platform !== "win32",
}, (t) => {
  const f = fixture(t);
  const initial = new Zk1SyncAtomicRetainedAnchorDevOff(f.options);
  initial.close();
  const native = require("../services/chunkUploadWindowsAcl");
  const originalBulkVerify = native.verifyWindowsChunkUploadTree;
  let unnecessaryBootstrapScans = 0;
  native.verifyWindowsChunkUploadTree = function (...args) {
    unnecessaryBootstrapScans++;
    return originalBulkVerify(...args);
  };
  try {
    const reopened = new Zk1SyncAtomicRetainedAnchorDevOff(f.options);
    reopened.close();
    assert.equal(unnecessaryBootstrapScans, 0,
      "existing signed SQLite needs only the fresh native authority check");
  } finally {
    native.verifyWindowsChunkUploadTree = originalBulkVerify;
  }
});

test("CodeQL #464: absent private directory is created under protected ancestry", (t) => {
  const f = fixture(t);
  const nested = path.join(f.dir, "new-private", "nested", "anchor.sqlite");
  assert.equal(fs.existsSync(path.dirname(nested)), false);
  const created = new Zk1SyncAtomicRetainedAnchorDevOff({
    ...f.options, filename: nested,
  });
  created.close();
  assert.equal(fs.existsSync(nested), true);
});
