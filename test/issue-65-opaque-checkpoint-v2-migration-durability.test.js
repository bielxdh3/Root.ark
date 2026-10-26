"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { syncPrivateParent, publishStagedJournal } =
  require("../src/services/zk1V2DurableJournalMigration");

function setup(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-v2-fsync-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const source = path.join(dir, "legacy-129.sqlite");
  const original = crypto.randomBytes(1024);
  fs.writeFileSync(source, original, { mode: 0o600 });
  return { dir, source, original };
}

test("unsupported directory fsync cannot be treated as successful namespace durability", (t) => {
  const { dir } = setup(t);
  const target = path.join(dir, "destination.sqlite");
  if (process.platform === "win32") {
    assert.throws(() => syncPrivateParent(target), /EPERM|EACCES|EINVAL/,
      "native Windows must fail closed rather than accept a file-only fsync");
  } else {
    assert.doesNotThrow(() => syncPrivateParent(target),
      "private POSIX parent directory must provide a working fsync barrier");
  }
  assert.equal(fs.existsSync(target), false);
});

test("link publication demands ordered file/parent barriers and no-replace", (t) => {
  const { dir, source, original } = setup(t);
  const stage = path.join(dir, "stage.sqlite");
  const target = path.join(dir, "destination.sqlite");
  fs.writeFileSync(stage, crypto.randomBytes(4096), { mode: 0o600 });
  const originalFsync = fs.fsyncSync;
  const observed = [];
  try {
    // On Windows only, simulate a supported dir fsync to exercise the POSIX
    // ordering logic. This does not claim Windows has durable name publication.
    fs.fsyncSync = (fd) => {
      const directory = fs.fstatSync(fd).isDirectory();
      observed.push(directory ? "parent" : "file");
      if (!directory || process.platform !== "win32") originalFsync(fd);
    };
    const value = publishStagedJournal(stage, target, () => {
      assert.equal(fs.existsSync(stage), false);
      assert.equal(fs.existsSync(target), true);
      return "accepted";
    });
    assert.equal(value, "accepted");
    assert.deepEqual(observed, ["file", "parent", "parent", "parent"]);
    assert.deepEqual(fs.readFileSync(source), original);
    assert.equal(fs.existsSync(stage), false);
    assert.equal(fs.existsSync(target), true);
    const preexisting = fs.readFileSync(target);
    fs.writeFileSync(stage, crypto.randomBytes(512), { mode: 0o600 });
    assert.throws(() => publishStagedJournal(stage, target, () => "wrong"));
    assert.deepEqual(fs.readFileSync(target), preexisting);
  } finally { fs.fsyncSync = originalFsync; }
});

test("injected failure at every directory barrier refuses acknowledgment and rolls back published alias", (t) => {
  const { dir, source, original } = setup(t);
  const historicalWal = crypto.randomBytes(2048);
  const historicalShm = crypto.randomBytes(256);
  fs.writeFileSync(source + "-wal", historicalWal);
  fs.writeFileSync(source + "-shm", historicalShm);
  const actualFsync = fs.fsyncSync;
  for (const failAt of [1, 2, 3]) {
    const stage = path.join(dir, `stage-${failAt}.sqlite`);
    const target = path.join(dir, `destination-${failAt}.sqlite`);
    fs.writeFileSync(stage, crypto.randomBytes(512), { mode: 0o600 });
    let barriers = 0;
    let acknowledged = false;
    try {
      fs.fsyncSync = (fd) => {
        if (fs.fstatSync(fd).isDirectory()) {
          barriers++;
          if (barriers === failAt) throw Error(`INJECTED_DIRECTORY_FSYNC_${failAt}`);
          if (process.platform === "win32") return;
        }
        return actualFsync(fd);
      };
      assert.throws(() => publishStagedJournal(stage, target,
        () => { acknowledged = true; return "never"; }),
      new RegExp(`INJECTED_DIRECTORY_FSYNC_${failAt}`));
    } finally { fs.fsyncSync = actualFsync; }
    assert.equal(acknowledged, false);
    assert.equal(fs.existsSync(target), false,
      `published alias must be rolled back when barrier ${failAt} fails`);
    assert.deepEqual(fs.readFileSync(source), original,
      `legacy source must survive fault ${failAt}`);
    assert.deepEqual(fs.readFileSync(source + "-wal"), historicalWal);
    assert.deepEqual(fs.readFileSync(source + "-shm"), historicalShm);
    if (fs.existsSync(stage)) fs.unlinkSync(stage);
  }
});

test("failed post-publication reopen retracts only the new destination alias", (t) => {
  const { dir, source, original } = setup(t);
  const stage = path.join(dir, "stage.sqlite");
  const target = path.join(dir, "destination.sqlite");
  fs.writeFileSync(stage, crypto.randomBytes(1024), { mode: 0o600 });
  const real = fs.fsyncSync;
  try {
    fs.fsyncSync = (fd) => fs.fstatSync(fd).isDirectory() && process.platform === "win32"
      ? undefined : real(fd);
    assert.throws(() => publishStagedJournal(stage, target,
      () => { throw Error("INJECTED_REOPEN_FAILURE"); }), /INJECTED_REOPEN_FAILURE/);
  } finally { fs.fsyncSync = real; }
  assert.equal(fs.existsSync(target), false);
  assert.equal(fs.existsSync(stage), false);
  assert.deepEqual(fs.readFileSync(source), original);
});

test("simulated crash before hardlink publication preserves existing journal and refuses success", (t) => {
  const { dir, source, original } = setup(t);
  const stage = path.join(dir, "stage.sqlite");
  const target = path.join(dir, "fresh.sqlite");
  fs.writeFileSync(stage, crypto.randomBytes(1024), { mode: 0o600 });
  const realFsync = fs.fsyncSync;
  const realLink = fs.linkSync;
  try {
    fs.fsyncSync = (fd) => fs.fstatSync(fd).isDirectory() && process.platform === "win32"
      ? undefined : realFsync(fd);
    fs.linkSync = () => { throw Error("INJECTED_LINK_CRASH"); };
    assert.throws(() => publishStagedJournal(stage, target,
      () => { throw Error("SHOULD_NOT_BE_CALLED"); }), /INJECTED_LINK_CRASH/);
  } finally { fs.fsyncSync = realFsync; fs.linkSync = realLink; }
  assert.equal(fs.existsSync(target), false);
  assert.equal(fs.existsSync(stage), true);
  assert.deepEqual(fs.readFileSync(source), original);
});
