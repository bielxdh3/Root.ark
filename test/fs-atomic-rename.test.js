"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { renameSyncWithWindowsEpermRetry } = require("../src/fs-atomic-rename");

function createFixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-atomic-rename-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return {
    source: path.join(directory, "replacement.tmp"),
    destination: path.join(directory, "state.json"),
  };
}

test("atomic Windows publication retries transient EPERM without removing the destination", (t) => {
  const { source, destination } = createFixture(t);
  fs.writeFileSync(source, "new state");
  fs.writeFileSync(destination, "previous state");
  const originalRenameSync = fs.renameSync;
  let calls = 0;
  let waits = 0;
  fs.renameSync = function (from, to, ...args) {
    calls += 1;
    assert.equal(fs.readFileSync(to, "utf8"), "previous state", "the committed destination remains visible until rename succeeds");
    if (calls === 1) throw Object.assign(new Error("injected transient EPERM"), { code: "EPERM" });
    return originalRenameSync.call(this, from, to, ...args);
  };
  t.after(() => { fs.renameSync = originalRenameSync; });

  renameSyncWithWindowsEpermRetry(source, destination, { platform: "win32", wait: () => { waits += 1; } });

  assert.equal(calls, 2);
  assert.equal(waits, 1);
  assert.equal(fs.readFileSync(destination, "utf8"), "new state");
  assert.equal(fs.existsSync(source), false);
});

test("atomic Windows publication stops after bounded EPERM retries and preserves both files", (t) => {
  const { source, destination } = createFixture(t);
  fs.writeFileSync(source, "unpublished state");
  fs.writeFileSync(destination, "previous state");
  const originalRenameSync = fs.renameSync;
  let calls = 0;
  let waits = 0;
  fs.renameSync = function () {
    calls += 1;
    throw Object.assign(new Error("injected persistent EPERM"), { code: "EPERM" });
  };
  t.after(() => { fs.renameSync = originalRenameSync; });

  assert.throws(
    () => renameSyncWithWindowsEpermRetry(source, destination, { platform: "win32", wait: () => { waits += 1; } }),
    { code: "EPERM" },
  );

  assert.equal(calls, 3);
  assert.equal(waits, 2);
  assert.equal(fs.readFileSync(destination, "utf8"), "previous state");
  assert.equal(fs.readFileSync(source, "utf8"), "unpublished state");
});

test("atomic publication retries only EPERM on Windows", (t) => {
  const { source, destination } = createFixture(t);
  fs.writeFileSync(source, "unpublished state");
  fs.writeFileSync(destination, "previous state");
  const originalRenameSync = fs.renameSync;
  let calls = 0;
  fs.renameSync = function () {
    calls += 1;
    throw Object.assign(new Error("injected rename error"), { code: "EACCES" });
  };
  t.after(() => { fs.renameSync = originalRenameSync; });

  assert.throws(
    () => renameSyncWithWindowsEpermRetry(source, destination, { platform: "win32", wait() { assert.fail("non-EPERM errors must not be retried"); } }),
    { code: "EACCES" },
  );
  assert.equal(calls, 1);
  assert.equal(fs.readFileSync(destination, "utf8"), "previous state");
  assert.equal(fs.readFileSync(source, "utf8"), "unpublished state");
});

test("atomic publication does not retry EPERM off Windows", (t) => {
  const { source, destination } = createFixture(t);
  fs.writeFileSync(source, "unpublished state");
  fs.writeFileSync(destination, "previous state");
  const originalRenameSync = fs.renameSync;
  let calls = 0;
  fs.renameSync = function () {
    calls += 1;
    throw Object.assign(new Error("injected rename EPERM"), { code: "EPERM" });
  };
  t.after(() => { fs.renameSync = originalRenameSync; });

  assert.throws(
    () => renameSyncWithWindowsEpermRetry(source, destination, { platform: "linux", wait() { assert.fail("non-Windows EPERM must not be retried"); } }),
    { code: "EPERM" },
  );
  assert.equal(calls, 1);
  assert.equal(fs.readFileSync(destination, "utf8"), "previous state");
  assert.equal(fs.readFileSync(source, "utf8"), "unpublished state");
});
