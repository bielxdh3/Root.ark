"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { spawnSync } = require("node:child_process");
const { withPrivateWindowsTestTemp } = require("./support/issue-65-private-temp-environment");

const snapshot = () => ({ TEMP: process.env.TEMP, TMP: process.env.TMP });

test("positive Windows fixture uses its own disposable TEMP, inherited by a child", async () => {
  const before = snapshot();
  let root;
  const result = await withPrivateWindowsTestTemp(async () => {
    if (process.platform === "win32") {
      root = os.tmpdir();
      assert.equal(process.env.TEMP, root);
      assert.equal(process.env.TMP, root);
      assert.notEqual(root, before.TEMP);
      assert.match(path.basename(root), /^rootark-zk65-positive-temp-/);
      assert.ok(fs.statSync(root).isDirectory());
      const child = spawnSync(process.execPath, ["-e",
        "process.exit(require('node:os').tmpdir()===process.env.TEMP && process.env.TEMP===process.env.TMP?0:1)"],
        { timeout: 10000, windowsHide: true, stdio: "ignore" });
      assert.equal(child.status, 0);
    } else assert.deepEqual(snapshot(), before);
    return 42;
  });
  assert.equal(result, 42);
  assert.deepEqual(snapshot(), before);
  if (root) assert.equal(fs.existsSync(root), false);
});

test("fixture restores the environment even when a positive test fails", async () => {
  const before = snapshot();
  const failure = new Error("ordinary fixture error");
  let root;
  await assert.rejects(withPrivateWindowsTestTemp(async () => {
    if (process.platform === "win32") root = os.tmpdir();
    throw failure;
  }), (error) => error === failure);
  assert.deepEqual(snapshot(), before);
  if (root) assert.equal(fs.existsSync(root), false);
});

test("independent fixture calls cannot overlap process-wide Windows TEMP changes", async () => {
  const before = snapshot();
  await withPrivateWindowsTestTemp(async () => {
    const inside = snapshot();
    if (process.platform === "win32") {
      await assert.rejects(withPrivateWindowsTestTemp(() => 1), /CONCURRENT_PRIVATE_TEST_TEMP/);
      assert.deepEqual(snapshot(), inside);
    } else assert.equal(await withPrivateWindowsTestTemp(() => 1), 1);
  });
  assert.deepEqual(snapshot(), before);
});
