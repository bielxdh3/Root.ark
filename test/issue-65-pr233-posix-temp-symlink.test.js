"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createZk1PrivateCloudStagingDirectory } =
  require("../src/services/zk1PrivateCloudStagingDirectory");

test("POSIX cloud-copy, readback and signed-catalog staging resolve a linked TMPDIR safely", async (t) => {
  if (process.platform === "win32") return t.skip("POSIX-only TEMP ancestor behavior");
  const originalTemp = process.env.TMPDIR;
  const sandbox = fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()),
    "rootark-zk1-temp-parent-"));
  const real = path.join(sandbox, "real");
  const alias = path.join(sandbox, "alias");
  fs.mkdirSync(real, { mode: 0o700 });
  fs.symlinkSync(real, alias, "dir");
  t.after(() => fs.rmSync(sandbox, { recursive: true, force: true }));
  try {
    process.env.TMPDIR = alias;
    for (const prefix of ["rootark-zk1-cloud-copy-", "rootark-zk1-cloud-readback-",
      "zk1-signed-catalog-write-", "zk1-signed-catalog-read-"]) {
      const stage = await createZk1PrivateCloudStagingDirectory(prefix);
      try {
        assert.equal(path.dirname(stage), fs.realpathSync.native(real),
          "staging must use the physical canonical root, not the symlink alias");
        const stat = fs.lstatSync(stage);
        assert.equal(stat.isDirectory(), true);
        assert.equal(stat.isSymbolicLink(), false);
        assert.equal(stat.mode & 0o077, 0,
          "private POSIX staging directory must not permit group/other access");
      } finally { fs.rmSync(stage, { recursive: true, force: true }); }
    }
  } finally {
    if (originalTemp === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = originalTemp;
  }
});
