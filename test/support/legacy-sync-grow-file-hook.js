"use strict";

// Adversarial fixture: grow the pinned inode after the first stat but before
// the caller reads it, and record any unbounded FileHandle.readFile call.
// The preloader also lives under test/support: default test discovery must
// neither mutate the host fs module nor require a private fixture environment.
function installGrowthFixture() {
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");

const target = process.env.ROOTARK_TEST_SYNC_GROW_PATH;
const marker = process.env.ROOTARK_TEST_SYNC_UNBOUNDED_READ_MARKER;
if (!target || !marker || !path.isAbsolute(target) || !path.isAbsolute(marker)) {
  throw Error("INVALID_SYNC_GROW_TEST_FIXTURE");
}
let grew = false;
const open = fsp.open;
fsp.open = async function (...args) {
  const handle = await open.apply(this, args);
  if (path.resolve(String(args[0])) !== target) return handle;
  const stat = handle.stat.bind(handle);
  handle.stat = async function (...statArgs) {
    const result = await stat(...statArgs);
    if (!grew) {
      grew = true;
      fs.appendFileSync(target, Buffer.alloc(12 * 1024 * 1024));
    }
    return result;
  };
  const readFile = handle.readFile.bind(handle);
  handle.readFile = async function (...readArgs) {
    fs.writeFileSync(marker, "readFile after growth");
    return readFile(...readArgs);
  };
  return handle;
};
}

const selected = process.env.ROOTARK_TEST_SYNC_GROW_FIXTURE;
if (selected === "1") installGrowthFixture();
else if (selected !== undefined || process.env.ROOTARK_TEST_SYNC_GROW_PATH
  || process.env.ROOTARK_TEST_SYNC_UNBOUNDED_READ_MARKER) {
  throw Error("INVALID_SYNC_GROW_TEST_INVOCATION");
}
