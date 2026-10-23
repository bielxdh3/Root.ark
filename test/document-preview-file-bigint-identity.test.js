const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { previewText } = require("../services/documentPreviewService");

test("preview rejects adjacent 64-bit file IDs that round to one Number", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-wide-id-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const requested = path.join(dir, "allowed.txt");
  const replacement = path.join(dir, "other.txt");
  fs.writeFileSync(requested, "safe");
  fs.writeFileSync(replacement, "leak");

  const checkedId = 9007199254740993n;
  const substitutedId = 9007199254740992n;
  assert.equal(Number(checkedId), Number(substitutedId), "PoC requires rounding collision");
  const originalLstat = fs.lstatSync;
  const originalFstat = fs.fstatSync;
  const originalOpen = fs.openSync;
  let redirected = false;
  fs.lstatSync = function (file, options) {
    const result = originalLstat.call(fs, file, options);
    if (file === requested) result.ino = options?.bigint ? checkedId : Number(checkedId);
    return result;
  };
  fs.openSync = function (file, ...args) {
    if (file === requested) { redirected = true; return originalOpen.call(fs, replacement, ...args); }
    return originalOpen.call(fs, file, ...args);
  };
  fs.fstatSync = function (fd, options) {
    const result = originalFstat.call(fs, fd, options);
    result.ino = options?.bigint ? substitutedId : Number(substitutedId);
    return result;
  };
  try {
    await assert.rejects(previewText(requested, "allowed.txt"), /PREVIEW_FILE_CHANGED/);
    assert.equal(redirected, true, "the attack must actually substitute the opened file");
  } finally {
    fs.lstatSync = originalLstat;
    fs.fstatSync = originalFstat;
    fs.openSync = originalOpen;
  }
});
