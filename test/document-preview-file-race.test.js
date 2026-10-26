const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { MAX_INPUT_BYTES, previewText } = require("../services/documentPreviewService");

test("preview rejects a large replacement switched after the old file was checked (CodeQL #132)", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-race-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, "approved.txt");
  const parked = path.join(dir, "parked.txt");
  const replacement = path.join(dir, "replacement.txt");
  fs.writeFileSync(target, "ok");
  fs.writeFileSync(replacement, Buffer.alloc(MAX_INPUT_BYTES + 1, 0x78));

  const originalStat = fs.statSync;
  const originalLstat = fs.lstatSync;
  let swapped = false;
  const swapAfterCheck = (original, file, args) => {
    const checked = original.call(fs, file, ...args);
    if (file === target && !swapped) {
      swapped = true;
      fs.renameSync(target, parked);
      fs.renameSync(replacement, target);
    }
    return checked;
  };
  fs.statSync = function (file, ...args) { return swapAfterCheck(originalStat, file, args); };
  fs.lstatSync = function (file, ...args) { return swapAfterCheck(originalLstat, file, args); };
  try {
    await assert.rejects(previewText(target, "approved.txt"), /PREVIEW_TOO_LARGE/);
    assert.equal(swapped, true, "PoC must switch the file after the original size check");
  } finally {
    fs.statSync = originalStat;
    fs.lstatSync = originalLstat;
  }
});

test("preview rejects a same-sized replacement instead of exposing a different file", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-identity-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, "approved.txt");
  const parked = path.join(dir, "parked.txt");
  const replacement = path.join(dir, "replacement.txt");
  fs.writeFileSync(target, "old");
  fs.writeFileSync(replacement, "new");
  const originalStat = fs.statSync;
  const originalLstat = fs.lstatSync;
  let swapped = false;
  const swapAfterCheck = (original, file, args) => {
    const checked = original.call(fs, file, ...args);
    if (file === target && !swapped) {
      swapped = true;
      fs.renameSync(target, parked);
      fs.renameSync(replacement, target);
    }
    return checked;
  };
  fs.statSync = function (file, ...args) { return swapAfterCheck(originalStat, file, args); };
  fs.lstatSync = function (file, ...args) { return swapAfterCheck(originalLstat, file, args); };
  try {
    await assert.rejects(previewText(target, "approved.txt"), /PREVIEW_FILE_CHANGED/);
    assert.equal(swapped, true);
  } finally {
    fs.statSync = originalStat;
    fs.lstatSync = originalLstat;
  }
});
