"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const script = path.resolve(__dirname, "../sync-client/rootark-sync-windows-cfapi-probe.ps1");
const powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const win = process.platform === "win32";

test("issue 66 CFAPI: sync-root lookup stays on the inspected open handle", async () => {
  const source = await fs.readFile(script, "utf8");
  // Before this fix the probe read FileAttributeTagInfo from a held handle,
  // then queried the sync-root status by a replaceable pathname. The probe
  // must use the same no-follow handle for both native observations.
  assert.match(source, /FILE_FLAG_OPEN_REPARSE_POINT/);
  assert.match(source, /GetFileInformationByHandleEx\(handle, 9, out tag, 8\)/);
  assert.match(source, /CfGetSyncRootInfoByHandle\(\s*SafeFileHandle handle,/);
  assert.match(source, /lookup = CfGetSyncRootInfoByHandle\(handle, 0, buffer, 8, out required\)/);
  assert.doesNotMatch(source, /\bCfGetSyncRootInfoByPath\s*\(/,
    "the open-handle proof must never fall back to a racy path lookup");
});

// Keep disposable probe fixtures after each run. Recursive pathname cleanup
// could delete a foreign subtree if a concurrent same-SID process replaced
// a scratch directory; no native retained-handle delete exists in this lab.

function run(args) {
  return spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-File", script, ...args], {
    encoding: "utf8", timeout: 25000, windowsHide: true,
  });
}

test("issue 66 CFAPI: the native probe requires an explicit opt-in", { skip: !win }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-") );
  const file = path.join(directory, "local.txt");
  await fs.writeFile(file, "ordinary local content");
  const result = run(["-LiteralPath", file]);
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout.trim(), "", "without opt-in no platform result is emitted");
  assert.equal(await fs.readFile(file, "utf8"), "ordinary local content");
});

test("issue 66 CFAPI: real Windows native inspection identifies an ordinary file without hydrating", { skip: !win }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-") );
  const file = path.join(directory, "ordinary.txt");
  const bytes = Buffer.from("preserve ordinary bytes");
  await fs.writeFile(file, bytes);
  // The probe must not mutate the original object. Keep its real file handle
  // pinned throughout the native call so the post-probe assertion never
  // reopens a pathname that another process could have replaced.
  const original = await fs.open(file, "r");
  t.after(() => original.close());
  const before = await original.stat();
  const result = run(["-AllowNativeProbe", "-LiteralPath", file]);
  assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
  const info = JSON.parse(result.stdout.trim());
  assert.equal(info.api, "Windows Cloud Files CFAPI");
  assert.equal(info.readOnly, true);
  assert.equal(info.nativeAvailable, true);
  assert.ok(info.platformBuild >= 16299, "CFAPI is supported on this Windows build");
  assert.equal(info.placeholder, false);
  assert.equal(info.syncRoot, false);
  assert.equal(info.placeholderState, 0);
  assert.equal(info.reparsePoint, false);
  assert.equal(info.syncRootLookupSucceeded, false);
  assert.deepEqual(await original.readFile(), bytes);
  const after = await original.stat();
  assert.equal(after.size, before.size);
  assert.equal(after.mtimeMs, before.mtimeMs);
});

test("issue 66 CFAPI: reparse-point inspection never follows the symlink target", { skip: !win }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-"));
  const target = path.join(directory, "target.txt");
  const link = path.join(directory, "link.txt");
  await fs.writeFile(target, "target is protected from modification");
  try { await fs.symlink(target, link, "file"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) { t.skip("Windows symlink privilege unavailable"); return; }
    throw error;
  }
  const result = run(["-AllowNativeProbe", "-LiteralPath", link]);
  assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
  const info = JSON.parse(result.stdout.trim());
  assert.equal(info.reparsePoint, true);
  assert.equal(info.placeholder, false);
  assert.equal(info.syncRootLookupSucceeded, false);
  assert.equal(await fs.readFile(target, "utf8"), "target is protected from modification");
});

test("issue 66 CFAPI: native probe fails closed for missing paths", { skip: !win }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-") );
  const result = run(["-AllowNativeProbe", "-LiteralPath", path.join(directory, "missing.txt")]);
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout.trim(), "");
});
