"use strict";

// Explicit NTFS LAB, not part of npm test or product runtime. Run with native
// executable built by build-held-link-win.cmd and Windows Node 22.
const assert = require("node:assert/strict");
const { spawn, execFileSync, execFile: execFileCallback } = require("node:child_process");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { promisify } = require("node:util");
const { test } = require("node:test");
const execFile = promisify(execFileCallback);

const binary = process.env.ROOTARK_NTFS_LINK_LAB_BINARY;
const rootParent = process.env.ROOTARK_NTFS_LINK_LAB_TMPDIR || path.join(__dirname, "lab-ntfs-runs");
const adversaryFile = path.join(__dirname, "held-link-win-adversary.cjs");
const originalBytes = "ORIGINAL SOURCE FSYNCED IN HELD NATIVE HANDLE";
const foreignBytes = "FOREIGN SAME-SID ADVERSARY REPLACEMENT BYTES";
assert.equal(process.platform, "win32", "Windows NTFS test only");
assert.ok(binary && fs.existsSync(binary), "ROOTARK_NTFS_LINK_LAB_BINARY must point to compiled native helper");
assert.equal(path.parse(path.resolve(rootParent)).root.toUpperCase(), "E:\\",
  "Synthetic fixtures MUST be on E: NTFS in this evidence run");

function sid() {
  const output = execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"],
    { encoding: "utf8" });
  const result = output.match(/S-\d(?:-\d+)+/);
  assert.ok(result, "real token SID must be observable");
  return result[0];
}

function physical(stat) { return [stat.dev, stat.ino]; }

async function fixture(t) {
  await fsp.mkdir(rootParent, { recursive: true });
  const root = await fsp.mkdtemp(path.join(rootParent, "held-link-disposable-"));
  const sourceDir = path.join(root, "src");
  const destinationDir = path.join(root, "destination");
  await fsp.mkdir(sourceDir);
  await fsp.mkdir(destinationDir);
  const sourcePath = path.join(sourceDir, "source.bin");
  const originalAlias = path.join(sourceDir, "original-retained.bin");
  const destinationName = "published.bin";
  const destinationPath = path.join(destinationDir, destinationName);
  const source = await fsp.open(sourcePath, "wx+");
  await source.writeFile(originalBytes);
  await source.sync();
  await source.close();
  t.after(async () => {
    // Test-owned, randomly named disposable fixtures ONLY. Native code never
    // deletes either name after an ambiguous publication.
    await fsp.rm(root, { recursive: true, force: true });
  });
  return { root, sourceDir, sourcePath, originalAlias,
    destinationDir, destinationPath, destinationName };
}

async function attack(f, replaceParent = false) {
  const args = [adversaryFile, f.sourcePath, f.originalAlias, foreignBytes];
  if (replaceParent) args.push(f.destinationDir,
    path.join(f.root, "retained-original-dir"));
  const { stdout, stderr } = await execFile(process.execPath, args);
  assert.equal(stderr, "");
  const actor = JSON.parse(stdout);
  assert.equal(actor.sid, sid(), "attacker second process must have same Windows SID");
  assert.notEqual(actor.pid, process.pid, "must run adversary in a separate process");
  assert.equal(await fsp.readFile(f.sourcePath, "utf8"), foreignBytes);
  assert.equal(await fsp.readFile(f.originalAlias, "utf8"), originalBytes);
  const original = await fsp.stat(f.originalAlias, { bigint: true });
  const foreign = await fsp.stat(f.sourcePath, { bigint: true });
  assert.notDeepEqual(physical(original), physical(foreign),
    "attacker must install a distinct real NTFS file ID");
  return { original, foreign, actor };
}

function start(f, basename = f.destinationName, extraEnv = {}) {
  const child = spawn(binary, [f.sourcePath, f.destinationDir, basename],
    { stdio: ["pipe", "pipe", "pipe"], windowsHide: true,
      env: { ...process.env, ...extraEnv } });
  let stdout = "", stderr = "", sawReady = false;
  let resolveReady, rejectReady;
  const ready = new Promise((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  const complete = new Promise((resolve, reject) => {
    child.stdout.on("data", data => {
      stdout += data.toString();
      // Windows CRT stdout in text mode writes CRLF; Linux writes LF.
      if (!sawReady && /READY\r?\n/.test(stdout)) {
        sawReady = true;
        resolveReady();
      }
    });
    child.stderr.on("data", data => { stderr += data.toString(); });
    child.once("error", error => { rejectReady(error); reject(error); });
    child.once("close", (code, signal) => {
      if (!sawReady) rejectReady(new Error(`native helper failed before READY: ${stderr}`));
      resolve({ code, signal, stdout, stderr });
    });
  });
  return { ready, complete, release: () => child.stdin.end("G"),
    abort: () => { child.stdin.end(); child.kill(); } };
}

function validPublishResult(result) {
  if (result.code === 0) {
    assert.match(result.stdout, /PUBLISHED same_fileid=1 source_flush=ok parent_flush=ok/);
    return "source+parent-flush-reported";
  }
  assert.equal(result.code, 85, result.stderr);
  assert.match(result.stderr, /stage=parent-flush.*published=1 durability=unknown/,
    "any other post-publication failure must not be called GREEN");
  return "source-flush-ok-parent-durability-unknown";
}

test("POSITIVE: native NTFS hardlink refers to already-flushed held source HANDLE", { timeout: 20000 }, async t => {
  const f = await fixture(t);
  const initial = await fsp.stat(f.sourcePath, { bigint: true });
  const helper = start(f);
  await helper.ready;
  helper.release();
  const result = await helper.complete;
  const checkpoint = validPublishResult(result);
  const actual = await fsp.stat(f.destinationPath, { bigint: true });
  assert.deepEqual(physical(actual), physical(initial));
  assert.equal(await fsp.readFile(f.destinationPath, "utf8"), originalBytes);
  assert.equal(await fsp.readFile(f.sourcePath, "utf8"), originalBytes);
  console.log("NTFS_POSITIVE_HELD_HANDLE checkpoint=" + checkpoint);
});

test("EXPECTED SECURITY RED: old fsp.link publishes second-process foreign source inode", { timeout: 20000 }, async t => {
  const f = await fixture(t);
  const { original, foreign } = await attack(f);
  await fsp.link(f.sourcePath, f.destinationPath);
  const published = await fsp.stat(f.destinationPath, { bigint: true });
  assert.deepEqual(physical(published), physical(foreign), "actual Win32 link re-resolves foreign source");
  assert.notDeepEqual(physical(published), physical(original));
  assert.equal(await fsp.readFile(f.destinationPath, "utf8"), foreignBytes);
  console.log("EXPECTED_SECURITY_RED_NTFS_FSP_LINK_FOREIGN_FILEID");
});

test("GREEN: held source HANDLE survives attacker second-process source pathname swap", { timeout: 20000 }, async t => {
  const f = await fixture(t);
  const helper = start(f);
  await helper.ready;
  const { original, foreign } = await attack(f);
  helper.release();
  const result = await helper.complete;
  const checkpoint = validPublishResult(result);
  const published = await fsp.stat(f.destinationPath, { bigint: true });
  assert.deepEqual(physical(published), physical(original), "native publishes opened file ID");
  assert.notDeepEqual(physical(published), physical(foreign));
  assert.equal(await fsp.readFile(f.destinationPath, "utf8"), originalBytes);
  assert.equal(await fsp.readFile(f.sourcePath, "utf8"), foreignBytes);
  console.log("NTFS_GREEN_HELD_SOURCE_FILEID checkpoint=" + checkpoint);
});

test("GREEN: held directory RootDirectory survives separate-process ancestor rename", { timeout: 20000 }, async t => {
  const f = await fixture(t);
  const helper = start(f);
  await helper.ready;
  const { original } = await attack(f, true);
  helper.release();
  const result = await helper.complete;
  const checkpoint = validPublishResult(result);
  const retainedPath = path.join(f.root, "retained-original-dir", f.destinationName);
  const published = await fsp.stat(retainedPath, { bigint: true });
  assert.deepEqual(physical(published), physical(original));
  await assert.rejects(fsp.lstat(f.destinationPath), { code: "ENOENT" },
    "decoy ancestor path must remain empty");
  assert.equal(await fsp.readFile(retainedPath, "utf8"), originalBytes);
  console.log("NTFS_GREEN_HELD_ROOT_DIRECTORY checkpoint=" + checkpoint);
});

test("NO-REPLACE: EEXIST preserves existing foreign destination and attack source", { timeout: 20000 }, async t => {
  const f = await fixture(t);
  await fsp.writeFile(f.destinationPath, "FOREIGN PREEXISTING DESTINATION", { flag: "wx" });
  const before = await fsp.stat(f.destinationPath, { bigint: true });
  const helper = start(f);
  await helper.ready;
  await attack(f);
  helper.release();
  const result = await helper.complete;
  assert.equal(result.code, 17, result.stderr);
  assert.match(result.stderr, /stage=no-replace win32=(80|183) published=0/);
  const after = await fsp.stat(f.destinationPath, { bigint: true });
  assert.deepEqual(physical(after), physical(before));
  assert.equal(await fsp.readFile(f.destinationPath, "utf8"), "FOREIGN PREEXISTING DESTINATION");
  assert.equal(await fsp.readFile(f.sourcePath, "utf8"), foreignBytes);
  assert.equal(await fsp.readFile(f.originalAlias, "utf8"), originalBytes);
  console.log("NTFS_GREEN_EEXIST_FOREIGN_DESTINATION_PRESERVED");
});

test("AMBIGUOUS CHECKPOINT: injected post-link flush failure never cleans uncertain names", { timeout: 20000 }, async t => {
  const f = await fixture(t);
  const helper = start(f, f.destinationName,
    { ROOTARK_LAB_FORCE_PARENT_FLUSH_FAILURE: "1" });
  await helper.ready;
  const { original, foreign } = await attack(f);
  helper.release();
  const result = await helper.complete;
  assert.equal(result.code, 85, result.stderr);
  assert.match(result.stderr,
    /stage=simulated-parent-flush win32=29 published=1 durability=unknown/);
  const published = await fsp.stat(f.destinationPath, { bigint: true });
  assert.deepEqual(physical(published), physical(original),
    "publisher reached native publication before deliberate checkpoint failure");
  assert.notDeepEqual(physical(published), physical(foreign));
  assert.equal(await fsp.readFile(f.destinationPath, "utf8"), originalBytes);
  assert.equal(await fsp.readFile(f.sourcePath, "utf8"), foreignBytes,
    "foreign replacement must never be unlinked by ambiguous cleanup");
  assert.equal(await fsp.readFile(f.originalAlias, "utf8"), originalBytes);
  console.log("NTFS_CHECKPOINT_INJECTED_UNKNOWN_PUBLISHED_NO_CLEANUP");
});

test("FAIL-CLOSED: invalid target basename rejected before mutation", { timeout: 20000 }, async t => {
  const f = await fixture(t);
  const result = await new Promise((resolve, reject) => {
    const child = spawn(binary, [f.sourcePath, f.destinationDir, "..\\escaped.bin"],
      { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    child.once("close", resolve);
    child.once("error", reject);
  });
  assert.equal(result, 2);
  await assert.rejects(fsp.lstat(path.join(f.root, "escaped.bin")), { code: "ENOENT" });
  await assert.rejects(fsp.lstat(f.destinationPath), { code: "ENOENT" });
});
