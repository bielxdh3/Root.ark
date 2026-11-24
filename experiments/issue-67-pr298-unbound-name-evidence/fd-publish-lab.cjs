"use strict";

// Node22 + g++ on Linux ext4 ONLY. Explicit LAB; never auto-run via npm test.
// Invocation: TMPDIR=/home/<user> node --test <this-file>
const assert = require("node:assert/strict");
const { spawn, execFile: execFileCallback } = require("node:child_process");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { promisify } = require("node:util");
const { test, before, after } = require("node:test");

const execFile = promisify(execFileCallback);
const sourceFile = path.join(__dirname, "fd-publish-linux.cpp");
const adversaryFile = path.join(__dirname, "fd-publish-adversary.cjs");
const ownedBytes = "ORIGINAL FSYNCED SYNTHETIC OWNER CONTENT";
const foreignBytes = "FOREIGN SYNTHETIC REPLACEMENT CONTENT";
let buildRoot, nativeBinary;

before(async () => {
  assert.equal(process.platform, "linux", "Linux-only descriptor publication LAB");
  assert.equal(fs.statfsSync(os.tmpdir()).type, 0xef53,
    "TMPDIR must be a native ext4-family filesystem, not NTFS drvfs/tmpfs");
  buildRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark67-fd-build-"));
  nativeBinary = path.join(buildRoot, "fd-publish-linux");
  const compiled = await execFile("g++", ["-std=c++20", "-O2", "-Wall", "-Wextra",
    "-Werror", sourceFile, "-o", nativeBinary]);
  assert.equal(compiled.stderr, "", "native helper compiled cleanly with -Werror");
  console.log(`LAB_COMPILER Linux Node=${process.version} source=${path.basename(sourceFile)}`);
});

after(async () => {
  if (buildRoot) await fsp.rm(buildRoot, { recursive: true, force: true });
});

async function fixture(t) {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark67-fd-evidence-"));
  const sourceDir = path.join(root, "source");
  const destinationDir = path.join(root, "destination");
  await fsp.mkdir(sourceDir);
  await fsp.mkdir(destinationDir);
  const sourcePath = path.join(sourceDir, "held-source.bin");
  const retainedPath = path.join(sourceDir, "retained-authentic.bin");
  const destinationName = "published.bin";
  const destinationPath = path.join(destinationDir, destinationName);
  const sourceFd = await fsp.open(sourcePath, fs.constants.O_RDWR | fs.constants.O_CREAT |
    fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  await sourceFd.writeFile(ownedBytes);
  await sourceFd.sync();
  const dirFd = await fsp.open(destinationDir,
    fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  t.after(async () => {
    await sourceFd.close();
    await dirFd.close();
    // Only disposable synthetic test fixtures are removed. Native publisher
    // never performs cleanup at source or destination names.
    await fsp.rm(root, { recursive: true, force: true });
  });
  return { root, sourceDir, destinationDir, destinationName, destinationPath,
    retainedPath, sourcePath, sourceFd, dirFd };
}

async function adversary(f, replaceAncestor = false) {
  const args = [adversaryFile, f.sourcePath, f.retainedPath, foreignBytes];
  if (replaceAncestor) args.push(f.destinationDir,
    path.join(f.root, "retained-original-directory"));
  const { stdout, stderr } = await execFile(process.execPath, args);
  assert.equal(stderr, "");
  const attack = JSON.parse(stdout);
  assert.notEqual(attack.pid, process.pid, "adversary must be a second process");
  assert.equal(attack.uid, process.getuid(), "adversary must be same UID");
  assert.deepEqual(await fsp.readFile(f.retainedPath, "utf8"), ownedBytes);
  assert.deepEqual(await fsp.readFile(f.sourcePath, "utf8"), foreignBytes);
  const original = await f.sourceFd.stat({ bigint: true });
  const retained = await fsp.lstat(f.retainedPath, { bigint: true });
  const foreign = await fsp.lstat(f.sourcePath, { bigint: true });
  assert.equal(original.ino, retained.ino, "held original source inode must survive rename");
  assert.notEqual(original.ino, foreign.ino, "attacker created another physical inode");
  assert.equal(foreign.ino.toString(), attack.ino);
  return { original, foreign, attack };
}

function startPublisher(f, name = f.destinationName) {
  const child = spawn(nativeBinary, [name], {
    stdio: ["pipe", "pipe", "pipe", f.sourceFd.fd, f.dirFd.fd],
  });
  let stdout = "", stderr = "", readySeen = false;
  let resolveReady, rejectReady;
  const ready = new Promise((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  const complete = new Promise((resolve, reject) => {
    child.stdout.on("data", (bytes) => {
      stdout += bytes.toString();
      if (!readySeen && stdout.includes("READY\n")) {
        readySeen = true;
        resolveReady();
      }
    });
    child.stderr.on("data", (bytes) => { stderr += bytes.toString(); });
    child.once("error", (error) => { rejectReady(error); reject(error); });
    child.once("close", (code, signal) => {
      if (!readySeen) rejectReady(new Error(`native helper closed before gate: ${stderr}`));
      resolve({ code, signal, stdout, stderr });
    });
  });
  return { ready, complete, release: () => child.stdin.end("G"),
    abort: () => { child.stdin.end(); child.kill(); } };
}

async function assertInodeEquals(left, right, description) {
  const a = typeof left === "string" ? await fsp.lstat(left, { bigint: true }) : left;
  const b = typeof right === "string" ? await fsp.lstat(right, { bigint: true }) : right;
  assert.deepEqual([a.dev, a.ino], [b.dev, b.ino], description);
}

test("POSITIVE native: publish only the already-fsynced held inode", async (t) => {
  const f = await fixture(t);
  const helper = startPublisher(f);
  await helper.ready;
  helper.release();
  const result = await helper.complete;
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /PUBLISHED mode=(AT_EMPTY_PATH|PROC_SELF_FD)/);
  assert.equal(await fsp.readFile(f.destinationPath, "utf8"), ownedBytes);
  const original = await f.sourceFd.stat({ bigint: true });
  await assertInodeEquals(f.destinationPath, original, "native link must refer to held source inode");
  assert.equal(original.nlink, 2n, "original source and published final are same inode");
  console.log("POSITIVE_FD_PUBLISH mode=" + result.stdout.trim().match(/mode=([^ ]+)/)[1]);
});

test("POSITIVE native: O_TMPFILE first attempts AT_EMPTY_PATH, reports fallback if denied", async (t) => {
  const f = await fixture(t);
  // asm-generic/fcntl.h: O_TMPFILE = __O_TMPFILE (020000000) | O_DIRECTORY.
  // Node 22 does not expose O_TMPFILE in fs.constants on this WSL build.
  const O_TMPFILE = 0o20000000 | fs.constants.O_DIRECTORY;
  const unnamed = await fsp.open(f.destinationDir, O_TMPFILE | fs.constants.O_RDWR, 0o600);
  t.after(() => unnamed.close());
  await unnamed.writeFile(ownedBytes);
  await unnamed.sync();
  const helper = startPublisher({ ...f, sourceFd: unnamed });
  await helper.ready;
  helper.release();
  const result = await helper.complete;
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /PUBLISHED mode=(AT_EMPTY_PATH|PROC_SELF_FD) at_empty_path_errno=\d+/);
  const source = await unnamed.stat({ bigint: true });
  await assertInodeEquals(f.destinationPath, source, "O_TMPFILE same inode published");
  assert.equal(source.nlink, 1n, "unnamed file gains first directory link");
  assert.equal(await fsp.readFile(f.destinationPath, "utf8"), ownedBytes);
  console.log("POSITIVE_OTMPFILE_PUBLISH " + result.stdout.trim().split("\n").pop());
});

test("EXPECTED SECURITY RED: after second process swaps pathname, real fsp.link publishes FOREIGN inode", async (t) => {
  const f = await fixture(t);
  const { original, foreign } = await adversary(f);
  await fsp.link(f.sourcePath, f.destinationPath);
  await assertInodeEquals(f.destinationPath, foreign, "RED: vulnerable path link publishes foreign inode");
  assert.notEqual((await fsp.lstat(f.destinationPath, { bigint: true })).ino, original.ino);
  assert.equal(await fsp.readFile(f.destinationPath, "utf8"), foreignBytes);
  assert.equal(await fsp.readFile(f.retainedPath, "utf8"), ownedBytes);
  console.log("EXPECTED_SECURITY_RED_SECOND_PROCESS_FSP_LINK_FOREIGN_INODE");
});

test("GREEN native: linkat through held FD survives same-UID source pathname replacement", async (t) => {
  const f = await fixture(t);
  const helper = startPublisher(f);
  await helper.ready;
  const { original, foreign } = await adversary(f);
  helper.release();
  const result = await helper.complete;
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /PUBLISHED mode=(AT_EMPTY_PATH|PROC_SELF_FD)/);
  await assertInodeEquals(f.destinationPath, original, "GREEN: retained FD pins source identity");
  assert.notEqual((await fsp.lstat(f.destinationPath, { bigint: true })).ino, foreign.ino);
  assert.equal(await fsp.readFile(f.destinationPath, "utf8"), ownedBytes);
  assert.equal(await fsp.readFile(f.sourcePath, "utf8"), foreignBytes,
    "foreign replacement must remain untouched; NO pathname cleanup");
  assert.equal(await fsp.readFile(f.retainedPath, "utf8"), ownedBytes);
  console.log("GREEN_FD_PUBLISH_SECOND_PROCESS_ORIGINAL_INODE mode=" +
    result.stdout.trim().match(/mode=([^ ]+)/)[1]);
});

test("GREEN held destination dirfd: pathname ancestor replaced by second process", async (t) => {
  const f = await fixture(t);
  const helper = startPublisher(f);
  await helper.ready;
  const { original } = await adversary(f, true);
  helper.release();
  const result = await helper.complete;
  assert.equal(result.code, 0, result.stderr);
  const publishedAt = path.join(f.root, "retained-original-directory", f.destinationName);
  await assertInodeEquals(publishedAt, original, "held destination dirfd targets original directory");
  await assert.rejects(fsp.lstat(f.destinationPath), { code: "ENOENT" },
    "attacker decoy destination namespace must remain untouched");
  assert.equal(await fsp.readFile(publishedAt, "utf8"), ownedBytes);
  console.log("GREEN_FD_PUBLISH_HELD_DIRFD_REPLACED_ANCESTOR");
});

test("NO-CLOBBER: existing destination survives foreign source replacement", async (t) => {
  const f = await fixture(t);
  const existingBytes = "EXISTING DESTINATION MUST SURVIVE";
  await fsp.writeFile(f.destinationPath, existingBytes, { flag: "wx" });
  const before = await fsp.lstat(f.destinationPath, { bigint: true });
  const helper = startPublisher(f);
  await helper.ready;
  await adversary(f);
  helper.release();
  const result = await helper.complete;
  assert.equal(result.code, 17, result.stderr);
  assert.match(result.stderr, /action=no-replace errno=17/);
  await assertInodeEquals(f.destinationPath, before, "existing inode must never be overwritten");
  assert.equal(await fsp.readFile(f.destinationPath, "utf8"), existingBytes);
  assert.equal(await fsp.readFile(f.sourcePath, "utf8"), foreignBytes);
  assert.equal(await fsp.readFile(f.retainedPath, "utf8"), ownedBytes);
  console.log("GREEN_FD_PUBLISH_EEXIST_NO_CLOBBER_NO_UNLINK");
});

test("FAIL-CLOSED: basename cannot contain traversal or path separators", async (t) => {
  const f = await fixture(t);
  const child = spawn(nativeBinary, ["../escaped"],
    { stdio: ["ignore", "pipe", "pipe", f.sourceFd.fd, f.dirFd.fd] });
  const result = await new Promise((resolve) => child.once("close", resolve));
  assert.equal(result, 2);
  await assert.rejects(fsp.lstat(path.join(f.root, "escaped")), { code: "ENOENT" });
  await assert.rejects(fsp.lstat(f.destinationPath), { code: "ENOENT" });
});
