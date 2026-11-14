"use strict";

// Issue #67 / PR #298, disposable OS-semantics proof, NOT a rollback helper.
// A held Linux dirfd remains usable after its directory is moved outside
// the selected root. A native NTFS directory HANDLE that denies SHARE_DELETE
// prevents that rename while it is held. Neither fact authorizes a root nor
// provides crash-safe recovery of a preexisting destination.
// Explicit opt-in: ROOTARK_ISSUE67_FD_LEASE_LAB=1 node --test <this file>.
// Ordinary CI discovery must not compile native tools or mutate test fixtures.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const test = require("node:test");
const labEnabled = process.env.ROOTARK_ISSUE67_FD_LEASE_LAB === "1";

if (process.argv[2] === "--independent-rename") {
  const [from, to] = process.argv.slice(3);
  try {
    fs.renameSync(from, to);
    process.stdout.write(JSON.stringify({ pid: process.pid, renamed: true }));
  } catch (error) {
    process.stdout.write(JSON.stringify({ pid: process.pid, renamed: false, code: error.code }));
  }
  process.exit(0);
}

function renameFromOtherProcess(from, to) {
  const result = spawnSync(process.execPath, [__filename, "--independent-rename", from, to], {
    windowsHide: true, encoding: "utf8", timeout: 5000,
  });
  assert.equal(result.status, 0, `rename helper failed: ${result.stderr}`);
  const value = JSON.parse(result.stdout);
  assert.notEqual(value.pid, process.pid, "independent process required");
  return value;
}

function testFixture(t) {
  const scratchBase = process.platform === "win32" ? path.resolve(__dirname, "..") : os.homedir();
  if (process.platform !== "win32") {
    assert.equal(fs.statfsSync(scratchBase).type, 0xef53, "ext4 required, not /mnt/e DrvFS");
  } else {
    assert.equal(path.parse(scratchBase).root.toUpperCase(), "E:\\", "native NTFS E: required");
  }
  const scratch = fs.mkdtempSync(path.join(scratchBase, "rootark-w1-fd-lease-"));
  t.after(() => {
    assert.ok(path.basename(scratch).startsWith("rootark-w1-fd-lease-"));
    fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });
  const root = path.join(scratch, "selected-root");
  const parent = path.join(root, "subdir");
  const relocated = path.join(scratch, "moved-outside-root");
  fs.mkdirSync(parent, { recursive: true });
  fs.writeFileSync(path.join(parent, "trusted.dat"), "original owner bytes", { flag: "wx" });
  return { scratch, root, parent, relocated };
}

function run(file, args, opts = {}) {
  return spawnSync(file, args, {
    windowsHide: true, encoding: "utf8", timeout: 20000, ...opts,
  });
}

function startHeldChild(command, args) {
  const child = spawn(command, args, { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
  const output = { stdout: "", stderr: "" };
  child.stdout.on("data", (data) => { output.stdout += data; });
  const ready = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`native exited before READY ${code}: ${output.stderr}`)));
    child.stderr.on("data", (data) => {
      output.stderr += data;
      if (/READY\r?\n/.test(output.stderr)) resolve();
    });
  });
  const finished = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, ...output }));
  });
  return { child, ready, finished };
}

test("#67 root custody: held dirfd cannot prevent POSIX rename, even with openat2 RESOLVE_BENEATH", {
  skip: !labEnabled || process.platform !== "linux", timeout: 20000,
}, async (t) => {
  const f = testFixture(t);
  const nativeSource = String.raw`
    #define _GNU_SOURCE
    #include <fcntl.h>
    #include <linux/openat2.h>
    #include <sys/syscall.h>
    #include <unistd.h>
    #include <stdio.h>
    int main(int argc, char** argv) {
      if (argc != 2) return 2;
      int dir = open(argv[1], O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
      if (dir < 0) return 3;
      fputs("READY\n", stderr); fflush(stderr);
      char line[8];
      if (!fgets(line, sizeof(line), stdin) || line[0] != 'G') return 4;
      struct open_how how = {0};
      how.flags = O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC;
      how.mode = 0600;
      how.resolve = RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV;
      int file = syscall(SYS_openat2, dir, "new.dat", &how, sizeof(how));
      if (file < 0) return 5;
      static const char text[] = "CREATED_VIA_HELD_DIRFD_AFTER_ROOT_ESCAPE";
      if (write(file, text, sizeof(text)-1) != (ssize_t)(sizeof(text)-1)) return 6;
      if (fsync(file) != 0) return 7;
      close(file); close(dir);
      return 0;
    }
  `;
  const cFile = path.join(f.scratch, "held-openat2.c");
  const binary = path.join(f.scratch, "held-openat2");
  fs.writeFileSync(cFile, nativeSource);
  const built = run("cc", ["-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2", "-o", binary, cFile]);
  assert.equal(built.status, 0, `native compile failed: ${built.stderr}`);
  const held = startHeldChild(binary, [f.parent]);
  t.after(() => { if (held.child.exitCode === null) held.child.kill(); });
  await held.ready;
  const action = renameFromOtherProcess(f.parent, f.relocated);
  assert.equal(action.renamed, true, "POSIX held dirfd is NOT a rename lock");
  fs.mkdirSync(f.parent);
  fs.writeFileSync(path.join(f.parent, "new.dat"), "FOREIGN_INDEPENDENT_WRITER", { flag: "wx" });
  held.child.stdin.end("GO\n");
  const done = await held.finished;
  assert.equal(done.code, 0, `held openat2 failed: ${done.stderr}`);
  assert.equal(fs.readFileSync(path.join(f.relocated, "new.dat"), "utf8"),
    "CREATED_VIA_HELD_DIRFD_AFTER_ROOT_ESCAPE",
    "relative openat2 created an inode OUTSIDE the validated root");
  assert.equal(fs.readFileSync(path.join(f.parent, "new.dat"), "utf8"),
    "FOREIGN_INDEPENDENT_WRITER", "in-root foreign inode must be untouched");
});

test("#67 root custody: NTFS native leased ancestors deny independent rename while HANDLE remains open", {
  skip: !labEnabled || process.platform !== "win32", timeout: 30000,
}, async (t) => {
  const f = testFixture(t);
  const exe = path.join(f.scratch, "native-contained-open.exe");
  const vswhere = "C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe";
  const candidates = run(vswhere, ["-all", "-products", "*", "-prerelease", "-find",
    "VC\\Auxiliary\\Build\\vcvars64.bat"]);
  const vcvars = candidates.stdout.trim().split(/\r?\n/).find(Boolean);
  assert.equal(candidates.status, 0, "real MSVC vcvars64.bat required");
  assert.ok(vcvars && fs.existsSync(vcvars));
  const nativeSource = path.resolve(__dirname, "../scripts/issue-67-native-contained-open.cpp");
  const batch = path.join(f.scratch, "build.cmd");
  fs.writeFileSync(batch, ["@echo off", `call "${vcvars}" >nul`,
    "if errorlevel 1 exit /b 1",
    `cl /nologo /std:c++17 /W4 /WX /EHsc /Fe:"${exe}" "${nativeSource}"`,
    "exit /b %errorlevel%", ""].join("\r\n"));
  const build = run("cmd.exe", ["/d", "/c", batch], { cwd: f.scratch });
  assert.equal(build.status, 0, `MSVC build failed: ${build.stdout} ${build.stderr}`);
  const fingerprint = run(exe, ["--fingerprint", f.root]);
  assert.equal(fingerprint.status, 0, `root fingerprint failed: ${fingerprint.stderr}`);
  const expected = JSON.parse(fingerprint.stdout).rootId;
  assert.match(expected, /^[a-f0-9]{48}$/);
  const held = startHeldChild(exe,
    ["--open", f.root, "subdir\\trusted.dat", expected, "--hold-ms", "1500"]);
  t.after(() => { if (held.child.exitCode === null) held.child.kill(); });
  await held.ready;
  const action = renameFromOtherProcess(f.parent, f.relocated);
  assert.equal(action.renamed, false, "NTFS held ancestor must deny rename");
  assert.ok(["EBUSY", "EPERM", "EACCES"].includes(action.code), action.code);
  const done = await held.finished;
  assert.equal(done.code, 0, `native lease failed: ${done.stderr}`);
  assert.equal(fs.readFileSync(path.join(f.parent, "trusted.dat"), "utf8"), "original owner bytes");
  assert.equal(fs.existsSync(f.relocated), false);
});
