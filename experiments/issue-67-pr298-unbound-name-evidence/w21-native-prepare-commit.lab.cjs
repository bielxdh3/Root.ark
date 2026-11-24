"use strict";

// Explicit Node22 lab runner. NOT in production or normal canonical tests.
// Invoked only as: node --test experiments/.../w21-native-prepare-commit.lab.cjs
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const here = __dirname;
const lines = (result) => [result.stdout || "", result.stderr || ""].join("\n");
const run = (program, args, options = {}) => spawnSync(program, args, {
  cwd: here, encoding: "utf8", timeout: 30000,
  windowsHide: true, maxBuffer: 128 * 1024,
  ...options,
});

test("lab-only PREPARE/COMMIT: Windows NTFS held FileId link + rename, no overwrite", async (t) => {
  if (process.platform !== "win32") return t.skip("Windows-only native HANDLE laboratory");
  assert.equal(Number(process.versions.node.split(".")[0]), 22, "Node22 required");
  const build = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-w21-native-win-build-"));
  t.after(() => fs.rmSync(build, { recursive: true, force: true }));
  const drive = path.parse(build).root[0].toUpperCase();
  const fsCheck = run("powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", `(Get-Volume -DriveLetter '${drive}').FileSystem`]);
  assert.equal(fsCheck.status, 0, `Failed to identify real Windows filesystem: ${lines(fsCheck)}`);
  assert.equal(fsCheck.stdout.trim(), "NTFS", "Native HANDLE lab requires a real NTFS volume");
  const compiler = path.join(process.env.WINDIR || "C:\\Windows",
    "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe");
  assert.ok(fs.existsSync(compiler), "Known system C# compiler required; no PATH fallback");
  const program = path.join(build, "w21-win-handle-link-lab.exe");
  const source = path.join(here, "w21-win-handle-link-lab.cs");
  const compiled = run(compiler,
    ["/nologo", "/target:exe", "/platform:x64", `/out:${program}`, source]);
  assert.equal(compiled.status, 0, `Native x64 lab compiler failed: ${lines(compiled)}`);
  for (const mode of ["link", "rename"]) {
    const executable = run(program, mode === "link" ? [] : ["rename"]);
    const label = mode === "link"
      ? "WINDOWS_NATIVE_HANDLE_LINK_LAB_PASS"
      : "WINDOWS_NATIVE_HANDLE_RENAME_LAB_PASS";
    assert.equal(executable.status, 0,
      `Native lab ${mode} returned ${executable.status}: ${lines(executable)}`);
    assert.ok(executable.stdout.includes(label),
      `missing physical native ${mode} proof: ${lines(executable)}`);
    for (const proof of ["secondProcess=true", "sameSid=true",
      "originalFileId=true", "noReplace=true", "foreignPreserved=true"]) {
      assert.ok(executable.stdout.includes(proof),
        `native ${mode} missing ${proof}: ${lines(executable)}`);
    }
  }
});

test("lab-only PREPARE/COMMIT: WSL ext4 held fd link + preserved stage; rename unsupported", async (t) => {
  if (process.platform !== "linux") return t.skip("Linux-only native dirfd laboratory");
  assert.equal(Number(process.versions.node.split(".")[0]), 22, "Node22 required");
  assert.ok(path.isAbsolute(os.tmpdir()), "A trusted path to real ext4 scratch is required");
  const mount = run("/usr/bin/findmnt", ["-n", "-o", "FSTYPE", "-T", os.tmpdir()]);
  assert.equal(mount.status, 0, `Cannot verify scratch filesystem: ${lines(mount)}`);
  assert.equal(mount.stdout.trim(), "ext4", "Native lab must run on actual Linux ext4, not tmpfs/DrvFS");
  const build = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-w21-native-posix-build-"));
  t.after(() => fs.rmSync(build, { recursive: true, force: true }));
  const compiler = "/usr/bin/g++";
  assert.ok(fs.existsSync(compiler), "Absolute system compiler required, no PATH fallback");
  const program = path.join(build, "w21-posix-fd-link-lab");
  const compiled = run(compiler, ["-std=c++17", "-O2", "-Wall", "-Wextra",
    "-Werror", path.join(here, "w21-posix-fd-link-lab.cpp"), "-o", program]);
  assert.equal(compiled.status, 0, `Native POSIX lab compiler failed: ${lines(compiled)}`);
  const output = run(program, [], { env: { ...process.env, TMPDIR: os.tmpdir() } });
  assert.equal(output.status, 0, `Native POSIX lab failed: ${lines(output)}`);
  assert.ok(output.stdout.includes("POSIX_NATIVE_FD_LINK_LAB_PASS"),
    `Expected physical held-fd link proof: ${lines(output)}`);
  assert.ok(output.stdout.includes("POSIX_PREPARE_COMMIT_STAGE_LAB_PASS"),
    `Expected no-clobber retained-stage proof: ${lines(output)}`);
  assert.ok(output.stdout.includes("renameByFdSupported=false"),
    "POSIX must never claim source-FD-bound renameat2");
});
