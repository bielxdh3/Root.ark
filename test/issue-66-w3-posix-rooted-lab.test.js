"use strict";

// Linux/WSL ext4 opt-in, test-only. All native binaries and fixtures live
// outside this checkout. No global filesystem cleanup is performed.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const enabled = process.platform === "linux" &&
  process.env.ROOTARK_ISSUE66_POSIX_LAB === "1";
const source = path.resolve(__dirname, "../experiments/issue66-posix-rooted-lab/posix_rooted_lab.c");
let executable;

function ready() {
  assert.match(process.version, /^v22\./);
  assert.match(os.release(), /microsoft|wsl/i);
  const home = os.homedir();
  assert.equal(fs.realpathSync(home), home, "native parent must be canonical");
  assert.equal(fs.statfsSync(home).type, 0xef53, "fixtures require physical ext4");
  if (!executable) {
    const build = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-w3-posix-build-"));
    executable = path.join(build, "rooted-lab");
    const cc = spawnSync("gcc", [
      "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
      source, "-o", executable,
    ], { encoding: "utf8", timeout: 30000, maxBuffer: 4096 });
    assert.equal(cc.status, 0, "native compilation must succeed");
    assert.equal(cc.error, undefined, "gcc unavailable");
  }
  return home;
}

function scratch(home) {
  const fixture = fs.mkdtempSync(path.join(home, "rootark-w3-posix-"));
  assert.match(path.basename(fixture), /^rootark-w3-posix-[a-zA-Z0-9_-]{6,}$/);
  assert.equal(path.dirname(fixture), home);
  // Fixtures are retained. Recursive pathname cleanup is explicitly forbidden.
  return path.basename(fixture);
}

function run(home, leaf, mode, optIn = true) {
  return spawnSync(executable, [home, leaf, mode], {
    encoding: "utf8", timeout: mode === "bulk" ? 90000 : 20000,
    maxBuffer: 1024, windowsHide: true,
    env: { ...process.env, ROOTARK_ISSUE66_POSIX_LAB: optIn ? "1" : "0" },
  });
}

test("#66 W3 reject disabled and nonempty disposable roots without touching markers",
  { skip: !enabled }, () => {
    const home = ready();
    const disabled = scratch(home);
    const no = run(home, disabled, "core", false);
    assert.equal(no.status, 41);
    assert.equal(no.stdout, "");
    assert.match(no.stderr, /^ROOTARK_POSIX_REJECTED\n$/);
    assert.deepEqual(fs.readdirSync(path.join(home, disabled)), []);

    const nonempty = scratch(home);
    fs.writeFileSync(path.join(home, nonempty, "foreign.marker"), "DO_NOT_TOUCH");
    const refused = run(home, nonempty, "core");
    assert.equal(refused.status, 41);
    assert.equal(refused.stdout, "");
    assert.match(refused.stderr, /^ROOTARK_POSIX_REJECTED\n$/);
    assert.equal(fs.readFileSync(path.join(home, nonempty, "foreign.marker"), "utf8"), "DO_NOT_TOUCH");
  });

test("#66 W3 POSIX anchored dirfd identity under deterministic A-B-A replacement",
  { skip: !enabled }, () => {
    const home = ready();
    const result = run(home, scratch(home), "core");
    assert.equal(result.error, undefined, "native helper timed out or failed to start");
    assert.equal(result.status, 0, "native proof failed closed");
    assert.equal(result.stderr, "");
    assert.equal(result.stdout, "ROOTARK_POSIX_V1 stage=CORE fs=EXT4 parent=INDEPENDENT_FD openat2=STRICT aba=PASS noReplace=PASS marker=PASS unicode=PASS unlink=PASS fsync=PASS\n");
  });

test("#66 W3 POSIX 16385 entries streaming enumeration of exact same fd",
  { skip: !enabled, timeout: 120000 }, () => {
    const home = ready();
    const result = run(home, scratch(home), "bulk");
    assert.equal(result.error, undefined, "native helper timed out or failed to start");
    assert.equal(result.status, 0, "16385-entry native proof failed closed");
    assert.equal(result.stderr, "");
    assert.equal(result.stdout, "ROOTARK_POSIX_V1 stage=BULK fs=EXT4 entries=16385 enumeration=SAME_FD unicode=PASS fsync=PASS\n");
  });

test("#66 W3 bind mount adversary requires explicit independent CAP_SYS_ADMIN test",
  { skip: "SKIP: bind mount attack not exercised; CAP_SYS_ADMIN and isolated mount namespace not established" }, () => {});
