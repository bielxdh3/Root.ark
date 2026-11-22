"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

function runCanonicalWithControlledTap(lines) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-canonical-zero-"));
  try {
    // The runner invokes npm.cmd through cmd.exe. Isolate the fake npm
    // executable to this single child process; never change the parent PATH.
    fs.writeFileSync(path.join(directory, "npm.cmd"),
      ["@echo off", ...lines.map((line) => `echo ${line}`), "exit /b 0"].join("\r\n") + "\r\n",
      "ascii");
    return spawnSync(process.execPath, [
      path.join(__dirname, "..", "scripts", "run-windows-canonical-tests.js"),
    ], {
      cwd: path.resolve(__dirname, ".."),
      encoding: "utf8", timeout: 15_000, windowsHide: true,
      env: { ...process.env,
        PATH: directory + path.delimiter + (process.env.PATH || "") },
    });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test("Windows canonical rejects a successful child with real TAP zero tests", {
  skip: process.platform !== "win32",
}, () => {
  const child = runCanonicalWithControlledTap([
    "TAP version 13", "1..0", "# tests 0", "# pass 0", "# fail 0",
  ]);
  assert.equal(child.signal, null);
  assert.equal(child.status, 1,
    "a zero-test TAP stream must not satisfy mandatory canonical coverage");
  assert.match(child.stderr, /FAIL Windows canonical suite:.*TAPresults=0 tests=0/);
  assert.doesNotMatch(child.stdout, /PASS Windows canonical suite/);
});

test("Windows canonical rejects all-skipped TAP even with exit 0 and fail 0", {
  skip: process.platform !== "win32",
}, () => {
  const child = runCanonicalWithControlledTap([
    "TAP version 13", "ok 1 - skipped # SKIP explicit",
    "1..1", "# tests 1", "# pass 0", "# fail 0",
  ]);
  assert.equal(child.signal, null);
  assert.equal(child.status, 1,
    "all-skipped TAP must not satisfy mandatory canonical coverage");
  assert.match(child.stderr, /FAIL Windows canonical suite:.*TAPresults=1 tests=1/);
  assert.doesNotMatch(child.stdout, /PASS Windows canonical suite/);
});

test("Windows canonical still accepts a syntactically complete positive TAP child", {
  skip: process.platform !== "win32",
}, () => {
  const child = runCanonicalWithControlledTap([
    "TAP version 13", "ok 1 - controlled positive",
    "1..1", "# tests 1", "# pass 1", "# fail 0",
  ]);
  assert.equal(child.signal, null);
  assert.equal(child.status, 0,
    "positive TAP must retain a functioning acceptance path");
  assert.match(child.stdout, /PASS Windows canonical suite:.*TAPresults=1 tests=1/);
});
