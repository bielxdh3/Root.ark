"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

test("issue 66 Windows picker resolves a relative localFolder against config, not caller cwd", {
  skip: process.platform !== "win32",
  timeout: 45000,
}, () => {
  const script = path.resolve(__dirname, "support/issue-66-windows-picker-relative-root-smoke.ps1");
  const picker = path.resolve(__dirname, "../sync-client/rootark-sync-windows-picker.ps1");
  const run = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", script, "-PickerScriptPath", picker], {
    cwd: __dirname,
    env: process.env,
    encoding: "utf8",
    timeout: 40000,
    windowsHide: true,
  });
  assert.equal(run.error, undefined);
  assert.equal(run.status, 0, `stdout: ${run.stdout}\nstderr: ${run.stderr}`);
  assert.match(run.stdout, /PASS: picker selects config-relative/);
});
