"use strict";

// Issue #203: enforce the library-only import boundary for a transitive
// advisory that currently has no patched sprintf-js release.
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");

function traceDependencyImports(entry) {
  const source = `
    const Module = require("node:module");
    const originalLoad = Module._load;
    const matches = [];
    Module._load = function(request, parent, isMain) {
      if (/^(?:argparse|sprintf-js)(?:\\/|$)/.test(request)) matches.push(request);
      return originalLoad.apply(this, arguments);
    };
    const loaded = require(process.argv[1]);
    if (!loaded) process.exitCode = 1;
    process.stdout.write(JSON.stringify(matches));
  `;
  const result = spawnSync(process.execPath, ["-e", source, entry], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 15_000,
    windowsHide: true,
    env: { ...process.env, NODE_ENV: "test" },
  });
  assert.equal(result.status, 0, `dependency trace failed: ${result.error?.code || result.signal || result.stderr || result.status}`);
  return JSON.parse(result.stdout);
}

test("advisory import tracer observes the vulnerable dependency when deliberately loaded", () => {
  assert.deepEqual(traceDependencyImports("sprintf-js"), ["sprintf-js"]);
});

test("Mammoth's documented library entry does not load CLI-only argparse or sprintf-js", () => {
  assert.deepEqual(traceDependencyImports("mammoth"), []);
});

test("DOCX worker imports only Mammoth's library entry, not its CLI", () => {
  const source = fs.readFileSync(path.join(ROOT, "services", "documentPreviewWorker.js"), "utf8");
  assert.match(source, /require\(["']mammoth["']\)/);
  assert.doesNotMatch(source, /(?:bin[\\/]mammoth|require\(["']argparse["']\)|require\(["']sprintf-js["']\))/);
});
