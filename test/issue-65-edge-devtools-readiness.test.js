"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { waitForEdgeDevtoolsPage } = require("./support/issue-65-edge-devtools-readiness");

test("Edge debug target waits for an actual page after a port file and transient HTTP startup errors", async (t) => {
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-edge-ready-"));
  t.after(() => fs.rmSync(profileDir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(profileDir, "DevToolsActivePort"), "43210\n/placeholder\n");
  let attempts = 0;
  const found = await waitForEdgeDevtoolsPage({
    profileDir,
    fetchTargets: async (url) => {
      assert.equal(url, "http://127.0.0.1:43210/json/list");
      attempts++;
      if (attempts === 1) throw Object.assign(Error("not listening"), { code: "ECONNREFUSED" });
      if (attempts === 2) return [];
      return [{ type: "page", webSocketDebuggerUrl: "ws://127.0.0.1:43210/devtools/page/1" }];
    },
    sleep: async () => {},
  });
  assert.equal(found, "ws://127.0.0.1:43210/devtools/page/1");
  assert.equal(attempts, 3);
});

test("Edge debug target never fetches an invalid port and rejects an exited browser promptly", async (t) => {
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-edge-ready-"));
  t.after(() => fs.rmSync(profileDir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(profileDir, "DevToolsActivePort"), "0\n");
  let called = false;
  let now = 0;
  await assert.rejects(waitForEdgeDevtoolsPage({
    profileDir, timeoutMs: 180,
    now: () => now,
    sleep: async (ms) => { now += ms; },
    fetchTargets: async () => { called = true; return []; },
  }), /EDGE_V2_TIMEOUT_devtools/);
  assert.equal(called, false);
  await assert.rejects(waitForEdgeDevtoolsPage({
    profileDir, child: { exitCode: 1 },
    fetchTargets: async () => { throw Error("must not fetch"); },
  }), /EDGE_V2_BROWSER_EXITED/);
});
