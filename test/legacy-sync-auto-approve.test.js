"use strict";

const assert = require("node:assert/strict");
const { execFile } = require("node:child_process");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { promisify } = require("node:util");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { writePrivateSyncConfig } =
  require("../sync-client/rootark-sync-private-config");

const execFileAsync = promisify(execFile);
const syncClient = path.resolve(__dirname, "../sync-client/rootark-sync.js");

test("legacy sync auto-approval sends POST to the approval endpoint", async (t) => {
  // The sync config contains a bearer token; tests must not place it in a
  // shared temp directory with an inherited Windows Modify ACL.
  const dir = createPrivateAuthorityFixture("rootark-sync-auto-approve-");
  const localFolder = path.join(dir, "files");
  await fsp.mkdir(localFolder);
  await fsp.writeFile(path.join(localFolder, "new.txt"), "content");

  const approvalMethods = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
      return;
    }
    if (req.url.startsWith("/upload?")) {
      req.resume();
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ fileName: "new.txt" }));
      return;
    }
    if (req.url.startsWith("/approve/")) {
      approvalMethods.push(req.method);
      const status = req.method === "POST" ? 200 : 405;
      res.writeHead(status, { "Content-Type": "application/json" }).end(status === 200 ? "{}" : JSON.stringify({ error: "Method not allowed" }));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    await fsp.rm(dir, { recursive: true, force: true });
  });

  const address = server.address();
  const configPath = path.join(dir, "config.json");
  await writePrivateSyncConfig(configPath, JSON.stringify({
    serverUrl: `http://127.0.0.1:${address.port}`,
    username: "sync-test",
    token: "test-token",
    localFolder,
    targetFolderId: "root",
    autoApprove: true,
    debounceMs: 1,
    stabilityMs: 1,
    retryLimit: 1,
  }));

  // Windows' native protected-DACL checks now also cover the shared private
  // state directory and its durable publication. They can exceed the older
  // 10s wall-clock budget without a network or authorization regression.
  await execFileAsync(process.execPath,
    [syncClient, "start", "--legacy-development-opt-in", "--once", "--config", configPath],
    { timeout: process.platform === "win32" ? 90000 : 10000 });
  assert.deepEqual(approvalMethods, ["POST"]);
});
