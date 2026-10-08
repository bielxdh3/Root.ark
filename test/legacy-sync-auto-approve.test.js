"use strict";

const assert = require("node:assert/strict");
const { execFile } = require("node:child_process");
const fsp = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { promisify } = require("node:util");
const test = require("node:test");

const execFileAsync = promisify(execFile);
const syncClient = path.resolve(__dirname, "../sync-client/rootark-sync.js");

test("legacy sync auto-approval sends POST to the approval endpoint", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-sync-auto-approve-"));
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
  await fsp.writeFile(configPath, JSON.stringify({
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

  await execFileAsync(process.execPath, [syncClient, "start", "--legacy-development-opt-in", "--once", "--config", configPath], { timeout: 10000 });
  assert.deepEqual(approvalMethods, ["POST"]);
});
