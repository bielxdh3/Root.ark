"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");
const { writePrivateSyncConfig } = require("../sync-client/rootark-sync-private-config");

test("two relative paths with identical remote basename must fail closed before HTTP", {
  timeout: 60000,
}, async (t) => {
  const privateDir = createPrivateAuthorityFixture("rootark-basename-private-");
  const shared = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-basename-source-"));
  t.after(async () => {
    await fs.rm(shared, { recursive: true, force: true });
    await fs.rm(privateDir, { recursive: true, force: true });
  });
  for (const dir of ["first", "second"]) {
    await fs.mkdir(path.join(shared, dir));
    await fs.writeFile(path.join(shared, dir, "same.txt"), `UNIQUE_${dir}`);
  }
  let uploads = 0;
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
    } else if (req.url.startsWith("/upload?")) {
      uploads++;
      req.resume();
      req.on("end", () => res.writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ fileName: "same.txt" })));
    } else res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const configPath = path.join(privateDir, "config.json");
  await writePrivateSyncConfig(configPath, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    localFolder: shared, targetFolderId: "root", username: "fixture",
    token: "fixture-token", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  }));
  const cli = path.resolve(__dirname, "../sync-client/rootark-sync.js");
  const child = spawn(process.execPath,
    [cli, "start", "--legacy-development-opt-in", "--once", "--config", configPath],
    { cwd: privateDir, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (part) => { output += part; });
  child.stderr.on("data", (part) => { output += part; });
  t.after(() => child.kill());
  const done = await new Promise((resolve, reject) => {
    child.once("close", resolve);
    child.once("error", reject);
  });
  assert.notEqual(done, 0, "ambiguous remote basename must not report successful mirror");
  assert.match(output, /SYNC_REMOTE_BASENAME_COLLISION/);
  assert.equal(uploads, 0, "collision preflight must reject before remote side effects");
});
