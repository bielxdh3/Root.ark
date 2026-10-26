"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsSync = require("node:fs");
const fs = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);
const script = path.resolve(__dirname, "../sync-client/rootark-sync.js");

test("legacy sync rejects a hardlink alias of a file outside the authorized folder", {
  timeout: 20000,
}, async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-foreign-hardlink-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const localFolder = path.join(root, "sync");
  await fs.mkdir(localFolder);
  const external = path.join(root, "outside.env");
  const alias = path.join(localFolder, "ordinary.txt");
  const marker = `external-synthetic-secret-${crypto.randomBytes(16).toString("hex")}`;
  await fs.writeFile(external, marker);
  await fs.link(external, alias);
  assert.equal((await fs.stat(alias)).nlink, 2, "the test must create a real hardlink");
  const uploads = [];
  let listings = 0;
  let swapOnList = false;
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/list?")) {
      listings++;
      if (swapOnList) {
        swapOnList = false;
        fsSync.renameSync(alias, path.join(root, "original-before-race.txt"));
        fsSync.linkSync(external, alias);
      }
      req.resume();
      res.writeHead(200, { "content-type": "application/json" });
      res.end("[]");
      return;
    }
    if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        uploads.push(Buffer.concat(chunks));
        res.writeHead(200, { "content-type": "application/json" });
        res.end('{"fileName":"ordinary.txt"}');
      });
      return;
    }
    req.resume();
    res.writeHead(404);
    res.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const config = path.join(root, "config.json");
  await fs.writeFile(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`, token: "synthetic-only",
    localFolder, targetFolderId: "root", retryLimit: 1,
    debounceMs: 1, stabilityMs: 1, scanIntervalMs: 1,
  }));
  await execFileAsync(process.execPath,
    [script, "start", "--legacy-development-opt-in", "--once", "--config", config],
    { timeout: 15000, cwd: root, windowsHide: true });
  assert.equal(uploads.length, 0,
    "a hardlink into the sync folder must not export bytes from an external file");
  assert.equal(await fs.readFile(external, "utf8"), marker,
    "refusing the alias must preserve the external file");

  // The directory scan saw an ordinary one-link file, but a local actor
  // substitutes an external hardlink after preflight and before HTTP upload.
  await fs.unlink(alias);
  await fs.writeFile(alias, "safe-local-content");
  swapOnList = true;
  await execFileAsync(process.execPath,
    [script, "start", "--legacy-development-opt-in", "--once", "--config", config],
    { timeout: 15000, cwd: root, windowsHide: true });
  assert.equal(swapOnList, false, "the fixture must swap at the real network boundary");
  assert.ok(listings > 0, "the real uploader reached its remote preflight");
  assert.equal(uploads.length, 0, "an external hardlink substituted during upload must fail closed");
  assert.equal(await fs.readFile(external, "utf8"), marker);
});
