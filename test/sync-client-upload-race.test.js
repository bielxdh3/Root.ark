const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { spawn } = require("node:child_process");

for (const mode of ["replacement", "symlink"]) test(`CodeQL #134: sync blocks ${mode} swapped after preflight`, { timeout: 35_000 }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-sync-race-"));
  const localFolder = path.join(root, "sync");
  fs.mkdirSync(localFolder);
  const target = path.join(localFolder, "safe.txt");
  const parked = path.join(root, "parked.txt");
  const secret = path.join(root, "synthetic-secret.txt");
  fs.writeFileSync(target, "original-file-content");
  fs.writeFileSync(secret, "outside-content-only!");
  if (mode === "symlink") {
    const probe = path.join(root, "link-capability-probe");
    try { fs.symlinkSync(secret, probe, "file"); fs.unlinkSync(probe); }
    catch (error) {
      fs.rmSync(root, { recursive: true, force: true });
      if (error.code === "EPERM" || error.code === "EACCES") { t.skip("Host does not permit symlink fixtures"); return; }
      throw error;
    }
  }
  let swapped = false;
  let uploads = 0;
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/list?")) {
      if (!swapped) {
        swapped = true;
        fs.renameSync(target, parked);
        if (mode === "symlink") fs.symlinkSync(secret, target, "file");
        else fs.copyFileSync(secret, target);
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end("[]");
      return;
    }
    if (req.url.startsWith("/upload?")) {
      uploads += 1;
      req.resume();
      req.once("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end('{"fileName":"safe.txt"}');
      });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const config = path.join(root, "config.json");
  fs.writeFileSync(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    token: "synthetic-local-test-token", localFolder, targetFolderId: "root",
    retryLimit: 1, debounceMs: 1, stabilityMs: 1,
  }));
  const script = path.resolve(__dirname, "..", "sync-client", "rootark-sync.js");
  const child = spawn(process.execPath, [script, "start", "--legacy-development-opt-in", "--once", "--config", config], {
    cwd: root, stdio: "ignore", windowsHide: true,
  });
  t.after(() => { try { child.kill(); } catch {} server.close(); fs.rmSync(root, { recursive: true, force: true }); });
  let timeout;
  const result = await Promise.race([
    new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code) => resolve(code));
    }),
    new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error("sync fixture timeout")), 28_000); }),
  ]).finally(() => clearTimeout(timeout));
  assert.equal(result, 0);
  assert.equal(swapped, true, "PoC must switch file identity after preflight");
  assert.equal(uploads, 0, "replaced file must not be uploaded");
});
