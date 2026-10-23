"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const vm = require("node:vm");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const modules = ["rootark-zk1-file-content", "rootark-zk1-ciphertext-chunk-root",
  "rootark-zk1-protected-http-client", "rootark-zk1-uncertain-put-reconciliation",
  "rootark-zk1-normal-browser-content", "rootark-zk1-browser-catalog",
  "rootark-zk1-client-logical-trash"];
const probe = fs.readFileSync(path.join(__dirname,
  "support/issue-65-restore-reconnect-browser-probe.js"), "utf8");

test("Node browser VM: signed-journal restore reconnect checks AEAD, rollback, logout and content parity", async () => {
  const runtime = { crypto: crypto.webcrypto, TextEncoder, TextDecoder,
    btoa, atob, URL, Headers, AbortController, setTimeout, clearTimeout };
  vm.createContext(runtime);
  for (const moduleName of modules) {
    const source = fs.readFileSync(path.join(__dirname, "../public/client/",
      moduleName + ".js"), "utf8");
    vm.runInContext(source, runtime, { filename: moduleName });
  }
  vm.runInContext(probe, runtime, { filename: "restore-reconnect-edge-probe" });
  const answer = await runtime.runRestoreReconnectionScenario();
  assert.equal(answer.result, "PASS");
  assert.equal(answer.puts, 0);
  assert.ok(answer.signedGets >= 3);
});

test("actual Edge executes restored-file reconnect checks with WebCrypto under restrictive CSP", {
  timeout: 40_000,
}, async (t) => {
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (process.platform !== "win32" || !fs.existsSync(edge)) {
    t.skip("Microsoft Edge Windows unavailable");
    return;
  }
  const html = "<!doctype html><html><head><meta charset='utf-8'></head><body>"
    + "<output id='result'>PENDING</output>"
    + modules.map((name) => `<script src='/assets/${name}.js'></script>`).join("")
    + "<script src='/probe.js'></script></body></html>";
  const server = http.createServer((req, res) => {
    res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'");
    if (req.url === "/") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(html);
    } else if (req.url === "/probe.js") {
      res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8" });
      res.end(probe);
    } else if (modules.some((name) => req.url === `/assets/${name}.js`)) {
      const name = req.url.slice("/assets/".length);
      res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8" });
      res.end(fs.readFileSync(path.join(__dirname, "../public/client", name)));
    } else { res.writeHead(404); res.end(); }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-edge-restore-"));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(folder, { recursive: true, force: true, maxRetries: 5 });
  });
  const url = "http://127.0.0.1:" + server.address().port + "/";
  const args = ["--headless=new", "--disable-gpu", "--no-first-run",
    "--disable-extensions", "--no-default-browser-check", "--virtual-time-budget=10000",
    "--user-data-dir=" + path.join(folder, "profile"), "--dump-dom", url];
  const result = await promisify(execFile)(edge, args, {
    timeout: 35_000, windowsHide: true, maxBuffer: 1024 * 1024,
  });
  assert.match(result.stdout, /EDGE_RESTORE_RECONNECT_PASS/,
    "actual Edge must execute the browser UMD and reject attacks before journal clear");
  assert.doesNotMatch(result.stdout, /EDGE_RESTORE_RECONNECT_FAIL/);
});
