"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const os = require("node:os");
const http = require("node:http");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const sourceFile = path.join(__dirname,
  "../public/client/rootark-zk1-opaque-device-delta-sync.js");
const probeFile = path.join(__dirname, "support/issue-65-opaque-delta-browser-probe.js");

test("independently authorized opaque delta client boots without generic sync-v2", () => {
  const source = fs.readFileSync(path.join(__dirname,
    "../public/client/rootark-zk1-opaque-device-delta-sync.js"), "utf8");
  const context = { crypto: crypto.webcrypto, TextEncoder, TextDecoder, btoa, atob,
    RootarkZk1BrowserOpaqueCatalogCommit: Object.freeze({ createClient() {} }),
    RootarkZk1ProtectedHttpClient: Object.freeze({}),
    RootarkZk1CiphertextRoot: Object.freeze({}) };
  context.globalThis = context;
  vm.runInNewContext(source, context);
  assert.equal(typeof context.RootarkZk1OpaqueDeviceDeltaSync.createClient, "function");
  assert.doesNotMatch(source, /sync-client\/|rootark-sync-v2|rootark-sync-adapter/);
});

test("Node22/24 browser VM rejects replay/logout after opaque delta with no plaintext metadata", async () => {
  const context = { crypto: crypto.webcrypto, TextEncoder, TextDecoder, btoa, atob,
    RootarkZk1BrowserOpaqueCatalogCommit: { createClient() {} },
    RootarkZk1ProtectedHttpClient: { signProtectedContentOperation() {} },
    RootarkZk1CiphertextRoot: { computeCiphertextRoot() {} } };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(sourceFile, "utf8"), context);
  vm.runInContext(fs.readFileSync(probeFile, "utf8"), context);
  assert.equal(await context.runOpaqueDeltaBrowserProbe(), "PASS");
});

test("real Edge runs opaque delta browser contract under restrictive CSP", {
  timeout: 40_000,
}, async (t) => {
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (process.platform !== "win32" || !fs.existsSync(edge)) {
    t.skip("Edge Windows unavailable");
    return;
  }
  const startup = "window.RootarkZk1BrowserOpaqueCatalogCommit={createClient(){}};"
    + "window.RootarkZk1ProtectedHttpClient={signProtectedContentOperation(){}};"
    + "window.RootarkZk1CiphertextRoot={computeCiphertextRoot(){}};";
  const html = "<!doctype html><meta charset='utf-8'>"
    + "<output id='probe-result'>PENDING</output>"
    + "<script src='/bootstrap.js'></script>"
    + "<script src='/client.js'></script><script src='/probe.js'></script>";
  const server = http.createServer((request, response) => {
    response.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'");
    const content = request.url === "/" ? html : request.url === "/bootstrap.js" ? startup
      : request.url === "/client.js" ? fs.readFileSync(sourceFile, "utf8")
        : request.url === "/probe.js" ? fs.readFileSync(probeFile, "utf8") : null;
    response.writeHead(content === null ? 404 : 200, {
      "Content-Type": request.url === "/" ? "text/html; charset=utf-8"
        : "text/javascript; charset=utf-8",
    });
    response.end(content ?? "");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-delta-edge-"));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  const url = "http://127.0.0.1:" + server.address().port + "/";
  const options = ["--headless=new", "--disable-gpu", "--no-first-run",
    "--no-default-browser-check", "--disable-extensions", "--virtual-time-budget=10000",
    "--user-data-dir=" + path.join(dir, "edge-profile"), "--dump-dom", url];
  const result = await promisify(execFile)(edge, options, {
    timeout: 35_000, windowsHide: true, maxBuffer: 1024 * 1024,
  });
  assert.match(result.stdout, /EDGE_OPAQUE_DELTA_PASS/);
  assert.doesNotMatch(result.stdout, /EDGE_OPAQUE_DELTA_FAIL/);
});
