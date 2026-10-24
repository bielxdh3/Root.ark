"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const Module = require("node:module");
const crypto = require("node:crypto");
const os = require("node:os");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const catalogSource = path.resolve(__dirname, "../public/client/rootark-zk1-browser-catalog.js");
const portableSource = path.resolve(__dirname,
  "../public/client/rootark-zk1-portable-versioned-backup-transport.js");
const TIMEOUT_IN_SOURCE = "const HTTP_READ_DEADLINE_MS = 15_000;";
const TEST_DEADLINE_MS = 250;

function readJsonForTest() {
  // This fixture only substitutes the timeout in a loaded copy, never adds
  // an unsafe configuration override to production.
  const original = fs.readFileSync(catalogSource, "utf8");
  const altered = original.replace(TIMEOUT_IN_SOURCE,
    `const HTTP_READ_DEADLINE_MS = ${TEST_DEADLINE_MS};`)
    .replace("return Object.freeze({ openCatalog, getCatalogCiphertext,",
      "return Object.freeze({ __testReadJson: readJson, openCatalog, getCatalogCiphertext,");
  const synthetic = new Module(catalogSource, module);
  synthetic.filename = catalogSource;
  synthetic.paths = Module._nodeModulePaths(path.dirname(catalogSource));
  synthetic._compile(altered, catalogSource);
  return synthetic.exports.__testReadJson;
}

async function hostileHttp(t, behavior) {
  const sockets = new Set();
  const timers = new Set();
  const server = http.createServer((request, response) => {
    request.resume();
    if (behavior === "headers") return;
    response.writeHead(200, { "content-type": "application/json" });
    response.write("{");
    if (behavior === "trickle") {
      const timer = setInterval(() => response.write(" "), 35);
      timers.add(timer);
      response.on("close", () => { clearInterval(timer); timers.delete(timer); });
    }
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    for (const timer of timers) clearInterval(timer);
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}/zk-1/v1/catalog/read`;
}

async function assertBoundedRejection(action, label) {
  const started = Date.now();
  const outcome = await Promise.race([
    action().then(() => "ACCEPTED", () => "DENIED"),
    new Promise((resolve) => setTimeout(() => resolve("STUCK"), 1100)),
  ]);
  assert.equal(outcome, "DENIED", `${label}: fail closed on hostile HTTP`);
  const elapsed = Date.now() - started;
  assert.ok(elapsed >= 150 && elapsed < 1050, `${label}: bounded wall clock ${elapsed}ms`);
}

for (const behavior of ["headers", "partial", "trickle"]) {
  test(`signed browser catalog read denies stalled ${behavior} response by absolute wall deadline`,
    { timeout: 5000 }, async (t) => {
      const url = await hostileHttp(t, behavior);
      const readJson = readJsonForTest();
      await assertBoundedRejection(() => readJson(fetch, url, {}, () => {}),
        `catalog ${behavior}`);
    });
}

test("portable recovery zeroizes every decrypted CEK when signed catalog GET stalls", {
  timeout: 5000,
}, async (t) => {
  const url = await hostileHttp(t, "partial");
  const readJson = readJsonForTest();
  const exposed = [{ cek: crypto.randomBytes(32), ciphertext: crypto.randomBytes(128) },
    { cek: crypto.randomBytes(32), ciphertext: crypto.randomBytes(128) }];
  const catalogHead = { sequence: 1, catalogDigest: "test-head", totalCount: 2 };
  const fakeCatalog = {
    openCatalog: async () => catalogHead,
    assertVersionedArchiveMatchesCatalog: async () => {
      await readJson(fetch, url, {}, () => {});
      throw new Error("hostile catalog must never finish");
    },
  };
  const synthetic = new Module(portableSource, module);
  synthetic.filename = portableSource;
  synthetic.require = (name) => {
    if (name === "./rootark-zk1-browser-versioned-archive") {
      return { recoverArchive: async () => ({ files: exposed }) };
    }
    if (name === "./rootark-zk1-browser-catalog") return fakeCatalog;
    throw new Error("unexpected import");
  };
  synthetic._compile(fs.readFileSync(portableSource, "utf8"), portableSource);
  const transport = synthetic.exports;
  const provider = { get: async () => new TextEncoder().encode('{"synthetic":true}') };
  const assertLive = () => {};
  await assertBoundedRejection(() => transport.recoverPortableVersionedBackupWithSignedCatalog({
    archivePin: crypto.randomBytes(32), provider,
    recoveryInput: { recoverySecret: crypto.randomBytes(32),
      independentOwnerSpkiSha256: crypto.randomBytes(32),
      signerKeyId: crypto.randomBytes(16),
      scope: {}, pinnedCurrentHead: { digest: crypto.randomBytes(32) } },
    verifiedAuthority: {}, assertLive, catalogInput: { assertLive },
  }), "portable CEK");
  for (const file of exposed) {
    assert.ok(file.cek.every((byte) => byte === 0), "released CEK zeroized");
    assert.ok(file.ciphertext.every((byte) => byte === 0), "associated ciphertext zeroized");
  }
});

test("real Edge enforces browser catalog absolute deadline under restrictive CSP", {
  timeout: 35_000,
}, async (t) => {
  const edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (process.platform !== "win32" || !fs.existsSync(edge)) {
    t.skip("Edge Windows unavailable");
    return;
  }
  const source = fs.readFileSync(catalogSource, "utf8")
    .replace(TIMEOUT_IN_SOURCE, `const HTTP_READ_DEADLINE_MS = ${TEST_DEADLINE_MS};`)
    .replace("return Object.freeze({ openCatalog, getCatalogCiphertext,",
      "return Object.freeze({ __testReadJson: readJson, openCatalog, getCatalogCiphertext,");
  const probe = `(async () => {
    try {
      await RootarkZk1BrowserCatalog.__testReadJson(fetch,
        location.origin + "/stall", {}, () => {});
      document.getElementById("result").textContent = "EDGE_DEADLINE_FAIL";
    } catch (_) {
      document.getElementById("result").textContent = "EDGE_DEADLINE_PASS";
    }
  })().catch(() => { document.getElementById("result").textContent = "EDGE_DEADLINE_FAIL"; });`;
  const html = "<!doctype html><meta charset='utf-8'><output id='result'>PENDING</output>"
    + "<script src='/catalog.js'></script><script src='/probe.js'></script>";
  const server = http.createServer((request, response) => {
    response.setHeader("Content-Security-Policy",
      "default-src 'none'; script-src 'self'; connect-src 'self'");
    if (request.url === "/stall") {
      response.writeHead(200, { "content-type": "application/json" });
      response.write("{");
      return;
    }
    const body = request.url === "/" ? html
      : request.url === "/catalog.js" ? source
        : request.url === "/probe.js" ? probe : null;
    response.writeHead(body === null ? 404 : 200, {
      "content-type": request.url === "/" ? "text/html; charset=utf-8"
        : "text/javascript; charset=utf-8",
    });
    response.end(body ?? "");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-catalog-edge-deadline-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const url = `http://127.0.0.1:${server.address().port}/`;
  const result = await promisify(execFile)(edge, [
    "--headless=new", "--disable-gpu", "--disable-extensions",
    "--no-first-run", "--no-default-browser-check",
    "--virtual-time-budget=5000", "--user-data-dir=" + path.join(dir, "edge"),
    "--dump-dom", url,
  ], { windowsHide: true, timeout: 20_000, maxBuffer: 1024 * 1024 });
  assert.match(result.stdout, /EDGE_DEADLINE_PASS/);
  assert.doesNotMatch(result.stdout, /EDGE_DEADLINE_FAIL/);
});
