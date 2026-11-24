"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { readReadyEdgeDevToolsPort, fetchReadyEdgeDevToolsPage } =
  require("../scripts/edge-devtools-ready");

test("Edge CDP file race: absent, partial, zero and invalid ports never become ready", (t) => {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-edge-port-fixture-"));
  t.after(() => fs.rmSync(profile, { recursive: true, force: true }));
  const file = path.join(profile, "DevToolsActivePort");
  assert.equal(readReadyEdgeDevToolsPort(profile), null, "file may not exist yet");
  for (const partial of ["", "0\n/devtools/browser/abcdef12", "65536\n/devtools/browser/abcdef12",
    "9222", "9222\n", "9222\n/foreign/socket/abcdef12", "x9222\n/devtools/browser/abcdef12",
    "9222\n/devtools/browser/abc", "9222\n/devtools/browser/abcdef12\n".repeat(1024)]) {
    fs.writeFileSync(file, partial);
    assert.equal(readReadyEdgeDevToolsPort(profile), null, `partial port must be rejected`);
  }
  fs.writeFileSync(file, "9222\r\n/devtools/browser/abcdef12\r\n");
  assert.equal(readReadyEdgeDevToolsPort(profile), 9222);
  fs.rmSync(file);
  assert.equal(readReadyEdgeDevToolsPort(profile), null, "file disappeared after being ready");
});

test("Edge CDP readiness requires a real page on the same loopback port", async (t) => {
  let mode = "unready";
  const server = http.createServer((_req, res) => {
    res.setHeader("Content-Type", "application/json");
    if (mode === "unready") res.end("[]");
    else if (mode === "foreign") res.end(JSON.stringify([{ type: "page",
      webSocketDebuggerUrl: "ws://example.com:9222/devtools/page/123" }]));
    else res.end(JSON.stringify([{ type: "page",
      webSocketDebuggerUrl: `ws://127.0.0.1:${server.address().port}/devtools/page/123` }]));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;
  assert.equal(await fetchReadyEdgeDevToolsPage(port), null);
  mode = "foreign";
  assert.equal(await fetchReadyEdgeDevToolsPage(port), null);
  mode = "ready";
  assert.match((await fetchReadyEdgeDevToolsPage(port)).webSocketDebuggerUrl,
    /^ws:\/\/127\.0\.0\.1:/);
  assert.equal(await fetchReadyEdgeDevToolsPage(0), null);
});
