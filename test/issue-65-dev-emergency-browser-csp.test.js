"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const ASSETS = new Map([
  ["/client/rootark-api.js", path.join(ROOT, "public", "client", "rootark-api.js")],
  ["/client/rootark-dev-vault-crypto.js", path.join(ROOT, "public", "client", "rootark-dev-vault-crypto.js")],
  ["/client/rootark-dev-vault-migration.js", path.join(ROOT, "public", "client", "rootark-dev-vault-migration.js")],
  ["/client/rootark-dev-vault-emergency.js", path.join(ROOT, "public", "client", "rootark-dev-vault-emergency.js")],
  ["/client/rootark-dev-vault-trusted-device.js", path.join(ROOT, "public", "client", "rootark-dev-vault-trusted-device.js")],
  ["/client/rootark-dev-vault-ui.js", path.join(ROOT, "public", "client", "rootark-dev-vault-ui.js")],
  ["/zk-dev/vendor/libsodium-sumo.js", require.resolve("libsodium-sumo")],
  ["/zk-dev/vendor/libsodium-wrappers.js", require.resolve("libsodium-wrappers-sumo")],
]);
const PROBE = [
  'window.addEventListener("load", async () => {',
  ' const output = document.createElement("output");',
  ' output.id = "browser-csp-argon2id-result"; document.body.append(output);',
  ' try {',
  '  const secret = await RootarkDevVaultCrypto.generateRecoveryKey();',
  '  const pkg = await RootarkDevVaultEmergency.createEmergencyPackage({ username: "alice",',
  '   recoveryKey: secret.recoveryKey, password: "synthetic password for browser recovery 2026" });',
  '  const raw = await RootarkDevVaultEmergency.openEmergencyPackage({ username: "alice",',
  '   packageBytes: pkg, password: "synthetic password for browser recovery 2026" });',
  '  output.textContent = raw === secret.recoveryKey ? "BROWSER_CSP_ARGON2ID_PASS" : "BROWSER_CSP_ARGON2ID_MISMATCH";',
  '  const keyId = await RootarkDevVaultCrypto.keyCommitment(secret.recoveryKey, "alice");',
  '  const trusted = await RootarkDevVaultTrustedDevice.enrollTrustedDevice({',
  '   username: "alice", recoveryKey: secret.recoveryKey, keyId });',
  '  const pending = await RootarkDevVaultTrustedDevice.createRecoveryRequest({username: "alice"});',
  '  const answer = await RootarkDevVaultTrustedDevice.approveRecoveryRequest({',
  '   username: "alice", record: trusted, request: pending.request });',
  '  const restored = await RootarkDevVaultTrustedDevice.completeRecoveryRequest({',
  '   username: "alice", privateKey: pending.privateKey, request: pending.request, answer });',
  '  if (restored.recoveryKey !== secret.recoveryKey) output.textContent = "BROWSER_DEVICE_RECOVERY_MISMATCH";',
  '  else if (output.textContent === "BROWSER_CSP_ARGON2ID_PASS") output.textContent = "BROWSER_CSP_ARGON2ID_PASS BROWSER_DEVICE_RECOVERY_PASS";',
  ' } catch (error) { output.textContent = "BROWSER_CSP_ARGON2ID_ERROR"; }',
  '});',
].join("\n");

test("developer page Argon2id runs under self-only JS and scoped wasm-unsafe-eval CSP", {
  timeout: 65_000,
}, async (t) => {
  if (process.platform !== "win32" || !fs.existsSync(EDGE)) {
    t.skip("Microsoft Edge headless browser unavailable");
    return;
  }
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-dev-browser-csp-"));
  const original = fs.readFileSync(path.join(ROOT, "public", "zk-dev-vault.html"), "utf8");
  assert.match(original, /src="\/zk-dev\/vendor\/libsodium-sumo\.js"/);
  assert.match(original, /src="\/client\/rootark-dev-vault-emergency\.js"/);
  assert.match(original, /src="\/client\/rootark-dev-vault-trusted-device\.js"/);
  const page = original.replace("</body>", '<script defer src="/__probe.js"></script></body>');
  const csp = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
    + "style-src 'self' 'unsafe-inline'; object-src 'none'";
  const server = http.createServer((req, res) => {
    res.setHeader("Content-Security-Policy", csp);
    res.setHeader("Cache-Control", "no-store");
    if (req.url === "/" || req.url === "/zk-dev-vault.html") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.end(page);
      return;
    }
    if (req.url === "/__probe.js") {
      res.setHeader("Content-Type", "application/javascript");
      res.end(PROBE);
      return;
    }
    if (req.url === "/zk-dev/v1/session") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ username: "alice", activeKeyId: null }));
      return;
    }
    if (req.url === "/zk-dev/v1/objects") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ objects: [] }));
      return;
    }
    if (ASSETS.has(req.url)) {
      res.setHeader("Content-Type", "application/javascript");
      fs.createReadStream(ASSETS.get(req.url)).pipe(res);
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = "http://127.0.0.1:" + server.address().port + "/zk-dev-vault.html";
  const args = ["--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
    "--user-data-dir=" + path.join(temp, "profile"),
    "--virtual-time-budget=60000", "--dump-dom", url];
  let edge;
  try {
    const output = await new Promise((resolve, reject) => {
      edge = spawn(EDGE, args, { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
      const chunks = [];
      let bytes = 0;
      edge.stdout.on("data", (chunk) => {
        bytes += chunk.byteLength;
        if (bytes <= 256 * 1024) chunks.push(chunk);
        else edge.kill();
      });
      edge.stderr.resume();
      edge.once("error", reject);
      edge.once("exit", (code) => code === 0 && bytes <= 256 * 1024
        ? resolve(Buffer.concat(chunks).toString("utf8"))
        : reject(new Error("Headless browser did not complete successfully")));
    });
    const result = /<output id="browser-csp-argon2id-result">([^<]*)<\/output>/i.exec(output)?.[1] || "PROBE_NOT_PRESENT";
    assert.match(result, /BROWSER_CSP_ARGON2ID_PASS/,
      "browser Argon2id must run without allowing unrestricted JavaScript eval");
    assert.match(result, /BROWSER_DEVICE_RECOVERY_PASS/,
      "the browser's own WebCrypto must complete the trusted-device recovery");
  } finally {
    if (edge && edge.exitCode === null) edge.kill();
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(temp, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
  }
});
