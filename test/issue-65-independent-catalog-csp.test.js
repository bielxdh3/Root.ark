"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const { parseIndependentCatalogConnectOrigins } = require("../src/zk1-catalog-connect-csp");

const ROOT = path.resolve(__dirname, "..");
const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const ENV_NAME = "ROOTARK_ZK1_INDEPENDENT_CATALOG_CONNECT_ORIGINS";

function request(origin, pathname, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get(new URL(pathname, origin), { headers }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers }));
    });
    req.once("error", reject);
    req.setTimeout(7000, () => req.destroy(new Error("HTTP request timed out")));
  });
}

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

async function fixture(t, catalogOrigins, script = "") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-csp-"));
  const publicDir = path.join(dir, "public");
  fs.mkdirSync(publicDir);
  fs.mkdirSync(path.join(dir, "data"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(publicDir, "index.html"), '<!doctype html><output id="result">PENDING</output><script defer src="/probe.js"></script>');
  fs.writeFileSync(path.join(publicDir, "login.html"), "<!doctype html><title>Login</title>");
  fs.writeFileSync(path.join(publicDir, "probe.js"), script);
  fs.writeFileSync(path.join(dir, "data", "users.local.json"), "[]");
  fs.writeFileSync(path.join(dir, "data", "folders.json"), "[]");
  const socket = http.createServer();
  const origin = await listen(socket);
  await new Promise((resolve) => socket.close(resolve));
  const port = Number(new URL(origin).port);
  const env = {
    ...process.env, NODE_ENV: "test", PORT: String(port), DB_ENABLED: "false",
    CLOUD_STORAGE_PROVIDER: "local", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
    JWT_SECRET: crypto.randomBytes(48).toString("hex"),
  };
  delete env[ENV_NAME];
  if (catalogOrigins !== undefined) env[ENV_NAME] = catalogOrigins;
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    env, cwd: dir, windowsHide: true, stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { if (stderr.length < 4096) stderr += chunk.toString(); });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill();
      await new Promise((resolve) => child.once("exit", resolve));
    }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });
  for (let i = 0; i < 250; i++) {
    if (child.exitCode !== null) throw new Error(`server exited (${child.exitCode}): ${stderr}`);
    try {
      const page = await request(origin, "/index.html");
      if (page.status === 200) return { origin, child, stderr: () => stderr };
    } catch { /* startup */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`server did not start: ${stderr}`);
}

test("catalog CSP origins accept only explicitly configured canonical HTTPS or loopback HTTP origins", () => {
  assert.deepEqual(parseIndependentCatalogConnectOrigins(undefined), []);
  assert.deepEqual(parseIndependentCatalogConnectOrigins(
    "https://cas.example:8443, https://witness.example, http://127.0.0.1:8484, http://[::1]:8485, https://cas.example:8443"),
  ["https://cas.example:8443", "https://witness.example", "http://127.0.0.1:8484", "http://[::1]:8485"]);
  for (const injected of [
    "https://cas.example; script-src *", "https://cas.example,", ",https://cas.example",
    "https://cas.example https://attacker.example", "https://evil.example/path",
    "https://evil.example/?x=1", "https://evil.example/#fragment",
    "https://username:password@evil.example", "https://evil.example@127.0.0.1",
    "http://192.168.1.1:443", "http://127.1:8080", "http://0.0.0.0:8181",
    "ws://127.0.0.1:8080", "https://*.example", "https://evil.example:443",
    "HTTPS://CAS.EXAMPLE", "https://cas.example\nconnect-src *",
    Array.from({ length: 9 }, (_, i) => `https://cas${i}.example`).join(","),
  ]) assert.throws(() => parseIndependentCatalogConnectOrigins(injected), undefined, injected);
});

test("real Root.ark serves independent catalog connect-src only on its workspace page", { timeout: 45_000 }, async (t) => {
  const cas = "https://cas.example:8443";
  const witness = "https://witness.example";
  const { origin } = await fixture(t, `${cas},${witness}`);
  for (const pathName of ["/", "/index.html"]) {
    const response = await request(origin, pathName);
    assert.equal(response.status, 200);
    assert.match(response.headers["content-security-policy"], /connect-src 'self' ws: wss: https:\/\/cas\.example:8443 https:\/\/witness\.example(?:;|$)/);
    assert.match(response.headers["content-security-policy"], /object-src 'none'/);
    assert.match(response.headers["content-security-policy"], /frame-ancestors 'self'/);
  }
  for (const pathName of ["/login.html", "/probe.js"]) {
    const response = await request(origin, pathName);
    const policy = response.headers["content-security-policy"];
    assert.match(policy, /connect-src 'self' ws: wss:(?:;|$)/);
    assert.doesNotMatch(policy, /cas\.example|witness\.example/);
  }
  const missing = await request(origin, "/does-not-exist");
  assert.equal(missing.status, 404);
  assert.doesNotMatch(missing.headers["content-security-policy"], /cas\.example|witness\.example/);
  const poisoned = await request(origin, "/index.html", {
    host: "untrusted.example", origin: "https://untrusted.example",
    "x-forwarded-host": "untrusted.example", "x-forwarded-proto": "https",
  });
  assert.equal(poisoned.status, 200);
  assert.doesNotMatch(poisoned.headers["content-security-policy"], /untrusted\.example/);
  assert.match(poisoned.headers["content-security-policy"], /https:\/\/cas\.example:8443 https:\/\/witness\.example/);
});

test("real Root.ark defaults to self-only catalog HTTP connections", { timeout: 45_000 }, async (t) => {
  const { origin } = await fixture(t);
  const policy = (await request(origin, "/index.html")).headers["content-security-policy"];
  assert.match(policy, /connect-src 'self' ws: wss:(?:;|$)/);
});

test("real Root.ark fails startup for malformed administrator CSP origins", { timeout: 45_000 }, async (t) => {
  await assert.rejects(() => fixture(t, "https://cas.example; connect-src *"),
    /server exited.*Invalid independent catalog CSP origin|server exited.*canonical HTTPS/s);
});

test("Edge allows both independently configured loopback probes and blocks an unlisted origin", {
  timeout: 90_000,
  skip: process.platform !== "win32" || !fs.existsSync(EDGE),
}, async (t) => {
  const targets = [];
  const hits = [0, 0, 0];
  for (let i = 0; i < 3; i++) {
    const service = http.createServer((req, res) => {
      hits[i]++;
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "content-type");
      res.setHeader("Cache-Control", "no-store");
      if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
      res.end("OK");
    });
    const origin = await listen(service);
    targets.push(origin);
    t.after(() => new Promise((resolve) => service.close(resolve)));
  }
  const script = `Promise.allSettled(${JSON.stringify(targets)}.map(origin => fetch(origin + '/probe', {
    method: 'POST', mode: 'cors', credentials: 'omit', redirect: 'error',
    headers: { 'content-type': 'application/json' }, body: '{}'
  }).then(response => response.text()))).then(results => {
    document.getElementById('result').textContent = results.map(result =>
      result.status === 'fulfilled' && result.value === 'OK' ? 'ALLOW' : 'BLOCK').join(',');
  });`;
  const { origin } = await fixture(t, targets.slice(0, 2).join(","), script);
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-edge-csp-"));
  t.after(() => fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
  const result = await new Promise((resolve, reject) => {
    const edge = spawn(EDGE, ["--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
      `--user-data-dir=${path.join(profile, "profile")}`, "--virtual-time-budget=8000", "--dump-dom", `${origin}/index.html`],
    { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    const output = [];
    let bytes = 0;
    const fail = setTimeout(() => { edge.kill(); reject(new Error("Edge navigation exceeded 25s")); }, 25000);
    edge.stdout.on("data", (buf) => { bytes += buf.length; if (bytes < 262144) output.push(buf); else edge.kill(); });
    edge.stderr.resume();
    edge.once("error", (error) => { clearTimeout(fail); reject(error); });
    edge.once("exit", (code) => {
      clearTimeout(fail);
      if (code !== 0) reject(new Error(`Edge exited ${code}`));
      else resolve(Buffer.concat(output).toString("utf8"));
    });
  });
  assert.match(result, /<output id="result">ALLOW,ALLOW,BLOCK<\/output>/,
    "CSP permits both configured CORS endpoints but denies any other origin before a network request");
  assert.ok(hits[0] > 0 && hits[1] > 0, "both approved endpoints received the browser probes");
  assert.equal(hits[2], 0, "disallowed endpoint received neither preflight nor POST");
});
