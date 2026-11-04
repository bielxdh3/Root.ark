"use strict";
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const NAME = "w168-disposable.txt";
const INIT = "w168-uninitialized.txt";
const OLD = "W168_OLD_OWNER_BYTES";
const CURRENT = "W168_CURRENT_OWNER_BYTES";

const request = (port, endpoint, method = "GET", headers = {}, body) => new Promise((resolve, reject) => {
  const req = http.request({ hostname: "127.0.0.1", port, path: endpoint, method,
    headers, signal: AbortSignal.timeout(16000) }, (res) => {
    const chunks = [];
    res.on("data", (chunk) => chunks.push(chunk));
    res.on("error", reject);
    res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
      body: Buffer.concat(chunks).toString("utf8") }));
  });
  req.on("error", reject);
  req.end(body);
});
async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}
async function boot(dir, port, strict, preload) {
  const env = { ...process.env, NODE_ENV: "test", DB_ENABLED: "false",
    PORT: String(port), UPLOAD_SCAN_ENABLED: "false", WEBDAV_ENABLED: "false",
    CLOUD_STORAGE_PROVIDER: "local", ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict ? "1" : "off",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    NODE_OPTIONS: [process.env.NODE_OPTIONS, preload && `--require=${preload}`].filter(Boolean).join(" ") };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    cwd: dir, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
  });
  let diagnostic = "";
  for (const stream of [child.stdout, child.stderr])
    stream.on("data", (chunk) => { diagnostic = (diagnostic + chunk.toString()).slice(-1400); });
  for (let i = 0; i < 240 && child.exitCode === null; i++) {
    try { if ((await request(port, "/login.html")).status === 200) return child; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 60));
  }
  child.kill();
  throw Error("disposable server failed to start: " + diagnostic);
}
async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve) => { child.once("exit", resolve); child.kill(); });
}
async function session(port, password) {
  const body = JSON.stringify({ username: "alice", password });
  const login = await request(port, "/auth/login", "POST", {
    "content-type": "application/json", "content-length": Buffer.byteLength(body),
  }, body);
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((v) => v.split(";")[0]);
  return { cookie: cookies.join("; "), origin: `http://127.0.0.1:${port}`,
    "x-csrf-token": cookies.find((v) => v.startsWith("rootark_csrf="))?.split("=")[1] };
}
const ROUTES = [
  { id: "initialize", method: "POST", endpoint: `/versions/${INIT}/initialize?folderId=root` },
  { id: "restore", method: "POST", endpoint: `/restore/${NAME}/v/1?folderId=root` },
  { id: "delete", method: "DELETE", endpoint: `/versions/${NAME}/v/1?folderId=root` },
];
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w168-versions-"));
  const data = path.join(dir, "data");
  const uploads = path.join(dir, "uploads");
  fs.mkdirSync(data);
  fs.mkdirSync(uploads);
  fs.mkdirSync(path.join(dir, "temp"));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"),
    process.platform === "win32" ? "junction" : "dir");
  const password = crypto.randomBytes(18).toString("base64url");
  fs.writeFileSync(path.join(data, "users.local.json"), JSON.stringify([{
    username: "alice", password: bcrypt.hashSync(password, 4), role: "admin",
    permissions: {}, sessionVersion: 0,
  }]));
  fs.writeFileSync(path.join(data, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "sistema", isRoot: true },
  ]));
  fs.writeFileSync(path.join(data, "file-permissions.json"), JSON.stringify({
    [`root/${NAME}`]: { folderId: "root", fileName: NAME, owner: "alice",
      public: false, users: {} },
    [`root/${INIT}`]: { folderId: "root", fileName: INIT, owner: "alice",
      public: false, users: {} },
  }));
  const current = path.join(uploads, NAME);
  const archived = path.join(uploads, NAME + ".v1");
  const initialized = path.join(uploads, INIT);
  const versions = path.join(data, "file-versions.json");
  fs.writeFileSync(current, CURRENT);
  fs.writeFileSync(archived, OLD);
  fs.writeFileSync(initialized, "W168_NEW_INITIAL_BYTES");
  const timestamp = "2026-10-28T12:00:00.000Z";
  fs.writeFileSync(versions, JSON.stringify({ [`root/${NAME}`]: {
    currentVersion: 2, versions: [
      { version: 1, storedAs: NAME + ".v1", uploadedBy: "alice",
        uploadedAt: timestamp, size: Buffer.byteLength(OLD), comment: "old" },
      { version: 2, storedAs: NAME, uploadedBy: "alice",
        uploadedAt: timestamp, size: Buffer.byteLength(CURRENT), comment: "current" },
    ],
  } }));
  const preload = path.join(dir, "adversarial-preload.cjs");
  const arm = path.join(dir, "arm-flip");
  const tripped = path.join(dir, "strict-flipped");
  const trace = path.join(dir, "native-version-mutators.log");
  fs.writeFileSync(preload, [
    '"use strict";',
    'const fs = require("node:fs");',
    'const path = require("node:path");',
    `const current = ${JSON.stringify(current)};`,
    `const archived = ${JSON.stringify(archived)};`,
    `const initialized = ${JSON.stringify(initialized)};`,
    `const versions = ${JSON.stringify(versions)};`,
    `const arm = ${JSON.stringify(arm)};`,
    `const tripped = ${JSON.stringify(tripped)};`,
    `const trace = ${JSON.stringify(trace)};`,
    'const originalStat = fs.statSync;',
    'const originalRead = fs.readFileSync;',
    'const originalWrite = fs.writeFileSync;',
    'const originalCopy = fs.copyFileSync;',
    'const originalRename = fs.renameSync;',
    'const originalRm = fs.rmSync;',
    'const target = (x) => typeof x === "string" && path.resolve(x);',
    'const mode = () => originalRead.call(fs, arm, "utf8").trim();',
    'function lateFlip(kind, file) {',
    '  if (!originalStat.call(fs, arm, { throwIfNoEntry: false })) return;',
    '  if (process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT !== "off") return;',
    '  const wanted = mode();',
    '  if ((wanted === "initialize" && kind === "stat" && target(file) === initialized)',
    '    || (wanted === "restore" && kind === "stat" && target(file) === archived)',
    '    || (wanted === "delete" && kind === "read" && target(file) === versions)) {',
    '    process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "1";',
    '    originalWrite.call(fs, tripped, kind + ":AFTER_ADMISSION");',
    '  }',
    '}',
    'fs.statSync = function (file, ...rest) { const result = originalStat.call(fs, file, ...rest); lateFlip("stat", file); return result; };',
    'fs.readFileSync = function (file, ...rest) { const result = originalRead.call(fs, file, ...rest); lateFlip("read", file); return result; };',
    'const watched = (file) => [current, archived, initialized, versions].includes(target(file))',
    '  || (typeof file === "string" && path.dirname(path.resolve(file)) === path.dirname(current)',
    '    && path.basename(file).startsWith(".rootark-restore-"));',
    'function mark(kind, file) { if (watched(file) && originalStat.call(fs, arm, { throwIfNoEntry: false }))',
    '  originalWrite.call(fs, trace, kind + ":" + path.basename(file) + "\\n", { flag: "a" }); }',
    'fs.writeFileSync = function (file, ...rest) { mark("WRITE", file); return originalWrite.call(fs, file, ...rest); };',
    'fs.copyFileSync = function (src, dst, ...rest) { mark("COPY", dst); return originalCopy.call(fs, src, dst, ...rest); };',
    'fs.renameSync = function (src, dst, ...rest) { mark("RENAME", src); return originalRename.call(fs, src, dst, ...rest); };',
    'fs.rmSync = function (file, ...rest) { mark("DELETE", file); return originalRm.call(fs, file, ...rest); };',
  ].join("\n"));
  let child;
  t.after(async () => {
    await stop(child);
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  return { dir, password, current, archived, initialized, versions, arm, tripped, trace, preload,
    get child() { return child; }, set child(c) { child = c; },
    get traces() { return fs.existsSync(trace) ? fs.readFileSync(trace, "utf8").trim().split("\n") : []; },
    snapshot() { return [fs.readFileSync(current, "utf8"), fs.readFileSync(archived, "utf8"),
      fs.readFileSync(initialized, "utf8"), fs.readFileSync(versions, "utf8")]; },
  };
}
function denied(f, response, before) {
  assert.equal(response.status, 503, response.body);
  assert.equal(response.headers["cache-control"], "no-store");
  assert.equal(JSON.parse(response.body).code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
  assert.deepEqual(f.snapshot(), before, "STRICT changed physical version bytes or metadata");
  assert.deepEqual(f.traces, [], "STRICT dispatched transient physical or metadata mutations");
}
for (const route of ROUTES) {
  test(`real JWT/CSRF ${route.id} STRICT restart rejects physical mutation; OFF preserves legacy behavior`, {
    timeout: 100000,
  }, async (t) => {
    const f = fixture(t);
    const port = await freePort();
    f.child = await boot(f.dir, port, true, f.preload);
    const headers = await session(port, f.password);
    const before = f.snapshot();
    denied(f, await request(port, route.endpoint, route.method, headers), before);
    await stop(f.child);
    f.child = await boot(f.dir, port, false, f.preload);
    const offHeaders = await session(port, f.password);
    const result = await request(port, route.endpoint, route.method, offHeaders);
    assert.equal(result.status, 200, `OFF ${route.id}: ${result.body}`);
    if (route.id === "initialize") {
      assert.equal(JSON.parse(fs.readFileSync(f.versions, "utf8"))[`root/${INIT}`].currentVersion, 1);
    } else if (route.id === "restore") {
      assert.equal(fs.readFileSync(f.current, "utf8"), OLD);
      assert.equal(fs.readFileSync(path.join(f.dir, "uploads", NAME + ".v2"), "utf8"), CURRENT);
    } else {
      assert.equal(fs.existsSync(f.archived), false);
      assert.equal(JSON.parse(fs.readFileSync(f.versions, "utf8"))[`root/${NAME}`].versions.length, 1);
    }
  });
  test(`real JWT/CSRF ${route.id} late OFF->STRICT denies before physical/metadata sink`, {
    timeout: 70000,
  }, async (t) => {
    const f = fixture(t);
    const port = await freePort();
    f.child = await boot(f.dir, port, false, f.preload);
    const headers = await session(port, f.password);
    const before = f.snapshot();
    fs.writeFileSync(f.arm, route.id);
    const response = await request(port, route.endpoint, route.method, headers);
    assert.match(fs.readFileSync(f.tripped, "utf8"), /AFTER_ADMISSION/,
      "test must flip STRICT during route work, not before HTTP entry");
    denied(f, response, before);
  });
}
