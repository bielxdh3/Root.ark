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
const SOURCE = "alice-precutover-opaque.bin";
const DEST = "alice-after-cutover.bin";
const BYTES = "W161_DISPOSABLE_OPAQUE_LEGACY_BYTES";

const request = (port, url, method = "GET", headers = {}, body) => new Promise((resolve, reject) => {
  const req = http.request({ hostname: "127.0.0.1", port, path: url, method,
    headers, signal: AbortSignal.timeout(12000) }, (res) => {
    const chunks = [];
    res.on("data", (chunk) => chunks.push(chunk));
    res.on("error", reject);
    res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
      body: Buffer.concat(chunks).toString("utf8") }));
  });
  req.on("error", reject);
  req.end(body);
});
async function portAvailable() {
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
    stream.on("data", (chunk) => { diagnostic = (diagnostic + chunk.toString()).slice(-1300); });
  child.diagnostic = () => diagnostic;
  for (let i = 0; i < 240 && child.exitCode === null; i++) {
    try { if ((await request(port, "/login.html")).status === 200) return child; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 60));
  }
  child.kill();
  throw new Error("disposable Root.ark boot failed: " + diagnostic);
}
async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve) => { child.once("exit", resolve); child.kill(); });
}
async function loginAndRename(port, password) {
  const body = JSON.stringify({ username: "alice", password });
  const login = await request(port, "/auth/login", "POST", {
    "content-type": "application/json", "content-length": Buffer.byteLength(body),
  }, body);
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((v) => v.split(";")[0]);
  const renameBody = JSON.stringify({ oldName: SOURCE, newName: DEST, folderId: "root" });
  return request(port, "/rename", "PUT", {
    cookie: cookies.join("; "), origin: `http://127.0.0.1:${port}`,
    "x-csrf-token": cookies.find((v) => v.startsWith("rootark_csrf="))?.split("=")[1],
    "content-type": "application/json", "content-length": Buffer.byteLength(renameBody),
  }, renameBody);
}
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w161-strict-rename-"));
  const data = path.join(dir, "data");
  fs.mkdirSync(data);
  fs.mkdirSync(path.join(dir, "uploads"));
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
    [`root/${SOURCE}`]: { folderId: "root", fileName: SOURCE, owner: "alice", public: false, users: {} },
  }));
  const src = path.join(dir, "uploads", SOURCE);
  const dst = path.join(dir, "uploads", DEST);
  fs.writeFileSync(src, BYTES);
  const trace = path.join(dir, "observe-native-rename.cjs");
  const traceLog = path.join(dir, "native-rename-dispatch.log");
  fs.writeFileSync(trace, [
    '"use strict";',
    'const fs = require("node:fs");',
    'const path = require("node:path");',
    `const source = ${JSON.stringify(src)};`,
    `const destination = ${JSON.stringify(dst)};`,
    `const log = ${JSON.stringify(traceLog)};`,
    'const original = fs.promises.rename.bind(fs.promises);',
    'fs.promises.rename = async function (oldPath, newPath) {',
    '  const forward = oldPath === source && newPath === destination;',
    '  const reverse = oldPath === destination && newPath === source;',
    '  if (forward || reverse) fs.appendFileSync(log, (forward ? "FORWARD_DISPATCH" : "ROLLBACK_DISPATCH") + "\\n");',
    '  const result = await original(oldPath, newPath);',
    '  if (forward || reverse) fs.appendFileSync(log, (forward ? "FORWARD_COMMIT" : "ROLLBACK_COMMIT") + "\\n");',
    '  return result;',
    '};',
  ].join("\n"));
  let child;
  t.after(async () => {
    await stop(child);
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  return { dir, password, src, dst, trace, traceLog,
    get traceLines() { return fs.existsSync(traceLog) ? fs.readFileSync(traceLog, "utf8").trim().split("\n") : []; },
    get child() { return child; }, set child(value) { child = value; } };
}

test("OFF-created legacy private file must not rename after STRICT=1 restart; OFF resumes", {
  timeout: 90_000,
}, async (t) => {
  const f = fixture(t);
  const port = await portAvailable();
  f.child = await boot(f.dir, port, false, f.trace);
  assert.equal(fs.readFileSync(f.src, "utf8"), BYTES);
  await stop(f.child);
  f.child = await boot(f.dir, port, true, f.trace);
  const result = await loginAndRename(port, f.password);
  assert.equal(result.status, 503, `strict rename leaked physical mutation: ${result.body} native=${f.traceLines.join(',')}`);
  assert.equal(result.headers["cache-control"], "no-store");
  assert.equal(JSON.parse(result.body).code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
  assert.equal(fs.readFileSync(f.src, "utf8"), BYTES);
  assert.equal(fs.existsSync(f.dst), false);
  assert.deepEqual(f.traceLines, [], "STRICT must not dispatch even a transient physical rename before rollback");
  await stop(f.child);
  f.child = await boot(f.dir, port, false, f.trace);
  const restored = await loginAndRename(port, f.password);
  assert.equal(restored.status, 200, `OFF semantics changed: ${restored.body}`);
  assert.equal(fs.readFileSync(f.dst, "utf8"), BYTES);
  assert.equal(fs.existsSync(f.src), false);
  assert.deepEqual(f.traceLines, ["FORWARD_DISPATCH", "FORWARD_COMMIT"]);
});

test("late OFF->STRICT flip after awaited source lookup rejects before physical rename", {
  timeout: 60_000,
}, async (t) => {
  const f = fixture(t);
  const port = await portAvailable();
  const arm = path.join(f.dir, "arm-late-strict");
  const tripped = path.join(f.dir, "late-strict-fired");
  const preload = path.join(f.dir, "late-strict-preload.cjs");
  fs.writeFileSync(preload, [
    '"use strict";',
    `require(${JSON.stringify(f.trace)});`,
    'const fs = require("node:fs");',
    'const path = require("node:path");',
    `const src = ${JSON.stringify(f.src)};`,
    `const arm = ${JSON.stringify(arm)};`,
    `const tripped = ${JSON.stringify(tripped)};`,
    'const original = fs.existsSync;',
    'fs.existsSync = function (filename) {',
    '  const exists = original.call(this, filename);',
    '  if (typeof filename === "string" && path.resolve(filename) === path.resolve(src)',
    '    && original.call(this, arm) && process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT === "off") {',
    '    process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "1";',
    '    fs.writeFileSync(tripped, "STRICT_AFTER_AWAIT");',
    '  }',
    '  return exists;',
    '};',
  ].join("\n"));
  f.child = await boot(f.dir, port, false, preload);
  fs.writeFileSync(arm, "ready");
  const result = await loginAndRename(port, f.password);
  assert.equal(fs.readFileSync(tripped, "utf8"), "STRICT_AFTER_AWAIT",
    "test did not trigger env change between route admission and physical rename");
  assert.equal(result.status, 503, `late STRICT rename physically mutated: ${result.body} native=${f.traceLines.join(',')}`);
  assert.equal(result.headers["cache-control"], "no-store");
  assert.equal(JSON.parse(result.body).code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
  assert.equal(fs.readFileSync(f.src, "utf8"), BYTES);
  assert.equal(fs.existsSync(f.dst), false);
  assert.deepEqual(f.traceLines, [], "late STRICT must forbid physical rename after awaited lookup");
});
