"use strict";

// Adversarial HTTP tests: strict cutover must reject a *physical* legacy
// cross-folder move, including a late mode flip after an awaited lookup.
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
const TARGET_FOLDER = "archive";
const BYTES = "W166_DISPOSABLE_PRE_CUTOVER_BYTES";

const request = (port, endpoint, method = "GET", headers = {}, body) => new Promise((resolve, reject) => {
  const req = http.request({ hostname: "127.0.0.1", port, path: endpoint, method,
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
async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
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
    stream.on("data", (chunk) => { diagnostic = (diagnostic + chunk.toString()).slice(-1200); });
  for (let i = 0; i < 240 && child.exitCode === null; i++) {
    try { if ((await request(port, "/login.html")).status === 200) return child; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 60));
  }
  child.kill();
  throw new Error("disposable server failed to start: " + diagnostic);
}
async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve) => { child.once("exit", resolve); child.kill(); });
}
async function loginAndMove(port, password) {
  const body = JSON.stringify({ username: "alice", password });
  const login = await request(port, "/auth/login", "POST", {
    "content-type": "application/json", "content-length": Buffer.byteLength(body),
  }, body);
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((v) => v.split(";")[0]);
  const move = JSON.stringify({ name: SOURCE, fromFolderId: "root", toFolderId: TARGET_FOLDER });
  return request(port, "/move", "PUT", {
    cookie: cookies.join("; "), origin: `http://127.0.0.1:${port}`,
    "x-csrf-token": cookies.find((v) => v.startsWith("rootark_csrf="))?.split("=")[1],
    "content-type": "application/json", "content-length": Buffer.byteLength(move),
  }, move);
}
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w166-strict-move-"));
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
    { id: TARGET_FOLDER, name: "Archive", createdBy: "alice", isRoot: false },
  ]));
  fs.writeFileSync(path.join(data, "file-permissions.json"), JSON.stringify({
    [`root/${SOURCE}`]: { folderId: "root", fileName: SOURCE, owner: "alice",
      public: false, users: {} },
  }));
  const src = path.join(dir, "uploads", SOURCE);
  const dst = path.join(dir, "uploads", TARGET_FOLDER, SOURCE);
  fs.writeFileSync(src, BYTES);
  const trace = path.join(dir, "observe-native-move.cjs");
  const traceLog = path.join(dir, "native-move-dispatch.log");
  fs.writeFileSync(trace, [
    '"use strict";',
    'const fs = require("node:fs");',
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
    get traceLines() { return fs.existsSync(traceLog)
      ? fs.readFileSync(traceLog, "utf8").trim().split("\n") : []; },
    get child() { return child; }, set child(value) { child = value; } };
}
function assertDeniedWithoutMove(f, response) {
  assert.equal(response.status, 503, `strict move: ${response.body}, native=${f.traceLines.join(",")}`);
  assert.equal(response.headers["cache-control"], "no-store");
  assert.equal(JSON.parse(response.body).code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
  assert.equal(fs.readFileSync(f.src, "utf8"), BYTES);
  assert.equal(fs.existsSync(f.dst), false);
  assert.deepEqual(f.traceLines, [], "STRICT must not dispatch even transient native rename");
}

test("OFF-created private file must not move across folders after STRICT restart; OFF resumes", {
  timeout: 90000,
}, async (t) => {
  const f = fixture(t);
  const port = await freePort();
  f.child = await boot(f.dir, port, false, f.trace);
  assert.equal(fs.readFileSync(f.src, "utf8"), BYTES);
  await stop(f.child);
  f.child = await boot(f.dir, port, true, f.trace);
  assertDeniedWithoutMove(f, await loginAndMove(port, f.password));
  await stop(f.child);
  f.child = await boot(f.dir, port, false, f.trace);
  const permitted = await loginAndMove(port, f.password);
  assert.equal(permitted.status, 200, `OFF move regressed: ${permitted.body}`);
  assert.equal(fs.existsSync(f.src), false);
  assert.equal(fs.readFileSync(f.dst, "utf8"), BYTES);
  assert.deepEqual(f.traceLines, ["FORWARD_DISPATCH", "FORWARD_COMMIT"]);
});

test("late OFF-to-STRICT flip after awaited source cache lookup forbids native cross-folder move", {
  timeout: 60000,
}, async (t) => {
  const f = fixture(t);
  const port = await freePort();
  const arm = path.join(f.dir, "arm-late-strict");
  const tripped = path.join(f.dir, "late-strict-fired");
  const preload = path.join(f.dir, "late-strict-preload.cjs");
  const destinationLookup = path.join(f.dir, "temp", TARGET_FOLDER, SOURCE);
  fs.writeFileSync(preload, [
    '"use strict";',
    `require(${JSON.stringify(f.trace)});`,
    'const fs = require("node:fs");',
    `const lookup = ${JSON.stringify(destinationLookup)};`,
    `const arm = ${JSON.stringify(arm)};`,
    `const tripped = ${JSON.stringify(tripped)};`,
    'const original = fs.existsSync;',
    'fs.existsSync = function (filename) {',
    '  const result = original.call(this, filename);',
    '  if (filename === lookup && original.call(this, arm)',
    '    && process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT === "off") {',
    '    process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "1";',
    '    fs.writeFileSync(tripped, "STRICT_AFTER_AWAIT");',
    '  }',
    '  return result;',
    '};',
  ].join("\n"));
  f.child = await boot(f.dir, port, false, preload);
  fs.writeFileSync(arm, "ready");
  const result = await loginAndMove(port, f.password);
  assert.equal(fs.readFileSync(tripped, "utf8"), "STRICT_AFTER_AWAIT",
    "test did not flip mode after cache authorization but before native move");
  assertDeniedWithoutMove(f, result);
});
