const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const bcrypt = require("bcryptjs");

const ROOT = path.resolve(__dirname, "..");
const SERVER = fs.readFileSync(path.join(ROOT, "server.js"), "utf8");

function freePort() {
  return new Promise((resolve, reject) => {
    const listener = net.createServer();
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", () => { const port = listener.address().port; listener.close(() => resolve(port)); });
  });
}

function request(port, requestPath, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, ...options }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.once("error", reject);
    req.end(options.body);
  });
}

async function waitForServer(port) {
  for (let index = 0; index < 100; index += 1) {
    try { await request(port, "/login.html"); return; } catch { await new Promise((resolve) => setTimeout(resolve, 40)); }
  }
  throw new Error("server did not start");
}

test("realtime and WebDAV meta-remediation matrix", async (t) => {
  const cases = [
    ["01 payload limit is configured", () => assert.match(SERVER, /maxPayload: REALTIME_MAX_PAYLOAD_BYTES/)],
    ["02 compression is disabled", () => assert.match(SERVER, /perMessageDeflate: false/)],
    ["03 heartbeat interval is configured", () => assert.match(SERVER, /REALTIME_HEARTBEAT_MS/)],
    ["04 heartbeat sends ping", () => assert.match(SERVER, /socket\.ping\(\)/)],
    ["05 dead sockets terminate", () => assert.match(SERVER, /socket\.terminate\(\)/)],
    ["06 heartbeat interval is cleared", () => assert.match(SERVER, /clearInterval\(realtimeHeartbeat\)/)],
    ["07 binary frames close with 1003", () => assert.match(SERVER, /socket\.close\(1003/)],
    ["08 slow clients close with 1013", () => assert.match(SERVER, /socket\.close\(1013/)],
    ["09 buffered amount is bounded", () => assert.match(SERVER, /REALTIME_MAX_BUFFERED_BYTES/)],
    ["10 realtime burst is bounded", () => assert.match(SERVER, /REALTIME_MAX_MESSAGES_PER_WINDOW/)],
    ["11 burst violation closes with 1008", () => assert.match(SERVER, /Limite de mensagens excedido/)],
    ["12 realtime authentication uses cookie", () => assert.match(SERVER, /parseCookies\(req\.headers\.cookie\)/)],
    ["13 realtime authentication checks origin", () => assert.match(SERVER, /origin === expectedOrigin/)],
    ["14 stale realtime identity is refreshed", () => assert.match(SERVER, /refreshRealtimeUser\(socket\)/)],
    ["15 invalid realtime identity closes", () => assert.match(SERVER, /Token invalido/)],
    ["16 malformed realtime JSON is contained", () => assert.match(SERVER, /JSON\.parse\(rawMessage\.toString\(\)\)/)],
    ["17 pong event is accepted", () => assert.match(SERVER, /message\.event === "ping"/)],
    ["18 realtime sends structured events", () => assert.match(SERVER, /JSON\.stringify\(\{ event, payload/)],
    ["19 realtime server path is explicit", () => assert.match(SERVER, /path: "\/ws"/)],
    ["20 realtime server closes on shutdown", () => assert.match(SERVER, /server\.once\("close"/)],
    ["21 WebDAV mount is normalized", () => assert.match(SERVER, /normalizeWebDavMountPath/)],
    ["22 WebDAV path matching is explicit", () => assert.match(SERVER, /isWebDavRequestPath/)],
    ["23 WebDAV named wildcard route exists", () => assert.match(SERVER, /WEBDAV_PATH}\/\*splat/)],
    ["24 Express 4 wildcard compatibility exists", () => assert.match(SERVER, /express\/package\.json/)],
    ["25 WebDAV OPTIONS advertises DAV", () => assert.match(SERVER, /res\.setHeader\("DAV", "1"\)/)],
    ["26 WebDAV allows only configured methods", () => assert.match(SERVER, /if \(WEBDAV_ALLOW_MOVE\) methods\.push\("MOVE"\)/)],
    ["27 WebDAV authenticates Basic credentials", () => assert.match(SERVER, /authenticateWebDavRequest/)],
    ["28 WebDAV emits WWW-Authenticate", () => assert.match(SERVER, /WWW-Authenticate/)],
    ["29 WebDAV checks request origin", () => assert.match(SERVER, /Origin denied/)],
    ["30 WebDAV decodes path segments repeatedly", () => assert.match(SERVER, /index < 3/)],
    ["31 WebDAV rejects slash injection", () => assert.match(SERVER, /decoded\.includes\("\/"\)/)],
    ["32 WebDAV rejects backslash injection", () => assert.match(SERVER, /decoded\.includes\("\\\\"\)/)],
    ["33 WebDAV rejects NUL injection", () => assert.match(SERVER, /decoded\.includes\("\\0"\)/)],
    ["34 WebDAV bounds PROPFIND depth", () => assert.match(SERVER, /!\["0", "1"\]\.includes\(depth\)/)],
    ["35 WebDAV returns multistatus", () => assert.match(SERVER, /\.status\(207\)/)],
    ["36 WebDAV bounds PUT content length", () => assert.match(SERVER, /SINGLE_UPLOAD_MAX_BYTES/)],
    ["37 WebDAV streams PUT body", () => assert.match(SERVER, /pipeline\(req, limiter, fs\.createWriteStream/)],
    ["38 WebDAV stages PUT in incoming", () => assert.match(SERVER, /SIMPLE_UPLOAD_INCOMING_DIR/)],
    ["39 WebDAV MOVE has explicit feature flag", () => assert.match(SERVER, /WEBDAV_ALLOW_MOVE/)],
    ["40 WebDAV MOVE requires upload permission", () => assert.match(SERVER, /Upload permission required/)],
    ["41 WebDAV MOVE rejects cross-folder targets", () => assert.match(SERVER, /Cross-folder MOVE is not supported/)],
    ["42 WebDAV MOVE rejects identical source", () => assert.match(SERVER, /Source and destination are identical/)],
    ["43 WebDAV MOVE uses overwrite precondition", () => assert.match(SERVER, /Destination exists/)],
    ["44 WebDAV MOVE validates destination origin", () => assert.match(SERVER, /target\.origin !== getExpectedOrigin/)],
    ["45 WebDAV MOVE validates child paths", () => assert.match(SERVER, /isSafeChildPath\(source\.folder\.uploadDir/)],
    ["46 WebDAV MOVE has a transaction id", () => assert.match(SERVER, /const transactionId = crypto\.randomUUID\(\)/)],
    ["47 WebDAV MOVE journals transaction state", () => assert.match(SERVER, /writeWebDavMoveJournal\(journal\)/)],
    ["48 WebDAV MOVE stages source before destination work", () => assert.match(SERVER, /step\("source\.stage"/)],
    ["49 WebDAV MOVE preserves destination before replacement", () => assert.match(SERVER, /step\("destination\.preserve"/)],
    ["50 WebDAV MOVE installs replacement by rename", () => assert.match(SERVER, /step\("replacement\.install"/)],
    ["51 WebDAV MOVE never unlinks destination before source staging", () => assert.equal(SERVER.includes("if (destinationExists) fs.rmSync(destinationPath"), false)],
    ["52 WebDAV MOVE snapshots metadata", () => assert.match(SERVER, /snapshotWebDavMoveMetadata/)],
    ["53 WebDAV MOVE restores metadata on failure", () => assert.match(SERVER, /restoreWebDavMoveMetadata\(metadataSnapshot\)/)],
    ["54 WebDAV MOVE journals public-link metadata", () => assert.match(SERVER, /metadata\.public_links/)],
    ["55 WebDAV MOVE journals permission metadata", () => assert.match(SERVER, /metadata\.permissions/)],
    ["56 WebDAV MOVE journals expiration metadata", () => assert.match(SERVER, /metadata\.expirations/)],
    ["57 WebDAV MOVE journals version metadata", () => assert.match(SERVER, /metadata\.versions/)],
    ["58 WebDAV MOVE journals encrypted metadata", () => assert.match(SERVER, /metadata\.encrypted/)],
    ["59 WebDAV MOVE supports named failure injection", () => assert.match(SERVER, /WEBDAV_MOVE_FAIL_AFTER/)],
    ["60 WebDAV MOVE supports numeric failure injection", () => assert.match(SERVER, /Number\(requestedFailure\) === stepNumber/)],
  ];

  await t.test("transactional replacement failure preserves both files", { timeout: 20_000 }, async (t2) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-transaction-"));
    fs.mkdirSync(path.join(dir, "data"));
    fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([{ username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: { upload: true }, sessionVersion: 0 }]));
    fs.mkdirSync(path.join(dir, "uploads"));
    fs.writeFileSync(path.join(dir, "uploads", "source.txt"), "source");
    fs.writeFileSync(path.join(dir, "uploads", "target.txt"), "target");
    try { fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction"); } catch {}
    const port = await freePort();
    const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: { ...process.env, PORT: String(port), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", WEBDAV_ENABLED: "true", WEBDAV_ALLOW_MOVE: "true", WEBDAV_MOVE_FAIL_AFTER: "replacement.install", JWT_SECRET: crypto.randomBytes(48).toString("base64url") }, stdio: "ignore", windowsHide: true });
    t2.after(async () => { if (child.exitCode === null) { child.kill(); await new Promise((resolve) => child.once("exit", resolve)); } fs.rmSync(dir, { recursive: true, force: true }); });
    await waitForServer(port);
    const authorization = `Basic ${Buffer.from("agent:password").toString("base64")}`;
    const result = await request(port, "/dav/source.txt", { method: "MOVE", headers: { authorization, destination: "/dav/target.txt", overwrite: "T" } });
    assert.equal(result.status, 500);
    assert.equal(fs.readFileSync(path.join(dir, "uploads", "source.txt"), "utf8"), "source");
    assert.equal(fs.readFileSync(path.join(dir, "uploads", "target.txt"), "utf8"), "target");
  });

  for (const [name, body] of cases) await t.test(name, body);
  assert.equal(cases.length, 60);
});
