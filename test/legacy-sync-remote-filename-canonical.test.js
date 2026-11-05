"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { writePrivateSyncConfig } =
  require("../sync-client/rootark-sync-private-config");

const CLI = path.resolve(__dirname, "../sync-client/rootark-sync.js");
// The real /upload handler in server.js calls shortenFileName; this is its
// 30-code-unit basename truncation, used to prove two sources alias remotely.
function serverFilename(name) {
  const extension = path.extname(name);
  const base = path.basename(name, extension);
  return name.length <= 30 ? name : `${base.slice(0, Math.max(1, 30 - extension.length))}${extension}`;
}

async function runFixture(t, names, { strictCapability = true } = {}) {
  const privateDir = createPrivateAuthorityFixture("rootark-canonical-name-private-");
  const source = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-canonical-name-source-"));
  t.after(async () => {
    await fs.rm(source, { recursive: true, force: true });
    await fs.rm(privateDir, { recursive: true, force: true });
  });
  for (const name of names) await fs.writeFile(path.join(source, name), `UNIQUE_SOURCE_${name}`);
  const uploads = [];
  const server = http.createServer((req, res) => {
    // Disposable server fixture advertises the strict-name protocol contract.
    if (req.url === "/legacy-sync/capabilities" && !strictCapability) {
      return res.writeHead(404, { "Content-Type": "application/json" }).end("{}");
    }
    if (req.url === "/legacy-sync/capabilities") {
      return res.writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ strictFilename: true }));
    }
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
    } else if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (part) => chunks.push(part));
      req.on("end", () => {
        const contents = Buffer.concat(chunks).toString("utf8");
        const submittedName = /filename="([^"]+)"/.exec(contents)?.[1] || "unknown.txt";
        uploads.push(submittedName);
        res.writeHead(200, { "Content-Type": "application/json" })
          .end(JSON.stringify({ fileName: serverFilename(submittedName) }));
      });
    } else res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const configPath = path.join(privateDir, "config.json");
  await writePrivateSyncConfig(configPath, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    localFolder: source, targetFolderId: "root", username: "fixture",
    token: "fixture-token", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  }));
  const child = spawn(process.execPath,
    [CLI, "start", "--legacy-development-opt-in", "--once", "--config", configPath],
    { cwd: privateDir, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (part) => { output += part.toString("utf8"); });
  child.stderr.on("data", (part) => { output += part.toString("utf8"); });
  const code = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error(`sync child timed out: ${output}`)); },
      process.platform === "win32" ? 90000 : 30000);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (exitCode) => { clearTimeout(timer); resolve(exitCode); });
  });
  return { code, output, uploads };
}

test("two distinct 31-character local basenames cannot alias through server truncation", {
  timeout: 180000,
}, async (t) => {
  const prefix = "a".repeat(26);
  const names = [`${prefix}X.txt`, `${prefix}Y.txt`];
  assert.equal(names[0].length, 31);
  assert.notEqual(names[0], names[1]);
  assert.equal(serverFilename(names[0]), serverFilename(names[1]),
    "real server.js shortenFileName collapses both basename identities");
  const result = await runFixture(t, names);
  assert.notEqual(result.code, 0, "unsafe basename must fail closed");
  assert.match(result.output, /SYNC_REMOTE_BASENAME_NONCANONICAL/);
  assert.deepEqual(result.uploads, [], "both filenames must be rejected before any remote POST");
});

test("colon filename cannot become a Windows alternate-stream underscore alias", {
  timeout: 180000,
  skip: process.platform === "win32" ? "Windows NTFS does not permit colon in local file names" : false,
}, async (t) => {
  // Windows server.js maps ':' to '_' even if this legacy client runs on POSIX.
  const result = await runFixture(t, ["a:b.txt", "a_b.txt"]);
  assert.notEqual(result.code, 0);
  assert.match(result.output, /SYNC_REMOTE_BASENAME_NONCANONICAL/);
  assert.deepEqual(result.uploads, [], "portable filename guard must reject before HTTP");
});

test("an exactly 30-character non-aliased filename remains uploadable", {
  timeout: 180000,
}, async (t) => {
  const name = `${"a".repeat(26)}.txt`;
  assert.equal(name.length, 30);
  const result = await runFixture(t, [name]);
  assert.equal(result.code, 0, result.output);
  assert.deepEqual(result.uploads, [name]);
});

test("an older server without strict-name capability is refused before any POST", {
  timeout: 180000,
}, async (t) => {
  const result = await runFixture(t, ["safe.txt"], { strictCapability: false });
  assert.notEqual(result.code, 0);
  assert.match(result.output, /SYNC_REMOTE_STRICT_FILENAME_UNSUPPORTED/);
  assert.deepEqual(result.uploads, [], "unsupported server must not receive mutating bytes");
});
