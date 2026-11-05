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

const cli = path.resolve(__dirname, "../sync-client/rootark-sync.js");
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function until(predicate, deadlineMs = 10000) {
  const deadline = Date.now() + deadlineMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("SYNC_TEST_WAIT_TIMED_OUT");
    await pause(25);
  }
}

test("periodic scan cannot overlap two uploads for the same local path", {
  timeout: 30000,
}, async (t) => {
  const privateHome = createPrivateAuthorityFixture("rootark-same-path-private-");
  const sharedHome = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-same-path-shared-"));
  t.after(async () => {
    await fs.rm(sharedHome, { recursive: true, force: true });
    await fs.rm(privateHome, { recursive: true, force: true });
  });
  const selected = path.join(sharedHome, "selected");
  await fs.mkdir(selected);
  const source = path.join(selected, "a.txt");
  await fs.writeFile(source, "SAME_PATH_OLD");

  let resolveFirst;
  const firstReceived = new Promise((resolve) => { resolveFirst = resolve; });
  let releaseFirst;
  const uploads = [];
  const server = http.createServer((req, res) => {
    // Disposable server fixture advertises the strict-name protocol contract.
    if (req.url === "/legacy-sync/capabilities") {
      return res.writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ strictFilename: true }));
    }
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "content-type": "application/json" }).end("[]");
      return;
    }
    if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        uploads.push(body.includes("SAME_PATH_NEW") ? "NEW" : "OLD");
        const ack = () => {
          if (!res.destroyed) {
            res.writeHead(200, { "content-type": "application/json" })
              .end(JSON.stringify({ fileName: "a.txt" }));
          }
        };
        if (uploads.length === 1) {
          releaseFirst = ack;
          resolveFirst();
        } else ack();
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = path.join(privateHome, "config.json");
  await writePrivateSyncConfig(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", token: "disposable-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1,
    scanIntervalMs: 75, retryLimit: 1,
  }));

  const child = spawn(process.execPath,
    [cli, "start", "--legacy-development-opt-in", "--config", config],
    { cwd: sharedHome, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (chunk) => { output += String(chunk); });
  }
  const exited = new Promise((resolve, reject) => {
    child.once("close", (code) => resolve(code));
    child.once("error", reject);
  });
  t.after(() => child.kill());
  try {
    await firstReceived;
    assert.deepEqual(uploads, ["OLD"]);
    await fs.writeFile(source, "SAME_PATH_NEW");
    // Several scan intervals elapse while A is still waiting for its HTTP
    // acknowledgement. A second write for this path must not begin yet.
    await pause(700);
    assert.deepEqual(uploads, ["OLD"],
      "a second same-path POST raced the unacknowledged first mutation");
    releaseFirst();
    releaseFirst = null;
    await until(() => uploads.includes("NEW"));
    assert.deepEqual(uploads.slice(0, 2), ["OLD", "NEW"]);
    // Do not deliberately interrupt the second valid HTTP operation while
    // asserting that normal quiescent exit releases its lock.
    await until(() => (output.match(/OK a\.txt/g) || []).length >= 2);
  } finally {
    if (releaseFirst) releaseFirst();
    child.kill("SIGINT");
    await exited;
  }
  assert.doesNotMatch(output, /SYNC_STATE_LOCK_RETAINED_UNCERTAIN_UPLOAD/);
});

test("ambiguous failed POST blocks further uploads in the still-running process", {
  timeout: 30000,
}, async (t) => {
  const privateHome = createPrivateAuthorityFixture("rootark-ongoing-ambiguity-private-");
  const sharedHome = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-ongoing-ambiguity-shared-"));
  t.after(async () => {
    await fs.rm(sharedHome, { recursive: true, force: true });
    await fs.rm(privateHome, { recursive: true, force: true });
  });
  const selected = path.join(sharedHome, "selected");
  await fs.mkdir(selected);
  const source = path.join(selected, "a.txt");
  await fs.writeFile(source, "AMBIGUOUS_A_OLD");
  const uploads = [];
  let commitOld;
  let remote = null;
  const server = http.createServer((req, res) => {
    // Disposable server fixture advertises the strict-name protocol contract.
    if (req.url === "/legacy-sync/capabilities") {
      return res.writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ strictFilename: true }));
    }
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "content-type": "application/json" }).end("[]");
      return;
    }
    if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        const marker = body.includes("AMBIGUOUS_A_NEW") ? "NEW" : "OLD";
        uploads.push(marker);
        if (uploads.length === 1) {
          // The server has accepted A, but disconnects before returning ACK;
          // its durable mutation may still execute after subsequent requests.
          commitOld = () => { remote = "OLD"; };
          res.destroy(new Error("intentional ambiguous HTTP outcome"));
          return;
        }
        remote = marker;
        res.writeHead(200, { "content-type": "application/json" })
          .end(JSON.stringify({ fileName: "a.txt" }));
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = path.join(privateHome, "config.json");
  await writePrivateSyncConfig(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", token: "disposable-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1,
    scanIntervalMs: 75, retryLimit: 1,
  }));
  const child = spawn(process.execPath,
    [cli, "start", "--legacy-development-opt-in", "--config", config],
    { cwd: sharedHome, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (chunk) => { output += String(chunk); });
  }
  const exited = new Promise((resolve, reject) => {
    child.once("close", (code) => resolve(code));
    child.once("error", reject);
  });
  t.after(() => child.kill());
  try {
    await until(() => output.includes("ERRO a.txt"));
    assert.deepEqual(uploads, ["OLD"]);
    assert.equal(typeof commitOld, "function");
    await fs.writeFile(source, "AMBIGUOUS_A_NEW");
    // Even with watcher activity and many interval scans, the uncertain A
    // write must remain an exclusive remote fence until operator recovery.
    await pause(700);
    assert.deepEqual(uploads, ["OLD"],
      "the running uploader sent NEW despite an unresolved OLD commit");
    commitOld();
    assert.equal(remote, "OLD");
  } finally {
    child.kill("SIGINT");
    await exited;
  }
});

test("once mode finishes more files than the bounded admission queue", {
  timeout: 120000,
  skip: process.platform === "win32"
    ? "Large fixture is exercised on POSIX; Windows native ACL cost is validated by smaller canonical suites"
    : false,
}, async (t) => {
  const privateHome = createPrivateAuthorityFixture("rootark-bounded-once-private-");
  const sharedHome = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-bounded-once-shared-"));
  t.after(async () => {
    await fs.rm(sharedHome, { recursive: true, force: true });
    await fs.rm(privateHome, { recursive: true, force: true });
  });
  const selected = path.join(sharedHome, "selected");
  await fs.mkdir(selected);
  for (let index = 0; index < 70; index++) {
    await fs.writeFile(path.join(selected, `file-${String(index).padStart(3, "0")}.txt`),
      `CONTENT_${index}`);
  }
  await fs.writeFile(path.join(selected, "A.txt"), "CASE_UPPER");
  await fs.writeFile(path.join(selected, "b.txt"), "CASE_LOWER");
  const uploads = [];
  const server = http.createServer((req, res) => {
    // Disposable server fixture advertises the strict-name protocol contract.
    if (req.url === "/legacy-sync/capabilities") {
      return res.writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ strictFilename: true }));
    }
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "content-type": "application/json" }).end("[]");
      return;
    }
    if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        const match = /filename="(file-\d{3}\.txt|A\.txt|b\.txt)"/.exec(body);
        uploads.push(match?.[1] || "INVALID_FILENAME");
        res.writeHead(200, { "content-type": "application/json" })
          .end(JSON.stringify({ fileName: match?.[1] || "unknown" }));
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = path.join(privateHome, "config.json");
  await writePrivateSyncConfig(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", token: "disposable-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  }));
  const child = spawn(process.execPath,
    [cli, "start", "--legacy-development-opt-in", "--once", "--config", config],
    { cwd: sharedHome, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (chunk) => { output += String(chunk); });
  }
  const timeout = setTimeout(() => child.kill(), 115000);
  t.after(() => child.kill());
  const code = await new Promise((resolve, reject) => {
    child.once("close", resolve);
    child.once("error", reject);
  });
  clearTimeout(timeout);
  assert.equal(code, 0, output);
  assert.equal(uploads.length, 72, "bounded --once must not silently omit the final batch");
  assert.equal(new Set(uploads).size, 72,
    "every source, including distinct names, must upload exactly once");
  assert.match(output, /Sync --once concluido/);
});

test("a busy watcher cannot starve round-robin audit of a late file", {
  timeout: 30000,
  skip: process.platform === "win32"
    ? "High-frequency watcher stress runs on POSIX; smaller Windows cases cover exclusive path logic"
    : false,
}, async (t) => {
  const privateHome = createPrivateAuthorityFixture("rootark-scan-fairness-private-");
  const sharedHome = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-scan-fairness-shared-"));
  t.after(async () => {
    await fs.rm(sharedHome, { recursive: true, force: true });
    await fs.rm(privateHome, { recursive: true, force: true });
  });
  const selected = path.join(sharedHome, "selected");
  await fs.mkdir(selected);
  const hotPaths = [];
  for (let index = 0; index < 85; index++) {
    const file = path.join(selected, `a-hot-${String(index).padStart(3, "0")}.txt`);
    hotPaths.push(file);
    await fs.writeFile(file, `ORIGINAL_${index}`);
  }
  await fs.writeFile(path.join(selected, "zz-victim.txt"), "VICTIM_REQUIRED");
  const uploads = [];
  let active = 0;
  let peak = 0;
  const server = http.createServer((req, res) => {
    // Disposable server fixture advertises the strict-name protocol contract.
    if (req.url === "/legacy-sync/capabilities") {
      return res.writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ strictFilename: true }));
    }
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "content-type": "application/json" }).end("[]");
      return;
    }
    if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        const filename = /filename="([^"]+)"/.exec(body)?.[1];
        uploads.push(filename);
        active++;
        peak = Math.max(peak, active);
        setTimeout(() => {
          active--;
          if (!res.destroyed) {
            res.writeHead(200, { "content-type": "application/json" })
              .end(JSON.stringify({ fileName: filename }));
          }
        }, 30);
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = path.join(privateHome, "config.json");
  await writePrivateSyncConfig(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", token: "disposable-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 2, stabilityMs: 1,
    scanIntervalMs: 80, retryLimit: 1,
  }));
  const child = spawn(process.execPath,
    [cli, "start", "--legacy-development-opt-in", "--config", config],
    { cwd: sharedHome, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (chunk) => { output += String(chunk); });
  }
  const exited = new Promise((resolve, reject) => {
    child.once("close", resolve);
    child.once("error", reject);
  });
  t.after(() => child.kill());
  let nextHot = 0;
  const flood = setInterval(() => {
    const filename = hotPaths[nextHot++ % 64];
    fs.writeFile(filename, `HOT_${nextHot}`).catch(() => {});
  }, 10);
  try {
    await until(() => uploads.includes("zz-victim.txt") || output.includes("ERRO:"), 20000);
    assert.ok(uploads.includes("zz-victim.txt"), output);
    assert.ok(peak <= 4, `bounded uploader exceeded four resident network slots: ${peak}`);
  } finally {
    clearInterval(flood);
    child.kill("SIGINT");
    await exited;
  }
});
