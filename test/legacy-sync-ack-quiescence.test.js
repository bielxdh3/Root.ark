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
const { privateSyncStatePath } =
  require("../sync-client/rootark-sync-private-state");

const cli = path.resolve(__dirname, "../sync-client/rootark-sync.js");
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("two durable ACK logs signal a quiescent same-path uploader at SIGINT", {
  timeout: 35000,
}, async (t) => {
  const privateHome = createPrivateAuthorityFixture("rootark-ack-quiescence-private-");
  const sharedHome = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-ack-quiescence-shared-"));
  t.after(async () => {
    await fs.rm(sharedHome, { recursive: true, force: true });
    await fs.rm(privateHome, { recursive: true, force: true });
  });
  const selected = path.join(sharedHome, "selected");
  await fs.mkdir(selected);
  const source = path.join(selected, "a.txt");
  await fs.writeFile(source, "ACK_OLD");

  let resolveFirst;
  const firstReceived = new Promise((resolve) => { resolveFirst = resolve; });
  let releaseFirst;
  const uploads = [];
  const server = http.createServer((req, res) => {
    if (req.url === "/legacy-sync/capabilities") {
      return res.writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify({ strictFilename: true }));
    }
    if (req.url.startsWith("/list?")) {
      return res.writeHead(200, { "content-type": "application/json" }).end("[]");
    }
    if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        uploads.push(Buffer.concat(chunks).includes(Buffer.from("ACK_NEW")) ? "NEW" : "OLD");
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

  const configPath = path.join(privateHome, "config.json");
  const policy = {
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", token: "disposable-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1,
    scanIntervalMs: 75, retryLimit: 1,
  };
  await writePrivateSyncConfig(configPath, JSON.stringify(policy));
  const statePath = privateSyncStatePath(configPath, policy);
  // Test-only preload: simulate the strongest possible interrupt at the
  // instant the second successful ACK log becomes externally observable.
  const preload = path.join(sharedHome, "interrupt-after-ack.cjs");
  await fs.writeFile(preload, `"use strict";
const original = console.log;
let acknowledged = 0;
console.log = function (...args) {
  original.apply(console, args);
  if (args.some((value) => /OK a\\.txt -> a\\.txt/.test(String(value)))
    && ++acknowledged === 2) process.emit("SIGINT");
};\n`);
  const child = spawn(process.execPath,
    ["--require", preload, cli, "start", "--legacy-development-opt-in", "--config", configPath],
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
  try {
    await firstReceived;
    await fs.writeFile(source, "ACK_NEW");
    await pause(300);
    assert.deepEqual(uploads, ["OLD"],
      "a newer same-path POST must not overlap the first pending ACK");
    releaseFirst();
    releaseFirst = null;
    assert.equal(await exited, 0, output);
  } finally {
    if (releaseFirst) releaseFirst();
    child.kill();
  }
  assert.deepEqual(uploads, ["OLD", "NEW"], output);
  assert.equal((output.match(/OK a\.txt -> a\.txt/g) || []).length, 2, output);
  const state = JSON.parse(await fs.readFile(statePath, "utf8"));
  assert.equal(state.files["a.txt"]?.lastStatus, "uploaded");
  assert.doesNotMatch(output, /SYNC_STATE_LOCK_RETAINED_UNCERTAIN_UPLOAD/);
  await assert.rejects(fs.lstat(`${statePath}.lock`), { code: "ENOENT" },
    "a completed fsynced upload cannot leave an uncertain-state lock");
});
