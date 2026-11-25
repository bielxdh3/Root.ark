"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { writePrivateSyncConfig } =
  require("../sync-client/rootark-sync-private-config");
const { privateSyncStatePath, writePrivateSyncState } =
  require("../sync-client/rootark-sync-private-state");

const cli = path.resolve(__dirname, "../sync-client/rootark-sync.js");
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForFirstPost(firstReceived, exited, clientError, getOutput,
  timeoutMs = 45000) {
  let timer;
  try {
    return await Promise.race([
      firstReceived,
      clientError,
      exited.then((code) => {
        throw new Error(`ACK_QUIESCENCE_EARLY_EXIT_${code}: ${getOutput().slice(-1500)}`);
      }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(
          `ACK_QUIESCENCE_FIRST_POST_TIMEOUT: ${getOutput().slice(-1500)}`)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

test("two durable ACK logs signal a quiescent same-path uploader at SIGINT", {
  timeout: 120000,
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
    // The private state is intentionally shared by server/account/folder.
    // A recycled ephemeral TCP port and a fixed fixture username could
    // adopt a prior run's immutable owner claim before the first POST.
    username: `fixture-ack-${crypto.randomUUID()}`,
    token: "disposable-token", localFolder: selected,
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
  let rejectClientError;
  const clientError = new Promise((_, reject) => { rejectClientError = reject; });
  // A failed initial owner preflight does not exit continuous watcher mode.
  // Reject the wait as soon as the client reports failure instead of hanging
  // until node:test cancels the entire scenario without useful diagnostics.
  clientError.catch(() => {});
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (chunk) => {
      output += String(chunk);
      if (/ERRO(?: a\.txt)?:/.test(output)) {
        rejectClientError(new Error(`ACK_QUIESCENCE_CLIENT_ERROR: ${output.slice(-1500)}`));
      }
    });
  }
  const exited = new Promise((resolve, reject) => {
    child.once("close", resolve);
    child.once("error", reject);
  });
  t.after(() => child.kill());
  const waitFor = async (operation, stage, timeoutMs) => {
    let timer;
    try {
      return await Promise.race([
        operation,
        clientError,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(
            `ACK_QUIESCENCE_${stage}_TIMEOUT: ${output.slice(-1500)}`)), timeoutMs);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
  try {
    await waitForFirstPost(firstReceived, exited, clientError, () => output);
    await fs.writeFile(source, "ACK_NEW");
    await pause(300);
    assert.deepEqual(uploads, ["OLD"],
      "a newer same-path POST must not overlap the first pending ACK");
    releaseFirst();
    releaseFirst = null;
    assert.equal(await waitFor(exited, "TWO_ACK_EXIT", 45000), 0, output);
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

test("pre-first-POST authority conflict produces a diagnostic, not a hung fixture", {
  timeout: 60000,
}, async (t) => {
  const privateHome = createPrivateAuthorityFixture("rootark-ack-denial-private-");
  const sharedHome = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-ack-denial-shared-"));
  t.after(async () => {
    await fs.rm(sharedHome, { recursive: true, force: true });
    await fs.rm(privateHome, { recursive: true, force: true });
  });
  const selected = path.join(sharedHome, "selected");
  await fs.mkdir(selected);
  await fs.writeFile(path.join(selected, "a.txt"), "DENIED_CONTENT");

  let mutationCount = 0;
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/upload?")) mutationCount++;
    res.writeHead(500).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const configPath = path.join(privateHome, "config.json");
  const policy = {
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: `fixture-denial-${crypto.randomUUID()}`,
    token: "disposable-token", localFolder: selected, targetFolderId: "root",
    debounceMs: 1, stabilityMs: 1, scanIntervalMs: 75, retryLimit: 1,
  };
  await writePrivateSyncConfig(configPath, JSON.stringify(policy));
  const statePath = privateSyncStatePath(configPath, policy);
  // Model a legitimate prior owner claim for a different local root. The
  // scanner refuses before HTTP and keeps running; the harness must fail
  // promptly with that concrete error, even though firstReceived never fires.
  await writePrivateSyncState(statePath, {
    files: Object.create(null),
    remoteBasenameOwners: {
      "a.txt": { localFolder: path.join(sharedHome, "former-owner"), relativePath: "a.txt" },
    },
  }, policy);

  const child = spawn(process.execPath,
    [cli, "start", "--legacy-development-opt-in", "--config", configPath],
    { cwd: sharedHome, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  t.after(() => child.kill());
  let output = "";
  let rejectClientError;
  const clientError = new Promise((_, reject) => { rejectClientError = reject; });
  clientError.catch(() => {});
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (chunk) => {
      output += String(chunk);
      if (output.includes("SYNC_REMOTE_BASENAME_AUTHORITY_CONFLICT")) {
        rejectClientError(new Error(`ACK_QUIESCENCE_CLIENT_ERROR: ${output.slice(-1500)}`));
      }
    });
  }
  const exited = new Promise((resolve, reject) => {
    child.once("close", resolve);
    child.once("error", reject);
  });
  try {
    const firstReceived = new Promise(() => {});
    await assert.rejects(
      waitForFirstPost(firstReceived, exited, clientError, () => output, 25000),
      /ACK_QUIESCENCE_CLIENT_ERROR:[\s\S]*SYNC_REMOTE_BASENAME_AUTHORITY_CONFLICT/);
    assert.equal(mutationCount, 0, "conflicting source owner must prevent all remote writes");
  } finally {
    child.kill("SIGINT");
    await exited;
  }
  // This negative fixture interrupts immediately after a refusal log, which
  // can precede the scheduler's final active-task decrement. A conservative
  // retained lock is valid here. Only this unique fixture, with zero HTTP
  // mutations and the child already exited, may clear its disposable lock.
  await fs.rm(`${statePath}.lock`, { force: true });
});
