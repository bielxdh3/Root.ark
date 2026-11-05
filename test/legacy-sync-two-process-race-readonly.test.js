"use strict";

// Disposable forensic RED only. This does not modify production files or
// publish a branch; run against the worker2 isolated worktree.
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
const { acquirePrivateSyncStateLock } =
  require("../sync-client/rootark-sync-private-lock");

const cli = path.resolve(__dirname, "../sync-client/rootark-sync.js");

test("SIGINT during a remotely pending upload must retain the state lock", {
  timeout: 120000, skip: process.platform === "win32"
    ? "POSIX signal-delivery fixture; Windows exit behavior is checked by lock lifecycle tests"
    : false,
}, async (t) => {
  const privateHome = createPrivateAuthorityFixture("rootark-interrupt-private-");
  const sharedHome = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-interrupt-shared-"));
  t.after(async () => {
    await fs.rm(sharedHome, { recursive: true, force: true });
    await fs.rm(privateHome, { recursive: true, force: true });
  });
  const selected = path.join(sharedHome, "selected");
  await fs.mkdir(selected);
  const source = path.join(selected, "a.txt");
  await fs.writeFile(source, "REMOTE_OLD");

  let resolveFirst;
  const firstReceived = new Promise((resolve) => { resolveFirst = resolve; });
  let delayedCommit;
  let remote = null;
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
      const pieces = [];
      req.on("data", (chunk) => pieces.push(chunk));
      req.on("end", () => {
        const body = Buffer.concat(pieces).toString("utf8");
        const content = body.includes("REMOTE_NEW") ? "REMOTE_NEW" : "REMOTE_OLD";
        uploads.push(content);
        const commit = () => {
          remote = content;
          if (!res.destroyed) {
            res.writeHead(200, { "content-type": "application/json" })
              .end(JSON.stringify({ fileName: "a.txt" }));
          }
        };
        if (uploads.length === 1) {
          delayedCommit = commit;
          resolveFirst();
        } else commit();
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = path.join(privateHome, "config.json");
  const policy = {
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", token: "disposable-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  };
  await writePrivateSyncConfig(config, JSON.stringify(policy));
  const lockPath = `${privateSyncStatePath(config, policy)}.lock`;

  const a = startClient(config, sharedHome);
  t.after(() => a.stop());
  try {
    await firstReceived;
    await fs.writeFile(source, "REMOTE_NEW");
    a.child.kill("SIGINT");
    const exitedA = await a.done;
    assert.equal(exitedA.code, 0, exitedA.output);
    assert.match(exitedA.output, /SYNC_STATE_LOCK_RETAINED_UNCERTAIN_UPLOAD/);
    assert.equal((await fs.lstat(lockPath)).isFile(), true,
      "uncertain remote commit must keep a stale exclusive lock");

    const b = startClient(config, sharedHome);
    t.after(() => b.stop());
    const blockedB = await b.done;
    assert.notEqual(blockedB.code, 0, blockedB.output);
    assert.match(blockedB.output, /SYNC_STATE_LOCK_HELD/);
    assert.deepEqual(uploads, ["REMOTE_OLD"],
      "second uploader must not mutate remote while A can still commit");

    delayedCommit();
    delayedCommit = null;
    assert.equal(remote, "REMOTE_OLD");
    // Only the disposable test fixture is now acting as a verified operator:
    // after the old remote mutation has settled, explicitly clear its lock.
    await fs.unlink(lockPath);
    const retry = startClient(config, sharedHome);
    t.after(() => retry.stop());
    const retried = await retry.done;
    assert.equal(retried.code, 0, retried.output);
    assert.deepEqual(uploads, ["REMOTE_OLD", "REMOTE_NEW"]);
    assert.equal(remote, "REMOTE_NEW");
    await assert.rejects(fs.lstat(lockPath), { code: "ENOENT" });
  } finally {
    if (delayedCommit) delayedCommit();
  }
});

test("failed fetch after upload body cannot unlock a remotely uncertain write", {
  timeout: 120000,
}, async (t) => {
  const privateHome = createPrivateAuthorityFixture("rootark-ambiguous-private-");
  const sharedHome = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-ambiguous-shared-"));
  t.after(async () => {
    await fs.rm(sharedHome, { recursive: true, force: true });
    await fs.rm(privateHome, { recursive: true, force: true });
  });
  const selected = path.join(sharedHome, "selected");
  await fs.mkdir(selected);
  const source = path.join(selected, "a.txt");
  await fs.writeFile(source, "AMBIGUOUS_OLD");
  const uploads = [];
  let pendingOldCommit = null;
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
      const pieces = [];
      req.on("data", (chunk) => pieces.push(chunk));
      req.on("end", () => {
        const body = Buffer.concat(pieces).toString("utf8");
        const content = body.includes("AMBIGUOUS_NEW")
          ? "AMBIGUOUS_NEW" : "AMBIGUOUS_OLD";
        uploads.push(content);
        if (uploads.length === 1) {
          // Request body reached server application, but connection drops
          // before HTTP ACK. The server can still commit this POST later.
          pendingOldCommit = () => { remote = content; };
          res.destroy(new Error("test-forced-ambiguous-ack"));
          return;
        }
        remote = content;
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
  const policy = {
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", token: "disposable-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  };
  await writePrivateSyncConfig(config, JSON.stringify(policy));
  const lockPath = `${privateSyncStatePath(config, policy)}.lock`;

  const a = startClient(config, sharedHome);
  t.after(() => a.stop());
  const failedA = await a.done;
  assert.notEqual(failedA.code, 0, failedA.output);
  assert.match(failedA.output, /SYNC_REMOTE_OUTCOME_UNCERTAIN/);
  assert.match(failedA.output, /ERRO a\.txt/);
  assert.deepEqual(uploads, ["AMBIGUOUS_OLD"]);
  assert.equal(typeof pendingOldCommit, "function");
  assert.equal((await fs.lstat(lockPath)).isFile(), true,
    "an ambiguous completed fetch failure must retain the state lock");
  await fs.writeFile(source, "AMBIGUOUS_NEW");

  const b = startClient(config, sharedHome);
  t.after(() => b.stop());
  const blocked = await b.done;
  assert.notEqual(blocked.code, 0, blocked.output);
  assert.match(blocked.output, /SYNC_STATE_LOCK_HELD/);
  assert.deepEqual(uploads, ["AMBIGUOUS_OLD"]);

  // Simulated operator now confirms the already-received OLD remote POST has
  // settled before removing this disposable test fixture lock.
  pendingOldCommit();
  assert.equal(remote, "AMBIGUOUS_OLD");
  await fs.unlink(lockPath);
  const retry = startClient(config, sharedHome);
  t.after(() => retry.stop());
  const retried = await retry.done;
  assert.equal(retried.code, 0, retried.output);
  assert.deepEqual(uploads, ["AMBIGUOUS_OLD", "AMBIGUOUS_NEW"]);
  assert.equal(remote, "AMBIGUOUS_NEW");
  await assert.rejects(fs.lstat(lockPath), { code: "ENOENT" });
});

function startClient(config, cwd, timeoutMs = 90000) {
  const child = spawn(process.execPath,
    [cli, "start", "--legacy-development-opt-in", "--once", "--config", config],
    { cwd, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  let output = "";
  for (const pipe of [child.stdout, child.stderr]) {
    pipe.on("data", (chunk) => { output += String(chunk); });
  }
  let timer;
  const done = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      child.kill();
      reject(new Error(`timeout ${child.pid}: ${output}`));
    }, timeoutMs);
    child.once("error", reject);
    child.once("close", (code) => {
      clearTimeout(timer);
      resolve({ code, output });
    });
  });
  return { child, done, stop() { child.kill(); clearTimeout(timer); } };
}

test("two private config roots targeting one authority share the lock and uploaded cache", { timeout: 120000 }, async (t) => {
  const privateHome = createPrivateAuthorityFixture("rootark-two-process-private-");
  const otherPrivateHome = createPrivateAuthorityFixture("rootark-two-process-other-config-");
  const sharedHome = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-two-process-shared-"));
  t.after(async () => {
    await fs.rm(sharedHome, { recursive: true, force: true });
    await fs.rm(privateHome, { recursive: true, force: true });
    await fs.rm(otherPrivateHome, { recursive: true, force: true });
  });
  const selected = path.join(sharedHome, "selected");
  await fs.mkdir(selected);
  await fs.writeFile(path.join(selected, "a.txt"), "A_CONTENT");

  let firstUploadResolve;
  let firstUploadResponder;
  const firstUploadReceived = new Promise((resolve) => { firstUploadResolve = resolve; });
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
      const pieces = [];
      req.on("data", (chunk) => pieces.push(chunk));
      req.on("end", () => {
        const body = Buffer.concat(pieces).toString("utf8");
        uploads.push(body);
        const respond = () => res.writeHead(200, { "content-type": "application/json" })
          .end(JSON.stringify({ fileName: body.includes('filename="b.txt"') ? "b.txt" : "a.txt" }));
        if (uploads.length === 1) {
          firstUploadResponder = respond;
          firstUploadResolve();
        } else respond();
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = path.join(privateHome, "config.json");
  const policy = { serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", token: "disposable-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1 };
  await writePrivateSyncConfig(config, JSON.stringify(policy));
  const otherConfig = path.join(otherPrivateHome, "config.json");
  await writePrivateSyncConfig(otherConfig, JSON.stringify({
    ...policy, deviceId: "another-legacy-device", keyEpoch: "new-epoch",
  }));
  assert.equal(privateSyncStatePath(config, policy),
    privateSyncStatePath(otherConfig, { ...policy,
      deviceId: "another-legacy-device", keyEpoch: "new-epoch" }),
    "device and epoch metadata must not split the real legacy remote upload authority");

  const a = startClient(config, sharedHome);
  t.after(() => a.stop());
  try {
    await firstUploadReceived;
    await fs.writeFile(path.join(selected, "b.txt"), "B_CONTENT");
    const b = startClient(otherConfig, sharedHome);
    t.after(() => b.stop());
    const bResult = await b.done;
    const statePath = privateSyncStatePath(config, policy);
    if (bResult.code !== 0) {
      assert.match(bResult.output, /SYNC_STATE_LOCK_HELD/,
        "the second process must fail closed before state read or upload");
      assert.equal(uploads.length, 1, "no second-process HTTP upload is allowed");
      firstUploadResponder();
      firstUploadResponder = null;
      const aResult = await a.done;
      assert.equal(aResult.code, 0, aResult.output);
      const aOnly = JSON.parse(await fs.readFile(statePath, "utf8"));
      assert.deepEqual(Object.keys(aOnly.files), ["a.txt"]);
      const retriedB = startClient(otherConfig, sharedHome);
      t.after(() => retriedB.stop());
      const retried = await retriedB.done;
      assert.equal(retried.code, 0, retried.output);
      const finalState = JSON.parse(await fs.readFile(statePath, "utf8"));
      assert.deepEqual(Object.keys(finalState.files).sort(), ["a.txt", "b.txt"]);
      return;
    }
    assert.equal(bResult.code, 0, bResult.output);
    const afterB = JSON.parse(await fs.readFile(statePath, "utf8"));
    assert.deepEqual(Object.keys(afterB.files).sort(), ["a.txt", "b.txt"],
      "second process confirmed BOTH uploads while first network request was held");
    assert.equal(afterB.files["b.txt"].lastStatus, "uploaded");

    firstUploadResponder();
    firstUploadResponder = null;
    const aResult = await a.done;
    assert.equal(aResult.code, 0, aResult.output);
    const afterA = JSON.parse(await fs.readFile(statePath, "utf8"));
    assert.equal(afterA.files["a.txt"].lastStatus, "uploaded");
    assert.equal(afterA.files["b.txt"]?.lastStatus, "uploaded",
      "last writer with stale in-memory state must not erase b.txt acknowledgement");
  } finally {
    if (firstUploadResponder) firstUploadResponder();
  }
});

test("two processes can report stale uploaded hash while remote contents differ", { timeout: 120000 }, async (t) => {
  const privateHome = createPrivateAuthorityFixture("rootark-two-process-ack-private-");
  const sharedHome = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-two-process-ack-source-"));
  t.after(async () => {
    await fs.rm(sharedHome, { recursive: true, force: true });
    await fs.rm(privateHome, { recursive: true, force: true });
  });
  const selected = path.join(sharedHome, "selected");
  await fs.mkdir(selected);
  const source = path.join(selected, "a.txt");
  const oldBytes = "LOCAL_OLD";
  const newBytes = "LOCAL_NEW";
  await fs.writeFile(source, oldBytes);

  let firstUploadResolve;
  const firstUploadReceived = new Promise((resolve) => { firstUploadResolve = resolve; });
  let heldAck;
  let remoteContents = null;
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
      const pieces = [];
      req.on("data", (chunk) => pieces.push(chunk));
      req.on("end", () => {
        const body = Buffer.concat(pieces).toString("utf8");
        const marker = body.includes(newBytes) ? newBytes : oldBytes;
        uploads.push(marker);
        // Faithful ordered server-side durable mutation: a subsequent upload
        // replaces the last value regardless of when earlier ACKs are sent.
        remoteContents = marker;
        const ack = () => res.writeHead(200, { "content-type": "application/json" })
          .end(JSON.stringify({ fileName: "a.txt" }));
        if (uploads.length === 1) {
          heldAck = ack;
          firstUploadResolve();
        } else ack();
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = path.join(privateHome, "config.json");
  const policy = { serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", token: "disposable-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1 };
  await writePrivateSyncConfig(config, JSON.stringify(policy));
  const a = startClient(config, sharedHome);
  t.after(() => a.stop());
  try {
    await firstUploadReceived;
    assert.equal(remoteContents, oldBytes, "A has already reached server storage");
    await fs.writeFile(source, newBytes);
    const b = startClient(config, sharedHome);
    t.after(() => b.stop());
    const bResult = await b.done;
    if (bResult.code !== 0) {
      assert.match(bResult.output, /SYNC_STATE_LOCK_HELD/,
        "concurrent stale uploader must be refused before remote mutation");
      assert.deepEqual(uploads, [oldBytes]);
      heldAck();
      heldAck = null;
      const aResult = await a.done;
      assert.equal(aResult.code, 0, aResult.output);
      assert.equal(remoteContents, oldBytes);
      const retryB = startClient(config, sharedHome);
      t.after(() => retryB.stop());
      const retryResult = await retryB.done;
      assert.equal(retryResult.code, 0, retryResult.output);
      assert.deepEqual(uploads, [oldBytes, newBytes]);
      assert.equal(remoteContents, newBytes);
      // A clean subsequent scan should now skip ONLY because both the remote
      // and private cache agree with the current local newBytes snapshot.
      const c = startClient(config, sharedHome);
      t.after(() => c.stop());
      const cResult = await c.done;
      assert.equal(cResult.code, 0, cResult.output);
      assert.equal(uploads.length, 2);
      return;
    }
    assert.equal(bResult.code, 0, bResult.output);
    assert.deepEqual(uploads, [oldBytes, newBytes]);
    assert.equal(remoteContents, newBytes, "B is the newest committed upload");

    // The local user reverts the file to OLD before the delayed, stale A
    // response reaches its client and A rewrites the private status cache.
    await fs.writeFile(source, oldBytes);
    heldAck();
    heldAck = null;
    const aResult = await a.done;
    assert.equal(aResult.code, 0, aResult.output);
    assert.equal(remoteContents, newBytes);

    const c = startClient(config, sharedHome);
    t.after(() => c.stop());
    const cResult = await c.done;
    assert.equal(cResult.code, 0, cResult.output);
    assert.equal(uploads.length, 3,
      "C must NOT skip LOCAL_OLD when remote latest contents are LOCAL_NEW");
    assert.equal(remoteContents, oldBytes);
  } finally {
    if (heldAck) heldAck();
  }
});

test("a stale exclusive lock fails closed, preserves bytes, and permits explicit recovery", { timeout: 120000 }, async (t) => {
  const privateHome = createPrivateAuthorityFixture("rootark-stale-lock-private-");
  const sharedHome = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-stale-lock-source-"));
  t.after(async () => {
    await fs.rm(sharedHome, { recursive: true, force: true });
    await fs.rm(privateHome, { recursive: true, force: true });
  });
  const selected = path.join(sharedHome, "selected");
  await fs.mkdir(selected);
  await fs.writeFile(path.join(selected, "a.txt"), "PRESERVE_UPLOAD");
  let uploadCount = 0;
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
      uploadCount++;
      req.resume();
      res.writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify({ fileName: "a.txt" }));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const config = path.join(privateHome, "config.json");
  const policy = { serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", token: "disposable-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1 };
  await writePrivateSyncConfig(config, JSON.stringify(policy));
  const lockPath = `${privateSyncStatePath(config, policy)}.lock`;
  const oldLock = JSON.stringify({ version: 1, pid: 99999999,
    startedAt: "2000-01-01T00:00:00.000Z", nonce: "PRESERVE_STALE_LOCK" });
  await fs.writeFile(lockPath, oldLock, { flag: "wx", mode: 0o600 });
  const first = startClient(config, sharedHome);
  t.after(() => first.stop());
  const blocked = await first.done;
  assert.notEqual(blocked.code, 0);
  assert.match(blocked.output, /SYNC_STATE_LOCK_HELD/);
  assert.equal(uploadCount, 0, "stale lock must refuse before the first upload");
  assert.equal(await fs.readFile(lockPath, "utf8"), oldLock,
    "a dead-looking PID must not trigger unsafe automatic lock unlink");

  // Simulate explicit operator confirmation that all prior clients stopped:
  // only the test fixture itself removes its known disposable lock.
  await fs.unlink(lockPath);
  const second = startClient(config, sharedHome);
  t.after(() => second.stop());
  const recovered = await second.done;
  assert.equal(recovered.code, 0, recovered.output);
  assert.equal(uploadCount, 1);
  await assert.rejects(fs.lstat(lockPath), { code: "ENOENT" },
    "the live process releases its own lock on ordinary exit");
});

test("release never removes a foreign lock which replaced the original inode", async (t) => {
  const privateHome = createPrivateAuthorityFixture("rootark-lock-swapped-");
  t.after(() => fs.rm(privateHome, { recursive: true, force: true }));
  const statePath = path.join(privateHome, "state-fixture.json");
  const lease = acquirePrivateSyncStateLock(statePath);
  const formerPath = `${lease.lockPath}.former`;
  await fs.rename(lease.lockPath, formerPath);
  const replacement = "DO_NOT_UNLINK_OTHER_PROCESS_LOCK";
  await fs.writeFile(lease.lockPath, replacement, { flag: "wx", mode: 0o600 });
  lease.release();
  lease.release();
  assert.equal(await fs.readFile(lease.lockPath, "utf8"), replacement);
  assert.equal((await fs.stat(formerPath)).isFile(), true);
});
