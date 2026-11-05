"use strict";

// Adversarial SIGINT/SIGTERM regression: receipt of request bytes is not proof
// of server-side durable commit. A stale lock must fence a replacement client
// even when the first client has already exited.
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

const CLI = path.resolve(__dirname, "../sync-client/rootark-sync.js");

function spawnOnce(config, cwd) {
  const child = spawn(process.execPath,
    [CLI, "start", "--legacy-development-opt-in", "--once", "--config", config],
    { cwd, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  let output = "";
  for (const pipe of [child.stdout, child.stderr]) {
    pipe.on("data", (chunk) => { output += String(chunk); });
  }
  const done = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error(`sync child timeout (${child.pid}): ${output}`));
    }, process.platform === "win32" ? 90000 : 30000);
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
    child.once("close", (code, signal) => {
      clearTimeout(timeout);
      resolve({ code, signal, output });
    });
  });
  return { child, done, stop() { if (child.exitCode === null) child.kill(); } };
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  test(`deferred remote COMMIT after ${signal} retains lock until verified manual recovery`,
    { timeout: 180000 }, async (t) => {
      const privateDir = createPrivateAuthorityFixture(`rootark-${signal}-deferred-private-`);
      const disposableDir = await fs.mkdtemp(path.join(os.tmpdir(),
        `rootark-${signal}-deferred-selected-`));
      t.after(async () => {
        await fs.rm(disposableDir, { recursive: true, force: true });
        await fs.rm(privateDir, { recursive: true, force: true });
      });
      const selected = path.join(disposableDir, "selected");
      await fs.mkdir(selected);
      await fs.writeFile(path.join(selected, "a.txt"), "PENDING_REMOTE_COMMIT");
      let receivedResolve;
      const received = new Promise((resolve) => { receivedResolve = resolve; });
      let commitDeferred;
      let requests = 0;
      let uploadRequests = 0;
      let remoteCommits = 0;
      const server = http.createServer((req, res) => {
    // Disposable server fixture advertises the strict-name protocol contract.
    if (req.url === "/legacy-sync/capabilities") {
      return res.writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ strictFilename: true }));
    }
        requests++;
        if (req.url.startsWith("/list?")) {
          res.writeHead(200, { "content-type": "application/json" }).end("[]");
          return;
        }
        if (req.url.startsWith("/upload?")) {
          const chunks = [];
          req.on("data", (chunk) => chunks.push(chunk));
          req.on("end", () => {
            uploadRequests++;
            const bytes = Buffer.concat(chunks);
            const commit = () => {
              assert.match(bytes.toString("utf8"), /PENDING_REMOTE_COMMIT/);
              remoteCommits++;
              if (!res.destroyed) {
                res.writeHead(200, { "content-type": "application/json" })
                  .end(JSON.stringify({ fileName: "a.txt" }));
              }
            };
            if (uploadRequests === 1) {
              commitDeferred = commit;
              receivedResolve();
            } else commit();
          });
          return;
        }
        res.writeHead(404).end();
      });
      await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
      t.after(() => new Promise((resolve) => server.close(resolve)));

      const config = path.join(privateDir, "config.json");
      const policy = {
        serverUrl: `http://127.0.0.1:${server.address().port}`,
        username: "fixture", token: "disposable-token", localFolder: selected,
        targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
      };
      await writePrivateSyncConfig(config, JSON.stringify(policy));
      const lockPath = `${privateSyncStatePath(config, policy)}.lock`;

      const a = spawnOnce(config, disposableDir);
      t.after(() => a.stop());
      try {
        // A has started an upload. HTTP body is complete, but the server has
        // deliberately NOT committed it and has not responded to the client.
        await received;
        assert.equal(remoteCommits, 0);
        assert.equal((await fs.stat(lockPath)).isFile(), true);
        assert.equal(a.child.kill(signal), true, `${signal} must be delivered`);
        const aExited = await a.done;
        assert.ok(aExited.code !== null || aExited.signal,
          "A must have exited while its server-side mutation was outstanding");
        assert.equal(remoteCommits, 0, "the remote mutation is still pending");

        const beforeB = requests;
        const b = spawnOnce(config, disposableDir);
        t.after(() => b.stop());
        const bResult = await b.done;
        assert.notEqual(bResult.code, 0, "B must fail closed rather than start sync");
        assert.match(bResult.output, /SYNC_STATE_LOCK_HELD/);
        assert.equal(requests, beforeB,
          "B cannot access the server while the dead A still has a pending COMMIT");

        // The remote eventually commits A's abandoned HTTP request after A
        // exited. This cannot be inferred from A's PID or an expired timer.
        commitDeferred();
        commitDeferred = null;
        assert.equal(remoteCommits, 1);
        const afterCommit = requests;
        const stillBlocked = spawnOnce(config, disposableDir);
        t.after(() => stillBlocked.stop());
        const blockedAgain = await stillBlocked.done;
        assert.notEqual(blockedAgain.code, 0);
        assert.match(blockedAgain.output, /SYNC_STATE_LOCK_HELD/);
        assert.equal(requests, afterCommit,
          "remote COMMIT does not automatically authorize stale-lock deletion");

        // The test operator has now confirmed A is stopped AND the deferred
        // server commit finished; only the disposable test fixture can
        // explicitly remove this exact old lock and perform safe recovery.
        await fs.unlink(lockPath);
        const recovered = spawnOnce(config, disposableDir);
        t.after(() => recovered.stop());
        const recoveredResult = await recovered.done;
        assert.equal(recoveredResult.code, 0, recoveredResult.output);
        assert.equal(remoteCommits, 2, "recovery rebuilds an actual ACK");
        await assert.rejects(fs.lstat(lockPath), { code: "ENOENT" },
          "a clean client releases its own lock after successful completion");
      } finally {
        // Prevent test timeout or server.close from hanging if a pre-fix
        // assertion failed. Mutates disposable mock server state only.
        if (commitDeferred) commitDeferred();
      }
    });
}

test("failed HTTP upload retains lock if the server could COMMIT after client exit",
  { timeout: 180000 }, async (t) => {
    const privateDir = createPrivateAuthorityFixture("rootark-uncertain-remote-private-");
    const disposableDir = await fs.mkdtemp(path.join(os.tmpdir(),
      "rootark-uncertain-remote-source-"));
    t.after(async () => {
      await fs.rm(disposableDir, { recursive: true, force: true });
      await fs.rm(privateDir, { recursive: true, force: true });
    });
    const selected = path.join(disposableDir, "selected");
    await fs.mkdir(selected);
    await fs.writeFile(path.join(selected, "a.txt"), "REMOTE_CAN_COMMIT_LATE");
    let completedUploads = 0;
    let uploadRequests = 0;
    let requests = 0;
    let lateCommit;
    const server = http.createServer((req, res) => {
    // Disposable server fixture advertises the strict-name protocol contract.
    if (req.url === "/legacy-sync/capabilities") {
      return res.writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ strictFilename: true }));
    }
      requests++;
      if (req.url.startsWith("/list?")) {
        res.writeHead(200, { "content-type": "application/json" }).end("[]");
        return;
      }
      if (req.url.startsWith("/upload?")) {
        const chunks = [];
        req.on("data", (chunk) => chunks.push(chunk));
        req.on("end", () => {
          uploadRequests++;
          const data = Buffer.concat(chunks);
          assert.match(data.toString("utf8"), /REMOTE_CAN_COMMIT_LATE/);
          if (uploadRequests === 1) {
            lateCommit = () => { completedUploads++; };
            // Simulate network failure AFTER request bytes reached the server.
            // The server can still finish this pending mutation later.
            res.destroy();
          } else {
            completedUploads++;
            res.writeHead(200, { "content-type": "application/json" })
              .end(JSON.stringify({ fileName: "a.txt" }));
          }
        });
        return;
      }
      res.writeHead(404).end();
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    t.after(() => new Promise((resolve) => server.close(resolve)));
    const config = path.join(privateDir, "config.json");
    const policy = {
      serverUrl: `http://127.0.0.1:${server.address().port}`,
      username: "fixture", token: "disposable-token", localFolder: selected,
      targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
    };
    await writePrivateSyncConfig(config, JSON.stringify(policy));
    const lockPath = `${privateSyncStatePath(config, policy)}.lock`;
    const a = spawnOnce(config, disposableDir);
    t.after(() => a.stop());
    const aResult = await a.done;
    // --once must no longer report successful completion after a mutating
    // HTTP response becomes ambiguous, even though the stale lock is kept.
    assert.notEqual(aResult.code, 0, aResult.output);
    assert.ok(lateCommit, "first request must reach the server");
    assert.equal(completedUploads, 0);
    assert.match(aResult.output, /SYNC_REMOTE_OUTCOME_UNCERTAIN/);
    const beforeB = requests;
    const b = spawnOnce(config, disposableDir);
    t.after(() => b.stop());
    const bResult = await b.done;
    assert.notEqual(bResult.code, 0);
    assert.match(bResult.output, /SYNC_STATE_LOCK_HELD/);
    assert.equal(requests, beforeB,
      "B must not mutate remote while an abandoned upload could still COMMIT");
    assert.equal((await fs.stat(lockPath)).isFile(), true);
    lateCommit();
    lateCommit = null;
    assert.equal(completedUploads, 1);
    await fs.unlink(lockPath);
    const recovered = spawnOnce(config, disposableDir);
    t.after(() => recovered.stop());
    const recoveredResult = await recovered.done;
    assert.equal(recoveredResult.code, 0, recoveredResult.output);
    assert.equal(completedUploads, 2);
    await assert.rejects(fs.lstat(lockPath), { code: "ENOENT" });
  });
