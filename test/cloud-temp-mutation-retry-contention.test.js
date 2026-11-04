"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { createFileLifecycleLock } = require("../services/fileLifecycleLock");
const { createCloudTempMutationQueue } = require("../services/cloudTempMutationQueue");

function externalLockProbe(directory) {
  const source = [
    'const { createFileLifecycleLock } = require(process.argv[1]);',
    'const lock = createFileLifecycleLock({ directory: process.argv[2], timeoutMs: 1200, pollMs: 5 });',
    'lock.run("root", "failed.txt", async () => {}).then(() => process.exit(0), () => process.exit(2));',
  ].join("\n");
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["-e", source,
      path.resolve(__dirname, "../services/fileLifecycleLock.js"), directory],
    { stdio: "ignore", windowsHide: true });
    child.once("error", reject);
    child.once("exit", (code) => resolve(code));
  });
}

test("failed provider deletion leaves durable intent, backs off repeated sweeps, and frees cross-process locks", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-queue-backoff-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  const locksDir = path.join(root, "locks");
  const queueDir = path.join(root, "queue");
  const lock = createFileLifecycleLock({ directory: locksDir, timeoutMs: 2000, pollMs: 5 });
  let attempts = 0;
  const args = { directory: queueDir, lifecycleLock: lock,
    localPathFor: () => { throw new Error("no read on delete"); },
    upload: () => { throw new Error("no upload on delete"); },
    remove: async () => {
      attempts++;
      if (attempts === 1) throw new Error("provider offline");
    },
    retryBaseMs: 100, retryMaxMs: 100 };
  const queue = createCloudTempMutationQueue(args);
  queue.setDesired("root", "failed.txt", "absent");
  await assert.rejects(queue.processAll(), /Cloud temp mutations remain pending/);
  assert.equal(attempts, 1);
  const record = queue.getRecord("root", "failed.txt");
  assert.equal(record.desired, "absent");
  await Promise.all(Array.from({ length: 12 }, () => queue.processAll()));
  assert.equal(attempts, 1, "periodic sweeps must not immediately flood a failed delete");
  assert.equal(await externalLockProbe(locksDir), 0,
    "a second process can acquire both lifecycle locks while provider is in backoff");
  await new Promise((resolve) => setTimeout(resolve, 125));
  await Promise.all(Array.from({ length: 8 }, () => queue.processAll()));
  assert.equal(attempts, 2, "after backoff, concurrent sweeps converge through one provider call");
  assert.equal(queue.getRecord("root", "failed.txt"), null);

  queue.setDesired("root", "failed.txt", "absent");
  let offline = true, resumedAttempts = 0;
  const restartedArgs = { ...args, remove: async () => {
    resumedAttempts++;
    if (offline) throw new Error("second outage");
  }, retryBaseMs: 30_000, retryMaxMs: 30_000 };
  const crashed = createCloudTempMutationQueue(restartedArgs);
  await assert.rejects(crashed.processAll());
  assert.equal(resumedAttempts, 1);
  offline = false;
  const restarted = createCloudTempMutationQueue(restartedArgs);
  await restarted.processAll();
  assert.equal(resumedAttempts, 2, "new process retries durable intent without inheriting old in-memory delay");
  assert.equal(restarted.getRecord("root", "failed.txt"), null);
});
