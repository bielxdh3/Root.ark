"use strict";

const assert = require("node:assert/strict");
const { fork } = require("node:child_process");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { SyncObjectStore } = require("../src/routes/sync");

test("two independently opened sync stores preserve both commits after stale instance writes", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-process-fence-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "objects.json");
  const first = await new SyncObjectStore(file).open();
  const second = await new SyncObjectStore(file).open();
  await first.transact((next) => { first.user(next, "alice").testIteration = 1; });
  await second.transact((next) => { second.user(next, "bob").testIteration = 1; });
  const stored = JSON.parse(await fs.readFile(file, "utf8"));
  assert.equal(stored.users.alice.testIteration, 1);
  assert.equal(stored.users.bob.testIteration, 1);
});

test("separate Node processes fence concurrent sync JSON writes and keep a monotonic result", { timeout: 20_000 }, async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-child-fence-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "objects.json");
  const fixture = path.join(__dirname, "fixtures", "sync-store-concurrent-child.js");
  const children = ["alice", "bob"].map((id) => fork(fixture, [file, id], { stdio: ["ignore", "pipe", "pipe", "ipc"], execArgv: [] }));
  t.after(() => children.forEach((child) => { if (child.exitCode === null) child.kill(); }));
  const results = children.map((child) => new Promise((resolve, reject) => {
    let output = "";
    child.stderr.on("data", (chunk) => { output += chunk.toString(); });
    child.on("message", (message) => {
      if (message?.type === "ready") child.send({ type: "go" });
      if (message?.type === "done") resolve();
    });
    child.on("exit", (code) => { if (code !== 0) reject(new Error(`child exit ${code}: ${output}`)); });
    child.on("error", reject);
  }));
  await Promise.all(results);
  const stored = JSON.parse(await fs.readFile(file, "utf8"));
  assert.equal(stored.users.alice.testIteration, 7);
  assert.equal(stored.users.bob.testIteration, 7);
});

test("an orphaned writer lock fails closed across restart without replacing the on-disk inventory", { timeout: 10_000 }, async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-orphan-lock-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "objects.json");
  const first = await new SyncObjectStore(file).open();
  await first.transact((next) => { first.user(next, "alice").testIteration = 0; });
  const before = await fs.readFile(file, "utf8");
  const handle = await fs.open(`${file}.writer-lock`, "wx");
  await handle.close(); // Simulates a crashed owner; no automatic stale-lock steal.
  const restarted = new SyncObjectStore(file);
  await assert.rejects(restarted.open(), { code: "SYNC_STORE_LOCK_BUSY" });
  await assert.rejects(first.transact((next) => { first.user(next, "alice").testIteration = 1; }), { code: "SYNC_STORE_LOCK_BUSY" });
  assert.equal(await fs.readFile(file, "utf8"), before);
  assert.equal((await fs.readdir(dir)).filter((name) => name.endsWith(".writer-lock")).length, 1);
});
