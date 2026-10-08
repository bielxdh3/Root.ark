const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createFileLifecycleLock } = require("../services/fileLifecycleLock");

const originalCwd = process.cwd();
const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-atomic-"));
process.chdir(runtime);
process.env.DB_ENABLED = "false";
const backupRepository = require("../repositories/backupRepository");
const restoreService = require("../services/restoreService");
const database = require("../db");

let sequence = 0;
function reset() {
  fs.rmSync(path.join(runtime, "data"), { recursive: true, force: true });
  fs.rmSync(path.join(runtime, "uploads"), { recursive: true, force: true });
  fs.mkdirSync(path.join(runtime, "uploads"), { recursive: true });
}

function seed(entries) {
  const id = `00000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}`;
  return backupRepository.saveBackup({
    id,
    filename: `rootark-backup-2026-08-01-00-00-${String(sequence).padStart(2, "0")}.zip`,
    metadata: {
      unrelated: { preserved: true },
      restoreSync: {
        operationId: `operation-${id}`,
        revision: 0,
        state: "pending",
        entries: entries || [
          { entryId: "a", path: "uploads/a.txt", area: "uploads", folderId: "root", name: "a.txt", state: "pending", attempts: 0, maxAttempts: 5, leaseToken: null, leaseUntil: null, nextAttemptAt: null },
          { entryId: "b", path: "uploads/b.txt", area: "uploads", folderId: "root", name: "b.txt", state: "pending", attempts: 0, maxAttempts: 5, leaseToken: null, leaseUntil: null, nextAttemptAt: null },
        ],
        transitions: [{ state: "pending", at: "2026-08-01T00:00:00.000Z" }],
      },
    },
  });
}

function mutate(id, entryId, expectedState, expectedLeaseToken, expectedRevision, update) {
  const current = backupRepository.getBackup(id);
  return backupRepository.mutateRestoreSyncEntry({
    backupId: id,
    operationId: current.metadata.restoreSync.operationId,
    entryId,
    expectedState,
    expectedLeaseToken,
    expectedRevision,
    mutate: (entry) => ({ entry: update(entry), at: "2026-08-01T00:00:00.000Z" }),
  });
}

test("restore provider reconciliation waits for a file mutation and uploads the current bytes", async () => {
  reset();
  const localPath = path.join(runtime, "uploads", "a.txt");
  fs.writeFileSync(localPath, "restored bytes");
  const saved = seed([{
    entryId: "only",
    path: "uploads/a.txt",
    area: "uploads",
    folderId: "root",
    name: "a.txt",
    state: "pending",
    attempts: 0,
    maxAttempts: 5,
    leaseToken: null,
    leaseUntil: null,
    nextAttemptAt: null,
  }]);
  const lifecycleLock = createFileLifecycleLock({ directory: path.join(runtime, "data", "file-lifecycle-locks") });
  let releaseRestoreUpload;
  const userMutationReleased = new Promise((resolve) => { releaseRestoreUpload = resolve; });
  let userMutationCommitted = false;
  let uploadStartedBeforeUserCommit = false;
  let remoteObject = "restored bytes";
  const uploader = {
    enabled: () => true,
    provider: "s3",
    upload: async (sourcePath) => {
      const snapshot = fs.readFileSync(sourcePath, "utf8");
      if (!userMutationCommitted) {
        uploadStartedBeforeUserCommit = true;
        await userMutationReleased;
      }
      remoteObject = snapshot;
    },
  };

  let markUserLockAcquired;
  let allowUserMutation;
  const userLockAcquired = new Promise((resolve) => { markUserLockAcquired = resolve; });
  const userMutationAllowed = new Promise((resolve) => { allowUserMutation = resolve; });
  const userOperation = lifecycleLock.run("root", "a.txt", async () => {
    markUserLockAcquired();
    await userMutationAllowed;
    fs.writeFileSync(localPath, "newer user bytes");
    remoteObject = "newer user bytes";
  });
  await userLockAcquired;
  const restoring = restoreService.processRestoreSync({
    backupId: saved.id,
    workerId: "restore-worker",
    uploader,
    runFileLifecycleMutation: (folderId, fileName, work) => lifecycleLock.run(folderId, fileName, work),
  });
  await new Promise((resolve) => setImmediate(resolve));
  allowUserMutation();
  await userOperation;
  userMutationCommitted = true;
  releaseRestoreUpload();
  await restoring;

  assert.equal(uploadStartedBeforeUserCommit, false, "restore upload must wait until the user mutation releases the shared lifecycle lock");
  assert.equal(remoteObject, "newer user bytes", "the queued restore upload must not replace newer provider content");
  assert.equal(backupRepository.getBackup(saved.id).metadata.restoreSync.entries[0].state, "completed");
});

test("restore-sync mutations preserve both entries across deterministic interleavings", async (t) => {
  for (let interleaving = 0; interleaving < 20; interleaving += 1) {
    await t.test(`interleaving ${interleaving + 1}`, () => {
      reset();
      const saved = seed();
      const first = mutate(saved.id, "a", "pending", null, 0, (entry) => ({ ...entry, state: "in_progress", leaseToken: "lease-a", leaseUntil: "2026-08-01T00:01:00.000Z" }));
      const second = mutate(saved.id, "b", "pending", null, 1, (entry) => ({ ...entry, state: "in_progress", leaseToken: "lease-b", leaseUntil: "2026-08-01T00:01:00.000Z" }));
      const order = interleaving % 2 === 0 ? [["a", "lease-a", 2], ["b", "lease-b", 3]] : [["b", "lease-b", 2], ["a", "lease-a", 3]];
      for (const [entryId, lease, revision] of order) mutate(saved.id, entryId, "in_progress", lease, revision, (entry) => ({ ...entry, state: "completed", leaseToken: null, leaseUntil: null }));
      const result = backupRepository.getBackup(saved.id);
      assert.equal(result.metadata.restoreSync.state, "completed");
      assert.deepEqual(result.metadata.restoreSync.entries.map((entry) => entry.state), ["completed", "completed"]);
      assert.deepEqual(result.metadata.unrelated, { preserved: true });
      assert.equal(first.metadata.restoreSync.revision, 1);
      assert.equal(second.metadata.restoreSync.revision, 2);
    });
  }
});

test("restore-sync rejects stale revisions and wrong leases, reclaims expired leases, and invalidates cancellation", () => {
  reset();
  const saved = seed();
  mutate(saved.id, "a", "pending", null, 0, (entry) => ({ ...entry, state: "in_progress", leaseToken: "lease-a", leaseUntil: "2026-07-31T23:59:00.000Z" }));
  assert.throws(() => mutate(saved.id, "b", "pending", null, 0, (entry) => entry), { code: "backup_revision_conflict" });
  const current = backupRepository.getBackup(saved.id);
  assert.throws(() => mutate(saved.id, "a", "in_progress", "wrong", current.metadata.restoreSync.revision, (entry) => entry), { code: "backup_lease_conflict" });
  mutate(saved.id, "a", "in_progress", "lease-a", current.metadata.restoreSync.revision, (entry) => ({ ...entry, state: "in_progress", leaseToken: "lease-reclaimed", leaseUntil: "2026-08-01T00:01:00.000Z" }));
  const afterReclaim = backupRepository.getBackup(saved.id);
  mutate(saved.id, "a", "in_progress", "lease-reclaimed", afterReclaim.metadata.restoreSync.revision, (entry) => ({ ...entry, state: "cancelled", leaseToken: null, leaseUntil: null }));
  const cancelled = backupRepository.getBackup(saved.id);
  assert.throws(() => mutate(saved.id, "a", "in_progress", "lease-reclaimed", cancelled.metadata.restoreSync.revision, (entry) => ({ ...entry, state: "completed" })), { code: "backup_state_conflict" });
});

test("overlapping provider uploads and sibling retry/terminal transitions are lossless", async () => {
  reset();
  fs.writeFileSync(path.join(runtime, "uploads", "a.txt"), "a");
  fs.writeFileSync(path.join(runtime, "uploads", "b.txt"), "b");
  const saved = seed();
  let releaseA;
  const gate = new Promise((resolve) => { releaseA = resolve; });
  const calls = [];
  const provider = { enabled: () => true, upload: async (filePath) => { calls.push(path.basename(filePath)); if (path.basename(filePath) === "a.txt") await gate; } };
  const first = restoreService.processRestoreSync({ backupId: saved.id, workerId: "worker-a", clock: { now: () => Date.parse("2026-08-01T00:00:00.000Z") }, uploader: provider });
  await new Promise((resolve) => setImmediate(resolve));
  const second = restoreService.processRestoreSync({ backupId: saved.id, workerId: "worker-b", clock: { now: () => Date.parse("2026-08-01T00:00:00.000Z") }, uploader: provider });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(calls.sort(), ["a.txt", "b.txt"]);
  releaseA();
  await Promise.all([first, second]);
  assert.equal(backupRepository.getBackup(saved.id).metadata.restoreSync.state, "completed");
});

test("SQLite restore-sync mutations use the same CAS boundary", () => {
  reset();
  const databasePath = path.join(runtime, "configured.sqlite");
  process.env.DB_ENABLED = "true";
  process.env.DATABASE_URL = databasePath;
  database.closeDb();
  database.getDb().exec(`CREATE TABLE backup_history (id TEXT PRIMARY KEY, filename TEXT NOT NULL, type TEXT NOT NULL, status TEXT NOT NULL, created_by TEXT, created_at TEXT NOT NULL, finished_at TEXT, size_bytes INTEGER NOT NULL DEFAULT 0, checksum TEXT, error_message TEXT, metadata_json TEXT NOT NULL DEFAULT '{}')`);
  try {
    const saved = seed();
    mutate(saved.id, "a", "pending", null, 0, (entry) => ({ ...entry, state: "in_progress", leaseToken: "sqlite-a", leaseUntil: "2026-08-01T00:01:00.000Z" }));
    const current = backupRepository.getBackup(saved.id);
    assert.throws(() => mutate(saved.id, "b", "pending", null, 0, (entry) => entry), { code: "backup_revision_conflict" });
    mutate(saved.id, "b", "pending", null, current.metadata.restoreSync.revision, (entry) => ({ ...entry, state: "completed" }));
    const afterB = backupRepository.getBackup(saved.id);
    mutate(saved.id, "a", "in_progress", "sqlite-a", afterB.metadata.restoreSync.revision, (entry) => ({ ...entry, state: "completed", leaseToken: null, leaseUntil: null }));
    const result = backupRepository.getBackup(saved.id);
    assert.equal(result.metadata.restoreSync.state, "completed");
    assert.deepEqual(result.metadata.unrelated, { preserved: true });
  } finally {
    database.closeDb();
    process.env.DB_ENABLED = "false";
    delete process.env.DATABASE_URL;
  }
});

test.after(() => {
  process.chdir(originalCwd);
  fs.rmSync(runtime, { recursive: true, force: true });
});
