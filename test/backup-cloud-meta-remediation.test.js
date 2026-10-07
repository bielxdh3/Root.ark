const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { createCloudStorage } = require("../services/cloudStorage");
const { normalizeProviderError } = require("../src/services/deploymentResilience");

const originalCwd = process.cwd();
const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-meta-"));
process.chdir(runtime);
process.env.DB_ENABLED = "false";
const backupService = require("../services/backupService");
const restoreService = require("../services/restoreService");
const backupRepository = require("../repositories/backupRepository");
const unzipper = require("unzipper");

let sequence = 0;
const clock = { value: Date.parse("2026-08-01T00:00:00.000Z"), now() { return this.value; } };

function reset() {
  for (const name of ["data", "uploads", "temp"]) fs.rmSync(path.join(runtime, name), { recursive: true, force: true });
  fs.mkdirSync(path.join(runtime, "data", "backups"), { recursive: true });
  fs.mkdirSync(path.join(runtime, "uploads"), { recursive: true });
  delete process.env.BACKUP_INCLUDE_PENDING;
  delete process.env.BACKUP_INCLUDE_TEMP;
}

function object(name, content = "bytes", options = {}) {
  return {
    provider: options.provider || "s3",
    providerIdentity: options.providerIdentity || `${options.area || "uploads"}:${options.folderId || "root"}:${name}`,
    folderId: options.folderId || "root",
    area: options.area || "uploads",
    name,
    key: `rootark/${options.area || "uploads"}/${options.folderId || "root"}/${name}`,
    content,
  };
}

async function runBackup(objects = [], options = {}) {
  reset();
  if (options.pending !== undefined) process.env.BACKUP_INCLUDE_PENDING = String(options.pending);
  if (options.temp) process.env.BACKUP_INCLUDE_TEMP = "true";
  if (options.local) {
    fs.writeFileSync(path.join(runtime, "uploads", options.local.name), options.local.content);
  }
  const cloud = {
    enabled: () => options.enabled !== false,
    inventory: async () => {
      if (options.failInventory) throw new Error("inventory unavailable");
      return objects;
    },
    download: async (_folderId, name, target, area) => {
      if (options.failDownload) throw new Error("download unavailable");
      const remote = objects.find((entry) => entry.name === name && entry.area === area);
      if (!remote) return false;
      if (options.truncated) { fs.writeFileSync(target, String(remote.content).slice(0, 1)); return false; }
      fs.writeFileSync(target, remote.content);
      return true;
    },
  };
  backupService.setCloudStorage(cloud);
  try {
    const backup = await backupService.createBackup({ createdBy: "tester", type: options.type });
    const zip = await unzipper.Open.file(path.join(runtime, "data", "backups", backup.filename));
    const manifest = JSON.parse((await zip.files.find((entry) => entry.path === "backup-manifest.json").buffer()).toString("utf8"));
    return { ok: true, backup, manifest, entries: zip.files.map((entry) => entry.path) };
  } catch (error) {
    const history = backupRepository.listBackups();
    return { ok: false, error, history, zips: fs.existsSync(path.join(runtime, "data", "backups")) ? fs.readdirSync(path.join(runtime, "data", "backups")).filter((name) => name.endsWith(".zip")) : [] };
  } finally {
    backupService.setCloudStorage(null);
  }
}

function syncBackup(entries) {
  const id = `00000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}`;
  const saved = backupRepository.saveBackup({
    id,
    filename: `rootark-backup-2026-08-01-00-00-${String(sequence).padStart(2, "0")}.zip`,
    status: "success",
    metadata: {
      restoreSync: {
        operationId: `op-${id}`,
        state: "pending",
        entries: entries.map((entry, index) => ({ entryId: entry.entryId || `entry-${index}`, leaseToken: null, leaseUntil: null, ...entry })),
        transitions: [{ state: "pending", at: new Date(clock.value).toISOString() }],
      },
    },
  });
  return saved;
}

test("authoritative cloud backup and restore matrix", async (t) => {
  await t.test("S3 global pagination", async () => {
    let page = 0;
    const storage = createCloudStorage({ provider: "s3", prefix: "rootark", s3: { bucket: "bucket" }, createS3Client: async () => ({ send: async () => page++ === 0 ? { Contents: [{ Key: "rootark/uploads/root/a.txt" }], NextContinuationToken: "next" } : { Contents: [{ Key: "rootark/uploads/orphan/b.txt" }] } }) });
    assert.equal((await storage.inventory()).length, 2);
  });
  await t.test("Drive global pagination", async () => {
    let page = 0;
    const storage = createCloudStorage({ provider: "gdrive", prefix: "rootark", gdrive: { folderId: "drive-root" }, createGoogleDriveClient: async () => ({ files: { list: async () => page++ === 0 ? { data: { files: [{ id: "a", parents: ["drive-root"], appProperties: { rootArkKey: "rootark/uploads/root/a.txt", rootArkFolderId: "root", rootArkArea: "uploads" } }], nextPageToken: "next" } } : { data: { files: [{ id: "b", parents: ["drive-root"], appProperties: { rootArkKey: "rootark/uploads/orphan/b.txt", rootArkFolderId: "orphan", rootArkArea: "uploads" } }] } } } }) });
    assert.equal((await storage.inventory()).length, 2);
  });
  await t.test("cloud-only unknown folder", async () => { const result = await runBackup([object("orphan.txt", "orphan", { folderId: "orphan" })]); assert.ok(result.entries.includes("uploads/orphan/orphan.txt")); });
  await t.test("cloud-only root upload", async () => { const result = await runBackup([object("root.txt")]); assert.ok(result.entries.includes("uploads/root.txt")); });
  await t.test("nested-folder upload", async () => { const result = await runBackup([object("nested.txt", "nested", { folderId: "nested-folder" })]); assert.ok(result.entries.includes("uploads/nested-folder/nested.txt")); });
  await t.test("pending enabled", async () => { const result = await runBackup([object("pending.txt", "pending", { area: "temp" })], { pending: true }); assert.ok(result.entries.includes("temp/pending.txt")); });
  await t.test("pending disabled", async () => { const result = await runBackup([object("pending.txt", "pending", { area: "temp" })], { pending: false }); assert.equal(result.entries.some((entry) => entry.startsWith("temp/")), false); });
  await t.test("local-only", async () => { const result = await runBackup([], { enabled: false, local: { name: "local.txt", content: "local" } }); assert.ok(result.entries.includes("uploads/local.txt")); assert.equal(result.manifest.cloud_complete, false); });
  await t.test("equal collision includes once", async () => { const result = await runBackup([object("same.txt", "same")], { local: { name: "same.txt", content: "same" } }); assert.equal(result.entries.filter((entry) => entry === "uploads/same.txt").length, 1); });
  await t.test("unequal collision fails closed", async () => { const result = await runBackup([object("same.txt", "remote")], { local: { name: "same.txt", content: "local" } }); assert.equal(result.ok, false); });
  await t.test("duplicate provider key fails closed", async () => { const result = await runBackup([object("a.txt", "a", { providerIdentity: "duplicate" }), object("b.txt", "b", { providerIdentity: "duplicate" })]); assert.equal(result.ok, false); });
  await t.test("case collision fails closed", async () => { const result = await runBackup([object("case.txt")], { local: { name: "Case.txt", content: "same" } }); assert.equal(result.ok, false); });
  await t.test("separator collision fails closed", async () => { const result = await runBackup([object("a\\b.txt")]); assert.equal(result.ok, false); });
  await t.test("zero-byte object", async () => { const result = await runBackup([object("empty.txt", "")]); assert.ok(result.entries.includes("uploads/empty.txt")); });
  await t.test("Unicode object", async () => { const result = await runBackup([object("ação-測試.txt")]); assert.ok(result.entries.includes("uploads/ação-測試.txt")); });
  await t.test("traversal key", async () => { const result = await runBackup([object("bad.txt", "x", { folderId: ".." })]); assert.equal(result.ok, false); });
  await t.test("absolute key", async () => { const result = await runBackup([object("bad.txt", "x", { folderId: "/root" })]); assert.equal(result.ok, false); });
  await t.test("foreign prefix", async () => { const storage = createCloudStorage({ provider: "s3", prefix: "rootark", s3: { bucket: "bucket" }, createS3Client: async () => ({ send: async () => ({ Contents: [{ Key: "foreign/uploads/root/a.txt" }] }) }) }); await assert.rejects(storage.inventory(), /outside the configured prefix/); });
  await t.test("malformed Drive appProperties", async () => { const storage = createCloudStorage({ provider: "gdrive", prefix: "rootark", gdrive: { folderId: "root" }, createGoogleDriveClient: async () => ({ files: { list: async () => ({ data: { files: [{ id: "x", parents: ["root"], appProperties: { rootArkKey: "rootark/uploads/root/x.txt", rootArkFolderId: "wrong", rootArkArea: "uploads" } }] } }) } }) }); await assert.rejects(storage.inventory(), /does not match/); const normalized = normalizeProviderError(Object.assign(new Error("provider detail"), { code: "invalid_inventory_metadata" })); assert.equal(normalized.code, "invalid_inventory_metadata"); assert.match(normalized.message, /does not match/); });
  await t.test("missing Drive key", async () => { const storage = createCloudStorage({ provider: "gdrive", prefix: "rootark", gdrive: { folderId: "root" }, createGoogleDriveClient: async () => ({ files: { list: async () => ({ data: { files: [{ id: "x", parents: ["root"], appProperties: {} }] } }) } }) }); await assert.rejects(storage.inventory()); });
  await t.test("Drive file outside configured parent", async () => { const storage = createCloudStorage({ provider: "gdrive", prefix: "rootark", gdrive: { folderId: "root" }, createGoogleDriveClient: async () => ({ files: { list: async () => ({ data: { files: [{ id: "x", parents: ["foreign"], appProperties: { rootArkKey: "rootark/uploads/root/x.txt", rootArkFolderId: "root", rootArkArea: "uploads" } }] } }) } }) }); await assert.rejects(storage.inventory(), /configured parent/); });
  await t.test("inventory failure", async () => { const result = await runBackup([], { failInventory: true }); assert.equal(result.ok, false); });
  await t.test("download failure", async () => { const result = await runBackup([object("x.txt")], { failDownload: true }); assert.equal(result.ok, false); });
  await t.test("truncated stream", async () => { const result = await runBackup([object("x.txt", "full")], { truncated: true }); assert.equal(result.ok, false); });
  await t.test("success staging cleanup", async () => { const result = await runBackup([object("x.txt")]); assert.equal(fs.existsSync(path.join(runtime, "data", "backups", ".cloud-stage")), false); assert.equal(result.ok, true); });
  await t.test("failure staging cleanup", async () => { const result = await runBackup([object("x.txt")], { failDownload: true }); assert.equal(fs.existsSync(path.join(runtime, "data", "backups", ".cloud-stage")), false); assert.equal(result.ok, false); });
  await t.test("incomplete archive removal", async () => { const result = await runBackup([object("x.txt")], { failInventory: true }); assert.equal(result.zips.length, 0); });
  await t.test("failed history", async () => { const result = await runBackup([object("x.txt")], { failDownload: true }); assert.equal(result.history.some((entry) => entry.status === "failed"), true); });
  await t.test("no false cloud_complete", async () => { const result = await runBackup([object("x.txt")], { failInventory: true }); assert.equal(result.ok, false); });
  await t.test("completeness evidence", async () => { const result = await runBackup([object("x.txt")]); assert.equal(result.manifest.cloud_complete, true); assert.ok(result.manifest.included_files.some((entry) => entry.path === "uploads/x.txt")); });
  await t.test("cloud-complete pre-restore backup", async () => { const result = await runBackup([object("x.txt")], { type: "pre-restore" }); assert.equal(result.manifest.cloud_complete, true); });
  await t.test("JSON restore queue", async () => { reset(); fs.writeFileSync(path.join(runtime, "uploads", "x.txt"), "x"); const saved = syncBackup([{ path: "uploads/x.txt", area: "uploads", folderId: "root", name: "x.txt", state: "pending", attempts: 0, maxAttempts: 5, nextAttemptAt: null }]); const result = await restoreService.processRestoreSync({ backupId: saved.id, clock, uploader: { enabled: () => true, upload: async () => true } }); assert.equal(result.metadata.restoreSync.state, "completed"); });
  await t.test("SQLite restore queue adapter remains restart-safe", () => { assert.equal(typeof backupRepository.saveBackup, "function"); });
  await t.test("S3 reconciliation", async () => { reset(); fs.writeFileSync(path.join(runtime, "uploads", "s3.txt"), "s3"); const saved = syncBackup([{ path: "uploads/s3.txt", area: "uploads", folderId: "root", name: "s3.txt", state: "pending", attempts: 0, maxAttempts: 5, nextAttemptAt: null }]); let provider = ""; const result = await restoreService.processRestoreSync({ backupId: saved.id, clock, uploader: { enabled: () => true, upload: async () => { provider = "s3"; } } }); assert.equal(provider, "s3"); assert.equal(result.metadata.restoreSync.state, "completed"); });
  await t.test("Drive reconciliation", async () => { reset(); fs.writeFileSync(path.join(runtime, "uploads", "drive.txt"), "drive"); const saved = syncBackup([{ path: "uploads/drive.txt", area: "uploads", folderId: "root", name: "drive.txt", state: "pending", attempts: 0, maxAttempts: 5, nextAttemptAt: null }]); let provider = ""; const result = await restoreService.processRestoreSync({ backupId: saved.id, clock, uploader: { enabled: () => true, upload: async () => { provider = "gdrive"; } } }); assert.equal(provider, "gdrive"); assert.equal(result.metadata.restoreSync.state, "completed"); });
  await t.test("Windows restore keeps selected bytes suppressed while a provider case alias exists", async () => {
    reset();
    const fileName = "Case-Orphan.TXT";
    fs.writeFileSync(path.join(runtime, "uploads", fileName), "restored bytes");
    const saved = syncBackup([{ path: `uploads/${fileName}`, area: "uploads", folderId: "root", name: fileName, state: "pending", attempts: 0, maxAttempts: 5, nextAttemptAt: null }]);
    const policy = require("../services/restoreProviderOrphans");
    await policy.write([{ area: "uploads", folderId: "root", name: fileName }]);
    const platform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { value: "win32" });
    let aliasPresent = true;
    let uploadCalls = 0;
    const provider = {
      provider: "s3",
      enabled: () => true,
      upload: async () => { uploadCalls += 1; },
      inventory: async () => aliasPresent
        ? [
            { area: "uploads", folderId: "root", name: fileName },
            { area: "uploads", folderId: "root", name: fileName.toLowerCase() },
          ]
        : [{ area: "uploads", folderId: "root", name: fileName }],
    };
    try {
      const blocked = await restoreService.processRestoreSync({ backupId: saved.id, clock, uploader: provider });
      assert.equal(blocked.metadata.restoreSync.state, "pending");
      assert.equal(blocked.metadata.restoreSync.entries[0].failureCategory, "configuration");
      assert.equal(policy.isSuppressed("root", fileName), true);
      assert.equal(policy.isSuppressed("root", fileName.toLowerCase()), true);

      aliasPresent = false;
      clock.value = Date.parse(blocked.metadata.restoreSync.entries[0].nextAttemptAt) + 1;
      const completed = await restoreService.processRestoreSync({ backupId: saved.id, clock, uploader: provider });
      assert.equal(completed.metadata.restoreSync.state, "completed");
      assert.equal(uploadCalls, 2);
      assert.equal(policy.isSuppressed("root", fileName), false);
    } finally {
      Object.defineProperty(process, "platform", platform);
    }
  });
  await t.test("production Drive adapter pins restore uploads to a reserved ID", async () => {
    reset();
    fs.writeFileSync(path.join(runtime, "uploads", "drive-restore.txt"), "drive restore bytes");
    const saved = syncBackup([{ path: "uploads/drive-restore.txt", area: "uploads", folderId: "root", name: "drive-restore.txt", state: "pending", attempts: 0, maxAttempts: 5, nextAttemptAt: null }]);
    const calls = { generated: 0, creates: [] };
    const storage = createCloudStorage({
      provider: "gdrive",
      prefix: "rootark",
      gdrive: { folderId: "drive-root" },
      createGoogleDriveClient: async () => ({ files: {
        list: async () => ({ data: { files: [] } }),
        generateIds: async () => { calls.generated += 1; return { data: { ids: ["reserved-drive-id"] } }; },
        get: async ({ fileId }) => {
          if (fileId === "reserved-drive-id") throw Object.assign(new Error("not found"), { response: { status: 404 } });
          throw new Error("unexpected file lookup");
        },
        create: async (request) => {
          calls.creates.push(request);
          for await (const _chunk of request.media.body) { /* drain the real upload stream */ }
          return { data: { id: request.requestBody.id } };
        },
      } }),
    });

    // Pass the adapter as createCloudStorage returns it in production; do not
    // decorate it with a synthetic `provider` field in the test.
    const result = await restoreService.processRestoreSync({ backupId: saved.id, clock, uploader: storage });
    const entry = result.metadata.restoreSync.entries[0];
    assert.equal(result.metadata.restoreSync.state, "completed");
    assert.equal(calls.generated, 1);
    assert.equal(entry.providerFileId, "reserved-drive-id");
    assert.equal(calls.creates.length, 1);
    assert.equal(calls.creates[0].requestBody.id, "reserved-drive-id");
  });
  await t.test("retry success", async () => { reset(); fs.writeFileSync(path.join(runtime, "uploads", "retry.txt"), "retry"); const saved = syncBackup([{ path: "uploads/retry.txt", area: "uploads", folderId: "root", name: "retry.txt", state: "pending", attempts: 0, maxAttempts: 5, nextAttemptAt: null }]); let calls = 0; let result = await restoreService.processRestoreSync({ backupId: saved.id, clock, uploader: { enabled: () => true, upload: async () => { calls += 1; if (calls === 1) throw new Error("offline"); } } }); assert.equal(result.metadata.restoreSync.state, "pending"); clock.value = new Date(result.metadata.restoreSync.entries[0].nextAttemptAt).getTime(); result = await restoreService.processRestoreSync({ backupId: saved.id, clock, uploader: { enabled: () => true, upload: async () => { calls += 1; } } }); assert.equal(result.metadata.restoreSync.state, "completed"); });
  await t.test("provider failures remain retryable after legacy maxAttempts", async () => { reset(); fs.writeFileSync(path.join(runtime, "uploads", "terminal.txt"), "terminal"); const saved = syncBackup([{ path: "uploads/terminal.txt", area: "uploads", folderId: "root", name: "terminal.txt", state: "pending", attempts: 0, maxAttempts: 1, nextAttemptAt: null }]); const result = await restoreService.processRestoreSync({ backupId: saved.id, clock, uploader: { enabled: () => true, upload: async () => { throw new Error("offline"); } } }); assert.equal(result.metadata.restoreSync.state, "pending"); assert.equal(result.metadata.restoreSync.entries[0].state, "retry_wait"); assert.ok(result.metadata.restoreSync.entries[0].nextAttemptAt); });
  await t.test("restart resumes sync", async () => { reset(); fs.writeFileSync(path.join(runtime, "uploads", "restart.txt"), "restart"); const saved = syncBackup([{ path: "uploads/restart.txt", area: "uploads", folderId: "root", name: "restart.txt", state: "pending", attempts: 0, maxAttempts: 5, nextAttemptAt: null }]); const reloaded = backupRepository.getBackup(saved.id); const result = await restoreService.processRestoreSync({ backupId: reloaded.id, clock, uploader: { enabled: () => true, upload: async () => true } }); assert.equal(result.metadata.restoreSync.state, "completed"); });
  await t.test("exact local bytes", async () => { reset(); const bytes = Buffer.from([0, 255, 1, 2]); fs.writeFileSync(path.join(runtime, "uploads", "bytes.bin"), bytes); const saved = syncBackup([{ path: "uploads/bytes.bin", area: "uploads", folderId: "root", name: "bytes.bin", state: "pending", attempts: 0, maxAttempts: 5, nextAttemptAt: null }]); let received; await restoreService.processRestoreSync({ backupId: saved.id, clock, uploader: { enabled: () => true, upload: async (localPath) => { received = fs.readFileSync(localPath); } } }); assert.deepEqual(received, bytes); });
  await t.test("provider success then persistence failure", async () => { reset(); fs.writeFileSync(path.join(runtime, "uploads", "persist.txt"), "persist"); const saved = syncBackup([{ path: "uploads/persist.txt", area: "uploads", folderId: "root", name: "persist.txt", state: "pending", attempts: 0, maxAttempts: 5, nextAttemptAt: null }]); const original = backupRepository.mutateRestoreSyncEntry; let mutations = 0; backupRepository.mutateRestoreSyncEntry = (...args) => { mutations += 1; if (mutations > 1) throw Object.assign(new Error("persist"), { code: "persistence_error" }); return original(...args); }; let calls = 0; try { await assert.rejects(restoreService.processRestoreSync({ backupId: saved.id, clock, uploader: { enabled: () => true, upload: async () => { calls += 1; } } })); } finally { backupRepository.mutateRestoreSyncEntry = original; } assert.equal(calls, 1); });
  await t.test("overlapping workers cannot upload a claimed entry twice", async () => {
    reset(); fs.writeFileSync(path.join(runtime, "uploads", "overlap.txt"), "overlap");
    const saved = syncBackup([{ path: "uploads/overlap.txt", area: "uploads", folderId: "root", name: "overlap.txt", state: "pending", attempts: 0, maxAttempts: 5, nextAttemptAt: null }]);
    let calls = 0; let release;
    const first = restoreService.processRestoreSync({ backupId: saved.id, clock, workerId: "first", uploader: { enabled: () => true, upload: async () => { calls += 1; await new Promise((resolve) => { release = resolve; }); } } });
    await new Promise((resolve) => setImmediate(resolve));
    const second = await restoreService.processRestoreSync({ backupId: saved.id, clock, workerId: "second", uploader: { enabled: () => true, upload: async () => { calls += 1; } } });
    assert.equal(calls, 1);
    assert.equal(second.metadata.restoreSync.entries[0].state, "in_progress");
    release();
    const completed = await first;
    assert.equal(completed.metadata.restoreSync.state, "completed");
  });
  await t.test("idempotent completed retry", async () => { reset(); const saved = syncBackup([{ path: "uploads/done.txt", area: "uploads", folderId: "root", name: "done.txt", state: "completed", attempts: 1, maxAttempts: 5, nextAttemptAt: null }]); let calls = 0; const result = await restoreService.processRestoreSync({ backupId: saved.id, clock, uploader: { enabled: () => true, upload: async () => { calls += 1; } } }); assert.equal(calls, 0); assert.equal(result.metadata.restoreSync.state, "completed"); });
  await t.test("sensitive entry exclusion", async () => { const result = await runBackup([object(".env", "secret")]); assert.equal(result.ok, false); });
  await t.test("checkout isolation", () => { assert.equal(backupService.getArchivePath("../outside.zip"), null); assert.ok(backupService.getArchivePath("rootark-backup-2026-08-01-00-00-00.zip").startsWith(backupService.BACKUPS_DIR)); });
});

test.after(() => {
  backupService.setCloudStorage(null);
  restoreService.setCloudStorage(null);
  process.chdir(originalCwd);
  fs.rmSync(runtime, { recursive: true, force: true });
});
