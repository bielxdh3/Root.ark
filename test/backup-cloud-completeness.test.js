const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const unzipper = require("unzipper");

const originalCwd = process.cwd();
const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-backup-"));
process.chdir(runtime);
process.env.DB_ENABLED = "false";
const backupService = require("../services/backupService");

test("cloud-only files are staged into the archive without changing the live cache", async () => {
  fs.mkdirSync(path.join(runtime, "uploads"), { recursive: true });
  fs.writeFileSync(path.join(runtime, "uploads", "local.txt"), "local");
  backupService.setCloudStorage({
    enabled: () => true,
    inventory: async () => [{ provider: "s3", providerIdentity: "cloud", area: "uploads", folderId: "root", name: "cloud.txt" }, { provider: "s3", providerIdentity: "local", area: "uploads", folderId: "root", name: "local.txt" }],
    download: async (_folderId, name, target) => { fs.writeFileSync(target, name === "cloud.txt" ? "cloud" : "local"); return true; },
  });
  const backup = await backupService.createBackup({ createdBy: "tester" });
  const archive = await unzipper.Open.file(path.join(runtime, "data", "backups", backup.filename));
  const manifest = JSON.parse((await archive.files.find((entry) => entry.path === "backup-manifest.json").buffer()).toString("utf8"));
  assert.equal(manifest.cloud_complete, true);
  assert.ok(archive.files.some((entry) => entry.path === "uploads/cloud.txt"));
  assert.equal(archive.files.filter((entry) => entry.path === "uploads/local.txt").length, 1);
  assert.equal(fs.existsSync(path.join(runtime, "uploads", "cloud.txt")), false);
  assert.equal(fs.existsSync(path.join(runtime, "data", "backups", ".cloud-stage")), false);
});

test("cold cloud cache staging files under uploads and temp are never archived", async () => {
  const previousIncludeTemp = process.env.BACKUP_INCLUDE_TEMP;
  process.env.BACKUP_INCLUDE_TEMP = "true";
  try {
    for (const area of ["uploads", "temp"]) {
      fs.mkdirSync(path.join(runtime, area), { recursive: true });
      fs.writeFileSync(path.join(runtime, area, ".rootark-cloud-cache-cold-file"), "cold provider cache");
      const directory = path.join(runtime, area, ".rootark-cloud-cache-cold-test");
      fs.mkdirSync(directory, { recursive: true });
      fs.writeFileSync(path.join(directory, "staged.bin"), "cold provider cache");
    }
    backupService.setCloudStorage({ enabled: () => false });
    const backup = await backupService.createBackup({ createdBy: "tester" });
    const archive = await unzipper.Open.file(path.join(runtime, "data", "backups", backup.filename));
    const entries = archive.files.map((entry) => entry.path);
    assert.equal(entries.some((entry) => entry.includes(".rootark-cloud-cache-")), false);
  } finally {
    if (previousIncludeTemp === undefined) delete process.env.BACKUP_INCLUDE_TEMP;
    else process.env.BACKUP_INCLUDE_TEMP = previousIncludeTemp;
  }
});

test("cloud coordination records under data are excluded while ordinary data remains backed up", async () => {
  const dataDir = path.join(runtime, "data");
  fs.mkdirSync(path.join(dataDir, ".rootark-cloud-file-locks"), { recursive: true });
  fs.mkdirSync(path.join(dataDir, ".rootark-cloud-temp-mutations"), { recursive: true });
  fs.mkdirSync(path.join(dataDir, ".rootark-cloud-upload-mutations"), { recursive: true });
  fs.writeFileSync(path.join(dataDir, ".rootark-cloud-file-locks", "active.json"), "lock state");
  fs.writeFileSync(path.join(dataDir, ".rootark-cloud-temp-mutations", "pending.json"), "temp queue state");
  fs.writeFileSync(path.join(dataDir, ".rootark-cloud-upload-mutations", "pending.json"), "upload queue state");
  fs.writeFileSync(path.join(dataDir, ".rootark-cloud-coordination.json"), "transient coordination state");
  fs.writeFileSync(path.join(dataDir, "settings.json"), JSON.stringify({ keep: true }));

  backupService.setCloudStorage({ enabled: () => false });
  const backup = await backupService.createBackup({ createdBy: "tester" });
  const archive = await unzipper.Open.file(path.join(dataDir, "backups", backup.filename));
  const entries = archive.files.map((entry) => entry.path);

  assert.ok(entries.includes("data/settings.json"));
  assert.equal(entries.some((entry) => entry.includes(".rootark-cloud-")), false);
});

test("a changed provider suppression policy cannot be recorded as a successful backup", async () => {
  const policy = require("../services/restoreProviderOrphans");
  const backupsDir = path.join(runtime, "data", "backups");
  const archivesBefore = fs.readdirSync(backupsDir).filter((name) => name.endsWith(".zip")).sort();
  const historyBefore = backupService.listBackups();
  await policy.write([]);
  backupService.setCloudStorage({
    enabled: () => true,
    inventory: async () => {
      await policy.write([{ area: "uploads", folderId: "root", name: "changed-during-backup.txt" }]);
      return [{ provider: "s3", providerIdentity: "changed", area: "uploads", folderId: "root", name: "changed-during-backup.txt" }];
    },
    download: async (_folderId, _name, target) => { fs.writeFileSync(target, "provider bytes"); return true; },
  });
  await assert.rejects(backupService.createBackup({ createdBy: "tester" }), /suppression policy changed/i);
  assert.deepEqual(fs.readdirSync(backupsDir).filter((name) => name.endsWith(".zip")).sort(), archivesBefore);
  const historyAfter = backupService.listBackups();
  assert.equal(historyAfter.filter((entry) => entry.status === "success").length, historyBefore.filter((entry) => entry.status === "success").length);
  assert.equal(historyAfter.filter((entry) => entry.status === "failed").length, historyBefore.filter((entry) => entry.status === "failed").length + 1);
});

test("divergent cloud collisions fail closed and leave no archive", () => {
  const isolated = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-backup-fail-"));
  const servicePath = path.join(__dirname, "..", "services", "backupService");
  const script = [
    `process.chdir(${JSON.stringify(isolated)}); process.env.DB_ENABLED = "false";`,
    'const fs = require("fs"); const path = require("path");',
    `const service = require(${JSON.stringify(servicePath)});`,
    'fs.mkdirSync("uploads", { recursive: true }); fs.writeFileSync("uploads/same.txt", "local");',
    'service.setCloudStorage({ enabled: () => true, inventory: async () => [{ provider: "s3", providerIdentity: "same", area: "uploads", folderId: "root", name: "same.txt" }], download: async (_f, _n, target) => { fs.writeFileSync(target, "remote"); return true; } });',
    'service.createBackup().then(() => process.exitCode = 2).catch(() => { const backups = path.join(process.cwd(), "data", "backups"); const files = fs.existsSync(backups) ? fs.readdirSync(backups).filter((name) => name.endsWith(".zip")) : []; process.exitCode = files.length ? 3 : 0; });',
  ].join(" ");
  const result = spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
  fs.rmSync(isolated, { recursive: true, force: true });
  assert.equal(result.status, 0, result.stderr);
});

test("cloud inventory and download failures cannot create a successful backup", async (t) => {
  for (const mode of ["list", "download"]) {
    await t.test(`${mode} failure`, () => {
      const isolated = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-backup-error-"));
      const servicePath = path.join(__dirname, "..", "services", "backupService");
      const script = [
        `process.chdir(${JSON.stringify(isolated)}); process.env.DB_ENABLED = "false";`,
        'const fs = require("fs"); const path = require("path");',
        `const service = require(${JSON.stringify(servicePath)});`,
        `service.setCloudStorage({ enabled: () => true, inventory: async () => { ${mode === "list" ? 'throw new Error("unavailable");' : 'return [{ provider: "s3", providerIdentity: "cloud", area: "uploads", folderId: "root", name: "cloud.txt" }];'} }, download: async () => { throw new Error("unavailable"); } });`,
        'service.createBackup().then(() => process.exitCode = 2).catch(() => { const backups = path.join(process.cwd(), "data", "backups"); const files = fs.existsSync(backups) ? fs.readdirSync(backups).filter((name) => name.endsWith(".zip")) : []; process.exitCode = files.length ? 3 : 0; });',
      ].join(" ");
      const result = spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
      fs.rmSync(isolated, { recursive: true, force: true });
      assert.equal(result.status, 0, result.stderr);
    });
  }
});

test("pending cloud objects are included only when configured", async (t) => {
  const servicePath = path.join(__dirname, "..", "services", "backupService");
  for (const includePending of [false, true]) {
    await t.test(includePending ? "includes pending area" : "excludes pending area", () => {
      const isolated = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-backup-pending-"));
      const script = [
        `process.chdir(${JSON.stringify(isolated)}); process.env.DB_ENABLED = "false"; process.env.BACKUP_INCLUDE_PENDING = ${JSON.stringify(String(includePending))};`,
        `const service = require(${JSON.stringify(servicePath)});`,
        'const calls = []; service.setCloudStorage({ enabled: () => true, inventory: async () => { calls.push(process.env.BACKUP_INCLUDE_PENDING === "true" ? "uploads,temp" : "uploads"); return []; }, download: async () => true });',
        'service.createBackup().then(() => console.log(JSON.stringify(calls))).catch((error) => { console.error(error); process.exitCode = 1; });',
      ].join(" ");
      const result = spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
      fs.rmSync(isolated, { recursive: true, force: true });
      assert.equal(result.status, 0, result.stderr);
      const calls = JSON.parse(result.stdout.trim());
      assert.deepEqual(calls, [includePending ? "uploads,temp" : "uploads"]);
    });
  }
});

test("unsafe cloud object names fail closed without retaining an archive", async (t) => {
  const servicePath = path.join(__dirname, "..", "services", "backupService");
  for (const name of ["../escape.txt", "/absolute.txt", "nested/file.txt", "nested\\file.txt", ".env"]) {
    await t.test(name, () => {
      const isolated = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-backup-unsafe-"));
      const script = [
        `process.chdir(${JSON.stringify(isolated)}); process.env.DB_ENABLED = "false";`,
        'const fs = require("fs"); const path = require("path");',
        `const service = require(${JSON.stringify(servicePath)});`,
        `service.setCloudStorage({ enabled: () => true, inventory: async () => [{ provider: "s3", providerIdentity: "bad", area: "uploads", folderId: "root", name: ${JSON.stringify(name)} }], download: async () => true });`,
        'service.createBackup().then(() => process.exitCode = 2).catch(() => { const backups = path.join(process.cwd(), "data", "backups"); const files = fs.existsSync(backups) ? fs.readdirSync(backups).filter((file) => file.endsWith(".zip")) : []; process.exitCode = files.length ? 3 : 0; });',
      ].join(" ");
      const result = spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
      fs.rmSync(isolated, { recursive: true, force: true });
      assert.equal(result.status, 0, `${name}: ${result.stderr}`);
    });
  }
});

test("a cloud-only object survives SQLite backup and restore", () => {
  const isolated = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-backup-sqlite-runtime-"));
  const databaseDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-backup-sqlite-db-"));
  const databasePath = path.join(databaseDir, "configured.sqlite");
  const servicePath = path.join(__dirname, "..", "services", "backupService");
  const restorePath = path.join(__dirname, "..", "services", "restoreService");
  const script = [
    `process.chdir(${JSON.stringify(isolated)}); process.env.DB_ENABLED = "true"; process.env.DATABASE_URL = ${JSON.stringify(databasePath)};`,
    'const assert = require("node:assert/strict"); const fs = require("node:fs");',
    `const Database = require(${JSON.stringify(path.join(__dirname, "..", "node_modules", "better-sqlite3"))});`,
    `const backup = require(${JSON.stringify(servicePath)}); const restore = require(${JSON.stringify(restorePath)});`,
    'const db = new Database(process.env.DATABASE_URL); db.exec("CREATE TABLE proof (value TEXT); INSERT INTO proof VALUES (\'cloud\');"); db.close();',
    'const cloud = { enabled: () => true, inventory: async () => [{ provider: "s3", providerIdentity: "cloud", area: "uploads", folderId: "root", name: "cloud.txt" }], download: async (_folder, _name, target) => { fs.writeFileSync(target, "cloud"); return true; } }; backup.setCloudStorage(cloud); restore.setCloudStorage(cloud);',
    'backup.createBackup({ createdBy: "test" }).then(async (saved) => { fs.rmSync("uploads", { recursive: true, force: true }); const result = await restore.restoreBackup(saved.id, { confirmation: "RESTORE", username: "test" }); assert.equal(fs.readFileSync("uploads/cloud.txt", "utf8"), "cloud"); assert.equal(result.cloudSync.state, "pending"); assert.equal(backup.listBackups().find((entry) => entry.id === saved.id).metadata.restoreSync.state, "pending"); console.log(JSON.stringify({ ok: true })); }).catch((error) => { console.error(error); process.exitCode = 1; });',
  ].join(" ");
  const result = spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
  fs.rmSync(isolated, { recursive: true, force: true });
  fs.rmSync(databaseDir, { recursive: true, force: true });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout.trim()).ok, true);
});

test("an incomplete backup does not claim a same-path provider object was archived", () => {
  const isolated = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-incomplete-cloud-restore-"));
  const servicePath = path.join(__dirname, "..", "services", "backupService");
  const restorePath = path.join(__dirname, "..", "services", "restoreService");
  const orphanPolicyPath = path.join(isolated, "data", ".rootark-restore-provider-orphans.json");
  const script = [
    `process.chdir(${JSON.stringify(isolated)}); process.env.DB_ENABLED = "false";`,
    'const assert = require("node:assert/strict"); const fs = require("node:fs");',
    `const backup = require(${JSON.stringify(servicePath)}); const restore = require(${JSON.stringify(restorePath)});`,
    'fs.mkdirSync("uploads", { recursive: true }); fs.writeFileSync("uploads/same.txt", "archived local bytes");',
    'backup.setCloudStorage({ enabled: () => false });',
    'backup.createBackup({ createdBy: "test" }).then(async (saved) => {',
    '  let inventoryCalls = 0;',
    '  const cloud = { enabled: () => true, inventory: async () => ++inventoryCalls === 1 ? [{ provider: "s3", providerIdentity: "uncaptured", area: "uploads", folderId: "root", name: "same.txt" }] : [], download: async (_folder, _name, target) => { fs.writeFileSync(target, "provider bytes not in the backup"); return true; } };',
    '  backup.setCloudStorage(cloud); restore.setCloudStorage(cloud);',
    '  const result = await restore.restoreBackup(saved.id, { confirmation: "RESTORE", username: "test" });',
    '  assert.equal(result.manifest.cloud_complete, false);',
    `  const policy = JSON.parse(fs.readFileSync(${JSON.stringify(orphanPolicyPath)}, "utf8"));`,
    '  assert.deepEqual(policy.objects, [{ area: "uploads", folderId: "root", name: "same.txt" }], "provider content absent from an incomplete archive remains suppressed even when its logical path matches");',
    '  process.stdout.write(JSON.stringify({ ok: true }));',
    '}).catch((error) => { console.error(error); process.exitCode = 1; });',
  ].join(" ");
  const result = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", timeout: 20_000 });
  fs.rmSync(isolated, { recursive: true, force: true });
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
  assert.equal(JSON.parse(result.stdout.trim()).ok, true);
});

test("cloud backup object matrix", async (t) => {
  const servicePath = path.join(__dirname, "..", "services", "backupService");
  const unzipperPath = path.join(__dirname, "..", "node_modules", "unzipper");
  const run = ({ objects = [], local = null, enabled = true, failList = false, failDownload = false }) => {
    const isolated = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-backup-matrix-"));
    const payload = JSON.stringify({ objects, local, enabled, failList, failDownload });
    const script = [
      `process.chdir(${JSON.stringify(isolated)}); process.env.DB_ENABLED = "false"; const input = ${payload};`,
      'const fs = require("fs"); const path = require("path");',
      `const service = require(${JSON.stringify(servicePath)}); const unzipper = require(${JSON.stringify(unzipperPath)});`,
      'if (input.local) { fs.mkdirSync("uploads", { recursive: true }); fs.writeFileSync(path.join("uploads", input.local.name), input.local.content); }',
      'service.setCloudStorage({ enabled: () => input.enabled, inventory: async () => { if (input.failList) throw new Error("offline"); return input.objects.map(([name]) => ({ provider: "s3", providerIdentity: name, area: "uploads", folderId: "root", name })); }, download: async (_f, name, target) => { if (input.failDownload) throw new Error("offline"); fs.writeFileSync(target, input.objects.find(([candidate]) => candidate === name)[1]); return true; } });',
      'service.createBackup().then(async (backup) => { const archive = await unzipper.Open.file(path.join("data", "backups", backup.filename)); console.log(JSON.stringify({ ok: true, entries: archive.files.filter((entry) => entry.type !== "Directory").map((entry) => entry.path), stage: fs.existsSync(path.join("data", "backups", ".cloud-stage")) })); }).catch(() => { const backups = path.join("data", "backups"); const zips = fs.existsSync(backups) ? fs.readdirSync(backups).filter((name) => name.endsWith(".zip")) : []; const history = fs.existsSync(path.join("data", "backup-history.json")) ? JSON.parse(fs.readFileSync(path.join("data", "backup-history.json"), "utf8")) : []; console.log(JSON.stringify({ ok: false, zips: zips.length, failed: history.some((entry) => entry.status === "failed"), stage: fs.existsSync(path.join("data", "backups", ".cloud-stage")) })); });',
    ].join(" ");
    const result = spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
    fs.rmSync(isolated, { recursive: true, force: true });
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout.trim());
  };
  await t.test("local-only upload remains available", () => assert.ok(run({ local: { name: "local.txt", content: "local" } }).entries.includes("uploads/local.txt")));
  await t.test("zero-byte remote upload is retained", () => assert.ok(run({ objects: [["empty.txt", ""]] }).entries.includes("uploads/empty.txt")));
  await t.test("Unicode remote key is retained", () => assert.ok(run({ objects: [["olá-文件.txt", "bytes"]] }).entries.includes("uploads/olá-文件.txt")));
  await t.test("fake S3 inventory is provider-neutral", () => assert.ok(run({ objects: [["s3-object.txt", "s3"]] }).entries.includes("uploads/s3-object.txt")));
  await t.test("fake Google Drive inventory is provider-neutral", () => assert.ok(run({ objects: [["drive-object.txt", "drive"]] }).entries.includes("uploads/drive-object.txt")));
  await t.test("disabled storage does not stage remote work", () => assert.equal(run({ enabled: false, local: { name: "offline.txt", content: "offline" } }).stage, false));
  await t.test("failed inventory removes archives and records failure", () => {
    const result = run({ failList: true });
    assert.deepEqual({ ok: result.ok, zips: result.zips, failed: result.failed, stage: result.stage }, { ok: false, zips: 0, failed: true, stage: false });
  });
});

test("restore-suppressed provider objects are not downloaded or archived", () => {
  const isolated = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-backup-suppressed-"));
  const servicePath = path.join(__dirname, "..", "services", "backupService");
  const unzipperPath = path.join(__dirname, "..", "node_modules", "unzipper");
  const script = [
    `process.chdir(${JSON.stringify(isolated)}); process.env.DB_ENABLED = "false"; process.env.BACKUP_INCLUDE_PENDING = "true";`,
    'const fs = require("node:fs"); const path = require("node:path");',
    `const service = require(${JSON.stringify(servicePath)}); const unzipper = require(${JSON.stringify(unzipperPath)});`,
    'fs.mkdirSync("uploads", { recursive: true }); fs.mkdirSync("temp", { recursive: true }); fs.writeFileSync("uploads/local.txt", "local upload"); fs.writeFileSync("temp/local-pending.txt", "local pending"); fs.writeFileSync("uploads/suppressed-upload.txt", "stale local upload"); fs.writeFileSync("temp/suppressed-pending.txt", "stale local pending");',
    'fs.mkdirSync("data", { recursive: true }); fs.writeFileSync("data/.rootark-restore-provider-orphans.json", JSON.stringify({ version: 1, objects: [{ area: "uploads", folderId: "root", name: "suppressed-upload.txt" }, { area: "temp", folderId: "root", name: "suppressed-pending.txt" }] }));',
    'const remotes = [{ area: "uploads", folderId: "root", name: "suppressed-upload.txt" }, { area: "temp", folderId: "root", name: "suppressed-pending.txt" }, { area: "uploads", folderId: "root", name: "cloud.txt" }, { area: "temp", folderId: "root", name: "cloud-pending.txt" }]; const downloads = [];',
    'service.setCloudStorage({ enabled: () => true, inventory: async () => remotes.map((remote) => ({ provider: "s3", providerIdentity: remote.name, ...remote })), download: async (folderId, name, target, area) => { downloads.push(`${area}/${name}`); fs.writeFileSync(target, `${area}:${name}`); return true; } });',
    'service.createBackup().then(async (backup) => { const archive = await unzipper.Open.file(path.join("data", "backups", backup.filename)); console.log(JSON.stringify({ entries: archive.files.filter((entry) => entry.type !== "Directory").map((entry) => entry.path), downloads })); }).catch((error) => { console.error(error); process.exitCode = 1; });',
  ].join(" ");
  const result = spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
  fs.rmSync(isolated, { recursive: true, force: true });
  assert.equal(result.status, 0, result.stderr);
  const { entries, downloads } = JSON.parse(result.stdout.trim());
  assert.equal(downloads.includes("uploads/suppressed-upload.txt"), false);
  assert.equal(downloads.includes("temp/suppressed-pending.txt"), false);
  assert.ok(entries.includes("uploads/local.txt"));
  assert.ok(entries.includes("temp/local-pending.txt"));
  assert.equal(entries.includes("uploads/suppressed-upload.txt"), false);
  assert.equal(entries.includes("temp/suppressed-pending.txt"), false);
  assert.ok(entries.includes("uploads/cloud.txt"));
  assert.ok(entries.includes("temp/cloud-pending.txt"));
});

test.after(() => {
  backupService.setCloudStorage(null);
  process.chdir(originalCwd);
  fs.rmSync(runtime, { recursive: true, force: true });
});
