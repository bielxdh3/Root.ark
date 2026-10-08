const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");

test("SQLite JSON read fallback is disabled unless explicitly enabled", () => {
  const env = { ...process.env };
  delete env.DB_READ_FALLBACK_JSON;
  const defaultResult = spawnSync(process.execPath, ["-e", 'process.stdout.write(String(require("./db").isJsonReadFallbackEnabled()))'], {
    cwd: ROOT,
    env,
    encoding: "utf8",
  });
  assert.equal(defaultResult.status, 0, defaultResult.stderr || defaultResult.stdout);
  assert.equal(defaultResult.stdout, "false");

  const enabledResult = spawnSync(process.execPath, ["-e", 'process.stdout.write(String(require("./db").isJsonReadFallbackEnabled()))'], {
    cwd: ROOT,
    env: { ...env, DB_READ_FALLBACK_JSON: "true" },
    encoding: "utf8",
  });
  assert.equal(enabledResult.status, 0, enabledResult.stderr || enabledResult.stdout);
  assert.equal(enabledResult.stdout, "true");
});

test("JSON migration preserves trash and backup history in SQLite across restart", { timeout: 20_000 }, () => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-json-sqlite-migration-"));
  try {
    for (const directory of ["db", "repositories"]) {
      fs.cpSync(path.join(ROOT, directory), path.join(fixtureRoot, directory), { recursive: true });
    }
    fs.mkdirSync(path.join(fixtureRoot, "src"), { recursive: true });
    fs.copyFileSync(path.join(ROOT, "src", "runtime-paths.js"), path.join(fixtureRoot, "src", "runtime-paths.js"));
    fs.mkdirSync(path.join(fixtureRoot, "data"), { recursive: true });

    const trashItem = {
      id: "11111111-1111-4111-8111-111111111111",
      itemType: "file",
      originalFolderId: "root",
      originalFileName: "retained.txt",
      trashPath: "files/retained.txt",
      deletedAt: "2026-09-01T00:00:00.000Z",
      metadata: { marker: "legacy-trash" },
      restoreMetadata: { marker: "restore-state" },
      status: "trashed",
    };
    const backup = {
      id: "22222222-2222-4222-8222-222222222222",
      filename: "rootark-backup-2026-09-01.zip",
      type: "manual",
      status: "success",
      createdAt: "2026-09-01T01:00:00.000Z",
      finishedAt: "2026-09-01T01:00:02.000Z",
      sizeBytes: 1234,
      checksum: "a".repeat(64),
      metadata: { marker: "legacy-backup" },
    };
    fs.writeFileSync(path.join(fixtureRoot, "data", "trash-items.json"), JSON.stringify([trashItem]));
    fs.writeFileSync(path.join(fixtureRoot, "data", "backup-history.json"), JSON.stringify([backup]));

    const env = {
      ...process.env,
      DB_ENABLED: "true",
      DATABASE_URL: path.join(fixtureRoot, "data", "rootark.sqlite"),
      NODE_PATH: path.join(ROOT, "node_modules"),
    };
    const migrate = spawnSync(process.execPath, ["-e", [
      'const trashRepository = require("./repositories/trashRepository");',
      'const backupRepository = require("./repositories/backupRepository");',
      'const migrate = require("./db/migrate-json-to-sqlite").migrate;',
      'migrate();',
      'const importedTrash = trashRepository.getTrashItem("11111111-1111-4111-8111-111111111111");',
      'const importedBackup = backupRepository.getBackup("22222222-2222-4222-8222-222222222222");',
      'if (importedTrash?.status !== "trashed" || importedTrash?.deletedAt !== "2026-09-01T00:00:00.000Z" || importedTrash?.metadata?.marker !== "legacy-trash" || importedTrash?.restoreMetadata?.marker !== "restore-state" || importedBackup?.status !== "success" || importedBackup?.sizeBytes !== 1234 || importedBackup?.checksum !== "a".repeat(64) || importedBackup?.metadata?.marker !== "legacy-backup") throw new Error("Legacy records were not imported before re-run");',
      `trashRepository.saveTrashItem(${JSON.stringify({ ...trashItem, status: "restored", metadata: { marker: "sqlite-current" } })});`,
      `backupRepository.saveBackup(${JSON.stringify({ ...backup, status: "failed", metadata: { marker: "sqlite-current" } })});`,
      'migrate();',
      'require("./db").closeDb();',
    ].join(" ")], {
      cwd: fixtureRoot,
      env,
      encoding: "utf8",
    });
    assert.equal(migrate.status, 0, migrate.stderr || migrate.stdout);

    const read = spawnSync(process.execPath, ["-e", [
      'const trash = require("./repositories/trashRepository").getTrashItem("11111111-1111-4111-8111-111111111111");',
      'const backup = require("./repositories/backupRepository").getBackup("22222222-2222-4222-8222-222222222222");',
      'console.log(JSON.stringify({ trash, backup }));',
    ].join(" ")], { cwd: fixtureRoot, env, encoding: "utf8" });
    assert.equal(read.status, 0, read.stderr || read.stdout);
    const records = JSON.parse(read.stdout.trim().split(/\r?\n/).at(-1));
    assert.equal(records.trash.metadata.marker, "sqlite-current");
    assert.equal(records.trash.restoreMetadata.marker, "restore-state");
    assert.equal(records.trash.status, "restored");
    assert.equal(records.backup.filename, backup.filename);
    assert.equal(records.backup.checksum, backup.checksum);
    assert.equal(records.backup.metadata.marker, "sqlite-current");
    assert.equal(records.backup.status, "failed");
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
});
