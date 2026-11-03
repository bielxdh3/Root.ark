const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");

function withMigrationFixture(run) {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-json-migration-rerun-"));
  try {
    for (const directory of ["db", "repositories"]) {
      fs.cpSync(path.join(ROOT, directory), path.join(fixture, directory), { recursive: true });
    }
    for (const file of [
      "services/chunkUploadWindowsAcl.js",
      "src/runtime-paths.js",
      "src/fs-atomic-rename.js",
      "src/services/syncResumeAccountProof.js",
      "src/services/syncSqliteAccountWriteFence.js",
      "src/services/zk1PrivateSqlitePath.js",
    ]) {
      const destination = path.join(fixture, file);
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.copyFileSync(path.join(ROOT, file), destination);
    }
    fs.mkdirSync(path.join(fixture, "data"));
    const env = {
      ...process.env,
      DB_ENABLED: "true",
      DATABASE_URL: path.join(fixture, "data", "rootark.sqlite"),
      NODE_PATH: process.env.NODE_PATH || path.join(ROOT, "node_modules"),
    };
    const execute = (script) => spawnSync(process.execPath, ["-e", script], {
      cwd: fixture, env, encoding: "utf8", timeout: 20_000,
    });
    run({ fixture, execute });
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true });
  }
}

test("JSON migration rerun leaves SQLite account CAS and updated account intact", { timeout: 30_000 }, () => {
  withMigrationFixture(({ fixture, execute }) => {
    fs.writeFileSync(path.join(fixture, "data", "users.json"), JSON.stringify([
      { username: "alice", password: "old-hash", role: "user", permissions: { read: true } },
    ]));
    const result = execute(`
      const assert = require('node:assert/strict');
      const { migrate } = require('./db/migrate-json-to-sqlite');
      const accounts = require('./repositories/usersRepository');
      migrate();
      const first = accounts.loadUsers()[0];
      assert.equal(first.storageRevision, 0);
      accounts.saveUsers([{ ...first, password: 'new-hash', permissions: { write: true } }]);
      const current = accounts.loadUsers()[0];
      assert.equal(current.storageRevision, 1);
      const beforeBackups = require('node:fs').readdirSync('./data/backups', { recursive: true }).sort();
      migrate();
      assert.deepEqual(require('node:fs').readdirSync('./data/backups', { recursive: true }).sort(), beforeBackups);
      const after = accounts.loadUsers()[0];
      assert.equal(after.storageRevision, 1);
      assert.equal(after.password, 'new-hash');
      assert.deepEqual(after.permissions, { write: true });
      assert.throws(() => accounts.saveUsers([first]), /storage revision conflict/i);
    `);
    assert.equal(result.status, 0, result.stderr || result.stdout);
  });
});

test("JSON migration rerun preserves later action history and folder changes", { timeout: 30_000 }, () => {
  withMigrationFixture(({ fixture, execute }) => {
    fs.writeFileSync(path.join(fixture, "data", "actions-history.json"), JSON.stringify([
      { id: "initial-action", action: "upload", actor: "alice", timestamp: "2026-01-01T00:00:00.000Z" },
    ]));
    fs.writeFileSync(path.join(fixture, "data", "folders.json"), JSON.stringify([
      { id: "root", name: "Arquivos atuais", isRoot: true, createdAt: "2026-01-01T00:00:00.000Z" },
      { id: "project", name: "Legacy folder", createdAt: "2026-01-01T00:00:00.000Z" },
    ]));
    const result = execute(`
      const assert = require('node:assert/strict');
      const { migrate } = require('./db/migrate-json-to-sqlite');
      const actions = require('./repositories/actionHistoryRepository');
      const folders = require('./repositories/foldersRepository');
      migrate();
      actions.saveActionHistory([...actions.loadActionHistory(),
        { id: 'new-action', action: 'rename', actor: 'alice', timestamp: '2026-01-02T00:00:00.000Z' }]);
      const nextFolders = folders.loadFolders().map((folder) => folder.id === 'project'
        ? { ...folder, name: 'Updated in SQLite' } : folder);
      folders.saveFolders(nextFolders);
      migrate();
      assert.deepEqual(new Set(actions.loadActionHistory().map((entry) => entry.id)),
        new Set(['initial-action', 'new-action']));
      assert.equal(folders.loadFolders().find((folder) => folder.id === 'project').name, 'Updated in SQLite');
    `);
    assert.equal(result.status, 0, result.stderr || result.stdout);
  });
});

test("JSON migration refuses changed source without modifying imported SQLite data", { timeout: 30_000 }, () => {
  withMigrationFixture(({ fixture, execute }) => {
    const source = path.join(fixture, "data", "users.json");
    fs.writeFileSync(source, JSON.stringify([{ username: "alice", password: "original" }]));
    const result = execute(`
      const assert = require('node:assert/strict');
      const fs = require('node:fs');
      const { migrate } = require('./db/migrate-json-to-sqlite');
      const users = require('./repositories/usersRepository');
      migrate();
      fs.writeFileSync('./data/users.json', JSON.stringify([{ username: 'alice', password: 'changed' }]));
      assert.throws(() => migrate(), /JSON source changed after import/i);
      assert.equal(users.loadUsers()[0].password, 'original');
    `);
    assert.equal(result.status, 0, result.stderr || result.stdout);
  });
});

test("JSON migration refuses pre-existing SQLite rows without an import marker", { timeout: 30_000 }, () => {
  withMigrationFixture(({ fixture, execute }) => {
    fs.writeFileSync(path.join(fixture, "data", "users.json"), JSON.stringify([
      { username: "alice", password: "legacy" },
    ]));
    const result = execute(`
      const assert = require('node:assert/strict');
      require('./db/migrations').runMigrations({ backup: false });
      const users = require('./repositories/usersRepository');
      users.saveUsers([{ username: 'alice', password: 'sqlite-current' }]);
      assert.throws(() => require('./db/migrate-json-to-sqlite').migrate(),
        /pre-existing SQLite data without an import marker/i);
      assert.equal(users.loadUsers()[0].password, 'sqlite-current');
      assert.equal(require('node:fs').existsSync('./data/backups'), false);
    `);
    assert.equal(result.status, 0, result.stderr || result.stdout);
  });
});

test("JSON migration refuses an already imported unmarked legacy database", { timeout: 30_000 }, () => {
  withMigrationFixture(({ fixture, execute }) => {
    fs.writeFileSync(path.join(fixture, "data", "users.json"), JSON.stringify([
      { username: "alice", password: "original" },
    ]));
    const result = execute(`
      const assert = require('node:assert/strict');
      const { migrate } = require('./db/migrate-json-to-sqlite');
      const { getDb } = require('./db');
      migrate();
      const beforeBackups = require('node:fs').readdirSync('./data/backups', { recursive: true }).sort();
      getDb().exec('DROP TABLE legacy_json_sqlite_import');
      assert.throws(() => migrate(), /pre-existing SQLite data without an import marker/i);
      assert.equal(require('./repositories/usersRepository').loadUsers()[0].password, 'original');
      assert.deepEqual(require('node:fs').readdirSync('./data/backups', { recursive: true }).sort(), beforeBackups);
    `);
    assert.equal(result.status, 0, result.stderr || result.stdout);
  });
});

test("JSON migration refuses a corrupted import marker without modifying account state", { timeout: 30_000 }, () => {
  withMigrationFixture(({ fixture, execute }) => {
    fs.writeFileSync(path.join(fixture, "data", "users.json"), JSON.stringify([
      { username: "alice", password: "original" },
    ]));
    const result = execute(`
      const assert = require('node:assert/strict');
      const { migrate } = require('./db/migrate-json-to-sqlite');
      const { getDb } = require('./db');
      migrate();
      getDb().exec('DELETE FROM legacy_json_sqlite_import');
      assert.throws(() => migrate(), /Invalid JSON migration import marker/i);
      assert.equal(require('./repositories/usersRepository').loadUsers()[0].password, 'original');
    `);
    assert.equal(result.status, 0, result.stderr || result.stdout);
  });
});
