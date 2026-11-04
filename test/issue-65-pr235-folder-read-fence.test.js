"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const vm = require("node:vm");
const crypto = require("node:crypto");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

const project = path.resolve(__dirname, "..");
const nodePath = [path.join(project, "node_modules"), process.env.NODE_PATH]
  .filter(Boolean).join(path.delimiter);

test("real SQLite folders remain readable during an awaited strict Sync account write fence", {
  timeout: 45_000,
}, (t) => {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA || os.homedir(),
      "zk65-folder-read-" + crypto.randomBytes(10).toString("hex"))
    : fs.mkdtempSync(path.join(os.tmpdir(), "zk65-folder-read-"));
  if (process.platform === "win32") {
    assert.equal(fs.existsSync(root), false);
    ensureWindowsChunkUploadRoot(root);
  }
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const script = String.raw`
    "use strict";
    const assert = require("node:assert/strict");
    const path = require("node:path");
    const Database = require("better-sqlite3");
    const project = process.env.ZK65_FOLDER_TEST_PROJECT;
    const { runMigrations } = require(path.join(project, "db", "migrations"));
    const { getDb, closeDb } = require(path.join(project, "db"));
    const folders = require(path.join(project, "repositories", "foldersRepository"));
    const { createSyncSqliteAccountWriteFence } =
      require(path.join(project, "src", "services", "syncSqliteAccountWriteFence"));
    (async () => {
      runMigrations({ backup: false });
      const db = getDb();
      const stamp = "2026-11-04T00:00:00.000Z";
      db.prepare("INSERT INTO users (username,password_hash,role,permissions_json,created_at,updated_at) "
        + "VALUES ('folder-reader','fixture','user',?, ?, ?)")
        .run(JSON.stringify({ upload: true }), stamp, stamp);
      folders.saveFolders([
        { id: "root", name: "Arquivos atuais", isRoot: true, createdAt: stamp },
        { id: "project", name: "Private project", createdAt: stamp,
          allowedUsers: ["folder-reader"] },
      ]);
      const rootBefore = db.prepare("SELECT updated_at FROM folders WHERE id='root'").get().updated_at;
      const fence = createSyncSqliteAccountWriteFence();
      await fence({ username: "folder-reader", sessionVersion: 0 },
        { operation: "put" }, async () => {
          await new Promise((resolve) => setImmediate(resolve));
          const other = new Database(process.env.DATABASE_URL, { timeout: 0 });
          try {
            assert.throws(() => other.prepare("UPDATE folders SET name=name WHERE id='project'").run(),
              (error) => error?.code === "SQLITE_BUSY",
              "the durable account fence must really hold an SQLite write reservation");
          } finally { other.close(); }
          const loaded = folders.loadFolders();
          assert.deepEqual(loaded.map((folder) => folder.id), ["root", "project"]);
          assert.deepEqual(loaded[1].allowedUsers, ["folder-reader"]);
          assert.equal(db.prepare("SELECT updated_at FROM folders WHERE id='root'").get().updated_at,
            rootBefore, "a folder lookup must never rewrite the root row");
        });
      assert.equal(db.prepare("SELECT count(*) AS n FROM folders WHERE deleted_at IS NULL")
        .get().n, 2);

      // A missing root is represented for callers without a read-path UPSERT.
      db.prepare("DELETE FROM folders WHERE id='root'").run();
      assert.deepEqual(folders.loadFolders().map((folder) => folder.id), ["root", "project"]);
      assert.equal(db.prepare("SELECT count(*) AS n FROM folders WHERE id='root'").get().n, 0);
      closeDb();
      process.stdout.write("ZK65_FOLDER_READ_ONLY_OK\n");
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `;
  const result = spawnSync(process.execPath, ["-e", script], {
    cwd: root, encoding: "utf8", timeout: 40_000, windowsHide: true,
    env: { ...process.env, NODE_PATH: nodePath, ZK65_FOLDER_TEST_PROJECT: project,
      DATABASE_URL: path.join(root, "rootark.sqlite"), DB_ENABLED: "true",
      DB_WRITE_LEGACY_JSON: "false" },
  });
  assert.equal(result.status, 0, result.error?.message || result.stderr || result.stdout);
  assert.match(result.stdout, /ZK65_FOLDER_READ_ONLY_OK/);
});

test("strict SQLite folder errors cannot be converted into an apparently empty folder catalog", () => {
  const source = fs.readFileSync(path.join(project, "server.js"), "utf8");
  const start = source.indexOf("function loadFolders() {");
  const end = source.indexOf("function saveFolders(", start);
  assert.ok(start >= 0 && end > start);
  const busy = Object.assign(new Error("database is locked"), { code: "SQLITE_BUSY" });
  let strict = true;
  const context = vm.createContext({
    shouldUseDatabase: () => true,
    shouldReadJsonFallback: () => false,
    foldersRepository: { loadFolders: () => { throw busy; } },
    dbConfig: { isStrictSyncModeObserved: () => strict },
    getDefaultFolders: () => [{ id: "root" }],
    console: { error: () => {} },
    fs: { existsSync: () => false },
  });
  vm.runInContext(source.slice(start, end), context, { filename: "server.js/loadFolders" });
  assert.throws(() => context.loadFolders(), (error) =>
    error?.code === "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" && error.cause === busy);
  strict = false;
  assert.deepEqual(context.loadFolders().map((folder) => folder.id), ["root"],
    "legacy non-strict fallback remains unchanged");
});
