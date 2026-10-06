const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const test = require("node:test");

const restoreService = require("../services/restoreService");

function makeDatabase(pathname, value, options = {}) {
  const database = new Database(pathname);
  if (options.wal) {
    database.pragma("journal_mode = WAL");
    database.pragma("wal_autocheckpoint = 0");
  }
  database.exec("CREATE TABLE proof (value TEXT NOT NULL);");
  database.prepare("INSERT INTO proof(value) VALUES (?)").run(value);
  if (!options.keepOpen) database.close();
  return database;
}

function makeFixture(options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-sqlite-meta-"));
  const sourceRoot = path.join(dir, "source");
  const sourceData = path.join(sourceRoot, "data");
  fs.mkdirSync(sourceData, { recursive: true });
  const sourcePath = path.join(sourceData, "rootark.sqlite");
  const destinationPath = path.join(dir, "configured.sqlite");
  const sourceDb = makeDatabase(sourcePath, options.sourceValue || "new", { wal: options.sourceWal, keepOpen: options.sourceWal });
  makeDatabase(destinationPath, options.destinationValue || "old", { wal: options.destinationWal });
  process.env.DB_ENABLED = "true";
  process.env.DATABASE_URL = destinationPath;
  const cleanup = () => {
    try { sourceDb?.close(); } catch {}
    fs.rmSync(dir, { recursive: true, force: true });
  };
  return { dir, sourceRoot, sourcePath, destinationPath, cleanup };
}

function readValue(pathname) {
  const database = new Database(pathname, { readonly: true });
  try { return database.prepare("SELECT value FROM proof").get().value; } finally { database.close(); }
}

function artifactNames(fixture) {
  return fs.readdirSync(fixture.dir).filter((name) => /configured\.sqlite\.restore-(stage|rollback)-|configured\.sqlite\.restore-journal/.test(name));
}

function assertOriginalSafe(fixture) {
  assert.equal(readValue(fixture.destinationPath), "old");
  assert.equal(fs.existsSync(restoreService.databaseJournalPath(fixture.destinationPath)), false);
  assert.deepEqual(artifactNames(fixture), []);
}

test("SQLite disaster-recovery meta-remediation matrix", async (t) => {
  const originalEnv = { DB_ENABLED: process.env.DB_ENABLED, DATABASE_URL: process.env.DATABASE_URL };
  const cases = [
    ["01 valid replacement installs", () => {
      const f = makeFixture(); try { assert.equal(restoreService.restoreDatabaseFiles(f.sourceRoot), true); assert.equal(readValue(f.destinationPath), "new"); } finally { f.cleanup(); }
    }],
    ["02 missing source database is a no-op", () => {
      const f = makeFixture(); try { fs.rmSync(f.sourcePath); assert.equal(restoreService.restoreDatabaseFiles(f.sourceRoot), false); assert.equal(readValue(f.destinationPath), "old"); } finally { f.cleanup(); }
    }],
    ["03 disabled database is a no-op", () => {
      const f = makeFixture(); try { process.env.DB_ENABLED = "false"; assert.equal(restoreService.restoreDatabaseFiles(f.sourceRoot), false); assert.equal(readValue(f.destinationPath), "old"); } finally { f.cleanup(); }
    }],
    ["04 corrupt source is rejected before destination mutation", () => {
      const f = makeFixture(); try { fs.writeFileSync(f.sourcePath, "not sqlite"); assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot)); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["05 truncated source is rejected before destination mutation", () => {
      const f = makeFixture(); try { fs.writeFileSync(f.sourcePath, fs.readFileSync(f.sourcePath).subarray(0, 40)); assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot)); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["06 journal path is adjacent to configured database", () => {
      const f = makeFixture(); try { assert.equal(restoreService.databaseJournalPath(f.destinationPath), `${f.destinationPath}.restore-journal.json`); } finally { f.cleanup(); }
    }],
    ["07 journal records exact transaction identity", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "stage.copy.primary", simulateCrash: true })); const journal = JSON.parse(fs.readFileSync(restoreService.databaseJournalPath(f.destinationPath))); assert.match(journal.transactionId, /^[a-f0-9-]{36}$/i); assert.equal(journal.destination, path.resolve(f.destinationPath)); restoreService.recoverDatabaseRestore(f.destinationPath); } finally { f.cleanup(); }
    }],
    ["08 journal records all artifact presence bits", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "stage.copy.primary", simulateCrash: true })); const journal = JSON.parse(fs.readFileSync(restoreService.databaseJournalPath(f.destinationPath))); assert.deepEqual(Object.keys(journal.originalPresent).sort(), ["", "-shm", "-wal"]); assert.equal(journal.originalPresent[""], true); assert.equal(journal.stagedPresent[""], true); restoreService.recoverDatabaseRestore(f.destinationPath); } finally { f.cleanup(); }
    }],
    ["09 journal starts in staged phase", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "stage.copy.primary", simulateCrash: true })); const journal = JSON.parse(fs.readFileSync(restoreService.databaseJournalPath(f.destinationPath))); assert.equal(journal.phase, "staged"); restoreService.recoverDatabaseRestore(f.destinationPath); } finally { f.cleanup(); }
    }],
    ["10 stage copy failure preserves original", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "stage.copy.primary" })); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["11 stage validation failure preserves original", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "stage.validate" })); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["12 original move failure preserves original", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "original.move.primary" })); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["13 replacement move failure restores original", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary" })); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["14 reopen validation failure restores original", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.reopen-validate" })); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["15 numeric first-step injection is recoverable", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: 1 })); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["16 numeric second-step injection is recoverable", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: 2 })); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["17 failure injector receives durable step names", () => {
      const f = makeFixture(); const steps = []; try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failureInjector: (step) => { steps.push(step); if (step === "original.move.primary") throw new Error("stop"); } })); assert.ok(steps.includes("stage.copy.primary")); assert.ok(steps.includes("original.move.primary")); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["18 simulated crash leaves journal for next process", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary", simulateCrash: true })); assert.equal(fs.existsSync(restoreService.databaseJournalPath(f.destinationPath)), true); } finally { try { restoreService.recoverDatabaseRestore(f.destinationPath); } catch {} f.cleanup(); }
    }],
    ["19 interrupted replacement recovers to original", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary", simulateCrash: true })); restoreService.recoverDatabaseRestore(f.destinationPath); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["20 recovery is idempotent after cleanup", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary", simulateCrash: true })); assert.equal(restoreService.recoverDatabaseRestore(f.destinationPath).phase, "rolled_back"); assert.equal(restoreService.recoverDatabaseRestore(f.destinationPath).reason, "no_journal"); assert.equal(readValue(f.destinationPath), "old"); } finally { f.cleanup(); }
    }],
    ["21 committed journal cleanup is safe", () => {
      const f = makeFixture(); try { assert.equal(restoreService.restoreDatabaseFiles(f.sourceRoot), true); const journalPath = restoreService.databaseJournalPath(f.destinationPath); const transactionId = crypto.randomUUID(); const journal = { version: 1, transactionId, destination: path.resolve(f.destinationPath), journalPath, stagePrefix: `${f.destinationPath}.restore-stage-${transactionId}`, rollbackPrefix: `${f.destinationPath}.restore-rollback-${transactionId}`, phase: "committed", originalPresent: { "": true, "-wal": false, "-shm": false }, stagedPresent: { "": true, "-wal": false, "-shm": false }, completedOperations: [] }; fs.writeFileSync(journalPath, JSON.stringify(journal)); assert.equal(restoreService.recoverDatabaseRestore(f.destinationPath).phase, "committed"); assert.equal(readValue(f.destinationPath), "new"); } finally { f.cleanup(); }
    }],
    ["22 malformed journal fails closed", () => {
      const f = makeFixture(); try { fs.writeFileSync(restoreService.databaseJournalPath(f.destinationPath), "{"); assert.throws(() => restoreService.recoverDatabaseRestore(f.destinationPath), /Journal SQLite invalido/); assert.equal(readValue(f.destinationPath), "old"); } finally { f.cleanup(); }
    }],
    ["23 wrong-destination journal fails closed", () => {
      const f = makeFixture(); try { const transactionId = crypto.randomUUID(); fs.writeFileSync(restoreService.databaseJournalPath(f.destinationPath), JSON.stringify({ version: 1, transactionId, destination: `${f.destinationPath}.other`, journalPath: restoreService.databaseJournalPath(f.destinationPath), stagePrefix: `${f.destinationPath}.restore-stage-${transactionId}`, rollbackPrefix: `${f.destinationPath}.restore-rollback-${transactionId}`, completedOperations: [], originalPresent: {}, stagedPresent: {} })); assert.throws(() => restoreService.recoverDatabaseRestore(f.destinationPath), /ambiguo/); assert.equal(readValue(f.destinationPath), "old"); } finally { f.cleanup(); }
    }],
    ["24 unknown journal sidecar fails closed", () => {
      const f = makeFixture(); try { const transactionId = crypto.randomUUID(); fs.writeFileSync(restoreService.databaseJournalPath(f.destinationPath), JSON.stringify({ version: 1, transactionId, destination: path.resolve(f.destinationPath), journalPath: restoreService.databaseJournalPath(f.destinationPath), stagePrefix: `${f.destinationPath}.restore-stage-${transactionId}`, rollbackPrefix: `${f.destinationPath}.restore-rollback-${transactionId}`, phase: "staged", completedOperations: [], originalPresent: { "": true, extra: true }, stagedPresent: { "": true, "-wal": false, "-shm": false } })); assert.throws(() => restoreService.recoverDatabaseRestore(f.destinationPath), /sidecar desconhecido/); assert.equal(readValue(f.destinationPath), "old"); } finally { f.cleanup(); }
    }],
    ["25 incomplete journal fails closed", () => {
      const f = makeFixture(); try { const transactionId = crypto.randomUUID(); fs.writeFileSync(restoreService.databaseJournalPath(f.destinationPath), JSON.stringify({ version: 1, transactionId, destination: path.resolve(f.destinationPath), journalPath: restoreService.databaseJournalPath(f.destinationPath), stagePrefix: `${f.destinationPath}.restore-stage-${transactionId}`, rollbackPrefix: `${f.destinationPath}.restore-rollback-${transactionId}`, phase: "staged", completedOperations: [], originalPresent: { "": true }, stagedPresent: { "": true } })); assert.throws(() => restoreService.recoverDatabaseRestore(f.destinationPath), /incompleto/); assert.equal(readValue(f.destinationPath), "old"); } finally { f.cleanup(); }
    }],
    ["26 absent destination remains absent after pre-mutation failure", () => {
      const f = makeFixture(); try { fs.rmSync(f.destinationPath); assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary" })); assert.equal(fs.existsSync(f.destinationPath), false); } finally { f.cleanup(); }
    }],
    ["27 absent destination receives valid replacement", () => {
      const f = makeFixture(); try { fs.rmSync(f.destinationPath); assert.equal(restoreService.restoreDatabaseFiles(f.sourceRoot), true); assert.equal(readValue(f.destinationPath), "new"); } finally { f.cleanup(); }
    }],
    ["28 source remains byte-for-byte unchanged", () => {
      const f = makeFixture(); try { const before = fs.readFileSync(f.sourcePath); restoreService.restoreDatabaseFiles(f.sourceRoot); assert.deepEqual(fs.readFileSync(f.sourcePath), before); } finally { f.cleanup(); }
    }],
    ["29 original bytes are preserved through failed replacement", () => {
      const f = makeFixture(); try { const before = fs.readFileSync(f.destinationPath); assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary" })); assert.deepEqual(fs.readFileSync(f.destinationPath), before); } finally { f.cleanup(); }
    }],
    ["30 configured path is used instead of runtime default", () => {
      const f = makeFixture(); try { restoreService.restoreDatabaseFiles(f.sourceRoot); assert.equal(readValue(f.destinationPath), "new"); assert.equal(fs.existsSync(path.join(f.dir, "data", "rootark.sqlite")), false); } finally { f.cleanup(); }
    }],
    ["31 no raw failure text is persisted in journal", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary", simulateCrash: true })); const raw = fs.readFileSync(restoreService.databaseJournalPath(f.destinationPath), "utf8"); assert.equal(raw.includes("Error"), false); restoreService.recoverDatabaseRestore(f.destinationPath); } finally { f.cleanup(); }
    }],
    ["32 successful commit leaves no stage artifacts", () => {
      const f = makeFixture(); try { restoreService.restoreDatabaseFiles(f.sourceRoot); assert.deepEqual(artifactNames(f), []); } finally { f.cleanup(); }
    }],
    ["33 successful commit leaves no rollback artifacts", () => {
      const f = makeFixture(); try { restoreService.restoreDatabaseFiles(f.sourceRoot); assert.equal(fs.readdirSync(f.dir).some((name) => name.includes("restore-rollback")), false); } finally { f.cleanup(); }
    }],
    ["34 original WAL and SHM absence is recorded", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "stage.copy.primary", simulateCrash: true })); const journal = JSON.parse(fs.readFileSync(restoreService.databaseJournalPath(f.destinationPath))); assert.equal(journal.originalPresent["-wal"], false); assert.equal(journal.originalPresent["-shm"], false); restoreService.recoverDatabaseRestore(f.destinationPath); } finally { f.cleanup(); }
    }],
    ["35 source WAL fixture validates as a set", () => {
      const f = makeFixture({ sourceWal: true }); try { restoreService.restoreDatabaseFiles(f.sourceRoot); assert.equal(readValue(f.destinationPath), "new"); } finally { f.cleanup(); }
    }],
    ["36 destination WAL fixture is recoverable", () => {
      const f = makeFixture({ destinationWal: true }); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "original.move.primary" })); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["37 destination SHM is not independently resurrected", () => {
      const f = makeFixture(); try { fs.writeFileSync(`${f.destinationPath}-shm`, "stale-shm"); assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary" })); assert.equal(readValue(f.destinationPath), "old"); } finally { f.cleanup(); }
    }],
    ["38 stage validation happens before original move", () => {
      const f = makeFixture(); const steps = []; try { restoreService.restoreDatabaseFiles(f.sourceRoot, { failureInjector: (step) => steps.push(step) }); assert.ok(steps.indexOf("stage.validate") < steps.findIndex((step) => step.startsWith("original.move"))); } finally { f.cleanup(); }
    }],
    ["39 original preservation precedes replacement move", () => {
      const f = makeFixture(); const steps = []; try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failureInjector: (step) => { steps.push(step); if (step === "replacement.move.primary") throw new Error("stop"); } })); assert.ok(steps.indexOf("original.move.primary") < steps.indexOf("replacement.move.primary")); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["40 reopen validation follows replacement installation", () => {
      const f = makeFixture(); const steps = []; try { restoreService.restoreDatabaseFiles(f.sourceRoot, { failureInjector: (step) => steps.push(step) }); assert.ok(steps.indexOf("replacement.move.primary") < steps.indexOf("replacement.reopen-validate")); } finally { f.cleanup(); }
    }],
    ["41 rollback removes replacement before restoring original", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary", simulateCrash: true })); restoreService.recoverDatabaseRestore(f.destinationPath); assert.equal(readValue(f.destinationPath), "old"); } finally { f.cleanup(); }
    }],
    ["42 rollback restores after primary move crash", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "original.move.primary", simulateCrash: true })); restoreService.recoverDatabaseRestore(f.destinationPath); assert.equal(readValue(f.destinationPath), "old"); } finally { f.cleanup(); }
    }],
    ["43 recovery refuses multiple legacy rollback candidates", () => {
      const f = makeFixture(); try { fs.rmSync(f.destinationPath); fs.writeFileSync(`${f.destinationPath}.restore-rollback-a`, "a"); fs.writeFileSync(`${f.destinationPath}.restore-rollback-b`, "b"); assert.throws(() => restoreService.recoverDatabaseRollback(f.destinationPath), /ambiguos/); } finally { f.cleanup(); }
    }],
    ["44 legacy rollback restores primary and sidecar", () => {
      const f = makeFixture(); try { fs.rmSync(f.destinationPath); const legacy = `${f.destinationPath}.restore-rollback-legacy`; fs.copyFileSync(f.sourcePath, legacy); fs.writeFileSync(`${legacy}-wal`, "sidecar"); restoreService.recoverDatabaseRollback(f.destinationPath); assert.equal(fs.existsSync(f.destinationPath), true); assert.equal(fs.readFileSync(`${f.destinationPath}-wal`, "utf8"), "sidecar"); } finally { f.cleanup(); }
    }],
    ["45 missing rollback with moved original fails closed", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "original.move.primary", simulateCrash: true })); const journalPath = restoreService.databaseJournalPath(f.destinationPath); const journal = JSON.parse(fs.readFileSync(journalPath)); fs.rmSync(`${f.destinationPath}.restore-rollback-${journal.transactionId}`, { force: true }); assert.throws(() => restoreService.recoverDatabaseRestore(f.destinationPath), /perdeu o original/); } finally { try { fs.rmSync(restoreService.databaseJournalPath(f.destinationPath), { force: true }); } catch {} f.cleanup(); }
    }],
    ["46 recovery honors transaction destination scope", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary", simulateCrash: true })); const other = path.join(f.dir, "other.sqlite"); fs.copyFileSync(f.destinationPath, other); assert.equal(readValue(other), "new"); restoreService.recoverDatabaseRestore(f.destinationPath); assert.equal(readValue(other), "new"); } finally { f.cleanup(); }
    }],
    ["47 journal timestamps are ISO strings", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "stage.copy.primary", simulateCrash: true })); const journal = JSON.parse(fs.readFileSync(restoreService.databaseJournalPath(f.destinationPath))); assert.doesNotThrow(() => new Date(journal.startedAt).toISOString()); assert.doesNotThrow(() => new Date(journal.updatedAt).toISOString()); restoreService.recoverDatabaseRestore(f.destinationPath); } finally { f.cleanup(); }
    }],
    ["48 journal completed operations are ordered", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary", simulateCrash: true })); const journal = JSON.parse(fs.readFileSync(restoreService.databaseJournalPath(f.destinationPath))); assert.ok(journal.completedOperations.indexOf("stage.copy.primary") < journal.completedOperations.indexOf("original.move.primary")); restoreService.recoverDatabaseRestore(f.destinationPath); } finally { f.cleanup(); }
    }],
    ["49 retry after failed restore succeeds", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary" })); assert.equal(restoreService.restoreDatabaseFiles(f.sourceRoot), true); assert.equal(readValue(f.destinationPath), "new"); } finally { f.cleanup(); }
    }],
    ["interrupted SQLite journal update preserves the prior recovery journal", () => {
      const f = makeFixture();
      const journalPath = restoreService.databaseJournalPath(f.destinationPath);
      const originalWriteFileSync = fs.writeFileSync;
      let temporaryWrites = 0;
      let abandonedTemporary;
      fs.writeFileSync = function interruptJournalUpdate(pathname, data, options) {
        const candidate = path.resolve(String(pathname));
        if (candidate.startsWith(`${path.resolve(journalPath)}.`) && candidate.endsWith(".tmp") && ++temporaryWrites === 2) {
          abandonedTemporary = candidate;
          originalWriteFileSync.call(this, pathname, String(data).slice(0, 12), options);
          throw Object.assign(new Error("injected interrupted journal update"), { code: "EIO" });
        }
        return originalWriteFileSync.call(this, pathname, data, options);
      };
      try {
        assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { simulateCrash: true }), /interrupted journal update/);
      } finally { fs.writeFileSync = originalWriteFileSync; }
      try {
        assert.ok(abandonedTemporary, "the interrupted update leaves only its unique temporary journal");
        assert.doesNotThrow(() => JSON.parse(fs.readFileSync(journalPath, "utf8")), "the previously committed recovery journal must remain intact");
        originalWriteFileSync(abandonedTemporary, "partial abandoned journal", { flag: "wx" });
        const recoveryWrites = [];
        fs.writeFileSync = function recordRecoveryJournalWrites(pathname, data, options) {
          if (path.resolve(String(pathname)).startsWith(`${path.resolve(journalPath)}.`) && String(pathname).endsWith(".tmp")) {
            recoveryWrites.push({ pathname: path.resolve(String(pathname)), flag: options?.flag });
          }
          return originalWriteFileSync.call(this, pathname, data, options);
        };
        assert.doesNotThrow(() => restoreService.recoverDatabaseRestore(f.destinationPath));
        assert.ok(recoveryWrites.length > 0);
        assert.ok(recoveryWrites.every((entry) => entry.pathname !== abandonedTemporary && entry.flag === "wx"), "recovery must use fresh exclusive journal temporaries");
        assert.equal(fs.readFileSync(abandonedTemporary, "utf8"), "partial abandoned journal", "restart recovery must not reuse an abandoned temporary");
        assert.equal(readValue(f.destinationPath), "old");
        assert.equal(fs.existsSync(journalPath), false);
        fs.rmSync(abandonedTemporary, { force: true });
        assert.deepEqual(artifactNames(f), []);
      } finally { fs.writeFileSync = originalWriteFileSync; f.cleanup(); }
    }],
    ["directory fsync EIO fails restore closed and permits later recovery", (t) => {
      if (process.platform === "win32") return t.skip("Node does not expose portable directory fsync on Windows");
      const f = makeFixture();
      const originalFsyncSync = fs.fsyncSync;
      fs.fsyncSync = function failDirectorySync(fd) {
        if (fs.fstatSync(fd).isDirectory()) throw Object.assign(new Error("injected directory fsync failure"), { code: "EIO" });
        return originalFsyncSync.call(this, fd);
      };
      try {
        assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot), { code: "EIO" });
        assert.equal(readValue(f.destinationPath), "old", "failed directory durability must not replace the original database");
      } finally { fs.fsyncSync = originalFsyncSync; }
      try {
        restoreService.recoverDatabaseRestore(f.destinationPath);
        assertOriginalSafe(f);
      } finally { f.cleanup(); }
    }],
    ["50 retry after crash recovery succeeds", () => {
      const f = makeFixture(); try { assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot, { failAt: "replacement.move.primary", simulateCrash: true })); restoreService.recoverDatabaseRestore(f.destinationPath); assert.equal(restoreService.restoreDatabaseFiles(f.sourceRoot), true); assert.equal(readValue(f.destinationPath), "new"); } finally { f.cleanup(); }
    }],
    ["51 foreign-key corruption is rejected", () => {
      const f = makeFixture(); try { const db = new Database(f.sourcePath); db.exec("DROP TABLE proof; CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(parent_id INTEGER REFERENCES parent(id)); PRAGMA foreign_keys = OFF; INSERT INTO child VALUES (99);"); db.close(); assert.throws(() => restoreService.restoreDatabaseFiles(f.sourceRoot)); assertOriginalSafe(f); } finally { f.cleanup(); }
    }],
    ["52 all replacement artifacts are validated after restore", () => {
      const f = makeFixture(); try { restoreService.restoreDatabaseFiles(f.sourceRoot); assert.doesNotThrow(() => restoreService.validateDatabase(f.destinationPath)); assert.equal(fs.existsSync(`${f.destinationPath}-wal`), false); assert.equal(fs.existsSync(`${f.destinationPath}-shm`), false); } finally { f.cleanup(); }
    }],
  ];

  try {
    for (const [name, body] of cases) await t.test(name, body);
  } finally {
    if (originalEnv.DB_ENABLED === undefined) delete process.env.DB_ENABLED; else process.env.DB_ENABLED = originalEnv.DB_ENABLED;
    if (originalEnv.DATABASE_URL === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = originalEnv.DATABASE_URL;
  }
  assert.equal(cases.length, 54);
});
