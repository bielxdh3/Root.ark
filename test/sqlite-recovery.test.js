const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const test = require("node:test");
require("./isolated-runtime")(test, "rootark-sqlite-recovery-runtime-");
const {
  validateDatabase,
  recoverDatabaseRollback,
  recoverDatabaseRestore,
  databaseJournalPath,
  restoreDatabaseFiles,
} = require("../services/restoreService");

test("SQLite restore staging validates and recovers safely", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-sqlite-recovery-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const valid = path.join(dir, "valid.sqlite");
  const db = new Database(valid); db.exec("PRAGMA foreign_keys = ON; CREATE TABLE proof (id INTEGER PRIMARY KEY, value TEXT); INSERT INTO proof(value) VALUES ('ok');"); db.close();
  await t.test("valid database passes integrity", () => assert.doesNotThrow(() => validateDatabase(valid)));
  const corrupt = path.join(dir, "corrupt.sqlite"); fs.writeFileSync(corrupt, "not sqlite");
  await t.test("corrupt database is rejected", () => assert.throws(() => validateDatabase(corrupt)));
  const truncated = path.join(dir, "truncated.sqlite"); fs.writeFileSync(truncated, fs.readFileSync(valid).subarray(0, 100));
  await t.test("truncated database is rejected", () => assert.throws(() => validateDatabase(truncated)));
  const destination = path.join(dir, "configured.sqlite");
  const rollback = `${destination}.restore-rollback-${crypto.randomUUID()}`; fs.copyFileSync(valid, rollback);
  recoverDatabaseRollback(destination);
  await t.test("interrupted primary is restored", () => assert.doesNotThrow(() => validateDatabase(destination)));
  await t.test("interrupted primary retains its committed row", () => {
    const recovered = new Database(destination, { readonly: true });
    try { assert.equal(recovered.prepare("SELECT value FROM proof").get().value, "ok"); }
    finally { recovered.close(); }
  });
  await t.test("legacy SQLite rollback without a journal preserves a WAL-bearing candidate for manual recovery", () => {
    const walSource = path.join(dir, "wal-rollback-source.sqlite");
    const walDatabase = new Database(walSource);
    const walDestination = path.join(dir, "wal-configured.sqlite");
    const walRollback = `${walDestination}.restore-rollback-${crypto.randomUUID()}`;
    try {
      walDatabase.pragma("journal_mode = WAL");
      walDatabase.pragma("wal_autocheckpoint = 0");
      walDatabase.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof(value) VALUES ('wal-recovered');");
      assert.equal(fs.existsSync(`${walSource}-wal`), true, "the fixture keeps committed bytes in its WAL");
      fs.copyFileSync(walSource, walRollback);
      fs.copyFileSync(`${walSource}-wal`, `${walRollback}-wal`);
      const walBytes = fs.readFileSync(`${walRollback}-wal`);

      assert.throws(() => recoverDatabaseRollback(walDestination), /sidecar provenance|manual recovery/i);
      assert.equal(fs.existsSync(walDestination), false, "recovery leaves a WAL-bearing orphan uninstalled without a journal");
      assert.equal(fs.existsSync(walRollback), true, "the orphan primary remains available for manual recovery");
      assert.deepEqual(fs.readFileSync(`${walRollback}-wal`), walBytes, "the WAL remains untouched for manual recovery");
    } finally {
      walDatabase.close();
    }
  });
  await t.test("legacy rollback rejects a destination WAL with unproven database provenance", () => {
    const primarySource = path.join(dir, "split-wal-primary-source.sqlite");
    const primaryDatabase = new Database(primarySource);
    const otherWalSource = path.join(dir, "split-wal-other-source.sqlite");
    const otherWalDatabase = new Database(otherWalSource);
    const walDestination = path.join(dir, "split-wal-configured.sqlite");
    const walRollback = `${walDestination}.restore-rollback-${crypto.randomUUID()}`;
    try {
      primaryDatabase.pragma("journal_mode = WAL");
      primaryDatabase.pragma("wal_autocheckpoint = 0");
      primaryDatabase.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof(value) VALUES ('orphan-primary');");
      otherWalDatabase.pragma("journal_mode = WAL");
      otherWalDatabase.pragma("wal_autocheckpoint = 0");
      otherWalDatabase.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof(value) VALUES ('unrelated-wal');");
      assert.equal(fs.existsSync(`${otherWalSource}-wal`), true, "the fixture keeps a valid WAL from another database");
      fs.copyFileSync(primarySource, walRollback);
      fs.copyFileSync(`${otherWalSource}-wal`, `${walDestination}-wal`);
      const mismatchedWalBytes = fs.readFileSync(`${walDestination}-wal`);

      assert.throws(() => recoverDatabaseRollback(walDestination), /sidecar provenance|ambiguous|manual recovery/i);
      assert.equal(fs.existsSync(walDestination), false, "recovery does not install a database with an unrelated WAL");
      assert.equal(fs.existsSync(walRollback), true, "the orphan primary remains available for manual recovery");
      assert.deepEqual(fs.readFileSync(`${walDestination}-wal`), mismatchedWalBytes, "the unrelated WAL is preserved untouched");
    } finally {
      primaryDatabase.close();
      otherWalDatabase.close();
    }
  });
  await t.test("legacy rollback rejects a stale destination SHM without journal provenance", () => {
    const shmDestination = path.join(dir, "stale-shm-configured.sqlite");
    const shmRollback = `${shmDestination}.restore-rollback-${crypto.randomUUID()}`;
    const staleShmPath = `${shmDestination}-shm`;
    const staleShm = Buffer.from("stale or corrupt transient WAL index");
    fs.copyFileSync(valid, shmRollback);
    fs.writeFileSync(staleShmPath, staleShm);

    assert.throws(() => recoverDatabaseRollback(shmDestination), /sidecar provenance|ambiguous|manual recovery/i);
    assert.equal(fs.existsSync(shmDestination), false, "recovery does not install an unvalidated database sidecar set");
    assert.equal(fs.existsSync(shmRollback), true, "the valid orphan primary is preserved for manual recovery");
    assert.deepEqual(fs.readFileSync(staleShmPath), staleShm, "the stale SHM is preserved untouched");
  });
  await t.test("legacy rollback rejects a valid foreign WAL beside the orphan primary", () => {
    const primarySource = path.join(dir, "rollback-wal-primary-source.sqlite");
    const primaryDatabase = new Database(primarySource);
    const foreignWalSource = path.join(dir, "rollback-wal-foreign-source.sqlite");
    const foreignWalDatabase = new Database(foreignWalSource);
    const destination = path.join(dir, "rollback-wal-provenance-configured.sqlite");
    const rollback = `${destination}.restore-rollback-${crypto.randomUUID()}`;
    const rollbackWal = `${rollback}-wal`;
    try {
      primaryDatabase.pragma("journal_mode = WAL");
      primaryDatabase.pragma("wal_autocheckpoint = 0");
      primaryDatabase.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof(value) VALUES ('orphan-primary');");
      foreignWalDatabase.pragma("journal_mode = WAL");
      foreignWalDatabase.pragma("wal_autocheckpoint = 0");
      foreignWalDatabase.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof(value) VALUES ('foreign-wal');");
      assert.equal(fs.existsSync(`${primarySource}-wal`), true);
      assert.equal(fs.existsSync(`${foreignWalSource}-wal`), true);
      fs.copyFileSync(primarySource, rollback);
      fs.copyFileSync(`${primarySource}-wal`, rollbackWal);
      fs.copyFileSync(`${foreignWalSource}-wal`, rollbackWal);
      const foreignWalBytes = fs.readFileSync(rollbackWal);

      assert.throws(() => recoverDatabaseRollback(destination), /sidecar provenance|ambiguous|manual recovery/i);
      assert.equal(fs.existsSync(destination), false, "recovery does not commit a database with an unproven WAL");
      assert.equal(fs.existsSync(rollback), true, "the orphan primary remains available for manual recovery");
      assert.deepEqual(fs.readFileSync(rollbackWal), foreignWalBytes, "the WAL with unproven provenance remains untouched");
    } finally {
      primaryDatabase.close();
      foreignWalDatabase.close();
    }
  });
  await t.test("legacy rollback rechecks sidecars before publishing its recovery journal", () => {
    const destination = path.join(dir, "late-wal-configured.sqlite");
    const rollback = `${destination}.restore-rollback-${crypto.randomUUID()}`;
    const lateWalPath = `${destination}-wal`;
    const lateWal = Buffer.from("WAL created after fallback validation");
    fs.copyFileSync(valid, rollback);

    assert.throws(() => recoverDatabaseRollback(destination, {
      failureInjector(step) {
        if (step === "legacy.rollback.before-journal") fs.writeFileSync(lateWalPath, lateWal);
      },
    }), /sidecar provenance changed|manual recovery/i);
    assert.equal(fs.existsSync(destination), false, "the fallback does not install a primary after a sidecar appears");
    assert.equal(fs.existsSync(rollback), true, "the orphan primary remains available for manual recovery");
    assert.equal(fs.existsSync(databaseJournalPath(destination)), false, "the fallback does not publish a journal for a changed artifact set");
    assert.deepEqual(fs.readFileSync(lateWalPath), lateWal, "the newly created sidecar is preserved untouched");
  });
  await t.test("journaled SQLite rollback resumes after each WAL and SHM rename", () => {
    const originalDbEnabled = process.env.DB_ENABLED;
    const originalDatabaseUrl = process.env.DATABASE_URL;
    for (const failAt of ["rollback.restore-wal", "rollback.restore-shm"]) {
      const originalSource = path.join(dir, `restart-${failAt.replaceAll(".", "-")}-original.sqlite`);
      const originalDatabase = new Database(originalSource);
      const destination = path.join(dir, `restart-${failAt.replaceAll(".", "-")}-configured.sqlite`);
      const replacementRoot = path.join(dir, `restart-${failAt.replaceAll(".", "-")}-replacement`);
      const replacementPath = path.join(replacementRoot, "data", "rootark.sqlite");
      const journalPath = databaseJournalPath(destination);
      try {
        originalDatabase.pragma("journal_mode = WAL");
        originalDatabase.pragma("wal_autocheckpoint = 0");
        originalDatabase.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof(value) VALUES ('restart-original');");
        assert.equal(fs.existsSync(`${originalSource}-wal`), true, "the fixture keeps committed bytes in its WAL");
        assert.equal(fs.existsSync(`${originalSource}-shm`), true, "the open fixture has its transient WAL index");
        const walBytes = fs.readFileSync(`${originalSource}-wal`);
        const shmBytes = fs.readFileSync(`${originalSource}-shm`);
        fs.copyFileSync(originalSource, destination);
        fs.copyFileSync(`${originalSource}-wal`, `${destination}-wal`);
        fs.copyFileSync(`${originalSource}-shm`, `${destination}-shm`);
        originalDatabase.close();

        fs.mkdirSync(path.dirname(replacementPath), { recursive: true });
        const replacementDatabase = new Database(replacementPath);
        replacementDatabase.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof(value) VALUES ('replacement');");
        replacementDatabase.close();
        process.env.DB_ENABLED = "true";
        process.env.DATABASE_URL = destination;

        assert.throws(() => restoreDatabaseFiles(replacementRoot, { failAt: "replacement.move.primary", simulateCrash: true }), /Falha injetada/);
        assert.throws(() => recoverDatabaseRestore(destination, { failAt }), /Falha injetada/);
        assert.equal(fs.existsSync(journalPath), true, "the durable rollback journal remains after interruption");
        const interruptedSuffix = failAt.slice("rollback.restore".length);
        const interruptedSidecarBytes = interruptedSuffix === "-wal" ? walBytes : shmBytes;
        const interruptedJournal = JSON.parse(fs.readFileSync(journalPath, "utf8"));
        assert.ok(interruptedJournal.completedOperations.includes(failAt), "the journal records the completed sidecar rename before interruption");
        assert.deepEqual(fs.readFileSync(`${destination}${interruptedSuffix}`), interruptedSidecarBytes,
          "the injected interruption occurs after the sidecar reached its destination");
        assert.equal(fs.existsSync(`${interruptedJournal.rollbackPrefix}${interruptedSuffix}`), false,
          "the moved sidecar is no longer present at the rollback path before restart");

        assert.equal(recoverDatabaseRestore(destination).phase, "rolled_back");
        assert.deepEqual(fs.readFileSync(`${destination}-wal`), walBytes, "restart preserves the original WAL sidecar");
        assert.deepEqual(fs.readFileSync(`${destination}-shm`), shmBytes, "restart preserves the original SHM sidecar");
        assert.equal(fs.existsSync(journalPath), false, "successful restart recovery removes its journal");
        const recovered = new Database(destination, { readonly: true });
        try { assert.equal(recovered.prepare("SELECT value FROM proof").get().value, "restart-original"); }
        finally { recovered.close(); }
      } finally {
        try { fs.rmSync(journalPath, { force: true }); } catch {}
        if (originalDatabase.open) originalDatabase.close();
        if (originalDbEnabled === undefined) delete process.env.DB_ENABLED; else process.env.DB_ENABLED = originalDbEnabled;
        if (originalDatabaseUrl === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = originalDatabaseUrl;
      }
    }
  });
  await t.test("existing destination is never replaced by recovery", () => {
    const preserve = path.join(dir, "preserve.sqlite"); fs.copyFileSync(valid, preserve); fs.writeFileSync(`${preserve}.restore-rollback-stale`, "old");
    recoverDatabaseRollback(preserve); assert.doesNotThrow(() => validateDatabase(preserve)); assert.equal(fs.existsSync(`${preserve}.restore-rollback-stale`), true);
  });
  await t.test("WAL database validates while its connection is open", () => {
    const walPath = path.join(dir, "wal.sqlite"); const wal = new Database(walPath); wal.pragma("journal_mode = WAL"); wal.exec("CREATE TABLE proof (value TEXT); INSERT INTO proof VALUES ('wal');");
    assert.equal(fs.existsSync(`${walPath}-wal`), true); assert.doesNotThrow(() => validateDatabase(walPath)); wal.close();
  });
  await t.test("reopen preserves exact committed rows", () => {
    const reopened = new Database(valid, { readonly: true }); assert.equal(reopened.prepare("SELECT value FROM proof").get().value, "ok"); reopened.close();
  });
  await t.test("foreign-key violations are rejected", () => {
    const foreign = path.join(dir, "foreign.sqlite"); const broken = new Database(foreign); broken.exec("PRAGMA foreign_keys = OFF; CREATE TABLE parent (id INTEGER PRIMARY KEY); CREATE TABLE child (parent_id INTEGER REFERENCES parent(id)); INSERT INTO child VALUES (1);"); broken.close();
    assert.throws(() => validateDatabase(foreign));
  });
  await t.test("missing rollback is a no-op", () => {
    const missing = path.join(dir, "missing.sqlite"); assert.doesNotThrow(() => recoverDatabaseRollback(missing)); assert.equal(fs.existsSync(missing), false);
  });
});
