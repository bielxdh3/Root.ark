const fs = require("node:fs");
const path = require("node:path");
const BetterSqlite3 = require("better-sqlite3");

const BUSY_TIMEOUT_MS = 3000;
const TABLE = "upload_chunk_rate_hits";

function assertSafeDirectory(directory) {
  let stats;
  try {
    stats = fs.lstatSync(directory);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (stats.isSymbolicLink() || !stats.isDirectory()) throw new Error("Unsafe rate-limit store directory");
}

// Mirrors ensureSafeSidecarFile in services/chunkUploadQuota.js: regular files only, no hard links.
function assertSafeSqliteFile(filePath) {
  let stats;
  try {
    stats = fs.lstatSync(filePath);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (stats.isSymbolicLink() || !stats.isFile() || stats.nlink !== 1) throw new Error("Unsafe rate-limit SQLite file");
}

// Host-shared sliding-window store for express-rate-limit. Every process on one host that opens the
// same database file shares the counts. It is not a multi-host store.
class SqliteSlidingWindowStore {
  constructor(databasePath, windowMs, limit, { Database = BetterSqlite3 } = {}) {
    this.databasePath = path.resolve(databasePath);
    this.windowMs = windowMs;
    this.limit = limit;
    this.Database = Database;
    this.database = null;
    this.statements = null;
    this.localKeys = true;
    this.prefix = "upload-chunk";
    this.cleanupTimer = setInterval(() => {
      try {
        this.sweep(Date.now());
      } catch {
        // The next request surfaces storage errors; the sweeper must not crash the process.
      }
    }, Math.min(windowMs, 60 * 1000));
    this.cleanupTimer.unref?.();
  }

  open() {
    if (this.database) return this.database;
    const directory = path.dirname(this.databasePath);
    fs.mkdirSync(directory, { recursive: true });
    assertSafeDirectory(directory);
    for (const filePath of [this.databasePath, `${this.databasePath}-wal`, `${this.databasePath}-shm`]) {
      assertSafeSqliteFile(filePath);
    }

    const database = new this.Database(this.databasePath, { timeout: BUSY_TIMEOUT_MS });
    try {
      database.pragma(`busy_timeout = ${BUSY_TIMEOUT_MS}`);
      if (database.pragma("journal_mode = WAL", { simple: true }) !== "wal") {
        throw new Error("Unable to enable WAL for rate-limit store");
      }
      database.pragma("synchronous = FULL");
      database.exec(`
        CREATE TABLE IF NOT EXISTS ${TABLE} (
          key TEXT NOT NULL,
          hit_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ${TABLE}_key_hit ON ${TABLE} (key, hit_at);
        CREATE INDEX IF NOT EXISTS ${TABLE}_hit ON ${TABLE} (hit_at);
      `);
      this.statements = {
        prune: database.prepare(`DELETE FROM ${TABLE} WHERE key = ? AND hit_at <= ?`),
        count: database.prepare(`SELECT COUNT(*) AS count, MIN(hit_at) AS oldest FROM ${TABLE} WHERE key = ?`),
        insert: database.prepare(`INSERT INTO ${TABLE} (key, hit_at) VALUES (?, ?)`),
        deleteLatest: database.prepare(
          `DELETE FROM ${TABLE} WHERE rowid = (SELECT rowid FROM ${TABLE} WHERE key = ? ORDER BY hit_at DESC, rowid DESC LIMIT 1)`,
        ),
        deleteKey: database.prepare(`DELETE FROM ${TABLE} WHERE key = ?`),
        deleteAll: database.prepare(`DELETE FROM ${TABLE}`),
        sweep: database.prepare(`DELETE FROM ${TABLE} WHERE hit_at <= ?`),
      };
    } catch (error) {
      database.close();
      throw error;
    }
    this.database = database;
    return database;
  }

  // Every state change runs in BEGIN IMMEDIATE so concurrent processes serialize on the write lock.
  write(work) {
    return this.open().transaction(work).immediate();
  }

  pruneKey(account, now) {
    this.statements.prune.run(account, now - this.windowMs);
  }

  increment(account) {
    return this.write(() => {
      const now = Date.now();
      this.pruneKey(account, now);
      const { count, oldest } = this.statements.count.get(account);
      if (count >= this.limit) {
        return { totalHits: this.limit + 1, resetTime: new Date(oldest + this.windowMs) };
      }
      this.statements.insert.run(account, now);
      const first = oldest === null ? now : Math.min(oldest, now);
      return { totalHits: count + 1, resetTime: new Date(first + this.windowMs) };
    });
  }

  decrement(account) {
    this.write(() => {
      this.pruneKey(account, Date.now());
      this.statements.deleteLatest.run(account);
    });
  }

  get(account) {
    return this.write(() => {
      this.pruneKey(account, Date.now());
      const { count, oldest } = this.statements.count.get(account);
      return count ? { totalHits: count, resetTime: new Date(oldest + this.windowMs) } : undefined;
    });
  }

  resetKey(account) {
    this.write(() => this.statements.deleteKey.run(account));
  }

  resetAll() {
    this.write(() => this.statements.deleteAll.run());
  }

  sweep(now) {
    if (!this.database) return;
    this.write(() => this.statements.sweep.run(now - this.windowMs));
  }

  shutdown() {
    clearInterval(this.cleanupTimer);
    if (this.database) this.database.close();
    this.database = null;
    this.statements = null;
  }
}

module.exports = SqliteSlidingWindowStore;
