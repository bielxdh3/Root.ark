const fs = require("fs");
const { getDatabasePath, getDb, nowIso } = require("./index");
const { backupDatabase } = require("./backup");

const MIGRATIONS = [
  {
    version: 1,
    name: "initial_sqlite_schema",
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
          version INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          applied_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL,
          permissions_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          deleted_at TEXT
        );

        CREATE TABLE IF NOT EXISTS folders (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          created_by TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          allowed_users_json TEXT NOT NULL DEFAULT '[]',
          is_root INTEGER NOT NULL DEFAULT 0,
          expires_at TEXT,
          deleted_at TEXT
        );

        CREATE TABLE IF NOT EXISTS pending_uploads (
          id TEXT PRIMARY KEY,
          file_name TEXT NOT NULL,
          original_name TEXT,
          folder_id TEXT NOT NULL,
          uploaded_by TEXT,
          uploaded_at TEXT,
          size INTEGER NOT NULL DEFAULT 0,
          metadata_json TEXT NOT NULL DEFAULT '{}',
          FOREIGN KEY(folder_id) REFERENCES folders(id)
        );

        CREATE TABLE IF NOT EXISTS public_links (
          token TEXT PRIMARY KEY,
          folder_id TEXT NOT NULL,
          file_name TEXT NOT NULL,
          created_by TEXT,
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          max_views INTEGER NOT NULL DEFAULT 0,
          views INTEGER NOT NULL DEFAULT 0,
          password_hash TEXT,
          metadata_json TEXT NOT NULL DEFAULT '{}',
          revoked_at TEXT,
          FOREIGN KEY(folder_id) REFERENCES folders(id)
        );

        CREATE TABLE IF NOT EXISTS actions_history (
          id TEXT PRIMARY KEY,
          action_type TEXT NOT NULL,
          username TEXT,
          folder_id TEXT,
          file_name TEXT,
          timestamp TEXT NOT NULL,
          details_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS file_permissions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          folder_id TEXT NOT NULL,
          file_name TEXT NOT NULL,
          allowed_users_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(folder_id, file_name),
          FOREIGN KEY(folder_id) REFERENCES folders(id)
        );

        CREATE TABLE IF NOT EXISTS file_expirations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          folder_id TEXT NOT NULL,
          file_name TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          created_by TEXT,
          created_at TEXT NOT NULL,
          UNIQUE(folder_id, file_name),
          FOREIGN KEY(folder_id) REFERENCES folders(id)
        );

        CREATE TABLE IF NOT EXISTS file_versions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          folder_id TEXT NOT NULL,
          file_name TEXT NOT NULL,
          versions_json TEXT NOT NULL DEFAULT '{}',
          updated_at TEXT NOT NULL,
          UNIQUE(folder_id, file_name),
          FOREIGN KEY(folder_id) REFERENCES folders(id)
        );

        CREATE TABLE IF NOT EXISTS encrypted_files (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          folder_id TEXT NOT NULL,
          file_name TEXT NOT NULL,
          encryption_level TEXT NOT NULL,
          metadata_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(folder_id, file_name),
          FOREIGN KEY(folder_id) REFERENCES folders(id)
        );

        CREATE TABLE IF NOT EXISTS analytics_events (
          id TEXT PRIMARY KEY,
          event_type TEXT NOT NULL,
          username TEXT,
          folder_id TEXT,
          folder_name TEXT,
          file_name TEXT,
          size INTEGER NOT NULL DEFAULT 0,
          timestamp TEXT NOT NULL,
          details_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
          id TEXT PRIMARY KEY,
          event_type TEXT NOT NULL,
          severity TEXT NOT NULL,
          actor_username TEXT,
          actor_ip TEXT,
          target_type TEXT,
          target_id TEXT,
          action TEXT,
          result TEXT,
          timestamp TEXT NOT NULL,
          details_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_folders_id ON folders(id);
        CREATE INDEX IF NOT EXISTS idx_file_permissions_file ON file_permissions(folder_id, file_name);
        CREATE INDEX IF NOT EXISTS idx_file_expirations_expires ON file_expirations(expires_at);
        CREATE INDEX IF NOT EXISTS idx_public_links_token ON public_links(token);
        CREATE INDEX IF NOT EXISTS idx_public_links_file ON public_links(folder_id, file_name);
        CREATE INDEX IF NOT EXISTS idx_analytics_event_type ON analytics_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON analytics_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_analytics_username ON analytics_events(username);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_logs(event_type);
        CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_logs(severity);
        CREATE INDEX IF NOT EXISTS idx_audit_actor_username ON audit_logs(actor_username);
        CREATE INDEX IF NOT EXISTS idx_actions_history_timestamp ON actions_history(timestamp);
      `);
    },
  },
  {
    version: 2,
    name: "backup_history",
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS backup_history (
          id TEXT PRIMARY KEY,
          filename TEXT NOT NULL,
          type TEXT NOT NULL,
          status TEXT NOT NULL,
          created_by TEXT,
          created_at TEXT NOT NULL,
          finished_at TEXT,
          size_bytes INTEGER NOT NULL DEFAULT 0,
          checksum TEXT,
          error_message TEXT,
          metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_backup_history_created_at ON backup_history(created_at);
        CREATE INDEX IF NOT EXISTS idx_backup_history_status ON backup_history(status);
      `);
    },
  },
  {
    version: 3,
    name: "trash_items",
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS trash_items (
          id TEXT PRIMARY KEY,
          item_type TEXT NOT NULL,
          original_folder_id TEXT,
          original_folder_name TEXT,
          original_file_name TEXT,
          stored_file_name TEXT,
          original_path TEXT,
          trash_path TEXT,
          deleted_by TEXT,
          deleted_at TEXT NOT NULL,
          size_bytes INTEGER NOT NULL DEFAULT 0,
          metadata_json TEXT NOT NULL DEFAULT '{}',
          restore_metadata_json TEXT NOT NULL DEFAULT '{}',
          status TEXT NOT NULL DEFAULT 'trashed',
          restored_by TEXT,
          restored_at TEXT,
          permanently_deleted_by TEXT,
          permanently_deleted_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_trash_status ON trash_items(status);
        CREATE INDEX IF NOT EXISTS idx_trash_deleted_at ON trash_items(deleted_at);
        CREATE INDEX IF NOT EXISTS idx_trash_deleted_by ON trash_items(deleted_by);
        CREATE INDEX IF NOT EXISTS idx_trash_original_file ON trash_items(original_folder_id, original_file_name);
      `);
    },
  },
  {
    version: 4,
    name: "user_session_versions",
    up(db) {
      db.exec("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0; ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;");
    },
  },
  {
    version: 5,
    name: "user_totp_security",
    up(db) {
      db.exec(`
        ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE users ADD COLUMN totp_secret_json TEXT;
        ALTER TABLE users ADD COLUMN totp_pending_secret_json TEXT;
        ALTER TABLE users ADD COLUMN totp_recovery_hashes_json TEXT NOT NULL DEFAULT '[]';
        ALTER TABLE users ADD COLUMN totp_last_used_step INTEGER;
        ALTER TABLE users ADD COLUMN totp_enrolled_at TEXT;
      `);
    },
  },
  {
    version: 6,
    name: "file_search_fts",
    up(db) {
      // Non-protected file names only. Encrypted/protected names are never inserted by the repository.
      // Trigram tokenizer gives substring candidates (same semantics as the existing includes() search).
      db.exec(`
        CREATE VIRTUAL TABLE IF NOT EXISTS file_search_index USING fts5(
          folder_id UNINDEXED,
          file_name,
          tokenize = 'trigram case_sensitive 0'
        );
      `);
    },
  },
  {
    version: 7,
    name: "public_link_permissions",
    up(db) {
      db.exec("ALTER TABLE public_links ADD COLUMN permissions_json TEXT;");
    },
  },
];

function ensureMigrationTable(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL
    )
  `);
}

function runMigrations(options = {}) {
  const databasePath = getDatabasePath();
  const databaseExists = fs.existsSync(databasePath);

  if (databaseExists && options.backup !== false) {
    backupDatabase({ databasePath });
  }

  const db = getDb();
  ensureMigrationTable(db);
  const applied = new Set(db.prepare("SELECT version FROM schema_migrations").all().map((row) => row.version));
  const pending = MIGRATIONS.filter((migration) => !applied.has(migration.version));

  for (const migration of pending) {
    const apply = db.transaction(() => {
      migration.up(db);
      db.prepare("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)")
        .run(migration.version, migration.name, nowIso());
    });
    apply();
    console.log(`Migration aplicada: ${migration.version} - ${migration.name}`);
  }

  if (!pending.length) {
    console.log("SQLite: nenhuma migration pendente.");
  }

  return { applied: pending.map((migration) => migration.version), databasePath };
}

if (require.main === module) {
  runMigrations();
}

module.exports = {
  MIGRATIONS,
  runMigrations,
};
