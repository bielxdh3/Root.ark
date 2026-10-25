"use strict";

// Deliberately opt-in and observational. PROVEN means the named bytes or
// bounded local join were read and checked; it NEVER means whole-corpus
// completeness, backup restorability, provider durability or deletion safety.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const zlib = require("node:zlib");
const { DatabaseSync } = require("node:sqlite");
const unzipper = require("unzipper");
const { inspectZk1LiveLegacyZipReferenceEvidence } =
  require("./zk1LiveLegacyZipReferenceEvidence");

const SCHEMA = "rootark-zk1-legacy-evidence-manifest/v1";
const MAX_FILES = 5000;
const MAX_BYTES = 128 * 1024 * 1024;
const MAX_FILE = 32 * 1024 * 1024;
const MAX_ROWS = 5000;
const MAX_JSON = 256 * 1024;
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const id = (kind, name) => sha(SCHEMA + "\0" + kind + "\0" + name);
const unknown = (count = 0) => ({ status: "UNKNOWN", count });
const proven = (count) => ({ status: "PROVEN", count });
const safePart = (name) => typeof name === "string" && name.length > 0 && name.length <= 255
  && name !== "." && name !== ".." && !name.endsWith(".") && !name.endsWith(" ")
  && !/[\\/\x00-\x1f<>:"|?*]/.test(name);
const stable = (a, b) => a.dev === b.dev && a.ino === b.ino
  && a.nlink === b.nlink && a.size === b.size
  && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
function directory(target) {
  const stat = fs.lstatSync(target, { bigint: true });
  const real = fs.realpathSync.native(target);
  const normalize = (s) => process.platform === "win32" ? s.toLowerCase() : s;
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || normalize(real) !== normalize(path.resolve(target))) throw Error("unsafe directory");
  return stat;
}
function fileBytes(target, budget) {
  const before = fs.lstatSync(target, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
    || before.size > BigInt(MAX_FILE) || before.size > BigInt(budget.left))
    throw Error("unsafe file");
  let fd;
  try {
    fd = fs.openSync(target, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    if (!stable(before, fs.fstatSync(fd, { bigint: true }))) throw Error("race opening");
    // readFileSync(fd) may continue allocating as a concurrent writer grows
    // the file past the size we validated. Read at most the initial size.
    const content = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < content.length) {
      const length = Math.min(16 * 1024, content.length - offset);
      const count = fs.readSync(fd, content, offset, length, null);
      if (count <= 0 || count > length) throw Error("short or invalid read");
      offset += count;
    }
    if (!stable(before, fs.fstatSync(fd, { bigint: true }))
      || !stable(before, fs.lstatSync(target, { bigint: true })))
      throw Error("race reading");
    budget.left -= content.length;
    return content;
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function tree(root, source) {
  if (typeof root !== "string" || !path.isAbsolute(root)) return { section: unknown(), entries: [], lookup: new Map() };
  const snapshots = [], dirs = [], entries = [], lookup = new Map();
  const budget = { left: MAX_BYTES };
  const seen = new Set();
  let visited = 0;
  try {
    function walk(folder, prefix, depth) {
      if (depth > 16) throw Error("depth exceeded");
      const before = directory(folder);
      const names = fs.readdirSync(folder).sort();
      visited += names.length;
      if (visited > MAX_FILES) throw Error("too many entries");
      if (new Set(names.map((n) => n.toLowerCase())).size !== names.length) throw Error("ambiguous names");
      dirs.push([folder, before, names]);
      for (const name of names) {
        if (!safePart(name) || seen.size >= MAX_FILES) throw Error("unknown entry");
        const relative = prefix + name, full = path.join(folder, name);
        const stat = fs.lstatSync(full, { bigint: true });
        if (stat.isSymbolicLink()) throw Error("symlink");
        if (stat.isDirectory()) { walk(full, relative + "/", depth + 1); continue; }
        if (!stat.isFile()) throw Error("nonfile");
        const identity = stat.dev + ":" + stat.ino;
        if (seen.has(identity)) throw Error("alias");
        seen.add(identity);
        const bytes = fileBytes(full, budget);
        const entry = { source, id: id(source, relative), sha256: sha(bytes),
          size: bytes.length, status: "PROVEN" };
        entries.push(entry);
        lookup.set(relative.replace(/\\/g, "/"), entry);
        snapshots.push([full, stat]);
      }
    }
    walk(root, "", 0);
    for (const [filename, original] of snapshots)
      if (!stable(original, fs.lstatSync(filename, { bigint: true }))) throw Error("file changed");
    for (const [folder, original, names] of dirs)
      if (!stable(original, directory(folder))
        || JSON.stringify(names) !== JSON.stringify(fs.readdirSync(folder).sort()))
        throw Error("directory changed");
    return { section: proven(entries.length), entries, lookup };
  } catch (_) { return { section: unknown(), entries: [], lookup: new Map() }; }
}
function rows(db, table, columns, optional = false) {
  const schema = db.prepare("SELECT type FROM sqlite_master WHERE name=?").get(table);
  if (!schema && optional) return [];
  if (!schema || schema.type !== "table") throw Error("missing SQL table");
  const actual = new Set(db.prepare(`PRAGMA table_info("${table}")`).all().map((c) => c.name));
  if (columns.some((c) => !actual.has(c))) throw Error("SQL column drift");
  const values = db.prepare(`SELECT ${columns.join(",")} FROM "${table}" LIMIT ?`).all(MAX_ROWS + 1);
  if (values.length > MAX_ROWS) throw Error("unbounded SQL");
  return values;
}
const KNOWN = new Set([
  "schema_migrations", "sqlite_sequence", "sqlite_stat1", "sqlite_stat4", "users",
  "folders", "pending_uploads", "public_links", "actions_history",
  "file_permissions", "file_expirations", "file_versions", "encrypted_files",
  "analytics_events", "audit_logs", "backup_history", "trash_items",
  "file_search_index", "sync_resume_factor_spend_grant",
  ...["data", "idx", "content", "docsize", "config"].map((v) => "file_search_index_" + v),
]);
function observeDb(filename) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) return { section: unknown(), tables: null };
  let db, snapshotDir;
  let result = { section: unknown(), tables: null };
  try {
    if (["-wal", "-shm", "-journal"].some((part) => fs.existsSync(filename + part)))
      throw Error("unsettled SQL sidecars");
    const budget = { left: MAX_BYTES };
    const bytes = fileBytes(filename, budget);
    // The original pathname is mutable. Opening it with SQLite after reading
    // the hash permits an A -> B -> A rebind that pairs A's hash with B's rows.
    // Query a private immutable-by-contract copy of the already pinned bytes.
    // This temp file is ours, never a source record; it is always disposed.
    snapshotDir = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-legacy-sql-image-"));
    const snapshotPath = path.join(snapshotDir, "image.sqlite");
    fs.writeFileSync(snapshotPath, bytes, { flag: "wx", mode: 0o600 });
    if (!bytes.equals(fileBytes(snapshotPath, { left: MAX_BYTES })))
      throw Error("snapshot mismatch");
    db = new DatabaseSync(snapshotPath, { readOnly: true });
    db.exec("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; BEGIN");
    if (db.prepare("PRAGMA quick_check").get()?.quick_check !== "ok") throw Error("invalid SQL");
    const schema = db.prepare("SELECT name,type FROM sqlite_master WHERE type IN ('table','view','trigger') LIMIT 129").all();
    if (schema.length > 128 || schema.some((item) => item.type !== "table" || !KNOWN.has(item.name)))
      throw Error("unrecognized SQL references");
    const tables = {};
    const selects = {
      folders: ["id"],
      file_versions: ["folder_id", "file_name", "versions_json"],
      file_search_index: ["folder_id", "file_name"],
      public_links: ["folder_id", "file_name"],
      file_permissions: ["folder_id", "file_name"],
      file_expirations: ["folder_id", "file_name"],
      encrypted_files: ["folder_id", "file_name"],
      trash_items: ["trash_path", "item_type", "status", "size_bytes"],
      backup_history: ["filename", "checksum", "status"],
      pending_uploads: ["id"],
    };
    for (const [table, columns] of Object.entries(selects))
      tables[table] = rows(db, table, columns);
    db.exec("COMMIT");
    db.close(); db = null;
    if (!bytes.equals(fileBytes(snapshotPath, { left: MAX_BYTES })))
      throw Error("snapshot changed during SQL inspection");
    if (!bytes.equals(fileBytes(filename, { left: MAX_BYTES }))) throw Error("database changed");
    if (["-wal", "-shm", "-journal"].some((part) => fs.existsSync(filename + part)))
      throw Error("database journal appeared");
    result = { section: { status: "PROVEN", count: 1, sha256: sha(bytes),
      id: id("sqlite", "legacy-source") }, tables };
  } catch (_) { /* Any unavailable evidence stays UNKNOWN. */ }
  finally {
    try { db?.close(); } catch (_) { result = { section: unknown(), tables: null }; }
    if (snapshotDir) {
      try { fs.rmSync(snapshotDir, { recursive: true, force: true }); }
      catch (_) { result = { section: unknown(), tables: null }; }
    }
  }
  return result;
}
function references(tables, uploads, trash, backups) {
  const fields = ["versions", "links", "permissions", "retention", "encryptedMetadata",
    "derivedIndex", "trashReferences", "backupReferences", "pendingUploads"];
  const output = Object.fromEntries(fields.map((key) => [key, unknown()]));
  if (!tables || uploads.section.status !== "PROVEN") return output;
  const physical = uploads.lookup;
  const logical = new Set();
  const validate = (r) => safePart(r.folder_id) && safePart(r.file_name)
    && (r.folder_id === "root" || tables.folders.some((f) => f.id === r.folder_id));
  const key = (folder, name) => (folder === "root" ? "" : folder + "/") + name;
  try {
    let versionCount = 0;
    const attributed = new Set();
    for (const row of tables.file_versions) {
      if (!validate(row) || !row.versions_json
        || Buffer.byteLength(row.versions_json) > MAX_JSON) throw Error("bad version");
      const v = JSON.parse(row.versions_json);
      if (!Array.isArray(v.versions) || v.versions.length === 0
        || v.versions.length > MAX_ROWS || !Number.isSafeInteger(v.currentVersion)) throw Error("missing versions");
      const seen = new Set();
      for (const revision of v.versions) {
        if (!Number.isSafeInteger(revision.version) || revision.version <= 0
          || seen.has(revision.version) || !safePart(revision.storedAs)
          || !Number.isSafeInteger(revision.size) || revision.size < 0)
          throw Error("ambiguous version");
        seen.add(revision.version);
        const alias = key(row.folder_id, revision.storedAs);
        if (!physical.has(alias) || physical.get(alias).size !== revision.size
          || attributed.has(alias)) throw Error("missing revision");
        attributed.add(alias); versionCount++;
        if (revision.version === v.currentVersion && revision.storedAs !== row.file_name)
          throw Error("current mismatch");
      }
      if (!seen.has(v.currentVersion)) throw Error("current missing");
      logical.add(key(row.folder_id, row.file_name));
    }
    // Unmapped files might be old generations or protected references.
    // They cannot prove that a join or deletion would be safe.
    if (attributed.size !== physical.size) throw Error("unattributed uploads");
    output.versions = proven(versionCount);
  } catch (_) { /* keep UNKNOWN; remaining joins must also be UNKNOWN */ }
  const fullyVersioned = output.versions.status === "PROVEN";
  for (const [kind, table] of [
    ["links", "public_links"], ["permissions", "file_permissions"],
    ["retention", "file_expirations"], ["encryptedMetadata", "encrypted_files"],
    ["derivedIndex", "file_search_index"],
  ]) {
    if (!fullyVersioned) continue;
    const values = tables[table];
    output[kind] = values.every((row) => validate(row)
      && logical.has(key(row.folder_id, row.file_name)))
      ? proven(values.length) : unknown(values.length);
  }
  output.pendingUploads = tables.pending_uploads.length === 0
    ? proven(0) : unknown(tables.pending_uploads.length);
  if (trash.section.status === "PROVEN") {
    const values = tables.trash_items;
    const attributed = new Set();
    output.trashReferences = values.every((row) => {
      const key = typeof row.trash_path === "string" ? row.trash_path.toLowerCase() : null;
      if (!key || attributed.has(key)) return false;
      attributed.add(key);
      return row.item_type === "file"
      && row.status === "trashed" && typeof row.trash_path === "string"
      && row.trash_path.split("/").every(safePart) && trash.lookup.has(row.trash_path)
      && Number.isSafeInteger(row.size_bytes)
      && trash.lookup.get(row.trash_path).size === row.size_bytes;
    }) && attributed.size === trash.lookup.size
      && [...trash.lookup.keys()].every((key) => attributed.has(key.toLowerCase()))
      ? proven(values.length) : unknown(values.length);
  }
  if (backups.section.status === "PROVEN") {
    const values = tables.backup_history;
    const attributed = new Set();
    output.backupReferences = values.every((row) => {
      const key = typeof row.filename === "string" ? row.filename.toLowerCase() : null;
      if (!key || attributed.has(key)) return false;
      attributed.add(key);
      return row.status === "success"
      && safePart(row.filename) && /^[a-f0-9]{64}$/.test(row.checksum || "")
      && backups.lookup.get(row.filename)?.sha256 === row.checksum;
    }) && attributed.size === backups.lookup.size
      && [...backups.lookup.keys()].every((key) => attributed.has(key.toLowerCase()))
      ? proven(values.length) : unknown(values.length);
  }
  return output;
}
async function inspectArchiveContents(backups) {
  if (backups.section.status !== "PROVEN") return { section: unknown(), entries: [] };
  const entries = [];
  let totalInflated = 0;
  let totalMembers = 0;
  try {
    for (const [name, archive] of backups.lookup) {
      // The archive itself has already been read and hashed by tree(). Read
      // again through the same no-follow identity checks before parsing.
      const root = backups.root;
      const bytes = fileBytes(path.join(root, name), { left: MAX_BYTES });
      if (sha(bytes) !== archive.sha256) throw Error("archive changed");
      // Validate central/local header correspondence and reject duplicate,
      // ambiguous or unsupported ZIP structures before inflating any entry.
      inspectZk1LiveLegacyZipReferenceEvidence({
        archives: new Map([[name, bytes]]),
        runSecret: Buffer.alloc(32),
      });
      const zip = await unzipper.Open.buffer(bytes);
      totalMembers += zip.files?.length || 0;
      if (!Array.isArray(zip.files) || zip.files.length === 0
        || zip.files.length > 1024 || totalMembers > MAX_FILES)
        throw Error("invalid archive");
      const names = new Set();
      const members = new Map();
      for (const member of zip.files) {
        const rel = member.path;
        if (typeof rel !== "string" || rel.length > 1024 || rel.startsWith("/")
          || rel.includes("\\") || rel.split("/").some((part) => !safePart(part))
          || !["uploads", "temp", "data"].includes(rel.split("/")[0])
            && rel !== "backup-manifest.json")
          throw Error("untrusted ZIP member");
        const attrs = Number(member.externalFileAttributes) >>> 16;
        if (member.type !== "File" || (attrs & 0o170000) === 0o120000
          || names.has(rel.toLowerCase()) || member.uncompressedSize > MAX_FILE)
          throw Error("ambiguous ZIP member");
        names.add(rel.toLowerCase());
        const chunks = [];
        let length = 0;
        for await (const chunk of member.stream()) {
          length += chunk.length;
          totalInflated += chunk.length;
          if (length > MAX_FILE || totalInflated > MAX_BYTES) throw Error("ZIP limit");
          chunks.push(chunk);
        }
        if (length !== member.uncompressedSize) throw Error("incomplete ZIP");
        const uncompressed = Buffer.concat(chunks);
        if (typeof zlib.crc32 === "function" && member.crc32 !== undefined
          && zlib.crc32(uncompressed) !== (member.crc32 >>> 0))
          throw Error("corrupt ZIP entry");
        members.set(rel, uncompressed);
        entries.push({ source: "backup-member", id: id("backup-member", name + "/" + rel),
          sha256: sha(uncompressed), size: length, status: "PROVEN" });
      }
      const manifestBytes = members.get("backup-manifest.json");
      if (!manifestBytes || manifestBytes.byteLength > MAX_JSON) throw Error("missing ZIP manifest");
      const manifest = JSON.parse(manifestBytes.toString("utf8"));
      if (!Array.isArray(manifest.included_files)
        || manifest.included_files.length !== members.size - 1)
        throw Error("incomplete ZIP manifest");
      const declared = new Set();
      for (const item of manifest.included_files) {
        if (!item || typeof item.path !== "string"
          || item.path === "backup-manifest.json"
          || !Number.isSafeInteger(item.size) || item.size < 0
          || declared.has(item.path) || !members.has(item.path)
          || members.get(item.path).length !== item.size)
          throw Error("unjoined ZIP manifest");
        declared.add(item.path);
      }
      if (declared.size !== members.size - 1
        || [...members.keys()].some((name) =>
          name !== "backup-manifest.json" && !declared.has(name)))
        throw Error("incomplete physical ZIP membership");
    }
    return { section: proven(entries.length), entries };
  } catch (_) { return { section: unknown(), entries: [] }; }
}
async function inspectZk1LegacyEvidenceManifest({
  optIn, databasePath, uploadsDir, tempDir, trashDir, backupsDir,
} = {}) {
  if (optIn !== true || typeof databasePath !== "string" || !path.isAbsolute(databasePath))
    throw new Error("ZK_LEGACY_EVIDENCE_MANIFEST_OPT_IN_REQUIRED");
  let uploads = tree(uploadsDir, "uploads");
  let temp = tree(tempDir, "temp");
  let trash = tree(trashDir, "trash");
  let backups = tree(backupsDir, "backups");
  backups.root = backupsDir;
  let sqlite = observeDb(databasePath);
  let referencesResult = references(sqlite.tables, uploads, trash, backups);
  if (referencesResult.backupReferences.status !== "PROVEN")
    backups.section = unknown(backups.section.count);
  let archived = await inspectArchiveContents(backups);
  // A writer may mutate another root while the asynchronous ZIP reader
  // yields. Recheck every namespace and the SQLite image after that await.
  // No source can remain PROVEN if the two observations disagree.
  const candidates = [
    [uploads, uploadsDir, "uploads"], [temp, tempDir, "temp"],
    [trash, trashDir, "trash"], [backups, backupsDir, "backups"],
  ];
  const changed = new Set();
  for (const [original, root, kind] of candidates) {
    const again = tree(root, kind);
    if (original.section.status !== "PROVEN" || again.section.status !== "PROVEN"
      || JSON.stringify(original.entries) !== JSON.stringify(again.entries))
      changed.add(kind);
  }
  const sqliteAgain = observeDb(databasePath);
  if (sqlite.section.status !== "PROVEN"
    || sqliteAgain.section.status !== "PROVEN"
    || sqlite.section.sha256 !== sqliteAgain.section.sha256)
    changed.add("sqlite");
  if (changed.has("uploads")) uploads = { section: unknown(), entries: [] };
  if (changed.has("temp")) temp = { section: unknown(), entries: [] };
  if (changed.has("trash")) trash = { section: unknown(), entries: [] };
  if (changed.has("backups")) backups = { section: unknown(), entries: [] };
  if (changed.has("sqlite")) sqlite = { section: unknown() };
  if (changed.has("sqlite") || changed.has("uploads") || changed.has("trash")
    || changed.has("backups")) {
    referencesResult = Object.fromEntries(Object.entries(referencesResult)
      .map(([kind, value]) => [kind, unknown(value.count)]));
  }
  if (changed.has("backups") || archived.section.status !== "PROVEN") {
    archived = { section: unknown(), entries: [] };
    backups.section = unknown(backups.section.count);
  }
  const sections = {
    sqlite: sqlite.section, uploads: uploads.section, temp: temp.section,
    trash: trash.section, backups: backups.section, backupMembers: archived.section,
    ...referencesResult,
    // Physical trash bytes and expiry rows cannot authenticate historical
    // tombstones, removed backups, restored generations, JSON mirrors, or
    // provider records not available in the selected on-host roots.
    trashTombstones: unknown(sqlite.tables?.trash_items.filter(
      (item) => item.status !== "trashed").length || 0),
    backupRetention: unknown(backups.section.status === "PROVEN"
      ? [...backups.lookup.keys()].filter((name) =>
        /\.retention-tombstone(?:\.json)?$/.test(name)
          || name.startsWith(".retention-transactions/")).length : 0),
    derivedSemantics: unknown(temp.section.count),
    jsonMirrors: unknown(),
    remoteProviderCopies: unknown(),
    restoreLineage: unknown(),
    writerQuiescence: unknown(),
  };
  const entries = [...uploads.entries, ...temp.entries, ...trash.entries,
    ...backups.entries, ...archived.entries].sort((a, b) =>
    a.source.localeCompare(b.source, "en") || a.id.localeCompare(b.id, "en"));
  const report = {
    schema: SCHEMA, readOnly: true, status: "UNKNOWN",
    // The selected roots cannot prove absent external copies, omitted
    // generations, remote snapshots, account keys or writer quiescence.
    wholeCorpusVerified: false, canDeleteLegacy: false, authorizesCutover: false,
    sections, entries,
  };
  return Object.freeze({ ...report, manifestSha256: sha(JSON.stringify(report)) });
}
module.exports = { inspectZk1LegacyEvidenceManifest };
