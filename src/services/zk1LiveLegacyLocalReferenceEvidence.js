"use strict";

// Optional bounded local readback of legacy version aliases and the derived
// FTS reference index. Local bytes never leave this module. This is not a
// complete migration inventory and cannot establish rollback protection.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const MAX_ENTRIES = 5000;
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_JSON_BYTES = 256 * 1024;

function deny() { throw new Error("ZK_LIVE_LEGACY_LOCAL_REFERENCES_UNAVAILABLE"); }
function same(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.nlink === b.nlink
    && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
}
function directory(target) {
  let stat, real;
  try {
    stat = fs.lstatSync(target, { bigint: true });
    real = fs.realpathSync.native(target);
  } catch (_) { deny(); }
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || (process.platform === "win32" ? real.toLowerCase() : real)
      !== (process.platform === "win32" ? path.resolve(target).toLowerCase() : path.resolve(target))) deny();
  return stat;
}
function safeName(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 255
    && value !== "." && value !== ".." && !/[\\/\x00-\x1f<>:"|?*]/.test(value)
    && value === path.basename(value) && !value.endsWith(".") && !value.endsWith(" ");
}
function rows(db, sql) {
  const values = db.prepare(sql).all(MAX_ENTRIES + 1);
  if (values.length > MAX_ENTRIES) deny();
  return values;
}
function parseVersionJson(source) {
  if (typeof source !== "string" || Buffer.byteLength(source, "utf8") > MAX_JSON_BYTES) deny();
  let parsed;
  try { parsed = JSON.parse(source); } catch (_) { deny(); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) deny();
  if (parsed.versions === undefined && (parsed.currentVersion === undefined || parsed.currentVersion === 0))
    return { currentVersion: 0, versions: [] };
  if (!Array.isArray(parsed.versions) || parsed.versions.length > MAX_ENTRIES) deny();
  if (parsed.versions.length === 0) {
    if (parsed.currentVersion !== undefined && parsed.currentVersion !== 0) deny();
    return { currentVersion: 0, versions: [] };
  }
  if (!Number.isSafeInteger(parsed.currentVersion) || parsed.currentVersion <= 0) deny();
  const seen = new Set();
  for (const item of parsed.versions) {
    if (!item || typeof item !== "object" || Array.isArray(item)
      || !Number.isSafeInteger(item.version) || item.version <= 0 || seen.has(item.version)
      || !safeName(item.storedAs)
      || (item.size !== undefined && (!Number.isSafeInteger(item.size) || item.size < 0))) deny();
    seen.add(item.version);
  }
  if (!seen.has(parsed.currentVersion)) deny();
  return { currentVersion: parsed.currentVersion, versions: parsed.versions };
}

function inspectZk1LiveLegacyLocalReferenceEvidence({ uploadsDir, db, runSecret,
  strictSourceReferences = false }) {
  if (typeof uploadsDir !== "string" || !path.isAbsolute(uploadsDir)
    || !db || !Buffer.isBuffer(runSecret) || runSecret.length !== 32
    || typeof strictSourceReferences !== "boolean") deny();
  const dirs = new Map([[uploadsDir, directory(uploadsDir)]]);
  const folders = rows(db, "SELECT id FROM folders ORDER BY id LIMIT ?");
  const allowed = new Set(["root"]);
  for (const row of folders) {
    if (!safeName(row.id) || allowed.has(row.id) && row.id !== "root") deny();
    allowed.add(row.id);
  }
  const seenFiles = new Set(), local = new Map();
  let totalBytes = 0n, entries = 0;
  function inspectFile(file, key) {
    let before, fd;
    try {
      // Trust only an already-opened, bounded regular descriptor. A named
      // lstat made before native open cannot authorize the inode that opens.
      fd = fs.openSync(file, fs.constants.O_RDONLY
        | (fs.constants.O_NONBLOCK || 0) | (fs.constants.O_NOFOLLOW || 0));
      before = fs.fstatSync(fd, { bigint: true });
      const named = fs.lstatSync(file, { bigint: true });
      if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
        || before.size > BigInt(MAX_FILE_BYTES)
        || !named.isFile() || named.isSymbolicLink() || !same(before, named)) deny();
      const inode = `${before.dev}:${before.ino}`;
      if (seenFiles.has(inode)) deny();
      seenFiles.add(inode);
      totalBytes += before.size;
      if (totalBytes > BigInt(MAX_TOTAL_BYTES)) deny();
      // Pin the allocation to the pre-open size, not a writer-grown inode.
      const data = Buffer.alloc(Number(before.size));
      let offset = 0;
      while (offset < data.length) {
        const count = fs.readSync(fd, data, offset,
          Math.min(64 * 1024, data.length - offset), offset);
        if (count <= 0 || count > data.length - offset) deny();
        offset += count;
      }
      if (BigInt(data.length) !== before.size
        || !same(before, fs.fstatSync(fd, { bigint: true }))
        || !same(before, fs.lstatSync(file, { bigint: true }))) deny();
      local.set(key, { file, before, size: data.length,
        hash: crypto.createHash("sha256").update(data).digest("hex") });
    } catch (_) { deny(); }
    finally { if (fd !== undefined) fs.closeSync(fd); }
  }
  function inspectDirectory(dir, folder, isRoot = false) {
    const names = fs.readdirSync(dir).sort();
    entries += names.length;
    if (entries > MAX_ENTRIES || new Set(names.map((n) => n.toLowerCase())).size !== names.length) deny();
    for (const name of names) {
      if (!safeName(name)) deny();
      const item = path.join(dir, name);
      const stat = fs.lstatSync(item, { bigint: true });
      if (stat.isSymbolicLink()) deny();
      if (stat.isDirectory()) {
        if (!isRoot || name === "root" || !allowed.has(name)) deny();
        dirs.set(item, directory(item));
        inspectDirectory(item, name);
      } else if (stat.isFile()) inspectFile(item, `${folder}\0${name}`);
      else deny();
    }
  }
  inspectDirectory(uploadsDir, "root", true);

  const versions = rows(db,
    "SELECT folder_id,file_name,versions_json FROM file_versions ORDER BY folder_id,file_name LIMIT ?");
  const refs = new Set(), historyFiles = new Map(), versionRows = new Set();
  let versionPayloads = 0;
  for (const row of versions) {
    if (!safeName(row.folder_id) || !allowed.has(row.folder_id) || !safeName(row.file_name)) deny();
    const logical = `${row.folder_id}\0${row.file_name}`;
    if (versionRows.has(logical)) deny();
    versionRows.add(logical);
    const history = parseVersionJson(row.versions_json);
    const current = history.versions.find((item) => item.version === history.currentVersion);
    if (current && current.storedAs !== row.file_name) deny();
    for (const item of history.versions) {
      const key = `${row.folder_id}\0${item.storedAs}`;
      const file = local.get(key);
      if (!file || (item.size !== undefined && item.size !== file.size)
        || historyFiles.has(key)) deny();
      historyFiles.set(key, logical);
      refs.add(key);
      if (++versionPayloads > MAX_ENTRIES) deny();
    }
  }
  const index = rows(db,
    "SELECT folder_id,file_name FROM file_search_index ORDER BY folder_id,file_name LIMIT ?");
  const uniqueSearch = new Set();
  for (const row of index) {
    if (!safeName(row.folder_id) || !allowed.has(row.folder_id) || !safeName(row.file_name)) deny();
    const key = `${row.folder_id}\0${row.file_name}`;
    if (uniqueSearch.has(key) || !local.has(key)) deny();
    uniqueSearch.add(key);
    refs.add(key);
  }

  // The ordinary scan reports unknown local bytes without treating them as
  // migration evidence. Strict opt-in additionally joins every known live
  // reference class to a real, versioned source. A dangling encrypted-file,
  // link, permission, expiry or derived entry can otherwise hide an omitted
  // legacy source even when the individual SQL and filesystem scans succeed.
  let sourceTypes;
  if (strictSourceReferences) {
    if (local.size !== refs.size) deny();
    for (const key of uniqueSearch) if (!versionRows.has(key)) deny();
    const referenceTables = Object.freeze([
      ["encryptedFiles", "encrypted_files"],
      ["publicLinks", "public_links"],
      ["filePermissions", "file_permissions"],
      ["retention", "file_expirations"],
    ]);
    const counts = { versionRows: versionRows.size, historicalPayloads: versionPayloads,
      derivedSearchReferences: uniqueSearch.size, unmappedLocalFiles: 0 };
    for (const [kind, table] of referenceTables) {
      const linked = rows(db, `SELECT folder_id,file_name FROM ${table}
        ORDER BY folder_id,file_name LIMIT ?`);
      for (const row of linked) {
        if (!safeName(row.folder_id) || !allowed.has(row.folder_id)
          || !safeName(row.file_name)
          || !versionRows.has(`${row.folder_id}\0${row.file_name}`)
          || !refs.has(`${row.folder_id}\0${row.file_name}`)) deny();
      }
      counts[kind] = linked.length;
    }
    // Pending uploads and trash may store independently reachable bytes whose
    // physical namespace is outside the uploads directory. Until an explicit
    // source reader can reconcile those, treat any row as unknown custody.
    for (const table of ["pending_uploads", "trash_items"])
      if (db.prepare(`SELECT 1 FROM ${table} LIMIT 1`).get()) deny();
    sourceTypes = Object.freeze(counts);
  }

  // Detect renamed/replaced payloads as well as added/removed namespace entries
  // after the SQLite read transaction started. This is local observational
  // stability, not an independent monotonic generation or remote ACK proof.
  for (const [key, saved] of local) {
    let current;
    try { current = fs.lstatSync(saved.file, { bigint: true }); } catch (_) { deny(); }
    if (!current.isFile() || current.isSymbolicLink() || !same(saved.before, current)) deny();
    if (!refs.has(key)) continue; // Unmapped bytes stay explicitly unverified.
  }
  for (const [dir, stat] of dirs) if (!same(stat, directory(dir))) deny();
  const counts = { versions: versionRows.size, versionPayloads,
    derivedSearchReferences: uniqueSearch.size, localFiles: local.size,
    unmappedLocalFiles: local.size - refs.size };
  const mac = crypto.createHmac("sha256", runSecret)
    .update("rootark-zk1-legacy-local-refs/v1\0")
    .update(JSON.stringify([...local].map(([key, val]) => [key, val.hash, val.size])))
    .update(JSON.stringify([...refs].sort())).update(JSON.stringify(counts))
    .update(JSON.stringify(sourceTypes || null)).digest("base64url");
  return Object.freeze({ observation: "partial-local-legacy-file-references-only",
    ...counts, ...(sourceTypes ? { strictSourceTypes: sourceTypes } : {}),
    ephemeralFingerprint: mac, globallyComplete: false });
}

module.exports = { inspectZk1LiveLegacyLocalReferenceEvidence };
