"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { once } = require("node:events");
const { DatabaseSync } = require("node:sqlite");
const { inspectZk1LiveLegacyReferencePreflight: inspect } =
  require("../src/services/zk1LiveLegacyReferencePreflight");
const { withInodeGrowthAfterFstat } = require("./support/issue-65-inode-growth-race");

const MODE = { dbEnabled: true, jsonReadFallback: false, jsonWriteMirror: false };
const NAME = "rootark-backup-2026-10-23-08-00-00.zip";
const OTHER = "rootark-backup-2026-10-23-09-00-00.zip";
const SECRET = "PRIVATE-SECRET-LEGACY-PATH-DO-NOT-EMIT";
const BYTES = Buffer.from("disposable synthetic backup archive bytes, not user data\0");
const SHA = crypto.createHash("sha256").update(BYTES).digest("hex");
const TX_ID = "cb9733c6-b4a2-4faa-aac5-84d540155645";
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-live-backup-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dataDir = path.join(root, "data");
  const backupDir = path.join(dataDir, "backups");
  fs.mkdirSync(backupDir, { recursive: true });
  const databasePath = path.join(dataDir, "rootark.sqlite");
  const db = new DatabaseSync(databasePath);
  db.exec(`
    CREATE TABLE file_versions(id INTEGER PRIMARY KEY, folder_id TEXT, file_name TEXT, versions_json TEXT);
    CREATE TABLE backup_history(id TEXT PRIMARY KEY, filename TEXT, type TEXT, status TEXT, metadata_json TEXT, checksum TEXT);
    CREATE TABLE trash_items(id TEXT PRIMARY KEY, item_type TEXT, status TEXT, original_file_name TEXT,
       trash_path TEXT, metadata_json TEXT, restore_metadata_json TEXT);
    CREATE TABLE public_links(token TEXT PRIMARY KEY, folder_id TEXT, file_name TEXT, revoked_at TEXT, metadata_json TEXT);
    CREATE VIRTUAL TABLE file_search_index USING fts5(folder_id UNINDEXED, file_name, tokenize='trigram case_sensitive 0');
    CREATE TABLE file_expirations(id INTEGER PRIMARY KEY, folder_id TEXT, file_name TEXT, expires_at TEXT);
  `);
  db.prepare("INSERT INTO backup_history VALUES (?,?,?,?,?,?)")
    .run("backup-1", NAME, "manual", "success", "{}", SHA);
  db.prepare("INSERT INTO file_versions VALUES (1,?,?,?)")
    .run("root", SECRET, JSON.stringify({ versions: [] }));
  db.close();
  fs.writeFileSync(path.join(backupDir, NAME), BYTES);
  fs.writeFileSync(path.join(dataDir, "backup-history.json"),
    JSON.stringify([{ id: "backup-1", filename: NAME, type: "manual", status: "success" }]));
  return { root, dataDir, backupDir, databasePath, zip: path.join(backupDir, NAME),
    history: path.join(dataDir, "backup-history.json") };
}
function scan(f, extra) {
  return inspect({ optIn: true, databasePath: f.databasePath,
    persistence: MODE, backupDataDir: f.dataDir, ...extra });
}
function mustDeny(f) {
  assert.throws(() => scan(f), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
}
function checkOpaque(f, result) {
  const payload = JSON.stringify(result);
  for (const secret of [SECRET, f.root, f.dataDir, f.backupDir, f.databasePath, NAME, OTHER, TX_ID])
    assert.equal(payload.includes(secret), false, "sensitive physical reference escaped");
  for (const key of ["authorizesCutover", "canDeleteLegacy", "wholeCorpusVerified", "authoritativeCorpusInventory"])
    assert.equal(result[key], false);
}

function selectedZip(entries) {
  const locals = [], centers = [];
  let offset = 0;
  for (const [name, payload] of entries) {
    const nameBytes = Buffer.from(name);
    const body = Buffer.from(payload);
    let crc = 0xffffffff;
    for (const value of body) {
      crc ^= value;
      for (let i = 0; i < 8; i++) crc = crc & 1
        ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
    crc = (crc ^ 0xffffffff) >>> 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x800, 6);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(body.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    locals.push(local, nameBytes, body);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x800, 8);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(body.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    centers.push(central, nameBytes);
    offset += local.length + nameBytes.length + body.length;
  }
  const directory = Buffer.concat(centers);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

function replaceArchive(f, bytes) {
  fs.writeFileSync(f.zip, bytes);
  const db = new DatabaseSync(f.databasePath);
  db.prepare("UPDATE backup_history SET checksum=? WHERE id='backup-1'")
    .run(crypto.createHash("sha256").update(bytes).digest("hex"));
  db.close();
}

test("explicit ZIP metadata inventory counts derived, SQL, unknown references without corpus clearance", (t) => {
  const f = fixture(t);
  const zip = selectedZip([
    ["backup-manifest.json", "{}"],
    ["data/rootark.sqlite", "private synthetic db bytes"],
    ["derived/previews/opaque.dat", "private synthetic preview"],
    ["future-family/surprise.dat", "unclassified synthetic file"],
  ]);
  replaceArchive(f, zip);
  const original = Buffer.from(fs.readFileSync(f.zip));
  const report = scan(f, { zipContentsOptIn: true });
  const observed = report.legacy.backupEvidence.archiveContents;
  assert.deepEqual({ ...observed, ephemeralFingerprint: null }, {
    observation: "partial-local-zip-central-directory-only",
    archivesInspected: 1, entries: 4, directories: 0,
    manifests: 1, sqliteCandidates: 1, derivedCandidates: 1,
    unknownEntries: 1, ephemeralFingerprint: null,
    contentReadbackVerified: false, derivedCoverage: "unknown",
    providerCoverage: "unknown", archiveCompleteness: "unknown",
    globallyComplete: false,
  });
  checkOpaque(f, report);
  assert.equal(JSON.stringify(report).includes("surprise.dat"), false);
  assert.deepEqual(fs.readFileSync(f.zip), original);
  assert.equal(report.authorizesCutover, false);
});

test("selected ZIP inventory rejects malformed, unsafe, aliased and oversized central directory without any writes", (t) => {
  const valid = selectedZip([["backup-manifest.json", "{}"]]);
  for (const build of [
    () => Buffer.from("not a ZIP"),
    () => selectedZip([["../traversal.txt", "bad"]]),
    () => selectedZip([["backup-manifest.json", "{}"], ["backup-manifest.json", "duplicate"]]),
    () => selectedZip([["x\\bad.txt", "unsafe"]]),
    () => { const b = Buffer.from(valid); b.writeUInt32LE(0xffffffff, b.length - 6); return b; },
    () => { const b = Buffer.from(valid); b.writeUInt16LE(0xffff, b.length - 14); return b; },
    () => { const b = Buffer.from(valid); b.writeUInt16LE(1, 6); return b; },
    () => { const b = Buffer.from(valid); b.writeUInt32LE(0xffffffff, 22); return b; },
  ]) {
    const f = fixture(t);
    replaceArchive(f, build());
    const before = fs.readFileSync(f.zip);
    assert.throws(() => scan(f, { zipContentsOptIn: true }),
      /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
    assert.deepEqual(fs.readFileSync(f.zip), before);
  }
});
function tx(f, phase = "prepared", name = NAME) {
  const txRoot = path.join(f.backupDir, ".retention-transactions");
  const folder = path.join(txRoot, "tx-" + TX_ID);
  fs.mkdirSync(folder, { recursive: true });
  const value = { version: 1, transactionId: TX_ID, phase,
    backupId: "backup-1", filename: name, checksum: SHA,
    archivePath: path.join(f.backupDir, name),
    tombstonePath: path.join(f.backupDir, name + ".retention-tombstone") };
  const file = path.join(folder, "transaction.json");
  fs.writeFileSync(file, JSON.stringify(value));
  return { folder, file, value };
}

test("read-only independent archive + JSON history evidence extends six SQL classes but never declares corpus complete", (t) => {
  const f = fixture(t);
  const before = [fs.readFileSync(f.zip), fs.readFileSync(f.history)];
  const a = scan(f), b = scan(f);
  assert.equal(a.legacy.backupEvidence.observation, "partial-local-backup-evidence-only");
  assert.deepEqual({ ...a.legacy.backupEvidence, ephemeralFingerprint: null },
    { observation: "partial-local-backup-evidence-only", historyRows: 1,
      jsonHistoryRows: 1, archives: 1, retentionTombstones: 0,
      retentionTransactions: 0, ephemeralFingerprint: null, globallyComplete: false });
  assert.equal(a.legacy.coverage, "partial");
  assert.equal(a.protected.coverage, "uninspected");
  assert.notEqual(a.legacy.backupEvidence.ephemeralFingerprint, b.legacy.backupEvidence.ephemeralFingerprint);
  checkOpaque(f, a);
  assert.deepEqual([fs.readFileSync(f.zip), fs.readFileSync(f.history)], before);
});

test("source aliases, orphan archives, stale history, missing archive and corrupt checksums refuse without deletion", (t) => {
  const attacks = [
    (f) => fs.writeFileSync(path.join(f.backupDir, OTHER), BYTES),
    (f) => fs.linkSync(f.zip, path.join(f.backupDir, OTHER)),
    (f) => fs.writeFileSync(f.history, JSON.stringify([{ id: "unknown", filename: NAME }])),
    (f) => fs.writeFileSync(f.history, "{broken"),
    (f) => fs.rmSync(f.zip),
    (f) => fs.writeFileSync(f.zip, "tampered legacy backup archive"),
    (f) => fs.writeFileSync(path.join(f.backupDir, "private-alias.bin"), "unknown"),
  ];
  for (const attack of attacks) {
    const f = fixture(t);
    const untouchedSql = fs.readFileSync(f.databasePath);
    attack(f);
    mustDeny(f);
    assert.deepEqual(fs.readFileSync(f.databasePath), untouchedSql, "scanner must never mutate SQL file");
  }
});

test("retention tombstone and on-disk transaction are accounted for, not recovered or signed", (t) => {
  const f = fixture(t);
  const tombstone = f.zip + ".retention-tombstone";
  const metadata = tombstone + ".json";
  fs.writeFileSync(tombstone, BYTES);
  fs.writeFileSync(metadata,
    JSON.stringify({ backupId: "backup-1", filename: NAME, checksum: SHA }));
  const transaction = tx(f);
  const artifacts = [f.zip, tombstone, metadata, transaction.file];
  const before = artifacts.map((name) => fs.readFileSync(name));
  const evidence = scan(f).legacy.backupEvidence;
  assert.equal(evidence.archives, 1);
  assert.equal(evidence.retentionTombstones, 1);
  assert.equal(evidence.retentionTransactions, 1);
  assert.equal(evidence.globallyComplete, false);
  assert.deepEqual(artifacts.map((name) => fs.readFileSync(name)), before);
});

test("retention references with invalid phase, displaced alias, missing pair or ambiguous transaction refuse", (t) => {
  for (const attack of [
    (f) => { fs.writeFileSync(f.zip + ".retention-tombstone", BYTES); },
    (f) => { fs.writeFileSync(f.zip + ".retention-tombstone.json", "{}"); },
    (f) => { const x = tx(f); fs.writeFileSync(x.file, JSON.stringify({ ...x.value, phase: "forged" })); },
    (f) => { const x = tx(f); fs.writeFileSync(x.file, JSON.stringify({ ...x.value, archivePath: f.root + "/other.zip" })); },
    (f) => { const x = tx(f); fs.writeFileSync(x.file, JSON.stringify({ ...x.value, checksum: "0".repeat(64) })); },
    (f) => { tx(f); fs.writeFileSync(path.join(f.backupDir, ".retention-transactions", "unknown.txt"), "unlisted"); },
  ]) {
    const f = fixture(t);
    attack(f);
    mustDeny(f);
    assert.equal(fs.existsSync(f.zip), true, "denied scan must preserve source backup");
  }
});

test("no supplied root is expressly uninspected; mismatched data root and symlinked roots cannot be adopted", (t) => {
  const f = fixture(t);
  const without = inspect({ optIn: true, databasePath: f.databasePath, persistence: MODE });
  assert.deepEqual(without.legacy.backupEvidence, { observation: "uninspected", globallyComplete: false });
  const other = fixture(t);
  assert.throws(() => scan(f, { backupDataDir: other.dataDir }), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
  const alias = path.join(f.root, "alias-data");
  try {
    fs.symlinkSync(f.dataDir, alias, process.platform === "win32" ? "junction" : "dir");
    assert.throws(() => scan(f, { backupDataDir: alias }), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
  } catch (error) {
    if (!["EPERM", "EACCES"].includes(error.code)) throw error;
  }
});

test("authenticated loopback fixture rejects an altered live backup without exposing aliases or paths", async (t) => {
  const f = fixture(t);
  const server = http.createServer((req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Content-Type", "application/json");
    if (req.url !== "/fixture/backup-evidence" || req.method !== "GET"
      || req.headers.authorization !== "fixture-only") {
      res.writeHead(403); res.end('{"error":"UNAVAILABLE"}'); return;
    }
    try {
      const payload = JSON.stringify(scan(f));
      res.writeHead(200); res.end(payload);
    } catch (_) {
      res.writeHead(503); res.end('{"error":"UNAVAILABLE"}');
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const url = `http://127.0.0.1:${server.address().port}/fixture/backup-evidence`;
  assert.equal((await fetch(url)).status, 403);
  const response = await fetch(url, { headers: { authorization: "fixture-only" } });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.legacy.backupEvidence.archives, 1);
  checkOpaque(f, result);
  fs.writeFileSync(f.history, JSON.stringify([{ id: "backup-foreign", filename: NAME }]));
  const rejected = await fetch(url, { headers: { authorization: "fixture-only" } });
  assert.equal(rejected.status, 503);
  assert.deepEqual(await rejected.json(), { error: "UNAVAILABLE" });
  assert.equal(fs.existsSync(f.zip), true);
});

test("bounded inspection refuses an oversized archive without reporting a partial result as complete", (t) => {
  const f = fixture(t);
  const fd = fs.openSync(f.zip, "r+");
  try { fs.ftruncateSync(fd, 32 * 1024 * 1024 + 1); } finally { fs.closeSync(fd); }
  mustDeny(f);
  assert.equal(fs.existsSync(f.zip), true);
});

test("late backup swap after hashing is rejected on final filesystem identity recheck", (t) => {
  const f = fixture(t);
  const original = fs.lstatSync;
  let calls = 0;
  fs.lstatSync = function (file, ...args) {
    if (String(file) === f.zip && ++calls === 3) {
      fs.writeFileSync(f.zip, "simulated concurrent untrusted backup replacement");
    }
    return original.call(this, file, ...args);
  };
  try {
    mustDeny(f);
    assert.ok(calls >= 3);
  } finally {
    fs.lstatSync = original;
  }
  assert.equal(fs.existsSync(f.zip), true, "never remove concurrent source material");
});

test("legacy backup mirror never allocates bytes grown past its JSON cap after fstat", async (t) => {
  const f = fixture(t);
  const observed = await withInodeGrowthAfterFstat({ target: f.history,
    extraBytes: 257 * 1024,
    run: () => mustDeny(f) });
  assert.equal(observed.attacked, true);
  assert.deepEqual(observed.numericFdReadLengths, [],
    "a growing backup JSON mirror must remain bounded before postread rejection");
});
