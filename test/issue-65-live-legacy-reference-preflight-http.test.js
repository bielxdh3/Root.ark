"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { DatabaseSync } = require("node:sqlite");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { once } = require("node:events");
const { inspectZk1LiveLegacyReferencePreflight: inspect } =
  require("../src/services/zk1LiveLegacyReferencePreflight");

const MODE = Object.freeze({ dbEnabled: true, jsonReadFallback: false, jsonWriteMirror: false });
const SECRET_NAME = "PRIVATE-LEGACY-filename-secret.txt";
const SECRET_PATH = "/private/data/trash/" + SECRET_NAME;
const SENSITIVE = [SECRET_NAME, SECRET_PATH, "PRIVATE-TOKEN", "PRIVATE-BACKUP-ARCHIVE"];

function makeFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-live-legacy-scan-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const databasePath = path.join(root, "synthetic-live.sqlite");
  const db = new DatabaseSync(databasePath);
  db.exec(`
    CREATE TABLE file_versions (
      id INTEGER PRIMARY KEY, folder_id TEXT, file_name TEXT, versions_json TEXT);
    CREATE TABLE backup_history (
      id TEXT PRIMARY KEY, filename TEXT, type TEXT, status TEXT, metadata_json TEXT);
    CREATE TABLE trash_items (
      id TEXT PRIMARY KEY, item_type TEXT, status TEXT, original_file_name TEXT,
      trash_path TEXT, metadata_json TEXT, restore_metadata_json TEXT);
    CREATE TABLE public_links (
      token TEXT PRIMARY KEY, folder_id TEXT, file_name TEXT, revoked_at TEXT, metadata_json TEXT);
    CREATE VIRTUAL TABLE file_search_index USING fts5(folder_id UNINDEXED, file_name,
      tokenize = 'trigram case_sensitive 0');
    CREATE TABLE file_expirations (
      id INTEGER PRIMARY KEY, folder_id TEXT, file_name TEXT, expires_at TEXT);
  `);
  db.prepare("INSERT INTO file_versions VALUES (1,?,?,?)")
    .run("root", SECRET_NAME, JSON.stringify({ currentVersion: 1, versions: [{ version: 1, storedAs: SECRET_NAME }] }));
  db.prepare("INSERT INTO backup_history VALUES (?,?,?,?,?)")
    .run("b1", "PRIVATE-BACKUP-ARCHIVE", "full", "success", "{}");
  db.prepare("INSERT INTO trash_items VALUES (?,?,?,?,?,?,?)")
    .run("t1", "file", "trashed", SECRET_NAME, SECRET_PATH, "{}", "{}");
  db.prepare("INSERT INTO public_links VALUES (?,?,?,?,?)")
    .run("PRIVATE-TOKEN", "root", SECRET_NAME, null, "{}");
  db.prepare("INSERT INTO public_links VALUES (?,?,?,?,?)")
    .run("PRIVATE-TOKEN-REVOKED", "root", SECRET_NAME, "2026-10-22T00:00:00Z", "{}");
  db.prepare("INSERT INTO file_search_index VALUES (?,?)").run("root", SECRET_NAME);
  db.prepare("INSERT INTO file_expirations VALUES (1,?,?,?)")
    .run("root", SECRET_NAME, "2026-11-01T00:00:00Z");
  db.close();
  return { root, databasePath };
}
function read(f) {
  return inspect({ optIn: true, databasePath: f.databasePath, persistence: MODE });
}
function ensureNotLeaked(value, f) {
  const serialized = JSON.stringify(value);
  for (const secret of [...SENSITIVE, f.root, f.databasePath])
    assert.ok(!serialized.includes(secret), "sensitive source locator must not leave legacy side");
}

test("real SQLite partial snapshot covers six mapped classes, including revoked links, without names", (t) => {
  const f = makeFixture(t);
  const first = read(f), second = read(f);
  assert.equal(first.schema, "rootark-zk1-live-legacy-reference-preflight/v1");
  assert.equal(first.readOnly, true);
  assert.equal(first.legacy.coverage, "partial");
  assert.equal(first.protected.coverage, "uninspected");
  assert.equal(first.snapshotOwnerSigned, false);
  for (const name of ["wholeCorpusVerified", "authorizesCutover", "canDeleteLegacy", "authoritativeCorpusInventory"])
    assert.equal(first[name], false);
  assert.deepEqual(first.legacy.observations.map((x) => x.kind),
    ["versions", "backups", "trash", "links", "derived", "retention"]);
  assert.deepEqual(first.legacy.observations.map((x) => x.observedRows),
    [1, 1, 1, 2, 1, 1]);
  assert.ok(first.blockers.some((text) => text.includes("tombstones")));
  assert.ok(first.blockers.some((text) => text.includes("protected-zk")));
  assert.notEqual(first.legacy.observations[0].ephemeralFingerprint,
    second.legacy.observations[0].ephemeralFingerprint, "opaque per-run digest must be unlinkable");
  ensureNotLeaked(first, f);
  ensureNotLeaked(second, f);
  const actual = new DatabaseSync(f.databasePath, { readOnly: true });
  assert.equal(actual.prepare("SELECT COUNT(*) n FROM public_links").get().n, 2);
  assert.equal(actual.prepare("SELECT file_name FROM file_versions").get().file_name, SECRET_NAME);
  actual.close();
});

test("read-only legacy preflight refuses fallback, missing database, corrupted JSON and schema omissions", (t) => {
  const f = makeFixture(t);
  for (const changed of [
    { optIn: false },
    { optIn: undefined },
    { persistence: { ...MODE, jsonReadFallback: true } },
    { persistence: { ...MODE, jsonWriteMirror: true } },
    { persistence: { ...MODE, dbEnabled: false } },
    { databasePath: path.join(f.root, "absent.sqlite") },
  ]) {
    assert.throws(() => inspect({ optIn: true, databasePath: f.databasePath,
      persistence: MODE, ...changed }), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
  }
  const db = new DatabaseSync(f.databasePath);
  db.exec("UPDATE file_versions SET versions_json = '{broken-json' WHERE id = 1");
  db.close();
  assert.throws(() => read(f), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
  const db2 = new DatabaseSync(f.databasePath);
  db2.exec("UPDATE file_versions SET versions_json = '{}'; DROP TABLE file_expirations");
  db2.close();
  assert.throws(() => read(f), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
  assert.equal(fs.existsSync(path.join(f.root, "absent.sqlite")), false,
    "readonly scan must never create absent databases");
});

test("unknown extra rows cannot be silently truncated into a purported complete inventory", (t) => {
  const f = makeFixture(t);
  const db = new DatabaseSync(f.databasePath);
  const insert = db.prepare("INSERT INTO file_expirations (id,folder_id,file_name,expires_at) VALUES (?,?,?,?)");
  db.exec("BEGIN");
  for (let i = 2; i <= 5002; i++) insert.run(i, "root", "opaque-" + i, "2026-11-01");
  db.exec("COMMIT");
  db.close();
  assert.throws(() => read(f), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
});

test("loopback HTTP fixture exposes only opaque partial evidence and generic failure", async (t) => {
  const f = makeFixture(t);
  const authorization = "fixture-only-not-production-secret";
  const server = http.createServer((req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Cache-Control", "no-store");
    if (req.method !== "GET" || req.url !== "/fixture/legacy-observation"
      || req.headers.authorization !== authorization) {
      res.writeHead(403); res.end('{"error":"UNAVAILABLE"}'); return;
    }
    try {
      const report = read(f);
      res.writeHead(200); res.end(JSON.stringify(report));
    } catch (_) {
      res.writeHead(503); res.end('{"error":"UNAVAILABLE"}');
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const endpoint = `http://127.0.0.1:${server.address().port}/fixture/legacy-observation`;
  const unauthorized = await fetch(endpoint);
  assert.equal(unauthorized.status, 403);
  const response = await fetch(endpoint, { headers: { authorization } });
  assert.equal(response.status, 200);
  const report = await response.json();
  ensureNotLeaked(report, f);
  assert.equal(report.legacy.coverage, "partial");
  assert.equal(report.authorizesCutover, false);

  const db = new DatabaseSync(f.databasePath);
  db.exec("DROP TABLE public_links");
  db.close();
  const denied = await fetch(endpoint, { headers: { authorization } });
  assert.equal(denied.status, 503);
  assert.deepEqual(await denied.json(), { error: "UNAVAILABLE" });
});
