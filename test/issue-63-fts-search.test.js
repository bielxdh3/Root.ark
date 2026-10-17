const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-issue-63-fts-"));
process.env.DATABASE_URL = path.join(directory, "rootark.sqlite");
process.env.DB_ENABLED = "true";

const { closeDb, getDb } = require("../db");
const { runMigrations } = require("../db/migrations");
const repo = require("../repositories/fileSearchIndexRepository");

runMigrations({ backup: false });

function indexedNames(folderId = "root") {
  return getDb().prepare("SELECT file_name FROM file_search_index WHERE folder_id = ? ORDER BY file_name")
    .all(folderId).map((row) => row.file_name);
}

test.after(() => {
  closeDb();
  fs.rmSync(directory, { recursive: true, force: true });
});

test("migration 6 creates an FTS5 table with unicode61 diacritics tokenizer", () => {
  const row = getDb().prepare("SELECT sql FROM sqlite_master WHERE name = 'file_search_index'").get();
  assert.ok(row, "file_search_index table must exist");
  assert.match(row.sql, /fts5/i);
  assert.match(row.sql, /unicode61 remove_diacritics 2/);
  const applied = getDb().prepare("SELECT version FROM schema_migrations WHERE version = 6").get();
  assert.ok(applied);
});

test("hostile queries are treated as literal text and never throw or match everything", () => {
  repo.upsert("root", "relatorio-anual.pdf");
  repo.upsert("root", "notas.txt");
  const hostile = ['"', '*', 'OR', 'NEAR(', 'a" OR "b', '"*', 'NOT', '^', '(', ') AND', ':', '-x', "' OR 1=1 --"];
  for (const query of hostile) {
    assert.doesNotThrow(() => repo.search(query), `query ${JSON.stringify(query)} must not throw`);
    const hits = repo.search(query).map((hit) => hit.fileName);
    assert.ok(hits.length < 2, `query ${JSON.stringify(query)} must not match every file`);
  }
  assert.deepEqual(repo.search("OR").map((hit) => hit.fileName), []);
  assert.deepEqual(repo.search("*").map((hit) => hit.fileName), []);
  assert.deepEqual(repo.search("\"").map((hit) => hit.fileName), []);
});

test("buildMatchQuery quotes tokens, doubles quotes and returns null without word characters", () => {
  assert.equal(repo.buildMatchQuery('say "hi"'), '"say"* """hi"""*');
  assert.equal(repo.buildMatchQuery("   "), null);
  assert.equal(repo.buildMatchQuery("*** ^^^"), null);
  assert.equal(repo.buildMatchQuery("a b c d e f g h i j").split(" ").length, 8);
});

test("prefix matching and diacritic folding work through the index", () => {
  repo.upsert("root", "Relatório Final.docx");
  assert.ok(repo.search("relatorio").some((hit) => hit.fileName === "Relatório Final.docx"));
  assert.ok(repo.search("RELAT").some((hit) => hit.fileName === "Relatório Final.docx"));
  assert.ok(repo.search("relatório").some((hit) => hit.fileName === "Relatório Final.docx"));
});

test("upsert, remove and rename keep the index consistent", () => {
  repo.upsert("root", "old-name.txt");
  repo.upsert("root", "old-name.txt");
  assert.equal(indexedNames().filter((name) => name === "old-name.txt").length, 1);
  repo.rename("root", "old-name.txt", "new-name.txt");
  assert.ok(indexedNames().includes("new-name.txt"));
  assert.ok(!indexedNames().includes("old-name.txt"));
  repo.remove("root", "new-name.txt");
  assert.ok(!indexedNames().includes("new-name.txt"));
});

test("search is scoped by folder and honours the folder argument", () => {
  repo.upsert("folderA", "shared-report.csv");
  repo.upsert("folderB", "shared-report.csv");
  const onlyA = repo.search("shared", 100, "folderA");
  assert.deepEqual(onlyA.map((hit) => hit.folderId), ["folderA"]);
});

test("syncFolder never inserts protected (encrypted) names and reconciles stale rows", () => {
  const encrypted = new Set(["secret-plan.pdf"]);
  const isProtected = (name) => encrypted.has(name);
  repo.syncFolder("vault", ["secret-plan.pdf", "public-plan.pdf"], isProtected);
  assert.deepEqual(indexedNames("vault"), ["public-plan.pdf"]);
  assert.deepEqual(repo.search("secret", 100, "vault"), []);
  assert.deepEqual(repo.search("plan", 100, "vault").map((hit) => hit.fileName), ["public-plan.pdf"]);

  // A file that later becomes protected must be removed from the index.
  repo.syncFolder("vault", ["public-plan.pdf"], (name) => name === "public-plan.pdf");
  assert.deepEqual(indexedNames("vault"), []);

  // Stale entries for files that disappeared are removed on the next sync.
  repo.syncFolder("vault", ["fresh.txt"]);
  assert.deepEqual(indexedNames("vault"), ["fresh.txt"]);
});
