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

function matchedNames(query, folderId = null) {
  return repo.search(query, 50000, folderId).map((hit) => hit.fileName);
}

test.after(() => {
  closeDb();
  fs.rmSync(directory, { recursive: true, force: true });
});

test("migration 6 creates a trigram FTS5 table with case folding", () => {
  const row = getDb().prepare("SELECT sql FROM sqlite_master WHERE name = 'file_search_index'").get();
  assert.ok(row, "file_search_index table must exist");
  assert.match(row.sql, /fts5/i);
  assert.match(row.sql, /trigram/);
  assert.match(row.sql, /case_sensitive 0/);
  assert.ok(getDb().prepare("SELECT version FROM schema_migrations WHERE version = 6").get());
});

test("substring query 'ort' matches report.pdf even when other files also match", () => {
  repo.upsert("root", "report.pdf");
  repo.upsert("root", "ortografia.txt");
  repo.upsert("root", "notas.txt");
  const hits = matchedNames("ort", "root");
  assert.ok(hits.includes("report.pdf"), "substring match must not be dropped");
  assert.ok(hits.includes("ortografia.txt"));
  assert.ok(!hits.includes("notas.txt"));
});

test("queries shorter than 3 characters produce no index query (callers use the full scan)", () => {
  assert.equal(repo.buildMatchQuery("ab"), null);
  assert.equal(repo.buildMatchQuery("é"), null);
  assert.deepEqual(repo.search("ab"), []);
  assert.equal(typeof repo.buildMatchQuery("abc"), "string");
});

test("phrase quoting keeps operators and quotes literal", () => {
  assert.equal(repo.buildMatchQuery('say "hi"'), '"say ""hi"""');
  assert.equal(repo.buildMatchQuery("a OR b"), '"a OR b"');
});

test("hostile inputs (%, _, backslash, quotes, *, operators) never throw or match everything", () => {
  repo.upsert("root", "100%_final-draft.txt");
  repo.upsert("root", "plain-notes.md");
  const hostile = ["%%%", "___", "\\\\\\", '"""', "***", "OR OR", "NEAR(", '" OR "x', "%_\\", "a\"b*c", "' OR 1=1 --"];
  for (const query of hostile) {
    assert.doesNotThrow(() => repo.search(query), `query ${JSON.stringify(query)} must not throw`);
    assert.ok(!matchedNames(query).includes("plain-notes.md"), `query ${JSON.stringify(query)} must not match unrelated files`);
  }
  // Literal percent/underscore/backslash are matched as text, not as LIKE wildcards.
  assert.ok(matchedNames("%_final").includes("100%_final-draft.txt"));
  assert.deepEqual(matchedNames("\\\\draft"), []);
  assert.deepEqual(matchedNames("%%%"), []);
  assert.deepEqual(matchedNames("___"), []);
  assert.deepEqual(matchedNames('"""'), []);
});

test("case-insensitive substring matching through the index", () => {
  repo.upsert("root", "Relatório Final.docx");
  assert.ok(matchedNames("RELAT").includes("Relatório Final.docx"));
  assert.ok(matchedNames("relatório").includes("Relatório Final.docx"));
});

test("index candidates are a superset of old includes() matches", () => {
  const names = [
    "Contrato 2024.pdf", "fotos_ferias.zip", "backup-ORT-2023.tar", "orthodox.md",
    "relatorio-anual.pdf", "data (copy).csv", "x.y.z", "rapport.doc",
  ];
  for (const name of names) repo.upsert("parity", name);
  for (const query of ["ort", "contrato", "fotos_", "copy)", "y.z", "ANU", "2024.p"]) {
    const expected = names.filter((name) => name.toLowerCase().includes(query.toLowerCase()));
    const candidates = new Set(matchedNames(query, "parity"));
    for (const name of expected) {
      assert.ok(candidates.has(name), `query ${query} must keep candidate ${name}`);
    }
  }
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

test("search is scoped by folder", () => {
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
  assert.deepEqual(matchedNames("secret", "vault"), []);
  assert.deepEqual(matchedNames("plan", "vault"), ["public-plan.pdf"]);

  // A file that later becomes protected must be removed from the index.
  repo.syncFolder("vault", ["public-plan.pdf"], (name) => name === "public-plan.pdf");
  assert.deepEqual(indexedNames("vault"), []);

  // Stale entries for files that disappeared are removed on the next sync.
  repo.syncFolder("vault", ["fresh.txt"]);
  assert.deepEqual(indexedNames("vault"), ["fresh.txt"]);
});
