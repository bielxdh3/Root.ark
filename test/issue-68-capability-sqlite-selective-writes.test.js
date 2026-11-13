"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

test("issue 68: stale legacy snapshots never revoke newer capability or erase admitted SQLite sessions", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-capability-sql-selective-"));
  const previous = { DB_ENABLED: process.env.DB_ENABLED, DATABASE_URL: process.env.DATABASE_URL };
  process.env.DB_ENABLED = "true";
  process.env.DATABASE_URL = path.join(dir, "rootark.sqlite");
  const { closeDb } = require("../db");
  const { runMigrations } = require("../db/migrations");
  const repository = require("../repositories/publicLinksRepository");
  t.after(() => {
    closeDb();
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  });
  runMigrations({ backup: false });

  const a = `C${"a".repeat(47)}`;
  const b = `C${"b".repeat(47)}`;
  const c = `C${"c".repeat(47)}`;
  const binding = { version: 2, folderId: "root", fileName: "safe.txt", identity: "e".repeat(64) };
  const entry = () => ({ fileName: "safe.txt", folderId: "root", shareKind: "capability-v1",
    resourceBinding: binding, createdBy: "tester", createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
    permissions: ["download"], maxViews: 0, maxDownloads: 3, views: 0, downloads: 0,
    capabilitySessions: {}, activeViewers: {} });

  repository.savePublicLinks({ [a]: entry() });
  const staleSnapshot = repository.loadPublicLinks();
  const alias = "1".repeat(32);
  const session = { alias, hash: "f".repeat(64), expiresAt: new Date(Date.now() + 2 * 60_000).toISOString(),
    expectedResourceBinding: binding, expectedFileName: "safe.txt", expectedFolderId: "root" };
  assert.equal(repository.addCapabilitySession(a, session).status, "ok",
    "genuinely committed session exists before stale writer replays its old snapshot");
  assert.ok(repository.loadPublicLinks()[a].capabilitySessions[alias]);
  repository.savePublicLinks({ ...staleSnapshot, [b]: entry() });
  repository.savePublicLinks(staleSnapshot);

  const afterLegacyWrite = repository.loadPublicLinks();
  assert.ok(afterLegacyWrite[a]?.capabilitySessions?.[alias],
    "legacy whole-map write must not roll back the independently committed session");
  assert.ok(afterLegacyWrite[b],
    "stale whole-map write must not silently revoke newly inserted capability B");
  assert.equal(repository.createCapability(c, entry()).status, "ok");
  assert.ok(repository.loadPublicLinks()[c]);
  assert.equal(repository.revokeCapability(a, "outsider").status, "forbidden");
  assert.ok(repository.loadPublicLinks()[a]);
  assert.equal(repository.revokeCapability(a, "tester").status, "ok");
  assert.equal(repository.loadPublicLinks()[a], undefined, "revoke must persist as tombstone");
  assert.ok(repository.loadPublicLinks()[b], "revoking A may not revoke unrelated B");
  assert.ok(repository.loadPublicLinks()[c], "revoking A may not revoke independently created C");
  assert.equal(repository.addCapabilitySession(a, session).status, "missing",
    "revoked capability cannot acquire another session");
  assert.equal(repository.createCapability(a, entry()).status, "collision",
    "revoked token cannot be reissued by stale database insert");
});

test("issue 68 P1: explicit file and folder trash revokes only affected SQLite capabilities", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-capability-trash-revoke-"));
  const previous = { DB_ENABLED: process.env.DB_ENABLED, DATABASE_URL: process.env.DATABASE_URL };
  process.env.DB_ENABLED = "true";
  process.env.DATABASE_URL = path.join(dir, "trash.sqlite");
  const { closeDb } = require("../db");
  const { runMigrations } = require("../db/migrations");
  const repository = require("../repositories/publicLinksRepository");
  t.after(() => {
    closeDb();
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  });
  runMigrations({ backup: false });

  const [fileA, fileB, late, unrelated] = ["1", "2", "3", "4"]
    .map((digit) => `C${digit.repeat(47)}`);
  const entry = (folderId, fileName) => ({
    fileName, folderId, shareKind: "capability-v1",
    resourceBinding: { version: 2, folderId, fileName, identity: "e".repeat(64) },
    createdBy: "tester", createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
    permissions: ["download"], maxViews: 0, views: 0, capabilitySessions: {},
  });
  const a = entry("trashed-folder", "a.txt");
  const b = entry("trashed-folder", "b.txt");
  const c = entry("other-folder", "a.txt");
  assert.equal(repository.createCapability(fileA, a).status, "ok");
  assert.equal(repository.createCapability(fileB, b).status, "ok");
  assert.equal(repository.createCapability(unrelated, c).status, "ok");

  const staleBeforeTrash = repository.loadPublicLinks();
  const withoutA = { ...staleBeforeTrash };
  delete withoutA[fileA];
  repository.savePublicLinks(withoutA,
    { capabilityRevocation: { folderId: "trashed-folder", fileName: "a.txt" } });
  assert.equal(repository.loadPublicLinks()[fileA], undefined,
    "explicit file trash must revoke even an unexpired C-prefixed capability");
  assert.ok(repository.loadPublicLinks()[fileB], "file trash must not revoke sibling capabilities");
  assert.ok(repository.loadPublicLinks()[unrelated], "file trash must not revoke other folders");

  // A second writer creates a new capability after the folder-trash caller's
  // snapshot was taken. Explicit folder revocation must cover it as well.
  const oldFolderSnapshot = repository.loadPublicLinks();
  assert.equal(repository.createCapability(late, entry("trashed-folder", "late.txt")).status, "ok");
  const withoutFolder = { [unrelated]: oldFolderSnapshot[unrelated] };
  repository.savePublicLinks(withoutFolder,
    { capabilityRevocation: { folderId: "trashed-folder" } });
  const after = repository.loadPublicLinks();
  for (const token of [fileA, fileB, late]) {
    assert.equal(after[token], undefined,
      "explicit folder trash must revoke every matching token, including a concurrent grant");
  }
  assert.ok(after[unrelated], "other folder's grant remains valid");
  repository.savePublicLinks(staleBeforeTrash);
  assert.equal(repository.loadPublicLinks()[fileA], undefined, "a stale snapshot cannot resurrect a revoked grant");
  assert.equal(repository.createCapability(fileA, a).status, "collision",
    "revoked capability token can never be reissued");
});

test("issue 68 P1: real folder trash and restore never reactivate a revoked SQLite capability", (t) => {
  // Run the actual trash service in a disposable runtime root: its paths are
  // bound to process.cwd() at module load, never the checked-out repository.
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-capability-trash-lifecycle-"));
  t.after(() => fs.rmSync(sandbox, { recursive: true, force: true }));
  const root = path.resolve(__dirname, "..");
  const script = `
    "use strict";
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const path = require("node:path");
    const root = ${JSON.stringify(root)};
    const { runMigrations } = require(path.join(root, "db/migrations"));
    const repository = require(path.join(root, "repositories/publicLinksRepository"));
    const trash = require(path.join(root, "services/trashService"));
    runMigrations({ backup: false });
    const folder = { id: "capfolder", name: "Confidential", isRoot: false,
      uploadDir: path.join(process.cwd(), "uploads", "capfolder"),
      tempDir: path.join(process.cwd(), "temp", "capfolder") };
    fs.mkdirSync(folder.uploadDir, { recursive: true });
    fs.mkdirSync(folder.tempDir, { recursive: true });
    fs.mkdirSync(path.join(process.cwd(), "data"), { recursive: true });
    fs.writeFileSync(path.join(folder.uploadDir, "a.txt"), "durable content");
    let folders = [folder];
    const empty = () => ({});
    const loaders = {
      loadFolders: () => folders,
      saveFolders: (next) => { folders = next; },
      loadFilePermissions: empty, saveFilePermissions: () => {},
      loadFileExpirations: empty, saveFileExpirations: () => {},
      loadFileVersions: empty, saveFileVersions: () => {},
      loadEncryptedFiles: empty, saveEncryptedFiles: () => {},
      loadPublicLinks: () => repository.loadPublicLinks(),
      savePublicLinks: (entries, options) => repository.savePublicLinks(entries, options),
    };
    const token = "C" + "a".repeat(47);
    const otherToken = "C" + "b".repeat(47);
    const make = (folderId) => ({ folderId, fileName: "a.txt", shareKind: "capability-v1",
      resourceBinding: { version: 2, folderId, fileName: "a.txt", identity: "d".repeat(64) },
      createdBy: "owner", createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 600000).toISOString(), permissions: ["download"] });
    assert.equal(repository.createCapability(token, make(folder.id)).status, "ok");
    assert.equal(repository.createCapability(otherToken, make("unrelated")).status, "ok");
    const removed = trash.moveFolderToTrash({ folder, deletedBy: "owner", loaders });
    assert.equal(removed.status, "trashed");
    assert.equal(repository.loadPublicLinks()[token], undefined,
      "the real trash lifecycle must revoke active capability grants");
    assert.ok(repository.loadPublicLinks()[otherToken], "unrelated grant survives");
    const restored = trash.restoreFolder({ item: removed, restoredBy: "owner", loaders });
    assert.equal(restored.status, "restored");
    assert.equal(fs.readFileSync(path.join(process.cwd(), "uploads", "capfolder", "a.txt"), "utf8"),
      "durable content", "the physical file really was restored");
    assert.equal(repository.loadPublicLinks()[token], undefined,
      "returning the same physical file and folder cannot resurrect its revoked bearer");
    assert.equal(repository.createCapability(token, make(folder.id)).status, "collision");
    assert.ok(repository.loadPublicLinks()[otherToken]);
    console.log("LIFECYCLE_PASS");
  `;
  const result = execFileSync(process.execPath, ["-e", script], {
    cwd: sandbox,
    env: { ...process.env, DB_ENABLED: "true", DATABASE_URL: path.join(sandbox, "rootark.sqlite") },
    timeout: 20_000, windowsHide: true, encoding: "utf8",
  });
  assert.match(result, /LIFECYCLE_PASS/);
});
