"use strict";

const assert = require("node:assert/strict");
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
