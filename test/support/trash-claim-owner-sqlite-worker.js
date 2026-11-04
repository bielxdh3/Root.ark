"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

if (process.env.DB_ENABLED !== "true") throw Error("SQLITE_TRASH_TEST_REQUIRED");
require("../../db/migrations").runMigrations({ backup: false });
const repo = require("../../repositories/trashRepository");
const service = require("../../services/trashService");

let counter = 0;
function queue() {
  const id = `fenced-remote-${++counter}`;
  const rel = path.join("files", id, "object.txt");
  const destination = path.join(process.cwd(), "data", "trash", rel);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, "old data");
  return service.queueRemoteDeletion({
    item: { id, itemType: "file", originalFolderId: "root",
      originalFileName: "object.txt", trashPath: rel, metadata: {},
      restoreMetadata: { versions: { versions: [] } }, status: "trashed" },
    deletedBy: "test", loaders: {}, provider: "s3",
  });
}

function reclaim(item) {
  const a = service.claimRemoteDeletion({ item, leaseMs: 1000, workerId: "A" });
  assert.ok(a);
  fs.utimesSync(a.path, new Date(0), new Date(0));
  const b = service.claimRemoteDeletion({ item, leaseMs: 1000, workerId: "B" });
  assert.ok(b);
  assert.notEqual(a.token, b.token);
  return { a, b };
}

{
  const item = queue();
  const { a, b } = reclaim(item);
  const stale = service.completeRemoteDeletion(a.item, { claimToken: a.token });
  assert.equal(stale.metadata.remoteDeletion.leaseToken, b.token);
  assert.equal(repo.getTrashItem(item.id).status, "remote_delete_pending");
  const finished = service.completeRemoteDeletion(b.item, { claimToken: b.token });
  assert.equal(finished.metadata.remoteDeletion.state, "completed");
}
{
  const item = queue();
  const { a, b } = reclaim(item);
  service.failRemoteDeletion(a.item, new Error("delayed provider"), { claimToken: a.token });
  const fresh = repo.getTrashItem(item.id);
  assert.equal(fresh.metadata.remoteDeletion.leaseToken, b.token);
  assert.equal(fresh.metadata.remoteDeletion.attempts, 0);
  service.failRemoteDeletion(b.item, new Error("actual failure"), { claimToken: b.token });
  assert.equal(repo.getTrashItem(item.id).metadata.remoteDeletion.attempts, 1);
}
{
  const item = queue();
  const a = service.claimRemoteDeletion({ item, leaseMs: 1000, workerId: "A" });
  assert.ok(a);
  service.cancelRemoteDeletion(repo.getTrashItem(item.id),
    "replacement_active", { status: "permanently_deleted" });
  service.completeRemoteDeletion(a.item, { claimToken: a.token });
  assert.equal(repo.getTrashItem(item.id).metadata.remoteDeletion.state, "cancelled");
}
process.stdout.write("SQLITE_REMOTE_CLAIM_FENCE_OK\n");
