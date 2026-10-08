const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const originalCwd = process.cwd();
const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-remote-"));
process.chdir(runtime);
process.env.DB_ENABLED = "false";
const trashRepository = require("../repositories/trashRepository");
const trashService = require("../services/trashService");

function item(id, fileName = "file.txt") {
  const relative = path.join("files", id, fileName);
  const absolute = path.join(runtime, "data", "trash", relative);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  fs.writeFileSync(absolute, "disposable");
  return { id, itemType: "file", originalFolderId: "root", originalFileName: fileName, trashPath: relative, metadata: {}, restoreMetadata: { versions: { versions: [] } }, status: "trashed" };
}

test("remote deletion remains pending until completion and survives JSON persistence", () => {
  const pending = trashService.queueRemoteDeletion({ item: item("11111111-1111-4111-8111-111111111111"), deletedBy: "tester", loaders: {} });
  assert.equal(pending.status, "remote_delete_pending");
  assert.equal(pending.metadata.remoteDeletion.state, "pending");
  assert.equal(fs.existsSync(path.join(runtime, "data", "trash", pending.trashPath)), false);
  const persisted = JSON.parse(fs.readFileSync(path.join(runtime, "data", "trash-items.json"), "utf8"));
  assert.equal(persisted[0].status, "remote_delete_pending");
  assert.equal(persisted[0].metadata.remoteDeletion.state, "pending");
});

test("trash repository finds pending deletion by exact file identity", () => {
  const matching = trashService.queueRemoteDeletion({ item: item("45454545-4545-4545-8545-454545454545", "target.txt"), deletedBy: "tester", loaders: {} });
  const differentFolder = trashService.queueRemoteDeletion({ item: { ...item("46464646-4646-4646-8646-464646464646", "target.txt"), originalFolderId: "other" }, deletedBy: "tester", loaders: {} });

  assert.deepEqual(
    trashRepository.listPendingFileRemoteDeletions("root", "target.txt").map((entry) => entry.id),
    [matching.id],
  );
  assert.equal(trashRepository.listPendingFileRemoteDeletions("other", "target.txt")[0].id, differentFolder.id);
});

test("failed retries are bounded and cannot falsely report permanent completion", () => {
  const pending = trashService.queueRemoteDeletion({ item: item("22222222-2222-4222-8222-222222222222"), deletedBy: "tester", loaders: {} });
  const failed = trashService.failRemoteDeletion(pending);
  assert.equal(failed.status, "remote_delete_pending");
  assert.equal(failed.metadata.remoteDeletion.state, "retry_wait");
  assert.equal(failed.metadata.remoteDeletion.attempts, 1);
  const completed = trashService.completeRemoteDeletion(failed);
  assert.equal(completed.status, "permanently_deleted");
  assert.equal(completed.metadata.remoteDeletion.state, "completed");
  assert.equal(trashService.completeRemoteDeletion(completed).status, "permanently_deleted");
});

test("remote deletion state machine preserves terminal and retry boundaries", async (t) => {
  await t.test("queueing a pending item is idempotent", () => {
    const pending = trashService.queueRemoteDeletion({ item: item("55555555-5555-4555-8555-555555555555"), deletedBy: "tester", loaders: {} });
    const queuedAgain = trashService.queueRemoteDeletion({ item: pending, deletedBy: "other", loaders: {} });
    assert.equal(queuedAgain, pending);
    assert.equal(queuedAgain.metadata.remoteDeletion.attempts, 0);
    assert.equal(queuedAgain.permanentlyDeletedBy, "tester");
  });

  await t.test("restored and completed items cannot be queued", () => {
    for (const [status, id] of [["restored", "66666666-6666-4666-8666-666666666666"], ["permanently_deleted", "66666666-6666-4666-8666-666666666667"]]) {
      const original = { ...item(id), status };
      assert.equal(trashService.queueRemoteDeletion({ item: original, deletedBy: "tester", loaders: {} }), original);
    }
  });

  await t.test("retry count caps at 25 and stores a generic failure marker", () => {
    let pending = trashService.queueRemoteDeletion({ item: item("77777777-7777-4777-8777-777777777777"), deletedBy: "tester", loaders: {} });
    for (let attempt = 0; attempt < 30; attempt += 1) pending = trashService.failRemoteDeletion(pending, new Error("provider detail must not persist"));
    assert.equal(pending.status, "remote_delete_pending");
    assert.equal(pending.metadata.remoteDeletion.attempts, 25);
    assert.equal(pending.metadata.remoteDeletion.state, "terminal_failure");
    assert.equal(pending.metadata.remoteDeletion.failureCategory, "provider_error");
    assert.equal(JSON.stringify(pending.metadata).includes("provider detail must not persist"), false);
  });

  await t.test("local-only completion has no remote state", () => {
    const completed = trashService.permanentlyDelete({ item: item("88888888-8888-4888-8888-888888888888"), deletedBy: "tester", loaders: {} });
    assert.equal(completed.status, "permanently_deleted");
    assert.equal(completed.metadata.remoteDeletion, undefined);
  });

  await t.test("completion keeps retry provenance while clearing a failure", () => {
    let pending = trashService.queueRemoteDeletion({ item: item("99999999-9999-4999-8999-999999999999"), deletedBy: "tester", loaders: {} });
    pending = trashService.failRemoteDeletion(pending);
    const completed = trashService.completeRemoteDeletion(pending);
    assert.equal(completed.metadata.remoteDeletion.attempts, 1);
    assert.equal(completed.metadata.remoteDeletion.state, "completed");
    assert.equal(completed.metadata.remoteDeletion.failureCategory, null);
    assert.ok(completed.metadata.remoteDeletion.completedAt);
  });

  await t.test("stale failure and completion cannot alter a restored item", () => {
    const restored = { ...item("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), status: "restored" };
    assert.equal(trashService.failRemoteDeletion(restored), restored);
    assert.equal(trashService.completeRemoteDeletion(restored), restored);
    assert.equal(restored.status, "restored");
  });

  await t.test("failed state can be reloaded from JSON without provider details", () => {
    let pending = trashService.queueRemoteDeletion({ item: item("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), deletedBy: "tester", loaders: {} });
    pending = trashService.failRemoteDeletion(pending, new Error("sensitive provider response"));
    const reloaded = trashRepository.getTrashItem(pending.id);
    assert.equal(reloaded.status, "remote_delete_pending");
    assert.equal(reloaded.metadata.remoteDeletion.state, "retry_wait");
    assert.equal(JSON.stringify(reloaded).includes("sensitive provider response"), false);
  });

  await t.test("all-status listing includes pending remote work", () => {
    const pending = trashService.queueRemoteDeletion({ item: item("cccccccc-cccc-4ccc-8ccc-cccccccccccc"), deletedBy: "tester", loaders: {} });
    assert.equal(trashRepository.listTrashItems({ status: "*" }).some((entry) => entry.id === pending.id), true);
    assert.equal(trashRepository.listTrashItems({ status: "remote_delete_pending" }).some((entry) => entry.id === pending.id), true);
  });
});

test("restored items cannot be converted by a stale queued operation", () => {
  const restored = { ...item("33333333-3333-4333-8333-333333333333"), status: "restored" };
  assert.equal(trashService.queueRemoteDeletion({ item: restored, deletedBy: "tester", loaders: {} }).status, "restored");
  assert.equal(trashService.completeRemoteDeletion(restored).status, "restored");
});

test("remote queue preserves lifecycle evidence for file variants", async (t) => {
  await t.test("queue records actor and queue timestamp", () => {
    const pending = trashService.queueRemoteDeletion({ item: item("dddddddd-dddd-4ddd-8ddd-dddddddddddd"), deletedBy: "actor", loaders: {} });
    assert.equal(pending.permanentlyDeletedBy, "actor");
    assert.ok(pending.permanentlyDeletedAt);
    assert.ok(pending.metadata.remoteDeletion.queuedAt);
  });

  await t.test("queue removes the disposable trash payload before remote completion", () => {
    const pending = trashService.queueRemoteDeletion({ item: item("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"), deletedBy: "tester", loaders: {} });
    assert.equal(fs.existsSync(path.join(runtime, "data", "trash", pending.trashPath)), false);
    assert.equal(pending.status, "remote_delete_pending");
  });

  await t.test("non-trashed items retain their metadata unchanged", () => {
    const original = { ...item("ffffffff-ffff-4fff-8fff-ffffffffffff"), status: "permanently_deleted", metadata: { marker: "keep" } };
    const result = trashService.queueRemoteDeletion({ item: original, deletedBy: "tester", loaders: {} });
    assert.deepEqual(result.metadata, { marker: "keep" });
  });

  await t.test("completed state is durable after a JSON reload", () => {
    const pending = trashService.queueRemoteDeletion({ item: item("12121212-1212-4121-8121-121212121212"), deletedBy: "tester", loaders: {} });
    const completed = trashService.completeRemoteDeletion(pending);
    const reloaded = trashRepository.getTrashItem(completed.id);
    assert.equal(reloaded.status, "permanently_deleted");
    assert.equal(reloaded.metadata.remoteDeletion.state, "completed");
  });
});

test("remote pending state persists through SQLite reopen", () => {
  const sqliteRuntime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-sqlite-"));
  const migrationPath = path.join(__dirname, "..", "db", "migrations");
  const repositoryPath = path.join(__dirname, "..", "repositories", "trashRepository");
  const servicePath = path.join(__dirname, "..", "services", "trashService");
  const script = [
    `process.chdir(${JSON.stringify(sqliteRuntime)});`,
    'process.env.DB_ENABLED = "true";',
    'process.env.DATABASE_URL = require("path").join(process.cwd(), "data", "rootark.sqlite");',
    `require(${JSON.stringify(migrationPath)}).runMigrations({ backup: false });`,
    `const repo = require(${JSON.stringify(repositoryPath)});`,
    `const service = require(${JSON.stringify(servicePath)});`,
    'const fs = require("fs"); const path = require("path");',
    'const id = "44444444-4444-4444-8444-444444444444"; const rel = path.join("files", id, "file.txt");',
    'const target = path.join(process.cwd(), "data", "trash", rel); fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, "x");',
    'service.queueRemoteDeletion({ item: { id, itemType: "file", originalFolderId: "root", originalFileName: "file.txt", trashPath: rel, metadata: {}, restoreMetadata: { versions: { versions: [] } }, status: "trashed" }, deletedBy: "tester", loaders: {} });',
    'console.log(JSON.stringify({ item: repo.getTrashItem(id), hidden: repo.isFileTrashed("root", "file.txt") }));',
  ].join(" ");
  const result = spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /"status":"remote_delete_pending"/);
  assert.match(result.stdout, /"state":"pending"/);
  assert.match(result.stdout, /"hidden":true/);
  fs.rmSync(sqliteRuntime, { recursive: true, force: true });
});

test.after(() => {
  process.chdir(originalCwd);
  fs.rmSync(runtime, { recursive: true, force: true });
});
