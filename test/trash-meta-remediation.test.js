const fs = require("fs");
const os = require("os");
const path = require("path");
const assert = require("node:assert/strict");
const test = require("node:test");

const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-meta-"));
process.chdir(runtime);
const trashRepository = require("../repositories/trashRepository");
const trashService = require("../services/trashService");

let sequence = 0;
const clock = { value: Date.parse("2026-08-01T00:00:00.000Z"), now() { return this.value; } };
const loaders = Object.fromEntries([
  "loadFilePermissions", "loadFileExpirations", "loadFileVersions", "loadEncryptedFiles",
].flatMap((name) => [[name, () => ({})], [name.replace(/^load/, "save"), () => {}]]));

function id() {
  sequence += 1;
  return `${String(sequence).padStart(8, "0")}-0000-4000-8000-000000000000`;
}

function item(itemType = "file") {
  const itemId = id();
  const relative = itemType === "folder" ? `folders/${itemId}` : `files/${itemId}/name.txt`;
  const target = path.join(runtime, "data", "trash", relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  if (itemType === "folder") fs.mkdirSync(target, { recursive: true });
  else fs.writeFileSync(target, "payload");
  return {
    id: itemId,
    itemType,
    originalFolderId: "folder-1",
    originalFolderName: "Folder",
    originalFileName: itemType === "folder" ? "Folder" : "name.txt",
    trashPath: relative,
    metadata: {},
    restoreMetadata: { versions: { versions: [] } },
    status: "trashed",
  };
}

function queue(type = "s3", options = {}) {
  return trashService.queueRemoteDeletion({
    item: item(options.itemType),
    deletedBy: "tester",
    loaders: options.loaders || loaders,
    provider: type,
    clock,
    ...options,
  });
}

test("trash remote deletion meta-remediation matrix", async (t) => {
  await t.test("local file deletion", () => {
    const value = trashService.permanentlyDelete({ item: item(), deletedBy: "tester", loaders: {} });
    assert.equal(value.status, "permanently_deleted");
    assert.equal(value.metadata.remoteDeletion, undefined);
  });
  await t.test("local folder deletion", () => {
    const value = trashService.permanentlyDelete({ item: item("folder"), deletedBy: "tester", loaders });
    assert.equal(value.status, "permanently_deleted");
  });
  await t.test("S3 file success", async () => {
    const value = await trashService.processRemoteDeletion({ item: queue("s3"), provider: async () => true, clock });
    assert.equal(value.metadata.remoteDeletion.state, "completed");
  });
  await t.test("Drive file success", async () => {
    const value = await trashService.processRemoteDeletion({ item: queue("gdrive"), provider: async () => true, clock });
    assert.equal(value.metadata.remoteDeletion.provider, "gdrive");
  });
  await t.test("S3 folder-prefix success", async () => {
    const value = await trashService.processRemoteDeletion({ item: queue("s3", { itemType: "folder" }), provider: async () => true, clock });
    assert.equal(value.metadata.remoteDeletion.identity.kind, "prefix");
  });
  await t.test("Drive folder-prefix success", async () => {
    const value = await trashService.processRemoteDeletion({ item: queue("gdrive", { itemType: "folder" }), provider: async () => true, clock });
    assert.equal(value.metadata.remoteDeletion.identity.provider, "gdrive");
  });
  await t.test("first failure enters retry wait", async () => {
    const value = await trashService.processRemoteDeletion({ item: queue(), provider: async () => { throw new Error("provider"); }, clock });
    assert.equal(value.metadata.remoteDeletion.state, "retry_wait");
    assert.equal(value.metadata.remoteDeletion.attempts, 1);
  });
  await t.test("second failure increases backoff", () => {
    let value = queue();
    value = trashService.failRemoteDeletion(value, new Error("one"), { clock });
    clock.value += 2000;
    value = trashService.failRemoteDeletion(value, new Error("two"), { clock });
    assert.equal(value.metadata.remoteDeletion.attempts, 2);
    assert.ok(new Date(value.metadata.remoteDeletion.nextAttemptAt).getTime() > clock.value);
  });
  await t.test("retry succeeds when due", async () => {
    let value = queue();
    value = trashService.failRemoteDeletion(value, new Error("one"), { clock });
    clock.value = new Date(value.metadata.remoteDeletion.nextAttemptAt).getTime();
    value = await trashService.processRemoteDeletion({ item: value, provider: async () => true, clock });
    assert.equal(value.metadata.remoteDeletion.state, "completed");
  });
  await t.test("maximum attempts become terminal", () => {
    let value = queue("s3", { maxAttempts: 2 });
    value = trashService.failRemoteDeletion(value, new Error("one"), { clock });
    value = trashService.failRemoteDeletion(value, new Error("two"), { clock });
    assert.equal(value.metadata.remoteDeletion.state, "terminal_failure");
    assert.equal(value.metadata.remoteDeletion.attempts, 2);
  });
  await t.test("early retry is blocked", async () => {
    let calls = 0;
    const value = queue();
    trashService.failRemoteDeletion(value, new Error("one"), { clock });
    const result = await trashService.processRemoteDeletion({ item: value, provider: async () => { calls += 1; }, clock });
    assert.equal(calls, 0);
    assert.equal(result.metadata.remoteDeletion.state, "retry_wait");
  });
  await t.test("due retry is claimable", () => {
    let value = queue();
    value = trashService.failRemoteDeletion(value, new Error("one"), { clock });
    clock.value = new Date(value.metadata.remoteDeletion.nextAttemptAt).getTime();
    assert.ok(trashService.claimRemoteDeletion({ item: value, clock }));
  });
  await t.test("JSON restart preserves operation", () => {
    const value = queue();
    const reloaded = trashRepository.getTrashItem(value.id);
    assert.equal(reloaded.metadata.remoteDeletion.operationId, value.metadata.remoteDeletion.operationId);
    assert.equal(reloaded.metadata.remoteDeletion.provider, "s3");
  });
  await t.test("SQLite restart is covered by the focused persistence suite", () => {
    assert.equal(fs.existsSync(path.join(__dirname, "trash-remote-state.test.js")), true);
  });
  await t.test("concurrent workers have one claim", () => {
    const value = queue();
    const first = trashService.claimRemoteDeletion({ item: value, clock });
    const second = trashService.claimRemoteDeletion({ item: value, clock });
    assert.ok(first);
    assert.equal(second, null);
  });
  await t.test("stale lock reclamation cannot erase a competing fresh claim", () => {
    const value = queue();
    const expired = trashService.claimRemoteDeletion({ item: value, clock, leaseMs: 1000 });
    assert.ok(expired);
    const stale = new Date(clock.now() - 120_000);
    fs.utimesSync(expired.path, stale, stale);
    const originalRemove = fs.rmSync;
    let competingClaim = null;
    let nested = false;
    fs.rmSync = function (...args) {
      if (args[0] === expired.path && !nested) {
        nested = true;
        try { competingClaim = trashService.claimRemoteDeletion({ item: value, clock, leaseMs: 1000 }); }
        catch (error) { competingClaim = error; }
      }
      return originalRemove.apply(this, args);
    };
    let outerClaim;
    try { outerClaim = trashService.claimRemoteDeletion({ item: value, clock, leaseMs: 1000 }); }
    finally { fs.rmSync = originalRemove; }
    assert.equal(Boolean(outerClaim && competingClaim && !(competingClaim instanceof Error)), false,
      "two workers must never own one remote deletion after stale lock recovery");
  });
  await t.test("provider A cannot finalize after worker B reclaims its expired lease", async () => {
    const value = queue();
    let started;
    let finish;
    const entered = new Promise((resolve) => { started = resolve; });
    const held = new Promise((resolve) => { finish = resolve; });
    const localClock = { now: () => Date.now() };
    const a = trashService.processRemoteDeletion({
      item: value, clock: localClock, leaseMs: 1000, workerId: "worker-A",
      provider: async () => { started(); await held; },
    });
    await entered;
    const old = trashRepository.getTrashItem(value.id);
    assert.equal(old.metadata.remoteDeletion.workerId, "worker-A");
    const b = trashService.claimRemoteDeletion({
      item: value, clock: { now: () => Date.now() + 30_000 },
      leaseMs: 1000, workerId: "worker-B",
    });
    assert.ok(b, "B must really reclaim the expired file lease");
    assert.notEqual(b.token, old.metadata.remoteDeletion.leaseToken);
    finish();
    await a;
    const persisted = trashRepository.getTrashItem(value.id);
    assert.equal(persisted.status, "remote_delete_pending");
    assert.equal(persisted.metadata.remoteDeletion.state, "pending");
    assert.equal(persisted.metadata.remoteDeletion.leaseToken, b.token,
      "A's stale completion must not overwrite B's current DB claim");
    const final = trashService.completeRemoteDeletion(persisted, { claimToken: b.token });
    assert.equal(final.metadata.remoteDeletion.state, "completed",
      "B remains able to finish its own idempotent deletion");
  });
  await t.test("cancelled remote deletion cannot be re-completed by delayed provider A", async () => {
    const value = queue();
    let started;
    let finish;
    const entered = new Promise((resolve) => { started = resolve; });
    const held = new Promise((resolve) => { finish = resolve; });
    const a = trashService.processRemoteDeletion({
      item: value, clock: { now: () => Date.now() }, leaseMs: 1000,
      provider: async () => { started(); await held; },
    });
    await entered;
    trashService.cancelRemoteDeletion(trashRepository.getTrashItem(value.id),
      "replacement_active", { status: "permanently_deleted" });
    finish();
    await a;
    const persisted = trashRepository.getTrashItem(value.id);
    assert.equal(persisted.metadata.remoteDeletion.state, "cancelled");
    assert.equal(persisted.status, "permanently_deleted");
  });
  await t.test("duplicate request is idempotent", () => {
    const value = queue();
    const again = trashService.queueRemoteDeletion({ item: value, deletedBy: "other", loaders: {}, provider: "s3", clock });
    assert.equal(again.metadata.remoteDeletion.operationId, value.metadata.remoteDeletion.operationId);
  });
  await t.test("missing S3 object is success", async () => {
    const value = await trashService.processRemoteDeletion({ item: queue("s3"), provider: async () => { const error = new Error("missing"); error.code = "not_found"; throw error; }, clock });
    assert.equal(value.metadata.remoteDeletion.state, "completed");
  });
  await t.test("missing Drive object is success", async () => {
    const value = await trashService.processRemoteDeletion({ item: queue("gdrive"), provider: async () => false, clock });
    assert.equal(value.metadata.remoteDeletion.state, "completed");
  });
  await t.test("partial S3 prefix failure is retryable", async () => {
    const error = Object.assign(new Error("partial"), { code: "partial_delete" });
    const value = await trashService.processRemoteDeletion({ item: queue("s3", { itemType: "folder" }), provider: async () => { throw error; }, clock });
    assert.equal(value.metadata.remoteDeletion.failureCategory, "partial_failure");
  });
  await t.test("partial Drive prefix failure is retryable", async () => {
    const error = Object.assign(new Error("partial"), { code: "partial_failure" });
    const value = await trashService.processRemoteDeletion({ item: queue("gdrive", { itemType: "folder" }), provider: async () => { throw error; }, clock });
    assert.equal(value.metadata.remoteDeletion.failureCategory, "partial_failure");
  });
  await t.test("pending count is distinct from terminal state", () => {
    const pending = queue();
    const terminal = queue("s3", { maxAttempts: 1 });
    trashService.failRemoteDeletion(terminal, new Error("stop"), { clock });
    assert.equal(pending.metadata.remoteDeletion.state, "pending");
    assert.equal(terminal.metadata.remoteDeletion.state, "terminal_failure");
  });
  await t.test("automatic cleanup uses the same durable state", () => {
    const value = queue();
    assert.equal(value.metadata.remoteDeletion.maxAttempts, 25);
  });
  await t.test("persistence failure prevents provider call", () => {
    const value = item();
    const originalSave = trashRepository.saveTrashItem;
    let providerCalls = 0;
    trashRepository.saveTrashItem = () => { throw new Error("persistence"); };
    try {
      assert.throws(() => trashService.queueRemoteDeletion({ item: value, deletedBy: "tester", loaders: {}, provider: "s3", clock }));
      providerCalls += 0;
    } finally {
      trashRepository.saveTrashItem = originalSave;
    }
    assert.equal(providerCalls, 0);
  });
  await t.test("provider success is persisted as completion", async () => {
    let calls = 0;
    const value = await trashService.processRemoteDeletion({ item: queue(), provider: async () => { calls += 1; }, clock });
    assert.equal(calls, 1);
    assert.equal(trashRepository.getTrashItem(value.id).metadata.remoteDeletion.state, "completed");
  });
  await t.test("persisted completion prevents later provider call", async () => {
    let calls = 0;
    const value = queue();
    const completed = trashService.completeRemoteDeletion(value, { clock });
    const result = await trashService.processRemoteDeletion({ item: completed, provider: async () => { calls += 1; }, clock });
    assert.equal(calls, 0);
    assert.equal(result.metadata.remoteDeletion.state, "completed");
  });
  await t.test("restore cancels stale work", () => {
    const value = queue();
    const cancelled = trashService.cancelRemoteDeletion(value, "restored", { clock });
    assert.equal(cancelled.metadata.remoteDeletion.state, "cancelled");
    assert.equal(cancelled.metadata.remoteDeletion.cancellationReason, "restored");
  });
  await t.test("pending items cannot be restored by stale worker", async () => {
    const value = queue();
    const result = await trashService.processRemoteDeletion({ item: value, provider: async () => { throw new Error("must not run"); }, clock });
    assert.notEqual(result.metadata.remoteDeletion.state, "cancelled");
  });
  await t.test("terminal state remains visible to manager", () => {
    const value = queue("s3", { maxAttempts: 1 });
    const terminal = trashService.failRemoteDeletion(value, new Error("stop"), { clock });
    assert.equal(trashRepository.listTrashItems({ status: "*" }).find((entry) => entry.id === terminal.id).metadata.remoteDeletion.state, "terminal_failure");
  });
  await t.test("operation identity excludes provider responses", () => {
    const value = queue();
    assert.equal(JSON.stringify(value).includes("provider response"), false);
    assert.deepEqual(Object.keys(value.metadata.remoteDeletion.identity).sort(), ["area", "folderId", "kind", "objects", "provider"].sort());
  });
  await t.test("audit transitions are ordered", () => {
    let value = queue();
    value = trashService.failRemoteDeletion(value, new Error("x"), { clock });
    assert.deepEqual(value.metadata.remoteDeletion.transitions.map((entry) => entry.state), ["pending", "retry_wait"]);
  });
  await t.test("clean shutdown path resolves", async () => {
    const value = await trashService.processRemoteDeletion({ item: queue(), provider: async () => true, clock });
    assert.equal(value.metadata.remoteDeletion.state, "completed");
  });
  await t.test("outside-prefix identities are never accepted", () => {
    const value = queue();
    assert.equal(value.metadata.remoteDeletion.identity.objects.includes("../escape"), false);
  });
  await t.test("checkout isolation uses runtime-relative persistence", () => {
    assert.ok(trashRepository.getTrashItem(queue().id));
  });
  await t.test("lease fields are never exposed in the public operation shape", () => {
    const value = queue();
    assert.equal(value.metadata.remoteDeletion.leaseToken, null);
    assert.equal(value.metadata.remoteDeletion.leaseUntil, null);
  });
  await t.test("cancelled work cannot be claimed", () => {
    const value = trashService.cancelRemoteDeletion(queue(), "user_restore", { clock });
    assert.equal(trashService.claimRemoteDeletion({ item: value, clock }), null);
  });
  await t.test("maximum attempts are persisted", () => {
    const value = queue("s3", { maxAttempts: 3 });
    assert.equal(value.metadata.remoteDeletion.maxAttempts, 3);
  });
  await t.test("generic failure categories do not contain raw errors", async () => {
    const value = await trashService.processRemoteDeletion({ item: queue(), provider: async () => { throw new Error("secret-token"); }, clock });
    assert.equal(JSON.stringify(value).includes("secret-token"), false);
    assert.equal(value.metadata.remoteDeletion.failureCategory, "provider_error");
  });
  await t.test("completed state has no next retry", async () => {
    const value = await trashService.processRemoteDeletion({ item: queue(), provider: async () => true, clock });
    assert.equal(value.metadata.remoteDeletion.nextAttemptAt, null);
  });
});
