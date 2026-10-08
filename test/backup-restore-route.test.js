const assert = require("node:assert/strict");
const test = require("node:test");
const registerBackupRoutes = require("../src/routes/backups");

test("committed restore cleanup failure returns restart-required service unavailable", async () => {
  let restoreHandler;
  const auditEvents = [];
  registerBackupRoutes({
    get() {},
    post(route, ...handlers) {
      if (route === "/backups/:id/restore") restoreHandler = handlers.at(-1);
    },
    delete() {},
  }, {
    auditLog(...event) { auditEvents.push(event); },
    authenticate() {},
    backupService: {},
    getAuditActor() { return { username: "fixture-manager" }; },
    requireBackupAccess() {},
    restoreService: {
      async restoreBackup() { throw new Error("injected staging cleanup failure"); },
      getWholeRestorePhase() { return "restart_required"; },
    },
    waitForRequestQuiescence: async () => true,
  });

  const response = {
    statusCode: null,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
  await restoreHandler({ params: { id: "00000000-0000-4000-8000-000000000000" }, body: { confirmation: "RESTORE" }, user: { username: "fixture-manager" } }, response);

  assert.equal(response.statusCode, 503);
  assert.equal(response.body.restartRequired, true);
  assert.equal(response.body.cleanupPending, true);
  assert.match(response.body.error, /limpeza temporária falhou/);
  assert.equal(auditEvents.at(-1)[0], "backup.restore.failed");
  assert.equal(auditEvents.at(-1)[4], "failure");
  assert.equal(auditEvents.at(-1)[5].error, "restore_recovery_pending");
  assert.equal(JSON.stringify(auditEvents.at(-1)[5]).includes("injected staging cleanup failure"), false);
});

test("backup HEAD metadata checks do not create download audit events", async () => {
  let downloadHandler;
  const auditEvents = [];
  registerBackupRoutes({
    get(route, ...handlers) {
      if (route === "/backups/:id/download") downloadHandler = handlers.at(-1);
    },
    post() {},
    delete() {},
  }, {
    auditLog(...event) { auditEvents.push(event); },
    authenticate() {},
    backupService: {
      getBackupOrThrow(id) { return { backup: { id, filename: "fixture.zip" }, archivePath: "/fixture.zip" }; },
    },
    getAuditActor() { return { username: "fixture-manager" }; },
    requireBackupAccess() {},
    restoreService: {},
    waitForRequestQuiescence: async () => true,
  });

  const response = { download(path, filename) { this.downloaded = { path, filename }; } };
  await downloadHandler({ method: "HEAD", params: { id: "fixture-id" } }, response);
  assert.deepEqual(auditEvents, [], "HEAD inspects the resource without claiming that bytes were downloaded");
  await downloadHandler({ method: "GET", params: { id: "fixture-id" } }, response);
  assert.equal(auditEvents.filter((event) => event[0] === "backup.downloaded").length, 1, "GET still records backup downloads");
});
