const assert = require("node:assert/strict");
const test = require("node:test");
const registerBackupRoutes = require("../src/routes/backups");

test("created backup with a post-processing failure returns a structured warning", async () => {
  let createHandler;
  const auditEvents = [];
  const backup = { id: "00000000-0000-4000-8000-000000000001", filename: "fixture.zip", status: "success" };
  const failure = Object.assign(new Error("internal storage path and failure details"), {
    backup,
    backupHistoryState: "durable",
    backupOperationState: "created-post-processing-failed",
    code: "RETENTION_LOCK_FAILED",
  });
  registerBackupRoutes({
    get() {},
    post(route, ...handlers) {
      if (route === "/backups") createHandler = handlers.at(-1);
    },
    delete() {},
  }, {
    auditLog(...event) { auditEvents.push(event); },
    authenticate() {},
    backupService: { async createBackup() { throw failure; } },
    getAuditActor() { return { username: "fixture-manager" }; },
    requireBackupAccess() {},
    restoreService: {},
    waitForRequestQuiescence: async () => true,
  });

  const response = {
    statusCode: null,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
  await createHandler({ body: {}, user: { username: "fixture-manager" } }, response);

  assert.equal(response.statusCode, 201);
  assert.equal(response.body.backup.id, backup.id);
  assert.equal(response.body.backupOperationState, "created-post-processing-failed");
  assert.match(response.body.warning, /backup criado/i);
  assert.equal(JSON.stringify(response.body).includes("internal storage path"), false);
  assert.equal(auditEvents.at(-1)[0], "backup.created");
  assert.equal(auditEvents.at(-1)[4], "partial");
  assert.equal(JSON.stringify(auditEvents.at(-1)[5]).includes("internal storage path"), false);
});

test("failed backup creation returns a stable error without filesystem details in response or audit", async () => {
  let createHandler;
  const auditEvents = [];
  const internalPath = "E:\\private-runtime\\data\\backup-history.json";
  const failure = Object.assign(new Error(`EACCES: permission denied, opening '${internalPath}'`), { code: "EACCES" });
  registerBackupRoutes({
    get() {},
    post(route, ...handlers) { if (route === "/backups") createHandler = handlers.at(-1); },
    delete() {},
  }, {
    auditLog(...event) { auditEvents.push(event); },
    authenticate() {},
    backupService: { async createBackup() { throw failure; } },
    getAuditActor() { return { username: "fixture-manager" }; },
    requireBackupAccess() {},
    restoreService: {},
    waitForRequestQuiescence: async () => true,
  });

  const response = {
    statusCode: null,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
  await createHandler({ body: {}, user: { username: "fixture-manager" } }, response);

  assert.equal(response.statusCode, 500);
  assert.deepEqual(response.body, { error: "Não foi possível criar o backup." });
  assert.equal(auditEvents.at(-1)[0], "backup.failed");
  assert.deepEqual(auditEvents.at(-1)[5], { errorCode: "EACCES" });
  assert.equal(JSON.stringify(response.body).includes(internalPath), false);
  assert.equal(JSON.stringify(auditEvents.at(-1)).includes(internalPath), false);
});

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

test("backup restore revalidates current authorization after request quiescence", async (t) => {
  const cases = [
    { name: "revoked session", status: 401, error: "Sessao invalida ou expirada" },
    { name: "removed backup permission", status: 403, error: "Permissao negada: manageBackups" },
    { name: "unavailable authorization store", status: 503, error: "Autorizacao indisponivel" },
  ];

  for (const scenario of cases) {
    await t.test(scenario.name, async () => {
      let restoreHandler;
      let releaseQuiescence;
      let markQuiescenceEntered;
      let authorizationRevoked = false;
      let restoreContinuedPastQuiescence = false;
      const quiescence = new Promise((resolve) => { releaseQuiescence = resolve; });
      const quiescenceEntered = new Promise((resolve) => { markQuiescenceEntered = resolve; });
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
        revalidateBackupAccess() {
          return authorizationRevoked ? scenario : null;
        },
        restoreService: {
          async restoreBackup(_id, options) {
            await options.waitForRequestQuiescence();
            await options.revalidateAuthorization();
            restoreContinuedPastQuiescence = true;
            return {
              backup: { id: "selected-backup" },
              preRestore: { id: "pre-restore-backup" },
              restartRecommended: true,
            };
          },
          getWholeRestorePhase() { return null; },
        },
        waitForRequestQuiescence: async () => {
          markQuiescenceEntered();
          await quiescence;
        },
      });

      const response = {
        statusCode: null,
        body: null,
        status(code) { this.statusCode = code; return this; },
        json(body) { this.body = body; return this; },
      };
      const restore = restoreHandler({
        params: { id: "selected-backup" },
        body: { confirmation: "RESTORE" },
        user: { username: "fixture-manager", permissions: { manageBackups: true }, sessionVersion: 0 },
      }, response);

      await quiescenceEntered;
      authorizationRevoked = true;
      releaseQuiescence();
      await restore;

      assert.equal(response.statusCode, scenario.status);
      assert.deepEqual(response.body, { error: scenario.error });
      assert.equal(restoreContinuedPastQuiescence, false, "restore must stop before its first mutation if current authorization cannot be confirmed");
      assert.equal(auditEvents.at(-1)[0], "backup.restore.failed");
      assert.equal(auditEvents.at(-1)[5].error, "RESTORE_AUTHORIZATION_REVOKED");
      assert.equal(auditEvents.some((event) => event[0] === "backup.restore.completed"), false);
    });
  }
});

test("backup restore reports a sanitized 503 when authorization cleanup is pending", async () => {
  let restoreHandler;
  const auditEvents = [];
  registerBackupRoutes({
    get() {},
    post(route, ...handlers) { if (route === "/backups/:id/restore") restoreHandler = handlers.at(-1); },
    delete() {},
  }, {
    auditLog(...event) { auditEvents.push(event); },
    authenticate() {},
    backupService: {},
    getAuditActor() { return { username: "fixture-manager" }; },
    requireBackupAccess() {},
    revalidateBackupAccess() { return null; },
    restoreService: {
      async restoreBackup() {
        throw Object.assign(new Error("Autorizacao revogada; a limpeza do backup temporario esta pendente"), {
          code: "RESTORE_AUTHORIZATION_REVOKED",
          statusCode: 503,
          authorizationCleanupPending: true,
        });
      },
      getWholeRestorePhase() { return null; },
    },
    waitForRequestQuiescence: async () => {},
  });

  const response = {
    statusCode: null,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
  await restoreHandler({ params: { id: "selected-backup" }, body: { confirmation: "RESTORE" }, user: { username: "fixture-manager" } }, response);

  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.body, {
    error: "Autorizacao revogada; a limpeza do backup temporario esta pendente",
    cleanupPending: true,
  });
  assert.equal(auditEvents.at(-1)[5].error, "RESTORE_AUTHORIZATION_REVOKED");
  assert.equal(auditEvents.at(-1)[5].cleanupPending, true);
  assert.doesNotMatch(JSON.stringify(auditEvents), /private cleanup failure|EIO/i);
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
