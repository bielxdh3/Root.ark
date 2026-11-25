const {
  assert, bcrypt, crypto, Database, fs, http, net, os, path, spawn, spawnSync, test,
  createFileLifecycleLock, classifyProcessOwner, createChunkUploadQuotaService, getCurrentProcessIdentity, ensureWindowsChunkUploadRoot,
  ROOT, SERVER, PUBLIC, TIMEOUT_MS, SERVER_BOOT_TIMEOUT_MS, FOLDER_ID, CHUNK_SESSION_TTL_MS, createChunkUploadQuota,
  chunkBoundaryRequestTimeout, isCanonicalNpmTestInvocation,
  getUnusedPort, request, waitForServer, login, multipartParts, multipart, isContained, testDeadQuotaOwnerEnv,
  createHarness, startGatedClamAv, upload, uploadPayload, uploadChunk, postJson, waitForExit, waitForFile,
  legacyChunkMetadata, auditLogs, auditLogFileSignature, waitForAuditLogs,
  filesUnder, directoryEntries, assertRejectedClean, pending, quarantine,
} = require("./support/upload-security-harness");

test("folder mutations revalidate session and upload permission after waiting for the lifecycle lock", { timeout: 45_000 }, async (t) => {
  let markerPath;
  const harness = await createHarness(t, {
    preloadSource: ({ dir }) => {
      markerPath = path.join(dir, "folder-lock-waiting");
      const lockDirectory = path.join(dir, "data", ".rootark-cloud-file-locks");
      const expectedLockPath = path.join(lockDirectory, `${crypto.createHash("sha256").update(`folder:${FOLDER_ID}`).digest("hex")}.lock`);
      return [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        `const lockDirectory = ${JSON.stringify(lockDirectory)};`,
        `const expectedLockPath = ${JSON.stringify(expectedLockPath)};`,
        `const markerPath = ${JSON.stringify(markerPath)};`,
        'const originalLinkSync = fs.linkSync;',
        'fs.linkSync = function (source, target) { try { return originalLinkSync.call(this, source, target); } catch (error) { if (error.code === "EEXIST" && typeof source === "string" && path.resolve(source).startsWith(path.resolve(lockDirectory) + path.sep) && typeof target === "string" && path.resolve(target) === path.resolve(expectedLockPath)) fs.writeFileSync(markerPath, "waiting"); throw error; } };',
      ].join("\n");
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const usersPath = path.join(harness.dir, "data", "users.local.json");
  const lock = createFileLifecycleLock({ directory: path.join(harness.dir, "data", ".rootark-cloud-file-locks"), timeoutMs: 5000, pollMs: 5 });
  const mutateUser = (change) => {
    const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
    change(users[0]);
    fs.writeFileSync(usersPath, JSON.stringify(users));
  };
  const withHeldFolderLock = async (startRequest, changeUser) => {
    fs.rmSync(markerPath, { force: true });
    let release;
    let markHeld;
    const held = new Promise((resolve) => { markHeld = resolve; });
    const operation = lock.runFolder(FOLDER_ID, async () => {
      markHeld();
      await new Promise((resolve) => { release = resolve; });
    });
    await held;
    const responsePromise = startRequest();
    assert.equal(await waitForFile(markerPath), true, "request did not reach the held folder lock");
    changeUser();
    release();
    const response = await responsePromise;
    await operation;
    return response;
  };

  const simple = await withHeldFolderLock(
    () => upload(harness.port, session, "revoked-simple.txt", Buffer.from("disposable simple bytes")),
    () => mutateUser((user) => { user.permissions.upload = false; }),
  );
  assert.equal(simple.status, 403, simple.body);
  assert.deepEqual(pending(harness.dir), {});
  assert.equal(fs.existsSync(path.join(harness.dir, "temp", FOLDER_ID, "revoked-simple.txt")), false);

  mutateUser((user) => { user.permissions.upload = true; });
  const uploadId = "revoked-chunk-after-scan";
  const chunk = await withHeldFolderLock(
    () => uploadChunk(harness.port, session, { uploadId, originalName: "revoked-chunk.txt", chunkIndex: 0, totalChunks: 1, bytes: Buffer.from("disposable chunk bytes") }),
    () => mutateUser((user) => { user.permissions.upload = false; }),
  );
  assert.equal(chunk.status, 403, chunk.body);
  assert.deepEqual(pending(harness.dir), {});
  const chunkDirectory = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const cleanupDeadline = Date.now() + 5000;
  while (filesUnder(chunkDirectory).length && Date.now() < cleanupDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual(filesUnder(chunkDirectory), []);
  assert.equal(fs.existsSync(path.join(harness.dir, "temp", FOLDER_ID, "revoked-chunk.txt")), false);

  mutateUser((user) => { user.permissions.upload = true; });
  const folderBefore = JSON.parse(fs.readFileSync(path.join(harness.dir, "data", "folders.json"), "utf8")).find((folder) => folder.id === FOLDER_ID);
  const body = JSON.stringify({ expiresAt: new Date(Date.now() + 60_000).toISOString() });
  const temporary = await withHeldFolderLock(
    () => request(harness.port, `/folders/${FOLDER_ID}/temporary`, {
      method: "PUT",
      headers: { cookie: session.cookie, origin: `http://127.0.0.1:${harness.port}`, "x-csrf-token": session.csrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      body,
    }),
    () => mutateUser((user) => { user.sessionVersion += 1; }),
  );
  assert.equal(temporary.status, 401, temporary.body);
  const folderAfter = JSON.parse(fs.readFileSync(path.join(harness.dir, "data", "folders.json"), "utf8")).find((folder) => folder.id === FOLDER_ID);
  assert.equal(folderAfter.expiresAt, folderBefore.expiresAt, "revoked session cannot update folder expiration after lock wait");
});

test("simple and chunk uploads revalidate current upload permission after a long scan", { timeout: 45_000 }, async (t) => {
  const scanner = await startGatedClamAv();
  const harness = await createHarness(t, {
    envOverrides: { UPLOAD_SCAN_PROVIDER: "clamav", CLAMAV_HOST: "127.0.0.1", CLAMAV_PORT: String(scanner.port) },
  });
  t.after(async () => {
    for (const gate of scanner.scans) gate.release();
    await new Promise((resolve) => scanner.server.close(resolve));
  });
  const session = await login(harness.port, "uploader", harness.password);
  const usersPath = path.join(harness.dir, "data", "users.local.json");
  const setUploadPermission = (allowed) => {
    const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
    users[0].permissions.upload = allowed;
    fs.writeFileSync(usersPath, JSON.stringify(users));
  };
  const waitForScan = async (index) => {
    const deadline = Date.now() + TIMEOUT_MS;
    while (scanner.scans.length <= index && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.ok(scanner.scans[index], `ClamAV scan ${index + 1} did not start`);
    await scanner.scans[index].started;
  };

  const simplePromise = upload(harness.port, session, "scan-revoked-simple.txt", Buffer.from("disposable simple bytes"));
  await waitForScan(0);
  setUploadPermission(false);
  scanner.scans[0].release();
  const simple = await simplePromise;
  assert.equal(simple.status, 403, simple.body);
  assert.deepEqual(pending(harness.dir), {});
  assert.equal(fs.existsSync(path.join(harness.dir, "temp", FOLDER_ID, "scan-revoked-simple.txt")), false);

  setUploadPermission(true);
  const chunkPromise = uploadChunk(harness.port, session, {
    uploadId: "scan-revoked-chunk",
    originalName: "scan-revoked-chunk.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("disposable chunk bytes"),
  });
  await waitForScan(1);
  setUploadPermission(false);
  scanner.scans[1].release();
  const chunk = await chunkPromise;
  assert.equal(chunk.status, 403, chunk.body);
  assert.deepEqual(pending(harness.dir), {});
  const chunkDirectory = path.join(harness.chunkRoot, FOLDER_ID, "scan-revoked-chunk");
  const cleanupDeadline = Date.now() + TIMEOUT_MS;
  while (filesUnder(chunkDirectory).length && Date.now() < cleanupDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual(filesUnder(chunkDirectory), []);
  assert.equal(fs.existsSync(path.join(harness.dir, "temp", FOLDER_ID, "scan-revoked-chunk.txt")), false);
});

test("chunk uploads stay disabled without explicit quota limits while the server remains available", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "",
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "",
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "",
    CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "",
    CHUNK_UPLOAD_STORAGE_TOPOLOGY: "",
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "quota-config-missing",
    originalName: "quota-config-missing.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("small disposable chunk"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
});

test("startup imports only validated legacy chunk parts into the quota ledger and scrubs legacy passwords", { timeout: 30_000 }, async (t) => {
  const uploadId = "legacy-quota-import";
  const payload = Buffer.from("legacy staged bytes");
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId),
        "0.part": payload,
      },
    }],
  });
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    const row = database.prepare("SELECT account_key, session_key, state, charge_bytes FROM quota_operations WHERE relative_path = ?").get(path.join(FOLDER_ID, uploadId, "0.part"));
    assert.deepEqual(row, {
      account_key: "uploader",
      session_key: `${FOLDER_ID}/${uploadId}`,
      state: "part_committed",
      charge_bytes: payload.length,
    }, harness.stderr.join(""));
    const metadata = JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8"));
    assert.equal(Object.hasOwn(metadata, "password"), false);
    assert.equal((await request(harness.port, "/login.html")).status, 200);
  } finally {
    database.close();
  }
});

test("a committed chunk whose file size disagrees with its live ledger charge fails closed and is preserved", { timeout: 30_000 }, async (t) => {
  const uploadId = "quota-charge-mismatch";
  const payload = Buffer.from("preserve mismatched committed bytes");
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId), "0.part": payload } }],
    preloadSource: ({ chunkRoot }) => `
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const quota = createChunkUploadQuota({ rootDir: ${JSON.stringify(chunkRoot)}, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "live-owner", processId: process.pid });
      quota.initialize([{ operationId: "mismatched-charge", accountKey: "uploader", sessionKey: ${JSON.stringify(`${FOLDER_ID}/${uploadId}`)}, relativePath: path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"), state: "part_committed", chargeBytes: ${payload.length + 1} }]);
      quota.close();
    `,
  });

  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "quota-charge-mismatch.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("must not be staged"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  assert.deepEqual(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part")), payload);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT charge_bytes FROM quota_operations WHERE operation_id = 'mismatched-charge'").get().charge_bytes, payload.length + 1);
  } finally {
    database.close();
  }
});

test("chunk handoff persists pending metadata when app data uses SQLite", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { appDataMode: "sqlite" });
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("sqlite pending handoff");
  const response = await uploadChunk(harness.port, session, {
    uploadId: "sqlite-app-pending",
    originalName: "sqlite-app-pending.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes,
  });
  assert.equal(response.status, 200, response.body);
  assert.equal(JSON.parse(response.body).complete, true);
  const database = new Database(path.join(harness.dir, "data", "rootark.sqlite"), { readonly: true });
  try {
    const pending = database.prepare("SELECT folder_id, file_name, uploaded_by FROM pending_uploads WHERE id = ?").get(`${FOLDER_ID}/sqlite-app-pending.txt`);
    assert.deepEqual(pending, { folder_id: FOLDER_ID, file_name: "sqlite-app-pending.txt", uploaded_by: "uploader" });
  } finally {
    database.close();
  }
  assert.equal(fs.statSync(path.join(harness.dir, "temp", FOLDER_ID, "sqlite-app-pending.txt")).size, bytes.length);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, "sqlite-app-pending")), false);
  const quota = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(quota.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    quota.close();
  }
});

test("startup removes a dead-owner incoming reservation only after reconciling its exact file", { timeout: 30_000 }, async (t) => {
  const operationId = "a".repeat(32);
  const bytes = "stale incoming";
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      fs.mkdirSync(path.join(root, "incoming"), { recursive: true });
      fs.writeFileSync(path.join(root, "incoming", ${JSON.stringify(operationId)}), ${JSON.stringify(bytes)});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize();
      quota.reserve({ operationId: ${JSON.stringify(operationId)}, accountKey: "uploader", relativePath: path.join("incoming", ${JSON.stringify(operationId)}), reservedBytes: 8 * 1024 * 1024 });
      quota.close();
    `,
  });
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, "incoming", operationId)), false, [...harness.stdout, ...harness.stderr].join(""));
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
  }
});

test("startup does not claim a suspicious stale incoming file it cannot safely remove", { timeout: 30_000 }, async (t) => {
  const operationId = "e".repeat(32);
  const bytes = "suspicious incoming with a hard link";
  const originalOwnerPid = 2147483000;
  const harness = await createHarness(t, {
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const quotaModule = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const createChunkUploadQuota = quotaModule.createChunkUploadQuota;
      const root = ${JSON.stringify(chunkRoot)};
      const incomingPath = path.join(root, "incoming", ${JSON.stringify(operationId)});
      fs.mkdirSync(path.dirname(incomingPath), { recursive: true });
      fs.writeFileSync(incomingPath, ${JSON.stringify(bytes)});
      const oldTime = new Date(Date.now() - 10 * 60 * 1000);
      fs.utimesSync(incomingPath, oldTime, oldTime);
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: ${originalOwnerPid} });
      quota.initialize();
      quota.reserve({ operationId: ${JSON.stringify(operationId)}, accountKey: "uploader", relativePath: path.join("incoming", ${JSON.stringify(operationId)}), reservedBytes: 8 * 1024 * 1024 });
      quota.close();
      quotaModule.createChunkUploadQuota = function (...args) {
        const service = createChunkUploadQuota(...args);
        const ownerStatus = service.ownerStatus.bind(service);
        const claim = service.claim.bind(service);
        const lstatSync = fs.lstatSync;
        let checks = 0;
        let operationClaimed = false;
        let injectedHardLink = false;
        service.claim = function (operation) {
          const result = claim(operation);
          if (operation.operationId === ${JSON.stringify(operationId)} && result) operationClaimed = true;
          return result;
        };
        fs.lstatSync = function (filePath, ...statArgs) {
          if (operationClaimed && !injectedHardLink && path.resolve(filePath) === path.resolve(incomingPath)) {
            fs.linkSync(incomingPath, path.join(${JSON.stringify(dir)}, "suspicious-alias"));
            injectedHardLink = true;
          }
          return lstatSync.call(this, filePath, ...statArgs);
        };
        service.ownerStatus = function (operation) {
          if (operation.operationId === ${JSON.stringify(operationId)}) {
            checks += 1;
            if (checks === 1) return "live";
            if (checks <= 3) return "dead";
          }
          return ownerStatus(operation);
        };
        return service;
      };
    `,
  });

  const incomingPath = path.join(harness.chunkRoot, "incoming", operationId);
  assert.equal(fs.readFileSync(incomingPath, "utf8"), bytes);
  assert.equal(fs.statSync(incomingPath).nlink, 2);
  const aliasPath = path.join(harness.dir, "suspicious-alias");
  assert.equal(fs.readFileSync(aliasPath, "utf8"), bytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    const operation = database.prepare("SELECT owner_pid, state, charge_bytes FROM quota_operations WHERE operation_id = ?").get(operationId);
    assert.equal(operation.owner_pid, originalOwnerPid, "invalid file state must leave the claim with the dead owner for restart recovery");
    assert.equal(operation.state, "reserved");
    assert.equal(operation.charge_bytes, 8 * 1024 * 1024);
  } finally {
    database.close();
  }
});

test("startup recovers a reused PID only when process-start identity proves it is stale", { timeout: 30_000 }, async (t) => {
  const operationId = "b".repeat(32);
  const bytes = "live incoming";
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => [
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      'const quotaModule = require(' + JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js")) + ');',
      'const { createChunkUploadQuota, getCurrentProcessIdentity } = quotaModule;',
      'const root = ' + JSON.stringify(chunkRoot) + ';',
      'const currentIdentity = getCurrentProcessIdentity();',
      'const oldIdentity = process.platform === "linux" && currentIdentity ? { ...currentIdentity, processStartTime: "0" } : currentIdentity;',
      'fs.mkdirSync(path.join(root, "incoming"), { recursive: true });',
      'fs.writeFileSync(path.join(root, "incoming", ' + JSON.stringify(operationId) + '), ' + JSON.stringify(bytes) + ');',
      'const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "prior-owner", processId: process.pid, processIdentity: oldIdentity });',
      'quota.initialize([{ operationId: ' + JSON.stringify(operationId) + ', accountKey: "uploader", relativePath: path.join("incoming", ' + JSON.stringify(operationId) + '), state: "writing", chargeBytes: Buffer.byteLength(' + JSON.stringify(bytes) + ') }]);',
      'quota.close();',
    ].join("\n"),
  });
  const shouldRecover = process.platform === "linux" && Boolean(getCurrentProcessIdentity());
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, "incoming", operationId)), !shouldRecover, harness.stderr.join(""));
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations WHERE operation_id = ?").get(operationId).count, shouldRecover ? 0 : 1);
  } finally {
    database.close();
  }
});

test("startup preserves incoming bytes and disables chunk uploads when an operation owner is from another host", { timeout: 30_000 }, async (t) => {
  const operationId = "d".repeat(32);
  const bytes = "preserve ambiguous owner";
  const foreignIdentity = { version: 1, platform: "linux", hostId: "b".repeat(64), bootId: "00000000-0000-0000-0000-000000000002", pidNamespace: "pid:[999999]", processStartTime: "1" };
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      fs.mkdirSync(path.join(root, "incoming"), { recursive: true });
      fs.writeFileSync(path.join(root, "incoming", ${JSON.stringify(operationId)}), ${JSON.stringify(bytes)});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "foreign-owner", processId: 4242, processIdentity: ${JSON.stringify(foreignIdentity)} });
      quota.initialize([{ operationId: ${JSON.stringify(operationId)}, accountKey: "uploader", relativePath: path.join("incoming", ${JSON.stringify(operationId)}), state: "writing", chargeBytes: Buffer.byteLength(${JSON.stringify(bytes)}) }]);
      quota.close();
    `,
  });
  assert.match(harness.stderr.join(""), /quota initialization unavailable/);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", operationId), "utf8"), bytes, "ambiguous ownership leaves the incoming payload untouched");
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "ambiguous-owner-blocked",
    originalName: "ambiguous-owner.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must remain blocked"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", operationId), "utf8"), bytes);
});

test("chunk quota fails closed when a persisted owner PID belongs to another PID namespace", () => {
  const currentIdentity = {
    version: 1,
    platform: "linux",
    hostId: "a".repeat(64),
    bootId: "00000000-0000-0000-0000-000000000001",
    pidNamespace: "pid:[100]",
    processStartTime: "500",
  };
  const ownerIdentity = { ...currentIdentity, pidNamespace: "pid:[200]", processStartTime: "1" };
  let signaled = false;

  const status = classifyProcessOwner(4242, ownerIdentity, currentIdentity, {
    platform: "linux",
    kill() { signaled = true; },
  });

  assert.equal(status, "unknown", "a numeric PID from a different namespace is ambiguous even when host and boot match");
  assert.equal(signaled, false, "namespace ambiguity must not be resolved by probing the colliding PID");
});

test("startup preserves an old incoming file owned by the exact live instance", { timeout: 30_000 }, async (t) => {
  const operationId = "c".repeat(32);
  const bytes = "old but actively owned incoming data";
  const harness = await createHarness(t, {
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const modulePath = ${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))};
      const quotaModule = require(modulePath);
      const createQuota = quotaModule.createChunkUploadQuota;
      quotaModule.createChunkUploadQuota = (options) => createQuota({ ...options, processInstanceId: "exact-live-instance" });
      const root = ${JSON.stringify(chunkRoot)};
      const incomingDir = path.join(root, "incoming");
      fs.mkdirSync(incomingDir, { recursive: true });
      const incomingPath = path.join(incomingDir, ${JSON.stringify(operationId)});
      fs.writeFileSync(incomingPath, ${JSON.stringify(bytes)});
      const old = new Date(Date.now() - 10 * 60 * 1000);
      fs.utimesSync(incomingPath, old, old);
      const quota = createQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "exact-live-instance", processId: process.pid });
      quota.initialize([{ operationId: ${JSON.stringify(operationId)}, accountKey: "uploader", relativePath: path.join("incoming", ${JSON.stringify(operationId)}), state: "writing", chargeBytes: Buffer.byteLength(${JSON.stringify(bytes)}) }]);
      quota.close();
      const simpleDir = path.join(${JSON.stringify(dir)}, "temp", ".incoming");
      fs.mkdirSync(simpleDir, { recursive: true });
      const simplePath = path.join(simpleDir, "1234567890123-0123456789abcdef.upload");
      fs.writeFileSync(simplePath, "stale simple upload");
      fs.utimesSync(simplePath, old, old);
    `,
  });
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", operationId), "utf8"), bytes);
  assert.deepEqual(filesUnder(path.join(harness.dir, "temp", ".incoming")), [], "ordinary simple-upload staging still receives age-based cleanup");
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT state, charge_bytes FROM quota_operations WHERE operation_id = ?").get(operationId), {
      state: "writing",
      charge_bytes: Buffer.byteLength(bytes),
    });
  } finally {
    database.close();
  }
});

test("startup removes an interrupted assembly and preserves charged source parts", { timeout: 30_000 }, async (t) => {
  const uploadId = "interrupted-assembly";
  const first = Buffer.from("part zero");
  const second = Buffer.from("part one");
  const assembly = Buffer.from("partial ciphertext");
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 2, encryptionLevel: "password" }), "0.part": first, "1.part": second, "assembled.upload": assembly },
    }],
    preloadSource: ({ chunkRoot }) => `
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "part-zero", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: ${first.length} },
        { operationId: "part-one", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "1.part"), state: "part_committed", chargeBytes: ${second.length} },
        { operationId: "assembly-op", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "assembled.upload"), state: "encrypting", chargeBytes: ${assembly.length} },
      ]);
      quota.close();
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.existsSync(path.join(sessionDir, "assembled.upload")), false);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), first);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "1.part")), second);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT relative_path, charge_bytes FROM quota_operations ORDER BY operation_id").all(), [
      { relative_path: path.join(FOLDER_ID, uploadId, "1.part"), charge_bytes: second.length },
      { relative_path: path.join(FOLDER_ID, uploadId, "0.part"), charge_bytes: first.length },
    ]);
  } finally {
    database.close();
  }
});

test("partial in-place encryption failure removes assembly scratch but preserves charged parts", { timeout: 30_000 }, async (t) => {
  const uploadId = "partial-encryption-failure";
  const source = Buffer.from("accepted source bytes that must remain intact");
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => [
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      'const target = path.join(' + JSON.stringify(chunkRoot) + ', ' + JSON.stringify(FOLDER_ID) + ', ' + JSON.stringify(uploadId) + ', "assembled.upload");',
      'const originalWriteFileSync = fs.writeFileSync;',
      'fs.writeFileSync = function (file, data, ...args) {',
      '  if (typeof file === "string" && path.resolve(file) === path.resolve(target) && Buffer.isBuffer(data)) {',
      '    originalWriteFileSync.call(this, file, data.subarray(0, Math.max(1, Math.floor(data.length / 2))), ...args);',
      '    throw Object.assign(new Error("injected partial encryption write"), { code: "EIO" });',
      '  }',
      '  return originalWriteFileSync.call(this, file, data, ...args);',
      '};',
    ].join("\n"),
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "partial-encryption-failure.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: source,
    encryptionLevel: "password",
    password: "disposable-encryption-password",
  });
  assert.equal(response.status, 400, response.body);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), source);
  assert.equal(fs.existsSync(path.join(sessionDir, "assembled.upload")), false);
  const metadata = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  assert.equal(Object.hasOwn(metadata, "password"), false);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT relative_path, state, charge_bytes FROM quota_operations ORDER BY operation_id").all(), [
      { relative_path: path.join(FOLDER_ID, uploadId, "0.part"), state: "part_committed", charge_bytes: source.length },
    ]);
  } finally {
    database.close();
  }
});

test("startup recovers an assembly interrupted during scanning from intact source parts", { timeout: 30_000 }, async (t) => {
  const uploadId = "scan-interrupted-assembly";
  const source = Buffer.from("source part remains charged");
  const assembly = Buffer.from("assembled bytes being scanned");
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none" }),
        "0.part": source,
        "assembled.upload": assembly,
      },
    }],
    preloadSource: ({ chunkRoot }) => [
      'const path = require("node:path");',
      'const { createChunkUploadQuota } = require(' + JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js")) + ');',
      'const root = ' + JSON.stringify(chunkRoot) + ';',
      'const session = path.join(' + JSON.stringify(FOLDER_ID) + ', ' + JSON.stringify(uploadId) + ');',
      'const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });',
      'quota.initialize([',
      '  { operationId: "scan-source", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: ' + source.length + ' },',
      '  { operationId: "scan-assembly", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "assembled.upload"), state: "assembled", chargeBytes: ' + assembly.length + ' },',
      ']);',
      'quota.close();',
    ].join("\n"),
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.existsSync(path.join(sessionDir, "assembled.upload")), false);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), source);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT relative_path, state, charge_bytes FROM quota_operations").all(), [
      { relative_path: path.join(FOLDER_ID, uploadId, "0.part"), state: "part_committed", charge_bytes: source.length },
    ]);
  } finally {
    database.close();
  }
});

test("startup finishes a replacement only when target, backup, incoming file, and ledger identities agree", { timeout: 30_000 }, async (t) => {
  const uploadId = "replacement-crash-recovery";
  const oldBytes = Buffer.from("old part");
  const newBytes = Buffer.from("replacement part");
  const newOperationId = "new-replacement-operation";
  const backupName = `.replacement-${newOperationId}.part`;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1 }), [backupName]: oldBytes } }],
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      fs.mkdirSync(path.join(root, "incoming"), { recursive: true });
      fs.writeFileSync(path.join(root, "incoming", ${JSON.stringify(newOperationId)}), ${JSON.stringify(newBytes.toString())});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "old-replacement-operation", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, ${JSON.stringify(backupName)}), state: "promoting", chargeBytes: ${oldBytes.length} },
        { operationId: ${JSON.stringify(newOperationId)}, accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "promoting", chargeBytes: ${newBytes.length} },
      ]);
      quota.close();
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), newBytes);
  assert.equal(fs.existsSync(path.join(sessionDir, backupName)), false);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, "incoming", newOperationId)), false);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT operation_id, state, charge_bytes FROM quota_operations").all(), [
      { operation_id: newOperationId, state: "part_committed", charge_bytes: newBytes.length },
    ]);
  } finally {
    database.close();
  }
});

test("replacement recovery preserves session data when quota ownership disagrees with metadata", { timeout: 45_000 }, async (t) => {
  const uploadId = "replacement-owner-mismatch";
  const oldBytes = Buffer.from("accepted old part must survive");
  const newBytes = Buffer.from("untrusted replacement input");
  const newOperationId = "new-replacement-operation";
  const backupName = `.replacement-${newOperationId}.part`;
  const sessionKey = `${FOLDER_ID}/${uploadId}`;
  const harness = await createHarness(t, {
    waitForReady: false,
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1 }), [backupName]: oldBytes } }],
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = ${JSON.stringify(sessionKey)};
      fs.mkdirSync(path.join(root, "incoming"), { recursive: true });
      fs.writeFileSync(path.join(root, "incoming", ${JSON.stringify(newOperationId)}), ${JSON.stringify(newBytes.toString())});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "old-replacement-operation", accountKey: "different-account", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, ${JSON.stringify(backupName)}), state: "promoting", chargeBytes: ${oldBytes.length} },
        { operationId: ${JSON.stringify(newOperationId)}, accountKey: "different-account", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "promoting", chargeBytes: ${newBytes.length} },
      ]);
      quota.close();
    `,
  });

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  try {
    assert.equal((await waitForServer(harness.port)).status, 200);
  } catch (error) {
    throw new Error(`${error.message}\nserver exit: ${harness.child.exitCode}\nserver stdout:\n${harness.stdout.join("")}\nserver stderr:\n${harness.stderr.join("")}`);
  }
  let loginSession;
  try {
    loginSession = await login(harness.port, "uploader", harness.password);
  } catch (error) {
    throw new Error(`${error.message}\nserver stdout:\n${harness.stdout.join("")}\nserver stderr:\n${harness.stderr.join("")}`);
  }
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  const blocked = await uploadChunk(harness.port, loginSession, {
    uploadId: "replacement-owner-mismatch-blocked",
    originalName: "replacement-owner-mismatch-blocked.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not start staging"),
  });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, backupName)), oldBytes);
  assert.deepEqual(fs.readFileSync(path.join(harness.chunkRoot, "incoming", newOperationId)), newBytes);
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false);
  assert.equal(fs.existsSync(path.join(sessionDir, "metadata.json")), true);
});

test("startup releases a deleted part only when its seven-day expiry tombstone proves cleanup intent", { timeout: 30_000 }, async (t) => {
  const uploadId = "expired-part-recovery";
  const tombstone = { __expiredAt: new Date().toISOString() };
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": tombstone } }],
    preloadSource: ({ chunkRoot }) => `
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const relative = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part");
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([{ operationId: "expired-part", accountKey: "uploader", sessionKey: ${JSON.stringify(`${FOLDER_ID}/${uploadId}`)}, relativePath: relative, state: "part_committed", chargeBytes: 10 }]);
      quota.close();
    `,
  });
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
  }
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8")), tombstone);
});

test("startup completes a durable handoff only with matching pending record and destination", { timeout: 30_000 }, async (t) => {
  const uploadId = "handoff-crash-recovery";
  const bytes = Buffer.from("published bytes");
  const fileName = "published.txt";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", originalName: fileName, fileName }), "0.part": bytes } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const parts = [{ operationId: "part-zero", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: ${bytes.length} }];
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([...parts, { operationId: "handoff-operation", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: ${JSON.stringify(`handoff/${FOLDER_ID}/${fileName}#${bytes.length}`)}, state: "handoff_pending", chargeBytes: ${bytes.length} }]);
      quota.close();
      fs.mkdirSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}), { recursive: true });
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)}), ${JSON.stringify(bytes.toString())});
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "data", "pending-uploads.json"), JSON.stringify({ ${JSON.stringify(`${FOLDER_ID}/${fileName}`)}: { folderId: ${JSON.stringify(FOLDER_ID)}, uploadedBy: "uploader" } }));
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false, harness.stderr.join(""));
  assert.equal(fs.existsSync(sessionDir), false, JSON.stringify({ entries: fs.existsSync(sessionDir) ? fs.readdirSync(sessionDir) : [], stderr: harness.stderr.join("") }));
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
  }
});

test("startup completes an injected metadata-unlink handoff interruption with an empty session directory", { timeout: 30_000 }, async (t) => {
  const uploadId = "handoff-empty-session-crash";
  const fileName = "handoff-empty-session.txt";
  const bytes = Buffer.from("durably published bytes");
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", originalName: fileName, fileName }) } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = ${JSON.stringify(FOLDER_ID + "/" + uploadId)};
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([{ operationId: "handed-off-marker", accountKey: "uploader", sessionKey: session, relativePath: ${JSON.stringify("handoff/" + FOLDER_ID + "/" + encodeURIComponent(fileName) + "#" + bytes.length)}, state: "handed_off", chargeBytes: 0 }]);
      quota.close();
      // Inject the crash boundary after metadata unlink and before session rmdir.
      fs.unlinkSync(path.join(root, ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "metadata.json"));
      fs.mkdirSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}), { recursive: true });
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)}), ${JSON.stringify(bytes.toString())});
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "data", "pending-uploads.json"), JSON.stringify({ ${JSON.stringify(FOLDER_ID + "/" + fileName)}: { folderId: ${JSON.stringify(FOLDER_ID)}, uploadedBy: "uploader" } }));
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.existsSync(sessionDir), false, harness.stderr.join(""));
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_sessions").get().count, 0);
  } finally {
    database.close();
  }
});

test("startup rejects unexpected contents in an empty-metadata handoff session directory", { timeout: 30_000 }, async (t) => {
  const uploadId = "handoff-unexpected-session-content";
  const fileName = "handoff-unexpected-content.txt";
  const bytes = Buffer.from("durably published bytes");
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: {
      "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", originalName: fileName, fileName }),
      "unexpected.bin": "must be preserved",
    } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = ${JSON.stringify(FOLDER_ID + "/" + uploadId)};
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([{ operationId: "handed-off-marker", accountKey: "uploader", sessionKey: session, relativePath: ${JSON.stringify("handoff/" + FOLDER_ID + "/" + encodeURIComponent(fileName) + "#" + bytes.length)}, state: "handed_off", chargeBytes: 0 }]);
      quota.close();
      fs.unlinkSync(path.join(root, ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "metadata.json"));
      fs.mkdirSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}), { recursive: true });
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)}), ${JSON.stringify(bytes.toString())});
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "data", "pending-uploads.json"), JSON.stringify({ ${JSON.stringify(FOLDER_ID + "/" + fileName)}: { folderId: ${JSON.stringify(FOLDER_ID)}, uploadedBy: "uploader" } }));
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "unexpected.bin"), "utf8"), "must be preserved", harness.stderr.join(""));
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
  const session = await login(harness.port, "uploader", harness.password);
  const blocked = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: fileName,
    chunkIndex: 0,
    totalChunks: 1,
    bytes,
  });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
});

test("startup removes an unregistered published handoff and keeps charged parts retryable", { timeout: 30_000 }, async (t) => {
  const uploadId = "handoff-published-no-pending";
  const fileName = "unregistered-published.txt";
  const bytes = Buffer.from("source part survives an unregistered publication");
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", originalName: fileName, fileName }), "0.part": bytes } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "part-zero", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: ${bytes.length} },
        { operationId: "published-output", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: ${JSON.stringify(`handoff/${FOLDER_ID}/${fileName}#${bytes.length}`)}, state: "handoff_published", chargeBytes: ${bytes.length} },
      ]);
      quota.close();
      fs.mkdirSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}), { recursive: true });
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)}), Buffer.from(${JSON.stringify(bytes.toString())}));
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const destinationPath = path.join(harness.dir, "temp", FOLDER_ID, fileName);
  assert.equal(fs.existsSync(destinationPath), false, harness.stderr.join(""));
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), bytes);

  const session = await login(harness.port, "uploader", harness.password);
  const retry = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: fileName,
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "none",
    bytes,
  });
  assert.equal(retry.status, 200, `${retry.body}\n${harness.stdout.join("")}\n${harness.stderr.join("")}`);
  assert.equal(JSON.parse(retry.body).complete, true);
  assert.deepEqual(fs.readFileSync(destinationPath), bytes);
  await harness.stopServer();
  const finalLedger = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    const remainingOperations = finalLedger.prepare("SELECT operation_id, account_key, session_key, relative_path, state, charge_bytes FROM quota_operations ORDER BY operation_id").all();
    assert.deepEqual(remainingOperations, [], `unexpected operations after successful retry: ${JSON.stringify(remainingOperations)}`);
  } finally {
    finalLedger.close();
  }
});

test("startup cleans an interrupted hard-link handoff and keeps its accepted part retryable", { timeout: 30_000 }, async (t) => {
  const uploadId = "hardlink-handoff-recovery";
  const fileName = "hardlink-recovery.txt";
  const bytes = Buffer.from("accepted source part survives interrupted publication");
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", originalName: fileName, fileName }), "0.part": bytes, "assembled.upload": bytes } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const source = path.join(root, session, "assembled.upload");
      const destination = path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)});
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.linkSync(source, destination);
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "a-part", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: ${bytes.length} },
        { operationId: "z-handoff", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: ${JSON.stringify(`handoff/${FOLDER_ID}/${fileName}#${bytes.length}`)}, state: "handoff_pending", chargeBytes: ${bytes.length} },
      ]);
      quota.close();
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const destinationPath = path.join(harness.dir, "temp", FOLDER_ID, fileName);
  assert.equal(fs.existsSync(destinationPath), false, harness.stderr.join(""));
  assert.equal(fs.existsSync(path.join(sessionDir, "assembled.upload")), false);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), bytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT operation_id, state, charge_bytes FROM quota_operations").all(), [
      { operation_id: "a-part", state: "part_committed", charge_bytes: bytes.length },
    ]);
  } finally {
    database.close();
  }
  const session = await login(harness.port, "uploader", harness.password);
  const retry = await uploadChunk(harness.port, session, { uploadId, originalName: fileName, chunkIndex: 0, totalChunks: 1, encryptionLevel: "none", bytes });
  assert.equal(retry.status, 200, retry.body);
  assert.deepEqual(fs.readFileSync(destinationPath), bytes);
});

test("startup resumes per-part cleanup after a durable handoff crash", { timeout: 30_000 }, async (t) => {
  const uploadId = "handoff-part-cleanup-recovery";
  const bytes = Buffer.from("published bytes");
  const remainingPart = Buffer.from("last source part");
  const fileName = "published-after-crash.txt";
  const completedMetadata = {
    ...legacyChunkMetadata(uploadId, { totalChunks: 2, encryptionLevel: "none", fileName }),
    __resumeBlocked: true,
    __chunkQuotaHandoffComplete: true,
  };
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": completedMetadata, "1.part": remainingPart } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "part-zero", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: 8 },
        { operationId: "part-one", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "1.part"), state: "part_committed", chargeBytes: ${remainingPart.length} },
        { operationId: "handoff-operation", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: ${JSON.stringify(`handoff/${FOLDER_ID}/${fileName}#${bytes.length}`)}, state: "handed_off", chargeBytes: 0 },
      ]);
      quota.close();
      fs.mkdirSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}), { recursive: true });
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)}), ${JSON.stringify(bytes.toString())});
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "data", "pending-uploads.json"), JSON.stringify({ ${JSON.stringify(`${FOLDER_ID}/${fileName}`)}: { folderId: ${JSON.stringify(FOLDER_ID)}, uploadedBy: "uploader" } }));
    `,
  });
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId)), false, harness.stderr.join(""));
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
  }
});

test("aborted chunk bodies remove their reserved incoming file before releasing quota", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const body = multipartParts([
    { field: "uploadId", bytes: "abort-reservation" },
    { field: "originalName", bytes: "abort.bin" },
    { field: "chunkIndex", bytes: "0" },
    { field: "totalChunks", bytes: "1" },
    { field: "chunk", filename: "abort.bin", bytes: Buffer.alloc(512 * 1024, 0x61) },
  ], { close: false });
  const req = http.request({
    host: "127.0.0.1",
    port: harness.port,
    path: "/upload-chunk",
    method: "POST",
    headers: {
      cookie: session.cookie,
      "x-csrf-token": session.csrf,
      "content-type": body.contentType,
      "content-length": body.body.length + 128,
    },
  });
  req.on("error", () => {});
  req.write(body.body);
  const incomingDir = path.join(harness.chunkRoot, "incoming");
  const incomingDeadline = Date.now() + 3000;
  while ((!fs.existsSync(incomingDir) || fs.readdirSync(incomingDir).length === 0) && Date.now() < incomingDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(fs.existsSync(incomingDir) && fs.readdirSync(incomingDir).length > 0, "Multer began writing after a prior reservation");
  req.destroy();
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"));
  try {
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      const incomingCount = fs.readdirSync(incomingDir).length;
      const operationCount = database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count;
      if (incomingCount === 0 && operationCount === 0) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(fs.readdirSync(incomingDir).length, 0);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
  }
});

test("bounded request timeout aborts a stalled chunk body and releases it only after cleanup", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, {
    preloadSource: [
      'const originalSetTimeout = global.setTimeout;',
      'global.setTimeout = function (callback, delay, ...args) { return originalSetTimeout(callback, delay === 5 * 60 * 1000 ? 1000 : delay, ...args); };',
    ].join("\n"),
  });
  const session = await login(harness.port, "uploader", harness.password);
  const body = multipartParts([
    { field: "uploadId", bytes: "timeout-reservation" },
    { field: "originalName", bytes: "timeout.bin" },
    { field: "chunkIndex", bytes: "0" },
    { field: "totalChunks", bytes: "1" },
    { field: "chunk", filename: "timeout.bin", bytes: Buffer.alloc(512 * 1024, 0x61) },
  ], { close: false });
  let timedOut;
  const timeoutResult = new Promise((resolve) => { timedOut = resolve; });
  const req = http.request({
    host: "127.0.0.1",
    port: harness.port,
    path: "/upload-chunk",
    method: "POST",
    headers: {
      cookie: session.cookie,
      "x-csrf-token": session.csrf,
      "content-type": body.contentType,
      "content-length": body.body.length + 128,
    },
  }, (res) => {
    res.resume();
    res.on("end", () => timedOut({ status: res.statusCode }));
  });
  req.on("error", (error) => timedOut({ error: error.code || error.name }));
  req.write(body.body);

  const incomingDir = path.join(harness.chunkRoot, "incoming");
  const incomingDeadline = Date.now() + 3000;
  while ((!fs.existsSync(incomingDir) || fs.readdirSync(incomingDir).length === 0) && Date.now() < incomingDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(fs.existsSync(incomingDir) && fs.readdirSync(incomingDir).length > 0, "the reservation and incoming write start before timeout");
  const timeout = await Promise.race([
    timeoutResult,
    new Promise((resolve) => setTimeout(() => resolve(null), 5000)),
  ]);
  assert.ok(timeout, "the HTTP server terminates the incomplete request within its configured timeout");
  assert.ok(timeout.status === 408 || timeout.error, JSON.stringify(timeout));

  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"));
  try {
    const cleanupDeadline = Date.now() + 5000;
    while (Date.now() < cleanupDeadline) {
      if (fs.readdirSync(incomingDir).length === 0 && database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count === 0) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.deepEqual(fs.readdirSync(incomingDir), []);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
    req.destroy();
  }
});

test("a corrupt chunk quota ledger disables only chunk uploads at startup", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => `require("node:fs").mkdirSync(${JSON.stringify(chunkRoot)}, { recursive: true }); require("node:fs").writeFileSync(${JSON.stringify(path.join(chunkRoot, ".quota.sqlite"))}, "corrupt ledger");`,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "quota-ledger-corrupt",
    originalName: "quota-ledger-corrupt.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("small disposable chunk"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
});

test("semantically invalid quota rows preserve session payloads while startup scrubs legacy passwords", { timeout: 45_000 }, async (t) => {
  const uploadId = "invalid-quota-state-path";
  const partBytes = Buffer.from("accepted disposable chunk data");
  const metadata = legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", password: "disposable-legacy-encryption-password" });
  const staleIncomingId = "a".repeat(32);
  const sessionKey = `${FOLDER_ID}/${uploadId}`;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": partBytes } }],
    preloadSource: ({ chunkRoot }) => [
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      `const chunkRoot = ${JSON.stringify(chunkRoot)};`,
      `const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});`,
      `const { ensureWindowsChunkUploadRoot } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadWindowsAcl.js"))});`,
      'fs.mkdirSync(path.join(chunkRoot, "incoming"), { recursive: true });',
      `if (process.platform !== "win32") fs.chmodSync(path.join(chunkRoot, ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}), 0o755);`,
      'ensureWindowsChunkUploadRoot(chunkRoot);',
      'const quota = createChunkUploadQuota({ rootDir: chunkRoot, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "stale-fixture", processId: 2147483647 });',
      'quota.initialize();',
      `const staleIncomingId = ${JSON.stringify(staleIncomingId)};`,
      'quota.reserve({ operationId: staleIncomingId, accountKey: "uploader", relativePath: path.join("incoming", staleIncomingId), reservedBytes: 12 });',
      'fs.writeFileSync(path.join(chunkRoot, "incoming", staleIncomingId), "retain during fail-closed validation");',
      `quota.reserve({ operationId: ${JSON.stringify("b".repeat(32))}, accountKey: "uploader", sessionKey: ${JSON.stringify(sessionKey)}, relativePath: path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"), reservedBytes: ${partBytes.length} });`,
      `quota.reserve({ operationId: ${JSON.stringify("c".repeat(32))}, accountKey: "uploader", sessionKey: ${JSON.stringify(sessionKey)}, relativePath: path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "metadata.json"), reservedBytes: ${Buffer.byteLength(JSON.stringify(metadata))} });`,
      'quota.close();',
    ].join("\n"),
  });

  if (process.platform !== "win32") {
    const sessionMode = fs.statSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId)).mode & 0o777;
    assert.equal(sessionMode, 0o700, "startup keeps legacy chunk sessions private while validating an invalid ledger");
  }
  assert.deepEqual(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part")), partBytes);
  const preservedMetadata = JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8"));
  assert.equal(preservedMetadata.uploadId, uploadId);
  assert.equal(preservedMetadata.folderId, FOLDER_ID);
  assert.equal(preservedMetadata.uploadedBy, "uploader");
  assert.equal(preservedMetadata.totalChunks, 1);
  assert.equal(preservedMetadata.encryptionLevel, "none");
  assert.equal(Object.hasOwn(preservedMetadata, "password"), false, "invalid-ledger startup still scrubs legacy plaintext upload passwords");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", staleIncomingId), "utf8"), "retain during fail-closed validation");
  const session = await login(harness.port, "uploader", harness.password);
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "quota-invalid-row-blocked",
    originalName: "quota-invalid-row-blocked.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not start staging"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part")).toString(), partBytes.toString());
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json")), true);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, "incoming", staleIncomingId)), true);
});

test("legacy quota import defers part permission changes and tombstone cleanup until every session validates", { timeout: 45_000 }, async (t) => {
  const firstUploadId = "first-valid-session";
  const expiredUploadId = "expired-session";
  const invalidUploadId = "invalid-session";
  const firstBytes = Buffer.from("preserve first legacy part");
  const expiredBytes = Buffer.from("preserve tombstone part until full scan");
  const invalidBytes = Buffer.from("preserve later invalid session part");
  const firstMetadata = legacyChunkMetadata(firstUploadId, { folderId: "a-legacy-first", totalChunks: 1, encryptionLevel: "none" });
  const expiredMetadata = { __expiredAt: new Date().toISOString() };
  const harness = await createHarness(t, {
    chunkSessions: [
      { folderId: "a-legacy-first", uploadId: firstUploadId, files: { "metadata.json": firstMetadata, "0.part": firstBytes } },
      { folderId: "b-legacy-expired", uploadId: expiredUploadId, files: { "metadata.json": expiredMetadata, "0.part": expiredBytes } },
      { folderId: "z-legacy-invalid", uploadId: invalidUploadId, files: { "metadata.json": "{invalid", "0.part": invalidBytes } },
    ],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const firstSession = path.join(${JSON.stringify(chunkRoot)}, "a-legacy-first", ${JSON.stringify(firstUploadId)});
      const expiredSession = path.join(${JSON.stringify(chunkRoot)}, "b-legacy-expired", ${JSON.stringify(expiredUploadId)});
      const chmodLog = path.join(${JSON.stringify(dir)}, "legacy-import-chmod-events.jsonl");
      const originalChmodSync = fs.chmodSync;
      fs.chmodSync = function (target, mode, ...args) {
        fs.appendFileSync(chmodLog, JSON.stringify({ target: String(target), stack: new Error().stack }) + "\\n");
        return originalChmodSync.call(this, target, mode, ...args);
      };
      if (process.platform !== "win32") {
        fs.chmodSync(path.join(firstSession, "0.part"), 0o644);
        fs.chmodSync(path.join(expiredSession, "0.part"), 0o644);
      }
    `,
  });

  const firstSession = path.join(harness.chunkRoot, "a-legacy-first", firstUploadId);
  const expiredSession = path.join(harness.chunkRoot, "b-legacy-expired", expiredUploadId);
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(path.join(firstSession, "0.part")).mode & 0o777, 0o644);
    assert.equal(fs.statSync(path.join(expiredSession, "0.part")).mode & 0o777, 0o644);
  }
  assert.deepEqual(fs.readFileSync(path.join(firstSession, "0.part")), firstBytes);
  assert.deepEqual(fs.readFileSync(path.join(expiredSession, "0.part")), expiredBytes);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(expiredSession, "metadata.json"), "utf8")), expiredMetadata);
  const invalidSession = path.join(harness.chunkRoot, "z-legacy-invalid", invalidUploadId);
  assert.deepEqual(fs.readFileSync(path.join(invalidSession, "0.part")), invalidBytes);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(invalidSession, "metadata.json"), "utf8")), { __resumeBlocked: true });
  if (process.platform !== "win32") {
    const chmodLog = path.join(harness.dir, "legacy-import-chmod-events.jsonl");
    const events = fs.readFileSync(chmodLog, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
    assert.deepEqual(events.filter((event) => event.stack.includes("readLegacyChunkQuotaOperations")), [], "legacy scan must complete before it changes any session permissions");
  }

  const session = await login(harness.port, "uploader", harness.password);
  const blocked = await uploadChunk(harness.port, session, {
    uploadId: "legacy-import-fail-closed",
    originalName: "legacy-import-fail-closed.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("quota import must remain unavailable"),
  });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
});

test("ownerless blocked legacy metadata cannot authorize quota recovery", { timeout: 45_000 }, async (t) => {
  const uploadId = "ownerless-blocked-ledger-session";
  const sessionKey = `${FOLDER_ID}/${uploadId}`;
  const partBytes = Buffer.from("preserve blocked legacy bytes");
  const blockedMetadata = {
    __resumeBlocked: true,
    uploadId,
    folderId: FOLDER_ID,
    totalChunks: 1,
    lastActivityAt: new Date().toISOString(),
  };
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": blockedMetadata, "0.part": partBytes } }],
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const root = ${JSON.stringify(chunkRoot)};
      const sessionDir = path.join(root, ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const { ensureWindowsChunkUploadRoot } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadWindowsAcl.js"))});
      ensureWindowsChunkUploadRoot(root);
      if (process.platform !== "win32") {
        fs.chmodSync(sessionDir, 0o755);
        fs.chmodSync(path.join(sessionDir, "metadata.json"), 0o644);
        fs.chmodSync(path.join(sessionDir, "0.part"), 0o644);
      }
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "stale-owner", processId: 2147483647 });
      quota.initialize([{ operationId: "blocked-part", accountKey: "different-account", sessionKey: ${JSON.stringify(sessionKey)}, relativePath: path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"), state: "part_committed", chargeBytes: ${partBytes.length} }]);
      quota.close();
    `,
  });

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(path.join(sessionDir, "0.part")).mode & 0o777, 0o644);
  }
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), partBytes);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8")), blockedMetadata);
  const session = await login(harness.port, "uploader", harness.password);
  const blocked = await uploadChunk(harness.port, session, {
    uploadId: "ownerless-blocked-ledger-probe",
    originalName: "ownerless-blocked-ledger-probe.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must remain blocked"),
  });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), partBytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT operation_id, account_key, state FROM quota_operations").all(), [
      { operation_id: "blocked-part", account_key: "different-account", state: "part_committed" },
    ]);
  } finally {
    database.close();
  }
});

test("handoff recovery preserves session data when quota ownership disagrees with metadata", { timeout: 45_000 }, async (t) => {
  const uploadId = "handoff-owner-mismatch";
  const fileName = "handoff-owner-mismatch.txt";
  const bytes = Buffer.from("accepted disposable source part");
  const sessionKey = `${FOLDER_ID}/${uploadId}`;
  const metadata = legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", originalName: fileName, fileName });
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": bytes } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = ${JSON.stringify(sessionKey)};
      const folderTemp = path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)});
      fs.mkdirSync(path.join(root, "incoming"), { recursive: true });
      fs.mkdirSync(folderTemp, { recursive: true });
      fs.writeFileSync(path.join(folderTemp, ${JSON.stringify(fileName)}), ${JSON.stringify(bytes.toString())});
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "data", "pending-uploads.json"), JSON.stringify({
        ${JSON.stringify(`${FOLDER_ID}/${fileName}`)}: { folderId: ${JSON.stringify(FOLDER_ID)}, uploadedBy: "uploader" },
      }));
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483647 });
      quota.initialize([
        { operationId: "a-part", accountKey: "different-account", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: ${bytes.length} },
        { operationId: "z-handoff", accountKey: "different-account", sessionKey: session.replace(path.sep, "/"), relativePath: ${JSON.stringify(`handoff/${FOLDER_ID}/${encodeURIComponent(fileName)}#${bytes.length}`)}, state: "handoff_pending", chargeBytes: ${bytes.length} },
      ]);
      quota.close();
    `,
  });

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), bytes);
  assert.equal(fs.existsSync(path.join(sessionDir, "metadata.json")), true);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
  const session = await login(harness.port, "uploader", harness.password);
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  const blocked = await uploadChunk(harness.port, session, {
    uploadId: "quota-owner-mismatch-blocked",
    originalName: "quota-owner-mismatch-blocked.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not start staging"),
  });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), bytes);
  assert.equal(fs.existsSync(path.join(sessionDir, "metadata.json")), true);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
});

test("an untracked incoming file is preserved and disables only chunk uploads at startup", { timeout: 30_000 }, async (t) => {
  const untrackedBytes = "preserve until operator reconciliation";
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => [
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      'fs.mkdirSync(path.join(' + JSON.stringify(chunkRoot) + ', "incoming"), { recursive: true });',
      'fs.writeFileSync(path.join(' + JSON.stringify(chunkRoot) + ', "incoming", "untracked-file"), ' + JSON.stringify(untrackedBytes) + ');',
    ].join("\n"),
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "quota-untracked-incoming",
    originalName: "quota-untracked-incoming.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not be staged"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", "untracked-file"), "utf8"), untrackedBytes);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), ["untracked-file"]);
  assert.equal((await request(harness.port, "/login.html")).status, 200);
});

test("chunk quota exhaustion rejects before creating a Multer incoming file", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "1",
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "1",
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "quota-capacity-exhausted",
    originalName: "quota-capacity-exhausted.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("small disposable chunk"),
  });
  assert.equal(response.status, 507, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_EXCEEDED");
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
  const quotaDatabase = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(quotaDatabase.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    quotaDatabase.close();
  }
});

test("chunk uploads fail closed before Multer when local single-host topology is unverified", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_STORAGE_TOPOLOGY: "",
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "unverified-chunk-topology",
    originalName: "unverified-chunk-topology.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not be staged"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), [], "the disabled endpoint creates no incoming staged file");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, ".quota.sqlite")), false);
  assert.equal((await request(harness.port, "/login.html")).status, 200);
});

test("chunk completion reserves assembly capacity before committing the final part", { timeout: 45_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(8 * 1024 * 1024),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(8 * 1024 * 1024),
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "assembly-quota-capacity",
    originalName: "assembly-quota-capacity.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.alloc(5 * 1024 * 1024, 0x61),
  });
  assert.equal(response.status, 507, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_EXCEEDED");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, "assembly-quota-capacity", "0.part")), false);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("verified incoming reservations shrink before exact-capacity final assembly", { timeout: 45_000 }, async (t) => {
  const cap = 8 * 1024 * 1024;
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(cap),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(cap),
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "assembly-quota-exact-capacity",
    originalName: "assembly-quota-exact-capacity.txt",
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "none",
    bytes: Buffer.alloc(4 * 1024 * 1024, 0x61),
  });
  assert.equal(response.status, 200, response.body);
  assert.equal(JSON.parse(response.body).complete, true);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
  const quotaDatabase = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(quotaDatabase.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
    assert.equal(quotaDatabase.prepare("SELECT value FROM quota_meta WHERE key = 'system_charge_bytes'").get().value, "0");
  } finally {
    quotaDatabase.close();
  }
});

test("maximum-size parts reserve and release the full bounded assembly charge", { timeout: 120_000 }, async (t) => {
  const partBytes = 8 * 1024 * 1024;
  const partCount = 3;
  const assemblyBytes = partBytes * partCount;
  const peakBytes = assemblyBytes * 2;
  const originalName = "bounded-maximum-assembly.txt";
  const part = Buffer.alloc(partBytes, 0x61);

  const deniedHarness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(peakBytes - 1),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(peakBytes - 1),
  } });
  const deniedSession = await login(deniedHarness.port, "uploader", deniedHarness.password);
  for (let chunkIndex = 0; chunkIndex < partCount - 1; chunkIndex += 1) {
    const response = await uploadChunk(deniedHarness.port, deniedSession, {
      uploadId: "bounded-assembly-under-cap",
      originalName,
      chunkIndex,
      totalChunks: partCount,
      bytes: part,
    });
    assert.equal(response.status, 200, response.body);
    assert.equal(JSON.parse(response.body).complete, false);
  }

  const rejectedFinalPart = await uploadChunk(deniedHarness.port, deniedSession, {
    uploadId: "bounded-assembly-under-cap",
    originalName,
    chunkIndex: partCount - 1,
    totalChunks: partCount,
    bytes: part,
  });
  assert.equal(rejectedFinalPart.status, 507, rejectedFinalPart.body);
  assert.equal(JSON.parse(rejectedFinalPart.body).code, "CHUNK_QUOTA_EXCEEDED");
  const deniedSessionDir = path.join(deniedHarness.chunkRoot, FOLDER_ID, "bounded-assembly-under-cap");
  assert.deepEqual(fs.readFileSync(path.join(deniedSessionDir, "0.part")), part);
  assert.deepEqual(fs.readFileSync(path.join(deniedSessionDir, "1.part")), part);
  assert.equal(fs.existsSync(path.join(deniedSessionDir, "2.part")), false);
  assert.deepEqual(fs.readdirSync(path.join(deniedHarness.chunkRoot, "incoming")), []);
  const deniedDatabase = new Database(path.join(deniedHarness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(deniedDatabase.prepare("SELECT value FROM quota_meta WHERE key = 'system_charge_bytes'").get().value, String(partBytes * 2));
    assert.equal(deniedDatabase.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 2);
  } finally {
    deniedDatabase.close();
  }

  const exactHarness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(peakBytes),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(peakBytes),
  } });
  const exactSession = await login(exactHarness.port, "uploader", exactHarness.password);
  for (let chunkIndex = 0; chunkIndex < partCount; chunkIndex += 1) {
    const response = await uploadChunk(exactHarness.port, exactSession, {
      uploadId: "bounded-assembly-exact-cap",
      originalName,
      chunkIndex,
      totalChunks: partCount,
      bytes: part,
    });
    assert.equal(response.status, 200, response.body);
    assert.equal(JSON.parse(response.body).complete, chunkIndex === partCount - 1);
  }
  assert.deepEqual(fs.readdirSync(path.join(exactHarness.chunkRoot, "incoming")), []);
  assert.equal(fs.existsSync(path.join(exactHarness.chunkRoot, FOLDER_ID, "bounded-assembly-exact-cap", "assembled.upload")), false);
  const exactDatabase = new Database(path.join(exactHarness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(exactDatabase.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
    assert.equal(exactDatabase.prepare("SELECT value FROM quota_meta WHERE key = 'system_charge_bytes'").get().value, "0");
  } finally {
    exactDatabase.close();
  }
});

test("an incoming reservation that exceeds the quota preserves the previously accepted part", { timeout: 45_000 }, async (t) => {
  const cap = 8 * 1024 * 1024;
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(cap),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(cap),
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const original = Buffer.alloc(8 * 1024 * 1024, 0x4f);
  const first = await uploadChunk(harness.port, session, {
    uploadId: "replacement-quota-preserve",
    originalName: "replacement-quota-preserve.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: original,
  });
  assert.equal(first.status, 200, first.body);
  const replacement = await uploadChunk(harness.port, session, {
    uploadId: "replacement-quota-preserve",
    originalName: "replacement-quota-preserve.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("replacement"),
  });
  assert.equal(replacement.status, 507, replacement.body);
  assert.deepEqual(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, "replacement-quota-preserve", "0.part")), original);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("a replacement is promoted with the previous part kept charged until it is removed", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(32 * 1024 * 1024),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(32 * 1024 * 1024),
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const first = await uploadChunk(harness.port, session, {
    uploadId: "replacement-quota-success",
    originalName: "replacement-quota-success.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("original part"),
  });
  assert.equal(first.status, 200, first.body);
  const replacement = await uploadChunk(harness.port, session, {
    uploadId: "replacement-quota-success",
    originalName: "replacement-quota-success.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("replacement part"),
  });
  assert.equal(replacement.status, 200, replacement.body);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, "replacement-quota-success", "0.part"), "utf8"), "replacement part");
  assert.equal(fs.readdirSync(path.join(harness.chunkRoot, FOLDER_ID, "replacement-quota-success")).some((name) => name.startsWith(".replacement-")), false);
});

test("a failed replacement rename restores the prior accepted part and its ledger charge", { timeout: 30_000 }, async (t) => {
  const uploadId = "replacement-rename-rollback";
  const original = Buffer.from("accepted source part");
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const renameSync = fs.renameSync;
      let incomingPromotions = 0;
      fs.renameSync = function (source, destination, ...args) {
        if (String(source).includes(path.join(".chunks", "incoming")) && String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part")) && ++incomingPromotions === 2) {
          throw Object.assign(new Error("injected promotion rename failure"), { code: "EIO" });
        }
        return renameSync.call(this, source, destination, ...args);
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const first = await uploadChunk(harness.port, session, { uploadId, originalName: `${uploadId}.txt`, chunkIndex: 0, totalChunks: 2, bytes: original });
  assert.equal(first.status, 200, first.body);
  const replacement = await uploadChunk(harness.port, session, { uploadId, originalName: `${uploadId}.txt`, chunkIndex: 0, totalChunks: 2, bytes: Buffer.from("replacement data") });
  assert.equal(replacement.status, 500, replacement.body);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original);
  assert.equal(fs.readdirSync(sessionDir).some((name) => name.startsWith(".replacement-")), false);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT relative_path, state, charge_bytes FROM quota_operations ORDER BY relative_path").all(), [
      { relative_path: path.join(FOLDER_ID, uploadId, "0.part"), state: "part_committed", charge_bytes: original.length },
    ]);
  } finally {
    database.close();
  }
});

async function prepareFailedReplacement(t, uploadId) {
  const original = Buffer.from("accepted part before failed replacement");
  const replacementBytes = Buffer.from("replacement remains charged for recovery");
  const harness = await createHarness(t, {
    deterministicQuotaRecovery: true,
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const renameSync = fs.renameSync;
      let incomingPromotions = 0;
      fs.renameSync = function (source, destination, ...args) {
        const isPartTarget = String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"));
        if (isPartTarget && String(source).includes(path.join(".chunks", "incoming")) && ++incomingPromotions === 2) {
          throw Object.assign(new Error("injected replacement promotion failure"), { code: "EIO" });
        }
        if (isPartTarget && path.basename(String(source)).startsWith(".replacement-")) {
          throw Object.assign(new Error("injected prior-part rollback failure"), { code: "EIO" });
        }
        return renameSync.call(this, source, destination, ...args);
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  assert.equal((await uploadChunk(harness.port, session, { uploadId, originalName: `${uploadId}.txt`, chunkIndex: 0, totalChunks: 2, bytes: original })).status, 200);
  assert.equal((await uploadChunk(harness.port, session, { uploadId, originalName: `${uploadId}.txt`, chunkIndex: 0, totalChunks: 2, bytes: replacementBytes })).status, 500);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const rows = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  let operations;
  try { operations = rows.prepare("SELECT operation_id, relative_path FROM quota_operations ORDER BY relative_path").all(); }
  finally { rows.close(); }
  const backupOperation = operations.find((row) => row.relative_path.includes(".replacement-"));
  return {
    harness,
    original,
    replacementBytes,
    sessionDir,
    backupOperationId: backupOperation.operation_id,
    backupFileName: path.basename(backupOperation.relative_path),
  };
}

test("restart reconciles a replacement when restoring its prior part fails", { timeout: 45_000 }, async (t) => {
  const uploadId = "replacement-rollback-recovery";
  const original = Buffer.from("accepted part before failed replacement");
  const replacementBytes = Buffer.from("replacement remains charged for recovery");
  const harness = await createHarness(t, {
    deterministicQuotaRecovery: true,
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const renameSync = fs.renameSync;
      let incomingPromotions = 0;
      fs.renameSync = function (source, destination, ...args) {
        const isPartTarget = String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"));
        if (isPartTarget && String(source).includes(path.join(".chunks", "incoming")) && ++incomingPromotions === 2) {
          throw Object.assign(new Error("injected replacement promotion failure"), { code: "EIO" });
        }
        if (isPartTarget && path.basename(String(source)).startsWith(".replacement-")) {
          throw Object.assign(new Error("injected prior-part rollback failure"), { code: "EIO" });
        }
        return renameSync.call(this, source, destination, ...args);
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const first = await uploadChunk(harness.port, session, { uploadId, originalName: `${uploadId}.txt`, chunkIndex: 0, totalChunks: 2, bytes: original });
  assert.equal(first.status, 200, first.body);
  const replacement = await uploadChunk(harness.port, session, { uploadId, originalName: `${uploadId}.txt`, chunkIndex: 0, totalChunks: 2, bytes: replacementBytes });
  assert.equal(replacement.status, 500, replacement.body);

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const incomingDir = path.join(harness.chunkRoot, "incoming");
  const backupName = fs.readdirSync(sessionDir).find((name) => name.startsWith(".replacement-"));
  assert.ok(backupName, "failed rollback retains the charged prior-part backup for recovery");
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, backupName)), original);
  const incomingName = fs.readdirSync(incomingDir)[0];
  assert.ok(incomingName, "failed replacement remains in its charged incoming path");
  assert.deepEqual(fs.readFileSync(path.join(incomingDir, incomingName)), replacementBytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations WHERE state = 'promoting'").get().count, 2);
  } finally {
    database.close();
  }

  harness.child.kill();
  await waitForExit(harness.child);
  const recoveryPort = await getUnusedPort();
  const recoveryPreloadPath = path.join(harness.dir, "replacement-recovery-preload.js");
  fs.writeFileSync(recoveryPreloadPath, `
    const fs = require("node:fs");
    const path = require("node:path");
    const renameSync = fs.renameSync;
    const unlinkSync = fs.unlinkSync;
    let failedPromotion = false;
    let failedAfterIncomingUnlink = false;
    fs.renameSync = function (source, destination, ...args) {
      if (!failedPromotion && String(source).includes(path.join(".chunks", "incoming")) && String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"))) {
        failedPromotion = true;
        throw Object.assign(new Error("injected recovery promotion failure"), { code: "EIO" });
      }
      return renameSync.call(this, source, destination, ...args);
    };
    fs.unlinkSync = function (target, ...args) {
      const isIncoming = String(target).includes(path.join(".chunks", "incoming"));
      const result = unlinkSync.call(this, target, ...args);
      if (isIncoming && !failedAfterIncomingUnlink) {
        failedAfterIncomingUnlink = true;
        throw Object.assign(new Error("injected crash after incoming unlink"), { code: "EIO" });
      }
      return result;
    };
  `);
  const recoveryChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, "--require", recoveryPreloadPath, SERVER], {
    cwd: harness.dir,
    env: { ...process.env, ...testDeadQuotaOwnerEnv(harness.child.pid), NODE_ENV: "test", PORT: String(recoveryPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_SCAN_PROVIDER: "disabled", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const recoveryStderr = [];
  recoveryChild.stderr.on("data", (chunk) => recoveryStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(recoveryPort)).status, 200, recoveryStderr.join(""));
    assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original);
    assert.deepEqual(fs.readdirSync(incomingDir), [], "the injected boundary leaves the restored part but no replacement incoming file");
    const interrupted = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      assert.equal(interrupted.prepare("SELECT COUNT(*) AS count FROM quota_operations WHERE state = 'promoting'").get().count, 2);
    } finally {
      interrupted.close();
    }
  } finally {
    if (recoveryChild.exitCode === null) {
      recoveryChild.kill();
      await waitForExit(recoveryChild);
    }
  }

  const finalRecoveryPort = await getUnusedPort();
  const finalRecoveryChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, SERVER], {
    cwd: harness.dir,
    env: { ...process.env, ...testDeadQuotaOwnerEnv(harness.child.pid, recoveryChild.pid), NODE_ENV: "test", PORT: String(finalRecoveryPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_SCAN_PROVIDER: "disabled", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const finalRecoveryStderr = [];
  finalRecoveryChild.stderr.on("data", (chunk) => finalRecoveryStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(finalRecoveryPort)).status, 200, finalRecoveryStderr.join(""));
    assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original, `second restart preserves the accepted part after an interruption between filesystem and ledger recovery: ${finalRecoveryStderr.join("")}`);
    assert.deepEqual(fs.readdirSync(incomingDir), []);
    const recovered = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      assert.deepEqual(recovered.prepare("SELECT state, charge_bytes, relative_path FROM quota_operations").all(), [
        { state: "part_committed", charge_bytes: original.length, relative_path: path.join(FOLDER_ID, uploadId, "0.part") },
      ]);
    } finally {
      recovered.close();
    }
  } finally {
    if (finalRecoveryChild.exitCode === null) {
      finalRecoveryChild.kill();
      await waitForExit(finalRecoveryChild);
    }
  }
});

test("restart reconciles a replacement after the restored-part ledger transition", { timeout: 45_000 }, async (t) => {
  const uploadId = "replacement-transition-recovery";
  const fixture = await prepareFailedReplacement(t, uploadId);
  const { harness, original, sessionDir, backupOperationId } = fixture;
  harness.child.kill();
  await waitForExit(harness.child);
  const failedPort = await getUnusedPort();
  const preloadPath = path.join(harness.dir, "replacement-transition-preload.js");
  fs.writeFileSync(preloadPath, `
    const fs = require("node:fs");
    const path = require("node:path");
    const renameSync = fs.renameSync;
    let failedPromotion = false;
    fs.renameSync = function (source, destination, ...args) {
      if (!failedPromotion && String(source).includes(path.join(".chunks", "incoming")) && String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"))) {
        failedPromotion = true;
        throw Object.assign(new Error("injected recovery promotion failure"), { code: "EIO" });
      }
      return renameSync.call(this, source, destination, ...args);
    };
    const quotaPath = path.join(${JSON.stringify(ROOT)}, "services", "chunkUploadQuota.js");
    const quota = require(quotaPath);
    const create = quota.createChunkUploadQuota;
    quota.createChunkUploadQuota = function (...args) {
      const service = create.apply(this, args);
      const transition = service.transition.bind(service);
      let failedTransition = false;
      service.transition = function (input) {
        const result = transition(input);
        if (!failedTransition && input.operationId === ${JSON.stringify(backupOperationId)} && input.state === "part_committed") {
          failedTransition = true;
          throw Object.assign(new Error("injected crash after backup transition"), { code: "EIO" });
        }
        return result;
      };
      return service;
    };
  `);
  const failedChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, "--require", preloadPath, SERVER], {
    cwd: harness.dir,
    env: { ...process.env, ...testDeadQuotaOwnerEnv(harness.child.pid), NODE_ENV: "test", PORT: String(failedPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const failedStderr = [];
  failedChild.stderr.on("data", (chunk) => failedStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(failedPort)).status, 200, failedStderr.join(""));
    assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original);
    const rows = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      assert.deepEqual(rows.prepare("SELECT state, charge_bytes FROM quota_operations ORDER BY state").all(), [
        { state: "part_committed", charge_bytes: original.length },
        { state: "promoting", charge_bytes: fixture.replacementBytes.length },
      ]);
    } finally { rows.close(); }
  } finally {
    if (failedChild.exitCode === null) { failedChild.kill(); await waitForExit(failedChild); }
  }

  const finalPort = await getUnusedPort();
  const finalChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, SERVER], {
    cwd: harness.dir,
    env: { ...process.env, ...testDeadQuotaOwnerEnv(harness.child.pid, failedChild.pid), NODE_ENV: "test", PORT: String(finalPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const finalStderr = [];
  finalChild.stderr.on("data", (chunk) => finalStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(finalPort)).status, 200, finalStderr.join(""));
    assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original);
    const rows = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      assert.deepEqual(rows.prepare("SELECT state, charge_bytes, relative_path FROM quota_operations").all(), [
        { state: "part_committed", charge_bytes: original.length, relative_path: path.join(FOLDER_ID, uploadId, "0.part") },
      ], finalStderr.join(""));
    } finally { rows.close(); }
  } finally {
    if (finalChild.exitCode === null) { finalChild.kill(); await waitForExit(finalChild); }
  }
});

test("restart reconciles a replacement after restoring the original target", { timeout: 45_000 }, async (t) => {
  const uploadId = "replacement-restore-boundary";
  const { harness, original, replacementBytes, sessionDir, backupFileName } = await prepareFailedReplacement(t, uploadId);
  harness.child.kill();
  await waitForExit(harness.child);
  const failedPort = await getUnusedPort();
  const preloadPath = path.join(harness.dir, "replacement-restore-preload.js");
  const restoreMarkerPath = path.join(harness.dir, "replacement-restore-hook-fired");
  fs.writeFileSync(preloadPath, `
    const fs = require("node:fs");
    const path = require("node:path");
    const markerPath = ${JSON.stringify(restoreMarkerPath)};
    const renameSync = fs.renameSync;
    let failedPromotion = false;
    let failedAfterRestore = false;
    fs.renameSync = function (source, destination, ...args) {
      if (!failedPromotion && String(source).includes(path.join(".chunks", "incoming")) && String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"))) {
        failedPromotion = true;
        throw Object.assign(new Error("injected recovery promotion failure"), { code: "EIO" });
      }
      const result = renameSync.call(this, source, destination, ...args);
      if (!failedAfterRestore && path.basename(String(source)) === ${JSON.stringify(backupFileName)} && String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"))) {
        failedAfterRestore = true;
        fs.writeFileSync(markerPath, "fired");
        throw Object.assign(new Error("injected interruption after target restore"), { code: "EIO" });
      }
      return result;
    };
  `);
  const failedChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, "--require", preloadPath, SERVER], {
    cwd: harness.dir,
    env: { ...process.env, ...testDeadQuotaOwnerEnv(harness.child.pid), NODE_ENV: "test", PORT: String(failedPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
  });
  const failedStderr = [];
  failedChild.stderr.on("data", (chunk) => failedStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(failedPort)).status, 200, failedStderr.join(""));
    assert.equal(fs.existsSync(restoreMarkerPath), true, "the injected interruption must occur after the original target is restored");
  }
  finally { if (failedChild.exitCode === null) { failedChild.kill(); await waitForExit(failedChild); } }
  const incomingDir = path.join(harness.chunkRoot, "incoming");
  const incomingName = fs.readdirSync(incomingDir)[0];
  assert.ok(incomingName, "the replacement remains at its charged incoming path after the interruption");
  assert.deepEqual(fs.readFileSync(path.join(incomingDir, incomingName)), replacementBytes);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original);
  assert.equal(fs.readdirSync(sessionDir).some((name) => name === backupFileName), false);
  const interruptedRows = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(interruptedRows.prepare("SELECT state, charge_bytes FROM quota_operations ORDER BY charge_bytes").all(), [
      { state: "promoting", charge_bytes: original.length },
      { state: "promoting", charge_bytes: replacementBytes.length },
    ]);
  } finally { interruptedRows.close(); }
  const finalPort = await getUnusedPort();
  const finalChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, SERVER], {
    cwd: harness.dir,
    env: { ...process.env, ...testDeadQuotaOwnerEnv(harness.child.pid, failedChild.pid), NODE_ENV: "test", PORT: String(finalPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
  });
  const finalStderr = [];
  finalChild.stderr.on("data", (chunk) => finalStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(finalPort)).status, 200);
    assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original);
    const rows = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try { assert.deepEqual(rows.prepare("SELECT state, charge_bytes FROM quota_operations").all(), [{ state: "part_committed", charge_bytes: original.length }], finalStderr.join("")); }
    finally { rows.close(); }
  } finally { if (finalChild.exitCode === null) { finalChild.kill(); await waitForExit(finalChild); } }
});

