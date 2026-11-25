const {
  assert, bcrypt, crypto, Database, fs, http, net, os, path, spawn, spawnSync, test,
  createFileLifecycleLock, classifyProcessOwner, createChunkUploadQuotaService, getCurrentProcessIdentity, ensureWindowsChunkUploadRoot,
  ROOT, SERVER, PUBLIC, TIMEOUT_MS, SERVER_BOOT_TIMEOUT_MS, FOLDER_ID, CHUNK_SESSION_TTL_MS, createChunkUploadQuota,
  chunkBoundaryRequestTimeout, isCanonicalNpmTestInvocation, releaseGateFixtureToHost, releaseGateVmRequire,
  getUnusedPort, request, waitForServer, login, multipartParts, multipart, isContained, testDeadQuotaOwnerEnv,
  createHarness, startGatedClamAv, upload, uploadPayload, uploadChunk, postJson, waitForExit, waitForFile,
  legacyChunkMetadata, auditLogs, auditLogFileSignature, waitForAuditLogs,
  filesUnder, directoryEntries, assertRejectedClean, pending, quarantine,
} = require("./support/upload-security-harness");

test("authorized harmless multipart upload enters the selected folder pending area", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("harmless upload\n");
  const response = await upload(harness.port, session, "notes.txt", bytes);
  const result = JSON.parse(response.body);

  assert.equal(response.status, 200);
  assert.equal(result.message, "Upload enviado para aprovacao");
  assert.equal(result.fileName, "notes.txt");
  assert.equal(result.folderId, FOLDER_ID);
  assert.deepEqual(pending(harness.dir)[`${FOLDER_ID}/notes.txt`], {
    uploadedBy: "uploader",
    uploadedAt: pending(harness.dir)[`${FOLDER_ID}/notes.txt`].uploadedAt,
    versionComment: "",
    compressedUpload: false,
    folderId: FOLDER_ID,
  });
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, "notes.txt")), bytes);
  assert.deepEqual(quarantine(harness.dir).items, []);
  assert.deepEqual(fs.existsSync(harness.quarantineDir) ? fs.readdirSync(harness.quarantineDir) : [], []);
});

test("strict legacy sync rejects pending suffix aliases before remote overwrite while browser upload still renames", { timeout: 60_000 }, async (t) => {
  const harness = await createHarness(t, { uploaderPermissions: { approve: true } });
  const unauthenticated = await request(harness.port, "/legacy-sync/capabilities");
  assert.equal(unauthenticated.status, 401, unauthenticated.body);
  const session = await login(harness.port, "uploader", harness.password);
  const capabilities = await request(harness.port, "/legacy-sync/capabilities", {
    headers: { cookie: session.cookie },
  });
  assert.equal(capabilities.status, 200, capabilities.body);
  assert.deepEqual(JSON.parse(capabilities.body), { strictFilename: true });

  const approvedBytes = Buffer.from("APPROVED_OTHER_SOURCE");
  const approved = await upload(harness.port, session, "a-1.txt", approvedBytes);
  assert.equal(approved.status, 200, approved.body);
  assert.equal(JSON.parse(approved.body).fileName, "a-1.txt");
  const promotion = await postJson(harness.port, session, `/approve/a-1.txt?folderId=${FOLDER_ID}`, {});
  assert.ok([200, 202].includes(promotion.status), promotion.body);
  const approvedPath = path.join(harness.dir, "uploads", FOLDER_ID, "a-1.txt");
  assert.deepEqual(fs.readFileSync(approvedPath), approvedBytes);

  const firstPendingBytes = Buffer.from("PENDING_A_ORIGINAL_SOURCE");
  const pendingA = await upload(harness.port, session, "a.txt", firstPendingBytes);
  assert.equal(pendingA.status, 200, pendingA.body);
  const pendingPath = path.join(harness.dir, "temp", FOLDER_ID, "a.txt");
  assert.deepEqual(fs.readFileSync(pendingPath), firstPendingBytes);
  const originalPending = pending(harness.dir);

  const flaggedUpload = (flag, method = "POST") => uploadPayload(harness.port, session, multipartParts([
    { filename: "a.txt", bytes: Buffer.from("UNAUTHORIZED_ALIAS_BYTES") },
    // The sync client's FormData puts the file before extra form fields.
    { field: "rootarkSyncStrictFilename", bytes: flag },
  ]), method);
  const strict = await flaggedUpload("true", "PUT");
  assert.equal(strict.status, 409, strict.body);
  assert.equal(JSON.parse(strict.body).code, "SYNC_STRICT_FILENAME_CONFLICT");

  // The separate PUT route prevents capability GET on an upgraded node
  // followed by POST on a legacy node ignoring a new multipart flag.
  const missingFlag = await uploadPayload(harness.port, session,
    multipart("a.txt", Buffer.from("MISSING_FLAG_BYTES")), "PUT");
  assert.equal(missingFlag.status, 400, missingFlag.body);
  assert.equal(JSON.parse(missingFlag.body).code, "SYNC_STRICT_FILENAME_INVALID_FLAG");

  for (const malformed of ["false", "TRUE", "1", ""]) {
    const rejected = await flaggedUpload(malformed, "PUT");
    assert.equal(rejected.status, 400, rejected.body);
    assert.equal(JSON.parse(rejected.body).code, "SYNC_STRICT_FILENAME_INVALID_FLAG");
  }
  const duplicateFlag = await uploadPayload(harness.port, session, multipartParts([
    { field: "rootarkSyncStrictFilename", bytes: "true" },
    { field: "rootarkSyncStrictFilename", bytes: "true" },
    { filename: "a.txt", bytes: Buffer.from("DUPLICATE_FLAG_BYTES") },
  ]), "PUT");
  assert.equal(duplicateFlag.status, 400, duplicateFlag.body);
  assert.equal(JSON.parse(duplicateFlag.body).code, "SYNC_STRICT_FILENAME_INVALID_FLAG");

  const longName = `${"x".repeat(28)}.txt`;
  const shortened = await uploadPayload(harness.port, session, multipartParts([
    { filename: longName, bytes: Buffer.from("TRUNCATION_ALIAS_BYTES") },
    { field: "rootarkSyncStrictFilename", bytes: "true" },
  ]), "PUT");
  assert.equal(shortened.status, 409, shortened.body);
  assert.equal(JSON.parse(shortened.body).code, "SYNC_STRICT_FILENAME_CONFLICT");
  assert.deepEqual(pending(harness.dir), originalPending);
  assert.deepEqual(fs.readFileSync(pendingPath), firstPendingBytes);
  assert.deepEqual(fs.readFileSync(approvedPath), approvedBytes);
  assert.equal(fs.existsSync(path.join(harness.dir, "temp", FOLDER_ID, "a-1.txt")), false);
  assert.deepEqual(filesUnder(path.join(harness.dir, "temp", ".incoming")), []);
  assert.deepEqual(quarantine(harness.dir).items, []);

  const safePut = await uploadPayload(harness.port, session, multipartParts([
    { filename: "z-strict.txt", bytes: Buffer.from("SAFE_STRICT_UPLOAD") },
    { field: "rootarkSyncStrictFilename", bytes: "true" },
  ]), "PUT");
  assert.equal(safePut.status, 200, safePut.body);
  assert.equal(JSON.parse(safePut.body).fileName, "z-strict.txt");

  const ordinary = await upload(harness.port, session, "a.txt", Buffer.from("BROWSER_SUFFIX_UPLOAD"));
  assert.equal(ordinary.status, 200, ordinary.body);
  const renamed = JSON.parse(ordinary.body);
  assert.equal(renamed.fileName, "a-1.txt");
  assert.equal(renamed.renamed, true);
  assert.deepEqual(fs.readFileSync(approvedPath), approvedBytes,
    "ordinary pending upload must not promote over the approved file before approval");
});

test("unavailable ClamAV fails closed before simple, chunked, or WebDAV uploads can reach approval", { timeout: 45_000 }, async (t) => {
  const unavailablePort = await getUnusedPort();
  const harness = await createHarness(t, {
    uploaderPermissions: { approve: true },
    envOverrides: {
      UPLOAD_SCAN_PROVIDER: "clamav",
      UPLOAD_FAIL_CLOSED: "",
      CLAMAV_HOST: "127.0.0.1",
      CLAMAV_PORT: String(unavailablePort),
      WEBDAV_ENABLED: "true",
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const simple = await upload(harness.port, session, "unavailable-simple.txt", Buffer.from("disposable simple bytes"));
  const chunked = await uploadChunk(harness.port, session, {
    uploadId: "unavailable-final-chunk",
    originalName: "unavailable-chunk.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("disposable chunk bytes"),
  });
  const webDav = await request(harness.port, `/dav/${FOLDER_ID}/unavailable-webdav.txt`, {
    method: "PUT",
    headers: {
      authorization: "Basic " + Buffer.from(`uploader:${harness.password}`).toString("base64"),
      "content-length": "23",
    },
    body: Buffer.from("disposable WebDAV bytes"),
  });

  for (const response of [simple, chunked, webDav]) assert.equal(response.status, 503, response.body);
  assert.deepEqual(pending(harness.dir), {});
  assert.equal(quarantine(harness.dir).items.length, 3);
  assert.deepEqual(filesUnder(path.join(harness.dir, "uploads")), []);
  for (const name of ["unavailable-simple.txt", "unavailable-chunk.txt", "unavailable-webdav.txt"]) {
    const approval = await postJson(harness.port, session, `/approve/${name}?folderId=${FOLDER_ID}`, {});
    assert.equal(approval.status, 404, approval.body);
  }
});

test("clean ClamAV INSTREAM responses with the protocol NUL terminator allow pending registration", { timeout: 30_000 }, async (t) => {
  const scanner = await startGatedClamAv();
  t.after(async () => {
    for (const gate of scanner.scans) gate.release();
    await new Promise((resolve) => scanner.server.close(resolve));
  });
  const harness = await createHarness(t, {
    envOverrides: { UPLOAD_SCAN_PROVIDER: "clamav", CLAMAV_HOST: "127.0.0.1", CLAMAV_PORT: String(scanner.port) },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("disposable clean scan fixture");
  const uploadPromise = upload(harness.port, session, "clean-scan.txt", bytes);
  const deadline = Date.now() + TIMEOUT_MS;
  while (!scanner.scans.length && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(scanner.scans[0], "upload did not reach ClamAV");
  await scanner.scans[0].started;
  scanner.scans[0].release();

  const response = await uploadPromise;
  assert.equal(response.status, 200, response.body);
  assert.equal(pending(harness.dir)[`${FOLDER_ID}/clean-scan.txt`].folderId, FOLDER_ID);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, "clean-scan.txt")), bytes);
  assert.deepEqual(quarantine(harness.dir).items, []);
});

test("unknown upload scan providers fail startup instead of skipping scanning", { timeout: 10_000 }, async (t) => {
  const harness = await createHarness(t, {
    waitForReady: false,
    envOverrides: { UPLOAD_SCAN_PROVIDER: "unknown-provider", UPLOAD_FAIL_CLOSED: "false" },
  });
  const exitCode = await waitForExit(harness.child, 3_000);

  assert.notEqual(exitCode, 0);
  assert.match(harness.stderr.join(""), /UPLOAD_SCAN_PROVIDER/);
});

test("non-development startup rejects disabled or fail-open upload scanning", { timeout: 30_000 }, async (t) => {
  const configurations = [
    { env: { NODE_ENV: "production", UPLOAD_SCAN_PROVIDER: "disabled" }, error: /production.*upload scanning/i },
    { env: { NODE_ENV: "production", UPLOAD_SCAN_PROVIDER: "clamav", UPLOAD_FAIL_CLOSED: "false" }, error: /production.*upload scanning/i },
    { env: { NODE_ENV: "production", UPLOAD_SCAN_ENABLED: "false", UPLOAD_SCAN_PROVIDER: "clamav" }, error: /production.*upload scanning/i },
    { env: { NODE_ENV: "production", UPLOAD_SCAN_PROVIDER: "clamav", UPLOAD_BLOCK_EXECUTABLES: "false" }, error: /production.*executable extension blocking/i },
    { env: { NODE_ENV: "production", UPLOAD_SCAN_PROVIDER: "clamav", UPLOAD_SUSPICIOUS_EXTENSIONS: ".txt" }, error: /production.*default suspicious-extension denylist/i },
    { env: { NODE_ENV: "production", UPLOAD_SCAN_PROVIDER: "clamav", UPLOAD_SUSPICIOUS_EXTENSIONS: ", " }, error: /production.*default suspicious-extension denylist/i },
    { env: { NODE_ENV: "staging", UPLOAD_SCAN_PROVIDER: "disabled" }, error: /bypass requires NODE_ENV=development or test/i },
  ];

  for (const { env: envOverrides, error } of configurations) {
    const harness = await createHarness(t, { waitForReady: false, envOverrides });
    const exitCode = await waitForExit(harness.child, 3_000);
    assert.notEqual(exitCode, 0);
    assert.match(harness.stderr.join(""), error);
  }
});

test("production allows additive suspicious extensions while retaining its required denylist", { timeout: 15_000 }, async (t) => {
  const harness = await createHarness(t, {
    envOverrides: {
      NODE_ENV: "production",
      UPLOAD_SCAN_PROVIDER: "clamav",
      UPLOAD_SUSPICIOUS_EXTENSIONS: ".exe,.bat,.cmd,.scr,.msi,.ps1,.vbs,.jar,.com,.custom",
    },
  });

  assert.equal(harness.child.exitCode, null);
});

test("wrong encrypted-file password stays an input error and records failed decrypt only", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { uploaderPermissions: { approve: true } });
  const session = await login(harness.port, "uploader", harness.password);
  const correctPassword = "correct-test-file-password";
  const payload = multipartParts([
    { field: "encryptionLevel", bytes: "password" },
    { field: "password", bytes: correctPassword },
    { filename: "password-check.txt", bytes: Buffer.from("disposable encrypted fixture") },
  ]);
  const uploaded = await uploadPayload(harness.port, session, payload);
  assert.equal(uploaded.status, 200, uploaded.body);
  const approved = await postJson(harness.port, session, `/approve/password-check.txt?folderId=${FOLDER_ID}`, {});
  assert.equal(approved.status, 200, approved.body);

  const wrongPassword = await postJson(harness.port, session, `/encrypted-download/password-check.txt?folderId=${FOLDER_ID}`, { password: "wrong-test-file-password" });
  assert.equal(wrongPassword.status, 422, wrongPassword.body);
  const stillAuthenticated = await request(harness.port, "/auth/me", { headers: { cookie: session.cookie } });
  assert.equal(stillAuthenticated.status, 200, stillAuthenticated.body);
  const audit = JSON.parse(fs.readFileSync(path.join(harness.dir, "data", "audit-logs.json"), "utf8"));
  assert.ok(audit.logs.some((entry) => entry.eventType === "file.decrypt.failed" && entry.result === "failure"));
  assert.equal(audit.logs.some((entry) => entry.eventType === "file.decrypt" && entry.result === "success"), false);

  // Real HTTP integration: a previously encrypted, approved upload must still decrypt
  // to the exact original bytes after PBKDF2 became asynchronous.
  const correctPasswordResponse = await postJson(harness.port, session, `/encrypted-download/password-check.txt?folderId=${FOLDER_ID}`, { password: correctPassword });
  assert.equal(correctPasswordResponse.status, 200, correctPasswordResponse.body);
  assert.equal(correctPasswordResponse.body, "disposable encrypted fixture");
  assert.equal(correctPasswordResponse.headers["cache-control"], "no-store");
});

test("traversal-style multipart filenames stay contained in the selected folder", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const cases = [["../../outside.txt", "outside.txt"], ["..\\..\\outside-win.txt", "outside-win.txt"]];
  const tempDir = path.join(harness.dir, "temp", FOLDER_ID);

  for (const [submittedName, expectedName] of cases) {
    const response = await upload(harness.port, session, submittedName, Buffer.from(submittedName));
    const result = JSON.parse(response.body);
    const storedPath = path.join(tempDir, result.fileName);
    assert.equal(response.status, 200);
    assert.equal(result.fileName, expectedName);
    assert.equal(result.originalName, expectedName);
    assert.equal(result.fileName.includes("/"), false);
    assert.equal(result.fileName.includes("\\"), false);
    assert.equal(result.originalName.includes("/"), false);
    assert.equal(result.originalName.includes("\\"), false);
    assert.equal(isContained(tempDir, storedPath), true);
    assert.equal(fs.existsSync(storedPath), true);
    assert.equal(fs.existsSync(path.join(harness.dir, path.basename(submittedName))), false);
    const entry = pending(harness.dir)[`${FOLDER_ID}/${result.fileName}`];
    assert.equal(entry.folderId, FOLDER_ID);
    assert.equal(entry.originalName === undefined || (!entry.originalName.includes("/") && !entry.originalName.includes("\\")), true);
  }
  assert.equal(fs.existsSync(path.join(path.dirname(harness.dir), "outside.txt")), false);
  assert.equal(fs.existsSync(path.join(path.dirname(harness.dir), "outside-win.txt")), false);
});

test("suspicious executable extensions are quarantined before pending upload registration", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const response = await upload(harness.port, session, "harmless.exe", Buffer.from("plain text only"));
  const result = JSON.parse(response.body);
  const items = quarantine(harness.dir).items;

  assert.equal(response.status, 415);
  assert.equal(result.error, "Upload bloqueado por politica de seguranca.");
  assert.deepEqual(pending(harness.dir), {});
  assert.equal(fs.existsSync(path.join(harness.dir, "temp", FOLDER_ID, "harmless.exe")), false);
  assert.equal(items.length, 1);
  assert.equal(items[0].reason, "suspicious_extension");
  const quarantinedPath = path.join(harness.quarantineDir, items[0].storedQuarantineFilename);
  assert.equal(isContained(harness.quarantineDir, quarantinedPath), true);
  assert.deepEqual(fs.readFileSync(quarantinedPath), Buffer.from("plain text only"));
});

test("suspicious executable extensions remain blocked with Windows trailing-dot or trailing-space aliases", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const fixtures = [
    ["payload-trailing-dot.exe.", Buffer.from("trailing dot executable fixture")],
    ["payload-trailing-space.exe ", Buffer.from("trailing space executable fixture")],
  ];

  for (const [fileName, bytes] of fixtures) {
    const response = await upload(harness.port, session, fileName, bytes);
    assert.equal(response.status, 415, response.body);
  }

  assert.deepEqual(pending(harness.dir), {});
  const items = quarantine(harness.dir).items;
  assert.equal(items.length, fixtures.length);
  assert.ok(items.every((item) => item.reason === "suspicious_extension"));
  const quarantinedBytes = items.map((item) => fs.readFileSync(path.join(harness.quarantineDir, item.storedQuarantineFilename)).toString());
  assert.deepEqual(quarantinedBytes.sort(), fixtures.map(([, bytes]) => bytes.toString()).sort());
});

test("suspicious executable extensions remain quarantined when development scanning is disabled", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: { UPLOAD_SCAN_ENABLED: "false", WEBDAV_ENABLED: "true" } });
  const session = await login(harness.port, "uploader", harness.password);
  const bytesByRoute = new Map([
    ["multipart", Buffer.from("inert multipart fixture")],
    ["chunked", Buffer.from("inert chunked fixture")],
    ["webdav", Buffer.from("inert WebDAV fixture")],
  ]);
  const simple = await upload(harness.port, session, "disabled-scan-multipart.exe.", bytesByRoute.get("multipart"));
  const chunked = await uploadChunk(harness.port, session, {
    uploadId: "disabled-scan-executable",
    originalName: "disabled-scan-chunked.exe ",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: bytesByRoute.get("chunked"),
  });
  const webDav = await request(harness.port, `/dav/${FOLDER_ID}/disabled-scan-webdav.exe.`, {
    method: "PUT",
    headers: {
      authorization: "Basic " + Buffer.from(`uploader:${harness.password}`).toString("base64"),
      "content-length": bytesByRoute.get("webdav").length,
    },
    body: bytesByRoute.get("webdav"),
  });
  const items = quarantine(harness.dir).items;

  for (const response of [simple, chunked, webDav]) assert.equal(response.status, 415, response.body);
  assert.deepEqual(pending(harness.dir), {});
  assert.equal(items.length, bytesByRoute.size);
  assert.ok(items.every((item) => item.reason === "suspicious_extension"));
  const quarantinedBytes = items.map((item) => {
    const quarantinedPath = path.join(harness.quarantineDir, item.storedQuarantineFilename);
    assert.equal(isContained(harness.quarantineDir, quarantinedPath), true);
    return fs.readFileSync(quarantinedPath).toString();
  });
  assert.deepEqual(quarantinedBytes.sort(), Array.from(bytesByRoute.values(), (bytes) => bytes.toString()).sort());
  assert.deepEqual(filesUnder(path.join(harness.dir, "uploads")), []);
  assert.deepEqual(filesUnder(path.join(harness.dir, "temp", ".incoming")), []);
  assert.deepEqual(filesUnder(path.join(harness.dir, "temp", FOLDER_ID)), []);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, FOLDER_ID)), []);
});

test("ordinary text uploads remain available when development scanning is disabled", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: { UPLOAD_SCAN_ENABLED: "false" } });
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("ordinary text upload");
  const response = await upload(harness.port, session, "disabled-scan.txt", bytes);

  assert.equal(response.status, 200, response.body);
  assert.equal(pending(harness.dir)[`${FOLDER_ID}/disabled-scan.txt`].folderId, FOLDER_ID);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, "disabled-scan.txt")), bytes);
  assert.deepEqual(quarantine(harness.dir).items, []);
});

test("development scanning can explicitly opt out of the executable extension block", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: { UPLOAD_SCAN_ENABLED: "false", UPLOAD_BLOCK_EXECUTABLES: "false" } });
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("explicit development opt-out fixture");
  const response = await upload(harness.port, session, "opt-out.exe", bytes);

  assert.equal(response.status, 200, response.body);
  assert.equal(pending(harness.dir)[`${FOLDER_ID}/opt-out.exe`].folderId, FOLDER_ID);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, "opt-out.exe")), bytes);
  assert.deepEqual(quarantine(harness.dir).items, []);
});

test("users without upload permission are rejected before Multer creates artifacts", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "viewer", harness.password);
  const response = await upload(harness.port, session, "denied.txt", Buffer.from("denied"));

  assert.equal(response.status, 403);
  assert.deepEqual(JSON.parse(response.body), { error: "Permissao negada: upload" });
  assertRejectedClean(harness, response, 403);
});

test("dot-segment upload IDs are rejected without touching sibling chunk sessions", { timeout: 30_000 }, async (t) => {
  const siblingId = "preserved-sibling-session";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId: siblingId, files: { "metadata.json": legacyChunkMetadata(siblingId, { totalChunks: 2 }), "0.part": "preserve this session" } }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const siblingDirectory = path.join(harness.chunkRoot, FOLDER_ID, siblingId);

  for (const uploadId of [".", ".."]) {
    const response = await uploadChunk(harness.port, session, {
      uploadId,
      originalName: "invalid.txt",
      chunkIndex: 0,
      totalChunks: 1,
      bytes: Buffer.from("must not be staged"),
    });
    assert.equal(response.status, 400, response.body);
    assert.equal(fs.readFileSync(path.join(siblingDirectory, "0.part"), "utf8"), "preserve this session");
    assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
  }
});

test("upload chunk route limit rejects requests before Multer writes staging files", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: { API_RATE_LIMIT_MAX: "1000", UPLOAD_CHUNK_RATE_LIMIT_MAX: "1" } });
  const session = await login(harness.port, "uploader", harness.password);
  const first = await uploadChunk(harness.port, session, {
    uploadId: "rate-limited-first",
    originalName: "first.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("first"),
  });
  assert.equal(first.status, 200, first.body);

  const rejectedId = "rate-limited-before-multer";
  const rejected = await uploadChunk(harness.port, session, {
    uploadId: rejectedId,
    originalName: "rejected.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("must not be staged"),
  });
  assert.equal(rejected.status, 429, rejected.body);
  assert.match(rejected.headers["retry-after"] || "", /^\d+$/);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, rejectedId)), false);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("chunk upload quota is per account across upload IDs and proxy-reported client IPs", { timeout: 45_000 }, async (t) => {
  const harness = await createHarness(t, {
    secondUploaderHasFolderAccess: true,
    envOverrides: {
      API_RATE_LIMIT_MAX: "1000",
      TRUSTED_PROXIES: "127.0.0.1",
      UPLOAD_CHUNK_RATE_LIMIT_MAX: "1",
    },
  });
  const uploaderSession = await login(harness.port, "uploader", harness.password);
  const otherUploaderSession = await login(harness.port, "other-uploader", harness.password);

  const firstAccountFirstUpload = await uploadChunk(harness.port, uploaderSession, {
    uploadId: "account-limit-uploader-first",
    originalName: "first.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: "first account chunk",
    forwardedFor: "198.51.100.10",
  });
  assert.equal(firstAccountFirstUpload.status, 200, firstAccountFirstUpload.body);

  const secondAccountFirstUpload = await uploadChunk(harness.port, otherUploaderSession, {
    uploadId: "account-limit-other-first",
    originalName: "other.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: "second account chunk",
    forwardedFor: "198.51.100.10",
  });
  assert.equal(secondAccountFirstUpload.status, 200, secondAccountFirstUpload.body);

  const sameAccountSecondUpload = await uploadChunk(harness.port, uploaderSession, {
    uploadId: "account-limit-uploader-second",
    originalName: "second.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: "must not be staged",
    forwardedFor: "203.0.113.77",
  });
  assert.equal(sameAccountSecondUpload.status, 429, sameAccountSecondUpload.body);
  assert.match(sameAccountSecondUpload.headers["retry-after"] || "", /^\d+$/);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, "account-limit-uploader-second")), false);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("chunk upload bypasses the generic API ceiling only when the dedicated peer guard is active", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, {
    envOverrides: { API_RATE_LIMIT_MAX: "1", UPLOAD_CHUNK_IP_RATE_LIMIT_MAX: "10" },
  });
  const exhaustedApiQuota = await request(harness.port, "/auth/me");
  assert.equal(exhaustedApiQuota.status, 401, exhaustedApiQuota.body);

  const malformedChunkRequest = await request(harness.port, "/upload-chunk", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": "1" },
    body: "{",
  });
  assert.equal(malformedChunkRequest.status, 400, malformedChunkRequest.body);
});

test("chunk upload peer guard limits requests before JSON parsing and returns Retry-After", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, {
    envOverrides: { API_RATE_LIMIT_MAX: "1000", UPLOAD_CHUNK_IP_RATE_LIMIT_MAX: "2" },
  });
  const sendMalformed = () => request(harness.port, "/upload-chunk", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": "1" },
    body: "{",
  });

  assert.equal((await sendMalformed()).status, 400);
  assert.equal((await sendMalformed()).status, 400);
  const limited = await sendMalformed();
  assert.equal(limited.status, 429, limited.body);
  assert.match(limited.headers["retry-after"] || "", /^\d+$/);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("out-of-order chunk uploads complete after all required parts arrive", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const uploadId = "out-of-order-assembly";
  const parts = [Buffer.from("first "), Buffer.from("middle "), Buffer.from("last")];

  for (const chunkIndex of [2, 0]) {
    const response = await uploadChunk(harness.port, session, {
      uploadId,
      originalName: "out-of-order-assembly.txt",
      chunkIndex,
      totalChunks: parts.length,
      encryptionLevel: "none",
      bytes: parts[chunkIndex],
    });
    assert.equal(response.status, 200, response.body);
    assert.equal(JSON.parse(response.body).complete, false);
  }

  const completed = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "out-of-order-assembly.txt",
    chunkIndex: 1,
    totalChunks: parts.length,
    encryptionLevel: "none",
    bytes: parts[1],
  });
  assert.equal(completed.status, 200, completed.body);
  assert.equal(JSON.parse(completed.body).complete, true);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, "out-of-order-assembly.txt")), Buffer.concat(parts));
});

test("chunk assembly fails closed when a session ledger path is duplicated", { timeout: 30_000 }, async (t) => {
  const uploadId = "duplicate-ledger-path";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: {
      "metadata.json": legacyChunkMetadata(uploadId, {
        originalName: "duplicate-ledger-path.txt",
        fileName: "duplicate-ledger-path.txt",
        totalChunks: 2,
        encryptionLevel: "none",
      }),
      "0.part": "preserve trusted chunk",
    } }],
  });
  const relativePath = path.join(FOLDER_ID, uploadId, "0.part");
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"));
  try {
    const original = database.prepare("SELECT * FROM quota_operations WHERE relative_path = ?").get(relativePath);
    assert.ok(original, "the accepted disposable fixture has a tracked quota charge");
    database.prepare(`
      INSERT INTO quota_operations (
        operation_id, account_key, session_key, relative_path, state, charge_bytes,
        owner_instance_id, owner_pid, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run("duplicate-path-operation", original.account_key, original.session_key, original.relative_path, "part_committed", original.charge_bytes, "injected-duplicate", process.pid, Date.now(), Date.now());
  } finally {
    database.close();
  }

  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "duplicate-ledger-path.txt",
    chunkIndex: 1,
    totalChunks: 2,
    encryptionLevel: "none",
    bytes: Buffer.from("must not assemble"),
  });
  assert.equal(response.status, 500, response.body);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "preserve trusted chunk");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part")), false);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "assembled.upload")), false);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
});

// The hosted Windows runner can need more than 180 seconds for the same 2,000
// individually authenticated requests. Keep every assertion and per-request
// deadline; restore the bounded CI-only budget from the historical #228 test.
const chunkBoundarySuiteTimeoutMs = process.platform === "win32" && process.env.CI === "true"
  ? 480_000 : 180_000;
test("a valid upload can send all 2,000 allowed chunks within the configured window",
  { timeout: chunkBoundarySuiteTimeoutMs }, async (t) => {
  const harness = await createHarness(t, {
    envOverrides: { API_RATE_LIMIT_MAX: "1" },
    readyTimeout: process.platform === "win32" ? 45_000 : TIMEOUT_MS,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  t.after(() => agent.destroy());
  const uploadId = "two-thousand-chunk-window";

  let completed;
  const startedAt = Date.now();
  let slowestMs = 0;
  let slowestIndex = -1;
  for (let chunkIndex = 0; chunkIndex < 2000; chunkIndex += 1) {
    const chunkStartedAt = Date.now();
    try {
      completed = await uploadChunk(harness.port, session, {
        uploadId,
        originalName: "two-thousand-parts.txt",
        chunkIndex,
        totalChunks: 2000,
        bytes: Buffer.from([chunkIndex % 256]),
        agent,
        timeoutMs: chunkBoundaryRequestTimeout(chunkIndex, 2000),
      });
    } catch (error) {
      throw new Error(`chunk ${chunkIndex}/2000: ${error.message}; elapsedMs=${Date.now() - chunkStartedAt}; totalElapsedMs=${Date.now() - startedAt}; previousSlowestMs=${slowestMs} at index ${slowestIndex}; serverExit=${harness.child.exitCode ?? "running"}`, { cause: error });
    }
    const elapsedMs = Date.now() - chunkStartedAt;
    if (elapsedMs > slowestMs) { slowestMs = elapsedMs; slowestIndex = chunkIndex; }
    if (chunkIndex === 0 || (chunkIndex + 1) % 250 === 0) t.diagnostic(`chunk progress ${chunkIndex + 1}/2000 elapsedMs=${Date.now() - startedAt} mostSlowMs=${slowestMs} index=${slowestIndex}`);
    assert.equal(completed.status, 200, `chunk ${chunkIndex}: ${completed.body}\n${harness.stderr.join("")}`);
  }

  assert.equal(JSON.parse(completed.body).complete, true);
});

test("chunk uploads accept the 8 MiB contract and reject larger parts without staging artifacts", { timeout: 45_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const maxPartBytes = 8 * 1024 * 1024;
  const acceptedId = "max-size-chunk-accepted";
  const accepted = await uploadChunk(harness.port, session, {
    uploadId: acceptedId,
    originalName: "large-client-file.bin",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.alloc(maxPartBytes, 0x61),
  });
  assert.equal(accepted.status, 200, accepted.body);
  assert.equal(fs.statSync(path.join(harness.chunkRoot, FOLDER_ID, acceptedId, "0.part")).size, maxPartBytes);

  const rejectedId = "oversize-chunk-rejected";
  const rejected = await uploadChunk(harness.port, session, {
    uploadId: rejectedId,
    originalName: "oversized-client-part.bin",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.alloc(maxPartBytes + 1, 0x62),
  });
  assert.equal(rejected.status, 413, rejected.body);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, rejectedId)), false);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
});

test("one-part empty chunk uploads complete without creating a zero-byte incoming reservation", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  let response;
  try {
    response = await uploadChunk(harness.port, session, {
      uploadId: "empty-single-part",
      originalName: "empty-single-part.txt",
      chunkIndex: 0,
      totalChunks: 1,
      encryptionLevel: "none",
      bytes: Buffer.alloc(0),
    });
  } catch (error) {
    throw new Error(`${error.message}\n${harness.stderr.join("")}`);
  }

  assert.equal(response.status, 200, response.body);
  assert.equal(JSON.parse(response.body).complete, true);
  assert.equal(fs.statSync(path.join(harness.dir, "temp", FOLDER_ID, "empty-single-part.txt")).size, 0);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
  }
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("ambiguous encrypted handoff without pending metadata preserves destination and quota across restart", { timeout: 30_000 }, async (t) => {
  const uploadId = "ambiguous-encrypted-handoff";
  const fileName = "ambiguous-encrypted-handoff.txt";
  const bytes = Buffer.from("published bytes with partial encryption intent");
  const metadata = legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "server-key", originalName: fileName, fileName });
  const harness = await createHarness(t, {
    waitForReady: false,
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": bytes } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const crypto = require("node:crypto");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const bytes = Buffer.from(${JSON.stringify(bytes.toString())});
      const destination = path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)});
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.writeFileSync(destination, bytes);
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "data", "encrypted-files.json"), JSON.stringify({ [${JSON.stringify(`${FOLDER_ID}/${fileName}`)}]: { folderId: ${JSON.stringify(FOLDER_ID)}, fileName: ${JSON.stringify(fileName)}, encryptionLevel: "server-key" } }));
      const cloudQueue = path.join(${JSON.stringify(dir)}, "data", ".rootark-cloud-temp-mutations");
      fs.mkdirSync(cloudQueue, { recursive: true });
      const digest = crypto.createHash("sha256").update(${JSON.stringify(`${FOLDER_ID}\0${fileName}`)}).digest("hex");
      fs.writeFileSync(path.join(cloudQueue, digest + ".json"), JSON.stringify({ version: 1, folderId: ${JSON.stringify(FOLDER_ID)}, fileName: ${JSON.stringify(fileName)}, desired: "present", generation: "partial-cloud-intent", updatedAt: new Date().toISOString() }));
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "part-charge", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: bytes.length },
        { operationId: "published-charge", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: ${JSON.stringify(`handoff/${FOLDER_ID}/${fileName}#${bytes.length}`)}, state: "handoff_published", chargeBytes: bytes.length },
      ]);
      quota.close();
    `,
  });
  try {
    assert.equal((await waitForServer(harness.port)).status, 200, harness.stderr.join(""));
  } catch (error) {
    throw new Error(`${error.message}\n${harness.stderr.join("")}`);
  }
  const destination = path.join(harness.dir, "temp", FOLDER_ID, fileName);
  assert.deepEqual(fs.readFileSync(destination), bytes, "partial encrypted intent must not cause startup to delete the publication");
  const session = await login(harness.port, "uploader", harness.password);
  const blocked = await uploadChunk(harness.port, session, { uploadId, originalName: fileName, chunkIndex: 0, totalChunks: 1, encryptionLevel: "server-key", bytes });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT state, charge_bytes FROM quota_operations ORDER BY operation_id").all(), [
      { state: "part_committed", charge_bytes: bytes.length },
      { state: "handoff_published", charge_bytes: bytes.length },
    ]);
  } finally {
    database.close();
  }
});

test("chunk multipart without a file or with a parser error releases the pre-Multer reservation", { timeout: 30_000 }, async (t) => {
  const readOperationCount = (harness) => {
    const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      return database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count;
    } finally {
      database.close();
    }
  };
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const noFile = multipartParts([
    { field: "uploadId", bytes: "missing-file" },
    { field: "originalName", bytes: "missing-file.txt" },
    { field: "chunkIndex", bytes: "0" },
    { field: "totalChunks", bytes: "1" },
  ]);
  let noFileResponse;
  try {
    noFileResponse = await request(harness.port, `/upload-chunk?folderId=${FOLDER_ID}`, {
      method: "POST",
      headers: { cookie: session.cookie, origin: `http://127.0.0.1:${harness.port}`, "x-csrf-token": session.csrf, "content-type": noFile.contentType, "content-length": noFile.body.length },
      body: noFile.body,
    });
  } catch (error) {
    throw new Error(`file-less multipart request failed: ${error.code || error.name}: ${error.message}`, { cause: error });
  }
  assert.equal(noFileResponse.status, 400, noFileResponse.body);
  await harness.stopServer();
  assert.equal(readOperationCount(harness), 0, "file-less multipart releases its reservation");

  const malformedHarness = await createHarness(t);
  const malformedSession = await login(malformedHarness.port, "uploader", malformedHarness.password);
  let malformed;
  try {
    malformed = await request(malformedHarness.port, `/upload-chunk?folderId=${FOLDER_ID}`, {
      method: "POST",
      headers: { cookie: malformedSession.cookie, origin: `http://127.0.0.1:${malformedHarness.port}`, "x-csrf-token": malformedSession.csrf, "content-type": "multipart/form-data; boundary=missing-boundary", "content-length": Buffer.byteLength("not multipart data") },
      body: "not multipart data",
    });
  } catch (error) {
    throw new Error(`malformed multipart request failed: ${error.code || error.name}: ${error.message}`, { cause: error });
  }
  assert.equal(malformed.status, 400, malformed.body);
  await malformedHarness.stopServer();
  assert.equal(readOperationCount(malformedHarness), 0, "parser failure before a filename path releases its reservation");
  assert.deepEqual(fs.readdirSync(path.join(malformedHarness.chunkRoot, "incoming")), []);
});

test("failed handoff destination cleanup retains its charge and blocks retries from creating orphan files", { timeout: 30_000 }, async (t) => {
  const uploadId = "handoff-cleanup-failure";
  const harness = await createHarness(t, {
    preloadSource: ({ dir }) => {
      const destinationPath = path.join(dir, "temp", FOLDER_ID, "handoff-cleanup-failure.txt");
      return [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        'const destination = ' + JSON.stringify(destinationPath) + ';',
        'const originalLstatSync = fs.lstatSync;',
        'const originalRmSync = fs.rmSync;',
        'const originalUnlinkSync = fs.unlinkSync;',
        'fs.lstatSync = function (file, ...args) {',
        '  const result = originalLstatSync.call(this, file, ...args);',
        '  if (typeof file === "string" && path.resolve(file) === path.resolve(destination) && result.isFile()) throw Object.assign(new Error("injected post-rename verification failure"), { code: "EIO" });',
        '  return result;',
        '};',
        'fs.rmSync = function (file, ...args) {',
        '  if (typeof file === "string" && path.resolve(file) === path.resolve(destination)) throw Object.assign(new Error("injected published file cleanup failure"), { code: "EIO" });',
        '  return originalRmSync.call(this, file, ...args);',
        '};',
        'fs.unlinkSync = function (file, ...args) {',
        '  if (typeof file === "string" && path.resolve(file) === path.resolve(destination)) throw Object.assign(new Error("injected published file unlink failure"), { code: "EIO" });',
        '  return originalUnlinkSync.call(this, file, ...args);',
        '};',
      ].join("\n");
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "handoff-cleanup-failure.txt",
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "none",
    bytes: Buffer.from("charged until handoff cleanup"),
  });
  assert.equal(response.status, 503, response.body);

  const destinationPath = path.join(harness.dir, "temp", FOLDER_ID, "handoff-cleanup-failure.txt");
  assert.equal(fs.existsSync(destinationPath), true, "the injected failed cleanup leaves the published destination present");
  const retry = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "handoff-cleanup-failure.txt",
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "none",
    bytes: Buffer.from("retry must not publish another orphan"),
  });
  assert.equal(retry.status, 503, retry.body);
  assert.equal(JSON.parse(retry.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal(fs.existsSync(destinationPath), true);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
  await harness.stopServer();
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    const handoff = database.prepare("SELECT operation_id, state, charge_bytes, relative_path FROM quota_operations WHERE state = 'handoff_published'").get();
    assert.ok(handoff, JSON.stringify({ rows: database.prepare("SELECT operation_id, state, charge_bytes, relative_path FROM quota_operations").all(), stderr: harness.stderr }));
    assert.equal(handoff.charge_bytes, fs.statSync(destinationPath).size);
    assert.match(handoff.relative_path.replace(/\\/g, "/"), /^handoff\//);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations WHERE state = 'handoff_published'").get().count, 1);
  } finally {
    database.close();
  }
});

test("a failed handed-off ledger transition preserves registered publication for startup reconciliation", { timeout: 45_000 }, async (t) => {
  const uploadId = "handoff-transition-failure";
  const fileName = "handoff-transition-failure.txt";
  const harness = await createHarness(t, {
    deterministicQuotaRecovery: true,
    preloadSource: () => `
      const quotaModule = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const createQuota = quotaModule.createChunkUploadQuota;
      quotaModule.createChunkUploadQuota = (...args) => {
        const quota = createQuota(...args);
        const transition = quota.transition;
        let injected = false;
        quota.transition = (operation) => {
          if (!injected && operation.state === "handed_off") {
            injected = true;
            throw Object.assign(new Error("injected post-registration ledger failure"), { code: "EIO" });
          }
          return transition(operation);
        };
        return quota;
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("registered bytes survive ledger transition failure");
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: fileName,
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "none",
    bytes,
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");

  const destinationPath = path.join(harness.dir, "temp", FOLDER_ID, fileName);
  const pendingPath = path.join(harness.dir, "data", "pending-uploads.json");
  const quotaPath = path.join(harness.chunkRoot, ".quota.sqlite");
  const originalServerPid = harness.child.pid;
  assert.deepEqual(fs.readFileSync(destinationPath), bytes);
  assert.ok(JSON.parse(fs.readFileSync(pendingPath, "utf8"))[`${FOLDER_ID}/${fileName}`]);
  const retry = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: fileName,
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "none",
    bytes: Buffer.from("must not create another published copy"),
  });
  assert.equal(retry.status, 503, retry.body);
  assert.equal(JSON.parse(retry.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.deepEqual(fs.readFileSync(destinationPath), bytes);
  await harness.stopServer();
  const database = new Database(quotaPath, { readonly: true });
  try {
    const operation = database.prepare("SELECT state, charge_bytes, relative_path FROM quota_operations WHERE state = 'handoff_published'").get();
    assert.ok(operation);
    assert.equal(operation.charge_bytes, bytes.length);
    assert.equal(operation.relative_path.replaceAll("\\", "/"), `handoff/${FOLDER_ID}/${encodeURIComponent(fileName)}#${bytes.length}`);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations WHERE state = 'handoff_published'").get().count, 1);
  } finally {
    database.close();
  }

  const recoveryPort = await getUnusedPort();
  const recoveryChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, SERVER], {
    cwd: harness.dir,
    env: {
      ...process.env,
      ...testDeadQuotaOwnerEnv(originalServerPid),
      NODE_ENV: "test",
      PORT: String(recoveryPort),
      DB_ENABLED: "false",
      DB_READ_FALLBACK_JSON: "true",
      DB_WRITE_LEGACY_JSON: "true",
      ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
      CLOUD_STORAGE_PROVIDER: "local",
      UPLOAD_SCAN_ENABLED: "true",
      UPLOAD_SCAN_PROVIDER: "disabled",
      UPLOAD_BLOCK_EXECUTABLES: "true",
      UPLOAD_QUARANTINE_DIR: harness.quarantineDir,
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024),
      CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024),
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000",
      CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000",
      CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const recoveryStderr = [];
  recoveryChild.stderr.on("data", (chunk) => recoveryStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(recoveryPort)).status, 200, recoveryStderr.join(""));
    assert.deepEqual(fs.readFileSync(destinationPath), bytes);
    assert.ok(JSON.parse(fs.readFileSync(pendingPath, "utf8"))[`${FOLDER_ID}/${fileName}`]);
    assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId)), false, recoveryStderr.join(""));
  } finally {
    if (recoveryChild.exitCode === null) {
      recoveryChild.kill();
      await waitForExit(recoveryChild);
    }
  }
  const recoveredLedger = new Database(quotaPath, { readonly: true });
  try {
    assert.equal(recoveredLedger.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    recoveredLedger.close();
  }
});

test("partial encrypted handoff registration preserves publication and charge while startup fails closed", { timeout: 45_000 }, async (t) => {
  const fileName = "partial-registration.txt";
  const uploadId = "partial-registration";
  const harness = await createHarness(t, {
    preloadSource: ({ dir }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const writeFileSync = fs.writeFileSync;
      let pendingWasWritten = false;
      let pendingRollbackFailed = false;
      fs.writeFileSync = (file, data, ...args) => {
        const name = String(file).replaceAll("\\\\", "/");
        const content = Buffer.isBuffer(data) ? data.toString("utf8") : String(data);
        if (name.endsWith("/data/encrypted-files.json") && content.includes(${JSON.stringify(fileName)})) {
          throw Object.assign(new Error("injected encrypted metadata write failure"), { code: "EIO" });
        }
        if (name.endsWith("/data/pending-uploads.json") && content.includes(${JSON.stringify(fileName)})) pendingWasWritten = true;
        else if (pendingWasWritten && !pendingRollbackFailed && name.endsWith("/data/pending-uploads.json")) {
          pendingRollbackFailed = true;
          throw Object.assign(new Error("injected pending rollback failure"), { code: "EIO" });
        }
        return writeFileSync.call(fs, file, data, ...args);
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("encrypted bytes retained after partial registration");
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: fileName,
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "server-key",
    bytes,
  });
  assert.equal(response.status, 503, response.body);
  const destinationPath = path.join(harness.dir, "temp", FOLDER_ID, fileName);
  assert.ok(fs.statSync(destinationPath).size > 0, "encrypted publication remains present");
  assert.ok(pending(harness.dir)[`${FOLDER_ID}/${fileName}`]);
  const quotaPath = path.join(harness.chunkRoot, ".quota.sqlite");
  const database = new Database(quotaPath, { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT state, charge_bytes FROM quota_operations WHERE state = 'handoff_published'").get(), {
      state: "handoff_published",
      charge_bytes: bytes.length,
    });
  } finally {
    database.close();
  }

  harness.child.kill();
  await waitForExit(harness.child);
  const recoveryPort = await getUnusedPort();
  const recoveryChild = spawn(process.execPath, [SERVER], {
    cwd: harness.dir,
    env: { ...process.env, NODE_ENV: "test", PORT: String(recoveryPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_SCAN_PROVIDER: "disabled", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const recoveryStderr = [];
  recoveryChild.stderr.on("data", (chunk) => recoveryStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(recoveryPort)).status, 200, recoveryStderr.join(""));
    assert.ok(fs.statSync(destinationPath).size > 0, "restart keeps the encrypted publication");
    assert.ok(pending(harness.dir)[`${FOLDER_ID}/${fileName}`]);
    const encryptedEntries = JSON.parse(fs.readFileSync(path.join(harness.dir, "data", "encrypted-files.json"), "utf8"));
    assert.equal(encryptedEntries[`${FOLDER_ID}/${fileName}`], undefined, "the fixture leaves encrypted intent incomplete");
    assert.deepEqual(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part")), bytes, "accepted source part remains available for reconciliation");
    const recoveredLedger = new Database(quotaPath, { readonly: true });
    try {
      assert.deepEqual(recoveredLedger.prepare("SELECT state, charge_bytes FROM quota_operations WHERE state = 'handoff_published'").get(), {
        state: "handoff_published",
        charge_bytes: bytes.length,
      });
    } finally {
      recoveredLedger.close();
    }
    const recoveredSession = await login(recoveryPort, "uploader", harness.password);
    const failClosed = await uploadChunk(recoveryPort, recoveredSession, { uploadId, originalName: fileName, chunkIndex: 0, totalChunks: 1, encryptionLevel: "server-key", bytes });
    assert.equal(failClosed.status, 503, failClosed.body);
    assert.equal(JSON.parse(failClosed.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  } finally {
    if (recoveryChild.exitCode === null) {
      recoveryChild.kill();
      await waitForExit(recoveryChild);
    }
  }
});

test("concurrent chunk sessions preserve both payloads without replacing a colliding destination", { timeout: 45_000 }, async (t) => {
  const name = "same-requested-name.txt";
  const collision = Buffer.from("file created concurrently after name selection");
  const harness = await createHarness(t, {
    preloadSource: ({ dir }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const writeFileSync = fs.writeFileSync;
      const target = path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(name)});
      const marker = path.join(${JSON.stringify(dir)}, "data", "collision-injected");
      let injected = false;
      for (const method of ["renameSync", "linkSync"]) {
        const original = fs[method];
        fs[method] = (source, destination, ...args) => {
          if (!injected && path.basename(String(source)) === "assembled.upload" && path.resolve(String(destination)) === path.resolve(target)) {
            injected = true;
            fs.mkdirSync(path.dirname(target), { recursive: true });
            writeFileSync(marker, "yes");
            writeFileSync(target, ${JSON.stringify(collision.toString())}, { flag: "wx" });
          }
          return original.call(fs, source, destination, ...args);
        };
      }
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const first = Buffer.from("first session content");
  const second = Buffer.from("second session content");
  for (const [uploadId, bytes] of [["same-name-first", first], ["same-name-second", second]]) {
    const response = await uploadChunk(harness.port, session, { uploadId, originalName: name, chunkIndex: 0, totalChunks: 2, encryptionLevel: "none", bytes });
    assert.equal(response.status, 200, response.body);
    assert.equal(JSON.parse(response.body).complete, false);
  }
  const completionInputs = [
    { uploadId: "same-name-first", bytes: Buffer.from("first tail") },
    { uploadId: "same-name-second", bytes: Buffer.from("second tail") },
  ];
  const completions = await Promise.all(completionInputs.map(({ uploadId, bytes }) => uploadChunk(harness.port, session, { uploadId, originalName: name, chunkIndex: 1, totalChunks: 2, encryptionLevel: "none", bytes })));
  assert.equal(fs.existsSync(path.join(harness.dir, "data", "collision-injected")), true, "fixture placed a colliding file after filename selection");
  assert.ok(completions.some((result) => result.status === 200));
  assert.ok(completions.some((result) => result.status !== 200), completions.map((result) => result.body).join("\n"));
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, name)), collision, "collision target is never overwritten");
  const failedIndex = completions.findIndex((result) => result.status !== 200);
  const retry = await uploadChunk(harness.port, session, {
    uploadId: completionInputs[failedIndex].uploadId,
    originalName: name,
    chunkIndex: 1,
    totalChunks: 2,
    encryptionLevel: "none",
    bytes: completionInputs[failedIndex].bytes,
  });
  assert.equal(retry.status, 200, retry.body);
  const names = Object.keys(pending(harness.dir)).map((key) => key.split("/").at(-1)).sort();
  assert.deepEqual(names, ["same-requested-name-1.txt", "same-requested-name-2.txt"]);
  const pendingEntries = pending(harness.dir);
  assert.equal(Object.keys(pendingEntries).length, 2);
  const contents = names.filter((fileName) => fileName !== name).map((fileName) => fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName), "utf8")).sort();
  assert.deepEqual(contents, ["first session contentfirst tail", "second session contentsecond tail"].sort());
});

test("Multer rejects malformed or disallowed multipart bodies without artifacts", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const checkout = [path.join(ROOT, "temp", ".incoming"), path.join(ROOT, "temp", FOLDER_ID), path.join(ROOT, "data", "pending-uploads.json"), path.join(ROOT, "data", "quarantine.json")];
  const checkoutBefore = checkout.map((target) => filesUnder(target));
  const normal = multipart("truncated.txt", Buffer.from("partial"));
  const cases = [
    ["truncated multipart body", { ...normal, body: normal.body.subarray(0, normal.body.length - 8) }],
    ["malformed boundary", { body: Buffer.from("not-a-multipart-body"), contentType: "multipart/form-data; boundary=missing" }],
    ["unexpected file field", multipartParts([{ field: "attachment", filename: "wrong.txt", bytes: "wrong" }])],
    ["multiple file parts", multipartParts([{ filename: "one.txt", bytes: "one" }, { filename: "two.txt", bytes: "two" }])],
    ["nested field name", multipartParts([{ field: "versionComment[nested]", bytes: "value" }, { filename: "nested.txt", bytes: "file" }])],
    ["oversized file", multipart("large.bin", Buffer.alloc(8 * 1024 * 1024 + 1, 0x61))],
  ];

  for (const [name, payload] of cases) {
    await t.test(name, async () => {
      const response = await uploadPayload(harness.port, session, payload);
      assertRejectedClean(harness, response);
      assert.deepEqual(checkout.map((target) => filesUnder(target)), checkoutBefore);
    });
  }
});

test("valid binary and UTF-8 filename uploads preserve bytes and API names", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from([0, 255, 1, 254, 13, 10, 128, 127]);
  const fileName = "ação-測試.bin";
  const response = await upload(harness.port, session, fileName, bytes);
  const result = JSON.parse(response.body);

  assert.equal(response.status, 200, response.body);
  assert.equal(result.fileName, fileName);
  assert.equal(result.originalName, fileName);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
});

test("chunk uploads scrub legacy secrets and require the final password before saving the last part", { timeout: 45_000 }, async (t) => {
  const legacyId = "legacy-resume";
  const firstPart = Buffer.from("resumed ");
  const finalPart = Buffer.from("upload\n");
  const migrationStartedAt = Date.now();
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId: legacyId, files: { "metadata.json": legacyChunkMetadata(legacyId), "0.part": firstPart } }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const legacyDir = path.join(harness.chunkRoot, FOLDER_ID, legacyId);
  const legacyMetadataPath = path.join(legacyDir, "metadata.json");
  const scrubbedLegacyMetadata = JSON.parse(fs.readFileSync(legacyMetadataPath, "utf8"));
  assert.equal(Object.hasOwn(scrubbedLegacyMetadata, "password"), false);
  assert.ok(Date.parse(scrubbedLegacyMetadata.lastActivityAt) >= migrationStartedAt, "legacy sessions receive a conservative fresh retention window");
  assert.equal(fs.readFileSync(path.join(legacyDir, "0.part")).toString(), firstPart.toString());

  const password = "final-only-secret-42";
  const resumed = await uploadChunk(harness.port, session, {
    uploadId: legacyId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: finalPart,
    password,
  });
  assert.equal(resumed.status, 200, resumed.body);
  assert.equal(JSON.parse(resumed.body).complete, true);
  const encryptedFilePath = path.join(harness.dir, "temp", FOLDER_ID, "encrypted.txt");
  const encryptedFile = fs.readFileSync(encryptedFilePath);
  const encryptedMetadata = JSON.parse(fs.readFileSync(path.join(harness.dir, "data", "encrypted-files.json"), "utf8"))[`${FOLDER_ID}/encrypted.txt`];
  assert.equal(encryptedMetadata.accessControl.requiresPassword, true);
  assert.equal(JSON.stringify(encryptedMetadata).includes(password), false);
  assert.notDeepEqual(encryptedFile, Buffer.concat([firstPart, finalPart]));
  const layer = encryptedMetadata.layers.find((item) => item.type === "password");
  const key = crypto.pbkdf2Sync(password, Buffer.from(layer.salt, "hex"), encryptedMetadata.iterations, 32, "sha256");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(layer.iv, "hex"));
  decipher.setAuthTag(Buffer.from(layer.authTag, "hex"));
  const decrypted = Buffer.concat([decipher.update(encryptedFile), decipher.final()]);
  assert.deepEqual(decrypted, Buffer.concat([firstPart, finalPart]));

  const newUploadId = "new-password-upload";
  const first = await uploadChunk(harness.port, session, {
    uploadId: newUploadId,
    originalName: "new-encrypted.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("first "),
    encryptionLevel: "password",
    password,
  });
  assert.equal(first.status, 200, first.body);
  const newSessionDir = path.join(harness.chunkRoot, FOLDER_ID, newUploadId);
  const firstMetadata = JSON.parse(fs.readFileSync(path.join(newSessionDir, "metadata.json"), "utf8"));
  assert.equal(Object.hasOwn(firstMetadata, "password"), false);
  assert.equal(JSON.stringify(firstMetadata).includes(password), false);
  assert.equal(fs.existsSync(path.join(newSessionDir, "1.part")), false);

  const rejectedFinal = await uploadChunk(harness.port, session, {
    uploadId: newUploadId,
    originalName: "new-encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("last"),
  });
  assert.equal(rejectedFinal.status, 400, rejectedFinal.body);
  assert.match(JSON.parse(rejectedFinal.body).error, /bloco final/i);
  assert.equal(fs.readFileSync(path.join(newSessionDir, "0.part")).toString(), "first ");
  assert.equal(fs.existsSync(path.join(newSessionDir, "1.part")), false);

  const acceptedFinal = await uploadChunk(harness.port, session, {
    uploadId: newUploadId,
    originalName: "new-encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("last"),
    password,
  });
  assert.equal(acceptedFinal.status, 200, acceptedFinal.body);
  assert.equal(JSON.parse(acceptedFinal.body).complete, true);
  assert.equal(fs.existsSync(newSessionDir), false);
  assert.equal((harness.stdout.join("") + harness.stderr.join("")).includes(password), false);
});

test("chunk session ids and numeric chunk indexes remain contained at their boundaries", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);

  const traversal = await uploadChunk(harness.port, session, {
    uploadId: "../outside-session",
    originalName: "bounded.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: "must not escape",
  });
  assert.equal(traversal.status, 400, traversal.body);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, "outside-session")), false);

  const uploadId = "bounded-index";
  const acceptedBoundary = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "bounded.txt",
    chunkIndex: 1999,
    totalChunks: 2000,
    bytes: "last allowed index",
  });
  assert.equal(acceptedBoundary.status, 200, acceptedBoundary.body);
  assert.equal(JSON.parse(acceptedBoundary.body).complete, false);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.readFileSync(path.join(sessionDir, "1999.part"), "utf8"), "last allowed index");

  const rejectedBoundary = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "bounded.txt",
    chunkIndex: 2000,
    totalChunks: 2000,
    bytes: "out of range",
  });
  assert.equal(rejectedBoundary.status, 400, rejectedBoundary.body);
  assert.equal(fs.existsSync(path.join(sessionDir, "2000.part")), false);
});

test("chunk metadata rejects path swaps with adjacent 64-bit file IDs", { timeout: 45_000 }, async (t) => {
  const uploadId = "file-id-precision";
  const adjacent = 9_007_199_254_740_992n;
  const harness = await createHarness(t, {
    waitForReady: false,
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId), "0.part": "original first part" } }],
    preloadSource: [
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      'const adjacent = 9007199254740992n;',
      'const matches = (target) => path.resolve(String(target)).split(path.sep).join("/").endsWith("/file-id-precision/metadata.json");',
      'const originalOpen = fs.openSync;',
      'const originalFstat = fs.fstatSync;',
      'const originalLstat = fs.lstatSync;',
      'const originalClose = fs.closeSync;',
      'const originalPromisesOpen = fs.promises.open;',
      'const originalPromisesLstat = fs.promises.lstat;',
      'const descriptors = new Set();',
      'const identify = (stats, args, ino) => new Proxy(stats, { get(target, key, receiver) { if (key === "dev") return args[0]?.bigint === true ? 1n : 1; if (key === "ino") return args[0]?.bigint === true ? ino : Number(ino); return Reflect.get(target, key, receiver); } });',
      'fs.openSync = function (target, ...args) { const fd = originalOpen.call(this, target, ...args); if (matches(target)) descriptors.add(fd); return fd; };',
      'fs.fstatSync = function (fd, ...args) { const stats = originalFstat.call(this, fd, ...args); return descriptors.has(fd) ? identify(stats, args, adjacent) : stats; };',
      'fs.closeSync = function (fd) { descriptors.delete(fd); return originalClose.call(this, fd); };',
      'fs.lstatSync = function (target, ...args) { const stats = originalLstat.call(this, target, ...args); return matches(target) ? identify(stats, args, adjacent + 1n) : stats; };',
      'fs.promises.open = async function (target, ...args) { const handle = await originalPromisesOpen.call(this, target, ...args); if (matches(target)) { const stat = handle.stat.bind(handle); handle.stat = async (...statArgs) => identify(await stat(...statArgs), statArgs, adjacent); } return handle; };',
      'fs.promises.lstat = async function (target, ...args) { const stats = await originalPromisesLstat.call(this, target, ...args); return matches(target) ? identify(stats, args, adjacent + 1n) : stats; };'
    ].join("\n"),
  });
  try { await waitForServer(harness.port); } catch (error) { throw new Error(error.message + "\n" + harness.stderr.join("")); }
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("second part"),
    password: "disposable-final-password",
  });
  assert.equal(Number(adjacent), Number(adjacent + 1n), "the injected adjacent file IDs collide as Numbers");
  assert.notEqual(response.status, 200, response.body);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "original first part");
  assert.equal(fs.existsSync(path.join(sessionDir, "1.part")), false);
});

test("chunk-session expiry sweep rejects path swaps with adjacent 64-bit file IDs", { timeout: 45_000 }, async (t) => {
  const uploadId = "async-file-id-precision";
  let metadataPath;
  let enablePath;
  let observedPath;
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId), "0.part": "original first part" } }],
    preloadSource: ({ dir, chunkRoot }) => {
      metadataPath = path.join(chunkRoot, FOLDER_ID, uploadId, "metadata.json");
      enablePath = path.join(dir, "enable-async-file-id-injection");
      observedPath = path.join(dir, "async-file-id-injection-observations");
      return [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        `const target = ${JSON.stringify(metadataPath)};`,
        `const enable = ${JSON.stringify(enablePath)};`,
        `const observed = ${JSON.stringify(observedPath)};`,
        'const adjacent = 9007199254740992n;',
        'const matches = (candidate) => path.resolve(String(candidate)) === path.resolve(target);',
        'const identify = (stats, args, ino) => new Proxy(stats, { get(value, key, receiver) { if (key === "dev") return args[0]?.bigint === true ? 1n : 1; if (key === "ino") return args[0]?.bigint === true ? ino : Number(ino); return Reflect.get(value, key, receiver); } });',
        'const originalOpenSync = fs.openSync;',
        'const originalFstatSync = fs.fstatSync;',
        'const originalLstatSync = fs.lstatSync;',
        'const targetDescriptors = new Set();',
        'fs.openSync = function (candidate, ...args) { const descriptor = originalOpenSync.call(this, candidate, ...args); if (matches(candidate)) targetDescriptors.add(descriptor); return descriptor; };',
        'fs.fstatSync = function (descriptor, ...args) { const value = originalFstatSync.call(this, descriptor, ...args); return targetDescriptors.has(descriptor) && fs.existsSync(enable) ? identify(value, args, adjacent) : value; };',
        'fs.lstatSync = function (candidate, ...args) { const value = originalLstatSync.call(this, candidate, ...args); if (!matches(candidate) || !fs.existsSync(enable)) return value; fs.appendFileSync(observed, "x"); return identify(value, args, adjacent + 1n); };',
      ].join("\n");
    },
  });

  fs.writeFileSync(enablePath, "enabled", { flag: "wx" });
  const firstSweepDeadline = Date.now() + 5_000;
  while ((!fs.existsSync(observedPath) || fs.readFileSync(observedPath, "utf8").length < 1) && Date.now() < firstSweepDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(fs.existsSync(observedPath), true, "the expiry reader inspected the metadata after injection was enabled");

  const expiredAt = new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString();
  const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  metadata.lastActivityAt = expiredAt;
  fs.writeFileSync(metadataPath, JSON.stringify(metadata));
  const secondSweepDeadline = Date.now() + 5_000;
  while (fs.readFileSync(observedPath, "utf8").length < 2 && Date.now() < secondSweepDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.ok(fs.readFileSync(observedPath, "utf8").length >= 2, "the expiry reader reached a second sweep after the fixture became expired");
  await new Promise((resolve) => setTimeout(resolve, 100));

  const sessionDir = path.dirname(metadataPath);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "original first part");
  const preservedMetadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  assert.equal(preservedMetadata.lastActivityAt, expiredAt);
  assert.equal(Object.hasOwn(preservedMetadata, "__expiredAt"), false, "an identity-mismatched session is not expired or rewritten");
});

test("malformed, unreadable, and orphan chunk sessions cannot overwrite retained parts", { timeout: 45_000 }, async (t) => {
  let unreadableMetadataPath;
  let markerPath;
  const unreadableId = "unreadable-session";
  const malformedId = "malformed-session";
  const orphanId = "orphan-session";
  const harness = await createHarness(t, {
    chunkSessions: [
      { uploadId: unreadableId, files: { "metadata.json": legacyChunkMetadata(unreadableId), "0.part": "unreadable-original" } },
      { uploadId: malformedId, files: { "metadata.json": "{invalid", "0.part": "malformed-original" } },
      { uploadId: orphanId, files: { "0.part": "orphan-original" } },
    ],
    preloadSource: ({ dir, chunkRoot }) => {
      unreadableMetadataPath = path.join(chunkRoot, FOLDER_ID, unreadableId, "metadata.json");
      markerPath = path.join(dir, "unreadable-read-attempted");
      return [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        `const target = ${JSON.stringify(unreadableMetadataPath)};`,
        `const marker = ${JSON.stringify(markerPath)};`,
        "const originalOpenSync = fs.openSync;",
        "fs.openSync = function (file, flags, ...args) {",
        "  if (typeof file === 'string' && path.resolve(file) === path.resolve(target) && (flags & fs.constants.O_RDONLY) === fs.constants.O_RDONLY) {",
        "    fs.writeFileSync(marker, 'triggered');",
        "    const error = new Error('injected metadata read failure'); error.code = 'EACCES'; throw error;",
        "  }",
        "  return originalOpenSync.call(this, file, flags, ...args);",
        "};",
      ].join("\n");
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  assert.equal(fs.readFileSync(markerPath, "utf8"), "triggered");
  for (const [uploadId, partName, original] of [
    [unreadableId, "0.part", "unreadable-original"],
    [malformedId, "0.part", "malformed-original"],
    [orphanId, "0.part", "orphan-original"],
  ]) {
    const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
    const blocked = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
    assert.equal(blocked.__resumeBlocked, true, uploadId);
    assert.equal(JSON.stringify(blocked).includes("legacy-secret-that-must-be-removed"), false);
    const response = await uploadChunk(harness.port, session, {
      uploadId,
      originalName: "encrypted.txt",
      chunkIndex: 0,
      totalChunks: 2,
      bytes: "attempted-overwrite",
      encryptionLevel: "password",
      password: "new-password-42",
    });
    assert.equal(response.status, 503, response.body);
    assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
    assert.equal(fs.readFileSync(path.join(sessionDir, partName), "utf8"), original);
  }
});

test("unsafe chunk session symlinks are rejected before touching the target", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const folderDir = path.join(harness.chunkRoot, FOLDER_ID);
  const targetDir = path.join(harness.dir, "outside-session-target");
  fs.mkdirSync(folderDir, { recursive: true });
  fs.mkdirSync(targetDir);
  fs.writeFileSync(path.join(targetDir, "keep.txt"), "do not touch");
  const sessionDir = path.join(folderDir, "linked-session");
  try {
    fs.symlinkSync(targetDir, sessionDir, process.platform === "win32" ? "junction" : "dir");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip(`directory symlink unavailable: ${error.code}`);
    throw error;
  }

  const response = await uploadChunk(harness.port, session, {
    uploadId: "linked-session",
    originalName: "encrypted.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: "must-not-write",
    encryptionLevel: "password",
    password: "new-password-42",
  });
  assert.equal(response.status, 400, response.body);
  assert.equal(fs.readFileSync(path.join(targetDir, "keep.txt"), "utf8"), "do not touch");
  assert.equal(fs.existsSync(path.join(targetDir, "0.part")), false);
});

test("unsafe chunk storage symlinks disable only chunk uploads at startup", { timeout: 30_000 }, async (t) => {
  let outsidePath;
  let markerPath;
  const harness = await createHarness(t, {
    waitForReady: false,
    preloadSource: ({ dir }) => {
      outsidePath = path.join(dir, "outside-chunk-storage");
      markerPath = path.join(dir, "chunk-storage-symlink-created");
      return [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        `const root = ${JSON.stringify(dir)};`,
        `const outside = ${JSON.stringify(outsidePath)};`,
        `const marker = ${JSON.stringify(markerPath)};`,
        'const temp = path.join(root, "temp");',
        'const chunkRoot = path.join(temp, ".chunks");',
        'fs.mkdirSync(temp, { recursive: true });',
        'fs.mkdirSync(outside, { recursive: true });',
        'try {',
        '  fs.symlinkSync(outside, chunkRoot, process.platform === "win32" ? "junction" : "dir");',
        '  fs.writeFileSync(marker, "created");',
        '} catch (error) {',
        '  fs.writeFileSync(marker, `unavailable:${error.code || "unknown"}`);',
        '}',
      ].join("\n");
    },
  });

  assert.equal(await waitForFile(markerPath), true, "startup did not reach the injected storage path setup");
  const setup = fs.readFileSync(markerPath, "utf8");
  if (setup.startsWith("unavailable:")) return t.skip(`chunk storage symlink unavailable: ${setup.slice("unavailable:".length)}`);

  assert.equal((await waitForServer(harness.port)).status, 200);
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "unsafe-storage-startup",
    originalName: "unsafe-storage-startup.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not write"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal(fs.existsSync(path.join(outsidePath, "incoming")), false);
  assert.equal((await request(harness.port, "/login.html")).status, 200);
});

test("chunk upload startup disables only chunk uploads when session enumeration cannot be verified", { timeout: 45_000 }, async (t) => {
  for (const targetName of ["root", "folder"]) {
    await t.test(`${targetName} directory enumeration failure`, { timeout: 20_000 }, async (nested) => {
      let markerPath;
      const harness = await createHarness(nested, {
        waitForReady: false,
        chunkSessions: targetName === "folder" ? [{ uploadId: "enumeration-seed", files: {} }] : [],
        preloadSource: ({ dir, chunkRoot }) => {
          const targetPath = targetName === "root" ? chunkRoot : path.join(chunkRoot, FOLDER_ID);
          markerPath = path.join(dir, "enumeration-failure-injected");
          return [
            'const fs = require("node:fs");',
            'const path = require("node:path");',
            `const target = ${JSON.stringify(targetPath)};`,
            `const marker = ${JSON.stringify(markerPath)};`,
            "const originalReaddirSync = fs.readdirSync;",
            "fs.readdirSync = function (directory, ...args) {",
            "  if (typeof directory === 'string' && path.resolve(directory) === path.resolve(target)) {",
            "    fs.writeFileSync(marker, 'triggered');",
            "    const error = new Error('injected directory enumeration failure'); error.code = 'EACCES'; throw error;",
            "  }",
            "  return originalReaddirSync.call(this, directory, ...args);",
            "};",
          ].join("\n");
        },
      });
      assert.equal((await waitForServer(harness.port)).status, 200);
      assert.equal(fs.readFileSync(markerPath, "utf8"), "triggered");
      const session = await login(harness.port, "uploader", harness.password);
      const response = await uploadChunk(harness.port, session, {
        uploadId: `enumeration-${targetName}`,
        originalName: "enumeration.txt",
        chunkIndex: 0,
        totalChunks: 1,
        bytes: Buffer.from("must not stage"),
      });
      assert.equal(response.status, 503, response.body);
      assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
      assert.equal((await request(harness.port, "/login.html")).status, 200);
    });
  }
});

test("folder lifecycle lock timeouts reject uploads, remove transient staging, and preserve accepted session data", { timeout: 30_000 }, async (t) => {
  const uploadId = "lifecycle-timeout-chunk";
  let timeoutResponseMarker;
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, {
          originalName: "timeout-chunk.txt",
          fileName: "timeout-chunk.txt",
          totalChunks: 2,
          encryptionLevel: "none",
        }),
        "0.part": "preserve accepted chunk",
      },
    }],
    preloadSource: ({ dir }) => {
      const sessionDir = path.join(dir, "temp", ".chunks", FOLDER_ID, uploadId);
      timeoutResponseMarker = path.join(dir, "chunk-timeout-response-marker.txt");
      return [
        "const lockModule = require(" + JSON.stringify(path.join(ROOT, "services", "fileLifecycleLock.js")) + ");",
        "const create = lockModule.createFileLifecycleLock;",
        "lockModule.createFileLifecycleLock = (options) => create({ ...options, timeoutMs: 150, pollMs: 5 });",
        'const fs = require("node:fs");',
        `const expressResponse = require(${JSON.stringify(require.resolve("express/lib/response", { paths: [ROOT] }))});`,
        `const sessionDir = ${JSON.stringify(sessionDir)};`,
        `const markerPath = ${JSON.stringify(timeoutResponseMarker)};`,
        "const originalJson = expressResponse.json;",
        'expressResponse.json = function (...args) { if (this.statusCode === 503 && this.req?.url?.startsWith("/upload-chunk")) fs.writeFileSync(markerPath, fs.existsSync(sessionDir) ? "present" : "absent"); return originalJson.apply(this, args); };',
        'process.env.WEBDAV_ENABLED = "true";',
      ].join("\n");
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const existingSessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const { createFileLifecycleLock } = require("../services/fileLifecycleLock");
  const lock = createFileLifecycleLock({
    directory: path.join(harness.dir, "data", ".rootark-cloud-file-locks"),
    timeoutMs: 10_000,
    pollMs: 5,
  });
  let releaseLock;
  let markLockHeld;
  const lockHeld = new Promise((resolve) => { markLockHeld = resolve; });
  const heldOperation = lock.runFolder(FOLDER_ID, async () => {
    markLockHeld();
    await new Promise((resolve) => { releaseLock = resolve; });
  });
  await lockHeld;

  try {
    const simple = await upload(harness.port, session, "timeout-simple.txt", Buffer.from("disposable simple upload"));
    assertRejectedClean(harness, simple, 503);

    const chunk = await uploadChunk(harness.port, session, {
      uploadId,
      originalName: "timeout-chunk.txt",
      chunkIndex: 1,
      totalChunks: 2,
      bytes: Buffer.from("disposable final chunk"),
    });
    assertRejectedClean(harness, chunk, 503);
    assert.equal(chunk.headers["retry-after"], "5");
    assert.equal(fs.existsSync(existingSessionDir), true);
    assert.equal(fs.readFileSync(path.join(existingSessionDir, "0.part"), "utf8"), "preserve accepted chunk");
    assert.equal(fs.readFileSync(path.join(existingSessionDir, "1.part"), "utf8"), "disposable final chunk");
    assert.equal(fs.readFileSync(timeoutResponseMarker, "utf8"), "present", "the existing session remains present when the 503 response is sent");
    assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
    const webDavBody = Buffer.from("disposable WebDAV upload");
    const webDav = await request(harness.port, "/dav/" + FOLDER_ID + "/timeout-webdav.txt", {
      method: "PUT",
      headers: {
        authorization: "Basic " + Buffer.from("uploader:" + harness.password).toString("base64"),
        "content-length": webDavBody.length,
      },
      body: webDavBody,
    });
    assertRejectedClean(harness, webDav, 503);
  } finally {
    releaseLock();
    await heldOperation;
  }
  await harness.stopServer();
  const quotaDatabase = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    const sessionOperations = quotaDatabase.prepare("SELECT state, relative_path FROM quota_operations WHERE session_key = ? ORDER BY relative_path").all(`${FOLDER_ID}/${uploadId}`);
    assert.deepEqual(sessionOperations.map((operation) => [operation.state, operation.relative_path]), [
      ["part_committed", path.join(FOLDER_ID, uploadId, "0.part")],
      ["part_committed", path.join(FOLDER_ID, uploadId, "1.part")],
    ]);
  } finally {
    quotaDatabase.close();
  }
});

test("a timed-out duplicate chunk request cannot mutate an active upload session", { timeout: 30_000 }, async (t) => {
  const scanner = await startGatedClamAv();
  t.after(async () => {
    for (const gate of scanner.scans) gate.release();
    await new Promise((resolve) => scanner.server.close(resolve));
  });
  const uploadId = "Concurrent-Timeout-Chunk";
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, {
          originalName: "concurrent-timeout.txt",
          fileName: "concurrent-timeout.txt",
          totalChunks: 2,
          encryptionLevel: "none",
        }),
        "0.part": Buffer.alloc(2 * 1024 * 1024, 0x61),
      },
    }],
    preloadSource: () => {
      return [
        "const lockModule = require(" + JSON.stringify(path.join(ROOT, "services", "fileLifecycleLock.js")) + ");",
        "const create = lockModule.createFileLifecycleLock;",
        "lockModule.createFileLifecycleLock = (options) => create({ ...options, timeoutMs: 200, pollMs: 5 });",
      ].join("\n");
    },
    envOverrides: { UPLOAD_SCAN_PROVIDER: "clamav", CLAMAV_HOST: "127.0.0.1", CLAMAV_PORT: String(scanner.port) },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const { createFileLifecycleLock } = require("../services/fileLifecycleLock");
  const lock = createFileLifecycleLock({
    directory: path.join(harness.dir, "data", ".rootark-cloud-file-locks"),
    timeoutMs: 10_000,
    pollMs: 5,
  });
  let releaseFolder;
  let markFolderHeld;
  const folderHeld = new Promise((resolve) => { markFolderHeld = resolve; });
  const heldOperation = lock.runFolder(FOLDER_ID, async () => {
    markFolderHeld();
    await new Promise((resolve) => { releaseFolder = resolve; });
  });
  await folderHeld;

  try {
    const uploadArgs = {
      uploadId,
      originalName: "concurrent-timeout.txt",
      chunkIndex: 1,
      totalChunks: 2,
      bytes: Buffer.alloc(2 * 1024 * 1024, 0x62),
    };
    const firstPromise = uploadChunk(harness.port, session, uploadArgs);
    const firstScanDeadline = Date.now() + 5000;
    while (scanner.scans.length < 1 && Date.now() < firstScanDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.ok(scanner.scans[0], "first upload did not reach scanning");
    await scanner.scans[0].started;

    const secondArgs = {
      ...uploadArgs,
      uploadId: process.platform === "win32" ? uploadId.toLowerCase() : uploadId,
    };
    const secondPromise = uploadChunk(harness.port, session, secondArgs);
    const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
    const stagedPath = path.join(sessionDir, "assembled.upload");
    const second = await secondPromise;
    assert.equal(second.status, 503, second.body);
    assert.equal(fs.existsSync(stagedPath), true, "a timed-out duplicate request must not remove another request's staged file");
    const activeMetadata = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
    assert.notEqual(activeMetadata.__resumeBlocked, true, "an alias request must not block the active session metadata");

    scanner.scans[0].release();
    const first = await firstPromise;
    assert.equal(first.status, 503, first.body);
  } finally {
    releaseFolder();
    await heldOperation;
  }
});

