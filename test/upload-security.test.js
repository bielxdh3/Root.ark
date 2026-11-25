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

test("release gate mock identifies native Windows and POSIX npm test calls", () => {
  assert.equal(isCanonicalNpmTestInvocation("npm", ["test", "--", "--test-reporter=tap"]), true);
  assert.equal(isCanonicalNpmTestInvocation("C:\\Windows\\System32\\cmd.exe", ["/d", "/s", "/c", "npm.cmd test -- --test-reporter=tap"]), true);
  assert.equal(isCanonicalNpmTestInvocation(process.execPath, ["--test", "test/upload-security.test.js"]), false);
  assert.equal(isCanonicalNpmTestInvocation("npm", ["audit", "--package-lock-only"]), false);
});

test("dead-owner quota test preload is inert outside the test environment", () => {
  const quotaModulePath = path.join(ROOT, "services", "chunkUploadQuota.js");
  const preloadPath = path.join(ROOT, "test", "fixtures", "chunk-quota-dead-owner-preload.js");
  const script = `const quota = require(${JSON.stringify(quotaModulePath)}); const original = quota.createChunkUploadQuota; require(${JSON.stringify(preloadPath)}); if (quota.createChunkUploadQuota !== original) process.exitCode = 1;`;
  const result = spawnSync(process.execPath, ["-e", script], {
    env: { ...process.env, NODE_ENV: "production", ROOTARK_TEST_DEAD_QUOTA_OWNER_PIDS: String(process.pid) },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr || "production preload changed the quota factory");
});

test("release gate reports categorical failed-child telemetry and skips redundant full tests", () => {
  const vm = require("node:vm");
  const { createRequire } = require("node:module");
  const gatePath = path.join(ROOT, "scripts", "validate-release-gate.js");
  const gateRequire = createRequire(gatePath);
  const calls = [];
  const printed = [];
  const simulatedSpawnSync = (executable, args) => {
    calls.push({ executable, args });
    if (args.some((value) => String(value).endsWith("upload-security.test.js"))) {
      return {
        status: 1,
        stdout: "not ok 7 - a second startup rejects ambiguous quota owner\n  failureType: 'testCodeFailure'\n  error: Upload denied password=synthetic-sensitive-fixture Authorization: Basic c2Vuc2l0aXZl refresh_token=synthetic-refresh-key access_token=synthetic-access-key\n",
        stderr: "Synthetic diagnostic: bearer test-secret-value\n",
      };
    }
    return { status: 0, stdout: "", stderr: "" };
  };
  const simulatedProcess = { execPath: process.execPath, exitCode: 0 };
  vm.runInNewContext(fs.readFileSync(gatePath, "utf8"), {
    __dirname: path.dirname(gatePath),
    process: simulatedProcess,
    console: { log: (value) => printed.push(String(value)) },
    require: (name) => name === "node:child_process" ? { spawnSync: simulatedSpawnSync } : gateRequire(name),
  }, { filename: gatePath });
  const output = printed.join("\n");
  assert.match(output, /FAIL: Upload security boundary — exit 1/);
  assert.match(output, /CHILD_DIAG_V1 exit=1 signal=none spawn=none footer=missing progress=none reporter=none/,
    "only allowlisted child status metadata is visible in CI");
  assert.match(output, /raw output withheld/);
  assert.doesNotMatch(output, /a second startup rejects ambiguous quota owner|synthetic-sensitive-fixture|test-secret-value|c2Vuc2l0aXZl|synthetic-refresh-key|synthetic-access-key|bearer/i,
    "neither arbitrary failing test names nor fixture secrets may be logged");
  assert.equal(calls.some(({ args }) => /(?:^|\s)(?:npm(?:\.cmd)?\s+test|test(?:\s|$))/.test(args.join(" "))), false, "no expensive canonical npm test after an earlier hard failure on Windows or POSIX");
  assert.equal(simulatedProcess.exitCode, 1, "the gate still fails closed");
});

test("release gate emits bounded categorical TAP failure metadata from canonical npm test on Windows", () => {
  const vm = require("node:vm");
  const { createRequire } = require("node:module");
  const gatePath = path.join(ROOT, "scripts", "validate-release-gate.js");
  const gateRequire = createRequire(gatePath);
  const printed = [];
  const commands = [];
  const simulatedProcess = { execPath: process.execPath, exitCode: 0 };
  const secret = "synthetic-canonical-npm-secret";
  const simulatedSpawnSync = (executable, args) => {
    commands.push(args.map(String).join(" "));
    if (isCanonicalNpmTestInvocation(executable, args)) {
      return {
        status: 1,
        stdout: `TAP version 13\nnot ok 327 - a concurrent upload boundary failed token=${secret}\n  error: expected success password=${secret}\n# tests 1411\n# pass 1410\n# fail 1\n`,
        stderr: `npm error code 1\nnpm error stderr=${secret}`,
      };
    }
    return { status: 0, stdout: "", stderr: "" };
  };
  vm.runInNewContext(fs.readFileSync(gatePath, "utf8"), {
    __dirname: path.dirname(gatePath),
    process: simulatedProcess,
    console: { log: (line) => printed.push(String(line)) },
    require: (name) => name === "node:child_process" ? { spawnSync: simulatedSpawnSync } : gateRequire(name),
  }, { filename: gatePath });
  const output = printed.join("\n");
  assert.ok(commands.some((line) => /(?:^|\s)(?:npm(?:\.cmd)?\s+)?test -- --test-reporter=tap(?:\s|$)/.test(line)), "canonical npm still runs every test with a deterministic TAP reporter");
  assert.match(output, /FAIL diagnostics \(final-head canonical npm test\):/);
  assert.match(output, /CHILD_DIAG_V1 exit=1 signal=none spawn=none footer=missing progress=327:327 reporter=tap/);
  assert.match(output, /raw output withheld/);
  assert.doesNotMatch(output, /not ok 327|a concurrent upload boundary failed|# fail 1/,
    "arbitrary TAP names and raw counters are never copied into CI logs");
  assert.doesNotMatch(output, new RegExp(secret), "TAP and stderr secrets are not printed");
  assert.ok(output.length < 5000, "CI failure log stays bounded");
  assert.equal(simulatedProcess.exitCode, 1);
});

test("release gate preserves early TAP failure ordinals, not names, after long diagnostics", () => {
  const vm = require("node:vm");
  const { createRequire } = require("node:module");
  const gatePath = path.join(ROOT, "scripts", "validate-release-gate.js");
  const gateRequire = createRequire(gatePath);
  const printed = [];
  const secret = "synthetic-early-failure-secret";
  const simulatedProcess = { execPath: process.execPath, exitCode: 0 };
  const names = Array.from({ length: 7 }, (_, i) =>
    `not ok ${i + 1} - WebDAV failure ${i + 1} token=${secret}`);
  const trailing = Array.from({ length: 40 }, (_, i) => `  error: synthetic error detail ${i}`);
  vm.runInNewContext(fs.readFileSync(gatePath, "utf8"), {
    __dirname: path.dirname(gatePath),
    process: simulatedProcess,
    console: { log: (line) => printed.push(String(line)) },
    require: (name) => name === "node:child_process" ? { spawnSync: (executable, args) =>
      isCanonicalNpmTestInvocation(executable, args)
        ? { status: 1, stdout: `TAP version 13\n${names.join("\n")}\n${trailing.join("\n")}\n# fail 7\n`, stderr: "" }
        : { status: 0, stdout: "", stderr: "" } } : gateRequire(name),
  }, { filename: gatePath });
  const output = printed.join("\n");
  assert.match(output, /FAIL: final-head canonical npm test — exit 1/);
  assert.match(output, /CHILD_DIAG_V1 exit=1 signal=none spawn=none footer=missing progress=1:7 reporter=tap/,
    "bounded first/last TAP ordinals remain visible without test names");
  assert.match(output, /raw output withheld/);
  assert.doesNotMatch(output, /not ok|WebDAV failure|# fail 7|synthetic error detail/);
  assert.doesNotMatch(output, new RegExp(secret));
  assert.ok(output.length < 12000, "categorical metadata remains bounded");
  assert.equal(simulatedProcess.exitCode, 1, "the canonical release gate must still fail closed");
});

test("release gate prints metadata-only failure diagnostics for unknown npm output", () => {
  const vm = require("node:vm");
  const { createRequire } = require("node:module");
  const gatePath = path.join(ROOT, "scripts", "validate-release-gate.js");
  const gateRequire = createRequire(gatePath);
  const printed = [];
  const secret = "synthetic-unknown-sensitive-stdout";
  vm.runInNewContext(fs.readFileSync(gatePath, "utf8"), {
    __dirname: path.dirname(gatePath),
    process: { execPath: process.execPath, exitCode: 0 },
    console: { log: (line) => printed.push(String(line)) },
    require: (name) => name === "node:child_process" ? { spawnSync: (executable, args) => isCanonicalNpmTestInvocation(executable, args)
      ? { status: 1, stdout: `unknown-format ${secret}\n`, stderr: "", error: { code: "ENOBUFS" } }
      : { status: 0, stdout: "", stderr: "" } } : gateRequire(name),
  }, { filename: gatePath });
  const output = printed.join("\n");
  assert.match(output, /FAIL diagnostics \(final-head canonical npm test\):/);
  assert.match(output, /ENOBUFS/);
  assert.match(output, /stdoutBytes=/);
  assert.doesNotMatch(output, new RegExp(secret), "fallback cannot expose arbitrary child stdout");
});

test("2,000-chunk boundary keeps ordinary socket timeout strict and bounds final assembly separately", () => {
  assert.equal(chunkBoundaryRequestTimeout(0, 2000), TIMEOUT_MS);
  assert.equal(chunkBoundaryRequestTimeout(1998, 2000), TIMEOUT_MS);
  assert.equal(chunkBoundaryRequestTimeout(1999, 2000), 30_000);
  assert.equal(chunkBoundaryRequestTimeout(1999, 2001), TIMEOUT_MS, "test-only final assembly allowance is restricted to the supported 2,000 part boundary");
});

test("waits for audit logs to finish an observed rewrite before parsing", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-audit-write-race-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, "data"));
  const file = path.join(dir, "data", "audit-logs.json");
  fs.writeFileSync(file, JSON.stringify({ logs: [] }));

  const expected = [{ id: "first" }, { id: "second" }];
  let resolveTransientSyntaxError;
  const transientSyntaxError = new Promise((resolve) => { resolveTransientSyntaxError = resolve; });
  const waiting = waitForAuditLogs(
    dir,
    (logs) => logs.length === expected.length,
    250,
    () => resolveTransientSyntaxError()
  );
  fs.writeFileSync(file, "{\"logs\":[");
  const observation = await Promise.race([
    transientSyntaxError.then(() => "observed"),
    waiting.then(() => "completed", () => "timed out")
  ]);
  assert.equal(observation, "observed", "the helper read malformed JSON during the observed-rewrite retry window");
  fs.writeFileSync(file, JSON.stringify({ logs: expected }));
  assert.deepEqual(await waiting, expected);

  fs.writeFileSync(file, "{\"logs\":[");
  await assert.rejects(waitForAuditLogs(dir, () => true), SyntaxError, "stable malformed JSON fails without a retry window");
  fs.rmSync(file);
  await assert.rejects(waitForAuditLogs(dir, () => true), { code: "ENOENT" }, "non-JSON file errors fail immediately");
});


test("chunk-session sweep retries leftover parts after a tombstone unlink failure", { timeout: 45_000 }, async (t) => {
  const uploadId = "expired-part-unlink-retry";
  const markerDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-chunk-unlink-markers-"));
  const failurePath = path.join(markerDir, "failure");
  const retrySweepPath = path.join(markerDir, "retry");
  t.after(() => fs.rmSync(markerDir, { recursive: true, force: true }));
  const harness = await createHarness(t, {
    waitForReady: false,
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "60000" },
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }),
        "0.part": "expired plaintext",
      },
    }],
    preloadSource: `
      const fs = require("node:fs");
      const unlinkSync = fs.unlinkSync;
      const originalSetInterval = global.setInterval;
      let failedOnce = false;
      fs.unlinkSync = function (target, ...args) {
        if (!failedOnce && String(target).includes(${JSON.stringify(uploadId)}) && String(target).endsWith("0.part")) {
          failedOnce = true;
          fs.writeFileSync(${JSON.stringify(failurePath)}, "injected");
          throw Object.assign(new Error("injected one-time unlink failure"), { code: "EIO" });
        }
        const result = unlinkSync.call(this, target, ...args);
        if (String(target).includes(${JSON.stringify(uploadId)}) && String(target).endsWith("0.part")) {
          // Make the unlink-to-quota-release window observable across processes.
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
        }
        return result;
      };
      global.setInterval = (callback, delay, ...args) => {
        if (String(callback).includes("cleanupExpiredChunkSessions")) {
          return originalSetInterval((...callbackArgs) => {
            if (fs.existsSync(${JSON.stringify(retrySweepPath)})) callback(...callbackArgs);
          }, 25, ...args);
        }
        return originalSetInterval(callback, delay, ...args);
      };
    `,
  });

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const metadataPath = path.join(sessionDir, "metadata.json");
  const partPath = path.join(sessionDir, "0.part");
  assert.equal(await waitForFile(failurePath, 30_000), true, "startup sweep injected one unlink failure");
  const firstMarker = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  assert.deepEqual(Object.keys(firstMarker), ["__expiredAt"]);
  assert.equal(fs.existsSync(partPath), true, "part remains after the failed first sweep");

  const expiryEventsPromise = waitForAuditLogs(harness.dir, (logs) => logs.filter((entry) =>
    entry.eventType === "upload.chunk_session.expired" && entry.target?.id === uploadId
  ).length >= 2);
  fs.writeFileSync(retrySweepPath, "run", { flag: "wx", mode: 0o600 });
  // The successful expiry audit follows part unlink and quota release in the server.
  // Observe completion before reading quota state across processes.
  const expiryEvents = (await expiryEventsPromise).filter((entry) => entry.eventType === "upload.chunk_session.expired" && entry.target?.id === uploadId);
  assert.equal(fs.existsSync(partPath), false, "a later sweep removes the leftover part promptly");
  assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), firstMarker, "retry preserves the original tombstone and its seven-day TTL");
  const quotaDatabase = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(quotaDatabase.prepare("SELECT COUNT(*) AS count FROM quota_operations WHERE session_key = ?").get(`${FOLDER_ID}/${uploadId}`).count, 0, "all expiry charges release after tombstone cleanup confirms the parts are gone");
  } finally {
    quotaDatabase.close();
  }
  assert.deepEqual(expiryEvents.map((entry) => ({ result: entry.result, details: entry.details })), [
    { result: "failure", details: { source: "sweeper" } },
    { result: "success", details: { source: "sweeper" } },
  ], "audit records the failed initial deletion and successful retry without payload data");
});

test("expired chunk sessions are removed at seven days while recent sessions are preserved", { timeout: 45_000 }, async (t) => {
  const expiredId = "seven-day-expired";
  const markerExpiredId = "expired-tombstone-cleaned";
  const recentId = "seven-day-recent";
  const harness = await createHarness(t, {
    chunkSessions: [
      { uploadId: expiredId, files: { "metadata.json": legacyChunkMetadata(expiredId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }), "0.part": "expired plaintext" } },
      { uploadId: markerExpiredId, files: { "metadata.json": { __expiredAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }, "0.part": "expired leftover plaintext" } },
      { uploadId: recentId, files: { "metadata.json": legacyChunkMetadata(recentId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS + 60_000).toISOString() }), "0.part": "recent plaintext" } },
    ],
  });

  const expiredDir = path.join(harness.chunkRoot, FOLDER_ID, expiredId);
  const markerExpiredDir = path.join(harness.chunkRoot, FOLDER_ID, markerExpiredId);
  const recentDir = path.join(harness.chunkRoot, FOLDER_ID, recentId);
  const expiredMarker = JSON.parse(fs.readFileSync(path.join(expiredDir, "metadata.json"), "utf8"));
  assert.equal(typeof expiredMarker.__expiredAt, "string", "expired uploads retain only a bounded marker that blocks stale resumes");
  assert.equal(fs.existsSync(path.join(expiredDir, "0.part")), false, "all chunk plaintext is removed at seven days");
  assert.equal(fs.existsSync(markerExpiredDir), false, "old metadata-only tombstones are eventually removed");
  assert.equal(fs.readFileSync(path.join(recentDir, "0.part"), "utf8"), "recent plaintext");
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT session_key FROM quota_sessions ORDER BY session_key").all().map((row) => row.session_key), [`${FOLDER_ID}/${expiredId}`, `${FOLDER_ID}/${recentId}`]);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 1, "expiry releases its part operation while retaining the active recent part");
  } finally {
    database.close();
  }
});

test("seven-day expiry still cleans validated sessions when the configured quota ledger is unavailable", { timeout: 45_000 }, async (t) => {
  const expiredId = "expiry-ledger-unavailable";
  const recentId = "recent-ledger-unavailable";
  const harness = await createHarness(t, {
    chunkSessions: [
      { uploadId: expiredId, files: { "metadata.json": legacyChunkMetadata(expiredId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }), "0.part": "expired plaintext" } },
      { uploadId: recentId, files: { "metadata.json": legacyChunkMetadata(recentId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS + 60_000).toISOString() }), "0.part": "recent plaintext" } },
    ],
    preloadSource: ({ chunkRoot }) => `
      require("node:fs").writeFileSync(${JSON.stringify(path.join(chunkRoot, ".quota.sqlite"))}, "not a SQLite database");
    `,
  });

  const expiredDir = path.join(harness.chunkRoot, FOLDER_ID, expiredId);
  const recentDir = path.join(harness.chunkRoot, FOLDER_ID, recentId);
  assert.match(harness.stderr.join(""), /quota initialization unavailable/);
  assert.equal(fs.existsSync(path.join(expiredDir, "0.part")), false, `a validated seven-day-old part is removed under the shared lifecycle lock; ${harness.stderr.join("")}`);
  assert.equal(typeof JSON.parse(fs.readFileSync(path.join(expiredDir, "metadata.json"), "utf8")).__expiredAt, "string", "the expiry tombstone remains available to reject stale resumptions");
  assert.equal(fs.readFileSync(path.join(recentDir, "0.part"), "utf8"), "recent plaintext", "recent data is preserved while the quota ledger is unavailable");

  const session = await login(harness.port, "uploader", harness.password);
  const rejected = await uploadChunk(harness.port, session, {
    uploadId: "quota-ledger-unavailable-request",
    originalName: "quota-ledger-unavailable-request.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not be staged"),
  });
  assert.equal(rejected.status, 503, rejected.body);
  assert.equal(JSON.parse(rejected.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  const incomingDir = path.join(harness.chunkRoot, "incoming");
  assert.ok(!fs.existsSync(incomingDir) || fs.readdirSync(incomingDir).length === 0, "upload still fails closed before writing a new part");
});

test("a second startup preserves a live chunk promotion before its incoming rename", { timeout: 90_000 }, async (t) => {
  const uploadId = "live-promotion-startup";
  let promotionGate;
  const harness = await createHarness(t, {
    readyTimeout: 30_000,
    preloadSource: ({ dir }) => {
      promotionGate = {
        entered: path.join(dir, "promotion-entered"),
        release: path.join(dir, "promotion-release"),
      };
      return `
        const fs = require("node:fs");
        const path = require("node:path");
        const renameSync = fs.renameSync;
        fs.renameSync = function (source, destination, ...args) {
          const target = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part");
          if (String(source).includes(path.join(".chunks", "incoming")) && String(destination).endsWith(target)) {
            fs.writeFileSync(${JSON.stringify(promotionGate.entered)}, "entered");
            const signal = new Int32Array(new SharedArrayBuffer(4));
            const deadline = Date.now() + 30000;
            while (!fs.existsSync(${JSON.stringify(promotionGate.release)}) && Date.now() < deadline) Atomics.wait(signal, 0, 0, 10);
            if (!fs.existsSync(${JSON.stringify(promotionGate.release)})) throw new Error("promotion test gate timed out");
          }
          return renameSync.call(this, source, destination, ...args);
        };
      `;
    },
  });
  const originalSession = await login(harness.port, "uploader", harness.password);
  const originalBytes = Buffer.from("still owned by the active promotion");
  const originalCompletion = uploadChunk(harness.port, originalSession, {
    uploadId,
    originalName: `${uploadId}.txt`,
    chunkIndex: 0,
    totalChunks: 2,
    bytes: originalBytes,
    timeoutMs: 90_000,
  }).then((value) => ({ value }), (error) => ({ error }));
  assert.equal(await waitForFile(promotionGate.entered), true, "the original process pauses after the promoting ledger transition and before rename");

  const incomingPath = path.join(harness.chunkRoot, "incoming", fs.readdirSync(path.join(harness.chunkRoot, "incoming"))[0]);
  const sessionPartPath = path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part");
  assert.equal(fs.existsSync(sessionPartPath), false);
  assert.deepEqual(fs.readFileSync(incomingPath), originalBytes);
  const beforeStartup = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(beforeStartup.prepare("SELECT state, charge_bytes, relative_path, owner_pid FROM quota_operations").get(), {
      state: "promoting",
      charge_bytes: originalBytes.length,
      relative_path: path.join(FOLDER_ID, uploadId, "0.part"),
      owner_pid: harness.child.pid,
    });
  } finally {
    beforeStartup.close();
  }

  const secondPort = await getUnusedPort();
  const secondChild = spawn(process.execPath, [SERVER], {
    cwd: harness.dir,
    env: {
      ...process.env,
      NODE_ENV: "test",
      PORT: String(secondPort),
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
  const secondStderr = [];
  secondChild.stderr.on("data", (chunk) => secondStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(secondPort, 30_000)).status, 200, secondStderr.join(""));
    assert.doesNotMatch(secondStderr.join(""), /quota initialization unavailable/);
    const secondSession = await login(secondPort, "uploader", harness.password);
    const secondUpload = await uploadChunk(secondPort, secondSession, {
      uploadId: "second-process-quota-check",
      originalName: "second-process-quota-check.txt",
      chunkIndex: 0,
      totalChunks: 2,
      bytes: Buffer.from("quota remains ready"),
    });
    assert.equal(secondUpload.status, 200, secondUpload.body);
    assert.deepEqual(fs.readFileSync(incomingPath), originalBytes, "startup leaves the live operation's incoming file untouched");
    const duringStartup = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      assert.deepEqual(duringStartup.prepare("SELECT state, charge_bytes, relative_path, owner_pid FROM quota_operations WHERE relative_path = ?").get(path.join(FOLDER_ID, uploadId, "0.part")), {
        state: "promoting",
        charge_bytes: originalBytes.length,
        relative_path: path.join(FOLDER_ID, uploadId, "0.part"),
        owner_pid: harness.child.pid,
      });
      assert.equal(duringStartup.prepare("SELECT SUM(charge_bytes) AS bytes FROM quota_operations").get().bytes, originalBytes.length + Buffer.byteLength("quota remains ready"));
    } finally {
      duringStartup.close();
    }
  } finally {
    fs.writeFileSync(promotionGate.release, "release");
    if (secondChild.exitCode === null) {
      secondChild.kill();
      await waitForExit(secondChild);
    }
  }
  const originalResult = await originalCompletion;
  if (originalResult.error) throw originalResult.error;
  assert.equal(originalResult.value.status, 200, originalResult.value.body);
});

test("a second startup revalidates a live promotion renamed after incoming enumeration", { timeout: 90_000 }, async (t) => {
  const uploadId = "live-promotion-after-enumeration";
  let gates;
  const harness = await createHarness(t, {
    readyTimeout: 30_000,
    preloadSource: ({ dir }) => {
      gates = Object.fromEntries(["beforeRename", "allowRename", "renamed", "finishPromotion", "lstatEntered", "finishLstat"]
        .map((name) => [name, path.join(dir, name)]));
      return `
        const fs = require("node:fs");
        const path = require("node:path");
        const renameSync = fs.renameSync;
        fs.renameSync = function (source, destination, ...args) {
          const target = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part");
          if (String(source).includes(path.join(".chunks", "incoming")) && String(destination).endsWith(target)) {
            const signal = new Int32Array(new SharedArrayBuffer(4));
            fs.writeFileSync(${JSON.stringify(gates.beforeRename)}, "entered");
            const beforeDeadline = Date.now() + 30000;
            while (!fs.existsSync(${JSON.stringify(gates.allowRename)}) && Date.now() < beforeDeadline) Atomics.wait(signal, 0, 0, 10);
            if (!fs.existsSync(${JSON.stringify(gates.allowRename)})) throw new Error("promotion test gate timed out before rename");
            const result = renameSync.call(this, source, destination, ...args);
            fs.writeFileSync(${JSON.stringify(gates.renamed)}, "renamed");
            const afterDeadline = Date.now() + 30000;
            while (!fs.existsSync(${JSON.stringify(gates.finishPromotion)}) && Date.now() < afterDeadline) Atomics.wait(signal, 0, 0, 10);
            if (!fs.existsSync(${JSON.stringify(gates.finishPromotion)})) throw new Error("promotion test gate timed out after rename");
            return result;
          }
          return renameSync.call(this, source, destination, ...args);
        };
      `;
    },
  });
  const originalSession = await login(harness.port, "uploader", harness.password);
  const originalBytes = Buffer.from("the live rename remains charged");
  const originalCompletion = uploadChunk(harness.port, originalSession, {
    uploadId,
    originalName: `${uploadId}.txt`,
    chunkIndex: 0,
    totalChunks: 2,
    bytes: originalBytes,
    timeoutMs: 90_000,
  }).then((value) => ({ value }), (error) => ({ error }));
  assert.equal(await waitForFile(gates.beforeRename), true);

  const incomingDir = path.join(harness.chunkRoot, "incoming");
  const incomingPath = path.join(incomingDir, fs.readdirSync(incomingDir)[0]);
  const sessionPartPath = path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part");
  const lstatPreloadPath = path.join(harness.dir, "pause-incoming-lstat.js");
  fs.writeFileSync(lstatPreloadPath, `
    const fs = require("node:fs");
    const path = require("node:path");
    const lstatSync = fs.lstatSync;
    fs.lstatSync = function (target, ...args) {
      if (path.resolve(String(target)) === path.resolve(${JSON.stringify(incomingPath)})) {
        fs.writeFileSync(${JSON.stringify(gates.lstatEntered)}, "entered");
        const signal = new Int32Array(new SharedArrayBuffer(4));
        const deadline = Date.now() + 30000;
        while (!fs.existsSync(${JSON.stringify(gates.finishLstat)}) && Date.now() < deadline) Atomics.wait(signal, 0, 0, 10);
        if (!fs.existsSync(${JSON.stringify(gates.finishLstat)})) throw new Error("lstat test gate timed out");
      }
      return lstatSync.call(this, target, ...args);
    };
  `);
  const secondPort = await getUnusedPort();
  const secondChild = spawn(process.execPath, ["--require", lstatPreloadPath, SERVER], {
    cwd: harness.dir,
    env: {
      ...process.env,
      NODE_ENV: "test",
      PORT: String(secondPort),
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
  const secondStderr = [];
  const secondStdout = [];
  secondChild.stderr.on("data", (chunk) => secondStderr.push(chunk.toString()));
  secondChild.stdout.on("data", (chunk) => secondStdout.push(chunk.toString()));
  try {
    assert.equal(await waitForFile(gates.lstatEntered, 60_000), true, `the second process pauses after enumerating the incoming file; exit: ${secondChild.exitCode}; stdout: ${secondStdout.join("")}; stderr: ${secondStderr.join("")}`);
    fs.writeFileSync(gates.allowRename, "allow");
    assert.equal(await waitForFile(gates.renamed), true, "the live owner atomically moves the incoming file while startup is paused");
    assert.equal(fs.existsSync(incomingPath), false);
    assert.deepEqual(fs.readFileSync(sessionPartPath), originalBytes);
    const duringRename = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      assert.deepEqual(duringRename.prepare("SELECT state, charge_bytes, relative_path, owner_pid FROM quota_operations").get(), {
        state: "promoting",
        charge_bytes: originalBytes.length,
        relative_path: path.join(FOLDER_ID, uploadId, "0.part"),
        owner_pid: harness.child.pid,
      });
    } finally {
      duringRename.close();
    }
    fs.writeFileSync(gates.finishLstat, "resume");
    assert.equal((await waitForServer(secondPort, 30_000)).status, 200, secondStderr.join(""));
    assert.doesNotMatch(secondStderr.join(""), /quota initialization unavailable/);
    const secondSession = await login(secondPort, "uploader", harness.password);
    const secondUpload = await uploadChunk(secondPort, secondSession, {
      uploadId: "second-process-after-rename",
      originalName: "second-process-after-rename.txt",
      chunkIndex: 0,
      totalChunks: 2,
      bytes: Buffer.from("quota remains ready"),
    });
    assert.equal(secondUpload.status, 200, secondUpload.body);
  } finally {
    for (const gate of [gates.allowRename, gates.finishPromotion, gates.finishLstat]) fs.writeFileSync(gate, "release");
    if (secondChild.exitCode === null) {
      secondChild.kill();
      await waitForExit(secondChild);
    }
  }
  const originalResult = await originalCompletion;
  if (originalResult.error) throw originalResult.error;
  assert.equal(originalResult.value.status, 200, originalResult.value.body);
});

test("zero-byte multipart sessions are bounded per account and system", { timeout: 45_000 }, async (t) => {
  const harness = await createHarness(t, {
    secondUploaderHasFolderAccess: true,
    envOverrides: {
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "4",
      CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "6",
    },
  });
  const uploader = await login(harness.port, "uploader", harness.password);
  for (const uploadId of ["empty-part-one", "empty-part-two"]) {
    const response = await uploadChunk(harness.port, uploader, {
      uploadId,
      originalName: uploadId + ".txt",
      chunkIndex: 0,
      totalChunks: 2,
      bytes: Buffer.alloc(0),
    });
    assert.equal(response.status, 200, response.body);
    assert.equal(JSON.parse(response.body).complete, false);
  }
  const accountOverflow = await uploadChunk(harness.port, uploader, {
    uploadId: "empty-part-account-overflow",
    originalName: "empty-part-account-overflow.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.alloc(0),
  });
  assert.equal(accountOverflow.status, 507, accountOverflow.body);
  assert.equal(JSON.parse(accountOverflow.body).code, "CHUNK_QUOTA_EXCEEDED");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, "empty-part-account-overflow")), false);

  const otherUploader = await login(harness.port, "other-uploader", harness.password);
  const systemLastEntry = await uploadChunk(harness.port, otherUploader, {
    uploadId: "empty-part-system-last-entry",
    originalName: "empty-part-system-last-entry.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.alloc(0),
  });
  assert.equal(systemLastEntry.status, 200, systemLastEntry.body);
  const systemOverflow = await uploadChunk(harness.port, otherUploader, {
    uploadId: "empty-part-system-overflow",
    originalName: "empty-part-system-overflow.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.alloc(0),
  });
  assert.equal(systemOverflow.status, 507, systemOverflow.body);
  assert.equal(JSON.parse(systemOverflow.body).code, "CHUNK_QUOTA_EXCEEDED");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, "empty-part-system-overflow")), false);

  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 3);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_sessions").get().count, 3);
    assert.equal(database.prepare("SELECT SUM(charge_bytes) AS bytes FROM quota_operations").get().bytes, 0);
  } finally {
    database.close();
  }
});

test("expired chunk cleanup remains serialized and runs when quota configuration is unavailable", { timeout: 45_000 }, async (t) => {
  const expiredId = "expired-without-quota";
  const recentId = "recent-without-quota";
  const harness = await createHarness(t, {
    chunkSessions: [
      { uploadId: expiredId, files: { "metadata.json": legacyChunkMetadata(expiredId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }), "0.part": "expired disposable part" } },
      { uploadId: recentId, files: { "metadata.json": legacyChunkMetadata(recentId, { lastActivityAt: new Date().toISOString() }), "0.part": "recent disposable part" } },
    ],
    envOverrides: {
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "",
      CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "",
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "",
      CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "",
    },
  });
  const expiredDir = path.join(harness.chunkRoot, FOLDER_ID, expiredId);
  const recentDir = path.join(harness.chunkRoot, FOLDER_ID, recentId);
  assert.equal(fs.existsSync(path.join(expiredDir, "0.part")), false, harness.stderr.join(""));
  assert.equal(typeof JSON.parse(fs.readFileSync(path.join(expiredDir, "metadata.json"), "utf8")).__expiredAt, "string");
  assert.equal(fs.readFileSync(path.join(recentDir, "0.part"), "utf8"), "recent disposable part");

  const session = await login(harness.port, "uploader", harness.password);
  const blocked = await uploadChunk(harness.port, session, {
    uploadId: "quota-disabled-still-blocks-upload",
    originalName: "quota-disabled.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not stage"),
  });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
});

test("an expired upload cannot resume from its old chunks after restart cleanup", { timeout: 45_000 }, async (t) => {
  const uploadId = "expired-upload-cannot-resume";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 1).toISOString() }), "0.part": "expired plaintext" } }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("must start a new upload"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part")), false);
  assert.equal(typeof JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8")).__expiredAt, "string");
  assert.deepEqual(pending(harness.dir), {});
});

test("valid accepted chunk activity refreshes the seven-day session window", { timeout: 45_000 }, async (t) => {
  const uploadId = "activity-refreshes-window";
  const lastActivityAt = new Date(Date.now() - CHUNK_SESSION_TTL_MS + 60_000).toISOString();
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 3, encryptionLevel: "none", originalName: "activity.txt", fileName: "activity.txt", lastActivityAt }),
        "0.part": "first chunk",
      },
    }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "activity.txt",
    chunkIndex: 1,
    totalChunks: 3,
    bytes: Buffer.from("second chunk"),
  });
  assert.equal(response.status, 200, response.body);
  const metadata = JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8"));
  assert.ok(Date.parse(metadata.lastActivityAt) > Date.parse(lastActivityAt));
  assert.ok(Math.abs(Date.now() - Date.parse(metadata.lastActivityAt)) < 5_000);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part"), "utf8"), "second chunk");
});

test("expiry wins while a multipart body is paused before its session fields are parsed", { timeout: 45_000 }, async (t) => {
  const uploadId = "expiry-wins-before-fields";
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    chunkSessions: [{ uploadId, files: {
      "metadata.json": legacyChunkMetadata(uploadId, {
        totalChunks: 1,
        encryptionLevel: "none",
        lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS + 5_000).toISOString(),
      }),
      "0.part": "previously accepted part",
    } }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const payload = multipartParts([
    { field: "uploadId", bytes: uploadId },
    { field: "originalName", bytes: "expiry-race.txt" },
    { field: "chunkIndex", bytes: "0" },
    { field: "totalChunks", bytes: "1" },
    { field: "encryptionLevel", bytes: "none" },
    { field: "chunk", filename: "expiry-race.txt", bytes: Buffer.from("stale in-flight request") },
  ]);
  const responsePromise = new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port: harness.port,
      path: "/upload-chunk?folderId=" + FOLDER_ID,
      method: "POST",
      headers: {
        cookie: session.cookie,
        origin: "http://127.0.0.1:" + harness.port,
        "x-csrf-token": session.csrf,
        "content-type": payload.contentType,
        "content-length": payload.body.length,
      },
    }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.flushHeaders();
    t.after(() => req.destroy());
    (async () => {
      const metadataPath = path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json");
      const deadline = Date.now() + 10_000;
      while (Date.now() < deadline) {
        if (fs.existsSync(metadataPath)) {
          try {
            const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
            if (typeof metadata.__expiredAt === "string") break;
          } catch {}
        }
        await new Promise((resolveWait) => setTimeout(resolveWait, 20));
      }
      const tombstone = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
      assert.equal(typeof tombstone.__expiredAt, "string", "expiry marker is durable before the body resumes");
      req.end(payload.body);
    })().catch(reject);
  });

  const response = await responsePromise;
  assert.equal(response.status, 409, response.body);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const marker = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  assert.equal(typeof marker.__expiredAt, "string");
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
  const quotaDatabase = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(quotaDatabase.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    quotaDatabase.close();
  }
});

test("an active incoming chunk does not defer cleanup of unrelated expired sessions", { timeout: 45_000 }, async (t) => {
  const uploadId = "expired-with-other-incoming-upload";
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }), "0.part": "expired plaintext" } }],
  });

  const incomingFile = crypto.randomUUID();
  const quota = createChunkUploadQuota({
    rootDir: harness.chunkRoot,
    perAccountBytes: 64 * 1024 * 1024,
    systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000,
  });
  const incomingBytes = Buffer.from("active upload staging data");
  quota.reserve({ operationId: incomingFile, accountKey: "uploader", relativePath: `incoming/${incomingFile}`, reservedBytes: incomingBytes.length });
  fs.writeFileSync(path.join(harness.chunkRoot, "incoming", incomingFile), incomingBytes, { mode: 0o600 });
  quota.close();

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const cleanupDeadline = Date.now() + 5_000;
  while (fs.existsSync(path.join(sessionDir, "0.part")) && Date.now() < cleanupDeadline) await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false, "unrelated expired chunk data is still pruned");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", incomingFile), "utf8"), incomingBytes.toString(), "the sweeper leaves incoming upload staging files untouched");
});

test("the chunk-session sweeper shares the cross-process session lock when quota is unavailable", { timeout: 45_000 }, async (t) => {
  const uploadId = "sweeper-session-lock";
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const databasePath = ${JSON.stringify(path.join(chunkRoot, ".quota.sqlite"))};
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      fs.writeFileSync(databasePath, "not a SQLite database");
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  fs.mkdirSync(sessionDir, { recursive: true });
  fs.writeFileSync(path.join(sessionDir, "metadata.json"), JSON.stringify(legacyChunkMetadata(uploadId, {
    lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString(),
    encryptionLevel: "none",
  }), null, 2));
  fs.writeFileSync(path.join(sessionDir, "0.part"), "keep active part");
  const sessionIdentity = path.resolve(sessionDir);
  const lockIdentity = process.platform === "win32" ? sessionIdentity.toLowerCase() : sessionIdentity;
  const lock = createFileLifecycleLock({ directory: path.join(harness.dir, "data", ".rootark-cloud-file-locks"), timeoutMs: 10_000, pollMs: 5 });
  let releaseLock;
  let markLockHeld;
  const lockHeld = new Promise((resolve) => { markLockHeld = resolve; });
  assert.match(harness.stderr.join(""), /quota initialization unavailable/);
  const heldOperation = lock.runFolder(`chunk-upload:${lockIdentity}`, async () => {
    markLockHeld();
    await new Promise((resolve) => { releaseLock = resolve; });
  });
  await lockHeld;
  await new Promise((resolve) => setTimeout(resolve, 1250));
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), true, "the sweeper waits for the upload session lock");
  const metadataPath = path.join(sessionDir, "metadata.json");
  const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  metadata.lastActivityAt = new Date().toISOString();
  fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
  releaseLock();
  await heldOperation;
  await new Promise((resolve) => setTimeout(resolve, 1250));
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "keep active part");

  metadata.lastActivityAt = new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString();
  fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
  const cleanupDeadline = Date.now() + 5_000;
  while (fs.existsSync(sessionDir) && Date.now() < cleanupDeadline) await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false, `the periodic sweeper deletes expired chunk data; ${harness.stderr.join("")}`);
  assert.equal(typeof JSON.parse(fs.readFileSync(metadataPath, "utf8")).__expiredAt, "string");
});

test("a different uploader cannot overwrite or finish another user's chunk session", { timeout: 45_000 }, async (t) => {
  const uploadId = "session-owner-binding";
  const originalPart = "owner's first chunk";
  const harness = await createHarness(t, {
    secondUploaderHasFolderAccess: true,
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 2, encryptionLevel: "none", originalName: "owner-file.txt", fileName: "owner-file.txt", uploadedBy: "uploader" }), "0.part": originalPart } }],
  });
  const otherUploader = await login(harness.port, "other-uploader", harness.password);
  const response = await uploadChunk(harness.port, otherUploader, {
    uploadId,
    originalName: "owner-file.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("attacker's final chunk"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), originalPart);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part")), false);
  assert.deepEqual(pending(harness.dir), {});
});

test("case-folded account aliases cannot resume another exact uploader identity", { timeout: 45_000 }, async (t) => {
  const uploadId = "case-alias-session-owner";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { encryptionLevel: "none" }), "0.part": "original chunk" } }],
  });
  const usersPath = path.join(harness.dir, "data", "users.local.json");
  const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
  users.push({ username: "UPLOADER", password: bcrypt.hashSync(harness.password, 10), role: "user", permissions: { upload: true, listFiles: true }, sessionVersion: 0 });
  fs.writeFileSync(usersPath, JSON.stringify(users));
  const foldersPath = path.join(harness.dir, "data", "folders.json");
  const folders = JSON.parse(fs.readFileSync(foldersPath, "utf8"));
  folders.find((folder) => folder.id === FOLDER_ID).allowedUsers.push("UPLOADER");
  fs.writeFileSync(foldersPath, JSON.stringify(folders));
  const alias = await login(harness.port, "UPLOADER", harness.password);
  const response = await uploadChunk(harness.port, alias, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("alias chunk"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "original chunk");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part")), false);
});

test("a recreated uploader account with a newer session generation cannot resume old chunks", { timeout: 45_000 }, async (t) => {
  const uploadId = "recreated-uploader-generation";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { encryptionLevel: "none" }), "0.part": "old account chunk" } }],
  });
  const usersPath = path.join(harness.dir, "data", "users.local.json");
  const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
  users[0].sessionVersion = 1;
  fs.writeFileSync(usersPath, JSON.stringify(users));
  const recreatedAccount = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, recreatedAccount, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("new account chunk"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "old account chunk");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part")), false);
});

test("unbound pre-migration chunk sessions fail closed and preserve their parts", { timeout: 45_000 }, async (t) => {
  const uploadId = "legacy-unbound-session";
  const legacyMetadata = legacyChunkMetadata(uploadId, { encryptionLevel: "none" });
  delete legacyMetadata.uploaderSessionVersion;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyMetadata, "0.part": "unbound legacy chunk" } }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("must not bind legacy data"),
  });
  assert.equal(response.status, 409, response.body);
  const metadata = JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8"));
  assert.equal(metadata.__resumeBlocked, true);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "unbound legacy chunk");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part")), false);
});

test("recent unbound legacy sessions retain only validated expiry data and remain non-resumable", { timeout: 45_000 }, async (t) => {
  const uploadId = "recent-unbound-legacy-session";
  const legacyMetadata = legacyChunkMetadata(uploadId, { encryptionLevel: "none", lastActivityAt: new Date().toISOString() });
  delete legacyMetadata.uploaderSessionVersion;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyMetadata, "0.part": "retain recent legacy chunk" } }],
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const metadata = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  assert.deepEqual(Object.keys(metadata).sort(), ["__resumeBlocked", "folderId", "lastActivityAt", "totalChunks", "uploadId"]);
  assert.equal(metadata.__resumeBlocked, true);
  assert.equal(metadata.uploadId, uploadId);
  assert.equal(metadata.folderId, FOLDER_ID);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "retain recent legacy chunk");

  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("never attach to old data"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "retain recent legacy chunk");
  assert.equal(fs.existsSync(path.join(sessionDir, "1.part")), false);
});

test("startup gives an unbound legacy session without activity a fresh blocked retention window", { timeout: 45_000 }, async (t) => {
  const uploadId = "startup-unbound-legacy-no-activity";
  const legacyMetadata = legacyChunkMetadata(uploadId, { encryptionLevel: "none" });
  delete legacyMetadata.uploaderSessionVersion;
  delete legacyMetadata.lastActivityAt;
  const migrationStartedAt = Date.now();
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyMetadata, "0.part": "retain legacy chunk" } }],
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const metadata = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  assert.deepEqual(Object.keys(metadata).sort(), ["__resumeBlocked", "folderId", "lastActivityAt", "totalChunks", "uploadId"]);
  assert.equal(metadata.__resumeBlocked, true);
  assert.ok(Date.parse(metadata.lastActivityAt) >= migrationStartedAt);
  assert.ok(Date.now() - Date.parse(metadata.lastActivityAt) < 5_000);
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("cannot resume old data"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "retain legacy chunk");
});

test("request blocks and timestamps an unbound legacy session created without activity metadata", { timeout: 45_000 }, async (t) => {
  const uploadId = "request-unbound-legacy-no-activity";
  const harness = await createHarness(t);
  const legacyMetadata = legacyChunkMetadata(uploadId, { encryptionLevel: "none" });
  delete legacyMetadata.uploaderSessionVersion;
  delete legacyMetadata.lastActivityAt;
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  fs.mkdirSync(sessionDir, { recursive: true });
  fs.writeFileSync(path.join(sessionDir, "metadata.json"), JSON.stringify(legacyMetadata));
  fs.writeFileSync(path.join(sessionDir, "0.part"), "retain runtime legacy chunk");
  const conversionStartedAt = Date.now();
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("cannot bind runtime legacy data"),
  });
  assert.equal(response.status, 409, response.body);
  const metadata = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  assert.deepEqual(Object.keys(metadata).sort(), ["__resumeBlocked", "folderId", "lastActivityAt", "totalChunks", "uploadId"]);
  assert.equal(metadata.__resumeBlocked, true);
  assert.ok(Date.parse(metadata.lastActivityAt) >= conversionStartedAt);
  assert.ok(Date.now() - Date.parse(metadata.lastActivityAt) < 5_000);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "retain runtime legacy chunk");
  assert.equal(fs.existsSync(path.join(sessionDir, "1.part")), false);
});

test("stale unbound legacy sessions expire safely while remaining non-resumable", { timeout: 45_000 }, async (t) => {
  const uploadId = "stale-unbound-legacy-session";
  const legacyMetadata = legacyChunkMetadata(uploadId, {
    encryptionLevel: "none",
    lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString(),
  });
  delete legacyMetadata.uploaderSessionVersion;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyMetadata, "0.part": "expire stale legacy chunk" } }],
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const marker = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  assert.deepEqual(Object.keys(marker), ["__expiredAt"]);
  assert.equal(typeof marker.__expiredAt, "string");
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false);
  const event = auditLogs(harness.dir).find((entry) => entry.eventType === "upload.chunk_session.expired" && entry.target?.id === uploadId);
  assert.ok(event);
  assert.deepEqual(event.details, { source: "sweeper" });

  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("cannot resume expired data"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false);
});

test("malformed blocked legacy sessions preserve their data instead of being swept", { timeout: 45_000 }, async (t) => {
  const uploadId = "malformed-blocked-legacy-session";
  const malformedBlockedMetadata = {
    __resumeBlocked: true,
    uploadId,
    folderId: FOLDER_ID,
    totalChunks: 2,
    lastActivityAt: "not-a-timestamp",
  };
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": malformedBlockedMetadata, "0.part": "preserve malformed blocked data" } }],
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8")), malformedBlockedMetadata);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "preserve malformed blocked data");
  assert.equal(auditLogs(harness.dir).some((entry) => entry.eventType === "upload.chunk_session.expired" && entry.target?.id === uploadId), false);
});

test("invalid chunk activity time preserves session data and disables only chunk uploads", { timeout: 30_000 }, async (t) => {
  const uploadId = "invalid-chunk-activity-time";
  const bytes = Buffer.from("preserve unattributable activity session");
  const metadata = legacyChunkMetadata(uploadId, { lastActivityAt: "not-a-timestamp" });
  const harness = await createHarness(t, {
    waitForReady: false,
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": bytes } }],
  });
  assert.equal((await waitForServer(harness.port)).status, 200, harness.stderr.join(""));
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const blockedMetadata = { __resumeBlocked: true };
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8")), blockedMetadata);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), bytes);

  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "invalid-chunk-activity-time.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("must not be staged"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), bytes);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8")), blockedMetadata);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("periodic expiry audits successful deletion with safe session identifiers", { timeout: 45_000 }, async (t) => {
  const uploadId = "audited-expired-session";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 1).toISOString() }), "0.part": "sensitive uploaded bytes" } }],
  });
  const events = auditLogs(harness.dir).filter((entry) => entry.eventType === "upload.chunk_session.expired");
  assert.equal(events.length, 1);
  assert.deepEqual(events[0].actor, { username: "system", role: "system", ip: null, userAgent: null });
  assert.deepEqual(events[0].target, { type: "chunk_session", id: uploadId, folderId: FOLDER_ID });
  assert.equal(events[0].action, "expired");
  assert.equal(events[0].result, "success");
  assert.deepEqual(events[0].details, { source: "sweeper" });
  assert.equal(JSON.stringify(events[0]).includes("sensitive uploaded bytes"), false);
});

test("request-triggered expiry audits successful deletion", { timeout: 45_000 }, async (t) => {
  const uploadId = "request-audited-expired-session";
  const harness = await createHarness(t);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  fs.mkdirSync(sessionDir, { recursive: true });
  fs.writeFileSync(path.join(sessionDir, "metadata.json"), JSON.stringify(legacyChunkMetadata(uploadId)));
  fs.writeFileSync(path.join(sessionDir, "0.part"), "request-triggered sensitive bytes");
  const metadataPath = path.join(sessionDir, "metadata.json");
  const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  metadata.lastActivityAt = new Date(Date.now() - CHUNK_SESSION_TTL_MS - 1).toISOString();
  fs.writeFileSync(metadataPath, JSON.stringify(metadata));
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("new chunk"),
  });
  assert.equal(response.status, 409, response.body);
  const event = auditLogs(harness.dir).find((entry) => entry.eventType === "upload.chunk_session.expired" && entry.target?.id === uploadId);
  assert.ok(event);
  assert.equal(event.actor.username, "system");
  assert.deepEqual(event.target, { type: "chunk_session", id: uploadId, folderId: FOLDER_ID });
  assert.deepEqual(event.details, { source: "request" });
  assert.equal(JSON.stringify(event).includes("request-triggered sensitive bytes"), false);
});

test("non-expired sessions are inspected without acquiring durable filesystem locks", { timeout: 45_000 }, async (t) => {
  const uploadId = "recent-session-no-lock";
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date().toISOString() }), "0.part": "recent chunk" } }],
  });
  await new Promise((resolve) => setTimeout(resolve, 1100));
  assert.equal(fs.existsSync(path.join(harness.dir, "data", ".rootark-cloud-file-locks")), false);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "recent chunk");
});

test("overlapping expiry sweep ticks do not start competing session-lock work", { timeout: 45_000 }, async (t) => {
  const uploadId = "overlapping-sweep-session";
  const lockAttemptsPath = path.join(os.tmpdir(), `rootark-chunk-sweep-lock-attempts-${crypto.randomUUID()}.txt`);
  t.after(() => fs.rmSync(lockAttemptsPath, { force: true }));
  const lockModulePath = path.join(ROOT, "services", "fileLifecycleLock.js");
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }), "0.part": "expired chunk" } }],
    preloadSource: `
      const fs = require("node:fs");
      const lifecycle = require(${JSON.stringify(lockModulePath)});
      const create = lifecycle.createFileLifecycleLock;
      lifecycle.createFileLifecycleLock = (options) => {
        const lock = create(options);
        const runFolder = lock.runFolder;
        lock.runFolder = async (...args) => {
          fs.appendFileSync(${JSON.stringify(lockAttemptsPath)}, "attempt\\n");
          await new Promise((resolve) => setTimeout(resolve, 2000));
          return runFolder(...args);
        };
        return lock;
      };
    `,
  });
  assert.equal(await waitForFile(lockAttemptsPath), true);
  await new Promise((resolve) => setTimeout(resolve, 1100));
  assert.equal(fs.readFileSync(lockAttemptsPath, "utf8").trim().split(/\r?\n/).length, 1);
});

test("chunk-session expiry sweep yields to requests and eventually reaches later sessions", { timeout: 60_000 }, async (t) => {
  const sweepCount = 128;
  const sweepDelayMs = 50;
  // The test deliberately queues sequential filesystem delays. Startup and
  // filesystem scheduling are not guaranteed to finish within a fixed 10s on
  // Windows under parallel tests. Bound progress by the injected workload,
  // but never relax the normal-request responsiveness assertion below.
  const sweepProgressBudgetMs = 10_000 + 2 * sweepCount * sweepDelayMs;
  const lastUploadId = `sweep-yield-${sweepCount - 1}`;
  const markerDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-chunk-sweep-markers-"));
  const delayEnabledPath = path.join(markerDir, "delay-enabled");
  const sweepStartedPath = `${delayEnabledPath}.started`;
  t.after(() => fs.rmSync(markerDir, { recursive: true, force: true }));
  fs.writeFileSync(delayEnabledPath, "enabled", { flag: "wx", mode: 0o600 });
  const chunkSessions = Array.from({ length: sweepCount }, (_, index) => {
    const uploadId = `sweep-yield-${index}`;
    const isLast = index === sweepCount - 1;
    return {
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, {
          lastActivityAt: new Date().toISOString(),
        }),
        "0.part": isLast ? "late expired chunk" : "recent chunk",
      },
    };
  });
  const fixtureBase = process.platform === "win32" ? process.env.USERPROFILE : os.tmpdir();
  const harnessPrefix = path.join(fixtureBase, "rootark-upload-safety-");
  const sessionPathMarker = `${path.sep}temp${path.sep}.chunks${path.sep}${FOLDER_ID}${path.sep}sweep-yield-`;
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    waitForReady: false,
    chunkSessions,
    preloadSource: `
      const fs = require("node:fs");
      const readdir = fs.promises.readdir.bind(fs.promises);
      let sessionReads = 0;
      let delayedSessionReads = 0;
      fs.promises.readdir = async (target, ...args) => {
        const entries = await readdir(target, ...args);
        if (String(target).startsWith(${JSON.stringify(harnessPrefix)}) && String(target).includes(${JSON.stringify(sessionPathMarker)})) {
          sessionReads += 1;
          if (sessionReads > ${sweepCount}) {
            await new Promise((resolve) => setTimeout(resolve, ${sweepDelayMs}));
            delayedSessionReads += 1;
            if (delayedSessionReads === 8) fs.writeFileSync(${JSON.stringify(sweepStartedPath)}, "8 delayed session reads complete");
          }
        }
        return entries;
      };
    `,
  });

  assert.equal(await waitForFile(sweepStartedPath, sweepProgressBudgetMs), true, "the periodic sweep completed eight delayed session reads");
  const lastMetadataPath = path.join(harness.chunkRoot, FOLDER_ID, lastUploadId, "metadata.json");
  const lastMetadata = JSON.parse(fs.readFileSync(lastMetadataPath, "utf8"));
  lastMetadata.lastActivityAt = new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString();
  fs.writeFileSync(lastMetadataPath, JSON.stringify(lastMetadata));
  const finalPartPath = path.join(harness.chunkRoot, FOLDER_ID, lastUploadId, "0.part");
  assert.equal(fs.existsSync(finalPartPath), true, "the final session remains intact until the periodic sweep runs");
  const requestStartedAt = Date.now();
  const response = await request(harness.port, "/login.html");
  const requestDuration = Date.now() - requestStartedAt;
  assert.equal(response.status, 200);
  const requestLatencyBudgetMs = (sweepCount - 8) * 50 / 2;
  assert.ok(requestDuration < requestLatencyBudgetMs, `normal request took ${requestDuration}ms while sequential metadata delays were still queued`);

  const cleanupDeadline = Date.now() + sweepProgressBudgetMs;
  while (fs.existsSync(finalPartPath) && Date.now() < cleanupDeadline) await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(fs.existsSync(finalPartPath), false, "the sweep eventually processes the last expired session");
});

test("the expiry sweep does not keep a live session metadata handle open across chunk writes", { timeout: process.platform === "win32" ? 60_000 : 30_000 }, async (t) => {
  const uploadId = "live-sweep-metadata-handle";
  let metadataHandleMarker;
  const harness = await createHarness(t, {
    // Cold-start Windows ACL preflight may exceed the generic 10s readiness
    // window under parallel hosted suites; upload assertions stay unchanged.
    readyTimeout: process.platform === "win32" ? 30_000 : TIMEOUT_MS,
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    preloadSource: ({ dir }) => {
      const metadataPath = path.join(dir, "temp", ".chunks", FOLDER_ID, uploadId, "metadata.json");
      metadataHandleMarker = path.join(dir, "sweep-held-metadata.txt");
      return `
        const fs = require("node:fs");
        const open = fs.promises.open.bind(fs.promises);
        const metadataPath = ${JSON.stringify(metadataPath)};
        const markerPath = ${JSON.stringify(metadataHandleMarker)};
        let metadataHandleOpen = false;
        fs.promises.open = async (target, ...args) => {
          const handle = await open(target, ...args);
          if (String(target) !== metadataPath) return handle;
          metadataHandleOpen = true;
          fs.writeFileSync(markerPath, "held");
          await new Promise((resolve) => setTimeout(resolve, 3000));
          metadataHandleOpen = false;
          return handle;
        };
        const rename = fs.renameSync;
        fs.renameSync = function (source, destination, ...args) {
          if (String(destination) === metadataPath && metadataHandleOpen) {
            throw Object.assign(new Error("metadata is temporarily held by expiry sweep"), { code: "EPERM" });
          }
          return rename.call(this, source, destination, ...args);
        };
      `;
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const first = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "live-sweep.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("first accepted chunk"),
  });
  assert.equal(first.status, 200, first.body);
  await new Promise((resolve) => setTimeout(resolve, 1400));
  const second = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "live-sweep.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("second accepted chunk"),
  });
  assert.equal(second.status, 200, second.body);
  assert.equal(fs.existsSync(metadataHandleMarker), false, "the expiry sweep should not open a live session metadata file asynchronously");
});

test("chunk activity metadata retries transient EPERM only on Windows", { timeout: 45_000 }, async (t) => {
  const uploadId = "activity-rename-retries-eperm";
  const previousActivity = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  let attemptsPath;
  const metadata = legacyChunkMetadata(uploadId, { lastActivityAt: previousActivity, totalChunks: 3 });
  delete metadata.password;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": "existing accepted chunk", "1.part": "previously accepted second chunk" } }],
    preloadSource: ({ dir }) => {
      attemptsPath = path.join(dir, "metadata-rename-attempts.txt");
      return `
      const fs = require("node:fs");
      const renameSync = fs.renameSync;
      let metadataRenameAttempts = 0;
      fs.renameSync = (source, destination) => {
        if (String(source).includes(".metadata-scrub-") && String(destination).endsWith("metadata.json")) {
          metadataRenameAttempts += 1;
          fs.writeFileSync(${JSON.stringify(attemptsPath)}, String(metadataRenameAttempts));
          if (metadataRenameAttempts <= 3) throw Object.assign(new Error("transient metadata rename failure"), { code: "EPERM" });
        }
        return renameSync.call(fs, source, destination);
      };
      `;
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 3,
    bytes: Buffer.from("second chunk"),
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(response.status, process.platform === "win32" ? 200 : 500, response.body);
  assert.equal(fs.readFileSync(attemptsPath, "utf8"), process.platform === "win32" ? "4" : "1", "only Windows retries transient EPERM");
  const metadataAfter = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  if (process.platform === "win32") assert.ok(Date.parse(metadataAfter.lastActivityAt) > Date.parse(previousActivity));
  else assert.equal(metadataAfter.lastActivityAt, previousActivity, "non-Windows EPERM preserves prior metadata");
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "existing accepted chunk");
  assert.equal(fs.readFileSync(path.join(sessionDir, "1.part"), "utf8"), process.platform === "win32" ? "second chunk" : "previously accepted second chunk", "metadata failure must not commit a replacement chunk");
  assert.deepEqual(fs.readdirSync(sessionDir).filter((name) => name.startsWith(".metadata-scrub-")), []);
});

test("persistent EPERM prevents chunk commit and preserves prior activity metadata", { timeout: 45_000 }, async (t) => {
  const uploadId = "activity-rename-persistent-eperm";
  const previousActivity = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  let attemptsPath;
  const metadata = legacyChunkMetadata(uploadId, { lastActivityAt: previousActivity, totalChunks: 3 });
  delete metadata.password;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": "existing accepted chunk", "1.part": "previously accepted second chunk" } }],
    preloadSource: ({ dir }) => {
      attemptsPath = path.join(dir, "metadata-rename-attempts.txt");
      return `
      const fs = require("node:fs");
      const renameSync = fs.renameSync;
      let metadataRenameAttempts = 0;
      fs.renameSync = (source, destination) => {
        if (String(source).includes(".metadata-scrub-") && String(destination).endsWith("metadata.json")) {
          metadataRenameAttempts += 1;
          fs.writeFileSync(${JSON.stringify(attemptsPath)}, String(metadataRenameAttempts));
          throw Object.assign(new Error("persistent metadata rename failure"), { code: "EPERM" });
        }
        return renameSync.call(fs, source, destination);
      };
      `;
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 3,
    bytes: Buffer.from("second chunk"),
  });
  assert.equal(response.status, 500, response.body);
  assert.equal(fs.readFileSync(attemptsPath, "utf8"), process.platform === "win32" ? "5" : "1", "persistent EPERM uses the bounded Windows retry schedule and fails immediately elsewhere");
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8")), metadata);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "existing accepted chunk");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part"), "utf8"), "previously accepted second chunk", "persistent metadata failure preserves the accepted replacement target");
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId)).filter((name) => name.startsWith(".metadata-scrub-")), []);
});

test("persistent activity metadata failure releases a first chunk reservation", { timeout: 45_000 }, async (t) => {
  const uploadId = "activity-rename-first-part-persistent-eperm";
  let attemptsPath;
  const harness = await createHarness(t, {
    preloadSource: ({ dir }) => {
      attemptsPath = path.join(dir, "metadata-rename-attempts.txt");
      return `
        const fs = require("node:fs");
        const renameSync = fs.renameSync;
        let metadataRenameAttempts = 0;
        fs.renameSync = (source, destination) => {
          if (String(source).includes(".metadata-scrub-") && String(destination).endsWith("metadata.json")) {
            metadataRenameAttempts += 1;
            fs.writeFileSync(${JSON.stringify(attemptsPath)}, String(metadataRenameAttempts));
            throw Object.assign(new Error("persistent metadata rename failure"), { code: "EPERM" });
          }
          return renameSync.call(fs, source, destination);
        };
      `;
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "first-chunk.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("first accepted chunk"),
  });
  assert.equal(response.status, 500, response.body);
  assert.equal(fs.readFileSync(attemptsPath, "utf8"), process.platform === "win32" ? "5" : "1");
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), [], "failed metadata refresh removes the uncommitted incoming file");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part")), false);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0, "failed first part leaves no orphaned quota charge");
  } finally {
    database.close();
  }
});

test("non-EPERM while refreshing chunk activity fails immediately and preserves prior metadata", { timeout: 45_000 }, async (t) => {
  const uploadId = "activity-rename-non-eperm";
  const previousActivity = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  let attemptsPath;
  const metadata = legacyChunkMetadata(uploadId, { lastActivityAt: previousActivity, totalChunks: 3 });
  delete metadata.password;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": "existing accepted chunk" } }],
    preloadSource: ({ dir }) => {
      attemptsPath = path.join(dir, "metadata-rename-attempts.txt");
      return `
      const fs = require("node:fs");
      const renameSync = fs.renameSync;
      let metadataRenameAttempts = 0;
      fs.renameSync = (source, destination) => {
        if (String(source).includes(".metadata-scrub-") && String(destination).endsWith("metadata.json")) {
          metadataRenameAttempts += 1;
          fs.writeFileSync(${JSON.stringify(attemptsPath)}, String(metadataRenameAttempts));
          throw Object.assign(new Error("metadata rename I/O failure"), { code: "EIO" });
        }
        return renameSync.call(fs, source, destination);
      };
      `;
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 3,
    bytes: Buffer.from("second chunk"),
  });
  assert.equal(response.status, 500, response.body);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.readFileSync(attemptsPath, "utf8"), "1", "non-EPERM metadata rename failures are not retried");
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8")), metadata);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "existing accepted chunk");
  assert.equal(fs.existsSync(path.join(sessionDir, "1.part")), false, "metadata failure leaves a previously absent part uncommitted");
  assert.deepEqual(fs.readdirSync(sessionDir).filter((name) => name.startsWith(".metadata-scrub-")), []);
});

test("failed chunk rename does not refresh accepted activity", { timeout: 45_000 }, async (t) => {
  const uploadId = "failed-chunk-rename-preserves-activity";
  const previousActivity = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: previousActivity, totalChunks: 3, originalName: "encrypted.txt", encryptionLevel: "none" }), "0.part": "already accepted chunk", "1.part": "previously accepted replacement target" } }],
    preloadSource: `
      const fs = require("node:fs");
      const renameSync = fs.renameSync;
      fs.renameSync = (source, destination) => {
        if (String(destination).endsWith(".part")) throw Object.assign(new Error("fixture rename failure"), { code: "EIO" });
        return renameSync.call(fs, source, destination);
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 3,
    bytes: Buffer.from("rename must fail"),
  });
  assert.equal(response.status, 500, response.body);
  const metadata = JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8"));
  assert.equal(metadata.lastActivityAt, previousActivity);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "already accepted chunk");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part"), "utf8"), "previously accepted replacement target");
});

test("chunk metadata failure leaves a previously absent part uncommitted", { timeout: 45_000 }, async (t) => {
  const uploadId = "metadata-failure-no-prior-part";
  const metadata = legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(), totalChunks: 3, originalName: "encrypted.txt", encryptionLevel: "none" });
  delete metadata.password;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": "already accepted chunk" } }],
    preloadSource: `
      const fs = require("node:fs");
      const renameSync = fs.renameSync;
      fs.renameSync = (source, destination) => {
        if (String(source).includes(".metadata-scrub-") && String(destination).endsWith("metadata.json")) throw Object.assign(new Error("metadata rename failure"), { code: "EIO" });
        return renameSync.call(fs, source, destination);
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 3,
    bytes: Buffer.from("must not commit"),
  });
  assert.equal(response.status, 500, response.body);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8")), metadata);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "already accepted chunk");
  assert.equal(fs.existsSync(path.join(sessionDir, "1.part")), false);
  assert.deepEqual(fs.readdirSync(sessionDir).filter((name) => name.startsWith(".metadata-scrub-")), []);
});

