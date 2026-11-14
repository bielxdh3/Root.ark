"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

if (process.env.ROOTARK_TEST_UPLOAD_OPTOUT_CHILD === "1") {
  // Fixed, data-free stage markers survive a spawnSync timeout. They let the
  // parent distinguish slow test setup, backup creation, and a child that
  // finished the ZIP assertions but did not exit (without printing fixtures).
  const stage = (name) => fs.writeSync(2, `[backup-optout-stage:${name}]\n`);
  stage("child-started");
  if (process.env.ROOTARK_TEST_UPLOAD_OPTOUT_ADVERSARIAL === "bad-json") {
    fs.writeSync(1, "SYNTHETIC_STDOUT_SECRET_CANARY\nE:\\synthetic-private\\keys\\credential.txt\n");
    process.exit(0);
  }
  if (process.env.ROOTARK_TEST_UPLOAD_OPTOUT_ADVERSARIAL === "1") {
    fs.writeSync(2, "SYNTHETIC_SECRET_CANARY_DO_NOT_DISCLOSE\nE:\\synthetic-private\\keys\\credential.txt\n");
    fs.writeSync(2, "[backup-optout-stage:untrusted]\n");
    for (let index = 0; index < 64; index += 1) stage("child-started");
    fs.writeSync(1, "SYNTHETIC_STDOUT_SECRET_CANARY\n");
    process.exit(73);
  }
  const dataDir = path.join(process.cwd(), "data");
  const uploadsDir = path.join(process.cwd(), "uploads");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(uploadsDir, { recursive: true });
  fs.writeFileSync(path.join(dataDir, "settings.json"), "{}");
  fs.writeFileSync(path.join(uploadsDir, "local-only.txt"), "local bytes");
  stage("fixture-created");

  const backupService = require("../services/backupService");
  const unzipper = require("unzipper");
  stage("modules-loaded");
  let inventoryCalls = 0;
  let downloadCalls = 0;
  backupService.setCloudStorage({
    enabled: () => true,
    inventory: async () => {
      inventoryCalls += 1;
      return [{
        provider: "s3", providerIdentity: "disposable-cloud-only",
        area: "uploads", folderId: "root", name: "cloud-only.txt",
      }];
    },
    download: async (_folderId, _name, target) => {
      downloadCalls += 1;
      fs.writeFileSync(target, "remote bytes");
      return true;
    },
  });

  (async () => {
    stage("backup-started");
    const saved = await backupService.createBackup({ createdBy: "disposable-test" });
    stage("backup-created");
    const zip = await unzipper.Open.file(path.join(dataDir, "backups", saved.filename));
    const manifest = JSON.parse((await zip.files.find((entry) => entry.path === "backup-manifest.json").buffer()).toString("utf8"));
    stage("manifest-read");
    console.log(JSON.stringify({
      status: saved.status,
      cloudComplete: manifest.cloud_complete,
      metadataCloudComplete: saved.metadata.cloudComplete,
      entries: zip.files.filter((entry) => entry.type !== "Directory").map((entry) => entry.path),
      listed: manifest.included_files.map((entry) => entry.path),
      inventoryCalls, downloadCalls,
    }));
    stage("child-completed");
  })().catch(() => { stage("backup-failed"); process.exitCode = 1; });
} else {
  // Child stderr/stdout can contain private paths, stack traces or provider
  // messages. Treat them as untrusted: never copy either into TAP diagnostics.
  const knownStages = new Set([
    "child-started", "fixture-created", "modules-loaded", "backup-started",
    "backup-created", "manifest-read", "child-completed", "backup-failed",
  ]);

  function safeChildDiagnostics(result) {
    const seen = new Set();
    const stages = [];
    // Bound both the scanned input and the emitted stage list. Accept only
    // exact whole-line markers with names from the fixed test-owned enum.
    const lines = typeof result.stderr === "string"
      ? result.stderr.slice(0, 8192).split(/\r?\n/, 128)
      : [];
    for (const line of lines) {
      const match = /^\[backup-optout-stage:([a-z-]{1,32})\]$/.exec(line);
      if (match && knownStages.has(match[1]) && !seen.has(match[1])) {
        seen.add(match[1]);
        stages.push(match[1]);
      }
    }
    const exit = Number.isSafeInteger(result.status) && result.status >= 0 && result.status <= 255
      ? result.status
      : "unknown";
    const signal = ["SIGTERM", "SIGKILL", "SIGINT", "SIGBREAK", "SIGABRT"].includes(result.signal)
      ? result.signal
      : result.signal == null ? "none" : "other";
    return [
      `child_exit=${exit}`,
      `child_signal=${signal}`,
      `child_timed_out=${result.error?.code === "ETIMEDOUT"}`,
      `child_spawn_error=${Boolean(result.error)}`,
      `child_json_emitted=${typeof result.stdout === "string" && result.stdout.trim().endsWith("}")}`,
      `child_stages=${stages.length ? stages.join(",") : "none"}`,
    ].join("\n");
  }

  function runFixture(includeUploads, adversarial = false) {
    const runtime = createPrivateAuthorityFixture("rootark-67-cloud-optout-");
    try {
      const result = spawnSync(process.execPath, [__filename], {
        cwd: runtime, encoding: "utf8", timeout: 45000,
        env: {
          ...Object.fromEntries(Object.entries(process.env).filter(([key]) =>
            !/^(AWS_|GOOGLE_|CLOUD_STORAGE_|S3_|GDRIVE_|DRIVE_|ZK10_)/i.test(key))),
          NODE_ENV: "test", DB_ENABLED: "false", BACKUP_ENABLED: "true",
          BACKUP_INCLUDE_UPLOADS: String(includeUploads),
          BACKUP_INCLUDE_TEMP: "false", BACKUP_INCLUDE_PENDING: "false",
          UPLOAD_QUARANTINE_DIR: path.join(runtime, "quarantine"),
          ROOTARK_TEST_UPLOAD_OPTOUT_CHILD: "1",
          ROOTARK_TEST_UPLOAD_OPTOUT_ADVERSARIAL: adversarial === "bad-json" ? "bad-json" : adversarial ? "1" : "0",
        },
      });
      assert.equal(result.status, 0, safeChildDiagnostics(result));
      try {
        return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
      } catch {
        assert.fail(`child_json_invalid=true\n${safeChildDiagnostics(result)}`);
      }
    } finally {
      fs.rmSync(runtime, { recursive: true, force: true });
    }
  }

  test("disabling uploads excludes local and cloud uploads and cannot certify a complete baseline", () => {
    const result = runFixture(false);
    assert.equal(result.status, "success");
    assert.equal(result.inventoryCalls, 1, "retain authoritative inventory admission");
    assert.equal(result.downloadCalls, 0, "disabled cloud uploads must never be downloaded");
    assert.equal(result.cloudComplete, false, "partial ZIP must not certify the restore baseline");
    assert.equal(result.metadataCloudComplete, false);
    assert.ok(result.entries.includes("data/settings.json"));
    assert.equal(result.entries.some((entry) => entry.startsWith("uploads/")), false);
    assert.equal(result.listed.some((entry) => entry.startsWith("uploads/")), false);
  });

  test("enabling uploads preserves local and cloud coverage with a complete baseline", () => {
    const result = runFixture(true);
    assert.equal(result.status, "success");
    assert.equal(result.inventoryCalls, 1);
    assert.equal(result.downloadCalls, 1);
    assert.equal(result.cloudComplete, true);
    assert.equal(result.metadataCloudComplete, true);
    for (const name of ["uploads/local-only.txt", "uploads/cloud-only.txt"]) {
      assert.ok(result.entries.includes(name), `missing ZIP entry ${name}`);
      assert.ok(result.listed.includes(name), `missing manifest entry ${name}`);
    }
  });

  test("adversarial child error never leaks fake secrets, paths, stdout, or unbounded stages", () => {
    assert.throws(() => runFixture(false, true), (error) => {
      assert.equal(error.code, "ERR_ASSERTION");
      assert.match(error.message, /child_exit=73/);
      assert.doesNotMatch(error.message, /SYNTHETIC_SECRET_CANARY_DO_NOT_DISCLOSE/);
      assert.doesNotMatch(error.message, /SYNTHETIC_STDOUT_SECRET_CANARY/);
      assert.doesNotMatch(error.message, /synthetic-private|credential\.txt|untrusted/);
      assert.ok(error.message.length < 400, "failure diagnostics must stay bounded");
      return true;
    });
  });

  test("invalid child JSON never leaks synthetic stdout in parsing failure", () => {
    assert.throws(() => runFixture(false, "bad-json"), (error) => {
      assert.equal(error.code, "ERR_ASSERTION");
      assert.match(error.message, /child_json_invalid=true/);
      assert.doesNotMatch(error.message, /SYNTHETIC_STDOUT_SECRET_CANARY|synthetic-private|credential\.txt/);
      assert.ok(error.message.length < 400, "invalid-JSON failure diagnostics must stay bounded");
      return true;
    });
  });
}
