"use strict";

// Disposable opt-in ZIP coverage gate. No real archive or user data is read.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

if (process.env.ROOTARK_TEST_COVERAGE_CHILD === "1") {
  const root = process.cwd();
  const uploads = path.join(root, "uploads");
  const outside = path.join(root, "outside-disposable");
  fs.mkdirSync(path.join(root, "data"), { recursive: true });
  fs.mkdirSync(uploads, { recursive: true });
  fs.mkdirSync(path.join(root, "temp"), { recursive: true });
  fs.mkdirSync(outside, { recursive: true });
  fs.writeFileSync(path.join(root, "data", "settings.json"), "{}");
  fs.writeFileSync(path.join(outside, "recoverable.txt"), "outside remains unchanged");
  const mode = process.env.ROOTARK_TEST_COVERAGE_MODE;
  try {
    if (mode === "root-link") {
      fs.rmdirSync(uploads);
      fs.symlinkSync(outside, uploads, process.platform === "win32" ? "junction" : "dir");
    } else if (mode === "nested-link") {
      fs.mkdirSync(path.join(uploads, "files"));
      fs.symlinkSync(outside, path.join(uploads, "files", "archive"),
        process.platform === "win32" ? "junction" : "dir");
    } else if (mode === "file-link") {
      fs.symlinkSync(path.join(outside, "recoverable.txt"),
        path.join(uploads, "alias.txt"), "file");
    } else if (mode === "unsupported-fifo") {
      if (process.platform === "win32") {
        console.log(JSON.stringify({ skipped: "POSIX FIFO fixture only" }));
        process.exit(0);
      }
      const result = spawnSync("mkfifo", [path.join(uploads, "blocked.pipe")]);
      assert.equal(result.status, 0, "mkfifo fixture failed");
    } else if (mode === "ordinary") {
      fs.writeFileSync(path.join(uploads, "payload.txt"), "expected payload");
    } else {
      throw new Error("Invalid disposable coverage fixture mode");
    }
  } catch (error) {
    if (process.platform === "win32" && ["EPERM", "EACCES"].includes(error.code)) {
      console.log(JSON.stringify({ skipped: "Windows link privileges unavailable" }));
      process.exit(0);
    }
    throw error;
  }
  const service = require("../services/backupService");
  const repository = require("../repositories/backupRepository");
  service.setCloudStorage({ enabled: () => false });
  (async () => {
    let created = null;
    let error = null;
    try {
      created = await service.createBackup({
        createdBy: "disposable-coverage-fixture",
        backupId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
      });
    } catch (failure) { error = failure.message; }
    const last = repository.latestStatus();
    const archives = fs.existsSync(service.BACKUPS_DIR)
      ? fs.readdirSync(service.BACKUPS_DIR).filter((name) => name.endsWith(".zip")) : [];
    console.log(JSON.stringify({
      created: Boolean(created), error, status: last?.status || null,
      archiveCount: archives.length,
      outsideBytes: fs.readFileSync(path.join(outside, "recoverable.txt"), "utf8"),
    }));
  })().catch((error) => { console.error(error.stack || error); process.exitCode = 1; });
} else {
  function runDisposableBackup(t, mode) {
    const runtime = createPrivateAuthorityFixture("rootark-67-zip-coverage-");
    t.after(() => fs.rmSync(runtime, { recursive: true, force: true }));
    const env = {
      ...Object.fromEntries(Object.entries(process.env).filter(([name]) =>
        !/^(AWS_|GOOGLE_|CLOUD_STORAGE_|S3_|GDRIVE_|DRIVE_|ZK10_)/i.test(name))),
      NODE_ENV: "test",
      DB_ENABLED: "false",
      BACKUP_ENABLED: "true",
      BACKUP_INCLUDE_UPLOADS: "true",
      BACKUP_INCLUDE_TEMP: "false",
      BACKUP_RETENTION_COUNT: "10",
      UPLOAD_QUARANTINE_DIR: path.join(runtime, "quarantine"),
      ROOTARK_TEST_COVERAGE_MODE: mode,
      ROOTARK_TEST_COVERAGE_CHILD: "1",
    };
    const result = spawnSync(process.execPath, [__filename], {
      cwd: runtime, env, encoding: "utf8", timeout: 30000,
    });
    assert.equal(result.status, 0, "disposable child failed: " + result.stderr);
    const output = result.stdout.trim().split(/\r?\n/).at(-1);
    const response = JSON.parse(output);
    if (response.skipped) {
      t.skip(response.skipped);
      return null;
    }
    return response;
  }

  test("#67 backup ZIP includes ordinary opted-in upload sources", (t) => {
    const result = runDisposableBackup(t, "ordinary");
    if (!result) return;
    assert.equal(result.created, true);
    assert.equal(result.status, "success");
    assert.equal(result.archiveCount, 1);
  });

  for (const mode of ["root-link", "nested-link", "file-link", "unsupported-fifo"]) {
    test("#67 backup ZIP fails closed instead of silently omitting " + mode, (t) => {
      const result = runDisposableBackup(t, mode);
      if (!result) return;
      assert.equal(result.created, false, "a skipped source must not produce a successful backup");
      assert.equal(result.status, "failed");
      assert.equal(result.archiveCount, 0);
      assert.match(result.error, /backup source|symbolic link|unsafe/i);
      assert.equal(result.outsideBytes, "outside remains unchanged");
    });
  }
}
