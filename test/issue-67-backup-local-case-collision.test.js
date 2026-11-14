"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

if (process.env.ROOTARK_TEST_LOCAL_CASE_BACKUP_CHILD === "1") {
  const root = process.cwd();
  const data = path.join(root, "data");
  const uploads = path.join(root, "uploads");
  fs.mkdirSync(data, { recursive: true });
  fs.mkdirSync(uploads, { recursive: true });
  fs.writeFileSync(path.join(data, "settings.json"), "{}");
  fs.writeFileSync(path.join(uploads, "Case.txt"), "uppercase content");
  if (process.env.ROOTARK_TEST_LOCAL_CASE_BACKUP_MODE === "collision") {
    fs.writeFileSync(path.join(uploads, "case.txt"), "lowercase content");
    const names = fs.readdirSync(uploads);
    if (!names.includes("Case.txt") || !names.includes("case.txt")) {
      console.log(JSON.stringify({ skipped: "filesystem does not support case-distinct siblings" }));
      process.exit(0);
    }
  }
  const backupService = require("../services/backupService");
  const backupRepository = require("../repositories/backupRepository");
  backupService.setCloudStorage({ enabled: () => false });
  (async () => {
    let created = null;
    let error = null;
    let entries = [];
    try {
      created = await backupService.createBackup();
      const unzipper = require("unzipper");
      const zip = await unzipper.Open.file(path.join(data, "backups", created.filename));
      entries = zip.files.map((item) => item.path);
    } catch (failure) { error = failure.message; }
    const zipDir = path.join(data, "backups");
    const archives = fs.existsSync(zipDir)
      ? fs.readdirSync(zipDir).filter((name) => name.endsWith(".zip")) : [];
    const history = backupRepository.listBackups();
    console.log(JSON.stringify({
      ok: Boolean(created), error, entries, archives: archives.length,
      success: history.filter((item) => item.status === "success").length,
      failed: history.filter((item) => item.status === "failed").length,
      included: created?.metadata?.manifest?.included_files?.map((item) => item.path) || [],
    }));
  })().catch((error) => { console.error(error.stack || error); process.exitCode = 1; });
} else {
  function run(mode) {
    const runtime = createPrivateAuthorityFixture("rootark-backup-local-case-");
    const env = {
      ...Object.fromEntries(Object.entries(process.env).filter(([key]) =>
        !/^(AWS_|GOOGLE_|CLOUD_STORAGE_|S3_|GDRIVE_|DRIVE_|ZK10_)/i.test(key))),
      NODE_ENV: "test", DB_ENABLED: "false", BACKUP_ENABLED: "true",
      BACKUP_INCLUDE_UPLOADS: "true", BACKUP_INCLUDE_TEMP: "false",
      BACKUP_INCLUDE_PENDING: "false", BACKUP_RETENTION_COUNT: "10",
      UPLOAD_QUARANTINE_DIR: path.join(runtime, "quarantine"),
      ROOTARK_TEST_LOCAL_CASE_BACKUP_CHILD: "1",
      ROOTARK_TEST_LOCAL_CASE_BACKUP_MODE: mode,
    };
    try {
      const result = spawnSync(process.execPath, [__filename], {
        cwd: runtime, env, encoding: "utf8", timeout: 60000,
      });
      assert.equal(result.status, 0, result.stderr || result.error?.message || result.stdout);
      return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
    } finally {
      fs.rmSync(runtime, { recursive: true, force: true });
    }
  }

  test("local ZIP rejects case-distinct paths that its restore cannot admit", (t) => {
    const result = run("collision");
    if (result.skipped) return t.skip(result.skipped);
    assert.equal(result.ok, false, JSON.stringify(result));
    assert.match(result.error, /backup entry collision/i);
    assert.equal(result.archives, 0);
    assert.equal(result.success, 0);
    assert.equal(result.failed, 1);
  });

  test("local ZIP still includes ordinary upload and JSON entries", () => {
    const result = run("ordinary");
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.archives, 1);
    for (const name of ["uploads/Case.txt", "data/settings.json"]) {
      assert.ok(result.entries.includes(name), `missing ZIP entry ${name}`);
      assert.ok(result.included.includes(name), `missing manifest entry ${name}`);
    }
  });
}
