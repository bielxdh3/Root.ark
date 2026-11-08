"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

if (process.env.ROOTARK_TEST_UPLOAD_OPTOUT_CHILD === "1") {
  const dataDir = path.join(process.cwd(), "data");
  const uploadsDir = path.join(process.cwd(), "uploads");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(uploadsDir, { recursive: true });
  fs.writeFileSync(path.join(dataDir, "settings.json"), "{}");
  fs.writeFileSync(path.join(uploadsDir, "local-only.txt"), "local bytes");

  const backupService = require("../services/backupService");
  const unzipper = require("unzipper");
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
    const saved = await backupService.createBackup({ createdBy: "disposable-test" });
    const zip = await unzipper.Open.file(path.join(dataDir, "backups", saved.filename));
    const manifest = JSON.parse((await zip.files.find((entry) => entry.path === "backup-manifest.json").buffer()).toString("utf8"));
    console.log(JSON.stringify({
      status: saved.status,
      cloudComplete: manifest.cloud_complete,
      metadataCloudComplete: saved.metadata.cloudComplete,
      entries: zip.files.filter((entry) => entry.type !== "Directory").map((entry) => entry.path),
      listed: manifest.included_files.map((entry) => entry.path),
      inventoryCalls, downloadCalls,
    }));
  })().catch((error) => { console.error(error.stack || error); process.exitCode = 1; });
} else {
  function runFixture(includeUploads) {
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
        },
      });
      assert.equal(result.status, 0, result.stderr || result.error?.message || result.stdout);
      return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
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
}
