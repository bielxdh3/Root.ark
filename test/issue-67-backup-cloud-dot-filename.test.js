"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const ROOT = path.resolve(__dirname, "..");

function runCloudFixture(names) {
  const runtime = createPrivateAuthorityFixture("rootark-67-cloud-path-");
  const script = [
    'const fs = require("node:fs"); const path = require("node:path");',
    'const service = require(' + JSON.stringify(path.join(ROOT, "services", "backupService")) + ');',
    'const unzipper = require(' + JSON.stringify(path.join(ROOT, "node_modules", "unzipper")) + ');',
    'const names = ' + JSON.stringify(names) + ';',
    'fs.mkdirSync("data", { recursive: true }); fs.mkdirSync("uploads", { recursive: true });',
    'const objects = names.map((name, i) => ({ provider: "s3", providerIdentity: "different-object-" + i, area: "uploads", folderId: "root", name }));',
    'const downloads = []; let index = 0;',
    'service.setCloudStorage({ enabled: () => true, inventory: async () => objects,',
    '  download: async (_folderId, _name, target) => { const i = index++; downloads.push(i); fs.writeFileSync(target, "distinct remote bytes " + i); return true; } });',
    '(async () => {',
    '  let created = null; let error = null; let entries = []; let payloads = {};',
    '  try { created = await service.createBackup();',
    '    const archive = await unzipper.Open.file(path.join("data", "backups", created.filename));',
    '    entries = archive.files.filter((entry) => entry.type !== "Directory").map((entry) => entry.path);',
    '    for (const entry of archive.files.filter((entry) => entry.path.startsWith("uploads/"))) payloads[entry.path] = (await entry.buffer()).toString("utf8");',
    '  } catch (failure) { error = failure.message; }',
    '  const dir = path.join("data", "backups"); const zips = fs.existsSync(dir) ? fs.readdirSync(dir).filter((name) => name.endsWith(".zip")) : [];',
    '  const history = service.listBackups();',
    '  console.log(JSON.stringify({ created: !!created, error, zips, entries, payloads, downloads, success: history.filter((entry) => entry.status === "success").length, failed: history.filter((entry) => entry.status === "failed").length }));',
    '})().catch((error) => { console.error(error.stack || error); process.exitCode = 1; });',
  ].join("\n");
  try {
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: {
        ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(AWS_|GOOGLE_|CLOUD_STORAGE_|S3_|GDRIVE_|DRIVE_|ZK10_)/i.test(key))),
        DB_ENABLED: "false",
        NODE_ENV: "test",
        BACKUP_ENABLED: "true",
        BACKUP_INCLUDE_UPLOADS: "true",
        BACKUP_INCLUDE_TEMP: "false",
        UPLOAD_QUARANTINE_DIR: path.join(runtime, "quarantine"),
      },
      encoding: "utf8",
      timeout: 45_000,
    });
    assert.equal(result.status, 0, result.stderr || result.error?.message || result.stdout);
    return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
}

test("an ordinary remote filename remains represented in the ZIP", () => {
  const result = runCloudFixture(["first.txt"]);
  assert.equal(result.created, true, JSON.stringify(result));
  assert.deepEqual(result.downloads, [0]);
  assert.equal(result.success, 1);
  assert.equal(result.failed, 0);
  assert.equal(result.zips.length, 1);
  assert.equal(result.payloads["uploads/first.txt"], "distinct remote bytes 0");
});

for (const name of [".", ".."]) {
  test("remote filename " + name + " cannot collapse the ZIP entry path", () => {
    const result = runCloudFixture([name]);
    assert.equal(result.created, false, JSON.stringify(result));
    assert.match(result.error, /unsafe path/i);
    assert.deepEqual(result.zips, []);
    assert.equal(result.success, 0);
    assert.equal(result.failed, 1);
    assert.deepEqual(result.downloads, [], "reject unsafe remote names before downloading");
  });
}
