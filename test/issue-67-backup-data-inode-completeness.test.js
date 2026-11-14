"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const ROOT = path.resolve(__dirname, "..");

function runCase(kind, name = "settings.json") {
  const runtime = createPrivateAuthorityFixture("rootark-backup-inode-");
  const servicePath = path.join(ROOT, "services", "backupService");
  const unzipperPath = path.join(ROOT, "node_modules", "unzipper");
  const script = [
    'const fs = require("node:fs"); const path = require("node:path"); const { spawnSync } = require("node:child_process");',
    'process.chdir(' + JSON.stringify(runtime) + ');',
    'const backup = require(' + JSON.stringify(servicePath) + ');',
    'const unzipper = require(' + JSON.stringify(unzipperPath) + ');',
    'const kind = ' + JSON.stringify(kind) + '; const name = ' + JSON.stringify(name) + ';',
    'const dataDir = path.join(process.cwd(), "data"); fs.mkdirSync(dataDir, { recursive: true });',
    'fs.writeFileSync(path.join(dataDir, "ordinary.json"), "{}");',
    'const target = path.join(dataDir, name); const external = path.join(process.cwd(), "outside-source.txt");',
    'if (kind === "directory" || kind === "excluded") fs.mkdirSync(target);',
    'if (kind === "symlink") { fs.writeFileSync(external, "external"); try { fs.symlinkSync(external, target, "file"); } catch (error) { if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) { console.log(JSON.stringify({ skipped: error.code })); process.exit(0); } throw error; } }',
    'if (kind === "fifo") { const result = spawnSync("mkfifo", [target], { encoding: "utf8" }); if (result.status !== 0) throw Error(result.stderr || "mkfifo failed"); }',
    'if (kind === "regular") { fs.writeFileSync(target, "{}"); fs.writeFileSync(path.join(dataDir, "README.md"), "readme"); }',
    'backup.setCloudStorage({ enabled: () => false });',
    '(async () => { let record = null; let error = null; let members = []; try { record = await backup.createBackup(); const archive = await unzipper.Open.file(path.join(dataDir, "backups", record.filename)); members = archive.files.map((entry) => entry.path); } catch (failure) { error = failure.message; }',
    'const backupsDir = path.join(dataDir, "backups"); const zips = fs.existsSync(backupsDir) ? fs.readdirSync(backupsDir).filter((entry) => entry.endsWith(".zip")) : [];',
    'const history = backup.listBackups(); console.log(JSON.stringify({ ok: !!record, error, zips, success: history.filter((entry) => entry.status === "success").length, failed: history.filter((entry) => entry.status === "failed").length, members, included: record?.metadata?.manifest?.included_files?.map((entry) => entry.path) || [] })); })().catch((error) => { console.error(error); process.exitCode = 1; });',
  ].join("\n");
  const env = {
    ...process.env,
    NODE_ENV: "test",
    DB_ENABLED: "false",
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "false",
    BACKUP_INCLUDE_TEMP: "false",
    UPLOAD_QUARANTINE_DIR: path.join(runtime, "quarantine"),
  };
  try {
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime, env, encoding: "utf8", timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.error?.message || result.stdout);
    return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
}

for (const [kind, name] of [
  ["directory", "settings.json"],
  ["directory", "README.md"],
  ["symlink", "sync-objects.json"],
  ...(process.platform === "win32" ? [] : [["fifo", "settings.json"]]),
]) {
  test("eligible data/" + name + " " + kind + " aborts ZIP and success metadata", (t) => {
    const result = runCase(kind, name);
    if (result.skipped) return t.skip("symlink unavailable: " + result.skipped);
    assert.equal(result.ok, false, JSON.stringify(result));
    // The signed-history guard now rejects a noncanonical physical inode
    // before the generic backup-source scanner can inspect the symlink.
    const expected = name === "sync-objects.json"
      ? /(?:backup (?:data )?source.*(?:symbolic link|junction|regular file|unsupported filesystem entry)|signed sync history must use the physical canonical data\/sync-objects\.json filename)/i
      : /backup (?:data )?source.*(symbolic link|junction|regular file|unsupported filesystem entry)/i;
    assert.match(result.error, expected);
    assert.deepEqual(result.zips, []);
    assert.equal(result.success, 0);
    assert.equal(result.failed, 1);
  });
}

test("sensitive excluded data/credentials.json directory does not block normal archive", () => {
  const result = runCase("excluded", "credentials.json");
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.ok(result.members.includes("data/ordinary.json"));
  assert.ok(!result.members.includes("data/credentials.json"));
  assert.equal(result.success, 1);
});

test("regular JSON and README.md are recorded in a successful ZIP manifest", () => {
  const result = runCase("regular");
  assert.equal(result.ok, true, JSON.stringify(result));
  for (const name of ["data/settings.json", "data/README.md", "data/ordinary.json"]) {
    assert.ok(result.members.includes(name), name + " absent from ZIP");
    assert.ok(result.included.includes(name), name + " absent from manifest");
  }
});
