const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");

test("quarantine backup and restore preserve external payloads and reject incomplete archives", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-restore-runtime-"));
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-payloads-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const unzipper = require(${JSON.stringify(path.join(ROOT, "node_modules", "unzipper"))});
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
      const payloadName = "blocked-upload.bin";
      const secretPayloadName = "credentials.pem";
      const payloadPath = path.join(process.env.UPLOAD_QUARANTINE_DIR, payloadName);
      const secretPayloadPath = path.join(process.env.UPLOAD_QUARANTINE_DIR, secretPayloadName);
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      const payloadBytes = Buffer.from("disposable quarantined bytes");
      const secretPayloadBytes = Buffer.from("sensitive key material");
      const metadata = { items: [
        { id: "quarantine-entry", storedQuarantineFilename: payloadName, originalFilename: "untrusted.bin" },
        { id: "sensitive-quarantine-entry", storedQuarantineFilename: secretPayloadName, originalFilename: "untrusted.pem" },
      ] };
      const safeMetadata = { items: [metadata.items[0]] };
      fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
      fs.writeFileSync(metadataPath, JSON.stringify(metadata));
      fs.writeFileSync(payloadPath, payloadBytes);
      fs.writeFileSync(secretPayloadPath, secretPayloadBytes);
      fs.writeFileSync(path.join(process.cwd(), "data", "runtime-only.json"), "before");
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        const zip = await unzipper.Open.file(backupService.getArchivePath(backup.filename));
        const entries = zip.files.map((entry) => entry.path);
        assert.ok(entries.includes("data/quarantine.json"));
        const archivedPayload = zip.files.find((entry) => entry.path === "data/quarantine/" + payloadName);
        assert.ok(archivedPayload);
        assert.deepEqual(await archivedPayload.buffer(), payloadBytes);
        assert.equal(entries.includes("data/quarantine/" + secretPayloadName), false);
        const archivedMetadata = JSON.parse(await zip.files.find((entry) => entry.path === "data/quarantine.json").buffer());
        assert.deepEqual(archivedMetadata, safeMetadata);

        const changedPayloadName = "changed-upload.bin";
        fs.rmSync(payloadPath);
        fs.writeFileSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, changedPayloadName), "mutated");
        const changedMetadata = { items: [{ id: "changed", storedQuarantineFilename: changedPayloadName }, metadata.items[1]] };
        fs.writeFileSync(metadataPath, JSON.stringify(changedMetadata));
        fs.writeFileSync(path.join(process.cwd(), "data", "runtime-only.json"), "mutated");
        await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" });
        assert.deepEqual(fs.readFileSync(payloadPath), payloadBytes);
        assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), { items: [metadata.items[0], metadata.items[1]] });
        assert.equal(fs.existsSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, changedPayloadName)), false);
        assert.deepEqual(fs.readFileSync(secretPayloadPath), secretPayloadBytes);
        assert.equal(fs.readFileSync(path.join(process.cwd(), "data", "runtime-only.json"), "utf8"), "before");

        const conflictingMetadata = { items: [{ id: "changed", storedQuarantineFilename: changedPayloadName }, metadata.items[1]] };
        fs.writeFileSync(metadataPath, JSON.stringify(conflictingMetadata));
        fs.writeFileSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, changedPayloadName), "mutated-again");
        fs.writeFileSync(path.join(process.cwd(), "data", "runtime-only.json"), "preflight-must-not-write");
        await assert.rejects(restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" }), /Quarantine payload destination already exists/);
        assert.equal(fs.readFileSync(path.join(process.cwd(), "data", "runtime-only.json"), "utf8"), "preflight-must-not-write");
        assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), conflictingMetadata);
        assert.equal(fs.readFileSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, changedPayloadName), "utf8"), "mutated-again");
        assert.deepEqual(fs.readFileSync(payloadPath), payloadBytes);
        fs.writeFileSync(path.join(process.cwd(), "data", "runtime-only.json"), "before");

        const sameIdSensitiveItem = { id: "quarantine-entry", storedQuarantineFilename: secretPayloadName, originalFilename: "private.pem" };
        const currentSecretBytes = Buffer.from("new current secret bytes");
        fs.writeFileSync(secretPayloadPath, currentSecretBytes);
        fs.writeFileSync(metadataPath, JSON.stringify({ items: [sameIdSensitiveItem] }));
        await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" });
        assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), { items: [sameIdSensitiveItem] });
        assert.deepEqual(fs.readFileSync(secretPayloadPath), currentSecretBytes);
        assert.deepEqual(fs.readFileSync(payloadPath), payloadBytes);

        const badArchivePath = path.join(backupService.BACKUPS_DIR, "rootark-backup-2026-09-28-23-59-59.zip");
        const badMetadataPath = path.join(process.cwd(), "data", "bad-quarantine.json");
        const badRuntimePath = path.join(process.cwd(), "data", "bad-runtime.json");
        const missingMetadata = { items: [{ id: "missing", storedQuarantineFilename: "missing.bin" }] };
        const changedBytes = Buffer.from("must not restore");
        fs.writeFileSync(badMetadataPath, JSON.stringify(missingMetadata));
        fs.writeFileSync(badRuntimePath, changedBytes);
        const files = [
          { absolutePath: badMetadataPath, entryPath: "data/quarantine.json", size: fs.statSync(badMetadataPath).size },
          { absolutePath: badRuntimePath, entryPath: "data/runtime-only.json", size: changedBytes.length },
        ];
        const manifest = { backup_id: "33333333-3333-4333-8333-333333333333", included_files: files.map((file) => ({ path: file.entryPath, size: file.size })) };
        await backupService.createZipArchive(badArchivePath, manifest, files);
        const badBackup = { id: manifest.backup_id, filename: path.basename(badArchivePath), type: "manual", status: "success", createdAt: new Date().toISOString(), sizeBytes: fs.statSync(badArchivePath).size, checksum: await backupService.calculateFileHash(badArchivePath), metadata: {} };
        backupRepository.saveBackup(badBackup);
        await assert.rejects(restoreService.restoreBackup(badBackup.id, { confirmation: "RESTORE", username: "fixture" }), /Quarantine payload is missing/);
        assert.equal(fs.readFileSync(path.join(process.cwd(), "data", "runtime-only.json"), "utf8"), "before");
        assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), { items: [sameIdSensitiveItem] });
        assert.deepEqual(fs.readFileSync(payloadPath), payloadBytes);
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: quarantineDir, BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(quarantineDir, { recursive: true, force: true });
  }
});

test("quarantine restore recovers its prior state after process interruption", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-crash-runtime-"));
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-crash-payloads-"));
  try {
    const setupScript = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      const archivePayload = path.join(process.env.UPLOAD_QUARANTINE_DIR, "archive.bin");
      const currentPayload = path.join(process.env.UPLOAD_QUARANTINE_DIR, "current.bin");
      fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
      fs.mkdirSync(process.env.UPLOAD_QUARANTINE_DIR, { recursive: true });
      const archivedMetadata = { items: [{ id: "archive", storedQuarantineFilename: "archive.bin" }] };
      fs.writeFileSync(metadataPath, JSON.stringify(archivedMetadata));
      fs.writeFileSync(archivePayload, "archived-payload");
      fs.writeFileSync(path.join(process.cwd(), "data", "runtime-only.json"), "current-runtime-state");
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        fs.rmSync(archivePayload);
        fs.writeFileSync(currentPayload, "current-payload");
        fs.writeFileSync(metadataPath, JSON.stringify({ items: [{ id: "current", storedQuarantineFilename: "current.bin" }] }));
        const nativeRename = fs.renameSync;
        fs.renameSync = function (source, destination) {
          if (String(source).includes(".rootark-quarantine-restore-") && path.resolve(destination) === path.resolve(metadataPath)) process.exit(73);
          return nativeRename.call(this, source, destination);
        };
        await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" });
        process.exitCode = 2;
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const env = { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: quarantineDir, BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false", BACKUP_RETENTION_COUNT: "20" };
    const interrupted = spawnSync(process.execPath, ["-e", setupScript], { cwd: runtime, env, encoding: "utf8" });
    assert.equal(interrupted.status, 73, interrupted.stderr || interrupted.stdout);

    const recoveryScript = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      restoreService.recoverQuarantineRestore();
      assert.deepEqual(JSON.parse(fs.readFileSync(path.join(process.cwd(), "data", "quarantine.json"), "utf8")), { items: [{ id: "current", storedQuarantineFilename: "current.bin" }] });
      assert.equal(fs.readFileSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "current.bin"), "utf8"), "current-payload");
      assert.equal(fs.existsSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "archive.bin")), false);
      assert.equal(fs.readFileSync(path.join(process.cwd(), "data", "runtime-only.json"), "utf8"), "current-runtime-state");
      console.log(JSON.stringify({ ok: true }));
    `;
    const recovered = spawnSync(process.execPath, ["-e", recoveryScript], { cwd: runtime, env, encoding: "utf8" });
    assert.equal(recovered.status, 0, recovered.stderr || recovered.stdout);
    assert.equal(JSON.parse(recovered.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(quarantineDir, { recursive: true, force: true });
  }
});

test("quarantine restore recovery preserves missing metadata state across startup initialization", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-empty-crash-runtime-"));
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-empty-crash-payloads-"));
  try {
    const setupScript = `
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      const archivePayload = path.join(process.env.UPLOAD_QUARANTINE_DIR, "archive.bin");
      fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
      fs.mkdirSync(process.env.UPLOAD_QUARANTINE_DIR, { recursive: true });
      fs.writeFileSync(metadataPath, JSON.stringify({ items: [{ id: "archive", storedQuarantineFilename: "archive.bin" }] }));
      fs.writeFileSync(archivePayload, "archived-payload");
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        fs.rmSync(metadataPath);
        fs.rmSync(archivePayload);
        const nativeRename = fs.renameSync;
        fs.renameSync = function (source, destination) {
          if (String(source).includes(".rootark-quarantine-restore-") && path.resolve(destination) === path.resolve(metadataPath)) process.exit(73);
          return nativeRename.call(this, source, destination);
        };
        await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" });
        process.exitCode = 2;
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const env = { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: quarantineDir, BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false", BACKUP_RETENTION_COUNT: "20" };
    const interrupted = spawnSync(process.execPath, ["-e", setupScript], { cwd: runtime, env, encoding: "utf8" });
    assert.equal(interrupted.status, 73, interrupted.stderr || interrupted.stdout);

    const recoveryScript = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      if (!fs.existsSync(metadataPath) && !restoreService.hasPendingQuarantineRestore()) fs.writeFileSync(metadataPath, JSON.stringify({ items: [] }, null, 2));
      restoreService.recoverQuarantineRestore();
      if (!fs.existsSync(metadataPath)) fs.writeFileSync(metadataPath, JSON.stringify({ items: [] }, null, 2));
      assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), { items: [] });
      assert.equal(fs.existsSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "archive.bin")), false);
      assert.equal(restoreService.hasPendingQuarantineRestore(), false);
    `;
    const recovered = spawnSync(process.execPath, ["-e", recoveryScript], { cwd: runtime, env, encoding: "utf8" });
    assert.equal(recovered.status, 0, recovered.stderr || recovered.stdout);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(quarantineDir, { recursive: true, force: true });
  }
});

test("quarantine restore startup finalizes a committed transaction after interruption", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-commit-crash-runtime-"));
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-commit-crash-payloads-"));
  try {
    const setupScript = `
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      const journalPath = path.join(process.cwd(), "data", ".rootark-quarantine-restore-journal.json");
      const archivePayload = path.join(process.env.UPLOAD_QUARANTINE_DIR, "archive.bin");
      const currentPayload = path.join(process.env.UPLOAD_QUARANTINE_DIR, "current.bin");
      fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
      fs.mkdirSync(process.env.UPLOAD_QUARANTINE_DIR, { recursive: true });
      fs.writeFileSync(metadataPath, JSON.stringify({ items: [{ id: "archive", storedQuarantineFilename: "archive.bin" }] }));
      fs.writeFileSync(archivePayload, "archived-payload");
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        fs.writeFileSync(metadataPath, JSON.stringify({ items: [{ id: "current", storedQuarantineFilename: "current.bin" }] }));
        fs.rmSync(archivePayload);
        fs.writeFileSync(currentPayload, "current-payload");
        const nativeRmSync = fs.rmSync;
        fs.rmSync = function (target, options) {
          if (path.resolve(String(target)) === path.resolve(journalPath)) {
            const stages = fs.readdirSync(process.env.UPLOAD_QUARANTINE_DIR).filter((name) => name.startsWith(".rootark-quarantine-restore-"));
            if (stages.some((name) => fs.existsSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, name, "committed")))) process.exit(74);
          }
          return nativeRmSync.call(this, target, options);
        };
        await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" });
        process.exitCode = 2;
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const env = { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: quarantineDir, BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false", BACKUP_RETENTION_COUNT: "20" };
    const interrupted = spawnSync(process.execPath, ["-e", setupScript], { cwd: runtime, env, encoding: "utf8" });
    assert.equal(interrupted.status, 74, interrupted.stderr || interrupted.stdout);

    const recoveryScript = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      restoreService.recoverQuarantineRestore();
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), { items: [{ id: "archive", storedQuarantineFilename: "archive.bin" }] });
      assert.equal(fs.readFileSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "archive.bin"), "utf8"), "archived-payload");
      assert.equal(fs.existsSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "current.bin")), false);
      assert.equal(fs.existsSync(path.join(process.cwd(), "data", ".rootark-quarantine-restore-journal.json")), false);
      assert.equal(fs.readdirSync(process.env.UPLOAD_QUARANTINE_DIR).some((name) => name.startsWith(".rootark-quarantine-restore-")), false);
      console.log(JSON.stringify({ ok: true }));
    `;
    const recovered = spawnSync(process.execPath, ["-e", recoveryScript], { cwd: runtime, env, encoding: "utf8" });
    assert.equal(recovered.status, 0, recovered.stderr || recovered.stdout);
    assert.equal(JSON.parse(recovered.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(quarantineDir, { recursive: true, force: true });
  }
});

test("quarantine restore recovers after each payload and metadata rename boundary", { timeout: 60_000 }, () => {
  const cases = ["old-payload-1", "old-payload-2", "new-payload-1", "new-payload-2", "old-metadata", "new-metadata", "committed-marker"];
  for (const boundary of cases) {
    const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-rename-runtime-"));
    const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-rename-payloads-"));
    try {
      const setupScript = `
        const fs = require("node:fs");
        const path = require("node:path");
        const boundary = ${JSON.stringify(boundary)};
        const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
        const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
        const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
        const journalPath = path.join(process.cwd(), "data", ".rootark-quarantine-restore-journal.json");
        const payloadDir = process.env.UPLOAD_QUARANTINE_DIR;
        const archiveNames = ["archive-1.bin", "archive-2.bin"];
        const currentNames = ["current-1.bin", "current-2.bin"];
        fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
        fs.mkdirSync(payloadDir, { recursive: true });
        fs.writeFileSync(metadataPath, JSON.stringify({ items: archiveNames.map((storedQuarantineFilename, index) => ({ id: "archive-" + (index + 1), storedQuarantineFilename })) }));
        archiveNames.forEach((name, index) => fs.writeFileSync(path.join(payloadDir, name), "archive-payload-" + (index + 1)));
        (async () => {
          const backup = await backupService.createBackup({ createdBy: "fixture" });
          fs.writeFileSync(metadataPath, JSON.stringify({ items: currentNames.map((storedQuarantineFilename, index) => ({ id: "current-" + (index + 1), storedQuarantineFilename })) }));
          archiveNames.forEach((name) => fs.rmSync(path.join(payloadDir, name)));
          currentNames.forEach((name, index) => fs.writeFileSync(path.join(payloadDir, name), "current-payload-" + (index + 1)));
          const nativeRename = fs.renameSync;
          fs.renameSync = function (source, destination) {
            const from = path.resolve(String(source));
            const to = path.resolve(String(destination));
            const isOldPayload = currentNames.some((name, index) => from === path.join(payloadDir, name) && to.endsWith("old-" + index));
            const isNewPayload = archiveNames.some((name, index) => from.endsWith("new-" + index) && to === path.join(payloadDir, name));
            const isOldMetadata = from === metadataPath && to.endsWith("old-metadata");
            const isNewMetadata = from.endsWith("new-metadata") && to === metadataPath;
            const isCommittedMarker = from.endsWith("committed.tmp") && to.endsWith("committed");
            const matches = (boundary === "old-payload-1" && isOldPayload && to.endsWith("old-0"))
              || (boundary === "old-payload-2" && isOldPayload && to.endsWith("old-1"))
              || (boundary === "new-payload-1" && isNewPayload && to === path.join(payloadDir, "archive-1.bin"))
              || (boundary === "new-payload-2" && isNewPayload && to === path.join(payloadDir, "archive-2.bin"))
              || (boundary === "old-metadata" && isOldMetadata)
              || (boundary === "new-metadata" && isNewMetadata)
              || (boundary === "committed-marker" && isCommittedMarker);
            const result = nativeRename.call(this, source, destination);
            if (matches) process.exit(75);
            return result;
          };
          await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" });
          process.exitCode = 2;
        })().catch((error) => { console.error(error); process.exitCode = 1; });
      `;
      const env = { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: quarantineDir, BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false", BACKUP_RETENTION_COUNT: "20" };
      const interrupted = spawnSync(process.execPath, ["-e", setupScript], { cwd: runtime, env, encoding: "utf8" });
      assert.equal(interrupted.status, 75, `${boundary}: ${interrupted.stderr || interrupted.stdout}`);

      const recoveryScript = `
        const assert = require("node:assert/strict");
        const fs = require("node:fs");
        const path = require("node:path");
        const boundary = ${JSON.stringify(boundary)};
        const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
        const payloadDir = process.env.UPLOAD_QUARANTINE_DIR;
        const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
        const committed = boundary === "committed-marker";
        restoreService.recoverQuarantineRestore();
        const expectedNames = committed ? ["archive-1.bin", "archive-2.bin"] : ["current-1.bin", "current-2.bin"];
        const absentNames = committed ? ["current-1.bin", "current-2.bin"] : ["archive-1.bin", "archive-2.bin"];
        const expectedPrefix = committed ? "archive" : "current";
        assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), { items: expectedNames.map((storedQuarantineFilename, index) => ({ id: expectedPrefix + "-" + (index + 1), storedQuarantineFilename })) });
        expectedNames.forEach((name, index) => assert.equal(fs.readFileSync(path.join(payloadDir, name), "utf8"), expectedPrefix + "-payload-" + (index + 1)));
        absentNames.forEach((name) => assert.equal(fs.existsSync(path.join(payloadDir, name)), false));
        assert.equal(restoreService.hasPendingQuarantineRestore(), false);
        assert.equal(fs.readdirSync(payloadDir).some((name) => name.startsWith(".rootark-quarantine-restore-")), false);
        console.log(JSON.stringify({ ok: true }));
      `;
      const recovered = spawnSync(process.execPath, ["-e", recoveryScript], { cwd: runtime, env, encoding: "utf8" });
      assert.equal(recovered.status, 0, `${boundary}: ${recovered.stderr || recovered.stdout}`);
      assert.equal(JSON.parse(recovered.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
    } finally {
      fs.rmSync(runtime, { recursive: true, force: true });
      fs.rmSync(quarantineDir, { recursive: true, force: true });
    }
  }
});
