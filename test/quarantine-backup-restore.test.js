const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");

test("quarantine metadata is read from the validated file descriptor and rejects path swaps", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-metadata-read-"));
  const metadataPath = path.join(directory, "quarantine.json");
  const replacementPath = path.join(directory, "replacement.json");
  const metadata = { items: [] };
  const originalReadFileSync = fs.readFileSync;
  const originalLstatSync = fs.lstatSync;
  let openedDescriptor;
  try {
    fs.writeFileSync(metadataPath, JSON.stringify(metadata));
    fs.writeFileSync(replacementPath, JSON.stringify({ items: [{ id: "replacement" }] }));
    fs.readFileSync = function readFileFromDescriptor(file, ...args) {
      if (typeof file === "number") openedDescriptor = file;
      return originalReadFileSync.call(this, file, ...args);
    };
    const quarantinePaths = require("../src/quarantine-paths");
    assert.deepEqual(quarantinePaths.readQuarantineMetadata(metadataPath), metadata);
    assert.equal(typeof openedDescriptor, "number");
    fs.lstatSync = function lstatAfterPathSwap(file, ...args) {
      if (path.resolve(file) === path.resolve(metadataPath)) return originalLstatSync.call(this, replacementPath, ...args);
      return originalLstatSync.call(this, file, ...args);
    };
    assert.throws(() => quarantinePaths.readQuarantineMetadata(metadataPath), /not a regular file/);
  } finally {
    fs.readFileSync = originalReadFileSync;
    fs.lstatSync = originalLstatSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("quarantine readers reject dangling symlinks on Windows", { skip: process.platform !== "win32", timeout: 30_000 }, (t) => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-dangling-link-runtime-"));
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-dangling-link-payloads-"));
  const dataDir = path.join(runtime, "data");
  const metadataPath = path.join(dataDir, "quarantine.json");
  const journalPath = path.join(dataDir, ".rootark-quarantine-restore-journal.json");
  try {
    fs.mkdirSync(dataDir, { recursive: true });
    const stagePath = path.join(quarantineDir, `.rootark-quarantine-restore-${crypto.randomUUID()}`);
    fs.mkdirSync(stagePath);
    try {
      fs.symlinkSync("missing-target", metadataPath, "file");
      fs.symlinkSync("missing-target", journalPath, "file");
    } catch (error) {
      if (["EPERM", "EACCES", "UNKNOWN"].includes(error.code)) {
        t.skip("Windows symbolic-link privileges are unavailable");
        return;
      }
      throw error;
    }
    const script = `
      const assert = require("node:assert/strict");
      const path = require("node:path");
      const quarantinePaths = require(${JSON.stringify(path.join(ROOT, "src", "quarantine-paths"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      assert.throws(() => quarantinePaths.readQuarantineMetadata(path.join(process.cwd(), "data", "quarantine.json")), /not a regular file/);
      assert.throws(() => restoreService.recoverQuarantineRestore(), /journal is invalid/);
      assert.equal(require("node:fs").existsSync(${JSON.stringify(stagePath)}), true);
      console.log(JSON.stringify({ ok: true }));
    `;
    const env = { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: quarantineDir, BACKUP_ENABLED: "true", BACKUP_RETENTION_COUNT: "20" };
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, env, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(quarantineDir, { recursive: true, force: true });
  }
});

test("quarantine startup recovery is serialized with cross-process restores", { timeout: 30_000 }, async () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-recovery-lock-runtime-"));
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-recovery-lock-payloads-"));
  const stagePath = path.join(quarantineDir, `.rootark-quarantine-restore-${crypto.randomUUID()}`);
  const env = { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: quarantineDir, BACKUP_ENABLED: "true", BACKUP_RETENTION_COUNT: "20" };
  let holder;
  try {
    fs.mkdirSync(path.join(runtime, "data"), { recursive: true });
    fs.mkdirSync(stagePath);
    const holderScript = `
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const release = backupService.acquireLock("restore");
      process.send({ locked: true });
      process.on("message", (message) => {
        if (!message || !message.release) return;
        release();
        process.send({ released: true }, () => process.disconnect());
      });
    `;
    holder = spawn(process.execPath, ["-e", holderScript], { cwd: runtime, env, stdio: ["ignore", "ignore", "pipe", "ipc"] });
    const locked = await new Promise((resolve, reject) => {
      holder.once("message", resolve);
      holder.once("error", reject);
      holder.once("exit", (code) => reject(new Error(`Lock holder exited before acquiring the lock: ${code}`)));
    });
    assert.deepEqual(locked, { locked: true });

    const blockedScript = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      assert.throws(() => restoreService.recoverQuarantineRestore(), { code: "BACKUP_LOCKED" });
      assert.equal(fs.existsSync(${JSON.stringify(stagePath)}), true);
      console.log(JSON.stringify({ blocked: true }));
    `;
    const blocked = spawnSync(process.execPath, ["-e", blockedScript], { cwd: runtime, env, encoding: "utf8" });
    assert.equal(blocked.status, 0, blocked.stderr || blocked.stdout);
    assert.equal(JSON.parse(blocked.stdout.trim().split(/\r?\n/).at(-1)).blocked, true);

    const releasedPromise = new Promise((resolve, reject) => {
      holder.once("message", resolve);
      holder.once("error", reject);
      holder.once("exit", (code) => reject(new Error(`Lock holder exited before releasing the lock: ${code}`)));
    });
    holder.send({ release: true });
    assert.deepEqual(await releasedPromise, { released: true });
    await new Promise((resolve, reject) => {
      holder.once("exit", (code) => code === 0 ? resolve() : reject(new Error(`Lock holder exited with ${code}`)));
      holder.once("error", reject);
    });

    const recoveryScript = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      assert.equal(restoreService.recoverQuarantineRestore(), false);
      assert.equal(fs.existsSync(${JSON.stringify(stagePath)}), false);
      console.log(JSON.stringify({ recovered: true }));
    `;
    const recovered = spawnSync(process.execPath, ["-e", recoveryScript], { cwd: runtime, env, encoding: "utf8" });
    assert.equal(recovered.status, 0, recovered.stderr || recovered.stdout);
    assert.equal(JSON.parse(recovered.stdout.trim().split(/\r?\n/).at(-1)).recovered, true);
  } finally {
    if (holder?.connected) {
      holder.send({ release: true });
      await new Promise((resolve) => {
        const timer = setTimeout(() => { holder.kill(); resolve(); }, 2_000);
        holder.once("exit", () => { clearTimeout(timer); resolve(); });
      });
    }
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(quarantineDir, { recursive: true, force: true });
  }
});

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
      const payloadName = "Blocked-Upload.Bin";
      const secretPayloadName = "credentials.pem";
      const envPayloadNames = [".env.local", ".env.production", ".env.development"];
      const payloadPath = path.join(process.env.UPLOAD_QUARANTINE_DIR, payloadName);
      const secretPayloadPath = path.join(process.env.UPLOAD_QUARANTINE_DIR, secretPayloadName);
      const envPayloadPaths = envPayloadNames.map((name) => path.join(process.env.UPLOAD_QUARANTINE_DIR, name));
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      const payloadBytes = Buffer.from("disposable quarantined bytes");
      const secretPayloadBytes = Buffer.from("sensitive key material");
      const envPayloadBytes = envPayloadNames.map((name) => Buffer.from("sensitive " + name));
      const metadata = { items: [
        { id: "quarantine-entry", storedQuarantineFilename: payloadName, originalFilename: "untrusted.bin" },
        { id: "sensitive-quarantine-entry", storedQuarantineFilename: secretPayloadName, originalFilename: "untrusted.pem" },
        ...envPayloadNames.map((name, index) => ({ id: "sensitive-" + name, storedQuarantineFilename: name, originalFilename: "untrusted-" + index + ".bin" })),
      ] };
      const safeMetadata = { items: [metadata.items[0]] };
      fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
      fs.writeFileSync(metadataPath, JSON.stringify(metadata));
      fs.writeFileSync(payloadPath, payloadBytes);
      fs.writeFileSync(secretPayloadPath, secretPayloadBytes);
      envPayloadPaths.forEach((filePath, index) => fs.writeFileSync(filePath, envPayloadBytes[index]));
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
        for (const name of envPayloadNames) assert.equal(entries.includes("data/quarantine/" + name), false);
        const archivedMetadata = JSON.parse(await zip.files.find((entry) => entry.path === "data/quarantine.json").buffer());
        const archivedManifest = JSON.parse((await zip.files.find((entry) => entry.path === "backup-manifest.json").buffer()).toString("utf8"));
        assert.equal(archivedManifest.quarantine_format_version, 1);
        assert.deepEqual(archivedMetadata, safeMetadata);

        const changedPayloadName = "changed-upload.bin";
        fs.rmSync(payloadPath);
        fs.writeFileSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, changedPayloadName), "mutated");
        const changedMetadata = { items: [{ id: "changed", storedQuarantineFilename: changedPayloadName }, ...metadata.items.slice(1)] };
        fs.writeFileSync(metadataPath, JSON.stringify(changedMetadata));
        fs.writeFileSync(path.join(process.cwd(), "data", "runtime-only.json"), "mutated");
        await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" });
        assert.deepEqual(fs.readFileSync(payloadPath), payloadBytes);
        assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), { items: [metadata.items[0], ...metadata.items.slice(1)] });
        assert.equal(fs.existsSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, changedPayloadName)), false);
        assert.deepEqual(fs.readFileSync(secretPayloadPath), secretPayloadBytes);
        envPayloadPaths.forEach((filePath, index) => assert.deepEqual(fs.readFileSync(filePath), envPayloadBytes[index]));
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

        const legacyArchivePath = path.join(backupService.BACKUPS_DIR, "rootark-backup-2026-09-28-23-59-58.zip");
        const legacyMetadataPath = path.join(process.cwd(), "data", "legacy-quarantine.json");
        const legacyRuntimePath = path.join(process.cwd(), "data", "legacy-runtime.json");
        const legacyMetadata = { items: [{ id: "legacy", storedQuarantineFilename: "legacy.bin" }] };
        const legacyBytes = Buffer.from("restored by legacy backup");
        fs.writeFileSync(legacyMetadataPath, JSON.stringify(legacyMetadata));
        fs.writeFileSync(legacyRuntimePath, legacyBytes);
        const legacyFiles = [
          { absolutePath: legacyMetadataPath, entryPath: "data/quarantine.json", size: fs.statSync(legacyMetadataPath).size },
          { absolutePath: legacyRuntimePath, entryPath: "data/runtime-only.json", size: legacyBytes.length },
        ];
        const legacyManifest = { backup_id: "33333333-3333-4333-8333-333333333333", included_files: legacyFiles.map((file) => ({ path: file.entryPath, size: file.size })) };
        await backupService.createZipArchive(legacyArchivePath, legacyManifest, legacyFiles);
        const legacyBackup = { id: legacyManifest.backup_id, filename: path.basename(legacyArchivePath), type: "manual", status: "success", createdAt: new Date().toISOString(), sizeBytes: fs.statSync(legacyArchivePath).size, checksum: await backupService.calculateFileHash(legacyArchivePath), metadata: {} };
        backupRepository.saveBackup(legacyBackup);
        await assert.rejects(restoreService.restoreBackup(legacyBackup.id, { confirmation: "RESTORE", username: "fixture" }), /Quarantine archive payloads are missing/);
        assert.equal(fs.readFileSync(path.join(process.cwd(), "data", "runtime-only.json"), "utf8"), "before");
        assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), { items: [sameIdSensitiveItem] });
        assert.deepEqual(fs.readFileSync(payloadPath), payloadBytes);

        const badArchivePath = path.join(backupService.BACKUPS_DIR, "rootark-backup-2026-09-28-23-59-59.zip");
        const badMetadataPath = path.join(process.cwd(), "data", "bad-quarantine.json");
        const badRuntimePath = path.join(process.cwd(), "data", "bad-runtime.json");
        const incompleteMetadata = { items: [{ id: "missing", storedQuarantineFilename: "missing.bin" }] };
        const changedBytes = Buffer.from("must not restore");
        fs.writeFileSync(badMetadataPath, JSON.stringify(incompleteMetadata));
        fs.writeFileSync(badRuntimePath, changedBytes);
        const badFiles = [
          { absolutePath: badMetadataPath, entryPath: "data/quarantine.json", size: fs.statSync(badMetadataPath).size },
          { absolutePath: badRuntimePath, entryPath: "data/runtime-only.json", size: changedBytes.length },
        ];
        const badManifest = { backup_id: "44444444-4444-4444-8444-444444444444", quarantine_format_version: 1, included_files: badFiles.map((file) => ({ path: file.entryPath, size: file.size })) };
        await backupService.createZipArchive(badArchivePath, badManifest, badFiles);
        const badBackup = { id: badManifest.backup_id, filename: path.basename(badArchivePath), type: "manual", status: "success", createdAt: new Date().toISOString(), sizeBytes: fs.statSync(badArchivePath).size, checksum: await backupService.calculateFileHash(badArchivePath), metadata: {} };
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

test("restore rejects legacy dotenv archives before changing runtime files", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-dotenv-restore-runtime-"));
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-dotenv-restore-payloads-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
      const dataEnvPath = path.join(process.cwd(), "data", ".env.local");
      const uploadEnvPath = path.join(process.cwd(), "uploads", ".ENV.PRODUCTION");
      const runtimePath = path.join(process.cwd(), "data", "runtime-only.json");
      fs.mkdirSync(path.dirname(dataEnvPath), { recursive: true });
      fs.mkdirSync(path.dirname(uploadEnvPath), { recursive: true });
      fs.writeFileSync(dataEnvPath, "current-data-env");
      fs.writeFileSync(uploadEnvPath, "current-upload-env");
      fs.writeFileSync(runtimePath, "current-runtime-data");
      (async () => {
        const cases = [
          { entryPath: "data/.env.local", currentPath: dataEnvPath },
          { entryPath: "uploads/.ENV.PRODUCTION", currentPath: uploadEnvPath },
        ];
        for (const [index, item] of cases.entries()) {
          const sourcePath = path.join(process.cwd(), "archived-env-" + index);
          const archivePath = path.join(backupService.BACKUPS_DIR, "rootark-backup-2026-09-29-00-00-00-00" + index + "-0000000" + index + ".zip");
          fs.mkdirSync(path.dirname(archivePath), { recursive: true });
          fs.writeFileSync(sourcePath, "attacker-controlled archived secret");
          const files = [{ absolutePath: sourcePath, entryPath: item.entryPath, size: fs.statSync(sourcePath).size }];
          const backupId = "55555555-5555-4555-8555-55555555555" + index;
          const manifest = { backup_id: backupId, included_files: files.map((file) => ({ path: file.entryPath, size: file.size })) };
          await backupService.createZipArchive(archivePath, manifest, files);
          backupRepository.saveBackup({ id: backupId, filename: path.basename(archivePath), type: "manual", status: "success", createdAt: new Date().toISOString(), sizeBytes: fs.statSync(archivePath).size, checksum: await backupService.calculateFileHash(archivePath), metadata: {} });
          await assert.rejects(restoreService.restoreBackup(backupId, { confirmation: "RESTORE", username: "fixture" }), /Entrada sensivel bloqueada/);
          assert.equal(fs.readFileSync(item.currentPath, "utf8"), index === 0 ? "current-data-env" : "current-upload-env");
          assert.equal(fs.readFileSync(runtimePath, "utf8"), "current-runtime-data");
        }
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: quarantineDir, BACKUP_ENABLED: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(quarantineDir, { recursive: true, force: true });
  }
});

test("restore rejects case-aliased quarantine control files on Windows", { skip: process.platform !== "win32", timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-control-restore-runtime-"));
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-control-restore-payloads-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
      const quarantineMetadataPath = path.join(process.cwd(), "data", "quarantine.json");
      const journalPath = path.join(process.cwd(), "data", ".rootark-quarantine-restore-journal.json");
      const runtimePath = path.join(process.cwd(), "data", "runtime-only.json");
      fs.mkdirSync(path.dirname(quarantineMetadataPath), { recursive: true });
      fs.writeFileSync(quarantineMetadataPath, JSON.stringify({ items: [] }));
      fs.writeFileSync(journalPath, "current recovery journal");
      fs.writeFileSync(runtimePath, "current runtime data");
      (async () => {
        const cases = [
          { entryPath: "data/Quarantine.json", bytes: "{\\"items\\":[]}" },
          { entryPath: "data/.ROOTARK-QUARANTINE-RESTORE-JOURNAL.JSON", bytes: "attacker journal" },
        ];
        for (const [index, item] of cases.entries()) {
          const sourcePath = path.join(process.cwd(), "archived-control-" + index);
          const archivePath = path.join(backupService.BACKUPS_DIR, "rootark-backup-2026-09-29-00-01-00-00" + index + "-0000000" + index + ".zip");
          fs.mkdirSync(path.dirname(archivePath), { recursive: true });
          fs.writeFileSync(sourcePath, item.bytes);
          const files = [{ absolutePath: sourcePath, entryPath: item.entryPath, size: fs.statSync(sourcePath).size }];
          const backupId = "66666666-6666-4666-8666-66666666666" + index;
          const manifest = { backup_id: backupId, included_files: files.map((file) => ({ path: file.entryPath, size: file.size })) };
          await backupService.createZipArchive(archivePath, manifest, files);
          backupRepository.saveBackup({ id: backupId, filename: path.basename(archivePath), type: "manual", status: "success", createdAt: new Date().toISOString(), sizeBytes: fs.statSync(archivePath).size, checksum: await backupService.calculateFileHash(archivePath), metadata: {} });
          await assert.rejects(restoreService.restoreBackup(backupId, { confirmation: "RESTORE", username: "fixture" }), /Entrada de controle bloqueada/);
          assert.equal(fs.readFileSync(quarantineMetadataPath, "utf8"), JSON.stringify({ items: [] }));
          assert.equal(fs.readFileSync(journalPath, "utf8"), "current recovery journal");
          assert.equal(fs.readFileSync(runtimePath, "utf8"), "current runtime data");
        }
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
