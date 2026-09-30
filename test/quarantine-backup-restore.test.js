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
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const quarantinePaths = require(${JSON.stringify(path.join(ROOT, "src", "quarantine-paths"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      fs.mkdirSync(backupService.BACKUPS_DIR, { recursive: true });
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

test("backup and restore reject quarantine directories that equal or contain uploads", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-overlap-runtime-"));
  const externalQuarantine = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-overlap-external-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const uploadsDir = path.join(process.cwd(), "uploads");
      const runtimeRoot = process.cwd();
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      fs.mkdirSync(uploadsDir, { recursive: true });
      fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
      fs.writeFileSync(path.join(uploadsDir, "ordinary.txt"), "before restore");
      fs.writeFileSync(metadataPath, JSON.stringify({ items: [] }));
      (async () => {
        process.env.UPLOAD_QUARANTINE_DIR = process.env.EXTERNAL_QUARANTINE_DIR;
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        const preRestoreCountBefore = backupRepository.listBackups().filter((item) => item.type === "pre-restore").length;
        for (const overlapPath of [uploadsDir, runtimeRoot]) {
          process.env.UPLOAD_QUARANTINE_DIR = overlapPath;
          await assert.rejects(
            () => backupService.createBackup({ createdBy: "fixture" }),
            /quarantine directory equals or contains uploads/,
          );
          await assert.rejects(
            () => restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" }),
            /quarantine directory equals or contains uploads/,
          );
          assert.equal(backupRepository.listBackups().filter((item) => item.type === "pre-restore").length, preRestoreCountBefore);
          assert.equal(fs.readFileSync(path.join(uploadsDir, "ordinary.txt"), "utf8"), "before restore");
        }
        const alias = path.join(runtimeRoot, "uploads-alias");
        try {
          fs.symlinkSync(uploadsDir, alias, process.platform === "win32" ? "junction" : "dir");
          process.env.UPLOAD_QUARANTINE_DIR = alias;
          await assert.rejects(
            () => backupService.createBackup({ createdBy: "fixture" }),
            /quarantine directory equals or contains uploads/,
          );
        } catch (error) {
          if (!["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error.code)) throw error;
        }
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: externalQuarantine, EXTERNAL_QUARANTINE_DIR: externalQuarantine, BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(externalQuarantine, { recursive: true, force: true });
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

test("quarantine backup excludes prefixed payloads inside included uploads", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-upload-exclusion-runtime-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const unzipper = require(${JSON.stringify(path.join(ROOT, "node_modules", "unzipper"))});
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const uploadsDir = path.join(process.cwd(), "uploads");
      const quarantineDir = process.env.UPLOAD_QUARANTINE_DIR;
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      const payloadName = "quarantined-secret-7f3a2.bin";
      fs.mkdirSync(quarantineDir, { recursive: true });
      fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
      fs.mkdirSync(uploadsDir, { recursive: true });
      fs.writeFileSync(path.join(uploadsDir, "ordinary-upload.txt"), "ordinary upload");
      fs.writeFileSync(path.join(quarantineDir, payloadName), "sensitive quarantined bytes");
      fs.writeFileSync(metadataPath, JSON.stringify({ items: [
        { id: "sensitive-entry", storedQuarantineFilename: payloadName, originalFilename: ".env.local" },
      ] }));
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        const zip = await unzipper.Open.file(backupService.getArchivePath(backup.filename));
        const entries = zip.files.map((entry) => entry.path);
        assert.ok(entries.includes("uploads/ordinary-upload.txt"));
        assert.equal(entries.includes("uploads/.quarantine-store/" + payloadName), false);
        assert.equal(entries.includes("data/quarantine/" + payloadName), false);
        const archivedMetadata = JSON.parse((await zip.files.find((entry) => entry.path === "data/quarantine.json").buffer()).toString("utf8"));
        assert.deepEqual(archivedMetadata.items, []);
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: path.join(runtime, "uploads", ".quarantine-store"), BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("quarantine restore preserves payloads nested under uploads", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-nested-restore-runtime-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const uploadsDir = path.join(process.cwd(), "uploads");
      const quarantineDir = process.env.UPLOAD_QUARANTINE_DIR;
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      const archivedName = "archived-safe.bin";
      const currentName = "current-safe.bin";
      const sensitiveName = "current-sensitive.bin";
      const metadata = { items: [
        { id: "archived", storedQuarantineFilename: archivedName, originalFilename: "document.bin" },
        { id: "sensitive", storedQuarantineFilename: sensitiveName, originalFilename: ".env.local" },
      ] };
      fs.mkdirSync(quarantineDir, { recursive: true });
      fs.mkdirSync(uploadsDir, { recursive: true });
      fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
      fs.writeFileSync(path.join(uploadsDir, "ordinary.txt"), "before restore");
      fs.writeFileSync(path.join(quarantineDir, archivedName), "archived quarantine payload");
      fs.writeFileSync(path.join(quarantineDir, sensitiveName), "current sensitive payload");
      fs.writeFileSync(metadataPath, JSON.stringify(metadata));
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        fs.rmSync(path.join(quarantineDir, archivedName));
        fs.writeFileSync(path.join(quarantineDir, currentName), "current safe payload");
        fs.writeFileSync(path.join(uploadsDir, "ordinary.txt"), "after backup");
        const currentMetadata = { items: [
          { id: "current", storedQuarantineFilename: currentName, originalFilename: "current.bin" },
          metadata.items[1],
        ] };
        fs.writeFileSync(metadataPath, JSON.stringify(currentMetadata));
        await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" });
        assert.equal(fs.readFileSync(path.join(uploadsDir, "ordinary.txt"), "utf8"), "before restore");
        assert.equal(fs.readFileSync(path.join(quarantineDir, archivedName), "utf8"), "archived quarantine payload");
        assert.equal(fs.readFileSync(path.join(quarantineDir, sensitiveName), "utf8"), "current sensitive payload");
        assert.equal(fs.existsSync(path.join(quarantineDir, currentName)), false);
        assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), { items: [metadata.items[0], metadata.items[1]] });
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: path.join(runtime, "uploads", ".quarantine-store"), BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("quarantine restore preserves payloads addressed through a Windows short path", { timeout: 30_000 }, (t) => {
  if (process.platform !== "win32") {
    t.skip("Windows short-path aliases are not available on this platform");
    return;
  }
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-shortpath-runtime-"));
  try {
    const quarantineDir = path.join(runtime, "uploads", ".quarantine-store");
    fs.mkdirSync(quarantineDir, { recursive: true });
    const shortPathResult = spawnSync("cmd.exe", ["/d", "/q"], {
      input: `for %I in ("${quarantineDir}") do @echo %~sI\r\nexit\r\n`,
      encoding: "utf8",
    });
    const shortQuarantineDir = shortPathResult.stdout.trim().split(/\r?\n/).at(-1);
    if (shortPathResult.status !== 0 || !shortQuarantineDir || shortQuarantineDir.toLowerCase() === quarantineDir.toLowerCase()
      || !shortQuarantineDir.includes("~")) {
      t.skip("The runtime volume does not provide an 8.3 short-path alias");
      return;
    }
    assert.equal(fs.realpathSync.native(shortQuarantineDir).toLowerCase(), fs.realpathSync.native(quarantineDir).toLowerCase());
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const uploadsDir = path.join(process.cwd(), "uploads");
      const quarantineDir = process.env.LONG_QUARANTINE_DIR;
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      fs.mkdirSync(uploadsDir, { recursive: true });
      fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
      fs.writeFileSync(path.join(uploadsDir, "ordinary.txt"), "before restore");
      fs.writeFileSync(path.join(quarantineDir, "archived-safe.bin"), "archived quarantine payload");
      fs.writeFileSync(metadataPath, JSON.stringify({ items: [
        { id: "archived", storedQuarantineFilename: "archived-safe.bin", originalFilename: "document.bin" },
      ] }));
      (async () => {
        process.env.UPLOAD_QUARANTINE_DIR = quarantineDir;
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        fs.rmSync(path.join(quarantineDir, "archived-safe.bin"));
        fs.writeFileSync(path.join(uploadsDir, "ordinary.txt"), "after backup");
        fs.writeFileSync(metadataPath, JSON.stringify({ items: [] }));
        process.env.UPLOAD_QUARANTINE_DIR = process.env.SHORT_QUARANTINE_DIR;
        await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" });
        assert.equal(fs.readFileSync(path.join(uploadsDir, "ordinary.txt"), "utf8"), "before restore");
        assert.equal(fs.readFileSync(path.join(quarantineDir, "archived-safe.bin"), "utf8"), "archived quarantine payload");
        assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")).items.map((item) => item.id), ["archived"]);
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "false", LONG_QUARANTINE_DIR: quarantineDir, SHORT_QUARANTINE_DIR: shortQuarantineDir, BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("quarantine restore does not write through upload junction ancestors", { timeout: 30_000 }, (t) => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-junction-restore-runtime-"));
  const external = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-junction-restore-external-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const uploadsDir = path.join(process.cwd(), "uploads");
      const cacheDir = path.join(uploadsDir, "cache");
      const quarantineDir = process.env.UPLOAD_QUARANTINE_DIR;
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      const external = process.env.QUARANTINE_EXTERNAL_DIR;
      const siblingPath = path.join(external, "neighbor.txt");
      fs.mkdirSync(path.join(cacheDir, "private"), { recursive: true });
      fs.mkdirSync(path.join(process.cwd(), "data"), { recursive: true });
      fs.writeFileSync(path.join(uploadsDir, "ordinary.txt"), "before restore");
      fs.writeFileSync(path.join(cacheDir, "neighbor.txt"), "archived neighbor");
      fs.writeFileSync(path.join(quarantineDir, "archived-safe.bin"), "archived quarantine payload");
      fs.writeFileSync(metadataPath, JSON.stringify({ items: [
        { id: "archived", storedQuarantineFilename: "archived-safe.bin", originalFilename: "document.bin" },
      ] }));
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        fs.mkdirSync(path.join(external, "private"), { recursive: true });
        fs.writeFileSync(path.join(external, "private", "current-sensitive.bin"), "current sensitive payload");
        fs.writeFileSync(siblingPath, "external neighbor after backup");
        fs.writeFileSync(metadataPath, JSON.stringify({ items: [
          { id: "sensitive", storedQuarantineFilename: "current-sensitive.bin", originalFilename: ".env.local" },
        ] }));
        fs.writeFileSync(path.join(uploadsDir, "ordinary.txt"), "after backup");
        fs.rmSync(cacheDir, { recursive: true, force: true });
        try {
          fs.symlinkSync(external, cacheDir, process.platform === "win32" ? "junction" : "dir");
        } catch (error) {
          if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error.code)) {
            console.log(JSON.stringify({ skipped: "directory symlink/junction creation is unavailable" }));
            return;
          }
          throw error;
        }
        const backupCountBeforeRestore = backupRepository.listBackups().length;
        await assert.rejects(
          restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" }),
          /Restore is not supported when the quarantine directory is nested below an uploads subdirectory/,
        );
        assert.equal(fs.readFileSync(path.join(uploadsDir, "ordinary.txt"), "utf8"), "after backup");
        assert.equal(fs.lstatSync(cacheDir).isSymbolicLink(), true);
        assert.equal(fs.readFileSync(siblingPath, "utf8"), "external neighbor after backup");
        assert.equal(fs.existsSync(path.join(quarantineDir, "archived-safe.bin")), false);
        assert.equal(fs.readFileSync(path.join(quarantineDir, "current-sensitive.bin"), "utf8"), "current sensitive payload");
        assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), { items: [
          { id: "sensitive", storedQuarantineFilename: "current-sensitive.bin", originalFilename: ".env.local" },
        ] });
        assert.equal(backupRepository.listBackups().length, backupCountBeforeRestore);
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: path.join(runtime, "uploads", "cache", "private"), QUARANTINE_EXTERNAL_DIR: external, BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const outcome = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
    if (outcome.skipped) {
      t.skip(outcome.skipped);
      return;
    }
    assert.equal(outcome.ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(external, { recursive: true, force: true });
  }
});

test("quarantine restore rejects deep paths reached through an upload alias", { timeout: 30_000 }, (t) => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-alias-restore-runtime-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const uploadsDir = path.join(process.cwd(), "uploads");
      const aliasDir = path.join(process.cwd(), "uploads-alias");
      const quarantineDir = process.env.UPLOAD_QUARANTINE_DIR;
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      fs.mkdirSync(uploadsDir, { recursive: true });
      fs.mkdirSync(path.join(uploadsDir, "cache"), { recursive: true });
      fs.mkdirSync(path.join(process.cwd(), "data"), { recursive: true });
      try {
        fs.symlinkSync(uploadsDir, aliasDir, process.platform === "win32" ? "junction" : "dir");
      } catch (error) {
        if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error.code)) {
          console.log(JSON.stringify({ skipped: "directory symlink/junction creation is unavailable" }));
          process.exit(0);
        }
        throw error;
      }
      fs.writeFileSync(path.join(uploadsDir, "ordinary.txt"), "before restore");
      fs.writeFileSync(metadataPath, JSON.stringify({ items: [] }));
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        const countBeforeRestore = backupRepository.listBackups().length;
        await assert.rejects(
          restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" }),
          /Restore is not supported when the quarantine directory is nested below an uploads subdirectory/,
        );
        assert.equal(backupRepository.listBackups().length, countBeforeRestore);
        assert.equal(fs.existsSync(quarantineDir), false, "missing quarantine suffix must remain missing");
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: path.join(runtime, "uploads-alias", "cache", "private"), BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const outcome = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
    if (outcome.skipped) {
      t.skip(outcome.skipped);
      return;
    }
    assert.equal(outcome.ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("quarantine restore fails closed if an upload alias becomes nested during restore", { timeout: 30_000 }, (t) => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-alias-race-runtime-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const uploadsDir = path.join(process.cwd(), "uploads");
      const aliasDir = path.join(process.cwd(), "uploads-alias");
      const cacheDir = path.join(uploadsDir, "cache");
      const movedQuarantineDir = path.join(uploadsDir, "private", "cache");
      const quarantineDir = process.env.UPLOAD_QUARANTINE_DIR;
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      fs.mkdirSync(cacheDir, { recursive: true });
      fs.mkdirSync(movedQuarantineDir, { recursive: true });
      fs.mkdirSync(path.join(process.cwd(), "data"), { recursive: true });
      try {
        fs.symlinkSync(uploadsDir, aliasDir, process.platform === "win32" ? "junction" : "dir");
      } catch (error) {
        if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error.code)) {
          console.log(JSON.stringify({ skipped: "directory symlink/junction creation is unavailable" }));
          process.exit(0);
        }
        throw error;
      }
      fs.mkdirSync(quarantineDir, { recursive: true });
      fs.writeFileSync(path.join(cacheDir, "ordinary.txt"), "before restore");
      fs.writeFileSync(path.join(quarantineDir, "current.bin"), "current quarantine payload");
      fs.writeFileSync(path.join(movedQuarantineDir, "current-sensitive.bin"), "moved quarantine payload");
      fs.writeFileSync(metadataPath, JSON.stringify({ items: [] }));
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        const originalCreateBackup = backupService.createBackup;
        let raceHookReached = false;
        backupService.createBackup = async (...args) => {
          const created = await originalCreateBackup(...args);
          if (args[0]?.type === "pre-restore") {
            const originalReadDir = fs.readdirSync;
            fs.readdirSync = function (target, options) {
              const entries = originalReadDir.apply(this, arguments);
              if (!raceHookReached && path.resolve(target) === uploadsDir && options?.withFileTypes) {
                raceHookReached = true;
                fs.rmSync(aliasDir, { recursive: true, force: true });
                fs.symlinkSync(path.join(uploadsDir, "private"), aliasDir, process.platform === "win32" ? "junction" : "dir");
              }
              return entries;
            };
          }
          return created;
        };
        await assert.rejects(
          restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" }),
          /quarantine directory is nested below an uploads subdirectory/,
        );
        assert.equal(raceHookReached, true, "the alias retarget must happen after uploads have been enumerated");
        assert.equal(fs.readFileSync(path.join(movedQuarantineDir, "current-sensitive.bin"), "utf8"), "moved quarantine payload");
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: path.join(runtime, "uploads-alias", "cache"), BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const outcome = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
    if (outcome.skipped) {
      t.skip(outcome.skipped);
      return;
    }
    assert.equal(outcome.ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("quarantine files under data are excluded from generic backup collection", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-data-exclusion-runtime-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const unzipper = require(${JSON.stringify(path.join(ROOT, "node_modules", "unzipper"))});
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const dataDir = path.join(process.cwd(), "data");
      const metadataPath = path.join(dataDir, "quarantine.json");
      const secretName = "quarantined-secret-123.env.local.json";
      const safeName = "quarantined-safe-456.json";
      fs.mkdirSync(dataDir, { recursive: true });
      fs.writeFileSync(path.join(dataDir, "ordinary.json"), "ordinary runtime data");
      fs.writeFileSync(path.join(dataDir, secretName), "sensitive quarantined bytes");
      fs.writeFileSync(path.join(dataDir, safeName), "safe quarantined bytes");
      fs.writeFileSync(metadataPath, JSON.stringify({ items: [
        { id: "sensitive", storedQuarantineFilename: secretName, originalFilename: ".env.local.json" },
        { id: "safe", storedQuarantineFilename: safeName, originalFilename: "document.json" },
      ] }));
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        const zip = await unzipper.Open.file(backupService.getArchivePath(backup.filename));
        const entries = zip.files.map((entry) => entry.path);
        assert.ok(entries.includes("data/ordinary.json"));
        assert.equal(entries.includes("data/" + secretName), false);
        assert.equal(entries.includes("data/" + safeName), false);
        assert.ok(entries.includes("data/quarantine/" + safeName));
        assert.equal(entries.includes("data/quarantine/" + secretName), false);
        const archivedMetadata = JSON.parse((await zip.files.find((entry) => entry.path === "data/quarantine.json").buffer()).toString("utf8"));
        assert.deepEqual(archivedMetadata.items, [{ id: "safe", storedQuarantineFilename: safeName, originalFilename: "document.json" }]);
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: path.join(runtime, "data"), BACKUP_ENABLED: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("generic data backup collection skips symlinked files", { timeout: 30_000 }, (t) => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-data-symlink-runtime-"));
  const external = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-data-symlink-external-"));
  try {
    const dataDir = path.join(runtime, "data");
    const ordinaryPath = path.join(dataDir, "ordinary.json");
    const externalSecretPath = path.join(external, "private-config");
    const symlinkPath = path.join(dataDir, "public.json");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(ordinaryPath, "ordinary data");
    fs.writeFileSync(externalSecretPath, "external secret bytes");
    try {
      fs.symlinkSync(externalSecretPath, symlinkPath, "file");
    } catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP", "EINVAL"].includes(error.code)) {
        t.skip("file symlink creation is unavailable");
        return;
      }
      throw error;
    }
    const script = `
      const assert = require("node:assert/strict");
      const unzipper = require(${JSON.stringify(path.join(ROOT, "node_modules", "unzipper"))});
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        const zip = await unzipper.Open.file(backupService.getArchivePath(backup.filename));
        const entries = zip.files.map((entry) => entry.path);
        assert.ok(entries.includes("data/ordinary.json"));
        assert.equal(entries.includes("data/public.json"), false);
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "false", BACKUP_ENABLED: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(external, { recursive: true, force: true });
  }
});

test("generic uploads and temp backup collection skip symlinked roots and entries", { timeout: 30_000 }, (t) => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-backup-root-symlink-runtime-"));
  const external = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-backup-root-symlink-external-"));
  try {
    const uploadRoot = path.join(runtime, "uploads");
    const tempRoot = path.join(runtime, "temp");
    const externalUploadRoot = path.join(external, "upload-root");
    const externalTempRoot = path.join(external, "temp-root");
    const externalTempEntry = path.join(external, "temp-entry");
    fs.mkdirSync(externalUploadRoot, { recursive: true });
    fs.mkdirSync(externalTempRoot, { recursive: true });
    fs.mkdirSync(externalTempEntry, { recursive: true });
    fs.writeFileSync(path.join(externalUploadRoot, "root-secret.txt"), "external upload root bytes");
    fs.writeFileSync(path.join(externalTempRoot, "root-secret.txt"), "external temp root bytes");
    fs.writeFileSync(path.join(externalTempEntry, "entry-secret.txt"), "external temp entry bytes");
    try {
      const linkType = process.platform === "win32" ? "junction" : "dir";
      fs.symlinkSync(externalUploadRoot, uploadRoot, linkType);
      fs.symlinkSync(externalTempRoot, tempRoot, linkType);
    } catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error.code)) {
        t.skip("directory symlink/junction creation is unavailable");
        return;
      }
      throw error;
    }
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const unzipper = require(${JSON.stringify(path.join(ROOT, "node_modules", "unzipper"))});
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const tempRoot = path.join(process.cwd(), "temp");
      const externalTempEntry = process.env.EXTERNAL_TEMP_ENTRY;
      const linkType = process.platform === "win32" ? "junction" : "dir";
      (async () => {
        const rootBackup = await backupService.createBackup({ createdBy: "fixture" });
        const rootZip = await unzipper.Open.file(backupService.getArchivePath(rootBackup.filename));
        const rootEntries = rootZip.files.map((entry) => entry.path);
        assert.equal(rootEntries.includes("uploads/root-secret.txt"), false);
        assert.equal(rootEntries.includes("temp/root-secret.txt"), false);

        fs.rmSync(tempRoot, { recursive: true, force: true });
        fs.mkdirSync(tempRoot, { recursive: true });
        fs.writeFileSync(path.join(tempRoot, "ordinary.txt"), "ordinary temp file");
        fs.symlinkSync(externalTempEntry, path.join(tempRoot, "external-alias"), linkType);
        const entryBackup = await backupService.createBackup({ createdBy: "fixture" });
        const entryZip = await unzipper.Open.file(backupService.getArchivePath(entryBackup.filename));
        const entryPaths = entryZip.files.map((entry) => entry.path);
        assert.ok(entryPaths.includes("temp/ordinary.txt"));
        assert.equal(entryPaths.includes("temp/external-alias/entry-secret.txt"), false);
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, EXTERNAL_TEMP_ENTRY: externalTempEntry, DB_ENABLED: "false", BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "true", BACKUP_INCLUDE_TEMP: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(external, { recursive: true, force: true });
  }
});

test("backup fails closed when a collected source path is swapped before it opens", { timeout: 30_000 }, (t) => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-backup-source-race-runtime-"));
  const external = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-backup-source-race-external-"));
  try {
    const uploadsDir = path.join(runtime, "uploads");
    const target = path.join(uploadsDir, "ordinary.txt");
    const secretPath = path.join(external, "outside-secret.txt");
    const replacementPath = path.join(external, "replacement.txt");
    const symlinkProbe = path.join(runtime, "symlink-probe");
    fs.mkdirSync(uploadsDir, { recursive: true });
    fs.writeFileSync(target, "checked in-root upload");
    fs.writeFileSync(secretPath, "outside secret sentinel");
    fs.writeFileSync(replacementPath, "replacement bytes");
    let useSymlink = true;
    try {
      fs.symlinkSync(secretPath, symlinkProbe, "file");
      fs.unlinkSync(symlinkProbe);
    } catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP", "UNKNOWN"].includes(error.code)) {
        useSymlink = false;
      } else throw error;
    }

    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const archiver = require(${JSON.stringify(path.join(ROOT, "node_modules", "archiver"))});
      const unzipper = require(${JSON.stringify(path.join(ROOT, "node_modules", "unzipper"))});
      const target = path.join(process.cwd(), "uploads", "ordinary.txt");
      const held = target + ".checked";
      const external = process.env.EXTERNAL_SECRET_PATH;
      const replacement = process.env.RACE_REPLACEMENT_PATH;
      const originalOpenSync = fs.openSync;
      const originalUpdateQueueTaskWithStats = archiver.Archiver.prototype._updateQueueTaskWithStats;
      let swapped = false;
      const replacePath = () => {
        if (swapped) return;
        fs.renameSync(target, held);
        if (process.env.RACE_USE_SYMLINK === "true") fs.symlinkSync(external, target, "file");
        else fs.renameSync(replacement, target);
        swapped = true;
      };
      archiver.Archiver.prototype._updateQueueTaskWithStats = function replaceAfterLegacyArchiveStat(task, stats) {
        const updated = originalUpdateQueueTaskWithStats.call(this, task, stats);
        if (updated && typeof updated.filepath === "string" && path.resolve(updated.filepath) === path.resolve(target)) replacePath();
        return updated;
      };
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      fs.openSync = function replaceBeforeDescriptorOpen(filePath, ...args) {
        if (typeof filePath === "string" && path.resolve(filePath) === path.resolve(target)) replacePath();
        return originalOpenSync.call(fs, filePath, ...args);
      };
      (async () => {
        let failure = null;
        try {
          await backupService.createBackup({ createdBy: "fixture" });
        } catch (error) {
          failure = error;
        }
        assert.equal(swapped, true, "the fixture should replace the collected pathname");
        assert.ok(failure, "backup must reject a source that changes after collection");
        assert.match(String(failure.code || "") + " " + String(failure.message || ""), /Backup source|symbolic link|symlink|ELOOP|aliased/i);
        console.log(JSON.stringify({ ok: true, swapped }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, EXTERNAL_SECRET_PATH: secretPath, RACE_REPLACEMENT_PATH: replacementPath, RACE_USE_SYMLINK: String(useSymlink), DB_ENABLED: "false", BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const outcome = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
    assert.equal(outcome.ok, true);
    assert.equal(outcome.swapped, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(external, { recursive: true, force: true });
  }
});

test("quarantine backups exclude external payloads reached through upload aliases", { timeout: 30_000 }, (t) => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-alias-runtime-"));
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-alias-payloads-"));
  try {
    const uploadsDir = path.join(runtime, "uploads");
    const aliasPath = path.join(uploadsDir, ".quarantine-alias");
    fs.mkdirSync(uploadsDir, { recursive: true });
    try {
      fs.symlinkSync(quarantineDir, aliasPath, process.platform === "win32" ? "junction" : "dir");
    } catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error.code)) {
        t.skip("directory symlink/junction creation is unavailable");
        return;
      }
      throw error;
    }
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const unzipper = require(${JSON.stringify(path.join(ROOT, "node_modules", "unzipper"))});
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const uploadsDir = path.join(process.cwd(), "uploads");
      const quarantineDir = process.env.UPLOAD_QUARANTINE_DIR;
      const quarantineParentDir = path.dirname(quarantineDir);
      const secretName = "quarantined-secret-7f3a.env.local";
      const safeName = "safe-quarantine-item.bin";
      fs.writeFileSync(path.join(quarantineParentDir, "external-neighbor.txt"), "unrelated external file");
      fs.writeFileSync(path.join(uploadsDir, "ordinary.txt"), "ordinary upload");
      fs.mkdirSync(quarantineDir, { recursive: true });
      fs.writeFileSync(path.join(quarantineDir, secretName), "sensitive quarantined bytes");
      fs.writeFileSync(path.join(quarantineDir, safeName), "safe quarantined bytes");
      fs.mkdirSync(path.join(process.cwd(), "data"), { recursive: true });
      fs.writeFileSync(path.join(process.cwd(), "data", "quarantine.json"), JSON.stringify({ items: [
        { id: "sensitive", storedQuarantineFilename: secretName, originalFilename: ".env.local" },
        { id: "safe", storedQuarantineFilename: safeName, originalFilename: "document.bin" },
      ] }));
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        const zip = await unzipper.Open.file(backupService.getArchivePath(backup.filename));
        const entries = zip.files.map((entry) => entry.path);
        assert.ok(entries.includes("uploads/ordinary.txt"));
        assert.equal(entries.includes("uploads/.quarantine-alias/" + secretName), false);
        assert.equal(entries.includes("uploads/.quarantine-alias/" + safeName), false);
        assert.equal(entries.includes("uploads/.quarantine-alias/external-neighbor.txt"), false);
        assert.ok(entries.includes("data/quarantine/" + safeName));
        assert.equal(entries.includes("data/quarantine/" + secretName), false);
        const archivedMetadata = JSON.parse((await zip.files.find((entry) => entry.path === "data/quarantine.json").buffer()).toString("utf8"));
        assert.deepEqual(archivedMetadata.items, [{ id: "safe", storedQuarantineFilename: safeName, originalFilename: "document.bin" }]);
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "false", UPLOAD_QUARANTINE_DIR: path.join(quarantineDir, "private"), BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "true", BACKUP_RETENTION_COUNT: "20" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(quarantineDir, { recursive: true, force: true });
  }
});

test("quarantine restore keeps metadata renames on the data volume", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-volume-runtime-"));
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-volume-payloads-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const metadataPath = path.join(process.cwd(), "data", "quarantine.json");
      const archivePayloadPath = path.join(process.env.UPLOAD_QUARANTINE_DIR, "archive.bin");
      const currentPayloadPath = path.join(process.env.UPLOAD_QUARANTINE_DIR, "current.bin");
      fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
      fs.mkdirSync(process.env.UPLOAD_QUARANTINE_DIR, { recursive: true });
      fs.writeFileSync(metadataPath, JSON.stringify({ items: [{ id: "archive", storedQuarantineFilename: "archive.bin" }] }));
      fs.writeFileSync(archivePayloadPath, "archived-payload");
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        fs.writeFileSync(metadataPath, JSON.stringify({ items: [{ id: "current", storedQuarantineFilename: "current.bin" }] }));
        fs.rmSync(archivePayloadPath);
        fs.writeFileSync(currentPayloadPath, "current-payload");
        const nativeRename = fs.renameSync;
        const metadata = path.resolve(metadataPath);
        const quarantineRoot = path.resolve(process.env.UPLOAD_QUARANTINE_DIR);
        const isWithinQuarantine = (candidate) => {
          const relative = path.relative(quarantineRoot, path.resolve(String(candidate)));
          return relative === "" || (relative !== ".." && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative));
        };
        fs.renameSync = function rejectCrossVolumeMetadataRename(source, destination, ...args) {
          if ((path.resolve(String(source)) === metadata && isWithinQuarantine(destination))
            || (path.resolve(String(destination)) === metadata && isWithinQuarantine(source))) {
            const error = new Error("simulated cross-volume metadata rename");
            error.code = "EXDEV";
            throw error;
          }
          return nativeRename.call(this, source, destination, ...args);
        };
        try {
          await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" });
        } finally {
          fs.renameSync = nativeRename;
        }
        assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), { items: [{ id: "archive", storedQuarantineFilename: "archive.bin" }] });
        assert.equal(fs.readFileSync(archivePayloadPath, "utf8"), "archived-payload");
        assert.equal(fs.existsSync(currentPayloadPath), false);
        assert.equal(restoreService.hasPendingQuarantineRestore(), false);
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

test("quarantine backup filters case-aliased metadata on Windows", { skip: process.platform !== "win32", timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-case-backup-runtime-"));
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-quarantine-case-backup-payloads-"));
  try {
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const path = require("node:path");
      const unzipper = require(${JSON.stringify(path.join(ROOT, "node_modules", "unzipper"))});
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const metadataPath = path.join(process.cwd(), "data", "Quarantine.json");
      fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
      fs.mkdirSync(process.env.UPLOAD_QUARANTINE_DIR, { recursive: true });
      const metadata = { items: [
        { id: "sensitive-entry", storedQuarantineFilename: "private-key.pem", originalFilename: "private-key.pem" },
        { id: "safe-entry", storedQuarantineFilename: "safe.bin", originalFilename: "safe.bin" },
      ] };
      fs.writeFileSync(metadataPath, JSON.stringify(metadata));
      fs.writeFileSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "private-key.pem"), "sensitive quarantine payload");
      fs.writeFileSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "safe.bin"), "safe quarantine payload");
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        const zip = await unzipper.Open.file(backupService.getArchivePath(backup.filename));
        const metadataEntries = zip.files.filter((entry) => entry.path.toLowerCase() === "data/quarantine.json");
        assert.deepEqual(metadataEntries.map((entry) => entry.path), ["data/quarantine.json"]);
        const archivedMetadata = JSON.parse((await metadataEntries[0].buffer()).toString("utf8"));
        assert.deepEqual(archivedMetadata.items, [metadata.items[1]]);
        assert.equal(zip.files.some((entry) => entry.path.toLowerCase() === "data/quarantine/private-key.pem"), false);
        fs.rmSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "safe.bin"));
        fs.writeFileSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "current.bin"), "current payload");
        fs.writeFileSync(metadataPath, JSON.stringify({ items: [{ id: "current-entry", storedQuarantineFilename: "current.bin", originalFilename: "current.bin" }] }));
        await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "fixture" });
        assert.deepEqual(fs.readFileSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "safe.bin")), Buffer.from("safe quarantine payload"));
        assert.deepEqual(JSON.parse(fs.readFileSync(path.join(process.cwd(), "data", "quarantine.json"), "utf8")), { items: [metadata.items[1]] });
        assert.equal(fs.existsSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "current.bin")), false);
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
            const isOldMetadata = from === metadataPath && path.dirname(to) === path.dirname(metadataPath)
              && /^\.rootark-quarantine-restore-metadata-[a-f0-9-]{36}-old\.tmp$/i.test(path.basename(to));
            const isNewMetadata = to === metadataPath && path.dirname(from) === path.dirname(metadataPath)
              && /^\.rootark-quarantine-restore-metadata-[a-f0-9-]{36}-new\.tmp$/i.test(path.basename(from));
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
        assert.equal(fs.readdirSync(path.dirname(metadataPath)).some((name) => /^\.rootark-quarantine-restore-metadata-[a-f0-9-]{36}-(?:old|new)\.tmp$/i.test(name)), false);
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
