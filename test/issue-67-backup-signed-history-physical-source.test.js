"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

if (process.env.ROOTARK_SIGNED_HISTORY_ZIP_CHILD === "1") {
  const crypto = require("node:crypto");
  const { SyncObjectStore } = require("../src/routes/sync");
  const protocol = require("../sync-client/rootark-sync-protocol");
  const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
  const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
  const backup = require("../services/backupService");
  const repository = require("../repositories/backupRepository");
  const unzipper = require("unzipper");
  const mode = process.env.ROOTARK_SIGNED_HISTORY_ZIP_MODE;
  const root = process.cwd();
  const dataDir = path.join(root, "data");
  const canonical = path.join(dataDir, "sync-objects.json");
  const uppercase = path.join(dataDir, "SYNC-OBJECTS.JSON");
  const external = path.join(root, "external-history.json");
  (async () => {
    if (process.platform === "win32") ensureWindowsChunkUploadRoot(dataDir);
    else fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dataDir, "settings.json"), "{}");
    const storePath = mode === "external" ? external : canonical;
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    const owner = publicKey.export({ format: "der", type: "spki" }).toString("base64url");
    const secret = crypto.randomBytes(32);
    const store = await new SyncObjectStore(storePath, { atomicDeviceRegistry: true }).open();
    await store.enrollDevice({ username: "alice", deviceId: "device-a", publicKey: owner, expectedEpoch: 0 });
    for (const objectId of ["alpha", "beta"]) {
      let previous = null;
      for (const counter of [1, 2]) {
        const operation = protocol.createOperation({
          operation: previous ? "update" : "create", objectId, fileId: objectId,
          versionId: `${objectId}-${counter}`, operationId: `${objectId}-op-${counter}`,
          deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", fileKey: secret,
          revision: { counter, deviceId: "device-a" },
          baseRevision: previous?.revision || null,
          metadata: { path: `${objectId}.txt`, name: `${objectId}.txt` },
          plaintext: Buffer.from(`${objectId}: signed revision ${counter}`),
        });
        const signed = { ...operation, authorization: await createAuthorizationProof(operation, {
          username: "alice", privateKey, publicKey: owner,
        }) };
        assert.equal((await store.put("alice", signed)).kind, "stored");
        previous = signed;
      }
      assert.equal(store.history("alice", objectId).length, 2);
    }
    // Snapshot signed-history counts before a physical case-only rename: the
    // store intentionally resolves the original pathname on each subsequent
    // history() call, which is absent on POSIX after rename.
    const versions = [store.history("alice", "alpha").length,
      store.history("alice", "beta").length];
    const original = fs.readFileSync(storePath);
    if (mode === "physical-uppercase") {
      fs.renameSync(canonical, uppercase);
      delete process.env.SYNC_OBJECTS_FILE;
    } else if (mode === "config-uppercase") {
      process.env.SYNC_OBJECTS_FILE = uppercase;
    } else if (mode === "external") {
      process.env.SYNC_OBJECTS_FILE = external;
    } else if (mode === "canonical") {
      process.env.SYNC_OBJECTS_FILE = canonical;
    } else throw Error("Unknown signed ZIP scenario");
    backup.setCloudStorage({ enabled: () => false });
    let created = null, error = null, entries = [], archivedEqual = false;
    try {
      created = await backup.createBackup({ createdBy: "signed-history-fixture" });
      const zip = await unzipper.Open.file(path.join(dataDir, "backups", created.filename));
      entries = zip.files.map((item) => item.path);
      const history = zip.files.find((item) => item.path === "data/sync-objects.json");
      archivedEqual = Boolean(history) && (await history.buffer()).equals(original);
    } catch (failure) { error = failure.message; }
    const backupDir = path.join(dataDir, "backups");
    const archives = fs.existsSync(backupDir)
      ? fs.readdirSync(backupDir).filter((name) => name.endsWith(".zip")) : [];
    console.log(JSON.stringify({ ok: Boolean(created), error, entries, archivedEqual,
      archives, success: repository.listBackups().filter((item) => item.status === "success").length,
      failed: repository.listBackups().filter((item) => item.status === "failed").length,
      physical: fs.readdirSync(dataDir).filter((name) => name.toLowerCase() === "sync-objects.json"),
      versions,
    }));
  })().catch((error) => { console.error(error.stack || error); process.exitCode = 1; });
} else {
  function runFixture(mode) {
    const runtime = createPrivateAuthorityFixture("rootark-history-zip-");
    const environment = {
      ...Object.fromEntries(Object.entries(process.env).filter(([key]) =>
        !/^(AWS_|GOOGLE_|CLOUD_STORAGE_|S3_|GDRIVE_|DRIVE_|ZK10_|SYNC_OBJECTS_FILE)/i.test(key))),
      NODE_ENV: "test", DB_ENABLED: "false", BACKUP_ENABLED: "true",
      BACKUP_INCLUDE_UPLOADS: "true", BACKUP_INCLUDE_TEMP: "false",
      BACKUP_RETENTION_COUNT: "10", UPLOAD_QUARANTINE_DIR: path.join(runtime, "quarantine"),
      ROOTARK_SIGNED_HISTORY_ZIP_CHILD: "1", ROOTARK_SIGNED_HISTORY_ZIP_MODE: mode,
    };
    try {
      const child = spawnSync(process.execPath, [__filename], {
        cwd: runtime, env: environment, encoding: "utf8", windowsHide: true, timeout: 60000,
      });
      assert.equal(child.status, 0, child.stderr || child.error?.message || child.stdout);
      return JSON.parse(child.stdout.trim().split(/\r?\n/).at(-1));
    } finally { fs.rmSync(runtime, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); }
  }
  test("whole-account ZIP preserves both signed revisions of two canonical objects byte-for-byte", () => {
    const result = runFixture("canonical");
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(result.versions, [2, 2]);
    assert.equal(result.archivedEqual, true);
    assert.equal(result.entries.filter((name) => name === "data/sync-objects.json").length, 1);
    assert.equal(result.archives.length, 1);
    assert.equal(result.success, 1);
  });
  for (const mode of ["physical-uppercase", "config-uppercase", "external"]) {
    test(`signed whole-account ZIP refuses unarchived signed history: ${mode}`, () => {
      const result = runFixture(mode);
      assert.deepEqual(result.versions, [2, 2]);
      assert.equal(result.ok, false, JSON.stringify(result));
      assert.match(result.error, /signed.*history|sync.*history|canonical|archive/i);
      assert.deepEqual(result.archives, []);
      assert.equal(result.success, 0);
      assert.equal(result.failed, 1);
    });
  }
}
