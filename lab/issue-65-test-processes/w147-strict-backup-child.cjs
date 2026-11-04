"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { createBackup, createZipArchive, getBackupOrThrow } = require("../../services/backupService");
const { scheduleAutomaticBackups } = require("../../services/backupScheduler");
const { restoreBackup, processRestoreSync } = require("../../services/restoreService");

const marker = "W147_DISPOSABLE_LEGACY_PLAINTEXT";
async function attempted(work) {
  try { await work(); return { allowed: true }; }
  catch (error) { return { allowed: false, code: error.code || null }; }
}
async function main() {
  const action = process.argv[2];
  let result;
  if (action === "create") {
    const record = await createBackup({ type: "automatic", createdBy: "system" });
    result = { allowed: true, id: record.id, filename: record.filename };
  } else if (action === "lookup") {
    const { archivePath } = getBackupOrThrow(process.argv[3]);
    result = { allowed: true, archiveExists: fs.existsSync(archivePath) };
  } else if (action === "zip") {
    const target = path.join(process.cwd(), "raw-direct.zip");
    await createZipArchive(target, {}, [{ entryPath: "uploads/root/legacy.txt", contents: Buffer.from(marker) }]);
    result = { allowed: true, archiveExists: fs.existsSync(target) };
  } else if (action === "restore") {
    await restoreBackup(process.argv[3], { confirmation: "RESTORE" });
    result = { allowed: true };
  } else if (action === "restore-sync") {
    await processRestoreSync({ backupId: process.argv[3] });
    result = { allowed: true };
  } else if (action === "schedule") {
    let scheduled = false;
    const task = scheduleAutomaticBackups({
      env: process.env,
      cron: { schedule() { scheduled = true; return { stop() {} }; } },
      createBackup,
    });
    result = { allowed: Boolean(task), scheduled };
  } else if (action === "strict-bundle") {
    const id = process.argv[3];
    const attempts = {};
    attempts.create = await attempted(() => createBackup({ type: "automatic", createdBy: "system" }));
    attempts.zip = await attempted(() => createZipArchive(path.join(process.cwd(), "raw-direct.zip"),
      {}, [{ entryPath: "uploads/root/legacy.txt", contents: Buffer.from(marker) }]));
    attempts.lookup = await attempted(() => Promise.resolve(getBackupOrThrow(id)));
    attempts.restore = await attempted(() => restoreBackup(id, { confirmation: "RESTORE" }));
    attempts.restoreSync = await attempted(() => processRestoreSync({ backupId: id }));
    let scheduled = false;
    const task = scheduleAutomaticBackups({
      env: process.env, cron: { schedule() { scheduled = true; return { stop() {} }; } },
      createBackup,
    });
    result = { attempts, scheduled, allowed: Boolean(task) };
  } else {
    throw new Error("Unknown action");
  }
  console.log(JSON.stringify(result));
}
main().catch((error) => {
  console.log(JSON.stringify({ allowed: false, code: error.code || null, error: error.message }));
}).finally(() => {
  // A child fixture is deliberately a one-shot process, not a background app.
  process.exit(0);
});
