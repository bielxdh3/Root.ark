"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { BACKUPS_DIR, recoverRetentionAtStartup, setCloudStorage } = require("../../services/backupService");

async function main() {
  const cloudStage = path.join(BACKUPS_DIR, ".cloud-stage", crypto.randomUUID());
  const sqliteStage = path.join(process.cwd(), "data", `.sqlite-backup-${crypto.randomUUID()}`);
  fs.mkdirSync(cloudStage, { recursive: true });
  fs.mkdirSync(sqliteStage, { recursive: true });
  const cloudPath = path.join(cloudStage, "original-cloud-bytes.txt");
  const sqlitePath = path.join(sqliteStage, "rootark.sqlite");
  const marker = "OWNER_PRIVATE_INTERRUPTED_BACKUP_BYTES";
  fs.writeFileSync(cloudPath, marker);
  fs.writeFileSync(sqlitePath, marker);
  if (process.argv[2] === "flip") {
    setCloudStorage({ enabled: () => false, resolveInventoryContext: async () => {
      process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "1";
    } });
  }
  let result;
  try { await recoverRetentionAtStartup(); result = { allowed: true, code: null }; }
  catch (error) { result = { allowed: false, code: error.code || null }; }
  console.log(JSON.stringify({ ...result, cloudBytesRetained: fs.existsSync(cloudPath)
    && fs.readFileSync(cloudPath, "utf8") === marker,
  sqliteBytesRetained: fs.existsSync(sqlitePath)
    && fs.readFileSync(sqlitePath, "utf8") === marker }));
}
main().catch((error) => { console.error(error.code || error.message); process.exitCode = 1; });
