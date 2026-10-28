"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { cleanupRetention, deleteBackup, recoverRetentionTombstones,
  BACKUPS_DIR, RETENTION_TRANSACTIONS_DIR, setCloudStorage } = require("../../services/backupService");
const repository = require("../../repositories/backupRepository");

async function main() {
  fs.mkdirSync(BACKUPS_DIR, { recursive: true });
  const ids = [crypto.randomUUID(), crypto.randomUUID()];
  const filenames = [
    "rootark-backup-2026-10-28-19-20-01.zip",
    "rootark-backup-2026-10-28-19-20-02.zip",
  ];
  const sentinels = ["STRICT_OLD_ARCHIVE_CONTENT", "STRICT_NEW_ARCHIVE_CONTENT"];
  for (let i = 0; i < 2; i++) {
    fs.writeFileSync(path.join(BACKUPS_DIR, filenames[i]), sentinels[i]);
    repository.saveBackup({
      id: ids[i], filename: filenames[i], status: "success", type: "automatic",
      createdAt: new Date(Date.now() - (i === 0 ? 20000 : 0)).toISOString(),
      metadata: {},
    });
  }
  if (process.argv[2] === "tombstone") {
    const orphan = path.join(BACKUPS_DIR,
      "rootark-backup-2020-01-01-00-00-00.zip.retention-tombstone");
    const marker = "UNRECOVERED_HISTORICAL_OWNER_BYTES";
    fs.writeFileSync(orphan, marker);
    fs.writeFileSync(`${orphan}.json`, JSON.stringify({ backupId: crypto.randomUUID(),
      filename: "rootark-backup-2020-01-01-00-00-00.zip", checksum: null }));
    let outcome;
    try { recoverRetentionTombstones(); outcome = { allowed: true, code: null }; }
    catch (error) { outcome = { allowed: false, code: error.code || null }; }
    console.log(JSON.stringify({ ...outcome,
      orphanPreserved: fs.existsSync(orphan) && fs.readFileSync(orphan, "utf8") === marker,
      metadataPreserved: fs.existsSync(`${orphan}.json`) }));
    return;
  }
  if (process.argv[2] === "flip") {
    setCloudStorage({ enabled: () => false, resolveInventoryContext: async () => {
      process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "1";
    } });
  }
  if (["hashflip", "deletehashflip"].includes(process.argv[2])) {
    const originalCreateReadStream = fs.createReadStream;
    fs.createReadStream = function flipAtRealArchiveHashEnd(...args) {
      const stream = originalCreateReadStream.apply(this, args);
      stream.once("end", () => { process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "1"; });
      return stream;
    };
  }
  let outcome;
  try {
    if (process.argv[2] === "deletehashflip") await deleteBackup(ids[0]);
    else await cleanupRetention();
    outcome = { allowed: true, code: null };
  } catch (error) {
    outcome = { allowed: false, code: error.code || null };
  }
  console.log(JSON.stringify({ ...outcome,
    survivingArchives: filenames.map((name) => fs.existsSync(path.join(BACKUPS_DIR, name))),
    survivingRecords: ids.map((id) => Boolean(repository.getBackup(id))),
    originalContents: filenames.map((name, i) =>
      fs.existsSync(path.join(BACKUPS_DIR, name)) &&
      fs.readFileSync(path.join(BACKUPS_DIR, name), "utf8") === sentinels[i]),
    retentionJournalCount: fs.existsSync(RETENTION_TRANSACTIONS_DIR)
      ? fs.readdirSync(RETENTION_TRANSACTIONS_DIR).length : 0,
  }));
}

main().catch((error) => { console.error(error.code || error.message); process.exitCode = 1; });
