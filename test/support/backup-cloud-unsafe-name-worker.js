"use strict";

// An unsafe cloud name is data for the backup service, never generated code.
const fs = require("node:fs");
const path = require("node:path");
const servicePath = process.env.ROOTARK_TEST_BACKUP_SERVICE;
if (!servicePath || !path.isAbsolute(servicePath)
  || !Object.hasOwn(process.env, "ROOTARK_TEST_CLOUD_NAME")) {
  throw Error("INVALID_CLOUD_NAME_TEST_FIXTURE");
}
process.env.DB_ENABLED = "false";
const service = require(servicePath);
service.setCloudStorage({ enabled: () => true,
  inventory: async () => [{ provider: "s3", providerIdentity: "bad",
    area: "uploads", folderId: "root", name: process.env.ROOTARK_TEST_CLOUD_NAME }],
  download: async () => true });
service.createBackup().then(() => { process.exitCode = 2; }).catch(() => {
  const backups = path.join(process.cwd(), "data", "backups");
  const files = fs.existsSync(backups)
    ? fs.readdirSync(backups).filter((file) => file.endsWith(".zip")) : [];
  process.exitCode = files.length ? 3 : 0;
});
