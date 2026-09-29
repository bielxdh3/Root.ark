const fs = require("fs");
const path = require("path");

function getUploadQuarantineDir() {
  return path.resolve(process.env.UPLOAD_QUARANTINE_DIR || "./data/quarantine");
}

function isSensitiveQuarantineItem(item) {
  const sensitiveName = (value) => {
    if (typeof value !== "string" || !value) return false;
    const base = value.replace(/\\/g, "/").split("/").at(-1).toLowerCase();
    return base === ".env" || base.endsWith(".env") || base.includes("credentials") || base.includes("service-account")
      || base.endsWith(".key") || base.endsWith(".pem") || base.endsWith(".p12") || base === "server-master.key";
  };
  return sensitiveName(item?.storedQuarantineFilename) || sensitiveName(item?.originalFilename);
}

function readQuarantineMetadata(metadataPath) {
  let stat;
  try {
    stat = fs.lstatSync(metadataPath);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  if (!stat.isFile()) throw new Error("Quarantine metadata is not a regular file");

  let metadata;
  try {
    metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  } catch {
    throw new Error("Quarantine metadata is invalid");
  }
  if (!metadata || !Array.isArray(metadata.items)) throw new Error("Quarantine metadata is invalid");
  return metadata;
}

function validateQuarantinePayloads(items, quarantineDir) {
  if (!Array.isArray(items)) throw new Error("Quarantine metadata is invalid");
  const filenames = new Set();
  const payloads = [];
  for (const item of items) {
    const filename = item?.storedQuarantineFilename;
    if (typeof filename !== "string" || !filename || filename === "." || filename === ".." || filename.includes("/") || filename.includes("\\") || path.basename(filename) !== filename || /[<>:"|?*\u0000-\u001f]/.test(filename) || /[. ]$/.test(filename) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(filename)) {
      throw new Error("Quarantine payload filename is invalid");
    }
    const filenameKey = filename.toLowerCase();
    if (filenames.has(filenameKey)) throw new Error("Quarantine payload filename is duplicated");
    filenames.add(filenameKey);

    const absolutePath = path.join(quarantineDir, filename);
    let stat;
    try {
      stat = fs.lstatSync(absolutePath);
    } catch (error) {
      if (error.code === "ENOENT") throw new Error("Quarantine payload is missing");
      throw error;
    }
    if (!stat.isFile()) throw new Error("Quarantine payload is not a regular file");
    payloads.push({ absolutePath, filename, size: stat.size });
  }
  return payloads;
}

module.exports = { getUploadQuarantineDir, isSensitiveQuarantineItem, readQuarantineMetadata, validateQuarantinePayloads };
