const fs = require("fs");
const path = require("path");

function getUploadQuarantineDir() {
  return path.resolve(process.env.UPLOAD_QUARANTINE_DIR || "./data/quarantine");
}

function pathVariants(value) {
  const resolved = path.resolve(value);
  const variants = new Map([[process.platform === "win32" ? resolved.toLowerCase() : resolved, resolved]]);
  try {
    const real = fs.realpathSync.native ? fs.realpathSync.native(resolved) : fs.realpathSync(resolved);
    const key = process.platform === "win32" ? real.toLowerCase() : real;
    if (!variants.has(key)) variants.set(key, real);
  } catch {}
  return [...variants.values()];
}

function isPathWithin(basePath, targetPath) {
  const base = path.resolve(basePath);
  const target = path.resolve(targetPath);
  const comparableBase = process.platform === "win32" ? base.toLowerCase() : base;
  const comparableTarget = process.platform === "win32" ? target.toLowerCase() : target;
  const relative = path.relative(comparableBase, comparableTarget);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function quarantineDirContainsUploads(uploadsDir, quarantineDir) {
  return pathVariants(quarantineDir).some((quarantinePath) => pathVariants(uploadsDir).some((uploadsPath) => isPathWithin(quarantinePath, uploadsPath)));
}

function isSensitiveQuarantineItem(item) {
  const sensitiveName = (value) => {
    if (typeof value !== "string" || !value) return false;
    const base = value.replace(/\\/g, "/").split("/").at(-1).toLowerCase();
    return base === ".env" || base.startsWith(".env.") || base.endsWith(".env") || base.includes("credentials") || base.includes("service-account")
      || base.endsWith(".key") || base.endsWith(".pem") || base.endsWith(".p12") || base === "server-master.key";
  };
  return sensitiveName(item?.storedQuarantineFilename) || sensitiveName(item?.originalFilename);
}

function readQuarantineRegularFile(filePath, encoding) {
  let descriptor;
  try {
    const noFollow = fs.constants.O_NOFOLLOW || 0;
    try { descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow); }
    catch (error) {
      if (error.code === "ENOENT") {
        try {
          const pathStat = fs.lstatSync(filePath);
          if (pathStat.isSymbolicLink()) {
            const invalid = new Error("Quarantine file is not a regular file");
            invalid.code = "QUARANTINE_NOT_REGULAR";
            throw invalid;
          }
        } catch (pathError) {
          if (pathError.code !== "ENOENT") throw pathError;
        }
      }
      throw error;
    }
    const descriptorStat = fs.fstatSync(descriptor);
    let pathStat;
    try { pathStat = fs.lstatSync(filePath); }
    catch (error) {
      if (error.code !== "ENOENT") throw error;
      const changed = new Error("Quarantine file changed while it was being opened");
      changed.code = "QUARANTINE_PATH_CHANGED";
      throw changed;
    }
    if (!descriptorStat.isFile() || !pathStat.isFile() || pathStat.isSymbolicLink()
      || descriptorStat.dev !== pathStat.dev || descriptorStat.ino !== pathStat.ino) {
      const error = new Error("Quarantine file is not a regular file");
      error.code = "QUARANTINE_NOT_REGULAR";
      throw error;
    }
    return fs.readFileSync(descriptor, encoding);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readQuarantineMetadata(metadataPath) {
  let contents;
  try {
    contents = readQuarantineRegularFile(metadataPath, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return null;
    if (error.code === "QUARANTINE_NOT_REGULAR") throw new Error("Quarantine metadata is not a regular file");
    throw new Error("Quarantine metadata is invalid");
  }

  let metadata;
  try {
    metadata = JSON.parse(contents);
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

module.exports = { getUploadQuarantineDir, isSensitiveQuarantineItem, quarantineDirContainsUploads, readQuarantineMetadata, readQuarantineRegularFile, validateQuarantinePayloads };
