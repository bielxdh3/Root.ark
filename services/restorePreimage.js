const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const LEGACY_FORMAT_VERSION = 1;
const FORMAT_VERSION = 2;
const FILE_MODE = 0o600;
const DIR_MODE = 0o700;
const COPY_BUFFER_SIZE = 1024 * 1024;

function hashFile(pathname) {
  const digest = crypto.createHash("sha256");
  const buffer = Buffer.allocUnsafe(COPY_BUFFER_SIZE);
  const fd = fs.openSync(pathname, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    const before = fs.lstatSync(pathname, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
      throw new Error("Restore pre-image file is aliased or invalid");
    }
    if (!identityMatches(before, opened)) throw new Error("Restore pre-image file changed while opening");
    let read;
    while ((read = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) digest.update(buffer.subarray(0, read));
    const after = fs.fstatSync(fd, { bigint: true });
    if (!identityMatches(opened, after)) throw new Error("Restore pre-image file changed while hashing");
  } finally { fs.closeSync(fd); }
  return digest.digest("hex");
}

function ensureSafeDirectory(pathname, { create = false } = {}) {
  const resolved = path.resolve(pathname);
  const root = path.parse(resolved).root;
  let current = root;
  for (const segment of path.relative(root, resolved).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    try {
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error("Restore pre-image path contains an unsafe directory");
    } catch (error) {
      if (error.code !== "ENOENT" || !create) throw error;
      fs.mkdirSync(current, { mode: DIR_MODE });
    }
  }
  return resolved;
}

function safeRelativePath(relative) {
  if (typeof relative !== "string" || !relative || path.isAbsolute(relative) || relative.includes("\\") || relative.split("/").some((part) => !part || part === "." || part === ".." || part.includes(":"))) {
    throw new Error("Restore pre-image contains an unsafe relative path");
  }
  return relative;
}

function identityMatches(before, after) {
  return before.dev === after.dev && before.ino === after.ino
    && before.size === after.size && before.mtimeNs === after.mtimeNs
    && before.ctimeNs === after.ctimeNs && before.nlink === after.nlink;
}

function copyVerifiedFile(source, destination, expectedHash = null) {
  const sourceFd = fs.openSync(source, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  let outputFd;
  let destinationCreated = false;
  const digest = crypto.createHash("sha256");
  const buffer = Buffer.allocUnsafe(COPY_BUFFER_SIZE);
  try {
    const opened = fs.fstatSync(sourceFd, { bigint: true });
    const before = fs.lstatSync(source, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) throw new Error("Restore pre-image source is aliased or invalid");
    if (!opened.isFile() || opened.nlink !== 1n || !identityMatches(before, opened)) throw new Error("Restore pre-image source changed while opening");
    outputFd = fs.openSync(destination, "wx", FILE_MODE);
    destinationCreated = true;
    let position = 0;
    let read;
    while ((read = fs.readSync(sourceFd, buffer, 0, buffer.length, position)) > 0) {
      const chunk = buffer.subarray(0, read);
      digest.update(chunk);
      let written = 0;
      while (written < read) written += fs.writeSync(outputFd, chunk, written, read - written);
      position += read;
    }
    const copiedHash = digest.digest("hex");
    const finalSource = fs.fstatSync(sourceFd, { bigint: true });
    if (!identityMatches(opened, finalSource) || (expectedHash && copiedHash !== expectedHash)) throw new Error("Restore pre-image source changed or failed integrity verification");
    fs.fsyncSync(outputFd);
    return { sha256: copiedHash, size: Number(finalSource.size), mode: Number(finalSource.mode & 0o777n) };
  } catch (error) {
    if (destinationCreated) fs.rmSync(destination, { force: true });
    throw error;
  } finally {
    if (outputFd !== undefined) fs.closeSync(outputFd);
    fs.closeSync(sourceFd);
  }
}

function walkTree(root, excludedPath = null) {
  const rootStat = fs.lstatSync(root);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) throw new Error("Restore pre-image tree root is unsafe");
  const entries = [];
  const excluded = excludedPath ? path.resolve(excludedPath) : null;
  const excludedReal = excluded && fs.existsSync(excluded) ? fs.realpathSync(excluded) : null;
  const visit = (directory, relative = "") => {
    for (const name of fs.readdirSync(directory)) {
      const absolute = path.join(directory, name);
      const childRelative = relative ? `${relative}/${name}` : name;
      const stat = fs.lstatSync(absolute, { bigint: true });
      if (stat.isSymbolicLink()) throw new Error("Restore pre-image tree contains a symbolic link");
      if (excluded && (absolute === excluded || absolute.startsWith(`${excluded}${path.sep}`))) continue;
      if (excludedReal) {
        let real;
        try { real = fs.realpathSync(absolute); } catch {}
        if (real && (real === excludedReal || real.startsWith(`${excludedReal}${path.sep}`))) continue;
      }
      if (stat.isDirectory()) {
        entries.push({ path: safeRelativePath(childRelative), type: "directory", mode: Number(stat.mode & 0o777n) });
        visit(absolute, childRelative);
      } else if (stat.isFile()) {
        if (stat.nlink !== 1n) throw new Error("Restore pre-image tree contains a hard-linked file");
        entries.push({ path: safeRelativePath(childRelative), type: "file", size: Number(stat.size), mode: Number(stat.mode & 0o777n), sha256: hashFile(absolute) });
      } else throw new Error("Restore pre-image tree contains an unsupported filesystem entry");
    }
  };
  visit(root);
  return entries.sort((left, right) => left.path.localeCompare(right.path));
}

function snapshotTree(destination, snapshotRoot, excludedPath = null) {
  let rootStat;
  try { rootStat = fs.lstatSync(destination); }
  catch (error) { if (error.code === "ENOENT") return { existed: false, rootMode: null, entries: [] }; throw error; }
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) throw new Error("Restore pre-image destination root is not a safe directory");
  const rootMode = rootStat.mode & 0o777;
  ensureSafeDirectory(snapshotRoot, { create: true });
  const entries = walkTree(destination, excludedPath);
  for (const entry of entries) {
    const stagedPath = path.join(snapshotRoot, ...entry.path.split("/"));
    if (entry.type === "directory") {
      ensureSafeDirectory(stagedPath, { create: true });
      try { fs.chmodSync(stagedPath, entry.mode); } catch (error) { if (process.platform !== "win32") throw error; }
    } else {
      ensureSafeDirectory(path.dirname(stagedPath), { create: true });
      const result = copyVerifiedFile(path.join(destination, ...entry.path.split("/")), stagedPath, entry.sha256);
      if (result.size !== entry.size) throw new Error("Restore pre-image file size changed while staging");
    }
  }
  verifyTree(snapshotRoot, entries);
  return { existed: true, rootMode, entries };
}

function verifyTree(root, entries) {
  const listed = walkTree(root);
  if (listed.length !== entries.length) throw new Error("Restore pre-image staging tree is incomplete");
  const expected = new Map(entries.map((entry) => [entry.path, entry]));
  for (const actual of listed) {
    const prior = expected.get(actual.path);
    if (!prior || prior.type !== actual.type || (prior.type === "file" && (prior.sha256 !== actual.sha256 || prior.size !== actual.size))) {
      throw new Error("Restore pre-image staging tree failed integrity verification");
    }
  }
  return true;
}

function removeTree(pathname) {
  try {
    const stat = fs.lstatSync(pathname);
    if (stat.isSymbolicLink()) throw new Error("Restore pre-image destination became a symbolic link");
    fs.rmSync(pathname, { recursive: true, force: true });
  } catch (error) { if (error.code !== "ENOENT") throw error; }
}

function fileRestoreTemporaryPath(destination, transactionId, index) {
  if (!/^[a-f0-9-]{36}$/i.test(String(transactionId || "")) || !Number.isSafeInteger(index) || index < 0) {
    throw new Error("Restore pre-image temporary identity is invalid");
  }
  return path.resolve(destination) + "." + transactionId + "." + index + ".restore-preimage";
}

function removeFileRestoreTemporary(pathname) {
  let stat;
  try { stat = fs.lstatSync(pathname, { bigint: true }); }
  catch (error) { if (error.code === "ENOENT") return; throw error; }
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1n) throw new Error("Restore pre-image temporary is unsafe");
  fs.unlinkSync(pathname);
}

function syncFile(pathname) {
  const fd = fs.openSync(pathname, "r");
  try {
    try { fs.fsyncSync(fd); }
    catch (error) {
      if (!(process.platform === "win32" && ["EPERM", "ENOTSUP", "EINVAL"].includes(error.code))) throw error;
    }
  } finally { fs.closeSync(fd); }
}

function syncDirectory(directory) {
  if (process.platform === "win32") return false;
  const fd = fs.openSync(directory, "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return true;
}

function syncFileSet(paths) {
  const directories = new Set();
  for (const pathname of paths) {
    let stat;
    try { stat = fs.lstatSync(pathname); }
    catch (error) {
      if (error.code === "ENOENT") throw new Error("Expected restore durability target is missing", { cause: error });
      throw error;
    }
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Restore durability target is not a regular file");
    syncFile(pathname);
    directories.add(path.dirname(pathname));
  }
  for (const directory of directories) syncDirectory(directory);
}

function syncTree(root) {
  let rootStat;
  try { rootStat = fs.lstatSync(root); }
  catch (error) {
    if (error.code !== "ENOENT") throw error;
    syncDirectory(path.dirname(root));
    return;
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error("Restore durability tree is unsafe");
  const directories = [];
  const visit = (directory) => {
    directories.push(directory);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const pathname = path.join(directory, entry.name);
      const stat = fs.lstatSync(pathname);
      if (stat.isSymbolicLink()) throw new Error("Restore durability tree contains a symbolic link");
      if (stat.isDirectory()) visit(pathname);
      else if (stat.isFile()) syncFile(pathname);
      else throw new Error("Restore durability tree contains an unsupported entry");
    }
  };
  visit(root);
  for (const directory of directories.reverse()) syncDirectory(directory);
  syncDirectory(path.dirname(root));
}

function restoreTree(destination, snapshotRoot, snapshot, transactionId, options = {}) {
  if (!snapshot.existed) {
    removeTree(destination);
    syncDirectory(path.dirname(destination));
    return;
  }
  const legacyManifest = options.legacyManifest === true;
  if (!legacyManifest && (!Number.isSafeInteger(snapshot.rootMode) || snapshot.rootMode < 0 || snapshot.rootMode > 0o777)) {
    throw new Error("Restore pre-image tree root mode is invalid");
  }
  verifyTree(snapshotRoot, snapshot.entries);
  ensureSafeDirectory(path.dirname(destination), { create: true });
  removeTree(destination);
  ensureSafeDirectory(destination, { create: true });
  for (let index = 0; index < snapshot.entries.length; index += 1) {
    const entry = snapshot.entries[index];
    safeRelativePath(entry.path);
    const target = path.join(destination, ...entry.path.split("/"));
    const source = path.join(snapshotRoot, ...entry.path.split("/"));
    if (entry.type === "directory") {
      ensureSafeDirectory(target, { create: true });
      try { fs.chmodSync(target, entry.mode); } catch (error) { if (process.platform !== "win32") throw error; }
    } else {
      ensureSafeDirectory(path.dirname(target), { create: true });
      const temporary = fileRestoreTemporaryPath(target, transactionId, index);
      removeFileRestoreTemporary(temporary);
      const result = copyVerifiedFile(source, temporary, entry.sha256);
      if (result.size !== entry.size) throw new Error("Restore pre-image file size changed during recovery");
      try { fs.renameSync(temporary, target); }
      catch (error) { fs.rmSync(target, { force: true }); fs.renameSync(temporary, target); }
      try { fs.chmodSync(target, entry.mode); } catch (error) { if (process.platform !== "win32") throw error; }
    }
  }
  if (!legacyManifest) {
    try { fs.chmodSync(destination, snapshot.rootMode); } catch (error) { if (process.platform !== "win32") throw error; }
  }
  syncTree(destination);
}

function snapshotFileSet(paths, snapshotRoot) {
  ensureSafeDirectory(snapshotRoot, { create: true });
  const files = [];
  for (let index = 0; index < paths.length; index += 1) {
    const destination = path.resolve(paths[index]);
    let stat;
    try { stat = fs.lstatSync(destination, { bigint: true }); }
    catch (error) { if (error.code === "ENOENT") { files.push({ destination, existed: false }); continue; } throw error; }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) throw new Error("Restore pre-image file destination is aliased or invalid");
    const stagedName = String(index);
    const stagedPath = path.join(snapshotRoot, stagedName);
    const originalHash = hashFile(destination);
    const copied = copyVerifiedFile(destination, stagedPath, originalHash);
    if (copied.size !== Number(stat.size)) throw new Error("Restore pre-image file changed while staging");
    files.push({ destination, existed: true, stagedName, ...copied });
  }
  return files;
}

function restoreFileSet(files, snapshotRoot, transactionId) {
  const affectedDirectories = new Set();
  for (let index = 0; index < files.length; index += 1) {
    const entry = files[index];
    const destination = path.resolve(entry.destination);
    ensureSafeDirectory(path.dirname(destination), { create: true });
    affectedDirectories.add(path.dirname(destination));
    const temporary = fileRestoreTemporaryPath(destination, transactionId, index);
    removeFileRestoreTemporary(temporary);
    let current;
    try { current = fs.lstatSync(destination); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    if (current && (current.isSymbolicLink() || !current.isFile())) throw new Error("Restore pre-image file destination became unsafe");
    if (!entry.existed) { if (current) fs.rmSync(destination, { force: true }); continue; }
    safeRelativePath(entry.stagedName);
    const staged = path.join(snapshotRoot, entry.stagedName);
    if (hashFile(staged) !== entry.sha256) throw new Error("Restore pre-image file failed integrity verification");
    const copied = copyVerifiedFile(staged, temporary, entry.sha256);
    if (copied.size !== entry.size) throw new Error("Restore pre-image file size changed during recovery");
    if (current) fs.rmSync(destination, { force: true });
    fs.renameSync(temporary, destination);
    try { fs.chmodSync(destination, entry.mode); } catch (error) { if (process.platform !== "win32") throw error; }
    syncFile(destination);
  }
  for (const directory of affectedDirectories) syncDirectory(directory);
}

function writeManifest(manifestPath, manifest) {
  const contents = `${JSON.stringify(manifest)}\n`;
  const fd = fs.openSync(manifestPath, "wx", FILE_MODE);
  try { fs.writeFileSync(fd, contents); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  return crypto.createHash("sha256").update(contents).digest("hex");
}

function readManifest(manifestPath, expectedHash, transactionId) {
  const contents = fs.readFileSync(manifestPath, "utf8");
  const actualHash = crypto.createHash("sha256").update(contents).digest("hex");
  if (actualHash !== expectedHash) throw new Error("Restore pre-image manifest failed integrity verification");
  const manifest = JSON.parse(contents);
  if (![LEGACY_FORMAT_VERSION, FORMAT_VERSION].includes(manifest.version) || manifest.transactionId !== transactionId || !Array.isArray(manifest.domains)) {
    throw new Error("Restore pre-image manifest is invalid");
  }
  return manifest;
}

module.exports = {
  FORMAT_VERSION,
  LEGACY_FORMAT_VERSION,
  copyVerifiedFile,
  ensureSafeDirectory,
  hashFile,
  readManifest,
  restoreFileSet,
  restoreTree,
  snapshotFileSet,
  snapshotTree,
  syncFileSet,
  syncTree,
  verifyTree,
  writeManifest,
};
