"use strict";

// The unsigned co-located registry cannot serve as revocation authority when
// other local principals can replace its directory, JSON, lock, or rename
// staging files. Never chmod/rewrite ACLs on the user's existing data store.
const fs = require("node:fs");
const path = require("node:path");
const { verifyWindowsChunkUploadTree } =
  require("../../services/chunkUploadWindowsAcl");

function denied() {
  return Object.assign(new Error("Atomic sync registry requires a separately protected storage directory"), {
    code: "SYNC_ATOMIC_REGISTRY_STORAGE_UNSAFE",
  });
}

function assertPosixPrivate(directory, filename) {
  const uid = process.getuid?.();
  if (!Number.isSafeInteger(uid)) throw denied();
  let current = directory;
  while (true) {
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw denied();
    if (current === directory) {
      if (stat.uid !== uid || (stat.mode & 0o777) !== 0o700) throw denied();
    } else {
      // chmod(0755) only removes group/other writes; it does NOT prevent
      // the directory's owner from renaming this subtree or chmod-ing its
      // parent writable again. Only our own UID or privileged root is an
      // acceptable ancestor owner. Root-owned sticky /tmp is the sole
      // intentional exception to the group/other writable rule.
      if (stat.uid !== uid && stat.uid !== 0) throw denied();
      if ((stat.mode & 0o022) !== 0
        && !((stat.mode & 0o1000) !== 0 && stat.uid === 0)) {
        throw denied();
      }
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  for (const entry of fs.readdirSync(directory)) {
    if (entry !== filename && entry !== filename + ".writer-lock"
      && !entry.startsWith(filename + ".tmp-")) continue;
    const stat = fs.lstatSync(path.join(directory, entry));
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
      || stat.uid !== uid || (stat.mode & 0o777) !== 0o600) throw denied();
  }
}

function assertAtomicRegistryStoragePermissions(filePath) {
  try {
    if (typeof filePath !== "string" || !path.isAbsolute(filePath)) throw denied();
    const directory = path.dirname(filePath);
    if (process.platform === "win32") {
      // C# native ACL checks require protected root DACL and trusted owner,
      // reject unsafe writable ancestors, reparse points, broad ACEs and
      // every existing descendant (including .writer-lock and .tmp files).
      verifyWindowsChunkUploadTree(directory);
    } else {
      assertPosixPrivate(directory, path.basename(filePath));
    }
    return true;
  } catch (_) { throw denied(); }
}

module.exports = { assertAtomicRegistryStoragePermissions };
