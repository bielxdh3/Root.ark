"use strict";

const crypto = require("node:crypto");
// Snapshot the native RNG at module load. A later mutation of the shared
// node:crypto exports must not choose a predictable private staging basename.
const NATIVE_RANDOM_BYTES = crypto.randomBytes;
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { checkWindowsPrivateCloudDirectory } = require("./zk1WindowsPrivateCloudAcl");

// A Windows temporary directory inherited from a shared OS temp root can be
// renamed beneath a pending provider GET. Create a restricted, random staging
// directory under a native-ACL-verified user directory instead. Never repair
// permissive ACLs in place, and never fall back to shared temp on failure.
async function createZk1PrivateCloudStagingDirectory(prefix) {
  if (!/^[a-z0-9-]{1,64}$/.test(prefix)) throw new Error("Invalid cloud staging prefix");
  if (process.platform !== "win32") {
    // TEMP/TMPDIR may resolve through an ordinary OS-managed symlink.
    // Canonicalize only the trusted staging root, BEFORE creating our private
    // 0700 directory. Never canonicalize a caller-controlled upload source:
    // the bounded provider's per-ancestor no-symlink checks stay mandatory.
    const realTempRoot = fs.realpathSync.native(os.tmpdir());
    return fs.mkdtempSync(path.join(realTempRoot, prefix));
  }
  const root = path.join(process.env.LOCALAPPDATA || os.homedir(),
    `${prefix}${NATIVE_RANDOM_BYTES(16).toString("hex")}`);
  await checkWindowsPrivateCloudDirectory(root, "create");
  return root;
}

module.exports = { createZk1PrivateCloudStagingDirectory };
