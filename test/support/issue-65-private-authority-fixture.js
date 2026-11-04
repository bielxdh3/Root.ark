"use strict";

// Disposable CAS/witness startup fixtures hold private Ed25519 and TLS keys.
// Windows shared TEMP can grant unrelated SIDs Modify or key-read access;
// create the fixture under an independently protected owner-only DACL.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { ensureWindowsChunkUploadRoot } =
  require("../../services/chunkUploadWindowsAcl");

function createPrivateAuthorityFixture(prefix) {
  if (typeof prefix !== "string" || !/^[a-zA-Z0-9-]{1,65}$/.test(prefix)) {
    throw Error("INVALID_AUTHORITY_TEST_FIXTURE");
  }
  if (process.platform !== "win32") {
    return fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()), prefix));
  }
  const local = process.env.LOCALAPPDATA;
  if (typeof local !== "string" || !path.isAbsolute(local)) {
    throw Error("UNTRUSTED_AUTHORITY_TEST_ROOT");
  }
  const directory = path.join(local, prefix + crypto.randomBytes(10).toString("hex"));
  if (fs.existsSync(directory)) throw Error("UNTRUSTED_AUTHORITY_TEST_ROOT");
  ensureWindowsChunkUploadRoot(directory);
  return directory;
}

module.exports = { createPrivateAuthorityFixture };
