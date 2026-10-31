"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { ensureWindowsChunkUploadRoot } =
  require("../../services/chunkUploadWindowsAcl");

function privateAuthorityDirectory(prefix) {
  if (process.platform !== "win32") {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    fs.chmodSync(dir, 0o700);
    return dir;
  }
  const dir = path.join(process.env.LOCALAPPDATA,
    `${prefix}${crypto.randomBytes(9).toString("hex")}`);
  if (fs.existsSync(dir)) throw Error("AUTHORITY_TEST_DIRECTORY_EXISTS");
  ensureWindowsChunkUploadRoot(dir);
  return dir;
}

function privateAuthorityChild(parent, name) {
  const dir = path.join(parent, name);
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(dir);
  else fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

module.exports = { privateAuthorityDirectory, privateAuthorityChild };
