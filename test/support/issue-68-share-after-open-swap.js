"use strict";

// Loaded only by the disposable HTTP fixture. Restore the authorized pathname
// *after* the real file opener has verified the foreign descriptor, but before
// the share's beforeSend callback runs. The outgoing fd still reads foreign
// bytes while re-opening the path would read the original, authorized bytes.
const fs = require("node:fs");
const path = require("node:path");
const fileReader = require("../../services/fileReadHandle");

if (process.env.NODE_ENV !== "test") throw new Error("Test-only file swap hook");

const filePath = process.env.ROOTARK_TEST_SHARE_SWAP_FILE;
const savedPath = process.env.ROOTARK_TEST_SHARE_SWAP_SAVED_FILE;
const markerPath = process.env.ROOTARK_TEST_SHARE_SWAP_MARKER;
if (!filePath || !savedPath || !markerPath) throw new Error("Incomplete test swap paths");

const originalOpen = fileReader.openReadHandle;
fileReader.openReadHandle = function openWithAfterFdSwap(candidate) {
  const readHandle = originalOpen(candidate);
  if (path.resolve(candidate) !== path.resolve(filePath) || !fs.existsSync(markerPath)) {
    return readHandle;
  }

  try {
    fs.renameSync(filePath, `${filePath}.untrusted-opened`);
    fs.renameSync(savedPath, filePath);
    fs.unlinkSync(markerPath);
  } catch (error) {
    fs.closeSync(readHandle.fd);
    throw error;
  }
  return readHandle;
};
