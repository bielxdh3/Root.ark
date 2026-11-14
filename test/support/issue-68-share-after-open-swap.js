"use strict";

// Loaded only by the disposable HTTP fixture. Restore the authorized pathname
// *after* the real file opener has verified the foreign descriptor, but before
// the share's beforeSend callback runs. The outgoing fd still reads foreign
// bytes while re-opening the path would read the original, authorized bytes.
const fs = require("node:fs");
const path = require("node:path");
const fileReader = require("../../services/fileReadHandle");

const filePath = process.env.ROOTARK_TEST_SHARE_SWAP_FILE;
const savedPath = process.env.ROOTARK_TEST_SHARE_SWAP_SAVED_FILE;
const markerPath = process.env.ROOTARK_TEST_SHARE_SWAP_MARKER;
const foreignFdOnly = process.env.ROOTARK_TEST_SHARE_FOREIGN_FD_ONLY === "1";
const foreignFdPath = process.env.ROOTARK_TEST_SHARE_FOREIGN_FD_PATH;
// Node's full test discovery also loads support/*.js as standalone tests.
// Stay inert without a configured attack; reject partially configured hooks.
if (filePath || savedPath || markerPath) {
  if (process.env.NODE_ENV !== "test") throw new Error("Test-only file swap hook");
  if (!filePath || !savedPath || !markerPath) throw new Error("Incomplete test swap paths");
  if (foreignFdOnly && !foreignFdPath) throw new Error("Missing test-only foreign descriptor path");

  const originalOpen = fileReader.openReadHandle;
  fileReader.openReadHandle = function openWithAfterFdSwap(candidate) {
    const readHandle = originalOpen(candidate);
    if (path.resolve(candidate) !== path.resolve(filePath) || !fs.existsSync(markerPath)) {
      return readHandle;
    }

    try {
      if (foreignFdOnly) {
        // The original path and its inode/ctime remain untouched. Substituting
        // an actual descriptor to a different regular file isolates the
        // final descriptor-bound authorization from pathname generation
        // checks; a pathname-only check would leak the foreign bytes.
        const alternate = fs.openSync(foreignFdPath, "r");
        const stats = fs.fstatSync(alternate);
        fs.closeSync(readHandle.fd);
        fs.unlinkSync(markerPath);
        return { fd: alternate, stats };
      }
      fs.renameSync(filePath, `${filePath}.untrusted-opened`);
      fs.renameSync(savedPath, filePath);
      fs.unlinkSync(markerPath);
    } catch (error) {
      fs.closeSync(readHandle.fd);
      throw error;
    }
    return readHandle;
  };
}
