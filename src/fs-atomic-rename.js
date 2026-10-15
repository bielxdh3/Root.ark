"use strict";

const fs = require("fs");

const WINDOWS_ATOMIC_RENAME_MAX_ATTEMPTS = 3;
const WINDOWS_ATOMIC_RENAME_RETRY_DELAY_MS = 10;
const renameRetryWait = new Int32Array(new SharedArrayBuffer(4));

function waitForWindowsRenameRetry() {
  Atomics.wait(renameRetryWait, 0, 0, WINDOWS_ATOMIC_RENAME_RETRY_DELAY_MS);
}

function renameSyncWithWindowsEpermRetry(source, destination, options = {}) {
  const platform = options.platform || process.platform;
  const wait = options.wait || waitForWindowsRenameRetry;

  for (let attempt = 1; attempt <= WINDOWS_ATOMIC_RENAME_MAX_ATTEMPTS; attempt += 1) {
    try {
      fs.renameSync(source, destination);
      return;
    } catch (error) {
      // Preserve the existing committed file; never unlink it as a rename fallback.
      if (platform !== "win32" || error.code !== "EPERM" || attempt === WINDOWS_ATOMIC_RENAME_MAX_ATTEMPTS) throw error;
      wait();
    }
  }
}

module.exports = { renameSyncWithWindowsEpermRetry };
