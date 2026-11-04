"use strict";

// Preload a fixed fault injector so test-controlled paths never become code.
const fs = require("node:fs");
const path = require("node:path");

const target = process.env.ROOTARK_TEST_CLEANUP_BACKUP;
const mode = process.env.ROOTARK_TEST_CLEANUP_FAULT;
if (!target || !path.isAbsolute(target)
  || !["EPERM_ONCE", "EBUSY_ONCE", "EPERM_ALWAYS"].includes(mode)) {
  throw Error("INVALID_CLEANUP_TEST_FAULT");
}
const expected = path.resolve(target);
const nativeRemove = fs.rmSync;
let failed = false;
fs.rmSync = (filename, options) => {
  if (path.resolve(String(filename)) === expected && (!failed || mode === "EPERM_ALWAYS")) {
    failed = true;
    const code = mode.startsWith("EBUSY") ? "EBUSY" : "EPERM";
    throw Object.assign(new Error("fixture cleanup fault"), { code });
  }
  return nativeRemove(filename, options);
};
