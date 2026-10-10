"use strict";

const fs = require("node:fs");
const { createFileLifecycleLock } = require("../../services/fileLifecycleLock");

const mode = process.env.ROOTARK_LOCK_CHILD_MODE;
const directory = process.env.ROOTARK_LOCK_CHILD_DIRECTORY;
const markerPath = process.env.ROOTARK_LOCK_CHILD_MARKER;
if (!directory || !markerPath || !["interrupt-initialization", "hold-published-lock"].includes(mode)) {
  throw new Error("Invalid file lifecycle lock child test configuration");
}

const waitCell = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
function waitForever() {
  while (true) Atomics.wait(waitCell, 0, 0, 1000);
}

const lock = createFileLifecycleLock({ directory, timeoutMs: 5000 });
if (mode === "interrupt-initialization") {
  const originalWriteFileSync = fs.writeFileSync;
  fs.writeFileSync = function (target, data, ...args) {
    if (typeof target === "number" && String(data).includes('"createdAt"')) {
      originalWriteFileSync.call(this, target, '{"token":"partial-before-crash"');
      originalWriteFileSync.call(this, markerPath, "paused");
      waitForever();
    }
    return originalWriteFileSync.call(this, target, data, ...args);
  };
  lock.runFolder("root", async () => {
    throw new Error("interrupted owner must not enter protected work");
  }).catch(() => { process.exitCode = 1; });
} else {
  lock.runFolder("root", async () => {
    fs.writeFileSync(markerPath, String(process.pid));
    waitForever();
  }).catch(() => { process.exitCode = 1; });
}
