"use strict";

// Disposable second same-SID OS process. Wait for native publication's
// retained-directory rendezvous, then atomically create and fsync B.
// This actor supplies no custody, signer trust or production authority.
const fs = require("node:fs");
const path = require("node:path");

const scratch = process.argv[2];
if (!scratch || !path.win32.isAbsolute(scratch)) process.exit(31);
const ready = path.join(scratch, "publisher-ready.signal");
const foreign = path.join(scratch, "held", "published.bin");
const ack = path.join(scratch, "writer-ack.signal");
const complete = path.join(scratch, "postattack-ready.signal");
const sleep = new Int32Array(new SharedArrayBuffer(4));
const deadline = Date.now() + 12000;
while (!fs.existsSync(ready) && Date.now() < deadline) {
  Atomics.wait(sleep, 0, 0, 10);
}
if (!fs.existsSync(ready) ||
    fs.readFileSync(ready, "utf8") !== "PUBLISHER_READY_V1") process.exit(32);

let handle;
try {
  handle = fs.openSync(foreign, "wx");
  fs.writeSync(handle, Buffer.from("FOREIGN_UNTRUSTED_TARGET_BYTES"));
  fs.fsyncSync(handle);
  const marker = fs.openSync(ack, "wx");
  try {
    fs.writeSync(marker, "WRITER_READY_V1");
    fs.fsyncSync(marker);
  } finally { fs.closeSync(marker); }
  // Keep the foreign descriptor live UNTIL the publisher proves the native
  // NtSetInformationFile collision completed. A fixed sleep is not a race
  // oracle under heavy Windows load.
  const completionDeadline = Date.now() + 12000;
  while (!fs.existsSync(complete) && Date.now() < completionDeadline) {
    Atomics.wait(sleep, 0, 0, 10);
  }
  if (!fs.existsSync(complete) ||
      fs.readFileSync(complete, "utf8") !== "COLLISION_COMPLETE_V1") {
    process.exitCode = 34;
  }
} catch {
  process.exitCode = 33;
} finally {
  if (handle !== undefined) fs.closeSync(handle);
}
