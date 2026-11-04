"use strict";

// Isolated read-only SQLite content verifier. The witness signing key must stay
// in the HTTPS process; this worker returns only a boolean verdict.
const { parentPort, workerData } = require("node:worker_threads");
const crypto = require("node:crypto");
const fs = require("node:fs");
const Database = require("better-sqlite3");

function fail() { throw new Error("WITNESS_CAS_FLOOR_DENIED"); }
function assertFileIdentity() {
  const stat = fs.statSync(workerData.filename, { bigint: true });
  if (!stat.isFile() || stat.dev.toString() !== workerData.fileDev
    || stat.ino.toString() !== workerData.fileIno) fail();
}
function verify() {
  assertFileIdentity();
  const db = new Database(workerData.filename, { readonly: true, fileMustExist: true });
  try {
    db.pragma("query_only = ON");
    db.transaction(() => {
      const identity = db.prepare("SELECT identity FROM witness_cas_floor_identity WHERE id=1").get();
      const row = db.prepare("SELECT sequence,hash FROM witness_cas_floor_event ORDER BY sequence DESC LIMIT 1").get();
      const count = db.prepare("SELECT COUNT(*) AS n FROM witness_cas_floor_event").get().n;
      if (identity?.identity !== workerData.identity || count !== workerData.sequence
        || (row?.sequence || 0) !== count || (row?.hash || "0".repeat(64)) !== workerData.lastHash) fail();
      const hash = crypto.createHash("sha256");
      let expectedSequence = 0;
      for (const item of db.prepare(
        "SELECT sequence,line,hash,predecessor FROM witness_cas_floor_event ORDER BY sequence").iterate()) {
        expectedSequence++;
        if (item.sequence !== expectedSequence || typeof item.line !== "string"
          || typeof item.hash !== "string" || typeof item.predecessor !== "string") fail();
        hash.update(JSON.stringify([item.sequence, item.line, item.hash, item.predecessor]) + "\n");
      }
      if (expectedSequence !== count || hash.digest("hex") !== workerData.chainDigest) fail();
    }).deferred();
    assertFileIdentity();
  } finally { db.close(); }
}

try {
  verify();
  parentPort.postMessage("VERIFIED");
} catch (_) {
  process.exitCode = 1;
}
