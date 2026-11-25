"use strict";

// Disposable test-signer process. No key is exported to the consumer. This
// same-SID test signer is NOT an independently administered off-host operator.
const { generateKeyPairSync, sign } = require("node:crypto");
const { spawnSync } = require("node:child_process");

if (process.argv.length !== 5 || !["locked", "movable"].includes(process.argv[3])) {
  process.exitCode = 2;
} else {
  const runner = spawnSync(process.argv[2], ["enroll", process.argv[3], process.argv[4]], {
    windowsHide: true, encoding: "utf8", timeout: 20000, maxBuffer: 16000,
  });
  if (runner.status !== 0 || !/^ENROLLED\|[A-Za-z0-9+/=,]+\r?\n$/.test(runner.stdout || "")) {
    process.stderr.write("TEST_NATIVE_ENROLLMENT_UNAVAILABLE\n");
    process.exitCode = 3;
  } else {
    const record = { root: process.argv[4],
      ids: runner.stdout.trim().slice("ENROLLED|".length) };
    const key = generateKeyPairSync("ed25519");
    const message = Buffer.from(JSON.stringify(record));
    const signature = sign(null, message, key.privateKey).toString("base64");
    const publicKey = key.publicKey.export({ format: "pem", type: "spki" });
    process.stdout.write(JSON.stringify({ record, signature, publicKey }) + "\n");
  }
}
