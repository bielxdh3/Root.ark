"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createCloudStorage } = require("../services/cloudStorage");

const AUTHORIZED = "approved-upload-inode";
const FOREIGN = "foreign-private-bytes";

async function consume(body) {
  if (Buffer.isBuffer(body)) return body.toString("utf8");
  const pieces = [];
  for await (const part of body) pieces.push(Buffer.from(part));
  return Buffer.concat(pieces).toString("utf8");
}

for (const bounded of [false, true]) {
test(`${bounded ? "bounded ZK" : "legacy"} S3 upload refuses single-link parent rename between preflight stat and FD open`, async (t) => {
  assert.equal(Buffer.byteLength(AUTHORIZED), Buffer.byteLength(FOREIGN),
    "adversarial files must have identical lengths so size cannot detect the swap");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-parent-stat-race-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true, maxRetries: 5 }));
  const authorized = path.join(root, "authorized");
  const incoming = path.join(root, "incoming-foreign");
  const detached = path.join(root, "detached-approved");
  fs.mkdirSync(authorized);
  fs.mkdirSync(incoming);
  const localPath = path.join(authorized, "ciphertext.bin");
  fs.writeFileSync(localPath, AUTHORIZED);
  fs.writeFileSync(path.join(incoming, "ciphertext.bin"), FOREIGN);
  let swapped = false;
  let received = "";
  let providerCalls = 0;
  const statSync = fs.statSync;
  fs.statSync = function (filename, ...rest) {
    const stat = statSync.call(fs, filename, ...rest);
    if (filename === localPath && !swapped) {
      swapped = true;
      fs.renameSync(authorized, detached);
      fs.renameSync(incoming, authorized);
      assert.equal(fs.statSync(localPath).nlink, 1);
    }
    return stat;
  };
  const cloud = createCloudStorage({ provider: "s3", s3: { bucket: "fixture" },
    createS3Client: async () => ({ send: async (cmd) => {
      providerCalls++;
      received = await consume(cmd.input.Body);
      return {};
    } }),
  });
  let result;
  try {
    result = await cloud.upload(localPath, "root", "ciphertext.bin", "uploads",
      bounded ? { zk1BoundedBytes: Buffer.byteLength(AUTHORIZED) } : {})
      .then(() => "fulfilled", () => "rejected");
  } finally { fs.statSync = statSync; }
  assert.equal(swapped, true, "attacker must replace directory after initial stat");
  assert.equal(fs.readFileSync(path.join(detached, "ciphertext.bin"), "utf8"), AUTHORIZED);
  assert.equal(fs.readFileSync(localPath, "utf8"), FOREIGN);
  assert.equal(received.includes(FOREIGN), false,
    "cloud SDK must never receive a foreign single-link inode after a parent swap");
  assert.equal(result, "rejected", "preflight file identity must be bound to the opened FD");
  assert.equal(providerCalls, 0, "rejected upload must fail before contacting cloud provider");
});
}
