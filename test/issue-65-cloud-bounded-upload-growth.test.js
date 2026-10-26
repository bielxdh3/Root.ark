"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createCloudStorage } = require("../services/cloudStorage");

function setup(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-cloud-growth-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const source = path.join(dir, "ciphertext.ct");
  const bytes = Buffer.from("authorized-opaque-ciphertext-only");
  fs.writeFileSync(source, bytes);
  return { source, bytes };
}

test("bounded ZK upload reads exactly authorized bytes without an unbounded FD read", async (t) => {
  const { source, bytes } = setup(t);
  const original = fs.readFileSync;
  let uploaded;
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "fixture" },
    createS3Client: async () => ({ send: async (request) => {
      uploaded = request.input.Body;
      return {};
    } }),
  });
  fs.readFileSync = function (input, ...rest) {
    if (typeof input === "number") throw Error("unbounded FD read forbidden");
    return original.call(fs, input, ...rest);
  };
  try {
    await storage.upload(source, "root", "ciphertext.ct", "uploads",
      { zk1BoundedBytes: bytes.length });
  } finally { fs.readFileSync = original; }
  assert.deepEqual(uploaded, bytes);
});

test("same-inode growth after ZK preflight fails before uploading any bytes", async (t) => {
  const { source, bytes } = setup(t);
  const original = fs.readSync;
  let extended = false;
  let requests = 0;
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "fixture" },
    createS3Client: async () => ({ send: async () => { requests++; return {}; } }),
  });
  fs.readSync = function (fd, buffer, offset, length, position) {
    if (!extended && typeof fd === "number" && buffer?.length === bytes.length) {
      extended = true;
      fs.appendFileSync(source, Buffer.alloc(bytes.length * 4, 0x41));
    }
    return original.call(fs, fd, buffer, offset, length, position);
  };
  let error;
  try {
    await storage.upload(source, "root", "ciphertext.ct", "uploads",
      { zk1BoundedBytes: bytes.length });
  } catch (caught) { error = caught; }
  finally { fs.readSync = original; }
  assert.equal(extended, true, "the original inode must grow during its bounded read");
  assert.ok(error, "a changed inode must never result in a success ACK");
  assert.equal(requests, 0, "no cloud upload may occur after source growth");
  assert.equal(fs.statSync(source).size, bytes.length * 5);
});
