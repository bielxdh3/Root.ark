"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createCloudStorage } = require("../services/cloudStorage");

const FOREIGN = "FOREIGN_PRIVATE_BYTES_MUST_NEVER_LEAVE_DISK";
const AUTHORIZED = "AUTHORIZED_CLOUD_UPLOAD_BYTES";

async function consume(body) {
  const parts = [];
  for await (const chunk of body) parts.push(Buffer.from(chunk));
  return Buffer.concat(parts).toString("utf8");
}

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-upload-race-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const source = path.join(dir, "authorized", "data.bin");
  const foreign = path.join(dir, "foreign-private.bin");
  fs.mkdirSync(path.dirname(source));
  fs.writeFileSync(source, AUTHORIZED);
  fs.writeFileSync(foreign, FOREIGN);
  let swapped = false;
  function swap() {
    if (swapped) throw Error("swap already executed");
    swapped = true;
    fs.renameSync(source, path.join(dir, "original.bin"));
    // A hardlink does not require Windows Developer Mode and is a real
    // physical name swap; the injected provider observes the foreign inode.
    fs.linkSync(foreign, source);
  }
  return { source, swap, wasSwapped: () => swapped };
}

function assertNoForeignBytes(received, result) {
  assert.equal(received.includes(FOREIGN), false,
    "an attacker-controlled path replacement must not disclose foreign file bytes to the provider");
  if (result.status === "fulfilled") assert.equal(received, AUTHORIZED,
    "success must mean the provider received only the originally authorized bytes");
}

test("legacy S3 upload never leaks a swapped-in foreign hardlink between preflight and SDK send", async (t) => {
  const { source, swap } = fixture(t);
  let received = "";
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "fixture" },
    createS3Client: async () => {
      swap(); // The preflight has already run; SDK construction is asynchronous.
      return { send: async (cmd) => {
        received = await consume(cmd.input.Body);
        return {};
      } };
    },
  });
  const result = await storage.upload(source, "root", "item.bin")
    .then((value) => ({ status: "fulfilled", value }), (error) => ({ status: "rejected", error }));
  assertNoForeignBytes(received, result);
});

test("legacy Drive create never leaks a swapped-in foreign hardlink after metadata lookup", async (t) => {
  const { source, swap } = fixture(t);
  let received = "";
  const client = { files: {
    list: async () => { swap(); return { data: { files: [] } }; },
    create: async (request) => { received = await consume(request.media.body); return { data: { id: "created" } }; },
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" },
    createGoogleDriveClient: async () => client });
  const result = await storage.upload(source, "root", "item.bin")
    .then((value) => ({ status: "fulfilled", value }), (error) => ({ status: "rejected", error }));
  assertNoForeignBytes(received, result);
});

test("legacy Drive pinned update never leaks a foreign hardlink after ID ownership lookup", async (t) => {
  const { source, swap } = fixture(t);
  let received = "";
  const client = { files: {
    get: async () => {
      swap();
      return { data: { id: "pinned", parents: ["parent"], appProperties: {
        rootArkKey: "rootark/uploads/root/item.bin", rootArkFolderId: "root", rootArkArea: "uploads",
      } } };
    },
    update: async (request) => { received = await consume(request.media.body); return { data: { id: "pinned" } }; },
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" },
    createGoogleDriveClient: async () => client });
  const result = await storage.upload(source, "root", "item.bin", "uploads", { providerFileId: "pinned" })
    .then((value) => ({ status: "fulfilled", value }), (error) => ({ status: "rejected", error }));
  assertNoForeignBytes(received, result);
});

test("legacy S3 FD stream still reads authorized inode if attacker swaps path after SDK gets Body", async (t) => {
  const { source, swap } = fixture(t);
  let received = "";
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "fixture" },
    createS3Client: async () => ({ send: async (cmd) => {
      assert.equal(cmd.input.ContentLength, Buffer.byteLength(AUTHORIZED));
      swap(); // SDK received Body; async stream has not read the path yet.
      received = await consume(cmd.input.Body);
      return {};
    } }),
  });
  const result = await storage.upload(source, "root", "item.bin")
    .then((value) => ({ status: "fulfilled", value }), (error) => ({ status: "rejected", error }));
  assertNoForeignBytes(received, result);
  assert.equal(result.status, "fulfilled", "a verified FD must survive pathname replacement");
});

test("legacy Drive FD stream cannot read a swapped path after SDK receives media", async (t) => {
  const { source, swap } = fixture(t);
  let received = "";
  const drive = { files: {
    list: async () => ({ data: { files: [] } }),
    create: async (request) => {
      swap();
      received = await consume(request.media.body);
      return { data: { id: "created" } };
    },
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" },
    createGoogleDriveClient: async () => drive });
  const result = await storage.upload(source, "root", "item.bin")
    .then((value) => ({ status: "fulfilled", value }), (error) => ({ status: "rejected", error }));
  assertNoForeignBytes(received, result);
  assert.equal(result.status, "fulfilled");
});

test("legacy uploads reject an already-hardlinked source without contacting providers", async (t) => {
  const { source } = fixture(t);
  fs.linkSync(source, path.join(path.dirname(source), "second-link.bin"));
  let s3Called = 0;
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "fixture" },
    createS3Client: async () => { s3Called++; return { send: async () => ({}) }; },
  });
  await assert.rejects(storage.upload(source, "root", "item.bin"), { code: "invalid_path" });
  assert.equal(s3Called, 0, "unsafe source must be rejected before SDK initialization");
});
