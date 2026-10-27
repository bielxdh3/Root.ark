"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

// Permit a small isolated provider fixture even when this worktree deliberately
// has no installed crypto packages. Exercise the real cloudStorage source and native fs.
const resilience = require.resolve("../src/services/deploymentResilience");
require.cache[resilience] = { id: resilience, filename: resilience,
  loaded: true, exports: { normalizeProviderError: (error) => error } };
const { createCloudStorage } = require("../services/cloudStorage");

const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");

function stage(t) {
  const directory = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA, "zk65-cloud-upload-stage-" + crypto.randomBytes(8).toString("hex"))
    : fs.mkdtempSync(path.join(os.tmpdir(), "zk65-cloud-upload-stage-"));
  if (process.platform === "win32") {
    require("../services/chunkUploadWindowsAcl").ensureWindowsChunkUploadRoot(directory);
  }
  t.after(() => fs.rmSync(directory, { force: true, recursive: true, maxRetries: 5 }));
  return directory;
}

function s3() {
  const writes = [];
  return { writes, cloud: createCloudStorage({ provider: "s3", s3: { bucket: "fixture" },
    createS3Client: async () => ({ send: async (command) => {
      writes.push(Buffer.from(command.input.Body)); return {};
    } }) }) };
}

test("bounded S3 refuses same-inode rewrite between stat and open before provider PUT", async (t) => {
  const root = stage(t);
  const source = path.join(root, "sealed.ct");
  const trusted = Buffer.alloc(64, 0x41);
  fs.writeFileSync(source, trusted, { flag: "wx", mode: 0o600 });
  const { cloud, writes } = s3();
  const open = fs.openSync;
  let injected = false;
  fs.openSync = function (filename, ...rest) {
    if (!injected && filename === source) {
      injected = true;
      fs.writeFileSync(source, Buffer.alloc(64, 0x5a));
    }
    return open.call(fs, filename, ...rest);
  };
  try {
    await assert.rejects(cloud.upload(source, "folder", "sealed.ct", "uploads",
      { zk1BoundedBytes: 64 }));
  } finally { fs.openSync = open; }
  assert.equal(injected, true);
  assert.equal(writes.length, 0);
});

test("S3 refuses a source whose ancestor is a Windows junction before first stat", async (t) => {
  if (process.platform !== "win32") return t.skip("Windows junction-specific");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-cloud-junction-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const legitimate = path.join(root, "legitimate");
  const foreign = path.join(root, "foreign");
  fs.mkdirSync(legitimate);
  fs.mkdirSync(foreign);
  const trusted = Buffer.alloc(64, 0x41);
  fs.writeFileSync(path.join(legitimate, "sealed.ct"), trusted);
  fs.writeFileSync(path.join(foreign, "sealed.ct"), Buffer.alloc(64, 0x5a));
  const held = path.join(root, "held");
  fs.renameSync(legitimate, held);
  fs.symlinkSync(foreign, legitimate, "junction");
  const { cloud, writes } = s3();
  await assert.rejects(cloud.upload(path.join(legitimate, "sealed.ct"),
    "folder", "sealed.ct", "uploads",
    { zk1BoundedBytes: 64 }));
  assert.equal(writes.length, 0);
});

test("signed digest rejects same-size in-place tampering even if filesystem timestamps alias", async (t) => {
  const root = stage(t);
  const source = path.join(root, "sealed.ct");
  const trusted = Buffer.alloc(64, 0x41);
  fs.writeFileSync(source, trusted, { flag: "wx", mode: 0o600 });
  const original = fs.statSync(source, { bigint: true });
  const { cloud, writes } = s3();
  const read = fs.readSync;
  const fstat = fs.fstatSync;
  const lstat = fs.lstatSync;
  let injected = false;
  fs.readSync = function (fd, ...args) {
    if (!injected) {
      injected = true;
      fs.writeFileSync(source, Buffer.alloc(trusted.length, 0x5a));
    }
    return read.call(fs, fd, ...args);
  };
  fs.fstatSync = function (fd, options) {
    const result = fstat.call(fs, fd, options);
    if (injected && result.ino === original.ino) {
      result.mtimeNs = original.mtimeNs;
      result.ctimeNs = original.ctimeNs;
    }
    return result;
  };
  fs.lstatSync = function (filename, options) {
    const result = lstat.call(fs, filename, options);
    if (injected && filename === source) {
      result.mtimeNs = original.mtimeNs;
      result.ctimeNs = original.ctimeNs;
    }
    return result;
  };
  try {
    await assert.rejects(cloud.upload(source, "folder", "sealed.ct", "uploads",
      { zk1BoundedBytes: trusted.length, zk1ExpectedSha256: sha(trusted) }),
    /digest mismatch/);
  } finally {
    fs.readSync = read;
    fs.fstatSync = fstat;
    fs.lstatSync = lstat;
  }
  assert.equal(injected, true);
  assert.equal(writes.length, 0);
});

test("bounded S3 and pinned Drive send only the trusted captured Buffer", async (t) => {
  const root = stage(t);
  const source = path.join(root, "sealed.ct");
  const trusted = Buffer.from("trusted sealed opaque ciphertext");
  fs.writeFileSync(source, trusted, { flag: "wx", mode: 0o600 });
  const { cloud, writes } = s3();
  assert.equal((await cloud.upload(source, "folder", "sealed.ct", "uploads", {
    zk1BoundedBytes: trusted.length, zk1ExpectedSha256: sha(trusted),
  })).provider, "s3");
  assert.deepEqual(writes, [trusted]);

  const driveWrites = [];
  const drive = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "root" },
    createGoogleDriveClient: async () => ({ files: {
      get: async () => { throw Object.assign(new Error("missing"), { status: 404 }); },
      create: async ({ media }) => {
        const parts = []; for await (const part of media.body) parts.push(Buffer.from(part));
        driveWrites.push(Buffer.concat(parts));
        return { data: { id: "drive-pinned-file" } };
      },
    } }) });
  assert.equal((await drive.upload(source, "folder", "sealed.ct", "uploads", {
    zk1BoundedBytes: trusted.length, zk1ExpectedSha256: sha(trusted),
    providerFileId: "drive-pinned-file",
  })).id, "drive-pinned-file");
  assert.deepEqual(driveWrites, [trusted]);
});
