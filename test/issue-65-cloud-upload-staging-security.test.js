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
      { zk1BoundedBytes: 64, zk1ExpectedSha256: sha(trusted) }));
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

test("ZK integrity opt-in requires independently supplied digest before S3 or pinned Drive provider writes", async (t) => {
  const root = stage(t);
  const source = path.join(root, "sealed.ct");
  const trusted = Buffer.from("immutable independently hashed ciphertext");
  fs.writeFileSync(source, trusted, { flag: "wx", mode: 0o600 });
  const { cloud, writes } = s3();
  const driveWrites = [];
  const drive = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "root" },
    createGoogleDriveClient: async () => ({ files: {
      get: async () => { throw Object.assign(new Error("missing"), { status: 404 }); },
      create: async ({ media }) => {
        const parts = []; for await (const part of media.body) parts.push(Buffer.from(part));
        driveWrites.push(Buffer.concat(parts));
        return { data: { id: "pinned" } };
      },
    } }) });
  for (const writer of [cloud, drive]) {
    const extras = writer === drive ? { providerFileId: "pinned" } : {};
    for (const options of [
      { ...extras, zk1BoundedBytes: trusted.length },
      { ...extras, zk1ExpectedSha256: sha(trusted) },
      { ...extras, zk1BoundedBytes: undefined, zk1ExpectedSha256: sha(trusted) },
      { ...extras, zk1BoundedBytes: trusted.length, zk1ExpectedSha256: undefined },
      { ...extras, zk1BoundedBytes: trusted.length, zk1ExpectedSha256: sha(trusted), zk1UnsafeFallback: true },
      Object.assign(Object.create({ zk1BoundedBytes: trusted.length,
        zk1ExpectedSha256: sha(trusted) }), extras),
      Object.assign(Object.create({ zk1ExpectedSha256: sha(trusted) }), extras),
    ]) {
      await assert.rejects(writer.upload(source, "folder", "sealed.ct", "uploads", options),
        { code: "configuration" });
    }
  }
  assert.deepEqual(writes, []);
  assert.deepEqual(driveWrites, []);
});

test("bounded S3 lost ACK never retries changed bytes under the prior trusted digest", async (t) => {
  const root = stage(t);
  const source = path.join(root, "ciphertext.ct");
  const original = Buffer.from("original-authenticated-ciphertext");
  const changed = Buffer.alloc(original.length, 0x42);
  assert.equal(original.length, changed.length);
  fs.writeFileSync(source, original, { flag: "wx", mode: 0o600 });
  const remote = [];
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "fixture" },
    createS3Client: async () => ({ send: async ({ input }) => {
      remote.push(Buffer.from(input.Body));
      if (remote.length === 1) throw new Error("lost remote acknowledgement");
      return {};
    } }) });
  const options = { zk1BoundedBytes: original.length, zk1ExpectedSha256: sha(original) };
  await assert.rejects(storage.upload(source, "folder", "ciphertext.ct", "uploads", options));
  assert.deepEqual(remote, [original], "remote PUT might have happened despite missing ACK");
  fs.writeFileSync(source, changed);
  await assert.rejects(storage.upload(source, "folder", "ciphertext.ct", "uploads", options),
    { code: "configuration" });
  assert.deepEqual(remote, [original], "retries never downgrade to attacker content");
  fs.writeFileSync(source, original);
  assert.equal((await storage.upload(source, "folder", "ciphertext.ct", "uploads", options)).provider, "s3");
  assert.deepEqual(remote, [original, original]);
});

test("bounded pinned Drive 409 recovery reuses authenticated snapshot after source rewrite", async (t) => {
  const root = stage(t);
  const source = path.join(root, "ciphertext.ct");
  const original = Buffer.from("signed-cloud-ciphertext-data");
  fs.writeFileSync(source, original, { flag: "wx", mode: 0o600 });
  const received = [];
  let gets = 0;
  const cloud = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "root" },
    createGoogleDriveClient: async () => ({ files: {
      get: async () => {
        if (++gets === 1) throw Object.assign(new Error("missing"), { status: 404 });
        return { data: { id: "pinned", parents: ["root"], appProperties: {
          rootArkKey: "rootark/uploads/folder/ciphertext.ct",
          rootArkFolderId: "folder", rootArkArea: "uploads" } } };
      },
      create: async ({ media }) => {
        received.push(Buffer.concat(await Array.fromAsync(media.body)));
        fs.writeFileSync(source, Buffer.alloc(original.length, 0x42));
        throw Object.assign(new Error("ambiguous create 409"), { status: 409 });
      },
      update: async ({ media, fileId }) => {
        assert.equal(fileId, "pinned");
        received.push(Buffer.concat(await Array.fromAsync(media.body)));
        return { data: { id: fileId } };
      },
    } }) });
  assert.equal((await cloud.upload(source, "folder", "ciphertext.ct", "uploads", {
    providerFileId: "pinned", zk1BoundedBytes: original.length,
    zk1ExpectedSha256: sha(original),
  })).id, "pinned");
  assert.deepEqual(received, [original, original], "retry must not reread altered source");
});
