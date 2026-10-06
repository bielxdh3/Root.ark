const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Readable } = require("stream");
const { createCloudStorage } = require("../services/cloudStorage");

function drain(stream) {
  return new Promise((resolve) => {
    stream.once("close", resolve);
    stream.once("error", resolve);
    stream.resume();
  });
}

test("local provider is a no-op and does not create clients", async () => {
  let created = 0;
  const storage = createCloudStorage({ provider: "local", createS3Client: async () => { created += 1; } });
  assert.equal(storage.enabled(), false);
  assert.deepEqual(await storage.list("root"), []);
  assert.equal(created, 0);
});

test("key construction rejects traversal and keeps unicode filenames deterministic", async () => {
  const storage = createCloudStorage({ provider: "s3", prefix: "rootark", s3: { bucket: "test" }, createS3Client: async () => ({}) });
  assert.equal(storage.key("folder", "olá.txt"), "rootark/uploads/folder/olá.txt");
  assert.equal(storage.key("folder", "", "temp"), "rootark/temp/folder");
  assert.throws(() => storage.key("../folder", "safe.txt"), { code: "invalid_path" });
  assert.throws(() => storage.key("folder", "../safe.txt"), { code: "invalid_path" });
  await assert.rejects(storage.removePrefix("rootark-evil/uploads/root"), { code: "invalid_prefix" });
});

test("S3 uses the expected bucket/key and paginates listings", async () => {
  const calls = [];
  const storage = createCloudStorage({ provider: "s3", prefix: "rootark", s3: { bucket: "bucket" }, createS3Client: async () => ({ send: async (command) => {
    calls.push(command.input);
    if (command.constructor.name === "ListObjectsV2Command") return calls.filter((call) => call.Prefix).length === 1
      ? { Contents: [{ Key: "rootark/uploads/folder/a.txt", Size: 5, LastModified: new Date("2026-10-01T00:00:00.000Z") }, { Key: "rootark/uploads/folder/nested/hidden.txt", Size: 6 }], NextContinuationToken: "next" }
      : { Contents: [{ Key: "rootark/uploads/folder/b.txt", Size: 7 }] };
    return {};
  } }) });
  assert.deepEqual(await storage.list("folder"), [
    { name: "a.txt", key: "rootark/uploads/folder/a.txt", size: 5, modifiedAt: "2026-10-01T00:00:00.000Z", uploadedAt: "2026-10-01T00:00:00.000Z" },
    { name: "b.txt", key: "rootark/uploads/folder/b.txt", size: 7 },
  ]);
  assert.deepEqual(calls[0], { Bucket: "bucket", Prefix: "rootark/uploads/folder/", ContinuationToken: undefined });
});

test("cloud inventory rejects foreign, malformed, duplicate, and mismatched identities", async () => {
  let contents = [{ Key: "other/uploads/folder/file.txt" }];
  const s3 = createCloudStorage({ provider: "s3", prefix: "rootark", s3: { bucket: "bucket" }, createS3Client: async () => ({ send: async () => ({ Contents: contents }) }) });
  await assert.rejects(s3.inventory(), { code: "foreign_prefix" });
  contents = [{ Key: "rootark/uploads/folder/file/extra.txt" }];
  await assert.rejects(s3.inventory(), { code: "invalid_inventory_key" });
  contents = [{ Key: "rootark/uploads/folder/file.txt" }, { Key: "rootark/uploads/folder/file.txt" }];
  await assert.rejects(s3.inventory(), { code: "duplicate_inventory_identity" });

  let driveFiles = [{ id: "drive-1", parents: ["other-parent"], appProperties: { rootArkKey: "rootark/uploads/folder/file.txt", rootArkFolderId: "folder", rootArkArea: "uploads" } }];
  const drive = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => ({ files: { list: async () => ({ data: { files: driveFiles } }) } }) });
  await assert.rejects(drive.inventory(), { code: "outside_configured_parent" });
  driveFiles = [{ id: "drive-1", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/folder/file.txt", rootArkFolderId: "wrong", rootArkArea: "uploads" } }];
  await assert.rejects(drive.inventory(), { code: "invalid_inventory_metadata" });
  driveFiles = [{ parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/folder/file.txt", rootArkFolderId: "folder", rootArkArea: "uploads" } }];
  await assert.rejects(drive.inventory(), { code: "invalid_inventory_identity" });
});

test("download cleans up a partial cache file after a provider stream failure", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-"));
  const target = path.join(root, "cache.txt");
  const stream = new Readable({ read() { this.push("partial"); this.destroy(new Error("stream failure")); } });
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "bucket" }, createS3Client: async () => ({ send: async () => ({ Body: stream }) }) });
  await assert.rejects(storage.download("root", "cache.txt", target), { code: "provider_error" });
  assert.equal(fs.existsSync(target), false);
  fs.rmSync(root, { recursive: true, force: true });
});

test("Google Drive escapes lookup values and uses a deterministic duplicate", async () => {
  const queries = [];
  const drive = { files: {
    list: async ({ q }) => { queries.push(q); return { data: { files: [{ id: "z" }, { id: "a" }] } }; },
    delete: async ({ fileId }) => { assert.equal(fileId, "a"); },
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });
  assert.equal(await storage.remove("folder'one", "safe.txt"), true);
  assert.match(queries[0], /folder\\'one/);
});

test("provider selection and configuration failures have stable categories", async () => {
  const unsupported = createCloudStorage({ provider: "ftp" });
  await assert.rejects(unsupported.list("root"), { code: "unsupported_provider" });
  const s3 = createCloudStorage({ provider: "s3", createS3Client: async () => ({}) });
  await assert.rejects(s3.list("root"), { code: "configuration" });
  const drive = createCloudStorage({ provider: "gdrive", createGoogleDriveClient: async () => ({ files: { list: async () => ({ data: { files: [] } }) } }) });
  await assert.rejects(drive.upload(__filename, "root", "file.txt"), { code: "configuration" });
});

test("key containment normalizes separators and rejects empty or absolute segments", () => {
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "bucket" }, createS3Client: async () => ({}) });
  assert.equal(storage.key("folder\\child", "file.txt"), "rootark/uploads/folder/child/file.txt");
  assert.equal(storage.key("", "file.txt"), "rootark/uploads/root/file.txt");
  assert.throws(() => storage.key("/absolute", "file.txt"), { code: "invalid_path" });
  assert.throws(() => storage.key("folder", "" , ""), { code: "invalid_path" });
  assert.throws(() => storage.key("folder", "/absolute.txt"), { code: "invalid_path" });
});

test("S3 upload and delete send stable provider-neutral keys", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-"));
  const source = path.join(root, "source.txt");
  fs.writeFileSync(source, "bytes");
  const calls = [];
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "bucket" }, createS3Client: async () => ({ send: async (command) => { calls.push(command); if (command.input.Body) await drain(command.input.Body); return {}; } }) });
  assert.deepEqual(await storage.upload(source, "folder", "file.txt"), { provider: "s3", key: "rootark/uploads/folder/file.txt" });
  assert.equal(await storage.remove("folder", "file.txt"), true);
  assert.equal(calls[0].input.Bucket, "bucket");
  assert.equal(calls[1].input.Key, "rootark/uploads/folder/file.txt");
  fs.rmSync(root, { recursive: true, force: true });
});

test("S3 prefix deletion paginates, ignores empty pages, and rejects partial batches", async () => {
  let page = 0;
  const calls = [];
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "bucket" }, createS3Client: async () => ({ send: async (command) => {
    calls.push(command.constructor.name);
    if (command.constructor.name === "ListObjectsV2Command") return page++ === 0 ? { Contents: [], NextContinuationToken: "next" } : { Contents: [{ Key: "rootark/uploads/folder/a" }] };
    return {};
  } }) });
  assert.equal(await storage.removePrefix("rootark/uploads/folder"), true);
  assert.deepEqual(calls, ["ListObjectsV2Command", "ListObjectsV2Command", "DeleteObjectsCommand"]);
  const partial = createCloudStorage({ provider: "s3", s3: { bucket: "bucket" }, createS3Client: async () => ({ send: async (command) => command.constructor.name === "ListObjectsV2Command" ? { Contents: [{ Key: "rootark/uploads/folder/a" }] } : { Errors: [{ Key: "rootark/uploads/folder/a" }] } }) });
  await assert.rejects(partial.removePrefix("rootark/uploads/folder"), { code: "partial_delete" });
});

test("S3 download preserves existing cache and downloads new bytes", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-"));
  const cached = path.join(root, "cached.txt");
  fs.writeFileSync(cached, "existing");
  let calls = 0;
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "bucket" }, createS3Client: async () => ({ send: async () => { calls += 1; return { Body: Readable.from("fresh") }; } }) });
  assert.equal(await storage.download("root", "cached.txt", cached), false);
  assert.equal(fs.readFileSync(cached, "utf8"), "existing");
  const target = path.join(root, "new.txt");
  assert.equal(await storage.download("root", "new.txt", target), true);
  assert.equal(fs.readFileSync(target, "utf8"), "fresh");
  assert.equal(calls, 1);
  fs.rmSync(root, { recursive: true, force: true });
});

test("Google Drive creates, updates, lists pages, and deletes missing or existing keys", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-"));
  const source = path.join(root, "source.txt");
  fs.writeFileSync(source, "bytes");
  let mode = "absent";
  const calls = [];
  const drive = { files: {
    list: async (request) => { calls.push(request); if (request.fields === "files(id,name)") return { data: { files: mode === "update" ? [{ id: "existing" }] : [] } }; return { data: { files: [] } }; },
    create: async (request) => { calls.push(request); await drain(request.media.body); return { data: { id: "created" } }; },
    update: async (request) => { calls.push(request); await drain(request.media.body); },
    delete: async (request) => { calls.push(request); },
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });
  assert.equal((await storage.upload(source, "root", "file.txt")).id, "created");
  mode = "update";
  assert.equal((await storage.upload(source, "root", "file.txt")).id, "existing");
  mode = "absent";
  assert.equal(await storage.remove("root", "missing.txt"), false);
  mode = "update";
  assert.equal(await storage.remove("root", "file.txt"), true);
  assert.ok(calls.some((call) => call.requestBody?.parents?.[0] === "parent"));
  assert.ok(calls.some((call) => call.fileId === "existing"));
  fs.rmSync(root, { recursive: true, force: true });
});

test("Google Drive lists and deletes every paginated prefix entry", async () => {
  let page = 0;
  const deleted = [];
  const drive = { files: { list: async ({ fields }) => {
    if (fields.includes("appProperties")) {
      const files = page++ === 0
        ? [
          { id: "a", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/root/a", rootArkFolderId: "root", rootArkArea: "uploads" }, size: "4", createdTime: "2026-10-01T00:00:00.000Z" },
          { id: "foreign-parent", parents: ["elsewhere"], appProperties: { rootArkKey: "rootark/uploads/root/foreign-parent", rootArkFolderId: "root", rootArkArea: "uploads" } },
          { id: "wrong-key", parents: ["parent"], appProperties: { rootArkKey: "outside/uploads/root/wrong-key", rootArkFolderId: "root", rootArkArea: "uploads" } },
        ]
        : [{ id: "b", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/root/b", rootArkFolderId: "root", rootArkArea: "uploads" } }];
      return { data: { files, nextPageToken: page === 1 ? "next" : undefined } };
    }
    return { data: { files: [{ id: "a" }, { id: "b" }], nextPageToken: page++ ? undefined : "next" } };
  }, delete: async ({ fileId }) => deleted.push(fileId) } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });
  assert.deepEqual(await storage.list("root"), [
    { name: "a", id: "a", key: "rootark/uploads/root/a", size: 4, uploadedAt: "2026-10-01T00:00:00.000Z" },
    { name: "b", id: "b", key: "rootark/uploads/root/b" },
  ]);
  page = 0;
  assert.equal(await storage.removePrefix("rootark/uploads/root"), true);
  assert.deepEqual(deleted, ["a", "b", "a", "b"]);
});

test("configuration errors avoid client creation and provider errors do not disclose credentials", async () => {
  let created = 0;
  const missingBucket = createCloudStorage({ provider: "s3", createS3Client: async () => { created += 1; return {}; } });
  await assert.rejects(missingBucket.remove("root", "file.txt"), { code: "configuration" });
  assert.equal(created, 0);
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "bucket" }, createS3Client: async () => ({ send: async () => { throw new Error("credential=private-value"); } }) });
  await assert.rejects(storage.remove("root", "file.txt"), (error) => error.code === "provider_error" && !error.message.includes("private-value"));
});

test("object operations reject empty filenames while prefix keys remain available", async () => {
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "bucket" }, createS3Client: async () => ({ send: async () => ({}) }) });
  assert.equal(storage.key("root", ""), "rootark/uploads/root");
  await assert.rejects(storage.remove("root", ""), { code: "invalid_path" });
});

test("Google Drive download succeeds, misses cleanly, and removes partial files", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-"));
  const target = path.join(root, "file.txt");
  let mode = "success";
  const drive = { files: {
    list: async () => ({ data: { files: mode === "missing" ? [] : [{ id: "file" }] } }),
    get: async () => ({ data: mode === "failure" ? new Readable({ read() { this.push("partial"); this.destroy(new Error("failure")); } }) : Readable.from("content") }),
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });
  assert.equal(await storage.download("root", "file.txt", target), true);
  assert.equal(fs.readFileSync(target, "utf8"), "content");
  fs.rmSync(target);
  mode = "missing";
  assert.equal(await storage.download("root", "missing.txt", target), false);
  mode = "failure";
  await assert.rejects(storage.download("root", "broken.txt", target), { code: "provider_error" });
  assert.equal(fs.existsSync(target), false);
  fs.rmSync(root, { recursive: true, force: true });
});

test("status exposes provider-neutral configuration without credentials", () => {
  const storage = createCloudStorage({ provider: "s3", prefix: "rootark", s3: { bucket: "bucket", region: "eu" } });
  assert.deepEqual(storage.status(), { provider: "s3", enabled: true, prefix: "rootark", s3: { bucketConfigured: true, region: "eu", endpointConfigured: false }, gdrive: { folderConfigured: false, credentialsConfigured: false } });
});

test("root-folder keys use the uploads area", () => {
  const storage = createCloudStorage({ provider: "s3" });
  assert.equal(storage.key(), "rootark/uploads/root");
});

test("temporary keys preserve the requested area", () => {
  const storage = createCloudStorage({ provider: "s3" });
  assert.equal(storage.key("folder", "item.bin", "temp"), "rootark/temp/folder/item.bin");
});

test("Windows separators normalize inside folder identifiers", () => {
  const storage = createCloudStorage({ provider: "s3" });
  assert.equal(storage.key("folder\\nested", "item.bin"), "rootark/uploads/folder/nested/item.bin");
});

test("empty cloud prefixes fail before a client is created", async () => {
  let created = 0;
  const storage = createCloudStorage({ provider: "s3", createS3Client: async () => { created += 1; return { send: async () => ({}) }; } });
  await assert.rejects(storage.removePrefix(""), { code: "invalid_prefix" });
  assert.equal(created, 0);
});

test("filename separators are rejected for object operations", async () => {
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "bucket" }, createS3Client: async () => ({ send: async () => ({}) }) });
  await assert.rejects(storage.remove("folder", "nested\\item.bin"), { code: "invalid_path" });
});

test("upload of a missing local file is a no-op", async () => {
  let created = 0;
  const storage = createCloudStorage({ provider: "s3", s3: { bucket: "bucket" }, createS3Client: async () => { created += 1; return { send: async () => ({}) }; } });
  assert.equal(await storage.upload(path.join(os.tmpdir(), "rootark-missing-file"), "root", "item.bin"), null);
  assert.equal(created, 0);
});

test("S3 configuration errors are stable before client creation", async () => {
  const storage = createCloudStorage({ provider: "s3", createS3Client: async () => ({}) });
  await assert.rejects(storage.remove("root", "item.bin"), { code: "configuration" });
});

test("Google Drive configuration errors are stable before client creation", async () => {
  const storage = createCloudStorage({ provider: "gdrive", createGoogleDriveClient: async () => ({}) });
  await assert.rejects(storage.list("root"), { code: "provider_error" });
});
