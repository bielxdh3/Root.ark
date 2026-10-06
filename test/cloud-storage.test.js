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
    list: async ({ q }) => { queries.push(q); return { data: { files: [
      { id: "a", parents: ["other-parent"], appProperties: { rootArkKey: "rootark/uploads/folder'one/safe.txt", rootArkFolderId: "folder'one", rootArkArea: "uploads" } },
      { id: "z", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/folder'one/safe.txt", rootArkFolderId: "folder'one", rootArkArea: "uploads" } },
    ] } }; },
    get: async () => ({ data: { id: "z", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/folder'one/safe.txt", rootArkFolderId: "folder'one", rootArkArea: "uploads" } } }),
    delete: async ({ fileId }) => { assert.equal(fileId, "z"); },
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });
  assert.equal(await storage.remove("folder'one", "safe.txt"), true);
  assert.match(queries[0], /folder\\'one/);
});

test("Google Drive operations ignore same-key records outside the configured parent or with mismatched metadata", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-drive-ownership-"));
  const source = path.join(root, "source.txt");
  const target = path.join(root, "download.txt");
  fs.writeFileSync(source, "replacement bytes");
  const key = "rootark/uploads/folder/file.txt";
  const records = [
    { id: "a-outside", parents: ["other-parent"], appProperties: { rootArkKey: key, rootArkFolderId: "folder", rootArkArea: "uploads" } },
    { id: "b-wrong-folder", parents: ["parent"], appProperties: { rootArkKey: key, rootArkFolderId: "other", rootArkArea: "uploads" } },
    { id: "c-wrong-area", parents: ["parent"], appProperties: { rootArkKey: key, rootArkFolderId: "folder", rootArkArea: "temp" } },
    { id: "z-owned", parents: ["parent"], appProperties: { rootArkKey: key, rootArkFolderId: "folder", rootArkArea: "uploads" } },
  ];
  const calls = [];
  const drive = { files: {
    list: async () => ({ data: { files: records } }),
    get: async ({ fileId, alt }) => {
      calls.push(["get", fileId, alt || "metadata"]);
      if (alt === "media") return { data: Readable.from(fileId === "z-owned" ? "owned bytes" : "outside bytes") };
      return { data: records.find((record) => record.id === fileId) };
    },
    update: async ({ fileId, media }) => { calls.push(["update", fileId]); await drain(media.body); },
    create: async ({ requestBody, media }) => { calls.push(["create", requestBody.parents[0]]); await drain(media.body); return { data: { id: "created" } }; },
    delete: async ({ fileId }) => { calls.push(["delete", fileId]); },
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });

  try {
    assert.equal(await storage.download("folder", "file.txt", target), true);
    assert.equal(fs.readFileSync(target, "utf8"), "owned bytes");
    assert.deepEqual(await storage.upload(source, "folder", "file.txt"), { provider: "gdrive", key, id: "z-owned" });
    assert.equal(await storage.remove("folder", "file.txt"), true);
    assert.deepEqual(calls.filter((call) => call[0] === "update" || call[0] === "delete"), [["update", "z-owned"], ["delete", "z-owned"]]);
    assert.deepEqual(calls.filter((call) => call[0] === "get" && call[2] === "media"), [["get", "z-owned", "media"]]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("Google Drive operations do not read, overwrite, or delete a matching key outside its configured parent", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-drive-foreign-"));
  const source = path.join(root, "source.txt");
  const target = path.join(root, "download.txt");
  fs.writeFileSync(source, "replacement bytes");
  const foreign = { id: "foreign", parents: ["other-parent"], appProperties: { rootArkKey: "rootark/uploads/folder/file.txt", rootArkFolderId: "folder", rootArkArea: "uploads" } };
  const calls = [];
  const drive = { files: {
    list: async () => ({ data: { files: [foreign] } }),
    get: async ({ fileId, alt }) => { calls.push(["get", fileId, alt || "metadata"]); return { data: Readable.from("foreign bytes") }; },
    update: async ({ fileId }) => calls.push(["update", fileId]),
    create: async ({ requestBody, media }) => { calls.push(["create", requestBody.parents[0]]); await drain(media.body); return { data: { id: "owned-created" } }; },
    delete: async ({ fileId }) => calls.push(["delete", fileId]),
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });

  try {
    assert.equal(await storage.download("folder", "file.txt", target), false);
    assert.equal(fs.existsSync(target), false);
    assert.deepEqual(await storage.upload(source, "folder", "file.txt"), { provider: "gdrive", key: foreign.appProperties.rootArkKey, id: "owned-created" });
    assert.equal(await storage.remove("folder", "file.txt"), false);
    assert.deepEqual(calls, [["create", "parent"]]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("Google Drive operations recheck parent and key metadata immediately before provider effects", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-drive-stale-"));
  const source = path.join(root, "source.txt");
  const target = path.join(root, "download.txt");
  fs.writeFileSync(source, "replacement bytes");
  const key = "rootark/uploads/folder/file.txt";
  const listed = { id: "listed", parents: ["parent"], appProperties: { rootArkKey: key, rootArkFolderId: "folder", rootArkArea: "uploads" } };
  const moved = { ...listed, parents: ["other-parent"] };
  const calls = [];
  const drive = { files: {
    list: async () => ({ data: { files: [listed] } }),
    get: async ({ fileId, alt }) => {
      calls.push(["get", fileId, alt || "metadata"]);
      return { data: alt === "media" ? Readable.from("unexpected bytes") : moved };
    },
    update: async ({ fileId }) => calls.push(["update", fileId]),
    create: async () => assert.fail("a stale object must not be replaced by a duplicate"),
    delete: async ({ fileId }) => calls.push(["delete", fileId]),
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });

  try {
    await assert.rejects(storage.download("folder", "file.txt", target), { code: "provider_error" });
    await assert.rejects(storage.upload(source, "folder", "file.txt"), { code: "provider_error" });
    await assert.rejects(storage.remove("folder", "file.txt"), { code: "provider_error" });
    assert.equal(fs.existsSync(target), false);
    assert.deepEqual(calls, [["get", "listed", "metadata"], ["get", "listed", "metadata"], ["get", "listed", "metadata"]]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
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
  const owned = { id: "existing", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/root/file.txt", rootArkFolderId: "root", rootArkArea: "uploads" } };
  const drive = { files: {
    list: async (request) => { calls.push(request); if (request.fields.includes("appProperties")) return { data: { files: mode === "update" ? [owned] : [] } }; return { data: { files: [] } }; },
    get: async () => ({ data: owned }),
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

test("Google Drive resolves an existing file ID or reserves a generated ID for restore retries", async () => {
  let existing = true;
  const drive = { files: {
    list: async () => ({ data: { files: existing ? [{ id: "existing", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/folder/file.txt", rootArkFolderId: "folder", rootArkArea: "uploads" } }] : [] } }),
    get: async () => ({ data: { id: "existing", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/folder/file.txt", rootArkFolderId: "folder", rootArkArea: "uploads" } } }),
    generateIds: async () => ({ data: { ids: ["reserved"] } }),
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });
  assert.equal(await storage.resolveUploadId("folder", "file.txt"), "existing");
  existing = false;
  assert.equal(await storage.resolveUploadId("folder", "file.txt"), "reserved");
});

test("Google Drive updates only the pinned ID after verifying its key and parent", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-"));
  const source = path.join(root, "source.txt");
  fs.writeFileSync(source, "bytes");
  const updates = [];
  const drive = { files: {
    get: async () => ({ data: { id: "pinned", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/folder/file.txt", rootArkFolderId: "folder", rootArkArea: "uploads" } } }),
    update: async (request) => { updates.push(request); await drain(request.media.body); return { data: { id: request.fileId } }; },
    create: async () => assert.fail("must not create a second Drive file"),
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });
  assert.deepEqual(await storage.upload(source, "folder", "file.txt", "uploads", { providerFileId: "pinned" }), { provider: "gdrive", key: "rootark/uploads/folder/file.txt", id: "pinned" });
  assert.equal(updates.length, 1);
  assert.equal(updates[0].fileId, "pinned");
  assert.equal("parents" in updates[0].requestBody, false);
  fs.rmSync(root, { recursive: true, force: true });
});

test("Google Drive creates a missing pinned ID and safely recovers a 409 create race", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-"));
  const source = path.join(root, "source.txt");
  fs.writeFileSync(source, "bytes");
  const key = "rootark/uploads/folder/file.txt";
  const owned = { id: "pinned", parents: ["parent"], appProperties: { rootArkKey: key, rootArkFolderId: "folder", rootArkArea: "uploads" } };
  await t.test("404 creates the exact pinned ID", async () => {
    const calls = [];
    const drive = { files: {
      get: async (request) => { calls.push(["get", request.fileId]); throw Object.assign(new Error("missing"), { code: 404 }); },
      create: async (request) => { calls.push(["create", request.requestBody.id]); await drain(request.media.body); return { data: { id: request.requestBody.id } }; },
    } };
    const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });
    const result = await storage.upload(source, "folder", "file.txt", "uploads", { providerFileId: "pinned" });
    assert.equal(result.id, "pinned");
    assert.deepEqual(calls, [["get", "pinned"], ["create", "pinned"]]);
  });
  await t.test("409 re-reads, verifies ownership, and updates the same ID", async () => {
    let gets = 0;
    const updates = [];
    const drive = { files: {
      get: async (request) => { assert.equal(request.fileId, "pinned"); gets += 1; if (gets === 1) throw Object.assign(new Error("missing"), { code: 404 }); return { data: owned }; },
      create: async (request) => { await drain(request.media.body); throw Object.assign(new Error("already exists"), { code: 409 }); },
      update: async (request) => { updates.push(request.fileId); await drain(request.media.body); return { data: { id: request.fileId } }; },
    } };
    const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });
    const result = await storage.upload(source, "folder", "file.txt", "uploads", { providerFileId: "pinned" });
    assert.equal(result.id, "pinned");
    assert.equal(gets, 2);
    assert.deepEqual(updates, ["pinned"]);
  });
  fs.rmSync(root, { recursive: true, force: true });
});

test("Google Drive refuses to update a pinned ID owned by another key or parent", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-"));
  const source = path.join(root, "source.txt");
  fs.writeFileSync(source, "bytes");
  let updates = 0;
  let gets = 0;
  const drive = { files: {
    get: async () => { gets += 1; return { data: { id: "pinned", parents: ["other-parent"], appProperties: { rootArkKey: "rootark/uploads/other/file.txt", rootArkFolderId: "other", rootArkArea: "uploads" } } }; },
    update: async () => { updates += 1; },
    create: async () => assert.fail("must not create when pinned ID is owned by another object"),
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });
  await assert.rejects(storage.upload(source, "folder", "file.txt", "uploads", { providerFileId: "pinned" }), { code: "provider_error" });
  assert.equal(gets, 1);
  assert.equal(updates, 0);
  fs.rmSync(root, { recursive: true, force: true });
});

test("Google Drive lists and deletes every paginated prefix entry", async () => {
  let page = 0;
  const deleted = [];
  const pages = [
    [
      { id: "a", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/root/a", rootArkFolderId: "root", rootArkArea: "uploads" }, size: "4", createdTime: "2026-10-01T00:00:00.000Z" },
      { id: "foreign-parent", parents: ["elsewhere"], appProperties: { rootArkKey: "rootark/uploads/root/foreign-parent", rootArkFolderId: "root", rootArkArea: "uploads" } },
      { id: "wrong-key", parents: ["parent"], appProperties: { rootArkKey: "outside/uploads/root/wrong-key", rootArkFolderId: "root", rootArkArea: "uploads" } },
    ],
    [{ id: "b", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/root/b", rootArkFolderId: "root", rootArkArea: "uploads" } }],
  ];
  const drive = { files: { list: async ({ fields, pageToken }) => {
    assert.equal(pageToken, page === 0 ? undefined : "next");
    const files = pages[page++] || [];
    return { data: { files, nextPageToken: page === 1 ? "next" : undefined } };
  }, get: async ({ fileId }) => ({ data: pages.flat().find((file) => file.id === fileId) }), delete: async ({ fileId }) => deleted.push(fileId) } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });
  assert.deepEqual(await storage.list("root"), [
    { name: "a", id: "a", key: "rootark/uploads/root/a", size: 4, uploadedAt: "2026-10-01T00:00:00.000Z" },
    { name: "b", id: "b", key: "rootark/uploads/root/b" },
  ]);
  page = 0;
  assert.equal(await storage.removePrefix("rootark/uploads/root"), true);
  assert.deepEqual(deleted, ["a", "b"]);
});

test("Google Drive prefix removal ignores matching tags outside its parent or canonical prefix", async () => {
  const key = "rootark/uploads/root/owned.txt";
  const files = [
    { id: "owned", parents: ["parent"], appProperties: { rootArkKey: key, rootArkFolderId: "root", rootArkArea: "uploads" } },
    { id: "outside-parent", parents: ["other-parent"], appProperties: { rootArkKey: "rootark/uploads/root/outside.txt", rootArkFolderId: "root", rootArkArea: "uploads" } },
    { id: "wrong-prefix", parents: ["parent"], appProperties: { rootArkKey: "other/uploads/root/unrelated.txt", rootArkFolderId: "root", rootArkArea: "uploads" } },
  ];
  const deleted = [];
  const checked = [];
  const drive = { files: {
    list: async ({ pageToken }) => ({ data: { files: pageToken ? [] : files } }),
    get: async ({ fileId }) => { checked.push(fileId); return { data: files.find((file) => file.id === fileId) }; },
    delete: async ({ fileId }) => deleted.push(fileId),
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });

  assert.equal(await storage.removePrefix("rootark/uploads/root"), true);
  assert.deepEqual(checked, ["owned"]);
  assert.deepEqual(deleted, ["owned"]);
});

test("Google Drive prefix removal rechecks ownership immediately before deletion", async () => {
  const listed = { id: "moved", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/root/file.txt", rootArkFolderId: "root", rootArkArea: "uploads" } };
  const deleted = [];
  const drive = { files: {
    list: async () => ({ data: { files: [listed] } }),
    get: async () => ({ data: { ...listed, parents: ["other-parent"] } }),
    delete: async ({ fileId }) => deleted.push(fileId),
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });

  await assert.rejects(storage.removePrefix("rootark/uploads/root"), { code: "provider_error" });
  assert.deepEqual(deleted, []);
});

test("Google Drive prefix removal parses folder identity relative to a multi-segment configured prefix", async () => {
  const owned = { id: "owned", parents: ["parent"], appProperties: { rootArkKey: "tenant/rootark/uploads/team/file.txt", rootArkFolderId: "team", rootArkArea: "uploads" } };
  const deleted = [];
  const drive = { files: {
    list: async () => ({ data: { files: [owned] } }),
    get: async () => ({ data: owned }),
    delete: async ({ fileId }) => deleted.push(fileId),
  } };
  const storage = createCloudStorage({ provider: "gdrive", prefix: "tenant/rootark", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });

  assert.equal(await storage.removePrefix("tenant/rootark/uploads/team"), true);
  assert.deepEqual(deleted, ["owned"]);
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
  const owned = { id: "file", parents: ["parent"], appProperties: { rootArkKey: "rootark/uploads/root/file.txt", rootArkFolderId: "root", rootArkArea: "uploads" } };
  const drive = { files: {
    list: async () => ({ data: { files: mode === "missing" ? [] : [owned] } }),
    get: async ({ alt }) => ({ data: alt === "media"
      ? mode === "failure" ? new Readable({ read() { this.push("partial"); this.destroy(new Error("failure")); } }) : Readable.from("content")
      : owned }),
  } };
  const storage = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "parent" }, createGoogleDriveClient: async () => drive });
  assert.equal(await storage.download("root", "file.txt", target), true);
  assert.equal(fs.readFileSync(target, "utf8"), "content");
  fs.rmSync(target);
  mode = "missing";
  assert.equal(await storage.download("root", "missing.txt", target), false);
  mode = "failure";
  await assert.rejects(storage.download("root", "file.txt", target), { code: "provider_error" });
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
