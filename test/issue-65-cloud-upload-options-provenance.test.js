"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const resilience = require.resolve("../src/services/deploymentResilience");
require.cache[resilience] = { id: resilience, filename: resilience,
  loaded: true, exports: { normalizeProviderError: (error) => error } };
const { createCloudStorage } = require("../services/cloudStorage");

const sha = (data) => crypto.createHash("sha256").update(data).digest("hex");

function fixture(t) {
  const dir = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA,
      "zk65-cloud-opt-" + crypto.randomBytes(8).toString("hex"))
    : fs.mkdtempSync(path.join(os.tmpdir(), "zk65-cloud-opt-"));
  if (process.platform === "win32") {
    require("../services/chunkUploadWindowsAcl").ensureWindowsChunkUploadRoot(dir);
  }
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "ciphertext.ct");
  const original = Buffer.from("signed caller ciphertext");
  fs.writeFileSync(file, original, { flag: "wx", mode: 0o600 });
  const remote = [];
  const cloud = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "root" },
    createGoogleDriveClient: async () => ({ files: {
      get: async () => { throw Object.assign(new Error("missing"), { status: 404 }); },
      create: async ({ requestBody, media }) => {
        remote.push({ id: requestBody.id, data: Buffer.concat(await Array.fromAsync(media.body)) });
        return { data: { id: requestBody.id } };
      },
    } }),
  });
  return { file, original, remote, cloud };
}

test("bounded Drive refuses an inherited providerFileId instead of trusting prototype-selected destination", async (t) => {
  const { file, original, remote, cloud } = fixture(t);
  const options = Object.assign(Object.create({ providerFileId: "attacker-target" }), {
    zk1BoundedBytes: original.length, zk1ExpectedSha256: sha(original),
  });
  await assert.rejects(cloud.upload(file, "folder", "ciphertext.ct", "uploads", options),
    { code: "configuration" });
  assert.equal(remote.length, 0, "invalid options must be rejected before any provider PUT");
});

test("bounded Drive refuses an accessor-backed expected digest, not a mutable stand-in for caller evidence", async (t) => {
  const { file, original, remote, cloud } = fixture(t);
  let reads = 0;
  const options = { providerFileId: "pinned", zk1BoundedBytes: original.length };
  Object.defineProperty(options, "zk1ExpectedSha256", {
    enumerable: true, get() { reads += 1; return sha(original); },
  });
  await assert.rejects(cloud.upload(file, "folder", "ciphertext.ct", "uploads", options),
    { code: "configuration" });
  assert.equal(reads, 0, "do not execute an untrusted digest accessor");
  assert.equal(remote.length, 0);
});

test("bounded Drive never silently downgrades malformed array options to legacy upload", async (t) => {
  const { file, original, remote, cloud } = fixture(t);
  const options = [];
  options.providerFileId = "pinned";
  options.zk1BoundedBytes = original.length;
  options.zk1ExpectedSha256 = sha(original);
  await assert.rejects(cloud.upload(file, "folder", "ciphertext.ct", "uploads", options),
    { code: "configuration" });
  assert.equal(remote.length, 0);
});

test("bounded Drive still accepts own immutable digest and pinned destination without modifying legacy API", async (t) => {
  const { file, original, remote, cloud } = fixture(t);
  const result = await cloud.upload(file, "folder", "ciphertext.ct", "uploads", {
    providerFileId: "pinned", zk1BoundedBytes: original.length,
    zk1ExpectedSha256: sha(original),
  });
  assert.equal(result.id, "pinned");
  assert.deepEqual(remote, [{ id: "pinned", data: original }]);
});
