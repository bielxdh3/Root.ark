"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { Readable } = require("node:stream");
const { execFileSync } = require("node:child_process");
const os = require("node:os");
const test = require("node:test");
const { createCloudStorage } = require("../services/cloudStorage");
const { createZk1PrivateCloudStagingDirectory } =
  require("../src/services/zk1PrivateCloudStagingDirectory");

for (const provider of ["s3", "gdrive"]) {
  for (const attack of [false, true]) {
    test(`${provider} bounded GET ${attack ? "rejects stage junction swap without overwriting foreign file" : "reads into its private parent"}`, async (t) => {
      const directory = await createZk1PrivateCloudStagingDirectory("zk65-cloud-get-stage-");
      t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5 }));
      const destination = path.join(directory, "ciphertext.ct");
      const foreign = path.join(directory, "foreign");
      fs.mkdirSync(foreign);
      const outside = path.join(foreign, "ciphertext.ct");
      fs.writeFileSync(outside, "FOREIGN_SENTINEL_MUST_SURVIVE", { flag: "wx" });
      const bytes = Buffer.from("OPAQ_CIPHER_BOUNDED_GET_FIXTURE");
      let swaps = 0;
      const swapDuringProviderAwait = () => {
        if (!attack) return;
        const name = fs.readdirSync(directory).find((entry) => entry.startsWith(".rootark-cloud-cache-"));
        assert.ok(name, "the provider is awaited only after the private staging directory exists");
        const original = path.join(directory, name);
        // With an already-open staging FD, Windows can deny the rename itself.
        // The attempt must still reach the actual provider-await boundary.
        swaps++;
        fs.renameSync(original, `${original}-held`);
        fs.symlinkSync(foreign, original, process.platform === "win32" ? "junction" : "dir");
      };
      const cloud = createCloudStorage(provider === "s3" ? {
        provider: "s3", s3: { bucket: "disposable" },
        createS3Client: async () => ({ async send() {
          swapDuringProviderAwait();
          return { $metadata: { httpStatusCode: 200 }, ContentLength: bytes.length,
            Body: Readable.from([bytes]) };
        } }),
      } : {
        provider: "gdrive", gdrive: { folderId: "disposable-root" },
        createGoogleDriveClient: async () => ({ files: {
          get: async ({ alt }) => {
            if (alt === "media") {
              swapDuringProviderAwait();
              return { status: 200, headers: { "content-length": String(bytes.length) },
                data: Readable.from([bytes]) };
            }
            return { data: { id: "fixture-pinned-id", parents: ["disposable-root"],
              appProperties: { rootArkKey: cloud.key("folder", "name.ct", "uploads"),
                rootArkFolderId: "folder", rootArkArea: "uploads" } } };
          },
        } }),
      });
      const opts = { maxBytes: bytes.length,
        ...(provider === "gdrive" ? { providerFileId: "fixture-pinned-id" } : {}) };
      let result;
      try { result = await cloud.download("folder", "name.ct", destination,
        "uploads", () => true, opts); }
      catch (error) { result = `${error?.code || "denied"}: ${error?.message || ""}`; }
      assert.equal(fs.readFileSync(outside, "utf8"), "FOREIGN_SENTINEL_MUST_SURVIVE",
        "a swapped disposable stage must NEVER overwrite an unrelated existing file");
      if (attack) {
        assert.equal(swaps, 1, `exercise an actual NTFS junction swap during GET; result=${result}`);
        assert.notEqual(result, true, "a changed stage must never be credited as a successful GET");
      } else {
        assert.equal(result, true, "an authorized private destination must still work");
        assert.deepEqual(fs.readFileSync(destination), bytes);
      }
    });
  }
}

test("Windows bounded GET rejects a writable shared-ACL parent before any S3 request", async (t) => {
  if (process.platform !== "win32") return t.skip("Windows DACL-specific admission check");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-cloud-get-unsafe-acl-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5 }));
  execFileSync("C:\\Windows\\System32\\icacls.exe", [directory,
    "/grant", "*S-1-5-11:(OI)(CI)M"], { windowsHide: true });
  const destination = path.join(directory, "ciphertext.ct");
  let remoteGets = 0;
  const cloud = createCloudStorage({ provider: "s3", s3: { bucket: "fixture" },
    createS3Client: async () => ({ async send() { remoteGets++; return {
      $metadata: { httpStatusCode: 200 }, ContentLength: 1,
      Body: Readable.from([Buffer.from("x")]),
    }; } }),
  });
  await assert.rejects(cloud.download("folder", "name.ct", destination,
    "uploads", () => true, { maxBytes: 1 }), { code: "provider_error" });
  assert.equal(remoteGets, 0, "unsafe destination ACL must fail before remote side effects");
  assert.equal(fs.existsSync(destination), false);
});
