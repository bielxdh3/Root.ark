"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { inspectZk1CloudMigrationReadiness } = require("../src/services/zk1ProviderMigrationPreflight");
const { createCloudStorage } = require("../services/cloudStorage");

function provider(kind = "s3") {
  const activity = [];
  let context = "a".repeat(64);
  const entries = [{ provider: kind, providerIdentity: "provider-private-id",
    key: "private/bucket/uploads/user/my-secrets.txt", area: "uploads",
    folderId: "user", name: "my-secrets.txt" }];
  return {
    activity,
    entries,
    status() { activity.push("status"); return { provider: kind, enabled: true }; },
    enabled() { activity.push("enabled"); return true; },
    async resolveInventoryContext() { activity.push("identity"); return context; },
    async inventory() { activity.push("inventory"); return entries; },
    setContext(value) { context = value; },
    async upload() { activity.push("UNSAFE_UPLOAD"); throw new Error("write attempt"); },
    async remove() { activity.push("UNSAFE_DELETE"); throw new Error("write attempt"); },
    async removePrefix() { activity.push("UNSAFE_PURGE"); throw new Error("write attempt"); },
    async download() { activity.push("UNSAFE_CACHE_WRITE"); throw new Error("write attempt"); },
  };
}

test("dry-run inventory uses real cloud storage's read-only API and never exports private names", async () => {
  const p = provider();
  const first = await inspectZk1CloudMigrationReadiness({ cloudStorage: p });
  const second = await inspectZk1CloudMigrationReadiness({ cloudStorage: p });
  assert.deepEqual(p.activity, ["status", "enabled", "identity", "inventory", "identity",
    "status", "enabled", "identity", "inventory", "identity"]);
  assert.equal(first.schema, "rootark-zk1-cloud-migration-readiness/v1");
  assert.equal(first.readOnly, true);
  assert.equal(first.canMigrate, false);
  assert.equal(first.rollbackReady, false);
  assert.equal(first.objects.length, 1);
  assert.equal(first.objects[0].area, "uploads");
  assert.equal(first.objects[0].reference.length, 43);
  assert.notEqual(first.objects[0].reference, second.objects[0].reference,
    "private cross-run identifiers must not be correlatable from reports");
  assert.deepEqual(first.blockers, ["missing-version-history", "missing-backup-inventory",
    "missing-trash-sync-webdav-inventory", "missing-content-integrity-proof",
    "missing-authorized-key-recovery", "missing-physical-migration-fence"]);
  const serialized = JSON.stringify(first);
  for (const secret of ["private/bucket", "provider-private-id", "my-secrets",
    "user", "a".repeat(64)]) assert.equal(serialized.includes(secret), false);
});

test("rejects changed cloud identity, malformed inventory and unavailable providers fail closed", async () => {
  const p = provider("gdrive");
  p.inventory = async () => { p.activity.push("inventory"); p.setContext("b".repeat(64)); return p.entries; };
  await assert.rejects(inspectZk1CloudMigrationReadiness({ cloudStorage: p }),
    /ZK_MIGRATION_PREFLIGHT_UNAVAILABLE/);
  const q = provider();
  q.entries.push({ ...q.entries[0] });
  await assert.rejects(inspectZk1CloudMigrationReadiness({ cloudStorage: q }),
    /ZK_MIGRATION_PREFLIGHT_UNAVAILABLE/);
  q.entries.length = 0;
  q.entries.push({ ...provider().entries[0], area: "backup" });
  await assert.rejects(inspectZk1CloudMigrationReadiness({ cloudStorage: q }),
    /ZK_MIGRATION_PREFLIGHT_UNAVAILABLE/);
  const unsupported = provider("local");
  await assert.rejects(inspectZk1CloudMigrationReadiness({ cloudStorage: unsupported }),
    /ZK_MIGRATION_PREFLIGHT_UNAVAILABLE/);
});

test("existing S3 inventory adapter is consumed read-only using a disposable fake backend", async () => {
  let listingCalls = 0;
  const s3 = createCloudStorage({ provider: "s3", prefix: "rootark", rootFolderId: "root",
    s3: { bucket: "disposable-bucket", region: "us-east-1",
      endpoint: "https://unused.invalid", principalId: "isolated-lab-principal" },
    createS3Client: async () => ({
      async send(command) {
        listingCalls++;
        assert.equal(command.constructor.name, "ListObjectsV2Command");
        assert.equal(command.input.Bucket, "disposable-bucket");
        assert.equal(command.input.Prefix, "rootark/");
        return { Contents: [{ Key: "rootark/uploads/folder/private-name.bin" }],
          NextContinuationToken: undefined };
      },
    }),
  });
  const result = await inspectZk1CloudMigrationReadiness({ cloudStorage: s3 });
  assert.equal(listingCalls, 1);
  assert.equal(result.provider, "s3");
  assert.equal(result.objects.length, 1);
  assert.equal(JSON.stringify(result).includes("private-name.bin"), false);
});

test("existing Google Drive inventory adapter is consumed read-only using a disposable fake backend", async () => {
  let listingCalls = 0;
  const drive = createCloudStorage({ provider: "gdrive", prefix: "rootark",
    gdrive: { folderId: "isolated-drive-folder" },
    createGoogleDriveClient: async () => ({
      about: { async get() { return { data: { user: { permissionId: "isolated-user" } } }; } },
      files: { async list() {
        listingCalls++;
        return { data: { files: [{ id: "private-drive-file-id", name: "private.pdf",
          parents: ["isolated-drive-folder"],
          appProperties: { rootArkKey: "rootark/uploads/folder/private.pdf",
            rootArkFolderId: "folder", rootArkArea: "uploads" } }] } };
      } },
    }),
  });
  const result = await inspectZk1CloudMigrationReadiness({ cloudStorage: drive });
  assert.equal(listingCalls, 1);
  assert.equal(result.provider, "gdrive");
  assert.equal(result.objects.length, 1);
  assert.equal(JSON.stringify(result).includes("private.pdf"), false);
  assert.equal(JSON.stringify(result).includes("private-drive-file-id"), false);
});
