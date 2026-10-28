"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const resilience = require.resolve("../src/services/deploymentResilience");
require.cache[resilience] = { id: resilience, filename: resilience,
  loaded: true, exports: { normalizeProviderError: (error) => error } };
const { createCloudStorage } = require("../services/cloudStorage");

test("foreign UID cannot redirect a legacy cloud upload through a symlinked ancestor", async (t) => {
  if (process.platform !== "linux" || process.getuid?.() !== 0) {
    return t.skip("requires Linux root to create a genuinely foreign UID fixture");
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w154-cloud-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const tenant = path.join(root, "tenant");
  const outside = path.join(root, "outside");
  fs.mkdirSync(tenant, { mode: 0o777 });
  fs.chmodSync(tenant, 0o777);
  fs.mkdirSync(outside, { mode: 0o700 });
  fs.writeFileSync(path.join(outside, "secret.txt"), "private-file-outside-authorized-root", { mode: 0o600 });
  fs.chmodSync(root, 0o755);

  const link = path.join(tenant, "alias");
  const attacker = spawnSync("runuser", ["-u", "nobody", "--", "ln", "-s", outside, link],
    { encoding: "utf8" });
  assert.equal(attacker.status, 0, attacker.stderr);
  const transmitted = [];
  const cloud = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "root" },
    createGoogleDriveClient: async () => ({ files: {
      list: async () => ({ data: { files: [] } }),
      create: async ({ media }) => {
        transmitted.push(Buffer.concat(await Array.fromAsync(media.body)));
        return { data: { id: "remote-created-object" } };
      },
    } }) });
  await assert.rejects(cloud.upload(path.join(link, "secret.txt"), "folder", "upload.txt"),
    /unsafe|untrusted|invalid|source/i);
  assert.equal(transmitted.length, 0, "private bytes must never reach provider IO");
});

test("ordinary legacy cloud uploads from a private regular source remain available", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w154-legacy-safe-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, "source.txt");
  const expected = Buffer.from("synthetic-regular-legacy-cloud-source");
  fs.writeFileSync(source, expected, { flag: "wx", mode: 0o600 });
  const transmitted = [];
  const cloud = createCloudStorage({ provider: "gdrive", gdrive: { folderId: "root" },
    createGoogleDriveClient: async () => ({ files: {
      list: async () => ({ data: { files: [] } }),
      create: async ({ media }) => {
        transmitted.push(Buffer.concat(await Array.fromAsync(media.body)));
        return { data: { id: "legacy-allowed" } };
      },
    } }) });
  const uploaded = await cloud.upload(source, "folder", "source.txt");
  assert.equal(uploaded.id, "legacy-allowed");
  assert.deepEqual(transmitted, [expected]);
});
