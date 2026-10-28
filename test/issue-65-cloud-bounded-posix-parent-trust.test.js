"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Readable } = require("node:stream");
const { spawnSync } = require("node:child_process");
const Module = require("node:module");

// Exercise the real provider adapter without loading the unrelated auth/HPKE
// server stack: only its error presentation dependency is replaced. The
// filesystem admission, transport path and provider mocks are unmodified.
const originalLoad = Module._load;
let createCloudStorage;
try {
  Module._load = function (request, parent, isMain) {
    if (request === "../src/services/deploymentResilience"
      && parent?.filename === require.resolve("../services/cloudStorage")) {
      return { normalizeProviderError: (error) => error };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  ({ createCloudStorage } = require("../services/cloudStorage"));
} finally { Module._load = originalLoad; }

const posixOnly = process.platform === "win32";

function driveFixture(onProviderRead = () => {}) {
  const body = Buffer.from("DISPOSABLE_PRIVATE_CIPHERTEXT");
  const fileId = "pinned-fixture-id";
  let providerReads = 0;
  const cloud = createCloudStorage({
    provider: "gdrive", gdrive: { folderId: "fixture-parent" },
    createGoogleDriveClient: async () => ({ files: {
      get: async ({ fileId: requested, alt }) => {
        providerReads++;
        onProviderRead();
        assert.equal(requested, fileId);
        if (alt === "media") return { status: 200, data: Readable.from([body]) };
        return { data: { id: fileId, parents: ["fixture-parent"],
          appProperties: { rootArkKey: cloud.key("fixture-folder", "opaque.ct", "uploads"),
            rootArkFolderId: "fixture-folder", rootArkArea: "uploads" } } };
      },
    } }),
  });
  return { cloud, body, fileId, get providerReads() { return providerReads; } };
}

test("bounded cloud download must reject other-UID-writable POSIX parent before any stage or provider GET", {
  skip: posixOnly }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-cloud-posix-hostile-"));
  const unsafeParent = path.join(root, "attacker-can-rename");
  fs.mkdirSync(unsafeParent, { mode: 0o777 });
  fs.chmodSync(unsafeParent, 0o777);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fixture = driveFixture();
  let stageCreations = 0;
  const original = fs.mkdtempSync;
  fs.mkdtempSync = function (prefix, ...args) {
    if (String(prefix).includes(".rootark-cloud-cache-")) stageCreations++;
    return original.call(this, prefix, ...args);
  };
  try {
    await assert.rejects(fixture.cloud.download("fixture-folder", "opaque.ct",
      path.join(unsafeParent, "opaque.ct"), "uploads", () => true,
      { providerFileId: fixture.fileId, maxBytes: fixture.body.length }));
  } finally { fs.mkdtempSync = original; }
  assert.equal(stageCreations, 0, "unsafe ancestor must be rejected before any filesystem effect");
  assert.equal(fixture.providerReads, 0, "unsafe ancestor must be rejected before remote GET");
  assert.deepEqual(fs.readdirSync(unsafeParent), []);
});

test("bounded cloud download accepts owner-private 0700 parent below trusted sticky temp ancestry", {
  skip: posixOnly }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-cloud-posix-private-"));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fixture = driveFixture();
  const target = path.join(root, "opaque.ct");
  assert.equal(await fixture.cloud.download("fixture-folder", "opaque.ct",
    target, "uploads", () => true,
    { providerFileId: fixture.fileId, maxBytes: fixture.body.length }), true);
  assert.deepEqual(fs.readFileSync(target), fixture.body);
  assert.ok(fixture.providerReads >= 2);
});

test("real lower UID can rename a service-owned 0700 stage inside an unsafe 0777 parent", {
  skip: posixOnly || typeof process.getuid !== "function" || process.getuid() !== 0,
}, (t) => {
  const probe = spawnSync("runuser", ["--version"], { windowsHide: true });
  if (probe.status !== 0) { t.skip("runuser unavailable"); return; }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-cloud-lowuid-proof-"));
  fs.chmodSync(root, 0o755);
  const unsafe = path.join(root, "other-uid-writable");
  fs.mkdirSync(unsafe, { mode: 0o777 });
  fs.chmodSync(unsafe, 0o777);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const stage = fs.mkdtempSync(path.join(unsafe, ".rootark-cloud-cache-"));
  fs.chmodSync(stage, 0o700);
  const renamed = `${stage}-redirected`;
  const child = spawnSync("runuser", ["-u", "nobody", "--", process.execPath, "-e",
    "require('node:fs').renameSync(process.argv[1],process.argv[2])", stage, renamed],
  { encoding: "utf8", windowsHide: true, timeout: 5000 });
  assert.equal(child.status, 0,
    "foreign UID must really be able to redirect the nominally private stage through its 0777 parent");
  assert.equal(fs.existsSync(stage), false);
  assert.equal(fs.statSync(renamed).isDirectory(), true);
});

test("bounded cloud download accepts service-owned 0755 ordinary folders with no foreign write", {
  skip: posixOnly }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-cloud-posix-normal-"));
  fs.chmodSync(root, 0o755);
  const parent = path.join(root, "normal-folder");
  fs.mkdirSync(parent, { mode: 0o755 });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fixture = driveFixture();
  const target = path.join(parent, "opaque.ct");
  assert.equal(await fixture.cloud.download("fixture-folder", "opaque.ct",
    target, "uploads", () => true,
    { providerFileId: fixture.fileId, maxBytes: fixture.body.length }), true);
  assert.deepEqual(fs.readFileSync(target), fixture.body);
});

test("bounded cloud download rejects permissions changed while provider GET is pending", {
  skip: posixOnly }, async (t) => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-cloud-posix-flip-"));
  fs.chmodSync(parent, 0o700);
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  let changed = false;
  const fixture = driveFixture(() => {
    if (!changed) { fs.chmodSync(parent, 0o777); changed = true; }
  });
  const target = path.join(parent, "opaque.ct");
  await assert.rejects(fixture.cloud.download("fixture-folder", "opaque.ct",
    target, "uploads", () => true,
    { providerFileId: fixture.fileId, maxBytes: fixture.body.length }));
  assert.equal(changed, true, "fixture must actually change the DACL-equivalent POSIX mode");
  assert.equal(fs.existsSync(target), false, "no foreign-writable destination may be published");
});
