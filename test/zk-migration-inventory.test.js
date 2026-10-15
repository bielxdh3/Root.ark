"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const repositoryRoot = path.resolve(__dirname, "..");
const scriptPath = path.join(repositoryRoot, "scripts", "zk-migration-inventory.js");
const markerName = ".rootark-disposable-fixture";
const markerValue = "rootark-zk-inventory-fixture-v1\n";

function createFixture(t, records, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-inventory-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));

  if (options.marker !== false) {
    fs.writeFileSync(path.join(directory, markerName), markerValue, { mode: 0o600 });
  }
  if (options.metadata !== false) {
    const metadata = typeof records === "string" ? records : JSON.stringify(records);
    fs.writeFileSync(path.join(directory, "encrypted-files.json"), metadata, { mode: 0o600 });
  }
  return directory;
}

function runInventory(directory, { preloadPath, env = {} } = {}) {
  const args = [...(preloadPath ? ["--require", preloadPath] : []), scriptPath];
  if (directory !== undefined) args.push("--source-dir", directory);
  return spawnSync(process.execPath, args, {
    cwd: repositoryRoot,
    env: { ...process.env, ...env },
    encoding: "utf8",
    windowsHide: true,
  });
}

function readReport(result) {
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  return JSON.parse(result.stdout);
}

test("requires an explicit absolute disposable fixture path", (t) => {
  const missing = runInventory();
  assert.equal(missing.status, 2);
  assert.equal(missing.stdout, "");

  const relative = spawnSync(process.execPath, [scriptPath, "--source-dir", "data"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    windowsHide: true,
  });
  assert.equal(relative.status, 2);
  assert.equal(relative.stdout, "");

  const unmarked = createFixture(t, {}, { marker: false });
  const rejected = runInventory(unmarked);
  assert.equal(rejected.status, 2);
  assert.equal(rejected.stdout, "");

  const outsideTemp = path.resolve(os.tmpdir(), "..");
  const outsideTempResult = runInventory(outsideTemp);
  assert.equal(outsideTempResult.status, 2);
  assert.equal(outsideTempResult.stdout, "");
  assert.match(outsideTempResult.stderr, /temporary directory/);
});

test("reports only allowlisted metadata with per-run opaque references and unknown joins", (t) => {
  const fixture = createFixture(t, {
    "private-folder/alice-secret-name.txt": {
      encryptionLevel: "dual",
      originalFilename: "alice-secret-name.txt",
      uploadedBy: "PRIVATE-USERNAME-SHOULD-NOT-APPEAR",
      accessControl: {
        owner: "PRIVATE-OWNER-SHOULD-NOT-APPEAR",
        authorizedUsers: ["PRIVATE-AUTHORIZED-USER-SHOULD-NOT-APPEAR"],
      },
      password: "PRIVATE-PASSWORD-SHOULD-NOT-APPEAR",
      token: "PRIVATE-TOKEN-SHOULD-NOT-APPEAR",
      masterKey: "PRIVATE-MASTER-KEY-SHOULD-NOT-APPEAR",
      deviceKey: "PRIVATE-DEVICE-KEY-SHOULD-NOT-APPEAR",
      salt: "PRIVATE-SALT-SHOULD-NOT-APPEAR",
      layers: [{ iv: "PRIVATE-IV-SHOULD-NOT-APPEAR", authTag: "PRIVATE-TAG-SHOULD-NOT-APPEAR" }],
    },
    "opaque-ref-two": { encryptionLevel: "password", originalFilename: "ANOTHER-PRIVATE-NAME" },
    "legacy-without-explicit-mode": { uploadedBy: "PRIVATE-USER-2" },
  });
  const envContent = "PRIVATE-ENV-CREDENTIAL-SHOULD-NOT-APPEAR";
  const uploadContent = "PRIVATE-FILE-CONTENT-SHOULD-NOT-APPEAR";
  fs.writeFileSync(path.join(fixture, ".env"), envContent, { mode: 0o600 });
  fs.mkdirSync(path.join(fixture, "uploads"));
  fs.writeFileSync(path.join(fixture, "uploads", "payload.bin"), uploadContent, { mode: 0o600 });
  const sourceEntriesBefore = fs.readdirSync(fixture).sort();
  const sourceBefore = [
    fs.readFileSync(path.join(fixture, markerName)),
    fs.readFileSync(path.join(fixture, "encrypted-files.json")),
    fs.readFileSync(path.join(fixture, ".env")),
    fs.readFileSync(path.join(fixture, "uploads", "payload.bin")),
  ];

  const first = readReport(runInventory(fixture));
  const second = readReport(runInventory(fixture));
  const output = JSON.stringify(first);

  assert.equal(first.schema, "rootark-migration-inventory-v1");
  assert.equal(first.scope, "explicit-disposable-fixture-legacy-metadata-only");
  assert.equal(first.readOnly, true);
  assert.equal(first.fullMigrationCoverage, false);
  assert.equal(first.recordsExamined, 3);
  assert.deepEqual(first.objects.map(({ currentMode }) => currentMode), ["dual", "password", "server-key"]);
  assert.deepEqual(first.objects.map(({ currentLabel }) => currentLabel), Array(3).fill("legacy-encryption-mode"));
  assert.deepEqual(first.objects.map(({ migrationLabel }) => migrationLabel), Array(3).fill("not-assessed"));
  assert.deepEqual(first.objects.map(({ joinStatus }) => joinStatus), Array(3).fill("unjoined"));
  assert.deepEqual(first.objects.map(({ derivedArtifacts, backups, externalCloudCopies, deviceOrKeyAvailability }) => ({
    derivedArtifacts,
    backups,
    externalCloudCopies,
    deviceOrKeyAvailability,
  })), Array(3).fill({
    derivedArtifacts: "unknown",
    backups: "unknown",
    externalCloudCopies: "unknown",
    deviceOrKeyAvailability: "unknown",
  }));
  assert.equal(first.coverage.migrationEligibility, "unavailable-not-evaluated");
  assert.equal(first.coverage.referencesOutsideThisMetadata, "unknown");
  assert.deepEqual(first.coverage.inspected, ["encrypted-files.json"]);
  assert.notDeepEqual(first.objects.map(({ reference }) => reference), second.objects.map(({ reference }) => reference));
  assert.notEqual(first.runReference, second.runReference);

  for (const privateValue of [
    "alice-secret-name.txt",
    "PRIVATE-USERNAME-SHOULD-NOT-APPEAR",
    "PRIVATE-OWNER-SHOULD-NOT-APPEAR",
    "PRIVATE-AUTHORIZED-USER-SHOULD-NOT-APPEAR",
    "PRIVATE-PASSWORD-SHOULD-NOT-APPEAR",
    "PRIVATE-TOKEN-SHOULD-NOT-APPEAR",
    "PRIVATE-MASTER-KEY-SHOULD-NOT-APPEAR",
    "PRIVATE-DEVICE-KEY-SHOULD-NOT-APPEAR",
    "PRIVATE-SALT-SHOULD-NOT-APPEAR",
    "PRIVATE-IV-SHOULD-NOT-APPEAR",
    "PRIVATE-TAG-SHOULD-NOT-APPEAR",
    "PRIVATE-ENV-CREDENTIAL-SHOULD-NOT-APPEAR",
    "PRIVATE-FILE-CONTENT-SHOULD-NOT-APPEAR",
    "ANOTHER-PRIVATE-NAME",
    fixture,
  ]) {
    assert.equal(output.includes(privateValue), false, `report leaked ${privateValue}`);
  }

  assert.deepEqual([
    fs.readFileSync(path.join(fixture, markerName)),
    fs.readFileSync(path.join(fixture, "encrypted-files.json")),
    fs.readFileSync(path.join(fixture, ".env")),
    fs.readFileSync(path.join(fixture, "uploads", "payload.bin")),
  ], sourceBefore);
  assert.deepEqual(fs.readdirSync(fixture).sort(), sourceEntriesBefore);
});

test("rejects symlinked fixture roots without following them", (t) => {
  const fixture = createFixture(t, { "opaque-ref": { encryptionLevel: "server-key" } });
  const link = path.join(path.dirname(fixture), `${path.basename(fixture)}-link`);
  fs.symlinkSync(fixture, link, process.platform === "win32" ? "junction" : "dir");
  t.after(() => fs.unlinkSync(link));

  const result = runInventory(link);
  assert.equal(result.status, 2);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /symlinks are not allowed/);
});

test("rejects malformed, unsupported, oversized, and over-count metadata", (t) => {
  for (const input of [
    "{broken",
    "[]",
    '{"one":{"encryptionLevel":"dual",}}',
    '{"one":{"invalid-number":-}}',
    '{"one":{"encryptionLevel":"dual","encryptionLevel":"password"}}',
    '{"one":{"nested":{"field":1,"field":2}}}',
    '{"one":{"encryptionLevel":"dual"},"one":{"encryptionLevel":"password"}}',
    { one: null },
    { one: { encryptionLevel: "none" } },
    { one: { padding: "x".repeat(65 * 1024) } },
  ]) {
    const fixture = createFixture(t, input);
    const result = runInventory(fixture);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, "");
  }

  const oversizedFixture = createFixture(t, {}, { metadata: false });
  fs.writeFileSync(path.join(oversizedFixture, "encrypted-files.json"), " ".repeat(4 * 1024 * 1024 + 1));
  const oversizedResult = runInventory(oversizedFixture);
  assert.equal(oversizedResult.status, 2);
  assert.equal(oversizedResult.stdout, "");
  assert.match(oversizedResult.stderr, /size limit/);

  const tooMany = Object.fromEntries(Array.from({ length: 5001 }, (_, index) => [`object-${index}`, { encryptionLevel: "server-key" }]));
  const fixture = createFixture(t, tooMany);
  const result = runInventory(fixture);
  assert.equal(result.status, 2);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /record count exceeds the limit/);
});

test("rejects a fixture path swap when adjacent 64-bit file IDs collide as Numbers", (t) => {
  const fixture = createFixture(t, { "opaque-fixture": { encryptionLevel: "server-key" } });
  const preloadPath = path.join(os.tmpdir(), "rootark-zk-id-precision-" + process.pid + ".cjs");
  t.after(() => fs.rmSync(preloadPath, { force: true }));
  fs.writeFileSync(preloadPath, String.raw`const fs = require("node:fs");
const path = require("node:path");
const target = path.resolve(process.env.ROOTARK_ZK_IDENTITY_TARGET);
const adjacent = 9_007_199_254_740_992n;
const originalOpen = fs.openSync;
const originalFstat = fs.fstatSync;
const originalLstat = fs.lstatSync;
const originalClose = fs.closeSync;
const descriptors = new Set();
const sameType = (stats, bigint, ino) => new Proxy(stats, { get(object, property, receiver) {
  if (property === "dev") return bigint ? 1n : 1;
  if (property === "ino") return bigint ? ino : Number(ino);
  return Reflect.get(object, property, receiver);
} });
fs.openSync = function (file, ...args) {
  const descriptor = originalOpen.call(this, file, ...args);
  if (path.resolve(String(file)) === target) descriptors.add(descriptor);
  return descriptor;
};
fs.fstatSync = function (descriptor, ...args) {
  const stats = originalFstat.call(this, descriptor, ...args);
  return descriptors.has(descriptor) ? sameType(stats, args[0]?.bigint === true, adjacent) : stats;
};
fs.lstatSync = function (file, ...args) {
  const stats = originalLstat.call(this, file, ...args);
  return path.resolve(String(file)) === target ? sameType(stats, args[0]?.bigint === true, adjacent + 1n) : stats;
};
fs.closeSync = function (descriptor) {
  descriptors.delete(descriptor);
  return originalClose.call(this, descriptor);
};
`);
  const result = runInventory(fixture, {
    preloadPath,
    env: { ROOTARK_ZK_IDENTITY_TARGET: path.join(fixture, "encrypted-files.json") },
  });
  assert.equal(Number(9_007_199_254_740_992n), Number(9_007_199_254_740_993n));
  assert.equal(result.status, 2, result.stderr || result.stdout);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /fixture file changed while opening/);
});
