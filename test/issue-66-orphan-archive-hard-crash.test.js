"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");

async function physicalChild(script, args) {
  const child = spawn(process.execPath, ["-e", script, ...args],
    { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (data) => { stderr += data.toString(); });
  const code = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("orphan archive physical child timeout"));
    }, 30000);
    child.once("exit", (result) => { clearTimeout(timeout); resolve(result); });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
  });
  return { code, stderr };
}

test("issue 66: real hard crash after archive rename refuses fresh-process cold replay", {
  skip: !["linux", "win32"].includes(process.platform)
    && "requires tested Windows NTFS or Linux ext4 archive crash boundary",
}, async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-orphan-crash-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const root = path.join(dir, "device");
  const source = path.join(dir, "source");
  const storePath = path.join(dir, "store.json");
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(storePath).open();
  let unexpectedWrites = 0;
  const adapter = {
    async list(objectId = "") { return store.list("alice", objectId || null); },
    async push(operation) {
      unexpectedWrites++;
      return { status: 201, record: (await store.put("alice", operation)).record };
    },
  };
  const create = (dirName, excludedPaths = []) => new SyncEngine({
    rootDir: dirName, adapter,
    deviceId: dirName === source ? "device-a" : "device-b",
    keyEpoch: "epoch-1", compartmentId: "private", excludedPaths,
    fileKeyResolver: () => key,
  }).open();
  await fsp.mkdir(path.join(source, "PRIVATE"), { recursive: true });
  await fsp.writeFile(path.join(source, "PRIVATE", "secret.txt"), "authenticated remote bytes");
  await (await create(source)).syncOnce();
  const original = store.list("alice")[0];
  assert.ok(original && !original.tombstone);
  const device = await create(root);
  await device.syncOnce();
  device.snapshot.excludedPaths = ["private"];
  device.snapshot.excludedPathsCasefoldVersion = 1;
  await device.persistSnapshot();
  const before = unexpectedWrites;

  const crashScript = String.raw`
"use strict";
const fsp = require("node:fs/promises");
const path = require("node:path");
const { SyncEngine } = require(process.argv[1]);
const { SyncObjectStore } = require(process.argv[2]);
const root = process.argv[3];
const priorRename = fsp.rename;
fsp.rename = async (from, to, ...args) => {
  if (path.basename(String(from)) === ".rootark-sync-evictions"
    && path.basename(String(to)).startsWith(".rootark-sync-evictions-archive-")
    && path.resolve(await fsp.realpath(path.dirname(String(from))))
      === path.resolve(await fsp.realpath(root))) {
    await priorRename(from, to, ...args);
    process.exit(74); // genuine hard exit before the post-rename directory fsync
  }
  return priorRename(from, to, ...args);
};
(async () => {
  const store = await new SyncObjectStore(process.argv[4]).open();
  const sync = await new SyncEngine({
    rootDir: root, deviceId: "device-b",
    keyEpoch: "epoch-1", compartmentId: "private",
    excludedPaths: ["private"], fileKeyResolver: () => Buffer.from(process.argv[5], "base64"),
    adapter: {
      async list(id = "") { return store.list("alice", id || null); },
      async push() { process.exit(94); },
    },
  }).open();
  await sync.syncOnce();
  process.exit(92);
})().catch((error) => { process.stderr.write(String(error)); process.exit(93); });
`;
  const freshScript = String.raw`
"use strict";
const { SyncEngine } = require(process.argv[1]);
const { SyncObjectStore } = require(process.argv[2]);
(async () => {
  const store = await new SyncObjectStore(process.argv[4]).open();
  await new SyncEngine({
    rootDir: process.argv[3], deviceId: "device-b",
    keyEpoch: "epoch-1", compartmentId: "private",
    excludedPaths: [], fileKeyResolver: () => Buffer.from(process.argv[5], "base64"),
    adapter: {
      async list(id = "") { return store.list("alice", id || null); },
      async push() { process.exit(96); },
    },
  }).open();
  process.exit(92); // unsafe acceptance of an orphaned archive
})().catch((error) => {
  if (error?.code === "invalid_snapshot"
    && /Orphaned eviction archive needs independent recovery/.test(error.message)) process.exit(75);
  process.stderr.write(String(error)); process.exit(93);
});
`;
  const args = [
    require.resolve("../sync-client/rootark-sync-engine"),
    require.resolve("../src/routes/sync"),
    root, storePath, key.toString("base64"),
  ];
  const crashed = await physicalChild(crashScript, args);
  assert.equal(crashed.code, 74, `the child must die exactly after archive rename: ${crashed.stderr}`);
  const checkpoint = JSON.parse(await fsp.readFile(snapshotPath, "utf8"));
  assert.equal(checkpoint.evictionLedgerRequired, false);
  assert.equal(checkpoint.remoteOnly[original.objectId]?.reason, "evicted");
  const archived = (await fsp.readdir(root)).filter((name) =>
    name.startsWith(".rootark-sync-evictions-archive-"));
  assert.equal(archived.length, 1, "a unique on-disk archive must survive the actual hard exit");
  const archivedPath = path.join(root, archived[0]);
  const namesBeforeCold = (await fsp.readdir(archivedPath)).sort();
  assert.ok(namesBeforeCold.some((name) => name.endsWith(".prepare.json")),
    "the retained archive must contain the exact durable PREPARE evidence");
  const bytesBeforeCold = new Map(await Promise.all(namesBeforeCold.map(async (name) =>
    [name, await fsp.readFile(path.join(archivedPath, name))])));
  await assert.rejects(fsp.lstat(path.join(root, ".rootark-sync-evictions")), { code: "ENOENT" });
  // Remove only the orphaned test process lock inside the disposable fixture,
  // never a foreign or privileged root.
  await fsp.rmdir(path.join(root, ".rootark-sync.lock"));
  const restarted = await physicalChild(freshScript, args);
  assert.equal(restarted.code, 75,
    `a genuinely fresh process must refuse the orphaned archive: ${restarted.stderr}`);
  assert.equal(unexpectedWrites, before);
  assert.equal(store.list("alice").filter((item) => item.tombstone).length, 0);
  assert.equal(store.list("alice", original.objectId)[0].operationId, original.operationId);
  assert.deepEqual((await fsp.readdir(archivedPath)).sort(), namesBeforeCold,
    "cold denial must not silently remove a PREPARE or other archive record");
  for (const [name, bytes] of bytesBeforeCold) {
    assert.deepEqual(await fsp.readFile(path.join(archivedPath, name)), bytes,
      `cold denial must preserve the original bytes of ${name}`);
  }
});
