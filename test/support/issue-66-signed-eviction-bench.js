"use strict";

// Disposable, real-Ed25519 verified exclusion migration benchmark. Preparation
// is excluded from the timer, to isolate snapshot/journal write amplification.
// Usage: node test/support/issue-66-signed-eviction-bench.js 160
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const { SyncEngine } = require("../../sync-client/rootark-sync-engine");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyHistoricalAuthorizationProof } =
  require("../../sync-client/rootark-sync-authorization");

async function main() {
  const count = Number(process.argv[2]);
  if (!Number.isInteger(count) || count < 1 || count > 640) {
    throw new Error("Benchmark requires 1..640 disposable fixture files");
  }
  const temp = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue66-bench-"));
  const rootDir = path.join(temp, "device");
  try {
    await fsp.mkdir(path.join(rootDir, "PRIVATE"), { recursive: true });
    const key = crypto.randomBytes(32);
    const signing = crypto.generateKeyPairSync("ed25519");
    const publicKey = signing.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
    const records = new Map();
    const snapshotFiles = {};
    for (let index = 0; index < count; index += 1) {
      const relative = `PRIVATE/clean-${String(index).padStart(4, "0")}.txt`;
      const plaintext = Buffer.from(`verified signed owner bytes ${count}:${index}`, "utf8");
      const operation = protocol.createOperation({
        operation: "create", operationId: `bench-op-${index}`,
        objectId: `bench-object-${index}`, fileId: `bench-file-${index}`,
        versionId: `bench-version-${index}`,
        revision: { counter: 1, deviceId: "device-a" }, baseRevision: null,
        keyEpoch: "epoch-1", compartmentId: "private", deviceId: "device-a",
        metadata: { path: relative, name: path.posix.basename(relative), size: plaintext.length },
        fileKey: key, plaintext,
      });
      operation.authorization = await createAuthorizationProof(operation, {
        username: "alice", publicKey, privateKey: signing.privateKey,
      });
      records.set(operation.objectId, operation);
      snapshotFiles[relative] = {
        objectId: operation.objectId, fileId: operation.fileId,
        versionId: operation.versionId, revision: operation.revision,
        hash: crypto.createHash("sha256").update(plaintext).digest("hex"),
        deleted: false, directory: false,
      };
      await fsp.writeFile(path.join(rootDir, "PRIVATE", path.posix.basename(relative)), plaintext);
    }
    let pushes = 0;
    let verified = 0;
    const adapter = {
      async push() { pushes += 1; throw new Error("No remote mutations are allowed"); },
      async list(objectId = "") { return objectId ? records.has(objectId) ? [records.get(objectId)] : []
        : [...records.values()]; },
    };
    const options = {
      rootDir, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
      compartmentId: "private", fileKeyResolver: () => key,
      excludedPaths: ["private"], requireAuthorization: true,
      verifyIncoming: async (operation) => {
        verified += 1;
        return verifyHistoricalAuthorizationProof(operation.authorization, operation, {
          username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
          revokedDeviceIds: [],
        });
      },
    };
    const sync = await new SyncEngine(options).open();
    sync.snapshot.files = snapshotFiles;
    sync.snapshot.excludedPaths = ["private"];
    sync.snapshot.excludedPathsCasefoldVersion = 1;
    await sync.persistSnapshot();
    let snapshotBytes = 0;
    let snapshotWrites = 0;
    let observedWrites = 0;
    const originalPersist = sync.persistSnapshot.bind(sync);
    sync.persistSnapshot = async () => {
      snapshotWrites += 1;
      snapshotBytes += Buffer.byteLength(JSON.stringify(sync.snapshot));
      return originalPersist();
    };
    const originalObserve = sync.journal.observeAdmission.bind(sync.journal);
    sync.journal.observeAdmission = async (...args) => {
      observedWrites += 1;
      return originalObserve(...args);
    };
    const started = process.hrtime.bigint();
    const result = await sync.withMutationLock(() => sync._applyExcludedPaths());
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.equal(result.evicted, count);
    assert.equal(pushes, 0);
    assert.equal(observedWrites, 0, "verified eviction does not apply inbound envelope or write observed[]");
    assert.equal(Object.keys(sync.snapshot.files).length, 0);
    assert.equal(Object.keys(sync.snapshot.remoteOnly).length, count);
    assert.equal(verified, count);
    assert.deepEqual(await fsp.readdir(path.join(rootDir, "PRIVATE")), []);
    assert.equal((await fsp.readdir(path.join(rootDir, ".rootark-sync-evictions"))).length, 0);
    const restored = await new SyncEngine(options).open();
    assert.equal(Object.keys(restored.snapshot.remoteOnly).length, count);
    assert.equal(pushes, 0);
    process.stdout.write(`${JSON.stringify({
      count, elapsedMs: Number(elapsedMs.toFixed(2)), snapshotWrites,
      snapshotMB: Number((snapshotBytes / 1024 / 1024).toFixed(3)),
      observedWrites, verified, remotePushes: pushes,
      rssAfterMB: Number((process.memoryUsage().rss / 1024 / 1024).toFixed(2)),
    })}\n`);
  } finally {
    await fsp.rm(temp, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`${error?.stack || error}\n`);
  process.exitCode = 1;
});
