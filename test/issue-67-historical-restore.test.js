"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");

const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

test("#67: restore CLI rejects an incomplete request before reading private credentials", () => {
  const command = spawnSync(process.execPath, [path.join(__dirname, "../sync-client/rootark-sync-v2.js"),
    "restore", "--config", "missing-private-config", "--object-id", "file-1"], { encoding: "utf8", windowsHide: true });
  assert.equal(command.status, 1);
  assert.match(command.stderr, /version-id/i);
  assert.doesNotMatch(command.stdout + command.stderr, /ROOTARK_SYNC_FILE_KEY|token|privateKey/);
});

async function fixture(t) {
  const root = createPrivateAuthorityFixture("rootark-67-restore-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const local = path.join(root, "client");
  await fsp.mkdir(local);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeySpki = publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const privateFileKey = crypto.randomBytes(32);
  const trusted = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKeySpki }, revokedDeviceIds: [] };
  const sign = async (input) => {
    const operation = protocol.createOperation({
      objectId: "file-1", fileId: "file-1", deviceId: "device-a", keyEpoch: "epoch-1",
      compartmentId: "private", fileKey: privateFileKey, ...input,
    });
    return { ...operation, authorization: await createAuthorizationProof(operation, {
      username: "alice", privateKey, publicKey: publicKeySpki,
    }) };
  };
  const original = await sign({ operation: "create", versionId: "first", operationId: "first-op",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "document.txt", name: "document.txt" },
    plaintext: Buffer.from("original authenticated bytes") });
  const deleted = await sign({ operation: "delete", versionId: "deleted", operationId: "delete-op",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: original.revision,
    metadata: { path: "document.txt" } });
  let current = deleted;
  const versions = [original, deleted];
  let pushes = 0;
  const adapter = {
    history: async () => ({ protocolVersion: 2, versions: versions.map((record) => structuredClone(record)) }),
    list: async () => structuredClone(current),
    push: async (operation) => {
      pushes += 1;
      protocol.validateFreshSignedOperation(operation);
      assert.equal(await verifyAuthorizationProof(operation.authorization, operation, trusted), true);
      if (protocol.compareRevisions(operation.baseRevision, current.revision) !== 0) {
        const err = new Error("Stale revision");
        err.status = 409;
        throw err;
      }
      current = structuredClone(operation);
      versions.push(current);
      return structuredClone(current);
    },
  };
  const engine = await new SyncEngine({
    rootDir: local, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => privateFileKey, requireAuthorization: true,
    authorize: () => true, authorizeOutgoing: () => !trusted.revokedDeviceIds.includes("device-a"),
    verifyIncoming: (record) => verifyAuthorizationProof(record.authorization, record, trusted),
    authorizationFactory: (operation) => createAuthorizationProof(operation, {
      username: "alice", privateKey, publicKey: publicKeySpki,
    }),
  }).open();
  return { root, local, engine, original, deleted, versions, trusted, adapter, sign, privateFileKey, publicKeySpki,
    setCurrent: (value) => { current = value; },
    pushes: () => pushes, current: () => current };
}

test("#67: restoring a deleted historical ciphertext creates a fresh signed revision and real local bytes", async (t) => {
  const f = await fixture(t);
  const result = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(result.restored, true);
  assert.equal(result.pushed, true);
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"), "original authenticated bytes");
  assert.equal(f.pushes(), 1);
  assert.equal(f.versions.length, 3);
  assert.equal(f.versions[0].versionId, "first");
  assert.equal(f.versions[1].versionId, "deleted");
  const restored = f.current();
  assert.notEqual(restored.operationId, f.original.operationId);
  assert.notEqual(restored.versionId, f.original.versionId);
  assert.equal(restored.operation, "update");
  assert.equal(restored.baseRevision.counter, 2);
  assert.equal(restored.revision.counter, 3);
  assert.equal(await verifyAuthorizationProof(restored.authorization, restored, f.trusted), true);
  assert.equal(protocol.decryptPayload(restored, f.engine.fileKeyResolver(restored)).toString(), "original authenticated bytes");
});

test("#67: invalid historical signature, unknown version and revoked signer fail before any new write", async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "missing"), /version|history/i);
  f.versions[0] = { ...f.original, ciphertext: f.original.ciphertext + "AA" };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"));
  assert.equal(f.pushes(), 0);
  assert.equal(fs.existsSync(path.join(f.local, "document.txt")), false);
  f.versions[0] = f.original;
  f.trusted.revokedDeviceIds.push("device-a");
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"));
  assert.equal(f.pushes(), 0);
  assert.equal(fs.existsSync(path.join(f.local, "document.txt")), false);
});

test("#67: historical MOVE restores authenticated file bytes, not the encrypted move framing", async (t) => {
  const f = await fixture(t);
  const moved = await f.sign({ operation: "move", operationId: "move-op", versionId: "move-version",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: f.original.revision,
    metadata: { path: "moved.txt", sourcePath: "document.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("historical move content"), f.privateFileKey),
  });
  const deleted = await f.sign({ operation: "delete", operationId: "delete-move-op", versionId: "delete-move-version",
    revision: { counter: 3, deviceId: "device-a" }, baseRevision: moved.revision,
    metadata: { path: "moved.txt" } });
  f.versions.splice(1, 1, moved, deleted);
  f.setCurrent(deleted);
  const outcome = await f.engine.restoreHistoricalVersion("file-1", moved.versionId);
  assert.equal(outcome.pushed, true);
  assert.equal(await fsp.readFile(path.join(f.local, "moved.txt"), "utf8"), "historical move content");
  assert.equal(f.current().revision.counter, 4);
});

test("#67: restore never overwrites untracked local data or accepts a cross-object current head", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  await fsp.writeFile(target, "independent local data");
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"), /untracked|overwrite/i);
  assert.equal(await fsp.readFile(target, "utf8"), "independent local data");
  assert.equal(f.pushes(), 0);
  await fsp.unlink(target);
  f.setCurrent({ ...f.deleted, objectId: "foreign-file" });
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"));
  assert.equal(f.pushes(), 0);
});

test("#67: restore rejects unsent edits to a tracked local file before enqueuing or pushing", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const lastSynced = Buffer.from("last synchronized content");
  await fsp.writeFile(target, lastSynced);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(lastSynced).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const unsent = Buffer.from("UNSENT LOCAL MODIFICATION");
  await fsp.writeFile(target, unsent);
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_conflict");
  assert.deepEqual(await fsp.readFile(target), unsent);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);
  assert.equal(fs.existsSync(path.join(f.local, ".rootark-trash")), false);
});

test("#67: real atomic device registry durably admits a newly signed historical restore", async (t) => {
  const f = await fixture(t);
  const storagePath = path.join(f.root, "physical-store.json");
  const store = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  await store.enrollDevice({ username: "alice", deviceId: "device-a",
    publicKey: f.publicKeySpki, expectedEpoch: 0 });
  assert.equal((await store.put("alice", f.original)).kind, "stored");
  assert.equal((await store.put("alice", f.deleted)).kind, "stored");
  f.adapter.history = async (id) => ({ protocolVersion: 2, versions: store.history("alice", id) });
  f.adapter.list = async (id) => store.list("alice", id)[0];
  f.adapter.push = async (operation) => {
    const admitted = await store.put("alice", operation);
    assert.equal(admitted.kind, "stored");
    return admitted.record;
  };
  const before = await fsp.readFile(storagePath, "utf8");
  const restored = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(restored.pushed, true);
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"), "original authenticated bytes");
  assert.equal(store.history("alice", "file-1").length, 3);
  const durable = JSON.parse(await fsp.readFile(storagePath, "utf8"));
  assert.equal(durable.users.alice.objects["file-1"].operationId, restored.operationId);
  assert.equal(JSON.parse(before).users.alice.versions["file-1"].length, 2);
  const reopened = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  assert.equal(reopened.list("alice", "file-1")[0].versionId, restored.versionId);
});
