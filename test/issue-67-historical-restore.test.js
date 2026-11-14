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

async function restoreRecoveredBytesOnlyIfVacant(target, bytes) {
  // This helper is deliberately test-only. Recovery must never overwrite a
  // path another writer creates after the earlier existence assertion.
  const file = await fsp.open(target, "wx", 0o600);
  try {
    await file.writeFile(bytes);
    await file.sync();
  } finally {
    await file.close();
  }
}

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

test("#67 P2: stale tracked source cannot restore after an authenticated remote MOVE", async (t) => {
  const f = await fixture(t);
  const source = path.join(f.local, "document.txt");
  const destination = path.join(f.local, "moved.txt");
  const originalBytes = Buffer.from("original authenticated bytes");
  await fsp.writeFile(source, originalBytes);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(originalBytes).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const moved = await f.sign({ operation: "move", operationId: "trusted-move-op",
    versionId: "trusted-move-version", revision: { counter: 2, deviceId: "device-a" },
    baseRevision: f.original.revision,
    metadata: { path: "moved.txt", sourcePath: "document.txt" },
    plaintext: protocol.encodeMovePayload(originalBytes, f.privateFileKey),
  });
  assert.equal(await verifyAuthorizationProof(moved.authorization, moved, f.trusted), true);
  f.versions.splice(1, 1, moved);
  f.setCurrent(moved);

  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_conflict",
    "restore must not duplicate a signed identity at stale and current paths");
  assert.deepEqual(await fsp.readFile(source), originalBytes);
  assert.equal(fs.existsSync(destination), false);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);

  // The fixture's historical `list(objectId)` returns a single record;
  // the ordinary sync pull uses `list()` and expects a record collection.
  const historyList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? historyList(objectId) : [await historyList()];
  const synced = await f.engine.syncOnce();
  assert.equal(synced.offline, false);
  assert.equal(fs.existsSync(source), false, "verified MOVE reconciles the old name");
  assert.deepEqual(await fsp.readFile(destination), originalBytes);
  const result = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(result.pushed, true, "normal restore succeeds after reconciling the signed MOVE");
  assert.equal(f.current().revision.counter, 3);
  assert.equal(fs.existsSync(source), false);
  assert.deepEqual(await fsp.readFile(destination), originalBytes);
});

test("#67 P2: a signed fileId rotation cannot hide the old tracked objectId during MOVE restore", async (t) => {
  const f = await fixture(t);
  const source = path.join(f.local, "document.txt");
  const destination = path.join(f.local, "moved.txt");
  const originalBytes = Buffer.from("original authenticated bytes");
  await fsp.writeFile(source, originalBytes);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(originalBytes).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const rotated = await f.sign({ operation: "update", fileId: "rotated-file-id",
    operationId: "signed-id-rotation", versionId: "rotated-version",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: f.original.revision,
    metadata: { path: "document.txt" }, plaintext: originalBytes,
  });
  const moved = await f.sign({ operation: "move", fileId: "rotated-file-id",
    operationId: "signed-rotated-move", versionId: "moved-rotated-version",
    revision: { counter: 3, deviceId: "device-a" }, baseRevision: rotated.revision,
    metadata: { path: "moved.txt", sourcePath: "document.txt" },
    plaintext: protocol.encodeMovePayload(originalBytes, f.privateFileKey),
  });
  assert.equal(await verifyAuthorizationProof(rotated.authorization, rotated, f.trusted), true);
  assert.equal(await verifyAuthorizationProof(moved.authorization, moved, f.trusted), true);
  f.versions.splice(1, 1, rotated, moved);
  f.setCurrent(moved);

  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", rotated.versionId),
    (error) => error.code === "restore_local_conflict",
    "the old tracked object cannot be hidden by a newly signed fileId");
  assert.deepEqual(await fsp.readFile(source), originalBytes);
  assert.equal(fs.existsSync(destination), false);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);
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

test("#67: a clean tracked file can be restored and its former bytes remain recoverable in trash", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const clean = Buffer.from("clean synchronized newer content");
  await fsp.writeFile(target, clean);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "newer",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(clean).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const result = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(result.pushed, true);
  assert.equal(await fsp.readFile(target, "utf8"), "original authenticated bytes");
  const trash = path.join(f.local, ".rootark-trash");
  const files = await fsp.readdir(trash);
  assert.equal(files.length, 1);
  assert.deepEqual(await fsp.readFile(path.join(trash, files[0])), clean);
});

test("#67: a local write while the signed restore enters its durable outbox cannot be overwritten or pushed", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const clean = Buffer.from("last synchronized content");
  await fsp.writeFile(target, clean);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(clean).digest("hex"),
  };
  await f.engine.persistSnapshot();

  const enqueue = f.engine.journal.enqueue.bind(f.engine.journal);
  const unsent = Buffer.from("UNSENT LOCAL MODIFICATION DURING ENQUEUE");
  f.engine.journal.enqueue = async (operation) => {
    const result = await enqueue(operation);
    await fsp.writeFile(target, unsent);
    return result;
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_conflict");
  assert.deepEqual(await fsp.readFile(target), unsent);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0,
    "rejected restore must not remain eligible for retry/push after restart");
});

test("#67: staging detects an edit after final hash read and restores changed bytes to their path", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const clean = Buffer.from("clean snapshot");
  await fsp.writeFile(target, clean);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(clean).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const stage = f.engine.stageExisting.bind(f.engine);
  const edit = Buffer.from("NEW EDIT BETWEEN CHECK AND STAGING");
  f.engine.stageExisting = async (requested) => {
    await fsp.writeFile(target, edit);
    return stage(requested);
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_conflict");
  assert.deepEqual(await fsp.readFile(target), edit);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);
});

test("#67: staged content hash rejects same-size edits with restored mtime and stable inode", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const clean = Buffer.from("clean synchronized bytes");
  const altered = Buffer.from("dirty synchronized bytes");
  assert.equal(clean.length, altered.length);
  const timestamp = new Date("2023-11-14T00:00:00.000Z");
  await fsp.writeFile(target, clean);
  await fsp.utimes(target, timestamp, timestamp);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(clean).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const stage = f.engine.stageExisting.bind(f.engine);
  f.engine.stageExisting = async (requested) => {
    await fsp.writeFile(target, altered);
    await fsp.utimes(target, timestamp, timestamp);
    return stage(requested);
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_conflict");
  assert.deepEqual(await fsp.readFile(target), altered);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);
});

test("#67: a restart cannot dispatch a signed restore whose file was not materialized", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const old = Buffer.from("previous clean on-disk bytes");
  await fsp.writeFile(target, old);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(old).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const stage = f.engine.stageHistoricalRestore.bind(f.engine);
  f.engine.stageHistoricalRestore = async (...args) => {
    await stage(...args);
    throw new Error("simulated process halt after moving original to trash");
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"), /simulated process halt/);
  assert.equal(fs.existsSync(target), false);
  assert.equal((await f.engine.journal.recover()).length, 1);
  f.adapter.list = async (id) => id ? structuredClone(f.current()) : [structuredClone(f.current())];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory,
  }).open();
  await assert.rejects(reopened.syncOnce(), (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), 0, "an unmaterialized local restore must never be pushed after restart");
  assert.equal((await reopened.journal.recover()).length, 1);
  assert.equal(fs.existsSync(target), false);
  const trash = await fsp.readdir(path.join(f.local, ".rootark-trash"));
  assert.equal(trash.length, 1);
  assert.deepEqual(await fsp.readFile(path.join(f.local, ".rootark-trash", trash[0])), old);
  // Explicit recovery is possible without a new signature: materialize the
  // exact authenticated pending bytes, then let the existing CAS path resume.
  const recoveredBytes = protocol.decryptPayload(f.original, f.privateFileKey);
  try {
    // Simulate a competing writer recreating the missing path after the
    // absence check. Recovery must refuse and preserve those exact bytes.
    const competingBytes = Buffer.from("rival local edit before explicit recovery");
    await fsp.writeFile(target, competingBytes, { flag: "wx" });
    await assert.rejects(() => restoreRecoveredBytesOnlyIfVacant(target, recoveredBytes),
      (error) => error.code === "EEXIST");
    assert.deepEqual(await fsp.readFile(target), competingBytes);
    await fsp.unlink(target);
    await restoreRecoveredBytesOnlyIfVacant(target, recoveredBytes);
  } finally {
    recoveredBytes.fill(0);
  }
  const resumed = await reopened.syncOnce();
  assert.equal(resumed.pushed, 1);
  assert.equal(f.pushes(), 1);
  assert.equal((await reopened.journal.recover()).length, 0);
});

test("#67 P2: offline materialized restore survives later local edit and pushes before the edit", async (t) => {
  const f = await fixture(t);
  const actualPush = f.adapter.push;
  let offline = true;
  f.adapter.push = async (operation) => {
    if (offline) throw Object.assign(new Error("disposable offline"), { code: "offline" });
    return actualPush(operation);
  };
  const result = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(result.restored, true);
  assert.equal(result.pushed, false);
  assert.equal(result.pending, true);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 1);
  const target = path.join(f.local, "document.txt");
  assert.equal(await fsp.readFile(target, "utf8"), "original authenticated bytes");
  const materialized = f.engine.snapshot.files["document.txt"];
  assert.equal(materialized.versionId, result.versionId);
  assert.equal(materialized.hash,
    crypto.createHash("sha256").update("original authenticated bytes").digest("hex"));

  // This is a legitimate LOCAL edit to a restore already durably written to
  // the filesystem and sync snapshot. The restore's signed parent must commit
  // before the edit is assigned a subsequent CAS revision.
  const edited = Buffer.from("locally edited after successful materialization");
  await fsp.writeFile(target, edited);
  offline = false;
  const historyList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? historyList(objectId) : [await historyList(objectId)];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory,
  }).open();
  const committedRestore = await reopened.syncOnce();
  assert.equal(committedRestore.pushed, 1,
    "durably materialized restore must not strand the entire outbox on later user edits");
  assert.equal(f.pushes(), 1);
  assert.equal((await reopened.journal.recover()).length, 0);
  assert.deepEqual(await fsp.readFile(target), edited, "signed restore ACK cannot erase local edits");
  assert.equal(f.current().versionId, result.versionId);
  const after = await reopened.syncOnce();
  assert.equal(after.pushed, 1, "later local edit is independently signed after restore CAS");
  assert.equal(f.pushes(), 2);
  assert.deepEqual(protocol.decryptPayload(f.current(), f.privateFileKey), edited);
  assert.deepEqual(await fsp.readFile(target), edited);
});

test("#67 P2: forged persisted snapshot alone cannot authorize a never-materialized restore", async (t) => {
  const f = await fixture(t);
  const stage = f.engine.stageHistoricalRestore.bind(f.engine);
  f.engine.stageHistoricalRestore = async (...args) => {
    await stage(...args);
    throw new Error("disposable crash before restoring target bytes");
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    /disposable crash before restoring target bytes/);
  const queued = await f.engine.journal.recover();
  assert.equal(queued.length, 1);
  const signed = queued[0];
  assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.trusted), true);
  const payload = protocol.decryptPayload(signed, f.privateFileKey);
  try {
    // Simulate a local attacker altering the untrusted snapshot JSON without
    // changing the signed journal or materializing the file's actual bytes.
    f.engine.snapshot.files["document.txt"] = {
      objectId: signed.objectId, fileId: signed.fileId, versionId: signed.versionId,
      revision: signed.revision, hash: crypto.createHash("sha256").update(payload).digest("hex"),
      deleted: false, directory: false,
    };
    await f.engine.persistSnapshot();
  } finally { payload.fill(0); }
  assert.equal(fs.existsSync(path.join(f.local, "document.txt")), false);
  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? originalList(objectId) : [await originalList(objectId)];
  const resumed = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory,
  }).open();
  await assert.rejects(resumed.syncOnce(),
    (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), 0);
  assert.equal((await resumed.journal.recover()).length, 1);
});

test("#67 P2: deletion after durable offline restore remains a later signed delete", async (t) => {
  const f = await fixture(t);
  const actualPush = f.adapter.push;
  let offline = true;
  f.adapter.push = async (operation) => {
    if (offline) throw Object.assign(new Error("disposable offline"), { code: "offline" });
    return actualPush(operation);
  };
  const pending = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(pending.pending, true);
  const target = path.join(f.local, "document.txt");
  assert.equal(await fsp.readFile(target, "utf8"), "original authenticated bytes");
  await fsp.unlink(target);
  offline = false;
  const historyList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? historyList(objectId) : [await historyList(objectId)];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory,
  }).open();
  const restored = await reopened.syncOnce();
  assert.equal(restored.pushed, 1);
  assert.equal(f.current().versionId, pending.versionId);
  assert.equal(fs.existsSync(target), false, "remote restore ACK cannot re-create the deleted local file");
  const deletion = await reopened.syncOnce();
  assert.equal(deletion.pushed, 1);
  assert.equal(f.current().operation, "delete");
  assert.equal(f.current().tombstone, true);
  assert.equal(fs.existsSync(target), false);
  assert.deepEqual(await reopened.journal.recover(), []);
});

test("#67 P2: failing physical file fsync cannot certify a restore as materialized", async (t) => {
  const f = await fixture(t);
  const originalOpen = fsp.open;
  let injected = 0;
  fsp.open = async (name, ...rest) => {
    const handle = await originalOpen(name, ...rest);
    if (String(name).includes("document.txt.tmp-")) {
      Object.defineProperty(handle, "sync", {
        value: async () => {
          injected += 1;
          throw Object.assign(new Error("disposable file fsync refused"), { code: "EIO" });
        }, configurable: true,
      });
    }
    return handle;
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "EIO");
  } finally { fsp.open = originalOpen; }
  assert.equal(injected, 1, "the fsync injection must hit the REAL plaintext file handle");
  assert.equal(f.pushes(), 0);
  assert.equal(fs.existsSync(path.join(f.local, "document.txt")), false,
    "failure before link must not create a supposed restored file");
  const pending = await f.engine.journal.recover();
  assert.equal(pending.length, 1, "the signed outbox cannot be silently cleared");
  assert.equal(f.engine.journal.hasMaterializedRestore(pending[0]), false,
    "the journal must not witness bytes that were never physically flushed");
  assert.equal(f.engine.snapshot.files["document.txt"], undefined);
});

test("#67 P2: a recovered restore without witness cannot push if retry file fsync fails", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const stage = f.engine.stageHistoricalRestore.bind(f.engine);
  f.engine.stageHistoricalRestore = async (...args) => {
    await stage(...args);
    throw new Error("disposable halt before durable materialization");
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    /disposable halt before durable materialization/);
  const [signed] = await f.engine.journal.recover();
  assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.trusted), true);
  assert.equal(f.engine.journal.hasMaterializedRestore(signed), false);
  const bytes = protocol.decryptPayload(signed, f.privateFileKey);
  try { await restoreRecoveredBytesOnlyIfVacant(target, bytes); }
  finally { bytes.fill(0); }
  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? originalList(objectId) : [await originalList(objectId)];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory,
  }).open();
  const originalOpen = fsp.open;
  let injected = 0;
  fsp.open = async (name, flags, ...rest) => {
    const handle = await originalOpen(name, flags, ...rest);
    if (name === target && typeof flags === "number" && (flags & fs.constants.O_RDWR)) {
      Object.defineProperty(handle, "sync", { value: async () => {
        injected += 1;
        throw Object.assign(new Error("disposable recovered file fsync EIO"), { code: "EIO" });
      }, configurable: true });
    }
    return handle;
  };
  try {
    await assert.rejects(reopened.syncOnce(), (error) => error.code === "restore_local_materialization_missing");
  } finally { fsp.open = originalOpen; }
  assert.equal(injected, 1, "retry must fsync the exact recovered file descriptor");
  assert.equal(f.pushes(), 0, "failed retry fsync must never authorize remote POST");
  assert.equal((await reopened.journal.recover()).length, 1);
  assert.equal(reopened.journal.hasMaterializedRestore(signed), false);
  assert.deepEqual(await fsp.readFile(target), Buffer.from("original authenticated bytes"));
  const resumed = await reopened.syncOnce();
  assert.equal(resumed.pushed, 1, "a fresh successful physical sync permits a safe retry");
  assert.equal(f.pushes(), 1);
});

test("#67 P2: failed POSIX directory fsync after link cannot authorize push on retry", {
  skip: process.platform === "win32" ? "directory FileHandle.sync is not available on Windows" : false,
}, async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const originalOpen = fsp.open;
  const originalLink = fsp.link;
  let linked = false;
  let injectionsRemaining = 2;
  fsp.link = async (source, destination) => {
    const result = await originalLink(source, destination);
    if (destination === target && source.startsWith(`${target}.tmp-`)) linked = true;
    return result;
  };
  fsp.open = async (name, flags, ...rest) => {
    const handle = await originalOpen(name, flags, ...rest);
    if (linked && name === f.local
      && typeof flags === "number"
      && (flags & (fs.constants.O_DIRECTORY || 0)) !== 0
      && (flags & (fs.constants.O_NOFOLLOW || 0)) !== 0
      && (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR)) === fs.constants.O_RDONLY
      && injectionsRemaining > 0) {
      Object.defineProperty(handle, "sync", { value: async () => {
        injectionsRemaining -= 1;
        throw Object.assign(new Error("disposable directory durability EIO"), { code: "EIO" });
      }, configurable: true });
    }
    return handle;
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "EIO");
    assert.equal(injectionsRemaining, 1, "first EIO must strike directory sync after physical link");
    assert.equal(await fsp.readFile(target, "utf8"), "original authenticated bytes");
    const [signed] = await f.engine.journal.recover();
    assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.trusted), true);
    assert.equal(f.engine.journal.hasMaterializedRestore(signed), false);
    assert.equal(f.pushes(), 0);
    const originalList = f.adapter.list;
    f.adapter.list = async (objectId) => objectId
      ? originalList(objectId) : [await originalList(objectId)];
    const reopened = await new SyncEngine({
      rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
      keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
      fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
      authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
      verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory,
    }).open();
    await assert.rejects(reopened.syncOnce(),
      (error) => error.code === "restore_local_materialization_missing",
      "the real POSIX retry must fail closed when directory fsync fails");
    assert.equal(injectionsRemaining, 0, "second EIO must strike missing-witness retry directory fsync");
    assert.equal(f.pushes(), 0, "the server must not receive the restore after either fsync EIO");
    assert.equal((await reopened.journal.recover()).length, 1);
    assert.equal(reopened.journal.hasMaterializedRestore(signed), false);
    const result = await reopened.syncOnce();
    assert.equal(result.pushed, 1, "physical fsync on the real retry permits subsequent admission");
    assert.equal(f.pushes(), 1);
    assert.equal((await reopened.journal.recover()).length, 0);
  } finally { fsp.open = originalOpen; fsp.link = originalLink; }
});

test("#67 P2: restart recovers an exactly bound crash hardlink or fails closed on changed identity", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const originalUnlink = fsp.unlink;
  const originalRemove = fsp.rm;
  let interruptedCleanup = 0;
  let suppressedCleanup = 0;
  fsp.unlink = async (name, ...args) => {
    if (String(name).startsWith(`${target}.tmp-`)) {
      interruptedCleanup += 1;
      throw new Error("disposable hard crash after linked staging identity was committed");
    }
    return originalUnlink(name, ...args);
  };
  fsp.rm = async (name, ...args) => {
    if (String(name).startsWith(`${target}.tmp-`)) {
      suppressedCleanup += 1;
      return;
    }
    return originalRemove(name, ...args);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      /disposable hard crash after linked staging identity was committed/);
  } finally { fsp.unlink = originalUnlink; fsp.rm = originalRemove; }
  assert.equal(interruptedCleanup, 1, "real target link and exact bound identity precede failed unlink");
  assert.equal(suppressedCleanup, 1, "simulated kill must bypass only the stage unlink cleanup");
  const [pending] = await f.engine.journal.recover();
  assert.equal(await verifyAuthorizationProof(pending.authorization, pending, f.trusted), true);
  assert.equal(f.engine.journal.hasMaterializedRestore(pending), false);
  const staging = f.engine.journal.restoreStagingInfo(pending);
  assert.ok(staging, "crash recovery needs a durable exact staged inode/name bound to signed envelope");
  const orphan = path.join(f.local, staging.name);
  assert.equal(fs.existsSync(orphan), true, "the original producer-created temporary hardlink remains");
  assert.equal((await fsp.lstat(target)).nlink, 2);
  assert.equal((await fsp.lstat(orphan)).ino, (await fsp.lstat(target)).ino);
  const current = await fsp.lstat(target, { bigint: true });
  const idMatches = current.ino.toString() === staging.ino
    && current.dev.toString() === staging.dev;
  // Win32 filesystem index exposure can change across link creation. If it
  // does, a pre-crash journal identity MUST NOT authorize guessed cleanup.
  // This is safe manual-recovery NO-GO, not a falsely claimed auto-repair.
  if (!idMatches) {
    assert.equal(process.platform, "win32", "POSIX inode identity must remain stable");
  }
  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? originalList(objectId) : [await originalList(objectId)];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory,
  }).open();
  if (!idMatches) {
    await assert.rejects(reopened.syncOnce(),
      (error) => error.code === "restore_local_materialization_missing");
    assert.equal(f.pushes(), 0);
    assert.equal(fs.existsSync(orphan), true, "mismatched staged identity cannot be deleted");
    assert.equal((await reopened.journal.recover()).length, 1);
    assert.equal(await fsp.readFile(target, "utf8"), "original authenticated bytes");
    return;
  }
  const result = await reopened.syncOnce();
  assert.equal(result.pushed, 1, "a verified original restore may safely resume after cleanup");
  assert.equal(f.pushes(), 1);
  assert.equal(fs.existsSync(orphan), false, "remove only the authenticated temporary second hardlink");
  assert.equal((await fsp.lstat(target)).nlink, 1);
  assert.equal(await fsp.readFile(target, "utf8"), "original authenticated bytes");
  assert.deepEqual(await reopened.journal.recover(), []);
});

test("#67 P2: foreign hardlink cannot be misidentified as restore temp and deleted", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const stage = f.engine.stageHistoricalRestore.bind(f.engine);
  f.engine.stageHistoricalRestore = async (...args) => {
    await stage(...args);
    throw new Error("disposable stop before materialization");
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"), /disposable stop/);
  const [pending] = await f.engine.journal.recover();
  const bytes = protocol.decryptPayload(pending, f.privateFileKey);
  try { await restoreRecoveredBytesOnlyIfVacant(target, bytes); }
  finally { bytes.fill(0); }
  // A user can legitimately create a hardlink whose name merely resembles
  // the engine's staging suffix. It has NO durable journal staging intent.
  // Matching the suffix, inode and payload hash must not suffice to unlink it.
  const foreignName = `${target}.tmp-${process.pid}-${crypto.randomUUID()}`;
  await fsp.link(target, foreignName);
  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? originalList(objectId) : [await originalList(objectId)];
  const countBefore = f.pushes();
  await assert.rejects(f.engine.syncOnce(),
    (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), countBefore);
  assert.equal((await fsp.lstat(target)).nlink, 2);
  assert.equal(fs.existsSync(foreignName), true, "never remove an arbitrary user hardlink");
  assert.equal((await f.engine.journal.recover()).length, 1);
});

test("#67 P2: pre-link crash cannot silently upload the durable staging temp", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const stage = f.engine.stageHistoricalRestore.bind(f.engine);
  const originalRemove = fsp.rm;
  let skippedCleanup = 0;
  f.engine.stageHistoricalRestore = async (...args) => {
    await stage(...args);
    throw new Error("disposable crash before hardlink to target");
  };
  fsp.rm = async (name, ...args) => {
    if (String(name).startsWith(`${target}.tmp-`)) {
      skippedCleanup += 1;
      return;
    }
    return originalRemove(name, ...args);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      /disposable crash before hardlink to target/);
  } finally { fsp.rm = originalRemove; }
  assert.equal(skippedCleanup, 1, "injected process kill must preserve producer's exact staging temp");
  const [signed] = await f.engine.journal.recover();
  assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.trusted), true);
  const intent = f.engine.journal.restoreStagingInfo(signed);
  assert.ok(intent, "signed outbox must preserve its physically pinned staging intent");
  const staged = path.join(f.local, intent.name);
  assert.equal((await fsp.lstat(staged, { bigint: true })).ino.toString(), intent.ino);
  assert.equal(fs.existsSync(target), false);
  const originalList = f.adapter.list;
  f.adapter.list = async (objectId) => objectId
    ? originalList(objectId) : [await originalList(objectId)];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory,
  }).open();
  await assert.rejects(reopened.syncOnce(),
    (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), 0, "a staged but never linked file must not create remote content");
  assert.equal(fs.existsSync(staged), true, "manual recovery must still have the original bytes");
  assert.equal((await reopened.journal.recover()).length, 1);
});

test("#67 P2: crash after staging name intent but before inode bind cannot upload orphan", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const originalBind = f.engine.journal.bindRestoreStagingIdentity.bind(f.engine.journal);
  const originalRemove = fsp.rm;
  let injected = 0;
  f.engine.journal.bindRestoreStagingIdentity = async () => {
    injected += 1;
    throw new Error("disposable kill after file data fsync before inode intent bind");
  };
  fsp.rm = async (name, ...args) => {
    if (String(name).startsWith(`${target}.tmp-`)) return;
    return originalRemove(name, ...args);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      /disposable kill after file data fsync before inode intent bind/);
  } finally {
    fsp.rm = originalRemove;
    f.engine.journal.bindRestoreStagingIdentity = originalBind;
  }
  assert.equal(injected, 1);
  const [signed] = await f.engine.journal.recover();
  assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.trusted), true);
  const intent = f.engine.journal.restoreStagingInfo(signed);
  assert.ok(intent && intent.name && intent.dev === null && intent.ino === null);
  const staged = path.join(f.local, intent.name);
  assert.equal((await fsp.lstat(staged)).nlink, 1);
  assert.equal(fs.existsSync(target), false);
  const originalList = f.adapter.list;
  f.adapter.list = async (id) => id ? originalList(id) : [await originalList(id)];
  const reopened = await new SyncEngine({
    rootDir: f.local, adapter: f.adapter, deviceId: f.engine.deviceId,
    keyEpoch: f.engine.keyEpoch, compartmentId: f.engine.compartmentId,
    fileKeyResolver: f.engine.fileKeyResolver, requireAuthorization: true,
    authorize: f.engine.authorize, authorizeOutgoing: f.engine.authorizeOutgoing,
    verifyIncoming: f.engine.verifyIncoming, authorizationFactory: f.engine.authorizationFactory,
  }).open();
  await assert.rejects(reopened.syncOnce(),
    (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), 0);
  assert.equal(fs.existsSync(staged), true, "cannot discard or upload the unbound exact-stage bytes");
  assert.equal((await reopened.journal.recover()).length, 1);
});

test("#67 P2: O_EXCL staging collision cannot delete another user's file", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const originalOpen = fsp.open;
  const foreign = Buffer.from("FOREIGN_STAGING_COLLISION_MUST_SURVIVE");
  let collided = null;
  fsp.open = async (name, flags, ...args) => {
    if (!collided && typeof name === "string" && name.startsWith(`${target}.tmp-`)
      && typeof flags === "number" && (flags & fs.constants.O_EXCL)) {
      collided = name;
      await fsp.writeFile(name, foreign, { flag: "wx" });
    }
    return originalOpen(name, flags, ...args);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "EEXIST");
  } finally { fsp.open = originalOpen; }
  assert.ok(collided, "the collision must occur after durable signed name intent");
  assert.deepEqual(await fsp.readFile(collided), foreign,
    "finally must never delete the foreign file when exclusive creation failed");
  assert.equal(f.pushes(), 0);
  const [pending] = await f.engine.journal.recover();
  assert.equal(await verifyAuthorizationProof(pending.authorization, pending, f.trusted), true);
  assert.equal(f.engine.journal.hasMaterializedRestore(pending), false);
});

test("#67 P2: staging bytes changed immediately before signed hardlink cannot gain witness", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const originalLink = fsp.link;
  const foreign = Buffer.from("FOREIGN_EDIT_REPLACES_AUTHENTICATED_STAGED_BYTES");
  let edited = 0;
  fsp.link = async (source, destination) => {
    if (destination === target && source.startsWith(`${target}.tmp-`)) {
      edited += 1;
      // Genuine on-disk edit through the same pathname after the outbox
      // bound its name/inode but immediately before the filesystem link.
      await fsp.writeFile(source, foreign);
    }
    return originalLink(source, destination);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_local_materialization_missing");
  } finally { fsp.link = originalLink; }
  assert.equal(edited, 1, "the adversarial edit must strike the real hardlink path");
  assert.equal(f.pushes(), 0, "mutated bytes must not be presented as signed materialization");
  const [signed] = await f.engine.journal.recover();
  assert.equal(await verifyAuthorizationProof(signed.authorization, signed, f.trusted), true);
  assert.equal(f.engine.journal.hasMaterializedRestore(signed), false);
  assert.equal(f.engine.snapshot.files["document.txt"], undefined);
  assert.deepEqual(await fsp.readFile(target), foreign,
    "a conflicting local file must remain for manual recovery, not be silently removed");
});

test("#67 P2: witnessed offline restore never removes a user's matching-suffix hardlink", async (t) => {
  const f = await fixture(t);
  const actualPush = f.adapter.push;
  f.adapter.push = async () => {
    throw Object.assign(new Error("disposable offline"), { code: "offline" });
  };
  try {
    const result = await f.engine.restoreHistoricalVersion("file-1", "first");
    assert.equal(result.pending, true);
    const [signed] = await f.engine.journal.recover();
    assert.equal(f.engine.journal.hasMaterializedRestore(signed), true);
    assert.equal(f.engine.journal.restoreStagingInfo(signed), null);
    const target = path.join(f.local, "document.txt");
    const userLink = `${target}.tmp-${process.pid}-${crypto.randomUUID()}`;
    await fsp.link(target, userLink);
    await assert.rejects(f.engine.syncOnce(),
      (error) => error.code === "unsafe_path" || error.code === "restore_local_materialization_missing");
    assert.equal(fs.existsSync(userLink), true,
      "a valid local restore witness must NEVER authorize cleanup of a later user alias");
    assert.equal((await fsp.lstat(userLink)).nlink, 2);
    assert.equal((await f.engine.journal.recover()).length, 1);
    assert.equal(f.pushes(), 0);
  } finally { f.adapter.push = actualPush; }
});

test("#67: hardlink permission failure preserves local bytes and blocks remote restore", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const old = Buffer.from("newer synchronized local bytes");
  await fsp.writeFile(target, old);
  f.engine.snapshot.files["document.txt"] = {
    objectId: "file-1", fileId: "file-1", versionId: "first",
    revision: f.original.revision, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(old).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const originalLink = fsp.link;
  fsp.link = async (source, destination) => {
    if (destination === target && source.includes(".tmp-")) {
      throw Object.assign(new Error("simulated hardlink permission denial"), { code: "EACCES" });
    }
    return originalLink(source, destination);
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"), /hardlink permission denial/);
  } finally { fsp.link = originalLink; }
  assert.deepEqual(await fsp.readFile(target), old);
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 1);
  await assert.rejects(f.engine.syncOnce(), (error) => error.code === "restore_local_materialization_missing");
  assert.equal(f.pushes(), 0);
});

test("#67: an untracked file created after enqueue is never replaced by restore", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "document.txt");
  const enqueue = f.engine.journal.enqueue.bind(f.engine.journal);
  f.engine.journal.enqueue = async (operation) => {
    const result = await enqueue(operation);
    await fsp.writeFile(target, "NEW UNTRACKED FILE");
    return result;
  };
  await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
    (error) => error.code === "restore_local_conflict");
  assert.equal(await fsp.readFile(target, "utf8"), "NEW UNTRACKED FILE");
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);
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

test("#67 P2: restore succeeds across signed fileId rotation create(oldId) -> update(newId) -> delete(newId)", async (t) => {
  const f = await fixture(t);
  const oldId = "old-file-id";
  const newId = "rotated-file-id";
  const originalBytes = Buffer.from("original authenticated bytes");
  const updatedBytes = Buffer.from("updated authenticated bytes");
  const created = await f.sign({ operation: "create", fileId: oldId, versionId: "v1-created", operationId: "op1",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "document.txt", name: "document.txt" },
    plaintext: originalBytes });
  const updated = await f.sign({ operation: "update", fileId: newId, versionId: "v2-updated", operationId: "op2",
    baseRevision: created.revision, revision: { counter: 2, deviceId: "device-a" },
    metadata: { path: "document.txt", name: "document.txt" }, plaintext: updatedBytes });
  const deleted = await f.sign({ operation: "delete", fileId: newId, versionId: "v3-deleted", operationId: "op3",
    baseRevision: updated.revision, revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "document.txt" } });
  f.versions.splice(0, f.versions.length, created, updated, deleted);
  f.setCurrent(deleted);
  const restored = await f.engine.restoreHistoricalVersion("file-1", "v1-created");
  assert.equal(restored.pushed, true);
  assert.equal(restored.sourceVersionId, "v1-created");
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"), "original authenticated bytes");
  assert.equal(f.current().fileId, newId, "restored revision inherits current rotated fileId");
});
