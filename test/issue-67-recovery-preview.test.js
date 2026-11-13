"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { Readable } = require("node:stream");
const test = require("node:test");

const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { readHistoricalRestorePlanInput } = require("../sync-client/rootark-sync-v2");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

async function fixture(t, { strict = true } = {}) {
  const root = createPrivateAuthorityFixture("rootark-67-preview-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const local = path.join(root, "client");
  await fsp.mkdir(local);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeySpki = publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const fileKey = crypto.randomBytes(32);
  const policy = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKeySpki }, revokedDeviceIds: [] };
  let custody = true;
  let grant = true;
  let pushes = 0;
  const sign = async (input) => {
    const operation = protocol.createOperation({
      objectId: "object-1", fileId: "file-1", deviceId: "device-a", keyEpoch: "epoch-1",
      compartmentId: "private", fileKey, ...input,
    });
    return { ...operation, authorization: await createAuthorizationProof(operation, {
      username: "alice", privateKey, publicKey: publicKeySpki,
    }) };
  };
  const original = await sign({ operation: "create", versionId: "v1", operationId: "op1",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "note.txt" },
    plaintext: Buffer.from("authenticated historical bytes") });
  const deleted = await sign({ operation: "delete", versionId: "v2", operationId: "op2",
    baseRevision: original.revision, revision: { counter: 2, deviceId: "device-a" },
    metadata: { path: "note.txt" } });
  const versions = [original, deleted];
  let head = deleted;
  const adapter = {
    history: async () => ({ protocolVersion: 2, versions: structuredClone(versions) }),
    list: async () => structuredClone(head),
    push: async () => { pushes++; throw new Error("Preview must never push"); },
  };
  const engine = await new SyncEngine({
    rootDir: local, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => fileKey, requireAuthorization: true,
    requireIndependentHistoricalAdmission: strict,
    reverifySeenIncoming: strict,
    requireCurrentOutgoingAuthorization: strict,
    currentDeviceAuthorization: () => grant,
    authorizeOutgoing: () => grant,
    authorize: () => true,
    verifyIncoming: async (record) => custody && verifyAuthorizationProof(record.authorization, record, policy),
    authorizationFactory: (record) => createAuthorizationProof(record, {
      username: "alice", privateKey, publicKey: publicKeySpki,
    }),
  }).open();
  return {
    engine, local, fileKey, original, deleted, versions, adapter, sign,
    setCustody: (value) => { custody = value; },
    setGrant: (value) => { grant = value; },
    setHead: (value) => { head = value; },
    pushes: () => pushes,
  };
}

test("#67: strict preview verifies signed history and AEAD without signing, journaling, or materializing", async (t) => {
  const f = await fixture(t);
  const journalPath = path.join(f.local, ".rootark-sync-journal.json");
  const snapshotPath = path.join(f.local, ".rootark-sync-index.json");
  const beforeJournal = await fsp.readFile(journalPath);
  const beforeSnapshot = await fsp.readFile(snapshotPath);
  const preview = await f.engine.previewHistoricalRestore("object-1", "v1");
  assert.deepEqual(preview, {
    readOnly: true, ready: true, objectId: "object-1", sourceVersionId: "v1",
    currentVersionId: "v2", baseRevision: f.deleted.revision,
    path: "note.txt", sizeBytes: 30, localAction: "create-from-deleted",
    verifiedRetainedVersions: 2, requiresFreshRestoreCheck: true,
  });
  assert.deepEqual(await fsp.readFile(journalPath), beforeJournal);
  assert.deepEqual(await fsp.readFile(snapshotPath), beforeSnapshot);
  assert.equal(fs.existsSync(path.join(f.local, "note.txt")), false);
  assert.equal((await f.engine.journal.recover()).length, 0);
  assert.equal(f.pushes(), 0);
});

test("#67: preview CLI rejects missing independent custody before reading private config", () => {
  const cli = path.resolve(__dirname, "../sync-client/rootark-sync-v2.js");
  const result = spawnSync(process.execPath, [cli, "preview", "--config", "missing-secret-config",
    "--object-id", "object-1", "--version-id", "v1"], {
    encoding: "utf8", windowsHide: true,
    env: { ...process.env, ROOTARK_SYNC_REQUIRE_INDEPENDENT_HISTORY: "0" },
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /independent custody/i);
  assert.doesNotMatch(result.stderr + result.stdout, /ROOTARK_SYNC_FILE_KEY|token|privateKey/);
});

test("#67: preview on unopened root refuses before creating a snapshot or journal", async (t) => {
  const root = createPrivateAuthorityFixture("rootark-67-preview-not-open-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const engine = new SyncEngine({ rootDir: root,
    adapter: { list: async () => [], push: async () => { throw new Error("unexpected push"); } },
    requireIndependentHistoricalAdmission: true, requireAuthorization: true,
    requireCurrentOutgoingAuthorization: true, currentDeviceAuthorization: () => true,
    reverifySeenIncoming: true, verifyIncoming: () => true,
    authorizationFactory: () => { throw new Error("unexpected signature"); },
  });
  await assert.rejects(engine.previewHistoricalRestore("object-1", "v1"),
    (error) => error.code === "history_preview_unavailable");
  assert.equal(fs.existsSync(path.join(root, ".rootark-sync-journal.json")), false);
  assert.equal(fs.existsSync(path.join(root, ".rootark-sync-index.json")), false);
});

test("#67 P2: preview never recreates a missing journal after an initialized root", async (t) => {
  const f = await fixture(t);
  const journalPath = path.join(f.local, ".rootark-sync-journal.json");
  const lockPath = path.join(f.local, ".rootark-sync.lock");
  const snapshotPath = path.join(f.local, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  await fsp.unlink(journalPath);
  const entriesBefore = (await fsp.readdir(f.local)).sort();

  await assert.rejects(f.engine.previewHistoricalRestore("object-1", "v1"),
    (error) => error.code === "history_preview_unavailable");
  assert.equal(fs.existsSync(journalPath), false, "missing security evidence must not be recreated");
  assert.equal(fs.existsSync(lockPath), false, "preview must not persist a process lock");
  assert.deepEqual((await fsp.readdir(f.local)).sort(), entriesBefore);
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(f.pushes(), 0);
});

test("#67 P2: preview uses no process lock writes and detects changed on-disk snapshot", async (t) => {
  const f = await fixture(t);
  const originalAcquire = f.engine.acquireProcessLock;
  f.engine.acquireProcessLock = async () => {
    throw new Error("Read-only preview attempted to create the writer lock");
  };
  try {
    const valid = await f.engine.previewHistoricalRestore("object-1", "v1");
    assert.equal(valid.ready, true);
    const originalHistory = f.adapter.history;
    f.adapter.history = async (...args) => {
      const result = await originalHistory(...args);
      const snapshotPath = path.join(f.local, ".rootark-sync-index.json");
      const snapshot = JSON.parse(await fsp.readFile(snapshotPath, "utf8"));
      snapshot.untrustedConcurrentEdit = true;
      await fsp.writeFile(snapshotPath, JSON.stringify(snapshot));
      return result;
    };
    await assert.rejects(f.engine.previewHistoricalRestore("object-1", "v1"),
      (error) => error.code === "history_preview_stale");
    assert.equal(fs.existsSync(path.join(f.local, ".rootark-sync.lock")), false);
    assert.equal(f.pushes(), 0);
  } finally {
    f.engine.acquireProcessLock = originalAcquire;
  }
});

test("#67 P2: preview refuses an active writer lock or a missing initialized snapshot", async (t) => {
  const f = await fixture(t);
  const lockPath = path.join(f.local, ".rootark-sync.lock");
  await fsp.mkdir(lockPath);
  await assert.rejects(f.engine.previewHistoricalRestore("object-1", "v1"),
    (error) => error.code === "sync_root_busy");
  assert.equal(fs.existsSync(lockPath), true, "preview must never replace a writer marker");
  await fsp.rmdir(lockPath);

  const snapshotPath = path.join(f.local, ".rootark-sync-index.json");
  await fsp.unlink(snapshotPath);
  await assert.rejects(f.engine.previewHistoricalRestore("object-1", "v1"),
    (error) => error.code === "history_preview_unavailable");
  assert.equal(fs.existsSync(snapshotPath), false, "a lost snapshot must not be recreated");
  assert.equal(fs.existsSync(lockPath), false);
  assert.equal(f.pushes(), 0);
});

test("#67 P2: journal loss during async historical fetch cannot return a ready preview", async (t) => {
  const f = await fixture(t);
  const journalPath = path.join(f.local, ".rootark-sync-journal.json");
  const originalHistory = f.adapter.history;
  f.adapter.history = async (...args) => {
    const history = await originalHistory(...args);
    await fsp.unlink(journalPath);
    return history;
  };
  await assert.rejects(f.engine.previewHistoricalRestore("object-1", "v1"),
    (error) => error.code === "history_preview_unavailable");
  assert.equal(fs.existsSync(journalPath), false);
  assert.equal(fs.existsSync(path.join(f.local, ".rootark-sync.lock")), false);
  assert.equal(f.pushes(), 0);
});

test("#67 P2: read-only bootstrap on an existing sync root never acquires the writer lock", async (t) => {
  const f = await fixture(t);
  const journalPath = path.join(f.local, ".rootark-sync-journal.json");
  const snapshotPath = path.join(f.local, ".rootark-sync-index.json");
  const beforeJournal = await fsp.readFile(journalPath);
  const beforeSnapshot = await fsp.readFile(snapshotPath);
  const reopened = new SyncEngine({ rootDir: f.local, adapter: f.adapter });
  reopened.acquireProcessLock = async () => { throw new Error("Read-only bootstrap acquired writer lock"); };
  await reopened.open({ readOnly: true });
  assert.equal(reopened.opened, true);
  assert.deepEqual(await fsp.readFile(journalPath), beforeJournal);
  assert.deepEqual(await fsp.readFile(snapshotPath), beforeSnapshot);
  assert.equal(fs.existsSync(path.join(f.local, ".rootark-sync.lock")), false);
});

test("#67 P2: journal loss between preview bootstrap preflight and open never recreates security state", async (t) => {
  const f = await fixture(t);
  const journalPath = path.join(f.local, ".rootark-sync-journal.json");
  const snapshotPath = path.join(f.local, ".rootark-sync-index.json");
  const beforeSnapshot = await fsp.readFile(snapshotPath);
  const reopened = new SyncEngine({ rootDir: f.local, adapter: f.adapter });
  const originalJournalOpen = reopened.journal.open.bind(reopened.journal);
  reopened.journal.open = async (options) => {
    await fsp.unlink(journalPath);
    return originalJournalOpen(options);
  };
  await assert.rejects(reopened.open({ readOnly: true }),
    (error) => error.code === "history_preview_unavailable");
  assert.equal(fs.existsSync(journalPath), false, "lost evidence must stay absent");
  assert.equal(fs.existsSync(path.join(f.local, ".rootark-sync.lock")), false);
  assert.deepEqual(await fsp.readFile(snapshotPath), beforeSnapshot);
  assert.equal(f.pushes(), 0);
});

test("#67: preview refuses missing independent evidence, revoked current device and missing custody", async (t) => {
  const f = await fixture(t, { strict: false });
  await assert.rejects(f.engine.previewHistoricalRestore("object-1", "v1"),
    (error) => error.code === "authorization_required");
  const strict = await fixture(t);
  strict.setCustody(false);
  await assert.rejects(strict.engine.previewHistoricalRestore("object-1", "v1"),
    (error) => error.code === "remote_authorization_rejected");
  strict.setCustody(true);
  strict.setGrant(false);
  await assert.rejects(strict.engine.previewHistoricalRestore("object-1", "v1"),
    (error) => error.code === "authorization_rejected");
  assert.equal(strict.pushes(), 0);
  assert.equal((await strict.engine.journal.recover()).length, 0);
});

test("#67: preview verifies every retained signature, not just selected and current", async (t) => {
  const f = await fixture(t);
  const intermediate = await f.sign({ operation: "update", versionId: "middle", operationId: "middle-op",
    baseRevision: f.original.revision, revision: { counter: 2, deviceId: "device-a" },
    metadata: { path: "note.txt" }, plaintext: Buffer.from("middle authenticated bytes") });
  f.versions.splice(1, 0, { ...intermediate, metadata: { ...intermediate.metadata, name: "tampered.txt" } });
  await assert.rejects(f.engine.previewHistoricalRestore("object-1", "v1"),
    /authorization envelope binding mismatch|authorization rejected/i);
  assert.equal(f.pushes(), 0);
});

test("#67: preview rejects valid Ed25519 proof over inaccessible AEAD payload", async (t) => {
  const f = await fixture(t);
  f.versions[0] = await f.sign({ operation: "create", versionId: "v1", operationId: "op1",
    revision: f.original.revision, metadata: { path: "note.txt" },
    plaintext: Buffer.from("authenticated historical bytes"), fileKey: crypto.randomBytes(32) });
  await assert.rejects(f.engine.previewHistoricalRestore("object-1", "v1"));
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);
});

test("#67: preview rejects a signed current head with mismatched AEAD key", async (t) => {
  const f = await fixture(t);
  const corruptedHead = await f.sign({ operation: "delete", versionId: "v2", operationId: "op2",
    baseRevision: f.original.revision, revision: f.deleted.revision,
    metadata: { path: "note.txt" }, fileKey: crypto.randomBytes(32) });
  f.versions[1] = corruptedHead;
  f.setHead(corruptedHead);
  await assert.rejects(f.engine.previewHistoricalRestore("object-1", "v1"));
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 0);
});

test("#67: preview rejects a changed current HEAD independent of historical LIST", async (t) => {
  const f = await fixture(t);
  const otherHead = await f.sign({ operation: "delete", versionId: "v3", operationId: "op3",
    baseRevision: f.deleted.revision, revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "note.txt" } });
  f.setHead(otherHead);
  await assert.rejects(f.engine.previewHistoricalRestore("object-1", "v1"),
    (error) => error.code === "invalid_history");
  assert.equal(f.pushes(), 0);
});

test("#67: preview refuses untracked and unsent local bytes but accepts clean tracked destination", async (t) => {
  const f = await fixture(t);
  const target = path.join(f.local, "note.txt");
  await fsp.writeFile(target, "untracked owner bytes");
  await assert.rejects(f.engine.previewHistoricalRestore("object-1", "v1"),
    (error) => error.code === "restore_local_conflict");
  const synchronized = Buffer.from("synchronized newer bytes");
  const hash = crypto.createHash("sha256").update(synchronized).digest("hex");
  f.engine.snapshot.files["note.txt"] = {
    objectId: "object-1", fileId: "file-1", versionId: "v2",
    revision: f.deleted.revision, hash, directory: false, deleted: false,
  };
  await f.engine.persistSnapshot();
  await assert.rejects(f.engine.previewHistoricalRestore("object-1", "v1"),
    (error) => error.code === "restore_local_conflict");
  await fsp.writeFile(target, synchronized);
  const outcome = await f.engine.previewHistoricalRestore("object-1", "v1");
  assert.equal(outcome.localAction, "replace-clean-tracked");
  assert.deepEqual(await fsp.readFile(target), synchronized);
  assert.equal(f.pushes(), 0);
});

test("#67 P2: preview succeeds across signed fileId rotation create(oldId) -> update(newId) -> delete(newId)", async (t) => {
  const f = await fixture(t);
  const oldId = "file-old";
  const newId = "file-rotated";
  const original = await f.sign({ operation: "create", fileId: oldId, versionId: "v1", operationId: "op1",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "note.txt" },
    plaintext: Buffer.from("authenticated historical bytes") });
  const updated = await f.sign({ operation: "update", fileId: newId, versionId: "v2", operationId: "op2",
    baseRevision: original.revision, revision: { counter: 2, deviceId: "device-a" },
    metadata: { path: "note.txt" }, plaintext: Buffer.from("authenticated updated bytes") });
  const deleted = await f.sign({ operation: "delete", fileId: newId, versionId: "v3", operationId: "op3",
    baseRevision: updated.revision, revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "note.txt" } });
  f.versions.splice(0, f.versions.length, original, updated, deleted);
  f.setHead(deleted);
  const outcome = await f.engine.previewHistoricalRestore("object-1", "v1");
  assert.equal(outcome.ready, true);
  assert.equal(outcome.sourceVersionId, "v1");
  assert.equal(outcome.currentVersionId, "v3");
  assert.equal(outcome.verifiedRetainedVersions, 3);
  assert.equal(f.pushes(), 0);
});

async function attachSecondSignedHistory(f, secondPath = "second.txt") {
  const first = await f.sign({ objectId: "object-2", fileId: "file-2", operation: "create",
    operationId: "second-create", versionId: "second-v1",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: secondPath }, plaintext: Buffer.from("second retained bytes") });
  const deleted = await f.sign({ objectId: "object-2", fileId: "file-2", operation: "delete",
    operationId: "second-delete", versionId: "second-v2", baseRevision: first.revision,
    revision: { counter: 2, deviceId: "device-a" }, metadata: { path: secondPath } });
  const secondVersions = [first, deleted];
  const oldHistory = f.adapter.history;
  const oldList = f.adapter.list;
  f.adapter.history = async (objectId) => objectId === "object-2"
    ? { protocolVersion: 2, versions: structuredClone(secondVersions) } : oldHistory(objectId);
  f.adapter.list = async (objectId) => objectId === "object-2"
    ? structuredClone(deleted) : oldList(objectId);
  return secondVersions;
}

const TWO_RESTORES = [
  { objectId: "object-1", versionId: "v1" },
  { objectId: "object-2", versionId: "second-v1" },
];

test("#67: multi-object preflight verifies two retained signed histories without writes", async (t) => {
  const f = await fixture(t);
  await attachSecondSignedHistory(f);
  const journal = await fsp.readFile(path.join(f.local, ".rootark-sync-journal.json"));
  const snapshot = await fsp.readFile(path.join(f.local, ".rootark-sync-index.json"));
  const plan = await f.engine.previewHistoricalRestorePlan(TWO_RESTORES);
  assert.equal(plan.readOnly, true);
  assert.equal(plan.ready, true);
  assert.equal(plan.atomic, false);
  assert.equal(plan.objectCount, 2);
  assert.equal(plan.localOverwriteCount, 0);
  assert.equal(plan.requiresFreshRestoreCheck, true);
  assert.deepEqual(plan.entries.map((entry) => [entry.objectId, entry.path,
    entry.verifiedRetainedVersions, entry.localAction]), [
    ["object-1", "note.txt", 2, "create-from-deleted"],
    ["object-2", "second.txt", 2, "create-from-deleted"],
  ]);
  assert.deepEqual(await fsp.readFile(path.join(f.local, ".rootark-sync-journal.json")), journal);
  assert.deepEqual(await fsp.readFile(path.join(f.local, ".rootark-sync-index.json")), snapshot);
  assert.equal(fs.existsSync(path.join(f.local, "note.txt")), false);
  assert.equal(fs.existsSync(path.join(f.local, "second.txt")), false);
  assert.equal(f.pushes(), 0);
});

test("#67: plan validates bounded unique IDs before any remote history read", async (t) => {
  const f = await fixture(t);
  let histories = 0;
  f.adapter.history = async () => { histories++; throw new Error("History must not be read"); };
  for (const invalid of [[], Array.from({ length: 33 }, () => TWO_RESTORES[0]),
    [TWO_RESTORES[0], TWO_RESTORES[0]],
    [{ objectId: "object-1", versionId: "../../bad" }],
    [{ objectId: "object-1", versionId: "v1", hidden: "extra" }]]) {
    await assert.rejects(f.engine.previewHistoricalRestorePlan(invalid),
      (error) => error.code === "invalid_restore_plan");
  }
  assert.equal(histories, 0);
  assert.equal(f.pushes(), 0);
});

test("#67: multi-object plan rejects case-folded file collisions and ancestor targets", async (t) => {
  const f = await fixture(t);
  await attachSecondSignedHistory(f, "NOTE.TXT");
  await assert.rejects(f.engine.previewHistoricalRestorePlan(TWO_RESTORES),
    (error) => error.code === "restore_plan_conflict");
  const g = await fixture(t);
  await attachSecondSignedHistory(g, "note.txt/child.txt");
  await assert.rejects(g.engine.previewHistoricalRestorePlan(TWO_RESTORES),
    (error) => error.code === "restore_plan_conflict");
  assert.equal(f.pushes() + g.pushes(), 0);
});

test("#67: any invalid retained history, revoked grant or local overwrite rejects entire plan", async (t) => {
  const f = await fixture(t);
  const second = await attachSecondSignedHistory(f);
  second[0] = { ...second[0], metadata: { ...second[0].metadata, path: "tampered.txt" } };
  await assert.rejects(f.engine.previewHistoricalRestorePlan(TWO_RESTORES));
  second[0] = await f.sign({ objectId: "object-2", fileId: "file-2", operation: "create",
    operationId: "second-create", versionId: "second-v1",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "second.txt" }, plaintext: Buffer.from("second retained bytes") });
  f.setGrant(false);
  await assert.rejects(f.engine.previewHistoricalRestorePlan(TWO_RESTORES),
    (error) => error.code === "authorization_rejected");
  f.setGrant(true);
  await fsp.writeFile(path.join(f.local, "second.txt"), "unsent local bytes");
  await assert.rejects(f.engine.previewHistoricalRestorePlan(TWO_RESTORES),
    (error) => error.code === "restore_local_conflict");
  assert.equal(f.pushes(), 0);
  assert.equal(fs.existsSync(path.join(f.local, "note.txt")), false);
});

test("#67: journal loss during second history read rejects full plan without recreating state", async (t) => {
  const f = await fixture(t);
  await attachSecondSignedHistory(f);
  const journalPath = path.join(f.local, ".rootark-sync-journal.json");
  const oldHistory = f.adapter.history;
  f.adapter.history = async (id) => {
    const result = await oldHistory(id);
    if (id === "object-2") await fsp.unlink(journalPath);
    return result;
  };
  await assert.rejects(f.engine.previewHistoricalRestorePlan(TWO_RESTORES),
    (error) => error.code === "history_preview_unavailable");
  assert.equal(fs.existsSync(journalPath), false);
  assert.equal(fs.existsSync(path.join(f.local, ".rootark-sync.lock")), false);
  assert.equal(f.pushes(), 0);
});

test("#67: batch preview counts clean local replacements as explicit overwrite risk", async (t) => {
  const f = await fixture(t);
  await attachSecondSignedHistory(f);
  const synchronized = Buffer.from("clean synchronized bytes");
  f.engine.snapshot.files["note.txt"] = {
    objectId: "object-1", fileId: "file-1", versionId: "v2",
    revision: f.deleted.revision,
    hash: crypto.createHash("sha256").update(synchronized).digest("hex"),
    directory: false, deleted: false,
  };
  await f.engine.persistSnapshot();
  await fsp.writeFile(path.join(f.local, "note.txt"), synchronized);
  const plan = await f.engine.previewHistoricalRestorePlan(TWO_RESTORES);
  assert.equal(plan.localOverwriteCount, 1);
  assert.equal(plan.entries[0].localAction, "replace-clean-tracked");
  assert.equal(plan.entries[1].localAction, "create-from-deleted");
  assert.deepEqual(await fsp.readFile(path.join(f.local, "note.txt")), synchronized);
  assert.equal(f.pushes(), 0);
});

test("#67: plan rejects first HEAD advancing while second signed history is fetched", async (t) => {
  const f = await fixture(t);
  await attachSecondSignedHistory(f);
  const advanced = await f.sign({ operation: "delete", versionId: "v3", operationId: "op3",
    baseRevision: f.deleted.revision, revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "note.txt" } });
  const oldHistory = f.adapter.history;
  f.adapter.history = async (objectId) => {
    const result = await oldHistory(objectId);
    if (objectId === "object-2") f.setHead(advanced);
    return result;
  };
  await assert.rejects(f.engine.previewHistoricalRestorePlan(TWO_RESTORES),
    (error) => error.code === "history_preview_stale");
  assert.equal(f.pushes(), 0);
});

test("#67: plan rechecks earlier local destination after a later asynchronous fetch", async (t) => {
  const f = await fixture(t);
  await attachSecondSignedHistory(f);
  const oldHistory = f.adapter.history;
  f.adapter.history = async (objectId) => {
    const result = await oldHistory(objectId);
    if (objectId === "object-2") await fsp.writeFile(path.join(f.local, "note.txt"), "late unsent bytes");
    return result;
  };
  await assert.rejects(f.engine.previewHistoricalRestorePlan(TWO_RESTORES),
    (error) => error.code === "restore_local_conflict");
  assert.equal(await fsp.readFile(path.join(f.local, "note.txt"), "utf8"), "late unsent bytes");
  assert.equal(f.pushes(), 0);
});

test("#67: bounded stdin plan rejects malformed data and secret-bearing extras", async () => {
  const good = await readHistoricalRestorePlanInput(Readable.from([JSON.stringify(TWO_RESTORES)]));
  assert.deepEqual(good, TWO_RESTORES);
  for (const value of ["{}", "[", JSON.stringify([{ ...TWO_RESTORES[0], token: "sensitive" }]),
    "x".repeat(16385)]) {
    await assert.rejects(readHistoricalRestorePlanInput(Readable.from([value])),
      /plan/i);
  }
});

test("#67: preview-plan CLI denies absent custody and validates stdin before reading config", () => {
  const cli = path.resolve(__dirname, "../sync-client/rootark-sync-v2.js");
  const missingCustody = spawnSync(process.execPath,
    [cli, "preview-plan", "--config", "missing-private-config", "--plan-stdin"], {
      encoding: "utf8", windowsHide: true, input: JSON.stringify(TWO_RESTORES),
      env: { ...process.env, ROOTARK_SYNC_REQUIRE_INDEPENDENT_HISTORY: "0" },
    });
  assert.equal(missingCustody.status, 1);
  assert.match(missingCustody.stderr, /independent custody/i);
  const badInput = spawnSync(process.execPath,
    [cli, "preview-plan", "--config", "missing-private-config", "--plan-stdin"], {
      encoding: "utf8", windowsHide: true,
      input: JSON.stringify([{ ...TWO_RESTORES[0], token: "never-echo-me" }]),
      env: { ...process.env, ROOTARK_SYNC_REQUIRE_INDEPENDENT_HISTORY: "1" },
    });
  assert.equal(badInput.status, 1);
  assert.match(badInput.stderr, /plan/i);
  assert.doesNotMatch(badInput.stdout + badInput.stderr, /never-echo-me|ROOTARK_SYNC_FILE_KEY|privateKey/);
});
