"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

async function fixture(t) {
  const root = createPrivateAuthorityFixture("rootark-67-batch-execute-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const local = path.join(root, "local");
  await fsp.mkdir(local);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const fileKey = crypto.randomBytes(32);
  const policy = { username: "alice", trustedDevicePublicKeys: { "device-a": spki }, revokedDeviceIds: [] };
  const store = await new SyncObjectStore(path.join(root, "store.json"), { atomicDeviceRegistry: true }).open();
  await store.enrollDevice({ username: "alice", deviceId: "device-a", publicKey: spki, expectedEpoch: 0 });
  const sign = async (index, input) => {
    const operation = protocol.createOperation({
      objectId: `object-${index}`, fileId: `file-${index}`, deviceId: "device-a",
      keyEpoch: "epoch-1", compartmentId: "private", fileKey, ...input,
    });
    return { ...operation, authorization: await createAuthorizationProof(operation,
      { username: "alice", privateKey, publicKey: spki }) };
  };
  for (let index = 1; index <= 2; index++) {
    const original = await sign(index, { operation: "create", operationId: `create-${index}`,
      versionId: `version-${index}`, revision: { counter: 1, deviceId: "device-a" },
      metadata: { path: `file-${index}.txt` }, plaintext: Buffer.from(`signed owner bytes ${index}`) });
    const deleted = await sign(index, { operation: "delete", operationId: `delete-${index}`,
      versionId: `deleted-${index}`, baseRevision: original.revision,
      revision: { counter: 2, deviceId: "device-a" }, metadata: { path: `file-${index}.txt` } });
    assert.equal((await store.put("alice", original)).kind, "stored");
    assert.equal((await store.put("alice", deleted)).kind, "stored");
  }
  let grants = true;
  let custody = true;
  let pushes = 0;
  const adapter = {
    history: async (id) => ({ protocolVersion: 2, versions: store.history("alice", id) }),
    list: async (id) => store.list("alice", id)[0],
    push: async (operation) => {
      pushes += 1;
      const result = await store.put("alice", operation);
      if (result.kind !== "stored") throw Object.assign(new Error(`Remote denied: ${result.kind}`),
        { status: result.kind === "conflict" ? 409 : 403 });
      return result.record;
    },
  };
  const opts = {
    rootDir: local, adapter, deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => fileKey,
    requireAuthorization: true, requireIndependentHistoricalAdmission: true,
    reverifySeenIncoming: true, requireCurrentOutgoingAuthorization: true,
    currentDeviceAuthorization: () => grants,
    authorizeOutgoing: () => grants,
    authorize: () => grants,
    verifyIncoming: (record) => custody && verifyAuthorizationProof(record.authorization, record, policy),
    authorizationFactory: (record) => createAuthorizationProof(record,
      { username: "alice", privateKey, publicKey: spki }),
  };
  const engine = await new SyncEngine(opts).open();
  const requests = [
    { objectId: "object-1", versionId: "version-1" },
    { objectId: "object-2", versionId: "version-2" },
  ];
  return { root, local, engine, opts, requests, store, adapter, fileKey, sign,
    setGrant: (value) => { grants = value; },
    setCustody: (value) => { custody = value; },
    pushes: () => pushes,
  };
}

test("#67: controlled two-object restore commits actual signed CAS and durable per-object outcomes", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan(f.requests);
  const outcome = await f.engine.restoreHistoricalPlan(preview, { confirm: true });
  assert.equal(outcome.atomic, false);
  assert.equal(outcome.completed, 2);
  assert.equal(outcome.remaining, 0);
  assert.equal(outcome.partial, false);
  assert.equal(f.pushes(), 2);
  assert.deepEqual(outcome.items.map((item) => item.status), ["committed", "committed"]);
  for (let index = 1; index <= 2; index++) {
    assert.equal(await fsp.readFile(path.join(f.local, `file-${index}.txt`), "utf8"),
      `signed owner bytes ${index}`);
    const newest = f.store.list("alice", `object-${index}`)[0];
    assert.equal(newest.operation, "update");
    assert.match(newest.operationId, /^histrestore-/);
    assert.equal(newest.baseRevision.counter, 2);
    assert.equal(newest.revision.counter, 3);
  }
  await assert.rejects(f.engine.restoreHistoricalPlan(preview, { confirm: true }),
    (error) => error.code === "restore_plan_exists");
  const resumed = await f.engine.restoreHistoricalPlan(preview, { confirm: true, resume: true });
  assert.equal(resumed.completed, 2);
  assert.equal(f.pushes(), 2, "resume never duplicates an already signed commit");
});

test("#67: first signed success, second grant denied, then safe resume only second", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan(f.requests);
  const history = f.adapter.history;
  let revokedOnce = false;
  f.adapter.history = async (objectId) => {
    if (objectId === "object-2" && f.pushes() === 1 && !revokedOnce) {
      revokedOnce = true;
      f.setGrant(false);
    }
    return history(objectId);
  };
  const interrupted = await f.engine.restoreHistoricalPlan(preview, { confirm: true });
  assert.equal(interrupted.completed, 1);
  assert.equal(interrupted.partial, true);
  assert.equal(interrupted.items[0].status, "committed");
  assert.equal(interrupted.items[1].status, "blocked");
  assert.equal(f.pushes(), 1);
  await assert.rejects(f.engine.restoreHistoricalPlan(preview, { confirm: true, resume: true }),
    (error) => error.code === "authorization_rejected");
  f.setGrant(true);
  const reopened = await new SyncEngine(f.opts).open();
  const recovered = await reopened.restoreHistoricalPlan(preview, { confirm: true, resume: true });
  assert.equal(recovered.completed, 2);
  assert.equal(f.pushes(), 2);
  assert.equal(f.store.history("alice", "object-1").length, 3);
  assert.equal(f.store.history("alice", "object-2").length, 3);
});

test("#67: stage crash leaves an indeterminate signed intent; resume never repeats it", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan(f.requests);
  f.engine._pushPending = async () => { throw new Error("simulated process termination after local stage"); };
  const outcome = await f.engine.restoreHistoricalPlan(preview, { confirm: true });
  assert.equal(outcome.partial, true);
  assert.equal(outcome.items[0].status, "indeterminate");
  assert.equal(f.pushes(), 0);
  assert.equal((await f.engine.journal.recover()).length, 1);
  const reopened = await new SyncEngine(f.opts).open();
  await assert.rejects(reopened.restoreHistoricalPlan(preview, { confirm: true, resume: true }),
    (error) => error.code === "restore_plan_indeterminate");
  assert.equal(f.pushes(), 0);
  assert.equal(f.store.history("alice", "object-1").length, 2);
  assert.equal(f.store.history("alice", "object-2").length, 2);
});

test("#67: lost ACK after a real signed commit reconciles exact head without a second PUT", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan(f.requests);
  const push = f.adapter.push;
  let lostAck = false;
  f.adapter.push = async (operation) => {
    const result = await push(operation);
    if (!lostAck) {
      lostAck = true;
      throw new Error("simulated response dropped after durable commit");
    }
    return result;
  };
  const interrupted = await f.engine.restoreHistoricalPlan(preview, { confirm: true });
  assert.equal(interrupted.completed, 0);
  assert.equal(interrupted.items[0].status, "indeterminate");
  assert.equal(f.pushes(), 1);
  assert.equal(f.store.history("alice", "object-1").length, 3);
  const reopened = await new SyncEngine(f.opts).open();
  assert.equal((await reopened._verifyCommittedRestorePlanItem(interrupted.items[0],
    preview.entries[0])).operationId, interrupted.items[0].operationId);
  const resumed = await reopened.restoreHistoricalPlan(preview, { confirm: true, resume: true });
  assert.equal(resumed.completed, 2);
  assert.equal(resumed.items[0].status, "committed");
  assert.equal(f.pushes(), 2, "first signed write must never be retransmitted");
  assert.equal((await reopened.journal.recover()).length, 0);
  assert.equal(f.store.history("alice", "object-1").length, 3);
  assert.equal(f.store.history("alice", "object-2").length, 3);
});

test("#67: changed preview plan aborts before any write, and missing custody fails closed", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan(f.requests);
  const changed = { ...preview, entries: preview.entries.map((entry, i) => i
    ? { ...entry, path: "not-current.txt" } : entry) };
  await assert.rejects(f.engine.restoreHistoricalPlan(changed, { confirm: true }),
    (error) => error.code === "restore_plan_stale");
  f.setCustody(false);
  await assert.rejects(f.engine.restoreHistoricalPlan(preview, { confirm: true }));
  assert.equal(f.pushes(), 0);
  assert.equal(fs.existsSync(path.join(f.local, "file-1.txt")), false);
});

test("#67: new epoch or concurrent untracked destination rejects controlled execution", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan(f.requests);
  f.engine.keyEpoch = "epoch-2";
  await assert.rejects(f.engine.restoreHistoricalPlan(preview, { confirm: true }),
    (error) => error.code === "stale_key_epoch" || error.code === "restore_plan_stale");
  f.engine.keyEpoch = "epoch-1";
  const target = path.join(f.local, "file-2.txt");
  await fsp.writeFile(target, "untracked owner edits");
  await assert.rejects(f.engine.restoreHistoricalPlan(preview, { confirm: true }),
    (error) => error.code === "restore_local_conflict");
  assert.equal(await fsp.readFile(target, "utf8"), "untracked owner edits");
  assert.equal(f.pushes(), 0);
});

test("#67 reviewer P2: full retention cannot prune a selected second-oldest signed source", async (t) => {
  const f = await fixture(t);
  const operations = [];
  let prior = null;
  for (let counter = 1; counter <= 32; counter++) {
    const operation = await f.sign(3, { operation: counter === 1 ? "create" : "update",
      operationId: `retained-source-op-${counter}`,
      versionId: `retained-source-version-${counter}`,
      ...(prior ? { baseRevision: prior.revision } : {}),
      revision: { counter, deviceId: "device-a" },
      metadata: { path: "retained-source.txt" }, plaintext: Buffer.from(`content-${counter}`) });
    operations.push(operation);
    prior = operation;
  }
  const existingHistory = f.adapter.history;
  const existingList = f.adapter.list;
  f.adapter.history = async (objectId) => objectId === "object-3"
    ? { protocolVersion: 2, versions: operations } : existingHistory(objectId);
  f.adapter.list = async (objectId) => objectId === "object-3"
    ? operations[operations.length - 1] : existingList(objectId);
  await assert.rejects(f.engine.previewHistoricalRestorePlan([
    { objectId: "object-3", versionId: "retained-source-version-2" },
  ]), (error) => error.code === "history_source_prune_risk");
  assert.equal(f.pushes(), 0, "unsafe retention never mutates signed history");
});

test("#67 reviewer P2: 32 valid 511-character paths fit the execution plan admission budget", async (t) => {
  const f = await fixture(t);
  const histories = new Map();
  const requests = [];
  for (let index = 1; index <= 32; index++) {
    const objectId = `large-plan-${index}-${"x".repeat(36)}`;
    const versionId = `large-source-${index}-${"y".repeat(36)}`;
    const relativePath = `p${String(index).padStart(2, "0")}/${"a".repeat(180)}/${"b".repeat(180)}/${"c".repeat(145)}`;
    assert.equal(relativePath.length, 511);
    const created = await f.sign(index, { objectId, operation: "create",
      operationId: `large-plan-create-${index}`, versionId,
      revision: { counter: 1, deviceId: "device-a" },
      metadata: { path: relativePath }, plaintext: Buffer.from("owner data") });
    const removed = await f.sign(index, { objectId, operation: "delete",
      operationId: `large-plan-delete-${index}`,
      versionId: `deleted-${index}`, baseRevision: created.revision,
      revision: { counter: 2, deviceId: "device-a" },
      metadata: { path: relativePath } });
    histories.set(objectId, [created, removed]);
    requests.push({ objectId, versionId });
  }
  f.adapter.history = async (objectId) => ({ protocolVersion: 2,
    versions: histories.get(objectId) || [] });
  f.adapter.list = async (objectId) => histories.get(objectId)?.at(-1) || null;
  const plan = await f.engine.previewHistoricalRestorePlan(requests);
  assert.equal(plan.ready, true);
  assert.equal(plan.objectCount, 32);
  assert.ok(Buffer.byteLength(protocol.canonicalJson(plan)) > 32768,
    "a valid bounded 32-object plan legitimately exceeds the previous cap");
  f.engine.withMutationLock = async () => {
    throw Object.assign(new Error("stop before any mutation"), { code: "test_execution_reached" });
  };
  await assert.rejects(f.engine.restoreHistoricalPlan(plan, { confirm: true }),
    (error) => error.code === "test_execution_reached",
    "the exact preview must not be rejected by a smaller execution-only byte cap");
  assert.equal(f.pushes(), 0);
});

test("#67 reviewer P1: late signed remote update cannot become an unreviewed restore CAS base", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan([f.requests[0]]);
  const expected = preview.entries[0];
  const originalRestore = f.engine._restoreHistoricalVersion.bind(f.engine);
  let injected = false;
  f.engine._restoreHistoricalVersion = async (objectId, sourceVersionId, options) => {
    if (!injected) {
      injected = true;
      const old = f.store.list("alice", objectId)[0];
      assert.equal(old.versionId, expected.currentVersionId);
      const concurrent = await f.sign(1, { operation: "delete",
        operationId: "unreviewed-remote-delete", versionId: "unreviewed-remote-version",
        baseRevision: old.revision,
        revision: { counter: old.revision.counter + 1, deviceId: "device-a" },
        metadata: { path: "file-1.txt" } });
      assert.equal((await f.store.put("alice", concurrent)).kind, "stored");
    }
    return originalRestore(objectId, sourceVersionId, options);
  };
  const result = await f.engine.restoreHistoricalPlan(preview, { confirm: true });
  assert.equal(injected, true);
  assert.equal(result.completed, 0, "late remote update cannot be silently replaced");
  assert.equal(result.items[0].status, "blocked");
  assert.equal(f.pushes(), 0, "no signed restore is dispatched using unreviewed HEAD");
  assert.equal(f.store.list("alice", "object-1")[0].operationId,
    "unreviewed-remote-delete", "concurrent signed HEAD remains authoritative");
  assert.equal((await f.engine.journal.recover()).length, 0);
});

test("#67: signed remote HEAD change after preview denies all writes before first mutation", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan(f.requests);
  const prior = f.store.list("alice", "object-2")[0];
  const next = await f.sign(2, { operation: "delete", operationId: "delete-new-2",
    versionId: "deleted-new-2", baseRevision: prior.revision,
    revision: { counter: 3, deviceId: "device-a" }, metadata: { path: "file-2.txt" } });
  assert.equal((await f.store.put("alice", next)).kind, "stored");
  await assert.rejects(f.engine.restoreHistoricalPlan(preview, { confirm: true }),
    (error) => error.code === "restore_plan_stale");
  assert.equal(f.pushes(), 0);
  assert.equal(fs.existsSync(path.join(f.local, "file-1.txt")), false);
});

test("#67: later untracked file after first commit is preserved, remainder resumes only once", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan(f.requests);
  const history = f.adapter.history;
  let injected = false;
  f.adapter.history = async (objectId) => {
    if (!injected && objectId === "object-2" && f.pushes() === 1) {
      injected = true;
      await fsp.writeFile(path.join(f.local, "file-2.txt"), "late unsent owner content");
    }
    return history(objectId);
  };
  const partial = await f.engine.restoreHistoricalPlan(preview, { confirm: true });
  assert.equal(partial.completed, 1);
  assert.equal(partial.items[1].status, "blocked");
  assert.equal(await fsp.readFile(path.join(f.local, "file-2.txt"), "utf8"),
    "late unsent owner content");
  assert.equal(f.pushes(), 1);
  await fsp.unlink(path.join(f.local, "file-2.txt"));
  const reopened = await new SyncEngine(f.opts).open();
  const resumed = await reopened.restoreHistoricalPlan(preview, { confirm: true, resume: true });
  assert.equal(resumed.completed, 2);
  assert.equal(f.pushes(), 2);
});

test("#67: clean tracked overwrite requires separate explicit consent and preserves prior bytes", async (t) => {
  const f = await fixture(t);
  const previousBytes = Buffer.from("previous synchronized local bytes");
  await fsp.writeFile(path.join(f.local, "file-1.txt"), previousBytes);
  f.engine.snapshot.files["file-1.txt"] = {
    objectId: "object-1", fileId: "file-1", versionId: "deleted-1",
    revision: { counter: 2, deviceId: "device-a" }, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(previousBytes).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const preview = await f.engine.previewHistoricalRestorePlan(f.requests);
  assert.equal(preview.localOverwriteCount, 1);
  await assert.rejects(f.engine.restoreHistoricalPlan(preview, { confirm: true }),
    (error) => error.code === "restore_plan_overwrite_confirmation_required");
  assert.equal(f.pushes(), 0);
  const outcome = await f.engine.restoreHistoricalPlan(preview,
    { confirm: true, confirmCleanOverwrite: true });
  assert.equal(outcome.completed, 2);
  assert.equal(outcome.localOverwriteCount, 1);
  assert.equal(outcome.items[0].localAction, "replace-clean-tracked");
  const trash = await fsp.readdir(path.join(f.local, ".rootark-trash"));
  assert.equal(trash.length, 1);
  assert.deepEqual(await fsp.readFile(path.join(f.local, ".rootark-trash", trash[0])),
    previousBytes);
});

test("#67 P2: failed initial fsynced progress creation cannot permanently brick a never-started plan", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan([f.requests[0]]);
  const originalOpen = fsp.open;
  let injected = false;
  fsp.open = async (filePath, flags, ...rest) => {
    const handle = await originalOpen(filePath, flags, ...rest);
    if (!injected && flags === "wx" && String(filePath).includes(".rootark-recovery-execution-")) {
      injected = true;
      return new Proxy(handle, { get(target, key) {
        if (key === "writeFile") return async () => {
          throw Object.assign(new Error("injected write before initial fsync"), { code: "ENOSPC" });
        };
        const value = Reflect.get(target, key, target);
        return typeof value === "function" ? value.bind(target) : value;
      } });
    }
    return handle;
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalPlan(preview, { confirm: true }),
      (error) => error.code === "ENOSPC");
  } finally { fsp.open = originalOpen; }
  assert.equal(injected, true);
  assert.equal(f.pushes(), 0);
  const names = await fsp.readdir(f.local);
  assert.equal(names.some((name) => /^\.rootark-recovery-execution-[a-f0-9]{64}\.json$/.test(name)),
    false, "no final progress file may exist before a complete fsynced write");
  assert.ok(names.some((name) => name.includes(".rootark-recovery-execution-") && name.includes(".tmp-")),
    "uncommitted temporary evidence is preserved");
  const outcome = await f.engine.restoreHistoricalPlan(preview, { confirm: true });
  assert.equal(outcome.completed, 1);
  assert.equal(f.pushes(), 1);
});

test("#67 P2: crash after final hardlink publication with two links safely resumes once", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan([f.requests[0]]);
  const originalLink = fsp.link;
  let interrupted = false;
  fsp.link = async (source, destination) => {
    const linked = await originalLink(source, destination);
    if (!interrupted && String(destination).includes(".rootark-recovery-execution-")
      && String(destination).endsWith(".json")) {
      interrupted = true;
      throw Object.assign(new Error("simulated crash immediately after final link"), { code: "EIO" });
    }
    return linked;
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalPlan(preview, { confirm: true }),
      (error) => error.code === "EIO");
  } finally { fsp.link = originalLink; }
  assert.equal(interrupted, true);
  assert.equal(f.pushes(), 0);
  const names = await fsp.readdir(f.local);
  const final = names.find((name) => /^\.rootark-recovery-execution-[a-f0-9]{64}\.json$/.test(name));
  const temporary = names.find((name) => name.startsWith(`${final}.tmp-`));
  assert.ok(final && temporary);
  const before = await fsp.lstat(path.join(f.local, final), { bigint: true });
  const sibling = await fsp.lstat(path.join(f.local, temporary), { bigint: true });
  assert.equal(before.nlink, 2n);
  assert.equal(before.ino, sibling.ino);
  const reopened = await new SyncEngine(f.opts).open();
  const result = await reopened.restoreHistoricalPlan(preview, { confirm: true, resume: true });
  assert.equal(result.completed, 1);
  assert.equal(f.pushes(), 1);
  assert.equal((await fsp.lstat(path.join(f.local, final), { bigint: true })).nlink, 1n);
  assert.equal(fs.existsSync(path.join(f.local, temporary)), true,
    "original temporary is retained until identity-bound native retirement exists");
  assert.equal((await fsp.lstat(path.join(f.local, temporary), { bigint: true })).nlink, 1n);
});

test("#67 P2: unknown foreign hardlink to valid final progress is never unlinked or trusted", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan([f.requests[0]]);
  const originalLink = fsp.link;
  let interrupted = false;
  fsp.link = async (source, destination) => {
    const linked = await originalLink(source, destination);
    if (!interrupted && String(destination).includes(".rootark-recovery-execution-")
      && String(destination).endsWith(".json")) {
      interrupted = true;
      throw Object.assign(new Error("simulated post-link crash"), { code: "EIO" });
    }
    return linked;
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalPlan(preview, { confirm: true }),
      (error) => error.code === "EIO");
  } finally { fsp.link = originalLink; }
  const names = await fsp.readdir(f.local);
  const final = names.find((name) => /^\.rootark-recovery-execution-[a-f0-9]{64}\.json$/.test(name));
  const temporary = names.find((name) => name.startsWith(`${final}.tmp-`));
  const foreign = path.join(f.local, "foreign-duplicate-link");
  await fsp.rename(path.join(f.local, temporary), foreign);
  const reopened = await new SyncEngine(f.opts).open();
  await assert.rejects(reopened.restoreHistoricalPlan(preview, { confirm: true, resume: true }),
    (error) => error.code === "restore_plan_unavailable");
  assert.equal((await fsp.lstat(path.join(f.local, final), { bigint: true })).nlink, 2n);
  assert.equal(fs.existsSync(foreign), true);
  assert.equal(f.pushes(), 0);
});

test("#67 P2: a renamed foreign inode never replaces the verified progress temporary at unlink", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan([f.requests[0]]);
  const linkOriginal = fsp.link;
  let interrupted = false;
  fsp.link = async (source, destination) => {
    const linked = await linkOriginal(source, destination);
    if (!interrupted && String(destination).includes(".rootark-recovery-execution-")
      && String(destination).endsWith(".json")) {
      interrupted = true;
      throw Object.assign(new Error("crash after durable final link"), { code: "EIO" });
    }
    return linked;
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalPlan(preview, { confirm: true }),
      (error) => error.code === "EIO");
  } finally { fsp.link = linkOriginal; }
  assert.equal(interrupted, true);
  const names = await fsp.readdir(f.local);
  const final = names.find((name) => /^\.rootark-recovery-execution-[a-f0-9]{64}\.json$/.test(name));
  const temporary = path.join(f.local,
    names.find((name) => name.startsWith(`${final}.tmp-`)));
  const retained = `${temporary}.retained`;
  const nativeLstat = fsp.lstat;
  const unlinkOriginal = fsp.unlink;
  let swapped = false;
  let attemptedForeignUnlink = false;
  let foreignFd;
  let foreignStats;
  fsp.lstat = async (name, ...args) => {
    const stats = await nativeLstat(name, ...args);
    if (!swapped && name === temporary) {
      swapped = true;
      // The original two-link inode survives under retained. The attacker
      // puts unrelated bytes at the SAME checked name before its unlink.
      await fsp.rename(temporary, retained);
      await fsp.writeFile(temporary, "foreign synthetic progress marker");
      foreignFd = await fsp.open(temporary, "r");
      foreignStats = await foreignFd.stat({ bigint: true });
    }
    return stats;
  };
  fsp.unlink = async (name, ...args) => {
    if (name === temporary) {
      attemptedForeignUnlink = true;
      // Intercept at syscall boundary rather than actually deleting foreign.
      throw Object.assign(new Error("intercepted foreign unlink"), { code: "EACCES" });
    }
    return unlinkOriginal(name, ...args);
  };
  try {
    const reopened = await new SyncEngine(f.opts).open();
    await assert.rejects(reopened.restoreHistoricalPlan(preview,
      { confirm: true, resume: true }),
    (error) => error.code === "restore_plan_unavailable");
  } finally {
    fsp.lstat = nativeLstat;
    fsp.unlink = unlinkOriginal;
  }
  try {
    assert.equal(swapped, true, "test must replace the actual previously stat'ed temporary");
    assert.equal(attemptedForeignUnlink, false,
      "a checked inode must never authorize unlinking a later foreign pathname");
    assert.equal((await foreignFd.stat({ bigint: true })).ino, foreignStats.ino);
    assert.equal((await fsp.lstat(temporary, { bigint: true })).ino, foreignStats.ino);
    // The foreign descriptor was opened at the actual swap. Read THAT held
    // inode, not the independently mutable pathname checked by lstat above.
    assert.equal(await foreignFd.readFile({ encoding: "utf8" }),
      "foreign synthetic progress marker");
    assert.equal((await fsp.lstat(retained, { bigint: true })).nlink, 2n);
    assert.equal(f.pushes(), 0);
  } finally {
    if (foreignFd) await foreignFd.close();
  }
});

test("#67 P2: directory fsync failure after no-replace publication retains valid resumable final", async (t) => {
  if (process.platform === "win32") return t.skip("Windows does not support portable directory fsync");
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan([f.requests[0]]);
  const originalOpen = fsp.open;
  const originalLink = fsp.link;
  let published = false;
  let injected = false;
  fsp.link = async (...args) => {
    const result = await originalLink(...args);
    if (String(args[1]).includes(".rootark-recovery-execution-")) published = true;
    return result;
  };
  fsp.open = async (filePath, flags, ...rest) => {
    const handle = await originalOpen(filePath, flags, ...rest);
    if (published && !injected && filePath === f.local && flags === fs.constants.O_RDONLY) {
      injected = true;
      return new Proxy(handle, { get(target, key) {
        if (key === "sync") return async () => {
          throw Object.assign(new Error("simulated post-publication dir fsync EIO"), { code: "EIO" });
        };
        const value = Reflect.get(target, key, target);
        return typeof value === "function" ? value.bind(target) : value;
      } });
    }
    return handle;
  };
  try {
    await assert.rejects(f.engine.restoreHistoricalPlan(preview, { confirm: true }),
      (error) => error.code === "EIO");
  } finally {
    fsp.open = originalOpen;
    fsp.link = originalLink;
  }
  assert.equal(injected, true);
  assert.equal(f.pushes(), 0);
  const final = (await fsp.readdir(f.local)).find((name) =>
    /^\.rootark-recovery-execution-[a-f0-9]{64}\.json$/.test(name));
  assert.ok(final);
  const finalStat = await fsp.lstat(path.join(f.local, final), { bigint: true });
  assert.equal(finalStat.nlink, 2n,
    "a failed directory fsync must retain the original named temporary, not unlink by a mutable pathname");
  const aliases = (await fsp.readdir(f.local)).filter((name) =>
    name.startsWith(`${final}.tmp-`));
  assert.equal(aliases.length, 1, "exactly one original temporary remains as a retained alias");
  const aliasStat = await fsp.lstat(path.join(f.local, aliases[0]), { bigint: true });
  assert.equal(aliasStat.nlink, 2n);
  assert.equal(aliasStat.dev, finalStat.dev);
  assert.equal(aliasStat.ino, finalStat.ino,
    "published final and retained temporary must be the same already-fsynced inode");
  const reopened = await new SyncEngine(f.opts).open();
  const resumed = await reopened.restoreHistoricalPlan(preview, { confirm: true, resume: true });
  assert.equal(resumed.completed, 1);
  assert.equal(f.pushes(), 1);
});

test("#67 P2: final grant revocation before enqueue permits safe retry only after proof of no dispatch", async (t) => {
  const f = await fixture(t);
  const preview = await f.engine.previewHistoricalRestorePlan([f.requests[0]]);
  let signedChecks = 0;
  f.engine.authorizeOutgoing = (operation) => {
    if (operation.operationId.startsWith("histrestore-")) signedChecks += 1;
    return !operation.operationId.startsWith("histrestore-") || signedChecks !== 3;
  };
  const denied = await f.engine.restoreHistoricalPlan(preview, { confirm: true });
  assert.equal(denied.completed, 0);
  assert.equal(denied.items[0].status, "blocked");
  assert.equal(denied.items[0].neverDispatched, true);
  assert.equal(signedChecks, 3);
  assert.equal((await f.engine.journal.recover()).length, 0);
  assert.equal(f.pushes(), 0);
  assert.equal(f.store.history("alice", "object-1").length, 2);
  const reopened = await new SyncEngine(f.opts).open();
  const resumed = await reopened.restoreHistoricalPlan(preview, { confirm: true, resume: true });
  assert.equal(resumed.completed, 1);
  assert.equal(f.pushes(), 1, "only one new signed PUT after fresh authorization");
  assert.equal(f.store.history("alice", "object-1").length, 3);
});

test("#67 P2: discarded unsent local-conflict intent stays blocked until clean and safely resumes", async (t) => {
  const f = await fixture(t);
  const original = Buffer.from("last synchronized local content");
  const target = path.join(f.local, "file-1.txt");
  await fsp.writeFile(target, original);
  f.engine.snapshot.files["file-1.txt"] = {
    objectId: "object-1", fileId: "file-1", versionId: "deleted-1",
    revision: { counter: 2, deviceId: "device-a" }, deleted: false, directory: false,
    hash: crypto.createHash("sha256").update(original).digest("hex"),
  };
  await f.engine.persistSnapshot();
  const preview = await f.engine.previewHistoricalRestorePlan([f.requests[0]]);
  const enqueue = f.engine.journal.enqueue.bind(f.engine.journal);
  f.engine.journal.enqueue = async (operation) => {
    const result = await enqueue(operation);
    await fsp.writeFile(target, "unsent owner modification");
    return result;
  };
  const denied = await f.engine.restoreHistoricalPlan(preview,
    { confirm: true, confirmCleanOverwrite: true });
  assert.equal(denied.items[0].status, "blocked");
  assert.equal(denied.items[0].neverDispatched, true);
  assert.equal((await f.engine.journal.recover()).length, 0);
  assert.equal(f.pushes(), 0);
  const reopened = await new SyncEngine(f.opts).open();
  await assert.rejects(reopened.restoreHistoricalPlan(preview,
    { confirm: true, confirmCleanOverwrite: true, resume: true }),
  (error) => error.code === "restore_local_conflict");
  assert.equal(await fsp.readFile(target, "utf8"), "unsent owner modification");
  await fsp.writeFile(target, original);
  const resumed = await reopened.restoreHistoricalPlan(preview,
    { confirm: true, confirmCleanOverwrite: true, resume: true });
  assert.equal(resumed.completed, 1);
  assert.equal(f.pushes(), 1);
});
