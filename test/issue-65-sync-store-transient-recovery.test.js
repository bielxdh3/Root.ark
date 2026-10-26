"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");
const { createOperation } = require("../sync-client/rootark-sync-protocol");

function encryptedCreate(operationId) {
  return createOperation({ operation: "create", operationId,
    objectId: `object-${operationId}`, fileId: `file-${operationId}`,
    versionId: `version-${operationId}`, deviceId: "device-a",
    keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: `${operationId}.txt` },
    plaintext: Buffer.from("ciphertext-only-after-encryption"),
    fileKey: crypto.randomBytes(32) });
}

test("failed mutation leaves committed state unchanged and does not permanently poison sync writes", async (t) => {
  const folder = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-recovery-"));
  t.after(() => fs.rm(folder, { recursive: true, force: true }));
  const file = path.join(folder, "objects.json");
  const store = await new SyncObjectStore(file).open();
  const committed = await fs.readFile(file, "utf8");
  await assert.rejects(store.transact((state) => {
    state.users.alice = { objects: { forged: { plaintext: "must-not-persist" } } };
    throw new Error("injected transient mutation error");
  }), /injected transient mutation error/);
  assert.equal(await fs.readFile(file, "utf8"), committed);
  assert.deepEqual(store.list("alice"), []);

  const operation = encryptedCreate("after-error");
  assert.equal((await store.put("alice", operation)).kind, "stored");
  assert.equal(store.list("alice").length, 1);
  const reopened = await new SyncObjectStore(file).open();
  assert.equal(reopened.list("alice").length, 1);
  assert.equal(reopened.list("alice")[0].operationId, operation.operationId);
  assert.equal(await fs.readFile(file, "utf8").then((value) => value.includes("must-not-persist")), false);
});

test("failed filesystem commit remains uncommitted and the next durable commit can succeed", async (t) => {
  const folder = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-durable-retry-"));
  t.after(() => fs.rm(folder, { recursive: true, force: true }));
  const file = path.join(folder, "objects.json");
  const store = await new SyncObjectStore(file).open();
  const first = encryptedCreate("before-error");
  assert.equal((await store.put("alice", first)).kind, "stored");
  const stable = await fs.readFile(file, "utf8");
  const originalRename = fs.rename;
  fs.rename = async (source, destination) => {
    if (destination === file) throw Object.assign(new Error("injected transient disk failure"), { code: "EIO" });
    return originalRename(source, destination);
  };
  try {
    await assert.rejects(store.put("alice", encryptedCreate("failed-write")), { code: "EIO" });
  } finally { fs.rename = originalRename; }
  assert.equal(await fs.readFile(file, "utf8"), stable);
  assert.deepEqual(store.list("alice").map((item) => item.operationId), [first.operationId]);

  const next = encryptedCreate("after-disk-recovery");
  assert.equal((await store.put("alice", next)).kind, "stored");
  const reopened = await new SyncObjectStore(file).open();
  assert.deepEqual(reopened.list("alice").map((item) => item.operationId).sort(),
    [first.operationId, next.operationId].sort());
});

test("post-rename directory sync ambiguity quarantines every process and restart", async (t) => {
  const folder = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-sync-ambiguous-"));
  t.after(() => fs.rm(folder, { recursive: true, force: true }));
  const file = path.join(folder, "objects.json");
  const handlers = new Map();
  const capture = (method) => (route, ...chain) => handlers.set(`${method} ${route}`, chain.at(-1));
  const app = { get: capture("GET"), post: capture("POST"), put: capture("PUT"), delete: capture("DELETE") };
  const { store, ready } = registerSyncRoutes({ app, storagePath: file,
    authenticate() {}, requirePermission: () => () => {} });
  await ready;
  const old = encryptedCreate("already-committed");
  assert.equal((await store.put("alice", old)).kind, "stored");
  const peer = await new SyncObjectStore(file).open();
  const originalOpen = fs.open;
  fs.open = async (target, mode, ...args) => {
    if (target === folder && mode === "r") {
      return { async sync() { throw Object.assign(new Error("injected directory fsync failure"), { code: "EIO" }); }, async close() {} };
    }
    return originalOpen(target, mode, ...args);
  };
  const ambiguous = encryptedCreate("renamed-but-not-confirmed");
  try {
    await assert.rejects(store.put("alice", ambiguous), { code: "EIO" });
  } finally { fs.open = originalOpen; }
  const renamedState = await fs.readFile(file, "utf8");
  assert.ok(renamedState.includes(ambiguous.operationId), "rename already exposed the new record");

  assert.throws(() => store.list("alice"), { code: "SYNC_COMMIT_INDETERMINATE" },
    "remote clients must not read a stale in-memory head after an ambiguous rename");
  assert.throws(() => store.history("alice", old.objectId), { code: "SYNC_COMMIT_INDETERMINATE" },
    "history readback must not silently omit the indeterminate commit");

  const response = { statusCode: 200, body: null,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; } };
  await handlers.get("POST /sync/v1/objects")({ user: { username: "alice" }, method: "POST",
    body: encryptedCreate("rejected-by-http") }, response);
  assert.equal(response.statusCode, 503);
  assert.equal(response.body.code, "SYNC_COMMIT_INDETERMINATE");

  await assert.rejects(store.put("alice", encryptedCreate("unsafe-followup")),
    { code: "SYNC_COMMIT_INDETERMINATE" }, "same process must not overwrite the ambiguous disk state");
  assert.equal(await fs.readFile(file, "utf8"), renamedState, "unconfirmed operation has not been overwritten");
  assert.throws(() => peer.list("alice"), { code: "SYNC_STORE_LOCK_BUSY" },
    "a second process cannot serve the ambiguous rename as confirmed inventory");
  await assert.rejects(peer.put("alice", encryptedCreate("unsafe-peer-followup")),
    { code: "SYNC_STORE_LOCK_BUSY" });
  await assert.rejects(new SyncObjectStore(file).open(), { code: "SYNC_STORE_LOCK_BUSY" },
    "restart must require explicit operator reconciliation before writes resume");
  assert.equal(await fs.readFile(file, "utf8"), renamedState);
  assert.ok((await fs.stat(`${file}.writer-lock`)).isFile(), "durable quarantine survives the failed process");
});
