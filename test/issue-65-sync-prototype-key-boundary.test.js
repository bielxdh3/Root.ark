"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { SyncObjectStore } = require("../src/routes/sync");
const { createOperation } = require("../sync-client/rootark-sync-protocol");

function encryptedCreate(objectId, operationId, fileKey) {
  return createOperation({
    operation: "create", objectId, operationId, fileId: "file-" + objectId,
    versionId: "version-" + objectId, deviceId: "device-a",
    keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: objectId + ".txt", name: objectId + ".txt", size: 4 },
    plaintext: Buffer.from("data"), fileKey,
  });
}

test("issue 65 sync: inherited operation and object keys cannot impersonate committed records", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-issue65-sync-proto-keys-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, "objects.json");
  const store = await new SyncObjectStore(file).open();
  const key = crypto.randomBytes(32);
  const first = encryptedCreate("item-a", "constructor", key);
  const second = encryptedCreate("constructor", "operation-b", key);
  const third = encryptedCreate("toString", "toString", key);
  assert.equal((await store.put("alice", first)).kind, "stored");
  assert.equal((await store.put("alice", second)).kind, "stored");
  assert.equal((await store.put("alice", third)).kind, "stored");
  assert.equal((await store.put("alice", first)).kind, "replay");

  const reopened = await new SyncObjectStore(file).open();
  assert.equal(reopened.list("alice").length, 3);
  assert.equal(reopened.history("alice", "constructor").length, 1);
  assert.equal(reopened.history("alice", "toString").length, 1);
  assert.equal(reopened.list("constructor").length, 0);
});

test("issue 65 sync: authenticated prototype-named account is stored without mutating Object.prototype", () => {
  // A child process contains any prototype pollution on the unpatched RED implementation.
  const modulePath = path.resolve(__dirname, "../src/routes/sync.js");
  const protocolPath = path.resolve(__dirname, "../sync-client/rootark-sync-protocol.js");
  const script = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs/promises");
    const os = require("node:os");
    const path = require("node:path");
    const crypto = require("node:crypto");
    const { SyncObjectStore } = require(${JSON.stringify(modulePath)});
    const { createOperation } = require(${JSON.stringify(protocolPath)});
    (async () => {
      const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-issue65-proto-user-"));
      try {
        const file = path.join(directory, "objects.json");
        const store = await new SyncObjectStore(file).open();
        const operation = createOperation({
          operation: "create", objectId: "object-a", operationId: "operation-a",
          fileId: "file-a", versionId: "version-a", deviceId: "device-a",
          keyEpoch: "epoch-1", compartmentId: "private",
          revision: { counter: 1, deviceId: "device-a" },
          metadata: { path: "a.txt", name: "a.txt", size: 4 },
          plaintext: Buffer.from("data"), fileKey: crypto.randomBytes(32),
        });
        assert.equal((await store.put("__proto__", operation)).kind, "stored");
        assert.equal(Object.hasOwn(Object.prototype, "objects"), false);
        const persisted = JSON.parse(await fs.readFile(file, "utf8"));
        assert.equal(Object.hasOwn(persisted.users, "__proto__"), true);
        const reopened = await new SyncObjectStore(file).open();
        assert.equal(reopened.list("__proto__").length, 1);
        assert.equal(reopened.list("constructor").length, 0);
      } finally {
        await fs.rm(directory, { recursive: true, force: true });
      }
    })().catch((error) => { process.stderr.write(error.stack + "\\n"); process.exitCode = 1; });
  `;
  const child = spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8", timeout: 15000, windowsHide: true,
  });
  assert.equal(child.status, 0, child.stderr || child.error?.message || "child failed");
});

test("issue 65 sync: missing legacy account maps cannot inherit process-global polluted dictionaries", () => {
  const modulePath = path.resolve(__dirname, "../src/routes/sync.js");
  const protocolPath = path.resolve(__dirname, "../sync-client/rootark-sync-protocol.js");
  const script = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs/promises");
    const os = require("node:os");
    const path = require("node:path");
    const crypto = require("node:crypto");
    const { SyncObjectStore } = require(${JSON.stringify(modulePath)});
    const { createOperation } = require(${JSON.stringify(protocolPath)});
    (async () => {
      const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-issue65-poisoned-map-"));
      try {
        const file = path.join(directory, "objects.json");
        const store = await new SyncObjectStore(file).open();
        store.state.users.alice = {}; // A legacy account with missing per-object indexes.
        Object.defineProperty(Object.prototype, "seen", {
          value: { "operation-a": true }, configurable: true,
        });
        Object.defineProperty(Object.prototype, "objects", {
          value: { "object-a": { revision: { counter: 999 } } }, configurable: true,
        });
        Object.defineProperty(Object.prototype, "versions", {
          value: { "object-a": [{ revision: { counter: 999 } }] }, configurable: true,
        });
        assert.deepEqual(store.list("alice"), [], "a legacy account cannot expose inherited ciphertext");
        assert.deepEqual(store.list("alice", "object-a"), [], "a lookup cannot expose inherited object state");
        assert.deepEqual(store.history("alice", "object-a"), [], "history cannot expose inherited revisions");
        const operation = createOperation({
          operation: "create", objectId: "object-a", operationId: "operation-a",
          fileId: "file-a", versionId: "version-a", deviceId: "device-a",
          keyEpoch: "epoch-1", compartmentId: "private",
          revision: { counter: 1, deviceId: "device-a" },
          metadata: { path: "a.txt", name: "a.txt", size: 4 },
          plaintext: Buffer.from("data"), fileKey: crypto.randomBytes(32),
        });
        assert.equal((await store.put("alice", operation)).kind, "stored");
        assert.equal(Object.hasOwn(store.state.users.alice, "seen"), true);
        assert.equal(Object.hasOwn(store.state.users.alice, "objects"), true);
        const reopened = await new SyncObjectStore(file).open();
        assert.equal(reopened.list("alice").length, 1);
      } finally { await fs.rm(directory, { recursive: true, force: true }); }
    })().catch((error) => { process.stderr.write(error.stack + "\\n"); process.exitCode = 1; });
  `;
  const child = spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8", timeout: 15000, windowsHide: true,
  });
  assert.equal(child.status, 0, child.stderr || child.error?.message || "child failed");
});
