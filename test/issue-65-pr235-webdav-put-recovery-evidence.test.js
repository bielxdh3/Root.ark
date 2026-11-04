"use strict";

// Node22-only exclusive-gate tests. This fixture never writes to a real user
// journal or uses a production WebDAV account. TEST_UNRUN while gate closed.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

function fixture(t, operation) {
  const parent = createPrivateAuthorityFixture("webdav-replay-pin-");
  const root = path.join(parent, "private");
  fs.mkdirSync(root, { mode: 0o700 });
  const shutdown = [];
  t.after(async () => {
    // The root must outlive the bridge's filesystem ownership release.
    try { for (const stop of shutdown) await stop(); }
    finally { fs.rmSync(parent, { recursive: true, force: true }); }
  });
  const queued = [];
  const seen = [];
  const journal = {
    recover: async () => [operation],
    markSeen: async (id) => { seen.push(id); },
    update: async () => {},
  };
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: "test-only-replay-token",
    journal, protocolJournal: { enqueue: async (item) => { queued.push(item); } },
    toProtocolOperation: async (item) => ({ operationId: item.operationId,
      operation: item.kind }),
  });
  return { root, bridge, queued, seen, operation,
    registerShutdown: (stop) => shutdown.push(stop) };
}

function bindSyntheticInodeWitness(f) {
  // Unit fixture only. A fabricated witness is NOT proof of journal custody;
  // independent durable-journal reopen cases belong to the disk tests.
  const stat = fs.lstatSync(path.join(f.root, "item.txt"), { bigint: true });
  f.operation.installedIdentity = { dev: String(stat.dev), ino: String(stat.ino),
    type: "file" };
}

function put(phase, content = "AUTHENTIC_UPLOAD") {
  return {
    operationId: "put-replay", kind: "put", phase,
    path: "/item.txt", existed: false,
    putBytes: Buffer.byteLength(content),
    putSha256: crypto.createHash("sha256").update(content).digest("hex"),
  };
}

test("prepared PUT cannot enqueue a preexisting unrelated file as a completed upload", async (t) => {
  const f = fixture(t, put("prepared"));
  fs.writeFileSync(path.join(f.root, "item.txt"), "FOREIGN_PREEXISTING_BYTES");
  await assert.rejects(f.bridge.recoverPending(), { code: "WEBDAV_RECOVERY_INDETERMINATE" });
  assert.deepEqual(f.queued, []);
  assert.deepEqual(f.seen, []);
  assert.equal(fs.readFileSync(path.join(f.root, "item.txt"), "utf8"),
    "FOREIGN_PREEXISTING_BYTES");
});

test("source-moved PUT with matching synthetic inode witness can resume trusted journal fixture", async (t) => {
  const f = fixture(t, put("source-moved"));
  fs.writeFileSync(path.join(f.root, "item.txt"), "AUTHENTIC_UPLOAD", { mode: 0o600 });
  bindSyntheticInodeWitness(f);
  await f.bridge.recoverPending();
  assert.deepEqual(f.queued, [{ operationId: "put-replay", operation: "put" }]);
  assert.deepEqual(f.seen, ["put-replay"]);
});

test("source-moved PUT refuses a same-size foreign replacement without queueing", async (t) => {
  const f = fixture(t, put("source-moved"));
  fs.writeFileSync(path.join(f.root, "item.txt"), "FOREIGN!!_UPLOAD", { mode: 0o600 });
  bindSyntheticInodeWitness(f);
  await assert.rejects(f.bridge.recoverPending(), { code: "WEBDAV_RECOVERY_INDETERMINATE" });
  assert.deepEqual(f.queued, []);
  assert.deepEqual(f.seen, []);
});

test("old source-moved PUT records without content evidence fail closed", async (t) => {
  const legacy = put("source-moved");
  delete legacy.putSha256;
  delete legacy.putBytes;
  const f = fixture(t, legacy);
  fs.writeFileSync(path.join(f.root, "item.txt"), "AUTHENTIC_UPLOAD");
  await assert.rejects(f.bridge.recoverPending(), { code: "WEBDAV_RECOVERY_INDETERMINATE" });
  assert.deepEqual(f.queued, []);
  assert.deepEqual(f.seen, []);
});

test("staged existing PUT with both backup and destination remains indeterminate", async (t) => {
  const operation = { ...put("staged"), existed: true,
    trash: ".rootark-trash/existing-backup" };
  const f = fixture(t, operation);
  fs.mkdirSync(path.join(f.root, ".rootark-trash"), { mode: 0o700 });
  fs.writeFileSync(path.join(f.root, ".rootark-trash", "existing-backup"), "ORIGINAL");
  fs.writeFileSync(path.join(f.root, "item.txt"), "FOREIGN_PREEXISTING_BYTES");
  await assert.rejects(f.bridge.recoverPending(), { code: "WEBDAV_RECOVERY_INDETERMINATE" });
  assert.deepEqual(f.queued, []);
  assert.deepEqual(f.seen, []);
  assert.equal(fs.readFileSync(path.join(f.root, ".rootark-trash", "existing-backup"), "utf8"),
    "ORIGINAL", "manual recovery evidence must not be destroyed");
});

test("prepared PUT with no target has no bytes to replay and never enqueues", async (t) => {
  const f = fixture(t, put("prepared"));
  await f.bridge.recoverPending();
  assert.deepEqual(f.queued, []);
  assert.deepEqual(f.seen, ["put-replay"]);
});

test("real authenticated HTTP PUT records immutable byte count and SHA for restart", {
  timeout: 120000,
}, async (t) => {
  const { root, bridge: recoveryBridge, queued, seen, registerShutdown } = fixture(t, put("prepared"));
  const recorded = [];
  const mutationJournal = {
    enqueue: async (item) => { recorded.push({ ...item }); },
    update: async (id, changes) => {
      const entry = recorded.find((item) => item.operationId === id);
      if (entry) Object.assign(entry, changes);
    },
    markSeen: async () => {},
  };
  const live = new LocalSyncWebDavBridge({ rootDir: root, token: "test-only-http-put",
    journal: mutationJournal, port: 0 });
  registerShutdown(() => live.stop());
  await live.start();
  const content = Buffer.from("PAYLOAD_SIGNED_IN_LOCAL_MUTATION_JOURNAL");
  const response = await new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: live.address().port,
      method: "PUT", path: "/item.txt",
      headers: { authorization: "Bearer test-only-http-put" } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    req.on("error", reject);
    req.end(content);
  });
  assert.equal(response, 201);
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].phase, "source-moved");
  assert.equal(recorded[0].putBytes, content.length);
  assert.equal(recorded[0].putSha256, crypto.createHash("sha256")
    .update(content).digest("hex"));
  // A simulated lost journal ACK must not depend on guessed fixture digests:
  // replay exactly the operation captured from the true HTTP PUT path.
  recoveryBridge.journal.recover = async () => [recorded[0]];
  await recoveryBridge.recoverPending();
  assert.deepEqual(queued, [{ operationId: recorded[0].operationId, operation: "put" }]);
  assert.deepEqual(seen, [recorded[0].operationId]);
  assert.deepEqual(fs.readFileSync(path.join(root, "item.txt")), content);
});
