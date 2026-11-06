"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncConflictError } = require("../public/client/rootark-sync-adapter");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

async function fixture(t) {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA, `rootark-create-path-cas-${crypto.randomBytes(8).toString("hex")}`)
    : await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-create-path-cas-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const storagePath = path.join(root, "objects.json");
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const first = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  await first.enrollDevice({ username: "alice", deviceId: "device-a", publicKey, expectedEpoch: 0 });
  const second = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  const authorize = async (operation, username = "alice") => {
    operation.authorization = await createAuthorizationProof(operation, {
      username, publicKey, privateKey: signer.privateKey, expiresAt: Date.now() + 60_000,
    });
    return operation;
  };
  const sign = async (kind, objectId, relative, counter = 1, extra = {}, username = "alice") => {
    const operation = createOperation({
      operation: kind, objectId, fileId: `file-${objectId}`, versionId: crypto.randomUUID(),
      operationId: crypto.randomUUID(), deviceId: "device-a", keyEpoch: "epoch-1",
      compartmentId: "private", revision: { counter, deviceId: "device-a" },
      baseRevision: counter > 1 ? { counter: counter - 1, deviceId: "device-a" } : null,
      metadata: { path: relative, ...(kind === "move" ? { sourcePath: extra.sourcePath } : {}) },
      plaintext: Buffer.from(`ciphertext source for ${objectId}`), fileKey: crypto.randomBytes(32),
    });
    return authorize(operation, username);
  };
  return { first, second, sign, authorize, publicKey, storagePath };
}

test("issue 66 P2 atomic: simultaneous protected CREATE after both clients' empty preflight has one winner", async (t) => {
  const { first, second, sign, storagePath } = await fixture(t);
  assert.deepEqual(first.list("alice"), [], "client A sees an empty remote path before competing write");
  assert.deepEqual(second.list("alice"), [], "client B sees an empty remote path before competing write");
  const [a, b] = await Promise.all([
    first.put("alice", await sign("create", "object-a", "docs/collision.txt")),
    second.put("alice", await sign("create", "object-b", "docs/collision.txt")),
  ]);
  assert.deepEqual([a.kind, b.kind].sort(), ["path_conflict", "stored"]);
  const recorded = first.list("alice");
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].metadata.path, "docs/collision.txt");
  assert.equal(new Set(recorded.map((entry) => entry.objectId)).size, 1);
  const reloaded = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  assert.equal(reloaded.list("alice").length, 1, "collision cannot reappear after restart");
});

test("issue 66 P2 atomic: case-only remote paths cannot double-book a Windows filename", async (t) => {
  const { first, second, sign } = await fixture(t);
  const [a, b] = await Promise.all([
    first.put("alice", await sign("create", "object-a", "Docs/File.txt")),
    second.put("alice", await sign("create", "object-b", "docs/file.txt")),
  ]);
  assert.deepEqual([a.kind, b.kind].sort(), ["path_conflict", "stored"]);
  assert.equal(first.list("alice").filter((record) => !record.tombstone).length, 1);
});

test("issue 66 P2 atomic: same pathname belongs to tenant only, active owner blocks but deleted owner releases", async (t) => {
  const { first, second, sign, publicKey } = await fixture(t);
  await first.enrollDevice({ username: "bob", deviceId: "device-a",
    publicKey, expectedEpoch: 1 });
  assert.equal((await first.put("alice", await sign("create", "object-a", "docs/shared.txt"))).kind, "stored");
  assert.equal((await second.put("bob", await sign("create", "object-b", "docs/shared.txt", 1, {}, "bob"))).kind, "stored");
  assert.equal((await second.put("alice", await sign("create", "object-c", "docs/shared.txt"))).kind, "path_conflict");
  assert.equal(first.list("alice").length, 1);
  assert.equal(first.list("bob").length, 1);
  assert.equal((await first.put("alice", await sign("update", "object-a", "docs/shared.txt", 2))).kind, "stored",
    "same objectId can update its existing path");
  assert.equal((await first.put("alice", await sign("move", "object-a", "docs/moved.txt", 3,
    { sourcePath: "docs/shared.txt" }))).kind, "stored",
    "MOVE preserves identity and should not be rejected by CREATE collision policy");
  assert.equal((await second.put("alice", await sign("create", "object-c", "docs/shared.txt"))).kind, "stored",
    "former pathname is free after MOVE");
  assert.equal((await first.put("alice", await sign("delete", "object-c", "docs/shared.txt", 2))).kind, "stored");
  assert.equal((await second.put("alice", await sign("create", "object-d", "docs/shared.txt"))).kind, "stored",
    "tombstone does not reserve the pathname");
  assert.deepEqual(first.list("alice").filter((record) => !record.tombstone).map((record) => record.metadata.path).sort(),
    ["docs/moved.txt", "docs/shared.txt"]);
});

test("issue 66 P2 atomic: losing Files On-Demand client preserves outbox when rival commits after preflight", async (t) => {
  const { first, second, sign, authorize, storagePath } = await fixture(t);
  const rootDir = path.join(path.dirname(storagePath), "client");
  const relative = "docs/collision.txt";
  const filename = path.join(rootDir, "docs", "collision.txt");
  await fsp.mkdir(path.dirname(filename), { recursive: true });
  await fsp.writeFile(filename, "local bytes must survive the race");
  let preflightReads = 0;
  let pushes = 0;
  const adapter = {
    async list(objectId = "") {
      return second.list("alice", objectId || null);
    },
    async listInventory() {
      preflightReads++;
      const records = second.list("alice").map(({ ciphertext, nonce, tag, aad, authorization, ...record }) => record);
      return { protocolVersion: 2, view: "metadata", objects: records, nextCursor: null };
    },
    async push(operation) {
      pushes++;
      if (pushes === 1) {
        assert.equal(preflightReads, 1, "another client commits only AFTER this client's empty preflight");
        assert.equal((await first.put("alice", await sign("create", "object-rival", relative))).kind, "stored");
      }
      const result = await second.put("alice", await authorize({ ...operation }));
      if (result.kind === "path_conflict") throw new SyncConflictError({
        error: "Remote path occupied by another active object", code: "remote_path_collision",
      });
      return result.record;
    },
  };
  const client = await new SyncEngine({
    rootDir, adapter, deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => crypto.randomBytes(32),
    filesOnDemand: true, selectedPaths: ["docs"],
  }).open();
  await assert.rejects(client.syncOnce(), { code: "remote_path_collision" });
  assert.equal(pushes, 1);
  assert.equal((await client.journal.recover()).length, 1, "server collision must not mark the pending CREATE seen");
  assert.equal((await client.journal.recover())[0].metadata.path, relative);
  assert.equal((await fsp.readFile(filename, "utf8")), "local bytes must survive the race");
  assert.deepEqual(second.list("alice").map((record) => record.objectId), ["object-rival"]);
});
