"use strict";

// TEST_UNRUN: Node/WSL gate requires NODE_COUNT=0 + >=4096 MiB free RAM.
// Durable pair provenance is distinct from signed individual operation IDs.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

async function fixture(t) {
  const root = createPrivateAuthorityFixture("cos-atomic-journal-");
  const filename = path.join(root, "protocol-outbox.json");
  const journal = await new SyncJournal(filename).open();
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" })
    .toString("base64url");
  const event = crypto.randomUUID();
  t.after(async () => fsp.rm(root, { recursive: true, force: true, maxRetries: 5 }));
  const make = async (verb, relativePath, operationId, objectId) => {
    const plaintext = verb === "move"
      ? protocol.encodeMovePayload(Buffer.from("signed move bytes"), key)
      : Buffer.from("{}");
    const envelope = protocol.createOperation({
      operation: verb, operationId, objectId, fileId: `file-${objectId}`,
      versionId: crypto.randomUUID(), deviceId: "device-a", keyEpoch: "epoch-1",
      compartmentId: "private", revision: { counter: 2, deviceId: "device-a" },
      baseRevision: { counter: 1, deviceId: "device-a" },
      metadata: verb === "move"
        ? { path: relativePath, sourcePath: "source.ct" }
        : verb === "create" ? { path: relativePath, size: 2 }
          : { path: relativePath },
      plaintext, fileKey: key,
    });
    envelope.authorization = await createAuthorizationProof(envelope, {
      username: "alice", publicKey, privateKey: signer.privateKey,
      expiresAt: Date.now() + 120_000,
    });
    assert.equal(await verifyAuthorizationProof(envelope.authorization, envelope, {
      username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
      revokedDeviceIds: [],
    }), true, "test must start with cryptographically authentic signed envelopes");
    return envelope;
  };
  const digest = (verb) => crypto.createHash("sha256")
    .update(`${verb}:target.ct`).digest("hex").slice(0, 24);
  const deleted = await make("delete", "target.ct",
    `webdav-${event}-${digest("delete")}`, "old-target");
  const moved = await make("move", "target.ct",
    `webdav-${event}-${digest("move")}`, "source-object");
  const unrelated = await make("create", "unrelated.ct",
    `ordinary-${crypto.randomUUID()}`, "unrelated-object");
  return { root, filename, journal, event, deleted, moved, unrelated, make };
}

test("a signed DELETE + MOVE atomic group survives interleaved fsync and cannot mark either member seen alone", {
  timeout: 60000,
}, async (t) => {
  const f = await fixture(t);
  await f.journal.enqueue(f.deleted);
  await f.journal.enqueue(f.unrelated);
  await f.journal.enqueueMany([f.deleted, f.moved]);
  const cold = await new SyncJournal(f.filename).open();
  assert.deepEqual(cold.pending(), [f.deleted, f.unrelated, f.moved]);
  assert.deepEqual(cold.atomicSignedGroups(), {
    [f.event]: { deleteId: f.deleted.operationId, moveId: f.moved.operationId },
  });
  const before = await fsp.readFile(f.filename);
  await assert.rejects(cold.markSeen(f.deleted.operationId),
    /Atomic signed WebDAV pair requires markSeenMany/);
  await assert.rejects(cold.markSeen(f.moved.operationId),
    /Atomic signed WebDAV pair requires markSeenMany/);
  assert.deepEqual(await fsp.readFile(f.filename), before,
    "no separately acknowledged member may reach the durable journal");
  await cold.markSeenMany([
    { operationId: f.deleted.operationId }, { operationId: f.moved.operationId },
  ]);
  const after = await new SyncJournal(f.filename).open();
  assert.deepEqual(after.pending(), [f.unrelated]);
  assert.equal(after.hasSeen(f.deleted.operationId), true);
  assert.equal(after.hasSeen(f.moved.operationId), true);
  assert.deepEqual(after.atomicSignedGroups(), {});
});

test("cold open rejects missing signed MOVE while its durable atomic group still names both IDs", {
  timeout: 60000,
}, async (t) => {
  const f = await fixture(t);
  await f.journal.enqueueMany([f.deleted, f.moved]);
  const poisoned = JSON.parse(await fsp.readFile(f.filename, "utf8"));
  poisoned.pending = [f.deleted];
  delete poisoned.committedSigned[f.moved.operationId];
  const bytes = Buffer.from(JSON.stringify(poisoned) + "\n");
  const handle = await fsp.open(f.filename, "r+");
  try { await handle.truncate(0); await handle.writeFile(bytes); await handle.sync(); }
  finally { await handle.close(); }
  await assert.rejects(new SyncJournal(f.filename).open(),
    /Invalid atomic signed WebDAV journal group/);
  assert.deepEqual(await fsp.readFile(f.filename), bytes);
});

test("reordered or extra signed MOVE companions are rejected without ANY journal write", {
  timeout: 60000,
}, async (t) => {
  const f = await fixture(t);
  const before = await fsp.readFile(f.filename);
  for (const invalid of [[f.moved, f.deleted],
    [f.deleted, f.moved, f.unrelated], [f.moved, f.unrelated]]) {
    await assert.rejects(f.journal.enqueueMany(invalid),
      /Invalid atomic signed WebDAV batch membership/);
    assert.deepEqual(await fsp.readFile(f.filename), before);
  }
});

test("new cryptographically distinct webdavsolo DELETE remains a legal independent journal operation", {
  timeout: 60000,
}, async (t) => {
  const f = await fixture(t);
  const solo = await f.make("delete", "target.ct",
    `webdavsolo-${f.event}-${crypto.createHash("sha256")
      .update("delete:target.ct").digest("hex").slice(0, 24)}`, "solo-target");
  await f.journal.enqueue(solo);
  const cold = await new SyncJournal(f.filename).open();
  assert.deepEqual(cold.atomicSignedGroups(), {});
  await cold.markSeen(solo.operationId);
  const seen = await new SyncJournal(f.filename).open();
  assert.deepEqual(seen.pending(), []);
  assert.equal(seen.hasSeen(solo.operationId), true);
});
