"use strict";

// TEST_UNRUN: Node/WSL gate requires NODE_COUNT=0 and >=4096 MiB free RAM.
// This is an adapter transport-contract test, not proof that the server's
// atomic registry, independent CAS/witness or remote batch has been deployed.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");

async function signedPair() {
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" })
    .toString("base64url");
  const key = crypto.randomBytes(32);
  const sign = async (operation, metadata, objectId, fileId, options = {}) => {
    const payload = operation === "move"
      ? protocol.encodeMovePayload(Buffer.from("authorized relocated file"), key)
      : Buffer.from("{}");
    const envelope = protocol.createOperation({
      operation, operationId: options.operationId || crypto.randomUUID(), objectId, fileId,
      versionId: crypto.randomUUID(), deviceId: options.deviceId || "device-a",
      keyEpoch: options.keyEpoch || "epoch-1",
      compartmentId: options.compartmentId || "private",
      revision: { counter: 2, deviceId: "device-a" },
      baseRevision: { counter: 1, deviceId: "device-a" },
      metadata, plaintext: payload, fileKey: key,
    });
    envelope.authorization = await createAuthorizationProof(envelope, {
      username: "alice", publicKey, privateKey: pair.privateKey,
      expiresAt: Date.now() + 120_000,
      ...(options.replayId ? { replayId: options.replayId } : {}),
      ...(options.idempotencyKey ? { idempotencyKey: options.idempotencyKey } : {}),
    });
    assert.equal(await verifyAuthorizationProof(envelope.authorization, envelope, {
      username: "alice", trustedDevicePublicKeys: { [envelope.deviceId]: publicKey },
      revokedDeviceIds: [],
    }), true, "positive control uses actually verifiable Ed25519 envelopes");
    return envelope;
  };
  const deleted = await sign("delete", { path: "target.ct" },
    "old-target-object", "old-target-file");
  const moved = await sign("move", {
    path: "target.ct", sourcePath: "source.ct",
  }, "original-source-object", "original-source-file");
  return { deleted, moved, sign, publicKey };
}

function adapterWithCalls() {
  const calls = [];
  const adapter = createOpaqueSyncAdapter({
    baseUrl: "https://sync.example.test",
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return { status: 200, ok: true,
        json: async () => ({ protocolVersion: 2, objects: [] }) };
    },
  });
  return { calls, adapter };
}

test("two real Ed25519-signed DELETE then MOVE envelopes use ONE remote atomic POST, not two push() calls", async () => {
  const { deleted, moved } = await signedPair();
  const { calls, adapter } = adapterWithCalls();
  const result = await adapter.pushBatch([deleted, moved]);
  assert.deepEqual(result, { protocolVersion: 2, objects: [] });
  assert.equal(calls.length, 1, "no partial remote DELETE can precede a failed MOVE");
  assert.equal(calls[0].url, "https://sync.example.test/sync/v1/objects/batch");
  assert.equal(calls[0].options.method, "POST");
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(calls[0].options.headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(calls[0].options.body), { operations: [deleted, moved] },
    "retain exact signature, nonce, AAD and ciphertext in one POST body");
});

test("incomplete, reversed, unsigned, unrelated or repeated signed batches never dispatch HTTP", async () => {
  const { deleted, moved, sign, publicKey } = await signedPair();
  // Construct ENTIRELY NEW independently valid AES-GCM/Ed25519 envelopes,
  // not shallow tampering that assertOpaqueEnvelope would reject earlier due
  // to an unrelated AAD/signature mismatch (false-green pair-guard tests).
  const alternate = async (metadata = { path: "target.ct", sourcePath: "source.ct" },
    objectId = moved.objectId, fileId = moved.fileId, options = {}) => {
    const signed = await sign("move", metadata, objectId, fileId, options);
    assert.equal(await verifyAuthorizationProof(signed.authorization, signed, {
      username: "alice", trustedDevicePublicKeys: { [signed.deviceId]: publicKey },
      revokedDeviceIds: [],
    }), true);
    return signed;
  };
  const otherDestination = await alternate({ path: "other.ct", sourcePath: "source.ct" });
  const sameObject = await alternate(undefined, deleted.objectId);
  const sameFile = await alternate(undefined, moved.objectId, deleted.fileId);
  const differentDevice = await alternate(undefined, moved.objectId, moved.fileId,
    { deviceId: "device-b" });
  const differentCompartment = await alternate(undefined, moved.objectId, moved.fileId,
    { compartmentId: "other" });
  const differentKeyEpoch = await alternate(undefined, moved.objectId, moved.fileId,
    { keyEpoch: "epoch-2" });
  const repeatedOperationId = await alternate(undefined, moved.objectId, moved.fileId,
    { operationId: deleted.operationId });
  const repeatedReplay = await alternate(undefined, moved.objectId, moved.fileId,
    { replayId: deleted.authorization.replayId });
  const repeatedIdempotency = await alternate(undefined, moved.objectId, moved.fileId,
    { idempotencyKey: deleted.authorization.idempotencyKey });
  const unsigned = { ...moved };
  delete unsigned.authorization;
  const { calls, adapter } = adapterWithCalls();
  for (const invalid of [
    [], [deleted], [moved, deleted], [deleted, moved, moved],
    [deleted, unsigned], [deleted, otherDestination],
    [deleted, sameObject], [deleted, sameFile],
    [deleted, differentDevice], [deleted, differentCompartment],
    [deleted, differentKeyEpoch], [deleted, repeatedOperationId],
    [deleted, repeatedReplay], [deleted, repeatedIdempotency],
  ]) {
    await assert.rejects(async () => adapter.pushBatch(invalid));
  }
  assert.equal(calls.length, 0, "bad batch must never partly reach a remote write");
});
