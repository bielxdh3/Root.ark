"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createOperation, validateOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncObjectStore } = require("../src/routes/sync");
const { attestCiphertextOnlyRecords } = require("../src/services/deploymentResilience");

test("expired historical device proof remains readable but cannot authorize a new write", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-historical-sync-auth-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, "sync.json");
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = createOperation({ operation: "create", objectId: "historical-object",
    fileId: "historical-file", versionId: "historical-version", operationId: "historical-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "historical.txt" },
    plaintext: Buffer.from("ciphertext-only"), fileKey: crypto.randomBytes(32) });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: keys.privateKey, publicKey, expiresAt: Date.now() + 5000,
  });
  assert.equal(validateOperation(operation).operationId, operation.operationId);
  const store = await new SyncObjectStore(file).open();
  assert.equal((await store.put("alice", operation)).kind, "stored");
  const now = Date.now;
  try {
    Date.now = () => operation.authorization.expiresAt + 1;
    assert.throws(() => validateOperation(operation), { code: "authorization_expired" });
    const reopened = await new SyncObjectStore(file).open();
    assert.equal(reopened.list("alice").length, 1);
    assert.equal(reopened.list("alice")[0].authorization.signature,
      operation.authorization.signature);
    assert.throws(() => attestCiphertextOnlyRecords([{ ...operation,
      authorization: { ...operation.authorization, signature: "not*base64url" },
    }]), { code: "SYNC_ATTESTATION_FAILED" });
  } finally { Date.now = now; }
});
