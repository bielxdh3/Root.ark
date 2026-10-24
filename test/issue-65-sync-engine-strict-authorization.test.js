"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const protocol = require("../sync-client/rootark-sync-protocol");

test("strict sync refuses remote ciphertext if no incoming authorization verifier was supplied", async (t) => {
  const rootDir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-sync-strict-auth-"));
  t.after(() => fsp.rm(rootDir, { recursive: true, force: true }));
  const fileKey = crypto.randomBytes(32);
  const remote = protocol.createOperation({
    operation: "create",
    objectId: "untrusted-remote",
    deviceId: "device-foreign",
    keyEpoch: "epoch-1",
    compartmentId: "private",
    revision: { counter: 1, deviceId: "device-foreign" },
    metadata: { path: "injected.txt" },
    plaintext: Buffer.from("unapproved remote plaintext"),
    fileKey,
  });
  // Incoming bytes are genuinely encrypted. The failure must be the missing
  // verification authority, not a malformed envelope or unavailable file key.
  const engine = await new SyncEngine({
    rootDir, adapter: { push: async () => ({}), list: async () => [] },
    deviceId: "device-local", keyEpoch: "epoch-1",
    fileKeyResolver: () => fileKey, requireAuthorization: true,
  }).open();

  await assert.rejects(engine.apply(remote), { code: "remote_authorization_rejected" });
  await assert.rejects(fsp.readFile(path.join(rootDir, "injected.txt")), { code: "ENOENT" });
});
