"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");

function unsignedOperation(key) {
  return createOperation({
    operation: "create", objectId: "remote-unsigned", fileId: "remote-file",
    versionId: "remote-version", operationId: "remote-operation",
    deviceId: "remote-device", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "remote-device" },
    metadata: { path: "remote.txt" },
    plaintext: Buffer.from("unsigned remote data"), fileKey: key,
  });
}

async function setup(t, requireAuthorization) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "zk65-incoming-proof-policy-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const remote = unsignedOperation(key);
  let verifierCalls = 0;
  const engine = await new SyncEngine({
    rootDir: dir,
    adapter: { async push() { throw new Error("Unexpected outgoing write"); },
      async list() { return [remote]; } },
    deviceId: "local-device", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key, requireAuthorization,
    verifyIncoming: async () => { verifierCalls += 1; return true; },
  }).open();
  return { dir, engine, verifierCalls: () => verifierCalls };
}

test("strict client rejects unsigned remote envelope even if custom verifier returns true", async (t) => {
  const { dir, engine, verifierCalls } = await setup(t, true);
  await assert.rejects(engine.syncOnce(), { code: "remote_authorization_rejected" });
  assert.equal(verifierCalls(), 0, "missing mandatory proof cannot delegate its presence check");
  await assert.rejects(fs.stat(path.join(dir, "remote.txt")), { code: "ENOENT" });
});

test("unprotected legacy client still imports an unsigned encrypted remote object", async (t) => {
  const { dir, engine } = await setup(t, false);
  const result = await engine.syncOnce();
  assert.equal(result.pulled, 1);
  assert.equal(await fs.readFile(path.join(dir, "remote.txt"), "utf8"), "unsigned remote data");
});
