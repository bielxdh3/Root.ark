"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const protocol = require("../sync-client/rootark-sync-protocol");
const authorization = require("../sync-client/rootark-sync-authorization");

test("Sync v2 CLI verifies real signed incoming operations and rejects absent or forged authorization", async () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const operation = protocol.createOperation({ operation: "create", objectId: "signed-incoming",
    deviceId: "device1", keyEpoch: "epoch1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device1" },
    metadata: { path: "signed.txt" }, plaintext: Buffer.from("ciphertext-protected"),
    fileKey: crypto.randomBytes(32) });
  const signature = await authorization.createAuthorizationProof(operation, {
    username: "alice", privateKey: keys.privateKey, publicKey });
  const signedIncoming = { ...operation, authorization: signature };
  assert.equal(await authorization.verifyAuthorizationProof(signature, signedIncoming,
    { username: "alice" }), true, "test fixture must have a genuine Ed25519 proof");

  const config = { serverUrl: "https://unused.invalid", localFolder: path.resolve("unused-sync-v2"),
    token: "not-used", username: "alice", deviceId: "device1", keyEpoch: "epoch1" };
  let engineOptions = null;
  class FakeEngine {
    constructor(options) { engineOptions = options; }
    async open() { return this; }
    async syncOnce() { return { pushed: 0, pulled: 0, conflicts: [], offline: false }; }
  }
  const imports = {
    "node:crypto": crypto,
    "node:fs/promises": { readFile: async () => JSON.stringify(config) },
    "node:path": path,
    "./rootark-sync-engine": { SyncEngine: FakeEngine },
    "../public/client/rootark-sync-adapter": { createOpaqueSyncAdapter: () => ({}) },
    "./rootark-sync-authorization": authorization,
  };
  const source = fs.readFileSync(path.join(__dirname, "../sync-client/rootark-sync-v2.js"), "utf8");
  const sandboxModule = { exports: {} };
  vm.runInNewContext(source, {
    module: sandboxModule, exports: sandboxModule.exports,
    require(name) {
      if (!Object.hasOwn(imports, name)) throw Error("Unexpected Sync v2 import: " + name);
      return imports[name];
    },
    process: { env: { ROOTARK_SYNC_FILE_KEY: crypto.randomBytes(32).toString("base64url"),
      ROOTARK_SYNC_DEVICE_PRIVATE_KEY: keys.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"),
      ROOTARK_SYNC_DEVICE_PUBLIC_KEY: publicKey }, cwd: () => process.cwd(), argv: [] },
    Buffer, console: { log() {} }, setTimeout,
  }, { filename: "sync-client/rootark-sync-v2.js" });
  await sandboxModule.exports.start({ config: "not-opened.json", once: true });
  assert.ok(engineOptions && engineOptions.requireAuthorization === true);
  assert.equal(await engineOptions.verifyIncoming(signedIncoming), true);
  assert.equal(await engineOptions.verifyIncoming({ ...operation }), false,
    "missing authorization must fail closed");
  await assert.rejects(engineOptions.verifyIncoming({ ...signedIncoming,
    authorization: { ...signature, signature: crypto.randomBytes(64).toString("base64url") } }),
  /Authorization signature invalid/);
  await assert.rejects(engineOptions.verifyIncoming({ ...signedIncoming,
    metadata: { ...signedIncoming.metadata, path: "forged.txt" } }),
  /Authorization payload mismatch/);
});
