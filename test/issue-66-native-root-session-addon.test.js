"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  ROOT_SESSION_CONTRACT,
  openNativeRootSession,
  openCompiledNativeRootSession,
  isVerifiedNativeRootSession,
} = require("../sync-client/rootark-sync-native-root-session-contract");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");

test("issue 66 native addon: implements all 13 REQUIRED_OPERATIONS and rejects JS forgery", async (t) => {
  const scratch = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-native-addon-"));
  const rootDir = path.join(scratch, "vault");
  await fsp.mkdir(rootDir, { recursive: true });
  t.after(() => fsp.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));

  const session = openCompiledNativeRootSession(rootDir);
  t.after(() => { try { session.close(); } catch { /* already closed */ } });

  assert.equal(isVerifiedNativeRootSession(session), true);
  const forged = Object.fromEntries(ROOT_SESSION_CONTRACT.requiredOperations.map((k) => [k, () => true]));
  assert.equal(isVerifiedNativeRootSession(forged), false, "plain JS object cannot impersonate RootSession");
  assert.throws(() => openNativeRootSession(true, forged), { code: "root_session_native_unavailable" });

  for (const op of ROOT_SESSION_CONTRACT.requiredOperations) {
    if (op === "openRootFromTrustedParent") continue;
    assert.equal(typeof session[op], "function", `missing native method ${op}`);
  }

  assert.equal(session.openChildDirectory("docs/sub"), true);
  assert.throws(() => session.openChildDirectory("../escape"), /Unsafe|traversal/i);

  const payload = Buffer.from("native-root-session-bytes-v1");
  assert.equal(session.createExclusiveFile("docs/sub/a.tmp", payload), true);
  assert.throws(() => session.createExclusiveFile("docs/sub/a.tmp", payload), /Exclusive create failed/);

  assert.equal(session.renameNoReplace("docs/sub/a.tmp", "docs/sub/a.txt"), true);
  assert.equal(session.createExclusiveFile("docs/sub/b.tmp", Buffer.from("rival")), true);
  assert.throws(() => session.renameNoReplace("docs/sub/b.tmp", "docs/sub/a.txt"), /No-replace|RENAME_NOREPLACE/);

  const stat = session.openContainedFile("docs/sub/a.txt");
  assert.equal(stat.size, payload.length);
  assert.deepEqual(session.readOpenedFile("docs/sub/a.txt"), payload);
  assert.deepEqual(session.enumerateDirectory("docs/sub").sort(), ["a.txt", "b.tmp"]);

  assert.equal(session.syncOpenedFile("docs/sub/a.txt"), true);
  assert.equal(session.syncDirectory("docs/sub"), true);
  assert.equal(session.reacquireRoot(), true);
  assert.equal(session.commitDurableRecovery(), true);

  assert.equal(session.removeEntry("docs/sub/b.tmp"), true);
  assert.deepEqual(session.enumerateDirectory("docs/sub"), ["a.txt"]);
  assert.equal(session.close(), true);
  assert.equal(isVerifiedNativeRootSession(session), false, "closed session is no longer verified");
});

test("issue 66 native SyncEngine: hydrates with nativeRootSession while default FOD stays fail-closed", async (t) => {
  const scratch = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-native-engine-"));
  const rootDir = path.join(scratch, "root");
  t.after(() => fsp.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));

  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trusted = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] };
  const plaintext = Buffer.from("verified native RootSession hydration payload");
  const op = protocol.createOperation({
    operation: "create", objectId: "obj-native-1", fileId: "file-native-1",
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "docs/native.txt", size: plaintext.length },
    plaintext, fileKey: key,
  });
  op.authorization = await createAuthorizationProof(op, {
    username: "alice", privateKey: signer.privateKey, publicKey, expiresAt: Date.now() + 60_000,
  });
  const { authorization, ciphertext, nonce, tag, aad, ...inv } = op;
  const adapter = {
    async listInventory() { return { protocolVersion: 2, view: "metadata", objects: [inv], nextCursor: null }; },
    async list() { return [op]; },
    async push() { return []; },
  };
  const baseOpts = {
    rootDir, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs"], filesOnDemand: true, fileKeyResolver: () => key,
    requireAuthorization: true,
    verifyIncoming: (o) => verifyAuthorizationProof(o.authorization, o, trusted),
    authorizationFactory: (o) => createAuthorizationProof(o, {
      username: "alice", privateKey: signer.privateKey, publicKey, expiresAt: Date.now() + 60_000,
    }),
  };

  const failClosed = await new SyncEngine(baseOpts).open();
  await assert.rejects(failClosed.materializeRemote("docs/native.txt"), { code: "root_session_native_unavailable" });
  assert.equal(fs.existsSync(path.join(rootDir, "docs", "native.txt")), false);

  const nativeEngine = await new SyncEngine({ ...baseOpts, nativeRootSession: true }).open();
  try {
    assert.equal(await nativeEngine.materializeRemote("docs/native.txt"), true);
    assert.deepEqual(await fsp.readFile(path.join(rootDir, "docs", "native.txt")), plaintext);
  } finally {
    await nativeEngine.close();
  }
});
