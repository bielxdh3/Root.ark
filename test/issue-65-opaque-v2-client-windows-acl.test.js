"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { Zk1OpaqueCheckpointV2Client } =
  require("../src/services/zk1OpaqueCheckpointV2Client");
const { Zk1OpaqueCatalogCheckpointV2Stage } =
  require("../src/services/zk1OpaqueCatalogCheckpointV2Stage");
const { createOpaqueCheckpointV2HttpsClient } =
  require("../src/services/zk1OpaqueCheckpointV2Remote");
const { createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { privateAuthorityDirectory, privateAuthorityChild } =
  require("./support/issue-65-private-authority-directory");
const { assertPrivateSqliteAuthorityDirectory } =
  require("../src/services/zk1PrivateSqlitePath");

test("Windows checkpoint V2 journal rejects Users Modify before bootstrap and after launch", {
  skip: process.platform !== "win32",
}, async (t) => {
  const root = privateAuthorityDirectory("zk65-v2-private-acl-");
  let client;
  let stage;
  t.after(() => {
    if (stage?.db.open) stage.db.close();
    if (client) client.close();
    fs.rmSync(root, { force: true, recursive: true, maxRetries: 5, retryDelay: 50 });
  });
  const trusted = privateAuthorityChild(root, "trusted");
  const hostile = privateAuthorityChild(root, "hostile");
  const pairs = Array.from({ length: 8 }, () => crypto.generateKeyPairSync("ed25519"));
  const [cas, floor, checkpoint, owner, catalog, witness, oldCas, oldFloor] = pairs;
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("checkpoint-v2"), keyring_id: crypto.randomBytes(16) };
  // Real branded client constructors, with pinned disposable transport settings.
  // No remote operation is sent by this journal bootstrap/ACL test.
  const transport = { endpoint: "https://127.0.0.1:53431/", ca: "fixture-ca",
    clientKey: "fixture-key", clientCert: "fixture-cert",
    serverFingerprint256: "ab:".repeat(31) + "ab" };
  const v1FloorClient = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    ...transport, floorPublicKey: oldFloor.publicKey,
    casSignerPublicKey: oldCas.publicKey, trustedScope: scope });
  const v1CasClient = { publicKey: oldCas.publicKey, async readHead() { throw Error("not called"); } };
  const casClient = createOpaqueCheckpointV2HttpsClient({ ...transport,
    authorityPublicKey: cas.publicKey, casPublicKey: cas.publicKey,
    floorPublicKey: floor.publicKey, scope });
  const floorClient = createOpaqueCheckpointV2HttpsClient({ ...transport,
    authorityPublicKey: floor.publicKey, casPublicKey: cas.publicKey,
    floorPublicKey: floor.publicKey, scope });
  const args = {
    trustedScope: scope,
    expectedV1Digest: crypto.randomBytes(32),
    expectedV1Checkpoint: crypto.randomBytes(32),
    casClient, floorClient, v1CasClient, v1FloorClient,
    checkpointPublicKey: checkpoint.publicKey, ownerPublicKey: owner.publicKey,
    catalogPublicKey: catalog.publicKey,
    ownerTrust: { pinnedWitness: { publicKey: witness.publicKey },
      minimumHead: {}, freshWitnessHead: async () => null },
  };
  const grantUsers = (entry) => execFileSync(
    "C:\\Windows\\System32\\icacls.exe", [entry,
      "/grant", fs.statSync(entry).isDirectory()
        ? "*S-1-5-32-545:(OI)(CI)M" : "*S-1-5-32-545:M"], { windowsHide: true });
  const removeUsers = (directory) => execFileSync(
    "C:\\Windows\\System32\\icacls.exe", [directory,
      "/remove:g", "*S-1-5-32-545"], { windowsHide: true });

  const hostilePath = path.join(hostile, "untrusted.sqlite");
  grantUsers(hostile);
  assert.throws(() => assertPrivateSqliteAuthorityDirectory(hostilePath));
  assert.throws(() => new Zk1OpaqueCheckpointV2Client({ ...args,
    journalPath: hostilePath, bootstrapNew: true }),
  /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE|Windows chunk staging ACL validation failed|Untrusted principal/);
  assert.equal(fs.existsSync(hostilePath), false,
    "an untrusted writable ancestor must be denied before creating the SQLite journal");

  const stageArgs = { bootstrapNew: true, trustedScope: scope,
    ownerPublicKey: owner.publicKey, checkpointPublicKey: checkpoint.publicKey,
    casClient: v1CasClient, floorClient: v1FloorClient,
    resolveCatalogSigner: async () => catalog.publicKey };
  const hostileStagePath = path.join(hostile, "untrusted-stage.sqlite");
  assert.throws(() => new Zk1OpaqueCatalogCheckpointV2Stage(hostileStagePath, stageArgs));
  assert.equal(fs.existsSync(hostileStagePath), false,
    "a staging journal cannot be created beneath a foreign Modify ACE");

  const safePath = path.join(trusted, "owner.sqlite");
  client = new Zk1OpaqueCheckpointV2Client({ ...args,
    journalPath: safePath, bootstrapNew: true });
  assert.ok(fs.statSync(safePath).size >= 4096, "trusted bootstrap writes a durable SQLite journal");
  assert.deepEqual(await client.exportSignedIntents(), []);
  const safeStagePath = path.join(trusted, "owner-stage.sqlite");
  stage = new Zk1OpaqueCatalogCheckpointV2Stage(safeStagePath, stageArgs);
  assert.ok(fs.statSync(safeStagePath).size >= 4096);
  assert.deepEqual(await stage.audit(), { count: 0, pending: false,
    lastSequence: 0, lastCheckpointDigest: Buffer.alloc(32),
    publishedV2: false, remoteCloudDurabilityProven: false });
  for (const [file, read] of [
    [safePath, () => client.exportSignedIntents()],
    [safeStagePath + "-wal", () => stage.audit()],
  ]) {
    assert.equal(fs.existsSync(file), true, "SQLite main file and WAL must be present for ACL tests");
    grantUsers(file);
    try {
      assert.throws(() => assertPrivateSqliteAuthorityDirectory(file),
        `native ACL must reject Users Modify on ${path.basename(file)}`);
      await assert.rejects(read(),
        /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE|ZK_OPAQUE_CHECKPOINT_STAGE_DENIED/,
        `foreign Modify on ${path.basename(file)} must invalidate an open journal`);
    } finally { removeUsers(file); }
  }
  client.close();
  client = new Zk1OpaqueCheckpointV2Client({ ...args,
    journalPath: safePath, bootstrapNew: false });
  assert.deepEqual(await client.exportSignedIntents(), [],
    "a trusted existing V2 SQLite journal may be reopened");
  stage.db.close();
  stage = new Zk1OpaqueCatalogCheckpointV2Stage(safeStagePath,
    { ...stageArgs, bootstrapNew: false });
  assert.equal((await stage.audit()).count, 0);

  grantUsers(trusted);
  try {
    assert.throws(() => assertPrivateSqliteAuthorityDirectory(safePath));
    await assert.rejects(client.exportSignedIntents(),
      /ZK_CHECKPOINT_V2_CLIENT_UNAVAILABLE|Windows chunk staging ACL validation failed|Untrusted principal/,
      "post-bootstrap foreign Modify denies reads even with an already-open handle");
    await assert.rejects(stage.audit(),
      /ZK_OPAQUE_CHECKPOINT_STAGE_DENIED|Windows chunk staging ACL validation failed|Untrusted principal/);
    assert.throws(() => new Zk1OpaqueCheckpointV2Client({ ...args,
      journalPath: safePath, bootstrapNew: false }));
    assert.throws(() => new Zk1OpaqueCatalogCheckpointV2Stage(safeStagePath,
      { ...stageArgs, bootstrapNew: false }));
  } finally { removeUsers(trusted); }
  assert.deepEqual(await client.exportSignedIntents(), [],
    "owner-only ACL permits normal read after hostile ACE removal");
});
