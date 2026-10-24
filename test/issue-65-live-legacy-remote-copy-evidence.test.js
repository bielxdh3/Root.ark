"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createCloudStorage } = require("../services/cloudStorage");
const { inspectZk1LiveLegacyRemoteCopyEvidence: inspect } =
  require("../src/services/zk1ProviderMigrationPreflight");

const OWNER_DOMAIN = Buffer.from("Root.ark/zk-1/legacy-remote-copy-scan/owner/v1\0");
const GENERATION_DOMAIN = Buffer.from("Root.ark/zk-1/legacy-remote-copy-scan/generation/v1\0");
const scope = { account_id: "a".repeat(32), compartment_id: "b".repeat(14),
  keyring_id: "c".repeat(32) };
const namespaceIdentity = "d".repeat(64);
const context = "e".repeat(64);
const now = () => Math.floor(Date.now() / 1000);
function sign(privateKey, domain, statement) {
  return crypto.sign(null, Buffer.concat([domain, Buffer.from(JSON.stringify(statement))]),
    privateKey).toString("base64url");
}
function fixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const generationKey = crypto.generateKeyPairSync("ed25519");
  const events = [];
  let observedContext = context;
  let observedGeneration = 12;
  let entries = [{ provider: "s3", area: "uploads", folderId: "owner-folder",
    name: "PRIVATE-secret.ct", key: "rootark/uploads/owner-folder/PRIVATE-secret.ct",
    providerIdentity: "rootark/uploads/owner-folder/PRIVATE-secret.ct" }];
  const statements = { type: "rootark-zk1-legacy-remote-copy-owner/v1", scope,
    provider: "s3", namespaceIdentity, readerContext: context,
    folderIds: ["owner-folder"], generation: 12,
    issuedAt: now(), expiresAt: now() + 120 };
  const authorization = { statement: statements,
    signature: sign(owner.privateKey, OWNER_DOMAIN, statements) };
  const cloudStorage = {
    status() { events.push("status"); return { provider: "s3", enabled: true }; },
    enabled() { events.push("enabled"); return true; },
    zk1StorageNamespace() { events.push("namespace"); return namespaceIdentity; },
    async resolveInventoryContext() { events.push("identity"); return observedContext; },
    async inventory(opts) { events.push("inventory");
      assert.equal(opts.maxEntries, 5000);
      assert.equal(opts.maxPages, 8);
      assert.equal(opts.abortSignal instanceof AbortSignal, true);
      return entries;
    },
    upload() { throw new Error("FORBIDDEN_UPLOAD"); },
    remove() { throw new Error("FORBIDDEN_DELETE"); },
    download() { throw new Error("FORBIDDEN_GET_WITH_WRITE"); },
  };
  const readSignedGeneration = async (nonce) => {
    events.push("generation");
    const statement = { type: "rootark-zk1-legacy-remote-copy-generation/v1",
      scope, provider: "s3", namespaceIdentity, readerContext: observedContext,
      generation: observedGeneration, nonce };
    return { statement, signature: sign(generationKey.privateKey, GENERATION_DOMAIN, statement) };
  };
  const args = { optIn: true, cloudStorage, scope, authorization,
    pinnedOwnerPublicKey: owner.publicKey,
    pinnedGenerationPublicKey: generationKey.publicKey,
    readSignedGeneration };
  return { args, events, owner, generationKey, authorization,
    setEntries(value) { entries = value; },
    changeGeneration(value) { observedGeneration = value; },
    changeContext(value) { observedContext = value; } };
}

test("owner-authorized S3 legacy remote copy references are observed read-only with private names redacted", async () => {
  const f = fixture();
  const first = await inspect(f.args);
  const second = await inspect(f.args);
  assert.equal(first.observation, "partial-owner-scoped-remote-provider-references-only");
  assert.equal(first.observedCopies, 1);
  assert.equal(first.readOnly, true);
  for (const field of ["globallyComplete", "authorizesCutover", "providerDurabilityProven",
    "providerObjectVersionVerified", "legacySqlJoinVerified"])
    assert.equal(first[field], false);
  assert.notEqual(first.ephemeralFingerprint, second.ephemeralFingerprint);
  assert.deepEqual(f.events.filter((entry) => entry === "inventory"), ["inventory", "inventory"]);
  for (const secret of ["PRIVATE-secret", "owner-folder", "rootark/uploads", context,
    namespaceIdentity]) assert.equal(JSON.stringify(first).includes(secret), false);
});

test("remote copy evidence refuses old generation, changed identity, foreign owner, unknown class, overflow and replay", async () => {
  for (const attack of [
    (f) => { f.changeGeneration(13); },
    (f) => { f.changeContext("f".repeat(64)); },
    (f) => { f.args.optIn = false; },
    (f) => { f.args.pinnedOwnerPublicKey = crypto.generateKeyPairSync("ed25519").publicKey; },
    (f) => { f.args.pinnedGenerationPublicKey = f.owner.publicKey; },
    (f) => { f.args.scope = { ...scope, account_id: "f".repeat(32) }; },
    (f) => { f.args.authorization.statement.expiresAt = now() - 1; },
    (f) => { f.setEntries([{ provider: "s3", area: "uploads", folderId: "foreign-owner",
      name: "secret.ct", key: "rootark/uploads/foreign-owner/secret.ct",
      providerIdentity: "rootark/uploads/foreign-owner/secret.ct" }]); },
    (f) => { f.setEntries([{ provider: "s3", area: "preview", folderId: "owner-folder",
      name: "secret.ct", key: "rootark/preview/owner-folder/secret.ct",
      providerIdentity: "rootark/preview/owner-folder/secret.ct" }]); },
    (f) => { f.setEntries(Array.from({ length: 5001 }, (_, i) => ({ provider: "s3",
      area: "uploads", folderId: "owner-folder", name: `item-${i}`,
      key: `rootark/uploads/owner-folder/item-${i}`,
      providerIdentity: `rootark/uploads/owner-folder/item-${i}` }))); },
    (f) => { f.setEntries([
      { provider: "s3", area: "uploads", folderId: "owner-folder", name: "private.ct",
        key: "rootark/uploads/owner-folder/private.ct",
        providerIdentity: "rootark/uploads/owner-folder/private.ct" },
      { provider: "s3", area: "uploads", folderId: "owner-folder", name: "private.ct",
        key: "rootark/uploads/owner-folder/private.ct",
        providerIdentity: "rootark/uploads/owner-folder/private.ct" },
    ]); },
  ]) {
    const f = fixture();
    attack(f);
    await assert.rejects(inspect(f.args), /ZK_LIVE_LEGACY_REMOTE_COPY_UNAVAILABLE/);
  }
  const f = fixture();
  f.args.readSignedGeneration = async (nonce) => {
    const good = await fixture().args.readSignedGeneration(nonce);
    return good; // different signing key cannot manufacture the pinned generation
  };
  await assert.rejects(inspect(f.args), /ZK_LIVE_LEGACY_REMOTE_COPY_UNAVAILABLE/);
});

function realAdapterFixture(provider, pages) {
  const owner = crypto.generateKeyPairSync("ed25519");
  const generationKey = crypto.generateKeyPairSync("ed25519");
  let generation = 12;
  const commands = [];
  let idx = 0;
  const config = { provider, prefix: "rootark", rootFolderId: "root",
    resolvePrincipalIdentity: async () => "fixture-readonly-principal" };
  if (provider === "s3") {
    config.s3 = { bucket: "disposable-fixture", region: "us-east-1" };
    config.createS3Client = async () => ({ send: async (command, options) => {
      commands.push(command.constructor.name);
      assert.equal(command.constructor.name, "ListObjectsV2Command");
      assert.equal(command.input.MaxKeys, 1000);
      assert.equal(options.abortSignal instanceof AbortSignal, true);
      if (idx++ >= pages.length) throw new Error("UNBOUNDED_PAGES");
      return pages[Math.min(idx - 1, pages.length - 1)];
    } });
  } else {
    config.gdrive = { folderId: "owner-drive-root" };
    config.createGoogleDriveClient = async () => ({ files: { list: async (args, opts) => {
      commands.push("drive:list");
      assert.equal(opts.signal instanceof AbortSignal, true);
      assert.equal(args.pageSize, 100);
      if (idx++ >= pages.length) throw new Error("UNBOUNDED_PAGES");
      return { data: pages[Math.min(idx - 1, pages.length - 1)] };
    } } });
  }
  const adapter = createCloudStorage(config);
  const namespace = adapter.zk1StorageNamespace();
  const readerContext = crypto.createHash("sha256").update(JSON.stringify(provider === "s3"
    ? [provider, "rootark", "root", "disposable-fixture", "us-east-1", "", false,
      "fixture-readonly-principal"]
    : [provider, "rootark", "root", "owner-drive-root", "fixture-readonly-principal"]))
    .digest("hex");
  const statement = { type: "rootark-zk1-legacy-remote-copy-owner/v1", scope,
    provider, namespaceIdentity: namespace, readerContext,
    folderIds: ["owner-folder"], generation: 12,
    issuedAt: now(), expiresAt: now() + 120 };
  const readSignedGeneration = async (nonce) => {
    const body = { type: "rootark-zk1-legacy-remote-copy-generation/v1", scope,
      provider, namespaceIdentity: namespace, readerContext,
      generation, nonce };
    return { statement: body, signature: sign(generationKey.privateKey, GENERATION_DOMAIN, body) };
  };
  return { commands, adapter, args: { optIn: true, cloudStorage: adapter, scope,
    authorization: { statement, signature: sign(owner.privateKey, OWNER_DOMAIN, statement) },
    pinnedOwnerPublicKey: owner.publicKey,
    pinnedGenerationPublicKey: generationKey.publicKey, readSignedGeneration },
    setGeneration(value) { generation = value; } };
}

test("real S3 inventory issues bounded listing only, forbids repeated pages and foreign owner folders", async () => {
  const key = "rootark/uploads/owner-folder/private-remote.ct";
  const validPage = { IsTruncated: false, Contents: [{ Key: key }] };
  const f = realAdapterFixture("s3", [validPage]);
  assert.equal((await inspect(f.args)).observedCopies, 1);
  assert.deepEqual(f.commands, ["ListObjectsV2Command"]);
  const repeated = realAdapterFixture("s3", [{ IsTruncated: true,
    NextContinuationToken: "same-page", Contents: [{ Key: key }] },
  { IsTruncated: true, NextContinuationToken: "same-page", Contents: [] }]);
  await assert.rejects(inspect(repeated.args), /ZK_LIVE_LEGACY_REMOTE_COPY_UNAVAILABLE/);
  assert.equal(repeated.commands.length, 2, "repeating the same page cannot spin indefinitely");
  const overfull = realAdapterFixture("s3", [{ IsTruncated: false,
    Contents: Array.from({ length: 1001 }, (_, i) => ({ Key: `${key}${i}` })) }]);
  await assert.rejects(inspect(overfull.args), /ZK_LIVE_LEGACY_REMOTE_COPY_UNAVAILABLE/);
  assert.equal(overfull.commands.length, 1);
  const unknown = realAdapterFixture("s3", [{ IsTruncated: false,
    Contents: [{ Key: "rootark/previews/owner-folder/private.ct" }] }]);
  await assert.rejects(inspect(unknown.args), /ZK_LIVE_LEGACY_REMOTE_COPY_UNAVAILABLE/);
  const unauthorized = realAdapterFixture("s3", [{ IsTruncated: false,
    Contents: [{ Key: "rootark/uploads/foreign/private.ct" }] }]);
  await assert.rejects(inspect(unauthorized.args), /ZK_LIVE_LEGACY_REMOTE_COPY_UNAVAILABLE/);
});

test("real Drive metadata listing admits only pinned ID and rejects generation race or unknown pages", async () => {
  const file = { id: "pinned-opaque-drive-id", name: "private-remote.ct",
    parents: ["owner-drive-root"],
    appProperties: { rootArkKey: "rootark/uploads/owner-folder/private-remote.ct",
      rootArkFolderId: "owner-folder", rootArkArea: "uploads" } };
  const f = realAdapterFixture("gdrive", [{ files: [file] }]);
  assert.equal((await inspect(f.args)).observedCopies, 1);
  assert.deepEqual(f.commands, ["drive:list"]);
  const altered = realAdapterFixture("gdrive", [{ files: [file] }]);
  const real = altered.args.cloudStorage.inventory;
  altered.args.cloudStorage.inventory = async (opts) => {
    const items = await real(opts);
    altered.setGeneration(13);
    return items;
  };
  await assert.rejects(inspect(altered.args), /ZK_LIVE_LEGACY_REMOTE_COPY_UNAVAILABLE/);
  const loop = realAdapterFixture("gdrive", [{ files: [file], nextPageToken: "repeated" },
    { files: [], nextPageToken: "repeated" }]);
  await assert.rejects(inspect(loop.args), /ZK_LIVE_LEGACY_REMOTE_COPY_UNAVAILABLE/);
  assert.equal(loop.commands.length, 2);
  const foreignRoot = realAdapterFixture("gdrive", [{ files: [
    { ...file, parents: ["foreign-account-folder"] } ] }]);
  await assert.rejects(inspect(foreignRoot.args), /ZK_LIVE_LEGACY_REMOTE_COPY_UNAVAILABLE/);
  const foreignNamespace = realAdapterFixture("gdrive", [{ files: [
    { ...file, appProperties: { ...file.appProperties,
      rootArkKey: "foreign/uploads/owner-folder/private-remote.ct" } }] }]);
  await assert.rejects(inspect(foreignNamespace.args), /ZK_LIVE_LEGACY_REMOTE_COPY_UNAVAILABLE/);
});
