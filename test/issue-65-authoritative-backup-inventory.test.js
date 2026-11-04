"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const history = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const roots = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");
const chunks = require("../public/client/rootark-zk1-ciphertext-chunk-root");
const api = require("../public/client/rootark-zk1-authoritative-backup-inventory");
const roster = require("../public/client/rootark-zk1-owner-account-backup-roster");
const b64 = (v) => Buffer.from(v).toString("base64url");
const hash = (v) => crypto.createHash("sha256").update(v).digest();
const shaHex = (v) => hash(v).toString("hex");
const random = (n) => crypto.randomBytes(n);
const DOMAIN = Buffer.from("Root.ark/zk-1/owner-inventory-trust-head/v1\0");
const COMMIT_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0");
const GRANT = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key",
  "manifest_revision", "manifest_digest", "current_epoch", "enrolled_epoch",
  "revoked_at_epoch"];

async function fixture(sharedOwner = crypto.generateKeyPairSync("ed25519"),
  sharedAccountId = random(16)) {
  const owner = sharedOwner;
  const signer = crypto.generateKeyPairSync("ed25519");
  const ownerSigningKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    owner.privateKey.export({ type: "pkcs8", format: "der" }), "Ed25519", false, ["sign"]);
  const ownerPublicKey = await crypto.webcrypto.subtle.importKey("spki",
    owner.publicKey.export({ type: "spki", format: "der" }), "Ed25519", true, ["verify"]);
  const ownerSpki = owner.publicKey.export({ type: "spki", format: "der" });
  const inventorySpki = signer.publicKey.export({ type: "spki", format: "der" });
  const scopeBytes = { account_id: sharedAccountId,
    compartment_id: random(12), keyring_id: random(16) };
  const scope = Object.fromEntries(Object.entries(scopeBytes).map(([key, value]) => [key, b64(value)]));
  const ownerSignerKeyId = random(16), inventorySignerKeyId = random(16), deviceId = "owner-offline";
  const pinnedCurrentHead = { revision: 7, digest: random(32), epoch: 4 };
  const h1 = await history.signOwnerCheckpoint({ scope, signerKey: ownerSigningKey,
    signerPublicKey: ownerPublicKey, signerKeyId: ownerSignerKeyId, deviceId,
    revision: 6, manifestDigest: random(32), issuedAt: 1000, previous: null });
  const predecessor = await history.verifyOwnerCheckpoint({ checkpoint: h1, scope,
    signerPublicKey: ownerPublicKey, signerKeyId: ownerSignerKeyId, previous: null });
  const h2 = await history.signOwnerCheckpoint({ scope, signerKey: ownerSigningKey,
    signerPublicKey: ownerPublicKey, signerKeyId: ownerSignerKeyId, deviceId,
    revision: pinnedCurrentHead.revision, manifestDigest: pinnedCurrentHead.digest,
    issuedAt: 1100, previous: predecessor });
  const ownerHistoryChain = [h1, h2];
  const grantFields = { schema: "rootark-zk1-browser-owner-device-grant/v1", ...scope,
    device_id: deviceId, authorization_key_id: b64(random(16)),
    authorization_public_key: b64(random(32)),
    manifest_revision: pinnedCurrentHead.revision,
    manifest_digest: b64(pinnedCurrentHead.digest), current_epoch: pinnedCurrentHead.epoch,
    enrolled_epoch: 1, revoked_at_epoch: null };
  const grantSig = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(GRANT.map((k) => [k, grantFields[k]])))),
  ]), owner.privateKey);
  const signedDeviceGrant = { ...grantFields, signature: b64(grantSig) };

  const objectIdA = random(16), objectIdB = random(16);
  const payloads = [Buffer.from("opaque first revision 000000"), Buffer.from("opaque second revision 00000"),
    Buffer.from("opaque another object 000000")];
  const cases = [
    { object_id: objectIdA, revision: 1, epoch: 2, ciphertext_sha256: hash(payloads[0]), ct: payloads[0] },
    { object_id: objectIdA, revision: 2, epoch: 3, ciphertext_sha256: hash(payloads[1]), ct: payloads[1] },
    { object_id: objectIdB, revision: 1, epoch: 4, ciphertext_sha256: hash(payloads[2]), ct: payloads[2] },
  ].sort((a, b) => Buffer.compare(a.object_id, b.object_id) || a.revision - b.revision);
  const tuples = cases.map(({ ct, ...tuple }) => tuple);
  const genesisSnapshot = await inventory.createSignedSnapshot({
    signerKeyId: inventorySignerKeyId, privateKey: signer.privateKey,
    scope: scopeBytes, sequence: 0, previousRoot: null, entries: [], nonce: random(32) });
  let lastRoot = Buffer.from((await z.decodeDeterministic(genesisSnapshot)).root);
  let entries = [];
  const committedProofChain = [];
  for (const tuple of tuples) {
    const nextSequence = entries.length + 1;
    const next = [...entries, tuple].sort((a, b) =>
      Buffer.compare(a.object_id, b.object_id) || a.revision - b.revision);
    const root = await inventory.computeRoot(scopeBytes, nextSequence, lastRoot, next);
    const operation = { operation_id: random(16), expected_sequence: nextSequence - 1,
      expected_root: lastRoot, ...tuple };
    const unsigned = { type: "rootark-content-inventory-entry/v1", version: 1,
      signer_key_id: inventorySignerKeyId, scope: scopeBytes,
      sequence: nextSequence, previous_root: lastRoot, root,
      operation_id: operation.operation_id, expected_sequence: nextSequence - 1,
      expected_root: lastRoot, request_digest: hash(await z.encodeDeterministic(operation)),
      entry: tuple };
    const signature = crypto.sign(null, Buffer.concat([COMMIT_DOMAIN,
      await z.encodeDeterministic(unsigned)]), signer.privateKey);
    committedProofChain.push(await z.encodeDeterministic({ ...unsigned, signature }));
    entries = next;
    lastRoot = root;
  }
  const previousRoot = (await z.decodeDeterministic(committedProofChain.at(-1))).previous_root;
  const signedSnapshot = await inventory.createSignedSnapshot({
    signerKeyId: inventorySignerKeyId, privateKey: signer.privateKey,
    scope: scopeBytes, sequence: tuples.length, previousRoot,
    entries: tuples, nonce: random(32) });
  const selectedRoot = Buffer.from((await z.decodeDeterministic(signedSnapshot)).root);
  const ownerStatement = { schema: "rootark-zk1-owner-inventory-trust-head/v1", ...scope,
    inventory_signer_key_id: b64(inventorySignerKeyId),
    inventory_spki_sha256: shaHex(inventorySpki), counter: 1,
    inventory_sequence: cases.length, inventory_root: selectedRoot.toString("hex"),
    snapshot_sha256: shaHex(signedSnapshot), previous_checkpoint_digest: null,
    issued_at: 1200, expires_at: 2000 };
  const fields = Buffer.from(JSON.stringify(ownerStatement));
  const ownerSig = crypto.sign(null, Buffer.concat([DOMAIN, fields]), owner.privateKey);
  const independentlyPinnedInventoryCheckpointDigest = hash(Buffer.concat([
    DOMAIN, fields, ownerSig])).toString("hex");
  const ownerInventoryPortable = JSON.stringify({ schema: "rootark-zk1-owner-inventory-portable/v1",
    owner_spki: b64(ownerSpki), checkpoints: [{ ...ownerStatement, signature: b64(ownerSig) }],
    minimum_snapshot: b64(signedSnapshot) });
  const items = [];
  for (const row of cases) {
    const root = await chunks.computeCiphertextRoot([row.ct]);
    const ownerRootCheckpoint = await roots.signOwnerCiphertextRootCheckpoint({
      scope, signerKey: ownerSigningKey, signerKeyId: ownerSignerKeyId, deviceId,
      manifestRevision: pinnedCurrentHead.revision, manifestDigest: pinnedCurrentHead.digest,
      manifestEpoch: pinnedCurrentHead.epoch, objectId: b64(row.object_id),
      objectRevision: row.revision, ciphertextEpoch: row.epoch,
      ciphertextRoot: root, issuedAt: 1400 });
    items.push({ objectId: b64(row.object_id), revision: row.revision, epoch: row.epoch,
      ciphertext: row.ct, ownerRootCheckpoint });
  }
  const input = { scope, ownerPublicKey, ownerSigningKey,
    independentOwnerSpkiSha256: hash(ownerSpki), pinnedCurrentHead,
    signedDeviceGrant, ownerHistoryChain, ownerSignerKeyId, deviceId,
    ownerInventoryPortable, independentlyPinnedInventoryCheckpointDigest,
    independentlyPinnedInventorySignerSpkiSha256: shaHex(inventorySpki),
    inventorySignerPublicKey: signer.publicKey, inventorySignerKeyId,
    genesisSnapshot, committedProofChain, items, issuedAt: 1400, nowSeconds: 1400 };
  return input;
}
const failure = /ZK_AUTHORITATIVE_BACKUP_DENIED/;
function verification(input, result) {
  const { ownerSigningKey, items, issuedAt, ...rest } = input;
  return { ...rest, snapshot: result.snapshot,
    independentlyPinnedBackupSha256: result.snapshotSha256 };
}
test("signed complete inventory preserves all object revisions, validates signed genesis chain", async () => {
  const input = await fixture();
  const created = await api.createVerifiedSnapshot(input);
  assert.equal(created.snapshot.inventorySequence, 3);
  assert.equal(created.snapshot.items.length, 3);
  assert.equal(created.completeRelativeToOwnerCheckpoint, true);
  assert.equal(created.globalAccountCompletenessProven, false);
  assert.equal(created.versionAwareCekArchiveCompleted, false);
  assert.equal(created.authorizesProductionRestore, false);
  const objects = new Map();
  for (const item of created.snapshot.items) {
    objects.set(item.objectId, [...(objects.get(item.objectId) || []), item.revision]);
  }
  assert.deepEqual([...objects.values()].map((v) => v.join(",")).sort(), ["1", "1,2"]);
  const verified = await api.verifyBackupSnapshot(verification(input, created));
  assert.equal(verified.completeRelativeToOwnerCheckpoint, true);
});
test("missing authority, omissions, duplicates, mutations, scope and stale grants fail closed", async () => {
  const i = await fixture();
  const changes = [
    { ownerInventoryPortable: null },
    { independentlyPinnedInventoryCheckpointDigest: "0".repeat(64) },
    { independentlyPinnedInventorySignerSpkiSha256: "0".repeat(64) },
    { items: i.items.slice(0, 2) },
    { items: [...i.items, i.items[0]] },
    { items: [i.items[0], i.items[2], i.items[1]] },
    { items: [{ ...i.items[0], ciphertext: Buffer.from("tampered ciphertext") }, ...i.items.slice(1)] },
    { items: [{ ...i.items[0], revision: 2 }, ...i.items.slice(1)] },
    { scope: { ...i.scope, keyring_id: b64(random(16)) } },
    { pinnedCurrentHead: { ...i.pinnedCurrentHead, revision: 8 } },
    { signedDeviceGrant: { ...i.signedDeviceGrant, revoked_at_epoch: 4 } },
    { inventorySignerKeyId: random(16) },
    { ownerSignerKeyId: random(16) },
    { committedProofChain: [Buffer.from(i.committedProofChain[0]).fill(0),
      ...i.committedProofChain.slice(1)] },
    { ownerHistoryChain: i.ownerHistoryChain.slice(1) },
    { committedProofChain: i.committedProofChain.slice(1) },
    { genesisSnapshot: i.ownerInventoryPortable },
  ];
  for (const change of changes)
    await assert.rejects(api.createVerifiedSnapshot({ ...i, ...change }), failure);
});
test("signed backup rejects omitted revision, replay, digest fork and alternate owner", async () => {
  const i = await fixture();
  const created = await api.createVerifiedSnapshot(i);
  const base = verification(i, created);
  for (const change of [
    { independentlyPinnedBackupSha256: random(32) },
    { snapshot: { ...created.snapshot, items: created.snapshot.items.slice(1) } },
    { snapshot: { ...created.snapshot, signature: b64(random(64)) } },
    { snapshot: { ...created.snapshot, ownerRevision: 6 } },
    { pinnedCurrentHead: { ...i.pinnedCurrentHead, epoch: 3 } },
    { ownerInventoryPortable: i.ownerInventoryPortable.replace("minimum_snapshot", "other_snapshot") },
  ]) await assert.rejects(api.verifyBackupSnapshot({ ...base, ...change }), failure);
});
test("owner-pinned account roster refuses backup with third authenticated keyring omitted", async () => {
  const owner = crypto.generateKeyPairSync("ed25519");
  const accountId = random(16);
  const fixtures = await Promise.all(Array.from({ length: 3 },
    () => fixture(owner, accountId)));
  const proofs = [];
  for (const item of fixtures) {
    const made = await api.createVerifiedSnapshot(item);
    proofs.push(await api.verifyBackupSnapshot(verification(item, made)));
  }
  const common = { ownerPublicKey: fixtures[0].ownerPublicKey,
    independentOwnerSpkiSha256: fixtures[0].independentOwnerSpkiSha256,
    accountId: b64(accountId) };
  const signedRoster = await roster.createOwnerRoster({ ...common,
    ownerSigningKey: fixtures[0].ownerSigningKey, verifiedKeyringProofs: proofs,
    issuedAt: 1400 });
  assert.equal(signedRoster.ownerDeclaredKeyringCount, 3);
  assert.equal(signedRoster.globalAccountCompletenessProven, false);
  const verify = { ...common, roster: signedRoster.roster,
    independentlyPinnedRosterSha256: signedRoster.rosterSha256,
    verifiedKeyringProofs: proofs };
  assert.equal((await roster.verifyOwnerRosterCoverage(verify)).keyringCount, 3);
  const foreign = await fixture(crypto.generateKeyPairSync("ed25519"), accountId);
  const foreignMade = await api.createVerifiedSnapshot(foreign);
  const foreignProof = await api.verifyBackupSnapshot(verification(foreign, foreignMade));
  for (const overrides of [
    { verifiedKeyringProofs: proofs.slice(0, 2) },
    { verifiedKeyringProofs: [proofs[0], proofs[0], proofs[2]] },
    { verifiedKeyringProofs: [...proofs.slice(0, 2), { completeRelativeToOwnerCheckpoint: true }] },
    { verifiedKeyringProofs: [...proofs.slice(0, 2), foreignProof] },
    { independentlyPinnedRosterSha256: random(32) },
    { roster: { ...signedRoster.roster, keyringCount: 2 } },
  ]) await assert.rejects(roster.verifyOwnerRosterCoverage({ ...verify, ...overrides }),
    /ZK_ACCOUNT_BACKUP_ROSTER_DENIED/);
});
