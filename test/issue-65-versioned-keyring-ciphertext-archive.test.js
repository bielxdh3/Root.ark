"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const history = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const roots = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");
const chunks = require("../public/client/rootark-zk1-ciphertext-chunk-root");
const snapshots = require("../public/client/rootark-zk1-authoritative-backup-inventory");
const roster = require("../public/client/rootark-zk1-owner-account-backup-roster");
const archive = require("../public/client/rootark-zk1-versioned-keyring-ciphertext-archive");
const portable = require("../public/client/rootark-zk1-portable-file-recovery");
const fileContent = require("../public/client/rootark-zk1-file-content");
const b64 = (v) => Buffer.from(v).toString("base64url");
const rnd = (n) => crypto.randomBytes(n);
const sha = (v) => crypto.createHash("sha256").update(v).digest();
const deny = /ZK_(VERSIONED_KEYRING_ARCHIVE|KEYRING_ARCHIVE)_DENIED/;

async function fixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const signer = crypto.generateKeyPairSync("ed25519");
  const subtle = crypto.webcrypto.subtle;
  const ownerSigningKey = await subtle.importKey("pkcs8",
    owner.privateKey.export({ type: "pkcs8", format: "der" }), "Ed25519", false, ["sign"]);
  const ownerPublicKey = await subtle.importKey("spki",
    owner.publicKey.export({ type: "spki", format: "der" }), "Ed25519", true, ["verify"]);
  const ownerSpki = owner.publicKey.export({ type: "spki", format: "der" });
  const signerSpki = signer.publicKey.export({ type: "spki", format: "der" });
  const scopeBytes = { account_id: rnd(16), compartment_id: rnd(8), keyring_id: rnd(16) };
  const scope = Object.fromEntries(Object.entries(scopeBytes).map(([key, value]) => [key, b64(value)]));
  const signerKeyId = rnd(16), inventorySignerKeyId = rnd(16), deviceId = "owner-offline";
  const pinnedCurrentHead = { revision: 7, digest: rnd(32), epoch: 4 };
  const h1 = await history.signOwnerCheckpoint({ scope, signerKey: ownerSigningKey,
    signerPublicKey: ownerPublicKey, signerKeyId, deviceId,
    revision: 6, manifestDigest: rnd(32), issuedAt: 1000, previous: null });
  const previous = await history.verifyOwnerCheckpoint({ checkpoint: h1, scope,
    signerPublicKey: ownerPublicKey, signerKeyId, previous: null });
  const h2 = await history.signOwnerCheckpoint({ scope, signerKey: ownerSigningKey,
    signerPublicKey: ownerPublicKey, signerKeyId, deviceId,
    revision: pinnedCurrentHead.revision, manifestDigest: pinnedCurrentHead.digest,
    issuedAt: 1100, previous });
  const grantFields = { schema: "rootark-zk1-browser-owner-device-grant/v1", ...scope,
    device_id: deviceId, authorization_key_id: b64(rnd(16)), authorization_public_key: b64(rnd(32)),
    manifest_revision: pinnedCurrentHead.revision,
    manifest_digest: b64(pinnedCurrentHead.digest), current_epoch: pinnedCurrentHead.epoch,
    enrolled_epoch: 1, revoked_at_epoch: null };
  const GRANT = ["schema", "account_id", "compartment_id", "keyring_id", "device_id",
    "authorization_key_id", "authorization_public_key", "manifest_revision",
    "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
  const grantMessage = Buffer.concat([
    Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(GRANT.map((name) => [name, grantFields[name]]))))]);
  const signedDeviceGrant = { ...grantFields,
    signature: b64(crypto.sign(null, grantMessage, owner.privateKey)) };
  const objectA = rnd(16), objectB = rnd(16);
  const versions = [
    { objectId: objectA, revision: 1, epoch: 2, versionId: rnd(16), parentId: null },
    { objectId: objectA, revision: 2, epoch: 3, versionId: rnd(16) },
    { objectId: objectB, revision: 1, epoch: 4, versionId: rnd(16), parentId: null },
  ];
  versions[1].parentId = versions[0].versionId;
  for (const row of versions) {
    row.cek = rnd(32);
    row.metadata = { ...scope, object_id: b64(row.objectId), version_id: b64(row.versionId),
      parent_version_id: row.parentId === null ? null : b64(row.parentId),
      epoch: row.epoch, kind: "file" };
    const cekKey = await fileContent.importFileCek(row.cek);
    row.ciphertext = Buffer.from(await fileContent.encryptFile({
      cek: cekKey, metadata: row.metadata, name: "opaque.txt",
      mediaType: "text/plain", data: Buffer.from("owner private ciphertext revision") }));
    row.ciphertextSha256 = sha(row.ciphertext);
  }
  versions.sort((a, b) => Buffer.compare(a.objectId, b.objectId) || a.revision - b.revision);
  const tuples = versions.map((row) => ({
    object_id: row.objectId, revision: row.revision, epoch: row.epoch,
    ciphertext_sha256: row.ciphertextSha256 }));
  const genesisSnapshot = await inventory.createSignedSnapshot({
    signerKeyId: inventorySignerKeyId, privateKey: signer.privateKey,
    scope: scopeBytes, sequence: 0, previousRoot: null, entries: [], nonce: rnd(32) });
  let lastRoot = Buffer.from((await z.decodeDeterministic(genesisSnapshot)).root);
  let committed = [];
  const committedProofChain = [];
  for (const tuple of tuples) {
    const seq = committed.length + 1;
    const next = [...committed, tuple].sort((a, b) =>
      Buffer.compare(a.object_id, b.object_id) || a.revision - b.revision);
    const root = await inventory.computeRoot(scopeBytes, seq, lastRoot, next);
    const operation = { operation_id: rnd(16), expected_sequence: seq - 1,
      expected_root: lastRoot, ...tuple };
    const unsigned = { type: "rootark-content-inventory-entry/v1", version: 1,
      signer_key_id: inventorySignerKeyId, scope: scopeBytes, sequence: seq,
      previous_root: lastRoot, root, operation_id: operation.operation_id,
      expected_sequence: seq - 1, expected_root: lastRoot,
      request_digest: sha(await z.encodeDeterministic(operation)), entry: tuple };
    const signature = crypto.sign(null, Buffer.concat([
      Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0"),
      await z.encodeDeterministic(unsigned)]), signer.privateKey);
    committedProofChain.push(await z.encodeDeterministic({ ...unsigned, signature }));
    committed = next; lastRoot = root;
  }
  const previousRoot = (await z.decodeDeterministic(committedProofChain.at(-1))).previous_root;
  const signedSnapshot = await inventory.createSignedSnapshot({
    signerKeyId: inventorySignerKeyId, privateKey: signer.privateKey,
    scope: scopeBytes, sequence: tuples.length, previousRoot,
    entries: tuples, nonce: rnd(32) });
  const inventoryRoot = Buffer.from((await z.decodeDeterministic(signedSnapshot)).root);
  const invStatement = { schema: "rootark-zk1-owner-inventory-trust-head/v1", ...scope,
    inventory_signer_key_id: b64(inventorySignerKeyId),
    inventory_spki_sha256: sha(signerSpki).toString("hex"), counter: 1,
    inventory_sequence: versions.length, inventory_root: inventoryRoot.toString("hex"),
    snapshot_sha256: sha(signedSnapshot).toString("hex"),
    previous_checkpoint_digest: null, issued_at: 1200, expires_at: 2000 };
  const invDomain = Buffer.from("Root.ark/zk-1/owner-inventory-trust-head/v1\0");
  const statement = Buffer.from(JSON.stringify(invStatement));
  const invSignature = crypto.sign(null, Buffer.concat([invDomain, statement]), owner.privateKey);
  const independentlyPinnedInventoryCheckpointDigest =
    sha(Buffer.concat([invDomain, statement, invSignature])).toString("hex");
  const ownerInventoryPortable = JSON.stringify({
    schema: "rootark-zk1-owner-inventory-portable/v1", owner_spki: b64(ownerSpki),
    checkpoints: [{ ...invStatement, signature: b64(invSignature) }],
    minimum_snapshot: b64(signedSnapshot) });
  const items = [];
  for (const row of versions) {
    const ciphertextRoot = await chunks.computeCiphertextRoot([row.ciphertext]);
    const ownerRootCheckpoint = await roots.signOwnerCiphertextRootCheckpoint({
      scope, signerKey: ownerSigningKey, signerKeyId, deviceId,
      manifestRevision: pinnedCurrentHead.revision, manifestDigest: pinnedCurrentHead.digest,
      manifestEpoch: pinnedCurrentHead.epoch, objectId: b64(row.objectId),
      objectRevision: row.revision, ciphertextEpoch: row.epoch,
      ciphertextRoot, issuedAt: 1400 });
    items.push({ objectId: b64(row.objectId), revision: row.revision,
      epoch: row.epoch, ciphertext: row.ciphertext, ownerRootCheckpoint });
  }
  const authorityInput = { scope, ownerPublicKey, ownerSigningKey,
    independentOwnerSpkiSha256: sha(ownerSpki), pinnedCurrentHead,
    signedDeviceGrant, ownerHistoryChain: [h1, h2], ownerSignerKeyId: signerKeyId,
    deviceId, ownerInventoryPortable, independentlyPinnedInventoryCheckpointDigest,
    independentlyPinnedInventorySignerSpkiSha256: sha(signerSpki).toString("hex"),
    inventorySignerPublicKey: signer.publicKey, inventorySignerKeyId,
    genesisSnapshot, committedProofChain, items, issuedAt: 1400, nowSeconds: 1400 };
  const signedBackup = await snapshots.createVerifiedSnapshot(authorityInput);
  const { items: _, issuedAt: __, ownerSigningKey: ___, ...verifyArgs } = authorityInput;
  const backupVerification = { ...verifyArgs, snapshot: signedBackup.snapshot,
    independentlyPinnedBackupSha256: signedBackup.snapshotSha256 };
  const ownProof = await snapshots.verifyBackupSnapshot(backupVerification);
  const signedRoster = await roster.createOwnerRoster({
    ownerPublicKey, ownerSigningKey, independentOwnerSpkiSha256: sha(ownerSpki),
    accountId: scope.account_id, verifiedKeyringProofs: [ownProof], issuedAt: 1400 });
  const rosterVerification = { roster: signedRoster.roster,
    independentlyPinnedRosterSha256: signedRoster.rosterSha256,
    ownerPublicKey, independentOwnerSpkiSha256: sha(ownerSpki),
    accountId: scope.account_id };
  const verifiedAuthority = await archive.verifyVersionedAuthority({
    backupVerification, rosterVerification, otherVerifiedKeyringProofs: [] });
  const versionInputs = versions.map((row) => ({
    metadata: row.metadata, objectRevision: row.revision,
    ciphertext: row.ciphertext, cek: row.cek }));
  const recoverySecret = portable.generateRecoverySecret();
  const archiveInput = { recoverySecret, ownerSigningKey, ownerPublicKey,
    independentOwnerSpkiSha256: sha(ownerSpki), pinnedCurrentHead,
    scope, ownerHistoryCheckpoint: h2, previousOwnerHistoryProof: previous,
    signedDeviceGrant, signerKeyId, deviceId, issuedAt: 1500 };
  return { owner, authorityInput, backupVerification, rosterVerification,
    verifiedAuthority, versionInputs, versions, archiveInput,
    restoreInput: { recoverySecret, ownerPublicKey,
      independentOwnerSpkiSha256: sha(ownerSpki), pinnedCurrentHead,
      scope, signerKeyId, deviceId, previousOwnerHistoryProof: previous } };
}
async function sealedFixture() {
  const f = await fixture();
  const sealed = await archive.createVersionedArchive({ archiveInput: f.archiveInput,
    versions: f.versionInputs, verifiedAuthority: f.verifiedAuthority });
  return { ...f, sealed, restoreInput: { ...f.restoreInput,
    archive: sealed.archive, independentlyPinnedArchiveSha256: sealed.archiveSha256 } };
}
test("v2 archive preserves same-object revisions 1→2 with original ciphertext and 32-byte CEK", async () => {
  const f = await sealedFixture();
  assert.equal(f.sealed.archive.format, "rootark-zk1-keyring-portable-archive/v2");
  assert.ok(!JSON.stringify(f.sealed.archive).includes(b64(f.versions[0].cek)));
  const opened = await archive.recoverVersionedArchive({ recoveryInput: f.restoreInput,
    verifiedAuthority: f.verifiedAuthority });
  assert.equal(opened.files.length, 3);
  assert.equal(opened.completeRelativeToPinnedInventory, true);
  assert.equal(opened.ownerSignedAccountRosterVerified, true);
  assert.equal(opened.authorizesProductionRestore, false);
  for (let i = 0; i < opened.files.length; i++) {
    assert.equal(opened.files[i].objectId, b64(f.versions[i].objectId));
    assert.equal(opened.files[i].objectRevision, f.versions[i].revision);
    assert.deepEqual(Buffer.from(opened.files[i].ciphertext), f.versions[i].ciphertext);
    assert.deepEqual(Buffer.from(opened.files[i].cek), f.versions[i].cek);
    opened.files[i].ciphertext.fill(0);
    opened.files[i].cek.fill(0);
  }
});
test("v2 fails on missing revision, duplicated revision, forged ancestry, wrong root and wrong CEK", async () => {
  const f = await fixture();
  const versions = f.versionInputs;
  const sameObject = versions.find((v) => v.objectRevision === 2);
  const earliest = versions.find((v) => v.objectRevision === 1
    && v.metadata.object_id === sameObject.metadata.object_id);
  for (const v of [
    [],
    Array.from({ length: 13 }, () => versions[0]),
    versions.slice(1),
    [...versions, versions[0]],
    versions.map((entry) => entry === sameObject ? {
      ...entry, metadata: { ...entry.metadata,
        version_id: earliest.metadata.version_id } } : entry),
    versions.map((entry) => entry === sameObject ? {
      ...entry, metadata: { ...entry.metadata, parent_version_id: b64(rnd(16)) } } : entry),
    versions.map((entry) => entry === sameObject ? {
      ...entry, ciphertext: rnd(entry.ciphertext.length) } : entry),
    versions.map((entry) => entry === sameObject ? {
      ...entry, cek: rnd(32) } : entry),
    versions.map((entry) => entry === earliest ? {
      ...entry, objectRevision: 3 } : entry),
  ]) await assert.rejects(archive.createVersionedArchive({ archiveInput: f.archiveInput,
    versions: v, verifiedAuthority: f.verifiedAuthority }), deny);
});
test("v2 rejects altered roster/checkpoint, stale head, forged authority, replay and v1 downgrade", async () => {
  const f = await sealedFixture();
  for (const patch of [
    { independentlyPinnedRosterSha256: rnd(32) },
    { roster: { ...f.rosterVerification.roster, keyringCount: 2 } },
  ]) await assert.rejects(archive.verifyVersionedAuthority({
    backupVerification: f.backupVerification,
    rosterVerification: { ...f.rosterVerification, ...patch },
    otherVerifiedKeyringProofs: [] }), deny);
  for (const patch of [
    { independentlyPinnedInventoryCheckpointDigest: "0".repeat(64) },
    { pinnedCurrentHead: { ...f.archiveInput.pinnedCurrentHead, revision: 8 } },
    { signedDeviceGrant: { ...f.archiveInput.signedDeviceGrant, revoked_at_epoch: 4 } },
  ]) await assert.rejects(archive.verifyVersionedAuthority({
    backupVerification: { ...f.backupVerification, ...patch },
    rosterVerification: f.rosterVerification, otherVerifiedKeyringProofs: [] }), deny);
  await assert.rejects(archive.recoverVersionedArchive({
    recoveryInput: f.restoreInput, verifiedAuthority: { ...f.verifiedAuthority } }), deny);
  for (const patch of [
    { independentlyPinnedArchiveSha256: rnd(32) },
    { pinnedCurrentHead: { ...f.restoreInput.pinnedCurrentHead, epoch: 3 } },
    { scope: { ...f.restoreInput.scope, keyring_id: b64(rnd(16)) } },
    { archive: { ...f.sealed.archive, format: "rootark-zk1-keyring-portable-archive/v1" } },
  ]) await assert.rejects(archive.recoverVersionedArchive({
    recoveryInput: { ...f.restoreInput, ...patch },
    verifiedAuthority: f.verifiedAuthority }), deny);
});
test("v2 historical recovery keeps current signed grant, owner re-endorsement and one-use device PoP", async () => {
  const f = await sealedFixture();
  const raw = f.sealed.archive;
  const context = { format: raw.format, scope: raw.scope,
    ownerRevision: raw.ownerRevision, ownerDigest: raw.ownerDigest,
    ownerEpoch: raw.ownerEpoch, archiveId: raw.archiveId };
  const subtle = crypto.webcrypto.subtle;
  const hkdf = await subtle.importKey("raw", f.restoreInput.recoverySecret,
    "HKDF", false, ["deriveKey"]);
  const info = Buffer.concat([Buffer.from("Root.ark/zk-1/keyring-archive-key/v1\0"),
    Buffer.from(JSON.stringify(context))]);
  const aes = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256",
    salt: Buffer.from(raw.salt, "base64url"), info }, hkdf,
  { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const decrypted = Buffer.from(await subtle.decrypt({ name: "AES-GCM",
    iv: Buffer.from(raw.nonce, "base64url"),
    additionalData: Buffer.from(JSON.stringify(context)), tagLength: 128 },
  aes, Buffer.from(raw.ciphertextBase64, "base64url")));
  const payload = JSON.parse(decrypted.toString("utf8"));
  decrypted.fill(0);
  const [first, second] = f.authorityInput.ownerHistoryChain;
  const proof2 = await history.verifyOwnerCheckpoint({ checkpoint: second,
    scope: f.restoreInput.scope, signerPublicKey: f.archiveInput.ownerPublicKey,
    signerKeyId: f.restoreInput.signerKeyId,
    previous: f.restoreInput.previousOwnerHistoryProof });
  const laterHead = { revision: 8, digest: rnd(32), epoch: 5 };
  const third = await history.signOwnerCheckpoint({
    scope: f.restoreInput.scope, signerKey: f.archiveInput.ownerSigningKey,
    signerPublicKey: f.archiveInput.ownerPublicKey, signerKeyId: f.restoreInput.signerKeyId,
    deviceId: f.restoreInput.deviceId, revision: laterHead.revision,
    manifestDigest: laterHead.digest, issuedAt: 1700, previous: proof2 });
  const device = crypto.generateKeyPairSync("ed25519");
  const rawDevicePublic = device.publicKey.export({ format: "der", type: "spki" });
  const currentGrant = { ...f.archiveInput.signedDeviceGrant,
    manifest_revision: laterHead.revision, manifest_digest: b64(laterHead.digest),
    current_epoch: laterHead.epoch, authorization_key_id: b64(rnd(16)),
    authorization_public_key: b64(rawDevicePublic.subarray(-32)) };
  const GRANT = ["schema", "account_id", "compartment_id", "keyring_id", "device_id",
    "authorization_key_id", "authorization_public_key", "manifest_revision",
    "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
  const grantMessage = Buffer.concat([Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(GRANT.map((name) => [name, currentGrant[name]]))))]);
  currentGrant.signature = b64(crypto.sign(null, grantMessage, f.owner.privateKey));
  const currentOwnerRootCheckpoints = await Promise.all(payload.entries.map(({ bundle }) =>
    roots.signOwnerCiphertextRootCheckpoint({
      scope: f.restoreInput.scope, signerKey: f.archiveInput.ownerSigningKey,
      signerKeyId: f.restoreInput.signerKeyId, deviceId: f.restoreInput.deviceId,
      manifestRevision: laterHead.revision, manifestDigest: laterHead.digest,
      manifestEpoch: laterHead.epoch, objectId: bundle.metadata.object_id,
      objectRevision: bundle.objectRevision, ciphertextEpoch: bundle.metadata.epoch,
      ciphertextRoot: Buffer.from(bundle.ciphertextRoot, "base64url"), issuedAt: 1701 })));
  const base = { ...f.restoreInput, pinnedCurrentHead: laterHead,
    previousOwnerHistoryProof: null, historicalRecovery: {
      signedOwnerHistoryChain: [first, second, third], currentSignedDeviceGrant: currentGrant,
      currentOwnerRootCheckpoints } };
  await assert.rejects(archive.recoverVersionedArchive({
    recoveryInput: base, verifiedAuthority: f.verifiedAuthority }), deny);
  async function withPop(input) {
    const keyring = require("../public/client/rootark-zk1-keyring-portable-archive");
    const challenge = await keyring.issueHistoricalRecoveryChallenge({
      archiveSha256: input.independentlyPinnedArchiveSha256, accountArchiveSha256: null,
      scope: input.scope, pinnedCurrentHead: input.pinnedCurrentHead,
      independentOwnerSpkiSha256: input.independentOwnerSpkiSha256,
      currentSignedDeviceGrant: input.historicalRecovery.currentSignedDeviceGrant });
    return { ...input, historicalRecovery: { ...input.historicalRecovery,
      devicePoP: { challenge, signature: b64(crypto.sign(null,
        Buffer.from(keyring.historicalRecoveryChallengeMessage(challenge)), device.privateKey)) } } };
  }
  const approved = await withPop(base);
  const opened = await archive.recoverVersionedArchive({
    recoveryInput: approved, verifiedAuthority: f.verifiedAuthority });
  assert.equal(opened.files.length, 3);
  assert.equal(opened.historicalOwnerContinuityVerified, true);
  for (const item of opened.files) {
    item.ciphertext.fill(0); item.cek.fill(0);
  }
  await assert.rejects(archive.recoverVersionedArchive({
    recoveryInput: approved, verifiedAuthority: f.verifiedAuthority }), deny);
  const revoked = await withPop({ ...base, historicalRecovery: {
    ...base.historicalRecovery, currentSignedDeviceGrant: {
      ...currentGrant, revoked_at_epoch: laterHead.epoch } } });
  await assert.rejects(archive.recoverVersionedArchive({
    recoveryInput: revoked, verifiedAuthority: f.verifiedAuthority }), deny);
});
