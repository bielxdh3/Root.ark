"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const os = require("node:os");
const { spawn, execFileSync } = require("node:child_process");
const express = require("express");
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
const browserAuthority = require("../public/client/rootark-zk1-browser-authoritative-backup");
const b64 = (v) => Buffer.from(v).toString("base64url");
const rnd = (n) => crypto.randomBytes(n);
const sha = (v) => crypto.createHash("sha256").update(v).digest();
const deny = /ZK_(VERSIONED_KEYRING_ARCHIVE|KEYRING_ARCHIVE)_DENIED/;

async function fixture(clock = 1400, versionCount = 3) {
  assert.ok(Number.isInteger(versionCount) && versionCount >= 1 && versionCount <= 12);
  const offset = clock - 1400;
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
    revision: 6, manifestDigest: rnd(32), issuedAt: 1000 + offset, previous: null });
  const previous = await history.verifyOwnerCheckpoint({ checkpoint: h1, scope,
    signerPublicKey: ownerPublicKey, signerKeyId, previous: null });
  const h2 = await history.signOwnerCheckpoint({ scope, signerKey: ownerSigningKey,
    signerPublicKey: ownerPublicKey, signerKeyId, deviceId,
    revision: pinnedCurrentHead.revision, manifestDigest: pinnedCurrentHead.digest,
    issuedAt: 1100 + offset, previous });
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
  const versions = [];
  for (let index = 0; index < versionCount; index++) {
    const last = versionCount > 1 && index === versionCount - 1;
    versions.push({ objectId: last ? objectB : objectA,
      revision: last ? 1 : index + 1,
      epoch: last ? 4 : index === 0 ? 2 : 3,
      versionId: rnd(16),
      parentId: !last && index > 0 ? versions[index - 1].versionId : null });
  }
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
    previous_checkpoint_digest: null, issued_at: 1200 + offset, expires_at: 2000 + offset };
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
      ciphertextRoot, issuedAt: 1400 + offset });
    items.push({ objectId: b64(row.objectId), revision: row.revision,
      epoch: row.epoch, ciphertext: row.ciphertext, ownerRootCheckpoint });
  }
  const authorityInput = { scope, ownerPublicKey, ownerSigningKey,
    independentOwnerSpkiSha256: sha(ownerSpki), pinnedCurrentHead,
    signedDeviceGrant, ownerHistoryChain: [h1, h2], ownerSignerKeyId: signerKeyId,
    deviceId, ownerInventoryPortable, independentlyPinnedInventoryCheckpointDigest,
    independentlyPinnedInventorySignerSpkiSha256: sha(signerSpki).toString("hex"),
    inventorySignerPublicKey: signer.publicKey, inventorySignerKeyId,
    genesisSnapshot, committedProofChain, items, issuedAt: 1400 + offset, nowSeconds: clock };
  const signedBackup = await snapshots.createVerifiedSnapshot(authorityInput);
  const { items: _, issuedAt: __, ownerSigningKey: ___, ...verifyArgs } = authorityInput;
  const backupVerification = { ...verifyArgs, snapshot: signedBackup.snapshot,
    independentlyPinnedBackupSha256: signedBackup.snapshotSha256 };
  const ownProof = await snapshots.verifyBackupSnapshot(backupVerification);
  const signedRoster = await roster.createOwnerRoster({
    ownerPublicKey, ownerSigningKey, independentOwnerSpkiSha256: sha(ownerSpki),
    accountId: scope.account_id, verifiedKeyringProofs: [ownProof], issuedAt: clock });
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
    signedDeviceGrant, signerKeyId, deviceId, issuedAt: 1500 + offset };
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
test("browser WebCrypto independently verifies REAL owner pinned signed CBOR snapshot and complete owner roster", async () => {
  const f = await fixture();
  const context = {
    ...f.backupVerification,
    roster: f.rosterVerification.roster,
    independentRosterSha256: f.rosterVerification.independentlyPinnedRosterSha256,
    ownerHistoryCheckpoint: f.authorityInput.ownerHistoryChain[1],
    previousOwnerHistoryProof: f.archiveInput.previousOwnerHistoryProof,
    signerKeyId: f.archiveInput.signerKeyId,
    inventorySignerPublicKey: await crypto.webcrypto.subtle.importKey("spki",
      f.authorityInput.inventorySignerPublicKey.export({ type: "spki", format: "der" }),
      "Ed25519", true, ["verify"]),
  };
  const proof = await browserAuthority.verifyBackupSnapshot(context);
  assert.equal(proof.completeRelativeToOwnerCheckpoint, true);
  assert.equal(proof.globalAccountCompletenessProven, false);
  assert.equal(browserAuthority.readVerifiedBackupProof(proof).rows.length, 3);
  for (const changed of [
    { independentlyPinnedBackupSha256: rnd(32) },
    { independentlyPinnedInventoryCheckpointDigest: "0".repeat(64) },
    { independentRosterSha256: rnd(32) },
    { roster: { ...context.roster, keyringCount: 2 } },
    { snapshot: { ...context.snapshot, items: context.snapshot.items.slice(1) } },
    { pinnedCurrentHead: { ...context.pinnedCurrentHead, revision: 8 } },
    { inventorySignerKeyId: rnd(16) },
    { snapshot: { ...context.snapshot, items: context.snapshot.items.map(
      (row, i) => i === 1 ? { ...row, ciphertextBase64: b64(rnd(50)) } : row) } },
  ]) await assert.rejects(browserAuthority.verifyBackupSnapshot({
    ...context, ...changed }), /ZK_BROWSER_AUTHORITATIVE_BACKUP_DENIED/);
});
test("browser authority verifies archived signed inventory only through genesis-to-current owner continuity", async () => {
  const f = await fixture();
  const [genesis, archived] = f.authorityInput.ownerHistoryChain;
  const predecessor = await history.verifyOwnerCheckpoint({ checkpoint: archived,
    scope: f.archiveInput.scope, signerPublicKey: f.archiveInput.ownerPublicKey,
    signerKeyId: f.archiveInput.signerKeyId,
    previous: f.archiveInput.previousOwnerHistoryProof });
  const laterHead = { revision: 8, digest: rnd(32), epoch: 5 };
  const current = await history.signOwnerCheckpoint({
    scope: f.archiveInput.scope, signerKey: f.archiveInput.ownerSigningKey,
    signerPublicKey: f.archiveInput.ownerPublicKey,
    signerKeyId: f.archiveInput.signerKeyId, deviceId: f.archiveInput.deviceId,
    revision: laterHead.revision, manifestDigest: laterHead.digest,
    issuedAt: 1700, previous: predecessor });
  const signedGrant = { ...f.archiveInput.signedDeviceGrant,
    manifest_revision: laterHead.revision,
    manifest_digest: b64(laterHead.digest), current_epoch: laterHead.epoch };
  const GRANT = ["schema", "account_id", "compartment_id", "keyring_id", "device_id",
    "authorization_key_id", "authorization_public_key", "manifest_revision",
    "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
  signedGrant.signature = b64(crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(GRANT.map((key) => [key, signedGrant[key]])))),
  ]), f.owner.privateKey));
  const input = { ...f.backupVerification,
    roster: f.rosterVerification.roster,
    independentRosterSha256: f.rosterVerification.independentlyPinnedRosterSha256,
    inventorySignerPublicKey: await crypto.webcrypto.subtle.importKey("spki",
      f.authorityInput.inventorySignerPublicKey.export({ type: "spki", format: "der" }),
      "Ed25519", true, ["verify"]),
    ownerHistoryCheckpoint: current, previousOwnerHistoryProof: predecessor,
    signedDeviceGrant: signedGrant,
    pinnedCurrentHead: laterHead, signerKeyId: f.archiveInput.signerKeyId,
    archivalHistoryChain: [genesis, archived, current] };
  assert.equal((await browserAuthority.verifyBackupSnapshot(input))
    .completeRelativeToOwnerCheckpoint, true);
  for (const badChain of [null, [archived, current],
    [genesis, { ...archived, signature: b64(rnd(64)) }, current],
    [genesis, archived, { ...current, manifest_digest: b64(rnd(32)) }]]) {
    await assert.rejects(browserAuthority.verifyBackupSnapshot({
      ...input, archivalHistoryChain: badChain }),
    /ZK_BROWSER_AUTHORITATIVE_BACKUP_DENIED/);
  }
});
test("UMD browser-only modules mint signed inventory authority and restore genuine ciphertext+CEK", async () => {
  const f = await fixture();
  const context = vm.createContext({ crypto: crypto.webcrypto, Uint8Array,
    ArrayBuffer, TextEncoder, TextDecoder, btoa, atob, performance, setTimeout });
  const scripts = ["rootark-zk1-file-content", "rootark-zk1-ciphertext-chunk-root",
    "rootark-zk1-owner-signed-checkpoint", "rootark-zk1-owner-ciphertext-root-checkpoint",
    "rootark-zk1-normal-browser-trust-floor", "rootark-zk1-owner-inventory-trust-head",
    "rootark-zk1-portable-file-recovery", "rootark-zk1-browser-authoritative-backup",
    "rootark-zk1-keyring-portable-archive", "rootark-zk1-browser-versioned-archive"];
  for (const name of scripts) vm.runInContext(fs.readFileSync(path.join(__dirname,
    "../public/client", name + ".js"), "utf8"), context, { filename: name + ".js" });
  context.ownerKey = f.archiveInput.ownerPublicKey;
  context.privateKey = f.archiveInput.ownerSigningKey;
  context.ownerPin = f.archiveInput.independentOwnerSpkiSha256;
  context.secret = f.archiveInput.recoverySecret;
  context.signerId = f.archiveInput.signerKeyId;
  context.inventorySignerId = f.authorityInput.inventorySignerKeyId;
  context.invPin = f.backupVerification.independentlyPinnedBackupSha256;
  context.rosterPin = f.rosterVerification.independentlyPinnedRosterSha256;
  context.inventorySignerKey = await crypto.webcrypto.subtle.importKey("spki",
    f.authorityInput.inventorySignerPublicKey.export({ type: "spki", format: "der" }),
    "Ed25519", true, ["verify"]);
  context.trustedJson = JSON.stringify({
    scope: f.archiveInput.scope, ownerHistoryChain: f.authorityInput.ownerHistoryChain,
    grant: f.archiveInput.signedDeviceGrant,
    head: { ...f.archiveInput.pinnedCurrentHead, digest: b64(f.archiveInput.pinnedCurrentHead.digest) },
    signerKeyId: b64(f.archiveInput.signerKeyId), deviceId: f.archiveInput.deviceId,
    snapshot: f.backupVerification.snapshot, roster: f.rosterVerification.roster,
    ownerInventoryPortable: f.authorityInput.ownerInventoryPortable,
    inventoryCheckpointDigest: f.authorityInput.independentlyPinnedInventoryCheckpointDigest,
    inventorySignerSpki: f.authorityInput.independentlyPinnedInventorySignerSpkiSha256,
    versions: f.versionInputs.map((entry) => ({
      metadata: entry.metadata, objectRevision: entry.objectRevision,
      ciphertextBase64: b64(entry.ciphertext), cekBase64: b64(entry.cek) })),
  });
  const opened = await vm.runInContext(`(async () => {
    const input = JSON.parse(trustedJson);
    const before = await RootarkZk1OwnerSignedCheckpoint.verifyOwnerCheckpoint({
      checkpoint: input.ownerHistoryChain[0], scope: input.scope,
      signerPublicKey: ownerKey, signerKeyId: signerId, previous: null });
    const head = { revision: input.head.revision,
      digest: Uint8Array.from(atob(input.head.digest.replace(/-/g, "+").replace(/_/g, "/") + "="),
        (c) => c.charCodeAt(0)), epoch: input.head.epoch };
    const backupVerification = { snapshot: input.snapshot, roster: input.roster,
      independentRosterSha256: rosterPin, ownerPublicKey: ownerKey,
      independentOwnerSpkiSha256: ownerPin, pinnedCurrentHead: head,
      scope: input.scope, ownerInventoryPortable: input.ownerInventoryPortable,
      independentlyPinnedInventoryCheckpointDigest: input.inventoryCheckpointDigest,
      independentlyPinnedInventorySignerSpkiSha256: input.inventorySignerSpki,
      inventorySignerPublicKey: inventorySignerKey, inventorySignerKeyId: inventorySignerId,
      signedDeviceGrant: input.grant, ownerHistoryCheckpoint: input.ownerHistoryChain[1],
      previousOwnerHistoryProof: before, signerKeyId: signerId,
      deviceId: input.deviceId, independentlyPinnedBackupSha256: invPin, nowSeconds: 1400 };
    const authority = await RootarkZk1KeyringPortableArchive.verifyVersionedAuthority({
      backupVerification, rosterVerification: { roster: input.roster,
        independentlyPinnedRosterSha256: rosterPin, ownerPublicKey: ownerKey,
        independentOwnerSpkiSha256: ownerPin, accountId: input.scope.account_id },
      otherVerifiedKeyringProofs: [] });
    const common = { recoverySecret: secret, ownerPublicKey: ownerKey,
      independentOwnerSpkiSha256: ownerPin, pinnedCurrentHead: head, scope: input.scope,
      signerKeyId: signerId, deviceId: input.deviceId, previousOwnerHistoryProof: before };
    const sealed = await RootarkZk1BrowserVersionedArchive.createArchive({
      archiveInput: { ...common, ownerSigningKey: privateKey,
        signedDeviceGrant: input.grant, ownerHistoryCheckpoint: input.ownerHistoryChain[1],
        issuedAt: 1500 }, versions: input.versions, verifiedAuthority: authority,
      assertLive: () => {} });
    const opened = await RootarkZk1BrowserVersionedArchive.recoverArchive({
      recoveryInput: { ...common, archive: sealed.archive,
        independentlyPinnedArchiveSha256: sealed.archiveSha256 },
      verifiedAuthority: authority, assertLive: () => {} });
    const output = opened.files.map((item) => ({
      objectId: item.objectId, revision: item.objectRevision,
      ciphertext: Uint8Array.from(item.ciphertext), cek: Uint8Array.from(item.cek) }));
    for (const item of opened.files) { item.ciphertext.fill(0); item.cek.fill(0); }
    return { format: sealed.archive.format, output };
  })()`, context);
  assert.equal(opened.format, "rootark-zk1-keyring-portable-archive/v2");
  assert.equal(opened.output.length, 3);
  for (let i = 0; i < opened.output.length; i++) {
    assert.deepEqual(Buffer.from(opened.output[i].ciphertext), f.versions[i].ciphertext);
    assert.deepEqual(Buffer.from(opened.output[i].cek), f.versions[i].cek);
    opened.output[i].cek.fill(0); opened.output[i].ciphertext.fill(0);
  }
});

// End-to-end real Edge test. Every imported signature is produced by the same
// Node fixtures as the cryptographic suite; no browser verifier is mocked.
test("REAL Edge: authenticated signed CBOR v2 archive export/import and failure fencing", {
  timeout: 120000,
}, async (t) => {
  const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  if (!fs.existsSync(EDGE)) return t.skip("Microsoft Edge unavailable");
  const f = await fixture(Math.floor(Date.now() / 1000), 12);
  const app = express();
  let requests = 0, sensitiveWire = false, unexpectedRequests = 0;
  const scriptNames = ["rootark-zk1-file-content", "rootark-zk1-ciphertext-chunk-root",
    "rootark-zk1-ciphertext-download-integrity", "rootark-zk1-owner-signed-checkpoint",
    "rootark-zk1-owner-ciphertext-root-checkpoint", "rootark-zk1-protected-http-client",
    "rootark-zk1-uncertain-put-reconciliation", "rootark-zk1-normal-browser-trust-floor",
    "rootark-zk1-normal-browser-content", "rootark-zk1-owner-inventory-trust-head",
    "rootark-zk1-browser-authoritative-backup", "rootark-zk1-portable-file-recovery",
    "rootark-zk1-browser-recovery-http", "rootark-zk1-recoverable-workspace",
    "rootark-dev-vault-migration", "rootark-zk1-legacy-migration-workflow",
    "rootark-zk1-legacy-transition-receipt",
    "rootark-zk1-legacy-batch-migration", "rootark-zk1-v2-device-approval",
    "rootark-zk1-v2-browser-pop", "rootark-zk1-v2-committed-approval",
    "rootark-zk1-keyring-portable-archive", "rootark-zk1-browser-versioned-archive",
    "rootark-zk1-account-portable-recovery", "rootark-zk1-authenticated-workspace"];
  for (const name of scriptNames) app.get("/client/" + name + ".js", (_req, res) =>
    res.type("application/javascript").sendFile(path.join(__dirname, "../public/client",
      name + ".js"), { dotfiles: "allow" }));
  app.get("/edge-bootstrap.js", (_req, res) => res.type("application/javascript")
    .send("window.RootarkApi={get:async(path)=>{const response=await fetch(path,{credentials:'same-origin'});if(!response.ok)throw Error('session');return response.json()}};"));
  app.get("/zk-1/v1/workspace-capability", (req, res) => {
    requests++;
    if (!req.headers.cookie?.includes("rootark_session=edge-archive")) return res.sendStatus(401);
    return res.json({ enabled: true, securityVersion: 2, signedHistoryRequired: true });
  });
  app.get("/edge-workspace", (_req, res) => res.type("html")
    .set("Content-Security-Policy", "default-src 'self'; script-src 'self'; connect-src 'self'")
    .send('<!doctype html><html><head><meta charset="utf-8">'
      + '<script defer src="/edge-bootstrap.js"></script>'
      + '<script defer src="/client/rootark-zk1-authenticated-workspace.js"></script>'
      + '</head><body><section class="protected-client-panel">'
      + '<p id="protectedClientStatus"></p></section></body></html>'));
  app.use((req, res) => {
    if (req.url !== "/favicon.ico") unexpectedRequests++;
    sensitiveWire ||= /cekBase64|ciphertextBase64|owner private ciphertext revision/.test(req.url);
    res.sendStatus(404);
  });
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(() => { server.closeAllConnections(); server.close(); server.unref(); });
  const origin = "http://127.0.0.1:" + server.address().port;
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-v2-edge-archive-"));
  const child = spawn(EDGE, ["--headless=new", "--disable-gpu", "--no-first-run",
    "--disable-extensions", "--remote-debugging-port=0",
    "--user-data-dir=" + profile, "about:blank"], { stdio: "ignore", windowsHide: true });
  let socket;
  t.after(async () => {
    socket?.close();
    if (child.pid) {
      try { execFileSync("taskkill", ["/PID", String(child.pid), "/T", "/F"],
        { timeout: 10000, stdio: "ignore" }); } catch (_) { child.kill(); }
    }
    for (let index = 0; index < 30; index++) {
      try { fs.rmSync(profile, { recursive: true, force: true }); break; }
      catch (e) {
        if (!["EPERM", "EBUSY", "ENOTEMPTY"].includes(e.code)) throw e;
        await new Promise((resolve) => setTimeout(resolve, 120));
      }
    }
  });
  const wait = async (callback, label) => {
    for (let i = 0; i < 150; i++) {
      const result = await callback();
      if (result) return result;
      await new Promise((resolve) => setTimeout(resolve, 60));
    }
    throw Error("EDGE_V2_TIMEOUT_" + label);
  };
  const port = await wait(() => {
    const p = path.join(profile, "DevToolsActivePort");
    return fs.existsSync(p) ? Number(fs.readFileSync(p, "utf8").split(/\r?\n/)[0]) : null;
  }, "debug-port");
  const pages = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
  socket = new WebSocket(pages.find((p) => p.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  let serial = 0;
  const pending = new Map();
  socket.addEventListener("message", ({ data }) => {
    const item = JSON.parse(data);
    if (!pending.has(item.id)) return;
    const { resolve, reject } = pending.get(item.id);
    pending.delete(item.id);
    item.error ? reject(Error(item.error.message)) : resolve(item.result);
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++serial;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Network.enable");
  await send("Network.setCookie", { url: origin, name: "rootark_session",
    value: "edge-archive", httpOnly: true, sameSite: "Strict" });
  await send("Network.setCookie", { url: origin, name: "rootark_csrf",
    value: "edge-session", sameSite: "Strict" });
  const evaluate = async (expression) => {
    const result = await send("Runtime.evaluate", {
      expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw Error("EDGE_EXCEPTION: " + result.exceptionDetails.text);
    return result.result?.value;
  };
  await send("Page.navigate", { url: origin + "/edge-workspace" });
  await wait(() => evaluate("document.readyState==='complete'"), "load");
  await evaluate("window.dispatchEvent(new Event('rootark:workspace-rendered'))");
  await wait(() => evaluate("!!document.querySelector('#zk1-workspace-open')"), "entry");
  await evaluate("document.querySelector('#zk1-workspace-open').click()");
  await wait(() => evaluate("!!document.querySelector('dialog[open]')"), "dialog");
  await evaluate(`window.__versionsDownloads=[];window.__pending=[];window.__blobMap=new Map();
    const initial=URL.createObjectURL.bind(URL);
    URL.createObjectURL=(blob)=>{const url=initial(blob);__blobMap.set(url,blob);return url};
    HTMLAnchorElement.prototype.click=function(){
      const name=this.download, blob=__blobMap.get(this.href);
      __pending.push(blob.arrayBuffer().then(buf=>{
        const data=Array.from(new Uint8Array(buf), b=>String.fromCharCode(b)).join('');
        __versionsDownloads.push({name,data:btoa(data).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'')});
      }));
    };
    window.__setFiles=(map)=>{for(const [name,encoded] of Object.entries(map)){
      const el=document.querySelector('[data-zk1-field="'+name+'"]');
      const bin=atob(encoded.replace(/-/g,'+').replace(/_/g,'/')+
        '='.repeat((4-encoded.length%4)%4));
      const bytes=Uint8Array.from(bin,c=>c.charCodeAt(0));
      const dt=new DataTransfer();dt.items.add(new File([bytes],name+'.json'));el.files=dt.files;
    }};
    window.__setValues=(map)=>{for(const [name,value] of Object.entries(map))
      document.querySelector('[data-zk1-field="'+name+'"]').value=String(value)};
    window.__run=(name)=>document.querySelector('[data-zk1-action="'+name+'"]').click();`);
  const files = {
    owner: b64(f.owner.publicKey.export({ type: "spki", format: "der" }).subarray(-32)),
    grant: b64(JSON.stringify(f.archiveInput.signedDeviceGrant)),
    history: b64(JSON.stringify(f.authorityInput.ownerHistoryChain)),
    secret: b64(f.archiveInput.recoverySecret),
    "v2-snapshot": b64(JSON.stringify(f.backupVerification.snapshot)),
    "v2-roster": b64(JSON.stringify(f.rosterVerification.roster)),
    "inventory-portable": b64(f.authorityInput.ownerInventoryPortable),
    "v2-inventory-signer": b64(f.authorityInput.inventorySignerPublicKey.export({
      type: "spki", format: "der" })),
    "archive-owner-private": b64(f.owner.privateKey.export({ type: "pkcs8", format: "der" })),
    "v2-versions": b64(JSON.stringify({ schema: "rootark-zk1-version-selection/v1",
      versions: f.versionInputs.map((v) => ({
        metadata: v.metadata, objectRevision: v.objectRevision,
        ciphertextBase64: b64(v.ciphertext), cekBase64: b64(v.cek) })) })),
  };
  const values = {
    "owner-hash": b64(sha(f.owner.publicKey.export({ type: "spki",
      format: "der" }).subarray(-32))),
    "owner-spki": b64(f.archiveInput.independentOwnerSpkiSha256),
    revision: f.archiveInput.pinnedCurrentHead.revision,
    digest: b64(f.archiveInput.pinnedCurrentHead.digest),
    epoch: f.archiveInput.pinnedCurrentHead.epoch,
    "v2-snapshot-pin": b64(f.backupVerification.independentlyPinnedBackupSha256),
    "v2-roster-pin": b64(f.rosterVerification.independentlyPinnedRosterSha256),
    "inventory-pin": f.authorityInput.independentlyPinnedInventoryCheckpointDigest,
    "inventory-signer-spki": f.authorityInput.independentlyPinnedInventorySignerSpkiSha256,
    "v2-inventory-signer-id": b64(f.authorityInput.inventorySignerKeyId),
    "owner-signer": b64(f.archiveInput.signerKeyId),
    "owner-device": f.archiveInput.deviceId,
  };
  const fill = async (fileMap = files, valueMap = values) => {
    await evaluate("window.__setFiles(" + JSON.stringify(fileMap)
      + ");window.__setValues(" + JSON.stringify(valueMap) + ")");
  };
  const click = (action) => evaluate("window.__run(" + JSON.stringify(action) + ")");
  const status = () => evaluate("document.querySelector('[data-zk1-field=status]')?.textContent");
  const untilStatus = async (needle) => wait(async () => {
    const value = await status();
    return value?.includes(needle) ? value : null;
  }, needle);
  const downloads = () => evaluate("(async()=>{await Promise.all(__pending);return __versionsDownloads})()");
  await fill();
  await click("provision");
  await wait(async () => /Âncora offline|Piso local verificado/.test(await status()), "provision");
  await fill();
  await evaluate("document.querySelector('[data-zk1-field=v2-opt-in]').checked=true");
  await click("versioned-create");
  const created = await untilStatus("V2:");
  assert.match(created, /todas as versões verificadas/);
  const generated = await downloads();
  const archiveFile = generated.find((item) => item.name === "rootark-keyring-versions-v2.json");
  const hashFile = generated.find((item) => item.name === "rootark-keyring-versions-v2.sha256.txt");
  assert.ok(archiveFile && hashFile);
  const archiveText = Buffer.from(archiveFile.data, "base64url").toString("utf8");
  const archiveHash = Buffer.from(hashFile.data, "base64url").toString("utf8");
  assert.equal(JSON.parse(archiveText).format, "rootark-zk1-keyring-portable-archive/v2");
  await fill({ ...files, "archive-json": b64(archiveText) }, {
    ...values, "archive-sha": archiveHash });
  await click("versioned-recover");
  const restored = await untilStatus("V2:");
  assert.match(restored, /versões autenticadas/);
  const all = await downloads();
  const recovered = all.filter((item) => item.name.endsWith(".ciphertext"));
  const ceks = all.filter((item) => item.name.endsWith(".cek"));
  assert.equal(recovered.length, 12);
  assert.equal(ceks.length, 12);
  for (const entry of f.versionInputs) {
    const prefix = "zk1-" + entry.metadata.object_id + "-r" + entry.objectRevision;
    assert.deepEqual(Buffer.from(all.find((item) =>
      item.name === prefix + ".ciphertext")?.data || "", "base64url"), entry.ciphertext);
    assert.deepEqual(Buffer.from(all.find((item) =>
      item.name === prefix + ".cek")?.data || "", "base64url"), entry.cek);
  }
  assert.equal(requests > 0, true);
  assert.equal(sensitiveWire, false);
  assert.equal(unexpectedRequests, 0, "archive export/import leaked data to an HTTP route");
  const previous = all.length;
  // Omitted owner-authenticated revision MUST fail before any artifact release.
  const altered = { schema: "rootark-zk1-version-selection/v1",
    versions: f.versionInputs.slice(1).map((v) => ({
      metadata: v.metadata, objectRevision: v.objectRevision,
      ciphertextBase64: b64(v.ciphertext), cekBase64: b64(v.cek) })) };
  await fill({ ...files, "v2-versions": b64(JSON.stringify(altered)) });
  await click("versioned-create");
  await untilStatus("Operação recusada");
  assert.equal((await downloads()).length, previous);
  await fill({ ...files, "archive-json": b64(archiveText) },
    { ...values, "archive-sha": b64(rnd(32)) });
  await click("versioned-recover");
  await untilStatus("Operação recusada");
  assert.equal((await downloads()).length, previous,
    "invalid independent archive hash released a partial version");
  const allVersions = JSON.parse(Buffer.from(files["v2-versions"], "base64url").toString("utf8"));
  const corrupted = allVersions.versions.map((entry, i) =>
    i === allVersions.versions.length - 1
      ? { ...entry, cekBase64: b64(rnd(32)) } : entry);
  const portableWire = JSON.parse(f.authorityInput.ownerInventoryPortable);
  portableWire.minimum_snapshot = b64(rnd(64));
  const adversarial = [
    { files: { "v2-versions": b64(JSON.stringify({
      ...allVersions, versions: [...allVersions.versions, allVersions.versions[0]] })) } },
    { files: { "v2-versions": b64(JSON.stringify({
      ...allVersions, versions: corrupted })) } },
    { files: { "v2-roster": b64(JSON.stringify({
      ...f.rosterVerification.roster, keyringCount: 2 })) } },
    { files: { "inventory-portable": b64(JSON.stringify(portableWire)) } },
    { values: { "v2-snapshot-pin": b64(rnd(32)) } },
  ];
  for (const attack of adversarial) {
    await fill({ ...files, ...attack.files }, { ...values, ...attack.values });
    await click("versioned-create");
    await untilStatus("Operação recusada");
    assert.equal((await downloads()).length, previous,
      "tampered inventory, roster, version count or CEK released a local artifact");
  }
  // Real owner-signed later head. Re-endorse the *archive bundle roots*,
  // retain the original inventory checkpoint, and use the NEW device key
  // for the browser-generated one-shot historical PoP.
  const [first, second] = f.authorityInput.ownerHistoryChain;
  const predecessor = await history.verifyOwnerCheckpoint({
    checkpoint: second, scope: f.archiveInput.scope,
    signerPublicKey: f.archiveInput.ownerPublicKey,
    signerKeyId: f.archiveInput.signerKeyId,
    previous: f.archiveInput.previousOwnerHistoryProof });
  const newHead = { revision: 8, digest: rnd(32), epoch: 5 };
  const third = await history.signOwnerCheckpoint({
    scope: f.archiveInput.scope, signerKey: f.archiveInput.ownerSigningKey,
    signerPublicKey: f.archiveInput.ownerPublicKey,
    signerKeyId: f.archiveInput.signerKeyId, deviceId: f.archiveInput.deviceId,
    revision: newHead.revision, manifestDigest: newHead.digest,
    issuedAt: Math.floor(Date.now() / 1000), previous: predecessor });
  const device = crypto.generateKeyPairSync("ed25519");
  const devicePrivate = device.privateKey.export({ type: "pkcs8", format: "der" });
  const newerGrant = { ...f.archiveInput.signedDeviceGrant,
    manifest_revision: newHead.revision, manifest_digest: b64(newHead.digest),
    current_epoch: newHead.epoch, authorization_key_id: b64(rnd(16)),
    authorization_public_key: b64(device.publicKey.export({
      type: "spki", format: "der" }).subarray(-32)) };
  const grantBody = ["schema", "account_id", "compartment_id", "keyring_id", "device_id",
    "authorization_key_id", "authorization_public_key", "manifest_revision",
    "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
  newerGrant.signature = b64(crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(grantBody.map((k) => [k, newerGrant[k]]))))]),
  f.owner.privateKey));
  const outer = JSON.parse(archiveText);
  const archiveContext = { format: outer.format, scope: outer.scope,
    ownerRevision: outer.ownerRevision, ownerDigest: outer.ownerDigest,
    ownerEpoch: outer.ownerEpoch, archiveId: outer.archiveId };
  const subtle = crypto.webcrypto.subtle;
  const holder = await subtle.importKey("raw", f.archiveInput.recoverySecret,
    "HKDF", false, ["deriveKey"]);
  const key = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256",
    salt: Buffer.from(outer.salt, "base64url"),
    info: Buffer.concat([Buffer.from("Root.ark/zk-1/keyring-archive-key/v1\0"),
      Buffer.from(JSON.stringify(archiveContext))]) }, holder,
  { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const opened = JSON.parse(Buffer.from(await subtle.decrypt({
    name: "AES-GCM", iv: Buffer.from(outer.nonce, "base64url"),
    additionalData: Buffer.from(JSON.stringify(archiveContext)), tagLength: 128 },
  key, Buffer.from(outer.ciphertextBase64, "base64url"))).toString("utf8"));
  const signedCurrentRoots = await Promise.all(opened.entries.map(({ bundle }) =>
    roots.signOwnerCiphertextRootCheckpoint({
      scope: f.archiveInput.scope, signerKey: f.archiveInput.ownerSigningKey,
      signerKeyId: f.archiveInput.signerKeyId, deviceId: f.archiveInput.deviceId,
      manifestRevision: newHead.revision, manifestDigest: newHead.digest,
      manifestEpoch: newHead.epoch, objectId: bundle.metadata.object_id,
      objectRevision: bundle.objectRevision, ciphertextEpoch: bundle.metadata.epoch,
      ciphertextRoot: Buffer.from(bundle.ciphertextRoot, "base64url"),
      issuedAt: Math.floor(Date.now() / 1000) })));
  const historicalRecovery = { signedOwnerHistoryChain: [first, second, third],
    currentSignedDeviceGrant: newerGrant, currentOwnerRootCheckpoints: signedCurrentRoots };
  const historicalSelection = { schema: "rootark-zk1-keyring-history-endorsement/v1",
    scope: f.archiveInput.scope, historicalRecovery };
  const nextFiles = { ...files, history: b64(JSON.stringify([first, second, third])),
    grant: b64(JSON.stringify(newerGrant)),
    private: b64(devicePrivate),
    "archive-json": b64(archiveText),
    "archive-historical-proof": b64(JSON.stringify(historicalSelection)) };
  const nextValues = { ...values, revision: newHead.revision,
    epoch: newHead.epoch, digest: b64(newHead.digest), "archive-sha": archiveHash };
  await fill(nextFiles, nextValues);
  await evaluate("document.querySelector('[data-zk1-field=archive-historical-opt-in]').checked=true");
  await click("provision");
  await wait(async () => /Âncora offline|Piso local verificado/.test(await status()), "new-floor");
  await fill({ ...nextFiles, private: b64(devicePrivate) }, nextValues);
  await evaluate("document.querySelector('[data-zk1-field=archive-historical-opt-in]').checked=true;"
    + "document.querySelector('[data-zk1-field=v2-opt-in]').checked=true");
  await click("versioned-recover");
  const histStatus = await untilStatus("V2:");
  assert.match(histStatus, /versões autenticadas/);
  const countAfterHistorical = (await downloads()).length;
  assert.equal(countAfterHistorical, previous + 24);
  // A subsequent owner-approved operation issues another browser-local PoP
  // rather than importing a self-declared challenge from JSON.
  const beforeInvalid = countAfterHistorical;
  await fill({ ...nextFiles, private: b64(devicePrivate) }, nextValues);
  await evaluate("document.querySelector('[data-zk1-field=archive-historical-opt-in]').checked=true;"
    + "document.querySelector('[data-zk1-field=v2-opt-in]').checked=true");
  await click("versioned-recover");
  await untilStatus("V2:");
  assert.equal((await downloads()).length, beforeInvalid + 24);
  // Pause only AFTER the real WebCrypto verifier has authenticated EVERY
  // revision, with the original module handling signatures and AEAD. The
  // delay gives the test a deterministic race window at the release boundary.
  await evaluate(`window.__realVersioned=RootarkZk1BrowserVersionedArchive;
    window.__installArchiveHold=()=>{
      window.__holdReady=false;window.__releaseArchive=null;window.__heldOpened=null;
      window.RootarkZk1BrowserVersionedArchive={
        ...window.__realVersioned,
        recoverArchive:async(input)=>{
          const result=await window.__realVersioned.recoverArchive(input);
          window.__heldOpened=result;
          window.__holdReady=true;
          await new Promise(resolve=>window.__releaseArchive=resolve);
          return result;
        }
      };
    };
    window.__heldWiped=()=>window.__heldOpened?.files.every(file=>
      file.ciphertext.every(v=>v===0)&&file.cek.every(v=>v===0));`);
  for (const interruptedBy of ["csrf", "logout"]) {
    const before = (await downloads()).length;
    await fill({ ...nextFiles, private: b64(devicePrivate) }, nextValues);
    await evaluate("document.querySelector('[data-zk1-field=archive-historical-opt-in]').checked=true;"
      + "document.querySelector('[data-zk1-field=v2-opt-in]').checked=true;"
      + "window.__installArchiveHold()");
    await click("versioned-recover");
    await wait(() => evaluate("window.__holdReady===true&&typeof window.__releaseArchive==='function'"),
      "post-verification-" + interruptedBy);
    if (interruptedBy === "csrf") await evaluate(
      "document.cookie='rootark_csrf=swapped; path=/';window.__releaseArchive()");
    else await evaluate(
      "window.dispatchEvent(new Event('rootark:logout'));window.__releaseArchive()");
    await untilStatus("Operação recusada");
    assert.equal((await downloads()).length, before,
      "revoked session downloaded ciphertext/CEK after full verification");
    assert.equal(await evaluate("window.__heldWiped()"), true,
      "pending plaintext-equivalent CEK and ciphertext were not zeroized");
    if (interruptedBy === "csrf") await evaluate(
      "document.cookie='rootark_csrf=edge-session; path=/'");
  }
});

test("versioned signed manifest accepts 1 and 12 revisions, rejects omitted rows before release", async () => {
  for (const count of [1, 12]) {
    const f = await fixture(1400, count);
    const sealed = await archive.createVersionedArchive({
      archiveInput: f.archiveInput, versions: f.versionInputs,
      verifiedAuthority: f.verifiedAuthority });
    const opened = await archive.recoverVersionedArchive({
      recoveryInput: { ...f.restoreInput, archive: sealed.archive,
        independentlyPinnedArchiveSha256: sealed.archiveSha256 },
      verifiedAuthority: f.verifiedAuthority });
    assert.equal(opened.files.length, count);
    for (const file of opened.files) {
      file.ciphertext.fill(0); file.cek.fill(0);
    }
    if (count > 1) await assert.rejects(archive.createVersionedArchive({
      archiveInput: f.archiveInput, versions: f.versionInputs.slice(1),
      verifiedAuthority: f.verifiedAuthority }), deny);
  }
});
