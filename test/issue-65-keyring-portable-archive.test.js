"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const api = require("../public/client/rootark-zk1-keyring-portable-archive");
const portable = require("../public/client/rootark-zk1-portable-file-recovery");
const ownerHistory = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const ownerRoots = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");
const floor = require("../public/client/rootark-zk1-normal-browser-trust-floor");

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const random = (n) => crypto.randomBytes(n);
const failure = /ZK_KEYRING_ARCHIVE_DENIED/;
const GRANT = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key",
  "manifest_revision", "manifest_digest", "current_epoch", "enrolled_epoch",
  "revoked_at_epoch"];
const grantDomain = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");

async function prepare() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const subtle = crypto.webcrypto.subtle;
  const ownerSigningKey = await subtle.importKey("pkcs8",
    keys.privateKey.export({ format: "der", type: "pkcs8" }), "Ed25519", false, ["sign"]);
  const ownerPublicKey = await subtle.importKey("spki",
    keys.publicKey.export({ format: "der", type: "spki" }), "Ed25519", true, ["verify"]);
  const spki = keys.publicKey.export({ format: "der", type: "spki" });
  const scope = { account_id: b64(random(16)), compartment_id: b64(random(8)),
    keyring_id: b64(random(16)) };
  const signerKeyId = random(16);
  const deviceId = "owner-laptop";
  const pinnedCurrentHead = { revision: 7, digest: random(32), epoch: 4 };
  const signedDeviceGrant = { schema: "rootark-zk1-browser-owner-device-grant/v1",
    ...scope, device_id: deviceId, authorization_key_id: b64(random(16)),
    authorization_public_key: b64(random(32)),
    manifest_revision: pinnedCurrentHead.revision,
    manifest_digest: b64(pinnedCurrentHead.digest),
    current_epoch: pinnedCurrentHead.epoch, enrolled_epoch: 1,
    revoked_at_epoch: null };
  function signGrant(input) {
    const canonical = Buffer.from(JSON.stringify(Object.fromEntries(
      GRANT.map((n) => [n, input[n]]))));
    return { ...input, signature: b64(crypto.sign(null,
      Buffer.concat([grantDomain, canonical]), keys.privateKey)) };
  }
  const ownerHistoryCheckpoint = await ownerHistory.signOwnerCheckpoint({ scope,
    signerKey: ownerSigningKey, signerPublicKey: ownerPublicKey, signerKeyId,
    deviceId, revision: pinnedCurrentHead.revision,
    manifestDigest: pinnedCurrentHead.digest, issuedAt: 1600, previous: null });
  const files = Array.from({ length: 3 }, (_, i) => ({
    metadata: { ...scope, object_id: b64(random(16)), version_id: b64(random(16)),
      parent_version_id: null, epoch: i + 1, kind: "file" },
    objectRevision: i + 1, name: `file${i}.txt`,
    mediaType: "text/plain", data: Buffer.from(`private payload ${i}, keyring archive`) }));
  const recoverySecret = portable.generateRecoverySecret();
  const common = { recoverySecret, ownerPublicKey,
    independentOwnerSpkiSha256: crypto.createHash("sha256").update(spki).digest(),
    pinnedCurrentHead, scope, signerKeyId, deviceId,
    previousOwnerHistoryProof: null };
  const options = { ...common, ownerSigningKey, files,
    ownerHistoryCheckpoint, signedDeviceGrant: signGrant(signedDeviceGrant),
    issuedAt: 1601 };
  const msg = Buffer.from(JSON.stringify(Object.fromEntries(GRANT.map((n) =>
    [n, signedDeviceGrant[n]]))));
  assert.equal(crypto.verify(null, Buffer.concat([grantDomain, msg]),
    keys.publicKey, Buffer.from(options.signedDeviceGrant.signature, "base64url")), true);
  const direct = await ownerHistory.verifyOwnerCheckpoint({ checkpoint: ownerHistoryCheckpoint,
    scope, signerPublicKey: ownerPublicKey, signerKeyId, previous: null });
  assert.equal(direct.revision, pinnedCurrentHead.revision);
  await floor.verifyExternalAnchor({ ownerPublicKey,
    independentOwnerSpkiSha256: common.independentOwnerSpkiSha256,
    pinnedCurrentHead, signedDeviceGrant: options.signedDeviceGrant,
    ownerHistoryCheckpoint, previousOwnerHistoryProof: null });
  const sealed = await api.createArchive(options);
  const recover = { ...common, archive: sealed.archive,
    independentlyPinnedArchiveSha256: sealed.archiveSha256 };
  return { keys, common, options, files, sealed, recover,
    signedDeviceGrant, signGrant, ownerHistoryCheckpoint };
}

test("encrypted owner-signed keyring archive restores 3 files with independent 256-bit secret and pin, no server CEK", async () => {
  const f = await prepare();
  const archive = f.sealed.archive;
  assert.equal(f.sealed.independentlyPinnedByModule, false);
  assert.equal(archive.format, "rootark-zk1-keyring-portable-archive/v1");
  assert.equal(f.common.recoverySecret.byteLength, 32);
  const payload = JSON.stringify(archive);
  assert.ok(!payload.includes(f.files[0].metadata.object_id));
  assert.ok(!payload.includes(f.files[1].name));
  assert.ok(!payload.includes(f.files[2].data.toString("utf8")));
  assert.ok(!payload.includes(b64(f.common.recoverySecret)));
  const restored = await api.recoverArchive(f.recover);
  assert.equal(restored.files.length, 3);
  assert.equal(restored.signedManifestVerified, true);
  assert.equal(restored.allOwnerSignedRootsVerified, true);
  assert.equal(restored.currentOnlineRevocationVerified, false);
  assert.equal(restored.authorizesProductionRestore, false);
  const byId = new Map(restored.files.map((entry) => [entry.objectId, entry]));
  for (const file of f.files) {
    assert.deepEqual(Buffer.from(byId.get(file.metadata.object_id).data), file.data);
    assert.equal(byId.get(file.metadata.object_id).objectRevision, file.objectRevision);
  }
  for (const restoredFile of restored.files) restoredFile.data.fill(0);
});

test("rollback, wrong external archive pin, changed current head, fork and cross-keyring scope all fail before release", async () => {
  const f = await prepare();
  for (const changed of [
    { independentlyPinnedArchiveSha256: random(32) },
    { recoverySecret: random(32) },
    { independentOwnerSpkiSha256: random(32) },
    { scope: { ...f.common.scope, keyring_id: b64(random(16)) } },
    { pinnedCurrentHead: { ...f.common.pinnedCurrentHead, revision: 8 } },
    { pinnedCurrentHead: { ...f.common.pinnedCurrentHead, epoch: 5 } },
    { pinnedCurrentHead: { ...f.common.pinnedCurrentHead, digest: random(32) } },
    { archive: { ...f.sealed.archive, ciphertextBase64: b64(random(100)) } },
    { archive: { ...f.sealed.archive, signature: b64(random(64)) } },
    { archive: { ...f.sealed.archive, ownerRevision: 8 } },
    { archive: { ...f.sealed.archive, extraArbitraryFile: "file" } },
  ]) await assert.rejects(api.recoverArchive({ ...f.recover, ...changed }), failure);

  const fork = await api.createArchive({ ...f.options, files: f.files.slice(0, 2) });
  await assert.rejects(api.recoverArchive({ ...f.recover, archive: fork.archive }), failure,
    "even a valid second owner signature cannot replace the independently pinned exact snapshot");
  const alternativeKeyring = { ...f.options, scope: { ...f.common.scope,
    keyring_id: b64(random(16)) } };
  await assert.rejects(api.createArchive(alternativeKeyring), failure);
});

test("duplicate object or version, partial write, unsigned arbitrary file list and invalid epoch are rejected", async () => {
  const f = await prepare();
  const duplicate = { ...f.files[1], metadata: { ...f.files[1].metadata,
    object_id: f.files[0].metadata.object_id } };
  const duplicateVersion = { ...f.files[1], metadata: { ...f.files[1].metadata,
    version_id: f.files[0].metadata.version_id } };
  for (const files of [
    [f.files[0], duplicate], [f.files[0], duplicateVersion],
    [f.files[0], f.files[0]],
    [{ ...f.files[0], metadata: { ...f.files[0].metadata,
      epoch: f.common.pinnedCurrentHead.epoch + 1 } }],
    [{ ...f.files[0], data: new Uint8Array(2 * 1024 * 1024 + 1) }],
    Array.from({ length: 13 }, () => f.files[0]),
    [],
  ]) await assert.rejects(api.createArchive({ ...f.options, files }), failure);
  const full = f.sealed.archive;
  await assert.rejects(api.recoverArchive({ ...f.recover, archive: {
    ...full, ciphertextBase64: full.ciphertextBase64.slice(0, -2),
  } }), failure);
});

test("offline enrolled grant requires owner signature and cannot be revoked/new-device self-declared", async () => {
  const f = await prepare();
  const ownerHead = f.options.pinnedCurrentHead;
  const base = { ...f.signedDeviceGrant };
  for (const signedDeviceGrant of [
    { ...f.options.signedDeviceGrant, revoked_at_epoch: 4 },
    { ...f.options.signedDeviceGrant, device_id: "new-device" },
    f.signGrant({ ...base, revoked_at_epoch: 4 }),
    f.signGrant({ ...base, enrolled_epoch: 5 }),
    f.signGrant({ ...base, device_id: "new-device" }),
    f.signGrant({ ...base, manifest_revision: ownerHead.revision - 1 }),
  ]) await assert.rejects(api.createArchive({ ...f.options, signedDeviceGrant }), failure);
  await assert.rejects(api.recoverArchive({ ...f.recover,
    previousOwnerHistoryProof: { signedCheckpointVerified: true, authorizesRecovery: true } }),
  failure);
});

test("valid signed history seq2 requires genuinely branded predecessor, and forged brand is denied", async () => {
  const f = await prepare();
  const previous = await ownerHistory.verifyOwnerCheckpoint({
    checkpoint: f.ownerHistoryCheckpoint, scope: f.common.scope,
    signerPublicKey: f.common.ownerPublicKey,
    signerKeyId: f.common.signerKeyId, previous: null });
  const second = await ownerHistory.signOwnerCheckpoint({
    scope: f.common.scope, signerKey: f.options.ownerSigningKey,
    signerPublicKey: f.options.ownerPublicKey,
    signerKeyId: f.options.signerKeyId, deviceId: f.options.deviceId,
    revision: f.common.pinnedCurrentHead.revision,
    manifestDigest: f.common.pinnedCurrentHead.digest,
    issuedAt: 1602, previous });
  const signed = await api.createArchive({ ...f.options,
    ownerHistoryCheckpoint: second, previousOwnerHistoryProof: previous });
  const input = { ...f.recover, archive: signed.archive,
    independentlyPinnedArchiveSha256: signed.archiveSha256,
    previousOwnerHistoryProof: previous };
  assert.equal((await api.recoverArchive(input)).files.length, 3);
  for (const fake of [{ ...previous }, { ...previous, authorizesRecovery: true },
    { signedCheckpointVerified: true }, new Proxy(previous, {})]) {
    await assert.rejects(api.recoverArchive({ ...input,
      previousOwnerHistoryProof: fake }), failure);
  }
});

test("a genuinely owner-signed but unrecoverable later file aborts the entire multi-file restore", async () => {
  const f = await prepare();
  const previous = f.sealed.archive;
  const subtle = crypto.webcrypto.subtle;
  const context = { format: previous.format, scope: previous.scope,
    ownerRevision: previous.ownerRevision, ownerDigest: previous.ownerDigest,
    ownerEpoch: previous.ownerEpoch, archiveId: previous.archiveId };
  const base = await subtle.importKey("raw", f.common.recoverySecret, "HKDF", false,
    ["deriveKey"]);
  const kdf = Buffer.concat([Buffer.from("Root.ark/zk-1/keyring-archive-key/v1\0"),
    Buffer.from(JSON.stringify(context))]);
  const archiveKey = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256",
    salt: Buffer.from(previous.salt, "base64url"), info: kdf }, base,
  { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const plaintext = await subtle.decrypt({ name: "AES-GCM",
    iv: Buffer.from(previous.nonce, "base64url"),
    additionalData: Buffer.from(JSON.stringify(context)), tagLength: 128 },
  archiveKey, Buffer.from(previous.ciphertextBase64, "base64url"));
  const payload = JSON.parse(Buffer.from(plaintext).toString("utf8"));
  assert.equal(payload.entries.length, 3);
  // The owner signs an envelope containing one valid, two valid, and then a
  // corrupt user-held CEK wrap. Signature/root checks pass but the last
  // portable decryption fails: the API must not return the first two files.
  const last = payload.entries[2].bundle;
  last.wrap.sealedCek = b64(random(Buffer.from(last.wrap.sealedCek, "base64url").length));
  const unsigned = { ...previous, nonce: b64(random(12)) };
  const modified = Buffer.from(await subtle.encrypt({ name: "AES-GCM",
    iv: Buffer.from(unsigned.nonce, "base64url"),
    additionalData: Buffer.from(JSON.stringify(context)), tagLength: 128 },
  archiveKey, Buffer.from(JSON.stringify(payload))));
  unsigned.ciphertextBase64 = b64(modified);
  const fields = ["format", "scope", "ownerRevision", "ownerDigest", "ownerEpoch",
    "archiveId", "salt", "nonce", "ciphertextBase64"];
  const signaturePayload = Buffer.concat([
    Buffer.from("Root.ark/zk-1/keyring-archive-signed/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(fields.map((name) => [name, unsigned[name]]))))]);
  unsigned.signature = b64(crypto.sign(null, signaturePayload, f.keys.privateKey));
  const sha = crypto.createHash("sha256").update(JSON.stringify(unsigned)).digest();
  await assert.rejects(api.recoverArchive({ ...f.recover, archive: unsigned,
    independentlyPinnedArchiveSha256: sha }), failure,
  "even a fresh owner signature does not permit a partially decrypted account archive");
});

test("caller mutation after first await cannot swap files, head, grants or signer identity", async () => {
  const f = await prepare();
  const oldData = Buffer.from(f.files[0].data);
  const trustedScope = { ...f.common.scope };
  const pinnedHead = { ...f.common.pinnedCurrentHead,
    digest: Buffer.from(f.common.pinnedCurrentHead.digest) };
  const ownerId = Buffer.from(f.common.signerKeyId);
  const oldPin = Buffer.from(f.common.independentOwnerSpkiSha256);
  const archivePromise = api.createArchive(f.options);
  // The async function must copy all caller-owned fields before its first
  // await, including the file bytes and signed owner grant.
  f.files[0].data.fill(0);
  f.files[0].metadata.object_id = b64(random(16));
  f.options.signedDeviceGrant.signature = b64(random(64));
  f.common.scope.keyring_id = b64(random(16));
  f.common.pinnedCurrentHead.digest.fill(0);
  f.common.signerKeyId.fill(0);
  const sealed = await archivePromise;
  const restored = await api.recoverArchive({ archive: sealed.archive,
    recoverySecret: f.common.recoverySecret, ownerPublicKey: f.common.ownerPublicKey,
    independentOwnerSpkiSha256: oldPin,
    independentlyPinnedArchiveSha256: sealed.archiveSha256,
    pinnedCurrentHead: pinnedHead, scope: trustedScope,
    signerKeyId: ownerId, deviceId: f.common.deviceId,
    previousOwnerHistoryProof: null });
  assert.ok(restored.files.some((item) => Buffer.from(item.data).equals(oldData)));
  for (const item of restored.files) item.data.fill(0);
});

async function laterOwnerHeadFixture() {
  const f = await prepare();
  const archive = f.sealed.archive;
  const context = { format: archive.format, scope: archive.scope,
    ownerRevision: archive.ownerRevision, ownerDigest: archive.ownerDigest,
    ownerEpoch: archive.ownerEpoch, archiveId: archive.archiveId };
  const subtle = crypto.webcrypto.subtle;
  const secretKey = await subtle.importKey("raw", f.common.recoverySecret, "HKDF", false,
    ["deriveKey"]);
  const secretInfo = Buffer.concat([Buffer.from("Root.ark/zk-1/keyring-archive-key/v1\0"),
    Buffer.from(JSON.stringify(context))]);
  const key = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256",
    salt: Buffer.from(archive.salt, "base64url"), info: secretInfo }, secretKey,
  { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const opened = Buffer.from(await subtle.decrypt({ name: "AES-GCM",
    iv: Buffer.from(archive.nonce, "base64url"),
    additionalData: Buffer.from(JSON.stringify(context)), tagLength: 128 },
  key, Buffer.from(archive.ciphertextBase64, "base64url")));
  const manifest = JSON.parse(opened.toString("utf8"));
  opened.fill(0);
  const genesisProof = await ownerHistory.verifyOwnerCheckpoint({
    checkpoint: f.ownerHistoryCheckpoint, scope: f.common.scope,
    signerPublicKey: f.common.ownerPublicKey,
    signerKeyId: f.common.signerKeyId, previous: null });
  const laterHead = { revision: 8, digest: random(32), epoch: 5 };
  const laterHistory = await ownerHistory.signOwnerCheckpoint({
    scope: f.common.scope, signerKey: f.options.ownerSigningKey,
    signerPublicKey: f.options.ownerPublicKey,
    signerKeyId: f.common.signerKeyId, deviceId: f.common.deviceId,
    revision: laterHead.revision, manifestDigest: laterHead.digest,
    issuedAt: 1700, previous: genesisProof });
  const currentlySignedGrant = f.signGrant({ ...f.signedDeviceGrant,
    manifest_revision: laterHead.revision, manifest_digest: b64(laterHead.digest),
    current_epoch: laterHead.epoch });
  const currentOwnerRootCheckpoints = await Promise.all(manifest.entries.map(({ bundle }) =>
    ownerRoots.signOwnerCiphertextRootCheckpoint({
      scope: f.common.scope, signerKey: f.options.ownerSigningKey,
      signerKeyId: f.common.signerKeyId, deviceId: f.common.deviceId,
      manifestRevision: laterHead.revision, manifestDigest: laterHead.digest,
      manifestEpoch: laterHead.epoch, objectId: bundle.metadata.object_id,
      objectRevision: bundle.objectRevision, ciphertextEpoch: bundle.metadata.epoch,
      ciphertextRoot: Buffer.from(bundle.ciphertextRoot, "base64url"), issuedAt: 1701 })));
  const historicalRecovery = { signedOwnerHistoryChain: [f.ownerHistoryCheckpoint, laterHistory],
    currentSignedDeviceGrant: currentlySignedGrant, currentOwnerRootCheckpoints };
  const input = { ...f.recover, pinnedCurrentHead: laterHead, historicalRecovery };
  return { f, input, historicalRecovery, laterHead, laterHistory };
}

test("RED: legitimate later head and epoch recover archived roots ONLY after current owner re-endorsement and signed genesis continuity", async () => {
  const { f, input } = await laterOwnerHeadFixture();
  await assert.rejects(api.recoverArchive({ ...input, historicalRecovery: undefined }), failure);
  const restored = await api.recoverArchive(input);
  assert.equal(restored.files.length, 3);
  assert.equal(restored.currentSignedGrantAtPinnedHeadVerified, true);
  assert.equal(restored.historicalOwnerContinuityVerified, true);
  assert.equal(restored.allOwnerSignedRootsVerified, true);
  for (const item of restored.files) item.data.fill(0);
  assert.equal(f.sealed.archive.ownerRevision, 7, "historical sealed ciphertext never rewritten");
});

test("historic recovery fails closed on stale/revoked grant, fork, missing roots, reused outsider history or rollback", async () => {
  const { f, input, historicalRecovery, laterHead, laterHistory } = await laterOwnerHeadFixture();
  const forged = (patch) => ({ ...input, historicalRecovery: { ...historicalRecovery, ...patch } });
  for (const value of [
    { currentSignedDeviceGrant: f.options.signedDeviceGrant },
    { currentSignedDeviceGrant: f.signGrant({ ...f.signedDeviceGrant,
      manifest_revision: laterHead.revision, manifest_digest: b64(laterHead.digest),
      current_epoch: laterHead.epoch, revoked_at_epoch: laterHead.epoch }) },
    { currentSignedDeviceGrant: f.signGrant({ ...f.signedDeviceGrant,
      manifest_revision: laterHead.revision, manifest_digest: b64(laterHead.digest),
      current_epoch: laterHead.epoch, device_id: "unauthorized-new-device" }) },
    { signedOwnerHistoryChain: [laterHistory] },
    { signedOwnerHistoryChain: [f.ownerHistoryCheckpoint, {
      ...laterHistory, manifest_digest: b64(random(32)) }] },
    { signedOwnerHistoryChain: [f.ownerHistoryCheckpoint, laterHistory, laterHistory] },
    { currentOwnerRootCheckpoints: historicalRecovery.currentOwnerRootCheckpoints.slice(1) },
    { currentOwnerRootCheckpoints: historicalRecovery.currentOwnerRootCheckpoints.map((root, i) =>
      i === 2 ? { ...root, ciphertext_root: b64(random(32)) } : root) },
  ]) await assert.rejects(api.recoverArchive(forged(value)), failure);
  for (const changed of [
    { pinnedCurrentHead: { ...laterHead, revision: 7 } },
    { pinnedCurrentHead: { ...laterHead, digest: random(32) } },
    { pinnedCurrentHead: f.common.pinnedCurrentHead },
    { independentlyPinnedArchiveSha256: random(32) },
    { independentOwnerSpkiSha256: random(32) },
  ]) await assert.rejects(api.recoverArchive({ ...input, ...changed }), failure);
});

test("signed genesis through owner history sequence 3 stays valid, while wrong intermediate predecessor/future epoch cannot authorize", async () => {
  const { f, input, laterHead, historicalRecovery } = await laterOwnerHeadFixture();
  const seq1 = await ownerHistory.verifyOwnerCheckpoint({
    checkpoint: f.ownerHistoryCheckpoint, scope: f.common.scope,
    signerPublicKey: f.common.ownerPublicKey,
    signerKeyId: f.common.signerKeyId, previous: null });
  const intermediate = await ownerHistory.signOwnerCheckpoint({
    scope: f.common.scope, signerKey: f.options.ownerSigningKey,
    signerPublicKey: f.common.ownerPublicKey, signerKeyId: f.common.signerKeyId,
    deviceId: f.common.deviceId, revision: f.common.pinnedCurrentHead.revision,
    manifestDigest: f.common.pinnedCurrentHead.digest, issuedAt: 1699,
    previous: seq1 });
  const seq2 = await ownerHistory.verifyOwnerCheckpoint({ checkpoint: intermediate,
    scope: f.common.scope, signerPublicKey: f.common.ownerPublicKey,
    signerKeyId: f.common.signerKeyId, previous: seq1 });
  const latest = await ownerHistory.signOwnerCheckpoint({
    scope: f.common.scope, signerKey: f.options.ownerSigningKey,
    signerPublicKey: f.common.ownerPublicKey, signerKeyId: f.common.signerKeyId,
    deviceId: f.common.deviceId, revision: laterHead.revision,
    manifestDigest: laterHead.digest, issuedAt: 1702, previous: seq2 });
  const chain = [f.ownerHistoryCheckpoint, intermediate, latest];
  const restored = await api.recoverArchive({ ...input,
    historicalRecovery: { ...historicalRecovery, signedOwnerHistoryChain: chain } });
  assert.equal(restored.files.length, 3);
  for (const entry of restored.files) entry.data.fill(0);
  await assert.rejects(api.recoverArchive({ ...input,
    historicalRecovery: { ...historicalRecovery,
      signedOwnerHistoryChain: [chain[0], { ...chain[1],
        signature: b64(random(64)) }, chain[2]] } }), failure);
  await assert.rejects(api.recoverArchive({ ...input,
    pinnedCurrentHead: { ...laterHead, epoch: 3 },
    historicalRecovery: { ...historicalRecovery, signedOwnerHistoryChain: chain } }), failure);
});

test("hist recovery snapshots grants, complete chain and per-object endorsement before async verification", async () => {
  const { input } = await laterOwnerHeadFixture();
  const supplied = { ...input, historicalRecovery: {
    signedOwnerHistoryChain: input.historicalRecovery.signedOwnerHistoryChain.map((item) => ({ ...item })),
    currentSignedDeviceGrant: { ...input.historicalRecovery.currentSignedDeviceGrant },
    currentOwnerRootCheckpoints: input.historicalRecovery.currentOwnerRootCheckpoints.map((item) => ({ ...item })),
  } };
  const p = api.recoverArchive(supplied);
  supplied.historicalRecovery.currentSignedDeviceGrant.signature = b64(random(64));
  supplied.historicalRecovery.signedOwnerHistoryChain[1].manifest_digest = b64(random(32));
  supplied.historicalRecovery.currentOwnerRootCheckpoints[2].ciphertext_root = b64(random(32));
  const files = await p;
  assert.equal(files.files.length, 3);
  for (const file of files.files) file.data.fill(0);
});

test("browser UMD archive is available without Node globals", async () => {
  const context = vm.createContext({ crypto: crypto.webcrypto, TextEncoder,
    TextDecoder, btoa, atob, Uint8Array, ArrayBuffer });
  for (const script of ["rootark-zk1-file-content.js",
    "rootark-zk1-ciphertext-chunk-root.js", "rootark-zk1-portable-file-recovery.js",
    "rootark-zk1-owner-signed-checkpoint.js",
    "rootark-zk1-owner-ciphertext-root-checkpoint.js",
    "rootark-zk1-normal-browser-trust-floor.js",
    "rootark-zk1-keyring-portable-archive.js"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../public/client", script), "utf8"), context);
  }
  assert.equal(vm.runInContext("typeof RootarkZk1KeyringPortableArchive.createArchive", context), "function");
  assert.equal(vm.runInContext("typeof RootarkZk1KeyringPortableArchive.recoverArchive", context), "function");
  const f = await prepare();
  context.archiveJSON = JSON.stringify(f.sealed.archive);
  context.scopeJSON = JSON.stringify(f.common.scope);
  context.headRevision = f.common.pinnedCurrentHead.revision;
  context.headEpoch = f.common.pinnedCurrentHead.epoch;
  context.headDigest = f.common.pinnedCurrentHead.digest;
  context.heldSecret = f.common.recoverySecret;
  context.ownerVerifyKey = f.common.ownerPublicKey;
  context.ownerSpkiHash = f.common.independentOwnerSpkiSha256;
  context.offlineArchiveHash = f.sealed.archiveSha256;
  context.signerId = f.common.signerKeyId;
  context.deviceId = f.common.deviceId;
  const outcome = await vm.runInContext(`RootarkZk1KeyringPortableArchive.recoverArchive({
    archive: JSON.parse(archiveJSON), scope: JSON.parse(scopeJSON),
    recoverySecret: new Uint8Array(heldSecret),
    independentOwnerSpkiSha256: new Uint8Array(ownerSpkiHash),
    independentlyPinnedArchiveSha256: new Uint8Array(offlineArchiveHash),
    pinnedCurrentHead: { revision: headRevision,
      digest: new Uint8Array(headDigest), epoch: headEpoch },
    ownerPublicKey: ownerVerifyKey, signerKeyId: new Uint8Array(signerId),
    deviceId, previousOwnerHistoryProof: null,
  })`, context);
  assert.equal(outcome.files.length, 3);
  const restored = new Map(outcome.files.map((item) => [item.objectId,
    Buffer.from(item.data)]));
  for (const source of f.files) {
    assert.deepEqual(restored.get(source.metadata.object_id), source.data);
  }
  for (const item of outcome.files) item.data.fill(0);
  // The opt-in historical path must work through the browser UMD implementation,
  // not only CommonJS/Node's in-process owner checkpoint module.
  const later = await laterOwnerHeadFixture();
  context.historicalWire = JSON.stringify(later.input.archive);
  context.historicalAuthority = JSON.stringify(later.historicalRecovery);
  context.laterHead = later.laterHead;
  context.heldSecret = later.input.recoverySecret;
  context.ownerVerifyKey = later.input.ownerPublicKey;
  context.ownerSpkiHash = later.input.independentOwnerSpkiSha256;
  context.offlineArchiveHash = later.input.independentlyPinnedArchiveSha256;
  context.scopeJSON = JSON.stringify(later.input.scope);
  context.signerId = later.input.signerKeyId;
  context.deviceId = later.input.deviceId;
  const historicResult = await vm.runInContext(`RootarkZk1KeyringPortableArchive.recoverArchive({
    archive: JSON.parse(historicalWire), scope: JSON.parse(scopeJSON),
    recoverySecret: new Uint8Array(heldSecret),
    independentOwnerSpkiSha256: new Uint8Array(ownerSpkiHash),
    independentlyPinnedArchiveSha256: new Uint8Array(offlineArchiveHash),
    pinnedCurrentHead: { revision: laterHead.revision,
      digest: new Uint8Array(laterHead.digest), epoch: laterHead.epoch },
    ownerPublicKey: ownerVerifyKey, signerKeyId: new Uint8Array(signerId),
    deviceId, previousOwnerHistoryProof: null,
    historicalRecovery: JSON.parse(historicalAuthority)
  })`, context);
  assert.equal(historicResult.files.length, 3);
  assert.equal(historicResult.historicalOwnerContinuityVerified, true);
  for (const item of historicResult.files) item.data.fill(0);
});
