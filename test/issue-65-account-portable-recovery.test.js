"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const api = require("../public/client/rootark-zk1-account-portable-recovery");
const keyringApi = require("../public/client/rootark-zk1-keyring-portable-archive");
const portable = require("../public/client/rootark-zk1-portable-file-recovery");
const ownerHistory = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const ownerRoots = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");

const b64 = (raw) => Buffer.from(raw).toString("base64url");
const random = (n) => crypto.randomBytes(n);
const failure = /ZK_ACCOUNT_PORTABLE_RECOVERY_DENIED/;
const grantFields = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key",
  "manifest_revision", "manifest_digest", "current_epoch", "enrolled_epoch",
  "revoked_at_epoch"];
const grantDomain = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const accountDomain = Buffer.from("Root.ark/zk-1/account-portable-recovery/v1\0");

async function fixture(count = 3) {
  const keys = crypto.generateKeyPairSync("ed25519");
  const subtle = crypto.webcrypto.subtle;
  const ownerSigningKey = await subtle.importKey("pkcs8",
    keys.privateKey.export({ format: "der", type: "pkcs8" }), "Ed25519", false, ["sign"]);
  const ownerPublicKey = await subtle.importKey("spki",
    keys.publicKey.export({ format: "der", type: "spki" }), "Ed25519", true, ["verify"]);
  const independentOwnerSpkiSha256 = crypto.createHash("sha256")
    .update(keys.publicKey.export({ format: "der", type: "spki" })).digest();
  const accountId = b64(random(16));
  const keyringOptions = [];
  const recoverOptions = [];
  for (let i = 0; i < count; i++) {
    const scope = { account_id: accountId, compartment_id: b64(Buffer.from([i + 1])),
      keyring_id: b64(random(16)) };
    const pinnedCurrentHead = { revision: 10 + i, digest: random(32), epoch: 4 + i };
    const signerKeyId = random(16);
    const deviceId = "owner-device";
    const signedDeviceGrant = { schema: "rootark-zk1-browser-owner-device-grant/v1",
      ...scope, device_id: deviceId, authorization_key_id: b64(random(16)),
      authorization_public_key: b64(random(32)),
      manifest_revision: pinnedCurrentHead.revision,
      manifest_digest: b64(pinnedCurrentHead.digest),
      current_epoch: pinnedCurrentHead.epoch, enrolled_epoch: 1,
      revoked_at_epoch: null };
    const grantMessage = Buffer.concat([grantDomain, Buffer.from(JSON.stringify(
      Object.fromEntries(grantFields.map((field) => [field, signedDeviceGrant[field]]))))]);
    signedDeviceGrant.signature = b64(crypto.sign(null, grantMessage, keys.privateKey));
    const ownerHistoryCheckpoint = await ownerHistory.signOwnerCheckpoint({
      scope, signerKey: ownerSigningKey, signerPublicKey: ownerPublicKey,
      signerKeyId, deviceId, revision: pinnedCurrentHead.revision,
      manifestDigest: pinnedCurrentHead.digest, issuedAt: 1600 + i, previous: null });
    const recoverySecret = portable.generateRecoverySecret();
    const files = [{ metadata: { ...scope, object_id: b64(random(16)),
      version_id: b64(random(16)), parent_version_id: null, epoch: 1, kind: "file" },
    objectRevision: 1, name: `compartment-${i}.txt`,
    mediaType: "text/plain", data: Buffer.from(`secret file ${i}`) }];
    keyringOptions.push({ scope, recoverySecret, ownerSigningKey, ownerPublicKey,
      independentOwnerSpkiSha256, pinnedCurrentHead, files,
      ownerHistoryCheckpoint, previousOwnerHistoryProof: null,
      signedDeviceGrant, signerKeyId, deviceId, issuedAt: 1700 + i });
    recoverOptions.push({ scope, recoverySecret, ownerPublicKey,
      independentOwnerSpkiSha256, pinnedCurrentHead, signerKeyId,
      deviceId, previousOwnerHistoryProof: null });
  }
  const creation = { accountId, ownerSigningKey, ownerPublicKey,
    independentOwnerSpkiSha256, keyrings: [...keyringOptions].reverse() };
  return { ...creation, create: creation, keys, keyringOptions, recoverOptions,
    recovery: (sealed) => ({ accountArchive: sealed.archive, accountId,
      independentlyPinnedAccountSha256: sealed.archiveSha256,
      ownerPublicKey, independentOwnerSpkiSha256, keyrings: recoverOptions }) };
}

function signAltered(f, mutate) {
  const accountArchive = JSON.parse(JSON.stringify(f.sealed.archive));
  mutate(accountArchive);
  const canonical = { format: accountArchive.format, accountId: accountArchive.accountId,
    keyrings: accountArchive.keyrings };
  accountArchive.signature = b64(crypto.sign(null, Buffer.concat([
    accountDomain, Buffer.from(JSON.stringify(canonical))]), f.keys.privateKey));
  const independentlyPinnedAccountSha256 = crypto.createHash("sha256")
    .update(JSON.stringify(accountArchive)).digest();
  return { ...f.recovery(f.sealed), accountArchive, independentlyPinnedAccountSha256 };
}

test("owner signed account manifest atomically recovers independent keyrings under one offline pin", async () => {
  const f = await fixture();
  f.sealed = await api.createArchive(f.create);
  assert.equal(f.sealed.authorizesProductionRestore, false);
  assert.equal(f.sealed.archive.keyrings.length, 3);
  assert.ok(Object.isFrozen(f.sealed.archive.keyrings));
  assert.ok(Object.isFrozen(f.sealed.archive.keyrings[0].archive));
  assert.equal(f.sealed.archive.keyrings[0].scope.compartment_id, b64(Buffer.from([1])));
  assert.ok(JSON.stringify(f.sealed.archive).length < 16 * 1024 * 1024);
  const wire = JSON.stringify(f.sealed.archive);
  for (const ring of f.keyringOptions) {
    assert.ok(!wire.includes(ring.files[0].name));
    assert.ok(!wire.includes(ring.files[0].data.toString("utf8")));
    assert.ok(!wire.includes(b64(ring.recoverySecret)));
  }
  const restored = await api.recoverArchive(f.recovery(f.sealed));
  assert.equal(restored.allKeyringsVerified, true);
  assert.equal(restored.authorizesProductionRestore, false);
  assert.equal(restored.currentOnlineRevocationVerified, false);
  assert.equal(restored.keyrings.length, 3);
  for (let i = 0; i < 3; i++) {
    assert.equal(Buffer.from(restored.keyrings[i].files[0].data).toString(), `secret file ${i}`);
  }
  for (const ring of restored.keyrings) for (const file of ring.files) file.data.fill(0);
});

test("aggregate rollback, pins, owner identity, wrong keyring, current head and epoch fail closed", async () => {
  const f = await fixture();
  f.sealed = await api.createArchive(f.create);
  const correct = f.recovery(f.sealed);
  for (const changed of [
    { independentlyPinnedAccountSha256: random(32) },
    { independentOwnerSpkiSha256: random(32) },
    { accountId: b64(random(16)) },
    { keyrings: correct.keyrings.slice(0, 2) },
    { keyrings: [...correct.keyrings].reverse() },
    { keyrings: correct.keyrings.map((item, i) => i === 1
      ? { ...item, scope: { ...item.scope, keyring_id: b64(random(16)) } } : item) },
    { keyrings: correct.keyrings.map((item, i) => i === 1
      ? { ...item, pinnedCurrentHead: { ...item.pinnedCurrentHead,
        epoch: item.pinnedCurrentHead.epoch - 1 } } : item) },
    { keyrings: correct.keyrings.map((item, i) => i === 2
      ? { ...item, recoverySecret: random(32) } : item) },
    { keyrings: correct.keyrings.map((item, i) => i === 2
      ? { ...item, previousOwnerHistoryProof: { signedCheckpointVerified: true } } : item) },
  ]) await assert.rejects(api.recoverArchive({ ...correct, ...changed }), failure);
  const differentOwner = await fixture(1);
  await assert.rejects(api.recoverArchive({ ...correct,
    ownerPublicKey: differentOwner.ownerPublicKey }), failure);
  await assert.rejects(api.recoverArchive({ ...correct,
    accountArchive: { ...f.sealed.archive, signature: b64(random(64)) } }), failure);
});

test("owner signed aggregate with corrupted last keyring cannot release earlier plaintext", async () => {
  const f = await fixture();
  f.sealed = await api.createArchive(f.create);
  const malicious = signAltered(f, (aggregate) => {
    const last = aggregate.keyrings.at(-1);
    last.archive.ciphertextBase64 = last.archive.ciphertextBase64.slice(0, -2) + "AA";
    last.archiveSha256 = b64(crypto.createHash("sha256")
      .update(JSON.stringify(last.archive)).digest());
  });
  await assert.rejects(api.recoverArchive(malicious), failure);
});

test("duplicate keyring IDs, foreign account, unsigned edits, malformed order, limits reject", async () => {
  const f = await fixture(2);
  await assert.rejects(api.createArchive({ ...f.create, keyrings: [f.keyringOptions[0],
    f.keyringOptions[0]] }), failure);
  await assert.rejects(api.createArchive({ ...f.create, keyrings: [f.keyringOptions[0],
    { ...f.keyringOptions[1], scope: { ...f.keyringOptions[1].scope,
      account_id: b64(random(16)) } }] }), failure);
  await assert.rejects(api.createArchive({ ...f.create, keyrings: [] }), failure);
  await assert.rejects(api.createArchive({ ...f.create, keyrings: Array(9).fill(f.keyringOptions[0]) }), failure);
  f.sealed = await api.createArchive(f.create);
  const correct = f.recovery(f.sealed);
  const swapped = JSON.parse(JSON.stringify(f.sealed.archive));
  swapped.keyrings.reverse();
  await assert.rejects(api.recoverArchive({ ...correct, accountArchive: swapped }), failure);
  const huge = JSON.parse(JSON.stringify(f.sealed.archive));
  huge.keyrings[0].archive.ciphertextBase64 = "a".repeat(16 * 1024 * 1024);
  await assert.rejects(api.recoverArchive({ ...correct, accountArchive: huge }), failure);
  await assert.rejects(api.recoverArchive({ ...correct,
    accountArchive: { ...f.sealed.archive, extra: "unsigned" } }), failure);
  await assert.rejects(api.recoverArchive({ ...correct,
    accountArchive: { ...f.sealed.archive, keyrings: [
      f.sealed.archive.keyrings[0], f.sealed.archive.keyrings[0]] } }), failure);
});

test("browser UMD restores account without Node globals", async () => {
  const f = await fixture(2);
  f.sealed = await api.createArchive(f.create);
  const sandbox = vm.createContext({ crypto: crypto.webcrypto, TextEncoder, TextDecoder,
    atob, btoa, Uint8Array, ArrayBuffer });
  for (const file of ["rootark-zk1-file-content.js",
    "rootark-zk1-ciphertext-chunk-root.js", "rootark-zk1-portable-file-recovery.js",
    "rootark-zk1-owner-signed-checkpoint.js",
    "rootark-zk1-owner-ciphertext-root-checkpoint.js",
    "rootark-zk1-normal-browser-trust-floor.js",
    "rootark-zk1-keyring-portable-archive.js",
    "rootark-zk1-account-portable-recovery.js"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../public/client", file), "utf8"), sandbox);
  }
  sandbox.input = f.recovery(f.sealed);
  const restored = await vm.runInContext(`RootarkZk1AccountPortableRecovery.recoverArchive({
    ...input, accountArchive: JSON.parse(JSON.stringify(input.accountArchive)),
    keyrings: input.keyrings.map(ring => ({ ...ring, scope: { ...ring.scope },
      recoverySecret: new Uint8Array(ring.recoverySecret),
      independentOwnerSpkiSha256: new Uint8Array(ring.independentOwnerSpkiSha256),
      signerKeyId: new Uint8Array(ring.signerKeyId),
      pinnedCurrentHead: { ...ring.pinnedCurrentHead,
        digest: new Uint8Array(ring.pinnedCurrentHead.digest) } })),
    independentOwnerSpkiSha256: new Uint8Array(input.independentOwnerSpkiSha256),
    independentlyPinnedAccountSha256: new Uint8Array(input.independentlyPinnedAccountSha256)
  })`, sandbox);
  assert.equal(restored.keyrings.length, 2);
  for (const ring of restored.keyrings) for (const file of ring.files) file.data.fill(0);
});

test("concurrent caller mutations cannot substitute pinned heads or holder secrets after admission", async () => {
  const f = await fixture(2);
  f.sealed = await api.createArchive(f.create);
  const input = f.recovery(f.sealed);
  const ringCopies = input.keyrings.map((item) => ({ ...item,
    recoverySecret: Buffer.from(item.recoverySecret),
    signerKeyId: Buffer.from(item.signerKeyId),
    independentOwnerSpkiSha256: Buffer.from(item.independentOwnerSpkiSha256),
    pinnedCurrentHead: { ...item.pinnedCurrentHead,
      digest: Buffer.from(item.pinnedCurrentHead.digest) },
    scope: { ...item.scope } }));
  const promise = api.recoverArchive({ ...input, keyrings: ringCopies });
  ringCopies[1].recoverySecret.fill(0);
  ringCopies[1].pinnedCurrentHead.digest.fill(0);
  ringCopies[1].signerKeyId.fill(0);
  ringCopies[1].independentOwnerSpkiSha256.fill(0);
  ringCopies[1].scope.keyring_id = b64(random(16));
  const restored = await promise;
  assert.equal(restored.keyrings.length, 2);
  for (const ring of restored.keyrings) for (const file of ring.files) file.data.fill(0);
});

test("fresh import of the same owner public key is accepted; foreign signing authority is rejected", async () => {
  const f = await fixture(2);
  const freshKey = await crypto.webcrypto.subtle.importKey("spki",
    f.keys.publicKey.export({ type: "spki", format: "der" }),
    "Ed25519", true, ["verify"]);
  const refreshedOptions = f.create.keyrings.map((ring) => ({ ...ring,
    ownerPublicKey: freshKey }));
  f.sealed = await api.createArchive({ ...f.create, keyrings: refreshedOptions });
  const recovery = f.recovery(f.sealed);
  recovery.keyrings[0] = { ...recovery.keyrings[0], ownerPublicKey: freshKey };
  const opened = await api.recoverArchive(recovery);
  for (const ring of opened.keyrings) for (const file of ring.files) file.data.fill(0);
  const intruder = await fixture(1);
  await assert.rejects(api.createArchive({ ...f.create,
    keyrings: f.create.keyrings.map((ring, index) => index === 1
      ? { ...ring, ownerSigningKey: intruder.ownerSigningKey } : ring) }), failure);
});

test("coordinator zeroizes earlier plaintext when a later keyring fails", async () => {
  const f = await fixture(2);
  f.sealed = await api.createArchive(f.create);
  const firstPlaintext = new Uint8Array([21, 22, 23, 24]);
  let calls = 0;
  const ringModule = require.resolve("../public/client/rootark-zk1-keyring-portable-archive");
  const accountModule = require.resolve("../public/client/rootark-zk1-account-portable-recovery");
  const originalRing = require.cache[ringModule].exports;
  const originalAccount = require.cache[accountModule].exports;
  try {
    require.cache[ringModule].exports = {
      recoverArchive: async () => {
        if (++calls === 2) throw new Error("late keyring MAC failure");
        return { files: [{ data: firstPlaintext }] };
      },
    };
    delete require.cache[accountModule];
    const injected = require(accountModule);
    await assert.rejects(injected.recoverArchive(f.recovery(f.sealed)), failure);
  } finally {
    require.cache[ringModule].exports = originalRing;
    require.cache[accountModule].exports = originalAccount;
  }
  assert.equal(calls, 2);
  assert.deepEqual(Array.from(firstPlaintext), [0, 0, 0, 0]);
});

test("account coordinator preserves atomic multi-keyring restore when one archived keyring advances to signed newer head", async () => {
  const f = await fixture(2);
  const sealed = await api.createArchive(f.create);
  const accountRestore = f.recovery(sealed);
  const archived = sealed.archive.keyrings[1].archive;
  const old = f.keyringOptions[1];
  const oldRecovery = f.recoverOptions[1];
  const context = { format: archived.format, scope: archived.scope,
    ownerRevision: archived.ownerRevision, ownerDigest: archived.ownerDigest,
    ownerEpoch: archived.ownerEpoch, archiveId: archived.archiveId };
  const subtle = crypto.webcrypto.subtle;
  const base = await subtle.importKey("raw", old.recoverySecret, "HKDF", false,
    ["deriveKey"]);
  const info = Buffer.concat([Buffer.from("Root.ark/zk-1/keyring-archive-key/v1\0"),
    Buffer.from(JSON.stringify(context))]);
  const wrapped = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256",
    salt: Buffer.from(archived.salt, "base64url"), info }, base,
  { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const bytes = Buffer.from(await subtle.decrypt({ name: "AES-GCM",
    iv: Buffer.from(archived.nonce, "base64url"),
    additionalData: Buffer.from(JSON.stringify(context)), tagLength: 128 },
  wrapped, Buffer.from(archived.ciphertextBase64, "base64url")));
  const entries = JSON.parse(bytes.toString("utf8")).entries;
  bytes.fill(0);
  const prior = await ownerHistory.verifyOwnerCheckpoint({
    checkpoint: old.ownerHistoryCheckpoint, scope: old.scope,
    signerPublicKey: old.ownerPublicKey, signerKeyId: old.signerKeyId, previous: null });
  const currentHead = { revision: old.pinnedCurrentHead.revision + 1,
    digest: random(32), epoch: old.pinnedCurrentHead.epoch + 1 };
  const newest = await ownerHistory.signOwnerCheckpoint({ scope: old.scope,
    signerKey: old.ownerSigningKey, signerPublicKey: old.ownerPublicKey,
    signerKeyId: old.signerKeyId, deviceId: old.deviceId,
    revision: currentHead.revision, manifestDigest: currentHead.digest,
    issuedAt: 1800, previous: prior });
  const currentUnsignedGrant = { ...old.signedDeviceGrant,
    manifest_revision: currentHead.revision,
    manifest_digest: b64(currentHead.digest), current_epoch: currentHead.epoch };
  delete currentUnsignedGrant.signature;
  const grantMessage = Buffer.concat([grantDomain, Buffer.from(JSON.stringify(
    Object.fromEntries(grantFields.map((field) => [field, currentUnsignedGrant[field]]))))]);
  const currentSignedDeviceGrant = { ...currentUnsignedGrant,
    signature: b64(crypto.sign(null, grantMessage, f.keys.privateKey)) };
  const currentOwnerRootCheckpoints = await Promise.all(entries.map(({ bundle }) =>
    ownerRoots.signOwnerCiphertextRootCheckpoint({ scope: old.scope,
      signerKey: old.ownerSigningKey, signerKeyId: old.signerKeyId,
      deviceId: old.deviceId, manifestRevision: currentHead.revision,
      manifestDigest: currentHead.digest, manifestEpoch: currentHead.epoch,
      objectId: bundle.metadata.object_id, objectRevision: bundle.objectRevision,
      ciphertextEpoch: bundle.metadata.epoch,
      ciphertextRoot: Buffer.from(bundle.ciphertextRoot, "base64url"), issuedAt: 1801 })));
  const updatedSecond = { ...oldRecovery, pinnedCurrentHead: currentHead,
    historicalRecovery: { signedOwnerHistoryChain: [old.ownerHistoryCheckpoint, newest],
      currentSignedDeviceGrant, currentOwnerRootCheckpoints } };
  await assert.rejects(api.recoverArchive({ ...accountRestore,
    keyrings: [accountRestore.keyrings[0], { ...oldRecovery,
      pinnedCurrentHead: currentHead }] }), failure,
  "normal recovery still denies a changed head without explicit historical authority");
  const restored = await api.recoverArchive({ ...accountRestore,
    keyrings: [accountRestore.keyrings[0], updatedSecond] });
  assert.equal(restored.keyrings.length, 2);
  assert.equal(Buffer.from(restored.keyrings[1].files[0].data).toString(), "secret file 1");
  for (const ring of restored.keyrings) for (const file of ring.files) file.data.fill(0);
  await assert.rejects(api.recoverArchive({ ...accountRestore,
    keyrings: [accountRestore.keyrings[0], { ...updatedSecond,
      historicalRecovery: { ...updatedSecond.historicalRecovery,
        currentSignedDeviceGrant: old.signedDeviceGrant } }] }), failure,
  "old signed grant does not authorize the later head, even inside a valid account archive");
});

test("aggregate payload above 16 MiB is denied even when each keyring is individually valid", async () => {
  const f = await fixture(3);
  const oversized = f.keyringOptions.map((item) => ({ ...item,
    files: Array.from({ length: 3 }, (_, i) => ({ ...item.files[0],
      metadata: { ...item.files[0].metadata, object_id: b64(random(16)),
        version_id: b64(random(16)) }, objectRevision: i + 1,
      data: Buffer.alloc(1_000_000, 7) })) }));
  const single = await keyringApi.createArchive(oversized[0]);
  assert.equal(single.archive.format, "rootark-zk1-keyring-portable-archive/v1");
  await assert.rejects(api.createArchive({ ...f.create, keyrings: oversized }), failure);
});
