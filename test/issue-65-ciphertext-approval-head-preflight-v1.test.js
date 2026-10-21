"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const h = require("../src/crypto/rootark-zk-recovery-history-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { signZk1CiphertextDeviceApprovalV1 } =
  require("../src/crypto/rootark-zk-ciphertext-device-approval-v1");
const { inspectZk1CiphertextApprovalHeadPreflightV1 } =
  require("../src/crypto/rootark-zk-ciphertext-approval-head-preflight-v1");

const WITNESS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const rand = (n) => crypto.randomBytes(n);
const equalBytes = (a, b) => Buffer.from(a).equals(Buffer.from(b));

async function setup({ deviceCount = 2, deviceIndex = 1 } = {}) {
  const state = await fixtures.createInitialState(deviceCount);
  const signer = state.headManifest.devices[deviceIndex];
  const signerPrivate = state.actors.get(Buffer.from(signer.authorization_key_id).toString("hex"));
  const devicePublic = crypto.createPublicKey(signerPrivate);
  const verifiedPublicHistory = await h.verifyRecoveryHistoryPublicV2({
    expectedScope: state.scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: state.transitions, packageEnvelopes: [], now: 1100,
  });
  const witnessSigning = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = rand(16);
  const witnessNonce = rand(32);
  const nonce = rand(32);
  const chunkBytes = [rand(13), rand(97)];
  const objectId = rand(16).toString("base64url");
  const root = computeZk1CiphertextRoot(chunkBytes);
  const expected = { scope: state.scope, objectId, objectRevision: 3,
    expectedChunkCount: chunkBytes.length, expectedRootHash: root, nonce };
  const approval = { type: "rootark-zk1-ciphertext-device-approval/v1",
    suite: "rootark-zk-1", ...state.scope, object_id: objectId,
    object_revision: 3, manifest_revision: verifiedPublicHistory.revision,
    manifest_digest: Buffer.from(verifiedPublicHistory.headDigest),
    keyring_epoch: state.headManifest.current_epoch,
    expected_chunk_count: chunkBytes.length, expected_root_hash: Buffer.from(root),
    device_id: signer.device_id,
    signer_key_id: Buffer.from(signer.authorization_key_id),
    nonce, issued_at: 10000, expires_at: 10100 };
  const witnessUnsigned = { type: "rootark-recovery-witness-head/v1",
    witness_key_id: witnessKeyId, ...state.scope,
    current_revision: verifiedPublicHistory.revision,
    current_manifest_digest: Buffer.from(verifiedPublicHistory.headDigest),
    witness_sequence: verifiedPublicHistory.revision,
    nonce: witnessNonce, observed_at: 10000,
    status: "committed", pending_reservation_id: null };
  const pinnedDevice = { deviceId: signer.device_id,
    signerKeyId: Buffer.from(signer.authorization_key_id), publicKey: devicePublic };
  const witnessPinned = { keyId: witnessKeyId, publicKey: witnessSigning.publicKey };
  const minimumHead = { revision: verifiedPublicHistory.revision,
    digest: Buffer.from(verifiedPublicHistory.headDigest),
    witnessSequence: verifiedPublicHistory.revision };
  const signApproval = (fields = approval, privateKey = signerPrivate) =>
    signZk1CiphertextDeviceApprovalV1({ approval: fields, privateKey });
  const signWitness = async (fields = witnessUnsigned, privateKey = witnessSigning.privateKey) => {
    const signature = crypto.sign(null, Buffer.concat([WITNESS_DOMAIN,
      await z.encodeDeterministic(fields)]), privateKey);
    return z.encodeDeterministic({ ...fields, signature });
  };
  const input = { rawApproval: await signApproval(), verifiedPublicHistory,
    rawWitnessHead: await signWitness(), witnessPinned, witnessNonce,
    minimumHead, pinnedDevice, expected, nowSeconds: 10020 };
  return { state, signer, approval, witnessUnsigned, expected, chunkBytes,
    input, signApproval, signWitness, witnessSigning };
}
const inspect = (input) => inspectZk1CiphertextApprovalHeadPreflightV1(input);
const invalid = /ZK_CIPHERTEXT_APPROVAL_PREFLIGHT_UNAVAILABLE/;

test("signed manifest history + independently pinned witness + active listed signer matches exact ciphertext commitment, but never authorizes release", async () => {
  const f = await setup();
  assert.equal(await h.isVerifiedPublicRecoveryHistoryV2(f.input.verifiedPublicHistory), true);
  const result = await inspect(f.input);
  assert.deepEqual(result, { cryptographicLinkVerified: true,
    signerListedActiveInSignedHead: true, witnessHeadSignatureMatched: true,
    authorizesRelease: false, liveAuthorityVerified: false, nonceConsumed: false });
  assert.equal(Object.isFrozen(result), true);
});

test("manifest device revocation, old head and mismatched device identity all fail even with valid signatures", async () => {
  const f = await setup();
  await fixtures.appendDeviceRevocation(f.state, f.signer.device_id);
  const old = f.input.verifiedPublicHistory;
  const fresh = await h.verifyRecoveryHistoryPublicV2({ expectedScope: f.state.scope,
    baseManifest: f.state.baseManifest, baseReceipt: f.state.baseReceipt,
    pinnedWitness: f.state.pinnedWitness, transitions: f.state.transitions,
    packageEnvelopes: [] });
  const current = { ...f.input, verifiedPublicHistory: fresh,
    minimumHead: { revision: fresh.revision, digest: Buffer.from(fresh.headDigest),
      witnessSequence: fresh.revision },
    rawWitnessHead: await f.signWitness({ ...f.witnessUnsigned,
      current_revision: fresh.revision, current_manifest_digest: Buffer.from(fresh.headDigest),
      witness_sequence: fresh.revision }) };
  await assert.rejects(inspect(current), invalid, "revoked signer cannot approve under latest head");
  const freshlySignedRevoked = await f.signApproval({ ...f.approval,
    manifest_revision: fresh.revision, manifest_digest: Buffer.from(fresh.headDigest),
    keyring_epoch: f.state.headManifest.current_epoch });
  await assert.rejects(inspect({ ...current, rawApproval: freshlySignedRevoked }), invalid,
    "even correctly re-signed current-epoch ciphertext is denied for a revoked signer");
  await assert.rejects(inspect({ ...f.input,
    minimumHead: current.minimumHead }), invalid,
  "signed old witness is below independently pinned high-water floor");
  assert.equal(old.headManifest.devices.some((x) =>
    x.device_id === f.signer.device_id && x.revoked_at_epoch === null), true);
  await assert.rejects(inspect({ ...f.input, pinnedDevice: {
    ...f.input.pinnedDevice, deviceId: "other-device" } }), invalid);
});

test("scope, key, epoch, revision, manifest digest, count, root and challenge substitutions fail with correctly re-signed approval", async () => {
  const f = await setup();
  const changes = [{ account_id: rand(16) }, { compartment_id: rand(5) },
    { keyring_id: rand(16) }, { device_id: "forged-active-device" },
    { signer_key_id: rand(16) }, { keyring_epoch: f.approval.keyring_epoch + 1 },
    { manifest_revision: f.approval.manifest_revision + 1 },
    { manifest_digest: rand(32) }, { object_revision: 4 },
    { object_id: rand(16).toString("base64url") },
    { expected_chunk_count: 3 }, { expected_root_hash: rand(32) },
    { nonce: rand(32) }];
  for (const changed of changes) {
    const rawApproval = await f.signApproval({ ...f.approval, ...changed });
    await assert.rejects(inspect({ ...f.input, rawApproval }), invalid, Object.keys(changed)[0]);
  }
  const wrongRoot = computeZk1CiphertextRoot([f.chunkBytes[1], f.chunkBytes[0]]);
  assert.equal(equalBytes(wrongRoot, f.expected.expectedRootHash), false);
  await assert.rejects(inspect({ ...f.input, expected: {
    ...f.expected, expectedRootHash: wrongRoot } }), invalid);
});

test("forged witness issuer, stale/future receipt, pending witness, forged history and client-supplied status are rejected", async () => {
  const f = await setup();
  const attacker = crypto.generateKeyPairSync("ed25519");
  await assert.rejects(inspect({ ...f.input,
    rawWitnessHead: await f.signWitness(f.witnessUnsigned, attacker.privateKey) }), invalid);
  await assert.rejects(inspect({ ...f.input, witnessPinned: {
    ...f.input.witnessPinned, publicKey: attacker.publicKey } }), invalid);
  await assert.rejects(inspect({ ...f.input,
    rawWitnessHead: await f.signWitness({ ...f.witnessUnsigned, status: "pending" }) }), invalid);
  await assert.rejects(inspect({ ...f.input,
    rawWitnessHead: await f.signWitness({ ...f.witnessUnsigned, observed_at: 9870 }) }), invalid);
  await assert.rejects(inspect({ ...f.input,
    rawWitnessHead: await f.signWitness({ ...f.witnessUnsigned, observed_at: 10040 }) }), invalid);
  await assert.rejects(inspect({ ...f.input,
    verifiedPublicHistory: { ...f.input.verifiedPublicHistory } }), invalid);
  await assert.rejects(inspect({ ...f.input, deviceIsActive: true }), invalid);
  await assert.rejects(inspect({ ...f.input, expected: {
    ...f.expected, deviceActive: true } }), invalid);
  await assert.rejects(inspect({ ...f.input, pinnedDevice: {
    ...f.input.pinnedDevice, publicKey: attacker.publicKey } }), invalid);
});

test("replay never consumes nonce; tampering caller byte buffers/public keys across await cannot change context", async () => {
  const f = await setup();
  const proof = await inspect(f.input);
  assert.equal((await inspect(f.input)).nonceConsumed, false);
  assert.equal(proof.authorizesRelease, false);
  const raw = Buffer.from(f.input.rawApproval);
  const witnessRaw = Buffer.from(f.input.rawWitnessHead);
  const expectedRoot = Buffer.from(f.input.expected.expectedRootHash);
  const id = Buffer.from(f.input.pinnedDevice.signerKeyId);
  const concurrent = inspect({ ...f.input, rawApproval: raw, rawWitnessHead: witnessRaw,
    expected: { ...f.expected, expectedRootHash: expectedRoot },
    pinnedDevice: { ...f.input.pinnedDevice, signerKeyId: id } });
  raw.fill(0); witnessRaw.fill(0); expectedRoot.fill(0); id.fill(0);
  assert.deepEqual(await concurrent, proof, "all mutable inputs must be snapshotted before awaiting");
  const f2 = await setup();
  const p = inspect(f2.input);
  f2.input.pinnedDevice.publicKey = crypto.generateKeyPairSync("ed25519").publicKey;
  f2.input.witnessPinned.publicKey = crypto.generateKeyPairSync("ed25519").publicKey;
  assert.deepEqual(await p, proof, "pinned key references must not be re-read after await");
});
