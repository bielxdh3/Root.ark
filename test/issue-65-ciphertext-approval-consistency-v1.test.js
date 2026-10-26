"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const manifestV2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const historyV2 = require("../src/crypto/rootark-zk-recovery-history-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { signZk1CiphertextDeviceApprovalV1 } = require("../src/crypto/rootark-zk-ciphertext-device-approval-v1");
const { inspectZk1CiphertextApprovalConsistencyV1 } = require("../src/crypto/rootark-zk-ciphertext-approval-consistency-v1");

const random = (length) => crypto.randomBytes(length);
const WITNESS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const invalid = /ZK_CIPHERTEXT_APPROVAL_CONSISTENCY_INVALID/;

async function makeFixture() {
  const state = await fixtures.createInitialState(2);
  const head = state.verifiedHistory.headManifest;
  const signer = head.devices[1];
  const deviceKeys = {
    deviceId: signer.device_id,
    signerKeyId: Buffer.from(signer.authorization_key_id),
    publicKey: crypto.createPublicKey({ key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"), signer.authorization_public_key,
    ]), format: "der", type: "spki" }),
  };
  const digest = await manifestV2.recoveryManifestDigestV2(head);
  const nonce = random(32);
  const expected = {
    scope: state.scope, objectId: random(16).toString("base64url"), objectRevision: 2,
    manifestRevision: head.revision, manifestDigest: digest,
    keyringEpoch: head.current_epoch, expectedChunkCount: 3,
    expectedRootHash: random(32), nonce,
  };
  const approval = {
    type: "rootark-zk1-ciphertext-device-approval/v1", suite: "rootark-zk-1",
    ...state.scope, object_id: expected.objectId, object_revision: expected.objectRevision,
    manifest_revision: expected.manifestRevision, manifest_digest: digest,
    keyring_epoch: expected.keyringEpoch, expected_chunk_count: expected.expectedChunkCount,
    expected_root_hash: expected.expectedRootHash,
    device_id: signer.device_id, signer_key_id: signer.authorization_key_id,
    nonce, issued_at: 1000, expires_at: 1100,
  };
  const privateKey = state.actors.get(Buffer.from(signer.authorization_key_id).toString("hex"));
  const raw = await signZk1CiphertextDeviceApprovalV1({ approval, privateKey });
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = random(16);
  const witnessUnsigned = {
    type: "rootark-recovery-witness-head/v1", witness_key_id: witnessKeyId,
    ...state.scope, current_revision: head.revision, current_manifest_digest: digest,
    witness_sequence: head.revision, nonce, observed_at: 1100,
    status: "committed", pending_reservation_id: null,
  };
  async function encodeWitness(unsigned = witnessUnsigned, signingKey = witnessKeys.privateKey) {
    return z.encodeDeterministic({ ...unsigned, signature: crypto.sign(null,
      Buffer.concat([WITNESS_DOMAIN, await z.encodeDeterministic(unsigned)]), signingKey) });
  }
  const witness = {
    raw: await encodeWitness(),
    pinned: { keyId: witnessKeyId, publicKey: witnessKeys.publicKey },
    nonce, minimumHead: { revision: head.revision, witnessSequence: head.revision, digest },
  };
  return { state, deviceKeys, raw, expected, witness, encodeWitness, witnessUnsigned,
    input: { raw, expected, nowSeconds: 1010, verifiedHistory: state.verifiedHistory,
      pinnedDevice: deviceKeys, witness } };
}

test("verified history, exact device row and signed witness tuple are consistent without publication authority", async () => {
  const f = await makeFixture();
  const first = await inspectZk1CiphertextApprovalConsistencyV1(f.input);
  assert.deepEqual(first, {
    signatureVerified: true, manifestHistoryVerified: true, deviceRecordConsistent: true,
    witnessSignatureVerified: true, manifestWitnessTupleConsistent: true,
    liveFreshnessVerified: false, nonceConsumed: false,
    authorizesPublish: false, authorizesRecovery: false,
  });
  assert.deepEqual(await inspectZk1CiphertextApprovalConsistencyV1(f.input), first,
    "replay must remain non-authorizing and never consume a nonce");
});

test("rejects device key substitution, mismatching scope, epoch, object commitment and nonce", async () => {
  const f = await makeFixture();
  const foreign = crypto.generateKeyPairSync("ed25519");
  const changes = [
    { pinnedDevice: { ...f.deviceKeys, publicKey: foreign.publicKey } },
    { pinnedDevice: { ...f.deviceKeys, signerKeyId: random(16) } },
    { expected: { ...f.expected, scope: { ...f.expected.scope, account_id: random(16) } } },
    { expected: { ...f.expected, keyringEpoch: f.expected.keyringEpoch + 1 } },
    { expected: { ...f.expected, objectId: random(16).toString("base64url") } },
    { expected: { ...f.expected, objectRevision: f.expected.objectRevision + 1 } },
    { expected: { ...f.expected, expectedRootHash: random(32) } },
    { expected: { ...f.expected, nonce: random(32) } },
    { witness: { ...f.witness, nonce: random(32) } },
  ];
  for (const change of changes) {
    await assert.rejects(inspectZk1CiphertextApprovalConsistencyV1({ ...f.input, ...change }), invalid);
  }
});

test("rejects revoked signer, stale manifest revision and mismatched or uncommitted witness", async () => {
  const f = await makeFixture();
  await fixtures.appendDeviceRevocation(f.state, "trusted-1");
  const revokedManifest = f.state.verifiedHistory.headManifest;
  const revokedDigest = await manifestV2.recoveryManifestDigestV2(revokedManifest);
  const decoded = await z.decodeDeterministic(f.raw);
  const { signature: _oldSignature, ...unsigned } = decoded;
  const devicePrivateKey = f.state.actors.get(Buffer.from(f.deviceKeys.signerKeyId).toString("hex"));
  const revokedRaw = await signZk1CiphertextDeviceApprovalV1({
    approval: { ...unsigned, manifest_revision: revokedManifest.revision,
      manifest_digest: revokedDigest, keyring_epoch: revokedManifest.current_epoch },
    privateKey: devicePrivateKey,
  });
  const revokedHeadWire = await f.encodeWitness({ ...f.witnessUnsigned,
    current_revision: revokedManifest.revision,
    current_manifest_digest: revokedDigest,
    witness_sequence: revokedManifest.revision,
  });
  // Every signature and manifest/witness tuple is correct. Only the current
  // signed v2 manifest's revoked_at_epoch must cause rejection.
  await assert.rejects(inspectZk1CiphertextApprovalConsistencyV1({
    ...f.input, raw: revokedRaw,
    verifiedHistory: f.state.verifiedHistory,
    expected: { ...f.expected, manifestRevision: revokedManifest.revision,
      manifestDigest: revokedDigest, keyringEpoch: revokedManifest.current_epoch },
    witness: { ...f.witness, raw: revokedHeadWire,
      minimumHead: { revision: revokedManifest.revision,
        witnessSequence: revokedManifest.revision, digest: revokedDigest } },
  }), invalid, "revoked device must fail even with valid signatures and fresh matching signed tuple");
  await assert.rejects(inspectZk1CiphertextApprovalConsistencyV1({
    ...f.input, verifiedHistory: f.state.verifiedHistory,
  }), invalid);
  const wrongRevision = { ...f.witnessUnsigned, current_revision: f.witnessUnsigned.current_revision + 1,
    witness_sequence: f.witnessUnsigned.witness_sequence + 1 };
  await assert.rejects(inspectZk1CiphertextApprovalConsistencyV1({ ...f.input,
    witness: { ...f.witness, raw: await f.encodeWitness(wrongRevision),
      minimumHead: { ...f.witness.minimumHead, revision: wrongRevision.current_revision,
        witnessSequence: wrongRevision.witness_sequence } },
  }), invalid);
  const mismatchedDigest = { ...f.witnessUnsigned, current_manifest_digest: random(32) };
  await assert.rejects(inspectZk1CiphertextApprovalConsistencyV1({ ...f.input,
    witness: { ...f.witness, raw: await f.encodeWitness(mismatchedDigest),
      minimumHead: { ...f.witness.minimumHead, digest: mismatchedDigest.current_manifest_digest } },
  }), invalid);
  const pending = { ...f.witnessUnsigned, status: "pending", pending_reservation_id: random(16) };
  await assert.rejects(inspectZk1CiphertextApprovalConsistencyV1({ ...f.input,
    witness: { ...f.witness, raw: await f.encodeWitness(pending) },
  }), invalid);
});

test("rejects unverified, mutable or caller-asserted authority and snapshots inputs before asynchronous decoding", async () => {
  const f = await makeFixture();
  await assert.rejects(inspectZk1CiphertextApprovalConsistencyV1({ ...f.input,
    verifiedHistory: { ...f.state.verifiedHistory, authorizationVerified: true } }), invalid);
  await assert.rejects(inspectZk1CiphertextApprovalConsistencyV1({ ...f.input,
    deviceActive: true }), invalid);
  const now = { ...f.input, raw: Buffer.from(f.raw), expected: structuredClone(f.expected),
    witness: { ...f.witness, raw: Buffer.from(f.witness.raw),
      pinned: { ...f.witness.pinned, keyId: Buffer.from(f.witness.pinned.keyId) } } };
  const pending = inspectZk1CiphertextApprovalConsistencyV1(now);
  now.raw.fill(0);
  now.expected.expectedRootHash.fill(0);
  now.witness.raw.fill(0);
  now.witness.pinned.keyId.fill(0);
  assert.equal((await pending).authorizesPublish, false);
  const historical = f.state.verifiedHistory;
  const restored = Buffer.from(historical.headManifest.devices[1].authorization_public_key);
  historical.headManifest.devices[1].authorization_public_key.fill(0);
  await assert.rejects(inspectZk1CiphertextApprovalConsistencyV1(f.input), invalid);
  restored.copy(historical.headManifest.devices[1].authorization_public_key);
  assert.equal(await historyV2.isVerifiedTrustedDeviceRecoveryHistoryV2(historical), true);
});
