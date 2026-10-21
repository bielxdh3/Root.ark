"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const z = require("../src/crypto/rootark-zk-1");
const history = require("../src/crypto/rootark-zk-recovery-history-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { signZk1CiphertextDeviceApprovalV1 } =
  require("../src/crypto/rootark-zk-ciphertext-device-approval-v1");
const { Zk1ExperimentalPgApprovalReplayLedger } =
  require("../src/services/zk1ExperimentalPgApprovalReplayLedger");
const { inspectAndRecordExperimentalApproval } =
  require("../src/services/zk1ExperimentalApprovalCryptoReplay");

const url = process.env.ROOTARK_ZK1_REPLAY_WRITER_PG_URL;
const enabled = Boolean(url);
const rand = (n) => crypto.randomBytes(n);
const DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const deny = /ZK_CRYPTO_REPLAY_LAB_DENIED/;

async function context(t) {
  const pool = new Pool({ connectionString: url, max: 2, connectionTimeoutMillis: 3000 });
  t.after(async () => pool.end());
  const state = await fixtures.createInitialState(2);
  const signer = state.headManifest.devices[1];
  const signerPrivate = state.actors.get(Buffer.from(signer.authorization_key_id).toString("hex"));
  const verifiedPublicHistory = await history.verifyRecoveryHistoryPublicV2({
    expectedScope: state.scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: state.transitions, packageEnvelopes: [], now: 1100,
  });
  const currentSeconds = Math.floor(Date.now() / 1000);
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = rand(16);
  const witnessNonce = rand(32);
  const nonce = rand(32);
  const chunks = [rand(29), rand(107)];
  const expected = { scope: state.scope, objectId: rand(16).toString("base64url"),
    objectRevision: 7, expectedChunkCount: chunks.length,
    expectedRootHash: computeZk1CiphertextRoot(chunks), nonce };
  const approval = { type: "rootark-zk1-ciphertext-device-approval/v1",
    suite: "rootark-zk-1", ...state.scope,
    object_id: expected.objectId, object_revision: expected.objectRevision,
    manifest_revision: verifiedPublicHistory.revision,
    manifest_digest: Buffer.from(verifiedPublicHistory.headDigest),
    keyring_epoch: state.headManifest.current_epoch,
    expected_chunk_count: chunks.length, expected_root_hash: expected.expectedRootHash,
    device_id: signer.device_id,
    signer_key_id: Buffer.from(signer.authorization_key_id),
    nonce, issued_at: currentSeconds - 1, expires_at: currentSeconds + 120 };
  const witnessUnsigned = { type: "rootark-recovery-witness-head/v1",
    witness_key_id: witnessKeyId, ...state.scope,
    current_revision: verifiedPublicHistory.revision,
    current_manifest_digest: Buffer.from(verifiedPublicHistory.headDigest),
    witness_sequence: verifiedPublicHistory.revision,
    nonce: witnessNonce, observed_at: currentSeconds - 1,
    status: "committed", pending_reservation_id: null };
  const signApproval = (fields = approval, key = signerPrivate) =>
    signZk1CiphertextDeviceApprovalV1({ approval: fields, privateKey: key });
  const signWitness = async (fields = witnessUnsigned) => z.encodeDeterministic({
    ...fields, signature: crypto.sign(null, Buffer.concat([DOMAIN,
      await z.encodeDeterministic(fields)]), witnessKeys.privateKey) });
  const preflight = { rawApproval: await signApproval(), verifiedPublicHistory,
    rawWitnessHead: await signWitness(),
    witnessPinned: { keyId: witnessKeyId, publicKey: witnessKeys.publicKey },
    witnessNonce, minimumHead: { revision: verifiedPublicHistory.revision,
      digest: Buffer.from(verifiedPublicHistory.headDigest),
      witnessSequence: verifiedPublicHistory.revision },
    pinnedDevice: { deviceId: signer.device_id,
      signerKeyId: Buffer.from(signer.authorization_key_id),
      publicKey: crypto.createPublicKey(signerPrivate) },
    expected, nowSeconds: currentSeconds };
  return { pool, ledger: new Zk1ExperimentalPgApprovalReplayLedger({ pool }),
    preflight, signApproval, signWitness, signerPrivate, approval, signer,
    state, witnessUnsigned };
}

test("valid historical signed device approval + witness links before atomically recording a nonce", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const f = await context(t);
  const approved = await inspectAndRecordExperimentalApproval({ ledger: f.ledger,
    preflight: f.preflight });
  assert.deepEqual(approved, { historicalCryptographicLinkVerified: true,
    replayTombstoneCommitted: true, freshLiveAuthorityVerified: false,
    authorizesRelease: false, protectedIoAdmission: false });
  await assert.rejects(inspectAndRecordExperimentalApproval({ ledger: f.ledger,
    preflight: f.preflight }), deny,
  "exact valid signed candidate may only be consumed once even after a lost ACK");
});

test("wrong signer, altered signed object and mismatched witness prevent replay record", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const f = await context(t);
  const other = crypto.generateKeyPairSync("ed25519");
  const wrong = await f.signApproval(f.approval, other.privateKey);
  const mutated = await f.signApproval({ ...f.approval, object_id: rand(16).toString("base64url") });
  const wrongWitness = rand(32);
  for (const changed of [
    { rawApproval: wrong }, { rawApproval: mutated },
    { witnessNonce: wrongWitness },
    { expected: { ...f.preflight.expected, expectedRootHash: rand(32) } },
  ]) await assert.rejects(inspectAndRecordExperimentalApproval({ ledger: f.ledger,
    preflight: { ...f.preflight, ...changed } }), deny);
  // Invalid attempts must not consume the legitimate device challenge.
  assert.equal((await inspectAndRecordExperimentalApproval({ ledger: f.ledger,
    preflight: f.preflight })).replayTombstoneCommitted, true);
});

test("a correctly signed revoked device in a later signed manifest never reaches the replay ledger", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const f = await context(t);
  await fixtures.appendDeviceRevocation(f.state, f.signer.device_id);
  const latest = await history.verifyRecoveryHistoryPublicV2({
    expectedScope: f.state.scope, baseManifest: f.state.baseManifest,
    baseReceipt: f.state.baseReceipt, pinnedWitness: f.state.pinnedWitness,
    transitions: f.state.transitions, packageEnvelopes: [], now: 1100,
  });
  const revokedApproval = await f.signApproval({ ...f.approval,
    manifest_revision: latest.revision,
    manifest_digest: Buffer.from(latest.headDigest),
    keyring_epoch: f.state.headManifest.current_epoch });
  const updatedWitness = await f.signWitness({ ...f.witnessUnsigned,
    current_revision: latest.revision,
    current_manifest_digest: Buffer.from(latest.headDigest),
    witness_sequence: latest.revision });
  let called = 0;
  const original = f.ledger.consumeCandidate.bind(f.ledger);
  f.ledger.consumeCandidate = (...args) => { called++; return original(...args); };
  const changed = { ...f.preflight, verifiedPublicHistory: latest,
    rawApproval: revokedApproval, rawWitnessHead: updatedWitness,
    minimumHead: { revision: latest.revision,
      digest: Buffer.from(latest.headDigest), witnessSequence: latest.revision } };
  await assert.rejects(inspectAndRecordExperimentalApproval({ ledger: f.ledger,
    preflight: changed }), deny,
  "valid Ed25519 signature is insufficient when signed head marks signer revoked");
  assert.equal(called, 0, "no nonce ledger SQL effect may follow revoked proof");
});

test("mutable caller bytes cannot retarget signed context after asynchronous verifier starts", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const f = await context(t);
  const input = { ...f.preflight,
    rawApproval: Buffer.from(f.preflight.rawApproval),
    expected: { ...f.preflight.expected, nonce: Buffer.from(f.preflight.expected.nonce) } };
  const pending = inspectAndRecordExperimentalApproval({ ledger: f.ledger, preflight: input });
  input.rawApproval.fill(0);
  input.expected.nonce.fill(0);
  assert.equal((await pending).replayTombstoneCommitted, true,
    "the committed nonce and approval must be snapshotted before first await");
  await assert.rejects(inspectAndRecordExperimentalApproval({ ledger: f.ledger,
    preflight: f.preflight }), deny, "original nonce, not mutated bytes, was committed");
});
