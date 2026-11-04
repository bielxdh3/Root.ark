"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
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
const { inspectAndRecordExperimentalOnlineApproval } =
  require("../src/services/zk1ExperimentalApprovalCryptoReplay");
const { createZk1WitnessHttpsServer } =
  require("../src/services/zk1WitnessHttpsServer");

const url = process.env.ROOTARK_ZK1_REPLAY_WRITER_PG_URL;
const enabled = Boolean(url);
const rand = (n) => crypto.randomBytes(n);
const DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const deny = /ZK_CRYPTO_REPLAY_LAB_DENIED/;

function labTlsCertificates(dir) {
  const commands = [
    "set -eu",
    'openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=ZK replay disposable CA" -days 1 >/dev/null 2>&1',
    'openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" >/dev/null 2>&1',
    'printf "subjectAltName=DNS:localhost,IP:127.0.0.1\\nextendedKeyUsage=serverAuth\\n" > server.ext',
    'openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 1 -extfile server.ext >/dev/null 2>&1',
    'openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=replay-fixture" >/dev/null 2>&1',
    'printf "extendedKeyUsage=clientAuth\\n" > client.ext',
    'openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 1 -extfile client.ext >/dev/null 2>&1',
  ].join("\n");
  if (process.platform === "win32") {
    generateNativeFixtureCertificates(dir, {
      caSubject: "ZK replay disposable CA", servers: ["server"], clients: ["client"],
    });
  } else {
    execFileSync("bash", ["-lc", commands], { cwd: dir, timeout: 20000 });
  }
  return Object.fromEntries(["ca.pem", "server.key", "server.pem", "client.key", "client.pem"]
    .map((filename) => [filename, fs.readFileSync(path.join(dir, filename))]));
}

async function onlineWitness(t, f) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-replay-tls-"));
  const certs = labTlsCertificates(dir);
  let mode = "committed";
  const challenges = new Set();
  const required = ["reserve", "resolve", "prepareQuiesce", "cancelExpiredQuiesce",
    "beginIoAdmission", "finishIoAdmission"];
  const ledger = Object.fromEntries(required.map((name) => [name, () => {
    throw new Error("DISPOSABLE_HEAD_ONLY");
  }]));
  ledger.freshHead = async ({ nonce }) => {
    if (mode === "unavailable") throw new Error("ISOLATED_WITNESS_UNAVAILABLE");
    const hex = Buffer.from(nonce).toString("hex");
    if (challenges.has(hex)) throw new Error("CHALLENGE_REUSED");
    challenges.add(hex);
    if (mode === "delayed_sign") {
      await new Promise((resolve) => setTimeout(resolve, 1150));
    }
    return f.signWitness({
    ...f.witnessUnsigned, nonce: mode === "wrong_nonce" ? rand(32) : nonce,
    observed_at: mode === "stale" ? Math.floor(Date.now() / 1000) - 100
      : mode === "delayed_sign" ? Math.floor(Date.now() / 1000)
        : f.witnessUnsigned.observed_at,
    status: mode === "pending" ? "pending" : "committed",
    pending_reservation_id: mode === "pending" ? rand(16) : null,
    current_manifest_digest: mode === "pending" ? null
      : mode === "wrong_digest" ? rand(32) : f.witnessUnsigned.current_manifest_digest,
    current_revision: mode === "pending" ? null : f.witnessUnsigned.current_revision,
    });
  };
  const fingerprint = new crypto.X509Certificate(certs["client.pem"]).fingerprint256;
  const grantScope = Object.fromEntries(Object.entries(f.preflight.expected.scope)
    .map(([name, bytes]) => [name, Buffer.from(bytes).toString("base64url")]));
  const server = createZk1WitnessHttpsServer({
    key: certs["server.key"], cert: certs["server.pem"], clientCa: certs["ca.pem"],
    ledger, principals: { [fingerprint]: { roles: ["head"], scopes: [grantScope] } },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const witnessTls = { endpoint: "https://localhost:" + server.address().port,
    ca: certs["ca.pem"], clientKey: certs["client.key"],
    clientCert: certs["client.pem"],
    serverFingerprint256: new crypto.X509Certificate(certs["server.pem"]).fingerprint256 };
  return { witnessTls, setMode: (value) => { mode = value; }, challenges };
}

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
  const changed = { ...f.preflight, verifiedPublicHistory: latest,
    rawApproval: revokedApproval, rawWitnessHead: updatedWitness,
    minimumHead: { revision: latest.revision,
      digest: Buffer.from(latest.headDigest), witnessSequence: latest.revision } };
  await assert.rejects(inspectAndRecordExperimentalApproval({ ledger: f.ledger,
    preflight: changed }), deny,
  "valid Ed25519 signature is insufficient when signed head marks signer revoked");
  assert.equal((await inspectAndRecordExperimentalApproval({
    ledger: f.ledger, preflight: f.preflight,
  })).replayTombstoneCommitted, true,
  "failed revoked signer proof cannot burn the nonce: original valid candidate must still COMMIT");
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

test("a forged prototype/overridden replay ledger cannot claim a PostgreSQL COMMIT", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const f = await context(t);
  const forged = Object.create(Zk1ExperimentalPgApprovalReplayLedger.prototype);
  forged.consumeCandidate = async () => ({ replayRecordCommitted: true,
    authorizesRelease: false });
  await assert.rejects(inspectAndRecordExperimentalApproval({
    ledger: forged, preflight: f.preflight,
  }), deny);
  f.ledger.consumeCandidate = forged.consumeCandidate;
  await assert.rejects(inspectAndRecordExperimentalApproval({
    ledger: f.ledger, preflight: f.preflight,
  }), deny, "injected override cannot claim a durable tombstone");
  delete f.ledger.consumeCandidate;
  assert.equal((await inspectAndRecordExperimentalApproval({
    ledger: f.ledger, preflight: f.preflight,
  })).replayTombstoneCommitted, true, "only genuine SQL commit consumes nonce");
});

test("new live mTLS witness challenge is signed, pinned and nonce-bound before replay COMMIT", {
  skip: !enabled && "requires disposable PostgreSQL fixture",
}, async (t) => {
  const f = await context(t);
  const remote = await onlineWitness(t, f);
  const { rawWitnessHead: _historical, witnessNonce: _priorNonce,
    ...preflight } = f.preflight;
  await assert.rejects(inspectAndRecordExperimentalOnlineApproval({
    ledger: f.ledger, preflight,
    witnessTls: { ...remote.witnessTls,
      serverFingerprint256: "00:".repeat(31) + "00" },
  }), deny, "TLS pin failure must never consume an approval nonce");
  remote.setMode("pending");
  for (const mode of ["pending", "wrong_nonce", "wrong_digest", "stale", "unavailable"]) {
    remote.setMode(mode);
    await assert.rejects(inspectAndRecordExperimentalOnlineApproval({
      ledger: f.ledger, preflight, witnessTls: remote.witnessTls,
    }), deny, mode + " witness must not reach replay SQL");
  }
  remote.setMode("delayed_sign");
  const snapshotted = { ...preflight,
    rawApproval: Buffer.from(preflight.rawApproval),
    expected: { ...preflight.expected, nonce: Buffer.from(preflight.expected.nonce) } };
  const pending = inspectAndRecordExperimentalOnlineApproval({
    ledger: f.ledger, preflight: snapshotted, witnessTls: remote.witnessTls,
  });
  snapshotted.rawApproval.fill(0);
  snapshotted.expected.nonce.fill(0);
  const result = await pending;
  assert.deepEqual(result, { historicalCryptographicLinkVerified: true,
    replayTombstoneCommitted: true, freshLiveAuthorityVerified: false,
    authorizesRelease: false, protectedIoAdmission: false });
  remote.setMode("committed");
  await assert.rejects(inspectAndRecordExperimentalOnlineApproval({
    ledger: f.ledger, preflight, witnessTls: remote.witnessTls,
  }), deny, "repeated approval cannot replay using a different head challenge");
  assert.equal(remote.challenges.size, 6, "each reached mTLS request has a distinct random challenge");
});
