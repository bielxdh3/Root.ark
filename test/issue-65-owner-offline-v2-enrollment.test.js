"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const manifest = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const verify = require("../src/crypto/rootark-zk-recovery-history-v2");
const enrollment = require("../src/crypto/rootark-zk1-owner-offline-v2-enrollment");
const commitment = require("../src/crypto/rootark-zk1-offline-commitment-receipt");
const approval = require("../public/client/rootark-zk1-v2-device-approval");
const browserPop = require("../public/client/rootark-zk1-v2-browser-pop");
const committedApproval = require("../public/client/rootark-zk1-v2-committed-approval");
const normal = require("../public/client/rootark-zk1-normal-browser-content");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");

const b64 = (value) => Buffer.from(value).toString("base64url");
const pub = (key) => key.export({ format: "der", type: "spki" }).subarray(-32);
const newDeviceRequest = async () => {
  const hpke = await z.hpkeSuite().kem.generateKeyPair();
  const hpkePublicRaw = await z.hpkeSuite().kem.serializePublicKey(hpke.publicKey);
  const hpkePrivateRaw = await z.hpkeSuite().kem.serializePrivateKey(hpke.privateKey);
  const signer = crypto.generateKeyPairSync("ed25519");
  const hpkePrivateDer = Buffer.concat([
    Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(hpkePrivateRaw)]);
  const request = {
    schema: "rootark-zk1-device-enrollment-request/v1",
    device_id: "new-secure-browser-device",
    authorization_key_id: b64(crypto.randomBytes(16)),
    authorization_public_key: b64(pub(signer.publicKey)),
    hpke_key_id: b64(crypto.randomBytes(16)),
    hpke_public_key: b64(hpkePublicRaw),
    challenge: b64(crypto.randomBytes(32)),
    approval: "OWNER_MUST_VERIFY_IDENTITY_AND_FINISH_V2_POP_AND_SIGN_CURRENT_GRANT",
  };
  return { request, signer, hpkePrivateDer, hpkePrivateRaw };
};

test("owner offline ceremony: new device proves V2 HPKE+Ed25519; owner signs only after independently pinned committed head", async () => {
  const state = await fixtures.createInitialState(3);
  const owner = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const witnessSpki = b64(crypto.createHash("sha256").update(witness.publicKey.export({
    format: "der", type: "spki" })).digest());
  const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
    .map((name) => [name, b64(state.headManifest[name])]));
  const signReceipt = (fields, signer = witness.privateKey) => {
    const source = { schema: commitment.SCHEMA, status: "committed", ...scope,
      revision: null, digest: null, epoch: null, previous_revision: null,
      previous_digest: null, operation_id: null, pop_challenge_id: null,
      request_nonce: null, commit_nonce: null, sequence: null,
      previous_receipt_sha256: null, issued_at: null, expires_at: null,
      ...fields };
    const unsigned = Object.fromEntries(commitment.FIELDS.map((name) => [name, source[name]]));
    return { ...unsigned, signature: b64(crypto.sign(null,
      commitment.commitmentSigningBytes(unsigned), signer)) };
  };
  const receiptHash = (signed) => crypto.createHash("sha256").update(Buffer.concat([
    commitment.commitmentSigningBytes(Object.fromEntries(commitment.FIELDS.map(
      (name) => [name, signed[name]]))), Buffer.from(signed.signature, "base64url")])).digest();
  const ownerRaw = pub(owner.publicKey);
  const ownerSpki = crypto.createHash("sha256").update(
    owner.publicKey.export({ format: "der", type: "spki" })).digest();
  const former = state.headManifest;
  const externalCurrentHead = {
    revision: former.revision,
    digest: b64(await manifest.recoveryManifestDigestV2(former)),
    epoch: former.current_epoch,
  };
  const fresh = await newDeviceRequest();
  const now = Math.floor(Date.now() / 1000);
  const priorCommitment = signReceipt({ revision: former.revision,
    digest: externalCurrentHead.digest, epoch: former.current_epoch,
    sequence: 10, issued_at: now, expires_at: now + 600 });
  const prepared = await enrollment.beginOwnerEnrollment({
    request: fresh.request, verifiedHistory: state.verifiedHistory,
    externalCurrentHead, trustedOwnerPublicKey: owner.publicKey,
    independentOwnerSpkiSha256: b64(ownerSpki),
    trustedCommitmentSignerPublicKey: witness.publicKey,
    independentCommitmentSignerSpkiSha256: witnessSpki,
    trustedPriorCommitment: priorCommitment, nowSeconds: now,
  });
  const exportedChallenge = enrollment.exportBrowserChallenge(prepared);
  for (const [label, changes] of [
    ["wrong HPKE recipient", { deviceHpkePrivateDer: Buffer.concat([
      Buffer.from("302e020100300506032b656e04220420", "hex"), crypto.randomBytes(32)]) }],
    ["wrong signing key", { deviceAuthorizationPrivateDer: crypto.generateKeyPairSync("ed25519")
      .privateKey.export({ format: "der", type: "pkcs8" }) }],
    ["forged request target", { request: { ...fresh.request,
      hpke_public_key: b64(crypto.randomBytes(32)) } }],
    ["modified signed challenge", { challenge: { ...exportedChallenge,
      ciphertext: b64(crypto.randomBytes(48)) } }],
  ]) await assert.rejects(browserPop.respond({
    request: fresh.request, challenge: exportedChallenge,
    deviceHpkePrivateDer: fresh.hpkePrivateDer,
    deviceAuthorizationPrivateDer: fresh.signer.privateKey.export({
      format: "der", type: "pkcs8" }), nowSeconds: now, ...changes,
  }), /ZK_V2_BROWSER_POP_DENIED/, label);
  const answer = await browserPop.respond({
    request: fresh.request, challenge: exportedChallenge,
    deviceHpkePrivateDer: fresh.hpkePrivateDer,
    deviceAuthorizationPrivateDer: fresh.signer.privateKey.export({
      format: "der", type: "pkcs8" }), nowSeconds: now,
  });
  const actor = state.actors.get(Buffer.from(former.devices[0].authorization_key_id)
    .toString("hex"));
  const candidate = await enrollment.stageBrowserPopResponse({
    prepared, response: answer, trustedActorPrivateKey: actor, nowSeconds: now + 5,
  });
  assert.equal(candidate.manifest.operation.operation_type, "enroll-device");
  assert.equal(candidate.manifest.revision, former.revision + 1);
  assert.equal(candidate.manifest.devices.length, former.devices.length + 1);
  assert.equal(candidate.manifest.wraps.length, former.wraps.length + former.epochs.length);
  const recipient = await z.hpkeSuite().kem.deserializePrivateKey(fresh.hpkePrivateRaw);
  for (const epochEntry of former.epochs) {
    const envelope = candidate.manifest.wraps.find((entry) =>
      entry.device_id === fresh.request.device_id && entry.epoch === epochEntry.epoch);
    assert.ok(envelope, "new device must have authenticated wrapped key for each historical epoch");
    const context = { suite: "rootark-zk-1",
      account_id: former.account_id, compartment_id: former.compartment_id,
      purpose: "key-wrap", recipient_type: "device",
      recipient_id: fresh.request.device_id,
      recipient_key_id: Buffer.from(fresh.request.hpke_key_id, "base64url"),
      epoch: epochEntry.epoch, key_ref: epochEntry.key_ref, wrap_id: envelope.wrap_id };
    const encoded = await z.encodeDeterministic(context);
    const key = Buffer.from(await z.hpkeOpen({ recipientKey: recipient,
      enc: envelope.enc, ciphertext: envelope.ciphertext,
      info: Buffer.concat([Buffer.from("Root.ark/zk-1/keyring-wrap-info/v2\0"), encoded]),
      aad: Buffer.concat([Buffer.from("Root.ark/zk-1/keyring-wrap-aad/v2\0"), encoded]) }));
    assert.deepEqual(key, Buffer.from(state.epochKeys.find((entry) =>
      entry.epoch === epochEntry.epoch).key));
    key.fill(0);
  }
  await assert.rejects(enrollment.stageV2Enrollment({
    prepared, response: answer, trustedActorPrivateKey: actor, nowSeconds: now,
  }), /ZK_OWNER_OFFLINE_ENROLLMENT_DENIED/, "same POP session cannot enroll twice");
  const committed = {
    revision: candidate.manifest.revision,
    digest: b64(await manifest.recoveryManifestDigestV2(candidate.manifest)),
    epoch: candidate.manifest.current_epoch,
  };
  const signedCommittedHead = signReceipt({ revision: committed.revision,
    digest: committed.digest, epoch: committed.epoch,
    previous_revision: former.revision, previous_digest: externalCurrentHead.digest,
    operation_id: b64(candidate.manifest.operation.operation_id),
    pop_challenge_id: b64(candidate.manifest.operation.target_pop_proof.challenge_context.challenge_id),
    request_nonce: fresh.request.challenge, commit_nonce: prepared.commitmentNonce,
    sequence: 12, previous_receipt_sha256: b64(receiptHash(priorCommitment)),
    issued_at: now + 6, expires_at: now + 300 });
  const revokedReceipt = { ...signedCommittedHead, status: "revoked" };
  revokedReceipt.signature = b64(crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/offline-commitment-receipt/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(commitment.FIELDS.map(
      (name) => [name, revokedReceipt[name]]))))]), witness.privateKey));
  assert.equal(crypto.verify(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/offline-commitment-receipt/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(commitment.FIELDS.map(
      (name) => [name, revokedReceipt[name]]))))]), witness.publicKey,
  Buffer.from(revokedReceipt.signature, "base64url")), true,
  "revoked status must be denied even if the real independent witness signed it");
  await assert.rejects(enrollment.ownerApproveCommittedEnrollment({
    candidate, signedCommittedHead: { ...externalCurrentHead },
    ownerPrivateKey: owner.privateKey, nowSeconds: now + 9,
  }), /ZK_OWNER_OFFLINE_ENROLLMENT_DENIED/,
  "an unsigned self-reported head cannot authorize new device");
  const hostileReceipts = [
    { ...signedCommittedHead, digest: externalCurrentHead.digest },
    signReceipt({ ...signedCommittedHead, commit_nonce: b64(crypto.randomBytes(32)) }),
    signReceipt({ ...signedCommittedHead, request_nonce: b64(crypto.randomBytes(32)) }),
    signReceipt({ ...signedCommittedHead, pop_challenge_id: b64(crypto.randomBytes(16)) }),
    signReceipt({ ...signedCommittedHead, operation_id: b64(crypto.randomBytes(16)) }),
    signReceipt({ ...signedCommittedHead, previous_receipt_sha256: b64(crypto.randomBytes(32)) }),
    signReceipt({ ...signedCommittedHead, sequence: priorCommitment.sequence }),
    signReceipt({ ...signedCommittedHead, expires_at: now + 7 }),
    revokedReceipt,
    signReceipt({ ...signedCommittedHead }, crypto.generateKeyPairSync("ed25519").privateKey),
  ];
  for (const [index, hostileReceipt] of hostileReceipts.entries()) {
    await assert.rejects(enrollment.ownerApproveCommittedEnrollment({
      candidate, signedCommittedHead: hostileReceipt,
      ownerPrivateKey: owner.privateKey, nowSeconds: now + 9,
    }), /ZK_OWNER_OFFLINE_ENROLLMENT_DENIED/,
    `hostile commitment ${index} must fail closed`);
  }
  const issued = await enrollment.ownerApproveCommittedEnrollment({
    candidate, signedCommittedHead, ownerPrivateKey: owner.privateKey,
    nowSeconds: now + 9,
  });
  assert.equal(issued.noServerSecretExposure, true);
  assert.equal(issued.signedCommitmentVerified, true);
  assert.equal(issued.physicalDurabilityProven, false);
  assert.equal(issued.externalCustodyProven, false);
  await assert.rejects(enrollment.ownerApproveCommittedEnrollment({
    candidate, signedCommittedHead, ownerPrivateKey: owner.privateKey,
    nowSeconds: now + 9,
  }), /ZK_OWNER_OFFLINE_ENROLLMENT_DENIED/, "replay owner authorization blocked");
  assert.equal(issued.signedDeviceGrant.manifest_digest, committed.digest);
  assert.equal(issued.signedDeviceGrant.device_id, fresh.request.device_id);

  // A completely fresh client holds only its new Ed25519 private key,
  // externally retained owner identity/head, request and signed approval.
  const subtle = crypto.webcrypto.subtle;
  const ownerPublic = await subtle.importKey("raw", ownerRaw, "Ed25519", true, ["verify"]);
  const newPublic = await subtle.importKey("raw",
    pub(fresh.signer.publicKey), "Ed25519", true, ["verify"]);
  const newPrivate = await subtle.importKey("pkcs8",
    fresh.signer.privateKey.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  const credentials = {
    request: JSON.parse(JSON.stringify(fresh.request)),
    approval: JSON.parse(JSON.stringify(issued.approval)),
    signedDeviceGrant: JSON.parse(JSON.stringify(issued.signedDeviceGrant)),
    ownerPublicKey: ownerPublic,
    pinnedOwnerKeyHash: crypto.createHash("sha256").update(ownerRaw).digest(),
    independentOwnerSpkiSha256: ownerSpki,
    pinnedCurrentHead: {
      revision: committed.revision, digest: Buffer.from(committed.digest, "base64url"),
      epoch: committed.epoch,
    },
    devicePublicKey: newPublic, devicePrivateKey: newPrivate, nowSeconds: now + 9,
  };
  const report = await approval.verifyImportedApproval(credentials);
  assert.equal(report.verifiedOwnerOfflineApproval, true);
  assert.equal(report.v2TransitionProvenByBrowser, false);
  const witnessPublicKey = await subtle.importKey("raw", pub(witness.publicKey),
    "Ed25519", true, ["verify"]);
  const linked = {
    ...credentials,
    committedReceipt: signedCommittedHead,
    previousReceipt: priorCommitment,
    signedV2Manifest: issued.signedV2Manifest,
    witnessPublicKey,
    independentWitnessSpkiSha256: Buffer.from(witnessSpki, "base64url"),
    independentlyPinnedPreviousReceiptSha256: receiptHash(priorCommitment),
  };
  const liveProof = await committedApproval.verifyCommittedApproval(linked);
  assert.equal(liveProof.committedOwnerApprovalVerified, true);
  assert.equal(liveProof.previousReceiptHashPinned, true);
  assert.equal(liveProof.committedV2ManifestDigestMatched, true);
  assert.equal(liveProof.publicV2HistoryVerifiedByBrowser, false);
  assert.equal(liveProof.authorizesProductionIo, false);
  for (const [label, override] of [
    ["forged witness", { witnessPublicKey: await subtle.importKey("raw",
      pub(crypto.generateKeyPairSync("ed25519").publicKey), "Ed25519", true, ["verify"]) }],
    ["wrong witness SPKI pin", { independentWitnessSpkiSha256: crypto.randomBytes(32) }],
    ["self-pinned previous receipt", { independentlyPinnedPreviousReceiptSha256: crypto.randomBytes(32) }],
    ["fork witness head", { committedReceipt: { ...signedCommittedHead,
      digest: b64(crypto.randomBytes(32)) } }],
    ["replayed operation", { committedReceipt: { ...signedCommittedHead,
      operation_id: b64(crypto.randomBytes(16)) } }],
    ["revoked device", { signedDeviceGrant: { ...issued.signedDeviceGrant,
      revoked_at_epoch: committed.epoch } }],
    ["unrelated HPKE target", { request: { ...fresh.request,
      hpke_public_key: b64(crypto.randomBytes(32)) } }],
    ["unsigned witness", { committedReceipt: { ...signedCommittedHead,
      signature: b64(crypto.randomBytes(64)) } }],
    ["altered signed V2 bytes", { signedV2Manifest: b64(crypto.randomBytes(256)) }],
  ]) await assert.rejects(committedApproval.verifyCommittedApproval({
    ...linked, ...override,
  }), /ZK_V2_COMMITTED_APPROVAL_DENIED/, label);
  const active = await normal.verifyOwnerGrant({
    ownerPublicKey: ownerPublic, pinnedOwnerKeyHash: credentials.pinnedOwnerKeyHash,
    pinnedCurrentHead: credentials.pinnedCurrentHead,
    signedDeviceGrant: issued.signedDeviceGrant,
    devicePublicKey: newPublic, devicePrivateKey: newPrivate,
  });
  assert.equal(active.ownerGrantSignatureVerified, true);
  assert.equal(await verify.isVerifiedTrustedDeviceRecoveryHistoryV2(state.verifiedHistory), true,
    "original head verified before offline stage");

  const attacks = [
    { approval: { ...issued.approval, signature: b64(crypto.randomBytes(64)) } },
    { approval: { ...issued.approval, pop_challenge_id: b64(crypto.randomBytes(16)) } },
    { request: { ...fresh.request, hpke_public_key: b64(crypto.randomBytes(32)) } },
    { independentOwnerSpkiSha256: crypto.randomBytes(32) },
    { pinnedCurrentHead: { ...credentials.pinnedCurrentHead, revision: former.revision } },
    { signedDeviceGrant: { ...issued.signedDeviceGrant, revoked_at_epoch: committed.epoch } },
    { nowSeconds: now + 310 },
  ];
  for (const [index, changes] of attacks.entries()) {
    await assert.rejects(approval.verifyImportedApproval({
      ...credentials, ...changes,
    }), /ZK_V2_OWNER_APPROVAL_DENIED/, `hostile approval case ${index}`);
  }
  const attacker = crypto.generateKeyPairSync("ed25519");
  await assert.rejects(enrollment.beginOwnerEnrollment({
    request: fresh.request, verifiedHistory: state.verifiedHistory,
    externalCurrentHead, trustedOwnerPublicKey: attacker.publicKey,
    independentOwnerSpkiSha256: b64(ownerSpki),
    trustedCommitmentSignerPublicKey: witness.publicKey,
    independentCommitmentSignerSpkiSha256: witnessSpki,
    trustedPriorCommitment: priorCommitment, nowSeconds: now,
  }), /ZK_OWNER_OFFLINE_ENROLLMENT_DENIED/);
  await assert.rejects(enrollment.beginOwnerEnrollment({
    request: fresh.request, verifiedHistory: state.verifiedHistory,
    externalCurrentHead, trustedOwnerPublicKey: owner.publicKey,
    independentOwnerSpkiSha256: b64(ownerSpki),
    trustedCommitmentSignerPublicKey: witness.publicKey,
    independentCommitmentSignerSpkiSha256: b64(crypto.randomBytes(32)),
    trustedPriorCommitment: priorCommitment, nowSeconds: now,
  }), /ZK_OWNER_OFFLINE_ENROLLMENT_DENIED/, "foreign independent signer pin");
  await assert.rejects(enrollment.beginOwnerEnrollment({
    request: fresh.request, verifiedHistory: state.verifiedHistory,
    externalCurrentHead, trustedOwnerPublicKey: owner.publicKey,
    independentOwnerSpkiSha256: b64(ownerSpki),
    trustedCommitmentSignerPublicKey: witness.publicKey,
    independentCommitmentSignerSpkiSha256: witnessSpki,
    trustedPriorCommitment: { ...priorCommitment, signature: b64(crypto.randomBytes(64)) },
    nowSeconds: now,
  }), /ZK_OWNER_OFFLINE_ENROLLMENT_DENIED/, "unsigned/forged prior commitment");
  await assert.rejects(enrollment.beginOwnerEnrollment({
    request: fresh.request, verifiedHistory: state.verifiedHistory,
    externalCurrentHead, trustedOwnerPublicKey: owner.publicKey,
    independentOwnerSpkiSha256: b64(ownerSpki),
    trustedCommitmentSignerPublicKey: witness.publicKey,
    independentCommitmentSignerSpkiSha256: witnessSpki,
    trustedPriorCommitment: priorCommitment, nowSeconds: now - 60,
  }), /ZK_OWNER_OFFLINE_ENROLLMENT_DENIED/, "caller clock rollback cannot extend PoP");
});
