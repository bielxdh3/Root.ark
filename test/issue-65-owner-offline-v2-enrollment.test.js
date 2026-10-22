"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const manifest = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const verify = require("../src/crypto/rootark-zk-recovery-history-v2");
const enrollment = require("../src/crypto/rootark-zk1-owner-offline-v2-enrollment");
const approval = require("../public/client/rootark-zk1-v2-device-approval");
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
  const prepared = await enrollment.beginOwnerEnrollment({
    request: fresh.request, verifiedHistory: state.verifiedHistory,
    externalCurrentHead, trustedOwnerPublicKey: owner.publicKey,
    independentOwnerSpkiSha256: b64(ownerSpki), nowSeconds: now,
  });
  const answer = await enrollment.answerTargetPop({
    request: fresh.request, challenge: prepared.challenge,
    deviceHpkePrivateDer: fresh.hpkePrivateDer,
    deviceAuthorizationPrivateDer: fresh.signer.privateKey.export({
      format: "der", type: "pkcs8" }), nowSeconds: now,
  });
  const actor = state.actors.get(Buffer.from(former.devices[0].authorization_key_id)
    .toString("hex"));
  const candidate = await enrollment.stageV2Enrollment({
    prepared, response: answer, trustedActorPrivateKey: actor, nowSeconds: now,
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
  await assert.rejects(enrollment.ownerApproveCommittedEnrollment({
    candidate, externalCommittedHead: { ...externalCurrentHead },
    ownerPrivateKey: owner.privateKey, nowSeconds: now,
  }), /ZK_OWNER_OFFLINE_ENROLLMENT_DENIED/,
  "an uncommitted candidate cannot authorize new device");
  const issued = await enrollment.ownerApproveCommittedEnrollment({
    candidate, externalCommittedHead: committed, ownerPrivateKey: owner.privateKey,
    nowSeconds: now,
  });
  assert.equal(issued.noServerSecretExposure, true);
  assert.equal(issued.committedHeadOriginProven, false);
  await assert.rejects(enrollment.ownerApproveCommittedEnrollment({
    candidate, externalCommittedHead: committed, ownerPrivateKey: owner.privateKey,
    nowSeconds: now,
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
    devicePublicKey: newPublic, devicePrivateKey: newPrivate, nowSeconds: now,
  };
  const report = await approval.verifyImportedApproval(credentials);
  assert.equal(report.verifiedOwnerOfflineApproval, true);
  assert.equal(report.v2TransitionProvenByBrowser, false);
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
    { nowSeconds: now + 301 },
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
    independentOwnerSpkiSha256: b64(ownerSpki), nowSeconds: now,
  }), /ZK_OWNER_OFFLINE_ENROLLMENT_DENIED/);
});
