"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const express = require("express");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");
const { Zk1ProtectedObjectStore } = require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");
const protectedClient = require("../public/client/rootark-zk1-protected-http-client");
const content = require("../public/client/rootark-zk1-file-content");
const ciphertextRoots = require("../public/client/rootark-zk1-ciphertext-chunk-root");
const cekTransfer = (() => {
  try { return require("../src/crypto/rootark-zk1-owner-authorized-file-cek-transfer"); }
  catch (error) { if (error.code === "MODULE_NOT_FOUND") return {}; throw error; }
})();
const cekBatch = (() => {
  try { return require("../src/crypto/rootark-zk1-owner-authorized-versioned-cek-batch"); }
  catch (error) { if (error.code === "MODULE_NOT_FOUND") return {}; throw error; }
})();
const { openProtectedRecipientShareFile } = (() => {
  try { return require("../src/crypto/rootark-zk1-recipient-share-cek"); }
  catch (error) { if (error.code === "MODULE_NOT_FOUND") return {}; throw error; }
})();
const { shareGrantMessageV1 } = require("../src/services/zk1ProtectedCiphertextSharing");
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

test("offline V2 enrollment rejects a locally signed owner key disguised as the externally pinned owner", async () => {
  const state = await fixtures.createInitialState(2);
  const owner = crypto.generateKeyPairSync("ed25519");
  const foreign = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const signer = crypto.createPublicKey({
    key: owner.publicKey.export({ format: "der", type: "spki" }),
    type: "spki", format: "der",
  });
  const foreignSpki = foreign.publicKey.export({ format: "der", type: "spki" });
  signer.export = () => Buffer.from(foreignSpki);
  const now = Math.floor(Date.now() / 1000);
  const prior = state.headManifest;
  const head = { revision: prior.revision,
    digest: b64(await manifest.recoveryManifestDigestV2(prior)),
    epoch: prior.current_epoch };
  const unsigned = { schema: commitment.SCHEMA, status: "committed",
    account_id: b64(prior.account_id), compartment_id: b64(prior.compartment_id),
    keyring_id: b64(prior.keyring_id), revision: head.revision,
    digest: head.digest, epoch: head.epoch,
    previous_revision: null, previous_digest: null,
    operation_id: null, pop_challenge_id: null, request_nonce: null,
    commit_nonce: null, sequence: 1, previous_receipt_sha256: null,
    issued_at: now, expires_at: now + 300 };
  const signed = { ...unsigned, signature: b64(crypto.sign(null,
    commitment.commitmentSigningBytes(unsigned), witness.privateKey)) };
  const args = { request: (await newDeviceRequest()).request,
    verifiedHistory: state.verifiedHistory, externalCurrentHead: head,
    trustedOwnerPublicKey: owner.publicKey,
    independentOwnerSpkiSha256: b64(crypto.createHash("sha256").update(
      owner.publicKey.export({ type: "spki", format: "der" })).digest()),
    trustedCommitmentSignerPublicKey: witness.publicKey,
    independentCommitmentSignerSpkiSha256: b64(crypto.createHash("sha256").update(
      witness.publicKey.export({ type: "spki", format: "der" })).digest()),
    trustedPriorCommitment: signed, nowSeconds: now };
  const honest = await enrollment.beginOwnerEnrollment(args);
  assert.ok(honest.challenge);
  await assert.rejects(enrollment.beginOwnerEnrollment({ ...args,
    trustedOwnerPublicKey: signer,
    independentOwnerSpkiSha256: b64(crypto.createHash("sha256")
      .update(foreignSpki).digest()),
  }), /ZK_OWNER_OFFLINE_ENROLLMENT_DENIED/);
});

test("owner offline ceremony: new device proves V2 HPKE+Ed25519; owner signs only after independently pinned committed head", async (t) => {
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
    ...[undefined, null, NaN, Infinity, -Infinity, -1, 1.5,
      "100", Number.MAX_SAFE_INTEGER + 1].map((nowSeconds) => ({ nowSeconds })),
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

  await t.test("DEV-OFF: owner-signed file CEK rewrap lets independent B decrypt signed HTTP after real SQLite restart", async (sub) => {
    const dir = createPrivateAuthorityFixture("zk65-distinct-b-restore-");
    const filename = path.join(dir, "protected.sqlite");
    const currentManifest = candidate.manifest;
    const currentDigest = await manifest.recoveryManifestDigestV2(currentManifest);
    const freshWitnessKeyId = crypto.randomBytes(16);
    const witnessProvider = {
      async freshHead({ nonce }) {
        const statement = { type: "rootark-recovery-witness-head/v1",
          witness_key_id: freshWitnessKeyId, ...state.scope,
          current_revision: currentManifest.revision,
          current_manifest_digest: currentDigest,
          witness_sequence: currentManifest.revision, nonce,
          observed_at: now + 9, status: "committed", pending_reservation_id: null };
        return z.encodeDeterministic({ ...statement, signature: crypto.sign(null,
          Buffer.concat([Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0"),
            Buffer.from(await z.encodeDeterministic(statement))]), witness.privateKey) });
      },
      async beginIoAdmission() { return { admissionId: crypto.randomBytes(16), proceed: true }; },
      async finishIoAdmission() { return { status: "completed" }; },
    };
    const storeArgs = { trustedScope: state.scope, bootstrapNew: true,
      admissionRequired: true, witnessProvider,
      witnessPinned: { keyId: freshWitnessKeyId, publicKey: witness.publicKey },
      minimumHead: { revision: 1, witnessSequence: 1,
        digest: await manifest.recoveryManifestDigestV2(state.baseManifest) },
      manifestProvider: () => z.encodeDeterministic(currentManifest),
      nowSeconds: () => now + 9 };
    let store = new Zk1ProtectedObjectStore(filename, storeArgs);
    const app = express();
    const authenticated = (req, res, next) => {
      if (req.get("x-fixture-session") !== "owner") return res.sendStatus(401);
      req.user = { username: "owner" }; next();
    };
    const liveStore = { put: (...args) => store.put(...args),
      get: (...args) => store.get(...args),
      runWithAdmission: (...args) => store.runWithAdmission(...args) };
    registerZk1ProtectedObjectRoutes({ app, store: liveStore, authenticate: authenticated,
      requirePermission: () => (_req, _res, next) => next(),
      resolveTrustedScope: () => state.scope });
    const server = await new Promise((resolve) => {
      const started = app.listen(0, "127.0.0.1", () => resolve(started));
    });
    sub.after(async () => {
      await new Promise((resolve) => server.close(resolve));
      store.close(); fs.rmSync(dir, { recursive: true, force: true });
    });
    const origin = `http://127.0.0.1:${server.address().port}`;
    let puts = 0, reads = 0;
    const fetchImpl = (url, options) => {
      if (url.endsWith("/content/put")) puts++;
      if (url.endsWith("/content/read")) reads++;
      return fetch(url, { ...options,
        headers: { ...options.headers, "x-fixture-session": "owner" } });
    };
    const scope = Object.fromEntries(Object.entries(state.scope)
      .map(([name, value]) => [name, b64(value)]));
    const originalDevice = currentManifest.devices.find((entry) => entry.device_id !== fresh.request.device_id
      && entry.revoked_at_epoch === null);
    assert.ok(originalDevice);
    const originalActor = state.actors.get(Buffer.from(originalDevice.authorization_key_id).toString("hex"));
    const originalSigner = await subtle.importKey("pkcs8",
      originalActor.export({ format: "der", type: "pkcs8" }), "Ed25519", false, ["sign"]);
    const signing = { signerKey: originalSigner, scope,
      deviceId: originalDevice.device_id, manifestRevision: currentManifest.revision,
      manifestDigest: currentDigest, epoch: currentManifest.current_epoch,
      nowSeconds: now + 9 };
    const metadata = { ...scope, object_id: b64(crypto.randomBytes(16)),
      version_id: b64(crypto.randomBytes(16)), parent_version_id: null,
      epoch: currentManifest.current_epoch, kind: "file" };
    const ownerHeldCek = crypto.randomBytes(32);
    const originalCek = await content.importFileCek(ownerHeldCek);
    const bytes = Buffer.from("distinct-B-HPKE-signed-http-sqlite-restart-evidence");
    const sealed = await content.encryptFile({ cek: originalCek, metadata,
      name: "private.txt", mediaType: "text/plain", data: bytes });
    const put = await protectedClient.signProtectedContentOperation({
      ...signing, operation: "put", objectId: metadata.object_id,
      expectedObjectRevision: null, ciphertext: sealed });
    assert.equal((await protectedClient.postProtectedCiphertextPut({
      origin, request: put, fetchImpl })).revision, 1);
    assert.equal(puts, 1);
    store.close();
    store = new Zk1ProtectedObjectStore(filename, { ...storeArgs, bootstrapNew: false });
    const persisted = store.db.prepare("SELECT revision, ciphertext FROM zk_content_object WHERE id=?")
      .get(metadata.object_id);
    assert.equal(persisted.revision, 1, "physical SQLite reopened with committed ciphertext");
    assert.equal(Buffer.from(persisted.ciphertext).includes(bytes), false,
      "protected SQLite must never contain file plaintext");
    assert.equal(Buffer.from(persisted.ciphertext).equals(Buffer.from(sealed)), true);
    const currentEpoch = currentManifest.epochs.find((row) => row.epoch === metadata.epoch);
    const deviceWrap = currentManifest.wraps.find((row) =>
      row.device_id === fresh.request.device_id && row.epoch === metadata.epoch);
    assert.ok(deviceWrap && currentEpoch, "B must have a genuine owner-authorized HPKE epoch wrap");
    const hpkeContext = { suite: "rootark-zk-1",
      account_id: state.scope.account_id,
      compartment_id: state.scope.compartment_id,
      purpose: "key-wrap", recipient_type: "device",
      recipient_id: fresh.request.device_id,
      recipient_key_id: Buffer.from(fresh.request.hpke_key_id, "base64url"),
      epoch: metadata.epoch, key_ref: currentEpoch.key_ref, wrap_id: deviceWrap.wrap_id };
    const hpkeContextBytes = await z.encodeDeterministic(hpkeContext);
    const bRecipient = await z.hpkeSuite().kem.deserializePrivateKey(fresh.hpkePrivateRaw);
    const bEpochKey = Buffer.from(await z.hpkeOpen({
      recipientKey: bRecipient, enc: deviceWrap.enc, ciphertext: deviceWrap.ciphertext,
      info: Buffer.concat([Buffer.from("Root.ark/zk-1/keyring-wrap-info/v2\0"), hpkeContextBytes]),
      aad: Buffer.concat([Buffer.from("Root.ark/zk-1/keyring-wrap-aad/v2\0"), hpkeContextBytes]),
    }));
    assert.equal(bEpochKey.length, 32);
    assert.deepEqual(bEpochKey, Buffer.from(state.epochKeys.find((row) =>
      row.epoch === metadata.epoch).key), "independent B private key must open real epoch bytes");
    bEpochKey.fill(0);
    const digest = crypto.createHash("sha256").update(sealed).digest();
    const root = await ciphertextRoots.computeCiphertextRoot([sealed]);
    const signedGet = await protectedClient.signProtectedContentOperation({
      ...signing, signerKey: newPrivate, deviceId: fresh.request.device_id,
      operation: "get", objectId: metadata.object_id,
      expectedObjectRevision: 1, expectedCiphertextDigest: digest,
      ciphertext: null });
    const ciphertextOnly = await protectedClient.postProtectedCiphertextBackupRead({
      origin, request: signedGet, expectedObjectRevision: 1,
      expectedEpoch: metadata.epoch, expectedRoot: root, fetchImpl });
    assert.ok(ciphertextOnly && reads > 0);
    assert.equal(puts, 1, "B may only use signed GET after restart");
    await assert.rejects(protectedClient.postProtectedCiphertextBackupRead({
      origin, request: signedGet, expectedObjectRevision: 1,
      expectedEpoch: metadata.epoch, expectedRoot: root, fetchImpl }),
    /ZK_BROWSER_CONTENT_UNAVAILABLE/,
    "physical SQLite restart does not reset the consumed authenticated GET nonce");
    const publicAuthority = {
      request: fresh.request, signedDeviceGrant: issued.signedDeviceGrant,
      approval: issued.approval, signedV2Manifest: issued.signedV2Manifest,
      ownerPublicKey: owner.publicKey, independentOwnerSpkiSha256: ownerSpki,
      witnessPublicKey: witness.publicKey,
      independentWitnessSpkiSha256: Buffer.from(witnessSpki, "base64url"),
      currentHead: { ...committed, digest: Buffer.from(committed.digest, "base64url") },
      committedReceipt: signedCommittedHead, previousReceipt: priorCommitment,
      operatorMinimumSequence: signedCommittedHead.sequence, nowSeconds: now + 9,
    };
    assert.equal(typeof cekTransfer.sealOwnerAuthorizedFileCek,
      "function", "ZK06 missing owner-signed file CEK HPKE rewrap protocol");
    const envelope = await cekTransfer.sealOwnerAuthorizedFileCek({
      ownerPrivateKey: owner.privateKey, ownerHeldCek,
      metadata, objectRevision: 1, ciphertext: sealed, ciphertextRoot: root,
      authority: publicAuthority,
    });
    await assert.rejects(cekTransfer.sealOwnerAuthorizedFileCek({
      ownerPrivateKey: owner.privateKey, ownerHeldCek: crypto.randomBytes(32),
      metadata, objectRevision: 1, ciphertext: sealed, ciphertextRoot: root,
      authority: publicAuthority,
    }), /ZK_OWNER_FILE_CEK_DENIED/,
    "owner cannot authorize arbitrary 32-byte material as a per-file CEK");
    await assert.rejects(cekTransfer.sealOwnerAuthorizedFileCek({
      ownerPrivateKey: owner.privateKey, ownerHeldCek,
      metadata, objectRevision: 1, ciphertext: sealed, ciphertextRoot: root,
      authority: { ...publicAuthority, approval: {
        ...issued.approval, request_sha256: b64(crypto.randomBytes(32)) } },
    }), /ZK_OWNER_FILE_CEK_DENIED/,
    "substituted owner approval must not authorize B's HPKE recipient");
    const attackerHpke = await z.hpkeSuite().kem.generateKeyPair();
    await assert.rejects(cekTransfer.sealOwnerAuthorizedFileCek({
      ownerPrivateKey: owner.privateKey, ownerHeldCek,
      metadata, objectRevision: 1, ciphertext: sealed, ciphertextRoot: root,
      authority: { ...publicAuthority, request: {
        ...fresh.request, hpke_public_key: b64(await z.hpkeSuite().kem.serializePublicKey(
          attackerHpke.publicKey)) } },
    }), /ZK_OWNER_FILE_CEK_DENIED/,
    "owner must not seal CEK to an HPKE key absent from signed V2 PoP and approval");
    // A hostile caller can mutate its ORIGINAL request after the owner/PoP
    // check has awaited, while actual owner AEAD decryption is still pending.
    // This is a genuine async seam in the owner CEK transfer path, not a
    // fabricated signature or a direct call to a test-only seal function.
    const racedAuthority = { ...publicAuthority, request: { ...fresh.request } };
    const maliciousRecipient = b64(await z.hpkeSuite().kem.serializePublicKey(
      attackerHpke.publicKey));
    const realDecrypt = subtle.decrypt;
    let mutatedAfterVerification = false;
    subtle.decrypt = async function (...args) {
      // Preserve the native AES-GCM operation; mutate only after it finishes.
      const result = await realDecrypt.apply(this, args);
      racedAuthority.request.hpke_public_key = maliciousRecipient;
      mutatedAfterVerification = true;
      return result;
    };
    let racedEnvelope;
    try {
      racedEnvelope = await cekTransfer.sealOwnerAuthorizedFileCek({
        ownerPrivateKey: owner.privateKey, ownerHeldCek, metadata,
        objectRevision: 1, ciphertext: sealed, ciphertextRoot: root,
        authority: racedAuthority,
      });
    } finally { delete subtle.decrypt; }
    assert.equal(mutatedAfterVerification, true,
      "attack exercised the real asynchronous file AEAD boundary");
    assert.equal(racedEnvelope.core.hpke_public_key, fresh.request.hpke_public_key,
      "post-verification request mutation must never select the HPKE recipient");
    const racedContext = await z.encodeDeterministic(racedEnvelope.core);
    await assert.rejects(z.hpkeOpen({
      recipientKey: attackerHpke.privateKey,
      enc: Buffer.from(racedEnvelope.enc, "base64url"),
      ciphertext: Buffer.from(racedEnvelope.ciphertext, "base64url"),
      info: Buffer.concat([Buffer.from(
        "Root.ark/zk-1/owner-authorized-file-cek-info/v1\0"), racedContext]),
      aad: Buffer.concat([Buffer.from(
        "Root.ark/zk-1/owner-authorized-file-cek-aad/v1\0"), racedContext]),
    }), /AUTHENTICATION_FAILED/,
    "attacker's substituted X25519 private key must not recover A's CEK");
    const bOpenedRaced = await z.hpkeOpen({
      recipientKey: bRecipient,
      enc: Buffer.from(racedEnvelope.enc, "base64url"),
      ciphertext: Buffer.from(racedEnvelope.ciphertext, "base64url"),
      info: Buffer.concat([Buffer.from(
        "Root.ark/zk-1/owner-authorized-file-cek-info/v1\0"), racedContext]),
      aad: Buffer.concat([Buffer.from(
        "Root.ark/zk-1/owner-authorized-file-cek-aad/v1\0"), racedContext]),
    });
    assert.deepEqual(Buffer.from(bOpenedRaced), ownerHeldCek,
      "genuine approved B still unwraps the owner CEK after caller mutation");
    bOpenedRaced.fill(0);

    for (const label of ["metadata", "ciphertext", "head", "root"]) {
      const otherMeta = { ...metadata };
      const otherCipher = Buffer.from(sealed);
      const otherRoot = Buffer.from(root);
      const otherHead = { ...publicAuthority.currentHead,
        digest: Buffer.from(publicAuthority.currentHead.digest) };
      const otherAuthority = { ...publicAuthority, currentHead: otherHead };
      let mutated = false;
      subtle.decrypt = async function (...args) {
        const result = await realDecrypt.apply(this, args);
        if (label === "metadata") otherMeta.object_id = b64(crypto.randomBytes(16));
        if (label === "ciphertext") otherCipher[otherCipher.length - 1] ^= 1;
        if (label === "head") otherHead.digest[0] ^= 1;
        if (label === "root") otherRoot[0] ^= 1;
        mutated = true;
        return result;
      };
      let safe;
      try {
        safe = await cekTransfer.sealOwnerAuthorizedFileCek({
          ownerPrivateKey: owner.privateKey, ownerHeldCek,
          metadata: otherMeta, objectRevision: 1,
          ciphertext: otherCipher, ciphertextRoot: otherRoot,
          authority: otherAuthority,
        });
      } finally { delete subtle.decrypt; }
      assert.equal(mutated, true, `${label}: mutation ran after real AEAD decrypt`);
      assert.equal(safe.core.object_id, metadata.object_id,
        `${label}: original object identity was pinned before await`);
      assert.equal(safe.core.ciphertext_sha256, b64(digest),
        `${label}: ciphertext digest pinned before await`);
      assert.equal(safe.core.ciphertext_root, b64(root),
        `${label}: ciphertext root pinned before await`);
      assert.equal(safe.core.owner_digest, committed.digest,
        `${label}: signed owner head pinned before await`);
    }
    // The owner also must not create a fresh CEK grant after the signed
    // approval expires while the real file AEAD open is pending.
    const originalWallClock = Date.now;
    let ownerDecryptFinished = false;
    subtle.decrypt = async function (...args) {
      const result = await realDecrypt.apply(this, args);
      ownerDecryptFinished = true;
      Date.now = () => (signedCommittedHead.expires_at + 2) * 1000;
      return result;
    };
    try {
      await assert.rejects(cekTransfer.sealOwnerAuthorizedFileCek({
        ownerPrivateKey: owner.privateKey, ownerHeldCek,
        metadata, objectRevision: 1, ciphertext: sealed, ciphertextRoot: root,
        authority: publicAuthority,
      }), /ZK_OWNER_FILE_CEK_DENIED/,
      "A must refuse CEK rewrap after authorization expires during real file AEAD open");
    } finally {
      Date.now = originalWallClock;
      delete subtle.decrypt;
    }
    assert.equal(ownerDecryptFinished, true,
      "test must reach the genuine file AEAD before expiring the grant");
    for (const label of ["request", "metadata", "head", "opened envelope"]) {
      let accessed = 0;
      const accessor = { enumerable: true, configurable: true,
        get() { accessed++; return label === "head"
          ? publicAuthority.currentHead.digest
          : label === "metadata" ? metadata.object_id
            : label === "request" ? fresh.request.hpke_public_key
              : envelope.core.owner_digest; } };
      if (label === "opened envelope") {
        const hostileCore = { ...envelope.core };
        Object.defineProperty(hostileCore, "owner_digest", accessor);
        await assert.rejects(cekTransfer.openOwnerAuthorizedFileCek({
          envelope: { ...envelope, core: hostileCore },
          authority: { ...linked, nowSeconds: now + 9 },
          operatorMinimumSequence: signedCommittedHead.sequence,
          metadata, objectRevision: 1,
          ciphertext: Buffer.from(ciphertextOnly.ciphertextBase64, "base64url"),
          ciphertextRoot: root, deviceHpkePrivateKey: bRecipient,
          nowSeconds: now + 9,
        }),
          /ZK_OWNER_FILE_CEK_DENIED/, "B rejects accessors in a signed envelope");
      } else {
        const request = { ...fresh.request };
        const meta = { ...metadata };
        const head = { ...publicAuthority.currentHead };
        if (label === "request") Object.defineProperty(request, "hpke_public_key", accessor);
        if (label === "metadata") Object.defineProperty(meta, "object_id", accessor);
        if (label === "head") Object.defineProperty(head, "digest", accessor);
        await assert.rejects(cekTransfer.sealOwnerAuthorizedFileCek({
          ownerPrivateKey: owner.privateKey, ownerHeldCek, metadata: meta,
          objectRevision: 1, ciphertext: sealed, ciphertextRoot: root,
          authority: { ...publicAuthority, request, currentHead: head },
        }), /ZK_OWNER_FILE_CEK_DENIED/, `${label}: owner rejects accessor-bearing trust inputs`);
      }
      assert.equal(accessed, 0,
        `${label}: a malicious getter must never run while taking the trust snapshot`);
    }
    assert.equal(envelope.authorizesProductionRestore, false);
    const recoveredCiphertext = Buffer.from(ciphertextOnly.ciphertextBase64, "base64url");
    const open = (overrides = {}) => cekTransfer.openOwnerAuthorizedFileCek({
      envelope, authority: { ...linked, nowSeconds: now + 9 },
      operatorMinimumSequence: signedCommittedHead.sequence,
      metadata, objectRevision: 1, ciphertext: recoveredCiphertext,
      ciphertextRoot: root, deviceHpkePrivateKey: bRecipient,
      nowSeconds: now + 9, ...overrides,
    });
    // Expire the real signed authorization at the last awaited HPKE operation.
    // A previously approved CEK must not escape after the time-bound grant dies.
    const realHpkeOpen = z.hpkeOpen;
    const realDateNow = Date.now;
    let hpkeFinishedBeforeExpiry = false;
    z.hpkeOpen = async (...args) => {
      const result = await realHpkeOpen(...args);
      hpkeFinishedBeforeExpiry = true;
      Date.now = () => (envelope.core.expires_at + 2) * 1000;
      return result;
    };
    try {
      await assert.rejects(open(), /ZK_OWNER_FILE_CEK_DENIED/,
        "B cannot release a CEK after expiry during real HPKE open");
    } finally {
      z.hpkeOpen = realHpkeOpen;
      Date.now = realDateNow;
    }
    assert.equal(hpkeFinishedBeforeExpiry, true,
      "test must reach actual HPKE decrypt before the clock changes");
    const bCek = await open();
    assert.equal(bCek.authorizesProductionRestore, false);
    assert.equal(bCek.verifiedReleaseExpiresAt, Math.min(
      envelope.core.expires_at, issued.approval.expires_at,
      signedCommittedHead.expires_at),
    "owner CEK opener returns the signed owner/approval/witness expiration actually verified");
    const decrypted = await content.decryptFile({
      cek: await content.importFileCek(bCek.cek), metadata,
      envelopeBytes: recoveredCiphertext,
    });
    assert.deepEqual(Buffer.from(decrypted.data), bytes,
      "B independently decrypts exact SQLite-reopened HTTP bytes without receiving A recoverySecret");
    bCek.cek.fill(0); decrypted.data.fill(0);
    // The existing #276 share GET is HTTP-tested separately. Exercise its
    // signed grant/recipient-client protocol against the real retained file
    // and the existing owner-approved HPKE transfer, without minting a key.
    assert.equal(typeof openProtectedRecipientShareFile, "function",
      "recipient must be able to combine the authenticated share with owner CEK custody");
    const shareAuthorization = { ...state.scope, device_id: originalDevice.device_id,
      operation: "get", object_id: metadata.object_id, expected_object_revision: 1,
      manifest_revision: currentManifest.revision, manifest_digest: currentDigest,
      epoch: currentManifest.current_epoch, nonce: crypto.randomBytes(32),
      issued_at: now + 9, expires_at: now + 39, ciphertext_digest: digest };
    const grantInput = { authorization: shareAuthorization, grantId: b64(crypto.randomBytes(32)),
      recipientUsername: "recipient", recipientDeviceId: fresh.request.device_id,
      expiresAt: now + 129 };
    const message = await shareGrantMessageV1(grantInput);
    const grant = { grantId: grantInput.grantId, expiresAt: grantInput.expiresAt,
      shareStatementBase64: b64(message.subarray(Buffer.byteLength(
        "Root.ark/zk-1/protected-ciphertext-share/v1\0"))),
      shareSignatureBase64: b64(crypto.sign(null, message, originalActor)) };
    const readIndependentAuthority = async () => ({ scope,
      head: { revision: currentManifest.revision, epoch: currentManifest.current_epoch,
        digest: Uint8Array.from(currentDigest) },
      devices: currentManifest.devices.map((device) => ({
        deviceId: device.device_id,
        authorizationPublicKey: Uint8Array.from(device.authorization_public_key),
        enrolledEpoch: device.enrolled_epoch, revokedAtEpoch: device.revoked_at_epoch,
      })) });
    const recipientShareInput = { origin, grant, recipientUsername: "recipient",
      recipientDeviceId: fresh.request.device_id, signerKey: newPrivate,
      readIndependentAuthority, nowSeconds: () => now + 9,
      fetchImpl: async () => new Response(JSON.stringify({
        id: metadata.object_id, revision: 1, epoch: metadata.epoch,
        ciphertextBase64: b64(recoveredCiphertext),
        shareStatementBase64: grant.shareStatementBase64,
        shareSignatureBase64: grant.shareSignatureBase64,
      }), { status: 200, headers: { "content-type": "application/json" } }),
    };
    const bridgeArgs = { redeemInput: recipientShareInput, envelope,
      authority: { ...linked, nowSeconds: now + 9 },
      operatorMinimumSequence: signedCommittedHead.sequence,
      metadata, deviceHpkePrivateKey: bRecipient, nowSeconds: now + 9 };
    const shared = await openProtectedRecipientShareFile(bridgeArgs);
    assert.deepEqual(Buffer.from(shared.data), bytes);
    assert.equal(shared.authorizesProductionIo, false);
    shared.data.fill(0);
    // P2: the independently verified owner HPKE CEK is still valid when B
    // starts file AEAD, but its owner approval/witness expires DURING the
    // final file decrypt. Share grant expires later, so checking only the
    // share expiry at return is a false-green authorization boundary.
    const longGrantInput = { ...grantInput, grantId: b64(crypto.randomBytes(32)),
      expiresAt: Math.max(envelope.core.expires_at,
        issued.approval.expires_at, signedCommittedHead.expires_at) + 120 };
    const longMessage = await shareGrantMessageV1(longGrantInput);
    const longGrant = { grantId: longGrantInput.grantId,
      expiresAt: longGrantInput.expiresAt,
      shareStatementBase64: b64(longMessage.subarray(Buffer.byteLength(
        "Root.ark/zk-1/protected-ciphertext-share/v1\0"))),
      shareSignatureBase64: b64(crypto.sign(null, longMessage, originalActor)) };
    const longShareInput = { ...recipientShareInput, grant: longGrant,
      fetchImpl: async () => new Response(JSON.stringify({
        id: metadata.object_id, revision: 1, epoch: metadata.epoch,
        ciphertextBase64: b64(recoveredCiphertext),
        shareStatementBase64: longGrant.shareStatementBase64,
        shareSignatureBase64: longGrant.shareSignatureBase64,
      }), { status: 200, headers: { "content-type": "application/json" } }) };
    const firstExpiry = Math.min(envelope.core.expires_at,
      issued.approval.expires_at, signedCommittedHead.expires_at);
    assert.ok(longGrant.expiresAt > firstExpiry + 2,
      "the genuinely signed share must still be live after owner/witness expiration");
    const encodedFile = JSON.parse(recoveredCiphertext.toString("utf8"));
    const fileAeadCipherLength = Buffer.from(encodedFile.ciphertext, "base64url").length;
    assert.notEqual(fileAeadCipherLength, 48,
      "genuine file AEAD must be distinguishable from the 48-byte owner HPKE CEK ciphertext");
    const originalFinalDecrypt = subtle.decrypt;
    let finalAeadCompleted = false;
    subtle.decrypt = async function (...args) {
      const openedFile = await originalFinalDecrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) {
        finalAeadCompleted = true;
      }
      return openedFile;
    };
    try {
      const longGrantOpened = await openProtectedRecipientShareFile({ ...bridgeArgs,
        redeemInput: longShareInput });
      assert.deepEqual(Buffer.from(longGrantOpened.data), bytes,
        "real HPKE plus file AEAD still opens a live Ed25519 recipient share");
      longGrantOpened.data.fill(0);
    } finally {
      delete subtle.decrypt;
    }
    assert.equal(finalAeadCompleted, true,
      "positive control must complete genuine file AEAD before the expiry adversary");
    // Sign a NEW short-lived share with the real Ed25519 owner device key.
    // Allow its real expiration to pass ONLY after the genuine HPKE/file AEAD
    // path has completed; the third independent-authority callback then rolls
    // Date.now backwards. Merely mocking Date.now forwards here would not
    // prove the pinned release clock rejects an actually expired share.
    const physicalNow = Date.now;
    const shortIssuedAt = Math.floor(physicalNow() / 1000) - 1;
    const shortExpiresAt = shortIssuedAt + 15;
    const shortInput = { ...grantInput, grantId: b64(crypto.randomBytes(32)),
      authorization: { ...shareAuthorization, issued_at: shortIssuedAt },
      expiresAt: shortExpiresAt };
    const shortMessage = await shareGrantMessageV1(shortInput);
    const shortGrant = { grantId: shortInput.grantId, expiresAt: shortExpiresAt,
      shareStatementBase64: b64(shortMessage.subarray(Buffer.byteLength(
        "Root.ark/zk-1/protected-ciphertext-share/v1\0"))),
      shareSignatureBase64: b64(crypto.sign(null, shortMessage, originalActor)) };
    const shortNowSeconds = shortIssuedAt + 1;
    const shortShareInput = { ...recipientShareInput, grant: shortGrant,
      nowSeconds: () => shortNowSeconds,
      fetchImpl: async () => new Response(JSON.stringify({
        id: metadata.object_id, revision: 1, epoch: metadata.epoch,
        ciphertextBase64: b64(recoveredCiphertext),
        shareStatementBase64: shortGrant.shareStatementBase64,
        shareSignatureBase64: shortGrant.shareSignatureBase64,
      }), { status: 200, headers: { "content-type": "application/json" } }) };
    const shortBridge = { ...bridgeArgs, nowSeconds: shortNowSeconds,
      authority: { ...linked, nowSeconds: shortNowSeconds } };
    const originalSome = Array.prototype.some;
    const originalReadNow = Date.now;
    const realFinalDecrypt = subtle.decrypt;
    let poisonInstalled = false;
    let authorityReadsWithPoison = 0, genuineAeadBeforePoison = false;
    let realExpiryObserved = false;
    subtle.decrypt = async function (...args) {
      const result = await realFinalDecrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) {
        genuineAeadBeforePoison = true;
      }
      return result;
    };
    let expiryOutcome;
    try {
      expiryOutcome = await openProtectedRecipientShareFile({ ...shortBridge,
        redeemInput: { ...shortShareInput, readIndependentAuthority: async () => {
          const current = await readIndependentAuthority();
          if (++authorityReadsWithPoison === 3) {
            assert.equal(genuineAeadBeforePoison, true,
              "the real file AEAD must complete before the malicious third read");
            assert.ok(physicalNow() < shortExpiresAt * 1000,
              "genuine file AEAD must finish while the short signed share is still live");
            const remaining = shortExpiresAt * 1000 - physicalNow();
            if (remaining > 0) await new Promise((resolve) =>
              setTimeout(resolve, remaining + 30));
            realExpiryObserved = physicalNow() >= shortExpiresAt * 1000;
            assert.equal(realExpiryObserved, true,
              "the genuine native clock, not a patched Date.now, crossed signed expiry");
            poisonInstalled = true;
            Array.prototype.some = () => false;
            Date.now = () => shortIssuedAt * 1000;
          }
          return current;
        } },
      }).then((value) => value, (error) => error);
    } finally {
      Array.prototype.some = originalSome;
      Date.now = originalReadNow;
      delete subtle.decrypt;
    }
    if (expiryOutcome?.data instanceof Uint8Array) expiryOutcome.data.fill(0);
    assert.equal(genuineAeadBeforePoison, true,
      "the real encrypted file was opened before the callback poisoned Array.some");
    assert.equal(authorityReadsWithPoison, 3,
      "the malicious method replacement occurred on the final independent authority read");
    assert.equal(poisonInstalled, true);
    assert.equal(realExpiryObserved, true,
      "a real deadline must pass after AES-GCM, before Date.now rolls backwards");
    assert.ok(expiryOutcome instanceof Error
      && /ZK_SHARE_FILE_OPEN_DENIED/.test(expiryOutcome.message),
    "a real expired Ed25519 share must deny despite Date.now rollback and forged Array.some");
    await assert.rejects(openProtectedRecipientShareFile({ ...bridgeArgs,
      redeemInput: { ...recipientShareInput, grant: { ...grant,
        shareSignatureBase64: b64(crypto.randomBytes(64)) } },
    }), /ZK_SHARE_FILE_OPEN_DENIED/, "a forged share proof cannot be rescued by a valid CEK");
    await assert.rejects(openProtectedRecipientShareFile({ ...bridgeArgs,
      envelope: { ...envelope, core: { ...envelope.core,
        ciphertext_sha256: b64(crypto.randomBytes(32)) } },
    }), /ZK_SHARE_FILE_OPEN_DENIED/, "a valid recipient key cannot cross a ciphertext digest");
    await assert.rejects(openProtectedRecipientShareFile({ ...bridgeArgs,
      envelope: { ...envelope, core: { ...envelope.core,
        device_id: "other-device" } },
    }), /ZK_SHARE_FILE_OPEN_DENIED/, "no recipient-device substitution");
    await assert.rejects(openProtectedRecipientShareFile({ ...bridgeArgs,
      metadata: { ...metadata, account_id: b64(crypto.randomBytes(16)) },
    }), /ZK_SHARE_FILE_OPEN_DENIED/, "owner-approved CEK cannot cross tenant");
    await assert.rejects(openProtectedRecipientShareFile({ ...bridgeArgs,
      envelope: { ...envelope, core: { ...envelope.core, object_revision: 2 } },
    }), /ZK_SHARE_FILE_OPEN_DENIED/, "a CEK transfer for a different revision is not share access");
    await assert.rejects(openProtectedRecipientShareFile({ ...bridgeArgs,
      redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => ({
        ...await readIndependentAuthority(), head: {
          ...(await readIndependentAuthority()).head, epoch: metadata.epoch + 1 },
      }) },
    }), /ZK_SHARE_FILE_OPEN_DENIED/, "advanced independent epoch blocks local file release");
    let authorityReads = 0;
    await assert.rejects(openProtectedRecipientShareFile({ ...bridgeArgs,
      redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => {
        const current = await readIndependentAuthority();
        if (++authorityReads === 3) {
          current.devices.find((device) =>
            device.deviceId === originalDevice.device_id).revokedAtEpoch = metadata.epoch;
        }
        return current;
      } },
    }), /ZK_SHARE_FILE_OPEN_DENIED/,
    "issuer revoked during HPKE/file AEAD awaits cannot yield plaintext");
    assert.equal(authorityReads, 3,
      "additional current authority check must occur after owner CEK and file AEAD");
    // P2: an independently signed reader is entrusted at entry, but its OWN
    // callback can replace the caller-owned function property during the
    // second awaited read. The actual original reader detects revocation
    // after file AEAD on its third call; a replacement returns stale authority.
    const readerAttack = { ...recipientShareInput };
    const realDecryptForReader = subtle.decrypt;
    let readerAeadFinished = false, realReaderCalls = 0, staleReaderCalls = 0;
    let issuerRevokedOnThirdReader = false;
    subtle.decrypt = async function (...args) {
      const openedFile = await realDecryptForReader.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) readerAeadFinished = true;
      return openedFile;
    };
    readerAttack.readIndependentAuthority = async function () {
      const current = await readIndependentAuthority();
      realReaderCalls++;
      if (realReaderCalls === 2) {
        readerAttack.readIndependentAuthority = async function () {
          staleReaderCalls++;
          // This stale callback still returns a valid-looking previously
          // active owner-signed roster; only the original would see revocation.
          return readIndependentAuthority();
        };
      }
      if (realReaderCalls === 3) {
        assert.equal(readerAeadFinished, true,
          "third real authority read must be after genuine file AES-GCM");
        const issuer = current.devices.find((entry) =>
          entry.deviceId === originalDevice.device_id);
        assert.ok(issuer);
        issuer.revokedAtEpoch = metadata.epoch;
        issuerRevokedOnThirdReader = true;
      }
      return current;
    };
    let swappedReaderOutcome;
    try {
      swappedReaderOutcome = await openProtectedRecipientShareFile({
        ...bridgeArgs, redeemInput: readerAttack,
      }).then((result) => result, (error) => error);
    } finally { delete subtle.decrypt; }
    if (swappedReaderOutcome?.data instanceof Uint8Array) swappedReaderOutcome.data.fill(0);
    assert.equal(realReaderCalls, 3,
      "the originally trusted independent reader must run at final release");
    assert.equal(readerAeadFinished, true,
      "attack must traverse real owner HPKE and local file AES");
    assert.equal(issuerRevokedOnThirdReader, true,
      "genuine third authority reading must contain revoked issuer");
    assert.equal(staleReaderCalls, 0,
      "an awaited read may not substitute a stale authority implementation");
    assert.ok(swappedReaderOutcome instanceof Error
      && /ZK_SHARE_FILE_OPEN_DENIED/.test(swappedReaderOutcome.message),
    "a newly revoked issuer cannot release plaintext via callback reference swap");
    // P2 RED-on-parent: a callback returns a genuinely REVOKED current issuer
    // after genuine share signatures, HTTP/SQLite-reopened ciphertext,
    // recipient HPKE and file AES-GCM have all succeeded. A poisoned filter must not let
    // currentAuthority() replace that roster with an attacker-chosen old view.
    const nativeFilter = Array.prototype.filter;
    const nativeDecrypt = subtle.decrypt;
    let finalAeadBeforeRevocation = false;
    let readsWithRevocation = 0;
    let revocationReturned = false;
    let attackerFilterCalls = 0;
    let revokedRoster;
    let falselyActiveRoster;
    subtle.decrypt = async function (...args) {
      const result = await nativeDecrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) {
        finalAeadBeforeRevocation = true;
      }
      return result;
    };
    let filterAttackOutcome;
    try {
      filterAttackOutcome = await openProtectedRecipientShareFile({ ...bridgeArgs,
        redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => {
          const current = await readIndependentAuthority();
          if (++readsWithRevocation === 3) {
            assert.equal(finalAeadBeforeRevocation, true,
              "the real file AEAD must finish before the third authority read");
            const issuer = current.devices.find((device) =>
              device.deviceId === originalDevice.device_id);
            assert.ok(issuer, "the independently verified current roster contains the real issuer");
            issuer.revokedAtEpoch = metadata.epoch;
            revocationReturned = true;
            revokedRoster = current.devices;
            falselyActiveRoster = current.devices.map((device) => ({
              ...device, revokedAtEpoch: null,
            }));
            Array.prototype.filter = function (predicate, thisArg) {
              if (this === revokedRoster) {
                attackerFilterCalls++;
                return Reflect.apply(nativeFilter, falselyActiveRoster,
                  [predicate, thisArg]);
              }
              return Reflect.apply(nativeFilter, this, [predicate, thisArg]);
            };
          }
          return current;
        } },
      }).then((value) => value, (error) => error);
    } finally {
      Array.prototype.filter = nativeFilter;
      delete subtle.decrypt;
    }
    if (filterAttackOutcome?.data instanceof Uint8Array) filterAttackOutcome.data.fill(0);
    assert.equal(finalAeadBeforeRevocation, true,
      "P2 fixture must run signed share and real HPKE+file AES-GCM before poisoning");
    assert.equal(readsWithRevocation, 3,
      "the bad native filter is installed only for the final independent read");
    assert.equal(revocationReturned, true,
      "the final callback must return a genuinely revoked issuer, not a fake active snapshot");
    assert.equal(revokedRoster?.find((device) =>
      device.deviceId === originalDevice.device_id)?.revokedAtEpoch, metadata.epoch,
    "the final authority result really contains the revoked issuer epoch");
    assert.equal(attackerFilterCalls, 0,
      "the release fence may not call a rebound Array.prototype.filter");
    assert.ok(filterAttackOutcome instanceof Error
      && /ZK_SHARE_FILE_OPEN_DENIED/.test(filterAttackOutcome.message),
    "a revoked issuer may not release plaintext by swapping the roster filter");
    // Native Array#filter is NOT a sufficient fix. On the returned current
    // authority roster it consults constructor[Symbol.species], which can
    // manufacture a Proxy output and replace the genuinely revoked issuer
    // with an active clone. This bypasses even a captured native filter.
    let speciesAuthorityReads = 0, speciesInvocations = 0, forgedHits = 0;
    let speciesAeadCompleted = false, signedRosterRevoked = false;
    const speciesDecrypt = subtle.decrypt;
    subtle.decrypt = async function (...args) {
      const openedFile = await speciesDecrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) speciesAeadCompleted = true;
      return openedFile;
    };
    let speciesOutcome;
    try {
      speciesOutcome = await openProtectedRecipientShareFile({ ...bridgeArgs,
        redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => {
          const current = await readIndependentAuthority();
          if (++speciesAuthorityReads === 3) {
            assert.equal(speciesAeadCompleted, true,
              "real AES-GCM must finish before the hostile final roster");
            const issuer = current.devices.find((entry) =>
              entry.deviceId === originalDevice.device_id);
            assert.ok(issuer);
            issuer.revokedAtEpoch = metadata.epoch;
            signedRosterRevoked = true;
            Object.defineProperty(current.devices, "constructor", { value: {
              [Symbol.species]: function ForgedFilteredRoster() {
                speciesInvocations++;
                return new Proxy([], { defineProperty(target, prop, descriptor) {
                  if (typeof prop === "string" && /^\d+$/.test(prop)
                    && Object.hasOwn(descriptor, "value")) {
                    forgedHits++;
                    return Reflect.defineProperty(target, prop, { ...descriptor,
                      value: { ...descriptor.value, revokedAtEpoch: null } });
                  }
                  return Reflect.defineProperty(target, prop, descriptor);
                } });
              },
            } });
          }
          return current;
        } },
      }).then((value) => value, (error) => error);
    } finally { delete subtle.decrypt; }
    if (speciesOutcome?.data instanceof Uint8Array) speciesOutcome.data.fill(0);
    assert.equal(speciesAeadCompleted, true,
      "species adversary must reach real owner HPKE and file AES-GCM");
    assert.equal(speciesAuthorityReads, 3,
      "species poison applies exclusively after the last authority await");
    assert.equal(signedRosterRevoked, true,
      "the actual returned authority list still contains a revoked issuer");
    assert.equal(speciesInvocations, 0,
      "final revocation fence cannot construct attacker-defined filter species");
    assert.equal(forgedHits, 0,
      "no malicious species result may turn a revoked issuer into active");
    assert.ok(speciesOutcome instanceof Error
      && /ZK_SHARE_FILE_OPEN_DENIED/.test(speciesOutcome.message),
    "a revoked issuer must deny plaintext even with a forged filter species");
    // P2 RED on the previous descriptor-only patch: the REAL Uint8Array key
    // of the recipient owns a malicious `length` getter and iterator. Reading
    // either while checking B runs attacker JS that revives the genuinely
    // revoked issuer A before A's independent signature check. A native
    // typed-array byte copy must never dispatch either property.
    let poisonedKeyReads = 0, poisonedIteratorRuns = 0;
    let typedKeyAuthorityReads = 0, typedKeyAeadCompleted = false;
    let revokedIssuerReturned = false, finalIssuer;
    const typedKeyDecrypt = subtle.decrypt;
    subtle.decrypt = async function (...args) {
      const openedFile = await typedKeyDecrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) typedKeyAeadCompleted = true;
      return openedFile;
    };
    const actualUint8Iterator = Uint8Array.prototype[Symbol.iterator];
    let typedKeyOutcome;
    try {
      typedKeyOutcome = await openProtectedRecipientShareFile({ ...bridgeArgs,
        redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => {
          const current = await readIndependentAuthority();
          if (++typedKeyAuthorityReads === 3) {
            assert.equal(typedKeyAeadCompleted, true,
              "genuine file AES-GCM completes before the third roster is read");
            finalIssuer = current.devices.find((entry) =>
              entry.deviceId === originalDevice.device_id);
            const recipient = current.devices.find((entry) =>
              entry.deviceId === fresh.request.device_id);
            assert.ok(finalIssuer && recipient);
            finalIssuer.revokedAtEpoch = metadata.epoch;
            revokedIssuerReturned = true;
            assert.ok(recipient.authorizationPublicKey instanceof Uint8Array);
            assert.equal(recipient.authorizationPublicKey.byteLength, 32);
            Object.defineProperty(recipient.authorizationPublicKey, "length", { get() {
              poisonedKeyReads++;
              finalIssuer.revokedAtEpoch = null;
              return 32;
            } });
            Object.defineProperty(recipient.authorizationPublicKey, Symbol.iterator, {
              value: function () {
                poisonedIteratorRuns++;
                finalIssuer.revokedAtEpoch = null;
                return Reflect.apply(actualUint8Iterator, this, []);
              },
            });
          }
          return current;
        } },
      }).then((value) => value, (error) => error);
    } finally { delete subtle.decrypt; }
    if (typedKeyOutcome?.data instanceof Uint8Array) typedKeyOutcome.data.fill(0);
    assert.equal(typedKeyAeadCompleted, true,
      "the getter adversary must pass real signed share, HPKE and AES-GCM");
    assert.equal(typedKeyAuthorityReads, 3,
      "malicious typed key is installed only for the final authority check");
    assert.equal(revokedIssuerReturned, true,
      "the independent authority must return an actually revoked issuer");
    assert.equal(poisonedKeyReads, 0,
      "native key snapshot must not execute attacker-owned typed-array length getter");
    assert.equal(poisonedIteratorRuns, 0,
      "native key snapshot must not run attacker-owned Symbol.iterator");
    assert.equal(finalIssuer?.revokedAtEpoch, metadata.epoch,
      "issuer must remain revoked after the final local key check");
    assert.ok(typedKeyOutcome instanceof Error
      && /ZK_SHARE_FILE_OPEN_DENIED/.test(typedKeyOutcome.message),
    "recipient's malicious real Uint8Array cannot revive the issuer and release plaintext");
    // P2 RED-on-previous-patch: final head.digest is ALSO a caller-supplied
    // real Uint8Array. Buffer.from(digest) consults a hostile own valueOf
    // before active(recipient) / active(issuer), reviving the signed issuer
    // even though the third independent authority read returned it revoked.
    let headDigestAuthorityReads = 0, headDigestAeadCompleted = false;
    let headDigestValueOfReads = 0, headDigestLengthReads = 0;
    let headDigestIssuerRevoked = false, headDigestIssuer;
    const headDigestDecrypt = subtle.decrypt;
    subtle.decrypt = async function (...args) {
      const openedFile = await headDigestDecrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) headDigestAeadCompleted = true;
      return openedFile;
    };
    let headDigestOutcome;
    try {
      headDigestOutcome = await openProtectedRecipientShareFile({ ...bridgeArgs,
        redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => {
          const current = await readIndependentAuthority();
          if (++headDigestAuthorityReads === 3) {
            assert.equal(headDigestAeadCompleted, true,
              "file AES-GCM must complete before the malicious final head digest");
            headDigestIssuer = current.devices.find((entry) =>
              entry.deviceId === originalDevice.device_id);
            assert.ok(headDigestIssuer, "current independent roster contains real issuer");
            headDigestIssuer.revokedAtEpoch = metadata.epoch;
            headDigestIssuerRevoked = true;
            const trueDigest = Uint8Array.from(current.head.digest);
            assert.equal(trueDigest.byteLength, 32);
            assert.ok(current.head.digest instanceof Uint8Array,
              "head digest must be a genuine native Uint8Array, not a fake dictionary");
            Object.defineProperty(current.head.digest, "valueOf", { value() {
              headDigestValueOfReads++;
              headDigestIssuer.revokedAtEpoch = null;
              return trueDigest;
            } });
            Object.defineProperty(current.head.digest, "length", { get() {
              headDigestLengthReads++;
              headDigestIssuer.revokedAtEpoch = null;
              return 32;
            } });
          }
          return current;
        } },
      }).then((value) => value, (error) => error);
    } finally { delete subtle.decrypt; }
    if (headDigestOutcome?.data instanceof Uint8Array) headDigestOutcome.data.fill(0);
    assert.equal(headDigestAeadCompleted, true,
      "head-digest attack must reach real Ed25519 share, HPKE and AES-GCM");
    assert.equal(headDigestAuthorityReads, 3,
      "head digest is poisoned only for the final independent authority read");
    assert.equal(headDigestIssuerRevoked, true,
      "final authority must return a genuinely revoked signed issuer");
    assert.equal(headDigestValueOfReads, 0,
      "native head-digest copy may not dispatch an attacker-owned valueOf");
    assert.equal(headDigestLengthReads, 0,
      "native head-digest copy may not run an attacker-owned length getter");
    assert.equal(headDigestIssuer?.revokedAtEpoch, metadata.epoch,
      "head digest conversion cannot revive the final signed issuer");
    assert.ok(headDigestOutcome instanceof Error
      && /ZK_SHARE_FILE_OPEN_DENIED/.test(headDigestOutcome.message),
    "revoked issuer must block local plaintext despite malicious head digest");
    // P2 RED on the preceding native-copy fix: Buffer#equals is still looked
    // up after the third (revoked) independent roster read. Calling the real
    // equality operation does not make a malicious method side-effect-free.
    const originalBufferEquals = Buffer.prototype.equals;
    const bufferEqualsDecrypt = subtle.decrypt;
    let equalsAuthorityReads = 0, equalsFileAeadCompleted = false;
    let equalsIssuerRevoked = false, equalsIssuer, interceptedEqualsCalls = 0;
    subtle.decrypt = async function (...args) {
      const result = await bufferEqualsDecrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) equalsFileAeadCompleted = true;
      return result;
    };
    let equalsOutcome;
    try {
      equalsOutcome = await openProtectedRecipientShareFile({ ...bridgeArgs,
        redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => {
          const current = await readIndependentAuthority();
          if (++equalsAuthorityReads === 3) {
            assert.equal(equalsFileAeadCompleted, true,
              "real AES-GCM must finish before overriding Buffer#equals");
            equalsIssuer = current.devices.find((entry) =>
              entry.deviceId === originalDevice.device_id);
            assert.ok(equalsIssuer, "the genuine current roster contains the issuer");
            equalsIssuer.revokedAtEpoch = metadata.epoch;
            equalsIssuerRevoked = true;
            Buffer.prototype.equals = function (other) {
              interceptedEqualsCalls++;
              equalsIssuer.revokedAtEpoch = null;
              // Honest equality and authentic signed head stay intact; only
              // the revocation side effect makes the old release unsafe.
              return Reflect.apply(originalBufferEquals, this, [other]);
            };
          }
          return current;
        } },
      }).then((value) => value, (error) => error);
    } finally {
      Buffer.prototype.equals = originalBufferEquals;
      delete subtle.decrypt;
    }
    if (equalsOutcome?.data instanceof Uint8Array) equalsOutcome.data.fill(0);
    assert.equal(equalsFileAeadCompleted, true,
      "equals adversary must reach the real signed Ed25519+HPKE+file AES-GCM path");
    assert.equal(equalsAuthorityReads, 3,
      "the hostile equality method applies only after the third independent read");
    assert.equal(equalsIssuerRevoked, true,
      "independent authority must actually report a revoked signed issuer");
    assert.equal(interceptedEqualsCalls, 0,
      "final authority must not dispatch rebound Buffer.prototype.equals");
    assert.equal(equalsIssuer?.revokedAtEpoch, metadata.epoch,
      "mutable Buffer equality must not revive the issuer");
    assert.ok(equalsOutcome instanceof Error
      && /ZK_SHARE_FILE_OPEN_DENIED/.test(equalsOutcome.message),
    "revoked issuer must deny plaintext despite malicious Buffer#equals");
    // One adjacent reachable P2: scope checks run AFTER the hostile third
    // callback too. The old b64() dynamically dispatched Buffer.from and
    // Buffer#toString before active(issuer); both can revive a revoked signer
    // while returning the completely honest signed scope bytes.
    const originalBufferFrom = Buffer.from;
    const originalBufferToString = Buffer.prototype.toString;
    const scopeB64Decrypt = subtle.decrypt;
    let scopeB64AuthorityReads = 0, scopeB64FileAeadCompleted = false;
    let scopeB64IssuerRevoked = false, scopeB64Issuer;
    let spoofedFromCalls = 0, spoofedToStringCalls = 0;
    subtle.decrypt = async function (...args) {
      const result = await scopeB64Decrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) scopeB64FileAeadCompleted = true;
      return result;
    };
    let scopeB64Outcome;
    try {
      scopeB64Outcome = await openProtectedRecipientShareFile({ ...bridgeArgs,
        redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => {
          const current = await readIndependentAuthority();
          if (++scopeB64AuthorityReads === 3) {
            assert.equal(scopeB64FileAeadCompleted, true,
              "real AES-GCM must finish before poisoning scope encoding");
            scopeB64Issuer = current.devices.find((entry) =>
              entry.deviceId === originalDevice.device_id);
            assert.ok(scopeB64Issuer);
            scopeB64Issuer.revokedAtEpoch = metadata.epoch;
            scopeB64IssuerRevoked = true;
            Buffer.from = function (...args) {
              spoofedFromCalls++;
              scopeB64Issuer.revokedAtEpoch = null;
              return Reflect.apply(originalBufferFrom, Buffer, args);
            };
            Buffer.prototype.toString = function (...args) {
              spoofedToStringCalls++;
              scopeB64Issuer.revokedAtEpoch = null;
              return Reflect.apply(originalBufferToString, this, args);
            };
          }
          return current;
        } },
      }).then((value) => value, (error) => error);
    } finally {
      Buffer.from = originalBufferFrom;
      Buffer.prototype.toString = originalBufferToString;
      delete subtle.decrypt;
    }
    if (scopeB64Outcome?.data instanceof Uint8Array) scopeB64Outcome.data.fill(0);
    assert.equal(scopeB64FileAeadCompleted, true,
      "scope-b64 adversary must reach real signed share, HPKE, file AES-GCM");
    assert.equal(scopeB64AuthorityReads, 3,
      "scope globals are poisoned only on the third independent read");
    assert.equal(scopeB64IssuerRevoked, true,
      "the final independent roster must contain a revoked issuer");
    assert.equal(spoofedFromCalls, 0,
      "final scope check must not call a rebound global Buffer.from");
    assert.equal(spoofedToStringCalls, 0,
      "final scope check must not call a rebound Buffer.prototype.toString");
    assert.equal(scopeB64Issuer?.revokedAtEpoch, metadata.epoch,
      "scope normalization must not un-revoke the issuer");
    assert.ok(scopeB64Outcome instanceof Error
      && /ZK_SHARE_FILE_OPEN_DENIED/.test(scopeB64Outcome.message),
    "a revoked issuer must deny plaintext despite poisoned scope encoding");
    // Final issuer signature verification is also on the same post-await
    // release path. A callback can substitute a DIFFERENT valid Ed25519 key
    // in the third roster and monkeypatch crypto.verify() to return true.
    // Its signed share remains authentic only under the ORIGINAL issuer key.
    const substitutedIssuer = crypto.generateKeyPairSync("ed25519");
    const substitutedIssuerRaw = Uint8Array.from(pub(substitutedIssuer.publicKey));
    assert.equal(crypto.verify(null, message, substitutedIssuer.publicKey,
      Buffer.from(grant.shareSignatureBase64, "base64url")), false,
    "control: genuine signed share must NOT verify under substituted issuer key");
    const originalCreatePublicKey = crypto.createPublicKey;
    const originalVerify = crypto.verify;
    const originalBufferConcat = Buffer.concat;
    const signatureDecrypt = subtle.decrypt;
    let signatureAuthorityReads = 0, signatureAeadCompleted = false;
    let signerSubstituted = false, spoofedVerifyCalls = 0;
    let spoofedCreateKeyCalls = 0, spoofedConcatCalls = 0;
    subtle.decrypt = async function (...args) {
      const result = await signatureDecrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) signatureAeadCompleted = true;
      return result;
    };
    let signatureOutcome;
    try {
      signatureOutcome = await openProtectedRecipientShareFile({ ...bridgeArgs,
        redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => {
          const current = await readIndependentAuthority();
          if (++signatureAuthorityReads === 3) {
            assert.equal(signatureAeadCompleted, true,
              "real AES-GCM must finish before the forged signature boundary");
            const currentIssuer = current.devices.find((entry) =>
              entry.deviceId === originalDevice.device_id);
            assert.ok(currentIssuer && currentIssuer.revokedAtEpoch === null);
            currentIssuer.authorizationPublicKey = substitutedIssuerRaw;
            signerSubstituted = true;
            crypto.createPublicKey = function (...args) {
              spoofedCreateKeyCalls++;
              return Reflect.apply(originalCreatePublicKey, crypto, args);
            };
            Buffer.concat = function (...args) {
              spoofedConcatCalls++;
              return Reflect.apply(originalBufferConcat, Buffer, args);
            };
            crypto.verify = function () {
              spoofedVerifyCalls++;
              return true;
            };
          }
          return current;
        } },
      }).then((value) => value, (error) => error);
    } finally {
      crypto.createPublicKey = originalCreatePublicKey;
      Buffer.concat = originalBufferConcat;
      crypto.verify = originalVerify;
      delete subtle.decrypt;
    }
    if (signatureOutcome?.data instanceof Uint8Array) signatureOutcome.data.fill(0);
    assert.equal(signatureAeadCompleted, true,
      "signature spoof must traverse real signed share, owner HPKE, file AEAD");
    assert.equal(signatureAuthorityReads, 3,
      "signature monkeypatch must occur only after third independent read");
    assert.equal(signerSubstituted, true,
      "third authority must really contain a different native Ed25519 key");
    assert.equal(spoofedVerifyCalls, 0,
      "final signature check must not call rebound crypto.verify");
    assert.equal(spoofedCreateKeyCalls, 0,
      "final signature check must not call rebound crypto.createPublicKey");
    assert.equal(spoofedConcatCalls, 0,
      "final signature check must not call rebound Buffer.concat");
    assert.ok(signatureOutcome instanceof Error
      && /ZK_SHARE_FILE_OPEN_DENIED/.test(signatureOutcome.message),
    "a replaced issuer key must not authenticate an old genuine share");
    // The final native-byte and enrollment validators must not re-read a
    // callback-rebound Number.isSafeInteger before testing issuer revocation.
    const originalIsSafeInteger = Number.isSafeInteger;
    const numericDecrypt = subtle.decrypt;
    let numericAuthorityReads = 0, numericAeadCompleted = false;
    let numericIssuerRevoked = false, numericIssuer, numericSpoofCalls = 0;
    subtle.decrypt = async function (...args) {
      const result = await numericDecrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) numericAeadCompleted = true;
      return result;
    };
    let numericOutcome;
    try {
      numericOutcome = await openProtectedRecipientShareFile({ ...bridgeArgs,
        redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => {
          const current = await readIndependentAuthority();
          if (++numericAuthorityReads === 3) {
            assert.equal(numericAeadCompleted, true);
            numericIssuer = current.devices.find((entry) =>
              entry.deviceId === originalDevice.device_id);
            assert.ok(numericIssuer);
            numericIssuer.revokedAtEpoch = metadata.epoch;
            numericIssuerRevoked = true;
            Number.isSafeInteger = function (value) {
              numericSpoofCalls++;
              numericIssuer.revokedAtEpoch = null;
              return Reflect.apply(originalIsSafeInteger, Number, [value]);
            };
          }
          return current;
        } },
      }).then((value) => value, (error) => error);
    } finally {
      Number.isSafeInteger = originalIsSafeInteger;
      delete subtle.decrypt;
    }
    if (numericOutcome?.data instanceof Uint8Array) numericOutcome.data.fill(0);
    assert.equal(numericAeadCompleted, true,
      "numeric spoof must reach real signed share, HPKE and file AEAD");
    assert.equal(numericAuthorityReads, 3);
    assert.equal(numericIssuerRevoked, true,
      "final independent authority must report a genuinely revoked issuer");
    assert.equal(numericSpoofCalls, 0,
      "final roster check must not call rebound Number.isSafeInteger");
    assert.equal(numericIssuer?.revokedAtEpoch, metadata.epoch);
    assert.ok(numericOutcome instanceof Error
      && /ZK_SHARE_FILE_OPEN_DENIED/.test(numericOutcome.message),
    "numeric intrinsic spoof must not reauthorize the revoked issuer");
    // P2: the final authority callback may also rebind Object.freeze.
    // It must not be allowed to forge DEV-OFF policy flags on a VALID,
    // otherwise successful plaintext result after the real file AEAD.
    const originalFreeze = Object.freeze;
    const freezeDecrypt = subtle.decrypt;
    let freezeAuthorityReads = 0, freezeAeadCompleted = false, forgedReleaseCalls = 0;
    subtle.decrypt = async function (...args) {
      const openedFile = await freezeDecrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) freezeAeadCompleted = true;
      return openedFile;
    };
    let freezeOutcome;
    try {
      freezeOutcome = await openProtectedRecipientShareFile({ ...bridgeArgs,
        redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => {
          const current = await readIndependentAuthority();
          if (++freezeAuthorityReads === 3) {
            assert.equal(freezeAeadCompleted, true,
              "real HPKE and file AES must finish before final release");
            const issuer = current.devices.find((entry) =>
              entry.deviceId === originalDevice.device_id);
            assert.ok(issuer && issuer.revokedAtEpoch === null,
              "positive control uses a genuinely active signed issuer");
            Object.freeze = function (value) {
              if (value?.schema === "rootark-zk1-recipient-share-file-dev/v1") {
                forgedReleaseCalls++;
                return { ...value, serverRevocationProofVerified: true,
                  externalCustodyProven: true, authorizesProductionIo: true };
              }
              return Reflect.apply(originalFreeze, Object, [value]);
            };
          }
          return current;
        } },
      }).then((value) => value, (error) => error);
    } finally {
      Object.freeze = originalFreeze;
      delete subtle.decrypt;
    }
    assert.equal(freezeAuthorityReads, 3,
      "policy flag attack must occur on final independent authority read");
    assert.equal(freezeAeadCompleted, true,
      "policy flag test must reach real signed share and AES file decrypt");
    assert.ok(freezeOutcome && !(freezeOutcome instanceof Error)
      && freezeOutcome.data instanceof Uint8Array && freezeOutcome.data.length > 0,
    "positive control must actually release a nonempty decrypted file");
    assert.equal(forgedReleaseCalls, 0,
      "the release boundary may not dispatch callback-rebound Object.freeze");
    assert.equal(freezeOutcome.serverRevocationProofVerified, false);
    assert.equal(freezeOutcome.externalCustodyProven, false);
    assert.equal(freezeOutcome.authorizesProductionIo, false);
    freezeOutcome.data.fill(0);
    // P2: even a PINNED Buffer.from(view) dispatches the raw Uint8Array's
    // inherited valueOf in Node22. The signed CBOR scope bytes are genuine,
    // but a poisoned Uint8Array.prototype.valueOf can un-revoke a real issuer
    // before active(issuer) if the final scope b64 reads that raw view.
    const priorTypedValueOf = Object.getOwnPropertyDescriptor(Uint8Array.prototype, "valueOf");
    const scopeBytesDecrypt = subtle.decrypt;
    let scopeBytesReads = 0, scopeBytesAead = false, scopeBytesIssuer;
    let scopeBytesSpoofCalls = 0;
    subtle.decrypt = async function (...args) {
      const result = await scopeBytesDecrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) scopeBytesAead = true;
      return result;
    };
    let scopeBytesOutcome;
    try {
      scopeBytesOutcome = await openProtectedRecipientShareFile({ ...bridgeArgs,
        redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => {
          const current = await readIndependentAuthority();
          if (++scopeBytesReads === 3) {
            assert.equal(scopeBytesAead, true,
              "scope byte poison must follow genuine HPKE and file AEAD");
            scopeBytesIssuer = current.devices.find((entry) =>
              entry.deviceId === originalDevice.device_id);
            assert.ok(scopeBytesIssuer);
            scopeBytesIssuer.revokedAtEpoch = metadata.epoch;
            Uint8Array.prototype.valueOf = function () {
              scopeBytesSpoofCalls++;
              scopeBytesIssuer.revokedAtEpoch = null;
              return this;
            };
          }
          return current;
        } },
      }).then((value) => value, (error) => error);
    } finally {
      if (priorTypedValueOf) Object.defineProperty(Uint8Array.prototype, "valueOf", priorTypedValueOf);
      else delete Uint8Array.prototype.valueOf;
      delete subtle.decrypt;
    }
    if (scopeBytesOutcome?.data instanceof Uint8Array) scopeBytesOutcome.data.fill(0);
    assert.equal(scopeBytesReads, 3,
      "scope poisoning must occur only at the last independent authority read");
    assert.equal(scopeBytesAead, true);
    assert.equal(scopeBytesSpoofCalls, 0,
      "final scope serialization may not call callback-poisoned Uint8Array.valueOf");
    assert.equal(scopeBytesIssuer?.revokedAtEpoch, metadata.epoch,
      "authentic revoked issuer must remain revoked throughout scope encoding");
    assert.ok(scopeBytesOutcome instanceof Error
      && /ZK_SHARE_FILE_OPEN_DENIED/.test(scopeBytesOutcome.message),
    "real revoked issuer must deny plaintext despite poisoned typed-array prototypes");
    // P2: an adverse last authority read that DENIES plaintext must still
    // wipe the real intermediate CEK and decrypted bytes. Rebound .fill
    // methods must never be able to turn that cleanup into a no-op.
    const previousOwnerFreeze = Object.freeze;
    const previousUint8From = Uint8Array.from;
    const previousBufferFill = Buffer.prototype.fill;
    const previousTypedFill = Uint8Array.prototype.fill;
    const cleanupDecrypt = subtle.decrypt;
    let capturedCek, capturedPlaintext, cleanupReads = 0;
    let cleanupAeadCompleted = false, cleanupRevoked = false;
    let spoofedBufferFill = 0, spoofedTypedFill = 0;
    // The file-content export is frozen. Observe genuine internal allocations
    // at their existing native construction boundaries instead of replacing
    // the module's read-only methods or fabricating plaintext.
    Object.freeze = function (value) {
      if (value?.cek instanceof Uint8Array
        && value.authorizesProductionRestore === false
        && Number.isSafeInteger(value.verifiedReleaseExpiresAt)) {
        capturedCek = value.cek;
      }
      return Reflect.apply(previousOwnerFreeze, Object, [value]);
    };
    Uint8Array.from = function (...args) {
      const nativeResult = Reflect.apply(previousUint8From, Uint8Array, args);
      if (nativeResult.length === bytes.length
        && nativeResult.every((byte, index) => byte === bytes[index])) {
        capturedPlaintext = nativeResult;
      }
      return nativeResult;
    };
    subtle.decrypt = async function (...args) {
      const openedFile = await cleanupDecrypt.apply(this, args);
      if (args[0]?.name === "AES-GCM"
        && args[2]?.byteLength === fileAeadCipherLength) cleanupAeadCompleted = true;
      return openedFile;
    };
    let cleanupOutcome;
    try {
      cleanupOutcome = await openProtectedRecipientShareFile({ ...bridgeArgs,
        redeemInput: { ...recipientShareInput, readIndependentAuthority: async () => {
          const current = await readIndependentAuthority();
          if (++cleanupReads === 3) {
            assert.equal(cleanupAeadCompleted, true,
              "a genuine file AEAD must finish before denied cleanup");
            assert.ok(capturedCek instanceof Uint8Array
              && capturedCek.some((byte) => byte !== 0),
            "real opened CEK must contain nonzero secret before denial");
            assert.ok(capturedPlaintext instanceof Uint8Array
              && capturedPlaintext.some((byte) => byte !== 0),
            "real decrypted file must contain bytes before denial");
            const issuer = current.devices.find((entry) =>
              entry.deviceId === originalDevice.device_id);
            assert.ok(issuer);
            issuer.revokedAtEpoch = metadata.epoch;
            cleanupRevoked = true;
            Buffer.prototype.fill = function () { spoofedBufferFill++; return this; };
            Uint8Array.prototype.fill = function () { spoofedTypedFill++; return this; };
          }
          return current;
        } },
      }).then((value) => value, (error) => error);
    } finally {
      Buffer.prototype.fill = previousBufferFill;
      Uint8Array.prototype.fill = previousTypedFill;
      Object.freeze = previousOwnerFreeze;
      Uint8Array.from = previousUint8From;
      delete subtle.decrypt;
    }
    assert.equal(cleanupReads, 3);
    assert.equal(cleanupRevoked, true);
    assert.ok(cleanupOutcome instanceof Error
      && /ZK_SHARE_FILE_OPEN_DENIED/.test(cleanupOutcome.message),
    "a genuinely revoked issuer must deny the final plaintext release");
    assert.equal(spoofedBufferFill, 0);
    assert.equal(spoofedTypedFill, 0);
    assert.ok(capturedCek instanceof Uint8Array
      && capturedCek.every((byte) => byte === 0),
    "denied share must wipe the opened native CEK even after fill rebinding");
    assert.ok(capturedPlaintext instanceof Uint8Array
      && capturedPlaintext.every((byte) => byte === 0),
    "denied share must wipe the actual decrypted buffer even after fill rebinding");
    // This proof covers the three explicitly owner-selected versions, never
    // unknown historical versions or externally held backup copies.
    assert.equal(typeof cekBatch.sealOwnerAuthorizedVersionedCeks, "function",
      "missing owner-signed multi-object, per-version CEK handoff");
    const secondMeta = { ...metadata, version_id: b64(crypto.randomBytes(16)),
      parent_version_id: metadata.version_id };
    const otherMeta = { ...metadata, object_id: b64(crypto.randomBytes(16)),
      version_id: b64(crypto.randomBytes(16)), parent_version_id: null };
    const secondCek = crypto.randomBytes(32), otherCek = crypto.randomBytes(32);
    const secondCiphertext = await content.encryptFile({
      cek: await content.importFileCek(secondCek), metadata: secondMeta,
      name: "historical-r2.txt", mediaType: "text/plain", data: Buffer.from("revision-2") });
    const otherCiphertext = await content.encryptFile({
      cek: await content.importFileCek(otherCek), metadata: otherMeta,
      name: "other-file.txt", mediaType: "text/plain", data: Buffer.from("other-object") });
    const versionRows = [
      { metadata, objectRevision: 1, ciphertext: Buffer.from(sealed),
        ciphertextRoot: root, ownerHeldCek: Buffer.from(ownerHeldCek) },
      { metadata: secondMeta, objectRevision: 2,
        ciphertext: Buffer.from(secondCiphertext),
        ciphertextRoot: await ciphertextRoots.computeCiphertextRoot([secondCiphertext]),
        ownerHeldCek: Buffer.from(secondCek) },
      { metadata: otherMeta, objectRevision: 1,
        ciphertext: Buffer.from(otherCiphertext),
        ciphertextRoot: await ciphertextRoots.computeCiphertextRoot([otherCiphertext]),
        ownerHeldCek: Buffer.from(otherCek) },
    ];
    const bundle = await cekBatch.sealOwnerAuthorizedVersionedCeks({
      ownerPrivateKey: owner.privateKey, authority: publicAuthority, versions: versionRows,
      assertLive: () => undefined,
    });
    assert.equal(bundle.entries.length, 3);
    assert.equal(bundle.globalAccountCompletenessProven, false);
    assert.equal(bundle.authorizesProductionRestore, false);
    // Logout during the final real per-file owner HPKE seal must also fence
    // the signed release; every selected CEK was independently AEAD checked.
    const trueHpkeSeal = z.hpkeSeal;
    let ownerSessionLive = true, realSeals = 0;
    z.hpkeSeal = async (...args) => {
      const sealedCek = await trueHpkeSeal(...args);
      if (++realSeals === versionRows.length) ownerSessionLive = false;
      return sealedCek;
    };
    try {
      await assert.rejects(cekBatch.sealOwnerAuthorizedVersionedCeks({
        ownerPrivateKey: owner.privateKey, authority: publicAuthority,
        versions: versionRows,
        assertLive: () => { if (!ownerSessionLive) throw Error("OWNER_LOGGED_OUT"); },
      }), /ZK_OWNER_VERSIONED_CEK_BATCH_DENIED/,
      "owner logout after last genuine CEK seal must refuse the signed batch");
    } finally { z.hpkeSeal = trueHpkeSeal; }
    assert.equal(realSeals, versionRows.length,
      "owner-side revocation must occur after all genuine CEK seals");
    const openBatch = (overrides = {}) => cekBatch.openOwnerAuthorizedVersionedCeks({
      bundle, authority: { ...linked, nowSeconds: now + 9 },
      operatorMinimumSequence: signedCommittedHead.sequence,
      recipientHpkePrivateRaw: fresh.hpkePrivateRaw, nowSeconds: now + 9,
      assertLive: () => undefined,
      ...overrides,
    });
    const recoveredBatch = await openBatch();
    assert.equal(recoveredBatch.entries.length, 3);
    assert.equal(recoveredBatch.signedBatchCompletenessVerified, true);
    assert.equal(recoveredBatch.globalAccountCompletenessProven, false);
    for (const entry of recoveredBatch.entries) {
      const original = versionRows.find((row) => row.metadata.object_id === entry.metadata.object_id
        && row.objectRevision === entry.objectRevision);
      assert.ok(original);
      assert.deepEqual(entry.cek, original.ownerHeldCek);
      entry.cek.fill(0);
    }
    // A local session revoked while the LAST genuine X25519 HPKE open is
    // awaiting must never receive even the first validated historical CEK.
    // This exercises real crypto; the wrapper only schedules a local logout.
    const trueHpkeOpen = z.hpkeOpen;
    let localSessionLive = true, realOpens = 0;
    z.hpkeOpen = async (...args) => {
      const opened = await trueHpkeOpen(...args);
      if (++realOpens === versionRows.length) localSessionLive = false;
      return opened;
    };
    try {
      await assert.rejects(cekBatch.openOwnerAuthorizedVersionedCeks({
        bundle, authority: { ...linked, nowSeconds: now + 9 },
        operatorMinimumSequence: signedCommittedHead.sequence,
        recipientHpkePrivateRaw: fresh.hpkePrivateRaw, nowSeconds: now + 9,
        assertLive: () => { if (!localSessionLive) throw Error("SESSION_REVOKED"); },
      }), /ZK_OWNER_VERSIONED_CEK_BATCH_DENIED/,
      "revocation after last real HPKE open must fence all CEKs at final release");
    } finally { z.hpkeOpen = trueHpkeOpen; }
    assert.equal(realOpens, versionRows.length,
      "the test must exercise every real HPKE version before local revocation");
    // A revoked session must stop immediately, not perform unrelated file
    // decryptions or leak a successful partial result.
    localSessionLive = true; realOpens = 0;
    z.hpkeOpen = async (...args) => {
      const opened = await trueHpkeOpen(...args);
      if (++realOpens === 1) localSessionLive = false;
      return opened;
    };
    try {
      await assert.rejects(openBatch({
        assertLive: () => { if (!localSessionLive) throw Error("SESSION_REVOKED"); },
      }), /ZK_OWNER_VERSIONED_CEK_BATCH_DENIED/);
    } finally { z.hpkeOpen = trueHpkeOpen; }
    assert.equal(realOpens, 1,
      "first revoked CEK must stop later HPKE operations");
    await assert.rejects(openBatch({ assertLive: async () => undefined }),
      /ZK_OWNER_VERSIONED_CEK_BATCH_DENIED/,
    "an asynchronous local fence cannot masquerade as a final sync check");
    await assert.rejects(openBatch({ assertLive: () => false }),
      /ZK_OWNER_VERSIONED_CEK_BATCH_DENIED/,
    "a false session result cannot authorize CEK release");
    let hostileGetterRuns = 0;
    const hostileInput = { bundle, authority: { ...linked, nowSeconds: now + 9 },
      operatorMinimumSequence: signedCommittedHead.sequence,
      recipientHpkePrivateRaw: fresh.hpkePrivateRaw, nowSeconds: now + 9 };
    Object.defineProperty(hostileInput, "assertLive", {
      enumerable: true, get() { hostileGetterRuns++; throw Error("UNTRUSTED_GETTER"); },
    });
    await assert.rejects(cekBatch.openOwnerAuthorizedVersionedCeks(hostileInput),
      /ZK_OWNER_VERSIONED_CEK_BATCH_DENIED/);
    assert.equal(hostileGetterRuns, 0,
      "snapshotting trust and session callback cannot invoke hostile getters");
    for (const entries of [bundle.entries.slice(1),
      [...bundle.entries.slice(0, 2), bundle.entries[0]],
      bundle.entries.map((entry, index) => index === 1
        ? { ...entry, metadata: { ...entry.metadata,
          parent_version_id: b64(crypto.randomBytes(16)) } } : entry)]) {
      await assert.rejects(openBatch({ bundle: { ...bundle, entries } }),
        /ZK_OWNER_VERSIONED_CEK_BATCH_DENIED/,
      "owner-signed batch may never release an omitted, repeated or altered version");
    }
    const collisionMetadata = { ...otherMeta, version_id: metadata.version_id };
    const collisionCiphertext = await content.encryptFile({
      cek: await content.importFileCek(otherCek), metadata: collisionMetadata,
      name: "collision.txt", mediaType: "text/plain", data: Buffer.from("other-object") });
    await assert.rejects(cekBatch.sealOwnerAuthorizedVersionedCeks({
      ownerPrivateKey: owner.privateKey, authority: publicAuthority,
      assertLive: () => undefined,
      versions: [versionRows[0], { ...versionRows[2], metadata: collisionMetadata,
        ciphertext: Buffer.from(collisionCiphertext),
        ciphertextRoot: await ciphertextRoots.computeCiphertextRoot([collisionCiphertext]) }],
    }), /ZK_OWNER_VERSIONED_CEK_BATCH_DENIED/,
    "two distinct object UUIDs cannot reuse one version UUID in a signed recovery batch");
    const reusedCekCiphertext = await content.encryptFile({
      cek: await content.importFileCek(ownerHeldCek), metadata: otherMeta,
      name: "reused-cek.txt", mediaType: "text/plain", data: Buffer.from("same-cek-different-file") });
    await assert.rejects(cekBatch.sealOwnerAuthorizedVersionedCeks({
      ownerPrivateKey: owner.privateKey, authority: publicAuthority,
      assertLive: () => undefined,
      versions: [versionRows[0], { ...versionRows[2], ownerHeldCek: Buffer.from(ownerHeldCek),
        ciphertext: Buffer.from(reusedCekCiphertext),
        ciphertextRoot: await ciphertextRoots.computeCiphertextRoot([reusedCekCiphertext]) }],
    }), /ZK_OWNER_VERSIONED_CEK_BATCH_DENIED/,
    "two distinct historical file versions cannot reuse the same authenticated CEK");
    await assert.rejects(cekBatch.sealOwnerAuthorizedVersionedCeks({
      ownerPrivateKey: owner.privateKey, authority: publicAuthority,
      assertLive: () => undefined,
      versions: versionRows.slice(1),
    }), /ZK_OWNER_VERSIONED_CEK_BATCH_DENIED/,
    "declared versions cannot omit revision one of any object");
    await assert.rejects(openBatch({ authority: { ...linked,
      signedDeviceGrant: { ...issued.signedDeviceGrant,
        revoked_at_epoch: committed.epoch } } }),
    /ZK_OWNER_VERSIONED_CEK_BATCH_DENIED/,
    "a forged revocation field cannot grant a batch CEK");
    secondCek.fill(0); otherCek.fill(0);
    for (const row of versionRows) row.ownerHeldCek.fill(0);
    await assert.rejects(open({
      deviceHpkePrivateKey: await z.hpkeSuite().kem.generateKeyPair().then((pair) => pair.privateKey),
    }), /ZK_OWNER_FILE_CEK_DENIED/, "different X25519 private key cannot open B-specific CEK");
    // Deliberately do not mint a fake owner-signed revocation: actual witness-
    // committed revocation is separately exercised in the V2 revocation suite.
    // This asserts a revoked_at_epoch mutation to an authentic grant fails.
    const tamperedRevocationField = { ...issued.signedDeviceGrant,
      revoked_at_epoch: committed.epoch };
    await assert.rejects(open({ authority: { ...linked,
      signedDeviceGrant: tamperedRevocationField } }), /ZK_OWNER_FILE_CEK_DENIED/,
    "revocation bit cannot be changed without the genuine owner signature and V2 commit");
    await assert.rejects(open({ metadata: { ...metadata,
      account_id: b64(crypto.randomBytes(16)) } }), /ZK_OWNER_FILE_CEK_DENIED/,
    "cross-account CEK substitution is forbidden");
    await assert.rejects(open({ operatorMinimumSequence: signedCommittedHead.sequence + 1 }),
      /ZK_OWNER_FILE_CEK_DENIED/, "external monotonic floor ahead of witnessed head rejects rollback");
    await assert.rejects(open({ authority: { ...linked,
      pinnedCurrentHead: { ...linked.pinnedCurrentHead,
        digest: crypto.randomBytes(32) } } }), /ZK_OWNER_FILE_CEK_DENIED/,
    "stale or forged owner head cannot authorize recovery");
    await assert.rejects(open({ ciphertextRoot: crypto.randomBytes(32) }),
      /ZK_OWNER_FILE_CEK_DENIED/, "untrusted ciphertext root cannot substitute the witnessed owner pin");
    await assert.rejects(open({ envelope: { ...envelope,
      owner_signature: b64(crypto.randomBytes(64)) } }), /ZK_OWNER_FILE_CEK_DENIED/,
    "a valid HPKE message without owner-signed outer envelope cannot release CEK");
    await assert.rejects(open({ envelope: { ...envelope,
      ciphertext: b64(crypto.randomBytes(48)) } }), /ZK_OWNER_FILE_CEK_DENIED/,
    "altered recipient CEK ciphertext fails owner signature and HPKE authentication");
    const wrongSigning = crypto.generateKeyPairSync("ed25519");
    await assert.rejects(open({ authority: { ...linked,
      devicePrivateKey: await subtle.importKey("pkcs8", wrongSigning.privateKey.export({
        format: "der", type: "pkcs8" }), "Ed25519", false, ["sign"]) } }),
    /ZK_OWNER_FILE_CEK_DENIED/, "B must prove its own Ed25519 signing key");
    const corrupt = Buffer.from(recoveredCiphertext);
    corrupt[corrupt.length - 1] ^= 1;
    await assert.rejects(open({ ciphertext: corrupt }), /ZK_OWNER_FILE_CEK_DENIED/,
      "protected HTTP ciphertext tamper cannot receive CEK");
    ownerHeldCek.fill(0);
  });
});
