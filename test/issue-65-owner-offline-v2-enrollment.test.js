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
    const bCek = await open();
    assert.equal(bCek.authorizesProductionRestore, false);
    const decrypted = await content.decryptFile({
      cek: await content.importFileCek(bCek.cek), metadata,
      envelopeBytes: recoveredCiphertext,
    });
    assert.deepEqual(Buffer.from(decrypted.data), bytes,
      "B independently decrypts exact SQLite-reopened HTTP bytes without receiving A recoverySecret");
    bCek.cek.fill(0); decrypted.data.fill(0);
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
    });
    assert.equal(bundle.entries.length, 3);
    assert.equal(bundle.globalAccountCompletenessProven, false);
    assert.equal(bundle.authorizesProductionRestore, false);
    const openBatch = (overrides = {}) => cekBatch.openOwnerAuthorizedVersionedCeks({
      bundle, authority: { ...linked, nowSeconds: now + 9 },
      operatorMinimumSequence: signedCommittedHead.sequence,
      recipientHpkePrivateRaw: fresh.hpkePrivateRaw, nowSeconds: now + 9,
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
      versions: [versionRows[0], { ...versionRows[2], ownerHeldCek: Buffer.from(ownerHeldCek),
        ciphertext: Buffer.from(reusedCekCiphertext),
        ciphertextRoot: await ciphertextRoots.computeCiphertextRoot([reusedCekCiphertext]) }],
    }), /ZK_OWNER_VERSIONED_CEK_BATCH_DENIED/,
    "two distinct historical file versions cannot reuse the same authenticated CEK");
    await assert.rejects(cekBatch.sealOwnerAuthorizedVersionedCeks({
      ownerPrivateKey: owner.privateKey, authority: publicAuthority,
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
