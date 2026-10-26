"use strict";

// SYNTHETIC CLIENT-ONLY TEST FIXTURE. This is not an authorization provider:
// it has no live CAS, secure device keychain, witness freshness or replay store.
const crypto = require("node:crypto");
const z = require("../../src/crypto/rootark-zk-1");
const m = require("../../src/crypto/rootark-zk-recovery-manifest-v2");
const history = require("../../src/crypto/rootark-zk-recovery-history-v2");
const pkg = require("../../src/crypto/rootark-zk-recovery-package-v1");
const authorization = require("../../src/crypto/rootark-zk-recovery-authorization");
const { computeZk1CiphertextRoot } = require("../../src/crypto/rootark-zk-chunk-root-v1");
const file = require("../../public/client/rootark-zk1-file-content");
const fixtures = require("./issue-65-recovery-v2-fixtures");

const random = (n) => crypto.randomBytes(n);
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const domain = (s) => Buffer.from("Root.ark/zk-1/" + s + "\0", "ascii");
const domainHash = async (type, map) => sha256(Buffer.concat([domain(type), await z.encodeDeterministic(map)]));
const to64 = (b) => Buffer.from(b).toString("base64url");
function fail() { throw new Error("ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE"); }
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const publicRaw = (key) => Buffer.from(key.export({ format: "der", type: "spki" })).subarray(-32);

async function makeDualClientRecoveryLab() {
  // The same synthetic scope, epoch key, CEK and file wire are used by BOTH
  // clients; the package is a separate user-held encrypted export.
  const state = await fixtures.createInitialState(1);
  const scope = state.scope;
  const prior = state.headManifest;
  const epochKey = Buffer.from(state.epochKeys[0].key);
  const previousDigest = await m.recoveryManifestDigestV2(prior);
  const witnessReceipt = state.baseReceipt;
  const packageId = random(16);
  const operationId = random(16);
  const hpke = await z.hpkeSuite().kem.generateKeyPair();
  const hpkePublic = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(hpke.publicKey));
  const hpkePrivate = Buffer.from(await z.hpkeSuite().kem.serializePrivateKey(hpke.privateKey));
  const packageSigner = crypto.generateKeyPairSync("ed25519");
  const hpkeKeyId = random(16);
  const authorizationKeyId = random(16);
  const context = {
    type: "rootark-recovery-activation-context", version: 1,
    suite: "rootark-zk-1", ...scope,
    package_id: packageId, previous_revision: prior.revision,
    previous_manifest_digest: previousDigest, activation_revision: prior.revision + 1,
    operation_id: operationId, hpke_key_id: hpkeKeyId, hpke_public_key: hpkePublic,
    authorization_key_id: authorizationKeyId,
    authorization_public_key: publicRaw(packageSigner.publicKey),
    witness_base_receipt_digest: sha256(await z.encodeDeterministic(witnessReceipt)),
  };
  const activationContextDigest = await domainHash("recovery-activation-context/v1", context);
  const payload = {
    type: "rootark-recovery-state", version: 1, ...scope,
    package_id: packageId, previous_revision: prior.revision,
    previous_manifest_digest: previousDigest, activation_revision: prior.revision + 1,
    operation_id: operationId, activation_context: context,
    activation_context_digest: activationContextDigest,
    witness_base_receipt: witnessReceipt,
    previous_manifest: prior, current_epoch: prior.current_epoch,
    epoch_keys: [{ epoch: prior.current_epoch, key: epochKey }],
    recovery_authorization: {
      hpke_key_id: hpkeKeyId, hpke_private_key: hpkePrivate,
      authorization_key_id: authorizationKeyId,
      ed25519_private_seed: Buffer.from(packageSigner.privateKey.export({
        format: "der", type: "pkcs8",
      })).subarray(-32),
    },
  };
  const password = "synthetic package secret only for unit tests";
  const packageBytes = Buffer.from(await pkg.createRecoveryPackageV1({
    password, payload, pinnedWitness: state.pinnedWitness,
  }));
  // A real v2 register-package transition is signed by the PREVIOUS trusted
  // device, with the exact immutable encrypted envelope digest.
  const authority = {
    package_id: packageId, hpke_key_id: hpkeKeyId,
    hpke_public_key: hpkePublic, authorization_key_id: authorizationKeyId,
    authorization_public_key: publicRaw(packageSigner.publicKey),
    status: "active", activation_revision: prior.revision + 1,
    previous_revision: prior.revision, previous_manifest_digest: previousDigest,
    operation_id: operationId, activation_context_digest: activationContextDigest,
    package_envelope_digest: pkg.recoveryPackageEnvelopeDigest(packageBytes),
  };
  const keyRef = prior.epochs[0].key_ref;
  const wrapId = random(16);
  const wrapContext = {
    suite: "rootark-zk-1", account_id: scope.account_id,
    compartment_id: scope.compartment_id, purpose: "recovery-package",
    recipient_type: "recovery-package", recipient_id: packageId,
    recipient_key_id: hpkeKeyId, epoch: 1, key_ref: keyRef, wrap_id: wrapId,
  };
  const contextBytes = await z.encodeDeterministic(wrapContext);
  const envelope = await z.hpkeSeal({ recipientPublicKey: hpke.publicKey,
    plaintext: epochKey,
    info: Buffer.concat([domain("keyring-wrap-info/v2"), contextBytes]),
    aad: Buffer.concat([domain("keyring-wrap-aad/v2"), contextBytes]),
  });
  const recoveryWraps = [{ package_id: packageId, hpke_key_id: hpkeKeyId,
    epoch: 1, key_ref: keyRef, wrap_id: wrapId,
    enc: envelope.enc, ciphertext: envelope.ciphertext }];
  const core = {
    type: m.MANIFEST_TYPE, version: m.MANIFEST_VERSION, suite: "rootark-zk-1",
    ...scope, revision: prior.revision + 1, current_epoch: 1,
    epochs: prior.epochs, devices: prior.devices, wraps: prior.wraps,
    recovery_authority: authority, recovery_wraps: recoveryWraps,
    previous_manifest_digest: previousDigest,
    operation: {
      operation_id: operationId, operation_type: "register-package",
      actor_type: "device", actor_key_id: prior.devices[0].authorization_key_id,
      target_device_id: null, target_device_key_digest: null,
      compromised_package_id: null, recovery_policy_change: null,
      target_epoch_coverage: [], target_pop_proof: null, issued_at: 1000,
      expires_at: 1300, request_digest: Buffer.alloc(32),
    },
  };
  core.operation.request_digest = await m.expectedRecoveryRequestDigestV2(prior, core);
  const actorKey = state.actors.get(Buffer.from(prior.devices[0].authorization_key_id).toString("hex"));
  const activated = await m.signRecoveryTransitionV2({
    proposedCore: core, priorVerifiedHistory: state.verifiedHistory,
    actorPrivateKey: actorKey, manifestMacKey: epochKey,
    now: 1100, clockHealthy: true,
  });
  const transitions = [Buffer.from(await z.encodeDeterministic(activated))];
  const baseHistory = { expectedScope: scope, baseManifest: prior,
    baseReceipt: witnessReceipt, pinnedWitness: state.pinnedWitness,
    transitions, packageEnvelopeBytes: packageBytes,
    packageEnvelopes: [{ activationRevision: activated.revision, envelopeBytes: packageBytes }],
    now: 1100,
  };
  const deviceHistory = await history.verifyTrustedDeviceRecoveryHistoryV2({
    ...baseHistory, epochKeys: state.epochKeys,
  });
  // Authentic package verification starts with actual Argon2id13 AES-GCM
  // payload bytes and the original separately pinned signed base receipt.
  const packageOpened = await pkg.openRecoveryPackageV1({ password,
    envelopeBytes: packageBytes, expectedScope: scope,
    pinnedWitness: state.pinnedWitness });
  const packageHistory = await history.verifyRecoveryPackageHistoryV2({
    ...baseHistory, epochKeys: packageOpened.epoch_keys,
    recoveryPackageKeys: [{ package_id: packageId, hpke_key_id: hpkeKeyId,
      hpke_private_key: packageOpened.recovery_authorization.hpke_private_key }],
  });
  let activeDeviceHistory = deviceHistory;
  let activePackageHistory = packageHistory;

  const object = random(16);
  const version = random(16);
  const cek = random(32);
  const fileCek = await file.importFileCek(cek);
  const metadata = { account_id: to64(scope.account_id),
    compartment_id: to64(scope.compartment_id), keyring_id: to64(scope.keyring_id),
    object_id: to64(object), version_id: to64(version), parent_version_id: null,
    epoch: 1, kind: "file" };
  const plaintext = random(231);
  const fileWire = Buffer.from(await file.encryptFile({ cek: fileCek, metadata,
    name: "offline-private.txt", mediaType: "text/plain", data: plaintext }));
  const contentWrapId = random(16);
  const contentContext = { suite: "rootark-zk-1",
    compartment_id: scope.compartment_id, epoch: 1, purpose: "content",
    object_id: object, version_id: version, key_ref: keyRef,
    recipient_key_id: prior.devices[0].hpke_key_id, wrap_id: contentWrapId };
  const contentAad = Buffer.from(await z.encodeDeterministic({ ...scope,
    object_id: object, version_id: version, key_ref: keyRef,
    wrap_id: contentWrapId, purpose: "content", epoch: 1 }));
  const wrapped = Buffer.from(await z.wrapKey({ ...contentContext,
    cer: epochKey, plaintext: cek, aad: contentAad }));
  cek.fill(0);
  const fileRoot = computeZk1CiphertextRoot([fileWire]);
  // The server-facing projection holds ONLY ciphertext and public metadata.
  const projection = { fileWire, wrapped, manifestBytes: transitions[0], packageBytes };
  const publicProjection = Buffer.concat(Object.values(projection));
  const serverProjectionHasSecrets = publicProjection.includes(plaintext)
    || publicProjection.includes(epochKey)
    || publicProjection.includes(Buffer.from(password));

  // Trusted-device transfer path: replacement device proves BOTH its HPKE
  // private-key decryption and Ed25519 key possession in the existing
  // recovery-target-pop profile, over a synthetic authenticated local pairing
  // channel. No manifest enrollment or CAS activation is inferred from this.
  const targetHpke = await z.hpkeSuite().kem.generateKeyPair();
  const targetSigning = crypto.generateKeyPairSync("ed25519");
  const targetHpkeKeyId = random(16);
  const targetAuthorizationKeyId = random(16);
  const targetPublic = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(targetHpke.publicKey));
  const targetAuthPublic = publicRaw(targetSigning.publicKey);
  const targetDeviceKeyDigest = await authorization.recoveryTargetDeviceKeyDigest({
    deviceId: "synthetic-replacement", hpkeKeyId: targetHpkeKeyId,
    hpkePublicKey: targetPublic, authorizationKeyId: targetAuthorizationKeyId,
    authorizationPublicKey: targetAuthPublic,
  });
  const pop = await authorization.createTargetPopChallenge({ scope,
    targetDeviceId: "synthetic-replacement", hpkeKeyId: targetHpkeKeyId,
    hpkePublicKey: targetPublic, authorizationKeyId: targetAuthorizationKeyId,
    authorizationPublicKey: targetAuthPublic, operationId: random(16),
    issuedAt: 1000, expiresAt: 1200 });
  const popContextBytes = await z.encodeDeterministic(pop.challengeContext);
  const decryptedChallenge = Buffer.from(await z.hpkeOpen({
    recipientKey: targetHpke.privateKey, enc: pop.enc, ciphertext: pop.ciphertext,
    info: Buffer.concat([domain("recovery-target-pop-info/v1"), popContextBytes]),
    aad: Buffer.concat([domain("recovery-target-pop-aad/v1"), popContextBytes]),
  }));
  const responseUnsigned = { challenge_context: pop.challengeContext,
    challenge: decryptedChallenge };
  const response = { ...responseUnsigned,
    target_signature: crypto.sign(null, Buffer.concat([
      domain("recovery-target-pop-response/v1"),
      await z.encodeDeterministic(responseUnsigned),
    ]), targetSigning.privateKey) };
  const verifiedPop = await authorization.verifyTargetPopResponse({ challenge: pop,
    challengeContext: pop.challengeContext, response, expectedScope: scope,
    expectedDeviceKeyDigest: targetDeviceKeyDigest, now: 1100 });
  const targetPopVerified = await authorization.isVerifiedTargetPopResponse(verifiedPop, 1100);
  decryptedChallenge.fill(0);
  if (!targetPopVerified) fail();

  const targetWrapId = random(16);
  const targetWrapContext = { suite: "rootark-zk-1",
    account_id: scope.account_id, compartment_id: scope.compartment_id,
    purpose: "key-wrap", recipient_type: "device",
    recipient_id: "synthetic-replacement", recipient_key_id: targetHpkeKeyId,
    epoch: 1, key_ref: keyRef, wrap_id: targetWrapId };
  const targetWrapBytes = await z.encodeDeterministic(targetWrapContext);
  const targetWrappedEpoch = await z.hpkeSeal({
    recipientPublicKey: targetHpke.publicKey, plaintext: epochKey,
    info: Buffer.concat([domain("keyring-wrap-info/v2"), targetWrapBytes]),
    aad: Buffer.concat([domain("keyring-wrap-aad/v2"), targetWrapBytes]),
  });

  const requireLocalLabGate = (options) => {
    // Deliberately synthetic NO-GO flags, not a live CAS/witness protocol.
    if (options.pendingReservation || options.staleHead || options.replayedRequest
      || options.revokedDevice || options.lostDevice || options.noTrustedWitness) fail();
    const comparedRoot = options.wrongRoot ? random(32) : fileRoot;
    if (!same(comparedRoot, computeZk1CiphertextRoot([fileWire]))) fail();
    if (options.currentManifestDigest && !same(options.currentManifestDigest,
      deviceHistory.headDigest)) fail();
    if (activeDeviceHistory.freshnessProven !== false
      || activePackageHistory.freshnessProven !== false) fail();
  };
  const openFileWithEpoch = async (selectedEpoch, options) => {
    const ctx = options.wrongEpoch ? { ...contentContext, epoch: 2 } : contentContext;
    const rawCek = await z.unwrapKey({ ...ctx, cer: selectedEpoch,
      wrapped, aad: contentAad });
    const imported = await file.importFileCek(rawCek);
    rawCek.fill(0);
    const selectedMetadata = options.wrongVersion
      ? { ...metadata, version_id: to64(random(16)) } : metadata;
    const bytes = Buffer.from(fileWire);
    if (options.tamperedFile) bytes[bytes.length - 10] ^= 0x01;
    return file.decryptFile({ cek: imported, metadata: selectedMetadata,
      envelopeBytes: bytes });
  };
  async function openViaPackage(pass, options = {}) {
    requireLocalLabGate(options);
    const opened = await pkg.openRecoveryPackageV1({ password: pass,
      envelopeBytes: options.packageBytes ?? packageBytes,
      expectedScope: options.expectedScope ?? scope,
      pinnedWitness: state.pinnedWitness });
    // A verified package must be the precise ACTIVE key ID on the signed
    // history's head; old/replaced packages alone never confer authority.
    if (!same(opened.package_id, activePackageHistory.headManifest.recovery_authority.package_id)
      || !same(opened.recovery_authorization.authorization_key_id,
        activePackageHistory.headManifest.recovery_authority.authorization_key_id)) fail();
    if (!await history.isVerifiedRecoveryPackageHistoryV2(activePackageHistory)) fail();
    return openFileWithEpoch(Buffer.from(opened.epoch_keys[0].key), options);
  }
  async function openViaTrustedDevice(options = {}) {
    requireLocalLabGate(options);
    if (!await history.isVerifiedTrustedDeviceRecoveryHistoryV2(activeDeviceHistory)) fail();
    const source = activeDeviceHistory.headManifest.devices.find((d) => d.device_id === "trusted-0");
    if (!source || source.revoked_at_epoch !== null) fail();
    // The authorized source device holds epoch key locally. Transfer via the
    // reviewed HPKE base suite, never plaintext to the server. A returned
    // response remains candidate local recovery, NOT CAS/witness admission.
    const selectedWrapContext = options.wrongEpoch
      ? { ...targetWrapContext, epoch: 2 } : targetWrapContext;
    const selectedWrapBytes = await z.encodeDeterministic(selectedWrapContext);
    const recoveredEpoch = Buffer.from(await z.hpkeOpen({
      recipientKey: targetHpke.privateKey,
      enc: targetWrappedEpoch.enc, ciphertext: targetWrappedEpoch.ciphertext,
      info: Buffer.concat([domain("keyring-wrap-info/v2"), selectedWrapBytes]),
      aad: Buffer.concat([domain("keyring-wrap-aad/v2"), selectedWrapBytes]),
    }));
    try { return await openFileWithEpoch(recoveredEpoch, options); }
    finally { recoveredEpoch.fill(0); }
  }
  async function revokeTrustedDevice() {
    // Actual signed v2 revoke-device transition increments epoch and removes
    // the prior device's authority. The old epoch is NOT magically erased.
    state.headManifest = activated;
    state.verifiedHistory = deviceHistory;
    state.transitions = [...transitions];
    state.packageEnvelopes = [{ activationRevision: activated.revision,
      envelopeBytes: Buffer.from(packageBytes) }];
    state.recoveryPackageKeys = [{ package_id: Buffer.from(packageId),
      hpke_key_id: Buffer.from(hpkeKeyId),
      hpke_private_key: Buffer.from(hpkePrivate) }];
    const revoked = await fixtures.appendDeviceRevocation(state, "trusted-0");
    activeDeviceHistory = state.verifiedHistory;
    activePackageHistory = await history.verifyRecoveryPackageHistoryV2({
      ...baseHistory, transitions: [...transitions,
        Buffer.from(await z.encodeDeterministic(revoked))],
      epochKeys: packageOpened.epoch_keys,
      recoveryPackageKeys: state.recoveryPackageKeys,
    });
    return { revokedEpoch: revoked.current_epoch,
      packageStillActive: activePackageHistory.packageAuthorityStatus === "active",
      authorizesRelease: false };
  }
  return { password, packageBytes, fileCek, scope, plaintext, metadata,
    serverProjectionHasSecrets, manifestAuthorityVerified:
      await history.isVerifiedTrustedDeviceRecoveryHistoryV2(deviceHistory),
    packageHistoryVerified: await history.isVerifiedRecoveryPackageHistoryV2(packageHistory),
    targetPopVerified, authorizesRelease: false, openViaPackage, openViaTrustedDevice,
    revokeTrustedDevice };
}

module.exports = { makeDualClientRecoveryLab };
