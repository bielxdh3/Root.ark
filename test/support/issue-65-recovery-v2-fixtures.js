"use strict";

const crypto = require("node:crypto");
const z = require("../../src/crypto/rootark-zk-1");
const m = require("../../src/crypto/rootark-zk-recovery-manifest-v2");
const history = require("../../src/crypto/rootark-zk-recovery-history-v2");
const packageV1 = require("../../src/crypto/rootark-zk-recovery-package-v1");
const targetAuthorization = require("../../src/crypto/rootark-zk-recovery-authorization");

function rawPublic(key) {
  return Buffer.from(key.export({ format: "der", type: "spki" })).subarray(-32);
}

function keyId(prefix, index) {
  return Buffer.alloc(16, prefix + index);
}

async function createRecoveryWrap(scope, authority, epoch, keyRef, epochKey) {
  const wrapId = crypto.randomBytes(16);
  const context = {
    suite: "rootark-zk-1",
    account_id: Buffer.from(scope.account_id),
    compartment_id: Buffer.from(scope.compartment_id),
    purpose: "recovery-package",
    recipient_type: "recovery-package",
    recipient_id: Buffer.from(authority.package_id),
    recipient_key_id: Buffer.from(authority.hpke_key_id),
    epoch,
    key_ref: Buffer.from(keyRef),
    wrap_id: wrapId,
  };
  const info = Buffer.concat([
    Buffer.from("Root.ark/zk-1/keyring-wrap-info/v2\0", "ascii"),
    await z.encodeDeterministic(context),
  ]);
  const aad = Buffer.concat([
    Buffer.from("Root.ark/zk-1/keyring-wrap-aad/v2\0", "ascii"),
    await z.encodeDeterministic(context),
  ]);
  const sealed = await z.hpkeSeal({
    recipientPublicKey: await z.hpkeSuite().kem.deserializePublicKey(authority.hpke_public_key),
    info,
    aad,
    plaintext: epochKey,
  });
  return {
    package_id: Buffer.from(authority.package_id),
    hpke_key_id: Buffer.from(authority.hpke_key_id),
    epoch,
    key_ref: Buffer.from(keyRef),
    wrap_id: wrapId,
    enc: sealed.enc,
    ciphertext: sealed.ciphertext,
  };
}

function identifiers(manifest) {
  const used = new Set();
  used.add(`operation:${Buffer.from(manifest.operation.operation_id).toString("hex")}`);
  for (const device of manifest.devices) {
    used.add(`device-name:${device.device_id}`);
    used.add(`key:${Buffer.from(device.hpke_key_id).toString("hex")}`);
    used.add(`key:${Buffer.from(device.authorization_key_id).toString("hex")}`);
    used.add(`x25519-public:${Buffer.from(device.hpke_public_key).toString("hex")}`);
    used.add(`ed25519-public:${Buffer.from(device.authorization_public_key).toString("hex")}`);
  }
  for (const wrap of [...manifest.wraps, ...manifest.recovery_wraps]) {
    used.add(`wrap:${Buffer.from(wrap.wrap_id).toString("hex")}`);
  }
  return used;
}

async function refreshVerifiedHistory(state) {
  state.verifiedHistory = await history.verifyTrustedDeviceRecoveryHistoryV2({
    expectedScope: state.scope,
    baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt,
    pinnedWitness: state.pinnedWitness,
    epochKeys: state.epochKeys,
    transitions: state.transitions,
    packageEnvelopes: state.packageEnvelopes,
  });
  state.usedIdentifiers = new Set(state.verifiedHistory.usedIdentifiers);
  return state.verifiedHistory;
}

async function createInitialState(deviceCount = 3) {
  const scope = {
    account_id: Buffer.alloc(16, 0x41),
    compartment_id: Buffer.from("fixture-compartment"),
    keyring_id: Buffer.alloc(16, 0x42),
  };
  const actors = new Map();
  const signing = crypto.generateKeyPairSync("ed25519");
  const initialDevice = {
    device_id: "trusted-0",
    hpke_key_id: keyId(0x60, 0),
    hpke_public_key: crypto.randomBytes(32),
    authorization_key_id: keyId(0x50, 0),
    authorization_public_key: rawPublic(signing.publicKey),
    enrolled_epoch: 1,
    revoked_at_epoch: null,
  };
  const devices = [initialDevice];
  actors.set(initialDevice.authorization_key_id.toString("hex"), signing.privateKey);

  const epochKey = crypto.randomBytes(32);
  const core = {
    type: m.MANIFEST_TYPE,
    version: m.MANIFEST_VERSION,
    suite: "rootark-zk-1",
    ...scope,
    revision: 1,
    current_epoch: 1,
    epochs: [{ epoch: 1, key_ref: await m.recoveryKeyRefV2(scope, 1) }],
    devices,
    wraps: [],
    recovery_authority: null,
    recovery_wraps: [],
    previous_manifest_digest: Buffer.alloc(32),
    operation: {
      operation_id: crypto.randomBytes(16),
      operation_type: "initialize",
      actor_type: "device",
      actor_key_id: devices[0].authorization_key_id,
      target_device_id: null,
      target_device_key_digest: null,
      compromised_package_id: null,
      recovery_policy_change: null,
      target_epoch_coverage: [],
      target_pop_proof: null,
      issued_at: 1000,
      expires_at: 1300,
      request_digest: Buffer.alloc(32),
    },
  };
  core.operation.request_digest = await m.expectedRecoveryRequestDigestV2(null, core);
  const manifest = await m.signRecoveryTransitionV2({
    proposedCore: core,
    actorPrivateKey: signing.privateKey,
    manifestMacKey: epochKey,
    now: 1100,
    clockHealthy: true,
  });
  const state = {
    scope,
    actors,
    headManifest: manifest,
    epochKeys: [{ epoch: 1, key: epochKey }],
    recoveryPackageKeys: [],
    baseManifest: manifest,
    baseReceipt: null,
    pinnedWitness: null,
    transitions: [],
    packageEnvelopes: [],
    usedIdentifiers: identifiers(manifest),
  };
  const witness = await createWitnessAnchor(state);
  state.baseReceipt = witness.receipt;
  state.pinnedWitness = witness.pinnedWitness;
  await refreshVerifiedHistory(state);
  for (let index = 1; index < deviceCount; index += 1) await appendDeviceEnrollment(state, index);
  return state;
}

async function appendDeviceEnrollment(state, index) {
  const previous = state.headManifest;
  const hpke = await z.hpkeSuite().kem.generateKeyPair();
  const signing = crypto.generateKeyPairSync("ed25519");
  const target = {
    device_id: `trusted-${index}`,
    hpke_key_id: keyId(0x60, index),
    hpke_public_key: Buffer.from(await z.hpkeSuite().kem.serializePublicKey(hpke.publicKey)),
    authorization_key_id: keyId(0x50, index),
    authorization_public_key: rawPublic(signing.publicKey),
    enrolled_epoch: previous.current_epoch,
    revoked_at_epoch: null,
  };
  const operationId = crypto.randomBytes(16);
  const coverage = previous.epochs.map((entry) => entry.epoch);
  const challenge = await targetAuthorization.createTargetPopChallenge({
    scope: state.scope,
    operationId,
    targetDeviceId: target.device_id,
    hpkeKeyId: target.hpke_key_id,
    hpkePublicKey: target.hpke_public_key,
    authorizationKeyId: target.authorization_key_id,
    authorizationPublicKey: target.authorization_public_key,
    issuedAt: 1000,
    expiresAt: 1300,
  });
  const challengeContext = await z.encodeDeterministic(challenge.challengeContext);
  const challengePlaintext = await z.hpkeOpen({
    recipientKey: hpke.privateKey,
    enc: challenge.enc,
    ciphertext: challenge.ciphertext,
    info: Buffer.concat([Buffer.from("Root.ark/zk-1/recovery-target-pop-info/v1\0", "ascii"), challengeContext]),
    aad: Buffer.concat([Buffer.from("Root.ark/zk-1/recovery-target-pop-aad/v1\0", "ascii"), challengeContext]),
  });
  const responseBody = { challenge_context: challenge.challengeContext, challenge: challengePlaintext };
  const response = {
    ...responseBody,
    target_signature: crypto.sign(null,
      Buffer.concat([
        Buffer.from("Root.ark/zk-1/recovery-target-pop-response/v1\0", "ascii"),
        await z.encodeDeterministic(responseBody),
      ]), signing.privateKey),
  };
  const targetPopProof = await targetAuthorization.verifyTargetPopResponse({
    challenge,
    challengeContext: challenge.challengeContext,
    response,
    expectedScope: state.scope,
    expectedDeviceKeyDigest: challenge.challengeContext.target_device_key_digest,
    now: 1100,
  });
  state.lastVerifiedTargetPopProof = targetPopProof;
  const targetDeviceKeyDigest = await targetAuthorization.recoveryTargetDeviceKeyDigest({
    deviceId: target.device_id,
    hpkeKeyId: target.hpke_key_id,
    hpkePublicKey: target.hpke_public_key,
    authorizationKeyId: target.authorization_key_id,
    authorizationPublicKey: target.authorization_public_key,
  });
  const addedWraps = coverage.map((epoch) => {
    const epochEntry = previous.epochs.find((entry) => entry.epoch === epoch);
    return {
      device_id: target.device_id,
      epoch,
      key_ref: epochEntry.key_ref,
      wrap_id: crypto.randomBytes(16),
      enc: crypto.randomBytes(32),
      ciphertext: crypto.randomBytes(48),
    };
  });
  const core = {
    type: m.MANIFEST_TYPE,
    version: m.MANIFEST_VERSION,
    suite: "rootark-zk-1",
    account_id: previous.account_id,
    compartment_id: previous.compartment_id,
    keyring_id: previous.keyring_id,
    revision: previous.revision + 1,
    current_epoch: previous.current_epoch,
    epochs: previous.epochs,
    devices: [...previous.devices, target],
    wraps: [...previous.wraps, ...addedWraps],
    recovery_authority: previous.recovery_authority,
    recovery_wraps: previous.recovery_wraps,
    previous_manifest_digest: await m.recoveryManifestDigestV2(previous),
    operation: {
      operation_id: operationId,
      operation_type: "enroll-device",
      actor_type: "device",
      actor_key_id: previous.devices[0].authorization_key_id,
      target_device_id: target.device_id,
      target_device_key_digest: targetDeviceKeyDigest,
      compromised_package_id: null,
      recovery_policy_change: null,
      target_epoch_coverage: coverage,
      target_pop_proof: targetPopProof,
      issued_at: 1000,
      expires_at: 1300,
      request_digest: Buffer.alloc(32),
    },
  };
  core.operation.request_digest = await m.expectedRecoveryRequestDigestV2(previous, core);
  const actor = state.actors.get(Buffer.from(previous.devices[0].authorization_key_id).toString("hex"));
  const currentKey = state.epochKeys.find((entry) => entry.epoch === previous.current_epoch).key;
  state.headManifest = await m.signRecoveryTransitionV2({
    proposedCore: core,
    priorVerifiedHistory: state.verifiedHistory,
    actorPrivateKey: actor,
    manifestMacKey: currentKey,
    now: 1100,
    clockHealthy: true,
  });
  state.transitions.push(await encodeManifest(state.headManifest));
  state.actors.set(target.authorization_key_id.toString("hex"), signing.privateKey);
  await refreshVerifiedHistory(state);
  return state.headManifest;
}

async function prepareDeviceRevocation(state, deviceId, operationId = crypto.randomBytes(16)) {
  const previous = state.headManifest;
  const target = previous.devices.find((device) => device.device_id === deviceId);
  if (!target) throw new Error("fixture target device missing");
  const currentEpoch = previous.current_epoch + 1;
  const newKey = crypto.randomBytes(32);
  const newKeyRef = await m.recoveryKeyRefV2(previous, currentEpoch);
  const devices = previous.devices.map((device) => device.device_id === deviceId
    ? { ...device, revoked_at_epoch: currentEpoch }
    : device);
  const newWraps = devices.filter((device) => device.revoked_at_epoch === null).map((device) => ({
    device_id: device.device_id,
    epoch: currentEpoch,
    key_ref: newKeyRef,
    wrap_id: crypto.randomBytes(16),
    enc: crypto.randomBytes(32),
    ciphertext: crypto.randomBytes(48),
  }));
  const freshRecoveryWrap = previous.recovery_authority?.status === "active"
    ? await createRecoveryWrap(state.scope, previous.recovery_authority, currentEpoch, newKeyRef, newKey)
    : null;
  const core = {
    type: m.MANIFEST_TYPE,
    version: m.MANIFEST_VERSION,
    suite: "rootark-zk-1",
    account_id: previous.account_id,
    compartment_id: previous.compartment_id,
    keyring_id: previous.keyring_id,
    revision: previous.revision + 1,
    current_epoch: currentEpoch,
    epochs: [...previous.epochs, { epoch: currentEpoch, key_ref: newKeyRef }],
    devices,
    wraps: [...previous.wraps, ...newWraps],
    recovery_authority: previous.recovery_authority,
    recovery_wraps: previous.recovery_authority?.status === "active"
      ? [...previous.recovery_wraps, freshRecoveryWrap]
      : previous.recovery_wraps,
    previous_manifest_digest: await m.recoveryManifestDigestV2(previous),
    operation: {
      operation_id: operationId,
      operation_type: "revoke-device",
      actor_type: "device",
      actor_key_id: previous.devices[0].authorization_key_id,
      target_device_id: deviceId,
      target_device_key_digest: null,
      compromised_package_id: null,
      recovery_policy_change: null,
      target_epoch_coverage: [],
      target_pop_proof: null,
      issued_at: 1000,
      expires_at: 1300,
      request_digest: Buffer.alloc(32),
    },
  };
  core.operation.request_digest = await m.expectedRecoveryRequestDigestV2(previous, core);
  return { core, newKey, newWraps };
}

async function appendDeviceRevocation(state, deviceId, operationId) {
  const prepared = await prepareDeviceRevocation(state, deviceId, operationId);
  const previous = state.headManifest;
  const actor = state.actors.get(previous.devices[0].authorization_key_id.toString("hex"));
  const next = await m.signRecoveryTransitionV2({
    proposedCore: prepared.core,
    priorVerifiedHistory: state.verifiedHistory,
    actorPrivateKey: actor,
    manifestMacKey: prepared.newKey,
    now: 1100,
    clockHealthy: true,
  });
  state.headManifest = next;
  state.epochKeys.push({ epoch: next.current_epoch, key: prepared.newKey });
  state.transitions.push(await encodeManifest(next));
  await refreshVerifiedHistory(state);
  return next;
}

async function createPackageEnvelope(state, options = {}) {
  const previous = options.previousManifest || state.headManifest;
  const operationId = options.operationId || crypto.randomBytes(16);
  const packageId = options.packageId || crypto.randomBytes(16);
  const activationContextDigest = options.activationContextDigest || crypto.randomBytes(32);
  const envelope = {
    type: "rootark-recovery-package",
    suite: "rootark-zk-1",
    version: 1,
    purpose: "recovery-package",
    account_id: previous.account_id,
    compartment_id: previous.compartment_id,
    package_id: packageId,
    base_revision: previous.revision,
    base_manifest_digest: await m.recoveryManifestDigestV2(previous),
    activation_revision: previous.revision + 1,
    operation_id: operationId,
    activation_context_digest: activationContextDigest,
    kdf: { id: "argon2id13", salt: crypto.randomBytes(16), opslimit: 3, memlimit: 268435456, output_length: 32 },
    aead: { id: "AES-256-GCM", nonce: crypto.randomBytes(12) },
    ciphertext: crypto.randomBytes(48),
    tag: crypto.randomBytes(16),
  };
  return { envelope, envelopeBytes: await z.encodeDeterministic(envelope) };
}

async function appendPackageActivation(state, envelopeBytes, operationType = "register-package") {
  const previous = state.headManifest;
  const envelope = await z.decodeDeterministic(envelopeBytes);
  const existingAuthority = previous.recovery_authority;
  const signing = crypto.generateKeyPairSync("ed25519");
  const hpkeKeyId = crypto.randomBytes(16);
  const hpkeKeyPair = await z.hpkeSuite().kem.generateKeyPair();
  const hpkePublicKey = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(hpkeKeyPair.publicKey));
  const hpkePrivateKey = Buffer.from(await z.hpkeSuite().kem.serializePrivateKey(hpkeKeyPair.privateKey));
  const authorizationKeyId = crypto.randomBytes(16);
  const packagePublicKeys = {
    hpke_key_id: hpkeKeyId,
    hpke_public_key: hpkePublicKey,
    authorization_key_id: authorizationKeyId,
    authorization_public_key: rawPublic(signing.publicKey),
  };
  const authority = {
    package_id: envelope.package_id,
    ...packagePublicKeys,
    status: "active",
    activation_revision: envelope.activation_revision,
    previous_revision: envelope.base_revision,
    previous_manifest_digest: envelope.base_manifest_digest,
    operation_id: envelope.operation_id,
    activation_context_digest: envelope.activation_context_digest,
    package_envelope_digest: packageV1.recoveryPackageEnvelopeDigest(envelopeBytes),
  };
  const recoveryWraps = [];
  for (const epoch of previous.epochs) {
    const epochKey = state.epochKeys.find((entry) => entry.epoch === epoch.epoch)?.key;
    if (!epochKey) throw new Error("fixture epoch key missing");
    recoveryWraps.push(await createRecoveryWrap(state.scope, authority, epoch.epoch, epoch.key_ref, epochKey));
  }
  const core = {
    type: m.MANIFEST_TYPE,
    version: m.MANIFEST_VERSION,
    suite: "rootark-zk-1",
    account_id: previous.account_id,
    compartment_id: previous.compartment_id,
    keyring_id: previous.keyring_id,
    revision: previous.revision + 1,
    current_epoch: previous.current_epoch,
    epochs: previous.epochs,
    devices: previous.devices,
    wraps: previous.wraps,
    recovery_authority: authority,
    recovery_wraps: recoveryWraps,
    previous_manifest_digest: await m.recoveryManifestDigestV2(previous),
    operation: {
      operation_id: envelope.operation_id,
      operation_type: operationType,
      actor_type: "device",
      actor_key_id: previous.devices[0].authorization_key_id,
      target_device_id: null,
      target_device_key_digest: null,
      compromised_package_id: null,
      recovery_policy_change: null,
      target_epoch_coverage: [],
      target_pop_proof: null,
      issued_at: 1000,
      expires_at: 1300,
      request_digest: Buffer.alloc(32),
    },
  };
  core.operation.request_digest = await m.expectedRecoveryRequestDigestV2(previous, core);
  const actor = state.actors.get(previous.devices[0].authorization_key_id.toString("hex"));
  const currentKey = state.epochKeys.find((entry) => entry.epoch === previous.current_epoch).key;
  const next = await m.signRecoveryTransitionV2({
    proposedCore: core,
    priorVerifiedHistory: state.verifiedHistory,
    actorPrivateKey: actor,
    manifestMacKey: currentKey,
    now: 1100,
    clockHealthy: true,
  });
  state.headManifest = next;
  state.transitions.push(await encodeManifest(next));
  state.packageEnvelopes.push({ activationRevision: Number(next.revision), envelopeBytes: Buffer.from(envelopeBytes) });
  state.recoveryPackageKeys.push({
    package_id: Buffer.from(authority.package_id),
    hpke_key_id: Buffer.from(authority.hpke_key_id),
    hpke_private_key: hpkePrivateKey,
  });
  await refreshVerifiedHistory(state);
  return { manifest: next, envelopeBytes, packageSigningKey: signing.privateKey, existingAuthority };
}

async function appendPackageCompromise(state, envelopeBytes) {
  const previous = state.headManifest;
  const oldAuthority = previous.recovery_authority;
  if (!oldAuthority || oldAuthority.status !== "active") throw new Error("fixture recovery authority missing");
  const envelope = await z.decodeDeterministic(envelopeBytes);
  const signing = crypto.generateKeyPairSync("ed25519");
  const hpkeKeyId = crypto.randomBytes(16);
  const hpkeKeyPair = await z.hpkeSuite().kem.generateKeyPair();
  const hpkePublicKey = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(hpkeKeyPair.publicKey));
  const hpkePrivateKey = Buffer.from(await z.hpkeSuite().kem.serializePrivateKey(hpkeKeyPair.privateKey));
  const authorizationKeyId = crypto.randomBytes(16);
  const authority = {
    package_id: Buffer.from(envelope.package_id),
    hpke_key_id: hpkeKeyId,
    hpke_public_key: hpkePublicKey,
    authorization_key_id: authorizationKeyId,
    authorization_public_key: rawPublic(signing.publicKey),
    status: "active",
    activation_revision: envelope.activation_revision,
    previous_revision: envelope.base_revision,
    previous_manifest_digest: envelope.base_manifest_digest,
    operation_id: envelope.operation_id,
    activation_context_digest: envelope.activation_context_digest,
    package_envelope_digest: packageV1.recoveryPackageEnvelopeDigest(envelopeBytes),
  };
  const freshEpoch = Number(previous.current_epoch) + 1;
  const freshKey = crypto.randomBytes(32);
  const freshKeyRef = await m.recoveryKeyRefV2(state.scope, freshEpoch);
  const epochs = [...previous.epochs, { epoch: freshEpoch, key_ref: freshKeyRef }];
  const recoveryWraps = [];
  for (const epoch of epochs) {
    const epochKey = epoch.epoch === freshEpoch
      ? freshKey
      : state.epochKeys.find((entry) => entry.epoch === epoch.epoch)?.key;
    if (!epochKey) throw new Error("fixture epoch key missing");
    recoveryWraps.push(await createRecoveryWrap(state.scope, authority, epoch.epoch, epoch.key_ref, epochKey));
  }
  const deviceWraps = previous.devices.filter((device) => device.revoked_at_epoch === null).map((device) => ({
    device_id: device.device_id,
    epoch: freshEpoch,
    key_ref: freshKeyRef,
    wrap_id: crypto.randomBytes(16),
    enc: crypto.randomBytes(32),
    ciphertext: crypto.randomBytes(48),
  }));
  const core = {
    type: m.MANIFEST_TYPE,
    version: m.MANIFEST_VERSION,
    suite: "rootark-zk-1",
    account_id: previous.account_id,
    compartment_id: previous.compartment_id,
    keyring_id: previous.keyring_id,
    revision: previous.revision + 1,
    current_epoch: freshEpoch,
    epochs,
    devices: previous.devices,
    wraps: [...previous.wraps, ...deviceWraps],
    recovery_authority: authority,
    recovery_wraps: recoveryWraps,
    previous_manifest_digest: await m.recoveryManifestDigestV2(previous),
    operation: {
      operation_id: envelope.operation_id,
      operation_type: "compromise-package",
      actor_type: "device",
      actor_key_id: previous.devices[0].authorization_key_id,
      target_device_id: null,
      target_device_key_digest: null,
      compromised_package_id: Buffer.from(oldAuthority.package_id),
      recovery_policy_change: null,
      target_epoch_coverage: [],
      target_pop_proof: null,
      issued_at: 1000,
      expires_at: 1300,
      request_digest: Buffer.alloc(32),
    },
  };
  core.operation.request_digest = await m.expectedRecoveryRequestDigestV2(previous, core);
  const actor = state.actors.get(Buffer.from(previous.devices[0].authorization_key_id).toString("hex"));
  const next = await m.signRecoveryTransitionV2({
    proposedCore: core,
    priorVerifiedHistory: state.verifiedHistory,
    actorPrivateKey: actor,
    manifestMacKey: freshKey,
    now: 1100,
    clockHealthy: true,
  });
  state.headManifest = next;
  state.epochKeys.push({ epoch: freshEpoch, key: freshKey });
  state.transitions.push(await encodeManifest(next));
  state.packageEnvelopes.push({ activationRevision: Number(next.revision), envelopeBytes: Buffer.from(envelopeBytes) });
  state.recoveryPackageKeys.push({
    package_id: Buffer.from(authority.package_id),
    hpke_key_id: Buffer.from(authority.hpke_key_id),
    hpke_private_key: hpkePrivateKey,
  });
  await refreshVerifiedHistory(state);
  return next;
}

async function createWitnessAnchor(state) {
  const signing = crypto.generateKeyPairSync("ed25519");
  const keyIdBytes = crypto.randomBytes(16);
  const manifest = state.headManifest;
  const receipt = {
    type: "rootark-recovery-witness-base/v1",
    witness_key_id: keyIdBytes,
    account_id: manifest.account_id,
    compartment_id: manifest.compartment_id,
    keyring_id: manifest.keyring_id,
    revision: manifest.revision,
    manifest_digest: await m.recoveryManifestDigestV2(manifest),
    witness_sequence: 1,
    nonce: crypto.randomBytes(32),
    observed_at: 1000,
    status: "committed",
  };
  const prefix = Buffer.from("Root.ark/zk-1/recovery-witness-base/v1\0", "ascii");
  const signature = crypto.sign(null,
    Buffer.concat([prefix, await z.encodeDeterministic(receipt)]), signing.privateKey);
  return {
    receipt: { ...receipt, signature },
    pinnedWitness: { keyId: keyIdBytes, publicKey: signing.publicKey },
    signingPrivateKey: signing.privateKey,
  };
}

async function encodeManifest(manifest) {
  return z.encodeDeterministic(manifest);
}

module.exports = {
  appendDeviceEnrollment,
  appendDeviceRevocation,
  appendPackageActivation,
  appendPackageCompromise,
  createPackageEnvelope,
  createInitialState,
  createWitnessAnchor,
  encodeManifest,
  identifiers,
  prepareDeviceRevocation,
};
