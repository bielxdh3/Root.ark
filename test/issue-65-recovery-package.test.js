"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const recoveryKdf = require("../src/crypto/rootark-zk-recovery-kdf");
const {
  createRecoveryPackageV1,
  openRecoveryPackageV1,
  parseRecoveryPackageV1,
  recoveryPackageEnvelopeDigest,
} = require("../src/crypto/rootark-zk-recovery-package-v1");

const ENVELOPE_DIGEST_PREFIX = Buffer.from("Root.ark/zk-1/recovery-package-envelope/v1\0", "ascii");
const MANIFEST_DIGEST_PREFIX = Buffer.from("Root.ark/zk-1/recovery-manifest-digest/v1\0", "ascii");
const WITNESS_PREFIX = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");

const hash = (data) => crypto.createHash("sha256").update(data).digest();
const domainHash = (prefix, data) => hash(Buffer.concat([prefix, data]));

async function fixture(extraPayload = {}) {
  const accountId = Buffer.alloc(16, 0x11);
  const compartmentId = Buffer.from("compartment-a");
  const keyringId = Buffer.alloc(16, 0x22);
  const packageId = Buffer.alloc(16, 0x33);
  const operationId = Buffer.alloc(16, 0x44);
  const witnessKeyId = Buffer.alloc(16, 0x55);
  const witness = crypto.generateKeyPairSync("ed25519");
  const recoveryHpke = await z.hpkeSuite().kem.generateKeyPair();
  const recoveryHpkePrivate = Buffer.from(await z.hpkeSuite().kem.serializePrivateKey(recoveryHpke.privateKey));
  const recoveryHpkePublic = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(recoveryHpke.publicKey));
  const recoverySigning = crypto.generateKeyPairSync("ed25519");
  const recoverySigningPrivateDer = recoverySigning.privateKey.export({ format: "der", type: "pkcs8" });
  const recoverySigningSeed = Buffer.from(recoverySigningPrivateDer).subarray(-32);
  const recoverySigningPublicDer = recoverySigning.publicKey.export({ format: "der", type: "spki" });
  const recoverySigningPublic = Buffer.from(recoverySigningPublicDer).subarray(-32);
  const pinnedWitness = { keyId: witnessKeyId, publicKey: witness.publicKey };
  const previousManifest = {
    type: "rootark-recovery-manifest-v2",
    version: 2,
    suite: "rootark-zk-1",
    account_id: accountId,
    compartment_id: compartmentId,
    keyring_id: keyringId,
    revision: 1,
    current_epoch: 2,
    epochs: [
      { epoch: 1, key_ref: Buffer.alloc(32, 0x61) },
      { epoch: 2, key_ref: Buffer.alloc(32, 0x62) },
    ],
    devices: [],
    recovery_authority: null,
    mac: Buffer.alloc(32, 0x66),
    actor_signature: Buffer.alloc(64, 0x77),
  };
  const previousManifestBytes = await z.encodeDeterministic(previousManifest);
  const previousManifestDigest = domainHash(MANIFEST_DIGEST_PREFIX, previousManifestBytes);
  const witnessReceipt = {
    type: "rootark-recovery-witness-head",
    witness_key_id: witnessKeyId,
    account_id: accountId,
    compartment_id: compartmentId,
    keyring_id: keyringId,
    revision: 1,
    manifest_digest: previousManifestDigest,
    witness_sequence: 1,
    nonce: Buffer.alloc(32, 0x88),
    observed_at: 1_800_000_000,
    status: "committed",
  };
  const witnessReceiptBytes = await z.encodeDeterministic(witnessReceipt);
  witnessReceipt.signature = crypto.sign(null, Buffer.concat([WITNESS_PREFIX, witnessReceiptBytes]), witness.privateKey);
  const witnessReceiptDigest = hash(await z.encodeDeterministic(witnessReceipt));
  const activationContext = {
    type: "rootark-recovery-activation-context",
    version: 1,
    suite: "rootark-zk-1",
    account_id: accountId,
    compartment_id: compartmentId,
    keyring_id: keyringId,
    package_id: packageId,
    previous_revision: 1,
    previous_manifest_digest: previousManifestDigest,
    activation_revision: 2,
    operation_id: operationId,
    hpke_key_id: Buffer.alloc(16, 0x99),
    hpke_public_key: recoveryHpkePublic,
    authorization_key_id: Buffer.alloc(16, 0x9b),
    authorization_public_key: recoverySigningPublic,
    witness_base_receipt_digest: witnessReceiptDigest,
  };
  const activationContextDigest = domainHash(
    Buffer.from("Root.ark/zk-1/recovery-activation-context/v1\0", "ascii"),
    await z.encodeDeterministic(activationContext),
  );
  const payload = {
    type: "rootark-recovery-state",
    version: 1,
    account_id: accountId,
    compartment_id: compartmentId,
    keyring_id: keyringId,
    package_id: packageId,
    previous_revision: 1,
    previous_manifest_digest: previousManifestDigest,
    activation_revision: 2,
    operation_id: operationId,
    activation_context: activationContext,
    activation_context_digest: activationContextDigest,
    witness_base_receipt: witnessReceipt,
    previous_manifest: previousManifest,
    current_epoch: 2,
    epoch_keys: [
      { epoch: 1, key: Buffer.alloc(32, 0xa1) },
      { epoch: 2, key: Buffer.alloc(32, 0xa2) },
    ],
    recovery_authorization: {
      hpke_key_id: activationContext.hpke_key_id,
      hpke_private_key: recoveryHpkePrivate,
      authorization_key_id: activationContext.authorization_key_id,
      ed25519_private_seed: recoverySigningSeed,
    },
    ...extraPayload,
  };
  return {
    payload,
    pinnedWitness,
    expectedScope: { account_id: accountId, compartment_id: compartmentId, keyring_id: keyringId },
  };
}

function useTestKdf(t) {
  let calls = 0;
  t.mock.method(recoveryKdf, "deriveRecoveryKeyBounded", async ({ password, salt }) => {
    calls += 1;
    return crypto.createHash("sha256").update("test-only KDF").update(password).update(salt).digest();
  });
  return { calls: () => calls, reset: () => { calls = 0; } };
}

test("rejectsMalformedAndOversizedEnvelopeBeforeKdf", async (t) => {
  const kdf = useTestKdf(t);
  const { payload, expectedScope, pinnedWitness } = await fixture();

  await assert.rejects(
    parseRecoveryPackageV1({ envelopeBytes: Buffer.alloc(8 * 1024 * 1024 + 1), expectedScope }),
    (error) => error.code === "RECOVERY_PACKAGE_TOO_LARGE",
  );
  await assert.rejects(
    openRecoveryPackageV1({ password: "phase-one-password", envelopeBytes: Buffer.from([0xff]), expectedScope, pinnedWitness }),
  );
  assert.equal(kdf.calls(), 0);

  const valid = await createRecoveryPackageV1({ password: "phase-one-password", payload, pinnedWitness });
  const oversizedPayload = await z.decodeDeterministic(valid);
  oversizedPayload.ciphertext = Buffer.alloc(7 * 1024 * 1024 + 1);
  kdf.reset();
  await assert.rejects(
    openRecoveryPackageV1({
      password: "phase-one-password",
      envelopeBytes: await z.encodeDeterministic(oversizedPayload),
      expectedScope,
      pinnedWitness,
    }),
    (error) => error.code === "RECOVERY_PAYLOAD_TOO_LARGE",
  );
  assert.equal(kdf.calls(), 0);
});

test("roundTripsExactEnvelopeAndDomainSeparatedDigests", async (t) => {
  useTestKdf(t);
  const { payload, pinnedWitness, expectedScope } = await fixture();
  const envelopeBytes = await createRecoveryPackageV1({ password: "phase-one-password", payload, pinnedWitness });
  const parsed = await parseRecoveryPackageV1({ envelopeBytes, expectedScope });
  const envelope = await z.decodeDeterministic(envelopeBytes);
  const opened = await openRecoveryPackageV1({ password: "phase-one-password", envelopeBytes, expectedScope, pinnedWitness });

  assert.deepEqual(Object.keys(envelope).sort(), [
    "account_id", "activation_context_digest", "activation_revision", "aead", "base_manifest_digest",
    "base_revision", "ciphertext", "compartment_id", "kdf", "operation_id", "package_id", "purpose",
    "suite", "tag", "type", "version",
  ].sort());
  assert.equal(parsed.header.activation_revision, 2);
  assert.deepEqual(await z.encodeDeterministic(opened), await z.encodeDeterministic(payload));
  assert.deepEqual(
    recoveryPackageEnvelopeDigest(envelopeBytes),
    domainHash(ENVELOPE_DIGEST_PREFIX, envelopeBytes),
  );
  assert.equal(envelope.kdf.id, "argon2id13");
  assert.equal(envelope.kdf.opslimit, 3);
  assert.equal(envelope.kdf.memlimit, 268435456);
  assert.equal(envelope.kdf.output_length, 32);
  assert.equal(Buffer.from(envelope.aead.nonce).length, 12);
});

test("roundTripsPackageUsingTheRealBoundedKdfWorker", async () => {
  const { payload, pinnedWitness, expectedScope } = await fixture();
  const envelopeBytes = await createRecoveryPackageV1({ password: "phase-one-password", payload, pinnedWitness });
  const opened = await openRecoveryPackageV1({ password: "phase-one-password", envelopeBytes, expectedScope, pinnedWitness });
  assert.deepEqual(await z.encodeDeterministic(opened), await z.encodeDeterministic(payload));
});

test("rejectsWrongPasswordTamperingAndScopeMismatch", async (t) => {
  useTestKdf(t);
  const { payload, pinnedWitness, expectedScope } = await fixture();
  const envelopeBytes = await createRecoveryPackageV1({ password: "phase-one-password", payload, pinnedWitness });
  const envelope = await z.decodeDeterministic(envelopeBytes);

  await assert.rejects(
    openRecoveryPackageV1({ password: "wrong-password", envelopeBytes, expectedScope, pinnedWitness }),
    (error) => error.code === "AUTHENTICATION_FAILED",
  );
  const changedCiphertext = { ...envelope, ciphertext: Buffer.from(envelope.ciphertext) };
  changedCiphertext.ciphertext[0] ^= 1;
  await assert.rejects(
    openRecoveryPackageV1({
      password: "phase-one-password",
      envelopeBytes: await z.encodeDeterministic(changedCiphertext),
      expectedScope,
      pinnedWitness,
    }),
    (error) => error.code === "AUTHENTICATION_FAILED",
  );
  await assert.rejects(
    openRecoveryPackageV1({
      password: "phase-one-password",
      envelopeBytes,
      expectedScope: { ...expectedScope, account_id: Buffer.alloc(16, 0xee) },
      pinnedWitness,
    }),
    (error) => error.code === "SCOPE_MISMATCH",
  );
});

test("requiresContiguousCompleteEpochKeys", async (t) => {
  const kdf = useTestKdf(t);
  const { payload, pinnedWitness } = await fixture();

  await assert.rejects(
    createRecoveryPackageV1({
      password: "phase-one-password",
      payload: { ...payload, epoch_keys: [payload.epoch_keys[1]] },
      pinnedWitness,
    }),
    (error) => error.code === "KEY_COVERAGE_INCOMPLETE",
  );
  assert.equal(kdf.calls(), 0);
});

test("rejectsInvalidOrWrongScopeBaseWitnessReceipt", async (t) => {
  useTestKdf(t);
  const { payload, pinnedWitness } = await fixture();
  const badReceipt = { ...payload.witness_base_receipt, manifest_digest: Buffer.alloc(32, 0xff) };

  await assert.rejects(
    createRecoveryPackageV1({
      password: "phase-one-password",
      payload: { ...payload, witness_base_receipt: badReceipt },
      pinnedWitness,
    }),
    (error) => error.code === "INVALID_RECOVERY_PACKAGE",
  );
  await assert.rejects(
    createRecoveryPackageV1({ password: "phase-one-password", payload, pinnedWitness: { ...pinnedWitness, keyId: Buffer.alloc(16, 0x01) } }),
    (error) => error.code === "INVALID_RECOVERY_PACKAGE",
  );
  await assert.rejects(
    createRecoveryPackageV1({
      password: "phase-one-password",
      payload: {
        ...payload,
        recovery_authorization: {
          ...payload.recovery_authorization,
          hpke_private_key: Buffer.alloc(32, 0xee),
        },
      },
      pinnedWitness,
    }),
    (error) => error.code === "INVALID_RECOVERY_PACKAGE",
  );
});

test("digestChangesForOneByteEnvelopeSubstitution", async () => {
  const bytes = Buffer.from([0x01, 0x02, 0x03]);
  const changed = Buffer.from(bytes);
  changed[1] ^= 1;
  assert.notDeepEqual(recoveryPackageEnvelopeDigest(bytes), recoveryPackageEnvelopeDigest(changed));
});

test("rejectsUnsupportedKdfTupleBeforeWorkerStarts", async (t) => {
  const kdf = useTestKdf(t);
  const { payload, pinnedWitness, expectedScope } = await fixture();
  const valid = await createRecoveryPackageV1({ password: "phase-one-password", payload, pinnedWitness });
  const envelope = await z.decodeDeterministic(valid);
  envelope.kdf.memlimit = 8192;
  kdf.reset();
  await assert.rejects(
    openRecoveryPackageV1({
      password: "phase-one-password",
      envelopeBytes: await z.encodeDeterministic(envelope),
      expectedScope,
      pinnedWitness,
    }),
    (error) => error.code === "UNSUPPORTED_KDF_PROFILE",
  );
  assert.equal(kdf.calls(), 0);
});

test("rejectsV1AndUnexpectedRootKeyInV2WithoutChangingV1Shape", async (t) => {
  useTestKdf(t);
  const keyring = require("../src/crypto/rootark-zk-keyring");
  const v1 = await keyring.createAccountKeyring();
  const v1Manifest = keyring.exportManifest(v1);
  assert.equal(v1.rootKey.length, 32);
  assert.equal(v1Manifest.version, 1);
  assert.ok(Object.hasOwn(v1, "rootKey"));

  const { payload, pinnedWitness } = await fixture();
  await assert.rejects(
    createRecoveryPackageV1({
      password: "phase-one-password",
      payload: { ...payload, rootKey: Buffer.alloc(32, 0xcc) },
      pinnedWitness,
    }),
    (error) => error.code === "INVALID_RECOVERY_PACKAGE",
  );
  const hiddenRootKey = { ...payload };
  Object.defineProperty(hiddenRootKey, "rootKey", { value: Buffer.alloc(32, 0xdd) });
  await assert.rejects(
    createRecoveryPackageV1({ password: "phase-one-password", payload: hiddenRootKey, pinnedWitness }),
    (error) => error.code === "INVALID_RECOVERY_PACKAGE",
  );
});
