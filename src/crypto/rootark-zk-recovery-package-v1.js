"use strict";

const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const recoveryKdf = require("./rootark-zk-recovery-kdf");

const MAX_ENVELOPE_BYTES = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 7 * 1024 * 1024;
const KDF_PROFILE = Object.freeze({ id: "argon2id13", opslimit: 3, memlimit: 268435456, output_length: 32 });
const AEAD_PROFILE = Object.freeze({ id: "AES-256-GCM" });
const ENVELOPE_FIELDS = Object.freeze([
  "type", "suite", "version", "purpose", "account_id", "compartment_id", "package_id",
  "base_revision", "base_manifest_digest", "activation_revision", "operation_id",
  "activation_context_digest", "kdf", "aead", "ciphertext", "tag",
]);
const PAYLOAD_FIELDS = Object.freeze([
  "type", "version", "account_id", "compartment_id", "keyring_id", "package_id",
  "previous_revision", "previous_manifest_digest", "activation_revision", "operation_id",
  "activation_context", "activation_context_digest", "witness_base_receipt", "previous_manifest",
  "current_epoch", "epoch_keys", "recovery_authorization",
]);
const ACTIVATION_CONTEXT_FIELDS = Object.freeze([
  "type", "version", "suite", "account_id", "compartment_id", "keyring_id", "package_id",
  "previous_revision", "previous_manifest_digest", "activation_revision", "operation_id",
  "hpke_key_id", "hpke_public_key", "authorization_key_id", "authorization_public_key",
  "witness_base_receipt_digest",
]);
const WITNESS_RECEIPT_FIELDS = Object.freeze([
  "type", "witness_key_id", "account_id", "compartment_id", "keyring_id", "revision",
  "manifest_digest", "witness_sequence", "nonce", "observed_at", "status", "signature",
]);
const RECOVERY_AUTHORIZATION_FIELDS = Object.freeze([
  "hpke_key_id", "hpke_private_key", "authorization_key_id", "ed25519_private_seed",
]);
const EPOCH_KEY_FIELDS = Object.freeze(["epoch", "key"]);
const AAD_PREFIX = Buffer.from("Root.ark/zk-1/recovery-package/v1\0", "ascii");
const ACTIVATION_CONTEXT_PREFIX = Buffer.from("Root.ark/zk-1/recovery-activation-context/v1\0", "ascii");
const ENVELOPE_DIGEST_PREFIX = Buffer.from("Root.ark/zk-1/recovery-package-envelope/v1\0", "ascii");
const MANIFEST_DIGEST_PREFIX = Buffer.from("Root.ark/zk-1/recovery-manifest-digest/v1\0", "ascii");
const WITNESS_HEAD_PREFIX = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

function fail(code = "INVALID_RECOVERY_PACKAGE") {
  throw new z.RootarkZkError(code);
}

function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}

function exactMap(value, fields) {
  plainMap(value);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || keys.some((key) => typeof key !== "string" || !fields.includes(key))
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
  return value;
}

function plainMap(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail();
  if (Reflect.ownKeys(value).some((key) => typeof key !== "string"
    || key === "__proto__" || key === "constructor" || key === "prototype")) fail();
  return value;
}

function bytes(value, length, min, max) {
  if (!isBytes(value)) fail();
  if (length !== undefined && value.byteLength !== length) fail();
  if (min !== undefined && value.byteLength < min) fail();
  if (max !== undefined && value.byteLength > max) fail();
  return Buffer.from(value);
}

function u64(value, minimum = 0n) {
  let n;
  if (typeof value === "bigint") n = value;
  else if (Number.isSafeInteger(value)) n = BigInt(value);
  else fail();
  if (n < minimum || n > 0xffffffffffffffffn) fail();
  return n;
}

function sameBytes(left, right) {
  return isBytes(left) && isBytes(right) && left.byteLength === right.byteLength
    && crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

function domainHash(prefix, data) {
  return crypto.createHash("sha256").update(prefix).update(data).digest();
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest();
}

async function digestMap(prefix, value) {
  return domainHash(prefix, await z.encodeDeterministic(value));
}

function headerFromEnvelope(envelope) {
  const header = {};
  for (const field of ENVELOPE_FIELDS) {
    if (field !== "ciphertext" && field !== "tag") header[field] = envelope[field];
  }
  return header;
}

function validateExpectedScope(expectedScope) {
  if (!expectedScope || typeof expectedScope !== "object") fail();
  bytes(expectedScope.account_id, 16);
  bytes(expectedScope.compartment_id, undefined, 1, 128);
  if (expectedScope.keyring_id !== undefined) bytes(expectedScope.keyring_id, 16);
}

async function parseRecoveryPackageV1(input) {
  if (!input || !isBytes(input.envelopeBytes)) fail();
  if (input.envelopeBytes.byteLength > MAX_ENVELOPE_BYTES) fail("RECOVERY_PACKAGE_TOO_LARGE");
  validateExpectedScope(input.expectedScope);

  let envelope;
  try {
    envelope = await z.decodeDeterministic(input.envelopeBytes);
  } catch (_) {
    fail();
  }
  exactMap(envelope, ENVELOPE_FIELDS);
  if (envelope.type !== "rootark-recovery-package" || envelope.suite !== "rootark-zk-1"
    || envelope.version !== 1 || envelope.purpose !== "recovery-package") fail();
  bytes(envelope.account_id, 16);
  bytes(envelope.compartment_id, undefined, 1, 128);
  bytes(envelope.package_id, 16);
  bytes(envelope.base_manifest_digest, 32);
  bytes(envelope.operation_id, 16);
  bytes(envelope.activation_context_digest, 32);
  const baseRevision = u64(envelope.base_revision, 1n);
  const activationRevision = u64(envelope.activation_revision, 1n);
  if (activationRevision !== baseRevision + 1n) fail();

  if (!sameBytes(envelope.account_id, input.expectedScope.account_id)
    || !sameBytes(envelope.compartment_id, input.expectedScope.compartment_id)) fail("SCOPE_MISMATCH");

  exactMap(envelope.kdf, ["id", "salt", "opslimit", "memlimit", "output_length"]);
  bytes(envelope.kdf.salt, 16);
  if (envelope.kdf.id !== KDF_PROFILE.id || envelope.kdf.opslimit !== KDF_PROFILE.opslimit
    || envelope.kdf.memlimit !== KDF_PROFILE.memlimit || envelope.kdf.output_length !== KDF_PROFILE.output_length) {
    fail("UNSUPPORTED_KDF_PROFILE");
  }
  exactMap(envelope.aead, ["id", "nonce"]);
  if (envelope.aead.id !== AEAD_PROFILE.id) fail();
  bytes(envelope.aead.nonce, 12);
  bytes(envelope.ciphertext, undefined, 0, MAX_ENVELOPE_BYTES);
  if (envelope.ciphertext.byteLength > MAX_PAYLOAD_BYTES) fail("RECOVERY_PAYLOAD_TOO_LARGE");
  bytes(envelope.tag, 16);

  const header = headerFromEnvelope(envelope);
  return Object.freeze({
    envelopeBytes: Buffer.from(input.envelopeBytes),
    envelope,
    header,
    aad: Buffer.concat([AAD_PREFIX, await z.encodeDeterministic(header)]),
  });
}

async function verifyPinnedWitness(pinnedWitness, receipt) {
  if (!pinnedWitness || !isBytes(pinnedWitness.keyId)
    || !(pinnedWitness.publicKey instanceof crypto.KeyObject)
    || pinnedWitness.publicKey.type !== "public"
    || pinnedWitness.publicKey.asymmetricKeyType !== "ed25519") fail();
  if (!sameBytes(pinnedWitness.keyId, receipt.witness_key_id)) fail();
  const signature = bytes(receipt.signature, 64);
  const unsigned = {};
  for (const field of WITNESS_RECEIPT_FIELDS) {
    if (field !== "signature") unsigned[field] = receipt[field];
  }
  const signingBytes = Buffer.concat([WITNESS_HEAD_PREFIX, await z.encodeDeterministic(unsigned)]);
  let valid = false;
  try {
    valid = crypto.verify(null, signingBytes, pinnedWitness.publicKey, signature);
  } catch (_) {
    valid = false;
  }
  if (!valid) fail();
}

async function verifyRecoveryAuthorizationKeys(authorization, context) {
  const hpkePrivate = bytes(authorization.hpke_private_key, 32);
  const signingSeed = bytes(authorization.ed25519_private_seed, 32);
  try {
    const hpkePrivateKey = crypto.createPrivateKey({
      key: Buffer.concat([X25519_PKCS8_PREFIX, hpkePrivate]),
      format: "der",
      type: "pkcs8",
    });
    const hpkePublicDer = crypto.createPublicKey(hpkePrivateKey).export({ format: "der", type: "spki" });
    const hpkePublic = Buffer.from(hpkePublicDer).subarray(-32);
    const signingPrivateKey = crypto.createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_PREFIX, signingSeed]),
      format: "der",
      type: "pkcs8",
    });
    const signingPublicDer = crypto.createPublicKey(signingPrivateKey).export({ format: "der", type: "spki" });
    const signingPublic = Buffer.from(signingPublicDer).subarray(-32);
    if (!sameBytes(hpkePublic, context.hpke_public_key)
      || !sameBytes(signingPublic, context.authorization_public_key)) fail();
  } catch (_) {
    fail();
  } finally {
    z.clearSecret(hpkePrivate);
    z.clearSecret(signingSeed);
  }
}

async function validatePayload(payload, pinnedWitness, expectedScope) {
  exactMap(payload, PAYLOAD_FIELDS);
  if (payload.type !== "rootark-recovery-state" || payload.version !== 1) fail();
  bytes(payload.account_id, 16);
  bytes(payload.compartment_id, undefined, 1, 128);
  bytes(payload.keyring_id, 16);
  bytes(payload.package_id, 16);
  bytes(payload.previous_manifest_digest, 32);
  bytes(payload.operation_id, 16);
  bytes(payload.activation_context_digest, 32);
  const previousRevision = u64(payload.previous_revision, 1n);
  const activationRevision = u64(payload.activation_revision, 1n);
  const currentEpoch = u64(payload.current_epoch, 1n);
  if (activationRevision !== previousRevision + 1n) fail();

  const manifest = plainMap(payload.previous_manifest);
  if (u64(manifest.revision, 1n) !== previousRevision
    || u64(manifest.current_epoch, 1n) !== currentEpoch
    || !sameBytes(manifest.account_id, payload.account_id)
    || !sameBytes(manifest.compartment_id, payload.compartment_id)
    || !sameBytes(manifest.keyring_id, payload.keyring_id)) fail();
  if (!Array.isArray(manifest.epochs) || manifest.epochs.length < 1) fail();
  const manifestEpochs = manifest.epochs.map((entry) => {
    exactMap(entry, ["epoch", "key_ref"]);
    bytes(entry.key_ref, 32);
    return u64(entry.epoch, 1n);
  });
  if (manifestEpochs.some((epoch, index) => index > 0 && epoch !== manifestEpochs[index - 1] + 1n)) fail();
  if (manifestEpochs[manifestEpochs.length - 1] !== currentEpoch) fail();
  const computedManifestDigest = await digestMap(MANIFEST_DIGEST_PREFIX, manifest);
  if (!sameBytes(computedManifestDigest, payload.previous_manifest_digest)) fail();

  exactMap(payload.activation_context, ACTIVATION_CONTEXT_FIELDS);
  const context = payload.activation_context;
  if (context.type !== "rootark-recovery-activation-context" || context.version !== 1
    || context.suite !== "rootark-zk-1"
    || !sameBytes(context.account_id, payload.account_id)
    || !sameBytes(context.compartment_id, payload.compartment_id)
    || !sameBytes(context.keyring_id, payload.keyring_id)
    || !sameBytes(context.package_id, payload.package_id)
    || u64(context.previous_revision, 1n) !== previousRevision
    || !sameBytes(context.previous_manifest_digest, payload.previous_manifest_digest)
    || u64(context.activation_revision, 1n) !== activationRevision
    || !sameBytes(context.operation_id, payload.operation_id)) fail();
  bytes(context.hpke_key_id, 16);
  bytes(context.hpke_public_key, 32);
  bytes(context.authorization_key_id, 16);
  bytes(context.authorization_public_key, 32);
  bytes(context.witness_base_receipt_digest, 32);
  const computedContextDigest = await digestMap(ACTIVATION_CONTEXT_PREFIX, context);
  if (!sameBytes(computedContextDigest, payload.activation_context_digest)) fail();

  const receipt = exactMap(payload.witness_base_receipt, WITNESS_RECEIPT_FIELDS);
  if (receipt.type !== "rootark-recovery-witness-head" || receipt.status !== "committed"
    || !sameBytes(receipt.account_id, payload.account_id)
    || !sameBytes(receipt.compartment_id, payload.compartment_id)
    || !sameBytes(receipt.keyring_id, payload.keyring_id)
    || u64(receipt.revision, 1n) !== previousRevision
    || !sameBytes(receipt.manifest_digest, payload.previous_manifest_digest)) fail();
  bytes(receipt.witness_key_id, 16);
  bytes(receipt.nonce, 32);
  u64(receipt.witness_sequence, 1n);
  u64(receipt.observed_at, 0n);
  await verifyPinnedWitness(pinnedWitness, receipt);
  const receiptDigest = sha256(await z.encodeDeterministic(receipt));
  if (!sameBytes(receiptDigest, context.witness_base_receipt_digest)) fail();

  if (!Array.isArray(payload.epoch_keys) || payload.epoch_keys.length !== manifestEpochs.length) {
    fail("KEY_COVERAGE_INCOMPLETE");
  }
  for (let i = 0; i < payload.epoch_keys.length; i += 1) {
    const entry = exactMap(payload.epoch_keys[i], EPOCH_KEY_FIELDS);
    if (u64(entry.epoch, 1n) !== manifestEpochs[i]) fail("KEY_COVERAGE_INCOMPLETE");
    bytes(entry.key, 32);
  }

  const recoveryAuthorization = exactMap(payload.recovery_authorization, RECOVERY_AUTHORIZATION_FIELDS);
  bytes(recoveryAuthorization.hpke_key_id, 16);
  bytes(recoveryAuthorization.hpke_private_key, 32);
  bytes(recoveryAuthorization.authorization_key_id, 16);
  bytes(recoveryAuthorization.ed25519_private_seed, 32);
  if (!sameBytes(recoveryAuthorization.hpke_key_id, context.hpke_key_id)
    || !sameBytes(recoveryAuthorization.authorization_key_id, context.authorization_key_id)) fail();
  await verifyRecoveryAuthorizationKeys(recoveryAuthorization, context);

  if (expectedScope) {
    validateExpectedScope(expectedScope);
    if (!sameBytes(payload.account_id, expectedScope.account_id)
      || !sameBytes(payload.compartment_id, expectedScope.compartment_id)
      || (expectedScope.keyring_id && !sameBytes(payload.keyring_id, expectedScope.keyring_id))) {
      fail("SCOPE_MISMATCH");
    }
  }
  return payload;
}

async function createRecoveryPackageV1(input) {
  if (!input || typeof input !== "object") fail();
  const payload = await validatePayload(input.payload, input.pinnedWitness);
  const plaintext = await z.encodeDeterministic(payload);
  if (plaintext.byteLength > MAX_PAYLOAD_BYTES) fail("RECOVERY_PAYLOAD_TOO_LARGE");
  const salt = crypto.randomBytes(16);
  const nonce = crypto.randomBytes(12);
  const header = {
    type: "rootark-recovery-package",
    suite: "rootark-zk-1",
    version: 1,
    purpose: "recovery-package",
    account_id: payload.account_id,
    compartment_id: payload.compartment_id,
    package_id: payload.package_id,
    base_revision: payload.previous_revision,
    base_manifest_digest: payload.previous_manifest_digest,
    activation_revision: payload.activation_revision,
    operation_id: payload.operation_id,
    activation_context_digest: payload.activation_context_digest,
    kdf: { ...KDF_PROFILE, salt },
    aead: { ...AEAD_PROFILE, nonce },
  };
  const aad = Buffer.concat([AAD_PREFIX, await z.encodeDeterministic(header)]);
  let key;
  try {
    key = await recoveryKdf.deriveRecoveryKeyBounded({ password: input.password, salt });
    const sealed = z.aesGcmSeal({ key, nonce, aad, plaintext });
    const envelopeBytes = await z.encodeDeterministic({ ...header, ...sealed });
    if (envelopeBytes.byteLength > MAX_ENVELOPE_BYTES) fail("RECOVERY_PACKAGE_TOO_LARGE");
    return envelopeBytes;
  } finally {
    if (key) z.clearSecret(key);
    z.clearSecret(plaintext);
    z.clearSecret(salt);
  }
}

async function openRecoveryPackageV1(input) {
  if (!input || typeof input !== "object") fail();
  const parsed = await parseRecoveryPackageV1(input);
  let key;
  let plaintext;
  try {
    key = await recoveryKdf.deriveRecoveryKeyBounded({
      password: input.password,
      salt: Buffer.from(parsed.envelope.kdf.salt),
    });
    try {
      plaintext = z.aesGcmOpen({
        key,
        nonce: Buffer.from(parsed.envelope.aead.nonce),
        aad: parsed.aad,
        ciphertext: Buffer.from(parsed.envelope.ciphertext),
        tag: Buffer.from(parsed.envelope.tag),
      });
    } catch (_) {
      fail("AUTHENTICATION_FAILED");
    }
    if (plaintext.byteLength > MAX_PAYLOAD_BYTES) fail("RECOVERY_PAYLOAD_TOO_LARGE");
    let payload;
    try {
      payload = await z.decodeDeterministic(plaintext);
    } catch (_) {
      fail("INVALID_RECOVERY_PACKAGE");
    }
    await validatePayload(payload, input.pinnedWitness, input.expectedScope);
    if (!sameBytes(payload.account_id, parsed.envelope.account_id)
      || !sameBytes(payload.compartment_id, parsed.envelope.compartment_id)
      || !sameBytes(payload.package_id, parsed.envelope.package_id)
      || u64(payload.previous_revision, 1n) !== u64(parsed.envelope.base_revision, 1n)
      || !sameBytes(payload.previous_manifest_digest, parsed.envelope.base_manifest_digest)
      || u64(payload.activation_revision, 1n) !== u64(parsed.envelope.activation_revision, 1n)
      || !sameBytes(payload.operation_id, parsed.envelope.operation_id)
      || !sameBytes(payload.activation_context_digest, parsed.envelope.activation_context_digest)) fail();
    return payload;
  } finally {
    if (key) z.clearSecret(key);
    if (plaintext) z.clearSecret(plaintext);
  }
}

function recoveryPackageEnvelopeDigest(envelopeBytes) {
  if (!isBytes(envelopeBytes)) fail();
  if (envelopeBytes.byteLength > MAX_ENVELOPE_BYTES) fail("RECOVERY_PACKAGE_TOO_LARGE");
  return domainHash(ENVELOPE_DIGEST_PREFIX, Buffer.from(envelopeBytes));
}

module.exports = {
  parseRecoveryPackageV1,
  createRecoveryPackageV1,
  openRecoveryPackageV1,
  recoveryPackageEnvelopeDigest,
};
