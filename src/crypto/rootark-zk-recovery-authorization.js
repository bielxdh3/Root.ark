"use strict";

const crypto = require("node:crypto");
const z = require("./rootark-zk-1");

const INFO_PREFIX = Buffer.from("Root.ark/zk-1/recovery-target-pop-info/v1\0", "ascii");
const AAD_PREFIX = Buffer.from("Root.ark/zk-1/recovery-target-pop-aad/v1\0", "ascii");
const RESPONSE_PREFIX = Buffer.from("Root.ark/zk-1/recovery-target-pop-response/v1\0", "ascii");
const TARGET_KEYS_PREFIX = Buffer.from("Root.ark/zk-1/target-device-keys/v1\0", "ascii");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const CHALLENGE_FIELDS = Object.freeze([
  "type", "version", "account_id", "compartment_id", "keyring_id", "operation_id",
  "target_device_id", "target_device_key_digest", "challenge_id", "issued_at", "expires_at",
]);
const TRANSCRIPT_FIELDS = Object.freeze([
  "challenge_context", "enc", "ciphertext", "challenge", "target_signature",
]);
const RESPONSE_FIELDS = Object.freeze(["challenge_context", "challenge", "target_signature"]);
const challengeState = new WeakMap();
const verifiedResponses = new WeakMap();

function fail() {
  throw new z.RootarkZkError("INVALID_TARGET_POP");
}

function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}

function bytes(value, length) {
  if (!isBytes(value) || (length !== undefined && value.byteLength !== length)) fail();
  return Buffer.from(value);
}

function exactMap(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail();
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || keys.some((key) => typeof key !== "string" || !fields.includes(key))
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
  return value;
}

function safeText(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 64) fail();
  return value;
}

function safeTime(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail();
  return value;
}

function sameBytes(left, right) {
  return isBytes(left) && isBytes(right) && left.byteLength === right.byteLength
    && crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

function cloneContext(context) {
  return Object.fromEntries(Object.entries(context).map(([key, value]) => [
    key,
    isBytes(value) ? Buffer.from(value) : value,
  ]));
}

async function sameCanonical(left, rightBytes) {
  try {
    return sameBytes(await z.encodeDeterministic(left), rightBytes);
  } catch (_) {
    return false;
  }
}

async function recoveryTargetDeviceKeyDigest(input) {
  const value = {
    device_id: safeText(input.deviceId),
    hpke_key_id: bytes(input.hpkeKeyId, 16),
    hpke_public_key: bytes(input.hpkePublicKey, 32),
    authorization_key_id: bytes(input.authorizationKeyId, 16),
    authorization_public_key: bytes(input.authorizationPublicKey, 32),
  };
  return crypto.createHash("sha256")
    .update(TARGET_KEYS_PREFIX)
    .update(await z.encodeDeterministic(value))
    .digest();
}

function validateScope(scope) {
  if (!scope || typeof scope !== "object") fail();
  const compartmentId = bytes(scope.compartment_id);
  if (compartmentId.byteLength < 1 || compartmentId.byteLength > 128) fail();
  return {
    account_id: bytes(scope.account_id, 16),
    compartment_id: compartmentId,
    keyring_id: bytes(scope.keyring_id, 16),
  };
}

function validateChallengeContext(context) {
  exactMap(context, CHALLENGE_FIELDS);
  if (context.type !== "Root.ark-recovery-target-pop" || context.version !== 1) fail();
  bytes(context.account_id, 16);
  bytes(context.compartment_id);
  if (context.compartment_id.byteLength < 1 || context.compartment_id.byteLength > 128) fail();
  bytes(context.keyring_id, 16);
  bytes(context.operation_id, 16);
  safeText(context.target_device_id);
  bytes(context.target_device_key_digest, 32);
  bytes(context.challenge_id, 16);
  const issuedAt = safeTime(context.issued_at);
  const expiresAt = safeTime(context.expires_at);
  if (expiresAt <= issuedAt || expiresAt - issuedAt > 300) fail();
  return context;
}

function validateLiveWindow(context, now) {
  if (now === undefined) return;
  const current = safeTime(now);
  if (current < context.issued_at - 30 || current > context.expires_at) fail();
}

function rawEd25519PublicKey(keyBytes) {
  try {
    return crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, bytes(keyBytes, 32)]),
      format: "der",
      type: "spki",
    });
  } catch (_) {
    fail();
  }
}

async function verifyTranscriptSignature(transcript, publicKeyBytes) {
  const response = { challenge_context: transcript.challenge_context, challenge: transcript.challenge };
  const signatureInput = Buffer.concat([RESPONSE_PREFIX, await z.encodeDeterministic(response)]);
  try {
    if (!crypto.verify(null, signatureInput, rawEd25519PublicKey(publicKeyBytes), bytes(transcript.target_signature, 64))) fail();
  } catch (_) {
    fail();
  }
}

async function createTargetPopChallenge(input) {
  try {
    const scope = validateScope(input.scope);
    const deviceId = safeText(input.targetDeviceId);
    const hpkeKeyId = bytes(input.hpkeKeyId, 16);
    const hpkePublicKey = bytes(input.hpkePublicKey, 32);
    const authorizationKeyId = bytes(input.authorizationKeyId, 16);
    const authorizationPublicKey = bytes(input.authorizationPublicKey, 32);
    const issuedAt = safeTime(input.issuedAt);
    const expiresAt = safeTime(input.expiresAt);
    if (expiresAt <= issuedAt || expiresAt - issuedAt > 300) fail();
    const context = {
      type: "Root.ark-recovery-target-pop",
      version: 1,
      ...scope,
      operation_id: bytes(input.operationId, 16),
      target_device_id: deviceId,
      target_device_key_digest: await recoveryTargetDeviceKeyDigest({
        deviceId,
        hpkeKeyId,
        hpkePublicKey,
        authorizationKeyId,
        authorizationPublicKey,
      }),
      challenge_id: crypto.randomBytes(16),
      issued_at: issuedAt,
      expires_at: expiresAt,
    };
    const challengeContext = await z.encodeDeterministic(context);
    const challenge = crypto.randomBytes(32);
    const recipientPublicKey = await z.hpkeSuite().kem.deserializePublicKey(hpkePublicKey);
    const sealed = await z.hpkeSeal({
      recipientPublicKey,
      plaintext: challenge,
      info: Buffer.concat([INFO_PREFIX, challengeContext]),
      aad: Buffer.concat([AAD_PREFIX, challengeContext]),
    });
    const result = Object.freeze({
      challengeContext: context,
      enc: Buffer.from(sealed.enc),
      ciphertext: Buffer.from(sealed.ciphertext),
    });
    challengeState.set(result, {
      challenge,
      challengeContext,
      context: cloneContext(context),
      enc: Buffer.from(sealed.enc),
      ciphertext: Buffer.from(sealed.ciphertext),
      authorizationPublicKey,
      targetDeviceKeyDigest: Buffer.from(context.target_device_key_digest),
    });
    return result;
  } catch (error) {
    if (error instanceof z.RootarkZkError && error.code === "INVALID_TARGET_POP") throw error;
    fail();
  }
}

async function verifyTargetPopTranscript(input) {
  try {
    const transcript = exactMap(input.transcript, TRANSCRIPT_FIELDS);
    const context = validateChallengeContext(transcript.challenge_context);
    validateLiveWindow(context, input.now);
    const scope = validateScope(input.expectedScope);
    if (!sameBytes(context.account_id, scope.account_id)
      || !sameBytes(context.compartment_id, scope.compartment_id)
      || !sameBytes(context.keyring_id, scope.keyring_id)
      || !sameBytes(context.target_device_key_digest, bytes(input.expectedDeviceKeyDigest, 32))) fail();
    bytes(transcript.enc, 32);
    bytes(transcript.ciphertext, 48);
    bytes(transcript.challenge, 32);
    await verifyTranscriptSignature(transcript, input.targetAuthorizationPublicKey);
    return Object.freeze({
      targetSignatureValid: true,
      hpkePossessionProven: false,
      challengeContext: context,
      challenge: Buffer.from(transcript.challenge),
    });
  } catch (error) {
    if (error instanceof z.RootarkZkError && error.code === "INVALID_TARGET_POP") throw error;
    fail();
  }
}

async function verifyTargetPopResponse(input) {
  try {
    const state = challengeState.get(input.challenge);
    if (!state || !await sameCanonical(input.challengeContext, state.challengeContext)) fail();
    const response = exactMap(input.response, RESPONSE_FIELDS);
    if (!await sameCanonical(response.challenge_context, state.challengeContext)
      || !sameBytes(response.challenge, state.challenge)) fail();
    const transcript = {
      challenge_context: response.challenge_context,
      enc: state.enc,
      ciphertext: state.ciphertext,
      challenge: response.challenge,
      target_signature: response.target_signature,
    };
    await verifyTargetPopTranscript({
      transcript,
      expectedScope: input.expectedScope,
      expectedDeviceKeyDigest: input.expectedDeviceKeyDigest,
      targetAuthorizationPublicKey: state.authorizationPublicKey,
      now: input.now,
    });
    const verified = Object.freeze({
      challenge_context: cloneContext(state.context),
      enc: Buffer.from(state.enc),
      ciphertext: Buffer.from(state.ciphertext),
      challenge: Buffer.from(response.challenge),
      target_signature: Buffer.from(response.target_signature),
    });
    verifiedResponses.set(verified, await z.encodeDeterministic(verified));
    return verified;
  } catch (error) {
    if (error instanceof z.RootarkZkError && error.code === "INVALID_TARGET_POP") throw error;
    fail();
  }
}

async function isVerifiedTargetPopResponse(proof) {
  const snapshot = proof && verifiedResponses.get(proof);
  if (!snapshot) return false;
  try {
    return sameBytes(snapshot, await z.encodeDeterministic(proof));
  } catch (_) {
    return false;
  }
}

module.exports = {
  createTargetPopChallenge,
  isVerifiedTargetPopResponse,
  recoveryTargetDeviceKeyDigest,
  verifyTargetPopResponse,
  verifyTargetPopTranscript,
};
