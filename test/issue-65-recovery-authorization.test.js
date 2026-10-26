"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const a = require("../src/crypto/rootark-zk-recovery-authorization");

const INFO_PREFIX = Buffer.from("Root.ark/zk-1/recovery-target-pop-info/v1\0", "ascii");
const AAD_PREFIX = Buffer.from("Root.ark/zk-1/recovery-target-pop-aad/v1\0", "ascii");
const RESPONSE_PREFIX = Buffer.from("Root.ark/zk-1/recovery-target-pop-response/v1\0", "ascii");
const TARGET_KEYS_PREFIX = Buffer.from("Root.ark/zk-1/target-device-keys/v1\0", "ascii");

function rawEd25519Public(publicKey) {
  return Buffer.from(publicKey.export({ format: "der", type: "spki" })).subarray(-32);
}

async function expectedTargetDeviceKeyDigest(deviceId, hpkeKeyId, hpkePublicKey, authorizationKeyId, authorizationPublicKey) {
  const encoded = await z.encodeDeterministic({
    device_id: deviceId,
    hpke_key_id: hpkeKeyId,
    hpke_public_key: hpkePublicKey,
    authorization_key_id: authorizationKeyId,
    authorization_public_key: authorizationPublicKey,
  });
  return crypto.createHash("sha256").update(TARGET_KEYS_PREFIX).update(encoded).digest();
}

test("bindsChallengeToScopeTargetAndOperation", async () => {
  const targetHpke = await z.hpkeSuite().kem.generateKeyPair();
  const targetAuthorization = crypto.generateKeyPairSync("ed25519");
  const hpkeKeyId = Buffer.alloc(16, 0x31);
  const authorizationKeyId = Buffer.alloc(16, 0x32);
  const hpkePublicKey = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(targetHpke.publicKey));
  const authorizationPublicKey = rawEd25519Public(targetAuthorization.publicKey);
  const scope = {
    account_id: Buffer.alloc(16, 1),
    compartment_id: Buffer.from("compartment-a"),
    keyring_id: Buffer.alloc(16, 2),
  };
  const challenge = await a.createTargetPopChallenge({
    scope,
    operationId: Buffer.alloc(16, 3),
    targetDeviceId: "device-b",
    hpkeKeyId,
    hpkePublicKey,
    authorizationKeyId,
    authorizationPublicKey,
    issuedAt: 1000,
    expiresAt: 1300,
  });

  assert.equal(challenge.enc.length, 32);
  assert.equal(challenge.ciphertext.length, 48);
  assert.equal(challenge.challengeContext.challenge_id.length, 16);
  assert.deepEqual(challenge.challengeContext.account_id, scope.account_id);
  assert.deepEqual(challenge.challengeContext.compartment_id, scope.compartment_id);
  assert.deepEqual(challenge.challengeContext.keyring_id, scope.keyring_id);
  assert.deepEqual(challenge.challengeContext.operation_id, Buffer.alloc(16, 3));
  assert.equal(challenge.challengeContext.target_device_id, "device-b");
  assert.deepEqual(challenge.challengeContext.target_device_key_digest,
    await expectedTargetDeviceKeyDigest("device-b", hpkeKeyId, hpkePublicKey, authorizationKeyId, authorizationPublicKey));
});

test("acceptsOnlyMatchingChallengeAndTargetSignature", async () => {
  const targetHpke = await z.hpkeSuite().kem.generateKeyPair();
  const targetAuthorization = crypto.generateKeyPairSync("ed25519");
  const hpkeKeyId = Buffer.alloc(16, 0x41);
  const authorizationKeyId = Buffer.alloc(16, 0x42);
  const hpkePublicKey = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(targetHpke.publicKey));
  const authorizationPublicKey = rawEd25519Public(targetAuthorization.publicKey);
  const scope = {
    account_id: Buffer.alloc(16, 4),
    compartment_id: Buffer.from("compartment-b"),
    keyring_id: Buffer.alloc(16, 5),
  };
  const challenge = await a.createTargetPopChallenge({
    scope,
    operationId: Buffer.alloc(16, 6),
    targetDeviceId: "device-c",
    hpkeKeyId,
    hpkePublicKey,
    authorizationKeyId,
    authorizationPublicKey,
    issuedAt: 1000,
    expiresAt: 1300,
  });
  const plaintext = await z.hpkeOpen({
    recipientKey: targetHpke.privateKey,
    enc: challenge.enc,
    ciphertext: challenge.ciphertext,
    info: Buffer.concat([INFO_PREFIX, await z.encodeDeterministic(challenge.challengeContext)]),
    aad: Buffer.concat([AAD_PREFIX, await z.encodeDeterministic(challenge.challengeContext)]),
  });
  const responseBody = { challenge_context: challenge.challengeContext, challenge: plaintext };
  const response = {
    ...responseBody,
    target_signature: crypto.sign(
      null,
      Buffer.concat([RESPONSE_PREFIX, await z.encodeDeterministic(responseBody)]),
      targetAuthorization.privateKey,
    ),
  };
  const proof = await a.verifyTargetPopResponse({
    challenge,
    challengeContext: challenge.challengeContext,
    response,
    expectedScope: scope,
    expectedDeviceKeyDigest: challenge.challengeContext.target_device_key_digest,
    targetAuthorizationPublicKey: authorizationPublicKey,
    now: 1100,
  });
  assert.deepEqual(proof.challenge, plaintext);
  assert.deepEqual(proof.challenge_context, challenge.challengeContext);
  assert.equal(await a.isVerifiedTargetPopResponse(proof, 1100), true);
  assert.equal(await a.isVerifiedTargetPopResponse(proof), false);
  assert.equal(await a.isVerifiedTargetPopResponse(proof, 1301), false);

  await assert.rejects(
    a.verifyTargetPopResponse({
      challenge,
      challengeContext: challenge.challengeContext,
      response: { ...response, challenge: Buffer.alloc(32, 0xff) },
      expectedScope: scope,
      expectedDeviceKeyDigest: challenge.challengeContext.target_device_key_digest,
      now: 1100,
    }),
    (error) => error instanceof z.RootarkZkError && error.code === "INVALID_TARGET_POP",
  );

  for (const invalid of [
    { expectedDeviceKeyDigest: Buffer.alloc(32, 0xff), expectedScope: scope, now: 1100 },
    { expectedDeviceKeyDigest: challenge.challengeContext.target_device_key_digest, expectedScope: { ...scope, keyring_id: Buffer.alloc(16, 0xff) }, now: 1100 },
    { expectedDeviceKeyDigest: challenge.challengeContext.target_device_key_digest, expectedScope: scope, now: 1301 },
    { expectedDeviceKeyDigest: challenge.challengeContext.target_device_key_digest, expectedScope: scope },
  ]) {
    await assert.rejects(
      a.verifyTargetPopResponse({
        challenge,
        challengeContext: challenge.challengeContext,
        response,
        ...invalid,
      }),
      (error) => error instanceof z.RootarkZkError && error.code === "INVALID_TARGET_POP",
    );
  }
});

test("publicTranscriptAloneDoesNotProveTargetHpkePossession", async () => {
  const targetHpke = await z.hpkeSuite().kem.generateKeyPair();
  const targetAuthorization = crypto.generateKeyPairSync("ed25519");
  const authorizationPublicKey = rawEd25519Public(targetAuthorization.publicKey);
  const scope = {
    account_id: Buffer.alloc(16, 7),
    compartment_id: Buffer.from("compartment-c"),
    keyring_id: Buffer.alloc(16, 8),
  };
  const challenge = await a.createTargetPopChallenge({
    scope,
    operationId: Buffer.alloc(16, 9),
    targetDeviceId: "device-d",
    hpkeKeyId: Buffer.alloc(16, 0x51),
    hpkePublicKey: Buffer.from(await z.hpkeSuite().kem.serializePublicKey(targetHpke.publicKey)),
    authorizationKeyId: Buffer.alloc(16, 0x52),
    authorizationPublicKey: rawEd25519Public(targetAuthorization.publicKey),
    issuedAt: 1000,
    expiresAt: 1300,
  });
  const plaintext = await z.hpkeOpen({
    recipientKey: targetHpke.privateKey,
    enc: challenge.enc,
    ciphertext: challenge.ciphertext,
    info: Buffer.concat([INFO_PREFIX, await z.encodeDeterministic(challenge.challengeContext)]),
    aad: Buffer.concat([AAD_PREFIX, await z.encodeDeterministic(challenge.challengeContext)]),
  });
  const responseBody = { challenge_context: challenge.challengeContext, challenge: plaintext };
  const response = {
    ...responseBody,
    target_signature: crypto.sign(null,
      Buffer.concat([RESPONSE_PREFIX, await z.encodeDeterministic(responseBody)]),
      targetAuthorization.privateKey),
  };
  const transcript = await a.verifyTargetPopTranscript({
    transcript: {
      challenge_context: challenge.challengeContext,
      enc: challenge.enc,
      ciphertext: challenge.ciphertext,
      challenge: plaintext,
      target_signature: response.target_signature,
    },
    expectedScope: scope,
    expectedDeviceKeyDigest: challenge.challengeContext.target_device_key_digest,
    targetAuthorizationPublicKey: authorizationPublicKey,
    now: 1100,
  });
  assert.equal(transcript.targetSignatureValid, true);
  assert.equal(transcript.hpkePossessionProven, false);
  await assert.rejects(
    a.verifyTargetPopResponse({
      challenge: null,
      challengeContext: challenge.challengeContext,
      response,
      expectedScope: scope,
      expectedDeviceKeyDigest: challenge.challengeContext.target_device_key_digest,
      now: 1100,
    }),
    (error) => error instanceof z.RootarkZkError && error.code === "INVALID_TARGET_POP",
  );
});
