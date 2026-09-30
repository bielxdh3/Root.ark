"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");

const b = (value, length = 8) => Buffer.alloc(length, value);
const sample = () => ({
  type: "rootark-authorization-manifest-v1",
  suite: z.SUITE_ID,
  envelope_version: 1,
  compartment_id: b(1),
  epoch: 7,
  purpose: "content",
  sender_key_id: b(2),
  recipient_key_id: b(3),
  object_id: b(4),
  version_id: b(5),
  key_ref: b(6),
  expiry: 9223372036854775807n,
  replay_id: b(7),
  idempotency_key: b(8),
  wrap_id: b(9, 16),
  hpke_enc: b(10, 32),
  hpke_info_digest: b(11, 32),
  wrapped_key_digest: b(12, 32),
  ciphertext_digest: b(13, 32),
});
const scope = (extra = {}) => ({
  profile: z.PROFILE.HPKE_INFO,
  suite: z.SUITE_ID,
  envelope_version: 1,
  compartment_id: b(1),
  epoch: 7,
  purpose: "content",
  object_id: b(4),
  version_id: b(5),
  key_ref: b(6),
  sender_key_id: b(2),
  recipient_key_id: b(3),
  wrap_id: b(9, 16),
  manifest_core_digest: b(11, 32),
  ...extra,
});
const v2StaticCore = (extra = {}) => ({
  type: "rootark-authorization-manifest-v2",
  suite: z.SUITE_ID,
  envelope_version: 2,
  compartment_id: b(1),
  epoch: 7,
  purpose: "content",
  sender_key_id: b(2),
  recipient_key_id: b(3),
  object_id: b(4),
  version_id: b(5),
  key_ref: b(6),
  expiry: 1000n,
  replay_id: b(7),
  idempotency_key: b(8),
  wrap_id: b(9, 16),
  ...extra,
});
const digest = (value) => crypto.createHash("sha256").update(value).digest();

test("rootark-zk-1 registry fails closed", () => {
  assert.equal(z.SUITE_REGISTRY[z.SUITE_ID].read, "allowed");
  assert.equal(z.SUITE_REGISTRY[z.SUITE_ID].write, "allowed");
  assert.deepEqual(z.SUITE_STATES, { ALLOWED: "allowed", DEPRECATED: "deprecated", REJECTED: "rejected" });
  assert.throws(() => z.resolveSuite("unknown"), (error) => error.code === "UNKNOWN_SUITE");
  assert.throws(() => z.resolveSuite(z.SUITE_ID, 2), (error) => error.code === "UNSUPPORTED_SUITE_VERSION");
});

test("deterministic CBOR has a stable fixture and strict rejection", async () => {
  const value = { b: 1, a: Buffer.from([1, 2]) };
  const first = await z.encodeDeterministic(value);
  const second = await z.encodeDeterministic({ a: Buffer.from([1, 2]), b: 1 });
  assert.equal(first.toString("hex"), "a26161420102616201");
  assert.deepEqual(first, second);
  assert.deepEqual(await z.decodeDeterministic(first), { a: Uint8Array.from([1, 2]), b: 1 });
  const invalid = [
    Buffer.from("a2616101616101", "hex"),
    Buffer.from("bf616101ff", "hex"),
    Buffer.concat([first, Buffer.from([0])]),
    Buffer.from("a161611801", "hex"),
    Buffer.from("a16161fb3ff0000000000000", "hex"),
    Buffer.from("c000", "hex"),
  ];
  for (const bytes of invalid) await assert.rejects(z.decodeDeterministic(bytes));
  await assert.rejects(z.encodeDeterministic(new Map([["a", 1]])));
});

test("contract byte builders are deterministic and domain separated", async () => {
  const manifest = sample();
  const { hpke_info_digest: _hpke, wrapped_key_digest: _wrapped, ciphertext_digest: _ciphertext, ...coreInput } = manifest;
  assert.equal((await z.buildManifestCoreMap(coreInput)).type, manifest.type);
  const core = await z.buildManifestCoreBytes(coreInput);
  assert.deepEqual(core, await z.buildManifestCoreBytes({ ...coreInput }));
  assert.equal((await z.buildManifestCoreDigest(coreInput)).length, 32);
  const { sender_key_id: _sender, recipient_key_id: _recipient, ...aadInput } = scope({ profile: z.PROFILE.AAD });
  const aad = await z.buildAadBytes(aadInput);
  assert.equal((await z.buildAadMap(aadInput)).profile, z.PROFILE.AAD);
  const info = await z.buildHpkeInfoBytes(scope());
  assert.equal((await z.buildHpkeInfoMap(scope())).suite, z.SUITE_ID);
  const wrap = await z.buildWrapInfo({
    suite: z.SUITE_ID,
    compartment_id: b(1),
    epoch: 7,
    purpose: "content",
    object_id: b(4),
    version_id: b(5),
    key_ref: b(6),
    recipient_key_id: b(3),
    wrap_id: b(9, 16),
  });
  const signatureInput = await z.buildAuthorizationSignatureInput(manifest);
  assert.deepEqual(Object.keys(await z.buildManifestMap(manifest)).sort(), [
    "ciphertext_digest", "compartment_id", "epoch", "expiry", "envelope_version",
    "hpke_enc", "hpke_info_digest", "idempotency_key", "key_ref", "object_id",
    "purpose", "recipient_key_id", "replay_id", "sender_key_id", "suite", "type",
    "version_id", "wrap_id", "wrapped_key_digest",
  ].sort());
  assert.match(info.toString("ascii"), /^Root\.ark\/zk-1\/hpke-info\/v1/);
  assert.match(wrap.toString("ascii"), /^Root\.ark\/zk-1\/key-wrap\/v1/);
  assert.match(signatureInput.toString("ascii"), /^Root\.ark\/zk-1\/authorization-manifest\/v1/);
  assert.notDeepEqual(info, wrap);
  assert.equal(digest(info).toString("hex"), "fe736a0397589943ded8812a83fdce2d6ff246ba1898084ca22ff426c21a7cee");
  assert.equal(digest(aad).toString("hex"), "6a973aa27eb596d56359db09ff6ec1ea93e5dca0ff375cce837b2151cb4e40d7");
  await assert.rejects(z.buildManifestCoreBytes({ ...coreInput, suite: "other" }));
  await assert.rejects(z.buildManifestCoreBytes({ ...coreInput, wrap_id: b(9, 15) }));
  await assert.rejects(z.buildManifestCoreBytes({ ...coreInput, epoch: 0x10000000000000000n }));
  await assert.rejects(z.buildManifestCoreBytes({ ...coreInput, expiry: 0x8000000000000000n }));
  await assert.rejects(z.buildManifestCoreBytes({ ...coreInput, extra_required_field: 1 }));
  await assert.rejects(z.buildAadBytes({ ...aadInput, profile: z.PROFILE.HPKE_INFO }));
  await assert.rejects(z.buildHpkeInfoBytes({ ...scope(), profile: z.PROFILE.AAD }));
  await assert.rejects(z.buildAadBytes({ ...aadInput, purpose: "unknown" }));
  await assert.rejects(z.buildManifestBytes({ ...manifest, hpke_info_digest: b(11, 31) }));
  await assert.rejects(z.buildManifestBytes({ ...manifest, extra_required_field: 1 }));
  assert.notDeepEqual(await z.buildWrapInfo({
    suite: z.SUITE_ID,
    compartment_id: b(1),
    epoch: 7,
    purpose: "content",
    object_id: b(4),
    version_id: b(5),
    key_ref: b(6),
    recipient_key_id: b(3),
    wrap_id: b(12, 16),
  }), wrap);
});

test("v2 authorization profile has stable vectors and binds every static manifest field", async () => {
  const staticCore = v2StaticCore();
  const core = { ...staticCore, hpke_enc: b(10, 32) };
  const info = await z.buildAuthorizationHpkeInfoV2Bytes({ profile: z.PROFILE.HPKE_INFO_V2, ...staticCore });
  const coreDigest = await z.buildManifestCoreDigest(core);
  const aadInput = {
    profile: z.PROFILE.AAD_V2,
    suite: z.SUITE_ID,
    envelope_version: 2,
    compartment_id: staticCore.compartment_id,
    epoch: staticCore.epoch,
    purpose: staticCore.purpose,
    object_id: staticCore.object_id,
    version_id: staticCore.version_id,
    key_ref: staticCore.key_ref,
    wrap_id: staticCore.wrap_id,
    manifest_core_digest: coreDigest,
  };
  const aad = await z.buildAadBytes(aadInput);
  assert.equal(digest(info).toString("hex"), "8c84ed02a17eef29c5a2f01c5ff59c50b18289e42e9f87e631567496e67c4f1f");
  assert.equal(coreDigest.toString("hex"), "00c0309aada7cf718ecd9b91be25e275d902afa05b9e0e3a37fd9ffa42e8f300");
  assert.equal(digest(aad).toString("hex"), "4d516e0534197e3d87a28ce02a8d9806f783400247c33f07657e8bac9dfb8444");
  const manifest = {
    ...core,
    hpke_info_digest: b(11, 32),
    wrapped_key_digest: b(12, 32),
    ciphertext_digest: b(13, 32),
  };
  const manifestBytes = await z.buildManifestBytes(manifest);
  const signatureInput = await z.buildAuthorizationSignatureInput(manifest);
  assert.equal(digest(manifestBytes).toString("hex"), "18f4a57d4ca407e5c99e318075e61bbaa3f977513f902188752895e7cfb4ab67");
  assert.equal(digest(signatureInput).toString("hex"), "c432630648b6d6203922be026b1e29237c7e994fc9cd024fbe2eee9a22d9fced");
  assert.match(signatureInput.toString("ascii"), /^Root\.ark\/zk-1\/authorization-manifest\/v2/);
  assert.match(info.toString("ascii"), /^Root\.ark\/zk-1\/hpke-info\/v2/);
  assert.equal((await z.buildAadMap(aadInput)).profile, z.PROFILE.AAD_V2);
  assert.notDeepEqual(await z.buildAuthorizationHpkeInfoV2Bytes({ profile: z.PROFILE.HPKE_INFO_V2, ...v2StaticCore({ expiry: 1001n }) }), info);
  assert.notDeepEqual(await z.buildManifestCoreDigest({ ...core, hpke_enc: b(11, 32) }), coreDigest);
  await assert.rejects(z.buildAuthorizationHpkeInfoV2Bytes({ profile: z.PROFILE.HPKE_INFO_V2, ...staticCore, hpke_enc: b(10, 32) }));
  await assert.rejects(z.buildAuthorizationHpkeInfoV2Bytes({ profile: z.PROFILE.HPKE_INFO, ...staticCore }));
  await assert.rejects(z.buildAadBytes({ ...aadInput, profile: z.PROFILE.AAD, envelope_version: 2 }));
  await assert.rejects(z.buildManifestCoreBytes({ ...core, type: "rootark-authorization-manifest-v1" }));
  await assert.rejects(z.buildManifestCoreBytes({ ...core, envelope_version: 3 }));
});

test("AES-GCM and HKDF wrapping bind exact context and wrap_id", async () => {
  const aad = Buffer.from("test-aad");
  const plaintext = b(12, 32);
  const key = b(13, 32);
  const nonce = b(14, 12);
  const sealed = z.aesGcmSeal({ key, nonce, aad, plaintext });
  assert.deepEqual(z.aesGcmOpen({ key, nonce, aad, ...sealed }), plaintext);
  assert.throws(() => z.aesGcmOpen({ key, nonce, aad: Buffer.from("wrong"), ...sealed }));
  const wrongTag = Buffer.from(sealed.tag);
  wrongTag[0] ^= 1;
  assert.throws(() => z.aesGcmOpen({ key, nonce, aad, ciphertext: sealed.ciphertext, tag: wrongTag }));
  const input = { ...scope(), cer: b(15, 32), aad, plaintext };
  const wrapped = await z.wrapKey(input);
  assert.equal(wrapped.length, 60);
  assert.deepEqual(await z.unwrapKey({ ...input, wrapped }), plaintext);
  assert.notDeepEqual(await z.deriveWrapKey(input), await z.deriveWrapKey({ ...input, wrap_id: b(16, 16) }));
  await assert.rejects(z.unwrapKey({ ...input, wrapped: Buffer.from(wrapped).fill(0) }));
  assert.throws(() => z.aesGcmOpen({ key, nonce, aad, ciphertext: sealed.ciphertext, tag: wrongTag }), (error) => {
    assert.equal(error.message.includes(plaintext.toString("hex")), false);
    assert.equal(error.message.includes(key.toString("hex")), false);
    return error instanceof z.RootarkZkError;
  });
});

test("HKDF-SHA-256 uses IKM, salt, and info in the frozen order", async () => {
  const rfc5869 = z.hkdfSha256({
    ikm: Buffer.alloc(22, 0x0b),
    salt: Buffer.from("000102030405060708090a0b0c", "hex"),
    info: Buffer.from("f0f1f2f3f4f5f6f7f8f9", "hex"),
    length: 42,
  });
  assert.equal(rfc5869.toString("hex"), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
  const context = {
    suite: z.SUITE_ID,
    compartment_id: b(1),
    epoch: 7,
    purpose: "content",
    object_id: b(4),
    version_id: b(5),
    key_ref: b(6),
    recipient_key_id: b(3),
    wrap_id: b(9, 16),
    cer: b(15, 32),
  };
  const expected = "57acba80f742935aa8251cc51c6040c2f9509afee5a25348e86daf51dbfa86cf";
  const { cer: _cer, ...wrapContext } = context;
  const info = await z.buildWrapInfo(wrapContext);
  assert.equal((await z.deriveWrapKey(context)).toString("hex"), expected);
  assert.equal(z.hkdfSha256({ ikm: context.cer, salt: Buffer.alloc(0), info, length: 32 }).toString("hex"), expected);
  assert.notDeepEqual(await z.deriveWrapKey({ ...context, cer: b(16, 32) }), await z.deriveWrapKey(context));
  assert.notDeepEqual(z.hkdfSha256({ ikm: b(15, 32), salt: Buffer.alloc(0), info, length: 32 }), z.hkdfSha256({ ikm: b(15, 32), salt: b(1), info, length: 32 }));
  assert.notDeepEqual(z.hkdfSha256({ ikm: b(15, 32), salt: Buffer.alloc(0), info, length: 32 }), z.hkdfSha256({ ikm: b(15, 32), salt: Buffer.alloc(0), info: Buffer.concat([info, Buffer.from([1])]), length: 32 }));
  assert.notDeepEqual(await z.deriveWrapKey(context), await z.deriveWrapKey({ ...context, object_id: b(99) }));
  assert.notDeepEqual(await z.deriveWrapKey(context), await z.deriveWrapKey({ ...context, wrap_id: b(16, 16) }));
  assert.throws(() => z.hkdfSha256({ ikm: b(1), info, length: 0 }));
});

test("HPKE is RFC 9180 base mode with exact info and AAD", async () => {
  const suite = z.hpkeSuite();
  assert.equal(suite.kem.id, z.KEM_ID);
  assert.equal(suite.kdf.id, z.KDF_ID);
  assert.equal(suite.aead.id, z.AEAD_ID);
  const keys = await suite.kem.generateKeyPair();
  const input = { recipientPublicKey: keys.publicKey, info: Buffer.from("info"), aad: Buffer.from("aad"), plaintext: b(17, 32) };
  const sealed = await z.hpkeSeal(input);
  assert.equal(sealed.enc.length, 32);
  assert.deepEqual(await z.hpkeOpen({ ...input, recipientKey: keys.privateKey, ...sealed }), input.plaintext);
  await assert.rejects(z.hpkeOpen({ ...input, recipientKey: keys.privateKey, info: Buffer.from("wrong"), ...sealed }));
  await assert.rejects(z.hpkeOpen({ ...input, recipientKey: keys.privateKey, aad: Buffer.from("wrong"), ...sealed }));
  const wrongEnc = Buffer.from(sealed.enc);
  wrongEnc[0] ^= 1;
  await assert.rejects(z.hpkeOpen({ ...input, ...sealed, recipientKey: keys.privateKey, enc: wrongEnc }));
  const wrongCiphertext = Buffer.from(sealed.ciphertext);
  wrongCiphertext[0] ^= 1;
  await assert.rejects(z.hpkeOpen({ ...input, ...sealed, recipientKey: keys.privateKey, ciphertext: wrongCiphertext }));
  const other = await suite.kem.generateKeyPair();
  await assert.rejects(z.hpkeOpen({ ...input, recipientKey: other.privateKey, ...sealed }));
});

test("v2 envelope authenticates HPKE before consuming replay and releasing plaintext", async () => {
  const suite = z.hpkeSuite();
  const recipient = await suite.kem.generateKeyPair();
  const sender = crypto.generateKeyPairSync("ed25519");
  const staticCore = v2StaticCore();
  const wrappedKey = b(18, 60);
  const contentCiphertext = b(19, 48);
  const plaintext = b(17, 32);
  const sealed = await z.sealAuthorizationEnvelopeV2({
    static_core: staticCore,
    recipientPublicKey: recipient.publicKey,
    signingKey: sender.privateKey,
    plaintext,
    wrapped_key: wrappedKey,
    ciphertext: contentCiphertext,
  });
  assert.equal(sealed.manifest.envelope_version, 2);
  assert.equal(sealed.manifest.type, "rootark-authorization-manifest-v2");
  assert.equal(sealed.hpke_ciphertext.length, 48);
  assert.equal(sealed.signature.length, 64);
  assert.deepEqual(sealed.manifest.hpke_info_digest, digest(sealed.info));
  assert.deepEqual(sealed.manifest.wrapped_key_digest, digest(wrappedKey));
  assert.deepEqual(sealed.manifest.ciphertext_digest, digest(contentCiphertext));
  const aadMap = await z.decodeDeterministic(sealed.aad);
  const { hpke_info_digest: _infoDigest, wrapped_key_digest: _wrappedKeyDigest, ciphertext_digest: _ciphertextDigest, ...manifestCore } = sealed.manifest;
  assert.deepEqual(Buffer.from(aadMap.manifest_core_digest), await z.buildManifestCoreDigest(manifestCore));
  const decodedInfo = await z.decodeDeterministic(sealed.info.subarray(Buffer.byteLength(z.ASCII.HPKE_INFO_V2) + 1));
  assert.equal(Object.hasOwn(decodedInfo, "hpke_enc"), false);
  assert.equal(Object.hasOwn(decodedInfo, "manifest_core_digest"), false);

  const used = new Set();
  let claims = 0;
  const claimReplay = async (manifest) => {
    claims += 1;
    const key = [manifest.compartment_id, manifest.sender_key_id, manifest.recipient_key_id, manifest.replay_id, manifest.idempotency_key]
      .map((value) => Buffer.from(value).toString("hex")).join(":");
    if (used.has(key)) return false;
    used.add(key);
    return true;
  };
  const expectedScope = {
    sender_key_id: staticCore.sender_key_id,
    recipient_key_id: staticCore.recipient_key_id,
    compartment_id: staticCore.compartment_id,
    object_id: staticCore.object_id,
    version_id: staticCore.version_id,
    key_ref: staticCore.key_ref,
    purpose: staticCore.purpose,
    epoch: staticCore.epoch,
    wrap_id: staticCore.wrap_id,
  };
  const openInput = {
    manifest: sealed.manifest,
    signature: sealed.signature,
    senderPublicKey: sender.publicKey,
    recipientKey: recipient.privateKey,
    hpke_ciphertext: sealed.hpke_ciphertext,
    wrapped_key: wrappedKey,
    ciphertext: contentCiphertext,
    expected: expectedScope,
    now: 900,
    claimReplay,
  };
  let verificationClaims = 0;
  await assert.rejects(z.verifyAuthorization(sealed.manifest, sealed.signature, sender.publicKey, {
    ...expectedScope,
    now: 900,
    claimReplay: async () => { verificationClaims += 1; return true; },
  }), (error) => error.code === "V2_ENVELOPE_OPEN_REQUIRED");
  assert.equal(verificationClaims, 0);

  const tamperedHpkeCiphertext = Buffer.from(sealed.hpke_ciphertext);
  tamperedHpkeCiphertext[0] ^= 1;
  await assert.rejects(z.openAuthorizationEnvelopeV2({
    ...openInput,
    hpke_ciphertext: tamperedHpkeCiphertext,
  }), (error) => error.code === "AUTHENTICATION_FAILED");
  assert.equal(claims, 0);
  assert.deepEqual(await z.openAuthorizationEnvelopeV2(openInput), plaintext);
  await assert.rejects(z.openAuthorizationEnvelopeV2(openInput), (error) => error.code === "REPLAY_DETECTED");
  assert.equal(claims, 2);

  const beforeExpiry = claims;
  await assert.rejects(z.openAuthorizationEnvelopeV2({ ...openInput, now: 1000 }), (error) => error.code === "AUTHORIZATION_EXPIRED");
  assert.equal(claims, beforeExpiry);
  await assert.rejects(z.openAuthorizationEnvelopeV2({ ...openInput, now: undefined }), (error) => error.code === "REPLAY_STATE_REQUIRED");
  await assert.rejects(z.openAuthorizationEnvelopeV2({ ...openInput, ciphertext: b(20, 48) }), (error) => error.code === "SCOPE_MISMATCH");
  await assert.rejects(z.openAuthorizationEnvelopeV2({ ...openInput, expected: { ...expectedScope, object_id: b(99) } }), (error) => error.code === "SCOPE_MISMATCH");
  await assert.rejects(z.openAuthorizationEnvelopeV2({ ...openInput, expected: { object_id: b(4) } }), (error) => error.code === "EXPECTED_SCOPE_REQUIRED");
  await assert.rejects(z.openAuthorizationEnvelopeV2({
    ...openInput,
    claimReplay: async () => { throw new Error("storage unavailable"); },
  }), (error) => error.code === "REPLAY_CHECK_FAILED" && error.classification === z.SECURITY_CLASS.ENVIRONMENT);

  await assert.rejects(z.openAuthorizationEnvelopeV2(null), (error) => error.code === "INVALID_AUTHORIZATION_INPUT");
  await assert.rejects(z.openAuthorizationEnvelopeV2(undefined), (error) => error.code === "INVALID_AUTHORIZATION_INPUT");

  const claimsBeforeInvalidSignature = claims;
  const altered = { ...sealed.manifest, object_id: b(99) };
  await assert.rejects(z.openAuthorizationEnvelopeV2({ ...openInput, manifest: altered }), (error) => error.code === "AUTHENTICATION_FAILED");
  assert.equal(claims, claimsBeforeInvalidSignature);
  const alteredSignature = Buffer.from(sealed.signature);
  alteredSignature[0] ^= 1;
  await assert.rejects(z.openAuthorizationEnvelopeV2({ ...openInput, signature: alteredSignature }), (error) => error.code === "AUTHENTICATION_FAILED");
  assert.equal(claims, claimsBeforeInvalidSignature);
  await assert.rejects(z.openAuthorizationEnvelopeV2({
    ...openInput,
    expected: { ...expectedScope, object_id: b(99) },
  }), (error) => error.code === "SCOPE_MISMATCH");
  assert.equal(claims, claimsBeforeInvalidSignature);
  await assert.rejects(z.openAuthorizationEnvelopeV2({
    ...openInput,
    expected: { ...expectedScope, key_ref: b(99) },
  }), (error) => error.code === "SCOPE_MISMATCH");
  assert.equal(claims, claimsBeforeInvalidSignature);
  const wrongAad = Buffer.from(sealed.aad);
  wrongAad[wrongAad.length - 1] ^= 1;
  await assert.rejects(z.hpkeOpen({
    recipientKey: recipient.privateKey,
    enc: sealed.manifest.hpke_enc,
    ciphertext: sealed.hpke_ciphertext,
    info: sealed.info,
    aad: wrongAad,
  }));
});

test("Ed25519 authorization rejects altered signatures and substitutions", async () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const manifest = sample();
  const signature = await z.signAuthorization(manifest, keys.privateKey);
  assert.equal(signature.length, 64);
  assert.equal(await z.verifyAuthorization(manifest, signature, keys.publicKey), true);
  await assert.rejects(z.verifyAuthorization(manifest, signature, keys.publicKey, {
    epoch: BigInt(manifest.epoch),
  }), (error) => error.code === "SCOPE_MISMATCH");
  const altered = Buffer.from(signature);
  altered[0] ^= 1;
  await assert.rejects(z.verifyAuthorization(manifest, altered, keys.publicKey), (error) => error.code === "AUTHENTICATION_FAILED" && error.classification === z.SECURITY_CLASS.AUTHENTICATION);
  await assert.rejects(z.verifyAuthorization({ ...manifest, purpose: "key-wrap" }, signature, keys.publicKey), (error) => error.code === "AUTHENTICATION_FAILED");
  await assert.rejects(z.verifyAuthorization(manifest, signature, keys.publicKey, { object_id: b(99) }), (error) => error.code === "SCOPE_MISMATCH");
  for (const field of ["sender_key_id", "recipient_key_id", "compartment_id", "object_id", "version_id", "purpose", "epoch", "expiry", "replay_id", "idempotency_key", "wrap_id", "hpke_enc", "hpke_info_digest", "wrapped_key_digest", "ciphertext_digest"]) {
    const expected = {
      [field]: Buffer.isBuffer(manifest[field])
        ? b(99, manifest[field].length)
        : typeof manifest[field] === "bigint" ? manifest[field] + 1n : typeof manifest[field] === "string" ? "key-wrap" : manifest[field] + 1,
    };
    await assert.rejects(z.verifyAuthorization(manifest, signature, keys.publicKey, expected), (error) => error.code === "SCOPE_MISMATCH");
  }
});

test("Argon2id recovery derivation is explicit and upstream-compatible", async () => {
  const output = await z.deriveRecoveryKey({
    password: "test",
    salt: Buffer.alloc(16, 4),
    opslimit: 1,
    memlimit: 8192,
  });
  assert.equal(output.toString("hex"), "01208557cb93b18e135a9aba6409a7ed8423ee6276c9eb37f1570316cbcea69b");
  await assert.rejects(z.deriveRecoveryKey({ password: "test", salt: Buffer.alloc(15), opslimit: 1, memlimit: 8192 }));
  assert.equal(z.newWrapId().length, 16);
  assert.equal(z.newRecoverySalt().length, 16);
});

test("security errors do not contain secret material and clearing is best effort", async () => {
  const secret = "test-secret-material";
  await assert.rejects(z.decodeDeterministic(Buffer.from("c000", "hex")), (error) => {
    assert.equal(error.message.includes(secret), false);
    assert.equal(error.message, error.code);
    return error instanceof z.RootarkZkError;
  });
  const value = Buffer.from(secret);
  assert.equal(z.clearSecret(value), true);
  assert.deepEqual(value, Buffer.alloc(secret.length));
  assert.equal(z.clearSecret("not-bytes"), false);
});
