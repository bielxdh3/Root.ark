"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const { shareGrantMessageV1 } = require("../src/services/zk1ProtectedCiphertextSharing");
const {
  createProtectedRecipientShareOffer,
  openPortableProtectedRecipientShareFile,
} = require("../src/crypto/rootark-zk1-recipient-share-cek");

const b64 = (value) => Buffer.from(value).toString("base64url");

async function createSignedGrantFixture() {
  const issuer = crypto.generateKeyPairSync("ed25519");
  const accountId = crypto.randomBytes(16);
  const compartmentId = crypto.randomBytes(16);
  const keyringId = crypto.randomBytes(16);
  const scope = {
    account_id: b64(accountId),
    compartment_id: b64(compartmentId),
    keyring_id: b64(keyringId),
  };
  const now = Math.floor(Date.now() / 1000);
  const objectId = b64(crypto.randomBytes(16));
  const manifestDigest = crypto.randomBytes(32);
  const grantId = b64(crypto.randomBytes(32));
  const expiresAt = now + 60;
  const message = await shareGrantMessageV1({
    authorization: {
      account_id: accountId,
      compartment_id: compartmentId,
      keyring_id: keyringId,
      device_id: "device-issuer",
      operation: "get",
      object_id: objectId,
      expected_object_revision: 1,
      manifest_revision: 1,
      manifest_digest: manifestDigest,
      epoch: 1,
      nonce: crypto.randomBytes(32),
      issued_at: now,
      ciphertext_digest: crypto.randomBytes(32),
    },
    grantId,
    recipientUsername: "alice",
    recipientDeviceId: "device-recipient",
    expiresAt,
  });
  const domainLength = Buffer.byteLength("Root.ark/zk-1/protected-ciphertext-share/v1\0");
  const statementBytes = message.subarray(domainLength);
  return {
    grant: {
      grantId,
      expiresAt,
      shareStatementBase64: b64(statementBytes),
      shareSignatureBase64: b64(crypto.sign(null, message, issuer.privateKey)),
    },
    metadata: {
      ...scope,
      object_id: objectId,
      version_id: b64(crypto.randomBytes(16)),
      parent_version_id: null,
      epoch: 1,
      kind: "file",
    },
    now,
  };
}

test("issue 68 P2: portable redemption rejects callback getters before crypto or IO", async () => {
  const grant = {
    grantId: "grant-id",
    expiresAt: 1,
    shareStatementBase64: "statement",
    shareSignatureBase64: "signature",
  };
  let getterRan = false;
  let redeemGetTrapRan = false;
  let offerGetTrapRan = false;
  let inputGetTrapRan = false;
  let signerKeyRead = false;
  let authorityCalls = 0;
  let fetchCalls = 0;

  const hostileRedeemTarget = {
    origin: "https://example.invalid",
    grant,
    recipientUsername: "alice",
    recipientDeviceId: "device-recipient",
    signerKey: {
      get type() {
        signerKeyRead = true;
        return "private";
      },
    },
    get readIndependentAuthority() {
      getterRan = true;
      grant.grantId = "mutated-grant";
      hostileRedeemTarget.recipientUsername = "mallory";
      hostileRedeemTarget.recipientDeviceId = "device-attacker";
      return async () => { authorityCalls++; return {}; };
    },
    fetchImpl: async () => { fetchCalls++; throw Error("unexpected fetch"); },
    nowSeconds: () => 1,
  };
  const hostileRedeemInput = new Proxy(hostileRedeemTarget, {
    get(target, key, receiver) {
      redeemGetTrapRan = true;
      return Reflect.get(target, key, receiver);
    },
  });

  const offerTarget = {
    schema: "rootark-zk1-recipient-share-offer-dev/v1",
    authorizesProductionIo: false,
    externalCustodyProven: false,
    grant,
    recipientUsername: "alice",
    recipientDeviceId: "device-recipient",
    metadata: {
      account_id: "account", compartment_id: "compartment", keyring_id: "keyring",
      object_id: "object", version_id: "version", parent_version_id: null,
      epoch: 1, kind: "file",
    },
    envelope: {
      schema: "envelope", core: {}, enc: "enc", ciphertext: "ciphertext",
      owner_signature: "signature", authorizesProductionRestore: false,
      externalCustodyProven: false,
    },
  };
  const offer = new Proxy(offerTarget, {
    get(target, key, receiver) {
      offerGetTrapRan = true;
      return Reflect.get(target, key, receiver);
    },
  });

  await assert.rejects(
    openPortableProtectedRecipientShareFile(new Proxy({
      offer,
      redeemInput: hostileRedeemInput,
      authority: {},
      operatorMinimumSequence: 1,
      deviceHpkePrivateKey: null,
      nowSeconds: 1,
    }, {
      get(target, key, receiver) {
        inputGetTrapRan = true;
        return Reflect.get(target, key, receiver);
      },
    })),
    /ZK_SHARE_FILE_OPEN_DENIED/
  );

  assert.equal(getterRan, false, "readIndependentAuthority getter must never execute");
  assert.equal(redeemGetTrapRan, false, "redeemInput proxy get trap must never execute");
  assert.equal(offerGetTrapRan, false, "offer proxy get trap must never execute");
  assert.equal(inputGetTrapRan, false, "outer input proxy get trap must never execute");
  assert.equal(signerKeyRead, false, "crypto signer key must not be inspected");
  assert.equal(authorityCalls, 0, "authority callback must not be invoked");
  assert.equal(fetchCalls, 0, "network fetch must not be invoked");
  assert.equal(grant.grantId, "grant-id", "rejected getter must not mutate grant");
  assert.equal(hostileRedeemTarget.recipientUsername, "alice");
  assert.equal(hostileRedeemTarget.recipientDeviceId, "device-recipient");
});

test("issue 68 P2: data callback can mutate only the original, not the frozen redeem snapshot", async () => {
  const f = await createSignedGrantFixture();
  const originalGrantId = f.grant.grantId;
  let hostileRedeemTarget;
  let callbackCalls = 0;
  let fetchCalls = 0;
  let callbackSnapshot;
  const readIndependentAuthority = async function () {
    callbackCalls++;
    callbackSnapshot = this;
    f.grant.grantId = "mutated-grant";
    hostileRedeemTarget.recipientUsername = "mallory";
    hostileRedeemTarget.recipientDeviceId = "device-attacker";
    return {};
  };
  hostileRedeemTarget = {
    origin: "https://example.invalid",
    grant: f.grant,
    recipientUsername: "alice",
    recipientDeviceId: "device-recipient",
    signerKey: {
      type: "private", algorithm: { name: "Ed25519" },
      extractable: false, usages: ["sign"],
    },
    readIndependentAuthority,
    fetchImpl: async () => { fetchCalls++; throw Error("unexpected fetch"); },
    nowSeconds: () => f.now,
  };
  const offer = {
    schema: "rootark-zk1-recipient-share-offer-dev/v1",
    grant: f.grant,
    recipientUsername: "alice",
    recipientDeviceId: "device-recipient",
    metadata: f.metadata,
    envelope: {
      schema: "envelope", core: {}, enc: "enc", ciphertext: "ciphertext",
      owner_signature: "signature", authorizesProductionRestore: false,
      externalCustodyProven: false,
    },
    authorizesProductionIo: false,
    externalCustodyProven: false,
  };

  await assert.rejects(
    openPortableProtectedRecipientShareFile({
      offer,
      redeemInput: hostileRedeemTarget,
      authority: {},
      operatorMinimumSequence: 1,
      deviceHpkePrivateKey: null,
      nowSeconds: f.now,
    }),
    /ZK_SHARE_FILE_OPEN_DENIED/
  );

  assert.equal(callbackCalls, 1, "data callback must be reached with a valid signed grant");
  assert.notStrictEqual(callbackSnapshot, hostileRedeemTarget,
    "callback receiver must not be the caller-owned redeem object");
  assert.equal(Object.getPrototypeOf(callbackSnapshot), null);
  assert.equal(Object.isFrozen(callbackSnapshot), true);
  assert.equal(Object.isFrozen(callbackSnapshot.grant), true);
  assert.equal(callbackSnapshot.grant.grantId, originalGrantId);
  assert.equal(callbackSnapshot.recipientUsername, "alice");
  assert.equal(callbackSnapshot.recipientDeviceId, "device-recipient");
  assert.equal(f.grant.grantId, "mutated-grant");
  assert.equal(hostileRedeemTarget.recipientUsername, "mallory");
  assert.equal(hostileRedeemTarget.recipientDeviceId, "device-attacker");
  assert.equal(fetchCalls, 0, "invalid authority must be rejected before fetch");
});

async function createMinimalOfferFixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const issuer = crypto.generateKeyPairSync("ed25519");
  const recipient = crypto.generateKeyPairSync("ed25519");
  const recipientHpke = await z.hpkeSuite().kem.generateKeyPair();
  const recipientHpkePub = b64(await z.hpkeSuite().kem.serializePublicKey(recipientHpke.publicKey));

  const accountIdRaw = crypto.randomBytes(16);
  const compartmentIdRaw = crypto.randomBytes(16);
  const keyringIdRaw = crypto.randomBytes(16);

  const scope = {
    account_id: b64(accountIdRaw),
    compartment_id: b64(compartmentIdRaw),
    keyring_id: b64(keyringIdRaw),
  };
  const now = Math.floor(Date.now() / 1000);
  const epoch = 1;
  const revision = 1;
  const digest = crypto.randomBytes(32);

  const issuerId = "device-issuer";
  const recipientId = "device-recipient";

  const issuerPubBytes = Uint8Array.from(issuer.publicKey.export({ format: "der", type: "spki" }).subarray(12));
  const recipientPubBytes = Uint8Array.from(recipient.publicKey.export({ format: "der", type: "spki" }).subarray(12));

  const objectId = b64(crypto.randomBytes(16));
  const metadata = {
    ...scope,
    object_id: objectId,
    version_id: b64(crypto.randomBytes(16)),
    parent_version_id: null,
    epoch,
    kind: "file",
  };

  const plaintext = Buffer.from("test plaintext bytes");
  const ownerHeldCek = crypto.randomBytes(32);
  const cekKey = await crypto.webcrypto.subtle.importKey("raw", ownerHeldCek, "AES-GCM", false, ["encrypt", "decrypt"]);
  const iv = crypto.randomBytes(12);
  const ciphertextBuf = Buffer.from(await crypto.webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, cekKey, plaintext));
  const ciphertext = Buffer.concat([iv, ciphertextBuf]);
  const ciphertextDigest = crypto.createHash("sha256").update(ciphertext).digest();
  const ciphertextRoot = crypto.createHash("sha256").update(ciphertext).digest();

  const grantId = b64(crypto.randomBytes(32));

  const shareAuthorization = {
    account_id: accountIdRaw,
    compartment_id: compartmentIdRaw,
    keyring_id: keyringIdRaw,
    device_id: issuerId,
    operation: "get",
    object_id: metadata.object_id,
    expected_object_revision: 1,
    manifest_revision: revision,
    manifest_digest: digest,
    epoch,
    nonce: crypto.randomBytes(32),
    issued_at: now,
    ciphertext_digest: ciphertextDigest,
  };

  const grantInput = {
    authorization: shareAuthorization,
    grantId,
    recipientUsername: "alice",
    recipientDeviceId: recipientId,
    expiresAt: now + 60,
  };

  const message = await shareGrantMessageV1(grantInput);
  const grant = {
    grantId: grantInput.grantId,
    expiresAt: grantInput.expiresAt,
    shareStatementBase64: b64(message.subarray(Buffer.byteLength("Root.ark/zk-1/protected-ciphertext-share/v1\0"))),
    shareSignatureBase64: b64(crypto.sign(null, message, issuer.privateKey)),
  };

  const recipientPin = {
    recipientUsername: "alice",
    deviceId: recipientId,
    authorizationPublicKey: b64(recipientPubBytes),
    hpkePublicKey: recipientHpkePub,
  };

  const issuerPin = {
    deviceId: issuerId,
    authorizationPublicKey: b64(issuerPubBytes),
  };

  const baseAuthority = {
    scope,
    head: { revision, epoch, digest: Uint8Array.from(digest) },
    devices: [
      {
        deviceId: issuerId,
        authorizationPublicKey: issuerPubBytes,
        enrolledEpoch: epoch,
        revokedAtEpoch: null,
      },
      {
        deviceId: recipientId,
        authorizationPublicKey: recipientPubBytes,
        enrolledEpoch: epoch,
        revokedAtEpoch: null,
      },
    ],
  };

  return {
    owner,
    issuer,
    recipient,
    scope,
    now,
    epoch,
    revision,
    digest,
    metadata,
    ownerHeldCek,
    ciphertext,
    ciphertextRoot,
    grant,
    recipientPin,
    issuerPin,
    baseAuthority,
  };
}


test("issue 68: poisoned scope iterator and Array.some cannot suppress an independent owner scope mismatch", async () => {
  const f = await createMinimalOfferFixture();
  const originalIterator = Array.prototype[Symbol.iterator];
  const originalSome = Array.prototype.some;
  let iteratedSignedScope = 0;
  let poisonedScopeChecks = 0;
  let authorityReads = 0;
  const mismatched = { ...f.baseAuthority,
    scope: { ...f.baseAuthority.scope, account_id: b64(crypto.randomBytes(16)) },
  };
  try {
    await assert.rejects(createProtectedRecipientShareOffer({
      grant: f.grant, recipientPin: f.recipientPin, issuerPin: f.issuerPin,
      readIndependentAuthority: async () => {
        authorityReads++;
        Array.prototype[Symbol.iterator] = function* () {
          if (this.length === 3 && this[0] === "account_id") {
            iteratedSignedScope++;
            // Legacy for-of scope checking could silently skip all fields.
            return;
          }
          yield* Reflect.apply(originalIterator, this, []);
        };
        Array.prototype.some = function (...args) {
          if (this.length === 3 && this[0] === "scope") {
            poisonedScopeChecks++;
            return false;
          }
          return Reflect.apply(originalSome, this, args);
        };
        return mismatched;
      },
      ownerPrivateKey: f.owner.privateKey, ownerHeldCek: f.ownerHeldCek,
      metadata: f.metadata, objectRevision: 1, ciphertext: f.ciphertext,
      ciphertextRoot: f.ciphertextRoot, authority: f.baseAuthority,
      nowSeconds: f.now,
    }), /ZK_SHARE_OFFER_DENIED/);
  } finally {
    Array.prototype[Symbol.iterator] = originalIterator;
    Array.prototype.some = originalSome;
  }
  assert.equal(authorityReads, 1, "the independently read mismatched scope must be checked");
  assert.equal(iteratedSignedScope, 0,
    "the authority-scope guard must use indexed checks, not a replaceable iterator");
  assert.equal(poisonedScopeChecks, 0,
    "the authority-scope guard must not dispatch a replaceable Array.some");
});
