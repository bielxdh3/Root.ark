"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const { shareGrantMessageV1 } = require("../src/services/zk1ProtectedCiphertextSharing");
const {
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
