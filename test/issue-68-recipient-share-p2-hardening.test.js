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

const b64 = (buf) => Buffer.from(buf).toString("base64url");

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
  const now = 10000;
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

test("issue 68 P2: future-dated statement.issued_at is rejected beyond clock tolerance", async () => {
  const f = await createMinimalOfferFixture();

  // Create statement with issued_at in the future: now + 35 (> 30s clock tolerance)
  const statementBytes = Buffer.from(f.grant.shareStatementBase64, "base64url");
  const statement = await z.decodeDeterministic(statementBytes);
  statement.issued_at = f.now + 35;
  statement.expires_at = statement.issued_at + 60;

  const modifiedBytes = await z.encodeDeterministic(statement);
  const prefix = Buffer.from("Root.ark/zk-1/protected-ciphertext-share/v1\0");
  const modifiedSig = crypto.sign(null, Buffer.concat([prefix, Buffer.from(modifiedBytes)]), f.issuer.privateKey);

  const futureGrant = {
    grantId: f.grant.grantId,
    expiresAt: statement.expires_at,
    shareStatementBase64: b64(modifiedBytes),
    shareSignatureBase64: b64(modifiedSig),
  };

  await assert.rejects(
    createProtectedRecipientShareOffer({
      grant: futureGrant,
      recipientPin: f.recipientPin,
      issuerPin: f.issuerPin,
      readIndependentAuthority: async () => f.baseAuthority,
      ownerPrivateKey: f.owner.privateKey,
      ownerHeldCek: f.ownerHeldCek,
      metadata: f.metadata,
      objectRevision: 1,
      ciphertext: f.ciphertext,
      ciphertextRoot: f.ciphertextRoot,
      authority: f.baseAuthority,
      nowSeconds: f.now,
    }),
    /ZK_SHARE_OFFER_DENIED/
  );
});

test("issue 68 P2: snapshotAuthority validates non-negative safe integers for revision, epoch, and device epochs", async () => {
  const f = await createMinimalOfferFixture();

  const invalidHeads = [
    { revision: -1, epoch: 1, digest: f.baseAuthority.head.digest },
    { revision: 1.5, epoch: 1, digest: f.baseAuthority.head.digest },
    { revision: 1, epoch: -1, digest: f.baseAuthority.head.digest },
    { revision: "1", epoch: 1, digest: f.baseAuthority.head.digest },
  ];

  for (const badHead of invalidHeads) {
    await assert.rejects(
      createProtectedRecipientShareOffer({
        grant: f.grant,
        recipientPin: f.recipientPin,
        issuerPin: f.issuerPin,
        readIndependentAuthority: async () => ({ ...f.baseAuthority, head: badHead }),
        ownerPrivateKey: f.owner.privateKey,
        ownerHeldCek: f.ownerHeldCek,
        metadata: f.metadata,
        objectRevision: 1,
        ciphertext: f.ciphertext,
        ciphertextRoot: f.ciphertextRoot,
        authority: f.baseAuthority,
        nowSeconds: f.now,
      }),
      /ZK_SHARE_OFFER_DENIED/
    );
  }

  const invalidDevices = [
    { ...f.baseAuthority.devices[0], enrolledEpoch: -1 },
    { ...f.baseAuthority.devices[0], enrolledEpoch: 1.5 },
    { ...f.baseAuthority.devices[0], enrolledEpoch: 2, revokedAtEpoch: 1 }, // revokedAtEpoch < enrolledEpoch
    { ...f.baseAuthority.devices[0], revokedAtEpoch: -1 },
    { ...f.baseAuthority.devices[0], revokedAtEpoch: "revoked" },
  ];

  for (const badDevice of invalidDevices) {
    await assert.rejects(
      createProtectedRecipientShareOffer({
        grant: f.grant,
        recipientPin: f.recipientPin,
        issuerPin: f.issuerPin,
        readIndependentAuthority: async () => ({
          ...f.baseAuthority,
          devices: [badDevice, f.baseAuthority.devices[1]],
        }),
        ownerPrivateKey: f.owner.privateKey,
        ownerHeldCek: f.ownerHeldCek,
        metadata: f.metadata,
        objectRevision: 1,
        ciphertext: f.ciphertext,
        ciphertextRoot: f.ciphertextRoot,
        authority: f.baseAuthority,
        nowSeconds: f.now,
      }),
      /ZK_SHARE_OFFER_DENIED/
    );
  }
});

test("issue 68 P2: verifyOfferAuthority rejects non-monotonic post-sealing authority regression", async () => {
  const f = await createMinimalOfferFixture();

  let calls = 0;
  await assert.rejects(
    createProtectedRecipientShareOffer({
      grant: f.grant,
      recipientPin: f.recipientPin,
      issuerPin: f.issuerPin,
      readIndependentAuthority: async () => {
        calls++;
        if (calls === 2) {
          // Regress revision in post check
          return {
            ...f.baseAuthority,
            head: { ...f.baseAuthority.head, revision: f.baseAuthority.head.revision - 1 },
          };
        }
        return f.baseAuthority;
      },
      ownerPrivateKey: f.owner.privateKey,
      ownerHeldCek: f.ownerHeldCek,
      metadata: f.metadata,
      objectRevision: 1,
      ciphertext: f.ciphertext,
      ciphertextRoot: f.ciphertextRoot,
      authority: f.baseAuthority,
      nowSeconds: f.now,
    }),
    /ZK_SHARE_OFFER_DENIED/
  );
});

test("issue 68 P2: openPortableProtectedRecipientShareFile rejects getter reentrancy on redeemInput", async () => {
  const f = await createMinimalOfferFixture();
  let getterRan = false;

  const hostileRedeemInput = {
    get recipientUsername() {
      getterRan = true;
      return "alice";
    },
    get recipientDeviceId() {
      getterRan = true;
      return "device-recipient";
    },
    grant: f.grant,
  };

  const dummyOffer = {
    schema: "rootark-zk1-recipient-share-offer-dev/v1",
    authorizesProductionIo: false,
    externalCustodyProven: false,
    grant: f.grant,
    recipientUsername: "alice",
    recipientDeviceId: "device-recipient",
    metadata: f.metadata,
    envelope: {},
  };

  await assert.rejects(
    openPortableProtectedRecipientShareFile({
      offer: dummyOffer,
      redeemInput: hostileRedeemInput,
      authority: f.baseAuthority,
      operatorMinimumSequence: 1,
      deviceHpkePrivateKey: null,
      nowSeconds: f.now,
    }),
    /ZK_SHARE_FILE_OPEN_DENIED/
  );

  assert.equal(getterRan, false, "getter on redeemInput must never be executed");
});
