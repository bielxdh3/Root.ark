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

test("issue 68 P2: future-dated statement.issued_at is rejected beyond clock tolerance", async () => {
  const f = await createMinimalOfferFixture();

  // This reduced fixture cannot complete the owner V2 ceremony, but a valid
  // statement must reach the independent authority read. Prove the future
  // variant is rejected at the earlier clock boundary instead.
  let baselineReads = 0;
  await assert.rejects(createProtectedRecipientShareOffer({
    grant: f.grant, recipientPin: f.recipientPin, issuerPin: f.issuerPin,
    readIndependentAuthority: async () => { baselineReads++; return f.baseAuthority; },
    ownerPrivateKey: f.owner.privateKey, ownerHeldCek: f.ownerHeldCek,
    metadata: f.metadata, objectRevision: 1, ciphertext: f.ciphertext,
    ciphertextRoot: f.ciphertextRoot, authority: f.baseAuthority, nowSeconds: f.now,
  }), /ZK_SHARE_OFFER_DENIED/);
  assert.equal(baselineReads, 1, "a current signed grant must get past input and statement admission");

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

  let futureReads = 0;
  await assert.rejects(
    createProtectedRecipientShareOffer({
      grant: futureGrant,
      recipientPin: f.recipientPin,
      issuerPin: f.issuerPin,
      readIndependentAuthority: async () => { futureReads++; return f.baseAuthority; },
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
  assert.equal(futureReads, 0, "the future-issued statement must be denied before roster IO");
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
    let authorityReads = 0;
    await assert.rejects(
      createProtectedRecipientShareOffer({
        grant: f.grant,
        recipientPin: f.recipientPin,
        issuerPin: f.issuerPin,
        readIndependentAuthority: async () => {
          authorityReads++;
          return { ...f.baseAuthority, head: badHead };
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
    assert.equal(authorityReads, 1, "bad head must reach authority snapshot validation");
  }

  const invalidDevices = [
    { ...f.baseAuthority.devices[0], enrolledEpoch: -1 },
    { ...f.baseAuthority.devices[0], enrolledEpoch: 1.5 },
    { ...f.baseAuthority.devices[0], enrolledEpoch: 2, revokedAtEpoch: 1 }, // revokedAtEpoch < enrolledEpoch
    { ...f.baseAuthority.devices[0], revokedAtEpoch: -1 },
    { ...f.baseAuthority.devices[0], revokedAtEpoch: "revoked" },
  ];

  for (const badDevice of invalidDevices) {
    let authorityReads = 0;
    await assert.rejects(
      createProtectedRecipientShareOffer({
        grant: f.grant,
        recipientPin: f.recipientPin,
        issuerPin: f.issuerPin,
        readIndependentAuthority: async () => {
          authorityReads++;
          return {
            ...f.baseAuthority,
            devices: [badDevice, f.baseAuthority.devices[1]],
          };
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
    assert.equal(authorityReads, 1, "bad device must reach authority snapshot validation");
  }
});

// Post-sealing rollback is tested with an actual signed owner V2 witness,
// AEAD/HPKE sealing, and regressionReads === 2 in the owner ceremony suite.
// This reduced fixture cannot reach that boundary and must not claim it does.

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

test("issue 68: revoked owner roster does not consult poisoned Array.filter after authority await", async () => {
  const f = await createMinimalOfferFixture();
  const revoked = {
    ...f.baseAuthority,
    devices: f.baseAuthority.devices.map((device, index) =>
      index === 0 ? { ...device, revokedAtEpoch: f.epoch } : device),
  };
  const originalFilter = Array.prototype.filter;
  let filterCalls = 0;
  let authorityReads = 0;
  try {
    await assert.rejects(createProtectedRecipientShareOffer({
      grant: f.grant, recipientPin: f.recipientPin, issuerPin: f.issuerPin,
      readIndependentAuthority: async () => {
        authorityReads++;
        Array.prototype.filter = function (...args) {
          filterCalls++;
          return originalFilter.apply(this, args);
        };
        return revoked;
      },
      ownerPrivateKey: f.owner.privateKey, ownerHeldCek: f.ownerHeldCek,
      metadata: f.metadata, objectRevision: 1, ciphertext: f.ciphertext,
      ciphertextRoot: f.ciphertextRoot, authority: f.baseAuthority, nowSeconds: f.now,
    }), /ZK_SHARE_OFFER_DENIED/);
  } finally { Array.prototype.filter = originalFilter; }
  assert.equal(authorityReads, 1, "a valid grant reaches one independent authority read");
  assert.equal(filterCalls, 0,
    "revoked authority must fail before any callback-poisonable array filter is invoked");
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

test("issue 68 P2: independent roster snapshots never execute hostile native byte-view properties", async () => {
  const f = await createMinimalOfferFixture();
  for (const target of ["recipient-key", "head-digest"]) {
    let lengthReads = 0;
    let valueOfReads = 0;
    let iteratorReads = 0;
    let authorityReads = 0;
    const issuer = { ...f.baseAuthority.devices[0], revokedAtEpoch: f.epoch };
    const recipient = { ...f.baseAuthority.devices[1] };
    const head = { ...f.baseAuthority.head };
    const bytes = target === "head-digest"
      ? Uint8Array.from(head.digest)
      : Uint8Array.from(recipient.authorizationPublicKey);
    Object.defineProperties(bytes, {
      length: { get() { lengthReads++; issuer.revokedAtEpoch = null; return 32; } },
      valueOf: { value() { valueOfReads++; issuer.revokedAtEpoch = null; return bytes; } },
      [Symbol.iterator]: { value() { iteratorReads++; issuer.revokedAtEpoch = null; return [][Symbol.iterator](); } },
    });
    if (target === "head-digest") head.digest = bytes;
    else recipient.authorizationPublicKey = bytes;

    await assert.rejects(createProtectedRecipientShareOffer({
      grant: f.grant, recipientPin: f.recipientPin, issuerPin: f.issuerPin,
      readIndependentAuthority: async () => {
        authorityReads++;
        return { scope: f.baseAuthority.scope, head, devices: [issuer, recipient] };
      },
      ownerPrivateKey: f.owner.privateKey, ownerHeldCek: f.ownerHeldCek,
      metadata: f.metadata, objectRevision: 1, ciphertext: f.ciphertext,
      ciphertextRoot: f.ciphertextRoot, authority: f.baseAuthority, nowSeconds: f.now,
    }), /ZK_SHARE_OFFER_DENIED/);
    assert.equal(authorityReads, 1, `${target}: independent roster must be checked`);
    assert.equal(lengthReads, 0, `${target}: getter must not run`);
    assert.equal(valueOfReads, 0, `${target}: valueOf must not run`);
    assert.equal(iteratorReads, 0, `${target}: iterator must not run`);
    assert.equal(issuer.revokedAtEpoch, f.epoch, `${target}: issuer must remain revoked`);
  }
});
