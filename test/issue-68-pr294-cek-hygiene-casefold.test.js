"use strict";

// Independent #294 P1/P2 RED -> GREEN cases. All secrets are disposable.
// The signed share-grant admission and file AES-GCM are real; only the
// separate owner-CEK transfer is replaced in the recipient teardown fixture
// so that the late authority fence can be exercised deterministically.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const content = require("../public/client/rootark-zk1-file-content");
const roots = require("../public/client/rootark-zk1-ciphertext-chunk-root");
const cli = require("../scripts/zk1-recipient-offer-local");
const { shareGrantMessageV1 } = require("../src/services/zk1ProtectedCiphertextSharing");
const { createProtectedRecipientShareOffer } =
  require("../src/crypto/rootark-zk1-recipient-share-cek");

const b64 = bytes => Buffer.from(bytes).toString("base64url");
const sha = bytes => crypto.createHash("sha256").update(bytes).digest();
const DOMAIN = Buffer.from("Root.ark/zk-1/protected-ciphertext-share/v1\0");
const publicRaw = key => Uint8Array.from(key.export({ format: "der", type: "spki" }).subarray(-32));

async function signedFixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const issuer = crypto.generateKeyPairSync("ed25519");
  const recipient = crypto.generateKeyPairSync("ed25519");
  const hpkePair = await z.hpkeSuite().kem.generateKeyPair();
  const scopeRaw = [crypto.randomBytes(16), crypto.randomBytes(16), crypto.randomBytes(16)];
  const scope = { account_id: b64(scopeRaw[0]), compartment_id: b64(scopeRaw[1]),
    keyring_id: b64(scopeRaw[2]) };
  const metadata = { ...scope, object_id: b64(crypto.randomBytes(16)),
    version_id: b64(crypto.randomBytes(16)), parent_version_id: null, epoch: 1, kind: "file" };
  const cek = crypto.randomBytes(32);
  const cleartext = Buffer.from("real authenticated recipient file; long enough to distinguish CEK");
  const ciphertext = Buffer.from(await content.encryptFile({
    cek: await content.importFileCek(cek), metadata, name: "signed.txt",
    mediaType: "text/plain", data: cleartext,
  }));
  const digest = sha(ciphertext);
  const manifestDigest = crypto.randomBytes(32);
  const now = Math.floor(Date.now() / 1000);
  const grantId = b64(crypto.randomBytes(32));
  const issuerId = "device-issuer";
  const recipientId = "device-recipient";
  const signedMessage = await shareGrantMessageV1({
    authorization: {
      account_id: scopeRaw[0], compartment_id: scopeRaw[1], keyring_id: scopeRaw[2],
      device_id: issuerId, operation: "get", object_id: metadata.object_id,
      expected_object_revision: 1, manifest_revision: 1, manifest_digest: manifestDigest,
      epoch: 1, nonce: crypto.randomBytes(32), issued_at: now,
      ciphertext_digest: digest,
    },
    grantId, recipientUsername: "alice", recipientDeviceId: recipientId,
    expiresAt: now + 300,
  });
  const grant = { grantId, expiresAt: now + 300,
    shareStatementBase64: b64(signedMessage.subarray(DOMAIN.length)),
    shareSignatureBase64: b64(crypto.sign(null, signedMessage, issuer.privateKey)) };
  const issuerRaw = publicRaw(issuer.publicKey);
  const recipientRaw = publicRaw(recipient.publicKey);
  const authority = { scope, head: { revision: 1, epoch: 1, digest: Uint8Array.from(manifestDigest) },
    devices: [
      { deviceId: issuerId, authorizationPublicKey: issuerRaw,
        enrolledEpoch: 1, revokedAtEpoch: null },
      { deviceId: recipientId, authorizationPublicKey: recipientRaw,
        enrolledEpoch: 1, revokedAtEpoch: null },
    ],
  };
  return {
    owner, recipient, hpkePair, cek, cleartext, ciphertext, digest,
    metadata, scope, authority, now, grant, statement: await z.decodeDeterministic(
      signedMessage.subarray(DOMAIN.length)),
    recipientPin: { recipientUsername: "alice", deviceId: recipientId,
      authorizationPublicKey: b64(recipientRaw),
      hpkePublicKey: b64(await z.hpkeSuite().kem.serializePublicKey(hpkePair.publicKey)) },
    issuerPin: { deviceId: issuerId, authorizationPublicKey: b64(issuerRaw) },
  };
}

function poisonFill(targetSecret, observed) {
  const bufferFill = Buffer.prototype.fill;
  const typedFill = Uint8Array.prototype.fill;
  const spy = function (value, ...rest) {
    if (value === 0 && this.byteLength === targetSecret.length
      && crypto.timingSafeEqual(Buffer.from(this), targetSecret)) {
      observed.push(Buffer.from(this));
    }
    return Reflect.apply(typedFill, this, [value, ...rest]);
  };
  Buffer.prototype.fill = spy;
  Uint8Array.prototype.fill = spy;
  return () => {
    Buffer.prototype.fill = bufferFill;
    Uint8Array.prototype.fill = typedFill;
  };
}

test("P1: owner copied CEK cleanup cannot dispatch callback-replaced Buffer.fill", async () => {
  const f = await signedFixture();
  const leaked = [];
  let authorityReads = 0, restoreFill = () => {};
  const args = {
    grant: f.grant, recipientPin: f.recipientPin, issuerPin: f.issuerPin,
    readIndependentAuthority: async () => {
      authorityReads++;
      restoreFill = poisonFill(f.cek, leaked);
      return f.authority;
    },
    ownerPrivateKey: f.owner.privateKey, ownerHeldCek: Buffer.from(f.cek),
    metadata: f.metadata, objectRevision: 1, ciphertext: f.ciphertext,
    ciphertextRoot: await roots.computeCiphertextRoot([f.ciphertext]),
    // Deliberately invalid owner V2 proof: the genuine owner-signed grant and
    // independent roster must pass first, and then cleanup executes on denial.
    authority: f.authority, nowSeconds: f.now,
  };
  try {
    await assert.rejects(createProtectedRecipientShareOffer(args), /ZK_SHARE_OFFER_DENIED/);
  } finally {
    restoreFill();
  }
  assert.equal(authorityReads, 1,
    "the real signed issuer grant must be checked before the owner cleanup");
  assert.equal(leaked.length, 0,
    "post-authority mutable .fill may never see the 32-byte owner-held CEK");
});

function isolatedRecipientBridge({ receipt, cek, onDecrypt }) {
  const filename = require.resolve("../src/crypto/rootark-zk1-recipient-share-cek");
  const local = new Module(filename, module);
  local.filename = filename;
  local.paths = Module._nodeModulePaths(path.dirname(filename));
  const realRequire = local.require.bind(local);
  const checkedCek = Buffer.from(cek);
  local.require = name => {
    if (name === "../../public/client/rootark-zk1-recipient-share")
      return { redeemProtectedCiphertextShare: async () => receipt };
    if (name === "./rootark-zk1-owner-authorized-file-cek-transfer")
      return { openOwnerAuthorizedFileCek: async () => ({
        cek: checkedCek, verifiedReleaseExpiresAt: receipt.expiresAt,
        authorizesProductionRestore: false, externalCustodyProven: false,
      }), sealOwnerAuthorizedFileCek: async () => { throw Error("NOT_CALLED"); } };
    if (name === "../../public/client/rootark-zk1-file-content")
      return { ...content, decryptFile: async (...args) => {
        const opened = await content.decryptFile(...args);
        onDecrypt(opened);
        return opened;
      } };
    return realRequire(name);
  };
  local._compile(fs.readFileSync(filename, "utf8"), filename);
  return { ...local.exports, checkedCek };
}

test("P1: recipient CEK and authenticated plaintext teardown ignore poisoned .fill after final authority", async () => {
  const f = await signedFixture();
  // Real X25519 HPKE exchange, then real file AES-GCM using the opened key.
  const info = Buffer.from("Root.ark/pr294/p1-hygiene/info\0");
  const aad = Buffer.from("Root.ark/pr294/p1-hygiene/aad\0");
  const hpke = await z.hpkeSeal({
    recipientPublicKey: f.hpkePair.publicKey, plaintext: f.cek, info, aad,
  });
  const unwrapped = Buffer.from(await z.hpkeOpen({
    recipientKey: f.hpkePair.privateKey, enc: hpke.enc, ciphertext: hpke.ciphertext,
    info, aad,
  }));
  assert.deepEqual(unwrapped, f.cek, "genuine recipient HPKE must open the CEK");

  const s = f.statement;
  const receipt = {
    ownerGrantSignatureVerified: true, serverRevocationProofVerified: false,
    authorizesPlaintextRelease: false,
    ciphertextBase64: b64(f.ciphertext),
    shareStatementBase64: f.grant.shareStatementBase64,
    shareSignatureBase64: f.grant.shareSignatureBase64,
    ciphertextSha256Base64: b64(f.digest),
    grantId: f.grant.grantId, objectId: f.metadata.object_id,
    revision: 1, epoch: 1, expiresAt: f.now + 300,
  };
  let decrypted = null, aeadOpens = 0, authorityReads = 0;
  const bridge = isolatedRecipientBridge({ receipt, cek: unwrapped,
    onDecrypt: opened => { aeadOpens++; decrypted = opened; } });
  const observedCek = [], observedPlain = [];
  const originalBufferFill = Buffer.prototype.fill;
  const originalTypedFill = Uint8Array.prototype.fill;
  try {
    await assert.rejects(bridge.openProtectedRecipientShareFile({
      redeemInput: {
        origin: "https://example.invalid", grant: f.grant,
        recipientUsername: "alice", recipientDeviceId: f.recipientPin.deviceId,
        signerKey: f.recipient.privateKey,
        readIndependentAuthority: async () => {
          authorityReads++;
          assert.equal(aeadOpens, 1,
            "final authority is reached only after real AES-GCM plaintext open");
          const spy = function (value, ...args) {
            if (value === 0 && this.byteLength === 32
              && crypto.timingSafeEqual(Buffer.from(this), f.cek)) observedCek.push(1);
            if (value === 0 && this.byteLength === f.cleartext.length
              && crypto.timingSafeEqual(Buffer.from(this), f.cleartext)) observedPlain.push(1);
            return Reflect.apply(originalTypedFill, this, [value, ...args]);
          };
          Buffer.prototype.fill = spy;
          Uint8Array.prototype.fill = spy;
          // Invalid account head forces fail-closed AFTER authenticated
          // HPKE+AEAD and the final independent authority boundary.
          return { ...f.authority, scope: { ...f.scope, account_id: b64(crypto.randomBytes(16)) } };
        },
      },
      envelope: {
        schema: "rootark-zk1-owner-file-cek-envelope/v1",
        core: {
          account_id: f.metadata.account_id, compartment_id: f.metadata.compartment_id,
          keyring_id: f.metadata.keyring_id, object_id: f.metadata.object_id,
          object_revision: 1, epoch: 1, device_id: f.recipientPin.deviceId,
          owner_revision: 1, owner_digest: b64(s.manifest_digest), owner_epoch: 1,
          ciphertext_sha256: b64(f.digest),
        },
        enc: b64(hpke.enc), ciphertext: b64(hpke.ciphertext),
        owner_signature: b64(crypto.randomBytes(64)),
        authorizesProductionRestore: false, externalCustodyProven: false,
      },
      authority: f.authority, operatorMinimumSequence: 1,
      metadata: f.metadata, deviceHpkePrivateKey: f.hpkePair.privateKey,
      nowSeconds: f.now,
    }), /ZK_SHARE_FILE_OPEN_DENIED/);
  } finally {
    Buffer.prototype.fill = originalBufferFill;
    Uint8Array.prototype.fill = originalTypedFill;
    unwrapped.fill(0);
  }
  assert.equal(aeadOpens, 1, "a real file AES-GCM decrypt must have completed");
  assert.equal(authorityReads, 1, "independent authority must execute after AEAD");
  assert.equal(observedCek.length, 0, "callback-mutated fill must not observe recipient CEK");
  assert.equal(observedPlain.length, 0, "callback-mutated fill must not observe plaintext");
  assert.ok(bridge.checkedCek.every(byte => byte === 0), "recipient bridge must still zero CEK");
  assert.ok(decrypted.data.every(byte => byte === 0), "recipient bridge must still zero plaintext");
});

test("P2: Windows CLI rejects case-insensitive aliases before private I/O", () => {
  const property = Object.getOwnPropertyDescriptor(process, "platform");
  assert.equal(property?.configurable, true, "must exercise actual Windows parse branch");
  const acceptedLinux = cli.parse(["redeem", "--owned-dir", "/safe-root",
    "--context-module", "trust.js", "--offer", "ITEM.JSON", "--output", "item.json"]);
  assert.equal(acceptedLinux.opts["--offer"], "ITEM.JSON");
  try {
    Object.defineProperty(process, "platform", { configurable: true, value: "win32" });
    for (const args of [
      ["redeem", "--owned-dir", "E:\\safe-root", "--context-module", "trust.js",
        "--offer", "ITEM.JSON", "--output", "item.json"],
      ["export", "--owned-dir", "E:\\safe-root", "--context-module", "TRUST.js",
        "--offer", "trust.JS", "--grant", "grant.json"],
      ["export", "--owned-dir", "E:\\safe-root", "--context-module", "trust.js",
        "--offer", "GRANT.JSON", "--grant", "grant.json"],
    ]) assert.throws(() => cli.parse(args), /ZK_RECIPIENT_OFFER_CLI_DENIED/);
    assert.equal(cli.parse(["redeem", "--owned-dir", "E:\\safe-root",
      "--context-module", "trust.js", "--offer", "offer.json",
      "--output", "received.bin"]).mode, "redeem");
  } finally {
    Object.defineProperty(process, "platform", property);
  }
});
