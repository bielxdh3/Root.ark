"use strict";

// DEV-OFF cryptographic boundary only. Independent custody and protected I/O
// are intentionally outside these tests.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  key, spkiHash, signatureBytes, verifyOwnerRotationKeys,
} = require("../src/crypto/rootark-zk10-account-cutover-v1");

const domain = Buffer.from("Root.ark/zk10/owner-rotation/v1\0");
const der = publicKey => publicKey.export({ type: "spki", format: "der" });
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const b64 = bytes => bytes.toString("base64url");

test("P2 native owner SPKI identity cannot be replaced by instance .export", () => {
  const actual = crypto.generateKeyPairSync("ed25519");
  const foreign = crypto.generateKeyPairSync("ed25519");
  const expected = sha(der(actual.publicKey));
  const foreignDer = der(foreign.publicKey);
  assert.notEqual(expected, sha(foreignDer));
  Object.defineProperty(actual.publicKey, "export", { value: () => foreignDer });
  assert.equal(spkiHash(actual.publicKey), expected);
});

test("P2 rotation must reject forged from-SPKI while signatures use a different real root", () => {
  const realRoot = crypto.generateKeyPairSync("ed25519");
  const fakeRoot = crypto.generateKeyPairSync("ed25519");
  const next = crypto.generateKeyPairSync("ed25519");
  const account = b64(Buffer.alloc(16, 0xa1));
  const claimedSpki = sha(der(fakeRoot.publicKey));
  const rotation = {
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: account,
    generation: 1, from_spki_sha256: claimedSpki,
    next_public_key: b64(der(next.publicKey)), previous_rotation_digest: null,
  };
  const payload = signatureBytes(domain, rotation);
  const signed = { ...rotation,
    signature_from: b64(crypto.sign(null, payload, realRoot.privateKey)),
    signature_next: b64(crypto.sign(null, payload, next.privateKey)),
  };
  Object.defineProperty(realRoot.publicKey, "export", { value: () => der(fakeRoot.publicKey) });
  assert.throws(() => verifyOwnerRotationKeys([signed], realRoot.publicKey, account),
    /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
});

test("P2 RSA object with shadowed Ed25519 metadata cannot enter owner verification", () => {
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  Object.defineProperties(rsa.publicKey, {
    type: { value: "public" }, asymmetricKeyType: { value: "ed25519" },
  });
  assert.throws(() => key(rsa.publicKey, "public"), /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
});

test("legitimate native Ed25519 key survives misleading instance metadata", () => {
  const owner = crypto.generateKeyPairSync("ed25519");
  const correctDer = der(owner.publicKey);
  Object.defineProperties(owner.publicKey, {
    type: { value: "private" }, asymmetricKeyType: { value: "rsa" },
    export: { value: () => { throw Error("shadow export must never run"); } },
  });
  const canonical = key(owner.publicKey, "public");
  assert.notStrictEqual(canonical, owner.publicKey,
    "untrusted key instance must not remain in verification path");
  const bytes = Buffer.from("signed owner challenge");
  assert.equal(crypto.verify(null, bytes, canonical,
    crypto.sign(null, bytes, owner.privateKey)), true);
  assert.equal(spkiHash(owner.publicKey), sha(correctDer));
});
