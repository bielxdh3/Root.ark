"use strict";

// DEV-OFF cryptographic boundary. A native prototype method can still read
// attacker-controlled Symbol(kHandle) on a forged KeyObject wrapper; the
// supplied object must never survive into both SPKI hashing and verification.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { key, signatureBytes, verifyOwnerRotationKeys } =
  require("../src/crypto/rootark-zk10-account-cutover-v1");

const domain = Buffer.from("Root.ark/zk10/owner-rotation/v1\0");
const der = (value) => value.export({ format: "der", type: "spki" });
const b64 = (value) => value.toString("base64url");
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");

test("P2 changing native kHandle cannot validate SPKI B with owner A's signature", () => {
  const ownerA = crypto.generateKeyPairSync("ed25519");
  const foreignB = crypto.generateKeyPairSync("ed25519");
  const next = crypto.generateKeyPairSync("ed25519");
  const account = b64(Buffer.alloc(16, 0xa1));
  const claimedB = sha(der(foreignB.publicKey));
  assert.notEqual(claimedB, sha(der(ownerA.publicKey)));
  const rotation = {
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: account,
    generation: 1, from_spki_sha256: claimedB,
    next_public_key: b64(der(next.publicKey)), previous_rotation_digest: null,
  };
  const bytes = signatureBytes(domain, rotation);
  const signed = { ...rotation,
    signature_from: b64(crypto.sign(null, bytes, ownerA.privateKey)),
    signature_next: b64(crypto.sign(null, bytes, next.privateKey)),
  };
  const wrapped = Object.create(ownerA.publicKey);
  const handle = Object.getOwnPropertySymbols(ownerA.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "the test requires a real Node KeyObject handle");
  let foreignSpkiReads = 0;
  Object.defineProperty(wrapped, handle, { get() {
    // Native getter calls may be cached depending on Node version. Choose
    // B for export and A for verify regardless of intervening getter reads.
    if ((new Error().stack || "").includes("PublicKeyObject.export")) {
      foreignSpkiReads += 1;
      return foreignB.publicKey[handle];
    }
    return ownerA.publicKey[handle];
  } });
  assert.throws(() => verifyOwnerRotationKeys([signed], wrapped, account),
    { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" });
  assert.ok(foreignSpkiReads >= 1,
    "the native export must encounter the foreign handle");
});

test("canonical public key remains usable after its wrapper changes handles", () => {
  const owner = crypto.generateKeyPairSync("ed25519");
  const other = crypto.generateKeyPairSync("ed25519");
  const wrapped = Object.create(owner.publicKey);
  const handle = Object.getOwnPropertySymbols(owner.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle);
  let active = owner.publicKey[handle];
  Object.defineProperty(wrapped, handle, { get: () => active });
  const pinned = key(wrapped, "public");
  assert.notStrictEqual(pinned, wrapped);
  active = other.publicKey[handle];
  const bytes = Buffer.from("owner canonical identity");
  assert.equal(crypto.verify(null, bytes, pinned,
    crypto.sign(null, bytes, owner.privateKey)), true);
  assert.equal(crypto.verify(null, bytes, pinned,
    crypto.sign(null, bytes, other.privateKey)), false);
});
