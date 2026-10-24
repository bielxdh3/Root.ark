"use strict";

// Opt-in LAB admission guard. It never delegates the owner signing key, PG
// credential or physical STOP key to the ciphertext socket child. Every grant
// requires BOTH an independently pinned owner historical-root proof and a
// fresh nonce-signed CAS witness floor over a pinned mTLS connection.
// The witness floor is global: it is a conservative fail-closed change fence,
// not a signed statement that a particular device is currently approved.
const crypto = require("node:crypto");
const { Zk1WitnessCasAnchorHttpsClient } = require("./zk1WitnessCasAnchorHttpsClient");
const ownerRoots = require("../../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");

function deny() {
  const error = new Error("ZK_LAB_QUORUM_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function bytes(v, length) {
  if ((!Buffer.isBuffer(v) && !(v instanceof Uint8Array)) || v.length !== length) deny();
  return Buffer.from(v);
}
function equal(a, b) { return a.length === b.length && crypto.timingSafeEqual(a, b); }
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== keys.length
    || keys.some((k) => !Object.hasOwn(value, k))) deny();
}
function scopeAsWire(scope) {
  exact(scope, ["account_id", "compartment_id", "keyring_id"]);
  return Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
    .map((key) => [key, Buffer.from(scope[key]).toString("base64url")]));
}
class Zk1SharedPgWitnessCasEgressGuard {
  #witness;
  #floor;
  #scope;
  #root;
  #revision;
  #digest;
  #objectId;
  constructor(token, witness, floor, pinned) {
    if (token !== INTERNAL || !(witness instanceof Zk1WitnessCasAnchorHttpsClient)) deny();
    this.#witness = witness;
    this.#floor = Object.freeze({ sequence: floor.sequence, lastHash: floor.lastHash });
    this.#scope = { account_id: Buffer.from(pinned.scope.account_id),
      compartment_id: Buffer.from(pinned.scope.compartment_id),
      keyring_id: Buffer.from(pinned.scope.keyring_id) };
    this.#root = Buffer.from(pinned.root);
    this.#revision = pinned.revision;
    this.#digest = Buffer.from(pinned.digest);
    this.#objectId = pinned.objectId;
    Object.freeze(this);
  }

  static async establish({ witness, witnessFloor, ownerPublicSpki,
    externallyPinnedOwnerSpkiSha256,
    ownerProofInput } = {}) {
    try {
      if (!(witness instanceof Zk1WitnessCasAnchorHttpsClient)) deny();
      exact(witnessFloor, ["sequence", "lastHash"]);
      if (!Number.isSafeInteger(witnessFloor.sequence) || witnessFloor.sequence < 0
        || typeof witnessFloor.lastHash !== "string"
        || !/^[a-f0-9]{64}$/.test(witnessFloor.lastHash)) deny();
      const floorSnapshot = { sequence: witnessFloor.sequence,
        lastHash: witnessFloor.lastHash };
      exact(ownerProofInput, ["checkpoint", "ownerHistoryCheckpoint",
        "previousHistoryProof", "pinnedOwner", "expected"]);
      const pin = ownerProofInput.pinnedOwner;
      const expected = ownerProofInput.expected;
      exact(pin, ["scope", "deviceId", "signerKeyId", "publicKey"]);
      exact(expected, ["manifestRevision", "manifestDigest", "manifestEpoch",
        "objectId", "objectRevision", "ciphertextEpoch", "ciphertextRoot"]);
      // Caller-owned buffers and proof objects are mutable. Capture every
      // field before the first await; an adversarial caller cannot change the
      // expected root after successful signature verification but before we
      // bind the physically admitted GET.
      const pinnedScopeWire = { ...pin.scope };
      const frozenExpected = { ...expected,
        manifestDigest: bytes(expected.manifestDigest, 32),
        ciphertextRoot: bytes(expected.ciphertextRoot, 32) };
      const ownerCopy = { checkpoint: { ...ownerProofInput.checkpoint },
        ownerHistoryCheckpoint: { ...ownerProofInput.ownerHistoryCheckpoint },
        previousHistoryProof: ownerProofInput.previousHistoryProof,
        pinnedOwner: { scope: pinnedScopeWire,
          deviceId: pin.deviceId, signerKeyId: bytes(pin.signerKeyId, 16),
          publicKey: null }, expected: frozenExpected };
      if ((!Buffer.isBuffer(ownerPublicSpki) && !(ownerPublicSpki instanceof Uint8Array))
        || ownerPublicSpki.length < 32 || ownerPublicSpki.length > 256) deny();
      const spki = Buffer.from(ownerPublicSpki);
      if (!equal(crypto.createHash("sha256").update(spki).digest(),
        bytes(externallyPinnedOwnerSpkiSha256, 32))) deny();
      const publicKey = await crypto.webcrypto.subtle.importKey("spki", spki,
        "Ed25519", false, ["verify"]);
      ownerCopy.pinnedOwner.publicKey = publicKey;
      // Verify the exact owner chain and root with the existing independently
      // implemented, provenance-aware owner checker. Boolean flags in JSON
      // cannot manufacture its non-forgeable WeakMap proof.
      const proof = await ownerRoots.verifyOwnerCiphertextRootCheckpoint(ownerCopy);
      if (proof.trustedOwnerSignatureVerified !== true
        || proof.manifestCheckpointVerified !== true) deny();
      if (!ownerRoots.assertOwnerCiphertextRootProof({ proof,
        scope: pinnedScopeWire, deviceId: ownerCopy.pinnedOwner.deviceId,
        manifestRevision: frozenExpected.manifestRevision,
        manifestDigest: frozenExpected.manifestDigest,
        manifestEpoch: frozenExpected.manifestEpoch, objectId: frozenExpected.objectId,
        objectRevision: frozenExpected.objectRevision,
        ciphertextEpoch: frozenExpected.ciphertextEpoch,
        ciphertextRoot: frozenExpected.ciphertextRoot })) deny();
      const head = await witness.freshHead(floorSnapshot);
      if (head.sequence !== floorSnapshot.sequence || head.lastHash !== floorSnapshot.lastHash) deny();
      const scope = pinnedScopeWire;
      // Only the operator-provisioned scope and current revision can be used;
      // a historical object is not a general current-head grant.
      const pinnedScope = {
        account_id: Buffer.from(scope.account_id, "base64url"),
        compartment_id: Buffer.from(scope.compartment_id, "base64url"),
        keyring_id: Buffer.from(scope.keyring_id, "base64url"),
      };
      if (JSON.stringify(scopeAsWire(pinnedScope)) !== JSON.stringify(scope)) deny();
      return new Zk1SharedPgWitnessCasEgressGuard(INTERNAL, witness, floorSnapshot, {
        scope: pinnedScope, root: frozenExpected.ciphertextRoot,
        revision: frozenExpected.manifestRevision, digest: frozenExpected.manifestDigest,
        objectId: frozenExpected.objectId,
      });
    } catch (_) { deny(); }
  }

  async authorize({ io, expectedRootHash } = {}) {
    try {
      exact(io, ["scope", "workerId", "principal", "action", "objectId", "revision", "digest"]);
      const scope = io.scope;
      exact(scope, ["account_id", "compartment_id", "keyring_id"]);
      if (["account_id", "compartment_id", "keyring_id"].some((k) =>
        !Buffer.isBuffer(scope[k]) && !(scope[k] instanceof Uint8Array))) deny();
      if (io.action !== "get" || io.objectId !== this.#objectId
        || io.revision !== this.#revision
        || !equal(bytes(io.digest, 32), this.#digest)
        || !equal(bytes(expectedRootHash, 32), this.#root)
        || ["account_id", "compartment_id", "keyring_id"].some((k) =>
          !equal(Buffer.from(scope[k]), this.#scope[k]))) deny();
      const head = await this.#witness.freshHead(this.#floor);
      if (head.sequence !== this.#floor.sequence || head.lastHash !== this.#floor.lastHash) deny();
      return true;
    } catch (_) { deny(); }
  }
}
const INTERNAL = Object.freeze({});
module.exports = { Zk1SharedPgWitnessCasEgressGuard };
