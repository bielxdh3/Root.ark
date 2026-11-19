"use strict";

// Portable offline owner checkpoint. Signing MUST happen under an owner key
// outside the storage server. An independently retained digest and SPKI are
// supplied to the verifier over a separate trusted channel.
const crypto = require("node:crypto");
// Loaded before any owner/inventory KeyObject getter supplied by the caller.
// A same-realm getter must not retarget Ed25519 owner verification to an
// attacker-controlled crypto.verify implementation.
const {
  verify: NATIVE_VERIFY, sign: NATIVE_SIGN,
  createPublicKey: NATIVE_CREATE_PUBLIC_KEY,
  createHash: NATIVE_CREATE_HASH, hashUpdate: NATIVE_HASH_UPDATE,
  hashDigest: NATIVE_HASH_DIGEST, bufferFrom: NATIVE_BUFFER_FROM,
  bufferConcat: NATIVE_BUFFER_CONCAT, bufferToString: NATIVE_BUFFER_TO_STRING,
  bufferCompare: NATIVE_BUFFER_COMPARE,
  jsonStringify: NATIVE_JSON_STRINGIFY, freeze: NATIVE_FREEZE,
  ownKeys: NATIVE_OWN_KEYS, ownDescriptor: NATIVE_DESCRIPTOR,
  getPrototype: NATIVE_GET_PROTOTYPE, hasOwn: NATIVE_HAS_OWN,
  objectCreate: NATIVE_OBJECT_CREATE, arrayIsArray: NATIVE_ARRAY_IS_ARRAY,
} = require("./rootark-zk10-native-intrinsics-v1");
const { types: { isProxy } } = require("node:util");
const NATIVE_IS_BUFFER = Buffer.isBuffer.bind(Buffer);
// This detached facade is created before any caller-owned KeyObject getter.
// A live export lookup after the callback can substitute the valid decoded C
// for raw B while the genuine offline owner checkpoint still hashes B.
const codec = require("./rootark-zk-1");
const z = NATIVE_FREEZE({
  encodeDeterministic: codec.encodeDeterministic,
  decodeDeterministic: codec.decodeDeterministic,
});
const inventory = require("./rootark-zk-content-inventory-v1");
const NATIVE_VERIFY_INVENTORY_SNAPSHOT = inventory.verifySnapshot.bind(inventory);
const { nativeEd25519Spki } = require("./rootark-zk1-native-ed25519-public-key");

const DOMAIN = NATIVE_BUFFER_FROM("Root.ark/zk-1/owner-inventory-trust-head/v1\0", "ascii");
const SCHEMA = "rootark-zk1-owner-inventory-trust-head/v1";
const FIELDS = Object.freeze([
  "schema", "account_id", "compartment_id", "keyring_id", "inventory_signer_key_id",
  "inventory_spki_sha256", "counter", "inventory_sequence", "inventory_root",
  "snapshot_sha256", "previous_checkpoint_digest", "issued_at", "expires_at",
]);
const SIGNED_FIELDS = Object.freeze([...FIELDS, "signature"]);
const ENROLLMENT_FIELDS = Object.freeze(["checkpoints", "ownerPublicKey",
  "independentOwnerSpkiSha256", "independentRetainedCheckpointDigest",
  "expectedScope", "inventoryPublicKey", "inventorySignerKeyId",
  "minimumSnapshot", "nowSeconds"]);
const PLAIN_PROTO = Object.prototype;
const HEX = /^[0-9a-f]{64}$/;
function fail() { throw new Error("ZK_OWNER_INVENTORY_TRUST_UNVERIFIED"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || NATIVE_ARRAY_IS_ARRAY(value) ||
      isProxy(value)) fail();
  const prototype = NATIVE_GET_PROTOTYPE(value);
  if ((prototype !== PLAIN_PROTO && prototype !== null)
      || NATIVE_OWN_KEYS(value).length !== fields.length) fail();
  const out = NATIVE_OBJECT_CREATE(null);
  for (let i = 0; i < fields.length; i += 1) {
    const name = fields[i];
    const descriptor = NATIVE_DESCRIPTOR(value, name);
    if (!descriptor || !NATIVE_HAS_OWN(descriptor, "value")) fail();
    out[name] = descriptor.value;
  }
  return out;
}
function bounded(value, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) fail();
  return value;
}
function hex(value) {
  if (typeof value !== "string" || !HEX.test(value)) fail();
  return value;
}
function b64(value, min, max = min) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) fail();
  const decoded = NATIVE_BUFFER_FROM(value, "base64url");
  if (decoded.length < min || decoded.length > max
    || NATIVE_BUFFER_TO_STRING.call(decoded, "base64url") !== value) fail();
  return decoded;
}
function key(value, kind) {
  if (!(value instanceof crypto.KeyObject) || value.type !== kind
    || value.asymmetricKeyType !== "ed25519") fail();
  return value;
}
function digest(data) {
  const hash = NATIVE_CREATE_HASH("sha256");
  NATIVE_HASH_UPDATE.call(hash, data);
  return NATIVE_BUFFER_TO_STRING.call(NATIVE_HASH_DIGEST.call(hash), "hex");
}
function spkiHash(publicKey) {
  return digest(nativeEd25519Spki(key(publicKey, "public")));
}
function statement(value) {
  const v = exact(value, FIELDS);
  if (v.schema !== SCHEMA) fail();
  // Never enter a post-key-callback Array iterator supplied by this realm.
  b64(v.account_id, 16);
  b64(v.compartment_id, 1, 128);
  b64(v.keyring_id, 16);
  b64(v.inventory_signer_key_id, 16);
  hex(v.inventory_spki_sha256);
  hex(v.inventory_root);
  hex(v.snapshot_sha256);
  if (v.previous_checkpoint_digest !== null) hex(v.previous_checkpoint_digest);
  bounded(v.counter, 1);
  bounded(v.inventory_sequence);
  bounded(v.issued_at, 1);
  bounded(v.expires_at, v.issued_at + 1);
  if (v.expires_at - v.issued_at > 86400 * 30) fail();
  if (v.counter === 1 && v.previous_checkpoint_digest !== null) fail();
  if (v.counter > 1 && v.previous_checkpoint_digest === null) fail();
  return v;
}
function bytes(value) {
  return NATIVE_BUFFER_CONCAT([DOMAIN,
    NATIVE_BUFFER_FROM(NATIVE_JSON_STRINGIFY(statement(value)), "utf8")]);
}
function checkpointDigest(wire) {
  const v = exact(wire, SIGNED_FIELDS);
  const unsigned = NATIVE_OBJECT_CREATE(null);
  for (let i = 0; i < FIELDS.length; i += 1) {
    const name = FIELDS[i];
    unsigned[name] = v[name];
  }
  return digest(NATIVE_BUFFER_CONCAT([bytes(unsigned), b64(v.signature, 64)]));
}
function signOwnerInventoryCheckpoint({ payload, ownerPrivateKey } = {}) {
  const signature = NATIVE_SIGN(null, bytes(payload), key(ownerPrivateKey, "private"));
  return NATIVE_FREEZE({ ...statement(payload),
    signature: NATIVE_BUFFER_TO_STRING.call(signature, "base64url") });
}
function normalizeScope(scope) {
  const s = inventory.normalizeScope(scope);
  return { account_id: NATIVE_BUFFER_TO_STRING.call(s.account_id, "base64url"),
    compartment_id: NATIVE_BUFFER_TO_STRING.call(s.compartment_id, "base64url"),
    keyring_id: NATIVE_BUFFER_TO_STRING.call(s.keyring_id, "base64url") };
}
function compareScope(signed, wanted) {
  if (signed.account_id !== wanted.account_id ||
      signed.compartment_id !== wanted.compartment_id ||
      signed.keyring_id !== wanted.keyring_id) fail();
}
async function verifyOwnerInventoryEnrollment(input) {
  try {
    const r = exact(input, ENROLLMENT_FIELDS);
    // All operator-retained expectations, the physical snapshot and the
    // entire owner checkpoint chain MUST be detached before the first
    // externally supplied KeyObject getter can mutate caller-owned bytes.
    const pinnedOwnerSpki = hex(r.independentOwnerSpkiSha256);
    const pinnedDigest = hex(r.independentRetainedCheckpointDigest);
    const expectedScope = normalizeScope(r.expectedScope);
    const pinnedScopeBytes = {
      account_id: b64(expectedScope.account_id, 16),
      compartment_id: b64(expectedScope.compartment_id, 1, 128),
      keyring_id: b64(expectedScope.keyring_id, 16),
    };
    if (!NATIVE_IS_BUFFER(r.inventorySignerKeyId)) fail();
    const keyId = NATIVE_BUFFER_FROM(r.inventorySignerKeyId);
    if (keyId.length !== 16) fail();
    if (!NATIVE_IS_BUFFER(r.minimumSnapshot) &&
        !(r.minimumSnapshot instanceof Uint8Array)) fail();
    const snapshot = NATIVE_BUFFER_FROM(r.minimumSnapshot);
    if (snapshot.length < 1 || snapshot.length > inventory.MAX_SNAPSHOT_BYTES) fail();
    const now = bounded(r.nowSeconds, 1);
    if (!NATIVE_ARRAY_IS_ARRAY(r.checkpoints) || isProxy(r.checkpoints) ||
        r.checkpoints.length < 1 || r.checkpoints.length > 64 ||
        NATIVE_OWN_KEYS(r.checkpoints).length !== r.checkpoints.length + 1) fail();
    const checked = new Array(r.checkpoints.length);
    for (let index = 0; index < checked.length; index += 1) {
      const descriptor = NATIVE_DESCRIPTOR(r.checkpoints, String(index));
      if (!descriptor || !NATIVE_HAS_OWN(descriptor, "value")) fail();
      const record = exact(descriptor.value, SIGNED_FIELDS);
      const unsigned = NATIVE_OBJECT_CREATE(null);
      for (let f = 0; f < FIELDS.length; f += 1) {
        const name = FIELDS[f];
        unsigned[name] = record[name];
      }
      const current = statement(unsigned);
      const signature = b64(record.signature, 64);
      checked[index] = { current, signature, recordDigest: checkpointDigest(record) };
    }
    // A caller-owned KeyObject can swap its native kHandle after exporting
    // SPKI B and before Ed25519 verification. Reimport the exact detached
    // DER bytes and use only those new native keys for signatures and nested
    // inventory verification; the fingerprint and verifier must be identical.
    const ownerSpki = nativeEd25519Spki(key(r.ownerPublicKey, "public"));
    const inventorySpki = nativeEd25519Spki(key(r.inventoryPublicKey, "public"));
    const ownerKey = NATIVE_CREATE_PUBLIC_KEY({
      key: ownerSpki, format: "der", type: "spki",
    });
    const inventoryKey = NATIVE_CREATE_PUBLIC_KEY({
      key: inventorySpki, format: "der", type: "spki",
    });
    if (digest(ownerSpki) !== pinnedOwnerSpki) fail();
    const signerFingerprint = digest(inventorySpki);
    let previous = null;
    for (let index = 0; index < checked.length; index += 1) {
      const { current, signature, recordDigest } = checked[index];
      if (!NATIVE_VERIFY(null, bytes(current), ownerKey, signature)) fail();
      compareScope(current, expectedScope);
      if (current.inventory_spki_sha256 !== signerFingerprint
        || current.inventory_signer_key_id !== NATIVE_BUFFER_TO_STRING.call(keyId, "base64url")
        || current.counter !== index + 1) fail();
      const currentDigest = recordDigest;
      if (previous && (current.previous_checkpoint_digest !== previous.digest
        || current.inventory_sequence < previous.inventorySequence
        || (current.inventory_sequence === previous.inventorySequence
          && current.inventory_root !== previous.root)
        || current.issued_at < previous.issuedAt)) fail();
      previous = { digest: currentDigest, inventorySequence: current.inventory_sequence,
        root: current.inventory_root, snapshotHash: current.snapshot_sha256,
        issuedAt: current.issued_at, expiresAt: current.expires_at, counter: current.counter };
    }
    if (!previous || previous.digest !== pinnedDigest
      || now < previous.issuedAt || now > previous.expiresAt
      || digest(snapshot) !== previous.snapshotHash) fail();
    const decoded = await z.decodeDeterministic(snapshot);
    // Even a genuine owner signature is not evidence that a separately
    // decoded object C belongs to the owner's raw checkpointed bytes B.
    const canonical = await z.encodeDeterministic(decoded);
    if (canonical.length !== snapshot.length ||
        NATIVE_BUFFER_COMPARE(canonical, snapshot) !== 0) fail();
    if (decoded.sequence !== previous.inventorySequence ||
        NATIVE_BUFFER_COMPARE(NATIVE_BUFFER_FROM(decoded.root),
          NATIVE_BUFFER_FROM(previous.root, "hex")) !== 0) fail();
    const requested = decoded.entries?.length
      ? decoded.entries[0]
      : { object_id: NATIVE_BUFFER_FROM(new Uint8Array(16)), revision: 1, epoch: 1,
        ciphertext_sha256: NATIVE_BUFFER_FROM(new Uint8Array(32)) };
    const minimumHead = { sequence: previous.inventorySequence,
      root: NATIVE_BUFFER_FROM(previous.root, "hex") };
    await NATIVE_VERIFY_INVENTORY_SNAPSHOT({ serialized: snapshot, pinnedPublicKey: inventoryKey,
      pinnedSignerKeyId: keyId, expectedScope: pinnedScopeBytes, requested, minimumHead,
      nonce: decoded.nonce });
    // No nested callback may change the raw bytes that the offline owner
    // actually signed. Recheck the private snapshot before returning proof.
    if (digest(snapshot) !== previous.snapshotHash
      || NATIVE_BUFFER_COMPARE(snapshot, canonical) !== 0) fail();
    return NATIVE_FREEZE({ minimumHead, minimumSnapshot: NATIVE_BUFFER_FROM(snapshot),
      ownerSignatureVerified: true, externallyPinnedDigestMatched: true,
      signedCounter: previous.counter, ownerCheckpointDigest: previous.digest,
      // Custody of the external pin cannot be established from process memory.
      independentOffServerCustodyProven: false, authorizesIo: false });
  } catch (_) { fail(); }
}
module.exports = { SCHEMA, FIELDS, spkiHash, checkpointDigest,
  signOwnerInventoryCheckpoint, verifyOwnerInventoryEnrollment };
