"use strict";

// Portable offline owner checkpoint. Signing MUST happen under an owner key
// outside the storage server. An independently retained digest and SPKI are
// supplied to the verifier over a separate trusted channel.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const inventory = require("./rootark-zk-content-inventory-v1");
const { nativeEd25519Spki } = require("./rootark-zk1-native-ed25519-public-key");

const DOMAIN = Buffer.from("Root.ark/zk-1/owner-inventory-trust-head/v1\0", "ascii");
const SCHEMA = "rootark-zk1-owner-inventory-trust-head/v1";
const FIELDS = Object.freeze([
  "schema", "account_id", "compartment_id", "keyring_id", "inventory_signer_key_id",
  "inventory_spki_sha256", "counter", "inventory_sequence", "inventory_root",
  "snapshot_sha256", "previous_checkpoint_digest", "issued_at", "expires_at",
]);
const HEX = /^[0-9a-f]{64}$/;
function fail() { throw new Error("ZK_OWNER_INVENTORY_TRUST_UNVERIFIED"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
  return Object.fromEntries(fields.map((field) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail();
    return [field, descriptor.value];
  }));
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
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length < min || decoded.length > max
    || decoded.toString("base64url") !== value) fail();
  return decoded;
}
function key(value, kind) {
  if (!(value instanceof crypto.KeyObject) || value.type !== kind
    || value.asymmetricKeyType !== "ed25519") fail();
  return value;
}
function spkiHash(publicKey) {
  return crypto.createHash("sha256").update(nativeEd25519Spki(
    key(publicKey, "public"))).digest("hex");
}
function digest(data) { return crypto.createHash("sha256").update(data).digest("hex"); }
function statement(value) {
  const v = exact(value, FIELDS);
  if (v.schema !== SCHEMA) fail();
  for (const [field, min, max] of [["account_id", 16, 16],
    ["compartment_id", 1, 128], ["keyring_id", 16, 16],
    ["inventory_signer_key_id", 16, 16]]) b64(v[field], min, max);
  for (const field of ["inventory_spki_sha256", "inventory_root", "snapshot_sha256"]) hex(v[field]);
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
function bytes(value) { return Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(statement(value)), "utf8")]); }
function checkpointDigest(wire) {
  const v = exact(wire, [...FIELDS, "signature"]);
  return digest(Buffer.concat([bytes(Object.fromEntries(FIELDS.map((f) => [f, v[f]]))),
    b64(v.signature, 64)]));
}
function signOwnerInventoryCheckpoint({ payload, ownerPrivateKey } = {}) {
  const signature = crypto.sign(null, bytes(payload), key(ownerPrivateKey, "private"));
  return Object.freeze({ ...statement(payload), signature: signature.toString("base64url") });
}
function normalizeScope(scope) {
  const s = inventory.normalizeScope(scope);
  return { account_id: s.account_id.toString("base64url"),
    compartment_id: s.compartment_id.toString("base64url"),
    keyring_id: s.keyring_id.toString("base64url") };
}
function compareScope(signed, wanted) {
  for (const name of ["account_id", "compartment_id", "keyring_id"]) {
    if (signed[name] !== wanted[name]) fail();
  }
}
async function verifyOwnerInventoryEnrollment(input) {
  try {
    const r = exact(input, ["checkpoints", "ownerPublicKey", "independentOwnerSpkiSha256",
      "independentRetainedCheckpointDigest", "expectedScope", "inventoryPublicKey",
      "inventorySignerKeyId", "minimumSnapshot", "nowSeconds"]);
    const ownerKey = key(r.ownerPublicKey, "public");
    const inventoryKey = key(r.inventoryPublicKey, "public");
    if (spkiHash(ownerKey) !== hex(r.independentOwnerSpkiSha256)) fail();
    const pinnedDigest = hex(r.independentRetainedCheckpointDigest);
    const keyId = Buffer.from(r.inventorySignerKeyId);
    if (!Buffer.isBuffer(r.inventorySignerKeyId) || keyId.length !== 16) fail();
    const expectedScope = normalizeScope(r.expectedScope);
    const signerFingerprint = spkiHash(inventoryKey);
    const snapshot = Buffer.from(r.minimumSnapshot);
    if ((!Buffer.isBuffer(r.minimumSnapshot) && !(r.minimumSnapshot instanceof Uint8Array))
      || snapshot.length < 1 || snapshot.length > inventory.MAX_SNAPSHOT_BYTES) fail();
    if (!Array.isArray(r.checkpoints) || r.checkpoints.length < 1
      || r.checkpoints.length > 64
      || Reflect.ownKeys(r.checkpoints).length !== r.checkpoints.length + 1) fail();
    const now = bounded(r.nowSeconds, 1);
    let previous = null;
    for (let index = 0; index < r.checkpoints.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(r.checkpoints, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, "value")) fail();
      const record = exact(descriptor.value, [...FIELDS, "signature"]);
      const current = statement(Object.fromEntries(FIELDS.map((f) => [f, record[f]])));
      const signature = b64(record.signature, 64);
      if (!crypto.verify(null, bytes(current), ownerKey, signature)) fail();
      compareScope(current, expectedScope);
      if (current.inventory_spki_sha256 !== signerFingerprint
        || current.inventory_signer_key_id !== keyId.toString("base64url")
        || current.counter !== index + 1) fail();
      const currentDigest = checkpointDigest(record);
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
    if (decoded.sequence !== previous.inventorySequence
      || !Buffer.from(decoded.root).equals(Buffer.from(previous.root, "hex"))) fail();
    const requested = decoded.entries?.length
      ? decoded.entries[0]
      : { object_id: Buffer.alloc(16), revision: 1, epoch: 1,
        ciphertext_sha256: Buffer.alloc(32) };
    const minimumHead = { sequence: previous.inventorySequence,
      root: Buffer.from(previous.root, "hex") };
    await inventory.verifySnapshot({ serialized: snapshot, pinnedPublicKey: inventoryKey,
      pinnedSignerKeyId: keyId, expectedScope: r.expectedScope, requested, minimumHead,
      nonce: decoded.nonce });
    return Object.freeze({ minimumHead, minimumSnapshot: Buffer.from(snapshot),
      ownerSignatureVerified: true, externallyPinnedDigestMatched: true,
      signedCounter: previous.counter, ownerCheckpointDigest: previous.digest,
      // Custody of the external pin cannot be established from process memory.
      independentOffServerCustodyProven: false, authorizesIo: false });
  } catch (_) { fail(); }
}
module.exports = { SCHEMA, FIELDS, spkiHash, checkpointDigest,
  signOwnerInventoryCheckpoint, verifyOwnerInventoryEnrollment };
