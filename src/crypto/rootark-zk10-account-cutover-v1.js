"use strict";

// DEV-OFF cryptographic protocol primitives. A signature or Merkle proof never
// establishes independent off-host custody, freshness, or permission for I/O.
const crypto = require("node:crypto");
const { types: { isProxy } } = require("node:util");
// Capture once, BEFORE caller-owned KeyObject getters. Every lazily loaded
// peer cryptographic module reuses this same pristine snapshot.
const {
  createPublicKey: NATIVE_CREATE_PUBLIC_KEY,
  createHash: NATIVE_CREATE_HASH,
  verify: NATIVE_VERIFY,
  sign: NATIVE_SIGN,
  timingSafeEqual: NATIVE_TIMING_SAFE_EQUAL,
  hashUpdate: NATIVE_HASH_UPDATE,
  hashDigest: NATIVE_HASH_DIGEST,
  jsonStringify: NATIVE_JSON_STRINGIFY,
  bufferFrom: NATIVE_BUFFER_FROM,
  bufferConcat: NATIVE_BUFFER_CONCAT,
  arrayPush: NATIVE_ARRAY_PUSH,
  freeze: NATIVE_FREEZE,
  pickSignedFields: NATIVE_PICK_SIGNED_FIELDS,
  bufferToString: NATIVE_BUFFER_TO_STRING,
  arrayIsArray: NATIVE_ARRAY_IS_ARRAY,
  ownKeys: NATIVE_OWN_KEYS,
  ownDescriptor: NATIVE_OWN_DESCRIPTOR,
  defineProperty: NATIVE_DEFINE_PROPERTY,
  getPrototype: NATIVE_GET_PROTOTYPE,
  hasOwn: NATIVE_HAS_OWN,
  publicExport: NATIVE_PUBLIC_EXPORT,
  keyType: NATIVE_TYPE,
  keyAlgorithm: NATIVE_ALGORITHM,
  keyEquals: NATIVE_KEY_EQUALS,
} = require("./rootark-zk10-native-intrinsics-v1");
const DOMAIN_OWNER = Buffer.from("Root.ark/zk10/owner-account-cutover/v1\0");
const DOMAIN_ROTATION = Buffer.from("Root.ark/zk10/owner-rotation/v1\0");
const PUBLIC_KEY_FIXTURE = crypto.createPublicKey({
  key: Buffer.from("302a300506032b6570032100" + "00".repeat(32), "hex"),
  format: "der", type: "spki",
});
const GET_PROTOTYPE = Object.getPrototypeOf.bind(Object);
const OWN_DESCRIPTOR = Object.getOwnPropertyDescriptor.bind(Object);
const HAS_OWN = Object.hasOwn.bind(Object);
const NATIVE_APPLY = Reflect.apply.bind(Reflect);
const PUBLIC_KEY_PROTOTYPE = GET_PROTOTYPE(PUBLIC_KEY_FIXTURE);
const PRIVATE_KEY_PROTOTYPE = GET_PROTOTYPE(crypto.generateKeyPairSync("ed25519").privateKey);
const NATIVE_HANDLE = Object.getOwnPropertySymbols(PUBLIC_KEY_FIXTURE)
  .find((symbol) => symbol.description === "kHandle");
const NATIVE_KEY_TYPE = Object.getOwnPropertySymbols(PUBLIC_KEY_FIXTURE)
  .find((symbol) => symbol.description === "kKeyType");
const NATIVE_HANDLE_PROTOTYPE = GET_PROTOTYPE(OWN_DESCRIPTOR(PUBLIC_KEY_FIXTURE, NATIVE_HANDLE).value);
const NATIVE_HANDLE_ALGORITHM = OWN_DESCRIPTOR(NATIVE_HANDLE_PROTOTYPE, "getAsymmetricKeyType").value;
const NATIVE_HANDLE_EXPORT = OWN_DESCRIPTOR(NATIVE_HANDLE_PROTOTYPE, "export").value;
const RAW_NATIVE_TYPE = OWN_DESCRIPTOR(crypto.KeyObject.prototype, "type").get;
const RAW_NATIVE_ALGORITHM = OWN_DESCRIPTOR(
  GET_PROTOTYPE(PUBLIC_KEY_PROTOTYPE), "asymmetricKeyType").get;
const RAW_NATIVE_PUBLIC_EXPORT = OWN_DESCRIPTOR(PUBLIC_KEY_PROTOTYPE, "export").value;
const OWNER_FIELDS = NATIVE_FREEZE(["type", "immutable_account_id", "zk_account_id",
  "generation", "previous_cutover_digest", "inventory_head", "complete_corpus",
  "covered_compartments", "legacy_egress_scope", "reference_disposition",
  "migration_disposition", "grant", "grants", "suite", "nonce", "issued_at"]);
const ROTATION_FIELDS = NATIVE_FREEZE(["type", "immutable_account_id", "generation",
  "from_spki_sha256", "next_public_key", "previous_rotation_digest"]);
// Construct each wire field list before any caller-owned native getter runs.
// Late array spread would consult attacker-replaceable Symbol.iterator.
const OWNER_WIRE_FIELDS = NATIVE_FREEZE([...OWNER_FIELDS, "signature"]);
const ROTATION_WIRE_FIELDS = NATIVE_FREEZE([...ROTATION_FIELDS,
  "signature_from", "signature_next"]);
const HEX = /^[a-f0-9]{64}$/;
const B64 = /^[A-Za-z0-9_-]+$/;
const H = (...v) => {
  const hash = NATIVE_CREATE_HASH("sha256");
  NATIVE_HASH_UPDATE.call(hash, NATIVE_BUFFER_CONCAT(v));
  return NATIVE_HASH_DIGEST.call(hash);
};
function deny() {
  const err = new Error("ZK10_ACCOUNT_CUTOVER_UNVERIFIED");
  err.code = err.message;
  throw err;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || isProxy(value) || NATIVE_ARRAY_IS_ARRAY(value)) deny();
  const proto = NATIVE_GET_PROTOTYPE(value);
  if ((proto !== Object.prototype && proto !== null)
    || NATIVE_OWN_KEYS(value).length !== fields.length) deny();
  const output = {};
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    const descriptor = NATIVE_OWN_DESCRIPTOR(value, field);
    if (!descriptor || !NATIVE_HAS_OWN(descriptor, "value")) deny();
    NATIVE_DEFINE_PROPERTY(output, field, { value: descriptor.value,
      writable: true, enumerable: true, configurable: true });
  }
  return output;
}
function exactArray(value, minimum, maximum) {
  // A plain Array can still contain an own accessor at an indexed position.
  // Reading history[0], ownerKeys[0] or a signed compartment via an iterator
  // would invoke that accessor before signature verification. Validate every
  // bounded slot as an own DATA descriptor before consuming any element.
  if (isProxy(value) || !Array.isArray(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || value.length < minimum || value.length > maximum
    || Reflect.ownKeys(value).length !== value.length + 1) deny();
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = OWN_DESCRIPTOR(value, index);
    if (!descriptor || !HAS_OWN(descriptor, "value")) deny();
  }
  return value;
}
function decode(value, length) {
  if (typeof value !== "string" || !B64.test(value)) deny();
  const result = NATIVE_BUFFER_FROM(value, "base64url");
  if (result.length !== length || NATIVE_BUFFER_TO_STRING.call(result, "base64url") !== value) deny();
  return result;
}
function hex(value) { if (typeof value !== "string" || !HEX.test(value)) deny(); return value; }
function key(value, type) {
  try {
    // Neither a fake DATA kHandle nor an accessor-backed kKeyType may reach
    // native KeyObject accessors: both can execute caller-controlled JS.
    if (type !== "public" && type !== "private") deny();
    if (isProxy(value) || !(value instanceof crypto.KeyObject)
      || GET_PROTOTYPE(value) !== (type === "public"
        ? PUBLIC_KEY_PROTOTYPE : PRIVATE_KEY_PROTOTYPE)) deny();
    const handle = NATIVE_HANDLE && OWN_DESCRIPTOR(value, NATIVE_HANDLE);
    const keyType = NATIVE_KEY_TYPE && OWN_DESCRIPTOR(value, NATIVE_KEY_TYPE);
    if (!handle || !HAS_OWN(handle, "value")
      || !keyType || !HAS_OWN(keyType, "value") || keyType.value !== type
      || !handle.value || typeof handle.value !== "object"
      || isProxy(handle.value)
      || GET_PROTOTYPE(handle.value) !== NATIVE_HANDLE_PROTOTYPE
      || HAS_OWN(handle.value, "getAsymmetricKeyType")
      || HAS_OWN(handle.value, "export")
      || OWN_DESCRIPTOR(NATIVE_HANDLE_PROTOTYPE, "getAsymmetricKeyType")?.value
        !== NATIVE_HANDLE_ALGORITHM
      || OWN_DESCRIPTOR(NATIVE_HANDLE_PROTOTYPE, "export")?.value
        !== NATIVE_HANDLE_EXPORT
      || NATIVE_APPLY(NATIVE_HANDLE_ALGORITHM, handle.value, []) !== "ed25519"
      || NATIVE_APPLY(RAW_NATIVE_TYPE, value, []) !== type
      || NATIVE_APPLY(RAW_NATIVE_ALGORITHM, value, []) !== "ed25519") deny();
    if (type === "private") return value; // Never export private key material.
    if (type !== "public") deny();
    // Take one native SPKI snapshot, then discard the supplied reference.
    // Subsequent hash and signature checks use only the fresh, native key.
    const der = NATIVE_APPLY(RAW_NATIVE_PUBLIC_EXPORT, value, [{ format: "der", type: "spki" }]);
    if (!Buffer.isBuffer(der) || der.length !== 44) deny();
    const canonical = NATIVE_CREATE_PUBLIC_KEY({ key: Buffer.from(der),
      format: "der", type: "spki" });
    if (NATIVE_APPLY(RAW_NATIVE_TYPE, canonical, []) !== "public"
      || NATIVE_APPLY(RAW_NATIVE_ALGORITHM, canonical, []) !== "ed25519") deny();
    return canonical;
  } catch (_) { deny(); }
}
function pinnedSpkiHash(pinnedPublicKey) {
  return NATIVE_BUFFER_TO_STRING.call(H(NATIVE_PUBLIC_EXPORT.call(pinnedPublicKey,
    { format: "der", type: "spki" })), "hex");
}
function spkiHash(publicKey) {
  return pinnedSpkiHash(key(publicKey, "public"));
}
function samePublicKey(left, right) {
  return NATIVE_KEY_EQUALS.call(key(left, "public"), key(right, "public"));
}
function ownerPayload(payload) {
  const p = exact(payload, OWNER_FIELDS);
  if (p.type !== "rootark-zk10-owner-account-cutover/v1"
    || p.grant !== "protected_enforced" || p.suite !== "zk1-v2"
    || p.complete_corpus !== true || p.legacy_egress_scope !== "all"
    || p.reference_disposition !== "fully_accounted"
    || p.migration_disposition !== "closed") deny();
  // Completed cutover cannot carry compatibility grants. Migration windows
  // require their own separately signed pre-cutover policy protocol.
  exactArray(p.grants, 0, 0);
  decode(p.immutable_account_id, 16);
  decode(p.zk_account_id, 16);
  decode(p.nonce, 32);
  hex(p.inventory_head);
  if (!Number.isSafeInteger(p.generation) || p.generation < 1
    || !Number.isSafeInteger(p.issued_at) || p.issued_at < 1) deny();
  if (p.previous_cutover_digest !== null) hex(p.previous_cutover_digest);
  if ((p.generation === 1) !== (p.previous_cutover_digest === null)) deny();
  exactArray(p.covered_compartments, 1, 128);
  let previous = "";
  const names = [];
  for (let index = 0; index < p.covered_compartments.length; index += 1) {
    const descriptor = NATIVE_OWN_DESCRIPTOR(p.covered_compartments, index);
    if (!descriptor || !NATIVE_HAS_OWN(descriptor, "value")) deny();
    const item = descriptor.value;
    decode(item, 16);
    if (item <= previous) deny();
    previous = item;
    // Define an own DATA property directly: even a captured native Array.push
    // would invoke Array.prototype[7] installed by a hostile KeyObject getter.
    NATIVE_DEFINE_PROPERTY(names, index, { value: item,
      enumerable: true, writable: true, configurable: true });
  }
  // The verified statement is retained by the history caller alongside its
  // digest. Neither coverage nor grants may be rewritten after verification.
  return { ...p, covered_compartments: NATIVE_FREEZE(names), grants: NATIVE_FREEZE([]) };
}
function signatureBytes(domain, payload) {
  return NATIVE_BUFFER_CONCAT([domain, NATIVE_BUFFER_FROM(NATIVE_JSON_STRINGIFY(payload), "utf8")]);
}
function signOwnerCutover(payload, privateKey) {
  const p = ownerPayload(payload);
  return NATIVE_FREEZE({ ...p, signature: NATIVE_BUFFER_TO_STRING.call(NATIVE_SIGN(null,
    signatureBytes(DOMAIN_OWNER, p), key(privateKey, "private")), "base64url") });
}
function snapshotOwnerCutover(wire) {
  const signed = exact(wire, OWNER_WIRE_FIELDS);
  const p = ownerPayload(NATIVE_PICK_SIGNED_FIELDS(signed, OWNER_FIELDS));
  // Keep the statement and its digest on the same byte snapshot. In particular,
  // never re-read a Proxy wire after verifying its owner signature, and do not
  // retain references to caller-controlled nested arrays.
  const body = NATIVE_FREEZE({ ...p, grants: NATIVE_FREEZE([]),
    covered_compartments: NATIVE_FREEZE(p.covered_compartments) });
  return { body, bytes: signatureBytes(DOMAIN_OWNER, body),
    signature: decode(signed.signature, 64) };
}
function verifyOwnerCutover(wire, publicKey) {
  const { body, bytes, signature } = snapshotOwnerCutover(wire);
  if (!NATIVE_VERIFY(null, bytes, key(publicKey, "public"), signature)) deny();
  return body;
}
function digestOwnerCutover(wire) {
  const { bytes, signature } = snapshotOwnerCutover(wire);
  return NATIVE_BUFFER_TO_STRING.call(H(bytes, signature), "hex");
}
function rotationPayload(p) {
  const v = exact(p, ROTATION_FIELDS);
  if (v.type !== "rootark-zk10-owner-rotation/v1"
    || !Number.isSafeInteger(v.generation) || v.generation < 1
    || (v.generation === 1) !== (v.previous_rotation_digest === null)) deny();
  decode(v.immutable_account_id, 16);
  hex(v.from_spki_sha256);
  if (v.previous_rotation_digest !== null) hex(v.previous_rotation_digest);
  const der = decode(v.next_public_key, 44);
  let next;
  try { next = NATIVE_CREATE_PUBLIC_KEY({ key: der, format: "der", type: "spki" }); }
  catch (_) { deny(); }
  next = key(next, "public");
  if (!NATIVE_PUBLIC_EXPORT.call(next, { format: "der", type: "spki" }).equals(der)) deny();
  return { body: v, next };
}
function signOwnerRotation(payload, previousPrivateKey, nextPrivateKey) {
  const { body, next } = rotationPayload(payload);
  if (spkiHash(NATIVE_CREATE_PUBLIC_KEY(key(previousPrivateKey, "private")))
    !== body.from_spki_sha256 || spkiHash(NATIVE_CREATE_PUBLIC_KEY(key(nextPrivateKey, "private")))
    !== spkiHash(next)) deny();
  const data = signatureBytes(DOMAIN_ROTATION, body);
  return NATIVE_FREEZE({ ...body,
    signature_from: NATIVE_BUFFER_TO_STRING.call(
      NATIVE_SIGN(null, data, previousPrivateKey), "base64url"),
    signature_next: NATIVE_BUFFER_TO_STRING.call(
      NATIVE_SIGN(null, data, nextPrivateKey), "base64url") });
}
function verifyOwnerRotationKeys(rotations, pinnedRoot, immutableAccountId) {
  exactArray(rotations, 0, 8);
  let current = key(pinnedRoot, "public");
  const accepted = [current];
  let previousDigest = null;
  for (let index = 0; index < rotations.length; index += 1) {
    const signed = exact(rotations[index], ROTATION_WIRE_FIELDS);
    const { body, next } = rotationPayload(NATIVE_PICK_SIGNED_FIELDS(
      signed, ROTATION_FIELDS));
    if (body.immutable_account_id !== immutableAccountId
      || body.generation !== index + 1 || body.previous_rotation_digest !== previousDigest
      || body.from_spki_sha256 !== pinnedSpkiHash(current)) deny();
    const bytes = signatureBytes(DOMAIN_ROTATION, body);
    if (!NATIVE_VERIFY(null, bytes, current, decode(signed.signature_from, 64))
      || !NATIVE_VERIFY(null, bytes, next, decode(signed.signature_next, 64))) deny();
    previousDigest = NATIVE_BUFFER_TO_STRING.call(H(bytes, decode(signed.signature_from, 64),
      decode(signed.signature_next, 64)), "hex");
    current = next;
    // Keep every genuine generation key. A previous native KeyObject getter
    // can replace global String and redirect String(length) to an old slot.
    NATIVE_DEFINE_PROPERTY(accepted, accepted.length, { value: current,
      enumerable: true, writable: true, configurable: true });
  }
  return NATIVE_FREEZE(accepted);
}
function verifyOwnerRotationChain(rotations, pinnedRoot, immutableAccountId) {
  const keys = verifyOwnerRotationKeys(rotations, pinnedRoot, immutableAccountId);
  return keys[keys.length - 1];
}
function verifyOwnerCutoverHistory(history, ownerKeys, immutableAccountId) {
  exactArray(history, 1, 64);
  exactArray(ownerKeys, 1, 9);
  // Pin every trusted key once, not again after attacker-controlled history
  // processing. Reject accessors, holes and Proxies instead of invoking them.
  const pinnedKeys = [];
  for (let index = 0; index < ownerKeys.length; index += 1) {
    const entry = NATIVE_OWN_DESCRIPTOR(ownerKeys, index);
    if (!entry || !NATIVE_HAS_OWN(entry, "value")) deny();
    NATIVE_DEFINE_PROPERTY(pinnedKeys, index, { value: key(entry.value, "public"),
      enumerable: true, writable: true, configurable: true });
  }
  let previous = null;
  let keyIndex = 0;
  let last;
  for (let index = 0; index < history.length; index += 1) {
    const entry = NATIVE_OWN_DESCRIPTOR(history, index);
    if (!entry || !NATIVE_HAS_OWN(entry, "value")) deny();
    const signed = exact(entry.value, OWNER_WIRE_FIELDS);
    const payload = ownerPayload(NATIVE_PICK_SIGNED_FIELDS(signed, OWNER_FIELDS));
    // The signature verification and digest must refer to ONE immutable
    // signed record, not two independently read versions of the same slot.
    const compartments = [];
    for (let offset = 0; offset < payload.covered_compartments.length; offset += 1) {
      const part = NATIVE_OWN_DESCRIPTOR(payload.covered_compartments, offset);
      if (!part || !NATIVE_HAS_OWN(part, "value")) deny();
      NATIVE_DEFINE_PROPERTY(compartments, offset, { value: part.value,
        enumerable: true, writable: true, configurable: true });
    }
    const wire = NATIVE_FREEZE({ ...payload,
      covered_compartments: NATIVE_FREEZE(compartments),
      grants: NATIVE_FREEZE([]), signature: signed.signature });
    let verified;
    for (let cursor = keyIndex; cursor < pinnedKeys.length; cursor += 1) {
      try { verified = verifyOwnerCutover(wire, pinnedKeys[cursor]);
        keyIndex = cursor; break; } catch (_) { /* try later signed owner rotation */ }
    }
    if (!verified || verified.immutable_account_id !== immutableAccountId
      || verified.generation !== index + 1 || verified.previous_cutover_digest !== previous
      || (last && (verified.zk_account_id !== last.zk_account_id
        || verified.issued_at < last.issued_at
        || NATIVE_JSON_STRINGIFY(verified.covered_compartments)
          !== NATIVE_JSON_STRINGIFY(last.covered_compartments)))) deny();
    previous = digestOwnerCutover(wire);
    last = verified;
  }
  if (keyIndex !== pinnedKeys.length - 1) deny();
  return NATIVE_FREEZE({ statement: last, digest: previous });
}

const EMPTY = [H(Buffer.from("Root.ark/zk10/smt-empty/v1\0"))];
for (let depth = 0; depth < 256; depth += 1) EMPTY.push(
  H(Buffer.from("Root.ark/zk10/smt-node/v1\0"), EMPTY[depth], EMPTY[depth]));
const NODE = Buffer.from("Root.ark/zk10/smt-node/v1\0");
const LEAF = Buffer.from("Root.ark/zk10/smt-leaf/v1\0");
function leaf(accountId, cutoverDigest) {
  if (cutoverDigest === null) return EMPTY[0];
  return H(LEAF, decode(accountId, 16), NATIVE_BUFFER_FROM(hex(cutoverDigest), "hex"));
}
function pathBits(accountId) {
  return BigInt(`0x${NATIVE_BUFFER_TO_STRING.call(H(
    Buffer.from("Root.ark/zk10/smt-key/v1\0"), decode(accountId, 16)), "hex")}`);
}
function verifySparseEnrollmentProof(accountId, cutoverDigest, siblings, expectedRoot) {
  exactArray(siblings, 256, 256);
  let at = pathBits(accountId), current = leaf(accountId, cutoverDigest);
  for (const sibling of siblings) {
    const siblingHash = NATIVE_BUFFER_FROM(hex(sibling), "hex");
    current = at & 1n ? H(NODE, siblingHash, current) : H(NODE, current, siblingHash);
    at >>= 1n;
  }
  if (!NATIVE_TIMING_SAFE_EQUAL(current, NATIVE_BUFFER_FROM(hex(expectedRoot), "hex"))) deny();
  return true;
}
// Pure deterministic fixture/proof builder. The authority, not an app server,
// must create and independently retain the committed head for a real deployment.
function buildSparseEnrollmentProof(entries, accountId) {
  exactArray(entries, 0, 1024);
  let level = new Map();
  for (const record of entries) {
    const v = exact(record, ["accountId", "cutoverDigest"]);
    const at = pathBits(v.accountId).toString();
    if (level.has(at)) deny();
    level.set(at, leaf(v.accountId, v.cutoverDigest));
  }
  const wanted = pathBits(accountId);
  const siblings = [];
  for (let depth = 0; depth < 256; depth += 1) {
    const currentAt = wanted >> BigInt(depth);
    siblings.push(NATIVE_BUFFER_TO_STRING.call(
      level.get((currentAt ^ 1n).toString()) || EMPTY[depth], "hex"));
    const next = new Map();
    for (const [item, digest] of level) {
      const n = BigInt(item), parent = n >> 1n;
      if (next.has(parent.toString())) continue;
      const sibling = level.get((n ^ 1n).toString()) || EMPTY[depth];
      next.set(parent.toString(), n & 1n
        ? H(NODE, sibling, digest) : H(NODE, digest, sibling));
    }
    level = next;
  }
  return NATIVE_FREEZE({ root: NATIVE_BUFFER_TO_STRING.call(
    level.get("0") || EMPTY[256], "hex"),
    siblings: NATIVE_FREEZE(siblings) });
}
module.exports = { OWNER_FIELDS, ROTATION_FIELDS, exact, decode, hex, key, spkiHash,
  samePublicKey,
  signatureBytes, signOwnerCutover, verifyOwnerCutover, digestOwnerCutover,
  signOwnerRotation, verifyOwnerRotationChain, verifySparseEnrollmentProof,
  verifyOwnerRotationKeys, verifyOwnerCutoverHistory, buildSparseEnrollmentProof };
