"use strict";

// DEV-OFF cryptographic protocol primitives. A signature or Merkle proof never
// establishes independent off-host custody, freshness, or permission for I/O.
const crypto = require("node:crypto");
const { types: { isProxy } } = require("node:util");
const DOMAIN_OWNER = Buffer.from("Root.ark/zk10/owner-account-cutover/v1\0");
const DOMAIN_ROTATION = Buffer.from("Root.ark/zk10/owner-rotation/v1\0");
// Read native identity from Node prototypes, not caller-shadowable .type,
// .asymmetricKeyType or .export properties. Public KeyObjects must also be
// reimported: a prototype-derived wrapper can change its internal kHandle
// between an SPKI hash and crypto.verify, even with native methods.
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
const NATIVE_TYPE = OWN_DESCRIPTOR(crypto.KeyObject.prototype, "type").get;
const NATIVE_ALGORITHM = OWN_DESCRIPTOR(
  GET_PROTOTYPE(PUBLIC_KEY_PROTOTYPE), "asymmetricKeyType").get;
const NATIVE_PUBLIC_EXPORT = OWN_DESCRIPTOR(PUBLIC_KEY_PROTOTYPE, "export").value;
const OWNER_FIELDS = Object.freeze(["type", "immutable_account_id", "zk_account_id",
  "generation", "previous_cutover_digest", "inventory_head", "complete_corpus",
  "covered_compartments", "legacy_egress_scope", "reference_disposition",
  "migration_disposition", "grant", "grants", "suite", "nonce", "issued_at"]);
const ROTATION_FIELDS = Object.freeze(["type", "immutable_account_id", "generation",
  "from_spki_sha256", "next_public_key", "previous_rotation_digest"]);
const HEX = /^[a-f0-9]{64}$/;
const B64 = /^[A-Za-z0-9_-]+$/;
const H = (...v) => crypto.createHash("sha256").update(Buffer.concat(v)).digest();
function deny() {
  const err = new Error("ZK10_ACCOUNT_CUTOVER_UNVERIFIED");
  err.code = err.message;
  throw err;
}
function exact(value, fields) {
  // A Proxy getPrototypeOf/ownKeys/descriptor trap can run BEFORE Ed25519
  // verification and replace process-wide crypto.verify. Reject proxies
  // without evaluating any of their user-defined traps.
  if (!value || typeof value !== "object" || isProxy(value) || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length) deny();
  const output = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
    output[field] = descriptor.value;
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
  const result = Buffer.from(value, "base64url");
  if (result.length !== length || result.toString("base64url") !== value) deny();
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
      || NATIVE_APPLY(NATIVE_TYPE, value, []) !== type
      || NATIVE_APPLY(NATIVE_ALGORITHM, value, []) !== "ed25519") deny();
    if (type === "private") return value; // Never export private key material.
    if (type !== "public") deny();
    // Take one native SPKI snapshot, then discard the supplied reference.
    // Subsequent hash and signature checks use only the fresh, native key.
    const der = NATIVE_APPLY(NATIVE_PUBLIC_EXPORT, value, [{ format: "der", type: "spki" }]);
    if (!Buffer.isBuffer(der) || der.length !== 44) deny();
    const canonical = crypto.createPublicKey({ key: Buffer.from(der),
      format: "der", type: "spki" });
    if (NATIVE_APPLY(NATIVE_TYPE, canonical, []) !== "public"
      || NATIVE_APPLY(NATIVE_ALGORITHM, canonical, []) !== "ed25519") deny();
    return canonical;
  } catch (_) { deny(); }
}
function spkiHash(publicKey) {
  return H(NATIVE_APPLY(NATIVE_PUBLIC_EXPORT, key(publicKey, "public"),
    [{ format: "der", type: "spki" }])).toString("hex");
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
  for (const item of p.covered_compartments) {
    decode(item, 16);
    if (item <= previous) deny();
    previous = item;
    names.push(item);
  }
  return { ...p, covered_compartments: names };
}
function signatureBytes(domain, payload) {
  return Buffer.concat([domain, Buffer.from(JSON.stringify(payload), "utf8")]);
}
function signOwnerCutover(payload, privateKey) {
  const p = ownerPayload(payload);
  return Object.freeze({ ...p, signature: crypto.sign(null,
    signatureBytes(DOMAIN_OWNER, p), key(privateKey, "private")).toString("base64url") });
}
function snapshotOwnerCutover(wire) {
  const signed = exact(wire, [...OWNER_FIELDS, "signature"]);
  const p = ownerPayload(Object.fromEntries(OWNER_FIELDS.map((f) => [f, signed[f]])));
  // Keep the statement and its digest on the same byte snapshot. In particular,
  // never re-read a Proxy wire after verifying its owner signature, and do not
  // retain references to caller-controlled nested arrays.
  const body = Object.freeze({ ...p, grants: Object.freeze([]),
    covered_compartments: Object.freeze(p.covered_compartments) });
  return { body, bytes: signatureBytes(DOMAIN_OWNER, body),
    signature: decode(signed.signature, 64) };
}
function verifyOwnerCutover(wire, publicKey) {
  const { body, bytes, signature } = snapshotOwnerCutover(wire);
  if (!crypto.verify(null, bytes, key(publicKey, "public"), signature)) deny();
  return body;
}
function digestOwnerCutover(wire) {
  const { bytes, signature } = snapshotOwnerCutover(wire);
  return H(bytes, signature).toString("hex");
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
  try { next = crypto.createPublicKey({ key: der, format: "der", type: "spki" }); }
  catch (_) { deny(); }
  key(next, "public");
  return { body: v, next };
}
function signOwnerRotation(payload, previousPrivateKey, nextPrivateKey) {
  const { body, next } = rotationPayload(payload);
  if (spkiHash(crypto.createPublicKey(key(previousPrivateKey, "private")))
    !== body.from_spki_sha256 || spkiHash(crypto.createPublicKey(key(nextPrivateKey, "private")))
    !== spkiHash(next)) deny();
  const data = signatureBytes(DOMAIN_ROTATION, body);
  return Object.freeze({ ...body,
    signature_from: crypto.sign(null, data, previousPrivateKey).toString("base64url"),
    signature_next: crypto.sign(null, data, nextPrivateKey).toString("base64url") });
}
function verifyOwnerRotationKeys(rotations, pinnedRoot, immutableAccountId) {
  exactArray(rotations, 0, 8);
  let current = key(pinnedRoot, "public");
  const accepted = [current];
  let previousDigest = null;
  for (let index = 0; index < rotations.length; index += 1) {
    const signed = exact(rotations[index], [...ROTATION_FIELDS, "signature_from", "signature_next"]);
    const { body, next } = rotationPayload(Object.fromEntries(ROTATION_FIELDS.map((f) => [f, signed[f]])));
    if (body.immutable_account_id !== immutableAccountId
      || body.generation !== index + 1 || body.previous_rotation_digest !== previousDigest
      || body.from_spki_sha256 !== spkiHash(current)) deny();
    const bytes = signatureBytes(DOMAIN_ROTATION, body);
    if (!crypto.verify(null, bytes, current, decode(signed.signature_from, 64))
      || !crypto.verify(null, bytes, next, decode(signed.signature_next, 64))) deny();
    previousDigest = H(bytes, decode(signed.signature_from, 64),
      decode(signed.signature_next, 64)).toString("hex");
    current = next;
    accepted.push(current);
  }
  return Object.freeze(accepted);
}
function verifyOwnerRotationChain(rotations, pinnedRoot, immutableAccountId) {
  const keys = verifyOwnerRotationKeys(rotations, pinnedRoot, immutableAccountId);
  return keys[keys.length - 1];
}
function verifyOwnerCutoverHistory(history, ownerKeys, immutableAccountId) {
  exactArray(history, 1, 64);
  exactArray(ownerKeys, 1, 9);
  let previous = null;
  let keyIndex = 0;
  let last;
  for (let index = 0; index < history.length; index += 1) {
    const { body, bytes, signature } = snapshotOwnerCutover(history[index]);
    let verified;
    for (let cursor = keyIndex; cursor < ownerKeys.length; cursor += 1) {
      try {
        if (crypto.verify(null, bytes, key(ownerKeys[cursor], "public"), signature)) {
          verified = body;
          keyIndex = cursor;
          break;
        }
      } catch (_) { /* try later signed owner rotation */ }
    }
    if (!verified || verified.immutable_account_id !== immutableAccountId
      || verified.generation !== index + 1 || verified.previous_cutover_digest !== previous
      || (last && (verified.zk_account_id !== last.zk_account_id
        || verified.issued_at < last.issued_at
        || JSON.stringify(verified.covered_compartments)
          !== JSON.stringify(last.covered_compartments)))) deny();
    previous = H(bytes, signature).toString("hex");
    last = verified;
  }
  if (keyIndex !== ownerKeys.length - 1) deny();
  return Object.freeze({ statement: last, digest: previous });
}

const EMPTY = [H(Buffer.from("Root.ark/zk10/smt-empty/v1\0"))];
for (let depth = 0; depth < 256; depth += 1) EMPTY.push(
  H(Buffer.from("Root.ark/zk10/smt-node/v1\0"), EMPTY[depth], EMPTY[depth]));
const NODE = Buffer.from("Root.ark/zk10/smt-node/v1\0");
const LEAF = Buffer.from("Root.ark/zk10/smt-leaf/v1\0");
function leaf(accountId, cutoverDigest) {
  if (cutoverDigest === null) return EMPTY[0];
  return H(LEAF, decode(accountId, 16), Buffer.from(hex(cutoverDigest), "hex"));
}
function pathBits(accountId) {
  return BigInt(`0x${H(Buffer.from("Root.ark/zk10/smt-key/v1\0"),
    decode(accountId, 16)).toString("hex")}`);
}
function verifySparseEnrollmentProof(accountId, cutoverDigest, siblings, expectedRoot) {
  exactArray(siblings, 256, 256);
  let at = pathBits(accountId), current = leaf(accountId, cutoverDigest);
  for (const sibling of siblings) {
    const siblingHash = Buffer.from(hex(sibling), "hex");
    current = at & 1n ? H(NODE, siblingHash, current) : H(NODE, current, siblingHash);
    at >>= 1n;
  }
  if (!crypto.timingSafeEqual(current, Buffer.from(hex(expectedRoot), "hex"))) deny();
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
    siblings.push((level.get((currentAt ^ 1n).toString()) || EMPTY[depth]).toString("hex"));
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
  return Object.freeze({ root: (level.get("0") || EMPTY[256]).toString("hex"),
    siblings: Object.freeze(siblings) });
}
module.exports = { OWNER_FIELDS, ROTATION_FIELDS, exact, decode, hex, key, spkiHash,
  signatureBytes, signOwnerCutover, verifyOwnerCutover, digestOwnerCutover,
  signOwnerRotation, verifyOwnerRotationChain, verifySparseEnrollmentProof,
  verifyOwnerRotationKeys, verifyOwnerCutoverHistory, buildSparseEnrollmentProof };
