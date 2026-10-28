"use strict";

// DEV-OFF cryptographic protocol primitives. A signature or Merkle proof never
// establishes independent off-host custody, freshness, or permission for I/O.
const crypto = require("node:crypto");
const DOMAIN_OWNER = Buffer.from("Root.ark/zk10/owner-account-cutover/v1\0");
const DOMAIN_ROTATION = Buffer.from("Root.ark/zk10/owner-rotation/v1\0");
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
  if (!value || typeof value !== "object" || Array.isArray(value)
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
function decode(value, length) {
  if (typeof value !== "string" || !B64.test(value)) deny();
  const result = Buffer.from(value, "base64url");
  if (result.length !== length || result.toString("base64url") !== value) deny();
  return result;
}
function hex(value) { if (typeof value !== "string" || !HEX.test(value)) deny(); return value; }
function key(value, type) {
  if (!(value instanceof crypto.KeyObject) || value.type !== type
    || value.asymmetricKeyType !== "ed25519") deny();
  return value;
}
function spkiHash(publicKey) {
  return H(key(publicKey, "public").export({ format: "der", type: "spki" })).toString("hex");
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
  if (!Array.isArray(p.grants) || p.grants.length !== 0
    || Reflect.ownKeys(p.grants).length !== 1) deny();
  decode(p.immutable_account_id, 16);
  decode(p.zk_account_id, 16);
  decode(p.nonce, 32);
  hex(p.inventory_head);
  if (!Number.isSafeInteger(p.generation) || p.generation < 1
    || !Number.isSafeInteger(p.issued_at) || p.issued_at < 1) deny();
  if (p.previous_cutover_digest !== null) hex(p.previous_cutover_digest);
  if ((p.generation === 1) !== (p.previous_cutover_digest === null)) deny();
  if (!Array.isArray(p.covered_compartments) || p.covered_compartments.length < 1
    || p.covered_compartments.length > 128
    || Reflect.ownKeys(p.covered_compartments).length !== p.covered_compartments.length + 1) deny();
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
function verifyOwnerCutover(wire, publicKey) {
  const signed = exact(wire, [...OWNER_FIELDS, "signature"]);
  const p = ownerPayload(Object.fromEntries(OWNER_FIELDS.map((f) => [f, signed[f]])));
  if (!crypto.verify(null, signatureBytes(DOMAIN_OWNER, p), key(publicKey, "public"),
    decode(signed.signature, 64))) deny();
  return Object.freeze(p);
}
function digestOwnerCutover(wire) {
  const record = exact(wire, [...OWNER_FIELDS, "signature"]);
  const p = ownerPayload(Object.fromEntries(OWNER_FIELDS.map((f) => [f, record[f]])));
  decode(record.signature, 64);
  return H(signatureBytes(DOMAIN_OWNER, p), decode(record.signature, 64)).toString("hex");
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
  if (!Array.isArray(rotations) || rotations.length > 8
    || Reflect.ownKeys(rotations).length !== rotations.length + 1) deny();
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
  if (!Array.isArray(history) || history.length < 1 || history.length > 64
    || Reflect.ownKeys(history).length !== history.length + 1
    || !Array.isArray(ownerKeys) || !ownerKeys.length) deny();
  let previous = null;
  let keyIndex = 0;
  let last;
  for (let index = 0; index < history.length; index += 1) {
    let verified;
    for (let cursor = keyIndex; cursor < ownerKeys.length; cursor += 1) {
      try { verified = verifyOwnerCutover(history[index], ownerKeys[cursor]);
        keyIndex = cursor; break; } catch (_) { /* try later signed owner rotation */ }
    }
    if (!verified || verified.immutable_account_id !== immutableAccountId
      || verified.generation !== index + 1 || verified.previous_cutover_digest !== previous
      || (last && (verified.zk_account_id !== last.zk_account_id
        || verified.issued_at < last.issued_at
        || JSON.stringify(verified.covered_compartments)
          !== JSON.stringify(last.covered_compartments)))) deny();
    previous = digestOwnerCutover(history[index]);
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
  if (!Array.isArray(siblings) || siblings.length !== 256
    || Reflect.ownKeys(siblings).length !== 257) deny();
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
  if (!Array.isArray(entries) || entries.length > 1024) deny();
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
