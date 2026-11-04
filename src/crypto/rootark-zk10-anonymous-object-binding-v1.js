"use strict";

// DEV-OFF pure cryptographic building block for future anonymous share/open
// cutover. No current route produces immutable object identities, an externally
// complete object corpus, or an independently retained owner/corpus head.
// A valid owner signature therefore NEVER authorizes I/O or proves ownership.
const crypto = require("node:crypto");
const {
  exact, decode, hex, key, verifyOwnerRotationKeys, verifyOwnerCutoverHistory,
} = require("./rootark-zk10-account-cutover-v1");

const DOMAIN = Buffer.from("Root.ark/zk10/anonymous-object-binding/v1\0", "ascii");
const TOKEN_DOMAIN = Buffer.from("Root.ark/zk10/anonymous-object-token/v1\0", "ascii");
const INVENTORY_KEY = Buffer.from("Root.ark/zk10/anonymous-object-smt-key/v1\0", "ascii");
const INVENTORY_LEAF = Buffer.from("Root.ark/zk10/anonymous-object-smt-leaf/v1\0", "ascii");
const INVENTORY_NODE = Buffer.from("Root.ark/zk10/anonymous-object-smt-node/v1\0", "ascii");
const INVENTORY_EMPTY = Buffer.from("Root.ark/zk10/anonymous-object-smt-empty/v1\0", "ascii");
const FIELDS = Object.freeze([
  "type", "kind", "immutable_account_id", "zk_account_id",
  "owner_generation", "owner_cutover_digest", "inventory_head",
  "object_id", "object_revision", "ciphertext_sha256", "token_digest", "nonce",
]);
const INPUT_FIELDS = Object.freeze([
  "statement", "ownerCutoverHistory", "ownerRotations", "pinnedOwnerRoot",
  "independentlyRetainedCutoverDigest", "independentlyExpectedAccountId",
  "expectedKind", "expectedToken", "expectedObject", "objectMembershipProof",
]);
const OBJECT_FIELDS = Object.freeze(["object_id", "revision", "ciphertext_sha256"]);
const INVENTORY_FIELDS = Object.freeze([
  "immutable_account_id", "owner_generation", "object_id", "revision", "ciphertext_sha256",
]);
const TOKEN = /^[a-f0-9]{48}$/;

function deny() {
  const error = new Error("ZK10_ANONYMOUS_BINDING_UNVERIFIED");
  error.code = error.message;
  throw error;
}
function kind(value) {
  if (value !== "share" && value !== "open") deny();
  return value;
}
function canonical(value) {
  try {
    const v = exact(value, FIELDS);
    if (v.type !== "rootark-zk10-anonymous-object-binding/v1") deny();
    kind(v.kind);
    decode(v.immutable_account_id, 16);
    decode(v.zk_account_id, 16);
    decode(v.object_id, 16);
    decode(v.nonce, 32);
    hex(v.owner_cutover_digest);
    hex(v.inventory_head);
    hex(v.ciphertext_sha256);
    hex(v.token_digest);
    if (!Number.isSafeInteger(v.owner_generation) || v.owner_generation < 1
      || !Number.isSafeInteger(v.object_revision) || v.object_revision < 1) deny();
    return v;
  } catch (_) { deny(); }
}
function tokenDigest(rawKind, token) {
  kind(rawKind);
  if (typeof token !== "string" || !TOKEN.test(token)) deny();
  return crypto.createHash("sha256").update(TOKEN_DOMAIN)
    .update(Buffer.from(rawKind, "ascii")).update(Buffer.from([0]))
    .update(Buffer.from(token, "ascii")).digest("hex");
}
function sha(...parts) {
  const hash = crypto.createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}
function uint64(number, minimum) {
  if (!Number.isSafeInteger(number) || number < minimum) deny();
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(number));
  return buf;
}
function normalizedInventoryEntry(record) {
  const v = exact(record, INVENTORY_FIELDS);
  return {
    immutable_account_id: v.immutable_account_id,
    owner_generation: v.owner_generation,
    object_id: v.object_id,
    revision: v.revision,
    ciphertext_sha256: v.ciphertext_sha256,
    accountBytes: decode(v.immutable_account_id, 16),
    generationBytes: uint64(v.owner_generation, 1),
    objectBytes: decode(v.object_id, 16),
    revisionBytes: uint64(v.revision, 1),
    ciphertextBytes: Buffer.from(hex(v.ciphertext_sha256), "hex"),
  };
}
function inventoryPosition(entry) {
  return BigInt("0x" + sha(INVENTORY_KEY, entry.accountBytes, entry.objectBytes,
    entry.revisionBytes).toString("hex"));
}
function inventoryLeaf(entry) {
  return sha(INVENTORY_LEAF, entry.accountBytes, entry.generationBytes,
    entry.objectBytes, entry.revisionBytes, entry.ciphertextBytes);
}
const EMPTY = [sha(INVENTORY_EMPTY)];
for (let depth = 0; depth < 256; depth += 1) {
  EMPTY.push(sha(INVENTORY_NODE, EMPTY[depth], EMPTY[depth]));
}
function verifySparseObjectInventoryProof(accountId, generation, object, siblings, root) {
  const entry = normalizedInventoryEntry({
    immutable_account_id: accountId, owner_generation: generation,
    object_id: object.object_id, revision: object.revision,
    ciphertext_sha256: object.ciphertext_sha256,
  });
  if (!Array.isArray(siblings) || siblings.length !== 256
    || Reflect.ownKeys(siblings).length !== 257) deny();
  let position = inventoryPosition(entry);
  let current = inventoryLeaf(entry);
  for (const sibling of siblings) {
    const bytes = Buffer.from(hex(sibling), "hex");
    current = position & 1n
      ? sha(INVENTORY_NODE, bytes, current) : sha(INVENTORY_NODE, current, bytes);
    position >>= 1n;
  }
  if (!crypto.timingSafeEqual(current, Buffer.from(hex(root), "hex"))) deny();
  return true;
}
// Deterministic synthetic-proof helper. It cannot establish external custody,
// complete historical object coverage, or an independent retained floor.
function buildSparseObjectInventoryProof(records, accountId, objectId, revision) {
  decode(accountId, 16);
  decode(objectId, 16);
  uint64(revision, 1);
  if (!Array.isArray(records) || !records.length || records.length > 1024
    || Reflect.ownKeys(records).length !== records.length + 1) deny();
  let level = new Map();
  let target = null;
  for (const record of records) {
    const entry = normalizedInventoryEntry(record);
    if (entry.immutable_account_id !== accountId) deny();
    const position = inventoryPosition(entry).toString();
    if (level.has(position)) deny();
    level.set(position, inventoryLeaf(entry));
    if (entry.object_id === objectId && entry.revision === revision) {
      target = inventoryPosition(entry);
    }
  }
  if (target === null) deny();
  const siblings = [];
  for (let depth = 0; depth < 256; depth += 1) {
    const position = target >> BigInt(depth);
    siblings.push((level.get((position ^ 1n).toString()) || EMPTY[depth]).toString("hex"));
    const parents = new Map();
    for (const [index, digest] of level) {
      const address = BigInt(index);
      const parent = (address >> 1n).toString();
      if (parents.has(parent)) continue;
      const sibling = level.get((address ^ 1n).toString()) || EMPTY[depth];
      parents.set(parent, address & 1n
        ? sha(INVENTORY_NODE, sibling, digest) : sha(INVENTORY_NODE, digest, sibling));
    }
    level = parents;
  }
  return Object.freeze({ root: (level.get("0") || EMPTY[256]).toString("hex"),
    siblings: Object.freeze(siblings) });
}
function signatureBytes(body) {
  return Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(body), "utf8")]);
}
function signAnonymousObjectBinding(unsigned, privateKey) {
  try {
    const body = canonical(unsigned);
    const signature = crypto.sign(null, signatureBytes(body), key(privateKey, "private"));
    return Object.freeze({ ...body, signature: signature.toString("base64url") });
  } catch (_) { deny(); }
}
function verifyAnonymousObjectBinding(input) {
  try {
    const r = exact(input, INPUT_FIELDS);
    const expectedAccount = r.independentlyExpectedAccountId;
    decode(expectedAccount, 16);
    const independentDigest = hex(r.independentlyRetainedCutoverDigest);
    const expectedKind = kind(r.expectedKind);
    const expectedTokenDigest = tokenDigest(expectedKind, r.expectedToken);
    const expectedObject = exact(r.expectedObject, OBJECT_FIELDS);
    decode(expectedObject.object_id, 16);
    hex(expectedObject.ciphertext_sha256);
    if (!Number.isSafeInteger(expectedObject.revision) || expectedObject.revision < 1) deny();

    const wire = exact(r.statement, [...FIELDS, "signature"]);
    const body = canonical(Object.fromEntries(FIELDS.map((field) => [field, wire[field]])));
    const signature = decode(wire.signature, 64);
    const keys = verifyOwnerRotationKeys(r.ownerRotations, r.pinnedOwnerRoot, expectedAccount);
    const verifiedHead = verifyOwnerCutoverHistory(
      r.ownerCutoverHistory, keys, expectedAccount);
    const head = verifiedHead.statement;
    if (verifiedHead.digest !== independentDigest
      || body.immutable_account_id !== expectedAccount
      || body.immutable_account_id !== head.immutable_account_id
      || body.zk_account_id !== head.zk_account_id
      || body.owner_generation !== head.generation
      || body.owner_cutover_digest !== verifiedHead.digest
      || body.inventory_head !== head.inventory_head
      || body.kind !== expectedKind || body.token_digest !== expectedTokenDigest
      || body.object_id !== expectedObject.object_id
      || body.object_revision !== expectedObject.revision
      || body.ciphertext_sha256 !== expectedObject.ciphertext_sha256
      || !crypto.verify(null, signatureBytes(body), keys[keys.length - 1], signature)) deny();
    // Cryptographically prove this exact owner+object+revision+digest is in the
    // current owner-signed inventory root. The root's complete-corpus claim
    // still requires independently verified external issuance/custody.
    verifySparseObjectInventoryProof(expectedAccount, head.generation,
      expectedObject, r.objectMembershipProof, head.inventory_head);
    return Object.freeze({
      status: "VERIFIED_SIGNED_OBJECT_BINDING_NONAUTHORIZING",
      immutableAccountId: expectedAccount,
      ownerGeneration: head.generation,
      ownerCutoverDigest: independentDigest,
      objectId: body.object_id,
      objectRevision: body.object_revision,
      kind: expectedKind,
      signedInventoryMembershipVerified: true,
      // Supplied pins/claimed objects are not independently authenticated here.
      authorizesIo: false,
      independentObjectOwnershipProven: false,
      completeExternalCorpusProven: false,
      independentAnchorCustodyProven: false,
    });
  } catch (_) { deny(); }
}

module.exports = { FIELDS, DOMAIN, TOKEN_DOMAIN, tokenDigest,
  signAnonymousObjectBinding, verifyAnonymousObjectBinding,
  verifySparseObjectInventoryProof, buildSparseObjectInventoryProof };
