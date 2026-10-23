"use strict";

// Opt-in, side-effect-free archive cryptography. This module NEVER admits a
// catalog write, advances CAS/floor, or replaces owner history/recovery checks.
// Trust anchors (the checkpoint key and each historical device signer) are
// independently provided by the caller, not learned from archived bytes.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");

const HEADER_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");
const LEAF_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-archive-leaf/v2\0");
const NODE_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-archive-node/v2\0");
const SIGN_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-sign/v2\0");
const DIGEST_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-checkpoint-digest/v2\0");
const HEADER_TYPE = "rootark-zk1-opaque-catalog/v1";
const CHECKPOINT_TYPE = "rootark-zk1-opaque-catalog-checkpoint/v2";
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const HEADER_FIELDS = ["type", ...SCOPE, "sequence", "previous_digest",
  "manifest_revision", "manifest_digest", "epoch", "signer_device_id",
  "total_count", "page_digests", "issued_at"];
const CHECKPOINT_FIELDS = ["type", ...SCOPE, "previous_sequence", "previous_digest",
  "final_sequence", "final_digest", "previous_checkpoint_digest",
  "archive_root", "record_count", "issued_at"];
const RECORD_FIELDS = ["sequence", "header", "signature", "page_bodies"];
const PAGE_ITEM = ["object_id", "revision", "epoch", "ciphertext_digest",
  "metadata_ciphertext"];
const ZERO = Buffer.alloc(32);
const MAX_ARCHIVE_RECORDS = 128;
const MAX_ARCHIVE_BYTES = 8 * 1024 * 1024;
const MAX_HEADER_BYTES = 16384;
const MAX_PAGE_BYTES = 16384;
const MAX_PAGES = 128;

function fail() {
  const error = new Error("ZK_OPAQUE_CHECKPOINT_V2_UNVERIFIED");
  error.code = "ZK_OPAQUE_CHECKPOINT_V2_UNVERIFIED";
  throw error;
}
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length
    || keys.some((key) => !Object.hasOwn(value, key))) fail();
  return value;
}
function bytes(input, min, max = min) {
  if ((!Buffer.isBuffer(input) && !(input instanceof Uint8Array))
    || input.byteLength < min || input.byteLength > max) fail();
  return Buffer.from(input);
}
function seq(value, min, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail();
  return value;
}
function same(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function hash(domain, ...parts) {
  const h = crypto.createHash("sha256").update(domain);
  for (const part of parts) h.update(part);
  return h.digest();
}
function publicKey(key) {
  if (!(key instanceof crypto.KeyObject) || key.type !== "public"
    || key.asymmetricKeyType !== "ed25519") fail();
  return key;
}
function privateKey(key) {
  if (!(key instanceof crypto.KeyObject) || key.type !== "private"
    || key.asymmetricKeyType !== "ed25519") fail();
  return key;
}
function scopeOf(raw) {
  exact(raw, SCOPE);
  return {
    account_id: bytes(raw.account_id, 16),
    compartment_id: bytes(raw.compartment_id, 1, 128),
    keyring_id: bytes(raw.keyring_id, 16),
  };
}
function matchesScope(raw, scope) {
  for (const field of SCOPE) {
    if (!same(bytes(raw[field], field === "compartment_id" ? 1 : 16,
      field === "compartment_id" ? 128 : 16), scope[field])) fail();
  }
}
function checkpointDigest(checkpointBytes, signature) {
  return hash(DIGEST_DOMAIN, bytes(checkpointBytes, 1, MAX_HEADER_BYTES),
    bytes(signature, 64));
}
async function canonical(raw, max) {
  const buffer = bytes(raw, 1, max);
  const decoded = await z.decodeDeterministic(buffer);
  // The shared deterministic decoder already rejects duplicate map keys,
  // noncanonical integer encodings, indefinite lengths and trailing bytes.
  return decoded;
}
async function inspectRecord(record, scope, expectedSequence, expectedDigest,
  resolveCatalogSigner) {
  exact(record, RECORD_FIELDS);
  if (record.sequence !== expectedSequence) fail();
  const headerBytes = bytes(record.header, 1, MAX_HEADER_BYTES);
  const signature = bytes(record.signature, 64);
  const pageBodies = record.page_bodies;
  if (!Array.isArray(pageBodies) || pageBodies.length > MAX_PAGES) fail();
  const header = await canonical(headerBytes, MAX_HEADER_BYTES);
  exact(header, HEADER_FIELDS);
  if (header.type !== HEADER_TYPE || header.sequence !== expectedSequence) fail();
  matchesScope(header, scope);
  if (!same(bytes(header.previous_digest, 32), expectedDigest)
    || !Array.isArray(header.page_digests)
    || header.page_digests.length !== pageBodies.length
    || header.page_digests.length > MAX_PAGES
    || !Number.isSafeInteger(header.issued_at) || header.issued_at < 0
    || !Number.isSafeInteger(header.manifest_revision) || header.manifest_revision < 1
    || !Number.isSafeInteger(header.epoch) || header.epoch < 1
    || !Number.isSafeInteger(header.total_count)
    || header.total_count < 0 || header.total_count > 4096
    || header.page_digests.length !== Math.ceil(header.total_count / 32)
    || typeof header.signer_device_id !== "string"
    || !header.signer_device_id.length || header.signer_device_id.length > 64
    || /[\u0000-\u001f\u007f]/.test(header.signer_device_id)) fail();
  bytes(header.manifest_digest, 32);
  const catalogKey = publicKey(await resolveCatalogSigner(header));
  if (!crypto.verify(null, Buffer.concat([HEADER_DOMAIN, headerBytes]),
    catalogKey, signature)) fail();
  const normalized = [];
  let priorId = null;
  let priorRevision = 0;
  let count = 0;
  for (let i = 0; i < pageBodies.length; i++) {
    const raw = bytes(pageBodies[i], 1, MAX_PAGE_BYTES);
    if (!same(hash(Buffer.from("Root.ark/zk-1/opaque-catalog-page/v1\0"), raw),
      bytes(header.page_digests[i], 32))) fail();
    const page = await canonical(raw, MAX_PAGE_BYTES);
    if (!Array.isArray(page) || page.length < 1 || page.length > 32
      || (i < pageBodies.length - 1 && page.length !== 32)) fail();
    for (const item of page) {
      exact(item, PAGE_ITEM);
      if (typeof item.object_id !== "string"
        || !/^[A-Za-z0-9_-]{22}$/.test(item.object_id)
        || Buffer.from(item.object_id, "base64url").toString("base64url")
          !== item.object_id) fail();
      const revision = seq(item.revision, 1);
      seq(item.epoch, 1);
      bytes(item.ciphertext_digest, 32);
      bytes(item.metadata_ciphertext, 284);
      if (priorId !== null && (item.object_id < priorId
        || (item.object_id === priorId && revision <= priorRevision))) fail();
      priorId = item.object_id;
      priorRevision = revision;
      count++;
    }
    normalized.push(raw);
  }
  if (count !== header.total_count) fail();
  const digest = hash(HEADER_DOMAIN, headerBytes, signature);
  return {
    record: { sequence: record.sequence, header: headerBytes, signature,
      page_bodies: normalized },
    digest,
  };
}
async function leafDigest(record) {
  return hash(LEAF_DOMAIN, Buffer.from(await z.encodeDeterministic(record)));
}
function merkleParent(left, right) {
  return hash(NODE_DOMAIN, left, right);
}
function merkleLayers(leaves) {
  if (!leaves.length || leaves.length > MAX_ARCHIVE_RECORDS) fail();
  const layers = [leaves];
  while (layers.at(-1).length > 1) {
    const current = layers.at(-1);
    const parents = [];
    for (let i = 0; i < current.length; i += 2) {
      parents.push(merkleParent(current[i], current[i + 1] || current[i]));
    }
    layers.push(parents);
  }
  return layers;
}
function checkRange(previousSequence, previousDigest, previousCheckpointDigest) {
  const previous = seq(previousSequence, 0, Number.MAX_SAFE_INTEGER - 1);
  const digest = bytes(previousDigest, 32);
  const checkpoint = bytes(previousCheckpointDigest, 32);
  if (previous === 0 && (!same(digest, ZERO) || !same(checkpoint, ZERO))) fail();
  if (previous !== 0 && (same(digest, ZERO) || same(checkpoint, ZERO))) fail();
  return { previous, digest, checkpoint };
}
async function inspectArchive({ scope, records, previousSequence,
  previousDigest, previousCheckpointDigest, resolveCatalogSigner }) {
  const scoped = scopeOf(scope);
  if (typeof resolveCatalogSigner !== "function"
    || !Array.isArray(records) || !records.length
    || records.length > MAX_ARCHIVE_RECORDS) fail();
  const prior = checkRange(previousSequence, previousDigest, previousCheckpointDigest);
  if (prior.previous > Number.MAX_SAFE_INTEGER - records.length) fail();
  let currentDigest = prior.digest;
  const normalized = [];
  const leaves = [];
  let totalBytes = 0;
  for (let i = 0; i < records.length; i++) {
    const inspected = await inspectRecord(records[i], scoped,
      prior.previous + i + 1, currentDigest, resolveCatalogSigner);
    totalBytes += inspected.record.header.length + inspected.record.signature.length
      + inspected.record.page_bodies.reduce((sum, body) => sum + body.length, 0);
    if (totalBytes > MAX_ARCHIVE_BYTES) fail();
    normalized.push(inspected.record);
    leaves.push(await leafDigest(inspected.record));
    currentDigest = inspected.digest;
  }
  return { scope: scoped, records: normalized, leaves, previous: prior,
    finalSequence: prior.previous + records.length, finalDigest: currentDigest,
    archiveRoot: merkleLayers(leaves).at(-1)[0] };
}
function checkpointMatches(checkpoint, expected, archive) {
  exact(checkpoint, CHECKPOINT_FIELDS);
  if (checkpoint.type !== CHECKPOINT_TYPE) fail();
  matchesScope(checkpoint, archive.scope);
  if (checkpoint.previous_sequence !== archive.previous.previous
    || checkpoint.final_sequence !== archive.finalSequence
    || checkpoint.record_count !== archive.records.length
    || !same(bytes(checkpoint.previous_digest, 32), archive.previous.digest)
    || !same(bytes(checkpoint.previous_checkpoint_digest, 32), archive.previous.checkpoint)
    || !same(bytes(checkpoint.final_digest, 32), archive.finalDigest)
    || !same(bytes(checkpoint.archive_root, 32), archive.archiveRoot)) fail();
  seq(checkpoint.issued_at, 0);
  if (expected.expectedFinalSequence !== undefined
    && seq(expected.expectedFinalSequence, 1) !== archive.finalSequence) fail();
  if (expected.expectedFinalDigest !== undefined
    && !same(bytes(expected.expectedFinalDigest, 32), archive.finalDigest)) fail();
}
async function createAuthenticatedOpaqueCatalogArchiveV2({
  scope, records, previousSequence, previousDigest, previousCheckpointDigest,
  resolveCatalogSigner, checkpointPrivateKey, issuedAt,
}) {
  const archive = await inspectArchive({ scope, records, previousSequence,
    previousDigest, previousCheckpointDigest, resolveCatalogSigner });
  const checkpoint = { type: CHECKPOINT_TYPE, ...archive.scope,
    previous_sequence: archive.previous.previous, previous_digest: archive.previous.digest,
    final_sequence: archive.finalSequence, final_digest: archive.finalDigest,
    previous_checkpoint_digest: archive.previous.checkpoint,
    archive_root: archive.archiveRoot, record_count: archive.records.length,
    issued_at: seq(issuedAt, 0) };
  const checkpointBytes = Buffer.from(await z.encodeDeterministic(checkpoint));
  if (checkpointBytes.length > MAX_HEADER_BYTES) fail();
  const signature = crypto.sign(null, Buffer.concat([SIGN_DOMAIN, checkpointBytes]),
    privateKey(checkpointPrivateKey));
  return { checkpointBytes, checkpointSignature: signature,
    checkpointDigest: checkpointDigest(checkpointBytes, signature),
    records: archive.records };
}
async function verifyAuthenticatedOpaqueCatalogArchiveV2({
  checkpointBytes, checkpointSignature, pinnedCheckpointPublicKey,
  scope, records, previousSequence, previousDigest, previousCheckpointDigest,
  resolveCatalogSigner, expectedFinalSequence, expectedFinalDigest,
}) {
  const raw = bytes(checkpointBytes, 1, MAX_HEADER_BYTES);
  const signature = bytes(checkpointSignature, 64);
  if (!crypto.verify(null, Buffer.concat([SIGN_DOMAIN, raw]),
    publicKey(pinnedCheckpointPublicKey), signature)) fail();
  const checkpoint = await canonical(raw, MAX_HEADER_BYTES);
  const archive = await inspectArchive({ scope, records, previousSequence,
    previousDigest, previousCheckpointDigest, resolveCatalogSigner });
  checkpointMatches(checkpoint, { expectedFinalSequence, expectedFinalDigest }, archive);
  return { previousSequence: archive.previous.previous,
    finalSequence: archive.finalSequence, finalDigest: archive.finalDigest,
    archiveRoot: archive.archiveRoot, checkpointDigest: checkpointDigest(raw, signature) };
}
async function createOpaqueCatalogInclusionProofV2({ records, index }) {
  if (!Array.isArray(records) || !records.length
    || records.length > MAX_ARCHIVE_RECORDS) fail();
  seq(index, 0, records.length - 1);
  let totalBytes = 0;
  const leaves = [];
  for (const record of records) {
    exact(record, RECORD_FIELDS);
    const header = bytes(record.header, 1, MAX_HEADER_BYTES);
    const signature = bytes(record.signature, 64);
    if (!Array.isArray(record.page_bodies) || record.page_bodies.length > MAX_PAGES) fail();
    const pageBodies = record.page_bodies.map((body) => bytes(body, 1, MAX_PAGE_BYTES));
    totalBytes += header.length + signature.length
      + pageBodies.reduce((n, part) => n + part.length, 0);
    if (totalBytes > MAX_ARCHIVE_BYTES) fail();
    leaves.push(await leafDigest({ sequence: seq(record.sequence, 1), header,
      signature, page_bodies: pageBodies }));
  }
  const layers = merkleLayers(leaves);
  const siblings = [];
  let position = index;
  for (let level = 0; level < layers.length - 1; level++) {
    const nodes = layers[level];
    siblings.push(Buffer.from(nodes[position ^ 1] || nodes[position]));
    position = Math.floor(position / 2);
  }
  return { index, count: records.length, siblings };
}
async function verifyAuthenticatedOpaqueCatalogInclusionV2({
  checkpointBytes, checkpointSignature, pinnedCheckpointPublicKey,
  scope, record, proof, expectedPreviousSequence, expectedPreviousDigest,
  expectedPreviousCheckpointDigest, resolveCatalogSigner,
}) {
  const raw = bytes(checkpointBytes, 1, MAX_HEADER_BYTES);
  const signature = bytes(checkpointSignature, 64);
  if (!crypto.verify(null, Buffer.concat([SIGN_DOMAIN, raw]),
    publicKey(pinnedCheckpointPublicKey), signature)) fail();
  const checkpoint = await canonical(raw, MAX_HEADER_BYTES);
  exact(checkpoint, CHECKPOINT_FIELDS);
  const scoped = scopeOf(scope);
  matchesScope(checkpoint, scoped);
  if (checkpoint.type !== CHECKPOINT_TYPE) fail();
  const prior = checkRange(expectedPreviousSequence,
    expectedPreviousDigest, expectedPreviousCheckpointDigest);
  if (checkpoint.previous_sequence !== prior.previous
    || !same(bytes(checkpoint.previous_digest, 32), prior.digest)
    || !same(bytes(checkpoint.previous_checkpoint_digest, 32), prior.checkpoint)) fail();
  exact(proof, ["index", "count", "siblings"]);
  const count = seq(proof.count, 1, MAX_ARCHIVE_RECORDS);
  const index = seq(proof.index, 0, count - 1);
  if (!Array.isArray(proof.siblings) || checkpoint.record_count !== count
    || checkpoint.final_sequence !== prior.previous + count
    || checkpoint.final_sequence > Number.MAX_SAFE_INTEGER) fail();
  let width = count;
  let depth = 0;
  while (width > 1) { width = Math.ceil(width / 2); depth++; }
  if (proof.siblings.length !== depth) fail();
  // A proof authenticates one immutable leaf; full continuity across *every*
  // archived head is established only by verifyAuthenticated...ArchiveV2.
  const historicalSequence = prior.previous + index + 1;
  const header = await canonical(bytes(record.header, 1, MAX_HEADER_BYTES),
    MAX_HEADER_BYTES);
  exact(header, HEADER_FIELDS);
  const predecessor = bytes(header.previous_digest, 32);
  if (index === 0 && !same(predecessor, prior.digest)) fail();
  const inspected = await inspectRecord(record, scoped,
    historicalSequence, predecessor, resolveCatalogSigner);
  if (index === count - 1 && !same(inspected.digest,
    bytes(checkpoint.final_digest, 32))) fail();
  let computed = await leafDigest(inspected.record);
  let position = index;
  width = count;
  for (const rawSibling of proof.siblings) {
    const sibling = bytes(rawSibling, 32);
    if ((position ^ 1) >= width && !same(sibling, computed)) fail();
    computed = position % 2 === 0
      ? merkleParent(computed, sibling) : merkleParent(sibling, computed);
    position = Math.floor(position / 2);
    width = Math.ceil(width / 2);
  }
  if (!same(computed, bytes(checkpoint.archive_root, 32))) fail();
  seq(checkpoint.issued_at, 0);
  return { sequence: historicalSequence, digest: inspected.digest,
    archiveRoot: computed, checkpointDigest: checkpointDigest(raw, signature) };
}

module.exports = {
  MAX_ARCHIVE_RECORDS, MAX_ARCHIVE_BYTES,
  createAuthenticatedOpaqueCatalogArchiveV2,
  verifyAuthenticatedOpaqueCatalogArchiveV2,
  createOpaqueCatalogInclusionProofV2,
  verifyAuthenticatedOpaqueCatalogInclusionV2,
};
