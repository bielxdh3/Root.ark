"use strict";

// DEV / offline verifier. This module handles ciphertext only. A signed
// catalog proves completeness relative to that externally pinned checkpoint,
// never the completeness of arbitrary server/account storage or live custody.
const crypto = require("node:crypto");
const z = require("../../src/crypto/rootark-zk-1");
const inventory = require("../../src/crypto/rootark-zk-content-inventory-v1");
const floor = require("./rootark-zk1-normal-browser-trust-floor");
const ownerHistory = require("./rootark-zk1-owner-signed-checkpoint");
const ownerInventory = require("./rootark-zk1-owner-inventory-trust-head");
const ownerRoots = require("./rootark-zk1-owner-ciphertext-root-checkpoint");
const ciphertextRoots = require("./rootark-zk1-ciphertext-chunk-root");

const FORMAT = "rootark-zk1-authoritative-backup-inventory/v1";
const DOMAIN = Buffer.from("Root.ark/zk-1/authoritative-backup-inventory/v1\0");
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const META = ["objectId", "revision", "epoch", "ciphertextBase64", "ciphertextSha256",
  "ciphertextRoot", "ownerRootCheckpoint"];
const SIGNED = ["format", "scope", "ownerRevision", "ownerDigest", "ownerEpoch",
  "inventorySequence", "inventoryRoot", "inventoryCheckpointDigest", "issuedAt", "items"];
const OUTER = [...SIGNED, "signature"];
const ROOT_WIRE = ["schema", ...SCOPE, "device_id", "signer_key_id",
  "manifest_revision", "manifest_digest", "manifest_epoch", "object_id",
  "object_revision", "ciphertext_epoch", "ciphertext_root", "issued_at", "signature"];
const HISTORY_WIRE = ["schema", ...SCOPE, "device_id", "signer_key_id",
  "revision", "manifest_digest", "sequence", "previous_checkpoint_digest",
  "issued_at", "signature"];
const GRANT_WIRE = ["schema", ...SCOPE, "device_id", "authorization_key_id",
  "authorization_public_key", "manifest_revision", "manifest_digest",
  "current_epoch", "enrolled_epoch", "revoked_at_epoch", "signature"];
const MAX_ITEMS = 64;
const MAX_BYTES = 8 * 1024 * 1024;
const B64 = /^[A-Za-z0-9_-]+$/;
const HEX = /^[0-9a-f]{64}$/;
const verifiedBackupProofs = new WeakMap();
function deny() { throw new Error("ZK_AUTHORITATIVE_BACKUP_DENIED"); }
function exact(input, fields) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
    || Reflect.ownKeys(input).length !== fields.length) deny();
  const result = {};
  for (const field of fields) {
    const slot = Object.getOwnPropertyDescriptor(input, field);
    if (!slot || !Object.hasOwn(slot, "value")) deny();
    result[field] = slot.value;
  }
  return result;
}
function boundedArray(input, limit) {
  if (!Array.isArray(input) || input.length > limit
    || Reflect.ownKeys(input).length !== input.length + 1) deny();
  const output = [];
  for (let i = 0; i < input.length; i++) {
    const slot = Object.getOwnPropertyDescriptor(input, String(i));
    if (!slot || !Object.hasOwn(slot, "value")) deny();
    output.push(slot.value);
  }
  return output;
}
function bytes(raw, length, max = length) {
  if (!(raw instanceof Uint8Array) && !(raw instanceof ArrayBuffer)
    || raw.byteLength < length || raw.byteLength > max
    || (typeof SharedArrayBuffer !== "undefined" && raw.buffer instanceof SharedArrayBuffer)) deny();
  return Buffer.from(raw instanceof ArrayBuffer ? new Uint8Array(raw) : raw);
}
function decode(raw, count, max = count) {
  if (typeof raw !== "string" || !B64.test(raw)
    || raw.length > Math.ceil(max * 4 / 3) + 4) deny();
  const result = Buffer.from(raw, "base64url");
  if (result.length < count || result.length > max || result.toString("base64url") !== raw) deny();
  return result;
}
function uint(raw, min = 1) {
  if (!Number.isSafeInteger(raw) || raw < min) deny();
  return raw;
}
function scopeCopy(raw) {
  const result = exact(raw, SCOPE);
  decode(result.account_id, 16);
  decode(result.compartment_id, 1, 128);
  decode(result.keyring_id, 16);
  return result;
}
function hex(raw) { if (typeof raw !== "string" || !HEX.test(raw)) deny(); return raw; }
function digest(raw) { return crypto.createHash("sha256").update(raw).digest(); }
function same(a, b) { return a.length === b.length && crypto.timingSafeEqual(a, b); }
function publicKey(value) {
  if (value?.type !== "public" || value.algorithm?.name !== "Ed25519"
    || !value.usages?.includes("verify")) deny();
  return value;
}
function signerKey(value) {
  if (value?.type !== "private" || value.extractable !== false
    || value.algorithm?.name !== "Ed25519" || !value.usages?.includes("sign")) deny();
  return value;
}
function nodePublicKey(value) {
  if (!(value instanceof crypto.KeyObject) || value.type !== "public"
    || value.asymmetricKeyType !== "ed25519") deny();
  return value;
}
function signingBytes(body) {
  const unsigned = exact(body, SIGNED);
  const packed = Buffer.from(JSON.stringify(unsigned));
  if (packed.byteLength > MAX_BYTES * 2) deny();
  return Buffer.concat([DOMAIN, packed]);
}
function normalizeItem(raw) {
  const entry = exact(raw, META);
  decode(entry.objectId, 16);
  uint(entry.revision); uint(entry.epoch);
  decode(entry.ciphertextSha256, 32);
  decode(entry.ciphertextRoot, 32);
  if (typeof entry.ciphertextBase64 !== "string") deny();
  entry.ownerRootCheckpoint = exact(entry.ownerRootCheckpoint, ROOT_WIRE);
  return entry;
}
function material(raw) {
  const input = exact(raw, ["objectId", "revision", "epoch", "ciphertext", "ownerRootCheckpoint"]);
  decode(input.objectId, 16);
  uint(input.revision); uint(input.epoch);
  if (!(input.ciphertext instanceof Uint8Array) || input.ciphertext.length < 16
    || input.ciphertext.length > 4 * 1024 * 1024) deny();
  return { ...input, ownerRootCheckpoint: exact(input.ownerRootCheckpoint, ROOT_WIRE),
    ciphertext: bytes(input.ciphertext, 16, 4 * 1024 * 1024) };
}

async function verifyAuthority(raw) {
  // Copy mutable scope, head, grants, signed history and receipt arrays before
  // the first asynchronous crypto verification so caller mutations cannot
  // redirect the selected inventory halfway through a ceremony.
  const sc = scopeCopy(raw.scope);
  const owner = publicKey(raw.ownerPublicKey);
  const ownerPin = bytes(raw.independentOwnerSpkiSha256, 32);
  const head = exact(raw.pinnedCurrentHead, ["revision", "digest", "epoch"]);
  uint(head.revision); uint(head.epoch);
  head.digest = bytes(head.digest, 32);
  const signerId = bytes(raw.inventorySignerKeyId, 16);
  const signerPublic = nodePublicKey(raw.inventorySignerPublicKey);
  const signerPin = hex(raw.independentlyPinnedInventorySignerSpkiSha256);
  const rootSigner = bytes(raw.ownerSignerKeyId, 16);
  const chain = boundedArray(raw.ownerHistoryChain, 64).map((record) =>
    exact(record, HISTORY_WIRE));
  const grant = exact(raw.signedDeviceGrant, GRANT_WIRE);
  const portableWire = raw.ownerInventoryPortable;
  const checkpointPin = hex(raw.independentlyPinnedInventoryCheckpointDigest);
  const nowSeconds = uint(raw.nowSeconds);
  const genesis = bytes(raw.genesisSnapshot, 1, inventory.MAX_SNAPSHOT_BYTES);
  const receipts = inventory.normalizeCommittedProofChain(raw.committedProofChain);
  const spki = await crypto.webcrypto.subtle.exportKey("spki", owner);
  if (!same(digest(Buffer.from(spki)), ownerPin)) deny();
  if (digest(signerPublic.export({ type: "spki", format: "der" })).toString("hex") !== signerPin) deny();
  if (!chain.length || chain.length > 64) deny();
  let proof = null;
  let previous = null;
  for (const record of chain) {
    previous = proof;
    proof = await ownerHistory.verifyOwnerCheckpoint({ checkpoint: record, scope: sc,
      signerPublicKey: owner, signerKeyId: rootSigner, previous: proof });
  }
  if (proof.revision !== head.revision || proof.manifestDigest !== head.digest.toString("base64url")) deny();
  const currentCheckpoint = chain.at(-1);
  if (currentCheckpoint.device_id !== raw.deviceId) deny();
  await floor.verifyExternalAnchor({ ownerPublicKey: owner, independentOwnerSpkiSha256: ownerPin,
    pinnedCurrentHead: head, signedDeviceGrant: grant,
    ownerHistoryCheckpoint: currentCheckpoint, previousOwnerHistoryProof: previous });
  if (SCOPE.some((field) => grant[field] !== sc[field])
    || grant.device_id !== raw.deviceId) deny();
  if (typeof portableWire !== "string" || portableWire.length > 400000) deny();
  const admitted = await ownerInventory.importPortableEnrollment({
    serialized: portableWire,
    independentOwnerSpkiSha256: ownerPin.toString("hex"),
    independentCheckpointDigest: checkpointPin,
    expectedScope: SCOPE.map((field) => sc[field]),
    expectedInventorySpkiSha256: signerPin,
    nowSeconds,
  });
  if (admitted.ownerSignatureVerified !== true || admitted.independentlyPinnedDigestMatched !== true) deny();
  const portable = JSON.parse(portableWire);
  if (portable.checkpoints.at(-1)?.inventory_signer_key_id !== signerId.toString("base64url")) deny();
  const selected = decode(portable.minimum_snapshot, 1, inventory.MAX_SNAPSHOT_BYTES);
  const selectedDecoded = await z.decodeDeterministic(selected);
  const genesisDecoded = await z.decodeDeterministic(genesis);
  const genesisRoot = bytes(genesisDecoded.root, 32);
  if (genesisDecoded.sequence !== 0 || genesisDecoded.previous_root !== null) deny();
  const scopeBytes = Object.fromEntries(SCOPE.map((field) => [field, decode(sc[field],
    field === "compartment_id" ? 1 : 16, field === "compartment_id" ? 128 : 16)]));
  const requested = { object_id: Buffer.alloc(16), revision: 1,
    epoch: 1, ciphertext_sha256: Buffer.alloc(32) };
  await inventory.verifySnapshot({ serialized: genesis, pinnedPublicKey: signerPublic,
    pinnedSignerKeyId: signerId, expectedScope: scopeBytes, requested,
    minimumHead: { sequence: 0, root: genesisRoot }, nonce: bytes(genesisDecoded.nonce, 32) });
  const signedEntries = inventory.normalizeEntries(selectedDecoded.entries);
  const selectedRequest = signedEntries[0] || requested;
  if (receipts.length !== signedEntries.length || signedEntries.length > MAX_ITEMS) deny();
  const verified = await inventory.verifySnapshot({
    serialized: selected, pinnedPublicKey: signerPublic, pinnedSignerKeyId: signerId,
    expectedScope: scopeBytes, requested: selectedRequest,
    minimumHead: { sequence: 0, root: genesisRoot }, nonce: bytes(selectedDecoded.nonce, 32),
    minimumSnapshot: genesis, committedProofChain: receipts,
  });
  if (verified.sequence !== admitted.inventorySequence
    || verified.root.toString("hex") !== admitted.inventoryRoot
    || signedEntries.length !== admitted.inventorySequence
    || verified.verifiedInterveningReceipts !== signedEntries.length
    || (signedEntries.length && verified.outcome !== "PRESENT")) deny();
  return { sc, owner, ownerSpkiSha256: ownerPin.toString("hex"), head, proof,
    previous, currentCheckpoint, rootSigner, entries: signedEntries,
    sequence: admitted.inventorySequence, inventoryRoot: admitted.inventoryRoot,
    checkpointDigest: checkpointPin };
}

async function verifyItems(items, authority) {
  const raw = boundedArray(items, MAX_ITEMS).map(normalizeItem);
  if (raw.length !== authority.entries.length) deny();
  let total = 0;
  for (let i = 0; i < raw.length; i++) {
    const row = raw[i], signed = authority.entries[i];
    const payload = decode(row.ciphertextBase64, 16, 4 * 1024 * 1024);
    try {
      total += payload.length;
      if (total > MAX_BYTES
        || row.objectId !== signed.object_id.toString("base64url")
        || row.revision !== signed.revision || row.epoch !== signed.epoch
        || !same(digest(payload), signed.ciphertext_sha256)
        || row.ciphertextSha256 !== signed.ciphertext_sha256.toString("base64url")) deny();
      const root = bytes(await ciphertextRoots.computeCiphertextRoot([payload]), 32);
      if (root.toString("base64url") !== row.ciphertextRoot) deny();
      const verified = await ownerRoots.verifyOwnerCiphertextRootCheckpoint({
        checkpoint: row.ownerRootCheckpoint,
        ownerHistoryCheckpoint: authority.currentCheckpoint,
        previousHistoryProof: authority.previous,
        pinnedOwner: { scope: authority.sc, deviceId: authority.currentCheckpoint.device_id,
          signerKeyId: authority.rootSigner, publicKey: authority.owner },
        expected: { manifestRevision: authority.head.revision,
          manifestDigest: authority.head.digest, manifestEpoch: authority.head.epoch,
          objectId: row.objectId, objectRevision: row.revision,
          ciphertextEpoch: row.epoch, ciphertextRoot: root },
      });
      if (verified.trustedOwnerSignatureVerified !== true || verified.manifestCheckpointVerified !== true) deny();
    } finally { payload.fill(0); }
  }
  return raw;
}
function body(authority, items, issuedAt) {
  return { format: FORMAT, scope: authority.sc, ownerRevision: authority.head.revision,
    ownerDigest: authority.head.digest.toString("base64url"),
    ownerEpoch: authority.head.epoch, inventorySequence: authority.sequence,
    inventoryRoot: authority.inventoryRoot,
    inventoryCheckpointDigest: authority.checkpointDigest, issuedAt: uint(issuedAt), items };
}
async function createVerifiedSnapshot(input) {
  let copied = [];
  try {
    const raw = exact(input, ["scope", "ownerPublicKey", "ownerSigningKey",
      "independentOwnerSpkiSha256", "pinnedCurrentHead", "signedDeviceGrant",
      "ownerHistoryChain", "ownerSignerKeyId", "deviceId", "ownerInventoryPortable",
      "independentlyPinnedInventoryCheckpointDigest", "independentlyPinnedInventorySignerSpkiSha256",
      "inventorySignerPublicKey", "inventorySignerKeyId", "genesisSnapshot",
      "committedProofChain", "items", "issuedAt", "nowSeconds"]);
    const files = boundedArray(raw.items, MAX_ITEMS);
    let total = 0;
    for (const file of files) {
      const next = material(file);
      copied.push(next);
      total += next.ciphertext.byteLength;
      if (total > MAX_BYTES) deny();
    }
    total = 0;
    const rows = copied.map((item) => {
      total += item.ciphertext.byteLength;
      if (total > MAX_BYTES) deny();
      return Object.freeze({ objectId: item.objectId, revision: item.revision, epoch: item.epoch,
        ciphertextBase64: item.ciphertext.toString("base64url"),
        ciphertextSha256: digest(item.ciphertext).toString("base64url"),
        // The root is independently recomputed and owner-verified below.
        ciphertextRoot: item.ownerRootCheckpoint?.ciphertext_root,
        ownerRootCheckpoint: Object.freeze(item.ownerRootCheckpoint) });
    });
    const authority = await verifyAuthority(raw);
    await verifyItems(rows, authority);
    const unsigned = body(authority, Object.freeze(rows), raw.issuedAt);
    const signingKey = signerKey(raw.ownerSigningKey);
    const signature = Buffer.from(await crypto.webcrypto.subtle.sign("Ed25519",
      signingKey, signingBytes(unsigned)));
    if (!await crypto.webcrypto.subtle.verify("Ed25519", authority.owner, signature,
      signingBytes(unsigned))) deny();
    const result = Object.freeze({ ...unsigned, signature: signature.toString("base64url") });
    return Object.freeze({ snapshot: result, snapshotSha256: digest(Buffer.from(JSON.stringify(result))),
      completeRelativeToOwnerCheckpoint: true, globalAccountCompletenessProven: false,
      independentRemoteCustodyProven: false, versionAwareCekArchiveCompleted: false,
      authorizesProductionRestore: false });
  } catch (_) { deny(); }
  finally { for (const file of copied) file.ciphertext.fill(0); }
}
async function verifyBackupSnapshot(input) {
  try {
    const raw = exact(input, ["snapshot", "ownerPublicKey", "independentOwnerSpkiSha256",
      "independentlyPinnedBackupSha256", "pinnedCurrentHead", "scope", "ownerInventoryPortable",
      "independentlyPinnedInventoryCheckpointDigest", "independentlyPinnedInventorySignerSpkiSha256",
      "inventorySignerPublicKey", "inventorySignerKeyId", "genesisSnapshot",
      "committedProofChain", "ownerHistoryChain", "signedDeviceGrant", "ownerSignerKeyId",
      "deviceId", "nowSeconds"]);
    const wire = exact(raw.snapshot, OUTER);
    const serialized = JSON.stringify(wire);
    if (typeof serialized !== "string" || serialized.length > MAX_BYTES * 2) deny();
    const stableWire = exact(JSON.parse(serialized), OUTER);
    const expectedHash = bytes(raw.independentlyPinnedBackupSha256, 32);
    if (!same(digest(Buffer.from(serialized)), expectedHash)) deny();
    const authority = await verifyAuthority(raw);
    if (stableWire.format !== FORMAT
      || JSON.stringify(stableWire.scope) !== JSON.stringify(authority.sc)
      || stableWire.ownerRevision !== authority.head.revision
      || stableWire.ownerDigest !== authority.head.digest.toString("base64url")
      || stableWire.ownerEpoch !== authority.head.epoch
      || stableWire.inventorySequence !== authority.sequence
      || stableWire.inventoryRoot !== authority.inventoryRoot
      || stableWire.inventoryCheckpointDigest !== authority.checkpointDigest) deny();
    uint(stableWire.issuedAt);
    if (!await crypto.webcrypto.subtle.verify("Ed25519", authority.owner,
      decode(stableWire.signature, 64),
      signingBytes(Object.fromEntries(SIGNED.map((k) => [k, stableWire[k]]))))) deny();
    await verifyItems(stableWire.items, authority);
    const result = Object.freeze({ completeRelativeToOwnerCheckpoint: true,
      globalAccountCompletenessProven: false, authorizesProductionRestore: false,
      inventorySequence: authority.sequence });
    verifiedBackupProofs.set(result, Object.freeze({
      scope: Object.freeze({ ...authority.sc }),
      ownerSpkiSha256: authority.ownerSpkiSha256,
      snapshotSha256: expectedHash.toString("base64url"),
      inventoryCheckpointDigest: authority.checkpointDigest,
      inventoryRoot: authority.inventoryRoot,
      inventorySequence: authority.sequence,
    }));
    return result;
  } catch (_) { deny(); }
}
function readVerifiedBackupProof(proof) {
  const held = proof && verifiedBackupProofs.get(proof);
  if (!held) deny();
  return held;
}
module.exports = Object.freeze({ createVerifiedSnapshot, verifyBackupSnapshot,
  readVerifiedBackupProof });
