"use strict";

// DEV-OFF: an owner-selected, signed and indivisible set of historical file CEKs.
// This does NOT establish that the set contains every object/version in an
// account. A complete externally retained owner inventory is still required.
const crypto = require("node:crypto");
const { types: nativeTypes } = require("node:util");
const z = require("./rootark-zk-1");
const transfer = require("./rootark-zk1-owner-authorized-file-cek-transfer");
// Session fencing invokes an independently supplied callback after real
// HPKE. Keep cleanup independent of callback-mutated JS array prototypes.
const nativeApply = Reflect.apply;
const nativeArrayIsArray = Array.isArray;
const nativeGetPrototypeOf = Object.getPrototypeOf;
const nativeOwnKeys = Reflect.ownKeys;
const nativeHasOwn = Object.hasOwn;
const nativeObjectPrototype = Object.prototype;
const nativeBufferFrom = Buffer.from.bind(Buffer);
const nativeBufferAlloc = Buffer.alloc.bind(Buffer);
const nativeBufferConcat = Buffer.concat.bind(Buffer);
const nativeBufferToString = Buffer.prototype.toString;
const nativeJsonStringify = JSON.stringify;
const nativeArraySort = Array.prototype.sort;
const nativeArrayPush = Array.prototype.push;
const nativeVerify = crypto.verify.bind(crypto);
const nativeSign = crypto.sign.bind(crypto);
const nativeCreatePublicKey = crypto.createPublicKey.bind(crypto);
const nativeTimingSafeEqual = crypto.timingSafeEqual.bind(crypto);
const nativeSubtle = crypto.webcrypto.subtle;
const nativeExportKey = nativeSubtle.exportKey;
const nativeTypedFill = Uint8Array.prototype.fill;
const nativeTypedSet = Uint8Array.prototype.set;
const NativeUint8Array = Uint8Array;
const nativeTypedProto = Object.getPrototypeOf(Uint8Array.prototype);
const nativeTypedByteLength = Object.getOwnPropertyDescriptor(nativeTypedProto, "byteLength").get;
const nativeArrayBufferByteLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;
const nativeIsArrayBuffer = nativeTypes.isArrayBuffer;
const nativeIsUint8Array = nativeTypes.isUint8Array;
const nativeIsProxy = nativeTypes.isProxy;
const nativeIsCryptoKey = nativeTypes.isCryptoKey;
const nativeIsKeyObject = nativeTypes.isKeyObject;
const nativeHpkeSuite = z.hpkeSuite.bind(z);
const nativeKemDeserializePrivateKey = nativeHpkeSuite().kem.deserializePrivateKey;
const nativeTransferSeal = transfer.sealOwnerAuthorizedFileCek.bind(transfer);
const nativeTransferOpen = transfer.openOwnerAuthorizedFileCek.bind(transfer);
function copyPrivateSeed(bytes) {
  if (nativeIsProxy(bytes)) deny();
  let view;
  if (nativeIsUint8Array(bytes)) {
    if (nativeApply(nativeTypedByteLength, bytes, []) !== 32) deny();
    view = bytes;
  } else if (nativeIsArrayBuffer(bytes)) {
    if (nativeApply(nativeArrayBufferByteLength, bytes, []) !== 32) deny();
    view = new NativeUint8Array(bytes);
  } else deny();
  // Never call a mutable Buffer.from with the X25519 private key after the
  // caller's assertLive() callback has executed.
  const owned = nativeBufferAlloc(32);
  nativeApply(nativeTypedSet, owned, [view]);
  return owned;
}
function scrub(bytes) {
  if (bytes == null) return;
  if (nativeIsProxy(bytes)) deny();
  const view = nativeIsArrayBuffer(bytes) ? new NativeUint8Array(bytes) : bytes;
  if (!nativeIsUint8Array(view)) deny();
  nativeApply(nativeTypedFill, view, [0]);
}

const DOMAIN = nativeBufferFrom("Root.ark/zk-1/owner-versioned-cek-batch/v1\0");
const SCHEMA = "rootark-zk1-owner-versioned-cek-batch/v1";
const VERSION_KEYS = ["metadata", "objectRevision", "ciphertext", "ciphertextRoot", "ownerHeldCek"];
const ENTRY_KEYS = ["metadata", "objectRevision", "ciphertext", "ciphertextRoot", "envelope"];
const META_KEYS = ["account_id", "compartment_id", "keyring_id", "object_id",
  "version_id", "parent_version_id", "epoch", "kind"];
const MANIFEST_KEYS = ["schema", "owner_digest", "owner_revision", "witness_sequence",
  "entry_count", "entries"];
const BUNDLE_KEYS = ["schema", "manifest", "entries", "owner_signature",
  "signedBatchCompletenessVerified", "globalAccountCompletenessProven",
  "authorizesProductionRestore"];
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("base64url");
function deny() { throw Error("ZK_OWNER_VERSIONED_CEK_BATCH_DENIED"); }
function exact(obj, fields) {
  if (!obj || nativeIsProxy(obj) || typeof obj !== "object" || nativeArrayIsArray(obj)) deny();
  const proto = nativeGetPrototypeOf(obj);
  if (proto !== nativeObjectPrototype && proto !== null
    || nativeOwnKeys(obj).length !== fields.length) deny();
  for (let i = 0; i < fields.length; i++) if (!nativeHasOwn(obj, fields[i])) deny();
  return obj;
}
function str(value, limit = 512) {
  if (typeof value !== "string" || !value.length || value.length > limit) deny();
  return value;
}
function positive(value) {
  if (!Number.isSafeInteger(value) || value < 1) deny();
  return value;
}
function b64(value, length) {
  str(value, length === undefined ? 6 * 1024 * 1024 : Math.ceil(length * 4 / 3) + 4);
  if (!/^[A-Za-z0-9_-]+$/.test(value)) deny();
  const bytes = nativeBufferFrom(value, "base64url");
  if ((length !== undefined && bytes.length !== length)
    || bytes.toString("base64url") !== value) deny();
  return bytes;
}
// Snapshot caller-controlled material BEFORE any async signature, AEAD or HPKE
// operation. Never run attacker-controlled getters or reuse mutable buffers.
function snapshot(value, meter = { count: 0, bytes: 0 }, depth = 0) {
  if (++meter.count > 4096 || depth > 20) deny();
  if (value === null || typeof value === "boolean"
    || typeof value === "number" || typeof value === "string") {
    if (typeof value === "string" && value.length > 22 * 1024 * 1024) deny();
    return value;
  }
  if (nativeIsUint8Array(value)) {
    const size = nativeApply(nativeTypedByteLength, value, []);
    meter.bytes += size;
    if (size > 4 * 1024 * 1024 || meter.bytes > 32 * 1024 * 1024) deny();
    const owned = nativeBufferAlloc(size);
    nativeApply(nativeTypedSet, owned, [value]);
    return owned;
  }
  if (value instanceof ArrayBuffer) {
    meter.bytes += value.byteLength;
    if (value.byteLength > 4 * 1024 * 1024 || meter.bytes > 32 * 1024 * 1024) deny();
    return value.slice(0);
  }
  if (nativeIsKeyObject(value) || nativeIsCryptoKey(value)) return value;
  if (!value || typeof value !== "object") deny();
  const isArray = Array.isArray(value);
  if (!isArray && ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny();
  const desc = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(desc);
  if (isArray) {
    if (value.length > 32 || keys.length !== value.length + 1) deny();
    const out = [];
    for (let i = 0; i < value.length; i++) {
      if (!desc[i] || !Object.hasOwn(desc[i], "value")) deny();
      out.push(snapshot(desc[i].value, meter, depth + 1));
    }
    return Object.freeze(out);
  }
  const out = Object.create(null);
  for (const key of keys) {
    if (typeof key !== "string" || !Object.hasOwn(desc[key], "value")) deny();
    Object.defineProperty(out, key, { enumerable: true,
      value: snapshot(desc[key].value, meter, depth + 1) });
  }
  return Object.freeze(out);
}
function snapshotWithSessionFence(input, fields) {
  exact(input, [...fields, "assertLive"]);
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (!Object.hasOwn(descriptors.assertLive, "value")
    || typeof descriptors.assertLive.value !== "function") deny();
  const callback = descriptors.assertLive.value;
  // Only values captured from data descriptors may enter the immutable
  // crypto snapshot. An accessor must never execute as a side effect.
  const stable = snapshot(Object.fromEntries(fields.map(
    (name) => [name, descriptors[name].value])));
  return { stable, assertLive: () => {
    if (callback() !== undefined) deny();
  } };
}
function normalizedMetadata(meta) {
  exact(meta, META_KEYS);
  for (const key of ["account_id", "keyring_id", "object_id", "version_id"])
    b64(meta[key], 16);
  str(meta.compartment_id, 192);
  b64(meta.compartment_id);
  if (meta.parent_version_id !== null) b64(meta.parent_version_id, 16);
  if (meta.kind !== "file") deny();
  positive(meta.epoch);
  return Object.fromEntries(META_KEYS.map((key) => [key, meta[key]]));
}
function verifyVersionChain(entries) {
  if (!nativeArrayIsArray(entries) || entries.length === 0 || entries.length > 32) deny();
  const groups = new Map();
  const versionIds = new Set();
  let fixedScope;
  for (let entryIndex = 0; entryIndex < entries.length; entryIndex++) {
    const entry = entries[entryIndex];
    const meta = normalizedMetadata(entry.metadata);
    positive(entry.objectRevision);
    // A signed per-file version UUID must never alias another object/version.
    if (versionIds.has(meta.version_id)) deny();
    versionIds.add(meta.version_id);
    const scope = JSON.stringify([meta.account_id, meta.compartment_id, meta.keyring_id]);
    if (fixedScope && fixedScope !== scope) deny();
    fixedScope = scope;
    if (!groups.has(meta.object_id)) groups.set(meta.object_id, []);
    groups.get(meta.object_id).push({ revision: entry.objectRevision,
      versionId: meta.version_id, parent: meta.parent_version_id, epoch: meta.epoch });
  }
  for (const versions of groups.values()) {
    nativeApply(nativeArraySort, versions, [(a, b) => a.revision - b.revision]);
    for (let i = 0; i < versions.length; i++) {
      if (versions[i].revision !== i + 1
        || versions[i].parent !== (i === 0 ? null : versions[i - 1].versionId)
        || (i > 0 && versions[i].epoch < versions[i - 1].epoch)) deny();
    }
  }
  const sorted = new Array(entries.length);
  for (let index = 0; index < entries.length; index++) sorted[index] = entries[index];
  return nativeApply(nativeArraySort, sorted, [(a, b) => {
    const left = a.metadata.object_id, right = b.metadata.object_id;
    // Canonical base64url UUIDs are ASCII; avoid OS/ICU locale-dependent order.
    return (left < right ? -1 : left > right ? 1 : 0)
      || a.objectRevision - b.objectRevision;
  }]);
}
function entryRecord(entry) {
  exact(entry, ENTRY_KEYS);
  const meta = normalizedMetadata(entry.metadata);
  positive(entry.objectRevision);
  const ciphertext = b64(entry.ciphertext);
  if (ciphertext.length > 4 * 1024 * 1024) deny();
  const root = b64(entry.ciphertextRoot, 32);
  const envelope = entry.envelope;
  if (!envelope || typeof envelope !== "object") deny();
  return { metadata: meta, objectRevision: entry.objectRevision,
    ciphertext: entry.ciphertext, ciphertextRoot: root.toString("base64url"),
    envelope };
}
function makeManifest(entries) {
  const records = entries.map(entryRecord);
  const first = records[0].envelope.core;
  if (!first) deny();
  const ownerDigest = str(first.owner_digest), ownerRevision = positive(first.owner_revision);
  const witnessSequence = positive(first.witness_sequence);
  const summaries = records.map((record) => {
    const core = record.envelope.core;
    if (!core || core.owner_digest !== ownerDigest
      || core.owner_revision !== ownerRevision
      || core.witness_sequence !== witnessSequence
      || core.object_id !== record.metadata.object_id
      || core.version_id !== record.metadata.version_id
      || core.object_revision !== record.objectRevision) deny();
    return { object_id: record.metadata.object_id,
      version_id: record.metadata.version_id,
      object_revision: record.objectRevision,
      digest: sha(Buffer.from(JSON.stringify(record))) };
  });
  return { schema: SCHEMA, owner_digest: ownerDigest,
    owner_revision: ownerRevision, witness_sequence: witnessSequence,
    entry_count: entries.length, entries: summaries };
}
function signingBytes(manifest) {
  return Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(manifest), "utf8")]);
}

async function sealOwnerAuthorizedVersionedCeks(input) {
  let stable, assertLive;
  try {
    ({ stable, assertLive } = snapshotWithSessionFence(input,
      ["ownerPrivateKey", "authority", "versions"]));
    assertLive();
    if (!nativeArrayIsArray(stable.versions) || stable.versions.length > 8) deny();
    const candidateRows = new Array(stable.versions.length);
    for (let i = 0; i < stable.versions.length; i++) {
      candidateRows[i] = exact(stable.versions[i], VERSION_KEYS);
    }
    const versions = verifyVersionChain(candidateRows);
    for (let i = 0; i < versions.length; i++) {
      const cek = versions[i].ownerHeldCek;
      if (!nativeIsUint8Array(cek)
        || nativeApply(nativeTypedByteLength, cek, []) !== 32) deny();
      for (let j = 0; j < i; j++) {
        if (nativeTimingSafeEqual(cek, versions[j].ownerHeldCek)) deny();
      }
    }
    const entries = [];
    for (let versionIndex = 0; versionIndex < versions.length; versionIndex++) {
      const row = versions[versionIndex];
      assertLive();
      const envelope = await nativeTransferSeal({
        ownerPrivateKey: stable.ownerPrivateKey, authority: stable.authority,
        ownerHeldCek: row.ownerHeldCek, metadata: row.metadata,
        objectRevision: row.objectRevision,
        ciphertext: row.ciphertext, ciphertextRoot: row.ciphertextRoot,
      });
      assertLive();
      nativeApply(nativeArrayPush, entries, [{ metadata: normalizedMetadata(row.metadata),
        objectRevision: row.objectRevision,
        ciphertext: row.ciphertext.toString("base64url"),
        ciphertextRoot: nativeApply(nativeBufferToString,
          nativeBufferFrom(row.ciphertextRoot), ["base64url"]), envelope }]);
    }
    assertLive();
    const manifest = makeManifest(entries);
    const ownerSignature = nativeSign(null, signingBytes(manifest),
      stable.ownerPrivateKey).toString("base64url");
    assertLive();
    return { schema: SCHEMA, manifest, entries,
      owner_signature: ownerSignature,
      signedBatchCompletenessVerified: true,
      globalAccountCompletenessProven: false, authorizesProductionRestore: false };
  } catch (_) { deny(); }
  finally {
    const all = stable?.versions;
    // Do not consult Array.prototype[Symbol.iterator] after assertLive().
    if (all) for (let i = 0; i < all.length; i++) scrub(all[i].ownerHeldCek);
  }
}

async function openOwnerAuthorizedVersionedCeks(input) {
  let stable, raw, assertLive;
  const released = [];
  try {
    // Client-side logout/session fence, not a proof of off-host revocation.
    ({ stable, assertLive } = snapshotWithSessionFence(input, [
      "bundle", "authority", "operatorMinimumSequence",
      "recipientHpkePrivateRaw", "nowSeconds"]));
    assertLive();
    const wire = exact(stable.bundle, BUNDLE_KEYS);
    if (wire.schema !== SCHEMA || wire.signedBatchCompletenessVerified !== true
      || wire.globalAccountCompletenessProven !== false
      || wire.authorizesProductionRestore !== false) deny();
    const records = new Array(wire.entries.length);
    for (let i = 0; i < records.length; i++) records[i] = entryRecord(wire.entries[i]);
    const rows = verifyVersionChain(records);
    for (let i = 0; i < rows.length; i++) if (rows[i] !== records[i]) deny();
    const manifest = exact(wire.manifest, MANIFEST_KEYS);
    const expected = makeManifest(rows);
    if (JSON.stringify(expected) !== JSON.stringify(manifest)) deny();
    const ownerKey = stable.authority.ownerPublicKey;
    if (!nativeTypes.isCryptoKey(ownerKey)) deny();
    const ownerSpki = nativeBufferFrom(await nativeApply(nativeExportKey,
      nativeSubtle, ["spki", ownerKey]));
    assertLive();
    const ownerPublic = nativeCreatePublicKey({ key: ownerSpki, format: "der", type: "spki" });
    if (!nativeVerify(null, signingBytes(manifest), ownerPublic,
      b64(wire.owner_signature, 64))) deny();
    raw = copyPrivateSeed(stable.recipientHpkePrivateRaw);
    const suite = nativeHpkeSuite();
    for (let rowIndex = 0; rowIndex < rows.length; rowIndex++) {
      const row = rows[rowIndex];
      assertLive();
      // The session fence callback may replace Function.prototype.bind or
      // mutate the KEM prototype. Never rebind/reload a method while a private
      // X25519 seed is about to cross the third-party deserializer.
      const recipient = await nativeApply(nativeKemDeserializePrivateKey, suite.kem, [raw]);
      assertLive();
      const opened = await nativeTransferOpen({
        envelope: row.envelope, authority: stable.authority,
        operatorMinimumSequence: stable.operatorMinimumSequence,
        metadata: row.metadata, objectRevision: row.objectRevision,
        ciphertext: b64(row.ciphertext), ciphertextRoot: b64(row.ciphertextRoot, 32),
        deviceHpkePrivateKey: recipient, nowSeconds: stable.nowSeconds,
      });
      let duplicateCek = false;
      for (let i = 0; i < released.length; i++) {
        const previous = released[i];
        if (previous.cek.length === opened.cek.length
          && nativeTimingSafeEqual(previous.cek, opened.cek)) duplicateCek = true;
      }
      if (duplicateCek) {
        scrub(opened.cek);
        deny();
      }
      // Array.prototype.push is also callback-mutable and receives the raw
      // opened CEK as part of its argument.
      nativeApply(nativeArrayPush, released, [{ metadata: row.metadata,
        objectRevision: row.objectRevision, cek: opened.cek }]);
      // Protect the last awaited HPKE operation as well as intermediate ones.
      // No CEK escapes until the full batch passes this final synchronous gate.
      assertLive();
    }
    assertLive();
    return { entries: released, signedBatchCompletenessVerified: true,
      globalAccountCompletenessProven: false, authorizesProductionRestore: false };
  } catch (_) {
    for (let i = 0; i < released.length; i++) scrub(released[i].cek);
    deny();
  } finally {
    scrub(raw);
    scrub(stable?.recipientHpkePrivateRaw);
  }
}

module.exports = { sealOwnerAuthorizedVersionedCeks,
  openOwnerAuthorizedVersionedCeks };
