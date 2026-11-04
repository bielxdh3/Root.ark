"use strict";

// DEV-OFF: an owner-selected, signed and indivisible set of historical file CEKs.
// This does NOT establish that the set contains every object/version in an
// account. A complete externally retained owner inventory is still required.
const crypto = require("node:crypto");
const { types: nativeTypes } = require("node:util");
const z = require("./rootark-zk-1");
const transfer = require("./rootark-zk1-owner-authorized-file-cek-transfer");

const DOMAIN = Buffer.from("Root.ark/zk-1/owner-versioned-cek-batch/v1\0");
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
  if (!obj || typeof obj !== "object" || Array.isArray(obj)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(obj))
    || Reflect.ownKeys(obj).length !== fields.length
    || fields.some((name) => !Object.hasOwn(obj, name))) deny();
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
  const bytes = Buffer.from(value, "base64url");
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
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    meter.bytes += value.byteLength;
    if (value.byteLength > 4 * 1024 * 1024 || meter.bytes > 32 * 1024 * 1024) deny();
    return Buffer.from(value);
  }
  if (value instanceof ArrayBuffer) {
    meter.bytes += value.byteLength;
    if (value.byteLength > 4 * 1024 * 1024 || meter.bytes > 32 * 1024 * 1024) deny();
    return value.slice(0);
  }
  if (value instanceof crypto.KeyObject || nativeTypes.isCryptoKey(value)) return value;
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
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > 32) deny();
  const groups = new Map();
  const versionIds = new Set();
  let fixedScope;
  for (const entry of entries) {
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
    versions.sort((a, b) => a.revision - b.revision);
    for (let i = 0; i < versions.length; i++) {
      if (versions[i].revision !== i + 1
        || versions[i].parent !== (i === 0 ? null : versions[i - 1].versionId)
        || (i > 0 && versions[i].epoch < versions[i - 1].epoch)) deny();
    }
  }
  return [...entries].sort((a, b) => {
    const left = a.metadata.object_id, right = b.metadata.object_id;
    // Canonical base64url UUIDs are ASCII; avoid OS/ICU locale-dependent order.
    return (left < right ? -1 : left > right ? 1 : 0)
      || a.objectRevision - b.objectRevision;
  });
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
    if (!Array.isArray(stable.versions) || stable.versions.length > 8) deny();
    const versions = verifyVersionChain(stable.versions.map((row) => exact(row, VERSION_KEYS)));
    for (let i = 0; i < versions.length; i++) {
      const cek = versions[i].ownerHeldCek;
      if (!Buffer.isBuffer(cek) || cek.length !== 32) deny();
      for (let j = 0; j < i; j++) {
        if (crypto.timingSafeEqual(cek, versions[j].ownerHeldCek)) deny();
      }
    }
    const entries = [];
    for (const row of versions) {
      assertLive();
      const envelope = await transfer.sealOwnerAuthorizedFileCek({
        ownerPrivateKey: stable.ownerPrivateKey, authority: stable.authority,
        ownerHeldCek: row.ownerHeldCek, metadata: row.metadata,
        objectRevision: row.objectRevision,
        ciphertext: row.ciphertext, ciphertextRoot: row.ciphertextRoot,
      });
      assertLive();
      entries.push({ metadata: normalizedMetadata(row.metadata),
        objectRevision: row.objectRevision,
        ciphertext: row.ciphertext.toString("base64url"),
        ciphertextRoot: Buffer.from(row.ciphertextRoot).toString("base64url"), envelope });
    }
    assertLive();
    const manifest = makeManifest(entries);
    const ownerSignature = crypto.sign(null, signingBytes(manifest),
      stable.ownerPrivateKey).toString("base64url");
    assertLive();
    return { schema: SCHEMA, manifest, entries,
      owner_signature: ownerSignature,
      signedBatchCompletenessVerified: true,
      globalAccountCompletenessProven: false, authorizesProductionRestore: false };
  } catch (_) { deny(); }
  finally { for (const row of stable?.versions || []) row.ownerHeldCek?.fill(0); }
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
    const records = wire.entries.map(entryRecord);
    const rows = verifyVersionChain(records);
    if (rows.some((row, i) => row !== records[i])) deny();
    const manifest = exact(wire.manifest, MANIFEST_KEYS);
    const expected = makeManifest(rows);
    if (JSON.stringify(expected) !== JSON.stringify(manifest)) deny();
    const ownerKey = stable.authority.ownerPublicKey;
    if (!nativeTypes.isCryptoKey(ownerKey)) deny();
    const ownerSpki = Buffer.from(await crypto.webcrypto.subtle.exportKey("spki", ownerKey));
    assertLive();
    const ownerPublic = crypto.createPublicKey({ key: ownerSpki, format: "der", type: "spki" });
    if (!crypto.verify(null, signingBytes(manifest), ownerPublic,
      b64(wire.owner_signature, 64))) deny();
    raw = Buffer.from(stable.recipientHpkePrivateRaw);
    if (raw.length !== 32) deny();
    for (const row of rows) {
      assertLive();
      const recipient = await z.hpkeSuite().kem.deserializePrivateKey(raw);
      assertLive();
      const opened = await transfer.openOwnerAuthorizedFileCek({
        envelope: row.envelope, authority: stable.authority,
        operatorMinimumSequence: stable.operatorMinimumSequence,
        metadata: row.metadata, objectRevision: row.objectRevision,
        ciphertext: b64(row.ciphertext), ciphertextRoot: b64(row.ciphertextRoot, 32),
        deviceHpkePrivateKey: recipient, nowSeconds: stable.nowSeconds,
      });
      if (released.some((previous) => previous.cek.length === opened.cek.length
        && crypto.timingSafeEqual(previous.cek, opened.cek))) {
        opened.cek.fill(0);
        deny();
      }
      released.push({ metadata: row.metadata, objectRevision: row.objectRevision,
        cek: opened.cek });
      // Protect the last awaited HPKE operation as well as intermediate ones.
      // No CEK escapes until the full batch passes this final synchronous gate.
      assertLive();
    }
    assertLive();
    return { entries: released, signedBatchCompletenessVerified: true,
      globalAccountCompletenessProven: false, authorizesProductionRestore: false };
  } catch (_) {
    for (const row of released) row.cek.fill(0);
    deny();
  } finally {
    raw?.fill(0);
    const secret = stable?.recipientHpkePrivateRaw;
    if (secret instanceof ArrayBuffer) new Uint8Array(secret).fill(0);
    else secret?.fill(0);
  }
}

module.exports = { sealOwnerAuthorizedVersionedCeks,
  openOwnerAuthorizedVersionedCeks };
