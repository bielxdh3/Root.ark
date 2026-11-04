"use strict";

// DEV-OFF, read-only acceptance gate for an EXTERNALLY inventoried corpus.
// Neither this verifier nor server storage can discover an unlisted object.
// The owner must have independently obtained and pinned the complete signed
// account corpus, owner generation and monotonic predecessor before use.
const crypto = require("node:crypto");
const fileContent = require("../../public/client/rootark-zk1-file-content");
const DOMAIN = Buffer.from("Root.ark/zk-1/externally-pinned-owner-corpus/v1\0");
const FORMAT = "rootark-zk1-externally-pinned-owner-corpus/v1";
const FIELDS = ["schema", "accountId", "ownerGenerationId", "sequence",
  "previousCorpusSha256", "keyrings", "entries"];
const ENTRY = ["metadata", "objectRevision", "ciphertextSha256", "cekSha256"];
const META = ["account_id", "compartment_id", "keyring_id", "object_id",
  "version_id", "parent_version_id", "epoch", "kind"];
const MAX_VERSIONS = 64, MAX_KEYRINGS = 32, MAX_BYTES = 16 * 1024 * 1024;
const b64pattern = /^[A-Za-z0-9_-]+$/;

function deny() { throw new Error("ZK_OWNER_PINNED_CORPUS_DENIED"); }
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length) deny();
  const normalized = {};
  for (const key of keys) {
    const slot = Object.getOwnPropertyDescriptor(value, key);
    if (!slot || !Object.hasOwn(slot, "value")) deny();
    normalized[key] = slot.value;
  }
  return normalized;
}
function list(value, min, max) {
  if (!Array.isArray(value) || value.length < min || value.length > max
    || Reflect.ownKeys(value).length !== value.length + 1) deny();
  return Array.from({ length: value.length }, (_, i) => {
    const slot = Object.getOwnPropertyDescriptor(value, String(i));
    if (!slot || !Object.hasOwn(slot, "value")) deny();
    return slot.value;
  });
}
function copy(value, min, max = min) {
  if (!(value instanceof Uint8Array) && !(value instanceof ArrayBuffer)
    || value.byteLength < min || value.byteLength > max
    || (typeof SharedArrayBuffer !== "undefined"
      && (value instanceof SharedArrayBuffer || value.buffer instanceof SharedArrayBuffer))) deny();
  return Buffer.from(value instanceof ArrayBuffer ? new Uint8Array(value) : value);
}
function b64(value, min = 16, max = min) {
  if (typeof value !== "string" || !b64pattern.test(value)
    || value.length > Math.ceil(max * 4 / 3) + 4) deny();
  const raw = Buffer.from(value, "base64url");
  if (raw.length < min || raw.length > max || raw.toString("base64url") !== value) deny();
  return value;
}
function positive(value) {
  if (!Number.isSafeInteger(value) || value < 1) deny();
  return value;
}
function digest(value) { return crypto.createHash("sha256").update(value).digest(); }
function same(a, b) { return a.length === b.length && crypto.timingSafeEqual(a, b); }
function metadata(raw, accountId) {
  const m = exact(raw, META);
  if (b64(m.account_id) !== accountId || b64(m.keyring_id) !== m.keyring_id) deny();
  b64(m.compartment_id, 1, 128);
  b64(m.object_id); b64(m.version_id);
  if (m.parent_version_id !== null) b64(m.parent_version_id);
  positive(m.epoch);
  if (!["file", "derived-data"].includes(m.kind)) deny();
  return m;
}
function compare(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}
function rowOrder(a, b) {
  return compare(a.metadata.keyring_id, b.metadata.keyring_id)
    || compare(a.metadata.object_id, b.metadata.object_id)
    || a.objectRevision - b.objectRevision;
}
function normalizeEntries(raw, accountId, keyrings) {
  const entries = list(raw, 1, MAX_VERSIONS).map((v) => {
    const row = exact(v, ENTRY);
    row.metadata = metadata(row.metadata, accountId);
    row.objectRevision = positive(row.objectRevision);
    b64(row.ciphertextSha256, 32); b64(row.cekSha256, 32);
    if (!keyrings.has(row.metadata.keyring_id)) deny();
    return row;
  });
  const ownerByObject = new Map(), priorByObject = new Map(), versions = new Set();
  const cekHashes = new Set();
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i], m = entry.metadata;
    if (i && rowOrder(entries[i - 1], entry) >= 0) deny();
    // Immutable account/compartment/keyring ownership must remain bound to
    // the object UUID across all versions. A change needs an explicit new
    // object identity and independently authenticated migration evidence.
    const ownership = [m.account_id, m.compartment_id, m.keyring_id].join(":");
    const ownedBy = ownerByObject.get(m.object_id);
    if (ownedBy !== undefined && ownedBy !== ownership) deny();
    ownerByObject.set(m.object_id, ownership);
    if (versions.has(m.version_id)) deny();
    versions.add(m.version_id);
    // Each zk-1 file version must have a fresh random CEK. Even an externally
    // signed inventory cannot normalize CEK reuse into a valid migration.
    if (cekHashes.has(entry.cekSha256)) deny();
    cekHashes.add(entry.cekSha256);
    const prior = priorByObject.get(m.object_id);
    if (entry.objectRevision !== (prior ? prior.objectRevision + 1 : 1)
      || m.parent_version_id !== (prior ? prior.metadata.version_id : null)
      || (prior && m.epoch < prior.metadata.epoch)) deny();
    priorByObject.set(m.object_id, entry);
  }
  return entries;
}
function recoveryFiles(raw, accountId) {
  const copied = [];
  let total = 0;
  try {
    for (const value of list(raw, 1, MAX_VERSIONS)) {
      const file = exact(value, ["metadata", "objectRevision", "ciphertext", "cek"]);
      const m = metadata(file.metadata, accountId);
      const ciphertext = copy(file.ciphertext, 16, 4 * 1024 * 1024);
      const cek = copy(file.cek, 32);
      copied.push({ metadata: m, objectRevision: positive(file.objectRevision), ciphertext, cek });
      total += ciphertext.length;
      if (total > MAX_BYTES) deny();
    }
    return copied;
  } catch (_) {
    for (const file of copied) { file.ciphertext.fill(0); file.cek.fill(0); }
    deny();
  }
}
async function verifyPinnedOwnerCorpus(input) {
  let files = [];
  try {
    const args = exact(input, ["manifest", "independentlyPinnedCorpusSha256",
      "ownerPublicKey", "independentOwnerSpkiSha256", "expectedAccountId",
      "expectedOwnerGenerationId", "previousPinnedCorpus", "recoveredFiles"]);
    b64(args.expectedAccountId); b64(args.expectedOwnerGenerationId);
    const pinned = copy(args.independentlyPinnedCorpusSha256, 32);
    const ownerPin = copy(args.independentOwnerSpkiSha256, 32);
    const outer = exact(args.manifest, [...FIELDS, "signature"]);
    const wire = Buffer.from(JSON.stringify(outer));
    if (wire.length > 128 * 1024 || !same(digest(wire), pinned)) deny();
    const stable = exact(JSON.parse(wire.toString("utf8")), [...FIELDS, "signature"]);
    if (stable.schema !== FORMAT || stable.accountId !== args.expectedAccountId
      || stable.ownerGenerationId !== args.expectedOwnerGenerationId) deny();
    const sequence = positive(stable.sequence);
    const prev = args.previousPinnedCorpus;
    if (prev === null) {
      if (sequence !== 1 || stable.previousCorpusSha256 !== null) deny();
    } else {
      const floor = exact(prev, ["sequence", "corpusSha256", "accountId",
        "ownerGenerationId", "ownerSpkiSha256"]);
      const priorSequence = positive(floor.sequence);
      const priorSha = copy(floor.corpusSha256, 32);
      if (priorSequence >= Number.MAX_SAFE_INTEGER || sequence !== priorSequence + 1
        || stable.previousCorpusSha256 !== priorSha.toString("base64url")
        || floor.accountId !== stable.accountId
        || floor.ownerGenerationId !== stable.ownerGenerationId
        || floor.ownerSpkiSha256 !== ownerPin.toString("base64url")) deny();
    }
    const keyrings = list(stable.keyrings, 1, MAX_KEYRINGS);
    const keys = new Set();
    for (let i = 0; i < keyrings.length; i++) {
      const id = b64(keyrings[i]);
      if (keys.has(id) || (i && compare(keyrings[i - 1], id) >= 0)) deny();
      keys.add(id);
    }
    const entries = normalizeEntries(stable.entries, stable.accountId, keys);
    const canonical = JSON.stringify({ schema: stable.schema,
      accountId: stable.accountId, ownerGenerationId: stable.ownerGenerationId,
      sequence, previousCorpusSha256: stable.previousCorpusSha256,
      keyrings, entries, signature: stable.signature });
    if (canonical !== wire.toString("utf8")) deny();
    files = recoveryFiles(args.recoveredFiles, stable.accountId);
    // Preflight completeness before any AES/CEK operation. This rejects a
    // missing unknown-to-storage version or keyring after interrupted migration.
    if (files.length !== entries.length) deny();
    for (let i = 0; i < files.length; i++) {
      const actual = files[i], expected = entries[i];
      if (i && rowOrder(files[i - 1], actual) >= 0
        || actual.objectRevision !== expected.objectRevision
        || JSON.stringify(actual.metadata) !== JSON.stringify(expected.metadata)
        || !same(digest(actual.ciphertext), Buffer.from(expected.ciphertextSha256, "base64url"))
        || !same(digest(actual.cek), Buffer.from(expected.cekSha256, "base64url"))) deny();
    }
    const owner = args.ownerPublicKey;
    if (owner?.type !== "public" || owner.algorithm?.name !== "Ed25519"
      || !owner.usages?.includes("verify")) deny();
    const actualSpki = Buffer.from(await crypto.webcrypto.subtle.exportKey("spki", owner));
    if (!same(digest(actualSpki), ownerPin)) deny();
    const signature = Buffer.from(b64(stable.signature, 64), "base64url");
    const signed = Buffer.concat([DOMAIN,
      Buffer.from(JSON.stringify(Object.fromEntries(FIELDS.map((field) => [field, stable[field]]))))]);
    if (!await crypto.webcrypto.subtle.verify("Ed25519", owner, signature, signed)) deny();
    // Validate the actual per-version CEK against its exact authenticated
    // metadata, not only an owner-approved digest of arbitrary random bytes.
    for (const file of files) {
      const key = await fileContent.importFileCek(file.cek);
      const opened = await fileContent.decryptFile({ cek: key, metadata: file.metadata,
        envelopeBytes: file.ciphertext });
      opened.data.fill(0);
    }
    return Object.freeze({ allExternallyPinnedCorpusEntriesRecovered: true,
      corpusSequence: sequence, recoveredVersionCount: files.length,
      verifiedKeyringCount: keyrings.length,
      externalCorpusOriginVerifiedByModule: false,
      globalAccountCompletenessProven: false,
      accountWideRecoveryAuthorized: false, authorizesProductionRestore: false });
  } catch (_) { deny(); }
  finally { for (const file of files) { file.ciphertext.fill(0); file.cek.fill(0); } }
}

module.exports = Object.freeze({ verifyPinnedOwnerCorpus });
