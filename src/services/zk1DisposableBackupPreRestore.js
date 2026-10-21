"use strict";

// Strict offline, fixture-only PRE-RESTORE inspection. This never calls the
// legacy ZIP restore path and never authorizes live backup/restore operations.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { TextDecoder } = require("node:util");

const REPORT_SCHEMA = "rootark-zk1-disposable-backup-pre-restore-report/v1";
const MANIFEST_SCHEMA = "rootark-zk1-backup-pre-restore-fixture/v1";
const INDEX_SCHEMA = "rootark-zk1-backup-index-fixture/v1";
const MAX_METADATA_BYTES = 256 * 1024;
const MAX_PAYLOAD_BYTES = 4 * 1024 * 1024;
const MAX_OBJECTS = 32;
const MAX_VERSIONS = 8;
const BLOCKERS = Object.freeze([
  "missing-trusted-cas-witness",
  "missing-owner-approved-recovery-policy",
  "missing-authorized-client-decryption-proof",
  "missing-production-backup-restore-fence",
]);

class Refusal extends Error {
  constructor(code) { super(code); this.code = code; }
}
function deny(code) { throw new Refusal(code); }
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const id = (value) => typeof value === "string" && /^[a-z][a-z0-9_-]{0,63}$/.test(value);
const digest = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const posInt = (value) => Number.isSafeInteger(value) && value >= 1;
const nonNegInt = (value) => Number.isSafeInteger(value) && value >= 0;
function exactKeys(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join("|") === [...fields].sort().join("|");
}
function assertDirectory(dir) {
  try {
    const stat = fs.lstatSync(dir);
    if (!stat.isDirectory() || stat.isSymbolicLink()) deny("UNSAFE_FIXTURE");
  } catch (_) { deny("UNSAFE_FIXTURE"); }
}
function safeRoot(input) {
  if (typeof input !== "string" || !path.isAbsolute(input)) deny("UNSAFE_FIXTURE");
  const root = path.resolve(input);
  const tmp = path.resolve(os.tmpdir());
  if (path.dirname(root) !== tmp || !path.basename(root).startsWith("rootark-zk-backup-fixture-"))
    deny("UNSAFE_FIXTURE");
  const parsed = path.parse(root);
  let current = parsed.root;
  for (const part of root.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    assertDirectory(current);
  }
  return root;
}
function entriesExactly(dir, expected, directories = false) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_) { deny("INVENTORY_INCOMPLETE"); }
  const names = new Set(expected);
  for (const entry of entries) {
    if (!names.delete(entry.name)) deny("UNEXPECTED_FIXTURE_ENTRY");
    if (entry.isSymbolicLink() || (directories ? !entry.isDirectory() : !entry.isFile()))
      deny("UNEXPECTED_FIXTURE_ENTRY");
  }
  if (names.size) deny("INVENTORY_INCOMPLETE");
}
function checkRootEntries(root) {
  let entries;
  try { entries = fs.readdirSync(root, { withFileTypes: true }); }
  catch (_) { deny("UNSAFE_FIXTURE"); }
  const allowed = new Map([
    [".rootark-disposable-fixture", "file"], ["manifest.json", "file"],
    ["backup-index.json", "file"], ["versions", "directory"],
    ["copies", "directory"], ["envelopes", "directory"],
  ]);
  for (const entry of entries) {
    const kind = allowed.get(entry.name);
    if (!kind || entry.isSymbolicLink()
      || (kind === "file" ? !entry.isFile() : !entry.isDirectory()))
      deny("UNEXPECTED_FIXTURE_ENTRY");
    allowed.delete(entry.name);
  }
  if (allowed.size) deny("INVENTORY_INCOMPLETE");
}
function readRegular(file, maxSize, expectedFailure = "UNSAFE_FIXTURE_ENTRY") {
  let descriptor;
  try {
    const before = fs.lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || before.size > maxSize) deny(expectedFailure);
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev
      || opened.ino !== before.ino || opened.size !== before.size) deny(expectedFailure);
    const contents = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const again = fs.lstatSync(file);
    if (contents.length !== opened.size || contents.length > maxSize
      || after.mtimeMs !== opened.mtimeMs || after.size !== opened.size
      || after.nlink !== 1 || again.nlink !== 1 || again.isSymbolicLink()
      || again.dev !== opened.dev || again.ino !== opened.ino) deny(expectedFailure);
    return contents;
  } catch (error) {
    if (error instanceof Refusal) throw error;
    deny(expectedFailure);
  } finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}
function possibleLeak(bytes) {
  // Narrow heuristic: detects recognizable key/plaintext spill patterns, but
  // cannot cryptographically prove that arbitrary bytes are ciphertext.
  const sample = bytes.toString("latin1");
  return /ROOTARK_TEST_PLAINTEXT_MARKER|-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----|"(?:privateKey|password|plaintext|secretKey|recoveryPhrase)"\s*:/i.test(sample);
}
function strictJson(bytes) {
  if (possibleLeak(bytes)) deny("POSSIBLE_PLAINTEXT_OR_KEY_LEAK");
  let text;
  let parsed;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    parsed = JSON.parse(text);
    // Canonical exact JSON roundtrip rejects duplicate keys, ambiguous
    // representation, trailing data and producer-dependent reserialization.
    if (JSON.stringify(parsed) !== text) deny("MALFORMED_METADATA");
  } catch (error) {
    if (error instanceof Refusal) throw error;
    deny("MALFORMED_METADATA");
  }
  return parsed;
}
function validateIndex(index) {
  if (!exactKeys(index, ["schema", "backupId", "manifestSha256", "versionIds", "copyIds", "envelopeIds"])
    || index.schema !== INDEX_SCHEMA || !id(index.backupId) || !digest(index.manifestSha256))
    deny("MALFORMED_METADATA");
  for (const label of ["versionIds", "copyIds", "envelopeIds"]) {
    if (!Array.isArray(index[label]) || index[label].length > 512
      || index[label].some((entry) => !id(entry) || index[label].indexOf(entry) !== index[label].lastIndexOf(entry)))
      deny("MALFORMED_METADATA");
  }
}
function validateManifest(manifest, index, expectedCompartmentId, checkpoint) {
  if (!exactKeys(manifest, ["schema", "backupId", "compartmentId", "epoch", "revision", "objects"])
    || manifest.schema !== MANIFEST_SCHEMA || !id(manifest.backupId) || !id(manifest.compartmentId)
    || !posInt(manifest.epoch) || !posInt(manifest.revision)
    || !Array.isArray(manifest.objects) || manifest.objects.length < 1
    || manifest.objects.length > MAX_OBJECTS) deny("MALFORMED_METADATA");
  if (manifest.backupId !== index.backupId) deny("BACKUP_IDENTITY_MISMATCH");
  if (manifest.compartmentId !== expectedCompartmentId) deny("COMPARTMENT_MISMATCH");
  if (manifest.epoch < checkpoint.epoch
    || (manifest.epoch === checkpoint.epoch && manifest.revision <= checkpoint.revision))
    deny("STALE_OR_REPLAYED_MANIFEST");
  const objects = new Set();
  const versions = [];
  const copies = [];
  const envelopes = [];
  for (const obj of manifest.objects) {
    if (!exactKeys(obj, ["objectId", "versions"]) || !id(obj.objectId) || objects.has(obj.objectId)
      || !Array.isArray(obj.versions) || !obj.versions.length || obj.versions.length > MAX_VERSIONS)
      deny("MALFORMED_METADATA");
    objects.add(obj.objectId);
    let previous = null;
    for (const [idx, record] of obj.versions.entries()) {
      if (!exactKeys(record, ["versionId", "sequence", "parentVersionId", "ciphertextSha256",
        "copyId", "ownerEnvelopeId", "ownerEnvelopeSha256", "recoveryEnvelopeId", "recoveryEnvelopeSha256"])
        || !id(record.versionId) || record.sequence !== idx + 1
        || record.parentVersionId !== previous || !digest(record.ciphertextSha256)
        || !id(record.copyId) || !id(record.ownerEnvelopeId) || !id(record.recoveryEnvelopeId)
        || record.ownerEnvelopeId === record.recoveryEnvelopeId
        || !digest(record.ownerEnvelopeSha256) || !digest(record.recoveryEnvelopeSha256))
        deny("MALFORMED_METADATA");
      previous = record.versionId;
      versions.push(record.versionId);
      copies.push(record.copyId);
      envelopes.push(record.ownerEnvelopeId, record.recoveryEnvelopeId);
    }
  }
  for (const values of [versions, copies, envelopes]) {
    if (new Set(values).size !== values.length) deny("MALFORMED_METADATA");
  }
  const compare = (actual, declared) =>
    actual.length === declared.length && [...actual].sort().join("|") === [...declared].sort().join("|");
  if (!compare(versions, index.versionIds) || !compare(copies, index.copyIds)
    || !compare(envelopes, index.envelopeIds)) deny("INVENTORY_INCOMPLETE");
  return { versions, copies, envelopes };
}
function verifyPayload(root, folder, entry, extension, expected, mismatch) {
  const file = path.join(root, folder, `${entry}.${extension}`);
  const contents = readRegular(file, MAX_PAYLOAD_BYTES, "INVENTORY_INCOMPLETE");
  if (possibleLeak(contents)) deny("POSSIBLE_PLAINTEXT_OR_KEY_LEAK");
  if (!contents.length || sha(contents) !== expected) deny(mismatch);
}
function verifyAll(root, manifest, catalog) {
  for (const [folder, ids, extension] of [
    ["versions", catalog.versions, "ct"], ["copies", catalog.copies, "ct"],
    ["envelopes", catalog.envelopes, "env"],
  ]) {
    const dir = path.join(root, folder);
    assertDirectory(dir);
    entriesExactly(dir, ids.map((entry) => `${entry}.${extension}`));
  }
  for (const object of manifest.objects) for (const v of object.versions) {
    verifyPayload(root, "versions", v.versionId, "ct", v.ciphertextSha256, "VERSION_DIGEST_MISMATCH");
    verifyPayload(root, "copies", v.copyId, "ct", v.ciphertextSha256, "COPY_DIGEST_MISMATCH");
    verifyPayload(root, "envelopes", v.ownerEnvelopeId, "env", v.ownerEnvelopeSha256, "ENVELOPE_DIGEST_MISMATCH");
    verifyPayload(root, "envelopes", v.recoveryEnvelopeId, "env", v.recoveryEnvelopeSha256, "ENVELOPE_DIGEST_MISMATCH");
  }
}
function inspectZk1DisposableBackupPreRestore({ fixtureDir, expectedCompartmentId, checkpoint } = {}) {
  const report = { schema: REPORT_SCHEMA, readOnly: true, restoreAuthorized: false,
    fixtureVerified: false, checkedVersions: 0, checkedCopies: 0, checkedEnvelopes: 0,
    findings: [], blockers: [...BLOCKERS] };
  try {
    const root = safeRoot(fixtureDir);
    checkRootEntries(root);
    const marker = readRegular(path.join(root, ".rootark-disposable-fixture"), 128);
    if (marker.toString("utf8") !== "rootark-zk-backup-fixture-v1\n") deny("UNSAFE_FIXTURE");
    if (!id(expectedCompartmentId)) deny("COMPARTMENT_MISMATCH");
    if (!exactKeys(checkpoint, ["epoch", "revision"])
      || !nonNegInt(checkpoint.epoch) || !nonNegInt(checkpoint.revision))
      deny("CHECKPOINT_REQUIRED");
    const index = strictJson(readRegular(path.join(root, "backup-index.json"), MAX_METADATA_BYTES));
    validateIndex(index);
    const manifestBytes = readRegular(path.join(root, "manifest.json"), MAX_METADATA_BYTES);
    if (sha(manifestBytes) !== index.manifestSha256) deny("MANIFEST_DIGEST_MISMATCH");
    const manifest = strictJson(manifestBytes);
    const catalog = validateManifest(manifest, index, expectedCompartmentId, checkpoint);
    verifyAll(root, manifest, catalog);
    report.fixtureVerified = true;
    report.checkedVersions = catalog.versions.length;
    report.checkedCopies = catalog.copies.length;
    report.checkedEnvelopes = catalog.envelopes.length;
  } catch (error) {
    report.findings.push(error instanceof Refusal ? error.code : "FIXTURE_UNAVAILABLE");
  }
  return Object.freeze(report);
}

module.exports = { inspectZk1DisposableBackupPreRestore };
