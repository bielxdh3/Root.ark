"use strict";

// Strict offline, fixture-only PRE-RESTORE inspection. This never calls the
// legacy ZIP restore path and never authorizes live backup/restore operations.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { TextDecoder } = require("node:util");
const { assertPrivateSqliteAuthorityDirectory } = require("./zk1PrivateSqlitePath");

const REPORT_SCHEMA = "rootark-zk1-disposable-backup-pre-restore-report/v1";
const MANIFEST_SCHEMA = "rootark-zk1-backup-pre-restore-fixture/v1";
const INDEX_SCHEMA = "rootark-zk1-backup-index-fixture/v1";
const OWNER_APPROVAL_SCHEMA = "rootark-zk1-disposable-backup-owner-authorization/v1";
const OWNER_APPROVAL_DOMAIN = Buffer.from("Root.ark/zk-1/backup-owner-approval/v1\0", "ascii");
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
function samePath(left, right) {
  const a = path.resolve(left);
  const b = path.resolve(right);
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}
function pinDirectory(dir) {
  try {
    const stat = fs.lstatSync(dir, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) deny("UNSAFE_FIXTURE");
    // A junction can redirect descendants even when the leaf file itself is
    // opened with O_NOFOLLOW. Reject reparse/link resolution at EVERY parent.
    const real = fs.realpathSync.native(dir);
    if (!samePath(real, dir)) deny("UNSAFE_FIXTURE");
    return { dir, dev: stat.dev, ino: stat.ino, mode: stat.mode,
      birthtimeNs: stat.birthtimeNs, ctimeNs: stat.ctimeNs, real };
  } catch (_) { deny("UNSAFE_FIXTURE"); }
}
function verifyDirectoryPins(pins) {
  for (const pinned of pins) {
    const current = pinDirectory(pinned.dir);
    if (current.dev !== pinned.dev || current.ino !== pinned.ino
      || current.mode !== pinned.mode || current.birthtimeNs !== pinned.birthtimeNs
      || (pinned.privateBoundary && current.ctimeNs !== pinned.ctimeNs)
      || !samePath(current.real, pinned.real)) deny("UNSAFE_FIXTURE");
  }
}
function safeRoot(input) {
  if (typeof input !== "string" || !path.isAbsolute(input)) deny("UNSAFE_FIXTURE");
  const requestedRoot = path.resolve(input);
  const tmp = path.resolve(os.tmpdir());
  if (!samePath(path.dirname(requestedRoot), tmp)
    || !path.basename(requestedRoot).startsWith("rootark-zk-backup-fixture-"))
    deny("UNSAFE_FIXTURE");
  // Windows hosted agents may expose the OS-supplied TEMP through an
  // administrator-managed junction. Pin the real OS TEMP once, then perform
  // ALL content reads through its canonical path instead of following the
  // lexical alias while walking the private fixture. This does NOT permit
  // a junction at the fixture root or inside its owned child directories.
  let realTmp, root;
  try {
    realTmp = fs.realpathSync.native(tmp);
    root = path.join(realTmp, path.basename(requestedRoot));
    const lexical = fs.lstatSync(requestedRoot, { bigint: true });
    const canonical = fs.lstatSync(root, { bigint: true });
    if (!lexical.isDirectory() || lexical.isSymbolicLink()
      || !canonical.isDirectory() || canonical.isSymbolicLink()
      || lexical.dev !== canonical.dev || lexical.ino !== canonical.ino
      || !samePath(fs.realpathSync.native(requestedRoot), root)) deny("UNSAFE_FIXTURE");
  } catch (_) { deny("UNSAFE_FIXTURE"); }
  // Pinning the inode of a fixture is insufficient if another OS principal
  // can rename that inode through a shared, non-sticky TEMP ancestor. Reject
  // untrusted POSIX owners/modes and native Windows owner/DACL ancestry before
  // opening the first fixture file. SQLite's authority-path guard enforces
  // exactly this cross-principal pathname boundary without creating a file.
  try {
    assertPrivateSqliteAuthorityDirectory(path.join(root, "_backup_fixture_guard"));
    if (process.platform !== "win32") {
      const stat = fs.lstatSync(root, { bigint: true });
      if (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n) !== 0n)
        deny("UNSAFE_FIXTURE");
    }
  } catch (_) { deny("UNSAFE_FIXTURE"); }
  const parsed = path.parse(root);
  let current = parsed.root;
  const pins = [pinDirectory(current)];
  for (const part of root.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    verifyDirectoryPins(pins);
    pins.push(pinDirectory(current));
    verifyDirectoryPins(pins);
  }
  // Shared OS ancestors can be changed by unrelated processes. Watch their
  // identity; reserve change-time detection for the private fixture tree.
  pins[pins.length - 1].privateBoundary = true;
  return { root, pins, trustedTemporaryRoot: { alias: tmp, canonical: realTmp } };
}
function entriesExactly(dir, expected, verifyBoundary) {
  verifyBoundary();
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_) { deny("INVENTORY_INCOMPLETE"); }
  verifyBoundary();
  const names = new Set(expected);
  for (const entry of entries) {
    if (!names.delete(entry.name)) deny("UNEXPECTED_FIXTURE_ENTRY");
    if (entry.isSymbolicLink() || !entry.isFile())
      deny("UNEXPECTED_FIXTURE_ENTRY");
  }
  if (names.size) deny("INVENTORY_INCOMPLETE");
  verifyBoundary();
}
function checkRootEntries(root, verifyBoundary) {
  verifyBoundary();
  let entries;
  try { entries = fs.readdirSync(root, { withFileTypes: true }); }
  catch (_) { deny("UNSAFE_FIXTURE"); }
  verifyBoundary();
  const allowed = new Map([
    [".rootark-disposable-fixture", "file"], ["manifest.json", "file"],
    ["backup-index.json", "file"], ["owner-authorization.json", "file"], ["versions", "directory"],
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
  verifyBoundary();
}
function readRegular(file, maxSize, expectedFailure = "UNSAFE_FIXTURE_ENTRY", verifyBoundary = () => {}) {
  let descriptor;
  try {
    verifyBoundary();
    const before = fs.lstatSync(file, { bigint: true });
    verifyBoundary();
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
      || before.size > BigInt(maxSize)) deny(expectedFailure);
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    verifyBoundary();
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || opened.dev !== before.dev
      || opened.ino !== before.ino || opened.size !== before.size
      || opened.mtimeNs !== before.mtimeNs || opened.ctimeNs !== before.ctimeNs) deny(expectedFailure);
    // The descriptor's file may grow after fstat even with its pathname and
    // inode pinned. Never let readFileSync(fd) allocate through the attacker-
    // controlled EOF: read exactly the already validated original byte budget.
    const contents = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < contents.length) {
      const count = fs.readSync(descriptor, contents, offset,
        contents.length - offset, offset);
      if (count <= 0 || count > contents.length - offset) deny(expectedFailure);
      offset += count;
    }
    verifyBoundary();
    const after = fs.fstatSync(descriptor, { bigint: true });
    const again = fs.lstatSync(file, { bigint: true });
    if (BigInt(contents.length) !== opened.size || contents.length > maxSize
      || after.mtimeNs !== opened.mtimeNs || after.ctimeNs !== opened.ctimeNs
      || after.size !== opened.size || after.nlink !== 1n || again.nlink !== 1n
      || again.isSymbolicLink() || again.dev !== opened.dev || again.ino !== opened.ino
      || again.size !== opened.size || again.mtimeNs !== opened.mtimeNs
      || again.ctimeNs !== opened.ctimeNs) deny(expectedFailure);
    verifyBoundary();
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
function verifyOwnerBackupApproval(approvalBytes, trustedOwnerPublicKey, indexBytes, manifestBytes, manifest) {
  // A key embedded in the backup would be attacker-controlled. The caller must
  // pin the owner's Ed25519 public key independently of all fixture contents.
  if (!trustedOwnerPublicKey || trustedOwnerPublicKey.type !== "public"
    || trustedOwnerPublicKey.asymmetricKeyType !== "ed25519")
    deny("OWNER_BACKUP_AUTHORIZATION_INVALID");
  const approval = strictJson(approvalBytes);
  if (!exactKeys(approval, ["schema", "backupId", "compartmentId", "epoch", "revision",
    "indexSha256", "manifestSha256", "signature"])
    || approval.schema !== OWNER_APPROVAL_SCHEMA || approval.backupId !== manifest.backupId
    || approval.compartmentId !== manifest.compartmentId || approval.epoch !== manifest.epoch
    || approval.revision !== manifest.revision || approval.indexSha256 !== sha(indexBytes)
    || approval.manifestSha256 !== sha(manifestBytes)
    || typeof approval.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(approval.signature))
    deny("OWNER_BACKUP_AUTHORIZATION_INVALID");
  const signature = Buffer.from(approval.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== approval.signature)
    deny("OWNER_BACKUP_AUTHORIZATION_INVALID");
  const unsigned = { schema: approval.schema, backupId: approval.backupId,
    compartmentId: approval.compartmentId, epoch: approval.epoch, revision: approval.revision,
    indexSha256: approval.indexSha256, manifestSha256: approval.manifestSha256 };
  const message = Buffer.concat([OWNER_APPROVAL_DOMAIN, Buffer.from(JSON.stringify(unsigned))]);
  try {
    if (!crypto.verify(null, message, trustedOwnerPublicKey, signature))
      deny("OWNER_BACKUP_AUTHORIZATION_INVALID");
  } catch (_) { deny("OWNER_BACKUP_AUTHORIZATION_INVALID"); }
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
function verifyPayload(root, folder, entry, extension, expected, mismatch, verifyBoundary) {
  const file = path.join(root, folder, `${entry}.${extension}`);
  const contents = readRegular(file, MAX_PAYLOAD_BYTES, "INVENTORY_INCOMPLETE", verifyBoundary);
  if (possibleLeak(contents)) deny("POSSIBLE_PLAINTEXT_OR_KEY_LEAK");
  if (!contents.length || sha(contents) !== expected) deny(mismatch);
}
function verifyAll(root, manifest, catalog, verifyBoundary) {
  for (const [folder, ids, extension] of [
    ["versions", catalog.versions, "ct"], ["copies", catalog.copies, "ct"],
    ["envelopes", catalog.envelopes, "env"],
  ]) {
    const dir = path.join(root, folder);
    entriesExactly(dir, ids.map((entry) => `${entry}.${extension}`), verifyBoundary);
  }
  for (const object of manifest.objects) for (const v of object.versions) {
    verifyPayload(root, "versions", v.versionId, "ct", v.ciphertextSha256, "VERSION_DIGEST_MISMATCH", verifyBoundary);
    verifyPayload(root, "copies", v.copyId, "ct", v.ciphertextSha256, "COPY_DIGEST_MISMATCH", verifyBoundary);
    verifyPayload(root, "envelopes", v.ownerEnvelopeId, "env", v.ownerEnvelopeSha256, "ENVELOPE_DIGEST_MISMATCH", verifyBoundary);
    verifyPayload(root, "envelopes", v.recoveryEnvelopeId, "env", v.recoveryEnvelopeSha256, "ENVELOPE_DIGEST_MISMATCH", verifyBoundary);
  }
  verifyBoundary();
}
function inspectZk1DisposableBackupPreRestore({ fixtureDir, expectedCompartmentId,
  checkpoint, trustedOwnerPublicKey } = {}) {
  const report = { schema: REPORT_SCHEMA, readOnly: true, restoreAuthorized: false,
    fixtureVerified: false, ownerAuthorizationVerified: false,
    checkedVersions: 0, checkedCopies: 0, checkedEnvelopes: 0,
    findings: [], blockers: [...BLOCKERS] };
  try {
    const { root, pins, trustedTemporaryRoot } = safeRoot(fixtureDir);
    const verifyBoundary = () => {
      // A changing shared junction is NOT a new trusted temp location.
      // Content below always uses the original canonical private fixture.
      if (!samePath(fs.realpathSync.native(trustedTemporaryRoot.alias),
        trustedTemporaryRoot.canonical)) deny("UNSAFE_FIXTURE");
      verifyDirectoryPins(pins);
    };
    checkRootEntries(root, verifyBoundary);
    const marker = readRegular(path.join(root, ".rootark-disposable-fixture"), 128,
      "UNSAFE_FIXTURE_ENTRY", verifyBoundary);
    if (marker.toString("utf8") !== "rootark-zk-backup-fixture-v1\n") deny("UNSAFE_FIXTURE");
    if (!id(expectedCompartmentId)) deny("COMPARTMENT_MISMATCH");
    if (!exactKeys(checkpoint, ["epoch", "revision"])
      || !nonNegInt(checkpoint.epoch) || !nonNegInt(checkpoint.revision))
      deny("CHECKPOINT_REQUIRED");
    const indexBytes = readRegular(path.join(root, "backup-index.json"), MAX_METADATA_BYTES,
      "UNSAFE_FIXTURE_ENTRY", verifyBoundary);
    const index = strictJson(indexBytes);
    validateIndex(index);
    const manifestBytes = readRegular(path.join(root, "manifest.json"), MAX_METADATA_BYTES,
      "UNSAFE_FIXTURE_ENTRY", verifyBoundary);
    if (sha(manifestBytes) !== index.manifestSha256) deny("MANIFEST_DIGEST_MISMATCH");
    const manifest = strictJson(manifestBytes);
    const catalog = validateManifest(manifest, index, expectedCompartmentId, checkpoint);
    verifyOwnerBackupApproval(readRegular(path.join(root, "owner-authorization.json"), 4096,
      "UNSAFE_FIXTURE_ENTRY", verifyBoundary),
      trustedOwnerPublicKey, indexBytes, manifestBytes, manifest);
    // Freeze the identities of ALL child containers before any inventory
    // enumeration or ciphertext read. Check them after every filesystem call.
    for (const folder of ["versions", "copies", "envelopes"]) {
      verifyBoundary();
      const pinnedChild = pinDirectory(path.join(root, folder));
      pinnedChild.privateBoundary = true;
      pins.push(pinnedChild);
      verifyBoundary();
    }
    verifyAll(root, manifest, catalog, verifyBoundary);
    report.fixtureVerified = true;
    report.ownerAuthorizationVerified = true;
    report.checkedVersions = catalog.versions.length;
    report.checkedCopies = catalog.copies.length;
    report.checkedEnvelopes = catalog.envelopes.length;
  } catch (error) {
    report.findings.push(error instanceof Refusal ? error.code : "FIXTURE_UNAVAILABLE");
  }
  return Object.freeze(report);
}

module.exports = { inspectZk1DisposableBackupPreRestore };
