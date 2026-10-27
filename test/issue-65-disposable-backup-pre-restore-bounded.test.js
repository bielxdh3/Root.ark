"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { inspectZk1DisposableBackupPreRestore } =
  require("../src/services/zk1DisposableBackupPreRestore");
const { withInodeGrowthAfterFstat } = require("./support/issue-65-inode-growth-race");

test("disposable backup marker read cannot allocate inode bytes appended after fstat", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-backup-fixture-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const name of ["versions", "copies", "envelopes"])
    fs.mkdirSync(path.join(root, name));
  const marker = path.join(root, ".rootark-disposable-fixture");
  fs.writeFileSync(marker, "rootark-zk-backup-fixture-v1\n");
  for (const name of ["manifest.json", "backup-index.json", "owner-authorization.json"])
    fs.writeFileSync(path.join(root, name), "{}");
  let report;
  const originalRead = fs.readSync;
  const boundedReads = [];
  fs.readSync = function (fd, buffer, offset, length, position) {
    boundedReads.push({ length, position });
    return originalRead.call(fs, fd, buffer, offset, length, position);
  };
  let outcome;
  try {
    outcome = await withInodeGrowthAfterFstat({
      target: marker, extraBytes: 5 * 1024 * 1024,
      run: () => { report = inspectZk1DisposableBackupPreRestore({
        fixtureDir: root, expectedCompartmentId: "compartment1",
        checkpoint: { epoch: 0, revision: 0 },
      }); },
    });
  } finally { fs.readSync = originalRead; }
  assert.equal(outcome.attacked, true, "must race the actual marker descriptor after fstat");
  assert.equal(report.fixtureVerified, false, "a grown fixture must fail closed");
  assert.deepEqual(outcome.numericFdReadLengths, [],
    "an attacker-growable fixture must not be read using unbounded readFileSync(fd)");
  assert.ok(boundedReads.length >= 1, "the selected FD must undergo a real bounded read");
  assert.ok(boundedReads.every(({ length, position }) => length >= 1
    && position >= 0 && position + length <= Buffer.byteLength("rootark-zk-backup-fixture-v1\n")),
  "each positional FD read stays within the initially pinned size");
});

test("disposable backup bounded FD reads preserve a valid signed fixture", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-backup-fixture-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const write = (name, contents) => fs.writeFileSync(path.join(root, name), contents, { flag: "wx" });
  for (const name of ["versions", "copies", "envelopes"])
    fs.mkdirSync(path.join(root, name));
  write(".rootark-disposable-fixture", "rootark-zk-backup-fixture-v1\n");
  const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
  const ciphertext = Buffer.from("opaque version ciphertext");
  const ownerEnvelope = Buffer.from("opaque owner envelope");
  const recoveryEnvelope = Buffer.from("opaque recovery envelope");
  const record = { versionId: "version1", sequence: 1, parentVersionId: null,
    ciphertextSha256: sha(ciphertext), copyId: "copy1", ownerEnvelopeId: "owner1",
    ownerEnvelopeSha256: sha(ownerEnvelope), recoveryEnvelopeId: "recovery1",
    recoveryEnvelopeSha256: sha(recoveryEnvelope) };
  const manifest = { schema: "rootark-zk1-backup-pre-restore-fixture/v1",
    backupId: "backup1", compartmentId: "compartment1", epoch: 1, revision: 1,
    objects: [{ objectId: "object1", versions: [record] }] };
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  write("manifest.json", manifestBytes);
  const index = { schema: "rootark-zk1-backup-index-fixture/v1", backupId: "backup1",
    manifestSha256: sha(manifestBytes), versionIds: [record.versionId],
    copyIds: [record.copyId], envelopeIds: [record.ownerEnvelopeId, record.recoveryEnvelopeId] };
  const indexBytes = Buffer.from(JSON.stringify(index));
  write("backup-index.json", indexBytes);
  write("versions/version1.ct", ciphertext);
  write("copies/copy1.ct", ciphertext);
  write("envelopes/owner1.env", ownerEnvelope);
  write("envelopes/recovery1.env", recoveryEnvelope);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const approval = { schema: "rootark-zk1-disposable-backup-owner-authorization/v1",
    backupId: "backup1", compartmentId: "compartment1", epoch: 1, revision: 1,
    indexSha256: sha(indexBytes), manifestSha256: sha(manifestBytes) };
  const domain = Buffer.from("Root.ark/zk-1/backup-owner-approval/v1\0", "ascii");
  const signature = crypto.sign(null,
    Buffer.concat([domain, Buffer.from(JSON.stringify(approval))]), privateKey);
  write("owner-authorization.json", JSON.stringify({ ...approval,
    signature: signature.toString("base64url") }));
  const report = inspectZk1DisposableBackupPreRestore({ fixtureDir: root,
    expectedCompartmentId: "compartment1", checkpoint: { epoch: 0, revision: 0 },
    trustedOwnerPublicKey: publicKey });
  assert.equal(report.fixtureVerified, true, "valid signed backup remains readable");
  assert.equal(report.ownerAuthorizationVerified, true);
  assert.equal(report.restoreAuthorized, false, "fixture inspection never authorizes restore");
  assert.equal(report.checkedVersions, 1);
  assert.equal(report.checkedCopies, 1);
  assert.equal(report.checkedEnvelopes, 2);
  assert.deepEqual(report.findings, []);
});
