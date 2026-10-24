"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { inspectZk1DisposableBackupPreRestore } = require("../src/services/zk1DisposableBackupPreRestore");

const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const encode = (value) => JSON.stringify(value);
const OWNER_DOMAIN = Buffer.from("Root.ark/zk-1/backup-owner-approval/v1\0", "ascii");
const version = (id) => Buffer.from([0x00, 0x83, 0xac, 0x67, 0x91, id.charCodeAt(1), 0x00, 0xff, 0x2b, 0x73, 0xe4, 0x8f, 0xb2, 0x12, 0xdf, 0x8e]);

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-backup-fixture-"));
  t.after(() => fs.rmSync(dir, { force: true, recursive: true }));
  const owner = crypto.generateKeyPairSync("ed25519");
  for (const folder of ["versions", "copies", "envelopes"]) fs.mkdirSync(path.join(dir, folder));
  fs.writeFileSync(path.join(dir, ".rootark-disposable-fixture"), "rootark-zk-backup-fixture-v1\n");
  const records = [];
  for (const [index, id] of ["vone", "vtwo"].entries()) {
    const content = version(id);
    const owner = Buffer.from(`\u0002fixture-owner-envelope-${id}\u00ff`, "utf8");
    const recovery = Buffer.from(`\u0003fixture-recovery-envelope-${id}\u00fc`, "utf8");
    fs.writeFileSync(path.join(dir, "versions", `${id}.ct`), content);
    fs.writeFileSync(path.join(dir, "copies", `copy${id}.ct`), content);
    fs.writeFileSync(path.join(dir, "envelopes", `own${id}.env`), owner);
    fs.writeFileSync(path.join(dir, "envelopes", `rec${id}.env`), recovery);
    records.push({ versionId: id, sequence: index + 1, parentVersionId: index ? "vone" : null,
      ciphertextSha256: sha(content), copyId: `copy${id}`,
      ownerEnvelopeId: `own${id}`, ownerEnvelopeSha256: sha(owner),
      recoveryEnvelopeId: `rec${id}`, recoveryEnvelopeSha256: sha(recovery) });
  }
  const manifest = { schema: "rootark-zk1-backup-pre-restore-fixture/v1", backupId: "backupone",
    compartmentId: "compartmentone", epoch: 4, revision: 7,
    objects: [{ objectId: "objectone", versions: records }] };
  const persist = () => {
    const manifestBytes = Buffer.from(encode(manifest));
    fs.writeFileSync(path.join(dir, "manifest.json"), manifestBytes);
    const index = { schema: "rootark-zk1-backup-index-fixture/v1",
      backupId: manifest.backupId, manifestSha256: sha(manifestBytes),
      versionIds: ["vone", "vtwo"], copyIds: ["copyvone", "copyvtwo"],
      envelopeIds: ["ownvone", "recvone", "ownvtwo", "recvtwo"] };
    const indexBytes = Buffer.from(encode(index));
    fs.writeFileSync(path.join(dir, "backup-index.json"), indexBytes);
    const approval = { schema: "rootark-zk1-disposable-backup-owner-authorization/v1",
      backupId: manifest.backupId, compartmentId: manifest.compartmentId,
      epoch: manifest.epoch, revision: manifest.revision,
      indexSha256: sha(indexBytes), manifestSha256: sha(manifestBytes) };
    approval.signature = crypto.sign(null, Buffer.concat([OWNER_DOMAIN, Buffer.from(encode(approval))]),
      owner.privateKey).toString("base64url");
    fs.writeFileSync(path.join(dir, "owner-authorization.json"), encode(approval));
  };
  persist();
  const options = { fixtureDir: dir, expectedCompartmentId: "compartmentone",
    checkpoint: { epoch: 3, revision: 20 }, trustedOwnerPublicKey: owner.publicKey };
  return { dir, manifest, persist, options, owner };
}
const inspect = (f, extras = {}) => inspectZk1DisposableBackupPreRestore({ ...f.options, ...extras });
function blocked(report, finding) {
  assert.equal(report.restoreAuthorized, false);
  assert.equal(report.readOnly, true);
  assert.equal(report.fixtureVerified, false);
  assert.equal(report.ownerAuthorizationVerified, false);
  assert.ok(report.findings.includes(finding), JSON.stringify(report.findings));
}

test("a fully referenced synthetic backup is independently hashed but can never authorize restore", (t) => {
  const f = fixture(t);
  const before = new Map();
  for (const folder of [".", "versions", "copies", "envelopes"])
    for (const name of fs.readdirSync(path.join(f.dir, folder))) {
      const file = path.join(f.dir, folder, name);
      if (fs.statSync(file).isFile()) before.set(file, [sha(fs.readFileSync(file)), fs.statSync(file).mtimeMs]);
    }
  const report = inspect(f);
  assert.equal(report.fixtureVerified, true, JSON.stringify(report.findings));
  assert.equal(report.ownerAuthorizationVerified, true);
  assert.equal(report.restoreAuthorized, false);
  assert.equal(report.readOnly, true);
  assert.deepEqual(report.findings, []);
  assert.equal(report.checkedVersions, 2);
  assert.equal(report.checkedCopies, 2);
  assert.equal(report.checkedEnvelopes, 4);
  assert.deepEqual(report.blockers, ["missing-trusted-cas-witness", "missing-owner-approved-recovery-policy",
    "missing-authorized-client-decryption-proof", "missing-production-backup-restore-fence"]);
  assert.equal(JSON.stringify(report).includes(f.dir), false);
  for (const [file, state] of before) assert.deepEqual(
    [sha(fs.readFileSync(file)), fs.statSync(file).mtimeMs], state);
});

test("backup fixture FD rejects distinct 64-bit inode identities that round to the same Number", (t) => {
  const f = fixture(t);
  const file = path.join(f.dir, "manifest.json");
  const highInode = 2n ** 60n;
  const originalOpen = fs.openSync;
  const originalLstat = fs.lstatSync;
  const originalFstat = fs.fstatSync;
  let manifestFd;
  const substitute = (stat, ino) => { stat.ino = typeof stat.ino === "bigint" ? ino : Number(ino); return stat; };
  try {
    fs.openSync = function (name) {
      const fd = originalOpen.apply(this, arguments);
      if (name === file) manifestFd = fd;
      return fd;
    };
    fs.lstatSync = function (name) {
      const stat = originalLstat.apply(this, arguments);
      return name === file ? substitute(stat, highInode) : stat;
    };
    fs.fstatSync = function (fd) {
      const stat = originalFstat.apply(this, arguments);
      return fd === manifestFd ? substitute(stat, highInode + 1n) : stat;
    };
    blocked(inspect(f), "UNSAFE_FIXTURE_ENTRY");
  } finally {
    fs.openSync = originalOpen;
    fs.lstatSync = originalLstat;
    fs.fstatSync = originalFstat;
  }
});

test("owner approval requires an independently pinned Ed25519 public key", (t) => {
  const f = fixture(t);
  blocked(inspect(f, { trustedOwnerPublicKey: undefined }), "OWNER_BACKUP_AUTHORIZATION_INVALID");
  blocked(inspect(f, { trustedOwnerPublicKey: crypto.generateKeyPairSync("ed25519").publicKey }),
    "OWNER_BACKUP_AUTHORIZATION_INVALID");
  blocked(inspect(f, { trustedOwnerPublicKey: f.owner.privateKey }), "OWNER_BACKUP_AUTHORIZATION_INVALID");
  const approvalPath = path.join(f.dir, "owner-authorization.json");
  const approval = JSON.parse(fs.readFileSync(approvalPath, "utf8"));
  approval.signature = crypto.sign(null, Buffer.concat([OWNER_DOMAIN, Buffer.from(encode({
    schema: approval.schema, backupId: approval.backupId, compartmentId: approval.compartmentId,
    epoch: approval.epoch, revision: approval.revision, indexSha256: approval.indexSha256,
    manifestSha256: approval.manifestSha256,
  }))]), crypto.generateKeyPairSync("ed25519").privateKey).toString("base64url");
  fs.writeFileSync(approvalPath, encode(approval));
  blocked(inspect(f), "OWNER_BACKUP_AUTHORIZATION_INVALID");
});

test("attacker cannot forge owner-approved inventory by rehashing replaced ciphertext and manifest", (t) => {
  const f = fixture(t);
  const oldApproval = fs.readFileSync(path.join(f.dir, "owner-authorization.json"));
  const replacement = Buffer.from("\u0001opaque-synthetic-replacement\u0081");
  fs.writeFileSync(path.join(f.dir, "versions", "vone.ct"), replacement);
  fs.writeFileSync(path.join(f.dir, "copies", "copyvone.ct"), replacement);
  f.manifest.objects[0].versions[0].ciphertextSha256 = sha(replacement);
  f.persist();
  fs.writeFileSync(path.join(f.dir, "owner-authorization.json"), oldApproval);
  blocked(inspect(f), "OWNER_BACKUP_AUTHORIZATION_INVALID");
});

test("missing approval, altered signature, stale signed identity and unapproved index changes fail closed", (t) => {
  const f = fixture(t);
  const approvalPath = path.join(f.dir, "owner-authorization.json");
  const original = fs.readFileSync(approvalPath);
  fs.rmSync(approvalPath);
  blocked(inspect(f), "INVENTORY_INCOMPLETE");
  fs.writeFileSync(approvalPath, original);

  for (const mutate of [
    (a) => { a.signature = "a".repeat(86); },
    (a) => { a.epoch += 1; },
    (a) => { a.revision += 1; },
    (a) => { a.compartmentId = "compartmentother"; },
    (a) => { a.backupId = "backupother"; },
    (a) => { a.indexSha256 = "0".repeat(64); },
    (a) => { a.manifestSha256 = "0".repeat(64); },
  ]) {
    const a = JSON.parse(original.toString("utf8"));
    mutate(a);
    fs.writeFileSync(approvalPath, encode(a));
    blocked(inspect(f), "OWNER_BACKUP_AUTHORIZATION_INVALID");
  }
  fs.writeFileSync(approvalPath, original);
  const indexPath = path.join(f.dir, "backup-index.json");
  const modified = JSON.parse(fs.readFileSync(indexPath, "utf8"));
  modified.copyIds.reverse(); // Same set and hashes, but exact signed index bytes have changed.
  fs.writeFileSync(indexPath, encode(modified));
  blocked(inspect(f), "OWNER_BACKUP_AUTHORIZATION_INVALID");
});

test("stale epoch, replayed revision, wrong compartment and untrusted checkpoint are denied", (t) => {
  const f = fixture(t);
  blocked(inspect(f, { checkpoint: { epoch: 4, revision: 7 } }), "STALE_OR_REPLAYED_MANIFEST");
  blocked(inspect(f, { checkpoint: { epoch: 4, revision: 9 } }), "STALE_OR_REPLAYED_MANIFEST");
  blocked(inspect(f, { checkpoint: { epoch: 5, revision: 1 } }), "STALE_OR_REPLAYED_MANIFEST");
  blocked(inspect(f, { checkpoint: null }), "CHECKPOINT_REQUIRED");
  blocked(inspect(f, { expectedCompartmentId: "other" }), "COMPARTMENT_MISMATCH");
  assert.equal(inspect(f).fixtureVerified, true);
});

test("changed manifest, index, replayed backup identity and duplicate fields are rejected", (t) => {
  const f = fixture(t);
  f.manifest.revision = 99;
  fs.writeFileSync(path.join(f.dir, "manifest.json"), encode(f.manifest));
  blocked(inspect(f), "MANIFEST_DIGEST_MISMATCH");
  f.persist();
  f.manifest.backupId = "backupother";
  fs.writeFileSync(path.join(f.dir, "manifest.json"), encode(f.manifest));
  blocked(inspect(f), "MANIFEST_DIGEST_MISMATCH");
  f.persist();
  const doubled = '{"schema":"rootark-zk1-backup-pre-restore-fixture/v1","backupId":"backupone","backupId":"duplicate"}';
  fs.writeFileSync(path.join(f.dir, "manifest.json"), doubled);
  const index = JSON.parse(fs.readFileSync(path.join(f.dir, "backup-index.json"), "utf8"));
  index.manifestSha256 = sha(Buffer.from(doubled));
  fs.writeFileSync(path.join(f.dir, "backup-index.json"), encode(index));
  blocked(inspect(f), "MALFORMED_METADATA");
});

test("corrupted version, backup copy and recovery/owner envelope are refused", (t) => {
  for (const [folder, filename, expected] of [
    ["versions", "vone.ct", "VERSION_DIGEST_MISMATCH"],
    ["copies", "copyvone.ct", "COPY_DIGEST_MISMATCH"],
    ["envelopes", "ownvone.env", "ENVELOPE_DIGEST_MISMATCH"],
    ["envelopes", "recvone.env", "ENVELOPE_DIGEST_MISMATCH"],
  ]) {
    const f = fixture(t);
    fs.writeFileSync(path.join(f.dir, folder, filename), "corrupted-synthetic-copy");
    blocked(inspect(f), expected);
  }
});

test("missing copy, missing versions, missing owner/recovery envelopes, and undeclared extra files refuse", (t) => {
  for (const [folder, filename] of [
    ["versions", "vone.ct"], ["copies", "copyvone.ct"],
    ["envelopes", "ownvone.env"], ["envelopes", "recvone.env"],
  ]) {
    const f = fixture(t);
    fs.rmSync(path.join(f.dir, folder, filename));
    blocked(inspect(f), "INVENTORY_INCOMPLETE");
  }
  for (const folder of ["versions", "copies", "envelopes", "."]) {
    const f = fixture(t);
    fs.writeFileSync(path.join(f.dir, folder, "undeclared.bin"), "synthetic");
    blocked(inspect(f), "UNEXPECTED_FIXTURE_ENTRY");
  }
});

test("version chain gaps, duplicate IDs, owner/recovery alias and archive manifest mismatch refuse", (t) => {
  const changes = [
    (m) => { m.objects[0].versions[1].sequence = 3; },
    (m) => { m.objects[0].versions[1].parentVersionId = null; },
    (m) => { m.objects[0].versions[1].versionId = "vone"; },
    (m) => { m.objects[0].versions[1].ownerEnvelopeId = m.objects[0].versions[1].recoveryEnvelopeId; },
    (m) => { m.objects[0].versions.length = 1; },
    (m) => { m.objects[0].versions[1].copyId = m.objects[0].versions[0].copyId; },
  ];
  for (const change of changes) {
    const f = fixture(t);
    change(f.manifest);
    f.persist();
    const result = inspect(f);
    assert.equal(result.restoreAuthorized, false);
    assert.equal(result.fixtureVerified, false, "bad structural relationship must not pass");
  }
});

test("plaintext and key-material indicators refuse without echoing payloads", (t) => {
  for (const phrase of ["ROOTARK_TEST_PLAINTEXT_MARKER", "-----BEGIN PRIVATE KEY-----",
    '"privateKey":"synthetic"', '"password":"synthetic"']) {
    const f = fixture(t);
    const pathname = path.join(f.dir, "copies", "copyvone.ct");
    const content = Buffer.from(phrase);
    fs.writeFileSync(pathname, content);
    f.manifest.objects[0].versions[0].ciphertextSha256 = sha(content);
    fs.writeFileSync(path.join(f.dir, "versions", "vone.ct"), content);
    f.persist();
    const report = inspect(f);
    blocked(report, "POSSIBLE_PLAINTEXT_OR_KEY_LEAK");
    assert.equal(JSON.stringify(report).includes(phrase), false);
  }
});

test("fixture-only confinement: ZIP files, outside-temp folders, traversal and symlinks fail safely", (t) => {
  const f = fixture(t);
  blocked(inspect(f, { fixtureDir: path.join(f.dir, "backup.zip") }), "UNSAFE_FIXTURE");
  blocked(inspect(f, { fixtureDir: path.resolve(f.dir, "..") }), "UNSAFE_FIXTURE");
  const hostile = ["../escape", "back/track", "C:\\host", "__proto__"];
  for (const value of hostile) {
    const bad = fixture(t);
    bad.manifest.objects[0].versions[0].versionId = value;
    bad.persist();
    blocked(inspect(bad), "MALFORMED_METADATA");
  }
  const bad = fixture(t);
  fs.rmSync(path.join(bad.dir, "copies", "copyvone.ct"));
  try { fs.symlinkSync(path.join(bad.dir, "versions", "vone.ct"), path.join(bad.dir, "copies", "copyvone.ct"), "file"); }
  catch (error) { if (["EPERM", "EACCES"].includes(error.code)) return; throw error; }
  blocked(inspect(bad), "UNEXPECTED_FIXTURE_ENTRY");
});

test("a symlinked container or hardlinked metadata/payload cannot serve as backup evidence", (t) => {
  const hardlink = fixture(t);
  fs.linkSync(path.join(hardlink.dir, "manifest.json"), path.join(hardlink.dir, "extra-manifest-link"));
  blocked(inspect(hardlink), "UNEXPECTED_FIXTURE_ENTRY");
  fs.rmSync(path.join(hardlink.dir, "extra-manifest-link"));
  fs.linkSync(path.join(hardlink.dir, "versions", "vone.ct"),
    path.join(hardlink.dir, "copies", "extra-hardlink.ct"));
  blocked(inspect(hardlink), "UNEXPECTED_FIXTURE_ENTRY");
  fs.rmSync(path.join(hardlink.dir, "copies", "extra-hardlink.ct"));
  const sibling = path.join(hardlink.dir, "copies", "copyvone.ct");
  fs.rmSync(sibling);
  fs.linkSync(path.join(hardlink.dir, "versions", "vone.ct"), sibling);
  blocked(inspect(hardlink), "INVENTORY_INCOMPLETE");
  const symlink = fixture(t);
  fs.rmSync(path.join(symlink.dir, "versions"), { force: true, recursive: true });
  try { fs.symlinkSync(path.join(symlink.dir, "copies"), path.join(symlink.dir, "versions"), "junction"); }
  catch (error) { if (["EPERM", "EACCES"].includes(error.code)) return; throw error; }
  blocked(inspect(symlink), "UNEXPECTED_FIXTURE_ENTRY");
});

test("directory replacement during inventory enumeration cannot verify externally linked signed ciphertext", (t) => {
  const f = fixture(t);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-backup-race-outside-"));
  const detached = path.join(outside, "detached-original");
  const externalVersions = path.join(outside, "attacker-versions");
  fs.mkdirSync(externalVersions);
  for (const name of fs.readdirSync(path.join(f.dir, "versions"))) {
    fs.copyFileSync(path.join(f.dir, "versions", name), path.join(externalVersions, name));
  }
  t.after(() => fs.rmSync(outside, { force: true, recursive: true }));
  const versionsDir = fs.realpathSync.native(path.join(f.dir, "versions"));
  const realReaddir = fs.readdirSync;
  let swapped = false;
  fs.readdirSync = function (target, options) {
    if (!swapped && path.resolve(target) === versionsDir && options?.withFileTypes) {
      fs.renameSync(versionsDir, detached);
      try { fs.symlinkSync(externalVersions, versionsDir, process.platform === "win32" ? "junction" : "dir"); }
      catch (error) {
        fs.renameSync(detached, versionsDir);
        throw error;
      }
      swapped = true;
    }
    return realReaddir.apply(this, arguments);
  };
  let report;
  try { report = inspect(f); }
  finally {
    fs.readdirSync = realReaddir;
    if (swapped) {
      fs.rmSync(versionsDir, { force: true });
      fs.renameSync(detached, versionsDir);
    }
  }
  assert.equal(swapped, true, "the signed external ciphertext directory was actually traversed");
  blocked(report, "UNSAFE_FIXTURE");
});

test("directory ABA replacement restored before enumeration returns invalidates parent metadata", (t) => {
  const f = fixture(t);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-backup-race-aba-"));
  const detached = path.join(outside, "original");
  const other = path.join(outside, "external");
  fs.mkdirSync(other);
  const versionsDir = fs.realpathSync.native(path.join(f.dir, "versions"));
  for (const name of fs.readdirSync(versionsDir))
    fs.copyFileSync(path.join(versionsDir, name), path.join(other, name));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  const originalReaddir = fs.readdirSync;
  let swapped = false;
  fs.readdirSync = function (target, options) {
    if (!swapped && path.resolve(target) === versionsDir && options?.withFileTypes) {
      swapped = true;
      fs.renameSync(versionsDir, detached);
      try {
        fs.symlinkSync(other, versionsDir, process.platform === "win32" ? "junction" : "dir");
        return originalReaddir.apply(this, arguments);
      } finally {
        if (fs.lstatSync(versionsDir).isSymbolicLink()) fs.rmSync(versionsDir);
        fs.renameSync(detached, versionsDir);
      }
    }
    return originalReaddir.apply(this, arguments);
  };
  let report;
  try { report = inspect(f); }
  finally { fs.readdirSync = originalReaddir; }
  assert.equal(swapped, true);
  blocked(report, "UNSAFE_FIXTURE");
});

test("ancestor replacement immediately after an opened ciphertext read is rejected", (t) => {
  const f = fixture(t);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-backup-race-read-"));
  const detached = path.join(outside, "original");
  const other = path.join(outside, "external");
  fs.mkdirSync(other);
  const versionsDir = fs.realpathSync.native(path.join(f.dir, "versions"));
  for (const name of fs.readdirSync(versionsDir))
    fs.copyFileSync(path.join(versionsDir, name), path.join(other, name));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  const originalRead = fs.readFileSync;
  let reads = 0;
  let swapped = false;
  let renameBlocked = false;
  fs.readFileSync = function (target) {
    const result = originalRead.apply(this, arguments);
    if (typeof target === "number" && ++reads === 5) {
      try {
        fs.renameSync(versionsDir, detached);
        fs.symlinkSync(other, versionsDir, process.platform === "win32" ? "junction" : "dir");
        swapped = true;
      } catch (error) {
        if (!fs.existsSync(versionsDir) && fs.existsSync(detached))
          fs.renameSync(detached, versionsDir);
        if (process.platform === "win32" && ["EPERM", "EACCES", "EBUSY"].includes(error.code)) {
          renameBlocked = true;
        }
        throw error;
      }
    }
    return result;
  };
  let report;
  try { report = inspect(f); }
  finally {
    fs.readFileSync = originalRead;
    if (swapped) {
      fs.rmSync(versionsDir, { force: true });
      fs.renameSync(detached, versionsDir);
    }
  }
  assert.equal(swapped || renameBlocked, true,
    `file descriptor reads=${reads}; findings=${JSON.stringify(report.findings)}`);
  blocked(report, swapped ? "UNSAFE_FIXTURE" : "INVENTORY_INCOMPLETE");
});

test("metadata leak patterns, unexpected fields and unsupported modes cannot be trusted", (t) => {
  const f = fixture(t);
  const raw = JSON.parse(fs.readFileSync(path.join(f.dir, "backup-index.json"), "utf8"));
  raw.secretKey = "synthetic placeholder";
  fs.writeFileSync(path.join(f.dir, "backup-index.json"), encode(raw));
  blocked(inspect(f), "POSSIBLE_PLAINTEXT_OR_KEY_LEAK");
  const extra = fixture(t);
  extra.manifest.objects[0].versions[0].unsupportedSuite = "unencrypted";
  extra.persist();
  blocked(inspect(extra), "MALFORMED_METADATA");
});

test("incomplete directory roots and user-provided archive payload paths refuse before touching data", (t) => {
  const f = fixture(t);
  fs.rmSync(path.join(f.dir, "backup-index.json"));
  blocked(inspect(f), "INVENTORY_INCOMPLETE");
  const second = fixture(t);
  blocked(inspect(second, { fixtureDir: path.join(second.dir, "copies", "copyvone.ct") }), "UNSAFE_FIXTURE");
  blocked(inspect(second, { fixtureDir: "/definitely-not-a-rootark-temp-fixture" }), "UNSAFE_FIXTURE");
  assert.equal(inspect(second).fixtureVerified, true);
});
