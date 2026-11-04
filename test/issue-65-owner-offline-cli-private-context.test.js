"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { execFileSync } = require("node:child_process");
const ownerCli = require("../scripts/zk1-owner-offline-enroll-local");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

test("owner offline ceremony requires an owner-private directory and executable context module", (t) => {
  if (process.platform === "win32") return t.skip("POSIX mode fixture");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-offline-context-mode-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const moduleFile = path.join(root, "owner-context.js");
  fs.writeFileSync(moduleFile, "module.exports = async () => ({});\n", { mode: 0o600 });
  fs.chmodSync(root, 0o700);
  fs.chmodSync(moduleFile, 0o600);
  assert.equal(ownerCli.safeDir(root), root);
  assert.equal(ownerCli.trustedContextFile(root, "owner-context.js"), moduleFile);
  for (const mode of [0o777, 0o770, 0o755, 0o711]) {
    fs.chmodSync(root, mode);
    assert.throws(() => ownerCli.safeDir(root), /ZK_OWNER_LOCAL_CLI_DENIED/, `directory mode ${mode.toString(8)} must deny`);
  }
  fs.chmodSync(root, 0o700);
  for (const mode of [0o666, 0o660, 0o644, 0o604]) {
    fs.chmodSync(moduleFile, mode);
    assert.throws(() => ownerCli.trustedContextFile(root, "owner-context.js"),
      /ZK_OWNER_LOCAL_CLI_DENIED|ZK_AUTHORITY_FILE_UNTRUSTED/, `context mode ${mode.toString(8)} must deny`);
  }
  fs.chmodSync(moduleFile, 0o600);
  assert.equal(ownerCli.trustedContextFile(root, "owner-context.js"), moduleFile);
});

test("owner offline ceremony rejects real other-UID mutation of executable context", (t) => {
  if (process.platform !== "linux" || !process.getuid || process.getuid() !== 0
    || !fs.existsSync("/usr/sbin/runuser")) return t.skip("requires Linux root and runuser");
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-offline-uid-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const root = path.join(parent, "owner");
  fs.chmodSync(parent, 0o755);
  fs.mkdirSync(root, { mode: 0o755 });
  const file = path.join(root, "owner-context.js");
  fs.writeFileSync(file, "module.exports = () => ({trusted:true});\n", { mode: 0o666 });
  fs.chmodSync(file, 0o666);
  execFileSync("/usr/sbin/runuser", ["-u", "nobody", "--", "sh", "-c",
    'printf "module.exports = () => ({hostile:true});\\n" > "$1"', "sh", file]);
  assert.match(fs.readFileSync(file, "utf8"), /hostile/);
  assert.throws(() => ownerCli.safeDir(root), /ZK_OWNER_LOCAL_CLI_DENIED/);
  fs.chmodSync(root, 0o700);
  assert.throws(() => ownerCli.trustedContextFile(root, "owner-context.js"),
    /ZK_OWNER_LOCAL_CLI_DENIED|ZK_AUTHORITY_FILE_UNTRUSTED/);
  fs.chmodSync(file, 0o600);
  assert.equal(ownerCli.trustedContextFile(root, "owner-context.js"), file);
});

test("owner offline context rejects symlink directory, symlink file and multi-linked executable", (t) => {
  if (process.platform === "win32") return t.skip("POSIX link fixture");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-offline-owner-links-"));
  const alias = `${root}-alias`;
  t.after(() => {
    fs.rmSync(alias, { force: true });
    fs.rmSync(root, { recursive: true, force: true });
  });
  const file = path.join(root, "owner-context.js");
  fs.writeFileSync(file, "module.exports = () => ({});\n", { mode: 0o600 });
  assert.equal(ownerCli.trustedContextFile(root, "owner-context.js"), file);
  fs.symlinkSync(root, alias, "dir");
  assert.throws(() => ownerCli.safeDir(alias));
  fs.symlinkSync(file, path.join(root, "symlink-context.js"));
  assert.throws(() => ownerCli.trustedContextFile(root, "symlink-context.js"));
  const shadow = path.join(root, "shadow.js");
  fs.linkSync(file, shadow);
  assert.throws(() => ownerCli.trustedContextFile(root, "owner-context.js"));
});

test("Windows native ACL denies unrelated SID Modify on trusted owner module or directory", (t) => {
  if (process.platform !== "win32") return t.skip("native NTFS only");
  const privateFileRoot = createPrivateAuthorityFixture("rootark-owner-cli-file-acl-");
  const privateDirRoot = createPrivateAuthorityFixture("rootark-owner-cli-dir-acl-");
  t.after(() => {
    fs.rmSync(privateFileRoot, { recursive: true, force: true, maxRetries: 6 });
    fs.rmSync(privateDirRoot, { recursive: true, force: true, maxRetries: 6 });
  });
  const source = "module.exports = () => ({});\n";
  const file = path.join(privateFileRoot, "owner-context.js");
  fs.writeFileSync(file, source);
  assert.equal(ownerCli.safeDir(privateFileRoot), privateFileRoot);
  assert.equal(ownerCli.trustedContextFile(privateFileRoot, "owner-context.js"), file);
  execFileSync("icacls.exe", [file, "/grant", "*S-1-5-32-545:M"], { stdio: "ignore", windowsHide: true });
  assert.throws(() => ownerCli.trustedContextFile(privateFileRoot, "owner-context.js"));
  assert.equal(ownerCli.safeDir(privateDirRoot), privateDirRoot);
  execFileSync("icacls.exe", [privateDirRoot, "/grant", "*S-1-5-32-545:(OI)(CI)M"],
    { stdio: "ignore", windowsHide: true });
  assert.throws(() => ownerCli.safeDir(privateDirRoot));
});
