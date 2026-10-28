#!/usr/bin/env node
"use strict";

// Opt-in OFFLINE owner tool. No HTTP, DB connection, service/admin identity,
// cloud SDK, signing proxy, or fallback key source. Keep THIS PROCESS ALIVE
// across PoP + independently committed-head proof: WeakMap provenance cannot
// be serialized across restarts without lowering assurance.
const fs = require("node:fs");
const path = require("node:path");
const { assertPrivateSqliteDirectory } =
  require("../src/services/zk1PrivateSqlitePath");
const { readAuthorityPinnedFile } =
  require("../src/services/zk1AuthorityPinnedFile");
const { verifyWindowsLocalWebDavDirectory } =
  require("../services/chunkUploadWindowsAcl");
const { executeOwnerEnrollment } =
  require("../src/services/zk1OwnerOfflineEnrollmentOrchestrator");

const PARAMS = ["--owned-dir", "--context-module", "--owner-spki", "--witness-spki",
  "--head-revision", "--head-digest", "--head-epoch", "--prior-receipt-sha256"];
const MAX_INPUT = 65536;
function deny() { throw new Error("ZK_OWNER_LOCAL_CLI_DENIED"); }
function parse(argv) {
  if (argv.length !== PARAMS.length * 2) deny();
  const options = Object.create(null);
  for (let i = 0; i < argv.length; i += 2) {
    if (!PARAMS.includes(argv[i]) || Object.hasOwn(options, argv[i])
      || typeof argv[i + 1] !== "string" || !argv[i + 1]) deny();
    options[argv[i]] = argv[i + 1];
  }
  if (PARAMS.some((name) => !Object.hasOwn(options, name))) deny();
  return options;
}
function walkSafe(root) {
  let current = path.parse(root).root;
  for (const segment of root.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) deny();
  }
}
function safeDir(value) {
  if (!path.isAbsolute(value)) deny();
  const absolute = path.resolve(value);
  walkSafe(absolute);
  if (path.resolve(fs.realpathSync.native(absolute)).toLowerCase()
    !== absolute.toLowerCase()) deny();
  // The directory contains executable trusted operator code AND private
  // signing material supplied to that code. A writable or traversable folder
  // allows a different local UID to replace modules/ceremony inputs. Check
  // every ancestor, then require a private owner-controlled final directory.
  try {
    assertPrivateSqliteDirectory(path.join(absolute, ".rootark-offline-owner-boundary"));
    if (process.platform === "win32") {
      // NTFS mode bits cannot represent an inherited write/delete ACE. Use
      // the existing pinned native owner/DACL/ancestor verification helper.
      verifyWindowsLocalWebDavDirectory(absolute);
    } else {
      const stat = fs.lstatSync(absolute, { bigint: true });
      if (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n) !== 0n) deny();
    }
  } catch (_) { deny(); }
  return absolute;
}
function fileAt(root, filename, mustExist = true) {
  // A CLI-supplied context module is an owner-controlled basename. Without
  // this check ../ escapes the verified private ceremony folder, and a
  // seemingly trusted owner module could be loaded from an unrelated path.
  if (typeof filename !== "string" || !filename || filename.length > 128
    || filename === "." || filename === ".." || filename !== path.basename(filename)
    || /[\\/:\0]/.test(filename) || path.isAbsolute(filename)) deny();
  const value = path.join(root, filename);
  if (mustExist) {
    const stat = fs.lstatSync(value);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
      || stat.size < 1 || stat.size > MAX_INPUT) deny();
  } else if (fs.existsSync(value)) deny();
  return value;
}
function trustedContextFile(root, filename) {
  safeDir(root);
  const modulePath = fileAt(root, filename);
  if (path.extname(modulePath).toLowerCase() !== ".js") deny();
  // The shared authority reader pins file and ancestor identities and checks
  // owner-only POSIX 0600 or native Windows leaf owner/DACL before returning.
  // A trusted owner may still change their own code; less-privileged local
  // principals cannot replace this module after the trust checks.
  let source;
  try {
    source = readAuthorityPinnedFile(modulePath);
  } catch (_) { deny(); }
  finally { source?.fill(0); }
  return modulePath;
}
function readJson(root, filename) {
  const target = fileAt(root, filename);
  const fd = fs.openSync(target, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size < 1 || before.size > MAX_INPUT
      || before.ino !== fs.lstatSync(target).ino) deny();
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    if (after.size !== bytes.length || after.ino !== before.ino
      || fs.lstatSync(target).ino !== before.ino) deny();
    try { return JSON.parse(bytes.toString("utf8")); }
    finally { bytes.fill(0); }
  } finally { fs.closeSync(fd); }
}
function publishJson(root, filename, payload) {
  const destination = fileAt(root, filename, false);
  const bytes = Buffer.from(JSON.stringify(payload) + "\n", "utf8");
  if (bytes.byteLength < 1 || bytes.byteLength > 12 * 1024 * 1024) deny();
  const fd = fs.openSync(destination, fs.constants.O_CREAT | fs.constants.O_EXCL
    | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); bytes.fill(0); }
}
async function awaitJson(root, filename, until) {
  while (Date.now() < until) {
    if (fs.existsSync(path.join(root, filename))) return readJson(root, filename);
    await new Promise((resolve) => setTimeout(resolve, 180));
  }
  deny();
}
async function run(argv) {
  const args = parse(argv);
  const root = safeDir(args["--owned-dir"]);
  const modulePath = trustedContextFile(root, args["--context-module"]);
  // This module IS trusted operator code, never a response from a server.
  // It must reconstruct a REAL branded verifiedHistory using the canonical
  // verifier and provision private keys from offline owner-controlled storage.
  const buildTrusted = require(modulePath);
  if (typeof buildTrusted !== "function") deny();
  const trusted = await buildTrusted();
  const pin = (name) => {
    const value = args[name];
    if (!/^[A-Za-z0-9_-]{43}$/.test(value)
      || Buffer.from(value, "base64url").toString("base64url") !== value) deny();
    return value;
  };
  const unsignedHead = {
    revision: Number(args["--head-revision"]), epoch: Number(args["--head-epoch"]),
    digest: pin("--head-digest"),
    ownerSpkiSha256: pin("--owner-spki"), witnessSpkiSha256: pin("--witness-spki"),
    priorCommitmentSha256: pin("--prior-receipt-sha256"),
  };
  if (!Number.isSafeInteger(unsignedHead.revision) || unsignedHead.revision < 1
    || !Number.isSafeInteger(unsignedHead.epoch) || unsignedHead.epoch < 1) deny();
  const deadline = Date.now() + 280000; // inside the 300-second PoP TTL
  const result = await executeOwnerEnrollment({
    trusted, externalPins: unsignedHead, request: readJson(root, "request.json"),
    publishChallenge: (challenge) => publishJson(root, "challenge.json", challenge),
    awaitTargetPoP: () => awaitJson(root, "response.json", deadline),
    publishCandidate: (candidate) => publishJson(root, "candidate.json", candidate),
    awaitWitnessCommitment: () => awaitJson(root, "committed-receipt.json", deadline),
    publishDelivery: (delivery) => publishJson(root, "browser-delivery.json", delivery),
  });
  return result;
}
if (require.main === module) {
  run(process.argv.slice(2)).then((result) => {
    process.stdout.write(JSON.stringify(result) + "\n");
  }).catch((error) => {
    // An untrusted file, issuer or OS error never logs a secret or parsed input.
    process.stderr.write("ZK_OWNER_LOCAL_CLI_DENIED" +
      (error?.phase ? ":" + error.phase : "") + "\n");
    process.exitCode = 1;
  });
}
module.exports = { run, parse, safeDir, fileAt, trustedContextFile,
  readJson, publishJson, awaitJson };
