"use strict";

// Owner-side tool. No witness/CAS service imports and no network operations.
// The operator independently retains the minimum and provisions all keys.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const checkpoint = require("../src/crypto/rootark-zk1-owner-cas-floor-checkpoint");

const PIN_OWNER = "ROOTARK_ZK1_CAS_FLOOR_OWNER_SPKI_SHA256";
const PIN_CHECKPOINT = "ROOTARK_ZK1_CAS_FLOOR_OWNER_CHECKPOINT_SHA256";
const FLAGS = ["--owned-dir", "--input", "--owner-private-key", "--owner-public-key",
  "--witness-public-key", "--status-public-key", "--output", "--confirm-independent-minimum"];
const MAX_FILE = 65536;
function fail() { throw new Error("OWNER_FLOOR_SIGN_FAILED"); }

function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))
    || Reflect.ownKeys(value).some((field) => !fields.includes(field))) fail();
}

function parseArgs(argv) {
  if (argv.length !== (FLAGS.length * 2) - 1) fail();
  const args = Object.create(null);
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    if (!FLAGS.includes(flag) || Object.hasOwn(args, flag)) fail();
    if (flag === "--confirm-independent-minimum") {
      if (i !== argv.length - 1) fail();
      args[flag] = true;
      break;
    }
    if (typeof argv[i + 1] !== "string" || argv[i + 1].length === 0) fail();
    args[flag] = argv[i + 1];
  }
  if (FLAGS.some((flag) => !Object.hasOwn(args, flag))) fail();
  return args;
}

function noSymlinkComponents(location, io = fs) {
  const absolute = path.resolve(location);
  const root = path.parse(absolute).root;
  let current = root;
  for (const segment of absolute.slice(root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const stat = io.lstatSync(current);
    if (stat.isSymbolicLink()) fail();
  }
}

function within(root, candidate, exists = true, io = fs) {
  if (typeof candidate !== "string" || !path.isAbsolute(candidate)) fail();
  const absolute = path.resolve(candidate);
  const relative = path.relative(root, absolute);
  if (!relative || relative === ".." || relative.startsWith(".." + path.sep)
    || path.isAbsolute(relative)) fail();
  noSymlinkComponents(exists ? absolute : path.dirname(absolute), io);
  const resolved = io.realpathSync.native(exists ? absolute : path.dirname(absolute));
  const target = exists ? resolved : path.join(resolved, path.basename(absolute));
  const canonicalRelative = path.relative(root, target);
  if (!canonicalRelative || canonicalRelative === ".."
    || canonicalRelative.startsWith(".." + path.sep)
    || path.isAbsolute(canonicalRelative)) fail();
  return absolute;
}

function sameFile(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size
    && a.mtimeMs === b.mtimeMs;
}

// Snapshot the directory identities, including the ancestors of --owned-dir.
// A junction substituted between path validation and open must not authorize an FD.
function directoryChain(location, io = fs) {
  const absolute = path.resolve(location);
  const volume = path.parse(absolute).root;
  let current = volume;
  const paths = [volume];
  for (const component of absolute.slice(volume.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    paths.push(current);
  }
  return paths.map((dir) => {
    const info = io.lstatSync(dir);
    if (!info.isDirectory() || info.isSymbolicLink()) fail();
    const canonical = io.realpathSync.native(dir);
    const normalize = (value) => process.platform === "win32"
      ? path.resolve(value).toLowerCase() : path.resolve(value);
    if (normalize(canonical) !== normalize(dir)) fail();
    return { dir, dev: info.dev, ino: info.ino };
  });
}

function checkDirectories(chain, io = fs) {
  for (const { dir, dev, ino } of chain) {
    const info = io.lstatSync(dir);
    if (!info.isDirectory() || info.isSymbolicLink()
      || info.dev !== dev || info.ino !== ino) fail();
    const resolved = io.realpathSync.native(dir);
    const normalize = (value) => process.platform === "win32"
      ? path.resolve(value).toLowerCase() : path.resolve(value);
    if (normalize(resolved) !== normalize(dir)) fail();
  }
}

function checkOpenedPath(root, file, chain, opened, io = fs) {
  checkDirectories(chain, io);
  const atPath = io.lstatSync(file);
  if (!atPath.isFile() || atPath.isSymbolicLink() || !sameFile(opened, atPath)) fail();
  within(root, file, true, io);
  checkDirectories(chain, io);
}

function readOwned(root, file, chain, io = fs) {
  // Open first and authorize the FD before reading any file contents. A path
  // check alone followed by open is vulnerable to Windows junction swaps.
  const fd = io.openSync(file, io.constants.O_RDONLY
    | (io.constants.O_NOFOLLOW || 0) | (io.constants.O_NONBLOCK || 0));
  let buffer;
  try {
    const opened = io.fstatSync(fd);
    if (!opened.isFile() || opened.size <= 0 || opened.size > MAX_FILE) fail();
    checkOpenedPath(root, file, chain, opened, io);
    buffer = io.readFileSync(fd);
    if (buffer.length !== opened.size) fail();
    if (!sameFile(opened, io.fstatSync(fd))) fail();
    checkOpenedPath(root, file, chain, opened, io);
    const result = buffer;
    buffer = undefined;
    return result;
  } finally {
    if (buffer) buffer.fill(0);
    io.closeSync(fd);
  }
}

function keyId(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(value)) fail();
  const buffer = Buffer.from(value, "base64url");
  if (buffer.length !== 16 || buffer.toString("base64url") !== value) fail();
}

function publicEd25519(buffer) {
  const key = crypto.createPublicKey(buffer);
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") fail();
  return key;
}

function run(argv, now = Math.floor(Date.now() / 1000), io = fs) {
  const args = parseArgs(argv);
  const ownedDir = args["--owned-dir"];
  if (!path.isAbsolute(ownedDir)) fail();
  noSymlinkComponents(ownedDir, io);
  const ownedStat = io.lstatSync(ownedDir);
  if (!ownedStat.isDirectory() || ownedStat.isSymbolicLink()) fail();
  const root = io.realpathSync.native(ownedDir);
  const inputPath = within(root, args["--input"], true, io);
  const ownerPrivPath = within(root, args["--owner-private-key"], true, io);
  const ownerPubPath = within(root, args["--owner-public-key"], true, io);
  const witnessPubPath = within(root, args["--witness-public-key"], true, io);
  const statusPubPath = within(root, args["--status-public-key"], true, io);
  const outputPath = within(root, args["--output"], false, io);
  const allPaths = [inputPath, ownerPrivPath, ownerPubPath, witnessPubPath,
    statusPubPath, outputPath].map((name) => path.normalize(name).toLowerCase());
  if (new Set(allPaths).size !== allPaths.length) fail();
  const inputChain = directoryChain(path.dirname(inputPath), io);
  const ownerPrivChain = directoryChain(path.dirname(ownerPrivPath), io);
  const ownerPubChain = directoryChain(path.dirname(ownerPubPath), io);
  const witnessPubChain = directoryChain(path.dirname(witnessPubPath), io);
  const statusPubChain = directoryChain(path.dirname(statusPubPath), io);
  const outputChain = directoryChain(path.dirname(outputPath), io);

  const inputBytes = readOwned(root, inputPath, inputChain, io);
  let data;
  try { data = JSON.parse(inputBytes.toString("utf8")); }
  finally { inputBytes.fill(0); }
  exact(data, ["source", "witnessKeyId", "statusKeyId", "trustedMinimumHead",
    "issuedAt", "expiresAt"]);
  if (data.source !== "owner-retained-independent-floor/v1") fail();
  exact(data.trustedMinimumHead, ["sequence", "lastHash"]);
  keyId(data.witnessKeyId);
  keyId(data.statusKeyId);
  if (data.witnessKeyId === data.statusKeyId) fail();
  const { sequence, lastHash } = data.trustedMinimumHead;
  if (!Number.isSafeInteger(sequence) || sequence < 0 || sequence > 100000
    || typeof lastHash !== "string" || !/^[a-f0-9]{64}$/.test(lastHash)
    || (sequence === 0) !== (lastHash === "0".repeat(64))) fail();
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(data.issuedAt)
    || !Number.isSafeInteger(data.expiresAt)
    || data.issuedAt < now - 120 || data.issuedAt > now + 60
    || data.expiresAt <= now || data.expiresAt <= data.issuedAt
    || data.expiresAt - data.issuedAt > 3600) fail();

  const ownerPub = publicEd25519(readOwned(root, ownerPubPath, ownerPubChain, io));
  const witnessPub = publicEd25519(readOwned(root, witnessPubPath, witnessPubChain, io));
  const statusPub = publicEd25519(readOwned(root, statusPubPath, statusPubChain, io));
  const ownerSpki = ownerPub.export({ type: "spki", format: "der" });
  const witnessSpki = witnessPub.export({ type: "spki", format: "der" });
  const statusSpki = statusPub.export({ type: "spki", format: "der" });
  if (ownerSpki.equals(witnessSpki) || ownerSpki.equals(statusSpki)
    || witnessSpki.equals(statusSpki)) fail();
  const privatePem = readOwned(root, ownerPrivPath, ownerPrivChain, io);
  let ownerPriv;
  try { ownerPriv = crypto.createPrivateKey(privatePem); }
  finally { privatePem.fill(0); }
  if (ownerPriv.type !== "private" || ownerPriv.asymmetricKeyType !== "ed25519"
    || !crypto.createPublicKey(ownerPriv).export({ type: "spki", format: "der" })
      .equals(ownerSpki)) fail();

  const signedStatement = checkpoint.statement({
    witnessKeyId: data.witnessKeyId, statusKeyId: data.statusKeyId,
    witnessSpkiSha256: checkpoint.spkiFingerprint(witnessPub).toString("hex"),
    statusSpkiSha256: checkpoint.spkiFingerprint(statusPub).toString("hex"),
    sequence, lastHash, issuedAt: data.issuedAt, expiresAt: data.expiresAt,
  });
  const signature = crypto.sign(null, checkpoint.signingBytes(signedStatement), ownerPriv);
  if (signature.length !== 64 || !crypto.verify(null,
    checkpoint.signingBytes(signedStatement), ownerPub, signature)) fail();
  const artifact = {
    casAnchorFloor: {
      trustedMinimumHead: { sequence, lastHash },
      owner: { publicKeyPath: ownerPubPath, issuedAt: data.issuedAt,
        expiresAt: data.expiresAt, signature: signature.toString("base64url") },
    },
    envPins: {
      [PIN_OWNER]: checkpoint.spkiFingerprint(ownerPub).toString("hex"),
      [PIN_CHECKPOINT]: checkpoint.checkpointDigest(signedStatement, signature).toString("hex"),
    },
  };

  // An exclusive create never replaces an existing checkpoint. No file names,
  // private-key data, or input contents are emitted to the console on errors.
  // The new FD is empty and exclusive. Authorize its identity and ancestor
  // chain BEFORE writing signed material; recheck after fsync as well.
  const handle = io.openSync(outputPath, io.constants.O_WRONLY | io.constants.O_CREAT
    | io.constants.O_EXCL | (io.constants.O_NOFOLLOW || 0), 0o600);
  let completed = false;
  try {
    const opened = io.fstatSync(handle);
    if (!opened.isFile() || opened.size !== 0 || opened.nlink !== 1) fail();
    checkOpenedPath(root, outputPath, outputChain, opened, io);
    io.writeFileSync(handle, JSON.stringify(artifact, null, 2) + "\n", "utf8");
    io.fsyncSync(handle);
    checkOpenedPath(root, outputPath, outputChain, io.fstatSync(handle), io);
    completed = true;
  } finally {
    // Exclusive create proves this pathname did not exist at open. On an
    // aborted create, remove only the very same file we opened if still named
    // there; never follow a replacement symlink or delete a different inode.
    let abortedIdentity;
    if (!completed) {
      try {
        const opened = io.fstatSync(handle);
        const named = io.lstatSync(outputPath);
        if (named.isFile() && !named.isSymbolicLink()
          && opened.dev === named.dev && opened.ino === named.ino) {
          abortedIdentity = { dev: opened.dev, ino: opened.ino };
        }
      } catch (_) { /* A vanished or replaced file is never a cleanup target. */ }
    }
    io.closeSync(handle);
    if (abortedIdentity) {
      try {
        const named = io.lstatSync(outputPath);
        if (named.isFile() && !named.isSymbolicLink()
          && named.dev === abortedIdentity.dev && named.ino === abortedIdentity.ino) {
          io.unlinkSync(outputPath);
        }
      } catch (_) { /* Fail closed: never delete an unknown replacement. */ }
    }
  }
  process.stdout.write("OWNER_FLOOR_SIGNED\n");
}

if (require.main === module) {
  try { run(process.argv.slice(2)); }
  catch (_) { process.stderr.write("OWNER_FLOOR_SIGN_FAILED\n"); process.exitCode = 1; }
}

module.exports = { run };
