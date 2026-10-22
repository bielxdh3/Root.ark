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

function noSymlinkComponents(location) {
  const absolute = path.resolve(location);
  const root = path.parse(absolute).root;
  let current = root;
  for (const segment of absolute.slice(root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) fail();
  }
}

function within(root, candidate, exists = true) {
  if (typeof candidate !== "string" || !path.isAbsolute(candidate)) fail();
  const absolute = path.resolve(candidate);
  const relative = path.relative(root, absolute);
  if (!relative || relative === ".." || relative.startsWith(".." + path.sep)
    || path.isAbsolute(relative)) fail();
  noSymlinkComponents(exists ? absolute : path.dirname(absolute));
  const resolved = fs.realpathSync.native(exists ? absolute : path.dirname(absolute));
  const target = exists ? resolved : path.join(resolved, path.basename(absolute));
  const canonicalRelative = path.relative(root, target);
  if (!canonicalRelative || canonicalRelative === ".."
    || canonicalRelative.startsWith(".." + path.sep)
    || path.isAbsolute(canonicalRelative)) fail();
  return absolute;
}

function readOwned(root, name) {
  const file = within(root, name);
  const before = fs.lstatSync(file);
  if (!before.isFile() || before.size <= 0 || before.size > MAX_FILE) fail();
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.size !== before.size
      || opened.ino !== before.ino || opened.dev !== before.dev) fail();
    const buffer = fs.readFileSync(fd);
    if (buffer.length !== opened.size) fail();
    const after = fs.lstatSync(file);
    if (after.ino !== opened.ino || after.dev !== opened.dev || after.size !== opened.size
      || after.mtimeMs !== opened.mtimeMs) fail();
    within(root, file);
    return buffer;
  } finally { fs.closeSync(fd); }
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

function run(argv, now = Math.floor(Date.now() / 1000)) {
  const args = parseArgs(argv);
  const ownedDir = args["--owned-dir"];
  if (!path.isAbsolute(ownedDir)) fail();
  noSymlinkComponents(ownedDir);
  const ownedStat = fs.lstatSync(ownedDir);
  if (!ownedStat.isDirectory() || ownedStat.isSymbolicLink()) fail();
  const root = fs.realpathSync.native(ownedDir);
  const inputPath = within(root, args["--input"]);
  const ownerPrivPath = within(root, args["--owner-private-key"]);
  const ownerPubPath = within(root, args["--owner-public-key"]);
  const witnessPubPath = within(root, args["--witness-public-key"]);
  const statusPubPath = within(root, args["--status-public-key"]);
  const outputPath = within(root, args["--output"], false);
  const allPaths = [inputPath, ownerPrivPath, ownerPubPath, witnessPubPath,
    statusPubPath, outputPath].map((name) => path.normalize(name).toLowerCase());
  if (new Set(allPaths).size !== allPaths.length) fail();
  if (fs.existsSync(outputPath)) fail();

  const inputBytes = readOwned(root, inputPath);
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

  const ownerPub = publicEd25519(readOwned(root, ownerPubPath));
  const witnessPub = publicEd25519(readOwned(root, witnessPubPath));
  const statusPub = publicEd25519(readOwned(root, statusPubPath));
  const ownerSpki = ownerPub.export({ type: "spki", format: "der" });
  const witnessSpki = witnessPub.export({ type: "spki", format: "der" });
  const statusSpki = statusPub.export({ type: "spki", format: "der" });
  if (ownerSpki.equals(witnessSpki) || ownerSpki.equals(statusSpki)
    || witnessSpki.equals(statusSpki)) fail();
  const privatePem = readOwned(root, ownerPrivPath);
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
  within(root, outputPath, false);
  const handle = fs.openSync(outputPath, "wx", 0o600);
  try {
    fs.writeFileSync(handle, JSON.stringify(artifact, null, 2) + "\n", "utf8");
    fs.fsyncSync(handle);
  } finally { fs.closeSync(handle); }
  process.stdout.write("OWNER_FLOOR_SIGNED\n");
}

if (require.main === module) {
  try { run(process.argv.slice(2)); }
  catch (_) { process.stderr.write("OWNER_FLOOR_SIGN_FAILED\n"); process.exitCode = 1; }
}

module.exports = { run };
