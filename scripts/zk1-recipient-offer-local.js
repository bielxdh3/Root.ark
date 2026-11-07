#!/usr/bin/env node
"use strict";

// DEV-OFF local I/O adapter for the independently reviewed #290 primitives.
// There is deliberately NO key import, trust bootstrap, grant creation, or
// server authentication fallback in this CLI. Only a separately provisioned
// private trusted context module may supply live signed history, contact pins,
// owner/recipient secret handles and authenticated HTTP session.
const fs = require("node:fs");
const files = require("./zk1-owner-offline-enroll-local");
const { createProtectedRecipientShareOffer,
  openPortableProtectedRecipientShareFile } =
  require("../src/crypto/rootark-zk1-recipient-share-cek");

const EXPORT_KEYS = ["recipientPin", "issuerPin", "readIndependentAuthority",
  "ownerPrivateKey", "ownerHeldCek", "metadata", "objectRevision",
  "ciphertext", "ciphertextRoot", "authority", "nowSeconds"];
const REDEEM_KEYS = ["redeemInput", "authority", "operatorMinimumSequence",
  "deviceHpkePrivateKey", "nowSeconds"];
const COMMON = ["--owned-dir", "--context-module", "--offer"];
const MODE_KEYS = Object.freeze({
  export: [...COMMON, "--grant"],
  redeem: [...COMMON, "--output"],
});
const MAX_OUTPUT = 4 * 1024 * 1024;

function deny() { throw Error("ZK_RECIPIENT_OFFER_CLI_DENIED"); }
function strict(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== fields.length
    || fields.some((key) => !descriptors[key]
      || !Object.hasOwn(descriptors[key], "value"))) deny();
  return Object.fromEntries(fields.map((key) => [key, descriptors[key].value]));
}
function parse(argv) {
  if (!Array.isArray(argv) || argv.length < 2
    || !Object.hasOwn(MODE_KEYS, argv[0])) deny();
  const mode = argv[0];
  const fields = MODE_KEYS[mode];
  if (argv.length !== 1 + fields.length * 2) deny();
  const opts = Object.create(null);
  for (let i = 1; i < argv.length; i += 2) {
    if (!fields.includes(argv[i]) || Object.hasOwn(opts, argv[i])
      || typeof argv[i + 1] !== "string" || !argv[i + 1]) deny();
    opts[argv[i]] = argv[i + 1];
  }
  if (fields.some((field) => !Object.hasOwn(opts, field))
    || opts["--offer"] === opts["--context-module"]
    || opts["--offer"] === opts["--grant"]
    || opts["--output"] === opts["--offer"]
    || opts["--output"] === opts["--context-module"]) deny();
  return { mode, opts };
}
function privateOutput(root, name, bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_OUTPUT) deny();
  // Refuse an existing name: never clobber recipient plaintext or a trusted
  // input, even when it is a symlink. An exclusive private leaf inherits the
  // already independently verified owner-only directory ACL.
  files.safeDir(root);
  const filename = files.fileAt(root, name, false);
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
    | (fs.constants.O_NOFOLLOW || 0);
  const fd = fs.openSync(filename, flags, 0o600);
  try {
    const initial = fs.fstatSync(fd);
    if (!initial.isFile() || initial.nlink !== 1
      || (process.platform !== "win32" && (initial.mode & 0o077) !== 0)) deny();
    let position = 0;
    while (position < bytes.byteLength) {
      const written = fs.writeSync(fd, bytes, position, bytes.byteLength - position);
      if (!Number.isSafeInteger(written) || written <= 0) deny();
      position += written;
    }
    fs.fsyncSync(fd);
    const final = fs.fstatSync(fd);
    const named = fs.lstatSync(filename);
    if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1
      || final.ino !== initial.ino || final.dev !== initial.dev
      || named.ino !== final.ino || named.dev !== final.dev
      || final.size !== bytes.byteLength || named.size !== final.size) deny();
  } finally {
    // A failed private output may contain a PARTIAL plaintext file. It is
    // deliberately not unlinked by pathname: a concurrent rename could
    // replace the leaf before unlink. The user must inspect their private
    // directory and remove an incomplete artifact themselves.
    fs.closeSync(fd);
  }
}
async function run(argv) {
  let opened;
  try {
    const { mode, opts } = parse(argv);
    const root = files.safeDir(opts["--owned-dir"]);
    const moduleFile = files.trustedContextFile(root, opts["--context-module"]);
    const trustedBuilder = require(moduleFile);
    if (typeof trustedBuilder !== "function") deny();
    if (mode === "export") {
      files.fileAt(root, opts["--offer"], false);
      const grant = files.readJson(root, opts["--grant"]);
      const trusted = strict(await trustedBuilder("export", grant), EXPORT_KEYS);
      const offer = await createProtectedRecipientShareOffer({ ...trusted, grant });
      if (offer.authorizesProductionIo !== false
        || offer.externalCustodyProven !== false) deny();
      files.publishJson(root, opts["--offer"], offer);
      return "ZK_RECIPIENT_OFFER_EXPORTED";
    }
    files.fileAt(root, opts["--output"], false);
    const offer = files.readJson(root, opts["--offer"]);
    const trusted = strict(await trustedBuilder("redeem", offer), REDEEM_KEYS);
    opened = await openPortableProtectedRecipientShareFile({ ...trusted, offer });
    if (opened.authorizesProductionIo !== false
      || opened.externalCustodyProven !== false
      || opened.ownerGrantSignatureVerified !== true
      || opened.ownerCekTransferVerified !== true) deny();
    privateOutput(root, opts["--output"], opened.data);
    return "ZK_RECIPIENT_FILE_REDEEMED";
  } catch (_) { deny(); }
  finally {
    opened?.data?.fill(0);
  }
}
if (require.main === module) {
  run(process.argv.slice(2)).then((status) => {
    process.stdout.write(status + "\n");
  }).catch(() => {
    // No paths, server responses, account names, secret-bearing stack traces
    // or content bytes are included in process output.
    process.stderr.write("ZK_RECIPIENT_OFFER_CLI_DENIED\n");
    process.exitCode = 1;
  });
}
module.exports = { run, parse };
