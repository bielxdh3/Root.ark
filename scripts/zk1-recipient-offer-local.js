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
const COMMON = ["--owned-dir", "--context-module"];
const MODE_KEYS = Object.freeze({
  export: [...COMMON, "--offer", "--grant"],
  redeem: [...COMMON, "--offer", "--output"],
  "redeem-batch": [...COMMON, "--manifest"],
});
const MAX_OUTPUT = 4 * 1024 * 1024;
const MAX_BATCH = 8;
const BATCH_SCHEMA = "rootark-zk1-recipient-object-set-dev/v1";

function deny() { throw Error("ZK_RECIPIENT_OFFER_CLI_DENIED"); }
class BatchIncomplete extends Error {
  constructor(completed, total) {
    super(`ZK_RECIPIENT_BATCH_INCOMPLETE_${completed}_OF_${total}_INSPECT_PRIVATE_OUTPUTS`);
  }
}
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
  if (fields.some((field) => !Object.hasOwn(opts, field))) deny();
  const names = fields.filter((field) => field !== "--owned-dir")
    .map((field) => process.platform === "win32"
      ? opts[field].toLowerCase() : opts[field]);
  if (new Set(names).size !== names.length) deny();
  return { mode, opts };
}
function batchEntries(root, manifestName, contextName) {
  const manifest = strict(files.readJson(root, manifestName), ["schema", "entries"]);
  if (manifest.schema !== BATCH_SCHEMA || !Array.isArray(manifest.entries)
    || manifest.entries.length < 1 || manifest.entries.length > MAX_BATCH) deny();
  const reserved = new Set([contextName, manifestName].map((name) =>
    process.platform === "win32" ? name.toLowerCase() : name));
  const ids = new Set();
  const grants = new Set();
  // Validate the entire selected set before opening any ciphertext, issuing
  // signed HTTP GETs or writing plaintext. Offer claims are only preflight
  // selectors; each item's owner authority is independently verified below.
  return manifest.entries.map((entry) => {
    const { offer: offerName, output: outputName } =
      strict(entry, ["offer", "output"]);
    files.fileAt(root, offerName);
    files.fileAt(root, outputName, false);
    for (const name of [offerName, outputName]) {
      const normalized = process.platform === "win32" ? name.toLowerCase() : name;
      if (reserved.has(normalized)) deny();
      reserved.add(normalized);
    }
    const offer = files.readJson(root, offerName);
    if (offer?.schema !== "rootark-zk1-recipient-share-offer-dev/v1"
      || offer?.authorizesProductionIo !== false
      || offer?.externalCustodyProven !== false
      || typeof offer?.metadata?.object_id !== "string"
      || !offer.metadata.object_id
      || typeof offer?.grant?.grantId !== "string"
      || !offer.grant.grantId
      || ids.has(offer.metadata.object_id) || grants.has(offer.grant.grantId)) deny();
    ids.add(offer.metadata.object_id);
    grants.add(offer.grant.grantId);
    return { offer, outputName };
  });
}
function privateOutput(root, name, bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1
    || bytes.byteLength > MAX_OUTPUT) deny();
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
async function redeemBatch(root, opts, trustedBuilder) {
  const entries = batchEntries(root, opts["--manifest"], opts["--context-module"]);
  let completed = 0;
  for (const entry of entries) {
    let opened;
    try {
      // The trusted source must produce a fresh recipient session and live
      // independent authority for each owner-issued object grant.
      const trusted = strict(await trustedBuilder("redeem", entry.offer), REDEEM_KEYS);
      opened = await openPortableProtectedRecipientShareFile({
        ...trusted, offer: entry.offer,
      });
      if (opened.authorizesProductionIo !== false
        || opened.externalCustodyProven !== false
        || opened.ownerGrantSignatureVerified !== true
        || opened.ownerCekTransferVerified !== true) deny();
      privateOutput(root, entry.outputName, opened.data);
      completed++;
    } catch (_) {
      // Already completed files remain private and intact; a failed write
      // might have left an incomplete leaf. No atomicity/rollback is claimed.
      throw new BatchIncomplete(completed, entries.length);
    } finally {
      if (opened?.data instanceof Uint8Array) opened.data.fill(0);
    }
  }
  return `ZK_RECIPIENT_BATCH_REDEEMED_${completed}_OF_${entries.length}`;
}
async function run(argv) {
  let opened;
  try {
    const { mode, opts } = parse(argv);
    const root = files.safeDir(opts["--owned-dir"]);
    const moduleFile = files.trustedContextFile(root, opts["--context-module"]);
    const trustedBuilder = require(moduleFile);
    if (typeof trustedBuilder !== "function") deny();
    if (mode === "redeem-batch") {
      return await redeemBatch(root, opts, trustedBuilder);
    }
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
  } catch (error) {
    if (error instanceof BatchIncomplete) throw error;
    deny();
  }
  finally {
    opened?.data?.fill(0);
  }
}
if (require.main === module) {
  run(process.argv.slice(2)).then((status) => {
    process.stdout.write(status + "\n");
  }).catch((error) => {
    // No paths, server responses, account names, secret-bearing stack traces
    // or content bytes are included in process output.
    process.stderr.write((error instanceof BatchIncomplete
      ? error.message : "ZK_RECIPIENT_OFFER_CLI_DENIED") + "\n");
    process.exitCode = 1;
  });
}
module.exports = { run, parse };
