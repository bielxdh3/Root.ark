#!/usr/bin/env node
"use strict";
// Offline: no HTTP, cloud SDK, server account keys or key export.
const path = require("node:path");
const shared = require("./zk1-owner-offline-enroll-local");
const { executeOwnerRevocation } = require("../src/services/zk1OwnerOfflineRevocationOrchestrator");

const PARAMS = ["--owned-dir", "--context-module", "--owner-spki", "--witness-spki",
  "--cas-spki", "--cas-sequence", "--head-revision", "--head-digest",
  "--head-epoch", "--prior-receipt-sha256", "--revoke-device"];
function deny() { throw new Error("ZK_OWNER_V2_REVOKE_CLI_DENIED"); }
function parse(argv) {
  if (!Array.isArray(argv) || argv.length !== PARAMS.length * 2) deny();
  const args = Object.create(null);
  for (let i = 0; i < argv.length; i += 2) {
    if (!PARAMS.includes(argv[i]) || Object.hasOwn(args, argv[i])
      || typeof argv[i + 1] !== "string" || !argv[i + 1]) deny();
    args[argv[i]] = argv[i + 1];
  }
  if (PARAMS.some((name) => !Object.hasOwn(args, name))) deny();
  return args;
}
function pin(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)
    || Buffer.from(value, "base64url").toString("base64url") !== value) deny();
  return value;
}
async function run(argv) {
  const args = parse(argv);
  const folder = shared.safeDir(args["--owned-dir"]);
  const modulePath = shared.fileAt(folder, args["--context-module"]);
  if (path.extname(modulePath).toLowerCase() !== ".js") deny();
  const buildTrusted = require(modulePath);
  if (typeof buildTrusted !== "function") deny();
  // The operator's trusted code MUST reconstruct a branded history by
  // calling canonical verifyTrustedDeviceRecoveryHistoryV2.
  const trusted = await buildTrusted();
  const externalPins = {
    ownerSpkiSha256: pin(args["--owner-spki"]),
    witnessSpkiSha256: pin(args["--witness-spki"]),
    casSpkiSha256: pin(args["--cas-spki"]),
    casSequence: Number(args["--cas-sequence"]),
    priorCommitmentSha256: pin(args["--prior-receipt-sha256"]),
    digest: pin(args["--head-digest"]),
    revision: Number(args["--head-revision"]), epoch: Number(args["--head-epoch"]),
  };
  if (!Number.isSafeInteger(externalPins.revision) || externalPins.revision < 1
    || !Number.isSafeInteger(externalPins.epoch) || externalPins.epoch < 1) deny();
  if (!Number.isSafeInteger(externalPins.casSequence)
    || externalPins.casSequence < 1) deny();
  const deadline = Date.now() + 270000;
  return executeOwnerRevocation({ trusted, externalPins,
    targetDeviceId: args["--revoke-device"],
    publishCandidate: (candidate) =>
      shared.publishJson(folder, "revocation-candidate.json", candidate),
    awaitWitnessCommitment: () =>
      shared.awaitJson(folder, "revocation-committed-receipt.json", deadline),
    publishDelivery: (receipt) =>
      shared.publishJson(folder, "revocation-browser-delivery.json", receipt),
  });
}
if (require.main === module) {
  run(process.argv.slice(2)).then((result) =>
    process.stdout.write(JSON.stringify(result) + "\n")).catch((error) => {
    process.stderr.write("ZK_OWNER_V2_REVOKE_CLI_DENIED"
      + (error?.phase ? ":" + error.phase : "") + "\n");
    process.exitCode = 1;
  });
}
module.exports = { run, parse };
