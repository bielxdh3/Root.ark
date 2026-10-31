"use strict";
// Disposable test-only local trusted operator module; NEVER an application
// server endpoint. Real canonical history verifier creates the WeakMap brand.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const z = require("../../src/crypto/rootark-zk-1");
const verifier = require("../../src/crypto/rootark-zk-recovery-history-v2");
module.exports = async function buildTrusted() {
  const data = JSON.parse(fs.readFileSync(path.join(process.cwd(), "offline-state.json"), "utf8"));
  const dec = (value) => Buffer.from(value, "base64url");
  const scope = Object.fromEntries(Object.entries(data.scope).map(([k, v]) => [k, dec(v)]));
  const baseReceipt = Object.fromEntries(Object.entries(data.baseReceipt).map(([name, value]) =>
    [name, ["witness_key_id", "account_id", "compartment_id", "keyring_id",
      "manifest_digest", "nonce", "signature"].includes(name) ? dec(value) : value]));
  const verifiedHistory = await verifier.verifyTrustedDeviceRecoveryHistoryV2({
    expectedScope: scope, baseManifest: await z.decodeDeterministic(dec(data.base)),
    baseReceipt,
    pinnedWitness: { keyId: dec(data.baseWitnessKeyId),
      publicKey: crypto.createPublicKey({ key: dec(data.baseWitnessPublicDer),
        type: "spki", format: "der" }) },
    transitions: data.transitions.map(dec),
    epochKeys: data.epochs.map(({ epoch, key }) => ({ epoch, key: dec(key) })),
  });
  const ownerPrivateKey = crypto.createPrivateKey(data.ownerPrivatePem);
  return {
    verifiedHistory, ownerPrivateKey,
    trustedOwnerPublicKey: crypto.createPublicKey(ownerPrivateKey),
    trustedCommitmentSignerPublicKey: crypto.createPublicKey(data.witnessPublicPem),
    trustedCasSignerPublicKey: crypto.createPublicKey(data.casPublicPem),
    trustedPriorCommitment: data.prior,
    trustedActorPrivateKey: crypto.createPrivateKey(data.actorPrivatePem),
    // Separate operator-controlled signed CAS head GET is required.
    verifyExternalCommittedCas: async ({ candidate, receipt }) => {
      const signedHeadProof = JSON.parse(fs.readFileSync(
        path.join(process.cwd(), "cas-head-proof.json"), "utf8"));
      const signedCasProof = JSON.parse(fs.readFileSync(
        path.join(process.cwd(), "cas-commit-proof.json"), "utf8"));
      return {
        committed: true, independent: true,
        revision: candidate.revision, epoch: candidate.epoch,
        digest: candidate.digest, operationId: candidate.operationId,
        sequence: receipt.sequence,
        previousReceiptSha256: data.pin, signedHeadProof, signedCasProof,
      };
    },
  };
};
