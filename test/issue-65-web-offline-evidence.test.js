"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const recoveryHistory = require("../src/crypto/rootark-zk-recovery-history-v2");
const recoveryFixtures = require("./support/issue-65-recovery-v2-fixtures");

const contractPath = path.join(__dirname, "fixtures", "issue-65-web-offline-contract.json");
const projectRoot = path.join(__dirname, "..");

function readContract() {
  return JSON.parse(fs.readFileSync(contractPath, "utf8"));
}

function readSource(relativePath) {
  return fs.readFileSync(path.join(projectRoot, relativePath), "utf8");
}

function action(contract, id) {
  return contract.actions.find((item) => item.id === id);
}

async function verifiedPublicHistory() {
  const state = await recoveryFixtures.createInitialState(2);
  const baseManifest = state.headManifest;
  const baseAnchor = await recoveryFixtures.createWitnessAnchor(state);
  const packageEnvelope = await recoveryFixtures.createPackageEnvelope(state, { previousManifest: baseManifest });
  const activation = await recoveryFixtures.appendPackageActivation(state, packageEnvelope.envelopeBytes);
  const revocation = await recoveryFixtures.appendDeviceRevocation(state, "trusted-1");
  const packageEnvelopes = [{
    activationRevision: activation.manifest.revision,
    envelopeBytes: packageEnvelope.envelopeBytes,
  }];
  const transitions = await Promise.all([activation.manifest, revocation].map((manifest) =>
    recoveryFixtures.encodeManifest(manifest)));

  return recoveryHistory.verifyRecoveryHistoryPublicV2({
    expectedScope: state.scope,
    baseManifest,
    baseReceipt: baseAnchor.receipt,
    pinnedWitness: baseAnchor.pinnedWitness,
    packageEnvelopeBytes: packageEnvelope.envelopeBytes,
    packageEnvelopes,
    transitions,
    now: 100_000,
  });
}

test("downloadedFileNotRevocable", () => {
  const contract = readContract();
  assert.equal(contract.schema, "rootark-web-offline-contract/v1");
  assert.equal(contract.classification, "TEST_ONLY_POLICY_NOT_RUNTIME_ENFORCEMENT");
  assert.equal(contract.runtimeAdmissionEnforced, false);
  assert.deepEqual(contract.actions.map((item) => item.id), [
    "read-downloaded-copy",
    "view-already-open-plaintext",
    "new-transfer",
    "resume-transfer",
    "enroll-device",
    "recover-package",
    "browse-protected-index",
    "legacy-queued-sync",
  ]);
  assert.equal(action(contract, "read-downloaded-copy").decision, "allow-user-copy");
  assert.equal(action(contract, "read-downloaded-copy").requiresFreshAuthority, false);
  assert.equal(action(contract, "view-already-open-plaintext").decision, "already-held-only");
});

test("offlineSensitiveOperationsBlockedInContract", () => {
  const contract = readContract();
  for (const id of [
    "new-transfer",
    "resume-transfer",
    "enroll-device",
    "recover-package",
    "browse-protected-index",
  ]) {
    const item = action(contract, id);
    assert.ok(item, `missing policy action ${id}`);
    assert.equal(item.decision, "block", `${id} must be blocked offline`);
    assert.equal(item.requiresFreshAuthority, true, `${id} requires fresh authority`);
  }
  const legacyQueue = action(contract, "legacy-queued-sync");
  assert.equal(legacyQueue.decision, "not-authorized-for-zk");
  assert.equal(legacyQueue.requiresFreshAuthority, true);
});

test("legacyQueueNotNewZkAuthority", () => {
  const legacyQueue = readSource("public/client/rootark-offline-queue.js");
  const protectedStore = readSource("public/client/rootark-protected-store.js");
  const protectedSession = readSource("public/client/rootark-protected-session.js");
  const bootstrap = readSource("public/client/rootark-bootstrap.js");

  assert.match(legacyQueue, /rootark\.offline\.encrypted\.v2/);
  assert.match(legacyQueue, /adapter\.normalizeOpaqueEnvelope/);
  assert.match(legacyQueue, /drain:\s*\(\)\s*=>/);
  assert.match(protectedStore, /drainQueue:\s*async\s*\(key\)/);
  assert.match(protectedSession, /options\.getKey/);
  assert.match(bootstrap, /session\?\.syncOnce\?\.\(\)/);
  assert.doesNotMatch(legacyQueue, /freshnessProven\s*:\s*true|witness|CAS/i);
  assert.doesNotMatch(protectedSession, /freshnessProven\s*:\s*true|witness|CAS/i);
});

test("staleShellNotFreshSecurityState", () => {
  const worker = readSource("public/service-worker.js");
  assert.match(worker, /cache\.addAll\(SHELL_ASSETS\)/);
  assert.match(worker, /caches\.match\(request,\s*\{\s*ignoreSearch:\s*true\s*\}\)/);
  assert.match(worker, /"\/client\/rootark-protected-session\.js"/);
  assert.match(worker, /\^\\\/auth/);
  assert.match(worker, /\^\\\/api/);
  assert.match(worker, /fetch\(request,\s*\{\s*cache:\s*"no-store"\s*\}\)/);
  assert.doesNotMatch(worker, /freshnessProven\s*:\s*true|witness|CAS/i);
});

test("publicHistoryIsNotOnlineFreshness", async () => {
  const result = await verifiedPublicHistory();
  assert.equal(result.signedStateVerified, true);
  assert.equal(result.authorizationVerified, false);
  assert.equal(result.freshnessProven, false);
});
