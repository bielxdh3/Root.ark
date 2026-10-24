"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { spawn } = require("node:child_process");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const m = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const z = require("../src/crypto/rootark-zk-1");
const commitments = require("../src/crypto/rootark-zk1-offline-commitment-receipt");
const casModule = require("../src/crypto/rootark-zk1-offline-cas-commit-proof");
const orchestrator = require("../src/services/zk1OwnerOfflineRevocationOrchestrator");
const importer = require("../public/client/rootark-zk1-v2-owner-revocation-import");
const browser = require("../public/client/rootark-zk1-v2-owner-revocation-browser");

const b64 = (v) => Buffer.from(v).toString("base64url");
const sha = (v) => crypto.createHash("sha256").update(v).digest();
const spki = (key) => b64(sha(key.export({ format: "der", type: "spki" })));
const receiptHash = (receipt) => b64(sha(Buffer.concat([
  commitments.commitmentSigningBytes(Object.fromEntries(commitments.FIELDS.map(
    (name) => [name, receipt[name]]))), Buffer.from(receipt.signature, "base64url"),
])));
function signed(fields, scope, key) {
  const value = { schema: commitments.SCHEMA, status: "committed",
    ...Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
      .map((name) => [name, b64(scope[name])])),
    revision: null, digest: null, epoch: null, previous_revision: null,
    previous_digest: null, operation_id: null, pop_challenge_id: null,
    request_nonce: null, commit_nonce: null, sequence: null,
    previous_receipt_sha256: null, issued_at: null, expires_at: null, ...fields };
  const unsigned = Object.fromEntries(commitments.FIELDS.map((name) => [name, value[name]]));
  return { ...unsigned, signature: b64(crypto.sign(null,
    commitments.commitmentSigningBytes(unsigned), key)) };
}
async function setup({ spoofSameAuthority = false } = {}) {
  const state = await fixtures.createInitialState(2);
  const owner = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const cas = spoofSameAuthority ? { privateKey: witness.privateKey,
    publicKey: crypto.createPublicKey(witness.privateKey) }
    : crypto.generateKeyPairSync("ed25519");
  if (spoofSameAuthority) {
    const foreignCas = crypto.generateKeyPairSync("ed25519");
    cas.publicKey.export = () => foreignCas.publicKey.export({
      format: "der", type: "spki",
    });
  }
  const previous = state.headManifest;
  const priorDigest = b64(await m.recoveryManifestDigestV2(previous));
  const at = Math.floor(Date.now() / 1000);
  const prior = signed({ revision: previous.revision, digest: priorDigest,
    epoch: previous.current_epoch, sequence: 57,
    issued_at: at - 1, expires_at: at + 250 }, state.scope, witness.privateKey);
  const pins = { ownerSpkiSha256: spki(owner.publicKey),
    witnessSpkiSha256: spki(witness.publicKey),
    casSpkiSha256: spki(cas.publicKey), casSequence: 90,
    priorCommitmentSha256: receiptHash(prior),
    revision: previous.revision, digest: priorDigest, epoch: previous.current_epoch };
  const actor = state.actors.get(previous.devices[0].authorization_key_id.toString("hex"));
  const trusted = { verifiedHistory: state.verifiedHistory,
    trustedOwnerPublicKey: owner.publicKey, ownerPrivateKey: owner.privateKey,
    trustedCommitmentSignerPublicKey: witness.publicKey,
    trustedCasSignerPublicKey: cas.publicKey,
    trustedPriorCommitment: prior, trustedActorPrivateKey: actor };
  const first = (candidate, fields = {}, key = witness.privateKey) => signed({
    revision: candidate.revision, digest: candidate.digest, epoch: candidate.epoch,
    previous_revision: pins.revision, previous_digest: pins.digest,
    operation_id: candidate.operationId, pop_challenge_id: null,
    request_nonce: candidate.requestNonce, commit_nonce: candidate.commitNonce,
    sequence: prior.sequence + 1, previous_receipt_sha256: receiptHash(prior),
    issued_at: Math.floor(Date.now() / 1000), expires_at: at + 245, ...fields,
  }, state.scope, key);
  const second = (candidate, previousReceipt, fields = {}, key = witness.privateKey) =>
    signed({ revision: candidate.revision, digest: candidate.digest,
      epoch: candidate.epoch, previous_revision: candidate.revision,
      previous_digest: candidate.digest, operation_id: candidate.operationId,
      pop_challenge_id: null,
      request_nonce: candidate.requestNonce, commit_nonce: candidate.commitNonce,
      sequence: previousReceipt.sequence + 1,
      previous_receipt_sha256: receiptHash(previousReceipt),
      issued_at: Math.floor(Date.now() / 1000), expires_at: at + 245, ...fields,
    }, state.scope, key);
  const casReceipt = (firstReceipt, candidate, fields = {}, signer = cas.privateKey) => {
    const value = {
      schema: casModule.SCHEMA, status: "committed",
      ...Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
        .map((name) => [name, b64(state.scope[name])])),
      revision: candidate.revision, epoch: candidate.epoch, digest: candidate.digest,
      previous_revision: pins.revision, previous_digest: pins.digest,
      operation_id: candidate.operationId, request_nonce: candidate.requestNonce,
      commit_nonce: candidate.commitNonce,
      witness_receipt_sha256: receiptHash(firstReceipt),
      cas_sequence: pins.casSequence + 1, witness_sequence: firstReceipt.sequence,
      issued_at: Math.floor(Date.now() / 1000), expires_at: at + 250,
      ...fields,
    };
    const unsigned = Object.fromEntries(casModule.FIELDS.map((name) => [name, value[name]]));
    return { ...unsigned, signature: b64(crypto.sign(null,
      casModule.signingBytes(unsigned), signer)) };
  };
  const casAdapter = (firstReceipt, candidate) => ({
    committed: true, independent: true, revision: candidate.revision,
    epoch: candidate.epoch, digest: candidate.digest,
    operationId: candidate.operationId, sequence: firstReceipt.sequence,
    previousReceiptSha256: pins.priorCommitmentSha256,
    signedHeadProof: second(candidate, firstReceipt),
    signedCasProof: casReceipt(firstReceipt, candidate),
  });
  return { state, owner, witness, cas, previous, pins, prior, trusted,
    first, second, casReceipt, casAdapter };
}
test("owner V2 revocation cannot trust witness and CAS proofs from the same signer with spoofed SPKI export", async () => {
  const f = await setup({ spoofSameAuthority: true });
  await assert.rejects(perform(f), /ZK_OWNER_V2_REVOCATION_DENIED/,
    "distinct pinned signer hashes must refer to distinct native Ed25519 authorities");
});
async function perform(f, overrides = {}) {
  const outputs = [];
  let candidate, delivered;
  const trusted = { ...f.trusted, verifyExternalCommittedCas: async ({ candidate: v, receipt }) =>
    f.casAdapter(receipt, v), ...overrides.trusted };
  const result = await orchestrator.executeOwnerRevocation({
    trusted, externalPins: { ...f.pins, ...overrides.pins },
    targetDeviceId: overrides.target || "trusted-1",
    publishCandidate: async (payload) => {
      outputs.push("candidate");
      candidate = payload;
      assert.equal(payload.committed, false);
      assert.equal(payload.ownerApproved, false);
    },
    awaitWitnessCommitment: async () => {
      outputs.push("witness");
      return overrides.first ? overrides.first(candidate, f) : f.first(candidate);
    },
    publishDelivery: async (payload) => { outputs.push("delivery"); delivered = payload; },
    clock: overrides.clock,
  });
  return { result, candidate, delivered, outputs };
}
test("offline V2 rotation creates real HPKE wraps, revokes target, verifies dual independently signed witness/CAS, exports owner-signed delivery", async () => {
  const f = await setup();
  const { result, candidate, delivered, outputs } = await perform(f);
  assert.deepEqual(outputs, ["candidate", "witness", "delivery"]);
  assert.equal(result.completed, true);
  assert.equal(result.externalCasSignedHeadVerified, true);
  assert.equal(result.independentCasSignatureVerified, true);
  assert.equal(result.physicalDurabilityProven, false);
  assert.equal(result.pastCiphertextRevocationProven, false);
  const next = await z.decodeDeterministic(Buffer.from(candidate.signedV2Manifest, "base64url"));
  assert.equal(next.operation.operation_type, "revoke-device");
  assert.equal(next.current_epoch, f.previous.current_epoch + 1);
  assert.equal(next.revision, f.previous.revision + 1);
  assert.equal(next.devices.find((device) => device.device_id === "trusted-1").revoked_at_epoch,
    next.current_epoch);
  assert.equal(next.wraps.filter((wrap) => wrap.epoch === next.current_epoch).length, 1);
  assert.ok(next.wraps.filter((wrap) => wrap.epoch === next.current_epoch)
    .every((wrap) => wrap.device_id !== "trusted-1"));
  const { ownerSignature, ...unsigned } = delivered;
  assert.ok(crypto.verify(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/owner-v2-revocation-delivery/v1\0"),
    Buffer.from(JSON.stringify(unsigned))]), f.owner.publicKey,
  Buffer.from(ownerSignature, "base64url")));
  assert.equal(delivered.physicalDurabilityProven, false);
  assert.equal(delivered.signedSurvivorGrants.length, 1);
  assert.ok(delivered.signedSurvivorGrants.every((grant) =>
    grant.device_id !== "trusted-1" && grant.current_epoch === next.current_epoch
    && grant.revoked_at_epoch === null));
  assert.equal(JSON.stringify(delivered).includes("PRIVATE KEY"), false);
  const check = { delivery: delivered,
    ownerSpki: new Uint8Array(f.owner.publicKey.export({ type: "spki", format: "der" })),
    witnessSpki: new Uint8Array(f.witness.publicKey.export({ type: "spki", format: "der" })),
    casSpki: new Uint8Array(f.cas.publicKey.export({ type: "spki", format: "der" })),
    independentPins: {
      ownerSpkiSha256: f.pins.ownerSpkiSha256,
      witnessSpkiSha256: f.pins.witnessSpkiSha256,
      casSpkiSha256: f.pins.casSpkiSha256,
      priorReceiptSha256: f.pins.priorCommitmentSha256,
      casSequence: f.pins.casSequence,
      revision: result.revision, epoch: result.epoch,
      digest: candidate.digest, previousRevision: f.previous.revision,
      previousDigest: f.pins.digest,
    }, nowSeconds: Math.floor(Date.now() / 1000) };
  if (process.env.ZK65_EDGE_FIXTURE_DIR) {
    const dir = path.resolve(process.env.ZK65_EDGE_FIXTURE_DIR);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "delivery.json"), JSON.stringify(delivered));
    fs.writeFileSync(path.join(dir, "pins.json"), JSON.stringify(check.independentPins));
    for (const [name, bytes] of [["owner", check.ownerSpki],
      ["witness", check.witnessSpki], ["cas", check.casSpki]]) {
      fs.writeFileSync(path.join(dir, name + ".der"), bytes);
    }
  }
  const verified = await importer.verifyRevocationDelivery(check);
  assert.equal(verified.transferVerified, true);
  assert.equal(verified.authorizesProtectedIo, false);
  assert.equal(verified.liveCasOrCustodyVerified, false);
  assert.equal(verified.fullV2ManifestHistoryVerified, false);
  browser.clear();
  let fenceChecks = 0;
  const guarded = { ...check, assertLive: () => { fenceChecks++; } };
  const inspection = await browser.verifyOfflineTransfer(guarded);
  assert.equal(inspection.verified, true);
  assert.equal(inspection.revokedDeviceId, "trusted-1");
  assert.equal(inspection.epoch, delivered.epoch);
  assert.equal(inspection.signedSurvivorCount, 1);
  assert.equal(inspection.grantsReleased, false);
  assert.equal(inspection.fullV2HistoryVerified, false);
  assert.equal(inspection.authorizesProtectedIo, false);
  assert.equal(Object.hasOwn(inspection, "signedSurvivorGrants"), false);
  assert.ok(fenceChecks >= 3);
  await assert.rejects(browser.verifyOfflineTransfer(guarded),
    /ZK_V2_OWNER_REVOCATION_BROWSER_DENIED/);
  browser.clear();
  let checked = 0;
  await assert.rejects(browser.verifyOfflineTransfer({ ...guarded,
    assertLive: () => { if (++checked > 1) throw new Error("logged out / CSRF changed"); },
  }), /ZK_V2_OWNER_REVOCATION_BROWSER_DENIED/);
  // Abort must not consume a valid receipt's local replay floor.
  assert.equal((await browser.verifyOfflineTransfer(guarded)).verified, true);
  browser.clear();
  await assert.rejects(browser.verifyOfflineTransfer({ ...guarded,
    independentPins: { ...check.independentPins, casSequence: delivered.signedCasProof.cas_sequence },
  }), /ZK_V2_OWNER_REVOCATION_BROWSER_DENIED/);
  for (const changed of [
    { independentPins: { ...check.independentPins, epoch: f.pins.epoch } },
    { independentPins: { ...check.independentPins, casSequence: delivered.signedCasProof.cas_sequence } },
    { ownerSpki: new Uint8Array(crypto.randomBytes(check.ownerSpki.length)) },
    { delivery: { ...delivered, signedSurvivorGrants: [] } },
    { delivery: { ...delivered, signedSurvivorGrants: [f.prior] } },
    { delivery: { ...delivered, signedCasProof: { ...delivered.signedCasProof, signature: b64(crypto.randomBytes(64)) } } },
  ]) await assert.rejects(importer.verifyRevocationDelivery({ ...check, ...changed }),
    /ZK_OWNER_REVOCATION_IMPORT_DENIED/);
  // Even an OWNER-SIGNED grant from the previous epoch is not admissible
  // under the new externally pinned current head, including an old grant
  // originally issued for the now-revoked device.
  const old = { ...delivered.signedSurvivorGrants[0],
    device_id: "trusted-1",
    manifest_revision: f.previous.revision,
    manifest_digest: f.pins.digest,
    current_epoch: f.previous.current_epoch,
    enrolled_epoch: f.previous.devices[1].enrolled_epoch };
  delete old.signature;
  const grantDomain = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
  old.signature = b64(crypto.sign(null, Buffer.concat([
    grantDomain, Buffer.from(JSON.stringify(old))]), f.owner.privateKey));
  const unsignedDelivery = { ...unsigned, signedSurvivorGrants: [old] };
  const oldDelivery = { ...unsignedDelivery, ownerSignature: b64(crypto.sign(null,
    Buffer.concat([Buffer.from("Root.ark/zk-1/owner-v2-revocation-delivery/v1\0"),
      Buffer.from(JSON.stringify(unsignedDelivery))]), f.owner.privateKey)) };
  await assert.rejects(importer.verifyRevocationDelivery({
    ...check, delivery: oldDelivery }), /ZK_OWNER_REVOCATION_IMPORT_DENIED/);
  // A valid owner signature over mismatched CBOR cannot replace the actual
  // independently pinned V2 digest, nor can signed predecessor epochs fork.
  const altered = { ...unsigned, signedV2Manifest: b64(crypto.randomBytes(256)) };
  const alteredDelivery = { ...altered, ownerSignature: b64(crypto.sign(null,
    Buffer.concat([Buffer.from("Root.ark/zk-1/owner-v2-revocation-delivery/v1\0"),
      Buffer.from(JSON.stringify(altered))]), f.owner.privateKey)) };
  await assert.rejects(importer.verifyRevocationDelivery({ ...check, delivery: alteredDelivery }),
    /ZK_OWNER_REVOCATION_IMPORT_DENIED/);
  const ctx = vm.createContext({ crypto: crypto.webcrypto, TextEncoder, Uint8Array,
    ArrayBuffer, atob, btoa });
  vm.runInContext(fs.readFileSync(path.resolve(__dirname,
    "../public/client/rootark-zk1-v2-owner-revocation-import.js"), "utf8"), ctx);
  vm.runInContext(fs.readFileSync(path.resolve(__dirname,
    "../public/client/rootark-zk1-v2-owner-revocation-browser.js"), "utf8"), ctx);
  assert.equal(vm.runInContext(
    "typeof RootarkZk1V2OwnerRevocationImport.verifyRevocationDelivery", ctx), "function");
  assert.equal(vm.runInContext(
    "typeof RootarkZk1V2OwnerRevocationBrowser.verifyOfflineTransfer", ctx), "function");
});
test("canonical V2 signer rejects an actually revoked historical actor for a later epoch", async () => {
  const f = await setup();
  const state = f.state;
  const revoked = state.headManifest.devices.find((device) => device.device_id === "trusted-1");
  const oldSigner = state.actors.get(Buffer.from(revoked.authorization_key_id).toString("hex"));
  await fixtures.appendDeviceRevocation(state, "trusted-1");
  const prepared = await fixtures.prepareDeviceRevocation(state, "trusted-0");
  prepared.core.operation.actor_key_id = revoked.authorization_key_id;
  prepared.core.operation.request_digest = await m.expectedRecoveryRequestDigestV2(
    state.headManifest, prepared.core);
  await assert.rejects(m.signRecoveryTransitionV2({
    proposedCore: prepared.core, priorVerifiedHistory: state.verifiedHistory,
    actorPrivateKey: oldSigner, manifestMacKey: prepared.newKey,
    now: 1100, clockHealthy: true,
  }), /UNAUTHORIZED_ACTOR|HISTORY_INVALID|COMPROMISE_RECOVERY_UNAVAILABLE/);
});
test("unresponsive independent CAS cannot hang offline ceremony or release owner-signed grant", async () => {
  const f = await setup();
  let candidate, released = 0;
  await assert.rejects(orchestrator.executeOwnerRevocation({
    trusted: { ...f.trusted,
      verifyExternalCommittedCas: () => new Promise(() => {}) },
    externalPins: f.pins, targetDeviceId: "trusted-1",
    maxWaitMs: 130,
    publishCandidate: async (item) => { candidate = item; },
    awaitWitnessCommitment: async () => f.first(candidate),
    publishDelivery: async () => { released++; },
  }), /ZK_OWNER_V2_REVOCATION_DENIED/);
  assert.equal(candidate?.committed, false);
  assert.equal(released, 0);
});
test("revocation fails closed on forged current head, revoked actor, old epoch, witness rollback/fork/missing CAS proof", async () => {
  const modes = ["owner-pin", "witness-pin", "old-head", "old-epoch", "prior-pin",
    "self-revoke", "unknown-device", "no-cas", "false-cas", "unsigned-cas",
    "foreign-cas", "replay-cas", "missing-cas-signature", "foreign-cas-signature",
    "cas-rollback", "cas-fork", "foreign-witness", "fork-witness",
    "stale-sequence", "wrong-operation", "clock-rollback", "wrong-owner"];
  for (const mode of modes) {
    const f = await setup();
    const pins = {};
    const trusted = {};
    let target = "trusted-1";
    if (mode === "owner-pin") pins.ownerSpkiSha256 = b64(crypto.randomBytes(32));
    if (mode === "witness-pin") pins.witnessSpkiSha256 = b64(crypto.randomBytes(32));
    if (mode === "old-head") pins.digest = b64(crypto.randomBytes(32));
    if (mode === "old-epoch") pins.epoch = f.pins.epoch - 1;
    if (mode === "prior-pin") pins.priorCommitmentSha256 = b64(crypto.randomBytes(32));
    if (mode === "self-revoke") target = "trusted-0";
    if (mode === "unknown-device") target = "not-present";
    if (mode === "no-cas") trusted.verifyExternalCommittedCas = undefined;
    if (mode === "false-cas") trusted.verifyExternalCommittedCas = async () => ({ committed: true });
    if (mode === "wrong-owner") trusted.ownerPrivateKey =
      crypto.generateKeyPairSync("ed25519").privateKey;
    let sent = 0, candidate;
    await assert.rejects(orchestrator.executeOwnerRevocation({
      trusted: { ...f.trusted, ...trusted,
        verifyExternalCommittedCas: trusted.verifyExternalCommittedCas === undefined
          ? (mode === "no-cas" ? undefined : async ({ candidate: v, receipt }) => {
            const cas = f.casAdapter(receipt, v);
            if (mode === "unsigned-cas") cas.signedHeadProof = null;
            if (mode === "foreign-cas") cas.signedHeadProof = f.second(v, receipt, {},
              crypto.generateKeyPairSync("ed25519").privateKey);
            if (mode === "replay-cas") cas.signedHeadProof =
              f.second(v, receipt, { sequence: receipt.sequence });
            if (mode === "missing-cas-signature") cas.signedCasProof = null;
            if (mode === "foreign-cas-signature") cas.signedCasProof = f.casReceipt(receipt, v, {},
              crypto.generateKeyPairSync("ed25519").privateKey);
            if (mode === "cas-rollback") cas.signedCasProof = f.casReceipt(receipt, v,
              { cas_sequence: f.pins.casSequence });
            if (mode === "cas-fork") cas.signedCasProof = f.casReceipt(receipt, v,
              { digest: b64(crypto.randomBytes(32)) });
            return cas;
          }) : trusted.verifyExternalCommittedCas },
      externalPins: { ...f.pins, ...pins }, targetDeviceId: target,
      clock: mode === "clock-rollback"
        ? () => Math.floor(Date.now() / 1000) - 65 : undefined,
      publishCandidate: async (v) => { candidate = v; },
      awaitWitnessCommitment: async () => {
        if (mode === "foreign-witness") return f.first(candidate, {},
          crypto.generateKeyPairSync("ed25519").privateKey);
        if (mode === "fork-witness") return f.first(candidate,
          { digest: b64(crypto.randomBytes(32)) });
        if (mode === "stale-sequence") return f.first(candidate,
          { sequence: f.prior.sequence });
        if (mode === "wrong-operation") return f.first(candidate,
          { operation_id: b64(crypto.randomBytes(16)) });
        return f.first(candidate);
      },
      publishDelivery: async () => { sent++; },
    }), /ZK_OWNER_V2_REVOCATION_DENIED/, mode);
    assert.equal(sent, 0, "must not deliver on " + mode);
  }
});
test("real Node CLI exchanges candidate and two signed witness proofs with separate owner process", async (t) => {
  for (const mode of ["valid", "missing-cas", "bad-prior-pin"]) {
    const f = await setup();
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-owner-revoke-"));
    t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
    const file = (name) => path.join(root, name);
    const write = (name, data) => fs.writeFileSync(file(name), JSON.stringify(data));
    const source = path.resolve(__dirname, "../");
    write("offline-state.json", {
      scope: Object.fromEntries(Object.entries(f.state.scope).map(([name, bytes]) =>
        [name, b64(bytes)])),
      base: b64(await z.encodeDeterministic(f.state.baseManifest)),
      transitions: f.state.transitions.map(b64),
      baseReceipt: Object.fromEntries(Object.entries(f.state.baseReceipt).map(
        ([name, value]) => [name, Buffer.isBuffer(value) ? b64(value) : value])),
      baseWitnessKeyId: b64(f.state.pinnedWitness.keyId),
      baseWitnessPublicDer: b64(f.state.pinnedWitness.publicKey.export({
        type: "spki", format: "der" })),
      epochs: f.state.epochKeys.map(({ epoch, key }) => ({ epoch, key: b64(key) })),
      ownerPrivatePem: f.owner.privateKey.export({ type: "pkcs8", format: "pem" }),
      actorPrivatePem: f.trusted.trustedActorPrivateKey.export({ type: "pkcs8", format: "pem" }),
      witnessPublicPem: f.witness.publicKey.export({ type: "spki", format: "pem" }),
      casPublicPem: f.cas.publicKey.export({ type: "spki", format: "pem" }),
      prior: f.prior, pin: f.pins.priorCommitmentSha256,
    });
    fs.writeFileSync(file("owner-context.js"), "module.exports = require("
      + JSON.stringify(path.join(source, "test/support/issue-65-owner-revocation-cli-context.js"))
      + ");");
    const args = [
      path.join(source, "scripts/zk1-owner-offline-revoke-local.js"),
      "--owned-dir", root, "--context-module", "owner-context.js",
      "--owner-spki", f.pins.ownerSpkiSha256,
      "--witness-spki", f.pins.witnessSpkiSha256,
      "--cas-spki", f.pins.casSpkiSha256, "--cas-sequence", String(f.pins.casSequence),
      "--head-revision", String(f.pins.revision),
      "--head-digest", f.pins.digest, "--head-epoch", String(f.pins.epoch),
      "--prior-receipt-sha256", mode === "bad-prior-pin"
        ? b64(crypto.randomBytes(32)) : f.pins.priorCommitmentSha256,
      "--revoke-device", "trusted-1",
    ];
    const child = spawn(process.execPath, args, {
      cwd: root, env: { ...process.env }, windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    t.after(() => { if (!child.killed) child.kill(); });
    let out = "", err = "";
    child.stdout.on("data", (chunk) => { out += chunk; });
    child.stderr.on("data", (chunk) => { err += chunk; });
    const exit = new Promise((resolve) => {
      child.once("exit", (code, signal) => resolve({ code, signal }));
      child.once("error", (error) => resolve({ code: -1, error }));
    });
    const until = async (filename) => {
      for (let i = 0; i < 90; i++) {
        if (fs.existsSync(file(filename))) return JSON.parse(fs.readFileSync(file(filename), "utf8"));
        if (child.exitCode !== null) throw new Error("early CLI exit: " + err);
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      throw new Error("missing " + filename + ": " + err);
    };
    if (mode === "bad-prior-pin") {
      assert.notEqual((await exit).code, 0);
      assert.equal(fs.existsSync(file("revocation-candidate.json")), false);
      assert.equal(fs.existsSync(file("revocation-browser-delivery.json")), false);
      continue;
    }
    const candidate = await until("revocation-candidate.json");
    assert.equal(candidate.committed, false);
    const committed = f.first(candidate);
    write("revocation-committed-receipt.json", committed);
    if (mode === "valid") {
      write("cas-head-proof.json", f.second(candidate, committed));
      write("cas-commit-proof.json", f.casReceipt(committed, candidate));
      const delivery = await until("revocation-browser-delivery.json");
      assert.equal(delivery.schema, "rootark-zk1-v2-owner-revocation-delivery/v1");
      assert.equal(delivery.revokedDeviceId, "trusted-1");
      assert.equal((await exit).code, 0, err);
      assert.match(out, /"completed":true/);
    } else {
      assert.notEqual((await exit).code, 0);
      assert.equal(fs.existsSync(file("revocation-browser-delivery.json")), false);
      assert.match(err, /ZK_OWNER_V2_REVOKE_CLI_DENIED/);
    }
  }
});
