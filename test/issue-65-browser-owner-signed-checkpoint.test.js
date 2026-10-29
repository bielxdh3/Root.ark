"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { inspectZk1ExperimentalRemoteSignedHistory } =
  require("../src/services/zk1ExperimentalRemoteSignedHistory");
const api = require("../public/client/rootark-zk1-owner-signed-checkpoint");

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const fail = /ZK_OWNER_CHECKPOINT_UNVERIFIED/;
function fresh() {
  return { account_id: b64(crypto.randomBytes(16)),
    compartment_id: b64(Buffer.from("owner-compartment")),
    keyring_id: b64(crypto.randomBytes(16)) };
}
async function signer() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const privateKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    keys.privateKey.export({ format: "der", type: "pkcs8" }),
    "Ed25519", false, ["sign"]);
  const publicKey = await crypto.webcrypto.subtle.importKey("spki",
    keys.publicKey.export({ format: "der", type: "spki" }),
    "Ed25519", false, ["verify"]);
  return { keys, privateKey, publicKey };
}
function args(identity, keys, previous = null, revision = 1, digest = crypto.randomBytes(32)) {
  return { scope: identity, signerKey: keys.privateKey,
    signerPublicKey: keys.publicKey, signerKeyId: crypto.randomBytes(16),
    deviceId: "trusted-owner", revision, manifestDigest: digest,
    issuedAt: 1000 + revision, previous };
}
function verification(input, keys, checkpoint, previous = null) {
  return { checkpoint, scope: input.scope, signerPublicKey: keys.publicKey,
    signerKeyId: input.signerKeyId, previous };
}

test("WebCrypto owner signs portable domain-separated canonical CBOR checkpoint; Node Ed25519 and browser UMD agree", async () => {
  const identity = fresh();
  const keys = await signer();
  const input = args(identity, keys);
  const wire = await api.signOwnerCheckpoint(input);
  assert.equal(wire.schema, "rootark-zk1-owner-history-checkpoint/v1");
  assert.equal(wire.sequence, 1);
  assert.equal(wire.previous_checkpoint_digest, null);
  const head = await api.verifyOwnerCheckpoint(verification(input, keys, wire));
  assert.equal(head.revision, 1);
  assert.equal(head.signedCheckpointVerified, true);
  assert.equal(head.authorizesProtectedIo, false);
  const unsigned = { ...wire };
  delete unsigned.signature;
  for (const key of ["account_id", "compartment_id", "keyring_id",
    "manifest_digest", "signer_key_id"]) {
    unsigned[key] = Buffer.from(unsigned[key], "base64url");
  }
  const signBytes = Buffer.concat([Buffer.from("Root.ark/zk-1/owner-history-checkpoint/v1\0"),
    Buffer.from(await z.encodeDeterministic(unsigned))]);
  assert.equal(crypto.verify(null, signBytes, keys.keys.publicKey,
    Buffer.from(wire.signature, "base64url")), true,
  "browser deterministic CBOR must match independent Node canonical RFC8949 signature");
  const source = fs.readFileSync(path.resolve(__dirname,
    "../public/client/rootark-zk1-owner-signed-checkpoint.js"), "utf8");
  const context = vm.createContext({ crypto: crypto.webcrypto, TextEncoder, TextDecoder,
    Uint8Array, ArrayBuffer, btoa, atob });
  vm.runInContext(source, context);
  context.key = keys.privateKey;
  context.pub = keys.publicKey;
  context.identity = identity;
  context.keyId = Buffer.from(input.signerKeyId);
  context.digest = Buffer.from(input.manifestDigest);
  const vmResult = await vm.runInContext(`(async () => {
    const created = await RootarkZk1OwnerSignedCheckpoint.signOwnerCheckpoint({
      scope: { ...identity }, signerKey: key, signerPublicKey: pub,
      signerKeyId: keyId, deviceId: "trusted-owner", revision: 1,
      manifestDigest: digest, issuedAt: 1001, previous: null,
    });
    const verified = await RootarkZk1OwnerSignedCheckpoint.verifyOwnerCheckpoint({
      checkpoint: created, scope: { ...identity }, signerPublicKey: pub,
      signerKeyId: keyId, previous: null,
    });
    return { schema: created.schema, valid: verified.signedCheckpointVerified,
      permit: verified.authorizesProtectedIo };
  })()`, context);
  assert.equal(vmResult.schema, "rootark-zk1-owner-history-checkpoint/v1");
  assert.equal(vmResult.valid, true);
  assert.equal(vmResult.permit, false);
});

test("owner-held checkpoint enforces monotonic floor on caller-supplied head and rejects equal-revision fork", async () => {
  const identity = fresh();
  const keys = await signer();
  const digest1 = crypto.randomBytes(32);
  const first = args(identity, keys, null, 1, digest1);
  const wire1 = await api.signOwnerCheckpoint(first);
  const checkpoint1 = await api.verifyOwnerCheckpoint(verification(first, keys, wire1));
  const digest2 = crypto.randomBytes(32);
  const second = { ...first, previous: checkpoint1, revision: 2,
    manifestDigest: digest2, issuedAt: 1002 };
  const wire2 = await api.signOwnerCheckpoint(second);
  const checkpoint2 = await api.verifyOwnerCheckpoint(verification(first, keys, wire2, checkpoint1));
  const substituteKey = await signer();
  await assert.rejects(api.signOwnerCheckpoint({
    ...second, signerKey: substituteKey.privateKey,
    signerPublicKey: substituteKey.publicKey,
  }), fail, "matching keyId is not proof that the previous checkpoint used the same Ed25519 key");
  const forgedBody = { ...wire2 };
  delete forgedBody.signature;
  for (const field of ["account_id", "compartment_id", "keyring_id",
    "manifest_digest", "signer_key_id", "previous_checkpoint_digest"]) {
    forgedBody[field] = Buffer.from(forgedBody[field], "base64url");
  }
  const forgedWire = { ...wire2, signature: b64(crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/owner-history-checkpoint/v1\0"),
    Buffer.from(await z.encodeDeterministic(forgedBody)),
  ]), substituteKey.keys.privateKey)) };
  await assert.rejects(api.verifyOwnerCheckpoint({
    ...verification(first, substituteKey, forgedWire, checkpoint1),
  }), fail, "a different trusted public key cannot verify a successor of someone else's signed predecessor");
  assert.equal(wire2.sequence, 2);
  assert.equal(wire2.previous_checkpoint_digest, checkpoint1.checkpointDigest);
  await assert.rejects(api.verifyOwnerCheckpoint(verification(first, keys, wire2)),
    fail, "client may not silently initialize new trust root from checkpoint seq2");
  await assert.rejects(api.checkCandidateHeadAgainstCheckpoint({
    verifiedCheckpoint: checkpoint2, headRevision: 1, headDigest: digest1,
  }), fail, "restored CAS and witness at genuine old signed revision fails if trusted client carries checkpoint2");
  await assert.rejects(api.checkCandidateHeadAgainstCheckpoint({
    verifiedCheckpoint: checkpoint2, headRevision: 2,
    headDigest: crypto.randomBytes(32),
  }), fail, "same revision different valid manifest digest is a visible fork");
  const equal = await api.checkCandidateHeadAgainstCheckpoint({
    verifiedCheckpoint: checkpoint2, headRevision: 2, headDigest: digest2,
  });
  assert.equal(equal.monotonicOnly, true);
  assert.equal(equal.freshWitnessVerified, false);
  assert.equal(equal.authorizesRecovery, false);
  assert.equal((await api.checkCandidateHeadAgainstCheckpoint({
    verifiedCheckpoint: checkpoint2, headRevision: 3,
    headDigest: crypto.randomBytes(32),
  })).monotonicOnly, true,
  "a higher candidate is monotonic ONLY, not independently authenticated or fresh");
  const recoveredFromPeer = await api.verifyOwnerCheckpoint(verification(first, keys, wire1));
  const acceptedOnSecondClient = await api.verifyOwnerCheckpoint(
    verification(first, keys, wire2, recoveredFromPeer));
  assert.equal(acceptedOnSecondClient.checkpointDigest, checkpoint2.checkpointDigest,
    "another client independently verifies both signed checkpoint bytes");
  // A second browser realm has its OWN private WeakMap trust state: neither
  // signer nor branded proof objects cross the runtime, only signed wire
  // checkpoints, trusted key/scopes and the owner's retained floor.
  const source = fs.readFileSync(path.resolve(__dirname,
    "../public/client/rootark-zk1-owner-signed-checkpoint.js"), "utf8");
  const remoteRealm = vm.createContext({ crypto: crypto.webcrypto,
    TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, btoa, atob });
  vm.runInContext(source, remoteRealm);
  remoteRealm.wire1Json = JSON.stringify(wire1);
  remoteRealm.wire2Json = JSON.stringify(wire2);
  remoteRealm.scopeJson = JSON.stringify(identity);
  remoteRealm.publicKey = keys.publicKey;
  remoteRealm.signerKeyId = new Uint8Array(first.signerKeyId);
  remoteRealm.oldDigest = new Uint8Array(digest1);
  remoteRealm.newDigest = new Uint8Array(digest2);
  const remoteComparison = await vm.runInContext(`(async () => {
    const api = RootarkZk1OwnerSignedCheckpoint;
    const scope = JSON.parse(scopeJson);
    const initial = await api.verifyOwnerCheckpoint({
      checkpoint: JSON.parse(wire1Json), scope, signerPublicKey: publicKey,
      signerKeyId, previous: null,
    });
    const latest = await api.verifyOwnerCheckpoint({
      checkpoint: JSON.parse(wire2Json), scope, signerPublicKey: publicKey,
      signerKeyId, previous: initial,
    });
    let deniedOld = false;
    try {
      await api.checkCandidateHeadAgainstCheckpoint({
        verifiedCheckpoint: latest, headRevision: 1, headDigest: oldDigest,
      });
    } catch (error) {
      deniedOld = error.message === "ZK_OWNER_CHECKPOINT_UNVERIFIED";
    }
    const current = await api.checkCandidateHeadAgainstCheckpoint({
      verifiedCheckpoint: latest, headRevision: 2, headDigest: newDigest,
    });
    return { digest: latest.checkpointDigest, deniedOld,
      monotonicOnly: current.monotonicOnly, authorized: current.authorizesProtectedIo };
  })()`, remoteRealm);
  assert.equal(remoteComparison.digest, checkpoint2.checkpointDigest);
  assert.equal(remoteComparison.deniedOld, true);
  assert.equal(remoteComparison.monotonicOnly, true);
  assert.equal(remoteComparison.authorized, false);
});

test("tampered signatures, scope, keys, predecessor and caller mutations fail closed", async () => {
  const identity = fresh();
  const keys = await signer();
  const input = args(identity, keys);
  const pending = api.signOwnerCheckpoint(input);
  const originalDigest = Buffer.from(input.manifestDigest);
  const originalScope = { ...input.scope };
  input.scope.account_id = b64(crypto.randomBytes(16));
  input.manifestDigest.fill(0);
  input.signerKeyId.fill(0);
  const wire = await pending;
  assert.equal(wire.account_id, originalScope.account_id);
  assert.equal(wire.manifest_digest, b64(originalDigest));
  const stable = { ...input, scope: originalScope, signerKeyId:
    Buffer.from(wire.signer_key_id, "base64url") };
  assert.equal((await api.verifyOwnerCheckpoint(verification(stable, keys, wire)))
    .signedCheckpointVerified, true);
  for (const altered of [
    { ...wire, manifest_digest: b64(crypto.randomBytes(32)) },
    { ...wire, account_id: b64(crypto.randomBytes(16)) },
    { ...wire, signature: b64(crypto.randomBytes(64)) },
    { ...wire, sequence: 2 },
    { ...wire, previous_checkpoint_digest: b64(crypto.randomBytes(32)) },
    { ...wire, extra: "unexpected" },
  ]) {
    await assert.rejects(api.verifyOwnerCheckpoint(verification(stable, keys, altered)), fail);
  }
  const forgedSigner = await signer();
  await assert.rejects(api.verifyOwnerCheckpoint({
    ...verification(stable, keys, wire), signerPublicKey: forgedSigner.publicKey,
  }), fail);
  const manual = { signedCheckpointVerified: true, revision: 1000, manifestDigest: wire.manifest_digest };
  await assert.rejects(api.checkCandidateHeadAgainstCheckpoint({
    verifiedCheckpoint: manual, headRevision: 1000,
    headDigest: Buffer.from(wire.manifest_digest, "base64url"),
  }), fail, "unbranded caller-constructed proof cannot bypass checkpoint verification");
});

test("owner-held signed checkpoint blocks jointly rolled-back but freshly re-signed CAS+witness history in a local adapter", async () => {
  const state = await fixtures.createInitialState(2);
  const scope = state.scope;
  const identity = Object.fromEntries(Object.entries(scope)
    .map(([field, value]) => [field, b64(value)]));
  const witnessSigner = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const manifestAt = (revision) => revision === 1
    ? state.baseManifest : state.headManifest;
  const digestAt = async (revision) => v2.recoveryManifestDigestV2(manifestAt(revision));
  const baseUnsigned = {
    type: "rootark-recovery-witness-base/v1",
    witness_key_id: witnessKeyId, ...scope,
    revision: 1, manifest_digest: await digestAt(1), witness_sequence: 1,
    nonce: crypto.randomBytes(32), observed_at: 1000, status: "committed",
  };
  const baseReceipt = { ...baseUnsigned, signature: crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/recovery-witness-base/v1\0"),
    Buffer.from(await z.encodeDeterministic(baseUnsigned)),
  ]), witnessSigner.privateKey) };
  let advertisedRevision = 2;
  const casClient = {
    async getCommittedHistory() {
      const entries = [Buffer.from(await z.encodeDeterministic(state.baseManifest))];
      if (advertisedRevision === 2) {
        entries.push(Buffer.from(await z.encodeDeterministic(state.headManifest)));
      }
      return { headRevision: advertisedRevision,
        headDigest: await digestAt(advertisedRevision), entries };
    },
  };
  const witnessClient = {
    async freshHead({ nonce }) {
      // The test deliberately re-signs an OLD head with the genuine fixture
      // witness private key after its CAS and witness states "restore".
      // The nonce is new and the signature fully valid. No replayed bytes.
      const fields = {
        type: "rootark-recovery-witness-head/v1",
        witness_key_id: witnessKeyId, ...scope,
        current_revision: advertisedRevision,
        current_manifest_digest: await digestAt(advertisedRevision),
        witness_sequence: advertisedRevision, nonce, observed_at: 1100,
        status: "committed", pending_reservation_id: null,
      };
      return z.encodeDeterministic({ ...fields, signature: crypto.sign(null, Buffer.concat([
        Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0"),
        Buffer.from(await z.encodeDeterministic(fields)),
      ]), witnessSigner.privateKey) });
    },
  };
  const settings = { casClient, witnessClient, expectedScope: scope,
    baseReceipt, pinnedWitness: { keyId: witnessKeyId,
      publicKey: witnessSigner.publicKey },
    minimumHead: { revision: 1, witnessSequence: 1,
      digest: await digestAt(1) },
    packageEnvelopes: [], nowSeconds: () => 1100 };
  const verifiedCurrent = await inspectZk1ExperimentalRemoteSignedHistory(settings);
  assert.equal(verifiedCurrent.revision, 2);
  const device = state.headManifest.devices.find((item) => item.device_id === "trusted-0");
  const ownerPrivate = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
  const ownerPublic = crypto.createPublicKey(ownerPrivate);
  const ownerKeys = {
    privateKey: await crypto.webcrypto.subtle.importKey("pkcs8",
      ownerPrivate.export({ format: "der", type: "pkcs8" }), "Ed25519", false, ["sign"]),
    publicKey: await crypto.webcrypto.subtle.importKey("spki",
      ownerPublic.export({ format: "der", type: "spki" }), "Ed25519", false, ["verify"]),
  };
  const userInput = { scope: identity, signerKey: ownerKeys.privateKey,
    signerPublicKey: ownerKeys.publicKey,
    signerKeyId: Buffer.from(device.authorization_key_id),
    deviceId: device.device_id, revision: verifiedCurrent.revision,
    manifestDigest: verifiedCurrent.digest, issuedAt: 1100, previous: null };
  const ownerWire = await api.signOwnerCheckpoint(userInput);
  const retainedByOwner = await api.verifyOwnerCheckpoint(
    verification(userInput, ownerKeys, ownerWire));
  assert.equal((await api.checkCandidateHeadAgainstCheckpoint({
    verifiedCheckpoint: retainedByOwner, headRevision: verifiedCurrent.revision,
    headDigest: verifiedCurrent.digest,
  })).monotonicOnly, true);
  advertisedRevision = 1; // genuine signed historical CAS + fresh old witness
  const jointlyRestored = await inspectZk1ExperimentalRemoteSignedHistory(settings);
  assert.equal(jointlyRestored.revision, 1,
    "without an external client-retained floor, both correctly signed restored authorities can appear consistent");
  await assert.rejects(api.checkCandidateHeadAgainstCheckpoint({
    verifiedCheckpoint: retainedByOwner, headRevision: jointlyRestored.revision,
    headDigest: jointlyRestored.digest,
  }), fail, "a separately held owner checkpoint rejects both authorities' genuine old signed HEAD");
  advertisedRevision = 2;
  const restoredService = await inspectZk1ExperimentalRemoteSignedHistory(settings);
  assert.equal((await api.checkCandidateHeadAgainstCheckpoint({
    verifiedCheckpoint: retainedByOwner, headRevision: restoredService.revision,
    headDigest: restoredService.digest,
  })).monotonicOnly, true);
});
