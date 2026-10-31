"use strict";

// Adversarial client-side boundary regression. Run exclusively under the
// project Node22 gate; this test is NOT a substitute for server-side Ed25519,
// native SQLite, revocation or independent physical custody tests.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");

function operation(label) {
  return protocol.createOperation({
    operation: "create", operationId: `strict-${label}`,
    objectId: `object-${label}`, fileId: `file-${label}`,
    versionId: `version-${label}`, deviceId: "device-a",
    keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: `${label}.txt` },
    plaintext: Buffer.from("confidential fixture"), fileKey: crypto.randomBytes(32),
  });
}

async function signed(label) {
  const result = operation(label);
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" })
    .toString("base64url");
  result.authorization = await createAuthorizationProof(result, {
    username: "alice", privateKey: pair.privateKey, publicKey,
    expiresAt: Date.now() + 60_000,
  });
  return result;
}

function fixture(pending) {
  const calls = { pushed: 0, incoming: 0, admissionChecks: 0 };
  const journal = {
    recover: async () => pending ? [pending] : [],
    hasSeen: () => false,
    assertCompatibleAdmission: () => { calls.admissionChecks += 1; },
    hasLocalAdmission: () => false,
  };
  const engine = new SyncEngine({
    rootDir: process.cwd(), journal, requireAuthorization: true,
    authorize: async () => true, authorizeOutgoing: async () => true,
    verifyIncoming: async () => { calls.incoming += 1; return true; },
    adapter: { push: async () => { calls.pushed += 1; return { status: 200 }; },
      list: async () => [] },
  });
  return { engine, calls };
}

test("unsigned persisted queue cannot reach outgoing adapter in strict mode", async () => {
  const unsigned = operation("unsigned-queue");
  const { engine, calls } = fixture(unsigned);
  await assert.rejects(engine._pushPending({ pushed: 0, conflicts: [] }),
    { code: "authorization_required" });
  assert.equal(calls.pushed, 0,
    "the malicious journal item must fail BEFORE a remote HTTP send");
});

test("real signed Ed25519 envelope is allowed through the strict outbound boundary", async () => {
  const valid = await signed("positive-send");
  // Establish a cryptographic positive independently of the engine's
  // structural-only guard. The actual HTTP store must repeat this verification
  // under its own current device registry and atomic revocation transaction.
  assert.equal(await verifyAuthorizationProof(valid.authorization, valid, {
    username: "alice",
    trustedDevicePublicKeys: { "device-a": valid.authorization.publicKey },
    revokedDeviceIds: [],
  }), true);
  const { engine, calls } = fixture();
  assert.equal((await engine.retryPush(valid)).status, 200);
  assert.equal(calls.pushed, 1,
    "the positive control must reach the actual adapter callback");
  const tampered = { ...valid, ciphertext: operation("different-bytes").ciphertext };
  await assert.rejects(engine.retryPush(tampered),
    { code: "authorization_required" });
  assert.equal(calls.pushed, 1,
    "signed metadata digest must fence an altered ciphertext before dispatch");
});

test("unsigned incoming is rejected even when a permissive verifier returns true", async () => {
  const unsigned = operation("unsigned-incoming");
  const { engine, calls } = fixture();
  await assert.rejects(engine.verifyIncomingOperation(unsigned, { preObserve: false }),
    { code: "remote_authorization_rejected" });
  assert.equal(calls.incoming, 0,
    "an unsigned entry cannot delegate its admission to a permissive callback");
  assert.equal(calls.admissionChecks, 0,
    "no journal admission is inspected or mutated for an unsigned entry");

  const valid = await signed("positive-incoming");
  const digest = await engine.verifyIncomingOperation(valid, { preObserve: false });
  assert.equal(typeof digest, "string");
  assert.equal(calls.incoming, 1,
    "the positive control must actually reach the injected verifier");
});

test("independently pinned Ed25519 verifier rejects a forged signature and revoked key", async () => {
  const valid = await signed("verified-incoming");
  const trustedKey = valid.authorization.publicKey;
  const { engine, calls } = fixture();
  engine.verifyIncoming = async (candidate) => {
    calls.incoming += 1;
    return verifyAuthorizationProof(candidate.authorization, candidate, {
      username: "alice",
      trustedDevicePublicKeys: { "device-a": trustedKey },
      revokedDeviceIds: [],
    });
  };
  assert.equal(typeof await engine.verifyIncomingOperation(valid, { preObserve: false }),
    "string", "the genuine signed envelope must pass the independently pinned verifier");
  const forged = { ...valid, authorization: { ...valid.authorization,
    signature: crypto.randomBytes(64).toString("base64url") } };
  await assert.rejects(engine.verifyIncomingOperation(forged, { preObserve: false }),
    { code: "authorization_signature" },
    "a valid-shape, valid-digest envelope with a forged signature MUST reach cryptographic rejection");
  // A completely valid attacker signature must not enroll its own supplied
  // SPKI merely by passing structural digest/Ed25519 verification.
  const rogue = await signed("untrusted-rogue");
  assert.notEqual(rogue.authorization.publicKey, trustedKey);
  await assert.rejects(engine.verifyIncomingOperation(rogue, { preObserve: false }),
    { code: "authorization_device_untrusted" },
    "independently pinned survivor key must reject a rogue self-enrollment");
  engine.verifyIncoming = async (candidate) => {
    calls.incoming += 1;
    return verifyAuthorizationProof(candidate.authorization, candidate, {
      username: "alice",
      trustedDevicePublicKeys: { "device-a": trustedKey },
      revokedDeviceIds: ["device-a"],
    });
  };
  await assert.rejects(engine.verifyIncomingOperation(valid, { preObserve: false }),
    { code: "authorization_device_revoked" },
    "historical signature authenticity cannot authorize revoked device ingress");
  assert.equal(calls.incoming, 4,
    "all controls must reach the actual verifier, not a superficial shape check");
});
