"use strict";

// Real Ed25519 owner-independent inventory/PG/witness/device proof chain with
// an operator-owned live revocation decision. This is a synthetic, non-durable
// read proof, never a claim of independent production custody.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyHistoricalAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");
const pg = require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { envelopeBinding, verifySyncV2HistoricalWitnessAdmission } =
  require("../sync-client/rootark-sync-zk1-physical-binding");

const sha = (value) => crypto.createHash("sha256").update(value).digest("base64url");
const id = (value) => Buffer.alloc(16, value);
const hash = (value) => Buffer.alloc(32, value);
const domainEntry = Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0");
const domainFloor = Buffer.from("Root.ark/zk-1/witness-cas-physical-floor/v2\0");
const domainAdmission = Buffer.from("Root.ark/sync-v2/historical-witness-admission/v1\0");

async function genuineHistoricalEvidence({
  witnessIsInventory = false, witnessIsDevice = false,
  issuedAtSeconds = null, admittedAtMs = null, mismatchedDeviceKey = false,
  forgedDeviceSignature = false, expiredDeviceAuthorization = false,
} = {}) {
  const device = crypto.generateKeyPairSync("ed25519");
  const declaredDevice = mismatchedDeviceKey ? crypto.generateKeyPairSync("ed25519") : device;
  const inventory = crypto.generateKeyPairSync("ed25519");
  const attestor = crypto.generateKeyPairSync("ed25519");
  const witness = witnessIsDevice ? device : witnessIsInventory
    ? inventory : crypto.generateKeyPairSync("ed25519");
  const spki = declaredDevice.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const envelope = protocol.createOperation({ operation: "create", objectId: "object_1",
    fileId: "file_1", versionId: "version_1", deviceId: "device_1",
    compartmentId: "vault", keyEpoch: "epoch-1",
    revision: { counter: 1, deviceId: "device_1" },
    metadata: { path: "read-me.txt" }, plaintext: Buffer.from("historical positive"),
    fileKey: crypto.randomBytes(32) });
  envelope.authorization = await createAuthorizationProof(envelope, {
    username: "alice", publicKey: spki, privateKey: device.privateKey,
    expiresAt: Date.now() + 120_000,
  });
  if (expiredDeviceAuthorization) {
    // Genuine original Ed25519 authorization for an already-expired record;
    // createAuthorizationProof intentionally permits only newly fresh claims.
    envelope.authorization.expiresAt = Date.now() - 10_000;
    const { signature: _old, ...unsigned } = envelope.authorization;
    const signedBytes = Buffer.concat([Buffer.from(z.ASCII.AUTHORIZATION, "ascii"),
      Buffer.from([0]), await z.encodeDeterministic(unsigned)]);
    envelope.authorization.signature = crypto.sign(null, signedBytes,
      device.privateKey).toString("base64url");
  }
  if (forgedDeviceSignature) {
    const validSignature = envelope.authorization.signature;
    envelope.authorization.signature = `${validSignature[0] === "A" ? "B" : "A"}${validSignature.slice(1)}`;
  }
  const scope = { account_id: id(35), compartment_id: Buffer.from("vault"),
    keyring_id: id(36) };
  const bound = envelopeBinding(envelope, scope, 0, hash(37));
  const operation = bound.operation;
  const signerKeyId = id(38);
  const nonce = hash(39);
  const nowSeconds = issuedAtSeconds ?? Math.floor(Date.now() / 1000);
  const entry = { object_id: operation.object_id, revision: operation.revision,
    epoch: operation.epoch, ciphertext_sha256: operation.ciphertext_sha256 };
  const receiptBody = { type: "rootark-content-inventory-entry/v1", version: 1,
    signer_key_id: signerKeyId, scope, sequence: 1,
    previous_root: operation.expected_root, root: hash(40),
    operation_id: operation.operation_id,
    expected_sequence: operation.expected_sequence,
    expected_root: operation.expected_root,
    request_digest: crypto.createHash("sha256")
      .update(await z.encodeDeterministic(operation)).digest(), entry };
  const receiptSignature = crypto.sign(null, Buffer.concat([
    domainEntry, await z.encodeDeterministic(receiptBody),
  ]), inventory.privateKey);
  const receipt = Buffer.from(await z.encodeDeterministic({
    ...receiptBody, signature: receiptSignature,
  }));
  const physicalAttestation = await pg.signCommittedPhysicalReadback({
    scope, operation, nonce, issuedAt: nowSeconds,
    readback: { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation: 1, admissionId: id(41),
      operationId: operation.operation_id, revision: operation.revision,
      epoch: operation.epoch, digest: hash(42),
      expectedInventorySequence: operation.expected_sequence,
      expectedInventoryRoot: operation.expected_root, chunkCount: 1,
      root: hash(43), ciphertextSha256: operation.ciphertext_sha256,
      authorizesIo: false, provesIndependentOperator: false },
  }, attestor.privateKey);
  const witnessKeyId = id(44);
  const statusKeyId = id(45);
  const floorBody = { type: "rootark-zk1-witness-cas-physical-floor/v2",
    witnessKeyId: witnessKeyId.toString("base64url"),
    statusKeyId: statusKeyId.toString("base64url"),
    sequence: 2, lastHash: hash(46).toString("hex"),
    physicalFenceDigest: hash(47).toString("hex"),
    nonce: nonce.toString("base64url") };
  const freshFloor = { ...floorBody, signature: crypto.sign(null,
    Buffer.concat([domainFloor, Buffer.from(JSON.stringify(floorBody))]),
    witness.privateKey).toString("base64url") };
  const admissionBody = { type: "rootark-sync-v2-historical-witness-admission/v1",
    envelopeSha256: sha(bound.canonicalEnvelope),
    operationId: operation.operation_id.toString("base64url"),
    deviceId: envelope.deviceId,
    deviceSpkiSha256: sha(Buffer.from(spki, "base64url")),
    epoch: operation.epoch, checkpointSequence: operation.expected_sequence,
    checkpointRoot: operation.expected_root.toString("base64url"),
    inventoryReceiptSha256: sha(receipt),
    admittedAtMs: admittedAtMs ?? (expiredDeviceAuthorization
      ? envelope.authorization.expiresAt - 1000 : Date.now() - 1000),
    witnessSequence: floorBody.sequence, witnessLastHash: floorBody.lastHash,
    witnessPhysicalFenceDigest: floorBody.physicalFenceDigest };
  const admission = { ...admissionBody, signature: crypto.sign(null,
    Buffer.concat([domainAdmission, Buffer.from(JSON.stringify(admissionBody))]),
    witness.privateKey).toString("base64url") };
  const allowed = { username: "alice", trustedDevicePublicKeys: { device_1: spki },
    revokedDeviceIds: [] };
  const revoked = { username: "alice", trustedDevicePublicKeys: { device_1: spki },
    revokedDeviceIds: ["device_1"] };
  const input = { envelope, scope, expectedSequence: 0,
    expectedRoot: operation.expected_root, receipt, physicalAttestation,
    nonce, pinnedInventoryPublicKey: inventory.publicKey,
    pinnedInventorySignerKeyId: signerKeyId,
    pinnedPhysicalAttestorPublicKey: attestor.publicKey,
    localTrustedDevicePolicy: allowed, trustedCurrentDevicePolicyProvider: () => allowed,
    admission, freshFloor, pinnedWitnessPublicKey: witness.publicKey,
    witnessKeyId, statusKeyId,
    trustedMinimumFloor: { sequence: floorBody.sequence,
      lastHash: floorBody.lastHash, physicalFenceDigest: floorBody.physicalFenceDigest } };
  return { input, allowed, revoked, witness, inventory, attestor, device, declaredDevice, spki,
    scope, operation };
}

test("P2 physical: native witness getter cannot rewind verification time for genuinely signed stale PG A", async () => {
  const realNow = Date.now;
  const oldSeconds = Math.floor(realNow() / 1000) - 120;
  const f = await genuineHistoricalEvidence({
    issuedAtSeconds: oldSeconds, admittedAtMs: oldSeconds * 1000 + 1000,
  });
  assert.equal(crypto.verify(null, Buffer.concat([domainFloor, Buffer.from(JSON.stringify((({ signature, ...body }) => body)(f.input.freshFloor)))]),
    f.witness.publicKey, Buffer.from(f.input.freshFloor.signature, "base64url")), true);
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission(f.input),
    { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" }, "signed PG attestation older than 30 s is stale");
  let rewinds = 0;
  const old = poisonedNativeKey(f.witness.publicKey, () => {
    Date.now = () => { rewinds++; return oldSeconds * 1000 + 2000; };
  });
  try {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      ...f.input, pinnedWitnessPublicKey: old.publicKey,
    }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" },
    "rewinding a JS callback clock cannot revive real signed old PG bytes");
  } finally { Date.now = realNow; }
  assert.ok(old.reads > 0, "attacker's native getter must execute");
  assert.equal(rewinds, 0, "verification must not use callback-rebound Date.now");
  const good = await genuineHistoricalEvidence();
  assert.equal((await verifySyncV2HistoricalWitnessAdmission(good.input)).authorizesHistoricalRead, true);
});

test("P2 physical: native witness getter cannot suppress stale PG detection with mutable Math.abs", async () => {
  const oldSeconds = Math.floor(Date.now() / 1000) - 120;
  const f = await genuineHistoricalEvidence({
    issuedAtSeconds: oldSeconds, admittedAtMs: oldSeconds * 1000 + 1000,
  });
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission(f.input),
    { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  const originalAbs = Math.abs;
  let bypassCalls = 0;
  const poison = poisonedNativeKey(f.witness.publicKey, () => {
    Math.abs = () => { bypassCalls++; return 0; };
  });
  try {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      ...f.input, pinnedWitnessPublicKey: poison.publicKey,
    }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" },
    "post-getter Math.abs cannot claim a 120-second-old Ed25519 PG is fresh");
  } finally { Math.abs = originalAbs; }
  assert.ok(poison.reads > 0);
  assert.equal(bypassCalls, 0, "signed issue-time delta must use a captured numeric primitive");
  assert.equal((await verifySyncV2HistoricalWitnessAdmission((await genuineHistoricalEvidence()).input)).authorizesHistoricalRead, true);
});

test("P2 physical: native witness getter cannot retarget Math.floor for real signed PG clock", async () => {
  const oldSeconds = Math.floor(Date.now() / 1000) - 120;
  const f = await genuineHistoricalEvidence({
    issuedAtSeconds: oldSeconds, admittedAtMs: oldSeconds * 1000 + 1000,
  });
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission(f.input),
    { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  const originalFloor = Math.floor;
  let bypassCalls = 0;
  const poison = poisonedNativeKey(f.witness.publicKey, () => {
    Math.floor = (value) => {
      if (typeof value === "number" && value > 1000000) {
        bypassCalls++;
        return oldSeconds + 1;
      }
      return originalFloor(value);
    };
  });
  try {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      ...f.input, pinnedWitnessPublicKey: poison.publicKey,
    }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" },
    "post-key Math.floor must not shift the trusted now-seconds into stale A's window");
  } finally { Math.floor = originalFloor; }
  assert.ok(poison.reads > 0);
  assert.equal(bypassCalls, 0, "current clock conversion must use captured Math.floor");
  assert.equal((await verifySyncV2HistoricalWitnessAdmission((await genuineHistoricalEvidence()).input)).authorizesHistoricalRead, true);
});

test("P2 physical: witness getter cannot redirect dynamic device crypto.createPublicKey from declared B to signer A", async () => {
  const f = await genuineHistoricalEvidence({ mismatchedDeviceKey: true });
  assert.equal(f.device.publicKey.equals(f.declaredDevice.publicKey), false);
  await assert.rejects(verifyHistoricalAuthorizationProof(
    f.input.envelope.authorization, f.input.envelope, f.allowed),
  "real Ed25519 A signed an authorization declaring unrelated key B");
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission(f.input),
    { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  const original = crypto.createPublicKey;
  const declaredDer = f.declaredDevice.publicKey.export({ format: "der", type: "spki" });
  let replaced = 0;
  const poison = poisonedNativeKey(f.witness.publicKey, () => {
    crypto.createPublicKey = function(input) {
      if (input?.key?.equals?.(declaredDer)) {
        replaced++;
        return f.device.publicKey;
      }
      return original(input);
    };
  });
  try {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      ...f.input, pinnedWitnessPublicKey: poison.publicKey,
    }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  } finally { crypto.createPublicKey = original; }
  assert.ok(poison.reads > 0);
  assert.equal(replaced, 0, "device Ed25519 verifier must use captured native key decoder");
  assert.equal((await verifySyncV2HistoricalWitnessAdmission((await genuineHistoricalEvidence()).input)).authorizesHistoricalRead, true);
});

test("P2 physical: witness getter cannot turn invalid device Ed25519 signature B into an authorized read", async () => {
  const f = await genuineHistoricalEvidence({ forgedDeviceSignature: true });
  await assert.rejects(verifyHistoricalAuthorizationProof(
    f.input.envelope.authorization, f.input.envelope, f.allowed));
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission(f.input),
    { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  const original = crypto.verify;
  let faked = 0;
  const poison = poisonedNativeKey(f.witness.publicKey, () => {
    crypto.verify = (...args) => { faked++; return true; };
  });
  try {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      ...f.input, pinnedWitnessPublicKey: poison.publicKey,
    }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  } finally { crypto.verify = original; }
  assert.ok(poison.reads > 0);
  assert.equal(faked, 0, "post-getter mutable crypto.verify must never validate device authorization");
  assert.equal((await verifySyncV2HistoricalWitnessAdmission((await genuineHistoricalEvidence()).input)).authorizesHistoricalRead, true);
});

test("P2 historical: witness native getter cannot mutate externally retained revoked-device B policy into allowed A", async () => {
  const f = await genuineHistoricalEvidence();
  const restricted = { username: f.revoked.username,
    trustedDevicePublicKeys: { ...f.revoked.trustedDevicePublicKeys },
    revokedDeviceIds: ["device_1"] };
  const rejected = { ...f.input, localTrustedDevicePolicy: restricted };
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission(rejected),
    { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" },
    "a genuine device A was independently revoked");
  let tampered = 0;
  const evil = poisonedNativeKey(f.witness.publicKey, () => {
    tampered++;
    restricted.revokedDeviceIds = [];
  });
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
    ...rejected, pinnedWitnessPublicKey: evil.publicKey,
  }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" },
  "operator-pinned local revocation must be snapshotted before native witness getters");
  assert.ok(evil.reads > 0 && tampered > 0);
  assert.equal((await verifySyncV2HistoricalWitnessAdmission(f.input))
    .authorizesHistoricalRead, true, "independently allowed genuine device remains valid");
});

test("P2 historical: signed witness floor A cannot replace independently retained minimum floor B after key callback", async () => {
  const f = await genuineHistoricalEvidence();
  const floorB = { ...f.input.trustedMinimumFloor,
    sequence: f.input.trustedMinimumFloor.sequence + 1,
    lastHash: Buffer.alloc(32, 211).toString("hex") };
  assert.notEqual(floorB.sequence, f.input.freshFloor.sequence);
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
    ...f.input, trustedMinimumFloor: floorB,
  }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  let mutated = 0;
  const evil = poisonedNativeKey(f.witness.publicKey, () => {
    mutated++;
    floorB.sequence = f.input.trustedMinimumFloor.sequence;
    floorB.lastHash = f.input.trustedMinimumFloor.lastHash;
  });
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
    ...f.input, trustedMinimumFloor: floorB, pinnedWitnessPublicKey: evil.publicKey,
  }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" },
  "operator-retained floor B must be captured before hostile witness native key getter");
  assert.ok(evil.reads > 0 && mutated > 0);
  assert.equal((await verifySyncV2HistoricalWitnessAdmission(f.input))
    .authorizesHistoricalRead, true);
});

test("P2 strict Sync v2: evidence-provider callback cannot replay signed old challenge A by replacing crypto.randomBytes", async () => {
  const f = await genuineHistoricalEvidence({ expiredDeviceAuthorization: true });
  assert.ok(f.input.envelope.authorization.expiresAt < Date.now());
  assert.equal((await verifySyncV2HistoricalWitnessAdmission(f.input)).authorizesHistoricalRead,
    true, "genuinely signed, already-expired device A was historically admitted");
  const Module = require("node:module");
  const cache = new Map();
  const originalRandom = crypto.randomBytes;
  const oldLog = console.log;
  const envKeys = ["ROOTARK_SYNC_FILE_KEY", "ROOTARK_SYNC_DEVICE_PRIVATE_KEY",
    "ROOTARK_SYNC_DEVICE_PUBLIC_KEY"];
  const previousEnv = Object.fromEntries(envKeys.map((name) => [name, process.env[name]]));
  const issuedA = Buffer.from(f.input.nonce);
  let offered = 0, replayed = 0, challenges = 0;
  class FakeSyncEngine {
    constructor(options) { this.options = options; this.incomingAllowed = null; }
    async open() { return this; }
    async syncOnce() {
      this.incomingAllowed = await this.options.verifyIncoming(f.input.envelope);
      return { pushed: 0, pulled: 0, conflicts: [], offline: false };
    }
  }
  const stub = (relative, exports) => {
    const id = require.resolve(relative);
    cache.set(id, require.cache[id]);
    const moduleStub = new Module(id, module);
    moduleStub.filename = id;
    moduleStub.loaded = true;
    moduleStub.exports = exports;
    require.cache[id] = moduleStub;
  };
  const config = { serverUrl: "https://sync.example.test", token: "synthetic",
    username: "alice", deviceId: "device_1", keyEpoch: "epoch-1",
    compartmentId: "vault", localFolder: process.cwd(),
    trustedDevicePublicKeys: { device_1: f.spki }, revokedDeviceIds: [],
    deviceRevoked: false };
  const proof = { scope: f.input.scope, expectedSequence: f.input.expectedSequence,
    expectedRoot: f.input.expectedRoot, receipt: f.input.receipt,
    physicalAttestation: f.input.physicalAttestation,
    admission: f.input.admission, freshFloor: f.input.freshFloor };
  try {
    process.env.ROOTARK_SYNC_FILE_KEY = Buffer.alloc(32, 52).toString("base64url");
    process.env.ROOTARK_SYNC_DEVICE_PRIVATE_KEY = f.device.privateKey.export({
      format: "der", type: "pkcs8",
    }).toString("base64url");
    process.env.ROOTARK_SYNC_DEVICE_PUBLIC_KEY = f.spki;
    stub("../sync-client/rootark-sync-engine", { SyncEngine: FakeSyncEngine });
    stub("../sync-client/rootark-sync-v2-private-config", {
      readPrivateV2Config: () => config,
    });
    stub("../public/client/rootark-sync-adapter", { createOpaqueSyncAdapter: () => ({}) });
    const clientId = require.resolve("../sync-client/rootark-sync-v2");
    cache.set(clientId, require.cache[clientId]);
    delete require.cache[clientId];
    const { start } = require(clientId);
    console.log = () => {};
    const engine = await start({ once: true, requireIndependentHistoricalAdmission: true,
      trustedHistoricalAdmission: {
        localTrustedDevicePolicy: f.allowed,
        trustedCurrentDevicePolicyProvider: () => f.allowed,
        pinnedInventoryPublicKey: f.inventory.publicKey,
        pinnedInventorySignerKeyId: f.input.pinnedInventorySignerKeyId,
        pinnedPhysicalAttestorPublicKey: f.attestor.publicKey,
        pinnedWitnessPublicKey: f.witness.publicKey,
        witnessKeyId: f.input.witnessKeyId, statusKeyId: f.input.statusKeyId,
        trustedMinimumFloor: f.input.trustedMinimumFloor,
      },
      historicalEvidenceProvider: async (_operation, { nonce }) => {
        challenges++;
        if (challenges === 1) {
          assert.equal(nonce.equals(issuedA), false,
            "new client challenge is independent of the earlier signed nonce A");
          crypto.randomBytes = function(size, ...args) {
            if (size === 32) { replayed++; return Buffer.from(issuedA); }
            return originalRandom(size, ...args);
          };
          return null;
        }
        offered++;
        return proof;
      },
    });
    assert.equal(engine.incomingAllowed, false,
      "historical signed nonce A must not be replayable by poisoning client crypto.randomBytes");
    assert.equal(challenges, 3, "fresh challenge must be generated on each recovery/issue attempt");
    assert.equal(replayed, 0, "post-callback randomBytes replacement must never issue a challenge");
    assert.equal(offered, 2, "real signed replay was presented twice and denied");
  } finally {
    crypto.randomBytes = originalRandom;
    console.log = oldLog;
    for (const [id, old] of cache) {
      if (old) require.cache[id] = old;
      else delete require.cache[id];
    }
    for (const name of envKeys) {
      if (previousEnv[name] === undefined) delete process.env[name];
      else process.env[name] = previousEnv[name];
    }
  }
});

function poisonedNativeKey(publicKey, poison) {
  const handle = Object.getOwnPropertySymbols(publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "Node 22 genuine Ed25519 native kHandle");
  const inherited = Object.create(publicKey);
  let reads = 0;
  Object.defineProperty(inherited, handle, { get() {
    reads += 1;
    poison();
    return publicKey[handle];
  } });
  return { publicKey: inherited, get reads() { return reads; } };
}

test("P2 physical: native witness getter must not substitute a foreign device SPKI B for signed device A", async () => {
  // The device and witness are the SAME real Ed25519 principal. Their role
  // collision must fail even when a witness signs a false independent-device
  // claim referring to another generated, unrelated key B.
  const f = await genuineHistoricalEvidence({ witnessIsDevice: true });
  const otherDevice = crypto.generateKeyPairSync("ed25519");
  const independentDer = otherDevice.publicKey.export({ type: "spki", format: "der" });
  assert.notEqual(independentDer.toString("base64url"), f.spki);
  assert.equal(f.device.publicKey.equals(f.witness.publicKey), true);
  const { signature: _old, ...admissionA } = f.input.admission;
  const admissionB = { ...admissionA, deviceSpkiSha256: sha(independentDer) };
  const statementB = Buffer.concat([domainAdmission, Buffer.from(JSON.stringify(admissionB))]);
  const signatureB = crypto.sign(null, statementB, f.witness.privateKey);
  assert.equal(crypto.verify(null, statementB, f.witness.publicKey, signatureB), true,
    "false device-B statement was genuinely signed by witness/device A");
  const forged = { ...f.input, admission: {
    ...admissionB, signature: signatureB.toString("base64url"),
  } };
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission(forged),
    { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });

  const originalFrom = Buffer.from;
  let substituted = 0;
  const evil = poisonedNativeKey(f.witness.publicKey, () => {
    Buffer.from = function(value, encoding, ...rest) {
      if (value === f.spki && encoding === "base64url" && substituted === 0) {
        substituted += 1;
        // Only the verifier's post-getter raw SPKI decode gets identity B.
        Buffer.from = originalFrom;
        return originalFrom(independentDer);
      }
      return Reflect.apply(originalFrom, Buffer, [value, encoding, ...rest]);
    };
  });
  try {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      ...forged, pinnedWitnessPublicKey: evil.publicKey,
    }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  } finally { Buffer.from = originalFrom; }
  assert.ok(evil.reads > 0);
  assert.equal(substituted, 0, "verifier must use the pre-getter Buffer decoder");
  const good = await genuineHistoricalEvidence();
  assert.equal((await verifySyncV2HistoricalWitnessAdmission(good.input))
    .authorizesHistoricalRead, true);
});

test("P2 physical: post-key Buffer.from cannot launder a forged floor signature B into valid signature A", async () => {
  const f = await genuineHistoricalEvidence();
  const { signature: signedA, ...floorStatement } = f.input.freshFloor;
  const floorBytes = Buffer.concat([domainFloor, Buffer.from(JSON.stringify(floorStatement))]);
  assert.equal(crypto.verify(null, floorBytes, f.witness.publicKey,
    Buffer.from(signedA, "base64url")), true);
  const signedB = `${signedA[0] === "A" ? "B" : "A"}${signedA.slice(1)}`;
  assert.equal(crypto.verify(null, floorBytes, f.witness.publicKey,
    Buffer.from(signedB, "base64url")), false,
  "presented B signature is invalid despite valid historical signature A");
  const forged = { ...f.input, freshFloor: {
    ...f.input.freshFloor, signature: signedB,
  } };
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission(forged),
    { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  const originalFrom = Buffer.from;
  let substitutions = 0;
  const evil = poisonedNativeKey(f.witness.publicKey, () => {
    Buffer.from = function(value, encoding, ...rest) {
      if (value === signedB && encoding === "base64url") {
        substitutions += 1;
        return originalFrom(signedA, "base64url");
      }
      return Reflect.apply(originalFrom, Buffer, [value, encoding, ...rest]);
    };
  });
  try {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      ...forged, pinnedWitnessPublicKey: evil.publicKey,
    }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  } finally { Buffer.from = originalFrom; }
  assert.ok(evil.reads > 0);
  assert.equal(substitutions, 0, "signature decoding must retain native Buffer.from");
  assert.equal((await verifySyncV2HistoricalWitnessAdmission(f.input))
    .authorizesHistoricalRead, true);
});

test("P2 physical: signed ciphertext digest A must remain A after a malicious live-policy callback", async () => {
  const f = await genuineHistoricalEvidence();
  const signedA = Buffer.from(f.operation.ciphertext_sha256);
  const forgedDigestB = Buffer.alloc(32, 209);
  assert.equal(signedA.equals(forgedDigestB), false);
  const genuine = await verifySyncV2HistoricalWitnessAdmission(f.input);
  assert.deepEqual(genuine.envelopeSha256, signedA);
  assert.equal(genuine.authorizesHistoricalRead, true);
  const originalFrom = Buffer.from;
  let providerCalls = 0;
  let substitutions = 0;
  let result;
  try {
    result = await verifySyncV2HistoricalWitnessAdmission({
      ...f.input,
      trustedCurrentDevicePolicyProvider: () => {
        providerCalls += 1;
        Buffer.from = function(value, ...rest) {
          if (Buffer.isBuffer(value) && value.length === 32 && value.equals(signedA)) {
            substitutions += 1;
            return originalFrom(forgedDigestB);
          }
          return Reflect.apply(originalFrom, Buffer, [value, ...rest]);
        };
        return f.allowed;
      },
    });
  } finally { Buffer.from = originalFrom; }
  assert.equal(providerCalls, 1, "live-policy callback executes after genuine Ed25519 verification");
  assert.equal(substitutions, 0, "returned digest must use the early native buffer copy");
  assert.deepEqual(result.envelopeSha256, signedA,
    "real signature for ciphertext digest A cannot be published as ciphertext B");
  assert.equal(result.authorizesHistoricalRead, true);
  assert.equal(result.authorizesIo, false);
});

test("P2 historical: real signed valid read survives, revoked device never becomes authorized after witness getter", async () => {
  const f = await genuineHistoricalEvidence();
  const positive = await verifySyncV2HistoricalWitnessAdmission(f.input);
  assert.equal(positive.status, "SYNC_V2_HISTORICAL_WITNESS_VERIFIED");
  assert.equal(positive.authorizesHistoricalRead, true);
  assert.equal(positive.authorizesIo, false);
  const revokedInput = { ...f.input,
    trustedCurrentDevicePolicyProvider: () => f.revoked };
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission(revokedInput),
    { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });

  const handle = Object.getOwnPropertySymbols(f.witness.publicKey)
    .find((value) => value.description === "kHandle");
  assert.ok(handle, "real Ed25519 witness native getter");
  const inherited = Object.create(f.witness.publicKey);
  let reads = 0;
  const nativePush = Array.prototype.push;
  const nativeIncludes = Array.prototype.includes;
  Object.defineProperty(inherited, handle, { get() {
    reads += 1;
    Array.prototype.push = function(...values) {
      if (values.length === 1 && values[0] === "device_1") return this.length;
      return Reflect.apply(nativePush, this, values);
    };
    Array.prototype.includes = function(value, ...rest) {
      if (value === "device_1" && this[0] === "device_1") return false;
      return Reflect.apply(nativeIncludes, this, [value, ...rest]);
    };
    return f.witness.publicKey[handle];
  } });
  try {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      ...revokedInput, pinnedWitnessPublicKey: inherited,
    }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  } finally {
    Array.prototype.push = nativePush;
    Array.prototype.includes = nativeIncludes;
  }
  assert.ok(reads > 0, "physical native witness getter must be exercised");
  assert.equal((await verifySyncV2HistoricalWitnessAdmission(f.input))
    .authorizesHistoricalRead, true, "valid historical signer and device remain accepted");
});

test("P2 historical: witness cannot impersonate inventory signer via poisoned array iterator", async () => {
  const f = await genuineHistoricalEvidence({ witnessIsInventory: true });
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission(f.input),
    { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  const handle = Object.getOwnPropertySymbols(f.witness.publicKey)
    .find((value) => value.description === "kHandle");
  assert.ok(handle);
  let invoked = 0;
  let skipped = 0;
  const oldIterator = Array.prototype[Symbol.iterator];
  const inherited = Object.create(f.witness.publicKey);
  Object.defineProperty(inherited, handle, { get() {
    invoked += 1;
    Array.prototype[Symbol.iterator] = function*() {
      if (this.length === 3 && this[0] === f.inventory.publicKey
        && this[1] === f.attestor.publicKey) {
        skipped += 1;
        return;
      }
      yield* Reflect.apply(oldIterator, this, []);
    };
    return f.witness.publicKey[handle];
  } });
  try {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      ...f.input, pinnedWitnessPublicKey: inherited,
    }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  } finally {
    Array.prototype[Symbol.iterator] = oldIterator;
  }
  assert.ok(invoked > 0, "real inherited native kHandle was reached");
  assert.equal(skipped, 0, "the verifier must never consult the poisoned pin iterator");
});

test("P2 historical: signed witness floor nonce A cannot be replayed for new challenge B", async () => {
  const f = await genuineHistoricalEvidence();
  const nonceB = Buffer.alloc(32, 85);
  const nowSeconds = Math.floor(Date.now() / 1000);
  const physicalB = await pg.signCommittedPhysicalReadback({
    scope: f.scope, operation: f.operation, nonce: nonceB,
    issuedAt: nowSeconds,
    readback: { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation: 1, admissionId: id(41),
      operationId: f.operation.operation_id, revision: f.operation.revision,
      epoch: f.operation.epoch, digest: hash(42),
      expectedInventorySequence: f.operation.expected_sequence,
      expectedInventoryRoot: f.operation.expected_root, chunkCount: 1,
      root: hash(43), ciphertextSha256: f.operation.ciphertext_sha256,
      authorizesIo: false, provesIndependentOperator: false },
  }, f.attestor.privateKey);
  const replayInput = { ...f.input, nonce: nonceB, physicalAttestation: physicalB };
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission(replayInput),
    { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  const originalToString = Buffer.prototype.toString;
  const signedNonceA = f.input.nonce.toString("base64url");
  const handle = Object.getOwnPropertySymbols(f.witness.publicKey)
    .find((value) => value.description === "kHandle");
  assert.ok(handle);
  let invoked = 0;
  let altered = 0;
  const inherited = Object.create(f.witness.publicKey);
  Object.defineProperty(inherited, handle, { get() {
    invoked += 1;
    Buffer.prototype.toString = function(encoding, ...rest) {
      if (encoding === "base64url" && this.length === 32
        && crypto.timingSafeEqual(this, nonceB)) {
        altered += 1;
        return signedNonceA;
      }
      return Reflect.apply(originalToString, this, [encoding, ...rest]);
    };
    return f.witness.publicKey[handle];
  } });
  try {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      ...replayInput, pinnedWitnessPublicKey: inherited,
    }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  } finally {
    Buffer.prototype.toString = originalToString;
  }
  assert.ok(invoked > 0, "real inherited native kHandle was reached");
  assert.equal(altered, 0, "the verifier must use the captured Buffer serializer");
  assert.equal((await verifySyncV2HistoricalWitnessAdmission(f.input))
    .authorizesHistoricalRead, true);
});
