"use strict";

// Disposable Ed25519 keys and a genuine device authorization. This is an
// isolated native-invocation/role-separation probe, NOT a production admission
// receipt, independent witness custody or proof of positive PostgreSQL IO.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const NATIVE_KEY_EQUALS = crypto.KeyObject.prototype.equals;
const { verifyAttestedInventoryCommit } =
  require("../src/crypto/rootark-zk1-attested-inventory-commit-v1");
const { verifySyncV2HistoricalWitnessAdmission } =
  require("../sync-client/rootark-sync-zk1-physical-binding");

test("P2 physical: same Ed25519 inventory and PG signer cannot be disguised by inherited kHandle poisoning Function.call", async () => {
  const real = crypto.generateKeyPairSync("ed25519").publicKey;
  const symbol = Object.getOwnPropertySymbols(real)
    .find((value) => value.description === "kHandle");
  assert.ok(symbol, "Node 22 native KeyObject handle is required");
  const inherited = Object.create(real);
  const originalCall = Function.prototype.call;
  const trustedApply = Reflect.apply;
  let getterReads = 0;
  let equalityBypassAttempts = 0;
  let proofDecodeAttempts = 0;
  Object.defineProperty(inherited, symbol, { get() {
    getterReads++;
    Function.prototype.call = function(receiver, ...args) {
      if (this === NATIVE_KEY_EQUALS) {
        equalityBypassAttempts++;
        return false; // Same real physical key falsely declared separate
      }
      return trustedApply(this, receiver, args);
    };
    return real[symbol];
  } });
  // Expected scope/operation must now be safely snapshotted BEFORE the key
  // callback; valid detached fields keep the native role check reachable.
  const expectedScope = { account_id: Buffer.alloc(16, 15),
    compartment_id: Buffer.from("private"), keyring_id: Buffer.alloc(16, 16) };
  const expectedOperation = { operation_id: Buffer.alloc(16, 17), expected_sequence: 0,
    expected_root: Buffer.alloc(32, 18), object_id: Buffer.alloc(16, 19),
    revision: 1, epoch: 1, ciphertext_sha256: Buffer.alloc(32, 20) };
  const realDecode = z.decodeDeterministic;
  z.decodeDeterministic = async () => { proofDecodeAttempts++; throw Error("proof reached after role collision"); };
  try {
    await assert.rejects(verifyAttestedInventoryCommit({
      receipt: Buffer.from([1]), physicalAttestation: Buffer.from([1]),
      scope: expectedScope, operation: expectedOperation, nonce: Buffer.alloc(32, 11),
      pinnedInventoryPublicKey: inherited,
      pinnedInventorySignerKeyId: Buffer.alloc(16, 12),
      pinnedPhysicalAttestorPublicKey: real, nowSeconds: 1,
    }), /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/);
  } finally { Function.prototype.call = originalCall; z.decodeDeterministic = realDecode; }
  assert.ok(getterReads > 0, "genuine native getter must have run");
  assert.equal(equalityBypassAttempts, 0, "no mutable .call can suppress native signer equality");
  assert.equal(proofDecodeAttempts, 0, "equal real signers must reject before untrusted proof parsing");
});

test("P2: native inventory/PG operator separation cannot use mutable Function.call", async () => {
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  const trustedCall = Function.prototype.call;
  const trustedApply = Reflect.apply;
  let equalityBypassAttempts = 0;
  Function.prototype.call = function (receiver, ...args) {
    if (this === NATIVE_KEY_EQUALS && receiver === publicKey && args[0] === publicKey) {
      equalityBypassAttempts++;
      return false; // forge distinct operators for the SAME actual Ed25519 pin
    }
    return trustedApply(trustedCall, this, [receiver, ...args]);
  };
  try {
    await assert.rejects(verifyAttestedInventoryCommit({
      receipt: Buffer.from([0x01]), physicalAttestation: Buffer.from([0x01]),
      scope: {}, operation: {}, nonce: Buffer.alloc(32, 7),
      pinnedInventoryPublicKey: publicKey,
      pinnedInventorySignerKeyId: Buffer.alloc(16, 4),
      pinnedPhysicalAttestorPublicKey: publicKey, nowSeconds: 1,
    }), /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/);
  } finally { Function.prototype.call = trustedCall; }
  assert.equal(equalityBypassAttempts, 0,
    "an early native KeyObject.equals must not call attacker-retargetable .call");
});

test("P2: historical witness role collision is denied before an untrusted floor Proxy runs", async () => {
  const device = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const deviceSpki = device.publicKey.export({ type: "spki", format: "der" })
    .toString("base64url");
  const operation = protocol.createOperation({
    operation: "create", objectId: "object_1", fileId: "file_1",
    versionId: "version_1", deviceId: "device_1", compartmentId: "vault",
    keyEpoch: "epoch-1", revision: { counter: 1, deviceId: "device_1" },
    metadata: { path: "notes.txt" }, plaintext: Buffer.from("physical-bound synthetic"),
    fileKey: crypto.randomBytes(32),
  });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", publicKey: deviceSpki, privateKey: device.privateKey,
    expiresAt: Date.now() + 60_000,
  });
  const policy = { username: "alice", trustedDevicePublicKeys: {
    device_1: deviceSpki }, revokedDeviceIds: [] };
  let foreignTraps = 0;
  const hostileFloor = new Proxy({}, {
    ownKeys() { foreignTraps++; return []; },
  });
  const trustedCall = Function.prototype.call;
  const trustedApply = Reflect.apply;
  let equalityBypassAttempts = 0;
  Function.prototype.call = function (receiver, ...args) {
    if (this === NATIVE_KEY_EQUALS) {
      equalityBypassAttempts++;
      return false; // falsely assert witness and inventory are different keys
    }
    return trustedApply(trustedCall, this, [receiver, ...args]);
  };
  try {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      envelope: operation,
      scope: { account_id: crypto.randomBytes(16),
        compartment_id: Buffer.from("vault"), keyring_id: crypto.randomBytes(16) },
      expectedSequence: 0, expectedRoot: crypto.randomBytes(32),
      receipt: Buffer.from([0x01]), physicalAttestation: Buffer.from([0x01]),
      nonce: crypto.randomBytes(32),
      pinnedInventoryPublicKey: witness.publicKey,
      pinnedInventorySignerKeyId: Buffer.alloc(16, 2),
      pinnedPhysicalAttestorPublicKey: crypto.generateKeyPairSync("ed25519").publicKey,
      localTrustedDevicePolicy: policy,
      trustedCurrentDevicePolicyProvider: () => policy,
      admission: {}, freshFloor: hostileFloor,
      pinnedWitnessPublicKey: witness.publicKey,
      witnessKeyId: Buffer.alloc(16, 3), statusKeyId: Buffer.alloc(16, 4),
      trustedMinimumFloor: {},
    }), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/);
  } finally { Function.prototype.call = trustedCall; }
  assert.equal(equalityBypassAttempts, 0,
    "distinct native signer roles must be checked without dynamic .call");
  assert.equal(foreignTraps, 0,
    "the rejected equal-role witness must never reach an untrusted floor Proxy");
});
