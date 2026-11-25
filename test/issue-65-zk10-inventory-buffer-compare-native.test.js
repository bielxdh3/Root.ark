"use strict";

// Real disposable owner/inventory Ed25519 signature with a hostile same-realm
// native KeyObject handle. No persisted or production authority is involved.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");

test("P2 inventory: signed old snapshot A cannot satisfy retained minimum root B mutated by a key getter", async () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = Buffer.alloc(16, 181);
  const scope = { account_id: Buffer.alloc(16, 182),
    compartment_id: Buffer.from("protected"), keyring_id: Buffer.alloc(16, 183) };
  const entry = { object_id: Buffer.alloc(16, 184), revision: 1, epoch: 1,
    ciphertext_sha256: Buffer.alloc(32, 185) };
  const nonce = Buffer.alloc(32, 186);
  const previousRoot = Buffer.alloc(32, 187);
  const rootA = await inventory.computeRoot(scope, 1, previousRoot, [entry]);
  const rootB = Buffer.alloc(32, 188);
  assert.equal(rootA.equals(rootB), false);
  const serialized = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: signer.privateKey, scope, sequence: 1,
    previousRoot, entries: [entry], nonce,
  });
  const minimumHead = { sequence: 1, root: Buffer.from(rootB) };
  const args = (pin, floor) => ({ serialized, pinnedPublicKey: pin,
    pinnedSignerKeyId: signerKeyId, expectedScope: scope, requested: entry,
    minimumHead: floor, nonce });
  await assert.rejects(inventory.verifySnapshot(args(signer.publicKey, minimumHead)),
    { code: "INVENTORY_FLOOR" }, "trusted B floor must deny signed snapshot A");
  const injected = Object.create(signer.publicKey);
  let getterReads = 0;
  Object.defineProperty(injected, "type", { get() {
    getterReads++;
    minimumHead.root = Buffer.from(rootA);
    return "public";
  } });
  await assert.rejects(inventory.verifySnapshot(args(injected, minimumHead)),
    { code: "INVENTORY_FLOOR" },
    "minimum root B must be detached before any public-key property getter");
  assert.ok(getterReads > 0);
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey,
    { sequence: 1, root: rootA }))).outcome, "PRESENT",
  "signed genuine A remains valid when floor really is A");
});

test("P2 inventory: inherited numeric Array setter cannot turn owner-signed entry A into requested B", async () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = Buffer.alloc(16, 231);
  const scope = { account_id: Buffer.alloc(16, 232),
    compartment_id: Buffer.from("protected"), keyring_id: Buffer.alloc(16, 233) };
  const signedA = { object_id: Buffer.alloc(16, 234), revision: 1, epoch: 1,
    ciphertext_sha256: Buffer.alloc(32, 235) };
  const requestedB = { ...signedA, object_id: Buffer.alloc(16, 236) };
  const nonce = Buffer.alloc(32, 237);
  const previousRoot = Buffer.alloc(32, 238);
  const rootA = await inventory.computeRoot(scope, 1, previousRoot, [signedA]);
  const serialized = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: signer.privateKey, scope, sequence: 1,
    previousRoot, entries: [signedA], nonce,
  });
  const args = (pin, requested) => ({ serialized, pinnedPublicKey: pin,
    pinnedSignerKeyId: signerKeyId, expectedScope: scope, requested,
    minimumHead: { sequence: 1, root: rootA }, nonce });
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, signedA))).outcome,
    "PRESENT", "real owner-signed A is present");
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, requestedB))).outcome,
    "ABSENT", "unlisted B is absent");

  const priorZero = Object.getOwnPropertyDescriptor(Array.prototype, "0");
  const z = require("../src/crypto/rootark-zk-1");
  const nativeDecode = z.decodeDeterministic;
  const shadowedArrays = new WeakSet();
  const attackerPin = Object.create(signer.publicKey);
  let keyGetterReads = 0, interceptedAssignments = 0, returnedForgedB = 0, decodedCopies = 0;
  const installNumericTrap = () => {
    Object.defineProperty(Array.prototype, "0", {
      configurable: true,
      get() {
        if (!shadowedArrays.has(this)) return undefined;
        const immediate = (new Error().stack || "").split("\n")[2] || "";
        if (/\bat (?:Object\.)?verifySnapshot \(/.test(immediate)) {
          returnedForgedB++;
          return requestedB;
        }
        return signedA;
      },
      set(value) {
        const stack = new Error().stack || "";
        if (value && value.object_id && value.object_id.equals(signedA.object_id)
          && /\bnormalizeEntries \(/.test(stack)) {
          shadowedArrays.add(this);
          interceptedAssignments++;
          return;
        }
        Object.defineProperty(this, "0", {
          value, enumerable: true, configurable: true, writable: true,
        });
      },
    });
  };
  Object.defineProperty(attackerPin, "type", { get() {
    keyGetterReads++;
    // Keep the original canonical CBOR decode intact. The caller-owned key
    // callback can replace this mutable module export and install the array
    // setter exactly after decoding the genuinely signed A bytes.
    z.decodeDeterministic = async (...arguments_) => {
      const decoded = await nativeDecode(...arguments_);
      decodedCopies++;
      installNumericTrap();
      return decoded;
    };
    return "public";
  } });
  try {
    assert.equal((await inventory.verifySnapshot(args(attackerPin, requestedB))).outcome,
      "ABSENT", "a signed A row cannot become B through an inherited numeric slot");
  } finally {
    z.decodeDeterministic = nativeDecode;
    if (priorZero) Object.defineProperty(Array.prototype, "0", priorZero);
    else delete Array.prototype[0];
  }
  assert.ok(keyGetterReads > 0, "hostile native KeyObject property callback was reached");
  assert.ok(decodedCopies > 0, "real signed CBOR A was decoded before the numeric trap");
  assert.equal(interceptedAssignments, 0,
    "normalization must define its own indexed slots without inherited setters");
  assert.equal(returnedForgedB, 0, "signed membership must not consult prototype entries");
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, signedA))).outcome,
    "PRESENT", "signed A remains valid after the attempted attack");
});

test("P2 inventory: hostile late Array constructor cannot proxy a signed A row into requested B", async () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = Buffer.alloc(16, 241);
  const scope = { account_id: Buffer.alloc(16, 242),
    compartment_id: Buffer.from("protected"), keyring_id: Buffer.alloc(16, 243) };
  const signedA = { object_id: Buffer.alloc(16, 244), revision: 1, epoch: 1,
    ciphertext_sha256: Buffer.alloc(32, 245) };
  const requestedB = { ...signedA, object_id: Buffer.alloc(16, 246) };
  const nonce = Buffer.alloc(32, 247);
  const previousRoot = Buffer.alloc(32, 248);
  const rootA = await inventory.computeRoot(scope, 1, previousRoot, [signedA]);
  const serialized = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: signer.privateKey, scope, sequence: 1,
    previousRoot, entries: [signedA], nonce,
  });
  const args = (pin, requested) => ({ serialized, pinnedPublicKey: pin,
    pinnedSignerKeyId: signerKeyId, expectedScope: scope, requested,
    minimumHead: { sequence: 1, root: rootA }, nonce });
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, signedA))).outcome,
    "PRESENT", "genuine owner Ed25519 A remains present");
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, requestedB))).outcome,
    "ABSENT", "unsigned B cannot be found in a signed A-only snapshot");

  const z = require("../src/crypto/rootark-zk-1");
  const originalDecode = z.decodeDeterministic;
  const originalArray = global.Array;
  const pin = Object.create(signer.publicKey);
  let keyReads = 0, validDecodes = 0, maliciousConstructs = 0, substitutedReads = 0;
  Object.defineProperty(pin, "type", { get() {
    keyReads++;
    z.decodeDeterministic = async (...arguments_) => {
      const decoded = await originalDecode(...arguments_);
      validDecodes++;
      // An untrusted native key getter may rewrite this global AFTER genuine
      // CBOR decoding while normalizeEntries still uses the global Array.
      global.Array = new Proxy(originalArray, {
        construct(target, arguments_) {
          const direct = (new Error().stack || "").split("\n")[2] || "";
          const actual = Reflect.construct(target, arguments_, target);
          if (!/\bnormalizeEntries \(/.test(direct)) return actual;
          maliciousConstructs++;
          return new Proxy(actual, {
            get(array, property, receiver) {
              if (property === "0") {
                const caller = (new Error().stack || "").split("\n")[2] || "";
                if (/\bat (?:Object\.)?verifySnapshot \(/.test(caller)) {
                  substitutedReads++;
                  return requestedB;
                }
              }
              return Reflect.get(array, property, receiver);
            },
          });
        },
      });
      return decoded;
    };
    return "public";
  } });
  try {
    assert.equal((await inventory.verifySnapshot(args(pin, requestedB))).outcome,
      "ABSENT", "a caller-owned constructor cannot replace signed A with unsigned B");
  } finally {
    z.decodeDeterministic = originalDecode;
    global.Array = originalArray;
  }
  assert.ok(keyReads > 0, "hostile native key callback executed");
  assert.ok(validDecodes > 0, "original Ed25519-signed snapshot was actually decoded");
  assert.equal(maliciousConstructs, 0,
    "normalized rows must use an intrinsic Array literal, not the late global constructor");
  assert.equal(substitutedReads, 0, "membership cannot read a hostile Proxy array");
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, signedA))).outcome,
    "PRESENT", "owner-signed A stays accepted after the hostile callback");
});

test("P2 inventory: native key getter cannot replace signed member A with requested B through an Array iterator", async () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = Buffer.alloc(16, 201);
  const scope = { account_id: Buffer.alloc(16, 202),
    compartment_id: Buffer.from("protected"), keyring_id: Buffer.alloc(16, 203) };
  const memberA = { object_id: Buffer.alloc(16, 204), revision: 1, epoch: 1,
    ciphertext_sha256: Buffer.alloc(32, 205) };
  const memberB = { ...memberA, object_id: Buffer.alloc(16, 206) };
  const nonce = Buffer.alloc(32, 207);
  const previousRoot = Buffer.alloc(32, 208);
  const rootA = await inventory.computeRoot(scope, 1, previousRoot, [memberA]);
  const serialized = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: signer.privateKey, scope,
    sequence: 1, previousRoot, entries: [memberA], nonce,
  });
  const input = (pin, requested) => ({ serialized, pinnedPublicKey: pin,
    pinnedSignerKeyId: signerKeyId, expectedScope: scope, requested,
    minimumHead: { sequence: 1, root: rootA }, nonce });
  assert.equal((await inventory.verifySnapshot(input(signer.publicKey, memberA))).outcome,
    "PRESENT", "genuinely signed Ed25519 member A is present");
  assert.equal((await inventory.verifySnapshot(input(signer.publicKey, memberB))).outcome,
    "ABSENT", "unsigned member B is absent");

  const handle = Object.getOwnPropertySymbols(signer.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "native Ed25519 handle must be reachable");
  const poisoned = Object.create(signer.publicKey);
  const originalIterator = Array.prototype[Symbol.iterator];
  let keyGetterReads = 0;
  let substituted = 0;
  Object.defineProperty(poisoned, handle, { get() {
    keyGetterReads++;
    Array.prototype[Symbol.iterator] = function*() {
      // Only the post-signature membership loop can be substituted. CBOR
      // canonicalization and Ed25519 verification keep checking signed A.
      if (this.length === 1 && this[0]?.object_id?.equals?.(memberA.object_id)
        && /\bat (?:Object\.)?verifySnapshot \(/.test(new Error().stack)) {
        substituted++;
        yield memberB;
        return;
      }
      yield* Reflect.apply(originalIterator, this, []);
    };
    return signer.publicKey[handle];
  } });
  try {
    assert.equal((await inventory.verifySnapshot(input(poisoned, memberB))).outcome,
      "ABSENT", "signed member A cannot be presented as unsigned B");
  } finally {
    Array.prototype[Symbol.iterator] = originalIterator;
  }
  assert.ok(keyGetterReads > 0, "real native KeyObject getter executed");
  assert.equal(substituted, 0, "membership search must not use a post-key iterator");
  assert.equal((await inventory.verifySnapshot(input(signer.publicKey, memberA))).outcome,
    "PRESENT", "genuine A remains accepted");
});

test("P2 inventory: native key callback cannot hide an older signed object from monotonic superset comparison", async () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = Buffer.alloc(16, 211);
  const scope = { account_id: Buffer.alloc(16, 212),
    compartment_id: Buffer.from("protected"), keyring_id: Buffer.alloc(16, 213) };
  const oldA = { object_id: Buffer.alloc(16, 214), revision: 1,
    epoch: 1, ciphertext_sha256: Buffer.alloc(32, 215) };
  const newB = { object_id: Buffer.alloc(16, 216), revision: 1,
    epoch: 1, ciphertext_sha256: Buffer.alloc(32, 217) };
  const newC = { object_id: Buffer.alloc(16, 218), revision: 1,
    epoch: 1, ciphertext_sha256: Buffer.alloc(32, 219) };
  const genesisRoot = Buffer.alloc(32, 220);
  const oldRoot = await inventory.computeRoot(scope, 1, genesisRoot, [oldA]);
  const oldSnapshot = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: signer.privateKey, scope,
    sequence: 1, previousRoot: genesisRoot, entries: [oldA], nonce: Buffer.alloc(32, 221),
  });
  const nowNonce = Buffer.alloc(32, 222);
  const unsignedNewRoot = await inventory.computeRoot(scope, 2, oldRoot, [newB, newC]);
  const newSnapshot = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: signer.privateKey, scope,
    sequence: 2, previousRoot: oldRoot, entries: [newB, newC], nonce: nowNonce,
  });
  assert.equal(unsignedNewRoot.length, 32);
  const input = (pin) => ({
    serialized: newSnapshot, pinnedPublicKey: pin, pinnedSignerKeyId: signerKeyId,
    expectedScope: scope, requested: newB,
    minimumHead: { sequence: 1, root: oldRoot }, minimumSnapshot: oldSnapshot,
    nonce: nowNonce,
  });
  await assert.rejects(inventory.verifySnapshot(input(signer.publicKey)),
    { code: "INVENTORY_REMOVED" }, "signed snapshot B/C omits historical signed A");

  const hostile = Object.create(signer.publicKey);
  const oldIterator = Array.prototype[Symbol.iterator];
  let keyGetterReads = 0;
  let omissions = 0;
  Object.defineProperty(hostile, "type", { get() {
    keyGetterReads++;
    Array.prototype[Symbol.iterator] = function*() {
      if (this.length === 1 && this[0]?.object_id?.equals?.(oldA.object_id)
        && /\bat assertSuperset \(/.test(new Error().stack)) {
        omissions++;
        return;
      }
      yield* Reflect.apply(oldIterator, this, []);
    };
    return "public";
  } });
  try {
    await assert.rejects(inventory.verifySnapshot(input(hostile)),
      { code: "INVENTORY_REMOVED" },
      "a native public-key getter cannot hide previously signed historical object A");
  } finally {
    Array.prototype[Symbol.iterator] = oldIterator;
  }
  assert.ok(keyGetterReads > 0);
  assert.equal(omissions, 0, "monotonic history cannot invoke an attacker iterator");
});

test("P2 inventory: signed object A must not make requested B PRESENT via post-key Buffer.compare", async () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = Buffer.alloc(16, 71);
  const scope = { account_id: Buffer.alloc(16, 72),
    compartment_id: Buffer.from("inventory-same-realm"),
    keyring_id: Buffer.alloc(16, 73) };
  const requestedA = { object_id: Buffer.alloc(16, 74),
    revision: 1, epoch: 1, ciphertext_sha256: Buffer.alloc(32, 75) };
  const requestedB = { ...requestedA, object_id: Buffer.alloc(16, 76) };
  const previousRoot = Buffer.alloc(32, 77);
  const nonce = Buffer.alloc(32, 78);
  const signedRoot = await inventory.computeRoot(scope, 1, previousRoot, [requestedA]);
  const serialized = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: signer.privateKey, scope, sequence: 1,
    previousRoot, entries: [requestedA], nonce,
  });
  const args = (pin, requested) => ({
    serialized, pinnedPublicKey: pin, pinnedSignerKeyId: signerKeyId,
    expectedScope: scope, requested, minimumHead: { sequence: 1, root: signedRoot },
    nonce,
  });
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, requestedA))).outcome,
    "PRESENT", "real owner-signed entry A accepted");
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, requestedB))).outcome,
    "ABSENT", "unlisted object B absent with original comparisons");

  const handle = Object.getOwnPropertySymbols(signer.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "Node22 real native Ed25519 key handle");
  const poisonedPin = Object.create(signer.publicKey);
  const originalCompare = Buffer.compare;
  let getterReads = 0;
  let substitutions = 0;
  Object.defineProperty(poisonedPin, handle, { get() {
    getterReads += 1;
    Buffer.compare = function(left, right) {
      if (Buffer.isBuffer(left) && Buffer.isBuffer(right)
        && left.equals(requestedA.object_id) && right.equals(requestedB.object_id)) {
        substitutions += 1;
        return 0;
      }
      return Reflect.apply(originalCompare, Buffer, [left, right]);
    };
    return signer.publicKey[handle];
  } });
  try {
    assert.equal((await inventory.verifySnapshot(args(poisonedPin, requestedB))).outcome,
      "ABSENT", "valid signature for A must not authorize unlisted object B");
  } finally { Buffer.compare = originalCompare; }
  assert.ok(getterReads > 0, "product verification must invoke hostile inherited kHandle");
  assert.equal(substitutions, 0, "lookup must retain early native buffer comparator");
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, requestedA))).outcome,
    "PRESENT", "valid real Ed25519 owner remains accepted after the attack");
});
