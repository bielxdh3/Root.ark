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
  assert.equal(decodedCopies, 0,
    "signed CBOR decoding must use the captured native decoder, not a late module-export replacement");
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
  assert.equal(validDecodes, 0,
    "the native snapshot must not dispatch through a callback-replaced decoder export");
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
    await assert.rejects(inventory.verifySnapshot(input(poisoned, memberB)),
      { code: "INVENTORY_SIGNER_KEY" },
      "inherited native handle accessors must be rejected before membership verification");
  } finally {
    Array.prototype[Symbol.iterator] = originalIterator;
  }
  assert.equal(keyGetterReads, 0, "invalid inherited native handle getter must not execute");
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
    await assert.rejects(inventory.verifySnapshot(args(poisonedPin, requestedB)),
      { code: "INVENTORY_SIGNER_KEY" },
      "own inherited native handle accessor must be rejected before comparison");
  } finally { Buffer.compare = originalCompare; }
  assert.equal(getterReads, 0, "invalid inherited native handle getter must not execute");
  assert.equal(substitutions, 0, "lookup must retain early native buffer comparator");
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, requestedA))).outcome,
    "PRESENT", "valid real Ed25519 owner remains accepted after the attack");
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
    // The verifier now captures the native decoder before this callback.
    // Install the numeric setter directly at the getter boundary so it is
    // still a REAL hostile post-key mutation, not a dead decoder hook.
    installNumericTrap();
    z.decodeDeterministic = async (...arguments_) => {
      decodedCopies++;
      return nativeDecode(...arguments_);
    };
    return "public";
  } });
  try {
    // The trap is now installed BEFORE the detached canonical decode instead
    // of through a poisoned codec export. If it affects CBOR reconstruction,
    // strict canonical-byte rejection is an acceptable *specific* fail-closed
    // outcome; accepting unsigned B as PRESENT never is.
    await assert.rejects(inventory.verifySnapshot(args(attackerPin, requestedB)),
      { code: "INVENTORY_ENCODING" },
      "hostile pre-decode numeric setters must fail closed at canonical bytes");
  } finally {
    z.decodeDeterministic = nativeDecode;
    if (priorZero) Object.defineProperty(Array.prototype, "0", priorZero);
    else delete Array.prototype[0];
  }
  assert.ok(keyGetterReads > 0, "hostile native KeyObject property callback was reached");
  assert.equal(decodedCopies, 0,
    "native signed A must be decoded without dispatching to a poisoned codec export");
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
    // Install the constructor trap immediately after the genuine native key
    // callback. The old decoder-export hook is no longer an execution point.
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
    z.decodeDeterministic = async (...arguments_) => {
      validDecodes++;
      return originalDecode(...arguments_);
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
  assert.equal(validDecodes, 0,
    "valid signed snapshot must not dispatch through the hostile decoder export");
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

  const poisoned = Object.create(signer.publicKey);
  const originalIterator = Array.prototype[Symbol.iterator];
  let keyGetterReads = 0;
  let substituted = 0;
  Object.defineProperty(poisoned, "type", { get() {
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
    // This is the `type` getter, not the kHandle getter. Returning a native
    // handle here makes the verifier reject INVENTORY_SIGNER_KEY *before*
    // reaching the signed membership attack under test.
    return "public";
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
  // An accessor replacing kHandle itself must be rejected during native key
  // custody (before inventory comparison). Install the late comparator attack
  // at the genuine public-key `type` callback instead, while the native
  // Ed25519 handle remains valid so membership verification is actually run.
  Object.defineProperty(poisonedPin, "type", { get() {
    getterReads += 1;
    Buffer.compare = function(left, right) {
      if (Buffer.isBuffer(left) && Buffer.isBuffer(right)
        && left.equals(requestedA.object_id) && right.equals(requestedB.object_id)) {
        substitutions += 1;
        return 0;
      }
      return Reflect.apply(originalCompare, Buffer, [left, right]);
    };
    return "public";
  } });
  try {
    assert.equal((await inventory.verifySnapshot(args(poisonedPin, requestedB))).outcome,
      "ABSENT", "valid signature for A must not authorize unlisted object B");
  } finally { Buffer.compare = originalCompare; }
  assert.ok(getterReads > 0, "product verification must reach the hostile native-key type getter");
  assert.equal(substitutions, 0, "lookup must retain early native buffer comparator");
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, requestedA))).outcome,
    "PRESENT", "valid real Ed25519 owner remains accepted after the attack");
});

test("native Ed25519 handle lookup does not dispatch through a mutable Symbol.description getter", () => {
  const { nativeEd25519Spki } = require("../src/crypto/rootark-zk1-native-ed25519-public-key");
  const key = crypto.generateKeyPairSync("ed25519").publicKey;
  const originalDescription = Object.getOwnPropertyDescriptor(Symbol.prototype, "description");
  let descriptionReads = 0;
  try {
    Object.defineProperty(key, "type", { configurable: true, get() {
      Object.defineProperty(Symbol.prototype, "description", { configurable: true,
        get() { descriptionReads++; throw new Error("SYMBOL_DESCRIPTION_TRAP"); } });
      return "public";
    } });
    const spki = nativeEd25519Spki(key);
    assert.equal(spki.length, 44);
    assert.equal(descriptionReads, 0,
      "the captured native kHandle symbol must be compared by identity after caller getters");
  } finally {
    if (originalDescription) Object.defineProperty(Symbol.prototype, "description", originalDescription);
    else delete Symbol.prototype.description;
  }
});

test("P2 inventory: poisoned CBOR Object.keys cannot restore unsigned nonce B after encoding signed nonce A", async () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = Buffer.alloc(16, 131);
  const scope = { account_id: Buffer.alloc(16, 132),
    compartment_id: Buffer.from("nonce-cbor"), keyring_id: Buffer.alloc(16, 133) };
  const originalNonceA = Buffer.alloc(32, 134);
  const forgedNonceB = Buffer.from(originalNonceA);
  forgedNonceB[0] ^= 1;
  const root = await inventory.computeRoot(scope, 0, null, []);
  const genuineSignedA = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: signer.privateKey, scope,
    sequence: 0, previousRoot: null, entries: [], nonce: originalNonceA,
  });
  const z = require("../src/crypto/rootark-zk-1");
  const genuine = await z.decodeDeterministic(genuineSignedA);
  assert.deepEqual(await z.encodeDeterministic(genuine), genuineSignedA,
    "the genuine owner-signed CBOR A bytes must remain canonical and unchanged");
  const forgedB = Buffer.from(await z.encodeDeterministic({
    ...genuine, nonce: forgedNonceB,
  }));
  assert.notDeepEqual(forgedB, genuineSignedA);
  const requested = { object_id: Buffer.alloc(16, 135), revision: 1,
    epoch: 1, ciphertext_sha256: Buffer.alloc(32, 136) };
  const verify = (key, serialized = forgedB, nonce = forgedNonceB) =>
    inventory.verifySnapshot({ serialized, pinnedPublicKey: key,
      pinnedSignerKeyId: signerKeyId, expectedScope: scope,
      requested, minimumHead: { sequence: 0, root }, nonce });
  assert.equal((await verify(signer.publicKey, genuineSignedA, originalNonceA)).outcome, "ABSENT");
  await assert.rejects(verify(signer.publicKey), { code: "INVENTORY_SIGNATURE" });

  const originalKeys = Object.keys;
  let getterReads = 0, substitutions = 0, restorations = 0;
  const maliciousKey = crypto.createPublicKey({
    key: signer.publicKey.export({ type: "spki", format: "der" }),
    type: "spki", format: "der",
  });
  Object.defineProperty(maliciousKey, "type", { configurable: true, get() {
    getterReads++;
    Object.keys = function (value) {
      if (value && value.type === inventory.SNAPSHOT_TYPE
        && value.nonce?.length === 32 && !Object.hasOwn(value, "signature")
        && value.nonce[0] === forgedNonceB[0]) {
        substitutions++;
        value.nonce[0] = originalNonceA[0];
        queueMicrotask(() => { value.nonce[0] = forgedNonceB[0]; restorations++; });
      }
      return originalKeys(value);
    };
    return "public";
  } });
  let authenticated;
  try {
    try { authenticated = await verify(maliciousKey); }
    catch (error) { assert.ok(["INVENTORY_SIGNATURE", "INVENTORY_ENCODING"].includes(error.code)); }
    assert.equal((await verify(maliciousKey, genuineSignedA, originalNonceA)).outcome,
      "ABSENT", "genuine Ed25519 nonce A must verify with the hostile callback installed");
  } finally { Object.keys = originalKeys; delete maliciousKey.type; }
  assert.ok(getterReads > 0, "native Ed25519 KeyObject getter actually ran");
  assert.ok(substitutions > 0, "attacker mutated the unsigned nonce during CBOR encoding");
  assert.equal(restorations, substitutions, "the unsigned B nonce was restored");
  assert.equal(authenticated, undefined, "signed nonce A cannot authenticate unsigned nonce B");
  assert.equal((await verify(signer.publicKey, genuineSignedA, originalNonceA)).outcome, "ABSENT");
});

test("P2 inventory: Set.prototype.has cannot turn signed nonce A into unsigned nonce B", async () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = Buffer.alloc(16, 141);
  const scope = { account_id: Buffer.alloc(16, 142),
    compartment_id: Buffer.from("set-cbor"), keyring_id: Buffer.alloc(16, 143) };
  const signedNonceA = Buffer.alloc(32, 144);
  const unsignedNonceB = Buffer.from(signedNonceA);
  unsignedNonceB[0] ^= 1;
  const root = await inventory.computeRoot(scope, 0, null, []);
  const signedA = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: signer.privateKey, scope, sequence: 0,
    previousRoot: null, entries: [], nonce: signedNonceA,
  });
  const z = require("../src/crypto/rootark-zk-1");
  const decoded = await z.decodeDeterministic(signedA);
  const forgedB = Buffer.from(await z.encodeDeterministic({ ...decoded, nonce: unsignedNonceB }));
  assert.notDeepEqual(forgedB, signedA);
  const requested = { object_id: Buffer.alloc(16, 145), revision: 1,
    epoch: 1, ciphertext_sha256: Buffer.alloc(32, 146) };
  const verify = (pin, serialized = forgedB, nonce = unsignedNonceB) =>
    inventory.verifySnapshot({ serialized, pinnedPublicKey: pin,
      pinnedSignerKeyId: signerKeyId, expectedScope: scope,
      requested, minimumHead: { sequence: 0, root }, nonce });
  assert.equal((await verify(signer.publicKey, signedA, signedNonceA)).outcome, "ABSENT");
  await assert.rejects(verify(signer.publicKey), { code: "INVENTORY_SIGNATURE" });

  const nativeSetHas = Set.prototype.has;
  const maliciousPin = crypto.createPublicKey({
    key: signer.publicKey.export({ type: "spki", format: "der" }),
    type: "spki", format: "der",
  });
  let getterReads = 0, replacements = 0, restorations = 0;
  Object.defineProperty(maliciousPin, "type", { configurable: true, get() {
    getterReads++;
    Set.prototype.has = function (value) {
      if (value && value.type === inventory.SNAPSHOT_TYPE
        && value.nonce?.length === 32 && !Object.hasOwn(value, "signature")
        && value.nonce[0] === unsignedNonceB[0]) {
        replacements++;
        value.nonce[0] = signedNonceA[0];
        queueMicrotask(() => { value.nonce[0] = unsignedNonceB[0]; restorations++; });
      }
      return Reflect.apply(nativeSetHas, this, [value]);
    };
    return "public";
  } });
  let accepted, rejected, replacementsDuringVerification = -1;
  try {
    try { accepted = await verify(maliciousPin); }
    catch (error) { rejected = error; }
    replacementsDuringVerification = replacements;
    assert.equal((await verify(maliciousPin, signedA, signedNonceA)).outcome,
      "ABSENT", "genuine Ed25519 owner A remains accepted under hostile callback");
    const canaryNonce = Buffer.from(unsignedNonceB);
    const probe = { type: inventory.SNAPSHOT_TYPE, nonce: canaryNonce };
    assert.equal(new Set().has(probe), false);
    await Promise.resolve();
    assert.equal(probe.nonce[0], unsignedNonceB[0], "the probe restores unsigned nonce B");
  } finally {
    Set.prototype.has = nativeSetHas;
    delete maliciousPin.type;
  }
  assert.equal(accepted, undefined, "signed nonce A must not authenticate forged nonce B");
  assert.ok(["INVENTORY_SIGNATURE", "INVENTORY_ENCODING"].includes(rejected?.code));
  assert.ok(getterReads > 0, "native KeyObject.type callback executes");
  assert.equal(replacementsDuringVerification, 0,
    "the inventory codec must use its pinned Set.has before private CBOR copies");
  assert.equal(replacements, 1, "independent positive canary demonstrates live hostile Set.has");
  assert.equal(restorations, replacements, "nonce B is restored after each transient replacement");
  assert.equal((await verify(signer.publicKey, signedA, signedNonceA)).outcome, "ABSENT");
});

test("P2 inventory: shadowed native handle export cannot pin A when B is configured", async () => {
  const signerA = crypto.generateKeyPairSync("ed25519");
  const signerB = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = Buffer.alloc(16, 251);
  const scope = {
    account_id: Buffer.alloc(16, 252),
    compartment_id: Buffer.from("protected"),
    keyring_id: Buffer.alloc(16, 253),
  };
  const entry = {
    object_id: Buffer.alloc(16, 254),
    revision: 1,
    epoch: 1,
    ciphertext_sha256: Buffer.alloc(32, 255),
  };
  const nonce = Buffer.alloc(32, 250);
  const previousRoot = Buffer.alloc(32, 249);
  const root = await inventory.computeRoot(scope, 1, previousRoot, [entry]);
  const snapshotA = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: signerA.privateKey, scope, sequence: 1,
    previousRoot, entries: [entry], nonce,
  });
  const snapshotB = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: signerB.privateKey, scope, sequence: 1,
    previousRoot, entries: [entry], nonce,
  });
  const verify = (serialized, pinnedPublicKey) => inventory.verifySnapshot({
    serialized,
    pinnedPublicKey,
    pinnedSignerKeyId: signerKeyId,
    expectedScope: scope,
    requested: entry,
    minimumHead: { sequence: 1, root },
    nonce,
  });

  assert.equal((await verify(snapshotA, signerA.publicKey)).outcome, "PRESENT",
    "genuine signer A remains valid");
  assert.equal((await verify(snapshotB, signerB.publicKey)).outcome, "PRESENT",
    "genuine signer B remains valid");
  let proxyKeyTraps = 0;
  const proxyKey = new Proxy(signerB.publicKey, {
    get(target, property, receiver) {
      proxyKeyTraps++;
      return Reflect.get(target, property, receiver);
    },
    getPrototypeOf(target) {
      proxyKeyTraps++;
      return Reflect.getPrototypeOf(target);
    },
  });
  await assert.rejects(verify(snapshotA, proxyKey),
    { code: "INVENTORY_SIGNER_KEY" }, "native KeyObject proxies are not trusted key pins");
  assert.equal(proxyKeyTraps, 0, "native Proxy rejection must precede every KeyObject trap");

  const handleSymbol = Object.getOwnPropertySymbols(signerB.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handleSymbol, "Node native KeyObject handle symbol must exist");
  const handleDescriptor = Object.getOwnPropertyDescriptor(signerB.publicKey, handleSymbol);
  assert.ok(handleDescriptor && Object.hasOwn(handleDescriptor, "value"),
    "genuine public KeyObject must own a data handle");
  const handle = handleDescriptor.value;
  assert.equal(Object.getOwnPropertyDescriptor(handle, "export"), undefined,
    "fresh native handle must not start with an own export override");

  // The hostile handle exporter lies that configured key B is actually A.
  // Only public SPKI bytes are used; no private material is exported or logged.
  const spkiA = Buffer.from(signerA.publicKey.export({ type: "spki", format: "der" }));
  let shadowedExportCalls = 0;
  Object.defineProperty(handle, "export", {
    configurable: true,
    enumerable: false,
    writable: true,
    value() {
      shadowedExportCalls++;
      return Buffer.from(spkiA);
    },
  });

  let accepted;
  let rejected;
  try {
    try {
      accepted = await verify(snapshotA, signerB.publicKey);
    } catch (error) {
      rejected = error;
    }
  } finally {
    delete handle.export;
  }

  assert.equal(accepted, undefined,
    "snapshot A must not verify with configured B through a shadowed native exporter; observed outcome=" + (accepted?.outcome ?? "rejected"));
  assert.equal(rejected?.code, "INVENTORY_SIGNER_KEY",
    "a shadowed native-handle exporter must be rejected before signature verification");
  assert.equal(shadowedExportCalls, 0,
    "validation must reject the altered handle before invoking its own export method");
  const originalHandlePrototype = Object.getPrototypeOf(handle);
  const substitutedHandlePrototype = Object.create(originalHandlePrototype);
  let inheritedShadowCalls = 0;
  Object.defineProperty(substitutedHandlePrototype, "export", {
    configurable: true,
    value() { inheritedShadowCalls++; return Buffer.from(spkiA); },
  });
  Object.setPrototypeOf(handle, substitutedHandlePrototype);
  try {
    await assert.rejects(verify(snapshotA, signerB.publicKey),
      { code: "INVENTORY_SIGNER_KEY" },
      "a substituted native handle prototype must not redirect its inherited exporter");
  } finally {
    Object.setPrototypeOf(handle, originalHandlePrototype);
  }
  assert.equal(inheritedShadowCalls, 0,
    "prototype substitution must be rejected before inherited export dispatch");
  let exportOwner = originalHandlePrototype;
  let exportOwnerDescriptor = null;
  while (exportOwner && !exportOwnerDescriptor) {
    exportOwnerDescriptor = Object.getOwnPropertyDescriptor(exportOwner, "export");
    if (!exportOwnerDescriptor) exportOwner = Object.getPrototypeOf(exportOwner);
  }
  assert.ok(exportOwner && exportOwnerDescriptor
    && Object.hasOwn(exportOwnerDescriptor, "value"),
  "the captured native handle exporter must have a data-property owner");
  assert.ok(exportOwnerDescriptor.configurable || exportOwnerDescriptor.writable,
    "the Node native exporter can be adversarially replaced in this runtime");
  let replacedNativeExportCalls = 0;
  Object.defineProperty(exportOwner, "export", {
    ...exportOwnerDescriptor,
    value() { replacedNativeExportCalls++; return Buffer.from(spkiA); },
  });
  try {
    await assert.rejects(verify(snapshotB, signerB.publicKey),
      { code: "INVENTORY_SIGNER_KEY" },
      "a later replacement of the native handle prototype exporter must be rejected");
  } finally {
    Object.defineProperty(exportOwner, "export", exportOwnerDescriptor);
  }
  assert.equal(replacedNativeExportCalls, 0,
    "the pinned native exporter identity must be checked before dispatch");
  assert.equal((await verify(snapshotA, signerA.publicKey)).outcome, "PRESENT",
    "legitimate A verification remains available after the rejected attack");
  assert.equal((await verify(snapshotB, signerB.publicKey)).outcome, "PRESENT",
    "legitimate B verification remains available after the rejected attack");
});
