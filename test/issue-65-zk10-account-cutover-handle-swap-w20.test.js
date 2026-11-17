"use strict";

// DEV-OFF cryptographic boundary. Never read an accessor-backed native
// Symbol(kHandle) on a forged KeyObject wrapper.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { key, signatureBytes, verifyOwnerRotationKeys } =
  require("../src/crypto/rootark-zk10-account-cutover-v1");

const domain = Buffer.from("Root.ark/zk10/owner-rotation/v1\0");
const der = (value) => value.export({ format: "der", type: "spki" });
const b64 = (value) => value.toString("base64url");
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");

test("P2 changing native kHandle cannot validate SPKI B with owner A's signature", () => {
  const ownerA = crypto.generateKeyPairSync("ed25519");
  const foreignB = crypto.generateKeyPairSync("ed25519");
  const next = crypto.generateKeyPairSync("ed25519");
  const account = b64(Buffer.alloc(16, 0xa1));
  const claimedB = sha(der(foreignB.publicKey));
  assert.notEqual(claimedB, sha(der(ownerA.publicKey)));
  const rotation = {
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: account,
    generation: 1, from_spki_sha256: claimedB,
    next_public_key: b64(der(next.publicKey)), previous_rotation_digest: null,
  };
  const bytes = signatureBytes(domain, rotation);
  const signed = { ...rotation,
    signature_from: b64(crypto.sign(null, bytes, ownerA.privateKey)),
    signature_next: b64(crypto.sign(null, bytes, next.privateKey)),
  };
  const wrapped = Object.create(Object.getPrototypeOf(ownerA.publicKey));
  const symbols = Object.getOwnPropertySymbols(ownerA.publicKey);
  const handle = symbols.find((symbol) => symbol.description === "kHandle");
  const keyType = symbols.find((symbol) => symbol.description === "kKeyType");
  assert.ok(handle && keyType, "the test requires real Node KeyObject symbols");
  assert.ok(wrapped instanceof crypto.KeyObject);
  assert.strictEqual(Object.getPrototypeOf(wrapped), Object.getPrototypeOf(ownerA.publicKey),
    "the forged key must pass the exact public-key prototype shape gate");
  Object.defineProperty(wrapped, keyType, { value: "public" });
  let foreignSpkiReads = 0, handleReads = 0;
  Object.defineProperty(wrapped, handle, { get() {
    handleReads += 1;
    // Native getter calls may be cached depending on Node version. Choose
    // B for export and A for verify regardless of intervening getter reads.
    if ((new Error().stack || "").includes("PublicKeyObject.export")) {
      foreignSpkiReads += 1;
      return foreignB.publicKey[handle];
    }
    return ownerA.publicKey[handle];
  } });
  assert.throws(() => verifyOwnerRotationKeys([signed], wrapped, account),
    { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" });
  assert.equal(handleReads, 0, "the real-shaped wrapper's accessor must never execute");
  assert.equal(foreignSpkiReads, 0,
    "the accessor must be rejected before the native export runs");
});

test("accessor-backed native KeyObject handles are rejected before switching", () => {
  const owner = crypto.generateKeyPairSync("ed25519");
  const other = crypto.generateKeyPairSync("ed25519");
  const wrapped = Object.create(Object.getPrototypeOf(owner.publicKey));
  const symbols = Object.getOwnPropertySymbols(owner.publicKey);
  const handle = symbols.find((symbol) => symbol.description === "kHandle");
  const keyType = symbols.find((symbol) => symbol.description === "kKeyType");
  assert.ok(handle && keyType);
  assert.ok(wrapped instanceof crypto.KeyObject);
  Object.defineProperty(wrapped, keyType, { value: "public" });
  let active = owner.publicKey[handle];
  let handleReads = 0;
  Object.defineProperty(wrapped, handle, { get: () => { handleReads += 1; return active; } });
  assert.throws(() => key(wrapped, "public"),
    { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" });
  assert.equal(handleReads, 0, "neither native-shaped input may execute a kHandle getter");
  active = other.publicKey[handle];
  assert.throws(() => key(wrapped, "public"),
    { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" });
});

test("P2 owner root cannot be replaced by poisoning Function.prototype.call in kHandle", () => {
  const pinned = crypto.generateKeyPairSync("ed25519");
  const attacker = crypto.generateKeyPairSync("ed25519");
  const next = crypto.generateKeyPairSync("ed25519");
  const account = b64(Buffer.alloc(16, 0xc7));
  const claim = {
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: account,
    generation: 1, from_spki_sha256: sha(der(attacker.publicKey)),
    next_public_key: b64(der(next.publicKey)), previous_rotation_digest: null,
  };
  const bytes = signatureBytes(domain, claim);
  const signed = { ...claim,
    signature_from: b64(crypto.sign(null, bytes, attacker.privateKey)),
    signature_next: b64(crypto.sign(null, bytes, next.privateKey)),
  };
  const wrapped = Object.create(Object.getPrototypeOf(pinned.publicKey));
  const symbols = Object.getOwnPropertySymbols(pinned.publicKey);
  const handle = symbols.find((symbol) => symbol.description === "kHandle");
  const keyType = symbols.find((symbol) => symbol.description === "kKeyType");
  assert.ok(handle && keyType);
  assert.ok(wrapped instanceof crypto.KeyObject);
  Object.defineProperty(wrapped, keyType, { value: "public" });
  const nativeExport = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(pinned.publicKey), "export").value;
  const nativeCall = Function.prototype.call;
  let getterReads = 0;
  let substitutedExports = 0;
  Object.defineProperty(wrapped, handle, { get() {
    getterReads += 1;
    Function.prototype.call = function (receiver, ...args) {
      if (this === nativeExport && receiver === wrapped) {
        substitutedExports += 1;
        return der(attacker.publicKey);
      }
      return Reflect.apply(nativeCall, this, [receiver, ...args]);
    };
    return pinned.publicKey[handle];
  } });
  try {
    assert.throws(() => verifyOwnerRotationKeys([signed], wrapped, account),
      { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" });
  } finally {
    Function.prototype.call = nativeCall;
  }
  assert.equal(getterReads, 0, "accessor must not execute during native key checks");
  assert.equal(substitutedExports, 0, "attacker SPKI must never replace pinned root");
});

test("P2 forged DATA kHandle with JavaScript export cannot impersonate a signed root", () => {
  const owner = crypto.generateKeyPairSync("ed25519");
  const attacker = crypto.generateKeyPairSync("ed25519");
  const next = crypto.generateKeyPairSync("ed25519");
  const account = b64(Buffer.alloc(16, 0xd1));
  const claimed = {
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: account,
    generation: 1, from_spki_sha256: sha(der(attacker.publicKey)),
    next_public_key: b64(der(next.publicKey)), previous_rotation_digest: null,
  };
  const bytes = signatureBytes(domain, claimed);
  const signed = { ...claimed,
    signature_from: b64(crypto.sign(null, bytes, attacker.privateKey)),
    signature_next: b64(crypto.sign(null, bytes, next.privateKey)),
  };
  const wrapped = Object.create(Object.getPrototypeOf(owner.publicKey));
  const symbols = Object.getOwnPropertySymbols(owner.publicKey);
  const handle = symbols.find((symbol) => symbol.description === "kHandle");
  const keyType = symbols.find((symbol) => symbol.description === "kKeyType");
  assert.ok(handle && keyType);
  assert.ok(wrapped instanceof crypto.KeyObject);
  let fakeCalls = 0;
  Object.defineProperties(wrapped, {
    [handle]: { value: {
      getAsymmetricKeyType() { fakeCalls += 1; return "ed25519"; },
      export() { fakeCalls += 1; return der(attacker.publicKey); },
    } },
    [keyType]: { value: "public" },
  });
  assert.throws(() => verifyOwnerRotationKeys([signed], wrapped, account),
    { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" });
  assert.equal(fakeCalls, 0,
    "reject fake handle before calling its forged algorithm/export methods");
});

test("P2 native-shaped DATA handle without internal brand is denied before public-key export", () => {
  const owner = crypto.generateKeyPairSync("ed25519");
  const wrapped = Object.create(Object.getPrototypeOf(owner.publicKey));
  const symbols = Object.getOwnPropertySymbols(owner.publicKey);
  const handle = symbols.find((symbol) => symbol.description === "kHandle");
  const keyType = symbols.find((symbol) => symbol.description === "kKeyType");
  assert.ok(handle && keyType);
  const nativeHandle = owner.publicKey[handle];
  const nativePrototype = Object.getPrototypeOf(nativeHandle);
  const forgedHandle = Object.create(nativePrototype);
  assert.strictEqual(Object.getPrototypeOf(forgedHandle), nativePrototype,
    "a fake handle should survive a prototype-only native check");
  assert.equal(Object.hasOwn(forgedHandle, "export"), false);
  assert.equal(Object.hasOwn(forgedHandle, "getAsymmetricKeyType"), false);
  const nativeType = Object.getOwnPropertyDescriptor(nativePrototype, "getAsymmetricKeyType").value;
  assert.throws(() => Reflect.apply(nativeType, forgedHandle, []),
    "the copied handle prototype lacks Node's unforgeable internal native brand");
  Object.defineProperties(wrapped, {
    [handle]: { value: forgedHandle },
    [keyType]: { value: "public" },
  });
  assert.throws(() => key(wrapped, "public"),
    { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" });
});

test("P2 accessor kKeyType cannot run before native Ed25519 root pinning", () => {
  const owner = crypto.generateKeyPairSync("ed25519");
  const attacker = crypto.generateKeyPairSync("ed25519");
  const next = crypto.generateKeyPairSync("ed25519");
  const account = b64(Buffer.alloc(16, 0xd2));
  const claim = {
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: account,
    generation: 1, from_spki_sha256: sha(der(attacker.publicKey)),
    next_public_key: b64(der(next.publicKey)), previous_rotation_digest: null,
  };
  const bytes = signatureBytes(domain, claim);
  const signed = { ...claim,
    signature_from: b64(crypto.sign(null, bytes, attacker.privateKey)),
    signature_next: b64(crypto.sign(null, bytes, next.privateKey)),
  };
  const wrapped = Object.create(Object.getPrototypeOf(owner.publicKey));
  const symbols = Object.getOwnPropertySymbols(owner.publicKey);
  const handle = symbols.find((symbol) => symbol.description === "kHandle");
  const keyType = symbols.find((symbol) => symbol.description === "kKeyType");
  assert.ok(handle && keyType);
  Object.defineProperty(wrapped, handle, { value: owner.publicKey[handle] });
  const nativeCall = Function.prototype.call;
  const nativeExport = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(owner.publicKey), "export").value;
  let accessorReads = 0;
  Object.defineProperty(wrapped, keyType, { get() {
    accessorReads += 1;
    Function.prototype.call = function (receiver, ...args) {
      if (this === nativeExport && receiver === wrapped) return der(attacker.publicKey);
      return Reflect.apply(nativeCall, this, [receiver, ...args]);
    };
    return "public";
  } });
  try {
    assert.throws(() => verifyOwnerRotationKeys([signed], wrapped, account),
      { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" });
  } finally { Function.prototype.call = nativeCall; }
  assert.equal(accessorReads, 0,
    "kKeyType getter must never mutate same-realm intrinsics during key validation");
});

test("legitimate direct native Ed25519 public/private keys keep signed rotations usable", () => {
  const owner = crypto.generateKeyPairSync("ed25519");
  const next = crypto.generateKeyPairSync("ed25519");
  const account = b64(Buffer.alloc(16, 0xd3));
  const claim = {
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: account,
    generation: 1, from_spki_sha256: sha(der(owner.publicKey)),
    next_public_key: b64(der(next.publicKey)), previous_rotation_digest: null,
  };
  const bytes = signatureBytes(domain, claim);
  const signed = { ...claim,
    signature_from: b64(crypto.sign(null, bytes, owner.privateKey)),
    signature_next: b64(crypto.sign(null, bytes, next.privateKey)),
  };
  assert.strictEqual(key(owner.privateKey, "private"), owner.privateKey);
  const nativePublic = key(owner.publicKey, "public");
  assert.notStrictEqual(nativePublic, owner.publicKey);
  assert.equal(crypto.verify(null, bytes, nativePublic,
    crypto.sign(null, bytes, owner.privateKey)), true);
  const accepted = verifyOwnerRotationKeys([signed], owner.publicKey, account);
  assert.equal(accepted.length, 2);
  assert.equal(crypto.verify(null, bytes, accepted[1],
    crypto.sign(null, bytes, next.privateKey)), true);
});
