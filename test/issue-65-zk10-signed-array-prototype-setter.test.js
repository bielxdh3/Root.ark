"use strict";

// Real native KeyObject callback, genuine Ed25519 A/B signatures, and an
// inherited numeric Array setter targeting the SIXTH owner signed-wire field.
// The attack must never verify signed A bytes as an unsigned B inventory.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { jsonStringify: signedJson } =
  require("../src/crypto/rootark-zk10-native-intrinsics-v1");
const {
  OWNER_FIELDS, signOwnerCutover, digestOwnerCutover,
  verifyOwnerCutoverHistory, signOwnerRotation, verifyOwnerRotationKeys, spkiHash,
} = require("../src/crypto/rootark-zk10-account-cutover-v1");

const id = (n) => Buffer.alloc(16, n).toString("base64url");
const hex = (n) => Buffer.alloc(32, n).toString("hex");
const accountId = id(41);

function signedCutover(owner, inventoryHead, compartments = [id(43)]) {
  return signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: accountId, zk_account_id: id(42),
    generation: 1, previous_cutover_digest: null,
    inventory_head: inventoryHead, complete_corpus: true,
    covered_compartments: compartments, legacy_egress_scope: "all",
    reference_disposition: "fully_accounted", migration_disposition: "closed",
    grant: "protected_enforced", grants: [], suite: "zk1-v2",
    nonce: Buffer.alloc(32, 44).toString("base64url"), issued_at: 1800000000,
  }, owner.privateKey);
}

function fixture() {
  const A = crypto.generateKeyPairSync("ed25519");
  const B = crypto.generateKeyPairSync("ed25519");
  const signedA = signedCutover(A, hex(51));
  const signedB = signedCutover(B, hex(52));
  const digestA = digestOwnerCutover(signedA);
  const digestB = digestOwnerCutover(signedB);
  assert.notEqual(digestA, digestB, "genuinely distinct signed owners A and B");
  assert.equal(verifyOwnerCutoverHistory([signedA], [A.publicKey], accountId).digest, digestA);
  assert.equal(verifyOwnerCutoverHistory([signedB], [B.publicKey], accountId).digest, digestB);
  const forgedB = { ...signedB, signature: signedA.signature };
  assert.throws(() => verifyOwnerCutoverHistory([forgedB], [A.publicKey], accountId),
    { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" });
  return { A, B, signedA, signedB, forgedB, digestA, digestB };
}

function inheritedNativeKey(realPublicKey, callback) {
  const symbol = Object.getOwnPropertySymbols(realPublicKey)
    .find((value) => value.description === "kHandle");
  assert.ok(symbol, "Node 22 genuine native KeyObject Symbol(kHandle) required");
  const inherited = Object.create(realPublicKey);
  assert.ok(inherited instanceof crypto.KeyObject);
  let reads = 0;
  Object.defineProperty(inherited, symbol, { get() {
    reads++;
    callback();
    return realPublicKey[symbol];
  } });
  return { inherited, get reads() { return reads; } };
}

test("P2: malicious Array.prototype[5] setter cannot verify signed A as inventory B with digest A", () => {
  const f = fixture();
  const original = Object.getOwnPropertyDescriptor(Array.prototype, "5");
  const expectedB = `"inventory_head":"${f.signedB.inventory_head}"`;
  const signedAField = `"inventory_head":"${f.signedA.inventory_head}"`;
  assert.equal(OWNER_FIELDS[5], "inventory_head");
  let getterReads = 0;
  let setterIntercepts = 0;
  let probeIntercepts = 0;
  let probe = false;
  let armed = false;
  const key = inheritedNativeKey(f.A.publicKey, () => {
    getterReads++;
    if (armed) return;
    armed = true;
    Object.defineProperty(Array.prototype, "5", {
      configurable: true,
      set(value) {
        const attack = this.length === 5 && value === expectedB;
        if (attack) {
          if (probe) probeIntercepts++;
          else setterIntercepts++;
        }
        // Preserve normal Array.push behavior for other arrays. Define the
        // receiver's own DATA slot, not a recursive assignment to this[5].
        Object.defineProperty(this, "5", {
          value: attack ? signedAField : value,
          enumerable: true, writable: true, configurable: true,
        });
      },
    });
    probe = true;
    const canary = [0, 1, 2, 3, 4];
    canary.push(expectedB);
    assert.equal(canary[5], signedAField, "installed setter must actually forge byte field A");
    probe = false;
  });
  let result;
  let rejection;
  try {
    result = verifyOwnerCutoverHistory([f.forgedB], [key.inherited], accountId);
  } catch (error) { rejection = error; }
  finally {
    if (original) Object.defineProperty(Array.prototype, "5", original);
    else delete Array.prototype[5];
  }
  assert.ok(key.reads > 0 && getterReads > 0, "real kHandle getter must have executed");
  assert.ok(probeIntercepts > 0, "the attacker-installed numeric setter must be physically active");
  if (result) {
    assert.equal(result.statement.inventory_head, f.signedB.inventory_head,
      "proof of wrong B semantics returned after A signature");
    assert.equal(result.digest, f.digestA, "proof of signed A digest reported for B");
  }
  assert.equal(rejection?.code, "ZK10_ACCOUNT_CUTOVER_UNVERIFIED",
    "a valid A signature must never authenticate unsigned B even with inherited numeric setter");
  assert.equal(result, undefined);
  assert.equal(setterIntercepts, 0, "signed-wire scratch arrays must bypass hostile inherited setters");
});

test("P2: inherited Array.prototype[7] setter cannot rewrite a signed owner compartment during normalization", () => {
  const A = crypto.generateKeyPairSync("ed25519");
  const B = crypto.generateKeyPairSync("ed25519");
  const arrayA = Array.from({ length: 8 }, (_, index) => id(index + 1));
  const arrayB = [...arrayA.slice(0, 7), id(9)];
  const signedA = signedCutover(A, hex(55), arrayA);
  const signedB = signedCutover(B, hex(55), arrayB);
  const digestA = digestOwnerCutover(signedA);
  assert.notEqual(digestOwnerCutover(signedB), digestA);
  const forgedB = { ...signedB, signature: signedA.signature };
  assert.throws(() => verifyOwnerCutoverHistory([forgedB], [A.publicKey], accountId),
    { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" });
  const initial = Object.getOwnPropertyDescriptor(Array.prototype, "7");
  let intercepted = 0;
  const rogue = inheritedNativeKey(A.publicKey, () => {
    Object.defineProperty(Array.prototype, "7", { configurable: true, set(value) {
      const intercept = this.length === 7 && value === id(9);
      if (intercept) intercepted++;
      Object.defineProperty(this, "7", { value: intercept ? id(8) : value,
        enumerable: true, writable: true, configurable: true });
    } });
  });
  let accepted;
  let rejected;
  try { accepted = verifyOwnerCutoverHistory([forgedB], [rogue.inherited], accountId); }
  catch (error) { rejected = error; }
  finally {
    if (initial) Object.defineProperty(Array.prototype, "7", initial);
    else delete Array.prototype[7];
  }
  assert.ok(rogue.reads > 0);
  if (accepted) assert.equal(accepted.digest, digestA,
    "real physical RED shows valid A signature accepted for incoming unsigned B wire");
  assert.equal(rejected?.code, "ZK10_ACCOUNT_CUTOVER_UNVERIFIED",
    "no changed unsigned compartment can normalize into valid signed A bytes");
  assert.equal(accepted, undefined);
  assert.equal(intercepted, 0, "normalization must not dispatch inherited numeric setters");
});

test("P2: owner signed wire never invokes a late mutable Array iterator", () => {
  const f = fixture();
  const payload = Object.fromEntries(OWNER_FIELDS.map((name) => [name, f.signedA[name]]));
  const canonical = JSON.stringify(payload);
  assert.equal(signedJson(payload), canonical, "baseline canonical wire must remain JSON compatible");
  const original = Array.prototype[Symbol.iterator];
  let iteratorAttempts = 0;
  const key = inheritedNativeKey(f.A.publicKey, () => {
    Array.prototype[Symbol.iterator] = function () {
      if (this.length === OWNER_FIELDS.length && this[0] === "type") {
        iteratorAttempts++;
        throw new Error("ATTACKED_ARRAY_ITERATOR");
      }
      return Reflect.apply(original, this, []);
    };
  });
  let serialized;
  let error;
  try {
    spkiHash(key.inherited); // Physical native getter mutates the same realm.
    serialized = signedJson(payload);
  } catch (caught) { error = caught; }
  finally { Array.prototype[Symbol.iterator] = original; }
  assert.ok(key.reads > 0);
  assert.equal(error, undefined, "serializing a signed record must not consult poisoned iterators");
  assert.equal(iteratorAttempts, 0);
  assert.equal(serialized, canonical, "canonical wire field ordering must not change");
});

test("positive: genuine signed Ed25519 owner A and A-to-B rotation still verify", () => {
  const f = fixture();
  assert.equal(verifyOwnerCutoverHistory([f.signedA], [f.A.publicKey], accountId).digest,
    f.digestA);
  const rotation = signOwnerRotation({
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: accountId,
    generation: 1, from_spki_sha256: spkiHash(f.A.publicKey),
    next_public_key: f.B.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
    previous_rotation_digest: null,
  }, f.A.privateKey, f.B.privateKey);
  const keys = verifyOwnerRotationKeys([rotation], f.A.publicKey, accountId);
  assert.equal(keys.length, 2);
  assert.equal(crypto.KeyObject.prototype.equals.call(keys[1], f.B.publicKey), true);
});
