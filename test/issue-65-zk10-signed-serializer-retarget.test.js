"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const {
  signOwnerCutover, verifyOwnerCutoverHistory, digestOwnerCutover,
} = require("../src/crypto/rootark-zk10-account-cutover-v1");

const id = (v) => Buffer.alloc(16, v).toString("base64url");
const hex = (v) => Buffer.alloc(32, v).toString("hex");
const account = id(61);

function fixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const body = {
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: account, zk_account_id: id(62),
    generation: 1, previous_cutover_digest: null, inventory_head: hex(63),
    complete_corpus: true, covered_compartments: [id(64)],
    legacy_egress_scope: "all", reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced", grants: [],
    suite: "zk1-v2", nonce: Buffer.alloc(32, 65).toString("base64url"),
    issued_at: 1800000000,
  };
  const signed = signOwnerCutover(body, owner.privateKey);
  const digest = digestOwnerCutover(signed);
  assert.equal(verifyOwnerCutoverHistory([signed], [owner.publicKey], account).digest, digest);
  return { owner, body, signed, digest };
}

function inheritedOwnerWithPrototypePoison(publicKey, target, replacement) {
  const symbol = Object.getOwnPropertySymbols(publicKey)
    .find((candidate) => candidate.description === "kHandle");
  assert.ok(symbol);
  const inherited = Object.create(publicKey);
  const oldToJson = Object.getOwnPropertyDescriptor(target, "toJSON");
  let getterReads = 0;
  let toJsonCalls = 0;
  Object.defineProperty(inherited, symbol, { get() {
    getterReads += 1;
    Object.defineProperty(target, "toJSON", { configurable: true, writable: true,
      value: function attackerJson() {
        toJsonCalls += 1;
        return replacement(this);
      } });
    return publicKey[symbol];
  } });
  return {
    inherited,
    get getterReads() { return getterReads; },
    get toJsonCalls() { return toJsonCalls; },
    restore() {
      if (oldToJson) Object.defineProperty(target, "toJSON", oldToJson);
      else delete target.toJSON;
    },
  };
}

test("P2: inherited Object.prototype.toJSON cannot make signed cutover B verify under owner A's real Ed25519 signature", () => {
  const f = fixture();
  const forgedB = Object.freeze({ ...f.signed, inventory_head: hex(72) });
  assert.notEqual(forgedB.inventory_head, f.signed.inventory_head);
  assert.throws(() => verifyOwnerCutoverHistory([forgedB], [f.owner.publicKey], account),
    /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
  const hostile = inheritedOwnerWithPrototypePoison(f.owner.publicKey,
    Object.prototype, (value) => value.type === f.body.type ? f.body : value);
  try {
    assert.throws(() => verifyOwnerCutoverHistory([forgedB], [hostile.inherited], account),
      /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/,
      "the forged B inventory must not inherit signer A's canonical bytes");
    assert.ok(hostile.getterReads > 0, "real native owner KeyObject getter ran");
    assert.equal(hostile.toJsonCalls, 0,
      "canonical signed payload must never consult a patched prototype hook");
  } finally { hostile.restore(); }
  assert.equal(verifyOwnerCutoverHistory([f.signed], [f.owner.publicKey], account).digest, f.digest);
});

test("P2: Array.prototype.toJSON cannot substitute A's compartment corpus while accepting B", () => {
  const f = fixture();
  const forgedB = Object.freeze({ ...f.signed, covered_compartments: [id(66)] });
  assert.throws(() => verifyOwnerCutoverHistory([forgedB], [f.owner.publicKey], account),
    /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
  const hostile = inheritedOwnerWithPrototypePoison(f.owner.publicKey,
    Array.prototype, () => [...f.body.covered_compartments]);
  try {
    assert.throws(() => verifyOwnerCutoverHistory([forgedB], [hostile.inherited], account),
      /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/,
      "an inherited array serializer must not change the signed corpus");
    assert.ok(hostile.getterReads > 0);
    assert.equal(hostile.toJsonCalls, 0,
      "array fields must be serialized as validated primitives, not via toJSON");
  } finally { hostile.restore(); }
  assert.equal(verifyOwnerCutoverHistory([f.signed], [f.owner.publicKey], account).digest, f.digest);
});
