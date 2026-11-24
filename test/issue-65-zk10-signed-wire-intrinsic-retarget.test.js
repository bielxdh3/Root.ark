"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  OWNER_FIELDS, signOwnerCutover, digestOwnerCutover, verifyOwnerCutoverHistory,
} = require("../src/crypto/rootark-zk10-account-cutover-v1");

const account = Buffer.alloc(16, 41).toString("base64url");
const id = (x) => Buffer.alloc(16, x).toString("base64url");
const hex = (x) => Buffer.alloc(32, x).toString("hex");

function fixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const validA = signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: account, zk_account_id: id(42),
    generation: 1, previous_cutover_digest: null,
    inventory_head: hex(11), complete_corpus: true,
    covered_compartments: [id(43)], legacy_egress_scope: "all",
    reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced",
    grants: [], suite: "zk1-v2", nonce: Buffer.alloc(32, 44).toString("base64url"),
    issued_at: 1800000000,
  }, owner.privateKey);
  const digestA = digestOwnerCutover(validA);
  const forgedB = { ...validA, inventory_head: hex(22) };
  assert.notEqual(forgedB.inventory_head, validA.inventory_head);
  assert.equal(verifyOwnerCutoverHistory([validA], [owner.publicKey], account).digest, digestA);
  assert.throws(() => verifyOwnerCutoverHistory([forgedB], [owner.publicKey], account),
    /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
  const signedBodyA = Object.fromEntries(OWNER_FIELDS.map((field) => [field, validA[field]]));
  const canonicalA = JSON.stringify(signedBodyA);
  return { owner, validA, forgedB, digestA, canonicalA };
}

function getterBoundPublicKey(owner, poison) {
  const handle = Object.getOwnPropertySymbols(owner.publicKey)
    .find((s) => s.description === "kHandle");
  assert.ok(handle, "Node22 native KeyObject must expose Symbol(kHandle)");
  const inherited = Object.create(owner.publicKey);
  let getterCalls = 0;
  Object.defineProperty(inherited, handle, { get() {
    getterCalls++;
    poison();
    return owner.publicKey[handle];
  } });
  return { inherited, reads: () => getterCalls };
}

test("P2: captured signed owner A cannot become unsigned inventory B via Array.prototype.join retarget", () => {
  const f = fixture();
  const originalJoin = Array.prototype.join;
  let forgedJoins = 0;
  const poison = () => {
    Array.prototype.join = function(joiner) {
      if (joiner === "," && this.length === OWNER_FIELDS.length
        && typeof this[0] === "string" && this[0].startsWith('"type":')) {
        forgedJoins++;
        return f.canonicalA.slice(1, -1);
      }
      return originalJoin.call(this, joiner);
    };
  };
  const root = getterBoundPublicKey(f.owner, poison);
  try {
    assert.throws(() => verifyOwnerCutoverHistory([f.forgedB], [root.inherited], account),
      { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" },
      "an inherited native handle must fail closed before its getter");
    assert.equal(root.reads(), 0, "untrusted native handle getter must never execute");
    poison();
    assert.throws(() => verifyOwnerCutoverHistory([f.forgedB], [f.owner.publicKey], account),
      { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" },
      "even a genuine key cannot accept B with A's signature under a hostile Array.join");
    assert.equal(verifyOwnerCutoverHistory([f.validA], [f.owner.publicKey], account).digest,
      f.digestA, "the legitimate owner A must remain accepted under a rebound join");
  } finally {
    Array.prototype.join = originalJoin;
  }
  assert.equal(forgedJoins, 0,
    "serialized signed data must never dispatch to attacker-rebound Array.join");
  assert.equal(verifyOwnerCutoverHistory([f.validA], [f.owner.publicKey], account).digest, f.digestA);
});

test("P2: captured signed owner A cannot become unsigned inventory B via Buffer.from(UTF8) retarget", () => {
  const f = fixture();
  const originalFrom = Buffer.from;
  let forgedConversions = 0;
  const poison = () => {
    Buffer.from = function(input, encoding, ...rest) {
      if (typeof input === "string" && encoding === "utf8"
        && input.includes('"inventory_head":"' + f.forgedB.inventory_head + '"')) {
        forgedConversions++;
        return originalFrom.call(Buffer, f.canonicalA, "utf8");
      }
      return originalFrom.call(Buffer, input, encoding, ...rest);
    };
  };
  const root = getterBoundPublicKey(f.owner, poison);
  try {
    assert.throws(() => verifyOwnerCutoverHistory([f.forgedB], [root.inherited], account),
      { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" },
      "an inherited native handle must fail closed before its getter");
    assert.equal(root.reads(), 0, "untrusted native handle getter must never execute");
    poison();
    assert.throws(() => verifyOwnerCutoverHistory([f.forgedB], [f.owner.publicKey], account),
      { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" },
      "a genuine key must refuse unsigned inventory B despite hostile Buffer.from");
    assert.equal(verifyOwnerCutoverHistory([f.validA], [f.owner.publicKey], account).digest,
      f.digestA, "genuine signed A remains accepted under a rebound Buffer.from");
  } finally {
    Buffer.from = originalFrom;
  }
  assert.equal(forgedConversions, 0,
    "signed message bytes must use a pre-captured native Buffer.from");
  assert.equal(verifyOwnerCutoverHistory([f.validA], [f.owner.publicKey], account).digest, f.digestA);
});
