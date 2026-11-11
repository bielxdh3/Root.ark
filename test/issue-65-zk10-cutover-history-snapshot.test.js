"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  signOwnerCutover, digestOwnerCutover, verifyOwnerCutoverHistory,
} = require("../src/crypto/rootark-zk10-account-cutover-v1");

const id = (value) => Buffer.alloc(16, value).toString("base64url");
const hex = (value) => Buffer.alloc(32, value).toString("hex");

function signedCutover(privateKey, account, inventoryHead) {
  return signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: account,
    zk_account_id: id(2),
    generation: 1,
    previous_cutover_digest: null,
    inventory_head: inventoryHead,
    complete_corpus: true,
    covered_compartments: [id(3)],
    legacy_egress_scope: "all",
    reference_disposition: "fully_accounted",
    migration_disposition: "closed",
    grant: "protected_enforced",
    grants: [],
    suite: "zk1-v2",
    nonce: Buffer.alloc(32, 7).toString("base64url"),
    issued_at: 1800000000,
  }, privateKey);
}

test("P2: cutover history cannot verify one owner record and report another record's digest", () => {
  const owner = crypto.generateKeyPairSync("ed25519");
  const account = id(1);
  const signedA = signedCutover(owner.privateKey, account, hex(11));
  const signedB = signedCutover(owner.privateKey, account, hex(22));
  assert.notEqual(digestOwnerCutover(signedA), digestOwnerCutover(signedB));

  const good = verifyOwnerCutoverHistory([signedA], [owner.publicKey], account);
  assert.equal(good.statement.inventory_head, signedA.inventory_head);
  assert.equal(good.digest, digestOwnerCutover(signedA));

  let reads = 0;
  const switched = [signedA];
  Object.defineProperty(switched, "0", {
    enumerable: true, configurable: true,
    get() { return ++reads === 1 ? signedA : signedB; },
  });
  assert.throws(() => verifyOwnerCutoverHistory(switched, [owner.publicKey], account),
    { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" });
  assert.ok(reads <= 1, "an untrusted index must not be consulted twice");

  let proxyReads = 0;
  const switchedProxy = new Proxy([signedA], {
    get(target, property, receiver) {
      if (property === "0") return ++proxyReads === 1 ? signedA : signedB;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.throws(() => verifyOwnerCutoverHistory(switchedProxy, [owner.publicKey], account),
    { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" });
});
