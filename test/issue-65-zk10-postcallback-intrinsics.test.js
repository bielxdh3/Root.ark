"use strict";

// The only attacker execution point is a genuine inherited native KeyObject
// kHandle getter, AFTER module load and BEFORE signature, digest and output.
const assert = require("node:assert/strict");
const test = require("node:test");
const crypto = require("node:crypto");
const protocol = require("../sync-client/rootark-sync-protocol");
const { DOMAIN: ATOMIC_DOMAIN, verifyPinnedAtomicOwnerProvision } =
  require("../sync-client/rootark-sync-atomic-owner-provision");
const { OWNER_FIELDS, signOwnerCutover, digestOwnerCutover,
  verifyOwnerCutoverHistory } =
  require("../src/crypto/rootark-zk10-account-cutover-v1");

const id = (v) => Buffer.alloc(16, v).toString("base64url");
const hex = (v) => Buffer.alloc(32, v).toString("hex");
const account = id(57);

function ownerFixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const body = {
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: account, zk_account_id: id(58),
    generation: 1, previous_cutover_digest: null,
    inventory_head: hex(59), complete_corpus: true,
    covered_compartments: [id(60)], legacy_egress_scope: "all",
    reference_disposition: "fully_accounted", migration_disposition: "closed",
    grant: "protected_enforced", grants: [], suite: "zk1-v2",
    nonce: Buffer.alloc(32, 61).toString("base64url"), issued_at: 1800000000,
  };
  const A = signOwnerCutover(body, owner.privateKey);
  const digestA = digestOwnerCutover(A);
  const B = { ...A, inventory_head: hex(72) };
  assert.notEqual(A.inventory_head, B.inventory_head);
  assert.equal(verifyOwnerCutoverHistory([A], [owner.publicKey], account).digest, digestA);
  assert.throws(() => verifyOwnerCutoverHistory([B], [owner.publicKey], account),
    /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
  return { owner, A, B, digestA };
}

function evilNativeKey(publicKey, callback) {
  const handle = Object.getOwnPropertySymbols(publicKey)
    .find((s) => s.description === "kHandle");
  assert.ok(handle, "Node22 native Ed25519 kHandle required");
  const inherited = Object.create(publicKey);
  let reads = 0;
  Object.defineProperty(inherited, handle, { get() {
    reads++;
    callback();
    return publicKey[handle];
  } });
  return { inherited, get reads() { return reads; } };
}

test("P2: late Function.prototype.call rebind cannot authenticate unsigned owner B using valid Ed25519 A", () => {
  const f = ownerFixture();
  const realCall = Function.prototype.call;
  const nativeJoin = Array.prototype.join;
  const signedA = Object.fromEntries(OWNER_FIELDS.map((name) => [name, f.A[name]]));
  const realAJson = JSON.stringify(signedA);
  let forgedJoins = 0;
  const key = evilNativeKey(f.owner.publicKey, () => {
    Function.prototype.call = function(receiver, ...args) {
      if (this === nativeJoin && args[0] === "," && receiver?.length === OWNER_FIELDS.length
        && typeof receiver[0] === "string" && receiver[0].startsWith('"type":')) {
        forgedJoins++;
        return realAJson.slice(1, -1);
      }
      return Reflect.apply(this, receiver, args);
    };
  });
  try {
    assert.throws(() => verifyOwnerCutoverHistory([f.B], [key.inherited], account),
      /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
  } finally { Function.prototype.call = realCall; }
  assert.ok(key.reads > 0, "real native callback must execute");
  assert.equal(forgedJoins, 0, "post-callback .call dispatch must be immutable");
  assert.equal(verifyOwnerCutoverHistory([f.A], [f.owner.publicKey], account).digest, f.digestA);
});

test("P2: late Object.freeze cannot swap verified Ed25519 A statement to B with A digest", () => {
  const f = ownerFixture();
  const realFreeze = Object.freeze;
  let mutated = 0;
  const key = evilNativeKey(f.owner.publicKey, () => {
    Object.freeze = (value) => {
      if (value?.type === f.A.type && !Object.hasOwn(value, "signature")
        && value.inventory_head === f.A.inventory_head) {
        mutated++;
        return { ...value, inventory_head: f.B.inventory_head };
      }
      return realFreeze(value);
    };
  });
  try {
    const result = verifyOwnerCutoverHistory([f.A], [key.inherited], account);
    assert.equal(result.statement.inventory_head, f.A.inventory_head);
    assert.equal(result.digest, f.digestA);
  } finally { Object.freeze = realFreeze; }
  assert.ok(key.reads > 0);
  assert.equal(mutated, 0, "frozen verified statement must bypass mutable Object.freeze");
  assert.equal(verifyOwnerCutoverHistory([f.A], [f.owner.publicKey], account).digest, f.digestA);
});

test("P2: atomic owner certificate A cannot authorize unsigned identity B through lazy canonicalJson rebind", () => {
  const witness = crypto.generateKeyPairSync("ed25519");
  const cas = crypto.generateKeyPairSync("ed25519");
  const issuer = crypto.generateKeyPairSync("ed25519");
  const pub = (key) => key.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const identityA = { accountId: "11111111-1111-4111-8111-111111111111",
    storeId: "22222222-2222-4222-8222-222222222222",
    username: "owner-A", compartmentId: "private" };
  const identityB = { ...identityA, username: "owner-B" };
  const statementA = { type: "atomic-owner-provisioning", version: 1,
    scope: "synthetic", ...identityA, witnessSpki: pub(witness),
    casSpki: pub(cas), sequence: 1 };
  const statementB = { ...statementA, username: identityB.username };
  const signA = crypto.sign(null,
    Buffer.from(ATOMIC_DOMAIN + protocol.canonicalJson(statementA), "utf8"),
    issuer.privateKey).toString("base64url");
  const certificateA = { statement: statementA, signature: signA };
  const certificateB = { statement: statementB, signature: signA };
  const digestA = crypto.createHash("sha256")
    .update(ATOMIC_DOMAIN + protocol.canonicalJson(certificateA), "utf8").digest("hex");
  const verify = (identity, provisioning, witnessKey) => verifyPinnedAtomicOwnerProvision({
    identity, scope: "synthetic", provisioning,
    expectedDigest: digestA, provisionerPublicKey: issuer.publicKey,
    witnessPublicKey: witnessKey, casPublicKey: cas.publicKey,
  });
  assert.equal(verify(identityA, certificateA, witness.publicKey).identity.username, "owner-A");
  assert.throws(() => verify(identityB, certificateB, witness.publicKey),
    { code: "authorization_required" });

  const realCanonical = protocol.canonicalJson;
  let forged = 0;
  const key = evilNativeKey(witness.publicKey, () => {
    protocol.canonicalJson = (value) => {
      if (value?.type === statementB.type && value.username === identityB.username) {
        forged++;
        return realCanonical(statementA);
      }
      if (value?.statement?.username === identityB.username
        && value.signature === signA) {
        forged++;
        return realCanonical(certificateA);
      }
      return realCanonical(value);
    };
  });
  try {
    assert.throws(() => verify(identityB, certificateB, key.inherited),
      { code: "authorization_required" });
  } finally { protocol.canonicalJson = realCanonical; }
  assert.ok(key.reads > 0);
  assert.equal(forged, 0, "atomic statement and digest must use pinned canonical bytes");
  assert.equal(verify(identityA, certificateA, witness.publicKey).identity.username, "owner-A");
});
