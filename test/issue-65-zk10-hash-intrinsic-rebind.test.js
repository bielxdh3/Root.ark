"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const {
  signOwnerCutover, digestOwnerCutover, verifyOwnerCutover,
  verifyOwnerCutoverHistory, spkiHash, signOwnerRotation, verifyOwnerRotationKeys,
  OWNER_FIELDS, signatureBytes,
} = require("../src/crypto/rootark-zk10-account-cutover-v1");

const account = Buffer.alloc(16, 41).toString("base64url");
const id = (value) => Buffer.alloc(16, value).toString("base64url");
const hex = (value) => Buffer.alloc(32, value).toString("hex");
const DOMAIN_OWNER = Buffer.from("Root.ark/zk10/owner-account-cutover/v1\0");

function signedOwner(owner, inventory) {
  return signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: account, zk_account_id: id(42), generation: 1,
    previous_cutover_digest: null, inventory_head: hex(inventory),
    complete_corpus: true, covered_compartments: [id(43)],
    legacy_egress_scope: "all", reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced", grants: [],
    suite: "zk1-v2", nonce: Buffer.alloc(32, inventory).toString("base64url"),
    issued_at: 1800000000,
  }, owner.privateKey);
}

function fixture() {
  const A = crypto.generateKeyPairSync("ed25519");
  const B = crypto.generateKeyPairSync("ed25519");
  const signedA = signedOwner(A, 11);
  const signedB = signedOwner(B, 22);
  // A and B are independently signed Ed25519 records, not a fabricated hash.
  assert.equal(verifyOwnerCutover(signedA, A.publicKey).inventory_head, hex(11));
  assert.equal(verifyOwnerCutover(signedB, B.publicKey).inventory_head, hex(22));
  const digestA = digestOwnerCutover(signedA);
  const digestB = digestOwnerCutover(signedB);
  assert.notEqual(digestA, digestB);
  return { A, B, signedA, signedB, digestA, digestB };
}

// A real native KeyObject can be inherited, with a same-realm getter on the
// symbol used by Node's native KeyObject getters and DER exporter. This is not
// a Proxy or an overridden .export() method.
function controlledNativeRoot(publicKey, onRead) {
  const handle = Object.getOwnPropertySymbols(publicKey)
    .find((symbol) => String(symbol) === "Symbol(kHandle)");
  assert.ok(handle, "Node 22 must expose the physical native KeyObject handle");
  const inherited = Object.create(publicKey);
  assert.ok(inherited instanceof crypto.KeyObject);
  let reads = 0;
  Object.defineProperty(inherited, handle, { get() {
    reads++;
    onRead();
    return publicKey[handle];
  } });
  return { inherited, get reads() { return reads; } };
}

function withHashPrototypeRebind(work) {
  const hashProto = Object.getPrototypeOf(crypto.createHash("sha256"));
  const originalUpdate = Object.getOwnPropertyDescriptor(hashProto, "update");
  const originalDigest = Object.getOwnPropertyDescriptor(hashProto, "digest");
  assert.equal(typeof originalUpdate.value, "function");
  assert.equal(typeof originalDigest.value, "function");
  try { return work(hashProto, originalUpdate.value, originalDigest.value); }
  finally {
    Object.defineProperty(hashProto, "update", originalUpdate);
    Object.defineProperty(hashProto, "digest", originalDigest);
  }
}

test("P2 digest: a valid owner A signature cannot report signed owner B's digest through native Hash.prototype rebinding", () => {
  const f = fixture();
  let forgedDigests = 0;
  let armed = false;
  withHashPrototypeRebind((hashProto, nativeUpdate, nativeDigest) => {
    const root = controlledNativeRoot(f.A.publicKey, () => {
      if (armed) return;
      armed = true;
      Object.defineProperty(hashProto, "digest", { ...Object.getOwnPropertyDescriptor(hashProto, "digest"),
        value: function digestReplacement(encoding) {
          const result = nativeDigest.call(this, encoding);
          if (Buffer.isBuffer(result) && result.toString("hex") === f.digestA) {
            forgedDigests++;
            return Buffer.from(f.digestB, "hex");
          }
          return result;
        } });
    });
    const verified = verifyOwnerCutoverHistory([f.signedA], [root.inherited], account);
    assert.ok(root.reads > 0, "physical Symbol(kHandle) getter must execute");
    assert.equal(armed, true, "the native getter must install the hostile Hash prototype");
    assert.equal(verified.statement.inventory_head, f.signedA.inventory_head);
    assert.equal(verified.digest, f.digestA, "verified owner A must never report B's digest");
    assert.equal(forgedDigests, 0, "the canonical digest must bypass hostile prototype dispatch");
  });
});

test("P2 update: a valid owner A signature cannot hash signed owner B's bytes after hostile Hash.prototype.update rebinding", () => {
  const f = fixture();
  const signedPayload = (wire) => Object.fromEntries(OWNER_FIELDS.map((name) => [name, wire[name]]));
  const bytesA = Buffer.concat([signatureBytes(DOMAIN_OWNER, signedPayload(f.signedA)),
    Buffer.from(f.signedA.signature, "base64url")]);
  const bytesB = Buffer.concat([signatureBytes(DOMAIN_OWNER, signedPayload(f.signedB)),
    Buffer.from(f.signedB.signature, "base64url")]);
  assert.notDeepEqual(bytesA, bytesB);
  let rewrites = 0;
  let armed = false;
  withHashPrototypeRebind((hashProto, nativeUpdate) => {
    const root = controlledNativeRoot(f.A.publicKey, () => {
      if (armed) return;
      armed = true;
      Object.defineProperty(hashProto, "update", { ...Object.getOwnPropertyDescriptor(hashProto, "update"),
        value: function updateReplacement(bytes, encoding) {
          if (Buffer.isBuffer(bytes) && bytes.equals(bytesA)) {
            rewrites++;
            return nativeUpdate.call(this, bytesB, encoding);
          }
          return nativeUpdate.call(this, bytes, encoding);
        } });
    });
    const verified = verifyOwnerCutoverHistory([f.signedA], [root.inherited], account);
    assert.ok(root.reads > 0, "physical Symbol(kHandle) getter must execute");
    assert.equal(armed, true, "the native getter must install the hostile Hash prototype");
    assert.equal(verified.statement.inventory_head, f.signedA.inventory_head);
    assert.equal(verified.digest, f.digestA, "verified owner A must never hash signed B's bytes");
    assert.equal(rewrites, 0, "canonical hashing must bypass hostile update prototype dispatch");
  });
});

test("positive: authentic owner cutover and Ed25519 A-to-B owner rotation remain valid", () => {
  const f = fixture();
  const honest = verifyOwnerCutoverHistory([f.signedA], [f.A.publicKey], account);
  assert.equal(honest.digest, f.digestA);
  assert.equal(verifyOwnerCutoverHistory([f.signedB], [f.B.publicKey], account).digest, f.digestB);
  const rotation = signOwnerRotation({
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: account,
    generation: 1, from_spki_sha256: spkiHash(f.A.publicKey),
    next_public_key: f.B.publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
    previous_rotation_digest: null,
  }, f.A.privateKey, f.B.privateKey);
  const verifiedKeys = verifyOwnerRotationKeys([rotation], f.A.publicKey, account);
  assert.equal(verifiedKeys.length, 2);
  assert.equal(crypto.KeyObject.prototype.equals.call(verifiedKeys[1], f.B.publicKey), true);
});
