"use strict";

// Real disposable Ed25519 signatures. The inherited native kHandle getter is
// invoked by the product verifier, after the modules were loaded, and then
// attempts to replace mutable same-realm cryptographic/Array methods.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const pg = require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { verifyAttestedInventoryCommit } =
  require("../src/crypto/rootark-zk1-attested-inventory-commit-v1");
const { snapshotLocalDevicePolicy } =
  require("../sync-client/rootark-sync-zk1-physical-binding");
const { signOwnerCutover, digestOwnerCutover, verifyOwnerCutoverHistory } =
  require("../src/crypto/rootark-zk10-account-cutover-v1");

function nativeGetter(publicKey, onRead) {
  const symbol = Object.getOwnPropertySymbols(publicKey)
    .find((value) => value.description === "kHandle");
  assert.ok(symbol, "Node22 KeyObject native kHandle needed");
  const forged = Object.create(publicKey);
  let reads = 0;
  Object.defineProperty(forged, symbol, { get() {
    reads += 1;
    onRead();
    return publicKey[symbol];
  } });
  return { forged, get reads() { return reads; } };
}

function fixture() {
  const signer = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: Buffer.alloc(16, 21),
    compartment_id: Buffer.from("vault"), keyring_id: Buffer.alloc(16, 22) };
  const operation = { operation_id: Buffer.alloc(16, 23), expected_sequence: 0,
    expected_root: Buffer.alloc(32, 24), object_id: Buffer.alloc(16, 25),
    revision: 1, epoch: 1, ciphertext_sha256: Buffer.alloc(32, 26) };
  return { signer, scope, operation, signerKeyId: Buffer.alloc(16, 27) };
}

async function inventoryReceipt(f) {
  const entry = { object_id: f.operation.object_id, revision: f.operation.revision,
    epoch: f.operation.epoch, ciphertext_sha256: f.operation.ciphertext_sha256 };
  const unsigned = { type: "rootark-content-inventory-entry/v1", version: 1,
    signer_key_id: f.signerKeyId, scope: f.scope, sequence: 1,
    previous_root: f.operation.expected_root, root: Buffer.alloc(32, 28),
    operation_id: f.operation.operation_id, expected_sequence: f.operation.expected_sequence,
    expected_root: f.operation.expected_root,
    request_digest: crypto.createHash("sha256")
      .update(await z.encodeDeterministic(f.operation)).digest(), entry };
  const signature = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0"),
    await z.encodeDeterministic(unsigned),
  ]), f.signer.privateKey);
  return { good: Buffer.from(await z.encodeDeterministic({ ...unsigned, signature })),
    forged: Buffer.from(await z.encodeDeterministic({
      ...unsigned, root: Buffer.alloc(32, 99), signature,
    })) };
}

test("P2 inventory: native getter must not retarget genuine A signature to forged B", async () => {
  const f = fixture();
  const proof = await inventoryReceipt(f);
  const input = (serialized, pinnedPublicKey) => ({ serialized, pinnedPublicKey,
    pinnedSignerKeyId: f.signerKeyId, expectedScope: f.scope, operation: f.operation });
  assert.equal((await inventory.verifyCommittedEntryProof(input(proof.good,
    f.signer.publicKey))).outcome, "COMMITTED_IN_SIGNED_LEDGER");
  await assert.rejects(inventory.verifyCommittedEntryProof(input(proof.forged,
    f.signer.publicKey)), { code: "INVENTORY_SIGNATURE" });
  const originalVerify = crypto.verify;
  let retargetCalls = 0;
  const evil = nativeGetter(f.signer.publicKey, () => {
    crypto.verify = () => { retargetCalls++; return true; };
  });
  try {
    await assert.rejects(inventory.verifyCommittedEntryProof(input(proof.forged,
      evil.forged)), { code: "INVENTORY_SIGNATURE" });
  } finally { crypto.verify = originalVerify; }
  assert.ok(evil.reads > 0, "native getter executes after snapshot");
  assert.equal(retargetCalls, 0, "must use early captured crypto.verify");
  assert.equal((await inventory.verifyCommittedEntryProof(input(proof.good,
    f.signer.publicKey))).authorizesIo, false);
});

test("P2 composite: inherited Ed25519 inventory pin cannot make A signature authorize forged inventory B", async () => {
  const f = fixture();
  f.pgSigner = crypto.generateKeyPairSync("ed25519");
  assert.equal(f.signer.publicKey.equals(f.pgSigner.publicKey), false);
  const receipts = await inventoryReceipt(f);
  const physical = await physicalReceipt(f);
  const input = (receipt, pinnedInventoryPublicKey) => ({
    receipt, physicalAttestation: physical.signed,
    scope: f.scope, operation: f.operation, nonce: physical.nonce,
    pinnedInventoryPublicKey, pinnedInventorySignerKeyId: f.signerKeyId,
    pinnedPhysicalAttestorPublicKey: f.pgSigner.publicKey,
    nowSeconds: physical.now,
  });
  const positive = await verifyAttestedInventoryCommit(input(receipts.good,
    f.signer.publicKey));
  assert.equal(positive.status, "VERIFIED_COMPOSITE_NONAUTHORIZING");
  assert.equal(positive.authorizesIo, false);
  await assert.rejects(verifyAttestedInventoryCommit(input(receipts.forged,
    f.signer.publicKey)), /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/);
  const originalVerify = crypto.verify;
  let mutableCalls = 0;
  const poisonedKey = nativeGetter(f.signer.publicKey, () => {
    crypto.verify = () => { mutableCalls++; return true; };
  });
  try {
    await assert.rejects(verifyAttestedInventoryCommit(input(receipts.forged,
      poisonedKey.forged)), /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/);
  } finally { crypto.verify = originalVerify; }
  assert.ok(poisonedKey.reads > 0, "real inherited native getter before composite");
  assert.equal(mutableCalls, 0, "the pinned native inventory verifier must be used");
  assert.equal((await verifyAttestedInventoryCommit(input(receipts.good,
    f.signer.publicKey))).authorizesIo, false);
});

async function physicalReceipt(f) {
  const now = Math.floor(Date.now() / 1000);
  const nonce = Buffer.alloc(32, 29);
  const digest = Buffer.alloc(32, 30);
  const signed = await pg.signCommittedPhysicalReadback({
    scope: f.scope, operation: f.operation, nonce, issuedAt: now,
    readback: { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation: 1, admissionId: Buffer.alloc(16, 31),
      operationId: f.operation.operation_id, revision: 1, epoch: 1,
      digest, expectedInventorySequence: 0,
      expectedInventoryRoot: f.operation.expected_root, chunkCount: 1,
      root: Buffer.alloc(32, 32), ciphertextSha256: f.operation.ciphertext_sha256,
      authorizesIo: false, provesIndependentOperator: false },
  }, (f.pgSigner || f.signer).privateKey);
  return { signed, now, nonce, digest };
}

test("P2 PG: native getter cannot substitute signature verification or byte comparison", async () => {
  const f = fixture();
  const { signed, now, nonce, digest } = await physicalReceipt(f);
  const options = (pin, expected = undefined) => ({ scope: f.scope,
    operation: f.operation, expected, nonce, pinnedPublicKey: pin, nowSeconds: now });
  assert.equal((await pg.verifyCommittedPhysicalReadback(signed,
    options(f.signer.publicKey))).verified, true);
  const decoded = await z.decodeDeterministic(signed);
  const forged = Buffer.from(await z.encodeDeterministic({
    ...decoded, generation: 2, signature: decoded.signature,
  }));
  await assert.rejects(pg.verifyCommittedPhysicalReadback(forged,
    options(f.signer.publicKey)), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  const originalVerify = crypto.verify;
  let verifyCalls = 0;
  const evil = nativeGetter(f.signer.publicKey, () => {
    crypto.verify = () => { verifyCalls++; return true; };
  });
  try {
    await assert.rejects(pg.verifyCommittedPhysicalReadback(forged,
      options(evil.forged)), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  } finally { crypto.verify = originalVerify; }
  assert.ok(evil.reads > 0);
  assert.equal(verifyCalls, 0, "PG must verify Ed25519 through original native method");

  const originalCompare = crypto.timingSafeEqual;
  let comparisons = 0;
  const comparisonEvil = nativeGetter(f.signer.publicKey, () => {
    crypto.timingSafeEqual = () => { comparisons++; return true; };
  });
  try {
    await assert.rejects(pg.verifyCommittedPhysicalReadback(signed,
      options(comparisonEvil.forged, {
        digest: Buffer.alloc(32, 88), root: Buffer.alloc(32, 32), chunks: 1,
      })), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  } finally { crypto.timingSafeEqual = originalCompare; }
  assert.ok(comparisonEvil.reads > 0);
  assert.equal(comparisons, 0, "PG must retain original constant-time comparator");
  assert.equal((await pg.verifyCommittedPhysicalReadback(signed,
    options(f.signer.publicKey, { digest, root: Buffer.alloc(32, 32), chunks: 1 })))
    .authorizesIo, false);
});

test("P2 PG: signed physical attestation A cannot be decoded and re-encoded as forged B after KeyObject callback", async () => {
  const f = fixture();
  const { signed, now, nonce } = await physicalReceipt(f);
  const genuine = await z.decodeDeterministic(signed);
  const { signature, ...genuineUnsigned } = genuine;
  const genuineUnsignedBytes = await z.encodeDeterministic(genuineUnsigned);
  const foreign = Buffer.from(await z.encodeDeterministic({
    ...genuine, generation: 2, signature,
  }));
  assert.notDeepEqual(foreign, signed, "B must differ from the attestor-signed original A");
  const options = (pinnedPublicKey) => ({ scope: f.scope,
    operation: f.operation, nonce, pinnedPublicKey, nowSeconds: now,
    expected: undefined });
  await assert.rejects(pg.verifyCommittedPhysicalReadback(foreign,
    options(f.signer.publicKey)), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  const originalDecode = z.decodeDeterministic;
  const originalEncode = z.encodeDeterministic;
  let hijackedDecodeCalls = 0, hijackedEncodeCalls = 0;
  const evilKey = crypto.createPublicKey({
    key: f.signer.publicKey.export({ type: "spki", format: "der" }),
    type: "spki", format: "der",
  });
  let getterReads = 0;
  Object.defineProperty(evilKey, "type", { configurable: true, get() {
    getterReads++;
    // The signature of A remains genuine. The attacker supplies B with the
    // same signature and tries to substitute A's canonical unsigned bytes
    // only at the signature-verification boundary.
    z.decodeDeterministic = async () => {
      hijackedDecodeCalls++;
      return { ...genuine, generation: 2 };
    };
    z.encodeDeterministic = async (value) => {
      hijackedEncodeCalls++;
      return Object.hasOwn(value, "signature") ? foreign : genuineUnsignedBytes;
    };
    return "public";
  } });
  try {
    await assert.rejects(pg.verifyCommittedPhysicalReadback(foreign,
      options(evilKey)), /ZK_PHYSICAL_ATTESTATION_DENIED/,
    "a valid Ed25519 signature on A cannot authorize forged generation B");
  } finally {
    z.decodeDeterministic = originalDecode;
    z.encodeDeterministic = originalEncode;
    delete evilKey.type;
  }
  assert.ok(getterReads > 0, "the initial KeyObject type getter must fire");
  assert.equal(hijackedDecodeCalls, 0, "the verified decoder must not be retargetable");
  assert.equal(hijackedEncodeCalls, 0, "the signed-byte encoder must not be retargetable");
  const legitimate = await pg.verifyCommittedPhysicalReadback(signed,
    options(f.signer.publicKey));
  assert.equal(legitimate.generation, 1, "positive signed A must remain usable");
  assert.equal(legitimate.authorizesIo, false);
});

test("P2 PG: native CBOR internals cannot turn unsigned generation B into attestor-signed A through Buffer.from", async () => {
  const f = fixture();
  const { signed, now, nonce } = await physicalReceipt(f);
  const original = await z.decodeDeterministic(signed);
  const { signature, ...unsignedA } = original;
  const unsignedB = { ...unsignedA, generation: 2 };
  const encodedA = Buffer.from(await z.encodeDeterministic(unsignedA));
  const encodedB = Buffer.from(await z.encodeDeterministic(unsignedB));
  const forgedB = Buffer.from(await z.encodeDeterministic({ ...unsignedB, signature }));
  assert.notEqual(Buffer.compare(encodedA, encodedB), 0);
  await assert.rejects(pg.verifyCommittedPhysicalReadback(forgedB, {
    scope: f.scope, operation: f.operation, nonce,
    pinnedPublicKey: f.signer.publicKey, nowSeconds: now, expected: undefined,
  }), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  const nativeFrom = Buffer.from;
  const nativeIsBuffer = Buffer.isBuffer;
  const nativeCompare = Buffer.compare;
  let getterReads = 0, forgedCopies = 0, copiesDuringVerification = -1;
  const evilKey = crypto.createPublicKey({
    key: f.signer.publicKey.export({ type: "spki", format: "der" }),
    format: "der", type: "spki",
  });
  Object.defineProperty(evilKey, "type", { configurable: true, get() {
    getterReads++;
    Buffer.from = function (value, ...args) {
      if (value instanceof Uint8Array && !nativeIsBuffer(value)
        && nativeCompare(value, encodedB) === 0) {
        forgedCopies++;
        return nativeFrom(encodedA);
      }
      return nativeFrom(value, ...args);
    };
    return "public";
  } });
  try {
    await assert.rejects(pg.verifyCommittedPhysicalReadback(forgedB, {
      scope: f.scope, operation: f.operation, nonce,
      pinnedPublicKey: evilKey, nowSeconds: now, expected: undefined,
    }), /ZK_PHYSICAL_ATTESTATION_DENIED/,
    "the actual signed A cannot authorize forged PG generation B");
    copiesDuringVerification = forgedCopies;
    // Positive adversary canary: this hook really forges CBOR B into A.
    const probe = Buffer.from(new Uint8Array(encodedB));
    assert.equal(nativeCompare(probe, encodedA), 0);
    assert.equal(forgedCopies, copiesDuringVerification + 1);
  } finally {
    Buffer.from = nativeFrom;
    delete evilKey.type;
  }
  assert.ok(getterReads > 0, "the KeyObject getter must have run before codec use");
  assert.equal(copiesDuringVerification, 0,
    "verified signed bytes must not use the poisoned internal Buffer.from");
  const positive = await pg.verifyCommittedPhysicalReadback(signed, {
    scope: f.scope, operation: f.operation, nonce,
    pinnedPublicKey: f.signer.publicKey, nowSeconds: now, expected: undefined,
  });
  assert.equal(positive.generation, 1);
  assert.equal(positive.authorizesIo, false);
});

test("P2 device revocation: post-kHandle Array.push cannot erase revoked device", () => {
  const device = crypto.generateKeyPairSync("ed25519");
  const message = Buffer.from("real device policy callback");
  const signature = crypto.sign(null, message, device.privateKey);
  const originalPush = Array.prototype.push;
  const evil = nativeGetter(device.publicKey, () => {
    Array.prototype.push = function() { return this.length; };
  });
  let revoked;
  try {
    assert.equal(crypto.verify(null, message, evil.forged, signature), true,
      "real Ed25519 verifier invokes inherited kHandle");
    const policy = snapshotLocalDevicePolicy({ username: "alice",
      trustedDevicePublicKeys: { device_1: "AA" }, revokedDeviceIds: ["device_1"] });
    revoked = policy.revokedDeviceIds;
  } finally {
    Array.prototype.push = originalPush;
  }
  assert.ok(evil.reads > 0);
  assert.deepEqual(revoked, ["device_1"],
    "revoked device is retained even with post-getter Array.push monkeypatch");
});

test("P2 signed owner history returns immutable compartment coverage with original digest", () => {
  const owner = crypto.generateKeyPairSync("ed25519");
  const id = (value) => Buffer.alloc(16, value).toString("base64url");
  const a = signOwnerCutover({ type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: id(40), zk_account_id: id(41),
    generation: 1, previous_cutover_digest: null,
    inventory_head: Buffer.alloc(32, 42).toString("hex"), complete_corpus: true,
    covered_compartments: [id(43)], legacy_egress_scope: "all",
    reference_disposition: "fully_accounted", migration_disposition: "closed",
    grant: "protected_enforced", grants: [], suite: "zk1-v2",
    nonce: Buffer.alloc(32, 44).toString("base64url"), issued_at: 1800000000,
  }, owner.privateKey);
  const digestA = digestOwnerCutover(a);
  const result = verifyOwnerCutoverHistory([a], [owner.publicKey], id(40));
  assert.equal(result.digest, digestA);
  assert.equal(result.statement.covered_compartments[0], id(43));
  assert.ok(Object.isFrozen(result.statement.covered_compartments));
  assert.ok(Object.isFrozen(result.statement.grants));
  assert.throws(() => { result.statement.covered_compartments[0] = id(88); }, TypeError);
  assert.throws(() => { result.statement.grants.push("legacy_allow"); }, TypeError);
  assert.equal(result.statement.covered_compartments[0], id(43));
  assert.equal(result.digest, digestOwnerCutover(a));
});

test("P2 inventory signed A must not verify tampered B after hostile Buffer.concat retarget", async () => {
  const f = fixture();
  const { good, forged } = await inventoryReceipt(f);
  const a = await z.decodeDeterministic(good);
  const { signature: unused, ...unsignedA } = a;
  const originalConcat = Buffer.concat;
  const originalSigned = originalConcat([
    Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0"),
    await z.encodeDeterministic(unsignedA),
  ]);
  let replacements = 0;
  const evil = nativeGetter(f.signer.publicKey, () => {
    Buffer.concat = (segments, ...args) => {
      if (Array.isArray(segments) && segments[0]?.equals?.(
        Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0"))) {
        replacements++;
        return Buffer.from(originalSigned);
      }
      return originalConcat(segments, ...args);
    };
  });
  Object.defineProperty(evil.forged, "type", { get() {
    const handle = Object.getOwnPropertySymbols(f.signer.publicKey).find((k) => k.description === "kHandle");
    assert.ok(evil.forged[handle], "real native handle getter reached");
    return "public";
  } });
  const opts = (serialized, key) => ({ serialized, pinnedPublicKey: key,
    pinnedSignerKeyId: f.signerKeyId, expectedScope: f.scope, operation: f.operation });
  assert.equal((await inventory.verifyCommittedEntryProof(opts(good, f.signer.publicKey))).authorizesIo, false);
  await assert.rejects(inventory.verifyCommittedEntryProof(opts(forged, f.signer.publicKey)),
    { code: "INVENTORY_SIGNATURE" });
  try {
    await assert.rejects(inventory.verifyCommittedEntryProof(opts(forged, evil.forged)),
      { code: "INVENTORY_SIGNATURE" }, "signed A must never authenticate the forged B root");
  } finally { Buffer.concat = originalConcat; }
  assert.ok(evil.reads > 0, "hostile native getter must run");
  assert.equal(replacements, 0, "signed bytes must not reach poisoned Buffer.concat");
});

test("P2 PG signed A must not verify generation B after hostile Buffer.concat retarget", async () => {
  const f = fixture();
  const { signed, nonce, now } = await physicalReceipt(f);
  const a = await z.decodeDeterministic(signed);
  const { signature: unused, ...unsignedA } = a;
  const originalConcat = Buffer.concat;
  const originalSigned = originalConcat([
    Buffer.from("Root.ark/zk-1/physical-pg-readback-attestation/v1\0"),
    await z.encodeDeterministic(unsignedA),
  ]);
  const forged = Buffer.from(await z.encodeDeterministic({ ...a, generation: 2 }));
  const options = (pin) => ({ scope: f.scope, operation: f.operation, expected: undefined,
    nonce, pinnedPublicKey: pin, nowSeconds: now });
  assert.equal((await pg.verifyCommittedPhysicalReadback(signed,
    options(f.signer.publicKey))).generation, 1);
  await assert.rejects(pg.verifyCommittedPhysicalReadback(forged,
    options(f.signer.publicKey)), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  let replacements = 0;
  const evil = nativeGetter(f.signer.publicKey, () => {
    Buffer.concat = (segments, ...args) => {
      if (Array.isArray(segments) && segments[0]?.equals?.(
        Buffer.from("Root.ark/zk-1/physical-pg-readback-attestation/v1\0"))) {
        replacements++;
        return Buffer.from(originalSigned);
      }
      return originalConcat(segments, ...args);
    };
  });
  Object.defineProperty(evil.forged, "type", { get() {
    const handle = Object.getOwnPropertySymbols(f.signer.publicKey).find((k) => k.description === "kHandle");
    assert.ok(evil.forged[handle], "real native handle getter reached");
    return "public";
  } });
  try {
    await assert.rejects(pg.verifyCommittedPhysicalReadback(forged, options(evil.forged)),
      /ZK_PHYSICAL_ATTESTATION_DENIED/, "signed A must never authenticate generation B");
  } finally { Buffer.concat = originalConcat; }
  assert.ok(evil.reads > 0, "hostile native getter must run");
  assert.equal(replacements, 0, "signed bytes must not reach poisoned Buffer.concat");
});
test("P2 PG signed scope A cannot authorize foreign scope B via hostile Array.every", async () => {
  const f = fixture();
  const { signed, nonce, now } = await physicalReceipt(f);
  const scopeB = { ...f.scope, account_id: Buffer.alloc(16, 87) };
  const opts = (pin, scope) => ({ scope, operation: f.operation,
    expected: undefined, nonce, pinnedPublicKey: pin, nowSeconds: now });
  assert.equal((await pg.verifyCommittedPhysicalReadback(signed,
    opts(f.signer.publicKey, f.scope))).verified, true);
  await assert.rejects(pg.verifyCommittedPhysicalReadback(signed,
    opts(f.signer.publicKey, scopeB)), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  const originalEvery = Array.prototype.every;
  let attackCalls = 0;
  const evil = nativeGetter(f.signer.publicKey, () => {
    Array.prototype.every = function(callback, ...args) {
      if (this[0] === "account_id" || this[0] === "operation_id"
        || this[0] === "type") { attackCalls++; return true; }
      return originalEvery.call(this, callback, ...args);
    };
  });
  Object.defineProperty(evil.forged, "type", { get() {
    const handle = Object.getOwnPropertySymbols(f.signer.publicKey)
      .find((k) => k.description === "kHandle");
    assert.ok(evil.forged[handle], "real inherited native getter invoked");
    return "public";
  } });
  try {
    await assert.rejects(pg.verifyCommittedPhysicalReadback(signed,
      opts(evil.forged, scopeB)), /ZK_PHYSICAL_ATTESTATION_DENIED/,
    "valid signed A must not authorize a different account B");
  } finally { Array.prototype.every = originalEvery; }
  assert.ok(evil.reads > 0, "native getter must run");
  assert.equal(attackCalls, 0, "same-realm Array.every must never decide signed scope");
});

test("P2 PG: decoder input cannot mutate unsigned raw B into genuinely attestor-signed A after KeyObject callback", async () => {
  const f = fixture();
  const { signed, nonce, now } = await physicalReceipt(f);
  const originalA = await z.decodeDeterministic(signed);
  const forgedB = Buffer.from(await z.encodeDeterministic({
    ...originalA, generation: 2,
  }));
  const nativeFrom = Buffer.from;
  const nativeIsBuffer = Buffer.isBuffer;
  const nativeCompare = Buffer.compare;
  const nativeCopy = Buffer.prototype.copy;
  assert.equal(forgedB.length, signed.length,
    "genuine Ed25519 A and unsigned generation B must have equal CBOR length");
  assert.notEqual(nativeCompare(signed, forgedB), 0,
    "the provided wire B must differ from genuine signed A");
  const opts = (pin) => ({ scope: f.scope, operation: f.operation,
    expected: undefined, nonce, pinnedPublicKey: pin, nowSeconds: now });
  await assert.rejects(pg.verifyCommittedPhysicalReadback(forgedB,
    opts(f.signer.publicKey)), /ZK_PHYSICAL_ATTESTATION_DENIED/);

  const evilKey = crypto.createPublicKey({
    key: f.signer.publicKey.export({ type: "spki", format: "der" }),
    type: "spki", format: "der",
  });
  let keyReads = 0, mutations = 0, mutationsDuringVerification = -1;
  Object.defineProperty(evilKey, "type", { configurable: true, get() {
    keyReads++;
    Buffer.from = function(value, ...args) {
      // The hostile callback receives the verifier's PRIVATE Buffer holding
      // raw B only if the codec internally calls mutable Buffer.from(input).
      if (nativeIsBuffer(value) && value.length === forgedB.length
        && nativeCompare(value, forgedB) === 0) {
        nativeCopy.call(signed, value);
        mutations++;
      }
      return nativeFrom(value, ...args);
    };
    return "public";
  } });
  try {
    await assert.rejects(pg.verifyCommittedPhysicalReadback(forgedB,
      opts(evilKey)), /ZK_PHYSICAL_ATTESTATION_DENIED/,
    "owner-supplied raw B cannot become attestor-signed A during decoding");
    mutationsDuringVerification = mutations;
    // The attack is effective, not a zero-hit/disabled callback oracle:
    // direct invocation with a disposable B changes its bytes to signed A.
    const canaryB = nativeFrom(forgedB);
    Buffer.from(canaryB);
    assert.equal(nativeCompare(canaryB, signed), 0,
      "adversary can replace equal-length raw B in-place with genuine signed A");
    assert.equal(mutations, mutationsDuringVerification + 1);
  } finally {
    Buffer.from = nativeFrom;
    delete evilKey.type;
  }
  assert.ok(keyReads > 0, "the real KeyObject type getter must run");
  assert.equal(mutationsDuringVerification, 0,
    "the decoder must not call poisoned global Buffer.from on raw B");
  const genuine = await pg.verifyCommittedPhysicalReadback(signed,
    opts(f.signer.publicKey));
  assert.equal(genuine.verified, true, "attestor-signed A remains accepted");
  assert.equal(genuine.generation, 1);
  assert.equal(genuine.authorizesIo, false);
});

test("P2 PG: hostile CBOR Object.keys cannot transiently sign A while returning unsigned generation B", async () => {
  const f = fixture();
  const { signed, now, nonce } = await physicalReceipt(f);
  const genuineA = await z.decodeDeterministic(signed);
  assert.deepEqual(await z.encodeDeterministic(genuineA), signed,
    "the genuine Ed25519 signed CBOR A bytes must remain canonical and unchanged");
  const forgedB = Buffer.from(await z.encodeDeterministic({
    ...genuineA, generation: 2,
  }));
  assert.notDeepEqual(forgedB, signed);
  const verify = (pin, serialized = forgedB) => pg.verifyCommittedPhysicalReadback(serialized, {
    scope: f.scope, operation: f.operation, nonce,
    pinnedPublicKey: pin, nowSeconds: now, expected: undefined,
  });
  assert.equal((await verify(f.signer.publicKey, signed)).generation, 1);
  await assert.rejects(verify(f.signer.publicKey), /ZK_PHYSICAL_ATTESTATION_DENIED/);

  const originalKeys = Object.keys;
  let getterReads = 0, substitutions = 0, restored = 0;
  const maliciousPin = crypto.createPublicKey({
    key: f.signer.publicKey.export({ type: "spki", format: "der" }),
    type: "spki", format: "der",
  });
  Object.defineProperty(maliciousPin, "type", { configurable: true, get() {
    getterReads++;
    Object.keys = function (value) {
      if (value && value.type === pg.TYPE && value.generation === 2
        && !Object.hasOwn(value, "signature")) {
        substitutions++;
        value.generation = 1;
        queueMicrotask(() => { value.generation = 2; restored++; });
      }
      return originalKeys(value);
    };
    return "public";
  } });
  let accepted;
  try {
    try { accepted = await verify(maliciousPin); }
    catch (error) { assert.match(error.message, /ZK_PHYSICAL_ATTESTATION_DENIED/); }
    const positiveUnderPoison = await verify(maliciousPin, signed);
    assert.equal(positiveUnderPoison.generation, 1,
      "a genuine Ed25519 attestation A must still verify while the hostile callback is installed");
    assert.equal(positiveUnderPoison.authorizesIo, false);
  } finally {
    Object.keys = originalKeys;
    delete maliciousPin.type;
  }
  assert.ok(getterReads > 0, "the real Ed25519 KeyObject callback ran");
  assert.ok(substitutions > 0, "the CBOR unsigned-map poison was actually invoked");
  assert.equal(restored, substitutions, "every transient mutation was restored");
  assert.equal(accepted, undefined,
    "genuine signed A cannot authenticate the unsigned generation B");
  assert.equal((await verify(f.signer.publicKey, signed)).generation, 1);
});

test("P2 PG: Set.prototype.has after native KeyObject getter cannot sign A but return forged B", async () => {
  const f = fixture();
  const { signed, now, nonce } = await physicalReceipt(f);
  const originalA = await z.decodeDeterministic(signed);
  assert.equal(originalA.generation, 1);
  const forgedB = Buffer.from(await z.encodeDeterministic({ ...originalA, generation: 2 }));
  const verify = (pin, serialized = forgedB) => pg.verifyCommittedPhysicalReadback(serialized, {
    scope: f.scope, operation: f.operation, nonce,
    pinnedPublicKey: pin, nowSeconds: now, expected: undefined,
  });
  assert.equal((await verify(f.signer.publicKey, signed)).generation, 1);
  await assert.rejects(verify(f.signer.publicKey), /ZK_PHYSICAL_ATTESTATION_DENIED/);

  const nativeSetHas = Set.prototype.has;
  const maliciousPin = crypto.createPublicKey({
    key: f.signer.publicKey.export({ type: "spki", format: "der" }),
    type: "spki", format: "der",
  });
  let getterReads = 0, replacements = 0, restorations = 0;
  Object.defineProperty(maliciousPin, "type", { configurable: true, get() {
    getterReads++;
    Set.prototype.has = function (value) {
      if (value && value.type === pg.TYPE && value.generation === 2
        && !Object.hasOwn(value, "signature")) {
        replacements++;
        value.generation = 1;
        queueMicrotask(() => { value.generation = 2; restorations++; });
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
    const positive = await verify(maliciousPin, signed);
    assert.equal(positive.generation, 1, "a real Ed25519 signed A stays accepted under poison");
    assert.equal(positive.authorizesIo, false);
    // The same malicious hook demonstrably mutates a matching unsigned map,
    // even though the guarded codec must never invoke it during verification.
    const probe = { type: pg.TYPE, generation: 2 };
    assert.equal(new Set().has(probe), false);
    await Promise.resolve();
    assert.equal(probe.generation, 2, "the probe's queued restoration ran");
  } finally {
    Set.prototype.has = nativeSetHas;
    delete maliciousPin.type;
  }
  assert.equal(accepted, undefined, "a signature for A must never attest forged B");
  assert.match(rejected?.message || "", /ZK_PHYSICAL_ATTESTATION_DENIED/);
  assert.ok(getterReads > 0, "the real native KeyObject.type getter executed");
  assert.equal(replacementsDuringVerification, 0,
    "codec must use captured native Set.has, not the post-key hostile method");
  assert.equal(replacements, 1, "the hostile hook is live on an independent positive canary");
  assert.equal(restorations, replacements, "all transient A mutations were restored to B");
  assert.equal((await verify(f.signer.publicKey, signed)).generation, 1);
});
