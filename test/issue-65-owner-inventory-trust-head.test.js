"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { runOfflineSigner } =
  require("./support/issue-65-owner-inventory-offline-runner");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const { SCHEMA, FIELDS, checkpointDigest, verifyOwnerInventoryEnrollment } =
  require("../src/crypto/rootark-zk1-owner-inventory-trust-head");
const portable = require("../public/client/rootark-zk1-owner-inventory-trust-head");

async function fixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("owner-client"), keyring_id: crypto.randomBytes(16) };
  const signerKeyId = crypto.randomBytes(16);
  const nonce = crypto.randomBytes(32);
  const snapshot = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: keys.privateKey, scope,
    sequence: 0, previousRoot: null, entries: [], nonce,
  });
  const decoded = await require("../src/crypto/rootark-zk-1").decodeDeterministic(snapshot);
  const now = Math.floor(Date.now() / 1000);
  const signed = await runOfflineSigner({
    scope: Object.fromEntries(Object.entries(scope).map(([name, value]) =>
      [name, value.toString("base64url")])),
    inventorySignerKeyId: signerKeyId.toString("base64url"),
    inventorySpkiSha256: crypto.createHash("sha256")
      .update(keys.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
    heads: [{ sequence: 0, root: Buffer.from(decoded.root).toString("hex"),
      snapshotSha256: crypto.createHash("sha256").update(snapshot).digest("hex"),
      issuedAt: now - 5, expiresAt: now + 120 }],
  });
  const enrollment = {
    checkpoints: signed.checkpoints,
    ownerPublicKey: crypto.createPublicKey({ key: Buffer.from(signed.ownerSpki, "base64url"),
      type: "spki", format: "der" }),
    independentOwnerSpkiSha256: signed.independentOwnerSpkiSha256,
    independentRetainedCheckpointDigest: signed.independentRetainedCheckpointDigest,
    expectedScope: scope, inventoryPublicKey: keys.publicKey,
    inventorySignerKeyId: signerKeyId, minimumSnapshot: snapshot, nowSeconds: now,
  };
  return { enrollment, signed, scope, keys, now, snapshot };
}

// The owner signer is a genuinely separate process and signs the SHA-256 of
// the ACTUAL supplied bytes B, not the valid inventory bytes C later forged
// into the decoder by a caller-owned KeyObject getter.
async function signedOwnerOnInvalidInventoryBytes() {
  const good = await fixture();
  const z = require("../src/crypto/rootark-zk-1");
  const decodedC = await z.decodeDeterministic(good.snapshot);
  const fakeSignature = crypto.randomBytes(64);
  assert.notDeepEqual(fakeSignature, decodedC.signature);
  const bytesB = await z.encodeDeterministic({ ...decodedC, signature: fakeSignature });
  assert.notDeepEqual(bytesB, good.snapshot);
  const ownerB = await runOfflineSigner({
    scope: Object.fromEntries(Object.entries(good.scope).map(([name, data]) =>
      [name, data.toString("base64url")])),
    inventorySignerKeyId: good.enrollment.inventorySignerKeyId.toString("base64url"),
    inventorySpkiSha256: crypto.createHash("sha256").update(
      good.keys.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
    heads: [{ sequence: 0, root: Buffer.from(decodedC.root).toString("hex"),
      snapshotSha256: crypto.createHash("sha256").update(bytesB).digest("hex"),
      issuedAt: good.now - 5, expiresAt: good.now + 120 }],
  });
  const enrollmentB = {
    ...good.enrollment, minimumSnapshot: bytesB,
    checkpoints: ownerB.checkpoints,
    ownerPublicKey: crypto.createPublicKey({
      key: Buffer.from(ownerB.ownerSpki, "base64url"), format: "der", type: "spki",
    }),
    independentOwnerSpkiSha256: ownerB.independentOwnerSpkiSha256,
    independentRetainedCheckpointDigest: ownerB.independentRetainedCheckpointDigest,
  };
  assert.equal(enrollmentB.checkpoints[0].snapshot_sha256,
    crypto.createHash("sha256").update(bytesB).digest("hex"));
  await assert.rejects(verifyOwnerInventoryEnrollment(enrollmentB),
    /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/,
    "real offline owner signature over B cannot validate fake inventory signature B");
  return { good, decodedC, bytesB, enrollmentB };
}

test("owner-signed raw B rejects forged nested inventory signature despite post-KeyObject codec B-to-C", async () => {
  const { good, decodedC, bytesB, enrollmentB } =
    await signedOwnerOnInvalidInventoryBytes();
  const z = require("../src/crypto/rootark-zk-1");
  const originalDecode = z.decodeDeterministic;
  const owner = crypto.createPublicKey({
    key: enrollmentB.ownerPublicKey.export({ type: "spki", format: "der" }),
    format: "der", type: "spki",
  });
  let getterCalls = 0;
  let substituted = 0;
  Object.defineProperty(owner, "type", { configurable: true, get() {
    getterCalls++;
    z.decodeDeterministic = async (raw) => {
      if (Buffer.isBuffer(raw) && raw.equals(bytesB)) {
        substituted++;
        return decodedC; // Genuine signed inventory C, but B was owner-pinned.
      }
      return originalDecode(raw);
    };
    return "public";
  } });
  let accepted = false;
  try {
    try {
      await verifyOwnerInventoryEnrollment({ ...enrollmentB, ownerPublicKey: owner });
      accepted = true;
    } catch (error) {
      assert.match(error.message, /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
    }
  } finally {
    z.decodeDeterministic = originalDecode;
    delete owner.type;
  }
  assert.ok(getterCalls > 0, "genuine KeyObject callback must execute");
  assert.equal(accepted, false, "owner signature on B cannot attest to signed C");
  assert.equal((await verifyOwnerInventoryEnrollment(good.enrollment)).ownerSignatureVerified, true);
  assert.equal(substituted, 0,
    "no post-KeyObject dispatch may reach the shared mutable decoder export");
});

test("owner-signed raw B must not be mutated in decoder to an unsigned inventory C", async () => {
  const { good, bytesB, enrollmentB } = await signedOwnerOnInvalidInventoryBytes();
  // Offline owner signs the SHA256 of B. C is a genuine Ed25519 inventory
  // snapshot, identical in length but NOT authorized by that owner checkpoint.
  const signedC = Buffer.from(good.snapshot);
  assert.notDeepEqual(bytesB, signedC);
  assert.equal(bytesB.length, signedC.length);
  const ownerKey = crypto.createPublicKey({
    key: enrollmentB.ownerPublicKey.export({ type: "spki", format: "der" }),
    format: "der", type: "spki",
  });
  const originalFrom = Buffer.from;
  const nativeCompare = Buffer.compare.bind(Buffer);
  let getterReads = 0, mutatedCopies = 0;
  Object.defineProperty(ownerKey, "type", { configurable: true, get() {
    getterReads++;
    Buffer.from = function(input, ...args) {
      if (Buffer.isBuffer(input) && input.length === bytesB.length
        && nativeCompare(input, bytesB) === 0) {
        // Hostile post-owner-hash mutation of the verifier's local B copy:
        // original owner hash was B, nested Ed25519 inventory is now C.
        mutatedCopies++;
        signedC.copy(input);
      }
      return Reflect.apply(originalFrom, Buffer, [input, ...args]);
    };
    return "public";
  } });
  let accepted = false;
  try {
    try {
      await verifyOwnerInventoryEnrollment({ ...enrollmentB, ownerPublicKey: ownerKey });
      accepted = true;
    } catch (error) {
      assert.match(error.message, /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
    }
  } finally {
    Buffer.from = originalFrom;
    delete ownerKey.type;
  }
  assert.ok(getterReads > 0, "native KeyObject.type getter ran");
  assert.equal(accepted, false, "offline owner signature over B must not attest C");
  assert.equal(mutatedCopies, 0,
    "decoder input must use early pinned Buffer.from, never hostile wrapper");
  assert.equal((await verifyOwnerInventoryEnrollment(good.enrollment)).ownerSignatureVerified,
    true, "legitimate owner and inventory positive preserved");
});

test("valid offline owner A and signed inventory C survive post-getter codec export replacement", async () => {
  const f = await fixture();
  const z = require("../src/crypto/rootark-zk-1");
  const originalDecode = z.decodeDeterministic;
  const originalEncode = z.encodeDeterministic;
  const owner = crypto.createPublicKey({
    key: f.enrollment.ownerPublicKey.export({ type: "spki", format: "der" }),
    type: "spki", format: "der",
  });
  let getterCalls = 0;
  let injectedCalls = 0;
  Object.defineProperty(owner, "type", { configurable: true, get() {
    getterCalls++;
    z.decodeDeterministic = async () => {
      injectedCalls++;
      throw new Error("MUTABLE_DECODER_CALLED");
    };
    z.encodeDeterministic = async () => {
      injectedCalls++;
      throw new Error("MUTABLE_ENCODER_CALLED");
    };
    return "public";
  } });
  try {
    const accepted = await verifyOwnerInventoryEnrollment({
      ...f.enrollment, ownerPublicKey: owner,
    });
    assert.equal(accepted.ownerSignatureVerified, true);
    assert.equal(accepted.authorizesIo, false);
  } finally {
    z.decodeDeterministic = originalDecode;
    z.encodeDeterministic = originalEncode;
    delete owner.type;
  }
  assert.ok(getterCalls > 0, "native owner key callback executed");
  assert.equal(injectedCalls, 0,
    "authentic signed C must not use mutable codec exports after the getter");
});

test("owner-signed raw B rejects mutable nested verifier even with valid owner Ed25519", async () => {
  const { good, enrollmentB } = await signedOwnerOnInvalidInventoryBytes();
  const originalVerify = inventory.verifySnapshot;
  const owner = crypto.createPublicKey({
    key: enrollmentB.ownerPublicKey.export({ type: "spki", format: "der" }),
    format: "der", type: "spki",
  });
  let getterCalls = 0;
  Object.defineProperty(owner, "type", { configurable: true, get() {
    getterCalls++;
    inventory.verifySnapshot = async () => ({ status: "FAKE_ACCEPT" });
    return "public";
  } });
  let accepted = false;
  try {
    try {
      await verifyOwnerInventoryEnrollment({ ...enrollmentB, ownerPublicKey: owner });
      accepted = true;
    } catch (error) {
      assert.match(error.message, /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
    }
  } finally {
    inventory.verifySnapshot = originalVerify;
    delete owner.type;
  }
  assert.ok(getterCalls > 0);
  assert.equal(accepted, false, "forged nested verifier cannot authorize B");
  assert.equal((await verifyOwnerInventoryEnrollment(good.enrollment)).ownerSignatureVerified, true);
});

test("independent offline owner process signs an externally pinned, verified inventory root", async () => {
  const f = await fixture();
  const verified = await verifyOwnerInventoryEnrollment(f.enrollment);
  assert.equal(verified.ownerSignatureVerified, true);
  assert.equal(verified.externallyPinnedDigestMatched, true);
  assert.equal(verified.signedCounter, 1);
  assert.equal(verified.minimumHead.sequence, 0);
  assert.equal(verified.independentOffServerCustodyProven, false);
  assert.equal(verified.authorizesIo, false);
});

test("signed owner inventory ancestry cannot be verified under a spoofed independent owner SPKI pin", async () => {
  const f = await fixture();
  const genuineOwner = f.enrollment.ownerPublicKey;
  const disguisedOwner = crypto.createPublicKey({
    key: genuineOwner.export({ type: "spki", format: "der" }),
    format: "der", type: "spki",
  });
  const foreignOwner = crypto.generateKeyPairSync("ed25519");
  const foreignSpki = foreignOwner.publicKey.export({ type: "spki", format: "der" });
  disguisedOwner.export = () => Buffer.from(foreignSpki);
  await assert.rejects(verifyOwnerInventoryEnrollment({ ...f.enrollment,
    ownerPublicKey: disguisedOwner,
    independentOwnerSpkiSha256: crypto.createHash("sha256").update(foreignSpki).digest("hex"),
  }), /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/,
  "an owner signature is not proof of the independently pinned owner identity");
});

test("P2 native owner handle cannot pin SPKI B while verifying genuine owner Ed25519 A", async () => {
  const f = await fixture();
  const nativeA = f.enrollment.ownerPublicKey;
  const foreign = crypto.generateKeyPairSync("ed25519");
  const foreignSpki = foreign.publicKey.export({ type: "spki", format: "der" });
  const foreignPin = crypto.createHash("sha256").update(foreignSpki).digest("hex");
  await assert.rejects(verifyOwnerInventoryEnrollment({
    ...f.enrollment, independentOwnerSpkiSha256: foreignPin,
  }), /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/,
  "genuine signed owner A must reject independent pin B");

  const handle = Object.getOwnPropertySymbols(nativeA)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "Node22 real owner Ed25519 KeyObject handle required");
  const hybrid = Object.create(nativeA);
  let returnedForeignDuringSpki = 0;
  let returnedGenuineDuringVerification = 0;
  Object.defineProperty(hybrid, handle, { get() {
    if (new Error().stack.includes("nativeEd25519Spki")) {
      returnedForeignDuringSpki++;
      return foreign.publicKey[handle];
    }
    returnedGenuineDuringVerification++;
    return nativeA[handle];
  } });
  await assert.rejects(verifyOwnerInventoryEnrollment({
    ...f.enrollment, ownerPublicKey: hybrid,
    independentOwnerSpkiSha256: foreignPin,
  }), /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/,
  "caller-controlled native kHandle must never mix B identity with A signature");
  assert.ok(returnedForeignDuringSpki > 0, "native export must have observed attacker B handle");
  assert.equal(returnedGenuineDuringVerification, 0,
    "the verifier must not return to the caller-owned A handle after pinning B");
  assert.equal((await verifyOwnerInventoryEnrollment(f.enrollment)).ownerSignatureVerified, true,
    "genuine owner A remains accepted for the true A pin");
});

test("P2 native inventory handle cannot pin signer B while verifying genuine signed snapshot A", async () => {
  const f = await fixture();
  const otherInventory = crypto.generateKeyPairSync("ed25519");
  const spkiB = otherInventory.publicKey.export({ type: "spki", format: "der" });
  const decoded = await require("../src/crypto/rootark-zk-1").decodeDeterministic(f.snapshot);
  const freshOwner = await runOfflineSigner({
    scope: Object.fromEntries(Object.entries(f.scope).map(([name, bytes]) =>
      [name, bytes.toString("base64url")])),
    inventorySignerKeyId: f.enrollment.inventorySignerKeyId.toString("base64url"),
    inventorySpkiSha256: crypto.createHash("sha256").update(spkiB).digest("hex"),
    heads: [{ sequence: 0, root: Buffer.from(decoded.root).toString("hex"),
      snapshotSha256: crypto.createHash("sha256").update(f.snapshot).digest("hex"),
      issuedAt: f.now - 5, expiresAt: f.now + 120 }],
  });
  const claimedB = {
    ...f.enrollment, checkpoints: freshOwner.checkpoints,
    ownerPublicKey: crypto.createPublicKey({
      key: Buffer.from(freshOwner.ownerSpki, "base64url"),
      format: "der", type: "spki",
    }),
    independentOwnerSpkiSha256: freshOwner.independentOwnerSpkiSha256,
    independentRetainedCheckpointDigest: freshOwner.independentRetainedCheckpointDigest,
    inventoryPublicKey: otherInventory.publicKey,
  };
  await assert.rejects(verifyOwnerInventoryEnrollment(claimedB),
    /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/,
    "genuine owner-signed declaration of inventory B cannot verify snapshot signed by A");

  const realA = f.keys.publicKey;
  const handle = Object.getOwnPropertySymbols(realA)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "real Ed25519 inventory native handle required");
  const hybrid = Object.create(realA);
  let spkiBReads = 0;
  let checkedAReads = 0;
  Object.defineProperty(hybrid, handle, { get() {
    if (new Error().stack.includes("nativeEd25519Spki")) {
      spkiBReads++;
      return otherInventory.publicKey[handle];
    }
    checkedAReads++;
    return realA[handle];
  } });
  await assert.rejects(verifyOwnerInventoryEnrollment({
    ...claimedB, inventoryPublicKey: hybrid,
  }), /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/,
  "signed B inventory identity cannot validate genuine A snapshot through mutable kHandle");
  assert.ok(spkiBReads > 0, "fingerprint path exercised the foreign inventory handle");
  assert.equal(checkedAReads, 0,
    "nested inventory signature verifier must never use caller-owned A handle");
  // The caller's public key getter can also retarget the mutable Node
  // crypto.verify export after native SPKI export but before the nested
  // inventory snapshot verifies its Ed25519 signature. The independently
  // owner-signed inventory B fingerprint MUST still reject snapshot A.
  const originalVerify = crypto.verify;
  const poisoned = Object.create(realA);
  let exportBRuns = 0;
  let injectedVerifyRuns = 0;
  Object.defineProperty(poisoned, handle, { get() {
    if (new Error().stack.includes("nativeEd25519Spki")) {
      exportBRuns++;
      crypto.verify = (...args) => {
        injectedVerifyRuns++;
        return true;
      };
      return otherInventory.publicKey[handle];
    }
    return realA[handle];
  } });
  try {
    await assert.rejects(verifyOwnerInventoryEnrollment({
      ...claimedB, inventoryPublicKey: poisoned,
    }), /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/,
    "owner-signed B must not accept inventory-signed A via retargeted dynamic crypto.verify");
    assert.ok(exportBRuns > 0, "attack must execute inside a real native inventory getter");
    assert.equal(injectedVerifyRuns, 0, "nested verification must retain the native crypto.verify");
  } finally {
    crypto.verify = originalVerify;
  }
  assert.equal((await verifyOwnerInventoryEnrollment(f.enrollment)).ownerSignatureVerified, true,
    "unmodified legitimate A snapshot continues to verify with its signed A key");
});

test("browser/WebCrypto imports offline owner checkpoint with independent pins; export roundtrip is portable", async () => {
  const f = await fixture();
  const wire = portable.exportPortableEnrollment({
    ownerSpkiDer: Buffer.from(f.signed.ownerSpki, "base64url"),
    checkpoints: f.signed.checkpoints,
    minimumSnapshot: f.snapshot,
  });
  const args = { serialized: wire,
    independentOwnerSpkiSha256: f.signed.independentOwnerSpkiSha256,
    independentCheckpointDigest: f.signed.independentRetainedCheckpointDigest,
    expectedScope: Object.values(f.scope).map((value) => value.toString("base64url")),
    expectedInventorySpkiSha256: crypto.createHash("sha256")
      .update(f.keys.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
    nowSeconds: f.now };
  const verified = await portable.importPortableEnrollment(args);
  assert.equal(verified.ownerSignatureVerified, true);
  assert.equal(verified.ownerCheckpointCounter, 1);
  assert.equal(verified.inventorySnapshotSignatureVerified, false);
  assert.equal(verified.authorizesProtectedIo, false);
  await assert.rejects(portable.importPortableEnrollment({
    ...args, independentCheckpointDigest: "0".repeat(64),
  }), /ZK_OWNER_INVENTORY_IMPORT_DENIED/);
  await assert.rejects(portable.importPortableEnrollment({
    ...args, nowSeconds: f.now + 121,
  }), /ZK_OWNER_INVENTORY_IMPORT_DENIED/);
  await assert.rejects(portable.importPortableEnrollment({
    ...args, independentOwnerSpkiSha256: "0".repeat(64),
  }), /ZK_OWNER_INVENTORY_IMPORT_DENIED/);
});

test("forged owner, self-pinned checkpoint, expired proof, other inventory and replay deny", async () => {
  const f = await fixture();
  const rejected = async (overrides) => assert.rejects(
    verifyOwnerInventoryEnrollment({ ...f.enrollment, ...overrides }),
    /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
  await rejected({ independentOwnerSpkiSha256: "0".repeat(64) });
  await rejected({ independentRetainedCheckpointDigest: "0".repeat(64) });
  await rejected({ ownerPublicKey: crypto.generateKeyPairSync("ed25519").publicKey });
  await rejected({ inventoryPublicKey: crypto.generateKeyPairSync("ed25519").publicKey });
  await rejected({ minimumSnapshot: Buffer.from("false snapshot") });
  await rejected({ nowSeconds: f.now + 121 });
  await rejected({ nowSeconds: f.now - 10 });
  const changed = { ...f.signed.checkpoints[0], inventory_root: crypto.randomBytes(32).toString("hex") };
  await rejected({ checkpoints: [changed],
    independentRetainedCheckpointDigest: checkpointDigest(changed) });
  const forgedSignature = { ...f.signed.checkpoints[0],
    signature: crypto.randomBytes(64).toString("base64url") };
  await rejected({ checkpoints: [forgedSignature],
    independentRetainedCheckpointDigest: checkpointDigest(forgedSignature) });
});

test("fork, orphan successor, self-claimed previous digest and rollback counter deny", async () => {
  const f = await fixture();
  const root = f.signed.checkpoints[0];
  assert.equal(root.schema, SCHEMA);
  const fork = { ...root, counter: 2, previous_checkpoint_digest: checkpointDigest(root) };
  await assert.rejects(verifyOwnerInventoryEnrollment({
    ...f.enrollment, checkpoints: [root, fork],
    independentRetainedCheckpointDigest: checkpointDigest(fork),
  }), /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
  await assert.rejects(verifyOwnerInventoryEnrollment({
    ...f.enrollment, checkpoints: [fork],
    independentRetainedCheckpointDigest: checkpointDigest(fork),
  }), /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
});

test("owner-signed A never authorizes forged checkpoint B when owner KeyObject getter retargets crypto.verify", async () => {
  // Genuine external-owner Ed25519 signature A and valid signed inventory.
  // B changes ONLY the Ed25519 signature while remaining structurally valid;
  // the independently supplied B digest is real, not a fake unsigned marker.
  const f = await fixture();
  const forged = { ...f.signed.checkpoints[0],
    signature: crypto.randomBytes(64).toString("base64url") };
  const forgedDigest = checkpointDigest(forged);
  let getterCalls = 0;
  const owner = crypto.createPublicKey({
    key: f.enrollment.ownerPublicKey.export({ type: "spki", format: "der" }),
    type: "spki", format: "der",
  });
  const originalVerify = crypto.verify;
  Object.defineProperty(owner, "type", { configurable: true, get() {
    getterCalls += 1;
    crypto.verify = () => true;
    return "public";
  } });
  let verified;
  try {
    try {
      verified = await verifyOwnerInventoryEnrollment({
        ...f.enrollment, ownerPublicKey: owner,
        checkpoints: [forged],
        independentRetainedCheckpointDigest: forgedDigest,
      });
    } catch (error) {
      assert.match(error.message, /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
    }
  } finally {
    crypto.verify = originalVerify;
    delete owner.type;
  }
  assert.ok(getterCalls > 0, "the genuine key's hostile getter must execute");
  assert.equal(verified, undefined,
    "a retargeted same-realm crypto.verify may not validate a forged owner signature");
  const positive = await verifyOwnerInventoryEnrollment(f.enrollment);
  assert.equal(positive.ownerSignatureVerified, true,
    "genuinely signed A stays accepted after the negative");
});

test("owner KeyObject callback cannot rewrite independently expected account B to owner-signed A", async () => {
  const f = await fixture();
  const expectedB = { ...f.scope, account_id: crypto.randomBytes(16) };
  assert.notDeepEqual(expectedB.account_id, f.scope.account_id);
  const owner = crypto.createPublicKey({ key: f.enrollment.ownerPublicKey.export({
    type: "spki", format: "der" }), type: "spki", format: "der" });
  let called = 0;
  Object.defineProperty(owner, "type", { configurable: true, get() {
    called++;
    expectedB.account_id = Buffer.from(f.scope.account_id);
    return "public";
  } });
  let accepted = false;
  try {
    try {
      await verifyOwnerInventoryEnrollment({ ...f.enrollment,
        ownerPublicKey: owner, expectedScope: expectedB });
      accepted = true;
    } catch (error) {
      assert.match(error.message, /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
    }
  } finally { delete owner.type; }
  assert.ok(called > 0, "attacker-owned KeyObject getter must execute");
  assert.equal(accepted, false,
    "initial operator-expected B must not be replaced by owner-signed A");
  assert.equal((await verifyOwnerInventoryEnrollment(f.enrollment)).ownerSignatureVerified, true);
});

test("genuine signed checkpoint A cannot authorize unsigned B by post-getter Buffer.concat retarget", async () => {
  const f = await fixture();
  const authentic = f.signed.checkpoints[0];
  const forgedB = { ...authentic, issued_at: authentic.issued_at - 1 };
  const digestB = checkpointDigest(forgedB);
  const originalConcat = Buffer.concat;
  const domain = Buffer.from("Root.ark/zk-1/owner-inventory-trust-head/v1\0", "ascii");
  const unsignedA = Object.fromEntries(FIELDS.map((name) => [name, authentic[name]]));
  const signatureBytesA = originalConcat([domain,
    Buffer.from(JSON.stringify(unsignedA), "utf8")]);
  let substituted = 0;
  const owner = crypto.createPublicKey({ key: f.enrollment.ownerPublicKey.export({
    type: "spki", format: "der" }), type: "spki", format: "der" });
  Object.defineProperty(owner, "type", { configurable: true, get() {
    Buffer.concat = function(parts, ...args) {
      if (substituted === 0 && Array.isArray(parts) && parts.length === 2
          && Buffer.isBuffer(parts[0]) && parts[0].equals(domain)) {
        substituted++;
        return Buffer.from(signatureBytesA);
      }
      return originalConcat.call(Buffer, parts, ...args);
    };
    return "public";
  } });
  let accepted = false;
  try {
    try {
      await verifyOwnerInventoryEnrollment({ ...f.enrollment,
        ownerPublicKey: owner, checkpoints: [forgedB],
        independentRetainedCheckpointDigest: digestB });
      accepted = true;
    } catch (error) {
      assert.match(error.message, /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
    }
  } finally {
    Buffer.concat = originalConcat;
    delete owner.type;
  }
  assert.equal(accepted, false, "genuine signature A cannot attest to B");
  assert.equal((await verifyOwnerInventoryEnrollment(f.enrollment)).ownerSignatureVerified, true);
});

test("owner A native PublicKey export cannot be spoofed as foreign pinned B via Function.prototype.call", async () => {
  const f = await fixture();
  const owner = crypto.createPublicKey({ key: f.enrollment.ownerPublicKey.export({
    type: "spki", format: "der" }), type: "spki", format: "der" });
  const foreignKey = crypto.generateKeyPairSync("ed25519").publicKey;
  const foreignDer = foreignKey.export({ type: "spki", format: "der" });
  const foreignDigest = crypto.createHash("sha256").update(foreignDer).digest("hex");
  assert.notEqual(foreignDigest, f.enrollment.independentOwnerSpkiSha256);
  const oldCall = Function.prototype.call;
  const safeApply = Reflect.apply.bind(Reflect);
  let keyCallbacks = 0;
  Object.defineProperty(owner, "type", { configurable: true, get() {
    keyCallbacks++;
    Function.prototype.call = function(receiver, ...args) {
      if (receiver === owner && args[0]?.type === "spki" &&
          args[0]?.format === "der") return Buffer.from(foreignDer);
      return safeApply(oldCall, this, [receiver, ...args]);
    };
    return "public";
  } });
  let accepted = false;
  try {
    try {
      await verifyOwnerInventoryEnrollment({
        ...f.enrollment, ownerPublicKey: owner,
        independentOwnerSpkiSha256: foreignDigest,
      });
      accepted = true;
    } catch (error) {
      assert.match(error.message, /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
    }
  } finally {
    Function.prototype.call = oldCall;
    delete owner.type;
  }
  assert.ok(keyCallbacks > 0, "real owner KeyObject getter must be invoked");
  assert.equal(accepted, false,
    "genuinely owner-signed A cannot masquerade as independently pinned B");
  assert.equal((await verifyOwnerInventoryEnrollment(f.enrollment)).ownerSignatureVerified, true);
});
