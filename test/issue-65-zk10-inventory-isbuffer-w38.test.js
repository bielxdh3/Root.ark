"use strict";

// Owner signs real wire B in a separate Ed25519 process. B has a forged
// inventory signature; C has a valid inventory signature on the same claims.
// A hostile owner KeyObject getter must not be able to replace the *private*
// owner-hashed B buffer via a late Buffer.isBuffer read by nested copyBytes.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { runOfflineSigner } =
  require("./support/issue-65-owner-inventory-offline-runner");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const codec = require("../src/crypto/rootark-zk-1");
const { verifyOwnerInventoryEnrollment } =
  require("../src/crypto/rootark-zk1-owner-inventory-trust-head");

test("genuine offline owner B cannot accept inventory C substituted in nested copyBytes", async () => {
  const inventorySigner = crypto.generateKeyPairSync("ed25519");
  const scope = {
    account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("w38-inventory-native"),
    keyring_id: crypto.randomBytes(16),
  };
  const signerKeyId = crypto.randomBytes(16);
  const signedC = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: inventorySigner.privateKey, scope,
    sequence: 0, previousRoot: null, entries: [], nonce: crypto.randomBytes(32),
  });
  const decodedC = await codec.decodeDeterministic(signedC);
  const bytesB = await codec.encodeDeterministic({
    ...decodedC, signature: crypto.randomBytes(64),
  });
  assert.notDeepEqual(bytesB, signedC, "B must not have inventory signature C");
  assert.equal(bytesB.length, signedC.length,
    "physical B-to-C substitution cannot depend on a length mismatch");
  const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
  const spkiHash = sha256(inventorySigner.publicKey.export({
    type: "spki", format: "der",
  }));
  const signByOfflineOwner = async (snapshot) => {
    const now = Math.floor(Date.now() / 1000);
    const signed = await runOfflineSigner({
      scope: Object.fromEntries(Object.entries(scope).map(
        ([name, value]) => [name, value.toString("base64url")])),
      inventorySignerKeyId: signerKeyId.toString("base64url"),
      inventorySpkiSha256: spkiHash,
      heads: [{
        sequence: 0, root: Buffer.from(decodedC.root).toString("hex"),
        snapshotSha256: sha256(snapshot), issuedAt: now - 5, expiresAt: now + 120,
      }],
    });
    assert.equal(signed.checkpoints[0].snapshot_sha256, sha256(snapshot),
      "independent owner must sign the exact received raw bytes");
    return {
      checkpoints: signed.checkpoints,
      ownerPublicKey: crypto.createPublicKey({
        key: Buffer.from(signed.ownerSpki, "base64url"),
        type: "spki", format: "der",
      }),
      independentOwnerSpkiSha256: signed.independentOwnerSpkiSha256,
      independentRetainedCheckpointDigest: signed.independentRetainedCheckpointDigest,
      expectedScope: scope, inventoryPublicKey: inventorySigner.publicKey,
      inventorySignerKeyId: signerKeyId, minimumSnapshot: snapshot,
      nowSeconds: now,
    };
  };
  const ownerB = await signByOfflineOwner(bytesB);
  await assert.rejects(verifyOwnerInventoryEnrollment(ownerB),
    /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/,
    "owner signed B, but B has an invalid nested inventory signature");

  const ownerKey = crypto.createPublicKey({
    key: ownerB.ownerPublicKey.export({ type: "spki", format: "der" }),
    format: "der", type: "spki",
  });
  const nativeIsBuffer = Buffer.isBuffer;
  const nativeCompare = Buffer.compare.bind(Buffer);
  let ownerGetterCalls = 0;
  let nestedCopyBytesCalls = 0;
  let poisonedBToC = 0;
  Object.defineProperty(ownerKey, "type", { configurable: true, get() {
    ownerGetterCalls++;
    Buffer.isBuffer = function(value) {
      const genuine = nativeIsBuffer(value);
      if (genuine && value.length === bytesB.length
        && nativeCompare(value, bytesB) === 0) {
        const stack = new Error().stack || "";
        if (stack.includes("copyBytes") && stack.includes("verifySnapshot")) {
          nestedCopyBytesCalls++;
          // This is the verifier's private B, detached before the owner
          // getter. Only the nested inventory read may retarget it to C.
          signedC.copy(value);
          poisonedBToC++;
        }
      }
      return genuine;
    };
    return "public";
  } });
  let accepted = null;
  let rejection = null;
  try {
    try {
      accepted = await verifyOwnerInventoryEnrollment({
        ...ownerB, ownerPublicKey: ownerKey,
      });
    } catch (error) {
      rejection = error;
    }
  } finally {
    Buffer.isBuffer = nativeIsBuffer;
    delete ownerKey.type;
  }
  assert.ok(ownerGetterCalls > 0, "native owner KeyObject getter must run");
  assert.deepEqual(ownerB.minimumSnapshot, bytesB,
    "the hostile callback must mutate only the internal B, not caller input");
  assert.equal(accepted, null,
    "owner Ed25519 over raw B must NEVER authorize signed inventory C");
  assert.match(rejection?.message ?? "", /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
  assert.equal(poisonedBToC, 0,
    "nested inventory must not dispatch through hostile Buffer.isBuffer");
  assert.equal(nestedCopyBytesCalls, 0,
    "the owner-hashed snapshot must not reach the injected byte predicate");

  const ownerC = await signByOfflineOwner(signedC);
  const positive = await verifyOwnerInventoryEnrollment(ownerC);
  assert.equal(positive.ownerSignatureVerified, true,
    "genuine owner checkpoint C and genuine inventory C remain accepted");
  assert.equal(positive.authorizesIo, false);
  assert.equal(positive.independentOffServerCustodyProven, false);

  // A second native Array.isArray dispatch can see the *entire* nested
  // verifySnapshot request with its private .serialized B. A microtask can
  // restore B before the outer owner's final digest, so a final rehash alone
  // must not be treated as a substitute for pinned nested input operations.
  const originalIsArray = Array.isArray;
  const forgedKey = crypto.createPublicKey({
    key: ownerB.ownerPublicKey.export({ type: "spki", format: "der" }),
    format: "der", type: "spki",
  });
  let keyReads = 0, mutatedByArray = 0, restoredByMicrotask = 0;
  Object.defineProperty(forgedKey, "type", { configurable: true, get() {
    keyReads++;
    Array.isArray = function(value) {
      if (value && typeof value === "object" && !originalIsArray(value)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, "serialized");
        const wire = descriptor?.value;
        if (nativeIsBuffer(wire) && wire.length === bytesB.length
          && nativeCompare(wire, bytesB) === 0
          && (new Error().stack || "").includes("objectWithOptional")) {
          mutatedByArray++;
          signedC.copy(wire);
          queueMicrotask(() => {
            bytesB.copy(wire);
            restoredByMicrotask++;
          });
        }
      }
      return originalIsArray(value);
    };
    return "public";
  } });
  let arrayAccepted = null, arrayRejected = null;
  try {
    try {
      arrayAccepted = await verifyOwnerInventoryEnrollment({
        ...ownerB, ownerPublicKey: forgedKey,
      });
    } catch (error) {
      arrayRejected = error;
    }
  } finally {
    Array.isArray = originalIsArray;
    delete forgedKey.type;
  }
  assert.ok(keyReads > 0, "real owner KeyObject getter must fire");
  assert.deepEqual(ownerB.minimumSnapshot, bytesB);
  assert.equal(arrayAccepted, null,
    "temporary nested C must not pass if attacker later restores owner B");
  assert.match(arrayRejected?.message ?? "", /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
  assert.equal(mutatedByArray, 0,
    "nested verification must not dispatch the replaceable Array.isArray");
  assert.equal(restoredByMicrotask, 0,
    "no hostile task may restore original B after a forged nested acceptance");

  // These accessors were also mutable during the previous copyBytes bound:
  // merely capturing Buffer.isBuffer without pinning the backing view reads
  // would leave another same-reference mutation hook inside that copy.
  const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
  for (const name of ["buffer", "byteLength"]) {
    const nativeGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, name).get;
    const originalOwnDescriptor = Object.getOwnPropertyDescriptor(Buffer.prototype, name);
    const keyForAccessor = crypto.createPublicKey({
      key: ownerB.ownerPublicKey.export({ type: "spki", format: "der" }),
      type: "spki", format: "der",
    });
    let accessorKeyReads = 0, privateBMutations = 0;
    Object.defineProperty(keyForAccessor, "type", { configurable: true, get() {
      accessorKeyReads++;
      Object.defineProperty(Buffer.prototype, name, {
        configurable: true,
        get() {
          const stack = new Error().stack || "";
          if (nativeIsBuffer(this) && this.length === bytesB.length
            && nativeCompare(this, bytesB) === 0
            && stack.includes("copyBytes") && stack.includes("verifySnapshot")) {
            privateBMutations++;
            signedC.copy(this);
          }
          return Reflect.apply(nativeGetter, this, []);
        },
      });
      return "public";
    } });
    let acceptedByAccessor = null, accessorRejection = null;
    try {
      try {
        acceptedByAccessor = await verifyOwnerInventoryEnrollment({
          ...ownerB, ownerPublicKey: keyForAccessor,
        });
      } catch (error) {
        accessorRejection = error;
      }
    } finally {
      if (originalOwnDescriptor) {
        Object.defineProperty(Buffer.prototype, name, originalOwnDescriptor);
      } else {
        delete Buffer.prototype[name];
      }
      delete keyForAccessor.type;
    }
    assert.ok(accessorKeyReads > 0, `hostile KeyObject getter for ${name} ran`);
    assert.equal(acceptedByAccessor, null, `inherited ${name} getter cannot replace B`);
    assert.match(accessorRejection?.message ?? "", /ZK_OWNER_INVENTORY_TRUST_UNVERIFIED/);
    assert.equal(privateBMutations, 0,
      `native typed-array ${name} accessor must bypass hostile prototype getter`);
  }
});
