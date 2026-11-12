"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { runOfflineSigner } =
  require("./support/issue-65-owner-inventory-offline-runner");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const { SCHEMA, checkpointDigest, verifyOwnerInventoryEnrollment } =
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
