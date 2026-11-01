"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const protocol = require("../sync-client/rootark-sync-protocol");
const { DOMAIN, verifySignedOwnerBindingsDevOff } =
  require("../src/services/zk1SyncAtomicSignedOwnerBindingsDevOff");
const { WITNESS_DOMAIN } = require("../src/services/zk1SyncAtomicCasFloorLedgerDevOff");
const { createZk1SyncAtomicPgPhysicalFenceDevOff } =
  require("../src/services/zk1SyncAtomicPgPhysicalFenceDevOff");

const DENIED = { code: "ZK1_SYNC_OWNER_ROSTER_DEV_OFF_DENIED" };
const ADAPTER_DENIED = { code: "SYNC_ATOMIC_PG_FENCE_DEV_OFF_DENIED" };
const hash = () => crypto.randomBytes(32).toString("hex");
const signManifest = (manifest, key) => {
  const statement = Buffer.from(DOMAIN + protocol.canonicalJson(manifest), "utf8");
  return { manifest, trustedOwnerPublicKey: key.publicKey,
    signature: crypto.sign(null, statement, key.privateKey).toString("base64url"),
    independentlyPinnedSha256: crypto.createHash("sha256").update(statement).digest("hex"),
    trustedMinimumRevision: manifest.revision };
};

test("DEV-OFF operator-signed scope/owner/storage roster requires independent digest, signer and revision pins", async (t) => {
  const key = crypto.generateKeyPairSync("ed25519");
  const rogue = crypto.generateKeyPairSync("ed25519");
  const binding = { scope: "alice:private", accountId: crypto.randomUUID(),
    storeId: crypto.randomUUID(), username: "alice", compartmentId: "private" };
  const manifest = { version: 1, revision: 7, bindings: [binding] };
  const original = signManifest(manifest, key);
  const verified = verifySignedOwnerBindingsDevOff(original);
  assert.equal(verified.digest, original.independentlyPinnedSha256);
  assert.equal(verified.revision, 7);
  assert.deepEqual(verified.bindings, [binding]);
  assert.equal(Object.isFrozen(verified.bindings[0]), true);
  for (const hostile of [
    { independentlyPinnedSha256: hash() },
    { trustedMinimumRevision: 8 },
    { trustedOwnerPublicKey: rogue.publicKey },
    { signature: crypto.sign(null, Buffer.from("wrong domain"),
      key.privateKey).toString("base64url") },
    { manifest: { ...manifest, bindings: [{ ...binding, storeId: crypto.randomUUID() }] } },
    { trustedMinimumRevision: 0 },
    { independentlyPinnedSha256: undefined },
  ]) assert.throws(() => verifySignedOwnerBindingsDevOff({ ...original, ...hostile }),
    DENIED, "invalid signer, pin, revision, owner or domain must fail closed");
  const duplicate = signManifest({ ...manifest, bindings: [binding, { ...binding }] }, key);
  assert.throws(() => verifySignedOwnerBindingsDevOff(duplicate), DENIED);
  const broken = signManifest({ ...manifest,
    bindings: [{ ...binding, extra: "untrusted" }] }, key);
  assert.throws(() => verifySignedOwnerBindingsDevOff(broken), DENIED);

  const prev = process.env.NODE_ENV;
  process.env.NODE_ENV = "test";
  t.after(() => { if (prev === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prev; });
  const physicalKey = crypto.generateKeyPairSync("ed25519");
  const challenge = { ...binding, nonce: crypto.randomBytes(32).toString("base64url"),
    operationIds: ["delete:one", "move:one"], envelopeDigests: [hash(), hash()],
    expectedPrevious: null };
  const statement = { ...challenge, version: 2,
    commitId: crypto.randomUUID(), storeHeadSha256: hash(), fencingEpoch: 3,
    physicalDurable: true };
  delete statement.expectedPrevious;
  const witness = { statement, signature: crypto.sign(null,
    Buffer.from(WITNESS_DOMAIN + protocol.canonicalJson(statement)),
    physicalKey.privateKey).toString("base64url") };
  let observed = 0;
  const options = { witnessPublicKey: physicalKey.publicKey,
    signedOwnerBindingsAuthority: original,
    unsafeTestReadback: { async verifyCurrentSignedPair() {
      observed++;
      return { scope: binding.scope, username: binding.username,
        compartmentId: binding.compartmentId, commitId: statement.commitId,
        head: statement.storeHeadSha256,
        operationIds: challenge.operationIds, envelopeDigests: challenge.envelopeDigests,
        localPgRowsConsistent: true, witnessVerified: false, clientAckAuthorized: false };
    } },
    externalPhysicalFence: { async withCurrentRead(_input, continuation) {
      return continuation({ receipt: witness, lineage: null },
        { assertHeld: () => true });
    } },
  };
  assert.throws(() => createZk1SyncAtomicPgPhysicalFenceDevOff({ ...options,
    ownerBindings: [{ ...binding, accountId: crypto.randomUUID() }] }),
  ADAPTER_DENIED, "a raw roster cannot silently override a signed/pinned owner identity");
  assert.equal(observed, 0);
  const adapter = createZk1SyncAtomicPgPhysicalFenceDevOff(options);
  binding.storeId = crypto.randomUUID();
  assert.equal(await adapter.withCurrentRead(challenge, async () => "signed-owner-ok"),
    "signed-owner-ok", "changing a manifest source after construction cannot repin it");
  assert.equal(observed, 1);
  await assert.rejects(adapter.withCurrentRead({ ...challenge,
    storeId: binding.storeId }, async () => "bad"), ADAPTER_DENIED);
  assert.equal(observed, 1, "wrong store identity must be denied before SQL readback");
});
