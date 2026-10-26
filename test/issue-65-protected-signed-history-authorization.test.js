"use strict";

const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

// The protected store must never treat a current-head CAS manifest as proof
// that an Ed25519 device enrollment/revocation chain has been verified.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const history = require("../src/crypto/rootark-zk-recovery-history-v2");
const { createZk1SignedHistoryCasProofProvider } =
  require("../src/services/zk1SignedHistoryCasProofProvider");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } =
  require("../src/services/zk1ProtectedObjectStore");

const DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const forbidden = /ZK_CONTENT_UNAVAILABLE|ZK_CONTENT_DENIED/;

test("signed-history-required content denies forged approval and accepts ONLY independent branded complete chain", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-zk65-signed-content-");
  const instances = [];
  t.after(() => {
    for (const store of instances) store.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 });
  });
  const state = await fixtures.createInitialState(2);
  const scope = state.scope;
  let manifest = state.headManifest;
  let clock = 1100;
  const liveSigner = crypto.generateKeyPairSync("ed25519");
  const liveKeyId = crypto.randomBytes(16);
  let witnessReads = 0;
  let manifestReads = 0;
  const witnessProvider = {
    async freshHead({ nonce }) {
      witnessReads++;
      const unsigned = {
        type: "rootark-recovery-witness-head/v1",
        witness_key_id: liveKeyId, ...scope,
        current_revision: manifest.revision,
        current_manifest_digest: await v2.recoveryManifestDigestV2(manifest),
        witness_sequence: manifest.revision, nonce, observed_at: clock,
        status: "committed", pending_reservation_id: null,
      };
      return z.encodeDeterministic({ ...unsigned,
        signature: crypto.sign(null, Buffer.concat([
          DOMAIN, Buffer.from(await z.encodeDeterministic(unsigned)),
        ]), liveSigner.privateKey) });
    },
  };
  const floor = { revision: 1, witnessSequence: 1,
    digest: await v2.recoveryManifestDigestV2(state.baseManifest) };
  let supplied;
  let expensiveHistoryFetches = 0;
  const file = path.join(dir, "content.sqlite");
  const settings = {
    witnessProvider,
    witnessPinned: { keyId: liveKeyId, publicKey: liveSigner.publicKey },
    manifestProvider: () => { manifestReads++; return z.encodeDeterministic(manifest); },
    trustedScope: scope, minimumHead: floor, nowSeconds: () => clock,
    signedHistoryRequired: true,
    signedHistoryGenesisDigest: floor.digest,
    verifiedHistoryProvider: async () => {
      expensiveHistoryFetches += 1;
      return supplied;
    },
  };
  const store = new Zk1ProtectedObjectStore(file, { ...settings, bootstrapNew: true });
  instances.push(store);
  const id = crypto.randomBytes(16).toString("base64url");
  const data = crypto.randomBytes(200);
  const makePut = async () => {
    const device = manifest.devices[0];
    const authorization = { ...scope, device_id: device.device_id,
      operation: "put", object_id: id,
      expected_object_revision: null, manifest_revision: Number(manifest.revision),
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      epoch: Number(manifest.current_epoch), nonce: crypto.randomBytes(32),
      issued_at: clock - 1, expires_at: clock + 30,
      ciphertext_digest: crypto.createHash("sha256").update(data).digest(),
    };
    const signing = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
    return { scope, authorization,
      signature: crypto.sign(null, await contentAuthorizationMessageV1(authorization), signing),
      ciphertext: data };
  };
  const proposal = await makePut();
  // A fake proof returned by a TLS peer or callback must NEVER authorize.
  supplied = { signedStateVerified: true, revision: manifest.revision,
    headDigest: await v2.recoveryManifestDigestV2(manifest), headManifest: manifest };
  await assert.rejects(store.put(proposal), forbidden);
  assert.equal(store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 0);
  supplied = await history.verifyRecoveryHistoryPublicV2({
    expectedScope: scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: state.transitions, packageEnvelopes: state.packageEnvelopes,
    now: clock,
  });
  assert.equal(await history.isVerifiedPublicRecoveryHistoryV2(supplied), true);
  // A private verifier brand must bind BOTH the head and the owner genesis.
  // Otherwise a malicious callback can mutate baseManifest after verification
  // while retaining the brand and defeat the independent genesis pin.
  const oldBaseAccountByte = supplied.baseManifest.account_id[0];
  supplied.baseManifest.account_id[0] ^= 0x01;
  try {
    assert.equal(await history.isVerifiedPublicRecoveryHistoryV2(supplied), false,
      "tampering with branded proof's base genesis must invalidate its brand");
  } finally {
    supplied.baseManifest.account_id[0] = oldBaseAccountByte;
  }
  assert.equal(await history.isVerifiedPublicRecoveryHistoryV2(supplied), true);
  const wrongGenesis = new Zk1ProtectedObjectStore(path.join(dir, "wrong-genesis.sqlite"), {
    ...settings, bootstrapNew: true,
    signedHistoryGenesisDigest: crypto.randomBytes(32),
  });
  instances.push(wrongGenesis);
  await assert.rejects(wrongGenesis.put(proposal), forbidden,
    "a valid branded signed chain cannot replace the pinned owner genesis");
  assert.equal(wrongGenesis.db.prepare(
    "SELECT COUNT(*) AS n FROM zk_content_object").get().n, 0);
  assert.deepEqual(await store.put(proposal), { id, revision: 1 });
  const callsBeforeInvalidSignature = expensiveHistoryFetches;
  await assert.rejects(store.put({ ...proposal,
    authorization: { ...proposal.authorization, nonce: crypto.randomBytes(32) },
    signature: crypto.randomBytes(64) }), /ZK_CONTENT_DENIED/,
  "a forged Ed25519 operation must be rejected before any signed-history fetch");
  assert.equal(expensiveHistoryFetches, callsBeforeInvalidSignature,
    "invalid device keys must never trigger expensive full-history verification");
  const makeRead = async (unbound = false) => {
    const authorization = {
      ...proposal.authorization, operation: "get",
      ciphertext_digest: unbound ? null : crypto.createHash("sha256").update(data).digest(),
      nonce: crypto.randomBytes(32), expected_object_revision: unbound ? null : 1,
      manifest_revision: Number(manifest.revision),
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
    };
    const signing = state.actors.get(Buffer.from(
      manifest.devices[0].authorization_key_id).toString("hex"));
    return { scope, authorization, signature: crypto.sign(null,
      await contentAuthorizationMessageV1(authorization), signing) };
  };
  const providerBeforeUnbound = expensiveHistoryFetches;
  const witnessBeforeUnbound = witnessReads;
  const manifestBeforeUnbound = manifestReads;
  await assert.rejects(store.get(await makeRead(true)), /ZK_CONTENT_DENIED/,
    "owner-rooted mode must not trust mutable SQLite latest without a signed revision and ciphertext digest");
  assert.equal(expensiveHistoryFetches, providerBeforeUnbound,
    "unbound latest GET must fail before expensive owner-history verification");
  assert.equal(witnessReads, witnessBeforeUnbound,
    "unbound latest GET must fail before sending a witness network request");
  assert.equal(manifestReads, manifestBeforeUnbound,
    "unbound latest GET must fail before fetching an untrusted CAS manifest");
  assert.deepEqual((await store.get(await makeRead())).ciphertext, data,
    "signed exact revision and original digest still permit authentic historical GET");
  const originalProvider = store.verifiedHistoryProvider;
  const awaitingHistory = [];
  let twoEntered;
  const bothEntered = new Promise((resolve) => { twoEntered = resolve; });
  store.verifiedHistoryProvider = () => new Promise((resolve) => {
    awaitingHistory.push(resolve);
    if (awaitingHistory.length === 2) twoEntered();
  });
  const firstRead = store.get(await makeRead());
  const secondRead = store.get(await makeRead());
  try {
    await bothEntered;
    const thirdRead = store.get(await makeRead());
    await Promise.race([
      assert.rejects(thirdRead, /ZK_CONTENT_UNAVAILABLE/),
      new Promise((_, reject) => setTimeout(() => reject(
        new Error("third unsigned-history worker was not bounded")), 1500)),
    ]);
    assert.equal(awaitingHistory.length, 2,
      "no more than two expensive signed-history checks may be in flight");
  } finally {
    for (const settle of awaitingHistory) settle(supplied);
    await Promise.allSettled([firstRead, secondRead]);
    store.verifiedHistoryProvider = originalProvider;
  }
  // Local SQLite digests are not provenance. A privileged SQL writer can
  // INSERT a contiguous forged version and move the latest projection to it
  // without disabling the archive's UPDATE/DELETE immutability triggers.
  const forged = crypto.randomBytes(data.length);
  const ownScope = store.db.prepare("SELECT scope FROM zk_content_object WHERE id=?")
    .get(id).scope;
  store.db.prepare(`INSERT INTO zk_content_version
    (scope,id,revision,epoch,ciphertext,ciphertext_digest,provenance)
    VALUES (?,?,?,?,?,?,'transactional')`).run(ownScope, id, 2,
    Number(manifest.current_epoch), forged,
    crypto.createHash("sha256").update(forged).digest());
  store.db.prepare("UPDATE zk_content_object SET revision=2,ciphertext=? WHERE id=?")
    .run(forged, id);
  await assert.rejects(store.get(await makeRead(true)), /ZK_CONTENT_DENIED/,
    "SQL-forged latest content cannot be selected via an unbound owner-rooted GET");
  assert.deepEqual((await store.get(await makeRead())).ciphertext, data,
    "owner-signed original revision/digest still select unchanged real ciphertext");
  // Once a strict owner genesis is installed, restart cannot silently open
  // this same SQLite identity in latest-manifest-only mode or switch roots.
  assert.throws(() => new Zk1ProtectedObjectStore(file, {
    ...settings, signedHistoryRequired: false,
    verifiedHistoryProvider: undefined, bootstrapNew: false,
  }), /ZK_CONTENT_IDENTITY_MISMATCH/);
  assert.throws(() => new Zk1ProtectedObjectStore(file, {
    ...settings, signedHistoryGenesisDigest: crypto.randomBytes(32),
    bootstrapNew: false,
  }), /ZK_CONTENT_IDENTITY_MISMATCH/);
  const approved = supplied;
  // Genuine verified history for an OLDER head must not justify a newer,
  // still-signed witness head after revocation.
  await fixtures.appendDeviceRevocation(state, "trusted-1");
  manifest = state.headManifest;
  supplied = approved;
  await assert.rejects(store.get(await (async () => {
    const authorization = { ...proposal.authorization, device_id: "trusted-0",
      operation: "get", ciphertext_digest: crypto.createHash("sha256").update(data).digest(),
      manifest_revision: Number(manifest.revision),
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      expected_object_revision: 1, nonce: crypto.randomBytes(32) };
    return { scope, authorization, signature: crypto.sign(null,
      await contentAuthorizationMessageV1(authorization),
      state.actors.get(Buffer.from(manifest.devices[0].authorization_key_id).toString("hex"))) };
  })()), forbidden);
  // Absence of a source is an explicit bootstrap denial, not a fallback.
  assert.throws(() => new Zk1ProtectedObjectStore(path.join(dir, "missing.sqlite"), {
    ...settings, verifiedHistoryProvider: undefined, bootstrapNew: true,
  }), forbidden);
});

test("a bounded CAS history adapter returns private-brand owner-signed proofs, never invents a trust root", async () => {
  const state = await fixtures.createInitialState(2);
  const scope = state.scope;
  const digest = await v2.recoveryManifestDigestV2(state.baseManifest);
  const entries = [await z.encodeDeterministic(state.baseManifest),
    ...state.transitions.map((entry) => Buffer.from(entry))];
  const casClient = { async getCommittedHistory({ scope: selected }) {
    assert.deepEqual(selected, scope);
    return { headRevision: entries.length,
      headDigest: await v2.recoveryManifestDigestV2(state.headManifest),
      entries: entries.map((item) => Buffer.from(item)) };
  } };
  const provider = createZk1SignedHistoryCasProofProvider({
    casClient, trustedScope: scope,
    trustedGenesisDigest: digest,
    baseReceipt: state.baseReceipt, pinnedBaseWitness: state.pinnedWitness,
    packageEnvelopes: state.packageEnvelopes,
    nowSeconds: () => 1100,
  });
  const verified = await provider({ scope });
  assert.equal(await history.isVerifiedPublicRecoveryHistoryV2(verified), true);
  assert.equal(Number(verified.revision), entries.length);
  assert.deepEqual(verified.headDigest, await v2.recoveryManifestDigestV2(state.headManifest));
  await assert.rejects(provider({ scope: { ...scope, account_id: crypto.randomBytes(16) } }),
    /ZK1_SIGNED_HISTORY_UNVERIFIED/);
  const wrongGenesis = createZk1SignedHistoryCasProofProvider({
    casClient, trustedScope: scope,
    trustedGenesisDigest: crypto.randomBytes(32),
    baseReceipt: state.baseReceipt, pinnedBaseWitness: state.pinnedWitness,
    packageEnvelopes: state.packageEnvelopes,
    nowSeconds: () => 1100,
  });
  await assert.rejects(wrongGenesis({ scope }), /ZK1_SIGNED_HISTORY_UNVERIFIED/);
  const malicious = createZk1SignedHistoryCasProofProvider({
    casClient: { getCommittedHistory: async () => ({
      headRevision: 2, headDigest: crypto.randomBytes(32),
      entries: [entries[0], Buffer.from("nonauthoritative")] }) },
    trustedScope: scope, trustedGenesisDigest: digest, baseReceipt: state.baseReceipt,
    pinnedBaseWitness: state.pinnedWitness, packageEnvelopes: [],
    nowSeconds: () => 1100,
  });
  await assert.rejects(malicious({ scope }), /ZK1_SIGNED_HISTORY_UNVERIFIED/);
});
