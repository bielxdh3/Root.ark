"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const express = require("express");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const z = require("../src/crypto/rootark-zk-1");
const manifestV2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const historyV2 = require("../src/crypto/rootark-zk-recovery-history-v2");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } =
  require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } =
  require("../src/routes/zk1ProtectedObjectRoutes");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const COMMIT_DOMAIN = Buffer.from("Root.ark/zk-1/owner-physical-put-fence/v1\0");
const deny = /ZK_CONTENT_UNAVAILABLE|ZK_CONTENT_DENIED|ZK_CONTENT_IDENTITY_MISMATCH/;

test("protected physical PUT rechecks an independent signed owner generation after async admission", async (t) => {
  const folder = createPrivateAuthorityFixture("zk65-owner-physical-put-");
  const state = await fixtures.createInitialState(2);
  const scope = state.scope;
  const manifest = state.headManifest;
  const digest = await manifestV2.recoveryManifestDigestV2(manifest);
  const witness = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const operator = crypto.generateKeyPairSync("ed25519");
  const operatorKeyId = crypto.randomBytes(16);
  const foreign = crypto.generateKeyPairSync("ed25519");
  const clock = 1200;
  let generation = Number(manifest.revision);
  let allowed = true;
  let signer = operator.privateKey;
  let replayResponse = null;
  let admitted = null;
  let unlock = null;
  const scopeKey = scope.account_id.toString("hex") + ":" +
    scope.compartment_id.toString("hex") + ":" + scope.keyring_id.toString("hex");
  const witnessProvider = {
    async freshHead({ nonce }) {
      const unsigned = {
        type: "rootark-recovery-witness-head/v1", witness_key_id: witnessKeyId,
        ...scope, current_revision: manifest.revision, current_manifest_digest: digest,
        witness_sequence: manifest.revision, nonce, observed_at: clock,
        status: "committed", pending_reservation_id: null,
      };
      return z.encodeDeterministic({ ...unsigned,
        signature: crypto.sign(null, Buffer.concat([HEAD_DOMAIN,
          Buffer.from(await z.encodeDeterministic(unsigned))]), witness.privateKey) });
    },
    beginIoAdmission: async () => {
      if (admitted) {
        const enter = admitted;
        admitted = null;
        enter();
        await new Promise((resolve) => { unlock = resolve; });
      }
      return { admissionId: crypto.randomBytes(16), proceed: true };
    },
    finishIoAdmission: async () => undefined,
  };
  const signedHistory = await historyV2.verifyRecoveryHistoryPublicV2({
    expectedScope: scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: state.transitions, packageEnvelopes: state.packageEnvelopes,
    now: clock,
  });
  const policy = {
    pinnedPublicKey: operator.publicKey, pinnedKeyId: operatorKeyId,
    minimumGeneration: generation,
    readSignedHead({ nonce, deviceId, devicePublicKeySha256 }) {
      if (replayResponse) return replayResponse;
      const statement = {
        type: "rootark-zk1-owner-physical-put-fence-v1",
        signerKeyId: operatorKeyId.toString("base64url"),
        scopeKey,
        nonce: nonce.toString("base64url"),
        generation,
        manifestRevision: generation,
        manifestDigest: digest.toString("base64url"),
        deviceId, devicePublicKeySha256: devicePublicKeySha256.toString("base64url"),
        allowed, observedAt: clock,
      };
      const signature = crypto.sign(null, Buffer.concat([COMMIT_DOMAIN,
        Buffer.from(JSON.stringify(statement))]), signer);
      return { statement, signature };
    },
  };
  const filename = path.join(folder, "protected.sqlite");
  const floor = { revision: 1, witnessSequence: 1,
    digest: await manifestV2.recoveryManifestDigestV2(state.baseManifest) };
  const settings = {
    witnessProvider, witnessPinned: { keyId: witnessKeyId, publicKey: witness.publicKey },
    manifestProvider: async () => z.encodeDeterministic(manifest),
    trustedScope: scope, minimumHead: floor, signedHistoryRequired: true,
    signedHistoryGenesisDigest: floor.digest, verifiedHistoryProvider: async () => signedHistory,
    admissionRequired: true, nowSeconds: () => clock,
    physicalCommitOwnerFence: policy,
  };
  const stores = [];
  let server;
  const open = (bootstrapNew) => {
    const store = new Zk1ProtectedObjectStore(filename, { ...settings, bootstrapNew });
    stores.push(store);
    return store;
  };
  t.after(async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
    for (const store of stores) store.close();
    fs.rmSync(folder, { recursive: true, force: true, maxRetries: 10 });
  });
  let store = open(true);
  const createPut = async () => {
    const device = manifest.devices[0];
    const ciphertext = crypto.randomBytes(64);
    const authorization = { ...scope, device_id: device.device_id, operation: "put",
      object_id: crypto.randomBytes(16).toString("base64url"),
      expected_object_revision: null, manifest_revision: Number(manifest.revision),
      manifest_digest: digest, epoch: Number(manifest.current_epoch),
      nonce: crypto.randomBytes(32), issued_at: clock - 1, expires_at: clock + 30,
      ciphertext_digest: crypto.createHash("sha256").update(ciphertext).digest() };
    return { scope, authorization, ciphertext,
      signature: crypto.sign(null, await contentAuthorizationMessageV1(authorization),
        state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"))) };
  };
  const physicalWrite = async (input) => store.runWithAdmission(input, "put", (value) => value);
  let entered;
  const started = new Promise((resolve) => { entered = resolve; });
  admitted = entered;
  const revoked = physicalWrite(await createPut());
  await started;
  // Signed owner revocation becomes authoritative AFTER initial device/history
  // verification but BEFORE the asynchronous witness grants physical access.
  generation += 1;
  allowed = false;
  unlock();
  await assert.rejects(revoked, deny);
  assert.equal(store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 0);
  allowed = true; // ABA: old device signature remains valid but generation changed.
  await assert.rejects(physicalWrite(await createPut()), deny);
  assert.equal(store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 0);
  generation = Number(manifest.revision);
  signer = foreign.privateKey;
  await assert.rejects(physicalWrite(await createPut()), deny, "foreign operator signature");
  signer = operator.privateKey;
  replayResponse = policy.readSignedHead({
    nonce: crypto.randomBytes(32), deviceId: manifest.devices[0].device_id,
    devicePublicKeySha256: crypto.createHash("sha256")
      .update(manifest.devices[0].authorization_public_key).digest(),
  });
  await assert.rejects(physicalWrite(await createPut()), deny, "old signed nonce replay");
  replayResponse = null;
  const genuine = await createPut();
  assert.deepEqual(await physicalWrite(genuine),
    { id: genuine.authorization.object_id, revision: 1 });
  assert.equal(store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 1);
  // Exercise the canonical HTTP ingress, including the physical put under
  // admission while revocation wins during the delayed witness handshake.
  const app = express();
  app.use(express.json({ limit: "7mb" }));
  registerZk1ProtectedObjectRoutes({
    app, store, authenticate: (req, _res, next) => {
      req.user = { username: "owner", sessionVersion: 1 };
      next();
    }, requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => scope,
  });
  server = await new Promise((resolve) => {
    const running = app.listen(0, "127.0.0.1", () => resolve(running));
  });
  const send = (input) => fetch(
    `http://127.0.0.1:${server.address().port}/zk-1/v1/content/put`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        authorization: Object.fromEntries(Object.entries(input.authorization)
          .map(([key, value]) => [key, Buffer.isBuffer(value)
            ? value.toString("base64url") : value])),
        signatureBase64: input.signature.toString("base64url"),
        ciphertextBase64: input.ciphertext.toString("base64url"),
      }),
    });
  const accepted = await send(await createPut());
  assert.equal(accepted.status, 201);
  let enteredHttp;
  const httpAdmission = new Promise((resolve) => { enteredHttp = resolve; });
  admitted = enteredHttp;
  const deniedRequest = send(await createPut());
  await httpAdmission;
  generation += 1;
  allowed = false;
  unlock();
  const rejectedHttp = await deniedRequest;
  assert.equal(rejectedHttp.status, 503);
  assert.deepEqual(await rejectedHttp.json(), { error: "ZK_CONTENT_UNAVAILABLE" });
  assert.equal(store.db.prepare("SELECT COUNT(*) AS n FROM zk_content_object").get().n, 2);
  store.close();
  store = open(false);
  await assert.rejects(physicalWrite(await createPut()), deny, "revocation after restart");
  store.close();
  assert.throws(() => new Zk1ProtectedObjectStore(filename, {
    ...settings, bootstrapNew: false, physicalCommitOwnerFence: undefined,
  }), deny, "restart cannot silently disable pinned external owner fence");
  assert.throws(() => new Zk1ProtectedObjectStore(filename, {
    ...settings, bootstrapNew: false, physicalCommitOwnerFence: {
      ...policy, pinnedPublicKey: foreign.publicKey,
    },
  }), deny, "restart cannot replace independently pinned operator signer");
});
