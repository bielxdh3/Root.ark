"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const express = require("express");
const z = require("../src/crypto/rootark-zk-1");
const manifestV2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const historyV2 = require("../src/crypto/rootark-zk-recovery-history-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } =
  require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");
const { shareGrantMessageV1 } = require("../src/services/zk1ProtectedCiphertextSharing");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const b64 = (value) => Buffer.from(value).toString("base64url");
const wire = (value) => Object.fromEntries(Object.entries(value).map(([key, part]) =>
  [key, Buffer.isBuffer(part) ? b64(part) : part]));

test("#68: signed owner grant constrains authenticated ZK ciphertext delivery", { timeout: 90000 }, async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-issue68-zk-share-");
  const state = await fixtures.createInitialState(2);
  const scope = state.scope;
  let manifest = state.headManifest;
  let verifiedHistory = await historyV2.verifyRecoveryHistoryPublicV2({
    expectedScope: scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: state.transitions, packageEnvelopes: state.packageEnvelopes,
    now: 1400,
  });
  let now = 1400;
  let allowed = true;
  let pausedReadAdmission = null;
  const pauseNextReadAdmission = () => {
    let entered;
    let release;
    const started = new Promise((resolve) => { entered = resolve; });
    const wait = new Promise((resolve) => { release = resolve; });
    pausedReadAdmission = { entered, wait };
    return { started, release };
  };
  const witness = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const witnessProvider = {
    async freshHead({ nonce }) {
      const body = { type: "rootark-recovery-witness-head/v1",
        witness_key_id: witnessKeyId, ...scope, current_revision: manifest.revision,
        current_manifest_digest: await manifestV2.recoveryManifestDigestV2(manifest),
        witness_sequence: manifest.revision, nonce, observed_at: now,
        status: allowed ? "committed" : "pending",
        pending_reservation_id: allowed ? null : crypto.randomBytes(16) };
      return z.encodeDeterministic({ ...body, signature: crypto.sign(null,
        Buffer.concat([HEAD_DOMAIN, Buffer.from(await z.encodeDeterministic(body))]),
        witness.privateKey) });
    },
    async beginIoAdmission({ action }) {
      if (!allowed) throw Error("revoked gate");
      if (action === "get" && pausedReadAdmission) {
        const gate = pausedReadAdmission;
        pausedReadAdmission = null;
        gate.entered();
        await gate.wait;
      }
      return { admissionId: crypto.randomBytes(16), proceed: true };
    },
    async finishIoAdmission() { return { status: "completed" }; },
  };
  const filename = path.join(dir, "protected.sqlite");
  let store = new Zk1ProtectedObjectStore(filename, {
    witnessProvider, witnessPinned: { keyId: witnessKeyId, publicKey: witness.publicKey },
    trustedScope: scope, bootstrapNew: true, admissionRequired: true,
    signedHistoryRequired: true,
    signedHistoryGenesisDigest: await manifestV2.recoveryManifestDigestV2(state.baseManifest),
    verifiedHistoryProvider: async () => verifiedHistory,
    minimumHead: { revision: 1, witnessSequence: 1,
      digest: await manifestV2.recoveryManifestDigestV2(state.baseManifest) },
    manifestProvider: () => z.encodeDeterministic(manifest), nowSeconds: () => now,
  });
  let server;
  const mount = async () => {
    const app = express();
    const authenticate = (req, res, next) => {
      const username = req.get("x-fixture-account");
      if (!["owner", "recipient", "attacker"].includes(username)) return res.sendStatus(401);
      req.user = { username, sessionVersion: 1 }; next();
    };
    registerZk1ProtectedObjectRoutes({ app, store, authenticate,
      requirePermission: () => (_req, _res, next) => next(),
      resolveTrustedScope: (user) => user.username === "owner" ? scope : null });
    server = await new Promise((resolve) => {
      const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
    });
    return `http://127.0.0.1:${server.address().port}`;
  };
  t.after(async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
    store.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });
  let base = await mount();
  const post = async (endpoint, username, body) => {
    const response = await fetch(base + endpoint, { method: "POST",
      headers: { "content-type": "application/json", ...(username
        ? { "x-fixture-account": username } : {}) },
      body: JSON.stringify(body) });
    const responseText = await response.text();
    let parsed;
    try { parsed = JSON.parse(responseText); } catch (_) { parsed = responseText; }
    return { status: response.status, body: parsed };
  };
  const sign = async (device, operation, objectId, revision = null, digest = null) => {
    const authorization = { ...scope, device_id: device.device_id, operation,
      object_id: objectId, expected_object_revision: revision,
      manifest_revision: manifest.revision,
      manifest_digest: await manifestV2.recoveryManifestDigestV2(manifest),
      epoch: manifest.current_epoch, nonce: crypto.randomBytes(32),
      issued_at: now - 1, expires_at: now + 30, ciphertext_digest: digest };
    const key = state.actors.get(Buffer.from(device.authorization_key_id).toString("hex"));
    return { authorization, signature: crypto.sign(null,
      await contentAuthorizationMessageV1(authorization), key), key };
  };
  const owner = manifest.devices[0];
  const recipient = manifest.devices[1];
  const id = b64(crypto.randomBytes(16));
  const ciphertext = crypto.randomBytes(256);
  const digest = crypto.createHash("sha256").update(ciphertext).digest();
  const put = await sign(owner, "put", id, null, digest);
  const putResponse = await post("/zk-1/v1/content/put", "owner", {
    authorization: wire(put.authorization), signatureBase64: b64(put.signature),
    ciphertextBase64: b64(ciphertext),
  });
  assert.equal(putResponse.status, 201, JSON.stringify(putResponse.body));

  const getOwner = await sign(owner, "get", id, 1, digest);
  const grantId = b64(crypto.randomBytes(32));
  const grantInput = { grantId, recipientUsername: "recipient",
    recipientDeviceId: recipient.device_id, expiresAt: now + 120 };
  const shareSignature = crypto.sign(null, await shareGrantMessageV1({
    authorization: getOwner.authorization, ...grantInput }), getOwner.key);
  const grantBody = { ...grantInput, authorization: wire(getOwner.authorization),
    signatureBase64: b64(getOwner.signature), shareSignatureBase64: b64(shareSignature) };
  assert.equal((await post("/zk-1/v1/share/grant", null, grantBody)).status, 401);
  assert.equal((await post("/zk-1/v1/share/grant", "attacker", grantBody)).status, 403);
  assert.equal((await post("/zk-1/v1/share/grant", "owner",
    { ...grantBody, recipientUsername: "attacker" })).status, 403,
  "server cannot redirect an owner-signed grant to another account");
  assert.equal((await post("/zk-1/v1/share/grant", "owner",
    { ...grantBody, expiresAt: now + 1000 })).status, 403,
  "signed expiry cannot be extended by the caller");
  assert.deepEqual((await post("/zk-1/v1/share/grant", "owner", grantBody)),
    { status: 201, body: { grantId, expiresAt: now + 120 } });
  assert.equal((await post("/zk-1/v1/share/grant", "owner", grantBody)).status, 409,
    "owner request nonce cannot mint a second grant");

  const forgedGrantId = b64(crypto.randomBytes(32));
  const forgedProof = await sign(owner, "get", id, 1, digest);
  const forgedFields = { grantId: forgedGrantId, recipientUsername: "recipient",
    recipientDeviceId: recipient.device_id, expiresAt: now + 120 };
  const forgedBody = { ...forgedFields, authorization: wire(forgedProof.authorization),
    signatureBase64: b64(forgedProof.signature),
    shareSignatureBase64: b64(crypto.sign(null, await shareGrantMessageV1({
      authorization: forgedProof.authorization, ...forgedFields,
    }), crypto.generateKeyPairSync("ed25519").privateKey)) };
  assert.equal((await post("/zk-1/v1/share/grant", "owner", forgedBody)).status, 403,
    "a valid GET proof cannot substitute an unknown grant signing key");
  const validUnconsumedSignature = crypto.sign(null, await shareGrantMessageV1({
    authorization: forgedProof.authorization, ...forgedFields,
  }), forgedProof.key);
  assert.equal((await post("/zk-1/v1/share/grant", "owner", {
    ...forgedBody, shareSignatureBase64: b64(validUnconsumedSignature),
  })).status, 201, "bad grant signature must not consume the owner authorization nonce");

  const foreignScopeProof = await sign(owner, "get", id, 1, digest);
  const forgedTenantScope = { ...foreignScopeProof.authorization,
    account_id: crypto.randomBytes(16) };
  assert.equal((await post("/zk-1/v1/share/grant", "owner", {
    ...grantBody, grantId: b64(crypto.randomBytes(32)),
    authorization: wire(forgedTenantScope),
    signatureBase64: b64(foreignScopeProof.signature),
  })).status, 403, "cross-tenant scope substitution must fail before grant persistence");

  const readAs = async (username, device = recipient, overrides = {}) => {
    const request = await sign(device, "get", id, 1, digest);
    return post("/zk-1/v1/share/read", username, { grantId,
      authorization: wire(request.authorization), signatureBase64: b64(request.signature),
      ...overrides });
  };
  assert.equal((await readAs(null)).status, 401);
  assert.equal((await readAs("attacker")).status, 403,
    "forwarding grant identifier does not authorize the wrong account");
  assert.equal((await readAs("recipient", owner)).status, 403,
    "recipient login alone cannot substitute a different device key");
  const received = await readAs("recipient");
  assert.equal(received.status, 200, JSON.stringify(received.body));
  assert.equal(received.body.revision, 1);
  assert.equal(received.body.epoch, manifest.current_epoch);
  assert.deepEqual(Buffer.from(received.body.ciphertextBase64, "base64url"), ciphertext);
  assert.equal(received.body.shareSignatureBase64, b64(shareSignature));
  assert.ok(received.body.shareStatementBase64,
    "recipient independently verifies signed scope against pre-pinned owner device key");
  const issuerPublicKey = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(owner.authorization_public_key)]), format: "der", type: "spki",
  });
  const independentStatementBytes = Buffer.from(received.body.shareStatementBase64, "base64url");
  assert.equal(crypto.verify(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/protected-ciphertext-share/v1\0", "ascii"),
    independentStatementBytes,
  ]), issuerPublicKey, Buffer.from(received.body.shareSignatureBase64, "base64url")), true,
  "independently pinned recipient verifies the origin signature from ciphertext response");
  const independentStatement = await z.decodeDeterministic(independentStatementBytes);
  assert.equal(independentStatement.recipient_username, "recipient");
  assert.equal(independentStatement.recipient_device_id, recipient.device_id);
  assert.equal(independentStatement.object_id, id);
  assert.equal(independentStatement.object_revision, 1);
  assert.deepEqual(Buffer.from(independentStatement.ciphertext_digest), digest);
  assert.equal((await readAs("recipient", recipient,
    { authorization: wire(getOwner.authorization), signatureBase64: b64(getOwner.signature) })).status, 409,
  "owner GET nonce is already consumed by granting and cannot be replayed");
  const nextCiphertext = crypto.randomBytes(200);
  const nextDigest = crypto.createHash("sha256").update(nextCiphertext).digest();
  const nextWrite = await sign(owner, "put", id, 1, nextDigest);
  assert.equal((await post("/zk-1/v1/content/put", "owner", {
    authorization: wire(nextWrite.authorization),
    signatureBase64: b64(nextWrite.signature), ciphertextBase64: b64(nextCiphertext),
  })).status, 200);
  const newerRead = await sign(recipient, "get", id, 2, nextDigest);
  assert.equal((await post("/zk-1/v1/share/read", "recipient", {
    grantId, authorization: wire(newerRead.authorization),
    signatureBase64: b64(newerRead.signature),
  })).status, 403, "a grant for revision 1 cannot silently follow revision 2");
  const historicalRead = await readAs("recipient");
  assert.equal(historicalRead.status, 200);
  assert.deepEqual(Buffer.from(historicalRead.body.ciphertextBase64, "base64url"), ciphertext,
    "the pinned historical version stays available while the object advances");
  allowed = false;
  assert.equal((await readAs("recipient")).status, 503,
    "the independent witness must approve each recipient ciphertext read");
  allowed = true;

  const expiresGrantId = b64(crypto.randomBytes(32));
  const expiringProof = await sign(owner, "get", id, 1, digest);
  const expiresGrantInput = { grantId: expiresGrantId,
    recipientUsername: "recipient", recipientDeviceId: recipient.device_id,
    expiresAt: now + 5 };
  const expiringSignature = crypto.sign(null, await shareGrantMessageV1({
    authorization: expiringProof.authorization, ...expiresGrantInput,
  }), expiringProof.key);
  const expiringCreated = await post("/zk-1/v1/share/grant", "owner", {
    ...expiresGrantInput, authorization: wire(expiringProof.authorization),
    signatureBase64: b64(expiringProof.signature),
    shareSignatureBase64: b64(expiringSignature),
  });
  assert.equal(expiringCreated.status, 201, JSON.stringify(expiringCreated.body));
  const changePersistedExpiry = store.db.prepare(
    "UPDATE zk_content_share SET expires_at=? WHERE grant_id=?");
  const readExpiring = async () => {
    const proof = await sign(recipient, "get", id, 1, digest);
    return post("/zk-1/v1/share/read", "recipient", {
      grantId: expiresGrantId, authorization: wire(proof.authorization),
      signatureBase64: b64(proof.signature),
    });
  };
  changePersistedExpiry.run(now + 3600, expiresGrantId);
  assert.equal((await readExpiring()).status, 403,
    "extending a SQLite expiry must not override the immutable owner-signed expiry");
  changePersistedExpiry.run(expiresGrantInput.expiresAt, expiresGrantId);

  const delayedRead = pauseNextReadAdmission();
  const pendingRead = readExpiring();
  try {
    await delayedRead.started;
    changePersistedExpiry.run(now + 3600, expiresGrantId);
  } finally { delayedRead.release(); }
  assert.equal((await pendingRead).status, 403,
    "an expiry overwritten while awaiting physical admission must fail before HTTP egress");
  changePersistedExpiry.run(expiresGrantInput.expiresAt, expiresGrantId);

  const expiringDuringAdmission = pauseNextReadAdmission();
  const pendingExpiry = readExpiring();
  try {
    await expiringDuringAdmission.started;
    now = expiresGrantInput.expiresAt;
  } finally { expiringDuringAdmission.release(); }
  assert.equal((await pendingExpiry).status, 403,
    "signed expiry reached during an await must reject final ciphertext emission");

  changePersistedExpiry.run(now + 3600, expiresGrantId);
  const expiredRead = await sign(recipient, "get", id, 1, digest);
  assert.equal((await post("/zk-1/v1/share/read", "recipient", {
    grantId: expiresGrantId, authorization: wire(expiredRead.authorization),
    signatureBase64: b64(expiredRead.signature),
  })).status, 403, "expired owner-signed grant fails closed despite longer SQLite expiry");
  assert.equal((await readAs("recipient")).status, 200,
    "expiring one grant cannot affect another grant for the same ciphertext");

  await fixtures.appendDeviceRevocation(state, owner.device_id);
  manifest = state.headManifest;
  verifiedHistory = await historyV2.verifyRecoveryHistoryPublicV2({
    expectedScope: scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: state.transitions, packageEnvelopes: state.packageEnvelopes,
    now,
  });
  const rotatedDenied = await readAs("recipient");
  assert.equal(rotatedDenied.status, 403, JSON.stringify(rotatedDenied.body));

  const deniedRevoke = await post("/zk-1/v1/share/revoke", "recipient", { grantId });
  assert.equal(deniedRevoke.status, 403);
  assert.equal((await readAs("recipient")).status, 403,
    "owner device revocation remains effective before explicit grant revocation");
  assert.equal((await post("/zk-1/v1/share/revoke", "owner", { grantId })).status, 200);
  assert.equal((await readAs("recipient")).status, 403);
  assert.equal((await post("/zk-1/v1/share/revoke", "owner", { grantId })).status, 200);

  // A durable share survives process restart, but revocation tombstones stay closed.
  await new Promise((resolve) => server.close(resolve)); server = null;
  store.close();
  store = new Zk1ProtectedObjectStore(filename, { witnessProvider,
    witnessPinned: { keyId: witnessKeyId, publicKey: witness.publicKey },
    trustedScope: scope, bootstrapNew: false, admissionRequired: true,
    signedHistoryRequired: true,
    signedHistoryGenesisDigest: await manifestV2.recoveryManifestDigestV2(state.baseManifest),
    verifiedHistoryProvider: async () => verifiedHistory,
    minimumHead: { revision: 1, witnessSequence: 1,
      digest: await manifestV2.recoveryManifestDigestV2(state.baseManifest) },
    manifestProvider: () => z.encodeDeterministic(manifest), nowSeconds: () => now });
  base = await mount();
  assert.equal((await readAs("recipient")).status, 403);
});
