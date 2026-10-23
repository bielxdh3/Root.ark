"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const express = require("express");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const history = require("../src/crypto/rootark-zk-recovery-history-v2");
const fixture = require("./support/issue-65-recovery-v2-fixtures");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } =
  require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } =
  require("../src/routes/zk1ProtectedObjectRoutes");
const { Zk1OpaqueCatalog, catalogOperationObjectId, catalogHeaderMessage,
  catalogHeadDigest, catalogPageDigest, catalogCasDomain } =
  require("../src/services/zk1OpaqueCatalog");
const { verifyZk1OpaqueCatalogPage, sealZk1CatalogMetadataV1,
  openZk1CatalogMetadataV1 } =
  require("../src/crypto/rootark-zk1-opaque-catalog-client-v1");

const WITNESS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const digest = (bytes) => crypto.createHash("sha256").update(bytes).digest();

test("ZK1 opaque catalog: two owner-enrolled device sessions enumerate signed versions and GET; no names, stale/forged/missing/replay/rollback rejected", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-opaque-catalog-"));
  const state = await fixture.createInitialState(2);
  let manifest = state.headManifest;
  let clock = 1100;
  const scope = state.scope;
  const w = crypto.generateKeyPairSync("ed25519");
  const authorityKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const signedHistory = async () => history.verifyRecoveryHistoryPublicV2({
    expectedScope: scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: state.transitions, packageEnvelopes: state.packageEnvelopes, now: clock,
  });
  let proof = await signedHistory();
  let admissions = 0;
  const witnessProvider = {
    async freshHead({ nonce }) {
      const base = { type: "rootark-recovery-witness-head/v1", witness_key_id: witnessKeyId,
        ...scope, current_revision: manifest.revision,
        current_manifest_digest: await v2.recoveryManifestDigestV2(manifest),
        witness_sequence: manifest.revision, nonce, observed_at: clock,
        status: "committed", pending_reservation_id: null };
      return z.encodeDeterministic({ ...base, signature: crypto.sign(null,
        Buffer.concat([WITNESS_DOMAIN, Buffer.from(await z.encodeDeterministic(base))]),
        w.privateKey) });
    },
    async beginIoAdmission() {
      if (admissions) throw Error("active witness gate");
      admissions += 1;
      return { admissionId: crypto.randomBytes(16), proceed: true };
    },
    async finishIoAdmission() { admissions -= 1; },
  };
  const store = new Zk1ProtectedObjectStore(path.join(dir, "content.sqlite"), {
    bootstrapNew: true, witnessProvider, admissionRequired: true,
    witnessPinned: { keyId: witnessKeyId, publicKey: w.publicKey },
    trustedScope: scope, minimumHead: { revision: 1, witnessSequence: 1,
      digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    signedHistoryRequired: true,
    signedHistoryGenesisDigest: await v2.recoveryManifestDigestV2(state.baseManifest),
    verifiedHistoryProvider: async () => proof,
    manifestProvider: async () => z.encodeDeterministic(manifest),
    nowSeconds: () => clock,
  });
  let sequence = 0;
  let currentDigest = Buffer.alloc(32);
  let failCAS = false;
  const signedCas = async (nonce) => {
    const statement = { type: "rootark-zk1-opaque-catalog-cas/v1", ...scope,
      sequence, digest: Buffer.from(currentDigest), nonce: Buffer.from(nonce),
      observed_at: clock };
    return z.encodeDeterministic({ ...statement, signature: crypto.sign(null,
      Buffer.concat([catalogCasDomain, Buffer.from(await z.encodeDeterministic(statement))]),
      authorityKeys.privateKey) });
  };
  const authority = {
    publicKey: authorityKeys.publicKey,
    async readHead({ nonce }) { return signedCas(nonce); },
    async compareAndSwap({ expectedSequence, expectedDigest, nextSequence, nextDigest, nonce }) {
      if (failCAS || expectedSequence !== sequence || !expectedDigest.equals(currentDigest)
        || nextSequence !== sequence + 1) throw Error("CAS conflict");
      sequence = nextSequence;
      currentDigest = Buffer.from(nextDigest);
      return signedCas(nonce);
    },
  };
  const catalog = new Zk1OpaqueCatalog({ store, authority });
  const app = express();
  app.use(express.json({ limit: "7mb" }));
  const authenticate = (req, res, next) => {
    if (req.get("x-session") !== "authenticated") return res.sendStatus(401);
    req.user = { username: "owner" };
    next();
  };
  registerZk1ProtectedObjectRoutes({ app, store, opaqueCatalog: catalog,
    authenticate, requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: (user) => user.username === "owner" ? scope : null });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const send = async (url, body, authorized = true) => {
    const response = await fetch(origin + url, { method: "POST",
      headers: { "content-type": "application/json",
        ...(authorized ? { "x-session": "authenticated" } : {}) },
      body: JSON.stringify(body) });
    const raw = await response.text();
    let json;
    try { json = JSON.parse(raw); } catch (_) { json = { raw }; }
    return { status: response.status, json };
  };
  const device = (index) => manifest.devices[index];
  const privateKey = (index) => state.actors.get(
    Buffer.from(device(index).authorization_key_id).toString("hex"));
  const signed = async (index, operation, id, revision, ciphertextDigest) => {
    const auth = { ...scope, device_id: device(index).device_id,
      operation, object_id: id, expected_object_revision: revision,
      manifest_revision: Number(manifest.revision),
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      epoch: Number(manifest.current_epoch), nonce: crypto.randomBytes(32),
      issued_at: clock, expires_at: clock + 30, ciphertext_digest: ciphertextDigest };
    return { authorization: auth, signature: crypto.sign(null,
      await contentAuthorizationMessageV1(auth), privateKey(index)) };
  };
  const wire = (request) => ({
    authorization: Object.fromEntries(Object.entries(request.authorization).map(([k, v]) =>
      ["account_id", "compartment_id", "keyring_id", "manifest_digest", "nonce",
        "ciphertext_digest"].includes(k) && v !== null ? [k, b64(v)] : [k, v])),
    signatureBase64: b64(request.signature),
  });
  const id = crypto.randomBytes(16).toString("base64url");
  const sealed = crypto.randomBytes(90);
  const filename = "financial/private/file.txt";
  const metadataKey = crypto.randomBytes(32);
  const encryptedName = await sealZk1CatalogMetadataV1({
    scope, objectId: id, revision: 1, epoch: Number(manifest.current_epoch),
    metadataKey, name: filename });
  const write = await signed(0, "put", id, null, digest(sealed));
  assert.equal((await send("/zk-1/v1/content/put", { ...wire(write),
    ciphertextBase64: b64(sealed) })).status, 201);
  const entries = [[{ object_id: id, revision: 1, epoch: Number(manifest.current_epoch),
    ciphertext_digest: digest(sealed), metadata_ciphertext: encryptedName }]];
  const build = async (index, usedEntries = entries, parent = currentDigest, seq = sequence + 1) => {
    const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
      sequence: seq, previous_digest: Buffer.from(parent),
      manifest_revision: Number(manifest.revision),
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      epoch: Number(manifest.current_epoch),
      signer_device_id: device(index).device_id,
      total_count: usedEntries.flat().length,
      page_digests: await Promise.all(usedEntries.map(catalogPageDigest)), issued_at: clock };
    const signature = crypto.sign(null, await catalogHeaderMessage(header), privateKey(index));
    const headBytes = Buffer.from(await z.encodeDeterministic(header));
    const requestedDigest = catalogHeadDigest(headBytes, signature);
    const auth = await signed(index, "catalog-commit",
      catalogOperationObjectId(scope, "catalog-commit"),
      sequence === 0 ? null : sequence, requestedDigest);
    return { ...wire(auth), headerBase64: b64(headBytes),
      headerSignatureBase64: b64(signature), pages: usedEntries.map((page) =>
        page.map((e) => ({ objectId: e.object_id, revision: e.revision,
          epoch: e.epoch, ciphertextDigestBase64: b64(e.ciphertext_digest),
          metadataCiphertextBase64: b64(e.metadata_ciphertext) }))) };
  };
  const commit = await build(0);
  assert.equal((await send("/zk-1/v1/catalog/commit", commit, false)).status, 401);
  const created = await send("/zk-1/v1/catalog/commit", commit);
  assert.equal(created.status, 201, JSON.stringify(created.json));
  assert.equal(created.json.sequence, 1);
  assert.equal(admissions, 0);
  assert.equal((await send("/zk-1/v1/catalog/commit", commit)).status, 409,
    "same device nonce is persistently consumed");
  const requestRead = async (index, indexPage = 0, digestOverride = currentDigest) =>
    wire(await signed(index, "catalog-read", catalogOperationObjectId(scope, "catalog-read", indexPage),
      sequence, digestOverride));
  const firstRead = await requestRead(1);
  const read = await send("/zk-1/v1/catalog/read", { ...firstRead, pageIndex: 0 });
  assert.equal(read.status, 200, JSON.stringify(read.json));
  assert.equal(read.json.totalCount, 1);
  assert.equal(read.json.entries[0].objectId, id);
  assert.equal(read.json.entries[0].ciphertextDigestBase64, b64(digest(sealed)));
  assert.ok(!JSON.stringify(read.json).includes(filename));
  const ownerNonce = crypto.randomBytes(32);
  const ownerWitnessRaw = await witnessProvider.freshHead({ scope, nonce: ownerNonce });
  const verify = async (response) => verifyZk1OpaqueCatalogPage({
    response, expectedScope: scope, verifiedOwnerHistory: proof,
    pinnedOwnerGenesisDigest: await v2.recoveryManifestDigestV2(state.baseManifest),
    ownerWitnessRaw, ownerWitnessNonce: ownerNonce,
    pinnedOwnerWitness: { keyId: witnessKeyId, publicKey: w.publicKey },
    minimumOwnerHead: { revision: 1, witnessSequence: 1,
      digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    catalogNonce: Buffer.from(firstRead.authorization.nonce, "base64url"),
    pinnedCatalogAuthorityKey: authorityKeys.publicKey,
    minimumCatalogHead: { sequence: 0, digest: Buffer.alloc(32) },
    nowSeconds: clock,
  });
  const trusted = await verify(read.json);
  assert.equal(trusted.entries[0].objectId, id);
  assert.deepEqual(trusted.entries[0].ciphertextDigest, digest(sealed));
  assert.equal(await openZk1CatalogMetadataV1({ scope, objectId: id,
    revision: 1, epoch: Number(manifest.current_epoch), metadataKey,
    ciphertext: trusted.entries[0].metadataCiphertext }), filename);
  await assert.rejects(openZk1CatalogMetadataV1({ scope, objectId: id,
    revision: 2, epoch: Number(manifest.current_epoch), metadataKey,
    ciphertext: trusted.entries[0].metadataCiphertext }), /ZK_CATALOG_UNVERIFIED/);
  await assert.rejects(verify({ ...read.json,
    totalCount: read.json.totalCount - 1 }), /ZK_CATALOG_UNVERIFIED/);
  await assert.rejects(verify({ ...read.json, entries: read.json.entries.map(
    (e) => ({ ...e, ciphertextDigestBase64: b64(crypto.randomBytes(32)) })) }),
  /ZK_CATALOG_UNVERIFIED/);
  await assert.rejects(verify({ ...read.json,
    authorityProofBase64: b64(crypto.randomBytes(128)) }), /ZK_CATALOG_UNVERIFIED/);
  // Second-device independently verifies the entire public catalog page
  // against signer, page digest, and separately signed CAS head.
  const signedHead = await z.decodeDeterministic(Buffer.from(read.json.headerBase64, "base64url"));
  assert.equal(crypto.verify(null, await catalogHeaderMessage(signedHead),
    crypto.createPublicKey({ key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(manifest.devices[0].authorization_public_key)]), format: "der", type: "spki" }),
    Buffer.from(read.json.headerSignatureBase64, "base64url")), true);
  assert.deepEqual(await catalogPageDigest(entries[0]), Buffer.from(signedHead.page_digests[0]));
  const witnessed = await z.decodeDeterministic(Buffer.from(read.json.authorityProofBase64, "base64url"));
  const { signature: authoritySig, ...statement } = witnessed;
  assert.equal(crypto.verify(null, Buffer.concat([catalogCasDomain,
    Buffer.from(await z.encodeDeterministic(statement))]),
  authorityKeys.publicKey, authoritySig), true);
  assert.equal(witnessed.sequence, read.json.sequence);
  const signedGet = await signed(1, "get", id, 1, digest(sealed));
  const fetched = await send("/zk-1/v1/content/read", wire(signedGet));
  assert.equal(fetched.status, 200);
  assert.deepEqual(Buffer.from(fetched.json.ciphertextBase64, "base64url"), sealed);
  assert.equal((await send("/zk-1/v1/catalog/read", { ...firstRead, pageIndex: 0 })).status, 409);
  const wrongPage = await requestRead(1, 1);
  assert.equal((await send("/zk-1/v1/catalog/read",
    { ...wrongPage, pageIndex: 0 })).status, 403,
  "a signed catalog page challenge cannot be redirected to a different page");
  const omitted = await build(0, []);
  assert.equal((await send("/zk-1/v1/catalog/commit", omitted)).status, 409);
  const forged = await build(0);
  forged.headerSignatureBase64 = b64(crypto.randomBytes(64));
  assert.equal((await send("/zk-1/v1/catalog/commit", forged)).status, 403);
  const wrongScope = await build(0);
  wrongScope.authorization.compartment_id = b64(Buffer.from("other-compartment"));
  assert.equal((await send("/zk-1/v1/catalog/commit", wrongScope)).status, 403);
  const corrupted = await build(0);
  corrupted.pages[0][0].ciphertextDigestBase64 = b64(crypto.randomBytes(32));
  assert.equal((await send("/zk-1/v1/catalog/commit", corrupted)).status, 403);
  const previousSequence = sequence;
  const rolledBack = await requestRead(1);
  sequence = 0; currentDigest = Buffer.alloc(32);
  assert.equal((await send("/zk-1/v1/catalog/read", { ...rolledBack, pageIndex: 0 })).status, 503);
  sequence = previousSequence; currentDigest = Buffer.from(created.json.catalogDigest, "base64url");
  const deniedMissingDigest = await requestRead(1, 0, crypto.randomBytes(32));
  assert.equal((await send("/zk-1/v1/catalog/read", { ...deniedMissingDigest, pageIndex: 0 })).status, 409);
  failCAS = true;
  const competing = await build(1);
  assert.equal((await send("/zk-1/v1/catalog/commit", competing)).status, 503);
  failCAS = false;
  await fixture.appendDeviceRevocation(state, "trusted-0");
  manifest = state.headManifest;
  proof = await signedHistory();
  const afterRevocation = await requestRead(1);
  assert.equal((await send("/zk-1/v1/catalog/read",
    { ...afterRevocation, pageIndex: 0 })).status, 403,
  "a revoked catalog signer cannot silently remain trusted in the active epoch");
  // Concurrent authorized devices can propose the same next revision, but
  // the external CAS admits only one; the surviving ACTIVE device can re-sign
  // the unchanged historical inventory after a revocation.
  const proposalA = await build(1);
  const proposalB = await build(1);
  const transitions = await Promise.all([
    send("/zk-1/v1/catalog/commit", proposalA),
    send("/zk-1/v1/catalog/commit", proposalB),
  ]);
  assert.equal(transitions.filter((v) => v.status === 201).length, 1);
  assert.equal(transitions.filter((v) => [409, 503].includes(v.status)).length, 1);
  assert.equal(sequence, 2);
  const resumed = await requestRead(1);
  assert.equal((await send("/zk-1/v1/catalog/read", { ...resumed,
    pageIndex: 0 })).status, 200);
});
