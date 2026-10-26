"use strict";

const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const express = require("express");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const history = require("../src/crypto/rootark-zk-recovery-history-v2");
const fixture = require("./support/issue-65-recovery-v2-fixtures");
const { auditZk1CatalogReendorsement } = require("../src/services/zk1CatalogReendorsement");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } =
  require("../src/services/zk1ProtectedObjectStore");
const { Zk1OpaqueCatalog, catalogOperationObjectId, catalogHeaderMessage,
  catalogHeadDigest, catalogPageDigest, catalogCasDomain } =
  require("../src/services/zk1OpaqueCatalog");
const { sealZk1CatalogMetadataV1, openZk1CatalogMetadataV1 } =
  require("../src/crypto/rootark-zk1-opaque-catalog-client-v1");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");

const b64 = (x) => Buffer.from(x).toString("base64url");
const sha = (x) => crypto.createHash("sha256").update(x).digest();
const witnessDomain = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");

test("catalog transition retains exactly each archived metadata AEAD and ciphertext version", async () => {
  const id = b64(crypto.randomBytes(16));
  const old = { object_id: id, revision: 1, epoch: 1,
    ciphertext_digest: sha(Buffer.from("sealed")), metadata_ciphertext: crypto.randomBytes(284) };
  const next = { object_id: id, revision: 2, epoch: 2,
    ciphertext_digest: sha(Buffer.from("renamed")), metadata_ciphertext: crypto.randomBytes(284) };
  const physical = [
    { id, revision: 1, epoch: 1, ciphertext: Buffer.from("sealed"), ciphertext_digest: old.ciphertext_digest },
    { id, revision: 2, epoch: 2, ciphertext: Buffer.from("renamed"), ciphertext_digest: next.ciphertext_digest },
  ];
  const ok = (entries, rows = physical) => auditZk1CatalogReendorsement({
    previousPages: [[old]], proposedPages: [entries], physicalVersions: rows });
  assert.equal(ok([old, next]), true, "new rename revision keeps original AAD/metadata intact");
  const fault = (entries, rows) => assert.throws(() => ok(entries, rows),
    /ZK_CATALOG_CONFLICT/);
  fault([next]);
  fault([{ ...old, metadata_ciphertext: crypto.randomBytes(284) }, next]);
  fault([{ ...old, epoch: 2 }, next]);
  fault([{ ...old, ciphertext_digest: crypto.randomBytes(32) }, next]);
  fault([old, next, next]);
  fault([old, next], physical.slice(0, 1));
  fault([old, next], [{ ...physical[0], ciphertext: Buffer.from("altered") }, physical[1]]);
  fault([old, next], [{ ...physical[0], epoch: 2 }, physical[1]]);
});

test("revoked former signer cannot read or recommit; ACTIVE device re-endorses immutable historical pages through independent CAS", async (t) => {
  const dir = createPrivateAuthorityFixture("zk1-catalog-endorse-");
  const state = await fixture.createInitialState(2);
  const scope = state.scope;
  const witnessKey = crypto.generateKeyPairSync("ed25519");
  const catalogKey = crypto.generateKeyPairSync("ed25519");
  const witnessId = crypto.randomBytes(16);
  let manifest = state.headManifest;
  let clock = 1100;
  let casSeq = 0;
  let casDigest = Buffer.alloc(32);
  let proof = await verifyHistory();
  async function verifyHistory() {
    return history.verifyRecoveryHistoryPublicV2({ expectedScope: scope,
      baseManifest: state.baseManifest, baseReceipt: state.baseReceipt,
      pinnedWitness: state.pinnedWitness, transitions: state.transitions,
      packageEnvelopes: state.packageEnvelopes, now: clock });
  }
  const witness = {
    async freshHead({ nonce }) {
      const statement = { type: "rootark-recovery-witness-head/v1", witness_key_id: witnessId,
        ...scope, current_revision: manifest.revision,
        current_manifest_digest: await v2.recoveryManifestDigestV2(manifest),
        witness_sequence: manifest.revision, nonce, observed_at: clock,
        status: "committed", pending_reservation_id: null };
      return z.encodeDeterministic({ ...statement, signature: crypto.sign(null,
        Buffer.concat([witnessDomain, Buffer.from(await z.encodeDeterministic(statement))]),
        witnessKey.privateKey) });
    },
    async beginIoAdmission() { return { admissionId: crypto.randomBytes(16), proceed: true }; },
    async finishIoAdmission() {},
  };
  const store = new Zk1ProtectedObjectStore(path.join(dir, "versions.sqlite"), {
    bootstrapNew: true, witnessProvider: witness, admissionRequired: true,
    witnessPinned: { keyId: witnessId, publicKey: witnessKey.publicKey },
    trustedScope: scope, minimumHead: { revision: 1, witnessSequence: 1,
      digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    signedHistoryRequired: true,
    signedHistoryGenesisDigest: await v2.recoveryManifestDigestV2(state.baseManifest),
    verifiedHistoryProvider: async () => proof,
    manifestProvider: async () => z.encodeDeterministic(manifest),
    nowSeconds: () => clock,
  });
  async function casReceipt(nonce) {
    const statement = { type: "rootark-zk1-opaque-catalog-cas/v1", ...scope,
      sequence: casSeq, digest: Buffer.from(casDigest), nonce: Buffer.from(nonce),
      observed_at: clock };
    return z.encodeDeterministic({ ...statement, signature: crypto.sign(null,
      Buffer.concat([catalogCasDomain, Buffer.from(await z.encodeDeterministic(statement))]),
      catalogKey.privateKey) });
  }
  const catalog = new Zk1OpaqueCatalog({ store, authority: {
    publicKey: catalogKey.publicKey,
    async readHead({ nonce }) { return casReceipt(nonce); },
    async compareAndSwap({ expectedSequence, expectedDigest, nextSequence, nextDigest, nonce }) {
      if (casSeq !== expectedSequence || !casDigest.equals(expectedDigest)
        || nextSequence !== casSeq + 1) throw Error("external CAS rejected fork");
      casSeq = nextSequence;
      casDigest = Buffer.from(nextDigest);
      return casReceipt(nonce);
    },
  } });
  const app = express();
  app.use(express.json({ limit: "7mb" }));
  registerZk1ProtectedObjectRoutes({ app, store, opaqueCatalog: catalog,
    authenticate: (req, res, next) => req.get("x-session") === "authenticated"
      ? (req.user = { trusted: true }, next()) : res.sendStatus(401),
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: (user) => user.trusted ? scope : null });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  async function post(endpoint, data) {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${endpoint}`, {
      method: "POST", headers: { "content-type": "application/json", "x-session": "authenticated" },
      body: JSON.stringify(data) });
    return { status: response.status, json: await response.json() };
  }
  const device = (index) => manifest.devices[index];
  const key = (index) => state.actors.get(
    Buffer.from(device(index).authorization_key_id).toString("hex"));
  async function signed(index, operation, objectId, revision, contentDigest) {
    const auth = { ...scope, device_id: device(index).device_id,
      operation, object_id: objectId, expected_object_revision: revision,
      manifest_revision: Number(manifest.revision),
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      epoch: Number(manifest.current_epoch), nonce: crypto.randomBytes(32),
      issued_at: clock, expires_at: clock + 30, ciphertext_digest: contentDigest };
    const signature = crypto.sign(null, await contentAuthorizationMessageV1(auth), key(index));
    const wire = Object.fromEntries(Object.entries(auth).map(([field, value]) => [field,
      Buffer.isBuffer(value) || value instanceof Uint8Array ? b64(value) : value]));
    return { authorization: wire, signatureBase64: b64(signature) };
  }
  const objectId = b64(crypto.randomBytes(16));
  const metadataKey = crypto.randomBytes(32);
  const sealed1 = crypto.randomBytes(96);
  const digest1 = sha(sealed1);
  const archivedEpoch = Number(manifest.current_epoch);
  const metadata1 = await sealZk1CatalogMetadataV1({ scope, objectId, revision: 1,
    epoch: archivedEpoch, metadataKey, name: "hidden/private/account.txt" });
  assert.equal((await post("/zk-1/v1/content/put", {
    ...await signed(0, "put", objectId, null, digest1),
    ciphertextBase64: b64(sealed1) })).status, 201);
  const row1 = { object_id: objectId, revision: 1, epoch: archivedEpoch,
    ciphertext_digest: digest1, metadata_ciphertext: metadata1 };
  function buildPages(pages) {
    return pages.map((page) => page.map((row) => ({ objectId: row.object_id,
      revision: row.revision, epoch: row.epoch, ciphertextDigestBase64: b64(row.ciphertext_digest),
      metadataCiphertextBase64: b64(row.metadata_ciphertext) })));
  }
  async function commit(index, pages, options = {}) {
    const sequence = options.sequence ?? casSeq + 1;
    const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
      sequence, previous_digest: options.previousDigest || Buffer.from(casDigest),
      manifest_revision: Number(manifest.revision),
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      epoch: Number(manifest.current_epoch), signer_device_id: device(index).device_id,
      total_count: pages.flat().length,
      page_digests: await Promise.all(pages.map(catalogPageDigest)), issued_at: clock };
    const signature = crypto.sign(null, await catalogHeaderMessage(header), key(index));
    return { ...await signed(index, "catalog-commit", catalogOperationObjectId(scope, "catalog-commit"),
      options.revision === undefined ? casSeq || null : options.revision,
      catalogHeadDigest(Buffer.from(await z.encodeDeterministic(header)), signature)),
    headerBase64: b64(await z.encodeDeterministic(header)),
    headerSignatureBase64: b64(signature), pages: buildPages(pages) };
  }
  async function read(index) {
    return { ...await signed(index, "catalog-read",
      catalogOperationObjectId(scope, "catalog-read", 0), casSeq, casDigest), pageIndex: 0 };
  }
  assert.equal((await post("/zk-1/v1/catalog/commit", await commit(0, [[row1]]))).status, 201);
  await fixture.appendDeviceRevocation(state, "trusted-0");
  manifest = state.headManifest;
  proof = await verifyHistory();
  assert.equal((await post("/zk-1/v1/catalog/read", await read(0))).status, 403,
    "revoked device PoP is denied independently of catalog state");
  assert.equal((await post("/zk-1/v1/catalog/read", await read(1))).status, 403,
    "old revoked catalog signer cannot be treated as presently active");
  assert.equal((await post("/zk-1/v1/catalog/commit", await commit(0, [[row1]]))).status, 403);
  const badMetadata = { ...row1, metadata_ciphertext: crypto.randomBytes(284) };
  assert.equal((await post("/zk-1/v1/catalog/commit", await commit(1, [[badMetadata]]))).status, 409);
  assert.equal((await post("/zk-1/v1/catalog/commit", await commit(1, []))).status, 409);
  assert.equal((await post("/zk-1/v1/catalog/commit", await commit(1, [[row1]], {
    previousDigest: crypto.randomBytes(32) }))).status, 409);
  assert.equal((await post("/zk-1/v1/catalog/commit", await commit(1, [[row1]], {
    sequence: 1, revision: null }))).status, 409);
  const proposal = await commit(1, [[row1]]);
  const successor = await post("/zk-1/v1/catalog/commit", proposal);
  assert.equal(successor.status, 201, JSON.stringify(successor.json));
  assert.equal(successor.json.sequence, 2);
  assert.equal((await post("/zk-1/v1/catalog/commit", proposal)).status, 409,
    "persisted nonce and independent CAS exclude replay");
  const resumed = await post("/zk-1/v1/catalog/read", await read(1));
  assert.equal(resumed.status, 200, JSON.stringify(resumed.json));
  assert.equal(resumed.json.entries[0].epoch, archivedEpoch);
  assert.equal(resumed.json.entries[0].metadataCiphertextBase64, b64(metadata1));
  assert.equal(await openZk1CatalogMetadataV1({ scope, objectId, revision: 1,
    epoch: archivedEpoch, metadataKey, ciphertext: metadata1 }), "hidden/private/account.txt");
  await assert.rejects(openZk1CatalogMetadataV1({ scope, objectId, revision: 1,
    epoch: Number(manifest.current_epoch), metadataKey, ciphertext: metadata1 }),
  /ZK_CATALOG_UNVERIFIED/, "historic metadata must use original AEAD epoch");
  const sealed2 = crypto.randomBytes(96);
  const digest2 = sha(sealed2);
  const metadata2 = await sealZk1CatalogMetadataV1({ scope, objectId, revision: 2,
    epoch: Number(manifest.current_epoch), metadataKey, name: "hidden/private/renamed.txt" });
  assert.equal((await post("/zk-1/v1/content/put", {
    ...await signed(1, "put", objectId, 1, digest2), ciphertextBase64: b64(sealed2) })).status, 200);
  const row2 = { object_id: objectId, revision: 2, epoch: Number(manifest.current_epoch),
    ciphertext_digest: digest2, metadata_ciphertext: metadata2 };
  assert.equal(await openZk1CatalogMetadataV1({ scope, objectId, revision: 2,
    epoch: row2.epoch, metadataKey, ciphertext: metadata2 }), "hidden/private/renamed.txt");
  assert.equal((await post("/zk-1/v1/catalog/commit", await commit(1, [[row1, row2]]))).status, 201,
    "new authenticated version and its revised AEAD AAD remain legal");
  assert.equal((await post("/zk-1/v1/catalog/commit", await commit(1,
    [[{ ...row1, metadata_ciphertext: metadata2 }, row2]]))).status, 409);
  const readWithFork = await read(1);
  casSeq = 1;
  assert.equal((await post("/zk-1/v1/catalog/read", readWithFork)).status, 503,
    "independent authority rollback is rejected before page egress");
  casSeq = 3;
  assert.equal((await post("/zk-1/v1/catalog/read", await read(1))).status, 200);
  const unauthorized = await fetch(`http://127.0.0.1:${server.address().port}/zk-1/v1/catalog/read`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(await read(1)),
  });
  assert.equal(unauthorized.status, 401, "expired or missing session never receives catalog pages");
  // A logical tombstone must never conceal missing or replaced historical
  // ciphertext. Simulate a compromised SQLite writer in a disposable store:
  // the signed catalog head remains unchanged and the version count matches.
  const archived = store.db.prepare(
    "SELECT ciphertext,ciphertext_digest FROM zk_content_version WHERE id=? AND revision=1"
  ).get(objectId);
  assert.ok(archived?.ciphertext?.length > 0);
  store.db.exec("DROP TRIGGER zk_content_version_no_update");
  const replaced = crypto.randomBytes(archived.ciphertext.length);
  store.db.prepare("UPDATE zk_content_version SET ciphertext=? WHERE id=? AND revision=1")
    .run(replaced, objectId);
  assert.equal((await post("/zk-1/v1/catalog/read", await read(1))).status, 503,
    "replaced historical ciphertext fails despite matching row count");
  store.db.prepare("UPDATE zk_content_version SET ciphertext_digest=? WHERE id=? AND revision=1")
    .run(sha(replaced), objectId);
  assert.equal((await post("/zk-1/v1/catalog/read", await read(1))).status, 503,
    "rewritten ciphertext and self-consistent digest cannot override signed archive");
  store.db.prepare("UPDATE zk_content_version SET ciphertext=?,ciphertext_digest=? WHERE id=? AND revision=1")
    .run(archived.ciphertext, archived.ciphertext_digest, objectId);
  store.db.exec(`CREATE TRIGGER zk_content_version_no_update BEFORE UPDATE ON zk_content_version
    BEGIN SELECT RAISE(ABORT,'ZK_CONTENT_VERSION_IMMUTABLE'); END`);
  assert.equal((await post("/zk-1/v1/catalog/read", await read(1))).status, 200,
    "original historical ciphertext remains recoverable after damage repair");
  // AUDIT ONLY: reproduce a compromised SQLite writer racing the asynchronous
  // decode after the physical-version check but before catalog page egress.
  const originalPhysicalVerify = catalog.verifyPhysicalVersions.bind(catalog);
  const originalDecode = z.decodeDeterministic;
  let physicalCheckPassed = false;
  let changedAfterPhysicalCheck = false;
  catalog.verifyPhysicalVersions = (...args) => {
    originalPhysicalVerify(...args);
    physicalCheckPassed = true;
  };
  z.decodeDeterministic = async (...args) => {
    const decoded = await originalDecode(...args);
    if (physicalCheckPassed && !changedAfterPhysicalCheck) {
      changedAfterPhysicalCheck = true;
      store.db.exec("DROP TRIGGER zk_content_version_no_update");
      store.db.prepare("UPDATE zk_content_version SET ciphertext=? WHERE id=? AND revision=1")
        .run(replaced, objectId);
    }
    return decoded;
  };
  let raced;
  try { raced = await post("/zk-1/v1/catalog/read", await read(1)); }
  finally {
    z.decodeDeterministic = originalDecode;
    catalog.verifyPhysicalVersions = originalPhysicalVerify;
    if (changedAfterPhysicalCheck) {
      store.db.prepare("UPDATE zk_content_version SET ciphertext=? WHERE id=? AND revision=1")
        .run(archived.ciphertext, objectId);
      store.db.exec(`CREATE TRIGGER zk_content_version_no_update BEFORE UPDATE ON zk_content_version
        BEGIN SELECT RAISE(ABORT,'ZK_CONTENT_VERSION_IMMUTABLE'); END`);
    }
  }
  assert.equal(changedAfterPhysicalCheck, true, "attack fires only after successful physical inventory verification");
  assert.equal(raced.status, 503,
    "RED: corrupted ciphertext after physical check must not allow catalog page egress");
  // Corrupt a disposable archived page despite the SQLite immutability trigger:
  // even matching external CAS cannot cause the service to endorse it again.
  const originalPage = store.db.prepare(
    "SELECT body FROM zk_content_catalog_page WHERE sequence=1 AND page=0").get().body;
  store.db.exec("DROP TRIGGER zk_catalog_page_no_update");
  store.db.prepare("UPDATE zk_content_catalog_page SET body=? WHERE sequence=1")
    .run(Buffer.from(await z.encodeDeterministic([{ ...row1, metadata_ciphertext: crypto.randomBytes(284) }])));
  assert.equal((await post("/zk-1/v1/catalog/read", await read(1))).status, 503);
  store.db.prepare("UPDATE zk_content_catalog_page SET body=? WHERE sequence=1")
    .run(originalPage);
  store.db.exec("DROP TRIGGER zk_catalog_snapshot_no_update");
  store.db.prepare("UPDATE zk_content_catalog_snapshot SET signature=? WHERE sequence=1")
    .run(crypto.randomBytes(64));
  assert.equal((await post("/zk-1/v1/catalog/read", await read(1))).status, 503,
    "a forged historical Ed25519 head fails even after current signer re-endorses");
});
