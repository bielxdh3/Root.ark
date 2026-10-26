"use strict";

const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
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
const { sealZk1CatalogMetadataV1 } =
  require("../src/crypto/rootark-zk1-opaque-catalog-client-v1");

const b64 = (v) => Buffer.from(v).toString("base64url");
const hash = (v) => crypto.createHash("sha256").update(v).digest();
const WITNESS = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const GRANT_DOMAIN = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const GRANT_FIELDS = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key",
  "manifest_revision", "manifest_digest", "current_epoch",
  "enrolled_epoch", "revoked_at_epoch"];
const modules = ["rootark-zk1-file-content", "rootark-zk1-ciphertext-chunk-root",
  "rootark-zk1-ciphertext-download-integrity",
  "rootark-zk1-owner-ciphertext-root-checkpoint",
  "rootark-zk1-protected-http-client", "rootark-zk1-uncertain-put-reconciliation",
  "rootark-zk1-normal-browser-content", "rootark-zk1-browser-catalog",
  "rootark-zk1-browser-opaque-catalog-commit", "rootark-zk1-client-rename-move"];

function indexedDb() {
  const values = new Map();
  let initialized = false;
  return { open() {
    const request = {};
    const db = { close() {},
      objectStoreNames: { contains() { return initialized; } },
      createObjectStore() { initialized = true; },
      transaction(_name, mode) {
        const tx = { oncomplete: null, onabort: null, onerror: null,
          abort() { queueMicrotask(() => tx.onabort?.()); },
          objectStore() { return {
            get(key) {
              const r = { result: undefined };
              queueMicrotask(() => {
                r.result = values.get(key);
                r.onsuccess?.();
                queueMicrotask(() => tx.oncomplete?.());
              });
              return r;
            },
            put(value, key) {
              assert.equal(mode, "readwrite");
              values.set(key, structuredClone(value));
            },
          }; },
        };
        return tx;
      },
    };
    request.result = db;
    queueMicrotask(() => {
      if (!initialized) request.onupgradeneeded?.();
      queueMicrotask(() => request.onsuccess?.());
    });
    return request;
  } };
}

for (const mode of ["committed", "post-commit-read-fail", "forged-catalog-receipt",
  "post-put-read-fail"]) test(
  "rename/move uses witnessed catalog historical GET and signed CAS PUT; "
    + mode,
  async (t) => {
  const dir = createPrivateAuthorityFixture("zk1-client-move-");
  const state = await fixture.createInitialState(2);
  const manifest = state.headManifest, scope = state.scope, now = 1100;
  const witness = crypto.generateKeyPairSync("ed25519");
  const owner = crypto.generateKeyPairSync("ed25519");
  const casKey = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const ownerHead = { revision: Number(manifest.revision),
    digest: await v2.recoveryManifestDigestV2(manifest),
    epoch: Number(manifest.current_epoch) };
  const sourceId = b64(crypto.randomBytes(16));
  const scopeWire = Object.fromEntries(Object.entries(scope).map(([k, v]) => [k, b64(v)]));
  const sourceMetadata = { ...scopeWire, object_id: sourceId,
    version_id: b64(crypto.randomBytes(16)), parent_version_id: null,
    epoch: ownerHead.epoch, kind: "file" };
  const signedHistory = await history.verifyRecoveryHistoryPublicV2({
    expectedScope: scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: state.transitions, packageEnvelopes: state.packageEnvelopes, now,
  });
  const witnessProvider = {
    async freshHead({ nonce }) {
      const data = { type: "rootark-recovery-witness-head/v1",
        witness_key_id: witnessKeyId, ...scope,
        current_revision: manifest.revision, current_manifest_digest: ownerHead.digest,
        witness_sequence: manifest.revision, nonce, observed_at: now,
        status: "committed", pending_reservation_id: null };
      return z.encodeDeterministic({ ...data, signature: crypto.sign(null,
        Buffer.concat([WITNESS, Buffer.from(await z.encodeDeterministic(data))]),
        witness.privateKey) });
    },
    async beginIoAdmission() { return { admissionId: crypto.randomBytes(16), proceed: true }; },
    async finishIoAdmission() { return { status: "FINISHED" }; },
  };
  const store = new Zk1ProtectedObjectStore(path.join(dir, "content.sqlite"), {
    bootstrapNew: true, witnessProvider, admissionRequired: true,
    witnessPinned: { keyId: witnessKeyId, publicKey: witness.publicKey },
    trustedScope: scope, minimumHead: { revision: 1, witnessSequence: 1,
      digest: await v2.recoveryManifestDigestV2(state.baseManifest) },
    signedHistoryRequired: true, signedHistoryGenesisDigest:
      await v2.recoveryManifestDigestV2(state.baseManifest),
    verifiedHistoryProvider: async () => signedHistory,
    manifestProvider: async () => z.encodeDeterministic(manifest),
    nowSeconds: () => now,
  });
  let sequence = 0, casDigest = Buffer.alloc(32), puts = 0, reads = 0;
  const casStatement = async (nonce) => {
    const data = { type: "rootark-zk1-opaque-catalog-cas/v1", ...scope,
      sequence, digest: Buffer.from(casDigest), nonce: Buffer.from(nonce), observed_at: now };
    return z.encodeDeterministic({ ...data, signature: crypto.sign(null,
      Buffer.concat([catalogCasDomain, Buffer.from(await z.encodeDeterministic(data))]),
      casKey.privateKey) });
  };
  const authority = { publicKey: casKey.publicKey,
    async readHead({ nonce }) { return casStatement(nonce); },
    async compareAndSwap({ expectedSequence, expectedDigest, nextSequence, nextDigest, nonce }) {
      if (expectedSequence !== sequence || !expectedDigest.equals(casDigest)
        || nextSequence !== sequence + 1) throw Error("CAS collision");
      sequence = nextSequence; casDigest = Buffer.from(nextDigest);
      return casStatement(nonce);
    },
  };
  const app = express();
  app.use(express.json({ limit: "7mb" }));
  app.use((req, _res, next) => {
    if (req.path === "/zk-1/v1/content/put") puts++;
    if (req.path === "/zk-1/v1/content/read") reads++;
    next();
  });
  registerZk1ProtectedObjectRoutes({ app, store,
    opaqueCatalog: new Zk1OpaqueCatalog({ store, authority }),
    authenticate: (req, res, next) => {
      if (req.get("x-session") !== "yes") return res.sendStatus(401);
      req.user = { username: "owner" }; next();
    },
    requirePermission: () => (_req, _res, next) => next(),
    resolveTrustedScope: () => scope,
  });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    store.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  });
  const origin = "http://127.0.0.1:" + server.address().port;
  let active = true, csrf = "csrf-a", lostPut = false, lostCatalogAck = false;
  let forgeCatalogReceipt = false, failReadAfterPut = false;
  let failReadAfterPutThreshold = Number.MAX_SAFE_INTEGER;
  let switchDuringGet = null, catalogCommits = 0;
  const fetchImpl = async (url, options) => {
    if (!active || csrf !== "csrf-a") throw Error("session switched");
    if (failReadAfterPut && url.endsWith("/content/read")
      && puts > failReadAfterPutThreshold)
      throw Error("signed GET failed after accepted ciphertext PUT");
    const response = await fetch(url, { ...options,
      headers: { ...options.headers, "x-session": "yes", "x-csrf-token": csrf } });
    if (switchDuringGet && url.endsWith("/content/read")) {
      if (switchDuringGet === "logout") active = false;
      if (switchDuringGet === "csrf") csrf = "csrf-b";
      switchDuringGet = null;
    }
    if (lostPut && url.endsWith("/content/put")) {
      await response.arrayBuffer();
      throw Error("ACK dropped after durable server handler");
    }
    if (url.endsWith("/catalog/commit")) {
      catalogCommits++;
      if (forgeCatalogReceipt) {
        const forged = await response.json();
        return new Response(JSON.stringify({ ...forged,
          authorityProofBase64: b64(crypto.randomBytes(64)) }), {
          status: response.status,
          headers: { "content-type": "application/json" },
        });
      }
      if (lostCatalogAck) {
        await response.arrayBuffer();
        lostCatalogAck = false;
        throw Error("catalog ACK dropped after CAS");
      }
    }
    return response;
  };
  const send = async (url, body) => {
    const response = await fetchImpl(origin + url,
      { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(body) });
    return { status: response.status, result: await response.json() };
  };
  // Exercise the exact UMD modules as deployed to browsers, with only a
  // synthetic owner-floor IndexedDB implementation for this isolated fixture.
  const runtime = { crypto: crypto.webcrypto, TextEncoder, TextDecoder, console,
    AbortController, setTimeout, clearTimeout,
    btoa, atob, URL, Headers, structuredClone, queueMicrotask,
    location: { origin }, RootarkZk1NormalBrowserTrustFloor: {
      async assertCurrent({ signedDeviceGrant, pinnedCurrentHead }) {
        assert.equal(signedDeviceGrant.manifest_digest, b64(pinnedCurrentHead.digest));
      },
    },
  };
  vm.createContext(runtime);
  for (const name of modules) vm.runInContext(fs.readFileSync(path.join(__dirname,
    "../public/client/" + name + ".js"), "utf8"), runtime, { filename: name });
  // A browser naturally creates its inputs in one JS realm. VM fixtures have
  // to do this explicitly to exercise the strict own-prototype validation.
  const asRealm = vm.runInContext("(json) => JSON.parse(json)", runtime);
  const realm = (value) => asRealm(JSON.stringify(value));
  const file = runtime.RootarkZk1FileContent;
  const originalCek = await file.generateFileCek();
  const payload = Buffer.from("never available to server: inventory secret 12345");
  const originalCiphertext = Buffer.from(await file.encryptFile({
    cek: originalCek, metadata: realm(sourceMetadata), name: "original.txt",
    mediaType: "text/plain", data: payload }));
  const signerDevice = manifest.devices[0];
  const signerPair = state.actors.get(
    Buffer.from(signerDevice.authorization_key_id).toString("hex"));
  const signerKey = await crypto.webcrypto.subtle.importKey("pkcs8",
    signerPair.export({ type: "pkcs8", format: "der" }), "Ed25519", false, ["sign"]);
  const devicePublicKey = await crypto.webcrypto.subtle.importKey("raw",
    signerDevice.authorization_public_key, "Ed25519", true, ["verify"]);
  const ownerPublicRaw = owner.publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const ownerPublicKey = await crypto.webcrypto.subtle.importKey("raw",
    ownerPublicRaw, "Ed25519", true, ["verify"]);
  const grantBody = { schema: "rootark-zk1-browser-owner-device-grant/v1",
    ...scopeWire, device_id: signerDevice.device_id,
    authorization_key_id: b64(signerDevice.authorization_key_id),
    authorization_public_key: b64(signerDevice.authorization_public_key),
    manifest_revision: ownerHead.revision,
    manifest_digest: b64(ownerHead.digest), current_epoch: ownerHead.epoch,
    enrolled_epoch: Number(signerDevice.enrolled_epoch),
    revoked_at_epoch: signerDevice.revoked_at_epoch };
  const signedDeviceGrant = { ...grantBody,
    signature: b64(crypto.sign(null, Buffer.concat([GRANT_DOMAIN,
      Buffer.from(JSON.stringify(Object.fromEntries(GRANT_FIELDS.map((field) =>
        [field, grantBody[field]]))))]), owner.privateKey)) };
  const trust = { ownerPublicKey, pinnedOwnerKeyHash: hash(ownerPublicRaw),
    independentOwnerSpkiSha256: hash(owner.publicKey.export({ type: "spki", format: "der" })),
    pinnedCurrentHead: ownerHead, signedDeviceGrant,
    ownerHistoryCheckpoint: { independentFixture: true },
    previousOwnerHistoryProof: null };
  const rawSigner = async (operation, objectId, revision, ciphertextDigest) => {
    const auth = { ...scope, device_id: signerDevice.device_id, operation,
      object_id: objectId, expected_object_revision: revision,
      manifest_revision: ownerHead.revision, manifest_digest: ownerHead.digest,
      epoch: ownerHead.epoch, nonce: crypto.randomBytes(32),
      issued_at: now, expires_at: now + 30, ciphertext_digest: ciphertextDigest };
    const signature = crypto.sign(null, await contentAuthorizationMessageV1(auth), signerPair);
    return { authorization: Object.fromEntries(Object.entries(auth).map(([k, v]) =>
      ["account_id", "compartment_id", "keyring_id", "manifest_digest",
        "nonce", "ciphertext_digest"].includes(k) && v !== null ? [k, b64(v)] : [k, v])),
    signatureBase64: b64(signature) };
  };
  const firstPut = await rawSigner("put", sourceId, null, hash(originalCiphertext));
  assert.equal((await send("/zk-1/v1/content/put",
    { ...firstPut, ciphertextBase64: b64(originalCiphertext) })).status, 201);
  const sealedMetadataKey = crypto.randomBytes(32);
  const encryptedCatalogName = await sealZk1CatalogMetadataV1({
    scope, objectId: sourceId, revision: 1, epoch: ownerHead.epoch,
    metadataKey: sealedMetadataKey, name: "original.txt" });
  const page = [{ object_id: sourceId, revision: 1, epoch: ownerHead.epoch,
    ciphertext_digest: hash(originalCiphertext),
    metadata_ciphertext: encryptedCatalogName }];
  const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
    sequence: 1, previous_digest: Buffer.alloc(32),
    manifest_revision: ownerHead.revision, manifest_digest: ownerHead.digest,
    epoch: ownerHead.epoch, signer_device_id: signerDevice.device_id,
    total_count: 1, page_digests: [await catalogPageDigest(page)], issued_at: now };
  const rawHead = Buffer.from(await z.encodeDeterministic(header));
  const headerSignature = crypto.sign(null, await catalogHeaderMessage(header), signerPair);
  const headerDigest = catalogHeadDigest(rawHead, headerSignature);
  const commitAuth = await rawSigner("catalog-commit",
    catalogOperationObjectId(scope, "catalog-commit"), null, headerDigest);
  const committed = await send("/zk-1/v1/catalog/commit", {
    ...commitAuth, headerBase64: b64(rawHead), headerSignatureBase64: b64(headerSignature),
    pages: [[{ objectId: sourceId, revision: 1, epoch: ownerHead.epoch,
      ciphertextDigestBase64: b64(hash(originalCiphertext)),
      metadataCiphertextBase64: b64(encryptedCatalogName) }]],
  });
  assert.equal(committed.status, 201, JSON.stringify(committed.result));
  const authorityKey = await crypto.webcrypto.subtle.importKey("raw",
    casKey.publicKey.export({ type: "spki", format: "der" }).subarray(-32),
    "Ed25519", true, ["verify"]);
  const assertLive = () => { if (!active || csrf !== "csrf-a") throw Error("LOGOUT"); };
  const snapshot = await runtime.RootarkZk1BrowserCatalog.openCatalog({
    trust, signerGrant: signedDeviceGrant, devicePrivateKey: signerKey,
    catalogAuthorityKey: authorityKey,
    independentAuthoritySpkiHash: hash(casKey.publicKey.export({
      type: "spki", format: "der" })),
    pinnedCatalogHead: { sequence: 1, digest: committed.result.catalogDigest },
    origin: origin + "/", fetchImpl, assertLive, indexedDBImpl: indexedDb(),
    nowSeconds: () => now,
  });
  assert.equal(snapshot.totalCount, 1);
  const folder = b64(crypto.randomBytes(16));
  const options = Object.assign(realm({}), { catalog: snapshot, sourceIndex: 0,
    sourceMetadata: realm(sourceMetadata),
    sourceCek: originalCek, destinationName: "renamed.txt",
    destinationParentFolderId: folder, ...trust,
    devicePublicKey, devicePrivateKey: signerKey, origin: origin + "/",
    fetchImpl, nowSeconds: () => now, assertLive });
  const archiveKey = await crypto.webcrypto.subtle.generateKey({ name: "AES-GCM", length: 256 },
    false, ["encrypt", "decrypt"]);
  const archiveRecords = new Map();
  let failArchiveWrite = false, corruptArchiveRead = false, failJournalWrite = false;
  let forgeReceipt = false;
  const archive = {
    async write({ metadata, objectRevision, ciphertext, ciphertextDigest, cek }) {
      assert.ok([...intents.values()].some((intent) => intent.body.writes.some((write) =>
        write.objectId === metadata.object_id && write.revision === objectRevision
        && write.ciphertextDigest === b64(ciphertextDigest))),
      "signed durable intent must precede first CEK escrow side effect");
      if (failArchiveWrite) throw Error("archive unavailable");
      assert.equal(metadata.object_id, sourceId);
      assert.equal(objectRevision, 2);
      assert.deepEqual(hash(ciphertext), Buffer.from(ciphertextDigest));
      const iv = crypto.randomBytes(12);
      const aad = Buffer.from(JSON.stringify(metadata));
      const sealed = Buffer.from(await crypto.webcrypto.subtle.encrypt({
        name: "AES-GCM", iv, additionalData: aad }, archiveKey, cek));
      const id = b64(crypto.randomBytes(16));
      archiveRecords.set(id, { iv, aad, sealed });
      return forgeReceipt ? "forged-invalid-receipt" : id;
    },
    async read({ receiptId, metadata, objectRevision, ciphertextDigest }) {
      assert.equal(objectRevision, 2);
      assert.equal(ciphertextDigest.length, 32);
      const record = archiveRecords.get(receiptId);
      assert.ok(record);
      assert.equal(record.aad.toString(), JSON.stringify(metadata));
      const raw = new Uint8Array(await crypto.webcrypto.subtle.decrypt({
        name: "AES-GCM", iv: record.iv, additionalData: record.aad,
      }, archiveKey, record.sealed));
      if (corruptArchiveRead) raw[0] ^= 1;
      return raw;
    },
  };
  const intents = new Map();
  const journalStore = {
    async write(id, value) {
      if (failJournalWrite) throw Error("journal unavailable");
      if (intents.has(id)) throw Error("journal collision");
      intents.set(id, structuredClone(value));
    },
    async read(id) { return intents.has(id) ? realm(intents.get(id)) : undefined; },
    async remove(id) { intents.delete(id); },
  };
  const writerFactory = async () => {
    const publicWitness = await crypto.webcrypto.subtle.importKey("raw",
      witness.publicKey.export({ type: "spki", format: "der" }).subarray(-32),
      "Ed25519", false, ["verify"]);
    return runtime.RootarkZk1BrowserOpaqueCatalogCommit.createClient(Object.assign(realm({}), {
      origin: origin + "/", fetchImpl, ownerPublicKey, pinnedOwnerKeyHash: trust.pinnedOwnerKeyHash,
      pinnedOwnerHead: Object.assign(realm({}), { revision: ownerHead.revision,
        digest: ownerHead.digest, epoch: ownerHead.epoch }),
      signedDeviceGrant: realm(signedDeviceGrant), devicePublicKey, devicePrivateKey: signerKey,
      signerGrants: realm([signedDeviceGrant]),
      ownerWitnessPublicKey: publicWitness, ownerWitnessKeyId: witnessKeyId,
      ownerWitnessProbe: async ({ nonce }) => witnessProvider.freshHead({ nonce: Buffer.from(nonce) }),
      catalogAuthorityPublicKey: authorityKey,
      catalogProbe: async ({ nonce }) => authority.readHead({ nonce: Buffer.from(nonce) }),
      minimumCatalogHead: Object.assign(realm({}), { sequence: 1,
        digest: Buffer.from(committed.result.catalogDigest, "base64url") }),
      csrfToken: () => csrf, isSessionCurrent: () => active,
      assertCurrent: async () => assertLive(), nowSeconds: () => now, journalStore,
    }));
  };
  const metadataKey = await crypto.webcrypto.subtle.importKey("raw", sealedMetadataKey,
    "AES-GCM", false, ["encrypt"]);
  const composed = async () => Object.assign(realm({}), options, {
    catalogWriter: await writerFactory(), metadataKey, cekArchive: archive,
  });
  let noPutBefore = puts;
  for (const unsafe of [
    { origin: "http://localhost:" + server.address().port + "/" },
    { origin: origin + "/zk-1/v1/content/put" },
  ]) {
    await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMove(
      Object.assign(realm({}), options, unsafe)), /ZK_CLIENT_RENAME_MOVE_DENIED/,
    "cross-origin and path injection denied without an HTTP PUT");
    assert.equal(puts, noPutBefore);
  }
  for (const unsafe of [
    { nowSeconds: () => now - 100 },
    { fetchImpl: (url, request) => fetch(url, request) },
  ]) {
    await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMove(
      Object.assign(realm({}), options, unsafe)), /ZK_CLIENT_RENAME_MOVE_DENIED/,
    "expired signed authorization and unauthenticated HTTP requests are rejected");
  }
  // Unauthorized/expired requests may reach the route, but cannot commit a
  // revision. The valid CAS below must still succeed from predecessor 1.
  noPutBefore = puts;
  await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMove(Object.assign(
    realm({}), options, { sourceMetadata: realm({ ...sourceMetadata,
      version_id: b64(crypto.randomBytes(16)), epoch: ownerHead.epoch + 1 }) })),
  /ZK_CLIENT_RENAME_MOVE_DENIED/);
  assert.equal(puts, noPutBefore);
  for (const transition of ["logout", "csrf"]) {
    switchDuringGet = transition;
    await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMove(options),
      /ZK_CLIENT_RENAME_MOVE_DENIED/, transition + " after signed GET");
    assert.equal(puts, noPutBefore, "fenced GET must not reach PUT");
    active = true; csrf = "csrf-a";
  }
  const fakeCatalog = Object.assign(realm({}), snapshot);
  await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMove(
    Object.assign(realm({}), options, { catalog: fakeCatalog })),
  /ZK_CLIENT_RENAME_MOVE_DENIED/, "forged, unbranded catalog rejected");
  assert.equal(puts, noPutBefore);
  await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMove(
    Object.assign(realm({}), options, { signedDeviceGrant: realm({
      ...signedDeviceGrant, revoked_at_epoch: ownerHead.epoch }) })),
  /ZK_CLIENT_RENAME_MOVE_DENIED/, "revoked or edited owner grant refused");
  assert.equal(puts, noPutBefore);
  failArchiveWrite = true;
  const intentBeforeArchiveFailure = intents.size;
  await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMoveCommitted(await composed()),
    (error) => error.code === "ZK_CLIENT_RENAME_MOVE_ARCHIVE_UNCERTAIN"
      && error.outcome.retrySafe === false
      && intents.has(error.outcome.journalId), "uncertain archive retains prior signed intent");
  assert.equal(puts, noPutBefore);
  assert.equal(intents.size, intentBeforeArchiveFailure + 1);
  failArchiveWrite = false;
  corruptArchiveRead = true;
  await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMoveCommitted(await composed()),
    /ZK_CLIENT_RENAME_MOVE_ARCHIVE_UNCERTAIN/,
    "archive ACK with mismatching recovered CEK denied");
  assert.equal(puts, noPutBefore);
  corruptArchiveRead = false;
  forgeReceipt = true;
  await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMoveCommitted(await composed()),
    /ZK_CLIENT_RENAME_MOVE_/, "forged archive receipt denied before PUT");
  assert.equal(puts, noPutBefore);
  forgeReceipt = false;
  failJournalWrite = true;
  const archivesBeforeRejectedJournal = archiveRecords.size;
  await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMoveCommitted(await composed()),
    /ZK_CLIENT_RENAME_MOVE_DENIED/, "missing durable intent must precede PUT");
  assert.equal(puts, noPutBefore);
  assert.equal(archiveRecords.size, archivesBeforeRejectedJournal,
    "failed durable journal must never create external CEK escrow");
  failJournalWrite = false;
  const probeWriter = await writerFactory();
  assert.equal((await probeWriter.readAll()).rows.length, 1);
  lostPut = mode !== "post-put-read-fail";
  lostCatalogAck = mode !== "post-put-read-fail" && mode !== "forged-catalog-receipt";
  forgeCatalogReceipt = mode === "forged-catalog-receipt";
  failReadAfterPut = mode === "post-put-read-fail";
  failReadAfterPutThreshold = puts;
  const pendingBeforeCommit = intents.size;
  const committedInput = await composed();
  if (mode === "post-put-read-fail") {
    let pendingJournalId = null;
    await assert.rejects(
      runtime.RootarkZk1ClientRenameMove.renameOrMoveCommitted(committedInput), (error) => {
        assert.equal(error.code, "ZK_CLIENT_RENAME_MOVE_PUT_UNCERTAIN");
        assert.equal(error.outcome.retrySafe, false);
        assert.equal(error.outcome.ciphertextPutMayHaveCommitted, true);
        assert.equal(error.outcome.revision, 2);
        assert.ok(intents.has(error.outcome.journalId));
        pendingJournalId = error.outcome.journalId;
        return true;
      }, "a failed signed GET after PUT must retain the journal and prohibit retries");
    failReadAfterPut = false;
    assert.equal(puts, noPutBefore + 1);
    assert.equal(catalogCommits, 1, "no catalog commit without complete ciphertext readback");
    assert.equal(intents.size, pendingBeforeCommit + 1);
    const plannedDigest = Buffer.from(intents.get(pendingJournalId).body.writes[0]
      .ciphertextDigest, "base64url");
    const signed = await rawSigner("get", sourceId, 2, plannedDigest);
    assert.equal((await send("/zk-1/v1/content/read", signed)).status, 200,
      "remote immutable revision survived the failed client GET");
    return;
  }
  if (mode === "post-commit-read-fail") {
    const writer = committedInput.catalogWriter;
    let reads = 0;
    committedInput.catalogWriter = { ...writer, async readAll() {
      if (++reads === 2) throw Error("post-CAS signed read unavailable");
      return writer.readAll();
    } };
    await assert.rejects(
      runtime.RootarkZk1ClientRenameMove.renameOrMoveCommitted(committedInput), (error) => {
        assert.equal(error.code, "ZK_CLIENT_RENAME_MOVE_COMMIT_UNCERTAIN");
        assert.equal(error.outcome.retrySafe, false);
        assert.equal(error.outcome.revision, 2);
        assert.equal(error.outcome.signedCatalogReadbackVerified, false);
        assert.match(error.outcome.journalId, /^[A-Za-z0-9_-]{43}$/);
        return true;
      }, "a committed CAS with lost final readback preserves its reconciliation journal");
    assert.equal(sequence, 2, "the server and external authority really committed");
    assert.equal(catalogCommits, 2, "catalog commit must not retry");
    assert.equal(puts, noPutBefore + 1, "ciphertext PUT must not retry");
    assert.equal(intents.size, pendingBeforeCommit + 1, "journal survives uncertain commit");
    const [journalId] = [...intents.keys()].filter((id) => ![...intents.keys()]
      .slice(0, pendingBeforeCommit).includes(id));
    assert.equal(await (await writerFactory()).confirmPendingIntent(journalId), true,
      "explicit fresh authority/ciphertext proof recovers lost post-commit readback");
    assert.equal(intents.size, pendingBeforeCommit);
    return;
  }
  const result = await runtime.RootarkZk1ClientRenameMove.renameOrMoveCommitted(committedInput);
  lostPut = false;
  assert.equal(result.revision, 2);
  assert.equal(result.lostPutAckReconciled, true);
  assert.equal(result.sourceHistoricalVersionPreserved, true);
  assert.equal(result.metadata.parent_version_id, sourceMetadata.version_id);
  assert.notEqual(result.metadata.version_id, sourceMetadata.version_id);
  assert.equal(result.requiresExternalCekArchive, false);
  assert.equal(result.metadataCatalogCommitPending, false);
  assert.equal(result.cekArchiveReadbackVerified, true);
  assert.equal(result.signedCatalogCommitReadbackVerified, true);
  assert.equal(result.catalogSequence, 2);
  assert.equal(result.archivePhysicalDurabilityProven, false);
  assert.equal(result.durableExternalCommitVerified, false);
  assert.equal(result.authorizesCutover, false);
  assert.equal(intents.size, pendingBeforeCommit,
    "successful commit removes only its own intent after independent confirmation");
  assert.equal(catalogCommits, 2, "initial commit plus one signed CAS, never a retry");
  assert.equal(archiveRecords.size, 3, "archive precedes every attempted PUT");
  assert.notEqual(result.destinationCek, originalCek, "fresh CEK for each version");
  assert.equal(puts, noPutBefore + 1, "uncertain ACK must not retry PUT");
  assert.ok(reads >= 3, "historical source GET, uncertain ACK GET, final GET");
  const oldRead = await rawSigner("get", sourceId, 1, hash(originalCiphertext));
  const historical = await send("/zk-1/v1/content/read", oldRead);
  assert.equal(historical.status, 200);
  assert.equal(historical.result.ciphertextBase64, b64(originalCiphertext));
  const oldOpened = await file.decryptFile({ cek: originalCek, metadata: realm(sourceMetadata),
    envelopeBytes: originalCiphertext });
  assert.equal(oldOpened.name, "original.txt");
  assert.deepEqual(Buffer.from(oldOpened.data), payload);
  const newRead = await rawSigner("get", sourceId, 2,
    Buffer.from(result.ciphertextDigestBase64, "base64url"));
  const current = await send("/zk-1/v1/content/read", newRead);
  assert.equal(current.status, 200);
  assert.ok(!JSON.stringify(current.result).includes("renamed.txt"));
  assert.ok(!JSON.stringify(current.result).includes(folder));
  assert.ok(!JSON.stringify(current.result).includes(payload.toString()));
  const opened = await file.decryptFile({ cek: result.destinationCek,
    metadata: result.metadata,
    envelopeBytes: Buffer.from(current.result.ciphertextBase64, "base64url") });
  assert.equal(opened.name, "renamed.txt");
  assert.equal(opened.parentFolderId, folder);
  assert.deepEqual(Buffer.from(opened.data), payload);
  for (const wrong of [{ ...result.metadata, version_id: sourceMetadata.version_id },
    { ...result.metadata, parent_version_id: null },
    { ...result.metadata, epoch: result.metadata.epoch + 1 }]) {
    await assert.rejects(file.decryptFile({ cek: result.destinationCek,
      metadata: realm(wrong),
      envelopeBytes: Buffer.from(current.result.ciphertextBase64, "base64url") }),
    /ZK_FILE_INVALID/, "new AEAD binds version, predecessor and epoch");
  }
  opened.data.fill(0); oldOpened.data.fill(0);
  const beforeDenied = puts;
  await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMove(options),
    /ZK_CLIENT_RENAME_MOVE_DENIED/, "stale revision fails closed");
  assert.equal(puts, beforeDenied + 1, "stale CAS may reach endpoint but cannot commit");
  active = false;
  await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMove(options),
    /ZK_CLIENT_RENAME_MOVE_DENIED/, "logout fences new GET and any PUT");
  assert.equal(puts, beforeDenied + 1);
  active = true; csrf = "csrf-b";
  await assert.rejects(runtime.RootarkZk1ClientRenameMove.renameOrMove(options),
    /ZK_CLIENT_RENAME_MOVE_DENIED/, "CSRF/session change rejects");
  assert.equal(puts, beforeDenied + 1);
});
