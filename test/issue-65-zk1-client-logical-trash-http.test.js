"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
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
  "rootark-zk1-client-rename-move", "rootark-zk1-browser-opaque-catalog-commit",
  "rootark-zk1-client-logical-trash"];

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

test("DEV logical trash/restore: signed current catalog, new AEAD/CEK, archival readback, HTTP CAS and signed catalog head", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-client-move-"));
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
  let switchDuringGet = null;
  const fetchImpl = async (url, options) => {
    if (!active || csrf !== "csrf-a") throw Error("session switched");
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
    if (lostCatalogAck && url.endsWith("/catalog/commit")) {
      await response.arrayBuffer();
      throw Error("catalog ACK dropped after independently witnessed commit");
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
  const runtime = { crypto: crypto.webcrypto, TextEncoder, TextDecoder, AbortController,
    btoa, atob, URL, Headers, structuredClone, queueMicrotask, setTimeout, clearTimeout,
    location: { origin }, RootarkZk1NormalBrowserTrustFloor: {
      async assertCurrent({ signedDeviceGrant, pinnedCurrentHead }) {
        assert.equal(signedDeviceGrant.manifest_digest, b64(pinnedCurrentHead.digest));
      },
    },
  };
  vm.createContext(runtime);
  for (const name of modules) {
    let source = fs.readFileSync(path.join(__dirname,
      "../public/client/" + name + ".js"), "utf8");
    if (name === "rootark-zk1-browser-opaque-catalog-commit") {
      source = source.replace('throw new Error("ZK_BROWSER_CATALOG_UNVERIFIED")',
        'throw new Error("ZK_BROWSER_CATALOG_UNVERIFIED: " + new Error().stack)');
      source = source.replace('try { return await readAll(); } catch (_) { deny(); }',
        'try { return await readAll(); } catch (error) { throw error; }');
    }
    if (name === "rootark-zk1-client-logical-trash") {
      source = source.replace('} catch (_) { deny(); }\n      finally {\n        sourceBytes',
        '} catch (error) { throw new Error("ZK_LOGICAL_TRASH_DENIED: " + error.stack); }\n      finally {\n        sourceBytes');
      source = source.replace('throw new Error("ZK_LOGICAL_TRASH_DENIED")',
        'throw new Error("ZK_LOGICAL_TRASH_DENIED: " + new Error().stack)');
    }
    vm.runInContext(source, runtime, { filename: name });
  }
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
  const noPutBefore = puts;
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
  lostPut = true;
  const result = await runtime.RootarkZk1ClientRenameMove.renameOrMove(options);
  lostPut = false;
  assert.equal(result.revision, 2);
  assert.equal(result.lostPutAckReconciled, true);
  assert.equal(result.sourceHistoricalVersionPreserved, true);
  assert.equal(result.metadata.parent_version_id, sourceMetadata.version_id);
  assert.notEqual(result.metadata.version_id, sourceMetadata.version_id);
  assert.equal(result.requiresExternalCekArchive, true);
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

  active = true; csrf = "csrf-a";
  const metadataKey = await crypto.webcrypto.subtle.importKey("raw", crypto.randomBytes(32),
    "AES-GCM", false, ["encrypt", "decrypt"]);
  const witnessPublicKey = await crypto.webcrypto.subtle.importKey("raw",
    witness.publicKey.export({ type: "spki", format: "der" }).subarray(-32),
    "Ed25519", true, ["verify"]);
  const archiveAuthority = crypto.generateKeyPairSync("ed25519");
  const archiveAuthorityPublicKey = await crypto.webcrypto.subtle.importKey("raw",
    archiveAuthority.publicKey.export({ type: "spki", format: "der" }).subarray(-32),
    "Ed25519", true, ["verify"]);
  const archivePrefix = Buffer.from("Root.ark/zk-1/logical-trash-archive-receipt/v1\0");
  const catalogPrefix = Buffer.from("Root.ark/zk-1/logical-trash-catalog-receipt/v1\0");
  const operableCek = async (value) => ArrayBuffer.isView(value) && value.byteLength === 32
    ? crypto.webcrypto.subtle.importKey("raw", value, "AES-GCM", false,
      ["encrypt", "decrypt"]) : value;
  const sign = (prefix, body, key) => b64(crypto.sign(null,
    Buffer.concat([prefix, Buffer.from(JSON.stringify(body))]), key));
  const archived = new Map();
  const archiveKeys = async ({ challenge, entries }) => {
    for (const name of ["account_id", "compartment_id", "keyring_id"])
      assert.equal(challenge[name], scopeWire[name], "custody receipt must bind owner scope");
    for (const entry of entries) archived.set(entry.revision, {
      cek: ArrayBuffer.isView(entry.cek) ? Buffer.from(entry.cek) : entry.cek,
      bytes: Buffer.from(entry.ciphertext), metadata: entry.metadata });
    return realm({ signatureBase64: sign(archivePrefix, challenge, archiveAuthority.privateKey) });
  };
  const readArchivedCek = async ({ account_id, compartment_id, keyring_id, revision, versionId }) => {
    assert.equal(account_id, scopeWire.account_id);
    assert.equal(compartment_id, scopeWire.compartment_id);
    assert.equal(keyring_id, scopeWire.keyring_id);
    const saved = archived.get(revision);
    if (!saved || saved.metadata.version_id !== versionId) throw Error("MISSING_ARCHIVE_CEK");
    // The lifecycle now escrows a transient raw32 for the new tombstone and
    // immediately imports it as a nonextractable CryptoKey for operations.
    return operableCek(saved.cek);
  };
  const catalogProof = async (challenge) => realm({
    signatureBase64: sign(catalogPrefix, challenge, casKey.privateKey) });
  const csrfToken = () => csrf;
  const isSessionCurrent = () => active && csrf === "csrf-a";
  const assertOfflinePin = async ({ pinnedCurrentHead }) => {
    assert.equal(pinnedCurrentHead.revision, ownerHead.revision);
    assert.deepEqual(Buffer.from(pinnedCurrentHead.digest), Buffer.from(ownerHead.digest));
    return true;
  };
  const writerJournals = [];
  const makeWriter = (seq, digest) => {
    const journal = new Map();
    writerJournals.push(journal);
    return runtime.RootarkZk1BrowserOpaqueCatalogCommit.createClient(Object.assign(realm({}), {
      origin: origin + "/", fetchImpl, ownerPublicKey,
      pinnedOwnerKeyHash: hash(ownerPublicRaw),
      pinnedOwnerHead: Object.assign(realm({}), ownerHead),
      signedDeviceGrant: realm(signedDeviceGrant), devicePublicKey,
      devicePrivateKey: signerKey, signerGrants: [realm(signedDeviceGrant)],
      ownerWitnessPublicKey: witnessPublicKey, ownerWitnessKeyId: witnessKeyId,
      ownerWitnessProbe: ({ nonce }) => witnessProvider.freshHead({ nonce: Buffer.from(nonce) }),
      catalogAuthorityPublicKey: authorityKey,
      catalogProbe: ({ nonce }) => authority.readHead({ nonce }),
      minimumCatalogHead: Object.assign(realm({}), { sequence: seq, digest }),
      csrfToken, isSessionCurrent,
      assertCurrent: () => assertOfflinePin({ pinnedCurrentHead: ownerHead }),
      nowSeconds: () => now,
      journalStore: Object.assign(realm({}), {
        write: async (id, value) => { if (journal.has(id)) throw Error("REPLAY"); journal.set(id, value); },
        read: async (id) => journal.get(id), remove: async (id) => { journal.delete(id); },
      }),
    }));
  };
  const renameBytes = Buffer.from(current.result.ciphertextBase64, "base64url");
  const renamePage = [page[0], { object_id: sourceId, revision: 2,
    epoch: ownerHead.epoch, ciphertext_digest: hash(renameBytes),
    metadata_ciphertext: await sealZk1CatalogMetadataV1({
      scope, objectId: sourceId, revision: 2, epoch: ownerHead.epoch,
      metadataKey: sealedMetadataKey, name: "renamed.txt",
    }) }];
  const renameHeader = { ...header, sequence: 2, previous_digest: headerDigest,
    total_count: 2, page_digests: [await catalogPageDigest(renamePage)] };
  const renameHeadBytes = Buffer.from(await z.encodeDeterministic(renameHeader));
  const renameSignature = crypto.sign(null, await catalogHeaderMessage(renameHeader), signerPair);
  const renameDigest = catalogHeadDigest(renameHeadBytes, renameSignature);
  const renameAuth = await rawSigner("catalog-commit",
    catalogOperationObjectId(scope, "catalog-commit"), 1, renameDigest);
  const renamedCatalog = await send("/zk-1/v1/catalog/commit", {
    ...renameAuth, headerBase64: b64(renameHeadBytes),
    headerSignatureBase64: b64(renameSignature),
    pages: [renamePage.map((entry) => ({ objectId: entry.object_id,
      revision: entry.revision, epoch: entry.epoch,
      ciphertextDigestBase64: b64(entry.ciphertext_digest),
      metadataCiphertextBase64: b64(entry.metadata_ciphertext) }))],
  });
  assert.equal(renamedCatalog.status, 201, JSON.stringify(renamedCatalog.result));
  const openCatalog = (seq, digest) => runtime.RootarkZk1BrowserCatalog.openCatalog({
    trust, signerGrant: signedDeviceGrant, devicePrivateKey: signerKey,
    catalogAuthorityKey: authorityKey,
    independentAuthoritySpkiHash: hash(casKey.publicKey.export({
      type: "spki", format: "der" })), pinnedCatalogHead: { sequence: seq, digest },
    origin: origin + "/", fetchImpl, assertLive, indexedDBImpl: indexedDb(),
    nowSeconds: () => now,
  });
  const snapshot2 = await openCatalog(2, b64(renameDigest));
  assert.equal(snapshot2.entries.length, 2);
  const base = Object.assign(realm({}), {
    catalog: snapshot2, sourceIndex: 1, sourceMetadata: result.metadata,
    sourceCek: result.destinationCek, originalIndex: null,
    originalMetadata: null, originalCek: null,
    ownerPublicKey, pinnedOwnerKeyHash: hash(ownerPublicRaw),
    pinnedCurrentHead: Object.assign(realm({}), ownerHead),
    signedDeviceGrant: realm(signedDeviceGrant), devicePublicKey,
    devicePrivateKey: signerKey, origin: origin + "/", fetchImpl,
    nowSeconds: () => now, csrfToken, isSessionCurrent, assertOfflinePin,
    catalogWriter: makeWriter(2, renameDigest),
    metadataKey, archiveKeys, readArchivedCek, archiveAuthorityPublicKey,
    catalogProof, catalogAuthorityPublicKey: authorityKey,
  });
  const trash = runtime.RootarkZk1ClientLogicalTrash;
  const beforeTrash = puts;
  assert.throws(() => trash.permanentDelete(), /ZK_LOGICAL_TRASH_DENIED/);
  await assert.rejects(trash.trash(Object.assign(realm({}), base,
    { catalog: Object.assign(realm({}), snapshot2) })), /ZK_LOGICAL_TRASH_DENIED/,
  "forged catalog snapshot");
  await assert.rejects(trash.trash(Object.assign(realm({}), base,
    { sourceIndex: 0, sourceMetadata: realm(sourceMetadata) })), /ZK_LOGICAL_TRASH_DENIED/,
  "rollback to nonlatest revision");
  await assert.rejects(trash.trash(Object.assign(realm({}), base, {
    signedDeviceGrant: realm({ ...signedDeviceGrant, revoked_at_epoch: ownerHead.epoch }),
  })), /ZK_LOGICAL_TRASH_DENIED/, "revoked owner grant");
  await assert.rejects(trash.trash(Object.assign(realm({}), base, {
    archiveKeys: async () => realm({ signatureBase64: b64(crypto.randomBytes(64)) }),
  })), /ZK_LOGICAL_TRASH_DENIED/, "forged custody receipt");
  await assert.rejects(trash.trash(Object.assign(realm({}), base, {
    archiveKeys: async ({ challenge }) => realm({ signatureBase64: sign(archivePrefix,
      { ...challenge, account_id: b64(crypto.randomBytes(16)) }, archiveAuthority.privateKey) }),
  })), /ZK_LOGICAL_TRASH_DENIED/, "cross-scope archive receipt cannot be replayed");
  await assert.rejects(trash.trash(Object.assign(realm({}), base, {
    catalogProof: async () => realm({ signatureBase64: b64(crypto.randomBytes(64)) }),
  })), /ZK_LOGICAL_TRASH_DENIED/, "unavailable unpinned catalog preflight blocks any PUT");
  await assert.rejects(trash.trash(Object.assign(realm({}), base, {
    readArchivedCek: async () => null,
  })), /ZK_LOGICAL_TRASH_DENIED/, "missing key archive");
  active = false;
  await assert.rejects(trash.trash(base), /ZK_LOGICAL_TRASH_DENIED/, "logout fence");
  active = true;
  switchDuringGet = "csrf";
  await assert.rejects(trash.trash(base), /ZK_LOGICAL_TRASH_DENIED/, "CSRF during GET");
  csrf = "csrf-a";
  assert.equal(puts, beforeTrash, "no denied preflight could write");
  lostPut = true;
  lostCatalogAck = true;
  const trashed = await trash.trash(base);
  lostPut = false;
  lostCatalogAck = false;
  assert.equal(puts, beforeTrash + 1, "uncertain ACK never repeats PUT");
  assert.equal(trashed.revision, 3);
  assert.equal(trashed.logicalStateFinalized, true);
  assert.equal(trashed.archivedCeksReadbackVerified, true);
  assert.equal(trashed.signedCatalogHeadVerified, true);
  assert.equal(trashed.uncertainPutAckReconciled, true);
  assert.equal(trashed.physicalErasureProven, false);
  assert.equal(trashed.permanentDeletionAuthorized, false);
  assert.equal(trashed.metadata.parent_version_id, result.metadata.version_id);
  const historicalAfterTrash = await send("/zk-1/v1/content/read", await rawSigner("get",
    sourceId, 2, hash(renameBytes)));
  assert.equal(historicalAfterTrash.status, 200);
  assert.equal(historicalAfterTrash.result.ciphertextBase64, b64(renameBytes));
  const tomb = await send("/zk-1/v1/content/read", await rawSigner("get",
    sourceId, 3, Buffer.from(trashed.ciphertextDigestBase64, "base64url")));
  assert.equal(tomb.status, 200);
  assert.ok(!JSON.stringify(tomb.result).includes("renamed.txt"));
  assert.ok(!JSON.stringify(tomb.result).includes(folder));
  assert.ok(!JSON.stringify(tomb.result).includes(payload.toString()));
  const wrongRootGet = await runtime.RootarkZk1ProtectedHttpClient.signProtectedContentOperation(Object.assign(realm({}), {
    signerKey, scope: realm(scopeWire), deviceId: signerDevice.device_id,
    operation: "get", objectId: sourceId, expectedObjectRevision: 3,
    manifestRevision: ownerHead.revision, manifestDigest: ownerHead.digest,
    epoch: ownerHead.epoch, nowSeconds: now, ciphertext: null,
    expectedCiphertextDigest: Buffer.from(trashed.ciphertextDigestBase64, "base64url"),
  }));
  await assert.rejects(runtime.RootarkZk1ProtectedHttpClient.postProtectedCiphertextBackupRead({
    origin: origin + "/", request: wrongRootGet, fetchImpl,
    expectedObjectRevision: 3, expectedEpoch: ownerHead.epoch,
    expectedRoot: crypto.randomBytes(32),
  }), /ZK_/, "bad ciphertext root on actual HTTP GET");
  const snapshot3 = await openCatalog(trashed.catalogSequence, trashed.catalogDigestBase64);
  assert.equal(snapshot3.entries.length, 3);
  const restoreBase = Object.assign(realm({}), base, {
    catalog: snapshot3, sourceIndex: 2, sourceMetadata: trashed.metadata,
    sourceCek: await operableCek(archived.get(3).cek), originalIndex: 1,
    originalMetadata: result.metadata, originalCek: archived.get(2).cek,
    catalogWriter: makeWriter(3, Buffer.from(trashed.catalogDigestBase64, "base64url")),
  });
  const beforeRestore = puts;
  await assert.rejects(trash.restore(Object.assign(realm({}), restoreBase, {
    originalMetadata: realm({ ...result.metadata, version_id: b64(crypto.randomBytes(16)) }),
  })), /ZK_LOGICAL_TRASH_DENIED/, "tampered tombstone parent");
  await assert.rejects(trash.restore(Object.assign(realm({}), restoreBase, {
    readArchivedCek: async ({ revision, versionId }) => revision === 2
      ? null : readArchivedCek({ revision, versionId }),
  })), /ZK_LOGICAL_TRASH_DENIED/, "missing historical key");
  assert.equal(puts, beforeRestore);
  const restored = await trash.restore(restoreBase);
  assert.equal(restored.revision, 4);
  assert.equal(restored.logicalStateFinalized, true);
  assert.equal(puts, beforeRestore + 1);
  assert.equal(restored.metadata.parent_version_id, trashed.metadata.version_id);
  const restoredRead = await send("/zk-1/v1/content/read", await rawSigner("get",
    sourceId, 4, Buffer.from(restored.ciphertextDigestBase64, "base64url")));
  assert.equal(restoredRead.status, 200);
  const openedRestore = await file.decryptFile({ cek: await operableCek(archived.get(4).cek),
    metadata: restored.metadata,
    envelopeBytes: Buffer.from(restoredRead.result.ciphertextBase64, "base64url") });
  assert.equal(openedRestore.name, "renamed.txt");
  assert.equal(openedRestore.parentFolderId, folder);
  assert.deepEqual(Buffer.from(openedRestore.data), payload);
  openedRestore.data.fill(0);
  assert.equal((await send("/zk-1/v1/content/read", await rawSigner("get",
    sourceId, 3, Buffer.from(trashed.ciphertextDigestBase64, "base64url")))).status,
  200, "historic tombstone persists after restore");
  const snapshot4 = await openCatalog(restored.catalogSequence, restored.catalogDigestBase64);
  const beforeBadFinalProof = sequence;
  let badFinalProof;
  try { await trash.trash(Object.assign(realm({}), base, {
    catalog: snapshot4, sourceIndex: 3, sourceMetadata: restored.metadata,
    sourceCek: await operableCek(archived.get(4).cek),
    catalogWriter: makeWriter(4, Buffer.from(restored.catalogDigestBase64, "base64url")),
    catalogProof: async (challenge) => realm({ signatureBase64:
      challenge.purpose === "precommit"
        ? sign(catalogPrefix, challenge, casKey.privateKey)
        : b64(crypto.randomBytes(64)) }),
  })); } catch (error) { badFinalProof = error; }
  assert.match(badFinalProof?.code || "", /ZK_LOGICAL_TRASH_COMMIT_UNCERTAIN/);
  assert.equal(sequence, beforeBadFinalProof + 1,
    "CAS head advanced even though the final catalog proof was rejected");
  assert.equal(badFinalProof.outcome.signedCatalogReadbackVerified, true,
    "caller must receive evidence of the already verified signed CAS commit");
  assert.equal(badFinalProof.outcome.catalogSequence, sequence);
  assert.equal(badFinalProof.outcome.logicalStateFinalized, false);
  assert.equal(badFinalProof.outcome.retrySafe, false);
  assert.equal(writerJournals.at(-1).size, 1,
    "pending signed intent must remain durable for reconciliation after final proof failure");

  // Real HTTP PUT commits the next immutable version, but its subsequent GET
  // confirmation disappears. The client must report an uncertain I/O result,
  // not DENIED (which could tempt the caller to retry against a stale head).
  const snapshot5 = await openCatalog(badFinalProof.outcome.catalogSequence,
    badFinalProof.outcome.catalogDigestBase64);
  const saved5 = archived.get(5);
  assert.equal(snapshot5.entries.length, 5);
  const uncertainRestore = Object.assign(realm({}), restoreBase, {
    catalog: snapshot5, sourceIndex: 4, sourceMetadata: saved5.metadata,
    sourceCek: await operableCek(saved5.cek), originalIndex: 3,
    originalMetadata: restored.metadata,
    originalCek: await operableCek(archived.get(4).cek),
    catalogWriter: makeWriter(5,
      Buffer.from(badFinalProof.outcome.catalogDigestBase64, "base64url")),
    fetchImpl: async (url, options) => {
      const response = await fetchImpl(url, options);
      if (url.endsWith("/content/read")) {
        await response.arrayBuffer();
        throw Error("readback disconnected after committed PUT");
      }
      return response;
    },
  });
  const beforeLostReadback = puts;
  let readbackError;
  try { await trash.restore(uncertainRestore); } catch (error) { readbackError = error; }
  assert.equal(readbackError?.code, "ZK_LOGICAL_TRASH_PUT_UNCERTAIN");
  assert.equal(readbackError.outcome.phase, "ciphertext_readback");
  assert.equal(readbackError.outcome.retrySafe, false);
  assert.equal(readbackError.outcome.ciphertextPutMayHaveCommitted, true);
  assert.equal(readbackError.outcome.ciphertextReadbackVerified, false);
  assert.equal(readbackError.outcome.logicalStateFinalized, false);
  assert.equal(puts, beforeLostReadback + 1, "a real HTTP PUT already committed");
  assert.equal(sequence, badFinalProof.outcome.catalogSequence,
    "no catalog CAS can occur without ciphertext GET confirmation");
  assert.equal(writerJournals.at(-1).size, 1,
    "pre-PUT journal survives outage and cannot be silently retried");
  const stored6 = archived.get(6).bytes;
  const actual6 = await send("/zk-1/v1/content/read", await rawSigner("get",
    sourceId, 6, hash(stored6)));
  assert.equal(actual6.status, 200,
    "server persisted revision 6 despite missing browser readback");
  assert.equal(actual6.result.ciphertextBase64, b64(stored6));
});
