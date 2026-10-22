"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const https = require("node:https");
const express = require("express");
const jwt = require("jsonwebtoken");
const { Readable } = require("node:stream");
const { S3Client } = require("@aws-sdk/client-s3");
const { createCloudStorage } = require("../services/cloudStorage");
const { createZk1WebdavCiphertextAdapter } =
  require("../src/services/zk1WebdavCiphertextAdapter");
const { Zk1DurableContentInventoryLedger } =
  require("../src/services/zk1DurableContentInventoryLedger");
const { computeZk1CiphertextRoot } =
  require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1MultiproviderCiphertextRestore,
  createZk1MultiproviderRestoreGetHandler } =
  require("../src/services/zk1MultiproviderCiphertextRestore");
const { publishSignedCatalogSidecars, zk1CatalogSidecarAddress } =
  require("../src/services/zk1CloudSignedCatalogSidecar");
const ownerHistory = require("../public/client/rootark-zk1-owner-signed-checkpoint");
const ownerRoots = require("../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");
const portable = require("../public/client/rootark-zk1-portable-file-recovery");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const z = require("../src/crypto/rootark-zk-1");
const manifestV2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const verifiedHistory = require("../src/crypto/rootark-zk-recovery-history-v2");
const { createAuthenticate } = require("../src/middlewares/auth");
const { createRequirePermission } = require("../src/middlewares/permissions");
const { Zk1ProtectedObjectStore, contentAuthorizationMessageV1 } =
  require("../src/services/zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } = require("../src/routes/zk1ProtectedObjectRoutes");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");

const b64 = (data) => Buffer.from(data).toString("base64url");
const random = (n) => crypto.randomBytes(n);
async function on(port, server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${server.address().port}`;
}
async function secureGet(uri, ca) {
  return new Promise((resolve, reject) => {
    const req = https.get(uri, { ca, rejectUnauthorized: true, timeout: 5000 }, (res) => {
      const parts = [];
      res.on("data", (chunk) => parts.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(parts) }));
    });
    req.on("error", reject);
  });
}
async function secureTransfer(uri, ca, method, data = null) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(uri);
    const req = https.request({ hostname: parsed.hostname,
      port: parsed.port, path: parsed.pathname, ca, rejectUnauthorized: true,
      method, timeout: 5000 }, (res) => {
      const parts = [];
      res.on("data", (chunk) => parts.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(parts) }));
    });
    req.on("error", reject);
    req.end(data);
  });
}

test("restores opaque ciphertext + signed catalog over client HTTP GET from S3 SDK, Drive HTTPS and WebDAV mTLS quorum, rejecting rollback and revoked owner", {
  timeout: 35000,
}, async (t) => {
  const before = process.env.NODE_ENV;
  process.env.NODE_ENV = "development";
  t.after(() => { if (before === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = before; });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-full-restore-"));
  const sockets = [];
  const servers = [];
  const shutdown = async () => {
    for (const socket of sockets) socket.destroy();
    for (const server of servers) await new Promise((resolve) => server.close(resolve));
  };
  let ledger, protectedStore;
  t.after(async () => { await shutdown(); protectedStore?.close(); ledger?.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 8 }); });
  const register = async (server) => {
    server.on("connection", (socket) => { sockets.push(socket); });
    await on(0, server);
    servers.push(server);
    return server.address().port;
  };
  generateNativeFixtureCertificates(dir, { caSubject: "Cloud Restore Fixture CA",
    servers: ["server"], clients: ["client"] });
  const pem = (name) => fs.readFileSync(path.join(dir, name), "utf8");
  const ca = pem("ca.pem");
  const stores = { s3: new Map(), drive: new Map(), webdav: new Map() };
  const hits = { s3: 0, drive: 0, webdav: 0 };
  let revokeSessionDuringCloudGet = null;
  let cloudError = null;
  const s3 = http.createServer((req, res) => {
    const key = req.url.split("?")[0];
    hits.s3 += 1;
    if (req.method === "PUT") {
      const pieces = [];
      req.on("data", (chunk) => pieces.push(chunk));
      req.on("end", () => { stores.s3.set(key, Buffer.concat(pieces));
        res.writeHead(200); res.end(); });
      return;
    }
    if (req.method !== "GET") { res.writeHead(405); res.end(); return; }
    if (revokeSessionDuringCloudGet) {
      const action = revokeSessionDuringCloudGet;
      revokeSessionDuringCloudGet = null;
      action();
    }
    const body = cloudError === "s3" ? null : stores.s3.get(key);
    if (!body) { res.writeHead(404); res.end(); return; }
    res.writeHead(200); res.end(body);
  });
  const s3Port = await register(s3);
  const driveId = "pinned-drive-copy-restoration";
  const catalogDriveId = "pinned-signed-catalog-sidecar";
  const driveMetadata = new Map();
  let lostCatalogDriveAck = true;
  const driveServer = https.createServer({ key: pem("server.key"), cert: pem("server.pem"), ca },
    (req, res) => {
      hits.drive += 1;
      const target = /^\/drive\/([A-Za-z0-9_-]+)(?:\/(metadata|media))?$/.exec(req.url);
      if (!target) { res.writeHead(404); res.end(); return; }
      const id = target[1];
      if (req.method === "POST" || req.method === "PATCH") {
        const pieces = [];
        req.on("data", (chunk) => pieces.push(chunk));
        req.on("end", () => { stores.drive.set(id, Buffer.concat(pieces));
          res.writeHead(200, { "content-type": "application/json" });
          if (id === catalogDriveId && lostCatalogDriveAck) {
            lostCatalogDriveAck = false;
            res.end(JSON.stringify({ id: "forged-first-ack" }));
          } else res.end(JSON.stringify({ id })); });
        return;
      }
      if (req.method !== "GET" || cloudError === "gdrive"
        || !stores.drive.has(id)) { res.writeHead(404); res.end(); return; }
      if (target[2] === "metadata") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(driveMetadata.get(id))); return;
      }
      const body = target[2] === "media" ? stores.drive.get(id) : null;
      if (!body) { res.writeHead(404); res.end(); return; }
      res.writeHead(200); res.end(body);
    });
  const drivePort = await register(driveServer);
  const webdavServer = https.createServer({ key: pem("server.key"), cert: pem("server.pem"),
    ca, requestCert: true, rejectUnauthorized: true }, (req, res) => {
    hits.webdav += 1;
    if (req.method === "PUT") {
      const pieces = [];
      req.on("data", (chunk) => pieces.push(chunk));
      req.on("end", () => { stores.webdav.set(req.url, Buffer.concat(pieces));
        res.writeHead(201); res.end(); });
      return;
    }
    const body = stores.webdav.get(req.url);
    if (req.method !== "GET" || !body || cloudError === "webdav") {
      res.writeHead(404); res.end(); return;
    }
    res.writeHead(200); res.end(body);
  });
  const webdavPort = await register(webdavServer);

  // This plaintext is constructed and opened only by the test's user-held
  // client. None of the cloud servers or restore gateway receives it or a CEK.
  const plaintext = Buffer.from("Opaque multi-provider restore only decrypts on the owner's client");
  const ownerState = await fixtures.createInitialState(3);
  let activeHead = ownerState.headManifest;
  const scopeClient = Object.fromEntries(Object.entries(ownerState.scope)
    .map(([key, value]) => [key, b64(value)]));
  const objectId = random(16);
  const metadata = { ...scopeClient, object_id: b64(objectId),
    version_id: b64(random(16)), parent_version_id: null, epoch: 1, kind: "file" };
  const secret = portable.generateRecoverySecret();
  const bundle = await portable.sealForUserHeldSecret({
    recoverySecret: secret, metadata,
    name: "recovered.txt", mediaType: "text/plain", data: plaintext,
  });
  const ciphertext = Buffer.from(bundle.ciphertextBase64, "base64url");
  const sha = crypto.createHash("sha256").update(ciphertext).digest();
  const root = computeZk1CiphertextRoot([ciphertext]);
  const scope = { account_id: Buffer.from(scopeClient.account_id, "base64url"),
    compartment_id: Buffer.from(scopeClient.compartment_id, "base64url"),
    keyring_id: Buffer.from(scopeClient.keyring_id, "base64url") };
  const invKeys = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = random(16);
  ledger = await Zk1DurableContentInventoryLedger.open(path.join(dir, "ledger.sqlite"), {
    signerKeyId, signerPrivateKey: invKeys.privateKey, scope, bootstrapNew: true });
  const genesisNonce = random(32);
  const genesis = await ledger.getSnapshot({ nonce: genesisNonce });
  const operation = { operation_id: random(16),
    expected_sequence: 0, expected_root: Buffer.from(genesis.root),
    object_id: objectId, revision: 1, epoch: 1, ciphertext_sha256: sha };
  assert.equal((await ledger.append(operation)).status, "committed");
  const proof = (await ledger.getOperationStatus(operation.operation_id)).proof;
  const snapshotNonce = random(32);
  const signedCurrent = await ledger.getSnapshot({ nonce: snapshotNonce });

  const ownerKeys = crypto.generateKeyPairSync("ed25519");
  const signer = await crypto.webcrypto.subtle.importKey("pkcs8",
    ownerKeys.privateKey.export({ type: "pkcs8", format: "der" }), "Ed25519", false, ["sign"]);
  const verifier = await crypto.webcrypto.subtle.importKey("spki",
    ownerKeys.publicKey.export({ type: "spki", format: "der" }), "Ed25519", false, ["verify"]);
  const ownerSignerId = random(16);
  const ownerDigest = await manifestV2.recoveryManifestDigestV2(activeHead);
  const ownerRevision = Number(activeHead.revision);
  const ownerEpoch = Number(activeHead.current_epoch);
  const ownerHistoryCheckpoint = await ownerHistory.signOwnerCheckpoint({
    scope: scopeClient, signerKey: signer, signerPublicKey: verifier,
    signerKeyId: ownerSignerId, deviceId: "owner-device", revision: ownerRevision,
    manifestDigest: ownerDigest, issuedAt: 1001, previous: null });
  const ownerCheckpoint = await ownerRoots.signOwnerCiphertextRootCheckpoint({
    scope: scopeClient, signerKey: signer, signerKeyId: ownerSignerId,
    deviceId: "owner-device", manifestRevision: ownerRevision,
    manifestDigest: ownerDigest, manifestEpoch: ownerEpoch,
    objectId: metadata.object_id, objectRevision: 1,
    ciphertextEpoch: 1, ciphertextRoot: root, issuedAt: 1002 });
  const floor = { minimumHead: { sequence: 0, root: Buffer.from(genesis.root) },
    minimumSnapshot: Buffer.from(genesis.bytes) };
  let revoked = false;
  let currentEpoch = ownerEpoch;
  const gateway = new Zk1MultiproviderCiphertextRestore({
    pinnedInventoryPublicKey: invKeys.publicKey, pinnedInventorySignerKeyId: signerKeyId,
    pinnedOwner: { scope: scopeClient, deviceId: "owner-device",
      signerKeyId: ownerSignerId, publicKey: verifier },
    pinnedOwnerHead: { revision: ownerRevision, digest: ownerDigest, epoch: ownerEpoch },
    independentInventoryFloor: floor,
    assertCurrentAuthorization: async () => ({ active: !revoked,
      currentManifestRevision: ownerRevision, currentManifestDigest: Buffer.from(ownerDigest),
      currentEpoch }),
  });

  const s3Endpoint = `http://127.0.0.1:${s3Port}`;
  const s3Adapter = createCloudStorage({ provider: "s3", prefix: "zk1-restore",
    s3: { bucket: "quorum-fixture", region: "us-east-1", endpoint: s3Endpoint,
      forcePathStyle: true, principalId: "s3-reader" },
    resolvePrincipalIdentity: async () => "s3-reader",
    createS3Client: async () => new S3Client({ endpoint: s3Endpoint, forcePathStyle: true,
      region: "us-east-1", maxAttempts: 1,
      credentials: { accessKeyId: "TEST", secretAccessKey: "TEST" },
      responseChecksumValidation: "WHEN_REQUIRED" }),
  });
  const driveAdapter = createCloudStorage({ provider: "gdrive", prefix: "zk1-drive",
    gdrive: { folderId: "drive-parent" },
    resolvePrincipalIdentity: async () => "drive-reader",
    createGoogleDriveClient: async () => ({ files: {
      get: async ({ fileId, alt }) => {
        assert.ok([driveId, catalogDriveId].includes(fileId));
        const reply = await secureTransfer(`https://127.0.0.1:${drivePort}/drive/${fileId}/`
          + (alt === "media" ? "media" : "metadata"), ca, "GET");
        if (reply.status !== 200) throw Object.assign(new Error("not found"),
          { status: reply.status });
        return { data: alt === "media" ? Readable.from([reply.body])
          : JSON.parse(reply.body.toString("utf8")) };
      },
      create: async ({ requestBody, media }) => {
        assert.equal(requestBody.id, catalogDriveId);
        driveMetadata.set(catalogDriveId, { id: catalogDriveId,
          parents: ["drive-parent"], appProperties: requestBody.appProperties });
        const pieces = [];
        for await (const part of media.body) pieces.push(Buffer.from(part));
        const reply = await secureTransfer(`https://127.0.0.1:${drivePort}/drive/${catalogDriveId}`,
          ca, "POST", Buffer.concat(pieces));
        return { data: JSON.parse(reply.body.toString("utf8")) };
      },
      update: async ({ fileId, media }) => {
        assert.equal(fileId, catalogDriveId);
        const pieces = [];
        for await (const part of media.body) pieces.push(Buffer.from(part));
        const reply = await secureTransfer(`https://127.0.0.1:${drivePort}/drive/${fileId}`,
          ca, "PATCH", Buffer.concat(pieces));
        return { data: JSON.parse(reply.body.toString("utf8")) };
      },
    } }),
  });
  const webdavAdapter = createZk1WebdavCiphertextAdapter({
    developmentOnlyOptIn: true,
    endpoint: `https://127.0.0.1:${webdavPort}/dav`,
    namespace: "restore_quorum", ca,
    serverFingerprint256: new crypto.X509Certificate(pem("server.pem")).fingerprint256,
    clientCert: pem("client.pem"), clientKey: pem("client.key"),
  });
  const readers = [];
  for (const [provider, reader, pin] of [
    ["s3", s3Adapter, null], ["gdrive", driveAdapter, driveId],
    ["webdav", webdavAdapter, null],
  ]) readers.push({ cloudReader: reader, provider,
    expectedReaderContext: await reader.resolveInventoryContext(),
    pinnedDriveFileId: pin });

  const address = require("../src/services/zk1CloudCiphertextReadbackVerifier")
    .zk1CloudCopyAddress({ scope, operationId: operation.operation_id });
  const s3Key = s3Adapter.key(address.folder, address.name, "uploads");
  const driveKey = driveAdapter.key(address.folder, address.name, "uploads");
  const davKey = webdavAdapter.key(address.folder, address.name, "uploads");
  stores.s3.set(`/quorum-fixture/${s3Key}`, Buffer.from(ciphertext));
  stores.drive.set(driveId, Buffer.from(ciphertext));
  stores.webdav.set(`/dav/${davKey}`, Buffer.from(ciphertext));
  driveMetadata.set(driveId, { id: driveId, parents: ["drive-parent"],
    appProperties: { rootArkKey: driveKey, rootArkFolderId: address.folder,
      rootArkArea: "uploads" } });
  const recoverInput = { scope, operation,
    signedCommittedProof: proof, signedSnapshot: signedCurrent.bytes,
    snapshotNonce, committedProofChain: [proof],
    ownerCheckpoint, ownerHistoryCheckpoint, previousOwnerHistoryProof: null,
    expectedCiphertextRoot: root, chunkLengths: [ciphertext.length],
    readers, minimumMatchingProviders: 2 };

  // An owner history predecessor is NOT wire JSON: this is a process-local
  // WeakMap-branded proof returned by the cryptographic verifier. Rebuilding
  // an object with the same public fields MUST NOT mint the private brand.
  const historyVerify = (checkpoint, previous) => ownerHistory.verifyOwnerCheckpoint({
    checkpoint, scope: scopeClient, signerPublicKey: verifier,
    signerKeyId: ownerSignerId, previous });
  const proofV1 = await historyVerify(ownerHistoryCheckpoint, null);
  const attackerKeys = crypto.generateKeyPairSync("ed25519");
  const attackerSigner = await crypto.webcrypto.subtle.importKey("pkcs8",
    attackerKeys.privateKey.export({ type: "pkcs8", format: "der" }),
    "Ed25519", false, ["sign"]);
  const attackerVerifier = await crypto.webcrypto.subtle.importKey("spki",
    attackerKeys.publicKey.export({ type: "spki", format: "der" }),
    "Ed25519", false, ["verify"]);
  const foreignHistory = await ownerHistory.signOwnerCheckpoint({
    scope: scopeClient, signerKey: attackerSigner, signerPublicKey: attackerVerifier,
    signerKeyId: ownerSignerId, deviceId: "owner-device", revision: ownerRevision,
    manifestDigest: ownerDigest, issuedAt: 1001, previous: null });
  const foreignBrandedProof = await ownerHistory.verifyOwnerCheckpoint({
    checkpoint: foreignHistory, scope: scopeClient,
    signerPublicKey: attackerVerifier, signerKeyId: ownerSignerId, previous: null });
  assert.equal(foreignBrandedProof.signedCheckpointVerified, true);
  const historical = [];
  let predecessor = proofV1;
  for (const sequence of [2, 3]) {
    const signedHistory = await ownerHistory.signOwnerCheckpoint({
      scope: scopeClient, signerKey: signer, signerPublicKey: verifier,
      signerKeyId: ownerSignerId, deviceId: "owner-device", revision: ownerRevision,
      manifestDigest: ownerDigest, issuedAt: 1001 + sequence, previous: predecessor });
    const verified = await historyVerify(signedHistory, predecessor);
    assert.equal(verified.sequence, sequence);
    historical.push({ sequence, signedHistory, predecessor });
    predecessor = verified;
  }
  for (const item of historical) {
    await t.test(`verified owner history sequence ${item.sequence} restores; spoofed predecessor is rejected`, async () => {
      const request = { ...recoverInput,
        ownerHistoryCheckpoint: item.signedHistory,
        previousOwnerHistoryProof: item.predecessor };
      const opened = await gateway.restoreExact(request);
      assert.equal(opened.status, "SIGNED_CATALOG_AND_OWNER_ROOT_CLOUD_RESTORE");
      assert.deepEqual(opened.ciphertext, ciphertext);
      assert.equal(opened.verifiedProviders.length, 3);

      const beforeForgedGet = { ...hits };
      for (const forged of [
        { ...item.predecessor },
        Object.freeze({ ...item.predecessor, authorizesRecovery: true }),
        Object.freeze({ ...item.predecessor, signedCheckpointVerified: true }),
        Object.freeze({ ...item.predecessor, checkpointDigest: b64(random(32)) }),
        new Proxy(item.predecessor, {}),
        foreignBrandedProof,
      ]) {
        await assert.rejects(gateway.restoreExact({ ...request,
          previousOwnerHistoryProof: forged }), /ZK_MULTIPROVIDER_RESTORE_DENIED/);
      }
      assert.deepEqual(hits, beforeForgedGet,
        "no authenticated cloud GET for unbranded/forged predecessor claims");
    });
  }

  // Publish the separately addressed Ed25519 catalog backup over the REAL
  // disposable S3 SDK HTTP PUT, Drive HTTPS media CREATE and WebDAV mTLS PUT.
  const signedCatalog = Object.fromEntries(Object.entries(recoverInput).filter(
    ([key]) => !["scope", "operation", "readers", "minimumMatchingProviders"].includes(key)));
  const catalogTargets = [];
  for (const target of readers) {
    catalogTargets.push({ provider: target.provider,
      cloudWriter: target.cloudReader, expectedContext: target.expectedReaderContext,
      pinnedDriveFileId: target.provider === "gdrive" ? catalogDriveId : null });
  }
  const publishInput = { scope, operationId: operation.operation_id,
    signedCatalog, writers: catalogTargets };
  await assert.rejects(publishSignedCatalogSidecars(publishInput),
    /ZK_SIGNED_CATALOG_SIDECAR_DENIED/,
    "false Drive ACK after real media PUT cannot claim completed catalog replication");
  assert.equal(lostCatalogDriveAck, false);
  assert.equal(stores.drive.has(catalogDriveId), true,
    "a saved remote Drive copy can outlive a lost acknowledgement");
  const published = await publishSignedCatalogSidecars(publishInput);
  assert.equal(published.status, "SIGNED_CATALOG_PUT_ACK_NONAUTHORITATIVE");
  assert.equal(published.acknowledgements.length, 3);
  assert.equal(published.remoteDurabilityProven, false);
  const catalogReaders = catalogTargets.map(({ cloudWriter, expectedContext,
    provider, pinnedDriveFileId }) => ({ cloudReader: cloudWriter,
    expectedContext, provider, pinnedDriveFileId }));
  const remoteRecovery = { scope, operation, catalogReaders,
    readers, minimumMatchingProviders: 2, minimumMatchingCatalogProviders: 2 };
  const sidecar = zk1CatalogSidecarAddress(scope, operation.operation_id);
  const catalogWebdavKey = `/dav/${webdavAdapter.key(sidecar.folder, sidecar.name, "uploads")}`;
  const catalogDriveData = Buffer.from(stores.drive.get(catalogDriveId));

  let session = true;
  const handler = createZk1MultiproviderRestoreGetHandler({ gateway,
    pinnedOperationId: operation.operation_id,
    restoreInput: { mode: "cloud-catalog", request: remoteRecovery },
    authorizeHttpRequest: async (request) => session && request.headers.authorization === "Bearer ephemeral-test-session" });
  const app = http.createServer(handler);
  const appPort = await register(app);
  const url = `http://127.0.0.1:${appPort}/zk1-recovery/${b64(operation.operation_id)}`;
  const sendGet = () => fetch(url, { headers: { authorization: "Bearer ephemeral-test-session" } });
  assert.equal((await fetch(url)).status, 403, "unauthenticated GET must be blocked");
  const result = await sendGet();
  assert.equal(result.status, 200, "two independently verified remote bytes permit client transfer");
  assert.equal(result.headers.get("cache-control"), "no-store");
  const body = await result.json();
  assert.equal(body.providerCount, 3);
  assert.equal(body.signedCommittedProof, b64(proof));
  assert.equal(body.signedSnapshot, b64(signedCurrent.bytes));
  assert.equal(body.operationId, b64(operation.operation_id));
  assert.equal(body.signedCatalogRecoveredFromRemote, true);
  assert.deepEqual(Buffer.from(body.ciphertextBase64, "base64url"), ciphertext);
  assert.equal(body.remoteDurabilityProven, false);
  const clientBundle = { ...bundle, ciphertextBase64: body.ciphertextBase64 };
  const opened = await portable.openWithIndependentRoot({
    recoverySecret: secret, bundle: clientBundle,
    expectedMetadata: metadata,
    independentlyPinnedCiphertextRoot: root });
  assert.deepEqual(Buffer.from(opened.data), plaintext);
  assert.equal(opened.authorizesProductionRestore, false);

  stores.webdav.set(`/dav/${davKey}`, Buffer.alloc(ciphertext.length, 0x22));
  const partial = await sendGet();
  assert.equal(partial.status, 200, "one corrupted provider is quarantined by 2-of-3 quorum");
  assert.equal((await partial.json()).providerCount, 2);
  stores.drive.delete(driveId);
  assert.equal((await sendGet()).status, 403,
    "lost Drive copy with corrupt WebDAV leaves only one healthy authority");
  stores.drive.set(driveId, Buffer.from(ciphertext));
  stores.webdav.set(`/dav/${davKey}`, Buffer.from(ciphertext));
  stores.webdav.set(catalogWebdavKey, Buffer.alloc(stores.webdav.get(catalogWebdavKey).length, 0x43));
  const oneCorruptCatalog = await sendGet();
  assert.equal(oneCorruptCatalog.status, 200,
    "two intact independent catalog backups can survive one corrupted catalog sidecar");
  stores.drive.set(catalogDriveId, Buffer.alloc(catalogDriveData.length, 0xee));
  assert.equal((await sendGet()).status, 403,
    "one intact signed-catalog provider cannot authorize remote ciphertext GET");
  stores.drive.set(catalogDriveId, catalogDriveData);
  // Recreate the pinned WebDAV signed catalog from its original S3 peer.
  const catalogS3Key = `/quorum-fixture/${s3Adapter.key(sidecar.folder, sidecar.name, "uploads")}`;
  stores.webdav.set(catalogWebdavKey, Buffer.from(stores.s3.get(catalogS3Key)));
  const beforeTamper = { ...hits };
  const wrongOwner = { ...ownerCheckpoint, ciphertext_root: b64(random(32)) };
  await assert.rejects(gateway.restoreExact({ ...recoverInput,
    ownerCheckpoint: wrongOwner }), /ZK_MULTIPROVIDER_RESTORE_DENIED/);
  assert.deepEqual(hits, beforeTamper, "forged root denied before remote network");
  await assert.rejects(gateway.restoreExact({ ...recoverInput,
    signedCommittedProof: random(proof.length) }), /ZK_MULTIPROVIDER_RESTORE_DENIED/);
  const stale = { ...recoverInput,
    signedSnapshot: genesis.bytes, snapshotNonce: genesisNonce,
    committedProofChain: [] };
  await assert.rejects(gateway.restoreExact(stale), /ZK_MULTIPROVIDER_RESTORE_DENIED/,
    "rollback to old signed snapshot does not recover deleted catalog entry");
  assert.deepEqual(hits, beforeTamper);
  // Real normal authenticated session/CSRF endpoint on the SAME Express
  // middleware, backed by a genuinely owner-rooted and witness-pinned grant.
  const clock = 1100;
  const witnessSigner = crypto.generateKeyPairSync("ed25519");
  const witnessId = random(16);
  const baseDigest = await manifestV2.recoveryManifestDigestV2(ownerState.baseManifest);
  const brandedHistory = await verifiedHistory.verifyRecoveryHistoryPublicV2({
    expectedScope: ownerState.scope, baseManifest: ownerState.baseManifest,
    baseReceipt: ownerState.baseReceipt, pinnedWitness: ownerState.pinnedWitness,
    transitions: ownerState.transitions, packageEnvelopes: ownerState.packageEnvelopes,
    now: clock,
  });
  assert.equal(await verifiedHistory.isVerifiedPublicRecoveryHistoryV2(brandedHistory), true);
  protectedStore = new Zk1ProtectedObjectStore(path.join(dir, "recovery-grants.sqlite"), {
    trustedScope: ownerState.scope, bootstrapNew: true,
    signedHistoryRequired: true, signedHistoryGenesisDigest: baseDigest,
    verifiedHistoryProvider: () => brandedHistory, admissionRequired: true,
    minimumHead: { revision: 1, witnessSequence: 1, digest: baseDigest },
    witnessPinned: { keyId: witnessId, publicKey: witnessSigner.publicKey },
    witnessProvider: {
      async freshHead({ nonce }) {
        const unsigned = { type: "rootark-recovery-witness-head/v1",
          witness_key_id: witnessId, ...ownerState.scope, nonce,
          current_revision: activeHead.revision,
          current_manifest_digest: await manifestV2.recoveryManifestDigestV2(activeHead),
          witness_sequence: activeHead.revision, observed_at: clock,
          status: "committed", pending_reservation_id: null };
        const signature = crypto.sign(null, Buffer.concat([
          Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0"),
          Buffer.from(await z.encodeDeterministic(unsigned)),
        ]), witnessSigner.privateKey);
        return z.encodeDeterministic({ ...unsigned, signature });
      },
      async beginIoAdmission() { return { admissionId: random(16), proceed: true }; },
      async finishIoAdmission() { return { status: "FINISHED" }; },
    },
    manifestProvider: () => z.encodeDeterministic(activeHead),
    nowSeconds: () => clock,
  });
  const signedSessionSecret = random(32).toString("hex");
  let sessionVersion = 0;
  const authMiddleware = createAuthenticate({ jwt, jwtSecret: signedSessionSecret,
    loadUser: (name) => name === "owner" ? {
      username: "owner", sessionVersion, permissions: { listFiles: true, upload: true },
    } : null,
    normalizeUserPermissions: (user) => user.permissions });
  const allowedScope = (user) => user?.username === "owner" ? ownerState.scope : null;
  const gatewayPins = {
    pinnedInventoryPublicKey: invKeys.publicKey,
    pinnedInventorySignerKeyId: signerKeyId,
    pinnedOwner: { scope: scopeClient, deviceId: "owner-device",
      signerKeyId: ownerSignerId, publicKey: verifier },
    pinnedOwnerHead: { revision: ownerRevision, digest: ownerDigest, epoch: ownerEpoch },
    independentInventoryFloor: floor,
  };
  const signedRestoreInput = { mode: "cloud-catalog", request: remoteRecovery };
  const expressApp = express();
  assert.throws(() => registerZk1ProtectedObjectRoutes({
    app: express(), store: protectedStore, authenticate: authMiddleware,
    requirePermission: createRequirePermission(), resolveTrustedScope: allowedScope,
    multiproviderRestore: { gatewayPins: {
      ...gatewayPins, assertCurrentAuthorization: async () => ({ active: true }),
    }, restoreInput: signedRestoreInput }, environment: "test",
  }), /ZK_MULTIPROVIDER_HTTP_DENIED/);
  assert.throws(() => registerZk1ProtectedObjectRoutes({
    app: express(), store: protectedStore, authenticate: authMiddleware,
    requirePermission: createRequirePermission(), resolveTrustedScope: allowedScope,
    multiproviderRestore: { gatewayPins, restoreInput: signedRestoreInput },
    environment: "production",
  }), /ZK_MULTIPROVIDER_HTTP_DENIED/);
  registerZk1ProtectedObjectRoutes({ app: expressApp, store: protectedStore,
    authenticate: authMiddleware, requirePermission: createRequirePermission(),
    resolveTrustedScope: allowedScope,
    multiproviderRestore: { gatewayPins, restoreInput: signedRestoreInput },
    environment: "test" });
  const expressServer = http.createServer(expressApp);
  const expressPort = await register(expressServer);
  const secureUrl = `http://127.0.0.1:${expressPort}/zk-1/v1/multiprovider-restore/read`;
  const device = activeHead.devices[0];
  const privateDeviceKey = ownerState.actors.get(
    Buffer.from(device.authorization_key_id).toString("hex"));
  const makeSignedRequest = async ({ overrides = {}, key = privateDeviceKey } = {}) => {
    const authorization = { ...ownerState.scope, device_id: device.device_id,
      operation: "get", object_id: b64(operation.object_id),
      expected_object_revision: operation.revision,
      manifest_revision: ownerRevision, manifest_digest: ownerDigest,
      epoch: ownerEpoch, nonce: random(32), issued_at: clock - 1,
      expires_at: clock + 30, ciphertext_digest: operation.ciphertext_sha256,
      ...overrides };
    const signature = crypto.sign(null,
      await contentAuthorizationMessageV1(authorization), key);
    return { authorization: Object.fromEntries(Object.entries(authorization)
      .map(([name, value]) => [name, Buffer.isBuffer(value) ? b64(value) : value])),
    signatureBase64: b64(signature) };
  };
  const signedCookie = jwt.sign({ username: "owner", sessionVersion: 0 },
    signedSessionSecret, { expiresIn: "10m" });
  const sessionHeaders = { "content-type": "application/json",
    cookie: `rootark_session=${signedCookie}; rootark_csrf=restore-lab`,
    "x-csrf-token": "restore-lab" };
  const post = async (body, extra = {}) => fetch(secureUrl, {
    method: "POST", headers: { ...sessionHeaders, ...extra }, body: JSON.stringify(body),
  });
  const validRequest = await makeSignedRequest();
  const beforeAuth = { ...hits };
  assert.equal((await fetch(secureUrl)).status, 404, "GET not exposed: signed POST required");
  assert.equal((await post(validRequest, { cookie: "" })).status, 401);
  assert.equal((await post(validRequest, { "x-csrf-token": "" })).status, 403);
  assert.equal((await post({ ...validRequest, authorization: {
    ...validRequest.authorization, account_id: b64(random(16)),
  } })).status, 403);
  assert.equal((await post(await makeSignedRequest({ key:
    crypto.generateKeyPairSync("ed25519").privateKey }))).status, 403);
  assert.deepEqual(hits, beforeAuth, "unauthorized sessions and forged device GET must not reach clouds");
  const authorized = await post(validRequest);
  assert.equal(authorized.status, 200);
  const authorizedBody = await authorized.json();
  assert.deepEqual(Buffer.from(authorizedBody.ciphertextBase64, "base64url"), ciphertext);
  assert.equal(authorizedBody.authorizesProductionRestore, false);
  assert.equal(authorizedBody.remoteDurabilityProven, false);
  const afterSuccess = { ...hits };
  assert.equal((await post(validRequest)).status, 403,
    "persistent device nonce prevents replay across authenticated HTTP POST requests");
  assert.deepEqual(hits, afterSuccess);
  sessionVersion++;
  assert.equal((await post(await makeSignedRequest())).status, 401,
    "invalidated real application sessionVersion blocks remote GET");
  sessionVersion--;
  revokeSessionDuringCloudGet = () => { sessionVersion = 1; };
  const midflight = await post(await makeSignedRequest());
  assert.equal(midflight.status, 401,
    "session revoked DURING remote provider GET must be rechecked before ciphertext egress");
  assert.equal((await midflight.text()).includes("ciphertextBase64"), false);
  sessionVersion = 0;
  const afterMidflight = { ...hits };
  activeHead = await fixtures.appendDeviceRevocation(ownerState, device.device_id);
  assert.equal((await post(await makeSignedRequest())).status, 403,
    "independently witnessed revoked device cannot access remote ciphertext");
  assert.deepEqual(hits, afterMidflight, "revoked device blocked before contacting providers");
  activeHead = ownerState.headManifest;
  revoked = true;
  assert.equal((await sendGet()).status, 403,
    "post-restore owner revocation blocks another cloud GET");
  assert.deepEqual(hits, afterMidflight, "revocation checked before any remote request");
  revoked = false;
  currentEpoch = ownerEpoch + 1;
  assert.equal((await sendGet()).status, 403,
    "current owner epoch rollover requires a new independently pinned manifest");
  currentEpoch = ownerEpoch;
  session = false;
  assert.equal((await sendGet()).status, 403);

  for (const item of historical) {
    await t.test(`signed cloud sidecar history ${item.sequence} needs independently verified predecessor`, async () => {
      // A cloud copy carries signed history wire, not the private WeakMap
      // brand. The current owner verifier must mint that in-process proof.
      const persisted = { ...signedCatalog,
        ownerHistoryCheckpoint: item.signedHistory,
        previousOwnerHistoryProof: { ...item.predecessor } };
      const sidecarWrite = await publishSignedCatalogSidecars({
        ...publishInput, signedCatalog: persisted });
      assert.equal(sidecarWrite.acknowledgements.length, 3);
      await assert.rejects(gateway.restoreFromCloudCatalog(remoteRecovery),
        /ZK_MULTIPROVIDER_RESTORE_DENIED/,
        "server-replayed JSON must never recreate a branded owner proof");
      const repaired = await gateway.restoreFromCloudCatalog({ ...remoteRecovery,
        previousOwnerHistoryProof: item.predecessor });
      assert.equal(repaired.signedCatalogRecoveredFromRemote, true);
      assert.deepEqual(repaired.ciphertext, ciphertext);
      for (const predecessor of [{ ...item.predecessor }, foreignBrandedProof]) {
        await assert.rejects(gateway.restoreFromCloudCatalog({ ...remoteRecovery,
          previousOwnerHistoryProof: predecessor }), /ZK_MULTIPROVIDER_RESTORE_DENIED/);
      }
    });
  }
});
