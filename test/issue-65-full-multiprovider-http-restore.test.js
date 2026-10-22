"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const https = require("node:https");
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
  let ledger;
  t.after(async () => { await shutdown(); ledger?.close();
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
  const scopeClient = { account_id: b64(random(16)),
    compartment_id: b64(Buffer.from("cloud-quorum")), keyring_id: b64(random(16)) };
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
  const ownerDigest = random(32);
  const ownerHistoryCheckpoint = await ownerHistory.signOwnerCheckpoint({
    scope: scopeClient, signerKey: signer, signerPublicKey: verifier,
    signerKeyId: ownerSignerId, deviceId: "owner-device", revision: 9,
    manifestDigest: ownerDigest, issuedAt: 1001, previous: null });
  const ownerCheckpoint = await ownerRoots.signOwnerCiphertextRootCheckpoint({
    scope: scopeClient, signerKey: signer, signerKeyId: ownerSignerId,
    deviceId: "owner-device", manifestRevision: 9,
    manifestDigest: ownerDigest, manifestEpoch: 2,
    objectId: metadata.object_id, objectRevision: 1,
    ciphertextEpoch: 1, ciphertextRoot: root, issuedAt: 1002 });
  const floor = { minimumHead: { sequence: 0, root: Buffer.from(genesis.root) },
    minimumSnapshot: Buffer.from(genesis.bytes) };
  let revoked = false;
  let currentEpoch = 2;
  const gateway = new Zk1MultiproviderCiphertextRestore({
    pinnedInventoryPublicKey: invKeys.publicKey, pinnedInventorySignerKeyId: signerKeyId,
    pinnedOwner: { scope: scopeClient, deviceId: "owner-device",
      signerKeyId: ownerSignerId, publicKey: verifier },
    pinnedOwnerHead: { revision: 9, digest: ownerDigest, epoch: 2 },
    independentInventoryFloor: floor,
    assertCurrentAuthorization: async () => ({ active: !revoked,
      currentManifestRevision: 9, currentManifestDigest: Buffer.from(ownerDigest),
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
    signerKeyId: ownerSignerId, deviceId: "owner-device", revision: 9,
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
      signerKeyId: ownerSignerId, deviceId: "owner-device", revision: 9,
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
  revoked = true;
  assert.equal((await sendGet()).status, 403,
    "post-restore owner revocation blocks another cloud GET");
  assert.deepEqual(hits, beforeTamper, "revocation checked before any remote request");
  revoked = false;
  currentEpoch = 3;
  assert.equal((await sendGet()).status, 403,
    "current owner epoch rollover requires a new independently pinned manifest");
  currentEpoch = 2;
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
