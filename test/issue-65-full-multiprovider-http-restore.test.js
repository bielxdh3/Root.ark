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
const { shouldDeferZk1JsonParsing } = require("../src/middlewares/zk1DeferredJsonParsing");
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
const { signOwnerProviderVersionPin } =
  require("../src/services/zk1OwnerProviderVersionPin");
const { publishSignedCatalogSidecars, recoverSignedCatalogSidecar,
  verifyPublishedSignedCatalogSidecars, zk1CatalogSidecarAddress } =
  require("../src/services/zk1CloudSignedCatalogSidecar");
const { Zk1ExternallyPinnedProviderDomains, signProviderDomainAttestation,
  spkiFingerprint } = require("../src/services/zk1ExternallyPinnedProviderDomains");
const { GRANT_FIELDS, STATE_FIELDS, GRANT_DOMAIN, STATUS_DOMAIN, POP_DOMAIN } =
  require("../src/services/zk1FreshOwnerDeviceRestoreAuthority");
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
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(parts),
        headers: res.headers }));
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
  let partialS3CiphertextGet = false;
  let partialDriveCiphertextGet = false;
  let s3CurrentVersion = "owner-version-v1";
  let webdavCurrentEtag = '"opaque-v1"';
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
    const pinnedVersion = new URL(req.url, "http://localhost").searchParams.get("versionId");
    if (pinnedVersion !== null && pinnedVersion !== s3CurrentVersion) {
      res.writeHead(404); res.end(); return;
    }
    if (partialS3CiphertextGet && key.endsWith(".ct")) {
      res.writeHead(206, { "content-range": `bytes 0-${body.length - 1}/${body.length + 1}` });
      res.end(body); return;
    }
    // Real S3 supplies ContentLength for a full GET. A signed sidecar is
    // normally shorter than its maxBytes limit; an ordinary ciphertext copy
    // must still enforce its exact expected length.
    res.writeHead(200, { "x-amz-version-id": s3CurrentVersion,
      "content-length": String(body.length) }); res.end(body);
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
      if (partialDriveCiphertextGet && id === driveId) {
        res.writeHead(206, { "content-range": `bytes 0-${body.length - 1}/${body.length + 1}` });
        res.end(body); return;
      }
      res.writeHead(200, { "content-length": String(body.length) }); res.end(body);
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
    res.writeHead(200, { etag: webdavCurrentEtag }); res.end(body);
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
  let gateway;
  const restoreDevice = activeHead.devices[0];
  const deviceKeys = { privateKey: ownerState.actors.get(
    Buffer.from(restoreDevice.authorization_key_id).toString("hex")) };
  assert.ok(deviceKeys.privateKey);
  const deviceKeyId = Buffer.from(restoreDevice.authorization_key_id).toString("base64url");
  const grantFields = {
    schema: "rootark-zk1-browser-owner-device-grant/v1", ...scopeClient,
    device_id: restoreDevice.device_id,
    authorization_key_id: deviceKeyId,
    authorization_public_key: Buffer.from(restoreDevice.authorization_public_key)
      .toString("base64url"),
    manifest_revision: ownerRevision, manifest_digest: b64(ownerDigest), current_epoch: ownerEpoch,
    enrolled_epoch: ownerEpoch, revoked_at_epoch: null,
  };
  const signedCurrentDeviceGrant = { ...grantFields, signature: b64(crypto.sign(null,
    Buffer.concat([GRANT_DOMAIN, Buffer.from(JSON.stringify(
      Object.fromEntries(GRANT_FIELDS.map((k) => [k, grantFields[k]]))))]),
    ownerKeys.privateKey)) };
  let freshAttack = null;
  let finalEgressStatusReads = 0;
  let replayed = null;
  const fetchFreshSignedDeviceState = async (challenge) => {
    const now = Math.floor(Date.now() / 1000);
    if (freshAttack === "revoke-on-final-egress") finalEgressStatusReads += 1;
    const state = {
      schema: "rootark-zk1-current-device-restore-state/v1",
      ...challenge.scope, device_id: challenge.deviceId,
      authorization_key_id: challenge.authorizationKeyId,
      operation_id: challenge.operationId,
      manifest_revision: challenge.manifestRevision,
      manifest_digest: challenge.manifestDigest, current_epoch: currentEpoch,
      state: (revoked || (freshAttack === "revoke-on-final-egress"
        && finalEgressStatusReads >= 4)) ? "REVOKED" : "ACTIVE",
      nonce: freshAttack === "wrong-nonce" ? b64(random(32)) : challenge.nonce,
      issued_at: freshAttack === "expired" ? now - 35 : now,
      expires_at: freshAttack === "expired" ? now - 25 : now + 10,
    };
    const signed = { ...state, signature: b64(crypto.sign(null,
      Buffer.concat([STATUS_DOMAIN, Buffer.from(JSON.stringify(
        Object.fromEntries(STATE_FIELDS.map((k) => [k, state[k]]))))]),
      freshAttack === "forged" ? crypto.generateKeyPairSync("ed25519").privateKey
        : ownerKeys.privateKey)) };
    const popBytes = Buffer.concat([POP_DOMAIN, Buffer.from(challenge.nonce, "base64url"),
      Buffer.from(challenge.operationId, "base64url"),
      Buffer.from(signedCurrentDeviceGrant.signature, "base64url")]);
    const proof = b64(crypto.sign(null, popBytes, deviceKeys.privateKey));
    if (freshAttack === "replay" && replayed) return replayed;
    const result = { state: signed, deviceProofOfPossession: proof };
    if (!replayed) replayed = result;
    return result;
  };

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
        if (reply.status !== 200 && !(alt === "media" && reply.status === 206)) {
          throw Object.assign(new Error("not found"),
          { status: reply.status });
        }
        return { status: reply.status, headers: reply.headers,
          data: alt === "media" ? Readable.from([reply.body])
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
  const administrators = Object.fromEntries(["s3", "gdrive", "webdav"].map((provider) => [
    provider, { keys: crypto.generateKeyPairSync("ed25519"), id: random(32).toString("hex") },
  ]));
  const providerDomainPinset = new Zk1ExternallyPinnedProviderDomains({
    externallyPinnedDomains: Object.entries(administrators).map(([provider, admin]) => ({
      provider, trustDomainId: admin.id, administratorPublicKey: admin.keys.publicKey,
      independentAdministratorSpkiSha256: spkiFingerprint(admin.keys.publicKey),
    })),
  });
  const attest = (target) => {
    const admin = administrators[target.provider];
    const now = Math.floor(Date.now() / 1000);
    return signProviderDomainAttestation({ administratorPrivateKey: admin.keys.privateKey,
      statement: { schema: "rootark-zk1-provider-domain-attestation/v1",
        provider: target.provider, trust_domain_id: admin.id,
        namespace_sha256: (target.cloudReader || target.cloudWriter).zk1StorageNamespace(),
        principal_context_sha256: target.expectedReaderContext || target.expectedContext,
        drive_file_id: target.pinnedDriveFileId,
        ...Object.fromEntries(Object.entries(scopeClient).map(([key, value]) => [key, value])),
        issued_at: now - 3, expires_at: now + 300 } });
  };
  for (const reader of readers) reader.domainAttestation = attest(reader);
  const directGatewayPins = {
    pinnedInventoryPublicKey: invKeys.publicKey, pinnedInventorySignerKeyId: signerKeyId,
    pinnedOwner: { scope: scopeClient, deviceId: "owner-device",
      signerKeyId: ownerSignerId, publicKey: verifier },
    independentOwnerSpkiSha256: spkiFingerprint(ownerKeys.publicKey),
    pinnedOwnerHead: { revision: ownerRevision, digest: ownerDigest, epoch: ownerEpoch },
    independentInventoryFloor: floor, providerDomainPinset,
    signedCurrentDeviceGrant, fetchFreshSignedDeviceState,
    // Deliberately dishonest legacy callback: a Boolean ACTIVE is no longer
    // authority. The owner-signed nonce status must reject revocation/epoch.
    assertCurrentAuthorization: async () => ({ active: true,
      currentManifestRevision: ownerRevision, currentManifestDigest: Buffer.from(ownerDigest),
      currentEpoch: ownerEpoch }),
  };
  gateway = new Zk1MultiproviderCiphertextRestore(directGatewayPins);

  const address = require("../src/services/zk1CloudCiphertextReadbackVerifier")
    .zk1CloudCopyAddress({ scope, operationId: operation.operation_id });
  const s3Key = s3Adapter.key(address.folder, address.name, "uploads");
  const driveKey = driveAdapter.key(address.folder, address.name, "uploads");
  const davKey = webdavAdapter.key(address.folder, address.name, "uploads");
  const signVersion = (reader) => signOwnerProviderVersionPin({
    ownerPrivateKey: ownerKeys.privateKey, scope, operation, root,
    byteLength: ciphertext.length,
    ownerHead: { revision: ownerRevision, digest: ownerDigest, epoch: ownerEpoch },
    target: { provider: reader.provider,
      namespaceIdentity: reader.cloudReader.zk1StorageNamespace(),
      expectedReaderContext: reader.expectedReaderContext,
      providerObjectKey: reader.cloudReader.key(address.folder, address.name, "uploads"),
      pinnedDriveFileId: reader.pinnedDriveFileId },
    providerVersionId: reader.provider === "s3" ? "owner-version-v1" : null,
    providerEtag: reader.provider === "webdav" ? '"opaque-v1"' : null,
  });
  for (const reader of readers) reader.ownerSignedVersionPin = signVersion(reader);
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

  await t.test("owner Ed25519 pins exact S3 version, WebDAV ETag and Drive ID across fallback and restart", async () => {
    const pinnedReaders = readers.map((reader) => ({ ...reader }));
    const request = { ...recoverInput, readers: pinnedReaders, minimumMatchingProviders: 3 };
    const fullyPinned = await gateway.restoreExact(request);
    assert.deepEqual(fullyPinned.ciphertext, ciphertext);
    assert.equal(fullyPinned.ownerSignedProviderVersionsVerified, true);
    assert.deepEqual(fullyPinned.verifiedProviders.map((entry) => entry.provider),
      ["s3", "gdrive", "webdav"]);
    assert.equal(fullyPinned.verifiedProviders[0].providerVersionId, "owner-version-v1");
    assert.equal(fullyPinned.verifiedProviders[1].providerFileId, driveId);
    assert.equal(fullyPinned.verifiedProviders[2].providerEtag, '"opaque-v1"');

    // Attacker strips every owner-signed provider version after the owner
    // approved S3 VersionId/WebDAV ETag. Same bytes at stale versions must
    // never become an unsigned 2/3 quorum, including after a gateway restart.
    const allStripped = pinnedReaders.map(({ ownerSignedVersionPin, ...reader }) => reader);
    s3CurrentVersion = "owner-version-v0";
    webdavCurrentEtag = '"opaque-v0"';
    const beforeStrip = { ...hits };
    await assert.rejects(gateway.restoreExact({ ...request, readers: allStripped,
      minimumMatchingProviders: 2 }), /ZK_MULTIPROVIDER_RESTORE_DENIED/,
    "removing ALL owner signatures must not turn a signed version quorum into legacy");
    const afterRestart = new Zk1MultiproviderCiphertextRestore(directGatewayPins);
    await assert.rejects(afterRestart.restoreExact({ ...request, readers: allStripped,
      minimumMatchingProviders: 2 }), /ZK_MULTIPROVIDER_RESTORE_DENIED/,
    "stripped signatures must still be rejected by a new gateway instance");
    assert.deepEqual(hits, beforeStrip, "stripped owner signatures denied before remote GET");
    s3CurrentVersion = "owner-version-v1";
    webdavCurrentEtag = '"opaque-v1"';

    const beforeForgery = { ...hits };
    for (const forged of [
      { ...pinnedReaders[0], ownerSignedVersionPin: { ...pinnedReaders[0].ownerSignedVersionPin,
        signature: b64(random(64)) } },
      { ...pinnedReaders[0], ownerSignedVersionPin: { ...pinnedReaders[0].ownerSignedVersionPin,
        provider_version_id: "owner-version-v0" } },
      { ...pinnedReaders[0], ownerSignedVersionPin: { ...pinnedReaders[0].ownerSignedVersionPin,
        ciphertext_sha256: b64(random(32)) } },
      { ...pinnedReaders[0], ownerSignedVersionPin: { ...pinnedReaders[0].ownerSignedVersionPin,
        owner_head_revision: ownerRevision + 1 } },
      { ...pinnedReaders[1], ownerSignedVersionPin: { ...pinnedReaders[1].ownerSignedVersionPin,
        provider_file_id: "replayed-drive-id" } },
      { ...pinnedReaders[2], ownerSignedVersionPin: { ...pinnedReaders[2].ownerSignedVersionPin,
        provider_etag: '"opaque-v0"' } },
    ]) {
      const at = forged.provider === "s3" ? 0 : forged.provider === "gdrive" ? 1 : 2;
      await assert.rejects(gateway.restoreExact({ ...request,
        readers: pinnedReaders.map((entry, index) => index === at ? forged : entry) }),
      /ZK_MULTIPROVIDER_RESTORE_DENIED/);
    }
    await assert.rejects(gateway.restoreExact({ ...request,
      readers: [pinnedReaders[0], allStripped[1], pinnedReaders[2]] }),
    /ZK_MULTIPROVIDER_RESTORE_DENIED/, "signed quorum cannot downgrade to unpinned Drive");
    assert.deepEqual(hits, beforeForgery, "forged versions and downgrade deny before HTTP GET");

    const s3GetCount = hits.s3;
    let keyCalls = 0;
    const switchedS3 = { ...pinnedReaders[0], cloudReader: { ...pinnedReaders[0].cloudReader,
      key(...args) {
        keyCalls += 1;
        const original = s3Adapter.key(...args);
        return keyCalls === 1 ? original : `foreign/${original}`;
      },
    } };
    await assert.rejects(gateway.restoreExact({ ...request,
      readers: [switchedS3, pinnedReaders[1], pinnedReaders[2]] }),
    /ZK_MULTIPROVIDER_RESTORE_DENIED/, "provider must not switch object key after owner pin validation");
    assert.equal(hits.s3, s3GetCount, "key switch fails before S3 network read");

    s3CurrentVersion = "owner-version-v0"; // identical ciphertext, old remote version
    const fallback = await gateway.restoreExact({ ...request, minimumMatchingProviders: 2 });
    assert.equal(fallback.ownerSignedProviderVersionsVerified, true);
    assert.deepEqual(fallback.verifiedProviders.map((entry) => entry.provider),
      ["gdrive", "webdav"], "wrong S3 version cannot be counted even with equal bytes");
    assert.deepEqual(fallback.failedProviders, ["s3"]);

    // A new process must enforce the same owner signature without relying on
    // local in-memory provider observations from the first attempt.
    const restarted = new Zk1MultiproviderCiphertextRestore(directGatewayPins);
    webdavCurrentEtag = '"opaque-v0"'; // bytes unchanged, ETag changed
    await assert.rejects(restarted.restoreExact({ ...request, minimumMatchingProviders: 2 }),
      /ZK_MULTIPROVIDER_RESTORE_DENIED/,
      "Drive alone cannot satisfy quorum if remote S3 version and WebDAV ETag rolled back");
    s3CurrentVersion = "owner-version-v1";
    const recovered = await restarted.restoreExact({ ...request, minimumMatchingProviders: 2 });
    assert.deepEqual(recovered.verifiedProviders.map((entry) => entry.provider),
      ["s3", "gdrive"], "owner-pinned S3 version is usable after restart");
    s3CurrentVersion = "owner-version-v0";
    stores.drive.set(driveId, Buffer.alloc(ciphertext.length, 0xbb));
    await assert.rejects(restarted.restoreExact({ ...request, minimumMatchingProviders: 2 }),
      /ZK_MULTIPROVIDER_RESTORE_DENIED/,
      "digest-tampered Drive plus two stale version peers never release bytes");
    stores.drive.set(driveId, Buffer.from(ciphertext));
    s3CurrentVersion = "owner-version-v1";
    webdavCurrentEtag = '"opaque-v1"';
  });

  await t.test("a prior S3 GET loses quorum when later Drive GET rebinds its principal or namespace", async () => {
    for (const changed of ["principal", "namespace"]) {
      let rebound = false;
      let s3Downloads = 0;
      const s3 = { ...readers[0], cloudReader: {
        ...readers[0].cloudReader,
        async resolveInventoryContext() {
          return rebound && changed === "principal" ? "f".repeat(64)
            : s3Adapter.resolveInventoryContext();
        },
        zk1StorageNamespace() {
          return rebound && changed === "namespace" ? "e".repeat(64)
            : s3Adapter.zk1StorageNamespace();
        },
        async download(...args) {
          s3Downloads++;
          return s3Adapter.download(...args);
        },
      } };
      const drive = { ...readers[1], cloudReader: {
        ...readers[1].cloudReader,
        async download(...args) {
          const result = await driveAdapter.download(...args);
          rebound = true;
          return result;
        },
      } };
      try {
        await assert.rejects(gateway.restoreExact({ ...recoverInput,
          readers: [s3, drive, readers[2]], minimumMatchingProviders: 2 }),
        /ZK_MULTIPROVIDER_RESTORE_DENIED/,
        `stale S3 ${changed} must not count even with identical owner-pinned ciphertext`);
        assert.equal(s3Downloads, 1, `S3 ${changed} changed only after its valid GET`);
      } finally { rebound = false; }
    }
    const clean = await gateway.restoreExact(recoverInput);
    assert.deepEqual(clean.verifiedProviders.map((entry) => entry.provider), ["s3", "gdrive"]);
  });

  await t.test("last owner authorization check cannot leave stale provider counted", async () => {
    let changed = false;
    let calls = 0;
    const specific = new Zk1MultiproviderCiphertextRestore({ ...directGatewayPins,
      assertCurrentAuthorization: async (...args) => {
        calls++;
        if (calls === 2) changed = true;
        return directGatewayPins.assertCurrentAuthorization(...args);
      },
    });
    const s3 = { ...readers[0], cloudReader: { ...readers[0].cloudReader,
      async resolveInventoryContext() {
        return changed ? "d".repeat(64) : s3Adapter.resolveInventoryContext();
      },
    } };
    try {
      await assert.rejects(specific.restoreExact({ ...recoverInput,
        readers: [s3, readers[1], readers[2]] }), /ZK_MULTIPROVIDER_RESTORE_DENIED/,
      "quorum needs one final provider recheck after fresh owner state");
      assert.equal(calls >= 2, true, "the second owner check was executed");
    } finally { changed = false; }
  });

  await t.test("a verified 2/3 ciphertext quorum never waits on silent third provider", async () => {
    let thirdCalled = 0;
    const slow = { ...readers[2], cloudReader: { ...readers[2].cloudReader,
      async download() { thirdCalled++; return new Promise(() => {}); } } };
    const opened = await gateway.restoreExact({ ...recoverInput,
      readers: [readers[0], readers[1], slow] });
    assert.deepEqual(opened.ciphertext, ciphertext);
    assert.equal(opened.verifiedProviders.length, 2);
    assert.equal(thirdCalled, 0);
  });

  await t.test("silent first cloud GET observes abort and fails closed on absolute deadline", async () => {
    let aborted = false;
    const silent = { ...readers[0], cloudReader: { ...readers[0].cloudReader,
      download(_folder, _name, _destination, _area, _allowWrite, opts) {
        return new Promise((_, reject) => {
          opts.abortSignal.addEventListener("abort", () => {
            aborted = true; reject(new Error("cancelled"));
          }, { once: true });
        });
      } } };
    const timed = new Zk1MultiproviderCiphertextRestore({ ...directGatewayPins,
      ioDeadlineMs: 100 });
    await assert.rejects(timed.restoreExact({ ...recoverInput,
      readers: [silent, readers[1], readers[2]] }), /ZK_MULTIPROVIDER_RESTORE_DENIED/);
    assert.equal(aborted, true);
  });

  await t.test("client abort fences provider IO and releases no bytes", async () => {
    let aborted = false;
    const controller = new AbortController();
    const silent = { ...readers[0], cloudReader: { ...readers[0].cloudReader,
      download(_folder, _name, _destination, _area, _allowWrite, opts) {
        return new Promise((_, reject) => {
          opts.abortSignal.addEventListener("abort", () => {
            aborted = true; reject(new Error("client disconnected"));
          }, { once: true });
        });
      } } };
    const request = gateway.restoreExact({ ...recoverInput,
      readers: [silent, readers[1], readers[2]] }, { abortSignal: controller.signal });
    setTimeout(() => controller.abort(), 100);
    await assert.rejects(request, /ZK_MULTIPROVIDER_RESTORE_DENIED/);
    assert.equal(aborted, true);
  });

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
      assert.equal(opened.verifiedProviders.length, 2);

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
  for (const target of catalogTargets) target.domainAttestation = attest(target);
  const publishInput = { scope, operationId: operation.operation_id,
    signedCatalog, writers: catalogTargets, providerDomainPinset };
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
    provider, pinnedDriveFileId, domainAttestation }) => ({ cloudReader: cloudWriter,
    expectedContext, provider, pinnedDriveFileId, domainAttestation }));
  const verifiedSidecarReadback = await verifyPublishedSignedCatalogSidecars({
    scope, operationId: operation.operation_id, signedCatalog,
    readers: catalogReaders, minimumMatchingProviders: 2, providerDomainPinset,
    deadlineMs: 5000, observationOnly: true });
  assert.equal(verifiedSidecarReadback.status, "SIGNED_CATALOG_EXACT_REMOTE_REREAD_OBSERVATION");
  assert.equal(verifiedSidecarReadback.readbackMatched, true);
  assert.equal(verifiedSidecarReadback.authorizesIo, false);
  assert.equal(verifiedSidecarReadback.remoteDurabilityProven, false);
  assert.equal(verifiedSidecarReadback.coherentProviderIdentityQuorumProven, false);
  const remoteRecovery = { scope, operation, catalogReaders,
    readers, minimumMatchingProviders: 2, minimumMatchingCatalogProviders: 2 };

  await t.test("signed catalog 2/3 quorum skips a silent third provider", async () => {
    let thirdCalled = 0;
    const slow = { ...catalogReaders[2], cloudReader: { ...catalogReaders[2].cloudReader,
      async download() { thirdCalled++; return new Promise(() => {}); } } };
    const restored = await recoverSignedCatalogSidecar({ scope,
      operationId: operation.operation_id, readers: [catalogReaders[0], catalogReaders[1], slow],
      providerDomainPinset, deadlineMs: 500, observationOnly: true });
    assert.equal(restored.matchingCount, 2);
    assert.equal(restored.coherentProviderIdentityQuorumProven, false);
    assert.equal(thirdCalled, 0);
  });
  await t.test("signed catalog quorum recovers a real shorter-than-cap WebDAV sidecar when S3 is unavailable", async () => {
    let firstCalled = 0;
    const unavailableS3 = { ...catalogReaders[0], cloudReader: {
      ...catalogReaders[0].cloudReader,
      async download() { firstCalled += 1; throw new Error("S3 unavailable"); },
    } };
    // Drive HTTPS + WebDAV mTLS must be a viable quorum for a normal signed
    // catalog whose valid encoded length is much smaller than the wire cap.
    // Previously WebDAV used maxBytes as an exact size and refused this GET.
    const restored = await recoverSignedCatalogSidecar({ scope,
      operationId: operation.operation_id,
      readers: [unavailableS3, catalogReaders[1], catalogReaders[2]],
      providerDomainPinset, deadlineMs: 5000, observationOnly: true });
    assert.equal(firstCalled, 1);
    assert.equal(restored.matchingCount, 2);
  });

  await t.test("signed sidecar refuses a provider that never sends a byte", async () => {
    let aborted = false;
    const slow = { ...catalogReaders[0], cloudReader: { ...catalogReaders[0].cloudReader,
      download(_folder, _name, _destination, _area, _allowWrite, opts) {
        return new Promise((_, reject) => opts.abortSignal.addEventListener("abort", () => {
          aborted = true; reject(new Error("cancelled"));
        }, { once: true }));
      } } };
    await assert.rejects(recoverSignedCatalogSidecar({ scope,
      operationId: operation.operation_id, readers: [slow, catalogReaders[1]],
      providerDomainPinset, deadlineMs: 100,
      observationOnly: true }), /ZK_SIGNED_CATALOG_SIDECAR_DENIED/);
    assert.equal(aborted, true);
  });
  const sidecar = zk1CatalogSidecarAddress(scope, operation.operation_id);
  const catalogWebdavKey = `/dav/${webdavAdapter.key(sidecar.folder, sidecar.name, "uploads")}`;
  const catalogDriveData = Buffer.from(stores.drive.get(catalogDriveId));
  assert.ok(catalogDriveData.length < 1024 * 1024,
    "this end-to-end sample must exercise normal signed sidecars below the maximum wire cap");
  await t.test("ordinary WebDAV ciphertext GET still demands exact bytes without catalog-only cap mode", async () => {
    const destination = path.join(dir, "strict-exact-ciphertext.ct");
    await assert.rejects(webdavAdapter.download(sidecar.folder, sidecar.name,
      destination, "uploads", () => true, { maxBytes: catalogDriveData.length + 1 }),
    /ZK_WEBDAV_CIPHERTEXT_UNAVAILABLE/,
    "unsigned upper bounds must not silently relax the default exact ciphertext readback");
    assert.equal(fs.existsSync(destination), false);
  });

  let session = true;
  const handler = createZk1MultiproviderRestoreGetHandler({ gateway,
    pinnedOperationId: operation.operation_id,
    restoreInput: { mode: "cloud-catalog", request: remoteRecovery },
    authorizeHttpRequest: async (request) => ({
      authorized: Boolean(session && request.headers.authorization === "Bearer ephemeral-test-session"),
      deviceId: grantFields.device_id, authorizationKeyId: deviceKeyId,
    }) });
  assert.throws(() => createZk1MultiproviderRestoreGetHandler({ gateway,
    pinnedOperationId: random(16),
    restoreInput: { mode: "cloud-catalog", request: remoteRecovery },
    authorizeHttpRequest: async () => ({ authorized: true,
      deviceId: grantFields.device_id, authorizationKeyId: deviceKeyId }),
  }), /ZK_MULTIPROVIDER_RESTORE_DENIED/,
  "low-level route must pin the exact signed operation before serving requests");
  const app = http.createServer(handler);
  const appPort = await register(app);
  const url = `http://127.0.0.1:${appPort}/zk1-recovery/${b64(operation.operation_id)}`;
  const sendGet = () => fetch(url, { headers: { authorization: "Bearer ephemeral-test-session" } });
  assert.equal((await fetch(url)).status, 403, "unauthenticated GET must be blocked");
  const result = await sendGet();
  assert.equal(result.status, 200, "two independently verified remote bytes permit client transfer");
  assert.equal(result.headers.get("cache-control"), "no-store");
  const body = await result.json();
  assert.equal(body.providerCount, 2);
  assert.equal(body.signedCommittedProof, b64(proof));
  assert.equal(body.signedSnapshot, b64(signedCurrent.bytes));
  assert.equal(body.operationId, b64(operation.operation_id));
  assert.equal(body.signedCatalogRecoveredFromRemote, true);
  assert.deepEqual(Buffer.from(body.ciphertextBase64, "base64url"), ciphertext);
  assert.equal(body.remoteDurabilityProven, false);
  assert.equal(gateway.checkRequesterDeviceIdentity(true), false,
    "a Boolean HTTP authorization result is never a device identity");
  assert.equal(gateway.checkRequesterDeviceIdentity({ authorized: true,
    deviceId: "foreign-device", authorizationKeyId: deviceKeyId }), false);
  assert.equal(gateway.checkRequesterDeviceIdentity({ authorized: true,
    deviceId: grantFields.device_id, authorizationKeyId: deviceKeyId }), true);
  // Unlike the Express protected-object route, this lower-level, opt-in GET
  // gateway has its own final response egress boundary. A device may be
  // revoked AFTER the remote provider quorum has returned identical bytes,
  // while the HTTP identity callback is still in flight. Its response must
  // never emit ciphertext using only the earlier owner-state proof.
  freshAttack = "revoke-on-final-egress";
  finalEgressStatusReads = 0;
  const readsBeforeRevokedEgress = { ...hits };
  const revokedAtGatewayEgress = await sendGet();
  assert.equal(revokedAtGatewayEgress.status, 403,
    "low-level recovery GET must revalidate owner/device after provider quorum");
  assert.equal((await revokedAtGatewayEgress.text()).includes("ciphertextBase64"), false);
  assert.equal(finalEgressStatusReads, 4,
    "low-level gateway must make the final, independently signed owner-state check");
  assert.ok(hits.s3 > readsBeforeRevokedEgress.s3,
    "revocation adversary must activate only after genuine remote GET");
  freshAttack = null;
  for (const attack of ["replay", "wrong-nonce", "expired", "forged"]) {
    const before = { ...hits };
    freshAttack = attack;
    assert.equal((await sendGet()).status, 403, attack + " owner-state cannot release ciphertext");
    assert.deepEqual(hits, before, attack + " fails before cloud GET");
  }
  freshAttack = null;
  for (const [label, fake] of [
    ["cloned administrator identity", { ...readers[1],
      domainAttestation: { ...readers[1].domainAttestation,
        trust_domain_id: readers[0].domainAttestation.trust_domain_id } }],
    ["wrong provider admin signature", { ...readers[1],
      domainAttestation: { ...readers[1].domainAttestation,
        signature: readers[0].domainAttestation.signature } }],
    ["expired provider cert", { ...readers[1],
      domainAttestation: { ...readers[1].domainAttestation,
        expires_at: 1 } }],
    ["wrong namespace from cloned adapter", { ...readers[1],
      cloudReader: { ...readers[1].cloudReader,
        zk1StorageNamespace: readers[0].cloudReader.zk1StorageNamespace.bind(readers[0].cloudReader) } }],
  ]) {
    const before = { ...hits };
    await assert.rejects(gateway.restoreExact({ ...recoverInput,
      readers: [readers[0], fake, readers[2]] }),
    /ZK_MULTIPROVIDER_RESTORE_DENIED/, label);
    assert.deepEqual(hits, before, label + " fails before provider GET");
  }
  const beforeForeignScope = { ...hits };
  await assert.rejects(gateway.restoreExact({ ...recoverInput,
    scope: { ...scope, account_id: random(16) } }),
  /ZK_MULTIPROVIDER_RESTORE_DENIED/,
  "owner-signed root scope must match inventory/account rather than just object/root");
  assert.deepEqual(hits, beforeForeignScope, "foreign account blocked before network");
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
    independentOwnerSpkiSha256: spkiFingerprint(ownerKeys.publicKey),
    providerDomainPinset, signedCurrentDeviceGrant, fetchFreshSignedDeviceState,
  };
  const signedRestoreInput = { mode: "cloud-catalog", request: remoteRecovery };
  const expressApp = express();
  // Exercise the same opt-in global-parser selection that server.js uses.
  expressApp.use((req, res, next) => shouldDeferZk1JsonParsing(req, {
    contentConfig: "opted-in-config", environment: "test",
  }) ? next() : express.json()(req, res, next));
  const invalidStrictPins = [
    ["missing domain pin", Object.fromEntries(Object.entries(gatewayPins)
      .filter(([name]) => name !== "providerDomainPinset"))],
    ["null domain pin", { ...gatewayPins, providerDomainPinset: null }],
    ["forged domain pin class", { ...gatewayPins, providerDomainPinset: { verify: () => true } }],
    ["missing signed device grant", Object.fromEntries(Object.entries(gatewayPins)
      .filter(([name]) => name !== "signedCurrentDeviceGrant"))],
    ["missing fresh device authority", Object.fromEntries(Object.entries(gatewayPins)
      .filter(([name]) => name !== "fetchFreshSignedDeviceState"))],
    ["caller-provided active authorization", { ...gatewayPins,
      assertCurrentAuthorization: async () => ({ active: true }) }],
    ["forged owner pin", { ...gatewayPins,
      independentOwnerSpkiSha256: random(32).toString("hex") }],
    ["unsigned provider mode injection", { ...gatewayPins,
      providerTrustMode: "protected-store-logical-only" }],
  ];
  for (const [label, invalidPins] of invalidStrictPins) {
    assert.throws(() => registerZk1ProtectedObjectRoutes({
      app: express(), store: protectedStore, authenticate: authMiddleware,
      requirePermission: createRequirePermission(), resolveTrustedScope: allowedScope,
      multiproviderRestore: { gatewayPins: invalidPins, restoreInput: signedRestoreInput },
      environment: "test",
    }), /ZK_MULTIPROVIDER_HTTP_DENIED/, label + " must fail closed in dev");
  }
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
  expressApp.use((error, _req, res, _next) => res.status(error.status || 500).end());
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
  const overGlobalLimit = JSON.stringify({ padding: "A".repeat(120_000) });
  const unauthenticatedOversized = await fetch(secureUrl, { method: "POST",
    headers: { "content-type": "application/json" }, body: overGlobalLimit });
  assert.equal(unauthenticatedOversized.status, 401,
    "unauthenticated recovery must reject before consuming a large JSON body");
  const authenticatedOversized = await fetch(secureUrl, { method: "POST",
    headers: sessionHeaders, body: JSON.stringify({ padding: "A".repeat(9_000) }) });
  assert.equal(authenticatedOversized.status, 413,
    "authenticated recovery must enforce its local 8 KB parser limit");
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
  assert.equal(authorizedBody.administratorSignaturesVerified, true);
  assert.equal(authorizedBody.providerPhysicalIndependenceProven, false);
  // Remove all owner pins from the server's closure, leaving otherwise valid
  // device/session/CAS admission, sidecar, bytes and remote provider domains.
  // Historical versions retain the exact ciphertext digest: only signed
  // VersionId/ETag enforcement can distinguish the stale copies.
  const pinnedRemoteReaders = remoteRecovery.readers;
  remoteRecovery.readers = readers.map(({ ownerSignedVersionPin, ...reader }) => reader);
  s3CurrentVersion = "owner-version-v0";
  webdavCurrentEtag = '"opaque-v0"';
  const beforeHttpStrip = { ...hits };
  const strippedHttp = await post(await makeSignedRequest());
  assert.equal(strippedHttp.status, 403,
    "authenticated Express POST must reject removal of every owner version signature");
  assert.equal((await strippedHttp.text()).includes("ciphertextBase64"), false);
  assert.equal((await sendGet()).status, 403,
    "dedicated GET handler must also reject stripped owner versions");
  assert.deepEqual(hits, beforeHttpStrip,
    "stripped owner pins must deny before remote sidecar or ciphertext GET");
  remoteRecovery.readers = pinnedRemoteReaders;
  s3CurrentVersion = "owner-version-v1";
  webdavCurrentEtag = '"opaque-v1"';
  // Same real Express signed POST must survive one corrupt ciphertext provider,
  // but a second unavailable peer leaves no 2/3 byte quorum.
  const intactWebdav = Buffer.from(stores.webdav.get(`/dav/${davKey}`));
  stores.webdav.set(`/dav/${davKey}`, Buffer.alloc(ciphertext.length, 0x91));
  const oneCorrupt = await post(await makeSignedRequest());
  assert.equal(oneCorrupt.status, 200, "one bad provider still leaves 2/3 real HTTP restore");
  assert.equal((await oneCorrupt.json()).providerCount, 2);
  stores.drive.delete(driveId);
  const noQuorum = await post(await makeSignedRequest());
  assert.equal(noQuorum.status, 403, "corrupt WebDAV plus missing Drive never releases ciphertext");
  assert.equal((await noQuorum.text()).includes("ciphertextBase64"), false);
  stores.drive.set(driveId, Buffer.from(ciphertext));
  stores.webdav.set(`/dav/${davKey}`, intactWebdav);

  // A provider can answer HTTP 206 with exactly the signed bytes while its
  // object has a larger physical representation. That is not an exact remote
  // copy and must not count as either member of the 2/3 restore quorum.
  stores.drive.delete(driveId);
  partialS3CiphertextGet = true;
  const s3Partial = await post(await makeSignedRequest());
  assert.equal(s3Partial.status, 403,
    "S3 partial HTTP 206 plus valid WebDAV cannot claim two complete copies");
  assert.equal((await s3Partial.text()).includes("ciphertextBase64"), false);
  partialS3CiphertextGet = false;
  stores.drive.set(driveId, Buffer.from(ciphertext));
  stores.s3.delete(`/quorum-fixture/${s3Key}`);
  partialDriveCiphertextGet = true;
  const drivePartial = await post(await makeSignedRequest());
  assert.equal(drivePartial.status, 403,
    "Drive partial HTTPS 206 plus valid mTLS WebDAV cannot release ciphertext");
  assert.equal((await drivePartial.text()).includes("ciphertextBase64"), false);
  partialDriveCiphertextGet = false;
  stores.s3.set(`/quorum-fixture/${s3Key}`, Buffer.from(ciphertext));

  // A different device ID can have a syntactically valid OWNER signature,
  // the same private key and a valid fresh owner ACTIVE response. The actual
  // signed V2 manifest/device selected by protectedStore must still match.
  const differentDevice = { ...grantFields, device_id: "different-approved-device" };
  const differentSignature = b64(crypto.sign(null, Buffer.concat([
    GRANT_DOMAIN, Buffer.from(JSON.stringify(Object.fromEntries(
      GRANT_FIELDS.map((name) => [name, differentDevice[name]])))),
  ]), ownerKeys.privateKey));
  const differentSignedGrant = { ...differentDevice, signature: differentSignature };
  const mismatchedGatewayPins = { ...gatewayPins,
    signedCurrentDeviceGrant: differentSignedGrant,
    fetchFreshSignedDeviceState: async (challenge) => {
      const answer = await fetchFreshSignedDeviceState(challenge);
      const boundDeviceProof = Buffer.concat([
        POP_DOMAIN, Buffer.from(challenge.nonce, "base64url"),
        Buffer.from(challenge.operationId, "base64url"),
        Buffer.from(differentSignature, "base64url"),
      ]);
      return { ...answer, deviceProofOfPossession: b64(crypto.sign(null,
        boundDeviceProof, deviceKeys.privateKey)) };
    },
  };
  const mismatchedApp = express();
  registerZk1ProtectedObjectRoutes({
    app: mismatchedApp, store: protectedStore, authenticate: authMiddleware,
    requirePermission: createRequirePermission(), resolveTrustedScope: allowedScope,
    multiproviderRestore: { gatewayPins: mismatchedGatewayPins,
      restoreInput: signedRestoreInput }, environment: "test",
  });
  const mismatchedPort = await register(http.createServer(mismatchedApp));
  const mismatchedResponse = await fetch(
    `http://127.0.0.1:${mismatchedPort}/zk-1/v1/multiprovider-restore/read`,
    { method: "POST", headers: sessionHeaders,
      body: JSON.stringify(await makeSignedRequest()) });
  assert.equal(mismatchedResponse.status, 403,
    "a properly signed alternate device grant cannot borrow a V2 device identity");
  assert.equal((await mismatchedResponse.text()).includes("ciphertextBase64"), false);

  let afterSuccess = { ...hits };
  for (const attack of ["replay", "wrong-nonce", "expired", "forged"]) {
    freshAttack = attack;
    const before = { ...hits };
    const hostile = await post(await makeSignedRequest());
    assert.equal(hostile.status, 403, attack + " owner proof must deny authenticated HTTP");
    assert.equal((await hostile.text()).includes("ciphertextBase64"), false);
    assert.deepEqual(hits, before, attack + " must fail before cloud reads");
  }
  freshAttack = null;
  finalEgressStatusReads = 0;
  freshAttack = "revoke-on-final-egress";
  const beforeLateRevocation = { ...hits };
  const lateRevocation = await post(await makeSignedRequest());
  assert.equal(lateRevocation.status, 403,
    "a device revoked after cloud quorum but before Express egress must fail closed");
  assert.equal((await lateRevocation.text()).includes("ciphertextBase64"), false);
  assert.equal(finalEgressStatusReads, 4,
    "final egress MUST perform a fourth independently signed owner state check");
  assert.ok(hits.s3 > beforeLateRevocation.s3,
    "prove adversarial revocation happened only AFTER actual cloud reads");
  freshAttack = null;
  afterSuccess = { ...hits };
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
