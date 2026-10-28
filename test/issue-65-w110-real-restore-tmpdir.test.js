"use strict";

const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
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
const { withInodeGrowthAfterFstat } = require("./support/issue-65-inode-growth-race");
const { verifyWindowsChunkUploadTree } = require("../services/chunkUploadWindowsAcl");
const { createZk1PrivateCloudStagingDirectory } =
  require("../src/services/zk1PrivateCloudStagingDirectory");

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
  const dir = createPrivateAuthorityFixture("zk65-full-restore-");
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
  if (process.env.W110_ATTACK === "1") {
    assert.equal(process.platform, "linux", "foreign UID restore exploit requires Linux");
    assert.equal(process.getuid?.(), 0, "foreign UID restore exploit requires root + real nobody");
    const initialTemp = process.env.TMPDIR;
    process.env.TMPDIR = process.env.W110_UNSAFE_TMPDIR;
    process.stdout.write(`W110_TEST_ENV_TEMP_MATCH=${os.tmpdir() === process.env.W110_UNSAFE_TMPDIR}\n`);
    try {
      await assert.rejects(gateway.restoreExact(recoverInput), /ZK_MULTIPROVIDER_RESTORE_DENIED/);
      assert.equal(globalThis.__w110RestoreAttack?.victimDeleted, false,
        "a foreign UID must not trigger cleanup of an unrelated owner-private directory");
      assert.equal(globalThis.__w110RestoreAttack?.stageCreated,
        process.env.W110_ATTACK_DRIFT === "1",
        "unsafe parent refuses pre-create; post-create permission drift is detected at cleanup");
      assert.equal(globalThis.__w110RestoreAttack?.swapped,
        process.env.W110_ATTACK_DRIFT === "1",
        "post-create attack must perform a real foreign UID rename/swap; no false-green on setup failure");
      assert.equal(globalThis.__w110RestoreAttack?.cleanupObserved, false,
        "cleanup must never recursively remove the substituted victim directory");
    } finally {
      process.env.TMPDIR = initialTemp;
    }
  } else {
    const result = await gateway.restoreExact(recoverInput);
    assert.deepEqual(result.ciphertext, ciphertext);
  }
});
