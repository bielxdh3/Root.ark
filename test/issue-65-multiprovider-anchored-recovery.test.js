"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");
const { Readable } = require("node:stream");
const { runOfflineSigner } =
  require("./support/issue-65-owner-inventory-offline-runner");
const { checkpointDigest } = require("../src/crypto/rootark-zk1-owner-inventory-trust-head");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { privateAuthorityDirectory } =
  require("./support/issue-65-private-authority-directory");
const { createZk1WebdavCiphertextAdapter } =
  require("../src/services/zk1WebdavCiphertextAdapter");
const { computeZk1CiphertextRoot } =
  require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1DurableContentInventoryLedger } =
  require("../src/services/zk1DurableContentInventoryLedger");
const { Zk1PgPhysicalInventoryBridge } =
  require("../src/services/zk1PgPhysicalInventoryBridge");
const { signCommittedPhysicalReadback } =
  require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { Zk1SharedPgCiphertextSink } =
  require("../src/services/zk1SharedPgCiphertextSink");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../src/services/zk1SharedPgPhysicalCiphertextVerifier");
const { Zk1SharedPgPhysicalInventoryIntent } =
  require("../src/services/zk1SharedPgPhysicalInventoryIntent");
const { Zk1CloudCiphertextCopyPublisher } =
  require("../src/services/zk1CloudCiphertextCopyPublisher");
const { Zk1CloudCiphertextReadbackVerifier } =
  require("../src/services/zk1CloudCiphertextReadbackVerifier");

test("anchored signed operation reconciles lost ACK, partial three-provider copy and restart with real WebDAV HTTPS", async (t) => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = "development";
  t.after(() => { if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous; });
  // The SQLite authority opens WAL/SHM by pathname: its disposable test root
  // must satisfy the same native-private ACL as a real Windows authority.
  const directory = privateAuthorityDirectory("zk65-multiprovider-restart-");
  generateNativeFixtureCertificates(directory, { caSubject: "Recovery CA",
    servers: ["server"], clients: ["client"] });
  const read = (name) => fs.readFileSync(path.join(directory, name), "utf8");
  const ca = read("ca.pem");
  const serverCert = read("server.pem");
  const webdavStorage = new Map();
  const webdavRequests = [];
  let webdavPartitioned = false;
  const sockets = new Set();
  const server = https.createServer({ key: read("server.key"), cert: serverCert,
    ca, requestCert: true, rejectUnauthorized: true }, (req, res) => {
    webdavRequests.push(req.method);
    if (webdavPartitioned) {
      req.resume(); res.writeHead(503); res.end(); return;
    }
    if (req.method === "PUT") {
      const data = [];
      req.on("data", (chunk) => data.push(chunk));
      req.on("end", () => { webdavStorage.set(req.url, Buffer.concat(data));
        res.writeHead(201); res.end(); });
    } else if (req.method === "GET") {
      if (!webdavStorage.has(req.url)) { res.writeHead(404); res.end(); return; }
      res.writeHead(200); res.end(webdavStorage.get(req.url));
    } else { res.writeHead(405); res.end(); }
  });
  server.on("connection", (socket) => { sockets.add(socket);
    socket.on("close", () => sockets.delete(socket)); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve)); });

  const keys = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(5), keyring_id: crypto.randomBytes(16) };
  const signerKeyId = crypto.randomBytes(16);
  const dbPath = path.join(directory, "inventory.sqlite");
  const ledger = await Zk1DurableContentInventoryLedger.open(dbPath, {
    bootstrapNew: true, signerKeyId, signerPrivateKey: keys.privateKey, scope });
  t.after(() => ledger.close());
  // Cleanup hooks are called in registration order on Windows. Close the
  // HTTPS listener and SQLite handle before removing the disposable folder.
  t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5 }));
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const floor = { minimumHead: { sequence: 0, root: Buffer.from(genesis.root) },
    minimumSnapshot: Buffer.from(genesis.bytes) };
  const chunks = [crypto.randomBytes(61), crypto.randomBytes(103)];
  const cipher = Buffer.concat(chunks);
  const sha = crypto.createHash("sha256").update(cipher).digest();
  const root = computeZk1CiphertextRoot(chunks);
  const operation = { operation_id: crypto.randomBytes(16),
    expected_sequence: 0, expected_root: Buffer.from(genesis.root),
    object_id: crypto.randomBytes(16), revision: 1, epoch: 1,
    ciphertext_sha256: sha };
  assert.equal((await ledger.append(operation)).status, "committed");
  const ownerCurrent = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const now = Math.floor(Date.now() / 1000);
  const offline = await runOfflineSigner({
    scope: Object.fromEntries(Object.entries(scope).map(([name, value]) =>
      [name, value.toString("base64url")])),
    inventorySignerKeyId: signerKeyId.toString("base64url"),
    inventorySpkiSha256: crypto.createHash("sha256")
      .update(keys.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
    heads: [
      { sequence: genesis.sequence, root: genesis.root.toString("hex"),
        snapshotSha256: crypto.createHash("sha256").update(genesis.bytes).digest("hex"),
        issuedAt: now - 5, expiresAt: now + 600 },
      { sequence: ownerCurrent.sequence, root: ownerCurrent.root.toString("hex"),
        snapshotSha256: crypto.createHash("sha256").update(ownerCurrent.bytes).digest("hex"),
        issuedAt: now - 4, expiresAt: now + 600 },
    ],
  });
  const ownerPublicKey = crypto.createPublicKey({
    key: Buffer.from(offline.ownerSpki, "base64url"), type: "spki", format: "der",
  });
  const ownerEnrollment = (raised = false) => ({
    ownerPublicKey, independentOwnerSpkiSha256: offline.independentOwnerSpkiSha256,
    independentRetainedCheckpointDigest: raised
      ? offline.independentRetainedCheckpointDigest : checkpointDigest(offline.checkpoints[0]),
    checkpoints: raised ? offline.checkpoints : [offline.checkpoints[0]],
    minimumSnapshot: Buffer.from(raised ? ownerCurrent.bytes : genesis.bytes),
  });
  const expected = { scope, operation, digest: crypto.randomBytes(32),
    expectedRootHash: root, expectedChunkCount: chunks.length };
  const physicalSigner = crypto.generateKeyPairSync("ed25519");
  let currentPhysicalSigningKey = physicalSigner.privateKey;
  const makeBridge = (pinned = floor, enrolled = pinned === false ? null
    : ownerEnrollment(pinned !== floor), strictPhysical = false) => {
    // Disposable synthetic PG attestor only; the real Ed25519 SQLite ledger
    // and all remote GET/PUTs remain exercised in this isolated test.
    const verifier = Object.create(Zk1SharedPgPhysicalCiphertextVerifier.prototype);
    verifier.verifyExact = async (request) => {
      assert.deepEqual(request.scope.account_id, scope.account_id);
      return { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
        walFlushConfirmed: true, operationId: Buffer.from(operation.operation_id),
        root: Buffer.from(root), ciphertextSha256: Buffer.from(sha) };
    };
    return new Zk1PgPhysicalInventoryBridge({
      sink: Object.create(Zk1SharedPgCiphertextSink.prototype),
      intentAuthority: Object.create(Zk1SharedPgPhysicalInventoryIntent.prototype),
      verifier, ledger, pinnedPublicKey: keys.publicKey,
      pinnedSignerKeyId: signerKeyId,
      ...(strictPhysical ? {
        pinnedPhysicalAttestorPublicKey: physicalSigner.publicKey,
        attestorClient: { async requestAttestation({ scope: exactScope,
          operation: exactOperation, nonce }) {
          return signCommittedPhysicalReadback({ scope: exactScope,
            operation: exactOperation, nonce, issuedAt: Math.floor(Date.now() / 1000),
            readback: { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
              walFlushConfirmed: true, generation: 3, admissionId: crypto.randomBytes(16),
              operationId: exactOperation.operation_id, revision: exactOperation.revision,
              epoch: exactOperation.epoch,
              expectedInventorySequence: exactOperation.expected_sequence,
              expectedInventoryRoot: exactOperation.expected_root,
              digest: expected.digest, root, chunkCount: chunks.length,
              ciphertextSha256: exactOperation.ciphertext_sha256,
              authorizesIo: false, provesIndependentOperator: false },
          }, currentPhysicalSigningKey);
        } },
      } : {}),
      ...(pinned === false ? {} : { trustedInventoryFloor: pinned }),
      ...(enrolled === null ? {} : { ownerInventoryEnrollment: enrolled }),
    });
  };

  const stores = new Map(["s3", "gdrive"].map((provider) => [provider, new Map()]));
  const counts = { s3: 0, gdrive: 0 };
  let failDriveAck = true;
  const buildFixtureAdapter = (provider) => {
    const context = crypto.createHash("sha256").update(`isolated-${provider}`).digest("hex");
    const objectId = provider === "gdrive" ? "pinned-drive-id-restart" : null;
    const key = (folder, name, area) => `fixture-${provider}/${area}/${folder}/${name}`;
    const core = { enabled: () => true,
      status: () => ({ provider }), resolveInventoryContext: async () => context,
      zk1StorageNamespace: () => context, key };
    const writer = { ...core, async upload(source, folder, name, area, opts) {
      const cloudKey = key(folder, name, area);
      assert.equal(opts.zk1BoundedBytes, cipher.length);
      if (objectId) assert.equal(opts.providerFileId, objectId);
      counts[provider] += 1;
      stores.get(provider).set(cloudKey, fs.readFileSync(source));
      if (provider === "gdrive" && failDriveAck) {
        failDriveAck = false;
        throw new Error("remote persisted bytes; HTTP response lost");
      }
      return { provider, key: cloudKey, ...(objectId ? { id: objectId } : {}) };
    } };
    const reader = { ...core, async download(folder, name, destination, area, allow, opts) {
      const cloudKey = key(folder, name, area);
      const bytes = stores.get(provider).get(cloudKey);
      if (!bytes || !allow() || bytes.length > opts.maxBytes) return false;
      if (objectId) assert.equal(opts.providerFileId, objectId);
      fs.writeFileSync(destination, bytes, { flag: "wx", mode: 0o600 });
      return true;
    } };
    return { writer, reader, context, objectId };
  };
  const webdav = createZk1WebdavCiphertextAdapter({
    developmentOnlyOptIn: true,
    endpoint: `https://127.0.0.1:${server.address().port}/dav`,
    namespace: "recovery_fixture", ca,
    serverFingerprint256: new crypto.X509Certificate(serverCert).fingerprint256,
    clientCert: read("client.pem"), clientKey: read("client.key"),
  });
  const targets = [];
  for (const provider of ["s3", "gdrive", "webdav"]) {
    const f = provider === "webdav"
      ? { writer: webdav, reader: webdav,
        context: await webdav.resolveInventoryContext(), objectId: null }
      : buildFixtureAdapter(provider);
    targets.push({ cloudPublisher: new Zk1CloudCiphertextCopyPublisher({
      cloudWriter: f.writer, expectedProvider: provider,
      expectedWriterContext: f.context, pinnedDriveFileId: f.objectId }),
    cloudVerifier: new Zk1CloudCiphertextReadbackVerifier({
      cloudReader: f.reader, expectedProvider: provider,
      expectedReaderContext: f.context, pinnedDriveFileId: f.objectId }) });
  }
  const input = { physical: expected, chunks, copies: targets };
  const foreignS3 = buildFixtureAdapter("s3");
  const differentNamespace = new Zk1CloudCiphertextReadbackVerifier({
    cloudReader: { ...foreignS3.reader,
      zk1StorageNamespace: () => "f".repeat(64) },
    expectedProvider: "s3", expectedReaderContext: foreignS3.context,
  });
  await assert.rejects(makeBridge().reconcileOrPublishAnchoredCloudCopies({
    ...input, copies: [{ cloudPublisher: targets[0].cloudPublisher,
      cloudVerifier: differentNamespace }, ...targets.slice(1)],
  }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "S3 writer and reader on different physical namespaces cannot share a receipt");
  assert.deepEqual(counts, { s3: 0, gdrive: 0 });
  await assert.rejects(makeBridge(false).reconcileOrPublishAnchoredCloudCopies(input),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/, "owner floor required before network IO");
  await assert.rejects(makeBridge().reconcileOrPublishAnchoredCloudCopies(input),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/, "lost Drive ACK interrupts complete evidence");
  assert.deepEqual(counts, { s3: 1, gdrive: 1 });
  assert.equal(webdavRequests.length, 0);
  webdavPartitioned = true;
  await assert.rejects(makeBridge().reconcileOrPublishAnchoredCloudCopies(input),
    /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "partitioned third provider must not yield a successful three-copy receipt");
  assert.deepEqual(counts, { s3: 1, gdrive: 1 },
    "partition retry does not needlessly rewrite independently verified copies");
  webdavPartitioned = false;
  const replayed = await makeBridge().reconcileOrPublishAnchoredCloudCopies(input);
  assert.equal(replayed.status, "PG_SIGNED_AND_OWNER_SIGNED_CLOUD_COPIES_REREAD");
  assert.deepEqual(replayed.providers.map((r) => r.mode), [
    "reused_verified_copy", "reused_verified_copy", "republished_and_verified"]);
  assert.deepEqual(counts, { s3: 1, gdrive: 1 }, "lost-ACK replay does not duplicate PUTs");
  assert.equal(webdavRequests.filter((method) => method === "PUT").length, 2,
    "one rejected partition PUT and one successful recovery PUT");
  assert.equal(webdavStorage.size, 1);
  assert.deepEqual(replayed.providers.map((r) => r.provider), ["s3", "gdrive", "webdav"]);
  assert.equal(replayed.providers[1].providerFileId, "pinned-drive-id-restart");
  assert.ok(replayed.providers.every((r) => r.ciphertextSha256 === sha.toString("hex")));
  assert.ok(replayed.providers.every((r) => /^[a-f0-9]{64}$/.test(r.namespaceIdentity)));
  assert.match(replayed.observationDigest, /^[a-f0-9]{64}$/);
  assert.equal(replayed.authorizesIo, false);
  assert.equal(replayed.externalProviderDurabilityProven, false);
  assert.equal(replayed.ownerSignedInventoryCheckpointVerified, true);
  assert.equal(replayed.externallyPinnedCheckpointDigestMatched, true);
  assert.equal(replayed.signedOwnerCounter, 1);
  assert.equal(replayed.independentlyAnchoredFloorProven, false);
  assert.equal(replayed.externalOwnerCustodyVerified, false);
  assert.equal(Object.hasOwn(replayed, "ownerPinnedFloorChecked"), false);

  const strictBridge = makeBridge(floor, ownerEnrollment(false), true);
  const strictReadback = await strictBridge.reconcileCloudCopy({
    physical: expected, cloudVerifier: targets[0].cloudVerifier,
    chunkLengths: chunks.map((chunk) => chunk.length),
  });
  assert.equal(strictReadback.independentPhysicalAttestationVerified, true,
    "remote GET evidence must preserve separate physical attestor verification");
  assert.equal(strictReadback.physicalAttestationReceiptDigest.length, 32);
  const strictRecovery = await strictBridge.reconcileOrPublishAnchoredCloudCopies(input);
  assert.equal(strictRecovery.independentPhysicalAttestationVerified, true,
    "three-provider restart/retry evidence must carry the composite local proof");
  assert.equal(strictRecovery.externalProviderDurabilityProven, false);
  // Adversarial final-owner-verification stall: all remote copies and the
  // independent PG proof were fresh at the last reconcile, but the owner
  // checkpoint verifier's final awaited crypto crosses the 30-second bound.
  // Returning the old attestation as fresh would fabricate a current receipt.
  const delayedBridge = makeBridge(floor, ownerEnrollment(false), true);
  const cloudRead = delayedBridge.reconcileCloudCopy.bind(delayedBridge);
  let cloudChecks = 0;
  let finalSweepComplete = false;
  delayedBridge.reconcileCloudCopy = async (...args) => {
    const outcome = await cloudRead(...args);
    if (++cloudChecks === 6) finalSweepComplete = true;
    return outcome;
  };
  const physicalReconcile = delayedBridge.reconcile.bind(delayedBridge);
  const realNow = Date.now;
  const initialNow = realNow();
  let simulatedNow = initialNow;
  let crossedAfterFinalReconcile = false;
  try {
    Date.now = () => simulatedNow;
    delayedBridge.reconcile = async (...args) => {
      const result = await physicalReconcile(...args);
      if (finalSweepComplete && !crossedAfterFinalReconcile) {
        crossedAfterFinalReconcile = true;
        simulatedNow = initialNow + 31_000;
      }
      return result;
    };
    await assert.rejects(delayedBridge.reconcileOrPublishAnchoredCloudCopies(input),
      /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
      "owner verification must not return a physically expired attestation");
    assert.equal(cloudChecks, 6);
    assert.equal(crossedAfterFinalReconcile, true);
  } finally { Date.now = realNow; }
  const readsBeforeForgery = webdavRequests.length;
  currentPhysicalSigningKey = keys.privateKey;
  await assert.rejects(strictBridge.reconcileCloudCopy({ physical: expected,
    cloudVerifier: targets[2].cloudVerifier,
    chunkLengths: chunks.map((chunk) => chunk.length) }),
  /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "compromised inventory writer cannot substitute its own physical signature");
  assert.equal(webdavRequests.length, readsBeforeForgery,
    "forged local attestor proof blocks before contacting the remote provider");
  currentPhysicalSigningKey = physicalSigner.privateKey;

  // Remote tampering after success is detected; a subsequent signed retry
  // may repair only the affected current copy, and always rechecks all three.
  const s3Key = replayed.providers[0].providerObjectKey;
  stores.get("s3").set(s3Key, Buffer.alloc(cipher.length, 0xb7));
  const repaired = await makeBridge().reconcileOrPublishAnchoredCloudCopies(input);
  assert.equal(repaired.providers[0].mode, "republished_and_verified");
  assert.deepEqual(repaired.providers.slice(1).map((r) => r.mode), [
    "reused_verified_copy", "reused_verified_copy"]);
  assert.equal(counts.s3, 2);
  assert.equal(repaired.observationDigest, replayed.observationDigest,
    "observation identity remains stable for exactly the same signed bytes and provider IDs");
  const current = ownerCurrent;
  const raisedOwnerFloor = { minimumHead: { sequence: 1,
    root: Buffer.from(current.root) }, minimumSnapshot: Buffer.from(current.bytes) };
  const validRaised = await makeBridge(raisedOwnerFloor)
    .reconcileOrPublishAnchoredCloudCopies(input);
  assert.equal(validRaised.observationDigest, replayed.observationDigest);
  const originalSnapshot = ledger.getSnapshot.bind(ledger);
  ledger.getSnapshot = async () => genesis;
  const countBeforeRollback = { ...counts };
  await assert.rejects(makeBridge(raisedOwnerFloor)
    .reconcileOrPublishAnchoredCloudCopies(input), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "rollback below the independently pinned signed owner floor must block all remote IO");
  assert.deepEqual(counts, countBeforeRollback);
  ledger.getSnapshot = originalSnapshot;
  await assert.rejects(makeBridge().reconcileOrPublishAnchoredCloudCopies({
    ...input, physical: { ...expected, operation: {
      ...operation, operation_id: crypto.randomBytes(16) } } }),
  /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/, "replay with forged operation ID cannot publish");
});
