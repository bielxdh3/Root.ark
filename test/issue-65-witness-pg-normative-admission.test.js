"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const Database = require("better-sqlite3");
const z = require("../src/crypto/rootark-zk-1");
const contentInventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const { signCommittedPhysicalReadback } = require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { derivePhysicalChainPageNonce, derivePhysicalChainNonce } =
  require("../src/crypto/rootark-zk1-attested-inventory-commit-v1");
const { Zk1WitnessCasAnchorFloor, verifyFreshWitnessCasFloor } =
  require("../src/services/zk1WitnessCasAnchorFloor");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");
const { Zk1WitnessCasPhysicalAdmission } = require("../src/services/zk1WitnessCasPhysicalAdmission");
const { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer } =
  require("../src/services/zk1WitnessHttpsServer");
const { Zk1WitnessCasAnchorHttpsClient } =
  require("../src/services/zk1WitnessCasAnchorHttpsClient");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { Zk1DurableCasStatusLedger } =
  require("../src/services/zk1DurableCasStatusLedger");
const { createZk1PgPhysicalAttestorHttpsClient } =
  require("../src/services/zk1PgPhysicalAttestorHttpsClient");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { envelopeBinding, verifySyncV2HistoricalWitnessAdmission } =
  require("../sync-client/rootark-sync-zk1-physical-binding");
const { createExternalRecoveryHeadFixture } =
  require("./support/issue-65-external-recovery-head-fixture");

const DOMAIN = Buffer.from("Root.ark/zk-1/cas-witness-physical-owner-binding/v1\0");
const ENTRY = Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0");
const random = (n) => crypto.randomBytes(n);
const sha = (b) => crypto.createHash("sha256").update(b).digest();
const hex = (b) => sha(b).toString("hex");

async function backupPrivateWitnessFixture(db, filename) {
  await db.backup(filename);
  // better-sqlite3's backup destination inherits the process umask (usually
  // 0644 on Ubuntu). This is a disposable *authority* DB later reopened by
  // the witness's required owner-only SQLite guard; resecure the copy first.
  if (process.platform !== "win32") fs.chmodSync(filename, 0o600);
}

test("strict CAS witness floor refuses signed status advance without independent PG attestation and owner binding", async (t) => {
  const directory = createPrivateAuthorityFixture("zk65-witness-physical-");
  const externalAuthorities = [];
  t.after(() => {
    for (const authority of externalAuthorities.reverse()) authority.close();
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const status = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const owner = crypto.generateKeyPairSync("ed25519");
  const inventory = crypto.generateKeyPairSync("ed25519");
  const attestor = crypto.generateKeyPairSync("ed25519");
  const statusKeyId = random(16), witnessKeyId = random(16), inventoryKeyId = random(16);
  const scope = { account_id: random(16), compartment_id: Buffer.from("vault"),
    keyring_id: random(16) };
  const genesisSnapshot = Buffer.from(await contentInventory.createSignedSnapshot({
    signerKeyId: inventoryKeyId, privateKey: inventory.privateKey,
    scope, sequence: 0, previousRoot: null, entries: [], nonce: random(32),
  }));
  const genesisRoot = Buffer.from((await z.decodeDeterministic(genesisSnapshot)).root);
  const device = crypto.generateKeyPairSync("ed25519");
  const deviceSpki = device.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const syncEnvelope = createOperation({ operation: "create",
    operationId: "witness-historical-sync-1", objectId: "witness-historical-object-1",
    deviceId: "device-a", compartmentId: "vault", keyEpoch: "epoch-1",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "encrypted-object.bin" },
    plaintext: Buffer.from("client encrypted bytes"), fileKey: random(32) });
  syncEnvelope.authorization = await createAuthorizationProof(syncEnvelope, {
    username: "owner", privateKey: device.privateKey, publicKey: deviceSpki,
    expiresAt: Date.now() + 120000 });
  const bound = envelopeBinding(syncEnvelope, scope, 0, genesisRoot);
  const op = bound.operation;
  const requestDigest = sha(await z.encodeDeterministic(op));
  const tuple = { object_id: op.object_id, revision: op.revision,
    epoch: op.epoch, ciphertext_sha256: op.ciphertext_sha256 };
  const buildCurrentSnapshot = (nonce) => contentInventory.createSignedSnapshot({
    signerKeyId: inventoryKeyId, privateKey: inventory.privateKey,
    scope, sequence: 1, previousRoot: genesisRoot, entries: [tuple], nonce,
  });
  const root = Buffer.from((await z.decodeDeterministic(
    await buildCurrentSnapshot(random(32)))).root);
  const entryUnsigned = {
    type: "rootark-content-inventory-entry/v1", version: 1,
    signer_key_id: inventoryKeyId, scope, sequence: 1,
    previous_root: op.expected_root, root,
    operation_id: op.operation_id, expected_sequence: 0, expected_root: op.expected_root,
    request_digest: requestDigest,
    entry: { object_id: op.object_id, revision: op.revision,
      epoch: op.epoch, ciphertext_sha256: op.ciphertext_sha256 },
  };
  const receipt = Buffer.from(await z.encodeDeterministic({ ...entryUnsigned,
    signature: crypto.sign(null, Buffer.concat([ENTRY,
      Buffer.from(await z.encodeDeterministic(entryUnsigned))]), inventory.privateKey) }));
  const anchor = new Zk1CasTerminalAnchor(path.join(directory, "cas-anchor.log"), {
    bootstrapNew: true, statusKeyId, statusPrivateKey: status.privateKey,
  });
  const reservation = random(16);
  const query = { ...scope, reservation_id: reservation };
  const ticket = random(80), manifest = random(120);
  anchor.prepare(query, ticket, "committed", manifest);
  await anchor.append(query, ticket, "committed", manifest, random(64));
  const record = fs.readFileSync(anchor.filename, "utf8").trimEnd().split("\n").at(-1);
  let physicalCalls = 0;
  let inventoryCalls = 0;
  let forgeAttestor = false;
  let forkSnapshot = null;
  let forkProofs = null;
  let chainPhysicalPresent = false;
  let shiftClockAfterChain = false;
  let oldChainProof = false;
  const realDateNow = Date.now;
  const chainPhysicalProof = async (challenge) => {
    const pageNonce = derivePhysicalChainPageNonce(challenge, 0);
    const nonce = derivePhysicalChainNonce(pageNonce, 1, op.operation_id);
    return signCommittedPhysicalReadback({ scope, operation: op, nonce,
      issuedAt: Math.floor(Date.now() / 1000) - (oldChainProof ? 45 : 0),
      readback: { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
        walFlushConfirmed: true, authorizesIo: false,
        provesIndependentOperator: false, generation: 1,
        admissionId: random(16), operationId: op.operation_id,
        revision: op.revision, epoch: op.epoch,
        expectedInventorySequence: op.expected_sequence,
        expectedInventoryRoot: op.expected_root,
        ciphertextSha256: op.ciphertext_sha256,
        digest: random(32), root: random(32), chunkCount: 1 },
    }, attestor.privateKey);
  };
  const admission = new Zk1WitnessCasPhysicalAdmission({
    pinnedOwnerPublicKey: owner.publicKey,
    pinnedInventoryPublicKey: inventory.publicKey,
    pinnedInventorySignerKeyId: inventoryKeyId,
    pinnedPhysicalAttestorPublicKey: attestor.publicKey,
    trustedMinimumInventoryHead: { sequence: 0, root: genesisRoot },
    trustedMinimumInventorySnapshot: genesisSnapshot,
    physicalAttestorClient: {
      async requestAttestation({ scope: scopeArg, operation, nonce }) {
        physicalCalls += 1;
        const readback = { status: "PHYSICALLY_REREAD_PG_COMMITTED",
          verified: true, walFlushConfirmed: true, authorizesIo: false,
          provesIndependentOperator: false, generation: 1, admissionId: random(16),
          operationId: operation.operation_id, revision: operation.revision, epoch: operation.epoch,
          expectedInventorySequence: operation.expected_sequence,
          expectedInventoryRoot: operation.expected_root,
          ciphertextSha256: operation.ciphertext_sha256,
          digest: random(32), root: random(32), chunkCount: 1 };
        return signCommittedPhysicalReadback({ scope: scopeArg, operation, readback,
          nonce, issuedAt: Math.floor(Date.now() / 1000) },
        forgeAttestor ? status.privateKey : attestor.privateKey);
      },
    },
    inventoryClient: {
      async getVerifiedSnapshotWithChain({ scope: argScope, nonce }) {
        inventoryCalls += 1;
        assert.deepEqual(argScope, scope);
        const answer = { serializedSnapshot: Buffer.from(await (
          forkSnapshot ? forkSnapshot(nonce) : buildCurrentSnapshot(nonce))),
          authenticatedProofChain: forkProofs || [receipt], authorizesIo: false,
          ...(chainPhysicalPresent ? {
            authenticatedPhysicalProofChain: [await chainPhysicalProof(nonce)],
          } : {}) };
        if (shiftClockAfterChain) Date.now = () => realDateNow() + 45_000;
        return answer;
      },
    },
  });
  const floor = new Zk1WitnessCasAnchorFloor(path.join(directory, "witness-floor.sqlite"), {
    bootstrapNew: true, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission,
  });
  t.after(() => floor.close());
  assert.equal(floor.supportsClientHistoricalNonce, false,
    "legacy/non-issuer floor cannot advertise client historical nonce binding");
  const binding = { recordHash: hex(Buffer.from(record)), scope: {
    account_id: scope.account_id.toString("base64url"),
    compartment_id: scope.compartment_id.toString("base64url"),
    keyring_id: scope.keyring_id.toString("base64url"),
  }, operation: {
    operation_id: op.operation_id.toString("base64url"), expected_sequence: op.expected_sequence,
    expected_root: op.expected_root.toString("base64url"),
    object_id: op.object_id.toString("base64url"), revision: op.revision,
    epoch: op.epoch, ciphertext_sha256: op.ciphertext_sha256.toString("base64url"),
  }, inventoryReceipt: receipt.toString("base64url") };
  const signBinding = (value) => crypto.sign(null,
    Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(value))]), owner.privateKey).toString("base64url");
  const evidence = { ...binding, ownerSignature: signBinding(binding) };

  assert.throws(() => floor.advance({ records: [record] }), /WITNESS_CAS_FLOOR_DENIED/,
    "the compromised status signer cannot use the old unauthenticated path");
  await assert.rejects(floor.advanceAttested({ records: [record], evidence: [] }),
    /WITNESS_CAS_FLOOR_DENIED/);
  await assert.rejects(floor.advanceAttested({ records: [record], evidence: [{
    ...evidence, ownerSignature: signBinding({ ...binding, recordHash: "f".repeat(64) }),
  }] }), /WITNESS_CAS_FLOOR_DENIED/);
  assert.equal(physicalCalls, 0, "do not call physical attestor before owner authorization");
  forgeAttestor = true;
  await assert.rejects(floor.advanceAttested({ records: [record], evidence: [evidence] }),
    /WITNESS_CAS_FLOOR_DENIED/, "the CAS status signer cannot impersonate the physical signer");
  forgeAttestor = false;
  assert.equal(floor.head().sequence, 0, "failed evidence must not advance independent floor");
  await assert.rejects(floor.advanceAttested({ records: [record], evidence: [evidence] }),
    /WITNESS_CAS_FLOOR_DENIED/,
    "a target readback does not substitute for physical evidence on the signed chain");
  chainPhysicalPresent = true;
  oldChainProof = true;
  await assert.rejects(floor.advanceAttested({ records: [record], evidence: [evidence] }),
    /WITNESS_CAS_FLOOR_DENIED/,
  "an attestation issued before this witness's fresh challenge is not rescued by signed bytes");
  oldChainProof = false;
  shiftClockAfterChain = true;
  let result;
  try {
    result = await floor.advanceAttested({ records: [record], evidence: [evidence] });
  } finally {
    Date.now = realDateNow;
    shiftClockAfterChain = false;
  }
  assert.equal(result.sequence, 1);
  assert.equal(physicalCalls, 4,
    "each attempted new admission requires a fresh target readback");
  assert.equal(inventoryCalls, 3,
    "each authorized attempt requires its own signed inventory snapshot");
  const committedFence = await floor.proveCommittedPhysicalFence({ scope,
    operationId: op.operation_id, inventorySequence: 1, inventoryRoot: root,
    nonce: random(32) });
  assert.equal(committedFence.committedSequence, 1);
  assert.equal(committedFence.signedFloor.sequence, 1);
  assert.deepEqual(committedFence.operationId, op.operation_id);
  assert.equal(committedFence.authorizesHistoricalRead, false,
    "a durable witness floor alone is NOT a Sync historical admission receipt");
  for (const forged of [
    { operationId: random(16) }, { inventorySequence: 2 },
    { inventoryRoot: random(32) },
    { scope: { ...scope, account_id: random(16) } },
    { nonce: random(31) },
  ]) {
    await assert.rejects(floor.proveCommittedPhysicalFence({ scope,
      operationId: op.operation_id, inventorySequence: 1, inventoryRoot: root,
      nonce: random(32), ...forged }), /WITNESS_CAS_FLOOR_DENIED/);
  }
  // The separately provisioned historical issuer persists the exact Sync
  // envelope receipt only AFTER an independently attested physical CAS event.
  // A forged writer ACK, unrelated physical operation or user-supplied floor
  // cannot manufacture this witness-signed admission.
  const historicalFilename = path.join(directory, "witness-historical-sync.sqlite");
  let trustedDeviceRevocations = [];
  let advanceClockOnPolicyRefresh = false;
  let policyRefreshCount = 0;
  let policyRefreshExpired = false;
  const trustedSyncDevicePolicyProvider = () => {
    if (advanceClockOnPolicyRefresh && ++policyRefreshCount === 2) {
      policyRefreshExpired = true;
      Date.now = () => syncEnvelope.authorization.expiresAt + 1;
    }
    return { username: "owner", trustedDevicePublicKeys: { "device-a": deviceSpki },
      revokedDeviceIds: [...trustedDeviceRevocations] };
  };
  const historicalOptions = {
    witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission,
    enableSyncHistoricalIssuer: true, trustedSyncDevicePolicyProvider,
  };
  const externalRecovery = createExternalRecoveryHeadFixture(
    path.join(directory, "operator-outside-witness-recovery-head.sqlite"));
  externalAuthorities.push(externalRecovery);
  historicalOptions.trustedRecoveryNonceAuthority = externalRecovery.authority;
  assert.throws(() => new Zk1WitnessCasAnchorFloor(
    path.join(directory, "forbidden-policyless-issuer.sqlite"), {
      witnessKeyId, witnessPrivateKey: witness.privateKey,
      statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission,
      enableSyncHistoricalIssuer: true, bootstrapNew: true,
    }), /WITNESS_CAS_FLOOR_DENIED/,
  "historical issuer must never bootstrap without an operator-controlled policy source");
  assert.throws(() => new Zk1WitnessCasAnchorFloor(
    path.join(directory, "forbidden-rollback-bootstrap.sqlite"), {
      ...historicalOptions, bootstrapNew: true,
      trustedHistoricalAdmissionHead: { sequence: 1, lastHash: "f".repeat(64) },
    }), /WITNESS_CAS_FLOOR_DENIED/,
  "bootstrap must reject a nonzero externally pinned historical high-water");
  let historical = new Zk1WitnessCasAnchorFloor(historicalFilename, {
    ...historicalOptions, bootstrapNew: true });
  assert.equal(historical.supportsClientHistoricalNonce, true,
    "only strict active issuer can satisfy the independent transport capability guard");
  await historical.advanceAttested({ records: [record], evidence: [evidence] });
  const historicalChallenge = random(32);
  const issueInput = { envelope: syncEnvelope, scope, expectedSequence: 0,
    expectedRoot: genesisRoot, inventoryReceipt: receipt, nonce: historicalChallenge };
  externalRecovery.setAvailable(false);
  assert.equal(historical.supportsClientHistoricalNonce, false);
  await assert.rejects(historical.issueSyncHistoricalAdmission(issueInput),
    /WITNESS_CAS_FLOOR_DENIED/,
    "issuer cannot perform its FIRST signed admission when external operator floor is down");
  externalRecovery.setAvailable(true);
  assert.deepEqual(historical.historicalAdmissionHead(), {
    sequence: 0, lastHash: "0".repeat(64) });
  await assert.rejects(historical.issueSyncHistoricalAdmission({ ...issueInput,
    nonce: random(31) }), /WITNESS_CAS_FLOOR_DENIED/,
  "historical admission must reject malformed caller challenges before physical IO");
  await assert.rejects(historical.issueSyncHistoricalAdmission({ ...issueInput,
    nonce: undefined }), /WITNESS_CAS_FLOOR_DENIED/,
  "no witness-generated nonce may replace a missing client's challenge");
  await assert.rejects(historical.issueSyncHistoricalAdmission({ ...issueInput,
    localTrustedDevicePolicy: { username: "owner", trustedDevicePublicKeys: {
      "device-a": deviceSpki }, revokedDeviceIds: [] } }), /WITNESS_CAS_FLOOR_DENIED/,
  "caller-selected device policy is not a trusted witness configuration");
  trustedDeviceRevocations = ["device-a"];
  await assert.rejects(historical.issueSyncHistoricalAdmission(issueInput),
    /WITNESS_CAS_FLOOR_DENIED/, "an owner-revoked device cannot issue historical receipts");
  trustedDeviceRevocations = [];
  await assert.rejects(historical.issueSyncHistoricalAdmission({ ...issueInput,
    inventoryReceipt: Buffer.from("untrusted-user-ACK") }),
  /WITNESS_CAS_FLOOR_DENIED/);
  assert.deepEqual(historical.historicalAdmissionHead(), {
    sequence: 0, lastHash: "0".repeat(64) });
  // A successfully completed witness Ed25519 signature is NOT enough: the
  // device authorization may expire before the durable SQLite INSERT.
  const originalWitnessSign = crypto.sign;
  const originalClock = Date.now;
  const expiryDomain = Buffer.from("Root.ark/sync-v2/historical-witness-admission/v1\0");
  let signedBeforeExpiry = false;
  crypto.sign = (...args) => {
    const signed = originalWitnessSign(...args);
    if (Buffer.isBuffer(args[1]) && args[1].subarray(0, expiryDomain.length).equals(expiryDomain)) {
      signedBeforeExpiry = true;
      Date.now = () => syncEnvelope.authorization.expiresAt + 1;
    }
    return signed;
  };
  try {
    await assert.rejects(historical.issueSyncHistoricalAdmission(issueInput),
      /WITNESS_CAS_FLOOR_DENIED/,
      "a device expiring immediately after witness signature cannot get a durable admission");
  } finally {
    crypto.sign = originalWitnessSign;
    Date.now = originalClock;
  }
  assert.equal(signedBeforeExpiry, true,
    "the adversarial fixture must cross expiry specifically AFTER signing");
  assert.deepEqual(historical.historicalAdmissionHead(), {
    sequence: 0, lastHash: "0".repeat(64) },
  "expired post-sign admission must leave no persisted receipt or high-water advance");
  // If a trusted owner revokes the device during independent PG/SQLite work,
  // the final transaction must not persist a now-revoked signed operation.
  let revokedAtSign = false;
  crypto.sign = (...args) => {
    const signed = originalWitnessSign(...args);
    if (Buffer.isBuffer(args[1]) && args[1].subarray(0, expiryDomain.length).equals(expiryDomain)) {
      trustedDeviceRevocations = ["device-a"];
      revokedAtSign = true;
    }
    return signed;
  };
  try {
    await assert.rejects(historical.issueSyncHistoricalAdmission(issueInput),
      /WITNESS_CAS_FLOOR_DENIED/,
      "revocation between original validation and the SQLite transaction must fail closed");
  } finally {
    crypto.sign = originalWitnessSign;
    trustedDeviceRevocations = [];
  }
  assert.equal(revokedAtSign, true);
  assert.deepEqual(historical.historicalAdmissionHead(), {
    sequence: 0, lastHash: "0".repeat(64) });
  // A second adversarial interleaving passes the post-sign check and crosses
  // expiry AFTER the SQLite .immediate transaction has already started.
  const originalDbPrepare = Database.prototype.prepare;
  let crossedInsideTransaction = false;
  Database.prototype.prepare = function (sql, ...args) {
    const prepared = originalDbPrepare.call(this, sql, ...args);
    if (sql !== "SELECT COUNT(*) AS n FROM witness_cas_sync_historical_admission") {
      return prepared;
    }
    return new Proxy(prepared, { get(target, name) {
      if (name !== "get") return Reflect.get(target, name);
      return (...params) => {
        const result = target.get(...params);
        crossedInsideTransaction = true;
        Date.now = () => syncEnvelope.authorization.expiresAt + 1;
        return result;
      };
    } });
  };
  try {
    await assert.rejects(historical.issueSyncHistoricalAdmission(issueInput),
      /WITNESS_CAS_FLOOR_DENIED/,
      "device expiration inside SQLite .immediate transaction must roll back");
  } finally {
    Database.prototype.prepare = originalDbPrepare;
    Date.now = originalClock;
  }
  assert.equal(crossedInsideTransaction, true);
  assert.deepEqual(historical.historicalAdmissionHead(), {
    sequence: 0, lastHash: "0".repeat(64) });
  // The second device-policy fetch was previously AFTER the purported final
  // clock check; a synchronous trusted callback can cross expiry before INSERT.
  advanceClockOnPolicyRefresh = true;
  policyRefreshCount = 0;
  policyRefreshExpired = false;
  try {
    await assert.rejects(historical.issueSyncHistoricalAdmission(issueInput),
      /WITNESS_CAS_FLOOR_DENIED/,
      "expiry crossed synchronously by policy refresh must roll back INSERT");
  } finally {
    advanceClockOnPolicyRefresh = false;
    policyRefreshCount = 0;
    Date.now = originalClock;
  }
  assert.equal(policyRefreshExpired, true,
    "the trusted policy refresh must really cross device expiry inside SQLite");
  assert.deepEqual(historical.historicalAdmissionHead(), {
    sequence: 0, lastHash: "0".repeat(64) });
  const mutableChallenge = Buffer.from(historicalChallenge);
  const inFlight = historical.issueSyncHistoricalAdmission({
    ...issueInput, nonce: mutableChallenge });
  mutableChallenge.fill(0);
  const issued = await inFlight;
  assert.equal(issued.durableLocalWitnessAdmission, true);
  assert.equal(issued.authorizesHistoricalRead, false);
  assert.equal(issued.authorizesIo, false);
  assert.equal(issued.admission.envelopeSha256,
    sha(bound.canonicalEnvelope).toString("base64url"));
  assert.equal(issued.admission.operationId, op.operation_id.toString("base64url"));
  assert.equal(issued.admission.inventoryReceiptSha256,
    sha(receipt).toString("base64url"));
  assert.ok(issued.admission.admittedAtMs < syncEnvelope.authorization.expiresAt);
  assert.equal(issued.admission.witnessPhysicalFenceDigest,
    issued.freshFloor.physicalFenceDigest);
  assert.equal(issued.freshFloor.nonce, historicalChallenge.toString("base64url"),
    "the exact pre-queue client challenge must bind both PG and signed witness floor");
  const strictClientInput = {
    envelope: syncEnvelope, scope, expectedSequence: 0, expectedRoot: genesisRoot,
    receipt, physicalAttestation: issued.physicalAttestation,
    nonce: historicalChallenge, admission: issued.admission,
    freshFloor: issued.freshFloor,
    pinnedInventoryPublicKey: inventory.publicKey,
    pinnedInventorySignerKeyId: inventoryKeyId,
    pinnedPhysicalAttestorPublicKey: attestor.publicKey,
    localTrustedDevicePolicy: trustedSyncDevicePolicyProvider(),
    trustedCurrentDevicePolicyProvider: trustedSyncDevicePolicyProvider,
    pinnedWitnessPublicKey: witness.publicKey,
    witnessKeyId, statusKeyId,
    trustedMinimumFloor: {
      sequence: issued.freshFloor.sequence,
      lastHash: issued.freshFloor.lastHash,
      physicalFenceDigest: issued.freshFloor.physicalFenceDigest,
    },
  };
  const independentlyVerified = await verifySyncV2HistoricalWitnessAdmission(strictClientInput);
  assert.equal(independentlyVerified.status, "SYNC_V2_HISTORICAL_WITNESS_VERIFIED");
  assert.equal(independentlyVerified.historicalServerAdmissionProven, true);
  assert.equal(independentlyVerified.authorizesHistoricalRead, true);
  assert.equal(independentlyVerified.authorizesIo, false);
  for (const forged of [
    { nonce: random(32) },
    { freshFloor: { ...issued.freshFloor, nonce: random(32).toString("base64url") } },
    { physicalAttestation: Buffer.from("fake physical ACK") },
    { trustedMinimumFloor: { ...strictClientInput.trustedMinimumFloor,
      physicalFenceDigest: "f".repeat(64) } },
  ]) {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      ...strictClientInput, ...forged }), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/,
    "replayed/forged challenges, PG evidence or external floor must fail closed");
  }
  const { signature: admissionSignature, ...unsignedAdmission } = issued.admission;
  assert.equal(crypto.verify(null, Buffer.concat([
    Buffer.from("Root.ark/sync-v2/historical-witness-admission/v1\0"),
    Buffer.from(JSON.stringify(unsignedAdmission)),
  ]), witness.publicKey, Buffer.from(admissionSignature, "base64url")), true);
  await assert.rejects(historical.issueSyncHistoricalAdmission(issueInput),
    /WITNESS_CAS_FLOOR_DENIED/, "repeated same op ID cannot mint another signed receipt");
  // A lost HTTPS ACK cannot repeat a durable INSERT. Recovery must return
  // the ORIGINAL receipt, with a new signed floor and independent PG readback
  // for a fresh challenge, without changing either SQLite high-water.
  const persistedBeforeRecovery = historical.historicalAdmissionHead();
  const recoveryNonce = random(32);
  const recoveryInput = { ...issueInput, nonce: recoveryNonce };
  await assert.rejects(historical.recoverSyncHistoricalAdmission(issueInput),
    /WITNESS_CAS_FLOOR_DENIED/,
    "the ORIGINAL issuance nonce is consumed by its durable FULL receipt");
  const recovered = await historical.recoverSyncHistoricalAdmission(recoveryInput);
  assert.deepEqual(recovered.admission, issued.admission);
  const durableNonces = new Database(historicalFilename, { readonly: true,
    fileMustExist: true });
  try {
    assert.deepEqual(durableNonces.prepare(
      "SELECT nonce FROM witness_cas_sync_historical_issue_nonce WHERE operation_id=?"
    ).get(op.operation_id.toString("base64url")).nonce, historicalChallenge,
    "ISSUE nonce is physically stored in the same FULL SQLite admission commit");
    const stored = durableNonces.prepare(
      "SELECT r.operation_id,r.admission_hash,r.nonce,a.hash FROM"
      + " witness_cas_sync_historical_recovery_nonce r JOIN"
      + " witness_cas_sync_historical_admission a ON a.operation_id=r.operation_id"
      + " WHERE r.nonce=?").get(recoveryNonce);
    assert.equal(stored.operation_id, op.operation_id.toString("base64url"));
    assert.equal(stored.admission_hash, stored.hash,
      "recovery nonce is durably bound to the exact original admission hash");
  } finally { durableNonces.close(); }
  assert.deepEqual(historical.historicalAdmissionHead(), persistedBeforeRecovery);
  assert.equal(recovered.freshFloor.nonce, recoveryNonce.toString("base64url"));
  assert.equal((await verifySyncV2HistoricalWitnessAdmission({
    ...strictClientInput, nonce: recoveryNonce, admission: recovered.admission,
    freshFloor: recovered.freshFloor, physicalAttestation: recovered.physicalAttestation,
  })).authorizesHistoricalRead, true);
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
    ...strictClientInput, nonce: historicalChallenge,
    admission: recovered.admission, freshFloor: recovered.freshFloor,
    physicalAttestation: recovered.physicalAttestation,
  }), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/, "old challenge cannot reuse recovery proof");
  await assert.rejects(historical.recoverSyncHistoricalAdmission(recoveryInput),
    /WITNESS_CAS_FLOOR_DENIED/, "nonce replay cannot recover twice");
  const beforeReplayWindow = Date.now;
  try {
    Date.now = () => beforeReplayWindow() + 6 * 60 * 1000;
    await assert.rejects(historical.recoverSyncHistoricalAdmission(recoveryInput),
      /WITNESS_CAS_FLOOR_DENIED/,
      "even AFTER the former five-minute TTL, a committed nonce is permanently spent");
  } finally { Date.now = beforeReplayWindow; }
  const contestedNonce = random(32);
  const competing = await Promise.allSettled([
    historical.recoverSyncHistoricalAdmission({ ...recoveryInput, nonce: contestedNonce }),
    historical.recoverSyncHistoricalAdmission({ ...recoveryInput, nonce: contestedNonce }),
  ]);
  assert.deepEqual(competing.map((result) => result.status).sort(),
    ["fulfilled", "rejected"], "concurrent same-nonce recovery cannot double-claim");
  const originalPrepareForNonce = Database.prototype.prepare;
  let simulatedSqlInsert = false;
  Database.prototype.prepare = function (sql, ...args) {
    const stmt = originalPrepareForNonce.call(this, sql, ...args);
    if (!sql.startsWith("INSERT INTO witness_cas_sync_historical_recovery_nonce")) return stmt;
    return new Proxy(stmt, { get(target, key) {
      if (key !== "run") return Reflect.get(target, key);
      return (...values) => {
        target.run(...values);
        simulatedSqlInsert = true;
        throw Error("SIMULATED_RECOVERY_COMMIT_INTERRUPTED");
      };
    } });
  };
  const interruptedNonce = random(32);
  try {
    await assert.rejects(historical.recoverSyncHistoricalAdmission({
      ...recoveryInput, nonce: interruptedNonce,
    }), /WITNESS_CAS_FLOOR_DENIED/,
    "failure AFTER SQL INSERT must roll back the entire replay claim");
  } finally { Database.prototype.prepare = originalPrepareForNonce; }
  assert.equal(simulatedSqlInsert, true);
  const afterRollback = await historical.recoverSyncHistoricalAdmission({
    ...recoveryInput, nonce: interruptedNonce,
  });
  assert.equal(afterRollback.freshFloor.nonce, interruptedNonce.toString("base64url"),
    "rolled-back replay claim may be reattempted only with fresh PG proof");
  for (const bad of [
    { envelope: { ...syncEnvelope, deviceId: "wrong-device" } },
    { scope: { ...scope, keyring_id: random(16) } },
    { inventoryReceipt: Buffer.from("foreign-receipt") },
    { expectedRoot: random(32) },
    { nonce: random(31) },
  ]) {
    await assert.rejects(historical.recoverSyncHistoricalAdmission({
      ...recoveryInput, nonce: random(32), ...bad,
    }), /WITNESS_CAS_FLOOR_DENIED/);
  }
  trustedDeviceRevocations = ["device-a"];
  await assert.rejects(historical.recoverSyncHistoricalAdmission({
    ...recoveryInput, nonce: random(32),
  }), /WITNESS_CAS_FLOOR_DENIED/, "live owner revocation must fence lost-ACK recovery");
  trustedDeviceRevocations = [];
  const originalAttestSync = admission.attestSyncCommitted;
  admission.attestSyncCommitted = async function (...args) {
    const proof = await originalAttestSync.apply(this, args);
    trustedDeviceRevocations = ["device-a"];
    return proof;
  };
  try {
    await assert.rejects(historical.recoverSyncHistoricalAdmission({
      ...recoveryInput, nonce: random(32),
    }), /WITNESS_CAS_FLOOR_DENIED/,
    "revocation arriving DURING independent PG proof must refuse old admission");
  } finally {
    admission.attestSyncCommitted = originalAttestSync;
    trustedDeviceRevocations = [];
  }
  // Historical expiry is not a new grant: the immutable durable signature
  // attests to a past valid admission, while current revocation still applies.
  const expiryClock = Date.now;
  const expiredRecoveryNonce = random(32);
  try {
    Date.now = () => syncEnvelope.authorization.expiresAt + 1000;
    const past = await historical.recoverSyncHistoricalAdmission({
      ...recoveryInput, nonce: expiredRecoveryNonce,
    });
    assert.deepEqual(past.admission, issued.admission);
    assert.equal(past.freshFloor.nonce, expiredRecoveryNonce.toString("base64url"));
  } finally { Date.now = expiryClock; }
  assert.deepEqual(historical.historicalAdmissionHead(), persistedBeforeRecovery,
    "all recovery attempts are read-only");
  const admittedFloor = issued.freshFloor;
  const admittedHistoryHead = issued.historicalAdmissionHead;
  historical.close();
  const olderSignedReplaySnapshot = path.join(directory,
    "witness-valid-recovery-previous-signed-head.sqlite");
  fs.copyFileSync(historicalFilename, olderSignedReplaySnapshot);
  assert.equal(historical.supportsClientHistoricalNonce, false,
    "closed issuer cannot advertise live nonce-bound admission service");
  assert.throws(() => new Zk1WitnessCasAnchorFloor(historicalFilename, {
    ...historicalOptions, bootstrapNew: false, trustedMinimumHead: {
      sequence: 1, lastHash: admittedFloor.lastHash,
      physicalFenceDigest: admittedFloor.physicalFenceDigest },
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "an independent receipt issuer may not infer receipt high-water from its own DB");
  historical = new Zk1WitnessCasAnchorFloor(historicalFilename, {
    ...historicalOptions, bootstrapNew: false, trustedMinimumHead: {
      sequence: 1, lastHash: admittedFloor.lastHash,
      physicalFenceDigest: admittedFloor.physicalFenceDigest },
    trustedHistoricalAdmissionHead: admittedHistoryHead,
  });
  assert.deepEqual(historical.historicalAdmissionHead(), admittedHistoryHead);
  assert.deepEqual(historical.historicalAdmissionForOperation(op.operation_id).admission,
    issued.admission, "signed admission remains retrievable after durable restart");
  assert.equal(historical.historicalAdmissionForOperation(random(16)), null);
  await assert.rejects(historical.recoverSyncHistoricalAdmission(issueInput),
    /WITNESS_CAS_FLOOR_DENIED/,
    "issuer nonce remains consumed across process restart");
  await assert.rejects(historical.recoverSyncHistoricalAdmission(recoveryInput),
    /WITNESS_CAS_FLOOR_DENIED/,
    "a completed recovery nonce cannot replay after process restart");
  await assert.rejects(historical.recoverSyncHistoricalAdmission({
    ...recoveryInput, nonce: expiredRecoveryNonce,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "historically expired device does not reset used nonce state on restart");
  const restartNonce = random(32);
  const restartRecovered = await historical.recoverSyncHistoricalAdmission({
    ...recoveryInput, nonce: restartNonce,
  });
  assert.deepEqual(restartRecovered.admission, issued.admission,
    "lost ACK remains recoverable AFTER witness restart from FULL durable SQLite");
  assert.equal(restartRecovered.freshFloor.nonce, restartNonce.toString("base64url"));
  assert.deepEqual(historical.historicalAdmissionHead(), admittedHistoryHead,
    "recovery after restart must never append a new signed receipt");
  const independentlyPinnedRecoveryHead = historical.historicalRecoveryNonceHead();
  assert.ok(independentlyPinnedRecoveryHead.sequence >= 2,
    "recovery ledger exports a separately retainable monotonic head");
  historical.close();
  const pinnedRestart = {
    ...historicalOptions, bootstrapNew: false, trustedMinimumHead: {
      sequence: 1, lastHash: admittedFloor.lastHash,
      physicalFenceDigest: admittedFloor.physicalFenceDigest },
    trustedHistoricalAdmissionHead: admittedHistoryHead,
  };
  assert.throws(() => new Zk1WitnessCasAnchorFloor(olderSignedReplaySnapshot,
    pinnedRestart), /WITNESS_CAS_FLOOR_DENIED/,
  "old valid SQLite snapshot fails automatically without a caller-supplied static recovery floor");
  // Crash window: the immutable local nonce INSERT commits, but external
  // operator custody is unavailable BEFORE its monotonic CAS. No HTTP ACK,
  // no future ISSUE/RECOVER, and no automatic promotion on restart.
  const pendingPath = path.join(directory, "witness-external-checkpoint-pending.sqlite");
  fs.copyFileSync(historicalFilename, pendingPath);
  const externalPending = createExternalRecoveryHeadFixture(
    path.join(directory, "separate-operator-pending-recovery-head.sqlite"),
    independentlyPinnedRecoveryHead);
  externalAuthorities.push(externalPending);
  const pendingOptions = {
    ...pinnedRestart, trustedRecoveryNonceAuthority: externalPending.authority,
  };
  let pendingWitness = new Zk1WitnessCasAnchorFloor(pendingPath, pendingOptions);
  externalPending.setAvailable(false);
  await assert.rejects(pendingWitness.issueSyncHistoricalAdmission({
    ...issueInput, nonce: random(32),
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "offline external custody denies ISSUE before signing, despite a complete local admission");
  await assert.rejects(pendingWitness.recoverSyncHistoricalAdmission({
    ...recoveryInput, nonce: random(32),
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "offline external custody denies RECOVER before PG readback");
  externalPending.setAvailable(true);
  externalPending.setFailurePhase("before");
  const committedOnlyNonce = random(32);
  await assert.rejects(pendingWitness.recoverSyncHistoricalAdmission({
    ...recoveryInput, nonce: committedOnlyNonce,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "failure AFTER durable witness FULL but BEFORE external CAS returns no ACK");
  assert.deepEqual(externalPending.read(), independentlyPinnedRecoveryHead);
  pendingWitness.close();
  assert.throws(() => new Zk1WitnessCasAnchorFloor(pendingPath, pendingOptions),
    /WITNESS_CAS_FLOOR_DENIED/,
  "restart with local-ahead/external-behind pending checkpoint MUST be NO-GO");
  // An independent operator explicitly reconciles the ORIGINAL signed
  // SQLite chain to remote custody. The launcher may never do this itself.
  const pendingSql = new Database(pendingPath, { readonly: true, fileMustExist: true });
  const persistedPending = pendingSql.prepare(
    "SELECT sequence,last_hash FROM witness_cas_sync_historical_recovery_head WHERE id=1").get();
  pendingSql.close();
  const reconciled = { sequence: persistedPending.sequence,
    lastHash: persistedPending.last_hash };
  assert.equal(reconciled.sequence, independentlyPinnedRecoveryHead.sequence + 1);
  externalPending.setFailurePhase(null);
  assert.equal(externalPending.authority.compareAndAdvance(
    independentlyPinnedRecoveryHead, reconciled), true);
  // The external head eventually matching is NOT evidence the lost CAS ACK
  // was observed by this witness. Signed pending state survives independently.
  assert.throws(() => new Zk1WitnessCasAnchorFloor(pendingPath, pendingOptions),
    /WITNESS_CAS_FLOOR_DENIED/,
    "local-ahead pending marker remains quarantined after head-only reconciliation");
  const ackLostPath = path.join(directory, "witness-external-ack-lost.sqlite");
  fs.copyFileSync(historicalFilename, ackLostPath);
  const externalAckLost = createExternalRecoveryHeadFixture(
    path.join(directory, "separate-operator-ack-lost-head.sqlite"),
    independentlyPinnedRecoveryHead);
  externalAuthorities.push(externalAckLost);
  const ackLostOptions = {
    ...pinnedRestart, trustedRecoveryNonceAuthority: externalAckLost.authority,
  };
  pendingWitness = new Zk1WitnessCasAnchorFloor(ackLostPath, ackLostOptions);
  assert.deepEqual((await pendingWitness.recoverSyncHistoricalAdmission({
    ...recoveryInput, nonce: committedOnlyNonce,
  })).admission, issued.admission,
  "confirmed durable external CAS and second FULL transition permit ordinary recovery");
  const confirmedSql = new Database(ackLostPath, { readonly: true, fileMustExist: true });
  try {
    const ready = confirmedSql.prepare(
      "SELECT ack_phase,ack_previous_hash FROM witness_cas_sync_historical_recovery_head WHERE id=1"
    ).get();
    assert.deepEqual(ready, { ack_phase: "READY", ack_previous_hash: "0".repeat(64) },
      "only a second FULL transaction after a confirmed CAS and fresh external read clears quarantine");
  } finally { confirmedSql.close(); }
  await assert.rejects(pendingWitness.recoverSyncHistoricalAdmission({
    ...recoveryInput, nonce: committedOnlyNonce,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "an unacknowledged challenge remains forever spent");
  const preAckLostHead = pendingWitness.historicalRecoveryNonceHead();
  const acknowledgedExternallyButLost = random(32);
  externalAckLost.setFailurePhase("after");
  await assert.rejects(pendingWitness.recoverSyncHistoricalAdmission({
    ...recoveryInput, nonce: acknowledgedExternallyButLost,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "lost external CAS acknowledgment must not return HTTP recovery evidence");
  externalAckLost.setFailurePhase(null);
  assert.equal(pendingWitness.supportsClientHistoricalNonce, false,
    "even if CAS committed, a lost ACK must quarantine same-process historical ISSUE/RECOVER");
  await assert.rejects(pendingWitness.issueSyncHistoricalAdmission({
    ...issueInput, nonce: random(32),
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "a fresh ISSUE must not bypass ambiguous recovery ACK in the same process");
  await assert.rejects(pendingWitness.recoverSyncHistoricalAdmission({
    ...recoveryInput, nonce: random(32),
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "a fresh RECOVER must not bypass ambiguous recovery ACK in the same process");
  const ackLostSql = new Database(ackLostPath, { readonly: true, fileMustExist: true });
  try {
    const signedQuarantine = ackLostSql.prepare(
      "SELECT ack_phase,ack_previous_hash FROM witness_cas_sync_historical_recovery_head WHERE id=1"
    ).get();
    assert.equal(signedQuarantine.ack_phase, "PENDING");
    assert.equal(signedQuarantine.ack_previous_hash, preAckLostHead.lastHash);
  } finally { ackLostSql.close(); }
  pendingWitness.close();
  assert.throws(() => new Zk1WitnessCasAnchorFloor(ackLostPath, ackLostOptions),
    /WITNESS_CAS_FLOOR_DENIED/,
    "even though durable external CAS equals local head, ACK-lost quarantine survives restart");
  const forgedReadyPath = path.join(directory, "witness-pending-ack-forged-ready.sqlite");
  const snapshotPending = new Database(ackLostPath, { readonly: true, fileMustExist: true });
  try { await backupPrivateWitnessFixture(snapshotPending, forgedReadyPath); }
  finally { snapshotPending.close(); }
  const forgedReadyDb = new Database(forgedReadyPath);
  try {
    // A SQL editor with no witness private key cannot convert a signed
    // ambiguous CAS into a completed acknowledgment.
    forgedReadyDb.prepare("UPDATE witness_cas_sync_historical_recovery_head"
      + " SET ack_phase='READY',ack_previous_hash=? WHERE id=1")
      .run("0".repeat(64));
  } finally { forgedReadyDb.close(); }
  assert.throws(() => new Zk1WitnessCasAnchorFloor(forgedReadyPath, ackLostOptions),
    /WITNESS_CAS_FLOOR_DENIED/,
    "forged READY without witness Ed25519 signature fails closed on restart");
  const legacyRecoveryPath = path.join(directory, "witness-legacy-recovery-head-schema.sqlite");
  const beforeUpgrade = new Database(historicalFilename, { readonly: true, fileMustExist: true });
  try { await backupPrivateWitnessFixture(beforeUpgrade, legacyRecoveryPath); }
  finally { beforeUpgrade.close(); }
  const oldSchema = new Database(legacyRecoveryPath);
  try {
    oldSchema.exec("ALTER TABLE witness_cas_sync_historical_recovery_head"
      + " RENAME TO witness_cas_sync_historical_recovery_head_new");
    oldSchema.exec("CREATE TABLE witness_cas_sync_historical_recovery_head ("
      + "id INTEGER PRIMARY KEY CHECK(id=1),sequence INTEGER NOT NULL,"
      + "last_hash TEXT NOT NULL,signature BLOB NOT NULL)");
    oldSchema.exec("INSERT INTO witness_cas_sync_historical_recovery_head"
      + " SELECT id,sequence,last_hash,signature FROM"
      + " witness_cas_sync_historical_recovery_head_new");
    oldSchema.exec("DROP TABLE witness_cas_sync_historical_recovery_head_new");
  } finally { oldSchema.close(); }
  assert.throws(() => new Zk1WitnessCasAnchorFloor(legacyRecoveryPath, pinnedRestart),
    /WITNESS_CAS_FLOOR_DENIED/,
    "old recovery schema without witness-signed ACK phase cannot be upgraded implicitly");
  // Failure AFTER external CAS returns true but BEFORE the second FULL
  // transaction durably signs READY must quarantine, not infer success from
  // the external head already matching local nonce history.
  const failedClearPath = path.join(directory, "witness-recovery-second-full-failed.sqlite");
  const originalSql = new Database(historicalFilename, { readonly: true, fileMustExist: true });
  try { await backupPrivateWitnessFixture(originalSql, failedClearPath); }
  finally { originalSql.close(); }
  const failedClearExternal = createExternalRecoveryHeadFixture(
    path.join(directory, "separate-operator-second-full-failed.sqlite"),
    independentlyPinnedRecoveryHead);
  externalAuthorities.push(failedClearExternal);
  const failedClearOpts = { ...pinnedRestart,
    trustedRecoveryNonceAuthority: failedClearExternal.authority };
  const failedClearWitness = new Zk1WitnessCasAnchorFloor(failedClearPath, failedClearOpts);
  const prepareBeforeInjection = Database.prototype.prepare;
  try {
    Database.prototype.prepare = function (sql, ...other) {
      if (typeof sql === "string" && sql.includes("SET ack_phase='READY'")) {
        throw Error("TEST_SECOND_FULL_UNAVAILABLE");
      }
      return prepareBeforeInjection.call(this, sql, ...other);
    };
    await assert.rejects(failedClearWitness.recoverSyncHistoricalAdmission({
      ...recoveryInput, nonce: random(32),
    }), /WITNESS_CAS_FLOOR_DENIED/,
    "successful external CAS cannot bypass failed FULL-ready persistence");
  } finally { Database.prototype.prepare = prepareBeforeInjection; }
  const afterFailedClear = failedClearExternal.read();
  assert.equal(afterFailedClear.sequence, independentlyPinnedRecoveryHead.sequence + 1);
  assert.equal(failedClearWitness.supportsClientHistoricalNonce, false);
  failedClearWitness.close();
  assert.throws(() => new Zk1WitnessCasAnchorFloor(failedClearPath, failedClearOpts),
    /WITNESS_CAS_FLOOR_DENIED/,
    "failed second FULL transaction must keep signed PENDING quarantine after restart");
  // Reviewer26 P2: an independently durable external CAS may take long enough
  // for the device to be revoked or the verified PG attestation to expire.
  // The LAST READY signature must not reuse pre-CAS policy/time checks.
  const simulatePostCasDrift = async (label, afterExternalCas) => {
    const isolatedPath = path.join(directory, `witness-post-cas-${label}.sqlite`);
    const source = new Database(historicalFilename, { readonly: true, fileMustExist: true });
    try { await backupPrivateWitnessFixture(source, isolatedPath); }
    finally { source.close(); }
    const remote = createExternalRecoveryHeadFixture(
      path.join(directory, `operator-post-cas-${label}.sqlite`),
      independentlyPinnedRecoveryHead);
    externalAuthorities.push(remote);
    const authority = {
      loadHead: remote.authority.loadHead,
      compareAndAdvance(expected, next) {
        const accepted = remote.authority.compareAndAdvance(expected, next);
        if (accepted) afterExternalCas();
        return accepted;
      },
    };
    const options = { ...pinnedRestart, trustedRecoveryNonceAuthority: authority };
    const instance = new Zk1WitnessCasAnchorFloor(isolatedPath, options);
    let claimed;
    try {
      await assert.rejects(instance.recoverSyncHistoricalAdmission({
        ...recoveryInput, nonce: random(32),
      }), /WITNESS_CAS_FLOOR_DENIED/,
      `post-CAS ${label} cannot sign READY using stale policy/physical evidence`);
      claimed = remote.read();
      assert.equal(claimed.sequence, independentlyPinnedRecoveryHead.sequence + 1,
        `post-CAS ${label} happens only AFTER durable external advancement`);
      assert.equal(instance.supportsClientHistoricalNonce, false,
        `post-CAS ${label} must remain quarantined in-process`);
    } finally { instance.close(); }
    const sql = new Database(isolatedPath, { readonly: true, fileMustExist: true });
    try {
      assert.equal(sql.prepare("SELECT ack_phase FROM"
        + " witness_cas_sync_historical_recovery_head WHERE id=1").get().ack_phase,
      "PENDING", `post-CAS ${label} retains signed PENDING`);
    } finally { sql.close(); }
    assert.throws(() => new Zk1WitnessCasAnchorFloor(isolatedPath, options),
      /WITNESS_CAS_FLOOR_DENIED/,
      `post-CAS ${label} remains fail-closed after restart even if policy/time recovers`);
  };
  try {
    await simulatePostCasDrift("revoked", () => {
      trustedDeviceRevocations = ["device-a"];
    });
  } finally { trustedDeviceRevocations = []; }
  const clockBeforeSlowCas = Date.now;
  try {
    await simulatePostCasDrift("expired-physical", () => {
      // Deterministic synchronous CAS latency >30s without sleeping or
      // changing the bound envelope's still-valid device expiration.
      Date.now = () => clockBeforeSlowCas() + 45_000;
    });
  } finally { Date.now = clockBeforeSlowCas; }
  try {
    await simulatePostCasDrift("revoked-and-slow", () => {
      trustedDeviceRevocations = ["device-a"];
      Date.now = () => clockBeforeSlowCas() + 45_000;
    });
  } finally {
    trustedDeviceRevocations = [];
    Date.now = clockBeforeSlowCas;
  }
  assert.throws(() => new Zk1WitnessCasAnchorFloor(olderSignedReplaySnapshot, {
    ...historicalOptions, bootstrapNew: false, trustedMinimumHead: {
      sequence: 1, lastHash: admittedFloor.lastHash,
      physicalFenceDigest: admittedFloor.physicalFenceDigest },
    trustedHistoricalAdmissionHead: admittedHistoryHead,
    trustedRecoveryNonceHead: independentlyPinnedRecoveryHead,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "external recovery high-water detects a rollback to an older VALID signed ledger");
  // Independent reviewer W13: a successful ACK can be replayed after an SQL
  // actor deletes the recovery nonce row, with CAS and historical pins intact.
  // Recovery claims are permanent once committed; expiration is NOT authority
  // to erase their anti-replay history.
  const recoveryDeletePath = path.join(directory, "witness-recovery-delete.sqlite");
  fs.copyFileSync(historicalFilename, recoveryDeletePath);
  const recoveryDelete = new Database(recoveryDeletePath);
  try {
    assert.throws(() => recoveryDelete.prepare(
      "DELETE FROM witness_cas_sync_historical_recovery_nonce WHERE nonce=?"
    ).run(recoveryNonce), /HISTORICAL_RECOVERY_LOCKED/,
    "a direct SQL DELETE of an ACKed nonce must fail");
  } finally { recoveryDelete.close(); }
  const untouched = new Zk1WitnessCasAnchorFloor(recoveryDeletePath, {
    ...historicalOptions, bootstrapNew: false, trustedMinimumHead: {
      sequence: 1, lastHash: admittedFloor.lastHash,
      physicalFenceDigest: admittedFloor.physicalFenceDigest },
    trustedHistoricalAdmissionHead: admittedHistoryHead,
  });
  await assert.rejects(untouched.recoverSyncHistoricalAdmission(recoveryInput),
    /WITNESS_CAS_FLOOR_DENIED/,
    "ACKed challenge remains spent after SQLite restart");
  untouched.close();
  const bypassDeletePath = path.join(directory, "witness-recovery-bypass-delete.sqlite");
  fs.copyFileSync(historicalFilename, bypassDeletePath);
  const bypassDelete = new Database(bypassDeletePath);
  try {
    bypassDelete.exec("DROP TRIGGER no_historical_recovery_nonce_delete");
    bypassDelete.prepare(
      "DELETE FROM witness_cas_sync_historical_recovery_nonce WHERE nonce=?"
    ).run(recoveryNonce);
    bypassDelete.exec(`CREATE TRIGGER no_historical_recovery_nonce_delete
      BEFORE DELETE ON witness_cas_sync_historical_recovery_nonce
      BEGIN SELECT RAISE(ABORT,'HISTORICAL_RECOVERY_LOCKED'); END;`);
  } finally { bypassDelete.close(); }
  assert.throws(() => new Zk1WitnessCasAnchorFloor(bypassDeletePath, {
    ...historicalOptions, bootstrapNew: false, trustedMinimumHead: {
      sequence: 1, lastHash: admittedFloor.lastHash,
      physicalFenceDigest: admittedFloor.physicalFenceDigest },
    trustedHistoricalAdmissionHead: admittedHistoryHead,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "recreating the DELETE trigger cannot hide a missing recovery entry from signed high-water");
  const forgedHeadPath = path.join(directory, "witness-recovery-forged-head.sqlite");
  fs.copyFileSync(historicalFilename, forgedHeadPath);
  const forgedHeadDb = new Database(forgedHeadPath);
  try {
    forgedHeadDb.prepare("UPDATE witness_cas_sync_historical_recovery_head"
      + " SET sequence=sequence-1 WHERE id=1").run();
  } finally { forgedHeadDb.close(); }
  assert.throws(() => new Zk1WitnessCasAnchorFloor(forgedHeadPath, {
    ...historicalOptions, bootstrapNew: false, trustedMinimumHead: {
      sequence: 1, lastHash: admittedFloor.lastHash,
      physicalFenceDigest: admittedFloor.physicalFenceDigest },
    trustedHistoricalAdmissionHead: admittedHistoryHead,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "offline attacker cannot forge updated Ed25519 signed high-water");
  const nonceTamperPath = path.join(directory, "witness-issue-nonce-corrupt.sqlite");
  fs.copyFileSync(historicalFilename, nonceTamperPath);
  const nonceTamper = new Database(nonceTamperPath);
  try {
    nonceTamper.pragma("foreign_keys = OFF");
    nonceTamper.exec("DROP TRIGGER no_historical_issue_nonce_delete");
    nonceTamper.prepare("DELETE FROM witness_cas_sync_historical_issue_nonce").run();
  } finally { nonceTamper.close(); }
  assert.throws(() => new Zk1WitnessCasAnchorFloor(nonceTamperPath, {
    ...historicalOptions, bootstrapNew: false, trustedMinimumHead: {
      sequence: 1, lastHash: admittedFloor.lastHash,
      physicalFenceDigest: admittedFloor.physicalFenceDigest },
    trustedHistoricalAdmissionHead: admittedHistoryHead,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "removing original nonce ledger cannot silently enable historical recovery");
  // A SQL editor can forge an empty local history by deleting a row, but
  // cannot make the exact separately pinned signed-receipt high-water agree.
  const historicalDb = new Database(historicalFilename);
  try {
    // The stronger nonce ledger also has foreign keys to the immutable
    // admission. Explicitly simulate a malicious offline SQLite editor
    // bypassing referential integrity, rather than merely hitting its FK.
    historicalDb.pragma("foreign_keys = OFF");
    historicalDb.exec("DROP TRIGGER no_historical_admission_delete");
    historicalDb.prepare("DELETE FROM witness_cas_sync_historical_admission").run();
  } finally { historicalDb.close(); }
  assert.throws(() => new Zk1WitnessCasAnchorFloor(historicalFilename, {
    ...historicalOptions, bootstrapNew: false, trustedMinimumHead: {
      sequence: 1, lastHash: admittedFloor.lastHash,
      physicalFenceDigest: admittedFloor.physicalFenceDigest },
    trustedHistoricalAdmissionHead: admittedHistoryHead,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "a missing history row or immutable trigger cannot pass an external receipt floor");
  const durableFenceDb = new Database(path.join(directory, "witness-floor.sqlite"),
    { readonly: true, fileMustExist: true });
  try {
    assert.equal(durableFenceDb.prepare(
      "SELECT operation_id FROM witness_cas_inventory_fence WHERE sequence=1"
    ).get().operation_id, op.operation_id.toString("hex"),
    "the witness must sign and durably pin the independent PG operation ID");
    const retained = durableFenceDb.prepare(
      "SELECT original_pg_evidence FROM witness_cas_inventory_fence WHERE sequence=1"
    ).get().original_pg_evidence;
    assert.ok(Buffer.isBuffer(retained) && retained.length > 100,
      "the original attestor Ed25519 proof, signed inventory receipt and nonce must survive");
    const cold = await admission.verifyRetainedPhysicalEvidence(retained);
    assert.deepEqual(cold.operationId, op.operation_id);
    assert.equal(cold.scope, scope.account_id.toString("hex") + ":"
      + scope.compartment_id.length + ":" + scope.compartment_id.toString("hex")
      + ":" + scope.keyring_id.toString("hex"));
    assert.equal(cold.inventorySequence, 1);
    const changed = JSON.parse(retained.toString("utf8"));
    changed.operation.operation_id = random(16).toString("base64url");
    await assert.rejects(admission.verifyRetainedPhysicalEvidence(
      Buffer.from(JSON.stringify(changed))), /WITNESS_CAS_PHYSICAL_ADMISSION_DENIED/,
    "original Ed25519 attestor evidence cannot be replayed for another operation");
    const forgedAttestor = JSON.parse(retained.toString("utf8"));
    forgedAttestor.attestorSpki = status.publicKey.export({ type: "spki",
      format: "der" }).toString("base64url");
    await assert.rejects(admission.verifyRetainedPhysicalEvidence(
      Buffer.from(JSON.stringify(forgedAttestor))),
    /WITNESS_CAS_PHYSICAL_ADMISSION_DENIED/,
    "the persisted PG signer cannot be swapped for the CAS status signer");
    const forgedSignature = JSON.parse(retained.toString("utf8"));
    const originalBytes = Buffer.from(forgedSignature.physicalAttestation, "base64url");
    originalBytes[originalBytes.length - 1] ^= 1;
    forgedSignature.physicalAttestation = originalBytes.toString("base64url");
    await assert.rejects(admission.verifyRetainedPhysicalEvidence(
      Buffer.from(JSON.stringify(forgedSignature))),
    /WITNESS_CAS_PHYSICAL_ADMISSION_DENIED/,
    "the ORIGINAL PG signature must verify, not just a witness-reported boolean");
    assert.equal((await floor.auditRetainedPhysicalEvidence()).verifiedCommitted, 1);
  } finally { durableFenceDb.close(); }
  // Open a second independent witness instance with its PG transport OFFLINE.
  // All historical Ed25519 bytes must remain verifiable without a fresh PG ACK.
  const offlineAdmission = new Zk1WitnessCasPhysicalAdmission({
    pinnedOwnerPublicKey: owner.publicKey,
    pinnedInventoryPublicKey: inventory.publicKey,
    pinnedInventorySignerKeyId: inventoryKeyId,
    pinnedPhysicalAttestorPublicKey: attestor.publicKey,
    trustedMinimumInventoryHead: { sequence: 0, root: genesisRoot },
    trustedMinimumInventorySnapshot: genesisSnapshot,
    physicalAttestorClient: { requestAttestation() {
      throw new Error("PG18 is deliberately OFFLINE for cold audit");
    } },
    inventoryClient: { getVerifiedSnapshotWithChain() {
      throw new Error("inventory transport deliberately OFFLINE for cold audit");
    } },
  });
  const sealedHead = floor.head();
  const coldFloor = new Zk1WitnessCasAnchorFloor(path.join(directory,
    "witness-floor.sqlite"), { bootstrapNew: false, witnessKeyId,
    witnessPrivateKey: witness.privateKey, statusKeyId,
    statusPublicKey: status.publicKey, attestedAdmission: offlineAdmission,
    trustedMinimumHead: { ...sealedHead,
      physicalFenceDigest: floor.freshHead({ nonce: random(32) }).physicalFenceDigest },
  });
  try {
    assert.throws(() => coldFloor.freshHead({ nonce: random(32) }),
      /WITNESS_CAS_FLOOR_DENIED/,
      "restarted witness cannot sign a new head before cold PG Ed25519 re-audit");
    const recovery = await coldFloor.auditRetainedPhysicalEvidence();
    assert.equal(recovery.verifiedCommitted, 1);
    assert.equal(recovery.currentPgReadbackProven, false);
    assert.equal(recovery.externalDurabilityProven, false);
    assert.equal(coldFloor.freshHead({ nonce: random(32) }).sequence, 1);
    assert.equal((await coldFloor.proveCommittedPhysicalFence({ scope,
      operationId: op.operation_id, inventorySequence: 1,
      inventoryRoot: root, nonce: random(32) })).committedSequence, 1);
  } finally { coldFloor.close(); }
  // SQL-authorized tampering after an ACK must not survive even if CAS row,
  // witness key and signed high-water were not touched. Use a disposable copy.
  const corruptedPath = path.join(directory, "corrupted-original-pg.sqlite");
  const sourceDb = new Database(path.join(directory, "witness-floor.sqlite"),
    { readonly: true, fileMustExist: true });
  try { await backupPrivateWitnessFixture(sourceDb, corruptedPath); }
  finally { sourceDb.close(); }
  const corruptedDb = new Database(corruptedPath);
  try {
    const row = corruptedDb.prepare(
      "SELECT original_pg_evidence FROM witness_cas_inventory_fence WHERE sequence=1"
    ).get();
    const tampered = Buffer.from(row.original_pg_evidence);
    tampered[tampered.length - 1] ^= 1;
    corruptedDb.prepare("UPDATE witness_cas_inventory_fence"
      + " SET original_pg_evidence=? WHERE sequence=1").run(tampered);
  } finally { corruptedDb.close(); }
  assert.throws(() => new Zk1WitnessCasAnchorFloor(corruptedPath, {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey,
    attestedAdmission: offlineAdmission,
    trustedMinimumHead: { ...sealedHead,
      physicalFenceDigest: floor.freshHead({ nonce: random(32) }).physicalFenceDigest },
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "tampering retained PG bytes cannot pass signed witness startup after cold restore");
  const strictNonce = random(32);
  const strictSignedHead = floor.freshHead({ nonce: strictNonce });
  assert.equal(strictSignedHead.type, "rootark-zk1-witness-cas-physical-floor/v2",
    "strict witnesses must cryptographically bind the physical-inventory fence");
  const strictVerifiedHead = verifyFreshWitnessCasFloor({
    signed: strictSignedHead, nonce: strictNonce,
    pinnedWitnessPublicKey: witness.publicKey,
    pinnedWitnessKeyId: witnessKeyId, pinnedStatusKeyId: statusKeyId,
    requirePhysicalAdmission: true,
  });
  assert.match(strictVerifiedHead.physicalFenceDigest, /^[a-f0-9]{64}$/);
  assert.throws(() => verifyFreshWitnessCasFloor({
    signed: strictSignedHead, nonce: strictNonce,
    pinnedWitnessPublicKey: witness.publicKey,
    pinnedWitnessKeyId: witnessKeyId, pinnedStatusKeyId: statusKeyId,
    minimumHead: { sequence: strictVerifiedHead.sequence,
      lastHash: strictVerifiedHead.lastHash },
    requirePhysicalAdmission: true,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "strict external minimums may not silently omit the physical-fence digest");
  assert.throws(() => verifyFreshWitnessCasFloor({
    signed: { ...strictSignedHead, physicalFenceDigest: "f".repeat(64) },
    nonce: strictNonce, pinnedWitnessPublicKey: witness.publicKey,
    pinnedWitnessKeyId: witnessKeyId, pinnedStatusKeyId: statusKeyId,
    requirePhysicalAdmission: true,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "a signed CAS-only checkpoint cannot be spliced to a different physical fence");
  const legacyHeadBody = { type: "rootark-zk1-witness-cas-anchor-floor/v1",
    witnessKeyId: witnessKeyId.toString("base64url"),
    statusKeyId: statusKeyId.toString("base64url"), sequence: result.sequence,
    lastHash: result.lastHash, nonce: strictNonce.toString("base64url") };
  const legacyHead = { ...legacyHeadBody,
    signature: crypto.sign(null, Buffer.concat([
      Buffer.from("Root.ark/zk-1/witness-cas-anchor-floor/v1\0", "ascii"),
      Buffer.from(JSON.stringify(legacyHeadBody)),
    ]), witness.privateKey).toString("base64url") };
  assert.equal(verifyFreshWitnessCasFloor({
    signed: legacyHead, nonce: strictNonce,
    pinnedWitnessPublicKey: witness.publicKey,
    pinnedWitnessKeyId: witnessKeyId, pinnedStatusKeyId: statusKeyId,
  }).sequence, result.sequence, "the downgrade test must contain a valid legacy signature");
  assert.throws(() => verifyFreshWitnessCasFloor({
    signed: legacyHead, nonce: strictNonce,
    pinnedWitnessPublicKey: witness.publicKey,
    pinnedWitnessKeyId: witnessKeyId, pinnedStatusKeyId: statusKeyId,
    requirePhysicalAdmission: true,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "clients enrolled in physical admission refuse an otherwise valid CAS-only head");
  await assert.rejects(async () => verifyFreshWitnessCasFloor({
    signed: strictSignedHead, nonce: random(32),
    pinnedWitnessPublicKey: witness.publicKey,
    pinnedWitnessKeyId: witnessKeyId, pinnedStatusKeyId: statusKeyId,
    requirePhysicalAdmission: true,
  }), /WITNESS_CAS_FLOOR_DENIED/, "a replayed strict signed head fails a new challenge");
  assert.deepEqual(await floor.advanceAttested({ records: [record], evidence: [evidence] }),
    result, "exact retries of an already-fenced record are idempotent");
  // A compromised writer and separately valid inventory signer can make B1,
  // B2 on a divergent branch of the *same* signed genesis. B2 is genuinely
  // valid from genesis, but must be refused after this witness accepted A1.
  const forkTuple = { object_id: random(16), revision: 1, epoch: 1,
    ciphertext_sha256: random(32) };
  const fork1 = async (nonce) => contentInventory.createSignedSnapshot({
    signerKeyId: inventoryKeyId, privateKey: inventory.privateKey,
    scope, sequence: 1, previousRoot: genesisRoot, entries: [forkTuple], nonce,
  });
  const forkRoot1 = Buffer.from((await z.decodeDeterministic(
    await fork1(random(32)))).root);
  const forkOperation1 = { operation_id: random(16), expected_sequence: 0,
    expected_root: genesisRoot, ...forkTuple };
  const forkOperation2 = { operation_id: random(16), expected_sequence: 1,
    expected_root: forkRoot1, object_id: random(16), revision: 1,
    epoch: 1, ciphertext_sha256: random(32) };
  const forkTuple2 = { object_id: forkOperation2.object_id,
    revision: forkOperation2.revision, epoch: forkOperation2.epoch,
    ciphertext_sha256: forkOperation2.ciphertext_sha256 };
  forkSnapshot = (nonce) => contentInventory.createSignedSnapshot({
    signerKeyId: inventoryKeyId, privateKey: inventory.privateKey,
    scope, sequence: 2, previousRoot: forkRoot1,
    entries: [forkTuple, forkTuple2].sort(
      (a, b) => Buffer.compare(a.object_id, b.object_id)), nonce,
  });
  const forkRoot2 = Buffer.from((await z.decodeDeterministic(
    await forkSnapshot(random(32)))).root);
  const createForkReceipt = async (operation, sequence, nextRoot) => {
    const unsigned = { type: "rootark-content-inventory-entry/v1", version: 1,
      signer_key_id: inventoryKeyId, scope, sequence,
      previous_root: operation.expected_root, root: nextRoot,
      operation_id: operation.operation_id,
      expected_sequence: operation.expected_sequence,
      expected_root: operation.expected_root,
      request_digest: sha(await z.encodeDeterministic(operation)),
      entry: { object_id: operation.object_id, revision: operation.revision,
        epoch: operation.epoch, ciphertext_sha256: operation.ciphertext_sha256 },
    };
    return Buffer.from(await z.encodeDeterministic({ ...unsigned,
      signature: crypto.sign(null, Buffer.concat([ENTRY,
        Buffer.from(await z.encodeDeterministic(unsigned))]), inventory.privateKey),
    }));
  };
  const forkReceipt1 = await createForkReceipt(forkOperation1, 1, forkRoot1);
  const forkReceipt2 = await createForkReceipt(forkOperation2, 2, forkRoot2);
  forkProofs = [forkReceipt1, forkReceipt2];
  const validNonce = random(32);
  const validForkWithoutPinnedA = await contentInventory.verifySnapshot({
    serialized: Buffer.from(await forkSnapshot(validNonce)),
    pinnedPublicKey: inventory.publicKey, pinnedSignerKeyId: inventoryKeyId,
    expectedScope: scope, requested: forkTuple2,
    minimumHead: { sequence: 0, root: genesisRoot },
    minimumSnapshot: genesisSnapshot, committedProofChain: forkProofs,
    nonce: validNonce,
  });
  assert.equal(validForkWithoutPinnedA.status, "VERIFIED_NONAUTHORIZING",
    "the test's malicious fork must be a valid independently signed history");
  const secondQuery = { ...scope, reservation_id: random(16) };
  const secondTicket = random(80), secondManifest = random(120);
  anchor.prepare(secondQuery, secondTicket, "committed", secondManifest);
  await anchor.append(secondQuery, secondTicket, "committed", secondManifest, random(64));
  const forkRecord = fs.readFileSync(anchor.filename, "utf8").trimEnd().split("\n").at(-1);
  const forkBinding = { recordHash: hex(Buffer.from(forkRecord)),
    scope: binding.scope,
    operation: { operation_id: forkOperation2.operation_id.toString("base64url"),
      expected_sequence: 1, expected_root: forkRoot1.toString("base64url"),
      object_id: forkOperation2.object_id.toString("base64url"),
      revision: 1, epoch: 1,
      ciphertext_sha256: forkOperation2.ciphertext_sha256.toString("base64url"),
    },
    inventoryReceipt: forkReceipt2.toString("base64url") };
  await assert.rejects(floor.advanceAttested({ records: [forkRecord],
    evidence: [{ ...forkBinding, ownerSignature: signBinding(forkBinding) }],
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "new signed fork B cannot replace the already accepted A floor");
  assert.equal(floor.head().sequence, 1);
  forkSnapshot = null;
  forkProofs = null;
  // The real witness mTLS endpoint cannot accept the legacy one-field
  // payload once its independently persisted strict policy is enrolled.
  generateNativeFixtureCertificates(directory, {
    caSubject: "Strict Normative Witness CA", servers: ["server"], clients: ["allowed"],
  });
  const read = (name) => fs.readFileSync(path.join(directory, name));
  const forbidden = async () => { throw new Error("OTHER_ROLE_UNAVAILABLE"); };
  const service = createZk1WitnessHttpsServer({
    key: read("server.key"), cert: read("server.pem"), clientCa: read("ca.pem"),
    casAnchorFloor: floor,
    ledger: { reserve: forbidden, freshHead: forbidden, resolve: forbidden,
      prepareQuiesce: forbidden, cancelExpiredQuiesce: forbidden,
      beginIoAdmission: forbidden, finishIoAdmission: forbidden },
    principals: {
      [new crypto.X509Certificate(read("allowed.pem")).fingerprint256]:
        { roles: ["cas-anchor"], scopes: [] },
    },
  });
  await new Promise((resolve) => service.listen(0, "127.0.0.1", resolve));
  const client = new Zk1WitnessCasAnchorHttpsClient({
    endpoint: `https://localhost:${service.address().port}`,
    ca: read("ca.pem"), clientKey: read("allowed.key"),
    clientCert: read("allowed.pem"),
    serverFingerprint256: new crypto.X509Certificate(read("server.pem")).fingerprint256,
    pinnedWitnessPublicKey: witness.publicKey,
    pinnedWitnessKeyId: witnessKeyId, pinnedStatusKeyId: statusKeyId,
    requirePhysicalAdmission: true,
  });
  try {
    await assert.rejects(client.advanceSignedRecords([record]),
      /CAS_WITNESS_FLOOR_UNAVAILABLE/);
    assert.equal(await client.advanceSignedRecords([record], [evidence]), false);
    const clientHead = await client.freshHead({ ...result,
      physicalFenceDigest: strictVerifiedHead.physicalFenceDigest });
    assert.equal(clientHead.sequence, 1);
    assert.equal(clientHead.physicalFenceDigest, strictVerifiedHead.physicalFenceDigest);
  } finally {
    await drainZk1WitnessHttpsServer(service);
  }
  // End-to-end admission across a REAL mTLS socket to a distinct OS child
  // holding the attestor Ed25519 key. The child intentionally simulates PG
  // readback; physical PostgreSQL durability must be tested separately.
  const physicalDir = path.join(directory, "physical-child");
  fs.mkdirSync(physicalDir);
  generateNativeFixtureCertificates(physicalDir, {
    caSubject: "Normative Physical Witness CA",
    servers: ["attestor"], clients: ["allowed", "denied"],
  });
  const physicalRead = (name) => fs.readFileSync(path.join(physicalDir, name));
  const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
  const config = {
    caPath: path.join(physicalDir, "ca.pem"),
    serverKeyPath: path.join(physicalDir, "attestor.key"),
    serverCertPath: path.join(physicalDir, "attestor.pem"),
    signerKeyPath: path.join(physicalDir, "signer.key"),
    allowedFingerprint: new crypto.X509Certificate(physicalRead("allowed.pem")).fingerprint256,
    scope: Object.fromEntries(Object.entries(scope).map(([key, value]) => [key, b64(value)])),
    operation: Object.fromEntries(Object.entries(op).map(([key, value]) =>
      [key, Buffer.isBuffer(value) ? b64(value) : value])),
    digest: b64(random(32)), root: b64(random(32)), chunks: 1,
  };
  fs.writeFileSync(config.signerKeyPath,
    attestor.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  const configPath = path.join(physicalDir, "config.json");
  fs.writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
  const physicalChild = spawn(process.execPath, [
    path.join(__dirname, "../lab/issue-65-packet-b/pg-physical-attestor-child.js"), configPath,
  ], { stdio: ["ignore", "pipe", "pipe", "ipc"], windowsHide: true,
    env: { ...process.env, NODE_ENV: "test" } });
  t.after(() => { if (!physicalChild.killed) physicalChild.kill(); });
  const port = await new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error("attestor child startup timeout")), 15000);
    physicalChild.once("error", reject);
    physicalChild.once("exit", (code) => reject(new Error("attestor child exited " + code)));
    physicalChild.once("message", (message) => {
      clearTimeout(deadline);
      if (!Number.isSafeInteger(message?.port) || message.port < 1) {
        reject(new Error("invalid attestor child port"));
      } else resolve(message.port);
    });
  });
  const physicalConnection = { endpoint: `https://localhost:${port}`,
    ca: physicalRead("ca.pem"), clientKey: physicalRead("allowed.key"),
    clientCert: physicalRead("allowed.pem"),
    serverFingerprint256: new crypto.X509Certificate(
      physicalRead("attestor.pem")).fingerprint256,
  };
  const physicalClient = createZk1PgPhysicalAttestorHttpsClient(physicalConnection);
  const endToEndAdmission = new Zk1WitnessCasPhysicalAdmission({
    pinnedOwnerPublicKey: owner.publicKey,
    pinnedInventoryPublicKey: inventory.publicKey,
    pinnedInventorySignerKeyId: inventoryKeyId,
    pinnedPhysicalAttestorPublicKey: attestor.publicKey,
    trustedMinimumInventoryHead: { sequence: 0, root: genesisRoot },
    trustedMinimumInventorySnapshot: genesisSnapshot,
    physicalAttestorClient: physicalClient,
    inventoryClient: { getVerifiedSnapshotWithChain: async ({ nonce }) => ({
      serializedSnapshot: Buffer.from(await buildCurrentSnapshot(nonce)),
      authenticatedProofChain: [receipt],
      authenticatedPhysicalProofChain: [await chainPhysicalProof(nonce)],
    }) },
  });
  const remoteFloor = new Zk1WitnessCasAnchorFloor(
    path.join(directory, "separate-os-process-witness.sqlite"), {
      bootstrapNew: true, witnessKeyId, witnessPrivateKey: witness.privateKey,
      statusKeyId, statusPublicKey: status.publicKey,
      attestedAdmission: endToEndAdmission, enableSyncHistoricalIssuer: true,
      trustedSyncDevicePolicyProvider,
      trustedRecoveryNonceAuthority: (() => {
        const authority = createExternalRecoveryHeadFixture(
          path.join(directory, "remote-witness-operator-recovery-head.sqlite"));
        externalAuthorities.push(authority);
        return authority.authority;
      })(),
    });
  try {
    assert.equal((await remoteFloor.advanceAttested({
      records: [record], evidence: [evidence],
    })).sequence, 1, "separate-process mTLS physical attestor completes strict witness admission");
    const remoteReceipt = await remoteFloor.issueSyncHistoricalAdmission(issueInput);
    assert.equal(remoteReceipt.durableLocalWitnessAdmission, true);
    assert.equal(remoteReceipt.independentPhysicalReadbackVerified, true);
    assert.equal(remoteReceipt.authorizesIo, false);
    const unauthorized = createZk1PgPhysicalAttestorHttpsClient({
      ...physicalConnection, clientKey: physicalRead("denied.key"),
      clientCert: physicalRead("denied.pem"),
    });
    await assert.rejects(unauthorized.requestAttestation({
      scope, operation: op, nonce: random(32),
    }), /ZK_PHYSICAL_ATTESTOR_TRANSPORT_UNAVAILABLE/);
  } finally {
    remoteFloor.close();
    physicalChild.kill();
  }
  floor.close();
  assert.throws(() => new Zk1WitnessCasAnchorFloor(path.join(directory, "witness-floor.sqlite"), {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey,
  }), /WITNESS_CAS_FLOOR_DENIED/, "restart cannot drop strict physical admission policy");
  assert.throws(() => new Zk1WitnessCasAnchorFloor(path.join(directory, "witness-floor.sqlite"), {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey,
    attestedAdmission: admission,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "a signed old SQLite backup is not a trusted external high-water oracle");
  assert.throws(() => new Zk1WitnessCasAnchorFloor(path.join(directory, "witness-floor.sqlite"), {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey,
    attestedAdmission: admission,
    trustedMinimumHead: { sequence: 0, lastHash: "0".repeat(64) },
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "a stale external minimum must not be accepted as an exact restart boundary");
  assert.throws(() => new Zk1WitnessCasAnchorFloor(path.join(directory, "witness-floor.sqlite"), {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission,
    trustedMinimumHead: result,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "strict witness restart must reject a CAS-only external minimum lacking the physical digest");
  assert.throws(() => new Zk1WitnessCasAnchorFloor(path.join(directory, "witness-floor.sqlite"), {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission,
    trustedMinimumHead: { ...result, physicalFenceDigest: "f".repeat(64) },
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "strict witness restart must reject the correct signed CAS floor with a forked physical history");
  const independentlyPinnedMinimum = { ...result,
    physicalFenceDigest: strictVerifiedHead.physicalFenceDigest };
  const restarted = new Zk1WitnessCasAnchorFloor(path.join(directory, "witness-floor.sqlite"), {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission,
    trustedMinimumHead: independentlyPinnedMinimum,
  });
  assert.deepEqual(restarted.head(), result,
    "restart validates strict operator identities and the independently pinned floor");
  restarted.close();
  const operationTamperedPath = path.join(directory, "witness-operation-tampered.sqlite");
  fs.copyFileSync(path.join(directory, "witness-floor.sqlite"), operationTamperedPath);
  const operationTamperDb = new Database(operationTamperedPath);
  operationTamperDb.prepare("UPDATE witness_cas_inventory_fence SET operation_id=? WHERE sequence=1")
    .run(random(16).toString("hex"));
  operationTamperDb.close();
  assert.throws(() => new Zk1WitnessCasAnchorFloor(operationTamperedPath, {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission,
    trustedMinimumHead: independentlyPinnedMinimum,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "PG operation-id substitution after SQLite restart invalidates the witness signature");
  const replacement = new Zk1WitnessCasPhysicalAdmission({
    pinnedOwnerPublicKey: crypto.generateKeyPairSync("ed25519").publicKey,
    pinnedInventoryPublicKey: inventory.publicKey,
    pinnedInventorySignerKeyId: inventoryKeyId,
    pinnedPhysicalAttestorPublicKey: attestor.publicKey,
    trustedMinimumInventoryHead: { sequence: 0, root: genesisRoot },
    trustedMinimumInventorySnapshot: genesisSnapshot,
    physicalAttestorClient: { requestAttestation: async () => { throw Error("OFFLINE"); } },
    inventoryClient: { getVerifiedSnapshotWithChain: async () => null },
  });
  assert.throws(() => new Zk1WitnessCasAnchorFloor(path.join(directory, "witness-floor.sqlite"), {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: replacement,
  }), /WITNESS_CAS_FLOOR_DENIED/, "restart cannot silently repin a new owner signer");
  const tamperedPath = path.join(directory, "witness-tampered.sqlite");
  fs.copyFileSync(path.join(directory, "witness-floor.sqlite"), tamperedPath);
  const attackerDatabase = new Database(tamperedPath);
  attackerDatabase.prepare("DELETE FROM witness_cas_inventory_fence WHERE sequence=1").run();
  attackerDatabase.close();
  assert.throws(() => new Zk1WitnessCasAnchorFloor(tamperedPath, {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "editing SQLite cannot erase the witness-bound inventory fence after restart");
});

test("CAS persists mandatory physical evidence provider enrollment and refuses restart downgrade", (t) => {
  const directory = createPrivateAuthorityFixture("zk65-cas-normative-policy-");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const status = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const statusKeyId = random(16), witnessKeyId = random(16);
  const casAnchorWitness = new Zk1WitnessCasAnchorHttpsClient({
    endpoint: "https://localhost:9443", ca: Buffer.from("unconnected-test"),
    clientKey: Buffer.from("unconnected-test"), clientCert: Buffer.from("unconnected-test"),
    serverFingerprint256: new Array(32).fill("AB").join(":"),
    pinnedWitnessPublicKey: witness.publicKey,
    pinnedWitnessKeyId: witnessKeyId, pinnedStatusKeyId: statusKeyId,
    requirePhysicalAdmission: true,
  });
  const provider = { forSignedRecord: async () => { throw Error("NO_RECORD_YET"); } };
  const filename = path.join(directory, "status.sqlite");
  const options = { bootstrapNew: true, statusKeyId,
    statusPrivateKey: status.privateKey, anchorPath: path.join(directory, "anchor.log"),
    witnessPinned: { keyId: witnessKeyId, publicKey: witness.publicKey },
    trustedAnchorMinimumHead: { sequence: 0, lastHash: "0".repeat(64) },
    casAnchorWitness, casAnchorPhysicalEvidenceProvider: provider,
  };
  assert.throws(() => new Zk1DurableCasStatusLedger(filename, options),
    /CAS_ANCHOR_REQUIRED/,
    "strict CAS may not enroll without a separately retained physical-fence digest");
  options.trustedAnchorMinimumHead = {
    sequence: 0, lastHash: "0".repeat(64),
    physicalFenceDigest: hex(Buffer.alloc(0)),
  };
  const cas = new Zk1DurableCasStatusLedger(filename, options);
  cas.close();
  assert.throws(() => new Zk1DurableCasStatusLedger(filename, {
    ...options, bootstrapNew: false, casAnchorPhysicalEvidenceProvider: null,
  }), /CAS_IDENTITY_MISMATCH/,
  "neither a valid CAS status signing key nor writable local SQL can silently select legacy witness admission");
  const restarted = new Zk1DurableCasStatusLedger(filename, { ...options, bootstrapNew: false });
  restarted.close();
  assert.throws(() => new Zk1DurableCasStatusLedger(filename, {
    ...options, bootstrapNew: false, casAnchorWitness: null,
    casAnchorPhysicalEvidenceProvider: null,
  }), /CAS_IDENTITY_MISMATCH/, "CAS cannot remove both independent admission and witness on restart");
});
