"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
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
const { Zk1DurableCasStatusLedger } =
  require("../src/services/zk1DurableCasStatusLedger");
const { createZk1PgPhysicalAttestorHttpsClient } =
  require("../src/services/zk1PgPhysicalAttestorHttpsClient");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { envelopeBinding, verifySyncV2HistoricalWitnessAdmission } =
  require("../sync-client/rootark-sync-zk1-physical-binding");

const DOMAIN = Buffer.from("Root.ark/zk-1/cas-witness-physical-owner-binding/v1\0");
const ENTRY = Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0");
const random = (n) => crypto.randomBytes(n);
const sha = (b) => crypto.createHash("sha256").update(b).digest();
const hex = (b) => sha(b).toString("hex");

test("strict CAS witness floor refuses signed status advance without independent PG attestation and owner binding", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-witness-physical-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
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
  const admittedFloor = issued.freshFloor;
  const admittedHistoryHead = issued.historicalAdmissionHead;
  historical.close();
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
  historical.close();
  // A SQL editor can forge an empty local history by deleting a row, but
  // cannot make the exact separately pinned signed-receipt high-water agree.
  const historicalDb = new Database(historicalFilename);
  try {
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
  } finally { durableFenceDb.close(); }
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-cas-normative-policy-"));
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
