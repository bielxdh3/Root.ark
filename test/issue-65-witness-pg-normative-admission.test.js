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
  const op = { operation_id: random(16), expected_sequence: 0, expected_root: genesisRoot,
    object_id: random(16), revision: 1, epoch: 1, ciphertext_sha256: random(32) };
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
        return { serializedSnapshot: Buffer.from(await (
          forkSnapshot ? forkSnapshot(nonce) : buildCurrentSnapshot(nonce))),
          authenticatedProofChain: forkProofs || [receipt], authorizesIo: false };
      },
    },
  });
  const floor = new Zk1WitnessCasAnchorFloor(path.join(directory, "witness-floor.sqlite"), {
    bootstrapNew: true, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission,
  });
  t.after(() => floor.close());
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
  const result = await floor.advanceAttested({ records: [record], evidence: [evidence] });
  assert.equal(result.sequence, 1);
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
  assert.equal(physicalCalls, 2);
  assert.equal(inventoryCalls, 1);
  assert.deepEqual(await floor.advanceAttested({ records: [record], evidence: [evidence] }),
    result, "exact retries are idempotent but must re-attest");
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
    }) },
  });
  const remoteFloor = new Zk1WitnessCasAnchorFloor(
    path.join(directory, "separate-os-process-witness.sqlite"), {
      bootstrapNew: true, witnessKeyId, witnessPrivateKey: witness.privateKey,
      statusKeyId, statusPublicKey: status.publicKey,
      attestedAdmission: endToEndAdmission,
    });
  try {
    assert.equal((await remoteFloor.advanceAttested({
      records: [record], evidence: [evidence],
    })).sequence, 1, "separate-process mTLS physical attestor completes strict witness admission");
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
  const restarted = new Zk1WitnessCasAnchorFloor(path.join(directory, "witness-floor.sqlite"), {
    bootstrapNew: false, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey, attestedAdmission: admission,
    trustedMinimumHead: result,
  });
  assert.deepEqual(restarted.head(), result,
    "restart validates strict operator identities and the independently pinned floor");
  restarted.close();
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
