"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const z = require("../src/crypto/rootark-zk-1");
const v2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { Zk1OpaqueCatalogCasLedger } =
  require("../src/services/zk1OpaqueCatalogCasLedger");
const { createZk1OpaqueCatalogCasHttpsServer } =
  require("../src/services/zk1OpaqueCatalogCasHttpsServer");
const { createZk1OpaqueCatalogCasHttpsClient } =
  require("../src/services/zk1OpaqueCatalogCasHttpsClient");
const { Zk1OpaqueCatalogIndependentFloorLedger,
  createZk1OpaqueCatalogIndependentFloorHttpsServer,
  createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { catalogHeadDigest } = require("../src/services/zk1OpaqueCatalog");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { privateAuthorityDirectory } =
  require("./support/issue-65-private-authority-directory");

const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0");
const PAGE_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-page/v1\0");
const WITNESS_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0");
const BASE_DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-base/v1\0");
const b64 = (v) => Buffer.from(v).toString("base64url");
const hash = (v) => crypto.createHash("sha256").update(v).digest();

test("mTLS independent CAS rotates owner-granted signer A to B after A revocation; rollback, fork, nonce, restart denied", {
  timeout: 90000,
}, async (t) => {
  const dir = privateAuthorityDirectory("zk1-cas-rotate-");
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  generateNativeFixtureCertificates(dir, { caSubject: "ZK1 Owner CAS",
    servers: ["server", "floor"], clients: ["client", "foreign"] });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const state = await fixtures.createInitialState(1);
  const scope = state.scope;
  const witness = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const genesis = await v2.recoveryManifestDigestV2(state.baseManifest);
  const base = { type: "rootark-recovery-witness-base/v1",
    witness_key_id: witnessKeyId, ...scope, revision: 1,
    manifest_digest: genesis, witness_sequence: 1,
    nonce: crypto.randomBytes(32), observed_at: 1000, status: "committed" };
  state.baseReceipt = { ...base, signature: crypto.sign(null,
    Buffer.concat([BASE_DOMAIN, Buffer.from(await z.encodeDeterministic(base))]),
    witness.privateKey) };
  state.pinnedWitness = { keyId: witnessKeyId, publicKey: witness.publicKey };
  await fixtures.appendDeviceEnrollment(state, 1);
  const keys = (index) => state.actors.get(Buffer.from(
    state.headManifest.devices[index].authorization_key_id).toString("hex"));
  const signerA = crypto.createPublicKey({ key: Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(state.headManifest.devices[0].authorization_public_key)]),
  format: "der", type: "spki" });
  const signerB = crypto.createPublicKey({ key: Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(state.headManifest.devices[1].authorization_public_key)]),
  format: "der", type: "spki" });
  const authority = crypto.generateKeyPairSync("ed25519");
  const floorKeys = crypto.generateKeyPairSync("ed25519");
  const db = path.join(dir, "authority.sqlite");
  const minimumHead = { sequence: 0, digest: Buffer.alloc(32) };
  const ownerTrust = { genesisDigest: genesis, pinnedWitness: state.pinnedWitness,
    minimumHead: { revision: 1, witnessSequence: 1, digest: genesis },
    freshWitnessHead: ({ nonce }) => witnessed(nonce) };
  let ledger, server, client, floorLedger, floorServer, floorClient;
  floorLedger = new Zk1OpaqueCatalogIndependentFloorLedger(path.join(dir, "floor.sqlite"), {
    bootstrapNew: true, trustedScope: scope, signingPrivateKey: floorKeys.privateKey,
    casSignerPublicKey: authority.publicKey, catalogSignerPublicKey: signerA,
    ownerTrust,
  });
  floorServer = createZk1OpaqueCatalogIndependentFloorHttpsServer({
    ledger: floorLedger, key: read("floor.key"), cert: read("floor.pem"),
    clientCa: read("ca.pem"), authorizedClientFingerprint256:
      new crypto.X509Certificate(read("client.pem")).fingerprint256,
  });
  await new Promise((resolve) => floorServer.listen(0, "127.0.0.1", resolve));
  floorClient = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: "https://127.0.0.1:" + floorServer.address().port + "/",
    ca: read("ca.pem"), clientKey: read("client.key"), clientCert: read("client.pem"),
    serverFingerprint256: new crypto.X509Certificate(read("floor.pem")).fingerprint256,
    floorPublicKey: floorKeys.publicKey, casSignerPublicKey: authority.publicKey,
    trustedScope: scope,
  });
  assert.throws(() => new Zk1OpaqueCatalogCasLedger(db, {
    bootstrapNew: true, signingPrivateKey: authority.privateKey,
    catalogSignerPublicKey: signerA, trustedScope: scope, minimumHead, ownerTrust,
  }), /ZK_OPAQUE_CAS_UNAVAILABLE/,
  "owner V2 rotation may never bypass an unavailable/unconfigured independent floor");
  t.after(async () => {
    const closed = new Promise((resolve) => floorServer.close(resolve));
    floorServer.closeAllConnections();
    await closed;
    floorLedger.close();
  });
  const start = async (bootstrapNew) => {
    ledger = new Zk1OpaqueCatalogCasLedger(db, {
      bootstrapNew, signingPrivateKey: authority.privateKey,
      catalogSignerPublicKey: signerA, trustedScope: scope,
      minimumHead, ownerTrust, independentFloor: floorClient,
    });
    await ledger.ready;
    server = createZk1OpaqueCatalogCasHttpsServer({
      key: read("server.key"), cert: read("server.pem"),
      clientCa: read("ca.pem"),
      authorizedClientFingerprint256:
        new crypto.X509Certificate(read("client.pem")).fingerprint256,
      ledger,
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    client = createZk1OpaqueCatalogCasHttpsClient({
      endpoint: "https://127.0.0.1:" + server.address().port + "/",
      ca: read("ca.pem"), clientKey: read("client.key"), clientCert: read("client.pem"),
      serverFingerprint256: new crypto.X509Certificate(read("server.pem")).fingerprint256,
      authorityPublicKey: authority.publicKey,
    });
  };
  const stop = async () => {
    const closed = new Promise((resolve) => server.close(resolve));
    server.closeAllConnections();
    await closed;
    ledger.db.pragma("wal_checkpoint(TRUNCATE)");
    ledger.close();
  };
  t.after(async () => { if (server?.listening) await stop(); });
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const witnessed = async (nonce, manifest = state.headManifest) => {
    const statement = { type: "rootark-recovery-witness-head/v1",
      witness_key_id: witnessKeyId, ...scope,
      current_revision: manifest.revision,
      current_manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      witness_sequence: manifest.revision, nonce, observed_at: Math.floor(Date.now() / 1000),
      status: "committed", pending_reservation_id: null };
    return z.encodeDeterministic({ ...statement, signature: crypto.sign(null,
      Buffer.concat([WITNESS_DOMAIN, Buffer.from(await z.encodeDeterministic(statement))]),
      witness.privateKey) });
  };
  const evidence = async (nonce, manifest) => z.encodeDeterministic({
    baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt,
    transitions: state.transitions,
    packageEnvelopes: state.packageEnvelopes,
    witnessHeadRaw: await witnessed(nonce, manifest),
  });
  const entry = { object_id: b64(crypto.randomBytes(16)), revision: 1,
    epoch: 1, ciphertext_digest: crypto.randomBytes(32),
    metadata_ciphertext: crypto.randomBytes(284) };
  const page = Buffer.from(await z.encodeDeterministic([entry]));
  const pageDigest = hash(Buffer.concat([PAGE_DOMAIN, page]));
  const build = async (deviceIndex, expected, nonce = crypto.randomBytes(32),
    manifest = state.headManifest, oldProof = null) => {
    const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
      sequence: expected.sequence + 1, previous_digest: Buffer.from(expected.digest),
      manifest_revision: Number(manifest.revision),
      manifest_digest: await v2.recoveryManifestDigestV2(manifest),
      epoch: Number(manifest.current_epoch),
      signer_device_id: manifest.devices[deviceIndex].device_id,
      total_count: 1, page_digests: [pageDigest],
      issued_at: Math.floor(Date.now() / 1000) };
    const headBytes = Buffer.from(await z.encodeDeterministic(header));
    const headSignature = crypto.sign(null, Buffer.concat([HEAD_DOMAIN, headBytes]), keys(deviceIndex));
    return { scope, expectedSequence: expected.sequence, expectedDigest: expected.digest,
      nextSequence: header.sequence, nextDigest: catalogHeadDigest(headBytes, headSignature),
      nonce, headBytes, headSignature, pageBodies: [page],
      ownerEvidence: oldProof || Buffer.from(await evidence(nonce, manifest)) };
  };
  await start(true);
  const zero = { sequence: 0, digest: Buffer.alloc(32) };
  const initial = await build(0, zero);
  const initialReceipt = await z.decodeDeterministic(await client.compareAndSwap(initial));
  assert.equal(initialReceipt.sequence, 1);
  const first = { sequence: 1, digest: initial.nextDigest };
  const second = first;
  // Owner revokes A and advances the authenticated epoch. B remains enrolled.
  const oldManifest = state.headManifest;
  const oldTransitions = [...state.transitions];
  await fixtures.appendDeviceRevocation(state, "trusted-0");
  const forgedKey = crypto.generateKeyPairSync("ed25519");
  const malformed = await build(1, second);
  malformed.headSignature = crypto.sign(null, Buffer.concat([HEAD_DOMAIN, malformed.headBytes]),
    forgedKey.privateKey);
  malformed.nextDigest = catalogHeadDigest(malformed.headBytes, malformed.headSignature);
  await assert.rejects(client.compareAndSwap(malformed), /ACK_UNCERTAIN/);
  const stale = await build(0, second, crypto.randomBytes(32), oldManifest);
  await assert.rejects(client.compareAndSwap(stale), /ACK_UNCERTAIN/,
    "A may not author with the stale owner revision");
  const oldHistory = await build(0, second, crypto.randomBytes(32), oldManifest);
  const frozen = await z.decodeDeterministic(oldHistory.ownerEvidence);
  frozen.transitions = oldTransitions;
  oldHistory.ownerEvidence = Buffer.from(await z.encodeDeterministic(frozen));
  await assert.rejects(client.compareAndSwap(oldHistory), /ACK_UNCERTAIN/,
    "signed, recently observed pre-revocation witness must fail current independent witness check");
  const forgedWitness = await build(1, second);
  const altered = await z.decodeDeterministic(forgedWitness.ownerEvidence);
  altered.witnessHeadRaw = crypto.randomBytes(128);
  forgedWitness.ownerEvidence = Buffer.from(await z.encodeDeterministic(altered));
  await assert.rejects(client.compareAndSwap(forgedWitness), /ACK_UNCERTAIN/);
  const ownerReendorsement = await build(1, second);
  const receipt = await z.decodeDeterministic(await client.compareAndSwap(ownerReendorsement));
  assert.equal(receipt.sequence, 2);
  const third = { sequence: 2, digest: ownerReendorsement.nextDigest };
  const replay = await build(1, third, ownerReendorsement.nonce);
  await assert.rejects(client.compareAndSwap(replay), /ACK_UNCERTAIN/);
  const staleA = await build(0, third);
  await assert.rejects(client.compareAndSwap(staleA), /ACK_UNCERTAIN/,
    "revoked A cannot sign new heads even with current witness");
  const fork = await build(1, second);
  await assert.rejects(client.compareAndSwap(fork), /ACK_UNCERTAIN/);
  assert.equal((await z.decodeDeterministic(await client.readHead({
    scope, nonce: crypto.randomBytes(32) }))).sequence, 2);
  minimumHead.sequence = 2;
  minimumHead.digest = Buffer.from(third.digest);
  ownerTrust.minimumHead = { revision: Number(state.headManifest.revision),
    witnessSequence: Number(state.headManifest.revision),
    digest: await v2.recoveryManifestDigestV2(state.headManifest) };
  await stop();
  await start(false);
  const restartHead = await z.decodeDeterministic(await client.readHead({
    scope, nonce: crypto.randomBytes(32) }));
  assert.equal(restartHead.sequence, 2);
  const resumed = await build(1, third);
  assert.equal((await z.decodeDeterministic(await client.compareAndSwap(resumed))).sequence, 3);
  await stop();
  // Compromise only the local owner's mutable checkpoint, leaving all signed
  // snapshots and the independently signed remote floor intact. An operator
  // may still have the original revision-1 minimum in startup configuration.
  ownerTrust.minimumHead = { revision: 1, witnessSequence: 1, digest: genesis };
  const scopeId = [scope.account_id, scope.compartment_id, scope.keyring_id]
    .map((part) => Buffer.from(part).toString("hex")).join(":");
  const disk = new Database(db);
  const currentOwner = disk.prepare("SELECT revision,digest FROM owner_authority WHERE scope=?")
    .get(scopeId);
  assert.ok(currentOwner.revision > 1);
  disk.prepare("UPDATE owner_authority SET revision=?, digest=? WHERE scope=?")
    .run(1, genesis, scopeId);
  disk.close();
  const restartOnly = async () => {
    const candidate = new Zk1OpaqueCatalogCasLedger(db, {
      bootstrapNew: false, signingPrivateKey: authority.privateKey,
      catalogSignerPublicKey: signerA, trustedScope: scope,
      minimumHead, ownerTrust, independentFloor: floorClient,
    });
    try { await candidate.ready; } finally { candidate.close(); }
  };
  await assert.rejects(restartOnly(), /ZK_OPAQUE_CAS_UNAVAILABLE/,
    "mutable owner checkpoint rolled back behind signed owner history must fail startup");

  const patched = new Database(db);
  patched.prepare("UPDATE owner_authority SET revision=?,digest=? WHERE scope=?")
    .run(currentOwner.revision, currentOwner.digest, scopeId);
  patched.close();
  await restartOnly();
  // A forged trigger with the expected name on the wrong table disables
  // the intended snapshot immutability while fooling name-only schema checks.
  const forgedTrigger = new Database(db);
  forgedTrigger.exec(`DROP TRIGGER immutable_opaque_snapshot_update;
    CREATE TRIGGER immutable_opaque_snapshot_update BEFORE UPDATE ON identity
    BEGIN SELECT RAISE(ABORT, 'IMMUTABLE'); END;`);
  forgedTrigger.close();
  await assert.rejects(restartOnly(), /ZK_OPAQUE_CAS_UNAVAILABLE/,
    "forged immutability trigger attached to identity must fail startup");

  // The independently operated monotonic floor has its own immutable
  // transitions. Exercise the same forged-name attack on a valid SQLite copy.
  const floorCopy = path.join(dir, "floor-trigger-forgery.sqlite");
  await floorLedger.db.backup(floorCopy);
  if (process.platform !== "win32") fs.chmodSync(floorCopy, 0o600);
  const reopenFloor = () => new Zk1OpaqueCatalogIndependentFloorLedger(floorCopy, {
    bootstrapNew: false, trustedScope: scope, signingPrivateKey: floorKeys.privateKey,
    casSignerPublicKey: authority.publicKey, catalogSignerPublicKey: signerA,
    ownerTrust,
  });
  const healthyFloor = reopenFloor();
  healthyFloor.close();
  const tamperedFloor = new Database(floorCopy);
  tamperedFloor.exec(`DROP TRIGGER immutable_floor_transition_delete;
    CREATE TRIGGER immutable_floor_transition_delete BEFORE DELETE ON identity
    BEGIN SELECT RAISE(ABORT, 'IMMUTABLE'); END;`);
  tamperedFloor.close();
  assert.throws(reopenFloor, /ZK_OPAQUE_FLOOR_UNAVAILABLE/,
    "forged transition trigger must not pass as a valid independent floor");
  assert.equal(signerB.type, "public");
  assert.equal(signerA.type, "public");
});
