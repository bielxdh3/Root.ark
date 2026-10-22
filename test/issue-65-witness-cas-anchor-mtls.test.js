"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");
const { Zk1WitnessCasAnchorFloor } = require("../src/services/zk1WitnessCasAnchorFloor");
const { Zk1WitnessCasAnchorHttpsClient } =
  require("../src/services/zk1WitnessCasAnchorHttpsClient");
const { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer } =
  require("../src/services/zk1WitnessHttpsServer");

test("independent real mTLS witness retains exact signed CAS journal history and refuses forged/forked ACK", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-witness-cas-anchor-mtls-"));
  generateNativeFixtureCertificates(dir, { caSubject: "CAS Floor CA",
    servers: ["server"], clients: ["allowed", "denied"] });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const witness = crypto.generateKeyPairSync("ed25519");
  const status = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  const floorPath = path.join(dir, "witness-floor.sqlite");
  const casPath = path.join(dir, "cas-anchor.log");
  const floor = new Zk1WitnessCasAnchorFloor(floorPath, {
    bootstrapNew: true, witnessPrivateKey: witness.privateKey,
    witnessKeyId, statusKeyId, statusPublicKey: status.publicKey,
  });
  const anchor = new Zk1CasTerminalAnchor(casPath, {
    bootstrapNew: true, statusKeyId, statusPrivateKey: status.privateKey,
  });
  // Global witness-floor authority MUST have its own dedicated mTLS role.
  const fingerprint = new crypto.X509Certificate(read("allowed.pem")).fingerprint256;
  const dummy = async () => { throw new Error("UNREACHABLE_WITNESS_RECOVERY_ROUTE"); };
  const ledger = {
    reserve: dummy, freshHead: dummy, resolve: dummy, prepareQuiesce: dummy,
    cancelExpiredQuiesce: dummy, beginIoAdmission: dummy, finishIoAdmission: dummy,
  };
  assert.throws(() => createZk1WitnessHttpsServer({
    key: read("server.key"), cert: read("server.pem"), clientCa: read("ca.pem"),
    ledger, casAnchorFloor: floor, principals: {
      [fingerprint]: { roles: ["cas-anchor", "head"], scopes: [] },
    },
  }), /WITNESS_API_INVALID/, "global-floor role must never also authorize recovery head reads");
  const service = createZk1WitnessHttpsServer({
    key: read("server.key"), cert: read("server.pem"), clientCa: read("ca.pem"),
    ledger, casAnchorFloor: floor,
    principals: { [fingerprint]: { roles: ["cas-anchor"], scopes: [] } },
  });
  await new Promise((resolve) => service.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    await drainZk1WitnessHttpsServer(service);
    floor.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const cfg = { endpoint: `https://localhost:${service.address().port}`,
    ca: read("ca.pem"), clientKey: read("allowed.key"), clientCert: read("allowed.pem"),
    serverFingerprint256: new crypto.X509Certificate(read("server.pem")).fingerprint256,
    pinnedWitnessPublicKey: witness.publicKey, pinnedWitnessKeyId: witnessKeyId,
    pinnedStatusKeyId: statusKeyId,
  };
  const client = new Zk1WitnessCasAnchorHttpsClient(cfg);
  const genesis = await client.freshHead();
  assert.deepEqual(genesis, { sequence: 0, lastHash: "0".repeat(64) });
  const q = { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("main"),
    keyring_id: crypto.randomBytes(16), reservation_id: crypto.randomBytes(16) };
  const ticket = crypto.randomBytes(100);
  const manifest = crypto.randomBytes(100);
  anchor.prepare(q, ticket, "committed", manifest);
  await anchor.append(q, ticket, "committed", manifest, crypto.randomBytes(64));
  const page = anchor.signedRecordPage({ afterSequence: 0 });
  assert.equal(page.length, 1);
  assert.equal(await client.advanceSignedRecords(page), false,
    "a bare HTTP 200 is not a trusted durable floor ACK");
  const signedFloor = await client.freshHead(genesis);
  assert.deepEqual(signedFloor, anchor.headCheckpoint());
  assert.equal(await client.advanceSignedRecords(page), false, "lost ACK retry idempotent");
  await assert.rejects(client.advanceSignedRecords([
    JSON.stringify({ ...JSON.parse(page[0]), status: "not-committed-final" }),
  ]), /CAS_WITNESS_FLOOR_UNAVAILABLE/, "valid-looking record with wrong signature is refused");
  assert.deepEqual(await client.freshHead(signedFloor), signedFloor);
  await assert.rejects(new Zk1WitnessCasAnchorHttpsClient({
    ...cfg, serverFingerprint256: "00:".repeat(31) + "00",
  }).freshHead(), /CAS_WITNESS_FLOOR_UNAVAILABLE/);
  await assert.rejects(new Zk1WitnessCasAnchorHttpsClient({
    ...cfg, clientKey: read("denied.key"), clientCert: read("denied.pem"),
  }).freshHead(), /CAS_WITNESS_FLOOR_UNAVAILABLE/);
  await assert.rejects(new Zk1WitnessCasAnchorHttpsClient({
    ...cfg, pinnedWitnessPublicKey: crypto.generateKeyPairSync("ed25519").publicKey,
  }).freshHead(), /CAS_WITNESS_FLOOR_UNAVAILABLE/);
  await assert.rejects(client.freshHead({ sequence: 1, lastHash: "e".repeat(64) }),
    /CAS_WITNESS_FLOOR_UNAVAILABLE/, "same sequence divergent owner floor is not accepted");
});
