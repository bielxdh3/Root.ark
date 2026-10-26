"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const { Zk1HistoricalRecoveryOperator, ZERO } =
  require("../src/services/zk1HistoricalRecoveryOperator");
const { createSynchronousRecoveryOperatorClient, invokeRemote } =
  require("../src/services/zk1HistoricalRecoveryOperatorHttps");
const { signCommittedPhysicalReadback } =
  require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");

const operatorScript = path.resolve(__dirname, "../scripts/zk1-historical-recovery-operator.js");
const DOMAIN = Buffer.from("Root.ark/sync-v2/historical-witness-recovery-ledger/v2\0");
const sha = (raw) => crypto.createHash("sha256").update(raw).digest("hex");
const random = (n) => crypto.randomBytes(n);
const policy = { username: "owner", trustedDevicePublicKeys: { device_1: "AQAB" },
  revokedDeviceIds: [] };
const ZERO_HEAD = { sequence: 0, lastHash: ZERO };
function identity() {
  const witness = crypto.generateKeyPairSync("ed25519");
  const pg = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = random(16).toString("base64url");
  const statusKeyId = random(16).toString("base64url");
  return { witness, pg, pins: {
    witnessPublicKeyPem: witness.publicKey.export({ format: "pem", type: "spki" }),
    physicalAttestorPublicKeyPem: pg.publicKey.export({ format: "pem", type: "spki" }),
    witnessKeyId, statusKeyId,
  } };
}
async function recoveryEvidence(identityPins, prev = ZERO_HEAD) {
  const nonce = random(32);
  const scope = { account_id: random(16), compartment_id: Buffer.from("private"),
    keyring_id: random(16) };
  const operation = { operation_id: random(16), expected_sequence: 3,
    expected_root: random(32), object_id: random(16), revision: 1,
    epoch: 1, ciphertext_sha256: random(32) };
  const row = { sequence: prev.sequence + 1, nonce,
    operation_id: operation.operation_id.toString("base64url"),
    admission_hash: sha(random(32)), consumed_at_ms: Date.now(),
    previous_hash: prev.lastHash };
  row.hash = sha(row.previous_hash + "\0" + JSON.stringify([
    row.sequence, nonce.toString("base64url"), row.operation_id,
    row.admission_hash, row.consumed_at_ms,
  ]));
  const next = { sequence: row.sequence, lastHash: row.hash };
  const readySignature = crypto.sign(null, Buffer.concat([DOMAIN,
    Buffer.from(JSON.stringify([identityPins.pins.witnessKeyId,
      identityPins.pins.statusKeyId, next.sequence, next.lastHash, "READY", ZERO]))]),
  identityPins.witness.privateKey);
  const physicalIssuedAt = Math.floor(Date.now() / 1000);
  const physicalAttestation = await signCommittedPhysicalReadback({
    scope, operation, nonce, issuedAt: physicalIssuedAt,
    readback: {
      status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation: 1, admissionId: random(16),
      operationId: operation.operation_id, revision: 1, epoch: 1,
      digest: random(32), expectedInventorySequence: operation.expected_sequence,
      expectedInventoryRoot: operation.expected_root, chunkCount: 1,
      root: random(32), ciphertextSha256: operation.ciphertext_sha256,
      authorizesIo: false, provesIndependentOperator: false,
    },
  }, identityPins.pg.privateKey);
  const proof = { witnessKeyId: identityPins.pins.witnessKeyId,
    statusKeyId: identityPins.pins.statusKeyId, readySignature,
    policySnapshot: JSON.stringify(policy), ownerGeneration: 0,
    physicalIssuedAt, physicalAttestation: Buffer.from(physicalAttestation),
    scope, operation, nonce, recoveryRow: row };
  return { next, proof };
}
async function rereadPhysicalEvidence(id, proof) {
  // The PG attestor may legitimately re-read and issue a NEW signed proof for
  // the same already-consumed witness operation before finalization starts.
  const { scope, operation, nonce } = proof;
  const physicalIssuedAt = Math.floor(Date.now() / 1000);
  const physicalAttestation = await signCommittedPhysicalReadback({
    scope, operation, nonce, issuedAt: physicalIssuedAt,
    readback: { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation: 2, admissionId: random(16),
      operationId: operation.operation_id, revision: 1, epoch: 1,
      digest: random(32), expectedInventorySequence: operation.expected_sequence,
      expectedInventoryRoot: operation.expected_root, chunkCount: 1,
      root: random(32), ciphertextSha256: operation.ciphertext_sha256,
      authorizesIo: false, provesIndependentOperator: false },
  }, id.pg.privateKey);
  return { ...proof, physicalIssuedAt, physicalAttestation: Buffer.from(physicalAttestation) };
}
function privateDir() { return createPrivateAuthorityFixture("zk65-w50-op-"); }
function disposeFixture(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); }
  catch (error) {
    // Native Windows owner-only ACL fixtures can intentionally deny a recursive
    // deletion even to the process that wrote the contained database.
    if (process.platform !== "win32" || error.code !== "EPERM") throw error;
  }
}

test("operator verifies original witness/PG evidence, quarantines provisional ACK and fences owner generation", async (t) => {
  const dir = privateDir();
  const dbPath = path.join(dir, "operator.sqlite");
  const id = identity();
  const config = { databasePath: dbPath, initialPolicy: policy, ...id.pins };
  let operator = new Zk1HistoricalRecoveryOperator({ ...config, bootstrapNew: true });
  t.after(() => { operator.close(); disposeFixture(dir); });
  assert.deepEqual(operator.loadHead(), ZERO_HEAD);
  const { next, proof } = await recoveryEvidence(id);
  assert.equal(operator.compareAndAdvance(ZERO_HEAD, next), true);
  assert.equal(operator.compareAndAdvance(ZERO_HEAD, next), false,
    "stale head cannot create an ABA or duplicate nonce");
  assert.deepEqual(operator.loadHead(), next);
  assert.deepEqual(operator.loadFinalizedHead(), ZERO_HEAD);
  const badSignature = { ...proof, readySignature: random(64) };
  await assert.rejects(operator.finalizeAck(ZERO_HEAD, next, badSignature));
  const badPg = { ...proof, physicalAttestation: random(32) };
  await assert.rejects(operator.finalizeAck(ZERO_HEAD, next, badPg));
  assert.equal(await operator.finalizeAck(ZERO_HEAD, next, proof), true);
  assert.throws(() => operator.loadFinalizedHead(),
    "restart or crash after finalize cannot treat PROVISIONAL as SEALED");
  assert.equal(operator.sealAck(next, { ...proof, nonce: random(32) }), false);
  assert.equal(operator.sealAck(next, { ...proof,
    physicalIssuedAt: proof.physicalIssuedAt + 1 }), false,
  "an attacker cannot refresh the signed PG evidence age at the sealing CAS");
  operator.close();
  operator = new Zk1HistoricalRecoveryOperator(config);
  assert.throws(() => operator.loadFinalizedHead());
  assert.equal(operator.sealAck(next, proof), true);
  assert.deepEqual(operator.loadFinalizedHead(), next);
  assert.equal(operator.sealAck(next, proof), false);
  assert.equal(operator.advanceOwnerPolicy(0, { ...policy,
    revokedDeviceIds: ["device_1"] }), true);
  assert.equal(operator.loadOwnerGeneration(), 1);
  assert.equal(operator.advanceOwnerPolicy(0, policy), false);
  assert.throws(() => operator.loadFinalizedHead(),
    "durable owner revocation immediately invalidates an already SEALED ACK");
  assert.deepEqual(operator.loadQuarantinedHead(), next);
  assert.equal(operator.compareAndAdvance(next,
    { sequence: 2, lastHash: sha(random(8)) }), false);
  operator.close();
  operator = new Zk1HistoricalRecoveryOperator(config);
  assert.equal(operator.loadOwnerGeneration(), 1);
  assert.deepEqual(operator.loadQuarantinedHead(), next);
  assert.throws(() => operator.loadFinalizedHead());
  assert.throws(() => new Zk1HistoricalRecoveryOperator({ ...config, bootstrapNew: true }),
    "bootstrap cannot silently overwrite a durable operator identity");
  const other = identity();
  assert.throws(() => new Zk1HistoricalRecoveryOperator({
    databasePath: dbPath, ...other.pins }), "restart cannot substitute signing authority");
  const notYetSealed = new Zk1HistoricalRecoveryOperator({ ...config,
    databasePath: path.join(dir, "revoke-before-seal.sqlite"), bootstrapNew: true });
  try {
    assert.equal(notYetSealed.compareAndAdvance(ZERO_HEAD, next), true);
    assert.equal(await notYetSealed.finalizeAck(ZERO_HEAD, next, proof), true);
    assert.equal(notYetSealed.advanceOwnerPolicy(0, { ...policy,
      revokedDeviceIds: ["device_1"] }), true);
    assert.equal(notYetSealed.sealAck(next, proof), false,
      "an owner revoke between verification and SEAL wins the atomic CAS");
    assert.throws(() => notYetSealed.loadFinalizedHead());
  } finally { notYetSealed.close(); }
});

function writeJson(filename, value) {
  fs.writeFileSync(filename, JSON.stringify(value), { flag: "wx", mode: 0o600 });
}
function leafFingerprint(filename) {
  return new crypto.X509Certificate(fs.readFileSync(filename)).fingerprint256;
}
function spawnReady(configFile, bootstrap) {
  return new Promise((resolve, reject) => {
    const args = [operatorScript, "--serve", configFile];
    if (bootstrap) args.push("--bootstrap");
    const child = spawn(process.execPath, args,
      { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let output = "";
    let settled = false;
    const timer = setTimeout(() => fail(Error("OPERATOR_START_TIMEOUT")), 20000);
    function fail(err) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill();
      reject(err);
    }
    child.once("error", fail);
    child.once("exit", (code) => fail(Error("OPERATOR_EXIT_" + code)));
    child.stdout.on("data", (chunk) => {
      output += chunk.toString();
      if (output.length > 2048) return fail(Error("OPERATOR_STDOUT_TOO_LARGE"));
      const line = output.split("\n")[0];
      if (line.startsWith("{")) {
        try {
          const ready = JSON.parse(line);
          if (ready.ready && Number.isSafeInteger(ready.port)) {
            settled = true;
            clearTimeout(timer);
            resolve({ child, port: ready.port });
          }
        } catch (_) { /* Wait for a complete readiness line. */ }
      }
    });
  });
}
async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const done = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGKILL");
  await done;
}

test("real mTLS operator process, synchronous witness subprocess, crash and lost ACK, admin identity", async (t) => {
  const dir = privateDir();
  generateNativeFixtureCertificates(dir, { caSubject: "Recovery Operator Fixture",
    servers: ["operator"], clients: ["witness", "admin", "stranger"] });
  const id = identity();
  const fp = (name) => leafFingerprint(path.join(dir, name + ".pem"));
  const serverConfig = { operator: {
    databasePath: path.join(dir, "operator-service.sqlite"),
    initialPolicy: policy, ...id.pins,
  }, server: { host: "127.0.0.1", port: 0,
    keyPath: path.join(dir, "operator.key"), certPath: path.join(dir, "operator.pem"),
    clientCaPath: path.join(dir, "ca.pem"),
    witnessClientFingerprint: fp("witness"), adminClientFingerprint: fp("admin") } };
  const configPath = path.join(dir, "server-config.json");
  writeJson(configPath, serverConfig);
  let live = await spawnReady(configPath, true);
  t.after(async () => { await stopChild(live.child); disposeFixture(dir); });
  function clientConfig(name, port, override = {}) {
    const file = path.join(dir, `${name}-${port}-${crypto.randomBytes(3).toString("hex")}.json`);
    writeJson(file, { client: { hostname: "localhost", port,
      keyPath: path.join(dir, name + ".key"),
      certPath: path.join(dir, name + ".pem"),
      serverCaPath: path.join(dir, "ca.pem"),
      serverFingerprint: fp("operator"), ...override } });
    return file;
  }
  let witnessConfig = clientConfig("witness", live.port);
  let adminConfig = clientConfig("admin", live.port);
  const client = createSynchronousRecoveryOperatorClient(witnessConfig);
  assert.deepEqual(client.loadHead(), ZERO_HEAD);
  const { next, proof } = await recoveryEvidence(id);
  assert.equal(client.compareAndAdvance(ZERO_HEAD, next), true);
  assert.deepEqual(client.loadHead(), next);
  await assert.rejects(invokeRemote(adminConfig, "compareAndAdvance", [next,
    { sequence: 2, lastHash: sha(random(32)) }]));
  await assert.rejects(invokeRemote(witnessConfig, "advanceOwnerPolicy", [0, policy]));
  await assert.rejects(invokeRemote(clientConfig("stranger", live.port), "loadHead", []));
  assert.throws(() => createSynchronousRecoveryOperatorClient(clientConfig(
    "witness", live.port, { serverFingerprint: fp("witness") })).loadHead());
  // Operator commits an external head; caller could lose that ACK and crash.
  // After a real hard kill, the head is retained, but the unfinalized nonce
  // never authorizes historical recovery.
  await stopChild(live.child);
  live = await spawnReady(configPath, false);
  witnessConfig = clientConfig("witness", live.port);
  adminConfig = clientConfig("admin", live.port);
  let restart = createSynchronousRecoveryOperatorClient(witnessConfig);
  assert.deepEqual(restart.loadHead(), next);
  assert.deepEqual(restart.loadFinalizedHead(), ZERO_HEAD);
  assert.equal(restart.compareAndAdvance(ZERO_HEAD, next), false);
  const freshProof = await rereadPhysicalEvidence(id, proof);
  assert.equal(await restart.finalizeAck(ZERO_HEAD, next, freshProof), true);
  assert.throws(() => restart.loadFinalizedHead());
  // Hard crash while SQLite contains a durable PROVISIONAL transition.
  await stopChild(live.child);
  live = await spawnReady(configPath, false);
  witnessConfig = clientConfig("witness", live.port);
  restart = createSynchronousRecoveryOperatorClient(witnessConfig);
  assert.deepEqual(restart.loadHead(), next);
  assert.throws(() => restart.loadFinalizedHead());
  assert.equal(restart.sealAck(next, freshProof), true);
  assert.deepEqual(restart.loadFinalizedHead(), next);
  await stopChild(live.child);
  live = await spawnReady(configPath, false);
  witnessConfig = clientConfig("witness", live.port);
  adminConfig = clientConfig("admin", live.port);
  const retained = createSynchronousRecoveryOperatorClient(witnessConfig);
  assert.deepEqual(retained.loadFinalizedHead(), next);
  const inspect = spawnSync(process.execPath, [operatorScript, "--inspect", adminConfig],
    { encoding: "utf8", windowsHide: true, timeout: 10000 });
  assert.equal(inspect.status, 0);
  assert.deepEqual(JSON.parse(inspect.stdout), { ownerGeneration: 0, head: next });
  const updateFile = path.join(dir, "new-owner-policy.json");
  writeJson(updateFile, { ...policy, revokedDeviceIds: ["device_1"] });
  const update = spawnSync(process.execPath, [operatorScript, "--advance-policy",
    adminConfig, "0", updateFile], { encoding: "utf8", windowsHide: true, timeout: 10000 });
  assert.equal(update.status, 0);
  assert.equal(retained.loadOwnerGeneration(), 1);
  assert.throws(() => retained.loadFinalizedHead());
  assert.deepEqual(retained.loadQuarantinedHead(), next);
  const stale = spawnSync(process.execPath, [operatorScript, "--advance-policy",
    adminConfig, "0", updateFile], { encoding: "utf8", windowsHide: true, timeout: 10000 });
  assert.notEqual(stale.status, 0, "stale admin policy generation fails closed");
  assert.equal(retained.compareAndAdvance(next, {
    sequence: 2, lastHash: sha(random(32)),
  }), false);
});
