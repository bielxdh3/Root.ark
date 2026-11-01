"use strict";

// Hosted CI only: real separate Node operator, private SQLite authority,
// TLS 1.3/mTLS and local CAS ledger. Physical witness below is SYNTHETIC.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createPrivateAuthorityFixture } = require(
  "./support/issue-65-private-authority-fixture");
const { generateNativeFixtureCertificates } = require(
  "./support/issue-65-native-openssl-fixture");
const { Zk1SyncAtomicRetainedAnchorDevOff } = require(
  "../src/services/zk1SyncAtomicRetainedAnchorDevOff");
const { Zk1SyncAtomicCasFloorLedgerDevOff, GENESIS, WITNESS_DOMAIN } = require(
  "../src/services/zk1SyncAtomicCasFloorLedgerDevOff");
const { createZk1SyncAtomicRetainedAnchorHttpsClientDevOff } = require(
  "../src/services/zk1SyncAtomicRetainedAnchorHttpsDevOff");

const CLI = path.resolve(__dirname, "../scripts/zk1-sync-retained-anchor-server-dev-off.js");
const nonce = () => crypto.randomBytes(32).toString("base64url");
const hash = () => crypto.randomBytes(32).toString("hex");
const denied = { code: "SYNC_ATOMIC_CAS_DEV_OFF_UNVERIFIED" };

function runOperator(configFile, flag = "true") {
  const env = { ...process.env, NODE_ENV: "test" };
  if (flag === null) delete env.ROOTARK_SYNC_RETAINED_OPERATOR_DEV_OFF;
  else env.ROOTARK_SYNC_RETAINED_OPERATOR_DEV_OFF = flag;
  const child = spawn(process.execPath, [CLI, configFile], {
    env, cwd: path.dirname(CLI), stdio: ["ignore", "ignore", "pipe", "ipc"],
    windowsHide: true,
  });
  let errors = "";
  child.stderr.on("data", (chunk) => { errors = (errors + chunk.toString()).slice(-1024); });
  const ready = new Promise((resolve, reject) => {
    // Windows CI may compile a fresh native owner/DACL verifier before any
    // TLS listener is created; this is not the socket's response timeout.
    const timer = setTimeout(() => reject(Error("operator readiness timeout")), 45_000);
    const stop = (error, port) => {
      clearTimeout(timer);
      child.removeListener("message", onMessage);
      child.removeListener("exit", onExit);
      if (error) reject(error);
      else resolve(port);
    };
    const onMessage = (msg) => {
      if (msg?.kind === "SYNC_RETAINED_OPERATOR_DEV_READY"
        && Number.isInteger(msg.port) && msg.port > 0) stop(null, msg.port);
    };
    const onExit = (code) => stop(Error(`operator exited ${code}: ${errors}`));
    child.on("message", onMessage);
    child.once("exit", onExit);
    child.once("error", (error) => stop(error));
  });
  return { child, ready };
}

async function stopOperator(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve) => {
    const timer = setTimeout(() => { child.kill("SIGKILL"); resolve(); }, 5000);
    child.once("exit", () => { clearTimeout(timer); resolve(); });
    child.kill("SIGTERM");
  });
}

test("opt-in separate process denies missing activation even for a valid private operator config", { timeout: 90_000 }, async (t) => {
  const directory = createPrivateAuthorityFixture("zk65-operator-gate-");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true,
    maxRetries: 10, retryDelay: 100 }));
  const configFile = path.join(directory, "operator.json");
  fs.writeFileSync(configFile, "{}", { mode: 0o600 });
  const operator = runOperator(configFile, null);
  t.after(() => stopOperator(operator.child));
  await assert.rejects(operator.ready,
    /operator exited 1: SYNC_RETAINED_OPERATOR_DEV_OFF_DENIED/,
    "missing activation must deny by the explicit operator gate, not an unrelated crash");
});

test("separate operator mTLS bridges the real CAS ledger and refuses external drift and lost authority", { timeout: 240_000 }, async (t) => {
  const directory = createPrivateAuthorityFixture("zk65-operator-bridge-");
  let operator, secondOperator, ledger;
  t.after(async () => {
    ledger?.close();
    if (operator) await stopOperator(operator.child);
    if (secondOperator) await stopOperator(secondOperator.child);
    fs.rmSync(directory, { recursive: true, force: true,
      maxRetries: 10, retryDelay: 100 });
  });
  generateNativeFixtureCertificates(directory, { caSubject: "Rootark Operator Test CA",
    servers: ["anchor-server"], clients: ["reader", "writer", "outsider"] });
  const read = (name) => fs.readFileSync(path.join(directory, name));
  const fingerprint = (name) => new crypto.X509Certificate(
    read(`${name}.pem`)).fingerprint256.toUpperCase();
  const owner = { scope: "alice:protected", accountId: crypto.randomUUID(),
    storeId: crypto.randomUUID() };
  const signer = crypto.generateKeyPairSync("ed25519");
  const database = path.join(directory, "retained.sqlite");
  new Zk1SyncAtomicRetainedAnchorDevOff({
    filename: database, bootstrapNew: true, signerPrivateKey: signer.privateKey,
    ownerBindings: [owner], trustedMinimumHeads: [{ scope: owner.scope,
      sequence: 0, headHash: GENESIS }],
  }).close();
  fs.writeFileSync(path.join(directory, "signer.key"),
    signer.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  const configFile = path.join(directory, "operator.json");
  fs.writeFileSync(configFile, JSON.stringify({
    version: 1, host: "127.0.0.1", port: 0,
    database: "retained.sqlite", serverKey: "anchor-server.key",
    serverCert: "anchor-server.pem", clientCa: "ca.pem",
    signerKey: "signer.key", ownerBindings: [owner],
    trustedMinimumHeads: [{ scope: owner.scope, sequence: 0, headHash: GENESIS }],
    principals: {
      [fingerprint("reader")]: [{ scope: owner.scope, canAdvance: false }],
      [fingerprint("writer")]: [{ scope: owner.scope, canAdvance: true }],
    },
  }), { mode: 0o600 });
  if (process.platform !== "win32") {
    // A world-readable config can expose private signer/TLS key names and
    // operator grant topology even when its parent directory is private.
    // Fail closed on its leaf permissions, not just its directory ancestry.
    fs.chmodSync(configFile, 0o644);
    const exposed = runOperator(configFile);
    await assert.rejects(exposed.ready,
      /operator exited 1: SYNC_RETAINED_OPERATOR_DEV_OFF_DENIED/);
    await stopOperator(exposed.child);
    fs.chmodSync(configFile, 0o600);
  }
  operator = runOperator(configFile);
  const port = await operator.ready;
  const client = (role, portNumber = port) => createZk1SyncAtomicRetainedAnchorHttpsClientDevOff({
    hostname: "127.0.0.1", servername: "localhost", port: portNumber,
    ca: read("ca.pem"), cert: read(`${role}.pem`), key: read(`${role}.key`),
    pinnedServerFingerprint: fingerprint("anchor-server"),
    anchorPublicKey: signer.publicKey,
  });
  const writer = client("writer");
  const reader = client("reader");
  assert.equal((await reader.readSignedHead({ scope: owner.scope,
    nonce: nonce() })).statement.sequence, 0);
  await assert.rejects(client("outsider").readSignedHead({ scope: owner.scope,
    nonce: nonce() }), { code: "SYNC_ATOMIC_RETAINED_HTTPS_DEV_OFF_DENIED" });

  const casKey = crypto.generateKeyPairSync("ed25519");
  const witnessKey = crypto.generateKeyPairSync("ed25519");
  const identity = { ...owner, username: "alice", compartmentId: "private" };
  const physical = { commitId: crypto.randomUUID(), storeHeadSha256: hash(), fencingEpoch: 3 };
  const pair = { operationIds: ["delete.alpha", "move.beta"],
    envelopeDigests: [hash(), hash()] };
  const physicalFence = { withCurrentRead: async (challenge, continuation) => {
    let held = true;
    try {
      const statement = { version: 2, ...identity, nonce: challenge.nonce,
        operationIds: challenge.operationIds, envelopeDigests: challenge.envelopeDigests,
        ...physical, physicalDurable: true };
      const receipt = { statement, signature: crypto.sign(null,
        Buffer.from(WITNESS_DOMAIN + protocol.canonicalJson(statement)),
        witnessKey.privateKey).toString("base64url") };
      return await continuation({ receipt, lineage: null }, {
        assertHeld: () => held });
    } finally { held = false; }
  } };
  const options = { filename: path.join(directory, "local-cas.sqlite"),
    bootstrapNew: true, casPrivateKey: casKey.privateKey,
    witnessPublicKey: witnessKey.publicKey, anchorPublicKey: signer.publicKey,
    ownerBindings: [identity], physicalFence, retainedAnchor: writer };
  ledger = await Zk1SyncAtomicCasFloorLedgerDevOff.open(options);
  const input = { ...owner, ...pair };
  const advanced = await ledger.recordPhysicalPair(input);
  assert.equal(advanced.sequence, 1);
  assert.deepEqual(await ledger.recordPhysicalPair(input), advanced,
    "a repeated operation cannot append another remote retained head");
  assert.equal((await reader.readSignedHead({ scope: owner.scope,
    nonce: nonce() })).statement.headHash, advanced.headHash);

  // Two genuinely separate processes contend for one physical SQLite CAS.
  // Exactly one signed advance can win, even with distinct proposed heads.
  secondOperator = runOperator(configFile);
  const secondPort = await secondOperator.ready;
  const nextHeads = [hash(), hash()];
  const peers = [writer, client("writer", secondPort)];
  const proposals = peers.map((peer, index) =>
    peer.compareAndAdvance({ scope: owner.scope,
      expectedSequence: 1, expectedHeadHash: advanced.headHash,
      sequence: 2, headHash: nextHeads[index] }));
  const contests = await Promise.allSettled(proposals);
  const winners = contests.flatMap((result, index) =>
    result.status === "fulfilled" && result.value === true ? [index] : []);
  assert.equal(winners.length, 1,
    "two different authority processes cannot both win the same CAS sequence");
  for (const [index, result] of contests.entries()) {
    if (result.status === "rejected") {
      assert.equal(result.reason?.code, "SYNC_ATOMIC_RETAINED_HTTPS_DEV_OFF_DENIED");
      assert.equal(await peers[index].compareAndAdvance({ scope: owner.scope,
        expectedSequence: 1, expectedHeadHash: advanced.headHash,
        sequence: 2, headHash: nextHeads[index] }), false,
      "a contending process that hit an unavailable lock must later reject the stale CAS");
    } else if (index !== winners[0]) {
      assert.equal(result.value, false,
        "the other process must return a stale CAS rather than any positive value");
    }
  }
  const divergent = nextHeads[winners[0]];
  const heads = await Promise.all([reader.readSignedHead({ scope: owner.scope,
    nonce: nonce() }), client("reader", secondPort).readSignedHead({
    scope: owner.scope, nonce: nonce() })]);
  for (const received of heads) {
    assert.equal(received.statement.sequence, 2);
    assert.equal(received.statement.headHash, divergent);
  }
  // A separately authorized writer changed the remote high-water without a
  // local CAS transaction. Existing local rows must never authorize fallback.
  ledger.close();
  ledger = null;
  await assert.rejects(Zk1SyncAtomicCasFloorLedgerDevOff.open({
    ...options, bootstrapNew: false,
  }), denied, "remote signed drift must refuse an apparently valid local recovery");

  await stopOperator(operator.child);
  await assert.rejects(reader.readSignedHead({ scope: owner.scope,
    nonce: nonce() }), { code: "SYNC_ATOMIC_RETAINED_HTTPS_DEV_OFF_DENIED" },
  "there is no local bypass when the independently running authority stops");
});
