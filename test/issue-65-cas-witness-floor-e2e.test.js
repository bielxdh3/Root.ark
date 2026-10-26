"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const net = require("node:net");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { generateNativeFixtureCertificates, runNativeOpenSsl } =
  require("./support/issue-65-native-openssl-fixture");
const { Zk1WitnessCasAnchorFloor } = require("../src/services/zk1WitnessCasAnchorFloor");
const { Zk1WitnessCasAnchorHttpsClient } =
  require("../src/services/zk1WitnessCasAnchorHttpsClient");
const { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer } =
  require("../src/services/zk1WitnessHttpsServer");
const { Zk1DurableCasStatusLedger } =
  require("../src/services/zk1DurableCasStatusLedger");
const { Zk1DurableWitnessLedger } =
  require("../src/services/zk1DurableWitnessLedger");
const manifestV2 = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const z = require("../src/crypto/rootark-zk-1");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");

test("real mTLS CAS commit publishes signed independent witness floor; both local CAS files rolled back cannot restart", async (t) => {
  const directory = require("./support/issue-65-private-authority-fixture")
    .createPrivateAuthorityFixture("rootark-cas-witness-floor-e2e-");
  generateNativeFixtureCertificates(directory, {
    caSubject: "Dual Authority Floor CA", servers: ["server", "cas-server"], clients: ["allowed"],
  });
  const read = (name) => fs.readFileSync(path.join(directory, name));
  const witnessKeys = crypto.generateKeyPairSync("ed25519");
  const statusKeys = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  const floor = new Zk1WitnessCasAnchorFloor(path.join(directory, "witness-independent-floor.sqlite"), {
    bootstrapNew: true, witnessPrivateKey: witnessKeys.privateKey,
    witnessKeyId, statusKeyId, statusPublicKey: statusKeys.publicKey,
  });
  const fingerprint = new crypto.X509Certificate(read("allowed.pem")).fingerprint256;
  const unused = async () => { throw new Error("OTHER_WITNESS_ROUTE_NOT_CONFIGURED"); };
  const floorService = createZk1WitnessHttpsServer({
    key: read("server.key"), cert: read("server.pem"), clientCa: read("ca.pem"),
    casAnchorFloor: floor,
    ledger: { reserve: unused, freshHead: unused, resolve: unused,
      prepareQuiesce: unused, cancelExpiredQuiesce: unused,
      beginIoAdmission: unused, finishIoAdmission: unused },
    principals: { [fingerprint]: { roles: ["cas-anchor"], scopes: [] } },
  });
  await new Promise((resolve) => floorService.listen(0, "127.0.0.1", resolve));
  const floorClient = new Zk1WitnessCasAnchorHttpsClient({
    endpoint: `https://localhost:${floorService.address().port}`,
    ca: read("ca.pem"), clientKey: read("allowed.key"), clientCert: read("allowed.pem"),
    serverFingerprint256: new crypto.X509Certificate(read("server.pem")).fingerprint256,
    pinnedWitnessPublicKey: witnessKeys.publicKey,
    pinnedWitnessKeyId: witnessKeyId, pinnedStatusKeyId: statusKeyId,
  });
  const casPath = path.join(directory, "cas.sqlite");
  const anchorPath = path.join(directory, "cas-terminal.log");
  const casInitialCopy = path.join(directory, "pre-commit-cas.sqlite");
  const anchorInitialCopy = path.join(directory, "pre-commit-anchor.log");
  const casOptions = {
    bootstrapNew: true, statusKeyId, statusPrivateKey: statusKeys.privateKey,
    anchorPath, casAnchorWitness: floorClient,
    trustedAnchorMinimumHead: await floorClient.freshHead(),
    witnessPinned: { keyId: witnessKeyId, publicKey: witnessKeys.publicKey },
    nowSeconds: () => 1100,
  };
  const cas = new Zk1DurableCasStatusLedger(casPath, casOptions);
  const state = await fixtures.createInitialState(1);
  const manifest = state.headManifest;
  const raw = Buffer.from(await z.encodeDeterministic(manifest));
  const operation = { ...state.scope,
    reservation_id: crypto.randomBytes(16), operation_id: Buffer.from(manifest.operation.operation_id),
    expected_revision: null, expected_manifest_digest: null, proposed_revision: 1,
    proposed_manifest_digest: Buffer.from(await manifestV2.recoveryManifestDigestV2(manifest)),
    request_digest: Buffer.from(manifest.operation.request_digest),
    package_envelope_digest: null, expires_at: Number(manifest.operation.expires_at),
  };
  const witness = new Zk1DurableWitnessLedger(path.join(directory, "witness-recovery.sqlite"), {
    bootstrapNew: true, witnessKeyId,
    witnessPrivateKey: witnessKeys.privateKey,
    statusPinned: { keyId: statusKeyId, publicKey: statusKeys.publicKey },
    statusProvider: cas, nowSeconds: () => 1100,
  });
  let casClosed = false;
  t.after(async () => {
    if (!casClosed) cas.close();
    witness.close();
    await drainZk1WitnessHttpsServer(floorService);
    floor.close();
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  cas.db.pragma("wal_checkpoint(TRUNCATE)");
  fs.copyFileSync(casPath, casInitialCopy);
  fs.copyFileSync(anchorPath, anchorInitialCopy);
  const ticket = await witness.reserve(operation);
  assert.equal((await cas.registerReservation({ receipt: ticket })).status, "pending");
  const originalAdvance = floorClient.advanceSignedRecords.bind(floorClient);
  let ackLost = false;
  floorClient.advanceSignedRecords = async (records) => {
    await originalAdvance(records);
    if (!ackLost) { ackLost = true; throw new Error("SYNTHETIC_LOST_WITNESS_ACK"); }
    return false;
  };
  assert.deepEqual(await cas.commit({ receipt: ticket, manifestBytes: raw }),
    { status: "committed", replay: false });
  assert.equal(ackLost, true, "a lost ACK after witness persistence is reconciled through a new signed head");
  assert.equal((await floorClient.freshHead()).sequence, 1);
  assert.equal((await cas.getCommittedManifest({ scope: state.scope })).toString("hex"), raw.toString("hex"));
  assert.equal((await witness.resolve({ scope: state.scope })).status, "committed");
  const originalHead = floorClient.freshHead.bind(floorClient);
  floorClient.freshHead = async () => { throw new Error("SYNTHETIC_WITNESS_PARTITION"); };
  try {
    await assert.rejects(cas.getCommittedManifest({ scope: state.scope }),
      /CAS_ANCHOR_WITNESS_UNAVAILABLE/,
      "witness offline denies all CAS manifest reads in strict mode");
  } finally { floorClient.freshHead = originalHead; }
  assert.deepEqual(await cas.getCommittedManifest({ scope: state.scope }), raw);
  cas.close();
  casClosed = true;
  // Exercise the actual standalone entrypoint: it MUST fetch and validate
  // the independent witness floor before opening the old CAS database.
  const statusPath = path.join(directory, "status-private.pem");
  const witnessPath = path.join(directory, "witness-public.pem");
  const configPath = path.join(directory, "cas-standalone-config.json");
  fs.writeFileSync(statusPath, statusKeys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(witnessPath, witnessKeys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  const scopeWire = Object.fromEntries(Object.entries(state.scope)
    .map(([key, bytes]) => [key, Buffer.from(bytes).toString("base64url")]));
  const standaloneConfig = {
    listenHost: "127.0.0.1", listenPort: 0, bootstrapNew: false,
    dbPath: casPath, anchorPath,
    statusKeyId: statusKeyId.toString("base64url"), statusPrivateKeyPath: statusPath,
    witnessKeyId: witnessKeyId.toString("base64url"), witnessPublicKeyPath: witnessPath,
    serverKeyPath: path.join(directory, "cas-server.key"),
    serverCertPath: path.join(directory, "cas-server.pem"),
    clientCaPath: path.join(directory, "ca.pem"),
    principals: { [fingerprint]: { roles: ["terminal"], scopes: [scopeWire] } },
    casAnchorWitness: {
      endpoint: `https://localhost:${floorService.address().port}`,
      caPath: path.join(directory, "ca.pem"),
      clientKeyPath: path.join(directory, "allowed.key"),
      clientCertPath: path.join(directory, "allowed.pem"),
      serverFingerprint256: new crypto.X509Certificate(read("server.pem")).fingerprint256,
    },
  };
  async function launchStandalone(config, expectReady, extraEnv = {}) {
    fs.writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
    const child = spawn(process.execPath, [
      path.resolve(__dirname, "../scripts/zk1-cas-status-standalone.js"),
      "--config", configPath,
    ], { stdio: ["ignore", "pipe", "pipe", "ipc"], windowsHide: true,
      env: { ...process.env, ...extraEnv } });
    let timer;
    try {
      const ready = await Promise.race([
        new Promise((resolve) => {
          child.once("message", (message) => resolve(message?.type === "ready"));
          child.once("exit", () => resolve(false));
        }),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("CAS_STANDALONE_TIMEOUT")), 8000);
        }),
      ]);
      assert.equal(ready, expectReady);
    } finally {
      clearTimeout(timer);
      if (child.exitCode === null) {
        const exited = new Promise((resolve) => child.once("exit", resolve));
        child.kill("SIGTERM");
        await exited;
      }
    }
  }
  await launchStandalone(standaloneConfig, true);
  // An operator can opt in to a real private-IP listener. That is a wider
  // trust boundary than loopback: never let an unanchored fresh CAS bootstrap
  // there, even with a valid mTLS server identity and bound interface.
  const privateAdapter = Object.entries(os.networkInterfaces()).flatMap(([name, addresses]) =>
    (addresses || []).map((a) => ({ name, a }))).find(({ a }) => {
      if (a.internal || (a.family !== "IPv4" && a.family !== 4)
        || net.isIP(a.address) !== 4) return false;
      const [x, y] = a.address.split(".").map(Number);
      return x === 10 || (x === 172 && y >= 16 && y <= 31)
        || (x === 192 && y === 168);
    });
  if (privateAdapter) {
    const host = privateAdapter.a.address;
    const pins = {
      ROOTARK_ZK1_CAS_PRIVATE_BIND_HOST: host,
      ROOTARK_ZK1_CAS_PRIVATE_BIND_INTERFACE: privateAdapter.name,
    };
    const certName = "cas-server-private.pem";
    fs.writeFileSync(path.join(directory, "cas-server-private.ext"), [
      "extendedKeyUsage=serverAuth", "keyUsage=digitalSignature,keyEncipherment",
      "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:" + host, "",
    ].join("\n"));
    runNativeOpenSsl(directory, ["x509", "-req", "-in", "cas-server.csr",
      "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", certName, "-days", "1", "-extfile", "cas-server-private.ext"]);
    const remoteBase = { ...standaloneConfig, listenHost: host,
      serverCertPath: path.join(directory, certName) };
    const unanchored = { ...remoteBase, bootstrapNew: true,
      dbPath: path.join(directory, "unanchored-remote.sqlite"),
      anchorPath: path.join(directory, "unanchored-remote.log") };
    delete unanchored.casAnchorWitness;
    await launchStandalone(unanchored, false, pins);
    assert.equal(fs.existsSync(unanchored.dbPath), false,
      "no new SQLite CAS may be created before remote witness enrollment");
    await launchStandalone({ ...unanchored, casAnchorWitness: null }, false, pins);
    assert.equal(fs.existsSync(unanchored.dbPath), false);
    // An advertised witness with an unavailable live mTLS endpoint is also
    // insufficient: no stale copy of a formerly valid head authorizes start.
    const offline = { ...remoteBase, casAnchorWitness: {
      ...remoteBase.casAnchorWitness, endpoint: "https://127.0.0.1:1/",
    } };
    const originalDb = fs.readFileSync(casPath);
    await launchStandalone(offline, false, pins);
    assert.deepEqual(fs.readFileSync(casPath), originalDb,
      "witness outage must refuse before mutating an existing CAS image");
    await launchStandalone(remoteBase, true, pins);
  } else t.diagnostic("No RFC1918 interface: cross-host-capable bind test omitted");
  // The CAS database writer can directly rewrite the OPTIONAL-mode marker.
  // The independently signed CAS genesis must still force the witness role:
  // mutable SQLite alone is not trusted to enable/disable security features.
  const Database = require("better-sqlite3");
  const tamper = new Database(casPath);
  try {
    assert.equal(tamper.prepare("SELECT cas_anchor_witness_required FROM cas_identity WHERE id=1")
      .get().cas_anchor_witness_required, 1);
    tamper.prepare("UPDATE cas_identity SET cas_anchor_witness_required=0 WHERE id=1").run();
  } finally { tamper.close(); }
  const { casAnchorWitness: omitted, ...downgraded } = standaloneConfig;
  await launchStandalone(downgraded, false);
  assert.throws(() => new Zk1DurableCasStatusLedger(casPath, {
    ...casOptions, bootstrapNew: false,
    casAnchorWitness: null, trustedAnchorMinimumHead: undefined,
  }), /CAS_ANCHOR_INVALID/,
  "altered SQLite mode bit cannot defeat mandatory signed CAS witness enrollment");
  assert.throws(() => new Zk1DurableCasStatusLedger(casPath, {
    ...casOptions, bootstrapNew: false,
    casAnchorWitness: null, trustedAnchorMinimumHead: undefined,
  }), /CAS_(?:IDENTITY_MISMATCH|ANCHOR_INVALID)/,
  "turning off external floor after strict bootstrap cannot reopen the CAS");
  // Restore the perfectly valid previous CAS SQLite and signed terminal
  // genesis. The independently administered witness retains its last head.
  fs.copyFileSync(casInitialCopy, casPath);
  fs.copyFileSync(anchorInitialCopy, anchorPath);
  const independentlyPinnedHead = await floorClient.freshHead();
  assert.equal(independentlyPinnedHead.sequence, 1);
  assert.throws(() => new Zk1DurableCasStatusLedger(casPath, {
    ...casOptions, bootstrapNew: false,
    trustedAnchorMinimumHead: independentlyPinnedHead,
  }), /CAS_ANCHOR_INVALID/,
  "even two restored locally legitimate CAS files cannot erase the witness-owned floor");
});
