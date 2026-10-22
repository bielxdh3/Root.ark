"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const Database = require("better-sqlite3");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { Zk1WitnessCasAnchorFloor } = require("../src/services/zk1WitnessCasAnchorFloor");

test("actual standalone witness refuses signed-prefix floor rollback against separately owner-pinned head", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-witness-floor-standalone-"));
  generateNativeFixtureCertificates(dir, { caSubject: "Standalone Witness CA",
    servers: ["server"], clients: ["allowed"] });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const witness = crypto.generateKeyPairSync("ed25519");
  const status = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  const witnessDb = path.join(dir, "recovery-witness.sqlite");
  const floorDb = path.join(dir, "cas-floor.sqlite");
  const terminalPath = path.join(dir, "real-signed-cas.log");
  const files = { witnessKey: path.join(dir, "witness-private.pem"),
    statusPub: path.join(dir, "status-public.pem"),
    config: path.join(dir, "witness-config.json") };
  fs.writeFileSync(files.witnessKey, witness.privateKey.export({ type: "pkcs8", format: "pem" }));
  fs.writeFileSync(files.statusPub, status.publicKey.export({ type: "spki", format: "pem" }));
  const ownWitness = new Zk1DurableWitnessLedger(witnessDb, {
    bootstrapNew: true, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusPinned: { keyId: statusKeyId, publicKey: status.publicKey },
    statusProvider: { getTerminalProof: async () => { throw new Error("NOT_USED_IN_FLOOR_TEST"); } },
  });
  ownWitness.close();
  const floor = new Zk1WitnessCasAnchorFloor(floorDb, {
    bootstrapNew: true, witnessKeyId, witnessPrivateKey: witness.privateKey,
    statusKeyId, statusPublicKey: status.publicKey,
  });
  const anchor = new Zk1CasTerminalAnchor(terminalPath, {
    bootstrapNew: true, statusKeyId, statusPrivateKey: status.privateKey,
  });
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("witness"), keyring_id: crypto.randomBytes(16) };
  for (let i = 0; i < 2; i++) {
    const q = { ...scope, reservation_id: crypto.randomBytes(16) };
    const ticket = crypto.randomBytes(90);
    const manifest = crypto.randomBytes(90);
    anchor.prepare(q, ticket, "committed", manifest);
    await anchor.append(q, ticket, "committed", manifest, crypto.randomBytes(64));
  }
  floor.advance({ records: anchor.signedRecordPage({ afterSequence: 0 }) });
  const ownerRetained = { ...floor.head() };
  assert.equal(ownerRetained.sequence, 2);
  floor.close();
  const fingerprint = new crypto.X509Certificate(read("allowed.pem")).fingerprint256;
  const config = {
    listenHost: "127.0.0.1", listenPort: 0, bootstrapNew: false,
    dbPath: witnessDb, witnessKeyId: witnessKeyId.toString("base64url"),
    witnessPrivateKeyPath: files.witnessKey,
    statusKeyId: statusKeyId.toString("base64url"),
    statusPublicKeyPath: files.statusPub,
    serverKeyPath: path.join(dir, "server.key"),
    serverCertPath: path.join(dir, "server.pem"),
    clientCaPath: path.join(dir, "ca.pem"),
    principals: { [fingerprint]: { roles: ["cas-anchor"], scopes: [] } },
    cas: { endpoint: "https://localhost:44444/v1/terminal",
      caPath: path.join(dir, "ca.pem"),
      clientKeyPath: path.join(dir, "allowed.key"),
      clientCertPath: path.join(dir, "allowed.pem"),
      serverFingerprint256: new crypto.X509Certificate(read("server.pem")).fingerprint256 },
    casAnchorFloor: { dbPath: floorDb, trustedMinimumHead: ownerRetained },
  };
  const children = new Set();
  t.after(async () => {
    for (const child of children) {
      if (child.exitCode === null) {
        const exited = new Promise((resolve) => child.once("exit", resolve));
        child.kill("SIGTERM");
        await exited;
      }
    }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  async function start(candidate, expectReady) {
    fs.writeFileSync(files.config, JSON.stringify(candidate), { mode: 0o600 });
    const child = spawn(process.execPath, [
      path.resolve(__dirname, "../scripts/zk1-witness-standalone.js"),
      "--config", files.config,
    ], { stdio: ["ignore", "pipe", "pipe", "ipc"], windowsHide: true });
    children.add(child);
    let deadline;
    try {
      const result = await Promise.race([
        new Promise((resolve, reject) => {
          child.once("message", (message) => resolve(message?.type === "ready"));
          child.once("exit", () => resolve(false));
          child.once("error", reject);
        }),
        new Promise((_, reject) => {
          deadline = setTimeout(() => reject(new Error("WITNESS_FLOOR_START_TIMEOUT")), 8000);
        }),
      ]);
      assert.equal(result, expectReady);
    } finally {
      clearTimeout(deadline);
      if (child.exitCode === null) {
        const exited = new Promise((resolve) => child.once("exit", resolve));
        child.kill("SIGTERM");
        await exited;
      }
      children.delete(child);
    }
  }
  await start(config, true);
  const { trustedMinimumHead: absent, ...withoutOwnerFloor } = config.casAnchorFloor;
  await start({ ...config, casAnchorFloor: withoutOwnerFloor }, false);
  const db = new Database(floorDb);
  try { db.prepare("DELETE FROM witness_cas_floor_event WHERE sequence=2").run(); }
  finally { db.close(); }
  await start(config, false);
  // An owner-supplied mismatch at exactly the same signed sequence must also
  // fail; comparing just numeric revision would permit signed parallel forks.
  await start({ ...config, casAnchorFloor: { ...config.casAnchorFloor,
    trustedMinimumHead: { sequence: 1, lastHash: "f".repeat(64) } } }, false);
});
