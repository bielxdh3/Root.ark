"use strict";

// Independently startable single-node zk-1 CAS/status engine. Does NOT imply
// distributed durability, separate operator custody or physical I/O fencing.
// Operator provisions all identity files and externally pinned trust roots.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { Zk1DurableCasStatusLedger } = require("../src/services/zk1DurableCasStatusLedger");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");
const { Zk1WitnessCasAnchorHttpsClient } =
  require("../src/services/zk1WitnessCasAnchorHttpsClient");
const { createZk1CasStatusHttpsServer, drainZk1CasStatusHttpsServer } = require("../src/services/zk1CasStatusHttpsServer");

const FIELDS = Object.freeze([
  "listenHost", "listenPort", "bootstrapNew", "dbPath", "anchorPath", "statusKeyId",
  "statusPrivateKeyPath", "witnessKeyId", "witnessPublicKeyPath",
  "serverKeyPath", "serverCertPath", "clientCaPath", "principals",
]);
const ANCHOR_FIELDS = Object.freeze(["endpoint", "caPath", "clientKeyPath",
  "clientCertPath", "serverFingerprint256"]);
function fail() { throw new Error("CAS_STATUS_STARTUP_FAILED"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((key) => !Object.hasOwn(value, key))
    || Reflect.ownKeys(value).some((key) => !fields.includes(key))) fail();
}
function readFile(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)) fail();
  const info = fs.statSync(value);
  if (!info.isFile() || info.size <= 0 || info.size > 65536) fail();
  return fs.readFileSync(value);
}
function id(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(value)) fail();
  const result = Buffer.from(value, "base64url");
  if (result.length !== 16 || result.toString("base64url") !== value) fail();
  return result;
}
async function configure(config) {
  exact(config, Object.hasOwn(config || {}, "casAnchorWitness")
    ? [...FIELDS, "casAnchorWitness"] : FIELDS);
  if ((config.bootstrapNew !== true && config.bootstrapNew !== false)
    || !["127.0.0.1", "::1"].includes(config.listenHost)
    || !Number.isSafeInteger(config.listenPort)
    || config.listenPort < 0 || config.listenPort > 65535
    || typeof config.dbPath !== "string" || !path.isAbsolute(config.dbPath)
    || typeof config.anchorPath !== "string" || !path.isAbsolute(config.anchorPath)
    || path.resolve(config.anchorPath) === path.resolve(config.dbPath)) fail();
  const statusKeyId = id(config.statusKeyId);
  const statusPrivateKey = crypto.createPrivateKey(readFile(config.statusPrivateKeyPath));
  const witnessKeyId = id(config.witnessKeyId);
  const witnessPublicKey = crypto.createPublicKey(readFile(config.witnessPublicKeyPath));
  let casAnchorWitness = null;
  let trustedAnchorMinimumHead;
  if (Object.hasOwn(config, "casAnchorWitness")) {
    exact(config.casAnchorWitness, ANCHOR_FIELDS);
    const settings = config.casAnchorWitness;
    casAnchorWitness = new Zk1WitnessCasAnchorHttpsClient({
      endpoint: settings.endpoint, ca: readFile(settings.caPath),
      clientKey: readFile(settings.clientKeyPath),
      clientCert: readFile(settings.clientCertPath),
      serverFingerprint256: settings.serverFingerprint256,
      pinnedWitnessPublicKey: witnessPublicKey,
      pinnedWitnessKeyId: witnessKeyId, pinnedStatusKeyId: statusKeyId,
    });
    // Fail BEFORE opening or creating CAS SQLite on witness outage, nonce
    // replay, wrong signer or rollback. Never trust a locally derived floor.
    trustedAnchorMinimumHead = await casAnchorWitness.freshHead();
    if (!config.bootstrapNew && trustedAnchorMinimumHead.sequence === 0) {
      // An existing, nonempty CAS history cannot enroll into an EMPTY
      // independent witness floor without separately reviewed owner-backed
      // migration. It would bless a jointly rolled-back legacy CAS.
      const journal = new Zk1CasTerminalAnchor(config.anchorPath, {
        bootstrapNew: false, statusKeyId, statusPrivateKey,
        trustedMinimumHead: trustedAnchorMinimumHead,
        witnessRequired: true, witnessKeyId,
      });
      if (journal.headCheckpoint().sequence !== 0) fail();
    }
  }
  const ledger = new Zk1DurableCasStatusLedger(config.dbPath, {
    bootstrapNew: config.bootstrapNew,
    anchorPath: config.anchorPath,
    statusKeyId, statusPrivateKey,
    witnessPinned: {
      keyId: witnessKeyId, publicKey: witnessPublicKey,
    },
    casAnchorWitness, trustedAnchorMinimumHead,
  });
  try {
    return {
      ledger,
      server: createZk1CasStatusHttpsServer({
        key: readFile(config.serverKeyPath),
        cert: readFile(config.serverCertPath),
        clientCa: readFile(config.clientCaPath),
        principals: config.principals,
        ledger,
      }),
    };
  } catch (error) {
    ledger.close();
    throw error;
  }
}
async function main() {
  if (process.argv.length !== 4 || process.argv[2] !== "--config") fail();
  const config = JSON.parse(readFile(process.argv[3]).toString("utf8"));
  const { ledger, server } = await configure(config);
  let stopping = false;
  const close = () => {
    if (stopping) return;
    stopping = true;
    void drainZk1CasStatusHttpsServer(server).then(() => ledger.close()).catch(() => {
      process.exitCode = 1;
      try { ledger.close(); } catch (_) { /* fail closed */ }
    });
  };
  process.on("SIGTERM", close);
  process.on("SIGINT", close);
  server.once("error", () => {
    try { ledger.close(); } catch (_) { /* fail closed */ }
    process.stderr.write("CAS_STATUS_STARTUP_FAILED\n");
    process.exitCode = 1;
  });
  server.listen(config.listenPort, config.listenHost, () => {
    // Only disposable test supervisor receives the selected ephemeral port.
    if (typeof process.send === "function") {
      process.send({ type: "ready", port: server.address().port });
    }
  });
}
main().catch(() => {
  process.stderr.write("CAS_STATUS_STARTUP_FAILED\n");
  process.exitCode = 1;
});
