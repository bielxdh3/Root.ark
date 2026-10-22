"use strict";

// Independently startable zk-1 witness transport with strict opt-in.
// Credentials are provisioned by the operator as separate file paths and
// NEVER generated, printed, placed into Root.ark app config, or defaulted.
// No app runtime import, keyring/content I/O gate, or CAS status server.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer } = require("../src/services/zk1WitnessHttpsServer");
const { createZk1CasStatusHttpsClient } = require("../src/services/zk1CasStatusHttpsClient");
const { Zk1WitnessCasAnchorFloor } =
  require("../src/services/zk1WitnessCasAnchorFloor");

const TOP_FIELDS = Object.freeze([
  "listenHost", "listenPort", "bootstrapNew", "dbPath", "witnessKeyId",
  "witnessPrivateKeyPath", "statusKeyId", "statusPublicKeyPath",
  "serverKeyPath", "serverCertPath", "clientCaPath", "principals", "cas",
]);
const CAS_FIELDS = Object.freeze([
  "endpoint", "caPath", "clientKeyPath", "clientCertPath", "serverFingerprint256",
]);
function fail() { throw new Error("WITNESS_STARTUP_FAILED"); }
function exact(value, names) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== names.length
    || names.some((name) => !Object.hasOwn(value, name))
    || Reflect.ownKeys(value).some((name) => !names.includes(name))) fail();
}
function readFile(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)) fail();
  const stat = fs.statSync(value);
  if (!stat.isFile() || stat.size === 0 || stat.size > 65536) fail();
  return fs.readFileSync(value);
}
function decodeId(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(value)) fail();
  const buffer = Buffer.from(value, "base64url");
  if (buffer.length !== 16 || buffer.toString("base64url") !== value) fail();
  return buffer;
}
function configure(config) {
  exact(config, Object.hasOwn(config || {}, "casAnchorFloor")
    ? [...TOP_FIELDS, "casAnchorFloor"] : TOP_FIELDS);
  exact(config.cas, CAS_FIELDS);
  if (config.bootstrapNew !== true && config.bootstrapNew !== false) fail();
  // Only bind loopback by default. A remote deployment requires a reviewed
  // network isolation/provisioning profile, not accidental 0.0.0.0 exposure.
  if (config.listenHost !== "127.0.0.1" && config.listenHost !== "::1") fail();
  if (!Number.isSafeInteger(config.listenPort)
    || config.listenPort < 0 || config.listenPort > 65535
    || typeof config.dbPath !== "string" || !path.isAbsolute(config.dbPath)) fail();
  const statusProvider = createZk1CasStatusHttpsClient({
    endpoint: config.cas.endpoint,
    ca: readFile(config.cas.caPath),
    clientKey: readFile(config.cas.clientKeyPath),
    clientCert: readFile(config.cas.clientCertPath),
    serverFingerprint256: config.cas.serverFingerprint256,
  });
  const witnessKeyId = decodeId(config.witnessKeyId);
  const witnessPrivateKey = crypto.createPrivateKey(readFile(config.witnessPrivateKeyPath));
  const statusKeyId = decodeId(config.statusKeyId);
  const statusPublicKey = crypto.createPublicKey(readFile(config.statusPublicKeyPath));
  let floor = null;
  if (Object.hasOwn(config, "casAnchorFloor")) {
    // This is provisioned by the OUTSIDE owner/witness overseer. A restarted
    // witness may not derive its own minimum from its restored SQLite file.
    // The operator must advance this out-of-band checkpoint after witnessed
    // receipts; a stale external checkpoint cannot prevent every rollback.
    exact(config.casAnchorFloor, ["dbPath", "trustedMinimumHead"]);
    exact(config.casAnchorFloor.trustedMinimumHead, ["sequence", "lastHash"]);
    if (typeof config.casAnchorFloor.dbPath !== "string"
      || !path.isAbsolute(config.casAnchorFloor.dbPath)
      || path.resolve(config.casAnchorFloor.dbPath) === path.resolve(config.dbPath)
      || !Number.isSafeInteger(config.casAnchorFloor.trustedMinimumHead.sequence)
      || config.casAnchorFloor.trustedMinimumHead.sequence < 0
      || config.casAnchorFloor.trustedMinimumHead.sequence > 100000
      || typeof config.casAnchorFloor.trustedMinimumHead.lastHash !== "string"
      || !/^[a-f0-9]{64}$/.test(config.casAnchorFloor.trustedMinimumHead.lastHash)
      || (config.casAnchorFloor.trustedMinimumHead.sequence === 0
        && config.casAnchorFloor.trustedMinimumHead.lastHash !== "0".repeat(64))) fail();
    if (fs.existsSync(config.casAnchorFloor.dbPath)
      && fs.existsSync(config.dbPath)
      && fs.realpathSync.native(config.casAnchorFloor.dbPath).toLowerCase()
        === fs.realpathSync.native(config.dbPath).toLowerCase()) fail();
    floor = new Zk1WitnessCasAnchorFloor(config.casAnchorFloor.dbPath, {
      bootstrapNew: config.bootstrapNew, witnessKeyId,
      witnessPrivateKey, statusKeyId, statusPublicKey,
      trustedMinimumHead: config.casAnchorFloor.trustedMinimumHead,
    });
  }
  let ledger;
  try { ledger = new Zk1DurableWitnessLedger(config.dbPath, {
    bootstrapNew: config.bootstrapNew,
    witnessKeyId, witnessPrivateKey,
    statusPinned: {
      keyId: statusKeyId, publicKey: statusPublicKey,
    },
    statusProvider,
  }); } catch (error) { floor?.close(); throw error; }
  try {
    const server = createZk1WitnessHttpsServer({
      key: readFile(config.serverKeyPath),
      cert: readFile(config.serverCertPath),
      clientCa: readFile(config.clientCaPath),
      principals: config.principals,
      ledger,
      casAnchorFloor: floor,
    });
    return { server, ledger, floor };
  } catch (error) {
    ledger.close();
    floor?.close();
    throw error;
  }
}
async function main() {
  if (process.argv.length !== 4 || process.argv[2] !== "--config") fail();
  const config = JSON.parse(readFile(process.argv[3]).toString("utf8"));
  const { server, ledger, floor } = configure(config);
  server.once("error", () => {
    try { ledger.close(); } catch (_) { /* fail closed */ }
    try { floor?.close(); } catch (_) { /* fail closed */ }
    process.stderr.write("WITNESS_STARTUP_FAILED\n");
    process.exitCode = 1;
  });
  let stopping = false;
  const close = () => {
    if (stopping) return;
    stopping = true;
    void drainZk1WitnessHttpsServer(server).then(() => {
      ledger.close();
      floor?.close();
    }).catch(() => {
      // Do not print errors or sensitive config on shutdown failure.
      process.exitCode = 1;
      try { ledger.close(); } catch (_) { /* fail closed */ }
      try { floor?.close(); } catch (_) { /* fail closed */ }
    });
  };
  process.on("SIGTERM", close);
  process.on("SIGINT", close);
  server.listen(config.listenPort, config.listenHost, () => {
    // IPC is for the disposable integration test supervisor only.
    // Do not disclose keys, file paths, operation data or user scopes.
    if (typeof process.send === "function") {
      process.send({ type: "ready", port: server.address().port });
    }
  });
}
main().catch(() => {
  process.stderr.write("WITNESS_STARTUP_FAILED\n");
  process.exitCode = 1;
});
