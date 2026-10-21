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
  exact(config, TOP_FIELDS);
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
  const ledger = new Zk1DurableWitnessLedger(config.dbPath, {
    bootstrapNew: config.bootstrapNew,
    witnessKeyId: decodeId(config.witnessKeyId),
    witnessPrivateKey: crypto.createPrivateKey(readFile(config.witnessPrivateKeyPath)),
    statusPinned: {
      keyId: decodeId(config.statusKeyId),
      publicKey: crypto.createPublicKey(readFile(config.statusPublicKeyPath)),
    },
    statusProvider,
  });
  try {
    const server = createZk1WitnessHttpsServer({
      key: readFile(config.serverKeyPath),
      cert: readFile(config.serverCertPath),
      clientCa: readFile(config.clientCaPath),
      principals: config.principals,
      ledger,
    });
    return { server, ledger };
  } catch (error) {
    ledger.close();
    throw error;
  }
}
async function main() {
  if (process.argv.length !== 4 || process.argv[2] !== "--config") fail();
  const config = JSON.parse(readFile(process.argv[3]).toString("utf8"));
  const { server, ledger } = configure(config);
  server.once("error", () => {
    try { ledger.close(); } catch (_) { /* fail closed */ }
    process.stderr.write("WITNESS_STARTUP_FAILED\n");
    process.exitCode = 1;
  });
  let stopping = false;
  const close = () => {
    if (stopping) return;
    stopping = true;
    void drainZk1WitnessHttpsServer(server).then(() => ledger.close()).catch(() => {
      // Do not print errors or sensitive config on shutdown failure.
      process.exitCode = 1;
      try { ledger.close(); } catch (_) { /* fail closed */ }
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
