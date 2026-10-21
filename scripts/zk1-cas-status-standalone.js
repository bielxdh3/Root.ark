"use strict";

// Independently startable single-node zk-1 CAS/status engine. Does NOT imply
// distributed durability, separate operator custody or physical I/O fencing.
// Operator provisions all identity files and externally pinned trust roots.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { Zk1DurableCasStatusLedger } = require("../src/services/zk1DurableCasStatusLedger");
const { createZk1CasStatusHttpsServer, drainZk1CasStatusHttpsServer } = require("../src/services/zk1CasStatusHttpsServer");

const FIELDS = Object.freeze([
  "listenHost", "listenPort", "bootstrapNew", "dbPath", "anchorPath", "statusKeyId",
  "statusPrivateKeyPath", "witnessKeyId", "witnessPublicKeyPath",
  "serverKeyPath", "serverCertPath", "clientCaPath", "principals",
]);
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
function configure(config) {
  exact(config, FIELDS);
  if ((config.bootstrapNew !== true && config.bootstrapNew !== false)
    || !["127.0.0.1", "::1"].includes(config.listenHost)
    || !Number.isSafeInteger(config.listenPort)
    || config.listenPort < 0 || config.listenPort > 65535
    || typeof config.dbPath !== "string" || !path.isAbsolute(config.dbPath)
    || typeof config.anchorPath !== "string" || !path.isAbsolute(config.anchorPath)
    || path.resolve(config.anchorPath) === path.resolve(config.dbPath)) fail();
  const ledger = new Zk1DurableCasStatusLedger(config.dbPath, {
    bootstrapNew: config.bootstrapNew,
    anchorPath: config.anchorPath,
    statusKeyId: id(config.statusKeyId),
    statusPrivateKey: crypto.createPrivateKey(readFile(config.statusPrivateKeyPath)),
    witnessPinned: {
      keyId: id(config.witnessKeyId),
      publicKey: crypto.createPublicKey(readFile(config.witnessPublicKeyPath)),
    },
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
  const { ledger, server } = configure(config);
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
