"use strict";

// Explicit DEV-OFF process boundary for the Sync v2 retained high-water.
// No physical witness, owner custody guarantee or protected ACK capability.
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const { assertPrivateSqliteFile, assertPrivateSqliteAuthorityDirectory } =
  require("../src/services/zk1PrivateSqlitePath");
const { Zk1SyncAtomicRetainedAnchorDevOff } =
  require("../src/services/zk1SyncAtomicRetainedAnchorDevOff");
const { createZk1SyncAtomicRetainedAnchorHttpsServerDevOff } =
  require("../src/services/zk1SyncAtomicRetainedAnchorHttpsDevOff");

function demand(ok) { if (!ok) throw Error("SYNC_RETAINED_OPERATOR_DEV_OFF_DENIED"); }
function exact(object, fields) {
  demand(object && typeof object === "object" && !Array.isArray(object)
    && Object.keys(object).length === fields.length
    && fields.every((field) => Object.hasOwn(object, field)));
}

function operatorConfiguration(file) {
  demand(typeof file === "string" && path.isAbsolute(file));
  const absolute = path.resolve(file);
  const directory = path.dirname(absolute);
  assertPrivateSqliteAuthorityDirectory(absolute);
  assertPrivateSqliteFile(absolute);
  const config = JSON.parse(fs.readFileSync(absolute, "utf8"));
  exact(config, ["version", "host", "port", "database", "serverKey",
    "serverCert", "clientCa", "signerKey", "ownerBindings",
    "trustedMinimumHeads", "principals"]);
  demand(config.version === 1 && typeof config.host === "string"
    && net.isIP(config.host) !== 0
    && Number.isSafeInteger(config.port) && config.port >= 0
    && config.port <= 65535
    && (config.port !== 0 || process.env.NODE_ENV === "test"));
  const ownedFile = (name) => {
    demand(typeof name === "string" && /^[A-Za-z0-9._-]{1,100}$/.test(name)
      && name !== "." && name !== "..");
    const pathname = path.join(directory, name);
    assertPrivateSqliteFile(pathname);
    return pathname;
  };
  const dbFile = ownedFile(config.database);
  const readPrivate = (name) => fs.readFileSync(ownedFile(name));
  return {
    config, dbFile, key: readPrivate(config.serverKey),
    cert: readPrivate(config.serverCert),
    ca: readPrivate(config.clientCa),
    signerPrivateKey: crypto.createPrivateKey(readPrivate(config.signerKey)),
  };
}

async function main() {
  demand(["development", "test"].includes(process.env.NODE_ENV)
    && process.env.ROOTARK_SYNC_RETAINED_OPERATOR_DEV_OFF === "true"
    && process.argv.length === 3);
  const setup = operatorConfiguration(process.argv[2]);
  // No implicit bootstrap, secret key generation, floor reset or file repair.
  const anchor = new Zk1SyncAtomicRetainedAnchorDevOff({
    filename: setup.dbFile, bootstrapNew: false,
    ownerBindings: setup.config.ownerBindings,
    trustedMinimumHeads: setup.config.trustedMinimumHeads,
    signerPrivateKey: setup.signerPrivateKey,
  });
  let server;
  try {
    server = createZk1SyncAtomicRetainedAnchorHttpsServerDevOff({
      key: setup.key, cert: setup.cert, clientCa: setup.ca,
      anchor, principals: setup.config.principals,
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(setup.config.port, setup.config.host, resolve);
    });
  } catch (error) {
    server?.close();
    anchor.close();
    throw error;
  }
  const ready = { kind: "SYNC_RETAINED_OPERATOR_DEV_READY",
    port: server.address().port };
  if (typeof process.send === "function") process.send(ready);
  else process.stdout.write(JSON.stringify(ready) + "\n");
  const close = () => server.close(() => {
    anchor.close();
    process.exitCode = 0;
  });
  process.once("SIGTERM", close);
  process.once("SIGINT", close);
}

main().catch(() => {
  process.stderr.write("SYNC_RETAINED_OPERATOR_DEV_OFF_DENIED\n");
  process.exitCode = 1;
});
