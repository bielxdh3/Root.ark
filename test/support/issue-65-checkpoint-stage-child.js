"use strict";

// Node24 adversarial fixture: independent OS process / SQLite connection.
const crypto = require("node:crypto");
const fs = require("node:fs");
const z = require("../../src/crypto/rootark-zk-1");
const { createZk1OpaqueCatalogCasHttpsClient } =
  require("../../src/services/zk1OpaqueCatalogCasHttpsClient");
const { createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../../src/services/zk1OpaqueCatalogIndependentFloor");
const { Zk1OpaqueCatalogCheckpointV2Stage } =
  require("../../src/services/zk1OpaqueCatalogCheckpointV2Stage");

async function run() {
  const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const pem = (file) => fs.readFileSync(cfg.directory + "/" + file);
  const pub = (value) => crypto.createPublicKey(value);
  const scope = Object.fromEntries(Object.entries(cfg.scope)
    .map(([field, value]) => [field, Buffer.from(value, "base64url")]));
  const casClient = createZk1OpaqueCatalogCasHttpsClient({
    endpoint: cfg.casEndpoint, ca: pem("ca.pem"),
    clientKey: pem("client.key"), clientCert: pem("client.pem"),
    serverFingerprint256: cfg.casFingerprint,
    authorityPublicKey: pub(cfg.casSignerPem),
  });
  const floorClient = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: cfg.floorEndpoint, ca: pem("ca.pem"),
    clientKey: pem("client.key"), clientCert: pem("client.pem"),
    serverFingerprint256: cfg.floorFingerprint,
    floorPublicKey: pub(cfg.floorSignerPem),
    casSignerPublicKey: pub(cfg.casSignerPem),
    trustedScope: scope,
  });
  const stage = new Zk1OpaqueCatalogCheckpointV2Stage(cfg.stageDb, {
    bootstrapNew: false, trustedScope: scope,
    ownerPublicKey: pub(cfg.ownerSignerPem),
    checkpointPublicKey: pub(cfg.checkpointSignerPem),
    casClient, floorClient, resolveCatalogSigner: async () => pub(cfg.deviceSignerPem),
  });
  try {
    const candidate = await z.decodeDeterministic(fs.readFileSync(cfg.candidate));
    const result = await stage.stage(candidate);
    return { outcome: result.outcome, audit: await stage.audit() };
  } finally { stage.close(); }
}
run().then((result) => {
  process.stdout.write(JSON.stringify(result) + "\n");
}, (error) => {
  process.stdout.write(JSON.stringify({ error: error.code || error.message }) + "\n");
  process.exitCode = 1;
});
