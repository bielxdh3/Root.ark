"use strict";

// Child-process fixture, never a product server launcher.
const crypto = require("node:crypto");
const fs = require("node:fs");
const { Zk1OpaqueCatalogCasLedger } =
  require("../../src/services/zk1OpaqueCatalogCasLedger");
const { createZk1OpaqueCatalogCasHttpsServer } =
  require("../../src/services/zk1OpaqueCatalogCasHttpsServer");
const { createZk1OpaqueCatalogCasHttpsClient } =
  require("../../src/services/zk1OpaqueCatalogCasHttpsClient");
const { Zk1OpaqueCatalogIndependentFloorLedger,
  createZk1OpaqueCatalogIndependentFloorHttpsServer,
  createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../../src/services/zk1OpaqueCatalogIndependentFloor");

const read = (name) => fs.readFileSync(name);
const scope = (object) => Object.fromEntries(Object.entries(object)
  .map(([key, value]) => [key, Buffer.from(value, "base64url")]));
async function run() {
  const mode = process.argv[2];
  const config = JSON.parse(read(process.argv[3]).toString("utf8"));
  if (mode === "floor") {
    const ledger = new Zk1OpaqueCatalogIndependentFloorLedger(config.floorDbPath, {
      bootstrapNew: config.floorBootstrapNew, trustedScope: scope(config.scope),
      signingPrivateKey: crypto.createPrivateKey(read(config.floorKeyPath)),
      casSignerPublicKey: crypto.createPublicKey(read(config.authorityPublicKeyPath)),
      catalogSignerPublicKey: crypto.createPublicKey(read(config.catalogPublicKeyPath)),
    });
    const peerCert = new crypto.X509Certificate(read(config.clientCertPath));
    const server = createZk1OpaqueCatalogIndependentFloorHttpsServer({
      ledger, key: read(config.floorServerKeyPath), cert: read(config.floorServerCertPath),
      clientCa: read(config.caPath), authorizedClientFingerprint256: peerCert.fingerprint256,
      testOnlyDropAckOnce: config.floorDropAckOnce,
    });
    process.on("message", (message) => {
      if (message !== "stop") return;
      server.close(() => {
        ledger.db.pragma("wal_checkpoint(TRUNCATE)"); ledger.close();
        process.send?.({ stopped: true }, () => process.exit(0));
      });
      server.closeAllConnections();
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    process.send({ port: server.address().port });
    return;
  }
  if (mode === "server") {
    const signerPrivateKey = crypto.createPrivateKey(read(config.authorityKeyPath));
    const ledger = new Zk1OpaqueCatalogCasLedger(config.dbPath, {
      bootstrapNew: config.bootstrapNew,
      signingPrivateKey: signerPrivateKey,
      catalogSignerPublicKey: crypto.createPublicKey(read(config.catalogPublicKeyPath)),
      trustedScope: scope(config.scope),
      minimumHead: { sequence: config.minimumSequence,
        digest: Buffer.from(config.minimumDigest, "base64url") },
      independentFloor: createZk1OpaqueCatalogIndependentFloorHttpsClient({
        endpoint: config.floorEndpoint, ca: read(config.caPath),
        clientKey: read(config.clientKeyPath), clientCert: read(config.clientCertPath),
        serverFingerprint256: config.floorServerFingerprint256,
        floorPublicKey: crypto.createPublicKey(read(config.floorPublicKeyPath)),
        casSignerPublicKey: crypto.createPublicKey(signerPrivateKey),
        trustedScope: scope(config.scope), timeoutMs: config.floorTimeoutMs || 1500,
      }),
    });
    if (config.crashAfterLocalCommitOnce === true) {
      ledger.testOnlyAfterLocalCommit = () => process.exit(81);
    }
    await ledger.ready;
    const clientCert = new crypto.X509Certificate(read(config.clientCertPath));
    const server = createZk1OpaqueCatalogCasHttpsServer({
      key: read(config.serverKeyPath), cert: read(config.serverCertPath),
      clientCa: read(config.caPath),
      authorizedClientFingerprint256: clientCert.fingerprint256,
      ledger, testOnlyDropCasAckOnce: config.dropAckOnce,
    });
    process.on("message", (message) => {
      if (message !== "stop") return;
      server.close(() => {
        ledger.db.pragma("wal_checkpoint(TRUNCATE)");
        ledger.close();
        process.send?.({ stopped: true }, () => process.exit(0));
      });
      server.closeAllConnections();
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    process.send({ port: server.address().port });
    return;
  }
  if (mode === "writer") {
    const input = JSON.parse(read(process.argv[4]).toString("utf8"));
    const client = createZk1OpaqueCatalogCasHttpsClient({
      endpoint: config.endpoint, ca: read(config.caPath),
      clientKey: read(config.clientKeyPath), clientCert: read(config.clientCertPath),
      serverFingerprint256: config.serverFingerprint256,
      authorityPublicKey: crypto.createPublicKey(read(config.authorityPublicKeyPath)),
      timeoutMs: config.timeoutMs || 3000,
    });
    try {
      await client.compareAndSwap({
        scope: scope(config.scope), expectedSequence: input.expectedSequence,
        expectedDigest: Buffer.from(input.expectedDigest, "base64url"),
        nextSequence: input.nextSequence,
        nextDigest: Buffer.from(input.nextDigest, "base64url"),
        nonce: Buffer.from(input.nonce, "base64url"),
        headBytes: Buffer.from(input.headBytes, "base64url"),
        headSignature: Buffer.from(input.headSignature, "base64url"),
        pageBodies: input.pageBodies.map((p) => Buffer.from(p, "base64url")),
      });
      process.send?.({ outcome: "COMMITTED" }, () => process.exit(0));
    } catch (error) {
      process.send?.({ outcome: error.code }, () => process.exit(0));
    }
    return;
  }
  throw new Error("INVALID_FIXTURE_MODE");
}
run().catch((error) => {
  process.send?.({ startupError: error.code || error.message }, () => process.exit(1));
});
