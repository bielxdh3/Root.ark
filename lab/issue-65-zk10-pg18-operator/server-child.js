"use strict";
// Test-only process: credentials are read from an ACL-restricted disposable file.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { createZk10Pg18Operator, createZk10Pg18OperatorHttpsServer } =
  require("./operator");

let phase = "bootstrap";
async function main() {
  if (process.argv.length !== 3 || !path.isAbsolute(process.argv[2])
    || !process.send) throw Error("ZK10_TEST_CHILD_INVOCATION");
  const config = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const pool = new Pool({ connectionString: config.pgUrl, max: 3,
    connectionTimeoutMillis: 4000 });
  const read = (name) => fs.readFileSync(path.join(config.certDir, name));
  const operator = createZk10Pg18Operator({
    pool, operatorId: config.operatorId, immutableAccountId: config.accountId,
    canonicalZkAccountId: config.zkAccountId, identityDigest: config.identityDigest,
    initialPhysicalDigest: config.physicalDigest,
    operatorPrivateKey: crypto.createPrivateKey(config.operatorPrivatePem),
    operatorPublicKey: crypto.createPublicKey(config.operatorPublicPem),
    ownerPublicKey: crypto.createPublicKey(config.ownerPublicPem),
  });
  phase = "initialize";
  await operator.initialize();
  phase = "listen";
  const server = createZk10Pg18OperatorHttpsServer({
    operator, tls: { key: read("authority.key"), cert: read("authority.pem"),
      ca: read("ca.pem") }, clientFingerprint256: config.clientFingerprint256,
    dropCasAckOnce: config.dropCasAckOnce === true,
  });
  server.on("error", (error) => {
    if (process.send) process.send({ type: "fatal",
      code: error?.code === "EADDRINUSE" ? "ZK10_LISTEN_PORT_BUSY" : "ZK10_LISTEN_ERROR" });
    process.exitCode = 1;
  });
  server.listen(config.port || 0, "127.0.0.1", () => {
    process.send({ type: "ready", port: server.address().port });
  });
  process.on("message", (m) => {
    if (m?.type === "stop") {
      server.closeAllConnections();
      server.close(() => pool.end().finally(() => process.exit(0)));
    }
  });
}
main().catch((error) => {
  const reason = error?.message === "ZK10_DEV_OPERATOR_REJECTED" ? "VALIDATION"
    : ["ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "57P03", "42P01",
      "23505", "28P01", "3D000"].includes(error?.code) ? error.code : "OTHER";
  if (process.send) process.send({ type: "fatal", code:
    "ZK10_OPERATOR_" + phase.toUpperCase() + "_" + reason });
  process.exitCode = 1;
});
