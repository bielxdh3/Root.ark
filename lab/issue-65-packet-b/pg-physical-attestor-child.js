"use strict";

// Spawned laboratory child, kept outside test/ so Node's auto-discovery does
// not execute its argv-dependent process bootstrap as an independent test.
// Isolated protocol fixture by default. The explicitly opted-in PG18 lab mode
// uses only a separate read-only connection string passed to this child.
const fs = require("node:fs");
const crypto = require("node:crypto");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../../src/services/zk1SharedPgPhysicalCiphertextVerifier");
const { Pool } = require("pg");
const { createZk1PgPhysicalAttestorHttpsServer } =
  require("../../src/services/zk1PgPhysicalAttestorHttpsServer");

const config = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const decode = (source) => Object.fromEntries(Object.entries(source).map(([k, v]) =>
  [k, typeof v === "string" ? Buffer.from(v, "base64url") : v]));
const scope = decode(config.scope);
const operation = decode(config.operation);
const digest = Buffer.from(config.digest, "base64url");
const root = Buffer.from(config.root, "base64url");
class ProtocolFixtureVerifier extends Zk1SharedPgPhysicalCiphertextVerifier {
  constructor() { super({ pool: { connect() { throw new Error("synthetic protocol only"); } } }); }
  async verifyCommittedInventoryOperation(request) {
    if (config.readbackDelayMs) await new Promise((resolve) =>
      setTimeout(resolve, config.readbackDelayMs));
    for (const k of Object.keys(scope)) if (!Buffer.from(request.scope[k]).equals(scope[k])) throw Error("scope");
    for (const k of Object.keys(operation)) {
      if (Buffer.isBuffer(operation[k]) ? !Buffer.from(request.operation[k]).equals(operation[k])
        : request.operation[k] !== operation[k]) throw Error("operation");
    }
    return { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation: 3, admissionId: crypto.randomBytes(16),
      operationId: operation.operation_id, revision: operation.revision, epoch: operation.epoch,
      expectedInventorySequence: operation.expected_sequence,
      expectedInventoryRoot: operation.expected_root, digest, root,
      chunkCount: config.chunks, ciphertextSha256: operation.ciphertext_sha256,
      authorizesIo: false, provesIndependentOperator: false };
  }
}
if (config.useRealPg !== undefined && config.useRealPg !== true) {
  throw new Error("invalid real PG fixture mode");
}
if (config.useRealPg === true && !process.env.ROOTARK_ZK1_ATTESTOR_PG_URL) {
  throw new Error("missing isolated attestor PG connection");
}
const pool = config.useRealPg === true ? new Pool({
  connectionString: process.env.ROOTARK_ZK1_ATTESTOR_PG_URL,
  max: 2, connectionTimeoutMillis: 2500,
}) : null;
const server = createZk1PgPhysicalAttestorHttpsServer({
  key: fs.readFileSync(config.serverKeyPath), cert: fs.readFileSync(config.serverCertPath),
  clientCa: fs.readFileSync(config.caPath),
  signerPrivateKey: crypto.createPrivateKey(fs.readFileSync(config.signerKeyPath)),
  verifier: pool ? new Zk1SharedPgPhysicalCiphertextVerifier({ pool })
    : new ProtocolFixtureVerifier(),
  principals: { [config.allowedFingerprint]: [scope],
    ...(config.additionalFingerprint ? { [config.additionalFingerprint]: [scope] } : {}) },
});
server.listen(0, "127.0.0.1", () => process.send?.({ port: server.address().port }));
process.on("SIGTERM", () => server.close(async () => {
  await pool?.end();
  process.exit(0);
}));
