"use strict";

// Isolated protocol fixture: readback is SYNTHETIC. Real PG validation runs
// in the disposable PG18 lab; never describe this as a physical disk test.
const fs = require("node:fs");
const crypto = require("node:crypto");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../../src/services/zk1SharedPgPhysicalCiphertextVerifier");
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
const server = createZk1PgPhysicalAttestorHttpsServer({
  key: fs.readFileSync(config.serverKeyPath), cert: fs.readFileSync(config.serverCertPath),
  clientCa: fs.readFileSync(config.caPath),
  signerPrivateKey: crypto.createPrivateKey(fs.readFileSync(config.signerKeyPath)),
  verifier: new ProtocolFixtureVerifier(),
  principals: { [config.allowedFingerprint]: [scope] },
});
server.listen(0, "127.0.0.1", () => process.send?.({ port: server.address().port }));
process.on("SIGTERM", () => server.close(() => process.exit(0)));
