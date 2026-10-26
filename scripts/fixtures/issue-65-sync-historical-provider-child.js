"use strict";

// Disposable REAL TLS 1.3 mTLS witness service for the client transport test.
// Key material lives only in the child and temporary OpenSSL fixture directory.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const z = require("../../src/crypto/rootark-zk-1");
const { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer } =
  require("../../src/services/zk1WitnessHttpsServer");
const { envelopeBinding } =
  require("../../sync-client/rootark-sync-zk1-physical-binding");
const { signCommittedPhysicalReadback } =
  require("../../src/crypto/rootark-zk-pg-physical-attestation-v1");

const random = crypto.randomBytes;
const hash = (data) => crypto.createHash("sha256").update(data).digest("base64url");
const sign = (privateKey, domain, unsigned) =>
  crypto.sign(null, Buffer.concat([Buffer.from(domain),
    Buffer.from(JSON.stringify(unsigned))]), privateKey).toString("base64url");
const witness = crypto.generateKeyPairSync("ed25519");
const physical = crypto.generateKeyPairSync("ed25519");
const witnessKeyId = random(16), statusKeyId = random(16);
const fixedHead = { sequence: 5, lastHash: random(32).toString("hex"),
  physicalFenceDigest: random(32).toString("hex") };
const folder = process.argv[2];
const read = (name) => fs.readFileSync(path.join(folder, name));
const fingerprint = new crypto.X509Certificate(read("historical.pem")).fingerprint256;
const allowedScope = { account_id: Buffer.from(process.argv[3], "base64url"),
  compartment_id: Buffer.from("private"), keyring_id: Buffer.from(process.argv[4], "base64url") };
const scopeWire = Object.fromEntries(Object.entries(allowedScope)
  .map(([key, value]) => [key, value.toString("base64url")]));
let requests = 0;
const floor = {
  requiresPhysicalAttestation: true, supportsClientHistoricalNonce: true,
  async issueSyncHistoricalAdmission(input) {
    requests += 1;
    const bound = envelopeBinding(input.envelope, input.scope,
      input.expectedSequence, input.expectedRoot);
    const unsignedFloor = {
      type: "rootark-zk1-witness-cas-physical-floor/v2",
      witnessKeyId: witnessKeyId.toString("base64url"),
      statusKeyId: statusKeyId.toString("base64url"), ...fixedHead,
      nonce: input.nonce.toString("base64url"),
    };
    const freshFloor = { ...unsignedFloor, signature: sign(witness.privateKey,
      "Root.ark/zk-1/witness-cas-physical-floor/v2\0", unsignedFloor) };
    const unsignedAdmission = {
      type: "rootark-sync-v2-historical-witness-admission/v1",
      envelopeSha256: hash(bound.canonicalEnvelope),
      operationId: bound.operation.operation_id.toString("base64url"),
      deviceId: bound.envelope.deviceId,
      deviceSpkiSha256: hash(Buffer.from(bound.envelope.authorization.publicKey, "base64url")),
      epoch: bound.operation.epoch,
      checkpointSequence: bound.operation.expected_sequence,
      checkpointRoot: bound.operation.expected_root.toString("base64url"),
      inventoryReceiptSha256: hash(input.inventoryReceipt),
      admittedAtMs: Date.now(), witnessSequence: fixedHead.sequence,
      witnessLastHash: fixedHead.lastHash,
      witnessPhysicalFenceDigest: fixedHead.physicalFenceDigest,
    };
    const operation = bound.operation;
    const physicalAttestation = await signCommittedPhysicalReadback({
      scope: input.scope, operation, nonce: input.nonce,
      readback: {
        status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
        walFlushConfirmed: true, authorizesIo: false, provesIndependentOperator: false,
        generation: 4, admissionId: random(16), operationId: operation.operation_id,
        revision: operation.revision, epoch: operation.epoch,
        expectedInventorySequence: operation.expected_sequence,
        expectedInventoryRoot: operation.expected_root,
        ciphertextSha256: operation.ciphertext_sha256,
        digest: random(32), root: random(32), chunkCount: 1,
      }, issuedAt: Math.floor(Date.now() / 1000),
    }, physical.privateKey);
    process.send?.({ kind: "observed", nonce: input.nonce.toString("base64url"),
      sequence: input.expectedSequence, root: input.expectedRoot.toString("base64url"),
      receipt: hash(input.inventoryReceipt), envelope: hash(bound.canonicalEnvelope),
      scope: scopeWire, requests });
    return { freshFloor, admission: { ...unsignedAdmission,
      signature: sign(witness.privateKey,
        "Root.ark/sync-v2/historical-witness-admission/v1\0", unsignedAdmission) },
    physicalAttestation };
  },
};
const unused = async () => { throw Error("WRONG_WITNESS_ROLE"); };
const ledger = { reserve: unused, freshHead: unused, resolve: unused,
  prepareQuiesce: unused, cancelExpiredQuiesce: unused,
  beginIoAdmission: unused, finishIoAdmission: unused };
const server = createZk1WitnessHttpsServer({
  key: read("server.key"), cert: read("server.pem"), clientCa: read("ca.pem"),
  ledger, casAnchorFloor: floor,
  principals: { [fingerprint]: {
    roles: ["cas-historical-admit"], scopes: [scopeWire],
  } },
});
server.listen(0, "127.0.0.1", () => process.send?.({
  kind: "ready", port: server.address().port,
  witnessPublicKey: witness.publicKey.export({ format: "pem", type: "spki" }),
  physicalPublicKey: physical.publicKey.export({ format: "pem", type: "spki" }),
  witnessKeyId: witnessKeyId.toString("base64url"),
  statusKeyId: statusKeyId.toString("base64url"),
  minimum: fixedHead,
}));
process.on("message", async (message) => {
  if (message === "stop") {
    await drainZk1WitnessHttpsServer(server);
    process.exit(0);
  }
});
