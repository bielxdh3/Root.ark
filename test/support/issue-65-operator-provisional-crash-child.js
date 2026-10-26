"use strict";

// Disposable child process: actually validates the Ed25519 READY + PG proof,
// performs external operator SQLite WAL FULL provisional CAS, and terminates
// abruptly before replying to its witness caller. ONLY synthetic test data.
const fs = require("node:fs");
const crypto = require("node:crypto");
const { createExternalRecoveryHeadFixture } =
  require("./issue-65-external-recovery-head-fixture");

const revive = (_, value) => value && typeof value === "object"
  && value.type === "Buffer" && Array.isArray(value.data)
  ? Buffer.from(value.data) : value;

(async () => {
  const data = JSON.parse(fs.readFileSync(process.argv[2], "utf8"), revive);
  const operator = createExternalRecoveryHeadFixture(data.operatorPath, data.previous, {
    witnessPublicKey: crypto.createPublicKey(data.witnessPublicKeyPem),
    physicalAttestorPublicKey: crypto.createPublicKey(data.pgPublicKeyPem),
    policyProvider: () => data.ownerPolicy,
  });
  try {
    if (await operator.authority.finalizeAck(data.previous, data.next, data.proof) !== true)
      throw Error("TEST_CHILD_OPERATOR_CAS_NOT_COMMITTED");
    if (operator.authority.loadProvisionalHead().lastHash !== data.next.lastHash)
      throw Error("TEST_CHILD_OPERATOR_FULL_READBACK_FAILED");
    // Deliberately no operator.close()/RPC response: hard child process exit.
    process.exit(73);
  } catch (error) {
    process.stderr.write(`${error?.stack || error}\n`);
    process.exit(42);
  }
})();
