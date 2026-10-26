"use strict";

// One action per OS process. Parent test controls disposable fixtures and
// independently retains the last signed head; this process owns SQLite writes.
const crypto = require("node:crypto");
const { Zk1LegacyArchiveStageWitness } =
  require("../../src/services/zk1LegacyArchiveStageWitness");

process.once("message", async ({ setup, action, expectedHead, candidate,
  minimumHead, snapshot }) => {
  let witness;
  try {
    const publicKey = (raw) => crypto.createPublicKey({
      key: Buffer.from(raw, "base64url"), format: "der", type: "spki" });
    const privateKey = crypto.createPrivateKey({
      key: Buffer.from(setup.privateKey, "base64url"), format: "der", type: "pkcs8" });
    witness = new Zk1LegacyArchiveStageWitness({
      filename: setup.filename, bootstrapNew: false,
      privateKey, witnessPublicKey: publicKey(setup.publicKey),
      trustedScope: Object.fromEntries(Object.entries(setup.scope).map(
        ([name, value]) => [name, Buffer.from(value, "base64url")])),
      operatorPins: Object.fromEntries(Object.entries(setup.pins).map(
        ([name, value]) => [name, publicKey(value)])),
      trustedOwnerWitness: {
        pinnedWitness: { publicKey: publicKey(setup.ownerWitness.publicKey),
          keyId: Buffer.from(setup.ownerWitness.keyId, "base64url") },
        minimumHead: { revision: setup.ownerWitness.minimumHead.revision,
          witnessSequence: setup.ownerWitness.minimumHead.witnessSequence,
          digest: Buffer.from(setup.ownerWitness.minimumHead.digest, "base64url") },
      },
    });
    let output;
    if (action === "stage") output = await witness.stageSignedEvidence({ candidate, expectedHead });
    else if (action === "withdraw") output = witness.withdraw({ expectedHead });
    else if (action === "audit") output = witness.audit(minimumHead);
    else if (action === "snapshot") {
      await witness.db.backup(snapshot);
      output = witness.audit();
    } else throw Error("INVALID_TEST_OPERATION");
    witness.close();
    process.send({ ok: true, output }, () => process.disconnect());
  } catch (error) {
    if (witness) witness.close();
    process.send({ ok: false, code: error.code || error.message },
      () => process.disconnect());
  }
});
