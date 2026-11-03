"use strict";

// Disposable IPC-only adversarial test: use a separate Node process and SQLite
// handle to race the signed inventory's capacity boundary.
const crypto = require("node:crypto");
const { Zk1DurableContentInventoryLedger } =
  require("../../src/services/zk1DurableContentInventoryLedger");

process.once("message", async (request) => {
  let ledger;
  let result;
  try {
    ledger = await Zk1DurableContentInventoryLedger.open(request.filename, {
      bootstrapNew: false,
      signerKeyId: request.signerKeyId,
      signerPrivateKey: crypto.createPrivateKey(request.privateKeyPem),
      scope: request.scope,
    });
    await ledger.append(request.operation);
    result = { status: "accepted" };
  } catch (error) {
    result = { status: "rejected", code: error.code };
  } finally {
    ledger?.close();
  }
  process.send(result, () => { process.disconnect(); });
});
