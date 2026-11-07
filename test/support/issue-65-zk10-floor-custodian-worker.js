"use strict";

// Disposable worker-thread race harness. The Ed25519 key never reaches disk.
const { isMainThread, parentPort, workerData } = require("node:worker_threads");
const { createDevOffZk10MonotonicFloorCustodian } =
  require("../../src/services/zk10DevOffMonotonicFloorCustodian");

// node --test may discover support files. A normal module import never signs.
if (!isMainThread) {
  let custodian;
  try {
    custodian = createDevOffZk10MonotonicFloorCustodian(workerData.config);
    const result = custodian.attest(workerData.request, workerData.ownerLease);
    parentPort.postMessage({ signed: Boolean(result.floor.signature) });
  } catch (error) {
    parentPort.postMessage({ signed: false, code: error.code || "ZK10_CUSTODIAN_UNAVAILABLE" });
  } finally {
    try { custodian?.close(); } catch (_) { /* test-only */ }
  }
}

// Separate-OS-process race fixture. Ephemeral disposable Ed25519 fixture keys
// are delivered over test-only IPC and never written to a file or logged.
if (isMainThread && process.env.ROOTARK_ZK10_CUSTODIAN_PROCESS_FIXTURE === "1"
  && typeof process.send === "function") {
  const crypto = require("node:crypto");
  let custodian, request, ownerLease;
  process.on("message", (message) => {
    if (message.kind === "init") {
      try {
        const ownerPublicKey = crypto.createPublicKey({
          key: Buffer.from(message.ownerSpki, "base64url"), format: "der", type: "spki",
        });
        const custodianPrivateKey = crypto.createPrivateKey({
          key: Buffer.from(message.custodianPkcs8, "base64url"), format: "der", type: "pkcs8",
        });
        custodian = createDevOffZk10MonotonicFloorCustodian({
          ...message.config, bootstrap: undefined, ownerPublicKey, custodianPrivateKey,
        });
        request = message.request;
        ownerLease = message.ownerLease;
        process.send({ ready: true });
      } catch (_) {
        process.send({ ready: false });
        process.disconnect();
      }
    } else if (message.kind === "sign") {
      let signed = false;
      try { signed = Boolean(custodian.attest(request, ownerLease).floor.signature); }
      catch (_) { /* an expected loser must fail closed */ }
      finally {
        try { custodian?.close(); } catch (_) { /* disposable fixture only */ }
        process.send({ signed }, () => process.disconnect());
      }
    }
  });
}
