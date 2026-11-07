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
