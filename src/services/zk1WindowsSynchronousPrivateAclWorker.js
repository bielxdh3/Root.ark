"use strict";

// The private worker thread runs the existing pinned Windows PowerShell native
// verifier. Its C# is compiled ONCE, but it inspects owner/DACL/ancestors
// afresh on every message, including after a previous denial.
const { parentPort } = require("node:worker_threads");
const { createWindowsLocalWebDavAclVerifier } =
  require("../../services/chunkUploadWindowsAcl");

if (!parentPort) throw new Error("CAS_ACL_WORKER_ONLY");
const native = createWindowsLocalWebDavAclVerifier();
let stopped = false;
parentPort.on("message", async (request) => {
  if (request?.action === "stop") {
    stopped = true;
    native.stop();
    parentPort.close();
    return;
  }
  const slot = request?.signal instanceof SharedArrayBuffer
    && request.signal.byteLength === Int32Array.BYTES_PER_ELEMENT
    ? new Int32Array(request.signal) : null;
  if (!slot) return;
  let approved = false;
  try {
    if (!stopped && typeof request.path === "string"
      && ["private-directory", "authority-file"].includes(request.kind)) {
      if (request.kind === "authority-file") await native.verifyAuthorityFile(request.path);
      else await native.verifyPrivateDirectory(request.path);
      approved = true;
    }
  } catch (_) { /* Native failure always DENIES. */ }
  Atomics.store(slot, 0, approved ? 1 : 2);
  Atomics.notify(slot, 0, 1);
});
parentPort.on("close", () => native.stop());
