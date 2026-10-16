const path = require("node:path");

const quotaModule = require(path.join(__dirname, "..", "..", "services", "chunkUploadQuota.js"));
const createChunkUploadQuota = quotaModule.createChunkUploadQuota;
const deadOwnerPids = new Set((process.env.ROOTARK_TEST_DEAD_QUOTA_OWNER_PIDS || "")
  .split(",")
  .filter((value) => value !== "")
  .map(Number)
  .filter(Number.isSafeInteger));

function isKnownDeadTestOwner(pid) {
  if (pid === process.pid || !deadOwnerPids.has(pid)) return false;
  try {
    process.kill(pid, 0);
    return false;
  } catch (error) {
    return error.code === "ESRCH";
  }
}

if (process.env.NODE_ENV === "test") {
  quotaModule.createChunkUploadQuota = (options) => createChunkUploadQuota({
    ...options,
    classifyOwner: (pid, identity, current) => isKnownDeadTestOwner(pid)
      ? "dead"
      : (options.classifyOwner || quotaModule.classifyProcessOwner)(pid, identity, current),
  });
}
