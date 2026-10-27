"use strict";

const { createWindowsLocalWebDavAclVerifier } = require("../../services/chunkUploadWindowsAcl");

// Compile the exact same native strict ACL checks once in a bounded, private
// PowerShell worker. Each request still checks current NTFS owner/DACL and
// ancestry, with no cached verdict, shell or PATH lookup.
const MAX_INFLIGHT = 4;
let inflight = 0;
let resident = null;
let idleStop = null;

function checkWindowsPrivateCloudDirectory(directory, action) {
  if (process.platform !== "win32") return Promise.resolve();
  if (typeof directory !== "string" || (action !== "create" && action !== "verify")
    || inflight >= MAX_INFLIGHT) {
    return Promise.reject(new Error("Unverifiable private cloud directory"));
  }
  if (idleStop) { clearTimeout(idleStop); idleStop = null; }
  if (!resident) resident = createWindowsLocalWebDavAclVerifier();
  inflight++;
  const check = action === "create" ? resident.createPrivateDirectory(directory)
    : resident.verifyPrivateDirectory(directory);
  return check.finally(() => {
    inflight--;
    if (inflight === 0) {
      idleStop = setTimeout(() => {
        if (inflight === 0 && resident) { resident.stop(); resident = null; }
        idleStop = null;
      }, 2000);
      idleStop.unref?.();
    }
  });
}

module.exports = { checkWindowsPrivateCloudDirectory };
