"use strict";

const { execFile } = require("node:child_process");

// Run the existing pinned native Windows owner/ACL checker outside the HTTP
// event loop. Synchronous PowerShell Add-Type in a provider GET can otherwise
// stall unrelated requests. No PATH executable or caller-supplied script runs.
const ACL_SUBPROCESS = String.raw`
"use strict";
try {
  const acl = require(process.argv[3]);
  const action = process.argv[1];
  const directory = process.argv[2];
  if (action === "create") acl.ensureWindowsChunkUploadRoot(directory);
  else if (action !== "verify") throw Error("Unknown private cloud ACL action");
  acl.verifyWindowsChunkUploadTree(directory);
} catch (_) { process.exitCode = 1; }
`;

const ACL_MODULE = require.resolve("../../services/chunkUploadWindowsAcl");
const MAX_INFLIGHT = 4;
let inflight = 0;

function checkWindowsPrivateCloudDirectory(directory, action) {
  if (process.platform !== "win32") return Promise.resolve();
  if (typeof directory !== "string" || (action !== "create" && action !== "verify")
    || inflight >= MAX_INFLIGHT) {
    return Promise.reject(new Error("Unverifiable private cloud directory"));
  }
  inflight++;
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ["-e", ACL_SUBPROCESS, action, directory, ACL_MODULE], {
      windowsHide: true, timeout: 26000, maxBuffer: 4096, encoding: "utf8",
    }, (error, stdout, stderr) => {
      if (error || stdout || stderr) reject(new Error("Unverifiable private cloud directory"));
      else resolve();
    });
  }).finally(() => { inflight--; });
}

module.exports = { checkWindowsPrivateCloudDirectory };
