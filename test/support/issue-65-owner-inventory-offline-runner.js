"use strict";

const { spawn } = require("node:child_process");
const path = require("node:path");

function runOfflineSigner(input) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      path.resolve(__dirname, "../../scripts/issue-65-owner-inventory-offline-signer.js"),
      "--issue65-owner-inventory-stdin-v1",
    ], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    let stdout = "";
    let stderr = "";
    const deadline = setTimeout(() => child.kill("SIGKILL"), 15000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; if (stdout.length > 32768) child.kill(); });
    child.stderr.on("data", (chunk) => { stderr += chunk; if (stderr.length > 4096) child.kill(); });
    child.on("error", reject);
    child.on("exit", (code) => {
      clearTimeout(deadline);
      if (code !== 0) reject(new Error("OFFLINE_OWNER_SIGNER_FAILED"));
      else {
        try { resolve(JSON.parse(stdout)); } catch (_) { reject(new Error("OFFLINE_OWNER_SIGNER_FAILED")); }
      }
    });
    child.stdin.end(JSON.stringify(input));
  });
}
module.exports = { runOfflineSigner };
