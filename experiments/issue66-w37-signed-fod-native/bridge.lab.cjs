"use strict";

// Deliberately test-only: a positive signed Sync v2 FOD payload reaches the
// Windows NTFS HANDLE-relative no-replace publisher. No CFAPI registration,
// original-A independently enrolled root, RootSession or product I/O authority.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { verifyAuthorizationProof } = require("../../sync-client/rootark-sync-authorization");

const powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const script = path.join(__dirname, "..", "..", "test", "support",
  "issue-66-w26-native-file-publish-lab.ps1");

function deny(code) {
  throw Object.assign(new Error(code), { code });
}

async function materializeSelectedLab({ signedOperation, fileKey,
  localTrustedDevicePolicy, selectedPath, collision = false } = {}) {
  if (process.platform !== "win32" ||
    process.env.ROOTARK_ISSUE66_W37_FOD_LAB !== "1") deny("fod_lab_disabled");
  // Selection is a laboratory input, not an independent signed inventory or
  // CURRENT-floor attestation. It must match this exact signed operation.
  if (typeof selectedPath !== "string") deny("fod_lab_not_selected");
  let normalized;
  try {
    normalized = protocol.validateFreshSignedOperation(signedOperation);
    if (normalized.operation !== "create" && normalized.operation !== "update") {
      deny("fod_lab_operation_denied");
    }
    if (protocol.safeRelativePath(selectedPath, "path") !== normalized.metadata.path) {
      deny("fod_lab_not_selected");
    }
    if (await verifyAuthorizationProof(normalized.authorization,
      normalized, localTrustedDevicePolicy) !== true) deny("fod_lab_signature_denied");
  } catch (error) {
    if (error?.code?.startsWith?.("fod_lab_")) throw error;
    deny("fod_lab_signature_denied");
  }
  let plaintext;
  try {
    plaintext = protocol.decryptPayload(normalized, fileKey);
  } catch {
    deny("fod_lab_aead_denied");
  }
  if (plaintext.length < 1 || plaintext.length > 8192) deny("fod_lab_length_denied");
  const digest = crypto.createHash("sha256").update(plaintext).digest("hex");
  // The native process must verify these very bytes again from its original
  // opened HANDLE, including an exact short EOF after a 4096-byte boundary.
  const local = process.env.LOCALAPPDATA;
  if (!local || !path.win32.isAbsolute(local)) deny("fod_lab_location_denied");
  // A unique test-owned scratch is allocated only after every signature,
  // selection and AEAD check. Uncertain outcomes are deliberately retained.
  const scratch = fs.mkdtempSync(path.join(local, "rootark-w26-native-publish-w37-"));
  const mode = collision ? "FOD_COLLISION" : "FOD_POSITIVE";
  const outcome = spawnSync(powershell, [
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-File", script, "-Scratch", scratch, "-Mode", mode,
    "-PayloadSha256", digest,
  ], { windowsHide: true, encoding: "utf8", timeout: 25000, maxBuffer: 8192,
    input: plaintext,
    env: { ...process.env, ROOTARK_ISSUE66_W26_NATIVE_PUBLISH_LAB: "1",
      ROOTARK_ISSUE66_W37_FOD_LAB: "1" } });
  if (outcome.status !== 0 || outcome.error || outcome.stderr !== "") {
    deny("fod_lab_native_denied");
  }
  const evidence = (outcome.stdout || "").trim();
  if (collision) {
    if (evidence !== "ROOTARK_W26_HANDLE_PUBLISH mode=FOD_COLLISION result=DENIED foreign=INTACT stage=INTACT collisionNtstatus=0xC0000035") {
      deny("fod_lab_native_unverified");
    }
    return { mode, scratch, status: "collision_preserved", authorizesIo: false };
  }
  const expected = "ROOTARK_W26_HANDLE_PUBLISH mode=FOD_POSITIVE result=ORIGINAL_HANDLE inode=PINNED no_replace=YES" +
    ` bytes=${plaintext.length} sha256=${digest} cfapi=NOT_REGISTERED authority=LAB_ONLY_NO_GO`;
  if (evidence !== expected) deny("fod_lab_native_unverified");
  return { mode, scratch, status: "native_bytes_published",
    length: plaintext.length, sha256: digest, authorizesIo: false,
    cfapiRegistered: false, independentRootCustody: false };
}

module.exports = { materializeSelectedLab };
