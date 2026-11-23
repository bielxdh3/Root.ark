"use strict";

// Separate, fail-closed hosted Windows diagnostic for issue #65 / PR #276.
// Never emit ACLs, SIDs, usernames, user paths, environment variables, keys,
// filesystem objects, error.message or raw PowerShell output.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const PREFIX = "ROOTARK_ISSUE65_ACL_PROBE";
const STAGES = Object.freeze(["fixture_acl", "snapshot_root_acl", "snapshot_copy"]);
const ERROR_CODES = new Set([
  "PRIVATE_SNAPSHOT_DIRECTORY_INVALID",
  "UNTRUSTED_AUTHORITY_TEST_ROOT",
  "FILE_HANDLE_CHANGED",
  "FILE_HANDLE_CLOSE_UNCERTAIN",
  "EACCES", "EPERM", "ENOENT", "EBUSY", "ETIMEDOUT", "EIO",
]);

function safeCode(error) {
  return ERROR_CODES.has(error?.code) ? error.code : "OTHER";
}

async function runDiagnostic(steps, emit) {
  let failed = false;
  for (const stage of STAGES) {
    try {
      if (typeof steps?.[stage] !== "function") throw new Error("Missing diagnostic stage");
      await steps[stage]();
      emit(`${PREFIX} stage=${stage} result=PASS`);
    } catch (error) {
      emit(`${PREFIX} stage=${stage} result=FAIL code=${safeCode(error)}`);
      failed = true;
      break;
    }
  }
  // Preserve fault evidence even when a fixture or snapshot stage fails;
  // still attempt to remove the isolated fixture safely before returning.
  try {
    if (typeof steps?.cleanup !== "function") throw new Error("Missing cleanup stage");
    await steps.cleanup();
    emit(`${PREFIX} stage=cleanup result=PASS`);
  } catch (error) {
    emit(`${PREFIX} stage=cleanup result=FAIL code=${safeCode(error)}`);
    failed = true;
  }
  return !failed;
}

// Native PowerShell inside fileReadHandle may emit raw ACL errors to the
// process-level stderr before JavaScript catches and sanitizes an exception.
// Isolate that entire execution behind stdio pipes: only a fixed grammar of
// stage/result/code lines may cross from the child into hosted job logs.
function runIsolatedDiagnostic(runChild = spawnSync, emit = (line) => process.stdout.write(`${line}\n`)) {
  let child;
  try {
    child = runChild(process.execPath, [__filename, "--isolated-child"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 120_000,
      maxBuffer: 64 * 1024,
      windowsHide: true,
    });
  } catch {
    emit(`${PREFIX} stage=isolated_process result=FAIL code=OTHER`);
    return false;
  }
  const failure = `${PREFIX} stage=isolated_process result=FAIL code=OTHER`;
  if (child?.error || typeof child?.stdout !== "string" || typeof child?.stderr !== "string"
    || !Number.isInteger(child?.status) || child.signal) {
    emit(failure);
    return false;
  }
  const lines = child.stdout.trim().split(/\r?\n/);
  const validLine = new RegExp(`^${PREFIX} stage=(?:fixture_acl|snapshot_root_acl|snapshot_copy|cleanup|preflight) result=(?:PASS|FAIL)(?: code=(?:${[...ERROR_CODES, "OTHER"].join("|")}))?$`);
  if (!lines.length || !lines.every((line) => validLine.test(line))) {
    emit(failure);
    return false;
  }
  const succeeded = child.status === 0 &&
    lines.length === 4 && STAGES.concat("cleanup").every((stage, index) =>
      lines[index] === `${PREFIX} stage=${stage} result=PASS`);
  const hasFailure = lines.some((line) => line.includes(" result=FAIL"));
  if ((!succeeded && (!hasFailure || child.status === 0)) || (succeeded && child.stderr.length > 0)) {
    emit(failure);
    return false;
  }
  for (const line of lines) emit(line);
  return succeeded;
}

async function runWindowsProbe() {
  if (process.platform !== "win32") {
    throw Object.assign(new Error("Windows-only ACL diagnostic"), { code: "UNTRUSTED_AUTHORITY_TEST_ROOT" });
  }
  const local = process.env.LOCALAPPDATA;
  if (typeof local !== "string" || !path.isAbsolute(local) || /^\\\\/.test(local)) {
    throw Object.assign(new Error("Missing trusted Windows LOCALAPPDATA"), { code: "UNTRUSTED_AUTHORITY_TEST_ROOT" });
  }
  const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
  const {
    ensurePrivateShareSnapshotDirectory, snapshotReadHandle, cleanupReadHandle,
  } = require("../services/fileReadHandle");

  const base = path.resolve(local);
  const folder = path.join(base, `rootark-issue65-acl-probe-${crypto.randomBytes(12).toString("hex")}`);
  const fixtureName = path.basename(folder);
  if (!/^rootark-issue65-acl-probe-[a-f0-9]{24}$/.test(fixtureName)
    || path.relative(base, folder) !== fixtureName) {
    throw Object.assign(new Error("Invalid disposable fixture root"), { code: "UNTRUSTED_AUTHORITY_TEST_ROOT" });
  }
  const file = path.join(folder, "probe-opaque.bin");
  const sentinel = crypto.randomBytes(37);
  return runDiagnostic({
    fixture_acl() {
      // This reproduces createPrivateAuthorityFixture's Windows ACL primitive
      // before invoking any snapshot code. A failure here cannot be blamed
      // on ensurePrivateShareSnapshotDirectory or a descriptor leak.
      ensureWindowsChunkUploadRoot(folder);
      fs.writeFileSync(file, sentinel, { flag: "wx", mode: 0o600 });
    },
    snapshot_root_acl() {
      // Probe the SAME default ancestor and leaf policy used in production;
      // do not create a weaker temporary override for the sake of a PASS.
      ensurePrivateShareSnapshotDirectory();
    },
    async snapshot_copy() {
      const snapshot = await snapshotReadHandle(file);
      try {
        const received = Buffer.alloc(sentinel.length);
        const bytes = fs.readSync(snapshot.fd, received, 0, received.length, 0);
        if (bytes !== sentinel.length || !crypto.timingSafeEqual(received, sentinel)) {
          throw Object.assign(new Error("Snapshot bytes changed"), { code: "FILE_HANDLE_CHANGED" });
        }
      } finally {
        if (!cleanupReadHandle(snapshot)) {
          throw Object.assign(new Error("Snapshot cleanup was not proven"), { code: "FILE_HANDLE_CLOSE_UNCERTAIN" });
        }
      }
    },
    cleanup() {
      fs.rmSync(folder, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    },
  }, (line) => process.stdout.write(`${line}\n`));
}

if (require.main === module) {
  if (process.argv[2] === "--isolated-child") {
    runWindowsProbe().then((ok) => {
      if (!ok) process.exitCode = 1;
    }, (error) => {
      process.stdout.write(`${PREFIX} stage=preflight result=FAIL code=${safeCode(error)}\n`);
      process.exitCode = 1;
    });
  } else if (!runIsolatedDiagnostic()) {
    process.exitCode = 1;
  }
}

module.exports = { runDiagnostic, runIsolatedDiagnostic };
