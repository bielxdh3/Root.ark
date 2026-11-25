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
  "ACL_READ_ANCESTOR", "ACL_READ_PARENT", "ACL_READ_LEAF",
  "ACL_SEAL_SCRIPT_ANCESTOR", "ACL_SEAL_SCRIPT_PARENT", "ACL_SEAL_SCRIPT_LEAF",
  ...["ANCESTOR", "PARENT", "LEAF"].flatMap((role) =>
    ["GET_ACL", "OWNER", "RULES", "JSON"].map((step) => `ACL_READ_${role}_${step}`)),
  ...["ANCESTOR", "PARENT", "LEAF"].flatMap((role) =>
    ["CURRENT_USER", "OWNER_READ"].map((step) => "ACL_READ_" + role + "_" + step)),
  ...["ANCESTOR"].flatMap((role) => [2, 3, 4].flatMap((depth) =>
    ["GET_ACL", "CURRENT_USER", "OWNER_READ", "RULES", "JSON"].flatMap((step) =>
      ["ACCESS_DENIED", "SECURITY_EXCEPTION", "PATH_NOT_FOUND", "NOT_FOUND", "ITEM_NOT_FOUND", "OTHER"]
        .map((failure) => "ACL_READ_" + role + "_D" + depth + "_" + step + "_" + failure)))),
  ...["PARENT", "LEAF"].flatMap((role) =>
    ["GET_ACL", "CURRENT_USER", "OWNER_READ", "RULES", "JSON"].flatMap((step) =>
      ["ACCESS_DENIED", "SECURITY_EXCEPTION", "PATH_NOT_FOUND", "NOT_FOUND", "ITEM_NOT_FOUND", "OTHER"]
        .map((failure) => "ACL_READ_" + role + "_" + step + "_" + failure))),
  "EACCES", "EPERM", "ENOENT", "EBUSY", "ETIMEDOUT", "EIO",
]);

function safeCode(error) {
  return ERROR_CODES.has(error?.code) ? error.code : "OTHER";
}

// Decode a path only inside the isolated child for classification; NEVER put
// that path, the native stderr, SID or PowerShell script in its output. The
// target may be an ancestor, the private parent or the snapshot leaf.
function classifyNativeAclCommand(args, snapshotDirectory) {
  const command = Array.isArray(args) ? args[args.length - 1] : null;
  if (typeof command !== "string" || typeof snapshotDirectory !== "string") return "OTHER";
  // The seal SCRIPT reads the ACL and mutates it before writing. A failure
  // does not prove which individual operation failed. Never replay a write.
  const action = (command.includes("Set-Acl -LiteralPath $target")
      || command.includes("[System.IO.Directory]::SetAccessControl($target, $acl)")) ? "SEAL_SCRIPT"
    : (command.includes("Get-Acl -LiteralPath $target")
      || command.includes("[System.IO.Directory]::GetAccessControl($target)")) ? "READ" : null;
  const encoded = command.match(/FromBase64String\('([A-Za-z0-9+/=]{1,8192})'\)/)?.[1];
  if (!action || !encoded) return "OTHER";
  let candidate;
  try {
    const bytes = Buffer.from(encoded, "base64");
    if (bytes.length === 0 || bytes.length % 2 !== 0) return "OTHER";
    candidate = bytes.toString("utf16le");
  } catch { return "OTHER"; }
  if (!candidate || /[\u0000-\u001f]/.test(candidate)) return "OTHER";
  const target = path.win32.normalize(candidate).toLowerCase();
  const root = path.win32.normalize(snapshotDirectory).toLowerCase();
  const parent = path.win32.dirname(root);
  const role = target === root ? "LEAF" : target === parent ? "PARENT"
    : root.startsWith(target.replace(/[\\/]+$/, "") + "\\") ? "ANCESTOR" : null;
  return role ? `ACL_${action}_${role}` : "OTHER";
}

function classifyNativeAclAncestorDepth(args, snapshotDirectory) {
  const command = Array.isArray(args) ? args[args.length - 1] : null;
  if (typeof command !== "string" || typeof snapshotDirectory !== "string"
    || (!command.includes("Get-Acl -LiteralPath $target")
      && !command.includes("[System.IO.Directory]::GetAccessControl($target)"))) return null;
  const encoded = command.match(/FromBase64String\('([A-Za-z0-9+/=]{1,8192})'\)/)?.[1];
  if (!encoded) return null;
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length === 0 || bytes.length % 2 !== 0) return null;
  const candidate = bytes.toString("utf16le");
  if (!candidate || /[\u0000-\u001f]/.test(candidate)) return null;
  const target = path.win32.normalize(candidate).toLowerCase();
  const root = path.win32.normalize(snapshotDirectory).toLowerCase();
  if (!root.startsWith(target.replace(/[\\/]+$/, "") + "\\")) return null;
  const relative = path.win32.relative(target, root);
  if (!relative || relative === ".." || relative.startsWith("..\\")
    || path.win32.isAbsolute(relative)) return null;
  const depth = relative.split(/[\\/]+/).filter(Boolean).length;
  return [2, 3, 4].includes(depth) ? depth : null;
}

function buildReadAclFailureScript(script) {
  return "$rootarkProbeStage = 'GET_ACL'; try { " + script + " } catch { "
    + "$rootarkProbeError = 'OTHER'; $rootarkProbeException = $_.Exception; "
    + "if ($null -ne $rootarkProbeException) { "
    + "if ($rootarkProbeException -is [System.UnauthorizedAccessException] -or $rootarkProbeException.HResult -eq -2147024891) { $rootarkProbeError = 'ACCESS_DENIED' } "
    + "elseif ($rootarkProbeException -is [System.Security.SecurityException]) { $rootarkProbeError = 'SECURITY_EXCEPTION' } "
    + "elseif ($rootarkProbeException -is [System.IO.DirectoryNotFoundException] -or $rootarkProbeException.HResult -eq -2147024893) { $rootarkProbeError = 'PATH_NOT_FOUND' } "
    + "elseif ($rootarkProbeException -is [System.IO.FileNotFoundException] -or $rootarkProbeException.HResult -eq -2147024894) { $rootarkProbeError = 'NOT_FOUND' } "
    + "elseif ($rootarkProbeException -is [System.Management.Automation.ItemNotFoundException] -or $rootarkProbeException.HResult -eq -2146233087) { $rootarkProbeError = 'ITEM_NOT_FOUND' } }; "
    + "[Console]::Out.WriteLine('ROOTARK_ISSUE65_READ_SUBSTEP=' + $rootarkProbeStage + ';ERROR=' + $rootarkProbeError); exit 71 }";
}

// After a native read-script failure, replay only that already-trusted,
// read-only script with fixed stage labels. This does NOT authorize a directory
// and does not replace production validation; a changing result remains FAIL.
// Native exception, stderr, path, ACL and raw PowerShell text are never logged.
function classifyReadAclSubstep(native, binary, args, options, snapshotDirectory) {
  const code = classifyNativeAclCommand(args, snapshotDirectory);
  const ancestorDepth = code === "ACL_READ_ANCESTOR"
    ? classifyNativeAclAncestorDepth(args, snapshotDirectory) : null;
  if (!/^ACL_READ_(?:ANCESTOR|PARENT|LEAF)$/.test(code)) return code;
  const original = args[args.length - 1];
  const nativeRead = "$acl = [System.IO.Directory]::GetAccessControl($target)";
  const stages = [
    [original.includes(nativeRead) ? nativeRead : "$acl = Get-Acl -LiteralPath $target", "GET_ACL"],
    ["$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value", "CURRENT_USER"],
    ["$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value", "OWNER_READ"],
    ["$rules = @($acl.GetAccessRules(", "RULES"],
    [original.includes("isAdmin = $isAdmin")
      ? "[pscustomobject]@{ owner = $owner; current = $current; isAdmin = $isAdmin; protected = $acl.AreAccessRulesProtected; rules = $rules } | ConvertTo-Json -Depth 4 -Compress"
      : "[pscustomobject]@{ owner = $owner; current = $current; protected = $acl.AreAccessRulesProtected; rules = $rules } | ConvertTo-Json -Depth 4 -Compress", "JSON"],
  ];
  let script = original;
  for (const [needle, stage] of stages) {
    const index = script.indexOf(needle);
    if (index < 0 || script.indexOf(needle, index + needle.length) >= 0) return code;
    script = script.replace(needle, `$rootarkProbeStage = '${stage}'; ${needle}`);
  }
  script = buildReadAclFailureScript(script);
  try {
    native(binary, [...args.slice(0, -1), script], {
      ...options, stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    const output = typeof error?.stdout === "string" ? error.stdout : null;
    const matched = output?.match(/^ROOTARK_ISSUE65_READ_SUBSTEP=(GET_ACL|CURRENT_USER|OWNER_READ|RULES|JSON);ERROR=(ACCESS_DENIED|SECURITY_EXCEPTION|PATH_NOT_FOUND|NOT_FOUND|ITEM_NOT_FOUND|OTHER)\r?\n?$/);
    if (matched) {
      const suffix = matched[1] + "_" + matched[2];
      if (code === "ACL_READ_ANCESTOR" && ancestorDepth !== null) {
        return code + "_D" + ancestorDepth + "_" + suffix;
      }
      return code + "_" + suffix;
    }
    const legacy = output?.match(/^ROOTARK_ISSUE65_READ_SUBSTEP=(GET_ACL|CURRENT_USER|OWNER_READ|RULES|JSON)\r?\n?$/);
    if (legacy) return code + "_" + legacy[1];
  }
  return code;
}

function getSnapshotAclDirectory(snapshotApi) {
  if (typeof snapshotApi?.getPrivateShareSnapshotDirectory !== "function") {
    throw new TypeError("Snapshot API does not expose its effective private directory");
  }
  const directory = snapshotApi.getPrivateShareSnapshotDirectory();
  if (typeof directory !== "string" || !directory
    || (!path.isAbsolute(directory) && !path.win32.isAbsolute(directory))) {
    throw new TypeError("Snapshot API returned an invalid private directory");
  }
  return directory;
}

function loadSnapshotApiWithConfinedNativeErrors() {
  const childProcess = require("node:child_process");
  const original = childProcess.execFileSync;
  const moduleName = require.resolve("../services/fileReadHandle");
  if (require.cache[moduleName]) {
    throw new Error("Snapshot ACL diagnostic must load the original implementation in isolation");
  }
  let snapshotDirectory;
  childProcess.execFileSync = function (binary, args, options) {
    try { return original.call(this, binary, args, options); }
    catch (error) {
      const code = classifyReadAclSubstep(original.bind(this), binary, args, options, snapshotDirectory);
      if (code === "OTHER") throw error;
      // This classification is ONLY for the probe subprocess. Production
      // fileReadHandle remains untouched and still rejects unsafe ACLs.
      throw Object.assign(new Error("Private ACL native step unavailable"), { code });
    }
  };
  try {
    const snapshotApi = require(moduleName);
    // Bind classification to the exact path production will validate, including
    // ROOTARK_PRIVATE_SHARE_SNAPSHOT_DIRECTORY overrides. Never infer a second
    // default path that can disagree with the module's trusted ancestors.
    snapshotDirectory = getSnapshotAclDirectory(snapshotApi);
    return snapshotApi;
  }
  finally { childProcess.execFileSync = original; }
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
  } = loadSnapshotApiWithConfinedNativeErrors();

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

module.exports = { runDiagnostic, runIsolatedDiagnostic, classifyNativeAclCommand,
  classifyNativeAclAncestorDepth, buildReadAclFailureScript, classifyReadAclSubstep,
  getSnapshotAclDirectory };
