"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const { pipeline } = require("node:stream/promises");
const { Readable } = require("node:stream");

const pendingPrivateShareSnapshotCleanup = new Map();
// Windows worktree/TEMP ancestors may grant other users delete rights. Keep
// transient snapshots under the protected per-user profile unless explicitly
// configured to another directory whose full ancestor chain passes validation.
const PRIVATE_SHARE_SNAPSHOT_OVERRIDE = process.env.ROOTARK_PRIVATE_SHARE_SNAPSHOT_DIRECTORY || null;
const PRIVATE_SHARE_SNAPSHOT_DIRECTORY = path.resolve(PRIVATE_SHARE_SNAPSHOT_OVERRIDE
  || (process.platform === "win32" && process.env.LOCALAPPDATA
    ? path.join(process.env.LOCALAPPDATA, "Rootark", "share-snapshots")
    : "./temp/share-snapshots"));
const PRIVATE_SHARE_SNAPSHOT_PROCESS_INSTANCE = crypto.randomUUID();
const WINDOWS_SYSTEM_SID = "S-1-5-18";
const WINDOWS_ADMINISTRATORS_SID = "S-1-5-32-544";
const WINDOWS_CREATOR_OWNER_SID = "S-1-3-0";
const WINDOWS_OWNER_RIGHTS_SID = "S-1-3-4";
const WINDOWS_FULL_CONTROL = 0x1f01ff;
const WINDOWS_DIRECTORY_WRITE_RIGHTS = 0x0002 | 0x0004 | 0x0010 | 0x0040
  | 0x0100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

function isPathWithin(parentPath, childPath) {
  const relative = path.relative(path.resolve(parentPath), path.resolve(childPath));
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative));
}

function collectTrustedSnapshotAncestors() {
  if (process.platform === "win32" && !PRIVATE_SHARE_SNAPSHOT_OVERRIDE && process.env.LOCALAPPDATA) {
    if (process.env.USERPROFILE && isPathWithin(process.env.USERPROFILE, process.env.LOCALAPPDATA)) {
      const ancestors = [];
      let current = path.resolve(process.env.LOCALAPPDATA);
      while (isPathWithin(process.env.USERPROFILE, current)) {
        ancestors.push(path.resolve(current));
        if (path.resolve(current) === path.resolve(process.env.USERPROFILE)) break;
        current = path.dirname(current);
      }
      return ancestors;
    }
    return [path.resolve(process.env.LOCALAPPDATA)];
  }
  if (process.platform === "win32" && PRIVATE_SHARE_SNAPSHOT_OVERRIDE && process.env.LOCALAPPDATA
    && process.env.USERPROFILE && isPathWithin(process.env.USERPROFILE, PRIVATE_SHARE_SNAPSHOT_DIRECTORY)) {
    const ancestors = [];
    let current = path.dirname(path.dirname(PRIVATE_SHARE_SNAPSHOT_DIRECTORY));
    while (isPathWithin(process.env.USERPROFILE, current)) {
      ancestors.push(path.resolve(current));
      if (path.resolve(current) === path.resolve(process.env.USERPROFILE)) break;
      current = path.dirname(current);
    }
    return ancestors;
  }
  const ancestors = [];
  let current = path.dirname(path.dirname(PRIVATE_SHARE_SNAPSHOT_DIRECTORY));
  while (current && !ancestors.some((item) => path.resolve(item) === path.resolve(current))) {
    ancestors.push(path.resolve(current));
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return ancestors;
}

const PRIVATE_SHARE_SNAPSHOT_TRUSTED_ANCESTORS = collectTrustedSnapshotAncestors();

function runPowerShell(script) {
  const executable = process.env.SystemRoot
    ? path.join(process.env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    : "powershell.exe";
  return execFileSync(executable, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], {
    encoding: "utf8", windowsHide: true, timeout: 5_000,
  }).trim().replace(/^\uFEFF/, "");
}

function windowsDirectoryAcl(directoryPath) {
  const encodedPath = Buffer.from(directoryPath, "utf16le").toString("base64");
  const script = [
    "$ErrorActionPreference = 'Stop'",
    `$target = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('${encodedPath}'))`,
    "$acl = Get-Acl -LiteralPath $target",
    "$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value",
    "$rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object { [pscustomobject]@{ sid = $_.IdentityReference.Value; type = $_.AccessControlType.ToString(); rights = [int]$_.FileSystemRights } })",
    "[pscustomobject]@{ owner = $owner; current = $current; protected = $acl.AreAccessRulesProtected; rules = $rules } | ConvertTo-Json -Depth 4 -Compress",
  ].join("; ");
  const output = runPowerShell(script);
  const result = JSON.parse(output);
  result.rules = Array.isArray(result.rules) ? result.rules : result.rules ? [result.rules] : [];
  return result;
}

function secureNewWindowsSnapshotDirectory(directoryPath) {
  const encodedPath = Buffer.from(directoryPath, "utf16le").toString("base64");
  const script = [
    "$ErrorActionPreference = 'Stop'",
    `$target = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('${encodedPath}'))`,
    "$acl = Get-Acl -LiteralPath $target",
    "$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User",
    "$acl.SetAccessRuleProtection($true, $false)",
    "foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }",
    "$acl.SetOwner($current)",
    "$inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit",
    "$principals = @($current, [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))",
    "foreach ($principal in $principals) { $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($principal, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow); [void]$acl.AddAccessRule($rule) }",
    "Set-Acl -LiteralPath $target -AclObject $acl",
  ].join("; ");
  runPowerShell(script);
}

function validateDirectorySecurity(directoryPath, privateDirectory) {
  const stat = fs.lstatSync(directoryPath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw fileReadError("PRIVATE_SNAPSHOT_DIRECTORY_INVALID", "Private snapshot path must be a real directory");
  }

  if (process.platform === "win32") {
    const acl = windowsDirectoryAcl(directoryPath);
    const trustedOwners = new Set([acl.current, WINDOWS_SYSTEM_SID, WINDOWS_ADMINISTRATORS_SID]);
    if (!acl.current || (privateDirectory ? acl.owner !== acl.current : !trustedOwners.has(acl.owner))) {
      throw fileReadError("PRIVATE_SNAPSHOT_DIRECTORY_INVALID", "Private snapshot directory owner does not match the service account");
    }
    const trusted = new Set([acl.current, WINDOWS_SYSTEM_SID, WINDOWS_ADMINISTRATORS_SID,
      WINDOWS_CREATOR_OWNER_SID, WINDOWS_OWNER_RIGHTS_SID]);
    let currentRights = 0;
    let currentDeniedRights = 0;
    for (const rule of acl.rules) {
      const rights = Number(rule.rights) || 0;
      if (rule.sid === acl.current && rule.type === "Allow") currentRights |= rights;
      if (rule.sid === acl.current && rule.type === "Deny") currentDeniedRights |= rights;
      if (rule.type === "Allow" && (privateDirectory
        ? !trusted.has(rule.sid)
        : !trusted.has(rule.sid) && (rights & WINDOWS_DIRECTORY_WRITE_RIGHTS) !== 0)) {
        throw fileReadError("PRIVATE_SNAPSHOT_DIRECTORY_INVALID", "Private snapshot directory ACL grants unsafe access");
      }
    }
    if (privateDirectory && ((currentRights & WINDOWS_FULL_CONTROL) !== WINDOWS_FULL_CONTROL
      || (currentDeniedRights & (WINDOWS_FULL_CONTROL | 0x10000000 | 0x40000000)) !== 0)) {
      throw fileReadError("PRIVATE_SNAPSHOT_DIRECTORY_INVALID", "Private snapshot directory ACL is not restricted to its owner");
    }
    if (!privateDirectory && ((currentRights & WINDOWS_DIRECTORY_WRITE_RIGHTS) !== WINDOWS_DIRECTORY_WRITE_RIGHTS
      || (currentDeniedRights & WINDOWS_DIRECTORY_WRITE_RIGHTS) !== 0)) {
      throw fileReadError("PRIVATE_SNAPSHOT_DIRECTORY_INVALID", "Snapshot parent is not writable by its owner");
    }
    return stat;
  }

  const currentUid = typeof process.getuid === "function" ? process.getuid() : null;
  const mode = stat.mode & 0o7777;
  const trustedRootParent = !privateDirectory && stat.uid === 0;
  if (currentUid === null || (stat.uid !== currentUid && !trustedRootParent)) {
    throw fileReadError("PRIVATE_SNAPSHOT_DIRECTORY_INVALID", "Private snapshot directory owner does not match the service account");
  }
  if (privateDirectory ? (mode & 0o077) !== 0
    : ((mode & 0o022) !== 0 && (mode & 0o1000) === 0)) {
    throw fileReadError("PRIVATE_SNAPSHOT_DIRECTORY_INVALID", "Private snapshot directory permissions are too broad");
  }
  return stat;
}

function ensurePrivateShareSnapshotDirectory(directoryPath = PRIVATE_SHARE_SNAPSHOT_DIRECTORY) {
  const snapshotDirectory = path.resolve(directoryPath);
  if (snapshotDirectory === PRIVATE_SHARE_SNAPSHOT_DIRECTORY) {
    for (const ancestor of PRIVATE_SHARE_SNAPSHOT_TRUSTED_ANCESTORS) {
      validateDirectorySecurity(ancestor, false);
    }
  }
  const parentPath = path.dirname(snapshotDirectory);
  let parentCreated = false;
  try { fs.lstatSync(parentPath); }
  catch (error) {
    if (error.code !== "ENOENT") throw error;
    fs.mkdirSync(parentPath, { mode: 0o700 });
    parentCreated = true;
  }
  if (parentCreated) {
    if (process.platform === "win32") secureNewWindowsSnapshotDirectory(parentPath);
    else fs.chmodSync(parentPath, 0o700);
  }
  validateDirectorySecurity(parentPath, false);

  let directoryCreated = false;
  try { fs.lstatSync(snapshotDirectory); }
  catch (error) {
    if (error.code !== "ENOENT") throw error;
    fs.mkdirSync(snapshotDirectory, { mode: 0o700 });
    directoryCreated = true;
  }
  if (directoryCreated) {
    if (process.platform === "win32") secureNewWindowsSnapshotDirectory(snapshotDirectory);
    else fs.chmodSync(snapshotDirectory, 0o700);
  }
  validateDirectorySecurity(snapshotDirectory, true);
  return snapshotDirectory;
}

function getPrivateShareSnapshotDirectory() {
  return PRIVATE_SHARE_SNAPSHOT_DIRECTORY;
}

function getPrivateShareSnapshotProcessInstance() {
  return PRIVATE_SHARE_SNAPSHOT_PROCESS_INSTANCE;
}

function fileReadError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function invalidInternalFile(message) {
  return fileReadError("INVALID_INTERNAL_FILE", message);
}

function sameSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode
    && left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function openReadHandle(filePath) {
  let descriptor;
  try {
    let flags = fs.constants.O_RDONLY;
    if (typeof fs.constants.O_NOFOLLOW === "number") flags |= fs.constants.O_NOFOLLOW;
    if (typeof fs.constants.O_NONBLOCK === "number") flags |= fs.constants.O_NONBLOCK;
    descriptor = fs.openSync(filePath, flags);
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const currentPath = fs.lstatSync(filePath, { bigint: true });
    const afterPathCheck = fs.fstatSync(descriptor, { bigint: true });
    const stableSnapshot = (stat) => stat.dev === opened.dev && stat.ino === opened.ino
      && stat.mode === opened.mode && stat.size === opened.size
      && stat.mtimeNs === opened.mtimeNs && stat.ctimeNs === opened.ctimeNs;
    if (!opened.isFile() || opened.nlink !== 1n || !currentPath.isFile() || currentPath.isSymbolicLink()
      || !stableSnapshot(currentPath) || !stableSnapshot(afterPathCheck)) {
      throw fileReadError("FILE_HANDLE_CHANGED", "File changed while it was being opened");
    }

    const stats = fs.fstatSync(descriptor);
    const result = { fd: descriptor, fdOwned: true,
      fdIdentity: { dev: opened.dev, ino: opened.ino, mode: opened.mode,
        size: opened.size, nlink: opened.nlink, mtimeNs: opened.mtimeNs, ctimeNs: opened.ctimeNs },
      stats, snapshot: opened };
    descriptor = undefined;
    return result;
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    throw error;
  }
}

function validatePrivateSnapshotDirectory(directoryPath) {
  const productionDirectory = path.resolve(directoryPath) === PRIVATE_SHARE_SNAPSHOT_DIRECTORY;
  validateDirectorySecurity(path.dirname(directoryPath), false);
  validateDirectorySecurity(directoryPath, productionDirectory);
  if (productionDirectory) {
    for (const ancestor of PRIVATE_SHARE_SNAPSHOT_TRUSTED_ANCESTORS) {
      validateDirectorySecurity(ancestor, false);
    }
  }
}

function sameFileIdentity(stat, identity) {
  return Boolean(identity && stat.dev === identity.dev && stat.ino === identity.ino);
}

function snapshotBaseName(cleanupPath) {
  return path.basename(cleanupPath).replace(/(?:\.cleanup-[0-9a-f-]{36})?\.tmp$/i, "");
}

function makeQuarantinePath(cleanupPath) {
  return path.join(path.dirname(cleanupPath),
    `${snapshotBaseName(cleanupPath)}.cleanup-${crypto.randomUUID()}.tmp`);
}

function findQuarantinedSnapshot(cleanupPath, cleanupIdentity) {
  const directory = path.dirname(cleanupPath);
  const prefix = `${snapshotBaseName(cleanupPath)}.cleanup-`;
  let entries;
  try { entries = fs.readdirSync(directory); }
  catch (error) { return { path: null, found: error.code !== "ENOENT" }; }
  let found = false;
  for (const name of entries) {
    if (!name.startsWith(prefix) || !name.endsWith(".tmp")) continue;
    found = true;
    const candidate = path.join(directory, name);
    try {
      const stat = fs.lstatSync(candidate, { bigint: true });
      if (stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1n
        && sameFileIdentity(stat, cleanupIdentity)) return { path: candidate, found: true };
    } catch {}
  }
  return { path: null, found };
}

function removePrivateShareSnapshot(cleanupPath, cleanupIdentity, quarantinePath = null) {
  if (!cleanupPath) return { complete: true, quarantinePath: null };
  if (!cleanupIdentity) return { complete: false, quarantinePath };
  const directory = path.dirname(cleanupPath);
  try {
    fs.lstatSync(path.dirname(directory));
    fs.lstatSync(directory);
  }
  catch (error) {
    return { complete: error.code === "ENOENT", quarantinePath: null };
  }
  try { validatePrivateSnapshotDirectory(directory); }
  catch { return { complete: false, quarantinePath }; }

  const quarantineCandidates = findQuarantinedSnapshot(cleanupPath, cleanupIdentity);
  const candidates = [...new Set([quarantinePath, cleanupPath, quarantineCandidates.path].filter(Boolean))];
  let sourcePath = null;
  let foundCandidate = quarantineCandidates.found;
  for (const candidate of candidates) {
    try {
      const stat = fs.lstatSync(candidate, { bigint: true });
      foundCandidate = true;
      if (stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1n
        && sameFileIdentity(stat, cleanupIdentity)) {
        sourcePath = candidate;
        break;
      }
    } catch (error) {
      if (error.code !== "ENOENT") foundCandidate = true;
    }
  }
  if (!sourcePath) return { complete: !foundCandidate, quarantinePath };

  // Move the candidate to a fresh random name in the same private directory.
  // The rename is atomic on the same volume; checking the moved inode closes
  // the lstat→unlink race on both POSIX and Windows, where unlink-by-handle is
  // not exposed by Node's portable fs API.
  const targetPath = makeQuarantinePath(cleanupPath);
  try { fs.renameSync(sourcePath, targetPath); }
  catch (error) {
    if (error.code === "ENOENT") {
      const recovered = findQuarantinedSnapshot(cleanupPath, cleanupIdentity);
      if (recovered.path) return { complete: false, quarantinePath: recovered.path };
      let originalExists = false;
      try { fs.lstatSync(cleanupPath); originalExists = true; } catch (statError) {
        if (statError.code !== "ENOENT") originalExists = true;
      }
      return { complete: !originalExists && !recovered.found, quarantinePath: null };
    }
    return { complete: false, quarantinePath: sourcePath === cleanupPath ? null : sourcePath };
  }

  let moved;
  try { moved = fs.lstatSync(targetPath, { bigint: true }); }
  catch (error) {
    return { complete: error.code === "ENOENT", quarantinePath: targetPath };
  }
  if (!moved.isFile() || moved.isSymbolicLink() || moved.nlink !== 1n
    || !sameFileIdentity(moved, cleanupIdentity)) {
    // Never delete a replacement moved into quarantine. Restore it to the
    // source name when that name is still free; otherwise keep the quarantine
    // entry for an operator/retry to reconcile.
    try {
      fs.lstatSync(sourcePath);
    } catch (error) {
      if (error.code === "ENOENT") {
        try {
          fs.renameSync(targetPath, sourcePath);
          return { complete: false, quarantinePath: sourcePath === cleanupPath ? null : sourcePath };
        } catch {}
      }
    }
    return { complete: false, quarantinePath: targetPath };
  }

  try {
    fs.unlinkSync(targetPath);
    return { complete: true, quarantinePath: null };
  } catch {
    return { complete: false, quarantinePath: targetPath };
  }
}

function descriptorIdentityResult(fd) {
  try {
    const stat = fs.fstatSync(fd, { bigint: true });
    if (!stat.isFile()) return { identity: null, retryable: false };
    return { identity: { dev: stat.dev, ino: stat.ino }, retryable: true };
  } catch (error) {
    return { identity: null, retryable: ["EIO", "EINTR", "EAGAIN", "EBUSY"].includes(error.code) };
  }
}

function inspectDescriptor(fd, expectedIdentity) {
  try {
    const current = fs.fstatSync(fd, { bigint: true });
    return sameFileIdentity(current, expectedIdentity) ? "same" : "different";
  } catch (error) {
    if (error.code === "EBADF") return "closed";
    return "unknown";
  }
}

function closeOwnedDescriptor(readHandle, allowIdentityRetry = false) {
  const expected = readHandle.fdIdentity || readHandle.cleanupIdentity;
  if (!expected || expected.dev === undefined || expected.ino === undefined) return false;
  // Verify the numeric descriptor before EVERY close attempt. A prior owner
  // may already have closed it and the OS may have reused the number; only
  // EBADF or a dev/ino mismatch proves that this is no longer our descriptor.
  const beforeClose = inspectDescriptor(readHandle.fd, expected);
  if (beforeClose === "closed" || beforeClose === "different") return true;
  if (beforeClose !== "same") return false;
  try {
    fs.closeSync(readHandle.fd);
    return true;
  } catch (error) {
    if (error.code === "EBADF") return true;
    if (!allowIdentityRetry) return false;

    // dev/ino are the descriptor identity. Size, mode, link count and times
    // legitimately change while a partial snapshot is written and must never
    // be interpreted as proof that this numeric fd was reused.
    const state = inspectDescriptor(readHandle.fd, expected);
    if (state === "closed" || state === "different") return true;
    if (state !== "same") return false;

    // The private directory prevents another principal from opening this
    // random snapshot path. A same-inode fstat therefore permits one bounded
    // retry; a different inode or EBADF above is never closed again.
    try {
      fs.closeSync(readHandle.fd);
      return true;
    } catch (retryError) {
      if (retryError.code === "EBADF") return true;
      const retryState = inspectDescriptor(readHandle.fd, expected);
      return retryState === "closed" || retryState === "different";
    }
  }
}

function pendingCleanupKey(readHandle) {
  return readHandle.cleanupPath || `fd:${process.pid}:${crypto.randomUUID()}`;
}

function cleanupReadHandle(readHandle) {
  if (!readHandle) return true;
  const pathPending = readHandle.cleanupPath
    ? pendingPrivateShareSnapshotCleanup.get(readHandle.cleanupPath) : null;
  const candidateIdentity = readHandle.cleanupIdentity || readHandle.fdIdentity || null;
  const candidateMatches = (pending) => Boolean(pending?.identity && candidateIdentity
    && pending.identity.dev !== undefined && pending.identity.ino !== undefined
    && candidateIdentity.dev !== undefined && candidateIdentity.ino !== undefined
    && sameFileIdentity(pending.identity, candidateIdentity));
  let existingPending = candidateMatches(pathPending) ? pathPending : null;
  // Several original inodes may have occupied the same pathname. Pending
  // reservations are not interchangeable: locate only a proven identity,
  // including entries held under a distinct collision-safe map key.
  if (!existingPending && readHandle.cleanupPath && candidateIdentity) {
    for (const pending of pendingPrivateShareSnapshotCleanup.values()) {
      if (pending.cleanupPath === readHandle.cleanupPath && candidateMatches(pending)) {
        existingPending = pending;
        break;
      }
    }
  }
  // Identical inode identity does not transfer descriptor ownership. If this
  // cleanup still owns an fd (or must verify a stream-transferred fd), it must
  // complete that close independently; a prior pending record cannot silently
  // absorb the descriptor and leak a native handle.
  if (existingPending && Number.isInteger(readHandle.fd)
    && (readHandle.fdOwned !== false || readHandle.fdTransferredToStream === true)) {
    existingPending = null;
  }
  // The request/stream slot ends with this cleanup call. The byte reservation
  // remains attached to the pending entry until the owned inode is removed.
  const releaseActive = (release) => {
    if (typeof release === "function" && typeof release.releaseActive === "function") {
      try { release.releaseActive(); } catch {}
    }
  };
  if (existingPending) {
    releaseActive(existingPending.release);
    // This request's concurrency slot ends even when its byte reservation
    // cannot be attached to the older pending inode. Keep those bytes reserved
    // until their own identity is proven, but never strand an active slot.
    releaseActive(readHandle.cleanupCallback);
  } else releaseActive(readHandle.cleanupCallback);
  if (existingPending) {
    if (typeof readHandle.cleanupCallback === "function") {
      // Two distinct quotas may protect the same proven inode. Both stay
      // reserved until its cleanup succeeds; neither may be lost or released
      // merely because another callback was already registered.
      const priorRelease = existingPending.release;
      const newRelease = readHandle.cleanupCallback;
      if (!priorRelease) existingPending.release = newRelease;
      else if (priorRelease !== newRelease) {
        let released = false;
        existingPending.release = () => {
          if (released) return;
          released = true;
          try { priorRelease(); } finally { newRelease(); }
        };
      }
      readHandle.cleanupCallback = null;
    }
    retryPendingPrivateShareSnapshotCleanup();
    return !pendingPrivateShareSnapshotCleanup.has(existingPending.key);
  }
  const hasDescriptor = Number.isInteger(readHandle.fd);
  let identity = readHandle.cleanupIdentity || readHandle.fdIdentity || null;
  let fdClosed = true;
  let fdNeedsRetry = false;
  let identityRecoveryAllowed = readHandle.fdTransferredToStream !== true;

  if (readHandle.fdOwned !== false && hasDescriptor) {
    if (!identity) {
      // Recover only from the descriptor that this function still owns. Never
      // infer an unknown inode from the current pathname.
      const recovered = descriptorIdentityResult(readHandle.fd);
      identity = recovered.identity;
      identityRecoveryAllowed = recovered.retryable;
      if (identity) {
        readHandle.fdIdentity = identity;
        if (readHandle.cleanupPath) readHandle.cleanupIdentity = identity;
      }
    }
    if (!identity) {
      fdClosed = false;
      fdNeedsRetry = true;
    } else {
      fdClosed = closeOwnedDescriptor(readHandle, readHandle.allowIdentityRetry === true);
      fdNeedsRetry = !fdClosed;
    }
  } else if (readHandle.fdTransferredToStream === true && readHandle.cleanupPath && hasDescriptor) {
    // Called from the stream's close event. Confirm the transferred numeric
    // fd is closed/reused before considering the snapshot eligible for unlink.
    const state = identity ? inspectDescriptor(readHandle.fd, identity) : "unknown";
    if (state === "closed" || state === "different") fdClosed = true;
    else if (state === "same") {
      fdClosed = closeOwnedDescriptor(readHandle, true);
      fdNeedsRetry = !fdClosed;
    } else {
      fdClosed = false;
      // After ownership has transferred to ReadStream, an unknown identity
      // cannot be recovered from the numeric fd: Node may already have closed
      // and the process may have reused that number.
      fdNeedsRetry = true;
    }
  }

  readHandle.fdOwned = false;
  let quarantinePath = readHandle.quarantinePath || null;
  let pathCleanupComplete = !readHandle.cleanupPath;
  if (readHandle.cleanupPath && fdClosed && identity) {
    const cleanup = removePrivateShareSnapshot(readHandle.cleanupPath, identity, quarantinePath);
    pathCleanupComplete = cleanup.complete;
    quarantinePath = cleanup.quarantinePath;
  }

  const cleanupComplete = fdClosed && pathCleanupComplete;
  const existing = existingPending;
  if (cleanupComplete) {
    if (existing) pendingPrivateShareSnapshotCleanup.delete(readHandle.cleanupPath);
    const release = readHandle.cleanupCallback || existing?.release || null;
    readHandle.cleanupCallback = null;
    if (typeof release === "function") {
      try { release(); } catch {}
    }
  } else {
    // Never overwrite a prior unproven inode reservation just because two
    // different snapshots temporarily used the same pathname.
    const key = readHandle.cleanupPath && !pathPending
      ? readHandle.cleanupPath : pendingCleanupKey({});
    pendingPrivateShareSnapshotCleanup.set(key, {
      key,
      cleanupPath: readHandle.cleanupPath || existing?.cleanupPath || null,
      quarantinePath,
      identity,
      fd: hasDescriptor ? readHandle.fd : existing?.fd,
      fdOwned: fdNeedsRetry || (existing?.fdOwned === true && !fdClosed),
      identityRecoveryAllowed: identityRecoveryAllowed && existing?.identityRecoveryAllowed !== false,
      allowIdentityRetry: readHandle.allowIdentityRetry === true || existing?.allowIdentityRetry === true,
      release: existing?.release || readHandle.cleanupCallback || null,
      state: !identity ? "identity-unproven" : fdNeedsRetry ? "descriptor-close-pending" : "path-cleanup-pending",
      createdAt: existing?.createdAt || Date.now(),
      attempts: existing?.attempts || 0,
    });
    readHandle.cleanupCallback = null;
  }
  return cleanupComplete;
}

function retryPendingPrivateShareSnapshotCleanup() {
  let removed = 0;
  for (const [pendingKey, pending] of pendingPrivateShareSnapshotCleanup) {
    if (!pending.identity && pending.fdOwned && pending.identityRecoveryAllowed !== false
      && Number.isInteger(pending.fd)) {
      // This fd has not been closed yet: fstat can recover its identity while
      // it remains owned. An EBADF/other failure is not permission to trust a
      // pathname or release the reservation.
      const recovered = descriptorIdentityResult(pending.fd);
      pending.identity = recovered.identity;
      pending.identityRecoveryAllowed = recovered.retryable;
      if (!pending.identity) {
        pending.state = "identity-unproven";
        pending.attempts++;
        continue;
      }
    }
    if (pending.fdOwned) {
      if (!pending.identity) continue;
      if (!pending.allowIdentityRetry) {
        const state = inspectDescriptor(pending.fd, pending.identity);
        if (state !== "closed" && state !== "different") {
          pending.state = "descriptor-close-pending";
          pending.attempts++;
          continue;
        }
      } else if (!closeOwnedDescriptor({ fd: pending.fd, fdIdentity: pending.identity }, true)) {
        pending.state = "descriptor-close-pending";
        pending.attempts++;
        continue;
      }
      pending.fdOwned = false;
    }
    if (pending.cleanupPath && !pending.identity) {
      pending.state = "identity-unproven";
      pending.attempts++;
      continue;
    }
    const cleanup = removePrivateShareSnapshot(
      pending.cleanupPath, pending.identity, pending.quarantinePath,
    );
    if (!cleanup.complete) {
      pending.quarantinePath = cleanup.quarantinePath;
      pending.state = "path-cleanup-pending";
      pending.attempts++;
      continue;
    }
    pendingPrivateShareSnapshotCleanup.delete(pendingKey);
    if (typeof pending.release === "function") {
      try { pending.release(); } catch {}
    }
    removed++;
  }
  return removed;
}

function getPrivateShareSnapshotCleanupState() {
  const state = { pending: pendingPrivateShareSnapshotCleanup.size,
    identityUnproven: 0, identityRetryPending: 0, identityUnrecoverable: 0,
    descriptorClosePending: 0, pathCleanupPending: 0 };
  for (const pending of pendingPrivateShareSnapshotCleanup.values()) {
    if (pending.state === "identity-unproven") {
      state.identityUnproven++;
      if (pending.identityRecoveryAllowed === false || !Number.isInteger(pending.fd)) {
        state.identityUnrecoverable++;
      } else {
        state.identityRetryPending++;
      }
    }
    else if (pending.state === "descriptor-close-pending") state.descriptorClosePending++;
    else if (pending.state === "path-cleanup-pending") state.pathCleanupPending++;
  }
  return Object.freeze(state);
}

function isProcessAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code !== "ESRCH" && error.code !== "EINVAL";
  }
}

function cleanupOrphanPrivateShareSnapshots(directory = PRIVATE_SHARE_SNAPSHOT_DIRECTORY, now = Date.now()) {
  let removed = 0;
  let entries;
  try {
    validatePrivateSnapshotDirectory(directory);
    entries = fs.readdirSync(directory, { withFileTypes: true });
  }
  catch { return removed; }
  for (const entry of entries) {
    const match = /^rootark-share-egress-(\d+)-([0-9a-f-]{36})(?:-([0-9a-f-]{36}))?(?:\.cleanup-[0-9a-f-]{36})?\.tmp$/i.exec(entry.name);
    if (!match || !entry.isFile()) continue;
    const pid = Number(match[1]);
    const processInstance = match[3] ? match[2] : null;
    const fullPath = path.join(directory, entry.name);
    if (pendingPrivateShareSnapshotCleanup.has(fullPath)
      || [...pendingPrivateShareSnapshotCleanup.values()].some((pending) =>
        pending.cleanupPath === fullPath || pending.quarantinePath === fullPath)) continue;
    if (pid === process.pid) {
      if (processInstance === PRIVATE_SHARE_SNAPSHOT_PROCESS_INSTANCE) continue;
      // A same-PID legacy filename has no instance proof and cannot have been
      // created by this version, which always writes the instance component.
    } else if (isProcessAlive(pid)) {
      continue;
    }
    try {
      const stat = fs.lstatSync(fullPath, { bigint: true });
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) continue;
      const cleanup = removePrivateShareSnapshot(fullPath, { dev: stat.dev, ino: stat.ino });
      if (cleanup.complete) removed++;
    } catch {}
  }
  void now;
  return removed;
}

async function snapshotReadHandle(filePath, authorizedHandle = openReadHandle(filePath), options = {}) {
  const original = authorizedHandle;
  let snapshotDescriptor;
  let snapshotPath;
  let snapshotIdentity;
  let snapshotFdIdentity;
  try {
    const before = fs.fstatSync(original.fd, { bigint: true });
    if (!original.snapshot || before.nlink !== 1n || !sameSnapshot(original.snapshot, before)) {
      throw fileReadError("FILE_HANDLE_CHANGED", "File changed after its authorized descriptor was opened");
    }
    if (!Number.isSafeInteger(original.stats.size) || original.stats.size < 0
      || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw fileReadError("FILE_HANDLE_CHANGED", "File size cannot be snapshotted safely");
    }
    snapshotPath = path.join(ensurePrivateShareSnapshotDirectory(),
      `rootark-share-egress-${process.pid}-${PRIVATE_SHARE_SNAPSHOT_PROCESS_INSTANCE}-${crypto.randomUUID()}.tmp`);
    let flags = fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL;
    if (typeof fs.constants.O_NOFOLLOW === "number") flags |= fs.constants.O_NOFOLLOW;
    snapshotDescriptor = fs.openSync(snapshotPath, flags, 0o600);
    const created = fs.fstatSync(snapshotDescriptor, { bigint: true });
    const createdPath = fs.lstatSync(snapshotPath, { bigint: true });
    if (!created.isFile() || created.nlink !== 1n || !createdPath.isFile()
      || createdPath.isSymbolicLink() || createdPath.nlink !== 1n
      || !sameFileIdentity(createdPath, { dev: created.dev, ino: created.ino })) {
      throw fileReadError("FILE_HANDLE_CHANGED", "Private share snapshot is not a unique regular file");
    }
    snapshotIdentity = { dev: created.dev, ino: created.ino };
    snapshotFdIdentity = { dev: created.dev, ino: created.ino };

    const destination = fs.createWriteStream(null, { fd: snapshotDescriptor, autoClose: false, start: 0 });
    const source = before.size === 0n
      ? Readable.from([])
      : fs.createReadStream(null, { fd: original.fd, autoClose: true,
        start: 0, end: Number(before.size - 1n) });
    // The source ReadStream now owns the original descriptor and closes it
    // exactly once on completion, abort or error. Never manually close the
    // same numeric fd after handing it to a stream.
    if (before.size > 0n) original.fdOwned = false;
    if (options.signal) await pipeline(source, destination, { signal: options.signal });
    else await pipeline(source, destination);

    const afterPath = fs.lstatSync(filePath, { bigint: true });
    const snapshotAfter = fs.fstatSync(snapshotDescriptor, { bigint: true });
    // The source ReadStream auto-closed the original fd after pipeline. The
    // path identity/stat fence is sufficient here: it catches in-place writes
    // (ctime/mtime/size) and replacement (dev/ino) without touching a closed fd.
    if (!afterPath.isFile() || afterPath.isSymbolicLink()
      || !sameSnapshot(before, afterPath) || !snapshotAfter.isFile()
      || snapshotAfter.size !== before.size || snapshotAfter.nlink !== 1n) {
      throw fileReadError("FILE_HANDLE_CHANGED", "File changed while snapshotting share bytes");
    }

    fs.fsyncSync(snapshotDescriptor);
    if (original.fdOwned !== false && !closeOwnedDescriptor(original)) {
      // The fd may still be open, or may have been reused after an ambiguous
      // close error. Do not retry its number from the catch path.
      original.fdOwned = false;
      throw fileReadError("FILE_HANDLE_CLOSE_UNCERTAIN", "Authorized descriptor close could not be verified");
    }
    original.fdOwned = false;
    const result = {
      fd: snapshotDescriptor,
      fdOwned: true,
      allowIdentityRetry: true,
      fdIdentity: { dev: snapshotAfter.dev, ino: snapshotAfter.ino },
      stats: original.stats,
      cleanupPath: snapshotPath,
      cleanupIdentity: { dev: snapshotAfter.dev, ino: snapshotAfter.ino },
      cleanupCallback: original.cleanupCallback || null,
    };
    original.cleanupCallback = null;
    snapshotDescriptor = undefined;
    return result;
  } catch (error) {
    const snapshotCleanupCallback = original.cleanupCallback || null;
    const snapshotOwnsReservation = Boolean(snapshotPath && snapshotDescriptor !== undefined);
    if (snapshotOwnsReservation) original.cleanupCallback = null;
    if (original.fdOwned !== false) {
      cleanupReadHandle({ fd: original.fd, fdOwned: true,
        fdIdentity: original.fdIdentity,
        cleanupCallback: snapshotOwnsReservation ? null : snapshotCleanupCallback });
      original.fdOwned = false;
    }
    let snapshotCleanupComplete = true;
    if (snapshotPath && snapshotDescriptor !== undefined && snapshotIdentity) {
      snapshotCleanupComplete = cleanupReadHandle({
        fd: snapshotDescriptor,
        fdOwned: true,
        allowIdentityRetry: true,
        fdIdentity: snapshotFdIdentity,
        cleanupPath: snapshotPath,
        cleanupIdentity: snapshotIdentity,
        cleanupCallback: snapshotCleanupCallback,
      });
      original.cleanupCallback = null;
    } else if (snapshotPath && snapshotDescriptor !== undefined) {
      snapshotCleanupComplete = cleanupReadHandle({
        fd: snapshotDescriptor,
        fdOwned: true,
        allowIdentityRetry: true,
        fdIdentity: snapshotFdIdentity,
        cleanupPath: snapshotPath,
        cleanupIdentity: null,
        cleanupCallback: snapshotCleanupCallback,
      });
      original.cleanupCallback = null;
    } else {
      cleanupReadHandle(original);
    }
    error.snapshotCleanupComplete = snapshotCleanupComplete;
    throw error;
  }
}

function readBoundedRegularFile(filePath, maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes === Number.MAX_SAFE_INTEGER) {
    throw new TypeError("maxBytes must be a non-negative safe integer below Number.MAX_SAFE_INTEGER");
  }

  let descriptor;
  try {
    let flags = fs.constants.O_RDONLY;
    if (typeof fs.constants.O_NOFOLLOW === "number") flags |= fs.constants.O_NOFOLLOW;
    if (typeof fs.constants.O_NONBLOCK === "number") flags |= fs.constants.O_NONBLOCK;
    descriptor = fs.openSync(filePath, flags);

    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || opened.isSymbolicLink() || opened.size > BigInt(maxBytes)) {
      throw invalidInternalFile("Internal file must be a bounded regular file");
    }
    const openedPath = fs.lstatSync(filePath, { bigint: true });
    if (!openedPath.isFile() || openedPath.isSymbolicLink() || !sameSnapshot(opened, openedPath)) {
      throw invalidInternalFile("Internal file changed while opening");
    }

    const chunks = [];
    const buffer = Buffer.alloc(Math.min(64 * 1024, maxBytes + 1));
    let total = 0;
    while (total <= maxBytes) {
      const count = fs.readSync(descriptor, buffer, 0, Math.min(buffer.length, maxBytes + 1 - total), total);
      if (count === 0) break;
      total += count;
      if (total > maxBytes) throw invalidInternalFile("Internal file exceeds its size limit");
      chunks.push(Buffer.from(buffer.subarray(0, count)));
    }

    const stat = fs.fstatSync(descriptor, { bigint: true });
    const afterRead = fs.fstatSync(descriptor, { bigint: true });
    const afterReadPath = fs.lstatSync(filePath, { bigint: true });
    if (!afterRead.isFile() || afterRead.size > BigInt(maxBytes)
      || !afterReadPath.isFile() || afterReadPath.isSymbolicLink()
      || !sameSnapshot(opened, afterRead) || !sameSnapshot(afterRead, afterReadPath)) {
      throw invalidInternalFile("Internal file changed while reading");
    }

    return { contents: Buffer.concat(chunks, total), stat };
  } catch (error) {
    if (error.code === "ELOOP" || error.code === "EMLINK") {
      throw invalidInternalFile("Internal file cannot be a symbolic link");
    }
    throw error;
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

module.exports = {
  cleanupOrphanPrivateShareSnapshots,
  cleanupReadHandle,
  getPrivateShareSnapshotCleanupState,
  ensurePrivateShareSnapshotDirectory,
  getPrivateShareSnapshotDirectory,
  getPrivateShareSnapshotProcessInstance,
  openReadHandle,
  readBoundedRegularFile,
  retryPendingPrivateShareSnapshotCleanup,
  snapshotReadHandle,
};
