"use strict";

// Issue #66: specification and fail-closed seam for a FUTURE native service.
// Intentionally unused by SyncEngine. No JS object, FileHandle, path or stat
// can be promoted to an authority by this module. Nothing loads a .node addon.
// A real implementation must enforce the whole contract inside native code,
// with an independently controlled root/ancestor and writer-isolation policy.

const ROOT_SESSION_ERROR = Object.freeze({
  FEATURE_DISABLED: "root_session_feature_disabled",
  NATIVE_UNAVAILABLE: "root_session_native_unavailable",
  UNVERIFIED_AUTHORITY: "root_session_unverified_authority",
  UNTRUSTED_ROOT: "root_session_untrusted_root",
  UNSAFE_TRAVERSAL: "root_session_unsafe_traversal",
  ROOT_IDENTITY_CHANGED: "root_session_root_identity_changed",
  CONCURRENT_WRITER: "root_session_concurrent_writer",
  NO_REPLACE_CONFLICT: "root_session_no_replace_conflict",
  DURABILITY_INDETERMINATE: "root_session_durability_indeterminate",
  ROLLBACK_INDETERMINATE: "root_session_rollback_indeterminate",
  COLD_REOPEN_UNVERIFIED: "root_session_cold_reopen_unverified",
});

// Each operation takes only opaque session-relative native handles and exact
// child names. Directory listing is bound to the SAME opened directory used
// for child reads. The native component, not JavaScript, verifies every
// ancestor, mount/reparse boundary, ownership and durability precondition.
const REQUIRED_OPERATIONS = Object.freeze([
  "openRootFromTrustedParent", // independently pinned parent, root and volume
  "openChildDirectory", // descendant of held root, no mount/reparse traversal
  "enumerateDirectory", // stream the exact directory opened by native handle
  "openContainedFile", // relative to the pinned ancestor, reject hardlinks
  "readOpenedFile", // FD/HANDLE-bound bytes, no pathname reopen
  "createExclusiveFile", // native no-replace, sealed file ownership
  "renameNoReplace", // both parents owned by the same pinned root session
  "removeEntry", // delete opened inode or require independently isolated parent
  "syncOpenedFile", // durable bytes, check write/flush errors
  "syncDirectory", // durable namespace transitions, platform-specific proof
  "reacquireRoot", // cold restart from the original trusted parent authority
  "commitDurableRecovery", // ordered flush, journal/snapshot marker fence
  "close", // release every live handle and fail closed on indeterminate state
]);

const WINDOWS_OPS = Object.freeze({
  openRootFromTrustedParent: "native HANDLE acquisition from protected parent; verify NTFS volume, ownership/DACL and all ancestors",
  openChildDirectory: "NtCreateFile RootDirectory or verified equivalent; reject reparse points and mount traversal",
  enumerateDirectory: "enumerate names through the exact opened directory HANDLE, preserving UTF-16 names",
  openContainedFile: "open from pinned parent HANDLE and verify file ID, volume, link and reparse state",
  readOpenedFile: "read from that exact HANDLE and prevent concurrent same-principal modification",
  createExclusiveFile: "create entry relative to trusted parent HANDLE with native exclusive semantics",
  renameNoReplace: "rename between pinned directory HANDLEs without overwrite or foreign cleanup",
  removeEntry: "SetFileInformationByHandle on the originally opened file HANDLE acquired relative to an independently trusted parent; never reopen mutable leaf for deletion",
  syncOpenedFile: "FlushFileBuffers on exact modified file HANDLE, verify errors",
  syncDirectory: "prove durable NTFS namespace update; do not assume Node directory fsync works",
  reacquireRoot: "cold reopen using independently trusted parent, identity and anti-rollback anchor",
  commitDurableRecovery: "native durable ordered journal/marker/snapshot commit; unknown completion stays blocked",
  close: "close HANDLEs without reporting success for an indeterminate transaction",
});

const POSIX_OPS = Object.freeze({
  openRootFromTrustedParent: "open trusted dirfd and pin root/ancestor mount identity and owner policy",
  openChildDirectory: "Linux openat2 beneath held dirfd with NO_SYMLINKS and NO_XDEV, reject mount crossing",
  enumerateDirectory: "fdopendir/readdir on the held dirfd, stream ALL entries, preserve exact names",
  openContainedFile: "openat2 on held parent; no symlink, hardlink alias or mount escape",
  readOpenedFile: "read from the opened fd; concurrent writer must be excluded or snapshot protected",
  createExclusiveFile: "openat with O_EXCL/O_NOFOLLOW under held directory fd",
  renameNoReplace: "renameat2 RENAME_NOREPLACE between held parent dirfds",
  removeEntry: "unlinkat only after independently proven same-UID hostile writer isolation for the pinned parent and its ancestors; an fstat/lstat followed by unlinkat is not atomic identity-conditional deletion",
  syncOpenedFile: "fsync/fdatasync exact opened file descriptor",
  syncDirectory: "fsync held parent dirfds after every namespace transition",
  reacquireRoot: "cold reopen from pinned trusted-parent identity and independent rollback anchor",
  commitDurableRecovery: "ordered data/dirfd syncs plus trusted checkpoint fence, fail on uncertain durability",
  close: "close retained descriptors and fail closed for unresolved transactions",
});

const GUARDS = Object.freeze({
  nativeExecutionRequired: true,
  noPathnameFallback: true,
  rejectCrossMountTraversal: true,
  requireSamePrincipalWriterIsolation: true,
  noStatThenUnlinkAsIdentityAuthority: true,
  requireTrustedParentBeforeDestructiveRemove: true,
  requireIndependentTrustedParent: true,
  requireIndependentRollbackAnchor: true,
  requiredMarkerUntilDurableCommit: true,
  noRemoteDeleteOnIndeterminateRecovery: true,
  renormalizeNamesInJavaScript: false,
});

const ROOT_SESSION_CONTRACT = Object.freeze({
  version: 1,
  requiredOperations: REQUIRED_OPERATIONS,
  platforms: Object.freeze({ win32: WINDOWS_OPS, linux: POSIX_OPS, posix: POSIX_OPS }),
  guards: GUARDS,
  genesisEnumeration: Object.freeze({
    streaming: true,
    acceptsLegitimateEntriesAtLeast: 16385,
    truncateAt16384: false,
    preserveExactNames: true,
    rejectAmbiguousAliases: true,
  }),
});

class RootSessionUnavailableError extends Error {
  constructor(code) {
    super("Issue #66 native root custody is not available; recovery must remain blocked");
    this.name = "RootSessionUnavailableError";
    this.code = code;
  }
}

// Reserved activation point. A boolean flag or a supplied object does NOT
// attest to a native OS handle. An actual native backend will have to replace
// this unconditional denial only after independent code/image and root-policy
// review. Extra arguments are ignored, never enumerated or invoked.
function openNativeRootSession(featureEnabled = false) {
  if (featureEnabled !== true) throw new RootSessionUnavailableError(ROOT_SESSION_ERROR.FEATURE_DISABLED);
  throw new RootSessionUnavailableError(ROOT_SESSION_ERROR.NATIVE_UNAVAILABLE);
}

// Deliberately not an "isNative" duck-type check. No JS-visible object is
// currently accepted as recovery authority, including a real Node FileHandle.
function requireNativeRecoveryAuthority() {
  throw new RootSessionUnavailableError(ROOT_SESSION_ERROR.UNVERIFIED_AUTHORITY);
}

module.exports = {
  ROOT_SESSION_CONTRACT,
  ROOT_SESSION_ERROR,
  openNativeRootSession,
  requireNativeRecoveryAuthority,
};
