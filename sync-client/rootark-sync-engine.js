"use strict";

const crypto = require("node:crypto");
const { AsyncLocalStorage } = require("node:async_hooks");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");

const protocol = require("./rootark-sync-protocol");
const { verifyPinnedAtomicOwnerProvision } = require("./rootark-sync-atomic-owner-provision");
const { validatePortableRelativePath } = require("./rootark-sync-paths");
const { SyncJournal, renameWithRetry } = require("./rootark-sync-journal");
const { SyncConflictError } = require("../public/client/rootark-sync-adapter");
const { openNativeRootSession } = require("./rootark-sync-native-root-session-contract");

const SNAPSHOT_VERSION = 1;
// A v2 snapshot fences old clients that do not know how to replay the
// fsynced per-object eviction overlay. Upgrade durably BEFORE first PREPARE,
// not after staging a file; old v1 binaries must reject version 2. The
// explicit required flag prevents a vanished *entire* active journal from
// looking like a successfully compacted empty journal.
const EVICTION_LEDGER_SNAPSHOT_VERSION = 2;
// v1 added portable case-folding on POSIX, but marked migration complete even
// when a dirty legacy alias was retained. Revisit v1 snapshots under v2 so
// an already-stranded alias gets a durable watch when its bytes become clean.
const EXCLUDED_PATHS_CASEFOLD_VERSION = 2;
const INTERNAL_NAMES = new Set([".rootark-trash", ".rootark-conflicts", ".rootark-sync-journal.json", ".rootark-sync-index.json", ".rootark-sync-evictions", ".rootark-sync.lock", ".rootark-webdav-owner.lock"]);
const INTERNAL_NAME_PREFIXES = [".rootark-sync-lock-init-", ".rootark-sync-evictions-archive-"];
const ROOT_MUTATION_QUEUES = new Map();
const MAX_EVICTION_ATTEMPTS = 3;
const TRANSIENT_EVICTION_CODES = new Set(["EBUSY", "EPERM", "EAGAIN"]);
const ROOT_MUTATION_CONTEXT = new AsyncLocalStorage();
// Module-private and deliberately non-overridable. A future verified native
// opener returning successfully must NEVER resume the legacy pathname replay.
function denyLegacyNativeRootReplay() {
  openNativeRootSession(true);
  fail("Legacy eviction recovery is not authorized by native custody", "root_session_native_unavailable");
}
function denyUntrustedNativeEviction() {
  // The recovery fence alone cannot make pathname-based stage/rename/unlink
  // safe. Reject both explicit and automatic Files On-Demand eviction before
  // consulting a path or changing remote-only/durable eviction state.
  // A future native opener returning does not enable this legacy JS route.
  openNativeRootSession(true);
  fail("Native rooted cache eviction is not operational", "root_session_native_unavailable");
}
function denyUntrustedNativeSignedDelete() {
  // A disappearance in a pathname scan (or an old pending signed tombstone)
  // is not independently verified authority to delete a remote object.
  // Even a future native opener cannot authorize this old JS write path.
  openNativeRootSession(true);
  fail("Native rooted signed DELETE is not operational", "root_session_native_unavailable");
}
function signedEnvelopeDigest(operation) {
  return crypto.createHash("sha256")
    .update(protocol.canonicalJson(operation), "utf8").digest("hex");
}

// v2 is intentionally incompatible with v1: a v1 receipt has no immutable
// owner-provisioned account/store namespace and MUST NOT authorize new ACKs.
const ATOMIC_ADMISSION_DOMAIN = "rootark-sync-atomic-batch-witness-v2\0";
const ATOMIC_CAS_FLOOR_DOMAIN = "rootark-sync-atomic-batch-external-cas-floor-v2\0";
const ATOMIC_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function pinnedAtomicOwnerIdentity(value) {
  if (value == null) return null;
  // Detach option-owned getters just once. An apparent immutable identity
  // must not be replaced between constructor validation and signed readback.
  let identity;
  try { identity = JSON.parse(protocol.canonicalJson(value)); }
  catch { fail("Atomic batch owner identity is not canonical JSON", "authorization_required"); }
  if (!identity || typeof identity !== "object" || Array.isArray(identity)
    || Object.keys(identity).sort().join(",")
      !== ["accountId", "storeId", "username", "compartmentId"].sort().join(",")
    || typeof identity.accountId !== "string" || !ATOMIC_UUID.test(identity.accountId)
    || typeof identity.storeId !== "string" || !ATOMIC_UUID.test(identity.storeId)
    || typeof identity.username !== "string" || !identity.username || identity.username.length > 512
    || typeof identity.compartmentId !== "string"
    || !identity.compartmentId || identity.compartmentId.length > 512) {
    fail("Atomic batch requires immutable externally provisioned account/store identity",
      "authorization_required");
  }
  return Object.freeze(identity);
}
function pinnedAtomicWitnessKey(value) {
  if (value == null) return null;
  let key;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    key = crypto.createPublicKey({ key: Buffer.from(value), format: "der", type: "spki" });
  } else if (typeof value === "string" && /^[A-Za-z0-9_-]{40,512}$/.test(value)) {
    const der = Buffer.from(value, "base64url");
    if (der.toString("base64url") !== value) {
      fail("Atomic batch witness key is not canonical", "authorization_required");
    }
    key = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  } else if (value instanceof crypto.KeyObject && value.type === "public") {
    // createPublicKey(publicKeyObject) throws ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE:
    // an independently supplied public pin is already a parsed KeyObject.
    key = value;
  } else {
    key = crypto.createPublicKey(value);
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    fail("Atomic batch witness pin must be an Ed25519 public key",
      "authorization_required");
  }
  return key;
}
function verifyAtomicBatchAdmission(response, operations, trustedWitnessKey, trustedScope, identity) {
  // Client-signed envelopes echoed by the server are NOT evidence that the
  // server committed them. Only a separate pinned witness can attest the
  // exact physical store head AFTER the two operations become durable.
  if (!trustedWitnessKey) fail("Independent atomic batch witness is unavailable",
    "sync_atomic_batch_indeterminate");
  const receipt = response?.atomicAdmission;
  const statement = receipt?.statement;
  const required = ["version", "scope", "accountId", "storeId", "username",
    "compartmentId", "nonce", "operationIds", "envelopeDigests",
    "commitId", "storeHeadSha256", "fencingEpoch", "physicalDurable"];
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)
    || Object.keys(receipt).sort().join(",") !== ["signature", "statement"].sort().join(",")
    || !statement || typeof statement !== "object" || Array.isArray(statement)
    || Object.keys(statement).sort().join(",") !== required.sort().join(",")
    || statement.version !== 2 || statement.scope !== trustedScope
    || !identity || statement.accountId !== identity.accountId
    || statement.storeId !== identity.storeId
    || statement.username !== identity.username
    || statement.compartmentId !== identity.compartmentId
    || statement.physicalDurable !== true
    || typeof statement.nonce !== "string"
    || !/^[A-Za-z0-9_-]{43}$/.test(statement.nonce)
    || !Number.isSafeInteger(statement.fencingEpoch) || statement.fencingEpoch < 1
    || typeof statement.commitId !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(statement.commitId)
    || typeof statement.storeHeadSha256 !== "string"
    || !/^[a-f0-9]{64}$/.test(statement.storeHeadSha256)
    || !Array.isArray(statement.operationIds) || statement.operationIds.length !== 2
    || !Array.isArray(statement.envelopeDigests) || statement.envelopeDigests.length !== 2
    || operations.some((operation, index) =>
      operation.authorization?.username !== identity.username
      || operation.compartmentId !== identity.compartmentId
      || statement.operationIds[index] !== operation.operationId
      || statement.envelopeDigests[index] !== signedEnvelopeDigest(operation))
    || typeof receipt.signature !== "string"
    || !/^[A-Za-z0-9_-]{86}$/.test(receipt.signature)) {
    fail("Atomic batch lacks an exact independent durable admission receipt",
      "sync_atomic_batch_indeterminate");
  }
  const signature = Buffer.from(receipt.signature, "base64url");
  if (signature.length !== 64
    || signature.toString("base64url") !== receipt.signature
    || !crypto.verify(null, Buffer.from(ATOMIC_ADMISSION_DOMAIN
      + protocol.canonicalJson(statement), "utf8"), trustedWitnessKey, signature)) {
    fail("Independent atomic batch witness signature invalid",
      "sync_atomic_batch_indeterminate");
  }
}
function verifyAtomicBatchCasFloor(floor, witnessStatement, trustedCasKey,
  trustedScope, expectedNonce, identity) {
  // An independent, off-host CAS reader must attest the CURRENT retained
  // physical head with a separate pinned signer. A new witness nonce alone
  // cannot distinguish a re-signed stale head after physical rollback.
  // Detach any callback-owned objects/getters before checking fields or
  // verifying bytes; an accessor must not swap a value between comparison
  // against the physical witness and Ed25519 verification.
  let detached;
  try { detached = JSON.parse(protocol.canonicalJson(floor)); }
  catch { fail("External CAS floor is not canonical JSON", "sync_atomic_batch_indeterminate"); }
  const statement = detached?.statement;
  const keys = ["version", "scope", "accountId", "storeId", "nonce",
    "commitId", "storeHeadSha256", "fencingEpoch", "sequence", "current"];
  if (!trustedCasKey || !detached || typeof detached !== "object" || Array.isArray(detached)
    || Object.keys(detached).sort().join(",") !== ["statement", "signature"].sort().join(",")
    || !statement || typeof statement !== "object" || Array.isArray(statement)
    || Object.keys(statement).sort().join(",") !== keys.sort().join(",")
    || statement.version !== 2 || statement.scope !== trustedScope
    || !identity || statement.accountId !== identity.accountId
    || statement.storeId !== identity.storeId
    || statement.accountId !== witnessStatement.accountId
    || statement.storeId !== witnessStatement.storeId
    || statement.scope !== witnessStatement.scope
    || statement.nonce !== expectedNonce || statement.current !== true
    || !Number.isSafeInteger(statement.sequence) || statement.sequence < 1
    || statement.commitId !== witnessStatement.commitId
    || statement.storeHeadSha256 !== witnessStatement.storeHeadSha256
    || statement.fencingEpoch !== witnessStatement.fencingEpoch
    || typeof detached.signature !== "string"
    || !/^[A-Za-z0-9_-]{86}$/.test(detached.signature)) {
    fail("External CAS floor does not attest the same current batch head",
      "sync_atomic_batch_indeterminate");
  }
  const signature = Buffer.from(detached.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== detached.signature
    || !crypto.verify(null, Buffer.from(ATOMIC_CAS_FLOOR_DOMAIN
      + protocol.canonicalJson(statement), "utf8"), trustedCasKey, signature)) {
    fail("External CAS current floor signature invalid",
      "sync_atomic_batch_indeterminate");
  }
}
function envelopeCopy(operation) {
  // Detach incoming JSON from transport/callback-owned mutable references.
  // An async key resolver must never be able to swap an already-verified
  // signed envelope before the filesystem is changed.
  return JSON.parse(protocol.canonicalJson(operation));
}

function signedWebDavEventId(operation) {
  // Only an exact deterministic WebDAV operation ID can group two pending
  // signed envelopes. Never infer batch ownership from adjacent array order
  // alone, an untrusted metadata field or a caller-selected operation ID.
  if (!operation || typeof operation !== "object"
    || !Object.hasOwn(operation, "authorization")
    || !["delete", "move"].includes(operation.operation)
    || typeof operation.operationId !== "string"
    || typeof operation.metadata?.path !== "string") return null;
  const parts = /^webdav-(.+)-([a-f0-9]{24})$/.exec(operation.operationId);
  if (!parts || parts[1].length > 100) return null;
  const digest = crypto.createHash("sha256")
    .update(`${operation.operation}:${operation.metadata.path}`)
    .digest("hex").slice(0, 24);
  return parts[2] === digest ? parts[1] : null;
}

function assertAtomicSignedOverwritePair(deleted, moved) {
  const event = signedWebDavEventId(deleted);
  if (!event || event !== signedWebDavEventId(moved)
    || deleted.operation !== "delete" || moved.operation !== "move"
    || deleted.metadata.path !== moved.metadata.path
    || !moved.metadata.sourcePath || deleted.deviceId !== moved.deviceId
    || deleted.compartmentId !== moved.compartmentId
    || deleted.keyEpoch !== moved.keyEpoch
    || deleted.objectId === moved.objectId || deleted.fileId === moved.fileId
    || deleted.operationId === moved.operationId
    || deleted.authorization.replayId === moved.authorization.replayId
    || deleted.authorization.idempotencyKey === moved.authorization.idempotencyKey) {
    fail("Signed WebDAV overwrite batch identity or order mismatch", "authorization_rejected");
  }
  return true;
}

function fail(message, code = "sync_engine_error") {
  throw Object.assign(new Error(message), { code });
}

function transient(error) {
  return ["ECONNREFUSED", "ENETUNREACH", "ETIMEDOUT", "EAI_AGAIN", "offline"].includes(error?.code);
}

async function exists(filePath) {
  return fsp.lstat(filePath).then(() => true, (error) => error.code === "ENOENT" ? false : Promise.reject(error));
}

async function containedAbsolute(rootDir, target, allowMissing = true) {
  const root = path.resolve(rootDir);
  const resolved = path.resolve(target);
  if (!(resolved === root || resolved.startsWith(`${root}${path.sep}`))) fail("Sync path escaped root", "unsafe_path");
  const rootStats = await fsp.lstat(root);
  if (rootStats.isSymbolicLink()) fail("Sync root symlink is not supported", "unsafe_path");
  let current = root;
  for (const segment of path.relative(root, resolved).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    try {
      const stats = await fsp.lstat(current);
      if (stats.isSymbolicLink()) fail("Sync symlink path is not supported", "unsafe_path");
    } catch (error) {
      if (!allowMissing || error.code !== "ENOENT") throw error;
      break;
    }
  }
  return resolved;
}

async function contained(rootDir, relativePath, allowMissing = true) {
  const safe = protocol.safeRelativePath(relativePath, "path");
  return containedAbsolute(rootDir, path.resolve(rootDir, ...safe.split("/")), allowMissing);
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.ino !== 0n;
}

function sameFileVersion(left, right) {
  return sameFileIdentity(left, right) && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs
    && left.birthtimeNs === right.birthtimeNs && left.mode === right.mode;
}

// Track metadata changes to a deliberately retained dirty excluded file without
// rereading or hashing its private content on every future sync. Any detected
// change still goes through the full verified _evictLocal guard before eviction.
function evictionFileVersionStamp(stats) {
  if (!stats.isFile() || stats.isSymbolicLink()) return null;
  return crypto.createHash("sha256").update([
    stats.dev, stats.ino, stats.size, stats.mtimeNs, stats.ctimeNs,
    stats.birthtimeNs, stats.mode, stats.nlink,
  ].map(String).join(":"), "utf8").digest("hex");
}

function isWithinPath(root, target) {
  const relative = path.relative(root, target);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

async function readContainedFile(rootDir, relativePath, expectedStats = null, internalLedgerRead = false) {
  const root = path.resolve(rootDir);
  // The internal eviction ledger must be invisible to normal local/remote
  // sync paths, but still needs the same nofollow + FD/inode verification.
  // Only its fixed, hash-validated record names take this internal branch.
  const target = internalLedgerRead
    ? await containedAbsolute(root, path.resolve(root, ...relativePath.split("/")), false)
    : await contained(root, relativePath, false);
  const before = expectedStats || await fsp.lstat(target, { bigint: true });
  // A hardlink into the selected root can alias an unrelated file outside it.
  // Canonical path and FD identity checks alone cannot detect that provenance.
  if (!before.isFile() || before.isSymbolicLink() || before.ino === 0n || before.nlink !== 1n) {
    fail("Sync file must be a regular file with a stable identity", "unsafe_path");
  }

  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  const handle = await fsp.open(target, flags);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !sameFileVersion(before, opened)) fail("Sync file changed while opening", "unsafe_path");

    await containedAbsolute(root, target, false);
    const canonicalRoot = await fsp.realpath(root);
    const canonicalTarget = await fsp.realpath(target);
    if (!isWithinPath(canonicalRoot, canonicalTarget)) fail("Sync file escaped root", "unsafe_path");
    const pathStats = await fsp.lstat(target, { bigint: true });
    if (!pathStats.isFile() || pathStats.isSymbolicLink() || pathStats.nlink !== 1n
      || !sameFileIdentity(opened, pathStats)) {
      fail("Sync file changed while opening", "unsafe_path");
    }

    const data = await handle.readFile();
    const openedAfterRead = await handle.stat({ bigint: true });
    const pathAfterRead = await fsp.lstat(target, { bigint: true });
    if (!sameFileVersion(opened, openedAfterRead) || openedAfterRead.nlink !== 1n
      || !sameFileIdentity(openedAfterRead, pathAfterRead)
      || !pathAfterRead.isFile() || pathAfterRead.isSymbolicLink() || pathAfterRead.nlink !== 1n) {
      fail("Sync file changed while reading", "unsafe_path");
    }
    await containedAbsolute(root, target, false);
    const finalRoot = await fsp.realpath(root);
    const finalTarget = await fsp.realpath(target);
    if (!isWithinPath(finalRoot, finalTarget)) fail("Sync file escaped root", "unsafe_path");
    return data;
  } finally {
    await handle.close();
  }
}

async function canonicalRelativePath(rootDir, relativePath) {
  const safe = protocol.safeRelativePath(relativePath, "path");
  if (process.platform !== "win32") return safe;
  const root = path.resolve(rootDir);
  await containedAbsolute(root, root, false);
  const segments = safe.split("/");
  let current = root;
  for (let index = 0; index < segments.length; index += 1) {
    const requested = segments[index];
    const names = await fsp.readdir(current);
    const matches = names.filter((name) => name.toLowerCase() === requested.toLowerCase());
    const selected = names.includes(requested) ? requested : matches.length === 1 ? matches[0] : null;
    if (!selected) {
      if (matches.length > 1) fail("Ambiguous case-insensitive sync path", "unsafe_path");
      current = path.join(current, ...segments.slice(index));
      break;
    }
    current = path.join(current, selected);
    const stats = await fsp.lstat(current);
    if (stats.isSymbolicLink()) fail("Sync symlink path is not supported", "unsafe_path");
    if (index < segments.length - 1 && !stats.isDirectory()) fail("Sync path parent must be a directory", "unsafe_path");
  }
  await containedAbsolute(root, current, true);
  return path.relative(root, current).split(path.sep).join("/");
}

// Resolve a *negative* (excluded) tracked path on both NTFS and POSIX, where
// the casing on disk may differ from the remote/snapshot identity. This never
// confers selection or authorization: callers must verify both the tracked
// key and physical alias before evicting. Reject ambiguous aliases and links;
// cap each directory read so a damaged root cannot trigger an unbounded scan.
async function uniqueExcludedPhysicalPath(rootDir, trackedPath, directoryCache) {
  const safe = protocol.safeRelativePath(trackedPath, "path");
  const root = path.resolve(rootDir);
  await containedAbsolute(root, root, false);
  const segments = safe.split("/");
  let current = root;
  for (let i = 0; i < segments.length; i += 1) {
    const directoryStats = await fsp.lstat(current, { bigint: true });
    if (directoryStats.isSymbolicLink() || !directoryStats.isDirectory()) {
      fail("Excluded path parent is not a regular directory", "unsafe_path");
    }
    // Cache only for this migration pass. Validate directory identity/version
    // on every lookup; if a concurrent rename/create changes it, rescan.
    // This avoids opening the same parent N times for N dirty sibling files.
    let cached = directoryCache.get(current);
    if (!cached || !sameFileVersion(cached.stats, directoryStats)) {
      const names = new Map();
      let count = 0;
      for await (const entry of await fsp.opendir(current)) {
        if (++count > 16384) fail("Excluded path directory has too many entries", "unsafe_path");
        const key = entry.name.toLowerCase();
        if (names.has(key)) names.set(key, null); // ambiguous portable alias
        else names.set(key, entry.name);
      }
      const afterRead = await fsp.lstat(current, { bigint: true });
      if (!sameFileVersion(directoryStats, afterRead)) {
        fail("Excluded path directory changed during casefold lookup", "unsafe_path");
      }
      cached = { stats: afterRead, names };
      directoryCache.set(current, cached);
    }
    const chosen = cached.names.get(segments[i].toLowerCase());
    if (chosen === null) fail("Ambiguous excluded portable case alias", "unsafe_path");
    if (chosen === undefined) return null;
    current = path.join(current, chosen);
    const stats = await fsp.lstat(current, { bigint: true });
    if (stats.isSymbolicLink() || (i < segments.length - 1 && !stats.isDirectory())) {
      fail("Excluded path contains a link or non-directory parent", "unsafe_path");
    }
  }
  await containedAbsolute(root, current, false);
  return path.relative(root, current).split(path.sep).join("/");
}

// After a successful, *fully verified* eviction the sync engine itself moved
// a single cache file out of its parent directory and rewrote its own snapshot
// in the root. Account for only those known local operations in the in-pass
// index, rather than rescanning N siblings for each of N safe evictions.
// All affected directories are independently re-enumerated before a migration
// is certified complete; unknown additions/aliases never become authorized.
async function observeVerifiedExcludedEviction(rootDir, physicalPath, directoryCache) {
  const root = path.resolve(rootDir);
  const target = path.resolve(root, ...protocol.safeRelativePath(physicalPath, "path").split("/"));
  const parent = path.dirname(target);
  const parentCache = directoryCache.get(parent);
  if (!parentCache) fail("Verified eviction lost its physical directory index", "unsafe_path");
  const basename = path.basename(target);
  const casefold = basename.toLowerCase();
  if (parentCache.names.get(casefold) !== basename || await exists(target)) {
    fail("Verified eviction left an unexpected physical cache entry", "unsafe_path");
  }
  const afterParent = await fsp.lstat(parent, { bigint: true });
  if (!afterParent.isDirectory() || !sameFileIdentity(parentCache.stats, afterParent)) {
    fail("Verified eviction changed its parent directory identity", "unsafe_path");
  }
  parentCache.names.delete(casefold);
  parentCache.stats = afterParent;
  await refreshExcludedInternalRoot(root, directoryCache);
}

// stageExisting creates the dedicated trash directory *before* a rename. A
// transient EBUSY can therefore leave that empty, safe internal directory
// behind even when no eviction succeeded. Keep that one known root entry in
// the in-pass index, but still compare the entire directory at the end.
async function refreshExcludedInternalRoot(rootDir, directoryCache) {
  const root = path.resolve(rootDir);
  const rootCache = directoryCache.get(root);
  if (!rootCache) return;
  const afterRoot = await fsp.lstat(root, { bigint: true });
  if (!afterRoot.isDirectory() || !sameFileIdentity(rootCache.stats, afterRoot)) {
    fail("Excluded sync root identity changed", "unsafe_path");
  }
  for (const internalName of [".rootark-trash", EVICTION_LEDGER_DIR]) {
    const internalPath = path.join(root, internalName);
    if (!(await exists(internalPath))) continue;
    const stats = await fsp.lstat(internalPath);
    if (!stats.isDirectory() || stats.isSymbolicLink()) fail("Unsafe internal sync directory", "unsafe_path");
    if (rootCache.names.has(internalName) && rootCache.names.get(internalName) !== internalName) {
      fail("Ambiguous internal sync directory", "unsafe_path");
    }
    rootCache.names.set(internalName, internalName);
  }
  rootCache.stats = afterRoot;
}

// The engine's own removals were the only names subtracted from the cache.
// Compare against physical names once per directory after the batch: external
// concurrent additions, case collisions and unexpected replacements fail
// closed instead of being recorded as an entirely applied exclusion.
async function verifyExcludedDirectoryIndexes(directoryCache) {
  for (const [directory, cached] of directoryCache) {
    const before = await fsp.lstat(directory, { bigint: true });
    if (!before.isDirectory() || !sameFileIdentity(cached.stats, before)) {
      fail("Excluded directory identity changed during batch", "unsafe_path");
    }
    const actual = new Map();
    let count = 0;
    for await (const entry of await fsp.opendir(directory)) {
      if (++count > 16384) fail("Excluded path directory has too many entries", "unsafe_path");
      const key = entry.name.toLowerCase();
      if (actual.has(key)) fail("Ambiguous excluded portable case alias", "unsafe_path");
      actual.set(key, entry.name);
    }
    const after = await fsp.lstat(directory, { bigint: true });
    if (!sameFileVersion(before, after) || actual.size !== cached.names.size) {
      fail("Excluded directory changed outside verified evictions", "unsafe_path");
    }
    for (const [key, name] of actual) {
      if (cached.names.get(key) !== name) {
        fail("Excluded directory names changed outside verified evictions", "unsafe_path");
      }
    }
  }
}

function canonicalMapPath(relativePath, ...maps) {
  if (process.platform !== "win32") return relativePath;
  for (const map of maps) {
    if (Object.prototype.hasOwnProperty.call(map, relativePath)) return relativePath;
  }
  const matches = new Set();
  for (const map of maps) {
    for (const candidate of Object.keys(map)) {
      if (candidate.toLowerCase() === relativePath.toLowerCase()) matches.add(candidate);
    }
  }
  if (matches.size > 1) fail("Ambiguous case-insensitive sync snapshot path", "unsafe_path");
  return matches.size === 1 ? [...matches][0] : relativePath;
}

async function durableJson(filePath, value) {
  const temporary = `${filePath}.tmp-${process.pid}-${crypto.randomUUID()}`;
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
    | (fs.constants.O_SYNC || 0);
  let handle;
  try {
    handle = await fsp.open(temporary, flags, 0o600);
    await handle.writeFile(`${JSON.stringify(value)}\n`);
    await handle.sync();
    await handle.close();
    handle = null;
    await renameWithRetry(temporary, filePath);
    // Node cannot reliably fsync directory handles on Windows. Flush the
    // containing directory where the platform supports it; the file itself
    // is opened with O_SYNC and explicitly synced before the atomic rename.
    if (process.platform !== "win32") {
      const directory = await fsp.open(path.dirname(filePath), fs.constants.O_RDONLY);
      try { await directory.sync(); } finally { await directory.close(); }
    }
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fsp.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

// A bounded, per-object write-ahead snapshot overlay. Full snapshots remain
// the authoritative compaction format; small independently synced PREPARE and
// COMMIT records only protect the window between verified remote content and
// removing its local cache file. No record ever authorizes a remote write.
const EVICTION_LEDGER_DIR = ".rootark-sync-evictions";
const EVICTION_LEDGER_VERSION = 1;
const EVICTION_LEDGER_MAX = 16384;
const EVICTION_LEDGER_HASH = /^[a-f0-9]{64}$/;
const EVICTION_LEDGER_ZERO = "0".repeat(64);
const EVICTION_LEDGER_ARCHIVE = ".rootark-sync-evictions-archive-";
// v1 clients already ignore .rootark-trash. Atomically stage the synced
// head file there until v2 is durable; a crash must not strand a half-built
// genesis directory that would block startup before any PREPARE.
const EVICTION_GENESIS_STAGE = ".rootark-eviction-genesis-head.json";
const EVICTION_LEDGER_EPOCH = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function evictionLedgerDirectory(rootDir) { return path.join(rootDir, EVICTION_LEDGER_DIR); }
function evictionLedgerName(objectId, phase) {
  return `${crypto.createHash("sha256").update(objectId, "utf8").digest("hex")}.${phase}.json`;
}
function evictionLedgerDigest(item) {
  return crypto.createHash("sha256").update(protocol.canonicalJson(item), "utf8").digest("hex");
}
function validEvictionLedgerHead(head) {
  return head && typeof head === "object" && !Array.isArray(head)
    && Object.keys(head).sort().join(",") === "digest,epoch,sequence"
    && typeof head.epoch === "string" && EVICTION_LEDGER_EPOCH.test(head.epoch)
    && Number.isSafeInteger(head.sequence) && head.sequence >= 0 && head.sequence <= EVICTION_LEDGER_MAX
    && typeof head.digest === "string" && EVICTION_LEDGER_HASH.test(head.digest);
}
async function fsyncEvictionDirectory(directory) {
  if (process.platform === "win32") return;
  const handle = await fsp.open(directory, fs.constants.O_RDONLY);
  try { await handle.sync(); } finally { await handle.close(); }
}
// Immutable ledger records must never overwrite an existing name between a
// preflight and rename; a torn exclusive file is deliberately fail-closed.
async function createDurableEvictionRecord(filePath, value) {
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
    | (fs.constants.O_SYNC || 0);
  const handle = await fsp.open(filePath, flags, 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8");
    await handle.sync();
  } finally { await handle.close(); }
  await fsyncEvictionDirectory(path.dirname(filePath));
}
async function openEvictionLedger(rootDir, create = false) {
  const directory = evictionLedgerDirectory(rootDir);
  if (create) {
    const existed = await exists(directory);
    await fsp.mkdir(directory, { recursive: true, mode: 0o700 });
    if (!existed && process.platform !== "win32") {
      const parent = await fsp.open(rootDir, fs.constants.O_RDONLY);
      try { await parent.sync(); } finally { await parent.close(); }
    }
  } else if (!(await exists(directory))) return null;
  const stats = await fsp.lstat(directory, { bigint: true });
  if (!stats.isDirectory() || stats.isSymbolicLink()) fail("Unsafe eviction ledger directory", "invalid_snapshot");
  await containedAbsolute(rootDir, directory, false);
  return directory;
}
async function stagedEvictionGenesis(rootDir) {
  const trash = path.join(rootDir, ".rootark-trash");
  if (!(await exists(trash))) return null;
  await containedAbsolute(rootDir, trash, false);
  const rootStats = await fsp.lstat(rootDir, { bigint: true });
  const trashStats = await fsp.lstat(trash, { bigint: true });
  if (!rootStats.isDirectory() || rootStats.isSymbolicLink() || rootStats.ino === 0n
    || !trashStats.isDirectory() || trashStats.isSymbolicLink() || trashStats.ino === 0n) {
    fail("Unsafe pre-upgrade eviction genesis parent", "invalid_snapshot");
  }
  // No count bound here: legacy trash can contain arbitrarily many legitimate
  // retained files when a process crashes after the required-v2 checkpoint.
  // Scan the *entire* directory in O(1) memory for every portable case alias
  // of the sole authoritative marker, not just the first 16,384 entries.
  // Other trash content does not witness an eviction and grants no authority.
  // POSIX holds the parent's directory FD to detect concurrent path replacement.
  // Windows cannot portably open a directory FD through fs.promises.open, so
  // lstat identity/version and contained FD verification remain mandatory.
  let held = null;
  let candidate = null;
  const assertUnchanged = async () => {
    await containedAbsolute(rootDir, trash, false);
    const currentRoot = await fsp.lstat(rootDir, { bigint: true });
    const currentTrash = await fsp.lstat(trash, { bigint: true });
    if (!sameFileVersion(rootStats, currentRoot)
      || !sameFileVersion(trashStats, currentTrash)
      || (held && !sameFileVersion(trashStats, await held.stat({ bigint: true })))) {
      fail("Eviction genesis parent changed during streamed proof", "invalid_snapshot");
    }
  };
  try {
    if (process.platform !== "win32") {
      held = await fsp.open(trash, fs.constants.O_RDONLY
        | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0));
      await assertUnchanged();
    }
    for await (const entry of await fsp.opendir(trash)) {
      if (entry.name.toLowerCase() !== EVICTION_GENESIS_STAGE) continue;
      if (candidate !== null || entry.name !== EVICTION_GENESIS_STAGE) {
        fail("Ambiguous staged eviction genesis", "invalid_snapshot");
      }
      candidate = entry.name;
    }
    await assertUnchanged();
    if (candidate === null) return null;
    const headFile = path.join(trash, EVICTION_GENESIS_STAGE);
    const headStats = await fsp.lstat(headFile, { bigint: true });
    if (!headStats.isFile() || headStats.isSymbolicLink()
      || headStats.nlink !== 1n || headStats.size > 8192n) {
      fail("Unsafe staged eviction genesis head", "invalid_snapshot");
    }
    let head;
    try {
      const raw = await readContainedFile(rootDir, `.rootark-trash/${EVICTION_GENESIS_STAGE}`,
        headStats, true);
      head = JSON.parse(raw.toString("utf8"));
    } catch {
      fail("Unreadable staged eviction genesis head", "invalid_snapshot");
    }
    await assertUnchanged();
    if (!validEvictionLedgerHead(head) || head.sequence !== 0
      || head.digest !== EVICTION_LEDGER_ZERO) {
      fail("Invalid staged eviction genesis", "invalid_snapshot");
    }
    return { trash, file: headFile, head };
  } finally {
    if (held) await held.close();
  }
}
async function createStagedEvictionGenesis(rootDir) {
  const existing = await stagedEvictionGenesis(rootDir);
  if (existing) return existing;
  const trash = path.join(rootDir, ".rootark-trash");
  if (!(await exists(trash))) {
    await fsp.mkdir(trash, { mode: 0o700 });
    await fsyncEvictionDirectory(rootDir);
  }
  await containedAbsolute(rootDir, trash, false);
  const stats = await fsp.lstat(trash, { bigint: true });
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    fail("Unsafe pre-upgrade eviction genesis parent", "invalid_snapshot");
  }
  const head = { epoch: crypto.randomUUID(), sequence: 0, digest: EVICTION_LEDGER_ZERO };
  const file = path.join(trash, EVICTION_GENESIS_STAGE);
  // durableJson fsyncs temporary bytes then atomically renames and fsyncs
  // the parent on POSIX. A crash before rename leaves no visible genesis.
  await durableJson(file, head);
  return { trash, file, head };
}
async function promoteStagedEvictionGenesis(rootDir, staged) {
  const active = await readEvictionLedger(rootDir);
  if (active.head || active.entries.size) {
    fail("Existing eviction journal prevents genesis promotion", "invalid_snapshot");
  }
  const directory = active.directory || await openEvictionLedger(rootDir, true);
  const headFile = path.join(directory, "head.json");
  if (await exists(headFile)) fail("Eviction head appeared during promotion", "invalid_snapshot");
  await fsp.rename(staged.file, headFile);
  await fsyncEvictionDirectory(directory);
  await fsyncEvictionDirectory(staged.trash);
  const promoted = await readEvictionLedger(rootDir, staged.head.epoch);
  if (promoted.entries.size || !promoted.head
    || promoted.head.sequence !== 0 || promoted.head.digest !== EVICTION_LEDGER_ZERO) {
    fail("Durable genesis promotion is indeterminate", "invalid_snapshot");
  }
}
function validateEvictionPrepare(item, filename) {
  if (!item || typeof item !== "object" || Array.isArray(item)
    || Object.keys(item).sort().join(",") !== "epoch,fileId,hash,objectId,path,physical,previousDigest,record,remoteDigest,sequence,tx,version"
    || item.version !== EVICTION_LEDGER_VERSION
    || typeof item.tx !== "string" || !/^[a-f0-9-]{36}$/.test(item.tx)
    || typeof item.epoch !== "string" || !EVICTION_LEDGER_EPOCH.test(item.epoch)
    || !Number.isSafeInteger(item.sequence) || item.sequence < 1 || item.sequence > EVICTION_LEDGER_MAX
    || typeof item.previousDigest !== "string" || !EVICTION_LEDGER_HASH.test(item.previousDigest)
    || typeof item.remoteDigest !== "string" || !EVICTION_LEDGER_HASH.test(item.remoteDigest)
    || typeof item.objectId !== "string" || !item.objectId || item.objectId.length > 512
    || ["__proto__", "prototype", "constructor"].includes(item.objectId)
    || typeof item.fileId !== "string" || !item.fileId || item.fileId.length > 512
    || !EVICTION_LEDGER_HASH.test(item.hash)
    || filename !== evictionLedgerName(item.objectId, "prepare")) {
    fail("Invalid durable eviction PREPARE", "invalid_snapshot");
  }
  try {
    protocol.safeRelativePath(item.path, "path");
    protocol.safeRelativePath(item.physical, "physical");
  } catch { fail("Invalid durable eviction path", "invalid_snapshot"); }
  if (item.path.toLowerCase() !== item.physical.toLowerCase()
    || !item.record || item.record.objectId !== item.objectId
    || item.record.fileId !== item.fileId || item.record.path !== item.path
    || item.record.hash !== item.hash || item.record.reason !== "evicted"
    || item.record.directory !== false || item.record.deleted !== false
    || Object.keys(item.record).sort().join(",") !== "deleted,directory,fileId,hash,objectId,path,reason,revision,versionId") {
    fail("Invalid durable eviction identity", "invalid_snapshot");
  }
  return item;
}
async function readEvictionLedger(rootDir, expectedEpoch = null) {
  const directory = await openEvictionLedger(rootDir);
  if (!directory) return { directory: null, entries: new Map(), head: null };
  const files = await fsp.readdir(directory);
  if (files.length > EVICTION_LEDGER_MAX * 2 + 1) fail("Eviction ledger capacity exceeded", "invalid_snapshot");
  let head = null;
  const entries = new Map();
  for (const filename of files) {
    const match = /^([a-f0-9]{64})\.(prepare|commit)\.json$/.exec(filename);
    if (!match && filename !== "head.json") fail("Malformed or torn eviction ledger entry", "invalid_snapshot");
    const file = path.join(directory, filename);
    const stats = await fsp.lstat(file, { bigint: true });
    if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1n || stats.size > 8192n) {
      fail("Unsafe eviction ledger entry", "invalid_snapshot");
    }
    let item;
    try {
      const bytes = await readContainedFile(rootDir, `${EVICTION_LEDGER_DIR}/${filename}`, stats, true);
      if (bytes.length > 8192) fail("Oversized eviction ledger entry", "invalid_snapshot");
      item = JSON.parse(bytes.toString("utf8"));
    }
    catch { fail("Torn eviction ledger entry", "invalid_snapshot"); }
    if (filename === "head.json") {
      if (!validEvictionLedgerHead(item)) fail("Invalid eviction ledger head", "invalid_snapshot");
      head = item;
      continue;
    }
    const row = entries.get(match[1]) || {};
    if (row[match[2]]) fail("Duplicated eviction ledger entry", "invalid_snapshot");
    row[match[2]] = { item, filename };
    entries.set(match[1], row);
  }
  // A synced zero-sequence genesis may precede the snapshot's v2 upgrade.
  // No cache file may leave its path until the v2 required marker is durable.
  if ((!head && entries.size > 0)
    || (head && entries.size === 0
      && (head.sequence !== 0 || head.digest !== EVICTION_LEDGER_ZERO))) {
    fail("Missing eviction ledger head or PREPARE entries", "invalid_snapshot");
  }
  let sequence = 0;
  let digest = EVICTION_LEDGER_ZERO;
  const ordered = [...entries.values()].sort((left, right) =>
    left.prepare?.item?.sequence - right.prepare?.item?.sequence);
  for (const row of ordered) {
    if (!row.prepare) fail("Eviction COMMIT without PREPARE", "invalid_snapshot");
    validateEvictionPrepare(row.prepare.item, row.prepare.filename);
    if (row.prepare.item.sequence !== sequence + 1
      || row.prepare.item.previousDigest !== digest
      || row.prepare.item.epoch !== head.epoch) {
      fail("Eviction journal sequence or chain is not monotonic", "invalid_snapshot");
    }
    sequence += 1;
    digest = evictionLedgerDigest(row.prepare.item);
  }
  if (head && (head.sequence !== sequence || head.digest !== digest
    || (expectedEpoch !== null && head.epoch !== expectedEpoch))) {
    fail("Eviction ledger head is not anchored to the sync snapshot", "invalid_snapshot");
  }
  for (const [id, row] of entries) {
    if (!row.prepare) fail("Eviction COMMIT without PREPARE", "invalid_snapshot");
    validateEvictionPrepare(row.prepare.item, row.prepare.filename);
    if (evictionLedgerName(row.prepare.item.objectId, "prepare").slice(0, 64) !== id) {
      fail("Conflicting eviction ledger identity", "invalid_snapshot");
    }
    if (row.commit && (!row.commit.item || row.commit.item.version !== EVICTION_LEDGER_VERSION
      || row.commit.item.tx !== row.prepare.item.tx
      || row.commit.item.digest !== crypto.createHash("sha256")
        .update(JSON.stringify(row.prepare.item)).digest("hex")
      || Object.keys(row.commit.item).sort().join(",") !== "digest,tx,version")) {
      fail("Eviction COMMIT differs from PREPARE", "invalid_snapshot");
    }
  }
  if (entries.size > EVICTION_LEDGER_MAX) fail("Eviction ledger has too many objects", "invalid_snapshot");
  return { directory, entries, head };
}
async function writeEvictionPrepare(rootDir, prepare, currentHead) {
  const filename = evictionLedgerName(prepare.objectId, "prepare");
  validateEvictionPrepare(prepare, filename);
  if (!validEvictionLedgerHead(currentHead) || currentHead.epoch !== prepare.epoch
    || prepare.sequence !== currentHead.sequence + 1
    || prepare.previousDigest !== currentHead.digest) {
    fail("Eviction PREPARE lost its monotonic snapshot anchor", "invalid_snapshot");
  }
  const directory = await openEvictionLedger(rootDir, true);
  const file = path.join(directory, filename);
  const headPath = path.join(directory, "head.json");
  if (!(await exists(headPath))) {
    fail("Unreconciled eviction journal head", "invalid_snapshot");
  }
  if (currentHead.sequence === 0) {
    const initial = await readEvictionLedger(rootDir, currentHead.epoch);
    if (initial.entries.size || !initial.head || initial.head.sequence !== 0
      || initial.head.digest !== EVICTION_LEDGER_ZERO) {
      fail("Missing or replaced durable eviction genesis", "invalid_snapshot");
    }
  }
  // One in-flight version per object; never overwrite an earlier PREPARE
  // whose physical state might still be awaiting replay.
  if (await exists(file)
    || await exists(path.join(directory, evictionLedgerName(prepare.objectId, "commit")))) {
    fail("Unreconciled durable eviction PREPARE/COMMIT", "invalid_snapshot");
  }
  await createDurableEvictionRecord(file, prepare);
  const head = { epoch: prepare.epoch, sequence: prepare.sequence,
    digest: evictionLedgerDigest(prepare) };
  await durableJson(headPath, head);
  return head;
}
async function writeEvictionCommit(rootDir, prepare) {
  const digest = crypto.createHash("sha256").update(JSON.stringify(prepare)).digest("hex");
  await createDurableEvictionRecord(path.join(evictionLedgerDirectory(rootDir), evictionLedgerName(prepare.objectId, "commit")),
    { version: EVICTION_LEDGER_VERSION, tx: prepare.tx, digest });
}
async function clearEvictionLedger(rootDir, expectedEpoch = null) {
  const { directory, entries } = await readEvictionLedger(rootDir, expectedEpoch);
  if (!directory || !entries.size) return;
  // The full snapshot is durable. Atomically retire the whole old ledger
  // before removing individual files, so a crash during cleanup cannot
  // expose a partial active chain to the next process.
  const archived = path.join(rootDir, `${EVICTION_LEDGER_ARCHIVE}${crypto.randomUUID()}`);
  await fsp.rename(directory, archived);
  await fsyncEvictionDirectory(rootDir);
  await fsp.mkdir(directory, { mode: 0o700 });
  await fsyncEvictionDirectory(rootDir);
  for (const row of entries.values()) {
    if (row.commit) await fsp.unlink(path.join(archived, row.commit.filename));
    await fsp.unlink(path.join(archived, row.prepare.filename));
  }
  await fsp.unlink(path.join(archived, "head.json"));
  await fsp.rmdir(archived);
  await fsyncEvictionDirectory(rootDir);
}

function normalizeWebDavPath(value) {
  let decoded;
  try { decoded = decodeURIComponent(String(value || "")); } catch { fail("Invalid WebDAV path", "unsafe_path"); }
  return protocol.safeRelativePath(decoded.replace(/^\/+|\/+$/g, ""), "path");
}

function pathWithin(relativePath, parentPath) {
  const relative = process.platform === "win32" ? relativePath.toLowerCase() : relativePath;
  const parent = process.platform === "win32" ? parentPath.toLowerCase() : parentPath;
  return relative === parent || relative.startsWith(`${parent}/`);
}

function pathsEqual(left, right) {
  return pathWithin(left, right) && pathWithin(right, left);
}

function evictionError(code, message, cause, rollbackCause) {
  return Object.assign(new Error(message), { code, cause, ...(rollbackCause ? { rollbackCause } : {}) });
}

function normalizeExcludedPaths(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) fail("Excluded paths must be an array", "invalid_excluded_paths");
  return [...new Set(value.map((item) => validatePortableRelativePath(item, "excludedPath")))].sort();
}

function pathKey(relativePath) {
  return process.platform === "win32" ? relativePath.toLowerCase() : relativePath;
}

function pinnedKey(objectId) {
  // Never index a parsed JSON object by an untrusted objectId such as
  // "__proto__"; a SHA-256 hex key also stays portable across devices.
  return crypto.createHash("sha256").update(objectId, "utf8").digest("hex");
}

function sameSnapshotRevision(left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino
    && left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs);
}

function activeIdentityPath(files, operation, exceptPath) {
  return Object.entries(files).find(([relativePath, prior]) => relativePath !== exceptPath
    && !prior.deleted && prior.directory
    && prior.objectId === operation.objectId && prior.fileId === operation.fileId)?.[0] || null;
}

function activeFileIdentityPath(files, operation, exceptPath) {
  return Object.entries(files).find(([relativePath, prior]) => relativePath !== exceptPath
    && !prior.deleted && !prior.directory
    && prior.objectId === operation.objectId && prior.fileId === operation.fileId)?.[0] || null;
}

class SyncEngine {
  constructor(options = {}) {
    if (!options.adapter || typeof options.adapter.push !== "function" || typeof options.adapter.list !== "function") {
      fail("Sync adapter with push and list is required");
    }
    this.rootDir = path.resolve(options.rootDir || process.cwd());
    this.journal = options.journal || new SyncJournal(options.journalPath || path.join(this.rootDir, ".rootark-sync-journal.json"));
    this.snapshotPath = path.resolve(options.snapshotPath || path.join(this.rootDir, ".rootark-sync-index.json"));
    this.adapter = options.adapter;
    this.deviceId = String(options.deviceId || "");
    this.keyEpoch = String(options.keyEpoch || "");
    this.compartmentId = String(options.compartmentId || "");
    this.fileKeyResolver = options.fileKeyResolver || (() => options.fileKey);
    this.authorize = options.authorize || (() => true);
    this.authorizeOutgoing = options.authorizeOutgoing || (() => true);
    // Supplied by the embedding process from independently trusted, CURRENT
    // device policy. Config snapshots and the local journal are not authority.
    this.currentDeviceAuthorization = options.currentDeviceAuthorization || null;
    this.requireCurrentOutgoingAuthorization = options.requireCurrentOutgoingAuthorization === true;
    // Must be supplied from an independent, trusted owner-pinned source.
    // NEVER accept a key sent by the sync server or serialized in the journal.
    const witnessPublicKey = pinnedAtomicWitnessKey(options.atomicBatchWitnessPublicKey);
    const witnessReadback = options.atomicBatchWitnessReadback || null;
    const witnessScope = options.atomicBatchWitnessScope || null;
    const ownerIdentity = pinnedAtomicOwnerIdentity(options.atomicBatchOwnerIdentity);
    const casFloorPublicKey = pinnedAtomicWitnessKey(options.atomicBatchCasFloorPublicKey);
    const casFloorReadback = options.atomicBatchCasFloorReadback || null;
    if (casFloorReadback !== null
      && typeof casFloorReadback !== "function") {
      fail("Independent external CAS floor reader must be a function",
        "authorization_required");
    }
    if (witnessPublicKey && casFloorPublicKey
      && witnessPublicKey.export({ type: "spki", format: "der" })
        .equals(casFloorPublicKey.export({ type: "spki", format: "der" }))) {
      fail("External CAS floor and physical witness require distinct pinned keys",
        "authorization_required");
    }
    if (witnessScope !== null
      && (typeof witnessScope !== "string"
        || !/^[A-Za-z0-9._:-]{1,256}$/.test(witnessScope))) {
      fail("Atomic batch witness scope must be a trusted account/store identifier",
        "authorization_required");
    }
    if (witnessReadback !== null
      && typeof witnessReadback !== "function") {
      fail("Independent atomic batch witness readback must be a function",
        "authorization_required");
    }
    const ownerProvision = (witnessPublicKey || witnessReadback || witnessScope
      || ownerIdentity || casFloorPublicKey || casFloorReadback)
      ? verifyPinnedAtomicOwnerProvision({
        identity: ownerIdentity,
        scope: witnessScope,
        provisionerPublicKey: options.atomicBatchOwnerProvisionerPublicKey,
        provisioning: options.atomicBatchOwnerProvisioning,
        expectedDigest: options.atomicBatchOwnerProvisionDigest,
        witnessPublicKey, casPublicKey: casFloorPublicKey,
      }) : null;
    if (ownerProvision && [witnessPublicKey, casFloorPublicKey].some((key) =>
      key && key.export({ type: "spki", format: "der" }).equals(
        ownerProvision.publicKey.export({ type: "spki", format: "der" })))) {
      fail("Owner provisioner, witness and CAS must have distinct pinned keys",
        "authorization_required");
    }
    // Never let an async callback swap the signer, CAS identity, scope or
    // direct-readback function after construction. Ordinary instance fields
    // would allow a witness callback to mutate `this.*` between awaited
    // signature checks and silently defeat the separate-authority contract.
    Object.defineProperties(this, {
      atomicBatchWitnessPublicKey: { value: witnessPublicKey },
      atomicBatchWitnessReadback: { value: witnessReadback },
      atomicBatchWitnessScope: { value: witnessScope },
      atomicBatchOwnerIdentity: { value: ownerIdentity },
      atomicBatchOwnerProvisionerPublicKey: { value: ownerProvision?.publicKey || null },
      atomicBatchCasFloorPublicKey: { value: casFloorPublicKey },
      atomicBatchCasFloorReadback: { value: casFloorReadback },
    });
    if ((options.currentDeviceAuthorization != null && typeof options.currentDeviceAuthorization !== "function")
      || (this.requireCurrentOutgoingAuthorization && !this.currentDeviceAuthorization)) {
      fail("Current device authorization callback is required", "authorization_required");
    }
    this.verifyIncoming = options.verifyIncoming || null;
    this.reverifySeenIncoming = options.reverifySeenIncoming === true;
    this.authorizationFactory = options.authorizationFactory || null;
    this.requireAuthorization = options.requireAuthorization === true;
    this.translateWebDavOperation = options.translateWebDavOperation || null;
    this.maxRetries = Math.max(1, Math.min(5, Number(options.maxRetries || 3)));
    if (options.selectedPaths != null && !Array.isArray(options.selectedPaths)) fail("Selected paths must be an array", "invalid_selected_paths");
    this.selectedPaths = options.selectedPaths == null ? null : [...new Set(options.selectedPaths.map((value) => protocol.safeRelativePath(value, "selectedPath")))].sort();
    this.excludedPaths = normalizeExcludedPaths(options.excludedPaths);
    Object.defineProperty(this, "filesOnDemand", {
      value: options.filesOnDemand === true,
    });
    // A future Files On-Demand recovery must use native, independently rooted
    // custody. The old path-based required-v2 replay is not safe against
    // same-principal A→B→A. This strict bit cannot be downgraded by callbacks;
    // non-Files-On-Demand legacy recovery is unchanged unless explicitly opted
    // into the stricter fail-closed policy.
    Object.defineProperty(this, "requireNativeRootRecovery", {
      value: this.filesOnDemand || options.requireNativeRootRecovery === true,
    });
    if (this.filesOnDemand && typeof this.adapter.listInventory !== "function") {
      fail("Files On-Demand requires a metadata inventory adapter", "inventory_unavailable");
    }
    this.snapshot = { version: SNAPSHOT_VERSION, files: {}, remoteOnly: {} };
    this.snapshotDiskRevision = null;
    this.evictionLedgerHead = null;
    // If a failed pin-policy compensation cannot be durably verified, keep
    // the pre-existing process lock on disk: no restart may silently evict.
    this.pinnedPolicyIndeterminate = false;
    this.opened = false;
  }

  withMutationLock(work) {
    const queueKey = process.platform === "win32" ? this.rootDir.toLowerCase() : this.rootDir;
    if (ROOT_MUTATION_CONTEXT.getStore() === queueKey) {
      fail("Sync mutations cannot re-enter a root operation", "sync_root_busy");
    }
    const previous = ROOT_MUTATION_QUEUES.get(queueKey) || Promise.resolve();
    let releaseQueue;
    const queueGate = new Promise((resolve) => { releaseQueue = resolve; });
    ROOT_MUTATION_QUEUES.set(queueKey, queueGate);
    const run = async () => {
      await fsp.mkdir(this.rootDir, { recursive: true });
      await containedAbsolute(this.rootDir, this.rootDir, false);
      const processLock = await this.acquireProcessLock();
      try {
        await openEngineBuiltIn.call(this);
        return await ROOT_MUTATION_CONTEXT.run(queueKey, work);
      } finally {
        // The same exclusive mkdir marker is understood by fresh processes.
        // Never release it after an indeterminate failed unpin rollback;
        // explicit operator recovery is required instead of trusting disk.
        if (!this.pinnedPolicyIndeterminate) await this.releaseProcessLock(processLock);
      }
    };
    const operation = previous.then(run, run);
    return operation.finally(() => {
      releaseQueue();
      if (ROOT_MUTATION_QUEUES.get(queueKey) === queueGate) ROOT_MUTATION_QUEUES.delete(queueKey);
    });
  }

  async open() {
    return this.withMutationLock(async () => this);
  }

  async acquireProcessLock() {
    const lockPath = path.join(this.rootDir, ".rootark-sync.lock");
    try {
      // mkdir is an atomic no-overwrite claim. The lock directory is empty so
      // release can use rmdir, which itself refuses to remove a replacement
      // directory if it contains anything.
      await fsp.mkdir(lockPath, { mode: 0o700 });
      return lockPath;
    } catch (error) {
      if (error.code === "EEXIST") {
        fail("Another sync writer owns this folder, or its leftover lock needs manual recovery", "sync_root_busy");
      }
      throw error;
    }
  }

  async releaseProcessLock(lockPath) {
    try {
      // The operation is atomic with respect to directory contents: if an
      // unexpected actor replaced this marker with a nonempty lock directory,
      // rmdir refuses to remove it instead of deleting by checked pathname.
      await fsp.rmdir(lockPath);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }

  async _open() {
    await fsp.mkdir(this.rootDir, { recursive: true });
    await containedAbsolute(this.rootDir, this.rootDir, false);
    this.journal = await this.journal.open();
    // A rejected native-required cold open must never let a later open use
    // public, mutable this.snapshot as if it were still the disk contents.
    // Re-parse the durable snapshot on every strict entry, including retries
    // after a previously failed recovery. This is a JS-state safeguard; it
    // does not authenticate the disk or protect against hostile root swaps.
    if (this.requireNativeRootRecovery) this.snapshotDiskRevision = null;
    let snapshotStats;
    try {
      snapshotStats = await fsp.lstat(this.snapshotPath, { bigint: true });
    } catch (error) {
      if (error.code !== "ENOENT" || this.opened) fail("Sync snapshot is unavailable", "invalid_snapshot");
      await durableJson(this.snapshotPath, this.snapshot);
      snapshotStats = await fsp.lstat(this.snapshotPath, { bigint: true });
    }
    if (!snapshotStats.isFile() || snapshotStats.isSymbolicLink()) fail("Sync snapshot is not a regular file", "invalid_snapshot");
    if (!sameSnapshotRevision(this.snapshotDiskRevision, snapshotStats)) {
      let parsed;
      try {
        parsed = JSON.parse(await fsp.readFile(this.snapshotPath, "utf8"));
      } catch {
        fail("Invalid sync snapshot", "invalid_snapshot");
      }
      if (![SNAPSHOT_VERSION, EVICTION_LEDGER_SNAPSHOT_VERSION].includes(parsed.version)
        || !parsed.files || typeof parsed.files !== "object" || Array.isArray(parsed.files)) fail("Invalid sync snapshot", "invalid_snapshot");
      if ((parsed.version === EVICTION_LEDGER_SNAPSHOT_VERSION
        && (typeof parsed.evictionLedgerEpoch !== "string"
          || !EVICTION_LEDGER_EPOCH.test(parsed.evictionLedgerEpoch)
          || typeof parsed.evictionLedgerRequired !== "boolean"))
        || (parsed.version === SNAPSHOT_VERSION
          && (parsed.evictionLedgerEpoch !== undefined
            || parsed.evictionLedgerRequired !== undefined))) {
        fail("Sync snapshot has an invalid eviction replay epoch", "invalid_snapshot");
      }
      if (parsed.remoteOnly === undefined) parsed.remoteOnly = {};
      if (!parsed.remoteOnly || typeof parsed.remoteOnly !== "object" || Array.isArray(parsed.remoteOnly)) fail("Invalid remote-only sync state", "invalid_snapshot");
      if (parsed.excludedPaths !== undefined) {
        try { parsed.excludedPaths = normalizeExcludedPaths(parsed.excludedPaths); } catch { fail("Invalid excluded sync paths", "invalid_snapshot"); }
      }
      if (parsed.excludedPathsCasefoldVersion !== undefined
        && ![1, EXCLUDED_PATHS_CASEFOLD_VERSION].includes(parsed.excludedPathsCasefoldVersion)) {
        fail("Unknown excluded sync policy version", "invalid_snapshot");
      }
      if (parsed.pendingEvictions !== undefined) {
        if (!parsed.pendingEvictions || typeof parsed.pendingEvictions !== "object" || Array.isArray(parsed.pendingEvictions)) fail("Invalid pending evictions", "invalid_snapshot");
        for (const entry of Object.values(parsed.pendingEvictions)) {
          if (!entry || typeof entry !== "object" || typeof entry.code !== "string" || !Number.isInteger(entry.attempts) || entry.attempts < 0) fail("Invalid pending eviction", "invalid_snapshot");
          try { protocol.safeRelativePath(entry.path, "path"); } catch { fail("Invalid pending eviction path", "invalid_snapshot"); }
          if (entry.localVersionStamp !== undefined
            && (entry.code !== "local_changes_pending" || typeof entry.localVersionStamp !== "string"
              || !/^[a-f0-9]{64}$/.test(entry.localVersionStamp))) {
            fail("Invalid retained excluded-file version", "invalid_snapshot");
          }
          if (entry.localPath !== undefined) {
            try {
              protocol.safeRelativePath(entry.localPath, "localPath");
              if (entry.code !== "local_changes_pending" || entry.localVersionStamp === undefined
                || entry.localPath.toLowerCase() !== entry.path.toLowerCase()) {
                fail("Invalid retained excluded-file path", "invalid_snapshot");
              }
            } catch { fail("Invalid retained excluded-file path", "invalid_snapshot"); }
          }
        }
      }
      if (parsed.pinnedFiles !== undefined) {
        if (!parsed.pinnedFiles || typeof parsed.pinnedFiles !== "object"
          || Array.isArray(parsed.pinnedFiles)
          || Object.keys(parsed.pinnedFiles).length > 65536) {
          fail("Invalid local pinned-file policy", "invalid_snapshot");
        }
        const pinnedPaths = new Set();
        for (const [key, item] of Object.entries(parsed.pinnedFiles)) {
          if (!item || typeof item !== "object" || Array.isArray(item)
            || Object.keys(item).sort().join(",") !== "fileId,objectId,path"
            || typeof item.objectId !== "string" || !item.objectId
            || typeof item.fileId !== "string" || !item.fileId
            || key !== pinnedKey(item.objectId)
            || typeof item.path !== "string") {
            fail("Invalid local pinned-file identity", "invalid_snapshot");
          }
          try { protocol.safeRelativePath(item.path, "pinnedPath"); }
          catch { fail("Invalid local pinned-file path", "invalid_snapshot"); }
          const portablePath = item.path.toLowerCase();
          if (pinnedPaths.has(portablePath)) fail("Ambiguous local pinned-file path", "invalid_snapshot");
          pinnedPaths.add(portablePath);
          const tracked = parsed.files[item.path];
          if (!tracked || tracked.deleted || tracked.directory
            || tracked.objectId !== item.objectId || tracked.fileId !== item.fileId) {
            fail("Pinned-file identity differs from the local snapshot", "invalid_snapshot");
          }
        }
      }
      for (const [objectId, item] of Object.entries(parsed.remoteOnly)) {
        if (!item || typeof item !== "object" || item.objectId !== objectId || typeof item.path !== "string") fail("Invalid remote-only sync entry", "invalid_snapshot");
        try {
          protocol.safeRelativePath(item.path, "path");
          if (item.sourcePath) protocol.safeRelativePath(item.sourcePath, "sourcePath");
        } catch { fail("Invalid remote-only sync path", "invalid_snapshot"); }
        if (!["excluded", "evicted"].includes(item.reason) || typeof item.deleted !== "boolean") fail("Invalid remote-only sync entry", "invalid_snapshot");
      }
      this.snapshot = parsed;
      this.snapshotDiskRevision = snapshotStats;
    }
    // A crash between a per-object durable PREPARE and the final full
    // checkpoint must be recovered BEFORE local reconciliation or outbound
    // sync. Replay never unlinks anything or authorizes a remote operation.
    this.evictionLedgerHead = null;
    if (this.requireNativeRootRecovery && this.snapshot.evictionLedgerRequired) {
      denyLegacyNativeRootReplay();
    }
    // Run the module-captured implementation, never a caller-replaced
    // instance or prototype hook which could silently disarm required-v2.
    await replayEvictionLedgerBuiltIn.call(this);
    this.opened = true;
    return this;
  }

  async replayEvictionLedger() {
    if (this.requireNativeRootRecovery && this.snapshot.evictionLedgerRequired) {
      // The only currently available RootSession contract rejects activation.
      // Do not read legacy path-based staging/ledger trees, clear the required
      // marker, emit operations, or accept a caller-supplied fake native object.
      denyLegacyNativeRootReplay();
    }
    const { entries, head } = await readEvictionLedger(this.rootDir,
      this.snapshot.evictionLedgerRequired ? this.snapshot.evictionLedgerEpoch : null);
    if (this.requireNativeRootRecovery && entries.size) {
      // Even if a future native backend can be opened, legacy JS path replay
      // must never be selected for an unfinished ledger transaction.
      denyLegacyNativeRootReplay();
    }
    // A normal v1 snapshot or an already-compacted v2 checkpoint has no
    // active eviction to replay. Do not inspect accumulated .rootark-trash
    // here: its legitimate contents can exceed the strict genesis scan cap,
    // and its staged head is only authoritative while a v2 snapshot explicitly
    // requires replay (or an active ledger must be reconciled). A subsequent
    // migration still validates the staged genesis before any PREPARE.
    if (!this.snapshot.evictionLedgerRequired && !entries.size) {
      if (!head) return;
      // A successfully recovered zero-PREPARE epoch may retain head.json
      // after its full durable checkpoint. No cached file was moved by it;
      // a later ordinary restart must not scan unrelated retained trash.
      if (head.sequence === 0 && head.digest === EVICTION_LEDGER_ZERO) {
        if (this.snapshot.version === EVICTION_LEDGER_SNAPSHOT_VERSION
          && head.epoch !== this.snapshot.evictionLedgerEpoch) {
          fail("Inactive eviction genesis epoch differs from durable checkpoint", "invalid_snapshot");
        }
        return;
      }
    }
    const staged = await stagedEvictionGenesis(this.rootDir);
    if (this.snapshot.evictionLedgerRequired && !head) {
      // A crash after the v2 snapshot but before promoting the genesis can
      // leave the only durable head in v1's already-internal trash namespace.
      // No PREPARE is allowed before promotion. Still demand full physical
      // proof, since a forged staged genesis cannot attest to lost files.
      if (!staged || staged.head.epoch !== this.snapshot.evictionLedgerEpoch) {
        fail("Required active eviction ledger is missing", "invalid_snapshot");
      }
      await this.recoverUnstartedEvictionLedger(staged);
      return;
    }
    if (head && !entries.size) {
      if (staged) fail("Conflicting staged and active eviction genesis", "invalid_snapshot");
      if (this.snapshot.evictionLedgerRequired) {
        if (head.epoch !== this.snapshot.evictionLedgerEpoch
          || head.sequence !== 0 || head.digest !== EVICTION_LEDGER_ZERO) {
          fail("Eviction genesis is not anchored to required snapshot", "invalid_snapshot");
        }
        // An empty genesis alone could have been fabricated after losing a
        // post-PREPARE ledger. Require all original plaintext cache files to
        // be present and clean before disarming its required marker.
        await this.recoverUnstartedEvictionLedger();
      }
      return;
    }
    if (entries.size && (this.snapshot.version !== EVICTION_LEDGER_SNAPSHOT_VERSION
      || head.epoch !== this.snapshot.evictionLedgerEpoch || staged)) {
      fail("Eviction journal requires a matching v2 snapshot", "invalid_snapshot");
    }
    if (!entries.size) return;
    if (this.snapshot.version !== EVICTION_LEDGER_SNAPSHOT_VERSION) {
      fail("Eviction overlay requires durable snapshot version fence", "invalid_snapshot");
    }
    const recovered = JSON.parse(JSON.stringify(this.snapshot));
    const directoryCache = new Map();
    for (const row of entries.values()) {
      const item = row.prepare.item;
      const tracked = Object.hasOwn(recovered.files, item.path)
        ? recovered.files[item.path] : null;
      const marker = Object.hasOwn(recovered.remoteOnly, item.objectId)
        ? recovered.remoteOnly[item.objectId] : null;
      if (!tracked && (!marker
        || protocol.canonicalJson(marker) !== protocol.canonicalJson(item.record))) {
        fail("Eviction journal has neither its tracked file nor a committed marker", "invalid_snapshot");
      }
      if (tracked && (tracked.deleted || tracked.directory || tracked.objectId !== item.objectId
        || tracked.fileId !== item.fileId || tracked.hash !== item.hash)) {
        fail("Eviction journal no longer matches its tracked identity", "invalid_snapshot");
      }
      const physical = await uniqueExcludedPhysicalPath(this.rootDir, item.path, directoryCache);
      if (physical === null) {
        if (recovered.pinnedFiles?.[pinnedKey(item.objectId)]?.fileId === item.fileId) {
          fail("Pinned file cannot be replay-evicted", "invalid_snapshot");
        }
        if (tracked) {
          // A PREPARE is local intent, never proof that the remote copy still
          // exists. Re-fetch its exact previously authenticated envelope and
          // verify the owner signature/current revocation policy and AEAD
          // plaintext hash before trusting a missing local cache file.
          let remote;
          try {
            const response = await this.adapter.list(item.objectId);
            const records = Array.isArray(response) ? response
              : Array.isArray(response?.objects) ? response.objects : response ? [response] : [];
            if (records.length !== 1) throw new Error("Missing exact remote eviction witness");
            remote = protocol.validateStoredOperation(records[0]);
            if (remote.objectId !== item.objectId || remote.fileId !== item.fileId
              || remote.versionId !== item.record.versionId
              || remote.metadata.path !== item.path
              || remote.tombstone || remote.operation === "delete"
              || signedEnvelopeDigest(remote) !== item.remoteDigest
              || protocol.canonicalJson(remote.revision) !== protocol.canonicalJson(item.record.revision)) {
              throw new Error("Remote eviction witness no longer matches PREPARE");
            }
            await this.verifyIncomingOperation(remote, { preObserve: false });
            const key = await this.keyFor(remote);
            const plaintext = protocol.decryptPayload(remote, key);
            const content = remote.operation === "move"
              ? protocol.decodeMovePayload(plaintext, key) || plaintext : plaintext;
            if (crypto.createHash("sha256").update(content).digest("hex") !== item.hash) {
              throw new Error("Remote content no longer matches evicted cache");
            }
          } catch {
            fail("Missing or unauthenticated remote eviction replay witness", "invalid_snapshot");
          }
        }
        // JSON object indexes may legally contain names like "__proto__";
        // assigning through [] would mutate the prototype rather than store
        // a durable own remote-only entry on those names.
        Object.defineProperty(recovered.remoteOnly, item.objectId, {
          value: item.record, enumerable: true, writable: true, configurable: true,
        });
        if (tracked) delete recovered.files[item.path];
        if (recovered.pendingEvictions) delete recovered.pendingEvictions[item.objectId];
      } else if (tracked) {
        // PREPARE alone is not a deletion receipt. An existing local file
        // could contain new dirty bytes; preserve it and arrange a fresh full
        // signed verification once the engine resumes, never unlink on replay.
        recovered.pendingEvictions = recovered.pendingEvictions || {};
        if (!Object.hasOwn(recovered.pendingEvictions, item.objectId)) {
          Object.defineProperty(recovered.pendingEvictions, item.objectId, {
            value: { path: item.path, code: "sync_operation_pending", attempts: 0 },
            enumerable: true, writable: true, configurable: true,
          });
        }
      } else {
        // A stale old journal record must not suppress an unrelated new file
        // whose local identity was never part of this eviction.
        fail("Untracked file occupies a recorded eviction path", "invalid_snapshot");
      }
    }
    if (recovered.pendingEvictions && !Object.keys(recovered.pendingEvictions).length) {
      delete recovered.pendingEvictions;
    }
    // Every committed eviction now has a durable remote-only marker, and
    // every still-present local file retains its tracked identity/watch.
    // Retire the guard in that same full durable checkpoint, before cleanup.
    recovered.evictionLedgerRequired = false;
    const previous = this.snapshot;
    this.snapshot = recovered;
    try { await this.persistSnapshot(); }
    catch (error) { this.snapshot = previous; throw error; }
    await clearEvictionLedger(this.rootDir, this.snapshot.evictionLedgerEpoch);
  }

  async recoverUnstartedEvictionLedger(staged = null) {
    if (this.requireNativeRootRecovery) denyLegacyNativeRootReplay();
    // Called under the cross-process exclusive root lock, only when required
    // is true and the anchored genesis exists without any PREPARE records.
    // Repeated full-file verification is intentional: this exceptional path
    // must not use a metadata-only stamp as proof of clean retained bytes.
    const assertAllTrackedBytesPresent = async () => {
      try {
        const live = Object.entries(this.snapshot.files).filter(([, item]) => !item.deleted);
        if (!live.some(([, item]) => !item.directory)) {
          fail("Empty active eviction recovery has no tracked cache files", "invalid_snapshot");
        }
        const names = await fsp.readdir(this.rootDir);
        if (names.length > 16384 || names.some((name) =>
          (name.toLowerCase() === EVICTION_LEDGER_DIR && name !== EVICTION_LEDGER_DIR)
          || name.toLowerCase().startsWith(EVICTION_LEDGER_ARCHIVE))) {
          fail("An ambiguous or archived eviction ledger remains", "invalid_snapshot");
        }
        // The regular sync scanner obeys the *current* mutable selection and
        // exclusion policy. A restart with the same excluded path as before
        // the crash would hide its intact tracked bytes and strand required
        // genesis forever. Recovery must inspect physical entries regardless
        // of that policy, without silently ignoring unknown names or links.
        const scanned = await this.scanPhysicalCacheForEvictionRecovery();
        const trackedKeys = new Set();
        const physicalCache = new Map();
        const emptyHash = crypto.createHash("sha256").update(Buffer.alloc(0)).digest("hex");
        for (const [relative, prior] of live) {
          protocol.safeRelativePath(relative, "path");
          const folded = relative.toLowerCase();
          if (trackedKeys.has(folded) || !EVICTION_LEDGER_HASH.test(prior.hash)) {
            fail("Ambiguous or unhashable tracked cache file", "invalid_snapshot");
          }
          trackedKeys.add(folded);
          // Reject case-only aliases even on POSIX: reconcileLocal could
          // otherwise DELETE the old tracked spelling and CREATE the alias.
          const physical = await uniqueExcludedPhysicalPath(this.rootDir, relative, physicalCache);
          if (physical !== relative) fail("Tracked cache path is not physically intact", "invalid_snapshot");
          const target = await contained(this.rootDir, relative, false);
          const stats = await fsp.lstat(target, { bigint: true });
          if (prior.directory) {
            if (!stats.isDirectory() || stats.isSymbolicLink() || prior.hash !== emptyHash) {
              fail("Tracked cache directory is not intact", "invalid_snapshot");
            }
          } else {
            if (!stats.isFile() || stats.isSymbolicLink()) {
              fail("Tracked cache file is not intact", "invalid_snapshot");
            }
            const bytes = await readContainedFile(this.rootDir, relative, stats);
            if (crypto.createHash("sha256").update(bytes).digest("hex") !== prior.hash) {
              fail("Tracked cache bytes differ from the last durable snapshot", "invalid_snapshot");
            }
          }
          if (!Object.hasOwn(scanned, relative)
            || scanned[relative].directory !== Boolean(prior.directory)
            || scanned[relative].hash !== prior.hash) {
            fail("Tracked file is absent from the complete local scan", "invalid_snapshot");
          }
        }
        for (const relative of Object.keys(scanned)) {
          if (!Object.hasOwn(this.snapshot.files, relative)
            || this.snapshot.files[relative].deleted) {
            fail("Untracked local content prevents empty-ledger recovery", "invalid_snapshot");
          }
        }
      } catch {
        fail("Unproven physical state after required eviction ledger loss", "invalid_snapshot");
      }
    };
    await assertAllTrackedBytesPresent();
    const reread = async () => {
      const { entries, head } = await readEvictionLedger(this.rootDir, this.snapshot.evictionLedgerEpoch);
      const stagedNow = staged ? await stagedEvictionGenesis(this.rootDir) : null;
      if (entries.size || (staged ? (head || !stagedNow
        || stagedNow.file !== staged.file || stagedNow.head.epoch !== staged.head.epoch)
        : (!head || head.epoch !== this.snapshot.evictionLedgerEpoch
          || head.sequence !== 0 || head.digest !== EVICTION_LEDGER_ZERO))) {
        fail("Eviction genesis changed during physical proof", "invalid_snapshot");
      }
    };
    await reread();
    await assertAllTrackedBytesPresent();
    await reread();
    this.snapshot.evictionLedgerRequired = false;
    try { await this.persistSnapshot(); }
    catch (error) {
      this.snapshot.evictionLedgerRequired = true;
      throw error;
    }
  }

  async persistSnapshot() {
    await durableJson(this.snapshotPath, this.snapshot);
    this.snapshotDiskRevision = await fsp.lstat(this.snapshotPath, { bigint: true });
  }

  async keyFor(operation) {
    if (await this.authorize(operation) !== true) fail("Sync authorization rejected", "authorization_rejected");
    if (operation.keyEpoch !== this.keyEpoch && this.keyEpoch) fail("Stale sync key epoch", "stale_key_epoch");
    const key = await this.fileKeyResolver(operation);
    if (!key) fail("No authorized file key is available", "key_unavailable");
    return key;
  }

  async verifyIncomingOperation(operation, { preObserve = true } = {}) {
    // Strict mode is local policy, never a request-controlled proof opt-in.
    // Historical expiry is allowed only for a structurally bound SIGNED
    // record; the trusted verifier below must still check key and revocation.
    if (this.requireAuthorization) {
      if (!operation || !Object.hasOwn(operation, "authorization")) {
        fail("Remote sync device authorization is required", "remote_authorization_rejected");
      }
      try { protocol.validateStoredOperation(operation); }
      catch { fail("Remote sync device authorization is invalid", "remote_authorization_rejected"); }
    }
    const digest = signedEnvelopeDigest(operation);
    // A valid signer can sign two different envelopes using one operation ID.
    // Reject a conflicting identity BEFORE mutating the filesystem or snapshot.
    this.journal.assertCompatibleAdmission(operation.operationId, digest);
    // A remote LIST/materialization can race with an unsent signed local
    // operation. `markSeen` removes pending by ID: require the FULL exact
    // signed envelope match so an incoming same-ID variant cannot erase it.
    for (const queued of await this.journal.recover()) {
      if (queued.operationId !== operation.operationId) continue;
      let queuedDigest;
      try {
        queuedDigest = signedEnvelopeDigest(protocol.validateStoredOperation(queued));
      } catch {
        fail("Conflicting local sync admission evidence", "remote_authorization_rejected");
      }
      if (queuedDigest !== digest) {
        fail("Conflicting local sync admission evidence", "remote_authorization_rejected");
      }
    }
    if (!this.verifyIncoming) {
      if (this.requireAuthorization) fail("Remote sync authorization verifier is required", "remote_authorization_rejected");
      return null;
    }
    // Capture freshness before asynchronous verification and I/O. Successful
    // authentication can cross the expiry deadline before the journal fsync.
    const candidate = this.localAdmissionDigestIfFresh(operation);
    const locallyAdmitted = this.journal.hasLocalAdmission(operation.operationId, digest);
    if (await this.verifyIncoming(operation, { locallyAdmitted }) !== true) {
      fail("Remote sync authorization rejected", "remote_authorization_rejected");
    }
    // A well-signed remote envelope must not consume finite durable journal
    // capacity if this client does not authorize its operation at all.
    if (await this.authorize(operation) !== true) {
      fail("Sync authorization rejected", "authorization_rejected");
    }
    if (signedEnvelopeDigest(operation) !== digest) {
      fail("Remote sync envelope changed during authorization", "remote_authorization_rejected");
    }
    this.journal.assertCompatibleAdmission(operation.operationId, digest);
    if (candidate && preObserve) await this.journal.observeAdmission(operation.operationId, candidate);
    // The exact historical digest already pinned locally can complete its
    // observed->admitted transition after a crash, even after expiry. Never
    // derive this from operation-ID-only legacy `seen` entries.
    return candidate || (locallyAdmitted ? digest : null);
  }
  localAdmissionDigestIfFresh(operation) {
    return this.requireAuthorization && this.verifyIncoming && operation.authorization
      && Number.isSafeInteger(operation.authorization.expiresAt)
      && operation.authorization.expiresAt > Date.now()
      ? signedEnvelopeDigest(operation) : null;
  }

  isInScope(relativePath) {
    return this.selectedPaths === null || this.selectedPaths.some((selected) => pathWithin(relativePath, selected));
  }

  isExcluded(relativePath) {
    // Exclusion is a DENY policy, so apply the portable Windows case-fold
    // comparison on POSIX too. Otherwise an excluded "private" silently
    // permits "PRIVATE/secret.txt" to be uploaded or hydrated on Linux.
    // Keep selectedPaths and object-identity comparisons platform-specific:
    // those positive decisions must not gain access through a case alias.
    const portablePath = relativePath.toLowerCase();
    return this.excludedPaths.some((excluded) => {
      const portableExcluded = excluded.toLowerCase();
      return portablePath === portableExcluded || portablePath.startsWith(`${portableExcluded}/`);
    });
  }

  isSelected(relativePath) {
    return this.isInScope(relativePath) && !this.isExcluded(relativePath);
  }

  needsTraversal(relativePath) {
    if (this.isExcluded(relativePath)) return false;
    return this.selectedPaths === null || this.isSelected(relativePath)
      || this.selectedPaths.some((selected) => pathWithin(selected, relativePath));
  }

  operationIsSelected(operation) {
    const paths = [operation.metadata?.path, operation.metadata?.sourcePath].filter(Boolean);
    return paths.length > 0 && paths.every((relativePath) => this.isSelected(relativePath));
  }

  operationDestinationIsSelected(operation) {
    return typeof operation.metadata?.path === "string" && this.isSelected(operation.metadata.path);
  }

  async browseRemoteInventory({ limit = 64, cursor = null } = {}) {
    if (typeof this.adapter.listInventory !== "function") {
      fail("Metadata inventory is not supported by this sync adapter", "inventory_unavailable");
    }
    // Browsing is read-only and advisory. No remote-only pins, journal entries
    // or local files may be created from metadata without fetching and
    // independently verifying the complete signed envelope.
    const page = await this.adapter.listInventory({ limit, cursor });
    if (!page || !Array.isArray(page.objects)) fail("Invalid metadata inventory page", "invalid_inventory");
    return {
      ...page, advisory: true,
      objects: page.objects.map((record) => ({
        ...record, selectedOnDevice: this.operationDestinationIsSelected(record),
      })),
    };
  }

  async scanOnDemandInventory(requestedPath = null) {
    let cursor = null;
    let available = 0;
    let matching = null;
    const seenCursors = new Set();
    for (let pageNumber = 0; pageNumber < 1024; pageNumber += 1) {
      const page = await this.browseRemoteInventory({ limit: 64, cursor });
      if (page.objects.length > 64 || (page.objects.length === 0 && page.nextCursor !== null)) {
        fail("Invalid metadata inventory page", "invalid_inventory");
      }
      for (const entry of page.objects) {
        const remotePath = protocol.safeRelativePath(entry.metadata?.path, "path");
        if (!this.isSelected(remotePath)) continue;
        if (!entry.tombstone && entry.metadata?.contentType !== "inode/directory") available += 1;
        if (requestedPath !== null && !entry.tombstone && pathsEqual(remotePath, requestedPath)) {
          if (matching) fail("More than one remote object matches this path", "remote_object_ambiguous");
          matching = entry;
        }
      }
      if (page.nextCursor === null) return { available, matching };
      if (typeof page.nextCursor !== "string" || !page.nextCursor
        || seenCursors.has(page.nextCursor)) fail("Repeated or invalid metadata cursor", "invalid_inventory");
      seenCursors.add(page.nextCursor);
      cursor = page.nextCursor;
    }
    fail("Metadata inventory exceeds the supported page bound", "invalid_inventory");
  }

  rememberRemoteOnly(operation, reason, options = {}) {
    const pathName = operation.metadata?.path;
    if (!pathName) return;
    const prior = this.snapshot.remoteOnly[operation.objectId] || {};
    this.snapshot.remoteOnly[operation.objectId] = {
      objectId: operation.objectId,
      fileId: operation.fileId,
      versionId: operation.versionId,
      revision: operation.revision,
      path: pathName,
      ...(operation.metadata.sourcePath ? { sourcePath: operation.metadata.sourcePath } : {}),
      directory: operation.metadata.contentType === "inode/directory" || options.directory === true || prior.directory === true,
      deleted: Boolean(operation.tombstone || operation.operation === "delete"),
      reason: prior.reason === "evicted" ? "evicted" : reason,
      ...(prior.hash ? { hash: prior.hash } : {}),
    };
  }

  preflightOutOfScopeMove(operation) {
    const tombstone = Boolean(operation.tombstone || operation.operation === "delete");
    const directoryMove = operation.operation === "update" && operation.metadata?.contentType === "inode/directory";
    if ((operation.operation !== "move" && !directoryMove && !tombstone)
      || typeof operation.metadata?.path !== "string" || this.isSelected(operation.metadata.path)) return null;
    if (!tombstone && !directoryMove && !operation.metadata?.sourcePath) return null;

    let sourcePath;
    if (tombstone) {
      sourcePath = activeIdentityPath(this.snapshot.files, operation, operation.metadata.path)
        || activeFileIdentityPath(this.snapshot.files, operation, operation.metadata.path);
    } else if (directoryMove) {
      sourcePath = activeIdentityPath(this.snapshot.files, operation, operation.metadata.path);
    } else {
      sourcePath = activeFileIdentityPath(this.snapshot.files, operation, operation.metadata.path)
        || (this.snapshot.files[operation.metadata.sourcePath]?.objectId === operation.objectId
        && this.snapshot.files[operation.metadata.sourcePath]?.fileId === operation.fileId
        && !this.snapshot.files[operation.metadata.sourcePath]?.deleted
        && !this.snapshot.files[operation.metadata.sourcePath]?.directory
        ? operation.metadata.sourcePath : null);
    }
    if (!sourcePath || !this.isSelected(sourcePath)) return null;

    const prior = this.snapshot.files[sourcePath];
    const directoryRecord = directoryMove || (tombstone && Boolean(prior?.directory));
    if (!prior || prior.deleted || Boolean(prior.directory) !== directoryRecord
      || prior.objectId !== operation.objectId || prior.fileId !== operation.fileId) return null;

    // Reconciliation can stage/rename the origin and then discard its tracked
    // snapshot entry. A signed MOVE/DELETE outside selectedPaths must never
    // sidestep the local pin policy merely because _apply() is not called.
    // Fold case on every OS so a POSIX path remains safe after Windows replay.
    const originKey = sourcePath.toLowerCase();
    if (Object.values(this.snapshot.pinnedFiles || {}).some((pin) => {
      const pinnedPath = pin.path.toLowerCase();
      return pinnedPath === originKey || pinnedPath.startsWith(`${originKey}/`);
    })) {
      fail("Pinned local origin cannot be reconciled outside selected paths", "file_pinned");
    }

    return { sourcePath, prior, tombstone, directoryRecord };
  }

  async reconcileOutOfScopeMove(operation, summary, options = {}) {
    // The same side-effect-free check runs BEFORE signature pre-observation.
    // Keep it here too for direct callers and changes during verification.
    const source = this.preflightOutOfScopeMove(operation);
    // No pull/reconciliation entry point may separately advance a member of
    // a locally durable signed DELETE+MOVE remote transaction. A partial LIST
    // or out-of-scope sweep is not a two-envelope atomic admission receipt.
    if (Object.keys(this.journal.atomicSignedGroups?.() || {}).length) {
      fail("Cannot reconcile remote changes while an atomic WebDAV batch is pending",
        "sync_atomic_batch_indeterminate");
    }
    if (!source) return false;
    const { sourcePath, prior, tombstone, directoryRecord } = source;

    const pending = (await this.journal.recover()).filter((item) => item.protocolVersion && item.objectId === operation.objectId);
    const target = await contained(this.rootDir, sourcePath, true);
    const sourceExists = await exists(target);
    let changedLocally = false;
    if (sourceExists) {
      const stats = await fsp.lstat(target, { bigint: true });
      if (stats.isSymbolicLink() || (directoryRecord ? !stats.isDirectory() : !stats.isFile())) {
        fail("Tracked sync source has an unexpected type", "unsafe_path");
      }
      if (directoryRecord) {
        const currentFiles = await this.scanFiles();
        const trackedEntries = Object.entries(this.snapshot.files).filter(([relativePath, item]) => !item.deleted
          && pathWithin(relativePath, sourcePath));
        const trackedKeys = new Set(trackedEntries.map(([relativePath]) => pathKey(relativePath)));
        for (const [relativePath, item] of trackedEntries) {
          const currentPath = canonicalMapPath(relativePath, currentFiles);
          const current = currentFiles[currentPath];
          if (!current || current.hash !== item.hash || Boolean(current.directory) !== Boolean(item.directory)) changedLocally = true;
        }
        if (Object.keys(currentFiles).some((relativePath) => pathWithin(relativePath, sourcePath) && !trackedKeys.has(pathKey(relativePath)))) {
          changedLocally = true;
        }
      } else {
        const bytes = await readContainedFile(this.rootDir, sourcePath, stats);
        changedLocally = crypto.createHash("sha256").update(bytes).digest("hex") !== prior.hash;
      }
    }

    const hasLocalConflict = changedLocally || pending.length > 0;
    if (hasLocalConflict) {
      for (const item of pending) {
        if (item.protocolVersion && !(options.preservedOperationIds || []).includes(item.operationId)) await this.recoverConflict(item, summary);
      }
      if (sourceExists && !directoryRecord) {
        const conflictRoot = path.join(this.rootDir, ".rootark-conflicts");
        await fsp.mkdir(conflictRoot, { recursive: true });
        await containedAbsolute(this.rootDir, conflictRoot, false);
        const operationKey = crypto.createHash("sha256").update(operation.operationId).digest("hex").slice(0, 16);
        const conflictPath = path.join(conflictRoot, `${operationKey}-${crypto.randomUUID()}.local.conflict`);
        await containedAbsolute(this.rootDir, conflictPath, true);
        await fsp.rename(target, conflictPath);
      }
      if (!directoryRecord && !options.preservedOperationIds?.includes(operation.operationId)) await this.recoverConflict(operation, summary);
      summary.conflicts ||= [];
      if (!options.conflictAlreadyRecorded && !summary.conflicts.some((conflict) => conflict.operationId === operation.operationId)) {
        summary.conflicts.push({ operationId: operation.operationId, policy: "preserve-local-and-remote", reason: tombstone
          ? "remote-delete-outside-selected-scope" : "remote-move-outside-selected-scope" });
      }
    } else if (sourceExists) {
      if (!directoryRecord) {
        await this.stageExisting(target);
      } else if ((await fsp.readdir(target)).length === 0) {
        const hasActiveDescendant = Object.entries(this.snapshot.files).some(([relativePath, item]) => relativePath !== sourcePath
          && !item.deleted && pathWithin(relativePath, sourcePath));
        if (!hasActiveDescendant) await this.stageExisting(target);
      }
    }

    for (const relativePath of Object.keys(this.snapshot.files)) {
      if (pathsEqual(relativePath, sourcePath)) delete this.snapshot.files[relativePath];
    }
    this.rememberRemoteOnly(operation, "excluded", { directory: directoryRecord });
    for (const item of pending) await this.journal.markSeen(item.operationId);
    await this.pruneEmptyUntrackedParents(path.dirname(target));
    await this.persistSnapshot();
    return true;
  }

  async buildOperation(input) {
    const key = input.fileKey || await this.fileKeyResolver(input);
    let operationInput = input;
    if (input.operation === "move") {
      let movePlaintext = input.plaintext;
      if (movePlaintext === undefined) {
        const target = await contained(this.rootDir, input.metadata?.path, false);
        const stats = await fsp.lstat(target, { bigint: true });
        if (stats.isFile()) movePlaintext = await readContainedFile(this.rootDir, input.metadata?.path, stats);
        else if (!stats.isDirectory()) fail("Sync move source must be a regular file or directory", "unsafe_path");
      }
      if (movePlaintext !== undefined) operationInput = { ...input, plaintext: protocol.encodeMovePayload(movePlaintext, key) };
    }
    const operation = protocol.createOperation({
      ...operationInput,
      deviceId: input.deviceId || this.deviceId,
      keyEpoch: input.keyEpoch || this.keyEpoch,
      compartmentId: input.compartmentId || this.compartmentId,
      operationId: input.operationId || crypto.randomUUID(),
      fileKey: key,
    });
    await this.assertOutgoingAuthorized(operation);
    if (this.authorizationFactory) operation.authorization = await this.authorizationFactory(operation);
    else if (this.requireAuthorization) fail("Device authorization is required", "authorization_required");
    // Signing can await an external key provider. Revocation after the initial
    // check must stop the signed operation before it reaches the journal.
    await this.assertOutgoingAuthorized(operation);
    return operation;
  }

  async assertOutgoingAuthorized(operation, authorizedAction = null) {
    if (this.requireNativeRootRecovery && (operation.operation === "delete" || operation.tombstone)) {
      denyUntrustedNativeSignedDelete();
    }
    let locallyAuthorized;
    try { locallyAuthorized = await this.authorizeOutgoing(operation); } catch {
      fail("Local sync authorization rejected", "authorization_rejected");
    }
    if (locallyAuthorized !== true) {
      fail("Local sync authorization rejected", "authorization_rejected");
    }
    if (this.requireCurrentOutgoingAuthorization && operation.deviceId !== this.deviceId) {
      fail("Local sync device authorization rejected", "authorization_rejected");
    }
    if (this.currentDeviceAuthorization) {
      let currentDecision;
      try { currentDecision = this.currentDeviceAuthorization(operation); } catch {
        fail("Current sync device authorization rejected", "authorization_rejected");
      }
      if (this.requireCurrentOutgoingAuthorization) {
        // Strict mode must use a synchronous, operator-trusted current policy.
        // Awaiting even a resolved Promise would let a queued microtask revoke
        // the device between reading true and beginning the HTTP PUT.
        let isAsyncDecision;
        try { isAsyncDecision = Boolean(currentDecision && typeof currentDecision.then === "function"); } catch {
          fail("Current sync device authorization rejected", "authorization_rejected");
        }
        if (isAsyncDecision) {
          Promise.resolve(currentDecision).catch(() => {});
          fail("Synchronous current device authorization is required", "authorization_required");
        }
        if (currentDecision !== true) {
          fail("Current sync device authorization rejected", "authorization_rejected");
        }
      } else if (await currentDecision !== true) {
        // Backward compatibility for explicitly non-strict integrations.
        fail("Current sync device authorization rejected", "authorization_rejected");
      }
    }
    // Local journals and translation callbacks are NOT an authorization
    // authority. Enforce the mandatory signed-envelope boundary at every
    // action (journal enqueue or HTTP dispatch), not just during creation.
    // Build-time pre-sign current-device checks intentionally have no action.
    if (authorizedAction && this.requireAuthorization) {
      try { protocol.validateFreshSignedOperation(operation); }
      catch { fail("Fresh outgoing sync device authorization is required",
        "authorization_required"); }
    }
    // No await after the strict synchronous policy + signed-envelope checks.
    // HTTP dispatch runs here, before a queued revocation microtask can run.
    if (authorizedAction) return authorizedAction();
  }

  async enqueueChange(input) {
    return this.withMutationLock(() => this._enqueueChange(input));
  }

  async _enqueueChange(input) {
    if (!this.opened) await openEngineBuiltIn.call(this);
    const remoteOnly = this.snapshot.remoteOnly[input.objectId];
    if (remoteOnly?.reason === "evicted") fail("Materialize a remote-only file before enqueuing changes", "remote_only_object");
    const key = input.fileKey || await this.fileKeyResolver(input);
    const operation = protocol.validateOperation(await this.buildOperation({ ...input, fileKey: key }));
    await this.assertOutgoingAuthorized(operation, () => this.journal.enqueue(operation));
    let hash;
    if (operation.operation === "move") {
      const plaintext = protocol.decodeMovePayload(protocol.decryptPayload(operation, key), key);
      if (plaintext !== null) hash = crypto.createHash("sha256").update(plaintext).digest("hex");
    }
    this.rememberOperation(operation, hash);
    await this.persistSnapshot();
    return operation;
  }

  async translateWebDavMutation(event) {
    if (!this.opened) await this.open();
    if (!event || typeof event.operationId !== "string" || !event.operationId) fail("WebDAV mutation id is required", "invalid_webdav_mutation");
    const kind = String(event.kind || "");
    if (!["put", "move", "delete"].includes(kind)) fail("Unsupported WebDAV mutation", "invalid_webdav_mutation");
    if (this.requireNativeRootRecovery && (kind === "delete" || kind === "move")) {
      // MOVE may also generate a destination tombstone in an overwrite pair.
      denyUntrustedNativeSignedDelete();
    }
    const operationPrefixes = [`webdav-${event.operationId}-`,
      `webdavsolo-${event.operationId}-`];
    const pendingForEvent = (await this.journal.recover()).filter((operation) =>
      typeof operation.operationId === "string"
        && operationPrefixes.some((prefix) => operation.operationId.startsWith(prefix)));
    if (pendingForEvent.length) return pendingForEvent;
    if (this.journal.state?.seen?.some((operationId) => typeof operationId === "string"
      && operationPrefixes.some((prefix) => operationId.startsWith(prefix)))) return [];
    const requestedSourcePath = normalizeWebDavPath(event.source || event.path);
    const requestedDestinationPath = normalizeWebDavPath(event.destination || event.path || event.source);
    const current = await this.scanFiles();
    const snapshotFiles = { ...this.snapshot.files };
    for (const pending of await this.journal.recover()) {
      if (!pending.protocolVersion || pending.journalType) continue;
      const relativePath = pending.metadata?.path;
      if (!relativePath) continue;
      const source = pending.operation === "move" ? pending.metadata.sourcePath
        : (pending.operation === "update" && pending.metadata.contentType === "inode/directory"
          ? activeIdentityPath(snapshotFiles, pending, relativePath) : null);
      const prior = source
        ? snapshotFiles[source] || (source === relativePath ? snapshotFiles[relativePath] : null) || {}
        : snapshotFiles[relativePath] || {};
      if (source && source !== relativePath) delete snapshotFiles[source];
      snapshotFiles[relativePath] = {
        ...prior,
        objectId: pending.objectId,
        fileId: pending.fileId,
        versionId: pending.versionId,
        revision: pending.revision,
        deleted: Boolean(pending.tombstone || pending.operation === "delete"),
        directory: pending.metadata.contentType === "inode/directory"
          || ((pending.operation === "move" || pending.operation === "delete") && Boolean(prior.directory)),
      };
    }
    const sourcePath = canonicalMapPath(requestedSourcePath, snapshotFiles, current);
    const destinationPath = canonicalMapPath(requestedDestinationPath, current, snapshotFiles);
    const operations = [];
    const mappedSourcePaths = new Set();
    const stableOperationId = (verbAndPath) => {
      // Standalone DELETE has distinct Ed25519-bound ID namespace. A legacy
      // `webdav-` DELETE alone is ambiguous with a displaced-target tombstone
      // from an atomic overwrite and must never be pushed by itself after a
      // local journal manifest was deleted/corrupted. The same applies to an
      // orphaned atomic MOVE if its DELETE and group manifest were stripped.
      const soloDelete = kind === "delete" && verbAndPath.startsWith("delete:");
      const soloMove = kind === "move" && !event.previousDestinationIdentity
        && verbAndPath.startsWith("move:");
      return `${soloDelete || soloMove ? "webdavsolo" : "webdav"}-${event.operationId}-${crypto.createHash("sha256")
        .update(verbAndPath).digest("hex").slice(0, 24)}`;
    };
    const identityFor = (relativePath, prior) => {
      const deletedPrior = snapshotFiles[relativePath]?.deleted ? snapshotFiles[relativePath] : null;
      const identitySeed = deletedPrior ? crypto.randomUUID().replace(/-/g, "")
        : crypto.createHash("sha256").update(relativePath).digest("hex").slice(0, 32);
      return {
        objectId: prior?.objectId || `object-${identitySeed}`,
        fileId: prior?.fileId || `file-${identitySeed}`,
      };
    };
    const buildForPath = async ({ operation, relativePath, source, prior, content, directory }) => {
      const identity = identityFor(relativePath, prior);
      const fileContext = { ...prior, ...identity, path: source || relativePath, keyEpoch: this.keyEpoch };
      const fileKey = await this.fileKeyResolver(fileContext);
      if (!fileKey) fail("No authorized file key is available", "key_unavailable");
      const baseRevision = prior?.revision || null;
      const revision = { counter: (baseRevision?.counter || 0) + 1, deviceId: this.deviceId };
      const metadata = operation === "delete"
        ? { path: relativePath }
        : operation === "move"
          ? { path: relativePath, sourcePath: source }
          : { path: relativePath, name: path.posix.basename(relativePath), size: content.length, ...(directory ? { contentType: "inode/directory" } : {}) };
      return protocol.validateOperation(await this.buildOperation({
        operation,
        objectId: identity.objectId,
        fileId: identity.fileId,
        versionId: crypto.randomUUID(),
        operationId: stableOperationId(`${operation}:${relativePath}`),
        baseRevision,
        revision,
        metadata,
        plaintext: operation === "delete" ? undefined : content,
        fileKey,
      }));
    };

    if (kind === "delete") {
      const deletedPaths = Object.entries(snapshotFiles)
        .filter(([relativePath, prior]) => pathWithin(relativePath, sourcePath) && !prior.deleted)
        .map(([relativePath, prior]) => ({ relativePath, prior }))
        .sort((left, right) => right.relativePath.split("/").length - left.relativePath.split("/").length);
      for (const { relativePath, prior } of deletedPaths) {
        operations.push(await buildForPath({ operation: "delete", relativePath, prior }));
      }
      return operations;
    }

    let destinationStats;
    if (kind === "move") {
      await contained(this.rootDir, sourcePath, true);
      const destinationTarget = await contained(this.rootDir, destinationPath, false);
      destinationStats = await fsp.lstat(destinationTarget);
      if (destinationStats.isDirectory()) {
        for (const [priorPath, prior] of Object.entries(snapshotFiles)) {
          if (!pathWithin(priorPath, sourcePath) || prior.deleted || !prior.directory) continue;
          const suffix = priorPath === sourcePath ? "" : priorPath.slice(sourcePath.length);
          const mappedPath = `${destinationPath}${suffix}`;
          if (current[mappedPath]) continue;
          const mappedTarget = await contained(this.rootDir, mappedPath, true);
          if (await exists(mappedTarget) && (await fsp.lstat(mappedTarget)).isDirectory()) current[mappedPath] = { size: 0, directory: true };
        }
      }
    }

    if (kind === "put" || destinationStats?.isFile()) {
      const relativePath = destinationPath;
      const file = current[relativePath];
      if (!file || file.directory) fail("WebDAV file mutation is missing its destination", "unsafe_path");
      const priorSource = kind === "move" ? snapshotFiles[sourcePath] : null;
      const priorDestination = snapshotFiles[relativePath];
      const sourceIsActive = priorSource && !priorSource.deleted;
      const destinationIsActive = priorDestination && !priorDestination.deleted;
      const content = await readContainedFile(this.rootDir, relativePath);
      if (sourceIsActive && destinationIsActive
        && (priorSource.objectId !== priorDestination.objectId || priorSource.fileId !== priorDestination.fileId)) {
        mappedSourcePaths.add(sourcePath);
        operations.push(await buildForPath({ operation: "delete", relativePath, prior: priorDestination }));
        operations.push(await buildForPath({ operation: "move", relativePath, source: sourcePath, prior: priorSource, content, directory: false }));
      } else {
        const prior = sourceIsActive ? priorSource : (destinationIsActive ? priorDestination : null);
        if (sourceIsActive && !priorSource.directory) mappedSourcePaths.add(sourcePath);
        const operation = kind === "move" && sourceIsActive && !priorSource.directory
          ? "move"
          : prior ? "update" : "create";
        operations.push(await buildForPath({ operation, relativePath, source: operation === "move" ? sourcePath : null, prior, content, directory: false }));
      }
    } else if (kind === "move" && destinationStats?.isDirectory()) {
      const destinationTypes = {};
      const walkTypes = async (relativePath) => {
        const target = await contained(this.rootDir, relativePath, false);
        const stats = await fsp.lstat(target);
        destinationTypes[relativePath] = stats.isDirectory();
        if (!stats.isDirectory()) return;
        for (const entry of await fsp.readdir(target, { withFileTypes: true })) {
          const childPath = `${relativePath}/${entry.name}`;
          try { protocol.safeRelativePath(childPath, "path"); } catch { continue; }
          await containedAbsolute(this.rootDir, path.join(target, entry.name), false);
          if (entry.isDirectory()) await walkTypes(childPath);
          else if (entry.isFile()) destinationTypes[childPath] = false;
        }
      };
      await walkTypes(destinationPath);
      const priorDescendantPaths = new Set();
      for (const [priorPath, prior] of Object.entries(snapshotFiles)) {
        if (!pathWithin(priorPath, destinationPath) || prior.deleted) continue;
        let ancestor = path.posix.dirname(priorPath);
        while (ancestor !== "." && pathWithin(ancestor, destinationPath)) {
          priorDescendantPaths.add(ancestor);
          if (ancestor === destinationPath) break;
          ancestor = path.posix.dirname(ancestor);
        }
      }
      for (const [relativePath, currentType] of Object.entries(destinationTypes)) {
        if (!pathWithin(relativePath, destinationPath)) continue;
        const prior = snapshotFiles[relativePath];
        const priorIsActive = prior && !prior.deleted;
        const priorHasActiveChildren = priorDescendantPaths.has(relativePath);
        if (!priorIsActive && !priorHasActiveChildren) continue;
        const priorType = Boolean(priorIsActive && prior.directory) || priorHasActiveChildren;
        if (priorType !== currentType) {
          throw Object.assign(new Error("Cannot overwrite a nested file with a collection or vice versa"), { statusCode: 409, code: "webdav_type_conflict" });
        }
      }

      const movedPaths = Object.keys(current).filter((relativePath) => relativePath.startsWith(`${destinationPath}/`)
        || (relativePath === destinationPath && current[relativePath].directory)).sort();
      const mappedDestinationPaths = new Set(movedPaths);
      const destinationDeletes = new Map();
      for (const [relativePath, prior] of Object.entries(snapshotFiles)) {
        if (pathWithin(relativePath, destinationPath) && !prior.deleted && !mappedDestinationPaths.has(relativePath)) {
          destinationDeletes.set(relativePath, prior);
        }
      }
      for (const relativePath of movedPaths) {
        if (!current[relativePath].directory) continue;
        const suffix = relativePath === destinationPath ? "" : relativePath.slice(destinationPath.length);
        const priorSource = snapshotFiles[`${sourcePath}${suffix}`];
        const priorDestination = snapshotFiles[relativePath];
        if (priorSource && !priorSource.deleted && priorSource.directory
          && priorDestination && !priorDestination.deleted
          && (priorDestination.objectId !== priorSource.objectId || priorDestination.fileId !== priorSource.fileId)) {
          destinationDeletes.set(relativePath, priorDestination);
        }
      }
      const orderedDestinationDeletes = [...destinationDeletes.entries()]
        .map(([relativePath, prior]) => ({ relativePath, prior }))
        .sort((left, right) => right.relativePath.split("/").length - left.relativePath.split("/").length || left.relativePath.localeCompare(right.relativePath));
      for (const { relativePath, prior } of orderedDestinationDeletes) {
        operations.push(await buildForPath({ operation: "delete", relativePath, prior }));
      }
      for (const relativePath of movedPaths) {
        const suffix = relativePath === destinationPath ? "" : relativePath.slice(destinationPath.length);
        const oldPath = `${sourcePath}${suffix}`;
        const file = current[relativePath];
        const priorSource = snapshotFiles[oldPath];
        const priorDestination = snapshotFiles[relativePath];
        const sourceIsActive = priorSource && !priorSource.deleted;
        const destinationIsActive = priorDestination && !priorDestination.deleted;
        if (sourceIsActive) mappedSourcePaths.add(oldPath);

        if (file.directory) {
          if (sourceIsActive && priorSource.directory) {
            operations.push(await buildForPath({ operation: "update", relativePath, prior: priorSource, content: Buffer.alloc(0), directory: true }));
          } else {
            if (sourceIsActive) operations.push(await buildForPath({ operation: "delete", relativePath: oldPath, prior: priorSource }));
            const directoryPrior = destinationIsActive ? priorDestination : null;
            operations.push(await buildForPath({ operation: directoryPrior ? "update" : "create", relativePath, prior: directoryPrior, content: Buffer.alloc(0), directory: true }));
          }
          continue;
        }

        const content = await readContainedFile(this.rootDir, relativePath);
        if (sourceIsActive && destinationIsActive
          && (priorSource.objectId !== priorDestination.objectId || priorSource.fileId !== priorDestination.fileId)) {
          operations.push(await buildForPath({ operation: "delete", relativePath, prior: priorDestination }));
          operations.push(await buildForPath({ operation: "move", relativePath, source: oldPath, prior: priorSource, content, directory: false }));
        } else {
          const prior = sourceIsActive && !priorSource.directory ? priorSource : (destinationIsActive && !priorDestination.directory ? priorDestination : null);
          const operation = sourceIsActive && !priorSource.directory ? "move" : (prior ? "update" : "create");
          operations.push(await buildForPath({ operation, relativePath, source: operation === "move" ? oldPath : null, prior, content, directory: false }));
        }
      }
      for (const [oldPath, prior] of Object.entries(snapshotFiles)) {
        if (!pathWithin(oldPath, sourcePath) || prior.deleted || mappedSourcePaths.has(oldPath)) continue;
        operations.push(await buildForPath({ operation: "delete", relativePath: oldPath, prior }));
      }
    } else {
      fail("WebDAV move destination is not a regular file or directory", "unsafe_path");
    }

    return operations;
  }

  async retryPush(operation) {
    let lastError;
    for (let attempt = 0; attempt < this.maxRetries; attempt += 1) {
      // The journal's prior authorization is not a live device grant. Check
      // again on EVERY attempt, after all queue/retry waits, before HTTP PUT.
      // An in-flight request still needs independent server-side revocation
      // fencing in the atomic PUT transaction.
      try { return await this.assertOutgoingAuthorized(operation, () => this.adapter.push(operation)); } catch (error) {
        lastError = error;
        if (error?.code === "authorization_rejected" || error?.code === "authorization_required") throw error;
        if (!transient(error) || attempt + 1 === this.maxRetries) throw error;
      }
    }
    throw lastError;
  }

  async recoverConflict(operation, summary) {
    if (operation.operation === "delete" || operation.tombstone) return;
    const key = await this.keyFor(operation);
    const decrypted = protocol.decryptPayload(operation, key);
    const plaintext = operation.operation === "move" ? (protocol.decodeMovePayload(decrypted, key) || decrypted) : decrypted;
    const conflictRoot = path.join(this.rootDir, ".rootark-conflicts");
    await fsp.mkdir(conflictRoot, { recursive: true });
    await containedAbsolute(this.rootDir, conflictRoot, false);
    const target = path.join(conflictRoot, `${operation.operationId}.conflict`);
    await containedAbsolute(this.rootDir, target, true);
    await fsp.writeFile(target, plaintext, { mode: 0o600 });
    summary.conflictRecovery = (summary.conflictRecovery || 0) + 1;
  }

  async pushPending(summary) {
    return this.withMutationLock(() => this._pushPending(summary));
  }

  async pushAtomicSignedOverwritePair(pending, summary) {
    if (!this.requireAuthorization || !this.requireCurrentOutgoingAuthorization
      || typeof this.currentDeviceAuthorization !== "function"
      || typeof this.adapter.pushBatch !== "function"
      || typeof this.journal.markSeenMany !== "function"
      || !this.atomicBatchWitnessPublicKey
      || !this.atomicBatchWitnessReadback || !this.atomicBatchWitnessScope
      || !this.atomicBatchOwnerIdentity
      || !this.atomicBatchCasFloorPublicKey || !this.atomicBatchCasFloorReadback) {
      fail("Atomic protected WebDAV remote batch transport unavailable",
        "sync_atomic_batch_unavailable");
    }
    // A persisted batch can be older than the device grant that admitted it.
    // Historical readback MUST NOT turn an expired/revoked grant into a new
    // POST. Structural validation is enough to identify immutable bytes for
    // an independently signed physical witness; live policy is still required
    // by assertOutgoingAuthorized before EVERY new network write.
    const [deleted, moved] = pending.map((entry) =>
      protocol.validateStoredOperation(entry));
    if (!deleted.authorization || !moved.authorization) {
      fail("Atomic protected WebDAV batch lacks original signed envelopes",
        "sync_atomic_batch_indeterminate");
    }
    assertAtomicSignedOverwritePair(deleted, moved);
    if (![deleted, moved].every((entry) => this.operationIsSelected(entry))) {
      fail("Atomic WebDAV destination selection cannot split the batch",
        "sync_atomic_batch_unavailable");
    }
    const digests = [deleted, moved].map(signedEnvelopeDigest);
    let response;
    const expiredBeforeRequest = [deleted, moved].some((entry) =>
      entry.authorization.expiresAt <= Date.now());
    let uncertainRequest = expiredBeforeRequest
      ? Object.assign(new Error("Historical signed batch requires read-only witness"),
        { code: "authorization_required" }) : null;
    if (!expiredBeforeRequest) try {
      // The second member's async authorizeOutgoing() can outlive the first
      // member's expiry or current revocation decision. Recheck BOTH signed
      // envelopes and the synchronous owner-trusted policy in one no-await
      // window immediately before beginning the single remote batch POST.
      const dispatchIfBothStillFresh = () => {
        for (const member of [deleted, moved]) {
          try { protocol.validateFreshSignedOperation(member); }
          catch { fail("Atomic batch member expired before dispatch", "authorization_required"); }
          let current;
          try { current = this.currentDeviceAuthorization(member); }
          catch { fail("Atomic batch current device grant unavailable", "authorization_rejected"); }
          if (current !== true) {
            try {
              if (current && typeof current.then === "function") {
                Promise.resolve(current).catch(() => {});
              }
            } catch { /* a broken policy is a denial */ }
            fail("Atomic batch device grant changed before dispatch", "authorization_rejected");
          }
        }
        return this.adapter.pushBatch([deleted, moved]);
      };
      // The final synchronous current-policy checks begin ONE network
      // request. Remote registry must fence BOTH signatures under one lock.
      response = await this.assertOutgoingAuthorized(deleted, () =>
        this.assertOutgoingAuthorized(moved, () =>
          dispatchIfBothStillFresh()));
    } catch (error) {
      // A 409 or a dropped ACK may mean the remote atomic transaction was
      // committed, or may mean neither write happened. A plain LIST echo of
      // the two envelopes proves neither signed server admission nor durable
      // physical custody. Never fabricate a successful pair ACK from LIST.
      // Preserve both pending until independently signed atomic admission
      // readback proves the exact pair; no remote-wins partial repair. A
      // genuine commit followed by a lost HTTP ACK can return 409 on retry.
      // That must be checked with a fresh direct witness challenge, not kept
      // in a permanent 409 loop.
      if (transient(error) || [403, 409, 423, 503].includes(error?.status)
        || ["authorization_rejected", "authorization_required"].includes(error?.code)) {
        // Revocation and current-policy denial prohibit another write, not
        // the separate read-only verification of an old physical commit.
        // A remote denial after previous admission may also arrive after
        // an earlier lost ACK; only the separate witness can disambiguate.
        uncertainRequest = error;
      }
      else fail("Atomic signed WebDAV remote batch outcome indeterminate",
        "sync_atomic_batch_indeterminate");
    }
    if (!uncertainRequest && (!Array.isArray(response?.objects) || response.objects.length !== 2
      || response.objects.some((entry, index) => {
        try {
          return signedEnvelopeDigest(protocol.validateStoredOperation(entry)) !== digests[index];
        } catch { return true; }
      }))) {
      fail("Atomic signed WebDAV remote batch lacks exact two-envelope ACK",
        "sync_atomic_batch_indeterminate");
    }
    // A successful HTTP status (including an exact two-envelope echo) does
    // not authenticate remote fsync, CAS fencing, or physical admission.
    // In the absence of an independent signed durable witness, keep BOTH
    // original operations pending and never persist an invented success.
    // Fresh unpredictable challenge goes DIRECTLY to the independent witness
    // AFTER HTTP admission. A cached receipt in the sync server's response
    // can be replayed after the server rolls its physical state backwards.
    // The readback transport must independently attest its current durable
    // head/floor, not fetch unsigned LIST or re-sign the server's JSON.
    const witnessNonce = crypto.randomBytes(32).toString("base64url");
    let witnessed;
    try {
      witnessed = await this.atomicBatchWitnessReadback({
        scope: this.atomicBatchWitnessScope,
        accountId: this.atomicBatchOwnerIdentity.accountId,
        storeId: this.atomicBatchOwnerIdentity.storeId,
        nonce: witnessNonce,
        operationIds: [deleted.operationId, moved.operationId],
        envelopeDigests: digests,
      });
    } catch {
      if (uncertainRequest && transient(uncertainRequest)) {
        summary.offline = true;
        return;
      }
      fail("Independent atomic admission readback unavailable",
        "sync_atomic_batch_indeterminate");
    }
    let detachedWitness;
    try { detachedWitness = JSON.parse(protocol.canonicalJson(witnessed)); }
    catch { fail("Independent witness receipt is not canonical JSON",
      "sync_atomic_batch_indeterminate"); }
    if (detachedWitness?.statement?.nonce !== witnessNonce) {
      if (uncertainRequest && transient(uncertainRequest) && !witnessed) {
        summary.offline = true;
        return;
      }
      fail("Independent atomic admission readback nonce mismatch",
        "sync_atomic_batch_indeterminate");
    }
    // The independent readback callback returns the receipt itself, not the
    // sync server's unsigned HTTP payload. Keep that distinction explicit:
    // accepting a server-supplied `atomicAdmission` would undermine the
    // separate witness and a valid direct receipt must not be rejected.
    verifyAtomicBatchAdmission({ atomicAdmission: detachedWitness }, [deleted, moved],
      this.atomicBatchWitnessPublicKey, this.atomicBatchWitnessScope,
      this.atomicBatchOwnerIdentity);
    // An independently retained CAS floor must independently sign a second
    // fresh challenge AFTER witness verification. Only an exact current
    // physical head can authorize a local ACK; never use a journal/PG row or
    // the original sync HTTP response as this readback.
    const verifiedWitnessStatement = detachedWitness.statement;
    const floorNonce = crypto.randomBytes(32).toString("base64url");
    let floor;
    try {
      floor = await this.atomicBatchCasFloorReadback({
        scope: this.atomicBatchWitnessScope,
        accountId: this.atomicBatchOwnerIdentity.accountId,
        storeId: this.atomicBatchOwnerIdentity.storeId,
        nonce: floorNonce,
        commitId: verifiedWitnessStatement.commitId,
        storeHeadSha256: verifiedWitnessStatement.storeHeadSha256,
        fencingEpoch: verifiedWitnessStatement.fencingEpoch,
      });
    } catch {
      fail("Independent external CAS floor unavailable",
        "sync_atomic_batch_indeterminate");
    }
    verifyAtomicBatchCasFloor(floor, verifiedWitnessStatement,
      this.atomicBatchCasFloorPublicKey, this.atomicBatchWitnessScope, floorNonce,
      this.atomicBatchOwnerIdentity);
    // Remote admission is one transaction. Local advancement may still crash;
    // keep BOTH original outbox entries pending until one atomic markSeenMany
    // after the verified response and local snapshot are durably written.
    let moveHash = null;
    let historicalKeyUnavailable = false;
    try {
      moveHash = await this.hashPendingPayload(moved);
    } catch (error) {
      // A cryptographically verified PHYSICAL historical admission is not a
      // new decrypt permission. After rekey or device revocation the old file
      // key can be unavailable; that must not make a previously committed
      // remote pair forever unacknowledgeable. Never invent a new plaintext
      // hash: rememberOperation may only carry forward a previously trusted
      // snapshot hash, if one exists. Any other error still fails closed.
      if (!["authorization_rejected", "stale_key_epoch", "key_unavailable"].includes(error?.code)) {
        throw error;
      }
      historicalKeyUnavailable = true;
    }
    const observed = [deleted, moved].map((entry, index) =>
      this.localAdmissionDigestIfFresh(entry) === digests[index] ? digests[index] : null);
    for (let index = 0; index < pending.length; index++) {
      if (observed[index]) await this.journal.observeAdmission(pending[index].operationId, observed[index]);
    }
    this.rememberOperation(deleted);
    this.rememberOperation(moved, moveHash);
    if (historicalKeyUnavailable) {
      // Even a previously trusted source hash cannot certify CURRENT local
      // bytes after the file key becomes unavailable. Preserve the signed
      // remote admission, but make local content identity explicitly unknown.
      this.snapshot.files[moved.metadata.path].hash = null;
    }
    await this.persistSnapshot();
    await this.journal.markSeenMany(pending.map((entry, index) => ({
      operationId: entry.operationId, admittedDigest: observed[index],
    })));
    summary.pushed += 2;
  }

  async _pushPending(summary) {
    const recovered = await this.journal.recover();
    if (this.requireNativeRootRecovery && recovered.some((operation) =>
      !this.journal.hasSeen(operation.operationId)
      && (operation.operation === "delete" || operation.tombstone))) {
      // Pre-existing outboxes must not bypass current native custody rules.
      denyUntrustedNativeSignedDelete();
    }
    // The journal's durable group manifest—not adjacency—is the local
    // evidence that the DELETE and MOVE entered the outbox together.
    // enqueueMany can leave unrelated records between two group members.
    const groups = typeof this.journal.atomicSignedGroups === "function"
      ? this.journal.atomicSignedGroups() : {};
    const groupedById = new Map();
    const pendingById = new Map(recovered.map((item) => [item.operationId, item]));
    for (const [eventId, pair] of Object.entries(groups)) {
      if (!pair || typeof pair.deleteId !== "string" || typeof pair.moveId !== "string"
        || groupedById.has(pair.deleteId) || groupedById.has(pair.moveId)
        || !pendingById.has(pair.deleteId) || !pendingById.has(pair.moveId)
        || signedWebDavEventId(pendingById.get(pair.deleteId)) !== eventId
        || signedWebDavEventId(pendingById.get(pair.moveId)) !== eventId) {
        fail("Atomic signed WebDAV outbox group has missing/mismatched member",
          "sync_atomic_batch_indeterminate");
      }
      assertAtomicSignedOverwritePair(pendingById.get(pair.deleteId),
        pendingById.get(pair.moveId));
      groupedById.set(pair.deleteId, pair);
      groupedById.set(pair.moveId, pair);
    }
    // Old local outboxes can contain two valid-looking WebDAV envelopes
    // admitted separately before group provenance existed. Detect pairs
    // across the ENTIRE queue; never let an intervening unrelated item cause
    // the DELETE to escape via adapter.push. Without durable enqueueMany
    // provenance there is no safe automatic remote transaction to infer.
    const ungroupedCandidates = new Map();
    for (const operation of recovered) {
      const event = signedWebDavEventId(operation);
      if (!event || groupedById.has(operation.operationId)) continue;
      const candidates = ungroupedCandidates.get(event) || [];
      candidates.push(operation);
      ungroupedCandidates.set(event, candidates);
    }
    if ([...ungroupedCandidates.values()].some((candidates) => candidates.length > 1)) {
      fail("Unproven historical atomic WebDAV outbox group",
        "sync_atomic_batch_indeterminate");
    }
    const pushedGroups = new Set();
    for (let index = 0; index < recovered.length; index += 1) {
      const original = recovered[index];
      if (this.journal.hasSeen(original.operationId)) continue;
      const group = groupedById.get(original.operationId);
      if (group) {
        if (pushedGroups.has(group.deleteId)) continue;
        await this.pushAtomicSignedOverwritePair([
          pendingById.get(group.deleteId), pendingById.get(group.moveId),
        ], summary);
        pushedGroups.add(group.deleteId);
        if (summary.offline) break;
        continue;
      }
      const next = recovered[index + 1];
      const event = signedWebDavEventId(original);
      if (event && next && signedWebDavEventId(next) === event) {
        // Two adjacent lookalikes are not proof of one fsynced group.
        fail("Unproven atomic WebDAV journal batch provenance",
          "sync_atomic_batch_indeterminate");
      }
      // A prior version may have acknowledged DELETE but crashed before the
      // companion MOVE. Such legacy partial evidence must NOT send MOVE as a
      // standalone remote write; only manual independent reconciliation can
      // determine whether the DELETE was ever committed remotely.
      if (event && original.operation === "move") {
        // An old `webdav-` MOVE can be the surviving half of a tampered
        // overwrite batch. Its signature says MOVE, not that a destination
        // tombstone was never required. Only new `webdavsolo-` IDs may be
        // independently dispatched without a durable group manifest.
        fail("Ambiguous legacy WebDAV MOVE cannot be remotely committed alone",
          "sync_atomic_batch_indeterminate");
      }
      if (event && original.operation === "delete") {
        // The only secure standalone WebDAV DELETE namespace is the new
        // signed `webdavsolo-` variant. Old `webdav-` DELETE IDs could be a
        // missing half of a poisoned DELETE+MOVE journal; presence/absence of
        // locally editable manifest or seen IDs is not cryptographic proof.
        fail("Ambiguous legacy WebDAV DELETE cannot be remotely committed alone",
          "sync_atomic_batch_indeterminate");
      }
      let pending = original;
      if (pending.journalType === "webdav-mutation") {
        if (!this.translateWebDavOperation) continue;
        const translated = await this.translateWebDavOperation(pending);
        if (!translated) continue;
        if (this.journal.replace) await this.journal.replace(pending.operationId, translated);
        else await this.journal.update(pending.operationId, translated);
        pending = translated;
      }
      let operation;
      try {
        operation = protocol.validateOperation(pending);
        if (!this.operationIsSelected(operation)) continue;
        if (this.filesOnDemand && operation.operation === "create") {
          // A metadata-only pull cannot establish that a new local path is free remotely.
          // Recheck EVERY pending CREATE immediately before push, including old outbox
          // entries replayed after a crash/offline interval. Never treat the mutable
          // local snapshot (or a previous successful inventory read) as a path lock.
          let inventory;
          try {
            inventory = await this.scanOnDemandInventory(operation.metadata.path);
          } catch (error) {
            // A 409 on metadata paging signals a stale inventory cursor, NOT
            // a rejected outgoing push. Never run remote-wins conflict recovery
            // or mark a pending local CREATE seen because metadata changed.
            if (error?.status === 409 || error?.code === "sync_conflict"
              || error instanceof SyncConflictError) {
              fail("Metadata inventory changed during CREATE preflight", "inventory_changed");
            }
            throw error;
          }
          if (inventory.matching) {
            fail("A remote object already owns the Files On-Demand CREATE path",
              "remote_path_collision");
          }
        }
        const outboundFreshDigest = this.localAdmissionDigestIfFresh(operation);
        const result = await this.retryPush(operation);
        if (result?.status >= 400) {
          if (result.status === 409 && (result.code === "remote_path_collision"
            || result.payload?.code === "remote_path_collision")) {
            fail("A protected remote CREATE path was occupied after preflight", "remote_path_collision");
          }
          if (result.status !== 409) fail("Sync push rejected", "push_rejected");
          throw new SyncConflictError(result);
        }
        // Persist the exact pre-expiry observation BEFORE snapshot writes. A
        // later journal fsync failure must not make this verified ciphertext
        // impossible to authenticate after authorization expires.
        const acknowledgedDigest = outboundFreshDigest && result?.operationId === operation.operationId
          && signedEnvelopeDigest(result) === outboundFreshDigest ? outboundFreshDigest : null;
        if (acknowledgedDigest) await this.journal.observeAdmission(operation.operationId, acknowledgedDigest);
        if (operation.operation === "move" || operation.operation === "delete") {
          const hash = operation.operation === "move" ? await this.hashPendingPayload(operation) : undefined;
          this.rememberOperation(operation, hash);
          await this.persistSnapshot();
        } else {
          const hash = await this.hashPendingPayload(operation);
          this.rememberOperation(operation, hash);
          await this.persistSnapshot();
        }
        // HTTP 2xx is not an independently signed admission receipt. Pin only
        // our locally signed exact envelope if the response echoes every byte.
        // Unknown ACKs and conflict results remain seen-only.
        await this.journal.markSeen(operation.operationId, acknowledgedDigest);
        summary.pushed += 1;
      } catch (error) {
        if (error?.code === "remote_path_collision"
          || error?.payload?.code === "remote_path_collision") {
          fail("A protected remote CREATE path was occupied after preflight", "remote_path_collision");
        }
        // A local authorization failure is never an HTTP conflict. Even a
        // callback that throws status:409 must not consume a pending journal
        // operation or trigger remote-wins recovery without a real response.
        if (error?.code === "authorization_rejected" || error?.code === "authorization_required") throw error;
        if (error instanceof SyncConflictError || error?.status === 409 || error?.code === "sync_conflict") {
          const current = error.current
            ? envelopeCopy(protocol.validateStoredOperation(error.current)) : null;
          if (current?.operationId === operation?.operationId
            && signedEnvelopeDigest(current) !== signedEnvelopeDigest(operation)) {
            fail("Conflicting local sync admission evidence", "remote_authorization_rejected");
          }
          // A conflict response for A can point to B, whose operation ID may
          // already be reserved by a DIFFERENT pending signed envelope. Never
          // let markSeen(B) silently consume that still-unsent local operation.
          if (current) {
            const currentDigest = signedEnvelopeDigest(current);
            for (const queued of await this.journal.recover()) {
              if (queued.operationId !== current.operationId) continue;
              let queuedDigest;
              try {
                queuedDigest = signedEnvelopeDigest(protocol.validateStoredOperation(queued));
              } catch {
                fail("Conflicting local sync admission evidence", "remote_authorization_rejected");
              }
              if (queuedDigest !== currentDigest) {
                fail("Conflicting local sync admission evidence", "remote_authorization_rejected");
              }
            }
          }
          if (current && !this.operationDestinationIsSelected(current)) {
            this.preflightOutOfScopeMove(current);
          }
          summary.conflicts.push({ operationId: operation?.operationId || pending.operationId, policy: "remote-wins", currentRevision: error.currentRevision || error.payload?.currentRevision || null });
          await this.recoverConflict(operation, summary);
          if (current) {
            let verifiedFreshDigest;
            if (this.operationDestinationIsSelected(current)) {
              verifiedFreshDigest = await this._apply(current, summary);
            } else {
              verifiedFreshDigest = await this.verifyIncomingOperation(current);
              const reconciled = await this.reconcileOutOfScopeMove(current, summary, {
                preservedOperationIds: [operation.operationId], conflictAlreadyRecorded: true,
              });
              if (!reconciled) {
                this.rememberRemoteOnly(current, "excluded");
                await this.persistSnapshot();
              }
            }
            // A verified remote winner is not the local pending operation.
            // Its separately signed envelope needs its own durable admission
            // pin after the remote snapshot/materialization is persisted.
            await this.journal.markSeen(current.operationId, verifiedFreshDigest);
          }
          await this.journal.markSeen(operation.operationId);
          summary.pushed += 1;
          continue;
        }
        if (transient(error)) { summary.offline = true; continue; }
        throw error;
      }
    }
  }

  async hashPendingPayload(operation) {
    const key = await this.keyFor(operation);
    const decrypted = protocol.decryptPayload(operation, key);
    const content = operation.operation === "move"
      ? protocol.decodeMovePayload(decrypted, key) || decrypted
      : decrypted;
    return crypto.createHash("sha256").update(content).digest("hex");
  }

  async stageExisting(target) {
    // A public caller may pass an absolute source. Never stage a file from
    // outside this root, even when the trash destination itself is contained.
    // This rejects static escapes, NOT concurrent same-SID ancestor swaps.
    const safeTarget = await containedAbsolute(this.rootDir, target, true);
    if (!(await exists(safeTarget))) return null;
    const trashDir = path.join(this.rootDir, ".rootark-trash");
    await fsp.mkdir(trashDir, { recursive: true });
    await containedAbsolute(this.rootDir, trashDir, false);
    const trashTarget = path.join(trashDir, `${Date.now()}-${crypto.randomUUID()}-${path.basename(safeTarget)}`);
    await containedAbsolute(this.rootDir, trashTarget, true);
    await fsp.rename(safeTarget, trashTarget);
    return trashTarget;
  }

  async apply(operation, summary = null) {
    return this.withMutationLock(() => this._apply(operation, summary));
  }

  async _apply(operation, summary = null, beforeHydrationWrite = null) {
    operation = envelopeCopy(operation);
    // Incoming authenticated DELETE/tombstone is not independent authority
    // to stage or unlink cached bytes when the native root is unavailable.
    // This also protects direct _apply() callers, not just public apply().
    if (this.requireNativeRootRecovery && (operation.operation === "delete" || operation.tombstone)) {
      denyUntrustedNativeSignedDelete();
    }
    const verifiedFreshDigest = await this.verifyIncomingOperation(operation, { preObserve: false });
    const key = await this.keyFor(operation);
    const plaintext = protocol.decryptPayload(operation, key);
    const incomingMetadata = operation.metadata || {};
    if (!incomingMetadata.path) fail("Sync operation path is required", "unsafe_path");
    const canonicalSourcePath = incomingMetadata.sourcePath
      ? await canonicalRelativePath(this.rootDir, incomingMetadata.sourcePath)
      : null;
    let canonicalPath = await canonicalRelativePath(this.rootDir, incomingMetadata.path);
    const requestedPath = String(incomingMetadata.path);
    const sourceName = canonicalSourcePath ? path.posix.basename(canonicalSourcePath) : null;
    const requestedName = path.posix.basename(requestedPath);
    const requestedCaseOnlyMove = process.platform === "win32" && operation.operation === "move"
      && typeof incomingMetadata.sourcePath === "string"
      && incomingMetadata.sourcePath.toLowerCase() === requestedPath.toLowerCase()
      && incomingMetadata.sourcePath !== requestedPath;
    if (process.platform === "win32" && operation.operation === "move" && canonicalSourcePath
      && canonicalSourcePath.toLowerCase() === canonicalPath.toLowerCase()
      && sourceName.toLowerCase() === requestedName.toLowerCase() && sourceName !== requestedName) {
      canonicalPath = path.posix.join(path.posix.dirname(canonicalSourcePath), path.posix.basename(incomingMetadata.path));
    }
    const metadata = {
      ...incomingMetadata,
      path: canonicalPath,
      ...(canonicalSourcePath ? { sourcePath: canonicalSourcePath } : {}),
    };
    operation = { ...operation, metadata };
    const target = await contained(this.rootDir, metadata.path, true);
    // A signed operation may target a directory which contains a device-local
    // pinned file. stageExisting() moves whole directory trees, so check every
    // path it could remove or relocate BEFORE recording admission or touching
    // the filesystem. Use portable case-folding even on POSIX: a source made
    // on Linux must not become destructive if replayed on Windows.
    const protectedPaths = Object.values(this.snapshot.pinnedFiles || {});
    const affectedPaths = [metadata.path];
    if (operation.operation === "move" && metadata.sourcePath) {
      affectedPaths.push(metadata.sourcePath);
    }
    if (["update", "move", "delete"].includes(operation.operation)) {
      for (const [relativePath, entry] of Object.entries(this.snapshot.files)) {
        if (entry && !entry.deleted && entry.objectId === operation.objectId
          && entry.fileId === operation.fileId) affectedPaths.push(relativePath);
      }
    }
    if (protectedPaths.some((pin) => affectedPaths.some((candidate) =>
      pin.path.toLowerCase().startsWith(`${candidate.toLowerCase()}/`)))) {
      fail("A pinned file is inside a directory affected by the signed operation", "file_pinned");
    }
    if (operation.operation === "delete"
      && this.snapshot.pinnedFiles?.[pinnedKey(operation.objectId)]?.fileId === operation.fileId) {
      fail("Pinned file must be unpinned before applying a remote delete", "file_pinned");
    }
    if (["create", "update", "move"].includes(operation.operation)
      && protectedPaths.some((pin) =>
        pin.path.toLowerCase() === metadata.path.toLowerCase()
        && (pin.objectId !== operation.objectId || pin.fileId !== operation.fileId))) {
      // Guard the destination BEFORE the first journal observation, mkdir,
      // stageExisting or rename. Signed operations from another object can
      // never replace a device-pinned target, even via direct apply() or
      // when Files-On-Demand is disabled on the reopened client.
      fail("A pinned file owns the destination path", "file_pinned");
    }
    // Credential/key/AEAD/path preflight is complete. Fsync the exact verified
    // envelope before the first filesystem or snapshot mutation; failure here
    // must not leave an applied object with no restart-safe observation.
    if (verifiedFreshDigest) await this.journal.observeAdmission(operation.operationId, verifiedFreshDigest);
    let cleanupPath = null;
    if (operation.operation === "delete" || operation.tombstone) {
      const priorAtTarget = this.snapshot.files[metadata.path];
      const targetMatchesIdentity = priorAtTarget && !priorAtTarget.deleted
        && priorAtTarget.objectId === operation.objectId && priorAtTarget.fileId === operation.fileId;
      const sourcePath = targetMatchesIdentity ? metadata.path
        : (activeIdentityPath(this.snapshot.files, operation, metadata.path)
          || activeFileIdentityPath(this.snapshot.files, operation, metadata.path));
      if (!sourcePath) {
        delete this.snapshot.remoteOnly[operation.objectId];
        await this.persistSnapshot();
        return verifiedFreshDigest;
      }
      cleanupPath = sourcePath;
      const pathOccupiedByOther = priorAtTarget && !priorAtTarget.deleted
        && (priorAtTarget.objectId !== operation.objectId || priorAtTarget.fileId !== operation.fileId);
      const tombstonePath = pathOccupiedByOther ? sourcePath : metadata.path;
      const deleteTarget = await contained(this.rootDir, sourcePath, true);
      await this.stageExisting(deleteTarget);
      this.rememberOperation({ ...operation, metadata: { ...metadata, path: tombstonePath } }, undefined, sourcePath);
    } else if (operation.operation === "move") {
      if (!metadata.sourcePath) fail("Move source path is required", "unsafe_path");
      if (metadata.sourcePath === metadata.path && !requestedCaseOnlyMove) fail("Move source and destination must differ", "move_source_missing");
      const priorAtSource = this.snapshot.files[metadata.sourcePath];
      const sourceMatchesIdentity = priorAtSource && !priorAtSource.deleted && !priorAtSource.directory
        && priorAtSource.objectId === operation.objectId && priorAtSource.fileId === operation.fileId;
      const sourcePath = sourceMatchesIdentity ? metadata.sourcePath
        : activeFileIdentityPath(this.snapshot.files, operation, metadata.path);
      cleanupPath = sourcePath;
      const source = sourcePath ? await contained(this.rootDir, sourcePath, true) : null;
      const sourceExists = source ? await exists(source) : false;
      const movePayload = protocol.decodeMovePayload(plaintext, key);
      if (!sourceExists && movePayload === null) fail("Moved file is unavailable and the operation has no recovery payload", "move_source_missing");
      await fsp.mkdir(path.dirname(target), { recursive: true });
      await containedAbsolute(this.rootDir, path.dirname(target), false);
      if (beforeHydrationWrite) await beforeHydrationWrite();
      let hash;
      if (sourceExists) {
        if (source !== target) {
          const sameWindowsPath = process.platform === "win32"
            && path.resolve(source).toLowerCase() === path.resolve(target).toLowerCase();
          if (!sameWindowsPath && await exists(target)) await this.stageExisting(target);
          await fsp.rename(source, target);
        }
        const movedStats = await fsp.lstat(target, { bigint: true });
        if (movedStats.isFile()) hash = crypto.createHash("sha256").update(await readContainedFile(this.rootDir, metadata.path, movedStats)).digest("hex");
      } else {
        if (await exists(target)) await this.stageExisting(target);
        const temporary = `${target}.tmp-${process.pid}-${crypto.randomUUID()}`;
        try {
          await fsp.writeFile(temporary, movePayload, { mode: 0o600, flag: "wx" });
          await fsp.rename(temporary, target);
        } finally { await fsp.rm(temporary, { force: true }).catch(() => {}); }
        hash = crypto.createHash("sha256").update(movePayload).digest("hex");
      }
      this.rememberOperation(operation, hash, sourcePath);
    } else {
      await fsp.mkdir(path.dirname(target), { recursive: true });
      await containedAbsolute(this.rootDir, path.dirname(target), false);
      if (beforeHydrationWrite) await beforeHydrationWrite();
      if (metadata.contentType === "inode/directory") {
        const sourcePath = operation.operation === "update" ? activeIdentityPath(this.snapshot.files, operation, metadata.path) : null;
        let relocated = false;
        if (sourcePath) {
          const source = await contained(this.rootDir, sourcePath, true);
          if (await exists(source)) {
            if (!(await fsp.lstat(source)).isDirectory()) fail("Tracked directory identity points to a non-directory", "unsafe_path");
            if (source !== target) {
              if (await exists(target)) await this.stageExisting(target);
              await fsp.rename(source, target);
            }
            relocated = true;
          }
        }
        if (!relocated) {
          try {
            await fsp.mkdir(target, { recursive: false });
          } catch (error) {
            if (error.code !== "EEXIST") throw error;
            if (!(await fsp.lstat(target)).isDirectory()) {
              await this.stageExisting(target);
              await fsp.mkdir(target, { recursive: false });
            }
          }
        }
      } else {
        const temporary = `${target}.tmp-${process.pid}-${crypto.randomUUID()}`;
        await fsp.writeFile(temporary, plaintext, { mode: 0o600 });
        try {
          if (await exists(target)) await this.stageExisting(target);
          await fsp.rename(temporary, target);
        } finally { await fsp.rm(temporary, { force: true }).catch(() => {}); }
      }
      this.rememberOperation(operation, crypto.createHash("sha256").update(plaintext).digest("hex"));
    }
    if (operation.operation === "move" && cleanupPath) {
      await this.pruneEmptyUntrackedParents(path.dirname(await contained(this.rootDir, cleanupPath, true)));
    } else if (operation.operation === "delete" || operation.tombstone) {
      await this.pruneEmptyUntrackedParents(path.dirname(await contained(this.rootDir, cleanupPath || metadata.path, true)));
    }
    await this.persistSnapshot();
    if (summary) summary.applied = (summary.applied || 0) + 1;
    return verifiedFreshDigest;
  }

  // Only for a required-v2, zero-PREPARE genesis under the exclusive root
  // mutation lock. Unlike scanFiles(), this walks every physical cache path
  // without isSelected()/needsTraversal() and rejects untracked entries.
  // The extra conservative checks never grant a server-side DELETE.
  async scanPhysicalCacheForEvictionRecovery() {
    const root = this.rootDir;
    const expected = new Set();
    const parents = new Set();
    for (const [relative, item] of Object.entries(this.snapshot.files)) {
      if (!item || item.deleted) continue;
      protocol.safeRelativePath(relative, "path");
      expected.add(relative);
      let ancestor = path.posix.dirname(relative);
      while (ancestor !== ".") {
        parents.add(ancestor);
        ancestor = path.posix.dirname(ancestor);
      }
    }
    const scanned = Object.create(null);
    const emptyHash = crypto.createHash("sha256").update(Buffer.alloc(0)).digest("hex");
    let visited = 0;
    const walk = async (directory, prefix = "") => {
      const before = await fsp.lstat(directory, { bigint: true });
      if (!before.isDirectory() || before.isSymbolicLink() || before.ino === 0n) {
        fail("Unsafe physical cache directory during eviction recovery", "invalid_snapshot");
      }
      const names = new Set();
      let directoryCount = 0;
      for await (const entry of await fsp.opendir(directory)) {
        if (++directoryCount > 16384) {
          fail("Physical recovery directory capacity exceeded", "invalid_snapshot");
        }
        if (++visited > EVICTION_LEDGER_MAX * 2) {
          fail("Physical recovery traversal capacity exceeded", "invalid_snapshot");
        }
        const folded = entry.name.toLowerCase();
        if (names.has(folded)) fail("Ambiguous physical casefold alias in cache", "invalid_snapshot");
        names.add(folded);
        if (!prefix) {
          const internalName = [...INTERNAL_NAMES].find((name) => name.toLowerCase() === folded);
          if (internalName) {
            if (entry.name !== internalName) fail("Ambiguous internal cache entry", "invalid_snapshot");
            continue;
          }
          if (INTERNAL_NAME_PREFIXES.some((name) => folded.startsWith(name))) {
            if (!INTERNAL_NAME_PREFIXES.some((name) => entry.name.startsWith(name))) {
              fail("Ambiguous internal cache prefix", "invalid_snapshot");
            }
            continue;
          }
        }
        const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
        protocol.safeRelativePath(relative, "path");
        if (!expected.has(relative) && !parents.has(relative)) {
          fail("Untracked physical path during eviction recovery", "invalid_snapshot");
        }
        const target = path.join(directory, entry.name);
        await containedAbsolute(root, target, false);
        const stats = await fsp.lstat(target, { bigint: true });
        if (stats.isSymbolicLink() || stats.ino === 0n) {
          fail("Unsafe cache link during eviction recovery", "invalid_snapshot");
        }
        if (stats.isDirectory()) {
          await walk(target, relative);
          if (expected.has(relative)) {
            scanned[relative] = { directory: true, hash: emptyHash };
          }
        } else if (stats.isFile()) {
          if (!expected.has(relative)) {
            fail("Untracked physical file during eviction recovery", "invalid_snapshot");
          }
          const bytes = await readContainedFile(root, relative, stats);
          scanned[relative] = { directory: false,
            hash: crypto.createHash("sha256").update(bytes).digest("hex") };
        } else {
          fail("Unsupported physical cache entry during eviction recovery", "invalid_snapshot");
        }
      }
      const after = await fsp.lstat(directory, { bigint: true });
      if (!sameFileVersion(before, after)) {
        fail("Physical cache directory changed during recovery", "invalid_snapshot");
      }
    };
    await walk(root);
    return scanned;
  }

  async scanFiles() {
    const result = {};
    const emptyHash = crypto.createHash("sha256").update(Buffer.alloc(0)).digest("hex");
    const walk = async (directory, prefix = "") => {
      let hasSyncEntries = false;
      for (const entry of await fsp.readdir(directory, { withFileTypes: true })) {
        if (prefix === "" && ([...INTERNAL_NAMES].some((name) => name.toLowerCase() === entry.name.toLowerCase())
          || INTERNAL_NAME_PREFIXES.some((name) => entry.name.toLowerCase().startsWith(name)))) continue;
        if (entry.name.startsWith(".rootark-put-") || entry.name.startsWith(".rootark-move-")) continue;
        const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
        try { protocol.safeRelativePath(relative, "path"); } catch { continue; }
        const target = path.join(directory, entry.name);
        await containedAbsolute(this.rootDir, target, false);
        if (entry.isDirectory()) {
          if (!this.needsTraversal(relative)) continue;
          const childHasSyncEntries = await walk(target, relative);
          const prior = this.snapshot.files[relative];
          if (this.selectedPaths === null
            ? (!childHasSyncEntries || (prior && !prior.deleted && prior.directory))
            : (this.isSelected(relative) && (!childHasSyncEntries || (prior && !prior.deleted && prior.directory)))) {
            result[relative] = { hash: emptyHash, size: 0, directory: true };
          }
          if (childHasSyncEntries || this.isSelected(relative) || this.selectedPaths === null) hasSyncEntries = true;
        } else if (entry.isFile() && this.isSelected(relative)) {
          const data = await readContainedFile(this.rootDir, relative);
          result[relative] = { hash: crypto.createHash("sha256").update(data).digest("hex"), size: data.length, directory: false };
          hasSyncEntries = true;
        }
      }
      return hasSyncEntries;
    };
    await walk(this.rootDir);
    return result;
  }

  async pruneEmptyUntrackedParents(directory) {
    const root = path.resolve(this.rootDir);
    let current = path.resolve(directory);
    while (current !== root && current.startsWith(`${root}${path.sep}`)) {
      await containedAbsolute(root, current, true);
      const relative = path.relative(root, current).split(path.sep).join("/");
      const prior = this.snapshot.files[relative];
      if (prior && !prior.deleted && prior.directory) break;
      try {
        await fsp.rmdir(current);
      } catch (error) {
        if (error.code === "ENOENT") {
          current = path.dirname(current);
          continue;
        }
        if (["ENOTEMPTY", "EEXIST"].includes(error.code)) break;
        throw error;
      }
      current = path.dirname(current);
    }
  }

  async reconcileLocal() {
    return this.withMutationLock(() => this._reconcileLocal());
  }

  async _reconcileLocal() {
    const scanned = await this.scanFiles();
    const current = {};
    const snapshotPathByKey = new Map();
    if (process.platform === "win32") {
      for (const relative of Object.keys(this.snapshot.files)) {
        const key = pathKey(relative);
        const prior = snapshotPathByKey.get(key);
        if (prior && prior !== relative) fail("Ambiguous case-insensitive sync snapshot path", "unsafe_path");
        snapshotPathByKey.set(key, relative);
      }
    }
    for (const [relative, file] of Object.entries(scanned)) {
      const canonical = process.platform === "win32" ? snapshotPathByKey.get(pathKey(relative)) || relative : relative;
      current[canonical] = file;
    }
    const evictedByPath = new Map();
    for (const item of Object.values(this.snapshot.remoteOnly)) {
      if (item.reason !== "evicted" || item.deleted || item.directory) continue;
      const key = pathKey(item.path);
      const matches = evictedByPath.get(key) || [];
      matches.push(item);
      evictedByPath.set(key, matches);
    }
    const protectedPaths = new Set();
    for (const operation of await this.journal.recover()) {
      if (operation.metadata?.path) protectedPaths.add(pathKey(operation.metadata.path));
      if (operation.metadata?.sourcePath) protectedPaths.add(pathKey(operation.metadata.sourcePath));
      if (operation.operation === "update" && operation.metadata?.contentType === "inode/directory") {
        const sourcePath = activeIdentityPath(this.snapshot.files, operation, operation.metadata.path);
        if (sourcePath) protectedPaths.add(pathKey(sourcePath));
      }
      if (operation.journalType === "webdav-mutation") {
        for (const value of [operation.path, operation.source, operation.destination]) {
          if (typeof value !== "string") continue;
          try { protectedPaths.add(pathKey(protocol.safeRelativePath(decodeURIComponent(value).replace(/^\/+/, ""), "path"))); } catch {}
        }
      }
    }
    for (const [relative, prior] of Object.entries(this.snapshot.files)) {
      if (protectedPaths.has(pathKey(relative))) continue;
      if (!this.isSelected(relative)) continue;
      if (prior.deleted || current[relative]) continue;
      if (this.snapshot.pinnedFiles?.[pinnedKey(prior.objectId)]?.fileId === prior.fileId) {
        fail("Pinned local file is missing; refusing to enqueue remote DELETE", "pinned_file_missing");
      }
      const eviction = this.snapshot.remoteOnly[prior.objectId];
      if (eviction?.reason === "evicted" && pathsEqual(eviction.path, relative)) {
        delete this.snapshot.files[relative];
        continue;
      }
      if (this.requireNativeRootRecovery) denyUntrustedNativeSignedDelete();
      const key = await this.fileKeyResolver(prior);
      const operation = await this.buildOperation({ operation: "delete", objectId: prior.objectId, fileId: prior.fileId, versionId: crypto.randomUUID(), baseRevision: prior.revision, revision: { counter: (prior.revision?.counter || 0) + 1, deviceId: this.deviceId }, metadata: { path: relative }, fileKey: key });
      await this.assertOutgoingAuthorized(operation, () => this.journal.enqueue(operation));
      this.rememberOperation(operation);
    }
    for (const [relative, file] of Object.entries(current)) {
      if (protectedPaths.has(pathKey(relative))) continue;
      let prior = this.snapshot.files[relative];
      if (prior && !prior.deleted && this.snapshot.remoteOnly[prior.objectId]?.reason === "evicted"
        && pathsEqual(this.snapshot.remoteOnly[prior.objectId].path, relative)) delete this.snapshot.remoteOnly[prior.objectId];
      const evicted = !prior || prior.deleted ? evictedByPath.get(pathKey(relative)) || [] : [];
      if (evicted.length > 1) fail("More than one evicted remote object matches this path", "remote_object_ambiguous");
      const evictedEntry = evicted[0] || null;
      if (evictedEntry) {
        prior = evictedEntry;
        if (prior.hash === file.hash) {
          this.snapshot.files[relative] = { ...prior, hash: file.hash, deleted: false };
          delete this.snapshot.remoteOnly[prior.objectId];
          continue;
        }
      }
      const isDirectory = Boolean(file.directory);
      if (prior && !prior.deleted && prior.hash === file.hash && Boolean(prior.directory) === isDirectory) continue;
      const isUpdate = prior && !prior.deleted;
      const identitySeed = prior?.deleted
        ? crypto.randomUUID().replace(/-/g, "")
        : crypto.createHash("sha256").update(relative).digest("hex").slice(0, 32);
      const objectId = isUpdate ? prior.objectId : `object-${identitySeed}`;
      const fileId = isUpdate ? prior.fileId : `file-${identitySeed}`;
      const data = isDirectory ? Buffer.alloc(0) : await readContainedFile(this.rootDir, relative);
      const contentHash = crypto.createHash("sha256").update(data).digest("hex");
      const key = await this.fileKeyResolver({ objectId, fileId, path: relative, keyEpoch: this.keyEpoch });
      const metadata = { path: relative, name: path.basename(relative), size: data.length, ...(isDirectory ? { contentType: "inode/directory" } : {}) };
      const operation = await this.buildOperation({ operation: isUpdate ? "update" : "create", objectId, fileId, versionId: crypto.randomUUID(), baseRevision: isUpdate ? prior.revision : null, revision: { counter: (prior?.revision?.counter || 0) + 1, deviceId: this.deviceId }, metadata, plaintext: data, fileKey: key });
      await this.assertOutgoingAuthorized(operation, () => this.journal.enqueue(operation));
      this.rememberOperation(operation, contentHash);
    }
    await this.persistSnapshot();
  }

  rememberOperation(operation, hash, sourcePathOverride) {
    const pathName = operation.metadata?.path;
    if (!pathName) return;
    const sourcePath = sourcePathOverride !== undefined ? sourcePathOverride
      : operation.operation === "move" ? operation.metadata.sourcePath
        : (operation.operation === "update" && operation.metadata.contentType === "inode/directory"
          ? activeIdentityPath(this.snapshot.files, operation, pathName) : null);
    const prior = sourcePath
      ? this.snapshot.files[sourcePath] || (sourcePath === pathName ? this.snapshot.files[pathName] : null) || {}
      : this.snapshot.files[pathName] || {};
    if (sourcePath && sourcePath !== pathName) delete this.snapshot.files[sourcePath];
    this.snapshot.files[pathName] = {
      objectId: operation.objectId, fileId: operation.fileId, versionId: operation.versionId,
      revision: operation.revision, hash: hash || prior.hash, deleted: Boolean(operation.tombstone),
      directory: operation.tombstone || operation.operation === "move" || operation.operation === "delete"
        ? Boolean(prior.directory)
        : operation.metadata?.contentType === "inode/directory",
    };
    // A verified MOVE retains object/file identity; carry device-local
    // retention intent without trusting advisory inventory metadata.
    if (operation.operation === "move") {
      const pin = this.snapshot.pinnedFiles?.[pinnedKey(operation.objectId)];
      if (pin && pin.fileId === operation.fileId) {
        this.snapshot.pinnedFiles[pinnedKey(operation.objectId)] = { ...pin, path: pathName };
      }
    }
    delete this.snapshot.remoteOnly[operation.objectId];
  }

  async evictLocal(relativePath) {
    return this.withMutationLock(() => this._evictLocal(relativePath));
  }

  // Pinning is a durable DEVICE-LOCAL retention policy, not a remote trust pin
  // or an authorization to decrypt. A successful pin first materializes the
  // exact signed full envelope through the regular Files On-Demand verifier.
  async pinLocal(relativePath) {
    return this.withMutationLock(() => this._pinLocal(relativePath));
  }

  async _pinLocal(relativePath) {
    if (!this.filesOnDemand) fail("Files On-Demand is not enabled", "files_on_demand_disabled");
    if (!this.requireAuthorization || typeof this.verifyIncoming !== "function") {
      // Ordinary non-strict sync is allowed to use a caller-supplied AEAD
      // key without any device signature. That is insufficient to establish
      // a new durable PIN from an adversarial remote metadata inventory.
      fail("Pinning requires independently verified signed remote authorization", "authorization_required");
    }
    const safePath = await canonicalRelativePath(this.rootDir, relativePath);
    if (!this.isSelected(safePath)) fail("Pinned file must be selected and not excluded", "path_not_selected");
    const oldPins = this.snapshot.pinnedFiles || {};
    if (Object.values(oldPins).some((entry) =>
      entry.path.toLowerCase() === safePath.toLowerCase() && entry.path !== safePath)) {
      // Match the portable validation performed on restart, not POSIX
      // pathsEqual: legacy signed case-distinct objects may exist on Linux.
      // Reject the alias BEFORE hydration or any snapshot mutation.
      fail("Portable case-fold alias collides with a pinned path", "pinned_path_alias");
    }
    const priorPinned = Object.values(oldPins).find((entry) => entry.path === safePath);
    if (priorPinned && (!this.snapshot.files[safePath]
      || this.snapshot.files[safePath].objectId !== priorPinned.objectId
      || this.snapshot.files[safePath].fileId !== priorPinned.fileId)) {
      fail("Pinned identity must not be silently replaced", "pinned_identity_changed");
    }
    await this._materializeOnDemand(safePath);
    const tracked = this.snapshot.files[safePath];
    if (!tracked || tracked.deleted || tracked.directory || !/^[a-f0-9]{64}$/.test(tracked.hash || "")) {
      fail("Only a verified hydrated regular file can be pinned", "cache_entry_unavailable");
    }
    if (priorPinned && (priorPinned.objectId !== tracked.objectId || priorPinned.fileId !== tracked.fileId)) {
      fail("Pinned identity changed during hydration", "pinned_identity_changed");
    }
    const previous = this.snapshot.pinnedFiles;
    this.snapshot.pinnedFiles = { ...oldPins,
      [pinnedKey(tracked.objectId)]: { objectId: tracked.objectId, fileId: tracked.fileId, path: safePath } };
    try { await this.persistSnapshot(); }
    catch (error) { this.snapshot.pinnedFiles = previous; throw error; }
    return { path: safePath, pinned: true, objectId: tracked.objectId };
  }

  async unpinLocal(relativePath) {
    return this.withMutationLock(() => this._unpinLocal(relativePath));
  }

  async _unpinLocal(relativePath) {
    if (!this.filesOnDemand) fail("Files On-Demand is not enabled", "files_on_demand_disabled");
    const safePath = await canonicalRelativePath(this.rootDir, relativePath);
    const previous = this.snapshot.pinnedFiles || {};
    const match = Object.values(previous).find((entry) => pathsEqual(entry.path, safePath));
    if (!match) return { path: safePath, pinned: false, applied: false };
    const next = { ...previous };
    delete next[pinnedKey(match.objectId)];
    this.snapshot.pinnedFiles = next;
    const priorPending = this.snapshot.pendingEvictions;
    if (this.isExcluded(safePath)) {
      // Exclusion may already be marked applied while retention prevented
      // eviction. Keep one durable retry intent together with the unpin,
      // so the next sync can apply its existing verified eviction path.
      this.snapshot.pendingEvictions = { ...(priorPending || {}),
        [match.objectId]: { path: safePath, code: "file_unpinned", attempts: 0 } };
    }
    try { await this.persistSnapshot(); }
    catch (error) {
      this.snapshot.pinnedFiles = previous;
      this.snapshot.pendingEvictions = priorPending;
      // A directory fsync can fail AFTER atomic rename: restoring only the
      // in-memory pin would leave a durably unpinned file on restart. Rewrite
      // the previous policy under the SAME root lock, fsync it and read it
      // back before returning the original failed-unpin error.
      try {
        await this.persistSnapshot();
        const disk = JSON.parse(await fsp.readFile(this.snapshotPath, "utf8"));
        if (JSON.stringify(disk.pinnedFiles || {}) !== JSON.stringify(previous)
          || JSON.stringify(disk.pendingEvictions || {}) !== JSON.stringify(priorPending || {})) {
          throw new Error("Compensated pin policy does not match durable snapshot");
        }
      } catch (rollbackError) {
        this.pinnedPolicyIndeterminate = true;
        throw Object.assign(new Error("Pinned policy persistence is indeterminate; recover the root explicitly", {
          cause: error,
        }), { code: "pinned_policy_indeterminate", rollbackCause: rollbackError });
      }
      throw error;
    }
    // Removing retention intent does not remove local bytes or write to server.
    return { path: safePath, pinned: false, applied: true };
  }

  async pinStatus(relativePath = null) {
    return this.withMutationLock(async () => {
      if (!this.filesOnDemand) fail("Files On-Demand is not enabled", "files_on_demand_disabled");
      const status = async (safePath) => {
        const pin = Object.values(this.snapshot.pinnedFiles || {}).find((entry) => pathsEqual(entry.path, safePath));
        const target = await contained(this.rootDir, safePath, true);
        const present = await exists(target);
        return { path: safePath, pinned: Boolean(pin), localPresent: present, objectId: pin?.objectId || null };
      };
      if (relativePath !== null) return status(await canonicalRelativePath(this.rootDir, relativePath));
      const all = Object.values(this.snapshot.pinnedFiles || {}).sort((a, b) => a.path.localeCompare(b.path));
      return { localOnly: true, files: await Promise.all(all.map((item) => status(item.path))) };
    });
  }

  async _evictLocal(relativePath, excludedTrackedPath = null, trustedCasefoldIndex = null, batchDurable = false) {
    if (this.requireNativeRootRecovery) denyUntrustedNativeEviction();
    if (!this.opened) await openEngineBuiltIn.call(this);
    // The internal exclusion path was already case-resolved with a bounded
    // directory index; do not enumerate the same Windows parent 640 times.
    const safePath = excludedTrackedPath === null
      ? await canonicalRelativePath(this.rootDir, relativePath)
      : protocol.safeRelativePath(relativePath, "path");
    const snapshotPath = excludedTrackedPath === null
      ? safePath : protocol.safeRelativePath(excludedTrackedPath, "trackedPath");
    if (!this.isInScope(safePath) || !this.isInScope(snapshotPath)) {
      fail("Only selected paths can be evicted", "path_not_selected");
    }
    if (excludedTrackedPath !== null) {
      if (!this.isExcluded(safePath) || !this.isExcluded(snapshotPath)
        || snapshotPath.toLowerCase() !== safePath.toLowerCase()
        || (trustedCasefoldIndex
          ? trustedCasefoldIndex.get(snapshotPath.toLowerCase()) !== snapshotPath
          : Object.keys(this.snapshot.files).filter((candidate) =>
            candidate.toLowerCase() === snapshotPath.toLowerCase()).length !== 1)) {
        fail("Excluded tracked path does not uniquely match the physical alias", "unsafe_path");
      }
    }
    const prior = this.snapshot.files[snapshotPath];
    if (!prior || prior.deleted || prior.directory || !/^[a-f0-9]{64}$/.test(prior.hash || "")) fail("Only a tracked file can be evicted", "cache_entry_unavailable");
    if (this.snapshot.pinnedFiles?.[pinnedKey(prior.objectId)]?.fileId === prior.fileId) {
      fail("Pinned file cannot be evicted before unpin", "file_pinned");
    }
    const pending = await this.journal.recover();
    if (pending.some((operation) => operation.objectId === prior.objectId
      || operation.metadata?.path === snapshotPath || operation.metadata?.sourcePath === snapshotPath
      || operation.metadata?.path === safePath || operation.metadata?.sourcePath === safePath)) {
      fail("A pending sync operation prevents cache eviction", "sync_operation_pending");
    }
    const target = await contained(this.rootDir, safePath, false);
    const before = await fsp.lstat(target, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink()) fail("Only regular files can be evicted", "unsafe_path");
    const bytes = await readContainedFile(this.rootDir, safePath, before);
    const hash = crypto.createHash("sha256").update(bytes).digest("hex");
    const afterRead = await fsp.lstat(target, { bigint: true });
    if (hash !== prior.hash || !sameFileVersion(before, afterRead)) fail("Local file changed since its last sync", "local_changes_pending");

    const remoteResult = await this.adapter.list(prior.objectId);
    const remoteRecords = Array.isArray(remoteResult) ? remoteResult
      : Array.isArray(remoteResult?.objects) ? remoteResult.objects : remoteResult ? [remoteResult] : [];
    if (remoteRecords.length !== 1) fail("Current remote object is unavailable", "remote_object_missing");
    const remote = protocol.validateStoredOperation(remoteRecords[0]);
    if (remote.objectId !== prior.objectId || remote.fileId !== prior.fileId
      || (excludedTrackedPath !== null ? remote.metadata.path !== snapshotPath
        : !pathsEqual(remote.metadata.path, safePath))) {
      fail("Current remote object no longer matches the local cache", "remote_object_changed");
    }
    // Eviction verifies an existing signed remote object but does not APPLY
    // that envelope. Its exact digest is separately persisted in PREPARE,
    // so a per-file observed[] journal fsync would be redundant and turn a
    // signed exclusion batch quadratic again.
    await this.verifyIncomingOperation(remote, { preObserve: false });
    if (remote.tombstone || remote.operation === "delete") fail("Current remote object has been deleted", "remote_object_deleted");
    const remoteKey = await this.keyFor(remote);
    const remotePlaintext = protocol.decryptPayload(remote, remoteKey);
    const remoteContent = remote.operation === "move"
      ? protocol.decodeMovePayload(remotePlaintext, remoteKey) || remotePlaintext
      : remotePlaintext;
    if (crypto.createHash("sha256").update(remoteContent).digest("hex") !== hash) {
      fail("Current remote content differs from the local cache", "remote_content_changed");
    }

    const beforeStage = await fsp.lstat(target, { bigint: true });
    if (!sameFileVersion(before, beforeStage)) fail("Local file changed during cache verification", "local_changes_pending");
    const confirmedBytes = await readContainedFile(this.rootDir, safePath, beforeStage);
    const afterConfirm = await fsp.lstat(target, { bigint: true });
    if (crypto.createHash("sha256").update(confirmedBytes).digest("hex") !== hash || !sameFileVersion(beforeStage, afterConfirm)) {
      fail("Local file changed during cache verification", "local_changes_pending");
    }

    const hadPriorMarker = Object.prototype.hasOwnProperty.call(this.snapshot.remoteOnly, prior.objectId);
    const priorMarker = hadPriorMarker ? this.snapshot.remoteOnly[prior.objectId] : undefined;
    const restoreMemoryMarker = () => {
      if (hadPriorMarker) this.snapshot.remoteOnly[prior.objectId] = priorMarker;
      else delete this.snapshot.remoteOnly[prior.objectId];
    };
    // Only used while the file is back at its path, so a failed rollback persist leaves a state the
    // next reconcile resolves (the file is local and the stale marker is dropped) without a remote delete.
    const rollbackEviction = async (cause) => {
      restoreMemoryMarker();
      // In a batch the small PREPARE already protects the crash window. The
      // previous full snapshot is still on disk, so no large rollback write
      // is needed before restoring the same physically present local file.
      if (batchDurable) throw cause;
      try {
        await this.persistSnapshot();
      } catch (persistError) {
        throw evictionError("eviction_rollback_failed", "Eviction rollback could not be persisted; the next sync reconciles this file", cause, persistError);
      }
      throw cause;
    };

    // The marker is committed before the file leaves its path, so the file is never outside its path
    // without a durable record that the remote object is the only copy.
    const evictedMarker = {
      objectId: remote.objectId, fileId: remote.fileId, versionId: remote.versionId,
      revision: remote.revision, path: snapshotPath, directory: false, deleted: false, reason: "evicted", hash,
    };
    const prepare = batchDurable ? {
      version: EVICTION_LEDGER_VERSION, tx: crypto.randomUUID(),
      objectId: prior.objectId, fileId: prior.fileId,
      path: snapshotPath, physical: safePath, hash, record: evictedMarker,
      remoteDigest: signedEnvelopeDigest(remote),
    } : null;
    if (prepare) {
      if (!this.evictionLedgerHead) {
        // Stage the genesis under v1-recognized .rootark-trash. Old v1
        // clients must NEVER see a new .rootark-sync-evictions name before
        // the incompatible v2 snapshot is durable.
        const { entries: pendingEntries, head: priorHead } =
          await readEvictionLedger(this.rootDir);
        if (pendingEntries.size || (priorHead
          && (priorHead.sequence !== 0 || priorHead.digest !== EVICTION_LEDGER_ZERO))) {
          fail("Unreconciled eviction ledger before snapshot upgrade", "invalid_snapshot");
        }
        // A prior zero-head is usable only when its old staged genesis has
        // actually disappeared. Concurrent/stale copies cannot be silently
        // combined with a fresh PREPARE: doing so would brick cold replay.
        if (priorHead && await stagedEvictionGenesis(this.rootDir)) {
          fail("Conflicting staged and active eviction genesis", "invalid_snapshot");
        }
        const staged = priorHead ? null : await createStagedEvictionGenesis(this.rootDir);
        const genesis = priorHead || staged.head;
        const priorVersion = this.snapshot.version;
        const priorEpoch = this.snapshot.evictionLedgerEpoch;
        const priorRequired = this.snapshot.evictionLedgerRequired;
        this.snapshot.version = EVICTION_LEDGER_SNAPSHOT_VERSION;
        this.snapshot.evictionLedgerEpoch = genesis.epoch;
        this.snapshot.evictionLedgerRequired = true;
        try { await this.persistSnapshot(); }
        catch (error) {
          this.snapshot.version = priorVersion;
          if (priorEpoch === undefined) delete this.snapshot.evictionLedgerEpoch;
          else this.snapshot.evictionLedgerEpoch = priorEpoch;
          if (priorRequired === undefined) delete this.snapshot.evictionLedgerRequired;
          else this.snapshot.evictionLedgerRequired = priorRequired;
          throw error;
        }
        if (staged) await promoteStagedEvictionGenesis(this.rootDir, staged);
        this.evictionLedgerHead = genesis;
      }
      if (this.snapshot.version !== EVICTION_LEDGER_SNAPSHOT_VERSION
        || this.snapshot.evictionLedgerEpoch !== this.evictionLedgerHead.epoch
        || this.snapshot.evictionLedgerRequired !== true) {
        fail("Eviction journal is not anchored to its durable snapshot", "invalid_snapshot");
      }
      prepare.epoch = this.evictionLedgerHead.epoch;
      prepare.sequence = this.evictionLedgerHead.sequence + 1;
      prepare.previousDigest = this.evictionLedgerHead.digest;
      try {
        this.evictionLedgerHead = await writeEvictionPrepare(this.rootDir,
          prepare, this.evictionLedgerHead);
      } catch (error) {
        throw evictionError("invalid_snapshot", "Eviction PREPARE durability is indeterminate", error);
      }
    }
    this.snapshot.remoteOnly[prior.objectId] = evictedMarker;
    try {
      if (!batchDurable) await this.persistSnapshot();
    } catch (error) {
      await rollbackEviction(error);
    }

    let staged;
    try {
      staged = await this.stageExisting(target);
      if (!staged) fail("Local cache entry disappeared during eviction", "cache_entry_unavailable");
    } catch (error) {
      // A stage helper can move the file and then fail. A durable PREPARE is
      // now the only restart-safe evidence that a missing local cache is not
      // a user-requested deletion. Never roll it back or compact it away.
      if (!(await exists(target))) {
        throw evictionError("eviction_restore_failed",
          "Eviction stage returned an error after the cache path disappeared; recover the durable PREPARE", error);
      }
      await rollbackEviction(error);
    }
    // Renames the staged copy back only if nothing now occupies the path. Never deletes the staged copy.
    const restoreStagedFile = async () => {
      if (await exists(target)) return false;
      await fsp.rename(staged, target);
      return true;
    };
    try {
      const stagedStats = await fsp.lstat(staged, { bigint: true });
      if (!stagedStats.isFile() || !sameFileIdentity(beforeStage, stagedStats) || stagedStats.size !== beforeStage.size
        || stagedStats.mtimeNs !== beforeStage.mtimeNs || stagedStats.mode !== beforeStage.mode) {
        fail("Local file changed during cache eviction", "unsafe_path");
      }
    } catch (error) {
      // The marker is committed and the file is out of its path. Restore the file when possible; otherwise
      // keep the eviction (marker stays) and the staged copy, so reconciliation never pushes a delete.
      let restored;
      try {
        restored = await restoreStagedFile();
      } catch (restoreError) {
        throw evictionError("eviction_restore_failed", "Eviction could not restore the local file; the staged copy is kept in the trash folder", error, restoreError);
      }
      if (!restored) throw evictionError("eviction_restore_failed", "The local path was recreated during eviction; the staged copy is kept in the trash folder", error);
      await rollbackEviction(error);
    }
    // The eviction is committed and the file is out of its path, so a failed cleanup only leaves the staged copy in the trash folder.
    await fsp.unlink(staged).catch(() => {});
    if (this.snapshot.files[snapshotPath]?.objectId === prior.objectId) delete this.snapshot.files[snapshotPath];
    if (prepare) await writeEvictionCommit(this.rootDir, prepare);
    else await this.persistSnapshot();
    return true;
  }

  async materializeRemote(relativePath) {
    return this.withMutationLock(() => this._materializeRemote(relativePath));
  }

  async _materializeRemote(relativePath) {
    if (!this.opened) await openEngineBuiltIn.call(this);
    const safePath = await canonicalRelativePath(this.rootDir, relativePath);
    if (!this.isSelected(safePath)) fail("Remote-only path is outside the selected scope", "path_not_selected");
    if (this.filesOnDemand) return this._materializeOnDemand(safePath);
    const matches = Object.values(this.snapshot.remoteOnly).filter((item) => pathsEqual(item.path, safePath));
    const activeMatches = matches.filter((item) => !item.deleted);
    if (activeMatches.length > 1) fail("More than one remote-only object matches this path", "remote_object_ambiguous");
    const entry = activeMatches[0] || matches[0];
    if (!entry) fail("No remote-only object is recorded for this path", "remote_object_unavailable");
    const result = await this.adapter.list(entry.objectId);
    const records = Array.isArray(result) ? result : Array.isArray(result?.objects) ? result.objects : result ? [result] : [];
    if (!records.length) fail("Remote object is no longer available", "remote_object_unavailable");
    const operation = envelopeCopy(protocol.validateStoredOperation(records[0]));
    if (operation.objectId !== entry.objectId || !this.operationDestinationIsSelected(operation)) {
      fail("Remote object is outside the selected scope", "path_not_selected");
    }
    const verifiedFreshDigest = await this.verifyIncomingOperation(operation, { preObserve: false });
    if (operation.tombstone) {
      if (verifiedFreshDigest) await this.journal.observeAdmission(operation.operationId, verifiedFreshDigest);
      this.rememberRemoteOnly(operation, entry.reason);
      await this.persistSnapshot();
      return false;
    }
    const appliedDigest = await this._apply(operation);
    await this.journal.markSeen(operation.operationId, verifiedFreshDigest || appliedDigest);
    return true;
  }

  async _materializeOnDemand(safePath) {
    if (Object.keys(this.journal.atomicSignedGroups?.() || {}).length) {
      fail("Cannot hydrate while a signed atomic sync batch is pending", "sync_atomic_batch_indeterminate");
    }
    const { matching } = await this.scanOnDemandInventory(safePath);
    if (!matching) fail("Remote object is not in the metadata inventory", "remote_object_unavailable");
    if (matching.tombstone) fail("Remote object has been deleted", "remote_object_deleted");

    const prior = this.snapshot.files[safePath];
    const target = await contained(this.rootDir, safePath, true);
    const evicted = this.snapshot.remoteOnly[matching.objectId];
    const checkLocalCache = async () => {
      const present = await exists(target);
      if (prior && !prior.deleted && (prior.objectId !== matching.objectId
        || prior.fileId !== matching.fileId || !present)) {
        fail("Tracked local file changed or disappeared", "local_changes_pending");
      }
      if (present) {
        if (!prior || prior.deleted || prior.directory || !/^[a-f0-9]{64}$/.test(prior.hash || "")) {
          fail("Untracked local file cannot be overwritten by hydration", "local_changes_pending");
        }
        const before = await fsp.lstat(target, { bigint: true });
        const bytes = await readContainedFile(this.rootDir, safePath, before);
        if (crypto.createHash("sha256").update(bytes).digest("hex") !== prior.hash) {
          fail("Local file changed since its last sync", "local_changes_pending");
        }
      } else if (evicted && (!pathsEqual(evicted.path, safePath) || evicted.deleted)) {
        fail("Evicted file no longer matches this path", "remote_object_changed");
      }
    };
    await checkLocalCache();
    const pending = await this.journal.recover();
    if (pending.some((operation) => operation.objectId === matching.objectId
      || operation.metadata?.path === safePath || operation.metadata?.sourcePath === safePath)) {
      fail("Pending local sync prevents hydration", "sync_operation_pending");
    }

    const result = await this.adapter.list(matching.objectId);
    const records = Array.isArray(result) ? result : Array.isArray(result?.objects) ? result.objects : result ? [result] : [];
    if (records.length !== 1) fail("Remote object is not available", "remote_object_unavailable");
    const operation = envelopeCopy(protocol.validateStoredOperation(records[0]));
    if (operation.objectId !== matching.objectId || operation.fileId !== matching.fileId
      || operation.versionId !== matching.versionId || operation.operationId !== matching.operationId
      || operation.tombstone !== matching.tombstone || operation.operation !== matching.operation
      || operation.keyEpoch !== matching.keyEpoch || operation.compartmentId !== matching.compartmentId
      || operation.deviceId !== matching.deviceId || operation.protocolVersion !== matching.protocolVersion
      || protocol.canonicalJson(operation.baseRevision) !== protocol.canonicalJson(matching.baseRevision)
      || protocol.canonicalJson(operation.revision) !== protocol.canonicalJson(matching.revision)
      || protocol.canonicalJson(operation.metadata) !== protocol.canonicalJson(matching.metadata)) {
      fail("Remote object changed since metadata inventory", "inventory_changed");
    }
    if (operation.metadata.contentType === "inode/directory") {
      fail("Files On-Demand materializes regular files only", "cache_entry_unavailable");
    }
    const moveKey = operation.operation === "move" ? await this.keyFor(operation) : null;
    const movePayload = moveKey
      ? protocol.decodeMovePayload(protocol.decryptPayload(operation, moveKey), moveKey) : null;
    if (moveKey && movePayload === null) {
      fail("Remote MOVE has no verified recovery payload", "move_source_missing");
    }
    const checkBeforeWrite = async () => {
      await checkLocalCache();
      if (!moveKey) return;
      const sourcePath = activeFileIdentityPath(this.snapshot.files, operation, safePath);
      if (!sourcePath) return;
      const source = await contained(this.rootDir, sourcePath, true);
      if (!(await exists(source))) return;
      const tracked = this.snapshot.files[sourcePath];
      const bytes = await readContainedFile(this.rootDir, sourcePath);
      const hash = crypto.createHash("sha256").update(bytes).digest("hex");
      if (!tracked || hash !== tracked.hash
        || !bytes.equals(movePayload)) {
        fail("Moved source has uncommitted local changes", "local_changes_pending");
      }
    };
    await checkBeforeWrite();
    const verifiedFreshDigest = await this._apply(operation, null, checkBeforeWrite);
    await this.journal.markSeen(operation.operationId, verifiedFreshDigest);
    return true;
  }

  async pullRemote(summary) {
    return this.withMutationLock(() => this._pullRemote(summary));
  }

  async _pullRemote(summary) {
    // A remotely visible single side of a just-committed/lost-ACK pair must
    // NOT consume that local pending ID via _apply, markSeen or the excluded-
    // path reconciliation path. Recover the atomic pair through its outbound
    // transaction/readback first; never split a journal group in pullRemote.
    if (Object.keys(this.journal.atomicSignedGroups?.() || {}).length) {
      fail("Remote pull blocked by pending atomic signed WebDAV batch",
        "sync_atomic_batch_indeterminate");
    }
    let result;
    try {
      result = await this.adapter.list();
    } catch (error) {
      if (transient(error)) { summary.offline = true; return; }
      throw error;
    }
    const records = Array.isArray(result) ? result : result?.objects;
    if (!Array.isArray(records)) fail("Sync pull returned an invalid record list", "invalid_pull");
    const rank = (operation) => {
      if (operation.tombstone || operation.operation === "delete") return 0;
      if (operation.metadata?.contentType === "inode/directory"
        || (operation.operation === "move" && activeIdentityPath(this.snapshot.files, operation, operation.metadata?.path))) return 1;
      return 2;
    };
    const ordered = [...records].sort((left, right) => {
      const rankDifference = rank(left) - rank(right);
      if (rankDifference) return rankDifference;
      if (rank(left) === 1) {
        const leftDepth = left.metadata.path.split("/").length;
        const rightDepth = right.metadata.path.split("/").length;
        if (leftDepth !== rightDepth) return leftDepth - rightDepth;
        const pathOrder = left.metadata.path.localeCompare(right.metadata.path);
        if (pathOrder) return pathOrder;
      }
      return String(left.objectId).localeCompare(String(right.objectId)) || String(left.versionId).localeCompare(String(right.versionId));
    });
    // Fail before touching any local state if this single untrusted response
    // contains incompatible signatures for one operation ID. Remote-only pins
    // are intentionally fsynced after the snapshot and cannot guard the batch.
    const batchDigests = new Map();
    const inspected = ordered.map((raw) => envelopeCopy(protocol.validateStoredOperation(raw)));
    for (const operation of inspected) {
      const digest = signedEnvelopeDigest(operation);
      this.journal.assertCompatibleAdmission(operation.operationId, digest);
      const previous = batchDigests.get(operation.operationId);
      if (previous !== undefined && previous !== digest) {
        fail("Conflicting local sync admission evidence", "remote_authorization_rejected");
      }
      batchDigests.set(operation.operationId, digest);
    }
    const REMOTE_ONLY_ADMISSION_BATCH = 128;
    const observedRemoteOnly = [];
    const flushRemoteOnly = async () => {
      if (!observedRemoteOnly.length) return;
      // Bounded durability boundaries: a 10k-object response must not hold
      // 10k unpromoted pre-observations until the very end of the LIST.
      // Fsync the current snapshot before converting any pin to applied.
      await this.persistSnapshot();
      for (const { operation, verifiedFreshDigest } of observedRemoteOnly) {
        await this.journal.markSeen(operation.operationId, verifiedFreshDigest);
      }
      observedRemoteOnly.length = 0;
    };
    for (const operation of inspected) {
      if (!this.operationDestinationIsSelected(operation)) {
        // A refused pinned origin must not consume the finite, durable
        // observed[] window before reconciliation rejects its signed MOVE.
        this.preflightOutOfScopeMove(operation);
        const verifiedFreshDigest = await this.verifyIncomingOperation(operation);
        await this.reconcileOutOfScopeMove(operation, summary);
        this.rememberRemoteOnly(operation, "excluded");
        observedRemoteOnly.push({ operation, verifiedFreshDigest });
        if (observedRemoteOnly.length >= REMOTE_ONLY_ADMISSION_BATCH) await flushRemoteOnly();
        continue;
      }
      const remoteOnly = this.snapshot.remoteOnly[operation.objectId];
      if (remoteOnly?.reason === "evicted") {
        const verifiedFreshDigest = await this.verifyIncomingOperation(operation);
        this.rememberRemoteOnly(operation, "evicted");
        observedRemoteOnly.push({ operation, verifiedFreshDigest });
        if (observedRemoteOnly.length >= REMOTE_ONLY_ADMISSION_BATCH) await flushRemoteOnly();
        continue;
      }
      // A folder re-included after an exclusion must hydrate even if this operation was seen before.
      if (this.journal.hasSeen(operation.operationId) && remoteOnly?.reason !== "excluded") {
        // The local seen JSON is mutable. In independently enforced historical
        // mode it cannot suppress verification of remote signed envelopes on
        // a restarted pull; a forged seen ID only risks local availability.
        if (this.reverifySeenIncoming) await this.verifyIncomingOperation(operation,
          { preObserve: false });
        continue;
      }
      const verifiedFreshDigest = await this._apply(operation, summary);
      await this.journal.markSeen(operation.operationId, verifiedFreshDigest);
      summary.pulled += 1;
    }
    await flushRemoteOnly();
  }

  // Applies the configured exclusions once per change. Excluded tracked files are evicted
  // through the guarded _evictLocal path; excluded files with no local copy become remote-only
  // records so that no remote delete can ever be pushed for them. Remote objects are never deleted.
  async _applyExcludedPaths() {
    const applied = this.snapshot.excludedPaths || [];
    const listChanged = JSON.stringify(applied) !== JSON.stringify(this.excludedPaths);
    // A pre-upgrade snapshot may claim that ["private"] was already applied
    // while retaining tracked "PRIVATE/secret.txt" bytes on POSIX. Revisit
    // those entries once even if the configured list has not changed.
    const needsCasefoldMigration = this.excludedPaths.length > 0
      && this.snapshot.excludedPathsCasefoldVersion !== EXCLUDED_PATHS_CASEFOLD_VERSION;
    // Exclusion-policy changes can cause automatic destructive eviction,
    // but the old path-based helper cannot establish native root custody.
    // Deny BEFORE creating retry state, inspecting mutable names, or
    // persisting exclusion policy / remote-only markers. A harmless no-op
    // with the same already-applied policy remains permitted.
    if (this.requireNativeRootRecovery && (listChanged || needsCasefoldMigration
      || Object.keys(this.snapshot.pendingEvictions || {}).length)) {
      denyUntrustedNativeEviction();
    }
    this.snapshot.pendingEvictions = this.snapshot.pendingEvictions || {};
    const pendingEvictions = this.snapshot.pendingEvictions;
    if (!listChanged && !needsCasefoldMigration && !Object.keys(pendingEvictions).length) return null;
    const report = { evicted: 0, released: 0, kept: [], failed: [] };
    let needsPersistence = listChanged || needsCasefoldMigration;
    const pending = await this.journal.recover();
    const excludedObjectIds = new Set();
    const directoryCache = new Map(); // never persist stale filesystem names across syncs
    // Never begin a ledger-backed destructive batch that cannot be fully
    // recovered within the bounded ledger reader's object limit.
    const candidateCount = Object.entries(this.snapshot.files).filter(([relative, prior]) =>
      !prior.deleted && !prior.directory && this.isExcluded(relative)
      && (listChanged || needsCasefoldMigration || pendingEvictions[prior.objectId])).length;
    if (candidateCount > EVICTION_LEDGER_MAX) {
      fail("Excluded cache migration exceeds durable ledger capacity", "eviction_capacity_exceeded");
    }
    const snapshotCasefoldIndex = new Map();
    for (const relative of Object.keys(this.snapshot.files)) {
      const folded = relative.toLowerCase();
      if (snapshotCasefoldIndex.has(folded)) snapshotCasefoldIndex.set(folded, null);
      else snapshotCasefoldIndex.set(folded, relative);
    }
    for (const [relative, prior] of Object.entries(this.snapshot.files)) {
      if (prior.deleted || prior.directory || !this.isExcluded(relative)) continue;
      const retry = pendingEvictions[prior.objectId];
      if (!listChanged && !needsCasefoldMigration && !retry) continue;
      excludedObjectIds.add(prior.objectId);
      if (this.snapshot.pinnedFiles?.[pinnedKey(prior.objectId)]?.fileId === prior.fileId) {
        if (retry) needsPersistence = true;
        delete pendingEvictions[prior.objectId];
        report.kept.push({ path: relative, code: "file_pinned" });
        continue;
      }
      if (retry && retry.attempts >= MAX_EVICTION_ATTEMPTS) {
        report.failed.push({ path: relative, code: retry.code });
        continue;
      }
      // A path may be renamed only by case after the migration watch was
      // stored. A missing old-cased path on POSIX is not proof of no local
      // bytes; on Windows the filesystem may canonicalize to a different key.
      const physicalPath = await uniqueExcludedPhysicalPath(this.rootDir, relative, directoryCache);
      const target = physicalPath === null ? null : await contained(this.rootDir, physicalPath, false);
      // A dirty legacy alias is kept until its local file metadata changes.
      // With no change, do not hash potentially large private bytes repeatedly.
      // The final eviction still compares complete remote and local content.
      // A failed metadata probe provides NO safe version evidence. Abort this
      // pass (preserving the durable dirty watch / pending migration marker)
      // rather than converting an EIO into terminal local_changes_pending.
      const localVersionStamp = target === null ? null
        : evictionFileVersionStamp(await fsp.lstat(target, { bigint: true }));
      if (retry?.code === "local_changes_pending" && localVersionStamp
        && localVersionStamp === retry.localVersionStamp
        && physicalPath === retry.localPath) continue;
      if (pending.some((operation) => operation.objectId === prior.objectId
        || operation.metadata?.path === relative || operation.metadata?.sourcePath === relative)) {
        // The pending operation must settle first. Preserve a dirty-file watch
        // so an alias that became clean during that operation is not stranded.
        if (!retry) {
          pendingEvictions[prior.objectId] = {
            path: relative, code: "sync_operation_pending", attempts: 0,
          };
          needsPersistence = true;
        }
        report.kept.push({ path: relative, code: "sync_operation_pending" });
        continue;
      }
      needsPersistence = true;
      delete pendingEvictions[prior.objectId];
      if (target === null || !(await exists(target))) {
        this.snapshot.remoteOnly[prior.objectId] = {
          objectId: prior.objectId, fileId: prior.fileId, versionId: prior.versionId, revision: prior.revision,
          path: relative, directory: false, deleted: false, reason: "excluded", ...(prior.hash ? { hash: prior.hash } : {}),
        };
        delete this.snapshot.files[relative];
        report.released += 1;
        continue;
      }
      try {
        await this._evictLocal(physicalPath, relative, snapshotCasefoldIndex, true);
        await observeVerifiedExcludedEviction(this.rootDir, physicalPath, directoryCache);
        report.evicted += 1;
      } catch (error) {
        if (["invalid_snapshot", "eviction_restore_failed", "eviction_rollback_failed"].includes(error?.code)) {
          // The file may be out of its former path while the durable
          // PREPARE is the only crash-recovery witness. Never compact away
          // that witness after a failed physical restore/ledger mutation.
          throw error;
        }
        await refreshExcludedInternalRoot(this.rootDir, directoryCache);
        const code = error?.code || "unknown";
        // Transient failures (for example a file held open on Windows) are retried on later cycles, up to a bound.
        // Dirty local edits are retained, and rechecked only after an observed
        // local metadata change; other nontransient failures are durably quarantined.
        if (TRANSIENT_EVICTION_CODES.has(code) || code === "cache_entry_unavailable") {
          const attempts = (retry?.attempts || 0) + 1;
          pendingEvictions[prior.objectId] = { path: relative, code, attempts };
          if (attempts >= MAX_EVICTION_ATTEMPTS) report.failed.push({ path: relative, code });
          else report.kept.push({ path: relative, code });
        } else if (code === "local_changes_pending" && localVersionStamp) {
          pendingEvictions[prior.objectId] = {
            path: relative, code, attempts: 0, localVersionStamp, localPath: physicalPath,
          };
          report.kept.push({ path: relative, code });
        } else if (code === "sync_operation_pending") {
          // An operation can arrive after the initial journal check. Retain
          // its retry intent until the operation settles, as above.
          pendingEvictions[prior.objectId] = { path: relative, code, attempts: 0 };
          report.kept.push({ path: relative, code });
        } else {
          // A rejected physical alias must never be considered migrated. A
          // bounded durable failure remains visible across restarts without
          // retrying an unsafe unlink or scanning the tree indefinitely.
          pendingEvictions[prior.objectId] = {
            path: relative, code, attempts: MAX_EVICTION_ATTEMPTS,
          };
          report.failed.push({ path: relative, code });
        }
      }
    }
    // Drop retry records for objects that are no longer tracked as excluded local files.
    for (const objectId of Object.keys(pendingEvictions)) {
      if (!excludedObjectIds.has(objectId)) {
        delete pendingEvictions[objectId];
        needsPersistence = true;
      }
    }
    await verifyExcludedDirectoryIndexes(directoryCache);
    if (!needsPersistence) return report.failed.length || report.kept.length ? report : null;
    if (Object.keys(pendingEvictions).length) this.snapshot.pendingEvictions = pendingEvictions;
    else delete this.snapshot.pendingEvictions;
    // The applied list is stored only when exclusions are configured, so snapshots of devices that never use them keep their existing shape.
    if (this.excludedPaths.length) {
      this.snapshot.excludedPaths = [...this.excludedPaths];
      // Every tracked entry has been checked. Locally dirty legacy aliases
      // retain a durable version watch until safely evicted, while pinned
      // entries remain under explicit retention and unpin retry semantics.
      this.snapshot.excludedPathsCasefoldVersion = EXCLUDED_PATHS_CASEFOLD_VERSION;
    } else {
      delete this.snapshot.excludedPaths;
      delete this.snapshot.excludedPathsCasefoldVersion;
    }
    const compacting = this.evictionLedgerHead !== null;
    if (compacting) {
      // Verify that the on-disk chain still contains every PREPARE produced
      // in this batch before retiring the active flag. The full checkpoint
      // is already populated with remote-only markers for staged files.
      const { head } = await readEvictionLedger(this.rootDir, this.snapshot.evictionLedgerEpoch);
      if (!head || this.snapshot.evictionLedgerRequired !== true
        || head.epoch !== this.evictionLedgerHead.epoch
        || head.sequence !== this.evictionLedgerHead.sequence
        || head.digest !== this.evictionLedgerHead.digest) {
        fail("Active eviction ledger changed before durable checkpoint", "invalid_snapshot");
      }
      this.snapshot.evictionLedgerRequired = false;
    }
    try { await this.persistSnapshot(); }
    catch (error) {
      if (compacting) this.snapshot.evictionLedgerRequired = true;
      throw error;
    }
    await clearEvictionLedger(this.rootDir, this.snapshot.evictionLedgerEpoch || null);
    this.evictionLedgerHead = null;
    return report;
  }

  async syncOnce() {
    return this.withMutationLock(() => this._syncOnce());
  }

  async _syncOnce() {
    if (!this.opened) await openEngineBuiltIn.call(this);
    const summary = { pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false };
    let excluded;
    try { excluded = await this._applyExcludedPaths(); }
    catch (error) {
      // A partial batch may have durable PREPARE records but no compacted
      // snapshot yet. Reopen from disk and replay them under the next lock,
      // rather than retaining a speculative in-memory snapshot after EIO.
      this.opened = false;
      this.snapshotDiskRevision = null;
      this.evictionLedgerHead = null;
      throw error;
    }
    if (excluded) summary.excluded = excluded;
    await this._reconcileLocal();
    await this._pushPending(summary);
    if (!summary.offline) {
      if (this.filesOnDemand) {
        try {
          summary.available = (await this.scanOnDemandInventory()).available;
        } catch (error) {
          if (transient(error)) summary.offline = true;
          else throw error;
        }
      } else await this._pullRemote(summary);
    }
    return summary;
  }
}

// Captured once while loading the trusted module. A caller or callback may
// override an engine method, but cannot authorize an unverified native replay
// by replacing this local binding. This is not OS-level writer custody.
const replayEvictionLedgerBuiltIn = SyncEngine.prototype.replayEvictionLedger;
const openEngineBuiltIn = SyncEngine.prototype._open;

module.exports = { SyncEngine, contained, containedAbsolute, normalizeExcludedPaths };
