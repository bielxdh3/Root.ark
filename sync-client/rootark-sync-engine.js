"use strict";

const crypto = require("node:crypto");
const { AsyncLocalStorage } = require("node:async_hooks");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");

const protocol = require("./rootark-sync-protocol");
const { SyncJournal } = require("./rootark-sync-journal");
const { SyncConflictError } = require("../public/client/rootark-sync-adapter");

const SNAPSHOT_VERSION = 1;
const INTERNAL_NAMES = new Set([".rootark-trash", ".rootark-conflicts", ".rootark-sync-journal.json", ".rootark-sync-index.json", ".rootark-sync.lock"]);
const INTERNAL_NAME_PREFIXES = [".rootark-sync-lock-init-"];
const ROOT_MUTATION_QUEUES = new Map();
const ROOT_MUTATION_CONTEXT = new AsyncLocalStorage();

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

function isWithinPath(root, target) {
  const relative = path.relative(root, target);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

async function readContainedFile(rootDir, relativePath, expectedStats = null) {
  const root = path.resolve(rootDir);
  const target = await contained(root, relativePath, false);
  const before = expectedStats || await fsp.lstat(target, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.ino === 0n) {
    fail("Sync file must be a regular file with a stable identity", "unsafe_path");
  }

  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  const handle = await fsp.open(target, flags);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameFileVersion(before, opened)) fail("Sync file changed while opening", "unsafe_path");

    await containedAbsolute(root, target, false);
    const canonicalRoot = await fsp.realpath(root);
    const canonicalTarget = await fsp.realpath(target);
    if (!isWithinPath(canonicalRoot, canonicalTarget)) fail("Sync file escaped root", "unsafe_path");
    const pathStats = await fsp.lstat(target, { bigint: true });
    if (!pathStats.isFile() || pathStats.isSymbolicLink() || !sameFileIdentity(opened, pathStats)) {
      fail("Sync file changed while opening", "unsafe_path");
    }

    const data = await handle.readFile();
    const openedAfterRead = await handle.stat({ bigint: true });
    const pathAfterRead = await fsp.lstat(target, { bigint: true });
    if (!sameFileVersion(opened, openedAfterRead) || !sameFileIdentity(openedAfterRead, pathAfterRead)
      || !pathAfterRead.isFile() || pathAfterRead.isSymbolicLink()) {
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
    await fsp.rename(temporary, filePath);
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

function pathKey(relativePath) {
  return process.platform === "win32" ? relativePath.toLowerCase() : relativePath;
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
    this.verifyIncoming = options.verifyIncoming || null;
    this.authorizationFactory = options.authorizationFactory || null;
    this.requireAuthorization = options.requireAuthorization === true;
    this.translateWebDavOperation = options.translateWebDavOperation || null;
    this.maxRetries = Math.max(1, Math.min(5, Number(options.maxRetries || 3)));
    if (options.selectedPaths != null && !Array.isArray(options.selectedPaths)) fail("Selected paths must be an array", "invalid_selected_paths");
    this.selectedPaths = options.selectedPaths == null ? null : [...new Set(options.selectedPaths.map((value) => protocol.safeRelativePath(value, "selectedPath")))].sort();
    this.snapshot = { version: SNAPSHOT_VERSION, files: {}, remoteOnly: {} };
    this.snapshotDiskRevision = null;
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
        await this._open();
        return await ROOT_MUTATION_CONTEXT.run(queueKey, work);
      } finally {
        await this.releaseProcessLock(processLock);
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
      if (parsed.version !== SNAPSHOT_VERSION || !parsed.files || typeof parsed.files !== "object" || Array.isArray(parsed.files)) fail("Invalid sync snapshot", "invalid_snapshot");
      if (parsed.remoteOnly === undefined) parsed.remoteOnly = {};
      if (!parsed.remoteOnly || typeof parsed.remoteOnly !== "object" || Array.isArray(parsed.remoteOnly)) fail("Invalid remote-only sync state", "invalid_snapshot");
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
    this.opened = true;
    return this;
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

  async verifyIncomingOperation(operation) {
    if (this.verifyIncoming && await this.verifyIncoming(operation) !== true) fail("Remote sync authorization rejected", "remote_authorization_rejected");
  }

  isSelected(relativePath) {
    return this.selectedPaths === null || this.selectedPaths.some((selected) => pathWithin(relativePath, selected));
  }

  needsTraversal(relativePath) {
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

  rememberRemoteOnly(operation, reason) {
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
      directory: operation.metadata.contentType === "inode/directory" || prior.directory === true,
      deleted: Boolean(operation.tombstone),
      reason: prior.reason === "evicted" ? "evicted" : reason,
      ...(prior.hash ? { hash: prior.hash } : {}),
    };
  }

  async reconcileOutOfScopeMove(operation, summary, options = {}) {
    const directoryMove = operation.operation === "update" && operation.metadata?.contentType === "inode/directory";
    if ((operation.operation !== "move" && !directoryMove) || operation.tombstone
      || typeof operation.metadata?.path !== "string" || this.isSelected(operation.metadata.path)) return false;
    if (!directoryMove && !operation.metadata?.sourcePath) return false;

    const sourcePath = directoryMove
      ? activeIdentityPath(this.snapshot.files, operation, operation.metadata.path)
      : activeFileIdentityPath(this.snapshot.files, operation, operation.metadata.path)
        || (this.snapshot.files[operation.metadata.sourcePath]?.objectId === operation.objectId
        && this.snapshot.files[operation.metadata.sourcePath]?.fileId === operation.fileId
        && !this.snapshot.files[operation.metadata.sourcePath]?.deleted
        && !this.snapshot.files[operation.metadata.sourcePath]?.directory
        ? operation.metadata.sourcePath : null);
    if (!sourcePath || !this.isSelected(sourcePath)) return false;

    const prior = this.snapshot.files[sourcePath];
    if (!prior || prior.deleted || Boolean(prior.directory) !== directoryMove
      || prior.objectId !== operation.objectId || prior.fileId !== operation.fileId) return false;

    const pending = (await this.journal.recover()).filter((item) => item.protocolVersion && item.objectId === operation.objectId);
    const target = await contained(this.rootDir, sourcePath, true);
    const sourceExists = await exists(target);
    let changedLocally = false;
    if (sourceExists) {
      const stats = await fsp.lstat(target, { bigint: true });
      if (stats.isSymbolicLink() || (directoryMove ? !stats.isDirectory() : !stats.isFile())) {
        fail("Tracked sync source has an unexpected type", "unsafe_path");
      }
      if (directoryMove) {
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
      if (sourceExists && !directoryMove) {
        const conflictRoot = path.join(this.rootDir, ".rootark-conflicts");
        await fsp.mkdir(conflictRoot, { recursive: true });
        await containedAbsolute(this.rootDir, conflictRoot, false);
        const operationKey = crypto.createHash("sha256").update(operation.operationId).digest("hex").slice(0, 16);
        const conflictPath = path.join(conflictRoot, `${operationKey}-${crypto.randomUUID()}.local.conflict`);
        await containedAbsolute(this.rootDir, conflictPath, true);
        await fsp.rename(target, conflictPath);
      }
      if (!directoryMove && !options.preservedOperationIds?.includes(operation.operationId)) await this.recoverConflict(operation, summary);
      summary.conflicts ||= [];
      if (!options.conflictAlreadyRecorded && !summary.conflicts.some((conflict) => conflict.operationId === operation.operationId)) {
        summary.conflicts.push({ operationId: operation.operationId, policy: "preserve-local-and-remote", reason: "remote-move-outside-selected-scope" });
      }
    } else if (sourceExists) {
      if (!directoryMove) {
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
    this.rememberRemoteOnly(operation, "excluded");
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
    if (await this.authorizeOutgoing(operation) !== true) fail("Local sync authorization rejected", "authorization_rejected");
    if (this.authorizationFactory) operation.authorization = await this.authorizationFactory(operation);
    else if (this.requireAuthorization) fail("Device authorization is required", "authorization_required");
    return operation;
  }

  async enqueueChange(input) {
    return this.withMutationLock(() => this._enqueueChange(input));
  }

  async _enqueueChange(input) {
    if (!this.opened) await this._open();
    const remoteOnly = this.snapshot.remoteOnly[input.objectId];
    if (remoteOnly?.reason === "evicted") fail("Materialize a remote-only file before enqueuing changes", "remote_only_object");
    const key = input.fileKey || await this.fileKeyResolver(input);
    const operation = protocol.validateOperation(await this.buildOperation({ ...input, fileKey: key }));
    await this.journal.enqueue(operation);
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
    const operationPrefix = `webdav-${event.operationId}-`;
    const pendingForEvent = (await this.journal.recover()).filter((operation) => typeof operation.operationId === "string" && operation.operationId.startsWith(operationPrefix));
    if (pendingForEvent.length) return pendingForEvent;
    if (this.journal.state?.seen?.some((operationId) => typeof operationId === "string" && operationId.startsWith(operationPrefix))) return [];
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
    const stableOperationId = (relativePath) => `webdav-${event.operationId}-${crypto.createHash("sha256").update(relativePath).digest("hex").slice(0, 24)}`;
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
      try { return await this.adapter.push(operation); } catch (error) {
        lastError = error;
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

  async _pushPending(summary) {
    for (const original of await this.journal.recover()) {
      if (this.journal.hasSeen(original.operationId)) continue;
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
        const result = await this.retryPush(operation);
        if (result?.status >= 400) {
          if (result.status !== 409) fail("Sync push rejected", "push_rejected");
          throw new SyncConflictError(result);
        }
        if (operation.operation === "move" || operation.operation === "delete") {
          const hash = operation.operation === "move" ? await this.hashPendingPayload(operation) : undefined;
          this.rememberOperation(operation, hash);
          await this.persistSnapshot();
        } else {
          const hash = await this.hashPendingPayload(operation);
          this.rememberOperation(operation, hash);
          await this.persistSnapshot();
        }
        await this.journal.markSeen(operation.operationId);
        summary.pushed += 1;
      } catch (error) {
        if (error instanceof SyncConflictError || error?.status === 409 || error?.code === "sync_conflict") {
          summary.conflicts.push({ operationId: operation?.operationId || pending.operationId, policy: "remote-wins", currentRevision: error.currentRevision || error.payload?.currentRevision || null });
          await this.recoverConflict(operation, summary);
          if (error.current) {
            const current = protocol.validateOperation(error.current);
            if (this.operationDestinationIsSelected(current)) {
              await this._apply(current, summary);
            } else {
              await this.verifyIncomingOperation(current);
              const reconciled = await this.reconcileOutOfScopeMove(current, summary, {
                preservedOperationIds: [operation.operationId], conflictAlreadyRecorded: true,
              });
              if (!reconciled) {
                this.rememberRemoteOnly(current, "excluded");
                await this.persistSnapshot();
              }
            }
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
    if (!(await exists(target))) return null;
    const trashDir = path.join(this.rootDir, ".rootark-trash");
    await fsp.mkdir(trashDir, { recursive: true });
    await containedAbsolute(this.rootDir, trashDir, false);
    const trashTarget = path.join(trashDir, `${Date.now()}-${crypto.randomUUID()}-${path.basename(target)}`);
    await containedAbsolute(this.rootDir, trashTarget, true);
    await fsp.rename(target, trashTarget);
    return trashTarget;
  }

  async apply(operation, summary = null) {
    return this.withMutationLock(() => this._apply(operation, summary));
  }

  async _apply(operation, summary = null) {
    await this.verifyIncomingOperation(operation);
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
        return;
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
      const eviction = this.snapshot.remoteOnly[prior.objectId];
      if (eviction?.reason === "evicted" && pathsEqual(eviction.path, relative)) {
        delete this.snapshot.files[relative];
        continue;
      }
      const key = await this.fileKeyResolver(prior);
      const operation = await this.buildOperation({ operation: "delete", objectId: prior.objectId, fileId: prior.fileId, versionId: crypto.randomUUID(), baseRevision: prior.revision, revision: { counter: (prior.revision?.counter || 0) + 1, deviceId: this.deviceId }, metadata: { path: relative }, fileKey: key });
      await this.journal.enqueue(operation);
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
      await this.journal.enqueue(operation);
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
    delete this.snapshot.remoteOnly[operation.objectId];
  }

  async evictLocal(relativePath) {
    return this.withMutationLock(() => this._evictLocal(relativePath));
  }

  async _evictLocal(relativePath) {
    if (!this.opened) await this._open();
    const safePath = await canonicalRelativePath(this.rootDir, relativePath);
    if (!this.isSelected(safePath)) fail("Only selected paths can be evicted", "path_not_selected");
    const prior = this.snapshot.files[safePath];
    if (!prior || prior.deleted || prior.directory || !/^[a-f0-9]{64}$/.test(prior.hash || "")) fail("Only a tracked file can be evicted", "cache_entry_unavailable");
    const pending = await this.journal.recover();
    if (pending.some((operation) => operation.objectId === prior.objectId
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
    const remote = protocol.validateOperation(remoteRecords[0]);
    if (remote.objectId !== prior.objectId || remote.fileId !== prior.fileId || !pathsEqual(remote.metadata.path, safePath)) {
      fail("Current remote object no longer matches the local cache", "remote_object_changed");
    }
    await this.verifyIncomingOperation(remote);
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

    this.snapshot.remoteOnly[prior.objectId] = {
      objectId: remote.objectId, fileId: remote.fileId, versionId: remote.versionId,
      revision: remote.revision, path: safePath, directory: false, deleted: false, reason: "evicted", hash,
    };
    await this.persistSnapshot();
    const staged = await this.stageExisting(target);
    if (!staged) fail("Local cache entry disappeared during eviction", "cache_entry_unavailable");
    const stagedStats = await fsp.lstat(staged, { bigint: true });
    if (!stagedStats.isFile() || !sameFileIdentity(beforeStage, stagedStats) || stagedStats.size !== beforeStage.size
      || stagedStats.mtimeNs !== beforeStage.mtimeNs || stagedStats.mode !== beforeStage.mode) {
      if (!(await exists(target))) await fsp.rename(staged, target);
      fail("Local file changed during cache eviction", "unsafe_path");
    }
    await fsp.unlink(staged);
    if (this.snapshot.files[safePath]?.objectId === prior.objectId) delete this.snapshot.files[safePath];
    await this.persistSnapshot();
    return true;
  }

  async materializeRemote(relativePath) {
    return this.withMutationLock(() => this._materializeRemote(relativePath));
  }

  async _materializeRemote(relativePath) {
    if (!this.opened) await this._open();
    const safePath = await canonicalRelativePath(this.rootDir, relativePath);
    if (!this.isSelected(safePath)) fail("Remote-only path is outside the selected scope", "path_not_selected");
    const matches = Object.values(this.snapshot.remoteOnly).filter((item) => pathsEqual(item.path, safePath));
    const activeMatches = matches.filter((item) => !item.deleted);
    if (activeMatches.length > 1) fail("More than one remote-only object matches this path", "remote_object_ambiguous");
    const entry = activeMatches[0] || matches[0];
    if (!entry) fail("No remote-only object is recorded for this path", "remote_object_unavailable");
    const result = await this.adapter.list(entry.objectId);
    const records = Array.isArray(result) ? result : Array.isArray(result?.objects) ? result.objects : result ? [result] : [];
    if (!records.length) fail("Remote object is no longer available", "remote_object_unavailable");
    const operation = protocol.validateOperation(records[0]);
    if (operation.objectId !== entry.objectId || !this.operationDestinationIsSelected(operation)) {
      fail("Remote object is outside the selected scope", "path_not_selected");
    }
    await this.verifyIncomingOperation(operation);
    if (operation.tombstone) {
      this.rememberRemoteOnly(operation, entry.reason);
      await this.persistSnapshot();
      return false;
    }
    await this._apply(operation);
    await this.journal.markSeen(operation.operationId);
    return true;
  }

  async pullRemote(summary) {
    return this.withMutationLock(() => this._pullRemote(summary));
  }

  async _pullRemote(summary) {
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
    let remoteOnlyChanged = false;
    for (const raw of ordered) {
      const operation = protocol.validateOperation(raw);
      if (!this.operationDestinationIsSelected(operation)) {
        await this.verifyIncomingOperation(operation);
        await this.reconcileOutOfScopeMove(operation, summary);
        this.rememberRemoteOnly(operation, "excluded");
        remoteOnlyChanged = true;
        continue;
      }
      const remoteOnly = this.snapshot.remoteOnly[operation.objectId];
      if (remoteOnly?.reason === "evicted") {
        await this.verifyIncomingOperation(operation);
        this.rememberRemoteOnly(operation, "evicted");
        remoteOnlyChanged = true;
        continue;
      }
      if (this.journal.hasSeen(operation.operationId)) continue;
      await this._apply(operation, summary);
      await this.journal.markSeen(operation.operationId);
      summary.pulled += 1;
    }
    if (remoteOnlyChanged) await this.persistSnapshot();
  }

  async syncOnce() {
    return this.withMutationLock(() => this._syncOnce());
  }

  async _syncOnce() {
    if (!this.opened) await this._open();
    const summary = { pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false };
    await this._reconcileLocal();
    await this._pushPending(summary);
    if (!summary.offline) await this._pullRemote(summary);
    return summary;
  }
}

module.exports = { SyncEngine, contained, containedAbsolute };
