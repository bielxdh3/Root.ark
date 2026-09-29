"use strict";

const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const path = require("node:path");

const protocol = require("./rootark-sync-protocol");
const { SyncJournal } = require("./rootark-sync-journal");
const { SyncConflictError } = require("../public/client/rootark-sync-adapter");

const SNAPSHOT_VERSION = 1;
const INTERNAL_NAMES = new Set([".rootark-trash", ".rootark-conflicts", ".rootark-sync-journal.json", ".rootark-sync-index.json"]);

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

async function durableJson(filePath, value) {
  const temporary = `${filePath}.tmp-${process.pid}-${crypto.randomUUID()}`;
  await fsp.writeFile(temporary, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await fsp.rename(temporary, filePath);
}

function normalizeWebDavPath(value) {
  let decoded;
  try { decoded = decodeURIComponent(String(value || "")); } catch { fail("Invalid WebDAV path", "unsafe_path"); }
  return protocol.safeRelativePath(decoded.replace(/^\/+|\/+$/g, ""), "path");
}

function pathWithin(relativePath, parentPath) {
  return relativePath === parentPath || relativePath.startsWith(`${parentPath}/`);
}

function activeIdentityPath(files, operation, exceptPath) {
  return Object.entries(files).find(([relativePath, prior]) => relativePath !== exceptPath
    && !prior.deleted && prior.directory
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
    this.snapshot = { version: SNAPSHOT_VERSION, files: {} };
    this.opened = false;
  }

  async open() {
    await fsp.mkdir(this.rootDir, { recursive: true });
    await containedAbsolute(this.rootDir, this.rootDir, false);
    this.journal = await this.journal.open();
    try {
      const parsed = JSON.parse(await fsp.readFile(this.snapshotPath, "utf8"));
      if (parsed.version !== SNAPSHOT_VERSION || !parsed.files || typeof parsed.files !== "object") throw new Error("Invalid sync snapshot");
      this.snapshot = parsed;
    } catch (error) {
      if (error.code !== "ENOENT") fail("Invalid sync snapshot", "invalid_snapshot");
      await durableJson(this.snapshotPath, this.snapshot);
    }
    this.opened = true;
    return this;
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

  async buildOperation(input) {
    const key = input.fileKey || await this.fileKeyResolver(input);
    let operationInput = input;
    if (input.operation === "move") {
      let movePlaintext = input.plaintext;
      if (movePlaintext === undefined) {
        const target = await contained(this.rootDir, input.metadata?.path, false);
        const stats = await fsp.lstat(target);
        if (stats.isFile()) movePlaintext = await fsp.readFile(target);
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
    if (!this.opened) await this.open();
    const key = input.fileKey || await this.fileKeyResolver(input);
    const operation = protocol.validateOperation(await this.buildOperation({ ...input, fileKey: key }));
    await this.journal.enqueue(operation);
    let hash;
    if (operation.operation === "move") {
      const plaintext = protocol.decodeMovePayload(protocol.decryptPayload(operation, key), key);
      if (plaintext !== null) hash = crypto.createHash("sha256").update(plaintext).digest("hex");
    }
    this.rememberOperation(operation, hash);
    await durableJson(this.snapshotPath, this.snapshot);
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
    const sourcePath = normalizeWebDavPath(event.source || event.path);
    const destinationPath = normalizeWebDavPath(event.destination || event.path || event.source);
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
    const operations = [];
    const mappedSourcePaths = new Set();
    const stableOperationId = (relativePath) => `webdav-${event.operationId}-${crypto.createHash("sha256").update(relativePath).digest("hex").slice(0, 24)}`;
    const identityFor = (relativePath, prior) => ({
      objectId: prior?.objectId || `object-${crypto.createHash("sha256").update(relativePath).digest("hex").slice(0, 32)}`,
      fileId: prior?.fileId || `file-${crypto.createHash("sha256").update(relativePath).digest("hex").slice(0, 32)}`,
    });
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
      const content = await fsp.readFile(await contained(this.rootDir, relativePath, false));
      if (sourceIsActive && destinationIsActive && priorSource.objectId !== priorDestination.objectId) {
        mappedSourcePaths.add(sourcePath);
        operations.push(await buildForPath({ operation: "delete", relativePath: sourcePath, prior: priorSource }));
        operations.push(await buildForPath({ operation: "update", relativePath, prior: priorDestination, content, directory: false }));
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
          && priorDestination && !priorDestination.deleted && priorDestination.objectId !== priorSource.objectId) {
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

        const content = await fsp.readFile(await contained(this.rootDir, relativePath, false));
        if (sourceIsActive && destinationIsActive && priorSource.objectId !== priorDestination.objectId) {
          operations.push(await buildForPath({ operation: "delete", relativePath: oldPath, prior: priorSource }));
          operations.push(await buildForPath({ operation: "update", relativePath, prior: priorDestination, content, directory: false }));
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
    for (const original of await this.journal.recover()) {
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
        const result = await this.retryPush(operation);
        if (result?.status >= 400) {
          if (result.status !== 409) fail("Sync push rejected", "push_rejected");
          throw new SyncConflictError(result);
        }
        if (operation.operation === "move" || operation.operation === "delete") {
          let hash;
          if (operation.operation === "move") {
            const movedPath = await contained(this.rootDir, operation.metadata.path, true);
            if (await exists(movedPath)) {
              const movedStats = await fsp.lstat(movedPath);
              if (movedStats.isFile()) hash = crypto.createHash("sha256").update(await fsp.readFile(movedPath)).digest("hex");
              else if (movedStats.isDirectory()) hash = crypto.createHash("sha256").update(Buffer.alloc(0)).digest("hex");
            }
          }
          this.rememberOperation(operation, hash);
          await durableJson(this.snapshotPath, this.snapshot);
        } else {
          const target = await contained(this.rootDir, operation.metadata.path, true);
          let hash;
          if (operation.metadata.contentType === "inode/directory") hash = crypto.createHash("sha256").update(Buffer.alloc(0)).digest("hex");
          else if (await exists(target) && (await fsp.lstat(target)).isFile()) hash = crypto.createHash("sha256").update(await fsp.readFile(target)).digest("hex");
          this.rememberOperation(operation, hash);
          await durableJson(this.snapshotPath, this.snapshot);
        }
        await this.journal.markSeen(operation.operationId);
        summary.pushed += 1;
      } catch (error) {
        if (error instanceof SyncConflictError || error?.status === 409 || error?.code === "sync_conflict") {
          summary.conflicts.push({ operationId: operation?.operationId || pending.operationId, policy: "remote-wins", currentRevision: error.currentRevision || error.payload?.currentRevision || null });
          await this.recoverConflict(operation, summary);
          if (error.current) await this.apply(protocol.validateOperation(error.current), summary);
          await this.journal.markSeen(operation.operationId);
          summary.pushed += 1;
          continue;
        }
        if (transient(error)) { summary.offline = true; continue; }
        throw error;
      }
    }
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
    await this.verifyIncomingOperation(operation);
    const key = await this.keyFor(operation);
    const plaintext = protocol.decryptPayload(operation, key);
    const metadata = operation.metadata || {};
    if (!metadata.path) fail("Sync operation path is required", "unsafe_path");
    const target = await contained(this.rootDir, metadata.path, true);
    if (operation.operation === "delete" || operation.tombstone) {
      await this.stageExisting(target);
      const prior = this.snapshot.files[metadata.path] || {};
      this.snapshot.files[metadata.path] = { objectId: operation.objectId, fileId: operation.fileId, versionId: operation.versionId, revision: operation.revision, deleted: true, directory: Boolean(prior.directory) };
    } else if (operation.operation === "move") {
      if (!metadata.sourcePath) fail("Move source path is required", "unsafe_path");
      const source = await contained(this.rootDir, metadata.sourcePath, true);
      const sourceExists = await exists(source);
      const movePayload = protocol.decodeMovePayload(plaintext, key);
      if (!sourceExists && movePayload === null) fail("Moved file is unavailable and the operation has no recovery payload", "move_source_missing");
      await fsp.mkdir(path.dirname(target), { recursive: true });
      await containedAbsolute(this.rootDir, path.dirname(target), false);
      let hash;
      if (sourceExists) {
        if (source !== target) {
          if (await exists(target)) await this.stageExisting(target);
          await fsp.rename(source, target);
        }
        const movedStats = await fsp.lstat(target);
        if (movedStats.isFile()) hash = crypto.createHash("sha256").update(await fsp.readFile(target)).digest("hex");
      } else {
        if (await exists(target)) await this.stageExisting(target);
        const temporary = `${target}.tmp-${process.pid}-${crypto.randomUUID()}`;
        try {
          await fsp.writeFile(temporary, movePayload, { mode: 0o600, flag: "wx" });
          await fsp.rename(temporary, target);
        } finally { await fsp.rm(temporary, { force: true }).catch(() => {}); }
        hash = crypto.createHash("sha256").update(movePayload).digest("hex");
      }
      this.rememberOperation(operation, hash);
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
    if (operation.operation === "move" && metadata.sourcePath) {
      await this.pruneEmptyUntrackedParents(path.dirname(await contained(this.rootDir, metadata.sourcePath, true)));
    } else if (operation.operation === "delete" || operation.tombstone) {
      await this.pruneEmptyUntrackedParents(path.dirname(target));
    }
    await durableJson(this.snapshotPath, this.snapshot);
    if (summary) summary.applied = (summary.applied || 0) + 1;
  }

  async scanFiles() {
    const result = {};
    const emptyHash = crypto.createHash("sha256").update(Buffer.alloc(0)).digest("hex");
    const walk = async (directory, prefix = "") => {
      let hasSyncEntries = false;
      for (const entry of await fsp.readdir(directory, { withFileTypes: true })) {
        if (prefix === "" && [...INTERNAL_NAMES].some((name) => name.toLowerCase() === entry.name.toLowerCase())) continue;
        if (entry.name.startsWith(".rootark-put-") || entry.name.startsWith(".rootark-move-")) continue;
        const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
        try { protocol.safeRelativePath(relative, "path"); } catch { continue; }
        const target = path.join(directory, entry.name);
        await containedAbsolute(this.rootDir, target, false);
        if (entry.isDirectory()) {
          const childHasSyncEntries = await walk(target, relative);
          const prior = this.snapshot.files[relative];
          if (!childHasSyncEntries || (prior && !prior.deleted && prior.directory)) {
            result[relative] = { hash: emptyHash, size: 0, directory: true };
          }
          hasSyncEntries = true;
        } else if (entry.isFile()) {
          const data = await fsp.readFile(target);
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
    const current = await this.scanFiles();
    const protectedPaths = new Set();
    for (const operation of await this.journal.recover()) {
      if (operation.metadata?.path) protectedPaths.add(operation.metadata.path);
      if (operation.metadata?.sourcePath) protectedPaths.add(operation.metadata.sourcePath);
      if (operation.operation === "update" && operation.metadata?.contentType === "inode/directory") {
        const sourcePath = activeIdentityPath(this.snapshot.files, operation, operation.metadata.path);
        if (sourcePath) protectedPaths.add(sourcePath);
      }
      if (operation.journalType === "webdav-mutation") {
        for (const value of [operation.path, operation.source, operation.destination]) {
          if (typeof value !== "string") continue;
          try { protectedPaths.add(protocol.safeRelativePath(decodeURIComponent(value).replace(/^\/+/, ""), "path")); } catch {}
        }
      }
    }
    for (const [relative, prior] of Object.entries(this.snapshot.files)) {
      if (protectedPaths.has(relative)) continue;
      if (prior.deleted || current[relative]) continue;
      const key = await this.fileKeyResolver(prior);
      const operation = await this.buildOperation({ operation: "delete", objectId: prior.objectId, fileId: prior.fileId, versionId: crypto.randomUUID(), baseRevision: prior.revision, revision: { counter: (prior.revision?.counter || 0) + 1, deviceId: this.deviceId }, metadata: { path: relative }, fileKey: key });
      await this.journal.enqueue(operation);
      this.rememberOperation(operation);
    }
    for (const [relative, file] of Object.entries(current)) {
      if (protectedPaths.has(relative)) continue;
      const prior = this.snapshot.files[relative];
      const isDirectory = Boolean(file.directory);
      if (prior && !prior.deleted && prior.hash === file.hash && Boolean(prior.directory) === isDirectory) continue;
      const isUpdate = prior && !prior.deleted;
      const objectId = isUpdate ? prior.objectId : `object-${crypto.createHash("sha256").update(relative).digest("hex").slice(0, 32)}`;
      const fileId = isUpdate ? prior.fileId : `file-${crypto.createHash("sha256").update(relative).digest("hex").slice(0, 32)}`;
      const data = isDirectory ? Buffer.alloc(0) : await fsp.readFile(path.join(this.rootDir, ...relative.split("/")));
      const key = await this.fileKeyResolver({ objectId, fileId, path: relative, keyEpoch: this.keyEpoch });
      const metadata = { path: relative, name: path.basename(relative), size: data.length, ...(isDirectory ? { contentType: "inode/directory" } : {}) };
      const operation = await this.buildOperation({ operation: isUpdate ? "update" : "create", objectId, fileId, versionId: crypto.randomUUID(), baseRevision: isUpdate ? prior.revision : null, revision: { counter: (prior?.revision?.counter || 0) + 1, deviceId: this.deviceId }, metadata, plaintext: data, fileKey: key });
      await this.journal.enqueue(operation);
      this.rememberOperation(operation, file.hash);
    }
    await durableJson(this.snapshotPath, this.snapshot);
  }

  rememberOperation(operation, hash) {
    const pathName = operation.metadata?.path;
    if (!pathName) return;
    const sourcePath = operation.operation === "move" ? operation.metadata.sourcePath
      : (operation.operation === "update" && operation.metadata.contentType === "inode/directory"
        ? activeIdentityPath(this.snapshot.files, operation, pathName) : null);
    const prior = sourcePath
      ? this.snapshot.files[sourcePath] || (sourcePath === pathName ? this.snapshot.files[pathName] : null) || {}
      : this.snapshot.files[pathName] || {};
    if (sourcePath && sourcePath !== pathName) delete this.snapshot.files[sourcePath];
    this.snapshot.files[pathName] = {
      objectId: operation.objectId, fileId: operation.fileId, versionId: operation.versionId,
      revision: operation.revision, hash: hash || prior.hash, deleted: Boolean(operation.tombstone),
      directory: operation.tombstone || operation.operation === "move"
        ? Boolean(prior.directory)
        : operation.metadata?.contentType === "inode/directory",
    };
  }

  async pullRemote(summary) {
    const result = await this.adapter.list();
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
    for (const raw of ordered) {
      const operation = protocol.validateOperation(raw);
      if (this.journal.hasSeen(operation.operationId)) continue;
      await this.apply(operation, summary);
      await this.journal.markSeen(operation.operationId);
      summary.pulled += 1;
    }
  }

  async syncOnce() {
    if (!this.opened) await this.open();
    const summary = { pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false };
    await this.reconcileLocal();
    await this.pushPending(summary);
    if (!summary.offline) await this.pullRemote(summary);
    return summary;
  }
}

module.exports = { SyncEngine, contained, containedAbsolute };
