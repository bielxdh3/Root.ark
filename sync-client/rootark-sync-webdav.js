"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const { validatePortableRelativePath } = require("./rootark-sync-paths");

const MAX_BODY_BYTES = 8 * 1024 * 1024;
function isLoopback(host) {
  const value = String(host || "").toLowerCase();
  return value === "localhost" || value === "127.0.0.1" || value === "::1" || (net.isIP(value) === 6 && value === "0:0:0:0:0:0:0:1");
}

function safeSegments(urlPath) {
  let decoded;
  try { decoded = decodeURIComponent(urlPath); } catch { throw Object.assign(new Error("Invalid path"), { statusCode: 400 }); }
  if (decoded.includes("\0") || decoded.includes("\\")) throw Object.assign(new Error("Unsafe path"), { statusCode: 400 });
  const segments = decoded.split("/").filter(Boolean);
  if (segments.length) {
    try { validatePortableRelativePath(segments.join("/"), "path"); } catch { throw Object.assign(new Error("Unsafe path"), { statusCode: 400 }); }
  }
  return segments;
}

function sameOrBelow(candidate, parent) {
  const left = path.resolve(candidate);
  const right = path.resolve(parent);
  const compare = process.platform === "win32" ? (value) => value.toLowerCase() : (value) => value;
  const a = compare(left);
  const b = compare(right);
  return a === b || a.startsWith(`${b}${path.sep}`);
}

async function rejectSymlinks(rootDir, targetPath, allowMissing = true) {
  const root = path.resolve(rootDir);
  const resolved = path.resolve(targetPath);
  if (!(resolved === root || resolved.startsWith(`${root}${path.sep}`))) throw Object.assign(new Error("Path outside bridge root"), { statusCode: 400 });
  const rootStats = await fsp.lstat(root);
  if (rootStats.isSymbolicLink()) throw Object.assign(new Error("Symlink bridge root is not supported"), { statusCode: 400 });
  const relative = path.relative(root, resolved);
  let current = root;
  for (const segment of relative ? relative.split(path.sep) : []) {
    current = path.join(current, segment);
    let stats;
    try { stats = await fsp.lstat(current); } catch (error) {
      if (allowMissing && error.code === "ENOENT") break;
      throw error;
    }
    if (stats.isSymbolicLink()) throw Object.assign(new Error("Symlink paths are not supported"), { statusCode: 400 });
  }
  return resolved;
}

async function canonicalExistingPath(rootDir, targetPath) {
  const checked = await rejectSymlinks(rootDir, targetPath, false);
  if (process.platform !== "win32") return checked;

  const root = path.resolve(rootDir);
  let current = root;
  for (const requestedName of path.relative(root, checked).split(path.sep).filter(Boolean)) {
    const names = await fsp.readdir(current);
    const name = names.find((entry) => entry === requestedName)
      || names.find((entry) => entry.toLowerCase() === requestedName.toLowerCase());
    if (!name) throw Object.assign(new Error("Path does not exist"), { code: "ENOENT" });
    current = path.join(current, name);
    const stats = await fsp.lstat(current);
    if (stats.isSymbolicLink()) throw Object.assign(new Error("Symlink paths are not supported"), { statusCode: 400 });
  }
  return current;
}

function encodedWebDavPath(rootDir, targetPath) {
  const relative = path.relative(path.resolve(rootDir), path.resolve(targetPath)).split(path.sep).join("/");
  validatePortableRelativePath(relative, "path");
  return `/${relative.split("/").map((segment) => encodeURIComponent(segment)).join("/")}`;
}

function xml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" }[character]));
}

function writeResponse(res, status, body = "", headers = {}) {
  res.writeHead(status, { "Cache-Control": "no-store", ...headers });
  res.end(body);
}

class LocalSyncWebDavBridge {
  constructor(options = {}) {
    this.rootDir = path.resolve(options.rootDir || process.cwd());
    this.trashDir = path.resolve(options.trashDir || path.join(this.rootDir, ".rootark-trash"));
    this.token = String(options.token || "");
    this.host = options.host || "127.0.0.1";
    this.port = Number(options.port || 0);
    this.maxBodyBytes = Number(options.maxBodyBytes || MAX_BODY_BYTES);
    this.journal = options.journal || null;
    this.protocolJournal = options.protocolJournal || null;
    this.toProtocolOperation = options.toProtocolOperation || null;
    this.onOperation = options.onOperation || (options.journal ? (operation) => options.journal.enqueue(operation) : null);
    if (!this.token) throw new Error("Local WebDAV bridge bearer token is required");
    if (!isLoopback(this.host)) throw new Error("Local WebDAV bridge must bind to loopback");
    this.server = http.createServer((req, res) => this.handle(req, res));
  }

  async start() {
    await fsp.mkdir(this.rootDir, { recursive: true });
    await rejectSymlinks(this.rootDir, this.rootDir, false);
    await fsp.mkdir(this.trashDir, { recursive: true });
    await rejectSymlinks(this.rootDir, this.trashDir, false);
    if (this.trashDir === this.rootDir) throw Object.assign(new Error("Trash directory must be below bridge root"), { statusCode: 400 });
    await this.recoverPending();
    await new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(this.port, this.host, resolve);
    });
    return this.address();
  }

  address() { return this.server.address(); }

  async recoverPending() {
    if (!this.journal?.recover) return;
    for (const operation of await this.journal.recover()) {
      if (operation.phase === "protocol-queued") {
        if (this.journal.markSeen) await this.journal.markSeen(operation.operationId);
        continue;
      }
      if (!["move", "put", "delete"].includes(operation.kind)) continue;
      const sourcePath = operation.source || operation.path;
      const destinationPath = operation.kind === "delete" ? sourcePath : (operation.destination || operation.path || operation.source);
      if (!destinationPath) continue;
      const destination = await this.target(destinationPath);
      const source = sourcePath ? await this.target(sourcePath) : null;
      const backup = operation.trash ? path.resolve(this.rootDir, operation.trash) : null;
      if (backup) await rejectSymlinks(this.rootDir, backup, true);
      const backupExists = backup ? await fsp.lstat(backup).then(() => true, (error) => error.code === "ENOENT" ? false : Promise.reject(error)) : false;
      const destinationExists = await fsp.lstat(destination).then(() => true, (error) => error.code === "ENOENT" ? false : Promise.reject(error));
      const sourceExists = source ? await fsp.lstat(source).then(() => true, (error) => error.code === "ENOENT" ? false : Promise.reject(error)) : false;
      let applied = false;
      if (operation.kind === "move") {
        applied = !sourceExists && destinationExists
          && (operation.phase === "source-moved" || (!operation.trash && operation.phase === "prepared") || (backupExists && ["prepared", "staged"].includes(operation.phase)));
      }
      else if (operation.kind === "put") applied = destinationExists && (!operation.existed || backupExists);
      else applied = !sourceExists && backupExists;

      if (applied) {
        const protocolQueued = await this.enqueueProtocol(operation);
        if (protocolQueued) await this.updateJournal(operation.operationId, { phase: "protocol-queued" });
        if (this.journal.markSeen) await this.journal.markSeen(operation.operationId);
        continue;
      }

      if (backupExists && !destinationExists && operation.kind !== "delete") {
        await fsp.rename(backup, destination);
      } else if ((backupExists || destinationExists) && operation.phase === "staged") {
        continue;
      }
      if (this.journal.markSeen) await this.journal.markSeen(operation.operationId);
    }
  }

  async updateJournal(operationId, patch) {
    if (this.journal?.update) await this.journal.update(operationId, patch);
  }

  async markJournalSeen(operationId) {
    if (this.journal?.markSeen) await this.journal.markSeen(operationId);
  }

  async enqueueProtocol(operation) {
    if (!this.protocolJournal) return false;
    if (!this.toProtocolOperation) throw new Error("WebDAV protocol translation required");
    const translated = await this.toProtocolOperation(operation);
    if (!translated) throw new Error("WebDAV mutation translation failed");
    try {
      if (Array.isArray(translated)) {
        if (!translated.length) return false;
        if (typeof this.protocolJournal.enqueueMany !== "function") throw new Error("WebDAV mutation batch cannot be committed atomically");
        await this.protocolJournal.enqueueMany(translated);
      } else {
        await this.protocolJournal.enqueue(translated);
      }
    } catch (error) {
      if (error.journalCommitted) return true;
      throw error;
    }
    return true;
  }

  async stop() {
    if (!this.server.listening) return;
    await new Promise((resolve) => this.server.close(resolve));
  }

  authorized(req) {
    const header = String(req.headers.authorization || "");
    const supplied = header.startsWith("Bearer ") ? header.slice(7) : "";
    const expected = Buffer.from(this.token);
    const actual = Buffer.from(supplied);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  }

  async target(urlPath) {
    const target = await rejectSymlinks(this.rootDir, path.join(this.rootDir, ...safeSegments(urlPath)), true);
    if (target === this.rootDir) return target;
    if (sameOrBelow(target, this.trashDir)) throw Object.assign(new Error("Internal trash path is not accessible"), { statusCode: 400 });
    await rejectSymlinks(this.rootDir, path.dirname(target), false);
    return target;
  }

  async body(req) {
    const declared = Number(req.headers["content-length"]);
    if (Number.isSafeInteger(declared) && declared > this.maxBodyBytes) throw Object.assign(new Error("Payload too large"), { statusCode: 413 });
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > this.maxBodyBytes) throw Object.assign(new Error("Payload too large"), { statusCode: 413 });
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }

  async properties(target, requestPath) {
    const stats = await fsp.lstat(target);
    if (stats.isSymbolicLink()) throw Object.assign(new Error("Symlink paths are not supported"), { statusCode: 400 });
    const collection = stats.isDirectory();
    return `<d:response><d:href>${xml(requestPath)}${collection ? "/" : ""}</d:href><d:propstat><d:prop><d:resourcetype>${collection ? "<d:collection/>" : ""}</d:resourcetype><d:getcontentlength>${collection ? 0 : stats.size}</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`;
  }

  async handle(req, res) {
    if (!this.authorized(req)) return writeResponse(res, 401, "Unauthorized", { "WWW-Authenticate": "Bearer" });
    try {
      // Validate the raw request target before WHATWG URL normalizes dot segments.
      safeSegments(String(req.url || "/").split("?", 1)[0]);
      const parsed = new URL(req.url, "http://localhost");
      const target = await this.target(parsed.pathname);
      if (req.method === "OPTIONS") return writeResponse(res, 204, "", { DAV: "1", Allow: "OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, MOVE, DELETE" });
      if (req.method === "PROPFIND") {
        const depth = String(req.headers.depth || "0");
        if (!["0", "1"].includes(depth)) return writeResponse(res, 400, "Invalid depth");
        const results = [await this.properties(target, parsed.pathname)];
        if (depth === "1" && (await fsp.lstat(target)).isDirectory()) {
          for (const entry of await fsp.readdir(target, { withFileTypes: true })) {
            if (entry.isSymbolicLink()) continue;
            results.push(await this.properties(path.join(target, entry.name), `${parsed.pathname.replace(/\/$/, "")}/${entry.name}`));
          }
        }
        return writeResponse(res, 207, `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">${results.join("")}</d:multistatus>`, { "Content-Type": "application/xml; charset=utf-8" });
      }
      if (["GET", "HEAD"].includes(req.method)) {
        const stats = await fsp.lstat(target);
        if (!stats.isFile()) return writeResponse(res, 405, "Not a file");
        res.writeHead(200, { "Content-Length": stats.size, "Cache-Control": "no-store" });
        if (req.method === "HEAD") return res.end();
        return fs.createReadStream(target).pipe(res);
      }
      if (req.method === "PUT") {
        if (target === this.rootDir) return writeResponse(res, 400, "Invalid target");
        const data = await this.body(req);
        const parent = path.dirname(target);
        await fsp.mkdir(parent, { recursive: false }).catch((error) => { if (error.code !== "EEXIST") throw error; });
        await rejectSymlinks(this.rootDir, parent, false);
        const existing = await fsp.lstat(target).catch((error) => error.code === "ENOENT" ? null : Promise.reject(error));
        if (existing?.isSymbolicLink() || existing?.isDirectory()) return writeResponse(res, 409, "Invalid target");
        const operationId = crypto.randomUUID();
        const backup = existing ? path.join(this.trashDir, `.rootark-put-${operationId}-${path.basename(target)}`) : null;
        const operation = {
          operationId,
          kind: "put",
          journalType: "webdav-mutation",
          path: parsed.pathname,
          source: parsed.pathname,
          destination: parsed.pathname,
          existed: Boolean(existing),
          trash: backup ? path.relative(this.rootDir, backup) : null,
          phase: "prepared",
        };
        if (this.onOperation) await this.onOperation(operation);
        const temporary = path.join(parent, `.rootark-put-${process.pid}-${crypto.randomUUID()}`);
        let staged = false;
        let installed = false;
        let protocolQueued = false;
        try {
          await fsp.writeFile(temporary, data, { mode: 0o600 });
          if (backup) {
            await rejectSymlinks(this.rootDir, backup, true);
            await fsp.rename(target, backup);
            staged = true;
            await this.updateJournal(operationId, { phase: "staged" });
          }
          await fsp.rename(temporary, target);
          installed = true;
          await this.updateJournal(operationId, { phase: "source-moved" });
          protocolQueued = await this.enqueueProtocol(operation);
          if (protocolQueued) await this.updateJournal(operationId, { phase: "protocol-queued" });
          try { await this.markJournalSeen(operationId); } catch (error) { if (!protocolQueued) throw error; }
        } catch (error) {
          await fsp.rm(temporary, { force: true }).catch(() => {});
          if (protocolQueued) return writeResponse(res, existing ? 204 : 201);
          if (installed) await fsp.rm(target, { recursive: true, force: true }).catch(() => {});
          if (staged) await fsp.rename(backup, target).catch(() => {});
          throw error;
        }
        return writeResponse(res, existing ? 204 : 201);
      }
      if (req.method === "MKCOL") {
        if (target === this.rootDir) return writeResponse(res, 405, "Already exists");
        await fsp.mkdir(target, { recursive: false });
        await rejectSymlinks(this.rootDir, target, false);
        return writeResponse(res, 201);
      }
      if (req.method === "MOVE") return await this.move(req, res, target, parsed);
      if (req.method === "DELETE") return await this.remove(req, res, target, parsed);
      return writeResponse(res, 405, "Method not allowed");
    } catch (error) {
      const status = error.statusCode || (error.code === "ENOENT" ? 404 : error.code === "EEXIST" ? 405 : 500);
      return writeResponse(res, status, status === 500 ? "Bridge operation failed" : error.message);
    }
  }

  async destination(req) {
    const value = String(req.headers.destination || "");
    if (!value) throw Object.assign(new Error("Destination required"), { statusCode: 400 });
    const parsed = new URL(value, `http://${this.host}`);
    if (parsed.hostname !== this.host && !isLoopback(parsed.hostname)) throw Object.assign(new Error("Destination outside bridge"), { statusCode: 400 });
    return { parsed, target: await this.target(parsed.pathname) };
  }

  async move(req, res, source, parsed) {
    if (source === this.rootDir) return writeResponse(res, 400, "Cannot move root");
    const destination = await this.destination(req);
    if (destination.target === source) return writeResponse(res, 400, "Source and destination are identical");
    const existing = await fsp.lstat(destination.target).catch((error) => error.code === "ENOENT" ? null : Promise.reject(error));
    let canonicalSource = null;
    if (process.platform === "win32") {
      canonicalSource = await canonicalExistingPath(this.rootDir, source);
      if (existing) {
        const canonicalDestination = await canonicalExistingPath(this.rootDir, destination.target);
        if (canonicalSource.toLowerCase() === canonicalDestination.toLowerCase()) {
          return writeResponse(res, 400, "Source and destination are identical");
        }
      }
    }
    if (existing && String(req.headers.overwrite || "T").toUpperCase() !== "T") return writeResponse(res, 412, "Destination exists");
    if (existing && (await fsp.lstat(source)).isDirectory() !== existing.isDirectory()) return writeResponse(res, 409, "Cannot overwrite a file with a collection or vice versa");
    const sourceForTranslation = process.platform === "win32"
      ? encodedWebDavPath(this.rootDir, canonicalSource)
      : parsed.pathname;
    await rejectSymlinks(this.rootDir, path.dirname(destination.target), false);
    const operationId = crypto.randomUUID();
    const backup = existing ? path.join(this.trashDir, `.rootark-move-${operationId}-${path.basename(destination.target)}`) : null;
    const operation = {
      operationId,
      kind: "move",
      journalType: "webdav-mutation",
      source: sourceForTranslation,
      destination: destination.parsed.pathname,
      trash: backup ? path.relative(this.rootDir, backup) : null,
      phase: "prepared",
    };
    if (this.onOperation) await this.onOperation(operation);
    let staged = false;
    let moved = false;
    let protocolQueued = false;
    try {
      if (backup) {
        await rejectSymlinks(this.rootDir, backup, true);
        await fsp.rename(destination.target, backup);
        staged = true;
        await this.updateJournal(operationId, { phase: "staged" });
      }
      await fsp.rename(source, destination.target);
      moved = true;
      await this.updateJournal(operationId, { phase: "source-moved" });
      protocolQueued = await this.enqueueProtocol(operation);
      if (protocolQueued) await this.updateJournal(operationId, { phase: "protocol-queued" });
      try { await this.markJournalSeen(operationId); } catch (error) { if (!protocolQueued) throw error; }
    } catch (error) {
      if (protocolQueued) return writeResponse(res, existing ? 204 : 201);
      if (moved) {
        await fsp.rename(destination.target, source).catch(() => {});
      }
      if (staged) {
        await fsp.rename(backup, destination.target).catch(() => {});
      }
      throw error;
    }
    return writeResponse(res, existing ? 204 : 201);
  }

  async remove(req, res, target, parsed) {
    if (target === this.rootDir) return writeResponse(res, 400, "Cannot delete root");
    const stats = await fsp.lstat(target);
    if (stats.isSymbolicLink()) return writeResponse(res, 400, "Symlink paths are not supported");
    await fsp.mkdir(this.trashDir, { recursive: true });
    const trashTarget = path.join(this.trashDir, `${Date.now()}-${crypto.randomUUID()}-${path.basename(target)}`);
    await rejectSymlinks(this.rootDir, trashTarget, true);
    const operation = { operationId: crypto.randomUUID(), kind: "delete", journalType: "webdav-mutation", source: parsed.pathname, trash: path.relative(this.rootDir, trashTarget), phase: "prepared" };
    if (this.onOperation) await this.onOperation(operation);
    await fsp.rename(target, trashTarget);
    let protocolQueued = false;
    try {
      await this.updateJournal(operation.operationId, { phase: "source-moved" });
      protocolQueued = await this.enqueueProtocol(operation);
      if (protocolQueued) await this.updateJournal(operation.operationId, { phase: "protocol-queued" });
      try { await this.markJournalSeen(operation.operationId); } catch (error) { if (!protocolQueued) throw error; }
    } catch (error) {
      if (protocolQueued) return writeResponse(res, 204);
      await fsp.rename(trashTarget, target).catch(() => {});
      throw error;
    }
    return writeResponse(res, 204);
  }
}

module.exports = { LocalSyncWebDavBridge, isLoopback, rejectSymlinks, safeSegments };
