const fs = require("fs");
const path = require("path");
const { spawn, spawnSync } = require("node:child_process");
const unzipper = require("unzipper");

const MAX_INPUT_BYTES = Number(process.env.PREVIEW_MAX_INPUT_BYTES || 5 * 1024 * 1024);
const MAX_OUTPUT_CHARS = Number(process.env.PREVIEW_MAX_OUTPUT_CHARS || 200_000);
const TIMEOUT_MS = Number(process.env.PREVIEW_TIMEOUT_MS || 10_000);
const MAX_DOCX_ENTRIES = Number(process.env.PREVIEW_MAX_DOCX_ENTRIES || 2_000);
const MAX_DOCX_UNCOMPRESSED_BYTES = Number(process.env.PREVIEW_MAX_DOCX_UNCOMPRESSED_BYTES || 50 * 1024 * 1024);
const MAX_DOCX_COMPRESSION_RATIO = Number(process.env.PREVIEW_MAX_DOCX_COMPRESSION_RATIO || 100);
const MAX_CONCURRENT_PARSERS = Math.min(32, Math.max(1, Number(process.env.PREVIEW_MAX_CONCURRENCY || 2)));
const MAX_PARSER_QUEUE = Math.min(128, Math.max(0, Number(process.env.PREVIEW_MAX_QUEUE || 16)));
const TERMINATION_GRACE_MS = 100;
const TEXT_EXTENSIONS = new Set([".txt", ".md", ".json", ".csv", ".log", ".xml", ".yaml", ".yml"]);
const PARSER_WORKER = path.join(__dirname, "documentPreviewWorker.js");
let activeParsers = 0;
const parserQueue = [];

function bounded(value) {
  const text = String(value || "");
  return text.length > MAX_OUTPUT_CHARS ? `${text.slice(0, MAX_OUTPUT_CHARS)}\n[preview truncated]` : text;
}

function readPinnedText(filePath) {
  // The caller authorizes a path; check that the opened file is still the
  // same regular file and cap the bytes actually read from its descriptor.
  // On Windows (and other 64-bit filesystems), Number dev/ino may silently
  // round distinct adjacent file IDs to the same value. Preserve exact IDs.
  const expected = fs.lstatSync(filePath, { bigint: true });
  if (!expected.isFile() || expected.isSymbolicLink() || expected.size > BigInt(MAX_INPUT_BYTES)) {
    throw parserFailure("PREVIEW_TOO_LARGE", "PREVIEW_TOO_LARGE");
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!opened.isFile() || opened.size > BigInt(MAX_INPUT_BYTES)) throw parserFailure("PREVIEW_TOO_LARGE", "PREVIEW_TOO_LARGE");
    if (opened.dev !== expected.dev || opened.ino !== expected.ino) {
      throw parserFailure("PREVIEW_FILE_CHANGED", "PREVIEW_FILE_CHANGED");
    }
    const chunks = [];
    let total = 0;
    while (total <= MAX_INPUT_BYTES) {
      const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, MAX_INPUT_BYTES + 1 - total));
      const bytes = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytes === 0) break;
      chunks.push(buffer.subarray(0, bytes));
      total += bytes;
    }
    if (total > MAX_INPUT_BYTES) throw parserFailure("PREVIEW_TOO_LARGE", "PREVIEW_TOO_LARGE");
    return Buffer.concat(chunks, total).toString("utf8");
  } finally {
    fs.closeSync(fd);
  }
}

function sameDocumentIdentity(a, b) {
  return a.isFile() && !a.isSymbolicLink() && a.nlink === 1n
    && a.dev === b.dev && a.ino === b.ino && a.size === b.size
    && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
}

function capturePrivateDocument(filePath) {
  // Capture under the authorized pathname exactly once. Both DOCX preflight
  // and the child parser must use these private bytes, never reopen that name.
  const expected = fs.lstatSync(filePath, { bigint: true });
  if (!expected.isFile() || expected.isSymbolicLink() || expected.nlink !== 1n
    || expected.size > BigInt(MAX_INPUT_BYTES)) {
    throw parserFailure("PREVIEW_TOO_LARGE", "PREVIEW_TOO_LARGE");
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY
    | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0));
  const allocatedChunks = [];
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!sameDocumentIdentity(expected, opened)) {
      throw parserFailure("PREVIEW_FILE_CHANGED", "PREVIEW_FILE_CHANGED");
    }
    const chunks = [];
    let total = 0;
    while (total <= MAX_INPUT_BYTES) {
      const part = Buffer.allocUnsafe(Math.min(64 * 1024, MAX_INPUT_BYTES + 1 - total));
      // Track every allocation before readSync: it may throw after writing
      // partial bytes. Both successful and failed captures must erase them.
      allocatedChunks.push(part);
      const size = fs.readSync(fd, part, 0, part.length, null);
      if (!size) break;
      total += size;
      chunks.push(part.subarray(0, size));
    }
    if (total > MAX_INPUT_BYTES) throw parserFailure("PREVIEW_TOO_LARGE", "PREVIEW_TOO_LARGE");
    const ended = fs.fstatSync(fd, { bigint: true });
    const named = fs.lstatSync(filePath, { bigint: true });
    if (!sameDocumentIdentity(opened, ended)
      || !sameDocumentIdentity(ended, named) || BigInt(total) !== opened.size) {
      throw parserFailure("PREVIEW_FILE_CHANGED", "PREVIEW_FILE_CHANGED");
    }
    return Buffer.concat(chunks, total);
  } finally {
    // Buffer.concat creates the independently owned snapshot returned to the
    // parser. The original read allocations also contain plaintext and must
    // not be left live until garbage collection (even on a thrown read).
    for (const part of allocatedChunks) part.fill(0);
    fs.closeSync(fd);
  }
}

function killParserProcess(child, force = false) {
  if (!child || child.exitCode !== null && child.exitCode !== undefined) return;
  const signal = force ? "SIGKILL" : "SIGTERM";
  try { child.kill(signal); } catch {}
  if (child.pid && process.platform !== "win32") {
    try { process.kill(-child.pid, signal); } catch {}
  }
  if (process.platform === "win32" && child.pid && force) {
    try { spawnSync("taskkill", ["/pid", String(child.pid), "/t", "/f"], { windowsHide: true, stdio: "ignore" }); } catch {}
  }
}

function parserFailure(message, code = "PREVIEW_PARSER_FAILED") {
  const error = new Error(message);
  error.code = code;
  return error;
}

function childEnvironment() {
  const allowed = ["PATH", "NODE_PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "PATHEXT", "COMSPEC"];
  return Object.fromEntries(allowed.filter((key) => process.env[key] !== undefined).map((key) => [key, process.env[key]]));
}

function acquireParserSlot() {
  if (activeParsers < MAX_CONCURRENT_PARSERS) {
    activeParsers += 1;
    return Promise.resolve(() => { activeParsers -= 1; drainParserQueue(); });
  }
  if (parserQueue.length >= MAX_PARSER_QUEUE) return Promise.reject(parserFailure("PREVIEW_BUSY", "PREVIEW_BUSY"));
  return new Promise((resolve) => parserQueue.push(resolve));
}

function drainParserQueue() {
  if (!parserQueue.length || activeParsers >= MAX_CONCURRENT_PARSERS) return;
  activeParsers += 1;
  const resolve = parserQueue.shift();
  resolve(() => { activeParsers -= 1; drainParserQueue(); });
}

function isZipSymlink(entry) {
  if (entry.type === "SymbolicLink") return true;
  const madeByUnix = (Number(entry.versionMadeBy) >>> 8) === 3;
  const unixMode = Number(entry.externalFileAttributes) >>> 16;
  return madeByUnix && (unixMode & 0xf000) === 0xa000;
}

async function preflightDocx(source) {
  const archive = Buffer.isBuffer(source)
    ? await unzipper.Open.buffer(source) : await unzipper.Open.file(source);
  if (archive.files.length > MAX_DOCX_ENTRIES) throw parserFailure("PREVIEW_DOCX_TOO_MANY_ENTRIES", "PREVIEW_DOCX_TOO_MANY_ENTRIES");
  let totalUncompressed = 0;
  const normalized = new Set();
  const folded = new Set();
  for (const entry of archive.files) {
    const rawPath = String(entry.path || "").replace(/\\/g, "/");
    const safePath = path.posix.normalize(rawPath);
    if (!rawPath || rawPath.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(rawPath) || safePath === ".." || safePath.startsWith("../") || rawPath.split("/").includes("..")) {
      throw parserFailure("PREVIEW_DOCX_UNSAFE_PATH", "PREVIEW_DOCX_UNSAFE_PATH");
    }
    if (isZipSymlink(entry)) throw parserFailure("PREVIEW_DOCX_SYMLINK", "PREVIEW_DOCX_SYMLINK");
    if (normalized.has(safePath)) throw parserFailure("PREVIEW_DOCX_DUPLICATE_PATH", "PREVIEW_DOCX_DUPLICATE_PATH");
    normalized.add(safePath);
    const caseKey = safePath.toLowerCase();
    if (folded.has(caseKey)) throw parserFailure("PREVIEW_DOCX_CASE_COLLISION", "PREVIEW_DOCX_CASE_COLLISION");
    folded.add(caseKey);
    const flags = Number(entry.flags || 0);
    if (flags & 1) throw parserFailure("PREVIEW_DOCX_ENCRYPTED", "PREVIEW_DOCX_ENCRYPTED");
    const uncompressed = Number(entry.uncompressedSize);
    const compressed = Number(entry.compressedSize);
    if (!Number.isFinite(uncompressed) || !Number.isFinite(compressed) || uncompressed < 0 || compressed < 0) throw parserFailure("PREVIEW_DOCX_MALFORMED", "PREVIEW_DOCX_MALFORMED");
    totalUncompressed += uncompressed;
    if (totalUncompressed > MAX_DOCX_UNCOMPRESSED_BYTES || (uncompressed > 0 && compressed === 0) || (compressed > 0 && uncompressed / compressed > MAX_DOCX_COMPRESSION_RATIO)) {
      throw parserFailure("PREVIEW_DOCX_RESOURCE_LIMIT", "PREVIEW_DOCX_RESOURCE_LIMIT");
    }
    if (safePath.toLowerCase().endsWith(".rels")) {
      const relationships = (await entry.buffer()).toString("utf8");
      if (/<Relationship\b[^>]*(?:TargetMode\s*=\s*["']External["']|Target\s*=\s*["'][^"']*(?:https?:|file:|\\\\|\/\/))/i.test(relationships)) {
        throw parserFailure("PREVIEW_DOCX_EXTERNAL_RELATIONSHIP", "PREVIEW_DOCX_EXTERNAL_RELATIONSHIP");
      }
    }
  }
}

async function parseDocumentInChildProcessUnbounded(snapshot, extension, options = {}) {
  const spawnProcess = options.spawnImpl || spawn;
  const timeout = Number(options.timeoutMs ?? TIMEOUT_MS);
  const maxOutputBytes = Number(options.maxOutputBytes ?? Math.max(16_384, MAX_OUTPUT_CHARS * 8));
  const finalTerminationTimeout = Number(options.finalTerminationTimeoutMs ?? TERMINATION_GRACE_MS);
  return new Promise((resolve, reject) => {
    let child;
    let settled = false;
    let timer;
    let graceTimer;
    let finalTimer;
    let output = "";
    let errorOutput = "";
    let outputBytes = 0;
    let errorBytes = 0;
    let closeConfirmed = false;
    let pendingError = null;
    let state = "running";
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(graceTimer);
      clearTimeout(finalTimer);
      if (error) reject(error); else resolve(value);
    };
    const stop = (error) => {
      if (pendingError || settled) return;
      pendingError = error;
      state = "graceful termination requested";
      killParserProcess(child);
      graceTimer = setTimeout(() => {
        if (closeConfirmed || settled) return;
        state = "forced termination requested";
        killParserProcess(child, true);
        finalTimer = setTimeout(() => {
          if (!closeConfirmed && !settled) {
            state = "unreaped failure";
            finish(parserFailure("Parser process exit was not confirmed", "PREVIEW_PROCESS_UNREAPED"));
          }
        }, Math.max(1, finalTerminationTimeout));
      }, TERMINATION_GRACE_MS);
      if (closeConfirmed) finish(pendingError);
    };
    try {
      child = spawnProcess(process.execPath, [PARSER_WORKER, JSON.stringify({ extension })], {
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
        detached: process.platform !== "win32",
        env: childEnvironment(),
      });
    } catch (error) {
      finish(parserFailure("Falha ao iniciar parser", "PREVIEW_PARSER_START_FAILED"));
      return;
    }
    timer = setTimeout(() => {
      stop(parserFailure("PREVIEW_TIMEOUT", "PREVIEW_TIMEOUT"));
    }, Math.max(1, timeout));
    child.stdout?.on("data", (chunk) => {
      outputBytes += chunk.byteLength;
      if (outputBytes > maxOutputBytes) return stop(parserFailure("PREVIEW_OUTPUT_TOO_LARGE", "PREVIEW_OUTPUT_TOO_LARGE"));
      output += chunk.toString();
    });
    child.stderr?.on("data", (chunk) => {
      errorBytes += chunk.byteLength;
      if (errorBytes > maxOutputBytes) return stop(parserFailure("PREVIEW_ERROR_OUTPUT_TOO_LARGE", "PREVIEW_ERROR_OUTPUT_TOO_LARGE"));
      errorOutput += chunk.toString();
    });
    if (!child.stdin || typeof child.stdin.end !== "function") {
      stop(parserFailure("Parser input pipe unavailable", "PREVIEW_PARSER_FAILED"));
    } else {
      child.stdin.on("error", () => stop(parserFailure("Parser input failed", "PREVIEW_PARSER_FAILED")));
      try { child.stdin.end(snapshot); }
      catch (_) { stop(parserFailure("Parser input failed", "PREVIEW_PARSER_FAILED")); }
    }
    child.once("error", () => stop(parserFailure("Falha no parser", "PREVIEW_PARSER_FAILED")));
    child.once("close", (code) => {
      closeConfirmed = true;
      state = "exited";
      if (pendingError) return finish(pendingError);
      if (settled) return;
      if (code !== 0) {
        finish(parserFailure(errorOutput.includes("PREVIEW_TIMEOUT") ? "PREVIEW_TIMEOUT" : "Falha no parser", errorOutput.includes("PREVIEW_TIMEOUT") ? "PREVIEW_TIMEOUT" : "PREVIEW_PARSER_FAILED"));
        return;
      }
      try {
        const message = JSON.parse(output);
        if (!message || message.ok !== true) throw new Error("invalid parser response");
        finish(null, bounded(message.content));
      } catch {
        finish(parserFailure("Resposta de parser invalida", "PREVIEW_PARSER_FAILED"));
      }
    });
  });
}

async function parseDocumentInChildProcess(filePath, extension, options = {}) {
  if (extension !== ".doc" && extension !== ".docx") {
    throw parserFailure("PREVIEW_UNSUPPORTED", "PREVIEW_UNSUPPORTED");
  }
  const release = await acquireParserSlot();
  try {
    const snapshot = capturePrivateDocument(filePath);
    try {
      if (extension === ".docx") await preflightDocx(snapshot);
      return await parseDocumentInChildProcessUnbounded(snapshot, extension, options);
    } finally {
      // No on-disk plaintext staging, even if a killed child never closes.
      // On timeout the input pipe is abandoned and these local bytes are erased.
      snapshot.fill(0);
    }
  }
  finally { release(); }
}

async function previewText(filePath, fileName, options = {}) {
  const extension = path.extname(fileName || filePath).toLowerCase();
  if (!TEXT_EXTENSIONS.has(extension) && extension !== ".doc" && extension !== ".docx") throw new Error("PREVIEW_UNSUPPORTED");
  if (TEXT_EXTENSIONS.has(extension)) {
    return { content: bounded(readPinnedText(filePath)), format: "text", language: extension.slice(1) || "text" };
  }
  const content = await parseDocumentInChildProcess(filePath, extension, options);
  return { content, format: "document", language: extension.slice(1) };
}

module.exports = { MAX_INPUT_BYTES, MAX_OUTPUT_CHARS, TIMEOUT_MS, MAX_DOCX_ENTRIES, MAX_DOCX_UNCOMPRESSED_BYTES, MAX_DOCX_COMPRESSION_RATIO, MAX_CONCURRENT_PARSERS, MAX_PARSER_QUEUE, PARSER_WORKER, previewText, parseDocumentInChildProcess, killParserProcess, preflightDocx };
