"use strict";

// The operator has its own OS process, certificate identity and SQLite file.
// Methods are intentionally identical to trustedRecoveryNonceAuthority.
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const tls = require("node:tls");
const path = require("node:path");
const v8 = require("node:v8");
const { spawnSync } = require("node:child_process");
const { assertPrivateSqliteFile } = require("./zk1PrivateSqlitePath");
const { Zk1HistoricalRecoveryOperator } =
  require("./zk1HistoricalRecoveryOperator");

const METHODS = new Set(["loadHead", "loadFinalizedHead", "loadOwnerGeneration",
  "loadQuarantinedHead", "compareAndAdvance", "quarantineFinalizedAck",
  "finalizeAck", "sealAck"]);
const ADMIN_METHODS = new Set(["advanceOwnerPolicy", "loadOwnerGeneration",
  "loadHead", "loadFinalizedHead", "loadQuarantinedHead"]);
const MAX_BODY = 256 * 1024;
const MAX_PROTECTED_FILE = 1024 * 1024;
function deny() { throw Error("HISTORICAL_RECOVERY_OPERATOR_TRANSPORT_DENIED"); }
function readConfig(filename) {
  const config = JSON.parse(readProtectedFile(filename).toString("utf8"));
  if (!config || typeof config !== "object" || Array.isArray(config)) deny();
  return config;
}
function certPath(filename) {
  return readProtectedFile(filename);
}
function fingerprint(v) {
  if (typeof v !== "string" || !/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/i.test(v)) deny();
  return v.toUpperCase();
}
function protectedFile(filename) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) deny();
  assertPrivateSqliteFile(filename);
  if (process.platform === "win32") {
    const { verifyWindowsAuthorityFilePath } =
      require("../../services/chunkUploadWindowsAcl");
    // Native leaf+DACL+safe-ancestor check, with no recursive scan of the
    // operator's live SQLite WAL/SHM tree on every short-lived bridge call.
    verifyWindowsAuthorityFilePath(filename);
  }
}
function sameFileIdentity(a, b) {
  return a.isFile() && b.isFile() && !a.isSymbolicLink()
    && !b.isSymbolicLink() && a.nlink === 1n && b.nlink === 1n
    && a.dev === b.dev && a.ino === b.ino;
}
function readProtectedFile(filename) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) deny();
  // Keep the opened object pinned across pathname and native Windows ACL
  // checks. A second read by pathname would reopen an unverified replacement.
  const fd = fs.openSync(filename, fs.constants.O_RDONLY
    | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!sameFileIdentity(opened, opened) || opened.size < 1n
      || opened.size > BigInt(MAX_PROTECTED_FILE)) deny();
    protectedFile(filename);
    const named = fs.lstatSync(filename, { bigint: true });
    const checked = fs.fstatSync(fd, { bigint: true });
    if (!sameFileIdentity(opened, named) || !sameFileIdentity(opened, checked)
      || opened.size !== checked.size || opened.mtimeNs !== checked.mtimeNs
      || opened.ctimeNs !== checked.ctimeNs) deny();
    const result = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < result.length) {
      const amount = fs.readSync(fd, result, offset, result.length - offset, offset);
      if (amount <= 0) deny();
      offset += amount;
    }
    const complete = fs.fstatSync(fd, { bigint: true });
    if (!sameFileIdentity(opened, complete) || complete.size !== opened.size
      || complete.mtimeNs !== opened.mtimeNs
      || complete.ctimeNs !== opened.ctimeNs) deny();
    return result;
  } finally { fs.closeSync(fd); }
}
function parsePayload(bytes) {
  if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > MAX_BODY) deny();
  return v8.deserialize(bytes);
}
function boundInput(req) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY) { reject(Error("BODY_TOO_LARGE")); req.destroy(); }
      else chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
function createHistoricalRecoveryOperatorServer(config, { bootstrapNew = false } = {}) {
  if (!config || typeof config !== "object" || !config.operator || !config.server) deny();
  const witnessFingerprint = fingerprint(config.server.witnessClientFingerprint);
  const adminFingerprint = fingerprint(config.server.adminClientFingerprint);
  if (witnessFingerprint === adminFingerprint) deny();
  const operator = new Zk1HistoricalRecoveryOperator({
    ...config.operator, bootstrapNew,
  });
  let server;
  try {
    server = https.createServer({
      cert: certPath(config.server.certPath), key: certPath(config.server.keyPath),
      ca: certPath(config.server.clientCaPath),
      minVersion: "TLSv1.3", requestCert: true, rejectUnauthorized: true,
    }, async (req, res) => {
      const send = (status, value) => {
        if (res.headersSent || res.destroyed) return;
        const data = v8.serialize(value);
        res.writeHead(status, { "Content-Type": "application/octet-stream",
          "Cache-Control": "no-store", "Content-Length": data.length });
        res.end(data);
      };
      try {
        if (req.method !== "POST" || req.url !== "/v1/recovery-operator") {
          return send(404, { ok: false });
        }
        const presented = req.socket.getPeerCertificate()?.fingerprint256?.toUpperCase();
        if (!req.socket.authorized || !presented
          || (presented !== witnessFingerprint && presented !== adminFingerprint)) {
          return send(403, { ok: false });
        }
        // Limit and authorize certificate identity BEFORE buffering proof bytes.
        const input = parsePayload(await boundInput(req));
        if (!input || typeof input !== "object" || Array.isArray(input)
          || Reflect.ownKeys(input).length !== 2 || !Object.hasOwn(input, "method")
          || !Object.hasOwn(input, "args") || !Array.isArray(input.args)
          || input.args.length > 3 || typeof input.method !== "string") deny();
        const witness = presented === witnessFingerprint;
        if (!(witness ? METHODS : ADMIN_METHODS).has(input.method)) deny();
        const arity = { loadHead: 0, loadFinalizedHead: 0, loadOwnerGeneration: 0,
          loadQuarantinedHead: 0, compareAndAdvance: 2,
          quarantineFinalizedAck: 1, finalizeAck: 3, sealAck: 2,
          advanceOwnerPolicy: 2 };
        if (input.args.length !== arity[input.method]) deny();
        const result = await operator[input.method](...input.args);
        return send(200, { ok: true, value: result });
      } catch (_) { send(409, { ok: false }); }
    });
    server.on("close", () => operator.close());
    return server;
  } catch (e) { operator.close(); throw e; }
}

function invokeRemote(configPath, method, args) {
  const config = readConfig(configPath).client;
  if (!config || typeof config !== "object"
    || !Number.isSafeInteger(config.port) || config.port < 1 || config.port > 65535
    || typeof config.hostname !== "string"
    || !/^[A-Za-z0-9.-]{1,253}$/.test(config.hostname)) deny();
  const certificate = fingerprint(config.serverFingerprint);
  const requestBody = v8.serialize({ method, args });
  if (requestBody.length > MAX_BODY) deny();
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: config.hostname, port: config.port,
      path: "/v1/recovery-operator", method: "POST", agent: false,
      minVersion: "TLSv1.3", rejectUnauthorized: true,
      key: certPath(config.keyPath), cert: certPath(config.certPath),
      ca: certPath(config.serverCaPath), timeout: 3500,
      checkServerIdentity: (host, peer) => {
        const standard = tls.checkServerIdentity(host, peer);
        if (standard) return standard;
        return peer.fingerprint256?.toUpperCase() === certificate
          ? undefined : Error("UNPINNED_OPERATOR_SERVER");
      },
      headers: { "Content-Type": "application/octet-stream",
        "Content-Length": requestBody.length },
    }, async (response) => {
      try {
        const chunks = [];
        let size = 0;
        for await (const chunk of response) {
          size += chunk.length;
          if (size > MAX_BODY) deny();
          chunks.push(chunk);
        }
        if (response.statusCode !== 200) deny();
        const result = parsePayload(Buffer.concat(chunks));
        if (!result || result.ok !== true || !Object.hasOwn(result, "value")) deny();
        resolve(result.value);
      } catch (e) { reject(e); }
    });
    req.on("timeout", () => req.destroy(Error("OPERATOR_TIMEOUT")));
    req.on("error", reject);
    req.end(requestBody);
  });
}

function createSynchronousRecoveryOperatorClient(configPath, { bridgePath =
  path.resolve(__dirname, "../../scripts/zk1-historical-recovery-operator.js") } = {}) {
  if (typeof configPath !== "string" || !path.isAbsolute(configPath)
    || typeof bridgePath !== "string" || !path.isAbsolute(bridgePath)) deny();
  const invoke = (method, args) => {
    if (!METHODS.has(method)) deny();
    const input = v8.serialize({ method, args });
    if (input.length > MAX_BODY) deny();
    // Node's witness API requires synchronous independent CAS readback. A
    // bounded short-lived child owns the TLS socket; a timeout denies access.
    const run = spawnSync(process.execPath, [bridgePath, "--bridge", configPath], {
      input, encoding: null, timeout: 6000, windowsHide: true,
      maxBuffer: MAX_BODY + 4096, stdio: ["pipe", "pipe", "pipe"],
    });
    if (run.error || run.status !== 0 || !Buffer.isBuffer(run.stdout)) deny();
    const result = parsePayload(run.stdout);
    if (!result || result.ok !== true || !Object.hasOwn(result, "value")) deny();
    return result.value;
  };
  return Object.freeze({
    loadHead: () => invoke("loadHead", []),
    loadFinalizedHead: () => invoke("loadFinalizedHead", []),
    loadOwnerGeneration: () => invoke("loadOwnerGeneration", []),
    loadQuarantinedHead: () => invoke("loadQuarantinedHead", []),
    compareAndAdvance: (a, b) => invoke("compareAndAdvance", [a, b]),
    quarantineFinalizedAck: (a) => invoke("quarantineFinalizedAck", [a]),
    finalizeAck: async (a, b, proof) => invoke("finalizeAck", [a, b, proof]),
    sealAck: (a, proof) => invoke("sealAck", [a, proof]),
  });
}
module.exports = { createHistoricalRecoveryOperatorServer,
  createSynchronousRecoveryOperatorClient, invokeRemote, readConfig };
