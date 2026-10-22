"use strict";

// Opt-in development replication of already opaque ZK1 ciphertext.
// An HTTPS PUT ACK is neither storage durability nor authorization evidence.
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const tls = require("node:tls");

const MAX_BYTES = 16 * 1024 * 1024;
const DEADLINE_MS = 15000;
const MAX_ACK = 4096;
const SAFE_NAMESPACE = /^[a-z0-9][a-z0-9_-]{2,63}$/;
const SAFE_FOLDER = /^zk1-[a-f0-9]{64}$/;
const SAFE_FILE = /^[A-Za-z0-9_-]{22}\.ct$/;

function unavailable() {
  const error = new Error("ZK_WEBDAV_CIPHERTEXT_UNAVAILABLE");
  error.code = error.message;
  return error;
}

function ensure(condition) { if (!condition) throw unavailable(); }

function samePath(left, right) {
  const a = path.resolve(left);
  const b = path.resolve(right);
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function pinParent(filename) {
  ensure(typeof filename === "string" && path.isAbsolute(filename));
  const directory = path.dirname(filename);
  const stat = fs.lstatSync(directory, { bigint: true });
  // O_NOFOLLOW only guards the leaf. A redirected ancestor can make a valid
  // exclusive create publish bytes into a foreign directory on Windows/Unix.
  ensure(stat.isDirectory() && !stat.isSymbolicLink()
    && samePath(fs.realpathSync.native(directory), directory));
  return { directory, dev: stat.dev, ino: stat.ino };
}

function verifyParent(pin) {
  const current = pinParent(path.join(pin.directory, "_webdav_parent_pin"));
  ensure(current.dev === pin.dev && current.ino === pin.ino);
}

function readBoundedFile(source, length) {
  const parent = pinParent(source);
  const namedBefore = fs.lstatSync(source, { bigint: true });
  ensure(namedBefore.isFile() && !namedBefore.isSymbolicLink()
    && namedBefore.nlink === 1n && namedBefore.size === BigInt(length));
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)
    | (fs.constants.O_CLOEXEC || 0);
  const fd = fs.openSync(source, flags);
  try {
    verifyParent(parent);
    const before = fs.fstatSync(fd, { bigint: true });
    ensure(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n
      && before.size === BigInt(length) && before.dev === namedBefore.dev
      && before.ino === namedBefore.ino);
    const data = Buffer.allocUnsafe(length);
    let position = 0;
    while (position < length) {
      const n = fs.readSync(fd, data, position, length - position, position);
      ensure(n > 0);
      position += n;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const namedAfter = fs.lstatSync(source, { bigint: true });
    verifyParent(parent);
    ensure(after.dev === before.dev && after.ino === before.ino
      && after.size === before.size && after.mtimeNs === before.mtimeNs
      && after.nlink === 1n && namedAfter.dev === before.dev
      && namedAfter.ino === before.ino && !namedAfter.isSymbolicLink()
      && namedAfter.nlink === 1n);
    return data;
  } finally { fs.closeSync(fd); }
}

function writeExclusive(destination, data, parent) {
  verifyParent(parent);
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
    | (fs.constants.O_NOFOLLOW || 0);
  const fd = fs.openSync(destination, flags, 0o600);
  try {
    verifyParent(parent);
    let offset = 0;
    while (offset < data.length) {
      const count = fs.writeSync(fd, data, offset, data.length - offset);
      ensure(count > 0);
      offset += count;
    }
    fs.fsyncSync(fd);
    verifyParent(parent);
  } finally {
    fs.closeSync(fd);
    // Never unlink by pathname after a failed write: a concurrent rename
    // could replace that name with somebody else's file before cleanup.
    // The caller owns cleanup of its private staging directory.
  }
}

function createZk1WebdavCiphertextAdapter(config = {}) {
  try {
    // Never let production config accidentally enable this experimental endpoint.
    ensure(config && Object.getPrototypeOf(config) === Object.prototype
      && config.developmentOnlyOptIn === true
      && process.env.NODE_ENV === "development"
      && typeof config.endpoint === "string"
      && /^https:\/\/[A-Za-z0-9.-]+(?::\d{1,5})?(?:\/[A-Za-z0-9_-]+)*\/?$/.test(config.endpoint)
      && SAFE_NAMESPACE.test(config.namespace)
      && typeof config.ca === "string" && config.ca.includes("BEGIN CERTIFICATE")
      && typeof config.serverFingerprint256 === "string");
    const endpoint = new URL(config.endpoint);
    ensure(endpoint.protocol === "https:" && !endpoint.username && !endpoint.password
      && !endpoint.search && !endpoint.hash && endpoint.hostname && !endpoint.pathname.includes("//"));
    const pin = config.serverFingerprint256.replace(/:/g, "").toLowerCase();
    ensure(/^[a-f0-9]{64}$/.test(pin));
    const namespace = config.namespace;
    const root = endpoint.pathname.replace(/\/$/, "");
    const ca = String(config.ca);
    const clientCert = config.clientCert;
    const clientKey = config.clientKey;
    ensure((clientCert === undefined && clientKey === undefined)
      || (typeof clientCert === "string" && clientCert.includes("BEGIN CERTIFICATE")
        && typeof clientKey === "string" && clientKey.includes("PRIVATE KEY")));
    const username = config.username;
    const password = config.password;
    ensure((username === undefined && password === undefined)
      || (typeof username === "string" && /^[A-Za-z0-9_.@-]{1,128}$/.test(username)
        && typeof password === "string" && password.length >= 1 && password.length <= 1024
        && !/[\r\n]/.test(password)));
    const authorization = username === undefined ? null
      : `Basic ${Buffer.from(`${username}:${password}`, "utf8").toString("base64")}`;
    // This identifies operator-pinned transport parameters, NOT a server
    // authenticated storage principal or a durable remote state.
    const context = crypto.createHash("sha256").update(JSON.stringify([
      "rootark-zk1-dev-webdav/v1", endpoint.origin, root, namespace, pin,
      username || "", clientCert ? crypto.createHash("sha256").update(clientCert).digest("hex") : "",
    ])).digest("hex");
    const namespaceIdentity = crypto.createHash("sha256").update(JSON.stringify([
      "rootark-zk1/webdav-namespace/v1", endpoint.origin, root, namespace, pin,
    ])).digest("hex");

    function key(folder, name, area) {
      ensure(area === "uploads" && SAFE_FOLDER.test(folder)
        && SAFE_FILE.test(name));
      return `${namespace}/uploads/${folder}/${name}`;
    }

    function transfer(method, objectKey, uploadBytes, expectedLength) {
      return new Promise((resolve, reject) => {
        let complete = false;
        let total = 0;
        const parts = [];
        let timer;
        let request;
        const finish = (error, value) => {
          if (complete) return;
          complete = true;
          clearTimeout(timer);
          if (error) {
            if (request) request.destroy();
            reject(unavailable());
          } else resolve(value);
        };
        try {
          const headers = { "accept-encoding": "identity" };
          if (authorization) headers.authorization = authorization;
          if (method === "PUT") {
            headers["content-type"] = "application/octet-stream";
            headers["content-length"] = String(uploadBytes.length);
          }
          request = https.request({
            protocol: "https:", hostname: endpoint.hostname, port: endpoint.port || 443,
            path: `${root}/${objectKey}`, method, headers,
            ca, cert: clientCert, key: clientKey, rejectUnauthorized: true,
            agent: false, // a new TLS handshake checks the pin for each operation
            checkServerIdentity(host, certificate) {
              const hostnameError = tls.checkServerIdentity(host, certificate);
              if (hostnameError) return unavailable();
              if (!certificate.raw || !crypto.timingSafeEqual(
                crypto.createHash("sha256").update(certificate.raw).digest(),
                Buffer.from(pin, "hex"))) return unavailable();
              return undefined;
            },
          }, (response) => {
            const goodStatus = method === "GET" ? response.statusCode === 200
              : [200, 201, 204].includes(response.statusCode);
            if (!goodStatus || (method === "GET" &&
              (response.headers["content-encoding"] && response.headers["content-encoding"] !== "identity"
                || response.headers["content-range"]))) {
              response.destroy();
              return finish(unavailable());
            }
            const max = method === "GET" ? expectedLength : MAX_ACK;
            if (response.headers["content-length"] !== undefined) {
              const advertised = response.headers["content-length"];
              if (!/^\d+$/.test(advertised) || Number(advertised) > max
                || (method === "GET" && Number(advertised) !== expectedLength)) {
                response.destroy();
                return finish(unavailable());
              }
            }
            response.on("data", (chunk) => {
              total += chunk.length;
              if (total > max) { response.destroy(); finish(unavailable()); }
              else if (method === "GET") parts.push(Buffer.from(chunk));
            });
            response.on("end", () => {
              if (method === "GET" && total !== expectedLength) finish(unavailable());
              else finish(null, method === "GET" ? Buffer.concat(parts, total) : null);
            });
            response.on("aborted", () => finish(unavailable()));
            response.on("error", () => finish(unavailable()));
          });
          request.on("error", () => finish(unavailable()));
          timer = setTimeout(() => finish(unavailable()), DEADLINE_MS);
          request.end(uploadBytes || undefined);
        } catch (_) { finish(unavailable()); }
      });
    }

    return Object.freeze({
      enabled: () => true,
      status: () => Object.freeze({ provider: "webdav", enabled: true, developmentOnly: true }),
      resolveInventoryContext: async () => context,
      zk1StorageNamespace: () => namespaceIdentity,
      key,
      async upload(source, folder, name, area, opts) {
        try {
          const objectKey = key(folder, name, area);
          ensure(opts && Object.keys(opts).length === 1
            && Number.isSafeInteger(opts.zk1BoundedBytes)
            && opts.zk1BoundedBytes >= 1 && opts.zk1BoundedBytes <= MAX_BYTES);
          const bytes = readBoundedFile(source, opts.zk1BoundedBytes);
          await transfer("PUT", objectKey, bytes, 0);
          return Object.freeze({ provider: "webdav", key: objectKey });
        } catch (_) { throw unavailable(); }
      },
      async download(folder, name, destination, area, allowWrite, opts) {
        try {
          const objectKey = key(folder, name, area);
          ensure(opts && Object.keys(opts).length === 1
            && Number.isSafeInteger(opts.maxBytes) && opts.maxBytes >= 1
            && opts.maxBytes <= MAX_BYTES && typeof destination === "string"
            && typeof allowWrite === "function" && allowWrite() === true);
          const parent = pinParent(destination);
          const bytes = await transfer("GET", objectKey, null, opts.maxBytes);
          ensure(allowWrite() === true);
          writeExclusive(destination, bytes, parent);
          return true;
        } catch (_) { throw unavailable(); }
      },
    });
  } catch (_) { throw unavailable(); }
}

module.exports = { createZk1WebdavCiphertextAdapter };
