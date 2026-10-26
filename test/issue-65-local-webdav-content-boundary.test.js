"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const rawFs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { Readable } = require("node:stream");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");

function request(port, method, requestPath, token) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1", port, method, path: requestPath,
      headers: token ? { authorization: `Bearer ${token}`, depth: "0" } : {},
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.once("end", () => resolve({
        status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.once("error", reject);
    req.end();
  });
}

test("issue 65 WebDAV local: deny/error bodies are non-sniffable plain text while PROPFIND stays XML", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-zk1-webdav-content-"));
  const token = crypto.randomBytes(32).toString("base64url");
  const bridge = new LocalSyncWebDavBridge({ rootDir: dir, token, port: 0 });
  t.after(async () => {
    await new Promise((resolve) => bridge.server.close(resolve));
    await fs.rm(dir, { recursive: true, force: true });
  });
  const address = await bridge.start();
  const denied = await request(address.port, "GET", "/%3Cscript%3Ealert(1)%3C/script%3E", "");
  assert.equal(denied.status, 401);
  assert.match(denied.headers["content-type"] || "", /^text\/plain;\s*charset=utf-8$/i);
  assert.equal(denied.headers["x-content-type-options"], "nosniff");
  const wrongMethod = await request(address.port, "PATCH", "/other", token);
  assert.equal(wrongMethod.status, 405);
  assert.match(wrongMethod.headers["content-type"] || "", /^text\/plain;\s*charset=utf-8$/i);
  assert.equal(wrongMethod.headers["x-content-type-options"], "nosniff");
  const propfind = await request(address.port, "PROPFIND", "/", token);
  assert.equal(propfind.status, 207);
  assert.match(propfind.headers["content-type"] || "", /^application\/xml;\s*charset=utf-8$/i);
  assert.equal(propfind.headers["x-content-type-options"], "nosniff");
});

test("issue 65 WebDAV local: GET and HEAD pin regular file identity and never stream by mutable path", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-zk1-webdav-get-fd-"));
  const token = crypto.randomBytes(32).toString("base64url");
  const bridge = new LocalSyncWebDavBridge({ rootDir: dir, token, port: 0 });
  t.after(async () => {
    await new Promise((resolve) => bridge.server.close(resolve));
    await fs.rm(dir, { recursive: true, force: true });
  });
  await fs.writeFile(path.join(dir, "pinned.txt"), "safe-ciphertext");
  const address = await bridge.start();
  const original = rawFs.createReadStream;
  let pathReopen = false;
  rawFs.createReadStream = function (file, options) {
    if (file !== null) {
      pathReopen = true;
      // Model a malicious replacement at the stream's delayed path resolution.
      // Keep exactly the declared Content-Length so the adversarial response
      // completes rather than stalling the HTTP client's framing.
      return Readable.from(["FAKE-CIPHERTEXT"]);
    }
    return original.apply(this, arguments);
  };
  let result;
  try { result = await request(address.port, "GET", "/pinned.txt", token); }
  finally { rawFs.createReadStream = original; }
  assert.equal(result.status, 200);
  assert.equal(pathReopen, false, "GET must read a checked file descriptor, never reopen its path");
  assert.equal(result.body, "safe-ciphertext");
  assert.equal(result.headers["content-type"], "application/octet-stream");
  assert.equal(result.headers["x-content-type-options"], "nosniff");
  const head = await request(address.port, "HEAD", "/pinned.txt", token);
  assert.equal(head.status, 200);
  assert.equal(head.body, "");
  assert.equal(head.headers["content-type"], "application/octet-stream");
  assert.equal(head.headers["x-content-type-options"], "nosniff");
});

test("issue 65 WebDAV local: replacement between lstat and open is rejected before GET headers", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-zk1-webdav-get-swap-"));
  const token = crypto.randomBytes(32).toString("base64url");
  const bridge = new LocalSyncWebDavBridge({ rootDir: dir, token, port: 0 });
  t.after(async () => {
    await new Promise((resolve) => bridge.server.close(resolve));
    await fs.rm(dir, { recursive: true, force: true });
  });
  const target = path.join(dir, "item.bin");
  await fs.writeFile(target, "authorized-bytes");
  const address = await bridge.start();
  const open = rawFs.openSync;
  let swapped = false;
  rawFs.openSync = function (file) {
    if (!swapped && path.resolve(String(file)) === target) {
      swapped = true;
      rawFs.renameSync(target, path.join(dir, "original.bin"));
      rawFs.writeFileSync(target, "unauthorized-bytes");
    }
    return open.apply(this, arguments);
  };
  let result;
  try { result = await request(address.port, "GET", "/item.bin", token); }
  finally { rawFs.openSync = open; }
  assert.equal(swapped, true, "test must replace the pathname before descriptor acquisition");
  assert.equal(result.status, 409);
  assert.equal(result.body.includes("unauthorized-bytes"), false);
  assert.equal(result.headers["x-content-type-options"], "nosniff");
});

test("issue 65 WebDAV local: client abort releases a pinned GET source stream", { timeout: 8000 }, async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-zk1-webdav-get-abort-"));
  const token = crypto.randomBytes(32).toString("base64url");
  const bridge = new LocalSyncWebDavBridge({ rootDir: dir, token, port: 0 });
  const target = path.join(dir, "large.bin");
  await fs.writeFile(target, Buffer.alloc(1024 * 1024));
  const address = await bridge.start();
  const original = rawFs.createReadStream;
  let source;
  let closed = false;
  rawFs.createReadStream = function (file, options) {
    assert.equal(file, null);
    let emitted = false;
    source = new Readable({
      read() {
        if (!emitted) { emitted = true; this.push(Buffer.alloc(4096)); }
        // Intentionally never finish; the client must be able to abort.
      },
      destroy(error, callback) {
        closed = true;
        rawFs.closeSync(options.fd);
        callback(error);
      },
    });
    return source;
  };
  t.after(async () => {
    rawFs.createReadStream = original;
    source?.destroy();
    await new Promise((resolve) => bridge.server.close(resolve));
    await fs.rm(dir, { recursive: true, force: true });
  });
  await new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1", port: address.port, path: "/large.bin",
      headers: { authorization: `Bearer ${token}` },
    }, (res) => res.once("data", () => {
      req.destroy();
      resolve();
    }));
    req.once("error", (error) => { if (error.code !== "ECONNRESET") reject(error); });
    req.end();
  });
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal(closed, true, "abort must destroy source and release its descriptor");
});
