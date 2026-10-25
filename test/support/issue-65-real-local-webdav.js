"use strict";

// Disposable real HTTPS WebDAV peer. No external HTTP endpoint or persistent data.
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { generateNativeFixtureCertificates } = require("./issue-65-native-openssl-fixture");

async function createRealLocalWebdav(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-live-webdav-"));
  const connections = new Set();
  const objects = new Map();
  const folders = new Set();
  const requests = [];
  let server;
  let mode = "normal";
  let version = 0;
  t.after(async () => {
    if (server) {
      for (const socket of connections) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    }
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5 });
  });
  generateNativeFixtureCertificates(directory, { caSubject: "Local ZK65 WebDAV CA",
    servers: ["server"], clients: ["writer", "reader", "foreign"] });
  const pem = (name) => fs.readFileSync(path.join(directory, name), "utf8");
  const ca = pem("ca.pem");
  const fingerprints = Object.fromEntries(["writer", "reader"].map((role) => [
    new crypto.X509Certificate(pem(`${role}.pem`)).fingerprint256, role,
  ]));
  server = https.createServer({ key: pem("server.key"), cert: pem("server.pem"),
    ca, requestCert: true, rejectUnauthorized: true }, (req, res) => {
    const identity = req.client.getPeerCertificate()?.fingerprint256;
    const role = req.client.authorized && fingerprints[identity];
    requests.push({ method: req.method, url: req.url, role: role || null,
      ifMatch: req.headers["if-match"] });
    if (!role || !["MKCOL", "PUT", "GET", "HEAD"].includes(req.method)
      || (["MKCOL", "PUT"].includes(req.method) && role !== "writer")
      || (["GET", "HEAD"].includes(req.method) && role !== "reader")) {
      req.resume(); res.writeHead(403); res.end(); return;
    }
    if (mode === "redirect") {
      req.resume(); res.writeHead(307, { location: "http://169.254.169.254/latest/meta-data/" });
      res.end(); return;
    }
    if (req.method === "MKCOL") {
      req.resume();
      const parent = req.url.slice(0, req.url.lastIndexOf("/")) || "/";
      if (parent !== "/" && !folders.has(parent)) {
        res.writeHead(409); res.end(); return;
      }
      if (folders.has(req.url)) { res.writeHead(405); res.end(); return; }
      folders.add(req.url); res.writeHead(201); res.end(); return;
    }
    const current = objects.get(req.url);
    if (req.method === "PUT") {
      const parent = req.url.slice(0, req.url.lastIndexOf("/"));
      if (!folders.has(parent)) { req.resume(); res.writeHead(409); res.end(); return; }
      if (req.headers["if-match"] && req.headers["if-match"] !== current?.etag) {
        req.resume(); res.writeHead(412); res.end(); return;
      }
      const chunks = [];
      let size = 0;
      req.on("data", (part) => {
        size += part.length;
        if (size > 16 * 1024 * 1024) req.destroy();
        else chunks.push(Buffer.from(part));
      });
      req.on("end", () => {
        const original = Buffer.concat(chunks);
        const ciphertext = mode === "corrupt-on-put"
          ? Buffer.alloc(original.length, 0x5c) : original;
        const etag = `"rev-${++version}"`;
        objects.set(req.url, { ciphertext, etag });
        res.writeHead(current ? 204 : 201, { etag }); res.end();
      });
      return;
    }
    req.resume();
    if (!current) { res.writeHead(404); res.end(); return; }
    if (req.headers["if-match"] && req.headers["if-match"] !== current.etag) {
      res.writeHead(412); res.end(); return;
    }
    const bytes = mode === "corrupt-on-get"
      ? Buffer.alloc(current.ciphertext.length, 0x2c) : current.ciphertext;
    res.writeHead(200, { etag: current.etag, "content-length": bytes.length,
      "content-type": "application/octet-stream" });
    res.end(req.method === "HEAD" ? undefined : bytes);
  });
  server.on("connection", (socket) => {
    connections.add(socket); socket.on("close", () => connections.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const endpoint = `https://127.0.0.1:${server.address().port}/dav`;
  const namespace = "isolated_physical_webdav";
  const common = { developmentOnlyOptIn: true, endpoint, namespace, ca,
    serverFingerprint256: new crypto.X509Certificate(pem("server.pem")).fingerprint256 };
  const config = (role) => ({ ...common, clientCert: pem(`${role}.pem`),
    clientKey: pem(`${role}.key`) });

  function raw(method, objectPath, role) {
    return new Promise((resolve, reject) => {
      const request = https.request({ hostname: "127.0.0.1", port: server.address().port,
        method, path: objectPath, ca, cert: pem(`${role}.pem`),
        key: pem(`${role}.key`), rejectUnauthorized: true }, (response) => {
        response.resume(); response.once("end", () => resolve({ status: response.statusCode,
          headers: response.headers }));
      });
      request.once("error", reject);
      request.end();
    });
  }
  async function provision(folder) {
    for (const suffix of ["/dav", `/dav/${namespace}`,
      `/dav/${namespace}/uploads`, `/dav/${namespace}/uploads/${folder}`]) {
      const result = await raw("MKCOL", suffix, "writer");
      if (result.status !== 201 && result.status !== 405) {
        throw new Error(`WebDAV test MKCOL refused: ${result.status}`);
      }
    }
  }
  return { config, requests, objects, raw, provision, namespace, endpoint,
    setMode: (value) => { mode = value; } };
}

module.exports = { createRealLocalWebdav };
