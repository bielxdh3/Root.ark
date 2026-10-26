"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { performance } = require("node:perf_hooks");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { createZk1CasWriteHttpsClient } =
  require("../src/services/zk1CasWriteHttpsClient");

test("CAS write fails within wall deadline when a pinned mTLS peer trickles bytes", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-cas-write-deadline-"));
  t.after(() => fs.rmSync(dir, { force: true, recursive: true, maxRetries: 5 }));
  generateNativeFixtureCertificates(dir, { caSubject: "CAS Write Deadline Fixture",
    servers: ["server"], clients: ["client"] });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const tls = { ca: read("ca.pem"), cert: read("server.pem"), key: read("server.key"),
    clientCert: read("client.pem"), clientKey: read("client.key") };
  let drip = false;
  const intervals = new Set();
  const sockets = new Set();
  const server = https.createServer({ key: tls.key, cert: tls.cert, ca: tls.ca,
    requestCert: true, rejectUnauthorized: true }, (request, response) => {
    request.resume();
    request.once("end", () => {
      const body = JSON.stringify({ status: "pending", authority: "CAS_ENGINE_ONLY" });
      response.writeHead(200, { "content-type": "application/json" });
      if (!drip) return response.end(body);
      response.flushHeaders();
      let position = 0;
      const interval = setInterval(() => {
        if (response.destroyed || position >= body.length) {
          clearInterval(interval);
          intervals.delete(interval);
          if (!response.destroyed) response.end();
          return;
        }
        response.write(body[position++]);
      }, 55);
      intervals.add(interval);
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    for (const interval of intervals) clearInterval(interval);
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const config = {
    endpoint: `https://localhost:${server.address().port}`,
    ca: tls.ca, clientCert: tls.clientCert, clientKey: tls.clientKey,
    serverFingerprint256: new crypto.X509Certificate(tls.cert).fingerprint256,
  };
  const receipt = crypto.randomBytes(64);
  assert.deepEqual(await createZk1CasWriteHttpsClient({ ...config,
    timeoutMs: 2000 }).register({ receipt }), { status: "pending" },
    "healthy mTLS peer must remain usable");

  drip = true;
  const start = performance.now();
  await assert.rejects(createZk1CasWriteHttpsClient({ ...config,
    timeoutMs: 500 }).register({ receipt }), /CAS_WRITE_TRANSPORT_UNAVAILABLE/);
  assert.ok(performance.now() - start < 2000,
    "periodic response bytes cannot indefinitely extend the configured request deadline");
});
