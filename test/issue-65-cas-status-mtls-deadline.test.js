"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const https = require("node:https");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { createZk1CasStatusHttpsClient } =
  require("../src/services/zk1CasStatusHttpsClient");

test("CAS status rejects a pinned mTLS peer that slowly streams a never-ending response", {
  timeout: 10000,
}, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-cas-status-trickle-"));
  const sockets = new Set();
  const intervals = new Set();
  let server;
  t.after(async () => {
    for (const interval of intervals) clearInterval(interval);
    for (const socket of sockets) socket.destroy();
    if (server?.listening) await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dir, { force: true, recursive: true });
  });
  generateNativeFixtureCertificates(dir, {
    caSubject: "Cas Status Deadline Fixture", servers: ["server"], clients: ["client"],
  });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const cert = read("server.pem");
  let accepted = 0;
  server = https.createServer({
    key: read("server.key"), cert, ca: read("ca.pem"),
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, (req, res) => {
    accepted += 1;
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.write('{"proofBase64":"');
    // Each byte arrives earlier than the socket's inactivity timeout.
    const interval = setInterval(() => res.write("A"), 25);
    intervals.add(interval);
    res.once("close", () => {
      clearInterval(interval);
      intervals.delete(interval);
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const client = createZk1CasStatusHttpsClient({
    endpoint: `https://127.0.0.1:${server.address().port}/v1/terminal`,
    ca: read("ca.pem"), clientKey: read("client.key"), clientCert: read("client.pem"),
    serverFingerprint256: new crypto.X509Certificate(cert).fingerprint256,
    timeoutMs: 150,
  });
  const query = {
    account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(8),
    keyring_id: crypto.randomBytes(16), reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), request_digest: crypto.randomBytes(32),
    package_envelope_digest: null, expected_revision: null,
    expected_manifest_digest: null, proposed_revision: 1,
    proposed_manifest_digest: crypto.randomBytes(32),
  };
  let guard;
  try {
    await assert.rejects(Promise.race([
      client.getTerminalProof({ query, nonce: crypto.randomBytes(32) }),
      new Promise((_, reject) => {
        guard = setTimeout(() => reject(new Error("CAS_STATUS_ABSOLUTE_DEADLINE_MISSING")), 750);
      }),
    ]), /CAS_STATUS_TRANSPORT_UNAVAILABLE/);
    assert.equal(accepted, 1, "attack reached the correctly pinned CAS-status peer");
  } finally {
    clearTimeout(guard);
  }
});
