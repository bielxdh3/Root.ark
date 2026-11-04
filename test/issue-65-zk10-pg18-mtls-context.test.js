"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const { createPinnedLabClientTls } =
  require("../lab/issue-65-zk10-pg18-operator/pinned-mtls-client");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { privateAuthorityDirectory } =
  require("./support/issue-65-private-authority-directory");

function get(url, options) {
  return new Promise((resolve, reject) => {
    const request = https.request(url, {
      ...options, method: "POST", timeout: 4000,
    }, (response) => {
      const protocol = response.socket.getProtocol();
      const authorized = response.socket.authorized;
      response.resume();
      response.on("end", () => resolve({ status: response.statusCode, protocol, authorized }));
      response.on("error", reject);
    });
    request.on("timeout", () => request.destroy(Error("ZK10_TEST_TLS_TIMEOUT")));
    request.on("error", reject);
    request.end("{}");
  });
}

test("PG18 disposable mTLS uses TLS1.3, verified server pin and pinned client identity", {
  timeout: 40000,
}, async (t) => {
  const dir = privateAuthorityDirectory("zk10-w168-mtls-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  generateNativeFixtureCertificates(dir, {
    caSubject: "ZK10 W168 disposable CA", servers: ["authority"],
    clients: ["client", "foreign"],
  });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const serverPin = new crypto.X509Certificate(read("authority.pem")).fingerprint256;
  const clientPin = new crypto.X509Certificate(read("client.pem")).fingerprint256;
  const server = https.createServer({
    cert: read("authority.pem"), key: read("authority.key"), ca: read("ca.pem"),
    minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
    requestCert: true, rejectUnauthorized: true,
  }, (req, res) => {
    res.statusCode = req.socket.authorized
      && req.socket.getPeerCertificate().fingerprint256 === clientPin ? 200 : 403;
    res.end();
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `https://127.0.0.1:${server.address().port}/`;
  const options = createPinnedLabClientTls(dir, "client", serverPin);
  assert.ok(options.secureContext, "Node TLS receives a pre-built SecureContext");
  for (const field of ["key", "cert", "ca"]) {
    assert.equal(Object.hasOwn(options, field), false,
      "private certificate material does not appear in HTTP request options");
  }
  assert.deepEqual(await get(url, options), {
    status: 200, protocol: "TLSv1.3", authorized: true,
  });
  assert.equal((await get(url, createPinnedLabClientTls(dir, "foreign", serverPin))).status, 403,
    "another CA-signed client cannot inherit the pinned mTLS identity");
  await assert.rejects(get(url, createPinnedLabClientTls(dir, "client", "00:".repeat(31) + "00")),
    /ZK10_PEER_PIN_MISMATCH/, "a valid CA chain cannot override the server pin");
  assert.throws(() => createPinnedLabClientTls(dir, "../authority", serverPin),
    /ZK10_CLIENT_TLS_CONFIG_INVALID/);
});
