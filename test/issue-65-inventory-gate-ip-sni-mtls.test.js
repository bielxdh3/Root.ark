"use strict";

// Exercise the real HTTPS/TLS handshake for literal-IP inventory and shared
// gate endpoints. SNI must be absent; IP SAN, CA and pin still authenticate
// every independent mTLS socket before an operation reaches the HTTP handler.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const https = require("node:https");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { generateNativeFixtureCertificates, runNativeOpenSsl } =
  require("./support/issue-65-native-openssl-fixture");
const { createZk1ContentInventoryHttpsClient } =
  require("../src/services/zk1ContentInventoryHttpsClient");
const { createZk1SharedPgGateHttpsClient } =
  require("../src/services/zk1SharedPgGateHttpsClient");

function fixtures(dir) {
  generateNativeFixtureCertificates(dir, {
    caSubject: "ZK1 IP SNI Fixture",
    servers: ["server", "wrongip"],
    clients: ["allowed", "denied"],
  });
  // Still issued by the same trusted CA and explicitly pinned by callers,
  // but this certificate cannot authenticate a 127.0.0.1 endpoint.
  fs.writeFileSync(path.join(dir, "wrongip.ext"), [
    "extendedKeyUsage=serverAuth",
    "keyUsage=digitalSignature,keyEncipherment",
    "subjectAltName=DNS:localhost,IP:127.0.0.2",
    "",
  ].join("\n"));
  runNativeOpenSsl(dir, ["x509", "-req", "-in", "wrongip.csr",
    "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
    "-out", "wrongip.pem", "-days", "1", "-extfile", "wrongip.ext"]);
  const load = (name) => fs.readFileSync(path.join(dir, name));
  const serverCert = load("server.pem");
  const wrongIpCert = load("wrongip.pem");
  const allowedCert = load("allowed.pem");
  return {
    ca: load("ca.pem"),
    allowedKey: load("allowed.key"),
    allowedCert,
    deniedKey: load("denied.key"),
    deniedCert: load("denied.pem"),
    allowedFingerprint: new crypto.X509Certificate(allowedCert).fingerprint256,
    server: {
      key: load("server.key"), cert: serverCert,
      fingerprint: new crypto.X509Certificate(serverCert).fingerprint256,
    },
    wrongIp: {
      key: load("wrongip.key"), cert: wrongIpCert,
      fingerprint: new crypto.X509Certificate(wrongIpCert).fingerprint256,
    },
  };
}

async function startServer(t, tls, identity, admittedFingerprint) {
  const routes = [];
  const sni = [];
  const sockets = new Set();
  const server = https.createServer({
    key: identity.key, cert: identity.cert, ca: tls.ca,
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, (request, response) => {
    routes.push(request.url);
    const identityFingerprint = new crypto.X509Certificate(
      request.socket.getPeerCertificate().raw).fingerprint256;
    if (identityFingerprint !== admittedFingerprint) {
      response.writeHead(403, { "content-type": "application/json" });
      response.end("{}");
      return;
    }
    request.resume();
    request.once("end", () => {
      const reply = request.url === "/v1/inventory/chain"
        ? { status: "pending", reason: "UNRESOLVED_INTENT" }
        : request.url === "/v1/admission/start"
          ? { admissionId: Buffer.alloc(16, 0x55).toString("base64url"),
            generation: 1, proceed: true }
          : null;
      response.writeHead(reply ? (request.url === "/v1/admission/start" ? 201 : 200) : 404,
        { "content-type": "application/json" });
      response.end(JSON.stringify(reply || {}));
    });
  });
  server.on("secureConnection", (socket) => sni.push(socket.servername));
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return { port: server.address().port, routes, sni };
}

test("inventory and shared gate IP-literal mTLS omit SNI and retain SAN, pin and role checks", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk65-ip-sni-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  const tls = fixtures(dir);
  const good = await startServer(t, tls, tls.server, tls.allowedFingerprint);
  const signer = crypto.generateKeyPairSync("ed25519");
  const signerId = crypto.randomBytes(16);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(12), keyring_id: crypto.randomBytes(16) };
  const input = { scope, workerId: crypto.randomBytes(16), action: "put",
    objectId: crypto.randomBytes(16).toString("base64url"),
    revision: 1, digest: crypto.randomBytes(32) };
  const makeInventory = (port, fingerprint, opts = {}) =>
    createZk1ContentInventoryHttpsClient({
      endpoint: `https://127.0.0.1:${port}`, ca: tls.ca,
      clientKey: opts.clientKey || tls.allowedKey,
      clientCert: opts.clientCert || tls.allowedCert,
      serverFingerprint256: fingerprint,
      inventoryPublicKey: signer.publicKey, inventorySignerKeyId: signerId,
      idleTimeoutMs: 300, wallTimeoutMs: 1200,
    });
  const makeGate = (port, fingerprint, opts = {}) =>
    createZk1SharedPgGateHttpsClient({
      endpoint: `https://127.0.0.1:${port}`, ca: tls.ca,
      clientKey: opts.clientKey || tls.allowedKey,
      clientCert: opts.clientCert || tls.allowedCert,
      serverFingerprint256: fingerprint, timeoutMs: 1200,
    });
  const page = { scope, afterSequence: 0, limit: 1 };
  const inventoryClient = makeInventory(good.port, tls.server.fingerprint);
  const gateClient = makeGate(good.port, tls.server.fingerprint);
  assert.deepEqual(await inventoryClient.getProofPage(page), {
    status: "pending", reason: "UNRESOLVED_INTENT", authorizesIo: false,
  });
  const admission = await gateClient.beginIoAdmission(input);
  assert.equal(admission.proceed, true);
  assert.equal(admission.generation, 1);
  assert.deepEqual(good.routes, ["/v1/inventory/chain", "/v1/admission/start"]);
  assert.equal(good.sni.length, 2);
  assert.ok(good.sni.every((name) => !name), "literal IP must not be sent as TLS SNI");

  const forgedPin = "00:".repeat(31) + "00";
  await assert.rejects(makeInventory(good.port, forgedPin).getProofPage(page),
    /INVENTORY_HTTP_UNAVAILABLE/);
  await assert.rejects(makeGate(good.port, forgedPin).beginIoAdmission(input),
    /ZK_GATE_TRANSPORT_UNAVAILABLE/);
  await assert.rejects(makeInventory(good.port, tls.server.fingerprint, {
    clientKey: tls.deniedKey, clientCert: tls.deniedCert,
  }).getProofPage(page), /INVENTORY_HTTP_UNAVAILABLE/);
  await assert.rejects(makeGate(good.port, tls.server.fingerprint, {
    clientKey: tls.deniedKey, clientCert: tls.deniedCert,
  }).beginIoAdmission(input), /ZK_GATE_TRANSPORT_UNAVAILABLE/);
  assert.deepEqual(good.routes.slice(0, 2), ["/v1/inventory/chain", "/v1/admission/start"]);
  assert.equal(good.routes.length, 4, "wrong pins must fail before HTTP; denied principals get 403");
  assert.ok(good.sni.every((name) => !name));

  const badSan = await startServer(t, tls, tls.wrongIp, tls.allowedFingerprint);
  await assert.rejects(makeInventory(badSan.port, tls.wrongIp.fingerprint).getProofPage(page),
    /INVENTORY_HTTP_UNAVAILABLE/);
  await assert.rejects(makeGate(badSan.port, tls.wrongIp.fingerprint).beginIoAdmission(input),
    /ZK_GATE_TRANSPORT_UNAVAILABLE/);
  assert.deepEqual(badSan.routes, [], "trusted CA and matching pin cannot override wrong IP SAN");
  assert.ok(badSan.sni.every((name) => !name));

  for (const badPath of ["/redirect", "/v1/admission/start", "/?unsafe=1"]) {
    assert.throws(() => createZk1ContentInventoryHttpsClient({
      endpoint: `https://127.0.0.1:${good.port}${badPath}`, ca: tls.ca,
      clientKey: tls.allowedKey, clientCert: tls.allowedCert,
      serverFingerprint256: tls.server.fingerprint,
      inventoryPublicKey: signer.publicKey, inventorySignerKeyId: signerId,
    }), /INVENTORY_HTTP_UNAVAILABLE/);
    assert.throws(() => createZk1SharedPgGateHttpsClient({
      endpoint: `https://127.0.0.1:${good.port}${badPath}`, ca: tls.ca,
      clientKey: tls.allowedKey, clientCert: tls.allowedCert,
      serverFingerprint256: tls.server.fingerprint,
    }), /ZK_GATE_TRANSPORT_UNAVAILABLE/);
  }
});
