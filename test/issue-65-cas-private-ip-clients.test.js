"use strict";

// Independent of SQLite native bindings: verify the real TLS handshake of
// both CAS clients on an OS-assigned RFC1918 interface under Node 22 and 24.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { generateNativeFixtureCertificates, runNativeOpenSsl } =
  require("./support/issue-65-native-openssl-fixture");
const { createZk1CasWriteHttpsClient } = require("../src/services/zk1CasWriteHttpsClient");
const { createZk1CasManifestHttpsClient } = require("../src/services/zk1CasManifestHttpsClient");

test("CAS write and manifest clients omit IP SNI while enforcing IP SAN and peer pins", async (t) => {
  const address = Object.entries(os.networkInterfaces()).flatMap(([adapter, entries]) =>
    (entries || []).map((entry) => ({ adapter, entry }))).find(({ entry }) => {
      if ((entry.family !== 4 && entry.family !== "IPv4")
        || entry.internal || net.isIP(entry.address) !== 4) return false;
      const [a, b] = entry.address.split(".").map(Number);
      return a === 10 || (a === 172 && b >= 16 && b <= 31)
        || (a === 192 && b === 168);
    });
  if (!address) return t.skip("no assigned RFC1918 adapter");
  const host = address.entry.address;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-private-tls-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  generateNativeFixtureCertificates(dir, {
    caSubject: "Rootark Private CAS Test CA", servers: ["server", "wrong"],
    clients: ["writer", "reader"],
  });
  fs.writeFileSync(path.join(dir, "server.ext"), [
    "extendedKeyUsage=serverAuth", "keyUsage=digitalSignature,keyEncipherment",
    `subjectAltName=IP:${host}`, "",
  ].join("\n"));
  runNativeOpenSsl(dir, ["x509", "-req", "-in", "server.csr",
    "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
    "-out", "server.pem", "-days", "1", "-extfile", "server.ext"]);
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const ca = read("ca.pem");
  const serverCert = read("server.pem");
  const serverPin = new crypto.X509Certificate(serverCert).fingerprint256;
  const oldCert = read("wrong.pem");
  const wrongPin = new crypto.X509Certificate(oldCert).fingerprint256;
  const scope = {
    account_id: crypto.randomBytes(16), compartment_id: Buffer.from("private-test"),
    keyring_id: crypto.randomBytes(16),
  };
  const responseManifest = Buffer.from("untrusted-cas-test-manifest");
  const writer = { clientKey: read("writer.key"), clientCert: read("writer.pem") };
  const reader = { clientKey: read("reader.key"), clientCert: read("reader.pem") };
  const receipt = crypto.randomBytes(64);
  const seenServerNames = [];

  const createServer = (key, cert) => {
    const server = https.createServer({
      key, cert, ca, requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
    }, (req, res) => {
      const fingerprint = req.socket.getPeerCertificate()?.fingerprint256;
      const role = fingerprint === new crypto.X509Certificate(writer.clientCert).fingerprint256
        ? "writer" : fingerprint === new crypto.X509Certificate(reader.clientCert).fingerprint256
          ? "reader" : "none";
      const validRole = req.url === "/v1/register" || req.url === "/v1/commit"
        ? role === "writer" : role === "reader";
      req.resume();
      res.setHeader("content-type", "application/json");
      if (!validRole) {
        res.writeHead(403);
        res.end('{"error":"FORBIDDEN"}');
      } else if (req.url === "/v1/register") {
        res.end('{"status":"pending","authority":"CAS_ENGINE_ONLY"}');
      } else if (req.url === "/v1/commit") {
        res.end('{"status":"committed","replay":true,"authority":"CAS_ENGINE_ONLY"}');
      } else if (req.url === "/v1/manifest") {
        res.end(JSON.stringify({ manifestBase64: responseManifest.toString("base64url") }));
      } else {
        res.writeHead(404);
        res.end('{"error":"NOT_FOUND"}');
      }
    });
    server.on("secureConnection", (socket) => seenServerNames.push(socket.servername));
    return server;
  };
  async function listen(server) {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, host, resolve);
    });
    return `https://${host}:${server.address().port}`;
  }
  async function close(server) {
    await new Promise((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
  }
  const live = createServer(read("server.key"), serverCert);
  const base = await listen(live);
  try {
    const makeWriter = (endpoint, pin, creds = writer) => createZk1CasWriteHttpsClient({
      endpoint, ca, clientKey: creds.clientKey, clientCert: creds.clientCert,
      serverFingerprint256: pin,
    });
    const makeReader = (endpoint, pin, creds = reader) => createZk1CasManifestHttpsClient({
      endpoint: endpoint + "/v1/manifest", ca,
      clientKey: creds.clientKey, clientCert: creds.clientCert,
      serverFingerprint256: pin,
    });
    assert.deepEqual(await makeWriter(base, serverPin).register({ receipt }), { status: "pending" });
    assert.deepEqual(await makeWriter(base, serverPin).commit({
      receipt, manifestBytes: responseManifest,
    }), { status: "committed", replay: true });
    assert.deepEqual(await makeReader(base, serverPin).getCommittedManifest({ scope }), responseManifest);
    assert.equal(seenServerNames.length, 3);
    assert.ok(seenServerNames.every((value) => !value), "IP host must not be transmitted in TLS SNI");
    await assert.rejects(makeWriter(base, wrongPin).register({ receipt }),
      /CAS_WRITE_TRANSPORT_UNAVAILABLE/);
    await assert.rejects(makeReader(base, wrongPin).getCommittedManifest({ scope }),
      /CAS_MANIFEST_TRANSPORT_UNAVAILABLE/);
    await assert.rejects(makeWriter(base, serverPin, reader).register({ receipt }),
      /CAS_WRITE_TRANSPORT_UNAVAILABLE/, "reader mTLS identity cannot write");
    await assert.rejects(makeReader(base, serverPin, writer).getCommittedManifest({ scope }),
      /CAS_MANIFEST_TRANSPORT_UNAVAILABLE/, "writer mTLS identity cannot read");
    assert.throws(() => makeWriter(base + "/v1/register", serverPin),
      /CAS_WRITE_TRANSPORT_UNAVAILABLE/);
    assert.throws(() => createZk1CasManifestHttpsClient({
      endpoint: base + "/v1/history", ca,
      clientKey: reader.clientKey, clientCert: reader.clientCert,
      serverFingerprint256: serverPin,
    }), /CAS_MANIFEST_TRANSPORT_UNAVAILABLE/);
  } finally { await close(live); }

  // A trusted CA and matching certificate fingerprint are insufficient when
  // the endpoint is an IP that does not appear in the server certificate SAN.
  const invalidSan = createServer(read("wrong.key"), oldCert);
  const invalidBase = await listen(invalidSan);
  try {
    await assert.rejects(createZk1CasWriteHttpsClient({
      endpoint: invalidBase, ca, clientKey: writer.clientKey,
      clientCert: writer.clientCert, serverFingerprint256: wrongPin,
    }).register({ receipt }), /CAS_WRITE_TRANSPORT_UNAVAILABLE/);
    await assert.rejects(createZk1CasManifestHttpsClient({
      endpoint: invalidBase + "/v1/manifest", ca,
      clientKey: reader.clientKey, clientCert: reader.clientCert,
      serverFingerprint256: wrongPin,
    }).getCommittedManifest({ scope }), /CAS_MANIFEST_TRANSPORT_UNAVAILABLE/);
  } finally { await close(invalidSan); }
});
