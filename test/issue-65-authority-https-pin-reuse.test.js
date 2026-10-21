"use strict";

// A connection opened by client A must not be reused by client B with a
// different pin. TLS.checkServerIdentity runs on handshake, not on re-use.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const https = require("node:https");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { createZk1WitnessHttpsClient } = require("../src/services/zk1WitnessHttpsClient");
const { createZk1CasManifestHttpsClient } = require("../src/services/zk1CasManifestHttpsClient");
const { createZk1CasWriteHttpsClient } = require("../src/services/zk1CasWriteHttpsClient");
const { createZk1CasStatusHttpsClient } = require("../src/services/zk1CasStatusHttpsClient");

function certificates(dir) {
  const cmds = [
    "set -eu",
    'openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=ZK1 Fixture CA" -days 1 >/dev/null 2>&1',
    'openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" >/dev/null 2>&1',
    'printf "subjectAltName=DNS:localhost,IP:127.0.0.1\\nextendedKeyUsage=serverAuth\\n" > server.ext',
    'openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 1 -extfile server.ext >/dev/null 2>&1',
    'openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=zkfixture" >/dev/null 2>&1',
    'printf "extendedKeyUsage=clientAuth\\n" > client.ext',
    'openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 1 -extfile client.ext >/dev/null 2>&1',
  ].join("\n");
  if (process.platform === "win32") {
    const unixDir = execFileSync("wsl.exe", ["-e", "wslpath", "-a", dir],
      { encoding: "utf8" }).trim();
    execFileSync("wsl.exe", ["-e", "bash", "-lc", "cd " + JSON.stringify(unixDir) + "; " + cmds],
      { stdio: "pipe", timeout: 25000 });
  } else {
    execFileSync("bash", ["-lc", cmds], { cwd: dir, stdio: "pipe", timeout: 25000 });
  }
  const read = (name) => fs.readFileSync(path.join(dir, name));
  return { ca: read("ca.pem"), key: read("server.key"), cert: read("server.pem"),
    clientKey: read("client.key"), clientCert: read("client.pem") };
}

test("every zk1 authority transport enforces its own TLS pin after previous same-target keep-alive request", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-pin-reuse-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  const tls = certificates(dir);
  const server = https.createServer({
    key: tls.key, cert: tls.cert, ca: tls.ca,
    requestCert: true, rejectUnauthorized: true,
  }, (request, response) => {
    request.resume();
    request.on("end", () => {
      const body = request.url === "/v1/head"
        ? { receiptBase64: Buffer.from("head").toString("base64url"), authority: "WITNESS_ENGINE_ONLY" }
        : request.url === "/v1/manifest"
          ? { manifestBase64: Buffer.from("manifest").toString("base64url") }
          : request.url === "/v1/terminal"
            ? { proofBase64: Buffer.from("terminal").toString("base64url") }
            : { status: "pending", authority: "CAS_ENGINE_ONLY" };
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(body));
    });
  });
  const sockets = new Set();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolve) => server.listen(0, "localhost", resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const correct = new crypto.X509Certificate(tls.cert).fingerprint256;
  const wrong = "00:".repeat(31) + "00";
  const opts = { ca: tls.ca, clientKey: tls.clientKey, clientCert: tls.clientCert };
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(12), keyring_id: crypto.randomBytes(16) };
  const query = { ...scope, reservation_id: crypto.randomBytes(16),
    operation_id: crypto.randomBytes(16), request_digest: crypto.randomBytes(32),
    package_envelope_digest: null, expected_revision: 1,
    expected_manifest_digest: crypto.randomBytes(32),
    proposed_revision: 2, proposed_manifest_digest: crypto.randomBytes(32) };
  // A deliberately shared persistent agent exposes wrong-pin client reuse
  // when the implementation does not isolate each TLS connection.
  const originalAgent = https.globalAgent;
  const shared = new https.Agent({ keepAlive: true, maxSockets: 1 });
  https.globalAgent = shared;
  try {
    const port = server.address().port;
    const cases = [
      ["witness", (pin) => createZk1WitnessHttpsClient({
        ...opts, endpoint: `https://localhost:${port}`,
        serverFingerprint256: pin,
      }).freshHead({ scope, nonce: crypto.randomBytes(32) })],
      ["CAS manifest", (pin) => createZk1CasManifestHttpsClient({
        ...opts, endpoint: `https://localhost:${port}/v1/manifest`,
        serverFingerprint256: pin,
      }).getCommittedManifest({ scope })],
      ["CAS status", (pin) => createZk1CasStatusHttpsClient({
        ...opts, endpoint: `https://localhost:${port}/v1/terminal`,
        serverFingerprint256: pin,
      }).getTerminalProof({ query, nonce: crypto.randomBytes(32) })],
      ["CAS write", (pin) => createZk1CasWriteHttpsClient({
        ...opts, endpoint: `https://localhost:${port}`,
        serverFingerprint256: pin,
      }).register({ receipt: crypto.randomBytes(128) })],
    ];
    for (const [label, send] of cases) {
      await send(correct);
      await assert.rejects(send(wrong), /TRANSPORT_UNAVAILABLE/,
        label + ": wrong-pin client must never inherit a verified previous socket");
    }
  } finally {
    https.globalAgent = originalAgent;
    shared.destroy();
  }
});
