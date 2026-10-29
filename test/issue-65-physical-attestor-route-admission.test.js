"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { createZk1PgPhysicalAttestorHttpsServer } =
  require("../src/services/zk1PgPhysicalAttestorHttpsServer");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../src/services/zk1SharedPgPhysicalCiphertextVerifier");

function send(port, { ca, clientKey, clientCert }, method, route, payload) {
  return new Promise((resolve, reject) => {
    const body = payload === undefined ? null : Buffer.from(JSON.stringify(payload));
    const req = https.request({ hostname: "127.0.0.1", servername: "localhost",
      port, method, path: route,
      ca, key: clientKey, cert: clientCert, minVersion: "TLSv1.3", agent: false,
      rejectUnauthorized: true,
      headers: body ? { "content-type": "application/json",
        "content-length": String(body.length) } : {},
    }, (res) => {
      res.resume();
      res.on("error", reject);
      res.on("end", () => resolve(res.statusCode));
    });
    req.on("error", reject);
    req.setTimeout(5000, () => req.destroy(Error("TEST_REQUEST_TIMEOUT")));
    req.end(body ?? undefined);
  });
}

test("physical attestor: route and scope cannot trigger verification without pinned mTLS principal", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-attestor-route-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  generateNativeFixtureCertificates(dir, {
    caSubject: "Rootark route test CA", servers: ["attestor"],
    clients: ["permitted", "unlisted"],
  });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const ca = read("ca.pem");
  const permitted = { ca, clientKey: read("permitted.key"), clientCert: read("permitted.pem") };
  const unlisted = { ca, clientKey: read("unlisted.key"), clientCert: read("unlisted.pem") };
  const fingerprint = new crypto.X509Certificate(permitted.clientCert).fingerprint256;
  const scope = { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("vault"),
    keyring_id: crypto.randomBytes(16) };
  const wireScope = (s) => Object.fromEntries(Object.entries(s).map(([key, value]) =>
    [key, value.toString("base64url")]));
  const operation = { operation_id: crypto.randomBytes(16).toString("base64url"),
    expected_sequence: 0, expected_root: crypto.randomBytes(32).toString("base64url"),
    object_id: crypto.randomBytes(16).toString("base64url"), revision: 1, epoch: 0,
    ciphertext_sha256: crypto.randomBytes(32).toString("base64url") };
  const payload = { scope: wireScope(scope), operation,
    nonce: crypto.randomBytes(32).toString("base64url") };

  let calls = 0;
  // No PG connection is made: this stub records the exact security boundary
  // where the actual independent physical verifier would be consulted.
  const verifier = Object.create(Zk1SharedPgPhysicalCiphertextVerifier.prototype);
  verifier.verifyCommittedInventoryOperation = async () => {
    calls += 1;
    throw Error("INTENTIONAL_TEST_READBACK_UNAVAILABLE");
  };
  const server = createZk1PgPhysicalAttestorHttpsServer({
    key: read("attestor.key"), cert: read("attestor.pem"), clientCa: ca,
    signerPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey,
    verifier, principals: { [fingerprint]: [scope] },
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;
  const route = "/v1/physical/attest";

  await assert.rejects(send(port, { ca }, "POST", route, payload),
    "a TLS client without its own certificate cannot reach the handler");
  assert.equal(await send(port, unlisted, "POST", route, payload), 403);
  assert.equal(await send(port, permitted, "GET", route), 404);
  assert.equal(await send(port, permitted, "POST", route + "?nonce=evil", payload), 404);
  assert.equal(await send(port, permitted, "POST", "/v1/physical/attest/", payload), 404);
  assert.equal(calls, 0, "unlisted principals and altered routes cannot touch the verifier");

  const foreignScope = { ...payload, scope: { ...payload.scope,
    keyring_id: crypto.randomBytes(16).toString("base64url") } };
  assert.equal(await send(port, permitted, "POST", route, foreignScope), 403);
  assert.equal(calls, 0, "a valid client certificate is insufficient for a foreign scope");

  assert.equal(await send(port, permitted, "POST", route, payload), 503);
  assert.equal(calls, 1, "only exact route plus pinned client and grant reaches physical verifier");
});
