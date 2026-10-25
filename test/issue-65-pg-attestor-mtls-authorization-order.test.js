"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../src/services/zk1SharedPgPhysicalCiphertextVerifier");
const { createZk1PgPhysicalAttestorHttpsServer } =
  require("../src/services/zk1PgPhysicalAttestorHttpsServer");

test("read-only attestor authenticates the mTLS principal before reporting method or path", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-attestor-auth-order-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  generateNativeFixtureCertificates(dir, { caSubject: "Disposable attestor auth order",
    servers: ["attestor"], clients: ["allowed", "other"] });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("vault"), keyring_id: crypto.randomBytes(16) };
  const fingerprint = new crypto.X509Certificate(read("allowed.pem")).fingerprint256;
  // The TLS admission decision occurs before PG readback and is exercised with
  // actual OS TLS identities; no connection to an external DB is necessary.
  const verifier = Object.create(Zk1SharedPgPhysicalCiphertextVerifier.prototype);
  verifier.verifyCommittedInventoryOperation = () => {
    throw Error("mTLS method/path probe reached protected PG readback");
  };
  const server = createZk1PgPhysicalAttestorHttpsServer({
    key: read("attestor.key"), cert: read("attestor.pem"), clientCa: read("ca.pem"),
    signerPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey,
    verifier, principals: { [fingerprint]: [scope] },
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  async function probe(identity, method, requestedPath) {
    return new Promise((resolve, reject) => {
      const req = https.request({ hostname: "localhost", port: server.address().port,
        ca: read("ca.pem"), key: read(identity + ".key"), cert: read(identity + ".pem"),
        method, path: requestedPath }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      });
      req.on("error", reject);
      req.end();
    });
  }
  assert.equal(await probe("other", "GET", "/wrong"), 403,
    "CA-signed but unauthorized TLS peers cannot probe route metadata");
  assert.equal(await probe("other", "POST", "/v1/physical/attest"), 403);
  assert.equal(await probe("allowed", "GET", "/wrong"), 404,
    "the pinned TLS principal alone can receive ordinary unknown-route replies");
  assert.equal(await probe("allowed", "GET", "/v1/physical/attest"), 404);
});
