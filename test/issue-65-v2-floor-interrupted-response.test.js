"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { Zk1V2CheckpointFloorHttpsClient } =
  require("../src/services/zk1V2CheckpointFloorHttps");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");

test("mTLS floor rejects truncated HTTP 200 bodies and settles before deadline", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-v2-floor-aborted-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  generateNativeFixtureCertificates(dir, {
    caSubject: "Rootark Floor Abort Test CA", servers: ["floor-server"],
    clients: ["permitted"],
  });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const ca = read("ca.pem");
  const clientCert = read("permitted.pem");
  let delivered = 0;
  let interruptMode = "abort";
  const server = https.createServer({
    key: read("floor-server.key"), cert: read("floor-server.pem"),
    ca, requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, (req, res) => {
    req.resume();
    delivered += 1;
    res.writeHead(200, { "content-type": "application/json", "content-length": "1000" });
    res.write('{"proof":"truncated');
    // First an abrupt peer close, then an indefinitely stalled partial 200.
    if (interruptMode === "abort") setImmediate(() => res.socket?.destroy());
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });

  const floorKeys = crypto.generateKeyPairSync("ed25519");
  const ownerKeys = crypto.generateKeyPairSync("ed25519");
  const client = new Zk1V2CheckpointFloorHttpsClient({
    endpoint: `https://127.0.0.1:${server.address().port}`,
    ca, clientKey: read("permitted.key"), clientCert,
    serverFingerprint256: new crypto.X509Certificate(read("floor-server.pem")).fingerprint256,
    pinnedFloorPublicKey: floorKeys.publicKey, pinnedOwnerPublicKey: ownerKeys.publicKey,
    scope: { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("vault"),
      keyring_id: crypto.randomBytes(16) },
    minimum: { sequence: 128, epoch: 0, chainHash: Buffer.alloc(32),
      headDigest: Buffer.alloc(32), checkpointDigest: Buffer.alloc(32) },
    timeoutMs: 300,
  });
  const outcome = await Promise.race([
    client.freshHead().then(() => "unexpected-success", (error) => error.code || error.message),
    new Promise((resolve) => setTimeout(() => resolve("never-settled"), 2000)),
  ]);
  assert.equal(outcome, "ZK_V2_REMOTE_FLOOR_UNAVAILABLE",
    "a partial 200 body must never leave freshHead indefinitely pending");
  assert.equal(delivered, 1, "request must reach the authenticated TLS service");
  interruptMode = "stall";
  const start = Date.now();
  await assert.rejects(client.freshHead(), /ZK_V2_REMOTE_FLOOR_UNAVAILABLE/,
    "the absolute deadline must reject when the socket has not emitted an error");
  assert.ok(Date.now() - start < 1500, "bounded request deadline must settle stalled responses");
  assert.equal(delivered, 2);
});
