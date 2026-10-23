"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const https = require("node:https");
const z = require("../src/crypto/rootark-zk-1");
const { createOpaqueCheckpointV2HttpsClient } =
  require("../src/services/zk1OpaqueCheckpointV2Remote");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");

test("v2 independent head rejects unsigned and forged baseline even over pinned TLS", {
  timeout: 30000,
}, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-v2-baseline-auth-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  generateNativeFixtureCertificates(dir, {
    caSubject: "ZK65 Baseline Auth",
    servers: ["v2cas"], clients: ["client"],
  });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const pinned = new crypto.X509Certificate(read("v2cas.pem")).fingerprint256;
  const cas = crypto.generateKeyPairSync("ed25519");
  const floor = crypto.generateKeyPairSync("ed25519");
  const attacker = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("baseline-auth"),
    keyring_id: crypto.randomBytes(16) };
  const head = crypto.randomBytes(32);
  const checkpoint = crypto.randomBytes(32);
  let fake = "unsigned";
  const server = https.createServer({
    key: read("v2cas.key"), cert: read("v2cas.pem"), ca: read("ca.pem"),
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, async (req, res) => {
    try {
      const parts = [];
      for await (const part of req) parts.push(part);
      const { nonce } = JSON.parse(Buffer.concat(parts).toString("utf8"));
      let proof = null;
      if (fake === "forged") {
        const statement = {
          type: "rootark-opaque-checkpoint-remote-receipt/v2",
          ...scope, role: "CAS", state: "V1_BASELINE", sequence: 128,
          head_digest: head, checkpoint_digest: checkpoint,
          operation_id: Buffer.alloc(32),
          cas_signer_fp: crypto.createHash("sha256").update(
            cas.publicKey.export({ format: "der", type: "spki" })).digest(),
          floor_signer_fp: crypto.createHash("sha256").update(
            floor.publicKey.export({ format: "der", type: "spki" })).digest(),
          nonce: Buffer.from(nonce, "base64url"),
          issued_at: Math.floor(Date.now() / 1000),
        };
        const raw = Buffer.from(await z.encodeDeterministic(statement));
        const signature = crypto.sign(null, Buffer.concat([
          Buffer.from("Root.ark/zk-1/opaque-checkpoint-remote/receipt/v2\0"),
          raw,
        ]), attacker.privateKey);
        proof = Buffer.from(await z.encodeDeterministic({
          ...statement, signature,
        })).toString("base64url");
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        state: "V1_BASELINE", sequence: 128,
        headDigest: head.toString("base64url"),
        checkpointDigest: checkpoint.toString("base64url"),
        operationId: null, proof,
      }));
    } catch (_) {
      res.writeHead(500);
      res.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => {
    server.closeAllConnections();
    server.close(resolve);
  }));
  const client = createOpaqueCheckpointV2HttpsClient({
    endpoint: `https://127.0.0.1:${server.address().port}/`,
    ca: read("ca.pem"), clientKey: read("client.key"),
    clientCert: read("client.pem"), serverFingerprint256: pinned,
    authorityPublicKey: cas.publicKey, casPublicKey: cas.publicKey,
    floorPublicKey: floor.publicKey, scope, timeoutMs: 3000,
  });
  await assert.rejects(client.head(), {
    code: "ZK_CHECKPOINT_V2_UNAVAILABLE",
  }, "unsigned baseline MUST NOT be trusted from an otherwise pinned TLS endpoint");
  fake = "forged";
  await assert.rejects(client.head(), {
    code: "ZK_CHECKPOINT_V2_UNAVAILABLE",
  }, "attacker-signed baseline MUST NOT impersonate the independent CAS key");
});
