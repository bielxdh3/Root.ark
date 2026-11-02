"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const z = require("../src/crypto/rootark-zk-1");
const { verifySignedHead, DOMAIN, TYPE } =
  require("../src/services/zk1V2CheckpointRemoteFloor");
const { createZk1V2CheckpointFloorHttpsServer,
  Zk1V2CheckpointFloorHttpsClient } =
  require("../src/services/zk1V2CheckpointFloorHttps");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");

const OWNER_DOMAIN = Buffer.from("Root.ark/zk-1/v2-checkpoint-floor-owner-advance/v1\0");
const ENTRY_DOMAIN = Buffer.from("v2-independent-floor-entry\0");
const ZERO = Buffer.alloc(32);
const sha = (...parts) => crypto.createHash("sha256").update(Buffer.concat(parts)).digest();

async function signedAncestry(scope, minimum, nonce, floorPrivateKey, ownerPrivateKey, count) {
  let chainHash = Buffer.from(minimum.chainHash);
  let headDigest = Buffer.from(minimum.headDigest);
  let checkpointDigest = Buffer.from(minimum.checkpointDigest);
  const ancestry = [];
  for (let i = 1; i <= count; i += 1) {
    const step = {
      sequence: minimum.sequence + i, epoch: i,
      head_digest: crypto.randomBytes(32), checkpoint_digest: crypto.randomBytes(32),
      previous_head_digest: headDigest, previous_checkpoint_digest: checkpointDigest,
      operation_id: crypto.randomBytes(32), cas_receipt_hash: crypto.randomBytes(32),
      floor_receipt_hash: crypto.randomBytes(32),
    };
    const statement = Buffer.from(await z.encodeDeterministic({ ...scope, ...step }));
    const ownerSignature = crypto.sign(null,
      Buffer.concat([OWNER_DOMAIN, statement]), ownerPrivateKey);
    chainHash = sha(ENTRY_DOMAIN, chainHash, statement, ownerSignature);
    ancestry.push({ ...step, owner_signature: ownerSignature });
    headDigest = step.head_digest;
    checkpointDigest = step.checkpoint_digest;
  }
  const last = ancestry.at(-1);
  const unsigned = {
    type: TYPE, ...scope, sequence: minimum.sequence + count, epoch: count,
    head_digest: headDigest, checkpoint_digest: checkpointDigest,
    chain_hash: chainHash, operation_id: last.operation_id,
    cas_receipt_hash: last.cas_receipt_hash,
    floor_receipt_hash: last.floor_receipt_hash,
    cas_receipt_identity_hash: crypto.randomBytes(32),
    floor_receipt_identity_hash: crypto.randomBytes(32),
    ancestry, nonce: Buffer.from(nonce), issued_at: Math.floor(Date.now() / 1000),
  };
  const signature = crypto.sign(null, Buffer.concat([DOMAIN,
    Buffer.from(await z.encodeDeterministic(unsigned))]), floorPrivateKey);
  return Buffer.from(await z.encodeDeterministic({ ...unsigned, signature }));
}

test("V2 floor HTTPS accepts eight signed ancestors and bounds the response", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-v2-floor-https-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  generateNativeFixtureCertificates(dir, {
    caSubject: "Rootark V2 Floor Test CA", servers: ["floor-server"],
    clients: ["permitted", "unlisted"],
  });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const ca = read("ca.pem");
  const permitted = { ca, clientKey: read("permitted.key"),
    clientCert: read("permitted.pem") };
  const floorKeys = crypto.generateKeyPairSync("ed25519");
  const ownerKeys = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(128),
    keyring_id: crypto.randomBytes(16) };
  const minimum = { sequence: 128, epoch: 0, chainHash: ZERO,
    headDigest: crypto.randomBytes(32), checkpointDigest: crypto.randomBytes(32) };
  let count = 8;
  let serverCalls = 0;
  const floor = {
    async freshHead(nonce, requestMinimum) {
      serverCalls += 1;
      assert.equal(requestMinimum.sequence, minimum.sequence);
      assert.deepEqual(requestMinimum.chainHash, minimum.chainHash);
      return signedAncestry(scope, minimum, nonce,
        floorKeys.privateKey, ownerKeys.privateKey, count);
    },
    async advance() { throw Error("UNEXPECTED_ADVANCE"); },
  };
  const server = createZk1V2CheckpointFloorHttpsServer({
    key: read("floor-server.key"), cert: read("floor-server.pem"), clientCa: ca,
    allowedClientFingerprint256: new crypto.X509Certificate(permitted.clientCert)
      .fingerprint256, floor,
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const endpoint = `https://127.0.0.1:${server.address().port}`;
  const clientOptions = { endpoint, ...permitted,
    serverFingerprint256: new crypto.X509Certificate(read("floor-server.pem"))
      .fingerprint256, pinnedFloorPublicKey: floorKeys.publicKey,
    pinnedOwnerPublicKey: ownerKeys.publicKey, scope, minimum };
  const sample = await signedAncestry(scope, minimum, crypto.randomBytes(32),
    floorKeys.privateKey, ownerKeys.privateKey, 8);
  assert.ok(sample.length > 4096, "eight legitimate ancestry entries exceed the old cap");
  assert.ok(Buffer.byteLength(JSON.stringify({ proof: sample.toString("base64url") })) < 8192,
    "the eight-entry proof fits the HTTPS response budget");
  await verifySignedHead(sample, { scope, pinnedFloorPublicKey: floorKeys.publicKey,
    pinnedOwnerPublicKey: ownerKeys.publicKey,
    nonce: (await z.decodeDeterministic(sample)).nonce, minimum });

  const client = new Zk1V2CheckpointFloorHttpsClient(clientOptions);
  const head = await client.freshHead();
  assert.equal(head.sequence, 136);
  assert.equal(serverCalls, 1);

  // The same signed proof cannot bypass the signed protocol's eight-entry cap.
  count = 9;
  const newClient = new Zk1V2CheckpointFloorHttpsClient(clientOptions);
  await assert.rejects(newClient.freshHead(), /ZK_V2_REMOTE_FLOOR_UNAVAILABLE/);
  assert.equal(serverCalls, 2);

  count = 16;
  const excessive = await signedAncestry(scope, minimum, crypto.randomBytes(32),
    floorKeys.privateKey, ownerKeys.privateKey, count);
  assert.ok(excessive.length > 6 * 1024,
    "oversized signed ancestry exceeds the independent decoded-proof budget");
  assert.ok(Buffer.byteLength(JSON.stringify({ proof: excessive.toString("base64url") })) > 8192,
    "oversized ancestry also exceeds the HTTPS response budget");
  const overBudgetClient = new Zk1V2CheckpointFloorHttpsClient(clientOptions);
  await assert.rejects(overBudgetClient.freshHead(), /ZK_V2_REMOTE_FLOOR_UNAVAILABLE/);
  assert.equal(serverCalls, 3);

  const unauthorised = new Zk1V2CheckpointFloorHttpsClient({
    ...clientOptions, clientKey: read("unlisted.key"), clientCert: read("unlisted.pem"),
  });
  await assert.rejects(unauthorised.freshHead(), /ZK_V2_REMOTE_FLOOR_UNAVAILABLE/);
  assert.equal(serverCalls, 3, "an unpinned mTLS client cannot request a proof");
});
