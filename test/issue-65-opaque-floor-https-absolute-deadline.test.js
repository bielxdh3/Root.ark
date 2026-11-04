"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");
const { performance } = require("node:perf_hooks");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const z = require("../src/crypto/rootark-zk-1");
const { createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");

const DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-independent-floor/v1\0");
const UNAVAILABLE = (error) => error?.code === "ZK_OPAQUE_FLOOR_UNAVAILABLE";

function within(promise, ms, label) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label)), ms);
  })]).finally(() => clearTimeout(timer));
}

test("opaque floor mTLS TLS1.3 enforces absolute deadlines on head and CAS", async (t) => {
  const dir = createPrivateAuthorityFixture("zk65-opaque-floor-deadline-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  generateNativeFixtureCertificates(dir, {
    caSubject: "Opaque Floor Deadline Fixture CA",
    servers: ["floor"], clients: ["operator"],
  });
  const read = (name) => fs.readFileSync(path.join(dir, name));
  const ca = read("ca.pem");
  const floor = crypto.generateKeyPairSync("ed25519");
  const cas = crypto.generateKeyPairSync("ed25519");
  const scope = {
    account_id: crypto.randomBytes(16), compartment_id: Buffer.from("deadline"),
    keyring_id: crypto.randomBytes(16),
  };
  const casFingerprint = crypto.createHash("sha256")
    .update(cas.publicKey.export({ format: "der", type: "spki" })).digest();
  const signedProof = async (nonce) => {
    const head = {
      type: "rootark-zk1-opaque-catalog-independent-floor/v1", ...scope,
      cas_signer_spki_sha256: casFingerprint, sequence: 0,
      digest: Buffer.alloc(32), nonce, observed_at: Math.floor(Date.now() / 1000),
    };
    const message = Buffer.from(await z.encodeDeterministic(head));
    const signature = crypto.sign(null, Buffer.concat([DOMAIN, message]), floor.privateKey);
    return Buffer.from(await z.encodeDeterministic({ ...head, signature })).toString("base64url");
  };

  let mode = "normal";
  const requests = [];
  const intervals = new Set();
  const server = https.createServer({
    key: read("floor.key"), cert: read("floor.pem"), ca,
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, async (req, res) => {
    const chunks = [];
    for await (const part of req) chunks.push(part);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    const record = {
      path: req.url, protocol: req.socket.getProtocol(), authorized: req.socket.authorized,
      writes: 0, closes: 0,
    };
    record.closed = new Promise((resolve) => {
      res.once("close", () => { record.closes++; resolve(); });
    });
    requests.push(record);
    res.writeHead(mode === "rejected" ? 503 : 200,
      { "content-type": "application/json" });
    const proof = await signedProof(Buffer.from(body.nonce, "base64url"));
    if (mode === "normal") {
      res.end(JSON.stringify({ proofBase64: proof }));
      return;
    }
    if (mode === "rejected") {
      res.write('{"error":');
      return;
    }
    if (mode === "truncated") {
      res.write('{"proofBase64":"');
      setImmediate(() => req.socket.destroy());
      return;
    }
    if (mode === "oversize") {
      res.write('{"proofBase64":"' + "A".repeat(8193));
      return;
    }
    // Header and first JSON byte arrive; activity every 50ms defeats idle timers.
    res.write("{");
    record.writes++;
    const interval = setInterval(() => {
      if (!res.destroyed) { res.write(" "); record.writes++; }
    }, 50);
    intervals.add(interval);
    res.once("close", () => {
      clearInterval(interval);
      intervals.delete(interval);
    });
    if (mode === "late") {
      const late = setTimeout(() => {
        if (!res.destroyed) res.end('"proofBase64":"' + proof + '"}');
      }, 220);
      res.once("close", () => clearTimeout(late));
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    for (const interval of intervals) clearInterval(interval);
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });

  const options = {
    endpoint: `https://127.0.0.1:${server.address().port}/`,
    ca, clientKey: read("operator.key"), clientCert: read("operator.pem"),
    serverFingerprint256: new crypto.X509Certificate(read("floor.pem")).fingerprint256,
    floorPublicKey: floor.publicKey, casSignerPublicKey: cas.publicKey,
    trustedScope: scope,
  };
  const normal = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    ...options, timeoutMs: 1000,
  });
  const bounded = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    ...options, timeoutMs: 100,
  });
  const operations = [
    ["/v1/floor/head", (client) => client.readHead({ scope })],
    ["/v1/floor/cas", (client) => client.compareAndSwap({
      scope, expectedSequence: 0, expectedDigest: Buffer.alloc(32),
      nextSequence: 1, nextDigest: Buffer.alloc(32, 3),
      headBytes: Buffer.from("fixture"), headSignature: Buffer.alloc(64),
    })],
  ];
  for (const [route, invoke] of operations) {
    await t.test(`${route}: valid pinned mTLS response succeeds`, async () => {
      mode = "normal";
      const result = await invoke(normal);
      assert.equal(result.sequence, 0);
      assert.deepEqual(result.digest, Buffer.alloc(32));
      assert.deepEqual(
        [requests.at(-1).path, requests.at(-1).protocol, requests.at(-1).authorized],
        [route, "TLSv1.3", true],
      );
    });
    await t.test(`${route}: 1 byte/50ms cannot extend the 100ms budget`, async () => {
      mode = "drip";
      const before = requests.length;
      const started = performance.now();
      await assert.rejects(within(invoke(bounded), 650, "FLOOR_DRIP_PENDING"), UNAVAILABLE);
      assert.ok(performance.now() - started < 450, "response outlived absolute deadline");
      assert.equal(requests.length, before + 1);
      const observed = requests.at(-1);
      assert.deepEqual([observed.path, observed.protocol, observed.authorized],
        [route, "TLSv1.3", true]);
      // On heavily loaded CI hosts the handshake can consume part of the
      // 100ms budget. The peer still sends a byte every 50ms until closed.
      assert.ok(observed.writes >= 1, "peer did not start its streaming response");
      await within(observed.closed, 500, "FLOOR_SOCKET_STILL_OPEN");
      assert.equal(observed.closes, 1);
      assert.equal(intervals.size, 0, "server stream survived the timeout");
    });
  }
  await t.test("a late otherwise-valid proof cannot be accepted", async () => {
    mode = "late";
    let settlements = 0;
    const result = bounded.readHead({ scope }).then(
      (value) => { settlements++; return value; },
      (error) => { settlements++; return error; },
    );
    const outcome = await within(result, 650, "FLOOR_LATE_PENDING");
    assert.ok(UNAVAILABLE(outcome));
    await within(requests.at(-1).closed, 500, "FLOOR_LATE_SOCKET_STILL_OPEN");
    assert.equal(settlements, 1);
    assert.equal(intervals.size, 0);
  });
  for (const failure of ["truncated", "oversize", "rejected"]) {
    await t.test(`${failure} HTTP body rejects and closes the socket`, async () => {
      mode = failure;
      await assert.rejects(within(bounded.readHead({ scope }), 650,
        "FLOOR_BODY_PENDING"), UNAVAILABLE);
      await within(requests.at(-1).closed, 500, "FLOOR_BODY_SOCKET_STILL_OPEN");
    });
  }
});
