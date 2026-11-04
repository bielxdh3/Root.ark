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
const { createZk1WitnessHttpsClient } =
  require("../src/services/zk1WitnessHttpsClient");

const UNAVAILABLE = (error) => error?.message === "WITNESS_TRANSPORT_UNAVAILABLE";
const scope = {
  account_id: Buffer.alloc(16, 1),
  compartment_id: Buffer.from("fixture"),
  keyring_id: Buffer.alloc(16, 2),
};
const operation = {
  ...scope, reservation_id: Buffer.alloc(16, 3), operation_id: Buffer.alloc(16, 4),
  expected_revision: 1, expected_manifest_digest: Buffer.alloc(32, 5),
  proposed_revision: 2, proposed_manifest_digest: Buffer.alloc(32, 6),
  request_digest: Buffer.alloc(32, 7), package_envelope_digest: null,
  expires_at: 1760000300,
};
const receipt = Buffer.from("disposable-signed-receipt");
const paths = [
  ["/v1/head", (client) => client.freshHead({ scope, nonce: Buffer.alloc(32, 8) }), receipt],
  ["/v1/quiesce", (client) => client.prepareQuiesce({ operation }),
    { status: "DRAINED", activeCount: 0 }],
  ["/v1/reserve", (client) => client.reserve({ operation }), receipt],
];

function within(promise, ms, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(Error(label)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

test("witness mTLS TLS1.3 requests enforce a total 100ms deadline even for authenticated byte trickle", async (t) => {
  const directory = createPrivateAuthorityFixture("zk65-witness-deadline-");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  generateNativeFixtureCertificates(directory, {
    caSubject: "ZK1 Witness Deadline Test CA", servers: ["witness"], clients: ["operator"],
  });
  const read = (name) => fs.readFileSync(path.join(directory, name));
  const ca = read("ca.pem");
  const fingerprint = new crypto.X509Certificate(read("witness.pem")).fingerprint256;
  let responseMode = "normal";
  const requests = [];
  const intervals = new Set();
  const server = https.createServer({
    key: read("witness.key"), cert: read("witness.pem"), ca,
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, (req, res) => {
    req.resume();
    const record = {
      path: req.url, tls: req.socket.getProtocol(), authorized: req.socket.authorized,
      writes: 0, closes: 0,
    };
    record.closed = new Promise((resolve) => {
      res.once("close", () => { record.closes++; resolve(); });
    });
    requests.push(record);
    res.writeHead(200, { "content-type": "application/json" });
    if (responseMode === "normal") {
      const response = req.url === "/v1/quiesce"
        ? { status: "DRAINED", activeCount: 0, authority: "WITNESS_IO_GATE_LOCAL_V1" }
        : { receiptBase64: receipt.toString("base64url"), authority: "WITNESS_ENGINE_ONLY" };
      res.end(JSON.stringify(response));
      return;
    }
    // The response begins with a JSON object but never completes it. Each
    // 50ms byte resets the socket inactivity timer indefinitely.
    res.write("{");
    record.writes++;
    const interval = setInterval(() => {
      if (!res.destroyed) { res.write(" "); record.writes++; }
    }, 50);
    if (responseMode === "late") {
      // This would finish as a valid authority response after the deadline.
      // It must not become a successful witness proof.
      const late = setTimeout(() => {
        if (!res.destroyed) res.end(`"receiptBase64":"${receipt.toString("base64url")}","authority":"WITNESS_ENGINE_ONLY"}`);
      }, 220);
      res.once("close", () => clearTimeout(late));
    }
    intervals.add(interval);
    res.once("close", () => {
      clearInterval(interval);
      intervals.delete(interval);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    for (const interval of intervals) clearInterval(interval);
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const options = {
    endpoint: `https://127.0.0.1:${server.address().port}`,
    ca, clientKey: read("operator.key"), clientCert: read("operator.pem"),
    serverFingerprint256: fingerprint,
  };
  const normal = createZk1WitnessHttpsClient({ ...options, timeoutMs: 1000 });
  const bounded = createZk1WitnessHttpsClient({ ...options, timeoutMs: 100 });

  for (const [route, invoke, result] of paths) {
    await t.test(`${route}: normal pinned mTLS response succeeds`, async () => {
      responseMode = "normal";
      assert.deepEqual(await invoke(normal), result);
      assert.deepEqual(
        [requests.at(-1).path, requests.at(-1).tls, requests.at(-1).authorized],
        [route, "TLSv1.3", true],
      );
    });
    await t.test(`${route}: 1 byte/50ms cannot extend 100ms deadline`, async () => {
      responseMode = "trickle";
      const before = requests.length;
      const start = performance.now();
      await assert.rejects(
        within(invoke(bounded), 650, "WITNESS_TEST_PENDING_BEYOND_650MS"),
        UNAVAILABLE,
      );
      assert.ok(performance.now() - start < 400, "witness exceeded absolute deadline");
      assert.equal(requests.length, before + 1, "authenticated TLS request did not reach peer");
      const observed = requests.at(-1);
      assert.deepEqual([observed.path, observed.tls, observed.authorized],
        [route, "TLSv1.3", true]);
      assert.ok(observed.writes >= 2, "peer did not exercise the streaming response");
      await within(observed.closed, 500, "WITNESS_TIMEOUT_SOCKET_NOT_DESTROYED");
      assert.equal(observed.closes, 1);
      assert.equal(intervals.size, 0, "dripping response survived client timeout");
    });
  }
  await t.test("a valid but late witness receipt never succeeds after deadline", async () => {
    responseMode = "late";
    const before = requests.length;
    let settlements = 0;
    const result = bounded.freshHead({ scope, nonce: Buffer.alloc(32, 8) })
      .then((value) => { settlements++; return value; },
        (error) => { settlements++; return error; });
    const failure = await within(result, 650, "WITNESS_LATE_PROOF_PENDING");
    assert.ok(UNAVAILABLE(failure), "accepted a late witness authority proof");
    assert.equal(requests.length, before + 1);
    const observed = requests.at(-1);
    await within(observed.closed, 500, "WITNESS_LATE_PROOF_SOCKET_OPEN");
    assert.equal(observed.closes, 1);
    assert.equal(settlements, 1);
    assert.equal(intervals.size, 0);
  });
  await t.test("wrong server pin is rejected before reading a valid JSON response", async () => {
    responseMode = "normal";
    const unpinned = createZk1WitnessHttpsClient({
      ...options, serverFingerprint256: Buffer.alloc(32, 0xee).toString("hex")
        .match(/../g).join(":").toUpperCase(), timeoutMs: 1000,
    });
    await assert.rejects(unpinned.freshHead({ scope, nonce: Buffer.alloc(32, 8) }),
      UNAVAILABLE);
  });
});
