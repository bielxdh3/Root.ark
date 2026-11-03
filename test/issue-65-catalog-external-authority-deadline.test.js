"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");
const { performance } = require("node:perf_hooks");
const { createCatalogAuthorityHttpsClient } =
  require("../src/services/zk1CatalogExternalAuthorityHttps");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const DENIED = /CATALOG_EXTERNAL_DENIED/;

test("catalog external authority mTLS client has an absolute deadline for both routes", async (t) => {
  const directory = createPrivateAuthorityFixture("zk1-catalog-deadline-");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  generateNativeFixtureCertificates(directory, {
    caSubject: "ZK1 Catalog Deadline Test CA", servers: ["authority"], clients: ["operator"],
  });
  const read = (name) => fs.readFileSync(path.join(directory, name));
  const serverCert = read("authority.pem");
  const ca = read("ca.pem");
  const proof = Buffer.from("disposable-signed-proof");
  const response = Buffer.from(JSON.stringify({ signedProof: proof.toString("base64url") }));
  let behavior = "normal";
  const activeIntervals = new Set();
  const trickleClosed = [];
  const observed = [];
  const server = https.createServer({
    key: read("authority.key"), cert: serverCert, ca,
    requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
  }, (req, res) => {
    observed.push({ route: req.url, tls: req.socket.getProtocol(),
      authorized: req.socket.authorized });
    req.resume();
    if (behavior === "normal") {
      res.writeHead(200, { "content-type": "application/json",
        "content-length": response.length });
      res.end(response);
      return;
    }
    if (behavior === "partial") {
      res.writeHead(200, { "content-type": "application/json",
        "content-length": response.length + 100 });
      res.write(response.subarray(0, 5));
      setImmediate(() => res.destroy());
      return;
    }
    if (behavior === "oversize") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(Buffer.alloc(8193, 0x20));
      return;
    }
    // The authenticated peer sends one byte every 500ms, indefinitely.
    // This defeats socket inactivity timeouts while staying below 8192 bytes.
    res.writeHead(200, { "content-type": "application/json" });
    res.write(" ");
    const interval = setInterval(() => {
      if (!res.destroyed) res.write(" ");
    }, 500);
    activeIntervals.add(interval);
    trickleClosed.push(new Promise((resolve) => res.once("close", resolve)));
    res.once("close", () => {
      clearInterval(interval);
      activeIntervals.delete(interval);
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    for (const interval of activeIntervals) clearInterval(interval);
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });

  const serverSpkiSha256 = crypto.createHash("sha256")
    .update(new crypto.X509Certificate(serverCert).publicKey
      .export({ format: "der", type: "spki" })).digest();
  const client = createCatalogAuthorityHttpsClient({
    endpoint: `https://127.0.0.1:${server.address().port}`,
    ca, key: read("operator.key"), cert: read("operator.pem"), serverSpkiSha256,
  });
  const request = {
    scope: { account_id: Buffer.alloc(16, 1), compartment_id: Buffer.from("fixture"),
      keyring_id: Buffer.alloc(16, 2) },
    ownerRevision: 1, ownerDigest: Buffer.alloc(32, 3), operationId: Buffer.alloc(16, 4),
    signerDeviceId: Buffer.alloc(16, 5), epoch: 1, sequence: 1,
    catalogDigest: Buffer.alloc(32, 6), floorCasSignerFingerprint: Buffer.alloc(32, 7),
    expiresAt: Math.floor(Date.now() / 1000) + 30,
  };
  const operations = [
    ["/v1/policy", () => client.policyGrant(request)],
    ["/v1/terminal", () => client.floorTerminal(Buffer.from("disposable-ticket"))],
  ];
  for (const [route, invoke] of operations) {
    await t.test(`${route} completes a normal TLS1.3/mTLS response`, async () => {
      behavior = "normal";
      assert.deepEqual(await invoke(), proof);
      const received = observed.at(-1);
      assert.deepEqual(received, { route, tls: "TLSv1.3", authorized: true });
    });
    await t.test(`${route} rejects an authenticated 500ms byte trickle within 5.5s`, async () => {
      behavior = "trickle";
      const start = performance.now();
      let watchdog;
      try {
        await assert.rejects(Promise.race([
          invoke(),
          new Promise((_, reject) => {
            watchdog = setTimeout(() => reject(Error("TEST_HUNG_BEYOND_5500MS")), 5500);
          }),
        ]), DENIED);
        assert.ok(performance.now() - start < 5500, "wall-clock deadline exceeded");
        const received = observed.at(-1);
        assert.deepEqual(received, { route, tls: "TLSv1.3", authorized: true });
        let closeWatchdog;
        try {
          await Promise.race([
            trickleClosed.at(-1),
            new Promise((_, reject) => {
              closeWatchdog = setTimeout(() => reject(Error("SOCKET_NOT_DESTROYED")), 1000);
            }),
          ]);
          assert.equal(activeIntervals.size, 0, "timed-out connection remains open");
        } finally { clearTimeout(closeWatchdog); }
      } finally { clearTimeout(watchdog); }
    });
    await t.test(`${route} rejects a prematurely closed response`, async () => {
      behavior = "partial";
      await assert.rejects(invoke(), DENIED);
    });
    await t.test(`${route} rejects a response over 8192 bytes`, async () => {
      behavior = "oversize";
      await assert.rejects(invoke(), DENIED);
    });
  }
  await t.test("a trusted CA cannot bypass the pinned server SPKI", async () => {
    behavior = "normal";
    const wrongPinClient = createCatalogAuthorityHttpsClient({
      endpoint: `https://127.0.0.1:${server.address().port}`,
      ca, key: read("operator.key"), cert: read("operator.pem"),
      serverSpkiSha256: Buffer.alloc(32, 0xee),
    });
    await assert.rejects(wrongPinClient.floorTerminal(Buffer.from("ticket")), DENIED);
  });
});
