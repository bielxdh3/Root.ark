"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { computeZk1CiphertextRoot } =
  require("../src/crypto/rootark-zk-chunk-root-v1");
const { createZk1WebdavCiphertextAdapter } =
  require("../src/services/zk1WebdavCiphertextAdapter");
const { Zk1CloudCiphertextCopyPublisher } =
  require("../src/services/zk1CloudCiphertextCopyPublisher");
const { Zk1CloudCiphertextReadbackVerifier } =
  require("../src/services/zk1CloudCiphertextReadbackVerifier");

test("mTLS WebDAV strong ETag pins GET and If-Match prevents stale ciphertext replacement", async (t) => {
  const originalEnvironment = process.env.NODE_ENV;
  process.env.NODE_ENV = "development";
  t.after(() => {
    if (originalEnvironment === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalEnvironment;
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-webdav-etag-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 4 }));
  generateNativeFixtureCertificates(dir, { caSubject: "Webdav ETag CA",
    servers: ["server"], clients: ["client"] });
  const read = (name) => fs.readFileSync(path.join(dir, name), "utf8");
  const ca = read("ca.pem");
  const certificate = read("server.pem");
  const stored = new Map();
  const calls = [];
  let seq = 0;
  let ignorePrecondition = false;
  let etagMode = "normal";
  let putEtagMode = "normal";
  const sockets = new Set();
  const server = https.createServer({ key: read("server.key"), cert: certificate,
    ca, requestCert: true, rejectUnauthorized: true }, (request, response) => {
    calls.push({ method: request.method, ifMatch: request.headers["if-match"],
      tlsAuthorized: request.client.authorized });
    const current = stored.get(request.url);
    if (request.method === "PUT") {
      if (request.headers["if-match"] && request.headers["if-match"] !== current?.etag) {
        request.resume(); response.writeHead(412); response.end(); return;
      }
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => {
        seq += 1;
        const etag = `"opaque-${seq}"`;
        stored.set(request.url, { data: Buffer.concat(chunks), etag });
        response.writeHead(201, putEtagMode === "missing" ? {}
          : { etag: putEtagMode === "weak" ? `W/${etag}` : etag });
        response.end();
      });
      return;
    }
    if (request.method === "GET" && current) {
      if (request.headers["if-match"] !== undefined && !ignorePrecondition
        && request.headers["if-match"] !== current.etag) {
        response.writeHead(412); response.end(); return;
      }
      const headers = { "content-type": "application/octet-stream" };
      if (etagMode === "normal") headers.etag = current.etag;
      if (etagMode === "weak") headers.etag = `W/${current.etag}`;
      if (etagMode === "forged") headers.etag = '"opaque-wrong"';
      response.writeHead(200, headers); response.end(current.data); return;
    }
    request.resume(); response.writeHead(404); response.end();
  });
  server.on("connection", (socket) => {
    sockets.add(socket); socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const config = { developmentOnlyOptIn: true,
    endpoint: `https://127.0.0.1:${server.address().port}/dav`,
    namespace: "etag_test_namespace", ca,
    serverFingerprint256: new crypto.X509Certificate(certificate).fingerprint256,
    clientCert: read("client.pem"), clientKey: read("client.key") };
  const writer = createZk1WebdavCiphertextAdapter(config);
  const reader = createZk1WebdavCiphertextAdapter({ ...config });
  const writeContext = await writer.resolveInventoryContext();
  const readContext = await reader.resolveInventoryContext();
  const chunks = [crypto.randomBytes(35), crypto.randomBytes(87)];
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(6), keyring_id: crypto.randomBytes(16) };
  const operationId = crypto.randomBytes(16);
  const data = Buffer.concat(chunks);
  const sha = crypto.createHash("sha256").update(data).digest();
  const root = computeZk1CiphertextRoot(chunks);
  const payload = { scope, operationId, ciphertextSha256: sha,
    expectedRootHash: root, chunks };
  const check = { scope, operationId, ciphertextSha256: sha,
    expectedRootHash: root, chunkLengths: chunks.map((part) => part.length) };
  const publisher = (etag = null) => new Zk1CloudCiphertextCopyPublisher({
    cloudWriter: writer, expectedProvider: "webdav", expectedWriterContext: writeContext,
    expectedWebdavEtag: etag,
  });
  const verifier = (etag) => new Zk1CloudCiphertextReadbackVerifier({
    cloudReader: reader, expectedProvider: "webdav",
    expectedReaderContext: readContext, pinnedWebdavEtag: etag,
  });
  const first = await publisher().publishExact(payload);
  assert.equal(first.providerEtag, '"opaque-1"');
  assert.equal(first.providerDurabilityProven, false);
  assert.equal((await verifier(first.providerEtag).verifyExact(check)).providerEtag,
    first.providerEtag);
  assert.equal(calls.at(-1).ifMatch, first.providerEtag);
  assert.ok(calls.every((call) => call.tlsAuthorized));

  // Same signed bytes at the same key do not imply the same remote version.
  const second = await publisher().publishExact(payload);
  assert.equal(second.providerEtag, '"opaque-2"');
  const beforeStale = seq;
  await assert.rejects(publisher(first.providerEtag).publishExact(payload),
    /ZK_CLOUD_COPY_UNAVAILABLE/, "stale If-Match must refuse PUT");
  assert.equal(seq, beforeStale, "conditional failure must preserve remote object");
  assert.equal(calls.at(-1).ifMatch, first.providerEtag);

  await assert.rejects(verifier(first.providerEtag).verifyExact(check),
    /ZK_CLOUD_READBACK_UNAVAILABLE/, "stale GET is precondition-failed");
  ignorePrecondition = true;
  await assert.rejects(verifier(first.providerEtag).verifyExact(check),
    /ZK_CLOUD_READBACK_UNAVAILABLE/,
    "even a peer ignoring If-Match cannot pass mismatching ETag with identical bytes");
  ignorePrecondition = false;
  assert.equal((await verifier(second.providerEtag).verifyExact(check)).readbackMatched, true);
  for (const mode of ["weak", "missing", "forged"]) {
    etagMode = mode;
    await assert.rejects(verifier(second.providerEtag).verifyExact(check),
      /ZK_CLOUD_READBACK_UNAVAILABLE/, "weak, absent and forged ETag must fail closed");
  }
  etagMode = "normal";
  const third = await publisher(second.providerEtag).publishExact(payload);
  assert.equal(third.providerEtag, '"opaque-3"');
  assert.equal((await verifier(third.providerEtag).verifyExact(check)).readbackMatched, true);
  putEtagMode = "missing";
  await assert.rejects(publisher(third.providerEtag).publishExact(payload),
    /ZK_CLOUD_COPY_UNAVAILABLE/,
    "a successful conditional PUT without a new ETag cannot issue a positive receipt");
  putEtagMode = "weak";
  await assert.rejects(publisher('"opaque-4"').publishExact(payload),
    /ZK_CLOUD_COPY_UNAVAILABLE/,
    "a weak ETag cannot be reused as the next object identity");

  const count = calls.length;
  for (const unsafe of ['W/"opaque-3"', '"opaque-3", "foreign"', '"unsafe\r\nvalue"', "*"]) {
    assert.throws(() => publisher(unsafe), /ZK_CLOUD_COPY_UNAVAILABLE/);
    assert.throws(() => verifier(unsafe), /ZK_CLOUD_READBACK_UNAVAILABLE/);
  }
  assert.equal(calls.length, count, "bad ETags must not reach the network");
});
