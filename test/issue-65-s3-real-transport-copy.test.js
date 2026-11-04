"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const crypto = require("node:crypto");
const { S3Client } = require("@aws-sdk/client-s3");
const { createCloudStorage } = require("../services/cloudStorage");
const { computeZk1CiphertextRoot } =
  require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1CloudCiphertextCopyPublisher } =
  require("../src/services/zk1CloudCiphertextCopyPublisher");
const { Zk1CloudCiphertextReadbackVerifier } =
  require("../src/services/zk1CloudCiphertextReadbackVerifier");

test("real AWS S3 client PUT/GET against isolated HTTP emulator verifies bytes after missing ACK and replay", async (t) => {
  const objects = new Map();
  const versions = new Map();
  const requests = [];
  const sockets = new Set();
  let corruptGet = false;
  let forgedVersionReply = false;
  let suspendVersionResponse = false;
  let failPutOnce = true;
  let version = 0;
  const server = http.createServer((request, response) => {
    const key = request.url.split("?")[0];
    requests.push({ method: request.method, key, url: request.url });
    if (request.method === "PUT") {
      const parts = [];
      request.on("data", (chunk) => parts.push(chunk));
      request.on("end", () => {
        const bytes = Buffer.concat(parts);
        objects.set(key, bytes);
        version += 1;
        versions.set(`s3-version-${version}`, bytes);
        if (failPutOnce) {
          failPutOnce = false;
          response.writeHead(400, { "content-type": "application/xml" });
          response.end("<Error><Code>AccessDenied</Code></Error>");
        } else { response.writeHead(200, { "x-amz-version-id": suspendVersionResponse
          ? "null" : `s3-version-${version}` }); response.end(); }
      });
    } else if (request.method === "GET") {
      const requestedVersion = new URL(request.url, "http://localhost").searchParams.get("versionId");
      const current = requestedVersion ? versions.get(requestedVersion) : objects.get(key);
      if (!current) { response.writeHead(404); response.end(); return; }
      const bytes = corruptGet ? Buffer.alloc(current.length, 0x19) : current;
      response.writeHead(200, { "content-length": bytes.length,
        "content-type": "application/octet-stream",
        "x-amz-version-id": forgedVersionReply ? "s3-version-1"
          : requestedVersion || `s3-version-${version}` });
      response.end(bytes);
    } else { response.writeHead(405); response.end(); }
  });
  server.on("connection", (socket) => { sockets.add(socket);
    socket.on("close", () => sockets.delete(socket)); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve)); });
  const endpoint = `http://127.0.0.1:${server.address().port}`;
  const create = (principal) => createCloudStorage({
    provider: "s3", prefix: "zk1-loopback-s3", rootFolderId: "root",
    s3: { bucket: "disposable-bucket", region: "us-east-1", endpoint,
      forcePathStyle: true, principalId: principal },
    resolvePrincipalIdentity: async () => principal,
    createS3Client: async () => new S3Client({
      endpoint, forcePathStyle: true, region: "us-east-1",
      credentials: { accessKeyId: "DISPOSABLE-KEY", secretAccessKey: "disposable-secret" },
      requestChecksumCalculation: "WHEN_REQUIRED",
      responseChecksumValidation: "WHEN_REQUIRED",
      maxAttempts: 1,
    }),
  });
  const writer = create("operator-writer");
  const reader = create("independent-reader");
  const publisher = new Zk1CloudCiphertextCopyPublisher({ cloudWriter: writer,
    expectedProvider: "s3", expectedWriterContext: await writer.resolveInventoryContext() });
  const verifier = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: reader,
    expectedProvider: "s3", expectedReaderContext: await reader.resolveInventoryContext() });
  const chunks = [crypto.randomBytes(79), crypto.randomBytes(41)];
  const expected = Buffer.concat(chunks);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(5), keyring_id: crypto.randomBytes(16) };
  const operationId = crypto.randomBytes(16);
  const sha = crypto.createHash("sha256").update(expected).digest();
  const root = computeZk1CiphertextRoot(chunks);
  const put = { scope, operationId, ciphertextSha256: sha,
    expectedRootHash: root, chunks };
  const read = { scope, operationId, ciphertextSha256: sha,
    expectedRootHash: root, chunkLengths: chunks.map((chunk) => chunk.length) };
  await assert.rejects(publisher.publishExact(put), /ZK_CLOUD_COPY_UNAVAILABLE/,
    "HTTP non-2xx after storing bytes must not pass as a successful PUT receipt");
  assert.equal(requests.filter((entry) => entry.method === "PUT").length, 1);
  const surviving = await verifier.verifyExact(read);
  assert.equal(surviving.readbackMatched, true,
    "independent GET proves bytes can survive a lost PUT response");
  assert.equal(surviving.providerFileId, null);
  assert.equal(surviving.readbackSha256.toString("hex"), sha.toString("hex"));
  assert.match(surviving.providerObjectKey, /\/uploads\/zk1-[a-f0-9]{64}\/[A-Za-z0-9_-]{22}\.ct$/);
  corruptGet = true;
  await assert.rejects(verifier.verifyExact(read), /ZK_CLOUD_READBACK_UNAVAILABLE/,
    "provider byte corruption must be detected independently of the PUT ACK");
  corruptGet = false;
  const ack = await publisher.publishExact(put);
  assert.equal(ack.providerObjectKey, surviving.providerObjectKey);
  assert.equal(ack.providerDurabilityProven, false);
  assert.equal(ack.providerVersionId, "s3-version-2");
  const replay = await verifier.verifyExact(read);
  assert.equal(replay.readbackMatched, true);
  const versionPinned = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: reader,
    expectedProvider: "s3", expectedReaderContext: await reader.resolveInventoryContext(),
    pinnedS3VersionId: ack.providerVersionId });
  const pinned = await versionPinned.verifyExact(read);
  assert.equal(pinned.providerVersionId, "s3-version-2");
  assert.equal(pinned.externalProviderDurabilityProven, false);
  assert.ok(requests.some((item) => item.method === "GET"
    && item.url.includes("versionId=s3-version-2")), "the real SDK GET must pin S3 VersionId");
  forgedVersionReply = true;
  await assert.rejects(versionPinned.verifyExact(read), /ZK_CLOUD_READBACK_UNAVAILABLE/,
    "even matching ciphertext bytes cannot authorize a different S3 object version");
  forgedVersionReply = false;
  const foreignReader = create("different-reader-credential");
  const foreignPin = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: foreignReader,
    expectedProvider: "s3", expectedReaderContext: await reader.resolveInventoryContext(),
    pinnedS3VersionId: ack.providerVersionId });
  const beforeForeign = requests.length;
  await assert.rejects(foreignPin.verifyExact(read), /ZK_CLOUD_READBACK_UNAVAILABLE/);
  assert.equal(requests.length, beforeForeign,
    "the wrong provider principal must not reach the remote GET");
  const pinnedContext = await reader.resolveInventoryContext();
  assert.throws(() => new Zk1CloudCiphertextReadbackVerifier({ cloudReader: reader,
    expectedProvider: "s3", expectedReaderContext: pinnedContext,
    pinnedS3VersionId: "null" }), /ZK_CLOUD_READBACK_UNAVAILABLE/);
  suspendVersionResponse = true;
  const unversioned = await publisher.publishExact(put);
  assert.equal(unversioned.providerVersionId, null,
    "a suspended S3 bucket can hold ciphertext but never advertises a pinnable null version");
  assert.equal(objects.size, 1, "same signed operation targets exactly the same S3 object key");
});
