"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createRealLocalWebdav } = require("./support/issue-65-real-local-webdav");
const { createZk1WebdavCiphertextAdapter } =
  require("../src/services/zk1WebdavCiphertextAdapter");
const { Zk1CloudCiphertextCopyPublisher } =
  require("../src/services/zk1CloudCiphertextCopyPublisher");
const { Zk1CloudCiphertextReadbackVerifier, zk1CloudCopyAddress } =
  require("../src/services/zk1CloudCiphertextReadbackVerifier");
const { computeZk1CiphertextRoot } =
  require("../src/crypto/rootark-zk-chunk-root-v1");

test("real loopback mTLS WebDAV MKCOL, PUT ACK, independent GET and HEAD reject rollback", async (t) => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = "development";
  t.after(() => { if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous; });
  const peer = await createRealLocalWebdav(t);
  const writer = createZk1WebdavCiphertextAdapter(peer.config("writer"));
  const reader = createZk1WebdavCiphertextAdapter(peer.config("reader"));
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(8), keyring_id: crypto.randomBytes(16) };
  const operationId = crypto.randomBytes(16);
  const chunks = [crypto.randomBytes(151), crypto.randomBytes(177)];
  const ciphertext = Buffer.concat(chunks);
  const sha = crypto.createHash("sha256").update(ciphertext).digest();
  const root = computeZk1CiphertextRoot(chunks);
  const pub = { scope, operationId, ciphertextSha256: sha, expectedRootHash: root, chunks };
  const check = { scope, operationId, ciphertextSha256: sha,
    expectedRootHash: root, chunkLengths: chunks.map((c) => c.length) };
  const address = zk1CloudCopyAddress({ scope, operationId });
  const key = `/dav/${writer.key(address.folder, address.name, "uploads")}`;
  // The writer and reader represent separately enrolled transport identities.
  const writerContext = await writer.resolveInventoryContext();
  const readerContext = await reader.resolveInventoryContext();
  assert.notEqual(writerContext, readerContext);
  assert.equal(writer.zk1StorageNamespace(), reader.zk1StorageNamespace());
  const publish = (etag = null, adapter = writer) => new Zk1CloudCiphertextCopyPublisher({
    cloudWriter: adapter, expectedProvider: "webdav",
    expectedWriterContext: adapter === writer ? writerContext : readerContext,
    expectedWebdavEtag: etag });
  const verify = (etag = null, adapter = reader) => new Zk1CloudCiphertextReadbackVerifier({
    cloudReader: adapter, expectedProvider: "webdav",
    expectedReaderContext: adapter === reader ? readerContext : writerContext,
    pinnedWebdavEtag: etag });

  await assert.rejects(publish().publishExact(pub), /ZK_CLOUD_COPY_UNAVAILABLE/,
    "real WebDAV cannot write into absent MKCOL parent");
  await peer.provision(address.folder);
  const first = await publish().publishExact(pub);
  assert.equal(first.status, "CLOUD_COPY_PUT_ACK_NONAUTHORITATIVE");
  assert.equal(first.providerDurabilityProven, false);
  assert.equal(first.authorizesIo, false);
  assert.match(first.providerEtag, /^"rev-\d+"$/);
  const head = await peer.raw("HEAD", key, "reader");
  assert.equal(head.status, 200);
  assert.equal(head.headers.etag, first.providerEtag);
  assert.equal(Number(head.headers["content-length"]), ciphertext.length);
  assert.equal((await verify(first.providerEtag).verifyExact(check)).status,
    "EXTERNAL_CIPHERTEXT_REREAD_MATCHED");
  assert.equal((await verify(first.providerEtag).verifyExact(check)).externalProviderDurabilityProven, false);
  assert.deepEqual(peer.objects.get(key)?.ciphertext, ciphertext);
  const priorGet = peer.requests.filter((entry) => entry.method === "GET").length;
  await assert.rejects(publish(null, reader).publishExact(pub), /ZK_CLOUD_COPY_UNAVAILABLE/,
    "read-only mTLS role must not PUT");
  await assert.rejects(verify(null, writer).verifyExact(check), /ZK_CLOUD_READBACK_UNAVAILABLE/,
    "write-only mTLS role must not GET");
  const rogue = createZk1WebdavCiphertextAdapter(peer.config("foreign"));
  const rogueContext = await rogue.resolveInventoryContext();
  await assert.rejects(new Zk1CloudCiphertextReadbackVerifier({ cloudReader: rogue,
    expectedProvider: "webdav", expectedReaderContext: rogueContext }).verifyExact(check),
  /ZK_CLOUD_READBACK_UNAVAILABLE/, "unprovisioned TLS identity must not GET");
  assert.ok(peer.requests.filter((entry) => entry.method === "GET").length > priorGet);

  const second = await publish(first.providerEtag).publishExact(pub);
  assert.notEqual(second.providerEtag, first.providerEtag);
  await assert.rejects(publish(first.providerEtag).publishExact(pub), /ZK_CLOUD_COPY_UNAVAILABLE/);
  await assert.rejects(verify(first.providerEtag).verifyExact(check), /ZK_CLOUD_READBACK_UNAVAILABLE/,
    "old ETag must not authenticate rewritten ciphertext, even when bytes match");
  peer.setMode("corrupt-on-get");
  await assert.rejects(verify(second.providerEtag).verifyExact(check), /ZK_CLOUD_READBACK_UNAVAILABLE/);
  peer.setMode("normal");
  assert.equal((await verify(second.providerEtag).verifyExact(check)).readbackMatched, true);
  peer.setMode("corrupt-on-put");
  const maliciousAck = await publish(second.providerEtag).publishExact(pub);
  assert.equal(maliciousAck.providerDurabilityProven, false);
  await assert.rejects(verify(maliciousAck.providerEtag).verifyExact(check),
    /ZK_CLOUD_READBACK_UNAVAILABLE/, "malicious peer returning a successful PUT ACK must be caught by GET");
  peer.setMode("redirect");
  const count = peer.requests.length;
  await assert.rejects(verify(maliciousAck.providerEtag).verifyExact(check),
    /ZK_CLOUD_READBACK_UNAVAILABLE/);
  assert.equal(peer.requests.length, count + 1,
    "HTTP redirect to metadata service must never be followed");
  const wrongPin = createZk1WebdavCiphertextAdapter({ ...peer.config("reader"),
    serverFingerprint256: "00".repeat(32) });
  await assert.rejects(new Zk1CloudCiphertextReadbackVerifier({ cloudReader: wrongPin,
    expectedProvider: "webdav",
    expectedReaderContext: await wrongPin.resolveInventoryContext() }).verifyExact(check),
  /ZK_CLOUD_READBACK_UNAVAILABLE/);
});

test("WebDAV development connector refuses non-loopback targets and production opt-in", async (t) => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = "development";
  t.after(() => { if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous; });
  const peer = await createRealLocalWebdav(t);
  const valid = peer.config("writer");
  for (const destination of ["https://169.254.169.254/dav", "https://10.0.0.1/dav",
    "https://127.0.0.2/dav", "https://metadata.google.internal/dav",
    "https://localhost.evil.invalid/dav"]) {
    assert.throws(() => createZk1WebdavCiphertextAdapter({ ...valid, endpoint: destination }),
      /ZK_WEBDAV_CIPHERTEXT_UNAVAILABLE/, "development destination must be loopback literal");
  }
  process.env.NODE_ENV = "production";
  assert.throws(() => createZk1WebdavCiphertextAdapter(valid),
    /ZK_WEBDAV_CIPHERTEXT_UNAVAILABLE/);
});
