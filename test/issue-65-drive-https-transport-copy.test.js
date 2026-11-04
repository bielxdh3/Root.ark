"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { Readable } = require("node:stream");
const { createCloudStorage } = require("../services/cloudStorage");
const { generateNativeFixtureCertificates } =
  require("./support/issue-65-native-openssl-fixture");
const { computeZk1CiphertextRoot } =
  require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1CloudCiphertextCopyPublisher } =
  require("../src/services/zk1CloudCiphertextCopyPublisher");
const { Zk1CloudCiphertextReadbackVerifier } =
  require("../src/services/zk1CloudCiphertextReadbackVerifier");
const { zk1CloudCopyAddress } =
  require("../src/services/zk1CloudCiphertextReadbackVerifier");

test("Drive media CREATE/UPDATE and GET-by-pinned-ID cross real HTTPS emulator after a forged ACK", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-drive-https-"));
  generateNativeFixtureCertificates(dir, { caSubject: "Drive HTTPS Peer CA",
    servers: ["server"], clients: ["client"] });
  const read = (name) => fs.readFileSync(path.join(dir, name), "utf8");
  const ca = read("ca.pem");
  const operationId = crypto.randomBytes(16);
  const chunks = [crypto.randomBytes(44), crypto.randomBytes(93)];
  const cipher = Buffer.concat(chunks);
  const sha = crypto.createHash("sha256").update(cipher).digest();
  const root = computeZk1CiphertextRoot(chunks);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(5), keyring_id: crypto.randomBytes(16) };
  const address = zk1CloudCopyAddress({ scope, operationId });
  const cloudKey = `zk1-drive-https/uploads/${address.folder}/${address.name}`;
  const id = "pinned-recovery-drive-file-id";
  const folderId = "disposable-parent-id";
  const metadata = () => ({ id, parents: [folderId], appProperties: {
    rootArkKey: cloudKey, rootArkFolderId: address.folder,
    rootArkArea: "uploads",
  } });
  let stored = null;
  let corrupted = false;
  let forgedMetadata = false;
  let countPut = 0;
  let countGet = 0;
  const sockets = new Set();
  const server = https.createServer({ key: read("server.key"),
    cert: read("server.pem"), ca }, (request, response) => {
    if (request.url === `/drive/${id}/metadata` && request.method === "GET") {
      response.writeHead(stored ? 200 : 404, { "content-type": "application/json" });
      response.end(JSON.stringify(stored ? {
        ...metadata(), ...(forgedMetadata ? { id: "forged-other-id" } : {}),
      } : {}));
    } else if (request.url === `/drive/${id}/media` && request.method === "GET") {
      countGet += 1;
      if (!stored) { response.writeHead(404); response.end(); return; }
      const bytes = corrupted ? Buffer.alloc(stored.length, 0x66) : stored;
      response.writeHead(200, { "content-length": bytes.length }); response.end(bytes);
    } else if (request.url === `/drive/${id}` && ["POST", "PATCH"].includes(request.method)) {
      const parts = [];
      request.on("data", (chunk) => parts.push(chunk));
      request.on("end", () => {
        countPut += 1;
        stored = Buffer.concat(parts);
        // Deliberately dishonest first HTTP ACK, despite a persisted object.
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ id: countPut === 1 ? "wrong-file-id" : id }));
      });
    } else { response.writeHead(404); response.end(); }
  });
  server.on("connection", (socket) => { sockets.add(socket);
    socket.on("close", () => sockets.delete(socket)); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve)); });
  t.after(() => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const transport = (method, suffix, body = null) => new Promise((resolve, reject) => {
    const request = https.request({ hostname: "127.0.0.1", port: server.address().port,
      path: `/drive/${id}${suffix}`, method, ca, rejectUnauthorized: true }, (res) => {
      const parts = [];
      res.on("data", (chunk) => parts.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(parts) }));
      res.on("error", reject);
    });
    request.on("error", reject);
    request.setTimeout(5000, () => request.destroy(new Error("Drive HTTPS deadline")));
    request.end(body);
  });
  const api = () => ({ files: {
    list: async () => { throw new Error("never enumerate same-key Drive duplicates"); },
    get: async ({ fileId, alt }) => {
      assert.equal(fileId, id);
      const result = await transport("GET", alt === "media" ? "/media" : "/metadata");
      if (result.status !== 200) throw Object.assign(new Error("missing Drive ID"),
        { status: result.status });
      return { data: alt === "media" ? Readable.from([result.body])
        : JSON.parse(result.body.toString("utf8")) };
    },
    create: async ({ requestBody, media }) => {
      assert.equal(requestBody.id, id);
      const parts = [];
      for await (const chunk of media.body) parts.push(Buffer.from(chunk));
      const reply = await transport("POST", "", Buffer.concat(parts));
      return { data: JSON.parse(reply.body.toString("utf8")) };
    },
    update: async ({ fileId, media }) => {
      assert.equal(fileId, id);
      const parts = [];
      for await (const chunk of media.body) parts.push(Buffer.from(chunk));
      const reply = await transport("PATCH", "", Buffer.concat(parts));
      return { data: JSON.parse(reply.body.toString("utf8")) };
    },
  } });
  const cloud = (principal) => createCloudStorage({
    provider: "gdrive", prefix: "zk1-drive-https", rootFolderId: "root",
    gdrive: { folderId }, resolvePrincipalIdentity: async () => principal,
    createGoogleDriveClient: async () => api(),
  });
  const writer = cloud("Drive writer principal");
  const reader = cloud("separately pinned Drive reader principal");
  const publisher = new Zk1CloudCiphertextCopyPublisher({ cloudWriter: writer,
    expectedProvider: "gdrive", expectedWriterContext: await writer.resolveInventoryContext(),
    pinnedDriveFileId: id });
  const verifier = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: reader,
    expectedProvider: "gdrive", expectedReaderContext: await reader.resolveInventoryContext(),
    pinnedDriveFileId: id });
  const put = { scope, operationId, ciphertextSha256: sha, expectedRootHash: root, chunks };
  const check = { scope, operationId, ciphertextSha256: sha, expectedRootHash: root,
    chunkLengths: chunks.map((chunk) => chunk.length) };
  assert.equal(publisher.pinnedCopyTarget.namespaceIdentity,
    verifier.pinnedCopyTarget.namespaceIdentity);
  await assert.rejects(publisher.publishExact(put), /ZK_CLOUD_COPY_UNAVAILABLE/);
  assert.deepEqual(stored, cipher);
  assert.equal((await verifier.verifyExact(check)).providerFileId, id);
  corrupted = true;
  await assert.rejects(verifier.verifyExact(check), /ZK_CLOUD_READBACK_UNAVAILABLE/);
  corrupted = false;
  forgedMetadata = true;
  await assert.rejects(verifier.verifyExact(check), /ZK_CLOUD_READBACK_UNAVAILABLE/);
  forgedMetadata = false;
  const retried = await publisher.publishExact(put);
  assert.equal(retried.providerFileId, id);
  assert.equal(retried.providerObjectKey, cloudKey);
  const reread = await verifier.verifyExact(check);
  assert.equal(reread.readbackSha256.toString("hex"), sha.toString("hex"));
  assert.equal(reread.externalProviderDurabilityProven, false);
  assert.equal(countPut, 2);
  assert.ok(countGet >= 3);
});
