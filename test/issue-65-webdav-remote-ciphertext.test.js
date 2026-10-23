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
const { createZk1WebdavCiphertextAdapter } =
  require("../src/services/zk1WebdavCiphertextAdapter");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1CloudCiphertextCopyPublisher } =
  require("../src/services/zk1CloudCiphertextCopyPublisher");
const { Zk1CloudCiphertextReadbackVerifier, zk1CloudCopyAddress } =
  require("../src/services/zk1CloudCiphertextReadbackVerifier");

async function fixture(t) {
  const initialEnvironment = process.env.NODE_ENV;
  process.env.NODE_ENV = "development";
  t.after(() => {
    if (initialEnvironment === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = initialEnvironment;
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-dev-webdav-"));
  t.after(() => fs.rmSync(dir, { force: true, recursive: true, maxRetries: 5 }));
  generateNativeFixtureCertificates(dir, { caSubject: "Webdav Fixture CA",
    servers: ["server"], clients: ["client"] });
  const read = (name) => fs.readFileSync(path.join(dir, name), "utf8");
  const ca = read("ca.pem");
  const cert = read("server.pem");
  const clientCert = read("client.pem");
  const clientKey = read("client.key");
  const pin = new crypto.X509Certificate(cert).fingerprint256;
  const saved = new Map();
  const requests = [];
  let mode = "normal";
  const expectedAuthorization = `Basic ${Buffer.from("webdav-tester:NOT-FOR-LOGS-SECRET").toString("base64")}`;
  const sockets = new Set();
  const server = https.createServer({ key: read("server.key"), cert, ca,
    requestCert: true, rejectUnauthorized: true }, (req, res) => {
    requests.push({ method: req.method, url: req.url,
      auth: req.headers.authorization, clientAuthorized: req.client.authorized });
    if (mode === "stall") { req.resume(); return; }
    if (mode === "redirect") { req.resume(); res.writeHead(302, { Location: "http://localhost/unsafe" }); res.end(); return; }
    if (mode === "missing") { req.resume(); res.writeHead(404); res.end(); return; }
    if (mode === "unauthorized") { req.resume(); res.writeHead(401); res.end(); return; }
    if (req.headers.authorization !== expectedAuthorization) {
      req.resume(); res.writeHead(401); res.end(); return;
    }
    if (req.method === "PUT") {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        saved.set(req.url, Buffer.concat(chunks));
        res.writeHead(201); res.end();
      });
      return;
    }
    if (req.method === "GET") {
      const data = saved.get(req.url);
      if (!data) { res.writeHead(404); res.end(); return; }
      const body = mode === "oversized" ? Buffer.concat([data, Buffer.from("extra")])
        : mode === "corrupt" ? Buffer.alloc(data.length, 0x42) : data;
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(body);
      return;
    }
    res.writeHead(405); res.end();
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const config = { developmentOnlyOptIn: true,
    endpoint: `https://127.0.0.1:${server.address().port}/dav`,
    namespace: "separate_dev_namespace", ca, serverFingerprint256: pin,
    clientCert, clientKey, username: "webdav-tester", password: "NOT-FOR-LOGS-SECRET" };
  const chunks = [crypto.randomBytes(71), crypto.randomBytes(119)];
  const ciphertext = Buffer.concat(chunks);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(5), keyring_id: crypto.randomBytes(16) };
  const operationId = crypto.randomBytes(16);
  const sha = crypto.createHash("sha256").update(ciphertext).digest();
  const root = computeZk1CiphertextRoot(chunks);
  const pubInput = { scope, operationId,
    ciphertextSha256: sha, expectedRootHash: root, chunks };
  const readInput = { scope, operationId,
    ciphertextSha256: sha, expectedRootHash: root,
    chunkLengths: chunks.map((chunk) => chunk.length) };
  const makePair = async (opts = config) => {
    const writer = createZk1WebdavCiphertextAdapter(opts);
    const reader = createZk1WebdavCiphertextAdapter({ ...opts });
    return {
      writer, reader,
      publisher: new Zk1CloudCiphertextCopyPublisher({
        cloudWriter: writer, expectedProvider: "webdav",
        expectedWriterContext: await writer.resolveInventoryContext() }),
      verifier: new Zk1CloudCiphertextReadbackVerifier({
        cloudReader: reader, expectedProvider: "webdav",
        expectedReaderContext: await reader.resolveInventoryContext() }),
    };
  };
  return { config, saved, requests, chunks, ciphertext, pubInput, readInput, makePair,
    setMode: (next) => { mode = next; } };
}

test("real mTLS HTTPS WebDAV PUT/GET is bounded, pinned and nonauthoritative", async (t) => {
  const f = await fixture(t);
  const { publisher, verifier } = await f.makePair();
  const ack = await publisher.publishExact(f.pubInput);
  assert.equal(ack.provider, "webdav");
  assert.equal(ack.status, "CLOUD_COPY_PUT_ACK_NONAUTHORITATIVE");
  assert.equal(ack.authorizesIo, false);
  assert.equal(ack.providerDurabilityProven, false);
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].method, "PUT");
  assert.equal(f.requests[0].clientAuthorized, true);
  assert.ok(f.requests[0].url.startsWith("/dav/separate_dev_namespace/uploads/zk1-"));
  assert.deepEqual([...f.saved.values()][0], f.ciphertext);
  const verified = await verifier.verifyExact(f.readInput);
  assert.equal(verified.readbackMatched, true);
  assert.equal(verified.authorizesIo, false);
  assert.equal(verified.externalProviderDurabilityProven, false);
  assert.equal(verified.independentlyAnchoredFloorProven, false);
  assert.equal(f.requests.at(-1).method, "GET");
  assert.equal(f.requests.at(-1).url, f.requests[0].url);
  assert.match(f.requests[0].auth, /^Basic /);

  await publisher.publishExact(f.pubInput);
  assert.equal(f.saved.size, 1, "replay stays at the fixed remote object key");
  await assert.rejects(publisher.publishExact({ ...f.pubInput, chunks: [
    crypto.randomBytes(f.chunks[0].length), f.chunks[1],
  ] }), /ZK_CLOUD_COPY_UNAVAILABLE/);
  assert.equal(f.requests.length, 3, "invalid ZK commitment cannot send bytes");
});

test("WebDAV rejects insecure/ambiguous setup, wrong pin, foreign context and path traversal", async (t) => {
  const f = await fixture(t);
  const invalid = [
    { developmentOnlyOptIn: false }, { endpoint: "http://localhost/dav" },
    { endpoint: f.config.endpoint.replace("/dav", "/dav/../foreign") },
    { endpoint: f.config.endpoint.replace("/dav", "/dav/%2e%2e") },
    { endpoint: f.config.endpoint.replace("/dav", "/dav?next=bad") },
    { endpoint: f.config.endpoint.replace("https://", "https://user:secret@") },
    { namespace: "../escape" }, { namespace: "tenant/foreign" },
    { ca: "" }, { serverFingerprint256: "A" },
    { username: "bad\r\nheader", password: "secret" },
  ];
  for (const change of invalid) assert.throws(() => createZk1WebdavCiphertextAdapter({
    ...f.config, ...change,
  }), /ZK_WEBDAV_CIPHERTEXT_UNAVAILABLE/);
  const prior = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = "production";
    assert.throws(() => createZk1WebdavCiphertextAdapter(f.config), /ZK_WEBDAV_CIPHERTEXT_UNAVAILABLE/);
  } finally {
    if (prior === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prior;
  }
  const wrong = await f.makePair({ ...f.config,
    serverFingerprint256: "00".repeat(32) });
  await assert.rejects(wrong.publisher.publishExact(f.pubInput), /ZK_CLOUD_COPY_UNAVAILABLE/);
  assert.equal(f.requests.length, 0, "wrong TLS pin must prevent HTTP request");
  const valid = await f.makePair();
  for (const pair of [
    ["../escape", "good.ct"], ["zk1-" + "a".repeat(64), "../escape.ct"],
    ["zk1-" + "a".repeat(64), "a/b.ct"],
  ]) assert.throws(() => valid.writer.key(pair[0], pair[1], "uploads"),
    /ZK_WEBDAV_CIPHERTEXT_UNAVAILABLE/);
  await valid.publisher.publishExact(f.pubInput);
  const invalidPassword = await f.makePair({ ...f.config, password: "wrong-secret" });
  await assert.rejects(invalidPassword.publisher.publishExact(f.pubInput),
    /ZK_CLOUD_COPY_UNAVAILABLE/);
  const foreignReader = createZk1WebdavCiphertextAdapter({ ...f.config,
    namespace: "other_dev_namespace" });
  const foreign = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: foreignReader,
    expectedProvider: "webdav", expectedReaderContext: await valid.reader.resolveInventoryContext() });
  await assert.rejects(foreign.verifyExact(f.readInput), /ZK_CLOUD_READBACK_UNAVAILABLE/);
  assert.equal(f.requests.length, 2, "namespace identity mismatch blocks GET");
  assert.throws(() => new Zk1CloudCiphertextCopyPublisher({ cloudWriter: valid.writer,
    expectedProvider: "webdav", expectedWriterContext: "a".repeat(64),
    pinnedDriveFileId: "foreign-id" }), /ZK_CLOUD_COPY_UNAVAILABLE/);
});

test("WebDAV rejects coercion-based remote path escape before any HTTPS PUT", async (t) => {
  const f = await fixture(t);
  const writer = createZk1WebdavCiphertextAdapter(f.config);
  const staging = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-coercion-"));
  t.after(() => fs.rmSync(staging, { recursive: true, force: true }));
  const source = path.join(staging, "opaque.ct");
  fs.writeFileSync(source, f.ciphertext);
  const folder = `zk1-${"a".repeat(64)}`;
  let conversions = 0;
  const maliciousName = {
    toString() {
      conversions += 1;
      return conversions === 1 ? `${"b".repeat(22)}.ct` : "../../outside/foreign.ct";
    },
  };
  const requestsBefore = f.requests.length;
  await assert.rejects(writer.upload(source, folder, maliciousName, "uploads",
    { zk1BoundedBytes: f.ciphertext.length }), /ZK_WEBDAV_CIPHERTEXT_UNAVAILABLE/);
  assert.equal(f.requests.length, requestsBefore,
    "a dynamic name must never be interpreted again as a remote path");

  const mutableNamespace = {
    toString: () => "separate_dev_namespace",
  };
  assert.throws(() => createZk1WebdavCiphertextAdapter({
    ...f.config, namespace: mutableNamespace,
  }), /ZK_WEBDAV_CIPHERTEXT_UNAVAILABLE/,
  "namespace identity and remote namespace must both be one validated string");

  let reads = 0;
  const getterConfig = { ...f.config };
  Object.defineProperty(getterConfig, "namespace", {
    enumerable: true,
    get() { return ++reads <= 2 ? "separate_dev_namespace" : "../foreign"; },
  });
  assert.throws(() => createZk1WebdavCiphertextAdapter(getterConfig),
    /ZK_WEBDAV_CIPHERTEXT_UNAVAILABLE/,
    "a namespace accessor must not mutate between validation and use");
});

test("WebDAV remote errors, redirect, truncated/oversized/corrupt data fail closed", async (t) => {
  const f = await fixture(t);
  const { publisher, verifier } = await f.makePair();
  await publisher.publishExact(f.pubInput);
  for (const status of ["redirect", "missing", "unauthorized"]) {
    f.setMode(status);
    await assert.rejects(publisher.publishExact(f.pubInput), /ZK_CLOUD_COPY_UNAVAILABLE/);
    await assert.rejects(verifier.verifyExact(f.readInput), /ZK_CLOUD_READBACK_UNAVAILABLE/);
  }
  for (const mode of ["oversized", "corrupt"]) {
    f.setMode(mode);
    await assert.rejects(verifier.verifyExact(f.readInput), /ZK_CLOUD_READBACK_UNAVAILABLE/);
  }
  f.setMode("normal");
  const bigger = { ...f.readInput, chunkLengths: [f.ciphertext.length - 1] };
  await assert.rejects(verifier.verifyExact(bigger), /ZK_CLOUD_READBACK_UNAVAILABLE/);
  assert.ok(f.requests.every((req) => ["GET", "PUT"].includes(req.method)));
  const password = f.config.password;
  for (const failure of ["ZK_CLOUD_COPY_UNAVAILABLE", "ZK_CLOUD_READBACK_UNAVAILABLE"]) {
    assert.ok(!failure.includes(password));
  }
});

test("WebDAV must reject download parent replaced by a junction or fresh directory during GET", async (t) => {
  const f = await fixture(t);
  const { publisher, reader, writer } = await f.makePair();
  await publisher.publishExact(f.pubInput);
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-webdav-parent-race-"));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  const foreign = path.join(scratch, "foreign");
  fs.mkdirSync(foreign);
  const marker = path.join(foreign, "keep.txt");
  fs.writeFileSync(marker, "do not modify", { flag: "wx" });
  const { folder, name } = zk1CloudCopyAddress({
    scope: f.pubInput.scope, operationId: f.pubInput.operationId,
  });
  for (const replacement of ["junction", "ordinary-directory"]) {
    const authorized = path.join(scratch, `authorized-${replacement}`);
    fs.mkdirSync(authorized);
    const destination = path.join(authorized, "ciphertext.ct");
    let checked = 0;
    await assert.rejects(reader.download(folder, name, destination, "uploads", () => {
      checked += 1;
      if (checked === 2) {
        if (replacement === "junction") {
          fs.rmdirSync(authorized);
          fs.symlinkSync(foreign, authorized,
            process.platform === "win32" ? "junction" : "dir");
        } else {
          fs.renameSync(authorized, path.join(scratch, "original-parent"));
          fs.mkdirSync(authorized);
        }
      }
      return true;
    }, { maxBytes: f.ciphertext.length }), /ZK_WEBDAV_CIPHERTEXT_UNAVAILABLE/);
    assert.equal(checked, 2, "authorization must be rechecked after the network operation");
    assert.equal(fs.existsSync(destination), false,
      "a changed parent cannot redirect opaque ciphertext outside its pinned directory");
  }
  assert.equal(fs.existsSync(path.join(foreign, "ciphertext.ct")), false);
  assert.equal(fs.readFileSync(marker, "utf8"), "do not modify");

  const sourceJunction = path.join(scratch, "untrusted-source-link");
  const foreignBytes = crypto.randomBytes(f.ciphertext.length);
  fs.writeFileSync(path.join(foreign, "secret.ct"), foreignBytes, { flag: "wx" });
  fs.symlinkSync(foreign, sourceJunction, process.platform === "win32" ? "junction" : "dir");
  const sentBefore = f.requests.length;
  await assert.rejects(writer.upload(path.join(sourceJunction, "secret.ct"),
    folder, name, "uploads", { zk1BoundedBytes: f.ciphertext.length }),
  /ZK_WEBDAV_CIPHERTEXT_UNAVAILABLE/);
  assert.equal(f.requests.length, sentBefore,
    "source through foreign parent must be refused before any HTTPS PUT");
});

test("WebDAV stalled HTTPS peer is terminated at the 15-second deadline", async (t) => {
  const f = await fixture(t);
  f.setMode("stall");
  const { publisher } = await f.makePair();
  const start = Date.now();
  await assert.rejects(publisher.publishExact(f.pubInput), /ZK_CLOUD_COPY_UNAVAILABLE/);
  assert.ok(Date.now() - start >= 14000 && Date.now() - start < 19000);
});
