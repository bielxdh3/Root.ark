"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Readable } = require("node:stream");
const { createCloudStorage } = require("../services/cloudStorage");
const { createZk1PrivateCloudStagingDirectory } =
  require("../src/services/zk1PrivateCloudStagingDirectory");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1CloudCiphertextReadbackVerifier, zk1CloudCopyAddress } =
  require("../src/services/zk1CloudCiphertextReadbackVerifier");

function fixture(provider) {
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(7), keyring_id: crypto.randomBytes(16) };
  const operationId = crypto.randomBytes(16);
  const chunks = [crypto.randomBytes(117), crypto.randomBytes(83)];
  const original = Buffer.concat(chunks);
  const ciphertextSha256 = crypto.createHash("sha256").update(original).digest();
  const expectedRootHash = computeZk1CiphertextRoot(chunks);
  const chunkLengths = chunks.map((chunk) => chunk.length);
  const address = zk1CloudCopyAddress({ scope, operationId });
  let payload = Buffer.from(original);
  let principal = `${provider}-reader-A`;
  let httpVariant = null;
  const calls = [];
  const config = {
    provider, prefix: "rootark-cloud-physical-fixture", rootFolderId: "root",
    resolvePrincipalIdentity: async () => principal,
  };
  if (provider === "s3") {
    config.s3 = { bucket: "disposable-fixture" };
    config.createS3Client = async () => ({ send: async (command, { abortSignal } = {}) => {
      calls.push(command.constructor.name);
      if (payload === "stall") {
        // Real SDK transports settle their request after honoring AbortSignal.
        // A never-settling mock instead models a noncooperative provider and
        // must keep the physical I/O fence held until it actually settles.
        assert.ok(abortSignal instanceof AbortSignal);
        return new Promise((_resolve, reject) => {
          if (abortSignal.aborted) return reject(new Error("synthetic S3 GET aborted"));
          abortSignal.addEventListener("abort",
            () => reject(new Error("synthetic S3 GET aborted")), { once: true });
        });
      }
      if (command.constructor.name !== "GetObjectCommand"
        || command.input.Bucket !== "disposable-fixture"
        || command.input.Key !== reader.key(address.folder, address.name, "uploads")
        || !payload) throw new Error("missing fixture object");
      return { Body: Readable.from([payload]),
        ...(httpVariant === null ? {} : {
          $metadata: { httpStatusCode: httpVariant.status },
          ...(httpVariant.contentRange ? { ContentRange: httpVariant.contentRange } : {}),
          ...(httpVariant.contentEncoding ? { ContentEncoding: httpVariant.contentEncoding } : {}),
        }) };
    } });
  } else {
    config.gdrive = { folderId: "fixture-parent" };
    const file = () => ({ id: "fixture-cloud-id", parents: ["fixture-parent"],
      appProperties: { rootArkKey: reader.key(address.folder, address.name, "uploads"),
        rootArkFolderId: address.folder, rootArkArea: "uploads" } });
    config.createGoogleDriveClient = async () => ({ files: {
      list: async () => { calls.push("list"); return { data: { files: payload ? [file()] : [] } }; },
      get: async ({ fileId, alt }) => {
        calls.push(`get:${alt || "metadata"}`);
        if (fileId !== "fixture-cloud-id" || !payload) throw new Error("missing fixture object");
        return alt === "media" ? { data: Readable.from([payload]),
          ...(httpVariant === null ? {} : {
            status: httpVariant.status,
            headers: {
              ...(httpVariant.contentRange ? { "content-range": httpVariant.contentRange } : {}),
              ...(httpVariant.contentEncoding ? { "content-encoding": httpVariant.contentEncoding } : {}),
            },
          }) } : { data: file() };
      },
    } });
  }
  const reader = createCloudStorage(config);
  const input = { scope, operationId, ciphertextSha256, expectedRootHash, chunkLengths };
  return { reader, input, calls, original,
    changePayload(next) { payload = next; }, changePrincipal(next) { principal = next; },
    setHttpVariant(next) { httpVariant = next; } };
}

for (const provider of ["s3", "gdrive"]) {
  test(`${provider} bounded ciphertext GET rejects partial and transformed HTTP representation even when sha/root match`, async () => {
    const f = fixture(provider);
    const readerContext = await f.reader.resolveInventoryContext();
    const verifier = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: f.reader,
      expectedProvider: provider, expectedReaderContext: readerContext,
      pinnedDriveFileId: provider === "gdrive" ? "fixture-cloud-id" : null });
    const contentRange = `bytes 0-${f.original.length - 1}/${f.original.length + 1}`;
    for (const httpVariant of [
      { status: 206, contentRange },
      { status: 200, contentRange },
      { status: 200, contentEncoding: "gzip" },
    ]) {
      f.setHttpVariant(httpVariant);
      await assert.rejects(verifier.verifyExact(f.input), /ZK_CLOUD_READBACK_UNAVAILABLE/,
        `${provider} may not claim a complete provider object from HTTP ${JSON.stringify(httpVariant)}`);
    }
    f.setHttpVariant({ status: 200 });
    assert.equal((await verifier.verifyExact(f.input)).readbackMatched, true);
  });
}

for (const provider of ["s3", "gdrive"]) {
  test(`independently pinned ${provider} identity re-reads exact opaque ciphertext only`, async () => {
    const f = fixture(provider);
    const pinned = await f.reader.resolveInventoryContext();
    const verifier = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: f.reader,
      expectedProvider: provider, expectedReaderContext: pinned,
      pinnedDriveFileId: provider === "gdrive" ? "fixture-cloud-id" : null });
    const good = await verifier.verifyExact(f.input);
    assert.equal(good.status, "EXTERNAL_CIPHERTEXT_REREAD_MATCHED");
    assert.equal(good.readbackMatched, true);
    assert.deepEqual(good.operationId, f.input.operationId);
    assert.equal(good.byteLength, f.original.length);
    assert.equal(good.authorizesIo, false);
    assert.equal(good.externalProviderDurabilityProven, false);
    assert.equal(good.independentlyAnchoredFloorProven, false);
    assert.ok(f.calls.length > 0);
    assert.ok(f.calls.every((item) => /^(GetObjectCommand|list|get:metadata|get:media)$/.test(item)),
      "the verifier must never invoke remote upload, delete or permission mutation");
    f.changePayload(Buffer.from(f.original).fill(0x55));
    await assert.rejects(verifier.verifyExact(f.input), /ZK_CLOUD_READBACK_UNAVAILABLE/);
    f.changePayload(Buffer.concat([f.original, Buffer.from([0x44])]));
    await assert.rejects(verifier.verifyExact(f.input), /ZK_CLOUD_READBACK_UNAVAILABLE/,
      "oversized provider streams must abort before publishing a local file");
    f.changePayload(null);
    await assert.rejects(verifier.verifyExact(f.input), /ZK_CLOUD_READBACK_UNAVAILABLE/);
    f.changePayload(Buffer.from(f.original));
    await assert.rejects(verifier.verifyExact({ ...f.input,
      operationId: crypto.randomBytes(16) }), /ZK_CLOUD_READBACK_UNAVAILABLE/);
    f.changePrincipal(`${provider}-reader-B`);
    await assert.rejects(verifier.verifyExact(f.input), /ZK_CLOUD_READBACK_UNAVAILABLE/,
      "changing the cloud principal must fail before exposing another object's bytes");
  });
}

test("cloud physical verifier rejects unsafe length/commitment inputs before provider reads", async () => {
  const f = fixture("s3");
  const pinned = await f.reader.resolveInventoryContext();
  const verifier = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: f.reader,
    expectedProvider: "s3", expectedReaderContext: pinned });
  for (const input of [
    { ...f.input, chunkLengths: [0, 200] },
    { ...f.input, chunkLengths: [4 * 1024 * 1024 + 1] },
    { ...f.input, chunkLengths: Array(17).fill(1) },
    { ...f.input, expectedRootHash: crypto.randomBytes(32) },
    { ...f.input, ciphertextSha256: crypto.randomBytes(32) },
    { ...f.input, chunkLengths: [f.input.chunkLengths[0] - 1,
      f.input.chunkLengths[1] + 1] },
    { ...f.input, scope: { ...f.input.scope, keyring_id: crypto.randomBytes(16) } },
  ]) await assert.rejects(verifier.verifyExact(input), /ZK_CLOUD_READBACK_UNAVAILABLE/);
  // Digest/scope mismatches may read only the addressed ciphertext, but cannot
  // mutate cloud data or cause a positive readback claim.
  assert.ok(f.calls.every((item) => item === "GetObjectCommand"));
});

test("cloud verifier rejects a remote adapter that tries to publish a linked local file", async () => {
  const f = fixture("s3");
  const disposable = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-cloud-untrusted-link-"));
  const original = path.join(disposable, "ciphertext-source.ct");
  fs.writeFileSync(original, f.original, { flag: "wx", mode: 0o600 });
  const readerContext = "a".repeat(64);
  const adapter = {
    status: () => ({ provider: "s3" }), enabled: () => true,
    resolveInventoryContext: async () => readerContext,
    key: (folder, name, area) => `rootark/${area}/${folder}/${name}`,
    download: async (_folder, _name, destination) => {
      fs.linkSync(original, destination);
      return true;
    },
  };
  try {
    const verifier = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: adapter,
      expectedProvider: "s3", expectedReaderContext: readerContext });
    await assert.rejects(verifier.verifyExact(f.input), /ZK_CLOUD_READBACK_UNAVAILABLE/,
      "a linked inode cannot masquerade as an isolated disposable ciphertext readback");
    assert.deepEqual(fs.readFileSync(original), f.original,
      "rejecting the forged adapter must not alter the original file");
  } finally { fs.rmSync(disposable, { recursive: true, force: true }); }
});

test("cloud ciphertext readback never allocates beyond pinned size if the downloaded inode grows after fstat", async () => {
  const f = fixture("s3");
  const context = "a".repeat(64);
  let destination;
  const reader = {
    status: () => ({ provider: "s3" }), enabled: () => true,
    resolveInventoryContext: async () => context,
    key: (folder, name, area) => `rootark/${area}/${folder}/${name}`,
    download: async (_folder, _name, file) => {
      destination = file;
      fs.writeFileSync(file, f.original, { flag: "wx", mode: 0o600 });
      return true;
    },
  };
  const verifier = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: reader,
    expectedProvider: "s3", expectedReaderContext: context });
  const originalStat = fs.fstatSync;
  const originalReadFile = fs.readFileSync;
  let injected = false;
  let bytesReadUnbounded = 0;
  // A malicious or broken provider-side adapter can retain the destination
  // name and append after the verifier opened and size-checked its inode.
  // The verifier must not allocate/read the extra bytes before rejecting it.
  try {
    fs.fstatSync = function (fd, options) {
      const stat = originalStat.call(fs, fd, options);
      if (!injected && destination && stat.isFile()
        && stat.size === BigInt(f.original.length)) {
        injected = true;
        fs.appendFileSync(destination, Buffer.alloc(64 * 1024, 0x66));
      }
      return stat;
    };
    fs.readFileSync = function (file, ...options) {
      const data = originalReadFile.call(fs, file, ...options);
      if (Number.isInteger(file)) bytesReadUnbounded = data.length;
      return data;
    };
    await assert.rejects(verifier.verifyExact(f.input), /ZK_CLOUD_READBACK_UNAVAILABLE/);
    assert.equal(injected, true, "simulated writer must race the verifier's fstat");
    assert.ok(bytesReadUnbounded <= f.original.length,
      "untrusted growth may never cause a read/allocation beyond the exact signed ciphertext size");
  } finally {
    fs.fstatSync = originalStat;
    fs.readFileSync = originalReadFile;
  }
});

test("bounded S3 readback never substitutes a file raced into the destination after GET", async () => {
  // On Windows, a bounded GET deliberately refuses a shared OS temp root.
  // Race the destination in a valid, ACL-protected private staging root.
  const disposable = process.platform === "win32"
    ? await createZk1PrivateCloudStagingDirectory("rootark-zk1-cloud-race-")
    : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-cloud-race-"));
  const destination = path.join(disposable, "ciphertext.ct");
  const remoteBytes = Buffer.from("provider-ciphertext");
  const replacement = Buffer.from("untrusted-local-copy");
  const reader = createCloudStorage({ provider: "s3", prefix: "rootark-race-fixture",
    s3: { bucket: "disposable" }, createS3Client: async () => ({ send: async () => ({
      Body: Readable.from((async function* () {
        fs.writeFileSync(destination, replacement, { flag: "wx" });
        yield remoteBytes;
      }())),
    }) }) });
  try {
    await assert.rejects(reader.download("opaque-folder", "opaque-name.ct", destination,
      "uploads", () => true, { maxBytes: remoteBytes.length }),
    "a concurrent destination must fail closed rather than accept unverified local bytes");
    assert.deepEqual(fs.readFileSync(destination), replacement,
      "a failed readback may not overwrite the other owner's unexpected destination");
  } finally { fs.rmSync(disposable, { recursive: true, force: true }); }
});

test("a provider stalled before the GET body cannot retain the bounded readback indefinitely", {
  timeout: 20000,
}, async () => {
  const f = fixture("s3");
  const pinned = await f.reader.resolveInventoryContext();
  const verifier = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: f.reader,
    expectedProvider: "s3", expectedReaderContext: pinned });
  f.changePayload("stall");
  const began = Date.now();
  await assert.rejects(verifier.verifyExact(f.input), /ZK_CLOUD_READBACK_UNAVAILABLE/);
  assert.ok(Date.now() - began < 19000,
    "the bounded remote lookup must stop before a stalled cloud client can hang a PG admission");
});
