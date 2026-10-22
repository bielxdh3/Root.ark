"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Readable } = require("node:stream");
const { createCloudStorage } = require("../services/cloudStorage");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1CloudCiphertextCopyPublisher } =
  require("../src/services/zk1CloudCiphertextCopyPublisher");
const { Zk1CloudCiphertextReadbackVerifier, zk1CloudCopyAddress } =
  require("../src/services/zk1CloudCiphertextReadbackVerifier");

function fixture(provider) {
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(7), keyring_id: crypto.randomBytes(16) };
  const operationId = crypto.randomBytes(16);
  const chunks = [crypto.randomBytes(100), crypto.randomBytes(93)];
  const sha = crypto.createHash("sha256").update(Buffer.concat(chunks)).digest();
  const root = computeZk1CiphertextRoot(chunks);
  const address = zk1CloudCopyAddress({ scope, operationId });
  const fileId = "fixed-disposable-zk1-physical-copy";
  const state = { stored: null, puts: 0, reads: 0, lastId: null, nextPayload: null };
  const client = (principal) => {
    const options = { provider, prefix: "rootark-disposable-zk1-publish",
      resolvePrincipalIdentity: async () => `${provider}-${principal}` };
    if (provider === "s3") {
      options.s3 = { bucket: "disposable-zk1-bucket" };
      options.createS3Client = async () => ({ send: async (command) => {
        if (command.constructor.name === "PutObjectCommand") {
          state.puts += 1;
          assert.equal(command.input.Bucket, "disposable-zk1-bucket");
          assert.equal(command.input.Key, clientKey());
          const collected = [];
          if (Buffer.isBuffer(command.input.Body)) collected.push(Buffer.from(command.input.Body));
          else for await (const bytes of command.input.Body) collected.push(Buffer.from(bytes));
          state.stored = Buffer.concat(collected);
          assert.equal(command.input.ContentLength, state.stored.length);
          return { ETag: "untrusted-storage-ack" };
        }
        if (command.constructor.name === "GetObjectCommand") {
          state.reads += 1;
          if (!state.stored) throw new Error("no opaque bytes stored");
          return { Body: Readable.from([state.stored]) };
        }
        throw new Error("Unexpected external side effect");
      } });
    } else {
      options.gdrive = { folderId: "disposable-drive-parent" };
      const metadata = () => ({ id: fileId, parents: ["disposable-drive-parent"],
        appProperties: { rootArkKey: clientKey(), rootArkFolderId: address.folder,
          rootArkArea: "uploads" } });
      const missing = () => Object.assign(new Error("not found"), { status: 404 });
      const persist = async (action, input) => {
        state.puts += 1;
        if (action === "create") {
          assert.equal(input.requestBody.id, fileId);
          assert.deepEqual(input.requestBody.parents, ["disposable-drive-parent"]);
        } else assert.equal(input.fileId, fileId);
        const collected = [];
        for await (const bytes of input.media.body) collected.push(Buffer.from(bytes));
        state.stored = Buffer.concat(collected);
        state.lastId = fileId;
        return { data: { id: fileId } };
      };
      options.createGoogleDriveClient = async () => ({ files: {
        list: async () => ({ data: { files: state.stored ? [metadata()] : [] } }),
        get: async ({ fileId: requested, alt }) => {
          if (requested !== fileId || !state.stored) throw missing();
          if (alt === "media") {
            state.reads += 1;
            return { data: Readable.from([state.stored]) };
          }
          return { data: metadata() };
        },
        create: (input) => persist("create", input),
        update: (input) => persist("update", input),
      } });
    }
    return createCloudStorage(options);
  };
  function clientKey() {
    return `rootark-disposable-zk1-publish/uploads/${address.folder}/${address.name}`;
  }
  const payload = { scope, operationId, ciphertextSha256: sha,
    expectedRootHash: root, chunks };
  return { client, payload, state, fileId, sha, root, chunks };
}

for (const provider of ["s3", "gdrive"]) {
  test(`opaque ${provider} bounded PUT plus independently pinned GET preserves exact operation`, async () => {
    const f = fixture(provider);
    const writer = f.client("writer");
    const reader = f.client("reader");
    const issuer = new Zk1CloudCiphertextCopyPublisher({ cloudWriter: writer,
      expectedProvider: provider, expectedWriterContext: await writer.resolveInventoryContext(),
      pinnedDriveFileId: provider === "gdrive" ? f.fileId : null });
    const verifier = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: reader,
      expectedProvider: provider, expectedReaderContext: await reader.resolveInventoryContext(),
      pinnedDriveFileId: provider === "gdrive" ? f.fileId : null });
    const original = Buffer.concat(f.chunks);
    const ack = await issuer.publishExact(f.payload);
    assert.equal(ack.status, "CLOUD_COPY_PUT_ACK_NONAUTHORITATIVE");
    assert.equal(ack.providerDurabilityProven, false);
    assert.equal(ack.authorizesIo, false);
    assert.deepEqual(ack.operationId, f.payload.operationId);
    assert.equal(f.state.puts, 1);
    assert.deepEqual(f.state.stored, original);
    const proof = await verifier.verifyExact({ scope: f.payload.scope,
      operationId: f.payload.operationId,
      ciphertextSha256: f.sha, expectedRootHash: f.root,
      chunkLengths: f.chunks.map((chunk) => chunk.length) });
    assert.equal(proof.readbackMatched, true);
    assert.ok(f.state.reads > 0);
    await issuer.publishExact(f.payload);
    assert.equal(f.state.puts, 2, "retry of exact operation overwrites only its own addressed opaque bytes");
    if (provider === "gdrive") assert.equal(f.state.lastId, f.fileId,
      "Google Drive retries must use the original owner-pinned immutable file ID");
    const beforeBad = f.state.puts;
    for (const bad of [
      { ...f.payload, chunks: [crypto.randomBytes(f.chunks[0].length), f.chunks[1]] },
      { ...f.payload, ciphertextSha256: crypto.randomBytes(32) },
      { ...f.payload, expectedRootHash: crypto.randomBytes(32) },
    ]) await assert.rejects(issuer.publishExact(bad), /ZK_CLOUD_COPY_UNAVAILABLE/);
    assert.equal(f.state.puts, beforeBad, "invalid ciphertext cannot start cloud provider effects");
  });
}

test("Drive writer cannot choose an implicit remote ID and S3 writer refuses a Drive ID", async () => {
  const drive = fixture("gdrive");
  const writer = drive.client("writer");
  const context = await writer.resolveInventoryContext();
  assert.throws(() => new Zk1CloudCiphertextCopyPublisher({
    cloudWriter: writer, expectedProvider: "gdrive", expectedWriterContext: context,
  }), /ZK_CLOUD_COPY_UNAVAILABLE/);
  const s3 = fixture("s3");
  const s3writer = s3.client("writer");
  const s3context = await s3writer.resolveInventoryContext();
  assert.throws(() => new Zk1CloudCiphertextCopyPublisher({
    cloudWriter: s3writer, expectedProvider: "s3",
    expectedWriterContext: s3context,
    pinnedDriveFileId: drive.fileId,
  }), /ZK_CLOUD_COPY_UNAVAILABLE/);
});

test("cloud copy writer rejects changed storage principal before any remote side effect", async () => {
  const f = fixture("s3");
  const writer = f.client("writer");
  const context = await writer.resolveInventoryContext();
  const publisher = new Zk1CloudCiphertextCopyPublisher({ cloudWriter: writer,
    expectedProvider: "s3", expectedWriterContext: context });
  writer.resolveInventoryContext = async () => "b".repeat(64);
  await assert.rejects(publisher.publishExact(f.payload), /ZK_CLOUD_COPY_UNAVAILABLE/);
  assert.equal(f.state.puts, 0,
    "the archive publisher must not start a remote PUT under a foreign writer identity");
});

test("Drive write never accepts a forged or absent physical ID in create, update or 409 retry acknowledgements", async () => {
  for (const scenario of ["create-foreign", "create-missing", "update-foreign",
    "update-missing", "retry-foreign", "retry-missing"]) {
    const f = fixture("gdrive");
    const addr = zk1CloudCopyAddress({ scope: f.payload.scope,
      operationId: f.payload.operationId });
    const key = `rootark-ack-fixture/uploads/${addr.folder}/${addr.name}`;
    const pin = f.fileId;
    let metadataReads = 0;
    let createCalls = 0;
    let updateCalls = 0;
    const responseId = scenario.endsWith("missing") ? {} : { id: "different-remote-id" };
    const cloudWriter = createCloudStorage({
      provider: "gdrive", prefix: "rootark-ack-fixture",
      resolvePrincipalIdentity: async () => "drive-upload-ack-principal",
      gdrive: { folderId: "ack-parent" },
      createGoogleDriveClient: async () => ({ files: {
        get: async ({ fileId }) => {
          assert.equal(fileId, pin);
          metadataReads += 1;
          if (scenario.startsWith("create")
            || (scenario.startsWith("retry") && metadataReads === 1)) {
            throw Object.assign(new Error("missing pinned file"), { status: 404 });
          }
          return { data: { id: pin, parents: ["ack-parent"],
            appProperties: { rootArkKey: key, rootArkFolderId: addr.folder,
              rootArkArea: "uploads" } } };
        },
        create: async ({ requestBody }) => {
          createCalls += 1;
          assert.equal(requestBody.id, pin);
          if (scenario.startsWith("retry")) {
            throw Object.assign(new Error("409 ID exists"), { status: 409 });
          }
          return { data: responseId };
        },
        update: async ({ fileId }) => {
          assert.equal(fileId, pin);
          updateCalls += 1;
          return { data: responseId };
        },
      } }),
    });
    const pub = new Zk1CloudCiphertextCopyPublisher({ cloudWriter,
      expectedProvider: "gdrive",
      expectedWriterContext: await cloudWriter.resolveInventoryContext(),
      pinnedDriveFileId: pin });
    await assert.rejects(pub.publishExact(f.payload), /ZK_CLOUD_COPY_UNAVAILABLE/,
      `${scenario} cannot yield acknowledged physical ciphertext replication`);
    assert.equal(createCalls, Number(!scenario.startsWith("update")));
    assert.equal(updateCalls, Number(!scenario.startsWith("create")));
  }
});

test("Drive verification never substitutes an older same-key duplicate for the exact published ID", async () => {
  const f = fixture("gdrive");
  const oldId = "a-previous-identical-object";
  const newId = "z-pinned-current-object";
  let forgedMetadataId = false;
  const oldBytes = Buffer.concat(f.chunks);
  const currentBytes = Buffer.alloc(oldBytes.length, 0x91);
  const addr = zk1CloudCopyAddress({ scope: f.payload.scope,
    operationId: f.payload.operationId });
  const cloudKey = `rootark-dup-fixture/uploads/${addr.folder}/${addr.name}`;
  const objects = new Map([[oldId, oldBytes]]);
  const inspected = [];
  const file = (id) => ({ id, parents: ["parent-dup"],
    appProperties: { rootArkKey: cloudKey, rootArkFolderId: addr.folder,
      rootArkArea: "uploads" } });
  const notFound = () => Object.assign(new Error("missing"), { status: 404 });
  const drive = () => ({ files: {
    list: async () => ({ data: { files: [file(oldId), file(newId)] } }),
    get: async ({ fileId, alt }) => {
      inspected.push(`${fileId}:${alt || "metadata"}`);
      if (!objects.has(fileId)) throw notFound();
      return alt === "media" ? { data: Readable.from([objects.get(fileId)]) }
        : { data: file(forgedMetadataId && fileId === newId ? oldId : fileId) };
    },
    create: async ({ requestBody, media }) => {
      assert.equal(requestBody.id, newId);
      const chunks = [];
      for await (const chunk of media.body) chunks.push(Buffer.from(chunk));
      assert.deepEqual(Buffer.concat(chunks), oldBytes);
      // A remote/compromised provider can ACK a different write. The old
      // same-key file must not substitute for this pinned file on GET.
      objects.set(newId, Buffer.from(currentBytes));
      return { data: { id: newId } };
    },
  } });
  const makeStorage = (identity) => createCloudStorage({
    provider: "gdrive", prefix: "rootark-dup-fixture",
    gdrive: { folderId: "parent-dup" },
    resolvePrincipalIdentity: async () => identity,
    createGoogleDriveClient: async () => drive(),
  });
  const writer = makeStorage("dup-writer");
  const reader = makeStorage("dup-reader");
  const publisher = new Zk1CloudCiphertextCopyPublisher({ cloudWriter: writer,
    expectedProvider: "gdrive", expectedWriterContext: await writer.resolveInventoryContext(),
    pinnedDriveFileId: newId });
  const verifier = new Zk1CloudCiphertextReadbackVerifier({ cloudReader: reader,
    expectedProvider: "gdrive", expectedReaderContext: await reader.resolveInventoryContext(),
    pinnedDriveFileId: newId });
  const ack = await publisher.publishExact(f.payload);
  assert.equal(ack.providerFileId, newId);
  assert.deepEqual(objects.get(oldId), oldBytes);
  await assert.rejects(verifier.verifyExact({ scope: f.payload.scope,
    operationId: f.payload.operationId, ciphertextSha256: f.sha,
    expectedRootHash: f.root,
    chunkLengths: f.chunks.map((chunk) => chunk.length) }),
  /ZK_CLOUD_READBACK_UNAVAILABLE/,
  "a valid older copy with identical logical key cannot masquerade as the corrupted current pinned copy");
  assert.ok(inspected.includes(`${newId}:media`));
  assert.ok(!inspected.includes(`${oldId}:media`),
    "the verifier must not fetch older duplicate media under any circumstances");
  objects.set(newId, oldBytes);
  const checked = await verifier.verifyExact({ scope: f.payload.scope,
    operationId: f.payload.operationId, ciphertextSha256: f.sha,
    expectedRootHash: f.root,
    chunkLengths: f.chunks.map((chunk) => chunk.length) });
  assert.equal(checked.providerFileId, newId);
  assert.equal(checked.readbackMatched, true);
  forgedMetadataId = true;
  await assert.rejects(verifier.verifyExact({ scope: f.payload.scope,
    operationId: f.payload.operationId, ciphertextSha256: f.sha,
    expectedRootHash: f.root,
    chunkLengths: f.chunks.map((chunk) => chunk.length) }),
  /ZK_CLOUD_READBACK_UNAVAILABLE/,
  "the provider cannot impersonate the pinned ID with another file's otherwise valid metadata");
  await assert.rejects(publisher.publishExact(f.payload), /ZK_CLOUD_COPY_UNAVAILABLE/,
    "a forged get-by-ID reply cannot authorize an update of another physical Drive object");
});

test("bounded cloud PUT rejects a provider that stalls before acknowledging the write", {
  timeout: 20000,
}, async () => {
  const f = fixture("s3");
  const writer = createCloudStorage({ provider: "s3", prefix: "rootark-stalled-copy-fixture",
    s3: { bucket: "stalled-upload-fixture" },
    resolvePrincipalIdentity: async () => "synthetic-reader-identity",
    createS3Client: async () => ({ send: async (cmd) => {
      assert.equal(cmd.constructor.name, "PutObjectCommand");
      return new Promise(() => {});
    } }),
  });
  const publisher = new Zk1CloudCiphertextCopyPublisher({ cloudWriter: writer,
    expectedProvider: "s3", expectedWriterContext: await writer.resolveInventoryContext() });
  const began = Date.now();
  await assert.rejects(publisher.publishExact(f.payload), /ZK_CLOUD_COPY_UNAVAILABLE/);
  assert.ok(Date.now() - began < 19000,
    "an unresponsive external upload must not leave a protected operation waiting indefinitely");
});
