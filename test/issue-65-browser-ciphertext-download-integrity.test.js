"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const file = require("../public/client/rootark-zk1-file-content");
const root = require("../public/client/rootark-zk1-ciphertext-chunk-root");
const download = require("../public/client/rootark-zk1-ciphertext-download-integrity");

const random = (n) => crypto.randomBytes(n);
const id = () => random(16).toString("base64url");

function frames(ciphertext, length) {
  const result = [];
  for (let offset = 0; offset < ciphertext.length; offset += length) {
    const end = Math.min(offset + length, ciphertext.length);
    result.push({ index: result.length, bytes: Buffer.from(ciphertext.subarray(offset, end)) });
  }
  return result;
}

async function fixture() {
  const cek = await file.generateFileCek();
  const metadata = { account_id: id(), compartment_id: id(), keyring_id: id(),
    object_id: id(), version_id: id(), parent_version_id: null,
    epoch: 2, kind: "file" };
  const plaintext = random(700 * 1024);
  const encrypted = Buffer.from(await file.encryptFile({ cek, metadata,
    name: "private-report.txt", mediaType: "application/octet-stream", data: plaintext }));
  const orderedFrames = frames(encrypted, 160 * 1024);
  const pinnedRoot = Buffer.from(await root.computeCiphertextRoot(
    orderedFrames.map((r) => r.bytes)));
  return { cek, metadata, plaintext, orderedFrames, pinnedRoot };
}

test("client verifies ordered ciphertext root before decrypting protected filename and bytes", async () => {
  const f = await fixture();
  const result = await download.inspectCiphertextDownload({
    frames: f.orderedFrames, expectedChunkCount: f.orderedFrames.length,
    expectedRoot: f.pinnedRoot, maxCiphertextBytes: 4 * 1024 * 1024,
  });
  assert.equal(result.integrityMatchesProvidedRoot, true);
  assert.equal(result.authorizesRelease, false);
  assert.equal(result.liveDeviceVerified, false);
  assert.equal(result.trustedRootProvenanceVerified, false);
  assert.deepEqual(Buffer.from(result.ciphertext),
    Buffer.concat(f.orderedFrames.map((r) => r.bytes)));
  // The returned view is intentionally *not* the verifier's internal copy:
  // callers can mutate public data without swapping bytes after integrity
  // inspection but before the client decrypt call.
  result.ciphertext.fill(0);
  const decoded = await download.decryptVerifiedCiphertext({
    inspection: result, cek: f.cek, metadata: f.metadata,
  });
  assert.equal(decoded.name, "private-report.txt");
  assert.deepEqual(Buffer.from(decoded.data), f.plaintext);
  assert.equal(decoded.authorizesRelease, false);
  decoded.data.fill(0);
});

test("wrong root, out-of-order, missing, duplicate and corrupted ciphertext fail closed", async () => {
  const f = await fixture();
  const inspect = (items, expectedRoot = f.pinnedRoot,
    expectedChunkCount = f.orderedFrames.length) => download.inspectCiphertextDownload({
    frames: items, expectedRoot, expectedChunkCount,
    maxCiphertextBytes: 4 * 1024 * 1024,
  });
  await assert.rejects(inspect(f.orderedFrames, random(32)), /ZK_DOWNLOAD_INTEGRITY_INVALID/);
  await assert.rejects(inspect(f.orderedFrames.slice().reverse()), /ZK_DOWNLOAD_INTEGRITY_INVALID/);
  await assert.rejects(inspect(f.orderedFrames.slice(0, -1)), /ZK_DOWNLOAD_INTEGRITY_INVALID/);
  await assert.rejects(inspect([f.orderedFrames[0], f.orderedFrames[0],
    ...f.orderedFrames.slice(2)]), /ZK_DOWNLOAD_INTEGRITY_INVALID/);
  const tampered = f.orderedFrames.map((frame) => ({
    index: frame.index, bytes: Buffer.from(frame.bytes),
  }));
  tampered[1].bytes[4] ^= 1;
  await assert.rejects(inspect(tampered), /ZK_DOWNLOAD_INTEGRITY_INVALID/);
  await assert.rejects(inspect(f.orderedFrames, f.pinnedRoot,
    f.orderedFrames.length + 1), /ZK_DOWNLOAD_INTEGRITY_INVALID/);
});

test("clones expected root and every frame before awaits; refuses changing caller-owned arrays", async () => {
  const f = await fixture();
  const immutableFrames = f.orderedFrames.map((frame) => ({
    index: frame.index, bytes: Buffer.from(frame.bytes),
  }));
  const originalRoot = Buffer.from(f.pinnedRoot);
  const pending = download.inspectCiphertextDownload({
    frames: immutableFrames, expectedChunkCount: immutableFrames.length,
    expectedRoot: f.pinnedRoot, maxCiphertextBytes: 4 * 1024 * 1024,
  });
  immutableFrames[0].bytes.fill(0);
  immutableFrames[0].index = 88;
  immutableFrames.push({ index: 100, bytes: random(10) });
  f.pinnedRoot.fill(0);
  const inspected = await pending;
  assert.equal(inspected.integrityMatchesProvidedRoot, true);
  assert.deepEqual(Buffer.from(await root.computeCiphertextRoot(
    frames(Buffer.concat(f.orderedFrames.map((r) => r.bytes)), 160 * 1024).map((r) => r.bytes))),
  originalRoot);
});

test("strict resource and shape limits reject hostile frame catalogs without allocating plaintext", async () => {
  for (const input of [
    null, {}, { frames: [], expectedChunkCount: 0, expectedRoot: random(32), maxCiphertextBytes: 128 },
    { frames: [{ index: 0, bytes: Buffer.alloc(0) }], expectedChunkCount: 1,
      expectedRoot: random(32), maxCiphertextBytes: 128 },
    { frames: [{ index: 0, bytes: random(500) }], expectedChunkCount: 1,
      expectedRoot: random(32), maxCiphertextBytes: 200 },
    { frames: [{ index: 0, bytes: random(5), leaked: "x" }], expectedChunkCount: 1,
      expectedRoot: random(32), maxCiphertextBytes: 128 },
    { frames: [{ index: 0, bytes: random(10) }], expectedChunkCount: 1,
      expectedRoot: random(31), maxCiphertextBytes: 128 },
    { frames: [{ index: 0, bytes: random(10) }], expectedChunkCount: 1,
      expectedRoot: random(32), maxCiphertextBytes: Number.MAX_SAFE_INTEGER },
    { frames: [{ index: -1, bytes: random(10) }], expectedChunkCount: 1,
      expectedRoot: random(32), maxCiphertextBytes: 128 },
  ]) {
    await assert.rejects(download.inspectCiphertextDownload(input),
      /ZK_DOWNLOAD_INTEGRITY_INVALID/);
  }
  const f = await fixture();
  const verified = await download.inspectCiphertextDownload({
    frames: f.orderedFrames, expectedChunkCount: f.orderedFrames.length,
    expectedRoot: f.pinnedRoot, maxCiphertextBytes: 4 * 1024 * 1024,
  });
  await assert.rejects(download.decryptVerifiedCiphertext({
    inspection: { ...verified, integrityMatchesProvidedRoot: false },
    cek: f.cek, metadata: f.metadata,
  }), /ZK_DOWNLOAD_INTEGRITY_INVALID/);
  const forged = Object.freeze({ ...verified, integrityMatchesProvidedRoot: true });
  await assert.rejects(download.decryptVerifiedCiphertext({
    inspection: forged, cek: f.cek, metadata: f.metadata,
  }), /ZK_DOWNLOAD_INTEGRITY_INVALID/,
  "a boolean integrity claim without a verifier-issued object cannot decrypt");
  await assert.rejects(download.decryptVerifiedCiphertext({
    inspection: verified, cek: f.cek,
    metadata: { ...f.metadata, compartment_id: id() },
  }), /ZK_FILE_INVALID/,
  "client-only AES-GCM AAD must reject cross-compartment replay");
});

test("browser global exposes no Node/Buffer requirement or server-controlled decrypt path", async () => {
  const context = { crypto: crypto.webcrypto, TextEncoder, TextDecoder,
    atob, btoa, Uint8Array, ArrayBuffer, DataView };
  context.window = context;
  for (const filename of ["rootark-zk1-file-content.js",
    "rootark-zk1-ciphertext-chunk-root.js", "rootark-zk1-ciphertext-download-integrity.js"]) {
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../public/client", filename), "utf8"),
      context, { timeout: 1000 });
  }
  const direct = context.RootarkZk1CiphertextDownloadIntegrity;
  assert.equal(typeof direct.inspectCiphertextDownload, "function");
  assert.equal(typeof direct.decryptVerifiedCiphertext, "function");
  assert.equal(context.Buffer, undefined);
  assert.equal(context.require, undefined);
  const chunks = [random(55), random(188)];
  const rootHash = await context.RootarkZk1CiphertextRoot.computeCiphertextRoot(chunks);
  const result = await direct.inspectCiphertextDownload({
    frames: chunks.map((bytes, index) => ({ index, bytes })),
    expectedChunkCount: chunks.length, expectedRoot: rootHash, maxCiphertextBytes: 4096,
  });
  assert.equal(result.authorizesRelease, false);
});
