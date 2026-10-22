"use strict";

// Standalone operator-only, nonauthorizing remote replication of ALREADY
// physically signed opaque ciphertext. A remote PUT acknowledgement is not
// a durable external receipt or a fenced cross-provider transaction.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");
const { computeZk1CiphertextRoot } = require("../crypto/rootark-zk-chunk-root-v1");
const { zk1CloudCopyAddress } = require("./zk1CloudCiphertextReadbackVerifier");

function fail() {
  const error = new Error("ZK_CLOUD_COPY_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
  const result = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail();
    result[field] = descriptor.value;
  }
  return result;
}
function bytes(value, length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer)
    || value.byteLength !== length) fail();
  return Buffer.from(value);
}
function same(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function boundedIdentity(action) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(action),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("ZK_CLOUD_COPY_UNAVAILABLE")), 15000);
      })]);
  } finally { clearTimeout(timer); }
}
function capturedChunks(values, expectedSha, expectedRoot) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 16
    || Reflect.ownKeys(values).length !== values.length + 1) fail();
  const snapshots = [];
  let total = 0;
  for (let index = 0; index < values.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(values, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail();
    const original = descriptor.value;
    if ((!Buffer.isBuffer(original) && !(original instanceof Uint8Array))
      || (typeof SharedArrayBuffer !== "undefined" && original.buffer instanceof SharedArrayBuffer)
      || original.byteLength < 1 || original.byteLength > 1024 * 1024
      || original.byteLength > 16 * 1024 * 1024 - total) fail();
    const copy = Buffer.from(original);
    snapshots.push(copy);
    total += copy.byteLength;
  }
  const hash = crypto.createHash("sha256");
  for (const chunk of snapshots) hash.update(chunk);
  if (!same(hash.digest(), expectedSha)
    || !same(computeZk1CiphertextRoot(snapshots), expectedRoot)) fail();
  return { chunks: snapshots, size: total };
}

class Zk1CloudCiphertextCopyPublisher {
  #writer;
  #context;
  #provider;
  #driveId;
  #namespace;
  constructor({ cloudWriter, expectedProvider, expectedWriterContext,
    pinnedDriveFileId = null } = {}) {
    if (!cloudWriter || typeof cloudWriter !== "object"
      || !["s3", "gdrive", "webdav"].includes(expectedProvider)
      || typeof expectedWriterContext !== "string"
      || !/^[a-f0-9]{64}$/.test(expectedWriterContext)
      || !["status", "enabled", "resolveInventoryContext", "key", "upload"]
        .every((method) => typeof cloudWriter[method] === "function")
      || cloudWriter.enabled() !== true
      || cloudWriter.status()?.provider !== expectedProvider
      || (["s3", "webdav"].includes(expectedProvider) && pinnedDriveFileId !== null)
      || (expectedProvider === "gdrive" &&
        (typeof pinnedDriveFileId !== "string"
          || !/^[A-Za-z0-9_-]{1,256}$/.test(pinnedDriveFileId)))) fail();
    this.#writer = cloudWriter;
    this.#context = expectedWriterContext;
    this.#provider = expectedProvider;
    this.#driveId = pinnedDriveFileId;
    this.#namespace = typeof cloudWriter.zk1StorageNamespace === "function"
      ? cloudWriter.zk1StorageNamespace() : null;
    if (this.#namespace !== null && !/^[a-f0-9]{64}$/.test(this.#namespace)) fail();
  }

  get pinnedCopyTarget() {
    return Object.freeze({ provider: this.#provider, driveFileId: this.#driveId,
      namespaceIdentity: this.#namespace });
  }

  async publishExact(input) {
    let directory;
    try {
      const raw = exact(input, ["scope", "operationId", "ciphertextSha256",
        "expectedRootHash", "chunks"]);
      const scope = inventory.normalizeScope(raw.scope);
      const operationId = bytes(raw.operationId, 16);
      const sha = bytes(raw.ciphertextSha256, 32);
      const root = bytes(raw.expectedRootHash, 32);
      const payload = capturedChunks(raw.chunks, sha, root);
      const address = zk1CloudCopyAddress({ scope, operationId });
      const key = this.#writer.key(address.folder, address.name, "uploads");
      if (typeof key !== "string"
        || !key.endsWith(`/uploads/${address.folder}/${address.name}`)) fail();
      if (await boundedIdentity(() => this.#writer.resolveInventoryContext()) !== this.#context) fail();
      directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-cloud-copy-"));
      const staged = path.join(directory, "sealed-opaque-copy.ct");
      const fd = fs.openSync(staged,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
      try {
        for (const chunk of payload.chunks) {
          let cursor = 0;
          while (cursor < chunk.length) {
            const written = fs.writeSync(fd, chunk, cursor, chunk.length - cursor);
            if (written < 1) fail();
            cursor += written;
          }
        }
        fs.fsyncSync(fd);
      } finally { fs.closeSync(fd); }
      const answer = await this.#writer.upload(staged, address.folder,
        address.name, "uploads", { zk1BoundedBytes: payload.size,
          ...(this.#driveId === null ? {} : { providerFileId: this.#driveId }) });
      if (!answer || answer.provider !== this.#provider || answer.key !== key
        || (this.#driveId !== null && answer.id !== this.#driveId)) fail();
      if (await boundedIdentity(() => this.#writer.resolveInventoryContext()) !== this.#context) fail();
      return Object.freeze({ status: "CLOUD_COPY_PUT_ACK_NONAUTHORITATIVE",
        operationId: Buffer.from(operationId), provider: this.#provider,
        providerFileId: this.#driveId,
        providerObjectKey: key, ciphertextSha256: Buffer.from(sha),
        namespaceIdentity: this.#namespace,
        byteLength: payload.size, authorizesIo: false,
        providerDurabilityProven: false });
    } catch (_) { fail(); }
    finally {
      if (directory) {
        try { fs.rmSync(directory, { recursive: true, force: true, maxRetries: 3 }); }
        catch (_) { fail(); }
      }
    }
  }
}

module.exports = { Zk1CloudCiphertextCopyPublisher };
