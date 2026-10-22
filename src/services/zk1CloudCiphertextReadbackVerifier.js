"use strict";

// Read-only *current-byte* evidence against an existing exact signed PG
// operation. The reader must be provisioned with separately pinned cloud
// identity. No upload/delete, client content authorization, GET release or
// assertion that the provider cannot roll its bytes back after this check.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");
const { computeZk1CiphertextRoot } = require("../crypto/rootark-zk-chunk-root-v1");

const DOMAIN = Buffer.from("Root.ark/zk-1/cloud-physical-copy/v1\0");
const MAX_BYTES = 16 * 1024 * 1024;
const CONTEXT = /^[a-f0-9]{64}$/;

function fail() {
  const error = new Error("ZK_CLOUD_READBACK_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function strict(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
  const copy = Object.create(null);
  for (const field of fields) {
    const d = Object.getOwnPropertyDescriptor(value, field);
    if (!d || !Object.hasOwn(d, "value")) fail();
    copy[field] = d.value;
  }
  return copy;
}
function bytes(input, length) {
  if ((!Buffer.isBuffer(input) && !(input instanceof Uint8Array))
    || input.byteLength !== length
    || (typeof SharedArrayBuffer !== "undefined" && input.buffer instanceof SharedArrayBuffer)) fail();
  return Buffer.from(input);
}
function equal(left, right) {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
async function boundedIdentityRead(action) {
  let timeout;
  try {
    return await Promise.race([
      Promise.resolve().then(action),
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error("ZK_CLOUD_READBACK_UNAVAILABLE")), 15000);
      }),
    ]);
  } finally { clearTimeout(timeout); }
}
function location(scope, operationId) {
  const partLength = Buffer.alloc(2);
  partLength.writeUInt16BE(scope.compartment_id.length);
  const digest = crypto.createHash("sha256").update(DOMAIN)
    .update(scope.account_id).update(partLength)
    .update(scope.compartment_id).update(scope.keyring_id).digest("hex");
  return { folder: `zk1-${digest}`, name: `${operationId.toString("base64url")}.ct` };
}
function zk1CloudCopyAddress(input) {
  const v = strict(input, ["scope", "operationId"]);
  const address = location(inventory.normalizeScope(v.scope), bytes(v.operationId, 16));
  return Object.freeze(address);
}

class Zk1CloudCiphertextReadbackVerifier {
  #reader;
  #expectedProvider;
  #expectedContext;
  constructor({ cloudReader, expectedProvider, expectedReaderContext } = {}) {
    if (!cloudReader || typeof cloudReader !== "object"
      || !["s3", "gdrive"].includes(expectedProvider)
      || !CONTEXT.test(expectedReaderContext)
      || !["status", "enabled", "resolveInventoryContext", "key", "download"]
        .every((method) => typeof cloudReader[method] === "function")
      || cloudReader.status()?.provider !== expectedProvider
      || cloudReader.enabled() !== true) fail();
    this.#reader = cloudReader;
    this.#expectedProvider = expectedProvider;
    this.#expectedContext = expectedReaderContext;
  }

  async verifyExact(input) {
    let dir;
    try {
      const v = strict(input, ["scope", "operationId", "ciphertextSha256",
        "expectedRootHash", "chunkLengths"]);
      const scope = inventory.normalizeScope(v.scope);
      const operationId = bytes(v.operationId, 16);
      const expectedSha = bytes(v.ciphertextSha256, 32);
      const expectedRoot = bytes(v.expectedRootHash, 32);
      const lengths = v.chunkLengths;
      if (!Array.isArray(lengths) || lengths.length < 1 || lengths.length > 16
        || Reflect.ownKeys(lengths).length !== lengths.length + 1) fail();
      let total = 0;
      const frozenLengths = [];
      for (const length of lengths) {
        if (!Number.isSafeInteger(length) || length < 1 || length > 4 * 1024 * 1024
          || length > MAX_BYTES - total) fail();
        total += length;
        frozenLengths.push(length);
      }
      const { folder, name } = location(scope, operationId);
      const expectedKey = this.#reader.key(folder, name, "uploads");
      if (typeof expectedKey !== "string" || !expectedKey.endsWith(`/uploads/${folder}/${name}`)) fail();
      const before = await boundedIdentityRead(() => this.#reader.resolveInventoryContext());
      if (before !== this.#expectedContext) fail();
      dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-cloud-readback-"));
      const destination = path.join(dir, "ciphertext.ct");
      const downloaded = await this.#reader.download(folder, name, destination, "uploads",
        () => true, { maxBytes: total });
      if (downloaded !== true) fail();
      const identity = await boundedIdentityRead(() => this.#reader.resolveInventoryContext());
      if (identity !== this.#expectedContext) fail();
      // Node's ordinary numeric inode/file IDs can round adjacent 64-bit
      // Windows identities to the same Number. Keep every comparison bigint.
      const stat = fs.lstatSync(destination, { bigint: true });
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n
        || stat.size !== BigInt(total)) fail();
      const fd = fs.openSync(destination,
        fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0));
      let contents;
      try {
        const opened = fs.fstatSync(fd, { bigint: true });
        if (!opened.isFile() || opened.size !== BigInt(total) || opened.nlink !== 1n
          || opened.dev !== stat.dev || opened.ino !== stat.ino) fail();
        contents = fs.readFileSync(fd);
        const after = fs.fstatSync(fd, { bigint: true });
        const named = fs.lstatSync(destination, { bigint: true });
        if (contents.length !== total || after.size !== opened.size
          || after.mtimeNs !== opened.mtimeNs || after.ino !== opened.ino
          || after.dev !== opened.dev || after.nlink !== 1n
          || named.ino !== opened.ino || named.dev !== opened.dev
          || named.nlink !== 1n || named.isSymbolicLink()) fail();
      } finally { fs.closeSync(fd); }
      const chunks = [];
      let offset = 0;
      for (const length of frozenLengths) {
        chunks.push(contents.subarray(offset, offset + length));
        offset += length;
      }
      if (!equal(crypto.createHash("sha256").update(contents).digest(), expectedSha)
        || !equal(computeZk1CiphertextRoot(chunks), expectedRoot)) fail();
      return Object.freeze({ status: "EXTERNAL_CIPHERTEXT_REREAD_MATCHED",
        provider: this.#expectedProvider, readbackMatched: true,
        byteLength: total, operationId: Buffer.from(operationId),
        authorizesIo: false, externalProviderDurabilityProven: false,
        independentlyAnchoredFloorProven: false });
    } catch (_) { fail(); }
    finally {
      if (dir) {
        try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }); }
        catch (_) { fail(); }
      }
    }
  }
}

module.exports = { Zk1CloudCiphertextReadbackVerifier, zk1CloudCopyAddress };
