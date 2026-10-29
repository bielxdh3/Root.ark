"use strict";

// Read-only *current-byte* evidence against an existing exact signed PG
// operation. The reader must be provisioned with separately pinned cloud
// identity. No upload/delete, client content authorization, GET release or
// assertion that the provider cannot roll its bytes back after this check.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createZk1PrivateCloudStagingDirectory } = require("./zk1PrivateCloudStagingDirectory");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");
const { computeZk1CiphertextRoot } = require("../crypto/rootark-zk-chunk-root-v1");

const DOMAIN = Buffer.from("Root.ark/zk-1/cloud-physical-copy/v1\0");
const MAX_BYTES = 16 * 1024 * 1024;
const CONTEXT = /^[a-f0-9]{64}$/;
const S3_VERSION = /^[A-Za-z0-9_.+\-=/]{1,1024}$/;
const WEBDAV_ETAG = /^"[A-Za-z0-9_.:-]{1,128}"$/;

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
  #driveId;
  #s3Version;
  #webdavEtag;
  #namespace;
  constructor({ cloudReader, expectedProvider, expectedReaderContext,
    pinnedDriveFileId = null, pinnedS3VersionId = null,
    pinnedWebdavEtag = null } = {}) {
    if (!cloudReader || typeof cloudReader !== "object"
      || !["s3", "gdrive", "webdav"].includes(expectedProvider)
      || !CONTEXT.test(expectedReaderContext)
      || !["status", "enabled", "resolveInventoryContext", "key", "download"]
        .every((method) => typeof cloudReader[method] === "function")
      || cloudReader.status()?.provider !== expectedProvider
      || cloudReader.enabled() !== true
      || (["s3", "webdav"].includes(expectedProvider) && pinnedDriveFileId !== null)
      || (pinnedS3VersionId !== null && (expectedProvider !== "s3"
        || pinnedS3VersionId === "null" || !S3_VERSION.test(pinnedS3VersionId)))
      || (pinnedWebdavEtag !== null && (expectedProvider !== "webdav"
        || !WEBDAV_ETAG.test(pinnedWebdavEtag)))
      || (expectedProvider === "gdrive" &&
        (typeof pinnedDriveFileId !== "string"
          || !/^[A-Za-z0-9_-]{1,256}$/.test(pinnedDriveFileId)))) fail();
    this.#reader = cloudReader;
    this.#expectedProvider = expectedProvider;
    this.#expectedContext = expectedReaderContext;
    this.#driveId = pinnedDriveFileId;
    this.#s3Version = pinnedS3VersionId;
    this.#webdavEtag = pinnedWebdavEtag;
    this.#namespace = typeof cloudReader.zk1StorageNamespace === "function"
      ? cloudReader.zk1StorageNamespace() : null;
    if (this.#namespace !== null && !/^[a-f0-9]{64}$/.test(this.#namespace)) fail();
  }

  get pinnedCopyTarget() {
    return Object.freeze({ provider: this.#expectedProvider, driveFileId: this.#driveId,
      namespaceIdentity: this.#namespace, providerVersionId: this.#s3Version,
      providerEtag: this.#webdavEtag });
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
      // Every bounded Windows provider GET now requires a private root:
      // S3/Drive stage through a nested disposable directory, while WebDAV
      // performs an exclusive create at the selected target pathname.
      dir = process.platform === "win32"
        ? await createZk1PrivateCloudStagingDirectory("rootark-zk1-cloud-readback-")
        : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-cloud-readback-"));
      const destination = path.join(dir, "ciphertext.ct");
      const downloaded = await this.#reader.download(folder, name, destination, "uploads",
        () => true, { maxBytes: total,
          ...(this.#s3Version === null ? {} : { providerVersionId: this.#s3Version }),
          ...(this.#webdavEtag === null ? {} : { expectedEtag: this.#webdavEtag }),
          ...(this.#expectedProvider === "webdav"
            ? { expectedSha256: expectedSha.toString("hex") } : {}),
          ...(this.#driveId === null ? {} : { providerFileId: this.#driveId }) });
      if (downloaded !== true) fail();
      const identity = await boundedIdentityRead(() => this.#reader.resolveInventoryContext());
      if (identity !== this.#expectedContext) fail();
      // Node's ordinary numeric inode/file IDs can round adjacent 64-bit
      // Windows identities to the same Number. Keep every comparison bigint.
      const fd = fs.openSync(destination,
        fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)
        | (fs.constants.O_CLOEXEC || 0) | (fs.constants.O_NONBLOCK || 0));
      let contents;
      try {
        const opened = fs.fstatSync(fd, { bigint: true });
        const stat = fs.lstatSync(destination, { bigint: true });
        if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n
          || stat.size !== BigInt(total)) fail();
        if (!opened.isFile() || opened.size !== BigInt(total) || opened.nlink !== 1n
          || opened.dev !== stat.dev || opened.ino !== stat.ino) fail();
        // A size/identity check does not constrain readFileSync(fd): another
        // writer can extend the inode between fstat and the read, causing an
        // unbounded allocation before the post-read check rejects it. Never
        // read more than the previously pinned ciphertext byte budget.
        contents = Buffer.alloc(total);
        let offset = 0;
        while (offset < total) {
          const count = fs.readSync(fd, contents, offset,
            Math.min(64 * 1024, total - offset), offset);
          if (count <= 0 || count > total - offset) fail();
          offset += count;
        }
        const after = fs.fstatSync(fd, { bigint: true });
        const named = fs.lstatSync(destination, { bigint: true });
        if (contents.length !== total || after.size !== opened.size
          || after.mtimeNs !== opened.mtimeNs || after.ino !== opened.ino
          || after.dev !== opened.dev || after.nlink !== 1n
          || named.ino !== opened.ino || named.dev !== opened.dev
          || named.nlink !== 1n || named.isSymbolicLink()
          || named.size !== opened.size
          || named.mtimeNs !== opened.mtimeNs) fail();
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
        providerFileId: this.#driveId,
        providerVersionId: this.#s3Version,
        providerEtag: this.#webdavEtag,
        providerObjectKey: expectedKey, readbackSha256: Buffer.from(expectedSha),
        namespaceIdentity: this.#namespace,
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
