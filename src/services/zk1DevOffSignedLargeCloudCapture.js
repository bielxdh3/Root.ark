"use strict";

// DEV-OFF / NONAUTHORIZING: a local, cryptographically authenticated captured
// ciphertext preimage. NO cloud credentials, PUT, provider readback or usable
// media stream is exposed. A supplied public key is NOT an independently
// established trust anchor; local replay detection is NOT a durable witness.
const crypto = require("node:crypto");
// The node:crypto export object is shared and mutable. Capture primitives at
// module initialization: a post-require monkeypatch must not turn a forged
// signature/digest into a verified signed ciphertext preimage.
const NATIVE_VERIFY = crypto.verify;
const NATIVE_CREATE_HASH = crypto.createHash;
const NATIVE_RANDOM_BYTES = crypto.randomBytes;
const NATIVE_CREATE_CIPHER = crypto.createCipheriv;
const NATIVE_CREATE_DECIPHER = crypto.createDecipheriv;
const NATIVE_TIMING_SAFE_EQUAL = crypto.timingSafeEqual;
const NATIVE_KEY_OBJECT = crypto.KeyObject;
const fs = require("node:fs");
const path = require("node:path");
const { createZk1PrivateCloudStagingDirectory } =
  require("./zk1PrivateCloudStagingDirectory");
const { checkWindowsPrivateCloudDirectory } = require("./zk1WindowsPrivateCloudAcl");

const DOMAIN = Buffer.from("Root.ark/zk-1/dev-off-signed-large-capture/v1\0");
const FORMAT = "rootark-zk1-dev-off-signed-large-capture/v1";
const FIELDS = Object.freeze(["format", "account_id", "object_id", "revision", "epoch",
  "operation_id", "ciphertext_sha256", "byte_length", "owner_head_revision",
  "owner_head_digest", "owner_head_epoch", "provider", "namespace_sha256",
  "principal_context_sha256", "provider_object_key", "provider_file_id",
  "issued_at", "expires_at"]);
const EXPECTED = Object.freeze(FIELDS.filter((key) =>
  !["format", "ciphertext_sha256", "byte_length", "issued_at", "expires_at"].includes(key)));
const HEX32 = /^[a-f0-9]{32}$/;
const HEX64 = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z0-9_-]{1,256}$/;
const CHUNK = 64 * 1024;
const MAX_PENDING = 4096;
const consumed = new Set(); // process-local only, never a replay authorization.

function fail() { throw new Error("ZK_DEV_OFF_CAPTURE_UNAVAILABLE"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((key) => !Object.hasOwn(value, key))) fail();
  const result = Object.create(null);
  for (const key of fields) {
    const desc = Object.getOwnPropertyDescriptor(value, key);
    if (!desc || !Object.hasOwn(desc, "value")) fail();
    result[key] = desc.value;
  }
  return result;
}
function positive(value, min = 1) {
  if (!Number.isSafeInteger(value) || value < min) fail();
}
function validate(input) {
  const signed = exact(input.signedClaim, [...FIELDS, "signature"]);
  const expected = exact(input.expected, EXPECTED);
  if (signed.format !== FORMAT || signed.provider !== "gdrive"
    || !HEX32.test(signed.account_id) || !HEX32.test(signed.object_id)
    || !HEX32.test(signed.operation_id)
    || !HEX64.test(signed.ciphertext_sha256)
    || !HEX64.test(signed.owner_head_digest)
    || !HEX64.test(signed.namespace_sha256)
    || !HEX64.test(signed.principal_context_sha256)
    || !ID.test(signed.provider_file_id)
    || typeof signed.provider_object_key !== "string"
    || signed.provider_object_key.length < 1
    || signed.provider_object_key.length > 2048
    || signed.provider_object_key.includes("\\")
    || signed.provider_object_key.split("/").some((part) =>
      !part || part === "." || part === "..")
    || EXPECTED.some((field) => signed[field] !== expected[field])) fail();
  for (const name of ["revision", "epoch", "owner_head_revision",
    "owner_head_epoch", "byte_length", "issued_at", "expires_at"]) {
    positive(signed[name], name === "epoch" || name === "owner_head_epoch" ? 0 : 1);
  }
  // Room for the 16-byte GCM tag and exact positional file arithmetic.
  if (signed.byte_length > Number.MAX_SAFE_INTEGER - 16) fail();
  if (signed.epoch > signed.owner_head_epoch
    || signed.expires_at <= signed.issued_at || signed.expires_at - signed.issued_at > 60) fail();
  const now = Math.floor(Date.now() / 1000);
  if (signed.issued_at > now + 2 || signed.expires_at < now) fail();
  if (!(input.pinnedOwnerPublicKey instanceof NATIVE_KEY_OBJECT)
    || input.pinnedOwnerPublicKey.type !== "public"
    || input.pinnedOwnerPublicKey.asymmetricKeyType !== "ed25519"
    || typeof signed.signature !== "string"
    || signed.signature.length !== 86
    || !/^[A-Za-z0-9_-]+$/.test(signed.signature)) fail();
  const signature = Buffer.from(signed.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== signed.signature) fail();
  const canonical = Object.fromEntries(FIELDS.map((name) => [name, signed[name]]));
  if (!NATIVE_VERIFY(null, Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(canonical))]),
    input.pinnedOwnerPublicKey, signature)) fail();
  return signed;
}
function sameSource(left, right) {
  return left.isFile() && right.isFile() && !left.isSymbolicLink()
    && !right.isSymbolicLink() && left.nlink === 1n && right.nlink === 1n
    && left.dev === right.dev && left.ino === right.ino
    && left.size === right.size && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}
function privateStage(stage) {
  const st = fs.lstatSync(stage, { bigint: true });
  if (!st.isDirectory() || st.isSymbolicLink()) fail();
  if (process.platform !== "win32"
    && (st.uid !== BigInt(process.getuid()) || (st.mode & 0o077n) !== 0n)) fail();
  return st;
}
function sameStage(stage, pinned) {
  const current = privateStage(stage);
  if (current.dev !== pinned.dev || current.ino !== pinned.ino) fail();
}
function writeAll(fd, data, length, position) {
  let done = 0;
  while (done < length) {
    const n = fs.writeSync(fd, data, done, length - done, position + done);
    if (n <= 0) fail();
    done += n;
  }
}

async function verifyDevOffSignedLargeCapture(input = {}) {
  let sourceFd;
  let stagedFd;
  let stageDir;
  let encryptedPath;
  let key;
  let buffer;
  // A malicious object getter must not switch the signed request or key
  // across async staging waits.
  const request = exact(input, ["sourcePath", "signedClaim",
    "pinnedOwnerPublicKey", "expected"]);
  const pendingKey = (() => {
    try {
      const claim = validate(request);
      // A local duplicate fence only: restarting the process resets this.
      return { claim, replay: `${claim.account_id}:${claim.operation_id}` };
    } catch { fail(); }
  })();
  const { claim, replay } = pendingKey;
  if (consumed.has(replay) || consumed.size >= MAX_PENDING) fail();
  // Concurrent same-operation invocations also fail closed. A locally failed
  // attempt must not be retried with an unverified fresh commitment.
  consumed.add(replay);
  try {
    if (typeof request.sourcePath !== "string" || !path.isAbsolute(request.sourcePath)) fail();
    const named = fs.lstatSync(request.sourcePath, { bigint: true });
    if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1n
      || named.size !== BigInt(claim.byte_length)) fail();
    sourceFd = fs.openSync(request.sourcePath, fs.constants.O_RDONLY
      | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0));
    const opened = fs.fstatSync(sourceFd, { bigint: true });
    if (!sameSource(opened, named)
      || !sameSource(opened, fs.lstatSync(request.sourcePath, { bigint: true }))) fail();

    stageDir = await createZk1PrivateCloudStagingDirectory("rootark-zk1-dev-capture-");
    if (process.platform === "win32") {
      await checkWindowsPrivateCloudDirectory(stageDir, "verify");
    }
    const stageIdentity = privateStage(stageDir);
    encryptedPath = path.join(stageDir, "sealed.enc");
    stagedFd = fs.openSync(encryptedPath, fs.constants.O_CREAT | fs.constants.O_EXCL
      | fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0), 0o600);
    const sealedIdentity = fs.fstatSync(stagedFd, { bigint: true });
    if (!sealedIdentity.isFile() || sealedIdentity.nlink !== 1n
      || sealedIdentity.size !== 0n) fail();

    key = NATIVE_RANDOM_BYTES(32);
    const iv = NATIVE_RANDOM_BYTES(12); // ephemeral; never persisted with the key.
    const cipher = NATIVE_CREATE_CIPHER("aes-256-gcm", key, iv);
    const expectedHash = claim.ciphertext_sha256;
    const hash = NATIVE_CREATE_HASH("sha256");
    buffer = Buffer.alloc(CHUNK);
    let offset = 0;
    while (offset < claim.byte_length) {
      const length = Math.min(CHUNK, claim.byte_length - offset);
      const n = fs.readSync(sourceFd, buffer, 0, length, offset);
      if (n <= 0 || n > length) fail();
      hash.update(buffer.subarray(0, n));
      const sealed = cipher.update(buffer.subarray(0, n));
      writeAll(stagedFd, sealed, sealed.length, offset);
      offset += n;
    }
    const tail = cipher.final();
    if (tail.length) writeAll(stagedFd, tail, tail.length, offset);
    const tag = cipher.getAuthTag();
    writeAll(stagedFd, tag, tag.length, offset + tail.length);
    const digest = hash.digest("hex");
    if (offset !== claim.byte_length || digest !== expectedHash) fail();
    if (!sameSource(opened, fs.fstatSync(sourceFd, { bigint: true }))
      || !sameSource(opened, fs.lstatSync(request.sourcePath, { bigint: true }))) fail();
    sameStage(stageDir, stageIdentity);
    fs.fsyncSync(stagedFd);
    fs.closeSync(sourceFd);
    sourceFd = undefined;
    const finalStageStat = fs.fstatSync(stagedFd, { bigint: true });
    const stagedName = fs.lstatSync(encryptedPath, { bigint: true });
    if (finalStageStat.size !== BigInt(claim.byte_length + 16)
      || stagedName.ino !== sealedIdentity.ino || stagedName.dev !== sealedIdentity.dev
      || stagedName.nlink !== 1n || stagedName.isSymbolicLink()) fail();

    // Read back the privately encrypted version and verify *all* its bytes
    // without exposing a reusable plaintext media stream or provider I/O.
    const diskTag = Buffer.alloc(16);
    if (fs.readSync(stagedFd, diskTag, 0, 16, claim.byte_length) !== 16
      || !NATIVE_TIMING_SAFE_EQUAL(diskTag, tag)) fail();
    const decipher = NATIVE_CREATE_DECIPHER("aes-256-gcm", key, iv);
    decipher.setAuthTag(diskTag);
    const reread = NATIVE_CREATE_HASH("sha256");
    let at = 0;
    while (at < claim.byte_length) {
      const count = Math.min(CHUNK, claim.byte_length - at);
      const n = fs.readSync(stagedFd, buffer, 0, count, at);
      if (n !== count) fail();
      const plaintext = decipher.update(buffer.subarray(0, n));
      reread.update(plaintext);
      plaintext.fill(0);
      at += n;
    }
    const finished = decipher.final();
    if (finished.length) { reread.update(finished); finished.fill(0); }
    if (reread.digest("hex") !== expectedHash) fail();
    sameStage(stageDir, stageIdentity);
    const afterStage = fs.fstatSync(stagedFd, { bigint: true });
    if (afterStage.dev !== sealedIdentity.dev || afterStage.ino !== sealedIdentity.ino
      || afterStage.size !== finalStageStat.size
      || afterStage.mtimeNs !== finalStageStat.mtimeNs
      || afterStage.ctimeNs !== finalStageStat.ctimeNs) fail();
    return Object.freeze({
      status: "DEV_OFF_SIGNED_PREIMAGE_CAPTURE_MATCHED_NONAUTHORITATIVE",
      sha256: digest, byteLength: offset, ioChunkBytes: CHUNK,
      signedPreimageMatched: true, encryptedSpoolRereadMatched: true,
      externalOwnerCustodyVerified: false, durableReplayFenceVerified: false,
      providerVersionedReadbackVerified: false, authorizesCloudUpload: false,
      authorizesProductionCutover: false,
    });
  } catch { fail(); }
  finally {
    if (buffer) buffer.fill(0);
    if (key) key.fill(0);
    if (sourceFd !== undefined) { try { fs.closeSync(sourceFd); } catch {} }
    if (stagedFd !== undefined) { try { fs.closeSync(stagedFd); } catch {} }
    if (stageDir) {
      // Never swallow cleanup failures as a positive result.
      try { fs.rmSync(stageDir, { recursive: true, force: true, maxRetries: 2 }); }
      catch { fail(); }
    }
  }
}

module.exports = { verifyDevOffSignedLargeCapture };
