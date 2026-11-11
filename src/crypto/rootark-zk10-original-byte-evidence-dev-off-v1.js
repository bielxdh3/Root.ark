"use strict";

// Issue #65 standalone DEV-OFF cryptographic evidence experiment.
// A test-supplied signed floor readback CANNOT prove off-host possession,
// independent monotonic retention, the complete historic corpus, or R1.
// Neither this gate nor its tickets authorize staging, provider writes or I/O.
// No HTTP route or production service imports this file.
const crypto = require("node:crypto");
const { types: { isProxy } } = require("node:util");
// Pin byte constructors before any caller-supplied KeyObject/nonce-readback
// callback can retarget Buffer.from/concat. Both native signature-message
// assembly and original-byte snapshots must use these immutable references.
const BUFFER_FROM = Buffer.from.bind(Buffer);
const BUFFER_CONCAT = Buffer.concat.bind(Buffer);
const NATIVE_UINT8ARRAY = Uint8Array;

const OWNER_DOMAIN = Buffer.from("Root.ark/zk10/owner-original-byte-evidence/v1\0");
const FLOOR_DOMAIN = Buffer.from("Root.ark/zk10/original-byte-floor-readback/v1\0");
const OWNER_FIELDS = Object.freeze([
  "type", "immutable_account_id", "object_id", "version_id",
  "key_epoch", "original_sha256", "original_length", "nonce",
  "floor_sequence", "floor_digest", "issued_at_ms", "expires_at_ms",
]);
const FLOOR_FIELDS = Object.freeze([
  "type", "immutable_account_id", "owner_spki_sha256",
  "sequence", "head_digest", "nonce", "revoked", "issued_at_ms", "expires_at_ms",
]);
const CONFIG_FIELDS = Object.freeze([
  "devOff", "pinnedOwnerPublicKey", "pinnedOwnerSpkiSha256",
  "pinnedFloorPublicKey", "pinnedFloorSpkiSha256",
  "independentlyRetainedMinimum", "readSignedCurrentFloor",
]);
const EXPECTED_FIELDS = Object.freeze([
  "immutable_account_id", "object_id", "version_id", "key_epoch",
]);
const MINIMUM_FIELDS = Object.freeze(["sequence", "headDigest"]);
const HEX64 = /^[a-f0-9]{64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const MAX_ORIGINAL_BYTES = 1024 * 1024 * 1024; // bounded experiment, not legacy unlimited upload
const MAX_CHUNK_BYTES = 16 * 1024 * 1024;
const MAX_CHUNKS = 65536;
const MAX_NONCES = 8192; // fail on capacity rather than forgetting replay evidence
const TTL_MS = 60000;
const FLOOR_TTL_MS = 10000;
const NOW = Date.now.bind(Date);
const VERIFY = crypto.verify.bind(crypto);
const HASH = crypto.createHash.bind(crypto);
const HASH_PROTOTYPE = Object.getPrototypeOf(HASH("sha256"));
const HASH_UPDATE = Object.getOwnPropertyDescriptor(HASH_PROTOTYPE, "update").value;
const HASH_DIGEST = Object.getOwnPropertyDescriptor(HASH_PROTOTYPE, "digest").value;
const TIMING_SAFE_EQUAL = crypto.timingSafeEqual.bind(crypto);
const JSON_STRINGIFY_PRIMITIVE = JSON.stringify.bind(JSON);
const RANDOM = crypto.randomBytes.bind(crypto);
const CREATE_PUBLIC = crypto.createPublicKey.bind(crypto);
const KEY_EQUALS = crypto.KeyObject.prototype.equals;
// Capture the native PublicKeyObject export method from a locally created
// disposable Ed25519 public key, never from a caller-controlled KeyObject.
// The 32 zero bytes here are only a fixed prototype-discovery fixture; they
// are not a trusted identity, signer, custodian, or accepted pin.
const PUBLIC_KEY_FIXTURE = CREATE_PUBLIC({
  key: Buffer.from("302a300506032b6570032100" + "00".repeat(32), "hex"),
  format: "der", type: "spki",
});
const PUBLIC_KEY_PROTOTYPE = Object.getPrototypeOf(PUBLIC_KEY_FIXTURE);
const KEY_HANDLE_SYMBOL = Object.getOwnPropertySymbols(PUBLIC_KEY_FIXTURE)
  .find((symbol) => symbol.description === "kHandle");
const KEY_TYPE_SYMBOL = Object.getOwnPropertySymbols(PUBLIC_KEY_FIXTURE)
  .find((symbol) => symbol.description === "kKeyType");
const NATIVE_HANDLE_PROTOTYPE = Object.getPrototypeOf(PUBLIC_KEY_FIXTURE[KEY_HANDLE_SYMBOL]);
const NATIVE_HANDLE_ALGORITHM = Object.getOwnPropertyDescriptor(
  NATIVE_HANDLE_PROTOTYPE, "getAsymmetricKeyType").value;
const NATIVE_HANDLE_EXPORT = Object.getOwnPropertyDescriptor(
  NATIVE_HANDLE_PROTOTYPE, "export").value;
const KEY_EXPORT = Object.getOwnPropertyDescriptor(PUBLIC_KEY_PROTOTYPE, "export").value;
const KEY_TYPE = Object.getOwnPropertyDescriptor(crypto.KeyObject.prototype, "type").get;
const KEY_ASYMMETRIC_TYPE = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(PUBLIC_KEY_PROTOTYPE), "asymmetricKeyType").get;
const VIEW_INTRINSICS = Object.getPrototypeOf(Uint8Array.prototype);
const VIEW_BUFFER = Object.getOwnPropertyDescriptor(VIEW_INTRINSICS, "buffer").get;
const VIEW_OFFSET = Object.getOwnPropertyDescriptor(VIEW_INTRINSICS, "byteOffset").get;
const VIEW_LENGTH = Object.getOwnPropertyDescriptor(VIEW_INTRINSICS, "byteLength").get;
const AB_LENGTH = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;

function deny() {
  const error = new Error("ZK10_ORIGINAL_BYTE_EVIDENCE_UNVERIFIED");
  error.code = error.message;
  throw error;
}
function exact(value, fields) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length) deny();
  const copy = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
    copy[field] = descriptor.value;
  }
  return copy;
}
function bytes(value, count) {
  if (typeof value !== "string" || !B64URL.test(value)) deny();
  const decoded = BUFFER_FROM(value, "base64url");
  if (decoded.length !== count || decoded.toString("base64url") !== value) deny();
  return value;
}
function hex(value) {
  if (typeof value !== "string" || !HEX64.test(value)) deny();
  return value;
}
function integer(value, min, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) deny();
  return value;
}
function publicKey(value, pinnedSpki) {
  if (isProxy(value) || !(value instanceof crypto.KeyObject)
    || Object.getPrototypeOf(value) !== PUBLIC_KEY_PROTOTYPE) deny();
  // Never execute a caller-owned Symbol(kHandle) getter while examining a
  // supposedly native key. Native direct KeyObjects own a DATA handle;
  // inherited wrappers/accessors are not a stable security principal.
  const handle = KEY_HANDLE_SYMBOL
    && Object.getOwnPropertyDescriptor(value, KEY_HANDLE_SYMBOL);
  const typeDescriptor = KEY_TYPE_SYMBOL
    && Object.getOwnPropertyDescriptor(value, KEY_TYPE_SYMBOL);
  // A forged Object.create(nativePublicPrototype) can own a DATA kHandle
  // whose value is actually a JavaScript object, or own an accessor kKeyType.
  // The native key accessors can dispatch through those objects before any
  // caught exception, poisoning crypto/hash methods for the next verification.
  // Check BOTH own descriptors and the raw handle's genuine native brand
  // before calling a single higher-level native KeyObject accessor/export.
  if (!handle || !Object.hasOwn(handle, "value")
    || !typeDescriptor || !Object.hasOwn(typeDescriptor, "value")
    || typeDescriptor.value !== "public"
    || !handle.value || typeof handle.value !== "object"
    || isProxy(handle.value)
    || Object.getPrototypeOf(handle.value) !== NATIVE_HANDLE_PROTOTYPE
    || Object.hasOwn(handle.value, "export")
    || Object.hasOwn(handle.value, "getAsymmetricKeyType")
    || Object.getOwnPropertyDescriptor(NATIVE_HANDLE_PROTOTYPE, "export")?.value
      !== NATIVE_HANDLE_EXPORT
    || Object.getOwnPropertyDescriptor(NATIVE_HANDLE_PROTOTYPE, "getAsymmetricKeyType")?.value
      !== NATIVE_HANDLE_ALGORITHM
    || NATIVE_HANDLE_ALGORITHM.call(handle.value) !== "ed25519"
    || KEY_TYPE.call(value) !== "public"
    || KEY_ASYMMETRIC_TYPE.call(value) !== "ed25519") deny();
  try {
    // Snapshot the native key material exactly once. An inherited KeyObject
    // can change its own Symbol(kHandle) between SPKI hashing and VERIFY.
    // All later checks must use this freshly imported, independent handle.
    const der = KEY_EXPORT.call(value, { type: "spki", format: "der" });
    if (!Buffer.isBuffer(der) || der.length !== 44) deny();
    const pinned = CREATE_PUBLIC({ key: der, format: "der", type: "spki" });
    if (KEY_TYPE.call(pinned) !== "public"
      || KEY_ASYMMETRIC_TYPE.call(pinned) !== "ed25519"
      || !KEY_EXPORT.call(pinned, { type: "spki", format: "der" }).equals(der)) deny();
    const digest = HASH("sha256");
    HASH_UPDATE.call(digest, der);
    const spkiDigest = HASH_DIGEST.call(digest, "hex");
    if (spkiDigest !== hex(pinnedSpki)) deny();
    return pinned;
  } catch (_) { deny(); }
}
function normalizedOwner(raw) {
  const o = exact(raw, OWNER_FIELDS);
  if (o.type !== "rootark-zk10-owner-original-byte-evidence/v1") deny();
  bytes(o.immutable_account_id, 16);
  bytes(o.object_id, 16);
  bytes(o.version_id, 16);
  bytes(o.nonce, 32);
  integer(o.key_epoch, 1);
  hex(o.original_sha256);
  integer(o.original_length, 0, MAX_ORIGINAL_BYTES);
  integer(o.floor_sequence, 1);
  hex(o.floor_digest);
  integer(o.issued_at_ms, 1);
  integer(o.expires_at_ms, o.issued_at_ms + 1);
  if (o.expires_at_ms - o.issued_at_ms > TTL_MS) deny();
  return Object.freeze(o);
}
function normalizedFloor(raw) {
  const f = exact(raw, FLOOR_FIELDS);
  if (f.type !== "rootark-zk10-original-byte-floor-readback/v1"
    || typeof f.revoked !== "boolean") deny();
  bytes(f.immutable_account_id, 16);
  hex(f.owner_spki_sha256);
  integer(f.sequence, 1);
  hex(f.head_digest);
  bytes(f.nonce, 32);
  integer(f.issued_at_ms, 1);
  integer(f.expires_at_ms, f.issued_at_ms + 1);
  if (f.expires_at_ms - f.issued_at_ms > FLOOR_TTL_MS) deny();
  return Object.freeze(f);
}
function signedSnapshot(record, fields, normalize, domain, pinnedKey) {
  const signed = exact(record, [...fields, "signature"]);
  const body = normalize(Object.fromEntries(fields.map((field) => [field, signed[field]])));
  const signature = BUFFER_FROM(bytes(signed.signature, 64), "base64url");
  // All normalized owner/floor records are FLAT scalar schemas. Serialize
  // each own primitive in the exact signed field order. JSON.stringify(body)
  // would invoke inherited toJSON hooks after an injected CURRENT callback.
  const encoded = fields.map((field) => {
    const descriptor = Object.getOwnPropertyDescriptor(body, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")
      || (descriptor.value !== null && !["string", "boolean", "number"].includes(
        typeof descriptor.value))) deny();
    return `${JSON_STRINGIFY_PRIMITIVE(field)}:${JSON_STRINGIFY_PRIMITIVE(descriptor.value)}`;
  });
  const message = BUFFER_CONCAT([domain, BUFFER_FROM(`{${encoded.join(",")}}`, "utf8")]);
  if (!VERIFY(null, message, pinnedKey, signature)) deny();
  return body;
}
function exactExpected(value) {
  const expected = exact(value, EXPECTED_FIELDS);
  bytes(expected.immutable_account_id, 16);
  bytes(expected.object_id, 16);
  bytes(expected.version_id, 16);
  integer(expected.key_epoch, 1);
  return Object.freeze(expected);
}
function immutableBytes(part, remaining) {
  // No JS-accessed byteLength/length/buffer/byteOffset properties may redefine
  // the real range hashed. Shared backing permits mutation between copies.
  if (isProxy(part) || (!Buffer.isBuffer(part) && !(part instanceof Uint8Array))) deny();
  if (["byteLength", "byteOffset", "buffer", "length"].some((field) =>
    Object.hasOwn(part, field))) deny();
  try {
    const length = VIEW_LENGTH.call(part);
    const offset = VIEW_OFFSET.call(part);
    const backing = VIEW_BUFFER.call(part);
    const total = AB_LENGTH.call(backing); // rejects SharedArrayBuffer and detached backing
    if (!Number.isSafeInteger(length) || length > MAX_CHUNK_BYTES || length > remaining
      || !Number.isSafeInteger(offset) || offset < 0 || offset > total
      || length > total - offset) deny();
    const copied = BUFFER_FROM(new NATIVE_UINT8ARRAY(backing, offset, length));
    if (copied.length !== length) deny();
    return copied;
  } catch (_) { deny(); }
}

function createDevOffOriginalByteEvidenceGate(options) {
  try {
    const o = exact(options, CONFIG_FIELDS);
    if (o.devOff !== true || process.env.NODE_ENV === "production"
      || typeof o.readSignedCurrentFloor !== "function") deny();
    const ownerKey = publicKey(o.pinnedOwnerPublicKey, o.pinnedOwnerSpkiSha256);
    const floorKey = publicKey(o.pinnedFloorPublicKey, o.pinnedFloorSpkiSha256);
    // A second KeyObject or spoofed .export() digest is not a second custodian.
    // Compare native key material before accepting either signing role.
    if (KEY_EQUALS.call(ownerKey, floorKey)) deny();
    const retained = exact(o.independentlyRetainedMinimum, MINIMUM_FIELDS);
    integer(retained.sequence, 1);
    hex(retained.headDigest);
    const observedNonces = new Set();
    const tickets = new WeakMap();

    function currentFloor(accountId) {
      // This callback is a DEVELOPMENT TEST INJECTION, not an off-host network
      // or independently audited monotonic custodian. Require a fresh signed
      // challenge; even its success is insufficient to authorize protected I/O.
      const challenge = RANDOM(32).toString("base64url");
      const signed = o.readSignedCurrentFloor(challenge);
      const floor = signedSnapshot(signed, FLOOR_FIELDS, normalizedFloor, FLOOR_DOMAIN, floorKey);
      const now = NOW();
      if (floor.immutable_account_id !== accountId
        || floor.owner_spki_sha256 !== o.pinnedOwnerSpkiSha256
        || floor.sequence !== retained.sequence || floor.head_digest !== retained.headDigest
        || floor.nonce !== challenge || floor.revoked
        || floor.issued_at_ms > now + 1000 || floor.issued_at_ms < now - FLOOR_TTL_MS
        || floor.expires_at_ms <= now || floor.expires_at_ms > now + FLOOR_TTL_MS) deny();
    }
    function validateOwnerWindow(intent) {
      const now = NOW();
      if (intent.issued_at_ms > now + 1000 || intent.issued_at_ms < now - TTL_MS
        || intent.expires_at_ms <= now) deny();
    }
    function freshOwner(intent) {
      validateOwnerWindow(intent);
      if (intent.floor_sequence !== retained.sequence
        || intent.floor_digest !== retained.headDigest) deny();
      currentFloor(intent.immutable_account_id);
      // A valid fresh custodian readback cannot extend an owner statement
      // whose independently signed lifetime expired inside the callback.
      validateOwnerWindow(intent);
    }
    function beginBeforeBody(input) {
      try {
        const { ownerEvidence, expected } = exact(input, ["ownerEvidence", "expected"]);
        const scope = exactExpected(expected);
        const intent = signedSnapshot(ownerEvidence, OWNER_FIELDS, normalizedOwner,
          OWNER_DOMAIN, ownerKey);
        if (EXPECTED_FIELDS.some((field) => intent[field] !== scope[field])) deny();
        freshOwner(intent);
        const replayKey = intent.immutable_account_id + ":" + intent.nonce;
        if (observedNonces.has(replayKey) || observedNonces.size >= MAX_NONCES) deny();
        observedNonces.add(replayKey);
        const ticket = Object.freeze({ authorizesIo: false, stagePermitted: false,
          independentCustodyProven: false });
        tickets.set(ticket, { intent, consumed: false });
        return ticket;
      } catch (_) { deny(); }
    }
    function verifyOriginalBytes(input) {
      try {
        const { ticket, chunks } = exact(input, ["ticket", "chunks"]);
        const saved = ticket && tickets.get(ticket);
        if (!saved || saved.consumed) deny();
        saved.consumed = true; // consume before any user-supplied byte access
        const intent = saved.intent;
        freshOwner(intent);
        if (!Array.isArray(chunks) || isProxy(chunks)
          || Object.getPrototypeOf(chunks) !== Array.prototype
          || chunks.length > MAX_CHUNKS
          || Reflect.ownKeys(chunks).length !== chunks.length + 1) deny();
        const digest = HASH("sha256");
        let size = 0;
        for (let index = 0; index < chunks.length; index++) {
          const descriptor = Object.getOwnPropertyDescriptor(chunks, String(index));
          if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
          const copied = immutableBytes(descriptor.value, intent.original_length - size);
          size += copied.length;
          HASH_UPDATE.call(digest, copied);
        }
        if (size !== intent.original_length
          || !TIMING_SAFE_EQUAL(HASH_DIGEST.call(digest),
            BUFFER_FROM(intent.original_sha256, "hex"))) deny();
        freshOwner(intent); // check another nonce-signed snapshot after assembly
        return Object.freeze({
          status: "SIGNED_ORIGINAL_BYTES_NONAUTHORIZING",
          originalByteDigestVerified: true, originalLength: size,
          authorizesIo: false, stagePermitted: false,
          independentCustodyProven: false, offHostMonotonicFloorProven: false,
          historicalCorpusComplete: false,
        });
      } catch (_) { deny(); }
    }
    return Object.freeze({ beginBeforeBody, verifyOriginalBytes,
      authorizesIo: false, stagePermitted: false });
  } catch (_) { deny(); }
}

module.exports = Object.freeze({ createDevOffOriginalByteEvidenceGate });
