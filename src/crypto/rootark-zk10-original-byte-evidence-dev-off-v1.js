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
// Capturing the native function is not sufficient while dispatch still looks
// up the mutable Function.prototype.call after a same-realm signed-CURRENT
// callback. Use a retained Reflect.apply function with its receiver bound
// BEFORE any hostile callback. This is DEV-OFF, not process isolation.
const SAFE_APPLY = Reflect.apply.bind(Reflect);
// An untrusted signed-CURRENT callback runs before both nonce-snapshot
// signature verification and later byte iteration. Capturing only crypto and
// Buffer factories does not stop a rebinding of JS property/array intrinsics
// from substituting a signed nonce or an original byte-array element.
const OWN_DESCRIPTOR = Object.getOwnPropertyDescriptor.bind(Object);
const HAS_OWN = Object.hasOwn.bind(Object);
const GET_PROTOTYPE = Object.getPrototypeOf.bind(Object);
const BASE_OBJECT_PROTOTYPE = Object.prototype;
const BASE_ARRAY_PROTOTYPE = Array.prototype;
const CREATE_NULL_PROTO = Object.create.bind(Object);
const FROM_ENTRIES = Object.fromEntries.bind(Object);
const FREEZE = Object.freeze.bind(Object);
const OWN_KEYS = Reflect.ownKeys.bind(Reflect);
const IS_ARRAY = Array.isArray.bind(Array);
const IS_SAFE_INTEGER = Number.isSafeInteger.bind(Number);
const ARRAY_MAP = Array.prototype.map;
const ARRAY_JOIN = Array.prototype.join;
const ARRAY_SOME = Array.prototype.some;
const BUFFER_IS_BUFFER = Buffer.isBuffer.bind(Buffer);
const BUFFER_TO_STRING = Buffer.prototype.toString;
const REGEX_TEST = RegExp.prototype.test;
const SET_HAS = Set.prototype.has;
const SET_ADD = Set.prototype.add;
const WEAK_GET = WeakMap.prototype.get;
const WEAK_SET = WeakMap.prototype.set;

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
// Signature-field order is created before any caller callback can poison the
// global Array iterator or spread semantics. signedSnapshot accepts only these
// two immutable schemas and never creates its field list from untrusted JS.
const OWNER_SIGNED_FIELDS = Object.freeze([...OWNER_FIELDS, "signature"]);
const FLOOR_SIGNED_FIELDS = Object.freeze([...FLOOR_FIELDS, "signature"]);
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
const HASH_PROTOTYPE = GET_PROTOTYPE(HASH("sha256"));
const HASH_UPDATE = OWN_DESCRIPTOR(HASH_PROTOTYPE, "update").value;
const HASH_DIGEST = OWN_DESCRIPTOR(HASH_PROTOTYPE, "digest").value;
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
const PUBLIC_KEY_PROTOTYPE = GET_PROTOTYPE(PUBLIC_KEY_FIXTURE);
const KEY_HANDLE_SYMBOL = Object.getOwnPropertySymbols(PUBLIC_KEY_FIXTURE)
  .find((symbol) => symbol.description === "kHandle");
const KEY_TYPE_SYMBOL = Object.getOwnPropertySymbols(PUBLIC_KEY_FIXTURE)
  .find((symbol) => symbol.description === "kKeyType");
const NATIVE_HANDLE_PROTOTYPE = GET_PROTOTYPE(PUBLIC_KEY_FIXTURE[KEY_HANDLE_SYMBOL]);
const NATIVE_HANDLE_ALGORITHM = OWN_DESCRIPTOR(
  NATIVE_HANDLE_PROTOTYPE, "getAsymmetricKeyType").value;
const NATIVE_HANDLE_EXPORT = OWN_DESCRIPTOR(
  NATIVE_HANDLE_PROTOTYPE, "export").value;
const KEY_EXPORT = OWN_DESCRIPTOR(PUBLIC_KEY_PROTOTYPE, "export").value;
const KEY_TYPE = OWN_DESCRIPTOR(crypto.KeyObject.prototype, "type").get;
const KEY_ASYMMETRIC_TYPE = OWN_DESCRIPTOR(
  GET_PROTOTYPE(PUBLIC_KEY_PROTOTYPE), "asymmetricKeyType").get;
const VIEW_INTRINSICS = GET_PROTOTYPE(Uint8Array.prototype);
const VIEW_BUFFER = OWN_DESCRIPTOR(VIEW_INTRINSICS, "buffer").get;
const VIEW_OFFSET = OWN_DESCRIPTOR(VIEW_INTRINSICS, "byteOffset").get;
const VIEW_LENGTH = OWN_DESCRIPTOR(VIEW_INTRINSICS, "byteLength").get;
const AB_LENGTH = OWN_DESCRIPTOR(ArrayBuffer.prototype, "byteLength").get;

function deny() {
  const error = new Error("ZK10_ORIGINAL_BYTE_EVIDENCE_UNVERIFIED");
  error.code = error.message;
  throw error;
}
function exact(value, fields) {
  const candidatePrototype = value !== null && typeof value === "object"
    ? GET_PROTOTYPE(value) : null;
  if (value === null || typeof value !== "object" || IS_ARRAY(value)
    || isProxy(value) || (candidatePrototype !== BASE_OBJECT_PROTOTYPE
      && candidatePrototype !== null)
    || OWN_KEYS(value).length !== fields.length) deny();
  const copy = CREATE_NULL_PROTO(null);
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    const descriptor = OWN_DESCRIPTOR(value, field);
    if (!descriptor || !HAS_OWN(descriptor, "value")) deny();
    copy[field] = descriptor.value;
  }
  return copy;
}
function bytes(value, count) {
  if (typeof value !== "string" || !SAFE_APPLY(REGEX_TEST, B64URL, [value])) deny();
  const decoded = BUFFER_FROM(value, "base64url");
  if (decoded.length !== count
    || SAFE_APPLY(BUFFER_TO_STRING, decoded, ["base64url"]) !== value) deny();
  return value;
}
function hex(value) {
  if (typeof value !== "string" || !SAFE_APPLY(REGEX_TEST, HEX64, [value])) deny();
  return value;
}
function integer(value, min, max = Number.MAX_SAFE_INTEGER) {
  if (!IS_SAFE_INTEGER(value) || value < min || value > max) deny();
  return value;
}
function publicKey(value, pinnedSpki) {
  if (isProxy(value) || !(value instanceof crypto.KeyObject)
    || GET_PROTOTYPE(value) !== PUBLIC_KEY_PROTOTYPE) deny();
  // Never execute a caller-owned Symbol(kHandle) getter while examining a
  // supposedly native key. Native direct KeyObjects own a DATA handle;
  // inherited wrappers/accessors are not a stable security principal.
  const handle = KEY_HANDLE_SYMBOL
    && OWN_DESCRIPTOR(value, KEY_HANDLE_SYMBOL);
  const typeDescriptor = KEY_TYPE_SYMBOL
    && OWN_DESCRIPTOR(value, KEY_TYPE_SYMBOL);
  // A forged Object.create(nativePublicPrototype) can own a DATA kHandle
  // whose value is actually a JavaScript object, or own an accessor kKeyType.
  // The native key accessors can dispatch through those objects before any
  // caught exception, poisoning crypto/hash methods for the next verification.
  // Check BOTH own descriptors and the raw handle's genuine native brand
  // before calling a single higher-level native KeyObject accessor/export.
  if (!handle || !HAS_OWN(handle, "value")
    || !typeDescriptor || !HAS_OWN(typeDescriptor, "value")
    || typeDescriptor.value !== "public"
    || !handle.value || typeof handle.value !== "object"
    || isProxy(handle.value)
    || GET_PROTOTYPE(handle.value) !== NATIVE_HANDLE_PROTOTYPE
    || HAS_OWN(handle.value, "export")
    || HAS_OWN(handle.value, "getAsymmetricKeyType")
    || OWN_DESCRIPTOR(NATIVE_HANDLE_PROTOTYPE, "export")?.value
      !== NATIVE_HANDLE_EXPORT
    || OWN_DESCRIPTOR(NATIVE_HANDLE_PROTOTYPE, "getAsymmetricKeyType")?.value
      !== NATIVE_HANDLE_ALGORITHM
    || SAFE_APPLY(NATIVE_HANDLE_ALGORITHM, handle.value, []) !== "ed25519"
    || SAFE_APPLY(KEY_TYPE, value, []) !== "public"
    || SAFE_APPLY(KEY_ASYMMETRIC_TYPE, value, []) !== "ed25519") deny();
  try {
    // Snapshot the native key material exactly once. An inherited KeyObject
    // can change its own Symbol(kHandle) between SPKI hashing and VERIFY.
    // All later checks must use this freshly imported, independent handle.
    const der = SAFE_APPLY(KEY_EXPORT, value, [{ type: "spki", format: "der" }]);
    if (!BUFFER_IS_BUFFER(der) || der.length !== 44) deny();
    const pinned = CREATE_PUBLIC({ key: der, format: "der", type: "spki" });
    if (SAFE_APPLY(KEY_TYPE, pinned, []) !== "public"
      || SAFE_APPLY(KEY_ASYMMETRIC_TYPE, pinned, []) !== "ed25519"
      || !SAFE_APPLY(KEY_EXPORT, pinned, [{ type: "spki", format: "der" }]).equals(der)) deny();
    const digest = HASH("sha256");
    SAFE_APPLY(HASH_UPDATE, digest, [der]);
    const spkiDigest = SAFE_APPLY(HASH_DIGEST, digest, ["hex"]);
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
  return FREEZE(o);
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
  return FREEZE(f);
}
function signedSnapshot(record, fields, normalize, domain, pinnedKey) {
  const signed = exact(record, fields === OWNER_FIELDS
    ? OWNER_SIGNED_FIELDS : fields === FLOOR_FIELDS ? FLOOR_SIGNED_FIELDS : []);
  // Array.prototype.map performs ArraySpeciesCreate even if its method is
  // captured. A hostile readSignedCurrentFloor callback can replace the
  // inherited Array.prototype.constructor[Symbol.species] and return a Proxy
  // which modifies only serialized field strings while retaining a different
  // in-memory signed statement. Use fixed indexed writes into a fresh
  // null-prototype record instead of constructing caller-controlled arrays.
  const unsigned = CREATE_NULL_PROTO(null);
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    const descriptor = OWN_DESCRIPTOR(signed, field);
    if (!descriptor || !HAS_OWN(descriptor, "value")) deny();
    unsigned[field] = descriptor.value;
  }
  const body = normalize(unsigned);
  const signature = BUFFER_FROM(bytes(signed.signature, 64), "base64url");
  // All normalized owner/floor records are FLAT scalar schemas. Serialize
  // each own primitive in the exact signed field order. JSON.stringify(body)
  // would invoke inherited toJSON hooks after an injected CURRENT callback.
  let encoded = "{";
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    const descriptor = OWN_DESCRIPTOR(body, field);
    const type = typeof descriptor?.value;
    if (!descriptor || !HAS_OWN(descriptor, "value")
      || (descriptor.value !== null && type !== "string"
        && type !== "boolean" && type !== "number")) deny();
    if (index !== 0) encoded += ",";
    encoded += `${JSON_STRINGIFY_PRIMITIVE(field)}:${JSON_STRINGIFY_PRIMITIVE(descriptor.value)}`;
  }
  encoded += "}";
  const message = BUFFER_CONCAT([domain,
    BUFFER_FROM(encoded, "utf8")]);
  if (!VERIFY(null, message, pinnedKey, signature)) deny();
  return body;
}
function exactExpected(value) {
  const expected = exact(value, EXPECTED_FIELDS);
  bytes(expected.immutable_account_id, 16);
  bytes(expected.object_id, 16);
  bytes(expected.version_id, 16);
  integer(expected.key_epoch, 1);
  return FREEZE(expected);
}
function immutableBytes(part, remaining) {
  // No JS-accessed byteLength/length/buffer/byteOffset properties may redefine
  // the real range hashed. Shared backing permits mutation between copies.
  if (isProxy(part) || (!BUFFER_IS_BUFFER(part) && !(part instanceof NATIVE_UINT8ARRAY))) deny();
  if (SAFE_APPLY(ARRAY_SOME, ["byteLength", "byteOffset", "buffer", "length"],
    [(field) => HAS_OWN(part, field)])) deny();
  try {
    const length = SAFE_APPLY(VIEW_LENGTH, part, []);
    const offset = SAFE_APPLY(VIEW_OFFSET, part, []);
    const backing = SAFE_APPLY(VIEW_BUFFER, part, []);
    const total = SAFE_APPLY(AB_LENGTH, backing, []); // rejects SharedArrayBuffer and detached backing
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
    if (SAFE_APPLY(KEY_EQUALS, ownerKey, [floorKey])) deny();
    const retained = exact(o.independentlyRetainedMinimum, MINIMUM_FIELDS);
    integer(retained.sequence, 1);
    hex(retained.headDigest);
    const observedNonces = new Set();
    const tickets = new WeakMap();

    function currentFloor(accountId) {
      // This callback is a DEVELOPMENT TEST INJECTION, not an off-host network
      // or independently audited monotonic custodian. Require a fresh signed
      // challenge; even its success is insufficient to authorize protected I/O.
      const challenge = SAFE_APPLY(BUFFER_TO_STRING, RANDOM(32), ["base64url"]);
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
        if (SAFE_APPLY(ARRAY_SOME, EXPECTED_FIELDS,
          [(field) => intent[field] !== scope[field]])) deny();
        freshOwner(intent);
        const replayKey = intent.immutable_account_id + ":" + intent.nonce;
        if (SAFE_APPLY(SET_HAS, observedNonces, [replayKey])
          || observedNonces.size >= MAX_NONCES) deny();
        SAFE_APPLY(SET_ADD, observedNonces, [replayKey]);
        const ticket = FREEZE({ authorizesIo: false, stagePermitted: false,
          independentCustodyProven: false });
        SAFE_APPLY(WEAK_SET, tickets, [ticket, { intent, consumed: false }]);
        return ticket;
      } catch (_) { deny(); }
    }
    function verifyOriginalBytes(input) {
      try {
        const { ticket, chunks } = exact(input, ["ticket", "chunks"]);
        const saved = ticket && SAFE_APPLY(WEAK_GET, tickets, [ticket]);
        if (!saved || saved.consumed) deny();
        saved.consumed = true; // consume before any user-supplied byte access
        const intent = saved.intent;
        freshOwner(intent);
        if (!IS_ARRAY(chunks) || isProxy(chunks)
          || GET_PROTOTYPE(chunks) !== Array.prototype
          || chunks.length > MAX_CHUNKS
          || OWN_KEYS(chunks).length !== chunks.length + 1) deny();
        const digest = HASH("sha256");
        let size = 0;
        for (let index = 0; index < chunks.length; index++) {
          const descriptor = OWN_DESCRIPTOR(chunks, index);
          if (!descriptor || !HAS_OWN(descriptor, "value")) deny();
          const copied = immutableBytes(descriptor.value, intent.original_length - size);
          size += copied.length;
          SAFE_APPLY(HASH_UPDATE, digest, [copied]);
        }
        if (size !== intent.original_length
          || !TIMING_SAFE_EQUAL(SAFE_APPLY(HASH_DIGEST, digest, []),
            BUFFER_FROM(intent.original_sha256, "hex"))) deny();
        freshOwner(intent); // check another nonce-signed snapshot after assembly
        return FREEZE({
          status: "SIGNED_ORIGINAL_BYTES_NONAUTHORIZING",
          originalByteDigestVerified: true, originalLength: size,
          authorizesIo: false, stagePermitted: false,
          independentCustodyProven: false, offHostMonotonicFloorProven: false,
          historicalCorpusComplete: false,
        });
      } catch (_) { deny(); }
    }
    return FREEZE({ beginBeforeBody, verifyOriginalBytes,
      authorizesIo: false, stagePermitted: false });
  } catch (_) { deny(); }
}

module.exports = FREEZE({ createDevOffOriginalByteEvidenceGate });
