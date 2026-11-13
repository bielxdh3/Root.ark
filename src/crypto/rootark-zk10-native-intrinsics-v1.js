"use strict";

// DEV-OFF, nonauthorizing cryptographic primitives. This module is loaded
// before the first caller-owned KeyObject getter. Reusing its frozen snapshot
// prevents a LATE require of a peer module from accepting a previously
// poisoned crypto factory, Hash prototype or JSON serializer as "native".
// It does not defend against an untrusted script running BEFORE initial load
// or supply independent custody, a protected process, or production I/O.
const crypto = require("node:crypto");
const { types: { isProxy } } = require("node:util");
// Capture these before the first caller-owned KeyObject getter too. Even an
// immutable JSON encoder can be retargeted via Array.join or Buffer.from.
// Calling a captured function through .call is insufficient: the dispatch
// itself re-reads Function.prototype.call after an untrusted native getter.
const APPLY = Reflect.apply.bind(Reflect);
const BUFFER_FROM = Buffer.from.bind(Buffer);
const BUFFER_CONCAT = Buffer.concat.bind(Buffer);
const BUFFER_COMPARE = Buffer.compare.bind(Buffer);
const BUFFER_TO_STRING = Buffer.prototype.toString;
const BUFFER_BYTE_LENGTH = Buffer.byteLength.bind(Buffer);
// This only pins the original JS clock method against same-realm rebinding;
// OS wall-clock changes still require independent trusted-time/floor evidence.
const DATE_NOW = Date.now.bind(Date);
const MATH_FLOOR = Math.floor.bind(Math);
const MATH_ABS = Math.abs.bind(Math);
const ARRAY_JOIN = Array.prototype.join;
const ARRAY_PUSH = Array.prototype.push;
const ARRAY_INCLUDES = Array.prototype.includes;
const ARRAY_SOME = Array.prototype.some;
const ARRAY_SORT = Array.prototype.sort;
const ARRAY_IS_ARRAY = Array.isArray.bind(Array);
const OWN_KEYS = Reflect.ownKeys.bind(Reflect);
const OWN_DESCRIPTOR = Object.getOwnPropertyDescriptor.bind(Object);
const GET_PROTOTYPE = Object.getPrototypeOf.bind(Object);
const HAS_OWN = Object.hasOwn.bind(Object);
const OBJECT_CREATE = Object.create.bind(Object);
const SET_PROTOTYPE = Object.setPrototypeOf.bind(Object);
const DEFINE_PROPERTY = Object.defineProperty.bind(Object);
const OBJECT_FREEZE = Object.freeze.bind(Object);
// A caller-owned Ed25519 KeyObject getter may replace Set and its prototype
// before a noncooperative CURRENT authority read settles. Keep the constructor,
// methods and internal-slot size getter pinned alongside the other intrinsics.
const SET_CONSTRUCTOR = Set;
const SET_ADD = SET_CONSTRUCTOR.prototype.add;
const SET_DELETE = SET_CONSTRUCTOR.prototype.delete;
const SET_SIZE = OWN_DESCRIPTOR(SET_CONSTRUCTOR.prototype, "size").get;
function newNativeSet() { return new SET_CONSTRUCTOR(); }

const createPublicKey = crypto.createPublicKey.bind(crypto);
const createHash = crypto.createHash.bind(crypto);
const prototype = Object.getPrototypeOf(createHash("sha256"));
const publicPrototype = Object.getPrototypeOf(createPublicKey({
  key: BUFFER_FROM("302a300506032b6570032100" + "00".repeat(32), "hex"),
  format: "der", type: "spki",
}));
const PRIMITIVE_STRINGIFY = JSON.stringify.bind(JSON);
const JSON_PARSE = JSON.parse.bind(JSON);

// Keep the familiar intrinsic.call(receiver, ...) interface for existing
// native key/hash call sites, but give each reference its own immutable call
// implementation. The attacker can reassign Function.prototype.call later.
function withSafeCall(method) {
  const boundNative = function(...args) { return APPLY(method, this, args); };
  DEFINE_PROPERTY(boundNative, "call", { value(receiver, ...args) {
    return APPLY(method, receiver, args);
  }, enumerable: false, configurable: false, writable: false });
  return OBJECT_FREEZE(boundNative);
}

// The decoded signed record is already an own-DATA snapshot. Pick only the
// protocol's signed fields without consulting Array.prototype.map, its
// mutable iterator or Object.fromEntries after an untrusted key callback.
function pickSignedFields(snapshot, names) {
  if (!snapshot || typeof snapshot !== "object" || isProxy(snapshot)) {
    throw new TypeError("noncanonical signed record");
  }
  const picked = OBJECT_CREATE(null);
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    const descriptor = OWN_DESCRIPTOR(snapshot, name);
    if (typeof name !== "string" || !descriptor || !HAS_OWN(descriptor, "value")) {
      throw new TypeError("invalid signed field");
    }
    DEFINE_PROPERTY(picked, name, { value: descriptor.value,
      enumerable: true, configurable: true, writable: true });
  }
  return picked;
}

// Ordinary JSON.stringify invokes inherited Object/Array.prototype.toJSON;
// capturing the function alone cannot bind a signature to the object actually
// checked. Serialize only detached DATA descriptors, recursively, without
// consulting prototype methods or triggering caller-owned getters/Proxy traps.
// Primitive escaping/number formatting still comes from the original native
// JSON serializer, preserving the signed wire layout and insertion order.
function canonicalStringify(value, depth = 0, sortKeys = false) {
  if (depth > 8) throw new TypeError("nested signed wire");
  if (value === null || typeof value === "string" || typeof value === "boolean"
    || (typeof value === "number" && Number.isFinite(value))) {
    return PRIMITIVE_STRINGIFY(value);
  }
  if (!value || typeof value !== "object" || isProxy(value)) {
    throw new TypeError("noncanonical signed wire");
  }
  if (ARRAY_IS_ARRAY(value)) {
    if (value.length > 1024 || OWN_KEYS(value).length !== value.length + 1) {
      throw new TypeError("noncanonical signed array");
    }
    // Detach the scratch array BEFORE the first push. Native Array.push still
    // consults inherited numeric setters on default-prototype arrays; a key
    // getter could replace signed field 5 while leaving the statement at B.
    const fields = SET_PROTOTYPE([], null);
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = OWN_DESCRIPTOR(value, String(index));
      if (!descriptor || !HAS_OWN(descriptor, "value")) {
        throw new TypeError("noncanonical signed array element");
      }
      APPLY(ARRAY_PUSH, fields, [canonicalStringify(descriptor.value, depth + 1, sortKeys)]);
    }
    return `[${APPLY(ARRAY_JOIN, fields, [","])}]`;
  }
  const prototype = GET_PROTOTYPE(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("noncanonical signed object prototype");
  }
  const names = OWN_KEYS(value);
  if (names.length > 128) throw new TypeError("oversized signed object");
  // Atomic SyncV2 wire uses lexicographically sorted object fields. Sort
  // with the initial native comparator, without a post-getter .sort() lookup.
  if (sortKeys) APPLY(ARRAY_SORT, names, []);
  // Iterators and inherited numeric setters are same-realm mutable after an
  // untrusted KeyObject getter. Iterate the own keys by index only.
  const fields = SET_PROTOTYPE([], null);
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    if (typeof name !== "string") throw new TypeError("symbol in signed object");
    const descriptor = OWN_DESCRIPTOR(value, name);
    if (!descriptor || !HAS_OWN(descriptor, "value") || !descriptor.enumerable) {
      throw new TypeError("noncanonical signed field");
    }
    APPLY(ARRAY_PUSH, fields, [
      `${PRIMITIVE_STRINGIFY(name)}:${canonicalStringify(descriptor.value, depth + 1, sortKeys)}`,
    ]);
  }
  return `{${APPLY(ARRAY_JOIN, fields, [","])}}`;
}
const canonicalSortedJson = (value) => canonicalStringify(value, 0, true);

module.exports = Object.freeze({
  createPublicKey,
  createHash,
  verify: crypto.verify.bind(crypto),
  sign: crypto.sign.bind(crypto),
  timingSafeEqual: crypto.timingSafeEqual.bind(crypto),
  randomBytes: crypto.randomBytes.bind(crypto),
  randomUUID: crypto.randomUUID.bind(crypto),
  apply: APPLY,
  freeze: OBJECT_FREEZE,
  pickSignedFields,
  jsonStringify: canonicalStringify,
  canonicalSortedJson,
  jsonParse: JSON_PARSE,
  bufferFrom: BUFFER_FROM,
  bufferConcat: BUFFER_CONCAT,
  bufferCompare: BUFFER_COMPARE,
  bufferToString: withSafeCall(BUFFER_TO_STRING),
  bufferByteLength: BUFFER_BYTE_LENGTH,
  dateNow: DATE_NOW,
  mathFloor: MATH_FLOOR,
  mathAbs: MATH_ABS,
  arrayJoin: withSafeCall(ARRAY_JOIN),
  arrayPush: withSafeCall(ARRAY_PUSH),
  arrayIncludes: withSafeCall(ARRAY_INCLUDES),
  arraySome: withSafeCall(ARRAY_SOME),
  arrayIsArray: ARRAY_IS_ARRAY,
  ownKeys: OWN_KEYS,
  ownDescriptor: OWN_DESCRIPTOR,
  getPrototype: GET_PROTOTYPE,
  hasOwn: HAS_OWN,
  objectCreate: OBJECT_CREATE,
  defineProperty: DEFINE_PROPERTY,
  newNativeSet,
  setAdd: withSafeCall(SET_ADD),
  setDelete: withSafeCall(SET_DELETE),
  setSize: withSafeCall(SET_SIZE),
  hashUpdate: withSafeCall(OWN_DESCRIPTOR(prototype, "update").value),
  hashDigest: withSafeCall(OWN_DESCRIPTOR(prototype, "digest").value),
  publicExport: withSafeCall(OWN_DESCRIPTOR(publicPrototype, "export").value),
  keyType: withSafeCall(OWN_DESCRIPTOR(crypto.KeyObject.prototype, "type").get),
  keyAlgorithm: withSafeCall(OWN_DESCRIPTOR(
    GET_PROTOTYPE(publicPrototype), "asymmetricKeyType").get),
  keyEquals: withSafeCall(crypto.KeyObject.prototype.equals),
});
