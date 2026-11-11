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
const BUFFER_FROM = Buffer.from.bind(Buffer);
const BUFFER_CONCAT = Buffer.concat.bind(Buffer);
const BUFFER_TO_STRING = Buffer.prototype.toString;
const BUFFER_BYTE_LENGTH = Buffer.byteLength.bind(Buffer);
const ARRAY_JOIN = Array.prototype.join;
const ARRAY_PUSH = Array.prototype.push;
const ARRAY_IS_ARRAY = Array.isArray.bind(Array);
const OWN_KEYS = Reflect.ownKeys.bind(Reflect);
const OWN_DESCRIPTOR = Object.getOwnPropertyDescriptor.bind(Object);
const GET_PROTOTYPE = Object.getPrototypeOf.bind(Object);
const HAS_OWN = Object.hasOwn.bind(Object);
const OBJECT_CREATE = Object.create.bind(Object);
const DEFINE_PROPERTY = Object.defineProperty.bind(Object);

const createPublicKey = crypto.createPublicKey.bind(crypto);
const createHash = crypto.createHash.bind(crypto);
const prototype = Object.getPrototypeOf(createHash("sha256"));
const publicPrototype = Object.getPrototypeOf(createPublicKey({
  key: BUFFER_FROM("302a300506032b6570032100" + "00".repeat(32), "hex"),
  format: "der", type: "spki",
}));
const PRIMITIVE_STRINGIFY = JSON.stringify.bind(JSON);

// Ordinary JSON.stringify invokes inherited Object/Array.prototype.toJSON;
// capturing the function alone cannot bind a signature to the object actually
// checked. Serialize only detached DATA descriptors, recursively, without
// consulting prototype methods or triggering caller-owned getters/Proxy traps.
// Primitive escaping/number formatting still comes from the original native
// JSON serializer, preserving the signed wire layout and insertion order.
function canonicalStringify(value, depth = 0) {
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
    const fields = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = OWN_DESCRIPTOR(value, String(index));
      if (!descriptor || !HAS_OWN(descriptor, "value")) {
        throw new TypeError("noncanonical signed array element");
      }
      ARRAY_PUSH.call(fields, canonicalStringify(descriptor.value, depth + 1));
    }
    return `[${ARRAY_JOIN.call(fields, ",")}]`;
  }
  const prototype = GET_PROTOTYPE(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("noncanonical signed object prototype");
  }
  const names = OWN_KEYS(value);
  if (names.length > 128) throw new TypeError("oversized signed object");
  const fields = [];
  for (const name of names) {
    if (typeof name !== "string") throw new TypeError("symbol in signed object");
    const descriptor = OWN_DESCRIPTOR(value, name);
    if (!descriptor || !HAS_OWN(descriptor, "value") || !descriptor.enumerable) {
      throw new TypeError("noncanonical signed field");
    }
    ARRAY_PUSH.call(fields, `${PRIMITIVE_STRINGIFY(name)}:${canonicalStringify(descriptor.value, depth + 1)}`);
  }
  return `{${ARRAY_JOIN.call(fields, ",")}}`;
}

module.exports = Object.freeze({
  createPublicKey,
  createHash,
  verify: crypto.verify.bind(crypto),
  sign: crypto.sign.bind(crypto),
  timingSafeEqual: crypto.timingSafeEqual.bind(crypto),
  randomBytes: crypto.randomBytes.bind(crypto),
  randomUUID: crypto.randomUUID.bind(crypto),
  jsonStringify: canonicalStringify,
  bufferFrom: BUFFER_FROM,
  bufferConcat: BUFFER_CONCAT,
  bufferToString: BUFFER_TO_STRING,
  bufferByteLength: BUFFER_BYTE_LENGTH,
  arrayJoin: ARRAY_JOIN,
  arrayPush: ARRAY_PUSH,
  arrayIsArray: ARRAY_IS_ARRAY,
  ownKeys: OWN_KEYS,
  ownDescriptor: OWN_DESCRIPTOR,
  getPrototype: GET_PROTOTYPE,
  hasOwn: HAS_OWN,
  objectCreate: OBJECT_CREATE,
  defineProperty: DEFINE_PROPERTY,
  hashUpdate: Object.getOwnPropertyDescriptor(prototype, "update").value,
  hashDigest: Object.getOwnPropertyDescriptor(prototype, "digest").value,
  publicExport: Object.getOwnPropertyDescriptor(publicPrototype, "export").value,
  keyType: Object.getOwnPropertyDescriptor(crypto.KeyObject.prototype, "type").get,
  keyAlgorithm: Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(publicPrototype), "asymmetricKeyType").get,
  keyEquals: crypto.KeyObject.prototype.equals,
});
