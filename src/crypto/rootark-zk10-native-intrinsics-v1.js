"use strict";

// DEV-OFF, nonauthorizing cryptographic primitives. This module is loaded
// before the first caller-owned KeyObject getter. Reusing its frozen snapshot
// prevents a LATE require of a peer module from accepting a previously
// poisoned crypto factory, Hash prototype or JSON serializer as "native".
// It does not defend against an untrusted script running BEFORE initial load
// or supply independent custody, a protected process, or production I/O.
const crypto = require("node:crypto");
const { types: { isProxy } } = require("node:util");

const createPublicKey = crypto.createPublicKey.bind(crypto);
const createHash = crypto.createHash.bind(crypto);
const prototype = Object.getPrototypeOf(createHash("sha256"));
const publicPrototype = Object.getPrototypeOf(createPublicKey({
  key: Buffer.from("302a300506032b6570032100" + "00".repeat(32), "hex"),
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
  if (Array.isArray(value)) {
    if (value.length > 1024 || Reflect.ownKeys(value).length !== value.length + 1) {
      throw new TypeError("noncanonical signed array");
    }
    const fields = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, "value")) {
        throw new TypeError("noncanonical signed array element");
      }
      fields.push(canonicalStringify(descriptor.value, depth + 1));
    }
    return `[${fields.join(",")}]`;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("noncanonical signed object prototype");
  }
  const names = Reflect.ownKeys(value);
  if (names.length > 128) throw new TypeError("oversized signed object");
  const fields = [];
  for (const name of names) {
    if (typeof name !== "string") throw new TypeError("symbol in signed object");
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !Object.hasOwn(descriptor, "value") || !descriptor.enumerable) {
      throw new TypeError("noncanonical signed field");
    }
    fields.push(`${PRIMITIVE_STRINGIFY(name)}:${canonicalStringify(descriptor.value, depth + 1)}`);
  }
  return `{${fields.join(",")}}`;
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
  hashUpdate: Object.getOwnPropertyDescriptor(prototype, "update").value,
  hashDigest: Object.getOwnPropertyDescriptor(prototype, "digest").value,
  publicExport: Object.getOwnPropertyDescriptor(publicPrototype, "export").value,
  keyType: Object.getOwnPropertyDescriptor(crypto.KeyObject.prototype, "type").get,
  keyAlgorithm: Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(publicPrototype), "asymmetricKeyType").get,
  keyEquals: crypto.KeyObject.prototype.equals,
});
