"use strict";

const crypto = require("node:crypto");

const REGISTRY_VERSION = 1;
const MAX_DEVICES = 10000;

function invalidRegistry() {
  return Object.assign(new Error("Atomic sync device registry is invalid or unavailable"), {
    code: "SYNC_ATOMIC_DEVICE_REGISTRY_INVALID",
  });
}

function exactFields(value, names) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
}

function validIdentifier(value, maxLength) {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

function validPublicKey(publicKey) {
  if (typeof publicKey !== "string" || publicKey.length > 128 || !/^[A-Za-z0-9_-]+$/.test(publicKey)) return false;
  try {
    const bytes = Buffer.from(publicKey, "base64url");
    const key = crypto.createPublicKey({ key: bytes, format: "der", type: "spki" });
    return key.asymmetricKeyType === "ed25519"
      && key.export({ format: "der", type: "spki" }).equals(bytes)
      && bytes.toString("base64url") === publicKey;
  } catch { return false; }
}

function emptyAtomicDeviceRegistry() {
  return { version: REGISTRY_VERSION, epoch: 0, devices: {} };
}

// Validate on every load from disk, including after a restart or an external edit.
// All writer methods below the sync store lock use the same validated snapshot.
function assertAtomicDeviceRegistry(registry) {
  if (!exactFields(registry, ["version", "epoch", "devices"])
    || registry.version !== REGISTRY_VERSION
    || !Number.isSafeInteger(registry.epoch) || registry.epoch < 0
    || !registry.devices || typeof registry.devices !== "object" || Array.isArray(registry.devices)) {
    throw invalidRegistry();
  }
  let count = 0;
  for (const [username, records] of Object.entries(registry.devices)) {
    if (!validIdentifier(username, 512) || !records || typeof records !== "object" || Array.isArray(records)) {
      throw invalidRegistry();
    }
    for (const [deviceId, record] of Object.entries(records)) {
      count += 1;
      if (count > MAX_DEVICES || !validIdentifier(deviceId, 256)
        || !exactFields(record, ["publicKey", "revokedAtEpoch"])
        || !validPublicKey(record.publicKey)
        || !(record.revokedAtEpoch === null || (Number.isSafeInteger(record.revokedAtEpoch)
          && record.revokedAtEpoch > 0 && record.revokedAtEpoch <= registry.epoch))) {
        throw invalidRegistry();
      }
    }
  }
  return registry;
}

module.exports = {
  MAX_DEVICES, assertAtomicDeviceRegistry, emptyAtomicDeviceRegistry, invalidRegistry,
  validIdentifier, validPublicKey,
};
