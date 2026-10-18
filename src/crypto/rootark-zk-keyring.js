"use strict";

// Server-blind key hierarchy primitive for rootark-zk-1 (issue #65).
// Pure library: no routes, no storage, no UI. Built only on rootark-zk-1 primitives
// (HPKE base mode X25519, deterministic CBOR encoding, clearSecret).
//
// Hierarchy: account root key (client-only, never in the manifest) and independent random
// per-epoch key-encryption keys. Epoch keys are NOT derived from the root key, so rotation
// genuinely excludes a revoked device. Each (device, epoch) pair has one HPKE wrap.
// Enrollment is non-retroactive: a device only receives the epoch it was enrolled at and later ones.

const crypto = require("node:crypto");
const z = require("./rootark-zk-1");

const MANIFEST_TYPE = "rootark-zk-keyring-manifest";
const MANIFEST_VERSION = 1;
const MAX_EPOCH = 0xffffffff;
const MAX_DEVICES = 256;
const MAX_EPOCHS = 64;
const DEVICE_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const B64U_RE = /^[A-Za-z0-9_-]+$/;
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

const MANIFEST_KEYS = ["type", "version", "suite", "account_id", "current_epoch", "epochs", "devices", "wraps", "mac"];
const DEVICE_KEYS = ["device_id", "public_key", "enrolled_epoch", "revoked_at_epoch"];
const WRAP_KEYS = ["device_id", "epoch", "enc", "ciphertext"];

function fail(code, classification) {
  throw new z.RootarkZkError(code, classification);
}

const b64u = (buf) => Buffer.from(buf).toString("base64url");

function fromB64u(value, length, code) {
  if (typeof value !== "string" || !B64U_RE.test(value)) fail(code);
  const out = Buffer.from(value, "base64url");
  if (b64u(out) !== value || (length !== undefined && out.length !== length)) fail(code);
  return out;
}

function checkDeviceId(deviceId) {
  if (typeof deviceId !== "string" || !DEVICE_ID_RE.test(deviceId) || FORBIDDEN_KEYS.has(deviceId)) {
    fail("INVALID_DEVICE_ID");
  }
  return deviceId;
}

function checkEpoch(epoch) {
  if (!Number.isSafeInteger(epoch) || epoch < 1 || epoch > MAX_EPOCH) fail("INVALID_EPOCH");
  return epoch;
}

function hasForbiddenKey(value, depth = 0) {
  if (depth > 8) return true;
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some((item) => hasForbiddenKey(item, depth + 1));
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || FORBIDDEN_KEYS.has(key)) return true;
    if (hasForbiddenKey(value[key], depth + 1)) return true;
  }
  return false;
}

function exactKeys(value, keys, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(code);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail(code);
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || keys.some((k) => !Object.hasOwn(value, k))) fail(code);
}

async function publicKeyBytes(devicePublicKey) {
  if (devicePublicKey instanceof Uint8Array) {
    if (devicePublicKey.length !== 32) fail("INVALID_DEVICE_PUBLIC_KEY");
    return Buffer.from(devicePublicKey);
  }
  try {
    return Buffer.from(await z.hpkeSuite().kem.serializePublicKey(devicePublicKey));
  } catch (_) {
    return fail("INVALID_DEVICE_PUBLIC_KEY");
  }
}

async function importPublicKey(raw) {
  try {
    return await z.hpkeSuite().kem.deserializePublicKey(raw);
  } catch (_) {
    return fail("INVALID_DEVICE_PUBLIC_KEY");
  }
}

function wrapContext(accountId, deviceId, epoch) {
  return { suite: z.SUITE_ID, account_id: Buffer.from(accountId), device_id: deviceId, epoch };
}

function wrapInfo(accountId, deviceId, epoch) {
  return z.encodeDeterministic({ type: "rootark-keyring-wrap-info-v1", ...wrapContext(accountId, deviceId, epoch) });
}

function wrapAad(accountId, deviceId, epoch) {
  return z.encodeDeterministic({ type: "rootark-keyring-wrap-aad-v1", ...wrapContext(accountId, deviceId, epoch) });
}

async function wrapEpochKeyTo(accountId, epochKey, rawPublicKey, deviceId, epoch) {
  const sealed = await z.hpkeSeal({
    recipientPublicKey: await importPublicKey(rawPublicKey),
    info: await wrapInfo(accountId, deviceId, epoch),
    aad: await wrapAad(accountId, deviceId, epoch),
    plaintext: epochKey,
  });
  return { device_id: deviceId, epoch, enc: b64u(sealed.enc), ciphertext: b64u(sealed.ciphertext) };
}

async function manifestMac(manifest, epochKey) {
  const { mac: _ignored, ...body } = manifest;
  const accountId = fromB64u(body.account_id, 16, "INVALID_MANIFEST");
  const macKey = z.hkdfSha256({
    ikm: epochKey,
    salt: Buffer.alloc(0),
    info: await z.encodeDeterministic({
      type: "rootark-keyring-manifest-mac-info-v1",
      suite: z.SUITE_ID,
      purpose: "manifest-mac",
      account_id: accountId,
      epoch: body.current_epoch,
    }),
    length: 32,
  });
  try {
    return crypto.createHmac("sha256", macKey).update(await z.encodeDeterministic(body)).digest();
  } finally {
    z.clearSecret(macKey);
  }
}

async function verifyManifestMac(manifest, epochKey) {
  const expected = await manifestMac(manifest, epochKey);
  const actual = fromB64u(manifest.mac, 32, "INVALID_MANIFEST");
  if (!crypto.timingSafeEqual(expected, actual)) fail("MANIFEST_MAC_INVALID", z.SECURITY_CLASS.AUTHENTICATION);
}

async function sealManifest(keyring) {
  const m = keyring.manifest;
  m.mac = b64u(await manifestMac(m, keyring.epochKeys[keyring.epochKeys.length - 1].key));
}

/** Generates the account root key and the epoch 1 key. Secrets live only in the returned object. */
async function createAccountKeyring() {
  const accountId = crypto.randomBytes(16);
  const keyring = {
    accountId,
    rootKey: crypto.randomBytes(32),
    epochKeys: [{ epoch: 1, key: crypto.randomBytes(32) }],
    manifest: {
      type: MANIFEST_TYPE,
      version: MANIFEST_VERSION,
      suite: z.SUITE_ID,
      account_id: b64u(accountId),
      current_epoch: 1,
      epochs: [1],
      devices: [],
      wraps: [],
      mac: "",
    },
  };
  await sealManifest(keyring);
  return keyring;
}

/** HPKE-wraps the current epoch key to a new device. Returns the wrap (also recorded in the manifest). */
async function enrollDevice(keyring, devicePublicKey, deviceId) {
  checkDeviceId(deviceId);
  const m = keyring.manifest;
  await verifyManifestMac(m, keyring.epochKeys[keyring.epochKeys.length - 1].key);
  if (m.devices.some((d) => d.device_id === deviceId)) fail("DUPLICATE_DEVICE_ID");
  if (m.devices.length >= MAX_DEVICES) fail("TOO_MANY_DEVICES");
  const raw = await publicKeyBytes(devicePublicKey);
  const { epoch, key } = keyring.epochKeys[keyring.epochKeys.length - 1];
  if (m.devices.some((d) => d.public_key === b64u(raw))) fail("DUPLICATE_DEVICE_PUBLIC_KEY");
  const wrap = await wrapEpochKeyTo(keyring.accountId, key, raw, deviceId, epoch);
  m.devices.push({ device_id: deviceId, public_key: b64u(raw), enrolled_epoch: epoch, revoked_at_epoch: null });
  m.wraps.push(wrap);
  await sealManifest(keyring);
  return { ...wrap };
}

/**
 * Marks the device revoked and rotates to a new random epoch key, wrapped only to remaining
 * non-revoked devices. Previously issued wraps (incl. the revoked device's) cannot be recalled:
 * revocation is forward-only, data of old epochs stays readable to whoever held those keys.
 */
async function revokeDevice(keyring, deviceId) {
  checkDeviceId(deviceId);
  const m = keyring.manifest;
  await verifyManifestMac(m, keyring.epochKeys[keyring.epochKeys.length - 1].key);
  const target = m.devices.find((d) => d.device_id === deviceId);
  if (!target) fail("UNKNOWN_DEVICE");
  if (target.revoked_at_epoch !== null) fail("DEVICE_ALREADY_REVOKED");
  const epoch = m.current_epoch + 1;
  checkEpoch(epoch);
  if (m.epochs.length >= MAX_EPOCHS) fail("TOO_MANY_EPOCHS");
  const key = crypto.randomBytes(32);
  const newWraps = [];
  for (const d of m.devices) {
    if (d.device_id === deviceId || d.revoked_at_epoch !== null) continue;
    newWraps.push(await wrapEpochKeyTo(keyring.accountId, key, fromB64u(d.public_key, 32, "INVALID_MANIFEST"), d.device_id, epoch));
  }
  target.revoked_at_epoch = epoch;
  m.current_epoch = epoch;
  m.epochs.push(epoch);
  m.wraps.push(...newWraps);
  keyring.epochKeys.push({ epoch, key });
  await sealManifest(keyring);
  return { epoch, wraps: newWraps.map((w) => ({ ...w })) };
}

/**
 * Unwraps an epoch key for a device. expectedContext: { accountId (Buffer|base64url), deviceId, epoch,
 * revokedAtEpoch? }. AAD/info are rebuilt from the expected context, never taken from the wrap.
 */
async function openEpochKey(wrap, devicePrivateKey, expectedContext) {
  if (!expectedContext || typeof expectedContext !== "object") fail("INVALID_CONTEXT");
  const deviceId = checkDeviceId(expectedContext.deviceId);
  const epoch = checkEpoch(expectedContext.epoch);
  const rawAccount = expectedContext.accountId;
  const accountId = typeof rawAccount === "string"
    ? fromB64u(rawAccount, 16, "INVALID_CONTEXT")
    : rawAccount instanceof Uint8Array ? Buffer.from(rawAccount) : fail("INVALID_CONTEXT");
  if (accountId.length !== 16) fail("INVALID_CONTEXT");
  exactKeys(wrap, WRAP_KEYS, "INVALID_WRAP");
  if (wrap.device_id !== deviceId || wrap.epoch !== epoch) fail("WRAP_SCOPE_MISMATCH", z.SECURITY_CLASS.SCOPE);
  const revokedAt = expectedContext.revokedAtEpoch;
  if (revokedAt !== undefined && revokedAt !== null && epoch >= checkEpoch(revokedAt)) {
    fail("DEVICE_REVOKED", z.SECURITY_CLASS.SCOPE);
  }
  return z.hpkeOpen({
    recipientKey: devicePrivateKey,
    enc: fromB64u(wrap.enc, 32, "INVALID_WRAP"),
    ciphertext: fromB64u(wrap.ciphertext, 48, "INVALID_WRAP"),
    info: await wrapInfo(accountId, deviceId, epoch),
    aad: await wrapAad(accountId, deviceId, epoch),
  });
}

/** Validates a serialized manifest (as stored by a server) and returns a normalized deep copy. */
function validateManifest(input) {
  if (hasForbiddenKey(input)) fail("INVALID_MAP_KEY");
  exactKeys(input, MANIFEST_KEYS, "INVALID_MANIFEST");
  if (input.type !== MANIFEST_TYPE) fail("INVALID_MANIFEST");
  if (input.version !== MANIFEST_VERSION) fail("UNSUPPORTED_MANIFEST_VERSION");
  if (input.suite !== z.SUITE_ID) fail("UNSUPPORTED_SUITE");
  fromB64u(input.account_id, 16, "INVALID_MANIFEST");
  fromB64u(input.mac, 32, "INVALID_MANIFEST");
  if (!Array.isArray(input.epochs) || input.epochs.length < 1 || input.epochs.length > MAX_EPOCHS) fail("INVALID_MANIFEST");
  input.epochs.forEach((e, i) => {
    checkEpoch(e);
    if (e !== i + 1) fail("NON_MONOTONIC_EPOCHS");
  });
  const current = checkEpoch(input.current_epoch);
  if (current !== input.epochs[input.epochs.length - 1]) fail("NON_MONOTONIC_EPOCHS");
  if (!Array.isArray(input.devices) || input.devices.length > MAX_DEVICES) fail("INVALID_MANIFEST");
  if (!Array.isArray(input.wraps) || input.wraps.length > MAX_DEVICES * input.epochs.length) fail("INVALID_MANIFEST");
  const devices = new Map();
  const pubkeys = new Set();
  for (const d of input.devices) {
    exactKeys(d, DEVICE_KEYS, "INVALID_MANIFEST");
    checkDeviceId(d.device_id);
    if (devices.has(d.device_id)) fail("DUPLICATE_DEVICE_ID");
    fromB64u(d.public_key, 32, "INVALID_MANIFEST");
    if (pubkeys.has(d.public_key)) fail("DUPLICATE_DEVICE_PUBLIC_KEY");
    pubkeys.add(d.public_key);
    checkEpoch(d.enrolled_epoch);
    if (d.enrolled_epoch > current) fail("INVALID_MANIFEST");
    if (d.revoked_at_epoch !== null) {
      checkEpoch(d.revoked_at_epoch);
      if (d.revoked_at_epoch <= d.enrolled_epoch || d.revoked_at_epoch > current) fail("INVALID_MANIFEST");
    }
    devices.set(d.device_id, d);
  }
  const seen = new Set();
  for (const w of input.wraps) {
    exactKeys(w, WRAP_KEYS, "INVALID_MANIFEST");
    const d = devices.get(w.device_id);
    checkEpoch(w.epoch);
    if (!d || w.epoch > current || w.epoch < d.enrolled_epoch) fail("INVALID_MANIFEST");
    if (d.revoked_at_epoch !== null && w.epoch >= d.revoked_at_epoch) fail("WRAP_FOR_REVOKED_DEVICE", z.SECURITY_CLASS.SCOPE);
    const id = `${w.device_id}\u0000${w.epoch}`;
    if (seen.has(id)) fail("DUPLICATE_WRAP");
    seen.add(id);
    fromB64u(w.enc, 32, "INVALID_MANIFEST");
    fromB64u(w.ciphertext, 48, "INVALID_MANIFEST");
  }
  for (const d of devices.values()) {
    const last = d.revoked_at_epoch === null ? current : d.revoked_at_epoch - 1;
    for (let e = d.enrolled_epoch; e <= last; e += 1) {
      if (!seen.has(`${d.device_id}\u0000${e}`)) fail("MISSING_WRAP");
    }
  }
  return JSON.parse(JSON.stringify(input));
}

/** Server-safe serialization: no root key, no epoch keys. */
function exportManifest(keyring) {
  return validateManifest(keyring.manifest);
}

/**
 * Authenticated, anti-rollback open. The device first unwraps the CURRENT epoch key from its own wrap,
 * verifies the manifest MAC with it (a server cannot forge it), then opens the requested epoch.
 * opts: { expectedAccountId (required, Buffer|base64url), minEpoch? (highest epoch the client has seen) }.
 * A revoked device cannot verify the manifest and is rejected. Limitation: rollback within the same
 * epoch (e.g. dropping a just-enrolled device) is not detectable by epoch alone.
 */
async function openEpochKeyFromManifest(manifest, devicePrivateKey, deviceId, epoch, opts) {
  const m = validateManifest(manifest);
  const expected = opts && opts.expectedAccountId;
  const expectedB64 = typeof expected === "string" ? expected : expected instanceof Uint8Array ? b64u(expected) : null;
  if (expectedB64 === null || fromB64u(expectedB64, 16, "INVALID_CONTEXT") === null) fail("INVALID_CONTEXT");
  if (m.account_id !== expectedB64) fail("ACCOUNT_MISMATCH", z.SECURITY_CLASS.SCOPE);
  if (opts.minEpoch !== undefined && m.current_epoch < checkEpoch(opts.minEpoch)) {
    fail("MANIFEST_ROLLBACK", z.SECURITY_CLASS.SCOPE);
  }
  const d = m.devices.find((x) => x.device_id === deviceId);
  if (!d || d.revoked_at_epoch !== null) fail("WRAP_NOT_FOUND", z.SECURITY_CLASS.SCOPE);
  const wrapAt = (e) => m.wraps.find((w) => w.device_id === deviceId && w.epoch === e);
  const currentWrap = wrapAt(m.current_epoch);
  if (!currentWrap) fail("WRAP_NOT_FOUND", z.SECURITY_CLASS.SCOPE);
  const open = (wrap, e) => openEpochKey(wrap, devicePrivateKey, { accountId: m.account_id, deviceId, epoch: e, revokedAtEpoch: d.revoked_at_epoch });
  const currentKey = await open(currentWrap, m.current_epoch);
  try {
    await verifyManifestMac(m, currentKey);
    if (epoch === m.current_epoch) return Buffer.from(currentKey);
    const wrap = wrapAt(epoch);
    if (!wrap) fail("WRAP_NOT_FOUND", z.SECURITY_CLASS.SCOPE);
    return await open(wrap, epoch);
  } finally {
    z.clearSecret(currentKey);
  }
}

/** Structural validation + MAC + account binding + anti-rollback, for a client holding the current epoch key. */
async function loadManifest(manifest, { epochKey, expectedAccountId, minEpoch }) {
  const m = validateManifest(manifest);
  const expected = typeof expectedAccountId === "string" ? expectedAccountId : expectedAccountId instanceof Uint8Array ? b64u(expectedAccountId) : null;
  if (expected === null) fail("INVALID_CONTEXT");
  if (m.account_id !== expected) fail("ACCOUNT_MISMATCH", z.SECURITY_CLASS.SCOPE);
  if (minEpoch !== undefined && m.current_epoch < checkEpoch(minEpoch)) fail("MANIFEST_ROLLBACK", z.SECURITY_CLASS.SCOPE);
  await verifyManifestMac(m, epochKey);
  return m;
}

function clearKeyring(keyring) {
  z.clearSecret(keyring.rootKey);
  for (const e of keyring.epochKeys) z.clearSecret(e.key);
}

module.exports = {
  MANIFEST_TYPE,
  MANIFEST_VERSION,
  createAccountKeyring,
  enrollDevice,
  revokeDevice,
  openEpochKey,
  openEpochKeyFromManifest,
  validateManifest,
  loadManifest,
  exportManifest,
  clearKeyring,
};
