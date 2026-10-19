"use strict";

const crypto = require("node:crypto");

const SECRET_BYTES = 20;
const SECRET_TEXT_LENGTH = 32;
const DIGITS = 6;
const PERIOD_SECONDS = 30;
const DEFAULT_WINDOW = 1;
const RECOVERY_CODE_COUNT = 10;
const RECOVERY_HASH_PREFIX = "scrypt-v1";
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const TOTP_SEED_ENCRYPTION_VERSION = 2;
const TOTP_SEED_ENCRYPTION_INFO = "Root.ark/TOTP/seed-encryption/v1";
const TOTP_SEED_KEY_DERIVATION = "hkdf-sha256";

function requireKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("TOTP key unavailable");
  return key;
}

function deriveTotpSeedKey(masterKey) {
  const rawKey = requireKey(masterKey);
  return Buffer.from(crypto.hkdfSync(
    "sha256",
    rawKey,
    Buffer.alloc(0),
    Buffer.from(TOTP_SEED_ENCRYPTION_INFO, "utf8"),
    32
  ));
}

function base32Encode(input) {
  const bytes = Buffer.from(input);
  let value = 0;
  let bits = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(value) {
  const normalized = String(value || "").replace(/\s+/g, "").replace(/=+$/g, "").toUpperCase();
  if (!/^[A-Z2-7]+$/.test(normalized)) throw new Error("Invalid TOTP secret");
  let bits = 0;
  let current = 0;
  const output = [];
  for (const character of normalized) {
    current = (current << 5) | BASE32_ALPHABET.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      output.push((current >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  const result = Buffer.from(output);
  if (result.length !== SECRET_BYTES) throw new Error("Invalid TOTP secret");
  return result;
}

function generateSecret(randomBytes = crypto.randomBytes) {
  return base32Encode(randomBytes(SECRET_BYTES));
}

function normalizeOtp(value) {
  const otp = String(value || "").replace(/\s+/g, "");
  return /^\d{6}$/.test(otp) ? otp : null;
}

function normalizeRecoveryCode(value) {
  return String(value || "").trim().toLowerCase().replace(/[\s-]/g, "");
}

function hotp(secret, counter) {
  const key = base32Decode(secret);
  const movingFactor = Buffer.alloc(8);
  movingFactor.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac("sha1", key).update(movingFactor).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff);
  return String(binary % (10 ** DIGITS)).padStart(DIGITS, "0");
}

function verifyTotp(secret, value, options = {}) {
  const otp = normalizeOtp(value);
  if (!otp) return null;
  const now = Number.isFinite(options.now) ? options.now : Date.now();
  const window = Number.isInteger(options.window) && options.window >= 0 && options.window <= 2 ? options.window : DEFAULT_WINDOW;
  const currentStep = Math.floor(now / 1000 / PERIOD_SECONDS);
  for (let offset = -window; offset <= window; offset += 1) {
    const step = currentStep + offset;
    if (step < 0) continue;
    const expected = hotp(secret, step);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(otp))) return step;
  }
  return null;
}

function encryptSecret(secret, key, aad) {
  const plaintext = base32Decode(secret);
  const iv = crypto.randomBytes(12);
  const derivedKey = deriveTotpSeedKey(key);
  try {
    const cipher = crypto.createCipheriv("aes-256-gcm", derivedKey, iv);
    cipher.setAAD(Buffer.from(String(aad), "utf8"));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {
      version: TOTP_SEED_ENCRYPTION_VERSION,
      algorithm: "aes-256-gcm",
      keyDerivation: TOTP_SEED_KEY_DERIVATION,
      keyInfo: TOTP_SEED_ENCRYPTION_INFO,
      iv: iv.toString("hex"),
      authTag: cipher.getAuthTag().toString("hex"),
      ciphertext: ciphertext.toString("hex"),
    };
  } finally {
    derivedKey.fill(0);
    plaintext.fill(0);
  }
}

function decryptSecret(record, key, aad) {
  if (!record || record.version !== TOTP_SEED_ENCRYPTION_VERSION || record.algorithm !== "aes-256-gcm" || record.keyDerivation !== TOTP_SEED_KEY_DERIVATION || record.keyInfo !== TOTP_SEED_ENCRYPTION_INFO) throw new Error("Invalid TOTP secret record");
  const iv = Buffer.from(record.iv || "", "hex");
  const authTag = Buffer.from(record.authTag || "", "hex");
  const ciphertext = Buffer.from(record.ciphertext || "", "hex");
  if (iv.length !== 12 || authTag.length !== 16 || ciphertext.length !== SECRET_BYTES) throw new Error("Invalid TOTP secret record");
  const derivedKey = deriveTotpSeedKey(key);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", derivedKey, iv);
    decipher.setAAD(Buffer.from(String(aad), "utf8"));
    decipher.setAuthTag(authTag);
    const secret = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    try {
      return base32Encode(secret);
    } finally {
      secret.fill(0);
    }
  } finally {
    derivedKey.fill(0);
  }
}

function hashRecoveryCode(code, randomBytes = crypto.randomBytes) {
  const normalized = normalizeRecoveryCode(code);
  if (normalized.length < 16) throw new Error("Invalid recovery code");
  const salt = randomBytes(16);
  const digest = crypto.scryptSync(normalized, salt, 32, { N: 16_384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 });
  return `${RECOVERY_HASH_PREFIX}$${salt.toString("hex")}$${digest.toString("hex")}`;
}

function verifyRecoveryCode(code, stored) {
  const normalized = normalizeRecoveryCode(code);
  if (!normalized || typeof stored !== "string") return false;
  const [prefix, saltText, digestText] = stored.split("$");
  if (prefix !== RECOVERY_HASH_PREFIX || !/^[0-9a-f]{32}$/.test(saltText) || !/^[0-9a-f]{64}$/.test(digestText)) return false;
  const digest = crypto.scryptSync(normalized, Buffer.from(saltText, "hex"), 32, { N: 16_384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 });
  return crypto.timingSafeEqual(digest, Buffer.from(digestText, "hex"));
}

const scryptAsync = require("node:util").promisify(crypto.scrypt);

async function verifyRecoveryCodeAsync(code, stored) {
  const normalized = normalizeRecoveryCode(code);
  if (!normalized || typeof stored !== "string") return false;
  const [prefix, saltText, digestText] = stored.split("$");
  if (prefix !== RECOVERY_HASH_PREFIX || !/^[0-9a-f]{32}$/.test(saltText) || !/^[0-9a-f]{64}$/.test(digestText)) return false;
  const digest = await scryptAsync(normalized, Buffer.from(saltText, "hex"), 32, { N: 16_384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 });
  return crypto.timingSafeEqual(digest, Buffer.from(digestText, "hex"));
}

async function hashRecoveryCodeAsync(code, randomBytes = crypto.randomBytes) {
  const normalized = normalizeRecoveryCode(code);
  if (normalized.length < 16) throw new Error("Invalid recovery code");
  const salt = randomBytes(16);
  const digest = await scryptAsync(normalized, salt, 32, { N: 16_384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 });
  return `${RECOVERY_HASH_PREFIX}$${salt.toString("hex")}$${digest.toString("hex")}`;
}

function generateRecoveryCodes(count = RECOVERY_CODE_COUNT, randomBytes = crypto.randomBytes) {
  if (!Number.isInteger(count) || count < 1 || count > 20) throw new Error("Invalid recovery code count");
  const codes = Array.from({ length: count }, () => {
    const raw = randomBytes(16).toString("hex");
    return `${raw.slice(0, 8)}-${raw.slice(8, 16)}-${raw.slice(16)}`;
  });
  return { codes, hashes: codes.map((code) => hashRecoveryCode(code, randomBytes)) };
}

async function generateRecoveryCodesAsync(count = RECOVERY_CODE_COUNT, randomBytes = crypto.randomBytes) {
  if (!Number.isInteger(count) || count < 1 || count > 20) throw new Error("Invalid recovery code count");
  const codes = Array.from({ length: count }, () => {
    const raw = randomBytes(16).toString("hex");
    return `${raw.slice(0, 8)}-${raw.slice(8, 16)}-${raw.slice(16)}`;
  });
  const hashes = [];
  // Keep scrypt memory use bounded to one recovery hash at a time while yielding the event loop.
  for (const code of codes) hashes.push(await hashRecoveryCodeAsync(code, randomBytes));
  return { codes, hashes };
}

module.exports = {
  DEFAULT_WINDOW,
  DIGITS,
  PERIOD_SECONDS,
  RECOVERY_CODE_COUNT,
  TOTP_SEED_ENCRYPTION_INFO,
  TOTP_SEED_ENCRYPTION_VERSION,
  TOTP_SEED_KEY_DERIVATION,
  base32Decode,
  base32Encode,
  deriveTotpSeedKey,
  decryptSecret,
  encryptSecret,
  generateRecoveryCodes,
  generateRecoveryCodesAsync,
  generateSecret,
  hashRecoveryCode,
  hotp,
  normalizeOtp,
  normalizeRecoveryCode,
  verifyRecoveryCode,
  verifyRecoveryCodeAsync,
  verifyTotp,
};
