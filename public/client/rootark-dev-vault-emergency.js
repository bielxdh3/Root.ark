(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto, require("libsodium-wrappers-sumo"));
  } else {
    root.RootarkDevVaultEmergency = factory(root.crypto, root.sodium);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto, sodium) {
  "use strict";

  // User-held encrypted backup for the *development* vault key only.
  // This is NOT the signed zk-1/manifest-v2 emergency recovery package.
  const FORMAT = "rootark-dev-emergency-v1";
  const CONTEXT = "Root.ark/dev-emergency-package/v1\0";
  const OPSLIMIT = 3;
  const MEMLIMIT = 268435456;
  // Known-answer test for the exact required 256 MiB Argon2id profile.
  // A JS backup module in some libsodium builds produced nonportable output
  // at this memory limit. Never wrap or unwrap keys with an incompatible KDF.
  const ARGON2ID_KAT_HEX = "6752db303bb8916a149e207626f46cf6aaf2305747801ea0b75a6c7014128a45";
  const MAX_PACKAGE_CHARS = 2048;
  const textEncoder = new TextEncoder();
  const B64URL = /^[A-Za-z0-9_-]+$/;
  let kdfHealthPromise = null;

  function invalid() { throw new Error("Invalid emergency package or passphrase"); }
  function strictObject(value, fields) {
    if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
    const keys = Reflect.ownKeys(value);
    if (keys.length !== fields.length || fields.some((f) => !Object.hasOwn(value, f))
      || keys.some((k) => typeof k !== "string" || !fields.includes(k))) invalid();
  }
  function encode64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function decode64(value, length) {
    if (typeof value !== "string" || !B64URL.test(value) || value.length > 96
      || value.length % 4 === 1) invalid();
    let string;
    try {
      string = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "="));
    } catch (_) { invalid(); }
    const raw = Uint8Array.from(string, (c) => c.charCodeAt(0));
    if (raw.length !== length || encode64(raw) !== value) invalid();
    return raw;
  }
  function validateAccount(username) {
    if (typeof username !== "string" || username.length < 1 || username.length > 256
      || /[\u0000-\u001f\u007f]/.test(username)) invalid();
  }
  function validatePassphrase(password) {
    if (typeof password !== "string" || password.length < 12
      || textEncoder.encode(password).length > 1024) invalid();
  }
  async function assertPortableKdf() {
    if (!sodium || !webCrypto?.subtle) invalid();
    if (!kdfHealthPromise) {
      kdfHealthPromise = (async () => {
        await sodium.ready;
        let sample;
        try {
          sample = sodium.crypto_pwhash(32, new Uint8Array(20), new Uint8Array(16),
            OPSLIMIT, MEMLIMIT, sodium.crypto_pwhash_ALG_ARGON2ID13, "uint8array");
          if (!(sample instanceof Uint8Array) || sample.length !== 32) invalid();
          const hex = Array.from(sample, (byte) => byte.toString(16).padStart(2, "0")).join("");
          if (hex !== ARGON2ID_KAT_HEX) invalid();
        } catch (_) {
          invalid();
        } finally {
          if (sample instanceof Uint8Array) sodium.memzero(sample);
        }
      })();
    }
    return kdfHealthPromise;
  }
  async function derive(password, salt) {
    await assertPortableKdf();
    const secret = textEncoder.encode(password);
    try {
      const result = sodium.crypto_pwhash(32, secret, salt, OPSLIMIT, MEMLIMIT,
        sodium.crypto_pwhash_ALG_ARGON2ID13, "uint8array");
      if (!(result instanceof Uint8Array) || result.length !== 32) invalid();
      return result;
    } finally { secret.fill(0); }
  }
  function aad(username) {
    return textEncoder.encode(CONTEXT + username);
  }
  async function createEmergencyPackage({ username, recoveryKey, password }) {
    validateAccount(username);
    validatePassphrase(password);
    const recoveryRaw = decode64(recoveryKey, 32);
    const salt = webCrypto.getRandomValues(new Uint8Array(16));
    const iv = webCrypto.getRandomValues(new Uint8Array(12));
    let wrappingKey;
    try {
      wrappingKey = await derive(password, salt);
      const nonExtractable = await webCrypto.subtle.importKey("raw", wrappingKey,
        { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
      const ciphertext = new Uint8Array(await webCrypto.subtle.encrypt({
        name: "AES-GCM", iv, additionalData: aad(username), tagLength: 128,
      }, nonExtractable, recoveryRaw));
      return {
        format: FORMAT,
        account: username,
        kdf: { name: "argon2id13", opslimit: OPSLIMIT, memlimit: MEMLIMIT,
          salt: encode64(salt) },
        iv: encode64(iv),
        ciphertext: encode64(ciphertext),
      };
    } finally {
      recoveryRaw.fill(0);
      if (wrappingKey) sodium.memzero(wrappingKey);
    }
  }
  async function openEmergencyPackage({ username, packageBytes, password }) {
    validateAccount(username);
    validatePassphrase(password);
    strictObject(packageBytes, ["format", "account", "kdf", "iv", "ciphertext"]);
    if (JSON.stringify(packageBytes).length > MAX_PACKAGE_CHARS
      || packageBytes.format !== FORMAT || packageBytes.account !== username) invalid();
    strictObject(packageBytes.kdf, ["name", "opslimit", "memlimit", "salt"]);
    if (packageBytes.kdf.name !== "argon2id13"
      || packageBytes.kdf.opslimit !== OPSLIMIT
      || packageBytes.kdf.memlimit !== MEMLIMIT) invalid();
    const salt = decode64(packageBytes.kdf.salt, 16);
    const iv = decode64(packageBytes.iv, 12);
    const ciphertext = decode64(packageBytes.ciphertext, 48);
    let wrappingKey;
    try {
      wrappingKey = await derive(password, salt);
      const nonExtractable = await webCrypto.subtle.importKey("raw", wrappingKey,
        { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
      const recovered = new Uint8Array(await webCrypto.subtle.decrypt({
        name: "AES-GCM", iv, additionalData: aad(username), tagLength: 128,
      }, nonExtractable, ciphertext));
      if (recovered.length !== 32) invalid();
      try { return encode64(recovered); } finally { recovered.fill(0); }
    } finally {
      if (wrappingKey) sodium.memzero(wrappingKey);
    }
  }

  return Object.freeze({ createEmergencyPackage, openEmergencyPackage });
}));
