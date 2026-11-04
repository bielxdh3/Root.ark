"use strict";

const crypto = require("node:crypto");

// Short-lived cache of VERIFIED WebDAV Basic credentials so parallel client requests do not each
// need a bcrypt compare (and do not each consume a login-protection reservation).
// Keys are HMAC(process-random secret, length-framed username and password); plaintext passwords are never stored.
// Unambiguous framing prevents embedded NUL bytes in a credential from aliasing another identity's key.
// Failures are never cached.
function createWebDavCredentialCache({ ttlMs = 60 * 1000, maxEntries = 1000, now = Date.now } = {}) {
  const secret = crypto.randomBytes(32);
  const entries = new Map();
  const inflight = new Map();

  const keyFor = (username, password) => {
    const userBytes = Buffer.from(String(username), "utf8");
    const passwordBytes = Buffer.from(String(password), "utf8");
    const length = (bytes) => {
      const framed = Buffer.allocUnsafe(4);
      framed.writeUInt32BE(bytes.length);
      return framed;
    };
    return crypto.createHmac("sha256", secret)
      .update(length(userBytes)).update(userBytes)
      .update(length(passwordBytes)).update(passwordBytes)
      .digest("hex");
  };
  const stillValid = (entry, user) => Boolean(entry && entry.expiresAt > now() && user && !user.disabled
    && String(user.password || "") === entry.passwordHash && (user.sessionVersion || 0) === entry.sessionVersion);

  return {
    keyFor,
    // Returns true when the credentials were verified recently and the fresh user record still matches.
    isVerified(key, user) {
      const entry = entries.get(key);
      if (!entry) return false;
      if (!stillValid(entry, user)) { entries.delete(key); return false; }
      return true;
    },
    remember(key, user) {
      entries.delete(key);
      while (entries.size >= maxEntries) entries.delete(entries.keys().next().value);
      entries.set(key, { passwordHash: String(user.password || ""), sessionVersion: user.sessionVersion || 0, expiresAt: now() + ttlMs });
    },
    // Coalesce concurrent compares for the same key: returns the in-flight promise or null.
    getInflight(key) { return inflight.get(key) || null; },
    setInflight(key, promise) {
      inflight.set(key, promise);
      const clear = () => { if (inflight.get(key) === promise) inflight.delete(key); };
      promise.then(clear, clear);
    },
    size: () => entries.size,
  };
}

module.exports = { createWebDavCredentialCache };
