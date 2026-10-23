(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto);
  } else {
    root.RootarkZk1BrowserAuthorityHeadRelay = factory(root.crypto);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto) {
  "use strict";

  // The authenticated Root.ark service transports a fresh proof from its
  // separately provisioned mTLS witness/CAS. It is NOT a source of trust keys.
  // The browser writer verifies the returned Ed25519 CBOR proof, exact nonce,
  // owner scope, age and pinned floor after every relay request.
  function deny() { throw new Error("ZK_BROWSER_AUTHORITY_RELAY_UNVERIFIED"); }
  function exact(obj, fields) {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(obj))
      || Reflect.ownKeys(obj).length !== fields.length
      || fields.some((field) => !Object.hasOwn(obj, field))) deny();
  }
  function copy(value, n) {
    if (!(value instanceof Uint8Array) || value.length !== n) deny();
    return new Uint8Array(value);
  }
  function equal(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }
  function to64(bytes) {
    let raw = "";
    for (const byte of bytes) raw += String.fromCharCode(byte);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
      || value.length > 10924) deny();
    let binary;
    try {
      binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "="));
    } catch (_) { deny(); }
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (!bytes.length || bytes.length > 8192 || to64(bytes) !== value) deny();
    return bytes;
  }
  function urlFrom(origin, kind) {
    let url;
    try { url = new URL(origin); } catch (_) { deny(); }
    if (url.href !== url.origin + "/" || url.username || url.password
      || url.search || url.hash || !["https:", "http:"].includes(url.protocol)
      || (url.protocol === "http:"
        && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
      || (typeof location === "object" && location.origin
        && url.origin !== location.origin)) deny();
    return url.origin + "/zk-1/v1/catalog/authority/" + kind;
  }
  async function verifyKey(raw, pin) {
    const lockedRaw = copy(raw, 32), lockedPin = copy(pin, 32);
    const key = await webCrypto.subtle.importKey("raw", lockedRaw,
      "Ed25519", true, ["verify"]);
    const digest = new Uint8Array(await webCrypto.subtle.digest("SHA-256",
      await webCrypto.subtle.exportKey("spki", key)));
    if (!equal(digest, lockedPin)) deny();
    return key;
  }
  async function createProbes(input) {
    exact(input, ["origin", "fetchImpl", "assertLive", "csrfToken",
      "ownerWitnessKeyRaw", "ownerWitnessSpkiSha256", "ownerWitnessKeyId",
      "catalogAuthorityKeyRaw", "catalogAuthoritySpkiSha256"]);
    if (!webCrypto?.subtle || typeof input.fetchImpl !== "function"
      || typeof input.assertLive !== "function"
      || typeof input.csrfToken !== "function") deny();
    const witnessUrl = urlFrom(input.origin, "witness-head");
    const casUrl = urlFrom(input.origin, "cas-head");
    input.assertLive();
    const [ownerWitnessPublicKey, catalogAuthorityPublicKey] = await Promise.all([
      verifyKey(input.ownerWitnessKeyRaw, input.ownerWitnessSpkiSha256),
      verifyKey(input.catalogAuthorityKeyRaw, input.catalogAuthoritySpkiSha256),
    ]);
    const ownerWitnessKeyId = copy(input.ownerWitnessKeyId, 16);
    input.assertLive();
    async function relay(url, field, { scope, nonce }) {
      exact(scope, ["account_id", "compartment_id", "keyring_id"]);
      for (const value of Object.values(scope)) {
        if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) deny();
      }
      const challenge = copy(nonce, 32);
      input.assertLive();
      const csrf = input.csrfToken();
      if (typeof csrf !== "string" || !csrf || csrf.length > 512
        || /[\r\n\u0000-\u001f\u007f]/.test(csrf)) deny();
      let response, wire;
      try {
        response = await input.fetchImpl(url, {
          method: "POST", mode: "same-origin", redirect: "error",
          credentials: "same-origin", cache: "no-store",
          headers: { "content-type": "application/json", accept: "application/json",
            "x-csrf-token": csrf },
          body: JSON.stringify({ nonce: to64(challenge) }),
        });
        input.assertLive();
        if (input.csrfToken() !== csrf || response.status !== 200
          || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(
            response.headers?.get("content-type") || "")) deny();
        if (!response.body || typeof response.body.getReader !== "function") deny();
        const reader = response.body.getReader();
        const parts = [];
        let total = 0, complete = false;
        try {
          while (true) {
            const next = await reader.read();
            if (next.done) { complete = true; break; }
            total += next.value.byteLength;
            if (total > 15000) deny();
            parts.push(next.value);
          }
        } finally {
          if (!complete) try { await reader.cancel(); } catch (_) { /* denied */ }
          reader.releaseLock();
        }
        const joined = new Uint8Array(total);
        let offset = 0;
        for (const part of parts) { joined.set(part, offset); offset += part.length; }
        wire = new TextDecoder("utf-8", { fatal: true }).decode(joined);
      } catch (_) { deny(); }
      input.assertLive();
      if (input.csrfToken() !== csrf) deny();
      let parsed;
      try { parsed = JSON.parse(wire); } catch (_) { deny(); }
      exact(parsed, [field]);
      return from64(parsed[field]);
    }
    return Object.freeze({
      ownerWitnessPublicKey, ownerWitnessKeyId, catalogAuthorityPublicKey,
      ownerWitnessProbe: (input) => relay(witnessUrl, "receiptBase64", input),
      catalogProbe: (input) => relay(casUrl, "proofBase64", input),
    });
  }
  return Object.freeze({ createProbes });
}));
