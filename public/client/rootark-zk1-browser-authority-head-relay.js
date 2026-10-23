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
  const encoder = new TextEncoder(), decoder = new TextDecoder("utf-8", { fatal: true });
  const WITNESS = encoder.encode("Root.ark/zk-1/recovery-witness-head/v1\0");
  const CAS = encoder.encode("Root.ark/zk-1/opaque-catalog-cas/v1\0");
  const SCOPE = ["account_id", "compartment_id", "keyring_id"];
  const WITNESS_FIELDS = ["type", "witness_key_id", ...SCOPE, "current_revision",
    "current_manifest_digest", "witness_sequence", "nonce", "observed_at",
    "status", "pending_reservation_id"];
  const CAS_FIELDS = ["type", ...SCOPE, "sequence", "digest", "nonce", "observed_at"];
  function strictBytes(value, min, max = min) {
    if (!(value instanceof Uint8Array) || value.length < min || value.length > max) deny();
    return value;
  }
  function uint(value, min, max = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < min || value > max) deny();
    return value;
  }
  function append(...parts) {
    const length = parts.reduce((total, item) => total + item.length, 0);
    if (length > 16384) deny();
    const out = new Uint8Array(length);
    let at = 0;
    for (const part of parts) { out.set(part, at); at += part.length; }
    return out;
  }
  function head(type, number) {
    const n = BigInt(uint(number)), major = type << 5;
    if (n < 24n) return Uint8Array.of(major + Number(n));
    if (n <= 255n) return Uint8Array.of(major + 24, Number(n));
    if (n <= 65535n) return Uint8Array.of(major + 25,
      Number(n >> 8n), Number(n & 255n));
    if (n <= 0xffffffffn) return Uint8Array.of(major + 26,
      Number((n >> 24n) & 255n), Number((n >> 16n) & 255n),
      Number((n >> 8n) & 255n), Number(n & 255n));
    return Uint8Array.of(major + 27, ...Array.from({ length: 8 },
      (_, i) => Number((n >> BigInt(56 - 8 * i)) & 255n)));
  }
  function canonical(value) {
    if (value === null) return Uint8Array.of(0xf6);
    if (typeof value === "number") return head(0, value);
    if (typeof value === "string") {
      const raw = encoder.encode(value);
      return append(head(3, raw.length), raw);
    }
    if (value instanceof Uint8Array) return append(head(2, value.length), value);
    if (Array.isArray(value)) return append(head(4, value.length), ...value.map(canonical));
    if (value && typeof value === "object" &&
      [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
      const entries = Object.keys(value).map((key) => [canonical(key), canonical(value[key])]);
      entries.sort(([a], [b]) => a.length - b.length
        || (() => { for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; })());
      return append(head(5, entries.length), ...entries.flat());
    }
    deny();
  }
  function decode(raw) {
    strictBytes(raw, 1, 8192);
    let offset = 0;
    function take(n) {
      if (offset + n > raw.length) deny();
      const part = raw.slice(offset, offset + n);
      offset += n;
      return part;
    }
    function read(depth) {
      if (depth > 12) deny();
      const tag = take(1)[0], major = tag >>> 5, info = tag & 31;
      if (tag === 0xf6) return null;
      if (![0, 2, 3, 4, 5].includes(major) || info > 27) deny();
      const count = info < 24 ? info : (() => {
        const n = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
        if (!n) deny();
        let size = 0;
        for (const byte of take(n)) size = size * 256 + byte;
        return uint(size, 0, major === 0 ? Number.MAX_SAFE_INTEGER : 8192);
      })();
      if (major === 0) return count;
      if (major === 2) return take(count);
      if (major === 3) return decoder.decode(take(count));
      if (major === 4) return Array.from({ length: count }, () => read(depth + 1));
      const result = Object.create(null);
      for (let i = 0; i < count; i++) {
        const key = read(depth + 1);
        if (typeof key !== "string" || ["__proto__", "constructor", "prototype"].includes(key)
          || Object.hasOwn(result, key)) deny();
        result[key] = read(depth + 1);
      }
      return result;
    }
    const decoded = read(0);
    if (offset !== raw.length || !equal(raw, canonical(decoded))) deny();
    return decoded;
  }
  async function checkedProof(raw, field, scope, nonce, keys, clock) {
    const receipt = decode(raw);
    const kind = field === "receiptBase64";
    const fields = kind ? WITNESS_FIELDS : CAS_FIELDS;
    exact(receipt, [...fields, "signature"]);
    const signature = strictBytes(receipt.signature, 64);
    const signed = Object.fromEntries(fields.map((name) => [name, receipt[name]]));
    for (const name of SCOPE) {
      if (!equal(strictBytes(receipt[name], name === "compartment_id" ? 1 : 16,
        name === "compartment_id" ? 128 : 16), scope[name])) deny();
    }
    if (!equal(strictBytes(receipt.nonce, 32), nonce)
      || Math.abs(uint(receipt.observed_at) - uint(clock())) > 30) deny();
    if (kind) {
      if (receipt.type !== "rootark-recovery-witness-head/v1"
        || !equal(strictBytes(receipt.witness_key_id, 16), keys.ownerWitnessKeyId)
        || receipt.status !== "committed" || receipt.pending_reservation_id !== null
        || uint(receipt.current_revision, 1) !== uint(receipt.witness_sequence, 1)) deny();
      strictBytes(receipt.current_manifest_digest, 32);
    } else {
      if (receipt.type !== "rootark-zk1-opaque-catalog-cas/v1"
        || uint(receipt.sequence, 0, 128) === 0
          && !equal(strictBytes(receipt.digest, 32), new Uint8Array(32))) deny();
      strictBytes(receipt.digest, 32);
    }
    if (!await webCrypto.subtle.verify("Ed25519",
      kind ? keys.ownerWitnessPublicKey : keys.catalogAuthorityPublicKey,
      signature, append(kind ? WITNESS : CAS, canonical(signed)))) deny();
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
    const configuredDeadline = Object.hasOwn(input || {}, "requestTimeoutMs");
    const customClock = Object.hasOwn(input || {}, "nowSeconds");
    exact(input, ["origin", "fetchImpl", "assertLive", "csrfToken",
      "ownerWitnessKeyRaw", "ownerWitnessSpkiSha256", "ownerWitnessKeyId",
      "catalogAuthorityKeyRaw", "catalogAuthoritySpkiSha256",
      ...(configuredDeadline ? ["requestTimeoutMs"] : []),
      ...(customClock ? ["nowSeconds"] : [])]);
    if (!webCrypto?.subtle || typeof input.fetchImpl !== "function"
      || typeof input.assertLive !== "function"
      || typeof input.csrfToken !== "function"
      || (customClock && typeof input.nowSeconds !== "function")) deny();
    // A byte limit alone cannot stop a compromised relay that never finishes
    // either its HTTP response headers or its response body.
    const deadlineMs = configuredDeadline ? input.requestTimeoutMs : 10000;
    if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 100 || deadlineMs > 10000
      || typeof AbortController !== "function") deny();
    const witnessUrl = urlFrom(input.origin, "witness-head");
    const casUrl = urlFrom(input.origin, "cas-head");
    input.assertLive();
    const [ownerWitnessPublicKey, catalogAuthorityPublicKey] = await Promise.all([
      verifyKey(input.ownerWitnessKeyRaw, input.ownerWitnessSpkiSha256),
      verifyKey(input.catalogAuthorityKeyRaw, input.catalogAuthoritySpkiSha256),
    ]);
    const ownerWitnessKeyId = copy(input.ownerWitnessKeyId, 16);
    const clock = customClock ? input.nowSeconds : () => Math.floor(Date.now() / 1000);
    const seen = new Map();
    input.assertLive();
    async function relay(url, field, { scope, nonce }) {
      exact(scope, SCOPE);
      const chosenScope = Object.fromEntries(SCOPE.map((name) => {
        const value = from64(scope[name]);
        strictBytes(value, name === "compartment_id" ? 1 : 16,
          name === "compartment_id" ? 128 : 16);
        return [name, value];
      }));
      const challenge = copy(nonce, 32);
      const replayKey = to64(challenge);
      const current = uint(clock());
      for (const [key, expiry] of seen) if (expiry < current) seen.delete(key);
      if (seen.has(replayKey) || seen.size >= 4096) deny();
      seen.set(replayKey, current + 60);
      input.assertLive();
      const csrf = input.csrfToken();
      if (typeof csrf !== "string" || !csrf || csrf.length > 512
        || /[\r\n\u0000-\u001f\u007f]/.test(csrf)) deny();
      let response, wire;
      const controller = new AbortController();
      let timer;
      try {
        const work = (async () => {
          response = await input.fetchImpl(url, {
            method: "POST", mode: "same-origin", redirect: "error",
            credentials: "same-origin", cache: "no-store", signal: controller.signal,
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
              input.assertLive();
              if (input.csrfToken() !== csrf) deny();
              if (!(next.value instanceof Uint8Array) || next.value.length === 0) deny();
              total += next.value.byteLength;
              if (total > 15000) deny();
              parts.push(next.value);
            }
          } finally {
            if (!complete) try { Promise.resolve(reader.cancel()).catch(() => {}); }
              catch (_) { /* denied */ }
            try { reader.releaseLock(); } catch (_) { /* stream aborted */ }
          }
          const joined = new Uint8Array(total);
          let offset = 0;
          for (const part of parts) { joined.set(part, offset); offset += part.length; }
          wire = new TextDecoder("utf-8", { fatal: true }).decode(joined);
        })();
        await Promise.race([work, new Promise((_resolve, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(new Error("ZK_BROWSER_AUTHORITY_RELAY_TIMEOUT"));
          }, deadlineMs);
        })]);
      } catch (_) { deny(); }
      finally { clearTimeout(timer); controller.abort(); }
      input.assertLive();
      if (input.csrfToken() !== csrf) deny();
      let parsed;
      try { parsed = JSON.parse(wire); } catch (_) { deny(); }
      exact(parsed, [field]);
      const proof = from64(parsed[field]);
      try {
        await checkedProof(proof, field, chosenScope, challenge,
          { ownerWitnessPublicKey, ownerWitnessKeyId, catalogAuthorityPublicKey }, clock);
      } catch (_) { deny(); }
      input.assertLive();
      if (input.csrfToken() !== csrf) deny();
      return proof;
    }
    return Object.freeze({
      ownerWitnessPublicKey, ownerWitnessKeyId, catalogAuthorityPublicKey,
      ownerWitnessProbe: (input) => relay(witnessUrl, "receiptBase64", input),
      catalogProbe: (input) => relay(casUrl, "proofBase64", input),
    });
  }
  return Object.freeze({ createProbes });
}));
