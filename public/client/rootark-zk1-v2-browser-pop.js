(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory(require("node:crypto").webcrypto);
  else root.RootarkZk1V2BrowserPop = factory(root.crypto);
}(typeof globalThis === "object" ? globalThis : this, function (cryptoImpl) {
  "use strict";
  // Interoperable RFC9180 base X25519/HKDF-SHA256/AES-256-GCM target PoP.
  // This answers a challenge, NEVER grants device authorization by itself.
  const subtle = cryptoImpl.subtle;
  const text = new TextEncoder();
  const fields = ["type", "version", "account_id", "compartment_id", "keyring_id",
    "operation_id", "target_device_id", "target_device_key_digest", "challenge_id",
    "issued_at", "expires_at"];
  const requestFields = ["schema", "device_id", "authorization_key_id",
    "authorization_public_key", "hpke_key_id", "hpke_public_key", "challenge", "approval"];
  const domains = { key: "Root.ark/zk-1/target-device-keys/v1\0",
    info: "Root.ark/zk-1/recovery-target-pop-info/v1\0",
    aad: "Root.ark/zk-1/recovery-target-pop-aad/v1\0",
    response: "Root.ark/zk-1/recovery-target-pop-response/v1\0" };
  function fail() { throw Error("ZK_V2_BROWSER_POP_DENIED"); }
  function exact(obj, keys) {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(obj))
      || Reflect.ownKeys(obj).length !== keys.length
      || keys.some((key) => !Object.hasOwn(obj, key))) fail();
  }
  function b64(raw) {
    let s = "";
    for (const b of raw) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function decode(value, size) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
      || value.length > Math.ceil(size * 4 / 3) + 4) fail();
    let s;
    try { s = atob(value.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { fail(); }
    const result = Uint8Array.from(s, (v) => v.charCodeAt(0));
    if (result.length !== size || b64(result) !== value) fail();
    return result;
  }
  function bytes(value, size) {
    if ((!ArrayBuffer.isView(value) && !(value instanceof ArrayBuffer))
      || value.byteLength !== size) fail();
    return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
      : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  function equal(a, b) {
    if (a.length !== b.length) return false;
    let x = 0;
    for (let i = 0; i < a.length; i++) x |= a[i] ^ b[i];
    return x === 0;
  }
  function concat(...list) {
    const size = list.reduce((s, x) => s + x.length, 0);
    if (size > 8192) fail();
    const out = new Uint8Array(size);
    let pos = 0;
    for (const x of list) { out.set(x, pos); pos += x.length; }
    return out;
  }
  function u16(n) { return Uint8Array.of(n >>> 8, n & 255); }
  // Canonical RFC8949 CBOR, restricted to the exact signed PoP dictionaries.
  // Maps sorted by encoded key length, then lexicographic encoded key bytes.
  function cbor(value) {
    const head = (major, n) => {
      if (!Number.isSafeInteger(n) || n < 0) fail();
      return n < 24 ? Uint8Array.of(major << 5 | n)
        : n < 256 ? Uint8Array.of(major << 5 | 24, n)
          : n < 65536 ? Uint8Array.of(major << 5 | 25, n >>> 8, n & 255)
            : Uint8Array.of(major << 5 | 26, n >>> 24, n >>> 16 & 255, n >>> 8 & 255, n & 255);
    };
    if (Number.isSafeInteger(value) && value >= 0) return head(0, value);
    if (typeof value === "string") {
      const s = text.encode(value);
      return concat(head(3, s.length), s);
    }
    if (value instanceof Uint8Array) return concat(head(2, value.length), value);
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const keys = Object.keys(value).map((k) => [cbor(k), k]);
      keys.sort((a, b) => {
        if (a[0].length !== b[0].length) return a[0].length - b[0].length;
        for (let i = 0; i < a[0].length; i++) {
          if (a[0][i] !== b[0][i]) return a[0][i] - b[0][i];
        }
        return 0;
      });
      return concat(head(5, keys.length), ...keys.flatMap(([encoded, key]) => [encoded, cbor(value[key])]));
    }
    fail();
  }
  async function hmac(key, message) {
    const imported = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await subtle.sign("HMAC", imported, message));
  }
  async function extract(salt, ikm) {
    return hmac(salt.length ? salt : new Uint8Array(32), ikm);
  }
  async function expand(prk, info, size) {
    if (size > 64) fail();
    let t = new Uint8Array(), out = new Uint8Array();
    for (let i = 1; out.length < size; i++) {
      t = await hmac(prk, concat(t, info, Uint8Array.of(i)));
      out = concat(out, t);
    }
    return out.slice(0, size);
  }
  async function labeledExtract(salt, suite, label, ikm) {
    return extract(salt, concat(text.encode("HPKE-v1"), suite, text.encode(label), ikm));
  }
  async function labeledExpand(prk, suite, label, info, len) {
    return expand(prk, concat(u16(len), text.encode("HPKE-v1"), suite,
      text.encode(label), info), len);
  }
  function contextFromWire(wire) {
    exact(wire, fields);
    if (wire.type !== "Root.ark-recovery-target-pop" || wire.version !== 1
      || typeof wire.target_device_id !== "string" || !wire.target_device_id
      || wire.target_device_id.length > 64) fail();
    if (!Number.isSafeInteger(wire.issued_at) || !Number.isSafeInteger(wire.expires_at)
      || wire.expires_at <= wire.issued_at
      || wire.expires_at - wire.issued_at > 300) fail();
    return { ...wire,
      account_id: decode(wire.account_id, 16),
      compartment_id: decode(wire.compartment_id, wire.compartment_id.length * 3 >>> 2),
      keyring_id: decode(wire.keyring_id, 16),
      operation_id: decode(wire.operation_id, 16),
      target_device_key_digest: decode(wire.target_device_key_digest, 32),
      challenge_id: decode(wire.challenge_id, 16) };
  }
  async function respond({ request, challenge, deviceHpkePrivateDer,
    deviceAuthorizationPrivateDer, nowSeconds }) {
    let recovered;
    try {
      exact(request, requestFields);
      if (request.schema !== "rootark-zk1-device-enrollment-request/v1"
        || request.approval !== "OWNER_MUST_VERIFY_IDENTITY_AND_FINISH_V2_POP_AND_SIGN_CURRENT_GRANT"
        || !Number.isSafeInteger(nowSeconds) || !Number.isSafeInteger(challenge?.challenge_context?.issued_at)) fail();
      exact(challenge, ["schema", "challenge_context", "enc", "ciphertext"]);
      if (challenge.schema !== "rootark-zk1-v2-browser-pop-challenge/v1") fail();
      const context = contextFromWire(challenge.challenge_context);
      if (nowSeconds < context.issued_at - 30 || nowSeconds > context.expires_at
        || context.target_device_id !== request.device_id) fail();
      const device = { device_id: request.device_id,
        hpke_key_id: decode(request.hpke_key_id, 16),
        hpke_public_key: decode(request.hpke_public_key, 32),
        authorization_key_id: decode(request.authorization_key_id, 16),
        authorization_public_key: decode(request.authorization_public_key, 32) };
      const claimedDigest = await subtle.digest("SHA-256",
        concat(text.encode(domains.key), cbor(device)));
      if (!equal(new Uint8Array(claimedDigest), context.target_device_key_digest)) fail();
      const hpkeKey = await subtle.importKey("pkcs8", deviceHpkePrivateDer,
        "X25519", false, ["deriveBits"]);
      const edKey = await subtle.importKey("pkcs8", deviceAuthorizationPrivateDer,
        "Ed25519", false, ["sign"]);
      const recipientPub = await subtle.importKey("raw", device.hpke_public_key,
        "X25519", false, []);
      const hpkeChallenge = decode(challenge.ciphertext, 48);
      const enc = decode(challenge.enc, 32);
      // A wrong recipient private key fails HPKE's authenticated AEAD tag.
      const ephemeral = await subtle.importKey("raw", enc, "X25519", false, []);
      const dh = new Uint8Array(await subtle.deriveBits(
        { name: "X25519", public: ephemeral }, hpkeKey, 256));
      const kemSuite = concat(text.encode("KEM"), u16(0x0020));
      const hpkeSuite = concat(text.encode("HPKE"), u16(0x0020), u16(1), u16(2));
      const prk = await labeledExtract(new Uint8Array(), kemSuite, "eae_prk", dh);
      const shared = await labeledExpand(prk, kemSuite, "shared_secret",
        concat(enc, device.hpke_public_key), 32);
      const info = concat(text.encode(domains.info), cbor(context));
      const aad = concat(text.encode(domains.aad), cbor(context));
      const pskHash = await labeledExtract(new Uint8Array(), hpkeSuite, "psk_id_hash", new Uint8Array());
      const infoHash = await labeledExtract(new Uint8Array(), hpkeSuite, "info_hash", info);
      const schedule = concat(Uint8Array.of(0), pskHash, infoHash);
      const secret = await labeledExtract(shared, hpkeSuite, "secret", new Uint8Array());
      const key = await labeledExpand(secret, hpkeSuite, "key", schedule, 32);
      const nonce = await labeledExpand(secret, hpkeSuite, "base_nonce", schedule, 12);
      const aead = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
      recovered = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce,
        additionalData: aad, tagLength: 128 }, aead, hpkeChallenge));
      if (recovered.length !== 32) fail();
      const sigPayload = concat(text.encode(domains.response),
        cbor({ challenge_context: context, challenge: recovered }));
      const signature = new Uint8Array(await subtle.sign("Ed25519", edKey, sigPayload));
      const ownSigner = await subtle.importKey("raw", device.authorization_public_key, "Ed25519", false, ["verify"]);
      if (!await subtle.verify("Ed25519", ownSigner, signature, sigPayload)) fail();
      return Object.freeze({ schema: "rootark-zk1-v2-browser-pop-response/v1",
        challenge_context: challenge.challenge_context, challenge: b64(recovered),
        target_signature: b64(signature) });
    } catch (_) { fail(); }
    finally { recovered?.fill(0); }
  }
  async function targetDigest(request) {
    request = JSON.parse(JSON.stringify(request));
    exact(request, requestFields);
    return b64(new Uint8Array(await subtle.digest("SHA-256",
      concat(text.encode(domains.key), cbor({
        device_id: request.device_id,
        hpke_key_id: decode(request.hpke_key_id, 16),
        hpke_public_key: decode(request.hpke_public_key, 32),
        authorization_key_id: decode(request.authorization_key_id, 16),
        authorization_public_key: decode(request.authorization_public_key, 32) })))));
  }
  return Object.freeze({ respond, targetDigest });
}));
