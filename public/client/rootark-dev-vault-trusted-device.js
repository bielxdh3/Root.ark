(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto);
  } else {
    root.RootarkDevVaultTrustedDevice = factory(root.crypto);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto) {
  "use strict";
  // This is an OFFLINE, user-mediated transport between two browsers.
  // It is NOT the independently witnessed zk-1 device authorization protocol.
  const subtle = webCrypto?.subtle;
  const encoder = new TextEncoder();
  const PREFIX = "Root.ark/dev-device-recovery/v1\0";
  const ESCROW_FORMAT = "rootark-dev-device-escrow-v1";
  const REQUEST_FORMAT = "rootark-dev-device-request-v1";
  const ANSWER_FORMAT = "rootark-dev-device-answer-v1";
  const TTL = 15 * 60 * 1000;
  const MAX_BYTES = 5000;
  const B64 = /^[A-Za-z0-9_-]+$/;
  function fail() { throw new Error("Invalid or expired trusted-device recovery"); }
  function fields(obj, keys) {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) fail();
    const own = Reflect.ownKeys(obj);
    if (own.length !== keys.length || keys.some((key) => !Object.hasOwn(obj, key))
      || own.some((key) => typeof key !== "string" || !keys.includes(key))) fail();
  }
  function account(username) {
    if (typeof username !== "string" || !username.length || username.length > 256
      || /[\u0000-\u001f\u007f]/.test(username)) fail();
    return username;
  }
  function enc(raw) {
    let binary = "";
    for (const n of raw) binary += String.fromCharCode(n);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function dec(value, bytes) {
    if (typeof value !== "string" || value.length > 120 || value.length % 4 === 1
      || !B64.test(value)) fail();
    let binary;
    try {
      binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "="));
    } catch (_) { fail(); }
    const result = Uint8Array.from(binary, (v) => v.charCodeAt(0));
    if (result.length !== bytes || enc(result) !== value) fail();
    return result;
  }
  function nonce(bytes) { return enc(webCrypto.getRandomValues(new Uint8Array(bytes))); }
  function checkCommitment(value) { dec(value, 32); return value; }
  function checkTime(value, now) {
    if (!Number.isSafeInteger(value) || value < 1 || value > now + 60000) fail();
  }
  function checkRequest(request, username, now) {
    fields(request, ["format", "username", "requestId", "publicKey", "createdAt", "expiresAt"]);
    if (request.format !== REQUEST_FORMAT || request.username !== account(username)) fail();
    dec(request.requestId, 16);
    const publicBytes = dec(request.publicKey, 65);
    if (publicBytes[0] !== 4) fail();
    checkTime(request.createdAt, now);
    if (!Number.isSafeInteger(request.expiresAt)
      || request.expiresAt !== request.createdAt + TTL
      || now > request.expiresAt) fail();
    return publicBytes;
  }
  async function requestFingerprint({ username, request, now = Date.now() }) {
    if (!subtle) fail();
    checkRequest(request, username, now);
    // Must bind the exact ECDH recipient public key: a request ID by itself
    // is NOT a safe human confirmation code (public-key substitution attack).
    const canonical = [request.format, request.username, request.requestId,
      request.publicKey, request.createdAt, request.expiresAt];
    const hash = new Uint8Array(await subtle.digest("SHA-256",
      encoder.encode(PREFIX + "human-pairing-confirmation\0"
        + JSON.stringify(canonical))));
    return enc(hash.subarray(0, 16));
  }
  function confirmRequestFingerprint(provided, expected) {
    // An exact 128-bit printed code must be supplied independently from the
    // requesting browser. No auto-filling from untrusted JSON is allowed.
    return typeof provided === "string" && typeof expected === "string"
      && /^[A-Za-z0-9_-]{22}$/.test(provided)
      && /^[A-Za-z0-9_-]{22}$/.test(expected) && provided === expected;
  }
  function checkRecord(record, username) {
    fields(record, ["format", "username", "deviceId", "keyId", "iv",
      "ciphertext", "wrappingKey"]);
    if (record.format !== ESCROW_FORMAT || record.username !== account(username)) fail();
    dec(record.deviceId, 16);
    checkCommitment(record.keyId);
    dec(record.iv, 12);
    dec(record.ciphertext, 48);
    if (!record.wrappingKey || record.wrappingKey.type !== "secret"
      || record.wrappingKey.extractable !== false
      || record.wrappingKey.algorithm?.name !== "AES-GCM"
      || record.wrappingKey.algorithm?.length !== 256
      || !record.wrappingKey.usages?.includes("decrypt")) fail();
  }
  function escrowAad(record) {
    return encoder.encode(PREFIX + "escrow\0"
      + record.username + "\0" + record.deviceId + "\0" + record.keyId);
  }
  async function enrollTrustedDevice({ username, recoveryKey, keyId }) {
    if (!subtle) fail();
    account(username);
    checkCommitment(keyId);
    const raw = dec(recoveryKey, 32);
    const deviceId = nonce(16);
    const iv = webCrypto.getRandomValues(new Uint8Array(12));
    try {
      const wrappingKey = await subtle.generateKey({ name: "AES-GCM", length: 256 },
        false, ["encrypt", "decrypt"]);
      const record = { format: ESCROW_FORMAT, username, deviceId, keyId,
        iv: enc(iv), ciphertext: "", wrappingKey };
      const ciphertext = new Uint8Array(await subtle.encrypt({
        name: "AES-GCM", iv, additionalData: escrowAad(record), tagLength: 128,
      }, wrappingKey, raw));
      record.ciphertext = enc(ciphertext);
      return record;
    } finally { raw.fill(0); }
  }
  async function createRecoveryRequest({ username, now = Date.now() }) {
    if (!subtle) fail();
    account(username);
    checkTime(now, now);
    const pair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" },
      false, ["deriveBits"]);
    const publicKey = enc(new Uint8Array(await subtle.exportKey("raw", pair.publicKey)));
    return {
      privateKey: pair.privateKey,
      request: { format: REQUEST_FORMAT, username, requestId: nonce(16),
        publicKey, createdAt: now, expiresAt: now + TTL },
    };
  }
  async function sessionKey(privateKey, peerKeyBytes, request, senderKey, keyId) {
    const peer = await subtle.importKey("raw", peerKeyBytes,
      { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = new Uint8Array(await subtle.deriveBits({
      name: "ECDH", public: peer,
    }, privateKey, 256));
    try {
      const hkdfKey = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
      return subtle.deriveKey({ name: "HKDF", hash: "SHA-256",
        salt: dec(request.requestId, 16),
        info: encoder.encode(PREFIX + "handoff\0" + request.username + "\0"
          + request.requestId + "\0" + request.publicKey + "\0"
          + senderKey + "\0" + keyId) },
      hkdfKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    } finally { shared.fill(0); }
  }
  function handoffAad(request, keyId, deviceId, senderPublicKey) {
    return encoder.encode(PREFIX + "answer\0" + JSON.stringify(request) + "\0"
      + keyId + "\0" + deviceId + "\0" + senderPublicKey);
  }
  async function approveRecoveryRequest({ username, record, request, now = Date.now() }) {
    if (!subtle) fail();
    checkRecord(record, username);
    const recipientPub = checkRequest(request, username, now);
    const raw = new Uint8Array(await subtle.decrypt({
      name: "AES-GCM", iv: dec(record.iv, 12),
      additionalData: escrowAad(record), tagLength: 128,
    }, record.wrappingKey, dec(record.ciphertext, 48)));
    try {
      if (raw.length !== 32) fail();
      const sender = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" },
        false, ["deriveBits"]);
      const senderPublicKey = enc(new Uint8Array(await subtle.exportKey("raw", sender.publicKey)));
      const key = await sessionKey(sender.privateKey, recipientPub, request,
        senderPublicKey, record.keyId);
      const iv = webCrypto.getRandomValues(new Uint8Array(12));
      const ciphertext = new Uint8Array(await subtle.encrypt({
        name: "AES-GCM", iv, tagLength: 128,
        additionalData: handoffAad(request, record.keyId, record.deviceId, senderPublicKey),
      }, key, raw));
      return { format: ANSWER_FORMAT, requestId: request.requestId,
        username, keyId: record.keyId, deviceId: record.deviceId,
        request, senderPublicKey, iv: enc(iv), ciphertext: enc(ciphertext) };
    } finally { raw.fill(0); }
  }
  async function completeRecoveryRequest({ username, privateKey, request, answer,
    now = Date.now() }) {
    if (!subtle) fail();
    checkRequest(request, username, now);
    fields(answer, ["format", "requestId", "username", "keyId", "deviceId",
      "request", "senderPublicKey", "iv", "ciphertext"]);
    if (answer.format !== ANSWER_FORMAT || answer.requestId !== request.requestId
      || answer.username !== username || JSON.stringify(answer.request) !== JSON.stringify(request)) fail();
    checkCommitment(answer.keyId);
    dec(answer.deviceId, 16);
    dec(answer.iv, 12);
    dec(answer.ciphertext, 48);
    const sender = dec(answer.senderPublicKey, 65);
    if (sender[0] !== 4 || privateKey?.type !== "private"
      || privateKey.extractable !== false || privateKey.algorithm?.name !== "ECDH"
      || privateKey.algorithm?.namedCurve !== "P-256") fail();
    if (JSON.stringify(answer).length > MAX_BYTES) fail();
    const key = await sessionKey(privateKey, sender, request,
      answer.senderPublicKey, answer.keyId);
    const recovered = new Uint8Array(await subtle.decrypt({
      name: "AES-GCM", iv: dec(answer.iv, 12), tagLength: 128,
      additionalData: handoffAad(request, answer.keyId, answer.deviceId, answer.senderPublicKey),
    }, key, dec(answer.ciphertext, 48)));
    try {
      if (recovered.length !== 32) fail();
      return { recoveryKey: enc(recovered), keyId: answer.keyId };
    } finally { recovered.fill(0); }
  }
  return Object.freeze({ enrollTrustedDevice, createRecoveryRequest,
    approveRecoveryRequest, completeRecoveryRequest, requestFingerprint,
    confirmRequestFingerprint });
}));
