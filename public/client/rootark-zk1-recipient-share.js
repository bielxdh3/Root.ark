(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-protected-http-client"));
  } else {
    root.RootarkZk1RecipientShare = factory(root.crypto, root.RootarkZk1ProtectedHttpClient);
  }
}(typeof globalThis === "object" ? globalThis : this, function (crypto, protectedHttp) {
  "use strict";

  // DEV-only ciphertext redemption. Trust roots, a current independently
  // verified V2 roster/head and recipient signing keys MUST exist beforehand.
  // Nothing supplied by the HTTP server provisions keys or local authority.
  const enc = new TextEncoder();
  const dec = new TextDecoder("utf-8", { fatal: true });
  const DOMAIN = enc.encode("Root.ark/zk-1/protected-ciphertext-share/v1\0");
  const FIELDS = ["type", "grant_id", "account_id", "compartment_id", "keyring_id",
    "object_id", "object_revision", "ciphertext_digest", "epoch", "manifest_revision",
    "manifest_digest", "issuer_device_id", "request_nonce", "issued_at", "expires_at",
    "recipient_username", "recipient_device_id"];
  const MAX_CIPHERTEXT = 4 * 1024 * 1024;
  const MAX_RESPONSE = 6 * 1024 * 1024;
  function deny() { throw new Error("ZK_SHARE_REDEMPTION_DENIED"); }
  function exact(value, keys) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== keys.length
      || keys.some((key) => !Object.hasOwn(value, key))) deny();
  }
  function bytes(value, min, max = min) {
    if (!(value instanceof Uint8Array) || value.byteLength < min
      || value.byteLength > max) deny();
    return Uint8Array.from(value);
  }
  function b64(value) {
    let binary = "";
    for (const byte of value) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(value, min, max = min) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
      || value.length > Math.ceil(max * 4 / 3) + 4) deny();
    let binary;
    try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
    const raw = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (raw.length < min || raw.length > max || b64(raw) !== value) deny();
    return raw;
  }
  function uint(value, min = 0) {
    if (!Number.isSafeInteger(value) || value < min) deny();
    return value;
  }
  function deviceName(value) {
    if (typeof value !== "string" || value.length < 1 || value.length > 64
      || /[\u0000-\u001f\u007f]/.test(value)) deny();
    return value;
  }
  function equals(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let index = 0; index < a.length; ++index) diff |= a[index] ^ b[index];
    return diff === 0;
  }
  // Exact deterministic CBOR subset for the 17-field signed grant. No tags,
  // indefinite lengths, duplicate/out-of-order map keys or noncanonical ints.
  // Bounded before allocation. The original raw bytes, not a JSON projection,
  // are what Ed25519 verifies.
  function statementFromCbor(raw) {
    const data = bytes(raw, 1, 4096);
    let offset = 0;
    const take = (length) => {
      if (!Number.isSafeInteger(length) || length < 0 || offset + length > data.length) deny();
      const part = data.subarray(offset, offset + length);
      offset += length;
      return part;
    };
    const read = (depth = 0) => {
      if (depth > 1) deny();
      const tag = take(1)[0], type = tag >> 5, additional = tag & 31;
      if (![0, 2, 3, 5].includes(type) || additional > 27) deny();
      let count;
      if (additional < 24) count = additional;
      else {
        const length = { 24: 1, 25: 2, 26: 4, 27: 8 }[additional];
        let n = 0n;
        for (const part of take(length)) n = n * 256n + BigInt(part);
        if (n > BigInt(Number.MAX_SAFE_INTEGER)) deny();
        count = Number(n);
        if ((additional === 24 && count < 24)
          || (additional === 25 && count <= 255)
          || (additional === 26 && count <= 65535)
          || (additional === 27 && count <= 0xffffffff)) deny();
      }
      if (type === 0) return count;
      if (type === 2 || type === 3) {
        if (count > 4096) deny();
        const value = take(count);
        return type === 2 ? Uint8Array.from(value) : dec.decode(value);
      }
      if (depth !== 0 || count !== FIELDS.length) deny();
      const record = Object.create(null);
      let previous = null;
      for (let i = 0; i < count; ++i) {
        const keyStart = offset;
        const key = read(1);
        const encodedKey = data.subarray(keyStart, offset);
        if (typeof key !== "string" || Object.hasOwn(record, key)) deny();
        if (previous) {
          const order = previous.length - encodedKey.length
            || (() => {
              for (let j = 0; j < previous.length; ++j) {
                if (previous[j] !== encodedKey[j]) return previous[j] - encodedKey[j];
              }
              return 0;
            })();
          if (order >= 0) deny();
        }
        previous = encodedKey;
        record[key] = read(1);
      }
      return record;
    };
    const statement = read();
    if (offset !== data.length || FIELDS.some((field) => !Object.hasOwn(statement, field))) deny();
    return statement;
  }
  function scopeBytes(scope) {
    exact(scope, ["account_id", "compartment_id", "keyring_id"]);
    return { account_id: from64(scope.account_id, 16),
      compartment_id: from64(scope.compartment_id, 1, 128),
      keyring_id: from64(scope.keyring_id, 16) };
  }
  function validStatement(s, grant, username, deviceId) {
    if (s.type !== "rootark-zk1-protected-ciphertext-share/v1"
      || !equals(bytes(s.grant_id, 32), from64(grant.grantId, 32))
      || typeof s.object_id !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(s.object_id)
      || b64(from64(s.object_id, 16)) !== s.object_id
      || uint(s.object_revision, 1) < 1
      || uint(s.epoch, 1) < 1 || uint(s.manifest_revision, 1) < 1
      || uint(s.issued_at) < 0 || uint(s.expires_at) <= s.issued_at
      || s.expires_at > s.issued_at + 86400
      || s.expires_at !== grant.expiresAt
      || s.recipient_username !== username
      || deviceName(s.recipient_device_id) !== deviceId) deny();
    deviceName(s.issuer_device_id);
    for (const key of ["account_id", "keyring_id", "ciphertext_digest",
      "manifest_digest", "request_nonce"]) bytes(s[key],
      ["account_id", "keyring_id"].includes(key) ? 16 : 32);
    bytes(s.compartment_id, 1, 128);
  }
  function trustedSnapshot(authority, s, recipientDeviceId) {
    exact(authority, ["scope", "head", "devices"]);
    exact(authority.head, ["revision", "epoch", "digest"]);
    const scope = scopeBytes(authority.scope);
    for (const field of ["account_id", "compartment_id", "keyring_id"]) {
      if (!equals(scope[field], s[field])) deny();
    }
    if (uint(authority.head.revision, 1) !== s.manifest_revision
      || uint(authority.head.epoch, 1) !== s.epoch
      || !equals(bytes(authority.head.digest, 32), s.manifest_digest)
      || !Array.isArray(authority.devices) || authority.devices.length > 128) deny();
    const active = (id) => {
      const candidates = authority.devices.filter((entry) => entry?.deviceId === id);
      if (candidates.length !== 1) deny();
      const entry = candidates[0];
      exact(entry, ["deviceId", "authorizationPublicKey", "enrolledEpoch", "revokedAtEpoch"]);
      if (deviceName(entry.deviceId) !== id || uint(entry.enrolledEpoch, 1) > s.epoch
        || entry.revokedAtEpoch !== null) deny();
      return bytes(entry.authorizationPublicKey, 32);
    };
    const recipientKey = active(recipientDeviceId);
    // Never carry a mutable provider object across crypto/network awaits.
    const stableScope = Object.fromEntries(
      Object.entries(scope).map(([key, value]) => [key, b64(value)]));
    return { scope: stableScope, issuerKey: active(s.issuer_device_id), recipientKey };
  }
  function endpoint(origin) {
    if (typeof origin !== "string") deny();
    let url;
    try { url = new URL(origin); } catch (_) { deny(); }
    if (url.href !== url.origin + "/" || url.username || url.password
      || url.search || url.hash || !["https:", "http:"].includes(url.protocol)
      || (url.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
      || (typeof location === "object" && location.origin && location.origin !== url.origin)) deny();
    return url.origin + "/zk-1/v1/share/read";
  }
  async function limitedJson(response) {
    if (response?.status !== 200 || !response.body || !response.headers
      || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(
        response.headers.get("content-type") || "")) deny();
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    let done = false;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) { done = true; break; }
        total += next.value.byteLength;
        if (total > MAX_RESPONSE) deny();
        chunks.push(next.value);
      }
    } finally {
      if (!done) { try { await reader.cancel(); } catch (_) { /* deny */ } }
      reader.releaseLock();
    }
    const joined = new Uint8Array(total);
    let at = 0;
    for (const part of chunks) { joined.set(part, at); at += part.length; }
    return JSON.parse(dec.decode(joined));
  }
  async function redeemProtectedCiphertextShare(input = {}) {
    let ciphertext;
    try {
      const keys = ["origin", "grant", "recipientUsername", "recipientDeviceId",
        "signerKey", "readIndependentAuthority",
        ...(Object.hasOwn(input, "fetchImpl") ? ["fetchImpl"] : []),
        ...(Object.hasOwn(input, "nowSeconds") ? ["nowSeconds"] : [])];
      exact(input, keys);
      exact(input.grant, ["grantId", "expiresAt", "shareStatementBase64", "shareSignatureBase64"]);
      if (!crypto?.subtle || !protectedHttp?.signProtectedContentOperation
        || typeof input.readIndependentAuthority !== "function"
        || typeof input.recipientUsername !== "string"
        || !/^[A-Za-z0-9_.@-]{1,128}$/.test(input.recipientUsername)
        || !input.signerKey || input.signerKey.type !== "private"
        || input.signerKey.algorithm?.name !== "Ed25519"
        || input.signerKey.extractable !== false
        || !input.signerKey.usages?.includes("sign")) deny();
      // An untrusted key provider must not replace the signer after its local
      // recipient-roster binding has been verified.
      const signerKey = input.signerKey;
      const fetchImpl = input.fetchImpl ?? fetch;
      const nowSeconds = input.nowSeconds ?? (() => Math.floor(Date.now() / 1000));
      if (typeof fetchImpl !== "function" || typeof nowSeconds !== "function") deny();
      const url = endpoint(input.origin);
      const grant = { grantId: input.grant.grantId, expiresAt: input.grant.expiresAt,
        shareStatementBase64: input.grant.shareStatementBase64,
        shareSignatureBase64: input.grant.shareSignatureBase64 };
      const raw = from64(grant.shareStatementBase64, 1, 4096);
      const signature = from64(grant.shareSignatureBase64, 64);
      const statement = statementFromCbor(raw);
      const recipientDeviceId = deviceName(input.recipientDeviceId);
      const recipientUsername = input.recipientUsername;
      validStatement(statement, grant, recipientUsername, recipientDeviceId);
      const currentTime = () => {
        const value = uint(nowSeconds());
        if (value >= statement.expires_at) deny();
        return value;
      };
      const first = trustedSnapshot(await input.readIndependentAuthority(),
        statement, recipientDeviceId);
      const issuer = await crypto.subtle.importKey("raw", first.issuerKey,
        "Ed25519", false, ["verify"]);
      if (!await crypto.subtle.verify("Ed25519", issuer, signature,
        Uint8Array.from([...DOMAIN, ...raw]))) deny();
      // A server can replay authentic owner-signed ciphertext while ignoring
      // the client's GET signature. Check possession of the independently
      // enrolled recipient key LOCALLY before any network request. The
      // nonextractable private CryptoKey is reused for the actual GET.
      const recipient = await crypto.subtle.importKey("raw", first.recipientKey,
        "Ed25519", false, ["verify"]);
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const localSignature = await crypto.subtle.sign("Ed25519", signerKey, challenge);
      if (!await crypto.subtle.verify("Ed25519", recipient, localSignature, challenge)) deny();
      const signed = await protectedHttp.signProtectedContentOperation({
        signerKey, scope: first.scope, deviceId: recipientDeviceId,
        operation: "get", objectId: statement.object_id,
        expectedObjectRevision: statement.object_revision,
        expectedCiphertextDigest: statement.ciphertext_digest,
        manifestRevision: statement.manifest_revision, manifestDigest: statement.manifest_digest,
        epoch: statement.epoch, nowSeconds: currentTime(), ciphertext: null,
      });
      const controller = new AbortController();
      let timer;
      try {
        let rejectDeadline;
        const deadline = new Promise((_, reject) => { rejectDeadline = reject; });
        timer = setTimeout(() => {
          controller.abort(); rejectDeadline(new Error("ZK_SHARE_DEADLINE"));
        }, 15000);
        const work = (async () => {
          const response = await fetchImpl(url, {
            method: "POST", redirect: "error", credentials: "same-origin",
            cache: "no-store", mode: "same-origin", signal: controller.signal,
            headers: { "content-type": "application/json", accept: "application/json" },
            body: JSON.stringify({ grantId: grant.grantId,
              authorization: signed.authorization, signatureBase64: signed.signatureBase64 }),
          });
          return limitedJson(response);
        })();
        const response = await Promise.race([work, deadline]);
        if (controller.signal.aborted) deny();
        exact(response, ["id", "revision", "epoch", "ciphertextBase64",
          "shareStatementBase64", "shareSignatureBase64"]);
        if (response.id !== statement.object_id
          || response.revision !== statement.object_revision || response.epoch !== statement.epoch
          || response.shareStatementBase64 !== grant.shareStatementBase64
          || response.shareSignatureBase64 !== grant.shareSignatureBase64) deny();
        ciphertext = from64(response.ciphertextBase64, 16, MAX_CIPHERTEXT);
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ciphertext));
        if (!equals(digest, statement.ciphertext_digest)) deny();
        const final = trustedSnapshot(await input.readIndependentAuthority(),
          statement, recipientDeviceId);
        if (!equals(final.issuerKey, first.issuerKey)
          || !equals(final.recipientKey, first.recipientKey)) deny();
        // No await after this final authority/expiry fence and before release.
        currentTime();
        return Object.freeze({
          schema: "rootark-zk1-recipient-ciphertext-receipt/v1",
          grantId: grant.grantId, objectId: statement.object_id,
          revision: statement.object_revision, epoch: statement.epoch,
          ciphertextBase64: response.ciphertextBase64,
          ciphertextSha256Base64: b64(digest),
          shareStatementBase64: grant.shareStatementBase64,
          shareSignatureBase64: grant.shareSignatureBase64,
          ownerGrantSignatureVerified: true,
          locallyIndependentAuthorityRequired: true,
          serverRevocationProofVerified: false,
          durableCopyProven: false, authorizesPlaintextRelease: false,
        });
      } finally {
        clearTimeout(timer);
        controller.abort();
      }
    } catch (_) { deny(); }
    finally { ciphertext?.fill(0); }
  }
  return Object.freeze({ redeemProtectedCiphertextShare });
}));
