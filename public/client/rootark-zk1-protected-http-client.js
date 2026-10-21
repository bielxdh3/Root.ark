(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-ciphertext-download-integrity"));
  } else {
    root.RootarkZk1ProtectedHttpClient = factory(root.crypto,
      root.RootarkZk1CiphertextDownloadIntegrity);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto, download) {
  "use strict";

  // Explicitly opt-in browser client for the development-only protected
  // ciphertext HTTP plane. It neither provisions owner trust roots nor
  // authorizes key release. The independently trusted client must acquire
  // a committed head before choosing the manifest fields signed here.
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const domain = encoder.encode("Root.ark/zk-1/protected-object-operation/v1\0");
  const MAX_CIPHERTEXT = 4 * 1024 * 1024;
  const fields = ["account_id", "compartment_id", "keyring_id", "device_id",
    "operation", "object_id", "expected_object_revision", "manifest_revision",
    "manifest_digest", "epoch", "nonce", "issued_at", "expires_at", "ciphertext_digest"];
  const encodedFields = new Set(["account_id", "compartment_id", "keyring_id",
    "manifest_digest", "nonce", "ciphertext_digest"]);
  const identityFields = ["account_id", "compartment_id", "keyring_id"];
  const idPattern = /^[A-Za-z0-9_-]{22}$/;
  const b64Pattern = /^[A-Za-z0-9_-]+$/;
  const genuineSigned = new WeakMap();
  function deny() { throw new Error("ZK_BROWSER_CONTENT_UNAVAILABLE"); }
  function exact(value, keys) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== keys.length
      || keys.some((key) => !Object.hasOwn(value, key))) deny();
  }
  function copy(raw, min, max = min) {
    if (!ArrayBuffer.isView(raw) && !(raw instanceof ArrayBuffer)) deny();
    const output = raw instanceof ArrayBuffer ? new Uint8Array(raw.slice(0))
      : new Uint8Array(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength));
    if (output.length < min || output.length > max) deny();
    return output;
  }
  function b64(bytes) {
    let binary = "";
    for (const value of bytes) binary += String.fromCharCode(value);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(input, min, max = min) {
    if (typeof input !== "string" || !b64Pattern.test(input)
      || input.length > Math.ceil(max * 4 / 3) + 4) deny();
    let binary;
    try {
      binary = atob(input.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(input.length / 4) * 4, "="));
    } catch (_) { deny(); }
    const raw = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (raw.length < min || raw.length > max || b64(raw) !== input) deny();
    return raw;
  }
  function unsigned(value) {
    if (!Number.isSafeInteger(value) || value < 0) deny();
    return value;
  }
  function positive(value) {
    if (unsigned(value) < 1) deny();
    return value;
  }
  function id(value) {
    if (typeof value !== "string" || !idPattern.test(value)) deny();
    from64(value, 16);
    return value;
  }
  function header(major, value) {
    const n = BigInt(unsigned(value));
    const initial = major << 5;
    if (n < 24n) return Uint8Array.of(initial + Number(n));
    if (n <= 0xffn) return Uint8Array.of(initial + 24, Number(n));
    if (n <= 0xffffn) return Uint8Array.of(initial + 25,
      Number(n >> 8n), Number(n & 255n));
    if (n <= 0xffffffffn) return Uint8Array.of(initial + 26,
      Number((n >> 24n) & 255n), Number((n >> 16n) & 255n),
      Number((n >> 8n) & 255n), Number(n & 255n));
    return Uint8Array.of(initial + 27, ...Array.from({ length: 8 },
      (_, index) => Number((n >> BigInt(56 - 8 * index)) & 255n)));
  }
  function join(parts, limit = 8192) {
    const total = parts.reduce((sum, item) => sum + item.byteLength, 0);
    if (total > limit) deny();
    const result = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.byteLength; }
    return result;
  }
  function encodeItem(value) {
    if (value === null) return Uint8Array.of(0xf6);
    if (Number.isSafeInteger(value) && value >= 0) return header(0, value);
    if (typeof value === "string") {
      const text = encoder.encode(value);
      return join([header(3, text.byteLength), text]);
    }
    if (value instanceof Uint8Array) return join([header(2, value.byteLength), value]);
    deny();
  }
  function cborSignedMessage(payload) {
    const entries = Object.entries(payload).map(([key, value]) => ({
      key: encodeItem(key), val: encodeItem(value),
    }));
    // For this fixed, all-text-key map, length then encoded-byte order is
    // identical to RFC 8949's deterministic encoded-byte lexicographic order.
    // This encoder is deliberately NOT a general-purpose CBOR implementation.
    entries.sort((a, b) => a.key.length - b.key.length
      || (() => {
        for (let i = 0; i < a.key.length; i += 1) {
          if (a.key[i] !== b.key[i]) return a.key[i] - b.key[i];
        }
        return 0;
      })());
    return join([domain, header(5, entries.length),
      ...entries.flatMap((entry) => [entry.key, entry.val])]);
  }
  async function signProtectedContentOperation(input) {
    try {
      exact(input, ["signerKey", "scope", "deviceId", "operation", "objectId",
        "expectedObjectRevision", "manifestRevision", "manifestDigest", "epoch",
        "nowSeconds", "ciphertext"]);
      if (!webCrypto?.subtle || !webCrypto?.getRandomValues
        || input.signerKey?.type !== "private"
        || input.signerKey?.extractable !== false
        || input.signerKey?.algorithm?.name !== "Ed25519"
        || !input.signerKey?.usages?.includes("sign")) deny();
      exact(input.scope, identityFields);
      const op = input.operation;
      if (!["put", "get"].includes(op)) deny();
      const now = unsigned(input.nowSeconds);
      if (now + 45 > Number.MAX_SAFE_INTEGER) deny();
      // Snapshot every caller-controlled scalar/reference before the first
      // asynchronous crypto operation; changing a form field during hashing
      // must never retarget the signed permission or associated ciphertext.
      const signerKey = input.signerKey;
      const deviceId = input.deviceId;
      const objectId = id(input.objectId);
      const expectedRevision = input.expectedObjectRevision === null ? null
        : positive(input.expectedObjectRevision);
      const revision = positive(input.manifestRevision);
      const epoch = positive(input.epoch);
      const compartment = from64(input.scope.compartment_id, 1, 128);
      const trustedScope = {
        account_id: from64(input.scope.account_id, 16),
        compartment_id: compartment,
        keyring_id: from64(input.scope.keyring_id, 16),
      };
      const manifestDigest = copy(input.manifestDigest, 32);
      const nonce = webCrypto.getRandomValues(new Uint8Array(32));
      if (typeof deviceId !== "string" || deviceId.length < 1
        || deviceId.length > 64 || /[\u0000-\u001f\u007f]/.test(deviceId)) deny();
      let sealed = null;
      let ciphertextDigest = null;
      if (op === "put") {
        sealed = copy(input.ciphertext, 16, MAX_CIPHERTEXT);
        ciphertextDigest = new Uint8Array(await webCrypto.subtle.digest("SHA-256", sealed));
      } else if (input.ciphertext !== null || expectedRevision !== null) deny();
      const request = {
        ...trustedScope, device_id: deviceId, operation: op, object_id: objectId,
        expected_object_revision: op === "put" ? expectedRevision : null,
        manifest_revision: revision,
        manifest_digest: manifestDigest, epoch,
        nonce, issued_at: now, expires_at: now + 45,
        ciphertext_digest: ciphertextDigest,
      };
      const signature = new Uint8Array(await webCrypto.subtle.sign(
        "Ed25519", signerKey, cborSignedMessage(request)));
      if (signature.length !== 64) deny();
      const wireAuth = {};
      for (const field of fields) {
        const value = request[field];
        wireAuth[field] = encodedFields.has(field) && value !== null ? b64(value) : value;
      }
      const wire = Object.freeze({ authorization: Object.freeze(wireAuth),
        signatureBase64: b64(signature),
        ...(op === "put" ? { ciphertextBase64: b64(sealed) } : {}) });
      genuineSigned.set(wire, { op, request: wire, objectId: request.object_id });
      return wire;
    } catch (_) { deny(); }
  }
  function httpEndpoint(origin, op) {
    if (typeof origin !== "string" || !origin) deny();
    let url;
    try { url = new URL(origin); } catch (_) { deny(); }
    if (url.href !== url.origin + "/" || url.username || url.password
      || url.search || url.hash || !["http:", "https:"].includes(url.protocol)) deny();
    if (url.protocol === "http:"
      && !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) deny();
    if (typeof location === "object" && location?.origin && url.origin !== location.origin) deny();
    return url.origin + "/zk-1/v1/content/" + (op === "get" ? "read" : "put");
  }
  async function readLimited(response, limit) {
    if (!response || !response.body || !response.headers
      || !/^(?:application\/json)(?:;\s*charset=utf-8)?$/i.test(
        response.headers.get("content-type") || "")) deny();
    const reader = response.body.getReader();
    const pieces = [];
    let bytes = 0;
    let completed = false;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) { completed = true; break; }
        bytes += next.value.byteLength;
        if (bytes > limit) deny();
        pieces.push(next.value);
      }
    } finally {
      if (!completed) {
        try { await reader.cancel(); } catch (_) { /* network failure is denial */ }
      }
      reader.releaseLock();
    }
    return JSON.parse(decoder.decode(join(pieces, limit)));
  }
  async function post(request, op, origin, fetchImpl) {
    const brand = genuineSigned.get(request);
    if (!brand || brand.op !== op || typeof fetchImpl !== "function") deny();
    const url = httpEndpoint(origin, op);
    let response;
    try {
      response = await fetchImpl(url, {
        method: "POST", redirect: "error", credentials: "same-origin",
        cache: "no-store", mode: "same-origin",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(brand.request),
      });
      if ((op === "put" && ![200, 201].includes(response.status))
        || (op === "get" && response.status !== 200)) deny();
      return await readLimited(response, op === "put" ? 2048 : 6 * 1024 * 1024);
    } catch (_) { deny(); }
  }
  async function postProtectedCiphertextPut({ origin, request, fetchImpl = fetch } = {}) {
    try {
      const decoded = await post(request, "put", origin, fetchImpl);
      exact(decoded, ["id", "revision"]);
      if (decoded.id !== genuineSigned.get(request).objectId) deny();
      return Object.freeze({ id: decoded.id, revision: positive(decoded.revision) });
    } catch (_) { deny(); }
  }
  async function postProtectedCiphertextRead({ origin, request, fetchImpl = fetch,
    expectedObjectRevision, expectedRoot, cek, metadata } = {}) {
    try {
      const commitment = copy(expectedRoot, 32);
      const revision = positive(expectedObjectRevision);
      const response = await post(request, "get", origin, fetchImpl);
      exact(response, ["id", "revision", "epoch", "ciphertextBase64"]);
      if (response.id !== genuineSigned.get(request).objectId
        || response.revision !== revision
        || response.epoch !== metadata?.epoch
        || metadata.object_id !== response.id) deny();
      const ciphertext = from64(response.ciphertextBase64, 16, MAX_CIPHERTEXT);
      // Do not use a root supplied by the HTTP response. Caller must pass a
      // previously independently authenticated ciphertext commitment.
      const checked = await download.inspectCiphertextDownload({
        frames: [{ index: 0, bytes: ciphertext }],
        expectedChunkCount: 1, expectedRoot: commitment,
        maxCiphertextBytes: MAX_CIPHERTEXT,
      });
      return await download.decryptVerifiedCiphertext({
        inspection: checked, cek, metadata,
      });
    } catch (_) { deny(); }
  }
  return Object.freeze({ signProtectedContentOperation,
    postProtectedCiphertextPut, postProtectedCiphertextRead });
}));
