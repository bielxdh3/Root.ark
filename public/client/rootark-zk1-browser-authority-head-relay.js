(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-protected-http-client"));
  } else {
    root.RootarkZk1BrowserAuthorityHeadRelay = factory(root.crypto,
      root.RootarkZk1ProtectedHttpClient);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto, contentHttp) {
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
  function from64(value, maximum = 8192) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
      || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 4 * 1024 * 1024
      || value.length > Math.ceil(maximum * 4 / 3) + 4) deny();
    let binary;
    try {
      binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "="));
    } catch (_) { deny(); }
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (!bytes.length || bytes.length > maximum || to64(bytes) !== value) deny();
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
    if (length > 11 * 1024 * 1024) deny();
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
    if (value === false) return Uint8Array.of(0xf4);
    if (value === true) return Uint8Array.of(0xf5);
    if (typeof value === "number") return value >= 0
      ? head(0, value) : head(1, -1 - value);
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
  function decode(raw, maximum = 8192) {
    strictBytes(raw, 1, maximum);
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
      if (tag === 0xf4) return false;
      if (tag === 0xf5) return true;
      if (![0, 1, 2, 3, 4, 5].includes(major) || info > 27) deny();
      const count = info < 24 ? info : (() => {
        const n = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
        if (!n) deny();
        let size = 0;
        for (const byte of take(n)) size = size * 256 + byte;
        return uint(size, 0, major === 0 ? Number.MAX_SAFE_INTEGER : maximum);
      })();
      if (major === 0) return count;
      if (major === 1) return -1 - count;
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
  const V2_RECEIPT = encoder.encode("Root.ark/zk-1/opaque-checkpoint-remote/receipt/v2\0");
  const V2_OWNER = encoder.encode("Root.ark/zk-1/opaque-checkpoint-remote/owner-approval/v2\0");
  const V2_HEAD = encoder.encode("Root.ark/zk-1/opaque-catalog-head/v1\0");
  const V2_CHECKPOINT = encoder.encode("Root.ark/zk-1/opaque-catalog-checkpoint-sign/v2\0");
  const V2_DIGEST = encoder.encode("Root.ark/zk-1/opaque-catalog-checkpoint-digest/v2\0");
  const V2_LEAF = encoder.encode("Root.ark/zk-1/opaque-catalog-archive-leaf/v2\0");
  const V2_PAGE = encoder.encode("Root.ark/zk-1/opaque-catalog-page/v1\0");
  const V2_GRANT = encoder.encode("Root.ark/zk-1/browser-owner-device-grant/v1\0");
  const V2_GRANT_FIELDS = ["schema", ...SCOPE, "device_id", "authorization_key_id",
    "authorization_public_key", "manifest_revision", "manifest_digest",
    "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
  const V2_HISTORY_ENDORSEMENT = encoder.encode(
    "Root.ark/zk-1/v2-historical-signer-endorsement/v1\0");
  const V2_HISTORY_FIELDS = ["schema", ...SCOPE, "sequence", "intent_sha256",
    "operation_id", "head_digest", "checkpoint_digest", "signer_device_id",
    "signer_public_key", "manifest_revision", "manifest_digest", "epoch",
    "genesis_digest", "witness_signer_spki_sha256"];
  const V2_RECEIPT_FIELDS = ["type", ...SCOPE, "role", "state", "sequence",
    "head_digest", "checkpoint_digest", "operation_id", "cas_signer_fp",
    "floor_signer_fp", "nonce", "issued_at"];
  const V2_OWNER_FIELDS = ["type", ...SCOPE, "operation_id", "checkpoint_digest",
    "previous_sequence", "previous_digest", "previous_checkpoint_digest",
    "final_sequence", "final_digest", "cas_signer_fp", "floor_signer_fp",
    "checkpoint_signer_fp", "issued_at"];
  const V2_CHECKPOINT_FIELDS = ["type", ...SCOPE, "previous_sequence", "previous_digest",
    "final_sequence", "final_digest", "previous_checkpoint_digest",
    "archive_root", "record_count", "issued_at"];
  const V2_HEADER_FIELDS = ["type", ...SCOPE, "sequence", "previous_digest",
    "manifest_revision", "manifest_digest", "epoch", "signer_device_id",
    "total_count", "page_digests", "issued_at"];
  // An inventory's public rows are labels only. Its ciphertext commitments and
  // live permission context remain private until verified by both authorities.
  const verifiedV2 = new WeakMap();
  async function digest(...parts) {
    return new Uint8Array(await webCrypto.subtle.digest("SHA-256", append(...parts)));
  }
  function scoped(value, scope) {
    for (const field of SCOPE) if (!equal(strictBytes(value[field],
      field === "compartment_id" ? 1 : 16,
      field === "compartment_id" ? 128 : 16), scope[field])) deny();
  }
  // Read-only browser boundary for a complete owner-approved signed 129..N chain.
  // Its only origin is the offline owner-provided sequence; fresh signed dual
  // remote heads decide whether its LAST checkpoint is currently finalized.
  // The server only relays nonce-bound independently signed CAS and floor heads.
  async function readFinalizedV2(input) {
    const chainProvided = Object.hasOwn(input || {}, "signedIntents");
    const grantProvided = Object.hasOwn(input || {}, "signedDeviceGrant");
    const historicalProofsProvided = Object.hasOwn(input || {}, "historicalSignerEndorsements");
    exact(input, ["origin", "fetchImpl", "assertLive", "csrfToken", "scope",
      "previousDigest", "previousCheckpointDigest", "ownerRevision", "ownerDigest",
      "ownerEpoch", "ownerDeviceId", "signedIntent", "casKeyRaw", "casSpkiPin",
      "floorKeyRaw", "floorSpkiPin", "checkpointKeyRaw", "checkpointSpkiPin",
      "deviceKeyRaw", "deviceSpkiPin",
      ...(chainProvided ? ["signedIntents"] : []),
      ...(grantProvided ? ["signedDeviceGrant", "ownerKeyRaw", "ownerSpkiPin"] : []),
      ...(historicalProofsProvided ? ["historicalSignerEndorsements",
        "independentGenesisDigest", "independentWitnessSpkiSha256"] : [])]);
    if (!webCrypto?.subtle || !webCrypto.getRandomValues
      || typeof input.fetchImpl !== "function"
      || typeof input.assertLive !== "function"
      || typeof input.csrfToken !== "function"
      || typeof AbortController !== "function") deny();
    exact(input.scope, SCOPE);
    const scope = Object.fromEntries(SCOPE.map((name) => {
      const b = from64(input.scope[name]);
      strictBytes(b, name === "compartment_id" ? 1 : 16,
        name === "compartment_id" ? 128 : 16);
      return [name, b];
    }));
    let previous = copy(input.previousDigest, 32);
    let previousCheckpoint = copy(input.previousCheckpointDigest, 32);
    if (previous.every((v) => v === 0) || previousCheckpoint.every((v) => v === 0)) deny();
    const ownerDigest = copy(input.ownerDigest, 32);
    const revision = uint(input.ownerRevision, 1), epoch = uint(input.ownerEpoch, 1);
    if (typeof input.ownerDeviceId !== "string" || !input.ownerDeviceId) deny();
    const url = urlFrom(input.origin, "v2-heads");
    input.assertLive();
    const [casKey, floorKey, checkpointKey, deviceKey] = await Promise.all([
      verifyKey(input.casKeyRaw, input.casSpkiPin),
      verifyKey(input.floorKeyRaw, input.floorSpkiPin),
      verifyKey(input.checkpointKeyRaw, input.checkpointSpkiPin),
      verifyKey(input.deviceKeyRaw, input.deviceSpkiPin),
    ]);
    const [casFp, floorFp, checkpointFp] = [
      input.casSpkiPin, input.floorSpkiPin, input.checkpointSpkiPin];
    if (equal(casFp, floorFp) || equal(casFp, checkpointFp)
      || equal(floorFp, checkpointFp)) deny();
    // Capture the entire caller-owned chain before the first awaited signature.
    const lastIntentRaw = strictBytes(input.signedIntent, 1, 10 * 1024 * 1024).slice();
    const chain = chainProvided ? input.signedIntents : [lastIntentRaw];
    if (!Array.isArray(chain) || !chain.length || chain.length > 128) deny();
    const signedChain = chain.map((raw) => strictBytes(raw, 1, 10 * 1024 * 1024).slice());
    if (!equal(signedChain.at(-1), lastIntentRaw)) deny();
    if (historicalProofsProvided && (!grantProvided
      || !Array.isArray(input.historicalSignerEndorsements)
      || input.historicalSignerEndorsements.length !== signedChain.length
      || input.historicalSignerEndorsements.length > 128)) deny();
    const historicalProofs = historicalProofsProvided
      ? input.historicalSignerEndorsements.map((entry) => {
        exact(entry, [...V2_HISTORY_FIELDS, "signature"]);
        return Object.fromEntries([...V2_HISTORY_FIELDS, "signature"]
          .map((field) => [field, entry[field]]));
      }) : null;
    const independentGenesis = historicalProofsProvided
      ? copy(input.independentGenesisDigest, 32) : null;
    const independentWitness = historicalProofsProvided
      ? copy(input.independentWitnessSpkiSha256, 32) : null;
    // A successor demands the independently pinned CURRENT owner-signed device
    // grant. The 129-only legacy opt-in preserves its earlier input contract.
    if (signedChain.length > 1 && !grantProvided) deny();
    let ownerKey = null;
    if (grantProvided) {
      exact(input.signedDeviceGrant, [...V2_GRANT_FIELDS, "signature"]);
      // Copy only signed scalar fields before WebCrypto yields. Later edits to
      // the UI's grant object cannot change which authorization was checked.
      const grant = Object.fromEntries([...V2_GRANT_FIELDS, "signature"]
        .map((name) => [name, input.signedDeviceGrant[name]]));
      ownerKey = await verifyKey(input.ownerKeyRaw, input.ownerSpkiPin);
      const frozenGrant = Object.fromEntries(V2_GRANT_FIELDS.map((name) => [name, grant[name]]));
      if (grant.schema !== "rootark-zk1-browser-owner-device-grant/v1"
        || grant.manifest_revision !== revision || grant.manifest_digest !== to64(ownerDigest)
        || grant.current_epoch !== epoch || grant.revoked_at_epoch !== null
        || uint(grant.enrolled_epoch, 1) > epoch
        || grant.device_id !== input.ownerDeviceId
        || !equal(from64(grant.authorization_public_key, 32), copy(input.deviceKeyRaw, 32))) deny();
      scoped(Object.fromEntries(SCOPE.map((name) => [name,
        from64(grant[name], name === "compartment_id" ? 128 : 16)])), scope);
      strictBytes(from64(grant.authorization_key_id), 16);
      if (!await webCrypto.subtle.verify("Ed25519", ownerKey,
        from64(grant.signature, 64), append(V2_GRANT,
          encoder.encode(JSON.stringify(frozenGrant))))) deny();
    }
    let sequence = 128;
    let previousOperation = null;
    let operation, headDigest, checkpointDigest, count, rows, privateRows;
    for (const [intentIndex, intentRaw] of signedChain.entries()) {
    const intent = decode(intentRaw, 10 * 1024 * 1024);
    const nextSequence = sequence + 1;
    exact(intent, ["type", ...SCOPE, "operation_id", "checkpoint_bytes",
      "checkpoint_signature", "records", "previous_sequence", "previous_digest",
      "previous_checkpoint_digest", "owner_approval", "owner_signature", "owner_evidence",
      ...(nextSequence > 129 ? ["predecessor_cas_receipt", "predecessor_floor_receipt"] : [])]);
    scoped(intent, scope);
    if (intent.type !== "rootark-opaque-checkpoint-remote-intent/v2"
      || intent.previous_sequence !== sequence
      || !equal(strictBytes(intent.previous_digest, 32), previous)
      || !equal(strictBytes(intent.previous_checkpoint_digest, 32), previousCheckpoint)
      || !Array.isArray(intent.records) || intent.records.length !== 1) deny();
    const ownerEvidence = decode(strictBytes(intent.owner_evidence, 1,
      2 * 1024 * 1024), 2 * 1024 * 1024);
    exact(ownerEvidence, ["baseManifest", "baseReceipt", "transitions",
      "packageEnvelopes", "witnessHeadRaw"]);
    strictBytes(ownerEvidence.witnessHeadRaw, 1, 8192);
    if (!Array.isArray(ownerEvidence.transitions)
      || !Array.isArray(ownerEvidence.packageEnvelopes)) deny();
    operation = strictBytes(intent.operation_id, 32);
    const record = intent.records[0];
    exact(record, ["sequence", "header", "signature", "page_bodies"]);
    if (record.sequence !== nextSequence || !Array.isArray(record.page_bodies)
      || record.page_bodies.length > 128) deny();
    const rawHead = strictBytes(record.header, 1, 16384);
    const rawSignature = strictBytes(record.signature, 64);
    const header = decode(rawHead, 16384);
    exact(header, V2_HEADER_FIELDS); scoped(header, scope);
    if (header.type !== "rootark-zk1-opaque-catalog/v1" || header.sequence !== nextSequence
      || !equal(strictBytes(header.previous_digest, 32), previous)
      || (!historicalProofs && (!equal(strictBytes(header.manifest_digest, 32), ownerDigest)
        || header.manifest_revision !== revision || header.epoch !== epoch
        || header.signer_device_id !== input.ownerDeviceId))
      || !Array.isArray(header.page_digests)
      || header.page_digests.length !== record.page_bodies.length
      || uint(header.total_count, 0, 4096) > 4096
      || header.page_digests.length !== Math.ceil(header.total_count / 32)) deny();
    let historicalSigner = deviceKey;
    if (historicalProofs) {
      const certificate = historicalProofs[intentIndex];
      const statement = Object.fromEntries(V2_HISTORY_FIELDS.map((f) => [f, certificate[f]]));
      if (certificate.schema !== "rootark-zk1-v2-historical-signer-endorsement/v1"
        || certificate.sequence !== nextSequence
        || certificate.signer_device_id !== header.signer_device_id
        || certificate.manifest_revision !== header.manifest_revision
        || certificate.epoch !== header.epoch
        || !equal(from64(certificate.manifest_digest, 32),
          strictBytes(header.manifest_digest, 32))
        || !equal(from64(certificate.genesis_digest, 32), independentGenesis)
        || !equal(from64(certificate.witness_signer_spki_sha256, 32), independentWitness)
        || !equal(from64(certificate.intent_sha256, 32), await digest(intentRaw))
        || !equal(from64(certificate.operation_id, 32), operation)) deny();
      scoped(Object.fromEntries(SCOPE.map((f) => [f,
        from64(certificate[f], f === "compartment_id" ? 128 : 16)])), scope);
      const expectedSigner = from64(certificate.signer_public_key, 32);
      historicalSigner = await webCrypto.subtle.importKey("raw", expectedSigner,
        "Ed25519", false, ["verify"]);
      if (!await webCrypto.subtle.verify("Ed25519", ownerKey,
        from64(certificate.signature, 64), append(V2_HISTORY_ENDORSEMENT,
          encoder.encode(JSON.stringify(statement))))) deny();
    }
    if (!await webCrypto.subtle.verify("Ed25519", historicalSigner, rawSignature,
      append(V2_HEAD, rawHead))) deny();
    count = 0; let last = null;
    rows = []; privateRows = [];
    for (let index = 0; index < record.page_bodies.length; index++) {
      const raw = strictBytes(record.page_bodies[index], 1, 16384);
      if (!equal(await digest(V2_PAGE, raw), strictBytes(header.page_digests[index], 32))) deny();
      const page = decode(raw, 16384);
      if (!Array.isArray(page) || page.length < 1 || page.length > 32
        || (index < record.page_bodies.length - 1 && page.length !== 32)) deny();
      for (const row of page) {
        exact(row, ["object_id", "revision", "epoch", "ciphertext_digest",
          "metadata_ciphertext"]);
        if (typeof row.object_id !== "string"
          || !/^[A-Za-z0-9_-]{22}$/.test(row.object_id)
          || to64(from64(row.object_id)) !== row.object_id
          || !Number.isSafeInteger(row.revision) || row.revision < 1
          || !Number.isSafeInteger(row.epoch) || row.epoch < 1
          || row.epoch > epoch
          || strictBytes(row.ciphertext_digest, 32).length !== 32
          || strictBytes(row.metadata_ciphertext, 284).length !== 284) deny();
        const order = row.object_id + ":" + String(row.revision).padStart(17, "0");
        if (last !== null && order <= last) deny();
        last = order; rows.push(Object.freeze({
          objectId: row.object_id, revision: row.revision, epoch: row.epoch }));
        privateRows.push(Object.freeze({ objectId: row.object_id,
          revision: row.revision, epoch: row.epoch,
          ciphertextDigest: copy(row.ciphertext_digest, 32) }));
        count++;
      }
    }
    if (count !== header.total_count) deny();
    headDigest = await digest(V2_HEAD, rawHead, rawSignature);
    const checkpointBytes = strictBytes(intent.checkpoint_bytes, 1, 16384);
    const checkpointSig = strictBytes(intent.checkpoint_signature, 64);
    if (!await webCrypto.subtle.verify("Ed25519", checkpointKey, checkpointSig,
      append(V2_CHECKPOINT, checkpointBytes))) deny();
    checkpointDigest = await digest(V2_DIGEST, checkpointBytes, checkpointSig);
    if (historicalProofs && (!equal(from64(historicalProofs[intentIndex].head_digest, 32), headDigest)
      || !equal(from64(historicalProofs[intentIndex].checkpoint_digest, 32), checkpointDigest))) deny();
    const checkpoint = decode(checkpointBytes, 16384);
    exact(checkpoint, V2_CHECKPOINT_FIELDS); scoped(checkpoint, scope);
    if (checkpoint.type !== "rootark-zk1-opaque-catalog-checkpoint/v2"
      || checkpoint.previous_sequence !== sequence || checkpoint.final_sequence !== nextSequence
      || checkpoint.record_count !== 1
      || !equal(strictBytes(checkpoint.previous_digest, 32), previous)
      || !equal(strictBytes(checkpoint.previous_checkpoint_digest, 32), previousCheckpoint)
      || !equal(strictBytes(checkpoint.final_digest, 32), headDigest)
      || !equal(strictBytes(checkpoint.archive_root, 32),
        await digest(V2_LEAF, canonical(record)))) deny();
    const approvalBytes = strictBytes(intent.owner_approval, 1, 4096);
    const approval = decode(approvalBytes, 4096);
    exact(approval, V2_OWNER_FIELDS); scoped(approval, scope);
    if (approval.type !== "rootark-opaque-checkpoint-remote-owner-approval/v2"
      || approval.previous_sequence !== sequence || approval.final_sequence !== nextSequence
      || !equal(strictBytes(approval.operation_id, 32), operation)
      || !equal(strictBytes(approval.previous_digest, 32), previous)
      || !equal(strictBytes(approval.previous_checkpoint_digest, 32), previousCheckpoint)
      || !equal(strictBytes(approval.final_digest, 32), headDigest)
      || !equal(strictBytes(approval.checkpoint_digest, 32), checkpointDigest)
      || !equal(strictBytes(approval.cas_signer_fp, 32), casFp)
      || !equal(strictBytes(approval.floor_signer_fp, 32), floorFp)
      || !equal(strictBytes(approval.checkpoint_signer_fp, 32), checkpointFp)
      || !await webCrypto.subtle.verify("Ed25519", deviceKey,
        strictBytes(intent.owner_signature, 64), append(V2_OWNER, approvalBytes))) deny();
    if (nextSequence > 129) {
      // Historical predecessor endorsements are immutable evidence. Freshness
      // belongs to the CURRENT remote head challenge checked below.
      for (const [field, role, signer] of [
        ["predecessor_cas_receipt", "CAS", casKey],
        ["predecessor_floor_receipt", "FLOOR", floorKey],
      ]) {
        const proof = decode(strictBytes(intent[field], 1, 4096));
        exact(proof, [...V2_RECEIPT_FIELDS, "signature"]); scoped(proof, scope);
        if (proof.type !== "rootark-opaque-checkpoint-remote-receipt/v2"
          || proof.role !== role || proof.state !== "FINALIZED"
          || proof.sequence !== sequence
          || !equal(strictBytes(proof.head_digest, 32), previous)
          || !equal(strictBytes(proof.checkpoint_digest, 32), previousCheckpoint)
          || !equal(strictBytes(proof.operation_id, 32), previousOperation)
          || !equal(strictBytes(proof.cas_signer_fp, 32), casFp)
          || !equal(strictBytes(proof.floor_signer_fp, 32), floorFp)) deny();
        uint(proof.issued_at, 0); strictBytes(proof.nonce, 32);
        const predecessorStatement = Object.fromEntries(
          V2_RECEIPT_FIELDS.map((name) => [name, proof[name]]));
        if (!await webCrypto.subtle.verify("Ed25519", signer,
          strictBytes(proof.signature, 64),
          append(V2_RECEIPT, canonical(predecessorStatement)))) deny();
      }
    }
    previous = headDigest;
    previousCheckpoint = checkpointDigest;
    previousOperation = operation;
    sequence = nextSequence;
    input.assertLive();
    }
    input.assertLive();
    const csrf = input.csrfToken();
    if (typeof csrf !== "string" || !csrf || csrf.length > 512) deny();
    async function recheckCurrent() {
    const nonce = webCrypto.getRandomValues(new Uint8Array(32));
    const controller = new AbortController();
    let timer;
    let response;
    try {
      const deadline = new Promise((_ok, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new Error("timeout")); }, 10000);
      });
      response = await Promise.race([input.fetchImpl(url, {
        method: "POST", mode: "same-origin", credentials: "same-origin",
        redirect: "error", cache: "no-store", signal: controller.signal,
        headers: { "content-type": "application/json", accept: "application/json",
          "x-csrf-token": csrf },
        body: JSON.stringify({ nonce: to64(nonce) }),
      }), deadline]);
      input.assertLive();
      if (csrf !== input.csrfToken() || response.status !== 200
        || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(
          response.headers?.get("content-type") || "")) deny();
      // Streamed size limit and a single absolute deadline covering headers and
      // body prevent a compromised same-origin proxy from exhausting memory.
      if (!response.body || typeof response.body.getReader !== "function") deny();
      const readBody = async () => {
        const reader = response.body.getReader();
        const chunks = []; let count = 0;
        try {
          while (true) {
            const part = await reader.read();
            if (part.done) break;
            if (!(part.value instanceof Uint8Array) || part.value.length === 0) deny();
            count += part.value.length;
            if (count > 12000) deny();
            chunks.push(part.value);
          }
        } finally {
          try { reader.releaseLock(); } catch (_) { /* aborted */ }
        }
        const joined = new Uint8Array(count);
        let position = 0;
        for (const chunk of chunks) { joined.set(chunk, position); position += chunk.length; }
        return decoder.decode(joined);
      };
      const body = await Promise.race([readBody(), deadline]);
      const result = JSON.parse(body);
      exact(result, ["casProofBase64", "floorProofBase64"]);
      for (const [field, role, signer] of [
        ["casProofBase64", "CAS", casKey], ["floorProofBase64", "FLOOR", floorKey],
      ]) {
        const proof = decode(from64(result[field]));
        exact(proof, [...V2_RECEIPT_FIELDS, "signature"]); scoped(proof, scope);
        if (proof.type !== "rootark-opaque-checkpoint-remote-receipt/v2"
          || proof.role !== role || proof.state !== "FINALIZED"
          || proof.sequence !== sequence || !equal(strictBytes(proof.nonce, 32), nonce)
          || Math.abs(uint(proof.issued_at) - Math.floor(Date.now() / 1000)) > 30
          || !equal(strictBytes(proof.operation_id, 32), operation)
          || !equal(strictBytes(proof.head_digest, 32), headDigest)
          || !equal(strictBytes(proof.checkpoint_digest, 32), checkpointDigest)
          || !equal(strictBytes(proof.cas_signer_fp, 32), casFp)
          || !equal(strictBytes(proof.floor_signer_fp, 32), floorFp)) deny();
        const signed = Object.fromEntries(V2_RECEIPT_FIELDS.map((n) => [n, proof[n]]));
        if (!await webCrypto.subtle.verify("Ed25519", signer,
          strictBytes(proof.signature, 64), append(V2_RECEIPT, canonical(signed)))) deny();
      }
      input.assertLive();
      if (csrf !== input.csrfToken()) deny();
    } catch (_) { deny(); }
    finally { clearTimeout(timer); controller.abort(); }
    }
    await recheckCurrent();
      const confirmed = Object.freeze({ sequence, digest: to64(headDigest),
        checkpointDigest: to64(checkpointDigest), totalCount: count,
        rows: Object.freeze(rows), independentlyFinalized: true,
        productionDurabilityProven: false });
      verifiedV2.set(confirmed, Object.freeze({
        url: input.origin + "zk-1/v1/content/read", fetchImpl: input.fetchImpl,
        assertLive: input.assertLive, csrfToken: input.csrfToken, csrf,
        scope: Object.freeze(Object.fromEntries(SCOPE.map((name) => [name, to64(scope[name])]))),
        head: Object.freeze({ revision, digest: ownerDigest, epoch }),
        deviceId: input.ownerDeviceId, deviceKey,
        recheckCurrent,
        rows: Object.freeze(privateRows),
      }));
      return confirmed;
  }
  async function getFinalizedV2Ciphertext(confirmed, index, signerKey) {
    try {
      const state = verifiedV2.get(confirmed);
      if (!state || !Number.isSafeInteger(index) || index < 0
        || index >= state.rows.length || !contentHttp?.signProtectedContentOperation
        || signerKey?.type !== "private" || signerKey?.extractable !== false
        || signerKey?.algorithm?.name !== "Ed25519"
        || !signerKey?.usages?.includes("sign")) deny();
      state.assertLive();
      if (state.csrf !== state.csrfToken()) deny();
      // A once-finalized head is insufficient for a later GET: newer signed
      // 132+ heads revoke this snapshot, even if its ciphertext stayed valid.
      await state.recheckCurrent();
      // Prove possession of the same current device credential that verified
      // the checkpoint. Never trust an imported key filename or UI label.
      const challenge = webCrypto.getRandomValues(new Uint8Array(32));
      const proof = new Uint8Array(await webCrypto.subtle.sign("Ed25519", signerKey, challenge));
      if (!await webCrypto.subtle.verify("Ed25519", state.deviceKey, proof, challenge)) deny();
      const row = state.rows[index];
      const signed = await contentHttp.signProtectedContentOperation({
        signerKey, scope: state.scope, deviceId: state.deviceId,
        operation: "get", objectId: row.objectId,
        expectedObjectRevision: row.revision,
        manifestRevision: state.head.revision, manifestDigest: state.head.digest,
        epoch: state.head.epoch, nowSeconds: Math.floor(Date.now() / 1000),
        ciphertext: null, expectedCiphertextDigest: row.ciphertextDigest,
      });
      state.assertLive();
      if (state.csrf !== state.csrfToken()) deny();
      const controller = new AbortController();
      let timer;
      try {
        const deadline = new Promise((_resolve, reject) => {
          timer = setTimeout(() => { controller.abort(); reject(new Error("timeout")); }, 10000);
        });
        const work = (async () => {
          const response = await state.fetchImpl(state.url, {
            method: "POST", mode: "same-origin", credentials: "same-origin",
            redirect: "error", cache: "no-store", signal: controller.signal,
            headers: { "content-type": "application/json", accept: "application/json",
              "x-csrf-token": state.csrf }, body: JSON.stringify(signed),
          });
          state.assertLive();
          if (state.csrf !== state.csrfToken() || response.status !== 200
            || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(
              response.headers?.get("content-type") || "")) deny();
          const reader = response.body?.getReader();
          if (!reader) deny();
          const pieces = []; let size = 0, complete = false;
          try {
            while (true) {
              const part = await reader.read();
              if (part.done) { complete = true; break; }
              state.assertLive();
              if (state.csrf !== state.csrfToken()
                || !(part.value instanceof Uint8Array) || !part.value.length) deny();
              size += part.value.length;
              if (size > 6 * 1024 * 1024) deny();
              pieces.push(part.value);
            }
          } finally {
            if (!complete) { try { await reader.cancel(); } catch (_) { /* fail closed */ } }
            reader.releaseLock();
          }
          const wire = new Uint8Array(size);
          let at = 0;
          for (const part of pieces) { wire.set(part, at); at += part.length; }
          const received = JSON.parse(decoder.decode(wire));
          exact(received, ["id", "revision", "epoch", "ciphertextBase64"]);
          if (received.id !== row.objectId || received.revision !== row.revision
            || received.epoch !== row.epoch) deny();
          const ciphertext = from64(received.ciphertextBase64, 4 * 1024 * 1024);
          if (ciphertext.length < 16 || ciphertext.length > 4 * 1024 * 1024
            || !equal(await digest(ciphertext), row.ciphertextDigest)) deny();
          await state.recheckCurrent();
          state.assertLive();
          if (state.csrf !== state.csrfToken()) deny();
          return Object.freeze({ objectId: row.objectId, revision: row.revision,
            epoch: row.epoch, ciphertextBase64: to64(ciphertext),
            productionDurabilityProven: false });
        })();
        return await Promise.race([work, deadline]);
      } finally { clearTimeout(timer); controller.abort(); }
    } catch (_) { deny(); }
  }
  return Object.freeze({ createProbes, readFinalizedV2, getFinalizedV2Ciphertext });
}));
