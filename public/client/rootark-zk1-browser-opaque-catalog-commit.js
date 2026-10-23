(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto);
  } else {
    root.RootarkZk1BrowserOpaqueCatalogCommit = factory(root.crypto);
  }
}(typeof globalThis === "object" ? globalThis : this, function (crypto) {
  "use strict";

  // Opt-in V2 browser catalog writer. Never expose names, CEKs, metadata keys,
  // trust pins or plaintext to the Root.ark server. Trust probes MUST contact
  // independent authorities; their signed responses are checked here.
  const te = new TextEncoder(), td = new TextDecoder("utf-8", { fatal: true });
  const HEAD = te.encode("Root.ark/zk-1/opaque-catalog-head/v1\0");
  const PAGE = te.encode("Root.ark/zk-1/opaque-catalog-page/v1\0");
  const CAS = te.encode("Root.ark/zk-1/opaque-catalog-cas/v1\0");
  const OP = te.encode("Root.ark/zk-1/protected-object-operation/v1\0");
  const OP_ID = te.encode("Root.ark/zk-1/opaque-catalog-operation-id/v1\0");
  const META = te.encode("Root.ark/zk-1/opaque-catalog-metadata/v1\0");
  const WITNESS = te.encode("Root.ark/zk-1/recovery-witness-head/v1\0");
  const GRANT = te.encode("Root.ark/zk-1/browser-owner-device-grant/v1\0");
  const INTENT = te.encode("Root.ark/zk-1/browser-opaque-catalog-intent/v1\0");
  const SCOPE = ["account_id", "compartment_id", "keyring_id"];
  const GRANT_FIELDS = ["schema", ...SCOPE, "device_id", "authorization_key_id",
    "authorization_public_key", "manifest_revision", "manifest_digest",
    "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
  const HEADER = ["type", ...SCOPE, "sequence", "previous_digest", "manifest_revision",
    "manifest_digest", "epoch", "signer_device_id", "total_count", "page_digests", "issued_at"];
  const ROW = ["object_id", "revision", "epoch", "ciphertext_digest", "metadata_ciphertext"];
  const OP_FIELDS = [...SCOPE, "device_id", "operation", "object_id",
    "expected_object_revision", "manifest_revision", "manifest_digest", "epoch",
    "nonce", "issued_at", "expires_at", "ciphertext_digest"];
  const WITNESS_FIELDS = ["type", "witness_key_id", ...SCOPE,
    "current_revision", "current_manifest_digest", "witness_sequence", "nonce",
    "observed_at", "status", "pending_reservation_id"];
  const CAS_FIELDS = ["type", ...SCOPE, "sequence", "digest", "nonce", "observed_at"];
  const ZERO = new Uint8Array(32);
  const MAX_ROWS = 4096;
  const PAGE_SIZE = 32;
  const verifiedSnapshots = new WeakMap();
  function indexedDbJournalStore(database = typeof indexedDB === "object" ? indexedDB : null) {
    if (!database || typeof database.open !== "function") deny();
    const dbName = "rootark-zk1-opaque-catalog-pending-intent-v1";
    async function execute(operation, key, value) {
      const db = await new Promise((resolve, reject) => {
        const request = database.open(dbName, 1);
        request.onupgradeneeded = () => {
          if (!request.result.objectStoreNames.contains("intents"))
            request.result.createObjectStore("intents");
        };
        request.onerror = () => reject(new Error("journal open denied"));
        request.onblocked = () => reject(new Error("journal blocked"));
        request.onsuccess = () => resolve(request.result);
      });
      try {
        return await new Promise((resolve, reject) => {
          const transaction = db.transaction("intents", operation === "read" ? "readonly" : "readwrite",
            operation === "read" ? undefined : { durability: "strict" });
          const store = transaction.objectStore("intents");
          const request = operation === "read" ? store.get(key)
            : operation === "write" ? store.add(value, key) : store.delete(key);
          let result;
          request.onsuccess = () => { result = request.result; };
          transaction.oncomplete = () => resolve(result);
          transaction.onerror = () => reject(new Error("journal transaction denied"));
          transaction.onabort = () => reject(new Error("journal transaction aborted"));
        });
      } finally { db.close(); }
    }
    return Object.freeze({ write: (key, value) => execute("write", key, value),
      read: (key) => execute("read", key), remove: (key) => execute("remove", key) });
  }
  function deny() { throw new Error("ZK_BROWSER_CATALOG_UNVERIFIED"); }
  function exact(v, fields) {
    if (!v || typeof v !== "object" || Array.isArray(v)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(v))
      || Reflect.ownKeys(v).length !== fields.length
      || fields.some((key) => !Object.hasOwn(v, key))) deny();
    return v;
  }
  function uint(n, min = 0, max = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(n) || n < min || n > max) deny();
    return n;
  }
  function bytes(v, min, max = min) {
    if (!(v instanceof ArrayBuffer) && !ArrayBuffer.isView(v)
      || !Number.isSafeInteger(v.byteLength) || v.byteLength < min || v.byteLength > max) deny();
    return v instanceof ArrayBuffer ? new Uint8Array(v.slice(0))
      : new Uint8Array(v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength));
  }
  function equal(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }
  function concat(...all) {
    const size = all.reduce((sum, part) => sum + part.length, 0);
    if (size > 6 * 1024 * 1024) deny();
    const out = new Uint8Array(size); let at = 0;
    for (const part of all) { out.set(part, at); at += part.length; }
    return out;
  }
  function b64(v) {
    let raw = "";
    for (const value of v) raw += String.fromCharCode(value);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(value, min, max = min) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
      || value.length > Math.ceil(max * 4 / 3) + 4) deny();
    let binary;
    try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
    const out = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (out.length < min || out.length > max || b64(out) !== value) deny();
    return out;
  }
  function id(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(value)) deny();
    from64(value, 16);
    return value;
  }
  function cborHead(type, value) {
    const n = BigInt(uint(value)), t = type << 5;
    if (n < 24n) return Uint8Array.of(t + Number(n));
    if (n <= 255n) return Uint8Array.of(t + 24, Number(n));
    if (n <= 65535n) return Uint8Array.of(t + 25, Number(n >> 8n), Number(n & 255n));
    if (n <= 0xffffffffn) return Uint8Array.of(t + 26, Number((n >> 24n) & 255n),
      Number((n >> 16n) & 255n), Number((n >> 8n) & 255n), Number(n & 255n));
    return Uint8Array.of(t + 27, ...Array.from({ length: 8 },
      (_, i) => Number((n >> BigInt(56 - 8 * i)) & 255n)));
  }
  function order(a, b) {
    if (a.length !== b.length) return a.length - b.length;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return 0;
  }
  function encode(v) {
    if (v === null) return Uint8Array.of(0xf6);
    if (typeof v === "number") return cborHead(0, v);
    if (typeof v === "string") {
      const raw = te.encode(v); return concat(cborHead(3, raw.length), raw);
    }
    if (v instanceof Uint8Array) return concat(cborHead(2, v.length), v);
    if (Array.isArray(v)) return concat(cborHead(4, v.length), ...v.map(encode));
    if (v && typeof v === "object"
      && [Object.prototype, null].includes(Object.getPrototypeOf(v))) {
      const entries = Object.keys(v).map((key) => [encode(key), encode(v[key])]);
      entries.sort((a, b) => order(a[0], b[0]));
      return concat(cborHead(5, entries.length), ...entries.flat());
    }
    deny();
  }
  function decode(raw) {
    const input = bytes(raw, 1, 16384); let at = 0;
    function take(n) { if (at + n > input.length) deny(); const part = input.slice(at, at + n); at += n; return part; }
    function read(depth) {
      if (depth > 16) deny();
      const tag = take(1)[0], major = tag >>> 5, info = tag & 31;
      if (tag === 0xf6) return null;
      if (![0, 2, 3, 4, 5].includes(major) || info > 27) deny();
      const count = info < 24 ? info : (() => {
        const length = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
        if (!length) deny(); let n = 0;
        for (const b of take(length)) n = n * 256 + b;
        return uint(n, 0, 16384);
      })();
      if (major === 0) return count;
      if (major === 2) return take(count);
      if (major === 3) return td.decode(take(count));
      if (major === 4) return Array.from({ length: count }, () => read(depth + 1));
      const obj = Object.create(null);
      for (let i = 0; i < count; i++) {
        const key = read(depth + 1);
        if (typeof key !== "string" || ["__proto__", "constructor", "prototype"].includes(key)
          || Object.hasOwn(obj, key)) deny();
        obj[key] = read(depth + 1);
      }
      return obj;
    }
    const result = read(0);
    if (at !== input.length || !equal(encode(result), input)) deny();
    return result;
  }
  async function hash(raw) { return new Uint8Array(await crypto.subtle.digest("SHA-256", raw)); }
  function edKey(key, type) {
    if (!key || key.type !== type || key.algorithm?.name !== "Ed25519"
      || !key.usages?.includes(type === "private" ? "sign" : "verify")
      || (type === "private" && key.extractable !== false)) deny();
    return key;
  }
  function scopeOf(grant) {
    return { account_id: from64(grant.account_id, 16),
      compartment_id: from64(grant.compartment_id, 1, 128),
      keyring_id: from64(grant.keyring_id, 16) };
  }
  function matchingScope(raw, scope) {
    for (const key of SCOPE) if (!equal(bytes(raw[key],
      key === "compartment_id" ? 1 : 16, key === "compartment_id" ? 128 : 16), scope[key])) deny();
  }
  async function verifyGrant(grant, ownerKey, scope, pin) {
    exact(grant, [...GRANT_FIELDS, "signature"]);
    if (grant.schema !== "rootark-zk1-browser-owner-device-grant/v1"
      || grant.manifest_revision !== pin.revision || grant.manifest_digest !== b64(pin.digest)
      || grant.current_epoch !== pin.epoch || grant.revoked_at_epoch !== null
      || uint(grant.enrolled_epoch, 1) > pin.epoch) deny();
    matchingScope(scopeOf(grant), scope);
    from64(grant.authorization_key_id, 16);
    const key = await crypto.subtle.importKey("raw", from64(grant.authorization_public_key, 32),
      "Ed25519", false, ["verify"]);
    if (typeof grant.device_id !== "string" || !grant.device_id
      || grant.device_id.length > 64 || /[\u0000-\u001f\u007f]/.test(grant.device_id)) deny();
    const signed = Object.fromEntries(GRANT_FIELDS.map((name) => [name, grant[name]]));
    if (!await crypto.subtle.verify("Ed25519", ownerKey, from64(grant.signature, 64),
      concat(GRANT, te.encode(JSON.stringify(signed))))) deny();
    return key;
  }
  function originURL(origin, route, resource = "catalog") {
    const url = new URL(origin);
    if (url.href !== url.origin + "/" || url.username || url.password || url.hash || url.search
      || !["http:", "https:"].includes(url.protocol)
      || (url.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
      || (typeof location === "object" && location.origin && url.origin !== location.origin)) deny();
    if ((resource !== "catalog" && resource !== "content")
      || (resource === "catalog" && !["commit", "read"].includes(route))
      || (resource === "content" && route !== "read")) deny();
    return url.origin + "/zk-1/v1/" + resource + "/" + route;
  }
  function inspectRows(rows) {
    if (!Array.isArray(rows) || rows.length > MAX_ROWS) deny();
    let previous = null;
    for (const row of rows) {
      exact(row, ROW); id(row.object_id);
      uint(row.revision, 1); uint(row.epoch, 1);
      bytes(row.ciphertext_digest, 32); bytes(row.metadata_ciphertext, 284);
      if (previous && (previous.object_id > row.object_id
        || (previous.object_id === row.object_id && previous.revision >= row.revision))) deny();
      previous = row;
    }
    return rows;
  }
  function wireRows(rows) {
    const pages = [];
    for (let i = 0; i < rows.length; i += PAGE_SIZE) {
      pages.push(rows.slice(i, i + PAGE_SIZE).map((item) => ({
        objectId: item.object_id, revision: item.revision, epoch: item.epoch,
        ciphertextDigestBase64: b64(item.ciphertext_digest),
        metadataCiphertextBase64: b64(item.metadata_ciphertext),
      })));
    }
    return pages;
  }
  async function makeMetadata(scope, objectId, revision, epoch, key, name) {
    if (typeof name !== "string" || /[\u0000-\u001f\u007f]/.test(name)) deny();
    const nameBytes = te.encode(name);
    if (nameBytes.length < 1 || nameBytes.length > 220
      || key?.type !== "secret" || key?.algorithm?.name !== "AES-GCM"
      || key.algorithm.length !== 256 || !key.usages?.includes("encrypt")
      || key.extractable !== false) deny();
    const padded = crypto.getRandomValues(new Uint8Array(256));
    padded[0] = nameBytes.length >>> 8; padded[1] = nameBytes.length & 255;
    padded.set(nameBytes, 2);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    try {
      const aad = concat(META, encode({ ...scope, object_id: objectId, revision, epoch }));
      const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv,
        additionalData: aad, tagLength: 128 }, key, padded));
      if (encrypted.length !== 272) deny();
      return concat(iv, encrypted);
    } finally { padded.fill(0); nameBytes.fill(0); }
  }
  function configure(input) {
    const customJournal = Object.hasOwn(input || {}, "journalStore");
    exact(input, ["origin", "fetchImpl", "ownerPublicKey", "pinnedOwnerKeyHash",
      "pinnedOwnerHead", "signedDeviceGrant", "devicePublicKey", "devicePrivateKey",
      "signerGrants", "ownerWitnessPublicKey", "ownerWitnessKeyId", "ownerWitnessProbe",
      "catalogAuthorityPublicKey", "catalogProbe", "minimumCatalogHead", "csrfToken",
      "isSessionCurrent", "assertCurrent", "nowSeconds", ...(customJournal ? ["journalStore"] : [])]);
    if (!crypto?.subtle || !crypto.getRandomValues || typeof input.fetchImpl !== "function"
      || typeof input.ownerWitnessProbe !== "function" || typeof input.catalogProbe !== "function"
      || typeof input.assertCurrent !== "function" || typeof input.isSessionCurrent !== "function"
      || typeof input.nowSeconds !== "function" || typeof input.csrfToken !== "function"
      || !Array.isArray(input.signerGrants)) deny();
    originURL(input.origin, "read");
    edKey(input.ownerPublicKey, "public"); edKey(input.devicePublicKey, "public");
    edKey(input.devicePrivateKey, "private");
    edKey(input.ownerWitnessPublicKey, "public");
    edKey(input.catalogAuthorityPublicKey, "public");
    const pin = exact(input.pinnedOwnerHead, ["revision", "digest", "epoch"]);
    uint(pin.revision, 1); uint(pin.epoch, 1); bytes(pin.digest, 32);
    const minimum = exact(input.minimumCatalogHead, ["sequence", "digest"]);
    uint(minimum.sequence, 0, 128); bytes(minimum.digest, 32);
    bytes(input.ownerWitnessKeyId, 16); bytes(input.pinnedOwnerKeyHash, 32);
    const journal = customJournal ? input.journalStore : indexedDbJournalStore();
    if (["write", "read", "remove"].some((name) => typeof journal?.[name] !== "function")) deny();
    return Object.freeze({ ...input, journalStore: journal });
  }
  function createClient(input) {
    const trust = configure(input);
    let floor = { sequence: trust.minimumCatalogHead.sequence,
      digest: bytes(trust.minimumCatalogHead.digest, 32) };
    let used = false;
    let prepared = false;
    let pendingCommit = null;
    const scope = scopeOf(trust.signedDeviceGrant);
    const pin = { revision: trust.pinnedOwnerHead.revision,
      digest: bytes(trust.pinnedOwnerHead.digest, 32), epoch: trust.pinnedOwnerHead.epoch };
    const requireSession = () => { if (trust.isSessionCurrent() !== true) deny(); };
    function remember(head, rows, header = null) {
      const result = { head: { sequence: head.sequence, digest: bytes(head.digest, 32) },
        rows: rows.map((row) => ({ ...row, ciphertext_digest: bytes(row.ciphertext_digest, 32),
          metadata_ciphertext: bytes(row.metadata_ciphertext, 284) })) };
      verifiedSnapshots.set(result, { scope: Object.fromEntries(SCOPE.map((k) => [k, b64(scope[k])])),
        manifestRevision: pin.revision, manifestDigest: b64(pin.digest), epoch: pin.epoch,
        head: { sequence: head.sequence, digest: bytes(head.digest, 32) },
        predecessorDigest: header ? bytes(header.previous_digest, 32) : null,
        signerDeviceId: header ? header.signer_device_id : null,
        rows: result.rows.map((row) => ({ ...row,
          ciphertext_digest: bytes(row.ciphertext_digest, 32),
          metadata_ciphertext: bytes(row.metadata_ciphertext, 284) })) });
      return result;
    }
    const now = () => uint(trust.nowSeconds(), 0);
    const probe = async (fn) => {
      requireSession();
      const nonce = crypto.getRandomValues(new Uint8Array(32));
      const raw = bytes(await fn({ scope: Object.fromEntries(SCOPE.map((k) => [k, b64(scope[k])])),
        nonce: new Uint8Array(nonce) }), 1, 8192);
      requireSession();
      return { nonce, decoded: decode(raw) };
    };
    async function ownerCurrent() {
      requireSession();
      const ownerHash = await hash(new Uint8Array(await crypto.subtle.exportKey("raw", trust.ownerPublicKey)));
      if (!equal(ownerHash, bytes(trust.pinnedOwnerKeyHash, 32))) deny();
      const { nonce, decoded: body } = await probe(trust.ownerWitnessProbe);
      exact(body, [...WITNESS_FIELDS, "signature"]);
      const { signature, ...stmt } = body;
      exact(stmt, WITNESS_FIELDS); matchingScope(stmt, scope);
      if (stmt.type !== "rootark-recovery-witness-head/v1"
        || !equal(bytes(stmt.witness_key_id, 16), bytes(trust.ownerWitnessKeyId, 16))
        || !equal(bytes(stmt.nonce, 32), nonce)
        || Math.abs(now() - uint(stmt.observed_at)) > 30
        || stmt.status !== "committed" || stmt.pending_reservation_id !== null
        || uint(stmt.current_revision, 1) !== pin.revision
        || uint(stmt.witness_sequence, 1) < pin.revision
        || !equal(bytes(stmt.current_manifest_digest, 32), pin.digest)
        || !await crypto.subtle.verify("Ed25519", trust.ownerWitnessPublicKey,
          bytes(signature, 64), concat(WITNESS, encode(stmt)))) deny();
      const deviceKey = await verifyGrant(trust.signedDeviceGrant, trust.ownerPublicKey, scope, pin);
      const rawDevice = new Uint8Array(await crypto.subtle.exportKey("raw", trust.devicePublicKey));
      if (!equal(rawDevice, from64(trust.signedDeviceGrant.authorization_public_key, 32))) deny();
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      if (!await crypto.subtle.verify("Ed25519", deviceKey,
        await crypto.subtle.sign("Ed25519", trust.devicePrivateKey, challenge), challenge)) deny();
      await trust.assertCurrent();
      requireSession();
    }
    async function casHead(nonce, raw) {
      const body = decode(raw);
      exact(body, [...CAS_FIELDS, "signature"]);
      const { signature, ...stmt } = body;
      exact(stmt, CAS_FIELDS); matchingScope(stmt, scope);
      if (stmt.type !== "rootark-zk1-opaque-catalog-cas/v1"
        || !equal(bytes(stmt.nonce, 32), nonce)
        || Math.abs(now() - uint(stmt.observed_at)) > 30
        || !await crypto.subtle.verify("Ed25519", trust.catalogAuthorityPublicKey,
          bytes(signature, 64), concat(CAS, encode(stmt)))) deny();
      const sequence = uint(stmt.sequence, 0, 128), digest = bytes(stmt.digest, 32);
      if ((sequence === 0 && !equal(digest, ZERO)) || sequence < floor.sequence
        || (sequence === floor.sequence && !equal(digest, floor.digest))) deny();
      return { sequence, digest };
    }
    async function freshHead() {
      const { nonce, decoded } = await probe(trust.catalogProbe);
      return casHead(nonce, encode(decoded));
    }
    function advance(next) {
      if (next.sequence < floor.sequence
        || (next.sequence === floor.sequence && !equal(next.digest, floor.digest))) deny();
      floor = { sequence: next.sequence, digest: bytes(next.digest, 32) };
    }
    async function signedAuth(operation, page, head, digest, objectIdForGet,
      revisionForGet, issuedOverride) {
      const serial = te.encode(SCOPE.map((key) => Array.from(scope[key])
        .map((v) => v.toString(16).padStart(2, "0")).join("")).join(":"));
      const objectId = operation === "get" ? id(objectIdForGet)
        : b64((await hash(concat(OP_ID, serial,
          te.encode(operation + ":" + page)))).slice(0, 16));
      const issued = issuedOverride === undefined ? now() : uint(issuedOverride);
      const nonce = crypto.getRandomValues(new Uint8Array(32));
      const request = { ...scope, device_id: trust.signedDeviceGrant.device_id,
        operation, object_id: objectId,
        expected_object_revision: operation === "get" ? uint(revisionForGet, 1)
          : operation === "catalog-commit"
            ? (head.sequence === 0 ? null : head.sequence) : head.sequence,
        manifest_revision: pin.revision, manifest_digest: pin.digest, epoch: pin.epoch,
        nonce, issued_at: issued, expires_at: issued + 30, ciphertext_digest: digest };
      const signature = new Uint8Array(await crypto.subtle.sign("Ed25519",
        trust.devicePrivateKey, concat(OP, encode(request))));
      const authorization = {};
      for (const [key, value] of Object.entries(request)) {
        authorization[key] = [...SCOPE, "manifest_digest", "nonce", "ciphertext_digest"].includes(key)
          ? b64(value) : value;
      }
      return { authorization, signatureBase64: b64(signature), nonce };
    }
    async function post(route, request, resource = "catalog") {
      requireSession();
      const csrf = trust.csrfToken();
      if (typeof csrf !== "string" || csrf.length < 1 || csrf.length > 512
        || /[\r\n\u0000-\u001f\u007f]/.test(csrf)) deny();
      // The server is untrusted. Never allocate response.text() before
      // checking its size. One deadline covers the request and every chunk;
      // cancellation also prevents a stalled body from holding the caller.
      const controller = new AbortController();
      let rejectDeadline, reader;
      const deadline = new Promise((_, reject) => { rejectDeadline = reject; });
      const timer = setTimeout(() => {
        controller.abort();
        rejectDeadline(new Error("catalog HTTP deadline"));
      }, 15000);
      try {
        const response = await Promise.race([
          trust.fetchImpl(originURL(trust.origin, route, resource), {
            method: "POST", mode: "same-origin", credentials: "same-origin", redirect: "error",
            cache: "no-store", signal: controller.signal,
            headers: { "content-type": "application/json", accept: "application/json",
              "x-csrf-token": csrf }, body: JSON.stringify(request),
          }), deadline,
        ]);
        requireSession();
        if (response.status !== (route === "commit" ? 201 : 200)
          || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(
            response.headers?.get("content-type") || "")) deny();
        const maximum = resource === "content" ? 6 * 1024 * 1024
          : route === "read" ? 25000 : 2048;
        if (!response.body || typeof response.body.getReader !== "function") deny();
        reader = response.body.getReader();
        const decoder = new TextDecoder("utf-8", { fatal: true });
        let raw = "", used = 0;
        while (true) {
          const piece = await Promise.race([reader.read(), deadline]);
          requireSession();
          if (piece.done) break;
          if (!ArrayBuffer.isView(piece.value) || !(piece.value.byteLength > 0)
            || piece.value.byteLength > maximum - used) deny();
          used += piece.value.byteLength;
          raw += decoder.decode(piece.value, { stream: true });
          if (raw.length > maximum) deny();
        }
        raw += decoder.decode();
        requireSession();
        if (raw.length > maximum) deny();
        return JSON.parse(raw);
      } finally {
        clearTimeout(timer);
        if (reader) {
          // Do not await cancellation: a malicious reader may never settle it.
          try { Promise.resolve(reader.cancel()).catch(() => {}); } catch (_) { /* deny below */ }
        }
        controller.abort();
      }
    }
    async function fetchVerifiedCiphertext(objectId, revision, epoch, digest) {
      // Resolve a potentially ambiguous earlier PUT by a NEW signed exact
      // version GET. A generic listing or an unverified PUT ACK is insufficient.
      await ownerCurrent();
      const signed = await signedAuth("get", 0, null, digest, objectId, revision);
      const response = await post("read", {
        authorization: signed.authorization, signatureBase64: signed.signatureBase64,
      }, "content");
      exact(response, ["id", "revision", "epoch", "ciphertextBase64"]);
      if (response.id !== objectId || response.revision !== revision || response.epoch !== epoch) deny();
      const actual = from64(response.ciphertextBase64, 16, 4 * 1024 * 1024);
      if (!equal(await hash(actual), digest)) deny();
      requireSession();
      return actual;
    }
    async function verifyCiphertextReadback(objectId, revision, epoch, ciphertext, digest) {
      const actual = await fetchVerifiedCiphertext(objectId, revision, epoch, digest);
      if (!equal(actual, ciphertext)) deny();
    }
    async function readVerifiedCiphertext(snapshot, objectId, revision) {
      try {
        const trusted = verifiedSnapshots.get(snapshot);
        if (!trusted || trusted.manifestRevision !== pin.revision
          || trusted.manifestDigest !== b64(pin.digest) || trusted.epoch !== pin.epoch
          || SCOPE.some((key) => trusted.scope[key] !== b64(scope[key]))) deny();
        const current = await freshHead();
        if (trusted.head.sequence !== current.sequence
          || !equal(trusted.head.digest, current.digest)) deny();
        const matches = trusted.rows.filter((row) => row.object_id === id(objectId)
          && row.revision === uint(revision, 1));
        if (matches.length !== 1) deny();
        const row = matches[0];
        const ciphertext = await fetchVerifiedCiphertext(row.object_id, row.revision,
          row.epoch, row.ciphertext_digest);
        return Object.freeze({ objectId: row.object_id, revision: row.revision,
          epoch: row.epoch, ciphertextBase64: b64(ciphertext),
          ciphertextDigestBase64: b64(row.ciphertext_digest) });
      } catch (_) { deny(); }
    }
    async function readSignedSuccessor(previous) {
      try {
        // A plain caller-provided catalog (or edited/rolled-back copy) is not
        // a predecessor. Only this owner's independently signed readAll() can
        // establish the old head, rows and trust epoch in the private WeakMap.
        const old = verifiedSnapshots.get(previous);
        if (!old || previous.head.sequence !== old.head.sequence
          || !equal(bytes(previous.head.digest, 32), old.head.digest)
          || previous.rows.length !== old.rows.length
          || old.manifestRevision !== pin.revision || old.epoch !== pin.epoch
          || old.manifestDigest !== b64(pin.digest)
          || SCOPE.some((key) => old.scope[key] !== b64(scope[key]))) deny();
        for (let i = 0; i < old.rows.length; ++i) {
          const before = old.rows[i], provided = previous.rows[i];
          if (!provided || provided.object_id !== before.object_id
            || provided.revision !== before.revision || provided.epoch !== before.epoch
            || !equal(bytes(provided.ciphertext_digest, 32), before.ciphertext_digest)
            || !equal(bytes(provided.metadata_ciphertext, 284), before.metadata_ciphertext)) deny();
        }
        // readAll verifies the active owner grant, live signed witness, CAS
        // signature, full Merkle catalog pages, and a second fresh CAS head.
        const next = await readAll();
        const signed = verifiedSnapshots.get(next);
        if (!signed || next.head.sequence !== old.head.sequence + 1
          || !signed.predecessorDigest
          || !equal(signed.predecessorDigest, old.head.digest)
          || signed.rows.length <= old.rows.length) deny();
        const oldRows = new Map(old.rows.map((row) => [row.object_id + ":" + row.revision, row]));
        const highest = new Map();
        for (const row of old.rows) highest.set(row.object_id,
          Math.max(highest.get(row.object_id) ?? 0, row.revision));
        const additions = [];
        for (const row of signed.rows) {
          const key = row.object_id + ":" + row.revision;
          const before = oldRows.get(key);
          if (before) {
            if (row.epoch !== before.epoch
              || !equal(row.ciphertext_digest, before.ciphertext_digest)
              || !equal(row.metadata_ciphertext, before.metadata_ciphertext)) deny();
            oldRows.delete(key);
          } else {
            // A signed insertion with a missing predecessor (or an invented
            // revision jump) is not a usable monotonic per-object delta.
            if (row.revision !== (highest.get(row.object_id) ?? 0) + 1
              || row.epoch !== pin.epoch) deny();
            highest.set(row.object_id, row.revision);
            additions.push({ objectId: row.object_id, revision: row.revision,
              epoch: row.epoch, ciphertextDigestBase64: b64(row.ciphertext_digest),
              metadataCiphertextBase64: b64(row.metadata_ciphertext) });
          }
        }
        if (oldRows.size || additions.length === 0
          || signed.rows.length !== old.rows.length + additions.length) deny();
        // Do not authorize a sync from a just-changed CAS/fork after the page
        // read; the next exact historical GET performs another CAS challenge.
        return Object.freeze({ snapshot: next, additions: Object.freeze(additions.map(
          (item) => Object.freeze(item))) });
      } catch (_) { deny(); }
    }
    async function readAll(expected) {
      await ownerCurrent();
      const current = await freshHead();
      if (expected && (expected.sequence !== current.sequence
        || !equal(expected.digest, current.digest))) deny();
      if (current.sequence === 0) return remember(current, []);
      const rows = []; let firstHeader = null; let count = null; let pages = null;
      for (let page = 0; page < (pages === null ? 1 : pages); page++) {
        await ownerCurrent();
        const signed = await signedAuth("catalog-read", page, current, current.digest);
        const response = await post("read", { authorization: signed.authorization,
          signatureBase64: signed.signatureBase64, pageIndex: page });
        const headerBytes = from64(response.headerBase64, 1, 16384);
        const header = decode(headerBytes);
        exact(header, HEADER); matchingScope(header, scope);
        if (header.type !== "rootark-zk1-opaque-catalog/v1"
          || header.sequence !== current.sequence
          || !equal(bytes(header.manifest_digest, 32), pin.digest)
          || header.manifest_revision !== pin.revision || header.epoch !== pin.epoch
          || uint(header.total_count, 0, MAX_ROWS) !== response.totalCount
          || uint(response.sequence) !== current.sequence
          || uint(response.pageIndex) !== page
          || !Array.isArray(header.page_digests)
          || header.page_digests.length !== Math.ceil(header.total_count / PAGE_SIZE)
          || response.pageCount !== header.page_digests.length) deny();
        const signer = trust.signerGrants.find((v) => v.device_id === header.signer_device_id);
        if (!signer) deny();
        const signerKey = await verifyGrant(signer, trust.ownerPublicKey, scope, pin);
        const sig = from64(response.headerSignatureBase64, 64);
        if (!await crypto.subtle.verify("Ed25519", signerKey, sig,
          concat(HEAD, headerBytes))) deny();
        const headDigest = await hash(concat(HEAD, headerBytes, sig));
        if (!equal(headDigest, current.digest)
          || !equal(from64(response.catalogDigest, 32), current.digest)
          || (firstHeader && !equal(firstHeader, headerBytes))) deny();
        if (!firstHeader) { firstHeader = headerBytes; count = header.total_count; pages = Math.max(1, header.page_digests.length); }
        if (pages !== Math.max(1, header.page_digests.length)) deny();
        const proof = from64(response.authorityProofBase64, 1, 8192);
        const witnessed = await casHead(signed.nonce, proof);
        if (witnessed.sequence !== current.sequence || !equal(witnessed.digest, current.digest)) deny();
        if (!Array.isArray(response.entries) || response.entries.length !== (count === 0 ? 0
          : page === pages - 1 ? count - page * PAGE_SIZE : PAGE_SIZE)) deny();
        const batch = response.entries.map((row) => {
          exact(row, ["objectId", "revision", "epoch", "ciphertextDigestBase64", "metadataCiphertextBase64"]);
          return { object_id: id(row.objectId), revision: uint(row.revision, 1),
            epoch: uint(row.epoch, 1), ciphertext_digest: from64(row.ciphertextDigestBase64, 32),
            metadata_ciphertext: from64(row.metadataCiphertextBase64, 284) };
        });
        if (batch.length && !equal(await hash(concat(PAGE, encode(batch))),
          bytes(header.page_digests[page], 32))) deny();
        rows.push(...batch);
      }
      inspectRows(rows);
      if (rows.length !== count) deny();
      const final = await freshHead();
      if (final.sequence !== current.sequence || !equal(final.digest, current.digest)) deny();
      advance(final);
      return remember(final, rows, decode(firstHeader));
    }
    async function prepareIntent(writes) {
      if (prepared || used) deny();
      prepared = true;
      try {
        if (!Array.isArray(writes) || !writes.length || writes.length > MAX_ROWS) deny();
        const snapshot = await readAll();
        if (snapshot.head.sequence >= 128) deny();
        const oldVersions = new Set(snapshot.rows.map((r) => r.object_id + ":" + r.revision));
        const planned = [];
        for (const item of writes) {
          exact(item, ["objectId", "revision", "epoch", "ciphertext"]);
          const objectId = id(item.objectId), revision = uint(item.revision, 1), epoch = uint(item.epoch, 1);
          const version = objectId + ":" + revision;
          if (oldVersions.has(version) || epoch !== pin.epoch) deny();
          oldVersions.add(version);
          planned.push({ objectId, revision, epoch,
            ciphertextDigest: b64(await hash(bytes(item.ciphertext, 16, 4 * 1024 * 1024))) });
        }
        planned.sort((a, b) => a.objectId < b.objectId ? -1 : a.objectId > b.objectId
          ? 1 : a.revision - b.revision);
        const journalId = b64(crypto.getRandomValues(new Uint8Array(32)));
        const body = { format: "rootark-zk1-browser-opaque-catalog-intent/v1",
          ...Object.fromEntries(SCOPE.map((k) => [k, b64(scope[k])])),
          deviceId: trust.signedDeviceGrant.device_id, manifestRevision: pin.revision,
          manifestDigest: b64(pin.digest), epoch: pin.epoch,
          previousSequence: snapshot.head.sequence, previousDigest: b64(snapshot.head.digest),
          journalId, issuedAt: now(), writes: planned,
          rows: wireRows(snapshot.rows).flat() };
        // Signed, opaque client-side journal committed before any new PUT.
        // No name, filesystem path, CEK or metadata key is persisted.
        const signature = b64(new Uint8Array(await crypto.subtle.sign("Ed25519",
          trust.devicePrivateKey, concat(INTENT, te.encode(JSON.stringify(body))))));
        await trust.journalStore.write(journalId, { body, signature });
        const saved = await trust.journalStore.read(journalId);
        if (!saved || saved.signature !== signature
          || JSON.stringify(saved.body) !== JSON.stringify(body)) deny();
        requireSession();
        return journalId;
      } catch (_) { deny(); }
    }
    async function verifiedIntent(journalId) {
      from64(journalId, 32);
      const saved = await trust.journalStore.read(journalId);
      exact(saved, ["body", "signature"]);
      const body = exact(saved.body, ["format", ...SCOPE, "deviceId", "manifestRevision",
        "manifestDigest", "epoch", "previousSequence", "previousDigest", "journalId",
        "issuedAt", "writes", "rows"]);
      if (body.format !== "rootark-zk1-browser-opaque-catalog-intent/v1"
        || body.deviceId !== trust.signedDeviceGrant.device_id || body.journalId !== journalId
        || body.manifestRevision !== pin.revision || body.manifestDigest !== b64(pin.digest)
        || body.epoch !== pin.epoch || SCOPE.some((key) => body[key] !== b64(scope[key]))
        || !await crypto.subtle.verify("Ed25519", trust.devicePublicKey,
          from64(saved.signature, 64), concat(INTENT, te.encode(JSON.stringify(body))))) deny();
      uint(body.previousSequence, 0, 128); uint(body.issuedAt);
      if (!Array.isArray(body.writes) || body.writes.length < 1
        || body.writes.length > MAX_ROWS
        || !Array.isArray(body.rows) || body.rows.length > MAX_ROWS) deny();
      const plans = new Map();
      for (const planned of body.writes) {
        exact(planned, ["objectId", "revision", "epoch", "ciphertextDigest"]);
        const version = id(planned.objectId) + ":" + uint(planned.revision, 1);
        if (plans.has(version) || planned.epoch !== pin.epoch) deny();
        plans.set(version, { objectId: planned.objectId, revision: planned.revision,
          epoch: planned.epoch, digest: from64(planned.ciphertextDigest, 32) });
      }
      const rows = body.rows.map((item) => {
        exact(item, ["objectId", "revision", "epoch", "ciphertextDigestBase64",
          "metadataCiphertextBase64"]);
        return { object_id: id(item.objectId), revision: uint(item.revision, 1),
          epoch: uint(item.epoch, 1), ciphertext_digest: from64(item.ciphertextDigestBase64, 32),
          metadata_ciphertext: from64(item.metadataCiphertextBase64, 284) };
      });
      inspectRows(rows);
      if (body.previousSequence === 0 && body.rows.length !== 0) deny();
      if (body.previousSequence >= 128) deny();
      const old = new Set(rows.map((row) => row.object_id + ":" + row.revision));
      if ([...plans.keys()].some((version) => old.has(version))) deny();
      return { body, rows, plans };
    }
    async function loadIntent(journalId, additions) {
      const { body, rows, plans } = await verifiedIntent(journalId);
      if (additions.length !== plans.size) deny();
      for (const addition of additions) {
        const version = id(addition.objectId) + ":" + uint(addition.revision, 1);
        if (!plans.has(version) || !equal(plans.get(version).digest,
          await hash(bytes(addition.ciphertext, 16, 4 * 1024 * 1024)))) deny();
        plans.delete(version);
      }
      if (plans.size !== 0) deny();
      await ownerCurrent();
      const current = await freshHead();
      if (current.sequence !== body.previousSequence
        || !equal(current.digest, from64(body.previousDigest, 32))) deny();
      return { head: current, rows };
    }
    async function commit(additions, journalId, options = {}) {
      if (used) deny();
      exact(options, Object.hasOwn(options, "retainPendingIntent") ? ["retainPendingIntent"] : []);
      if (Object.hasOwn(options, "retainPendingIntent")
        && options.retainPendingIntent !== true) deny();
      used = true; // one-use intent; lost ACK is never retried.
      try {
        if (!Array.isArray(additions) || additions.length < 1 || additions.length > MAX_ROWS) deny();
        if (typeof journalId !== "string") deny();
        const before = await loadIntent(journalId, additions);
        if (before.head.sequence >= 128) deny();
        const rows = before.rows.map((row) => ({ ...row }));
        const versions = new Set(rows.map((row) => row.object_id + ":" + row.revision));
        for (const addition of additions) {
          exact(addition, ["objectId", "revision", "epoch", "ciphertext", "name", "metadataKey"]);
          const objectId = id(addition.objectId), revision = uint(addition.revision, 1);
          const epoch = uint(addition.epoch, 1);
          const version = objectId + ":" + revision;
          if (versions.has(version) || epoch !== pin.epoch) deny();
          versions.add(version);
          const ciphertext = bytes(addition.ciphertext, 16, 4 * 1024 * 1024);
          const ciphertext_digest = await hash(ciphertext);
          await verifyCiphertextReadback(objectId, revision, epoch, ciphertext, ciphertext_digest);
          const metadata_ciphertext = await makeMetadata(scope, objectId, revision,
            epoch, addition.metadataKey, addition.name);
          rows.push({ object_id: objectId, revision, epoch, ciphertext_digest,
            metadata_ciphertext });
          ciphertext.fill(0);
        }
        rows.sort((a, b) => a.object_id < b.object_id ? -1 : a.object_id > b.object_id
          ? 1 : a.revision - b.revision);
        inspectRows(rows);
        const pages = [];
        for (let i = 0; i < rows.length; i += PAGE_SIZE) pages.push(rows.slice(i, i + PAGE_SIZE));
        const page_digests = await Promise.all(pages.map(async (p) => hash(concat(PAGE, encode(p)))));
        const issued = now();
        const header = { type: "rootark-zk1-opaque-catalog/v1", ...scope,
          sequence: before.head.sequence + 1, previous_digest: before.head.digest,
          manifest_revision: pin.revision, manifest_digest: pin.digest, epoch: pin.epoch,
          signer_device_id: trust.signedDeviceGrant.device_id, total_count: rows.length,
          page_digests, issued_at: issued };
        const rawHead = encode(header);
        if (rawHead.length > 16384) deny();
        const headerSig = new Uint8Array(await crypto.subtle.sign("Ed25519",
          trust.devicePrivateKey, concat(HEAD, rawHead)));
        const requestedDigest = await hash(concat(HEAD, rawHead, headerSig));
        const signed = await signedAuth("catalog-commit", 0, before.head,
          requestedDigest, undefined, undefined, issued);
        // Header time and authorization time must be byte-identical on the server.
        if (signed.authorization.issued_at !== issued) deny();
        const request = { authorization: signed.authorization, signatureBase64: signed.signatureBase64,
          headerBase64: b64(rawHead), headerSignatureBase64: b64(headerSig), pages: wireRows(rows) };
        await ownerCurrent();
        try {
          const ack = await post("commit", request);
          exact(ack, ["sequence", "catalogDigest", "authorityProofBase64"]);
          if (ack.sequence !== header.sequence
            || !equal(from64(ack.catalogDigest, 32), requestedDigest)) deny();
          const signedAck = await casHead(signed.nonce, from64(ack.authorityProofBase64, 1, 8192));
          if (signedAck.sequence !== header.sequence || !equal(signedAck.digest, requestedDigest)) deny();
        } catch (_) { /* Commit might have reached the external CAS. Read fresh, never repeat POST. */ }
        const final = await readAll({ sequence: header.sequence, digest: requestedDigest });
        if (final.rows.length !== rows.length) deny();
        for (let i = 0; i < rows.length; i++) {
          if (rows[i].object_id !== final.rows[i].object_id
            || rows[i].revision !== final.rows[i].revision || rows[i].epoch !== final.rows[i].epoch
            || !equal(rows[i].ciphertext_digest, final.rows[i].ciphertext_digest)
            || !equal(rows[i].metadata_ciphertext, final.rows[i].metadata_ciphertext)) deny();
        }
        advance(final.head);
        if (options.retainPendingIntent === true) {
          pendingCommit = { journalId, sequence: final.head.sequence,
            digest: b64(final.head.digest) };
        } else {
          await trust.journalStore.remove(journalId);
        }
        return Object.freeze({ sequence: final.head.sequence, digest: b64(final.head.digest),
          totalCount: rows.length, verifiedSignedReadback: true,
          productionDurabilityProven: false });
      } catch (_) { deny(); }
    }
    async function confirmPendingIntent(journalId, head) {
      try {
        const { body, rows: oldRows, plans } = await verifiedIntent(journalId);
        // The final proof can itself be lost. An absent caller hint is never
        // treated as success: derive the successor from a NEW independent CAS
        // challenge, then prove its full signed contents against the journal.
        const independentlyObserved = await freshHead();
        const wanted = { sequence: independentlyObserved.sequence,
          digest: bytes(independentlyObserved.digest, 32) };
        if (head !== undefined) {
          exact(head, ["sequence", "digest", "totalCount", "verifiedSignedReadback",
            "productionDurabilityProven"]);
          if (head.verifiedSignedReadback !== true
            || head.productionDurabilityProven !== false
            || head.totalCount !== oldRows.length + plans.size
            || head.sequence !== wanted.sequence
            || !equal(from64(head.digest, 32), wanted.digest)) deny();
        }
        if (wanted.sequence !== body.previousSequence + 1
          || (pendingCommit && (pendingCommit.journalId !== journalId
            || pendingCommit.sequence !== wanted.sequence
            || pendingCommit.digest !== b64(wanted.digest)))) deny();
        // The journal alone is only an intent, not a proof of a commit. On a
        // fresh browser instance the exact immutable successor must be proven
        // again by independent nonce-bound witness/CAS signatures and the
        // complete signed catalog readback; never retransmit the commit.
        const snapshot = await readAll(wanted);
        const verified = verifiedSnapshots.get(snapshot);
        if (!verified || verified.signerDeviceId !== body.deviceId
          || !equal(verified.predecessorDigest, from64(body.previousDigest, 32))
          || snapshot.rows.length !== oldRows.length + plans.size) deny();
        const actual = new Map();
        for (const row of snapshot.rows) {
          const version = row.object_id + ":" + row.revision;
          if (actual.has(version)) deny();
          actual.set(version, row);
        }
        for (const old of oldRows) {
          const version = old.object_id + ":" + old.revision;
          const row = actual.get(version);
          if (!row || row.epoch !== old.epoch
            || !equal(row.ciphertext_digest, old.ciphertext_digest)
            || !equal(row.metadata_ciphertext, old.metadata_ciphertext)) deny();
          actual.delete(version);
        }
        for (const [version, planned] of plans) {
          const row = actual.get(version);
          if (!row || row.epoch !== planned.epoch
            || !equal(row.ciphertext_digest, planned.digest)) deny();
          // A catalog row does not prove that its protected ciphertext exists.
          // Perform a NEW exact, authorized GET with the owner/device grant.
          await fetchVerifiedCiphertext(planned.objectId, planned.revision,
            planned.epoch, planned.digest);
          actual.delete(version);
        }
        if (actual.size !== 0) deny();
        const final = await freshHead();
        if (final.sequence !== wanted.sequence || !equal(final.digest, wanted.digest)) deny();
        requireSession();
        await trust.journalStore.remove(journalId);
        pendingCommit = null;
        return true;
      } catch (_) { deny(); }
    }
    // An explicit, verified additive delta only. Renames, moves, delete/trash,
    // compaction and any omission of an existing immutable version fail closed.
    return Object.freeze({ readAll: async () => {
      try { return await readAll(); } catch (_) { deny(); }
    }, readVerifiedCiphertext, readSignedSuccessor, prepareIntent, commit, confirmPendingIntent,
    delete: deny, trash: deny, rename: deny, move: deny });
  }
  return Object.freeze({ createClient, indexedDbJournalStore });
}));
