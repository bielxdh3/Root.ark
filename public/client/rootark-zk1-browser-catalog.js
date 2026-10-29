(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-normal-browser-trust-floor"),
      require("./rootark-zk1-protected-http-client"));
  } else {
    root.RootarkZk1BrowserCatalog = factory(root.crypto,
      root.RootarkZk1NormalBrowserTrustFloor, root.RootarkZk1ProtectedHttpClient);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto, trustFloor, http) {
  "use strict";
  // Only the explicitly mounted ZK1 routes are addressed. The browser never
  // touches generic sync-v2, plaintext metadata or a server-supplied trust pin.
  const enc = new TextEncoder(), dec = new TextDecoder("utf-8", { fatal: true });
  const DOMAIN_OP = enc.encode("Root.ark/zk-1/protected-object-operation/v1\0");
  const DOMAIN_ID = enc.encode("Root.ark/zk-1/opaque-catalog-operation-id/v1\0");
  const DOMAIN_HEAD = enc.encode("Root.ark/zk-1/opaque-catalog-head/v1\0");
  const DOMAIN_PAGE = enc.encode("Root.ark/zk-1/opaque-catalog-page/v1\0");
  const DOMAIN_CAS = enc.encode("Root.ark/zk-1/opaque-catalog-cas/v1\0");
  const DOMAIN_GRANT = enc.encode("Root.ark/zk-1/browser-owner-device-grant/v1\0");
  const DOMAIN_META = enc.encode("Root.ark/zk-1/opaque-catalog-metadata/v1\0");
  const GRANT = ["schema", "account_id", "compartment_id", "keyring_id",
    "device_id", "authorization_key_id", "authorization_public_key",
    "manifest_revision", "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
  const HEAD = ["type", "account_id", "compartment_id", "keyring_id", "sequence",
    "previous_digest", "manifest_revision", "manifest_digest", "epoch",
    "signer_device_id", "total_count", "page_digests", "issued_at"];
  const RECEIPT = ["type", "account_id", "compartment_id", "keyring_id",
    "sequence", "digest", "nonce", "observed_at", "signature"];
  const OP = ["account_id", "compartment_id", "keyring_id", "device_id", "operation",
    "object_id", "expected_object_revision", "manifest_revision", "manifest_digest",
    "epoch", "nonce", "issued_at", "expires_at", "ciphertext_digest"];
  const B64_FIELDS = new Set(["account_id", "compartment_id", "keyring_id",
    "manifest_digest", "nonce", "ciphertext_digest"]);
  const EMPTY = new Uint8Array(32);
  const MAX_VERSIONS = 4096, PAGE_SIZE = 32, MAX_CATALOG_HEADS = 128;
  const HTTP_READ_DEADLINE_MS = 15_000;
  const genuine = new WeakMap();
  function deny() { throw new Error("ZK_BROWSER_CATALOG_UNVERIFIED"); }
  function exact(v, keys) {
    if (!v || typeof v !== "object" || Array.isArray(v)
      || Object.keys(v).length !== keys.length
      || keys.some((key) => !Object.hasOwn(v, key))) deny();
  }
  function number(v, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(v) || v < minimum || v > maximum) deny();
    return v;
  }
  function to64(raw) {
    let s = "";
    for (const b of raw) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(s, min, max = min) {
    if (typeof s !== "string" || !/^[A-Za-z0-9_-]+$/.test(s)
      || s.length > Math.ceil(max * 4 / 3) + 4) deny();
    let raw;
    try { raw = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=")); }
    catch (_) { deny(); }
    const out = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    if (out.length < min || out.length > max || to64(out) !== s) deny();
    return out;
  }
  function bytes(v, min, max = min) {
    if (!ArrayBuffer.isView(v) || v.byteLength < min || v.byteLength > max) deny();
    return new Uint8Array(v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength));
  }
  function equal(a, b) {
    if (a.length !== b.length) return false;
    let delta = 0;
    for (let i = 0; i < a.length; i++) delta |= a[i] ^ b[i];
    return delta === 0;
  }
  function join(parts, bound = 32768) {
    const size = parts.reduce((n, x) => n + x.length, 0);
    if (size > bound) deny();
    const out = new Uint8Array(size);
    let i = 0;
    for (const part of parts) { out.set(part, i); i += part.length; }
    return out;
  }
  function major(prefix, value) {
    number(value);
    if (value < 24) return Uint8Array.of(prefix * 32 + value);
    if (value < 256) return Uint8Array.of(prefix * 32 + 24, value);
    if (value < 65536) return Uint8Array.of(prefix * 32 + 25, value >>> 8, value & 255);
    if (value < 4294967296) return Uint8Array.of(prefix * 32 + 26,
      (value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
    const b = BigInt(value);
    return Uint8Array.of(prefix * 32 + 27, ...Array.from({ length: 8 },
      (_, i) => Number((b >> BigInt(56 - i * 8)) & 255n)));
  }
  function cbor(x) {
    if (x === null) return Uint8Array.of(0xf6);
    if (Number.isSafeInteger(x) && x >= 0) return major(0, x);
    if (typeof x === "string") {
      const data = enc.encode(x); return join([major(3, data.length), data], 32768);
    }
    if (x instanceof Uint8Array) return join([major(2, x.length), x], 32768);
    if (Array.isArray(x)) return join([major(4, x.length), ...x.map(cbor)], 32768);
    if (!x || typeof x !== "object" || ![Object.prototype, null].includes(Object.getPrototypeOf(x))) deny();
    const items = Object.entries(x).map(([key, value]) => [cbor(key), cbor(value)]);
    const compare = (a, b) => a.length - b.length
      || (() => { for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; })();
    items.sort((a, b) => compare(a[0], b[0]));
    return join([major(5, items.length), ...items.flat()], 32768);
  }
  // Bounded, canonical subset of CBOR used by signed catalog envelopes.
  // Reject indefinite lengths, floats, tags, duplicate map keys, invalid UTF8.
  function decode(input, maximum) {
    const raw = bytes(input, 1, maximum);
    let offset = 0, nodes = 0;
    function take(n) {
      if (!Number.isSafeInteger(n) || n < 0 || offset + n > raw.length) deny();
      const value = raw.subarray(offset, offset + n); offset += n; return value;
    }
    function parse(depth) {
      if (depth > 8 || ++nodes > 1200) deny();
      const marker = take(1)[0], type = marker >>> 5, extra = marker & 31;
      if (marker === 0xf6) return null;
      if (![0, 2, 3, 4, 5].includes(type)) deny();
      let count;
      if (extra < 24) count = extra;
      else if (extra === 24) count = take(1)[0];
      else if (extra === 25) { const b = take(2); count = b[0] * 256 + b[1]; }
      else if (extra === 26) { const b = take(4);
        count = b[0] * 16777216 + b[1] * 65536 + b[2] * 256 + b[3]; }
      else if (extra === 27) {
        let n = 0n; for (const b of take(8)) n = n * 256n + BigInt(b);
        if (n > BigInt(Number.MAX_SAFE_INTEGER)) deny(); count = Number(n);
      } else deny();
      if (type === 0) return count;
      if (type === 2) return bytes(take(count), count);
      if (type === 3) return dec.decode(take(count));
      if (count > 1200) deny();
      if (type === 4) return Array.from({ length: count }, () => parse(depth + 1));
      const result = Object.create(null);
      for (let i = 0; i < count; i++) {
        const key = parse(depth + 1);
        if (typeof key !== "string" || Object.hasOwn(result, key)) deny();
        result[key] = parse(depth + 1);
      }
      return result;
    }
    const value = parse(0);
    if (offset !== raw.length || !equal(cbor(value), raw)) deny();
    return value;
  }
  async function hash(bytesValue) {
    return new Uint8Array(await webCrypto.subtle.digest("SHA-256", bytesValue));
  }
  function scopeOf(grant) {
    return Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
      .map((key) => [key, grant[key]]));
  }
  function scopeCheck(actual, expected) {
    for (const key of Object.keys(expected)) {
      if (!(actual[key] instanceof Uint8Array) || !equal(actual[key],
        from64(expected[key], key === "compartment_id" ? 1 : 16,
          key === "compartment_id" ? 128 : 16))) deny();
    }
  }
  function keyCheck(key, role) {
    if (key?.type !== role || key?.algorithm?.name !== "Ed25519"
      || !key?.usages?.includes(role === "private" ? "sign" : "verify")
      || (role === "private" && key.extractable !== false)) deny();
  }
  async function grantCheck(grant, ownerKey, pinnedHead) {
    exact(grant, [...GRANT, "signature"]);
    if (grant.schema !== "rootark-zk1-browser-owner-device-grant/v1"
      || grant.revoked_at_epoch !== null
      || grant.manifest_revision !== pinnedHead.revision
      || grant.manifest_digest !== to64(bytes(pinnedHead.digest, 32))
      || grant.current_epoch !== pinnedHead.epoch
      || number(grant.enrolled_epoch, 1) > pinnedHead.epoch) deny();
    for (const [field, size] of [["account_id", 16], ["keyring_id", 16],
      ["authorization_key_id", 16], ["authorization_public_key", 32]]) from64(grant[field], size);
    from64(grant.compartment_id, 1, 128);
    if (typeof grant.device_id !== "string" || !grant.device_id
      || grant.device_id.length > 64 || /[\u0000-\u001f\u007f]/.test(grant.device_id)) deny();
    const payload = join([DOMAIN_GRANT, enc.encode(JSON.stringify(
      Object.fromEntries(GRANT.map((field) => [field, grant[field]]))))]);
    if (!await webCrypto.subtle.verify("Ed25519", ownerKey, from64(grant.signature, 64), payload)) deny();
  }
  async function operationId(scope, page) {
    const key = ["account_id", "compartment_id", "keyring_id"].map((field) =>
      Array.from(from64(scope[field], field === "compartment_id" ? 1 : 16,
        field === "compartment_id" ? 128 : 16), (b) => b.toString(16).padStart(2, "0")).join("")).join(":");
    const data = join([DOMAIN_ID, enc.encode(key), enc.encode("catalog-read:" + page)]);
    return to64((await hash(data)).subarray(0, 16));
  }
  async function signedCatalogRead({ scope, signerKey, deviceId, head, sequence, digest, page, now }) {
    const authorization = { account_id: from64(scope.account_id, 16),
      compartment_id: from64(scope.compartment_id, 1, 128),
      keyring_id: from64(scope.keyring_id, 16), device_id: deviceId,
      operation: "catalog-read", object_id: await operationId(scope, page),
      expected_object_revision: number(sequence, 1, MAX_CATALOG_HEADS),
      manifest_revision: head.revision, manifest_digest: bytes(head.digest, 32),
      epoch: head.epoch, nonce: webCrypto.getRandomValues(new Uint8Array(32)),
      issued_at: now, expires_at: now + 45, ciphertext_digest: bytes(digest, 32) };
    const message = join([DOMAIN_OP, cbor(authorization)]);
    const signature = new Uint8Array(await webCrypto.subtle.sign("Ed25519", signerKey, message));
    const wire = Object.fromEntries(OP.map((field) => [field,
      B64_FIELDS.has(field) ? to64(authorization[field]) : authorization[field]]));
    return { authorization: wire, signatureBase64: to64(signature), pageIndex: page };
  }
  async function readJson(fetchImpl, url, body, assertLive, max = 35000) {
    if (typeof AbortController !== "function") deny();
    const controller = new AbortController();
    let reader, complete = false, timer;
    // The same absolute deadline covers DNS, response headers and every byte
    // of a slow/trickled body. Byte limits alone cannot bound stalled recovery
    // after historical CEKs have been decrypted in memory.
    const deadline = new Promise((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error("catalog HTTP deadline"));
      }, HTTP_READ_DEADLINE_MS);
    });
    try {
      const work = (async () => {
        assertLive();
        if (typeof location === "object" && location.origin
          && new URL(url).origin !== location.origin) deny();
        const response = await fetchImpl(url, {
          method: "POST", credentials: "same-origin",
          cache: "no-store", redirect: "error", mode: "same-origin",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify(body), signal: controller.signal,
        });
        assertLive();
        if (controller.signal.aborted || response.status !== 200
          || !/application\/json/i.test(response.headers.get("content-type") || "")) deny();
        reader = response.body?.getReader();
        if (!reader) deny();
        const chunks = []; let size = 0;
        while (true) {
          const { done, value } = await reader.read();
          assertLive();
          if (controller.signal.aborted) deny();
          if (done) { complete = true; break; }
          if (!ArrayBuffer.isView(value) || value.BYTES_PER_ELEMENT !== 1
            || value.byteLength === 0) deny();
          size += value.byteLength;
          if (size > max) deny();
          chunks.push(value);
        }
        return JSON.parse(dec.decode(join(chunks, max)));
      })();
      return await Promise.race([work, deadline]);
    } catch (_) { deny(); }
    finally {
      clearTimeout(timer);
      controller.abort();
      if (reader) {
        if (!complete) {
          // Never await cancellation: a malicious reader can stall cancel().
          try { Promise.resolve(reader.cancel()).catch(() => {}); } catch (_) { /* denied */ }
        }
        try { reader.releaseLock(); } catch (_) { /* aborted */ }
      }
    }
  }
  async function verifyPage({ response, scope, signerGrant, pinnedHead,
    authorityKey, requestNonce, expectedSequence, expectedDigest, index, now }) {
    exact(response, ["sequence", "totalCount", "pageIndex", "pageCount",
      "catalogDigest", "headerBase64", "headerSignatureBase64", "entries",
      "authorityProofBase64"]);
    const raw = from64(response.headerBase64, 1, 16384);
    const header = decode(raw, 16384);
    exact(header, HEAD);
    if (header.type !== "rootark-zk1-opaque-catalog/v1") deny();
    scopeCheck(header, scope);
    number(header.sequence, 1, MAX_CATALOG_HEADS);
    number(header.total_count, 0, MAX_VERSIONS);
    number(header.manifest_revision, 1);
    number(header.epoch, 1);
    number(header.issued_at);
    if (header.signer_device_id !== signerGrant.device_id
      || header.manifest_revision > pinnedHead.revision
      || (header.manifest_revision === pinnedHead.revision
        && !equal(header.manifest_digest, bytes(pinnedHead.digest, 32)))
      || header.epoch > pinnedHead.epoch
      || !Array.isArray(header.page_digests)
      || header.page_digests.length !== Math.ceil(header.total_count / PAGE_SIZE)
      || response.pageCount !== header.page_digests.length
      || response.totalCount !== header.total_count
      || response.pageIndex !== index || response.sequence !== header.sequence) deny();
    for (const d of header.page_digests) bytes(d, 32);
    bytes(header.previous_digest, 32);
    bytes(header.manifest_digest, 32);
    const signerKey = await webCrypto.subtle.importKey("raw",
      from64(signerGrant.authorization_public_key, 32), "Ed25519", false, ["verify"]);
    const signature = from64(response.headerSignatureBase64, 64);
    if (!await webCrypto.subtle.verify("Ed25519", signerKey, signature,
      join([DOMAIN_HEAD, raw]))) deny();
    const digest = await hash(join([DOMAIN_HEAD, raw, signature]));
    if (!equal(digest, from64(response.catalogDigest, 32))
      || header.sequence !== expectedSequence || !equal(digest, expectedDigest)) deny();
    const receipt = decode(from64(response.authorityProofBase64, 1, 8192), 8192);
    exact(receipt, RECEIPT);
    scopeCheck(receipt, scope);
    if (receipt.type !== "rootark-zk1-opaque-catalog-cas/v1"
      || receipt.sequence !== header.sequence
      || !equal(bytes(receipt.digest, 32), digest)
      || !equal(bytes(receipt.nonce, 32), requestNonce)
      || Math.abs(number(receipt.observed_at) - now) > 30) deny();
    const { signature: casSignature, ...statement } = receipt;
    if (!await webCrypto.subtle.verify("Ed25519", authorityKey,
      bytes(casSignature, 64), join([DOMAIN_CAS, cbor(statement)]))) deny();
    const entries = response.entries;
    const expected = header.total_count === 0 ? 0 : index === header.page_digests.length - 1
      ? header.total_count - index * PAGE_SIZE : PAGE_SIZE;
    if (!Array.isArray(entries) || entries.length !== expected) deny();
    const tuples = entries.map((entry) => {
      exact(entry, ["objectId", "revision", "epoch", "ciphertextDigestBase64",
        "metadataCiphertextBase64"]);
      const id = entry.objectId;
      if (!/^[A-Za-z0-9_-]{22}$/.test(id) || from64(id, 16).length !== 16) deny();
      return { object_id: id, revision: number(entry.revision, 1),
        epoch: number(entry.epoch, 1),
        ciphertext_digest: from64(entry.ciphertextDigestBase64, 32),
        metadata_ciphertext: from64(entry.metadataCiphertextBase64, 284) };
    });
    for (let i = 1; i < tuples.length; i++) if (tuples[i - 1].object_id > tuples[i].object_id
      || (tuples[i - 1].object_id === tuples[i].object_id
        && tuples[i - 1].revision >= tuples[i].revision)) deny();
    if (tuples.length) {
      const digestPage = await hash(join([DOMAIN_PAGE, cbor(tuples)], 16384));
      if (!equal(digestPage, bytes(header.page_digests[index], 32))) deny();
    }
    return { digest, header, entries: tuples };
  }
  function readFloor(scope, keyId, impl) {
    if (!impl || typeof impl.open !== "function") deny();
    const name = "rootark-zk1-browser-catalog-floor/v1";
    const key = JSON.stringify([scope.account_id, scope.compartment_id, scope.keyring_id, keyId]);
    return { name, key, impl };
  }
  async function indexedFloor(config, next = null) {
    const { name, key, impl } = config;
    const db = await new Promise((resolve, reject) => {
      const request = impl.open(name, 1);
      request.onupgradeneeded = () => request.result.createObjectStore("heads");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error("DB"));
      request.onblocked = () => reject(new Error("DB"));
    });
    try {
      return await new Promise((resolve, reject) => {
        let previous = null;
        const tx = db.transaction("heads", next ? "readwrite" : "readonly");
        const store = tx.objectStore("heads");
        const r = store.get(key);
        r.onsuccess = () => {
          try {
            previous = r.result ?? null;
            if (previous !== null) {
              exact(previous, ["sequence", "digest", "pageDigests"]);
              number(previous.sequence, 1, MAX_CATALOG_HEADS);
              from64(previous.digest, 32);
              if (!Array.isArray(previous.pageDigests)
                || previous.pageDigests.length > MAX_VERSIONS / PAGE_SIZE
                || previous.pageDigests.some((d) => from64(d, 32).length !== 32)) deny();
            }
            if (next) {
              if (previous && (next.sequence < previous.sequence
                || (next.sequence === previous.sequence && next.digest !== previous.digest))) deny();
              store.put(next, key);
            }
          } catch (_) { tx.abort(); }
        };
        tx.oncomplete = () => resolve(previous);
        tx.onerror = () => reject(new Error("DB"));
        tx.onabort = () => reject(new Error("DB"));
      });
    } finally { db.close(); }
  }
  async function openCatalog(input) {
    try {
      exact(input, ["trust", "signerGrant", "devicePrivateKey", "catalogAuthorityKey",
        "independentAuthoritySpkiHash", "pinnedCatalogHead", "origin", "fetchImpl",
        "assertLive", "indexedDBImpl", "nowSeconds"]);
      const { trust, assertLive } = input;
      if (typeof assertLive !== "function" || typeof input.fetchImpl !== "function"
        || typeof input.origin !== "string" || !/^https?:\/\//.test(input.origin)
        || (typeof location === "object" && location.origin
          && input.origin !== location.origin + "/")) deny();
      keyCheck(trust.ownerPublicKey, "public");
      keyCheck(input.catalogAuthorityKey, "public");
      keyCheck(input.devicePrivateKey, "private");
      const actualSpki = new Uint8Array(await webCrypto.subtle.exportKey("spki", input.catalogAuthorityKey));
      if (!equal(await hash(actualSpki), bytes(input.independentAuthoritySpkiHash, 32))) deny();
      if (!trust.ownerHistoryCheckpoint) deny();
      await trustFloor.assertCurrent({ ownerPublicKey: trust.ownerPublicKey,
        independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
        pinnedCurrentHead: trust.pinnedCurrentHead,
        signedDeviceGrant: trust.signedDeviceGrant,
        ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
        previousOwnerHistoryProof: trust.previousOwnerHistoryProof });
      assertLive();
      await grantCheck(trust.signedDeviceGrant, trust.ownerPublicKey, trust.pinnedCurrentHead);
      await grantCheck(input.signerGrant, trust.ownerPublicKey, trust.pinnedCurrentHead);
      const scope = scopeOf(trust.signedDeviceGrant);
      if (!Object.keys(scope).every((k) => scope[k] === input.signerGrant[k])) deny();
      const challenge = webCrypto.getRandomValues(new Uint8Array(32));
      const ownKey = await webCrypto.subtle.importKey("raw",
        from64(trust.signedDeviceGrant.authorization_public_key, 32),
        "Ed25519", false, ["verify"]);
      const proof = await webCrypto.subtle.sign("Ed25519", input.devicePrivateKey, challenge);
      if (!await webCrypto.subtle.verify("Ed25519", ownKey, proof, challenge)) deny();
      const clock = typeof input.nowSeconds === "function"
        ? input.nowSeconds : () => input.nowSeconds;
      const initialNow = number(clock(), 0);
      const floor = input.pinnedCatalogHead;
      exact(floor, ["sequence", "digest"]);
      number(floor.sequence, 0, MAX_CATALOG_HEADS);
      from64(floor.digest, 32);
      if (floor.sequence === 0 && floor.digest !== to64(EMPTY)) deny();
      const keyId = to64(await hash(actualSpki));
      const dbFloor = readFloor(scope, keyId, input.indexedDBImpl);
      const previous = await indexedFloor(dbFloor);
      assertLive();
      if (previous && (previous.sequence > floor.sequence
        || (previous.sequence === floor.sequence && previous.digest !== floor.digest))) deny();
      // The first trusted catalog head must be pinned outside the server.
      // Importing a server's "current" head is explicitly refused.
      if (floor.sequence < 1) deny();
      const pageDigests = [];
      const entries = [];
      let header = null;
      for (let index = 0; index < MAX_VERSIONS / PAGE_SIZE; index++) {
        const now = number(clock(), initialNow);
        const wire = await signedCatalogRead({ scope, signerKey: input.devicePrivateKey,
          deviceId: trust.signedDeviceGrant.device_id, head: trust.pinnedCurrentHead,
          sequence: floor.sequence, digest: from64(floor.digest, 32), page: index, now });
        assertLive();
        const response = await readJson(input.fetchImpl, input.origin + "zk-1/v1/catalog/read",
          wire, assertLive);
        const verified = await verifyPage({ response, scope, signerGrant: input.signerGrant,
          pinnedHead: trust.pinnedCurrentHead, authorityKey: input.catalogAuthorityKey,
          requestNonce: from64(wire.authorization.nonce, 32),
          expectedSequence: floor.sequence, expectedDigest: from64(floor.digest, 32),
          index, now });
        assertLive();
        if (header && (!equal(from64(response.headerBase64, 1, 16384),
          header.raw) || verified.header.total_count !== header.value.total_count)) deny();
        if (!header) header = { value: verified.header, raw: from64(response.headerBase64, 1, 16384) };
        entries.push(...verified.entries);
        if (verified.header.page_digests.length) {
          pageDigests.push(to64(verified.header.page_digests[index]));
        }
        if (index + 1 >= Math.max(1, verified.header.page_digests.length)) break;
      }
      if (!header || entries.length !== header.value.total_count) deny();
      const next = { sequence: floor.sequence, digest: floor.digest,
        pageDigests: [...pageDigests] };
      await indexedFloor(dbFloor, next);
      assertLive();
      const deltaPages = Array.from({ length: pageDigests.length }, (_, i) => i)
        .filter((index) => !previous || previous.pageDigests[index] !== pageDigests[index]);
      const context = Object.freeze({ scope, signerKey: input.devicePrivateKey,
        deviceId: trust.signedDeviceGrant.device_id, head: trust.pinnedCurrentHead,
        catalogDigest: from64(next.digest, 32), sequence: next.sequence,
        origin: input.origin, fetchImpl: input.fetchImpl, assertLive, nowSeconds: clock });
      const result = Object.freeze({ sequence: next.sequence,
        catalogDigest: next.digest, totalCount: entries.length,
        pageDigests: Object.freeze(pageDigests),
        changedPageIndices: Object.freeze(deltaPages),
        entries: Object.freeze(entries.map((entry) => Object.freeze({
          objectId: entry.object_id, revision: entry.revision, epoch: entry.epoch,
          ciphertextDigestBase64: to64(entry.ciphertext_digest),
          metadataCiphertextBase64: to64(entry.metadata_ciphertext),
        }))) });
      genuine.set(result, context);
      return result;
    } catch (_) { deny(); }
  }
  async function getCatalogCiphertext(result, index) {
    try {
      const context = genuine.get(result);
      if (!context) deny();
      number(index, 0, result.entries.length - 1);
      context.assertLive();
      const item = result.entries[index];
      const signed = await http.signProtectedContentOperation({
        signerKey: context.signerKey, scope: context.scope, deviceId: context.deviceId,
        operation: "get", objectId: item.objectId,
        expectedObjectRevision: item.revision, manifestRevision: context.head.revision,
        manifestDigest: context.head.digest, epoch: context.head.epoch,
        nowSeconds: number(context.nowSeconds()), ciphertext: null,
        expectedCiphertextDigest: from64(item.ciphertextDigestBase64, 32) });
      context.assertLive();
      const received = await readJson(context.fetchImpl, context.origin + "zk-1/v1/content/read",
        signed, context.assertLive, 6 * 1024 * 1024);
      exact(received, ["id", "revision", "epoch", "ciphertextBase64"]);
      if (received.id !== item.objectId || received.revision !== item.revision
        || received.epoch !== item.epoch) deny();
      const ciphertext = from64(received.ciphertextBase64, 16, 4 * 1024 * 1024);
      if (!equal(await hash(ciphertext), from64(item.ciphertextDigestBase64, 32))) deny();
      context.assertLive();
      return Object.freeze({ objectId: item.objectId, revision: item.revision,
        ciphertextBase64: to64(ciphertext) });
    } catch (_) { deny(); }
  }
  async function assertVersionedArchiveMatchesCatalog(input) {
    try {
      exact(input, ["catalog", "files"]);
      // Only openCatalog can issue this in-process capability after verifying
      // the device signature, independently pinned signed CAS head, page
      // digests, signed owner grant and monotonic local catalog floor.
      const context = genuine.get(input.catalog);
      if (!context || !Array.isArray(input.files)
        || input.files.length < 1 || input.files.length !== input.catalog.entries.length
        || input.files.length > MAX_VERSIONS
        || Reflect.ownKeys(input.files).length !== input.files.length + 1) deny();
      const seen = new Set();
      for (const [index, entry] of input.catalog.entries.entries()) {
        context.assertLive();
        const file = input.files[index];
        if (!file || typeof file !== "object" || !file.metadata
          || typeof file.metadata !== "object") deny();
        const key = entry.objectId + ":" + entry.revision;
        if (seen.has(key) || file.objectId !== entry.objectId
          || file.objectRevision !== entry.revision
          || file.metadata.object_id !== file.objectId
          || file.metadata.epoch !== entry.epoch
          || file.metadata.account_id !== context.scope.account_id
          || file.metadata.compartment_id !== context.scope.compartment_id
          || file.metadata.keyring_id !== context.scope.keyring_id) deny();
        seen.add(key);
        const sealed = bytes(file.ciphertext, 16, 4 * 1024 * 1024);
        if (!equal(await hash(sealed), from64(entry.ciphertextDigestBase64, 32))) deny();
        // The CAS snapshot alone may describe ciphertext no longer readable
        // after a failed copy or concurrent deletion. Require a fresh signed,
        // device-authorized protected GET for EVERY recovered version.
        const onServer = await getCatalogCiphertext(input.catalog, index);
        if (onServer.objectId !== file.objectId
          || onServer.revision !== file.objectRevision
          || !equal(sealed, from64(onServer.ciphertextBase64, 16, 4 * 1024 * 1024))) deny();
      }
      context.assertLive();
      return Object.freeze({ signedCatalogCasCoverageVerified: true,
        protectedCiphertextReadbackVerified: true,
        catalogSequence: input.catalog.sequence,
        authorizesCutover: false, externalDurabilityProven: false });
    } catch (_) { deny(); }
  }
  async function openCatalogName(result, index, metadataKey) {
    const context = genuine.get(result);
    if (!context) deny();
    number(index, 0, result.entries.length - 1);
    const item = result.entries[index];
    const sealed = from64(item.metadataCiphertextBase64, 284);
    const aad = join([DOMAIN_META, cbor({
      account_id: from64(context.scope.account_id, 16),
      compartment_id: from64(context.scope.compartment_id, 1, 128),
      keyring_id: from64(context.scope.keyring_id, 16),
      object_id: item.objectId, revision: item.revision, epoch: item.epoch,
    })]);
    try {
      const key = await webCrypto.subtle.importKey("raw", bytes(metadataKey, 32),
        "AES-GCM", false, ["decrypt"]);
      const opened = new Uint8Array(await webCrypto.subtle.decrypt({
        name: "AES-GCM", iv: sealed.subarray(0, 12), additionalData: aad,
        tagLength: 128 }, key, sealed.subarray(12)));
      const size = opened[0] * 256 + opened[1];
      if (size < 1 || size > 220) deny();
      const name = dec.decode(opened.subarray(2, 2 + size));
      opened.fill(0);
      if (!name || /[\u0000-\u001f\u007f]/.test(name)) deny();
      context.assertLive();
      return name;
    } catch (_) { deny(); }
  }
  return Object.freeze({ openCatalog, getCatalogCiphertext,
    assertVersionedArchiveMatchesCatalog, openCatalogName });
}));
