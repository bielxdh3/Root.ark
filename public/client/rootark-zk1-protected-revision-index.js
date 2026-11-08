(function (root, factory) {
  if (typeof module === "object" && module.exports)
    module.exports = factory(require("node:crypto").webcrypto);
  else root.RootarkZk1ProtectedRevisionIndex = factory(root.crypto);
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto) {
  "use strict";

  // Encrypted local snapshot of explicitly owner-selected, verified historical
  // text. Not a complete catalog index or an authorization source.
  const DB = "rootark-zk1-protected-revision-index-v1";
  const STORE = "revisions";
  const FORMAT = "rootark-zk1-protected-revision-index/v1";
  const MAX_ROWS = 128;
  const MAX_BYTES = 4 * 1024 * 1024;
  const PAGE = 50;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const opaque = /^[A-Za-z0-9_-]{22}$/;
  const digest = /^[A-Za-z0-9_-]{43}$/;
  const types = new Set(["text/plain", "text/markdown", "text/csv", "application/json"]);
  function deny() { throw Error("ZK_REVISION_INDEX_DENIED"); }
  function live(check) {
    if (typeof check !== "function") deny();
    const result = check();
    if (result === false || result && typeof result.then === "function") deny();
  }
  function to64(bytes) {
    let text = "";
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(raw, min, max = min) {
    if (typeof raw !== "string" || !/^[A-Za-z0-9_-]+$/.test(raw)
      || raw.length > Math.ceil(max * 4 / 3) + 4) deny();
    let data;
    try { data = Uint8Array.from(atob(raw.replace(/-/g, "+")
      .replace(/_/g, "/").padEnd(Math.ceil(raw.length / 4) * 4, "=")),
    (character) => character.charCodeAt(0)); } catch (_) { deny(); }
    if (data.length < min || data.length > max || to64(data) !== raw) deny();
    return data;
  }
  function scopeOf(grant) {
    const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
      .map((name) => [name, grant[name]]));
    from64(scope.account_id, 16);
    from64(scope.compartment_id, 1, 128);
    from64(scope.keyring_id, 16);
    return scope;
  }
  function context(input) {
    const { grant, ownerHead, baseline } = input;
    if (!grant || !ownerHead || !baseline
      || grant.revoked_at_epoch !== null
      || typeof grant.device_id !== "string" || !grant.device_id
      || grant.device_id.length > 128
      || !Number.isSafeInteger(grant.manifest_revision)
      || !Number.isSafeInteger(grant.current_epoch)
      || !Number.isSafeInteger(ownerHead.revision) || ownerHead.revision < 1
      || !Number.isSafeInteger(ownerHead.epoch) || ownerHead.epoch < 1
      || !digest.test(ownerHead.digest)
      || grant.manifest_revision !== ownerHead.revision
      || grant.manifest_digest !== ownerHead.digest
      || grant.current_epoch !== ownerHead.epoch
      || !Number.isSafeInteger(baseline.head?.sequence)
      || baseline.head.sequence < 1 || !digest.test(baseline.head.digest)
      || !Array.isArray(baseline.entries) || baseline.entries.length > 4096) deny();
    const scope = scopeOf(grant);
    return { format: FORMAT, scope, deviceId: grant.device_id,
      ownerHead: { revision: ownerHead.revision, epoch: ownerHead.epoch,
        digest: ownerHead.digest },
      catalogHead: { sequence: baseline.head.sequence, digest: baseline.head.digest } };
  }
  function cacheKey(scope) {
    return JSON.stringify([scope.account_id, scope.compartment_id, scope.keyring_id]);
  }
  function checkRows(rows, baseline) {
    if (!Array.isArray(rows) || !rows.length || rows.length > MAX_ROWS) deny();
    const signed = new Map();
    for (const entry of baseline.entries) {
      const key = entry.objectId + ":" + entry.revision;
      if (signed.has(key)) deny();
      signed.set(key, entry);
    }
    const seen = new Set();
    for (const row of rows) {
      if (!row || typeof row !== "object" || Array.isArray(row)
        || Object.keys(row).sort().join(",") !==
          "ciphertextDigestBase64,epoch,mediaType,name,objectId,revision,text"
        || !opaque.test(row.objectId)
        || !Number.isSafeInteger(row.revision) || row.revision < 1
        || !Number.isSafeInteger(row.epoch) || row.epoch < 1
        || !digest.test(row.ciphertextDigestBase64)
        || !types.has(row.mediaType)
        || typeof row.name !== "string" || !row.name
        || encoder.encode(row.name).length > 220
        || typeof row.text !== "string" || encoder.encode(row.text).length > 64 * 1024) deny();
      const key = row.objectId + ":" + row.revision;
      const original = signed.get(key);
      if (seen.has(key) || !original || original.epoch !== row.epoch
        || original.ciphertextDigestBase64 !== row.ciphertextDigestBase64) deny();
      seen.add(key);
    }
    return rows;
  }
  function store(indexedDBImpl) {
    if (typeof indexedDBImpl?.open !== "function") deny();
    async function transaction(mode, operation, key, value, expectedNonce, assertLive) {
      const database = await new Promise((resolve, reject) => {
        const request = indexedDBImpl.open(DB, 1);
        request.onupgradeneeded = () => {
          if (!request.result.objectStoreNames.contains(STORE))
            request.result.createObjectStore(STORE);
        };
        request.onerror = request.onblocked = () => reject(Error("INDEXEDDB_UNAVAILABLE"));
        request.onsuccess = () => resolve(request.result);
      });
      try {
        return await new Promise((resolve, reject) => {
          let result;
          try {
            const tx = database.transaction(STORE, mode);
            const objectStore = tx.objectStore(STORE);
            const request = operation === "delete" ? objectStore.delete(key)
              : objectStore.get(key);
            request.onsuccess = () => {
              if (operation === "save") {
                // A logout can happen while IndexedDB opens or before its
                // queued request settles. Check inside this write transaction.
                try { live(assertLive); }
                catch (_) { tx.abort(); return; }
                const present = request.result;
                if ((present?.nonce ?? null) !== expectedNonce) {
                  tx.abort();
                  return;
                }
                const write = objectStore.put(value, key);
                write.onerror = () => reject(Error("INDEXEDDB_UNAVAILABLE"));
              } else result = request.result;
            };
            request.onerror = () => reject(Error("INDEXEDDB_UNAVAILABLE"));
            tx.oncomplete = () => resolve(result);
            tx.onerror = tx.onabort = () => reject(Error("INDEXEDDB_UNAVAILABLE"));
          } catch (error) { reject(error); }
        });
      } finally { database.close(); }
    }
    return {
      read: (key) => transaction("readonly", "read", key),
      save: (key, value, expected, assertLive) =>
        transaction("readwrite", "save", key, value, expected, assertLive),
      delete: (key) => transaction("readwrite", "delete", key),
    };
  }
  async function keyFor(raw, scope) {
    if (!(raw instanceof Uint8Array) || raw.length !== 32 || !webCrypto?.subtle) deny();
    const root = await webCrypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
    const salt = await webCrypto.subtle.digest("SHA-256", encoder.encode(
      JSON.stringify([FORMAT, scope.account_id, scope.compartment_id, scope.keyring_id])));
    return webCrypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt,
      info: encoder.encode("Root.ark/zk-1/protected-revision-text-index/aes-gcm/v1") },
    root, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function verifiedHead(input, pinned) {
    live(input.assertLive);
    if (typeof input.client?.verifyPrivateListingHead !== "function") deny();
    const result = await input.client.verifyPrivateListingHead(input.baseline);
    live(input.assertLive);
    if (result?.head?.sequence !== pinned.catalogHead.sequence
      || result.head.digest !== pinned.catalogHead.digest
      || !["account_id", "compartment_id", "keyring_id"]
        .every((name) => result.scope?.[name] === pinned.scope[name])) deny();
  }
  async function openRows(record, pinned, secret, baseline) {
    if (!record || record.format !== FORMAT
      || record.context !== JSON.stringify(pinned)
      || !opaque.test(record.nonce)) deny();
    const plaintext = new Uint8Array(await webCrypto.subtle.decrypt({ name: "AES-GCM",
      iv: from64(record.iv, 12),
      additionalData: encoder.encode(record.context), tagLength: 128 },
    secret, from64(record.ciphertext, 16, MAX_BYTES + 16)));
    try {
      if (plaintext.length > MAX_BYTES) deny();
      return checkRows(JSON.parse(decoder.decode(plaintext)), baseline);
    } finally { plaintext.fill(0); }
  }
  async function append(input) {
    try {
      live(input?.assertLive);
      const pinned = context(input);
      const incoming = checkRows(input.entries, input.baseline);
      if (incoming.length > 64) deny(); // One complete verified batch only.
      await verifiedHead(input, pinned);
      const db = store(input.indexedDBImpl);
      const key = cacheKey(pinned.scope);
      const record = await db.read(key);
      live(input.assertLive);
      if (record && (!opaque.test(record.nonce) || record.format !== FORMAT)) deny();
      const secret = await keyFor(input.metadataRaw, pinned.scope);
      live(input.assertLive);
      const current = record?.context === JSON.stringify(pinned)
        ? await openRows(record, pinned, secret, input.baseline) : [];
      live(input.assertLive);
      const combined = new Map(current.map((row) => [row.objectId + ":" + row.revision, row]));
      for (const row of incoming) {
        const rowKey = row.objectId + ":" + row.revision;
        if (combined.has(rowKey) && JSON.stringify(combined.get(rowKey)) !== JSON.stringify(row)) deny();
        combined.set(rowKey, row);
      }
      const rows = checkRows([...combined.values()], input.baseline);
      const plain = encoder.encode(JSON.stringify(rows));
      if (plain.length > MAX_BYTES) { plain.fill(0); deny(); }
      const iv = webCrypto.getRandomValues(new Uint8Array(12));
      let sealed;
      try {
        sealed = await webCrypto.subtle.encrypt({ name: "AES-GCM", iv,
          additionalData: encoder.encode(JSON.stringify(pinned)), tagLength: 128 },
        secret, plain);
      } finally { plain.fill(0); }
      live(input.assertLive);
      await verifiedHead(input, pinned);
      await db.save(key, { format: FORMAT, context: JSON.stringify(pinned),
        nonce: to64(webCrypto.getRandomValues(new Uint8Array(16))),
        iv: to64(iv), ciphertext: to64(new Uint8Array(sealed)) },
      record?.nonce ?? null, input.assertLive);
      live(input.assertLive);
      return Object.freeze({ indexedCount: rows.length, persistedIndex: true,
        coverage: "owner-selected-revisions-only", plaintextSentToServer: false,
        authorizesMutation: false });
    } catch (_) { deny(); }
  }
  function checkedMatcher(query, mode) {
    if (typeof query !== "string" || query.length > 120
      || /[\u0000-\u001f\u007f\u2028\u2029]/.test(query)) deny();
    const folded = query.normalize("NFC").trim().toLocaleLowerCase();
    if (!folded || folded.length > 120) deny();
    if (mode === undefined || mode === "phrase") return (text) => text.indexOf(folded);
    if (mode !== "all-terms" || /[\u0080-\u009f\u2028\u2029]/u.test(folded)) deny();
    const terms = folded.split(/\s+/u);
    if (terms.length < 2 || terms.length > 4 || terms.some((word) => !word || word.length > 40)
      || new Set(terms).size !== terms.length) deny();
    return (text) => {
      let first = text.length;
      for (const term of terms) {
        const offset = text.indexOf(term);
        if (offset < 0) return -1;
        first = Math.min(first, offset);
      }
      return first;
    };
  }
  function sourceOffsetForFolded(text, offset) {
    let low = 0, high = text.length;
    while (low < high) {
      const mid = low + Math.floor((high - low + 1) / 2);
      if (text.slice(0, mid).toLocaleLowerCase().length <= offset) low = mid;
      else high = mid - 1;
    }
    return low;
  }
  async function search(input) {
    try {
      live(input?.assertLive);
      const match = checkedMatcher(input.query, input.matchMode);
      const pinned = context(input);
      await verifiedHead(input, pinned);
      const record = await store(input.indexedDBImpl).read(cacheKey(pinned.scope));
      live(input.assertLive);
      const secret = await keyFor(input.metadataRaw, pinned.scope);
      live(input.assertLive);
      const rows = await openRows(record, pinned, secret, input.baseline);
      live(input.assertLive);
      await verifiedHead(input, pinned);
      const entries = [];
      let totalMatches = 0;
      for (const row of rows) {
        const normalized = row.text.normalize("NFC");
        const at = match(normalized.toLocaleLowerCase());
        if (at >= 0) {
          if (entries.length < PAGE) {
            const start = Math.max(0, sourceOffsetForFolded(normalized, at) - 44);
            entries.push(Object.freeze({ objectId: row.objectId, revision: row.revision,
              name: row.name, mediaType: row.mediaType,
              excerpt: normalized.slice(start, start + 160) }));
          }
          totalMatches++;
        }
      }
      live(input.assertLive);
      return Object.freeze({ entries: Object.freeze(entries), indexedCount: rows.length,
        totalMatches, pageSize: PAGE, hasMore: totalMatches > entries.length,
        coverage: "owner-selected-revisions-only", plaintextSentToServer: false,
        authorizesMutation: false });
    } catch (_) { deny(); }
  }
  async function clear(input) {
    try {
      live(input?.assertLive);
      await store(input.indexedDBImpl).delete(cacheKey(scopeOf(input.grant)));
      live(input.assertLive);
    } catch (_) { deny(); }
  }
  return Object.freeze({ append, search, clear });
}));
