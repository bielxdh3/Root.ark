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
  const CLEARED = "rootark-zk1-protected-revision-index-clear/v1";
  const MAX_ROWS = 128;
  const MAX_BYTES = 4 * 1024 * 1024;
  const PAGE = 50;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  // Synchronous same-realm fence: invocation of clear invalidates ALL older
  // local async operations, including those waiting before the first IDB read.
  const clearGenerations = new Map();
  function generation(key) { return clearGenerations.get(key) || 0; }
  function browserRealm() {
    return typeof document === "object" || typeof WorkerGlobalScope !== "undefined";
  }
  function sharedGeneration(key) {
    if (!browserRealm()) return null; // Node's disposable fake IndexedDB.
    // Synchronous, same-origin, cross-tab invocation fence. Only an opaque
    // CSPRNG nonce is stored; no text, CEK, query or grant content is saved.
    // Workers or insecure contexts without synchronous origin storage DENY.
    if (typeof localStorage === "undefined"
      || typeof localStorage.getItem !== "function") deny();
    const value = localStorage.getItem(DB + "/clear/" + key);
    if (value !== null && !opaque.test(value)) deny();
    return value;
  }
  function captureGeneration(key) {
    return { local: generation(key), shared: sharedGeneration(key) };
  }
  function checkGeneration(key, expected) {
    if (generation(key) !== expected.local
      || sharedGeneration(key) !== expected.shared) deny();
  }
  function checkRecordGeneration(record, expected) {
    if (!browserRealm()) return;
    // A failed clear can update localStorage before the durable IDB commit.
    // Do not reauthorize that older encrypted row or tombstone until a new
    // successful clear reconciles both stores.
    if (record.format === CLEARED && record.nonce !== expected.shared
      || record.format === FORMAT
        && (record.clearNonce ?? null) !== expected.shared) deny();
  }
  function scopeGate(key, work) {
    // The initial append read and each scoped clear must be ordered across
    // tabs before any asynchronous crypto/network work can move the read past
    // the clear. A secure-context browser without Web Locks fails closed.
    // Browsers can run this script in a Window or a Worker. Never silently
    // downgrade either browser realm to single-realm locking when unsupported.
    if (!browserRealm())
      return work(); // Node's deterministic disposable IndexedDB test runtime.
    if (typeof navigator?.locks?.request !== "function") deny();
    return navigator.locks.request(DB + "/" + key, { mode: "exclusive" }, work);
  }
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
  async function context(input) {
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
    // A device can receive a newly signed grant at the same owner head.
    // Bind cached text to the exact grant, including its permissions, rather
    // than merely to device_id/manifest_revision/epoch.
    const grantDigest = to64(new Uint8Array(await webCrypto.subtle.digest(
      "SHA-256", encoder.encode(JSON.stringify(grant)))));
    return { format: FORMAT, scope, deviceId: grant.device_id, grantDigest,
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
    for (const entry of baseline?.entries || []) {
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
      if (seen.has(key) || baseline && (!original || original.epoch !== row.epoch
        || original.ciphertextDigestBase64 !== row.ciphertextDigestBase64)) deny();
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
            const request = operation === "clear" ? objectStore.put(value, key)
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
                // The asynchronous put can be queued while the device logs
                // out. Check AGAIN when IndexedDB acknowledges the write,
                // while the readwrite transaction can still be aborted.
                write.onsuccess = () => {
                  try { live(assertLive); }
                  catch (_) { tx.abort(); }
                };
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
      // Keep the CAS slot occupied even when no encrypted record existed.
      // IndexedDB serializes this replacement against conditional save writes.
      clear: (key, value) => transaction("readwrite", "clear", key, value),
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
  async function verifiedOwnerGrant(input, pinned) {
    // The caller independently re-imports and validates the current signed
    // owner/grant evidence against its monotonic trust floor. Catalog CAS alone
    // cannot detect a revoked device if its snapshot head has not changed.
    live(input.assertLive);
    if (typeof input.verifyOwnerGrant !== "function") deny();
    const current = await input.verifyOwnerGrant();
    live(input.assertLive);
    if (current?.verifiedCurrent !== true
      || !current.grant || current.grant.revoked_at_epoch !== null
      || JSON.stringify(current.grant) !== JSON.stringify(input.grant)
      || current.ownerHead?.revision !== pinned.ownerHead.revision
      || current.ownerHead?.epoch !== pinned.ownerHead.epoch
      || current.ownerHead?.digest !== pinned.ownerHead.digest) deny();
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
  function recordContext(record) {
    if (typeof record?.context !== "string" || record.context.length > 2048) deny();
    let stored;
    try { stored = JSON.parse(record.context); } catch (_) { deny(); }
    if (!stored || JSON.stringify(stored) !== record.context
      || stored.format !== FORMAT || !stored.scope
      || !Number.isSafeInteger(stored.catalogHead?.sequence)
      || !digest.test(stored.catalogHead?.digest)) deny();
    return stored;
  }
  function sameAuthority(previous, pinned) {
    return previous.grantDigest === pinned.grantDigest
      && previous.deviceId === pinned.deviceId
      && JSON.stringify(previous.scope) === JSON.stringify(pinned.scope)
      && JSON.stringify(previous.ownerHead) === JSON.stringify(pinned.ownerHead);
  }
  function signedRowSet(baseline) {
    const signed = new Map();
    for (const entry of baseline.entries) {
      const key = entry.objectId + ":" + entry.revision;
      if (signed.has(key)) deny();
      signed.set(key, entry);
    }
    return signed;
  }
  async function append(input) {
    try {
      live(input?.assertLive);
      const key = cacheKey(scopeOf(input.grant));
      const initialGeneration = captureGeneration(key);
      const assertCurrent = () => {
        live(input.assertLive);
        checkGeneration(key, initialGeneration);
      };
      const db = store(input.indexedDBImpl);
      // This first read must be requested at append INVOCATION, rather than
      // after context()'s asynchronous SHA-256, so a clear cannot complete
      // first and then be mistaken for an existing fresh baseline tombstone.
      const record = await scopeGate(key, () => db.read(key));
      assertCurrent();
      const pinned = await context(input);
      assertCurrent();
      if (cacheKey(pinned.scope) !== key) deny();
      const incoming = checkRows(input.entries, input.baseline);
      if (incoming.length > 64) deny(); // One complete verified batch only.
      const tombstone = record?.format === CLEARED;
      if (record && (!opaque.test(record.nonce)
        || (tombstone && Object.keys(record).sort().join(",") !== "format,nonce")
        || (!tombstone && record.format !== FORMAT))) deny();
      if (record) checkRecordGeneration(record, initialGeneration);
      await verifiedOwnerGrant(input, pinned);
      await verifiedHead(input, pinned);
      assertCurrent();
      const secret = await keyFor(input.metadataRaw, pinned.scope);
      assertCurrent();
      let current = [], discardedCount = 0, replacedIncompatibleIndex = false;
      if (record && !tombstone) {
        const previous = recordContext(record);
        // A newly supplied signed-but-historical catalog or owner epoch must
        // not roll back the scope's existing encrypted index version.
        if (previous.catalogHead.sequence > pinned.catalogHead.sequence
          || previous.catalogHead.sequence === pinned.catalogHead.sequence
            && previous.catalogHead.digest !== pinned.catalogHead.digest
          || previous.ownerHead?.epoch > pinned.ownerHead.epoch
          || previous.ownerHead?.revision > pinned.ownerHead.revision) deny();
        if (sameAuthority(previous, pinned)) {
          // The old ciphertext is AEAD-authenticated to its original signed
          // CAS head. On a new signed CAS, retain only exact surviving digests.
          const original = await openRows(record, previous, secret, null);
          const signed = signedRowSet(input.baseline);
          current = original.filter((row) => {
            const entry = signed.get(row.objectId + ":" + row.revision);
            const retain = entry?.epoch === row.epoch
              && entry.ciphertextDigestBase64 === row.ciphertextDigestBase64;
            if (!retain) discardedCount++;
            return retain;
          });
        } else {
          // Old-format indexes cannot prove identical complete grant. Owner
          // rotation and grant replacement must never import old plaintext.
          replacedIncompatibleIndex = true;
        }
      }
      assertCurrent();
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
      assertCurrent();
      await verifiedOwnerGrant(input, pinned);
      await verifiedHead(input, pinned);
      assertCurrent();
      await db.save(key, { format: FORMAT, context: JSON.stringify(pinned),
        nonce: to64(webCrypto.getRandomValues(new Uint8Array(16))),
        clearNonce: initialGeneration.shared,
        iv: to64(iv), ciphertext: to64(new Uint8Array(sealed)) },
      record?.nonce ?? null, assertCurrent);
      assertCurrent();
      return Object.freeze({ indexedCount: rows.length, persistedIndex: true,
        discardedCount, replacedIncompatibleIndex,
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
      const key = cacheKey(scopeOf(input.grant));
      const initialGeneration = captureGeneration(key);
      const assertCurrent = () => {
        live(input.assertLive);
        checkGeneration(key, initialGeneration);
      };
      const match = checkedMatcher(input.query, input.matchMode);
      const pinned = await context(input);
      assertCurrent();
      if (cacheKey(pinned.scope) !== key) deny();
      await verifiedOwnerGrant(input, pinned);
      await verifiedHead(input, pinned);
      const db = store(input.indexedDBImpl);
      const record = await db.read(key);
      assertCurrent();
      if (record && (record.format === FORMAT || record.format === CLEARED))
        checkRecordGeneration(record, initialGeneration);
      const secret = await keyFor(input.metadataRaw, pinned.scope);
      assertCurrent();
      let rows = await openRows(record, pinned, secret, input.baseline);
      assertCurrent();
      await verifiedOwnerGrant(input, pinned);
      await verifiedHead(input, pinned);
      const matches = [];
      for (const row of rows) {
        const normalized = row.text.normalize("NFC");
        const at = match(normalized.toLocaleLowerCase());
        if (at >= 0) {
          const start = Math.max(0, sourceOffsetForFolded(normalized, at) - 44);
          matches.push(Object.freeze({ objectId: row.objectId, revision: row.revision,
            name: row.name, mediaType: row.mediaType,
            excerpt: normalized.slice(start, start + 160) }));
        }
      }
      assertCurrent();
      const indexedCount = rows.length;
      // Only bounded excerpts remain in the asynchronous page navigation
      // closure; never retain all decrypted historical source text there.
      rows = null;
      const totalMatches = matches.length;
      const paged = (offset) => {
        if (!Number.isSafeInteger(offset) || offset < 0 || offset % PAGE !== 0
          || offset > 100 || (offset !== 0 && offset >= totalMatches)) deny();
        const entries = Object.freeze(matches.slice(offset, offset + PAGE));
        return Object.freeze({ entries, indexedCount, totalMatches,
          offset, pageSize: PAGE, hasMore: offset + entries.length < totalMatches,
          hasNext: offset + entries.length < totalMatches,
          hasPrevious: offset > 0,
          coverage: "owner-selected-revisions-only", plaintextSentToServer: false,
          authorizesMutation: false, readPage });
      };
      const readPage = async (offset) => {
        try {
          assertCurrent();
          await verifiedOwnerGrant(input, pinned);
          await verifiedHead(input, pinned);
          // A previously loaded result may outlive a scoped clear or a new
          // encrypted snapshot with the same signed catalog head. Never emit
          // another page from an index that was deleted/replaced meanwhile.
          const page = await scopeGate(key, async () => {
            const currentRecord = await db.read(key);
            assertCurrent();
            if (!currentRecord || currentRecord.format !== FORMAT
              || currentRecord.context !== record.context
              || currentRecord.nonce !== record.nonce) deny();
            checkRecordGeneration(currentRecord, initialGeneration);
            return paged(offset);
          });
          assertCurrent();
          return page;
        } catch (_) { deny(); }
      };
      // The FIRST page needs the same scoped current-record check as later
      // navigation, after the last asynchronous signed owner/catalog check.
      // Keep final check + page construction ordered against cross-tab clear.
      const firstPage = await scopeGate(key, async () => {
        const currentRecord = await db.read(key);
        assertCurrent();
        if (!currentRecord || currentRecord.format !== FORMAT
          || currentRecord.context !== record.context
          || currentRecord.nonce !== record.nonce) deny();
        checkRecordGeneration(currentRecord, initialGeneration);
        return paged(input.offset === undefined ? 0 : input.offset);
      });
      assertCurrent();
      return firstPage;
    } catch (_) { deny(); }
  }
  async function clear(input) {
    try {
      live(input?.assertLive);
      const key = cacheKey(scopeOf(input.grant));
      // Increment synchronously at invocation, even while IndexedDB is still
      // opening. The durable tombstone handles other tabs and restarts.
      clearGenerations.set(key, generation(key) + 1);
      const markerNonce = to64(webCrypto.getRandomValues(new Uint8Array(16)));
      if (browserRealm()) {
        if (typeof localStorage === "undefined"
          || typeof localStorage.setItem !== "function") deny();
        localStorage.setItem(DB + "/clear/" + key, markerNonce);
      }
      // Never delete the compare-and-swap slot: an already-running append may
      // have observed it empty, or may have pinned its old encrypted nonce.
      // A durable random tombstone defeats both cases across tabs/processes.
      await scopeGate(key, () => {
        // Other tabs can invoke a newer clear while this call waits on the
        // lock. Persist the latest shared generation, never resurrect an
        // older marker (ABA) or strand concurrent clears with a stale nonce.
        const newest = browserRealm() ? sharedGeneration(key) : markerNonce;
        if (newest === null) deny();
        return store(input.indexedDBImpl).clear(key, {
          format: CLEARED, nonce: newest,
        });
      });
      live(input.assertLive);
    } catch (_) { deny(); }
  }
  return Object.freeze({ append, search, clear });
}));
