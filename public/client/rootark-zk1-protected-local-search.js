(function (root, factory) {
  if (typeof module === "object" && module.exports)
    module.exports = factory(require("node:crypto").webcrypto);
  else root.RootarkZk1ProtectedLocalSearch = factory(root.crypto);
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto) {
  "use strict";

  // Browser-only materialized view of an independently verified signed catalog.
  // No query, filename, metadata key or index ever crosses the HTTP boundary.
  const DB = "rootark-zk1-protected-local-search-v1";
  const STORE = "catalogs";
  const FORMAT = "rootark-zk1-protected-local-search/v1";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const id = /^[A-Za-z0-9_-]{22}$/;
  const digest = /^[A-Za-z0-9_-]{43}$/;
  function deny() { throw new Error("ZK_LOCAL_SEARCH_DENIED"); }
  function live(check) {
    const value = check();
    if (value === false || value && typeof value.then === "function") deny();
  }
  function sameScope(a, b) {
    return ["account_id", "compartment_id", "keyring_id"]
      .every((name) => {
        if (a?.[name] !== b?.[name]) return false;
        try {
          decode64(a[name], name === "compartment_id" ? 1 : 16,
            name === "compartment_id" ? 128 : 16);
          return true;
        } catch (_) { return false; }
      });
  }
  function scopeOf(grant) {
    return { account_id: grant.account_id, compartment_id: grant.compartment_id,
      keyring_id: grant.keyring_id };
  }
  function headOf(value) {
    if (!Number.isSafeInteger(value?.sequence) || value.sequence < 1
      || !digest.test(value?.digest)) deny();
    return { sequence: value.sequence, digest: value.digest };
  }
  function context(input) {
    const { grant, baseline, ownerRevision, ownerEpoch, ownerDigest } = input;
    if (!grant || grant.revoked_at_epoch !== null
      || typeof grant.device_id !== "string" || grant.device_id.length < 1
      || grant.device_id.length > 128
      || !Number.isSafeInteger(ownerRevision) || ownerRevision < 1
      || !Number.isSafeInteger(ownerEpoch) || ownerEpoch < 1
      || !digest.test(ownerDigest)
      || grant.manifest_revision !== ownerRevision
      || grant.manifest_digest !== ownerDigest
      || grant.current_epoch !== ownerEpoch
      || !Array.isArray(baseline?.entries) || baseline.entries.length > 4096) deny();
    const head = headOf(baseline.head);
    return { format: FORMAT, scope: scopeOf(grant),
      ownerRevision, ownerEpoch, ownerDigest, head,
      count: baseline.entries.length };
  }
  function encode64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function decode64(value, minimum, maximum = minimum) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
      || value.length > Math.ceil(maximum * 4 / 3) + 4) deny();
    let output;
    try { output = Uint8Array.from(atob(value.replace(/-/g, "+")
      .replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=")),
    (char) => char.charCodeAt(0)); } catch (_) { deny(); }
    if (output.length < minimum || output.length > maximum
      || encode64(output) !== value) deny();
    return output;
  }
  async function sealingKey(raw, scope) {
    if (!(raw instanceof Uint8Array) || raw.length !== 32
      || !webCrypto?.subtle) deny();
    const base = await webCrypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
    const salt = await webCrypto.subtle.digest("SHA-256",
      encoder.encode(JSON.stringify([FORMAT, scope.account_id,
        scope.compartment_id, scope.keyring_id])));
    return webCrypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt,
      info: encoder.encode("Root.ark/zk-1/protected-local-search/aes-gcm/v1") },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  function store(indexedDBImpl) {
    if (typeof indexedDBImpl?.open !== "function") throw Error("INDEXEDDB_UNAVAILABLE");
    async function transaction(mode, operation, key, value) {
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
            const request = operation === "read" ? objectStore.get(key)
              : operation === "write" ? objectStore.put(value, key)
                : objectStore.delete(key);
            request.onsuccess = () => { result = request.result; };
            request.onerror = () => reject(Error("INDEXEDDB_UNAVAILABLE"));
            tx.oncomplete = () => resolve(result);
            tx.onerror = tx.onabort = () => reject(Error("INDEXEDDB_UNAVAILABLE"));
          } catch (error) { reject(error); }
        });
      } finally { database.close(); }
    }
    return {
      read: (key) => transaction("readonly", "read", key),
      write: (key, value) => transaction("readwrite", "write", key, value),
      delete: (key) => transaction("readwrite", "delete", key),
    };
  }
  function cacheKey(scope) {
    return JSON.stringify([scope.account_id, scope.compartment_id, scope.keyring_id]);
  }
  function latestEntries(baseline) {
    const latest = new Map();
    const seen = new Set();
    for (const entry of baseline.entries) {
      if (!entry || !id.test(entry.objectId)
        || !Number.isSafeInteger(entry.revision) || entry.revision < 1
        || !Number.isSafeInteger(entry.epoch) || entry.epoch < 1) deny();
      const key = entry.objectId + ":" + entry.revision;
      if (seen.has(key)) deny();
      seen.add(key);
      const prev = latest.get(entry.objectId);
      if (!prev || entry.revision > prev.revision) {
        latest.delete(entry.objectId);
        latest.set(entry.objectId, entry);
      }
    }
    return [...latest.values()];
  }
  function validRows(rows, expected) {
    if (!Array.isArray(rows) || rows.length !== expected.length
      || rows.length > 4096) deny();
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const signed = expected[i];
      if (!row || !signed || !id.test(row.objectId)
        || row.objectId !== signed.objectId || row.revision !== signed.revision
        || row.epoch !== signed.epoch || !Number.isSafeInteger(row.revision)
        || row.revision < 1 || !Number.isSafeInteger(row.epoch) || row.epoch < 1
        || typeof row.logicalTrashCandidate !== "boolean"
        || (row.logicalTrashCandidate ? row.name !== null
          : typeof row.name !== "string" || row.name.length < 1
            || row.name.length > 220)) deny();
    }
    return rows;
  }
  function verifyOpening(opened, contextValue, baseline) {
    const expected = latestEntries(baseline);
    if (opened?.independentlySignedCatalog !== true
      || opened.plaintextSentToServer !== false
      || opened.authorizesMutation !== false
      || !sameScope(opened.scope, contextValue.scope)
      || opened.head?.sequence !== contextValue.head.sequence
      || opened.head.digest !== contextValue.head.digest
      || opened.totalMatches !== expected.length) deny();
    return validRows(opened.entries, expected);
  }
  function filtered(rows, term, head, persisted) {
    const query = term.trim().normalize("NFC").toLowerCase();
    let totalMatches = 0;
    const entries = [];
    for (const row of rows) {
      if (!query || row.logicalTrashCandidate !== true
        && row.name.normalize("NFC").toLowerCase().includes(query)) {
        totalMatches++;
        if (!query || entries.length < 100) entries.push(row);
      }
    }
    return Object.freeze({ head, entries, totalMatches,
      persistedIndex: persisted, plaintextSentToServer: false,
      independentlySignedCatalog: true, authorizesMutation: false });
  }
  function renderVerifiedResults(container, entries, selectedInput, assertLive) {
    if (!container?.ownerDocument || typeof container.replaceChildren !== "function"
      || !selectedInput || typeof assertLive !== "function"
      || !Array.isArray(entries) || entries.length > 4096) deny();
    const fragment = container.ownerDocument.createDocumentFragment();
    for (const entry of entries) {
      if (!entry || !id.test(entry.objectId)
        || !Number.isSafeInteger(entry.revision) || entry.revision < 1
        || typeof entry.logicalTrashCandidate !== "boolean"
        || (entry.logicalTrashCandidate ? entry.name !== null
          : typeof entry.name !== "string" || !entry.name || entry.name.length > 220)) deny();
      const item = container.ownerDocument.createElement("div");
      item.textContent = (entry.logicalTrashCandidate
        ? "Lixeira lógica (verifique o tombstone assinado)" : entry.name)
        + " · revisão " + entry.revision + " ";
      const button = container.ownerDocument.createElement("button");
      button.type = "button";
      button.className = "button button-quiet";
      button.textContent = "Selecionar objeto";
      button.addEventListener("click", () => {
        try {
          if (!container.contains(button) || assertLive() === false) return;
          selectedInput.value = entry.objectId;
          selectedInput.focus();
        } catch (_) { /* Logout/session switch invalidates this local selection. */ }
      });
      item.append(button);
      fragment.append(item);
    }
    container.replaceChildren(fragment);
  }
  async function search(input) {
    try {
      if (typeof input?.assertLive !== "function" || typeof input.term !== "string"
        || input.term.length > 120
        || typeof input.client?.readPrivateListing !== "function"
        || typeof input.client?.verifyPrivateListingHead !== "function") deny();
      live(input.assertLive);
      const pinned = context(input);
      let database = null, record;
      const key = cacheKey(pinned.scope);
      try {
        database = store(input.indexedDBImpl);
        record = await database.read(key);
      } catch (_) { database = null; }
      live(input.assertLive);
      const aad = encoder.encode(JSON.stringify(pinned));
      let rows, usedCache = false;
      const matching = record?.format === FORMAT && record.context === JSON.stringify(pinned);
      if (matching) {
        // Revalidate CAS, witness and device grant before any cached name is released.
        const verified = await input.client.verifyPrivateListingHead(input.baseline);
        live(input.assertLive);
        if (!sameScope(verified?.scope, pinned.scope)
          || verified.head?.sequence !== pinned.head.sequence
          || verified.head.digest !== pinned.head.digest) deny();
        const secret = await sealingKey(input.metadataRaw, pinned.scope);
        live(input.assertLive);
        const opened = await webCrypto.subtle.decrypt({ name: "AES-GCM",
          iv: decode64(record.iv, 12), additionalData: aad, tagLength: 128 },
        secret, decode64(record.ciphertext, 16, 4 * 1024 * 1024 + 16));
        live(input.assertLive);
        if (opened.byteLength > 4 * 1024 * 1024) deny();
        rows = validRows(JSON.parse(decoder.decode(opened)), latestEntries(input.baseline));
        usedCache = true;
      } else {
        const sourceKey = await webCrypto.subtle.importKey("raw", input.metadataRaw,
          { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
        const opened = await input.client.readPrivateListing(input.baseline, sourceKey, "");
        live(input.assertLive);
        rows = verifyOpening(opened, pinned, input.baseline);
        if (database) {
          const secret = await sealingKey(input.metadataRaw, pinned.scope);
          const raw = encoder.encode(JSON.stringify(rows));
          if (raw.byteLength > 4 * 1024 * 1024) deny();
          const iv = webCrypto.getRandomValues(new Uint8Array(12));
          const ciphertext = await webCrypto.subtle.encrypt({ name: "AES-GCM",
            iv, additionalData: aad, tagLength: 128 }, secret, raw);
          raw.fill(0);
          live(input.assertLive);
          try {
            await database.write(key, { format: FORMAT, context: JSON.stringify(pinned),
              iv: encode64(iv), ciphertext: encode64(new Uint8Array(ciphertext)) });
          } catch (_) {
            // Persistence is optional; the full catalog is already authenticated.
            // Continue in-memory, never falling back to unverified cached bytes.
            database = null;
          }
          live(input.assertLive);
        }
      }
      return Object.freeze({ ...filtered(rows, input.term, pinned.head, Boolean(database)),
        reusedIndex: usedCache });
    } catch (_) { deny(); }
  }
  async function clear(input) {
    try {
      if (!input?.grant || typeof input.assertLive !== "function") deny();
      live(input.assertLive);
      await store(input.indexedDBImpl).delete(cacheKey(scopeOf(input.grant)));
      live(input.assertLive);
    } catch (_) { deny(); }
  }
  return Object.freeze({ search, clear, renderVerifiedResults });
}));
