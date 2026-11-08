(function (root, factory) {
  if (typeof module === "object" && module.exports)
    module.exports = factory(require("./rootark-zk1-selected-local-preview"));
  else root.RootarkZk1ProtectedTextBatch =
    factory(root.RootarkZk1SelectedLocalPreview);
}(typeof globalThis === "object" ? globalThis : this, function (preview) {
  "use strict";

  // The authenticated caller MUST provide a signed GET that independently
  // rechecks the current catalog/owner/CAS around each ciphertext retrieval.
  // Neither the search query nor imported CEKs are arguments to that GET.
  // Pins and CEKs MUST have been authenticated separately from Root.ark.
  const MAX_ITEMS = 64;
  const WINDOW = 8;
  const MAX_QUERY = 120;
  const MAX_EXCERPT = 160;
  const MAX_TERMS = 4;
  const MAX_TERM_LENGTH = 40;
  function deny() { throw Error("ZK_BATCH_TEXT_SEARCH_DENIED"); }
  function checkedQuery(raw) {
    if (typeof raw !== "string" || raw.length > MAX_QUERY
      || /[\u0000-\u001f\u007f\u2028\u2029]/.test(raw)) deny();
    const normalized = raw.normalize("NFC").trim();
    if (!normalized || normalized.length > MAX_QUERY) deny();
    return normalized.toLocaleLowerCase();
  }
  function checkedMatcher(input) {
    const term = checkedQuery(input.query);
    if (input.matchMode === undefined || input.matchMode === "phrase")
      return (text) => text.indexOf(term);
    if (input.matchMode !== "all-terms") deny();
    // DEV-OFF opt-in: 2-4 distinct literal tokens of 1-40 UTF-16 units;
    // NFC + locale lowercasing and Unicode whitespace splitting are local only.
    // Reject control/line separators and duplicates; never treat terms as regex.
    if (/[\u0080-\u009f\u2028\u2029]/u.test(term)) deny();
    const terms = term.split(/\s+/u);
    if (terms.length < 2 || terms.length > MAX_TERMS
      || terms.some((word) => !word || word.length > MAX_TERM_LENGTH)
      || new Set(terms).size !== terms.length) deny();
    return (text) => {
      let first = text.length;
      for (const word of terms) {
        const at = text.indexOf(word);
        if (at < 0) return -1;
        if (at < first) first = at;
      }
      return first;
    };
  }
  function sourceOffsetForFolded(normalized, foldedOffset) {
    // Lowercasing may expand Unicode (e.g. İ -> i + combining dot).
    // Binary-search source prefixes rather than slicing NFC with a folded offset.
    // The signed opener already limits plaintext to 64 KiB.
    let low = 0;
    let high = normalized.length;
    while (low < high) {
      const mid = low + Math.floor((high - low + 1) / 2);
      if (normalized.slice(0, mid).toLocaleLowerCase().length <= foldedOffset)
        low = mid;
      else high = mid - 1;
    }
    return low;
  }
  function checkedItems(input) {
    if (!Array.isArray(input.items) || input.items.length < 1
      || input.items.length > MAX_ITEMS
      || (input.items.length > WINDOW && typeof input.readCek !== "function")) deny();
    const seen = new Set();
    for (const item of input.items) {
      if (!item || typeof item !== "object"
        || !item.selected || typeof item.selected !== "object"
        || typeof item.selected.objectId !== "string"
        || !/^[A-Za-z0-9_-]{22}$/.test(item.selected.objectId)
        || !Number.isSafeInteger(item.selected.revision)
        || item.selected.revision < 1
        || !Number.isSafeInteger(item.selected.epoch)
        || item.selected.epoch < 1
        || (typeof input.readCek === "function"
          ? typeof item.cekFile !== "string" || !item.cekFile
            || item.cekFile.length > 120
          : !(item.rawCek instanceof Uint8Array) || item.rawCek.length !== 32)
        || typeof item.cekSha256Pin !== "string"
        || !/^[A-Za-z0-9_-]{43}$/.test(item.cekSha256Pin)
        || !item.metadata || typeof item.metadata !== "object") deny();
      const key = item.selected.objectId + ":" + item.selected.revision;
      if (seen.has(key)) deny();
      seen.add(key);
    }
    return input.items;
  }
  async function search(input) {
    try {
      if (!input || typeof input !== "object"
        || typeof input.assertLive !== "function"
        || typeof input.getChecked !== "function"
        || (input.readCek !== undefined && typeof input.readCek !== "function")
        || (input.onVerifiedBatch !== undefined
          && (typeof input.onVerifiedBatch !== "function"
            || typeof input.readCek !== "function"))
        || (input.onProgress !== undefined && typeof input.onProgress !== "function")
        || (input.isCancelled !== undefined && typeof input.isCancelled !== "function")
        || typeof preview?.open !== "function"
        || !input.grant || !input.ownerHead || !input.baseline) deny();
      const match = checkedMatcher(input);
      const items = checkedItems(input);
      const matches = [];
      // The optional encrypted revision index only receives a complete batch.
      // Never commit an earlier window if a later signed GET/CEK fails.
      const indexRows = input.onVerifiedBatch ? [] : null;
      const live = () => {
        const current = input.assertLive();
        const cancelled = input.isCancelled?.();
        if (current === false || current && typeof current.then === "function"
          || cancelled !== undefined && cancelled !== false) deny();
      };
      live();
      for (let offset = 0; offset < items.length; offset += WINDOW) {
        // Process no more than eight at a time, one signed GET + CEK in RAM
        // per revision. Keep only bounded excerpts until ALL checks succeed.
        for (const item of items.slice(offset, offset + WINDOW)) {
          live();
          // This callback performs fresh signed LIST/HEAD/GET. Never pass query/CEK.
          const checked = await input.getChecked(
            item.selected.objectId, item.selected.revision);
          live();
          let rawCek = null;
          try {
            rawCek = input.readCek ? await input.readCek(item.cekFile) : item.rawCek;
            live();
            if (!(rawCek instanceof Uint8Array) || rawCek.length !== 32) deny();
            const opened = await preview.open({
              checked, selected: item.selected, metadata: item.metadata,
              rawCek, cekSha256Pin: item.cekSha256Pin,
              baseline: input.baseline, grant: input.grant,
              ownerHead: input.ownerHead, assertLive: live,
            });
            live();
            if (!opened || opened.plaintextSentToServer !== false
              || opened.objectId !== item.selected.objectId
              || opened.revision !== item.selected.revision
              || opened.epoch !== item.selected.epoch
              || typeof opened.name !== "string"
              || typeof opened.text !== "string") deny();
            const normalized = opened.text.normalize("NFC");
            if (indexRows) indexRows.push(Object.freeze({
              objectId: opened.objectId, revision: opened.revision,
              epoch: opened.epoch,
              ciphertextDigestBase64: item.selected.ciphertextDigestBase64,
              name: opened.name, mediaType: opened.mediaType, text: opened.text,
            }));
            const hit = match(normalized.toLocaleLowerCase());
            if (hit >= 0) {
              const begin = Math.max(0, sourceOffsetForFolded(normalized, hit) - 44);
              matches.push(Object.freeze({
                objectId: opened.objectId, revision: opened.revision,
                name: opened.name, mediaType: opened.mediaType,
                excerpt: normalized.slice(begin, begin + MAX_EXCERPT),
              }));
            }
          } finally { if (input.readCek) rawCek?.fill(0); }
        }
        live();
        if (input.onProgress) {
          const reported = input.onProgress(Object.freeze({
            completed: Math.min(offset + WINDOW, items.length), total: items.length,
          }));
          if (reported && typeof reported.then === "function") deny();
        }
      }
      live();
      // All disposable CEKs have already been wiped by the per-revision finally.
      // No partial plaintext is persisted if any verification or cancellation fails.
      let indexChange = null;
      if (indexRows) {
        const indexed = await input.onVerifiedBatch(Object.freeze(indexRows));
        live();
        if (indexed?.persistedIndex !== true
          || indexed.indexedCount < indexRows.length
          || !Number.isSafeInteger(indexed.discardedCount)
          || indexed.discardedCount < 0
          || typeof indexed.replacedIncompatibleIndex !== "boolean"
          || indexed.plaintextSentToServer !== false
          || indexed.authorizesMutation !== false) deny();
        indexChange = { indexedDiscardedCount: indexed.discardedCount,
          indexedReplacedIncompatible: indexed.replacedIncompatibleIndex };
      }
      return Object.freeze({ totalSearched: items.length,
        totalMatches: matches.length, matches: Object.freeze(matches),
        ...(indexChange || {}),
        plaintextSentToServer: false, authorizesMutation: false });
    } catch (_) { deny(); }
  }
  return Object.freeze({ search });
}));
