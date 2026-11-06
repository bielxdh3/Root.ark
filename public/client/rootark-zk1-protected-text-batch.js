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
  const MAX_ITEMS = 8;
  const MAX_QUERY = 120;
  const MAX_EXCERPT = 160;
  function deny() { throw Error("ZK_BATCH_TEXT_SEARCH_DENIED"); }
  function checkedQuery(raw) {
    if (typeof raw !== "string" || raw.length > MAX_QUERY
      || /[\u0000-\u001f\u007f]/.test(raw)) deny();
    const normalized = raw.normalize("NFC").trim();
    if (!normalized || normalized.length > MAX_QUERY) deny();
    return normalized.toLocaleLowerCase();
  }
  function checkedItems(input) {
    if (!Array.isArray(input.items) || input.items.length < 1
      || input.items.length > MAX_ITEMS) deny();
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
        || !(item.rawCek instanceof Uint8Array)
        || item.rawCek.length !== 32
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
        || typeof preview?.open !== "function"
        || !input.grant || !input.ownerHead || !input.baseline) deny();
      const term = checkedQuery(input.query);
      const items = checkedItems(input);
      const matches = [];
      input.assertLive();
      for (const item of items) {
        input.assertLive();
        // This callback performs fresh signed LIST/HEAD/GET, not a cached
        // preview or server-provided plaintext. Never pass the query/CEK.
        const checked = await input.getChecked(
          item.selected.objectId, item.selected.revision);
        input.assertLive();
        const opened = await preview.open({
          checked, selected: item.selected, metadata: item.metadata,
          rawCek: item.rawCek, cekSha256Pin: item.cekSha256Pin,
          baseline: input.baseline, grant: input.grant,
          ownerHead: input.ownerHead, assertLive: input.assertLive,
        });
        input.assertLive();
        if (!opened || opened.plaintextSentToServer !== false
          || opened.objectId !== item.selected.objectId
          || opened.revision !== item.selected.revision
          || opened.epoch !== item.selected.epoch
          || typeof opened.name !== "string"
          || typeof opened.text !== "string") deny();
        const normalized = opened.text.normalize("NFC");
        const offset = normalized.toLocaleLowerCase().indexOf(term);
        if (offset >= 0) {
          const begin = Math.max(0, offset - 44);
          matches.push(Object.freeze({
            objectId: opened.objectId, revision: opened.revision,
            name: opened.name, mediaType: opened.mediaType,
            excerpt: normalized.slice(begin, begin + MAX_EXCERPT),
          }));
        }
      }
      input.assertLive();
      return Object.freeze({ totalSearched: items.length,
        totalMatches: matches.length, matches: Object.freeze(matches),
        plaintextSentToServer: false, authorizesMutation: false });
    } catch (_) { deny(); }
  }
  return Object.freeze({ search });
}));
