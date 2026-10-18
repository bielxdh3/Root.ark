(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory(require("./rootark-client-crypto"));
  else root.RootarkProtectedIndex = factory(root.RootarkClientCrypto);
}(typeof globalThis === "object" ? globalThis : this, function (crypto) {
  "use strict";

  const CONTEXT = "Root.ark/protected-index/v2";
  const ARTIFACT_FORMAT = "rootark-protected-index-v2";

  function text(value, name) {
    const result = String(value || "").trim();
    if (!result || result.length > 160 || !/^[A-Za-z0-9._:-]+$/.test(result)) throw new Error(`Indice ${name} invalido`);
    return result;
  }

  function identity(input) {
    return { id: text(input.id || input.fileId, "id"), versionId: text(input.versionId, "versionId"), keyEpoch: text(input.keyEpoch, "keyEpoch"), compartmentId: text(input.compartmentId, "compartmentId"), artifactFormat: text(input.artifactFormat || ARTIFACT_FORMAT, "artifactFormat") };
  }

  async function createEntry(input, key) {
    const item = identity(input);
    const payload = { identity: item, metadata: input.metadata && typeof input.metadata === "object" && !Array.isArray(input.metadata) ? crypto.canonicalize(input.metadata) : {} };
    return { ...item, envelope: await crypto.encryptJson(payload, key, { context: CONTEXT, identity: item }) };
  }

  async function decryptEntry(entry, key) {
    if (!entry || typeof entry !== "object" || !entry.envelope) throw new Error("Entrada de indice invalida");
    const item = identity(entry);
    const payload = await crypto.decryptJson(entry.envelope, key, { context: CONTEXT, identity: item });
    if (crypto.canonicalJson(payload.identity) !== crypto.canonicalJson(item)) throw new Error("Identidade do indice nao confere");
    return { ...item, metadata: payload.metadata };
  }

  function searchableValues(value, output = []) {
    if (Array.isArray(value)) value.forEach((item) => searchableValues(item, output));
    else if (value && typeof value === "object") Object.values(value).forEach((item) => searchableValues(item, output));
    else if (typeof value === "string" || typeof value === "number") output.push(String(value).toLocaleLowerCase());
    return output;
  }

  async function search(entries, term, key) {
    const query = String(term || "").trim().toLocaleLowerCase();
    const results = [];
    for (const entry of Array.isArray(entries) ? entries : []) {
      const decrypted = await decryptEntry(entry, key);
      if (!query || searchableValues(decrypted.metadata).some((value) => value.includes(query))) results.push(decrypted);
    }
    return results;
  }

  function invalidate(entries, change = {}) {
    return (Array.isArray(entries) ? entries : []).filter((entry) => {
      if (change.fileId && entry.id !== change.fileId) return true;
      if (change.tombstone) return false;
      if (change.versionId && entry.versionId !== change.versionId) return false;
      if (change.keyEpoch && entry.keyEpoch !== change.keyEpoch) return false;
      if (change.compartmentId && entry.compartmentId !== change.compartmentId) return false;
      if (change.revoked) return false;
      return true;
    });
  }

  return { ARTIFACT_FORMAT, CONTEXT, createEntry, decryptEntry, invalidate, invalidateForVersion: (entries, fileId, versionId) => invalidate(entries, { fileId, versionId }), invalidateOnEpoch: (entries, fileId, keyEpoch) => invalidate(entries, { fileId, keyEpoch }), invalidateOnRevoke: (entries, fileId) => invalidate(entries, { fileId, revoked: true }), invalidateOnTombstone: (entries, fileId) => invalidate(entries, { fileId, tombstone: true }), search };
}));
