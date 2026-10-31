(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./rootark-zk1-keyring-portable-archive"));
  } else {
    root.RootarkZk1BrowserVersionedArchive = factory(root.RootarkZk1KeyringPortableArchive);
  }
}(typeof globalThis === "object" ? globalThis : this, function (archive) {
  "use strict";
  const VERSION_PACKET = "rootark-zk1-versioned-ciphertext-cek/v1";
  const te = new TextEncoder(), td = new TextDecoder("utf-8", { fatal: true });
  function deny() { throw new Error("ZK_BROWSER_VERSIONED_ARCHIVE_DENIED"); }
  function exact(v, keys) {
    if (!v || typeof v !== "object" || Array.isArray(v)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(v))
      || Reflect.ownKeys(v).length !== keys.length
      || keys.some((k) => !Object.hasOwn(v, k))) deny();
  }
  function b64(bytes) {
    let value = "";
    for (const item of bytes) value += String.fromCharCode(item);
    return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(v, n, max = n) {
    if (typeof v !== "string" || !/^[A-Za-z0-9_-]+$/.test(v)
      || v.length > Math.ceil(max * 4 / 3) + 4) deny();
    let raw;
    try { raw = atob(v.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(v.length / 4) * 4, "=")); } catch (_) { deny(); }
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    if (bytes.length < n || bytes.length > max || b64(bytes) !== v) deny();
    return bytes;
  }
  async function createArchive(input) {
    let selected = [];
    try {
      exact(input, ["archiveInput", "versions", "verifiedAuthority", "assertLive"]);
      if (!Array.isArray(input.versions) || input.versions.length < 1
        || input.versions.length > 12) deny();
      let total = 0;
      for (const entry of input.versions) {
        exact(entry, ["metadata", "objectRevision", "ciphertextBase64", "cekBase64"]);
        const ciphertext = from64(entry.ciphertextBase64, 16, 1536 * 1024);
        const cek = from64(entry.cekBase64, 32);
        try {
          const packet = te.encode(JSON.stringify({ format: VERSION_PACKET,
            ciphertextBase64: b64(ciphertext), cekBase64: b64(cek) }));
          total += packet.length;
          if (packet.length > 2 * 1024 * 1024 || total > 8 * 1024 * 1024) deny();
          selected.push({ metadata: entry.metadata, objectRevision: entry.objectRevision,
            name: "opaque-ciphertext-version", mediaType: "application/octet-stream",
            data: packet });
        } finally { ciphertext.fill(0); cek.fill(0); }
      }
      input.assertLive();
      const sealed = await archive.createArchive({ ...input.archiveInput,
        versionedAuthority: input.verifiedAuthority, files: selected });
      input.assertLive();
      return sealed;
    } catch (_) { deny(); }
    finally { for (const file of selected) file.data.fill(0); }
  }
  async function recoverArchive(input) {
    let opened;
    try {
      exact(input, ["recoveryInput", "verifiedAuthority", "assertLive"]);
      input.assertLive();
      opened = await archive.recoverArchive({
        ...input.recoveryInput, versionedAuthority: input.verifiedAuthority });
      input.assertLive();
      if (opened.completeRelativeToPinnedInventory !== true
        || opened.ownerSignedAccountRosterVerified !== true
        || opened.revisionAncestryVerified !== true
        || !Array.isArray(opened.files) || opened.files.length < 1
        || opened.files.length > 12) deny();
      return opened;
    } catch (_) {
      for (const item of opened?.files || []) {
        item.ciphertext?.fill(0); item.cek?.fill(0);
      }
      deny();
    }
  }
  return Object.freeze({ createArchive, recoverArchive });
}));
