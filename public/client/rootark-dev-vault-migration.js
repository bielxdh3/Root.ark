(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.RootarkDevVaultMigration = factory();
}(typeof globalThis === "object" ? globalThis : this, function () {
  "use strict";

  // Non-destructive, explicitly user-selected legacy plaintext COPY only.
  // Never accepts password-encrypted legacy blobs or mutates legacy storage.
  const MAX_BYTES = 4 * 1024 * 1024;
  function fail() { throw new Error("Legacy file is unavailable or cannot be copied safely"); }
  function validName(value) {
    return typeof value === "string" && value.length > 0 && value.length <= 255
      && value !== "." && value !== ".."
      && !/[\\/\u0000-\u001f\u007f]/.test(value);
  }
  async function readLegacyPlaintext({
    name, folderId = "", maxBytes = MAX_BYTES,
    fetchImpl = typeof fetch === "function" ? fetch : null,
  }) {
    if (!validName(name) || typeof folderId !== "string"
      || (folderId && (!/^[A-Za-z0-9._-]{1,128}$/.test(folderId)
        || folderId === "." || folderId === ".."))
      || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_BYTES
      || typeof fetchImpl !== "function") fail();
    const route = "/files/" + encodeURIComponent(name)
      + (folderId ? "?folderId=" + encodeURIComponent(folderId) : "");
    let response;
    try {
      response = await fetchImpl(route, {
        method: "GET",
        credentials: "same-origin",
        redirect: "error",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        headers: { Accept: "application/octet-stream" },
      });
    } catch (_) { fail(); }
    // The legacy route returns 403 for encrypted modes. Do not automatically
    // invoke server-side decrypt, because a migration must never introduce
    // implicit legacy password or key handling.
    if (!response || response.status !== 200 || !response.body?.getReader) fail();
    const disposition = response.headers?.get?.("content-disposition");
    const advertisedLength = response.headers?.get?.("content-length");
    if (typeof disposition !== "string"
      || !/^attachment(?:\s*;|\s*$)/i.test(disposition)
      || typeof advertisedLength !== "string"
      || !/^\d+$/.test(advertisedLength)
      || !Number.isSafeInteger(Number(advertisedLength))
      || Number(advertisedLength) > maxBytes) {
      try { await response.body.cancel(); } catch (_) { /* refusal wins */ }
      fail();
    }
    const type = String(response.headers?.get?.("content-type") || "application/octet-stream")
      .split(";")[0].trim().toLowerCase();
    if (type.length > 128) fail();
    const mediaType = type || "application/octet-stream";
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!(value instanceof Uint8Array)
          || size + value.byteLength > maxBytes) fail();
        chunks.push(value);
        size += value.byteLength;
      }
      if (size !== Number(advertisedLength)) fail();
      const data = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        data.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return { name, mediaType, data };
    } catch (_) {
      try { await reader.cancel(); } catch (_) { /* best-effort stream cancellation */ }
      fail();
    } finally {
      // Best-effort cleanup of intermediate decoded network chunks. The
      // independent bounded result is separately scrubbed by the UI after
      // encryption/read-back, including on a failed copy.
      for (const chunk of chunks) chunk.fill(0);
      reader.releaseLock();
    }
  }
  return Object.freeze({ readLegacyPlaintext, MAX_BYTES });
}));
