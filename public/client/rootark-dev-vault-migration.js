(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.RootarkDevVaultMigration = factory();
}(typeof globalThis === "object" ? globalThis : this, function () {
  "use strict";

  // Non-destructive, explicitly user-selected legacy plaintext COPY only.
  // Never accepts password-encrypted legacy blobs or mutates legacy storage.
  const MAX_BYTES = 4 * 1024 * 1024;
  const READ_DEADLINE_MS = 15000;
  function fail() { throw new Error("Legacy file is unavailable or cannot be copied safely"); }
  function validName(value) {
    return typeof value === "string" && value.length > 0 && value.length <= 255
      && value !== "." && value !== ".."
      && !/[\\/\u0000-\u001f\u007f]/.test(value);
  }
  async function readLegacyPlaintext({
    name, folderId = "", maxBytes = MAX_BYTES,
    version = null,
    fetchImpl = typeof fetch === "function" ? fetch : null,
  }) {
    if (!validName(name) || typeof folderId !== "string"
      || (folderId && (!/^[A-Za-z0-9._-]{1,128}$/.test(folderId)
        || folderId === "." || folderId === ".."))
      || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_BYTES
      || (version !== null && (!Number.isSafeInteger(version) || version < 1))
      || typeof fetchImpl !== "function") fail();
    const route = (version === null ? "/files/" : "/download/")
      + encodeURIComponent(name)
      + (version === null ? "" : "/v/" + version)
      + (folderId ? "?folderId=" + encodeURIComponent(folderId) : "");
    const controller = new AbortController();
    let deadlineHandle, response, reader;
    const chunks = [];
    const deadline = new Promise((_, reject) => {
      deadlineHandle = setTimeout(() => {
        controller.abort();
        reject(new Error("Legacy download deadline exceeded"));
      }, READ_DEADLINE_MS);
    });
    const bounded = (promise) => Promise.race([promise, deadline]);
    try {
      response = await bounded(Promise.resolve().then(() => fetchImpl(route, {
        method: "GET",
        credentials: "same-origin",
        redirect: "error",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        headers: { Accept: "application/octet-stream" },
        signal: controller.signal,
      })).then((received) => {
        // A fake or noncooperative fetch may resolve after the deadline.
        // Discard and cancel that late response without exposing its bytes.
        if (controller.signal.aborted) {
          try {
            const canceled = received?.body?.cancel?.();
            if (canceled?.catch) canceled.catch(() => {});
          } catch (_) { /* already refused */ }
        }
        return received;
      }));
      // The legacy route returns 403 for encrypted modes. Do not invoke
      // server-side decrypt or accept a login HTML fallback as file contents.
      if (!response || response.status !== 200 || !response.body?.getReader) fail();
      const disposition = response.headers?.get?.("content-disposition");
      const advertisedLength = response.headers?.get?.("content-length");
      if (typeof disposition !== "string"
        || !/^attachment(?:\s*;|\s*$)/i.test(disposition)
        || typeof advertisedLength !== "string"
        || !/^\d+$/.test(advertisedLength)
        || !Number.isSafeInteger(Number(advertisedLength))
        || Number(advertisedLength) > maxBytes) fail();
      const type = String(response.headers?.get?.("content-type") || "application/octet-stream")
        .split(";")[0].trim().toLowerCase();
      if (type.length > 128) fail();
      const mediaType = type || "application/octet-stream";
      reader = response.body.getReader();
      let size = 0;
      while (true) {
        const { done, value } = await bounded(reader.read());
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
      return { name, mediaType, lastModified: response.headers?.get?.("last-modified") || null, data };
    } catch (_) {
      controller.abort();
      // Cancellation is best-effort: do not await a malicious/noncooperative
      // stream's cancel promise after the absolute deadline has expired.
      try {
        const canceled = reader ? reader.cancel() : response?.body?.cancel?.();
        if (canceled?.catch) canceled.catch(() => {});
      } catch (_) { /* refusal wins */ }
      fail();
    } finally {
      clearTimeout(deadlineHandle);
      // Best-effort cleanup of intermediate decoded network chunks. The
      // independent bounded result is separately scrubbed by the UI after
      // encryption/read-back, including on a failed copy.
      for (const chunk of chunks) chunk.fill(0);
      if (reader) { try { reader.releaseLock(); } catch (_) { /* canceled */ } }
    }
  }
  return Object.freeze({ readLegacyPlaintext, MAX_BYTES });
}));
