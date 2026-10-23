(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-legacy-migration-workflow"));
  } else {
    root.RootarkZk1LegacyBatchMigration = factory(root.crypto,
      root.RootarkZk1LegacyMigrationWorkflow);
  }
}(typeof globalThis === "object" ? globalThis : this, function (crypto, migration) {
  "use strict";
  // DEV, opt-in and non-destructive. All historical revisions become distinct
  // immutable ZK objects (revision 1); no legacy restore/delete or ZK cutover.
  // Keep migrationSecret (32 random bytes), CEKs and owner trust OFF the server.
  // A lost PUT ACK is resolved through the existing journal's signed GET only.
  const SCOPE = ["account_id", "compartment_id", "keyring_id"];
  const PIN = ["version", "storedAs", "uploadedAt", "size", "lastModified",
    "sha256", "mediaType"];
  const LIMIT = 12;
  const READ_DEADLINE_MS = 15000;
  function refuse() { throw new Error("ZK_LEGACY_BATCH_UNVERIFIED"); }
  function exact(obj, fields) {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(obj))
      || Reflect.ownKeys(obj).length !== fields.length
      || fields.some((key) => !Object.hasOwn(obj, key))) refuse();
  }
  function b64(bytes) {
    let text = "";
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function safeName(name) {
    return typeof name === "string" && name.length > 0 && name.length <= 255
      && name !== "." && name !== ".." && !/[\\/\u0000-\u001f\u007f]/.test(name);
  }
  function safeFolder(folderId) {
    return folderId === "" || (typeof folderId === "string"
      && /^[A-Za-z0-9._-]{1,128}$/.test(folderId)
      && folderId !== "." && folderId !== "..");
  }
  function validateEntry(entry) {
    exact(entry, ["legacy", "sourcePin", "cek"]);
    exact(entry.legacy, ["name", "folderId"]);
    exact(entry.sourcePin, PIN);
    if (!safeName(entry.legacy.name) || !safeFolder(entry.legacy.folderId)
      || !safeName(entry.sourcePin.storedAs)
      || !Number.isSafeInteger(entry.sourcePin.version) || entry.sourcePin.version < 1
      || !Number.isSafeInteger(entry.sourcePin.size) || entry.sourcePin.size < 0
      || entry.sourcePin.size > 2 * 1024 * 1024
      || typeof entry.sourcePin.sha256 !== "string"
      || !/^[A-Za-z0-9_-]{43}$/.test(entry.sourcePin.sha256)
      || typeof entry.sourcePin.uploadedAt !== "string"
      || !Number.isFinite(Date.parse(entry.sourcePin.uploadedAt))
      || typeof entry.sourcePin.lastModified !== "string"
      || !Number.isFinite(Date.parse(entry.sourcePin.lastModified))
      || new Date(entry.sourcePin.lastModified).toUTCString() !== entry.sourcePin.lastModified
      || typeof entry.sourcePin.mediaType !== "string"
      || !/^[a-z0-9][a-z0-9.!#$&^_+-]*\/[a-z0-9][a-z0-9.!#$&^_+-]*$/.test(entry.sourcePin.mediaType)
      || Object.prototype.toString.call(entry.cek) !== "[object CryptoKey]"
      || entry.cek.type !== "secret" || entry.cek.extractable !== false
      || entry.cek.algorithm?.name !== "AES-GCM"
      || entry.cek.algorithm?.length !== 256
      || !entry.cek.usages?.includes("encrypt")
      || !entry.cek.usages?.includes("decrypt")) refuse();
  }
  async function deriveIds(secret, scope, ownerPin, head, entry) {
    const key = await crypto.subtle.importKey("raw", secret,
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const selection = JSON.stringify({ schema: "rootark-zk1-legacy-batch/v1",
      scope, ownerPin, head, legacy: entry.legacy, sourcePin: entry.sourcePin });
    const sign = async (suffix) => new Uint8Array(await crypto.subtle.sign(
      "HMAC", key, new TextEncoder().encode(suffix + "\0" + selection)));
    return { object_id: b64((await sign("object")).slice(0, 16)),
      version_id: b64((await sign("version")).slice(0, 16)) };
  }
  async function verifyCatalog(entry, fetchImpl) {
    const url = "/versions/" + encodeURIComponent(entry.legacy.name)
      + (entry.legacy.folderId
        ? "?folderId=" + encodeURIComponent(entry.legacy.folderId) : "");
    const controller = new AbortController();
    let deadlineHandle, res, reader, complete = false;
    const deadline = new Promise((_, reject) => {
      deadlineHandle = setTimeout(() => {
        controller.abort();
        reject(new Error("Legacy catalog deadline exceeded"));
      }, READ_DEADLINE_MS);
    });
    const bounded = (promise) => Promise.race([promise, deadline]);
    try {
      res = await bounded(Promise.resolve().then(() => fetchImpl(url, { method: "GET", credentials: "same-origin",
        cache: "no-store", redirect: "error", referrerPolicy: "no-referrer",
        headers: { Accept: "application/json" }, signal: controller.signal })).then((received) => {
        if (controller.signal.aborted) {
          try {
            const canceled = received?.body?.cancel?.();
            if (canceled?.catch) canceled.catch(() => {});
          } catch (_) { /* already refused */ }
        }
        return received;
      }));
      if (res?.status !== 200
        || !/^application\/json(?:\s*;|\s*$)/i.test(res.headers?.get?.("content-type") || "")
        || !res.body?.getReader) refuse();
      // Bound the complete response, including chunked bodies without CL.
      reader = res.body.getReader();
      const decoder = new TextDecoder("utf-8", { fatal: true });
      let body = "", length = 0;
      while (true) {
        const { done, value } = await bounded(reader.read());
        if (done) break;
        if (!(value instanceof Uint8Array) || length + value.byteLength > 256 * 1024) refuse();
        length += value.byteLength;
        body += decoder.decode(value, { stream: true });
      }
      body += decoder.decode();
      complete = true;
      const data = JSON.parse(body);
      // The real route identifies the root folder as "root" while older
      // local fixtures use "". Even a root selection must authenticate the
      // folder identity; otherwise a foreign folder can replace the source.
      if (!data || data.fileName !== entry.legacy.name
        || (data.folderId !== entry.legacy.folderId
          && !(entry.legacy.folderId === "" && data.folderId === "root"))
        || !Array.isArray(data.versions) || data.versions.length > 512) refuse();
      const selected = data.versions.filter((v) => v?.version === entry.sourcePin.version);
      if (selected.length !== 1 || selected[0].storedAs !== entry.sourcePin.storedAs
        || selected[0].uploadedAt !== entry.sourcePin.uploadedAt
        || selected[0].size !== entry.sourcePin.size) refuse();
    } catch (_) { refuse(); }
    finally {
      clearTimeout(deadlineHandle);
      if (!complete) {
        controller.abort();
        try {
          const canceled = reader ? reader.cancel() : res?.body?.cancel?.();
          if (canceled?.catch) canceled.catch(() => {});
        } catch (_) { /* refusal wins */ }
      }
      if (reader) { try { reader.releaseLock(); } catch (_) { /* canceled */ } }
    }
  }
  async function runLegacyMigrationBatch(input) {
    exact(input, ["optIn", "entries", "migrationSecret", "trust", "origin",
      "fetchImpl", "journal", "nowSeconds",
      ...(Object.hasOwn(input || {}, "transitionApprovals") ? ["transitionApprovals"] : [])]);
    if (input.optIn !== true || !Array.isArray(input.entries)
      || input.entries.length < 1 || input.entries.length > LIMIT
      || !(input.migrationSecret instanceof Uint8Array)
      || input.migrationSecret.byteLength !== 32
      || typeof input.fetchImpl !== "function" || typeof input.origin !== "string"
      || !input.trust?.signedDeviceGrant || !input.trust?.pinnedCurrentHead) refuse();
    const approvals = Object.hasOwn(input, "transitionApprovals")
      ? input.transitionApprovals : null;
    if (approvals !== null && (!Array.isArray(approvals)
      || approvals.length !== input.entries.length
      || Reflect.ownKeys(approvals).length !== approvals.length + 1)) refuse();
    if (approvals) {
      for (let i = 0; i < approvals.length; i++) {
        const slot = Object.getOwnPropertyDescriptor(approvals, String(i));
        if (!slot || !Object.hasOwn(slot, "value")) refuse();
        if (slot.value !== null) exact(slot.value,
          ["signedRootCheckpoint", "signedTransitionReceipt"]);
      }
    }
    const scope = Object.fromEntries(SCOPE.map((field) =>
      [field, input.trust.signedDeviceGrant[field]]));
    if (SCOPE.some((field) => typeof scope[field] !== "string"
      || scope[field].length < 1 || scope[field].length > 128)) refuse();
    const ownerPinBytes = input.trust.independentOwnerSpkiSha256;
    const digestBytes = input.trust.pinnedCurrentHead.digest;
    if (!(ownerPinBytes instanceof Uint8Array || ownerPinBytes instanceof ArrayBuffer)
      || !(digestBytes instanceof Uint8Array || digestBytes instanceof ArrayBuffer)
      || ownerPinBytes.byteLength !== 32 || digestBytes.byteLength !== 32) refuse();
    const ownerPin = b64(new Uint8Array(ownerPinBytes));
    const head = { revision: input.trust.pinnedCurrentHead.revision,
      digest: b64(new Uint8Array(digestBytes)), epoch: input.trust.pinnedCurrentHead.epoch };
    if (!Number.isSafeInteger(head.revision) || !Number.isSafeInteger(head.epoch)
      || head.revision < 1 || head.epoch < 1) refuse();
    const secret = new Uint8Array(input.migrationSecret);
    const prepared = [];
    const seen = new Set();
    try {
      for (const selected of input.entries) {
        validateEntry(selected);
        const entry = { legacy: { ...selected.legacy }, sourcePin: { ...selected.sourcePin },
          cek: selected.cek };
        const identity = JSON.stringify({ legacy: entry.legacy,
          version: entry.sourcePin.version });
        if (seen.has(identity)) refuse();
        seen.add(identity);
        const ids = await deriveIds(secret, scope, ownerPin, head, entry);
        prepared.push({ entry, metadata: { ...scope, ...ids,
          parent_version_id: null, epoch: head.epoch, kind: "file" } });
      }
    } finally { secret.fill(0); }
    // Sequential, bounded: an ambiguous item never authorizes re-sending PUT,
    // and a partial batch never marks subsequent items as complete.
    const results = [];
    for (const [index, { entry, metadata }] of prepared.entries()) {
      const safeResult = { objectId: metadata.object_id,
        versionId: metadata.version_id, legacyVersion: entry.sourcePin.version,
        canDeleteLegacy: false, authorizesCutover: false };
      try {
        await verifyCatalog(entry, input.fetchImpl);
        const result = await migration.beginLegacyMigration({
          optIn: true, legacy: entry.legacy, sourcePin: entry.sourcePin,
          metadata, trust: input.trust, cek: entry.cek, origin: input.origin,
          fetchImpl: input.fetchImpl, journal: input.journal,
          nowSeconds: input.nowSeconds,
        });
        await verifyCatalog(entry, input.fetchImpl);
        let transitionResult = null;
        if (approvals && approvals[index] !== null) {
          const approved = approvals[index];
          exact(approved, ["signedRootCheckpoint", "signedTransitionReceipt"]);
          transitionResult = await migration.stageLegacyMigrationTransition({
            optIn: true, legacy: entry.legacy, sourcePin: entry.sourcePin,
            metadata, trust: input.trust, cek: entry.cek, origin: input.origin,
            fetchImpl: input.fetchImpl, journal: input.journal,
            nowSeconds: input.nowSeconds,
            signedRootCheckpoint: approved.signedRootCheckpoint,
            signedTransitionReceipt: approved.signedTransitionReceipt,
          });
          await verifyCatalog(entry, input.fetchImpl);
        }
        results.push(Object.freeze({ ...safeResult,
          phase: transitionResult?.phase || result.phase,
          transitionState: transitionResult?.state || "staged-copy",
          verifiedLocalReadback: true, root: result.root,
          requiresOwnerCheckpoint: !transitionResult,
          ownerTransitionReceiptVerified: Boolean(transitionResult),
          wholeCorpusVerified: false }));
      } catch (_) {
        results.push(Object.freeze({ ...safeResult,
          phase: "needs-manual-review", verifiedLocalReadback: false,
          transitionState: "needs-manual-review", requiresOwnerCheckpoint: true,
          ownerTransitionReceiptVerified: false, wholeCorpusVerified: false }));
      }
    }
    const approvedCount = results.filter((item) => item.ownerTransitionReceiptVerified).length;
    const state = approvedCount === results.length ? "verified-protected"
      : approvedCount > 0 ? "mixed" : "partial";
    return Object.freeze({ total: results.length,
      verified: results.filter((item) => item.verifiedLocalReadback).length,
      verifiedProtected: approvedCount, transitionState: state,
      wholeCorpusVerified: false, canDeleteLegacy: false, authorizesCutover: false,
      results: Object.freeze(results) });
  }
  return Object.freeze({ runLegacyMigrationBatch });
}));
