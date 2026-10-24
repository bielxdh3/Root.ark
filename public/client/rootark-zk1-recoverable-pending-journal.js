(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-portable-file-recovery"));
  } else {
    root.RootarkZk1RecoverablePendingJournal = factory(root.crypto,
      root.RootarkZk1PortableFileRecovery);
  }
}(typeof globalThis === "object" ? globalThis : this, function (crypto, portable) {
  "use strict";
  // This is a local *pending* backup of the encrypted portable bundle, NOT a
  // receipt of successful PUT, physical fsync, remote durability or owner approval.
  // Keep after uncertain GET and browser restart; never retry an ambiguous PUT.
  const DB = "rootark-zk1-recoverable-pending-v1";
  const STORE = "sealed-intents";
  const FORMAT = "rootark-zk1-recoverable-pending/v1";
  const DOMAIN = "Root.ark/zk-1/recoverable-pending-journal/v1\0";
  const encode = new TextEncoder();
  const decode = new TextDecoder("utf-8", { fatal: true });
  const ID = /^[A-Za-z0-9_-]{22}$/;
  const RE = /^[A-Za-z0-9_-]+$/;
  function deny() { throw Error("ZK_RECOVERABLE_PENDING_UNVERIFIED"); }
  function bytes(value, length) {
    if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)
      || value.byteLength !== length) deny();
    return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
      : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  function b64(raw) {
    let data = "";
    for (const value of raw) data += String.fromCharCode(value);
    return btoa(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(value, length) {
    if (typeof value !== "string" || !RE.test(value)
      || value.length > Math.ceil(length * 4 / 3) + 4) deny();
    let bin;
    try { bin = atob(value.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
    const result = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    if (result.length !== length || b64(result) !== value) deny();
    return result;
  }
  function exact(value, fields) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== fields.length
      || fields.some((key) => !Object.hasOwn(value, key))) deny();
  }
  function head(head) {
    exact(head, ["revision", "digest", "epoch"]);
    if (!Number.isSafeInteger(head.revision) || head.revision < 1
      || !Number.isSafeInteger(head.epoch) || head.epoch < 1) deny();
    return { revision: head.revision, digest: b64(bytes(head.digest, 32)), epoch: head.epoch };
  }
  function context(row) {
    return encode.encode(DOMAIN + JSON.stringify({ schema: row.schema,
      operationId: row.operationId, operationSignature: row.operationSignature,
      objectId: row.objectId, versionId: row.versionId,
      ownerSpkiSha256: row.ownerSpkiSha256,
      manifestRevision: row.manifestRevision, manifestDigest: row.manifestDigest,
      epoch: row.epoch, ownerHistorySequence: row.ownerHistorySequence,
      ciphertextSha256: row.ciphertextSha256, ciphertextRoot: row.ciphertextRoot }));
  }
  async function key(secret, salt, aad) {
    const imported = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt,
      info: aad }, imported, { name: "AES-GCM", length: 256 }, false,
    ["encrypt", "decrypt"]);
  }
  function metadata(bundle) {
    if (!bundle || !ID.test(bundle.metadata?.object_id || "")
      || !ID.test(bundle.metadata?.version_id || "")
      || bundle.metadata.parent_version_id !== null
      || bundle.metadata.kind !== "file" || bundle.objectRevision !== 1
      || typeof bundle.ciphertextBase64 !== "string"
      || bundle.ciphertextBase64.length > 6 * 1024 * 1024) deny();
    from64(bundle.ciphertextSha256, 32);
    from64(bundle.ciphertextRoot, 32);
    return bundle.metadata;
  }
  function record(value) {
    exact(value, ["schema", "operationId", "operationSignature",
      "objectId", "versionId", "ownerSpkiSha256",
      "manifestRevision", "manifestDigest", "epoch", "ownerHistorySequence",
      "ciphertextSha256", "ciphertextRoot", "salt", "iv", "sealed"]);
    if (value.schema !== FORMAT || !ID.test(value.objectId) || !ID.test(value.versionId)
      || !Number.isSafeInteger(value.manifestRevision) || value.manifestRevision < 1
      || !Number.isSafeInteger(value.epoch) || value.epoch < 1
      || (value.ownerHistorySequence !== null && (!Number.isSafeInteger(value.ownerHistorySequence)
        || value.ownerHistorySequence < 1))
      || typeof value.sealed !== "string" || value.sealed.length > 9 * 1024 * 1024) deny();
    for (const name of ["ownerSpkiSha256", "manifestDigest", "ciphertextSha256", "ciphertextRoot"])
      from64(value[name], 32);
    from64(value.operationId, 32); from64(value.operationSignature, 64);
    from64(value.salt, 32); from64(value.iv, 12);
    if (!RE.test(value.sealed)) deny();
    return value;
  }
  function openStore(indexedDBImpl = typeof indexedDB === "object" ? indexedDB : undefined) {
    if (typeof indexedDBImpl?.open !== "function") deny();
    async function transact(mode, task) {
      let db;
      try {
        db = await new Promise((resolve, reject) => {
          const request = indexedDBImpl.open(DB, 1);
          request.onupgradeneeded = () => {
            if (!request.result.objectStoreNames.contains(STORE))
              request.result.createObjectStore(STORE);
          };
          request.onerror = request.onblocked = () => reject(Error("open"));
          request.onsuccess = () => resolve(request.result);
        });
        return await new Promise((resolve, reject) => {
          let result;
          try {
            const tx = mode === "readonly" ? db.transaction(STORE, mode)
              : db.transaction(STORE, mode, { durability: "strict" });
            // Unsupported/relaxed strict transaction MUST NOT allow PUT.
            if (mode === "readwrite" && tx.durability !== "strict") { tx.abort(); deny(); }
            const request = task(tx.objectStore(STORE));
            request.onsuccess = () => { result = request.result; };
            tx.oncomplete = () => resolve(result);
            tx.onerror = tx.onabort = () => reject(Error("transaction"));
          } catch (error) { reject(error); }
        });
      } catch (_) { deny(); }
      finally { db?.close(); }
    }
    const store = Object.freeze({
      async prepare({ recoverySecret, bundle, ownerSpkiSha256, pinnedCurrentHead,
        ownerHistorySequence = null, operationId, operationSignature }) {
        let secret, plaintext, sealed;
        try {
          secret = bytes(recoverySecret, 32);
          const meta = metadata(bundle);
          const pinned = head(pinnedCurrentHead);
          if (pinned.epoch !== meta.epoch) deny();
          const row = { schema: FORMAT, operationId, operationSignature,
            objectId: meta.object_id,
            versionId: meta.version_id, ownerSpkiSha256: b64(bytes(ownerSpkiSha256, 32)),
            manifestRevision: pinned.revision, manifestDigest: pinned.digest,
            epoch: pinned.epoch, ownerHistorySequence,
            ciphertextSha256: bundle.ciphertextSha256, ciphertextRoot: bundle.ciphertextRoot,
            salt: b64(crypto.getRandomValues(new Uint8Array(32))),
            iv: b64(crypto.getRandomValues(new Uint8Array(12))) };
          const aad = context(row);
          plaintext = encode.encode(JSON.stringify(bundle));
          const sealingKey = await key(secret, from64(row.salt, 32), aad);
          sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM",
            iv: from64(row.iv, 12), additionalData: aad, tagLength: 128 }, sealingKey, plaintext));
          row.sealed = b64(sealed);
          record(row);
          // add(), NEVER put(): duplicate IDs or conflicting in-flight work
          // fail closed and cannot overwrite the first uncertain ciphertext.
          await transact("readwrite", (os) => os.add(row, row.objectId));
          const recovered = await store.load({ recoverySecret: secret, objectId: row.objectId });
          if (JSON.stringify(recovered.bundle) !== JSON.stringify(bundle)) deny();
          return Object.freeze({ objectId: row.objectId, strictTransactionCompleted: true,
            encryptedJournalReadbackVerified: true, independentPhysicalDurabilityProven: false });
        } catch (_) { deny(); }
        finally { secret?.fill(0); plaintext?.fill(0); sealed?.fill(0); }
      },
      async load({ recoverySecret, objectId }) {
        let secret, plaintext, opened;
        try {
          if (!ID.test(objectId || "")) deny();
          secret = bytes(recoverySecret, 32);
          const row = record(await transact("readonly", (os) => os.get(objectId)));
          if (row.objectId !== objectId) deny();
          const aad = context(row);
          const unsealingKey = await key(secret, from64(row.salt, 32), aad);
          const sealed = from64(row.sealed, Math.floor(row.sealed.length * 3 / 4));
          plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM",
            iv: from64(row.iv, 12), additionalData: aad, tagLength: 128 },
          unsealingKey, sealed));
          const bundle = JSON.parse(decode.decode(plaintext));
          const meta = metadata(bundle);
          if (meta.object_id !== row.objectId || meta.version_id !== row.versionId
            || meta.epoch !== row.epoch || bundle.ciphertextSha256 !== row.ciphertextSha256
            || bundle.ciphertextRoot !== row.ciphertextRoot) deny();
          // AEAD of the sealed CEK + exact ciphertext digest and root also
          // confirmed locally. Never place unwrapped CEK or file data in IDB.
          opened = await portable.openWithIndependentRoot({ recoverySecret: secret,
            bundle, expectedMetadata: meta,
            independentlyPinnedCiphertextRoot: from64(row.ciphertextRoot, 32) });
          return Object.freeze({ bundle, objectId, head: Object.freeze({
            revision: row.manifestRevision, digest: row.manifestDigest,
            epoch: row.epoch, ownerHistorySequence: row.ownerHistorySequence,
            ownerSpkiSha256: row.ownerSpkiSha256 }),
            encryptedJournalReadbackVerified: true, authorizesProductionIo: false });
        } catch (_) { deny(); }
        finally { secret?.fill(0); plaintext?.fill(0); opened?.data?.fill(0); }
      },
      async listPendingIds() {
        try {
          const ids = await transact("readonly", (os) => os.getAllKeys());
          if (!Array.isArray(ids) || ids.length > 4096 || ids.some((id) => !ID.test(id))) deny();
          // Opaque IDs only; no names, CEKs or plaintext disclosed.
          return Object.freeze([...ids]);
        } catch (_) { deny(); }
      },
    });
    return store;
  }
  return Object.freeze({ openStore });
}));
