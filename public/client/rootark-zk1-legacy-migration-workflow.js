(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-dev-vault-migration"),
      require("./rootark-zk1-file-content"),
      require("./rootark-zk1-ciphertext-chunk-root"),
      require("./rootark-zk1-protected-http-client"),
      require("./rootark-zk1-uncertain-put-reconciliation"),
      require("./rootark-zk1-normal-browser-content"),
      require("./rootark-zk1-normal-browser-trust-floor"),
      require("./rootark-zk1-owner-ciphertext-root-checkpoint"));
  } else {
    root.RootarkZk1LegacyMigrationWorkflow = factory(root.crypto,
      root.RootarkDevVaultMigration, root.RootarkZk1FileContent,
      root.RootarkZk1CiphertextRoot, root.RootarkZk1ProtectedHttpClient,
      root.RootarkZk1UncertainPutReconciliation,
      root.RootarkZk1NormalBrowserContent, root.RootarkZk1NormalBrowserTrustFloor,
      root.RootarkZk1OwnerCiphertextRootCheckpoint);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (webCrypto, legacyClient, file, roots, http, reconcile, browser, floor, ownerRoots) {
    "use strict";
    // Synthetic/dev workspace: explicit non-destructive opt-in. The OLD
    // /files route already gives its server plaintext. New protected PUT/GET
    // carries ciphertext only. Metadata (account/scope, object IDs, epoch,
    // size, access pattern, timing and hashed legacy locator) remains visible.
    // No profile/IndexedDB state proves independent provider durability or
    // survives a complete profile rollback. Retain the owner-signed checkpoint
    // and newest monotonic head separately, OFF the application server.
    const DB = "rootark-zk1-legacy-migration-intents-v1";
    const STORE = "migration_intents";
    const SCHEMA = "rootark-zk1-legacy-migration-intent/v1";
    const SCOPE = ["account_id", "compartment_id", "keyring_id"];
    const META = [...SCOPE, "object_id", "version_id", "parent_version_id", "epoch", "kind"];
    const PIN = ["version", "storedAs", "uploadedAt", "size", "lastModified",
      "sha256", "mediaType"];
    const activeJournals = new WeakSet();
    function deny() { throw new Error("ZK_LEGACY_MIGRATION_AMBIGUOUS"); }
    function exact(value, fields) {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
        || Reflect.ownKeys(value).length !== fields.length
        || fields.some((key) => !Object.hasOwn(value, key))) deny();
    }
    function bytes(raw, min, max = min) {
      if (!(raw instanceof ArrayBuffer) && !ArrayBuffer.isView(raw)
        || !Number.isSafeInteger(raw.byteLength) || raw.byteLength < min
        || raw.byteLength > max) deny();
      return raw instanceof ArrayBuffer ? new Uint8Array(raw.slice(0))
        : new Uint8Array(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength));
    }
    function b64(raw) {
      let text = "";
      for (const byte of raw) text += String.fromCharCode(byte);
      return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function from64(value, count, maximum = count) {
      if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
        || value.length > Math.ceil(maximum * 4 / 3) + 4) deny();
      let decoded;
      try { decoded = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
      const result = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
      if (result.length < count || result.length > maximum || b64(result) !== value) deny();
      return result;
    }
    async function digest(raw) {
      return b64(new Uint8Array(await webCrypto.subtle.digest("SHA-256", raw)));
    }
    function id(value) { if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(value)) deny(); return value; }
    function sourcePin(value) {
      exact(value, PIN);
      if (!Number.isSafeInteger(value.version) || value.version < 1
        || typeof value.storedAs !== "string" || !value.storedAs
        || value.storedAs.length > 255 || /[\\/\u0000-\u001f\u007f]/.test(value.storedAs)
        || typeof value.uploadedAt !== "string" || !Number.isFinite(Date.parse(value.uploadedAt))
        || typeof value.lastModified !== "string"
        || !Number.isFinite(Date.parse(value.lastModified))
        || new Date(value.lastModified).toUTCString() !== value.lastModified
        || !Number.isSafeInteger(value.size) || value.size < 0 || value.size > 2 * 1024 * 1024
        || typeof value.sha256 !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.sha256)
        || typeof value.mediaType !== "string" || !/^[a-z0-9][a-z0-9.!#$&^_+-]*\/[a-z0-9][a-z0-9.!#$&^_+-]*$/.test(value.mediaType)
        || value.mediaType.length > 128) deny();
      from64(value.sha256, 32);
      return Object.fromEntries(PIN.map((key) => [key, value[key]]));
    }
    function record(value) {
      exact(value, ["schema", "phase", "binding", "ciphertext", "root", "plainDigest",
        "cipherDigest", "sourceDescriptorDigest"]);
      if (value.schema !== SCHEMA || !["uncertain", "readback", "owner-proven"].includes(value.phase)
        || typeof value.binding !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.binding)
        || typeof value.plainDigest !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.plainDigest)
        || typeof value.cipherDigest !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.cipherDigest)
        || typeof value.sourceDescriptorDigest !== "string"
        || !/^[A-Za-z0-9_-]{43}$/.test(value.sourceDescriptorDigest)
        || typeof value.root !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.root)
        || typeof value.ciphertext !== "string" || value.ciphertext.length > 6 * 1024 * 1024) deny();
      from64(value.root, 32);
      from64(value.plainDigest, 32);
      from64(value.cipherDigest, 32);
      from64(value.sourceDescriptorDigest, 32);
      from64(value.ciphertext, 16, 4 * 1024 * 1024);
      return value;
    }
    async function openMigrationJournal(indexedDBImpl =
      typeof indexedDB === "object" ? indexedDB : undefined) {
      if (!indexedDBImpl?.open) deny();
      let db;
      try {
        db = await new Promise((resolve, reject) => {
          const request = indexedDBImpl.open(DB, 1);
          request.onupgradeneeded = () => {
            if (!request.result.objectStoreNames.contains(STORE))
              request.result.createObjectStore(STORE);
          };
          request.onsuccess = () => resolve(request.result);
          request.onerror = request.onblocked = () => reject(new Error("journal unavailable"));
        });
      } catch (_) { deny(); }
      let closed = false;
      const run = (key, next, expected) => new Promise((resolve, reject) => {
        if (closed || !db.objectStoreNames.contains(STORE)) { reject(new Error("closed")); return; }
        try {
          // The intent MUST commit before issuing the first network PUT.
          // Require Chromium's strict IDB durability request for readwrite
          // transactions; unsupported implementations fail closed.
          const tx = next === undefined ? db.transaction(STORE, "readonly")
            : db.transaction(STORE, "readwrite", { durability: "strict" });
          const store = tx.objectStore(STORE);
          const get = store.get(key);
          let found = null;
          get.onsuccess = () => {
            found = get.result ?? null;
            if (next !== undefined) {
              if (JSON.stringify(found) !== JSON.stringify(expected)) { tx.abort(); return; }
              store.put(next, key);
            }
          };
          tx.oncomplete = () => resolve(found);
          tx.onabort = tx.onerror = () => reject(new Error("journal CAS refused"));
        } catch (_) { reject(new Error("journal transaction refused")); }
      });
      const journal = Object.freeze({
        read(key) { id(key); return run(key); },
        cas(key, expected, next) { id(key); record(next); return run(key, next, expected); },
        close() { if (!closed) { closed = true; db.close(); } },
      });
      activeJournals.add(journal);
      return journal;
    }
    async function authority(input) {
      const trust = input.trust;
      exact(trust, ["ownerPublicKey", "pinnedOwnerKeyHash", "independentOwnerSpkiSha256",
        "pinnedCurrentHead", "signedDeviceGrant", "ownerHistoryCheckpoint",
        "previousOwnerHistoryProof", "devicePublicKey", "devicePrivateKey"]);
      if (trust.ownerHistoryCheckpoint === null) deny();
      exact(input.legacy, ["name", "folderId"]);
      exact(input.metadata, META);
      // Freeze the origin, locator and scope before any asynchronous crypto.
      // Reusing input.metadata after awaiting a signature would permit a form
      // mutation to redirect an otherwise valid device authorization.
      const legacy = { name: input.legacy.name, folderId: input.legacy.folderId };
      const meta = Object.fromEntries(META.map((field) => [field, input.metadata[field]]));
      const pinnedSource = Object.hasOwn(input, "sourcePin") ? sourcePin(input.sourcePin) : null;
      const head = { revision: trust.pinnedCurrentHead?.revision,
        digest: bytes(trust.pinnedCurrentHead?.digest, 32),
        epoch: trust.pinnedCurrentHead?.epoch };
      const grant = { ...trust.signedDeviceGrant };
      const anchored = {
        ownerPublicKey: trust.ownerPublicKey,
        independentOwnerSpkiSha256: bytes(trust.independentOwnerSpkiSha256, 32),
        pinnedCurrentHead: head,
        signedDeviceGrant: grant,
        ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
        previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
      };
      await floor.verifyExternalAnchor(anchored);
      if (typeof window === "object") await floor.assertCurrent(anchored);
      await browser.verifyOwnerGrant({ ownerPublicKey: trust.ownerPublicKey,
        pinnedOwnerKeyHash: trust.pinnedOwnerKeyHash,
        pinnedCurrentHead: head,
        signedDeviceGrant: grant,
        devicePublicKey: trust.devicePublicKey,
        devicePrivateKey: trust.devicePrivateKey });
      if (meta.kind !== "file" || meta.parent_version_id !== null
        || meta.epoch !== head.epoch
        || SCOPE.some((field) => meta[field] !== grant[field])) deny();
      id(meta.object_id);
      id(meta.version_id);
      if (typeof legacy.name !== "string" || legacy.name.length > 255
        || typeof legacy.folderId !== "string") deny();
      if (typeof input.fetchImpl !== "function" || typeof input.origin !== "string"
        || !activeJournals.has(input.journal) || input.optIn !== true) deny();
      const signer = { signerKey: trust.devicePrivateKey, scope: Object.fromEntries(
        SCOPE.map((field) => [field, meta[field]])), deviceId: grant.device_id,
        manifestRevision: head.revision,
        manifestDigest: head.digest,
        epoch: meta.epoch, nowSeconds: input.nowSeconds };
      if (!Number.isSafeInteger(input.nowSeconds) || input.nowSeconds < 1) deny();
      const binding = await digest(new TextEncoder().encode(JSON.stringify({
        schema: SCHEMA, legacy, metadata: meta,
        ownerSpki: b64(anchored.independentOwnerSpkiSha256),
        headDigest: b64(signer.manifestDigest), manifestRevision: signer.manifestRevision,
        ...(pinnedSource ? { pinnedSource } : {}),
      })));
      return { signer, binding, meta, trust, legacy, pinnedSource };
    }
    async function getPinnedSource(input, context) {
      const source = await legacyClient.readLegacyPlaintext({
        ...context.legacy, maxBytes: 2 * 1024 * 1024,
        version: context.pinnedSource?.version ?? null, fetchImpl: input.fetchImpl,
      });
      let accepted = false;
      try {
        if (context.pinnedSource && (source.data.byteLength !== context.pinnedSource.size
          || source.mediaType !== context.pinnedSource.mediaType
          || source.lastModified !== context.pinnedSource.lastModified
          || await digest(source.data) !== context.pinnedSource.sha256)) deny();
        accepted = true;
        return source;
      } finally { if (!accepted) source.data.fill(0); }
    }
    async function verifyReadback(input, context, saved) {
      const ciphertext = from64(saved.ciphertext, 16, 4 * 1024 * 1024);
      let source;
      try {
        if (await digest(ciphertext) !== saved.cipherDigest) deny();
        const root = await roots.computeCiphertextRoot([ciphertext]);
        if (b64(bytes(root, 32)) !== saved.root) deny();
        await reconcile.reconcileUncertainProtectedPut({
          origin: input.origin, fetchImpl: input.fetchImpl, signer: context.signer,
          objectId: context.meta.object_id, previousRevision: null,
          ciphertext, expectedRoot: root,
          expectedPlaintextSha256: from64(saved.plainDigest, 32),
          cek: input.cek, metadata: context.meta,
        });
        source = await getPinnedSource(input, context);
        if (await digest(source.data) !== saved.plainDigest
          || await digest(new TextEncoder().encode(JSON.stringify({
            name: source.name, mediaType: source.mediaType,
          }))) !== saved.sourceDescriptorDigest) deny();
        return true;
      } finally { source?.data?.fill(0); ciphertext.fill(0); }
    }
    async function beginLegacyMigration(input) {
      let source, ciphertext;
      try {
        exact(input, ["optIn", "legacy", "metadata", "trust", "cek", "origin",
          "fetchImpl", "journal", "nowSeconds", ...(Object.hasOwn(input, "sourcePin") ? ["sourcePin"] : [])]);
        const context = await authority(input);
        const key = context.meta.object_id;
        let previous = await input.journal.read(key);
        if (previous === null) {
          source = await getPinnedSource(input, context);
          ciphertext = await file.encryptFile({ cek: input.cek, metadata: context.meta,
            name: source.name, mediaType: source.mediaType, data: source.data });
          const root = bytes(await roots.computeCiphertextRoot([ciphertext]), 32);
          const saved = {
            schema: SCHEMA, phase: "uncertain", binding: context.binding,
            ciphertext: b64(ciphertext), root: b64(root),
            plainDigest: await digest(source.data), cipherDigest: await digest(ciphertext),
            sourceDescriptorDigest: await digest(new TextEncoder().encode(JSON.stringify({
              name: source.name, mediaType: source.mediaType,
            }))),
          };
          // Crash AFTER durable intent, BEFORE PUT: recovery does GET only.
          // This can leave an unresolved intent forever, never a false success.
          await input.journal.cas(key, null, saved);
          previous = saved;
          const put = await http.signProtectedContentOperation({
            ...context.signer, operation: "put", objectId: key,
            expectedObjectRevision: null, ciphertext,
          });
          try {
            const response = await http.postProtectedCiphertextPut({
              origin: input.origin, request: put, fetchImpl: input.fetchImpl });
            if (response.id !== key || response.revision !== 1) deny();
          } catch (_) { /* lost ACK is deliberately ambiguous until signed GET */ }
        }
        record(previous);
        if (previous.binding !== context.binding) deny();
        await verifyReadback(input, context, previous);
        if (previous.phase === "uncertain") await input.journal.cas(key, previous,
          { ...previous, phase: "readback" });
        return Object.freeze({ objectId: key, root: previous.root,
          phase: "awaiting-independent-owner-checkpoint", verifiedLocalReadback: true,
          canDeleteLegacy: false, authorizesCutover: false });
      } catch (_) { deny(); }
      finally { source?.data?.fill(0); ciphertext?.fill(0); }
    }
    async function finalizeLegacyMigration(input) {
      try {
        exact(input, ["optIn", "legacy", "metadata", "trust", "cek", "origin",
          "fetchImpl", "journal", "nowSeconds", "signedRootCheckpoint",
          ...(Object.hasOwn(input, "sourcePin") ? ["sourcePin"] : [])]);
        const context = await authority(input);
        const key = context.meta.object_id;
        const previous = await input.journal.read(key);
        if (!previous || !["readback", "owner-proven"].includes(previous.phase)
          || previous.binding !== context.binding) deny();
        await verifyReadback(input, context, previous);
        const checkpoint = input.signedRootCheckpoint;
        const history = context.trust.ownerHistoryCheckpoint;
        const signerKeyId = from64(history.signer_key_id, 16);
        const pinnedOwner = { scope: context.signer.scope, deviceId: history.device_id,
          signerKeyId, publicKey: context.trust.ownerPublicKey };
        const expected = { manifestRevision: context.signer.manifestRevision,
          manifestDigest: context.signer.manifestDigest,
          manifestEpoch: context.meta.epoch, objectId: key,
          objectRevision: 1, ciphertextEpoch: context.meta.epoch,
          ciphertextRoot: from64(previous.root, 32) };
        const proof = await ownerRoots.verifyOwnerCiphertextRootCheckpoint({
          checkpoint, ownerHistoryCheckpoint: history,
          previousHistoryProof: context.trust.previousOwnerHistoryProof,
          pinnedOwner, expected });
        ownerRoots.assertOwnerCiphertextRootProof({ proof, scope: pinnedOwner.scope,
          deviceId: pinnedOwner.deviceId,
          manifestRevision: expected.manifestRevision, manifestDigest: expected.manifestDigest,
          manifestEpoch: expected.manifestEpoch, objectId: expected.objectId,
          objectRevision: 1, ciphertextEpoch: expected.ciphertextEpoch,
          ciphertextRoot: expected.ciphertextRoot });
        if (previous.phase === "readback") await input.journal.cas(key, previous,
          { ...previous, phase: "owner-proven" });
        return Object.freeze({ objectId: key, root: previous.root,
          verifiedLocalReadback: true, externallySuppliedOwnerSignatureVerified: true,
          signedHistoricalCiphertextRootChecked: true,
          independentDurableWriteProven: false, externalRetentionProven: false,
          canDeleteLegacy: false, authorizesCutover: false, authorizesProductionIo: false });
      } catch (_) { deny(); }
    }
    return Object.freeze({ openMigrationJournal, beginLegacyMigration,
      finalizeLegacyMigration });
  }));
