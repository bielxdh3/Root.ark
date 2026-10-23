(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-browser-catalog"),
      require("./rootark-zk1-normal-browser-content"),
      require("./rootark-zk1-normal-browser-trust-floor"),
      require("./rootark-zk1-file-content"),
      require("./rootark-zk1-ciphertext-chunk-root"),
      require("./rootark-zk1-protected-http-client"),
      require("./rootark-zk1-uncertain-put-reconciliation"));
  } else {
    root.RootarkZk1ClientRenameMove = factory(root.crypto,
      root.RootarkZk1BrowserCatalog, root.RootarkZk1NormalBrowserContent,
      root.RootarkZk1NormalBrowserTrustFloor, root.RootarkZk1FileContent,
      root.RootarkZk1CiphertextRoot, root.RootarkZk1ProtectedHttpClient,
      root.RootarkZk1UncertainPutReconciliation);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (crypto, catalog, normal, floor, content, roots, http, reconcile) {
    "use strict";
    // DEV: append one authenticated, independently encrypted file version.
    // Catalog GET proves the old ciphertext/digest against its separately
    // pinned signed head + external CAS; the server never receives a filename,
    // parent folder, plaintext or CEK. No source deletion or implicit cutover.
    const META = ["account_id", "compartment_id", "keyring_id", "object_id",
      "version_id", "parent_version_id", "epoch", "kind"];
    const SCOPE = ["account_id", "compartment_id", "keyring_id"];
    const ID = /^[A-Za-z0-9_-]{22}$/;
    const MAX = 4 * 1024 * 1024;
    function deny() { throw new Error("ZK_CLIENT_RENAME_MOVE_DENIED"); }
    function exact(value, keys) {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
        || Reflect.ownKeys(value).length !== keys.length
        || keys.some((key) => !Object.hasOwn(value, key))) deny();
    }
    function bytes(value, minimum, maximum = minimum) {
      const arrayBuffer = Object.prototype.toString.call(value) === "[object ArrayBuffer]";
      if (!ArrayBuffer.isView(value) && !arrayBuffer
        || value.byteLength < minimum || value.byteLength > maximum) deny();
      return arrayBuffer ? new Uint8Array(value.slice(0))
        : new Uint8Array(value.buffer.slice(value.byteOffset,
          value.byteOffset + value.byteLength));
    }
    function from64(value, size, max = size) {
      if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
        || value.length > Math.ceil(max * 4 / 3) + 4) deny();
      let binary;
      try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=")); }
      catch (_) { deny(); }
      const result = Uint8Array.from(binary, (letter) => letter.charCodeAt(0));
      if (result.length < size || result.length > max) deny();
      if (b64(result) !== value) deny();
      return result;
    }
    function b64(raw) {
      let binary = "";
      for (const octet of raw) binary += String.fromCharCode(octet);
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function equal(a, b) {
      if (a.length !== b.length) return false;
      let delta = 0;
      for (let i = 0; i < a.length; ++i) delta |= a[i] ^ b[i];
      return delta === 0;
    }
    function validId(value) { if (!ID.test(value) || b64(from64(value, 16)) !== value) deny(); }
    function cookie() {
      if (typeof document !== "object") return null;
      const raw = document.cookie.split(";").map((part) => part.trim())
        .find((part) => part.startsWith("rootark_csrf="));
      if (!raw) deny();
      let value;
      try { value = decodeURIComponent(raw.slice("rootark_csrf=".length)); }
      catch (_) { deny(); }
      if (!value) deny();
      return value;
    }
    function clock(source) {
      const value = typeof source === "function" ? source() : source;
      if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - 45)
        deny();
      return value;
    }
    async function renameOrMove(input) {
      let oldCiphertext, oldPlain, newCiphertext, readBack, reconciledPlain;
      try {
        const keys = ["catalog", "sourceIndex", "sourceMetadata", "sourceCek",
          "destinationName", "destinationParentFolderId",
          "ownerPublicKey", "pinnedOwnerKeyHash", "independentOwnerSpkiSha256",
          "pinnedCurrentHead", "signedDeviceGrant", "ownerHistoryCheckpoint",
          "previousOwnerHistoryProof", "devicePublicKey", "devicePrivateKey",
          "origin", "fetchImpl", "nowSeconds", "assertLive"];
        exact(input, keys);
        exact(input.sourceMetadata, META);
        const source = { ...input.sourceMetadata };
        const head = { revision: input.pinnedCurrentHead?.revision,
          digest: bytes(input.pinnedCurrentHead?.digest, 32),
          epoch: input.pinnedCurrentHead?.epoch };
        if (!Number.isSafeInteger(head.revision) || head.revision < 1
          || !Number.isSafeInteger(head.epoch) || head.epoch < 1
          || source.kind !== "file"
          || !Number.isSafeInteger(source.epoch) || source.epoch < 1
          || source.epoch > head.epoch
          || typeof input.destinationName !== "string"
          || input.destinationName.length < 1 || input.destinationName.length > 255
          || /[\\/\u0000-\u001f\u007f]/.test(input.destinationName)
          || (input.destinationParentFolderId !== null
            && typeof input.destinationParentFolderId !== "string")
          || typeof input.fetchImpl !== "function" || typeof input.assertLive !== "function"
          || typeof input.origin !== "string")
          deny();
        if (input.destinationParentFolderId !== null) validId(input.destinationParentFolderId);
        validId(source.object_id);
        validId(source.version_id);
        if (source.parent_version_id !== null) validId(source.parent_version_id);
        const entry = input.catalog?.entries?.[input.sourceIndex];
        if (!entry || !Number.isSafeInteger(input.sourceIndex) || input.sourceIndex < 0
          || entry.objectId !== source.object_id || entry.epoch !== source.epoch
          || !Number.isSafeInteger(entry.revision) || entry.revision < 1
          || entry.revision >= Number.MAX_SAFE_INTEGER) deny();
        // Snapshot the independently verified catalog entry before async work.
        const previousRevision = entry.revision;
        const sourceDigest = from64(entry.ciphertextDigestBase64, 32);
        const ownerSpki = bytes(input.independentOwnerSpkiSha256, 32);
        const ownerRawPin = bytes(input.pinnedOwnerKeyHash, 32);
        const trust = { ownerPublicKey: input.ownerPublicKey,
          independentOwnerSpkiSha256: ownerSpki, pinnedCurrentHead: head,
          signedDeviceGrant: Object.fromEntries(Object.entries(input.signedDeviceGrant)),
          ownerHistoryCheckpoint: input.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: input.previousOwnerHistoryProof };
        const csrf = cookie();
        const assertLive = () => {
          input.assertLive();
          if (cookie() !== csrf) deny();
        };
        const guard = async () => {
          assertLive();
          if (typeof window === "object") {
            await floor.assertCurrent(trust);
            assertLive();
          }
        };
        const fetchGuarded = async (url, options) => {
          await guard();
          const response = await input.fetchImpl(url, options);
          assertLive();
          return response;
        };
        await guard();
        const proof = await normal.verifyOwnerGrant({
          ownerPublicKey: trust.ownerPublicKey,
          pinnedOwnerKeyHash: ownerRawPin, pinnedCurrentHead: head,
          signedDeviceGrant: trust.signedDeviceGrant,
          devicePublicKey: input.devicePublicKey,
          devicePrivateKey: input.devicePrivateKey,
        });
        if (!proof.ownerGrantSignatureVerified) deny();
        const scope = Object.fromEntries(SCOPE.map((name) =>
          [name, trust.signedDeviceGrant[name]]));
        if (SCOPE.some((name) => source[name] !== scope[name])
          || (input.destinationParentFolderId !== null
            && input.destinationParentFolderId === source.object_id)) deny();
        const signer = { signerKey: input.devicePrivateKey, scope,
          deviceId: trust.signedDeviceGrant.device_id,
          manifestRevision: head.revision, manifestDigest: head.digest,
          epoch: head.epoch, nowSeconds: clock(input.nowSeconds) };
        // The catalog's branded GET signs the historical revision + digest.
        // A caller-created or mutated entry cannot bypass its WeakMap proof.
        const historical = await catalog.getCatalogCiphertext(input.catalog, input.sourceIndex);
        await guard();
        if (historical.objectId !== source.object_id
          || historical.revision !== previousRevision) deny();
        oldCiphertext = from64(historical.ciphertextBase64, 16, MAX);
        const digest = bytes(await crypto.subtle.digest("SHA-256", oldCiphertext), 32);
        if (!equal(sourceDigest, digest)) deny();
        oldPlain = await content.decryptFile({ cek: input.sourceCek,
          metadata: source, envelopeBytes: oldCiphertext });
        await guard();
        if (oldPlain.authorizesRelease === true) deny();
        const next = { ...source,
          version_id: b64(crypto.getRandomValues(new Uint8Array(16))),
          parent_version_id: source.version_id, epoch: head.epoch };
        const destinationCek = await content.generateFileCek();
        const destinationParent = input.destinationParentFolderId;
        const newName = input.destinationName;
        const originalMediaType = oldPlain.mediaType;
        newCiphertext = await content.encryptFileWithParent({
          cek: destinationCek, metadata: next,
          name: newName, parentFolderId: destinationParent,
          mediaType: originalMediaType, data: oldPlain.data });
        // The original cleartext is no longer required once the new AEAD exists.
        oldPlain.data.fill(0); oldPlain = null;
        await guard();
        const root = bytes(await roots.computeCiphertextRoot([newCiphertext]), 32);
        const newDigest = bytes(await crypto.subtle.digest("SHA-256", newCiphertext), 32);
        const signedPut = await http.signProtectedContentOperation({
          ...signer, nowSeconds: clock(input.nowSeconds),
          operation: "put", objectId: source.object_id,
          expectedObjectRevision: previousRevision, ciphertext: newCiphertext });
        await guard();
        let lostAck = false;
        try {
          const ack = await http.postProtectedCiphertextPut({
            origin: input.origin, request: signedPut, fetchImpl: fetchGuarded });
          await guard();
          if (ack.id !== source.object_id || ack.revision !== previousRevision + 1) deny();
        } catch (_) {
          // A timed-out PUT may already be committed. Never issue a second PUT.
          await guard();
          reconciledPlain = await content.decryptFile({
            cek: destinationCek, metadata: next,
            envelopeBytes: newCiphertext });
          const expectedPlainDigest = bytes(await crypto.subtle.digest("SHA-256",
            reconciledPlain.data), 32);
          reconciledPlain.data.fill(0); reconciledPlain = null;
          await guard();
          const resolved = await reconcile.reconcileUncertainProtectedPut({
            origin: input.origin, fetchImpl: fetchGuarded,
            signer: { ...signer, nowSeconds: clock(input.nowSeconds) },
            objectId: source.object_id, previousRevision, ciphertext: newCiphertext,
            expectedRoot: root, expectedPlaintextSha256: expectedPlainDigest,
            cek: destinationCek, metadata: next,
          });
          await guard();
          if (!resolved.clientReadbackVerified) deny();
          lostAck = true;
        }
        // Confirm this exact new revision and AEAD from a fresh signed GET.
        const read = await http.signProtectedContentOperation({
          ...signer, nowSeconds: clock(input.nowSeconds),
          operation: "get", objectId: source.object_id,
          expectedObjectRevision: previousRevision + 1,
          expectedCiphertextDigest: newDigest, ciphertext: null });
        await guard();
        readBack = await http.postProtectedCiphertextRead({
          origin: input.origin, request: read, fetchImpl: fetchGuarded,
          expectedObjectRevision: previousRevision + 1, expectedRoot: root,
          metadata: next, cek: destinationCek });
        await guard();
        if (readBack.name !== newName
          || readBack.parentFolderId !== destinationParent
          || readBack.mediaType !== originalMediaType
          || readBack.authorizesRelease !== false) deny();
        return Object.freeze({
          objectId: source.object_id, revision: previousRevision + 1,
          previousRevision, metadata: Object.freeze(next),
          ciphertextDigestBase64: b64(newDigest), ciphertextRootBase64: b64(root),
          sourceHistoricalVersionPreserved: true,
          destinationReadbackVerified: true, lostPutAckReconciled: lostAck,
          destinationCek,
          requiresExternalCekArchive: true, metadataCatalogCommitPending: true,
          durableExternalCommitVerified: false, authorizesCutover: false,
          authorizesProductionIo: false,
        });
      } catch (_) { deny(); }
      finally {
        oldCiphertext?.fill(0);
        oldPlain?.data?.fill(0);
        newCiphertext?.fill(0);
        readBack?.data?.fill(0);
        reconciledPlain?.data?.fill(0);
      }
    }
    return Object.freeze({ renameOrMove });
  }));
