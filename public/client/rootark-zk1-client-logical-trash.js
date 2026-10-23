(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-browser-catalog"),
      require("./rootark-zk1-normal-browser-content"),
      require("./rootark-zk1-file-content"),
      require("./rootark-zk1-ciphertext-chunk-root"),
      require("./rootark-zk1-protected-http-client"));
  } else {
    root.RootarkZk1ClientLogicalTrash = factory(root.crypto,
      root.RootarkZk1BrowserCatalog, root.RootarkZk1NormalBrowserContent,
      root.RootarkZk1FileContent, root.RootarkZk1CiphertextRoot,
      root.RootarkZk1ProtectedHttpClient);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (crypto, catalog, normal, content, roots, http) {
    "use strict";

    // DEV opt-in. Every logical state change adds an immutable encrypted version.
    // Physical deletion, retention, GC and production durability are not proven.
    const te = new TextEncoder(), td = new TextDecoder("utf-8", { fatal: true });
    const FORMAT = "rootark-zk1-logical-trash/v1";
    const AAD = "Root.ark/zk-1/logical-trash-aead/v1\0";
    const ARCHIVE = "Root.ark/zk-1/logical-trash-archive-receipt/v1\0";
    const COMMIT = "Root.ark/zk-1/logical-trash-catalog-receipt/v1\0";
    const META = ["account_id", "compartment_id", "keyring_id", "object_id",
      "version_id", "parent_version_id", "epoch", "kind"];
    const SCOPE = ["account_id", "compartment_id", "keyring_id"];
    const ID = /^[A-Za-z0-9_-]{22}$/;
    const MAX = 4 * 1024 * 1024;
    function deny() { throw new Error("ZK_LOGICAL_TRASH_DENIED"); }
    function exact(v, keys) {
      if (!v || typeof v !== "object" || Array.isArray(v)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(v))
        || Reflect.ownKeys(v).length !== keys.length
        || keys.some((key) => !Object.hasOwn(v, key))) deny();
      return v;
    }
    function bytes(value, length, maximum = length) {
      const arrayBuffer = Object.prototype.toString.call(value) === "[object ArrayBuffer]";
      if ((!ArrayBuffer.isView(value) && !arrayBuffer)
        || value.byteLength < length || value.byteLength > maximum) deny();
      return arrayBuffer ? new Uint8Array(value.slice(0))
        : new Uint8Array(value.buffer.slice(value.byteOffset,
          value.byteOffset + value.byteLength));
    }
    function b64(raw) {
      let str = "";
      for (const octet of raw) str += String.fromCharCode(octet);
      return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function from64(value, minimum, maximum = minimum) {
      if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
        || value.length > Math.ceil(maximum * 4 / 3) + 4) deny();
      let decoded;
      try { decoded = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
      const raw = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
      if (raw.length < minimum || raw.length > maximum || b64(raw) !== value) deny();
      return raw;
    }
    function equal(a, b) {
      if (a.length !== b.length) return false;
      let difference = 0;
      for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
      return difference === 0;
    }
    function id(value) { if (typeof value !== "string" || !ID.test(value)) deny(); from64(value, 16); return value; }
    function metadata(source) {
      exact(source, META);
      const result = { ...source };
      id(result.account_id); from64(result.compartment_id, 1, 128);
      id(result.keyring_id); id(result.object_id); id(result.version_id);
      if (result.parent_version_id !== null) id(result.parent_version_id);
      if (!Number.isSafeInteger(result.epoch) || result.epoch < 1 || result.kind !== "file") deny();
      return result;
    }
    function key(key, kind) {
      if (!key || key.type !== kind || key.algorithm?.name !== "Ed25519"
        || (kind === "private" && (key.extractable !== false
          || !key.usages.includes("sign")))
        || (kind === "public" && !key.usages.includes("verify"))) deny();
      return key;
    }
    function cek(keyValue) {
      if (!keyValue || keyValue.type !== "secret" || keyValue.extractable !== false
        || keyValue.algorithm?.name !== "AES-GCM"
        || keyValue.algorithm?.length !== 256
        || !keyValue.usages?.includes("decrypt")
        || !keyValue.usages?.includes("encrypt")) deny();
      return keyValue;
    }
    async function sha(data) { return bytes(await crypto.subtle.digest("SHA-256", data), 32); }
    function time(v) {
      const n = v();
      if (!Number.isSafeInteger(n) || n < 0 || n > Number.MAX_SAFE_INTEGER - 45) deny();
      return n;
    }
    function cookie() {
      if (typeof document !== "object") return null;
      const part = document.cookie.split(";").map((s) => s.trim())
        .find((s) => s.startsWith("rootark_csrf="));
      if (!part) deny();
      try { return decodeURIComponent(part.slice(13)); } catch (_) { deny(); }
    }
    function tombstoneContext(next, prior) {
      return te.encode(AAD + JSON.stringify(next) + "\0" + JSON.stringify(prior));
    }
    async function sealTombstone(keyValue, next, prior) {
      cek(keyValue);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = te.encode(JSON.stringify({ state: "trashed", retention: "unknown" }));
      try {
        const encrypted = new Uint8Array(await crypto.subtle.encrypt({
          name: "AES-GCM", iv, additionalData: tombstoneContext(next, prior),
          tagLength: 128,
        }, keyValue, plaintext));
        return te.encode(JSON.stringify({ format: FORMAT, metadata: next,
          predecessor: prior, nonce: b64(iv), ciphertext: b64(encrypted) }));
      } finally { plaintext.fill(0); }
    }
    async function openTombstone(keyValue, next, raw, prior) {
      let plain;
      try {
        cek(keyValue);
        const wire = bytes(raw, 16, MAX);
        const parsed = JSON.parse(td.decode(wire));
        exact(parsed, ["format", "metadata", "predecessor", "nonce", "ciphertext"]);
        if (parsed.format !== FORMAT || JSON.stringify(parsed) !== td.decode(wire)
          || JSON.stringify(parsed.metadata) !== JSON.stringify(next)
          || JSON.stringify(parsed.predecessor) !== JSON.stringify(prior)) deny();
        plain = new Uint8Array(await crypto.subtle.decrypt({
          name: "AES-GCM", iv: from64(parsed.nonce, 12),
          additionalData: tombstoneContext(next, prior), tagLength: 128,
        }, keyValue, from64(parsed.ciphertext, 16, MAX)));
        if (td.decode(plain) !== '{"state":"trashed","retention":"unknown"}') deny();
      } catch (_) { deny(); } finally { plain?.fill(0); }
    }
    function predecessor(revision, digest, version) {
      if (!Number.isSafeInteger(revision) || revision < 1) deny();
      id(version); from64(digest, 32);
      return { revision, ciphertextDigest: digest, versionId: version };
    }
    async function signedReceipt(authority, domain, challenge, response) {
      exact(response, ["signatureBase64"]);
      const message = te.encode(domain + JSON.stringify(challenge));
      if (!await crypto.subtle.verify("Ed25519", key(authority, "public"),
        from64(response.signatureBase64, 64), message)) deny();
    }
    function latest(catalogSnapshot, entry, revision) {
      if (!catalogSnapshot || !Array.isArray(catalogSnapshot.entries)
        || !entry || entry.revision !== revision || entry.epoch < 1
        || catalogSnapshot.entries.some((row) => row.objectId === entry.objectId
          && row.revision > revision)) deny();
    }
    function noPermanentDelete() { deny(); }

    async function change(input) {
      let sourceBytes, oldPlain, originalBytes, destinationBytes, checkBytes;
      try {
        exact(input, ["action", "catalog", "sourceIndex", "sourceMetadata", "sourceCek",
          "originalIndex", "originalMetadata", "originalCek", "ownerPublicKey",
          "pinnedOwnerKeyHash", "pinnedCurrentHead", "signedDeviceGrant",
          "devicePublicKey", "devicePrivateKey", "origin", "fetchImpl", "nowSeconds",
          "csrfToken", "isSessionCurrent", "assertOfflinePin", "catalogWriter",
          "metadataKey", "archiveKeys", "readArchivedCek", "archiveAuthorityPublicKey",
          "catalogProof", "catalogAuthorityPublicKey"]);
        if (!["trash", "restore"].includes(input.action)
          || !Number.isSafeInteger(input.sourceIndex) || input.sourceIndex < 0
          || typeof input.fetchImpl !== "function" || typeof input.nowSeconds !== "function"
          || typeof input.csrfToken !== "function" || typeof input.isSessionCurrent !== "function"
          || typeof input.assertOfflinePin !== "function" || typeof input.archiveKeys !== "function"
          || typeof input.readArchivedCek !== "function" || typeof input.catalogProof !== "function"
          || !input.catalogWriter || typeof input.catalogWriter.prepareIntent !== "function"
          || typeof input.catalogWriter.commit !== "function"
          || typeof input.catalogWriter.readAll !== "function"
          || !["AES-GCM"].includes(input.metadataKey?.algorithm?.name)
          || input.metadataKey?.extractable !== false) deny();
        key(input.devicePrivateKey, "private"); key(input.devicePublicKey, "public");
        key(input.archiveAuthorityPublicKey, "public");
        key(input.catalogAuthorityPublicKey, "public");
        const source = metadata(input.sourceMetadata);
        const head = exact(input.pinnedCurrentHead, ["revision", "digest", "epoch"]);
        if (!Number.isSafeInteger(head.revision) || head.revision < 1
          || !Number.isSafeInteger(head.epoch) || head.epoch < 1
          || source.epoch > head.epoch) deny();
        const digestHead = bytes(head.digest, 32);
        const sourceRow = input.catalog?.entries?.[input.sourceIndex];
        if (!sourceRow || sourceRow.objectId !== source.object_id
          || sourceRow.epoch !== source.epoch || sourceRow.revision >= Number.MAX_SAFE_INTEGER) deny();
        latest(input.catalog, sourceRow, sourceRow.revision);
        const original = input.action === "restore" ? metadata(input.originalMetadata) : null;
        const originalRow = input.action === "restore" ? input.catalog?.entries?.[input.originalIndex] : null;
        if (input.action === "restore" && (!Number.isSafeInteger(input.originalIndex)
          || input.originalIndex < 0 || input.originalIndex === input.sourceIndex
          || original.object_id !== source.object_id
          || originalRow?.objectId !== source.object_id
          || originalRow?.epoch !== original.epoch
          || originalRow?.revision !== sourceRow.revision - 1)) deny();
        if (input.action === "trash" && (input.originalIndex !== null
          || input.originalMetadata !== null || input.originalCek !== null)) deny();
        const token = input.csrfToken(), browserCookie = cookie();
        if (typeof token !== "string" || !token || token.length > 512
          || /[\u0000-\u001f\u007f]/.test(token)
          || (browserCookie !== null && token !== browserCookie)) deny();
        const scope = Object.fromEntries(SCOPE.map((name) =>
          [name, input.signedDeviceGrant?.[name]]));
        if (SCOPE.some((name) => source[name] !== scope[name])) deny();
        const pinned = { revision: head.revision, digest: digestHead, epoch: head.epoch };
        const assertLive = () => {
          if (input.isSessionCurrent() !== true || input.csrfToken() !== token
            || (browserCookie !== null && cookie() !== browserCookie)) deny();
        };
        const guard = async () => {
          assertLive();
          if (await input.assertOfflinePin({ pinnedCurrentHead: pinned,
            signedDeviceGrant: input.signedDeviceGrant }) !== true) deny();
          assertLive();
        };
        const fetchGuarded = async (url, options) => {
          await guard();
          const reply = await input.fetchImpl(url, options);
          await guard();
          return reply;
        };
        await guard();
        const proof = await normal.verifyOwnerGrant({
          ownerPublicKey: input.ownerPublicKey,
          pinnedOwnerKeyHash: bytes(input.pinnedOwnerKeyHash, 32),
          pinnedCurrentHead: pinned, signedDeviceGrant: input.signedDeviceGrant,
          devicePublicKey: input.devicePublicKey, devicePrivateKey: input.devicePrivateKey,
        });
        if (proof.ownerGrantSignatureVerified !== true) deny();
        const signer = { signerKey: input.devicePrivateKey, scope,
          deviceId: input.signedDeviceGrant.device_id,
          manifestRevision: head.revision, manifestDigest: digestHead,
          epoch: head.epoch, nowSeconds: time(input.nowSeconds) };
        const historical = await catalog.getCatalogCiphertext(input.catalog, input.sourceIndex);
        await guard();
        if (historical.objectId !== source.object_id || historical.revision !== sourceRow.revision) deny();
        sourceBytes = from64(historical.ciphertextBase64, 16, MAX);
        const sourceDigest = from64(sourceRow.ciphertextDigestBase64, 32);
        if (!equal(await sha(sourceBytes), sourceDigest)) deny();
        const prior = predecessor(sourceRow.revision, sourceRow.ciphertextDigestBase64,
          source.version_id);
        if (input.action === "trash") {
          oldPlain = await content.decryptFile({ cek: input.sourceCek,
            metadata: source, envelopeBytes: sourceBytes });
          if (oldPlain.authorizesRelease === true) deny();
        } else {
          const originalPrior = predecessor(originalRow.revision,
            originalRow.ciphertextDigestBase64, original.version_id);
          if (source.parent_version_id !== original.version_id) deny();
          await openTombstone(input.sourceCek, source, sourceBytes, originalPrior);
          const old = await catalog.getCatalogCiphertext(input.catalog, input.originalIndex);
          await guard();
          if (old.objectId !== original.object_id || old.revision !== originalRow.revision) deny();
          originalBytes = from64(old.ciphertextBase64, 16, MAX);
          if (!equal(await sha(originalBytes), from64(originalRow.ciphertextDigestBase64, 32))) deny();
          oldPlain = await content.decryptFile({ cek: input.originalCek,
            metadata: original, envelopeBytes: originalBytes });
        }
        await guard();
        const next = { ...source, version_id: b64(crypto.getRandomValues(new Uint8Array(16))),
          parent_version_id: source.version_id, epoch: head.epoch };
        const newCek = await content.generateFileCek();
        if (input.action === "trash") {
          destinationBytes = await sealTombstone(newCek, next, prior);
        } else {
          destinationBytes = await content.encryptFileWithParent({ cek: newCek,
            metadata: next, name: oldPlain.name, mediaType: oldPlain.mediaType,
            parentFolderId: oldPlain.parentFolderId ?? null, data: oldPlain.data });
        }
        const newDigest = await sha(destinationBytes);
        const newRoot = bytes(await roots.computeCiphertextRoot([destinationBytes]), 32);
        const newRevision = sourceRow.revision + 1;
        if (!Number.isSafeInteger(newRevision)) deny();
        const archiveEntries = [
          { metadata: source, revision: sourceRow.revision, ciphertext: sourceBytes,
            cek: input.sourceCek, state: input.action === "trash" ? "file" : "trashed" },
          ...(input.action === "restore" ? [{ metadata: original, revision: originalRow.revision,
            ciphertext: originalBytes, cek: input.originalCek, state: "file" }] : []),
          { metadata: next, revision: newRevision, ciphertext: destinationBytes,
            cek: newCek, state: input.action === "trash" ? "trashed" : "file" },
        ];
        const nonce = b64(crypto.getRandomValues(new Uint8Array(32)));
        const archiveChallenge = { objectId: source.object_id, action: input.action,
          epoch: head.epoch, nonce, entries: await Promise.all(archiveEntries.map(async (entry) => ({
            revision: entry.revision, versionId: entry.metadata.version_id,
            ciphertextDigest: b64(await sha(entry.ciphertext)),
          }))) };
        await guard();
        const archiveReceipt = await input.archiveKeys({ challenge: archiveChallenge,
          entries: archiveEntries });
        await guard();
        await signedReceipt(input.archiveAuthorityPublicKey, ARCHIVE,
          archiveChallenge, archiveReceipt);
        // A signature claiming custody is insufficient. Actually open every
        // archived version using the freshly loaded nonextractable CEK.
        for (const entry of archiveEntries) {
          const restoredKey = await input.readArchivedCek({ objectId: source.object_id,
            revision: entry.revision, versionId: entry.metadata.version_id,
            nonce });
          await guard();
          if (entry.state === "file") {
            const plain = await content.decryptFile({ cek: restoredKey,
              metadata: entry.metadata, envelopeBytes: entry.ciphertext });
            plain.data.fill(0);
          } else {
            const reference = entry.revision === newRevision ? prior :
              predecessor(originalRow.revision, originalRow.ciphertextDigestBase64,
                original.version_id);
            await openTombstone(restoredKey, entry.metadata, entry.ciphertext, reference);
          }
          await guard();
        }
        // Journal is written before the PUT. Catalog writes are strictly
        // additive; no old row/ciphertext is omitted or overwritten.
        const journalId = await input.catalogWriter.prepareIntent([{
          objectId: source.object_id, revision: newRevision,
          epoch: head.epoch, ciphertext: destinationBytes }]);
        await guard();
        const put = await http.signProtectedContentOperation({
          ...signer, nowSeconds: time(input.nowSeconds), operation: "put",
          objectId: source.object_id, expectedObjectRevision: sourceRow.revision,
          ciphertext: destinationBytes });
        await guard();
        let uncertainAck = false;
        try {
          const ack = await http.postProtectedCiphertextPut({
            origin: input.origin, request: put, fetchImpl: fetchGuarded });
          await guard();
          if (ack.id !== source.object_id || ack.revision !== newRevision) deny();
        } catch (_) {
          uncertainAck = true; // One POST only; resolve through exact signed GET.
          await guard();
        }
        const read = await http.signProtectedContentOperation({
          ...signer, nowSeconds: time(input.nowSeconds), operation: "get",
          objectId: source.object_id, expectedObjectRevision: newRevision,
          expectedCiphertextDigest: newDigest, ciphertext: null });
        await guard();
        const readBack = await http.postProtectedCiphertextBackupRead({
          origin: input.origin, request: read, fetchImpl: fetchGuarded,
          expectedObjectRevision: newRevision, expectedEpoch: head.epoch,
          expectedRoot: newRoot });
        await guard();
        checkBytes = from64(readBack.ciphertextBase64, 16, MAX);
        if (!equal(checkBytes, destinationBytes)) deny();
        if (input.action === "trash") {
          await openTombstone(newCek, next, checkBytes, prior);
        } else {
          const decrypted = await content.decryptFile({ cek: newCek,
            metadata: next, envelopeBytes: checkBytes });
          try {
            if (decrypted.name !== oldPlain.name || decrypted.mediaType !== oldPlain.mediaType
              || decrypted.parentFolderId !== (oldPlain.parentFolderId ?? null)
              || !equal(decrypted.data, oldPlain.data)) deny();
          } finally { decrypted.data.fill(0); }
        }
        const written = await input.catalogWriter.commit([{
          objectId: source.object_id, revision: newRevision, epoch: head.epoch,
          ciphertext: destinationBytes,
          name: input.action === "trash" ? "opaque-trashed-version" : oldPlain.name,
          metadataKey: input.metadataKey,
        }], journalId);
        await guard();
        if (written?.verifiedSignedReadback !== true
          || !Number.isSafeInteger(written.sequence) || written.sequence < 1) deny();
        const commitDigest = from64(written.digest, 32);
        const final = await input.catalogWriter.readAll();
        await guard();
        if (final.head.sequence !== written.sequence
          || !equal(bytes(final.head.digest, 32), commitDigest)
          || !Array.isArray(final.rows)
          || !final.rows.some((row) => row.object_id === source.object_id
            && row.revision === newRevision && row.epoch === head.epoch
            && equal(bytes(row.ciphertext_digest, 32), newDigest))
          || !final.rows.some((row) => row.object_id === source.object_id
            && row.revision === sourceRow.revision
            && equal(bytes(row.ciphertext_digest, 32), sourceDigest))) deny();
        const commitChallenge = { objectId: source.object_id, revision: newRevision,
          epoch: head.epoch, ciphertextDigest: b64(newDigest),
          manifestRevision: head.revision, manifestDigest: b64(digestHead),
          sequence: written.sequence, digest: written.digest,
          nonce: b64(crypto.getRandomValues(new Uint8Array(32))) };
        const signedCatalog = await input.catalogProof(commitChallenge);
        await guard();
        await signedReceipt(input.catalogAuthorityPublicKey, COMMIT,
          commitChallenge, signedCatalog);
        return Object.freeze({ objectId: source.object_id, revision: newRevision,
          action: input.action, metadata: Object.freeze(next),
          ciphertextDigestBase64: b64(newDigest), ciphertextRootBase64: b64(newRoot),
          catalogSequence: written.sequence, catalogDigestBase64: written.digest,
          archivedCeksReadbackVerified: true, historicalCiphertextPreserved: true,
          signedCatalogHeadVerified: true, ciphertextReadbackVerified: true,
          uncertainPutAckReconciled: uncertainAck, logicalStateFinalized: true,
          permanentDeletionAuthorized: false, physicalErasureProven: false,
          productionDurabilityProven: false, authorizesProductionIo: false });
      } catch (_) { deny(); }
      finally {
        sourceBytes?.fill(0); originalBytes?.fill(0);
        destinationBytes?.fill(0); checkBytes?.fill(0);
        oldPlain?.data?.fill(0);
      }
    }
    return Object.freeze({ trash: (input) => change({ ...input, action: "trash" }),
      restore: (input) => change({ ...input, action: "restore" }),
      permanentDelete: noPermanentDelete });
  }));
