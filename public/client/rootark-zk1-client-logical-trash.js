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
      let rawNewCek;
      let journalId = null, archiveAttempted = false;
      let putAttempted = false, commitAttempted = false;
      let confirmedCommit = null;
      let pendingObjectId = null, pendingRevision = null;
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
          || typeof input.catalogWriter.confirmPendingIntent !== "function"
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
        // Retain only a transient client-side raw key for encrypted escrow.
        // The operational CEK is nonextractable immediately after import.
        rawNewCek = crypto.getRandomValues(new Uint8Array(32));
        const newCek = await content.importFileCek(rawNewCek);
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
        pendingObjectId = source.object_id;
        pendingRevision = newRevision;
        const archiveEntries = [
          { metadata: source, revision: sourceRow.revision, ciphertext: sourceBytes,
            cek: input.sourceCek, state: input.action === "trash" ? "file" : "trashed" },
          ...(input.action === "restore" ? [{ metadata: original, revision: originalRow.revision,
            ciphertext: originalBytes, cek: input.originalCek, state: "file" }] : []),
          { metadata: next, revision: newRevision, ciphertext: destinationBytes,
            cek: rawNewCek, state: input.action === "trash" ? "trashed" : "file" },
        ];
        // Establish the independently signed catalog authority before any
        // external key custody or ciphertext side effect.
        const preflightChallenge = { purpose: "precommit", objectId: source.object_id,
          revision: newRevision, epoch: head.epoch,
          ciphertextDigest: b64(newDigest), manifestRevision: head.revision,
          manifestDigest: b64(digestHead), previousSequence: input.catalog.sequence,
          previousDigest: input.catalog.catalogDigest,
          nonce: b64(crypto.getRandomValues(new Uint8Array(32))) };
        const preflightProof = await input.catalogProof(preflightChallenge);
        await guard();
        await signedReceipt(input.catalogAuthorityPublicKey, COMMIT,
          preflightChallenge, preflightProof);
        // The archive may save the CEK even when its acknowledgement is lost.
        // An immutable signed intent must exist before that first side effect.
        journalId = await input.catalogWriter.prepareIntent([{
          objectId: source.object_id, revision: newRevision,
          epoch: head.epoch, ciphertext: destinationBytes }]);
        await guard();
        // The signed, durable journal ID is also the CEK archive challenge
        // nonce. A reconnecting browser can re-read the exact escrowed key
        // without depending on a lost in-memory random nonce or retrying PUT.
        from64(journalId, 32);
        const nonce = journalId;
        const archiveChallenge = { ...scope, objectId: source.object_id, action: input.action,
          epoch: head.epoch, nonce, entries: await Promise.all(archiveEntries.map(async (entry) => ({
            revision: entry.revision, versionId: entry.metadata.version_id,
            ciphertextDigest: b64(await sha(entry.ciphertext)),
          }))) };
        archiveAttempted = true;
        const archiveReceipt = await input.archiveKeys({ challenge: archiveChallenge,
          entries: archiveEntries });
        await guard();
        await signedReceipt(input.archiveAuthorityPublicKey, ARCHIVE,
          archiveChallenge, archiveReceipt);
        // A signature claiming custody is insufficient. Actually open every
        // archived version using the freshly loaded nonextractable CEK.
        for (const entry of archiveEntries) {
          const restoredKey = await input.readArchivedCek({ ...scope, objectId: source.object_id,
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
        rawNewCek.fill(0); rawNewCek = null;
        await guard();
        const put = await http.signProtectedContentOperation({
          ...signer, nowSeconds: time(input.nowSeconds), operation: "put",
          objectId: source.object_id, expectedObjectRevision: sourceRow.revision,
          ciphertext: destinationBytes });
        await guard();
        let uncertainAck = false;
        try {
          // Once the request leaves the browser, even a thrown network error
          // cannot prove that the immutable version was not accepted. Keep the
          // prepared journal and forbid another PUT until signed GET resolves it.
          putAttempted = true;
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
        commitAttempted = true;
        const written = await input.catalogWriter.commit([{
          objectId: source.object_id, revision: newRevision, epoch: head.epoch,
          ciphertext: destinationBytes,
          name: input.action === "trash" ? "opaque-trashed-version" : oldPlain.name,
          metadataKey: input.metadataKey,
        }], journalId, { retainPendingIntent: true });
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
        // The writer checked the independent CAS signature and the complete
        // signed final catalog. Subsequent failures must say this COMMITTED.
        confirmedCommit = Object.freeze({ sequence: written.sequence,
          digest: written.digest });
        const commitChallenge = { objectId: source.object_id, revision: newRevision,
          epoch: head.epoch, ciphertextDigest: b64(newDigest),
          manifestRevision: head.revision, manifestDigest: b64(digestHead),
          sequence: written.sequence, digest: written.digest,
          nonce: b64(crypto.getRandomValues(new Uint8Array(32))) };
        const signedCatalog = await input.catalogProof(commitChallenge);
        await guard();
        await signedReceipt(input.catalogAuthorityPublicKey, COMMIT,
          commitChallenge, signedCatalog);
        if (await input.catalogWriter.confirmPendingIntent(journalId, written) !== true) deny();
        await guard();
        return Object.freeze({ objectId: source.object_id, revision: newRevision,
          action: input.action, metadata: Object.freeze(next),
          ciphertextDigestBase64: b64(newDigest), ciphertextRootBase64: b64(newRoot),
          catalogSequence: written.sequence, catalogDigestBase64: written.digest,
          archivedCeksReadbackVerified: true, historicalCiphertextPreserved: true,
          signedCatalogHeadVerified: true, ciphertextReadbackVerified: true,
          uncertainPutAckReconciled: uncertainAck, logicalStateFinalized: true,
          permanentDeletionAuthorized: false, physicalErasureProven: false,
          productionDurabilityProven: false, authorizesProductionIo: false });
      } catch (_) {
        if (commitAttempted) {
          // The external CAS may have committed even if its ACK, subsequent
          // verification or final independent proof was lost. Preserve the
          // signed intent for explicit operator reconciliation; never retry.
          const error = new Error("ZK_LOGICAL_TRASH_COMMIT_UNCERTAIN");
          error.code = error.message;
          error.outcome = Object.freeze({ objectId: pendingObjectId,
            revision: pendingRevision, journalId,
            catalogSequence: confirmedCommit?.sequence ?? null,
            catalogDigestBase64: confirmedCommit?.digest ?? null,
            signedCatalogReadbackVerified: confirmedCommit !== null,
            retrySafe: false, logicalStateFinalized: false });
          throw error;
        }
        if (putAttempted) {
          // A failed/missing readback is NOT proof that the initial PUT failed.
          // Retrying against the prior revision could strand the catalog or
          // collide with a successfully written immutable ciphertext version.
          const error = new Error("ZK_LOGICAL_TRASH_PUT_UNCERTAIN");
          error.code = error.message;
          error.outcome = Object.freeze({ objectId: pendingObjectId,
            revision: pendingRevision, journalId, phase: "ciphertext_readback",
            ciphertextPutMayHaveCommitted: true,
            ciphertextReadbackVerified: false, signedCatalogReadbackVerified: false,
            retrySafe: false, logicalStateFinalized: false });
          throw error;
        }
        if (archiveAttempted) {
          // Key escrow is an externally durable side effect. Without an ACK
          // we cannot declare the operation absent or silently retry it.
          const error = new Error("ZK_LOGICAL_TRASH_ARCHIVE_UNCERTAIN");
          error.code = error.message;
          error.outcome = Object.freeze({ objectId: pendingObjectId,
            revision: pendingRevision, journalId, phase: "key_archive",
            archiveMayHaveCommitted: true, ciphertextPutMayHaveCommitted: false,
            retrySafe: false, logicalStateFinalized: false });
          throw error;
        }
        deny();
      }
      finally {
        rawNewCek?.fill(0);
        sourceBytes?.fill(0); originalBytes?.fill(0);
        destinationBytes?.fill(0); checkBytes?.fill(0);
        oldPlain?.data?.fill(0);
      }
    }
    // Reconnect after a signed catalog CAS has committed, but the final ACK or
    // lifecycle proof was lost. This is explicitly a read-only recovery of a
    // TRASH commit: no PUT, no catalog commit, no plaintext release. A future
    // restore needs its own signed transaction and must not infer permission.
    async function reconcileCommittedTrash(input) {
      let sourceBytes, destinationBytes, opened;
      try {
        exact(input, ["catalogWriter", "journalId", "pinnedCatalogHead",
          "sourceMetadata", "destinationMetadata", "sourceRevision",
          "destinationRevision", "readArchivedCek", "assertLive"]);
        const writer = input.catalogWriter;
        if (typeof writer?.readAll !== "function"
          || typeof writer?.readVerifiedCiphertext !== "function"
          || typeof writer?.confirmPendingIntent !== "function"
          || typeof input.readArchivedCek !== "function"
          || typeof input.assertLive !== "function") deny();
        const journalId = b64(from64(input.journalId, 32));
        const source = metadata(input.sourceMetadata);
        const target = metadata(input.destinationMetadata);
        const sourceRevision = input.sourceRevision;
        const targetRevision = input.destinationRevision;
        if (!Number.isSafeInteger(sourceRevision) || sourceRevision < 1
          || sourceRevision >= Number.MAX_SAFE_INTEGER
          || targetRevision !== sourceRevision + 1
          || source.object_id !== target.object_id
          || SCOPE.some((field) => source[field] !== target[field])
          || target.parent_version_id !== source.version_id
          || target.epoch < source.epoch) deny();
        const outOfBand = exact(input.pinnedCatalogHead, ["sequence", "digest"]);
        const sequence = outOfBand.sequence;
        const digest = b64(from64(outOfBand.digest, 32));
        if (!Number.isSafeInteger(sequence) || sequence < 1 || sequence > 128) deny();
        const live = () => {
          // The session fence is synchronous: never treat a pending Promise
          // as a successful check while removing a committed journal.
          const check = input.assertLive();
          if (check === false || (check && typeof check.then === "function")) deny();
        };
        live();
        const snapshot = await writer.readAll();
        live();
        if (snapshot?.head?.sequence !== sequence
          || !equal(bytes(snapshot.head.digest, 32), from64(digest, 32))
          || !Array.isArray(snapshot.rows)) deny();
        const selected = [sourceRevision, targetRevision].map((revision) => {
          const found = snapshot.rows.filter((row) => row.object_id === source.object_id
            && row.revision === revision);
          if (found.length !== 1) deny();
          return found[0];
        });
        if (selected[0].epoch !== source.epoch || selected[1].epoch !== target.epoch
          || snapshot.rows.some((row) => row.object_id === source.object_id
            && row.revision > targetRevision)) deny();
        const scope = Object.fromEntries(SCOPE.map((field) => [field, source[field]]));
        const keys = [];
        for (const [index, item] of [source, target].entries()) {
          const revision = index ? targetRevision : sourceRevision;
          const recovered = await input.readArchivedCek({ ...scope,
            objectId: source.object_id, revision, versionId: item.version_id,
            nonce: journalId });
          cek(recovered);
          keys.push(recovered);
          live();
        }
        const sourceGet = await writer.readVerifiedCiphertext(snapshot,
          source.object_id, sourceRevision);
        live();
        const targetGet = await writer.readVerifiedCiphertext(snapshot,
          target.object_id, targetRevision);
        live();
        if (sourceGet.objectId !== source.object_id || targetGet.objectId !== target.object_id
          || sourceGet.revision !== sourceRevision || targetGet.revision !== targetRevision
          || sourceGet.epoch !== source.epoch || targetGet.epoch !== target.epoch) deny();
        sourceBytes = from64(sourceGet.ciphertextBase64, 16, MAX);
        destinationBytes = from64(targetGet.ciphertextBase64, 16, MAX);
        if (!equal(await sha(sourceBytes), bytes(selected[0].ciphertext_digest, 32))
          || !equal(await sha(destinationBytes), bytes(selected[1].ciphertext_digest, 32))) deny();
        opened = await content.decryptFile({ cek: keys[0],
          metadata: source, envelopeBytes: sourceBytes });
        if (opened.authorizesRelease === true) deny();
        opened.data.fill(0); opened = null;
        await openTombstone(keys[1], target, destinationBytes,
          predecessor(sourceRevision, b64(bytes(selected[0].ciphertext_digest, 32)),
            source.version_id));
        live();
        // The signed journal is checked AGAIN against independently pinned
        // CAS, complete history, exact protected GET and signer identity before
        // deletion. This also forbids replay of a competing/newer commit.
        if (await writer.confirmPendingIntent(journalId) !== true) deny();
        live();
        return Object.freeze({ objectId: source.object_id, revision: targetRevision,
          state: "trashed", signedCatalogCommitVerified: true,
          archivedCeksReadbackVerified: true, sourceHistoricalVersionPreserved: true,
          ciphertextReadbackVerified: true, productionDurabilityProven: false,
          permanentDeletionAuthorized: false, authorizesProductionIo: false });
      } catch (_) { deny(); }
      finally {
        sourceBytes?.fill(0); destinationBytes?.fill(0);
        opened?.data?.fill(0);
      }
    }
    // Recovery only AFTER a RESTORE catalog CAS is committed. Unlike a trash
    // reconciliation, both the old file and its authenticated tombstone must
    // be proven before accepting the newly encrypted restored file. In-memory
    // keys/ACKs may be gone; this uses only the durable signed journal ID and
    // fresh independently verified CAS + exact protected historical GETs.
    async function reconcileCommittedRestore(input) {
      const ciphertexts = [];
      const plains = [];
      try {
        exact(input, ["catalogWriter", "journalId", "pinnedCatalogHead",
          "originalMetadata", "sourceMetadata", "destinationMetadata",
          "originalRevision", "sourceRevision", "destinationRevision",
          "readArchivedCek", "assertLive"]);
        const writer = input.catalogWriter;
        if (typeof writer?.readAll !== "function"
          || typeof writer?.readVerifiedCiphertext !== "function"
          || typeof writer?.confirmPendingIntent !== "function"
          || typeof input.readArchivedCek !== "function"
          || typeof input.assertLive !== "function") deny();
        const journalId = b64(from64(input.journalId, 32));
        const original = metadata(input.originalMetadata);
        const source = metadata(input.sourceMetadata);
        const restored = metadata(input.destinationMetadata);
        const originalRevision = input.originalRevision;
        const sourceRevision = input.sourceRevision;
        const destinationRevision = input.destinationRevision;
        if (!Number.isSafeInteger(originalRevision) || originalRevision < 1
          || originalRevision >= Number.MAX_SAFE_INTEGER - 1
          || sourceRevision !== originalRevision + 1
          || destinationRevision !== sourceRevision + 1
          || original.object_id !== source.object_id
          || source.object_id !== restored.object_id
          || SCOPE.some((field) => original[field] !== source[field]
            || source[field] !== restored[field])
          || source.parent_version_id !== original.version_id
          || restored.parent_version_id !== source.version_id
          || original.epoch > source.epoch || source.epoch > restored.epoch) deny();
        const outside = exact(input.pinnedCatalogHead, ["sequence", "digest"]);
        const headSequence = outside.sequence;
        const headDigest = from64(outside.digest, 32);
        if (!Number.isSafeInteger(headSequence)
          || headSequence < 1 || headSequence > 128) deny();
        const live = () => {
          const check = input.assertLive();
          if (check === false || (check && typeof check.then === "function")) deny();
        };
        live();
        const snapshot = await writer.readAll();
        live();
        if (snapshot?.head?.sequence !== headSequence
          || !equal(bytes(snapshot.head.digest, 32), headDigest)
          || !Array.isArray(snapshot.rows)) deny();
        const versions = [originalRevision, sourceRevision, destinationRevision];
        const metas = [original, source, restored];
        const rows = versions.map((revision, index) => {
          const matches = snapshot.rows.filter((row) => row.object_id === source.object_id
            && row.revision === revision);
          if (matches.length !== 1 || matches[0].epoch !== metas[index].epoch) deny();
          return matches[0];
        });
        if (snapshot.rows.some((row) => row.object_id === source.object_id
          && row.revision > destinationRevision)) deny();
        const scope = Object.fromEntries(SCOPE.map((field) => [field, source[field]]));
        const keys = [];
        for (let i = 0; i < 3; ++i) {
          const keyValue = await input.readArchivedCek({ ...scope,
            objectId: source.object_id, revision: versions[i],
            versionId: metas[i].version_id, nonce: journalId });
          keys.push(cek(keyValue));
          live();
        }
        for (let i = 0; i < 3; ++i) {
          const read = await writer.readVerifiedCiphertext(snapshot,
            source.object_id, versions[i]);
          live();
          if (read.objectId !== source.object_id
            || read.revision !== versions[i] || read.epoch !== metas[i].epoch) deny();
          const wire = from64(read.ciphertextBase64, 16, MAX);
          ciphertexts.push(wire);
          if (!equal(await sha(wire), bytes(rows[i].ciphertext_digest, 32))) deny();
        }
        const expectedOriginal = predecessor(originalRevision,
          b64(bytes(rows[0].ciphertext_digest, 32)), original.version_id);
        await openTombstone(keys[1], source, ciphertexts[1], expectedOriginal);
        live();
        const first = await content.decryptFile({ cek: keys[0],
          metadata: original, envelopeBytes: ciphertexts[0] });
        plains.push(first.data);
        live();
        const last = await content.decryptFile({ cek: keys[2],
          metadata: restored, envelopeBytes: ciphertexts[2] });
        plains.push(last.data);
        live();
        if (first.authorizesRelease === true || last.authorizesRelease === true
          || first.name !== last.name || first.mediaType !== last.mediaType
          || (first.parentFolderId ?? null) !== (last.parentFolderId ?? null)
          || !equal(first.data, last.data)) deny();
        // Must revalidate signed journal signer, exact successor row, *all*
        // previous immutable rows, independent CAS/witness, and remote GETs
        // before removing the pending journal. Never repeat PUT/CAS.
        if (await writer.confirmPendingIntent(journalId) !== true) deny();
        live();
        return Object.freeze({ objectId: source.object_id,
          revision: destinationRevision, state: "file", restoredAfterTombstone: true,
          signedCatalogCommitVerified: true, archivedCeksReadbackVerified: true,
          historicalCiphertextPreserved: true, ciphertextReadbackVerified: true,
          permanentDeletionAuthorized: false, productionDurabilityProven: false,
          authorizesProductionIo: false });
      } catch (_) { deny(); }
      finally {
        for (const wire of ciphertexts) wire.fill(0);
        for (const plain of plains) plain.fill(0);
      }
    }
    return Object.freeze({ trash: (input) => change({ ...input, action: "trash" }),
      restore: (input) => change({ ...input, action: "restore" }),
      reconcileCommittedTrash, reconcileCommittedRestore,
      permanentDelete: noPermanentDelete });
  }));
