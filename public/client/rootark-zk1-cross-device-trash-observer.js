(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-browser-catalog"),
      require("./rootark-zk1-file-content"));
  } else {
    root.RootarkZk1CrossDeviceTrashObserver = factory(root.crypto,
      root.RootarkZk1BrowserCatalog, root.RootarkZk1FileContent);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (crypto, catalog, file) {
    "use strict";

    // Read-only cross-device reconciliation. Every version must be present in
    // the independently pinned, owner-authorized signed CAS catalog. Signed
    // exact-version GET and the locally archived CEK authenticate each state.
    // Neither a server-provided "deleted" flag nor an uncertain PUT/CAS ACK
    // is a tombstone. Never restore or erase ciphertext automatically.
    const te = new TextEncoder(), td = new TextDecoder("utf-8", { fatal: true });
    const SCOPE = ["account_id", "compartment_id", "keyring_id"];
    const META = [...SCOPE, "object_id", "version_id", "parent_version_id", "epoch", "kind"];
    const DOMAIN = "Root.ark/zk-1/logical-trash-aead/v1\0";
    const TOMBSTONE = "rootark-zk1-logical-trash/v1";
    const VALUE = '{"state":"trashed","retention":"unknown"}';
    const ID = /^[A-Za-z0-9_-]{22}$/;
    const MAX = 4 * 1024 * 1024;
    function deny() { throw new Error("ZK_CROSS_DEVICE_TRASH_UNVERIFIED"); }
    function exact(value, keys) {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
        || Reflect.ownKeys(value).length !== keys.length
        || keys.some((name) => !Object.hasOwn(value, name))) deny();
    }
    function decode64(value, min, max = min) {
      if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
        || value.length > Math.ceil(max * 4 / 3) + 4) deny();
      let binary;
      try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
      const raw = Uint8Array.from(binary, (v) => v.charCodeAt(0));
      if (raw.length < min || raw.length > max || to64(raw) !== value) deny();
      return raw;
    }
    function to64(bytes) {
      let binary = "";
      for (const value of bytes) binary += String.fromCharCode(value);
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function validId(value) { if (!ID.test(value)) deny(); decode64(value, 16); return value; }
    function metadata(raw, scope, objectId, row, previous) {
      exact(raw, META);
      const meta = { ...raw };
      for (const key of SCOPE) if (meta[key] !== scope[key]) deny();
      validId(meta.version_id);
      if (validId(meta.object_id) !== objectId
        || meta.kind !== "file" || meta.epoch !== row.epoch
        || !Number.isSafeInteger(meta.epoch) || meta.epoch < 1) deny();
      if (previous ? meta.parent_version_id !== previous.version_id
        : meta.parent_version_id !== null) deny();
      return meta;
    }
    function checkKey(key) {
      if (key?.type !== "secret" || key?.extractable !== false
        || key.algorithm?.name !== "AES-GCM" || key.algorithm.length !== 256
        || !key.usages?.includes("decrypt")) deny();
      return key;
    }
    function bytes(value, min, max) {
      if (!ArrayBuffer.isView(value) || value.byteLength < min
        || value.byteLength > max) deny();
      return new Uint8Array(value.buffer.slice(value.byteOffset,
        value.byteOffset + value.byteLength));
    }
    async function openTombstone(raw, key, meta, predecessor) {
      let plain;
      try {
        const wire = td.decode(bytes(raw, 16, MAX));
        const envelope = JSON.parse(wire);
        exact(envelope, ["format", "metadata", "predecessor", "nonce", "ciphertext"]);
        if (wire !== JSON.stringify(envelope) || envelope.format !== TOMBSTONE
          || JSON.stringify(envelope.metadata) !== JSON.stringify(meta)
          || JSON.stringify(envelope.predecessor) !== JSON.stringify(predecessor)) deny();
        const aad = te.encode(DOMAIN + JSON.stringify(meta) + "\0"
          + JSON.stringify(predecessor));
        plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM",
          iv: decode64(envelope.nonce, 12), additionalData: aad, tagLength: 128 },
        key, decode64(envelope.ciphertext, 16, MAX)));
        if (td.decode(plain) !== VALUE) deny();
      } catch (_) { deny(); } finally { plain?.fill(0); }
    }
    function current() {
      if (!crypto?.subtle || typeof catalog?.openCatalog !== "function"
        || typeof catalog?.getCatalogCiphertext !== "function"
        || typeof file?.decryptFile !== "function") deny();
    }
    async function inspect(input) {
      let snapshot;
      try {
        current();
        exact(input, ["catalogRead", "objectId", "versionMetadata",
          "readArchivedCek", "assertLive"]);
        if (!input.catalogRead || typeof input.readArchivedCek !== "function"
          || typeof input.assertLive !== "function") deny();
        const objectId = validId(input.objectId);
        const scope = {};
        for (const name of SCOPE) {
          const value = input.catalogRead.trust?.signedDeviceGrant?.[name];
          decode64(value, name === "compartment_id" ? 1 : 16,
            name === "compartment_id" ? 128 : 16);
          scope[name] = value;
        }
        const pinned = input.catalogRead.pinnedCatalogHead;
        if (!Number.isSafeInteger(pinned?.sequence) || pinned.sequence < 1
          || pinned.sequence > 128) deny();
        decode64(pinned.digest, 32);
        // Keep the owner/device and out-of-band CAS pins fixed across BOTH
        // reads. A caller cannot swap these halfway through a lost ACK or a
        // slow asynchronous GET to manufacture a new apparent lifecycle.
        const originalTrust = input.catalogRead.trust;
        const selectedRead = { ...input.catalogRead,
          pinnedCatalogHead: { sequence: pinned.sequence, digest: pinned.digest },
          signerGrant: { ...input.catalogRead.signerGrant },
          independentAuthoritySpkiHash: bytes(
            input.catalogRead.independentAuthoritySpkiHash, 32, 32),
          trust: { ...originalTrust,
            signedDeviceGrant: { ...originalTrust.signedDeviceGrant },
            independentOwnerSpkiSha256: bytes(
              originalTrust.independentOwnerSpkiSha256, 32, 32),
            pinnedCurrentHead: { ...originalTrust.pinnedCurrentHead,
              digest: bytes(originalTrust.pinnedCurrentHead.digest, 32, 32) } } };
        const outOfBandFloor = Object.freeze({ ...selectedRead.pinnedCatalogHead });
        if (!Array.isArray(input.versionMetadata) || input.versionMetadata.length < 1
          || input.versionMetadata.length > 128) deny();
        // Immutable local copy before any asynchronous work. Metadata is only
        // admitted once its actual ciphertext authenticates under the CEK.
        const metadataRows = input.versionMetadata.map((item) => {
          exact(item, META);
          return { ...item };
        });
        input.assertLive();
        snapshot = await catalog.openCatalog(selectedRead);
        input.assertLive();
        if (snapshot.sequence !== outOfBandFloor.sequence
          || snapshot.catalogDigest !== outOfBandFloor.digest
          || !Array.isArray(snapshot.entries)) deny();
        const matches = snapshot.entries.map((entry, index) => ({ entry, index }))
          .filter(({ entry }) => entry.objectId === objectId);
        if (!matches.length || matches.length !== metadataRows.length) deny();
        let previous = null, priorRow = null, lastState = "file", restored = false;
        let lastFile = null;
        for (let offset = 0; offset < matches.length; offset++) {
          const { entry, index } = matches[offset];
          if (entry.revision !== offset + 1 || entry.epoch < 1) deny();
          const meta = metadata(metadataRows[offset], scope, objectId, entry, previous);
          const cek = checkKey(await input.readArchivedCek({ ...scope,
            objectId, revision: entry.revision, versionId: meta.version_id }));
          input.assertLive();
          const received = await catalog.getCatalogCiphertext(snapshot, index);
          input.assertLive();
          if (received.objectId !== objectId || received.revision !== entry.revision
            || received.ciphertextBase64 === undefined) deny();
          const ciphertext = decode64(received.ciphertextBase64, 16, MAX);
          let value, opened;
          try {
            // A tombstone is identified by its authenticated domain and AEAD
            // payload, never by an untrusted metadata name or server hint.
            const isTombstone = td.decode(ciphertext).startsWith('{"format":"' + TOMBSTONE + '"');
            if (isTombstone) {
              if (!previous || lastState !== "file") deny();
              await openTombstone(ciphertext, cek, meta, {
                revision: priorRow.revision,
                ciphertextDigest: priorRow.ciphertextDigestBase64,
                versionId: previous.version_id });
              value = "trashed";
            } else {
              opened = await file.decryptFile({ cek, metadata: meta, envelopeBytes: ciphertext });
              if (opened.authorizesRelease === true) deny();
              const contentDigest = to64(new Uint8Array(await crypto.subtle.digest(
                "SHA-256", opened.data)));
              const currentFile = { name: opened.name,
                parentFolderId: opened.parentFolderId ?? null,
                mediaType: opened.mediaType, size: opened.data.byteLength,
                contentDigest };
              // The catalog authenticates that a new FILE was written; it does
              // not authenticate the user's intent to RESTORE a trashed file.
              // Only an exact re-encryption of the preceding live version can
              // be classified as a restore without a separate signed marker.
              if (lastState === "trashed" && (!lastFile
                || Object.keys(currentFile).some((name) =>
                  currentFile[name] !== lastFile[name]))) deny();
              value = "file";
              if (lastState === "trashed") restored = true;
              lastFile = currentFile;
            }
          } finally { opened?.data?.fill(0); ciphertext.fill(0); }
          previous = meta;
          priorRow = entry;
          lastState = value;
        }
        // A vanished catalog CAS ACK or a competing newer writer is never
        // inferred from an HTTP response. Require a SECOND independently
        // signed, exact-head catalog read before exposing current lifecycle.
        input.assertLive();
        const confirmed = await catalog.openCatalog(selectedRead);
        input.assertLive();
        if (confirmed.sequence !== snapshot.sequence
          || confirmed.catalogDigest !== snapshot.catalogDigest
          || confirmed.entries.length !== snapshot.entries.length) deny();
        return Object.freeze({ objectId, state: lastState,
          restoredAfterTombstone: restored, revision: priorRow.revision,
          catalogSequence: snapshot.sequence, catalogDigest: snapshot.catalogDigest,
          exactSignedGetAndAeadVerified: true, monotonicPinnedFloorVerified: true,
          physicalErasureProven: false, productionDurabilityProven: false,
          authorizesProductionRestore: false });
      } catch (_) { deny(); }
    }
    return Object.freeze({ inspect });
  }));
