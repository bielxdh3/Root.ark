(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-browser-opaque-catalog-commit"),
      require("./rootark-zk1-protected-http-client"),
      require("./rootark-zk1-ciphertext-chunk-root"),
      require("./rootark-zk1-file-content"));
  } else {
    root.RootarkZk1OpaqueDeviceDeltaSync = factory(root.crypto,
      root.RootarkZk1BrowserOpaqueCatalogCommit,
      root.RootarkZk1ProtectedHttpClient, root.RootarkZk1CiphertextRoot,
      root.RootarkZk1FileContent);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (crypto, catalog, http, roots, fileContent) {
    "use strict";
    // Owner-authorized, additive ZK1 opaque-catalog sync. No generic sync
    // engine, server-supplied trust pin, plaintext filename, CEK or local
    // filesystem path crosses the wire. A delta covers ONE signed CAS successor
    // only; an unproven gap/fork is not interpreted as a set of changes.
    const MAX = 4 * 1024 * 1024;
    const TRASH_NAME = "\uE000rootark-zk1-logical-trash/v1";
    const TRASH_TYPE = "rootark-zk1-opaque-logical-trash/v1";
    const TRASH_DOMAIN = new TextEncoder().encode("Root.ark/zk-1/opaque-logical-trash/v1\0");
    const TRASH_AAD = "Root.ark/zk-1/opaque-logical-trash-aead/v1\0";
    const REKEY_DOMAIN = new TextEncoder().encode("Root.ark/zk-1/opaque-owner-epoch-restore-grant/v1\0");
    const REKEY_FORMAT = "rootark-zk1-opaque-owner-epoch-restore-grant/v1";
    const REKEY_FIELDS = ["format", "account_id", "compartment_id", "keyring_id",
      "deviceId", "objectId", "sourceRevision", "sourceEpoch",
      "sourceDigest", "tombstoneRevision", "tombstoneEpoch", "tombstoneDigest",
      "catalogSequence", "catalogDigest", "ownerRevision", "ownerDigest",
      "currentEpoch", "destinationRevision", "currentCekSha256",
      "currentMetadataKeySha256", "nonce", "issuedAt", "expiresAt"];
    const te = new TextEncoder(), td = new TextDecoder("utf-8", { fatal: true });
    const tracked = new WeakMap();
    function deny() { throw new Error("ZK_OPAQUE_DELTA_SYNC_DENIED"); }
    function exact(value, keys) {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
        || Reflect.ownKeys(value).length !== keys.length
        || keys.some((key) => !Object.hasOwn(value, key))) deny();
      if (Object.values(Object.getOwnPropertyDescriptors(value)).some(
        (descriptor) => !Object.hasOwn(descriptor, "value"))) deny();
    }
    function bytes(value, min, max = min) {
      if (!ArrayBuffer.isView(value) && !(value instanceof ArrayBuffer)
        || value.byteLength < min || value.byteLength > max) deny();
      return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
        : new Uint8Array(value.buffer.slice(value.byteOffset,
          value.byteOffset + value.byteLength));
    }
    function equal(a, b) {
      if (a.length !== b.length) return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
      return diff === 0;
    }
    function b64(data) {
      let text = "";
      for (const byte of data) text += String.fromCharCode(byte);
      return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function from64(encoded, min, max = min) {
      if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]+$/.test(encoded)
        || encoded.length > Math.ceil(max * 4 / 3) + 4) deny();
      let raw;
      try { raw = Uint8Array.from(atob(encoded.replace(/-/g, "+")
        .replace(/_/g, "/").padEnd(Math.ceil(encoded.length / 4) * 4, "=")),
      (x) => x.charCodeAt(0)); } catch (_) { deny(); }
      if (raw.length < min || raw.length > max || b64(raw) !== encoded) deny();
      return raw;
    }
    function rowWire(row) {
      return Object.freeze({ objectId: row.object_id, revision: row.revision,
        epoch: row.epoch, ciphertextDigestBase64: b64(bytes(row.ciphertext_digest, 32)),
        metadataCiphertextBase64: b64(bytes(row.metadata_ciphertext, 284)) });
    }
    function metadataKey(key) {
      if (!key || key.type !== "secret" || key.algorithm?.name !== "AES-GCM"
        || key.algorithm.length !== 256 || key.extractable !== false
        || !key.usages?.includes("encrypt") || !key.usages?.includes("decrypt")) deny();
      return key;
    }
    function fileCek(key) {
      if (!key || key.type !== "secret" || key.algorithm?.name !== "AES-GCM"
        || key.algorithm.length !== 256 || key.extractable !== false
        || !key.usages?.includes("decrypt") || !key.usages?.includes("encrypt")) deny();
      return key;
    }
    function restoredSourceMetadata(value, scope, objectId, epoch) {
      exact(value, ["account_id", "compartment_id", "keyring_id", "object_id",
        "version_id", "parent_version_id", "epoch", "kind"]);
      if (Object.keys(scope).some((key) => value[key] !== scope[key])
        || value.object_id !== objectId || value.epoch !== epoch
        || value.kind !== "file" || !/^[A-Za-z0-9_-]{22}$/.test(value.version_id)
        || (value.parent_version_id !== null
          && !/^[A-Za-z0-9_-]{22}$/.test(value.parent_version_id))) deny();
      from64(value.version_id, 16);
      if (value.parent_version_id !== null) from64(value.parent_version_id, 16);
      return { ...value };
    }
    function historicalSourceMetadataKey(key) {
      if (!key || key.type !== "secret" || key.algorithm?.name !== "AES-GCM"
        || key.algorithm.length !== 256 || key.extractable !== false
        || key.usages?.length !== 1 || key.usages[0] !== "decrypt") deny();
      return key;
    }
    function readablePredecessorMetadataKey(key) {
      if (!key || key.type !== "secret" || key.algorithm?.name !== "AES-GCM"
        || key.algorithm.length !== 256 || key.extractable !== false
        || !key.usages?.includes("decrypt")) deny();
      return key;
    }
    function readOnlyEpochMetadataKey(mapping, epoch) {
      if (!Array.isArray(mapping) || mapping.length < 1 || mapping.length > 128
        || mapping.some((entry, index) => {
          if (!entry || Reflect.ownKeys(entry).length !== 2
            || !Object.hasOwn(entry, "epoch") || !Object.hasOwn(entry, "key")
            || !Number.isSafeInteger(entry.epoch) || entry.epoch < 1
            || mapping.slice(0, index).some((before) => before.epoch === entry.epoch)) return true;
          const key = entry.key;
          return !key || key.type !== "secret" || key.algorithm?.name !== "AES-GCM"
            || key.algorithm.length !== 256 || key.extractable !== false
            || key.usages?.length !== 1 || key.usages[0] !== "decrypt";
        })) deny();
      const matches = mapping.filter((entry) => entry.epoch === epoch);
      if (matches.length !== 1) deny();
      return matches[0].key;
    }
    function trashAad(scope, objectId, revision, epoch) {
      return te.encode(TRASH_AAD + JSON.stringify({ ...scope, objectId, revision, epoch }));
    }
    function scopeFor(grant) {
      return Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
        .map((key) => [key, grant[key]]));
    }
    async function verifyEpochRekeyGrant(grant, source, tombstone, state, trust,
      newCekRaw, newMetadataRaw) {
      exact(grant, [...REKEY_FIELDS, "signature"]);
      const { signature } = grant;
      const unsigned = Object.fromEntries(REKEY_FIELDS.map((name) => [name, grant[name]]));
      const scope = scopeFor(trust.signedDeviceGrant);
      if (grant.format !== REKEY_FORMAT
        || Object.keys(scope).some((name) => grant[name] !== scope[name])
        || grant.deviceId !== trust.signedDeviceGrant.device_id
        || grant.objectId !== source.object_id
        || grant.sourceRevision !== source.revision
        || grant.sourceEpoch !== source.epoch
        || grant.sourceDigest !== b64(bytes(source.ciphertext_digest, 32))
        || grant.tombstoneRevision !== tombstone.revision
        || grant.tombstoneEpoch !== tombstone.epoch
        || grant.tombstoneDigest !== b64(bytes(tombstone.ciphertext_digest, 32))
        || grant.catalogSequence !== state.head.sequence
        || grant.catalogDigest !== state.head.digest
        || grant.ownerRevision !== trust.pinnedOwnerHead.revision
        || grant.ownerDigest !== b64(bytes(trust.pinnedOwnerHead.digest, 32))
        || grant.currentEpoch !== trust.pinnedOwnerHead.epoch
        || grant.destinationRevision !== tombstone.revision + 1
        || grant.currentCekSha256 !== b64(new Uint8Array(await crypto.subtle.digest(
          "SHA-256", newCekRaw)))
        || grant.currentMetadataKeySha256 !== b64(new Uint8Array(await crypto.subtle.digest(
          "SHA-256", newMetadataRaw)))
        || !Number.isSafeInteger(grant.issuedAt)
        || !Number.isSafeInteger(grant.expiresAt)
        || grant.issuedAt < 1 || grant.expiresAt <= grant.issuedAt
        || grant.expiresAt - grant.issuedAt > 300
        || grant.issuedAt > trust.nowSeconds() + 30
        || trust.nowSeconds() > grant.expiresAt
        || from64(grant.nonce, 32).length !== 32) deny();
      const ownerKey = trust.ownerPublicKey;
      if (ownerKey?.type !== "public" || ownerKey.algorithm?.name !== "Ed25519"
        || ownerKey.extractable !== true || !ownerKey.usages?.includes("verify")
        || !equal(new Uint8Array(await crypto.subtle.digest("SHA-256",
          await crypto.subtle.exportKey("raw", ownerKey))),
        bytes(trust.pinnedOwnerKeyHash, 32))) deny();
      const msg = new Uint8Array([...REKEY_DOMAIN, ...te.encode(JSON.stringify(unsigned))]);
      if (!await crypto.subtle.verify("Ed25519", ownerKey,
        from64(signature, 64), msg)) deny();
    }
    async function sealTrash(statement, signer, key) {
      const unsigned = te.encode(JSON.stringify(statement));
      const signature = new Uint8Array(await crypto.subtle.sign("Ed25519",
        signer, new Uint8Array([...TRASH_DOMAIN, ...unsigned])));
      const plaintext = te.encode(JSON.stringify({ statement, signature: b64(signature) }));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      try {
        const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv,
          additionalData: trashAad(scopeFor(statement), statement.objectId,
            statement.revision, statement.epoch), tagLength: 128 }, key, plaintext));
        const out = new Uint8Array(iv.length + encrypted.length);
        out.set(iv); out.set(encrypted, iv.length);
        return out;
      } finally { plaintext.fill(0); unsigned.fill(0); signature.fill(0); }
    }
    function createClient(input) {
      exact(input, ["authority", "assertLive"]);
      if (typeof input.assertLive !== "function"
        || typeof catalog?.createClient !== "function"
        || typeof http?.signProtectedContentOperation !== "function"
        || typeof roots?.computeCiphertextRoot !== "function") deny();
      // Never accept a caller-created writer or snapshot as authority. Create
      // the real client here: it verifies the owner witness, device grant,
      // nonextractable signing key, full catalog and independent signed CAS.
      const source = input.authority;
      const trust = Object.freeze({ ...source,
        signedDeviceGrant: Object.freeze({ ...source.signedDeviceGrant }),
        pinnedOwnerHead: Object.freeze({ ...source.pinnedOwnerHead,
          digest: bytes(source.pinnedOwnerHead.digest, 32) }),
        signerGrants: Object.freeze(source.signerGrants.map((g) => Object.freeze({ ...g }))),
      });
      const writer = catalog.createClient(trust);
      let latest = null, usedMutation = false;
      const sessionCsrf = trust.csrfToken();
      if (typeof sessionCsrf !== "string" || !sessionCsrf || sessionCsrf.length > 512
        || /[\u0000-\u001f\u007f]/.test(sessionCsrf)) deny();
      const assertLive = () => {
        const result = input.assertLive();
        if (result === false || (result && typeof result.then === "function")
          || trust.isSessionCurrent() !== true
          || trust.csrfToken() !== sessionCsrf) deny();
      };
      function remember(snapshot) {
        const head = { sequence: snapshot.head.sequence, digest: b64(bytes(snapshot.head.digest, 32)) };
        const exposed = Object.freeze({ head: Object.freeze(head),
          entries: Object.freeze(snapshot.rows.map(rowWire)),
          plaintextMetadataExposed: false, independentCloudDurabilityProven: false });
        tracked.set(exposed, { owner: writer, snapshot, head });
        latest = exposed;
        return exposed;
      }
      async function readCurrent() {
        try {
          if (latest) deny(); // repeat reads must use a fresh instance/floor
          assertLive();
          const snapshot = await writer.readAll();
          assertLive();
          return remember(snapshot);
        } catch (_) { deny(); }
      }
      async function pullDelta(previous) {
        try {
          const state = tracked.get(previous);
          if (!state || state.owner !== writer || previous !== latest
            || previous.head.sequence !== state.head.sequence
            || previous.head.digest !== state.head.digest
            || previous.entries.length !== state.snapshot.rows.length) deny();
          assertLive();
          const successor = await writer.readSignedSuccessor(state.snapshot);
          assertLive();
          const entries = [];
          for (const item of successor.additions) {
            // Every newly added immutable ciphertext is fetched using this
            // receiving device's Ed25519 key and its own current grant. The
            // catalog authority binds its exact revision and SHA-256 digest.
            const fetched = await writer.readVerifiedCiphertext(successor.snapshot,
              item.objectId, item.revision);
            assertLive();
            if (fetched.objectId !== item.objectId || fetched.revision !== item.revision
              || fetched.epoch !== item.epoch
              || fetched.ciphertextDigestBase64 !== item.ciphertextDigestBase64) deny();
            entries.push(Object.freeze({ ...item,
              ciphertextBase64: fetched.ciphertextBase64 }));
          }
          // Another writer may have changed CAS while the ciphertext was in
          // transit. This extra full signed read closes that race before a
          // receiving device applies any delta.
          const checked = await writer.readAll();
          assertLive();
          if (checked.head.sequence !== successor.snapshot.head.sequence
            || !equal(bytes(checked.head.digest, 32),
              bytes(successor.snapshot.head.digest, 32))) deny();
          const current = remember(checked);
          return Object.freeze({ fromSequence: state.head.sequence,
            toSequence: current.head.sequence, catalogDigest: current.head.digest,
            additions: Object.freeze(entries), snapshot: current,
            plaintextMetadataExposed: false, productionDurabilityProven: false });
        } catch (_) { deny(); }
      }
      async function readPrivateListing(previous, metadataKey) {
        try {
          const state = tracked.get(previous);
          if (!state || state.owner !== writer || previous !== latest
            || previous.head.sequence !== state.head.sequence
            || previous.head.digest !== state.head.digest
            || previous.entries.length !== state.snapshot.rows.length
            || typeof catalog.openMetadata !== "function"
            || metadataKey?.type !== "secret"
            || metadataKey?.algorithm?.name !== "AES-GCM"
            || metadataKey.algorithm.length !== 256
            || metadataKey.extractable !== false
            || !metadataKey.usages?.includes("decrypt")) deny();
          assertLive();
          // Never decrypt the caller-supplied or cached rows: re-read the
          // complete owner/witness/CAS signed page set at the exact pinned
          // sequence and digest. A new head requires a NEW offline anchor.
          const current = await writer.readAll();
          assertLive();
          if (current.head.sequence !== state.head.sequence
            || !equal(bytes(current.head.digest, 32),
              from64(state.head.digest, 32))
            || current.rows.length !== state.snapshot.rows.length) deny();
          const entries = [];
          for (const row of current.rows) {
            assertLive();
            const name = await catalog.openMetadata({
              scope: trust.signedDeviceGrant, objectId: row.object_id,
              revision: row.revision, epoch: row.epoch, metadataKey,
              ciphertext: bytes(row.metadata_ciphertext, 284),
            });
            assertLive();
            entries.push(Object.freeze({ objectId: row.object_id,
              revision: row.revision, epoch: row.epoch,
              name: name === TRASH_NAME ? null : name,
              logicalTrashCandidate: name === TRASH_NAME }));
          }
          assertLive();
          // One bad entry/key invalidates the ENTIRE list; no partial results.
          return Object.freeze({ head: Object.freeze({ ...state.head }),
            entries: Object.freeze(entries),
            plaintextSentToServer: false, independentlySignedCatalog: true,
            authorizesMutation: false });
        } catch (_) { deny(); }
      }
      async function commitVersion(inputVersion, internalTrash = false,
        internalRestore = false, predecessorMetadataKey = null,
        restoreAdmission = null) {
        let journalId = null, phase = "none", sealed = null;
        try {
          exact(inputVersion, ["previous", "objectId", "expectedRevision",
            "revision", "epoch", "ciphertext", "name", "metadataKey"]);
          // Snapshot caller scalars before the first asynchronous signature.
          // A moving UI selection must never redirect the authorized PUT.
          inputVersion = { ...inputVersion };
          if (usedMutation || (internalRestore && typeof restoreAdmission !== "function")
            || (!internalRestore && restoreAdmission !== null)) deny();
          if (internalRestore) restoreAdmission();
          const base = tracked.get(inputVersion.previous);
          if (!base || base.owner !== writer || latest !== inputVersion.previous) deny();
          if (inputVersion.expectedRevision !== null
            && (!Number.isSafeInteger(inputVersion.expectedRevision)
              || inputVersion.expectedRevision < 1)) deny();
          const expectedRevision = inputVersion.expectedRevision;
          if (inputVersion.revision !== (expectedRevision === null ? 1 : expectedRevision + 1)
            || !Number.isSafeInteger(inputVersion.epoch)
            || inputVersion.epoch !== trust.pinnedOwnerHead.epoch) deny();
          if (typeof inputVersion.name !== "string" || !inputVersion.name
            || inputVersion.name.length > 220) deny();
          if ((inputVersion.name === TRASH_NAME) !== (internalTrash === true)) deny();
          sealed = bytes(inputVersion.ciphertext, 16, MAX);
          if (typeof inputVersion.objectId !== "string"
            || !/^[A-Za-z0-9_-]{22}$/.test(inputVersion.objectId)) deny();
          from64(inputVersion.objectId, 16);
          const known = base.snapshot.rows.filter((item) => item.object_id === inputVersion.objectId);
          const latestRevision = known.length ? Math.max(...known.map((item) => item.revision)) : null;
          if (latestRevision !== expectedRevision) deny();
          assertLive();
          const fresh = await writer.readAll();
          if (fresh.head.sequence !== base.head.sequence
            || !equal(bytes(fresh.head.digest, 32), from64(base.head.digest, 32))) deny();
          if (expectedRevision !== null) {
            // An ordinary append cannot turn a logical tombstone back into a
            // visible file. Only the privately authorized restore path may
            // issue that transition. A changed/unknown old metadata key also
            // fails closed instead of treating ciphertext as "not trash".
            metadataKey(inputVersion.metadataKey);
            if (internalRestore) readablePredecessorMetadataKey(predecessorMetadataKey);
            const parent = fresh.rows.find((row) => row.object_id === inputVersion.objectId
              && row.revision === expectedRevision);
            if (!parent) deny();
            const parentName = await catalog.openMetadata({
              scope: trust.signedDeviceGrant, objectId: inputVersion.objectId,
              revision: parent.revision, epoch: parent.epoch,
              metadataKey: internalRestore ? predecessorMetadataKey : inputVersion.metadataKey,
              ciphertext: bytes(parent.metadata_ciphertext, 284) });
            assertLive();
            if ((parentName === TRASH_NAME) !== (internalRestore === true)) deny();
          } else if (internalRestore) deny();
          const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", sealed));
          const root = await roots.computeCiphertextRoot([sealed]);
          // Durable, signer-authenticated intent BEFORE the external PUT.
          if (internalRestore) restoreAdmission();
          journalId = await writer.prepareIntent([{ objectId: inputVersion.objectId,
            revision: inputVersion.revision, epoch: inputVersion.epoch, ciphertext: sealed }],
          { sequence: base.head.sequence, digest: from64(base.head.digest, 32) });
          assertLive();
          const scope = Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
            .map((key) => [key, trust.signedDeviceGrant[key]]));
          const signing = { signerKey: trust.devicePrivateKey, scope,
            deviceId: trust.signedDeviceGrant.device_id,
            manifestRevision: trust.pinnedOwnerHead.revision,
            manifestDigest: bytes(trust.pinnedOwnerHead.digest, 32),
            epoch: inputVersion.epoch, nowSeconds: trust.nowSeconds() };
          const guardedFetch = async (url, options) => {
            assertLive();
            const csrf = trust.csrfToken();
            if (typeof csrf !== "string" || !csrf || csrf.length > 512) deny();
            const response = await trust.fetchImpl(url, { ...options,
              headers: { ...options.headers, "x-csrf-token": csrf } });
            assertLive();
            return response;
          };
          const put = await http.signProtectedContentOperation({ ...signing,
            operation: "put", objectId: inputVersion.objectId,
            expectedObjectRevision: expectedRevision, ciphertext: sealed });
          assertLive();
          phase = "put";
          if (internalRestore) restoreAdmission();
          // One and only one signed PUT, regardless of timeout/lost ACK.
          try { await http.postProtectedCiphertextPut({ origin: trust.origin,
            request: put, fetchImpl: guardedFetch }); } catch (_) { /* exact GET below */ }
          assertLive();
          const get = await http.signProtectedContentOperation({ ...signing,
            nowSeconds: trust.nowSeconds(), operation: "get", objectId: inputVersion.objectId,
            expectedObjectRevision: inputVersion.revision,
            expectedCiphertextDigest: digest, ciphertext: null });
          const read = await http.postProtectedCiphertextBackupRead({ origin: trust.origin,
            request: get, fetchImpl: guardedFetch,
            expectedObjectRevision: inputVersion.revision,
            expectedEpoch: inputVersion.epoch, expectedRoot: root });
          assertLive();
          if (read.ciphertextBase64 !== b64(sealed)
            || read.integrityMatchesPinnedRoot !== true) deny();
          phase = "commit";
          if (internalRestore) restoreAdmission();
          // Metadata name/CEK exist only in local memory. The writer seals the
          // filename as AES-GCM (284 bytes) before signed catalog POST.
          const receipt = await writer.commit([{ objectId: inputVersion.objectId,
            revision: inputVersion.revision, epoch: inputVersion.epoch,
            ciphertext: sealed, name: inputVersion.name,
            metadataKey: inputVersion.metadataKey }], journalId,
          { retainPendingIntent: true,
            ...(internalRestore ? { beforeCasAdmission: restoreAdmission } : {}) });
          assertLive();
          if (receipt.verifiedSignedReadback !== true) deny();
          if (internalTrash) {
            // A catalog CAS receipt is not by itself a tombstone proof. Before
            // clearing the sole signed pending intent, independently re-open
            // the committed AEAD statement and owner-signed signer grant.
            const current = remember(await writer.readAll());
            assertLive();
            const checked = await readTrash({ previous: current,
              objectId: inputVersion.objectId, metadataKey: inputVersion.metadataKey });
            if (checked.state !== "trashed"
              || checked.revision !== inputVersion.revision
              || checked.signedByAuthorizedDevice !== true) deny();
          }
          if (await writer.confirmPendingIntent(journalId, receipt) !== true) deny();
          assertLive();
          return Object.freeze({ sequence: receipt.sequence, digest: receipt.digest,
            journalClearedAfterSignedProof: true,
            plaintextMetadataExposed: false, productionDurabilityProven: false });
        } catch (_) {
          if (phase !== "none") {
            const error = new Error(phase === "put"
              ? "ZK_OPAQUE_DELTA_PUT_UNCERTAIN" : "ZK_OPAQUE_DELTA_COMMIT_UNCERTAIN");
            error.code = error.message;
            error.outcome = Object.freeze({ journalId, retrySafe: false,
              ciphertextPutMayHaveCommitted: true, catalogMayHaveCommitted: phase === "commit" });
            throw error;
          }
          deny();
        } finally {
          // The signed journal survives failures. Even the owning device may
          // never silently resubmit an uncertain immutable PUT/CAS.
          if (journalId !== null) usedMutation = true;
          sealed?.fill(0);
        }
      }
      async function trashVersion(inputTrash) {
        let ciphertext = null;
        try {
          exact(inputTrash, ["previous", "objectId", "expectedRevision", "metadataKey"]);
          const state = tracked.get(inputTrash.previous);
          if (!state || state.owner !== writer || latest !== inputTrash.previous
            || usedMutation || !Number.isSafeInteger(inputTrash.expectedRevision)
            || inputTrash.expectedRevision < 1) deny();
          const objectId = inputTrash.objectId;
          if (typeof objectId !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(objectId)) deny();
          from64(objectId, 16);
          const rows = state.snapshot.rows.filter((row) => row.object_id === objectId);
          const parent = rows.find((row) => row.revision === inputTrash.expectedRevision);
          if (!parent || rows.some((row) => row.revision > parent.revision)
            || !metadataKey(inputTrash.metadataKey)) deny();
          assertLive();
          const signed = await writer.readAll();
          assertLive();
          if (signed.head.sequence !== state.head.sequence
            || !equal(bytes(signed.head.digest, 32), from64(state.head.digest, 32))
            || signed.rows.length !== state.snapshot.rows.length) deny();
          const signedParent = signed.rows.find((row) => row.object_id === objectId
            && row.revision === parent.revision);
          if (!signedParent || !equal(bytes(signedParent.ciphertext_digest, 32),
            bytes(parent.ciphertext_digest, 32))
            || !equal(bytes(signedParent.metadata_ciphertext, 284),
              bytes(parent.metadata_ciphertext, 284))) deny();
          // The owner's local key must authenticate the predecessor metadata;
          // a duplicate tombstone cannot be mistaken for a live file.
          const priorName = await catalog.openMetadata({ scope: trust.signedDeviceGrant,
            objectId, revision: parent.revision, epoch: parent.epoch,
            metadataKey: inputTrash.metadataKey,
            ciphertext: bytes(parent.metadata_ciphertext, 284) });
          assertLive();
          if (priorName === TRASH_NAME) deny();
          const scope = scopeFor(trust.signedDeviceGrant);
          const statement = { format: TRASH_TYPE, ...scope,
            deviceId: trust.signedDeviceGrant.device_id, objectId,
            parentRevision: parent.revision, parentEpoch: parent.epoch,
            parentDigest: b64(bytes(parent.ciphertext_digest, 32)),
            parentMetadataDigest: b64(new Uint8Array(await crypto.subtle.digest("SHA-256",
              bytes(parent.metadata_ciphertext, 284)))),
            revision: parent.revision + 1, epoch: trust.pinnedOwnerHead.epoch,
            previousSequence: state.head.sequence, previousDigest: state.head.digest,
            ownerRevision: trust.pinnedOwnerHead.revision,
            ownerDigest: b64(bytes(trust.pinnedOwnerHead.digest, 32)),
            nonce: b64(crypto.getRandomValues(new Uint8Array(32))),
            issuedAt: trust.nowSeconds() };
          ciphertext = await sealTrash(statement, trust.devicePrivateKey,
            inputTrash.metadataKey);
          assertLive();
          const result = await commitVersion({ previous: inputTrash.previous,
            objectId, expectedRevision: parent.revision, revision: statement.revision,
            epoch: statement.epoch, ciphertext, name: TRASH_NAME,
            metadataKey: inputTrash.metadataKey }, true);
          return Object.freeze({ ...result, objectId, revision: statement.revision,
            state: "trashed", originalHistoryPreserved: true,
            serverPlaintextExposed: false, tombstoneSignedAndSealed: true });
        } catch (error) {
          if (error?.outcome) throw error; // Do not erase uncertain PUT/CAS.
          deny();
        } finally { ciphertext?.fill(0); }
      }
      async function readTrash(inputRead) {
        let clear = null;
        try {
          const historicalKeys = Object.hasOwn(inputRead || {}, "historicalMetadataKeys");
          exact(inputRead, historicalKeys
            ? ["previous", "objectId", "historicalMetadataKeys"]
            : ["previous", "objectId", "metadataKey"]);
          const state = tracked.get(inputRead.previous);
          if (!state || state.owner !== writer || latest !== inputRead.previous) deny();
          const signed = await writer.readAll();
          assertLive();
          if (signed.head.sequence !== state.head.sequence
            || !equal(bytes(signed.head.digest, 32), from64(state.head.digest, 32))) deny();
          const rows = signed.rows.filter((row) => row.object_id === inputRead.objectId);
          if (rows.length < 2) deny();
          const newest = rows[rows.length - 1], prior = rows[rows.length - 2];
          const historical = newest.epoch !== trust.pinnedOwnerHead.epoch;
          if (newest.revision !== prior.revision + 1
            || newest.epoch > trust.pinnedOwnerHead.epoch
            || historical !== historicalKeys) deny();
          const selectedKey = historical
            ? readOnlyEpochMetadataKey(inputRead.historicalMetadataKeys, newest.epoch)
            : metadataKey(inputRead.metadataKey);
          const stateName = await catalog.openMetadata({ scope: trust.signedDeviceGrant,
            objectId: newest.object_id, revision: newest.revision, epoch: newest.epoch,
            metadataKey: selectedKey,
            ciphertext: bytes(newest.metadata_ciphertext, 284) });
          if (stateName !== TRASH_NAME) deny();
          const fetched = await writer.readVerifiedCiphertext(signed,
            newest.object_id, newest.revision);
          assertLive();
          const envelope = from64(fetched.ciphertextBase64, 28, MAX);
          clear = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM",
            iv: envelope.slice(0, 12), additionalData: trashAad(scopeFor(trust.signedDeviceGrant),
              newest.object_id, newest.revision, newest.epoch), tagLength: 128 },
          selectedKey, envelope.slice(12)));
          const parsed = JSON.parse(td.decode(clear));
          exact(parsed, ["statement", "signature"]);
          const statement = parsed.statement;
          exact(statement, ["format", "account_id", "compartment_id", "keyring_id",
            "deviceId", "objectId", "parentRevision", "parentEpoch", "parentDigest",
            "parentMetadataDigest", "revision", "epoch", "previousSequence",
            "previousDigest", "ownerRevision", "ownerDigest", "nonce", "issuedAt"]);
          const scope = scopeFor(trust.signedDeviceGrant);
          if (!Number.isSafeInteger(statement.previousSequence)
            || statement.previousSequence < 0
            || statement.previousSequence >= state.head.sequence) deny();
          const signedTombstoneHead = await writer.readSignedHistoricalHead(signed,
            statement.previousSequence + 1, { objectId: newest.object_id,
              revision: newest.revision, epoch: newest.epoch,
              ciphertextDigest: newest.ciphertext_digest,
              metadataCiphertext: newest.metadata_ciphertext });
          assertLive();
          if (statement.format !== TRASH_TYPE
            || Object.keys(scope).some((key) => statement[key] !== scope[key])
            || statement.objectId !== newest.object_id
            || statement.parentRevision !== prior.revision
            || statement.parentEpoch !== prior.epoch
            || statement.parentDigest !== b64(bytes(prior.ciphertext_digest, 32))
            || statement.parentMetadataDigest !== b64(new Uint8Array(await crypto.subtle.digest(
              "SHA-256", bytes(prior.metadata_ciphertext, 284))))
            || statement.revision !== newest.revision || statement.epoch !== newest.epoch
            || signedTombstoneHead.exactHistoricalAuthorityVerified !== true
            || signedTombstoneHead.epoch !== newest.epoch
            || signedTombstoneHead.manifestRevision !== statement.ownerRevision
            || signedTombstoneHead.manifestDigest !== statement.ownerDigest
            || statement.previousDigest !== signedTombstoneHead.previousDigest
            || (historical && statement.ownerRevision >= trust.pinnedOwnerHead.revision)
            || (!historical && (statement.ownerRevision !== trust.pinnedOwnerHead.revision
              || statement.ownerDigest !== b64(bytes(trust.pinnedOwnerHead.digest, 32))))
            || !Number.isSafeInteger(statement.issuedAt)
            || !Number.isSafeInteger(signedTombstoneHead.issuedAt)
            || Math.abs(statement.issuedAt - signedTombstoneHead.issuedAt) > 60
            || statement.issuedAt > trust.nowSeconds() + 30
            || from64(statement.nonce, 32).length !== 32
            || from64(statement.previousDigest, 32).length !== 32) deny();
          const pub = historical
            ? await writer.verifyHistoricalSigner(statement.deviceId, newest.epoch,
              statement.ownerRevision, from64(statement.ownerDigest, 32))
            : await writer.verifyAuthorizedSigner(statement.deviceId, newest.epoch);
          if (!await crypto.subtle.verify("Ed25519", pub,
            from64(parsed.signature, 64),
            new Uint8Array([...TRASH_DOMAIN, ...te.encode(JSON.stringify(statement))]))) deny();
          const reconfirm = await writer.readAll();
          assertLive();
          if (reconfirm.head.sequence !== signed.head.sequence
            || !equal(bytes(reconfirm.head.digest, 32), bytes(signed.head.digest, 32))) deny();
          return Object.freeze({ state: "trashed", objectId: newest.object_id,
            revision: newest.revision, predecessorRevision: prior.revision,
            retainedHistoricalVersions: rows.length - 1, originalHistoryPreserved: true,
            signedByAuthorizedDevice: true, serverPlaintextExposed: false,
            historicEpochVerifiedReadOnly: historical, mutationAuthorized: false,
            ownerApprovedRekeyRequired: historical });
        } catch (_) { deny(); } finally { clear?.fill(0); }
      }
      async function restoreVersion(inputRestore) {
        let plaintext = null, sealed = null, nextCekBytes = null, nextMetadataBytes = null;
        try {
          const crossing = Object.hasOwn(inputRestore || {}, "ownerRekeyGrant");
          exact(inputRestore, ["previous", "objectId", "metadataKey",
            "sourceMetadata", "sourceCek", ...(crossing ? [
              "ownerRekeyGrant", "currentEpochCekRaw", "currentEpochMetadataKeyRaw",
              "tombstoneMetadataKey",
            ] : [])]);
          if (crossing) historicalSourceMetadataKey(inputRestore.metadataKey);
          else metadataKey(inputRestore.metadataKey);
          const currentTombstoneKey = crossing
            ? metadataKey(inputRestore.tombstoneMetadataKey) : inputRestore.metadataKey;
          if (usedMutation || !fileCek(inputRestore.sourceCek)
            || typeof fileContent?.decryptFile !== "function"
            || typeof fileContent?.encryptFileWithParent !== "function") deny();
          // Copy the signed grant before any await; a caller may not change
          // nonce, expiry or anchored digests after signature validation.
          if (crossing) exact(inputRestore.ownerRekeyGrant,
            [...REKEY_FIELDS, "signature"]);
          const rekeyGrant = crossing ? Object.freeze({ ...inputRestore.ownerRekeyGrant }) : null;
          const restoreAdmission = () => {
            assertLive();
            if (crossing && (trust.nowSeconds() > rekeyGrant.expiresAt
              || rekeyGrant.issuedAt > trust.nowSeconds() + 30
              || trust.signedDeviceGrant.current_epoch !== trust.pinnedOwnerHead.epoch
              || trust.signedDeviceGrant.revoked_at_epoch !== null)) deny();
            return true;
          };
          const state = tracked.get(inputRestore.previous);
          if (!state || state.owner !== writer || latest !== inputRestore.previous
            || inputRestore.previous.head.sequence !== state.head.sequence
            || inputRestore.previous.head.digest !== state.head.digest) deny();
          const objectId = inputRestore.objectId;
          if (typeof objectId !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(objectId)) deny();
          from64(objectId, 16);
          // The opaque marker is not an authoritative server trash flag. Its
          // Ed25519 author, predecessor digest and independent CAS predecessor
          // must be proven before recovering any historical plaintext.
          const marker = await readTrash({ previous: inputRestore.previous,
            objectId, metadataKey: currentTombstoneKey });
          assertLive();
          const signed = await writer.readAll();
          assertLive();
          if (signed.head.sequence !== state.head.sequence
            || !equal(bytes(signed.head.digest, 32), from64(state.head.digest, 32))
            || signed.rows.length !== state.snapshot.rows.length) deny();
          const rows = signed.rows.filter((row) => row.object_id === objectId);
          if (rows.length < 2) deny();
          const prior = rows[rows.length - 2], tombstone = rows[rows.length - 1];
          if (prior.revision !== marker.predecessorRevision
            || tombstone.revision !== marker.revision
            || tombstone.revision !== prior.revision + 1
            || tombstone.epoch !== trust.pinnedOwnerHead.epoch
            || (prior.epoch !== tombstone.epoch) !== crossing) deny();
          let targetCek = inputRestore.sourceCek, targetMetadataKey = inputRestore.metadataKey;
          if (crossing) {
            // Current owner grant and witness/CAS history are independently
            // authenticated by the actual browser writer.readAll above.
            // Accept a historical tombstone author ONLY when it is the same
            // currently owner-granted device. This excludes unsigned extra
            // signerGrants supplied by an untrusted caller (readTrash P2).
            if (trust.signedDeviceGrant.revoked_at_epoch !== null
              || trust.signedDeviceGrant.current_epoch !== trust.pinnedOwnerHead.epoch
              || prior.epoch >= tombstone.epoch) deny();
            const tombstoneGet = await writer.readVerifiedCiphertext(signed,
              objectId, tombstone.revision);
            assertLive();
            const rawTombstone = from64(tombstoneGet.ciphertextBase64, 28, MAX);
            if (tombstoneGet.ciphertextDigestBase64 !== b64(bytes(tombstone.ciphertext_digest, 32))
              || !equal(new Uint8Array(await crypto.subtle.digest("SHA-256",
                rawTombstone)), bytes(tombstone.ciphertext_digest, 32))) deny();
            let clearTombstone = null;
            try {
              clearTombstone = new Uint8Array(await crypto.subtle.decrypt({
                name: "AES-GCM", iv: rawTombstone.slice(0, 12),
                additionalData: trashAad(scopeFor(trust.signedDeviceGrant),
                  objectId, tombstone.revision, tombstone.epoch), tagLength: 128,
              }, currentTombstoneKey, rawTombstone.slice(12)));
              const parsed = JSON.parse(td.decode(clearTombstone));
              exact(parsed, ["statement", "signature"]);
              if (parsed.statement?.deviceId !== trust.signedDeviceGrant.device_id) deny();
              const trustedSigner = await crypto.subtle.importKey("raw",
                from64(trust.signedDeviceGrant.authorization_public_key, 32),
                "Ed25519", false, ["verify"]);
              if (!await crypto.subtle.verify("Ed25519", trustedSigner,
                from64(parsed.signature, 64),
                new Uint8Array([...TRASH_DOMAIN,
                  ...te.encode(JSON.stringify(parsed.statement))]))) deny();
            } finally { clearTombstone?.fill(0); }
            nextCekBytes = bytes(inputRestore.currentEpochCekRaw, 32);
            nextMetadataBytes = bytes(inputRestore.currentEpochMetadataKeyRaw, 32);
            if (equal(nextCekBytes, nextMetadataBytes)) deny();
            await verifyEpochRekeyGrant(rekeyGrant, prior,
              tombstone, state, trust, nextCekBytes, nextMetadataBytes);
            restoreAdmission();
            // The current tombstone key must be cryptographically distinct
            // from the original historical metadata key (revocation boundary).
            let reusedOldMetadataKey = false;
            try {
              await catalog.openMetadata({ scope: trust.signedDeviceGrant,
                objectId, revision: prior.revision, epoch: prior.epoch,
                metadataKey: currentTombstoneKey,
                ciphertext: bytes(prior.metadata_ciphertext, 284) });
              reusedOldMetadataKey = true;
            } catch (_) { /* the epoch keys must differ */ }
            if (reusedOldMetadataKey) deny();
            targetCek = await fileContent.importFileCek(nextCekBytes);
            targetMetadataKey = await crypto.subtle.importKey("raw",
              nextMetadataBytes, { name: "AES-GCM", length: 256 },
              false, ["encrypt", "decrypt"]);
          }
          const original = restoredSourceMetadata(inputRestore.sourceMetadata,
            scopeFor(trust.signedDeviceGrant), objectId, prior.epoch);
          const originalName = await catalog.openMetadata({
            scope: trust.signedDeviceGrant, objectId, revision: prior.revision,
            epoch: prior.epoch, metadataKey: inputRestore.metadataKey,
            ciphertext: bytes(prior.metadata_ciphertext, 284) });
          assertLive();
          if (originalName === TRASH_NAME) deny();
          const fetched = await writer.readVerifiedCiphertext(signed,
            objectId, prior.revision);
          assertLive();
          if (fetched.objectId !== objectId || fetched.revision !== prior.revision
            || fetched.epoch !== prior.epoch
            || fetched.ciphertextDigestBase64 !== b64(bytes(prior.ciphertext_digest, 32))) deny();
          const previousCiphertext = from64(fetched.ciphertextBase64, 16, MAX);
          if (!equal(new Uint8Array(await crypto.subtle.digest("SHA-256",
            previousCiphertext)), bytes(prior.ciphertext_digest, 32))) deny();
          plaintext = await fileContent.decryptFile({ cek: inputRestore.sourceCek,
            metadata: original, envelopeBytes: previousCiphertext });
          assertLive();
          if (plaintext.name !== originalName
            || plaintext.authorizesRelease === true) deny();
          if (crossing) {
            // A raw current-epoch "rekey" that equals the old CEK would leak
            // the new revision to devices revoked by the rotation.
            let sameKey = false;
            try {
              const duplicate = await fileContent.decryptFile({ cek: targetCek,
                metadata: original, envelopeBytes: previousCiphertext });
              duplicate.data.fill(0);
              sameKey = true;
            } catch (_) { /* different key is mandatory */ }
            if (sameKey) deny();
            let sameMetadataKey = false;
            try {
              await catalog.openMetadata({ scope: trust.signedDeviceGrant,
                objectId, revision: prior.revision, epoch: prior.epoch,
                metadataKey: targetMetadataKey,
                ciphertext: bytes(prior.metadata_ciphertext, 284) });
              sameMetadataKey = true;
            } catch (_) { /* a NEW current-epoch metadata key must not decrypt the old name */ }
            if (sameMetadataKey) deny();
          }
          const next = { ...original,
            version_id: b64(crypto.getRandomValues(new Uint8Array(16))),
            // Opaque tombstones do not contain a file-content version_id.
            // The last actual file is the authenticated content ancestor.
            parent_version_id: original.version_id,
            epoch: trust.pinnedOwnerHead.epoch };
          sealed = await fileContent.encryptFileWithParent({
            cek: targetCek, metadata: next, name: plaintext.name,
            mediaType: plaintext.mediaType,
            parentFolderId: plaintext.parentFolderId ?? null,
            data: plaintext.data });
          plaintext.data.fill(0); plaintext = null;
          assertLive();
          // This path deliberately reuses the independently held original CEK.
          // No new unrecoverable key is minted without signed archive custody.
          const result = await commitVersion({ previous: inputRestore.previous,
            objectId, expectedRevision: tombstone.revision,
            revision: tombstone.revision + 1, epoch: next.epoch,
            ciphertext: sealed, name: originalName,
            metadataKey: targetMetadataKey }, false, true,
          currentTombstoneKey, restoreAdmission);
          return Object.freeze({ ...result, objectId, revision: tombstone.revision + 1,
            state: "restored", predecessorRevision: prior.revision,
            tombstoneRevision: tombstone.revision, originalHistoryPreserved: true,
            sourceCiphertextVerifiedBySignedGet: true,
            tombstoneSignedAndVerified: true, originalCekReused: !crossing,
            independentlyOwnerSignedEpochRekey: crossing,
            serverPlaintextExposed: false, physicalDeletionAuthorized: false });
        } catch (error) {
          if (error?.outcome) throw error;
          deny();
        } finally {
          plaintext?.data?.fill(0);
          sealed?.fill(0);
          nextCekBytes?.fill(0);
          nextMetadataBytes?.fill(0);
        }
      }
      return Object.freeze({ readCurrent, pullDelta, readPrivateListing,
        commitVersion: (value) => commitVersion(value, false), trashVersion, readTrash, restoreVersion });
    }
    return Object.freeze({ createClient });
  }));
