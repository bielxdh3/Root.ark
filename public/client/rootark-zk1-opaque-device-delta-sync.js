(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-browser-opaque-catalog-commit"),
      require("./rootark-zk1-protected-http-client"),
      require("./rootark-zk1-ciphertext-chunk-root"));
  } else {
    root.RootarkZk1OpaqueDeviceDeltaSync = factory(root.crypto,
      root.RootarkZk1BrowserOpaqueCatalogCommit,
      root.RootarkZk1ProtectedHttpClient, root.RootarkZk1CiphertextRoot);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (crypto, catalog, http, roots) {
    "use strict";
    // Owner-authorized, additive ZK1 opaque-catalog sync. No generic sync
    // engine, server-supplied trust pin, plaintext filename, CEK or local
    // filesystem path crosses the wire. A delta covers ONE signed CAS successor
    // only; an unproven gap/fork is not interpreted as a set of changes.
    const MAX = 4 * 1024 * 1024;
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
              revision: row.revision, epoch: row.epoch, name }));
          }
          assertLive();
          // One bad entry/key invalidates the ENTIRE list; no partial results.
          return Object.freeze({ head: Object.freeze({ ...state.head }),
            entries: Object.freeze(entries),
            plaintextSentToServer: false, independentlySignedCatalog: true,
            authorizesMutation: false });
        } catch (_) { deny(); }
      }
      async function commitVersion(inputVersion) {
        let journalId = null, phase = "none", sealed = null;
        try {
          exact(inputVersion, ["previous", "objectId", "expectedRevision",
            "revision", "epoch", "ciphertext", "name", "metadataKey"]);
          // Snapshot caller scalars before the first asynchronous signature.
          // A moving UI selection must never redirect the authorized PUT.
          inputVersion = { ...inputVersion };
          if (usedMutation) deny();
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
          const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", sealed));
          const root = await roots.computeCiphertextRoot([sealed]);
          // Durable, signer-authenticated intent BEFORE the external PUT.
          journalId = await writer.prepareIntent([{ objectId: inputVersion.objectId,
            revision: inputVersion.revision, epoch: inputVersion.epoch, ciphertext: sealed }]);
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
          // Metadata name/CEK exist only in local memory. The writer seals the
          // filename as AES-GCM (284 bytes) before signed catalog POST.
          const receipt = await writer.commit([{ objectId: inputVersion.objectId,
            revision: inputVersion.revision, epoch: inputVersion.epoch,
            ciphertext: sealed, name: inputVersion.name,
            metadataKey: inputVersion.metadataKey }], journalId,
          { retainPendingIntent: true });
          assertLive();
          if (receipt.verifiedSignedReadback !== true) deny();
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
      return Object.freeze({ readCurrent, pullDelta, readPrivateListing, commitVersion });
    }
    return Object.freeze({ createClient });
  }));
