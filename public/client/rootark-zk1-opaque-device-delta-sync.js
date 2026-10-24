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
    const TRASH_NAME = "\uE000rootark-zk1-logical-trash/v1";
    const TRASH_TYPE = "rootark-zk1-opaque-logical-trash/v1";
    const TRASH_DOMAIN = new TextEncoder().encode("Root.ark/zk-1/opaque-logical-trash/v1\0");
    const TRASH_AAD = "Root.ark/zk-1/opaque-logical-trash-aead/v1\0";
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
    function trashAad(scope, objectId, revision, epoch) {
      return te.encode(TRASH_AAD + JSON.stringify({ ...scope, objectId, revision, epoch }));
    }
    function scopeFor(grant) {
      return Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
        .map((key) => [key, grant[key]]));
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
      async function commitVersion(inputVersion, internalTrash = false) {
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
          exact(inputRead, ["previous", "objectId", "metadataKey"]);
          const state = tracked.get(inputRead.previous);
          if (!state || state.owner !== writer || latest !== inputRead.previous
            || !metadataKey(inputRead.metadataKey)) deny();
          const signed = await writer.readAll();
          assertLive();
          if (signed.head.sequence !== state.head.sequence
            || !equal(bytes(signed.head.digest, 32), from64(state.head.digest, 32))) deny();
          const rows = signed.rows.filter((row) => row.object_id === inputRead.objectId);
          if (rows.length < 2) deny();
          const newest = rows[rows.length - 1], prior = rows[rows.length - 2];
          if (newest.revision !== prior.revision + 1
            || newest.epoch !== trust.pinnedOwnerHead.epoch) deny();
          const stateName = await catalog.openMetadata({ scope: trust.signedDeviceGrant,
            objectId: newest.object_id, revision: newest.revision, epoch: newest.epoch,
            metadataKey: inputRead.metadataKey,
            ciphertext: bytes(newest.metadata_ciphertext, 284) });
          if (stateName !== TRASH_NAME) deny();
          const fetched = await writer.readVerifiedCiphertext(signed,
            newest.object_id, newest.revision);
          assertLive();
          const envelope = from64(fetched.ciphertextBase64, 28, MAX);
          clear = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM",
            iv: envelope.slice(0, 12), additionalData: trashAad(scopeFor(trust.signedDeviceGrant),
              newest.object_id, newest.revision, newest.epoch), tagLength: 128 },
          inputRead.metadataKey, envelope.slice(12)));
          const parsed = JSON.parse(td.decode(clear));
          exact(parsed, ["statement", "signature"]);
          const statement = parsed.statement;
          exact(statement, ["format", "account_id", "compartment_id", "keyring_id",
            "deviceId", "objectId", "parentRevision", "parentEpoch", "parentDigest",
            "parentMetadataDigest", "revision", "epoch", "previousSequence",
            "previousDigest", "ownerRevision", "ownerDigest", "nonce", "issuedAt"]);
          const scope = scopeFor(trust.signedDeviceGrant);
          const signedParentHead = await writer.readVerifiedPredecessorDigest(signed);
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
            || statement.previousSequence !== state.head.sequence - 1
            || statement.previousDigest !== b64(signedParentHead)
            || statement.ownerRevision !== trust.pinnedOwnerHead.revision
            || statement.ownerDigest !== b64(bytes(trust.pinnedOwnerHead.digest, 32))
            || !Number.isSafeInteger(statement.issuedAt)
            || statement.issuedAt > trust.nowSeconds() + 30
            || from64(statement.nonce, 32).length !== 32
            || from64(statement.previousDigest, 32).length !== 32) deny();
          const signer = trust.signerGrants.find((grant) => grant.device_id === statement.deviceId
            && grant.revoked_at_epoch === null
            && grant.current_epoch === newest.epoch);
          if (!signer) deny();
          const pub = await crypto.subtle.importKey("raw",
            from64(signer.authorization_public_key, 32), "Ed25519", false, ["verify"]);
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
            signedByAuthorizedDevice: true, serverPlaintextExposed: false });
        } catch (_) { deny(); } finally { clear?.fill(0); }
      }
      return Object.freeze({ readCurrent, pullDelta, readPrivateListing,
        commitVersion: (value) => commitVersion(value, false), trashVersion, readTrash });
    }
    return Object.freeze({ createClient });
  }));
