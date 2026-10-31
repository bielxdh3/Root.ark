(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-normal-browser-content"),
      require("./rootark-zk1-normal-browser-trust-floor"),
      require("./rootark-zk1-owner-ciphertext-root-checkpoint"),
      require("./rootark-zk1-protected-http-client"),
      require("./rootark-zk1-persisted-portable-chunk-recovery"));
  } else {
    root.RootarkZk1PersistedBrowserRecovery = factory(root.crypto,
      root.RootarkZk1NormalBrowserContent, root.RootarkZk1NormalBrowserTrustFloor,
      root.RootarkZk1OwnerCiphertextRootCheckpoint,
      root.RootarkZk1ProtectedHttpClient,
      root.RootarkZk1PersistedPortableChunkRecovery);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (crypto, normal, floor, ownerRoots, http, persisted) {
    "use strict";

    // DEV opt-in: owner-pinned, local persisted chunk files + a REAL signed
    // protected HTTP readback. Neither response JSON nor portable archive
    // supplies a trusted owner head, root, public-key pin or recovery secret.
    // Not proof of remote fsync, source-chunk physical layout, or production I/O.
    const SCOPE = ["account_id", "compartment_id", "keyring_id"];
    const FIELDS = ["ownerPublicKey", "pinnedOwnerKeyHash",
      "independentOwnerSpkiSha256", "pinnedCurrentHead", "signedDeviceGrant",
      "ownerHistoryCheckpoint", "previousOwnerHistoryProof", "devicePublicKey",
      "devicePrivateKey", "origin", "fetchImpl", "nowSeconds", "bundle",
      "signedInventory", "expectedMetadata", "independentlyPinnedCiphertextRoot",
      "independentlyPinnedSourceChunkRoot", "ownerSignerKeyId", "ownerDeviceId",
      "ownerRootCheckpoint", "recoverySecret", "readChunk", "assertLive"];
    const META = [...SCOPE, "object_id", "version_id", "parent_version_id", "epoch", "kind"];
    function deny() { throw new Error("ZK_PERSISTED_BROWSER_RECOVERY_DENIED"); }
    function exact(raw, fields) {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(raw))
        || Reflect.ownKeys(raw).length !== fields.length
        || fields.some((name) => !Object.hasOwn(raw, name))) deny();
    }
    function bytes(value, size) {
      if (!((value instanceof ArrayBuffer) || ArrayBuffer.isView(value))
        || value.byteLength !== size) deny();
      return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
        : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + size));
    }
    function from64(value, maximum) {
      if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
        || value.length > Math.ceil(maximum * 4 / 3) + 4) deny();
      let text;
      try { text = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
      if (text.length < 1 || text.length > maximum) deny();
      const out = Uint8Array.from(text, (character) => character.charCodeAt(0));
      let roundtrip = "";
      for (const item of out) roundtrip += String.fromCharCode(item);
      if (btoa(roundtrip).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "") !== value) deny();
      return out;
    }
    function assertLive(callback) {
      if (typeof callback !== "function" || callback() !== undefined) deny();
    }
    async function recoverFromPinnedPersistedHttpGet(input) {
      let ciphertext, secret, recovered;
      try {
        exact(input, FIELDS);
        exact(input.expectedMetadata, META);
        if (!crypto?.subtle || !normal?.verifyOwnerGrant || !floor?.verifyExternalAnchor
          || !floor?.assertCurrent || !ownerRoots?.verifyOwnerCiphertextRootCheckpoint
          || !http?.postProtectedCiphertextBackupRead || !persisted?.recoverPersistedPortableChunks
          || typeof input.fetchImpl !== "function" || typeof input.readChunk !== "function") deny();
        const meta = { ...input.expectedMetadata };
        const grant = input.signedDeviceGrant;
        if (meta.kind !== "file" || input.bundle?.format !== "rootark-zk1-portable-file-recovery/v1"
          || !Number.isSafeInteger(input.nowSeconds) || input.nowSeconds < 1
          || meta.epoch !== input.pinnedCurrentHead?.epoch
          || SCOPE.some((name) => meta[name] !== grant?.[name])
          || input.bundle.objectRevision !== input.signedInventory?.objectRevision) deny();
        secret = bytes(input.recoverySecret, 32);
        const portableRoot = bytes(input.independentlyPinnedCiphertextRoot, 32);
        const nativeRoot = bytes(input.independentlyPinnedSourceChunkRoot, 32);
        const ownerPin = bytes(input.independentOwnerSpkiSha256, 32);
        assertLive(input.assertLive);
        const proof = await normal.verifyOwnerGrant({ ownerPublicKey: input.ownerPublicKey,
          pinnedOwnerKeyHash: input.pinnedOwnerKeyHash,
          pinnedCurrentHead: input.pinnedCurrentHead, signedDeviceGrant: grant,
          devicePublicKey: input.devicePublicKey, devicePrivateKey: input.devicePrivateKey });
        assertLive(input.assertLive);
        if (proof?.ownerGrantSignatureVerified !== true) deny();
        const anchor = { ownerPublicKey: input.ownerPublicKey,
          independentOwnerSpkiSha256: ownerPin,
          pinnedCurrentHead: input.pinnedCurrentHead,
          signedDeviceGrant: grant, ownerHistoryCheckpoint: input.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: input.previousOwnerHistoryProof };
        await floor.verifyExternalAnchor(anchor);
        assertLive(input.assertLive);
        if (typeof window === "object") await floor.assertCurrent(anchor);
        assertLive(input.assertLive);
        const rootProof = await ownerRoots.verifyOwnerCiphertextRootCheckpoint({
          checkpoint: input.ownerRootCheckpoint,
          ownerHistoryCheckpoint: input.ownerHistoryCheckpoint,
          previousHistoryProof: input.previousOwnerHistoryProof,
          pinnedOwner: { scope: Object.fromEntries(SCOPE.map((name) => [name, meta[name]])),
            deviceId: input.ownerDeviceId,
            signerKeyId: bytes(input.ownerSignerKeyId, 16), publicKey: input.ownerPublicKey },
          expected: { manifestRevision: input.pinnedCurrentHead.revision,
            manifestDigest: input.pinnedCurrentHead.digest,
            manifestEpoch: input.pinnedCurrentHead.epoch,
            objectId: meta.object_id, objectRevision: input.bundle.objectRevision,
            ciphertextEpoch: meta.epoch, ciphertextRoot: nativeRoot },
        });
        assertLive(input.assertLive);
        if (rootProof?.trustedOwnerSignatureVerified !== true
          || rootProof.manifestCheckpointVerified !== true
          || rootProof.authorizesRecovery !== false) deny();
        ciphertext = from64(input.bundle.ciphertextBase64, 4 * 1024 * 1024);
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ciphertext));
        assertLive(input.assertLive);
        const verifyCurrentHttpRead = async () => {
          const get = await http.signProtectedContentOperation({
            signerKey: input.devicePrivateKey,
            scope: Object.fromEntries(SCOPE.map((name) => [name, meta[name]])),
            deviceId: grant.device_id, manifestRevision: input.pinnedCurrentHead.revision,
            manifestDigest: input.pinnedCurrentHead.digest,
            epoch: input.pinnedCurrentHead.epoch, nowSeconds: input.nowSeconds,
            operation: "get", objectId: meta.object_id,
            expectedObjectRevision: input.bundle.objectRevision,
            expectedCiphertextDigest: digest, ciphertext: null,
          });
          assertLive(input.assertLive);
          await floor.verifyExternalAnchor(anchor);
          if (typeof window === "object") await floor.assertCurrent(anchor);
          assertLive(input.assertLive);
          // HTTP v1 commits to a single opaque envelope. Independently owner-
          // signed NATIVE segmentation is checked against the local chunks.
          const remote = await http.postProtectedCiphertextBackupRead({
            origin: input.origin, request: get, fetchImpl: input.fetchImpl,
            expectedObjectRevision: input.bundle.objectRevision,
            expectedEpoch: meta.epoch, expectedRoot: portableRoot,
          });
          assertLive(input.assertLive);
          if (remote?.ciphertextBase64 !== input.bundle.ciphertextBase64
            || remote.integrityMatchesPinnedRoot !== true
            || remote.durableBackupProven !== false) deny();
        };
        await verifyCurrentHttpRead();
        await floor.verifyExternalAnchor(anchor);
        if (typeof window === "object") await floor.assertCurrent(anchor);
        assertLive(input.assertLive);
        recovered = await persisted.recoverPersistedPortableChunks({
          bundle: input.bundle, signedInventory: input.signedInventory,
          expectedOwnerHead: input.pinnedCurrentHead,
          ownerPublicKey: input.ownerPublicKey,
          independentOwnerSpkiSha256: ownerPin, expectedMetadata: meta,
          independentlyPinnedCiphertextRoot: portableRoot,
          independentlyPinnedSourceChunkRoot: nativeRoot,
          recoverySecret: secret, readChunk: input.readChunk,
          assertLive: input.assertLive,
        });
        assertLive(input.assertLive);
        // An earlier GET cannot authorize plaintext after a later witness
        // revocation during asynchronous persisted chunk reads/decryption.
        // Re-sign with a fresh nonce and require actual server admission.
        await verifyCurrentHttpRead();
        assertLive(input.assertLive);
        if (recovered?.ownerSignatureVerified !== true
          || recovered.sourceChunkRootVerifiedAgainstIndependentPin !== true
          || recovered.authorizesProductionRestore !== false
          || recovered.independentRemoteDurabilityProven !== false) deny();
        return Object.freeze({ ...recovered,
          ownerRootSignatureVerified: true, protectedHttpReadbackVerified: true,
          sourceChunkPhysicalDurabilityProven: false,
          independentRemoteDurabilityProven: false, authorizesProductionRestore: false });
      } catch (_) { recovered?.data?.fill(0); deny(); }
      finally { ciphertext?.fill(0); secret?.fill(0); }
    }
    return Object.freeze({ recoverFromPinnedPersistedHttpGet });
  }));
