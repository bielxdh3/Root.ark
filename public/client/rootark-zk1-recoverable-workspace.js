(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-normal-browser-content"),
      require("./rootark-zk1-normal-browser-trust-floor"),
      require("./rootark-zk1-portable-file-recovery"),
      require("./rootark-zk1-protected-http-client"),
      require("./rootark-zk1-browser-recovery-http"));
  } else {
    root.RootarkZk1RecoverableWorkspace = factory(root.crypto,
      root.RootarkZk1NormalBrowserContent, root.RootarkZk1NormalBrowserTrustFloor,
      root.RootarkZk1PortableFileRecovery, root.RootarkZk1ProtectedHttpClient,
      root.RootarkZk1BrowserRecoveryHttp);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (webCrypto, normal, floor, portable, http, recovery) {
    "use strict";

    // Development-only bridge. The secret and wrapped CEK never cross HTTP.
    // The exported bundle is NOT a trusted owner root: independent owner-signed
    // root history, a fresh owner grant, and local floor are required on restore.
    const scopeKeys = ["account_id", "compartment_id", "keyring_id"];
    const metaKeys = [...scopeKeys, "object_id", "version_id",
      "parent_version_id", "epoch", "kind"];
    const base = ["ownerPublicKey", "pinnedOwnerKeyHash",
      "independentOwnerSpkiSha256", "pinnedCurrentHead", "signedDeviceGrant",
      "ownerHistoryCheckpoint", "devicePublicKey", "devicePrivateKey",
      "origin", "fetchImpl", "nowSeconds"];
    const upload = [...base, "recoverySecret", "metadata", "name", "mediaType", "data"];
    const restore = [...base, "recoverySecret", "bundle", "expectedMetadata",
      "independentlyPinnedCiphertextRoot", "ownerSignerKeyId", "ownerDeviceId",
      "ownerRootCheckpoint", "previousOwnerHistoryProof"];
    const b64re = /^[A-Za-z0-9_-]+$/;
    function deny() { throw new Error("ZK_RECOVERABLE_WORKSPACE_DENIED"); }
    function exact(value, fields) {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
        || Reflect.ownKeys(value).length !== fields.length
        || fields.some((key) => !Object.hasOwn(value, key))) deny();
    }
    function raw(value, size) {
      if ((!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value))
        || value.byteLength !== size) deny();
      return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
        : new Uint8Array(value.buffer.slice(value.byteOffset,
          value.byteOffset + value.byteLength));
    }
    function decode(value, size) {
      if (typeof value !== "string" || !b64re.test(value)
        || value.length > Math.ceil(size * 4 / 3) + 4) deny();
      let text;
      try { text = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
      const data = Uint8Array.from(text, (char) => char.charCodeAt(0));
      if (data.length !== size) deny();
      return data;
    }
    function anchor(input) {
      return { ownerPublicKey: input.ownerPublicKey,
        independentOwnerSpkiSha256: input.independentOwnerSpkiSha256,
        pinnedCurrentHead: input.pinnedCurrentHead,
        signedDeviceGrant: input.signedDeviceGrant,
        ownerHistoryCheckpoint: input.ownerHistoryCheckpoint,
        ...(Object.hasOwn(input, "previousOwnerHistoryProof")
          ? { previousOwnerHistoryProof: input.previousOwnerHistoryProof } : {}) };
    }
    async function validate(input, metadata) {
      exact(metadata, metaKeys);
      const grant = input.signedDeviceGrant;
      if (scopeKeys.some((key) => metadata[key] !== grant?.[key])
        || !Number.isSafeInteger(metadata.epoch) || metadata.epoch < 1
        || metadata.epoch > input.pinnedCurrentHead?.epoch || metadata.kind !== "file"
        || !Number.isSafeInteger(input.nowSeconds) || input.nowSeconds < 0) deny();
      const proof = await normal.verifyOwnerGrant({
        ownerPublicKey: input.ownerPublicKey,
        pinnedOwnerKeyHash: input.pinnedOwnerKeyHash,
        pinnedCurrentHead: input.pinnedCurrentHead,
        signedDeviceGrant: grant,
        devicePublicKey: input.devicePublicKey,
        devicePrivateKey: input.devicePrivateKey,
      });
      if (proof.ownerGrantSignatureVerified !== true) deny();
      await floor.verifyExternalAnchor(anchor(input));
      // Node fixtures have no IndexedDB; a real browser MUST have an already
      // offline-provisioned monotonic floor before sending protected requests.
      if (typeof window === "object") await floor.assertCurrent(anchor(input));
    }
    function signer(input) {
      const grant = input.signedDeviceGrant;
      return { signerKey: input.devicePrivateKey,
        scope: Object.fromEntries(scopeKeys.map((key) => [key, grant[key]])),
        deviceId: grant.device_id, manifestRevision: input.pinnedCurrentHead.revision,
        manifestDigest: input.pinnedCurrentHead.digest,
        epoch: input.pinnedCurrentHead.epoch, nowSeconds: input.nowSeconds };
    }
    async function createRecoverableProtectedFile(input) {
      let secret, opened, ciphertext;
      try {
        exact(input, Object.hasOwn(input || {}, "previousOwnerHistoryProof")
          ? [...upload, "previousOwnerHistoryProof"] : upload);
        secret = raw(input.recoverySecret, 32);
        await validate(input, input.metadata);
        if (input.metadata.epoch !== input.pinnedCurrentHead.epoch
          || input.metadata.parent_version_id !== null) deny();
        const bundle = await portable.sealForUserHeldSecret({
          recoverySecret: secret, metadata: input.metadata,
          name: input.name, mediaType: input.mediaType,
          data: input.data, objectRevision: 1,
        });
        const ciphertextLength = Math.floor(bundle.ciphertextBase64.length * 3 / 4);
        if (ciphertextLength < 16 || ciphertextLength > 4 * 1024 * 1024) deny();
        ciphertext = decode(bundle.ciphertextBase64, ciphertextLength);
        const digest = raw(await webCrypto.subtle.digest("SHA-256", ciphertext), 32);
        const expectedDigest = decode(bundle.ciphertextSha256, 32);
        if (digest.some((byte, index) => byte !== expectedDigest[index])) deny();
        const root = decode(bundle.ciphertextRoot, 32);
        const signed = await http.signProtectedContentOperation({
          ...signer(input), operation: "put", objectId: input.metadata.object_id,
          expectedObjectRevision: null, ciphertext,
        });
        // No blind retry after unknown PUT outcome; the exported bundle may
        // still be safely kept by the holder for independent reconciliation.
        await http.postProtectedCiphertextPut({
          origin: input.origin, request: signed, fetchImpl: input.fetchImpl,
        });
        const signedGet = await http.signProtectedContentOperation({
          ...signer(input), operation: "get", objectId: input.metadata.object_id,
          expectedObjectRevision: 1, expectedCiphertextDigest: digest,
          ciphertext: null,
        });
        await floor.verifyExternalAnchor(anchor(input));
        if (typeof window === "object") await floor.assertCurrent(anchor(input));
        const read = await http.postProtectedCiphertextBackupRead({
          origin: input.origin, request: signedGet, fetchImpl: input.fetchImpl,
          expectedObjectRevision: 1, expectedEpoch: input.metadata.epoch,
          expectedRoot: root,
        });
        if (read.ciphertextBase64 !== bundle.ciphertextBase64) deny();
        opened = await portable.openWithIndependentRoot({
          recoverySecret: secret, bundle, expectedMetadata: input.metadata,
          independentlyPinnedCiphertextRoot: root,
        });
        return Object.freeze({ bundle, objectId: input.metadata.object_id,
          ciphertextRoot: bundle.ciphertextRoot,
          clientReadbackVerified: true, ownerSignedHistoricalRootVerified: false,
          // Approval of the exported ciphertext root is an independent OWNER
          // step. An ordinary client operation cannot sign as the owner.
          externalOwnerRootApprovalRequiredForRestore: true,
          currentOnlineRevocationVerifiedByClient: false,
          authorizesProductionIo: false });
      } catch (_) { deny(); }
      finally { secret?.fill(0); opened?.data?.fill(0); ciphertext?.fill(0); }
    }
    async function restoreOnNewDevice(input) {
      let secret;
      try {
        exact(input, restore);
        secret = raw(input.recoverySecret, 32);
        await validate(input, input.expectedMetadata);
        // Owner must separately authorize the fresh device and sign the
        // historical root at the *currently* pinned owner head.
        const result = await recovery.recoverFromOwnerSignedProtectedGet({
          ...Object.fromEntries(base.map((key) => [key, input[key]])),
          recoverySecret: secret, bundle: input.bundle,
          expectedMetadata: input.expectedMetadata,
          independentlyPinnedCiphertextRoot: input.independentlyPinnedCiphertextRoot,
          ownerSignerKeyId: input.ownerSignerKeyId,
          ownerDeviceId: input.ownerDeviceId,
          ownerRootCheckpoint: input.ownerRootCheckpoint,
          previousOwnerHistoryProof: input.previousOwnerHistoryProof,
        });
        if (result.ownerSignedHistoricalRootVerified !== true) deny();
        return result;
      } catch (_) { deny(); }
      finally { secret?.fill(0); }
    }
    return Object.freeze({ createRecoverableProtectedFile, restoreOnNewDevice });
  }));
