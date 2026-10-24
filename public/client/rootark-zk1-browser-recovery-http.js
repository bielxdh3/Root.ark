(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-normal-browser-content"),
      require("./rootark-zk1-normal-browser-trust-floor"),
      require("./rootark-zk1-portable-file-recovery"),
      require("./rootark-zk1-protected-http-client"),
      require("./rootark-zk1-owner-ciphertext-root-checkpoint"));
  } else {
    root.RootarkZk1BrowserRecoveryHttp = factory(root.crypto,
      root.RootarkZk1NormalBrowserContent, root.RootarkZk1NormalBrowserTrustFloor,
      root.RootarkZk1PortableFileRecovery, root.RootarkZk1ProtectedHttpClient,
      root.RootarkZk1OwnerCiphertextRootCheckpoint);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (webCrypto, normal, floor, portable, http, ownerRoots) {
    "use strict";

    // A development-only normal HTTP GET followed by CLIENT-SIDE recovery
    // of an already-protected ciphertext. The server can authorize *current*
    // I/O but never sees the offline high-entropy secret or plaintext.
    // The exact owner's root and SPKI fingerprints are independent inputs.
    const fields = ["ownerPublicKey", "pinnedOwnerKeyHash",
      "independentOwnerSpkiSha256", "pinnedCurrentHead", "signedDeviceGrant",
      "devicePublicKey", "devicePrivateKey", "ownerHistoryCheckpoint",
      "recoverySecret", "bundle", "expectedMetadata",
      "independentlyPinnedCiphertextRoot", "origin", "fetchImpl", "nowSeconds"];
    const scopes = ["account_id", "compartment_id", "keyring_id"];
    const metaFields = [...scopes, "object_id", "version_id",
      "parent_version_id", "epoch", "kind"];
    const re64 = /^[A-Za-z0-9_-]+$/;
    function deny() { throw new Error("ZK_BROWSER_RECOVERY_HTTP_DENIED"); }
    function exact(value, keys) {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
        || Reflect.ownKeys(value).length !== keys.length
        || keys.some((key) => !Object.hasOwn(value, key))
        || Reflect.ownKeys(value).some((key) =>
          typeof key !== "string" || !keys.includes(key))) deny();
    }
    function from64(value, min, max = min) {
      if (typeof value !== "string" || !re64.test(value)
        || value.length > Math.ceil(max * 4 / 3) + 4) deny();
      let data;
      try { data = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
      const out = Uint8Array.from(data, (v) => v.charCodeAt(0));
      if (out.length < min || out.length > max
        || b64(out) !== value) deny();
      return out;
    }
    function b64(raw) {
      let text = "";
      for (const v of raw) text += String.fromCharCode(v);
      return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function same(a, b) {
      if (a.length !== b.length) return false;
      let different = 0;
      for (let i = 0; i < a.length; i++) different |= a[i] ^ b[i];
      return different === 0;
    }
    async function recoverFromProtectedGet(input) {
      let received, expectedCiphertext, digest, output;
      try {
        const hasHistory = Object.hasOwn(input || {}, "previousOwnerHistoryProof");
        exact(input, hasHistory ? [...fields, "previousOwnerHistoryProof"] : fields);
        exact(input.expectedMetadata, metaFields);
        const meta = { ...input.expectedMetadata };
        const grant = input.signedDeviceGrant;
        const proof = await normal.verifyOwnerGrant({
          ownerPublicKey: input.ownerPublicKey,
          pinnedOwnerKeyHash: input.pinnedOwnerKeyHash,
          pinnedCurrentHead: input.pinnedCurrentHead,
          signedDeviceGrant: grant,
          devicePublicKey: input.devicePublicKey,
          devicePrivateKey: input.devicePrivateKey,
        });
        if (!proof.ownerGrantSignatureVerified
          || proof.currentOnlineRevocationVerified !== false
          || meta.kind !== "file"
          // A past encrypted file stays readable after a newer legitimate
          // owner epoch, provided the CURRENT signer/grant/server admission
          // remains active and its historical owner-pinned root still matches.
          || !Number.isSafeInteger(meta.epoch) || meta.epoch < 1
          || meta.epoch > input.pinnedCurrentHead.epoch
          || scopes.some((key) => meta[key] !== grant[key])
          || typeof input.origin !== "string"
          || typeof input.fetchImpl !== "function"
          || !Number.isSafeInteger(input.nowSeconds) || input.nowSeconds < 0) deny();
        const ownerAnchor = {
          ownerPublicKey: input.ownerPublicKey,
          independentOwnerSpkiSha256: input.independentOwnerSpkiSha256,
          pinnedCurrentHead: input.pinnedCurrentHead,
          signedDeviceGrant: grant,
          ownerHistoryCheckpoint: input.ownerHistoryCheckpoint,
          ...(hasHistory ? { previousOwnerHistoryProof: input.previousOwnerHistoryProof } : {}),
        };
        await floor.verifyExternalAnchor(ownerAnchor);
        // On browsers, no authenticated request may leave before a previously
        // provisioned local monotonic floor also agrees with the owner head.
        if (typeof window === "object") {
          await floor.assertCurrent(ownerAnchor);
        }
        expectedCiphertext = from64(input.bundle?.ciphertextBase64,
          16, 4 * 1024 * 1024);
        const objectRevision = input.bundle?.objectRevision;
        if (!Number.isSafeInteger(objectRevision) || objectRevision < 1) deny();
        digest = new Uint8Array(await webCrypto.subtle.digest("SHA-256", expectedCiphertext));
        const requestedRoot = input.independentlyPinnedCiphertextRoot;
        if (!(requestedRoot instanceof ArrayBuffer)
          && !ArrayBuffer.isView(requestedRoot)) deny();
        const root = requestedRoot instanceof ArrayBuffer
          ? new Uint8Array(requestedRoot.slice(0))
          : new Uint8Array(requestedRoot.buffer.slice(
            requestedRoot.byteOffset, requestedRoot.byteOffset + requestedRoot.byteLength));
        if (root.length !== 32 || !same(root, from64(input.bundle.ciphertextRoot, 32))) deny();
        const signer = {
          signerKey: input.devicePrivateKey,
          scope: Object.fromEntries(scopes.map((name) => [name, grant[name]])),
          deviceId: grant.device_id,
          manifestRevision: input.pinnedCurrentHead.revision,
          manifestDigest: input.pinnedCurrentHead.digest,
          epoch: input.pinnedCurrentHead.epoch,
          nowSeconds: input.nowSeconds,
        };
        const signed = await http.signProtectedContentOperation({
          ...signer, operation: "get", objectId: meta.object_id,
          expectedObjectRevision: objectRevision, expectedCiphertextDigest: digest,
          ciphertext: null,
        });
        const result = await http.postProtectedCiphertextBackupRead({
          origin: input.origin, request: signed, fetchImpl: input.fetchImpl,
          expectedObjectRevision: objectRevision,
          expectedEpoch: meta.epoch, expectedRoot: root,
        });
        if (result.objectId !== meta.object_id || result.revision !== objectRevision
          || result.ciphertextBase64 !== input.bundle.ciphertextBase64
          || !result.integrityMatchesPinnedRoot
          || result.durableBackupProven !== false) deny();
        received = await portable.openWithIndependentRoot({
          recoverySecret: input.recoverySecret, bundle: input.bundle,
          expectedMetadata: meta,
          independentlyPinnedCiphertextRoot: root,
        });
        output = Object.freeze({
          name: received.name, mediaType: received.mediaType,
          data: received.data,
          ownerGrantVerified: true, externalOwnerSpkiPinMatched: true,
          ownerPinOriginProvenByModule: false,
          historicalGetVerified: true, localUserSecretOpened: true,
          serverRespondedToProtectedGet: true,
          independentServerGateProofVerified: false,
          independentDurableWriteProven: false,
          authorizesProductionRestore: false,
        });
        return output;
      } catch (_) {
        if (received && !output) received.data?.fill(0);
        deny();
      } finally {
        expectedCiphertext?.fill(0); digest?.fill(0);
      }
    }
    // Stronger opt-in recovery mode: a manually entered root can only be used
    // after the separately pinned owner actually signed the *exact* historical
    // ciphertext root and current manifest checkpoint. Neither a server JSON
    // flag nor the bundle's self-asserted root can manufacture this proof.
    async function recoverFromOwnerSignedProtectedGet(input) {
      let content;
      try {
        exact(input, [...fields, "ownerSignerKeyId", "ownerDeviceId",
          "ownerRootCheckpoint", "previousOwnerHistoryProof"]);
        if (!ownerRoots?.verifyOwnerCiphertextRootCheckpoint
          || input.ownerHistoryCheckpoint === null
          || input.ownerRootCheckpoint === null) deny();
        const original = Object.fromEntries(fields.map((key) => [key, input[key]]));
        original.previousOwnerHistoryProof = input.previousOwnerHistoryProof;
        const metadata = original.expectedMetadata;
        const grant = original.signedDeviceGrant;
        if (!metadata || !grant || scopes.some((name) =>
          metadata[name] !== grant[name])) deny();
        await floor.verifyExternalAnchor({
          ownerPublicKey: original.ownerPublicKey,
          independentOwnerSpkiSha256: original.independentOwnerSpkiSha256,
          pinnedCurrentHead: original.pinnedCurrentHead,
          signedDeviceGrant: grant,
          ownerHistoryCheckpoint: original.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: original.previousOwnerHistoryProof,
        });
        const signed = await ownerRoots.verifyOwnerCiphertextRootCheckpoint({
          checkpoint: input.ownerRootCheckpoint,
          ownerHistoryCheckpoint: original.ownerHistoryCheckpoint,
          previousHistoryProof: input.previousOwnerHistoryProof,
          pinnedOwner: {
            scope: Object.fromEntries(scopes.map((name) => [name, metadata[name]])),
            deviceId: input.ownerDeviceId,
            signerKeyId: from64(input.ownerSignerKeyId, 16),
            publicKey: original.ownerPublicKey,
          },
          expected: {
            manifestRevision: original.pinnedCurrentHead.revision,
            manifestDigest: original.pinnedCurrentHead.digest,
            manifestEpoch: original.pinnedCurrentHead.epoch,
            objectId: metadata.object_id,
            objectRevision: original.bundle?.objectRevision,
            ciphertextEpoch: metadata.epoch,
            ciphertextRoot: original.independentlyPinnedCiphertextRoot,
          },
        });
        if (signed.trustedOwnerSignatureVerified !== true
          || signed.manifestCheckpointVerified !== true
          || signed.authorizesRecovery !== false) deny();
        content = await recoverFromProtectedGet(original);
        return Object.freeze({ ...content,
          ownerSignedHistoricalRootVerified: true,
          externalOwnerKeyOriginVerifiedByModule: false,
          independentServerGateProofVerified: false,
          authorizesProductionRestore: false,
        });
      } catch (_) {
        content?.data?.fill(0);
        deny();
      }
    }
    return Object.freeze({ recoverFromProtectedGet, recoverFromOwnerSignedProtectedGet });
  }));
