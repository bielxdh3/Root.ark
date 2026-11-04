(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-file-content"),
      require("./rootark-zk1-ciphertext-chunk-root"),
      require("./rootark-zk1-protected-http-client"),
      require("./rootark-zk1-uncertain-put-reconciliation"),
      require("./rootark-zk1-normal-browser-trust-floor"));
  } else {
    root.RootarkZk1NormalBrowserContent = factory(root.crypto,
      root.RootarkZk1FileContent, root.RootarkZk1CiphertextRoot,
      root.RootarkZk1ProtectedHttpClient, root.RootarkZk1UncertainPutReconciliation,
      root.RootarkZk1NormalBrowserTrustFloor);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (webCrypto, fileContent, roots, http, reconciliation, trustFloor) {
    "use strict";

    // One-file, dev-only normal upload followed by an authenticated HTTP readback.
    // Owner identity and the *current* head pin MUST arrive independently of the
    // application server. A signed grant is not a live revocation oracle; the
    // protected server separately checks its witness and signed-history head.
    // No persisted CEK/index, normal download, cutover or production admission.
    const domain = new TextEncoder().encode("Root.ark/zk-1/browser-owner-device-grant/v1\0");
    const grantFields = ["schema", "account_id", "compartment_id", "keyring_id",
      "device_id", "authorization_key_id", "authorization_public_key",
      "manifest_revision", "manifest_digest", "current_epoch",
      "enrolled_epoch", "revoked_at_epoch"];
    const scopeFields = ["account_id", "compartment_id", "keyring_id"];
    const metadataFields = [...scopeFields, "object_id", "version_id",
      "parent_version_id", "epoch", "kind"];
    const inputFields = ["ownerPublicKey", "pinnedOwnerKeyHash", "pinnedCurrentHead",
      "signedDeviceGrant", "devicePublicKey", "devicePrivateKey", "metadata",
      "fileName", "mediaType", "data", "origin", "fetchImpl", "nowSeconds"];
    const schema = "rootark-zk1-browser-owner-device-grant/v1";
    const b64re = /^[A-Za-z0-9_-]+$/;
    const verified = new WeakMap();
    // This laboratory browser must have an externally provisioned local floor.
    // Node fixtures without a DOM exercise the signed-grant primitive directly.
    const browserRuntime = typeof window === "object";

    function deny() { throw new Error("ZK_NORMAL_BROWSER_AUTHORITY_UNVERIFIED"); }
    function exact(value, fields) {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
        || Reflect.ownKeys(value).length !== fields.length
        || fields.some((name) => !Object.hasOwn(value, name))) deny();
    }
    function copy(value, min, max = min) {
      if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)) deny();
      const length = value.byteLength;
      if (!Number.isSafeInteger(length) || length < min || length > max) deny();
      return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
        : new Uint8Array(value.buffer.slice(value.byteOffset,
          value.byteOffset + value.byteLength));
    }
    function b64(value) {
      let raw = "";
      for (const byte of value) raw += String.fromCharCode(byte);
      return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function from64(value, length, max = length) {
      if (typeof value !== "string" || !b64re.test(value)
        || value.length > Math.ceil(max * 4 / 3) + 4) deny();
      let binary;
      try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=")); }
      catch (_) { deny(); }
      const result = Uint8Array.from(binary, (c) => c.charCodeAt(0));
      if (result.length < length || result.length > max || b64(result) !== value) deny();
      return result;
    }
    function equal(a, b) {
      if (a.length !== b.length) return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
      return diff === 0;
    }
    function uint(value, min = 1) {
      if (!Number.isSafeInteger(value) || value < min) deny();
      return value;
    }
    function validKey(key, role) {
      if (!key || key.type !== role || key.algorithm?.name !== "Ed25519"
        || !key.usages?.includes(role === "private" ? "sign" : "verify")
        || (role === "private" && key.extractable !== false)) deny();
      return key;
    }
    function grantMessage(grant) {
      exact(grant, [...grantFields, "signature"]);
      if (grant.schema !== schema) deny();
      const canonical = {};
      for (const field of grantFields) canonical[field] = grant[field];
      const encoded = new TextEncoder().encode(JSON.stringify(canonical));
      if (encoded.byteLength > 2048) deny();
      const joined = new Uint8Array(domain.length + encoded.length);
      joined.set(domain);
      joined.set(encoded, domain.length);
      return joined;
    }
    function scopeFrom(grant) {
      return Object.fromEntries(scopeFields.map((key) => {
        from64(grant[key], key === "compartment_id" ? 1 : 16,
          key === "compartment_id" ? 128 : 16);
        return [key, grant[key]];
      }));
    }
    async function verifyOwnerGrant(input) {
      try {
        exact(input, ["ownerPublicKey", "pinnedOwnerKeyHash", "pinnedCurrentHead",
          "signedDeviceGrant", "devicePublicKey", "devicePrivateKey"]);
        const ownerKey = validKey(input.ownerPublicKey, "public");
        const signerPublic = validKey(input.devicePublicKey, "public");
        const signerPrivate = validKey(input.devicePrivateKey, "private");
        exact(input.pinnedCurrentHead, ["revision", "digest", "epoch"]);
        const pin = { revision: uint(input.pinnedCurrentHead.revision),
          digest: copy(input.pinnedCurrentHead.digest, 32),
          epoch: uint(input.pinnedCurrentHead.epoch) };
        const ownerHash = copy(input.pinnedOwnerKeyHash, 32);
        const sourceGrant = input.signedDeviceGrant;
        exact(sourceGrant, [...grantFields, "signature"]);
        const grant = Object.fromEntries([...grantFields, "signature"]
          .map((field) => [field, sourceGrant[field]]));
        const message = grantMessage(grant);
        const ownerRaw = new Uint8Array(await webCrypto.subtle.exportKey("raw", ownerKey));
        const fingerprint = new Uint8Array(await webCrypto.subtle.digest("SHA-256", ownerRaw));
        if (!equal(fingerprint, ownerHash)) deny();
        const signature = from64(grant.signature, 64);
        if (!await webCrypto.subtle.verify("Ed25519", ownerKey, signature, message)) deny();
        if (grant.manifest_revision !== pin.revision
          || grant.manifest_digest !== b64(pin.digest)
          || grant.current_epoch !== pin.epoch
          || uint(grant.enrolled_epoch) > pin.epoch
          || grant.revoked_at_epoch !== null
          || typeof grant.device_id !== "string"
          || !grant.device_id || grant.device_id.length > 64
          || /[\u0000-\u001f\u007f]/.test(grant.device_id)) deny();
        const scope = scopeFrom(grant);
        const deviceRaw = new Uint8Array(await webCrypto.subtle.exportKey("raw", signerPublic));
        if (!equal(deviceRaw, from64(grant.authorization_public_key, 32))) deny();
        const signerKeyId = from64(grant.authorization_key_id, 16);
        // The grant must belong to the actual device private key being used.
        const challenge = webCrypto.getRandomValues(new Uint8Array(32));
        const signatureChallenge = await webCrypto.subtle.sign(
          "Ed25519", signerPrivate, challenge);
        if (!await webCrypto.subtle.verify("Ed25519", signerPublic,
          signatureChallenge, challenge)) deny();
        const result = Object.freeze({ ownerGrantSignatureVerified: true,
          offServerOwnerAndHeadPinsMatched: true,
          signerListedActiveAtPinnedEpoch: true,
          currentOnlineRevocationVerified: false,
          authorizesProductionIo: false });
        verified.set(result, { scope, signerKey: signerPrivate,
          deviceId: grant.device_id, signerKeyId: b64(signerKeyId),
          revision: pin.revision, digest: pin.digest, epoch: pin.epoch });
        return result;
      } catch (_) { deny(); }
    }
    function contextOf(proof) {
      const value = verified.get(proof);
      if (!value) deny();
      return value;
    }
    async function uploadAndVerify(input) {
      let plaintext = null;
      let ciphertext = null;
      let checkedData = null;
      try {
        const hasPreviousOwnerHistoryProof = Object.hasOwn(input || {},
          "previousOwnerHistoryProof");
        exact(input, browserRuntime
          ? [...inputFields, "independentOwnerSpkiSha256", "ownerHistoryCheckpoint",
            ...(hasPreviousOwnerHistoryProof ? ["previousOwnerHistoryProof"] : [])]
          : inputFields);
        exact(input.metadata, metadataFields);
        const metadata = { ...input.metadata };
        const objectId = metadata.object_id;
        const fileName = input.fileName;
        const mediaType = input.mediaType;
        const origin = input.origin;
        const fetchImpl = input.fetchImpl;
        const nowSeconds = uint(input.nowSeconds, 0);
        plaintext = copy(input.data, 0, 2 * 1024 * 1024);
        const proof = await verifyOwnerGrant({
          ownerPublicKey: input.ownerPublicKey,
          pinnedOwnerKeyHash: input.pinnedOwnerKeyHash,
          pinnedCurrentHead: input.pinnedCurrentHead,
          signedDeviceGrant: input.signedDeviceGrant,
          devicePublicKey: input.devicePublicKey,
          devicePrivateKey: input.devicePrivateKey,
        });
        const trust = contextOf(proof);
        if (!scopeFields.every((field) => metadata[field] === trust.scope[field])
          || metadata.epoch !== trust.epoch
          || metadata.parent_version_id !== null || metadata.kind !== "file") deny();
        if (typeof fetchImpl !== "function" || typeof origin !== "string") deny();
        const plainDigest = new Uint8Array(await webCrypto.subtle.digest("SHA-256", plaintext));
        // The one-use CEK exists only in this browser operation. Persisting it
        // requires separately reviewed key wrapping and revocation support.
        const cek = await fileContent.generateFileCek();
        ciphertext = await fileContent.encryptFile({
          cek, metadata, name: fileName, mediaType, data: plaintext,
        });
        const root = copy(await roots.computeCiphertextRoot([ciphertext]), 32);
        const signer = { signerKey: trust.signerKey, scope: trust.scope,
          deviceId: trust.deviceId, manifestRevision: trust.revision,
          manifestDigest: trust.digest, epoch: trust.epoch,
          nowSeconds };
        const checkFloor = async () => {
          if (!browserRuntime) return;
          if (!trustFloor?.assertCurrent) deny();
          await trustFloor.assertCurrent({
            ownerPublicKey: input.ownerPublicKey,
            independentOwnerSpkiSha256: input.independentOwnerSpkiSha256,
            pinnedCurrentHead: input.pinnedCurrentHead,
            signedDeviceGrant: input.signedDeviceGrant,
            ownerHistoryCheckpoint: input.ownerHistoryCheckpoint,
            ...(hasPreviousOwnerHistoryProof
              ? { previousOwnerHistoryProof: input.previousOwnerHistoryProof } : {}),
          });
        };
        await checkFloor();
        const signed = await http.signProtectedContentOperation({
          ...signer, operation: "put", objectId, expectedObjectRevision: null,
          ciphertext,
        });
        let lostAck = false;
        try {
          const response = await http.postProtectedCiphertextPut({
            origin, request: signed, fetchImpl,
          });
          if (response.id !== objectId || response.revision !== 1) deny();
        } catch (_) {
          // A failed PUT response may have followed an actual commit. Never
          // blindly retry; a new historically bound GET resolves only readback.
          await reconciliation.reconcileUncertainProtectedPut({
            origin, fetchImpl, signer,
            objectId, previousRevision: null, ciphertext, expectedRoot: root,
            expectedPlaintextSha256: plainDigest, cek, metadata,
          });
          lostAck = true;
        }
        const digest = new Uint8Array(await webCrypto.subtle.digest("SHA-256", ciphertext));
        const signedRead = await http.signProtectedContentOperation({
          ...signer, operation: "get", objectId, expectedObjectRevision: 1,
          expectedCiphertextDigest: digest, ciphertext: null,
        });
        await checkFloor();
        const opened = await http.postProtectedCiphertextRead({
          origin, request: signedRead, fetchImpl,
          expectedObjectRevision: 1, expectedRoot: root, cek, metadata,
        });
        checkedData = opened.data;
        if (opened.name !== fileName || opened.mediaType !== mediaType
          || !equal(checkedData, plaintext)) deny();
        return Object.freeze({
          objectId, revision: 1, ciphertextRoot: b64(root),
          ownerAndDeviceCheckedLocally: true,
          protectedHttpReadbackVerified: true, lostPutAckReconciled: lostAck,
          persistentKeyRecoveryAvailable: false,
          independentDurableWriteProven: false, authorizesProductionIo: false,
        });
      } catch (_) { deny(); }
      finally {
        plaintext?.fill(0);
        ciphertext?.fill(0);
        checkedData?.fill(0);
      }
    }
    return Object.freeze({ verifyOwnerGrant, uploadAndVerify });
  }));
