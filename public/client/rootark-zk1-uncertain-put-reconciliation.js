(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(
      require("node:crypto").webcrypto,
      require("./rootark-zk1-ciphertext-chunk-root"),
      require("./rootark-zk1-protected-http-client"));
  } else {
    root.RootarkZk1UncertainPutReconciliation = factory(
      root.crypto, root.RootarkZk1CiphertextRoot, root.RootarkZk1ProtectedHttpClient);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (webCrypto, roots, httpClient) {
    "use strict";

    // Non-authorizing reconciliation of a PUT whose HTTP ACK may have been lost.
    // A fresh, independently signed historical GET is the ONLY network effect.
    // Never retries the PUT; never deletes/reclassifies source, grants release
    // or claims durable CAS/witness/provider evidence.
    const SCOPE = ["account_id", "compartment_id", "keyring_id"];
    const SIGNER = ["signerKey", "scope", "deviceId", "manifestRevision",
      "manifestDigest", "epoch", "nowSeconds"];
    const META = [...SCOPE, "object_id", "version_id", "parent_version_id",
      "epoch", "kind"];
    const INPUT = ["origin", "fetchImpl", "signer", "objectId",
      "previousRevision", "ciphertext", "expectedRoot",
      "expectedPlaintextSha256", "cek", "metadata"];
    const MAX_CIPHERTEXT = 4 * 1024 * 1024;
    function deny() { throw new Error("ZK_UNCERTAIN_PUT_NOT_RECONCILED"); }
    function exact(obj, fields) {
      if (!obj || typeof obj !== "object" || Array.isArray(obj)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(obj))
        || Reflect.ownKeys(obj).length !== fields.length
        || fields.some((key) => !Object.hasOwn(obj, key))) deny();
    }
    function copy(input, min, max = min) {
      if (!ArrayBuffer.isView(input) && !(input instanceof ArrayBuffer)) deny();
      // Enforce the bound BEFORE allocating a clone: caller-supplied buffers
      // can be enormous even though the accepted ciphertext limit is 4 MiB.
      const length = input.byteLength;
      if (!Number.isSafeInteger(length) || length < min || length > max) deny();
      const result = input instanceof ArrayBuffer
        ? new Uint8Array(input.slice(0))
        : new Uint8Array(input.buffer.slice(input.byteOffset,
          input.byteOffset + input.byteLength));
      if (result.byteLength !== length) deny();
      return result;
    }
    function equal(a, b) {
      if (a.byteLength !== b.byteLength) return false;
      let different = 0;
      for (let i = 0; i < a.byteLength; ++i) different |= a[i] ^ b[i];
      return different === 0;
    }
    function scopeMatches(scope, metadata) {
      return SCOPE.every((name) =>
        typeof scope[name] === "string" && scope[name] === metadata[name]);
    }
    async function reconcileUncertainProtectedPut(input) {
      let local = null;
      let opened = null;
      let expectedRoot;
      let expectedPlain;
      try {
        exact(input, INPUT);
        exact(input.signer, SIGNER);
        exact(input.signer.scope, SCOPE);
        exact(input.metadata, META);
        const objectId = input.objectId;
        const prior = input.previousRevision;
        if (prior !== null && (!Number.isSafeInteger(prior) || prior < 1
          || prior >= Number.MAX_SAFE_INTEGER)) deny();
        const revision = prior === null ? 1 : prior + 1;
        if (typeof objectId !== "string"
          || input.metadata.object_id !== objectId
          || !scopeMatches(input.signer.scope, input.metadata)
          || typeof input.fetchImpl !== "function" || typeof input.origin !== "string"
          || !webCrypto?.subtle?.digest || !roots?.computeCiphertextRoot
          || !httpClient?.signProtectedContentOperation
          || !httpClient?.postProtectedCiphertextRead) deny();
        // Snapshot all caller-controlled bytes, scalars and metadata before
        // the FIRST await. Caller mutations while crypto/network runs cannot
        // change which object/version/scope is signed and later examined.
        const metadata = { ...input.metadata };
        const signer = { ...input.signer, scope: { ...input.signer.scope },
          manifestDigest: copy(input.signer.manifestDigest, 32) };
        const origin = input.origin;
        const fetchImpl = input.fetchImpl;
        const cek = input.cek;
        expectedRoot = copy(input.expectedRoot, 32);
        expectedPlain = copy(input.expectedPlaintextSha256, 32);
        local = copy(input.ciphertext, 16, MAX_CIPHERTEXT);
        const actualRoot = copy(await roots.computeCiphertextRoot([local]), 32);
        if (!equal(expectedRoot, actualRoot)) deny();
        const ciphertextDigest = new Uint8Array(
          await webCrypto.subtle.digest("SHA-256", local));
        const signedRead = await httpClient.signProtectedContentOperation({
          ...signer, operation: "get", objectId,
          expectedObjectRevision: revision,
          expectedCiphertextDigest: ciphertextDigest, ciphertext: null,
        });
        opened = await httpClient.postProtectedCiphertextRead({
          origin, request: signedRead, fetchImpl, expectedObjectRevision: revision,
          expectedRoot: actualRoot, cek, metadata,
        });
        const plaintext = copy(opened.data, 0, MAX_CIPHERTEXT);
        const actualPlain = new Uint8Array(
          await webCrypto.subtle.digest("SHA-256", plaintext));
        plaintext.fill(0);
        if (!equal(expectedPlain, actualPlain) || opened.authorizesRelease !== false) deny();
        return Object.freeze({
          objectId, revision, clientReadbackVerified: true,
          independentDurableCommitProven: false,
          authorizesCutover: false, authorizesProtectedIo: false,
        });
      } catch (_) { deny(); }
      finally {
        local?.fill(0);
        opened?.data?.fill(0);
        expectedRoot?.fill(0);
        expectedPlain?.fill(0);
      }
    }
    return Object.freeze({ reconcileUncertainProtectedPut });
  }));
