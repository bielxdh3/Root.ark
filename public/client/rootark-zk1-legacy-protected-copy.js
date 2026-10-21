(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(
      require("./rootark-dev-vault-migration"),
      require("./rootark-zk1-file-content"),
      require("./rootark-zk1-ciphertext-chunk-root"),
      require("./rootark-zk1-protected-http-client"),
      require("node:crypto").webcrypto);
  } else {
    root.RootarkZk1LegacyProtectedCopy = factory(
      root.RootarkDevVaultMigration, root.RootarkZk1FileContent,
      root.RootarkZk1CiphertextRoot, root.RootarkZk1ProtectedHttpClient,
      root.crypto);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (legacyClient, fileContent, chunkRoot, httpClient, rootCrypto) {
    "use strict";

    // Explicit, NON-DESTRUCTIVE browser copy from an existing legacy file.
    // Does not delete source, switch references, authorize cutover, create a
    // recovery key, or claim that a server acknowledgement proves durability.
    // Actual production migration still requires an independently governed
    // CAS/witness and reversible provider transaction protocol.
    const PLAIN_LIMIT = 2 * 1024 * 1024;
    const SCOPE_FIELDS = ["account_id", "compartment_id", "keyring_id"];
    const SIGNER_FIELDS = ["signerKey", "scope", "deviceId", "manifestRevision",
      "manifestDigest", "epoch", "nowSeconds"];
    const META_FIELDS = [...SCOPE_FIELDS, "object_id", "version_id",
      "parent_version_id", "epoch", "kind"];
    function refuse() { throw new Error("ZK_CLIENT_MIGRATION_UNVERIFIED"); }
    function exact(input, fields) {
      if (!input || typeof input !== "object" || Array.isArray(input)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
        || Reflect.ownKeys(input).length !== fields.length
        || fields.some((field) => !Object.hasOwn(input, field))) refuse();
    }
    function copy(bytes, expected) {
      if (!ArrayBuffer.isView(bytes) && !(bytes instanceof ArrayBuffer)) refuse();
      const result = bytes instanceof ArrayBuffer ? new Uint8Array(bytes.slice(0))
        : new Uint8Array(bytes.buffer.slice(bytes.byteOffset,
          bytes.byteOffset + bytes.byteLength));
      if (expected !== undefined && result.length !== expected) refuse();
      return result;
    }
    function equal(left, right) {
      if (left.length !== right.length) return false;
      let difference = 0;
      for (let index = 0; index < left.length; index++) {
        difference |= left[index] ^ right[index];
      }
      return difference === 0;
    }
    async function copyLegacyIntoProtectedCiphertext(input) {
      let source = null;
      let after = null;
      let inspected = null;
      let ciphertext = null;
      let digest = null;
      try {
        exact(input, ["legacy", "metadata", "signer", "cek", "origin", "fetchImpl"]);
        exact(input.legacy, ["name", "folderId"]);
        exact(input.metadata, META_FIELDS);
        exact(input.signer, SIGNER_FIELDS);
        exact(input.signer.scope, SCOPE_FIELDS);
        if (!legacyClient?.readLegacyPlaintext || !fileContent?.encryptFile
          || !chunkRoot?.computeCiphertextRoot || !httpClient?.signProtectedContentOperation
          || !httpClient?.postProtectedCiphertextPut || !httpClient?.postProtectedCiphertextRead
          || typeof input.fetchImpl !== "function" || typeof input.origin !== "string") refuse();
        // Snapshot all caller-controlled context synchronously before fetching
        // legacy plaintext. A changed form/model must not retarget signing.
        const legacy = { name: input.legacy.name, folderId: input.legacy.folderId };
        const metadata = { ...input.metadata };
        const signer = {
          ...input.signer, scope: { ...input.signer.scope },
          manifestDigest: copy(input.signer.manifestDigest, 32),
        };
        const cek = input.cek;
        const origin = input.origin;
        const fetchImpl = input.fetchImpl;
        if (metadata.epoch !== signer.epoch || metadata.parent_version_id !== null
          || SCOPE_FIELDS.some((key) => metadata[key] !== signer.scope[key])) refuse();
        source = await legacyClient.readLegacyPlaintext({
          ...legacy, maxBytes: PLAIN_LIMIT, fetchImpl,
        });
        ciphertext = await fileContent.encryptFile({
          cek, metadata, name: source.name, mediaType: source.mediaType,
          data: source.data,
        });
        // SHA-256 chunk commitment computed before upload; never accept an
        // expected root supplied by untrusted server JSON.
        const rootBytes = copy(await chunkRoot.computeCiphertextRoot([ciphertext]), 32);
        digest = copy(await cryptoDigest(ciphertext), 32);
        const put = await httpClient.signProtectedContentOperation({
          ...signer, operation: "put", objectId: metadata.object_id,
          expectedObjectRevision: null, ciphertext,
        });
        const written = await httpClient.postProtectedCiphertextPut({
          origin, request: put, fetchImpl,
        });
        if (written.id !== metadata.object_id || written.revision !== 1) refuse();
        const signedRead = await httpClient.signProtectedContentOperation({
          ...signer, operation: "get", objectId: metadata.object_id,
          expectedObjectRevision: 1, expectedCiphertextDigest: digest,
          ciphertext: null,
        });
        inspected = await httpClient.postProtectedCiphertextRead({
          origin, request: signedRead, fetchImpl, expectedObjectRevision: 1,
          expectedRoot: rootBytes, cek, metadata,
        });
        if (inspected.name !== source.name
          || inspected.mediaType !== source.mediaType
          || !equal(copy(inspected.data), copy(source.data))) refuse();
        after = await legacyClient.readLegacyPlaintext({
          ...legacy, maxBytes: PLAIN_LIMIT, fetchImpl,
        });
        if (after.name !== source.name || after.mediaType !== source.mediaType
          || !equal(copy(after.data), copy(source.data))) refuse();
        return Object.freeze({
          objectId: metadata.object_id, revision: 1,
          ciphertextRoot: new Uint8Array(rootBytes),
          sourceRechecked: true, protectedCiphertextLocallyVerified: true,
          authorizesCutover: false, canDeleteLegacy: false,
        });
      } catch (_) { refuse(); }
      finally {
        // The original server/storage continues to own its source. Scrub only
        // temporary browser buffers held by this migration attempt.
        source?.data?.fill(0);
        after?.data?.fill(0);
        inspected?.data?.fill(0);
        ciphertext?.fill(0);
        digest?.fill(0);
      }
    }
    async function cryptoDigest(bytes) {
      if (!rootCrypto?.subtle?.digest) refuse();
      return new Uint8Array(await rootCrypto.subtle.digest("SHA-256", bytes));
    }
    return Object.freeze({ copyLegacyIntoProtectedCiphertext });
  }));
