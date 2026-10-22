(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-ciphertext-chunk-root"),
      require("./rootark-zk1-protected-http-client"));
  } else {
    root.RootarkZk1OwnerBackupImport = factory(root.crypto,
      root.RootarkZk1CiphertextRoot, root.RootarkZk1ProtectedHttpClient);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (webCrypto, roots, http) {
    "use strict";

    // Owner-authorized ciphertext *copy* to an absent object through the real
    // protected HTTP gate. This does not enroll devices, unwrap keys, resurrect
    // deleted/revoked access or grant permission to restore application state.
    // Owner integrity and current device admission are independent checks.
    const DOMAIN = "Root.ark/zk-1/client-backup-import-authorization/v1\0";
    const SCHEMA = "rootark-zk1-client-backup-import-authorization/v1";
    const OWNER_FIELDS = ["schema", "account_id", "compartment_id", "keyring_id",
      "object_id", "version_id", "epoch", "source_revision", "manifest_revision",
      "manifest_digest", "expires_at", "ciphertext_sha256", "ciphertext_root"];
    const INPUT_FIELDS = ["approval", "trustedOwnerPublicKey", "trustedRoot",
      "trustedEpoch", "ciphertextBase64", "signer", "origin", "fetchImpl"];
    const SIGNER_FIELDS = ["signerKey", "scope", "deviceId", "manifestRevision",
      "manifestDigest", "epoch", "nowSeconds"];
    const SCOPE_FIELDS = ["account_id", "compartment_id", "keyring_id"];
    const META_FIELDS = [...SCOPE_FIELDS, "object_id", "version_id",
      "parent_version_id", "epoch", "kind"];
    const MAX_WIRE = 4 * 1024 * 1024;
    const B64 = /^[A-Za-z0-9_-]+$/;
    const decoder = new TextDecoder("utf-8", { fatal: true });
    const encoder = new TextEncoder();
    function deny() { throw new Error("ZK_OWNER_BACKUP_IMPORT_DENIED"); }
    function exact(input, names) {
      if (!input || typeof input !== "object" || Array.isArray(input)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
        || Reflect.ownKeys(input).length !== names.length
        || Reflect.ownKeys(input).some((name) => typeof name !== "string" || !names.includes(name))
        || names.some((name) => !Object.hasOwn(input, name))) deny();
    }
    function b64(bytes) {
      let data = "";
      for (const value of bytes) data += String.fromCharCode(value);
      return btoa(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function from64(value, size, max = size) {
      if (typeof value !== "string" || !B64.test(value)
        || value.length > Math.ceil(max * 4 / 3) + 4) deny();
      let encoded;
      try {
        encoded = atob(value.replace(/-/g, "+").replace(/_/g, "/")
          .padEnd(Math.ceil(value.length / 4) * 4, "="));
      } catch (_) { deny(); }
      const bytes = Uint8Array.from(encoded, (part) => part.charCodeAt(0));
      if (bytes.length < size || bytes.length > max || b64(bytes) !== value) deny();
      return bytes;
    }
    function copy32(bytes) {
      if (!(bytes instanceof ArrayBuffer) && !ArrayBuffer.isView(bytes)
        || bytes.byteLength !== 32) deny();
      return bytes instanceof ArrayBuffer ? new Uint8Array(bytes.slice(0))
        : new Uint8Array(bytes.buffer.slice(bytes.byteOffset,
          bytes.byteOffset + bytes.byteLength));
    }
    function equal(left, right) {
      if (left.length !== right.length) return false;
      let difference = 0;
      for (let i = 0; i < left.length; ++i) difference |= left[i] ^ right[i];
      return difference === 0;
    }
    function positive(value) {
      if (!Number.isSafeInteger(value) || value < 1) deny();
      return value;
    }
    function id(value) {
      from64(value, 16);
      if (value.length !== 22) deny();
      return value;
    }
    function envelopeScope(bytes, owner) {
      // Reject plaintext and malformed/noncanonical ciphertext envelopes before
      // the owner signature is used to enable any network I/O.
      const parsed = JSON.parse(decoder.decode(bytes));
      exact(parsed, ["format", "algorithm", "metadata", "nonce", "ciphertext"]);
      if (parsed.format !== "rootark-zk1-file-v1"
        || parsed.algorithm !== "AES-256-GCM"
        || JSON.stringify(parsed) !== decoder.decode(bytes)) deny();
      exact(parsed.metadata, META_FIELDS);
      for (const field of [...SCOPE_FIELDS, "object_id", "version_id", "epoch"])
        if (parsed.metadata[field] !== owner[field]) deny();
      if (parsed.metadata.parent_version_id !== null || parsed.metadata.kind !== "file") deny();
      from64(parsed.nonce, 12);
      from64(parsed.ciphertext, 16, MAX_WIRE);
    }
    async function importOwnerSignedBackupCiphertext(input) {
      let sealed;
      let root;
      let digest;
      try {
        exact(input, INPUT_FIELDS);
        exact(input.approval, [...OWNER_FIELDS, "signatureBase64"]);
        exact(input.signer, SIGNER_FIELDS);
        exact(input.signer.scope, SCOPE_FIELDS);
        const owner = Object.fromEntries(OWNER_FIELDS.map((field) => [field, input.approval[field]]));
        const ownerSignature = from64(input.approval.signatureBase64, 64);
        if (owner.schema !== SCHEMA) deny();
        for (const field of ["account_id", "keyring_id", "object_id", "version_id"]) id(owner[field]);
        from64(owner.compartment_id, 1, 128);
        positive(owner.epoch);
        // This narrow path reconstructs only the original absent object at
        // revision 1. Higher archived revisions need a separately reviewed
        // full historical chain and cannot be relabeled revision 1.
        if (owner.source_revision !== 1) deny();
        positive(owner.manifest_revision);
        const ownerManifestDigest = from64(owner.manifest_digest, 32);
        if (!Number.isSafeInteger(owner.expires_at) || owner.expires_at < 1) deny();
        const ownerDigest = from64(owner.ciphertext_sha256, 32);
        const ownerRoot = from64(owner.ciphertext_root, 32);
        root = copy32(input.trustedRoot);
        const epoch = positive(input.trustedEpoch);
        if (epoch !== owner.epoch || input.signer.epoch !== epoch
          || input.signer.manifestRevision !== owner.manifest_revision
          || !equal(copy32(input.signer.manifestDigest), ownerManifestDigest)
          || !Number.isSafeInteger(input.signer.nowSeconds)
          || owner.expires_at < input.signer.nowSeconds
          || owner.expires_at > input.signer.nowSeconds + 45
          || !equal(root, ownerRoot)
          || SCOPE_FIELDS.some((name) => input.signer.scope[name] !== owner[name])
          || !webCrypto?.subtle || !roots?.computeCiphertextRoot
          || !http?.signProtectedContentOperation || !http?.postProtectedCiphertextPut
          || !http?.postProtectedCiphertextBackupRead
          || typeof input.fetchImpl !== "function" || typeof input.origin !== "string"
          || input.trustedOwnerPublicKey?.type !== "public"
          || input.trustedOwnerPublicKey?.algorithm?.name !== "Ed25519"
          || !input.trustedOwnerPublicKey.usages?.includes("verify")) deny();
        const signer = { ...input.signer,
          scope: { ...input.signer.scope }, manifestDigest: copy32(input.signer.manifestDigest) };
        const origin = input.origin;
        const fetchImpl = input.fetchImpl;
        // Snapshot ciphertext and all approval scalars before first await.
        sealed = from64(input.ciphertextBase64, 16, MAX_WIRE);
        envelopeScope(sealed, owner);
        const approvalMessage = encoder.encode(DOMAIN + JSON.stringify(owner));
        if (!await webCrypto.subtle.verify("Ed25519",
          input.trustedOwnerPublicKey, ownerSignature, approvalMessage)) deny();
        digest = new Uint8Array(await webCrypto.subtle.digest("SHA-256", sealed));
        if (!equal(digest, ownerDigest)
          || !equal(root, new Uint8Array(await roots.computeCiphertextRoot([sealed])))) deny();

        // Create ONLY. An already existing object (including a prior lost ACK)
        // must fail the server's CAS check; never replace it or retry this PUT.
        const put = await http.signProtectedContentOperation({
          ...signer, operation: "put", objectId: owner.object_id,
          expectedObjectRevision: null, ciphertext: sealed,
        });
        const written = await http.postProtectedCiphertextPut({ origin, request: put, fetchImpl });
        if (written.id !== owner.object_id || written.revision !== 1) deny();
        const get = await http.signProtectedContentOperation({
          ...signer, operation: "get", objectId: owner.object_id,
          expectedObjectRevision: 1, expectedCiphertextDigest: digest,
          ciphertext: null,
        });
        const readback = await http.postProtectedCiphertextBackupRead({
          origin, request: get, fetchImpl, expectedObjectRevision: 1,
          expectedEpoch: epoch, expectedRoot: root,
        });
        if (readback.objectId !== owner.object_id
          || readback.ciphertextBase64 !== b64(sealed)) deny();
        return Object.freeze({ objectId: owner.object_id, revision: 1,
          ownerSignatureVerified: true, ciphertextReadbackVerified: true,
          independentDurabilityProven: false, authorizesRecovery: false,
          authorizesRestore: false, authorizesRelease: false });
      } catch (_) { deny(); }
      finally { sealed?.fill(0); root?.fill(0); digest?.fill(0); }
    }
    return Object.freeze({ importOwnerSignedBackupCiphertext });
  }));
