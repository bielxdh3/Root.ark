(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-portable-file-recovery"),
      require("./rootark-zk1-ciphertext-chunk-root"));
  } else {
    root.RootarkZk1PersistedPortableChunkRecovery = factory(root.crypto,
      root.RootarkZk1PortableFileRecovery, root.RootarkZk1CiphertextRoot);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (crypto, portable, roots) {
    "use strict";

    // Offline client-side bridge from independently pinned owner inventory to
    // persisted opaque chunk bytes and existing HKDF/AES-GCM portable recovery.
    // No server-supplied head, archive-carried owner key or missing chunk can
    // authorize release. Not an online device/witness admission or backup fence.
    const FORMAT = "rootark-zk1-persisted-portable-chunk-inventory/v1";
    const DOMAIN = new TextEncoder().encode(
      "Root.ark/zk-1/persisted-portable-chunk-inventory/v1\0");
    const FIELDS = ["format", "scope", "ownerRevision", "ownerDigest", "ownerEpoch",
      "objectRevision", "chunkSha256", "chunkLengths", "ciphertextSha256", "ciphertextRoot"];
    const SCOPE = ["account_id", "compartment_id", "keyring_id"];
    const MAX_CHUNKS = 16;
    const MAX_CHUNK_BYTES = 1024 * 1024;
    const MAX_BYTES = 4 * 1024 * 1024;
    const encoder = new TextEncoder();
    const B64 = /^[A-Za-z0-9_-]+$/;

    function deny() { throw new Error("ZK_PERSISTED_PORTABLE_RECOVERY_DENIED"); }
    function exact(value, fields) {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
        || Reflect.ownKeys(value).length !== fields.length
        || Reflect.ownKeys(value).some((name) => typeof name !== "string"
          || !fields.includes(name))) deny();
      const copy = {};
      for (const name of fields) {
        const property = Object.getOwnPropertyDescriptor(value, name);
        if (!property || !Object.hasOwn(property, "value")) deny();
        copy[name] = property.value;
      }
      return copy;
    }
    function bytes(value, min, max = min) {
      if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)
        || value.byteLength < min || value.byteLength > max
        || (typeof SharedArrayBuffer !== "undefined"
          && (value instanceof SharedArrayBuffer || value.buffer instanceof SharedArrayBuffer))) deny();
      return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
        : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    function same(left, right) {
      if (left.length !== right.length) return false;
      let difference = 0;
      for (let i = 0; i < left.length; ++i) difference |= left[i] ^ right[i];
      return difference === 0;
    }
    function b64(raw) {
      let value = "";
      for (const part of raw) value += String.fromCharCode(part);
      return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function from64(value, length) {
      if (typeof value !== "string" || !B64.test(value)
        || value.length > Math.ceil(length * 4 / 3) + 4) deny();
      let binary;
      try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
      if (binary.length !== length) deny();
      const raw = Uint8Array.from(binary, (character) => character.charCodeAt(0));
      if (b64(raw) !== value) deny();
      return raw;
    }
    function positive(value) {
      if (!Number.isSafeInteger(value) || value < 1) deny();
      return value;
    }
    function live(callback) {
      if (typeof callback !== "function" || callback() !== undefined) deny();
    }
    function inventory(raw) {
      const record = exact(raw, [...FIELDS, "signature"]);
      if (record.format !== FORMAT) deny();
      const scope = exact(record.scope, SCOPE);
      for (const key of ["account_id", "keyring_id"]) from64(scope[key], 16);
      if (typeof scope.compartment_id !== "string" || !B64.test(scope.compartment_id)
        || scope.compartment_id.length > 171) deny();
      const decoded = atob(scope.compartment_id.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(scope.compartment_id.length / 4) * 4, "="));
      if (decoded.length < 1 || decoded.length > 128
        || b64(Uint8Array.from(decoded, (v) => v.charCodeAt(0))) !== scope.compartment_id) deny();
      record.scope = scope;
      positive(record.ownerRevision); positive(record.ownerEpoch); positive(record.objectRevision);
      from64(record.ownerDigest, 32);
      from64(record.ciphertextSha256, 32);
      from64(record.ciphertextRoot, 32);
      from64(record.signature, 64);
      if (!Array.isArray(record.chunkSha256) || !Array.isArray(record.chunkLengths)
        || record.chunkSha256.length < 1 || record.chunkSha256.length > MAX_CHUNKS
        || record.chunkSha256.length !== record.chunkLengths.length
        || Reflect.ownKeys(record.chunkSha256).length !== record.chunkSha256.length + 1
        || Reflect.ownKeys(record.chunkLengths).length !== record.chunkLengths.length + 1) deny();
      let total = 0;
      const sha = [], lengths = [];
      for (let i = 0; i < record.chunkSha256.length; ++i) {
        const length = record.chunkLengths[i];
        if (!Number.isSafeInteger(length) || length < 1 || length > MAX_CHUNK_BYTES
          || length > MAX_BYTES - total) deny();
        total += length;
        lengths.push(length);
        sha.push(record.chunkSha256[i]);
        from64(sha[i], 32);
      }
      record.chunkSha256 = sha;
      record.chunkLengths = lengths;
      return Object.freeze(record);
    }
    function signingMessage(record) {
      const body = encoder.encode(JSON.stringify(Object.fromEntries(FIELDS.map(
        (field) => [field, record[field]]))));
      const message = new Uint8Array(DOMAIN.length + body.length);
      message.set(DOMAIN); message.set(body, DOMAIN.length);
      return message;
    }
    async function createSignedPersistedPortableChunkInventory(input) {
      const captured = [];
      let ciphertext;
      try {
        const raw = exact(input, ["bundle", "ownerSigningKey", "ownerPublicKey",
          "independentOwnerSpkiSha256", "ownerHead", "chunks", "assertLive"]);
        const bundle = exact(raw.bundle, ["format", "metadata", "objectRevision",
          "ciphertextBase64", "ciphertextSha256", "ciphertextRoot", "wrap"]);
        const metadata = exact(bundle.metadata, ["account_id", "compartment_id",
          "keyring_id", "object_id", "version_id", "parent_version_id", "epoch", "kind"]);
        const head = exact(raw.ownerHead, ["revision", "digest", "epoch"]);
        if (bundle.format !== "rootark-zk1-portable-file-recovery/v1"
          || !Array.isArray(raw.chunks) || raw.chunks.length < 1
          || raw.chunks.length > MAX_CHUNKS
          || Reflect.ownKeys(raw.chunks).length !== raw.chunks.length + 1
          || positive(head.epoch) !== positive(metadata.epoch)
          || !crypto?.subtle || !roots?.computeCiphertextRoot) deny();
        const owner = raw.ownerPublicKey;
        const signingKey = raw.ownerSigningKey;
        if (!owner || owner.type !== "public" || owner.algorithm?.name !== "Ed25519"
          || !owner.usages?.includes("verify")
          || !signingKey || signingKey.type !== "private"
          || signingKey.algorithm?.name !== "Ed25519"
          || signingKey.extractable !== false || !signingKey.usages?.includes("sign")) deny();
        let total = 0;
        for (const rawChunk of raw.chunks) {
          const chunk = bytes(rawChunk, 1, MAX_CHUNK_BYTES);
          total += chunk.length;
          if (total > MAX_BYTES) deny();
          captured.push(chunk);
        }
        ciphertext = new Uint8Array(total);
        let cursor = 0;
        for (const chunk of captured) {
          ciphertext.set(chunk, cursor);
          cursor += chunk.length;
        }
        const spki = new Uint8Array(await crypto.subtle.exportKey("spki", owner));
        const fingerprint = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
        spki.fill(0);
        if (!same(fingerprint, bytes(raw.independentOwnerSpkiSha256, 32))) deny();
        const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", ciphertext));
        const root = new Uint8Array(await roots.computeCiphertextRoot([ciphertext]));
        if (bundle.ciphertextSha256 !== b64(hash)
          || bundle.ciphertextRoot !== b64(root)
          || bundle.ciphertextBase64 !== b64(ciphertext)) deny();
        live(raw.assertLive);
        const sha = [];
        for (const chunk of captured) {
          sha.push(b64(new Uint8Array(await crypto.subtle.digest("SHA-256", chunk))));
        }
        const scope = Object.fromEntries(SCOPE.map((key) => [key, metadata[key]]));
        const record = { format: FORMAT, scope,
          ownerRevision: positive(head.revision), ownerDigest: b64(bytes(head.digest, 32)),
          ownerEpoch: head.epoch, objectRevision: positive(bundle.objectRevision),
          chunkSha256: sha, chunkLengths: captured.map((chunk) => chunk.length),
          ciphertextSha256: b64(hash), ciphertextRoot: b64(root) };
        const signature = new Uint8Array(await crypto.subtle.sign("Ed25519",
          signingKey, signingMessage(record)));
        if (!await crypto.subtle.verify("Ed25519", owner, signature,
          signingMessage(record))) deny();
        live(raw.assertLive);
        return Object.freeze({ ...record, scope: Object.freeze(scope),
          chunkSha256: Object.freeze(sha),
          chunkLengths: Object.freeze(record.chunkLengths), signature: b64(signature) });
      } catch (_) { deny(); }
      finally {
        ciphertext?.fill(0);
        for (const chunk of captured) chunk.fill(0);
      }
    }
    async function recoverPersistedPortableChunks(input) {
      let secret, opened, combined;
      const captured = [];
      try {
        const raw = exact(input, ["bundle", "signedInventory", "expectedOwnerHead",
          "ownerPublicKey", "independentOwnerSpkiSha256", "expectedMetadata",
          "independentlyPinnedCiphertextRoot", "recoverySecret", "readChunk", "assertLive"]);
        if (!crypto?.subtle || !portable?.openWithIndependentRoot
          || !roots?.computeCiphertextRoot || typeof raw.readChunk !== "function") deny();
        const signed = inventory(raw.signedInventory);
        const current = exact(raw.expectedOwnerHead, ["revision", "digest", "epoch"]);
        const expected = exact(raw.expectedMetadata, ["account_id", "compartment_id",
          "keyring_id", "object_id", "version_id", "parent_version_id", "epoch", "kind"]);
        const retainedDigest = bytes(current.digest, 32);
        const independentlyPinnedRoot = bytes(raw.independentlyPinnedCiphertextRoot, 32);
        const ownerSpki = bytes(raw.independentOwnerSpkiSha256, 32);
        secret = bytes(raw.recoverySecret, 32);
        if (signed.ownerRevision !== positive(current.revision)
          || signed.ownerEpoch !== positive(current.epoch)
          || !same(from64(signed.ownerDigest, 32), retainedDigest)
          || signed.ownerEpoch !== positive(expected.epoch)
          || SCOPE.some((key) => signed.scope[key] !== expected[key])
          || raw.bundle?.objectRevision !== signed.objectRevision
          || !same(from64(signed.ciphertextRoot, 32), independentlyPinnedRoot)) deny();
        const owner = raw.ownerPublicKey;
        if (!owner || owner.type !== "public" || owner.algorithm?.name !== "Ed25519"
          || !owner.usages?.includes("verify")) deny();
        const spki = new Uint8Array(await crypto.subtle.exportKey("spki", owner));
        const fingerprint = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
        spki.fill(0);
        if (!same(fingerprint, ownerSpki)) deny();
        if (!await crypto.subtle.verify("Ed25519", owner,
          from64(signed.signature, 64), signingMessage(signed))) deny();
        live(raw.assertLive);
        // Every chunk must exist and match the owner's signed length/hash,
        // even when the portable bundle redundantly contains all ciphertext.
        for (let index = 0; index < signed.chunkLengths.length; ++index) {
          const part = bytes(await raw.readChunk({ index,
            scope: { ...signed.scope }, objectId: expected.object_id,
            revision: signed.objectRevision }), signed.chunkLengths[index]);
          captured.push(part);
          const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", part));
          if (!same(digest, from64(signed.chunkSha256[index], 32))) deny();
          live(raw.assertLive);
        }
        const total = signed.chunkLengths.reduce((sum, count) => sum + count, 0);
        combined = new Uint8Array(total);
        let cursor = 0;
        for (const part of captured) { combined.set(part, cursor); cursor += part.length; }
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", combined));
        const root = new Uint8Array(await roots.computeCiphertextRoot([combined]));
        if (!same(digest, from64(signed.ciphertextSha256, 32))
          || !same(root, independentlyPinnedRoot)
          || raw.bundle?.ciphertextSha256 !== signed.ciphertextSha256
          || raw.bundle?.ciphertextRoot !== signed.ciphertextRoot
          || b64(combined) !== raw.bundle?.ciphertextBase64) deny();
        opened = await portable.openWithIndependentRoot({ recoverySecret: secret,
          bundle: raw.bundle, expectedMetadata: expected,
          independentlyPinnedCiphertextRoot: independentlyPinnedRoot });
        live(raw.assertLive);
        return Object.freeze({ ...opened, persistedChunkInventoryVerified: true,
          ownerSignatureVerified: true, independentOwnerHeadMatched: true,
          currentOnlineRevocationVerified: false,
          independentRemoteDurabilityProven: false, authorizesProductionRestore: false });
      } catch (_) { opened?.data?.fill(0); deny(); }
      finally {
        secret?.fill(0); combined?.fill(0);
        for (const part of captured) part.fill(0);
      }
    }
    return Object.freeze({ createSignedPersistedPortableChunkInventory,
      recoverPersistedPortableChunks });
  }));
