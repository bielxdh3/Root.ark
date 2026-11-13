(function (root, factory) {
  if (typeof module === "object" && module.exports)
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-file-content"));
  else root.RootarkZk1SelectedLocalPreview = factory(root.crypto, root.RootarkZk1FileContent);
}(typeof globalThis === "object" ? globalThis : this,
  function (webCrypto, fileContent) {
    "use strict";
    // This is a local opener, not a CEK authority. The caller must use the
    // authenticated selected GET and supply owner-held metadata and a CEK
    // fingerprint pinned independently of the application server.
    const MAX_WIRE = 4 * 1024 * 1024;
    const MAX_PREVIEW = 64 * 1024;
    const digest = /^[A-Za-z0-9_-]{43}$/;
    const opaqueId = /^[A-Za-z0-9_-]{22}$/;
    const permittedTypes = new Set(["text/plain", "text/markdown",
      "text/csv", "application/json"]);
    const decoder = new TextDecoder("utf-8", { fatal: true });
    function deny() { throw Error("ZK_SELECTED_PREVIEW_DENIED"); }
    function encode64(bytes) {
      let text = "";
      for (const byte of bytes) text += String.fromCharCode(byte);
      return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function decode64(text, length, maximum = length) {
      if (typeof text !== "string" || !/^[A-Za-z0-9_-]+$/.test(text)
        || text.length > Math.ceil(maximum * 4 / 3) + 4) deny();
      const raw = Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(text.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
      if (raw.length < length || raw.length > maximum || encode64(raw) !== text) deny();
      return raw;
    }
    function live(check) {
      if (typeof check !== "function") deny();
      const result = check();
      if (result === false || result && typeof result.then === "function") deny();
    }
    function validId(text, min = 16, max = min) {
      if (min === 16 && max === 16 && !opaqueId.test(text)) deny();
      decode64(text, min, max);
    }
    function positive(number) {
      if (!Number.isSafeInteger(number) || number < 1) deny();
    }
    function prepare(input) {
      const { selected, checked, metadata, baseline, grant, ownerHead } = input;
      if (!selected || !checked || !metadata || !baseline || !grant || !ownerHead
        || !webCrypto?.subtle || typeof fileContent?.decryptFile !== "function"
        || typeof fileContent?.importFileCek !== "function") deny();
      validId(selected.objectId);
      positive(selected.revision); positive(selected.epoch);
      positive(ownerHead.revision); positive(ownerHead.epoch);
      positive(grant.current_epoch); positive(grant.manifest_revision);
      if (!digest.test(ownerHead.digest) || !digest.test(grant.manifest_digest)
        || !digest.test(selected.ciphertextDigestBase64)
        || !digest.test(checked.ciphertextDigestBase64)
        || grant.manifest_revision !== ownerHead.revision
        || grant.manifest_digest !== ownerHead.digest
        || grant.current_epoch !== ownerHead.epoch
        || grant.revoked_at_epoch !== null || selected.epoch > ownerHead.epoch
        || checked.verifiedCiphertext !== true
        || checked.plaintextAvailable !== false
        || checked.authorizesMutation !== false
        || checked.objectId !== selected.objectId
        || checked.revision !== selected.revision
        || checked.epoch !== selected.epoch
        || checked.ciphertextDigestBase64 !== selected.ciphertextDigestBase64
        || !Array.isArray(baseline.entries) || baseline.entries.length > 4096
        || baseline.entries.filter((row) =>
          row.objectId === selected.objectId && row.revision === selected.revision
          && row.epoch === selected.epoch
          && row.ciphertextDigestBase64 === selected.ciphertextDigestBase64).length !== 1
        || !Number.isSafeInteger(baseline.head?.sequence)
        || baseline.head.sequence < 1 || !digest.test(baseline.head.digest)
        || Reflect.ownKeys(metadata).length !== 8
        || !["account_id", "compartment_id", "keyring_id", "object_id",
          "version_id", "parent_version_id", "epoch", "kind"]
          .every((key) => Object.hasOwn(metadata, key))
        || metadata.object_id !== selected.objectId
        || metadata.epoch !== selected.epoch || metadata.kind !== "file") deny();
      validId(metadata.version_id);
      if (metadata.parent_version_id !== null) validId(metadata.parent_version_id);
      for (const name of ["account_id", "compartment_id", "keyring_id"]) {
        validId(grant[name], name === "compartment_id" ? 1 : 16,
          name === "compartment_id" ? 128 : 16);
        if (metadata[name] !== grant[name]) deny();
      }
      if (!(input.rawCek instanceof Uint8Array) || input.rawCek.length !== 32
        || !digest.test(input.cekSha256Pin)) deny();
    }
    async function open(input) {
      let sealed = null, opened = null;
      try {
        live(input?.assertLive);
        prepare(input);
        // The fingerprint must have been independently fixed by the owner.
        const actualKeyPin = encode64(new Uint8Array(
          await webCrypto.subtle.digest("SHA-256", input.rawCek)));
        live(input.assertLive);
        if (actualKeyPin !== input.cekSha256Pin) deny();
        sealed = decode64(input.checked.ciphertextBase64, 16, MAX_WIRE);
        const actualCipherDigest = encode64(new Uint8Array(
          await webCrypto.subtle.digest("SHA-256", sealed)));
        live(input.assertLive);
        if (actualCipherDigest !== input.selected.ciphertextDigestBase64) deny();
        const cek = await fileContent.importFileCek(input.rawCek);
        live(input.assertLive);
        opened = await fileContent.decryptFile({ cek,
          metadata: input.metadata, envelopeBytes: sealed });
        live(input.assertLive);
        if (!permittedTypes.has(opened.mediaType)
          || !(opened.data instanceof Uint8Array)
          || opened.data.length > MAX_PREVIEW) deny();
        const text = decoder.decode(opened.data);
        live(input.assertLive);
        return Object.freeze({ objectId: input.selected.objectId,
          revision: input.selected.revision, epoch: input.selected.epoch,
          name: opened.name, mediaType: opened.mediaType, text,
          plaintextSentToServer: false });
      } catch (_) { deny(); }
      finally { sealed?.fill(0); opened?.data?.fill(0); }
    }
    return Object.freeze({ open });
  }));
