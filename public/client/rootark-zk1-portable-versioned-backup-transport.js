(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./rootark-zk1-browser-versioned-archive"),
      require("./rootark-zk1-browser-catalog"));
  } else {
    root.RootarkZk1PortableVersionedBackupTransport = factory(
      root.RootarkZk1BrowserVersionedArchive, root.RootarkZk1BrowserCatalog);
  }
}(typeof globalThis === "object" ? globalThis : this, function (versioned, catalog) {
  "use strict";

  // DEV owner-held V2 transfer. The storage adapter is an untrusted,
  // authenticated create-only ciphertext store; it must never receive a CEK,
  // recovery secret or unencrypted file. Pin + recovery secret are transferred
  // out-of-band by the owner. No server/storage durability is proven here.
  const MAX_WIRE = 24 * 1024 * 1024;
  const preparedRecords = new WeakMap();
  const publishAttempted = new WeakSet();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const encoder = new TextEncoder();
  function deny() { throw new Error("ZK_PORTABLE_VERSIONED_BACKUP_DENIED"); }
  function exact(value, fields) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== fields.length
      || Reflect.ownKeys(value).some((key) => typeof key !== "string" || !fields.includes(key))
      || fields.some((key) => !Object.hasOwn(value, key))) deny();
  }
  function b64(value) {
    let raw = "";
    for (const byte of value) raw += String.fromCharCode(byte);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function copy(value, min, max = min) {
    if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)
      || !Number.isSafeInteger(value.byteLength)
      || value.byteLength < min || value.byteLength > max
      || (typeof SharedArrayBuffer !== "undefined"
        && (value instanceof SharedArrayBuffer || value.buffer instanceof SharedArrayBuffer))) deny();
    return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
      : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  function adapter(provider, write = false) {
    if (!provider || typeof provider.get !== "function"
      || (write && typeof provider.putIfAbsent !== "function")) deny();
  }
  function assertLive(callback) {
    if (typeof callback !== "function" || callback() !== undefined) deny();
  }
  function canonicalArchive(raw) {
    const bytes = copy(raw, 2, MAX_WIRE);
    try {
      const text = decoder.decode(bytes);
      const parsed = JSON.parse(text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)
        || JSON.stringify(parsed) !== text) deny();
      // The signed archive verifier enforces all schema, key and digest fields.
      return parsed;
    } catch (_) { deny(); }
    finally { bytes.fill(0); }
  }
  function archiveWire(archive) {
    const data = encoder.encode(JSON.stringify(archive));
    if (data.length < 2 || data.length > MAX_WIRE) deny();
    return data;
  }

  async function preparePortableVersionedBackup(input) {
    try {
      exact(input, ["archiveInput", "versions", "verifiedAuthority", "assertLive"]);
      assertLive(input.assertLive);
      const sealed = await versioned.createArchive(input);
      assertLive(input.assertLive);
      const archivePin = copy(sealed.archiveSha256, 32);
      const prepared = Object.freeze({ archive: sealed.archive,
        archivePin: new Uint8Array(archivePin),
        authorizesCutover: false, independentDurabilityProven: false });
      // Preserve the original immutable-by-serialization archive independently
      // from any caller mutations while a network write is outstanding.
      preparedRecords.set(prepared, Object.freeze({ pin: b64(archivePin),
        pinBytes: new Uint8Array(archivePin), wire: archiveWire(sealed.archive) }));
      archivePin.fill(0);
      return prepared;
    } catch (_) { deny(); }
  }

  async function publishPreparedVersionedBackup(input) {
    let readback;
    try {
      exact(input, ["prepared", "provider", "assertLive"]);
      const prepared = preparedRecords.get(input.prepared);
      if (!prepared || publishAttempted.has(input.prepared)) deny();
      adapter(input.provider, true);
      assertLive(input.assertLive);
      // No auto-retry after an ambiguous ACK, even when PUT might have
      // committed. The owner can reconcile on a different device via GET.
      publishAttempted.add(input.prepared);
      if (await input.provider.putIfAbsent({
        key: prepared.pin, bytes: new Uint8Array(prepared.wire),
      }) !== true) deny();
      assertLive(input.assertLive);
      readback = copy(await input.provider.get({ key: prepared.pin }), 2, MAX_WIRE);
      assertLive(input.assertLive);
      if (readback.length !== prepared.wire.length) deny();
      let difference = 0;
      for (let i = 0; i < readback.length; ++i)
        difference |= readback[i] ^ prepared.wire[i];
      if (difference !== 0) deny();
      return Object.freeze({ archivePin: new Uint8Array(prepared.pinBytes),
        remoteCiphertextReadbackVerified: true,
        independentDurabilityProven: false, authorizesCutover: false,
        authorizesProductionRestore: false });
    } catch (_) { deny(); }
    finally { readback?.fill(0); }
  }

  async function recoverPortableVersionedBackup(input) {
    let raw, opened, pin, recoverySecret;
    try {
      exact(input, ["archivePin", "provider", "recoveryInput",
        "verifiedAuthority", "assertLive"]);
      pin = copy(input.archivePin, 32);
      const key = b64(pin);
      adapter(input.provider);
      if (!input.recoveryInput || typeof input.recoveryInput !== "object"
        || Object.hasOwn(input.recoveryInput, "archive")
        || Object.hasOwn(input.recoveryInput, "independentlyPinnedArchiveSha256")) deny();
      const original = input.recoveryInput;
      recoverySecret = copy(original.recoverySecret, 32);
      const recoveryInput = { ...original, recoverySecret,
        independentOwnerSpkiSha256: copy(original.independentOwnerSpkiSha256, 32),
        signerKeyId: copy(original.signerKeyId, 16),
        scope: { ...original.scope },
        pinnedCurrentHead: { ...original.pinnedCurrentHead,
          digest: copy(original.pinnedCurrentHead?.digest, 32) } };
      assertLive(input.assertLive);
      raw = copy(await input.provider.get({ key }), 2, MAX_WIRE);
      assertLive(input.assertLive);
      const archive = canonicalArchive(raw);
      // Verify owner Ed25519 signature, independent pin, history/grant,
      // complete inventory, roster, version ancestry, every CEK and ciphertext
      // before returning even one plaintext-equivalent CEK.
      opened = await versioned.recoverArchive({
        recoveryInput: { ...recoveryInput,
          archive, independentlyPinnedArchiveSha256: pin },
        verifiedAuthority: input.verifiedAuthority, assertLive: input.assertLive,
      });
      assertLive(input.assertLive);
      return opened;
    } catch (_) {
      for (const item of opened?.files || []) {
        item.cek?.fill(0);
        item.ciphertext?.fill(0);
      }
      deny();
    } finally { raw?.fill(0); pin?.fill(0); recoverySecret?.fill(0); }
  }
  async function recoverPortableVersionedBackupWithSignedCatalog(input) {
    let recovered;
    try {
      exact(input, ["archivePin", "provider", "recoveryInput",
        "verifiedAuthority", "assertLive", "catalogInput"]);
      if (!catalog?.openCatalog || !catalog?.assertVersionedArchiveMatchesCatalog
        || !input.catalogInput || input.catalogInput.assertLive !== input.assertLive) deny();
      // Require an authenticated signed CAS/catalog preflight BEFORE the
      // remote archive GET and CEK decryption. A stale owner/catalog pin
      // cannot cause even an attempted cloud handoff in this opt-in mode.
      const startingCatalog = await catalog.openCatalog(input.catalogInput);
      assertLive(input.assertLive);
      recovered = await recoverPortableVersionedBackup({
        archivePin: input.archivePin, provider: input.provider,
        recoveryInput: input.recoveryInput,
        verifiedAuthority: input.verifiedAuthority, assertLive: input.assertLive,
      });
      assertLive(input.assertLive);
      // Re-probe the same signed CAS head after cloud transfer and decrypt:
      // a concurrent catalog move must not release an archival CEK set.
      const verified = await catalog.openCatalog(input.catalogInput);
      if (startingCatalog.sequence !== verified.sequence
        || startingCatalog.catalogDigest !== verified.catalogDigest
        || startingCatalog.totalCount !== verified.totalCount) deny();
      const crossCheck = await catalog.assertVersionedArchiveMatchesCatalog({
        catalog: verified, files: recovered.files,
      });
      if (crossCheck.signedCatalogCasCoverageVerified !== true
        || crossCheck.protectedCiphertextReadbackVerified !== true
        || crossCheck.authorizesCutover !== false) deny();
      // Each protected historical GET is asynchronous. A newer, genuinely
      // signed CAS successor can commit after the second preflight while an
      // old ciphertext is in flight. Reauthenticate the complete head AFTER
      // the last GET; a changed head must zero all decrypted CEKs below.
      const finalCatalog = await catalog.openCatalog(input.catalogInput);
      if (finalCatalog.sequence !== verified.sequence
        || finalCatalog.catalogDigest !== verified.catalogDigest
        || finalCatalog.totalCount !== verified.totalCount) deny();
      assertLive(input.assertLive);
      return Object.freeze({ ...recovered, signedCatalogCasCoverageVerified: true,
        protectedCiphertextReadbackVerified: true, authorizesProductionRestore: false,
        independentDurabilityProven: false });
    } catch (_) {
      // Decrypted historical CEKs remain internal until the ENTIRE signed
      // catalog and physical GET comparison finishes. No partial release.
      for (const file of recovered?.files || []) {
        file.cek?.fill(0);
        file.ciphertext?.fill(0);
      }
      deny();
    }
  }
  return Object.freeze({ preparePortableVersionedBackup,
    publishPreparedVersionedBackup, recoverPortableVersionedBackup,
    recoverPortableVersionedBackupWithSignedCatalog });
}));
