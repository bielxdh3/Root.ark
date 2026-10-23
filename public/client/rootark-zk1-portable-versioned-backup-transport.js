(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./rootark-zk1-browser-versioned-archive"));
  } else {
    root.RootarkZk1PortableVersionedBackupTransport = factory(
      root.RootarkZk1BrowserVersionedArchive);
  }
}(typeof globalThis === "object" ? globalThis : this, function (versioned) {
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
  return Object.freeze({ preparePortableVersionedBackup,
    publishPreparedVersionedBackup, recoverPortableVersionedBackup });
}));
