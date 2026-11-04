(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-keyring-portable-archive"));
  } else {
    root.RootarkZk1AccountPortableRecovery = factory(root.crypto,
      root.RootarkZk1KeyringPortableArchive);
  }
}(typeof globalThis === "object" ? globalThis : this, function (crypto, keyrings) {
  "use strict";

  // DEV/offline snapshot coordinator. It is NOT dual-authority recovery,
  // live revocation checking, or permission to restore in production.
  // Independently preserve the exact account SHA-256, owner SPKI fingerprint,
  // and each keyring's CURRENT owner head outside both server and archive.
  const FORMAT = "rootark-zk1-account-portable-recovery/v1";
  const DOMAIN = new TextEncoder().encode("Root.ark/zk-1/account-portable-recovery/v1\0");
  const MAX_KEYRINGS = 8;
  const MAX_BYTES = 16 * 1024 * 1024;
  const SCOPE = ["account_id", "compartment_id", "keyring_id"];
  const HEAD = ["revision", "digest", "epoch"];
  const ARCHIVE_FIELDS = ["format", "scope", "ownerRevision", "ownerDigest", "ownerEpoch",
    "archiveId", "salt", "nonce", "ciphertextBase64", "signature"];
  const ENTRY = ["scope", "ownerRevision", "ownerDigest", "ownerEpoch",
    "archiveSha256", "archive"];
  const SIGNED = ["format", "accountId", "keyrings"];
  const OUTER = [...SIGNED, "signature"];
  const enc = new TextEncoder();
  const canonical64 = /^[A-Za-z0-9_-]+$/;
  function deny() { throw new Error("ZK_ACCOUNT_PORTABLE_RECOVERY_DENIED"); }
  function exact(value, fields) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== fields.length) deny();
    for (const name of fields) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
    }
    if (Reflect.ownKeys(value).some((field) => typeof field !== "string"
      || !fields.includes(field))) deny();
  }
  function array(value) {
    if (!Array.isArray(value) || value.length < 1 || value.length > MAX_KEYRINGS
      || Reflect.ownKeys(value).length !== value.length + 1) deny();
    return Array.from({ length: value.length }, (_, i) => {
      const slot = Object.getOwnPropertyDescriptor(value, String(i));
      if (!slot || !Object.hasOwn(slot, "value")) deny();
      return slot.value;
    });
  }
  function bytes(value, count) {
    if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)
      || value.byteLength !== count || (typeof SharedArrayBuffer !== "undefined"
        && (value instanceof SharedArrayBuffer || value.buffer instanceof SharedArrayBuffer))) deny();
    return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
      : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  function b64(raw) {
    let s = "";
    for (const n of raw) s += String.fromCharCode(n);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(value, count) {
    if (typeof value !== "string" || !canonical64.test(value)
      || value.length > Math.ceil(count * 4 / 3) + 4) deny();
    let text;
    try { text = atob(value.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
    if (text.length !== count) deny();
    const result = Uint8Array.from(text, (ch) => ch.charCodeAt(0));
    if (b64(result) !== value) deny();
    return result;
  }
  function scope(value) {
    exact(value, SCOPE);
    const copy = Object.fromEntries(SCOPE.map((field) => [field, value[field]]));
    from64(copy.account_id, 16);
    from64(copy.keyring_id, 16);
    if (typeof copy.compartment_id !== "string" || !canonical64.test(copy.compartment_id)
      || copy.compartment_id.length > 171) deny();
    // Compartment ID is a canonical base64url encoding of 1..128 bytes.
    const chars = copy.compartment_id;
    let raw;
    try { raw = atob(chars.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(chars.length / 4) * 4, "=")); } catch (_) { deny(); }
    if (raw.length < 1 || raw.length > 128 || b64(Uint8Array.from(raw, (c) => c.charCodeAt(0))) !== chars) deny();
    return copy;
  }
  function head(value) {
    exact(value, HEAD);
    if (!Number.isSafeInteger(value.revision) || value.revision < 1
      || !Number.isSafeInteger(value.epoch) || value.epoch < 1) deny();
    return { revision: value.revision, digest: bytes(value.digest, 32), epoch: value.epoch };
  }
  function same(a, b) {
    if (a.length !== b.length) return false;
    let unequal = 0;
    for (let i = 0; i < a.length; i++) unequal |= a[i] ^ b[i];
    return unequal === 0;
  }
  function key(value, type) {
    if (!value || value.type !== type || value.algorithm?.name !== "Ed25519"
      || !value.usages?.includes(type === "public" ? "verify" : "sign")
      || (type === "private" && value.extractable !== false)) deny();
    return value;
  }
  async function ownerPin(publicKey, pin) {
    const exported = new Uint8Array(await crypto.subtle.exportKey("spki", key(publicKey, "public")));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", exported));
    exported.fill(0);
    if (!same(digest, pin)) deny();
  }
  function order(entries, accountId) {
    let prior = null;
    const ids = new Set();
    for (const entry of entries) {
      const sc = entry.scope;
      if (sc.account_id !== accountId || ids.has(sc.keyring_id)) deny();
      const next = `${sc.compartment_id}:${sc.keyring_id}`;
      if (prior !== null && prior >= next) deny();
      prior = next;
      ids.add(sc.keyring_id);
    }
  }
  function copyArchive(value) {
    exact(value, ARCHIVE_FIELDS);
    const result = Object.fromEntries(ARCHIVE_FIELDS.map((field) => [field, value[field]]));
    result.scope = scope(result.scope);
    if (result.format !== "rootark-zk1-keyring-portable-archive/v1"
      || !Number.isSafeInteger(result.ownerRevision) || result.ownerRevision < 1
      || !Number.isSafeInteger(result.ownerEpoch) || result.ownerEpoch < 1
      || typeof result.ciphertextBase64 !== "string" || !canonical64.test(result.ciphertextBase64)
      || result.ciphertextBase64.length > MAX_BYTES * 4 / 3 + 8) deny();
    from64(result.ownerDigest, 32);
    from64(result.archiveId, 16); from64(result.salt, 32);
    from64(result.nonce, 12); from64(result.signature, 64);
    return result;
  }
  function copyEntry(value) {
    exact(value, ENTRY);
    const sc = scope(value.scope);
    const archive = copyArchive(value.archive);
    if (!SCOPE.every((field) => sc[field] === archive.scope[field])
      || value.ownerRevision !== archive.ownerRevision
      || value.ownerDigest !== archive.ownerDigest
      || value.ownerEpoch !== archive.ownerEpoch) deny();
    from64(value.archiveSha256, 32);
    return { scope: sc, ownerRevision: archive.ownerRevision,
      ownerDigest: archive.ownerDigest, ownerEpoch: archive.ownerEpoch,
      archiveSha256: value.archiveSha256, archive };
  }
  function copyAccountArchive(value) {
    exact(value, OUTER);
    if (value.format !== FORMAT) deny();
    from64(value.accountId, 16); from64(value.signature, 64);
    const entries = array(value.keyrings).map(copyEntry);
    order(entries, value.accountId);
    return { format: FORMAT, accountId: value.accountId, keyrings: entries,
      signature: value.signature };
  }
  function copySignedWire(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny();
    const names = Reflect.ownKeys(value);
    if (names.length < 1 || names.length > 20) deny();
    const record = {};
    for (const name of names) {
      if (typeof name !== "string" || name.length > 80) deny();
      const d = Object.getOwnPropertyDescriptor(value, name);
      if (!d || !Object.hasOwn(d, "value")
        || !(typeof d.value === "string" || d.value === null
          || Number.isSafeInteger(d.value))
        || (typeof d.value === "string" && d.value.length > 2048)) deny();
      record[name] = d.value;
    }
    return Object.freeze(record);
  }
  function copyHistoricalRecovery(value) {
    exact(value, ["signedOwnerHistoryChain", "currentSignedDeviceGrant",
      "currentOwnerRootCheckpoints", "devicePoP"]);
    function bounded(list, max) {
      if (!Array.isArray(list) || list.length < 1 || list.length > max
        || Reflect.ownKeys(list).length !== list.length + 1) deny();
      return Array.from({ length: list.length }, (_, i) => {
        const d = Object.getOwnPropertyDescriptor(list, String(i));
        if (!d || !Object.hasOwn(d, "value")) deny();
        return copySignedWire(d.value);
      });
    }
    const proof = value.devicePoP;
    exact(proof, ["challenge", "signature"]);
    const challenge = Object.getOwnPropertyDescriptor(proof, "challenge");
    const signature = Object.getOwnPropertyDescriptor(proof, "signature");
    if (!challenge || !Object.hasOwn(challenge, "value")
      || !signature || !Object.hasOwn(signature, "value")) deny();
    from64(signature.value, 64);
    return { signedOwnerHistoryChain: bounded(value.signedOwnerHistoryChain, 64),
      currentSignedDeviceGrant: copySignedWire(value.currentSignedDeviceGrant),
      currentOwnerRootCheckpoints: bounded(value.currentOwnerRootCheckpoints, 12),
      devicePoP: Object.freeze({ challenge: challenge.value,
        signature: signature.value }) };
  }
  function immutableArchive(value) {
    for (const entry of value.keyrings) {
      Object.freeze(entry.scope);
      Object.freeze(entry.archive.scope);
      Object.freeze(entry.archive);
      Object.freeze(entry);
    }
    Object.freeze(value.keyrings);
    return Object.freeze(value);
  }
  function encoded(value) {
    const raw = enc.encode(JSON.stringify(value));
    if (raw.length > MAX_BYTES) deny();
    return raw;
  }
  function signedMessage(value) {
    const canonical = encoded(Object.fromEntries(SIGNED.map((field) => [field, value[field]])));
    const data = new Uint8Array(DOMAIN.length + canonical.length);
    data.set(DOMAIN); data.set(canonical, DOMAIN.length);
    return data;
  }
  async function digestAccount(value) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", encoded(value)));
  }
  async function createArchive(input) {
    try {
      exact(input, ["accountId", "ownerSigningKey", "ownerPublicKey",
        "independentOwnerSpkiSha256", "keyrings"]);
      if (!crypto?.subtle || !keyrings?.createArchive) deny();
      from64(input.accountId, 16);
      const ownerPublicKey = key(input.ownerPublicKey, "public");
      const ownerSigningKey = key(input.ownerSigningKey, "private");
      const trustedSpki = bytes(input.independentOwnerSpkiSha256, 32);
      const entries = array(input.keyrings).map((item) => {
        if (!item || typeof item !== "object") deny();
        const sc = scope(item.scope);
        if (sc.account_id !== input.accountId
          || !same(bytes(item.independentOwnerSpkiSha256, 32), trustedSpki)) deny();
        return { scope: sc, options: item };
      });
      entries.sort((a, b) => {
        const left = a.scope.compartment_id + ":" + a.scope.keyring_id;
        const right = b.scope.compartment_id + ":" + b.scope.keyring_id;
        return left < right ? -1 : left > right ? 1 : 0;
      });
      order(entries, input.accountId);
      // All keyring createArchive calls synchronously snapshot their input
      // before the first await; kick them off together to fence caller mutation.
      const creations = entries.map((entry) => keyrings.createArchive(entry.options));
      const sealed = await Promise.all(creations);
      await ownerPin(ownerPublicKey, trustedSpki);
      const inventory = sealed.map(({ archive, archiveSha256 }, index) => {
        const verified = copyArchive(archive);
        if (!SCOPE.every((field) => verified.scope[field] === entries[index].scope[field])) deny();
        return { scope: verified.scope, ownerRevision: verified.ownerRevision,
          ownerDigest: verified.ownerDigest, ownerEpoch: verified.ownerEpoch,
          archiveSha256: b64(bytes(archiveSha256, 32)), archive: verified };
      });
      const unsigned = { format: FORMAT, accountId: input.accountId, keyrings: inventory };
      const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", ownerSigningKey,
        signedMessage(unsigned)));
      if (!await crypto.subtle.verify("Ed25519", ownerPublicKey, signature,
        signedMessage(unsigned))) deny();
      const archive = immutableArchive(copyAccountArchive({
        ...unsigned, signature: b64(signature) }));
      const archiveSha256 = await digestAccount(archive);
      return Object.freeze({ archive, archiveSha256,
        independentlyPinnedByModule: false, authorizesProductionRestore: false });
    } catch (_) { deny(); }
  }
  async function recoverArchive(input) {
    const opened = [];
    let requested = [];
    try {
      exact(input, ["accountArchive", "independentlyPinnedAccountSha256", "accountId",
        "ownerPublicKey", "independentOwnerSpkiSha256", "keyrings"]);
      const archived = copyAccountArchive(input.accountArchive);
      if (archived.accountId !== input.accountId) deny();
      const ownerPublicKey = key(input.ownerPublicKey, "public");
      const spki = bytes(input.independentOwnerSpkiSha256, 32);
      const accountPin = bytes(input.independentlyPinnedAccountSha256, 32);
      // Snapshot every keyring's external trust material and holder secret
      // before any await. Delayed async verification cannot switch pins.
      for (const value of array(input.keyrings)) {
        const historic = Object.hasOwn(value || {}, "historicalRecovery");
        exact(value, ["scope", "pinnedCurrentHead", "recoverySecret",
          "ownerPublicKey", "independentOwnerSpkiSha256", "signerKeyId",
          "deviceId", "previousOwnerHistoryProof",
          ...(historic ? ["historicalRecovery"] : [])]);
        // Capture every fallible signed-wire/pin field first. The 256-bit
        // holder-secret copy is last, so a rejected history cannot strand a
        // secret allocation outside the finally zeroization list.
        const historicalRecovery = historic ? copyHistoricalRecovery(value.historicalRecovery) : null;
        const ringScope = scope(value.scope);
        const ringHead = head(value.pinnedCurrentHead);
        const ringOwnerPin = bytes(value.independentOwnerSpkiSha256, 32);
        const ringSigner = bytes(value.signerKeyId, 16);
        requested.push({ scope: ringScope, pinnedCurrentHead: ringHead,
          recoverySecret: bytes(value.recoverySecret, 32),
          ownerPublicKey: value.ownerPublicKey,
          independentOwnerSpkiSha256: ringOwnerPin,
          signerKeyId: ringSigner, deviceId: value.deviceId,
          previousOwnerHistoryProof: value.previousOwnerHistoryProof,
          ...(historic ? { historicalRecovery } : {}) });
      }
      if (requested.length !== archived.keyrings.length) deny();
      // Aggregate pin must be obtained independently: the archive is not its source.
      if (!same(await digestAccount(archived), accountPin)) deny();
      await ownerPin(ownerPublicKey, spki);
      if (!await crypto.subtle.verify("Ed25519", ownerPublicKey,
        from64(archived.signature, 64), signedMessage(archived))) deny();
      for (let index = 0; index < requested.length; index++) {
        const expected = requested[index];
        const archivedKeyring = archived.keyrings[index];
        const sc = expected.scope;
        if (!SCOPE.every((field) => sc[field] === archivedKeyring.scope[field])
          || !same(expected.independentOwnerSpkiSha256, spki)) deny();
        const pinnedHead = expected.pinnedCurrentHead;
        if (!Object.hasOwn(expected, "historicalRecovery")
          && (pinnedHead.revision !== archivedKeyring.ownerRevision
            || pinnedHead.epoch !== archivedKeyring.ownerEpoch
            || b64(pinnedHead.digest) !== archivedKeyring.ownerDigest)) deny();
        const result = await keyrings.recoverArchive({ archive: archivedKeyring.archive,
          independentlyPinnedArchiveSha256: from64(archivedKeyring.archiveSha256, 32),
          recoverySecret: expected.recoverySecret, ownerPublicKey: expected.ownerPublicKey,
          independentOwnerSpkiSha256: spki, pinnedCurrentHead: pinnedHead,
          scope: sc, signerKeyId: expected.signerKeyId,
          deviceId: expected.deviceId,
          previousOwnerHistoryProof: expected.previousOwnerHistoryProof,
          ...(Object.hasOwn(expected, "historicalRecovery")
            ? { historicalRecovery: expected.historicalRecovery,
              accountArchiveSha256: accountPin } : {}) });
        opened.push({ scope: sc, files: result.files });
      }
      // Return plaintext only once every keyring has passed signed history,
      // signed grant, signed roots and authenticated decryption checks.
      return Object.freeze({ keyrings: Object.freeze(opened.map((item) => Object.freeze(item))),
        allKeyringsVerified: true, aggregateSignatureVerified: true,
        aggregateIndependentPinMatched: true, currentOnlineRevocationVerified: false,
        authorizesProductionRestore: false });
    } catch (_) {
      for (const ring of opened) for (const file of ring.files) file.data?.fill(0);
      deny();
    } finally {
      for (const item of requested) {
        item.recoverySecret.fill(0);
        item.pinnedCurrentHead.digest.fill(0);
        item.signerKeyId.fill(0);
        item.independentOwnerSpkiSha256.fill(0);
      }
    }
  }
  return Object.freeze({ createArchive, recoverArchive });
}));
