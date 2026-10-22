(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-owner-signed-checkpoint"));
  } else {
    root.RootarkZk1NormalBrowserTrustFloor = factory(root.crypto,
      root.RootarkZk1OwnerSignedCheckpoint);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto, ownerHistory) {
  "use strict";

  // A local monotonic floor is only a second line of defence. Deleting the
  // browser profile or restoring its complete old snapshot removes this floor.
  // Keep the owner SPKI fingerprint and newest head independently OFF-SERVER.
  // Only an explicit offline-provision action can create or advance the floor.
  const DB = "rootark-zk1-normal-browser-owner-floor-v1";
  const STORE = "owners";
  const SCHEMA = "rootark-zk1-normal-browser-owner-floor/v1";
  const GRANT_SCHEMA = "rootark-zk1-browser-owner-device-grant/v1";
  const DOMAIN = new TextEncoder().encode("Root.ark/zk-1/browser-owner-device-grant/v1\0");
  const SCOPE = ["account_id", "compartment_id", "keyring_id"];
  const GRANT = ["schema", ...SCOPE, "device_id", "authorization_key_id",
    "authorization_public_key", "manifest_revision", "manifest_digest",
    "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
  const WIRE = [...GRANT, "signature"];
  const ANCHOR = ["ownerPublicKey", "independentOwnerSpkiSha256", "pinnedCurrentHead",
    "signedDeviceGrant", "ownerHistoryCheckpoint"];
  const RECORD = ["schema", "ownerSpkiSha256", "revision", "digest", "epoch"];
  const re64 = /^[A-Za-z0-9_-]+$/;

  function deny() { throw new Error("ZK_NORMAL_BROWSER_LOCAL_FLOOR_UNVERIFIED"); }
  function exact(value, fields) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== fields.length
      || fields.some((field) => !Object.hasOwn(value, field))) deny();
  }
  function uint(value) {
    if (!Number.isSafeInteger(value) || value < 1) deny();
    return value;
  }
  function bytes(value, count) {
    if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)
      || value.byteLength !== count) deny();
    return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
      : new Uint8Array(value.buffer.slice(value.byteOffset,
        value.byteOffset + value.byteLength));
  }
  function b64(value) {
    let result = "";
    for (const item of value) result += String.fromCharCode(item);
    return btoa(result).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(value, size, max = size) {
    if (typeof value !== "string" || !re64.test(value)
      || value.length > Math.ceil(max * 4 / 3) + 4) deny();
    let decoded;
    try { decoded = atob(value.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
    const result = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
    if (result.length < size || result.length > max || b64(result) !== value) deny();
    return result;
  }
  function normalized(raw) {
    exact(raw, RECORD);
    if (raw.schema !== SCHEMA) deny();
    from64(raw.ownerSpkiSha256, 32);
    from64(raw.digest, 32);
    uint(raw.revision);
    uint(raw.epoch);
    return raw;
  }
  function transition(previous, next) {
    if (previous === null) return;
    normalized(previous);
    if (previous.ownerSpkiSha256 !== next.ownerSpkiSha256
      || next.revision < previous.revision
      || next.epoch < previous.epoch
      || (next.revision === previous.revision
        && (next.digest !== previous.digest || next.epoch !== previous.epoch))) deny();
  }
  async function verifyExternalAnchor(input) {
    try {
      const priorProvided = Object.hasOwn(input || {}, "previousOwnerHistoryProof");
      exact(input, priorProvided ? [...ANCHOR, "previousOwnerHistoryProof"] : ANCHOR);
      const key = input.ownerPublicKey;
      if (key?.type !== "public" || key.algorithm?.name !== "Ed25519"
        || !key.usages?.includes("verify") || !webCrypto?.subtle) deny();
      const spki = new Uint8Array(await webCrypto.subtle.exportKey("spki", key));
      // Compare SHA-256 of the complete DER SPKI, not the raw 32-byte key.
      const expectedSpki = bytes(input.independentOwnerSpkiSha256, 32);
      const actualSpki = new Uint8Array(await webCrypto.subtle.digest("SHA-256", spki));
      if (b64(actualSpki) !== b64(expectedSpki)) deny();
      exact(input.pinnedCurrentHead, ["revision", "digest", "epoch"]);
      const candidate = {
        schema: SCHEMA, ownerSpkiSha256: b64(expectedSpki),
        revision: uint(input.pinnedCurrentHead.revision),
        digest: b64(bytes(input.pinnedCurrentHead.digest, 32)),
        epoch: uint(input.pinnedCurrentHead.epoch),
      };
      exact(input.signedDeviceGrant, WIRE);
      // Snapshot every signed field before WebCrypto yields. Otherwise a
      // concurrent mutation could switch the IndexedDB scope after signature
      // verification and poison another owner's floor.
      const grant = Object.fromEntries(WIRE.map((name) =>
        [name, input.signedDeviceGrant[name]]));
      if (grant.schema !== GRANT_SCHEMA || grant.manifest_revision !== candidate.revision
        || grant.manifest_digest !== candidate.digest
        || grant.current_epoch !== candidate.epoch) deny();
      for (const name of SCOPE) from64(grant[name], name === "compartment_id" ? 1 : 16,
        name === "compartment_id" ? 128 : 16);
      from64(grant.authorization_key_id, 16);
      from64(grant.authorization_public_key, 32);
      if (typeof grant.device_id !== "string" || !grant.device_id
        || grant.device_id.length > 64 || /[\u0000-\u001f\u007f]/.test(grant.device_id)
        || uint(grant.enrolled_epoch) > candidate.epoch
        || grant.revoked_at_epoch !== null) deny();
      const message = new TextEncoder().encode(JSON.stringify(
        Object.fromEntries(GRANT.map((field) => [field, grant[field]]))));
      if (message.byteLength > 2048) deny();
      const signed = new Uint8Array(DOMAIN.byteLength + message.byteLength);
      signed.set(DOMAIN); signed.set(message, DOMAIN.byteLength);
      if (!await webCrypto.subtle.verify("Ed25519", key,
        from64(grant.signature, 64), signed)) deny();

      if (input.ownerHistoryCheckpoint !== null) {
        const checkpoint = input.ownerHistoryCheckpoint;
        // A non-genesis checkpoint must present its *branded and verified*
        // predecessor, which is tied recursively to a signed genesis. Never
        // accept a self-reported prior hash or standalone sequence > 1.
        if (!ownerHistory?.verifyOwnerCheckpoint
          || !Number.isSafeInteger(checkpoint?.sequence)
          || checkpoint.sequence < 1
          || (checkpoint.sequence !== 1 && (!priorProvided
            || input.previousOwnerHistoryProof === null))) deny();
        const proof = await ownerHistory.verifyOwnerCheckpoint({
          checkpoint, scope: Object.fromEntries(SCOPE.map((name) => [name, grant[name]])),
          signerPublicKey: key, signerKeyId: from64(checkpoint.signer_key_id, 16),
          previous: priorProvided ? input.previousOwnerHistoryProof : null,
        });
        if (proof.revision !== candidate.revision
          || proof.manifestDigest !== candidate.digest) deny();
      }
      return { key: JSON.stringify(SCOPE.map((name) => grant[name])), candidate };
    } catch (_) { deny(); }
  }
  async function withFloor(input, operation, indexedDBImpl =
    typeof indexedDB === "object" ? indexedDB : undefined) {
    const { key, candidate } = await verifyExternalAnchor(input);
    if (!indexedDBImpl || typeof indexedDBImpl.open !== "function") deny();
    let db;
    try {
      db = await new Promise((resolve, reject) => {
        const request = indexedDBImpl.open(DB, 1);
        request.onupgradeneeded = () => {
          if (!request.result.objectStoreNames.contains(STORE))
            request.result.createObjectStore(STORE);
        };
        request.onblocked = () => reject(new Error("blocked"));
        request.onerror = () => reject(new Error("open"));
        request.onsuccess = () => resolve(request.result);
      });
      const outcome = await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, operation === "provision" ? "readwrite" : "readonly");
        const store = tx.objectStore(STORE);
        let saved;
        const request = store.get(key);
        request.onsuccess = () => {
          try {
            // Compare and write inside ONE IndexedDB readwrite transaction.
            // Simultaneous tabs serialize; a delayed tab cannot overwrite
            // the newer floor, including a corrupt or foreign record.
            const prior = request.result === undefined ? null : request.result;
            transition(prior, candidate);
            if (operation === "assert" && (prior === null
              || prior.revision !== candidate.revision
              || prior.digest !== candidate.digest
              || prior.epoch !== candidate.epoch)) deny();
            if (operation === "provision") store.put(candidate, key);
            saved = prior;
          } catch (_) { tx.abort(); }
        };
        tx.oncomplete = () => resolve(saved);
        tx.onerror = () => reject(new Error("tx"));
        tx.onabort = () => reject(new Error("floor"));
      });
      return Object.freeze({ localMonotonicFloorChecked: true,
        initialProvision: operation === "provision" && outcome === null,
        signedOwnerGrantVerified: true, optionalOwnerHistoryVerified:
          input.ownerHistoryCheckpoint !== null,
        externalPinOriginProven: false, independentRollbackProof: false,
        currentOnlineRevocationVerified: false, authorizesProductionIo: false });
    } catch (_) { deny(); }
    finally { db?.close(); }
  }
  return Object.freeze({
    // Verification primitive for synthetic callers; it does not read or
    // establish a floor and cannot authorize any browser I/O by itself.
    verifyExternalAnchor,
    provisionOffline(input) { return withFloor(input, "provision"); },
    assertCurrent(input) { return withFloor(input, "assert"); },
  });
}));
