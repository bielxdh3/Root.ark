(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./rootark-zk1-owner-signed-checkpoint"));
  } else {
    root.RootarkZk1OwnerCheckpointIndexedDb = factory(
      root.RootarkZk1OwnerSignedCheckpoint);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (owner) {
    "use strict";

    // Optional local-only IndexedDB checkpoint ledger. It never imports or
    // persists owner private keys, CEKs, plaintext, server credentials or a
    // recovery package. A same-origin attacker/whole-profile restore can
    // erase this store. Keep a signed checkpoint and a pinned key OFF-SERVER
    // and pass that trusted floor back on restart to detect a rollback.
    const DB = "rootark-zk1-owner-checkpoints-v1";
    const STORE = "owner_checkpoints";
    const SCHEMA = "rootark-zk1-owner-checkpoint-local/v1";
    const MAX_RECORDS = 512;
    const SCOPE = ["account_id", "compartment_id", "keyring_id"];
    const BASE = ["scope", "deviceId", "signerKeyId", "signerPublicKey"];
    const WIRE_FIELDS = ["schema", ...SCOPE, "device_id", "signer_key_id",
      "revision", "manifest_digest", "sequence", "previous_checkpoint_digest",
      "issued_at", "signature"];

    function deny() { throw new Error("ZK_OWNER_CHECKPOINT_STORAGE_UNVERIFIED"); }
    function exact(input, fields) {
      if (!input || typeof input !== "object" || Array.isArray(input)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
        || Reflect.ownKeys(input).length !== fields.length
        || fields.some((field) => !Object.hasOwn(input, field))) deny();
    }
    function safeWire(value) {
      exact(value, WIRE_FIELDS);
      for (const field of WIRE_FIELDS) {
        const item = value[field];
        if (typeof item === "string" && item.length > 256) deny();
        if (typeof item !== "string" && item !== null && !Number.isSafeInteger(item)) deny();
      }
      const encoded = JSON.stringify(value);
      if (encoded.length > 1024) deny();
      return JSON.parse(encoded);
    }
    function b64(bytes) {
      if (!ArrayBuffer.isView(bytes) && !(bytes instanceof ArrayBuffer)) deny();
      if (bytes.byteLength !== 16) deny();
      const cloned = bytes instanceof ArrayBuffer ? new Uint8Array(bytes.slice(0))
        : new Uint8Array(bytes.buffer.slice(bytes.byteOffset,
          bytes.byteOffset + bytes.byteLength));
      let text = "";
      for (const b of cloned) text += String.fromCharCode(b);
      return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function identity(input) {
      exact(input.scope, SCOPE);
      if (typeof input.deviceId !== "string" || input.deviceId.length < 1
        || input.deviceId.length > 64 || /[\u0000-\u001f\u007f]/.test(input.deviceId)
        || SCOPE.some((field) => typeof input.scope[field] !== "string"
          || input.scope[field].length < 2 || input.scope[field].length > 176)) deny();
      const keyId = b64(input.signerKeyId);
      const scope = { ...input.scope };
      const deviceId = input.deviceId;
      // Preserve the exact 16-byte key identifier for DataView, Buffer,
      // Uint8Array and ArrayBuffer alike. new Uint8Array(DataView) instead
      // interprets absent indexed elements and produces an empty byte view.
      const id = input.signerKeyId;
      const signerKeyId = id instanceof ArrayBuffer
        ? new Uint8Array(id.slice(0))
        : new Uint8Array(id.buffer.slice(id.byteOffset,
          id.byteOffset + id.byteLength));
      return { key: JSON.stringify([...SCOPE.map((field) => scope[field]), deviceId, keyId]),
        scope, deviceId, signerKeyId,
        signerPublicKey: input.signerPublicKey };
    }
    function floorValue(value) {
      if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) deny();
      return value;
    }
    async function openOwnerCheckpointStore({ databaseName = DB, indexedDBImpl =
      typeof indexedDB === "object" ? indexedDB : undefined } = {}) {
      if (databaseName !== DB
        || !indexedDBImpl || typeof indexedDBImpl.open !== "function"
        || !owner?.verifyOwnerCheckpoint) deny();
      const db = await new Promise((resolve, reject) => {
        let request;
        try { request = indexedDBImpl.open(databaseName, 1); } catch (_) { deny(); }
        request.onupgradeneeded = () => {
          if (!request.result.objectStoreNames.contains(STORE)) {
            request.result.createObjectStore(STORE);
          }
        };
        request.onerror = () => reject(new Error("ZK_OWNER_CHECKPOINT_STORAGE_UNVERIFIED"));
        request.onblocked = () => reject(new Error("ZK_OWNER_CHECKPOINT_STORAGE_UNVERIFIED"));
        request.onsuccess = () => resolve(request.result);
      });
      let closed = false;
      const usable = () => {
        if (closed || !db.objectStoreNames.contains(STORE)) deny();
      };
      function read(key) {
        usable();
        return new Promise((resolve, reject) => {
          let raw;
          try {
            const tx = db.transaction(STORE, "readonly");
            const request = tx.objectStore(STORE).get(key);
            request.onsuccess = () => { raw = request.result; };
            tx.oncomplete = () => resolve(raw ?? null);
            tx.onerror = () => reject(new Error("ZK_OWNER_CHECKPOINT_STORAGE_UNVERIFIED"));
            tx.onabort = () => reject(new Error("ZK_OWNER_CHECKPOINT_STORAGE_UNVERIFIED"));
          } catch (_) { reject(new Error("ZK_OWNER_CHECKPOINT_STORAGE_UNVERIFIED")); }
        });
      }
      async function verifyStored(raw, trusted) {
        if (raw === null) return null;
        exact(raw, ["schema", "records", "headDigest"]);
        if (raw.schema !== SCHEMA || !Array.isArray(raw.records)
          || raw.records.length < 1 || raw.records.length > MAX_RECORDS) deny();
        const snapshots = [];
        let prev = null;
        for (const entry of raw.records) {
          const wire = safeWire(entry);
          if (wire.device_id !== trusted.deviceId) deny();
          prev = await owner.verifyOwnerCheckpoint({
            checkpoint: wire, scope: trusted.scope,
            signerPublicKey: trusted.signerPublicKey,
            signerKeyId: trusted.signerKeyId, previous: prev,
          });
          snapshots.push(wire);
        }
        if (prev.sequence !== snapshots.length
          || prev.checkpointDigest !== raw.headDigest) deny();
        return { verifiedCheckpoint: prev, checkpointDigest: prev.checkpointDigest,
          records: snapshots };
      }
      function writeCompareAndSwap(key, expected, replacement) {
        usable();
        return new Promise((resolve, reject) => {
          try {
            const tx = db.transaction(STORE, "readwrite");
            const stored = tx.objectStore(STORE);
            const request = stored.get(key);
            request.onsuccess = () => {
              const observed = request.result ?? null;
              // Race-safe: the *complete* expected record is compared again
              // INSIDE the exclusive readwrite transaction, not just a digest
              // read before asynchronous WebCrypto verification.
              if (JSON.stringify(observed) !== JSON.stringify(expected)) {
                tx.abort(); return;
              }
              stored.put(replacement, key);
            };
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(new Error("ZK_OWNER_CHECKPOINT_STORAGE_UNVERIFIED"));
            tx.onabort = () => reject(new Error("ZK_OWNER_CHECKPOINT_STORAGE_UNVERIFIED"));
          } catch (_) { reject(new Error("ZK_OWNER_CHECKPOINT_STORAGE_UNVERIFIED")); }
        });
      }
      async function loadOwnerCheckpoint(input) {
        try {
          const hasFloor = Object.hasOwn(input || {}, "expectedExternalDigest");
          exact(input, [...BASE, ...(hasFloor ? ["expectedExternalDigest"] : [])]);
          const trusted = identity(input);
          const expected = hasFloor ? floorValue(input.expectedExternalDigest) : null;
          const record = await verifyStored(await read(trusted.key), trusted);
          if (expected && record?.checkpointDigest !== expected) deny();
          return record ? Object.freeze({
            checkpointDigest: record.checkpointDigest,
            verifiedCheckpoint: record.verifiedCheckpoint,
            count: record.records.length, independentRollbackProof: false,
            authorizesProtectedIo: false,
          }) : null;
        } catch (_) { deny(); }
      }
      async function bootstrapOwnerCheckpoint(input) {
        try {
          exact(input, [...BASE, "checkpoint"]);
          const trusted = identity(input);
          const checkpoint = safeWire(input.checkpoint);
          const proof = await owner.verifyOwnerCheckpoint({
            checkpoint, scope: trusted.scope,
            signerPublicKey: trusted.signerPublicKey,
            signerKeyId: trusted.signerKeyId, previous: null,
          });
          if (proof.sequence !== 1 || checkpoint.device_id !== trusted.deviceId) deny();
          if (await read(trusted.key) !== null) deny();
          await writeCompareAndSwap(trusted.key, null, {
            schema: SCHEMA, records: [checkpoint], headDigest: proof.checkpointDigest,
          });
          return Object.freeze({ storedLocally: true,
            checkpointDigest: proof.checkpointDigest,
            independentRollbackProof: false, authorizesProtectedIo: false });
        } catch (_) { deny(); }
      }
      async function appendOwnerCheckpoint(input) {
        try {
          exact(input, [...BASE, "checkpoint", "expectedHeadDigest"]);
          const trusted = identity(input);
          const expectedHead = floorValue(input.expectedHeadDigest);
          const checkpoint = safeWire(input.checkpoint);
          const beforeRaw = await read(trusted.key);
          const before = await verifyStored(beforeRaw, trusted);
          if (!before || before.checkpointDigest !== expectedHead
            || before.records.length >= MAX_RECORDS || checkpoint.device_id !== trusted.deviceId) deny();
          const next = await owner.verifyOwnerCheckpoint({
            checkpoint, scope: trusted.scope,
            signerPublicKey: trusted.signerPublicKey,
            signerKeyId: trusted.signerKeyId, previous: before.verifiedCheckpoint,
          });
          await writeCompareAndSwap(trusted.key, beforeRaw, {
            schema: SCHEMA, records: [...before.records, checkpoint],
            headDigest: next.checkpointDigest,
          });
          return Object.freeze({ storedLocally: true,
            checkpointDigest: next.checkpointDigest,
            independentRollbackProof: false, authorizesProtectedIo: false });
        } catch (_) { deny(); }
      }
      return Object.freeze({
        loadOwnerCheckpoint, bootstrapOwnerCheckpoint, appendOwnerCheckpoint,
        close() { if (!closed) { closed = true; db.close(); } },
      });
    }
    return Object.freeze({ openOwnerCheckpointStore });
  }));
