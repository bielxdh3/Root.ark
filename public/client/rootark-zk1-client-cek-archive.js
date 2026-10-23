(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto);
  } else {
    root.RootarkZk1ClientCekArchive = factory(root.crypto);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto) {
  "use strict";

  // Opt-in owner-held CEK archive. IndexedDB commits are local only. A separate
  // independently operated pin store is required on EVERY read; remote backup
  // carries only owner-signed AEAD ciphertext, never usable CEKs or filenames.
  const DB = "rootark-zk1-encrypted-cek-archive-v1";
  const STORE = "sealed";
  const FORMAT = "rootark-zk1-client-cek-archive/v1";
  const DOMAIN = new TextEncoder().encode("Root.ark/zk-1/client-cek-archive/v1\0");
  const RECEIPT = new TextEncoder().encode("Root.ark/zk-1/logical-trash-archive-receipt/v1\0");
  const BACKUP_RECEIPT = new TextEncoder().encode("Root.ark/zk-1/cek-backup-provider-receipt/v1\0");
  const OWNER_ROTATION = new TextEncoder().encode("Root.ark/zk-1/cek-owner-rotation/v1\0");
  const GRANT = new TextEncoder().encode("Root.ark/zk-1/browser-owner-device-grant/v1\0");
  const INFO = new TextEncoder().encode("Root.ark/zk-1/client-cek-archive-aead/v1\0");
  const GRANT_FIELDS = ["schema", "account_id", "compartment_id", "keyring_id",
    "device_id", "authorization_key_id", "authorization_public_key",
    "manifest_revision", "manifest_digest", "current_epoch", "enrolled_epoch",
    "revoked_at_epoch"];
  const META = ["account_id", "compartment_id", "keyring_id", "object_id",
    "version_id", "parent_version_id", "epoch", "kind"];
  const enc = new TextEncoder();
  const dec = new TextDecoder("utf-8", { fatal: true });
  const MAX_ENTRIES = 64;
  const MAX_RECORD = 512 * 1024;
  function deny() { throw new Error("ZK_CLIENT_CEK_ARCHIVE_DENIED"); }
  function exact(value, keys) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== keys.length
      || keys.some((key) => !Object.hasOwn(value, key))) deny();
  }
  function bytes(value, n) {
    if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)
      || value.byteLength !== n || (typeof SharedArrayBuffer !== "undefined"
        && (value instanceof SharedArrayBuffer || value.buffer instanceof SharedArrayBuffer))) deny();
    return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
      : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  function b64(value) {
    let s = "";
    for (const b of value) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(value, n, max = n) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
      || value.length > Math.ceil(max * 4 / 3) + 4) deny();
    let raw;
    try { raw = atob(value.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
    const output = Uint8Array.from(raw, (v) => v.charCodeAt(0));
    if (output.length < n || output.length > max || b64(output) !== value) deny();
    return output;
  }
  function positive(n) { if (!Number.isSafeInteger(n) || n < 1) deny(); return n; }
  function same(a, b) {
    if (a.length !== b.length) return false;
    let delta = 0;
    for (let i = 0; i < a.length; i++) delta |= a[i] ^ b[i];
    return delta === 0;
  }
  function message(domain, body) {
    const payload = enc.encode(JSON.stringify(body));
    const value = new Uint8Array(domain.length + payload.length);
    value.set(domain); value.set(payload, domain.length);
    return value;
  }
  async function sha(data) { return new Uint8Array(await webCrypto.subtle.digest("SHA-256", data)); }
  function snapshotHead(head) {
    exact(head, ["revision", "digest", "epoch"]);
    return { revision: positive(head.revision), digest: b64(bytes(head.digest, 32)),
      epoch: positive(head.epoch) };
  }
  function entryId(metadata, revision) {
    return JSON.stringify([metadata.object_id, revision, metadata.version_id]);
  }
  function metaCopy(value, scope, epoch) {
    exact(value, META);
    const metadata = Object.fromEntries(META.map((field) => [field, value[field]]));
    for (const field of META.slice(0, 3)) {
      if (metadata[field] !== scope[field]) deny();
    }
    for (const field of ["account_id", "keyring_id", "object_id", "version_id"])
      from64(metadata[field], 16);
    from64(metadata.compartment_id, 1, 128);
    if (metadata.parent_version_id !== null) from64(metadata.parent_version_id, 16);
    if (metadata.kind !== "file" || positive(metadata.epoch) > epoch) deny();
    return metadata;
  }
  function validateChallenge(challenge) {
    const hasScope = !!challenge && Object.hasOwn(challenge, "account_id");
    exact(challenge, [...(hasScope ? ["account_id", "compartment_id", "keyring_id"] : []),
      "objectId", "action", "epoch", "nonce", "entries"]);
    from64(challenge.objectId, 16);
    if (!["trash", "restore", "rename", "move", "rotate"].includes(challenge.action)) deny();
    if (hasScope) {
      from64(challenge.account_id, 16);
      from64(challenge.compartment_id, 1, 128);
      from64(challenge.keyring_id, 16);
    }
    positive(challenge.epoch);
    from64(challenge.nonce, 32);
    if (!Array.isArray(challenge.entries) || challenge.entries.length < 1
      || challenge.entries.length > 12) deny();
    for (const value of challenge.entries) {
      exact(value, ["revision", "versionId", "ciphertextDigest"]);
      positive(value.revision); from64(value.versionId, 16);
      from64(value.ciphertextDigest, 32);
    }
    return JSON.parse(JSON.stringify(challenge));
  }
  function parseRecord(raw) {
    if (typeof raw !== "string" || raw.length > MAX_RECORD || raw.length < 100) deny();
    let value;
    try { value = JSON.parse(raw); } catch (_) { deny(); }
    exact(value, ["format", "scope", "head", "sequence", "previousDigest", "challenge",
      "salt", "iv", "ciphertext", "signature"]);
    if (value.format !== FORMAT) deny();
    exact(value.scope, ["account_id", "compartment_id", "keyring_id"]);
    exact(value.head, ["revision", "digest", "epoch"]);
    positive(value.sequence);
    if (value.previousDigest !== null) from64(value.previousDigest, 32);
    from64(value.salt, 32); from64(value.iv, 12);
    from64(value.ciphertext, 16, MAX_RECORD);
    from64(value.signature, 64);
    validateChallenge(value.challenge);
    return value;
  }
  async function openCekArchive(input) {
    let db, recoverySecret;
    try {
      exact(input, ["indexedDBImpl", "recoverySecret", "ownerPublicKey", "ownerSigningKey",
        "independentOwnerSpkiSha256", "pinnedCurrentHead", "signedDeviceGrant",
        "pinProvider", "backupProvider", "backupReceiptPublicKey",
        "independentBackupReceiptSpkiSha256", "assertLive"]);
      if (!webCrypto?.subtle || !webCrypto?.getRandomValues ||
        typeof input.indexedDBImpl?.open !== "function" ||
        typeof input.assertLive !== "function" ||
        typeof input.pinProvider?.read !== "function" ||
        typeof input.pinProvider?.compareAndSwap !== "function" ||
        input.backupProvider !== null && (typeof input.backupProvider?.put !== "function"
          || typeof input.backupProvider?.get !== "function")) deny();
      recoverySecret = bytes(input.recoverySecret, 32);
      const head = snapshotHead(input.pinnedCurrentHead);
      const grant = input.signedDeviceGrant;
      exact(grant, [...GRANT_FIELDS, "signature"]);
      const scope = Object.fromEntries(GRANT_FIELDS.slice(1, 4).map((name) => [name, grant[name]]));
      for (const field of ["account_id", "keyring_id"]) from64(scope[field], 16);
      from64(scope.compartment_id, 1, 128);
      if (grant.manifest_revision !== head.revision || grant.manifest_digest !== head.digest
        || grant.current_epoch !== head.epoch || grant.enrolled_epoch > head.epoch
        || positive(grant.enrolled_epoch) < 1 || grant.revoked_at_epoch !== null
        || typeof grant.device_id !== "string" || !grant.device_id
        || typeof grant.schema !== "string") deny();
      from64(grant.authorization_key_id, 16);
      from64(grant.authorization_public_key, 32);
      const spki = new Uint8Array(await webCrypto.subtle.exportKey("spki", input.ownerPublicKey));
      if (!same(await sha(spki), bytes(input.independentOwnerSpkiSha256, 32))) deny();
      if (input.backupProvider !== null) {
        if (input.backupReceiptPublicKey?.algorithm?.name !== "Ed25519") deny();
        const receiptSpki = await webCrypto.subtle.exportKey("spki", input.backupReceiptPublicKey);
        if (!same(await sha(receiptSpki), bytes(input.independentBackupReceiptSpkiSha256, 32))) deny();
      } else if (input.backupReceiptPublicKey !== null
        || input.independentBackupReceiptSpkiSha256 !== null) deny();
      const signedFields = Object.fromEntries(GRANT_FIELDS.map((key) => [key, grant[key]]));
      if (!(await webCrypto.subtle.verify("Ed25519", input.ownerPublicKey,
        from64(grant.signature, 64), message(GRANT, signedFields)))) deny();
      // Signing authority must match the separately pinned owner key.
      if (input.ownerSigningKey !== null && (input.ownerSigningKey?.algorithm?.name !== "Ed25519"
        || input.ownerSigningKey.usages?.includes("sign") !== true)) deny();
      const openedLive = input.assertLive();
      if (openedLive === false || (openedLive && typeof openedLive.then === "function")) deny();
      db = await new Promise((resolve, reject) => {
        const request = input.indexedDBImpl.open(DB, 1);
        request.onupgradeneeded = () => {
          if (!request.result.objectStoreNames.contains(STORE))
            request.result.createObjectStore(STORE);
        };
        request.onerror = () => reject(Error("ZK_CLIENT_CEK_ARCHIVE_DENIED"));
        request.onblocked = () => reject(Error("ZK_CLIENT_CEK_ARCHIVE_DENIED"));
        request.onsuccess = () => resolve(request.result);
      });
      let closed = false;
      const alive = () => {
        if (closed || !db.objectStoreNames.contains(STORE)) deny();
        // A Promise is not a live-session assertion. Callers must fence the
        // current owner/grant/epoch synchronously at each sensitive boundary.
        const checked = input.assertLive();
        if (checked === false || (checked && typeof checked.then === "function")) deny();
      };
      const key = JSON.stringify([scope.account_id, scope.compartment_id, scope.keyring_id]);
      function readLocal() {
        alive();
        return new Promise((resolve, reject) => {
          let result;
          try {
            const tx = db.transaction(STORE, "readonly");
            const request = tx.objectStore(STORE).get(key);
            request.onsuccess = () => { result = request.result ?? null; };
            tx.oncomplete = () => resolve(result);
            tx.onerror = tx.onabort = () => reject(Error("ZK_CLIENT_CEK_ARCHIVE_DENIED"));
          } catch (_) { reject(Error("ZK_CLIENT_CEK_ARCHIVE_DENIED")); }
        });
      }
      function writeCas(expected, replacement) {
        alive();
        return new Promise((resolve, reject) => {
          try {
            const tx = db.transaction(STORE, "readwrite");
            const store = tx.objectStore(STORE);
            store.get(key).onsuccess = (event) => {
              if ((event.target.result ?? null) !== expected) { tx.abort(); return; }
              store.put(replacement, key);
            };
            tx.oncomplete = resolve;
            tx.onerror = tx.onabort = () => reject(Error("ZK_CLIENT_CEK_ARCHIVE_DENIED"));
          } catch (_) { reject(Error("ZK_CLIENT_CEK_ARCHIVE_DENIED")); }
        });
      }
      function unsigned(record) {
        return Object.fromEntries(Object.entries(record).filter(([name]) => name !== "signature"));
      }
      async function digest(raw) { return b64(await sha(enc.encode(raw))); }
      async function derive(salt) {
        return deriveFromSecret(recoverySecret, salt);
      }
      async function deriveFromSecret(secret, salt) {
        const material = await webCrypto.subtle.importKey("raw", secret,
          "HKDF", false, ["deriveKey"]);
        return webCrypto.subtle.deriveKey({ name: "HKDF", salt, info: INFO,
          hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 },
        false, ["encrypt", "decrypt"]);
      }
      function aad(record) {
        const { ciphertext, signature, ...context } = record;
        return message(DOMAIN, context);
      }
      async function verifyRecord(raw) {
        const record = parseRecord(raw);
        if (JSON.stringify(record.scope) !== JSON.stringify(scope)
          || record.head.revision !== head.revision || record.head.digest !== head.digest
          || record.head.epoch !== head.epoch || record.challenge.epoch !== head.epoch
          || (record.sequence === 1) !== (record.previousDigest === null)
          || record.challenge.objectId.length !== 22) deny();
        if (!(await webCrypto.subtle.verify("Ed25519", input.ownerPublicKey,
          from64(record.signature, 64), message(DOMAIN, unsigned(record))))) deny();
        return record;
      }
      async function decryptRecord(record, secret = recoverySecret) {
        const key = await deriveFromSecret(secret, from64(record.salt, 32));
        let plaintext;
        try {
          plaintext = new Uint8Array(await webCrypto.subtle.decrypt({ name: "AES-GCM",
            iv: from64(record.iv, 12), additionalData: aad(record), tagLength: 128 },
          key, from64(record.ciphertext, 16, MAX_RECORD)));
          if (plaintext.length > MAX_RECORD) deny();
          const parsed = JSON.parse(dec.decode(plaintext));
          if (!Array.isArray(parsed) || parsed.length > MAX_ENTRIES) deny();
          for (const row of parsed) {
            exact(row, ["metadata", "revision", "ciphertextDigest", "cek", "nonces"]);
            metaCopy(row.metadata, scope, head.epoch);
            positive(row.revision); from64(row.ciphertextDigest, 32);
            from64(row.cek, 32);
            if (!Array.isArray(row.nonces) || row.nonces.length < 1
              || row.nonces.length > 16 || new Set(row.nonces).size !== row.nonces.length) deny();
            for (const nonce of row.nonces) from64(nonce, 32);
          }
          return parsed;
        } finally { plaintext?.fill(0); }
      }
      async function readPinned() {
        alive();
        const raw = await readLocal();
        const pin = await input.pinProvider.read();
        alive();
        if (raw === null) { if (pin !== null) deny(); return null; }
        const observed = await digest(raw);
        if (pin !== observed) deny();
        const record = await verifyRecord(raw);
        const entries = await decryptRecord(record);
        alive();
        return { raw, observed, record, entries };
      }
      async function retrieveSignedArchive(digestValue, signer = input.ownerPublicKey) {
        if (input.backupProvider === null) deny();
        from64(digestValue, 32);
        alive();
        const response = await input.backupProvider.get({ key: digestValue });
        const raw = dec.decode(await verifyProviderReadback(response, digestValue));
        if (await digest(raw) !== digestValue) deny();
        const record = parseRecord(raw);
        if (JSON.stringify(record.scope) !== JSON.stringify(scope)
          || !(await webCrypto.subtle.verify("Ed25519", signer,
            from64(record.signature, 64), message(DOMAIN, unsigned(record))))) deny();
        return { raw, record, digest: digestValue };
      }
      // Walk the signed predecessor chain to a locally verified digest or
      // genesis. A remote latest response alone cannot prove its provenance.
      async function syncFromBackup({ expectedDigest }) {
        try {
          from64(expectedDigest, 32);
          alive();
          if (await input.pinProvider.read() !== expectedDigest) deny();
          const original = await readLocal();
          const originalDigest = original === null ? null : await digest(original);
          if (originalDigest === expectedDigest) {
            await readPinned();
            return Object.freeze({ independentlyPinnedDigest: expectedDigest,
              localIndexedDbCommitted: true, signedHistoryVerified: true,
              providerReadbackVerified: true });
          }
          if (original !== null) await verifyRecord(original);
          let next = expectedDigest;
          let previousSequence = null;
          const visited = new Set();
          for (let step = 0; step < 64; step++) {
            if (visited.has(next)) deny();
            visited.add(next);
            const fetched = await retrieveSignedArchive(next);
            if (fetched.record.head.revision !== head.revision
              || fetched.record.head.digest !== head.digest
              || fetched.record.head.epoch !== head.epoch
              || fetched.record.challenge.epoch !== head.epoch) deny();
            if (previousSequence !== null && fetched.record.sequence !== previousSequence - 1)
              deny();
            await decryptRecord(fetched.record);
            if (next === expectedDigest) {
              // Verify local signing authority and the current scope/owner.
              await verifyRecord(fetched.raw);
            }
            if (fetched.record.previousDigest === originalDigest) {
              if (original !== null) {
                const historic = parseRecord(original);
                if (historic.sequence + 1 !== fetched.record.sequence) deny();
              } else if (fetched.record.sequence !== 1) deny();
              break;
            }
            if (fetched.record.previousDigest === null) deny();
            previousSequence = fetched.record.sequence;
            next = fetched.record.previousDigest;
            if (step === 63) deny();
          }
          alive();
          if (await input.pinProvider.read() !== expectedDigest) deny();
          const latest = await retrieveSignedArchive(expectedDigest);
          await verifyRecord(latest.raw);
          await decryptRecord(latest.record);
          await writeCas(original, latest.raw);
          const observed = await readPinned();
          if (observed.observed !== expectedDigest) deny();
          return Object.freeze({ independentlyPinnedDigest: expectedDigest,
            localIndexedDbCommitted: true, signedHistoryVerified: true,
            providerReadbackVerified: true });
        } catch (_) { deny(); }
      }
      async function backup(raw) {
        if (!input.backupProvider) return false;
        const location = await digest(raw);
        const content = enc.encode(raw);
        try { await input.backupProvider.put({ key: location, ciphertext: content.slice() }); }
        catch (_) { /* ACK uncertain: independent GET is authoritative for this copy. */ }
        alive();
        const readback = await input.backupProvider.get({ key: location });
        const fetched = await verifyProviderReadback(readback, location);
        if (!same(fetched, content)) deny();
        alive();
        return true;
      }
      async function verifyProviderReadback(reply, digestValue) {
        exact(reply, ["ciphertext", "receipt"]);
        const source = reply.ciphertext;
        if (!(source instanceof ArrayBuffer) && !ArrayBuffer.isView(source)
          || source.byteLength < 100 || source.byteLength > MAX_RECORD) deny();
        const fetched = source instanceof ArrayBuffer ? new Uint8Array(source.slice(0))
          : new Uint8Array(source.buffer.slice(source.byteOffset,
            source.byteOffset + source.byteLength));
        exact(reply.receipt, ["schema", "digest", "byteLength", "providerId", "signature"]);
        const receipt = reply.receipt;
        if (receipt.schema !== "rootark-zk1-client-cek-backup-receipt/v1"
          || receipt.digest !== digestValue || receipt.byteLength !== fetched.byteLength) deny();
        from64(receipt.providerId, 16);
        const signed = { schema: receipt.schema, digest: receipt.digest,
          byteLength: receipt.byteLength, providerId: receipt.providerId };
        if (!(await webCrypto.subtle.verify("Ed25519", input.backupReceiptPublicKey,
          from64(receipt.signature, 64), message(BACKUP_RECEIPT, signed)))) deny();
        if (b64(await sha(fetched)) !== digestValue) deny();
        return fetched;
      }
      async function archiveKeys({ challenge, entries }) {
        try {
          alive();
          if (input.ownerSigningKey === null) deny();
          const request = validateChallenge(challenge);
          if (request.epoch !== head.epoch || !Array.isArray(entries)
            || entries.length !== request.entries.length || entries.length > 12) deny();
          if (Object.hasOwn(request, "account_id") &&
            (request.account_id !== scope.account_id
              || request.compartment_id !== scope.compartment_id
              || request.keyring_id !== scope.keyring_id)) deny();
          const previous = await readPinned();
          const accumulated = new Map((previous?.entries || []).map((item) =>
            [entryId(item.metadata, item.revision), item]));
          for (let i = 0; i < entries.length; i++) {
            const item = entries[i];
            exact(item, ["metadata", "revision", "ciphertext", "cek", "state"]);
            const meta = metaCopy(item.metadata, scope, head.epoch);
            positive(item.revision);
            if (meta.object_id !== request.objectId || item.revision !== request.entries[i].revision
              || meta.version_id !== request.entries[i].versionId
              || !["file", "trashed"].includes(item.state)
              || !(item.ciphertext instanceof Uint8Array)
              || item.ciphertext.byteLength < 16 || item.ciphertext.byteLength > 1536 * 1024) deny();
            if (b64(await sha(item.ciphertext)) !== request.entries[i].ciphertextDigest) deny();
            // CryptoKey(extractable=false) cannot be AEAD-wrapped or exported.
            // Never silently downgrade to storing a directly usable key in IDB.
            const id = entryId(meta, item.revision);
            let cek;
            if (item.cek?.type === "secret" && item.cek.extractable === false) {
              const existing = accumulated.get(id);
              if (!existing || existing.ciphertextDigest !== request.entries[i].ciphertextDigest
                || JSON.stringify(existing.metadata) !== JSON.stringify(meta)) deny();
              cek = from64(existing.cek, 32);
              const operational = await webCrypto.subtle.importKey("raw", cek, "AES-GCM",
                false, ["encrypt", "decrypt"]);
              const nonce = webCrypto.getRandomValues(new Uint8Array(12));
              const probe = webCrypto.getRandomValues(new Uint8Array(32));
              const settings = { name: "AES-GCM", iv: nonce,
                additionalData: enc.encode("Root.ark/zk-1/cek-provenance/v1"), tagLength: 128 };
              const [saved, supplied] = await Promise.all([
                webCrypto.subtle.encrypt(settings, operational, probe),
                webCrypto.subtle.encrypt(settings, item.cek, probe),
              ]);
              if (!same(new Uint8Array(saved), new Uint8Array(supplied))) deny();
              probe.fill(0);
            } else cek = bytes(item.cek, 32);
            try {
              const row = { metadata: meta, revision: item.revision,
                ciphertextDigest: request.entries[i].ciphertextDigest,
                cek: b64(cek), nonces: [request.nonce] };
              const prior = accumulated.get(id);
              if (prior) {
                if (JSON.stringify(prior.metadata) !== JSON.stringify(row.metadata)
                  || prior.ciphertextDigest !== row.ciphertextDigest || prior.cek !== row.cek
                  || prior.nonces.length >= 16) deny();
                if (!prior.nonces.includes(request.nonce)) prior.nonces.push(request.nonce);
              } else accumulated.set(id, row);
            } finally { cek.fill(0); }
          }
          if (accumulated.size > MAX_ENTRIES) deny();
          const sequence = (previous?.record.sequence || 0) + 1;
          if (!Number.isSafeInteger(sequence)) deny();
          const salt = webCrypto.getRandomValues(new Uint8Array(32));
          const iv = webCrypto.getRandomValues(new Uint8Array(12));
          const record = { format: FORMAT, scope, head, sequence,
            previousDigest: previous?.observed || null, challenge: request,
            salt: b64(salt), iv: b64(iv), ciphertext: "", signature: "" };
          let plaintext = enc.encode(JSON.stringify([...accumulated.values()]));
          try {
            if (plaintext.byteLength > MAX_RECORD / 2) deny();
            const key = await derive(salt);
            record.ciphertext = b64(new Uint8Array(await webCrypto.subtle.encrypt({
              name: "AES-GCM", iv, additionalData: aad(record), tagLength: 128 },
            key, plaintext)));
          } finally { plaintext.fill(0); }
          record.signature = b64(new Uint8Array(await webCrypto.subtle.sign(
            "Ed25519", input.ownerSigningKey, message(DOMAIN, unsigned(record)))));
          const raw = JSON.stringify(record);
          if (raw.length > MAX_RECORD) deny();
          await verifyRecord(raw);
          const backupVerified = await backup(raw);
          alive();
          await writeCas(previous?.raw || null, raw);
          const newPin = await digest(raw);
          try { await input.pinProvider.compareAndSwap(previous?.observed || null, newPin); }
          catch (_) { /* pin ACK may have been lost */ }
          alive();
          if (await input.pinProvider.read() !== newPin) deny();
          const committed = await readPinned();
          if (committed.observed !== newPin) deny();
          const signatureBase64 = b64(new Uint8Array(await webCrypto.subtle.sign(
            "Ed25519", input.ownerSigningKey, message(RECEIPT, request))));
          return Object.freeze({ signatureBase64, localIndexedDbCommitted: true,
            externallyPinnedDigest: newPin, remoteCiphertextReadbackVerified: backupVerified,
            independentCloudDurabilityProven: false });
        } catch (_) { deny(); }
      }
      async function readArchivedCek({ objectId, revision, versionId, nonce }) {
        try {
          from64(objectId, 16); positive(revision); from64(versionId, 16); from64(nonce, 32);
          const pinned = await readPinned();
          if (!pinned) deny();
          const matching = pinned.entries.filter((row) => row.metadata.object_id === objectId
            && row.revision === revision && row.metadata.version_id === versionId
            && row.nonces.includes(nonce));
          if (matching.length !== 1) deny();
          const cek = from64(matching[0].cek, 32);
          try {
            const key = await webCrypto.subtle.importKey("raw", cek, "AES-GCM", false,
              ["encrypt", "decrypt"]);
            alive();
            return key;
          } finally { cek.fill(0); }
        } catch (_) { deny(); }
      }
      function createRenameArchiveBridge() {
        return Object.freeze({
          async write({ metadata, objectRevision, ciphertext, ciphertextDigest, cek }) {
            try {
              alive();
              metaCopy(metadata, scope, head.epoch);
              positive(objectRevision);
              const expectedDigest = b64(bytes(ciphertextDigest, 32));
              if (b64(await sha(ciphertext)) !== expectedDigest) deny();
              const challenge = { objectId: metadata.object_id, action: "rename",
                epoch: head.epoch, nonce: b64(webCrypto.getRandomValues(new Uint8Array(32))),
                entries: [{ revision: objectRevision, versionId: metadata.version_id,
                  ciphertextDigest: expectedDigest }] };
              const receipt = await archiveKeys({ challenge, entries: [{ metadata,
                revision: objectRevision, ciphertext, cek, state: "file" }] });
              if (receipt.localIndexedDbCommitted !== true
                || receipt.externallyPinnedDigest !== await input.pinProvider.read()) deny();
              return receipt.externallyPinnedDigest;
            } catch (_) { deny(); }
          },
          async read({ receiptId, metadata, objectRevision, ciphertextDigest }) {
            try {
              from64(receiptId, 32);
              const wanted = metaCopy(metadata, scope, head.epoch);
              positive(objectRevision);
              const cipherDigest = b64(bytes(ciphertextDigest, 32));
              const pinned = await readPinned();
              if (!pinned || pinned.observed !== receiptId) deny();
              const found = pinned.entries.filter((entry) =>
                entryId(entry.metadata, entry.revision) === entryId(wanted, objectRevision)
                && JSON.stringify(entry.metadata) === JSON.stringify(wanted)
                && entry.ciphertextDigest === cipherDigest);
              if (found.length !== 1) deny();
              alive();
              return from64(found[0].cek, 32);
            } catch (_) { deny(); }
          },
        });
      }
      function createLogicalTrashBridge() {
        return Object.freeze({
          async archiveKeys(args) {
            const result = await archiveKeys(args);
            if (result.localIndexedDbCommitted !== true
              || result.remoteCiphertextReadbackVerified !== (input.backupProvider !== null)) deny();
            // Actual logical-trash signedReceipt() requires EXACTLY one field.
            return { signatureBase64: result.signatureBase64 };
          },
          async readArchivedCek(args) {
            if (!args || !["account_id", "compartment_id", "keyring_id"].every(
              (field) => args[field] === scope[field])) deny();
            return readArchivedCek(args);
          },
        });
      }
      async function reconcileUncertainArchive({ expectedDigest }) {
        try {
          from64(expectedDigest, 32);
          alive();
          const raw = await readLocal();
          if (raw === null || await digest(raw) !== expectedDigest) deny();
          const observed = await input.pinProvider.read();
          if (observed !== expectedDigest) {
            const verified = await verifyRecord(raw);
            if (verified.previousDigest !== observed) deny();
            try { await input.pinProvider.compareAndSwap(observed, expectedDigest); }
            catch (_) { /* reconcile lost pin ACK using independent read */ }
            if (await input.pinProvider.read() !== expectedDigest) deny();
          }
          const pinned = await readPinned();
          if (!pinned || pinned.observed !== expectedDigest) deny();
          const remoteReadback = await backup(pinned.raw);
          return Object.freeze({ localIndexedDbCommitted: true,
            externallyPinnedDigest: expectedDigest, remoteCiphertextReadbackVerified: remoteReadback,
            independentCloudDurabilityProven: false });
        } catch (_) { deny(); }
      }
      async function inspectPendingArchive() {
        try {
          alive();
          const raw = await readLocal();
          if (raw === null) return null;
          const record = await verifyRecord(raw);
          await decryptRecord(record);
          const observed = await input.pinProvider.read();
          const digestValue = await digest(raw);
          if (observed !== digestValue && observed !== record.previousDigest) deny();
          return Object.freeze({ digest: digestValue, previousDigest: record.previousDigest,
            independentlyPinned: observed === digestValue, authorizesKeyRelease: false });
        } catch (_) { deny(); }
      }
      async function restoreFromBackup({ expectedDigest }) {
        try {
          from64(expectedDigest, 32);
          if (input.backupProvider === null || await readLocal() !== null
            || await input.pinProvider.read() !== expectedDigest) deny();
          const restored = await syncFromBackup({ expectedDigest });
          return Object.freeze({ localIndexedDbCommitted: true, externallyPinnedDigest: expectedDigest,
            remoteCiphertextReadbackVerified: restored.providerReadbackVerified,
            independentCloudDurabilityProven: false });
        } catch (_) { deny(); }
      }
      async function verifyRotationEvidence(transition, previousOwnerPublicKey,
        independentPreviousOwnerSpkiSha256) {
          exact(transition, ["schema", "scope", "fromOwnerSpkiSha256",
            "toOwnerSpkiSha256", "fromHead", "toHead", "previousArchiveDigest",
            "nonce", "fromSignature", "toSignature"]);
          const signed = Object.fromEntries(Object.entries(transition).filter(
            ([field]) => !["fromSignature", "toSignature"].includes(field)));
          if (transition.schema !== "rootark-zk1-client-cek-owner-rotation/v1"
            || JSON.stringify(transition.scope) !== JSON.stringify(scope)
            || typeof transition.toOwnerSpkiSha256 !== "string"
            || transition.toOwnerSpkiSha256 !== b64(bytes(input.independentOwnerSpkiSha256, 32))
            || transition.fromOwnerSpkiSha256 !== b64(bytes(independentPreviousOwnerSpkiSha256, 32))
            || JSON.stringify(transition.toHead) !== JSON.stringify(head)
            ) deny();
          from64(transition.nonce, 32);
          from64(transition.previousArchiveDigest, 32);
          const oldHead = transition.fromHead;
          exact(oldHead, ["revision", "digest", "epoch"]);
          positive(oldHead.revision); from64(oldHead.digest, 32); positive(oldHead.epoch);
          if (head.revision <= oldHead.revision || head.epoch <= oldHead.epoch
            || transition.fromOwnerSpkiSha256 === transition.toOwnerSpkiSha256) deny();
          const previousSpki = await webCrypto.subtle.exportKey("spki", previousOwnerPublicKey);
          if (!same(await sha(previousSpki), bytes(independentPreviousOwnerSpkiSha256, 32))) deny();
          const signedBytes = message(OWNER_ROTATION, signed);
          if (!(await webCrypto.subtle.verify("Ed25519", previousOwnerPublicKey,
            from64(transition.fromSignature, 64), signedBytes))
            || !(await webCrypto.subtle.verify("Ed25519", input.ownerPublicKey,
              from64(transition.toSignature, 64), signedBytes))) deny();
          return oldHead;
      }
      async function rotateFromPreviousOwner({ transition, previousOwnerPublicKey,
        independentPreviousOwnerSpkiSha256, previousRecoverySecret }) {
        let priorSecret, plaintext;
        try {
          alive();
          if (input.ownerSigningKey === null || input.backupProvider === null) deny();
          const oldHead = await verifyRotationEvidence(transition, previousOwnerPublicKey,
            independentPreviousOwnerSpkiSha256);
          if (await input.pinProvider.read() !== transition.previousArchiveDigest) deny();
          priorSecret = bytes(previousRecoverySecret, 32);
          const old = await retrieveSignedArchive(transition.previousArchiveDigest,
            previousOwnerPublicKey);
          if (JSON.stringify(old.record.head) !== JSON.stringify(oldHead)
            || old.record.challenge.epoch !== oldHead.epoch) deny();
          const oldRows = await decryptRecord(old.record, priorSecret);
          if (oldRows.length < 1 || oldRows.length > MAX_ENTRIES) deny();
          const rawAtDestination = await readLocal();
          if (rawAtDestination !== null && rawAtDestination !== old.raw) deny();
          const anchor = oldRows[0];
          const request = { objectId: anchor.metadata.object_id, action: "rotate",
            epoch: head.epoch, nonce: transition.nonce,
            entries: [{ revision: anchor.revision, versionId: anchor.metadata.version_id,
              ciphertextDigest: anchor.ciphertextDigest }] };
          const salt = webCrypto.getRandomValues(new Uint8Array(32));
          const iv = webCrypto.getRandomValues(new Uint8Array(12));
          const rotated = { format: FORMAT, scope, head, sequence: old.record.sequence + 1,
            previousDigest: transition.previousArchiveDigest, challenge: request,
            salt: b64(salt), iv: b64(iv), ciphertext: "", signature: "" };
          if (!Number.isSafeInteger(rotated.sequence)) deny();
          plaintext = enc.encode(JSON.stringify(oldRows));
          if (plaintext.byteLength > MAX_RECORD / 2) deny();
          rotated.ciphertext = b64(new Uint8Array(await webCrypto.subtle.encrypt({
            name: "AES-GCM", iv, additionalData: aad(rotated), tagLength: 128 },
          await derive(salt), plaintext)));
          rotated.signature = b64(new Uint8Array(await webCrypto.subtle.sign(
            "Ed25519", input.ownerSigningKey, message(DOMAIN, unsigned(rotated)))));
          const raw = JSON.stringify(rotated);
          await verifyRecord(raw);
          await backup(raw);
          alive();
          if (await input.pinProvider.read() !== transition.previousArchiveDigest) deny();
          await writeCas(rawAtDestination, raw);
          const newDigest = await digest(raw);
          try {
            await input.pinProvider.compareAndSwap(transition.previousArchiveDigest, newDigest);
          } catch (_) { /* Lost pin ACK reconciled by fresh external floor GET. */ }
          if (await input.pinProvider.read() !== newDigest) deny();
          if ((await readPinned()).observed !== newDigest) deny();
          return Object.freeze({ localIndexedDbCommitted: true,
            independentlyPinnedDigest: newDigest, previousArchiveDigest: old.digest,
            signedOwnerRotationVerified: true, remoteCiphertextReadbackVerified: true,
            independentCloudDurabilityProven: false });
        } catch (_) { deny(); }
        finally { priorSecret?.fill(0); plaintext?.fill(0); }
      }
      async function adoptRotatedOwner({ transition, previousOwnerPublicKey,
        independentPreviousOwnerSpkiSha256, previousRecoverySecret,
        expectedDigest }) {
        let oldSecret;
        try {
          alive();
          const oldHead = await verifyRotationEvidence(transition, previousOwnerPublicKey,
            independentPreviousOwnerSpkiSha256);
          from64(expectedDigest, 32);
          if (await input.pinProvider.read() !== expectedDigest) deny();
          oldSecret = bytes(previousRecoverySecret, 32);
          const old = await retrieveSignedArchive(transition.previousArchiveDigest,
            previousOwnerPublicKey);
          if (JSON.stringify(old.record.head) !== JSON.stringify(oldHead)) deny();
          const historical = await decryptRecord(old.record, oldSecret);
          const newRecord = await retrieveSignedArchive(expectedDigest);
          await verifyRecord(newRecord.raw);
          if (newRecord.record.previousDigest !== old.digest
            || newRecord.record.sequence !== old.record.sequence + 1
            || newRecord.record.challenge.action !== "rotate"
            || newRecord.record.challenge.nonce !== transition.nonce) deny();
          const successor = await decryptRecord(newRecord.record);
          if (JSON.stringify(successor) !== JSON.stringify(historical)) deny();
          const oldLocal = await readLocal();
          if (oldLocal !== null && oldLocal !== old.raw) deny();
          alive();
          if (await input.pinProvider.read() !== expectedDigest) deny();
          await writeCas(oldLocal, newRecord.raw);
          if ((await readPinned()).observed !== expectedDigest) deny();
          return Object.freeze({ independentlyPinnedDigest: expectedDigest,
            previousArchiveDigest: old.digest, crossSignedOwnerRotationVerified: true,
            localIndexedDbCommitted: true, remoteCiphertextReadbackVerified: true,
            independentCloudDurabilityProven: false });
        } catch (_) { deny(); }
        finally { oldSecret?.fill(0); }
      }
      return Object.freeze({ archiveKeys, readArchivedCek, reconcileUncertainArchive,
        inspectPendingArchive, restoreFromBackup, syncFromBackup, rotateFromPreviousOwner,
        adoptRotatedOwner,
        createRenameArchiveBridge, createLogicalTrashBridge,
        close() { if (!closed) { closed = true; recoverySecret.fill(0); db.close(); } } });
    } catch (_) { recoverySecret?.fill(0); db?.close(); deny(); }
  }
  return Object.freeze({ openCekArchive });
}));
