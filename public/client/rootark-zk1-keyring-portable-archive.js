(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-portable-file-recovery"),
      require("./rootark-zk1-owner-ciphertext-root-checkpoint"),
      require("./rootark-zk1-normal-browser-trust-floor"),
      require("./rootark-zk1-owner-signed-checkpoint"));
  } else {
    root.RootarkZk1KeyringPortableArchive = factory(root.crypto,
      root.RootarkZk1PortableFileRecovery,
      root.RootarkZk1OwnerCiphertextRootCheckpoint,
      root.RootarkZk1NormalBrowserTrustFloor,
      root.RootarkZk1OwnerSignedCheckpoint);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (webCrypto, portable, ownerRoots, trustFloor, ownerHistory) {
    "use strict";

    // Development-only offline keyring snapshot, not server recovery authority.
    // The owner must independently retain (1) Ed25519 SPKI fingerprint,
    // (2) current owner head and (3) this exact archive SHA-256 out-of-band.
    // An archive or server reply cannot establish any of those trust anchors.
    const FORMAT = "rootark-zk1-keyring-portable-archive/v1";
    const CONTENT = "rootark-zk1-keyring-portable-contents/v1";
    const DOMAIN = new TextEncoder().encode("Root.ark/zk-1/keyring-archive-signed/v1\0");
    const KDF = new TextEncoder().encode("Root.ark/zk-1/keyring-archive-key/v1\0");
    const SCOPE = ["account_id", "compartment_id", "keyring_id"];
    const FILE_META = ["account_id", "compartment_id", "keyring_id",
      "object_id", "version_id", "parent_version_id", "epoch", "kind"];
    const OUTER = ["format", "scope", "ownerRevision", "ownerDigest", "ownerEpoch",
      "archiveId", "salt", "nonce", "ciphertextBase64", "signature"];
    const SIGNED = OUTER.slice(0, -1);
    const CONTENT_FIELDS = ["format", "signedDeviceGrant", "ownerHistoryCheckpoint", "entries"];
    const ENTRY = ["bundle", "ownerRootCheckpoint"];
    const MAX_FILES = 12;
    const MAX_PLAIN = 8 * 1024 * 1024;
    const MAX_ARCHIVE = 17 * 1024 * 1024;
    const enc = new TextEncoder();
    const dec = new TextDecoder("utf-8", { fatal: true });
    const re64 = /^[A-Za-z0-9_-]+$/;
    function deny() { throw new Error("ZK_KEYRING_ARCHIVE_DENIED"); }
    function exact(value, fields) {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
        || Reflect.ownKeys(value).length !== fields.length
        || fields.some((name) => !Object.hasOwn(value, name))
        || Reflect.ownKeys(value).some((name) => typeof name !== "string" || !fields.includes(name))) deny();
    }
    function bytes(value, count) {
      if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)
        || value.byteLength !== count
        || (typeof SharedArrayBuffer !== "undefined"
          && (value instanceof SharedArrayBuffer || value.buffer instanceof SharedArrayBuffer))) deny();
      return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
        : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    function detachedWire(value, maxFields = 20) {
      if (value === null) return null;
      if (!value || typeof value !== "object" || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny();
      const result = {};
      const names = Reflect.ownKeys(value);
      if (names.length < 1 || names.length > maxFields) deny();
      for (const name of names) {
        if (typeof name !== "string" || name.length > 80) deny();
        const desc = Object.getOwnPropertyDescriptor(value, name);
        if (!desc || !Object.hasOwn(desc, "value")
          || !(typeof desc.value === "string" || Number.isSafeInteger(desc.value)
            || desc.value === null)
          || (typeof desc.value === "string" && desc.value.length > 2048)) deny();
        result[name] = desc.value;
      }
      return Object.freeze(result);
    }
    function copyFiles(input) {
      if (!Array.isArray(input) || input.length < 1 || input.length > MAX_FILES
        || Reflect.ownKeys(input).length !== input.length + 1) deny();
      let total = 0;
      const output = [];
      try {
        for (let index = 0; index < input.length; index++) {
          const slot = Object.getOwnPropertyDescriptor(input, String(index));
          if (!slot || !Object.hasOwn(slot, "value")) deny();
          const file = slot.value;
          exact(file, ["metadata", "objectRevision", "name", "mediaType", "data"]);
          exact(file.metadata, FILE_META);
          const meta = Object.fromEntries(FILE_META.map((name) => {
            const prop = Object.getOwnPropertyDescriptor(file.metadata, name);
            if (!prop || !Object.hasOwn(prop, "value")) deny();
            return [name, prop.value];
          }));
          const inputBytes = file.data;
          if (!(inputBytes instanceof ArrayBuffer) && !ArrayBuffer.isView(inputBytes)) deny();
          total += inputBytes.byteLength;
          if (total > MAX_PLAIN) deny();
          output.push({ metadata: meta, objectRevision: file.objectRevision,
            name: file.name, mediaType: file.mediaType,
            data: bytes(inputBytes, inputBytes.byteLength) });
        }
        return output;
      } catch (_) {
        for (const file of output) file.data.fill(0);
        deny();
      }
    }
    function b64(raw) {
      let s = "";
      for (const v of raw) s += String.fromCharCode(v);
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function from64(value, min, max = min) {
      if (typeof value !== "string" || !re64.test(value)
        || value.length > Math.ceil(max * 4 / 3) + 4) deny();
      let binary;
      try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
      if (binary.length < min || binary.length > max) deny();
      const raw = Uint8Array.from(binary, (c) => c.charCodeAt(0));
      if (b64(raw) !== value) deny();
      return raw;
    }
    function positive(value) {
      if (!Number.isSafeInteger(value) || value < 1) deny();
      return value;
    }
    function scope(value) {
      exact(value, SCOPE);
      const copy = Object.fromEntries(SCOPE.map((key) => [key, value[key]]));
      for (const key of SCOPE) from64(copy[key], key === "compartment_id" ? 1 : 16,
        key === "compartment_id" ? 128 : 16);
      return copy;
    }
    function same(a, b) {
      if (a.length !== b.length) return false;
      let difference = 0;
      for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
      return difference === 0;
    }
    function signatureMessage(body) {
      const raw = enc.encode(JSON.stringify(Object.fromEntries(SIGNED.map((field) => [field, body[field]]))));
      if (raw.length > MAX_ARCHIVE) deny();
      const joined = new Uint8Array(DOMAIN.length + raw.length);
      joined.set(DOMAIN);
      joined.set(raw, DOMAIN.length);
      return joined;
    }
    async function archiveDigest(outer) {
      exact(outer, OUTER);
      const packed = enc.encode(JSON.stringify(Object.fromEntries(OUTER.map((field) => [field, outer[field]]))));
      if (packed.length > MAX_ARCHIVE) deny();
      return { digest: new Uint8Array(await webCrypto.subtle.digest("SHA-256", packed)), packed };
    }
    async function wrapping(secret, salt, context) {
      const base = await webCrypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
      const info = enc.encode(JSON.stringify(context));
      const payload = new Uint8Array(KDF.length + info.length);
      payload.set(KDF);
      payload.set(info, KDF.length);
      return webCrypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt,
        info: payload }, base, { name: "AES-GCM", length: 256 }, false,
      ["encrypt", "decrypt"]);
    }
    function key(value, kind) {
      if (!value || value.type !== kind || value.algorithm?.name !== "Ed25519"
        || !value.usages?.includes(kind === "private" ? "sign" : "verify")
        || (kind === "private" && value.extractable !== false)) deny();
      return value;
    }
    function validateEntries(entries, expectedScope, epoch) {
      if (!Array.isArray(entries) || entries.length < 1 || entries.length > MAX_FILES
        || Reflect.ownKeys(entries).length !== entries.length + 1) deny();
      const objects = new Set();
      const versions = new Set();
      let total = 0;
      for (const entry of entries) {
        exact(entry, ENTRY);
        const bundle = entry.bundle;
        if (!bundle || typeof bundle !== "object") deny();
        const meta = bundle.metadata;
        if (!meta || typeof meta !== "object" || !SCOPE.every((name) => meta[name] === expectedScope[name])
          || meta.kind !== "file" || !Number.isSafeInteger(meta.epoch)
          || meta.epoch < 1 || meta.epoch > epoch
          || !Number.isSafeInteger(bundle.objectRevision) || bundle.objectRevision < 1
          || objects.has(meta.object_id) || versions.has(meta.version_id)) deny();
        from64(meta.object_id, 16);
        from64(meta.version_id, 16);
        from64(bundle.ciphertextRoot, 32);
        from64(bundle.ciphertextSha256, 32);
        total += from64(bundle.ciphertextBase64, 1, 4 * 1024 * 1024).length;
        if (total > MAX_PLAIN * 2) deny();
        objects.add(meta.object_id);
        versions.add(meta.version_id);
      }
      // Canonical unique inventory order prevents alternate list permutations
      // from producing competing independent interpretations.
      for (let i = 1; i < entries.length; i++) {
        if (entries[i - 1].bundle.metadata.object_id >= entries[i].bundle.metadata.object_id) deny();
      }
    }
    function snapshotHistoricalRecovery(value) {
      exact(value, ["signedOwnerHistoryChain", "currentSignedDeviceGrant",
        "currentOwnerRootCheckpoints"]);
      const chain = value.signedOwnerHistoryChain;
      const roots = value.currentOwnerRootCheckpoints;
      if (!Array.isArray(chain) || chain.length < 2 || chain.length > 64
        || Reflect.ownKeys(chain).length !== chain.length + 1
        || !Array.isArray(roots) || roots.length < 1 || roots.length > MAX_FILES
        || Reflect.ownKeys(roots).length !== roots.length + 1) deny();
      const copyArray = (list) => Array.from({ length: list.length }, (_, index) => {
        const descriptor = Object.getOwnPropertyDescriptor(list, String(index));
        if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
        return detachedWire(descriptor.value);
      });
      return { chain: copyArray(chain), roots: copyArray(roots),
        currentGrant: detachedWire(value.currentSignedDeviceGrant) };
    }
    function sameSignedWire(a, b) {
      if (!a || !b || typeof b !== "object" || Array.isArray(b)) return false;
      const names = Reflect.ownKeys(a);
      return Reflect.ownKeys(b).length === names.length && names.every((name) => {
        const descriptor = Object.getOwnPropertyDescriptor(b, name);
        return descriptor && Object.hasOwn(descriptor, "value")
          && descriptor.value === a[name];
      });
    }
    async function verifyHistoricalRecovery({ historical, archive, payload, head,
      expectedScope, ownerPublicKey, ownerSpkiPin, signerKeyId, deviceId }) {
      if (!ownerHistory?.verifyOwnerCheckpoint
        || head.revision < archive.ownerRevision || head.epoch < archive.ownerEpoch
        || (head.revision === archive.ownerRevision && head.epoch === archive.ownerEpoch)
        || historical.roots.length !== payload.entries.length) deny();
      let previous = null;
      let archivedPrevious = null;
      let archivalMatched = false;
      let newestPrevious = null;
      for (let i = 0; i < historical.chain.length; i++) {
        const checkpoint = historical.chain[i];
        // The first checkpoint MUST be the signed genesis. A naked later
        // sequence, claimed digest or self-reported predecessor is worthless.
        if (i === 0 && checkpoint.sequence !== 1) deny();
        const brand = await ownerHistory.verifyOwnerCheckpoint({ checkpoint,
          scope: expectedScope, signerPublicKey: ownerPublicKey,
          signerKeyId, previous });
        if (brand.sequence !== i + 1 || checkpoint.device_id !== deviceId) deny();
        if (sameSignedWire(checkpoint, payload.ownerHistoryCheckpoint)) {
          if (archivalMatched || checkpoint.revision !== archive.ownerRevision
            || checkpoint.manifest_digest !== archive.ownerDigest) deny();
          archivedPrevious = previous;
          archivalMatched = true;
        }
        if (i === historical.chain.length - 1) newestPrevious = previous;
        previous = brand;
      }
      const newest = historical.chain[historical.chain.length - 1];
      if (!archivalMatched || !newestPrevious
        || newest.revision !== head.revision || newest.manifest_digest !== b64(head.digest)
        || newest.device_id !== deviceId) deny();
      // The archive's OLD grant is intentionally never used for present-day
      // authorization. Only a newly signed ACTIVE grant matching the independently
      // pinned CURRENT head can permit historical recovery.
      await verifyAnchors({ outer: { ownerRevision: head.revision,
        ownerDigest: b64(head.digest), ownerEpoch: head.epoch },
      ownerPublicKey, independentOwnerSpkiSha256: ownerSpkiPin,
      pinnedCurrentHead: head, signedDeviceGrant: historical.currentGrant,
      ownerHistoryCheckpoint: newest, previousOwnerHistoryProof: newestPrevious });
      await verifyEveryOwnerRoot(payload.entries, {
        ownerPublicKey, signerKeyId, deviceId, expectedScope,
        ownerHistoryCheckpoint: payload.ownerHistoryCheckpoint,
        previousOwnerHistoryProof: archivedPrevious,
        pinnedCurrentHead: { revision: archive.ownerRevision,
          digest: from64(archive.ownerDigest, 32), epoch: archive.ownerEpoch },
      });
      // A fresh owner signature must re-endorse the EXACT archived ciphertext
      // root at the latest pinned head. History alone cannot prove the file
      // still belongs to the current manifest after revocation/deletion.
      const endorsements = payload.entries.map((entry, index) => ({
        bundle: entry.bundle, ownerRootCheckpoint: historical.roots[index],
      }));
      await verifyEveryOwnerRoot(endorsements, {
        ownerPublicKey, signerKeyId, deviceId, expectedScope,
        ownerHistoryCheckpoint: newest, previousOwnerHistoryProof: newestPrevious,
        pinnedCurrentHead: head,
      });
    }
    async function verifyAnchors({ outer, signedDeviceGrant, ownerHistoryCheckpoint,
      previousOwnerHistoryProof, ownerPublicKey, independentOwnerSpkiSha256,
      pinnedCurrentHead }) {
      const verified = await trustFloor.verifyExternalAnchor({
        ownerPublicKey: key(ownerPublicKey, "public"),
        independentOwnerSpkiSha256: bytes(independentOwnerSpkiSha256, 32),
        pinnedCurrentHead, signedDeviceGrant, ownerHistoryCheckpoint,
        previousOwnerHistoryProof });
      if (!verified?.candidate || verified.candidate.revision !== outer.ownerRevision
        || verified.candidate.digest !== outer.ownerDigest
        || verified.candidate.epoch !== outer.ownerEpoch
        || signedDeviceGrant.device_id !== ownerHistoryCheckpoint.device_id
        || signedDeviceGrant.revoked_at_epoch !== null) deny();
    }
    async function verifyEveryOwnerRoot(entries, { ownerPublicKey, signerKeyId,
      deviceId, ownerHistoryCheckpoint, previousOwnerHistoryProof, pinnedCurrentHead,
      expectedScope }) {
      for (const entry of entries) {
        const bundle = entry.bundle;
        const proof = await ownerRoots.verifyOwnerCiphertextRootCheckpoint({
          checkpoint: entry.ownerRootCheckpoint,
          ownerHistoryCheckpoint, previousHistoryProof: previousOwnerHistoryProof,
          pinnedOwner: { scope: expectedScope, deviceId,
            signerKeyId: bytes(signerKeyId, 16), publicKey: ownerPublicKey },
          expected: { manifestRevision: pinnedCurrentHead.revision,
            manifestDigest: bytes(pinnedCurrentHead.digest, 32),
            manifestEpoch: pinnedCurrentHead.epoch,
            objectId: bundle.metadata.object_id, objectRevision: bundle.objectRevision,
            ciphertextEpoch: bundle.metadata.epoch,
            ciphertextRoot: from64(bundle.ciphertextRoot, 32) },
        });
        if (proof.trustedOwnerSignatureVerified !== true
          || proof.manifestCheckpointVerified !== true
          || proof.authorizesRecovery !== false) deny();
      }
    }
    async function createArchive(input) {
      let secret, contents, openedBytes, fixedFiles;
      try {
        exact(input, ["recoverySecret", "ownerSigningKey", "ownerPublicKey",
          "independentOwnerSpkiSha256", "pinnedCurrentHead", "scope", "files",
          "ownerHistoryCheckpoint", "previousOwnerHistoryProof", "signedDeviceGrant",
          "signerKeyId", "deviceId", "issuedAt"]);
        if (!webCrypto?.subtle || !portable?.sealForUserHeldSecret) deny();
        secret = bytes(input.recoverySecret, 32);
        const expectedScope = scope(input.scope);
        exact(input.pinnedCurrentHead, ["revision", "digest", "epoch"]);
        const head = { revision: input.pinnedCurrentHead.revision,
          digest: bytes(input.pinnedCurrentHead.digest, 32),
          epoch: input.pinnedCurrentHead.epoch };
        const ownerDigest = b64(bytes(head.digest, 32));
        positive(head.revision); positive(head.epoch); positive(input.issuedAt);
        const ownerPublicKey = key(input.ownerPublicKey, "public");
        const signingKey = key(input.ownerSigningKey, "private");
        const grant = detachedWire(input.signedDeviceGrant);
        const history = detachedWire(input.ownerHistoryCheckpoint);
        const spkiPin = bytes(input.independentOwnerSpkiSha256, 32);
        const id = bytes(input.signerKeyId, 16);
        const previous = input.previousOwnerHistoryProof; // preserve WeakMap brand
        const ownerDevice = input.deviceId;
        const signedAt = input.issuedAt;
        fixedFiles = copyFiles(input.files);
        const marker = { ownerRevision: head.revision, ownerDigest,
          ownerEpoch: head.epoch };
        await verifyAnchors({ outer: marker, ownerPublicKey,
          independentOwnerSpkiSha256: spkiPin, pinnedCurrentHead: head,
          signedDeviceGrant: grant, ownerHistoryCheckpoint: history,
          previousOwnerHistoryProof: previous });
        let totalBytes = 0;
        const entries = [];
        for (const file of fixedFiles) {
          totalBytes += file.data.byteLength;
          if (totalBytes > MAX_PLAIN) deny();
          const bundle = await portable.sealForUserHeldSecret({
            recoverySecret: secret, metadata: file.metadata,
            name: file.name, mediaType: file.mediaType, data: file.data,
            objectRevision: file.objectRevision });
          const rootCheckpoint = await ownerRoots.signOwnerCiphertextRootCheckpoint({
            scope: expectedScope, signerKey: signingKey,
            signerKeyId: id, deviceId: ownerDevice,
            manifestRevision: head.revision, manifestDigest: bytes(head.digest, 32),
            manifestEpoch: head.epoch, objectId: bundle.metadata.object_id,
            objectRevision: bundle.objectRevision, ciphertextEpoch: bundle.metadata.epoch,
            ciphertextRoot: from64(bundle.ciphertextRoot, 32), issuedAt: signedAt });
          entries.push({ bundle, ownerRootCheckpoint: rootCheckpoint });
        }
        entries.sort((a, b) => a.bundle.metadata.object_id < b.bundle.metadata.object_id ? -1
          : a.bundle.metadata.object_id > b.bundle.metadata.object_id ? 1 : 0);
        validateEntries(entries, expectedScope, head.epoch);
        await verifyEveryOwnerRoot(entries, { ownerPublicKey,
          signerKeyId: id, deviceId: ownerDevice,
          ownerHistoryCheckpoint: history, previousOwnerHistoryProof: previous,
          pinnedCurrentHead: head, expectedScope });
        // The complete object inventory, metadata, grant, wrapped CEKs and
        // signed per-file roots stay ENCRYPTED in the portable outer envelope.
        contents = enc.encode(JSON.stringify({ format: CONTENT,
          signedDeviceGrant: grant,
          ownerHistoryCheckpoint: history, entries }));
        if (contents.length > MAX_ARCHIVE / 2) deny();
        const salt = webCrypto.getRandomValues(new Uint8Array(32));
        const nonce = webCrypto.getRandomValues(new Uint8Array(12));
        const archiveId = webCrypto.getRandomValues(new Uint8Array(16));
        const context = { format: FORMAT, scope: expectedScope, ...marker,
          archiveId: b64(archiveId) };
        const archiveKey = await wrapping(secret, salt, context);
        openedBytes = new Uint8Array(await webCrypto.subtle.encrypt({ name: "AES-GCM",
          iv: nonce, additionalData: enc.encode(JSON.stringify(context)), tagLength: 128 },
        archiveKey, contents));
        const unsigned = { ...context, salt: b64(salt), nonce: b64(nonce),
          ciphertextBase64: b64(openedBytes) };
        const signature = new Uint8Array(await webCrypto.subtle.sign("Ed25519",
          signingKey, signatureMessage(unsigned)));
        const archive = Object.freeze({ ...unsigned, signature: b64(signature) });
        const { digest } = await archiveDigest(archive);
        return Object.freeze({ archive, archiveSha256: digest,
          // Only a separately stored copy of this hash is a trusted pin.
          independentlyPinnedByModule: false, authorizesProductionRestore: false });
      } catch (_) { deny(); }
      finally { secret?.fill(0); contents?.fill(0); openedBytes?.fill(0);
        for (const file of fixedFiles || []) file.data.fill(0); }
    }
    async function recoverArchive(input) {
      let secret, decrypted, recovered = [];
      try {
        const historic = Object.hasOwn(input || {}, "historicalRecovery");
        exact(input, ["archive", "recoverySecret", "ownerPublicKey",
          "independentOwnerSpkiSha256", "independentlyPinnedArchiveSha256",
          "pinnedCurrentHead", "scope", "signerKeyId", "deviceId",
          "previousOwnerHistoryProof", ...(historic ? ["historicalRecovery"] : [])]);
        secret = bytes(input.recoverySecret, 32);
        exact(input.archive, OUTER);
        const archive = Object.fromEntries(OUTER.map((name) => {
          const prop = Object.getOwnPropertyDescriptor(input.archive, name);
          if (!prop || !Object.hasOwn(prop, "value")) deny();
          return [name, prop.value];
        }));
        if (archive.format !== FORMAT) deny();
        archive.scope = scope(archive.scope);
        const expectedScope = scope(input.scope);
        if (!SCOPE.every((name) => archive.scope[name] === expectedScope[name])) deny();
        const ownerPublicKey = key(input.ownerPublicKey, "public");
        exact(input.pinnedCurrentHead, ["revision", "digest", "epoch"]);
        const head = { revision: input.pinnedCurrentHead.revision,
          digest: bytes(input.pinnedCurrentHead.digest, 32),
          epoch: input.pinnedCurrentHead.epoch };
        const ownerSpkiPin = bytes(input.independentOwnerSpkiSha256, 32);
        const archivePin = bytes(input.independentlyPinnedArchiveSha256, 32);
        const trustedSigner = bytes(input.signerKeyId, 16);
        const trustedDevice = input.deviceId;
        const predecessor = input.previousOwnerHistoryProof; // in-process brand
        const historical = historic ? snapshotHistoricalRecovery(input.historicalRecovery) : null;
        positive(head.revision); positive(head.epoch);
        if (historic ? predecessor !== null
          : (archive.ownerRevision !== head.revision
            || archive.ownerDigest !== b64(head.digest)
            || archive.ownerEpoch !== head.epoch)) deny();
        const { digest } = await archiveDigest(archive);
        if (!same(digest, archivePin)) deny();
        if (!await webCrypto.subtle.verify("Ed25519", ownerPublicKey,
          from64(archive.signature, 64), signatureMessage(archive))) deny();
        const context = { format: FORMAT, scope: expectedScope,
          ownerRevision: archive.ownerRevision, ownerDigest: archive.ownerDigest,
          ownerEpoch: archive.ownerEpoch, archiveId: archive.archiveId };
        from64(archive.archiveId, 16);
        const archiveKey = await wrapping(secret, from64(archive.salt, 32), context);
        const encrypted = from64(archive.ciphertextBase64, 17, MAX_ARCHIVE);
        decrypted = new Uint8Array(await webCrypto.subtle.decrypt({ name: "AES-GCM",
          iv: from64(archive.nonce, 12), additionalData: enc.encode(JSON.stringify(context)),
          tagLength: 128 }, archiveKey, encrypted));
        if (decrypted.length > MAX_ARCHIVE / 2) deny();
        let payload;
        try { payload = JSON.parse(dec.decode(decrypted)); } catch (_) { deny(); }
        exact(payload, CONTENT_FIELDS);
        if (payload.format !== CONTENT) deny();
        validateEntries(payload.entries, expectedScope, archive.ownerEpoch);
        if (historic) await verifyHistoricalRecovery({ historical, archive,
          payload, head, expectedScope, ownerPublicKey,
          ownerSpkiPin, signerKeyId: trustedSigner, deviceId: trustedDevice });
        else {
          await verifyAnchors({ outer: archive, ownerPublicKey,
            independentOwnerSpkiSha256: ownerSpkiPin,
            pinnedCurrentHead: head, signedDeviceGrant: payload.signedDeviceGrant,
            ownerHistoryCheckpoint: payload.ownerHistoryCheckpoint,
            previousOwnerHistoryProof: predecessor });
          await verifyEveryOwnerRoot(payload.entries, {
            ownerPublicKey, signerKeyId: trustedSigner, deviceId: trustedDevice,
            ownerHistoryCheckpoint: payload.ownerHistoryCheckpoint,
            previousOwnerHistoryProof: predecessor,
            pinnedCurrentHead: head, expectedScope });
        }
        // No partial release: accumulate privately until ALL files and
        // signatures have succeeded. On any failure wipe every opened file.
        for (const item of payload.entries) {
          const opened = await portable.openWithIndependentRoot({
            recoverySecret: secret, bundle: item.bundle,
            expectedMetadata: item.bundle.metadata,
            independentlyPinnedCiphertextRoot: from64(item.bundle.ciphertextRoot, 32) });
          recovered.push(Object.freeze({ objectId: item.bundle.metadata.object_id,
            objectRevision: item.bundle.objectRevision, metadata: item.bundle.metadata,
            name: opened.name, mediaType: opened.mediaType, data: opened.data }));
        }
        const result = Object.freeze({ files: Object.freeze(recovered),
          signedManifestVerified: true, allOwnerSignedRootsVerified: true,
          independentArchiveHashMatched: true, activeSignedGrantAtPinnedHeadVerified: true,
          currentSignedGrantAtPinnedHeadVerified: true,
          historicalOwnerContinuityVerified: historic,
          currentOnlineRevocationVerified: false,
          independentPinProvenanceVerifiedByModule: false,
          authorizesProductionRestore: false });
        recovered = [];
        return result;
      } catch (_) { for (const item of recovered) item.data?.fill(0); deny(); }
      finally { secret?.fill(0); decrypted?.fill(0); }
    }
    return Object.freeze({ createArchive, recoverArchive });
  }));
