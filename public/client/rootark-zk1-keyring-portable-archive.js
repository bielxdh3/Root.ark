(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-portable-file-recovery"),
      require("./rootark-zk1-owner-ciphertext-root-checkpoint"),
      require("./rootark-zk1-normal-browser-trust-floor"),
      require("./rootark-zk1-owner-signed-checkpoint"),
      require("./rootark-zk1-authoritative-backup-inventory"),
      require("./rootark-zk1-owner-account-backup-roster"),
      require("./rootark-zk1-ciphertext-chunk-root"),
      require("./rootark-zk1-file-content"));
  } else {
    root.RootarkZk1KeyringPortableArchive = factory(root.crypto,
      root.RootarkZk1PortableFileRecovery,
      root.RootarkZk1OwnerCiphertextRootCheckpoint,
      root.RootarkZk1NormalBrowserTrustFloor,
      root.RootarkZk1OwnerSignedCheckpoint,
      root.RootarkZk1BrowserAuthoritativeBackup?.inventoryBridge,
      root.RootarkZk1BrowserAuthoritativeBackup?.rosterBridge,
      root.RootarkZk1CiphertextRoot, root.RootarkZk1FileContent);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (webCrypto, portable, ownerRoots, trustFloor, ownerHistory,
    backupInventory, accountRoster, ciphertextRoots, fileContent) {
    "use strict";

    // Development-only offline keyring snapshot, not server recovery authority.
    // The owner must independently retain (1) Ed25519 SPKI fingerprint,
    // (2) current owner head and (3) this exact archive SHA-256 out-of-band.
    // An archive or server reply cannot establish any of those trust anchors.
    const FORMAT = "rootark-zk1-keyring-portable-archive/v1";
    const CONTENT = "rootark-zk1-keyring-portable-contents/v1";
    const VERSIONED_FORMAT = "rootark-zk1-keyring-portable-archive/v2";
    const VERSIONED_CONTENT = "rootark-zk1-keyring-portable-contents/v2";
    const VERSION_PACKET = "rootark-zk1-versioned-ciphertext-cek/v1";
    const DOMAIN = new TextEncoder().encode("Root.ark/zk-1/keyring-archive-signed/v1\0");
    const KDF = new TextEncoder().encode("Root.ark/zk-1/keyring-archive-key/v1\0");
    const SCOPE = ["account_id", "compartment_id", "keyring_id"];
    const FILE_META = ["account_id", "compartment_id", "keyring_id",
      "object_id", "version_id", "parent_version_id", "epoch", "kind"];
    const OUTER = ["format", "scope", "ownerRevision", "ownerDigest", "ownerEpoch",
      "archiveId", "salt", "nonce", "ciphertextBase64", "signature"];
    const SIGNED = OUTER.slice(0, -1);
    const CONTENT_FIELDS = ["format", "signedDeviceGrant", "ownerHistoryCheckpoint", "entries"];
    const VERSIONED_CONTENT_FIELDS = [...CONTENT_FIELDS, "versionProof"];
    const VERSION_PROOF_FIELDS = ["snapshotSha256", "rosterSha256",
      "inventoryCheckpointDigest", "inventoryRoot", "inventorySequence"];
    const PACKET_FIELDS = ["format", "ciphertextBase64", "cekBase64"];
    const ENTRY = ["bundle", "ownerRootCheckpoint"];
    const MAX_FILES = 12;
    const MAX_PLAIN = 8 * 1024 * 1024;
    const MAX_ARCHIVE = 17 * 1024 * 1024;
    const POP_SCHEMA = "rootark-zk1-historical-device-pop/v1";
    const POP_DOMAIN = new TextEncoder().encode("Root.ark/zk-1/historical-device-pop/v1\0");
    const POP_TTL_MS = 120000;
    const issuedPop = new WeakMap();
    const versionAuthorities = new WeakMap();
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
    function compareIds(a, b) {
      const left = from64(a, 16), right = from64(b, 16);
      for (let i = 0; i < 16; i++) {
        if (left[i] !== right[i]) return left[i] < right[i] ? -1 : 1;
      }
      return 0;
    }
    // The owner-signed ACTIVE grant is necessary but NOT device proof of
    // possession. The signer must prove possession of the distinct grant key
    // against a freshly minted, one-use, privately branded challenge.
    function popBinding(input) {
      exact(input, ["archiveSha256", "accountArchiveSha256", "scope",
        "pinnedCurrentHead", "independentOwnerSpkiSha256", "currentSignedDeviceGrant"]);
      const trustedScope = scope(input.scope);
      exact(input.pinnedCurrentHead, ["revision", "digest", "epoch"]);
      const revision = positive(input.pinnedCurrentHead.revision);
      const epoch = positive(input.pinnedCurrentHead.epoch);
      const grant = detachedWire(input.currentSignedDeviceGrant);
      if (typeof grant.device_id !== "string" || !grant.device_id) deny();
      return { schema: POP_SCHEMA, purpose: "historical-ciphertext-recovery",
        archiveSha256: b64(bytes(input.archiveSha256, 32)),
        accountArchiveSha256: input.accountArchiveSha256 === null ? null
          : b64(bytes(input.accountArchiveSha256, 32)),
        scope: trustedScope, ownerRevision: revision,
        ownerDigest: b64(bytes(input.pinnedCurrentHead.digest, 32)),
        ownerEpoch: epoch,
        ownerSpkiSha256: b64(bytes(input.independentOwnerSpkiSha256, 32)),
        currentGrant: grant };
    }
    function popMessage(challenge) {
      const encoded = enc.encode(JSON.stringify(challenge));
      if (encoded.byteLength > 4096) deny();
      const message = new Uint8Array(POP_DOMAIN.length + encoded.length);
      message.set(POP_DOMAIN); message.set(encoded, POP_DOMAIN.length);
      return message;
    }
    function freshPop(issued) {
      const wall = Date.now();
      if (!Number.isSafeInteger(wall) || wall < issued.issuedAtMs
        || wall > issued.expiresAtMs) deny();
      if (issued.monotonicStart !== null && typeof performance === "object"
        && typeof performance.now === "function"
        && (performance.now() < issued.monotonicStart
          || performance.now() - issued.monotonicStart > POP_TTL_MS)) deny();
    }
    async function issueHistoricalRecoveryChallenge(input) {
      try {
        if (!webCrypto?.subtle?.digest || !webCrypto?.getRandomValues) deny();
        const binding = popBinding(input); // snapshot all caller fields before await
        const bindingHash = new Uint8Array(await webCrypto.subtle.digest("SHA-256",
          enc.encode(JSON.stringify(binding))));
        const issuedAtMs = Date.now();
        if (!Number.isSafeInteger(issuedAtMs)
          || !Number.isSafeInteger(issuedAtMs + POP_TTL_MS)) deny();
        const challenge = Object.freeze({ schema: POP_SCHEMA,
          nonce: b64(webCrypto.getRandomValues(new Uint8Array(32))),
          issuedAtMs, expiresAtMs: issuedAtMs + POP_TTL_MS,
          bindingSha256: b64(bindingHash) });
        issuedPop.set(challenge, { used: false, bindingHash,
          issuedAtMs, expiresAtMs: challenge.expiresAtMs,
          monotonicStart: typeof performance === "object"
            && typeof performance.now === "function" ? performance.now() : null,
          message: popMessage(challenge) });
        return challenge;
      } catch (_) { deny(); }
    }
    function historicalRecoveryChallengeMessage(challenge) {
      const record = issuedPop.get(challenge);
      if (!record || record.used) deny();
      freshPop(record);
      return new Uint8Array(record.message);
    }
    async function verifyDevicePop(pop, input) {
      exact(pop, ["challenge", "signature"]);
      const record = issuedPop.get(pop.challenge);
      if (!record || record.used) deny();
      // Reserve before the first await; parallel or replayed callers cannot
      // consume one device signature twice, even when validation fails.
      record.used = true;
      freshPop(record);
      const signature = from64(pop.signature, 64);
      const expected = popBinding(input);
      const digest = new Uint8Array(await webCrypto.subtle.digest("SHA-256",
        enc.encode(JSON.stringify(expected))));
      if (!same(digest, record.bindingHash)) deny();
      const signer = await webCrypto.subtle.importKey("raw",
        from64(input.currentSignedDeviceGrant.authorization_public_key, 32),
        { name: "Ed25519" }, false, ["verify"]);
      if (!await webCrypto.subtle.verify("Ed25519", signer, signature,
        record.message)) deny();
      freshPop(record);
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
    function validateEntries(entries, expectedScope, epoch, versioned = false) {
      if (!Array.isArray(entries) || entries.length < 1 || entries.length > MAX_FILES
        || Reflect.ownKeys(entries).length !== entries.length + 1) deny();
      const objects = new Set();
      const versions = new Set();
      let previous = null;
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
          || (!versioned && objects.has(meta.object_id))
          || versions.has(meta.version_id)) deny();
        from64(meta.object_id, 16);
        from64(meta.version_id, 16);
        if (meta.parent_version_id !== null) from64(meta.parent_version_id, 16);
        from64(bundle.ciphertextRoot, 32);
        from64(bundle.ciphertextSha256, 32);
        total += from64(bundle.ciphertextBase64, 1, 4 * 1024 * 1024).length;
        if (total > MAX_PLAIN * 2) deny();
        objects.add(meta.object_id);
        versions.add(meta.version_id);
        if (versioned) {
          if (previous && compareIds(previous.metadata.object_id, meta.object_id) > 0) deny();
          const ancestor = previous && previous.metadata.object_id === meta.object_id
            ? previous : null;
          if (bundle.objectRevision !== (ancestor ? ancestor.objectRevision + 1 : 1)
            || meta.parent_version_id !== (ancestor ? ancestor.metadata.version_id : null)
            || (ancestor && meta.epoch < ancestor.metadata.epoch)) deny();
          previous = bundle;
        }
      }
      // Canonical unique inventory order prevents alternate list permutations
      // from producing competing independent interpretations.
      if (!versioned) for (let i = 1; i < entries.length; i++) {
        if (entries[i - 1].bundle.metadata.object_id >= entries[i].bundle.metadata.object_id) deny();
      }
    }
    function authorityFor(value, expectedScope, head) {
      const auth = value && versionAuthorities.get(value);
      if (!auth || SCOPE.some((name) => auth.scope[name] !== expectedScope[name])
        || auth.head.revision !== head.revision || auth.head.epoch !== head.epoch
        || auth.head.digest !== b64(head.digest)) deny();
      return auth;
    }
    // A capability exists only after BOTH independently pinned, signed
    // inventories and the complete owner roster were verified. Node-only DEV:
    // the browser UMD cannot mint this authority from self-reported JSON.
    async function verifyVersionedAuthority(input) {
      try {
        exact(input, ["backupVerification", "rosterVerification",
          "otherVerifiedKeyringProofs"]);
        if (!backupInventory?.verifyBackupSnapshot
          || !backupInventory?.readVerifiedBackupProof
          || !accountRoster?.verifyOwnerRosterCoverage) deny();
        const snapshotWire = JSON.stringify(input.backupVerification.snapshot);
        const rosterWire = JSON.stringify(input.rosterVerification.roster);
        if (typeof snapshotWire !== "string" || snapshotWire.length > MAX_ARCHIVE
          || typeof rosterWire !== "string" || rosterWire.length > 20000) deny();
        const snapshot = JSON.parse(snapshotWire);
        const roster = JSON.parse(rosterWire);
        const proof = await backupInventory.verifyBackupSnapshot({
          ...input.backupVerification, snapshot });
        const others = input.otherVerifiedKeyringProofs;
        if (!Array.isArray(others) || others.length > 7
          || Reflect.ownKeys(others).length !== others.length + 1) deny();
        await accountRoster.verifyOwnerRosterCoverage({
          ...input.rosterVerification, roster,
          verifiedKeyringProofs: [proof, ...others] });
        const own = backupInventory.readVerifiedBackupProof(proof);
        const sc = scope(snapshot.scope);
        if (input.rosterVerification.accountId !== sc.account_id
          || own.snapshotSha256 !== b64(bytes(
            input.backupVerification.independentlyPinnedBackupSha256, 32))
          || own.ownerSpkiSha256 !== Array.from(
            bytes(input.backupVerification.independentOwnerSpkiSha256, 32),
            (v) => v.toString(16).padStart(2, "0")).join("")) deny();
        const head = { revision: snapshot.ownerRevision,
          digest: snapshot.ownerDigest, epoch: snapshot.ownerEpoch };
        const rows = snapshot.items.map((item) => ({
          objectId: item.objectId, revision: item.revision, epoch: item.epoch,
          ciphertextSha256: item.ciphertextSha256,
          ciphertextRoot: item.ciphertextRoot,
          ciphertextBase64: item.ciphertextBase64 }));
        if (rows.length < 1 || rows.length > MAX_FILES) deny();
        const versionProof = Object.freeze({
          snapshotSha256: own.snapshotSha256,
          rosterSha256: b64(bytes(input.rosterVerification.independentlyPinnedRosterSha256, 32)),
          inventoryCheckpointDigest: own.inventoryCheckpointDigest,
          inventoryRoot: own.inventoryRoot, inventorySequence: own.inventorySequence });
        const capability = Object.freeze({ completeRelativeToOwnerCheckpoint: true,
          globalAccountCompletenessProven: false, authorizesProductionRestore: false });
        versionAuthorities.set(capability, Object.freeze({ scope: sc, head,
          rows, versionProof }));
        return capability;
      } catch (_) { deny(); }
    }
    async function decodePacket(raw, expectedRow, metadata) {
      let encoded, cek, opened;
      try {
        if (!expectedRow || !fileContent?.importFileCek || !fileContent?.decryptFile) deny();
        const packet = JSON.parse(dec.decode(raw));
        exact(packet, PACKET_FIELDS);
        if (packet.format !== VERSION_PACKET) deny();
        encoded = from64(packet.ciphertextBase64, 16, 4 * 1024 * 1024);
        cek = from64(packet.cekBase64, 32);
        const sha = new Uint8Array(await webCrypto.subtle.digest("SHA-256", encoded));
        const root = await ciphertextRoots.computeCiphertextRoot([encoded]);
        if (packet.ciphertextBase64 !== expectedRow.ciphertextBase64
          || !same(sha, from64(expectedRow.ciphertextSha256, 32))
          || !same(bytes(root, 32), from64(expectedRow.ciphertextRoot, 32))) deny();
        // The original zk-1 ciphertext MUST actually authenticate under this
        // exact CEK and version metadata; hash/root alone cannot prove that.
        const cekKey = await fileContent.importFileCek(cek);
        opened = await fileContent.decryptFile({ cek: cekKey, metadata,
          envelopeBytes: encoded });
        return { ciphertext: encoded, cek };
      } catch (_) { encoded?.fill(0); cek?.fill(0); deny(); }
      finally { opened?.data?.fill(0); }
    }
    async function verifyVersionedData(files, entries, authority) {
      if (entries.length !== authority.rows.length || files.length !== entries.length) deny();
      for (let index = 0; index < entries.length; index++) {
        const bundle = entries[index].bundle;
        const row = authority.rows[index];
        if (bundle.metadata.object_id !== row.objectId
          || bundle.objectRevision !== row.revision
          || bundle.metadata.epoch !== row.epoch) deny();
        const packet = await decodePacket(files[index].data, row, bundle.metadata);
        packet.ciphertext.fill(0); packet.cek.fill(0);
      }
    }
    function snapshotHistoricalRecovery(value) {
      exact(value, ["signedOwnerHistoryChain", "currentSignedDeviceGrant",
        "currentOwnerRootCheckpoints", "devicePoP"]);
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
      const proof = value.devicePoP;
      exact(proof, ["challenge", "signature"]);
      const challenge = Object.getOwnPropertyDescriptor(proof, "challenge");
      const signature = Object.getOwnPropertyDescriptor(proof, "signature");
      if (!challenge || !Object.hasOwn(challenge, "value")
        || !signature || !Object.hasOwn(signature, "value")) deny();
      from64(signature.value, 64);
      return { chain: copyArray(chain), roots: copyArray(roots),
        currentGrant: detachedWire(value.currentSignedDeviceGrant),
        devicePoP: Object.freeze({ challenge: challenge.value,
          signature: signature.value }) };
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
      expectedScope, ownerPublicKey, ownerSpkiPin, signerKeyId, deviceId,
      archivePin, accountPin }) {
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
      await verifyDevicePop(historical.devicePoP, {
        archiveSha256: archivePin, accountArchiveSha256: accountPin,
        scope: expectedScope, pinnedCurrentHead: head,
        independentOwnerSpkiSha256: ownerSpkiPin,
        currentSignedDeviceGrant: historical.currentGrant });
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
        const versioned = Object.hasOwn(input || {}, "versionedAuthority");
        exact(input, ["recoverySecret", "ownerSigningKey", "ownerPublicKey",
          "independentOwnerSpkiSha256", "pinnedCurrentHead", "scope", "files",
          "ownerHistoryCheckpoint", "previousOwnerHistoryProof", "signedDeviceGrant",
          "signerKeyId", "deviceId", "issuedAt",
          ...(versioned ? ["versionedAuthority"] : [])]);
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
        const authority = versioned
          ? authorityFor(input.versionedAuthority, expectedScope, head) : null;
        if (versioned) fixedFiles.sort((a, b) =>
          compareIds(a.metadata.object_id, b.metadata.object_id)
          || a.objectRevision - b.objectRevision);
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
        entries.sort((a, b) => versioned
          ? compareIds(a.bundle.metadata.object_id, b.bundle.metadata.object_id)
            || a.bundle.objectRevision - b.bundle.objectRevision
          : a.bundle.metadata.object_id < b.bundle.metadata.object_id ? -1
            : a.bundle.metadata.object_id > b.bundle.metadata.object_id ? 1 : 0);
        validateEntries(entries, expectedScope, head.epoch, versioned);
        if (versioned) await verifyVersionedData(fixedFiles, entries, authority);
        await verifyEveryOwnerRoot(entries, { ownerPublicKey,
          signerKeyId: id, deviceId: ownerDevice,
          ownerHistoryCheckpoint: history, previousOwnerHistoryProof: previous,
          pinnedCurrentHead: head, expectedScope });
        // The complete object inventory, metadata, grant, wrapped CEKs and
        // signed per-file roots stay ENCRYPTED in the portable outer envelope.
        contents = enc.encode(JSON.stringify({ format: versioned ? VERSIONED_CONTENT : CONTENT,
          signedDeviceGrant: grant,
          ownerHistoryCheckpoint: history, entries,
          ...(versioned ? { versionProof: authority.versionProof } : {}) }));
        if (contents.length > MAX_ARCHIVE / 2) deny();
        const salt = webCrypto.getRandomValues(new Uint8Array(32));
        const nonce = webCrypto.getRandomValues(new Uint8Array(12));
        const archiveId = webCrypto.getRandomValues(new Uint8Array(16));
        const context = { format: versioned ? VERSIONED_FORMAT : FORMAT,
          scope: expectedScope, ...marker,
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
        const aggregate = Object.hasOwn(input || {}, "accountArchiveSha256");
        const versioned = Object.hasOwn(input || {}, "versionedAuthority");
        exact(input, ["archive", "recoverySecret", "ownerPublicKey",
          "independentOwnerSpkiSha256", "independentlyPinnedArchiveSha256",
          "pinnedCurrentHead", "scope", "signerKeyId", "deviceId",
          "previousOwnerHistoryProof", ...(historic ? ["historicalRecovery"] : []),
          ...(aggregate ? ["accountArchiveSha256"] : []),
          ...(versioned ? ["versionedAuthority"] : [])]);
        if (aggregate && !historic) deny();
        secret = bytes(input.recoverySecret, 32);
        exact(input.archive, OUTER);
        const archive = Object.fromEntries(OUTER.map((name) => {
          const prop = Object.getOwnPropertyDescriptor(input.archive, name);
          if (!prop || !Object.hasOwn(prop, "value")) deny();
          return [name, prop.value];
        }));
        if (archive.format !== (versioned ? VERSIONED_FORMAT : FORMAT)) deny();
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
        const accountPin = aggregate ? bytes(input.accountArchiveSha256, 32) : null;
        const trustedSigner = bytes(input.signerKeyId, 16);
        const trustedDevice = input.deviceId;
        const predecessor = input.previousOwnerHistoryProof; // in-process brand
        const historical = historic ? snapshotHistoricalRecovery(input.historicalRecovery) : null;
        const authority = versioned
          ? versionAuthorities.get(input.versionedAuthority) : null;
        if (versioned && (!authority
          || SCOPE.some((name) => authority.scope[name] !== expectedScope[name])
          || authority.head.revision !== archive.ownerRevision
          || authority.head.digest !== archive.ownerDigest
          || authority.head.epoch !== archive.ownerEpoch)) deny();
        positive(head.revision); positive(head.epoch);
        if (historic ? predecessor !== null
          : (archive.ownerRevision !== head.revision
            || archive.ownerDigest !== b64(head.digest)
            || archive.ownerEpoch !== head.epoch)) deny();
        const { digest } = await archiveDigest(archive);
        if (!same(digest, archivePin)) deny();
        if (!await webCrypto.subtle.verify("Ed25519", ownerPublicKey,
          from64(archive.signature, 64), signatureMessage(archive))) deny();
        const context = { format: versioned ? VERSIONED_FORMAT : FORMAT, scope: expectedScope,
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
        exact(payload, versioned ? VERSIONED_CONTENT_FIELDS : CONTENT_FIELDS);
        if (payload.format !== (versioned ? VERSIONED_CONTENT : CONTENT)) deny();
        validateEntries(payload.entries, expectedScope, archive.ownerEpoch, versioned);
        if (versioned) {
          exact(payload.versionProof, VERSION_PROOF_FIELDS);
          if (JSON.stringify(payload.versionProof) !== JSON.stringify(authority.versionProof)
            || payload.entries.length !== authority.rows.length) deny();
        }
        if (historic) await verifyHistoricalRecovery({ historical, archive,
          payload, head, expectedScope, ownerPublicKey,
          ownerSpkiPin, signerKeyId: trustedSigner, deviceId: trustedDevice,
          archivePin, accountPin });
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
        for (let index = 0; index < payload.entries.length; index++) {
          const item = payload.entries[index];
          const opened = await portable.openWithIndependentRoot({
            recoverySecret: secret, bundle: item.bundle,
            expectedMetadata: item.bundle.metadata,
            independentlyPinnedCiphertextRoot: from64(item.bundle.ciphertextRoot, 32) });
          if (versioned) {
            let packet;
            try {
              const row = authority.rows[index];
              if (item.bundle.metadata.object_id !== row.objectId
                || item.bundle.objectRevision !== row.revision
                || item.bundle.metadata.epoch !== row.epoch) deny();
              packet = await decodePacket(opened.data, row, item.bundle.metadata);
              recovered.push(Object.freeze({
                objectId: item.bundle.metadata.object_id,
                versionId: item.bundle.metadata.version_id,
                parentVersionId: item.bundle.metadata.parent_version_id,
                objectRevision: item.bundle.objectRevision, metadata: item.bundle.metadata,
                ciphertext: packet.ciphertext, cek: packet.cek }));
            } finally { opened.data?.fill(0); }
          } else recovered.push(Object.freeze({ objectId: item.bundle.metadata.object_id,
            objectRevision: item.bundle.objectRevision, metadata: item.bundle.metadata,
            name: opened.name, mediaType: opened.mediaType, data: opened.data }));
        }
        const result = Object.freeze({ files: Object.freeze(recovered),
          signedManifestVerified: true, allOwnerSignedRootsVerified: true,
          independentArchiveHashMatched: true, activeSignedGrantAtPinnedHeadVerified: true,
          currentSignedGrantAtPinnedHeadVerified: true,
          historicalOwnerContinuityVerified: historic,
          ...(versioned ? { completeRelativeToPinnedInventory: true,
            ownerSignedAccountRosterVerified: true,
            revisionAncestryVerified: true } : {}),
          currentOnlineRevocationVerified: false,
          independentPinProvenanceVerifiedByModule: false,
          authorizesProductionRestore: false });
        recovered = [];
        return result;
      } catch (_) { for (const item of recovered) {
        item.data?.fill(0); item.ciphertext?.fill(0); item.cek?.fill(0);
      } deny(); }
      finally { secret?.fill(0); decrypted?.fill(0); }
    }
    return Object.freeze({ createArchive, recoverArchive, verifyVersionedAuthority,
      issueHistoricalRecoveryChallenge, historicalRecoveryChallengeMessage });
  }));
