(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-normal-browser-trust-floor"),
      require("./rootark-zk1-owner-inventory-trust-head"),
      require("./rootark-zk1-owner-signed-checkpoint"),
      require("./rootark-zk1-owner-ciphertext-root-checkpoint"),
      require("./rootark-zk1-ciphertext-chunk-root"));
  } else {
    root.RootarkZk1BrowserAuthoritativeBackup = factory(root.crypto,
      root.RootarkZk1NormalBrowserTrustFloor,
      root.RootarkZk1OwnerInventoryTrustHead,
      root.RootarkZk1OwnerSignedCheckpoint,
      root.RootarkZk1OwnerCiphertextRootCheckpoint,
      root.RootarkZk1CiphertextRoot);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (crypto, floor, ownerInventory, ownerHistory, ownerRoots, ciphertextRoots) {
    "use strict";
    // Browser verifier of the *real* RFC8949/Ed25519 signed inventory snapshot,
    // owner-pinned checkpoint, ciphertext rows, and owner-signed account roster.
    // Only the pinned owner's 1..12-version snapshot is admitted.
    const te = new TextEncoder(), td = new TextDecoder("utf-8", { fatal: true });
    const historyFields = ["account_id", "compartment_id", "keyring_id"];
    const snapshotFields = ["format", "scope", "ownerRevision", "ownerDigest", "ownerEpoch",
      "inventorySequence", "inventoryRoot", "inventoryCheckpointDigest", "issuedAt", "items"];
    const ownerRosterFields = ["format", "accountId", "issuedAt", "keyringCount", "keyrings"];
    const proofStore = new WeakMap();
    function deny() { throw new Error("ZK_BROWSER_AUTHORITATIVE_BACKUP_DENIED"); }
    function exact(v, keys) {
      if (!v || typeof v !== "object" || Array.isArray(v)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(v))
        || Reflect.ownKeys(v).length !== keys.length
        || keys.some((k) => !Object.hasOwn(v, k))) deny();
      return v;
    }
    function uint(v, min = 0) {
      if (!Number.isSafeInteger(v) || v < min) deny();
      return v;
    }
    function b64(bytes) {
      let s = "";
      for (const byte of bytes) s += String.fromCharCode(byte);
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function decode64(v, min, max = min) {
      if (typeof v !== "string" || !/^[A-Za-z0-9_-]+$/.test(v)
        || v.length > Math.ceil(max * 4 / 3) + 4) deny();
      let raw;
      try { raw = atob(v.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(v.length / 4) * 4, "=")); } catch (_) { deny(); }
      const result = Uint8Array.from(raw, (c) => c.charCodeAt(0));
      if (result.length < min || result.length > max || b64(result) !== v) deny();
      return result;
    }
    function bytes(value, length) {
      if (!(value instanceof Uint8Array) || value.length !== length) deny();
      return new Uint8Array(value);
    }
    function concat(...chunks) {
      const total = chunks.reduce((n, chunk) => n + chunk.length, 0);
      if (total > 20 * 1024 * 1024) deny();
      const result = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
      return result;
    }
    async function hash(data) {
      return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
    }
    function same(a, b) {
      if (a.length !== b.length) return false;
      let result = 0;
      for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i];
      return result === 0;
    }
    // Deterministic CBOR subset used by rootark-zk-content-inventory-v1.
    // Rejects floats, tags, undefined, indefinite lengths and noncanonical input.
    function encodeCbor(v) {
      const head = (type, length) => {
        uint(length);
        const major = type << 5;
        if (length < 24) return Uint8Array.of(major | length);
        if (length <= 0xff) return Uint8Array.of(major | 24, length);
        if (length <= 0xffff) return Uint8Array.of(major | 25, length >>> 8, length & 255);
        if (length <= 0xffffffff) return Uint8Array.of(major | 26,
          (length / 0x1000000) & 255, (length >>> 16) & 255, (length >>> 8) & 255, length & 255);
        const hi = Math.floor(length / 0x100000000), lo = length >>> 0;
        return Uint8Array.of(major | 27, hi >>> 24, (hi >>> 16) & 255,
          (hi >>> 8) & 255, hi & 255, lo >>> 24, (lo >>> 16) & 255,
          (lo >>> 8) & 255, lo & 255);
      };
      if (v === null) return Uint8Array.of(0xf6);
      if (typeof v === "number") return head(0, uint(v));
      if (typeof v === "string") { const data = te.encode(v); return concat(head(3, data.length), data); }
      if (v instanceof Uint8Array) return concat(head(2, v.length), v);
      if (Array.isArray(v)) return concat(head(4, v.length), ...v.map(encodeCbor));
      if (v && typeof v === "object") {
        const encoded = Object.keys(v).map((key) => [encodeCbor(key), encodeCbor(v[key])]);
        encoded.sort((a, b) => a[0].length - b[0].length
          || (() => { for (let i = 0; i < a[0].length; i++) {
            if (a[0][i] !== b[0][i]) return a[0][i] - b[0][i];
          } return 0; })());
        return concat(head(5, encoded.length), ...encoded.flat());
      }
      deny();
    }
    function parseCbor(input) {
      if (!(input instanceof Uint8Array) || input.length > 262144) deny();
      let pos = 0;
      const take = (n) => {
        if (n < 0 || pos + n > input.length) deny();
        const result = input.slice(pos, pos + n); pos += n; return result;
      };
      const length = (info) => {
        if (info < 24) return info;
        const n = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
        if (!n) deny();
        const octets = take(n);
        let value = 0;
        for (const byte of octets) value = value * 256 + byte;
        uint(value);
        return value;
      };
      const parse = (depth) => {
        if (depth > 12) deny();
        const tag = take(1)[0], major = tag >>> 5, info = tag & 31;
        if (major === 7 && tag === 0xf6) return null;
        if (![0, 2, 3, 4, 5].includes(major)) deny();
        const n = length(info);
        if (n > 262144) deny();
        if (major === 0) return n;
        if (major === 2) return take(n);
        if (major === 3) return td.decode(take(n));
        if (major === 4) return Array.from({ length: n }, () => parse(depth + 1));
        const obj = Object.create(null);
        for (let i = 0; i < n; i++) {
          const key = parse(depth + 1);
          if (typeof key !== "string" || ["__proto__", "prototype", "constructor"].includes(key)
            || Object.hasOwn(obj, key)) deny();
          obj[key] = parse(depth + 1);
        }
        return obj;
      };
      const result = parse(0);
      if (pos !== input.length || !same(input, encodeCbor(result))) deny();
      return result;
    }
    function scopeBytes(scope) {
      exact(scope, historyFields);
      return { account_id: decode64(scope.account_id, 16),
        compartment_id: decode64(scope.compartment_id, 1, 128),
        keyring_id: decode64(scope.keyring_id, 16) };
    }
    function orderRows(items) {
      if (!Array.isArray(items) || !items.length || items.length > 12) deny();
      let previous;
      for (const row of items) {
        exact(row, ["object_id", "revision", "epoch", "ciphertext_sha256"]);
        const id = bytes(row.object_id, 16);
        bytes(row.ciphertext_sha256, 32);
        uint(row.revision, 1); uint(row.epoch, 1);
        if (previous) {
          let compare = 0;
          for (let i = 0; i < 16; i++) {
            if (id[i] !== previous.id[i]) { compare = id[i] - previous.id[i]; break; }
          }
          if (compare < 0 || (compare === 0
            ? row.revision !== previous.revision + 1 || row.epoch < previous.epoch
            : row.revision !== 1)) deny();
        } else if (row.revision !== 1) deny();
        previous = { id, revision: row.revision, epoch: row.epoch };
      }
    }
    async function verifySnapshotCbor({ wire, key, signerId, expectedScope,
      pinnedRoot, pinnedSequence }) {
      const snapshot = parseCbor(wire);
      exact(snapshot, ["type", "version", "signer_key_id", "scope",
        "sequence", "previous_root", "root", "nonce", "entries", "signature"]);
      if (snapshot.type !== "rootark-content-inventory-snapshot/v1"
        || snapshot.version !== 1 || !same(bytes(snapshot.signer_key_id, 16), signerId)
        || snapshot.sequence !== pinnedSequence || !same(bytes(snapshot.root, 32), pinnedRoot)
        || !Array.isArray(snapshot.entries)
        || snapshot.entries.length !== pinnedSequence || pinnedSequence > 12) deny();
      const actualScope = snapshot.scope;
      exact(actualScope, historyFields);
      if (historyFields.some((field) => !same(actualScope[field], expectedScope[field]))) deny();
      orderRows(snapshot.entries);
      bytes(snapshot.nonce, 32);
      if (snapshot.sequence === 0 ? snapshot.previous_root !== null
        : !(snapshot.previous_root instanceof Uint8Array)) deny();
      const body = { type: snapshot.type, version: 1, scope: actualScope,
        sequence: snapshot.sequence, previous_root: snapshot.previous_root,
        entries: snapshot.entries };
      const rootHash = await hash(concat(
        te.encode("Root.ark/zk-1/content-inventory-root/v1\0"), encodeCbor(body)));
      if (!same(rootHash, snapshot.root)) deny();
      const unsigned = { ...body, signer_key_id: signerId, root: snapshot.root,
        nonce: snapshot.nonce };
      if (!await crypto.subtle.verify("Ed25519", key, bytes(snapshot.signature, 64),
        concat(te.encode("Root.ark/zk-1/content-inventory-snapshot/v1\0"),
          encodeCbor(unsigned)))) deny();
      return snapshot.entries;
    }
    async function verifyBackupSnapshot(input) {
      try {
        const { snapshot: inputSnapshot, roster, independentRosterSha256,
          ownerPublicKey, independentOwnerSpkiSha256, pinnedCurrentHead,
          scope, ownerInventoryPortable, independentlyPinnedInventoryCheckpointDigest,
          independentlyPinnedInventorySignerSpkiSha256,
          inventorySignerPublicKey, inventorySignerKeyId,
          signedDeviceGrant, ownerHistoryCheckpoint, previousOwnerHistoryProof,
          signerKeyId, deviceId, independentlyPinnedBackupSha256,
          nowSeconds, archivalHistoryChain = null } = input;
        const ownerSpki = await crypto.subtle.exportKey("spki", ownerPublicKey);
        if (!same(await hash(ownerSpki), bytes(independentOwnerSpkiSha256, 32))) deny();
        await floor.verifyExternalAnchor({ ownerPublicKey, independentOwnerSpkiSha256,
          pinnedCurrentHead, signedDeviceGrant, ownerHistoryCheckpoint,
          previousOwnerHistoryProof });
        if (deviceId !== signedDeviceGrant.device_id) deny();
        const ownerScope = scopeBytes(scope);
        const backup = JSON.parse(JSON.stringify(inputSnapshot));
        exact(backup, [...snapshotFields, "signature"]);
        if (backup.format !== "rootark-zk1-authoritative-backup-inventory/v1"
          || historyFields.some((field) => backup.scope[field] !== scope[field])
          || backup.inventoryCheckpointDigest !== independentlyPinnedInventoryCheckpointDigest) deny();
        const previousHead = backup.ownerRevision !== pinnedCurrentHead.revision
          || backup.ownerDigest !== b64(pinnedCurrentHead.digest)
          || backup.ownerEpoch !== pinnedCurrentHead.epoch;
        if (previousHead !== (archivalHistoryChain !== null)) deny();
        if (backup.ownerRevision > pinnedCurrentHead.revision
          || backup.ownerEpoch > pinnedCurrentHead.epoch) deny();
        let archiveCheckpoint = ownerHistoryCheckpoint;
        let archivePrevious = previousOwnerHistoryProof;
        if (previousHead) {
          if (!Array.isArray(archivalHistoryChain)
            || archivalHistoryChain.length < 2 || archivalHistoryChain.length > 64) deny();
          let prior = null, matched = false;
          for (let index = 0; index < archivalHistoryChain.length; index++) {
            const checkpoint = archivalHistoryChain[index];
            if (checkpoint.sequence !== index + 1
              || checkpoint.device_id !== deviceId) deny();
            const previous = prior;
            prior = await ownerHistory.verifyOwnerCheckpoint({
              checkpoint, scope, signerPublicKey: ownerPublicKey,
              signerKeyId, previous });
            if (checkpoint.revision === backup.ownerRevision
              && checkpoint.manifest_digest === backup.ownerDigest) {
              if (matched) deny();
              matched = true;
              archiveCheckpoint = checkpoint;
              archivePrevious = previous;
            }
          }
          const current = archivalHistoryChain.at(-1);
          if (!matched || current.revision !== pinnedCurrentHead.revision
            || current.manifest_digest !== b64(pinnedCurrentHead.digest)
            || JSON.stringify(current) !== JSON.stringify(ownerHistoryCheckpoint)) deny();
        }
        const snapshotWire = te.encode(JSON.stringify(backup));
        if (!same(await hash(snapshotWire), bytes(independentlyPinnedBackupSha256, 32))) deny();
        if (!await crypto.subtle.verify("Ed25519", ownerPublicKey,
          decode64(backup.signature, 64),
          concat(te.encode("Root.ark/zk-1/authoritative-backup-inventory/v1\0"),
            te.encode(JSON.stringify(Object.fromEntries(
              snapshotFields.map((field) => [field, backup[field]]))))))) deny();
        const inventoryPortable = JSON.parse(ownerInventoryPortable);
        const signedHead = inventoryPortable.checkpoints?.at(-1);
        if (!signedHead || backup.inventoryRoot !== signedHead.inventory_root
          || backup.inventorySequence !== signedHead.inventory_sequence) deny();
        const spki = await crypto.subtle.exportKey("spki", inventorySignerPublicKey);
        if (Array.from(await hash(spki), (v) => v.toString(16).padStart(2, "0")).join("")
          !== independentlyPinnedInventorySignerSpkiSha256) deny();
        const enroll = await ownerInventory.importPortableEnrollment({
          serialized: ownerInventoryPortable,
          independentOwnerSpkiSha256: Array.from(independentOwnerSpkiSha256,
            (v) => v.toString(16).padStart(2, "0")).join(""),
          independentCheckpointDigest: independentlyPinnedInventoryCheckpointDigest,
          expectedScope: historyFields.map((field) => scope[field]),
          expectedInventorySpkiSha256: independentlyPinnedInventorySignerSpkiSha256,
          nowSeconds });
        if (enroll.ownerSignatureVerified !== true
          || enroll.independentlyPinnedDigestMatched !== true) deny();
        const tuples = await verifySnapshotCbor({
          wire: decode64(inventoryPortable.minimum_snapshot, 1, 262144),
          key: inventorySignerPublicKey, signerId: bytes(inventorySignerKeyId, 16),
          expectedScope: ownerScope, pinnedRoot: Uint8Array.from(
            backup.inventoryRoot.match(/../g), (v) => parseInt(v, 16)),
          pinnedSequence: backup.inventorySequence });
        if (signedHead.inventory_signer_key_id !== b64(inventorySignerKeyId)
          || !Array.isArray(backup.items) || backup.items.length !== tuples.length
          || tuples.length < 1 || tuples.length > 12) deny();
        for (let i = 0; i < tuples.length; i++) {
          const row = backup.items[i], tuple = tuples[i];
          exact(row, ["objectId", "revision", "epoch", "ciphertextBase64",
            "ciphertextSha256", "ciphertextRoot", "ownerRootCheckpoint"]);
          const payload = decode64(row.ciphertextBase64, 16, 4 * 1024 * 1024);
          if (row.objectId !== b64(tuple.object_id) || row.revision !== tuple.revision
            || row.epoch !== tuple.epoch || row.ciphertextSha256 !== b64(tuple.ciphertext_sha256)
            || !same(await hash(payload), tuple.ciphertext_sha256)) deny();
          const calculatedRoot = await ciphertextRoots.computeCiphertextRoot([payload]);
          if (!same(calculatedRoot, decode64(row.ciphertextRoot, 32))) deny();
          const rootProof = await ownerRoots.verifyOwnerCiphertextRootCheckpoint({
            checkpoint: row.ownerRootCheckpoint, ownerHistoryCheckpoint: archiveCheckpoint,
            previousHistoryProof: archivePrevious,
            pinnedOwner: { scope, deviceId, signerKeyId, publicKey: ownerPublicKey },
            expected: { manifestRevision: backup.ownerRevision,
              manifestDigest: decode64(backup.ownerDigest, 32), manifestEpoch: backup.ownerEpoch,
              objectId: row.objectId, objectRevision: row.revision,
              ciphertextEpoch: row.epoch, ciphertextRoot: calculatedRoot } });
          if (rootProof.trustedOwnerSignatureVerified !== true
            || rootProof.manifestCheckpointVerified !== true) deny();
        }
        const ownerRoster = JSON.parse(JSON.stringify(roster));
        exact(ownerRoster, [...ownerRosterFields, "signature"]);
        if (ownerRoster.format !== "rootark-zk1-owner-account-backup-roster/v1"
          || ownerRoster.accountId !== scope.account_id
          || !Array.isArray(ownerRoster.keyrings) || ownerRoster.keyrings.length !== 1
          || ownerRoster.keyringCount !== 1) deny();
        if (!same(await hash(te.encode(JSON.stringify(ownerRoster))),
          bytes(independentRosterSha256, 32))) deny();
        if (!await crypto.subtle.verify("Ed25519", ownerPublicKey,
          decode64(ownerRoster.signature, 64),
          concat(te.encode("Root.ark/zk-1/owner-account-backup-roster/v1\0"),
            te.encode(JSON.stringify(Object.fromEntries(
              ownerRosterFields.map((field) => [field, ownerRoster[field]]))))))) deny();
        const rosterRow = ownerRoster.keyrings[0];
        exact(rosterRow, ["scope", "snapshotSha256", "inventoryCheckpointDigest",
          "inventoryRoot", "inventorySequence"]);
        if (historyFields.some((field) => rosterRow.scope[field] !== scope[field])
          || rosterRow.snapshotSha256 !== b64(independentlyPinnedBackupSha256)
          || rosterRow.inventoryCheckpointDigest !== backup.inventoryCheckpointDigest
          || rosterRow.inventoryRoot !== backup.inventoryRoot
          || rosterRow.inventorySequence !== backup.inventorySequence) deny();
        const proof = Object.freeze({ completeRelativeToOwnerCheckpoint: true,
          globalAccountCompletenessProven: false, authorizesProductionRestore: false });
        proofStore.set(proof, Object.freeze({ scope: { ...scope },
          snapshotSha256: b64(independentlyPinnedBackupSha256),
          // Provenance of the exact independently pinned, owner-signed roster
          // is part of the private brand. A later caller must not replace it
          // with a different roster whose single snapshot row happens to match.
          rosterSha256: b64(bytes(independentRosterSha256, 32)),
          rosterWire: JSON.stringify(ownerRoster),
          ownerSpkiSha256: Array.from(independentOwnerSpkiSha256,
            (v) => v.toString(16).padStart(2, "0")).join(""),
          inventoryCheckpointDigest: backup.inventoryCheckpointDigest,
          inventoryRoot: backup.inventoryRoot, inventorySequence: backup.inventorySequence,
          rows: backup.items.map((row) => Object.freeze({ ...row })) }));
        return proof;
      } catch (_) { deny(); }
    }
    function readVerifiedBackupProof(proof) {
      const held = proofStore.get(proof);
      if (!held) deny();
      return held;
    }
    const inventoryBridge = Object.freeze({
      verifyBackupSnapshot: (raw) => verifyBackupSnapshot({
        ...raw, inputSnapshot: raw.snapshot,
        independentRosterSha256: raw.independentRosterSha256 }),
      readVerifiedBackupProof,
    });
    // The archive module expects separate inventory/roster verifiers. This
    // roster verifier consumes only the freshly branded inventory proof.
    const rosterBridge = Object.freeze({ async verifyOwnerRosterCoverage(input) {
      if (!Array.isArray(input.verifiedKeyringProofs)
        || input.verifiedKeyringProofs.length !== 1
        || !proofStore.has(input.verifiedKeyringProofs[0])) deny();
      const held = proofStore.get(input.verifiedKeyringProofs[0]);
      const rosterWire = JSON.stringify(input.roster);
      const rosterPin = bytes(input.independentlyPinnedRosterSha256, 32);
      if (input.accountId !== held.scope.account_id
        || typeof rosterWire !== "string" || rosterWire !== held.rosterWire
        || !same(await hash(te.encode(rosterWire)), rosterPin)
        || b64(rosterPin) !== held.rosterSha256
        || input.roster.keyrings?.length !== 1
        || input.roster.keyrings[0]?.snapshotSha256 !== held.snapshotSha256) deny();
      return { allOwnerRosterKeyringsVerified: true };
    } });
    return Object.freeze({ verifyBackupSnapshot, readVerifiedBackupProof,
      inventoryBridge, rosterBridge, parseCbor, encodeCbor });
  }));
