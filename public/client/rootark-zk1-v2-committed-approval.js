(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-v2-device-approval"),
      require("./rootark-zk1-v2-browser-pop"),
      require("./rootark-zk1-normal-browser-trust-floor"));
  } else {
    root.RootarkZk1V2CommittedApproval = factory(root.crypto,
      root.RootarkZk1V2DeviceApproval, root.RootarkZk1V2BrowserPop,
      root.RootarkZk1NormalBrowserTrustFloor);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (cryptoImpl, approval, pop, floor) {
    "use strict";
    const subtle = cryptoImpl.subtle;
    const encoder = new TextEncoder();
    const PREFIX = encoder.encode("Root.ark/zk-1/offline-commitment-receipt/v1\0");
    const FIELDS = ["schema", "status", "account_id", "compartment_id", "keyring_id",
      "revision", "digest", "epoch", "previous_revision", "previous_digest",
      "operation_id", "pop_challenge_id", "request_nonce", "commit_nonce",
      "sequence", "previous_receipt_sha256", "issued_at", "expires_at"];
    const keys = [...FIELDS, "signature"];
    const branded = new WeakMap();
    const scopes = ["account_id", "compartment_id", "keyring_id"];
    function deny() { throw Error("ZK_V2_COMMITTED_APPROVAL_DENIED"); }
    function exact(value, fields) {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
        || Reflect.ownKeys(value).length !== fields.length
        || fields.some((f) => !Object.hasOwn(value, f))) deny();
    }
    function b64(bytes) {
      let s = "";
      for (const value of bytes) s += String.fromCharCode(value);
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function decode(value, min, max = min) {
      if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
        || value.length > Math.ceil(max * 4 / 3) + 4) deny();
      let input;
      try { input = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
      const bytes = Uint8Array.from(input, (v) => v.charCodeAt(0));
      if (bytes.length < min || bytes.length > max || b64(bytes) !== value) deny();
      return bytes;
    }
    function raw(value, size) {
      if ((!ArrayBuffer.isView(value) && !(value instanceof ArrayBuffer))
        || value.byteLength !== size) deny();
      return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
        : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    function equal(a, b) {
      if (a.length !== b.length) return false;
      let n = 0;
      for (let i = 0; i < a.length; i++) n |= a[i] ^ b[i];
      return n === 0;
    }
    function concat(...parts) {
      const out = new Uint8Array(parts.reduce((n, v) => n + v.length, 0));
      let pos = 0;
      for (const v of parts) { out.set(v, pos); pos += v.length; }
      return out;
    }
    const sha = async (bytes) => new Uint8Array(await subtle.digest("SHA-256", bytes));
    function wire(receipt) {
      exact(receipt, keys);
      if (receipt.schema !== "rootark-zk1-offline-commitment-receipt/v1"
        || receipt.status !== "committed") deny();
      decode(receipt.account_id, 16);
      decode(receipt.compartment_id, 1, 128);
      decode(receipt.keyring_id, 16);
      for (const name of ["digest", "request_nonce", "commit_nonce"]) {
        if (receipt[name] === null && name !== "digest") continue;
        decode(receipt[name], 32);
      }
      for (const name of ["previous_digest", "previous_receipt_sha256"]) {
        if (receipt[name] !== null) decode(receipt[name], 32);
      }
      for (const name of ["operation_id", "pop_challenge_id"]) {
        if (receipt[name] !== null) decode(receipt[name], 16);
      }
      decode(receipt.signature, 64);
      for (const n of ["revision", "epoch", "sequence", "issued_at", "expires_at"]) {
        if (!Number.isSafeInteger(receipt[n]) || receipt[n] < 1) deny();
      }
      if (receipt.previous_revision !== null
        && (!Number.isSafeInteger(receipt.previous_revision)
          || receipt.previous_revision < 1)) deny();
      if (receipt.expires_at <= receipt.issued_at
        || receipt.expires_at - receipt.issued_at > 3600) deny();
      return concat(PREFIX, encoder.encode(JSON.stringify(Object.fromEntries(
        FIELDS.map((field) => [field, receipt[field]])))));
    }
    async function validSigned(receipt, witnessKey) {
      const message = wire(receipt);
      if (!await subtle.verify("Ed25519", witnessKey, decode(receipt.signature, 64), message)) deny();
      return sha(concat(message, decode(receipt.signature, 64)));
    }
    async function begin(input) {
      try {
        exact(input, ["request", "approval", "signedDeviceGrant",
          "ownerPublicKey", "independentOwnerSpkiSha256", "pinnedOwnerKeyHash",
          "pinnedCurrentHead", "devicePublicKey", "devicePrivateKey", "nowSeconds",
          "committedReceipt", "previousReceipt", "witnessPublicKey",
          "independentWitnessSpkiSha256", "independentlyPinnedPreviousReceiptSha256",
          "signedV2Manifest"]);
        const { request, signedDeviceGrant: grant, approval: a,
          committedReceipt: current, previousReceipt: previous } = input;
        const basic = await approval.verifyImportedApproval({
          request, approval: a, signedDeviceGrant: grant,
          ownerPublicKey: input.ownerPublicKey,
          independentOwnerSpkiSha256: input.independentOwnerSpkiSha256,
          pinnedOwnerKeyHash: input.pinnedOwnerKeyHash,
          pinnedCurrentHead: input.pinnedCurrentHead,
          devicePublicKey: input.devicePublicKey, devicePrivateKey: input.devicePrivateKey,
          nowSeconds: input.nowSeconds });
        if (!basic.verifiedOwnerOfflineApproval || basic.authorizesProductionIo !== false) deny();
        const witness = input.witnessPublicKey;
        if (!witness || witness.type !== "public" || witness.algorithm?.name !== "Ed25519"
          || !witness.usages.includes("verify")) deny();
        const spkiPin = raw(input.independentWitnessSpkiSha256, 32);
        const computed = await sha(new Uint8Array(await subtle.exportKey("spki", witness)));
        if (!equal(spkiPin, computed)) deny();
        const priorHash = await validSigned(previous, witness);
        if (!equal(priorHash, raw(input.independentlyPinnedPreviousReceiptSha256, 32))) deny();
        const currentHash = await validSigned(current, witness);
        // This is the exact CBOR manifest signed/committed by the existing
        // Node V2 ceremony. The browser pins its domain-separated digest, and
        // the server separately verifies the full owner-rooted V2 signature
        // chain before any protected GET. Do not call this a public V2 proof.
        const manifestBytes = decode(input.signedV2Manifest, 128, 262144);
        const manifestDigest = await sha(concat(
          encoder.encode("Root.ark/zk-1/recovery-manifest-digest/v1\0"), manifestBytes));
        if (!equal(manifestDigest, raw(input.pinnedCurrentHead.digest, 32))) deny();
        if (!equal(decode(current.previous_receipt_sha256, 32), priorHash)
          || current.sequence <= previous.sequence
          || current.previous_revision !== previous.revision
          || current.previous_digest !== previous.digest
          || current.epoch < previous.epoch) deny();
        if (!Number.isSafeInteger(input.nowSeconds)
          || current.issued_at > input.nowSeconds + 30
          || current.expires_at < input.nowSeconds) deny();
        if (current.revision !== input.pinnedCurrentHead.revision
          || current.digest !== b64(raw(input.pinnedCurrentHead.digest, 32))
          || current.epoch !== input.pinnedCurrentHead.epoch
          || current.operation_id !== a.operation_id
          || current.pop_challenge_id !== a.pop_challenge_id
          || current.request_nonce !== request.challenge
          || a.target_device_key_digest !== await pop.targetDigest(request)
          || previous.revision >= current.revision) deny();
        for (const name of scopes) {
          if (current[name] !== grant[name] || previous[name] !== grant[name]) deny();
        }
        const snapshot = JSON.stringify({
          request, approval: a, grant, current, previous,
          manifestDigest: b64(manifestDigest),
          witness: b64(new Uint8Array(await subtle.exportKey("raw", witness))),
          witnessSpki: b64(spkiPin),
          priorHash: b64(priorHash),
          owner: b64(new Uint8Array(await subtle.exportKey("raw", input.ownerPublicKey))),
          ownerSpki: b64(raw(input.independentOwnerSpkiSha256, 32)),
          head: { revision: input.pinnedCurrentHead.revision,
            digest: b64(raw(input.pinnedCurrentHead.digest, 32)),
            epoch: input.pinnedCurrentHead.epoch },
          device: b64(new Uint8Array(await subtle.exportKey("raw", input.devicePublicKey))),
        });
        const result = Object.freeze({
          committedOwnerApprovalVerified: true, signedWitnessReceiptVerified: true,
          committedV2ManifestDigestMatched: true,
          independentWitnessSpkiPinMatched: true, previousReceiptHashPinned: true,
          publicV2HistoryVerifiedByBrowser: false, externalCustodyVerified: false,
          physicalDurabilityVerified: false, authorizesProductionIo: false });
        branded.set(result, { snapshot, issuedAt: a.issued_at,
          expiresAt: Math.min(a.expires_at, current.expires_at),
          currentReceiptHash: b64(currentHash) });
        return result;
      } catch (_) { deny(); }
    }
    async function assertForRestore({ proof, original, trust, devicePublicKey }) {
      try {
        const state = branded.get(proof);
        if (!state || proof.committedOwnerApprovalVerified !== true
          || proof.signedWitnessReceiptVerified !== true || proof.authorizesProductionIo !== false
          || Math.floor(Date.now() / 1000) > state.expiresAt) deny();
        // Recheck the exact local head/grant/signer binding, independent of
        // untrusted imported JSON, immediately before the first protected GET.
        if (trust.pinnedCurrentHead.revision !== original.pinnedCurrentHead.revision
          || trust.pinnedCurrentHead.epoch !== original.pinnedCurrentHead.epoch
          || b64(raw(trust.pinnedCurrentHead.digest, 32))
            !== b64(raw(original.pinnedCurrentHead.digest, 32))
          || JSON.stringify(trust.signedDeviceGrant) !== JSON.stringify(original.signedDeviceGrant)
          || !equal(new Uint8Array(await subtle.exportKey("raw", devicePublicKey)),
            new Uint8Array(await subtle.exportKey("raw", original.devicePublicKey)))) deny();
        const again = await begin({ ...original, nowSeconds: Math.floor(Date.now() / 1000) });
        const newState = branded.get(again);
        if (newState.snapshot !== state.snapshot) deny();
        await floor.assertCurrent({
          ownerPublicKey: trust.ownerPublicKey,
          independentOwnerSpkiSha256: trust.independentOwnerSpkiSha256,
          pinnedCurrentHead: trust.pinnedCurrentHead,
          signedDeviceGrant: trust.signedDeviceGrant,
          ownerHistoryCheckpoint: trust.ownerHistoryCheckpoint,
          previousOwnerHistoryProof: trust.previousOwnerHistoryProof,
        });
        return true;
      } catch (_) { deny(); }
    }
    return Object.freeze({ verifyCommittedApproval: begin, assertForRestore });
  }));
