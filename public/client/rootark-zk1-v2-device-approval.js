(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-normal-browser-content"),
      require("./rootark-zk1-normal-browser-trust-floor"));
  } else {
    root.RootarkZk1V2DeviceApproval = factory(root.crypto,
      root.RootarkZk1NormalBrowserContent, root.RootarkZk1NormalBrowserTrustFloor);
  }
}(typeof globalThis === "object" ? globalThis : this,
  function (cryptoImpl, normal, floor) {
    "use strict";
    const subtle = cryptoImpl.subtle;
    const DOMAIN = new TextEncoder().encode("Root.ark/zk-1/v2-offline-device-approval/v1\0");
    const SCHEMA = "rootark-zk1-offline-v2-device-approval/v1";
    const REQUEST_SCHEMA = "rootark-zk1-device-enrollment-request/v1";
    const REQUEST_KEYS = ["schema", "device_id", "authorization_key_id",
      "authorization_public_key", "hpke_key_id", "hpke_public_key", "challenge", "approval"];
    const BODY = ["schema", "request_sha256", "operation_id", "target_device_key_digest",
      "pop_challenge_id", "manifest_revision", "manifest_digest", "epoch",
      "grant_sha256", "issued_at", "expires_at"];
    const GRANT = ["schema", "account_id", "compartment_id", "keyring_id",
      "device_id", "authorization_key_id", "authorization_public_key",
      "manifest_revision", "manifest_digest", "current_epoch",
      "enrolled_epoch", "revoked_at_epoch"];
    function deny() { throw Error("ZK_V2_OWNER_APPROVAL_DENIED"); }
    function exact(value, keys) {
      if (!value || typeof value !== "object" || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
        || Reflect.ownKeys(value).length !== keys.length
        || keys.some((key) => !Object.hasOwn(value, key))) deny();
    }
    function b64(raw) {
      let result = "";
      for (const item of raw) result += String.fromCharCode(item);
      return btoa(result).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    function from64(value, length) {
      if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) deny();
      let text;
      try { text = atob(value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
      const raw = Uint8Array.from(text, (c) => c.charCodeAt(0));
      if (raw.length !== length || b64(raw) !== value) deny();
      return raw;
    }
    function bytes(value, size) {
      if ((!ArrayBuffer.isView(value) && !(value instanceof ArrayBuffer))
        || value.byteLength !== size) deny();
      return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
        : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    function equal(a, b) {
      if (a.length !== b.length) return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
      return diff === 0;
    }
    function positive(value) {
      if (!Number.isSafeInteger(value) || value < 1) deny();
      return value;
    }
    function requestWire(request) {
      exact(request, REQUEST_KEYS);
      if (request.schema !== REQUEST_SCHEMA
        || request.approval !== "OWNER_MUST_VERIFY_IDENTITY_AND_FINISH_V2_POP_AND_SIGN_CURRENT_GRANT"
        || typeof request.device_id !== "string" || request.device_id.length < 1
        || request.device_id.length > 64) deny();
      for (const name of ["authorization_key_id", "hpke_key_id"]) from64(request[name], 16);
      for (const name of ["authorization_public_key", "hpke_public_key", "challenge"])
        from64(request[name], 32);
      return new TextEncoder().encode(JSON.stringify(request));
    }
    function grantWire(grant) {
      exact(grant, [...GRANT, "signature"]);
      if (grant.schema !== "rootark-zk1-browser-owner-device-grant/v1"
        || grant.revoked_at_epoch !== null
        || positive(grant.enrolled_epoch) > positive(grant.current_epoch)) deny();
      return new TextEncoder().encode(JSON.stringify(
        Object.fromEntries(GRANT.map((key) => [key, grant[key]]))));
    }
    async function sha(bytesInput) {
      return b64(new Uint8Array(await subtle.digest("SHA-256", bytesInput)));
    }
    function signMessage(body) {
      const raw = new TextEncoder().encode(JSON.stringify(body));
      const joined = new Uint8Array(DOMAIN.length + raw.length);
      joined.set(DOMAIN); joined.set(raw, DOMAIN.length);
      return joined;
    }
    async function signOwnerApproval(input) {
      try {
        exact(input, ["request", "signedDeviceGrant", "ownerPrivateKey",
          "manifestOperationId", "targetDeviceKeyDigest", "popChallengeId",
          "issuedAt", "expiresAt"]);
        const requestBytes = requestWire(input.request);
        const grantBytes = grantWire(input.signedDeviceGrant);
        const grant = input.signedDeviceGrant;
        if (grant.device_id !== input.request.device_id
          || grant.authorization_key_id !== input.request.authorization_key_id
          || grant.authorization_public_key !== input.request.authorization_public_key
          || input.ownerPrivateKey?.type !== "private"
          || input.ownerPrivateKey?.algorithm?.name !== "Ed25519"
          || input.ownerPrivateKey?.extractable !== false) deny();
        for (const name of ["manifestOperationId", "popChallengeId"])
          from64(input[name], 16);
        from64(input.targetDeviceKeyDigest, 32);
        if (positive(input.expiresAt) <= positive(input.issuedAt)
          || input.expiresAt - input.issuedAt > 300) deny();
        const body = { schema: SCHEMA,
          request_sha256: await sha(requestBytes),
          operation_id: input.manifestOperationId,
          target_device_key_digest: input.targetDeviceKeyDigest,
          pop_challenge_id: input.popChallengeId,
          manifest_revision: grant.manifest_revision,
          manifest_digest: grant.manifest_digest, epoch: grant.current_epoch,
          grant_sha256: await sha(grantBytes),
          issued_at: input.issuedAt, expires_at: input.expiresAt };
        return Object.freeze({ ...body,
          signature: b64(new Uint8Array(await subtle.sign("Ed25519",
            input.ownerPrivateKey, signMessage(body)))) });
      } catch (_) { deny(); }
    }
    async function verifyImportedApproval(input) {
      try {
        exact(input, ["request", "approval", "signedDeviceGrant",
          "ownerPublicKey", "independentOwnerSpkiSha256", "pinnedOwnerKeyHash",
          "pinnedCurrentHead", "devicePublicKey", "devicePrivateKey", "nowSeconds"]);
        const requestBytes = requestWire(input.request);
        const grantBytes = grantWire(input.signedDeviceGrant);
        const approval = input.approval;
        exact(approval, [...BODY, "signature"]);
        if (approval.schema !== SCHEMA || input.ownerPublicKey?.type !== "public"
          || input.ownerPublicKey?.algorithm?.name !== "Ed25519"
          || input.nowSeconds < approval.issued_at - 30
          || input.nowSeconds > approval.expires_at
          || approval.expires_at <= approval.issued_at
          || approval.expires_at - approval.issued_at > 300) deny();
        from64(approval.signature, 64);
        from64(approval.operation_id, 16);
        from64(approval.target_device_key_digest, 32);
        from64(approval.pop_challenge_id, 16);
        const raw = bytes(await subtle.exportKey("raw", input.ownerPublicKey), 32);
        if (!equal(bytes(input.pinnedOwnerKeyHash, 32),
          new Uint8Array(await subtle.digest("SHA-256", raw)))) deny();
        if (!equal(bytes(input.independentOwnerSpkiSha256, 32),
          new Uint8Array(await subtle.digest("SHA-256",
            await subtle.exportKey("spki", input.ownerPublicKey))))) deny();
        const body = Object.fromEntries(BODY.map((key) => [key, approval[key]]));
        if (!await subtle.verify("Ed25519", input.ownerPublicKey,
          from64(approval.signature, 64), signMessage(body))) deny();
        const grant = input.signedDeviceGrant;
        if (approval.request_sha256 !== await sha(requestBytes)
          || approval.grant_sha256 !== await sha(grantBytes)
          || approval.manifest_revision !== input.pinnedCurrentHead?.revision
          || approval.manifest_digest !== b64(bytes(input.pinnedCurrentHead?.digest, 32))
          || approval.epoch !== input.pinnedCurrentHead.epoch
          || grant.manifest_revision !== approval.manifest_revision
          || grant.manifest_digest !== approval.manifest_digest
          || grant.current_epoch !== approval.epoch
          || grant.device_id !== input.request.device_id
          || grant.authorization_key_id !== input.request.authorization_key_id
          || grant.authorization_public_key !== input.request.authorization_public_key) deny();
        // Real device private key PoP is verified by the existing v2 runtime
        // before the owner signs. Recheck Ed25519 possession at import.
        const proven = await normal.verifyOwnerGrant({
          ownerPublicKey: input.ownerPublicKey, pinnedOwnerKeyHash: input.pinnedOwnerKeyHash,
          pinnedCurrentHead: input.pinnedCurrentHead, signedDeviceGrant: grant,
          devicePublicKey: input.devicePublicKey, devicePrivateKey: input.devicePrivateKey });
        if (!proven.ownerGrantSignatureVerified) deny();
        // No network call, no auto-provision, no trust in server JSON here.
        return Object.freeze({ verifiedOwnerOfflineApproval: true,
          requestMatchesDevice: true, currentHeadAndGrantBound: true,
          v2TransitionProvenByBrowser: false,
          independentHeadProvenanceByBrowser: false,
          requiresOfflineFloorProvisioning: true, authorizesProductionIo: false });
      } catch (_) { deny(); }
    }
    return Object.freeze({ signOwnerApproval, verifyImportedApproval });
  }));
