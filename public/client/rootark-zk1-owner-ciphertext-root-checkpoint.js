(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-owner-signed-checkpoint"));
  } else {
    root.RootarkZk1OwnerCiphertextRootCheckpoint = factory(root.crypto,
      root.RootarkZk1OwnerSignedCheckpoint);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto, ownerHistory) {
  "use strict";

  // Opt-in owner-signed ciphertext provenance. A separately provisioned owner
  // Ed25519 public key and independently trusted current manifest are required.
  // This does not prove live revocation state, authorize protected I/O/recovery,
  // or allow server-supplied roots to become trust anchors.
  const encoder = new TextEncoder();
  const DOMAIN = encoder.encode("Root.ark/zk-1/owner-ciphertext-root-checkpoint/v1\0");
  const SCHEMA = "rootark-zk1-owner-ciphertext-root-checkpoint/v1";
  const SCOPE = ["account_id", "compartment_id", "keyring_id"];
  const FIELDS = ["schema", ...SCOPE, "device_id", "signer_key_id", "manifest_revision",
    "manifest_digest", "manifest_epoch", "object_id", "object_revision",
    "ciphertext_epoch", "ciphertext_root", "issued_at"];
  const WIRE = [...FIELDS, "signature"];
  const proofs = new WeakMap();
  function fail() { throw new Error("ZK_OWNER_CIPHERTEXT_ROOT_UNVERIFIED"); }
  function exact(value, fields) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== fields.length
      || fields.some((field) => !Object.hasOwn(value, field))) fail();
  }
  function uint(value, min = 0) {
    if (!Number.isSafeInteger(value) || value < min) fail();
    return value;
  }
  function bytes(value, min, max = min) {
    if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)) fail();
    const size = value.byteLength;
    if (!Number.isSafeInteger(size) || size < min || size > max) fail();
    return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
      : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + size));
  }
  function to64(value) {
    let binary = "";
    for (const byte of value) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(raw, min, max = min) {
    if (typeof raw !== "string" || !/^[A-Za-z0-9_-]+$/.test(raw)
      || raw.length > Math.ceil(max * 4 / 3) + 4) fail();
    let decoded;
    try { decoded = atob(raw.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(raw.length / 4) * 4, "=")); } catch (_) { fail(); }
    const result = Uint8Array.from(decoded, (x) => x.charCodeAt(0));
    if (result.length < min || result.length > max || to64(result) !== raw) fail();
    return result;
  }
  function scope(value) {
    exact(value, SCOPE);
    return { account_id: from64(value.account_id, 16),
      compartment_id: from64(value.compartment_id, 1, 128),
      keyring_id: from64(value.keyring_id, 16) };
  }
  function device(value) {
    if (typeof value !== "string" || value.length < 1 || value.length > 64
      || /[\u0000-\u001f\u007f]/.test(value)) fail();
    return value;
  }
  function object(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(value)) fail();
    from64(value, 16);
    return value;
  }
  function same(a, b) {
    if (a.length !== b.length) return false;
    let difference = 0;
    for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
    return difference === 0;
  }
  function concat(parts, max = 4096) {
    const size = parts.reduce((sum, item) => sum + item.byteLength, 0);
    if (size > max) fail();
    const joined = new Uint8Array(size);
    let off = 0;
    for (const item of parts) { joined.set(item, off); off += item.byteLength; }
    return joined;
  }
  function header(major, value) {
    const n = BigInt(uint(value));
    const start = major << 5;
    if (n < 24n) return Uint8Array.of(start + Number(n));
    if (n <= 255n) return Uint8Array.of(start + 24, Number(n));
    if (n <= 65535n) return Uint8Array.of(start + 25,
      Number(n >> 8n), Number(n & 255n));
    if (n <= 0xffffffffn) return Uint8Array.of(start + 26,
      ...Array.from({ length: 4 }, (_, i) => Number((n >> BigInt(24 - i * 8)) & 255n)));
    return Uint8Array.of(start + 27,
      ...Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(56 - i * 8)) & 255n)));
  }
  function encode(value) {
    if (typeof value === "string") {
      const utf8 = encoder.encode(value);
      return concat([header(3, utf8.length), utf8]);
    }
    if (Number.isSafeInteger(value) && value >= 0) return header(0, value);
    if (value instanceof Uint8Array) return concat([header(2, value.length), value]);
    fail();
  }
  function signedMessage(value) {
    const entries = Object.entries(value).map(([key, val]) =>
      ({ key: encode(key), val: encode(val) }));
    entries.sort((a, b) => a.key.length - b.key.length
      || (() => { for (let i = 0; i < a.key.length; i++) {
        if (a.key[i] !== b.key[i]) return a.key[i] - b.key[i];
      } return 0; })());
    return concat([DOMAIN, header(5, entries.length),
      ...entries.flatMap((item) => [item.key, item.val])]);
  }
  function normalize(input) {
    exact(input, FIELDS);
    if (input.schema !== SCHEMA) fail();
    const sc = scope({ account_id: input.account_id,
      compartment_id: input.compartment_id, keyring_id: input.keyring_id });
    const manifestEpoch = uint(input.manifest_epoch, 1);
    const ciphertextEpoch = uint(input.ciphertext_epoch, 1);
    if (ciphertextEpoch > manifestEpoch) fail();
    return { schema: SCHEMA, ...sc, device_id: device(input.device_id),
      signer_key_id: from64(input.signer_key_id, 16),
      manifest_revision: uint(input.manifest_revision, 1),
      manifest_digest: from64(input.manifest_digest, 32),
      manifest_epoch: manifestEpoch, object_id: object(input.object_id),
      object_revision: uint(input.object_revision, 1),
      ciphertext_epoch: ciphertextEpoch,
      ciphertext_root: from64(input.ciphertext_root, 32),
      issued_at: uint(input.issued_at, 1) };
  }
  function wire(body, signature) {
    return Object.freeze({ schema: SCHEMA,
      ...Object.fromEntries(SCOPE.map((key) => [key, to64(body[key])])),
      device_id: body.device_id, signer_key_id: to64(body.signer_key_id),
      manifest_revision: body.manifest_revision, manifest_digest: to64(body.manifest_digest),
      manifest_epoch: body.manifest_epoch, object_id: body.object_id,
      object_revision: body.object_revision, ciphertext_epoch: body.ciphertext_epoch,
      ciphertext_root: to64(body.ciphertext_root), issued_at: body.issued_at,
      signature: to64(signature) });
  }
  function key(value, kind) {
    if (value?.type !== kind || value.algorithm?.name !== "Ed25519"
      || !value.usages?.includes(kind === "private" ? "sign" : "verify")
      || (kind === "private" && value.extractable !== false)) fail();
    return value;
  }
  async function signOwnerCiphertextRootCheckpoint(input) {
    try {
      exact(input, ["scope", "signerKey", "signerKeyId", "deviceId", "manifestRevision",
        "manifestDigest", "manifestEpoch", "objectId", "objectRevision",
        "ciphertextEpoch", "ciphertextRoot", "issuedAt"]);
      if (!webCrypto?.subtle?.sign) fail();
      const signer = key(input.signerKey, "private");
      const body = normalize({ schema: SCHEMA, ...input.scope,
        device_id: input.deviceId, signer_key_id: to64(bytes(input.signerKeyId, 16)),
        manifest_revision: input.manifestRevision,
        manifest_digest: to64(bytes(input.manifestDigest, 32)),
        manifest_epoch: input.manifestEpoch, object_id: input.objectId,
        object_revision: input.objectRevision, ciphertext_epoch: input.ciphertextEpoch,
        ciphertext_root: to64(bytes(input.ciphertextRoot, 32)), issued_at: input.issuedAt });
      const signature = new Uint8Array(await webCrypto.subtle.sign(
        "Ed25519", signer, signedMessage(body)));
      if (signature.length !== 64) fail();
      return wire(body, signature);
    } catch (_) { fail(); }
  }
  async function verifyOwnerCiphertextRootCheckpoint(input) {
    try {
      exact(input, ["checkpoint", "ownerHistoryCheckpoint", "previousHistoryProof",
        "pinnedOwner", "expected"]);
      const pin = input.pinnedOwner;
      exact(pin, ["scope", "deviceId", "signerKeyId", "publicKey"]);
      const trustedScope = scope(pin.scope);
      const trustedKeyId = bytes(pin.signerKeyId, 16);
      const trustedDevice = device(pin.deviceId);
      const publicKey = key(pin.publicKey, "public");
      const wanted = input.expected;
      exact(wanted, ["manifestRevision", "manifestDigest", "manifestEpoch",
        "objectId", "objectRevision", "ciphertextEpoch", "ciphertextRoot"]);
      const want = normalize({ schema: SCHEMA, ...pin.scope,
        device_id: trustedDevice, signer_key_id: to64(trustedKeyId),
        manifest_revision: wanted.manifestRevision,
        manifest_digest: to64(bytes(wanted.manifestDigest, 32)),
        manifest_epoch: wanted.manifestEpoch, object_id: wanted.objectId,
        object_revision: wanted.objectRevision, ciphertext_epoch: wanted.ciphertextEpoch,
        ciphertext_root: to64(bytes(wanted.ciphertextRoot, 32)), issued_at: 1 });
      const historyDevice = input.ownerHistoryCheckpoint?.device_id;
      const record = input.checkpoint;
      exact(record, WIRE);
      const sig = from64(record.signature, 64);
      const body = normalize(Object.fromEntries(FIELDS.map((name) => [name, record[name]])));
      for (const name of FIELDS) {
        if (name === "issued_at" || name === "schema") continue;
        if (body[name] instanceof Uint8Array ? !same(body[name], want[name])
          : body[name] !== want[name]) fail();
      }
      if (!SCOPE.every((name) => same(body[name], trustedScope[name]))) fail();
      const proof = await ownerHistory.verifyOwnerCheckpoint({
        checkpoint: input.ownerHistoryCheckpoint, scope: pin.scope,
        signerPublicKey: publicKey, signerKeyId: trustedKeyId,
        previous: input.previousHistoryProof,
      });
      if (historyDevice !== trustedDevice
        || proof.revision !== body.manifest_revision
        || proof.manifestDigest !== to64(body.manifest_digest)) fail();
      if (!await webCrypto.subtle.verify("Ed25519", publicKey, sig, signedMessage(body))) fail();
      const verified = Object.freeze({
        trustedOwnerSignatureVerified: true, manifestCheckpointVerified: true,
        liveDeviceRevocationVerified: false, authorizesRecovery: false,
        authorizesRestore: false, authorizesProtectedIo: false });
      proofs.set(verified, { ...body, root: new Uint8Array(body.ciphertext_root) });
      return verified;
    } catch (_) { fail(); }
  }
  function assertOwnerCiphertextRootProof({ proof, scope: expectedScope, deviceId,
    manifestRevision, manifestDigest, manifestEpoch, objectId, objectRevision,
    ciphertextEpoch, ciphertextRoot }) {
    try {
      const checked = proofs.get(proof);
      if (!checked || !SCOPE.every((name) => same(checked[name], scope(expectedScope)[name]))
        || checked.device_id !== deviceId
        || checked.manifest_revision !== uint(manifestRevision, 1)
        || !same(checked.manifest_digest, bytes(manifestDigest, 32))
        || checked.manifest_epoch !== uint(manifestEpoch, 1)
        || checked.object_id !== object(objectId)
        || checked.object_revision !== uint(objectRevision, 1)
        || checked.ciphertext_epoch !== uint(ciphertextEpoch, 1)
        || !same(checked.root, bytes(ciphertextRoot, 32))) fail();
      return true;
    } catch (_) { fail(); }
  }
  return Object.freeze({ signOwnerCiphertextRootCheckpoint,
    verifyOwnerCiphertextRootCheckpoint, assertOwnerCiphertextRootProof });
}));
