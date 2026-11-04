(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto);
  } else {
    root.RootarkZk1OwnerSignedCheckpoint = factory(root.crypto);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto) {
  "use strict";

  // Opt-in OWNER-DEVICE checkpoint. It does not store a checkpoint, independently
  // verify the origin/freshness of a claimed CAS/witness head or authorize I/O.
  // The trusted owner must retain an already-verified checkpoint off-server:
  // rolling back ALL client copies can still defeat this local anti-rollback.
  const encoder = new TextEncoder();
  const SIGN_DOMAIN = encoder.encode("Root.ark/zk-1/owner-history-checkpoint/v1\0");
  const HASH_DOMAIN = encoder.encode("Root.ark/zk-1/owner-history-checkpoint-hash/v1\0");
  const SCHEMA = "rootark-zk1-owner-history-checkpoint/v1";
  const SCOPE = ["account_id", "compartment_id", "keyring_id"];
  const BODY = ["schema", ...SCOPE, "device_id", "signer_key_id",
    "revision", "manifest_digest", "sequence", "previous_checkpoint_digest", "issued_at"];
  const WIRE = [...BODY, "signature"];
  const privateProofs = new WeakMap();

  function deny() { throw new Error("ZK_OWNER_CHECKPOINT_UNVERIFIED"); }
  function exact(value, fields) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== fields.length
      || fields.some((field) => !Object.hasOwn(value, field))) deny();
  }
  function uint(value, min = 0) {
    if (!Number.isSafeInteger(value) || value < min) deny();
    return value;
  }
  function copy(value, min, max = min) {
    if (!ArrayBuffer.isView(value) && !(value instanceof ArrayBuffer)) deny();
    const n = value.byteLength;
    if (!Number.isSafeInteger(n) || n < min || n > max) deny();
    const result = value instanceof ArrayBuffer ? new Uint8Array(value.slice(0))
      : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + n));
    if (result.byteLength !== n) deny();
    return result;
  }
  function base64(bytes) {
    let text = "";
    for (const value of bytes) text += String.fromCharCode(value);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(raw, min, max = min) {
    if (typeof raw !== "string" || !/^[A-Za-z0-9_-]+$/.test(raw)
      || raw.length > Math.ceil(max * 4 / 3) + 4) deny();
    let decoded;
    try { decoded = atob(raw.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(raw.length / 4) * 4, "=")); }
    catch (_) { deny(); }
    const output = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
    if (output.length < min || output.length > max || base64(output) !== raw) deny();
    return output;
  }
  function identity(scope) {
    exact(scope, SCOPE);
    return {
      account_id: from64(scope.account_id, 16),
      compartment_id: from64(scope.compartment_id, 1, 128),
      keyring_id: from64(scope.keyring_id, 16),
    };
  }
  function same(a, b) {
    if (a.length !== b.length) return false;
    let different = 0;
    for (let i = 0; i < a.length; ++i) different |= a[i] ^ b[i];
    return different === 0;
  }
  function join(parts, limit = 4096) {
    const size = parts.reduce((acc, part) => acc + part.byteLength, 0);
    if (size > limit) deny();
    const result = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.length; }
    return result;
  }
  function head(major, value) {
    const n = BigInt(uint(value));
    const prefix = major << 5;
    if (n < 24n) return Uint8Array.of(prefix + Number(n));
    if (n <= 255n) return Uint8Array.of(prefix + 24, Number(n));
    if (n <= 65535n) return Uint8Array.of(prefix + 25, Number(n >> 8n), Number(n & 255n));
    if (n <= 0xffffffffn) return Uint8Array.of(prefix + 26, ...Array.from({ length: 4 },
      (_, index) => Number((n >> BigInt(24 - index * 8)) & 255n)));
    return Uint8Array.of(prefix + 27, ...Array.from({ length: 8 },
      (_, index) => Number((n >> BigInt(56 - index * 8)) & 255n)));
  }
  function encode(value) {
    if (value === null) return Uint8Array.of(0xf6);
    if (Number.isSafeInteger(value) && value >= 0) return head(0, value);
    if (typeof value === "string") {
      const encoded = encoder.encode(value);
      return join([head(3, encoded.length), encoded]);
    }
    if (value instanceof Uint8Array) return join([head(2, value.length), value]);
    deny();
  }
  function canonical(body) {
    const entries = Object.entries(body).map(([name, value]) =>
      ({ key: encode(name), content: encode(value) }));
    // Canonical RFC8949 map key order for our bounded text-only keyset.
    entries.sort((left, right) => left.key.length - right.key.length
      || (() => {
        for (let i = 0; i < left.key.length; ++i) {
          if (left.key[i] !== right.key[i]) return left.key[i] - right.key[i];
        }
        return 0;
      })());
    return join([head(5, entries.length),
      ...entries.flatMap((entry) => [entry.key, entry.content])]);
  }
  function validKey(key, role) {
    if (!key || key.type !== role || key.algorithm?.name !== "Ed25519"
      || !key.usages?.includes(role === "private" ? "sign" : "verify")
      || (role === "private" && key.extractable !== false)) deny();
    return key;
  }
  function deviceId(value) {
    if (typeof value !== "string" || value.length < 1 || value.length > 64
      || /[\u0000-\u001f\u007f]/.test(value)) deny();
    return value;
  }
  function parseWire(wire) {
    exact(wire, WIRE);
    if (wire.schema !== SCHEMA) deny();
    const body = {
      schema: wire.schema,
      ...identity({ account_id: wire.account_id,
        compartment_id: wire.compartment_id, keyring_id: wire.keyring_id }),
      device_id: deviceId(wire.device_id),
      signer_key_id: from64(wire.signer_key_id, 16),
      revision: uint(wire.revision, 1),
      manifest_digest: from64(wire.manifest_digest, 32),
      sequence: uint(wire.sequence, 1),
      previous_checkpoint_digest: wire.previous_checkpoint_digest === null
        ? null : from64(wire.previous_checkpoint_digest, 32),
      issued_at: uint(wire.issued_at),
    };
    return { body, signature: from64(wire.signature, 64) };
  }
  function ancestor(previous) {
    if (previous === null) return null;
    const record = previous && privateProofs.get(previous);
    if (!record) deny();
    return record;
  }
  function continuity(body, previous) {
    if (!previous) {
      if (body.sequence !== 1 || body.previous_checkpoint_digest !== null) deny();
      return;
    }
    if (body.sequence !== previous.sequence + 1
      || !same(body.previous_checkpoint_digest || new Uint8Array(0), previous.digest)
      || body.device_id !== previous.deviceId
      || !same(body.signer_key_id, previous.signerKeyId)
      || !SCOPE.every((field) => same(body[field], previous.scope[field]))
      || body.revision < previous.revision
      || (body.revision === previous.revision
        && !same(body.manifest_digest, previous.manifestDigest))
      || body.issued_at < previous.issuedAt) deny();
  }
  async function recordDigest(message, signature) {
    return new Uint8Array(await webCrypto.subtle.digest("SHA-256",
      join([HASH_DOMAIN, message, signature])));
  }
  function toWire(body, signature) {
    return Object.freeze({
      schema: body.schema, account_id: base64(body.account_id),
      compartment_id: base64(body.compartment_id),
      keyring_id: base64(body.keyring_id), device_id: body.device_id,
      signer_key_id: base64(body.signer_key_id),
      revision: body.revision, manifest_digest: base64(body.manifest_digest),
      sequence: body.sequence,
      previous_checkpoint_digest: body.previous_checkpoint_digest === null
        ? null : base64(body.previous_checkpoint_digest),
      issued_at: body.issued_at, signature: base64(signature),
    });
  }
  async function signOwnerCheckpoint(input) {
    try {
      exact(input, ["scope", "signerKey", "signerPublicKey",
        "signerKeyId", "deviceId", "revision", "manifestDigest", "issuedAt", "previous"]);
      if (!webCrypto?.subtle?.sign || !webCrypto.subtle.verify) deny();
      const privateKey = validKey(input.signerKey, "private");
      const publicKey = validKey(input.signerPublicKey, "public");
      const prior = ancestor(input.previous);
      const body = { schema: SCHEMA, ...identity(input.scope),
        device_id: deviceId(input.deviceId), signer_key_id: copy(input.signerKeyId, 16),
        revision: uint(input.revision, 1), manifest_digest: copy(input.manifestDigest, 32),
        sequence: prior ? prior.sequence + 1 : 1,
        previous_checkpoint_digest: prior ? new Uint8Array(prior.digest) : null,
        issued_at: uint(input.issuedAt) };
      if (!Number.isSafeInteger(body.sequence)) deny();
      continuity(body, prior);
      // A mutable caller-supplied keyId is NOT a cryptographic public-key
      // identity. Preserve the predecessor signed message in the private
      // verified-proof brand, and require the CURRENT verifying key to verify
      // that exact predecessor signature before signing the successor.
      // This tolerates reimport of the SAME nonextractable Ed25519 public key.
      if (prior && !await webCrypto.subtle.verify("Ed25519", publicKey,
        prior.signature, prior.signedMessage)) deny();
      const message = join([SIGN_DOMAIN, canonical(body)]);
      const signature = new Uint8Array(await webCrypto.subtle.sign("Ed25519", privateKey, message));
      if (signature.length !== 64
        || !await webCrypto.subtle.verify("Ed25519", publicKey, signature, message)) deny();
      return toWire(body, signature);
    } catch (_) { deny(); }
  }
  async function verifyOwnerCheckpoint(input) {
    try {
      exact(input, ["checkpoint", "scope", "signerPublicKey", "signerKeyId", "previous"]);
      if (!webCrypto?.subtle?.verify || !webCrypto.subtle.digest) deny();
      const publicKey = validKey(input.signerPublicKey, "public");
      const pinnedScope = identity(input.scope);
      const pinnedKeyId = copy(input.signerKeyId, 16);
      const prior = ancestor(input.previous);
      const { body, signature } = parseWire(input.checkpoint);
      if (!same(body.signer_key_id, pinnedKeyId)
        || !SCOPE.every((field) => same(body[field], pinnedScope[field]))) deny();
      continuity(body, prior);
      if (prior && !await webCrypto.subtle.verify("Ed25519", publicKey,
        prior.signature, prior.signedMessage)) deny();
      const message = join([SIGN_DOMAIN, canonical(body)]);
      if (!await webCrypto.subtle.verify("Ed25519", publicKey, signature, message)) deny();
      const digest = await recordDigest(message, signature);
      const result = Object.freeze({
        revision: body.revision, sequence: body.sequence,
        checkpointDigest: base64(digest),
        manifestDigest: base64(body.manifest_digest),
        signedCheckpointVerified: true, authorizesProtectedIo: false,
        authorizesRecovery: false,
      });
      privateProofs.set(result, {
        revision: body.revision, sequence: body.sequence,
        digest: new Uint8Array(digest), manifestDigest: new Uint8Array(body.manifest_digest),
        scope: Object.fromEntries(SCOPE.map((field) =>
          [field, new Uint8Array(body[field])])),
        signerKeyId: new Uint8Array(body.signer_key_id),
        deviceId: body.device_id, issuedAt: body.issued_at,
        signedMessage: new Uint8Array(message), signature: new Uint8Array(signature),
      });
      return result;
    } catch (_) { deny(); }
  }
  async function checkCandidateHeadAgainstCheckpoint(input) {
    try {
      exact(input, ["verifiedCheckpoint", "headRevision", "headDigest"]);
      const trusted = ancestor(input.verifiedCheckpoint);
      const revision = uint(input.headRevision, 1);
      const digest = copy(input.headDigest, 32);
      if (revision < trusted.revision
        || (revision === trusted.revision && !same(digest, trusted.manifestDigest))) deny();
      return Object.freeze({ monotonicOnly: true, freshWitnessVerified: false,
        authorizesRecovery: false, authorizesProtectedIo: false });
    } catch (_) { deny(); }
  }
  return Object.freeze({ signOwnerCheckpoint, verifyOwnerCheckpoint,
    checkCandidateHeadAgainstCheckpoint });
}));
