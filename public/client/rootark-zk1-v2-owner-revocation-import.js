(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto);
  } else root.RootarkZk1V2OwnerRevocationImport = factory(root.crypto);
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto) {
  "use strict";
  // Offline browser-side transfer verification. Does not infer CAS custody,
  // validity of CBOR V2 history, live revocation or protected I/O authority.
  const encoder = new TextEncoder();
  const OWNER = encoder.encode("Root.ark/zk-1/owner-v2-revocation-delivery/v1\0");
  const GRANT = encoder.encode("Root.ark/zk-1/browser-owner-device-grant/v1\0");
  const WITNESS = encoder.encode("Root.ark/zk-1/offline-commitment-receipt/v1\0");
  const CAS = encoder.encode("Root.ark/zk-1/offline-cas-commit-proof/v1\0");
  const WITNESS_FIELDS = ["schema", "status", "account_id", "compartment_id", "keyring_id",
    "revision", "digest", "epoch", "previous_revision", "previous_digest", "operation_id",
    "pop_challenge_id", "request_nonce", "commit_nonce", "sequence",
    "previous_receipt_sha256", "issued_at", "expires_at"];
  const CAS_FIELDS = ["schema", "status", "account_id", "compartment_id", "keyring_id",
    "revision", "epoch", "digest", "previous_revision", "previous_digest",
    "operation_id", "request_nonce", "commit_nonce", "witness_receipt_sha256",
    "cas_sequence", "witness_sequence", "issued_at", "expires_at"];
  const GRANT_FIELDS = ["schema", "account_id", "compartment_id", "keyring_id",
    "device_id", "authorization_key_id", "authorization_public_key", "manifest_revision",
    "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
  function deny() { throw Error("ZK_OWNER_REVOCATION_IMPORT_DENIED"); }
  function exact(input, fields) {
    if (!input || typeof input !== "object" || Array.isArray(input)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
      || Reflect.ownKeys(input).length !== fields.length
      || fields.some((field) => !Object.hasOwn(input, field))) deny();
    return input;
  }
  function decode(raw, length, maximum = length) {
    if (typeof raw !== "string" || !/^[A-Za-z0-9_-]+$/.test(raw)
      || raw.length > Math.ceil(maximum * 4 / 3) + 4) deny();
    let bytes;
    try { bytes = Uint8Array.from(atob(raw.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(raw.length / 4) * 4, "=")), (v) => v.charCodeAt(0)); }
    catch (_) { deny(); }
    if (bytes.length < length || bytes.length > maximum || to64(bytes) !== raw) deny();
    return bytes;
  }
  function to64(bytes) {
    return btoa(Array.from(bytes, (v) => String.fromCharCode(v)).join(""))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function same(left, right) {
    if (left.length !== right.length) return false;
    let difference = 0;
    for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
    return difference === 0;
  }
  function joined(domain, payload, signature = null) {
    const body = encoder.encode(JSON.stringify(payload));
    if (body.length > 65536) deny();
    const output = new Uint8Array(domain.length + body.length + (signature?.length || 0));
    output.set(domain);
    output.set(body, domain.length);
    if (signature) output.set(signature, domain.length + body.length);
    return output;
  }
  async function importPin(publicSpki, expectedPin) {
    const copy = publicSpki instanceof Uint8Array ? new Uint8Array(publicSpki) : null;
    if (!copy || copy.length < 40 || copy.length > 512 || !webCrypto?.subtle) deny();
    const digest = new Uint8Array(await webCrypto.subtle.digest("SHA-256", copy));
    if (!same(digest, decode(expectedPin, 32))) deny();
    return webCrypto.subtle.importKey("spki", copy, "Ed25519", false, ["verify"]);
  }
  async function signature(key, domain, unsigned, sig) {
    return webCrypto.subtle.verify("Ed25519", key, decode(sig, 64), joined(domain, unsigned));
  }
  async function verifyRevocationDelivery(input) {
    try {
      const raw = exact(input, ["delivery", "ownerSpki", "witnessSpki",
        "casSpki", "independentPins", "nowSeconds"]);
      const pin = exact(raw.independentPins, ["ownerSpkiSha256", "witnessSpkiSha256",
        "casSpkiSha256", "priorReceiptSha256", "casSequence", "revision", "digest",
        "epoch", "previousRevision", "previousDigest"]);
      const owner = await importPin(raw.ownerSpki, pin.ownerSpkiSha256);
      const witness = await importPin(raw.witnessSpki, pin.witnessSpkiSha256);
      const cas = await importPin(raw.casSpki, pin.casSpkiSha256);
      if (same(raw.witnessSpki, raw.casSpki)
        || same(raw.ownerSpki, raw.witnessSpki)
        || same(raw.ownerSpki, raw.casSpki)) deny();
      const delivered = raw.delivery;
      if (!delivered || typeof delivered !== "object" || Array.isArray(delivered)) deny();
      const { ownerSignature, ...unsigned } = delivered;
      if (typeof ownerSignature !== "string" || Object.keys(unsigned).length !== 21
        || !await signature(owner, OWNER, unsigned, ownerSignature)) deny();
      if (delivered.schema !== "rootark-zk1-v2-owner-revocation-delivery/v1"
        || delivered.revision !== pin.revision || delivered.epoch !== pin.epoch
        || delivered.digest !== pin.digest
        || delivered.previousRevision !== pin.previousRevision
        || delivered.previousDigest !== pin.previousDigest
        || delivered.ownerSpkiSha256 !== pin.ownerSpkiSha256
        || delivered.witnessSpkiSha256 !== pin.witnessSpkiSha256
        || delivered.casSpkiSha256 !== pin.casSpkiSha256
        || delivered.authoritativeOutsideApp !== true
        || delivered.physicalDurabilityProven !== false
        || delivered.historicalCiphertextAccessRevoked !== false
        || !Number.isSafeInteger(raw.nowSeconds)
        || raw.nowSeconds < 1 || !Number.isSafeInteger(pin.revision)
        || !Number.isSafeInteger(pin.previousRevision)
        || !Number.isSafeInteger(pin.epoch)
        || pin.revision !== pin.previousRevision + 1) deny();
      // The owner-signed delivery includes signed V2 manifest CBOR, but a
      // signature over the JSON envelope alone does not check its head digest.
      // CBOR canonical history verification remains a separate required gate.
      const manifest = decode(delivered.signedV2Manifest, 128, 262144);
      const prefix = encoder.encode("Root.ark/zk-1/recovery-manifest-digest/v1\0");
      const digestWire = new Uint8Array(prefix.length + manifest.length);
      digestWire.set(prefix);
      digestWire.set(manifest, prefix.length);
      const manifestDigest = to64(new Uint8Array(await webCrypto.subtle.digest(
        "SHA-256", digestWire)));
      if (manifestDigest !== pin.digest) deny();
      const scope = delivered.scope;
      if (!scope || typeof scope !== "object"
        || !["account_id", "compartment_id", "keyring_id"]
          .every((name) => typeof scope[name] === "string")) deny();
      const previous = exact(delivered.previousReceipt, [...WITNESS_FIELDS, "signature"]);
      const first = exact(delivered.committedReceipt, [...WITNESS_FIELDS, "signature"]);
      const second = exact(delivered.signedHeadProof, [...WITNESS_FIELDS, "signature"]);
      const cs = exact(delivered.signedCasProof, [...CAS_FIELDS, "signature"]);
      const unsignedOf = (value, fields) =>
        Object.fromEntries(fields.map((field) => [field, value[field]]));
      for (const receipt of [previous, first, second]) {
        if (receipt.schema !== "rootark-zk1-offline-commitment-receipt/v1"
          || receipt.status !== "committed"
          || !await signature(witness, WITNESS, unsignedOf(receipt, WITNESS_FIELDS), receipt.signature)) deny();
      }
      const receiptHash = async (receipt) => to64(new Uint8Array(await webCrypto.subtle.digest(
        "SHA-256", joined(WITNESS, unsignedOf(receipt, WITNESS_FIELDS),
          decode(receipt.signature, 64)))));
      if (await receiptHash(previous) !== pin.priorReceiptSha256
        || first.previous_receipt_sha256 !== pin.priorReceiptSha256
        || second.previous_receipt_sha256 !== await receiptHash(first)
        || first.revision !== pin.revision || second.revision !== pin.revision
        || first.epoch !== pin.epoch || second.epoch !== pin.epoch
        || first.digest !== pin.digest || second.digest !== pin.digest
        || previous.revision !== pin.previousRevision
        || previous.digest !== pin.previousDigest
        || first.previous_revision !== previous.revision
        || first.previous_digest !== previous.digest
        || second.previous_revision !== first.revision
        || second.previous_digest !== first.digest
        || first.sequence !== previous.sequence + 1 || second.sequence !== first.sequence + 1
        || first.epoch !== previous.epoch + 1
        || first.operation_id !== delivered.operationId
        || second.operation_id !== delivered.operationId
        || first.pop_challenge_id !== null || second.pop_challenge_id !== null) deny();
      for (const field of ["account_id", "compartment_id", "keyring_id"]) {
        if ([previous, first, second, cs].some((row) => row[field] !== scope[field])) deny();
      }
      if (cs.schema !== "rootark-zk1-offline-cas-commit-proof/v1"
        || cs.status !== "committed"
        || !await signature(cas, CAS, unsignedOf(cs, CAS_FIELDS), cs.signature)
        || cs.revision !== pin.revision || cs.epoch !== pin.epoch
        || cs.digest !== pin.digest || cs.previous_revision !== pin.previousRevision
        || cs.previous_digest !== pin.previousDigest
        || cs.operation_id !== delivered.operationId
        || cs.request_nonce !== first.request_nonce
        || cs.commit_nonce !== first.commit_nonce
        || cs.witness_receipt_sha256 !== await receiptHash(first)
        || cs.witness_sequence !== first.sequence || cs.cas_sequence <= pin.casSequence
        || first.request_nonce !== second.request_nonce
        || first.commit_nonce !== second.commit_nonce
        || first.request_nonce !== cs.request_nonce
        || first.commit_nonce !== cs.commit_nonce
        || first.issued_at > raw.nowSeconds || first.expires_at < raw.nowSeconds
        || second.issued_at > raw.nowSeconds || second.expires_at < raw.nowSeconds
        || cs.issued_at > raw.nowSeconds || cs.expires_at < raw.nowSeconds) deny();
      const grants = delivered.signedSurvivorGrants;
      if (!Array.isArray(grants) || grants.length < 1 || grants.length > 256) deny();
      const seen = new Set();
      for (const value of grants) {
        const grant = exact(value, [...GRANT_FIELDS, "signature"]);
        if (grant.schema !== "rootark-zk1-browser-owner-device-grant/v1"
          || seen.has(grant.device_id) || grant.device_id === delivered.revokedDeviceId
          || grant.manifest_revision !== pin.revision
          || grant.manifest_digest !== pin.digest
          || grant.current_epoch !== pin.epoch || grant.revoked_at_epoch !== null
          || !Number.isSafeInteger(grant.enrolled_epoch)
          || grant.enrolled_epoch < 1 || grant.enrolled_epoch > pin.epoch
          || !Object.keys(scope).every((field) => grant[field] === scope[field])
          || !await signature(owner, GRANT, unsignedOf(grant, GRANT_FIELDS), grant.signature)) deny();
        seen.add(grant.device_id);
      }
      return Object.freeze({ ownerSignatureVerified: true,
        independentWitnessAndCasSignaturesVerified: true,
        activeSurvivorGrantsSigned: grants.length,
        transferVerified: true, revokedDeviceId: delivered.revokedDeviceId,
        liveCasOrCustodyVerified: false,
        fullV2ManifestHistoryVerified: false,
        authorizesProtectedIo: false,
        historicalCiphertextRevocationProven: false });
    } catch (_) { deny(); }
  }
  return Object.freeze({ verifyRevocationDelivery });
}));
