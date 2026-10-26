(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto);
  } else root.RootarkZk1LegacyTransitionReceipt = factory(root.crypto);
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto) {
  "use strict";
  // Signed transition of exactly ONE pinned legacy version into ONE protected
  // ciphertext object. A receipt never authorizes legacy deletion or cutover.
  const SCHEMA = "rootark-zk1-legacy-transition-receipt/v1";
  const DOMAIN = new TextEncoder().encode("Root.ark/zk-1/legacy-transition-receipt/v1\0");
  const SCOPE = ["account_id", "compartment_id", "keyring_id"];
  const PIN = ["version", "storedAs", "uploadedAt", "size", "lastModified",
    "sha256", "mediaType"];
  const TARGET = ["object_id", "version_id", "revision", "root", "ciphertext_sha256", "epoch"];
  const HEAD = ["revision", "digest", "epoch"];
  const REFS = ["links", "backups", "trash", "retention", "derived"];
  const FIELDS = ["schema", "scope", "legacy", "sourcePin", "target", "ownerHead",
    "binding", "sourceDescriptorDigest", "references", "state", "issuedAt", "nonce"];
  const WIRE = [...FIELDS, "signature"];
  function deny() { throw new Error("ZK_LEGACY_TRANSITION_UNVERIFIED"); }
  function exact(raw, fields) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(raw))
      || Reflect.ownKeys(raw).length !== fields.length) deny();
    const out = {};
    for (const field of fields) {
      const slot = Object.getOwnPropertyDescriptor(raw, field);
      if (!slot || !Object.hasOwn(slot, "value")) deny();
      out[field] = slot.value;
    }
    return out;
  }
  function b64(raw, n) {
    if (typeof raw !== "string" || !/^[A-Za-z0-9_-]+$/.test(raw)
      || raw.length > Math.ceil(n * 4 / 3) + 4) deny();
    let value;
    try { value = atob(raw.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(raw.length / 4) * 4, "=")); }
    catch (_) { deny(); }
    const bytes = Uint8Array.from(value, (ch) => ch.charCodeAt(0));
    if (bytes.length !== n || encode(bytes) !== raw) deny();
    return bytes;
  }
  function encode(raw) {
    let text = "";
    for (const byte of raw) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function integer(raw, min = 1) {
    if (!Number.isSafeInteger(raw) || raw < min) deny();
    return raw;
  }
  function payload(input) {
    const raw = exact(input, FIELDS);
    if (raw.schema !== SCHEMA || raw.state !== "verified-protected") deny();
    const scope = exact(raw.scope, SCOPE);
    for (const name of SCOPE) b64(scope[name], name === "compartment_id"
      ? b64Length(scope[name]) : 16);
    const legacy = exact(raw.legacy, ["name", "folderId"]);
    if (typeof legacy.name !== "string" || legacy.name.length < 1 || legacy.name.length > 255
      || /[\\/\u0000-\u001f\u007f]/.test(legacy.name)
      || typeof legacy.folderId !== "string" || legacy.folderId.length > 128
      || (legacy.folderId && !/^[A-Za-z0-9._-]+$/.test(legacy.folderId))) deny();
    const pin = exact(raw.sourcePin, PIN);
    if (typeof pin.storedAs !== "string" || pin.storedAs.length < 1 || pin.storedAs.length > 255
      || /[\\/\u0000-\u001f\u007f]/.test(pin.storedAs)
      || typeof pin.uploadedAt !== "string" || !Number.isFinite(Date.parse(pin.uploadedAt))
      || typeof pin.lastModified !== "string" || !Number.isFinite(Date.parse(pin.lastModified))
      || new Date(pin.lastModified).toUTCString() !== pin.lastModified
      || !Number.isSafeInteger(pin.size) || pin.size < 0 || pin.size > 2 * 1024 * 1024
      || typeof pin.mediaType !== "string" || pin.mediaType.length > 128
      || !/^[a-z0-9][a-z0-9.!#$&^_+-]*\/[a-z0-9][a-z0-9.!#$&^_+-]*$/.test(pin.mediaType)) deny();
    integer(pin.version); b64(pin.sha256, 32);
    const target = exact(raw.target, TARGET);
    b64(target.object_id, 16); b64(target.version_id, 16);
    integer(target.revision); integer(target.epoch);
    b64(target.root, 32); b64(target.ciphertext_sha256, 32);
    const head = exact(raw.ownerHead, HEAD);
    integer(head.revision); integer(head.epoch); b64(head.digest, 32);
    if (target.epoch !== head.epoch || target.revision !== 1) deny();
    b64(raw.binding, 32); b64(raw.sourceDescriptorDigest, 32);
    const references = exact(raw.references, REFS);
    // No authoritative dependency graph, deletion/retention or link proof
    // exists in the legacy client API. Refuse a caller's invented "clear".
    if (REFS.some((name) => references[name] !== "unknown")) deny();
    integer(raw.issuedAt); b64(raw.nonce, 16);
    return { ...raw, scope, legacy, sourcePin: pin, target, ownerHead: head, references };
  }
  function b64Length(value) {
    if (typeof value !== "string" || value.length > 172) deny();
    const decoded = value.replace(/-/g, "+").replace(/_/g, "/");
    let raw;
    try { raw = atob(decoded.padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
    if (raw.length < 1 || raw.length > 128) deny();
    return raw.length;
  }
  function message(body) {
    const packed = new TextEncoder().encode(JSON.stringify(payload(body)));
    if (packed.length > 4096) deny();
    const signed = new Uint8Array(DOMAIN.length + packed.length);
    signed.set(DOMAIN); signed.set(packed, DOMAIN.length);
    return signed;
  }
  function key(value, kind) {
    if (value?.type !== kind || value.algorithm?.name !== "Ed25519"
      || !value.usages?.includes(kind === "private" ? "sign" : "verify")
      || (kind === "private" && value.extractable !== false)) deny();
    return value;
  }
  function cloneReceipt(value) {
    const wire = exact(value, WIRE);
    const unsigned = payload(Object.fromEntries(FIELDS.map((name) => [name, wire[name]])));
    b64(wire.signature, 64);
    return { ...unsigned, signature: wire.signature };
  }
  async function signTransitionReceipt({ proposal, ownerSigningKey }) {
    try {
      const stable = payload(proposal);
      const sign = key(ownerSigningKey, "private");
      const signature = new Uint8Array(await webCrypto.subtle.sign("Ed25519", sign, message(stable)));
      return Object.freeze({ ...stable, signature: encode(signature) });
    } catch (_) { deny(); }
  }
  async function verifyTransitionReceipt({ receipt, expected, ownerPublicKey, nowSeconds }) {
    try {
      const actual = cloneReceipt(receipt);
      const reference = payload(expected);
      // The random nonce is owner-controlled; all other fields are derived
      // from independently checked signed GET, owner checkpoint and pins.
      const actualPayload = Object.fromEntries(FIELDS.map((field) => [field, actual[field]]));
      if (JSON.stringify(actualPayload) !== JSON.stringify(reference)
        || integer(nowSeconds) < actual.issuedAt
        || nowSeconds - actual.issuedAt > 86400
        || actual.issuedAt > nowSeconds) deny();
      if (!await webCrypto.subtle.verify("Ed25519", key(ownerPublicKey, "public"),
        b64(actual.signature, 64), message(actualPayload))) deny();
      return Object.freeze({ receipt: Object.freeze(actual), ownerSignatureVerified: true,
        state: "verified-protected", canDeleteLegacy: false, authorizesCutover: false,
        wholeCorpusVerified: false });
    } catch (_) { deny(); }
  }
  function createProposal({ scope, legacy, sourcePin, target, ownerHead, binding,
    sourceDescriptorDigest, issuedAt, nonce }) {
    return payload({ schema: SCHEMA, scope, legacy, sourcePin, target, ownerHead,
      binding, sourceDescriptorDigest, references: {
        links: "unknown", backups: "unknown", trash: "unknown", retention: "unknown", derived: "unknown",
      }, state: "verified-protected", issuedAt, nonce });
  }
  return Object.freeze({ createProposal, signTransitionReceipt,
    verifyTransitionReceipt, cloneReceipt });
}));
