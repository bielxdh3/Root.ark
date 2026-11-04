(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto);
  } else {
    root.RootarkZk1OwnerLegacyBatchSelection = factory(root.crypto);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto) {
  "use strict";
  // Owner-held, optional authorization of exactly the selected historical
  // legacy revisions. Never a full-corpus inventory or migration cutover.
  const SCHEMA = "rootark-zk1-owner-legacy-batch-selection/v1";
  const DOMAIN = new TextEncoder().encode("Root.ark/zk-1/owner-legacy-batch-selection/v1\0");
  const SCOPE = ["account_id", "compartment_id", "keyring_id"];
  const PIN = ["version", "storedAs", "uploadedAt", "size", "lastModified",
    "sha256", "mediaType"];
  const HEAD = ["revision", "digest", "epoch"];
  const COVERAGE = ["versions", "backups", "trash", "links", "retention",
    "derived", "provider", "archive"];
  const FIELDS = ["schema", "scope", "ownerSpkiSha256", "ownerHead", "migrationSecretSha256",
    "entries", "coverage", "issuedAt", "expiresAt", "nonce"];
  const WIRE = [...FIELDS, "signature"];
  const LIMIT = 12;
  function deny() { throw new Error("ZK_LEGACY_SELECTION_UNVERIFIED"); }
  function exact(raw, fields) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(raw))
      || Reflect.ownKeys(raw).length !== fields.length) deny();
    const copy = {};
    for (const name of fields) {
      const property = Object.getOwnPropertyDescriptor(raw, name);
      if (!property || !Object.hasOwn(property, "value")) deny();
      copy[name] = property.value;
    }
    return copy;
  }
  function encode(raw) {
    let value = "";
    for (const item of raw) value += String.fromCharCode(item);
    return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function decoded(value, length) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
      || value.length > Math.ceil(length * 4 / 3) + 4) deny();
    let raw;
    try { raw = Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=")), (v) => v.charCodeAt(0)); }
    catch (_) { deny(); }
    if (raw.length !== length || encode(raw) !== value) deny();
    return raw;
  }
  function raw32(value) {
    if (!(value instanceof Uint8Array || value instanceof ArrayBuffer)
      || value.byteLength !== 32) deny();
    return new Uint8Array(value instanceof ArrayBuffer ? value.slice(0) : value);
  }
  function number(value, minimum) {
    if (!Number.isSafeInteger(value) || value < minimum) deny();
    return value;
  }
  function entryList(entries) {
    if (!Array.isArray(entries) || entries.length < 1 || entries.length > LIMIT
      || Reflect.ownKeys(entries).length !== entries.length + 1) deny();
    const seen = new Set();
    return entries.map((item) => {
      const source = exact(item, ["legacy", "sourcePin"]);
      const legacy = exact(source.legacy, ["name", "folderId"]);
      const pin = exact(source.sourcePin, PIN);
      if (typeof legacy.name !== "string" || legacy.name.length < 1
        || legacy.name.length > 255 || legacy.name === "." || legacy.name === ".."
        || /[\\/\u0000-\u001f\u007f]/.test(legacy.name)
        || (legacy.folderId !== "" && (typeof legacy.folderId !== "string"
          || !/^[A-Za-z0-9._-]{1,128}$/.test(legacy.folderId)
          || legacy.folderId === "." || legacy.folderId === ".."))
        || typeof pin.storedAs !== "string" || pin.storedAs.length < 1
        || pin.storedAs.length > 255 || pin.storedAs === "." || pin.storedAs === ".."
        || /[\\/\u0000-\u001f\u007f]/.test(pin.storedAs)
        || typeof pin.uploadedAt !== "string" || !Number.isFinite(Date.parse(pin.uploadedAt))
        || typeof pin.lastModified !== "string" || !Number.isFinite(Date.parse(pin.lastModified))
        || new Date(pin.lastModified).toUTCString() !== pin.lastModified
        || number(pin.version, 1) < 1 || number(pin.size, 0) > 2 * 1024 * 1024
        || typeof pin.mediaType !== "string" || pin.mediaType.length > 128
        || !/^[a-z0-9][a-z0-9.!#$&^_+-]*\/[a-z0-9][a-z0-9.!#$&^_+-]*$/.test(pin.mediaType)) deny();
      decoded(pin.sha256, 32);
      const identity = JSON.stringify([legacy.folderId, legacy.name, pin.version]);
      if (seen.has(identity)) deny();
      seen.add(identity);
      return { legacy, sourcePin: pin };
    });
  }
  function coverage(value) {
    const raw = exact(value, COVERAGE);
    if (raw.versions !== "selected-only"
      || COVERAGE.slice(1).some((name) => raw[name] !== "unknown")) deny();
    return raw;
  }
  function header(trust) {
    const scope = exact(Object.fromEntries(SCOPE.map((name) =>
      [name, trust?.signedDeviceGrant?.[name]])), SCOPE);
    decoded(scope.account_id, 16);
    decoded(scope.keyring_id, 16);
    if (typeof scope.compartment_id !== "string"
      || scope.compartment_id.length > 172) deny();
    const compartment = Uint8Array.from(atob(scope.compartment_id.replace(/-/g, "+")
      .replace(/_/g, "/").padEnd(Math.ceil(scope.compartment_id.length / 4) * 4, "=")),
    (v) => v.charCodeAt(0));
    if (compartment.length < 1 || compartment.length > 128
      || encode(compartment) !== scope.compartment_id) deny();
    const ownerSpkiSha256 = encode(raw32(trust?.independentOwnerSpkiSha256));
    const rawHead = trust?.pinnedCurrentHead;
    const ownerHead = { revision: number(rawHead?.revision, 1),
      digest: encode(raw32(rawHead?.digest)), epoch: number(rawHead?.epoch, 1) };
    return { scope, ownerSpkiSha256, ownerHead };
  }
  function validated(wire) {
    const raw = exact(wire, WIRE);
    if (raw.schema !== SCHEMA) deny();
    const scope = exact(raw.scope, SCOPE);
    const ownerHead = exact(raw.ownerHead, HEAD);
    decoded(scope.account_id, 16); decoded(scope.keyring_id, 16);
    if (typeof scope.compartment_id !== "string" || scope.compartment_id.length > 172) deny();
    const compartment = Uint8Array.from(atob(scope.compartment_id.replace(/-/g, "+")
      .replace(/_/g, "/").padEnd(Math.ceil(scope.compartment_id.length / 4) * 4, "=")),
    (v) => v.charCodeAt(0));
    if (compartment.length < 1 || compartment.length > 128
      || encode(compartment) !== scope.compartment_id) deny();
    decoded(raw.ownerSpkiSha256, 32);
    decoded(raw.migrationSecretSha256, 32);
    number(ownerHead.revision, 1); decoded(ownerHead.digest, 32);
    number(ownerHead.epoch, 1);
    const entries = entryList(raw.entries);
    const limits = coverage(raw.coverage);
    number(raw.issuedAt, 1); number(raw.expiresAt, raw.issuedAt);
    if (raw.expiresAt - raw.issuedAt > 86400) deny();
    decoded(raw.nonce, 16); decoded(raw.signature, 64);
    return { ...raw, scope, ownerHead, entries, coverage: limits };
  }
  function bytes(fields) {
    const payload = new TextEncoder().encode(JSON.stringify(fields));
    if (payload.byteLength > 32768) deny();
    const out = new Uint8Array(DOMAIN.length + payload.length);
    out.set(DOMAIN); out.set(payload, DOMAIN.length);
    return out;
  }
  function key(raw, role) {
    if (raw?.type !== role || raw.algorithm?.name !== "Ed25519"
      || !raw.usages?.includes(role === "private" ? "sign" : "verify")
      || (role === "private" && raw.extractable !== false)) deny();
    return raw;
  }
  async function pinnedOwnerKey(ownerPublicKey, expectedSpkiSha256) {
    const pub = key(ownerPublicKey, "public");
    const spki = await webCrypto.subtle.exportKey("spki", pub);
    const computed = encode(new Uint8Array(await webCrypto.subtle.digest("SHA-256", spki)));
    if (computed !== expectedSpkiSha256) deny();
    return pub;
  }
  function unsigned(wire) {
    return Object.fromEntries(FIELDS.map((field) => [field, wire[field]]));
  }
  async function migrationSecretDigest(raw) {
    if (!(raw instanceof Uint8Array) || raw.byteLength !== 32) deny();
    return encode(new Uint8Array(await webCrypto.subtle.digest("SHA-256",
      new Uint8Array(raw))));
  }
  async function signOwnerSelection(input) {
    try {
      const raw = exact(input, ["optIn", "entries", "trust", "ownerSigningKey",
        "migrationSecret", "issuedAt", "expiresAt", "nonce"]);
      if (raw.optIn !== true) deny();
      // Copy the owner's visible selection and external trust pin before any
      // async key export or signature. No live mutable form reads afterwards.
      const { scope, ownerSpkiSha256, ownerHead } = header(raw.trust);
      const selections = entryList(raw.entries.map((e) => ({
        legacy: e.legacy, sourcePin: e.sourcePin,
      })));
      const ownerKey = key(raw.trust?.ownerPublicKey, "public");
      const signerKey = key(raw.ownerSigningKey, "private");
      const secret = new Uint8Array(raw.migrationSecret);
      if (secret.length !== 32) deny();
      const owner = await pinnedOwnerKey(ownerKey, ownerSpkiSha256);
      const statement = {
        schema: SCHEMA, scope, ownerSpkiSha256, ownerHead,
        migrationSecretSha256: await migrationSecretDigest(secret),
        entries: selections, coverage: Object.fromEntries(COVERAGE.map(
          (name) => [name, name === "versions" ? "selected-only" : "unknown"])),
        issuedAt: number(raw.issuedAt, 1),
        expiresAt: number(raw.expiresAt, raw.issuedAt),
        nonce: raw.nonce,
      };
      if (statement.expiresAt - statement.issuedAt > 86400) deny();
      decoded(raw.nonce, 16);
      const signature = encode(new Uint8Array(await webCrypto.subtle.sign(
        "Ed25519", signerKey, bytes(statement))));
      const signedSelection = validated({ ...statement, signature });
      if (!await webCrypto.subtle.verify("Ed25519", owner, decoded(signature, 64),
        bytes(unsigned(signedSelection)))) deny();
      const selectionSha256 = new Uint8Array(await webCrypto.subtle.digest("SHA-256",
        new TextEncoder().encode(JSON.stringify(signedSelection))));
      return Object.freeze({ signedSelection: Object.freeze(signedSelection),
        selectionSha256, canDeleteLegacy: false, wholeCorpusVerified: false });
    } catch (_) { deny(); }
  }
  async function verifyOwnerSelection(input) {
    try {
      const raw = exact(input, ["optIn", "signedSelection",
        "independentlyPinnedSelectionSha256", "entries", "trust",
        "migrationSecret", "nowSeconds"]);
      if (raw.optIn !== true) deny();
      // Copy entries synchronously so a caller cannot change the batch during
      // the async SPKI/signature checks.
      const expectedEntries = entryList(raw.entries);
      const signedSelection = validated(raw.signedSelection);
      const reference = header(raw.trust);
      const secret = new Uint8Array(raw.migrationSecret);
      if (secret.length !== 32) deny();
      const independentPin = encode(raw32(raw.independentlyPinnedSelectionSha256));
      const ownerKey = key(raw.trust?.ownerPublicKey, "public");
      if (JSON.stringify(signedSelection.scope) !== JSON.stringify(reference.scope)
        || signedSelection.ownerSpkiSha256 !== reference.ownerSpkiSha256
        || JSON.stringify(signedSelection.ownerHead) !== JSON.stringify(reference.ownerHead)
        || JSON.stringify(signedSelection.entries) !== JSON.stringify(expectedEntries)
        || signedSelection.migrationSecretSha256 !== await migrationSecretDigest(secret)
        || number(raw.nowSeconds, 1) < signedSelection.issuedAt
        || raw.nowSeconds > signedSelection.expiresAt) deny();
      const packed = new TextEncoder().encode(JSON.stringify(signedSelection));
      if (encode(new Uint8Array(await webCrypto.subtle.digest("SHA-256", packed)))
        !== independentPin) deny();
      const pub = await pinnedOwnerKey(ownerKey, reference.ownerSpkiSha256);
      if (!await webCrypto.subtle.verify("Ed25519", pub,
        decoded(signedSelection.signature, 64), bytes(unsigned(signedSelection)))) deny();
      return Object.freeze({ ownerSelectionVerified: true, selectedVersions: expectedEntries.length,
        wholeCorpusVerified: false, authorizesCutover: false, canDeleteLegacy: false });
    } catch (_) { deny(); }
  }
  return Object.freeze({ signOwnerSelection, verifyOwnerSelection });
}));
