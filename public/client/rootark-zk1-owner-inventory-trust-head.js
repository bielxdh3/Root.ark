(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto);
  } else {
    root.RootarkZk1OwnerInventoryTrustHead = factory(root.crypto);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto) {
  "use strict";
  // Portable owner custody file: owner SPKI and checkpoint are UNTRUSTED until
  // separately pinned hashes are supplied by the user. The browser validates
  // owner Ed25519 continuity; the PG verifier ALSO validates signed inventory
  // CBOR before it may use this as a local signed-inventory floor.
  const DOMAIN = new TextEncoder().encode("Root.ark/zk-1/owner-inventory-trust-head/v1\0");
  const FIELDS = ["schema", "account_id", "compartment_id", "keyring_id",
    "inventory_signer_key_id", "inventory_spki_sha256", "counter",
    "inventory_sequence", "inventory_root", "snapshot_sha256",
    "previous_checkpoint_digest", "issued_at", "expires_at"];
  const WIRE = [...FIELDS, "signature"];
  const SCHEMA = "rootark-zk1-owner-inventory-trust-head/v1";
  const BUNDLE = "rootark-zk1-owner-inventory-portable/v1";
  const text = new TextEncoder();
  function deny() { throw new Error("ZK_OWNER_INVENTORY_IMPORT_DENIED"); }
  function exact(value, fields) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== fields.length
      || fields.some((f) => !Object.hasOwn(value, f))) deny();
    return Object.fromEntries(fields.map((f) => [f, value[f]]));
  }
  function integer(value, min = 0) {
    if (!Number.isSafeInteger(value) || value < min) deny();
    return value;
  }
  function from64(value, size, max = size) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) deny();
    let binary;
    try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { deny(); }
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    if (bytes.length < size || bytes.length > max || to64(bytes) !== value) deny();
    return bytes;
  }
  function to64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function hex(value) {
    if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) deny();
    return value;
  }
  function concat(parts) {
    const size = parts.reduce((sum, item) => sum + item.length, 0);
    if (size > 32768) deny();
    const result = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.length; }
    return result;
  }
  async function sha256(bytes) {
    return Array.from(new Uint8Array(await webCrypto.subtle.digest("SHA-256", bytes)),
      (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  function statement(wire) {
    const record = exact(wire, WIRE);
    if (record.schema !== SCHEMA) deny();
    for (const f of ["account_id", "keyring_id", "inventory_signer_key_id"]) from64(record[f], 16);
    from64(record.compartment_id, 1, 128);
    for (const f of ["inventory_spki_sha256", "inventory_root", "snapshot_sha256"]) hex(record[f]);
    integer(record.counter, 1); integer(record.inventory_sequence);
    integer(record.issued_at, 1); integer(record.expires_at, record.issued_at + 1);
    if (record.expires_at - record.issued_at > 86400 * 30
      || (record.counter === 1 && record.previous_checkpoint_digest !== null)
      || (record.counter > 1 && !record.previous_checkpoint_digest)) deny();
    if (record.previous_checkpoint_digest !== null) hex(record.previous_checkpoint_digest);
    const signature = from64(record.signature, 64);
    return { fields: Object.fromEntries(FIELDS.map((f) => [f, record[f]])), signature };
  }
  async function digest(record) {
    const { fields, signature } = statement(record);
    return sha256(concat([DOMAIN, text.encode(JSON.stringify(fields)), signature]));
  }
  function exportPortableEnrollment({ ownerSpkiDer, checkpoints, minimumSnapshot } = {}) {
    if (!(ownerSpkiDer instanceof Uint8Array)
      || !(minimumSnapshot instanceof Uint8Array)
      || minimumSnapshot.length < 1 || minimumSnapshot.length > 262144
      || !Array.isArray(checkpoints) || checkpoints.length < 1 || checkpoints.length > 64) deny();
    const records = checkpoints.map((record) => {
      statement(record);
      return exact(record, WIRE);
    });
    return JSON.stringify({ schema: BUNDLE, owner_spki: to64(ownerSpkiDer),
      checkpoints: records, minimum_snapshot: to64(minimumSnapshot) });
  }
  async function importPortableEnrollment({ serialized, independentOwnerSpkiSha256,
    independentCheckpointDigest, expectedScope, expectedInventorySpkiSha256,
    nowSeconds } = {}) {
    try {
      if (typeof serialized !== "string" || serialized.length > 400000
        || !webCrypto?.subtle || !Array.isArray(expectedScope) || expectedScope.length !== 3) deny();
      const bundle = exact(JSON.parse(serialized),
        ["schema", "owner_spki", "checkpoints", "minimum_snapshot"]);
      if (bundle.schema !== BUNDLE || JSON.stringify(bundle) !== serialized) deny();
      const ownerSpki = from64(bundle.owner_spki, 44, 256);
      if (await sha256(ownerSpki) !== hex(independentOwnerSpkiSha256)) deny();
      const key = await webCrypto.subtle.importKey("spki", ownerSpki,
        "Ed25519", false, ["verify"]);
      if (!Array.isArray(bundle.checkpoints) || bundle.checkpoints.length < 1
        || bundle.checkpoints.length > 64) deny();
      let previous = null;
      for (const [index, record] of bundle.checkpoints.entries()) {
        const { fields, signature } = statement(record);
        if (fields.counter !== index + 1
          || fields.inventory_spki_sha256 !== hex(expectedInventorySpkiSha256)
          || !["account_id", "compartment_id", "keyring_id"].every(
            (name, offset) => fields[name] === expectedScope[offset])) deny();
        if (!await webCrypto.subtle.verify("Ed25519", key, signature,
          concat([DOMAIN, text.encode(JSON.stringify(fields))]))) deny();
        const currentDigest = await digest(record);
        if (previous && (fields.previous_checkpoint_digest !== previous.digest
          || fields.inventory_sequence < previous.sequence
          || (fields.inventory_sequence === previous.sequence
            && fields.inventory_root !== previous.root)
          || fields.issued_at < previous.issuedAt)) deny();
        previous = { digest: currentDigest, counter: fields.counter,
          sequence: fields.inventory_sequence, root: fields.inventory_root,
          snapshotHash: fields.snapshot_sha256, issuedAt: fields.issued_at,
          expiresAt: fields.expires_at };
      }
      if (!previous || previous.digest !== hex(independentCheckpointDigest)
        || integer(nowSeconds, 1) < previous.issuedAt || nowSeconds > previous.expiresAt) deny();
      const snapshot = from64(bundle.minimum_snapshot, 1, 262144);
      if (await sha256(snapshot) !== previous.snapshotHash) deny();
      return Object.freeze({ ownerSignatureVerified: true,
        independentlyPinnedDigestMatched: true, ownerCheckpointCounter: previous.counter,
        inventorySequence: previous.sequence, inventoryRoot: previous.root,
        // A browser import is not a substitute for verifying the signed CBOR
        // inventory or proving durable off-server custody.
        inventorySnapshotSignatureVerified: false,
        externalCustodyProven: false, authorizesProtectedIo: false });
    } catch (_) { deny(); }
  }
  return Object.freeze({ exportPortableEnrollment, importPortableEnrollment });
}));
