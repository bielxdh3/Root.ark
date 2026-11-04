(function (root, factory) {
  "use strict";
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto);
  } else {
    root.RootarkZk1OpaqueV1V2HandoffPreflight = factory(root.crypto);
  }
}(typeof globalThis === "object" ? globalThis : this, function (crypto) {
  "use strict";
  // Browser-only verification of the OFFLINE owner handoff. This does not
  // authenticate 128 record bytes; the Node preflight must verify them in full
  // and the browser must possess its own independent offline anchors.
  const domain = new TextEncoder().encode(
    "Root.ark/zk-1/opaque-v1-v2-owner-rollover-handoff/v1\0");
  const fields = ["type", "account_id", "compartment_id", "keyring_id",
    "v1_sequence", "v1_digest", "v1_archive_root", "v1_archive_checkpoint",
    "v2_cas_spki_sha256", "v2_floor_spki_sha256",
    "v2_checkpoint_spki_sha256", "owner_revision", "owner_digest",
    "owner_epoch", "next_epoch", "nonce", "issued_at", "expires_at"];
  function deny() { throw new Error("ZK_V1_V2_BROWSER_HANDOFF_UNVERIFIED"); }
  function exact(x, names) {
    if (!x || typeof x !== "object" || Array.isArray(x)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(x))
      || Reflect.ownKeys(x).length !== names.length
      || names.some((n) => !Object.hasOwn(x, n))
      || Object.values(Object.getOwnPropertyDescriptors(x)).some(
        (descriptor) => !Object.hasOwn(descriptor, "value"))) deny();
  }
  function b64(input, size) {
    if (typeof input !== "string" || !/^[A-Za-z0-9_-]+$/.test(input)) deny();
    let decoded;
    try {
      decoded = Uint8Array.from(atob(input.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(input.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
    } catch (_) { deny(); }
    if (decoded.length !== size || encode(decoded) !== input) deny();
    return decoded;
  }
  function encode(v) {
    let s = ""; for (const c of v) s += String.fromCharCode(c);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function equal(a, b) {
    if (a.length !== b.length) return false;
    let n = 0; for (let i = 0; i < a.length; i++) n |= a[i] ^ b[i];
    return n === 0;
  }
  async function verifyOwnerHandoff(input) {
    try {
      exact(input, ["handoff", "ownerSignature", "ownerPublicKeyRaw",
        "ownerSpkiSha256", "scope", "ownerHead", "v1Digest",
        "archiveRoot", "archiveCheckpoint", "v2PredecessorCheckpointPin",
        "v2CasSpkiSha256",
        "v2FloorSpkiSha256", "v2CheckpointSpkiSha256"]);
      const h = input.handoff;
      const nowSeconds = Math.floor(Date.now() / 1000);
      exact(h, fields);
      exact(input.scope, ["account_id", "compartment_id", "keyring_id"]);
      exact(input.ownerHead, ["revision", "digest", "epoch"]);
      if (h.type !== "rootark-zk1-opaque-v1-v2-owner-rollover-handoff/v1"
        || h.v1_sequence !== 128 || h.owner_epoch !== input.ownerHead.epoch
        || h.owner_revision !== input.ownerHead.revision
        || !Number.isSafeInteger(h.next_epoch)
        || h.next_epoch !== h.owner_epoch || !Number.isSafeInteger(h.issued_at)
        || !Number.isSafeInteger(h.expires_at)
        || h.issued_at < 1 || h.issued_at > nowSeconds + 30
        || h.expires_at <= h.issued_at
        || h.expires_at - h.issued_at > 300
        || nowSeconds > h.expires_at) deny();
      for (const field of Object.keys(input.scope))
        if (h[field] !== input.scope[field]) deny();
      for (const [key, expected] of [
        ["v1_digest", input.v1Digest],
        ["v1_archive_root", input.archiveRoot],
        ["v1_archive_checkpoint", input.archiveCheckpoint],
        ["v1_archive_checkpoint", input.v2PredecessorCheckpointPin],
        ["v2_cas_spki_sha256", input.v2CasSpkiSha256],
        ["v2_floor_spki_sha256", input.v2FloorSpkiSha256],
        ["v2_checkpoint_spki_sha256", input.v2CheckpointSpkiSha256],
        ["owner_digest", input.ownerHead.digest],
      ]) if (!equal(b64(h[key], 32), b64(expected, 32))) deny();
      b64(h.nonce, 32);
      const raw = b64(input.ownerPublicKeyRaw, 32);
      const pub = await crypto.subtle.importKey("raw", raw,
        "Ed25519", true, ["verify"]);
      const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pub));
      if (!equal(new Uint8Array(await crypto.subtle.digest("SHA-256", spki)),
        b64(input.ownerSpkiSha256, 32))) deny();
      const msg = new Uint8Array(domain.length
        + new TextEncoder().encode(JSON.stringify(h)).length);
      msg.set(domain);
      msg.set(new TextEncoder().encode(JSON.stringify(h)), domain.length);
      if (!await crypto.subtle.verify("Ed25519", pub,
        b64(input.ownerSignature, 64), msg)) deny();
      return Object.freeze({ state: "OWNER_V1_128_V2_HANDOFF_VERIFIED_READ_ONLY",
        sequence: 128, nextEpoch: h.next_epoch,
        archivedHistoryVerifiedHere: false, v2WriteAuthorized: false,
        v1ResetAuthorized: false, serverPlaintextExposed: false });
    } catch (_) { deny(); }
  }
  return Object.freeze({ verifyOwnerHandoff });
}));
