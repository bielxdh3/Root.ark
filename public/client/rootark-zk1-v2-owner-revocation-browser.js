(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./rootark-zk1-v2-owner-revocation-import"));
  } else root.RootarkZk1V2OwnerRevocationBrowser = factory(root.RootarkZk1V2OwnerRevocationImport);
}(typeof globalThis === "object" ? globalThis : this, function (transfer) {
  "use strict";
  // Only a receipt inspection workflow. This module intentionally has no
  // ProtectedObjectStore, HTTP or provisionOffline access and returns no grants.
  // Independent pins must arrive from outside the signed delivery and server.
  const pins = ["ownerSpkiSha256", "witnessSpkiSha256", "casSpkiSha256",
    "priorReceiptSha256", "casSequence", "revision", "digest", "epoch",
    "previousRevision", "previousDigest"];
  const highestSequence = new Map();
  function deny() { throw Error("ZK_V2_OWNER_REVOCATION_BROWSER_DENIED"); }
  function exact(value, keys) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).length !== keys.length
      || keys.some((key) => !Object.hasOwn(value, key))) deny();
    return value;
  }
  function unsigned(value) {
    if (!Number.isSafeInteger(value) || value < 1) deny();
    return value;
  }
  // Revocation validation never grants active-device authority, even after a
  // successful signed witness/CAS proof. Full canonical V2 history + live
  // policy must be separately verified before any caller uses survivor grants.
  async function verifyOfflineTransfer(input) {
    try {
      exact(input, ["delivery", "ownerSpki", "witnessSpki", "casSpki",
        "independentPins", "nowSeconds", "assertLive"]);
      if (typeof input.assertLive !== "function"
        || !transfer?.verifyRevocationDelivery) deny();
      input.assertLive();
      const external = exact(input.independentPins, pins);
      unsigned(external.casSequence);
      unsigned(external.revision);
      unsigned(external.epoch);
      unsigned(external.previousRevision);
      const scope = exact(input.delivery?.scope,
        ["account_id", "compartment_id", "keyring_id"]);
      const key = JSON.stringify([external.ownerSpkiSha256, scope.account_id,
        scope.compartment_id, scope.keyring_id]);
      const last = highestSequence.get(key);
      if (last !== undefined && external.casSequence < last) deny();
      const result = await transfer.verifyRevocationDelivery({
        delivery: input.delivery, ownerSpki: input.ownerSpki,
        witnessSpki: input.witnessSpki, casSpki: input.casSpki,
        independentPins: external, nowSeconds: input.nowSeconds,
      });
      input.assertLive();
      if (result.transferVerified !== true || result.authorizesProtectedIo !== false
        || result.fullV2ManifestHistoryVerified !== false
        || result.liveCasOrCustodyVerified !== false
        || result.activeSurvivorGrantsSigned < 1) deny();
      const current = unsigned(input.delivery.signedCasProof.cas_sequence);
      // Read the floor again after awaited WebCrypto. A second concurrent
      // import may have already consumed this very same CAS sequence.
      const latest = highestSequence.get(key);
      if ((latest !== undefined && current <= latest)
        || current <= external.casSequence) deny();
      input.assertLive();
      highestSequence.set(key, current);
      // Deliberately exclude raw delivery, signatures and survivor grant data.
      return Object.freeze({ verified: true, revision: external.revision,
        epoch: external.epoch, revokedDeviceId: result.revokedDeviceId,
        signedSurvivorCount: result.activeSurvivorGrantsSigned,
        witnessAndCasVerified: true, grantsReleased: false,
        fullV2HistoryVerified: false, authorizesProtectedIo: false,
        externalCustodyAndDurabilityVerified: false });
    } catch (_) { deny(); }
  }
  function clear() { highestSequence.clear(); }
  return Object.freeze({ verifyOfflineTransfer, clear });
}));
