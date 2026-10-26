"use strict";

// Opt-in multi-endpoint CAS witness floor readback fence. Each independently
// pinned witness performs a fresh TLS1.3/mTLS, Ed25519 and nonce challenge.
// The operator MUST retain the exact floor outside all witness databases.
// It does not persist evidence, distribute a new floor, prove remote fsync,
// establish independent machines, or implement consensus/atomic GET fencing.
const { Zk1WitnessCasAnchorHttpsClient } = require("./zk1WitnessCasAnchorHttpsClient");
const NATIVE_APPLY = Reflect.apply;
const NATIVE_FRESH_HEAD = Zk1WitnessCasAnchorHttpsClient.prototype.freshHead;

const HEX = /^[a-f0-9]{64}$/;
const GENESIS_HASH = "0".repeat(64);
const GENESIS_PHYSICAL = require("node:crypto").createHash("sha256").update("").digest("hex");
function deny() {
  const e = new Error("INDEPENDENT_WITNESS_FLOOR_UNAVAILABLE");
  e.code = e.message;
  throw e;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((key) => !Object.hasOwn(value, key))) deny();
  const result = {};
  for (const key of fields) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !Object.hasOwn(d, "value")) deny();
    result[key] = d.value;
  }
  return result;
}
function floorCopy(floor) {
  const v = exact(floor, ["sequence", "lastHash", "physicalFenceDigest"]);
  if (!Number.isSafeInteger(v.sequence) || v.sequence < 0 || v.sequence > 100000
    || typeof v.lastHash !== "string" || !HEX.test(v.lastHash)
    || typeof v.physicalFenceDigest !== "string" || !HEX.test(v.physicalFenceDigest)
    || (v.sequence === 0 && (v.lastHash !== GENESIS_HASH
      || v.physicalFenceDigest !== GENESIS_PHYSICAL))) deny();
  return Object.freeze(v);
}
function sameHead(a, b) {
  return a.sequence === b.sequence && a.lastHash === b.lastHash
    && a.physicalFenceDigest === b.physicalFenceDigest;
}

class Zk1IndependentWitnessFloorQuorum {
  #witnesses;
  #floor;
  constructor({ witnesses, externallyRetainedFloor } = {}) {
    if (!Array.isArray(witnesses) || witnesses.length < 2 || witnesses.length > 4
      || Reflect.ownKeys(witnesses).length !== witnesses.length + 1) deny();
    const getIdentity = Object.getOwnPropertyDescriptor(
      Zk1WitnessCasAnchorHttpsClient.prototype, "independentlyPinnedIdentity")?.get;
    if (typeof getIdentity !== "function") deny();
    const signers = new Set(), servers = new Set(), endpoints = new Set(), ids = new Set();
    let statusKeyId;
    const peers = [];
    for (const witness of witnesses) {
      if (Object.getPrototypeOf(witness) !== Zk1WitnessCasAnchorHttpsClient.prototype) deny();
      let id;
      try { id = getIdentity.call(witness); } catch (_) { deny(); }
      if (id.requirePhysicalAdmission !== true
        || typeof id.endpoint !== "string" || !id.endpoint.startsWith("https://")
        || !HEX.test(id.signerSpkiSha256)
        || typeof id.peerFingerprint256 !== "string"
        || typeof id.witnessKeyId !== "string" || typeof id.statusKeyId !== "string"
        || signers.has(id.signerSpkiSha256) || servers.has(id.peerFingerprint256)
        || endpoints.has(id.endpoint) || ids.has(id.witnessKeyId)) deny();
      if (statusKeyId !== undefined && id.statusKeyId !== statusKeyId) deny();
      statusKeyId = id.statusKeyId;
      signers.add(id.signerSpkiSha256);
      servers.add(id.peerFingerprint256);
      endpoints.add(id.endpoint);
      ids.add(id.witnessKeyId);
      peers.push(witness);
    }
    this.#floor = floorCopy(externallyRetainedFloor);
    this.#witnesses = Object.freeze(peers);
    Object.freeze(this);
  }
  get requiresPhysicalAdmission() { return true; }
  // For a restart, the operator must supply its *independently retained*
  // last authorized floor again. Mutable HTTP/JSON cannot lower this snapshot.
  async freshHead(minimum = undefined) {
    try {
      if (minimum !== undefined && !sameHead(floorCopy(minimum), this.#floor)) deny();
      // An injected client object can gain a shadow `.freshHead` after quorum
      // enrollment. Invoke the original class method against its private
      // pinned TLS/Ed25519 fields rather than a caller-overridden callback.
      const results = await Promise.all(this.#witnesses.map((client) =>
        NATIVE_APPLY(NATIVE_FRESH_HEAD, client, [this.#floor])));
      if (results.length !== this.#witnesses.length) deny();
      for (const result of results) {
        if (!sameHead(floorCopy(result), this.#floor)) deny();
      }
      return { ...this.#floor };
    } catch (_) { deny(); }
  }
}
module.exports = { Zk1IndependentWitnessFloorQuorum };
