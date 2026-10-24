"use strict";

// Read-only V1 #128 -> V2 handoff gate. Does not reset V1, publish V2, or
// create a new catalog authority. All historical bytes remain in the caller's
// immutable, independently archived 128-head corpus.
const crypto = require("node:crypto");
const z = require("../crypto/rootark-zk-1");
const { verifyAuthenticatedOpaqueCatalogArchiveV2 } =
  require("../crypto/rootark-zk1-opaque-catalog-checkpoint-v2");
const { catalogCasDomain } = require("./zk1OpaqueCatalog");

const OWNER_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-v1-v2-owner-rollover-handoff/v1\0");
const FLOOR_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-independent-floor/v1\0");
const FIELDS = ["type", "account_id", "compartment_id", "keyring_id",
  "v1_sequence", "v1_digest", "v1_archive_root", "v1_archive_checkpoint",
  "v2_cas_spki_sha256", "v2_floor_spki_sha256",
  "v2_checkpoint_spki_sha256", "owner_revision", "owner_digest",
  "owner_epoch", "next_epoch", "nonce", "issued_at", "expires_at"];
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const CAS_FIELDS = ["type", ...SCOPE, "sequence", "digest", "nonce", "observed_at"];
const FLOOR_FIELDS = ["type", ...SCOPE, "cas_signer_spki_sha256",
  "sequence", "digest", "nonce", "observed_at"];
function deny() { const e = new Error("ZK_V1_V2_ROLLOVER_PREFLIGHT_DENIED"); e.code = e.message; throw e; }
function exact(obj, fields) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(obj))
    || Reflect.ownKeys(obj).length !== fields.length
    || fields.some((name) => !Object.hasOwn(obj, name))
    || Object.values(Object.getOwnPropertyDescriptors(obj)).some(
      (descriptor) => !Object.hasOwn(descriptor, "value"))) deny();
}
function raw(value, size) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)
    || value.byteLength !== size) deny();
  return Buffer.from(value);
}
function eq(a, b) { return a.length === b.length && crypto.timingSafeEqual(a, b); }
function key(value) {
  if (!(value instanceof crypto.KeyObject) || value.type !== "public"
    || value.asymmetricKeyType !== "ed25519") deny();
  return value;
}
function fp(value) {
  return crypto.createHash("sha256").update(key(value).export({
    type: "spki", format: "der" })).digest();
}
function b64(v, len) {
  if (typeof v !== "string" || !/^[A-Za-z0-9_-]+$/.test(v)) deny();
  const data = Buffer.from(v, "base64url");
  if (data.length !== len || data.toString("base64url") !== v) deny();
  return data;
}
function scopeEqual(statement, scope) {
  for (const name of SCOPE) {
    const expected = raw(scope[name], name === "compartment_id" ? scope[name].length : 16);
    if (!eq(raw(statement[name], expected.length), expected)) deny();
  }
}
function validateHandoff(handoff, trust, archive, now) {
  exact(handoff, FIELDS);
  if (handoff.type !== "rootark-zk1-opaque-v1-v2-owner-rollover-handoff/v1"
    || handoff.v1_sequence !== 128
    || !eq(b64(handoff.v1_digest, 32), archive.finalDigest)
    || !eq(b64(handoff.v1_archive_root, 32), archive.archiveRoot)
    || !eq(b64(handoff.v1_archive_checkpoint, 32), archive.checkpointDigest)
    || !eq(b64(handoff.v2_cas_spki_sha256, 32), fp(trust.v2CasKey))
    || !eq(b64(handoff.v2_floor_spki_sha256, 32), fp(trust.v2FloorKey))
    || !eq(b64(handoff.v2_checkpoint_spki_sha256, 32), fp(trust.v2CheckpointKey))
    || handoff.owner_revision !== trust.ownerHead.revision
    || !eq(b64(handoff.owner_digest, 32), raw(trust.ownerHead.digest, 32))
    || handoff.owner_epoch !== trust.ownerHead.epoch
    || !Number.isSafeInteger(handoff.next_epoch)
    // A future epoch is not authorized before the current owner witness
    // actually commits it; the signed handoff must match the live epoch.
    || handoff.next_epoch !== handoff.owner_epoch
    || !Number.isSafeInteger(handoff.issued_at)
    || !Number.isSafeInteger(handoff.expires_at)
    || handoff.issued_at > now + 30 || now > handoff.expires_at
    || handoff.issued_at <= 0
    || handoff.expires_at <= handoff.issued_at
    || handoff.expires_at - handoff.issued_at > 300) deny();
  b64(handoff.nonce, 32);
  for (const name of SCOPE)
    if (handoff[name] !== raw(trust.scope[name],
      name === "compartment_id" ? trust.scope[name].length : 16).toString("base64url")) deny();
}
async function verifyReceipt(rawReceipt, fields, scope, expectedType, signer,
  domain, sequence, digest, now) {
  const parsed = await z.decodeDeterministic(rawReceipt);
  exact(parsed, [...fields, "signature"]);
  const signature = raw(parsed.signature, 64);
  const body = Object.fromEntries(fields.map((field) => [field, parsed[field]]));
  scopeEqual(parsed, scope);
  if (parsed.type !== expectedType || parsed.sequence !== sequence
    || !eq(raw(parsed.digest, 32), digest)
    || !Number.isSafeInteger(parsed.observed_at)
    || Math.abs(parsed.observed_at - now) > 30
    || !crypto.verify(null, Buffer.concat([domain,
      Buffer.from(await z.encodeDeterministic(body))]), key(signer), signature)) deny();
  return parsed;
}
async function verifyRolloverPreflight({
  scope, records128, archiveCheckpointBytes, archiveCheckpointSignature,
  checkpointKey, resolveCatalogSigner, v1CasClient, v1FloorClient,
  v1CasKey, v1FloorKey, v2CasKey, v2FloorKey, v2CheckpointKey,
  ownerKey, ownerHead, handoff, ownerSignature, independentSpkiPins,
  v2PredecessorCheckpointPin,
}) {
  try {
    const now = Math.floor(Date.now() / 1000);
    exact(scope, SCOPE);
    const originalScope = Object.fromEntries(SCOPE.map((name) =>
      [name, Buffer.from(scope[name])]));
    if (originalScope.account_id.length !== 16
      || originalScope.keyring_id.length !== 16
      || originalScope.compartment_id.length < 1
      || originalScope.compartment_id.length > 128) deny();
    exact(ownerHead, ["revision", "digest", "epoch"]);
    const witnessedOwner = { revision: ownerHead.revision,
      digest: raw(ownerHead.digest, 32), epoch: ownerHead.epoch };
    const ownerSig = raw(ownerSignature, 64);
    exact(handoff, FIELDS);
    const originalHandoff = Object.fromEntries(FIELDS.map((name) =>
      [name, handoff?.[name]]));
    exact(independentSpkiPins, ["v1Cas", "v1Floor", "v2Cas", "v2Floor",
      "archiveCheckpoint", "v2Checkpoint", "owner"]);
    if (!Array.isArray(records128) || records128.length !== 128
      || typeof resolveCatalogSigner !== "function"
      || typeof v1CasClient?.readHead !== "function"
      || typeof v1FloorClient?.readHead !== "function"
      || now < 1) deny();
    const keys = [v1CasKey, v1FloorKey, v2CasKey, v2FloorKey,
      v2CheckpointKey, checkpointKey, ownerKey].map(key);
    const prints = keys.map(fp);
    for (const [keyName, index] of [["v1Cas", 0], ["v1Floor", 1],
      ["v2Cas", 2], ["v2Floor", 3], ["v2Checkpoint", 4],
      ["archiveCheckpoint", 5], ["owner", 6]]) {
      if (!eq(prints[index], b64(independentSpkiPins[keyName], 32))) deny();
    }
    if (prints.some((value, i) => prints.some((other, j) =>
      i !== j && !(i === 4 && j === 5) && !(i === 5 && j === 4)
      && eq(value, other)))) deny();
    // All 128 headers/pages and EACH owner-verified historical device signer
    // must pass the existing canonical CBOR and Merkle verifier.
    const archive = await verifyAuthenticatedOpaqueCatalogArchiveV2({
      checkpointBytes: archiveCheckpointBytes,
      checkpointSignature: archiveCheckpointSignature,
      pinnedCheckpointPublicKey: checkpointKey,
      scope: originalScope, records: records128, previousSequence: 0,
      previousDigest: Buffer.alloc(32), previousCheckpointDigest: Buffer.alloc(32),
      resolveCatalogSigner, expectedFinalSequence: 128 });
    // The V2 baseline must commit to this FULL 128-head archive, not merely
    // an independently signed one-record suffix checkpoint at #128.
    if (!eq(b64(v2PredecessorCheckpointPin, 32), archive.checkpointDigest)) deny();
    const trust = { scope: originalScope, v2CasKey, v2FloorKey,
      v2CheckpointKey, ownerHead: witnessedOwner };
    validateHandoff(originalHandoff, trust, archive, now);
    if (!Number.isSafeInteger(witnessedOwner.revision) || witnessedOwner.revision < 1
      || !Number.isSafeInteger(witnessedOwner.epoch) || witnessedOwner.epoch < 1) deny();
    if (!crypto.verify(null, Buffer.concat([OWNER_DOMAIN,
      Buffer.from(JSON.stringify(originalHandoff))]), ownerKey, ownerSig)) deny();
    async function remoteTerminal() {
      const nonce = crypto.randomBytes(32);
      const copyScope = () => Object.fromEntries(SCOPE.map((name) =>
        [name, Buffer.from(originalScope[name])]));
      const [casRaw, floor] = await Promise.all([
        v1CasClient.readHead({ scope: copyScope(), nonce: Buffer.from(nonce) }),
        v1FloorClient.readHead({ scope: copyScope() }) ]);
      if (!(casRaw instanceof Uint8Array) || casRaw.byteLength < 1
        || casRaw.byteLength > 4096
        || !(floor?.proof instanceof Uint8Array)
        || floor.proof.byteLength < 1 || floor.proof.byteLength > 4096) deny();
      const cas = await verifyReceipt(casRaw, CAS_FIELDS, originalScope,
        "rootark-zk1-opaque-catalog-cas/v1", v1CasKey, catalogCasDomain,
        128, archive.finalDigest, now);
      if (!eq(raw(cas.nonce, 32), nonce)) deny();
      if (!floor || floor.sequence !== 128
        || !eq(raw(floor.digest, 32), archive.finalDigest)) deny();
      const floorReceipt = await verifyReceipt(raw(floor.proof, floor.proof.length),
        FLOOR_FIELDS, originalScope, "rootark-zk1-opaque-catalog-independent-floor/v1",
        v1FloorKey, FLOOR_DOMAIN, 128, archive.finalDigest, now);
      if (!eq(raw(floorReceipt.cas_signer_spki_sha256, 32), fp(v1CasKey))) deny();
    }
    await remoteTerminal();
    await remoteTerminal(); // reject head change while verifying the owner handoff
    return Object.freeze({
      state: "V1_128_ARCHIVED_OWNER_HANDOFF_VERIFIED_READ_ONLY",
      sequence: 128, digest: archive.finalDigest.toString("base64url"),
      archiveRoot: archive.archiveRoot.toString("base64url"),
      checkpointDigest: archive.checkpointDigest.toString("base64url"),
      ownerEpoch: handoff.owner_epoch, nextEpoch: handoff.next_epoch,
      archivesRetained: 128, v2WriteAuthorized: false,
      productionDurabilityProven: false, v1ResetAuthorized: false,
    });
  } catch (_) { deny(); }
}
module.exports = { verifyRolloverPreflight, OWNER_DOMAIN, FIELDS };
