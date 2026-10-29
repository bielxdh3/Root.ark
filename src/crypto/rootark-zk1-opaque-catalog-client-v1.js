"use strict";

// Portable, read-only verifier. Callers must independently pin the witness
// signing key and owner genesis. Never construct either pin from server JSON.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const recovery = require("./rootark-zk-recovery-history-v2");
const manifests = require("./rootark-zk-recovery-manifest-v2");
const { inspectVerifiedWitnessFreshHeadV1 } = require("./rootark-zk-witness-head-wire-v1");
const HEAD_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-head/v1\0", "ascii");
const PAGE_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-page/v1\0", "ascii");
const CAS_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-cas/v1\0", "ascii");
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const FIELDS = ["type", "account_id", "compartment_id", "keyring_id",
  "sequence", "previous_digest", "manifest_revision", "manifest_digest",
  "epoch", "signer_device_id", "total_count", "page_digests", "issued_at"];
const CAS_FIELDS = ["type", "account_id", "compartment_id", "keyring_id",
  "sequence", "digest", "nonce", "observed_at"];
const MAX_ENTRIES = 4096;
const PAGE_SIZE = 32;
const METADATA_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-metadata/v1\0");

function fail() { throw new Error("ZK_CATALOG_UNVERIFIED"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((key) => !Object.hasOwn(value, key))) fail();
}
function b64(s, size) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]+$/.test(s)
    || s.length > size * 2 + 4) fail();
  const result = Buffer.from(s, "base64url");
  if (result.length !== size || result.toString("base64url") !== s) fail();
  return result;
}
function bytes(value, size) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length !== size) fail();
  return Buffer.from(value);
}
function equal(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function safeInt(n, lower = 0, upper = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(n) || n < lower || n > upper) fail();
  return n;
}
function checkScope(source, scope) {
  for (const key of ["account_id", "compartment_id", "keyring_id"]) {
    if (!equal(Buffer.from(source[key] || []), Buffer.from(scope[key]))) fail();
  }
}
function trustedKey(key) {
  if (!(key instanceof crypto.KeyObject) || key.type !== "public"
    || key.asymmetricKeyType !== "ed25519") fail();
  return key;
}
async function metadataAad({ scope, objectId, revision, epoch }) {
  if (typeof objectId !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(objectId)
    || Buffer.from(objectId, "base64url").toString("base64url") !== objectId) fail();
  safeInt(revision, 1);
  safeInt(epoch, 1);
  return Buffer.concat([METADATA_DOMAIN, Buffer.from(await z.encodeDeterministic({
    account_id: bytes(scope.account_id, 16),
    compartment_id: Buffer.from(scope.compartment_id),
    keyring_id: bytes(scope.keyring_id, 16), object_id: objectId, revision, epoch,
  }))]);
}
async function sealZk1CatalogMetadataV1({ scope, objectId, revision, epoch, metadataKey, name }) {
  if (typeof name !== "string" || /[\u0000-\u001f\u007f]/.test(name)
    || Buffer.byteLength(name, "utf8") < 1 || Buffer.byteLength(name, "utf8") > 220) fail();
  const aad = await metadataAad({ scope, objectId, revision, epoch });
  const key = bytes(metadataKey, 32);
  const iv = crypto.randomBytes(12);
  const padded = crypto.randomBytes(256);
  const filename = Buffer.from(name, "utf8");
  padded.writeUInt16BE(filename.length, 0);
  filename.copy(padded, 2);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(padded), cipher.final()]);
  padded.fill(0);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]);
}
async function openZk1CatalogMetadataV1({ scope, objectId, revision, epoch, metadataKey, ciphertext }) {
  let decoded;
  try {
    const aad = await metadataAad({ scope, objectId, revision, epoch });
    const sealed = bytes(ciphertext, 284);
    const decipher = crypto.createDecipheriv("aes-256-gcm", bytes(metadataKey, 32),
      sealed.subarray(0, 12));
    decipher.setAAD(aad);
    decipher.setAuthTag(sealed.subarray(268));
    decoded = Buffer.concat([decipher.update(sealed.subarray(12, 268)), decipher.final()]);
    const size = decoded.readUInt16BE(0);
    if (size < 1 || size > 220) fail();
    const name = new TextDecoder("utf-8", { fatal: true }).decode(decoded.subarray(2, 2 + size));
    if (!name || /[\u0000-\u001f\u007f]/.test(name)) fail();
    return name;
  } catch (_) { fail(); }
  finally { decoded?.fill(0); }
}
async function verifyZk1OpaqueCatalogPage({
  response, expectedScope, verifiedOwnerHistory, pinnedOwnerGenesisDigest,
  ownerWitnessRaw, ownerWitnessNonce, pinnedOwnerWitness, minimumOwnerHead,
  catalogNonce, pinnedCatalogAuthorityKey, minimumCatalogHead, nowSeconds,
}) {
  try {
    const now = safeInt(nowSeconds);
    const ownerValid = await recovery.isVerifiedPublicRecoveryHistoryV2(verifiedOwnerHistory);
    if (!ownerValid || !verifiedOwnerHistory.headManifest
      || !verifiedOwnerHistory.baseManifest) fail();
    checkScope(verifiedOwnerHistory.headManifest, expectedScope);
    checkScope(verifiedOwnerHistory.baseManifest, expectedScope);
    if (!equal(bytes(await manifests.recoveryManifestDigestV2(
      verifiedOwnerHistory.baseManifest), 32), bytes(pinnedOwnerGenesisDigest, 32))) fail();
    await inspectVerifiedWitnessFreshHeadV1({
      raw: ownerWitnessRaw, scope: expectedScope,
      nonce: bytes(ownerWitnessNonce, 32), pinned: pinnedOwnerWitness,
      minimumHead: minimumOwnerHead });
    const witnessedOwner = await z.decodeDeterministic(ownerWitnessRaw);
    if (Number(witnessedOwner.current_revision) !== Number(verifiedOwnerHistory.revision)
      || !equal(bytes(witnessedOwner.current_manifest_digest, 32),
        bytes(verifiedOwnerHistory.headDigest, 32))
      || Math.abs(now - Number(witnessedOwner.observed_at)) > 30) fail();
    // Use length-checked variable-size decode; 16 KB is the whole bound.
    const rawHeader = Buffer.from(response.headerBase64, "base64url");
    if (rawHeader.length < 1 || rawHeader.length > 16384) fail();
    const header = await z.decodeDeterministic(rawHeader);
    exact(header, FIELDS);
    if (!equal(Buffer.from(await z.encodeDeterministic(header)), rawHeader)
      || header.type !== "rootark-zk1-opaque-catalog/v1") fail();
    checkScope(header, expectedScope);
    safeInt(header.sequence, 1, 128);
    safeInt(header.manifest_revision, 1);
    safeInt(header.epoch, 1);
    safeInt(header.total_count, 0, MAX_ENTRIES);
    safeInt(header.issued_at);
    bytes(header.previous_digest, 32);
    bytes(header.manifest_digest, 32);
    if (!Array.isArray(header.page_digests)
      || header.page_digests.length !== Math.ceil(header.total_count / PAGE_SIZE)) fail();
    for (const d of header.page_digests) bytes(d, 32);
    if (header.manifest_revision > Number(verifiedOwnerHistory.revision)
      || header.epoch > Number(verifiedOwnerHistory.headManifest.current_epoch)
      || !Number.isSafeInteger(response.totalCount) || response.totalCount !== header.total_count
      || response.pageCount !== header.page_digests.length
      || response.sequence !== header.sequence) fail();
    const signer = verifiedOwnerHistory.headManifest.devices.find((device) =>
      device.device_id === header.signer_device_id
      && device.revoked_at_epoch === null && Number(device.enrolled_epoch) <= header.epoch);
    if (!signer) fail();
    const signature = b64(response.headerSignatureBase64, 64);
    const signerKey = crypto.createPublicKey({ key: Buffer.concat([
      SPKI, bytes(signer.authorization_public_key, 32)]), format: "der", type: "spki" });
    if (!crypto.verify(null, Buffer.concat([HEAD_DOMAIN, rawHeader]), signerKey, signature)) fail();
    const digest = crypto.createHash("sha256").update(HEAD_DOMAIN)
      .update(rawHeader).update(signature).digest();
    if (!equal(digest, b64(response.catalogDigest, 32))) fail();
    const proofRaw = Buffer.from(response.authorityProofBase64, "base64url");
    if (proofRaw.length < 1 || proofRaw.length > 8192
      || proofRaw.toString("base64url") !== response.authorityProofBase64) fail();
    const proof = await z.decodeDeterministic(proofRaw);
    exact(proof, [...CAS_FIELDS, "signature"]);
    const { signature: authoritySignature, ...cas } = proof;
    exact(cas, CAS_FIELDS);
    if (cas.type !== "rootark-zk1-opaque-catalog-cas/v1") fail();
    checkScope(cas, expectedScope);
    if (!equal(bytes(cas.nonce, 32), bytes(catalogNonce, 32))
      || Math.abs(now - safeInt(cas.observed_at)) > 30
      || cas.sequence !== header.sequence
      || !equal(bytes(cas.digest, 32), digest)) fail();
    if (!crypto.verify(null, Buffer.concat([CAS_DOMAIN,
      Buffer.from(await z.encodeDeterministic(cas))]),
    trustedKey(pinnedCatalogAuthorityKey), bytes(authoritySignature, 64))) fail();
    safeInt(minimumCatalogHead?.sequence, 0, 128);
    const pinnedMinimum = bytes(minimumCatalogHead.digest, 32);
    if (header.sequence < minimumCatalogHead.sequence
      || (header.sequence === minimumCatalogHead.sequence
        && !equal(digest, pinnedMinimum))) fail();
    const pageIndex = safeInt(response.pageIndex, 0, MAX_ENTRIES / PAGE_SIZE);
    if (pageIndex >= Math.max(1, header.page_digests.length)
      || !Array.isArray(response.entries)
      || response.entries.length !== (header.total_count === 0 ? 0
        : pageIndex === header.page_digests.length - 1
          ? header.total_count - PAGE_SIZE * pageIndex : PAGE_SIZE)) fail();
    const entries = response.entries.map((entry) => {
      exact(entry, ["objectId", "revision", "epoch", "ciphertextDigestBase64",
        "metadataCiphertextBase64"]);
      const id = entry.objectId;
      if (typeof id !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(id)
        || Buffer.from(id, "base64url").toString("base64url") !== id) fail();
      return { object_id: id, revision: safeInt(entry.revision, 1),
        epoch: safeInt(entry.epoch, 1),
        ciphertext_digest: b64(entry.ciphertextDigestBase64, 32),
        metadata_ciphertext: b64(entry.metadataCiphertextBase64, 284) };
    });
    for (let i = 1; i < entries.length; i++) {
      if (entries[i - 1].object_id > entries[i].object_id
        || (entries[i - 1].object_id === entries[i].object_id
          && entries[i - 1].revision >= entries[i].revision)) fail();
    }
    if (header.total_count && !equal(bytes(header.page_digests[pageIndex], 32),
      crypto.createHash("sha256").update(PAGE_DOMAIN)
        .update(Buffer.from(await z.encodeDeterministic(entries))).digest())) fail();
    return Object.freeze({
      sequence: header.sequence, totalCount: header.total_count, pageIndex,
      digest: Buffer.from(digest),
      entries: Object.freeze(entries.map((item) => Object.freeze({
        objectId: item.object_id, revision: item.revision, epoch: item.epoch,
        ciphertextDigest: Buffer.from(item.ciphertext_digest),
        metadataCiphertext: Buffer.from(item.metadata_ciphertext),
      }))),
    });
  } catch (_) { fail(); }
}
module.exports = { verifyZk1OpaqueCatalogPage, sealZk1CatalogMetadataV1,
  openZk1CatalogMetadataV1 };
