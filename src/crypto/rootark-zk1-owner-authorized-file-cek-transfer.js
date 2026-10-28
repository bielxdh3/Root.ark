"use strict";

// DEV-OFF client-side only. No server route consumes this envelope. The owner
// explicitly rewraps an already-held FILE CEK; a device epoch key alone never
// grants access to historical file CEKs. No off-host or production claim.
const crypto = require("node:crypto");
const { types: nativeTypes } = require("node:util");
const z = require("./rootark-zk-1");
const commitment = require("./rootark-zk1-offline-commitment-receipt");
const committedApproval = require("../../public/client/rootark-zk1-v2-committed-approval");
const browserPop = require("../../public/client/rootark-zk1-v2-browser-pop");
const fileContent = require("../../public/client/rootark-zk1-file-content");
const roots = require("../../public/client/rootark-zk1-ciphertext-chunk-root");
const DOMAIN = Buffer.from("Root.ark/zk-1/owner-authorized-file-cek-transfer/v1\0");
const INFO = Buffer.from("Root.ark/zk-1/owner-authorized-file-cek-info/v1\0");
const AAD = Buffer.from("Root.ark/zk-1/owner-authorized-file-cek-aad/v1\0");
const FORMAT = "rootark-zk1-owner-device-file-cek-hpke/v1";
const GRANT = ["schema", "account_id", "compartment_id", "keyring_id", "device_id",
  "authorization_key_id", "authorization_public_key", "manifest_revision",
  "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
const REQUEST = ["schema", "device_id", "authorization_key_id",
  "authorization_public_key", "hpke_key_id", "hpke_public_key", "challenge", "approval"];
const APPROVAL = ["schema", "request_sha256", "operation_id",
  "target_device_key_digest", "pop_challenge_id", "manifest_revision",
  "manifest_digest", "epoch", "grant_sha256", "issued_at", "expires_at"];
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const META = [...SCOPE, "object_id", "version_id", "parent_version_id", "epoch", "kind"];
const BINDING = [...META, "object_revision", "device_id", "authorization_key_id",
  "hpke_key_id", "hpke_public_key", "owner_revision", "owner_digest", "owner_epoch",
  "witness_sequence", "witness_receipt_sha256", "signed_grant_sha256",
  "ciphertext_root", "ciphertext_sha256"];
const CORE = ["schema", ...BINDING, "nonce", "expires_at"];
function deny() { throw Error("ZK_OWNER_FILE_CEK_DENIED"); }
// Capture *all* caller-owned trust material synchronously, before the first
// await. Frozen plain objects cannot hide accessor reentrancy, and copying
// typed arrays prevents subsequent caller writes from changing pin/AEAD bytes.
// Native private/public keys are opaque handles, not caller-owned dictionaries.
function snapshotFields(value, depth = 0, budget = { count: 0, bytes: 0 }) {
  if (depth > 12 || ++budget.count > 512) deny();
  if (value === null || typeof value === "boolean" || typeof value === "number"
    || typeof value === "string") {
    if (typeof value === "string" && value.length > 524288) deny();
    return value;
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array
    || value instanceof ArrayBuffer) {
    const length = value.byteLength;
    budget.bytes += length;
    if (!Number.isSafeInteger(length) || length > 4 * 1024 * 1024
      || budget.bytes > 8 * 1024 * 1024) deny();
    if (Buffer.isBuffer(value)) return Buffer.from(value);
    if (value instanceof Uint8Array) return Uint8Array.from(value);
    return value.slice(0);
  }
  if (value instanceof crypto.KeyObject
    || nativeTypes.isCryptoKey(value)) return value;
  // @hpke uses XCryptoKey wrapping mutable 32-byte private raw material.
  // Copy that material synchronously; reconstruct a fresh HPKE handle only
  // after all other authorization checks. Never keep the caller's raw array.
  const prototype = value && typeof value === "object"
    ? Object.getPrototypeOf(value) : null;
  const ctor = prototype && Object.getOwnPropertyDescriptor(prototype, "constructor");
  if (ctor && Object.hasOwn(ctor, "value")
    && ctor.value?.name === "XCryptoKey") {
    const d = Object.getOwnPropertyDescriptors(value);
    const expected = ["key", "type", "extractable", "algorithm", "usages"];
    if (Reflect.ownKeys(d).length !== expected.length
      || expected.some((name) => !d[name] || !Object.hasOwn(d[name], "value"))
      || d.type.value !== "private" || !(d.key.value instanceof Uint8Array)
      || d.key.value.byteLength !== 32 || !Array.isArray(d.usages.value)
      || d.usages.value.length > 8) deny();
    const algorithm = snapshotFields(d.algorithm.value, depth + 1, budget);
    if (algorithm.name !== "X25519") deny();
    const usages = Object.getOwnPropertyDescriptors(d.usages.value);
    for (let i = 0; i < d.usages.value.length; i++) {
      if (!Object.hasOwn(usages[i] ?? {}, "value")
        || typeof usages[i].value !== "string") deny();
    }
    return Object.freeze({ hpkePrivateRaw: Uint8Array.from(d.key.value) });
  }
  if (typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const entries = Reflect.ownKeys(descriptors);
  const out = Object.create(Object.getPrototypeOf(value));
  for (const name of entries) {
    if (typeof name !== "string" || !Object.hasOwn(descriptors[name], "value")) deny();
    Object.defineProperty(out, name, { value: snapshotFields(
      descriptors[name].value, depth + 1, budget),
    enumerable: true, writable: false, configurable: false });
  }
  return Object.freeze(out);
}
function exact(v, keys) {
  if (!v || typeof v !== "object" || Array.isArray(v)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(v))
    || Reflect.ownKeys(v).length !== keys.length
    || keys.some((k) => !Object.hasOwn(v, k))) deny();
  return v;
}
function raw(v, length) {
  if (!ArrayBuffer.isView(v) || v.byteLength !== length) deny();
  return Buffer.from(v.buffer, v.byteOffset, v.byteLength);
}
function from64(v, n) {
  if (typeof v !== "string" || !/^[A-Za-z0-9_-]+$/.test(v)
    || v.length > Math.ceil(n * 4 / 3) + 3) deny();
  const b = Buffer.from(v, "base64url");
  if (b.length !== n || b.toString("base64url") !== v) deny();
  return b;
}
const b64 = (v) => Buffer.from(v).toString("base64url");
const sha = (v) => crypto.createHash("sha256").update(v).digest();
function compare(a, b) { return a.length === b.length && crypto.timingSafeEqual(a, b); }
function positive(v) { if (!Number.isSafeInteger(v) || v < 1) deny(); return v; }
function metadataCopy(meta) {
  exact(meta, META);
  for (const n of ["account_id", "keyring_id", "object_id", "version_id"])
    from64(meta[n], 16);
  const compartment = Buffer.from(meta.compartment_id, "base64url");
  if (!compartment.length || compartment.length > 128
    || b64(compartment) !== meta.compartment_id) deny();
  if (meta.parent_version_id !== null) from64(meta.parent_version_id, 16);
  positive(meta.epoch);
  if (meta.kind !== "file") deny();
  return Object.fromEntries(META.map((n) => [n, meta[n]]));
}
function headFrom(a) {
  const h = a.currentHead || a.pinnedCurrentHead;
  if (!h) deny();
  return { revision: positive(h.revision), epoch: positive(h.epoch),
    digest: raw(h.digest, 32) };
}
function toNodePub(publicKey) {
  if (publicKey?.type === "public" && typeof publicKey.export === "function")
    return publicKey;
  deny();
}
async function verifyOwnerApprovedHpkeRecipient(a, trusted, owner, nowSeconds) {
  // An Ed25519 device grant does NOT authenticate its unrelated X25519 key.
  // The owner's separate V2 approval commits to the complete request and
  // target PoP digest. Verify it before exposing an A-held CEK to that key.
  const request = exact(a.request, REQUEST);
  const approval = exact(a.approval, [...APPROVAL, "signature"]);
  if (request.schema !== "rootark-zk1-device-enrollment-request/v1"
    || request.approval !== "OWNER_MUST_VERIFY_IDENTITY_AND_FINISH_V2_POP_AND_SIGN_CURRENT_GRANT"
    || approval.schema !== "rootark-zk1-offline-v2-device-approval/v1"
    || !Number.isSafeInteger(approval.issued_at)
    || !Number.isSafeInteger(approval.expires_at)
    || approval.expires_at <= approval.issued_at
    || approval.expires_at - approval.issued_at > 300
    || approval.issued_at > nowSeconds + 30
    || approval.expires_at < nowSeconds) deny();
  from64(request.challenge, 32);
  for (const field of ["request_sha256", "target_device_key_digest",
    "manifest_digest", "grant_sha256"]) from64(approval[field], 32);
  for (const field of ["operation_id", "pop_challenge_id"]) from64(approval[field], 16);
  if (approval.request_sha256 !== b64(sha(Buffer.from(JSON.stringify(request))))
    || approval.grant_sha256 !== b64(sha(Buffer.from(JSON.stringify(
      Object.fromEntries(GRANT.map((field) => [field, trusted.grant[field]]))))))
    || approval.target_device_key_digest !== await browserPop.targetDigest(request)
    || approval.manifest_revision !== trusted.head.revision
    || approval.manifest_digest !== b64(trusted.head.digest)
    || approval.epoch !== trusted.head.epoch
    || approval.operation_id !== a.committedReceipt.operation_id
    || approval.pop_challenge_id !== a.committedReceipt.pop_challenge_id
    || request.challenge !== a.committedReceipt.request_nonce) deny();
  const approvedMessage = Buffer.concat([
    Buffer.from("Root.ark/zk-1/v2-offline-device-approval/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(
      APPROVAL.map((field) => [field, approval[field]]))))]);
  if (!crypto.verify(null, approvedMessage, owner, from64(approval.signature, 64))) deny();

  // The witness-pinned head identifies the exact signed V2 manifest, not a
  // JSON self-assertion. Ensure its committed target public keys match B.
  const manifestBytes = Buffer.from(a.signedV2Manifest, "base64url");
  if (manifestBytes.length < 128 || manifestBytes.length > 262144
    || b64(manifestBytes) !== a.signedV2Manifest
    || !compare(sha(Buffer.concat([
      Buffer.from("Root.ark/zk-1/recovery-manifest-digest/v1\0"), manifestBytes])),
    trusted.head.digest)) deny();
  const v2 = await z.decodeDeterministic(manifestBytes);
  const device = v2.devices?.find((d) => d.device_id === request.device_id);
  if (!device
    || !compare(Buffer.from(device.hpke_public_key), from64(request.hpke_public_key, 32))
    || !compare(Buffer.from(device.hpke_key_id), from64(request.hpke_key_id, 16))
    || !compare(Buffer.from(device.authorization_public_key),
      from64(request.authorization_public_key, 32))
    || !compare(Buffer.from(device.authorization_key_id),
      from64(request.authorization_key_id, 16))
    || !compare(Buffer.from(v2.operation?.target_device_key_digest),
      from64(approval.target_device_key_digest, 32))) deny();
  return Buffer.from(device.hpke_public_key);
}
async function normalizedAuthority(a, minimumSequence, nowSeconds, nodeKeys) {
  positive(minimumSequence); positive(nowSeconds);
  // A caller-supplied old time cannot resurrect an expired signed grant.
  if (Math.abs(Math.floor(Date.now() / 1000) - nowSeconds) > 30) deny();
  const grant = exact(snapshotFields(a.signedDeviceGrant), [...GRANT, "signature"]);
  const request = snapshotFields(a.request);
  if (!request || typeof request !== "object") deny();
  const owner = nodeKeys.owner, witness = nodeKeys.witness;
  const ownerHash = sha(owner.export({ type: "spki", format: "der" }));
  if (!compare(ownerHash, raw(a.independentOwnerSpkiSha256, 32))) deny();
  const head = headFrom(a);
  for (const k of SCOPE) {
    const value = Buffer.from(grant[k], "base64url");
    if (!value.length || value.length > (k === "compartment_id" ? 128 : 16)
      || (k !== "compartment_id" && value.length !== 16)
      || b64(value) !== grant[k]) deny();
  }
  if (!request || typeof request.device_id !== "string" || !request.device_id
    || request.device_id !== grant.device_id
    || request.authorization_key_id !== grant.authorization_key_id
    || request.authorization_public_key !== grant.authorization_public_key
    || grant.revoked_at_epoch !== null
    || grant.manifest_revision !== head.revision
    || grant.manifest_digest !== b64(head.digest)
    || grant.current_epoch !== head.epoch) deny();
  from64(request.hpke_key_id, 16);
  from64(request.hpke_public_key, 32);
  from64(request.authorization_public_key, 32);
  if (grant.enrolled_epoch > head.epoch) deny();
  const signatureInput = Buffer.concat([Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
    Buffer.from(JSON.stringify(Object.fromEntries(GRANT.map((k) => [k, grant[k]]))))]);
  if (!crypto.verify(null, signatureInput, owner, from64(grant.signature, 64))) deny();
  const expectedScope = Object.fromEntries(SCOPE.map((k) => [k, Buffer.from(grant[k], "base64url")]));
  const receipt = commitment.verifySignedReceipt({
    receipt: a.committedReceipt, signerPublicKey: witness,
    independentSignerSpkiSha256: b64(raw(a.independentWitnessSpkiSha256, 32)),
    expectedScope, expectedHead: head,
    nowSeconds, previousReceipt: a.previousReceipt,
  });
  if (receipt.sequence < minimumSequence) deny();
  const signedReceiptBytes = Buffer.concat([
    commitment.commitmentSigningBytes(Object.fromEntries(commitment.FIELDS.map(
      (k) => [k, a.committedReceipt[k]]))), from64(a.committedReceipt.signature, 64)]);
  return { grant, request, head, scope: expectedScope, sequence: receipt.sequence,
    receiptDigest: sha(signedReceiptBytes), grantDigest: sha(signatureInput),
    expiresAt: Math.min(a.committedReceipt.expires_at, nowSeconds + 300) };
}
async function binding({ metadata, revision, ciphertext, ciphertextRoot, authority }) {
  const meta = metadataCopy(metadata);
  positive(revision);
  const data = Buffer.from(ciphertext);
  if (!data.length || data.length > 4 * 1024 * 1024) deny();
  const pin = raw(ciphertextRoot, 32);
  if (!compare(Buffer.from(await roots.computeCiphertextRoot([data])), pin)) deny();
  for (const name of SCOPE) if (!compare(Buffer.from(meta[name], "base64url"),
    authority.scope[name])) deny();
  if (meta.epoch > authority.head.epoch) deny();
  return { ...meta, object_revision: revision,
    device_id: authority.request.device_id,
    authorization_key_id: authority.request.authorization_key_id,
    hpke_key_id: authority.request.hpke_key_id,
    hpke_public_key: authority.request.hpke_public_key,
    owner_revision: authority.head.revision,
    owner_digest: b64(authority.head.digest),
    owner_epoch: authority.head.epoch,
    witness_sequence: authority.sequence,
    witness_receipt_sha256: b64(authority.receiptDigest),
    signed_grant_sha256: b64(authority.grantDigest),
    ciphertext_root: b64(pin),
    ciphertext_sha256: b64(sha(data)) };
}
async function sealOwnerAuthorizedFileCek(input) {
  let cek, checked, stable;
  try {
    stable = snapshotFields(input);
    exact(stable, ["ownerPrivateKey", "ownerHeldCek", "metadata",
      "objectRevision", "ciphertext", "ciphertextRoot", "authority"]);
    const a = stable.authority;
    const owner = crypto.createPublicKey(stable.ownerPrivateKey);
    const witness = toNodePub(a.witnessPublicKey);
    const trusted = await normalizedAuthority(a, a.operatorMinimumSequence,
      a.nowSeconds, { owner, witness });
    const ownerApprovedHpkePublicKey = await verifyOwnerApprovedHpkeRecipient(
      a, trusted, owner, a.nowSeconds);
    cek = Buffer.from(raw(stable.ownerHeldCek, 32));
    // Possession of arbitrary 32 bytes is not proof of owning this particular
    // file's CEK. The authorizing owner must demonstrate an AEAD open of the
    // exact pinned ciphertext before exporting a recipient-specific envelope.
    checked = await fileContent.decryptFile({
      cek: await fileContent.importFileCek(cek),
      metadata: stable.metadata, envelopeBytes: stable.ciphertext });
    const core = { schema: FORMAT, ...await binding({
      metadata: stable.metadata, revision: stable.objectRevision,
      ciphertext: stable.ciphertext, ciphertextRoot: stable.ciphertextRoot, authority: trusted }),
      nonce: b64(crypto.randomBytes(16)), expires_at: trusted.expiresAt };
    exact(core, CORE);
    if (!compare(from64(core.hpke_public_key, 32), ownerApprovedHpkePublicKey)) deny();
    const context = Buffer.from(await z.encodeDeterministic(core));
    const recipient = await z.hpkeSuite().kem.deserializePublicKey(
      ownerApprovedHpkePublicKey);
    const sealed = await z.hpkeSeal({ recipientPublicKey: recipient, plaintext: cek,
      info: Buffer.concat([INFO, context]), aad: Buffer.concat([AAD, context]) });
    const message = Buffer.concat([DOMAIN, await z.encodeDeterministic({
      core, enc: sealed.enc, ciphertext: sealed.ciphertext })]);
    return Object.freeze({ schema: FORMAT, core, enc: b64(sealed.enc),
      ciphertext: b64(sealed.ciphertext),
      owner_signature: b64(crypto.sign(null, message, stable.ownerPrivateKey)),
      authorizesProductionRestore: false, externalCustodyProven: false });
  } catch (_) { deny(); }
  finally { checked?.data?.fill(0); cek?.fill(0); stable?.ownerHeldCek?.fill(0); }
}
async function openOwnerAuthorizedFileCek(input) {
  let cek, stable;
  try {
    stable = snapshotFields(input);
    exact(stable, ["envelope", "authority", "operatorMinimumSequence", "metadata",
      "objectRevision", "ciphertext", "ciphertextRoot", "deviceHpkePrivateKey",
      "nowSeconds"]);
    const { envelope: wire, authority: a } = stable;
    exact(wire, ["schema", "core", "enc", "ciphertext", "owner_signature",
      "authorizesProductionRestore", "externalCustodyProven"]);
    if (wire.schema !== FORMAT || wire.authorizesProductionRestore !== false
      || wire.externalCustodyProven !== false) deny();
    const approved = await committedApproval.verifyCommittedApproval({
      ...a, nowSeconds: stable.nowSeconds });
    if (approved.committedOwnerApprovalVerified !== true
      || approved.authorizesProductionIo !== false) deny();
    const owner = crypto.createPublicKey({ key: Buffer.from(
      await crypto.webcrypto.subtle.exportKey("spki", a.ownerPublicKey)),
      format: "der", type: "spki" });
    const witness = crypto.createPublicKey({ key: Buffer.from(
      await crypto.webcrypto.subtle.exportKey("spki", a.witnessPublicKey)),
      format: "der", type: "spki" });
    const trusted = await normalizedAuthority(a, stable.operatorMinimumSequence,
      stable.nowSeconds, { owner, witness });
    const core = wire.core;
    exact(core, CORE);
    if (core.schema !== FORMAT || !Number.isSafeInteger(core.expires_at)
      || core.expires_at < stable.nowSeconds) deny();
    const expected = await binding({
      metadata: stable.metadata, revision: stable.objectRevision,
      ciphertext: stable.ciphertext, ciphertextRoot: stable.ciphertextRoot, authority: trusted });
    for (const [key, value] of Object.entries(expected))
      if (core[key] !== value) deny();
    from64(core.nonce, 16);
    const context = Buffer.from(await z.encodeDeterministic(core));
    const enc = from64(wire.enc, 32);
    const ciphertext = from64(wire.ciphertext, 48);
    const signed = Buffer.concat([DOMAIN, await z.encodeDeterministic({ core, enc, ciphertext })]);
    if (!crypto.verify(null, signed, owner, from64(wire.owner_signature, 64))) deny();
    if (!(stable.deviceHpkePrivateKey?.hpkePrivateRaw instanceof Uint8Array)
      || stable.deviceHpkePrivateKey.hpkePrivateRaw.length !== 32) deny();
    const deviceHpkeKey = await z.hpkeSuite().kem.deserializePrivateKey(
      stable.deviceHpkePrivateKey.hpkePrivateRaw);
    cek = Buffer.from(await z.hpkeOpen({ recipientKey: deviceHpkeKey,
      enc, ciphertext, info: Buffer.concat([INFO, context]),
      aad: Buffer.concat([AAD, context]) }));
    if (cek.length !== 32) deny();
    return Object.freeze({ cek: Buffer.from(cek), authorizesProductionRestore: false,
      externalCustodyProven: false });
  } catch (_) { deny(); }
  finally { cek?.fill(0); stable?.deviceHpkePrivateKey?.hpkePrivateRaw?.fill(0); }
}
module.exports = { sealOwnerAuthorizedFileCek, openOwnerAuthorizedFileCek };
