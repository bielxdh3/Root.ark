"use strict";
// Offline owner-attested account roster: prevents omission from an
// independently pinned roster but does not discover unknown keyrings.
const crypto = require("node:crypto");
const protectedInventory = require("./rootark-zk1-authoritative-backup-inventory");
const FORMAT = "rootark-zk1-owner-account-backup-roster/v1";
const DOMAIN = Buffer.from("Root.ark/zk-1/owner-account-backup-roster/v1\0");
const FIELDS = ["format", "accountId", "issuedAt", "keyringCount", "keyrings"];
const OUTER = [...FIELDS, "signature"];
const ENTRY = ["scope", "snapshotSha256", "inventoryCheckpointDigest",
  "inventoryRoot", "inventorySequence"];
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
function deny() { throw new Error("ZK_ACCOUNT_BACKUP_ROSTER_DENIED"); }
function exact(input, fields) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
    || Reflect.ownKeys(input).length !== fields.length) deny();
  const copy = {};
  for (const name of fields) {
    const desc = Object.getOwnPropertyDescriptor(input, name);
    if (!desc || !Object.hasOwn(desc, "value")) deny();
    copy[name] = desc.value;
  }
  return copy;
}
function b64(raw, length) {
  if (typeof raw !== "string" || !/^[A-Za-z0-9_-]+$/.test(raw)) deny();
  const v = Buffer.from(raw, "base64url");
  if (v.length !== length || v.toString("base64url") !== raw) deny();
  return raw;
}
function hex(raw) {
  if (typeof raw !== "string" || !/^[0-9a-f]{64}$/.test(raw)) deny();
  return raw;
}
function digest(raw) { return crypto.createHash("sha256").update(raw).digest(); }
function rawBytes(value) {
  if (!(value instanceof Uint8Array) || value.length !== 32) deny();
  return Buffer.from(value);
}
function owner(value, type) {
  if (value?.type !== type || value.algorithm?.name !== "Ed25519"
    || !value.usages?.includes(type === "public" ? "verify" : "sign")
    || (type === "private" && value.extractable !== false)) deny();
  return value;
}
function validatedProofs(proofs, accountId, ownerSpkiSha256) {
  if (!Array.isArray(proofs) || proofs.length < 1 || proofs.length > 8
    || Reflect.ownKeys(proofs).length !== proofs.length + 1) deny();
  const result = [];
  for (let i = 0; i < proofs.length; i++) {
    const desc = Object.getOwnPropertyDescriptor(proofs, String(i));
    if (!desc || !Object.hasOwn(desc, "value")) deny();
    const proof = protectedInventory.readVerifiedBackupProof(desc.value);
    const scope = exact(proof.scope, SCOPE);
    if (scope.account_id !== accountId || proof.ownerSpkiSha256 !== ownerSpkiSha256) deny();
    b64(scope.account_id, 16); b64(scope.keyring_id, 16);
    const compartment = Buffer.from(scope.compartment_id, "base64url");
    if (compartment.length < 1 || compartment.length > 128) deny();
    b64(scope.compartment_id, compartment.length);
    b64(proof.snapshotSha256, 32);
    hex(proof.inventoryCheckpointDigest); hex(proof.inventoryRoot);
    if (!Number.isSafeInteger(proof.inventorySequence) || proof.inventorySequence < 0) deny();
    result.push({ scope, snapshotSha256: proof.snapshotSha256,
      inventoryCheckpointDigest: proof.inventoryCheckpointDigest,
      inventoryRoot: proof.inventoryRoot, inventorySequence: proof.inventorySequence });
  }
  result.sort((a, b) => {
    const left = a.scope.compartment_id + ":" + a.scope.keyring_id;
    const right = b.scope.compartment_id + ":" + b.scope.keyring_id;
    return left < right ? -1 : left > right ? 1 : 0;
  });
  const seen = new Set();
  for (const item of result) {
    if (seen.has(item.scope.keyring_id)) deny();
    seen.add(item.scope.keyring_id);
  }
  return result;
}
function signedBytes(body) {
  const packed = Buffer.from(JSON.stringify(exact(body, FIELDS)));
  if (packed.length > 20000) deny();
  return Buffer.concat([DOMAIN, packed]);
}
async function verifyOwnerKey(ownerPublicKey, pin) {
  const pub = owner(ownerPublicKey, "public");
  const actual = digest(Buffer.from(await crypto.webcrypto.subtle.exportKey("spki", pub)));
  if (!crypto.timingSafeEqual(actual, rawBytes(pin))) deny();
  return pub;
}
async function createOwnerRoster(input) {
  try {
    const raw = exact(input, ["ownerPublicKey", "ownerSigningKey",
      "independentOwnerSpkiSha256", "accountId", "verifiedKeyringProofs", "issuedAt"]);
    b64(raw.accountId, 16);
    const entries = validatedProofs(raw.verifiedKeyringProofs, raw.accountId,
      rawBytes(raw.independentOwnerSpkiSha256).toString("hex"));
    const signer = owner(raw.ownerSigningKey, "private");
    const pub = await verifyOwnerKey(raw.ownerPublicKey, raw.independentOwnerSpkiSha256);
    if (!Number.isSafeInteger(raw.issuedAt) || raw.issuedAt < 1) deny();
    const unsigned = { format: FORMAT, accountId: raw.accountId,
      issuedAt: raw.issuedAt, keyringCount: entries.length, keyrings: entries };
    const signed = signedBytes(unsigned);
    const signature = Buffer.from(await crypto.webcrypto.subtle.sign("Ed25519", signer, signed));
    if (!await crypto.webcrypto.subtle.verify("Ed25519", pub, signature, signed)) deny();
    const roster = Object.freeze({ ...unsigned, signature: signature.toString("base64url") });
    return Object.freeze({ roster, rosterSha256: digest(Buffer.from(JSON.stringify(roster))),
      requiresIndependentOwnerRosterPin: true, ownerDeclaredKeyringCount: entries.length,
      globalAccountCompletenessProven: false });
  } catch (_) { deny(); }
}
async function verifyOwnerRosterCoverage(input) {
  try {
    const raw = exact(input, ["roster", "independentlyPinnedRosterSha256",
      "ownerPublicKey", "independentOwnerSpkiSha256", "accountId", "verifiedKeyringProofs"]);
    const wire = exact(raw.roster, OUTER);
    const canonical = JSON.stringify(wire);
    if (typeof canonical !== "string" || canonical.length > 20000
      || !crypto.timingSafeEqual(digest(Buffer.from(canonical)),
        rawBytes(raw.independentlyPinnedRosterSha256))) deny();
    const stable = exact(JSON.parse(canonical), OUTER);
    b64(raw.accountId, 16);
    if (stable.format !== FORMAT || stable.accountId !== raw.accountId
      || !Number.isSafeInteger(stable.issuedAt) || stable.issuedAt < 1) deny();
    const pub = await verifyOwnerKey(raw.ownerPublicKey, raw.independentOwnerSpkiSha256);
    const signature = Buffer.from(b64(stable.signature, 64), "base64url");
    if (!await crypto.webcrypto.subtle.verify("Ed25519", pub, signature,
      signedBytes(Object.fromEntries(FIELDS.map((name) => [name, stable[name]]))))) deny();
    const checked = validatedProofs(raw.verifiedKeyringProofs, raw.accountId,
      rawBytes(raw.independentOwnerSpkiSha256).toString("hex"));
    if (!Array.isArray(stable.keyrings)
      || stable.keyringCount !== checked.length || stable.keyringCount !== stable.keyrings.length
      || JSON.stringify(checked) !== JSON.stringify(stable.keyrings)) deny();
    for (const item of stable.keyrings) {
      exact(item, ENTRY);
      exact(item.scope, SCOPE);
    }
    return Object.freeze({ allOwnerRosterKeyringsVerified: true,
      keyringCount: checked.length, globalAccountCompletenessProven: false,
      accountWideCekRecoveryProven: false, authorizesProductionRestore: false });
  } catch (_) { deny(); }
}
module.exports = Object.freeze({ createOwnerRoster, verifyOwnerRosterCoverage });
