"use strict";

// DEV-OFF: authenticate the immutable owner/account/store mapping before a
// physical witness and a separate CAS floor are allowed to ACK an atomic pair.
// The signing root MUST be pinned by the embedding process, never by sync JSON.
const crypto = require("node:crypto");
const { types: { isProxy } } = require("node:util");
const {
  createPublicKey: NATIVE_CREATE_PUBLIC_KEY,
  verify: NATIVE_VERIFY,
  createHash: NATIVE_CREATE_HASH,
  hashUpdate: NATIVE_HASH_UPDATE,
  hashDigest: NATIVE_HASH_DIGEST,
  keyType: NATIVE_TYPE,
  keyAlgorithm: NATIVE_ALGORITHM,
  publicExport: NATIVE_EXPORT,
  keyEquals: NATIVE_EQUALS,
  bufferFrom: NATIVE_BUFFER_FROM,
  bufferToString: NATIVE_BUFFER_TO_STRING,
  canonicalSortedJson: NATIVE_CANONICAL_SORTED_JSON,
  freeze: NATIVE_FREEZE,
  arrayIsArray: NATIVE_ARRAY_IS_ARRAY,
  ownKeys: NATIVE_OWN_KEYS,
  jsonParse: NATIVE_JSON_PARSE,
} = require("../src/crypto/rootark-zk10-native-intrinsics-v1");

// Verify native public-key identity, never caller-shadowable instance fields.
// Reimport each pin so later instance method mutation cannot change readback.

const DOMAIN = "Root.ark/sync-v2/atomic-owner-provisioning/v1\0";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SCOPE = /^[A-Za-z0-9._:-]{1,256}$/;
const deny = () => Object.assign(new Error("Atomic batch owner provision is not independently authenticated"),
  { code: "authorization_required" });
const exactKeys = (value, keys) => {
  if (!value || typeof value !== "object" || NATIVE_ARRAY_IS_ARRAY(value)) return false;
  const actual = NATIVE_OWN_KEYS(value);
  return actual.length === keys.length && actual.every((key) =>
    typeof key === "string" && keys.includes(key));
};

function pinnedProvisionerKey(input) {
  try {
    if (isProxy(input)) throw deny();
    let der;
    if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
      der = NATIVE_BUFFER_FROM(input);
    } else if (typeof input === "string") {
      if (!/^[A-Za-z0-9_-]{40,512}$/.test(input)) throw deny();
      der = NATIVE_BUFFER_FROM(input, "base64url");
      if (NATIVE_BUFFER_TO_STRING.call(der, "base64url") !== input) throw deny();
    } else if (input instanceof crypto.KeyObject) {
      if (NATIVE_TYPE.call(input) !== "public"
        || NATIVE_ALGORITHM.call(input) !== "ed25519") throw deny();
      der = NATIVE_EXPORT.call(input, { type: "spki", format: "der" });
    } else throw deny();
    const key = NATIVE_CREATE_PUBLIC_KEY({ key: der, format: "der", type: "spki" });
    if (NATIVE_TYPE.call(key) !== "public"
      || NATIVE_ALGORITHM.call(key) !== "ed25519") throw deny();
    return key;
  } catch { throw deny(); }
}

function verifyPinnedAtomicOwnerProvision({ identity, scope, provisionerPublicKey,
  provisioning, expectedDigest, witnessPublicKey, casPublicKey }) {
  // Detach all callback-owned certificate data exactly once; comparison and
  // Ed25519 verification must see identical canonical bytes, never getters.
  let detached;
  try { detached = NATIVE_JSON_PARSE(NATIVE_CANONICAL_SORTED_JSON(provisioning)); }
  catch { throw deny(); }
  if (!exactKeys(identity, ["accountId", "storeId", "username", "compartmentId"])
    || !exactKeys(detached, ["statement", "signature"])
    || !exactKeys(detached.statement,
      ["type", "version", "scope", "accountId", "storeId", "username",
        "compartmentId", "witnessSpki", "casSpki", "sequence"])) throw deny();
  const statement = detached.statement;
  if (statement.type !== "atomic-owner-provisioning" || statement.version !== 1
    || !Number.isSafeInteger(statement.sequence) || statement.sequence < 1
    || typeof scope !== "string" || !SCOPE.test(scope)
    || statement.scope !== scope
    || !UUID.test(statement.accountId) || !UUID.test(statement.storeId)
    || typeof statement.username !== "string" || !statement.username || statement.username.length > 512
    || typeof statement.compartmentId !== "string"
    || !statement.compartmentId || statement.compartmentId.length > 512
    || ["accountId", "storeId", "username", "compartmentId"]
      .some((field) => statement[field] !== identity[field])
    || typeof statement.witnessSpki !== "string"
    || typeof statement.casSpki !== "string"
    || !/^[a-f0-9]{64}$/.test(expectedDigest)
    || typeof detached.signature !== "string"
    || !/^[A-Za-z0-9_-]{86}$/.test(detached.signature)) throw deny();
  let witness, cas;
  try {
    witness = pinnedProvisionerKey(witnessPublicKey);
    cas = pinnedProvisionerKey(casPublicKey);
  } catch { throw deny(); }
  if (statement.witnessSpki !== NATIVE_BUFFER_TO_STRING.call(
    NATIVE_EXPORT.call(witness, { type: "spki", format: "der" }), "base64url")
    || statement.casSpki !== NATIVE_BUFFER_TO_STRING.call(
      NATIVE_EXPORT.call(cas, { type: "spki", format: "der" }), "base64url")) throw deny();
  const signature = NATIVE_BUFFER_FROM(detached.signature, "base64url");
  if (signature.length !== 64 || NATIVE_BUFFER_TO_STRING.call(signature, "base64url") !== detached.signature) throw deny();
  const pin = pinnedProvisionerKey(provisionerPublicKey);
  // All THREE separately administered principals must be physically distinct.
  if (NATIVE_EQUALS.call(witness, cas) || NATIVE_EQUALS.call(witness, pin)
    || NATIVE_EQUALS.call(cas, pin)) throw deny();
  if (!NATIVE_VERIFY(null, NATIVE_BUFFER_FROM(DOMAIN + NATIVE_CANONICAL_SORTED_JSON(statement), "utf8"),
    pin, signature)) throw deny();
  // A signature by itself is REPLAYABLE. The trusted embedding must retain
  // the CURRENT certificate digest outside mutable sync config, server and
  // journal; an older but correctly signed certificate must fail closed.
  const hash = NATIVE_CREATE_HASH("sha256");
  NATIVE_HASH_UPDATE.call(hash, DOMAIN + NATIVE_CANONICAL_SORTED_JSON(detached), "utf8");
  const digest = NATIVE_HASH_DIGEST.call(hash, "hex");
  if (digest !== expectedDigest) throw deny();
  // Expose the SAME newly-imported native signer identities used for the
  // signed provisioning check. Consumers must never revisit a caller-owned
  // KeyObject after this verification (its inherited kHandle can change).
  return NATIVE_FREEZE({ identity: NATIVE_FREEZE({
    accountId: statement.accountId, storeId: statement.storeId,
    username: statement.username, compartmentId: statement.compartmentId,
  }), publicKey: pin, witnessPublicKey: witness, casPublicKey: cas,
  provisioning: NATIVE_FREEZE({
    statement: NATIVE_FREEZE(statement), signature: detached.signature,
  }) });
}

module.exports = { DOMAIN, verifyPinnedAtomicOwnerProvision };
