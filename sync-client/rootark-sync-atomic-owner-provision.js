"use strict";

// DEV-OFF: authenticate the immutable owner/account/store mapping before a
// physical witness and a separate CAS floor are allowed to ACK an atomic pair.
// The signing root MUST be pinned by the embedding process, never by sync JSON.
const crypto = require("node:crypto");
const protocol = require("./rootark-sync-protocol");

const DOMAIN = "Root.ark/sync-v2/atomic-owner-provisioning/v1\0";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SCOPE = /^[A-Za-z0-9._:-]{1,256}$/;
const deny = () => Object.assign(new Error("Atomic batch owner provision is not independently authenticated"),
  { code: "authorization_required" });
const exactKeys = (value, keys) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && actual.every((key) =>
    typeof key === "string" && keys.includes(key));
};

function pinnedProvisionerKey(input) {
  try {
    let key;
    if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
      key = crypto.createPublicKey({ key: Buffer.from(input), format: "der", type: "spki" });
    } else if (typeof input === "string") {
      if (!/^[A-Za-z0-9_-]{40,512}$/.test(input)) throw deny();
      const bytes = Buffer.from(input, "base64url");
      if (bytes.toString("base64url") !== input) throw deny();
      key = crypto.createPublicKey({ key: bytes, format: "der", type: "spki" });
    } else if (input instanceof crypto.KeyObject && input.type === "public") {
      key = input;
    } else throw deny();
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw deny();
    return key;
  } catch { throw deny(); }
}

function verifyPinnedAtomicOwnerProvision({ identity, scope, provisionerPublicKey,
  provisioning, expectedDigest, witnessPublicKey, casPublicKey }) {
  // Detach all callback-owned certificate data exactly once; comparison and
  // Ed25519 verification must see identical canonical bytes, never getters.
  let detached;
  try { detached = JSON.parse(protocol.canonicalJson(provisioning)); }
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
  if (statement.witnessSpki !== witness.export({ type: "spki", format: "der" }).toString("base64url")
    || statement.casSpki !== cas.export({ type: "spki", format: "der" }).toString("base64url")) throw deny();
  const signature = Buffer.from(detached.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== detached.signature) throw deny();
  const pin = pinnedProvisionerKey(provisionerPublicKey);
  if ([witness, cas].some((other) => other.export({ type: "spki", format: "der" }).equals(
    pin.export({ type: "spki", format: "der" })))) throw deny();
  if (!crypto.verify(null, Buffer.from(DOMAIN + protocol.canonicalJson(statement), "utf8"),
    pin, signature)) throw deny();
  // A signature by itself is REPLAYABLE. The trusted embedding must retain
  // the CURRENT certificate digest outside mutable sync config, server and
  // journal; an older but correctly signed certificate must fail closed.
  const digest = crypto.createHash("sha256")
    .update(DOMAIN + protocol.canonicalJson(detached), "utf8").digest("hex");
  if (digest !== expectedDigest) throw deny();
  return Object.freeze({ identity: Object.freeze({
    accountId: statement.accountId, storeId: statement.storeId,
    username: statement.username, compartmentId: statement.compartmentId,
  }), publicKey: pin, provisioning: Object.freeze({
    statement: Object.freeze(statement), signature: detached.signature,
  }) });
}

module.exports = { DOMAIN, verifyPinnedAtomicOwnerProvision };
