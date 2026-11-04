"use strict";

// DEV-OFF. Verify independently provisionable, signed CURRENT claims against
// an independently retained corpus floor. This module never obtains a floor,
// determines who operates a witness, or authorizes any read/restore/egress.
// In particular, two keys controlled by the same person are NOT two
// independent witnesses. Only external provisioning can establish custody.
const crypto = require("node:crypto");
const NATIVE_VERIFY = crypto.verify;
const NATIVE_SIGN = crypto.sign;
const NATIVE_KEY_EQUALS = crypto.KeyObject.prototype.equals;
const NATIVE_PUBLIC_EXPORT = Object.getPrototypeOf(
  crypto.generateKeyPairSync("ed25519").publicKey).export;
const DOMAIN = Buffer.from("Root.ark/zk15/external-corpus-current/v1\0", "ascii");
const FIELDS = Object.freeze([
  "type", "witness_id", "account_id", "owner_generation_id",
  "owner_spki_sha256", "sequence", "corpus_sha256", "previous_corpus_sha256",
  "request_nonce", "issued_at", "expires_at",
]);
const INPUT = Object.freeze([
  "witnessPins", "statements", "independentlyRetainedFloor",
  "independentlyExpectedAccountId", "independentlyExpectedOwnerGenerationId",
  "independentlyExpectedOwnerSpkiSha256", "requestNonce", "nowSeconds",
]);
const FLOOR = Object.freeze([
  "accountId", "ownerGenerationId", "ownerSpkiSha256",
  "sequence", "corpusSha256", "previousCorpusSha256",
]);
const PIN = Object.freeze(["witnessId", "publicKey"]);
const WITNESS = /^[a-z][a-z0-9_-]{0,31}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
function deny() {
  const error = new Error("ZK15_EXTERNAL_CORPUS_CURRENT_UNVERIFIED");
  error.code = error.message;
  throw error;
}
function exact(input, keys) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) deny();
  const own = Reflect.ownKeys(input);
  if (own.length !== keys.length) deny();
  const data = Object.create(null);
  for (const name of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, "value")
      || descriptor.enumerable !== true) deny();
    data[name] = descriptor.value;
  }
  return data;
}
function fixedArray(input, length) {
  if (!Array.isArray(input) || input.length !== length
    || Reflect.ownKeys(input).length !== length + 1) deny();
  const copied = [];
  for (let i = 0; i < length; i += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(i));
    if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
    copied.push(descriptor.value);
  }
  return copied;
}
function encoded(value, byteLength) {
  if (typeof value !== "string" || !BASE64URL.test(value)) deny();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== byteLength || bytes.toString("base64url") !== value) deny();
  return value;
}
function positiveInt(value) {
  if (!Number.isSafeInteger(value) || value < 1) deny();
  return value;
}
function witnessId(value) {
  if (typeof value !== "string" || !WITNESS.test(value)) deny();
  return value;
}
function key(value, type) {
  if (!(value instanceof crypto.KeyObject) || value.type !== type
    || value.asymmetricKeyType !== "ed25519") deny();
  return value;
}
function fingerprint(publicKey) {
  // The native KeyObject export resists an attacker-defined .export override.
  const der = NATIVE_PUBLIC_EXPORT.call(key(publicKey, "public"),
    { type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("base64url");
}
function canonical(input) {
  const body = exact(input, FIELDS);
  if (body.type !== "rootark-zk15-external-corpus-current/v1") deny();
  witnessId(body.witness_id);
  encoded(body.account_id, 16);
  encoded(body.owner_generation_id, 16);
  encoded(body.owner_spki_sha256, 32);
  encoded(body.corpus_sha256, 32);
  if (body.previous_corpus_sha256 === null) {
    if (body.sequence !== 1) deny();
  } else encoded(body.previous_corpus_sha256, 32);
  encoded(body.request_nonce, 32);
  positiveInt(body.sequence);
  positiveInt(body.issued_at);
  positiveInt(body.expires_at);
  if (body.expires_at <= body.issued_at
    || body.expires_at - body.issued_at > 30) deny();
  return Object.fromEntries(FIELDS.map((field) => [field, body[field]]));
}
function signedBytes(body) {
  return Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(body), "utf8")]);
}
// Fixture/provisioner helper only. Signing locally is not evidence of an
// independently operated external witness.
function signExternalCorpusCurrentClaim(payload, privateKey) {
  try {
    const canonicalBody = canonical(payload);
    const signature = NATIVE_SIGN(null, signedBytes(canonicalBody),
      key(privateKey, "private")).toString("base64url");
    return Object.freeze({ ...canonicalBody, signature });
  } catch (_) { deny(); }
}
function currentFloor(input) {
  const floor = exact(input, FLOOR);
  encoded(floor.accountId, 16);
  encoded(floor.ownerGenerationId, 16);
  encoded(floor.ownerSpkiSha256, 32);
  positiveInt(floor.sequence);
  encoded(floor.corpusSha256, 32);
  if (floor.previousCorpusSha256 === null) {
    if (floor.sequence !== 1) deny();
  } else encoded(floor.previousCorpusSha256, 32);
  return floor;
}
function verifyExternalCorpusCurrentQuorum(rawInput) {
  try {
    const input = exact(rawInput, INPUT);
    const accountId = encoded(input.independentlyExpectedAccountId, 16);
    const generationId = encoded(input.independentlyExpectedOwnerGenerationId, 16);
    const ownerPin = encoded(input.independentlyExpectedOwnerSpkiSha256, 32);
    const nonce = encoded(input.requestNonce, 32);
    const now = positiveInt(input.nowSeconds);
    const floor = currentFloor(input.independentlyRetainedFloor);
    if (floor.accountId !== accountId || floor.ownerGenerationId !== generationId
      || floor.ownerSpkiSha256 !== ownerPin) deny();
    const witnessPins = fixedArray(input.witnessPins, 2).map((raw) => exact(raw, PIN));
    const statements = fixedArray(input.statements, 2);
    if (witnessId(witnessPins[0].witnessId) === witnessId(witnessPins[1].witnessId)) deny();
    const keys = witnessPins.map((pin) => key(pin.publicKey, "public"));
    if (NATIVE_KEY_EQUALS.call(keys[0], keys[1])
      || fingerprint(keys[0]) === ownerPin || fingerprint(keys[1]) === ownerPin) deny();
    let shared = null;
    for (let i = 0; i < statements.length; i += 1) {
      const wire = exact(statements[i], [...FIELDS, "signature"]);
      const body = canonical(Object.fromEntries(FIELDS.map((field) => [field, wire[field]])));
      const signature = Buffer.from(encoded(wire.signature, 64), "base64url");
      if (body.witness_id !== witnessPins[i].witnessId
        || body.account_id !== accountId
        || body.owner_generation_id !== generationId
        || body.owner_spki_sha256 !== ownerPin
        || body.request_nonce !== nonce
        || body.issued_at < now - 30 || body.issued_at > now + 2
        || body.expires_at <= now || body.expires_at > now + 30
        || !NATIVE_VERIFY(null, signedBytes(body), keys[i], signature)) deny();
      const agreed = Object.fromEntries(FIELDS
        .filter((field) => field !== "witness_id").map((field) => [field, body[field]]));
      if (shared !== null && JSON.stringify(shared) !== JSON.stringify(agreed)) deny();
      shared = agreed;
    }
    const unchanged = shared.sequence === floor.sequence
      && shared.corpus_sha256 === floor.corpusSha256
      && shared.previous_corpus_sha256 === floor.previousCorpusSha256;
    const successor = shared.sequence === floor.sequence + 1
      && shared.previous_corpus_sha256 === floor.corpusSha256
      && shared.corpus_sha256 !== floor.corpusSha256;
    if (!unchanged && !successor) deny();
    const candidateRetainedFloor = Object.freeze({
      accountId, ownerGenerationId: generationId, ownerSpkiSha256: ownerPin,
      sequence: shared.sequence, corpusSha256: shared.corpus_sha256,
      previousCorpusSha256: shared.previous_corpus_sha256,
    });
    return Object.freeze({
      status: "VERIFIED_EXTERNAL_CORPUS_CURRENT_CLAIM_NONAUTHORIZING",
      sequence: shared.sequence, corpusSha256: shared.corpus_sha256,
      ownerGenerationId: generationId, candidateRetainedFloor,
      authorizesIo: false, independentOffHostCustodyProven: false,
      globalAccountCompletenessProven: false,
      currentnessGuaranteeWithoutExternalCustody: false,
    });
  } catch (_) { deny(); }
}
module.exports = Object.freeze({
  DOMAIN, FIELDS, signExternalCorpusCurrentClaim,
  verifyExternalCorpusCurrentQuorum,
});
