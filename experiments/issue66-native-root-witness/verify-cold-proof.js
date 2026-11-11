"use strict";

// Non-authorizing reference implementation for a FUTURE independently owned
// native RootSession verifier. The witness and current monotonic floor must be
// signed by distinct, separately provisioned external principals. This JS
// verifier cannot establish their custody, inspect native root HANDLEs/FDs,
// prevent local same-UID/SID rollback or authorize a product recovery.
const crypto = require("node:crypto");
const { canonicalJson } = require("../../sync-client/rootark-sync-protocol");

const DOMAIN = "Root.ark/issue66/native-cold-proof/v1/";
const HEX = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SCOPE = /^[A-Za-z0-9._:-]{1,256}$/;
const fail = () => Object.assign(new Error("Independent native cold recovery proof unavailable"),
  { code: "root_session_unverified_authority" });
const exact = (value, keys) => value && typeof value === "object" && !Array.isArray(value)
  && Object.keys(value).length === keys.length
  && Object.keys(value).every((name) => keys.includes(name));

function detach(input, maximum = 8192) {
  // Never recursively stringify an unbounded caller object before applying
  // the budget. Copy only DATA descriptors, with depth/node/byte caps, to a
  // fresh plain object. Accessors must not change signed bytes mid-verification.
  let visited = 0;
  let bytes = 0;
  const ancestors = new WeakSet();
  const copy = (value, depth) => {
    if (++visited > 64 || depth > 7) throw fail();
    if (value === null || typeof value === "boolean") return value;
    if (typeof value === "number" && Number.isSafeInteger(value)) return value;
    if (typeof value === "string") {
      bytes += Buffer.byteLength(value, "utf8");
      if (bytes > maximum) throw fail();
      return value;
    }
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || ancestors.has(value)) throw fail();
    ancestors.add(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length > 32) throw fail();
    const result = Object.create(null);
    for (const key of keys) {
      if (typeof key !== "string" || !Object.hasOwn(descriptors[key], "value")) throw fail();
      bytes += Buffer.byteLength(key, "utf8");
      if (bytes > maximum) throw fail();
      Object.defineProperty(result, key, { value: copy(descriptors[key].value, depth + 1),
        enumerable: true, writable: true, configurable: true });
    }
    ancestors.delete(value);
    return result;
  };
  try {
    const encoded = canonicalJson(copy(input, 0));
    if (Buffer.byteLength(encoded, "utf8") > maximum) throw fail();
    return JSON.parse(encoded);
  } catch { throw fail(); }
}

function pinnedKey(input) {
  try {
    const bytes = typeof input === "string" && /^[A-Za-z0-9_-]{40,512}$/.test(input)
      ? Buffer.from(input, "base64url") : null;
    if (!bytes || bytes.toString("base64url") !== input) throw fail();
    const key = crypto.createPublicKey({ key: bytes, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ed25519") throw fail();
    const canonical = key.export({ format: "der", type: "spki" });
    if (!canonical.equals(bytes)) throw fail();
    return { key, spki: canonical.toString("base64url") };
  } catch { throw fail(); }
}

function verifySigned(domain, signed, pinned, requiredFields) {
  if (!exact(signed, ["statement", "signature"])
    || !exact(signed.statement, requiredFields)
    || typeof signed.signature !== "string"
    || !/^[A-Za-z0-9_-]{86}$/.test(signed.signature)) throw fail();
  const signature = Buffer.from(signed.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== signed.signature
    || !crypto.verify(null,
      Buffer.from(DOMAIN + domain + "\0" + canonicalJson(signed.statement), "utf8"),
      pinned.key, signature)) throw fail();
  return signed.statement;
}

function validBase(s, type, scope, rootDigest, epoch) {
  return s.type === type && s.version === 1 && s.scope === scope
    && s.rootDigest === rootDigest && s.epoch === epoch;
}

async function inspectSignedColdCommit({ scope, expectedOwnerDigest,
  ownerSignerSpki, witnessSignerSpki, floorSignerSpki,
  ownerProvision, currentSignedReadback, readPhysicalNative }) {
  if (typeof scope !== "string" || !SCOPE.test(scope)
    || !HEX.test(expectedOwnerDigest)
    || typeof currentSignedReadback !== "function"
    || typeof readPhysicalNative !== "function") throw fail();
  const owner = pinnedKey(ownerSignerSpki);
  const witness = pinnedKey(witnessSignerSpki);
  const floor = pinnedKey(floorSignerSpki);
  if (new Set([owner.spki, witness.spki, floor.spki]).size !== 3) throw fail();
  const provision = detach(ownerProvision);
  const o = verifySigned("owner", provision, owner,
    ["type", "version", "scope", "rootDigest", "epoch", "initialSequence",
      "witnessSpki", "floorSpki"]);
  if (!validBase(o, "root-owner", scope, o.rootDigest, o.epoch)
    || !HEX.test(o.rootDigest) || !UUID.test(o.epoch)
    || !Number.isSafeInteger(o.initialSequence) || o.initialSequence < 1
    || o.witnessSpki !== witness.spki || o.floorSpki !== floor.spki
    || crypto.createHash("sha256").update(DOMAIN + "provision\0" +
      canonicalJson(provision)).digest("hex") !== expectedOwnerDigest) throw fail();

  // Fresh nonce belongs to THIS verification, not to an untrusted disk
  // checkpoint. A separately signed CURRENT floor must bind that challenge.
  const challenge = crypto.randomBytes(32).toString("hex");
  const [current, observation] = await Promise.all([
    currentSignedReadback(challenge), readPhysicalNative(challenge),
  ]);
  const response = detach(current);
  const physical = detach(observation);
  if (!exact(response, ["witness", "floor"])
    || !exact(physical, ["phase", "rootDigest", "fileId", "prepareDigest", "commitDigest"])) throw fail();
  const w = verifySigned("witness", response.witness, witness,
    ["type", "version", "scope", "rootDigest", "epoch", "sequence", "phase",
      "fileId", "prepareDigest", "commitDigest", "challenge"]);
  const f = verifySigned("floor", response.floor, floor,
    ["type", "version", "scope", "rootDigest", "epoch", "sequence",
      "commitDigest", "challenge"]);
  if (!validBase(w, "root-commit", scope, o.rootDigest, o.epoch)
    || !validBase(f, "root-floor", scope, o.rootDigest, o.epoch)
    || w.challenge !== challenge || f.challenge !== challenge
    || w.phase !== "COMMITTED" || physical.phase !== "COMMITTED"
    || !Number.isSafeInteger(w.sequence) || w.sequence < o.initialSequence
    || f.sequence !== w.sequence
    || !HEX.test(w.prepareDigest) || !HEX.test(w.commitDigest)
    || !HEX.test(w.fileId)
    || w.fileId !== physical.fileId
    || w.prepareDigest !== physical.prepareDigest
    || w.commitDigest !== physical.commitDigest
    || f.commitDigest !== w.commitDigest
    || physical.rootDigest !== o.rootDigest) throw fail();

  // An inspected COMMIT is never an authorization to mutate or cold-replay.
  // Only native privileged custody with independent persistence can grant it.
  return Object.freeze({ status: "LAB_COLD_COMMIT_OBSERVED", sequence: w.sequence,
    authorizesIo: false, authorizesReplay: false, rootSessionAvailable: false });
}

module.exports = { DOMAIN, inspectSignedColdCommit };
