"use strict";

// Fail-closed OPERATOR PROVISIONING reference. Only a separate administrator
// can vouch for each provider's configured principal and namespace. A signed
// statement cannot prove separate physical custody or cloud durability.
const crypto = require("node:crypto");
const { nativeEd25519Spki } = require("../crypto/rootark-zk1-native-ed25519-public-key");

const DOMAIN = Buffer.from("Root.ark/zk-1/provider-domain-attestation/v1\0", "ascii");
const SCHEMA = "rootark-zk1-provider-domain-attestation/v1";
const FIELDS = Object.freeze(["schema", "provider", "trust_domain_id", "namespace_sha256",
  "principal_context_sha256", "drive_file_id", "account_id", "compartment_id",
  "keyring_id", "issued_at", "expires_at"]);
const HEX = /^[0-9a-f]{64}$/;
const PROVIDERS = ["s3", "gdrive", "webdav"];

function deny() { throw new Error("ZK_PROVIDER_DOMAIN_UNVERIFIED"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) deny();
  return Object.fromEntries(fields.map((field) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
    return [field, descriptor.value];
  }));
}
function hex(value) { if (typeof value !== "string" || !HEX.test(value)) deny(); return value; }
function integer(value, min) { if (!Number.isSafeInteger(value) || value < min) deny(); return value; }
function wireId(value, min, max = min) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) deny();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < min || bytes.length > max || bytes.toString("base64url") !== value) deny();
  return value;
}
function key(value, kind) {
  if (!(value instanceof crypto.KeyObject) || value.type !== kind
    || value.asymmetricKeyType !== "ed25519") deny();
  return value;
}
function spkiFingerprint(publicKey) {
  return crypto.createHash("sha256").update(nativeEd25519Spki(
    key(publicKey, "public"))).digest("hex");
}
function normalize(scope) {
  if (!scope || typeof scope !== "object") deny();
  const value = exact(scope, ["account_id", "compartment_id", "keyring_id"]);
  return Object.fromEntries(Object.entries(value).map(([name, input]) => {
    const bytes = Buffer.isBuffer(input) || input instanceof Uint8Array
      ? Buffer.from(input) : Buffer.from(wireId(input, name === "compartment_id" ? 1 : 16,
        name === "compartment_id" ? 128 : 16), "base64url");
    if (bytes.length < (name === "compartment_id" ? 1 : 16)
      || bytes.length > (name === "compartment_id" ? 128 : 16)) deny();
    return [name, bytes.toString("base64url")];
  }));
}
function statement(value) {
  const s = exact(value, FIELDS);
  if (s.schema !== SCHEMA || !PROVIDERS.includes(s.provider)) deny();
  for (const name of ["trust_domain_id", "namespace_sha256", "principal_context_sha256"])
    hex(s[name]);
  wireId(s.account_id, 16); wireId(s.compartment_id, 1, 128); wireId(s.keyring_id, 16);
  if (s.provider === "gdrive"
    ? typeof s.drive_file_id !== "string" || !/^[A-Za-z0-9_-]{1,256}$/.test(s.drive_file_id)
    : s.drive_file_id !== null) deny();
  integer(s.issued_at, 1);
  integer(s.expires_at, s.issued_at + 1);
  if (s.expires_at - s.issued_at > 7 * 86400) deny();
  return s;
}
function signingBytes(value) {
  return Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(statement(value)), "utf8")]);
}
function signProviderDomainAttestation({ statement: input, administratorPrivateKey } = {}) {
  const signature = crypto.sign(null, signingBytes(input), key(administratorPrivateKey, "private"));
  return Object.freeze({ ...statement(input), signature: signature.toString("base64url") });
}

class Zk1ExternallyPinnedProviderDomains {
  #roots;
  constructor({ externallyPinnedDomains } = {}) {
    if (!Array.isArray(externallyPinnedDomains) || externallyPinnedDomains.length < 2
      || externallyPinnedDomains.length > 3
      || Reflect.ownKeys(externallyPinnedDomains).length !== externallyPinnedDomains.length + 1) deny();
    const roots = new Map();
    const administrators = new Set();
    const spkis = new Set();
    for (const entry of externallyPinnedDomains) {
      const v = exact(entry, ["provider", "trustDomainId", "administratorPublicKey",
        "independentAdministratorSpkiSha256"]);
      if (!PROVIDERS.includes(v.provider) || roots.has(v.provider)) deny();
      const admin = hex(v.trustDomainId);
      const fp = spkiFingerprint(v.administratorPublicKey);
      if (fp !== hex(v.independentAdministratorSpkiSha256)
        || administrators.has(admin) || spkis.has(fp)) deny();
      administrators.add(admin);
      spkis.add(fp);
      roots.set(v.provider, Object.freeze({ admin, fp, publicKey: v.administratorPublicKey }));
    }
    this.#roots = roots;
    Object.freeze(this);
  }
  verify({ targets, scope, nowSeconds } = {}) {
    if (!Array.isArray(targets) || targets.length < 2 || targets.length > 3
      || Reflect.ownKeys(targets).length !== targets.length + 1) deny();
    const expectedScope = normalize(scope);
    const now = integer(nowSeconds, 1);
    const seenProviders = new Set();
    const seenAdmins = new Set();
    const seenContexts = new Set();
    for (const target of targets) {
      const v = exact(target, ["provider", "namespaceIdentity", "expectedReaderContext",
        "pinnedDriveFileId", "domainAttestation"]);
      const root = this.#roots.get(v.provider);
      if (!root || seenProviders.has(v.provider) || seenAdmins.has(root.admin)) deny();
      const record = exact(v.domainAttestation, [...FIELDS, "signature"]);
      const claim = statement(Object.fromEntries(FIELDS.map((name) => [name, record[name]])));
      const signed = Buffer.from(wireId(record.signature, 64), "base64url");
      if (!crypto.verify(null, signingBytes(claim), root.publicKey, signed)
        || claim.provider !== v.provider || claim.trust_domain_id !== root.admin
        || claim.namespace_sha256 !== hex(v.namespaceIdentity)
        || claim.principal_context_sha256 !== hex(v.expectedReaderContext)
        || claim.drive_file_id !== v.pinnedDriveFileId
        || claim.account_id !== expectedScope.account_id
        || claim.compartment_id !== expectedScope.compartment_id
        || claim.keyring_id !== expectedScope.keyring_id
        || now < claim.issued_at || now > claim.expires_at) deny();
      // Two differently branded SDKs configured for one identical principal
      // are not two independent custody domains even with valid signatures.
      if (seenContexts.has(claim.principal_context_sha256)) deny();
      seenProviders.add(v.provider);
      seenAdmins.add(root.admin);
      seenContexts.add(claim.principal_context_sha256);
    }
    return Object.freeze({ signedDomainsVerified: targets.length,
      suppliedSpkiPinsMatched: true, independentPinCustodyProven: false,
      physicalIndependenceProven: false,
      remoteDurabilityProven: false, authorizesIo: false });
  }
}

module.exports = { SCHEMA, FIELDS, spkiFingerprint, normalize,
  signProviderDomainAttestation, Zk1ExternallyPinnedProviderDomains };
