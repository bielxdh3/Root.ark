"use strict";

// Development-only opt-in attachment to the NORMAL Root.ark account-session
// and permission middleware. No legacy route is reclassified as zk-1; this
// explicit isolated cipher plane remains unsafe to call production ZK until
// an independently administered, linearizable per-chunk gate is available.
const path = require("node:path");
const crypto = require("node:crypto");
const { createZk1WitnessHttpsClient } = require("./zk1WitnessHttpsClient");
const { createZk1CasManifestHttpsClient } = require("./zk1CasManifestHttpsClient");
const { createZk1SignedHistoryCasProofProvider } =
  require("./zk1SignedHistoryCasProofProvider");
const { Zk1ProtectedObjectStore } = require("./zk1ProtectedObjectStore");
const { Zk1OpaqueCatalog } = require("./zk1OpaqueCatalog");
const { createZk1OpaqueCatalogCasHttpsClient } =
  require("./zk1OpaqueCatalogCasHttpsClient");
const { registerZk1ProtectedObjectRoutes } = require("../routes/zk1ProtectedObjectRoutes");
const { createAuthorityPinnedReader } = require("./zk1AuthorityPinnedFile");

const B64U = /^[A-Za-z0-9_-]+$/;
const PIN = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const WITNESS_FIELDS = ["endpoint", "caPath", "clientKeyPath", "clientCertPath",
  "serverFingerprint256", "signingKeyId", "signingPublicKeyPath"];
const CAS_FIELDS = WITNESS_FIELDS.slice(0, 5);
const CATALOG_CAS_FIELDS = [...CAS_FIELDS, "authorityPublicKeyPath", "timeoutMs"];
const CAS_DEADLINE_LIMITS = Object.freeze({
  timeoutMs: [100, 30000], historyDeadlineMs: [100, 300000],
});
const SIGNED_HISTORY_FIELDS = ["genesisDigest", "baseReceiptPath",
  "baseWitnessKeyId", "baseWitnessPublicKeyPath", "packageEnvelopes"];
const BASE_RECEIPT_FIELDS = ["type", "witness_key_id", "account_id",
  "compartment_id", "keyring_id", "revision", "manifest_digest",
  "witness_sequence", "nonce", "observed_at", "status", "signature"];
const BASE_RECEIPT_BYTES = ["witness_key_id", "account_id", "compartment_id",
  "keyring_id", "manifest_digest", "nonce", "signature"];
function fail(code = "ZK_CONTENT_BOOTSTRAP_INVALID") {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((name) => !Object.hasOwn(value, name))
    || Reflect.ownKeys(value).some((name) => !fields.includes(name))) fail();
}
function b64(value, min, max = min) {
  if (typeof value !== "string" || !B64U.test(value) || value.length > max * 2 + 4) fail();
  const raw = Buffer.from(value, "base64url");
  if (raw.length < min || raw.length > max || raw.toString("base64url") !== value) fail();
  return raw;
}
function absolute(value) {
  if (typeof value !== "string" || !value || !path.isAbsolute(value)) fail();
  return value;
}
function readFile(filename, max = 65536, reader) {
  try { return reader(absolute(filename), max); }
  catch (_) { fail(); }
}
function endpoint(config, witness, reader) {
  const tunedFields = witness ? [] : Object.keys(CAS_DEADLINE_LIMITS)
    .filter((field) => Object.hasOwn(config || {}, field));
  exact(config, witness ? WITNESS_FIELDS : [...CAS_FIELDS, ...tunedFields]);
  if (!PIN.test(config.serverFingerprint256)) fail();
  const tuning = {};
  for (const field of tunedFields) {
    const value = config[field];
    const [min, max] = CAS_DEADLINE_LIMITS[field];
    if (!Number.isSafeInteger(value) || value < min || value > max) fail();
    tuning[field] = value;
  }
  return {
    endpoint: config.endpoint,
    ca: readFile(config.caPath, 65536, reader),
    clientKey: readFile(config.clientKeyPath, 65536, reader),
    clientCert: readFile(config.clientCertPath, 65536, reader),
    serverFingerprint256: config.serverFingerprint256,
    ...tuning,
  };
}
function clientTlsIdentity(settings) {
  try {
    // PEM file bytes are not identities: leading whitespace, line endings
    // and equivalent key/certificate serialization may all change while
    // TLS still authenticates the very same credential.
    const key = crypto.createPublicKey(crypto.createPrivateKey(settings.clientKey))
      .export({ type: "spki", format: "der" });
    const cert = new crypto.X509Certificate(settings.clientCert);
    const certKey = cert.publicKey.export({ type: "spki", format: "der" });
    if (!key.equals(certKey)) fail();
    return { key, certificate: cert.raw };
  } catch (_) { fail(); }
}
function trustedSignedHistory(config, scope, casClient, reader) {
  exact(config, SIGNED_HISTORY_FIELDS);
  const genesisDigest = b64(config.genesisDigest, 32);
  const baseKeyId = b64(config.baseWitnessKeyId, 16);
  const basePublicKey = crypto.createPublicKey(readFile(config.baseWitnessPublicKeyPath, 65536, reader));
  if (basePublicKey.type !== "public" || basePublicKey.asymmetricKeyType !== "ed25519") fail();
  let receipt;
  try { receipt = JSON.parse(readFile(config.baseReceiptPath, 8192, reader).toString("utf8")); }
  catch (_) { fail(); }
  exact(receipt, BASE_RECEIPT_FIELDS);
  const copied = {};
  for (const name of BASE_RECEIPT_FIELDS) {
    if (BASE_RECEIPT_BYTES.includes(name)) {
      copied[name] = b64(receipt[name], name === "signature" ? 64
        : name === "compartment_id" ? 1
          : ["manifest_digest", "nonce"].includes(name) ? 32 : 16,
      name === "compartment_id" ? 128 : undefined);
    } else {
      copied[name] = receipt[name];
    }
  }
  if (copied.type !== "rootark-recovery-witness-base/v1"
    || copied.status !== "committed"
    || !Number.isSafeInteger(copied.revision) || copied.revision !== 1
    || !Number.isSafeInteger(copied.witness_sequence) || copied.witness_sequence !== 1
    || !Number.isSafeInteger(copied.observed_at) || copied.observed_at < 0
    || !copied.witness_key_id.equals(baseKeyId)
    || !copied.manifest_digest.equals(genesisDigest)
    || !["account_id", "compartment_id", "keyring_id"].every(
      (name) => copied[name].equals(scope[name]))) fail();
  if (!Array.isArray(config.packageEnvelopes) || config.packageEnvelopes.length > 4096) fail();
  let envelopeBytes = 0;
  const packageEnvelopes = config.packageEnvelopes.map((item) => {
    exact(item, ["activationRevision", "envelopePath"]);
    if (!Number.isSafeInteger(item.activationRevision)
      || item.activationRevision < 2) fail();
    const envelope = readFile(item.envelopePath, 8 * 1024 * 1024, reader);
    envelopeBytes += envelope.length;
    if (envelopeBytes > 64 * 1024 * 1024) fail();
    return { activationRevision: item.activationRevision, envelopeBytes: envelope };
  });
  return {
    signedHistoryRequired: true, signedHistoryGenesisDigest: genesisDigest,
    verifiedHistoryProvider: createZk1SignedHistoryCasProofProvider({
      casClient, trustedScope: scope, trustedGenesisDigest: genesisDigest,
      baseReceipt: copied, pinnedBaseWitness: { keyId: baseKeyId,
        publicKey: basePublicKey },
      packageEnvelopes,
    }),
  };
}
function registerZk1ProtectedContentWithReader({
  app, authenticate, requirePermission, configPath, environment,
  multiproviderRestore = null,
  opaqueCatalogAuthority = null,
  opaqueCheckpointV2 = null,
}, reader) {
  if (!["development", "test"].includes(environment)
    || !app || typeof app.post !== "function"
    || typeof authenticate !== "function" || typeof requirePermission !== "function") fail();
  const configBytes = readFile(configPath, 65536, reader);
  let config;
  try { config = JSON.parse(configBytes.toString("utf8")); }
  catch (_) { fail(); }
  exact(config, ["version", "bootstrapNew", "username", "contentDbPath",
    "scope", "minimumHead", "witness", "cas",
    ...(config.version === 2 ? ["signedHistory"] : []),
    ...(Object.hasOwn(config, "catalogCas") && config.version === 2
      ? ["catalogCas"] : [])]);
  if (![1, 2].includes(config.version) || ![true, false].includes(config.bootstrapNew)
    || typeof config.username !== "string" || config.username.length < 1
    || config.username.length > 128 || /[\u0000-\u001f\u007f]/.test(config.username)) fail();
  exact(config.scope, ["account_id", "compartment_id", "keyring_id"]);
  const scope = Object.freeze({
    account_id: b64(config.scope.account_id, 16),
    compartment_id: b64(config.scope.compartment_id, 1, 128),
    keyring_id: b64(config.scope.keyring_id, 16),
  });
  exact(config.minimumHead, ["revision", "digest"]);
  if (!Number.isSafeInteger(config.minimumHead.revision)
    || config.minimumHead.revision < 1) fail();
  const floor = {
    revision: config.minimumHead.revision,
    witnessSequence: config.minimumHead.revision,
    digest: b64(config.minimumHead.digest, 32),
  };
  const witnessTransport = endpoint(config.witness, true, reader);
  const casTransport = endpoint(config.cas, false, reader);
  // Separate logical endpoints are NOT independent trust roots if a single
  // server certificate or mTLS client identity is accepted as both CAS and
  // witness. Detect this unsafe alias at opt-in bootstrap, before opening or
  // creating the protected-content SQLite file. This does not prove their
  // actual operators or hosts are physically independent.
  const witnessClient = clientTlsIdentity(witnessTransport);
  const casClient = clientTlsIdentity(casTransport);
  if (config.witness.serverFingerprint256.toUpperCase()
    === config.cas.serverFingerprint256.toUpperCase()
    || witnessClient.key.equals(casClient.key)
    || witnessClient.certificate.equals(casClient.certificate)) fail();
  const publicKey = crypto.createPublicKey(readFile(config.witness.signingPublicKeyPath, 65536, reader));
  if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") fail();
  // Explicit V2-only opt-in. This signer is pinned by the operator and
  // cannot alias either the witness or manifest-CAS mTLS identity.
  let configuredCatalogAuthority = null;
  if (Object.hasOwn(config, "catalogCas")) {
    if (opaqueCatalogAuthority !== null) fail();
    exact(config.catalogCas, CATALOG_CAS_FIELDS);
    const catalogTransport = endpoint(Object.fromEntries(CAS_FIELDS.map((field) =>
      [field, config.catalogCas[field]])), false, reader);
    const catalogIdentity = clientTlsIdentity(catalogTransport);
    if ([config.witness.serverFingerprint256, config.cas.serverFingerprint256]
      .some((pin) => pin.toUpperCase()
        === config.catalogCas.serverFingerprint256.toUpperCase())
      || catalogIdentity.key.equals(witnessClient.key)
      || catalogIdentity.key.equals(casClient.key)
      || catalogIdentity.certificate.equals(witnessClient.certificate)
      || catalogIdentity.certificate.equals(casClient.certificate)) fail();
    const catalogPublicKey = crypto.createPublicKey(readFile(
      config.catalogCas.authorityPublicKeyPath, 65536, reader));
    if (catalogPublicKey.type !== "public" || catalogPublicKey.asymmetricKeyType !== "ed25519"
      || catalogPublicKey.equals(publicKey)) fail();
    configuredCatalogAuthority = createZk1OpaqueCatalogCasHttpsClient({
      ...catalogTransport, timeoutMs: config.catalogCas.timeoutMs,
      authorityPublicKey: catalogPublicKey,
    });
  }
  const witnessProvider = createZk1WitnessHttpsClient(witnessTransport);
  const manifestProvider = createZk1CasManifestHttpsClient(casTransport);
  // Version 2 is opt-in only in development/test and requires independently
  // provisioned public genesis/recovery witness roots, not CAS-provided ones.
  const signedHistory = config.version === 2
    ? trustedSignedHistory(config.signedHistory, scope, manifestProvider, reader) : {};
  const store = new Zk1ProtectedObjectStore(absolute(config.contentDbPath), {
    bootstrapNew: config.bootstrapNew, trustedScope: scope, admissionRequired: true,
    minimumHead: floor, witnessProvider,
    ...signedHistory,
    witnessPinned: { keyId: b64(config.witness.signingKeyId, 16), publicKey },
    manifestProvider: ({ account_id, compartment_id, keyring_id }) =>
      manifestProvider.getCommittedManifest({ scope: {
        account_id, compartment_id, keyring_id,
      } }),
  });
  try {
    // An independently pinned catalog CAS is an explicit opt-in dependency.
    // No unsigned local SQLite-list fallback is ever registered.
    const selectedCatalogAuthority = configuredCatalogAuthority || opaqueCatalogAuthority;
    const opaqueCatalog = selectedCatalogAuthority === null ? null
      : new Zk1OpaqueCatalog({ store, authority: selectedCatalogAuthority });
    registerZk1ProtectedObjectRoutes({ app, store, authenticate, requirePermission,
      resolveTrustedScope: (user) => user?.username === config.username ? scope : null,
      environment, multiproviderRestore, opaqueCatalog, opaqueCheckpointV2 });
  } catch (error) {
    store.close();
    throw error;
  }
  return store;
}
function registerZk1ProtectedContentFromConfig(options) {
  // Keep startup and every sensitive read synchronous and fail-closed.
  // One resident native verifier compiles once and authorizes each file anew.
  // Always release it after startup, including malformed config/errors.
  const pinned = createAuthorityPinnedReader();
  try { return registerZk1ProtectedContentWithReader(options, pinned.read); }
  finally { pinned.stop(); }
}

module.exports = { registerZk1ProtectedContentFromConfig };
