"use strict";

// Development-only opt-in attachment to the NORMAL Root.ark account-session
// and permission middleware. No legacy route is reclassified as zk-1; this
// explicit isolated cipher plane remains unsafe to call production ZK until
// an independently administered, linearizable per-chunk gate is available.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { createZk1WitnessHttpsClient } = require("./zk1WitnessHttpsClient");
const { createZk1CasManifestHttpsClient } = require("./zk1CasManifestHttpsClient");
const { createZk1SignedHistoryCasProofProvider } =
  require("./zk1SignedHistoryCasProofProvider");
const { Zk1ProtectedObjectStore } = require("./zk1ProtectedObjectStore");
const { Zk1OpaqueCatalog } = require("./zk1OpaqueCatalog");
const { registerZk1ProtectedObjectRoutes } = require("../routes/zk1ProtectedObjectRoutes");

const B64U = /^[A-Za-z0-9_-]+$/;
const PIN = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const WITNESS_FIELDS = ["endpoint", "caPath", "clientKeyPath", "clientCertPath",
  "serverFingerprint256", "signingKeyId", "signingPublicKeyPath"];
const CAS_FIELDS = WITNESS_FIELDS.slice(0, 5);
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
function sameFileIdentity(left, right) {
  return left.isFile() && right.isFile()
    && left.dev === right.dev && left.ino === right.ino
    && left.mode === right.mode && left.nlink === right.nlink
    && left.size === right.size && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}
function readFile(filename, max = 65536) {
  const input = absolute(filename);
  let descriptor;
  try {
    // Path validation alone leaves a lstat -> readFile race. Pin the exact
    // inode through an open descriptor before reading operator-provisioned
    // pins and TLS keys. BigInt avoids adjacent 64-bit file-ID collisions.
    const before = fs.lstatSync(input, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n
      || before.size < 1n || before.size > BigInt(max)) fail();
    descriptor = fs.openSync(input,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!sameFileIdentity(before, opened)) fail();
    const bytes = Buffer.alloc(Number(opened.size));
    let consumed = 0;
    while (consumed < bytes.length) {
      const size = fs.readSync(descriptor, bytes, consumed,
        bytes.length - consumed, null);
      if (size < 1) fail();
      consumed += size;
    }
    // Never trust a file that grew while being read, even within a pinned fd.
    if (fs.readSync(descriptor, Buffer.alloc(1), 0, 1, null) !== 0) fail();
    const after = fs.fstatSync(descriptor, { bigint: true });
    const currentPath = fs.lstatSync(input, { bigint: true });
    if (!sameFileIdentity(opened, after)
      || !sameFileIdentity(opened, currentPath)) fail();
    return bytes;
  } catch (_) { fail(); }
  finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}
function endpoint(config, witness) {
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
    ca: readFile(config.caPath),
    clientKey: readFile(config.clientKeyPath),
    clientCert: readFile(config.clientCertPath),
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
function trustedSignedHistory(config, scope, casClient) {
  exact(config, SIGNED_HISTORY_FIELDS);
  const genesisDigest = b64(config.genesisDigest, 32);
  const baseKeyId = b64(config.baseWitnessKeyId, 16);
  const basePublicKey = crypto.createPublicKey(readFile(config.baseWitnessPublicKeyPath));
  if (basePublicKey.type !== "public" || basePublicKey.asymmetricKeyType !== "ed25519") fail();
  let receipt;
  try { receipt = JSON.parse(readFile(config.baseReceiptPath, 8192).toString("utf8")); }
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
    const envelope = readFile(item.envelopePath, 8 * 1024 * 1024);
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
function registerZk1ProtectedContentFromConfig({
  app, authenticate, requirePermission, configPath, environment,
  multiproviderRestore = null,
  opaqueCatalogAuthority = null,
}) {
  if (!["development", "test"].includes(environment)
    || !app || typeof app.post !== "function"
    || typeof authenticate !== "function" || typeof requirePermission !== "function") fail();
  const configBytes = readFile(configPath);
  let config;
  try { config = JSON.parse(configBytes.toString("utf8")); }
  catch (_) { fail(); }
  exact(config, ["version", "bootstrapNew", "username", "contentDbPath",
    "scope", "minimumHead", "witness", "cas",
    ...(config.version === 2 ? ["signedHistory"] : [])]);
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
  const witnessTransport = endpoint(config.witness, true);
  const casTransport = endpoint(config.cas, false);
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
  const publicKey = crypto.createPublicKey(readFile(config.witness.signingPublicKeyPath));
  if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") fail();
  const witnessProvider = createZk1WitnessHttpsClient(witnessTransport);
  const manifestProvider = createZk1CasManifestHttpsClient(casTransport);
  // Version 2 is opt-in only in development/test and requires independently
  // provisioned public genesis/recovery witness roots, not CAS-provided ones.
  const signedHistory = config.version === 2
    ? trustedSignedHistory(config.signedHistory, scope, manifestProvider) : {};
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
    const opaqueCatalog = opaqueCatalogAuthority === null ? null
      : new Zk1OpaqueCatalog({ store, authority: opaqueCatalogAuthority });
    registerZk1ProtectedObjectRoutes({ app, store, authenticate, requirePermission,
      resolveTrustedScope: (user) => user?.username === config.username ? scope : null,
      environment, multiproviderRestore, opaqueCatalog });
  } catch (error) {
    store.close();
    throw error;
  }
  return store;
}

module.exports = { registerZk1ProtectedContentFromConfig };
