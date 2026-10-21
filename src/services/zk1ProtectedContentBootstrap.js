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
const { Zk1ProtectedObjectStore } = require("./zk1ProtectedObjectStore");
const { registerZk1ProtectedObjectRoutes } = require("../routes/zk1ProtectedObjectRoutes");

const B64U = /^[A-Za-z0-9_-]+$/;
const PIN = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i;
const WITNESS_FIELDS = ["endpoint", "caPath", "clientKeyPath", "clientCertPath",
  "serverFingerprint256", "signingKeyId", "signingPublicKeyPath"];
const CAS_FIELDS = WITNESS_FIELDS.slice(0, 5);
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
function readFile(filename, max = 65536) {
  const input = absolute(filename);
  const info = fs.lstatSync(input);
  if (!info.isFile() || info.size < 1 || info.size > max) fail();
  return fs.readFileSync(input);
}
function endpoint(config, witness) {
  exact(config, witness ? WITNESS_FIELDS : CAS_FIELDS);
  if (!PIN.test(config.serverFingerprint256)) fail();
  return {
    endpoint: config.endpoint,
    ca: readFile(config.caPath),
    clientKey: readFile(config.clientKeyPath),
    clientCert: readFile(config.clientCertPath),
    serverFingerprint256: config.serverFingerprint256,
  };
}
function registerZk1ProtectedContentFromConfig({
  app, authenticate, requirePermission, configPath, environment,
}) {
  if (!["development", "test"].includes(environment)
    || !app || typeof app.post !== "function"
    || typeof authenticate !== "function" || typeof requirePermission !== "function") fail();
  const configBytes = readFile(configPath);
  let config;
  try { config = JSON.parse(configBytes.toString("utf8")); }
  catch (_) { fail(); }
  exact(config, ["version", "bootstrapNew", "username", "contentDbPath",
    "scope", "minimumHead", "witness", "cas"]);
  if (config.version !== 1 || ![true, false].includes(config.bootstrapNew)
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
  const publicKey = crypto.createPublicKey(readFile(config.witness.signingPublicKeyPath));
  if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") fail();
  const witnessProvider = createZk1WitnessHttpsClient(witnessTransport);
  const manifestProvider = createZk1CasManifestHttpsClient(casTransport);
  const store = new Zk1ProtectedObjectStore(absolute(config.contentDbPath), {
    bootstrapNew: config.bootstrapNew, trustedScope: scope,
    minimumHead: floor, witnessProvider,
    witnessPinned: { keyId: b64(config.witness.signingKeyId, 16), publicKey },
    manifestProvider: ({ account_id, compartment_id, keyring_id }) =>
      manifestProvider.getCommittedManifest({ scope: {
        account_id, compartment_id, keyring_id,
      } }),
  });
  try {
    registerZk1ProtectedObjectRoutes({ app, store, authenticate, requirePermission,
      resolveTrustedScope: (user) => user?.username === config.username ? scope : null });
  } catch (error) {
    store.close();
    throw error;
  }
  return store;
}

module.exports = { registerZk1ProtectedContentFromConfig };
