"use strict";

// Provision this service on a separately administered host. Never co-locate
// its signing key, TLS identity or durable database with the catalog CAS DB.
const path = require("node:path");
const net = require("node:net");
const crypto = require("node:crypto");
const { readAuthorityPinnedFile } = require("./zk1AuthorityPinnedFile");
const { createZk1WitnessHttpsClient } = require("./zk1WitnessHttpsClient");
const { Zk1OpaqueCatalogIndependentFloorLedger,
  createZk1OpaqueCatalogIndependentFloorHttpsServer } =
  require("./zk1OpaqueCatalogIndependentFloor");

const FIELDS = ["developmentOnlyOptIn", "bindHost", "port", "databasePath",
  "bootstrapNew", "signingPrivateKeyPath", "casSignerPublicKeyPath",
  "catalogSignerPublicKeyPath", "trustedScope", "tlsKeyPath", "tlsCertPath",
  "clientCaPath", "authorizedClientFingerprint256"];
const OWNER_FIELDS = ["genesisDigest", "witnessPublicKeyPath", "witnessKeyId",
  "minimumHead", "witnessTransport"];
const WITNESS_TLS_FIELDS = ["endpoint", "caPath", "clientKeyPath",
  "clientCertPath", "serverFingerprint256", "timeoutMs"];
function fail() { throw new Error("ZK_OPAQUE_FLOOR_SERVICE_CONFIG_DENIED"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((k) => !Object.hasOwn(value, k))) fail();
}
function read(filename, maximum = 65536) {
  try {
    // Keep startup signing/TLS material subject to the exact same ancestry,
    // DACL and descriptor/path pinning as the standalone witness authority.
    const raw = readAuthorityPinnedFile(filename);
    if (raw.length > maximum) fail();
    return raw;
  } catch (_) { fail(); }
}
function decode(text, min, max = min) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]+$/.test(text)) fail();
  const result = Buffer.from(text, "base64url");
  if (result.length < min || result.length > max
    || result.toString("base64url") !== text) fail();
  return result;
}
async function startZk1OpaqueCatalogIndependentFloorServiceFromConfig(configPath) {
  let config;
  try { config = JSON.parse(read(configPath).toString("utf8")); }
  catch (_) { fail(); }
  exact(config, Object.hasOwn(config, "ownerTrust") ? [...FIELDS, "ownerTrust"] : FIELDS);
  if (config.developmentOnlyOptIn !== true
    || !["development", "test"].includes(process.env.NODE_ENV)
    || typeof config.bindHost !== "string" || !net.isIP(config.bindHost)
    || !Number.isSafeInteger(config.port) || config.port < 1024 || config.port > 65535
    || typeof config.bootstrapNew !== "boolean"
    || !/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i.test(config.authorizedClientFingerprint256)) fail();
  exact(config.trustedScope, ["account_id", "compartment_id", "keyring_id"]);
  const trustedScope = {
    account_id: decode(config.trustedScope.account_id, 16),
    compartment_id: decode(config.trustedScope.compartment_id, 1, 128),
    keyring_id: decode(config.trustedScope.keyring_id, 16),
  };
  let ownerTrust;
  if (config.ownerTrust !== undefined) {
    const owner = config.ownerTrust;
    exact(owner, OWNER_FIELDS);
    exact(owner.minimumHead, ["revision", "digest"]);
    exact(owner.witnessTransport, WITNESS_TLS_FIELDS);
    if (!Number.isSafeInteger(owner.minimumHead.revision)
      || owner.minimumHead.revision < 1) fail();
    const witnessPublicKey = crypto.createPublicKey(read(owner.witnessPublicKeyPath));
    const floorPublicKey = crypto.createPublicKey(read(config.signingPrivateKeyPath));
    const casPublicKey = crypto.createPublicKey(read(config.casSignerPublicKeyPath));
    const catalogPublicKey = crypto.createPublicKey(read(config.catalogSignerPublicKeyPath));
    if (witnessPublicKey.type !== "public"
      || witnessPublicKey.asymmetricKeyType !== "ed25519"
      || [floorPublicKey, casPublicKey, catalogPublicKey]
        .some((key) => key.equals(witnessPublicKey))) fail();
    const transport = owner.witnessTransport;
    const witnessClient = createZk1WitnessHttpsClient({
      endpoint: transport.endpoint, ca: read(transport.caPath),
      clientKey: read(transport.clientKeyPath),
      clientCert: read(transport.clientCertPath),
      serverFingerprint256: transport.serverFingerprint256,
      timeoutMs: transport.timeoutMs,
    });
    ownerTrust = { genesisDigest: decode(owner.genesisDigest, 32),
      pinnedWitness: { keyId: decode(owner.witnessKeyId, 16), publicKey: witnessPublicKey },
      minimumHead: { revision: owner.minimumHead.revision,
        witnessSequence: owner.minimumHead.revision,
        digest: decode(owner.minimumHead.digest, 32) },
      freshWitnessHead: ({ scope, nonce }) => witnessClient.freshHead({ scope, nonce }),
    };
  }
  const ledger = new Zk1OpaqueCatalogIndependentFloorLedger(config.databasePath, {
    bootstrapNew: config.bootstrapNew, trustedScope,
    signingPrivateKey: crypto.createPrivateKey(read(config.signingPrivateKeyPath)),
    casSignerPublicKey: crypto.createPublicKey(read(config.casSignerPublicKeyPath)),
    catalogSignerPublicKey: crypto.createPublicKey(read(config.catalogSignerPublicKeyPath)),
    ownerTrust,
  });
  let server;
  try {
    server = createZk1OpaqueCatalogIndependentFloorHttpsServer({
      ledger, key: read(config.tlsKeyPath), cert: read(config.tlsCertPath),
      clientCa: read(config.clientCaPath),
      authorizedClientFingerprint256: config.authorizedClientFingerprint256,
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(config.port, config.bindHost, resolve);
    });
  } catch (error) { server?.close(); ledger.close(); throw error; }
  return Object.freeze({ server,
    close: () => new Promise((resolve, reject) => {
      server.close((error) => {
        if (error) return reject(error);
        try { ledger.db.pragma("wal_checkpoint(TRUNCATE)"); ledger.close(); resolve(); }
        catch (caught) { reject(caught); }
      });
      server.closeIdleConnections();
    }),
  });
}
module.exports = { startZk1OpaqueCatalogIndependentFloorServiceFromConfig };
