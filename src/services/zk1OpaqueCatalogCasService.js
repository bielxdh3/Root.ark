"use strict";

// Explicitly configured standalone authority. Run on an independently
// administered host and keep signer PEM / floor outside the protected-content
// app's credentials and SQLite. Never provision a key automatically here.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const net = require("node:net");
const { Zk1OpaqueCatalogCasLedger } = require("./zk1OpaqueCatalogCasLedger");
const { createZk1OpaqueCatalogCasHttpsServer } =
  require("./zk1OpaqueCatalogCasHttpsServer");
const { createZk1WitnessHttpsClient } = require("./zk1WitnessHttpsClient");
const OWNER_FIELDS = ["genesisDigest", "witnessPublicKeyPath", "witnessKeyId",
  "minimumHead", "witnessTransport"];
const WITNESS_TLS_FIELDS = ["endpoint", "caPath", "clientKeyPath",
  "clientCertPath", "serverFingerprint256", "timeoutMs"];
const { createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("./zk1OpaqueCatalogIndependentFloor");
const FIELDS = ["developmentOnlyOptIn", "bindHost", "port", "databasePath",
  "bootstrapNew", "signingPrivateKeyPath", "catalogSignerPublicKeyPath",
  "trustedScope", "minimumHead", "tlsKeyPath", "tlsCertPath", "clientCaPath",
  "authorizedClientFingerprint256", "floorEndpoint", "floorCaPath",
  "floorClientKeyPath", "floorClientCertPath", "floorServerFingerprint256",
  "floorSignerPublicKeyPath"];
function deny() { throw new Error("ZK_OPAQUE_CAS_SERVICE_CONFIG_DENIED"); }
function strict(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) deny();
}
function readBounded(filename, maximum = 65536) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) deny();
  let fd;
  try {
    const named = fs.lstatSync(filename, { bigint: true });
    if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1n
      || named.size < 1n || named.size > BigInt(maximum)) deny();
    fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const before = fs.fstatSync(fd, { bigint: true });
    if (before.dev !== named.dev || before.ino !== named.ino
      || before.size !== named.size || before.mtimeNs !== named.mtimeNs) deny();
    const raw = fs.readFileSync(fd);
    const after = fs.fstatSync(fd, { bigint: true });
    if (raw.length !== Number(named.size) || after.dev !== before.dev
      || after.ino !== before.ino || after.size !== before.size
      || after.mtimeNs !== before.mtimeNs) deny();
    return raw;
  } catch (_) { deny(); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function decode(value, min, max = min) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) deny();
  const data = Buffer.from(value, "base64url");
  if (data.length < min || data.length > max
    || data.toString("base64url") !== value) deny();
  return data;
}
async function startZk1OpaqueCatalogCasServiceFromConfig(configPath) {
  let config;
  try { config = JSON.parse(readBounded(configPath).toString("utf8")); }
  catch (_) { deny(); }
  strict(config, Object.hasOwn(config, "ownerTrust") ? [...FIELDS, "ownerTrust"] : FIELDS);
  if (config.developmentOnlyOptIn !== true
    || !["development", "test"].includes(process.env.NODE_ENV)
    || typeof config.bindHost !== "string"
    || net.isIP(config.bindHost) === 0
    || !Number.isSafeInteger(config.port) || config.port < 1024 || config.port > 65535
    || ![true, false].includes(config.bootstrapNew)) deny();
  strict(config.trustedScope, ["account_id", "compartment_id", "keyring_id"]);
  strict(config.minimumHead, ["sequence", "digest"]);
  const trustedScope = {
    account_id: decode(config.trustedScope.account_id, 16),
    compartment_id: decode(config.trustedScope.compartment_id, 1, 128),
    keyring_id: decode(config.trustedScope.keyring_id, 16),
  };
  if (!Number.isSafeInteger(config.minimumHead.sequence)
    || config.minimumHead.sequence < 0 || config.minimumHead.sequence > 128) deny();
  const signer = crypto.createPrivateKey(readBounded(config.signingPrivateKeyPath));
  const catalogSigner = crypto.createPublicKey(readBounded(config.catalogSignerPublicKeyPath));
  let ownerTrust;
  if (config.ownerTrust !== undefined) {
    const owner = config.ownerTrust;
    strict(owner, OWNER_FIELDS);
    strict(owner.minimumHead, ["revision", "digest"]);
    strict(owner.witnessTransport, WITNESS_TLS_FIELDS);
    if (!Number.isSafeInteger(owner.minimumHead.revision)
      || owner.minimumHead.revision < 1
      || typeof owner.witnessTransport.timeoutMs !== "number") deny();
    const transport = owner.witnessTransport;
    const witnessPublicKey = crypto.createPublicKey(readBounded(owner.witnessPublicKeyPath));
    if (witnessPublicKey.type !== "public" || witnessPublicKey.asymmetricKeyType !== "ed25519"
      || witnessPublicKey.equals(crypto.createPublicKey(signer))
      || witnessPublicKey.equals(catalogSigner)
      || transport.serverFingerprint256.toUpperCase()
        === config.authorizedClientFingerprint256.toUpperCase()
      || config.tlsCertPath === transport.clientCertPath
      || config.tlsKeyPath === transport.clientKeyPath) deny();
    const witnessClient = createZk1WitnessHttpsClient({
      endpoint: transport.endpoint, ca: readBounded(transport.caPath),
      clientKey: readBounded(transport.clientKeyPath),
      clientCert: readBounded(transport.clientCertPath),
      serverFingerprint256: transport.serverFingerprint256,
      timeoutMs: transport.timeoutMs,
    });
    ownerTrust = {
      genesisDigest: decode(owner.genesisDigest, 32),
      pinnedWitness: { keyId: decode(owner.witnessKeyId, 16),
        publicKey: witnessPublicKey },
      minimumHead: { revision: owner.minimumHead.revision,
        witnessSequence: owner.minimumHead.revision,
        digest: decode(owner.minimumHead.digest, 32) },
      freshWitnessHead: ({ scope, nonce }) => witnessClient.freshHead({ scope, nonce }),
    };
  }
  const independentFloor = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: config.floorEndpoint, ca: readBounded(config.floorCaPath),
    clientKey: readBounded(config.floorClientKeyPath),
    clientCert: readBounded(config.floorClientCertPath),
    serverFingerprint256: config.floorServerFingerprint256,
    floorPublicKey: crypto.createPublicKey(readBounded(config.floorSignerPublicKeyPath)),
    casSignerPublicKey: crypto.createPublicKey(signer), trustedScope,
  });
  const ledger = new Zk1OpaqueCatalogCasLedger(config.databasePath, {
    bootstrapNew: config.bootstrapNew, signingPrivateKey: signer,
    catalogSignerPublicKey: catalogSigner, trustedScope, ownerTrust,
    minimumHead: { sequence: config.minimumHead.sequence,
      digest: decode(config.minimumHead.digest, 32) }, independentFloor,
  });
  let server;
  try {
    await ledger.ready;
    server = createZk1OpaqueCatalogCasHttpsServer({
      ledger, key: readBounded(config.tlsKeyPath),
      cert: readBounded(config.tlsCertPath),
      clientCa: readBounded(config.clientCaPath),
      authorizedClientFingerprint256: config.authorizedClientFingerprint256,
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(config.port, config.bindHost, resolve);
    });
  } catch (error) {
    server?.close();
    ledger.close();
    throw error;
  }
  return Object.freeze({
    server,
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
module.exports = { startZk1OpaqueCatalogCasServiceFromConfig };
