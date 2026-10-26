"use strict";

// Independently startable zk-1 witness transport with strict opt-in.
// Credentials are provisioned by the operator as separate file paths and
// NEVER generated, printed, placed into Root.ark app config, or defaulted.
// No app runtime import, keyring/content I/O gate, or CAS status server.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const os = require("node:os");
const net = require("node:net");
const { readAuthorityPinnedFile } = require("../src/services/zk1AuthorityPinnedFile");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { createZk1WitnessHttpsServer, drainZk1WitnessHttpsServer } = require("../src/services/zk1WitnessHttpsServer");
const { createZk1CasStatusHttpsClient } = require("../src/services/zk1CasStatusHttpsClient");
const { Zk1WitnessCasAnchorFloor } =
  require("../src/services/zk1WitnessCasAnchorFloor");
const { Zk1WitnessCasPhysicalAdmission } =
  require("../src/services/zk1WitnessCasPhysicalAdmission");
const ownerFloorCheckpoint = require("../src/crypto/rootark-zk1-owner-cas-floor-checkpoint");

const TOP_FIELDS = Object.freeze([
  "listenHost", "listenPort", "bootstrapNew", "dbPath", "witnessKeyId",
  "witnessPrivateKeyPath", "statusKeyId", "statusPublicKeyPath",
  "serverKeyPath", "serverCertPath", "clientCaPath", "principals", "cas",
]);
const CAS_FIELDS = Object.freeze([
  "endpoint", "caPath", "clientKeyPath", "clientCertPath", "serverFingerprint256",
]);
const OWNER_PIN_ENV = "ROOTARK_ZK1_CAS_FLOOR_OWNER_SPKI_SHA256";
const OWNER_CHECKPOINT_PIN_ENV = "ROOTARK_ZK1_CAS_FLOOR_OWNER_CHECKPOINT_SHA256";
const OWNER_FIELDS = Object.freeze(["publicKeyPath", "issuedAt", "expiresAt", "signature"]);
const PRIVATE_BIND_HOST_ENV = "ROOTARK_ZK1_WITNESS_PRIVATE_BIND_HOST";
const PRIVATE_BIND_INTERFACE_ENV = "ROOTARK_ZK1_WITNESS_PRIVATE_BIND_INTERFACE";
function fail() { throw new Error("WITNESS_STARTUP_FAILED"); }
function validateListenHost(host) {
  const pinnedHost = process.env[PRIVATE_BIND_HOST_ENV];
  const pinnedInterface = process.env[PRIVATE_BIND_INTERFACE_ENV];
  if (host === "127.0.0.1" || host === "::1") {
    // A partial or stale remote opt-in cannot silently become loopback.
    if (pinnedHost !== undefined || pinnedInterface !== undefined) fail();
    return;
  }
  // Require canonical literal RFC1918 IPv4 and two independent operator pins.
  // Reject wildcard, DNS, IPv6, public, CGNAT and link-local endpoints.
  if (typeof host !== "string" || net.isIP(host) !== 4
    || pinnedHost !== host || typeof pinnedInterface !== "string"
    || !pinnedInterface || pinnedInterface.length > 128) fail();
  const [first, second] = host.split(".").map(Number);
  if (!(first === 10 || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168))) fail();
  const interfaces = os.networkInterfaces();
  const addresses = Object.hasOwn(interfaces, pinnedInterface)
    ? interfaces[pinnedInterface] : null;
  if (!Array.isArray(addresses) || !addresses.some((address) =>
    (address.family === "IPv4" || address.family === 4)
    && address.internal === false && address.address === host)) fail();
}
function exact(value, names) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== names.length
    || names.some((name) => !Object.hasOwn(value, name))
    || Reflect.ownKeys(value).some((name) => !names.includes(name))) fail();
}
function readFile(value) {
  try { return readAuthorityPinnedFile(value); } catch (_) { fail(); }
}
function decodeId(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(value)) fail();
  const buffer = Buffer.from(value, "base64url");
  if (buffer.length !== 16 || buffer.toString("base64url") !== value) fail();
  return buffer;
}
// This object is injected by a separately governed, executable operator
// launcher, not read from JSON, a path contained in JSON or an HTTP request.
// The stock `node zk1-witness-standalone.js --config ...` CLI intentionally
// has no historical-issuer opt-in; missing external authority fails closed.
function snapshotHistoricalAuthority(authority, config, witnessKey, statusKey) {
  if (authority === undefined || authority === null) return null;
  exact(authority, ["physicalAdmission", "trustedSyncDevicePolicyProvider",
    "trustedMinimumHead", "trustedHistoricalAdmissionHead",
    "trustedRecoveryNonceAuthority",
    "witnessPublicKey", "statusPublicKey", "principals"]);
  if (!(authority.physicalAdmission instanceof Zk1WitnessCasPhysicalAdmission)
    || typeof authority.trustedSyncDevicePolicyProvider !== "function"
    || !(authority.witnessPublicKey instanceof crypto.KeyObject)
    || authority.witnessPublicKey.type !== "public"
    || authority.witnessPublicKey.asymmetricKeyType !== "ed25519"
    || !(authority.statusPublicKey instanceof crypto.KeyObject)
    || authority.statusPublicKey.type !== "public"
    || authority.statusPublicKey.asymmetricKeyType !== "ed25519"
    || !authority.trustedRecoveryNonceAuthority
    || typeof authority.trustedRecoveryNonceAuthority.loadHead !== "function"
    || typeof authority.trustedRecoveryNonceAuthority.compareAndAdvance !== "function"
    || typeof authority.trustedRecoveryNonceAuthority.loadFinalizedHead !== "function"
    || typeof authority.trustedRecoveryNonceAuthority.finalizeAck !== "function"
    || typeof authority.trustedRecoveryNonceAuthority.loadQuarantinedHead !== "function"
    || typeof authority.trustedRecoveryNonceAuthority.quarantineFinalizedAck !== "function"
    || !crypto.KeyObject.prototype.equals.call(authority.witnessPublicKey,
      crypto.createPublicKey(witnessKey))
    || !crypto.KeyObject.prototype.equals.call(authority.statusPublicKey, statusKey)
    || !config.casAnchorFloor || !authority.principals
    || typeof authority.principals !== "object"
    || Array.isArray(authority.principals)) fail();
  const floor = authority.trustedMinimumHead;
  exact(floor, ["sequence", "lastHash", "physicalFenceDigest"]);
  const historical = authority.trustedHistoricalAdmissionHead;
  exact(historical, ["sequence", "lastHash"]);
  // This object is a direct injection from the separate operator launcher,
  // never config JSON, request JSON, the witness SQLite or the CAS writer.
  // A *live* externally committed read is mandatory before any DB startup.
  let externalRecoveryHead;
  let finalizedRecoveryHead;
  try { externalRecoveryHead = authority.trustedRecoveryNonceAuthority.loadHead(); }
  catch (_) { fail(); }
  try { finalizedRecoveryHead = authority.trustedRecoveryNonceAuthority.loadFinalizedHead(); }
  catch (_) { fail(); }
  exact(externalRecoveryHead, ["sequence", "lastHash"]);
  exact(finalizedRecoveryHead, ["sequence", "lastHash"]);
  const checkHash = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
  if (!Number.isSafeInteger(floor.sequence) || floor.sequence < 0
    || floor.sequence > 100000 || !checkHash(floor.lastHash)
    || !checkHash(floor.physicalFenceDigest)
    || !Number.isSafeInteger(historical.sequence) || historical.sequence < 0
    || historical.sequence > 100000 || !checkHash(historical.lastHash)
    || !Number.isSafeInteger(externalRecoveryHead.sequence)
    || externalRecoveryHead.sequence < 0 || externalRecoveryHead.sequence > 4096
    || !checkHash(externalRecoveryHead.lastHash)
    || !Number.isSafeInteger(finalizedRecoveryHead.sequence)
    || finalizedRecoveryHead.sequence < 0 || finalizedRecoveryHead.sequence > 4096
    || !checkHash(finalizedRecoveryHead.lastHash)
    || finalizedRecoveryHead.sequence > externalRecoveryHead.sequence
    || (finalizedRecoveryHead.sequence === externalRecoveryHead.sequence
      && finalizedRecoveryHead.lastHash !== externalRecoveryHead.lastHash)
    || (finalizedRecoveryHead.sequence === 0
      && finalizedRecoveryHead.lastHash !== "0".repeat(64))
    || (externalRecoveryHead.sequence === 0
      && externalRecoveryHead.lastHash !== "0".repeat(64))
    || (historical.sequence === 0 && historical.lastHash !== "0".repeat(64))
    || (config.bootstrapNew && (externalRecoveryHead.sequence !== 0
      || finalizedRecoveryHead.sequence !== 0
      || historical.sequence !== 0
      || floor.sequence !== 0 || floor.lastHash !== "0".repeat(64)
      || floor.physicalFenceDigest !== crypto.createHash("sha256")
        .update("").digest("hex")))
    || floor.sequence !== config.casAnchorFloor.trustedMinimumHead.sequence
    || floor.lastHash !== config.casAnchorFloor.trustedMinimumHead.lastHash) fail();
  const mTls = authority.principals;
  const seen = Object.keys(mTls);
  if (seen.length < 1 || seen.length > 128) fail();
  const externalPrincipals = {};
  for (const fingerprint of seen) {
    if (!/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/i.test(fingerprint)
      || Object.keys(config.principals).some((old) =>
        old.toUpperCase() === fingerprint.toUpperCase())) fail();
    const auth = mTls[fingerprint];
    exact(auth, ["roles", "scopes"]);
    if (!Array.isArray(auth.roles) || auth.roles.length !== 1
      || auth.roles[0] !== "cas-historical-admit"
      || !Array.isArray(auth.scopes) || auth.scopes.length < 1
      || auth.scopes.length > 64) fail();
    // The HTTPS layer independently parses and canonicalizes these scopes.
    externalPrincipals[fingerprint] = { roles: ["cas-historical-admit"],
      scopes: auth.scopes };
  }
  // Only check provider validity here; do not cache it! W2 asks the
  // independently provisioned provider AGAIN before durable SQLite INSERT.
  const policy = authority.trustedSyncDevicePolicyProvider();
  if (!policy || typeof policy !== "object") fail();
  return Object.freeze({ physicalAdmission: authority.physicalAdmission,
    trustedSyncDevicePolicyProvider: authority.trustedSyncDevicePolicyProvider,
    trustedMinimumHead: Object.freeze({ ...floor }),
    trustedHistoricalAdmissionHead: Object.freeze({ ...historical }),
    trustedRecoveryNonceAuthority: authority.trustedRecoveryNonceAuthority,
    principals: externalPrincipals });
}

function configure(config, { historicalAuthority } = {}) {
  exact(config, Object.hasOwn(config || {}, "casAnchorFloor")
    ? [...TOP_FIELDS, "casAnchorFloor"] : TOP_FIELDS);
  exact(config.cas, CAS_FIELDS);
  // A mutable file cannot self-grant historical issuance. Refuse BEFORE
  // opening DBs or reading any signer/private-key file.
  if (Object.values(config.principals || {}).some((item) =>
    Array.isArray(item?.roles) && item.roles.includes("cas-historical-admit"))) fail();
  if (historicalAuthority !== undefined && !config.casAnchorFloor) fail();
  if (config.bootstrapNew !== true && config.bootstrapNew !== false) fail();
  validateListenHost(config.listenHost);
  if (!Number.isSafeInteger(config.listenPort)
    || config.listenPort < 0 || config.listenPort > 65535
    || typeof config.dbPath !== "string" || !path.isAbsolute(config.dbPath)) fail();
  const statusProvider = createZk1CasStatusHttpsClient({
    endpoint: config.cas.endpoint,
    ca: readFile(config.cas.caPath),
    clientKey: readFile(config.cas.clientKeyPath),
    clientCert: readFile(config.cas.clientCertPath),
    serverFingerprint256: config.cas.serverFingerprint256,
  });
  const witnessKeyId = decodeId(config.witnessKeyId);
  const witnessPrivateKey = crypto.createPrivateKey(readFile(config.witnessPrivateKeyPath));
  const statusKeyId = decodeId(config.statusKeyId);
  const statusPublicKey = crypto.createPublicKey(readFile(config.statusPublicKeyPath));
  const historical = snapshotHistoricalAuthority(historicalAuthority, config,
    witnessPrivateKey, statusPublicKey);
  const serverCert = readFile(config.serverCertPath);
  if (config.listenHost !== "127.0.0.1" && config.listenHost !== "::1") {
    // IP SAN is independently verified by remote clients alongside CA and
    // peer fingerprint; CN or DNS SAN cannot authorize an IP bind.
    if (!new crypto.X509Certificate(serverCert)
      .checkIP(config.listenHost, { subject: "never" })) fail();
  }
  // The owner signer pin is deliberately outside editable witness JSON. This
  // is an opt-in *storage/config-only* tamper guard, not a guarantee if the
  // service environment, clock, owner key, and witness are all compromised.
  const ownerPin = process.env[OWNER_PIN_ENV];
  const checkpointPin = process.env[OWNER_CHECKPOINT_PIN_ENV];
  if (ownerPin !== undefined && !/^[a-f0-9]{64}$/.test(ownerPin)) fail();
  if (checkpointPin !== undefined && !/^[a-f0-9]{64}$/.test(checkpointPin)) fail();
  // Both pins are retained independently of editable witness JSON. The
  // checkpoint digest specifically rejects replay of an authentic *older*
  // owner-signed minimum within its otherwise valid expiration window.
  if ((ownerPin === undefined) !== (checkpointPin === undefined)) fail();
  if (ownerPin !== undefined && !Object.hasOwn(config, "casAnchorFloor")) fail();
  let floor = null;
  if (Object.hasOwn(config, "casAnchorFloor")) {
    // This is provisioned by the OUTSIDE owner/witness overseer. A restarted
    // witness may not derive its own minimum from its restored SQLite file.
    // The operator must advance this out-of-band checkpoint after witnessed
    // receipts; a stale external checkpoint cannot prevent every rollback.
    const ownerSigned = Object.hasOwn(config.casAnchorFloor, "owner");
    exact(config.casAnchorFloor, ownerSigned
      ? ["dbPath", "trustedMinimumHead", "owner"]
      : ["dbPath", "trustedMinimumHead"]);
    exact(config.casAnchorFloor.trustedMinimumHead, ["sequence", "lastHash"]);
    if (typeof config.casAnchorFloor.dbPath !== "string"
      || !path.isAbsolute(config.casAnchorFloor.dbPath)
      || path.resolve(config.casAnchorFloor.dbPath) === path.resolve(config.dbPath)
      || !Number.isSafeInteger(config.casAnchorFloor.trustedMinimumHead.sequence)
      || config.casAnchorFloor.trustedMinimumHead.sequence < 0
      || config.casAnchorFloor.trustedMinimumHead.sequence > 100000
      || typeof config.casAnchorFloor.trustedMinimumHead.lastHash !== "string"
      || !/^[a-f0-9]{64}$/.test(config.casAnchorFloor.trustedMinimumHead.lastHash)
      || (config.casAnchorFloor.trustedMinimumHead.sequence === 0
        && config.casAnchorFloor.trustedMinimumHead.lastHash !== "0".repeat(64))) fail();
    // A pin requires an owner-authenticated bounded-age minimum; removing
    // the owner signature or changing the floor cannot silently downgrade.
    // Conversely, never accept a signature without an operator-owned pin.
    if (ownerSigned !== (ownerPin !== undefined)) fail();
    if (ownerSigned) {
      const signed = config.casAnchorFloor.owner;
      exact(signed, OWNER_FIELDS);
      const now = Math.floor(Date.now() / 1000);
      if (!Number.isSafeInteger(signed.issuedAt)
        || !Number.isSafeInteger(signed.expiresAt)
        || signed.issuedAt > now + 120 || signed.issuedAt < now - 86400
        || signed.expiresAt <= now || signed.expiresAt <= signed.issuedAt
        || signed.expiresAt - signed.issuedAt > 86400
        || typeof signed.signature !== "string"
        || !/^[A-Za-z0-9_-]{86}$/.test(signed.signature)) fail();
      const ownerPublicKey = crypto.createPublicKey(readFile(signed.publicKeyPath));
      if (ownerPublicKey.type !== "public" || ownerPublicKey.asymmetricKeyType !== "ed25519") fail();
      const ownerSpki = ownerPublicKey.export({ type: "spki", format: "der" });
      const fingerprint = ownerFloorCheckpoint.spkiFingerprint(ownerPublicKey);
      if (!crypto.timingSafeEqual(fingerprint, Buffer.from(ownerPin, "hex"))) fail();
      const witnessSpki = crypto.createPublicKey(witnessPrivateKey)
        .export({ type: "spki", format: "der" });
      const statusSpki = statusPublicKey.export({ type: "spki", format: "der" });
      if (ownerSpki.equals(witnessSpki) || ownerSpki.equals(statusSpki)
        || witnessSpki.equals(statusSpki)) fail();
      const witnessSpkiSha256 = crypto.createHash("sha256").update(witnessSpki).digest("hex");
      const statusSpkiSha256 = crypto.createHash("sha256").update(statusSpki).digest("hex");
      // The v2 statement binds the *actual* loaded keys, not just editable
      // 16-byte key IDs. Signature and independent digest reject key swaps.
      const ownerStatement = ownerFloorCheckpoint.statement({
        witnessKeyId: config.witnessKeyId,
        statusKeyId: config.statusKeyId,
        witnessSpkiSha256, statusSpkiSha256,
        sequence: config.casAnchorFloor.trustedMinimumHead.sequence,
        lastHash: config.casAnchorFloor.trustedMinimumHead.lastHash,
        issuedAt: signed.issuedAt, expiresAt: signed.expiresAt,
      });
      const signature = Buffer.from(signed.signature, "base64url");
      if (signature.length !== 64
        || signature.toString("base64url") !== signed.signature
        || !crypto.verify(null, ownerFloorCheckpoint.signingBytes(ownerStatement),
          ownerPublicKey, signature)) fail();
      const signedCheckpointDigest = ownerFloorCheckpoint.checkpointDigest(ownerStatement, signature);
      if (!crypto.timingSafeEqual(signedCheckpointDigest,
        Buffer.from(checkpointPin, "hex"))) fail();
    }
    if (fs.existsSync(config.casAnchorFloor.dbPath)
      && fs.existsSync(config.dbPath)
      && fs.realpathSync.native(config.casAnchorFloor.dbPath).toLowerCase()
        === fs.realpathSync.native(config.dbPath).toLowerCase()) fail();
    floor = new Zk1WitnessCasAnchorFloor(config.casAnchorFloor.dbPath, {
      bootstrapNew: config.bootstrapNew, witnessKeyId,
      witnessPrivateKey, statusKeyId, statusPublicKey,
      trustedMinimumHead: historical?.trustedMinimumHead
        || config.casAnchorFloor.trustedMinimumHead,
      ...(historical ? { attestedAdmission: historical.physicalAdmission,
        enableSyncHistoricalIssuer: true,
        trustedSyncDevicePolicyProvider: historical.trustedSyncDevicePolicyProvider,
        trustedHistoricalAdmissionHead: historical.trustedHistoricalAdmissionHead,
        trustedRecoveryNonceAuthority: historical.trustedRecoveryNonceAuthority } : {}),
    });
  }
  let ledger;
  try { ledger = new Zk1DurableWitnessLedger(config.dbPath, {
    bootstrapNew: config.bootstrapNew,
    witnessKeyId, witnessPrivateKey,
    statusPinned: {
      keyId: statusKeyId, publicKey: statusPublicKey,
    },
    statusProvider,
  }); } catch (error) { floor?.close(); throw error; }
  try {
    const server = createZk1WitnessHttpsServer({
      key: readFile(config.serverKeyPath),
      cert: serverCert,
      clientCa: readFile(config.clientCaPath),
      principals: historical ? { ...config.principals, ...historical.principals }
        : config.principals,
      ledger,
      casAnchorFloor: floor,
    });
    return { server, ledger, floor };
  } catch (error) {
    ledger.close();
    floor?.close();
    throw error;
  }
}
function serve(config, { historicalAuthority } = {}) {
  const { server, ledger, floor } = configure(config, { historicalAuthority });
  server.once("error", () => {
    try { ledger.close(); } catch (_) { /* fail closed */ }
    try { floor?.close(); } catch (_) { /* fail closed */ }
    process.stderr.write("WITNESS_STARTUP_FAILED\n");
    process.exitCode = 1;
  });
  let stopping = false;
  const close = () => {
    if (stopping) return;
    stopping = true;
    void drainZk1WitnessHttpsServer(server).then(() => {
      ledger.close();
      floor?.close();
    }).catch(() => {
      // Do not print errors or sensitive config on shutdown failure.
      process.exitCode = 1;
      try { ledger.close(); } catch (_) { /* fail closed */ }
      try { floor?.close(); } catch (_) { /* fail closed */ }
    });
  };
  process.on("SIGTERM", close);
  process.on("SIGINT", close);
  server.listen(config.listenPort, config.listenHost, () => {
    try {
      validateListenHost(config.listenHost);
      if (server.address()?.address !== config.listenHost) fail();
    } catch (_) {
      void drainZk1WitnessHttpsServer(server)
        .catch(() => { server.closeAllConnections(); })
        .finally(() => {
          try { ledger.close(); } catch (_) { /* fail closed */ }
          try { floor?.close(); } catch (_) { /* fail closed */ }
        });
      process.stderr.write("WITNESS_STARTUP_FAILED\n");
      process.exitCode = 1;
      return;
    }
    // IPC is for the disposable integration test supervisor only.
    // Do not disclose keys, file paths, operation data or user scopes.
    if (typeof process.send === "function") {
      process.send({ type: "ready", port: server.address().port });
    }
  });
  return Object.freeze({ server, ledger, floor });
}
async function main() {
  if (process.argv.length !== 4 || process.argv[2] !== "--config") fail();
  const config = JSON.parse(readFile(process.argv[3]).toString("utf8"));
  return serve(config);
}
if (require.main === module) {
  main().catch(() => {
    process.stderr.write("WITNESS_STARTUP_FAILED\n");
    process.exitCode = 1;
  });
}
// For a separately controlled Node launcher only. This is NOT an IPC/HTTP
// method and must not be called with trust material derived from JSON.
module.exports = { configure, serve };
