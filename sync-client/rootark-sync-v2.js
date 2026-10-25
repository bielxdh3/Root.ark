"use strict";

const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { SyncEngine } = require("./rootark-sync-engine");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");
const { createAuthorizationProof, verifyAuthorizationProof,
  verifyHistoricalAuthorizationProof } = require("./rootark-sync-authorization");

const DEFAULT_CONFIG = path.resolve(process.cwd(), ".rootark-sync.json");

function args(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) continue;
    const key = item.slice(2);
    const value = argv[index + 1];
    result[key] = value && !value.startsWith("--") ? value : true;
    if (result[key] !== true) index += 1;
  }
  return result;
}

async function readConfig(filePath) {
  const config = JSON.parse(await fsp.readFile(filePath, "utf8"));
  if (!config.serverUrl || !config.localFolder || !config.token || !config.username || !config.deviceId || !config.keyEpoch) throw new Error("Sync v2 requires serverUrl, username, localFolder, token, deviceId, and keyEpoch");
  const master = process.env.ROOTARK_SYNC_FILE_KEY;
  const fileKey = master ? Buffer.from(master, "base64url") : null;
  if (!fileKey || fileKey.length !== 32) throw new Error("ROOTARK_SYNC_FILE_KEY must be a 32-byte base64url key held only in memory");
  const privateKeyBytes = process.env.ROOTARK_SYNC_DEVICE_PRIVATE_KEY ? Buffer.from(process.env.ROOTARK_SYNC_DEVICE_PRIVATE_KEY, "base64url") : null;
  const publicKey = process.env.ROOTARK_SYNC_DEVICE_PUBLIC_KEY || "";
  if (!privateKeyBytes || !publicKey) throw new Error("Sync v2 requires device signing keys held only in memory");
  const pins = config.trustedDevicePublicKeys;
  if (!pins || typeof pins !== "object" || Array.isArray(pins) || !Object.keys(pins).length) {
    throw new Error("Sync v2 requires independently provisioned trustedDevicePublicKeys");
  }
  for (const [deviceId, spki] of Object.entries(pins)) {
    if (!deviceId || deviceId.length > 512 || typeof spki !== "string") {
      throw new Error("Sync v2 trusted device pin is invalid");
    }
    const bytes = Buffer.from(spki, "base64url");
    if (bytes.toString("base64url") !== spki
      || bytes.length !== 44
      || crypto.createPublicKey({ key: bytes, format: "der", type: "spki" }).asymmetricKeyType !== "ed25519") {
      throw new Error("Sync v2 trusted device pin must be canonical Ed25519 SPKI");
    }
  }
  if (!Array.isArray(config.revokedDeviceIds)
    || config.revokedDeviceIds.some((id) => typeof id !== "string"
      || !id || id.length > 512)) {
    throw new Error("Sync v2 requires an explicit revokedDeviceIds snapshot");
  }
  return { ...config, serverUrl: String(config.serverUrl).replace(/\/+$/, ""), localFolder: path.resolve(config.localFolder), fileKey, privateKey: crypto.createPrivateKey({ key: privateKeyBytes, format: "der", type: "pkcs8" }), publicKey };
}

function fileKeyResolver(master, fallbackEpoch) {
  return (operation) => crypto.createHmac("sha256", master).update(`${operation.fileId || operation.objectId}\0${operation.keyEpoch || fallbackEpoch}`, "utf8").digest();
}

async function start(options = {}) {
  const configPath = path.resolve(options.config || DEFAULT_CONFIG);
  const config = await readConfig(configPath);
  // The historical witness mode requires pins provisioned by the embedding
  // trusted process, outside the mutable sync config and local JSON journal.
  // The standalone CLI deliberately fails closed until a real independent
  // mTLS PG/witness evidence source is wired by that embedding process.
  const historicalMode = config.historicalAdmissionMode;
  if (historicalMode !== undefined
    && historicalMode !== "independent-physical-witness-v1") {
    throw new Error("Unsupported Sync v2 historical admission mode");
  }
  // The required mode must also be enforceable outside the mutable on-disk
  // config, or a local attacker can simply delete that JSON setting and
  // reactivate forgeable local-journal admissions on the next restart.
  const externalMode = options.requireIndependentHistoricalAdmission === true
    || process.env.ROOTARK_SYNC_REQUIRE_INDEPENDENT_HISTORY === "1";
  const strictHistorical = externalMode
    || historicalMode === "independent-physical-witness-v1";
  if (strictHistorical && (typeof options.historicalEvidenceProvider !== "function"
    || !options.trustedHistoricalAdmission)) {
    throw new Error("Independent witness evidence provider and external pins are required");
  }
  const trustedHistorical = strictHistorical ? (() => {
    const provided = options.trustedHistoricalAdmission;
    const copyPin = (pin) => Buffer.isBuffer(pin) || pin instanceof Uint8Array
      ? Buffer.from(pin) : pin;
    const floor = provided.trustedMinimumFloor;
    return {
      pinnedInventoryPublicKey: copyPin(provided.pinnedInventoryPublicKey),
      pinnedInventorySignerKeyId: copyPin(provided.pinnedInventorySignerKeyId),
      pinnedPhysicalAttestorPublicKey: copyPin(provided.pinnedPhysicalAttestorPublicKey),
      pinnedWitnessPublicKey: copyPin(provided.pinnedWitnessPublicKey),
      witnessKeyId: copyPin(provided.witnessKeyId),
      statusKeyId: copyPin(provided.statusKeyId),
      trustedMinimumFloor: floor && {
        sequence: floor.sequence, lastHash: floor.lastHash,
        physicalFenceDigest: floor.physicalFenceDigest,
      },
    };
  })() : null;
  const strictVerifier = strictHistorical
    ? require("./rootark-sync-zk1-physical-binding")
      .verifySyncV2HistoricalWitnessAdmission : null;
  const adapter = createOpaqueSyncAdapter({
    baseUrl: config.serverUrl,
    fetchImpl: (url, request = {}) => fetch(url, { ...request, headers: { Authorization: `Bearer ${config.token}`, ...(request.headers || {}) } }),
  });
  const engine = await new SyncEngine({
    rootDir: config.localFolder,
    adapter,
    selectedPaths: config.selectedPaths,
    excludedPaths: config.excludedPaths,
    deviceId: config.deviceId,
    keyEpoch: config.keyEpoch,
    compartmentId: config.compartmentId || "private",
    fileKeyResolver: fileKeyResolver(config.fileKey, config.keyEpoch),
    authorize: async (operation) => operation.keyEpoch === config.keyEpoch,
    authorizeOutgoing: async (operation) => config.deviceRevoked !== true
      && !config.revokedDeviceIds.includes(config.deviceId)
      && operation.deviceId === config.deviceId,
    verifyIncoming: async (operation, { locallyAdmitted = false } = {}) => {
      if (!operation.authorization) return false;
      const expected = { username: config.username,
        trustedDevicePublicKeys: config.trustedDevicePublicKeys,
        revokedDeviceIds: config.revokedDeviceIds };
      if (operation.authorization.expiresAt > Date.now()) {
        return verifyAuthorizationProof(operation.authorization, operation, expected);
      }
      // A signed but expired record does not prove that the remote server
      // admitted it before expiry. The default legacy mode retains only the
      // exact envelope locally witnessed while fresh; strict mode requires an
      // independently signed admission and a currently attested physical floor.
      if (strictHistorical) {
        // The supplied proof is untrusted transport data. Generate the nonce
        // locally, override all trust pins from the independent integration,
        // and revalidate the exact original signed encrypted envelope.
        const nonce = crypto.randomBytes(32);
        const proof = await options.historicalEvidenceProvider(operation,
          { nonce: Buffer.from(nonce) });
        if (!proof || typeof proof !== "object" || Array.isArray(proof)) return false;
        const verified = await strictVerifier({
          envelope: operation, scope: proof.scope,
          expectedSequence: proof.expectedSequence, expectedRoot: proof.expectedRoot,
          receipt: proof.receipt, physicalAttestation: proof.physicalAttestation,
          nonce, admission: proof.admission, freshFloor: proof.freshFloor,
          pinnedInventoryPublicKey: trustedHistorical.pinnedInventoryPublicKey,
          pinnedInventorySignerKeyId: trustedHistorical.pinnedInventorySignerKeyId,
          pinnedPhysicalAttestorPublicKey: trustedHistorical.pinnedPhysicalAttestorPublicKey,
          pinnedWitnessPublicKey: trustedHistorical.pinnedWitnessPublicKey,
          witnessKeyId: trustedHistorical.witnessKeyId,
          statusKeyId: trustedHistorical.statusKeyId,
          trustedMinimumFloor: trustedHistorical.trustedMinimumFloor,
          localTrustedDevicePolicy: expected,
        });
        return verified.authorizesHistoricalRead === true;
      }
      if (locallyAdmitted !== true) return false;
      return verifyHistoricalAuthorizationProof(operation.authorization, operation,
        expected);
    },
    authorizationFactory: (operation) => createAuthorizationProof(operation, { username: config.username, privateKey: config.privateKey, publicKey: config.publicKey }),
    requireAuthorization: true,
    reverifySeenIncoming: strictHistorical,
  }).open();
  const once = options.once === true || options.once === "true";
  do {
    const summary = await engine.syncOnce();
    console.log(JSON.stringify({ pushed: summary.pushed, pulled: summary.pulled, conflicts: summary.conflicts.length, offline: summary.offline }));
    if (!once) await new Promise((resolve) => setTimeout(resolve, Number(config.scanIntervalMs) || 5000));
  } while (!once);
  return engine;
}

if (require.main === module) {
  const [command = "help", ...rest] = process.argv.slice(2);
  if (command === "start") start({ ...args(rest) }).catch((error) => { console.error(`Sync v2 failed: ${error.message}`); process.exitCode = 1; });
  else console.log("Root.ark Sync v2\n\nUse: npm run sync:start -- --config .rootark-sync.json --once");
}

module.exports = { fileKeyResolver, start };
