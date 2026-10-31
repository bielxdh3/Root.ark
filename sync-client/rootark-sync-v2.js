"use strict";

const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const path = require("node:path");
const protocol = require("./rootark-sync-protocol");
const { normalizeTrustedSyncServerUrl } = require("./rootark-sync-transport-policy");
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
  return { ...config, serverUrl: normalizeTrustedSyncServerUrl(config.serverUrl), localFolder: path.resolve(config.localFolder), fileKey, privateKey: crypto.createPrivateKey({ key: privateKeyBytes, format: "der", type: "pkcs8" }), publicKey };
}

function fileKeyResolver(master, fallbackEpoch) {
  return (operation) => crypto.createHmac("sha256", master).update(`${operation.fileId || operation.objectId}\0${operation.keyEpoch || fallbackEpoch}`, "utf8").digest();
}

function trustedAtomicBatchWitnessOptions(options, strictHistorical,
  trustedLocalDevicePolicy = null, localCompartmentId = null) {
  // The remote DELETE+MOVE witness may be supplied only by the embedding
  // trusted process, never by .rootark-sync.json or a remote response. A
  // configured URL, signature or physicalDurable boolean is not a witness.
  if (!Object.hasOwn(options, "trustedAtomicBatchWitness")) return {};
  const supplied = options.trustedAtomicBatchWitness;
  const requiredFields = ["pinnedPublicKey", "scope", "readback", "ownerIdentity",
    "casPinnedPublicKey", "casReadback"];
  let pinned;
  let suppliedIdentity = null;
  try {
    // Read each own data property ONCE. Re-reading supplied.scope/key/readback
    // after checking a callback-owned getter or Proxy lets the caller swap
    // trusted authorities between validation and capture.
    if (!supplied || typeof supplied !== "object" || Array.isArray(supplied)) {
      throw new Error("not a strict owner supplied object");
    }
    const descriptors = Object.getOwnPropertyDescriptors(supplied);
    const names = Reflect.ownKeys(descriptors);
    if (names.length !== requiredFields.length
      || names.some((name) => typeof name !== "string"
        || !requiredFields.includes(name)
        || !Object.hasOwn(descriptors[name], "value"))) {
      throw new Error("accessor, symbol or unknown authority property");
    }
    pinned = Object.fromEntries(requiredFields.map((field) =>
      [field, descriptors[field].value]));
    if (pinned.ownerIdentity != null) {
      suppliedIdentity = JSON.parse(protocol.canonicalJson(pinned.ownerIdentity));
    }
  } catch {
    throw new Error("Atomic batch witness requires immutable canonical owner authority options");
  }
  if (!strictHistorical
    || typeof pinned.readback !== "function"
    || typeof pinned.casReadback !== "function"
    || typeof pinned.scope !== "string"
    || !/^[A-Za-z0-9._:-]{1,256}$/.test(pinned.scope)
    || !suppliedIdentity || typeof suppliedIdentity !== "object"
    || Array.isArray(suppliedIdentity)
    || Object.keys(suppliedIdentity).sort().join(",")
      !== ["accountId", "storeId", "username", "compartmentId"].sort().join(",")
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(suppliedIdentity.accountId)
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(suppliedIdentity.storeId)
    || typeof suppliedIdentity.username !== "string"
    || !suppliedIdentity.username || suppliedIdentity.username.length > 512
    || typeof suppliedIdentity.compartmentId !== "string"
    || !suppliedIdentity.compartmentId || suppliedIdentity.compartmentId.length > 512
    || (trustedLocalDevicePolicy && suppliedIdentity.username !== trustedLocalDevicePolicy.username)
    || (localCompartmentId !== null && suppliedIdentity.compartmentId !== localCompartmentId)
    || !pinned.pinnedPublicKey || !pinned.casPinnedPublicKey) {
    throw new Error("Atomic batch witness requires independently pinned readback and external CAS floor");
  }
  // Validate at construction using the engine's existing strict Ed25519
  // SPKI verifier. Capture all references now; config cannot replace them.
  const readback = pinned.readback;
  const casReadback = pinned.casReadback;
  const identity = Object.freeze(suppliedIdentity);
  return {
    atomicBatchWitnessPublicKey: Buffer.isBuffer(pinned.pinnedPublicKey)
      || pinned.pinnedPublicKey instanceof Uint8Array
      ? Buffer.from(pinned.pinnedPublicKey) : pinned.pinnedPublicKey,
    atomicBatchWitnessScope: pinned.scope,
    atomicBatchOwnerIdentity: identity,
    atomicBatchCasFloorPublicKey: Buffer.isBuffer(pinned.casPinnedPublicKey)
      || pinned.casPinnedPublicKey instanceof Uint8Array
      ? Buffer.from(pinned.casPinnedPublicKey) : pinned.casPinnedPublicKey,
    atomicBatchWitnessReadback: ({ scope, accountId, storeId, nonce, operationIds, envelopeDigests }) =>
      readback({ scope, accountId, storeId, nonce, operationIds: [...operationIds],
        envelopeDigests: [...envelopeDigests] }),
    atomicBatchCasFloorReadback: ({ scope, accountId, storeId, nonce, commitId, storeHeadSha256, fencingEpoch }) =>
      casReadback({ scope, accountId, storeId, nonce, commitId, storeHeadSha256, fencingEpoch }),
  };
}

function assertPinnedStrictLocalDeviceIdentity(config, independentlyPinnedPolicy) {
  // The mutable sync config and device-key environment cannot enroll a new
  // device or silently retarget the externally provisioned owner's account.
  // This local check is NOT the missing immutable account/store ID or a
  // substitute for independently retained physical witness/CAS evidence.
  const deviceId = config?.deviceId;
  const pins = independentlyPinnedPolicy?.trustedDevicePublicKeys;
  // A pinned public-key STRING is insufficient if the process holds a
  // different private key. Verify the exact Ed25519 signing key before any
  // network request or disk journal is opened in strict mode.
  let derivedPublicSpki = null;
  if (config?.privateKey instanceof crypto.KeyObject
    && config.privateKey.type === "private"
    && config.privateKey.asymmetricKeyType === "ed25519") {
    derivedPublicSpki = crypto.createPublicKey(config.privateKey)
      .export({ type: "spki", format: "der" }).toString("base64url");
  }
  if (typeof config?.username !== "string"
    || typeof deviceId !== "string" || !deviceId
    || typeof config?.publicKey !== "string"
    || config.username !== independentlyPinnedPolicy?.username
    || !pins || typeof pins !== "object" || Array.isArray(pins)
    || !Object.hasOwn(pins, deviceId)
    || pins[deviceId] !== config.publicKey
    || derivedPublicSpki !== config.publicKey
    || !Array.isArray(independentlyPinnedPolicy.revokedDeviceIds)
    || independentlyPinnedPolicy.revokedDeviceIds.includes(deviceId)) {
    throw new Error("Strict Sync v2 device identity differs from externally pinned owner policy");
  }
  return true;
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
  // The required mode MUST be activated outside the mutable on-disk config.
  // A config-only opt-in would silently become the legacy locallyAdmitted
  // policy when an attacker deletes this JSON field before a restart.
  const externalMode = options.requireIndependentHistoricalAdmission === true
    || process.env.ROOTARK_SYNC_REQUIRE_INDEPENDENT_HISTORY === "1";
  if (historicalMode === "independent-physical-witness-v1" && !externalMode) {
    throw new Error("Strict historical admission must be externally enforced; config-only mode is unsafe");
  }
  const strictHistorical = externalMode;
  if (strictHistorical && (typeof options.historicalEvidenceProvider !== "function"
    || !options.trustedHistoricalAdmission
    || !options.trustedHistoricalAdmission.localTrustedDevicePolicy
    || typeof options.trustedHistoricalAdmission.trustedCurrentDevicePolicyProvider !== "function")) {
    throw new Error("Independent witness evidence provider and external pins are required");
  }
  const strictBinding = strictHistorical
    ? require("./rootark-sync-zk1-physical-binding") : null;
  const independentlyPinnedDevicePolicy = strictHistorical
    ? strictBinding.snapshotLocalDevicePolicy(
      options.trustedHistoricalAdmission.localTrustedDevicePolicy) : null;
  if (strictHistorical) {
    assertPinnedStrictLocalDeviceIdentity(config, independentlyPinnedDevicePolicy);
  }
  const currentlyTrustedDevice = strictHistorical ? (deviceId) => {
    // Only the operator-injected callback can supply the current policy.
    // Recheck synchronously at the final decision, not before awaited crypto.
    const live = strictBinding.snapshotLocalDevicePolicy(
      options.trustedHistoricalAdmission.trustedCurrentDevicePolicyProvider());
    const originalSpki = independentlyPinnedDevicePolicy.trustedDevicePublicKeys[deviceId];
    return live.username === independentlyPinnedDevicePolicy.username
      && typeof originalSpki === "string"
      && live.trustedDevicePublicKeys[deviceId] === originalSpki
      && !independentlyPinnedDevicePolicy.revokedDeviceIds.includes(deviceId)
      && !live.revokedDeviceIds.includes(deviceId);
  } : null;
  const currentlyAuthorized = strictHistorical ? (operation) =>
    currentlyTrustedDevice(operation.deviceId)
      && operation.authorization?.username === independentlyPinnedDevicePolicy.username
      && operation.authorization?.publicKey
        === independentlyPinnedDevicePolicy.trustedDevicePublicKeys[operation.deviceId]
    : null;
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
  const atomicWitness = trustedAtomicBatchWitnessOptions(options, strictHistorical,
    independentlyPinnedDevicePolicy, config.compartmentId || "private");
  const strictVerifier = strictHistorical
    ? strictBinding.verifySyncV2HistoricalWitnessAdmission : null;
  const adapter = createOpaqueSyncAdapter({
    baseUrl: config.serverUrl,
    fetchImpl: (url, request = {}) => fetch(url, { ...request, headers: { Authorization: `Bearer ${config.token}`, ...(request.headers || {}) } }),
  });
  const engine = await new SyncEngine({
    ...atomicWitness,
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
      && operation.deviceId === config.deviceId
      && (strictHistorical ? currentlyTrustedDevice(config.deviceId)
        : !config.revokedDeviceIds.includes(config.deviceId)),
    // The engine must make a fresh independent decision after asynchronous
    // signing, before durable enqueue, and again just before every queued
    // retry/push. Authorization at initial operation creation is insufficient.
    requireCurrentOutgoingAuthorization: strictHistorical,
    currentDeviceAuthorization: strictHistorical
      ? (operation) => config.deviceRevoked !== true
        && operation.deviceId === config.deviceId
        && currentlyTrustedDevice(operation.deviceId)
      : undefined,
    verifyIncoming: async (operation, { locallyAdmitted = false } = {}) => {
      if (!operation.authorization) return false;
      const expected = independentlyPinnedDevicePolicy || { username: config.username,
        trustedDevicePublicKeys: config.trustedDevicePublicKeys,
        revokedDeviceIds: config.revokedDeviceIds };
      if (operation.authorization.expiresAt > Date.now()) {
        const verified = await verifyAuthorizationProof(operation.authorization, operation, expected);
        return verified === true && (!strictHistorical
          || (operation.authorization.expiresAt > Date.now()
            && currentlyAuthorized(operation)));
      }
      // A signed but expired record does not prove that the remote server
      // admitted it before expiry. The default legacy mode retains only the
      // exact envelope locally witnessed while fresh; strict mode requires an
      // independently signed admission and a currently attested physical floor.
      if (strictHistorical) {
        // Rechecks overwhelmingly reference already-issued durable receipts.
        // First try read-only recovery. When none exists, issue with another
        // CLIENT-generated challenge. If issuance committed but its HTTP ACK
        // was lost, recover with yet another fresh challenge; no nonce or
        // authority claim is accepted from the untrusted response.
        for (const recovery of [true, false, true]) {
          const nonce = crypto.randomBytes(32);
          try {
            const proof = await options.historicalEvidenceProvider(operation,
              { nonce: Buffer.from(nonce), recovery });
            if (!proof || typeof proof !== "object" || Array.isArray(proof)) continue;
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
              trustedCurrentDevicePolicyProvider:
                options.trustedHistoricalAdmission.trustedCurrentDevicePolicyProvider,
            });
            if (verified.authorizesHistoricalRead === true
              && verified.authorizesIo !== true
              && currentlyAuthorized(operation)) return true;
          } catch (_) { /* This attempt cannot authorize a read. */ }
          if (!currentlyAuthorized(operation)) return false;
        }
        return false;
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

module.exports = { fileKeyResolver, trustedAtomicBatchWitnessOptions,
  assertPinnedStrictLocalDeviceIdentity, start };
