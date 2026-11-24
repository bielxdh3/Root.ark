"use strict";

const crypto = require("node:crypto");
// Snapshot this at first load, not after a caller-owned KeyObject callback.
const { randomBytes: NATIVE_RANDOM_BYTES,
  bufferFrom: NATIVE_BUFFER_FROM, dateNow: NATIVE_DATE_NOW } =
  require("../src/crypto/rootark-zk10-native-intrinsics-v1");
const path = require("node:path");
const { types: nodeUtilTypes } = require("node:util");
const protocol = require("./rootark-sync-protocol");
const nativeCanonicalJson = protocol.canonicalJson;
const { normalizeTrustedSyncServerUrl } = require("./rootark-sync-transport-policy");
const { readPrivateV2Config } = require("./rootark-sync-v2-private-config");
const { SyncEngine, normalizeHistoricalRestorePlan } = require("./rootark-sync-engine");
const { verifyPinnedAtomicOwnerProvision } = require("./rootark-sync-atomic-owner-provision");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");
const { createAuthorizationProof, verifyAuthorizationProof,
  verifyHistoricalAuthorizationProof } = require("./rootark-sync-authorization");

// Transport and historical-evidence callbacks can mutate shared intrinsics.
// Pin the post-readback nonce, key-derivation and revocation checks at load time.
const NativeBuffer = Buffer;
const NativeArray = Array;
const NativeSet = Set;
const NativeObjectPrototype = Object.prototype;
const nativeIsProxy = nodeUtilTypes.isProxy;
const nativeIsKeyObject = nodeUtilTypes.isKeyObject;
const nativeBufferFrom = NativeBuffer.from.bind(NativeBuffer);
const nativeBufferToString = NativeBuffer.prototype.toString;
const nativeCryptoRandomBytes = crypto.randomBytes.bind(crypto);
const nativeCryptoCreateHmac = crypto.createHmac.bind(crypto);
const nativeCryptoCreatePublicKey = crypto.createPublicKey.bind(crypto);
const nativeCryptoCreatePrivateKey = crypto.createPrivateKey.bind(crypto);
const nativeHmacUpdate = crypto.Hmac.prototype.update;
const nativeHmacDigest = crypto.Hmac.prototype.digest;
const nativeArrayIsArray = Array.isArray;
const nativeArrayIncludes = Array.prototype.includes;
const nativeArrayMap = Array.prototype.map;
const nativeArrayPush = Array.prototype.push;
const nativeArraySlice = Array.prototype.slice;
const nativeObjectHasOwn = Object.hasOwn;
const nativeObjectKeys = Object.keys;
const nativeObjectCreate = Object.create;
const nativeObjectFreeze = Object.freeze;
const nativeObjectAssign = Object.assign;
const nativeObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const nativeObjectGetPrototypeOf = Object.getPrototypeOf;
const nativeReflectOwnKeys = Reflect.ownKeys;
const nativeReflectApply = Reflect.apply;
const nativeDateNow = Date.now;
const nativeNumberIsSafeInteger = Number.isSafeInteger;
const nativeRegExpExec = RegExp.prototype.exec;
const nativeStringStartsWith = String.prototype.startsWith;
const nativeStringSlice = String.prototype.slice;
const nativeSetAdd = Set.prototype.add;
const nativeSetHas = Set.prototype.has;
const nativePromiseCatch = Promise.prototype.catch;

function regexTest(pattern, value) {
  return nativeReflectApply(nativeRegExpExec, pattern, [value]) !== null;
}

function stringStartsWith(value, prefix) {
  return nativeReflectApply(nativeStringStartsWith, value, [prefix]);
}

function stringSlice(value, start) {
  return nativeReflectApply(nativeStringSlice, value, [start]);
}

function ownDataValue(value, key) {
  if (!value || typeof value !== "object" || nativeIsProxy(value)) return undefined;
  const descriptor = nativeObjectGetOwnPropertyDescriptor(value, key);
  return descriptor && nativeObjectHasOwn(descriptor, "value") ? descriptor.value : undefined;
}

function assertPlainDataObject(value, name) {
  if (!value || typeof value !== "object" || nativeArrayIsArray(value) || nativeIsProxy(value)) {
    throw new Error(`Invalid ${name}`);
  }
  const prototype = nativeObjectGetPrototypeOf(value);
  if (prototype !== NativeObjectPrototype && prototype !== null) throw new Error(`Invalid ${name}`);
  const keys = nativeObjectKeys(value);
  if (nativeReflectOwnKeys(value).length !== keys.length) throw new Error(`Invalid ${name}`);
  for (let index = 0; index < keys.length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, keys[index]);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value") || descriptor.enumerable !== true) {
      throw new Error(`Invalid ${name}`);
    }
  }
}

function snapshotArrayOfData(value, name) {
  if (!nativeArrayIsArray(value) || nativeIsProxy(value)
    || (nativeObjectGetPrototypeOf(value) !== NativeArray.prototype
      && nativeObjectGetPrototypeOf(value) !== null)
    || nativeObjectKeys(value).length !== value.length
    || nativeReflectOwnKeys(value).length !== value.length + 1) {
    throw new Error(`Invalid ${name}`);
  }
  const copy = new NativeArray(value.length);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, `${index}`);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value") || descriptor.enumerable !== true) {
      throw new Error(`Invalid ${name}`);
    }
    copy[index] = descriptor.value;
  }
  return nativeObjectFreeze(copy);
}

const DEFAULT_CONFIG = path.resolve(process.cwd(), ".rootark-sync.json");

function normalizeTrustedDevicePolicy(config) {
  // This policy is provisioned by the local CLI operator; it must never be
  // inferred from an incoming signed envelope or fetched from the peer.
  assertPlainDataObject(config, "Sync v2 config");
  const keys = ownDataValue(config, "trustedDevicePublicKeys");
  const revoked = ownDataValue(config, "revokedDeviceIds");
  if (!keys || typeof keys !== "object" || nativeArrayIsArray(keys) || nativeIsProxy(keys)
    || !nativeArrayIsArray(revoked) || nativeIsProxy(revoked)
    || (nativeObjectGetPrototypeOf(revoked) !== NativeArray.prototype
      && nativeObjectGetPrototypeOf(revoked) !== null)
    || nativeObjectKeys(keys).length < 1 || nativeObjectKeys(keys).length > 10000
    || nativeObjectKeys(revoked).length !== revoked.length
    || nativeReflectOwnKeys(revoked).length !== revoked.length + 1
    || revoked.length > 10000) {
    throw new Error("Sync v2 requires complete trusted device key and revocation policy");
  }
  assertPlainDataObject(keys, "trusted device key map");
  const pinned = nativeObjectCreate(null);
  const keyIds = nativeObjectKeys(keys);
  for (let index = 0; index < keyIds.length; index += 1) {
    const deviceId = keyIds[index];
    const descriptor = nativeObjectGetOwnPropertyDescriptor(keys, deviceId);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value")) throw new Error("Invalid trusted Sync v2 device key");
    const spki = descriptor.value;
    if (!regexTest(/^[A-Za-z0-9._:-]{1,160}$/, deviceId)
      || typeof spki !== "string" || !regexTest(/^[A-Za-z0-9_-]+$/, spki)
      || spki.length > 160) throw new Error("Invalid trusted Sync v2 device key");
    const der = nativeBufferFrom(spki, "base64url");
    try {
      if (nativeReflectApply(nativeBufferToString, der, ["base64url"]) !== spki || der.length !== 44
        || nativeCryptoCreatePublicKey({ key: der, format: "der",
          type: "spki" }).asymmetricKeyType !== "ed25519") throw Error();
    } catch (_) { throw new Error("Invalid trusted Sync v2 device key"); }
    pinned[deviceId] = spki;
  }
  const revokedSnapshot = [];
  const revokedSet = new NativeSet();
  for (let index = 0; index < revoked.length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(revoked, `${index}`);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value")
      || typeof descriptor.value !== "string" || !regexTest(/^[A-Za-z0-9._:-]{1,160}$/, descriptor.value)
      || nativeReflectApply(nativeSetHas, revokedSet, [descriptor.value])) {
      throw new Error("Invalid Sync v2 device revocations");
    }
    nativeReflectApply(nativeSetAdd, revokedSet, [descriptor.value]);
    nativeReflectApply(nativeArrayPush, revokedSnapshot, [descriptor.value]);
  }
  return nativeObjectFreeze({ trustedDevicePublicKeys: nativeObjectFreeze(pinned),
    revokedDeviceIds: nativeObjectFreeze(revokedSnapshot) });
}

function args(argv, strict = false) {
  const result = nativeObjectCreate(null);
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!stringStartsWith(item, "--")) {
      if (strict) throw new Error("Unsupported resume option or argument");
      continue;
    }
    const key = stringSlice(item, 2);
    if (strict && ((key !== "config" && key !== "device-id" && key !== "credentials-stdin")
      || nativeObjectHasOwn(result, key))) {
      throw new Error("Unsupported resume option or argument");
    }
    const value = argv[index + 1];
    result[key] = value && !stringStartsWith(value, "--") ? value : true;
    if (result[key] !== true) index += 1;
  }
  return result;
}

async function readConfig(filePath) {
  // Enforce the same private-directory/owner/ACL boundary as other local
  // authority material before parsing a URL, token or device trust policy.
  const config = readPrivateV2Config(filePath);
  if (!config.serverUrl || !config.localFolder || !config.token || !config.username || !config.deviceId || !config.keyEpoch) throw new Error("Sync v2 requires serverUrl, username, localFolder, token, deviceId, and keyEpoch");
  const policy = normalizeTrustedDevicePolicy(config);
  const master = process.env.ROOTARK_SYNC_FILE_KEY;
  const fileKey = master ? nativeBufferFrom(master, "base64url") : null;
  if (!fileKey || fileKey.length !== 32) throw new Error("ROOTARK_SYNC_FILE_KEY must be a 32-byte base64url key held only in memory");
  const privateKeyBytes = process.env.ROOTARK_SYNC_DEVICE_PRIVATE_KEY
    ? nativeBufferFrom(process.env.ROOTARK_SYNC_DEVICE_PRIVATE_KEY, "base64url") : null;
  const publicKey = process.env.ROOTARK_SYNC_DEVICE_PUBLIC_KEY || "";
  if (!privateKeyBytes || !publicKey) throw new Error("Sync v2 requires device signing keys held only in memory");
  return nativeObjectAssign(nativeObjectCreate(null), config, policy, {
    serverUrl: normalizeTrustedSyncServerUrl(config.serverUrl), localFolder: path.resolve(config.localFolder),
    fileKey, privateKey: nativeCryptoCreatePrivateKey({ key: privateKeyBytes, format: "der", type: "pkcs8" }), publicKey,
  });
}

function fileKeyResolver(master, fallbackEpoch) {
  return (operation) => {
    const hmac = nativeCryptoCreateHmac("sha256", master);
    nativeReflectApply(nativeHmacUpdate, hmac,
      [`${operation.fileId || operation.objectId}\0${operation.keyEpoch || fallbackEpoch}`, "utf8"]);
    return nativeReflectApply(nativeHmacDigest, hmac, []);
  };
}

function trustedAtomicBatchWitnessOptions(_options, strictHistorical) {
  // This helper is exported for embedding integrations, so it must not be a
  // side door around start()'s external-mode gate. The complete provider chain
  // is not yet hardened end-to-end; pair-only production mode deliberately
  // receives no historical witness options.
  if (strictHistorical === true) {
    throw new Error("Independent historical admission is disabled pending full provider-chain hardening");
  }
  // Pair-only mode previously rejected a caller-supplied witness rather than
  // silently ignoring a configuration that implied independent authority.
  // Preserve that fail-closed behavior without invoking Proxy traps/getters.
  if (_options && typeof _options === "object" && !nativeIsProxy(_options)
    && nativeObjectHasOwn(_options, "trustedAtomicBatchWitness")) {
    throw new Error("Atomic batch witness requires independently pinned readback and external CAS floor");
  }
  return {};
}

function assertPinnedStrictLocalDeviceIdentity(config, independentlyPinnedPolicy) {
  // The mutable sync config and device-key environment cannot enroll a new
  // device or silently retarget the externally provisioned owner's account.
  // This local check is NOT the missing immutable account/store ID or a
  // substitute for independently retained physical witness/CAS evidence.
  assertPlainDataObject(config, "strict Sync config");
  assertPlainDataObject(independentlyPinnedPolicy, "strict owner policy");
  const deviceId = ownDataValue(config, "deviceId");
  const pins = ownDataValue(independentlyPinnedPolicy, "trustedDevicePublicKeys");
  // A pinned public-key STRING is insufficient if the process holds a
  // different private key. Verify the exact Ed25519 signing key before any
  // network request or disk journal is opened in strict mode.
  let derivedPublicSpki = null;
  const privateKey = ownDataValue(config, "privateKey");
  if (nativeIsKeyObject(privateKey) && privateKey.type === "private"
    && privateKey.asymmetricKeyType === "ed25519") {
    const exported = nativeCryptoCreatePublicKey(privateKey).export({ type: "spki", format: "der" });
    derivedPublicSpki = nativeReflectApply(nativeBufferToString, exported, ["base64url"]);
  }
  const username = ownDataValue(config, "username");
  const publicKey = ownDataValue(config, "publicKey");
  const pinnedUsername = ownDataValue(independentlyPinnedPolicy, "username");
  const revokedDeviceIds = ownDataValue(independentlyPinnedPolicy, "revokedDeviceIds");
  if (typeof username !== "string"
    || typeof deviceId !== "string" || !deviceId
    || typeof publicKey !== "string"
    || username !== pinnedUsername
    || !pins || typeof pins !== "object" || nativeArrayIsArray(pins)
    || nativeIsProxy(pins)
    || !nativeObjectHasOwn(pins, deviceId)
    || ownDataValue(pins, deviceId) !== publicKey
    || derivedPublicSpki !== publicKey
    || !nativeArrayIsArray(revokedDeviceIds) || nativeIsProxy(revokedDeviceIds)
    || nativeReflectApply(nativeArrayIncludes, revokedDeviceIds,
      [deviceId])) {
    throw new Error("Strict Sync v2 device identity differs from externally pinned owner policy");
  }
  return true;
}

async function start(options = {}) {
  assertPlainDataObject(options, "Sync v2 options");
  if (ownDataValue(options, "previewPlan") === true) {
    // Validate the exact selection before reading keys or private config.
    options = nativeObjectAssign(nativeObjectCreate(null), options, {
      requests: normalizeHistoricalRestorePlan(ownDataValue(options, "requests")),
    });
  }
  if (ownDataValue(options, "restore") === true || ownDataValue(options, "preview") === true) {
    for (const key of ["object-id", "version-id"]) {
      if (typeof ownDataValue(options, key) !== "string"
        || !regexTest(/^[A-Za-z0-9._:-]{1,160}$/, ownDataValue(options, key))) {
        throw new Error(`Valid --${key} is required for historical restore or preview`);
      }
    }
  }
  if ((options.preview === true || options.previewPlan === true)
    && options.requireIndependentHistoricalAdmission !== true
    && process.env.ROOTARK_SYNC_REQUIRE_INDEPENDENT_HISTORY !== "1") {
    throw new Error("Historical preview requires externally enforced independent custody");
  }
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
  if (externalMode) {
    // The optional external provider chain still crosses modules whose
    // post-callback crypto/Buffer/JSON/Object intrinsics are not all pinned.
    // Keep it fail-closed until that entire chain is independently hardened;
    // this does not enable or claim any off-host durability evidence.
    throw new Error("Independent historical admission is temporarily disabled pending full provider-chain hardening");
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
      && !nativeReflectApply(nativeArrayIncludes,
        independentlyPinnedDevicePolicy.revokedDeviceIds, [deviceId])
      && !nativeReflectApply(nativeArrayIncludes, live.revokedDeviceIds, [deviceId]);
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
        : !nativeReflectApply(nativeArrayIncludes, config.revokedDeviceIds,
          [config.deviceId])),
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
      if (operation.authorization.expiresAt > NATIVE_DATE_NOW()) {
        const verified = await verifyAuthorizationProof(operation.authorization, operation, expected);
        return verified === true && (!strictHistorical
          || (operation.authorization.expiresAt > NATIVE_DATE_NOW()
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
          const nonce = NATIVE_RANDOM_BYTES(32);
          try {
            const proof = await options.historicalEvidenceProvider(operation,
              { nonce: NATIVE_BUFFER_FROM(nonce), recovery });
            if (!proof || typeof proof !== "object" || nativeArrayIsArray(proof)) continue;
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
    requireIndependentHistoricalAdmission: strictHistorical,
  }).open({ readOnly: options.preview === true || options.previewPlan === true });
  if (options.previewPlan === true) {
    const outcome = await engine.previewHistoricalRestorePlan(options.requests);
    console.log(JSON.stringify(outcome));
    return engine;
  }
  if (options.preview === true) {
    const outcome = await engine.previewHistoricalRestore(options["object-id"], options["version-id"]);
    // Advisory metadata only, no recovered plaintext or decrypted key bytes.
    console.log(JSON.stringify(outcome));
    return engine;
  }
  if (options.restore === true) {
    const outcome = await engine.restoreHistoricalVersion(options["object-id"], options["version-id"]);
    // Never print recovered plaintext, ciphertext, signing material or bearer.
    console.log(nativeCanonicalJson(outcome));
    return engine;
  }
  const once = options.once === true || options.once === "true";
  do {
    const summary = await engine.syncOnce();
  console.log(nativeCanonicalJson({ pushed: summary.pushed, pulled: summary.pulled,
    conflicts: summary.conflicts.length, offline: summary.offline }));
    if (!once) await new Promise((resolve) => setTimeout(resolve, Number(config.scanIntervalMs) || 5000));
  } while (!once);
  return engine;
}

async function history(options = {}) {
  assertPlainDataObject(options, "Sync history options");
  const objectId = ownDataValue(options, "object-id");
  // Validate user-supplied identifiers before reading private credentials or
  // contacting any endpoint. The HTTP route is for one exact object only.
  if (typeof objectId !== "string" || !regexTest(/^[A-Za-z0-9._:-]{1,160}$/, objectId)) {
    throw new Error("Valid --object-id is required");
  }
  const config = readPrivateV2Config(path.resolve(options.config || DEFAULT_CONFIG));
  if (!config || typeof config.serverUrl !== "string" || !config.serverUrl
    || typeof config.username !== "string" || !config.username
    || typeof config.token !== "string" || !config.token) {
    throw new Error("History requires private Sync v2 serverUrl, username and token");
  }
  const adapter = createOpaqueSyncAdapter({
    baseUrl: normalizeTrustedSyncServerUrl(config.serverUrl),
    fetchImpl: (url, request = {}) => fetch(url, { ...request,
      headers: { ...request.headers, Authorization: `Bearer ${config.token}` },
    }),
  });
  const response = await adapter.history(objectId);
  assertPlainDataObject(response, "Sync history response");
  const versions = snapshotArrayOfData(ownDataValue(response, "versions"), "Sync history versions");
  const versionSummaries = [];
  for (let index = 0; index < versions.length; index += 1) {
    const record = versions[index];
    assertPlainDataObject(record, "Sync history version");
    const metadata = ownDataValue(record, "metadata");
    assertPlainDataObject(metadata, "Sync history metadata");
    versionSummaries[index] = {
      versionId: ownDataValue(record, "versionId"),
      operation: ownDataValue(record, "operation"),
      revision: ownDataValue(record, "revision"),
      deviceId: ownDataValue(record, "deviceId"),
      keyEpoch: ownDataValue(record, "keyEpoch"),
      path: ownDataValue(metadata, "path"),
      tombstone: ownDataValue(record, "tombstone"),
    };
  }
  // Display only owner-readable metadata; ciphertext, proofs and credentials
  // never enter stdout. These are remote claims, not independently verified
  // historical admission evidence and cannot authorize a restore.
  const summary = {
    objectId,
    signatureVerified: false,
    versions: versionSummaries,
  };
  console.log(nativeCanonicalJson(summary));
  return summary;
}

async function readResumeCredentials(stream = process.stdin) {
  let size = 0;
  const chunks = [];
  let parsed;
  try {
    for await (const chunk of stream) {
      const bytes = Buffer.from(chunk);
      size += bytes.length;
      if (size > 2048) {
        bytes.fill(0);
        throw new Error("Invalid resume credentials on stdin");
      }
      chunks.push(bytes);
    }
    const input = Buffer.concat(chunks);
    try { parsed = JSON.parse(input.toString("utf8")); }
    catch { throw new Error("Invalid resume credentials on stdin"); }
    finally { input.fill(0); }
  } finally { chunks.forEach((bytes) => bytes.fill(0)); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)
    || Object.keys(parsed).some((key) => !["password", "code"].includes(key))
    || typeof parsed.password !== "string" || !parsed.password
    || parsed.password.length > 1024
    || (parsed.code !== undefined && (typeof parsed.code !== "string"
      || parsed.code.length > 256))) {
    throw new Error("Invalid resume credentials on stdin");
  }
  return parsed;
}

async function readHistoricalRestorePlanInput(stream = process.stdin) {
  let size = 0;
  const chunks = [];
  let parsed;
  try {
    for await (const chunk of stream) {
      if (size + Buffer.byteLength(chunk) > 16384) {
        throw new Error("Invalid historical restore plan on stdin");
      }
      const bytes = Buffer.from(chunk);
      size += bytes.length;
      chunks.push(bytes);
    }
    const input = Buffer.concat(chunks);
    try { parsed = JSON.parse(input.toString("utf8")); }
    catch { throw new Error("Invalid historical restore plan on stdin"); }
    finally { input.fill(0); }
  } finally { chunks.forEach((bytes) => bytes.fill(0)); }
  return normalizeHistoricalRestorePlan(parsed);
}

async function previewPlan(options = {}) {
  if (options["plan-stdin"] !== true
    || Object.keys(options).some((key) => !["plan-stdin", "config"].includes(key))) {
    throw new Error("Historical recovery plan requires --plan-stdin and optional --config");
  }
  // The standalone CLI cannot manufacture an independent custody authority.
  if (process.env.ROOTARK_SYNC_REQUIRE_INDEPENDENT_HISTORY !== "1") {
    throw new Error("Historical preview requires externally enforced independent custody");
  }
  const requests = await readHistoricalRestorePlanInput();
  return start({ ...options, previewPlan: true, requests });
}

async function resume(options = {}) {
  assertPlainDataObject(options, "Sync resume options");
  for (const key of nativeObjectKeys(options)) {
    if (key !== "config" && key !== "device-id" && key !== "credentials-stdin"
      && key !== "credentialsStream") {
      throw new Error("Unsupported resume option; credentials must use stdin");
    }
  }
  // Preserve the exported programmatic stream contract without turning a CLI
  // --credentialsStream <secret> argument into an alternate argv transport.
  const credentialsStream = options.credentialsStream;
  if (credentialsStream !== undefined && (credentialsStream === null
    || typeof credentialsStream !== "object"
    || typeof credentialsStream[Symbol.asyncIterator] !== "function")) {
    throw new Error("Unsupported resume option; credentials must use stdin");
  }
  const deviceId = options["device-id"];
  // The requested device and explicit credentials transport are validated
  // before reading a private config or accepting passwords from stdin.
  if (typeof deviceId !== "string" || !/^[A-Za-z0-9._:-]{1,160}$/.test(deviceId)) {
    throw new Error("Valid --device-id is required");
  }
  if (options["credentials-stdin"] !== true || "password" in options
    || "code" in options) {
    throw new Error("Resume requires --credentials-stdin; never pass secrets as command arguments");
  }
  const config = readPrivateV2Config(path.resolve(options.config || DEFAULT_CONFIG));
  if (!config || typeof config.serverUrl !== "string" || !config.serverUrl
    || typeof config.username !== "string" || !config.username
    || typeof config.token !== "string" || !config.token
    || typeof config.deviceId !== "string"
    || !/^[A-Za-z0-9._:-]{1,160}$/.test(config.deviceId)) {
    throw new Error("Resume requires private Sync v2 serverUrl, username, token and deviceId");
  }
  if (deviceId === config.deviceId) throw new Error("Paused device cannot resume itself");
  const credentials = await readResumeCredentials(credentialsStream || process.stdin);
  const adapter = createOpaqueSyncAdapter({
    baseUrl: normalizeTrustedSyncServerUrl(config.serverUrl),
    fetchImpl: (url, request = {}) => fetch(url, { ...request,
      headers: { ...request.headers, Authorization: `Bearer ${config.token}` },
    }),
  });
  let outcome;
  try {
    outcome = await adapter.resumeDevice(deviceId, {
      deviceId: config.deviceId, password: credentials.password, code: credentials.code,
    });
  } catch (error) {
    // An untrusted server error could reflect the submitted password/OTP.
    // Never print remote error text or the request body to the terminal.
    if (Number.isInteger(error?.status)) throw new Error(`Sync resume denied (HTTP ${error.status})`);
    throw new Error("Sync resume failed; no credentials disclosed");
  }
  console.log(JSON.stringify(outcome));
  return outcome;
}

async function resumeFromCli(argv) {
  return resume(args(argv, true));
}

if (require.main === module) {
  const argv = nativeReflectApply(nativeArraySlice, process.argv, [2]);
  const command = argv[0] || "help";
  const rest = [];
  for (let index = 1; index < argv.length; index += 1) {
    nativeReflectApply(nativeArrayPush, rest, [argv[index]]);
  }
  if (command === "start") nativeReflectApply(nativePromiseCatch, start(args(rest)),
    [(error) => { console.error(`Sync v2 failed: ${error.message}`); process.exitCode = 1; }]);
  else if (command === "history") nativeReflectApply(nativePromiseCatch, history(args(rest)),
    [(error) => { console.error(`Sync history failed: ${error.message}`); process.exitCode = 1; }]);
  else if (command === "preview") nativeReflectApply(nativePromiseCatch,
    start(nativeObjectAssign(args(rest), { preview: true })),
    [(error) => { console.error(`Sync preview failed: ${error.message}`); process.exitCode = 1; }]);
  else if (command === "preview-plan") nativeReflectApply(nativePromiseCatch,
    previewPlan(args(rest)),
    [(error) => { console.error(`Sync preview plan failed: ${error.message}`); process.exitCode = 1; }]);
  else if (command === "restore") nativeReflectApply(nativePromiseCatch,
    start(nativeObjectAssign(args(rest), { restore: true })),
    [(error) => { console.error(`Sync restore failed: ${error.message}`); process.exitCode = 1; }]);
  else if (command === "resume") nativeReflectApply(nativePromiseCatch, resumeFromCli(rest),
    [(error) => { console.error(`Sync resume failed: ${error.message}`); process.exitCode = 1; }]);
  else console.log("Root.ark Sync v2\n\nUse: npm run sync:start -- --config .rootark-sync.json --once\nOr: node sync-client/rootark-sync-v2.js history --config <private-config> --object-id <id>\nOr: node sync-client/rootark-sync-v2.js preview --config <private-config> --object-id <id> --version-id <id> (requires independently injected custody and current grant; never mutates files)\nOr: node sync-client/rootark-sync-v2.js preview-plan --config <private-config> --plan-stdin (JSON array of up to 32 {objectId,versionId}; independent custody required; never mutates)\nOr: node sync-client/rootark-sync-v2.js restore --config <private-config> --object-id <id> --version-id <id> (requires signing keys and authorized historical evidence)\nOr: node sync-client/rootark-sync-v2.js resume --config <private-config> --device-id <paused-device-id> --credentials-stdin (pipe private JSON {password,code?} from a separate trusted device)");
}

module.exports = { fileKeyResolver, normalizeTrustedDevicePolicy,
  trustedAtomicBatchWitnessOptions, assertPinnedStrictLocalDeviceIdentity,
  start, history, resume, readResumeCredentials, previewPlan, readHistoricalRestorePlanInput };
