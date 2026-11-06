"use strict";

const crypto = require("node:crypto");
const path = require("node:path");
const protocol = require("./rootark-sync-protocol");
const { normalizeTrustedSyncServerUrl } = require("./rootark-sync-transport-policy");
const { readPrivateV2Config } = require("./rootark-sync-v2-private-config");
const { SyncEngine, normalizeHistoricalRestorePlan } = require("./rootark-sync-engine");
const { verifyPinnedAtomicOwnerProvision } = require("./rootark-sync-atomic-owner-provision");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");
const { createAuthorizationProof, verifyAuthorizationProof,
  verifyHistoricalAuthorizationProof } = require("./rootark-sync-authorization");

const DEFAULT_CONFIG = path.resolve(process.cwd(), ".rootark-sync.json");

function normalizeTrustedDevicePolicy(config) {
  // This policy is provisioned by the local CLI operator; it must never be
  // inferred from an incoming signed envelope or fetched from the peer.
  const keys = config?.trustedDevicePublicKeys;
  const revoked = config?.revokedDeviceIds;
  if (!keys || typeof keys !== "object" || Array.isArray(keys)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(keys))
    || !Array.isArray(revoked)
    || Object.keys(keys).length < 1 || Object.keys(keys).length > 10000
    || revoked.length > 10000) {
    throw new Error("Sync v2 requires complete trusted device key and revocation policy");
  }
  const pinned = Object.create(null);
  for (const [deviceId, spki] of Object.entries(keys)) {
    if (!/^[A-Za-z0-9._:-]{1,160}$/.test(deviceId)
      || typeof spki !== "string" || !/^[A-Za-z0-9_-]+$/.test(spki)
      || spki.length > 160) throw new Error("Invalid trusted Sync v2 device key");
    const der = Buffer.from(spki, "base64url");
    try {
      if (der.toString("base64url") !== spki || der.length !== 44
        || crypto.createPublicKey({ key: der, format: "der",
          type: "spki" }).asymmetricKeyType !== "ed25519") throw Error();
    } catch (_) { throw new Error("Invalid trusted Sync v2 device key"); }
    pinned[deviceId] = spki;
  }
  if (revoked.some((deviceId) => typeof deviceId !== "string"
    || !/^[A-Za-z0-9._:-]{1,160}$/.test(deviceId))
    || new Set(revoked).size !== revoked.length) {
    throw new Error("Invalid Sync v2 device revocations");
  }
  return Object.freeze({ trustedDevicePublicKeys: Object.freeze(pinned),
    revokedDeviceIds: Object.freeze([...revoked]) });
}

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
  // Enforce the same private-directory/owner/ACL boundary as other local
  // authority material before parsing a URL, token or device trust policy.
  const config = readPrivateV2Config(filePath);
  if (!config.serverUrl || !config.localFolder || !config.token || !config.username || !config.deviceId || !config.keyEpoch) throw new Error("Sync v2 requires serverUrl, username, localFolder, token, deviceId, and keyEpoch");
  const policy = normalizeTrustedDevicePolicy(config);
  const master = process.env.ROOTARK_SYNC_FILE_KEY;
  const fileKey = master ? Buffer.from(master, "base64url") : null;
  if (!fileKey || fileKey.length !== 32) throw new Error("ROOTARK_SYNC_FILE_KEY must be a 32-byte base64url key held only in memory");
  const privateKeyBytes = process.env.ROOTARK_SYNC_DEVICE_PRIVATE_KEY ? Buffer.from(process.env.ROOTARK_SYNC_DEVICE_PRIVATE_KEY, "base64url") : null;
  const publicKey = process.env.ROOTARK_SYNC_DEVICE_PUBLIC_KEY || "";
  if (!privateKeyBytes || !publicKey) throw new Error("Sync v2 requires device signing keys held only in memory");
  return { ...config, ...policy, serverUrl: normalizeTrustedSyncServerUrl(config.serverUrl), localFolder: path.resolve(config.localFolder), fileKey, privateKey: crypto.createPrivateKey({ key: privateKeyBytes, format: "der", type: "pkcs8" }), publicKey };
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
    "casPinnedPublicKey", "casReadback", "ownerProvisionerPublicKey",
    "ownerProvisioning", "ownerProvisionDigest"];
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
  // The identity must be signed by a third owner-pinned Ed25519 root. Checking
  // equality against a caller-supplied UUID object without its provenance is
  // insufficient, even if the physical witness and CAS sign matching UUIDs.
  const provision = verifyPinnedAtomicOwnerProvision({
    identity: suppliedIdentity, scope: pinned.scope,
    provisionerPublicKey: pinned.ownerProvisionerPublicKey,
    provisioning: pinned.ownerProvisioning,
    expectedDigest: pinned.ownerProvisionDigest,
    witnessPublicKey: pinned.pinnedPublicKey,
    casPublicKey: pinned.casPinnedPublicKey,
  });
  // Validate again inside SyncEngine so direct callers cannot bypass the
  // trusted embedding wrapper. Capture every reference now.
  const readback = pinned.readback;
  const casReadback = pinned.casReadback;
  const identity = Object.freeze(suppliedIdentity);
  return {
    atomicBatchWitnessPublicKey: Buffer.isBuffer(pinned.pinnedPublicKey)
      || pinned.pinnedPublicKey instanceof Uint8Array
      ? Buffer.from(pinned.pinnedPublicKey) : pinned.pinnedPublicKey,
    atomicBatchWitnessScope: pinned.scope,
    atomicBatchOwnerIdentity: identity,
    atomicBatchOwnerProvisionerPublicKey: provision.publicKey,
    atomicBatchOwnerProvisioning: provision.provisioning,
    atomicBatchOwnerProvisionDigest: pinned.ownerProvisionDigest,
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
  if (options.previewPlan === true) {
    // Validate the complete selection before reading private keys or config.
    options = { ...options, requests: normalizeHistoricalRestorePlan(options.requests) };
  }
  if (options.restore === true || options.preview === true) {
    for (const key of ["object-id", "version-id"]) {
      if (typeof options[key] !== "string" || !/^[A-Za-z0-9._:-]{1,160}$/.test(options[key])) {
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
    console.log(JSON.stringify(outcome));
    return engine;
  }
  const once = options.once === true || options.once === "true";
  do {
    const summary = await engine.syncOnce();
    console.log(JSON.stringify({ pushed: summary.pushed, pulled: summary.pulled, conflicts: summary.conflicts.length, offline: summary.offline }));
    if (!once) await new Promise((resolve) => setTimeout(resolve, Number(config.scanIntervalMs) || 5000));
  } while (!once);
  return engine;
}

async function history(options = {}) {
  const objectId = options["object-id"];
  // Validate user-supplied identifiers before reading private credentials or
  // contacting any endpoint. The HTTP route is for one exact object only.
  if (typeof objectId !== "string" || !/^[A-Za-z0-9._:-]{1,160}$/.test(objectId)) {
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
  // Display only owner-readable metadata; ciphertext, proofs and credentials
  // never enter stdout. These are remote claims, not independently verified
  // historical admission evidence and cannot authorize a restore.
  const summary = {
    objectId,
    signatureVerified: false,
    versions: response.versions.map((record) => ({
      versionId: record.versionId,
      operation: record.operation,
      revision: record.revision,
      deviceId: record.deviceId,
      keyEpoch: record.keyEpoch,
      path: record.metadata.path,
      tombstone: record.tombstone,
    })),
  };
  console.log(JSON.stringify(summary));
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
  const credentials = await readResumeCredentials(options.credentialsStream || process.stdin);
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

if (require.main === module) {
  const [command = "help", ...rest] = process.argv.slice(2);
  if (command === "start") start({ ...args(rest) }).catch((error) => { console.error(`Sync v2 failed: ${error.message}`); process.exitCode = 1; });
  else if (command === "history") history({ ...args(rest) }).catch((error) => { console.error(`Sync history failed: ${error.message}`); process.exitCode = 1; });
  else if (command === "preview") start({ ...args(rest), preview: true }).catch((error) => { console.error(`Sync preview failed: ${error.message}`); process.exitCode = 1; });
  else if (command === "preview-plan") previewPlan(args(rest)).catch((error) => { console.error(`Sync preview plan failed: ${error.message}`); process.exitCode = 1; });
  else if (command === "restore") start({ ...args(rest), restore: true }).catch((error) => { console.error(`Sync restore failed: ${error.message}`); process.exitCode = 1; });
  else if (command === "resume") resume({ ...args(rest) }).catch((error) => { console.error(`Sync resume failed: ${error.message}`); process.exitCode = 1; });
  else console.log("Root.ark Sync v2\n\nUse: npm run sync:start -- --config .rootark-sync.json --once\nOr: node sync-client/rootark-sync-v2.js history --config <private-config> --object-id <id>\nOr: node sync-client/rootark-sync-v2.js preview --config <private-config> --object-id <id> --version-id <id> (requires independently injected custody and current grant; never mutates files)\nOr: node sync-client/rootark-sync-v2.js preview-plan --config <private-config> --plan-stdin (JSON array of up to 32 {objectId,versionId}; independent custody required; never mutates)\nOr: node sync-client/rootark-sync-v2.js restore --config <private-config> --object-id <id> --version-id <id> (requires signing keys and authorized historical evidence)\nOr: node sync-client/rootark-sync-v2.js resume --config <private-config> --device-id <paused-device-id> --credentials-stdin (pipe private JSON {password,code?} from a separate trusted device)");
}

module.exports = { fileKeyResolver, normalizeTrustedDevicePolicy,
  trustedAtomicBatchWitnessOptions, assertPinnedStrictLocalDeviceIdentity,
  start, history, resume, readResumeCredentials, previewPlan, readHistoricalRestorePlanInput };
