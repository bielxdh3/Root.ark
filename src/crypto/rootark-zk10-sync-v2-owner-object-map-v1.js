"use strict";

// DEV-OFF: cross-protocol cryptographic evidence, never an admission grant.
// Trust anchors, the current authority signing service and its retained floor
// must be provisioned independently of SyncV2 config, the storage server, JWT,
// or the owner-selected mapping. No current runtime wires these dependencies.
const crypto = require("node:crypto");
const { types: { isProxy } } = require("node:util");
const {
  createPublicKey: NATIVE_CREATE_PUBLIC_KEY,
  createHash: NATIVE_CREATE_HASH,
  verify: NATIVE_VERIFY,
  sign: NATIVE_SIGN,
  hashUpdate: NATIVE_HASH_UPDATE,
  hashDigest: NATIVE_HASH_DIGEST,
  randomBytes: NATIVE_RANDOM_BYTES,
  jsonStringify: NATIVE_JSON_STRINGIFY,
  bufferFrom: NATIVE_BUFFER_FROM,
  bufferConcat: NATIVE_BUFFER_CONCAT,
  bufferByteLength: NATIVE_BUFFER_BYTE_LENGTH,
  bufferToString: NATIVE_BUFFER_TO_STRING,
  arrayIncludes: NATIVE_ARRAY_INCLUDES,
  arrayIsArray: NATIVE_ARRAY_IS_ARRAY,
  ownKeys: NATIVE_OWN_KEYS,
  ownDescriptor: NATIVE_OWN_DESCRIPTOR,
  getPrototype: NATIVE_GET_PROTOTYPE,
  hasOwn: NATIVE_HAS_OWN,
  objectCreate: NATIVE_OBJECT_CREATE,
  defineProperty: NATIVE_DEFINE_PROPERTY,
  freeze: NATIVE_FREEZE,
  pickSignedFields: NATIVE_PICK_SIGNED_FIELDS,
} = require("./rootark-zk10-native-intrinsics-v1");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { verifyHistoricalAuthorizationProof } =
  require("../../sync-client/rootark-sync-authorization");
const { verifyPinnedAtomicOwnerProvision } =
  require("../../sync-client/rootark-sync-atomic-owner-provision");
const { snapshotLocalDevicePolicy } =
  require("../../sync-client/rootark-sync-zk1-physical-binding");
const { exact, decode, hex, key, spkiHash, samePublicKey,
  verifyOwnerRotationKeys, verifyOwnerCutoverHistory } =
  require("./rootark-zk10-account-cutover-v1");
const { verifySparseObjectInventoryProof } =
  require("./rootark-zk10-anonymous-object-binding-v1");

const OWNER_DOMAIN = Buffer.from("Root.ark/zk10/sync-v2-owner-object-map/v1\0", "ascii");
const CURRENT_DOMAIN = Buffer.from("Root.ark/zk10/sync-v2-current-map-head/v1\0", "ascii");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SYNC_ID = /^[A-Za-z0-9._:-]{1,160}$/;
const EPOCH = /^epoch-([1-9][0-9]*)$/;
const OWNER_FIELDS = NATIVE_FREEZE([
  "type", "sync_account_id", "sync_store_id", "sync_compartment_id",
  "sync_object_id", "sync_file_id", "sync_version_id", "sync_operation_id",
  "sync_revision_counter", "sync_revision_device_id", "sync_key_epoch",
  "sync_ciphertext_sha256", "zk_immutable_account_id", "zk_account_id",
  "zk_object_id", "zk_object_revision", "zk_ciphertext_sha256", "zk_epoch",
  "owner_generation", "owner_cutover_digest", "mapping_sequence",
  "previous_mapping_digest", "nonce",
]);
const HEAD_FIELDS = NATIVE_FREEZE([
  "type", "challenge", "sync_account_id", "zk_immutable_account_id",
  "mapping_sequence", "mapping_digest",
]);
const DEFAULT_HEAD_TIMEOUT_MS = 1500;
const DEFAULT_MAX_PENDING_HEAD_READS = 16;
const MAX_GLOBAL_PENDING_HEAD_READS = 64;
// Timeout/cancellation returns control to JS, but a noncooperative external
// adapter still owns its underlying promise until it actually settles.
const globalPendingHeadReads = new Set();
const SOURCE_FIELDS = NATIVE_FREEZE([
  "identity", "provisioning", "provisionerPublicKey", "provisioningDigest",
  "witnessPublicKey", "casPublicKey", "scope", "pinnedDevicePolicy", "currentDevicePolicy",
]);
const ZK_FIELDS = NATIVE_FREEZE([
  "immutableAccountId", "ownerRootPublicKey", "ownerCutoverHistory",
  "ownerRotations", "independentlyRetainedCutoverDigest",
]);
const AUTHORITY_FIELDS = NATIVE_FREEZE([
  "pinnedPublicKey", "independentlyRetainedFloor", "readCurrentHead",
]);
const INPUT_FIELDS = NATIVE_FREEZE([
  "sourceOperation", "zkObject", "zkMembershipProof", "ownerMapping",
]);

function deny() {
  throw Object.assign(new Error("ZK10_SYNC_V2_MAP_UNVERIFIED"),
    { code: "ZK10_SYNC_V2_MAP_UNVERIFIED" });
}
function number(value) {
  if (!Number.isSafeInteger(value) || value < 1) deny();
  return value;
}
function id(value) {
  if (typeof value !== "string" || !SYNC_ID.test(value)) deny();
  return value;
}
function uuid(value) {
  if (typeof value !== "string" || !UUID.test(value)) deny();
  return value;
}
function sha(bytes) {
  const hash = NATIVE_CREATE_HASH("sha256");
  NATIVE_HASH_UPDATE.call(hash, bytes);
  return NATIVE_HASH_DIGEST.call(hash, "hex");
}
function signedBytes(domain, payload) {
  return NATIVE_BUFFER_CONCAT([domain, NATIVE_BUFFER_FROM(NATIVE_JSON_STRINGIFY(payload), "utf8")]);
}
function ownPayload(value) {
  const p = exact(value, OWNER_FIELDS);
  if (p.type !== "rootark-zk10-sync-v2-owner-object-map/v1") deny();
  uuid(p.sync_account_id);
  uuid(p.sync_store_id);
  for (const field of ["sync_compartment_id", "sync_object_id", "sync_file_id",
    "sync_version_id", "sync_operation_id", "sync_revision_device_id"]) id(p[field]);
  number(p.sync_revision_counter);
  number(p.sync_key_epoch);
  for (const field of ["zk_immutable_account_id", "zk_account_id", "zk_object_id"]) {
    decode(p[field], 16);
  }
  number(p.zk_object_revision);
  number(p.zk_epoch);
  number(p.owner_generation);
  number(p.mapping_sequence);
  for (const field of ["sync_ciphertext_sha256", "zk_ciphertext_sha256",
    "owner_cutover_digest"]) hex(p[field]);
  if (p.previous_mapping_digest !== null) hex(p.previous_mapping_digest);
  if ((p.mapping_sequence === 1) !== (p.previous_mapping_digest === null)) deny();
  decode(p.nonce, 32);
  return p;
}
function unpackMap(value) {
  const signed = exact(value, [...OWNER_FIELDS, "signature"]);
  const payload = NATIVE_FREEZE(ownPayload(NATIVE_PICK_SIGNED_FIELDS(signed, OWNER_FIELDS)));
  return { payload, signature: decode(signed.signature, 64) };
}
function signOwnerObjectMap(unsigned, privateKey) {
  try {
    const payload = ownPayload(unsigned);
    return NATIVE_FREEZE({ ...payload,
      signature: NATIVE_BUFFER_TO_STRING.call(
        NATIVE_SIGN(null, signedBytes(OWNER_DOMAIN, payload), key(privateKey, "private")),
        "base64url") });
  } catch (_) { deny(); }
}
function digestOwnerObjectMap(signed) {
  try {
    const { payload, signature } = unpackMap(signed);
    return sha(NATIVE_BUFFER_CONCAT([signedBytes(OWNER_DOMAIN, payload), signature]));
  } catch (_) { deny(); }
}
function currentHeadPayload(value) {
  const p = exact(value, HEAD_FIELDS);
  if (p.type !== "rootark-zk10-sync-v2-current-map-head/v1") deny();
  decode(p.challenge, 32);
  uuid(p.sync_account_id);
  decode(p.zk_immutable_account_id, 16);
  number(p.mapping_sequence);
  hex(p.mapping_digest);
  return p;
}
// Authority-side test primitive. Only a separately pinned external signer is
// entitled to produce this response; signing a hard-coded head is not custody.
function signCurrentMappingHead(unsigned, privateKey) {
  try {
    const payload = currentHeadPayload(unsigned);
    return NATIVE_FREEZE({ ...payload,
      signature: NATIVE_BUFFER_TO_STRING.call(
        NATIVE_SIGN(null, signedBytes(CURRENT_DOMAIN, payload), key(privateKey, "private")),
        "base64url") });
  } catch (_) { deny(); }
}
function bytes(value, max = 12 * 1024 * 1024) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)
    || value.length > Math.ceil(max * 4 / 3) + 4) deny();
  const out = NATIVE_BUFFER_FROM(value, "base64url");
  if (out.length > max || NATIVE_BUFFER_TO_STRING.call(out, "base64url") !== value) deny();
  return out;
}
// Snapshot attacker data before asynchronous signature checks. JSON.stringify
// on an accessor/Proxy can change a field after it was bound to a signature.
function copyJson(value, depth = 0, budget = { nodes: 0, bytes: 0 }) {
  if (++budget.nodes > 20000) deny();
  // A Proxy can return different legitimate signed records from successive
  // get traps. A one-time descriptor snapshot avoids repeated reads; reject
  // proxies altogether rather than trusting arbitrary synthetic descriptors.
  if (isProxy(value)) deny();
  if (typeof value === "string") {
    budget.bytes += NATIVE_BUFFER_BYTE_LENGTH(value, "utf8");
    if (budget.bytes > 9 * 1024 * 1024) deny();
  }
  if (value === null || typeof value === "string"
    || typeof value === "number" || typeof value === "boolean") return value;
  if (depth > 8 || !value || typeof value !== "object") deny();
  const array = NATIVE_ARRAY_IS_ARRAY(value);
  if (!array && !NATIVE_ARRAY_INCLUDES.call([Object.prototype, null], NATIVE_GET_PROTOTYPE(value))) deny();
  const names = NATIVE_OWN_KEYS(value);
  if (names.length > 100 || (array && names.length !== value.length + 1)) deny();
  const result = array ? [] : NATIVE_OBJECT_CREATE(null);
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    if (array && name === "length") continue;
    if (typeof name !== "string" || name === "__proto__"
      || name === "constructor" || name === "toJSON") deny();
    const descriptor = NATIVE_OWN_DESCRIPTOR(value, name);
    if (!descriptor || !NATIVE_HAS_OWN(descriptor, "value")) deny();
    if (array && (!/^(0|[1-9][0-9]*)$/.test(name) || Number(name) >= value.length)) deny();
    budget.bytes += NATIVE_BUFFER_BYTE_LENGTH(name, "utf8");
    if (budget.bytes > 9 * 1024 * 1024) deny();
    NATIVE_DEFINE_PROPERTY(result, name, { value: copyJson(descriptor.value, depth + 1, budget),
      enumerable: true, configurable: true, writable: true });
  }
  return result;
}

function headLimits(value) {
  const limits = value === undefined
    ? { headTimeoutMs: DEFAULT_HEAD_TIMEOUT_MS,
      maxPendingHeadReads: DEFAULT_MAX_PENDING_HEAD_READS }
    : exact(value, ["headTimeoutMs", "maxPendingHeadReads"]);
  if (!Number.isSafeInteger(limits.headTimeoutMs)
    || limits.headTimeoutMs < 5 || limits.headTimeoutMs > 5000
    || !Number.isSafeInteger(limits.maxPendingHeadReads)
    || limits.maxPendingHeadReads < 1
    || limits.maxPendingHeadReads > MAX_GLOBAL_PENDING_HEAD_READS) deny();
  return limits;
}

function createOwnerObjectMapVerifier(config, headReadOptions) {
  try {
    const { headTimeoutMs, maxPendingHeadReads } = headLimits(headReadOptions);
    const c = exact(config, ["sourceAuthority", "zkAuthority", "mappingAuthority"]);
    const s = exact(c.sourceAuthority, SOURCE_FIELDS);
    const z = exact(c.zkAuthority, ZK_FIELDS);
    const a = exact(c.mappingAuthority, AUTHORITY_FIELDS);
    const sourceIdentity = exact(s.identity,
      ["accountId", "storeId", "username", "compartmentId"]);
    const identity = verifyPinnedAtomicOwnerProvision({ identity: sourceIdentity,
      scope: s.scope, provisioning: s.provisioning,
      provisionerPublicKey: s.provisionerPublicKey,
      expectedDigest: s.provisioningDigest,
      witnessPublicKey: s.witnessPublicKey, casPublicKey: s.casPublicKey }).identity;
    const localPolicy = snapshotLocalDevicePolicy(s.pinnedDevicePolicy);
    if (typeof s.currentDevicePolicy !== "function" || localPolicy.username !== identity.username
      || identity.compartmentId !== id(identity.compartmentId)) deny();
    decode(z.immutableAccountId, 16);
    const ownerRoot = key(z.ownerRootPublicKey, "public");
    // The underlying cutover verifier may inspect history entries once for
    // signature/root and again for digest. Snapshot the entire chain before
    // either operation; never let a mutable caller splice two signed heads.
    const rotations = copyJson(z.ownerRotations);
    const cutoverHistory = copyJson(z.ownerCutoverHistory);
    const ownerKeys = verifyOwnerRotationKeys(rotations, ownerRoot, z.immutableAccountId);
    const cutover = verifyOwnerCutoverHistory(cutoverHistory, ownerKeys,
      z.immutableAccountId);
    if (cutover.digest !== hex(z.independentlyRetainedCutoverDigest)) deny();
    const authorityKey = key(a.pinnedPublicKey, "public");
    const authorityHash = spkiHash(authorityKey);
    // A forged instance `.export` or `.type` never makes the SAME real
    // owner/provisioner/witness/CAS signer an independent CURRENT authority.
    // A caller-owned KeyObject's kHandle getter ran in key(a.pinnedPublicKey)
    // above. Do not spread `ownerKeys` now: Array.prototype[Symbol.iterator]
    // may omit the owner key entirely and silently authorize the SAME signer.
    const checkIndependent = (role) => {
      if (samePublicKey(authorityKey, role) || authorityHash === spkiHash(role)) deny();
    };
    for (let index = 0; index < ownerKeys.length; index += 1) {
      checkIndependent(ownerKeys[index]);
    }
    checkIndependent(nativePublic(s.provisionerPublicKey));
    checkIndependent(nativePublic(s.witnessPublicKey));
    checkIndependent(nativePublic(s.casPublicKey));
    const floor = exact(a.independentlyRetainedFloor, ["sequence", "digest"]);
    number(floor.sequence);
    hex(floor.digest);
    if (typeof a.readCurrentHead !== "function") deny();
    const pendingHeadReads = new Set();
    async function boundedCurrentHead(challenge, signal) {
      if (signal?.aborted || pendingHeadReads.size >= maxPendingHeadReads
        || globalPendingHeadReads.size >= MAX_GLOBAL_PENDING_HEAD_READS) deny();
      const controller = new AbortController();
      // Timers can run late if an adapter blocks the JS event loop. Reject a
      // result even if its microtask beats an overdue timeout callback.
      const expiresAt = process.hrtime.bigint() + BigInt(headTimeoutMs) * 1000000n;
      let timer, onCancel;
      const deadline = new Promise((resolve) => {
        timer = setTimeout(() => {
          controller.abort();
          resolve({ settled: false });
        }, headTimeoutMs);
      });
      const cancelled = new Promise((resolve) => {
        if (signal) {
          onCancel = () => {
            controller.abort();
            resolve({ settled: false });
          };
          signal.addEventListener("abort", onCancel, { once: true });
        }
      });
      // Reserve capacity BEFORE invoking an untrusted async adapter. A late
      // result never re-enters verification and never frees its slot early.
      const pending = Promise.resolve().then(() => {
        if (controller.signal.aborted) deny();
        return a.readCurrentHead(challenge, { signal: controller.signal });
      });
      pendingHeadReads.add(pending);
      globalPendingHeadReads.add(pending);
      void pending.then(
        () => { pendingHeadReads.delete(pending); globalPendingHeadReads.delete(pending); },
        () => { pendingHeadReads.delete(pending); globalPendingHeadReads.delete(pending); });
      try {
        const result = await Promise.race([
          pending.then((value) => ({ settled: true, value }),
            () => ({ settled: false })),
          deadline, cancelled,
        ]);
        if (!result.settled || controller.signal.aborted || signal?.aborted
          || process.hrtime.bigint() >= expiresAt) {
          controller.abort();
          deny();
        }
        return result.value;
      } finally {
        clearTimeout(timer);
        if (onCancel) signal.removeEventListener("abort", onCancel);
      }
    }
    let lastAcceptedSequence = 0;
    return async function verifyOwnerSignedMapping(input, control) {
      try {
        const signal = control === undefined ? undefined : exact(control, ["signal"]).signal;
        if (signal !== undefined && !(signal instanceof AbortSignal)) deny();
        if (signal?.aborted) deny();
        const r = exact(input, INPUT_FIELDS);
        const { payload, signature } = unpackMap(r.ownerMapping);
        const digest = sha(NATIVE_BUFFER_CONCAT([signedBytes(OWNER_DOMAIN, payload), signature]));
    if (!NATIVE_VERIFY(null, signedBytes(OWNER_DOMAIN, payload),
          ownerKeys[ownerKeys.length - 1], signature)
          || payload.owner_cutover_digest !== cutover.digest
          || payload.owner_generation !== cutover.statement.generation
          || payload.zk_immutable_account_id !== z.immutableAccountId
          || payload.zk_account_id !== cutover.statement.zk_account_id
          || payload.sync_account_id !== identity.accountId
          || payload.sync_store_id !== identity.storeId
          || payload.sync_compartment_id !== identity.compartmentId
          || payload.mapping_sequence <= lastAcceptedSequence) deny();
        if (payload.mapping_sequence === floor.sequence) {
          if (digest !== floor.digest) deny();
        } else if (payload.mapping_sequence === floor.sequence + 1) {
          if (payload.previous_mapping_digest !== floor.digest) deny();
        } else deny();

        const operation = copyJson(r.sourceOperation);
        if (NATIVE_BUFFER_BYTE_LENGTH(NATIVE_JSON_STRINGIFY(operation), "utf8") > 9 * 1024 * 1024) deny();
        const normalized = protocol.validateStoredOperation(operation);
        if (!normalized.authorization || normalized.operation === "delete"
          || normalized.tombstone || normalized.revision.counter < 1
          || normalized.revision.deviceId !== normalized.deviceId) deny();
        const epochMatch = EPOCH.exec(normalized.keyEpoch);
        if (!epochMatch || !Number.isSafeInteger(Number(epochMatch[1]))) deny();
        await verifyHistoricalAuthorizationProof(normalized.authorization, normalized, localPolicy);
        if (payload.sync_object_id !== normalized.objectId
          || payload.sync_file_id !== normalized.fileId
          || payload.sync_version_id !== normalized.versionId
          || payload.sync_operation_id !== normalized.operationId
          || payload.sync_revision_counter !== normalized.revision.counter
          || payload.sync_revision_device_id !== normalized.revision.deviceId
          || payload.sync_key_epoch !== Number(epochMatch[1])
          || payload.sync_ciphertext_sha256 !== sha(bytes(normalized.ciphertext))) deny();

        const target = exact(r.zkObject, ["object_id", "revision", "epoch", "ciphertext"]);
        decode(target.object_id, 16);
        number(target.revision);
        number(target.epoch);
        const targetDigest = sha(bytes(target.ciphertext));
        if (payload.zk_object_id !== target.object_id
          || payload.zk_object_revision !== target.revision
          || payload.zk_epoch !== target.epoch
          || payload.zk_ciphertext_sha256 !== targetDigest) deny();
        verifySparseObjectInventoryProof(z.immutableAccountId, cutover.statement.generation,
          { object_id: target.object_id, revision: target.revision,
            ciphertext_sha256: targetDigest },
          r.zkMembershipProof, cutover.statement.inventory_head);

        // Generate the challenge here. A signed old head with an old nonce is
        // not acceptable after a restart, even if its Ed25519 signature is valid.
        const challenge = NATIVE_BUFFER_TO_STRING.call(NATIVE_RANDOM_BYTES(32), "base64url");
        const wire = exact(await boundedCurrentHead(challenge, signal),
          [...HEAD_FIELDS, "signature"]);
        const head = currentHeadPayload(NATIVE_PICK_SIGNED_FIELDS(wire, HEAD_FIELDS));
        if (head.challenge !== challenge || head.mapping_digest !== digest
          || head.mapping_sequence !== payload.mapping_sequence
          || head.sync_account_id !== identity.accountId
          || head.zk_immutable_account_id !== z.immutableAccountId
      || !NATIVE_VERIFY(null, signedBytes(CURRENT_DOMAIN, head),
            authorityKey, decode(wire.signature, 64))) deny();
        const live = snapshotLocalDevicePolicy(s.currentDevicePolicy());
        const device = normalized.deviceId;
        if (live.username !== localPolicy.username
          || live.trustedDevicePublicKeys[device] !== localPolicy.trustedDevicePublicKeys[device]
          || NATIVE_ARRAY_INCLUDES.call(live.revokedDeviceIds, device)
          || NATIVE_ARRAY_INCLUDES.call(localPolicy.revokedDeviceIds, device)) deny();
        // Two concurrent readbacks may both be valid. The sequence is consumed
        // only after the awaited authority verification, on the same JS turn.
        if (signal?.aborted || payload.mapping_sequence <= lastAcceptedSequence) deny();
        lastAcceptedSequence = payload.mapping_sequence;
        return NATIVE_FREEZE({
          status: "VERIFIED_SIGNED_SYNC_V2_ZK10_MAPPING_NONAUTHORIZING",
          mappingDigest: digest, mappingSequence: payload.mapping_sequence,
          syncObjectId: payload.sync_object_id, zkObjectId: payload.zk_object_id,
          sourceAuthorizationVerified: true, ownerMappingVerified: true,
          zkSignedInventoryMembershipVerified: true, freshPinnedAuthorityHeadVerified: true,
          authorizesIo: false, independentCustodyProven: false,
          historicalLegacyCompletenessProven: false,
        });
      } catch (_) { deny(); }
    };
  } catch (_) { deny(); }
}
function nativePublic(value) {
  if (value instanceof crypto.KeyObject) return key(value, "public");
  let der;
  if (typeof value === "string") {
    der = decode(value, 44);
  } else if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    der = NATIVE_BUFFER_FROM(value);
    if (der.length !== 44) deny();
  } else deny();
  const result = key(NATIVE_CREATE_PUBLIC_KEY({ key: der,
    format: "der", type: "spki" }), "public");
  if (!result.export({ format: "der", type: "spki" }).equals(der)) deny();
  return result;
}
module.exports = { OWNER_FIELDS, HEAD_FIELDS, signOwnerObjectMap,
  digestOwnerObjectMap, signCurrentMappingHead, createOwnerObjectMapVerifier };
