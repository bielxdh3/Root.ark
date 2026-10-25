"use strict";

// Operator reference for rebuilding a LOST local ciphertext copy from two
// independently addressed remote stores. Only ciphertext crosses this
// boundary. It cannot establish cloud fsync, current revocation on its own,
// permanent remote custody, cross-provider atomicity or an I/O permit.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");
const { computeZk1CiphertextRoot } = require("../crypto/rootark-zk-chunk-root-v1");
const { zk1CloudCopyAddress } = require("./zk1CloudCiphertextReadbackVerifier");
const ownerRoots = require("../../public/client/rootark-zk1-owner-ciphertext-root-checkpoint");
const { recoverSignedCatalogSidecar } = require("./zk1CloudSignedCatalogSidecar");
const { Zk1ExternallyPinnedProviderDomains, spkiFingerprint } =
  require("./zk1ExternallyPinnedProviderDomains");
const { verifyFreshOwnerDeviceRestoreAuthority } =
  require("./zk1FreshOwnerDeviceRestoreAuthority");
const { verifyOwnerProviderVersionPin } = require("./zk1OwnerProviderVersionPin");
const { createZk1ProviderDeadline, validDeadlineMs, isZk1ProviderDeadline,
  DEFAULT_PROVIDER_DEADLINE_MS } = require("./zk1ProviderDeadline");

function deny() { const e = new Error("ZK_MULTIPROVIDER_RESTORE_DENIED"); e.code = e.message; throw e; }
function copied(value, length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer)
    || (length !== undefined && value.byteLength !== length)) deny();
  return Buffer.from(value);
}
function same(left, right) {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function whole(value, min = 1, max = 100000) {
  if (!Number.isSafeInteger(value) || value < min || value > max) deny();
  return value;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) deny();
  const result = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
    result[field] = descriptor.value;
  }
  return result;
}
function detachedSignedRecord(value) {
  // Detached before any remote await. The history and checkpoint validators
  // enforce the signed schema; this additionally forbids getters/proxies from
  // silently changing an already inspected trust input in flight.
  if (value === null) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny();
  const clean = {};
  const keys = Reflect.ownKeys(value);
  if (keys.length < 1 || keys.length > 32) deny();
  for (const key of keys) {
    if (typeof key !== "string" || key.length > 100) deny();
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !Object.hasOwn(d, "value")
      || !(typeof d.value === "string" || Number.isSafeInteger(d.value)
        || d.value === null)) deny();
    clean[key] = d.value;
  }
  return Object.freeze(clean);
}
function cloneOperation(value) {
  const op = exact(value, ["operation_id", "expected_sequence", "expected_root",
    "object_id", "revision", "epoch", "ciphertext_sha256"]);
  return { operation_id: copied(op.operation_id, 16),
    expected_sequence: whole(op.expected_sequence, 0, inventory.MAX_ENTRIES),
    expected_root: copied(op.expected_root, 32), object_id: copied(op.object_id, 16),
    revision: whole(op.revision), epoch: whole(op.epoch, 0),
    ciphertext_sha256: copied(op.ciphertext_sha256, 32) };
}
function requireOwnerVersionPins(values) {
  // This is a protocol requirement, independent of all request/constructor
  // flags. An unpinned legacy inventory can still be inspected via its signed
  // catalog, but cannot release cloud ciphertext through this restore API.
  if (!Array.isArray(values) || values.length < 2 || values.length > 3
    || Reflect.ownKeys(values).length !== values.length + 1
    || values.some((item) => !item || typeof item !== "object"
      || !Object.hasOwn(item, "ownerSignedVersionPin"))) deny();
}
function pinnedReaders(values, providerDomains, scope, operation, root, byteLength,
  ownerHead, ownerPublicKey) {
  requireOwnerVersionPins(values);
  const result = [];
  const names = new Set();
  const namespaces = new Set();
  for (const value of values) {
    const fields = ["cloudReader", "provider", "expectedReaderContext",
      "pinnedDriveFileId", "domainAttestation", "ownerSignedVersionPin"];
    const item = exact(value, fields);
    const reader = item.cloudReader;
    if (!reader || typeof reader !== "object"
      || !["s3", "gdrive", "webdav"].includes(item.provider)
      || names.has(item.provider) || reader.status?.()?.provider !== item.provider
      || reader.enabled?.() !== true
      || !["key", "download", "resolveInventoryContext", "zk1StorageNamespace"]
        .every((name) => typeof reader[name] === "function")
      || !/^[a-f0-9]{64}$/.test(item.expectedReaderContext)) deny();
    const namespace = reader.zk1StorageNamespace();
    if (typeof namespace !== "string" || !/^[a-f0-9]{64}$/.test(namespace)
      || namespaces.has(namespace)
      || (item.provider === "gdrive"
        ? !/^[A-Za-z0-9_-]{1,256}$/.test(item.pinnedDriveFileId)
        : item.pinnedDriveFileId !== null)) deny();
    names.add(item.provider);
    namespaces.add(namespace);
    const address = zk1CloudCopyAddress({ scope, operationId: operation.operation_id });
    const providerObjectKey = reader.key(address.folder, address.name, "uploads");
    const versionPin = verifyOwnerProviderVersionPin({
      signedPin: item.ownerSignedVersionPin, pinnedOwnerPublicKey: ownerPublicKey,
      scope, operation, root, byteLength, ownerHead,
      target: { provider: item.provider, namespaceIdentity: namespace,
        expectedReaderContext: item.expectedReaderContext, providerObjectKey,
        pinnedDriveFileId: item.pinnedDriveFileId },
    });
    result.push({ reader, provider: item.provider, namespace,
      context: item.expectedReaderContext, driveId: item.pinnedDriveFileId,
      domainAttestation: item.domainAttestation,
      ownerPinnedObjectKey: providerObjectKey,
      providerVersionId: versionPin.providerVersionId,
      providerEtag: versionPin.providerEtag, ownerSignedVersionPinVerified: true });
  }
  providerDomains.verify({ targets: result.map((item) => ({
    provider: item.provider, namespaceIdentity: item.namespace,
    expectedReaderContext: item.context, pinnedDriveFileId: item.driveId,
    domainAttestation: item.domainAttestation,
  })), scope, nowSeconds: Math.floor(Date.now() / 1000) });
  return result;
}
async function exactGet(target, scope, operation, root, lengths, byteLength, deadline) {
  let dir;
  try {
    const address = zk1CloudCopyAddress({ scope, operationId: operation.operation_id });
    const key = target.reader.key(address.folder, address.name, "uploads");
    if (typeof key !== "string"
      || !key.endsWith(`/uploads/${address.folder}/${address.name}`)
      || (target.ownerPinnedObjectKey !== null && key !== target.ownerPinnedObjectKey)
      || await deadline.run(() => target.reader.resolveInventoryContext()) !== target.context
      || target.reader.zk1StorageNamespace() !== target.namespace) deny();
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-cloud-recovery-"));
    const destination = path.join(dir, "opaque.ct");
    const ok = await deadline.run((signal) => target.reader.download(address.folder, address.name, destination,
      "uploads", () => !signal.aborted, { maxBytes: byteLength,
        ...(target.driveId === null ? {} : { providerFileId: target.driveId }),
        ...(target.providerVersionId === null ? {} : { providerVersionId: target.providerVersionId }),
        ...(target.providerEtag === null ? {} : { expectedEtag: target.providerEtag }),
        abortSignal: signal }));
    if (ok !== true || await deadline.run(() => target.reader.resolveInventoryContext()) !== target.context
      || target.reader.zk1StorageNamespace() !== target.namespace) deny();
    const named = fs.lstatSync(destination, { bigint: true });
    if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1n
      || named.size !== BigInt(byteLength)) deny();
    const fd = fs.openSync(destination,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    let data;
    try {
      const before = fs.fstatSync(fd, { bigint: true });
      if (!before.isFile() || before.dev !== named.dev || before.ino !== named.ino
        || before.size !== named.size || before.nlink !== 1n) deny();
      data = fs.readFileSync(fd);
      const after = fs.fstatSync(fd, { bigint: true });
      const now = fs.lstatSync(destination, { bigint: true });
      if (data.length !== byteLength || after.dev !== before.dev || after.ino !== before.ino
        || after.mtimeNs !== before.mtimeNs || after.size !== before.size
        || now.ino !== before.ino || now.dev !== before.dev || now.nlink !== 1n
        || now.isSymbolicLink()) deny();
    } finally { fs.closeSync(fd); }
    const pieces = [];
    let offset = 0;
    for (const length of lengths) { pieces.push(data.subarray(offset, offset + length)); offset += length; }
    if (!same(crypto.createHash("sha256").update(data).digest(), operation.ciphertext_sha256)
      || !same(computeZk1CiphertextRoot(pieces), root)) deny();
    return { data, evidence: Object.freeze({ provider: target.provider,
      namespaceIdentity: target.namespace, providerObjectKey: key,
      providerFileId: target.driveId, providerVersionId: target.providerVersionId,
      providerEtag: target.providerEtag, byteLength }) };
  } finally {
    if (dir) fs.rmSync(dir, { recursive: true, force: true, maxRetries: 4 });
  }
}

class Zk1MultiproviderCiphertextRestore {
  #publicKey;
  #signerId;
  #pinnedOwner;
  #ownerHead;
  #minimumHead;
  #minimumSnapshot;
  #authorize;
  #providerDomains;
  #deviceGrant;
  #freshDeviceState;
  #ioDeadlineMs;
  constructor({ pinnedInventoryPublicKey, pinnedInventorySignerKeyId, pinnedOwner,
    pinnedOwnerHead, independentInventoryFloor, assertCurrentAuthorization,
    providerDomainPinset, signedCurrentDeviceGrant,
    fetchFreshSignedDeviceState, independentOwnerSpkiSha256,
    ioDeadlineMs = DEFAULT_PROVIDER_DEADLINE_MS } = {}) {
    const head = exact(pinnedOwnerHead, ["revision", "digest", "epoch"]);
    const floor = exact(independentInventoryFloor, ["minimumHead", "minimumSnapshot"]);
    const min = exact(floor.minimumHead, ["sequence", "root"]);
    const owner = exact(pinnedOwner, ["scope", "deviceId", "signerKeyId", "publicKey"]);
    const ownerScope = exact(owner.scope, ["account_id", "compartment_id", "keyring_id"]);
    if (!(pinnedInventoryPublicKey instanceof crypto.KeyObject)
      || pinnedInventoryPublicKey.type !== "public"
      || pinnedInventoryPublicKey.asymmetricKeyType !== "ed25519"
      || !["account_id", "compartment_id", "keyring_id"].every(
        (key) => typeof ownerScope[key] === "string")
      || typeof owner.deviceId !== "string"
      || !owner.publicKey || owner.publicKey.type !== "public"
      || owner.publicKey.algorithm?.name !== "Ed25519"
      || typeof assertCurrentAuthorization !== "function"
      || !(providerDomainPinset instanceof Zk1ExternallyPinnedProviderDomains)
      || typeof fetchFreshSignedDeviceState !== "function"
      || !signedCurrentDeviceGrant || typeof signedCurrentDeviceGrant !== "object") deny();
    let actualOwnerFingerprint;
    try {
      actualOwnerFingerprint = spkiFingerprint(crypto.KeyObject.from(owner.publicKey));
    } catch (_) { deny(); }
    if (typeof independentOwnerSpkiSha256 !== "string"
      || !/^[a-f0-9]{64}$/.test(independentOwnerSpkiSha256)
      || actualOwnerFingerprint !== independentOwnerSpkiSha256) deny();
    this.#publicKey = pinnedInventoryPublicKey;
    this.#signerId = copied(pinnedInventorySignerKeyId, 16);
    this.#pinnedOwner = Object.freeze({ scope: Object.freeze({ ...ownerScope }),
      deviceId: owner.deviceId, signerKeyId: copied(owner.signerKeyId, 16),
      publicKey: owner.publicKey });
    this.#ownerHead = { revision: whole(head.revision),
      digest: copied(head.digest, 32), epoch: whole(head.epoch) };
    this.#minimumHead = { sequence: whole(min.sequence, 0, inventory.MAX_ENTRIES),
      root: copied(min.root, 32) };
    this.#minimumSnapshot = copied(floor.minimumSnapshot);
    if (this.#minimumSnapshot.length > inventory.MAX_SNAPSHOT_BYTES) deny();
    this.#authorize = assertCurrentAuthorization;
    this.#providerDomains = providerDomainPinset;
    this.#deviceGrant = detachedSignedRecord(signedCurrentDeviceGrant);
    this.#freshDeviceState = fetchFreshSignedDeviceState;
    this.#ioDeadlineMs = validDeadlineMs(ioDeadlineMs);
  }
  async #current(operation) {
    // A caller-supplied active Boolean is never enough: the owner authority
    // and actual enrolled device must BOTH sign a fresh nonce per request.
    const freshOwner = await verifyFreshOwnerDeviceRestoreAuthority({
      signedDeviceGrant: this.#deviceGrant,
      pinnedOwnerPublicKey: this.#pinnedOwner.publicKey,
      fetchSignedCurrentDeviceState: this.#freshDeviceState,
      scope: this.#pinnedOwner.scope, operation,
      ownerHead: this.#ownerHead,
    });
    const result = await this.#authorize({
      operationId: Buffer.from(operation.operation_id),
      objectId: Buffer.from(operation.object_id),
      revision: operation.revision, ciphertextEpoch: operation.epoch,
      ownerHeadRevision: this.#ownerHead.revision,
      ownerHeadDigest: Buffer.from(this.#ownerHead.digest),
      ownerHeadEpoch: this.#ownerHead.epoch,
    });
    if (!result || result.active !== true || result.currentManifestRevision !== this.#ownerHead.revision
      || result.currentEpoch !== this.#ownerHead.epoch
      || !Buffer.isBuffer(result.currentManifestDigest)
      || !same(result.currentManifestDigest, this.#ownerHead.digest)) deny();
    return freshOwner;
  }
  checkRequesterDeviceIdentity(value) {
    try {
      const proof = exact(value, ["authorized", "deviceId", "authorizationKeyId"]);
      return proof.authorized === true
        && proof.deviceId === this.#deviceGrant.device_id
        && proof.authorizationKeyId === this.#deviceGrant.authorization_key_id;
    } catch (_) { return false; }
  }
  async recheckBeforeEgress(operation) {
    // Rejection-only API: it neither reads nor releases ciphertext and cannot
    // be substituted with a caller-supplied Boolean authorization callback.
    try {
      const proof = await this.#current(cloneOperation(operation));
      return Object.freeze({ expiresAtSeconds: proof.expiresAtSeconds });
    } catch (_) { deny(); }
  }
  async restoreExact(input, { abortSignal, deadline } = {}) {
    let returned;
    if (deadline !== undefined && !isZk1ProviderDeadline(deadline)) deny();
    const limit = deadline || createZk1ProviderDeadline({
      deadlineMs: this.#ioDeadlineMs, parentSignal: abortSignal });
    try {
      const r = exact(input, ["scope", "operation", "signedCommittedProof",
        "signedSnapshot", "snapshotNonce", "committedProofChain", "ownerCheckpoint",
        "ownerHistoryCheckpoint", "previousOwnerHistoryProof", "expectedCiphertextRoot",
        "chunkLengths", "readers", "minimumMatchingProviders"]);
      const scope = inventory.normalizeScope(r.scope);
      if (["account_id", "compartment_id", "keyring_id"].some((name) =>
        scope[name].toString("base64url") !== this.#pinnedOwner.scope[name])) deny();
      const operation = cloneOperation(r.operation);
      const proofBytes = copied(r.signedCommittedProof);
      const snapshot = copied(r.signedSnapshot);
      const nonce = copied(r.snapshotNonce, 32);
      const root = copied(r.expectedCiphertextRoot, 32);
      if (proofBytes.length > inventory.MAX_COMMITTED_PROOF_BYTES
        || snapshot.length > inventory.MAX_SNAPSHOT_BYTES
        || !Array.isArray(r.chunkLengths) || r.chunkLengths.length < 1
        || r.chunkLengths.length > 16
        || Reflect.ownKeys(r.chunkLengths).length !== r.chunkLengths.length + 1) deny();
      const lengths = r.chunkLengths.map((value) => whole(value, 1, 1024 * 1024));
      const byteLength = lengths.reduce((sum, value) => sum + value, 0);
      if (byteLength > 16 * 1024 * 1024) deny();
      if (r.committedProofChain !== null && (!Array.isArray(r.committedProofChain)
        || r.committedProofChain.length > inventory.MAX_ENTRIES
        || Reflect.ownKeys(r.committedProofChain).length !== r.committedProofChain.length + 1)) deny();
      const chain = r.committedProofChain === null ? null : [];
      if (chain) for (let i = 0; i < r.committedProofChain.length; ++i) {
        const entry = Object.getOwnPropertyDescriptor(r.committedProofChain, String(i));
        if (!entry || !Object.hasOwn(entry, "value")) deny();
        chain.push(copied(entry.value));
      }
      const readers = pinnedReaders(r.readers, this.#providerDomains, scope,
        operation, root, byteLength, this.#ownerHead, this.#pinnedOwner.publicKey);
      const quorum = whole(r.minimumMatchingProviders, 2, readers.length);
      const checkpoint = detachedSignedRecord(r.ownerCheckpoint);
      const ownerHistoryCheckpoint = detachedSignedRecord(r.ownerHistoryCheckpoint);
      // An ancestor is NOT signed wire data: verifyOwnerCheckpoint brands its
      // frozen result in a module-private WeakMap. Copying even identical
      // public fields loses that proof and breaks valid history seq > 1.
      // Keep the exact in-process object; the pinned-owner verifier rejects
      // unbranded JSON, forged flags, foreign signers and broken continuity.
      const previousHistoryProof = r.previousOwnerHistoryProof;
      if (operation.epoch > this.#ownerHead.epoch) deny();
      // These two independently pinned signatures MUST verify before any GET.
      const signed = await inventory.verifyCommittedEntryProof({
        serialized: proofBytes, pinnedPublicKey: this.#publicKey,
        pinnedSignerKeyId: this.#signerId, expectedScope: scope, operation });
      if (signed.outcome !== "COMMITTED_IN_SIGNED_LEDGER") deny();
      const catalog = await inventory.verifySnapshot({
        serialized: snapshot, pinnedPublicKey: this.#publicKey,
        pinnedSignerKeyId: this.#signerId, expectedScope: scope,
        requested: { object_id: operation.object_id, revision: operation.revision,
          epoch: operation.epoch, ciphertext_sha256: operation.ciphertext_sha256 },
        minimumHead: this.#minimumHead, minimumSnapshot: this.#minimumSnapshot,
        committedProofChain: chain, nonce,
      });
      if (catalog.outcome !== "PRESENT" || catalog.sequence < signed.sequence) deny();
      const ownerProof = await ownerRoots.verifyOwnerCiphertextRootCheckpoint({
        checkpoint,
        ownerHistoryCheckpoint,
        previousHistoryProof,
        pinnedOwner: this.#pinnedOwner,
        expected: {
          manifestRevision: this.#ownerHead.revision,
          manifestDigest: this.#ownerHead.digest,
          manifestEpoch: this.#ownerHead.epoch,
          objectId: operation.object_id.toString("base64url"),
          objectRevision: operation.revision,
          ciphertextEpoch: operation.epoch, ciphertextRoot: root,
        },
      });
      if (ownerProof.trustedOwnerSignatureVerified !== true
        || ownerProof.manifestCheckpointVerified !== true
        || ownerProof.authorizesProtectedIo !== false) deny();
      limit.assertActive();
      await this.#current(operation);
      limit.assertActive();
      const good = [];
      const failed = [];
      for (const provider of readers) {
        if (good.length >= quorum) break;
        try { good.push(await exactGet(provider, scope, operation, root, lengths, byteLength, limit)); }
        catch (_) {
          if (limit.signal.aborted) deny();
          failed.push(provider.provider);
        }
      }
      if (good.length < quorum) deny();
      for (const match of good.slice(1)) if (!same(match.data, good[0].data)) deny();
      this.#providerDomains.verify({ targets: readers.map((item) => ({
        provider: item.provider, namespaceIdentity: item.namespace,
        expectedReaderContext: item.context, pinnedDriveFileId: item.driveId,
        domainAttestation: item.domainAttestation,
      })), scope, nowSeconds: Math.floor(Date.now() / 1000) });
      await this.#current(operation);
      limit.assertActive();
      const ciphertext = Buffer.from(good[0].data);
      returned = Object.freeze({ status: "SIGNED_CATALOG_AND_OWNER_ROOT_CLOUD_RESTORE",
        ciphertext, ciphertextSha256: Buffer.from(operation.ciphertext_sha256),
        ciphertextRoot: Buffer.from(root), operationId: Buffer.from(operation.operation_id),
        signedCommittedProof: proofBytes, signedSnapshot: snapshot,
        signedInventoryRoot: Buffer.from(catalog.root),
        signedInventorySequence: catalog.sequence,
        verifiedProviders: Object.freeze(good.map(({ evidence }) => evidence)),
        failedProviders: Object.freeze(failed),
        serverHasPlaintext: false, signedCurrentDeviceStateRequired: true,
        ownerSignedProviderVersionsVerified: readers.every((reader) => reader.ownerSignedVersionPinVerified),
        administratorSignaturesVerified: true,
        independentAdministratorCustodyProven: false,
        providerPhysicalIndependenceProven: false,
        currentAuthorizationCallbackPassed: true,
        externalOwnerPinCustodyVerifiedByModule: false,
        remoteDurabilityProven: false, authorizesProductionRestore: false });
      return returned;
    } catch (_) { deny(); }
    finally { if (!deadline) limit.close(); }
  }
  // Disaster path when the local SQLite catalog and plaintext-free backup are
  // both missing. Fetch independently matching signed sidecar bytes first;
  // restoreExact then verifies their full Ed25519 history, owner root and live
  // current authorization BEFORE reading or releasing ciphertext. When the
  // signed owner history has sequence > 1, only an already verified in-process
  // predecessor proof can satisfy its private WeakMap brand. A cloud sidecar
  // can retain the signed wire, but CANNOT serialize the verified proof brand.
  async restoreFromCloudCatalog({ scope, operation, catalogReaders, readers,
    minimumMatchingProviders = 2, minimumMatchingCatalogProviders = 2,
    previousOwnerHistoryProof = null } = {}, { abortSignal } = {}) {
    const limit = createZk1ProviderDeadline({
      deadlineMs: this.#ioDeadlineMs, parentSignal: abortSignal });
    try {
      requireOwnerVersionPins(readers);
      const fixed = cloneOperation(operation);
      const checkedScope = inventory.normalizeScope(scope);
      if (["account_id", "compartment_id", "keyring_id"].some((name) =>
        checkedScope[name].toString("base64url") !== this.#pinnedOwner.scope[name])) deny();
      limit.assertActive();
      await this.#current(fixed);
      limit.assertActive();
      const recovered = await recoverSignedCatalogSidecar({ scope,
        operationId: fixed.operation_id, readers: catalogReaders,
        minimumMatchingProviders: minimumMatchingCatalogProviders,
        providerDomainPinset: this.#providerDomains, deadline: limit,
        // Cloud observations are never an IO authority or simultaneous
        // provider identity fence. The signed bytes are independently checked
        // against immutable Ed25519 inventory and owner-root history below.
        observationOnly: true });
      const verified = await this.restoreExact({ scope, operation: fixed,
        ...recovered.signedCatalog,
        // Fail closed if the previous proof was merely replayed as JSON;
        // a real predecessor must come from the owner verifier, not the cloud.
        previousOwnerHistoryProof: previousOwnerHistoryProof === null
          ? recovered.signedCatalog.previousOwnerHistoryProof : previousOwnerHistoryProof,
        readers, minimumMatchingProviders }, { deadline: limit });
      return Object.freeze({ ...verified,
        signedCatalogRecoveredFromRemote: true,
        signedCatalogSourceProviders: recovered.providers,
        remoteDurabilityProven: false, authorizesProductionRestore: false });
    } catch (_) { deny(); }
    finally { limit.close(); }
  }
}

// Mount only behind an authenticated, currently authorized application route.
// The caller owns the access check and the read-only fixed operation mapping.
function createZk1MultiproviderRestoreGetHandler({ gateway, pinnedOperationId,
  restoreInput, authorizeHttpRequest } = {}) {
  if (!(gateway instanceof Zk1MultiproviderCiphertextRestore)
    || typeof authorizeHttpRequest !== "function") deny();
  const pinnedId = copied(pinnedOperationId, 16);
  const id = pinnedId.toString("base64url");
  // The route is bound to one immutable operation before handling requests.
  // Never use a mutable or dynamically supplied operation at the final
  // authorization boundary, even if the ciphertext itself has a valid digest.
  const mapped = restoreInput?.mode === "cloud-catalog"
    ? restoreInput.request?.operation : restoreInput?.operation;
  const fixedOperation = cloneOperation(mapped);
  if (!same(fixedOperation.operation_id, pinnedId)) deny();
  return async (request, response) => {
    try {
      if (request.method !== "GET" || request.url !== `/zk1-recovery/${id}`
        || gateway.checkRequesterDeviceIdentity(await authorizeHttpRequest(request)) !== true) deny();
      const restored = restoreInput?.mode === "cloud-catalog"
        ? await gateway.restoreFromCloudCatalog(restoreInput.request)
        : await gateway.restoreExact(restoreInput);
      if (!same(restored.operationId, pinnedId)
        || !same(restored.ciphertextSha256, fixedOperation.ciphertext_sha256)
        || gateway.checkRequesterDeviceIdentity(await authorizeHttpRequest(request)) !== true) deny();
      const body = Buffer.from(JSON.stringify({
        format: "rootark-zk1-cloud-recovery-response/v1",
        operationId: id, ciphertextBase64: restored.ciphertext.toString("base64url"),
        ciphertextSha256: restored.ciphertextSha256.toString("base64url"),
        ciphertextRoot: restored.ciphertextRoot.toString("base64url"),
        signedCommittedProof: restored.signedCommittedProof.toString("base64url"),
        signedSnapshot: restored.signedSnapshot.toString("base64url"),
        catalogSequence: restored.signedInventorySequence,
        catalogRoot: restored.signedInventoryRoot.toString("base64url"),
        providerCount: restored.verifiedProviders.length,
        providerPhysicalIndependenceProven: false,
        signedCatalogRecoveredFromRemote: restored.signedCatalogRecoveredFromRemote === true,
        remoteDurabilityProven: false, authorizesProductionRestore: false,
      }), "utf8");
      // There is an await between the restore's final owner check and the
      // second HTTP identity check above. Re-evaluate independently signed,
      // nonce-fresh owner/device state AFTER that await and body construction,
      // immediately before releasing even opaque ciphertext to this socket.
      // This is a rejection fence, not an atomic witness/cloud transaction.
      const egress = await gateway.recheckBeforeEgress(fixedOperation);
      if (!Number.isSafeInteger(egress.expiresAtSeconds)
        || Math.floor(Date.now() / 1000) >= egress.expiresAtSeconds) deny();
      response.writeHead(200, { "content-type": "application/json; charset=utf-8",
        "content-length": body.length, "cache-control": "no-store" });
      response.end(body);
    } catch (_) {
      if (!response.headersSent) response.writeHead(403, { "cache-control": "no-store" });
      response.end();
    }
  };
}

module.exports = { Zk1MultiproviderCiphertextRestore,
  createZk1MultiproviderRestoreGetHandler };
