"use strict";

// Separate opaque signed-catalog backup in the existing bounded provider data
// plane. A derived operation address prevents collision with the file copy.
// The sidecar is NOT itself a signature: consumers MUST verify the embedded
// Ed25519 committed proof, signed snapshot, owner root and monotonic floor.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");
const { zk1CloudCopyAddress } = require("./zk1CloudCiphertextReadbackVerifier");
const { Zk1ExternallyPinnedProviderDomains } =
  require("./zk1ExternallyPinnedProviderDomains");
const { createZk1ProviderDeadline, isZk1ProviderDeadline } =
  require("./zk1ProviderDeadline");

const FORMAT = "rootark-zk1-signed-catalog-sidecar/v1";
const DOMAIN = Buffer.from("Root.ark/zk-1/catalog-sidecar-operation/v1\0");
const MAX = Math.min(4 * 1024 * 1024, inventory.MAX_SNAPSHOT_BYTES + 200000);
function deny() { throw new Error("ZK_SIGNED_CATALOG_SIDECAR_DENIED"); }
function bytes(value, length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength !== length) deny();
  return Buffer.from(value);
}
function keyIdentity(target, method) {
  if (!target || typeof target !== "object" || Array.isArray(target)) deny();
  const adapter = target[method];
  if (!adapter || !["s3", "gdrive", "webdav"].includes(target.provider)
    || adapter.status?.()?.provider !== target.provider
    || adapter.enabled?.() !== true
    || !["key", "resolveInventoryContext", "zk1StorageNamespace",
      method === "cloudWriter" ? "upload" : "download"]
      .every((name) => typeof adapter[name] === "function")
    || !/^[a-f0-9]{64}$/.test(target.expectedContext)
    || !/^[a-f0-9]{64}$/.test(adapter.zk1StorageNamespace())
    || (target.provider === "gdrive"
      ? !/^[A-Za-z0-9_-]{1,256}$/.test(target.pinnedDriveFileId)
      : target.pinnedDriveFileId !== null)) deny();
  return { adapter, provider: target.provider, context: target.expectedContext,
    namespace: adapter.zk1StorageNamespace(), driveFileId: target.pinnedDriveFileId,
    domainAttestation: target.domainAttestation };
}
function pinnedDomains(providerDomainPinset, scope, pinned) {
  if (!(providerDomainPinset instanceof Zk1ExternallyPinnedProviderDomains)) deny();
  try {
    providerDomainPinset.verify({ scope, nowSeconds: Math.floor(Date.now() / 1000),
      targets: pinned.map((entry) => ({
        provider: entry.provider, namespaceIdentity: entry.namespace,
        expectedReaderContext: entry.context,
        pinnedDriveFileId: entry.driveFileId,
        domainAttestation: entry.domainAttestation,
      })) });
  } catch (_) { deny(); }
}
function copyAddress(scope, operationId) {
  const id = crypto.createHash("sha256").update(DOMAIN)
    .update(bytes(operationId, 16)).digest().subarray(0, 16);
  return zk1CloudCopyAddress({ scope: inventory.normalizeScope(scope), operationId: id });
}
function writerLocallyPinned(target, address, expectedKey) {
  return target.adapter.enabled?.() === true
    && target.adapter.status?.()?.provider === target.provider
    && target.adapter.zk1StorageNamespace() === target.namespace
    && target.adapter.key(address.folder, address.name, "uploads") === expectedKey;
}
function encodeCatalog(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) deny();
  const raw = {
    format: FORMAT,
    operationId: bytes(input.operationId, 16).toString("base64url"),
    signedCommittedProof: Buffer.from(input.signedCommittedProof).toString("base64url"),
    signedSnapshot: Buffer.from(input.signedSnapshot).toString("base64url"),
    snapshotNonce: bytes(input.snapshotNonce, 32).toString("base64url"),
    committedProofChain: input.committedProofChain.map((value) => Buffer.from(value).toString("base64url")),
    ownerCheckpoint: input.ownerCheckpoint,
    ownerHistoryCheckpoint: input.ownerHistoryCheckpoint,
    previousOwnerHistoryProof: input.previousOwnerHistoryProof,
    expectedCiphertextRoot: bytes(input.expectedCiphertextRoot, 32).toString("base64url"),
    chunkLengths: input.chunkLengths,
  };
  if (!Array.isArray(raw.chunkLengths) || raw.chunkLengths.length < 1
    || raw.chunkLengths.length > 16
    || raw.chunkLengths.some((length) => !Number.isSafeInteger(length)
      || length < 1 || length > 1024 * 1024)
    || !Array.isArray(raw.committedProofChain) || raw.committedProofChain.length > 64) deny();
  const data = Buffer.from(JSON.stringify(raw), "utf8");
  if (data.length < 1 || data.length > MAX) deny();
  return data;
}
function parseCatalog(data, expectedOperationId) {
  if (!Buffer.isBuffer(data) || data.length < 1 || data.length > MAX) deny();
  let wire;
  try { wire = JSON.parse(data.toString("utf8")); } catch (_) { deny(); }
  const fields = ["format", "operationId", "signedCommittedProof", "signedSnapshot",
    "snapshotNonce", "committedProofChain", "ownerCheckpoint", "ownerHistoryCheckpoint",
    "previousOwnerHistoryProof", "expectedCiphertextRoot", "chunkLengths"];
  if (!wire || typeof wire !== "object" || Array.isArray(wire)
    || Reflect.ownKeys(wire).length !== fields.length
    || fields.some((field) => !Object.hasOwn(wire, field))
    || wire.format !== FORMAT
    || wire.operationId !== bytes(expectedOperationId, 16).toString("base64url")
    || JSON.stringify(wire) !== data.toString("utf8")) deny();
  const from64 = (value, max) => {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
      || value.length > Math.ceil(max * 4 / 3) + 4) deny();
    const buffer = Buffer.from(value, "base64url");
    if (buffer.length > max || buffer.toString("base64url") !== value) deny();
    return buffer;
  };
  if (!Array.isArray(wire.committedProofChain) || wire.committedProofChain.length > 64
    || !Array.isArray(wire.chunkLengths) || wire.chunkLengths.length < 1
    || wire.chunkLengths.length > 16
    || wire.chunkLengths.some((length) => !Number.isSafeInteger(length)
      || length < 1 || length > 1024 * 1024)) deny();
  const output = {
    signedCommittedProof: from64(wire.signedCommittedProof, inventory.MAX_COMMITTED_PROOF_BYTES),
    signedSnapshot: from64(wire.signedSnapshot, inventory.MAX_SNAPSHOT_BYTES),
    snapshotNonce: from64(wire.snapshotNonce, 32),
    committedProofChain: wire.committedProofChain.map((entry) =>
      from64(entry, inventory.MAX_COMMITTED_PROOF_BYTES)),
    ownerCheckpoint: wire.ownerCheckpoint,
    ownerHistoryCheckpoint: wire.ownerHistoryCheckpoint,
    previousOwnerHistoryProof: wire.previousOwnerHistoryProof,
    expectedCiphertextRoot: from64(wire.expectedCiphertextRoot, 32),
    chunkLengths: wire.chunkLengths,
  };
  if (output.snapshotNonce.length !== 32 || output.expectedCiphertextRoot.length !== 32) deny();
  // roundtrip also rejects aliases, overlong encodings and unknown fields.
  if (!data.equals(encodeCatalog({ ...output, operationId: expectedOperationId }))) deny();
  return output;
}
async function publishSignedCatalogSidecars({ scope, operationId, signedCatalog, writers,
  providerDomainPinset } = {}) {
  let dir;
  try {
    if (!Array.isArray(writers) || writers.length < 2 || writers.length > 3) deny();
    const pinned = writers.map((target) => keyIdentity(target, "cloudWriter"));
    if (new Set(pinned.map((target) => target.provider)).size !== pinned.length
      || new Set(pinned.map((target) => target.namespace)).size !== pinned.length) deny();
    pinnedDomains(providerDomainPinset, scope, pinned);
    const payload = encodeCatalog({ ...signedCatalog, operationId });
    const address = copyAddress(scope, operationId);
    const keys = pinned.map((target) => target.adapter.key(
      address.folder, address.name, "uploads"));
    for (const [index, target] of pinned.entries())
      if (!writerLocallyPinned(target, address, keys[index])) deny();
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-signed-catalog-write-"));
    const staged = path.join(dir, "signed-catalog.ct");
    fs.writeFileSync(staged, payload, { flag: "wx", mode: 0o600 });
    const acknowledgements = [];
    for (const [index, target] of pinned.entries()) {
      const expectedKey = keys[index];
      if (!writerLocallyPinned(target, address, expectedKey)) deny();
      if (await target.adapter.resolveInventoryContext() !== target.context) deny();
      if (!writerLocallyPinned(target, address, expectedKey)) deny();
      const result = await target.adapter.upload(staged, address.folder, address.name,
        "uploads", { zk1BoundedBytes: payload.length,
          ...(target.provider === "webdav" ? { zk1ExpectedSha256: crypto.createHash("sha256").update(payload).digest("hex") } : {}),
          ...(target.driveFileId === null ? {} : { providerFileId: target.driveFileId }) });
      if (!writerLocallyPinned(target, address, expectedKey)
        || !result || result.provider !== target.provider || result.key !== expectedKey
        || (target.driveFileId !== null && result.id !== target.driveFileId)
        || await target.adapter.resolveInventoryContext() !== target.context
        || !writerLocallyPinned(target, address, expectedKey)) deny();
      acknowledgements.push(Object.freeze({ provider: target.provider,
        providerObjectKey: expectedKey, providerFileId: target.driveFileId }));
    }
    // A later remote PUT can revoke an earlier writer. Recheck every counted
    // provider before even a NON-AUTHORIZING ACK, including expiry of signed
    // domain attestations; separate probes do not prove an atomic cloud lease.
    for (const [index, target] of pinned.entries()) {
      if (!writerLocallyPinned(target, address, keys[index])) deny();
      if (await target.adapter.resolveInventoryContext() !== target.context) deny();
      if (!writerLocallyPinned(target, address, keys[index])) deny();
    }
    pinnedDomains(providerDomainPinset, scope, pinned);
    for (const [index, target] of pinned.entries())
      if (!writerLocallyPinned(target, address, keys[index])) deny();
    return Object.freeze({ status: "SIGNED_CATALOG_PUT_ACK_NONAUTHORITATIVE",
      acknowledgements: Object.freeze(acknowledgements), remoteDurabilityProven: false });
  } catch (_) { deny(); }
  finally { if (dir) fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }); }
}
async function recoverSignedCatalogSidecar({ scope, operationId, readers,
  minimumMatchingProviders = 2, providerDomainPinset, deadlineMs, abortSignal,
  deadline, expectedCatalogSha256, observationOnly = false } = {}) {
  if (!Array.isArray(readers) || readers.length < 2 || readers.length > 3
    || !Number.isSafeInteger(minimumMatchingProviders)
    || minimumMatchingProviders < 2 || minimumMatchingProviders > readers.length) deny();
  // Sequential remote GETs and async provider identity probes CANNOT establish
  // a coherent cross-provider principal snapshot. Until an independently
  // pinned atomic lease/fence exists, the only supported successful result is
  // explicitly opted-in, NON-AUTHORIZING signed-wire observation. In strict
  // mode finish all owned GETs before failing closed; no partial IO is left
  // in flight and no false current-authority quorum can escape.
  if (typeof observationOnly !== "boolean") deny();
  // Optional externally retained commitment to the exact published sidecar.
  // A quorum of two providers alone can agree on an old but well-formed blob.
  const expectedDigest = expectedCatalogSha256 === undefined ? null
    : bytes(expectedCatalogSha256, 32);
  const pinned = readers.map((target) => keyIdentity(target, "cloudReader"));
  if (new Set(pinned.map((target) => target.provider)).size !== pinned.length
    || new Set(pinned.map((target) => target.namespace)).size !== pinned.length) deny();
  pinnedDomains(providerDomainPinset, scope, pinned);
  if (deadline !== undefined && !isZk1ProviderDeadline(deadline)) deny();
  const limit = deadline || createZk1ProviderDeadline({ deadlineMs, parentSignal: abortSignal });
  const address = copyAddress(scope, operationId);
  const recovered = [];
  try {
  for (const target of pinned) {
    let dir;
    try {
      if (await limit.run(() => target.adapter.resolveInventoryContext()) !== target.context) deny();
      dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-signed-catalog-read-"));
      const destination = path.join(dir, "catalog.ct");
      const received = await limit.run((signal) => target.adapter.download(address.folder, address.name,
        destination, "uploads", () => !signal.aborted,
        { maxBytes: MAX, boundedLengthOnly: true, ...(target.driveFileId === null ? {}
          : { providerFileId: target.driveFileId }), abortSignal: signal }));
      if (received !== true || await limit.run(() => target.adapter.resolveInventoryContext()) !== target.context
        || target.adapter.zk1StorageNamespace() !== target.namespace) deny();
      const info = fs.lstatSync(destination, { bigint: true });
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n
        || info.size < 1n || info.size > BigInt(MAX)) deny();
      const fd = fs.openSync(destination,
        fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      let data;
      try {
        const opened = fs.fstatSync(fd, { bigint: true });
        if (!opened.isFile() || opened.nlink !== 1n || opened.dev !== info.dev
          || opened.ino !== info.ino || opened.size !== info.size) deny();
        // A hostile writer may grow the same inode after fstat. Reading an
        // unbounded descriptor would allocate attacker-controlled bytes before
        // the post-read identity check can reject the changed file.
        const exactLength = Number(opened.size);
        data = Buffer.alloc(exactLength);
        let offset = 0;
        while (offset < exactLength) {
          const count = fs.readSync(fd, data, offset,
            Math.min(64 * 1024, exactLength - offset), offset);
          if (count <= 0 || count > exactLength - offset) deny();
          offset += count;
        }
        const after = fs.fstatSync(fd, { bigint: true });
        const now = fs.lstatSync(destination, { bigint: true });
        if (data.length !== Number(info.size) || after.ino !== opened.ino
          || after.dev !== opened.dev || after.size !== opened.size
          || after.mtimeNs !== opened.mtimeNs || now.ino !== opened.ino
          || now.dev !== opened.dev || now.nlink !== 1n || now.isSymbolicLink()) deny();
      } finally { fs.closeSync(fd); }
      const parsed = parseCatalog(data, operationId);
      if (expectedDigest && !crypto.timingSafeEqual(
        crypto.createHash("sha256").update(data).digest(), expectedDigest)) deny();
      recovered.push({ data, parsed, provider: target.provider });
      const matching = recovered.filter((item) => item.data.equals(data));
      if (matching.length >= minimumMatchingProviders) break;
    } catch (_) {
      if (limit.signal.aborted) deny();
      // An unavailable or corrupt provider is excluded from quorum.
    }
    finally { if (dir) fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5 }); }
  }
  const groups = new Map();
  for (const item of recovered) {
    const hash = crypto.createHash("sha256").update(item.data).digest("hex");
    if (!groups.has(hash)) groups.set(hash, []);
    groups.get(hash).push(item);
  }
  const eligible = [...groups.values()].filter((group) => group.length >= minimumMatchingProviders);
  if (eligible.length !== 1 || eligible[0].some((value) => !value.data.equals(eligible[0][0].data))) deny();
  // The principal/namespace attested at the beginning must still own each
  // counted GET when the quorum completes. A second provider can stall long
  // enough for the first to be reconfigured or its attestation to expire.
  for (const match of eligible[0]) {
    const target = pinned.find((item) => item.provider === match.provider);
    if (!target || await limit.run(() => target.adapter.resolveInventoryContext()) !== target.context
      || target.adapter.zk1StorageNamespace() !== target.namespace) deny();
  }
  pinnedDomains(providerDomainPinset, scope, pinned);
  limit.assertActive();
  // No ordering of separate awaited identity checks proves that the first
  // principal stayed valid during the last provider's check. A full strict
  // success requires a future independently verified shared authority fence.
  if (!observationOnly) deny();
  return Object.freeze({ signedCatalog: eligible[0][0].parsed,
    providers: Object.freeze(eligible[0].map((item) => item.provider)),
    matchingCount: eligible[0].length, remoteDurabilityProven: false,
    signaturesVerifiedBySidecar: false, authorizesIo: false,
    observationalOnly: true, coherentProviderIdentityQuorumProven: false,
    crossProviderAtomicFenceProven: false });
  } finally { if (!deadline) limit.close(); }
}

// Read-only reconciliation after a lost PUT acknowledgement or after a process
// restart. The caller must retain the expected signed wire independently of
// the providers; verify the exact bytes on >=2 distinct pinned domains.
// Signatures, cloud fsync, and live protected IO are verified elsewhere.
async function verifyPublishedSignedCatalogSidecars({ scope, operationId, signedCatalog,
  readers, minimumMatchingProviders = 2, providerDomainPinset, deadlineMs,
  abortSignal, observationOnly = false } = {}) {
  try {
    // Capture the exact expected wire before any provider await, so callers
    // cannot swap a mutable input after the first read and authorize a replay.
    const expected = encodeCatalog({ ...signedCatalog, operationId });
    const digest = crypto.createHash("sha256").update(expected).digest();
    const result = await recoverSignedCatalogSidecar({ scope, operationId,
      readers, minimumMatchingProviders, providerDomainPinset, deadlineMs,
      abortSignal, expectedCatalogSha256: digest, observationOnly });
    return Object.freeze({ status: "SIGNED_CATALOG_EXACT_REMOTE_REREAD_OBSERVATION",
      catalogSha256: Buffer.from(digest), matchingCount: result.matchingCount,
      providers: result.providers, readbackMatched: true,
      authorizesIo: false, signaturesVerifiedBySidecar: false,
      observationalOnly: true, coherentProviderIdentityQuorumProven: false,
      crossProviderAtomicFenceProven: false, remoteDurabilityProven: false,
      providerPhysicalIndependenceProven: false });
  } catch (_) { deny(); }
}

module.exports = { publishSignedCatalogSidecars, recoverSignedCatalogSidecar,
  verifyPublishedSignedCatalogSidecars,
  zk1CatalogSidecarAddress: copyAddress };
