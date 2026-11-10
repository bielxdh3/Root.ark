"use strict";

// Intentionally NOT wired into SyncEngine._pullRemote: this is a source-level
// proof of the metadata-only fast path, not a native pinned-root transaction.
// A transient swap of the root/ancestor can still redirect the existing
// pathname-based journal or snapshot writes; peer/native review remains NO-GO.
const fsp = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { preflightAndPinSignedList } = require("./preflight");

const BOUND = 640;
const ALLOWED_ROOT = new Map([
  [".rootark-sync-index.json", "file"],
  [".rootark-sync-journal.json", "file"],
  [".rootark-sync.lock", "directory"],
]);

function reject(message, code = "remote_only_batch_ineligible") {
  throw Object.assign(new Error(message), { code });
}

async function assertRootHasNoPhysicalCache(rootDir) {
  const root = await fsp.lstat(rootDir, { bigint: true });
  if (!root.isDirectory() || root.isSymbolicLink() || root.ino === 0n) {
    reject("Physical root identity unavailable", "unsafe_path");
  }
  const names = await fsp.readdir(rootDir);
  for (const name of names) {
    const kind = ALLOWED_ROOT.get(name);
    if (!kind) reject("Physical root contains an untracked or staged inode", "unsafe_path");
    const stat = await fsp.lstat(path.join(rootDir, name), { bigint: true });
    if (stat.isSymbolicLink() || stat.ino === 0n
      || (kind === "file" && (!stat.isFile() || stat.nlink !== 1n))
      || (kind === "directory" && !stat.isDirectory())) {
      reject("Physical root contains a link or an unexpected inode", "unsafe_path");
    }
    if (kind === "directory") {
      // Even the exclusive lock directory must not shelter untracked bytes.
      // Read just one child so an oversized hostile tree fails in bounded time.
      const opened = await fsp.opendir(path.join(rootDir, name));
      try {
        if (await opened.read()) {
          reject("Exclusive root lock contains an untracked physical inode", "unsafe_path");
        }
      } finally { await opened.close(); }
    }
  }
  return { dev: root.dev, ino: root.ino };
}

function assertEmptyLocalCache(engine) {
  const snap = engine.snapshot;
  if (snap.evictionLedgerRequired === true || engine.evictionLedgerHead !== null
    || Object.keys(snap.pendingEvictions || {}).length
    || Object.keys(snap.files || {}).length
    || Object.keys(snap.pinnedFiles || {}).length) {
    reject("Active cache, pinned files or eviction replay prevents metadata batch");
  }
  if (Object.values(snap.remoteOnly || {}).some((entry) =>
    !entry || entry.reason !== "excluded" || entry.deleted || entry.directory
    || entry.sourcePath || entry.hash)) {
    reject("Previous physical eviction or tombstone prevents metadata batch");
  }
}

function assertExactRemoteOnlyList(engine, records) {
  if (!Array.isArray(records) || !records.length || records.length > BOUND
    || engine.filesOnDemand || engine.requireAuthorization !== true
    || typeof engine.verifyIncoming !== "function") {
    reject("Strict full signed LIST is required for metadata-only batching");
  }
  const seenId = new Set();
  const seenObject = new Set();
  const seenPath = new Set();
  const existingPaths = new Map(Object.values(engine.snapshot.remoteOnly || {})
    .map((entry) => [entry.path.toLowerCase(), entry.objectId]));
  for (const operation of records) {
    const relative = operation?.metadata?.path;
    if (!operation || !["create", "update"].includes(operation.operation)
      || operation.tombstone !== false || operation.metadata.sourcePath
      || operation.metadata.contentType === "inode/directory"
      || typeof relative !== "string" || !engine.isExcluded(relative)
      || engine.operationDestinationIsSelected(operation)
      || operation.keyEpoch !== engine.keyEpoch
      || !operation.authorization) {
      reject("LIST contains an operation with a local mutation or hydration path");
    }
    protocol.safeRelativePath(relative, "path");
    if (["__proto__", "constructor", "prototype"].includes(operation.objectId)
      || seenId.has(operation.operationId) || seenObject.has(operation.objectId)
      || seenPath.has(relative.toLowerCase())) {
      reject("Ambiguous remote-only LIST identities or portable paths");
    }
    seenId.add(operation.operationId);
    seenObject.add(operation.objectId);
    seenPath.add(relative.toLowerCase());
    const prior = engine.snapshot.remoteOnly[operation.objectId];
    if (prior && (prior.reason !== "excluded" || prior.deleted || prior.directory
      || prior.path !== relative || prior.fileId !== operation.fileId)) {
      reject("Remote-only identity differs from the persisted local record");
    }
    // A crash after the full snapshot and before the batch ACK can replay
    // the exact CREATE, including after its signature expires. Require the
    // same canonical bytes to have a durable observation before accepting a
    // CREATE for a path that now has a remote-only marker.
    if (prior && operation.operation === "create"
      && !engine.journal.hasLocalAdmission(operation.operationId,
        crypto.createHash("sha256").update(protocol.canonicalJson(operation)).digest("hex"))) {
      reject("Previously checkpointed CREATE lacks exact durable receipt");
    }
    if (!prior && operation.operation !== "create") {
      reject("UPDATE without an exact previous remote-only identity");
    }
    const otherObject = existingPaths.get(relative.toLowerCase());
    if (otherObject && otherObject !== operation.objectId) {
      reject("Another remote-only object owns the same portable path");
    }
    const digest = crypto.createHash("sha256")
      .update(protocol.canonicalJson(operation), "utf8").digest("hex");
    if (engine.journal.hasSeen(operation.operationId)
      && !engine.journal.hasLocalAdmission(operation.operationId, digest)) {
      reject("Legacy seen ID is not an exact signed admission receipt");
    }
  }
  for (const previous of Object.values(engine.snapshot.remoteOnly || {})) {
    if (!seenObject.has(previous.objectId)) {
      reject("LIST omits an existing local remote-only identity");
    }
  }
}

function assertTrustedPolicy(now, pinned, earlier = null) {
  let detached;
  try { detached = JSON.parse(protocol.canonicalJson(now)); }
  catch { reject("External owner policy is not canonical", "remote_authorization_rejected"); }
  if (!pinned || typeof pinned !== "object" || !Number.isSafeInteger(detached?.epoch)
    || detached.epoch < pinned.minEpoch || (earlier && detached.epoch < earlier.epoch)
    || typeof detached.username !== "string" || detached.username !== pinned.username
    || detached.keyEpoch !== pinned.keyEpoch
    || !Array.isArray(detached.revokedDeviceIds)
    || !detached.trustedDevicePublicKeys
    || typeof detached.trustedDevicePublicKeys !== "object"
    || Array.isArray(detached.trustedDevicePublicKeys)) {
    reject("External owner policy epoch or scope is invalid", "remote_authorization_rejected");
  }
  for (const [deviceId, key] of Object.entries(pinned.trustedDevicePublicKeys)) {
    if (detached.trustedDevicePublicKeys[deviceId] !== key) {
      reject("Current owner policy changed a pinned signer", "remote_authorization_rejected");
    }
  }
  return { epoch: detached.epoch, username: detached.username, keyEpoch: detached.keyEpoch,
    revokedDeviceIds: [...detached.revokedDeviceIds],
    trustedDevicePublicKeys: Object.assign(Object.create(null), pinned.trustedDevicePublicKeys) };
}

async function probeStrictRemoteOnlyBatch(engine, trusted, hooks = {}) {
  if (!trusted || typeof trusted.currentPolicyProvider !== "function"
    || !Number.isSafeInteger(trusted.minEpoch) || trusted.minEpoch < 1
    || trusted.keyEpoch !== engine.keyEpoch || !trusted.username
    || !trusted.trustedDevicePublicKeys) {
    reject("Independently pinned current device policy is missing");
  }
  // Detach the trusted *initial* pins before the first await. The current
  // provider can advance its epoch/revocation state, but cannot silently
  // replace the owner's originally pinned signer during a pending journal IO.
  const pinned = {
    minEpoch: trusted.minEpoch, keyEpoch: trusted.keyEpoch, username: trusted.username,
    trustedDevicePublicKeys: Object.assign(Object.create(null), trusted.trustedDevicePublicKeys),
  };
  const currentPolicyProvider = trusted.currentPolicyProvider;
  return engine.withMutationLock(async () => {
    const listed = await engine.adapter.list();
    if (listed && !Array.isArray(listed) &&
      (listed.nextCursor !== undefined && listed.nextCursor !== null)) {
      reject("Paginated or partial remote LIST has no complete inventory witness");
    }
    const records = Array.isArray(listed) ? listed : listed?.objects;
    if (!Array.isArray(records)) reject("Missing complete remote LIST array");
    const detached = records.map((record) =>
      JSON.parse(protocol.canonicalJson(record)));
    assertEmptyLocalCache(engine);
    assertExactRemoteOnlyList(engine, detached);
    if ((await engine.journal.recover()).length
      || Object.keys(engine.journal.atomicSignedGroups()).length) {
      reject("Pending local work prevents remote-only metadata-only admission");
    }
    const beforeRoot = await assertRootHasNoPhysicalCache(engine.rootDir);
    const policy = assertTrustedPolicy(await currentPolicyProvider(), pinned);
    if (detached.some((op) => policy.revokedDeviceIds.includes(op.deviceId))) {
      reject("A LIST signer is currently revoked", "authorization_device_revoked");
    }
    // The engine's configured verifier may require stronger independent
    // physical historical evidence; run it for every member, WITHOUT any
    // journal observation. Also perform our own Ed25519 check in preflight.
    for (const operation of detached) {
      await engine.verifyIncomingOperation(operation, { preObserve: false });
    }
    const verifySamePolicy = async () => {
      const live = assertTrustedPolicy(await currentPolicyProvider(), pinned, policy);
      if (detached.some((op) => live.revokedDeviceIds.includes(op.deviceId))) {
        reject("A LIST signer was revoked before durable admission", "authorization_device_revoked");
      }
      const currentRoot = await assertRootHasNoPhysicalCache(engine.rootDir);
      if (currentRoot.dev !== beforeRoot.dev || currentRoot.ino !== beforeRoot.ino) {
        reject("Root inode changed before metadata-only admission", "unsafe_path");
      }
    };
    const prepared = await preflightAndPinSignedList({
      records: detached, rootDir: engine.rootDir, journal: engine.journal,
      keyEpoch: engine.keyEpoch, fileKeyResolver: (operation) => engine.keyFor(operation),
      username: policy.username, trustedDevicePublicKeys: policy.trustedDevicePublicKeys,
      revokedDeviceIds: policy.revokedDeviceIds, beforeCommit: verifySamePolicy,
    });
    await hooks.afterObserve?.();
    await verifySamePolicy();
    const previous = engine.snapshot;
    engine.snapshot = JSON.parse(JSON.stringify(previous));
    try {
      for (const operation of prepared.operations) engine.rememberRemoteOnly(operation, "excluded");
      await engine.persistSnapshot();
    } catch (error) {
      engine.snapshot = previous;
      engine.snapshotDiskRevision = null;
      engine.opened = false;
      throw error;
    }
    await hooks.afterSnapshot?.();
    await verifySamePolicy();
    const ack = prepared.operations.map((operation) => ({ operationId: operation.operationId,
      digest: crypto.createHash("sha256")
        .update(protocol.canonicalJson(operation), "utf8").digest("hex") }));
    await engine.journal.batchMarkSeenRemoteOnly(ack, verifySamePolicy);
    return { observed: prepared.observed, acknowledged: ack.length };
  });
}

module.exports = { probeStrictRemoteOnlyBatch, assertRootHasNoPhysicalCache,
  assertExactRemoteOnlyList, assertEmptyLocalCache };
