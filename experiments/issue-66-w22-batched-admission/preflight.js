"use strict";

// Inert design probe: verify a complete signed LIST and commit bounded local
// admission pins before a caller would consider staging files. No stage,
// unlink, reconcile, or production engine hook is implemented here. A path
// preflight is NOT a native rooted handle lease against concurrent swaps.
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const path = require("node:path");

const protocol = require("../../sync-client/rootark-sync-protocol");
const { contained } = require("../../sync-client/rootark-sync-engine");
const { verifyAuthorizationProof, verifyHistoricalAuthorizationProof } =
  require("../../sync-client/rootark-sync-authorization");

const MAX_BATCH = 640;

function deny(message, code = "remote_authorization_rejected") {
  throw Object.assign(new Error(message), { code });
}

function freezeSignedSnapshot(value) {
  if (value && typeof value === "object") {
    for (const member of Object.values(value)) freezeSignedSnapshot(member);
    Object.freeze(value);
  }
  return value;
}

async function checkPhysicalCollision(rootDir, relative, operation, trackedFiles) {
  const segments = relative.split("/");
  let parent = rootDir;
  for (let i = 0; i < segments.length; i += 1) {
    const names = await fsp.readdir(parent);
    const matches = names.filter((name) => name.toLowerCase() === segments[i].toLowerCase());
    if (matches.length > 1 || (matches.length === 1 && matches[0] !== segments[i])) {
      deny("Portable physical case alias or collision", "remote_path_collision");
    }
    if (!matches.length) return;
    parent = path.join(parent, segments[i]);
    const stats = await fsp.lstat(parent, { bigint: true });
    if (stats.isSymbolicLink() || stats.ino === 0n) {
      deny("Physical link or unstable file identity", "unsafe_path");
    }
    if (i < segments.length - 1) {
      if (!stats.isDirectory()) deny("Physical file is a parent of remote path", "remote_path_collision");
    } else {
      const prior = Object.hasOwn(trackedFiles, relative) ? trackedFiles[relative] : null;
      if (!prior || prior.deleted || prior.objectId !== operation.objectId
        || prior.fileId !== operation.fileId
        || (prior.directory === true) !== (operation.metadata.contentType === "inode/directory")) {
        deny("Untracked physical occupant of remote path", "remote_path_collision");
      }
    }
  }
}

async function preflightAndPinSignedList(options) {
  const { records, rootDir, journal, keyEpoch, fileKeyResolver,
    username, trustedDevicePublicKeys, revokedDeviceIds,
    trackedFiles = Object.create(null), beforeCommit = null } = options;
  if (!Array.isArray(records) || records.length > MAX_BATCH || !rootDir
    || !journal || typeof journal.batchObserveAdmission !== "function"
    || typeof fileKeyResolver !== "function" || typeof username !== "string"
    || !trustedDevicePublicKeys || !Array.isArray(revokedDeviceIds)) {
    deny("Invalid preflight inputs");
  }
  // Snapshot every network-supplied field before any await or trust check.
  const detached = records.map((raw) =>
    JSON.parse(protocol.canonicalJson(raw)));
  const identities = new Set();
  const paths = new Set();
  const observations = [];
  const expected = { username,
    trustedDevicePublicKeys: Object.assign(Object.create(null), trustedDevicePublicKeys),
    revokedDeviceIds: [...revokedDeviceIds] };
  for (const operation of detached) {
    protocol.validateStoredOperation(operation);
    if (!operation.authorization || operation.keyEpoch !== keyEpoch) {
      deny("Unsigned or stale-epoch LIST member");
    }
    const digest = crypto.createHash("sha256")
      .update(protocol.canonicalJson(operation), "utf8").digest("hex");
    if (identities.has(operation.operationId)) deny("Duplicated LIST operationId");
    identities.add(operation.operationId);
    journal.assertCompatibleAdmission(operation.operationId, digest);
    const relative = operation.metadata?.path;
    if (typeof relative !== "string") deny("Missing LIST member path", "unsafe_path");
    protocol.safeRelativePath(relative, "path");
    const folded = relative.toLowerCase();
    if (paths.has(folded)) deny("LIST contains multiple physical path owners", "remote_path_collision");
    paths.add(folded);
    const previouslyPinned = journal.hasLocalAdmission(operation.operationId, digest);
    await (previouslyPinned ? verifyHistoricalAuthorizationProof
      : verifyAuthorizationProof)(operation.authorization, operation, expected);
    const key = await fileKeyResolver(operation);
    if (!key) deny("Remote LIST file key unavailable");
    protocol.decryptPayload(operation, key);
    await contained(rootDir, relative, true);
    await checkPhysicalCollision(rootDir, relative, operation, trackedFiles);
    if (!previouslyPinned) observations.push({ operationId: operation.operationId, digest });
  }
  // Contract: a supplied beforeCommit owner-policy/revocation callback MUST
  // execute even on a full replay whose every digest is already pinned and
  // whose observation batch is empty. The journal serializes that empty-batch
  // gate behind older transactions without inventing a new receipt.
  // An expiry check only before an awaited policy callback or journal queue
  // can turn a formerly fresh signature into a newly pinned expired receipt.
  // Recheck inside the queued journal mutation, after the last awaited policy
  // gate and before durableWrite. This is NOT an NTFS power-cut/fsync proof.
  const assertFreshAtCommitStart = () => {
    const now = Date.now();
    for (const item of detached) {
      const digest = crypto.createHash("sha256")
        .update(protocol.canonicalJson(item), "utf8").digest("hex");
      if (!journal.hasLocalAdmission(item.operationId, digest)
        && item.authorization.expiresAt <= now) {
        deny("Authorization expired before queued journal admission", "authorization_expired");
      }
    }
  };
  assertFreshAtCommitStart();
  await journal.batchObserveAdmission(observations, async () => {
    if (beforeCommit) await beforeCommit();
    assertFreshAtCommitStart();
  });
  return { operations: freezeSignedSnapshot(detached), observed: observations.length };
}

module.exports = { preflightAndPinSignedList };
