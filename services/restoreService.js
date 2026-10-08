const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const unzipper = require("unzipper");
const { closeDb, getDatabasePath, isDbEnabled } = require("../db");
const { resolveRuntimePath } = require("../src/runtime-paths");
const backupRepository = require("../repositories/backupRepository");
const backupService = require("./backupService");
const restorePreimage = require("./restorePreimage");
const restoreProviderOrphans = require("./restoreProviderOrphans");
const { attestCiphertextOnlyArchive } = require("../src/services/deploymentResilience");
const { getUploadQuarantineDir, isSensitiveQuarantineItem, quarantineDirContainsUploads, readQuarantineMetadata, readQuarantineRegularFile, validateQuarantinePayloads } = require("../src/quarantine-paths");

const RESTORE_TMP_DIR = path.join(backupService.BACKUPS_DIR, ".restore-tmp");
const RESTORE_SYNC_LOCK_DIR = resolveRuntimePath("data", "restore-sync-locks");
const WHOLE_RESTORE_COORDINATOR_PATH = resolveRuntimePath("data", ".rootark-restore-coordinator.json");
const WHOLE_RESTORE_ACK_ROOT = resolveRuntimePath("data", ".rootark-restore-restart-acks");
const RESTORABLE_ROOTS = new Set(["data", "uploads"]);
const WHOLE_RESTORE_COORDINATOR_VERSION = 3;
const MAX_RESTORE_SYNC_RETRY_DELAY_MS = 60 * 60 * 1000;
const S_IFMT = 0xf000;
const S_IFLNK = 0xa000;
let cloudStorage = null;
function setCloudStorage(storage) {
  cloudStorage = storage || null;
}

function writeWholeRestoreCoordinator(coordinator) {
  fs.mkdirSync(path.dirname(WHOLE_RESTORE_COORDINATOR_PATH), { recursive: true });
  const persisted = {
    ...coordinator,
    directorySync: process.platform === "win32" ? "unsupported" : "fsync",
  };
  const temporary = `${WHOLE_RESTORE_COORDINATOR_PATH}.${crypto.randomUUID()}.tmp`;
  const fd = fs.openSync(temporary, "wx", 0o600);
  try {
    fs.writeFileSync(fd, `${JSON.stringify(persisted, null, 2)}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.renameSync(temporary, WHOLE_RESTORE_COORDINATOR_PATH);
    fsyncCoordinatorDirectory(path.dirname(WHOLE_RESTORE_COORDINATOR_PATH));
  } catch (error) {
    fs.rmSync(temporary, { force: true });
    throw error;
  }
  return persisted;
}

function configuredRestartInstanceCount() {
  const raw = String(process.env.ROOTARK_RESTORE_INSTANCE_COUNT || "1").trim();
  if (!/^[1-9]\d{0,2}$/.test(raw)) throw new Error("ROOTARK_RESTORE_INSTANCE_COUNT must be an integer from 1 to 128");
  const count = Number(raw);
  if (count > 128) throw new Error("ROOTARK_RESTORE_INSTANCE_COUNT must be an integer from 1 to 128");
  return count;
}

function restoreInstanceId(requiredInstances, explicitInstanceId) {
  const configured = explicitInstanceId == null
    ? process.env.ROOTARK_INSTANCE_ID || (requiredInstances === 1 ? process.env.HOSTNAME || "default" : "")
    : explicitInstanceId;
  const instanceId = String(configured || "").trim();
  if (!instanceId || instanceId.length > 256 || /[\u0000-\u001f\u007f]/.test(instanceId)) {
    throw new Error(requiredInstances > 1
      ? "ROOTARK_INSTANCE_ID must be configured uniquely for every restore instance"
      : "ROOTARK_INSTANCE_ID is invalid");
  }
  return instanceId;
}

function requiresProviderOrphanPolicyAtStartup(startupState) {
  if (!startupState?.restartRequired) return false;
  const coordinator = startupState.coordinator || {};
  return coordinator.providerPolicyRequired !== false;
}

function persistWholeRestoreCoordinator({ backupId, requiredRestartInstances, preRestoreBackupId = null, providerReconciliation = [], providerPolicyRequired = false, phase = "preparing" }) {
  return writeWholeRestoreCoordinator({
    version: WHOLE_RESTORE_COORDINATOR_VERSION,
    transactionId: crypto.randomUUID(),
    phase,
    backupId: String(backupId),
    requiredRestartInstances,
    preRestoreBackupId: preRestoreBackupId == null ? null : String(preRestoreBackupId),
    providerReconciliation,
    providerPolicyRequired: Boolean(providerPolicyRequired),
    startedAt: new Date().toISOString(),
  });
}

function updateWholeRestoreCoordinator(coordinator, patch) {
  return writeWholeRestoreCoordinator({ ...coordinator, ...patch, updatedAt: new Date().toISOString() });
}

function readWholeRestoreCoordinator() {
  if (!pathExists(WHOLE_RESTORE_COORDINATOR_PATH)) return null;
  try {
    return JSON.parse(fs.readFileSync(WHOLE_RESTORE_COORDINATOR_PATH, "utf8"));
  } catch {
    throw new Error("Whole-restore coordinator is invalid; startup blocked for manual recovery");
  }
}

function wholeRestorePreimageRoot(transactionId) {
  if (!/^[a-f0-9-]{36}$/i.test(String(transactionId || ""))) throw new Error("Whole-restore pre-image transaction ID is invalid");
  return resolveRuntimePath("data", "backups", ".restore-preimages", transactionId);
}

function cleanupWholeRestorePreimages(transactionId) {
  const preimageRoot = wholeRestorePreimageRoot(transactionId);
  try { restorePreimage.ensureSafeDirectory(path.dirname(preimageRoot)); }
  catch (error) { if (error.code === "ENOENT") return false; throw error; }
  const stat = (() => { try { return fs.lstatSync(preimageRoot); } catch (error) { if (error.code === "ENOENT") return null; throw error; } })();
  if (!stat) return false;
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error("Whole-restore pre-image directory is unsafe");
  fs.rmSync(preimageRoot, { recursive: true, force: false });
  fsyncDirectory(path.dirname(preimageRoot));
  return true;
}

function restoreExtractionPaths(backupId, { createRoot = false } = {}) {
  const id = String(backupId || "");
  if (!/^[a-f0-9-]{36}$/i.test(id) || /[\\/]/.test(id)) throw new Error("Restore staging directory ID is invalid");
  const restoreRoot = restorePreimage.ensureSafeDirectory(RESTORE_TMP_DIR, { create: createRoot });
  const restoreDir = path.resolve(restoreRoot, id);
  if (path.dirname(restoreDir) !== restoreRoot) throw new Error("Restore staging directory escaped its root");
  let stageStat = null;
  try { stageStat = fs.lstatSync(restoreDir); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  if (stageStat && (stageStat.isSymbolicLink() || !stageStat.isDirectory())) throw new Error("Restore staging directory is unsafe");
  return { id, restoreRoot, restoreDir, stageStat };
}

function cleanupRestoreExtraction(backupId) {
  let paths;
  try { paths = restoreExtractionPaths(backupId); }
  catch (error) { if (error.code === "ENOENT") return false; throw error; }
  const { restoreRoot, restoreDir, stageStat } = paths;
  if (stageStat) {
    fs.rmSync(restoreDir, { recursive: true, force: true });
    fsyncDirectory(restoreRoot);
  }
  try {
    fs.rmdirSync(restoreRoot);
    fsyncDirectory(path.dirname(restoreRoot));
  } catch (error) {
    if (!["ENOENT", "ENOTEMPTY", "EEXIST"].includes(error.code)) throw error;
  }
  return Boolean(stageStat);
}

function restorableDataNames(extractedRoot) {
  const extractedData = path.join(extractedRoot, "data");
  const names = new Set(["backup-history.json"]);
  if (!fs.existsSync(extractedData)) return [...names].sort();
  for (const name of fs.readdirSync(extractedData)) {
    const foldedName = name.toLowerCase();
    if (foldedName === "backups" || foldedName === "quarantine.json" || foldedName === ".rootark-quarantine-restore-journal.json" || foldedName.startsWith(".rootark-quarantine-restore-metadata-") || foldedName.startsWith(".rootark-restore-coordinator.json") || foldedName === path.basename(restoreProviderOrphans.POLICY_PATH) || foldedName === path.basename(restoreProviderOrphans.STATE_PATH) || foldedName === "server-master.key" || foldedName.endsWith(".key") || foldedName.startsWith("rootark.sqlite")) continue;
    if (path.basename(name) !== name || name === "." || name === "..") throw new Error("Restore archive contains an unsafe data filename");
    const source = path.join(extractedData, name);
    const stat = fs.lstatSync(source);
    if (stat.isSymbolicLink()) throw new Error("Restore archive data file is a symbolic link");
    if (stat.isFile()) names.add(name);
  }
  return [...names].sort();
}

function wholePreimagePlan(extractedRoot, quarantinePlan) {
  const domains = [];
  if (quarantinePlan) domains.push("quarantine-files", "quarantine-tree");
  domains.push("data-files");
  if (pathExists(path.join(extractedRoot, "uploads"))) domains.push("uploads-tree");
  if (isDbEnabled()) domains.push("database-files");
  return { domains, dataFiles: [...new Set([...restorableDataNames(extractedRoot), path.basename(restoreProviderOrphans.POLICY_PATH), path.basename(restoreProviderOrphans.STATE_PATH)])].sort() };
}

function syncPreimageDirectories(root) {
  if (process.platform === "win32") return;
  const directories = [root];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const child = path.join(root, entry.name);
    if (entry.isDirectory() && !entry.isSymbolicLink()) directories.push(...syncPreimageDirectories(child));
  }
  for (const directory of directories.reverse()) {
    const fd = fs.openSync(directory, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }
  return directories;
}

function syncPreimageParentDirectory(root) {
  if (process.platform === "win32") return false;
  const fd = fs.openSync(path.dirname(root), "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return true;
}

function createWholeRestorePreimages(coordinator, extractedRoot, quarantinePlan, onDomainComplete) {
  const plan = wholePreimagePlan(extractedRoot, quarantinePlan);
  const preimageRoot = wholeRestorePreimageRoot(coordinator.transactionId);
  restorePreimage.ensureSafeDirectory(path.dirname(preimageRoot), { create: true });
  fs.mkdirSync(preimageRoot, { mode: 0o700 });
  syncPreimageParentDirectory(preimageRoot);
  const dataRoot = resolveRuntimePath("data");
  const domains = [];
  const stagePath = (name) => path.join(preimageRoot, name);
  if (plan.domains.includes("quarantine-files")) {
    domains.push({
      name: "quarantine-files",
      kind: "files",
      root: path.resolve(dataRoot),
      files: restorePreimage.snapshotFileSet([resolveRuntimePath("data", "quarantine.json")], stagePath("quarantine-files")),
    });
    onDomainComplete("quarantine-files");
    const quarantineRoot = validateQuarantineDestination(getUploadQuarantineDir());
    domains.push({
      name: "quarantine-tree",
      kind: "tree",
      root: quarantineRoot,
      snapshot: restorePreimage.snapshotTree(quarantineRoot, stagePath("quarantine-tree")),
    });
    onDomainComplete("quarantine-tree");
  }

  domains.push({
    name: "data-files",
    kind: "files",
    root: path.resolve(dataRoot),
    files: restorePreimage.snapshotFileSet(plan.dataFiles.map((name) => path.join(dataRoot, name)), stagePath("data-files")),
  });
  onDomainComplete("data-files");

  if (plan.domains.includes("uploads-tree")) {
    const uploadsRoot = path.resolve(resolveRuntimePath("uploads"));
    domains.push({ name: "uploads-tree", kind: "tree", root: uploadsRoot, snapshot: restorePreimage.snapshotTree(uploadsRoot, stagePath("uploads-tree")) });
    onDomainComplete("uploads-tree");
  }

  if (plan.domains.includes("database-files")) {
    closeDb();
    const databasePath = path.resolve(getDatabasePath());
    domains.push({
      name: "database-files",
      kind: "files",
      root: path.dirname(databasePath),
      files: restorePreimage.snapshotFileSet(SQLITE_SUFFIXES.map((suffix) => `${databasePath}${suffix}`), stagePath("database-files")),
    });
    onDomainComplete("database-files");
  }

  syncPreimageDirectories(preimageRoot);
  const manifest = { version: restorePreimage.FORMAT_VERSION, transactionId: coordinator.transactionId, plan, domains };
  const manifestHash = restorePreimage.writeManifest(path.join(preimageRoot, "manifest.json"), manifest);
  syncPreimageDirectories(preimageRoot);
  syncPreimageParentDirectory(preimageRoot);
  return { preimagePlan: plan, preimageHash: manifestHash };
}

function validateWholeRestorePreimages(coordinator, manifest) {
  const preimageRoot = wholeRestorePreimageRoot(coordinator.transactionId);
  if (!manifest || manifest.version !== restorePreimage.FORMAT_VERSION || manifest.transactionId !== coordinator.transactionId
    || !Array.isArray(manifest.domains) || !manifest.plan || !Array.isArray(manifest.plan.domains) || !Array.isArray(manifest.plan.dataFiles)
    || JSON.stringify(manifest.plan) !== JSON.stringify(coordinator.preimagePlan)
    || [...manifest.plan.domains].sort().join("\n") !== [...new Set(manifest.plan.domains)].sort().join("\n")) {
    throw new Error("Whole-restore pre-image plan is invalid");
  }
  const expected = new Set(manifest.plan.domains);
  if (manifest.plan.dataFiles.some((name) => typeof name !== "string" || !name || name === "." || name === ".."
    || path.basename(name) !== name || name.includes("/") || name.includes("\\") || name.includes(":"))
    || new Set(manifest.plan.dataFiles).size !== manifest.plan.dataFiles.length
    || !manifest.plan.dataFiles.includes("backup-history.json")) throw new Error("Whole-restore data pre-image plan is invalid");
  if (manifest.domains.length !== expected.size || manifest.domains.some((domain) => !expected.delete(domain.name)) || expected.size) {
    throw new Error("Whole-restore pre-image domains are incomplete");
  }
  if (manifest.domains.map((domain) => domain.name).join("\n") !== manifest.plan.domains.join("\n")) throw new Error("Whole-restore pre-image order is invalid");
  const dataRoot = path.resolve(resolveRuntimePath("data"));
  const quarantineRoot = path.resolve(validateQuarantineDestination(getUploadQuarantineDir()));
  const uploadsRoot = path.resolve(resolveRuntimePath("uploads"));
  const databasePath = path.resolve(getDatabasePath());
  for (const domain of manifest.domains) {
    const snapshotRoot = path.join(preimageRoot, domain.name);
    if (domain.name === "data-files" || domain.name === "quarantine-files") {
      if (domain.kind !== "files" || path.resolve(domain.root) !== dataRoot || !Array.isArray(domain.files)) throw new Error("Whole-restore data pre-image is invalid");
      const expectedNames = domain.name === "data-files" ? coordinator.preimagePlan.dataFiles : ["quarantine.json"];
      if (domain.files.length !== expectedNames.length) throw new Error("Whole-restore file pre-image is incomplete");
      for (let index = 0; index < expectedNames.length; index += 1) {
        const entry = domain.files[index];
        const expectedPath = path.resolve(dataRoot, expectedNames[index]);
        if (typeof entry.existed !== "boolean" || entry.destination !== expectedPath || path.basename(entry.destination) !== expectedNames[index]) throw new Error("Whole-restore file pre-image target is invalid");
        if (entry.existed) {
          if (entry.stagedName !== String(index) || !/^[a-f0-9]{64}$/.test(entry.sha256 || "") || !Number.isSafeInteger(entry.size) || entry.size < 0) throw new Error("Whole-restore file pre-image metadata is invalid");
          if (restorePreimage.hashFile(path.join(snapshotRoot, entry.stagedName)) !== entry.sha256) throw new Error("Whole-restore file pre-image failed integrity verification");
        } else if (entry.stagedName !== undefined) throw new Error("Whole-restore absent pre-image has unexpected staged data");
      }
    } else if (domain.name === "database-files") {
      if (!isDbEnabled() || domain.kind !== "files" || path.resolve(domain.root) !== path.dirname(databasePath) || !Array.isArray(domain.files)
        || domain.files.length !== SQLITE_SUFFIXES.length) throw new Error("Whole-restore database pre-image is invalid");
      for (let index = 0; index < SQLITE_SUFFIXES.length; index += 1) {
        const entry = domain.files[index];
        if (typeof entry.existed !== "boolean" || entry.destination !== `${databasePath}${SQLITE_SUFFIXES[index]}`) throw new Error("Whole-restore database pre-image target is invalid");
        if (entry.existed && (entry.stagedName !== String(index) || !/^[a-f0-9]{64}$/.test(entry.sha256 || "") || restorePreimage.hashFile(path.join(snapshotRoot, entry.stagedName)) !== entry.sha256)) throw new Error("Whole-restore database pre-image failed integrity verification");
      }
    } else if (domain.name === "uploads-tree" || domain.name === "quarantine-tree") {
      const target = domain.name === "uploads-tree" ? uploadsRoot : quarantineRoot;
      if (domain.kind !== "tree" || path.resolve(domain.root) !== target || !domain.snapshot || typeof domain.snapshot.existed !== "boolean" || !Array.isArray(domain.snapshot.entries)) throw new Error("Whole-restore directory pre-image is invalid");
      if (domain.snapshot.existed) restorePreimage.verifyTree(snapshotRoot, domain.snapshot.entries);
      else if (domain.snapshot.entries.length) throw new Error("Whole-restore absent directory pre-image has entries");
    } else throw new Error("Whole-restore pre-image has an unknown domain");
  }
  return manifest;
}

function recoverWholeRestorePreimages(coordinator, options = {}) {
  const release = options.lockHeld ? null : backupService.acquireLock("restore-recovery");
  let manifest = null;
  const completed = [];
  try {
    const current = readWholeRestoreCoordinator();
    if (!current || current.transactionId !== coordinator.transactionId || current.version !== WHOLE_RESTORE_COORDINATOR_VERSION
      || !["prepared", "rolling_back", "manual_recovery"].includes(current.phase)) throw new Error("Whole-restore coordinator changed during recovery");
    const preimageRoot = wholeRestorePreimageRoot(current.transactionId);
    manifest = restorePreimage.readManifest(path.join(preimageRoot, "manifest.json"), current.preimageHash, current.transactionId);
    validateWholeRestorePreimages(current, manifest);
    closeDb();
    if (isDbEnabled()) {
      const databasePath = getDatabasePath();
      if (pathExists(path.dirname(databasePath))) recoverDatabaseRollback(databasePath);
    }
    recoverQuarantineRestore({ lockHeld: true });
    let recovering = updateWholeRestoreCoordinator(current, { phase: "rolling_back", rollbackProgress: [] });
    for (const domain of [...manifest.domains].reverse()) {
      recovering = updateWholeRestoreCoordinator(recovering, { rollbackDomain: domain.name });
      const snapshotRoot = path.join(preimageRoot, domain.name);
      if (domain.kind === "tree") restorePreimage.restoreTree(domain.root, snapshotRoot, domain.snapshot, current.transactionId);
      else restorePreimage.restoreFileSet(domain.files, snapshotRoot, current.transactionId);
      completed.push(domain.name);
      recovering = updateWholeRestoreCoordinator(recovering, { rollbackProgress: completed });
      options.failureInjector?.(`restore.rollback.${domain.name}.completed`, { completed: [...completed] });
    }
    recovering = updateWholeRestoreCoordinator(recovering, {
      phase: "rollback_complete",
      rollbackCompletedAt: new Date().toISOString(),
      rollbackProgress: completed,
    });
    completeWholeRestoreCoordinator(recovering);
    return { recovered: true, transactionId: current.transactionId };
  } catch (error) {
    const current = readWholeRestoreCoordinator();
    const allDomainsRestored = Array.isArray(manifest?.domains)
      && manifest.domains.every((domain) => completed.includes(domain.name));
    if (current?.transactionId === coordinator.transactionId && current.phase !== "rollback_complete" && !allDomainsRestored) {
      try { updateWholeRestoreCoordinator(current, { phase: "manual_recovery", recoveryErrorCode: String(error.code || "recovery_failed").slice(0, 80) }); } catch {}
    }
    throw new Error("Whole-restore rollback failed; startup remains blocked for manual recovery", { cause: error });
  } finally { release?.(); }
}

function assertNoPendingWholeRestore(options = {}) {
  const coordinator = readWholeRestoreCoordinator();
  if (!coordinator) return { recovered: false, reason: "no_pending_restore" };
  if (![2, WHOLE_RESTORE_COORDINATOR_VERSION].includes(coordinator.version)
    || !["preparing", "prepared", "rolling_back", "rollback_complete", "manual_recovery", "restart_required"].includes(coordinator.phase)
    || !coordinator.backupId
    || !/^[a-f0-9-]{36}$/i.test(String(coordinator.transactionId || ""))
    || !Number.isInteger(coordinator.requiredRestartInstances)
    || coordinator.requiredRestartInstances < 1
    || coordinator.requiredRestartInstances > 128) {
    throw new Error("Whole-restore coordinator is ambiguous; startup blocked for manual recovery");
  }
  if (coordinator.phase === "restart_required" && coordinator.preRestoreBackupId) {
    return { recovered: false, restartRequired: true, coordinator };
  }
  if (coordinator.version === WHOLE_RESTORE_COORDINATOR_VERSION && coordinator.phase === "preparing") {
    const release = backupService.acquireLock("restore-preparation-recovery");
    try {
      const current = readWholeRestoreCoordinator();
      if (!current || current.transactionId !== coordinator.transactionId || current.phase !== "preparing") throw new Error("Whole-restore preparation changed during startup");
      cleanupWholeRestorePreimages(current.transactionId);
      completeWholeRestoreCoordinator(current);
      return { recovered: true, reason: "incomplete_preimage_preparation" };
    } finally { release(); }
  }
  if (coordinator.version === WHOLE_RESTORE_COORDINATOR_VERSION && ["prepared", "rolling_back", "manual_recovery"].includes(coordinator.phase)) {
    return recoverWholeRestorePreimages(coordinator, options);
  }
  if (coordinator.version === WHOLE_RESTORE_COORDINATOR_VERSION && coordinator.phase === "rollback_complete") {
    const release = backupService.acquireLock("restore-rollback-cleanup");
    try {
      const current = readWholeRestoreCoordinator();
      if (!current || current.transactionId !== coordinator.transactionId || current.phase !== "rollback_complete") {
        throw new Error("Whole-restore rollback cleanup changed during startup");
      }
      completeWholeRestoreCoordinator(current);
      return { recovered: true, reason: "completed_rollback_cleanup", transactionId: current.transactionId };
    } finally { release(); }
  }
  if (coordinator.phase === "manual_recovery") throw new Error("Whole-restore rollback failed; startup blocked for manual recovery");
  throw new Error("Whole-restore recovery is pending; startup blocked for manual recovery");
}

function completeWholeRestoreCoordinator(expectedCoordinator = null) {
  const current = readWholeRestoreCoordinator();
  if (!current) return false;
  if (expectedCoordinator && current.transactionId !== expectedCoordinator.transactionId) return false;
  if (!/^[a-f0-9-]{36}$/i.test(String(current.transactionId || ""))) {
    throw new Error("Whole-restore coordinator is ambiguous; startup blocked for manual recovery");
  }
  cleanupRestoreExtraction(current.backupId);
  const ackDirectory = path.join(WHOLE_RESTORE_ACK_ROOT, current.transactionId);
  fs.rmSync(ackDirectory, { recursive: true, force: true });
  if (current.version === WHOLE_RESTORE_COORDINATOR_VERSION) {
    const removed = cleanupWholeRestorePreimages(current.transactionId);
    if (current.phase === "rolling_back" && !removed) throw new Error("Whole-restore rollback pre-image disappeared before cleanup");
  }
  fs.rmSync(WHOLE_RESTORE_COORDINATOR_PATH, { force: true });
  fsyncCoordinatorDirectory(path.dirname(WHOLE_RESTORE_COORDINATOR_PATH));
  return true;
}

function prepareWholeRestoreStartup() {
  const coordinator = readWholeRestoreCoordinator();
  if (!coordinator) return false;
  if (![2, WHOLE_RESTORE_COORDINATOR_VERSION].includes(coordinator.version)
    || coordinator.phase !== "restart_required"
    || !coordinator.backupId
    || !coordinator.preRestoreBackupId
    || !/^[a-f0-9-]{36}$/i.test(String(coordinator.transactionId || ""))
    || !Number.isInteger(coordinator.requiredRestartInstances)
    || coordinator.requiredRestartInstances < 1
    || coordinator.requiredRestartInstances > 128) {
    throw new Error("Whole-restore recovery is pending; startup blocked for manual recovery");
  }
  if (configuredRestartInstanceCount() !== coordinator.requiredRestartInstances) {
    throw new Error("ROOTARK_RESTORE_INSTANCE_COUNT does not match the pending restore coordinator instance count");
  }
  restoreInstanceId(coordinator.requiredRestartInstances);
  if (!coordinator.selectedBackup || coordinator.selectedBackup.id !== coordinator.backupId
    || !coordinator.preRestoreBackup || coordinator.preRestoreBackup.id !== coordinator.preRestoreBackupId) {
    throw new Error("Whole-restore recovery records are incomplete; startup blocked for manual recovery");
  }
  backupRepository.saveBackup(coordinator.selectedBackup);
  backupRepository.saveBackup(coordinator.preRestoreBackup);
  return coordinator;
}

function acknowledgeWholeRestoreInstance(explicitInstanceId) {
  const coordinator = readWholeRestoreCoordinator();
  if (!coordinator) return { acknowledgedInstances: 0, requiredInstances: 0, complete: true };
  if (![2, WHOLE_RESTORE_COORDINATOR_VERSION].includes(coordinator.version) || coordinator.phase !== "restart_required") {
    throw new Error("Whole-restore recovery is pending; startup blocked for manual recovery");
  }
  const requiredInstances = Number(coordinator.requiredRestartInstances);
  if (configuredRestartInstanceCount() !== requiredInstances) {
    throw new Error("ROOTARK_RESTORE_INSTANCE_COUNT does not match the pending restore coordinator instance count");
  }
  const instanceId = restoreInstanceId(requiredInstances, explicitInstanceId);
  const transactionId = String(coordinator.transactionId || "");
  if (!/^[a-f0-9-]{36}$/i.test(transactionId)) throw new Error("Whole-restore coordinator is ambiguous; startup blocked for manual recovery");
  const ackDirectory = path.join(WHOLE_RESTORE_ACK_ROOT, transactionId);
  fs.mkdirSync(ackDirectory, { recursive: true, mode: 0o700 });
  const instanceHash = crypto.createHash("sha256").update(instanceId).digest("hex");
  const ackPath = path.join(ackDirectory, `${instanceHash}.json`);
  const temporary = `${ackPath}.${crypto.randomUUID()}.tmp`;
  const fd = fs.openSync(temporary, "wx", 0o600);
  try {
    fs.writeFileSync(fd, `${JSON.stringify({ transactionId, instanceId, acknowledgedAt: new Date().toISOString() })}\n`);
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  try {
    fs.renameSync(temporary, ackPath);
    fsyncCoordinatorDirectory(ackDirectory);
  } catch (error) {
    fs.rmSync(temporary, { force: true });
    throw error;
  }

  const acknowledgedIds = new Set();
  for (const name of fs.readdirSync(ackDirectory).filter((entry) => /^[a-f0-9]{64}\.json$/i.test(entry))) {
    try {
      const ack = JSON.parse(fs.readFileSync(path.join(ackDirectory, name), "utf8"));
      const hash = crypto.createHash("sha256").update(String(ack.instanceId || "")).digest("hex");
      if (ack.transactionId === transactionId && hash === name.slice(0, -5)) acknowledgedIds.add(hash);
    } catch {}
  }
  const acknowledgedInstances = acknowledgedIds.size;
  const complete = acknowledgedInstances >= requiredInstances;
  if (complete) completeWholeRestoreCoordinator(coordinator);
  return { acknowledgedInstances, requiredInstances, complete: complete && !isWholeRestoreBlocked() };
}

function isWholeRestoreBlocked() {
  return pathExists(WHOLE_RESTORE_COORDINATOR_PATH);
}

function getWholeRestorePhase() {
  try {
    const phase = readWholeRestoreCoordinator()?.phase;
    return ["preparing", "prepared", "rolling_back", "rollback_complete", "manual_recovery", "restart_required"].includes(phase) ? phase : phase ? "manual_recovery" : null;
  } catch {
    return "manual_recovery";
  }
}

function syncNow(clock) {
  return new Date(typeof clock === "function" ? clock() : clock?.now ? clock.now() : Date.now()).toISOString();
}

function syncEntries(manifest) {
  return (manifest?.included_files || [])
    .map((entry) => String(entry.path || "").replace(/\\/g, "/"))
    .filter((entryPath) => entryPath.startsWith("uploads/"))
    .map((entryPath) => {
      const [area, ...parts] = entryPath.split("/");
      const name = parts.pop();
      const folderId = parts.join("/") || "root";
      if (!name || !folderId || folderId.includes("/") || folderId === "." || folderId === ".." || /(^|\/)(\.env|.*credentials.*|.*\.key)$/i.test(name)) return null;
      return { entryId: crypto.randomUUID(), path: entryPath, area, folderId, name, providerIdentity: null, providerFileId: null, state: "pending", attempts: 0, nextAttemptAt: null, failureCategory: null, leaseToken: null, leaseUntil: null };
    })
    .filter(Boolean);
}

function localUploadFiles() {
  const root = resolveRuntimePath("uploads");
  let rootStat;
  try { rootStat = fs.lstatSync(root); }
  catch (error) { if (error.code === "ENOENT") return []; throw error; }
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) throw new Error("Local upload tree is unsafe; cloud reconciliation remains blocked");
  const files = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error("Local upload tree contains a symlink; cloud reconciliation remains blocked");
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile()) files.push(`uploads/${path.relative(root, absolute).replace(/\\/g, "/")}`);
      else throw new Error("Local upload tree contains an unsupported filesystem entry; cloud reconciliation remains blocked");
    }
  };
  visit(root);
  return files.sort();
}

async function localReconciliationPlan(manifest) {
  if (manifest?.cloud_complete !== true) {
    throw new Error("The selected backup has no complete cloud upload baseline; configure ROOTARK_PROVIDER_INVENTORY_BASELINE_BACKUP_ID with a complete backup and restart reconciliation");
  }
  const files = localUploadFiles();
  const entries = syncEntries({ included_files: files.map((entryPath) => ({ path: entryPath })) });
  for (const entry of entries) {
    const sourcePath = resolveRuntimePath(entry.path);
    if (fs.lstatSync(sourcePath).isSymbolicLink()) throw new Error("Local upload source changed to an unsafe path; cloud reconciliation remains blocked");
    entry.sourceHash = await backupService.calculateFileHash(sourcePath);
  }
  const fingerprint = crypto.createHash("sha256").update(JSON.stringify(entries.map(({ path: entryPath, sourceHash }) => [entryPath, sourceHash]))).digest("hex");
  return { entries, fingerprint };
}

function archivedProviderObjects(manifest) {
  if (manifest?.cloud_complete !== true) return new Set();
  return new Set((manifest?.included_files || [])
    .map((entry) => String(entry.path || "").replace(/\\/g, "/"))
    .filter((entryPath) => entryPath.startsWith("uploads/"))
    .map((entryPath) => {
      const [area, ...parts] = entryPath.split("/");
      const name = parts.pop();
      const folderId = parts.join("/") || "root";
      return name && folderId && !folderId.includes("/") && folderId !== "." && folderId !== ".."
        ? `${area}\0${folderId}\0${name}`
        : null;
    })
    .filter(Boolean));
}

function restoreSyncEntryDueAt(entry, now) {
  if (entry.state === "completed") return null;
  const parseDeadline = (value) => {
    if (value == null || value === "") return null;
    const parsed = typeof value === "string" ? Date.parse(value) : NaN;
    if (!Number.isFinite(parsed)) {
      throw new Error("Persisted provider restore deadline is invalid; cloud access remains blocked");
    }
    if (parsed - now > MAX_RESTORE_SYNC_RETRY_DELAY_MS) {
      throw new Error("Persisted provider restore deadline exceeds the supported one-hour limit; cloud access remains blocked");
    }
    return parsed;
  };
  const leaseUntil = entry.leaseToken ? parseDeadline(entry.leaseUntil) : null;
  const nextAttemptAt = parseDeadline(entry.nextAttemptAt);
  if (entry.leaseToken && leaseUntil === null) {
    throw new Error("Persisted provider restore deadline is invalid; cloud access remains blocked");
  }
  const blockers = [entry.leaseToken ? leaseUntil : null, nextAttemptAt].filter(Number.isFinite);
  if (!blockers.length) return null;
  const dueAt = Math.max(...blockers);
  return dueAt > now ? dueAt : null;
}

async function reconcileUnknownProviderInventory({ baselineBackupId, clock, sleep } = {}) {
  if (typeof cloudStorage?.resolveInventoryContext === "function") await cloudStorage.resolveInventoryContext();
  const previousStatus = restoreProviderOrphans.getInventoryStatus();
  const status = restoreProviderOrphans.getInventoryStatus(cloudStorage);
  if (status.state !== "unknown") return { state: status.state, changed: false };
  const currentInventoryContext = cloudStorage.inventoryContext?.() || null;
  const markerNeedsUpdate = status.backupId && (previousStatus.state !== "unknown" || previousStatus.inventoryContext !== currentInventoryContext);
  if (!cloudStorage?.enabled?.()) {
    if (markerNeedsUpdate) {
      try {
        await restoreProviderOrphans.markInventoryUnknown(status.backupId, {
          inventoryContext: currentInventoryContext || status.inventoryContext,
          previousInventoryContext: status.previousInventoryContext || previousStatus.inventoryContext,
        }, { validateBaseline: () => backupService.getBackupOrThrow(status.backupId) });
      } catch (error) {
        if (!["Backup nao encontrado", "Arquivo de backup nao encontrado"].includes(error.message)) throw error;
      }
    }
    return { state: "unknown", providerDisabled: true, changed: false };
  }
  if (typeof cloudStorage.inventory !== "function") throw new Error("Cloud provider inventory is required before cloud access can resume");
  const explicitBaseline = String(baselineBackupId || process.env.ROOTARK_PROVIDER_INVENTORY_BASELINE_BACKUP_ID || "").trim();
  let missingSelectedBaseline = false;
  if (status.backupId) {
    try { backupService.getBackupOrThrow(status.backupId); }
    catch (error) {
      if (!["Backup nao encontrado", "Arquivo de backup nao encontrado"].includes(error.message)) throw error;
      missingSelectedBaseline = true;
    }
  }
  if (missingSelectedBaseline && !explicitBaseline) {
    throw new Error("The selected provider inventory baseline is missing; set ROOTARK_PROVIDER_INVENTORY_BASELINE_BACKUP_ID to a different complete backup");
  }
  if (missingSelectedBaseline && explicitBaseline === status.backupId) {
    throw new Error("The selected provider inventory baseline is missing; ROOTARK_PROVIDER_INVENTORY_BASELINE_BACKUP_ID must name a different complete backup");
  }
  if (status.backupId && explicitBaseline && status.backupId !== explicitBaseline) {
    if (!missingSelectedBaseline) throw new Error("Explicit provider inventory baseline conflicts with the durable restore selection");
  }
  const selectedBackupId = missingSelectedBaseline || !status.backupId ? explicitBaseline : status.backupId;
  if (!selectedBackupId) throw new Error("An explicit backup baseline is required to reconcile legacy provider inventory");
  if (missingSelectedBaseline || !status.backupId) {
    await restoreProviderOrphans.markInventoryUnknown(selectedBackupId, { inventoryContext: currentInventoryContext }, {
      validateBaseline: () => backupService.getBackupOrThrow(selectedBackupId),
    });
  } else if (markerNeedsUpdate) {
    await restoreProviderOrphans.markInventoryUnknown(status.backupId, {
      inventoryContext: currentInventoryContext || status.inventoryContext,
      previousInventoryContext: status.previousInventoryContext || previousStatus.inventoryContext,
    }, { validateBaseline: () => backupService.getBackupOrThrow(status.backupId) });
  }

  const { backup, archivePath } = backupService.getBackupOrThrow(selectedBackupId);
  const { manifest } = await validateBackupArchive(backup, archivePath);
  const localPlan = await localReconciliationPlan(manifest);
  let selectedBackup = backupRepository.getBackup(selectedBackupId) || backup;
  const previousSync = selectedBackup.metadata?.restoreSync;
  const samePlan = previousSync?.providerContext === currentInventoryContext
    && previousSync?.localDeltaFingerprint === localPlan.fingerprint
    && JSON.stringify((previousSync.entries || []).map(({ path: entryPath, sourceHash }) => [entryPath, sourceHash]))
      === JSON.stringify(localPlan.entries.map(({ path: entryPath, sourceHash }) => [entryPath, sourceHash]));
  if (!samePlan || previousSync.state === "cancelled") {
    const now = Date.now();
    if ((previousSync?.entries || []).some((entry) => entry.leaseToken && Date.parse(entry.leaseUntil || "") > now)) {
      throw new Error("Provider restore sync lease is active during context change; cloud access remains blocked");
    }
    const restoreSync = createRestoreSync(manifest, clock, localPlan.entries);
    restoreSync.providerContext = currentInventoryContext;
    restoreSync.localDeltaFingerprint = localPlan.fingerprint;
    selectedBackup = backupRepository.saveBackup({
      ...selectedBackup,
      metadata: { ...selectedBackup.metadata, restoreSync },
    });
  }
  const queuedSync = selectedBackup.metadata?.restoreSync;
  if ((queuedSync?.entries || []).some((entry) => entry.state === "completed")) {
    const at = syncNow();
    selectedBackup = backupRepository.saveBackup({
      ...selectedBackup,
      metadata: {
        ...selectedBackup.metadata,
        restoreSync: {
          ...queuedSync,
          state: "pending",
          completedAt: null,
          entries: queuedSync.entries.map((entry) => entry.state === "completed"
            ? { ...entry, state: "pending", nextAttemptAt: null, failureCategory: null, leaseToken: null, leaseUntil: null }
            : entry),
          transitions: [...(queuedSync.transitions || []), { state: "pending", at }],
        },
      },
    });
  }
  const wait = typeof sleep === "function"
    ? sleep
    : (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
  while (true) {
    const sync = selectedBackup.metadata?.restoreSync;
    const now = Date.parse(syncNow(clock));
    const entries = sync?.entries || [];
    const allCompleted = entries.length > 0 && entries.every((entry) => entry.state === "completed");
    const dueTimes = entries.map((entry) => restoreSyncEntryDueAt(entry, now));
    const hasEligibleEntry = entries.some((entry, index) => entry.state !== "completed" && dueTimes[index] === null);
    const dueAt = dueTimes.filter(Number.isFinite).sort((left, right) => left - right)[0] || null;
    if (!hasEligibleEntry && !allCompleted && dueAt !== null) {
      const waitMs = dueAt - now;
      await wait(waitMs);
      selectedBackup = backupRepository.getBackup(selectedBackupId) || selectedBackup;
      continue;
    }
    if (!hasEligibleEntry && !allCompleted) break;
    const revision = Number(sync?.revision) || 0;
    const priorAttempts = new Map(entries.map((entry) => [entry.entryId, Number(entry.attempts) || 0]));
    selectedBackup = await processRestoreSyncInternal(
      { backupId: selectedBackupId, clock, uploader: cloudStorage },
      STARTUP_INVENTORY_RECONCILIATION,
    );
    const updatedSync = selectedBackup?.metadata?.restoreSync;
    if (updatedSync?.state === "completed") break;
    const attemptedFailure = (updatedSync?.entries || []).some((entry) => ["retry_wait", "terminal_failure"].includes(entry.state)
      && (Number(entry.attempts) || 0) > (priorAttempts.get(entry.entryId) || 0));
    if (attemptedFailure || (Number(updatedSync?.revision) || 0) <= revision) break;
  }
  const sync = selectedBackup?.metadata?.restoreSync;
  if (!sync || sync.state !== "completed" || (sync.entries || []).some((entry) => entry.state !== "completed")) {
    throw new Error(`Selected archive uploads are not fully reconciled (${sync?.state || "missing"}); cloud access remains blocked`);
  }
  const selectedUploads = new Set(sync.entries.map((entry) => restoreProviderOrphans.identityKey(entry.area, entry.folderId, entry.name)));
  const inventory = await cloudStorage.inventory();
  if (!Array.isArray(inventory)) throw new Error("Cloud provider inventory is invalid; cloud access remains blocked");
  const normalizedInventory = restoreProviderOrphans.normalizeObjects(inventory
    .filter((entry) => ["uploads", "temp"].includes(entry.area))
    .map(({ area, folderId, name }) => ({ area, folderId, name })));
  restoreProviderOrphans.assertUnambiguousProviderInventory(normalizedInventory);
  const orphaned = normalizedInventory.filter((entry) => !selectedUploads.has(
    restoreProviderOrphans.identityKey(entry.area, entry.folderId, entry.name),
  ));
  await restoreProviderOrphans.reconcileInventory(selectedBackupId, orphaned, cloudStorage.inventoryContext?.() || null);
  return { state: "reconciled", backupId: backup.id, suppressed: orphaned.length, changed: true };
}

function createRestoreSync(manifest, clock, entriesOverride = null) {
  const queuedAt = syncNow(clock);
  const entries = entriesOverride || syncEntries(manifest);
  const state = entries.length ? "pending" : "completed";
  return {
    operationId: crypto.randomUUID(),
    revision: 0,
    state,
    queuedAt,
    lastAttemptAt: null,
    completedAt: state === "completed" ? queuedAt : null,
    failureCategory: null,
    entries,
    transitions: [{ state, at: queuedAt }],
  };
}

function syncTransition(sync, state, at, details = {}) {
  return { ...sync, ...details, state, transitions: [...(sync.transitions || []), { state, at }] };
}

function claimSyncEntry(backupId, entryId, { now, leaseMs = 60 * 1000, workerId = crypto.randomUUID(), providerIdentity } = {}) {
  const current = backupRepository.getBackup(backupId);
  const sync = current?.metadata?.restoreSync;
  const index = sync?.entries?.findIndex((entry) => entry.entryId === entryId);
  if (!current || !sync || index < 0) return null;
  const existing = sync.entries[index];
  const leaseUntil = new Date(existing.leaseUntil || 0).getTime();
  if (existing.state === "completed" || (existing.leaseToken && leaseUntil > now)) return null;
  const token = `${workerId}:${crypto.randomUUID()}`;
  try {
    const saved = backupRepository.mutateRestoreSyncEntry({
      backupId,
      operationId: sync.operationId,
      entryId,
      expectedState: ["pending", "retry_wait", "in_progress", "terminal_failure"],
      expectedLeaseToken: existing.leaseToken || null,
      expectedRevision: Number(sync.revision) || 0,
      mutate: (entry) => ({
        entry: {
          ...entry,
          state: "in_progress",
          attempts: (Number(entry.attempts) || 0) + 1,
          nextAttemptAt: null,
          leaseToken: token,
          leaseUntil: new Date(now + leaseMs).toISOString(),
          providerIdentity: providerIdentity || entry.providerIdentity || "cloud",
        },
        details: { lastAttemptAt: new Date(now).toISOString() },
        at: new Date(now).toISOString(),
      }),
    });
    const claimedEntry = saved.metadata.restoreSync.entries.find((entry) => entry.entryId === entryId);
    return { backup: saved, entry: claimedEntry, token };
  } catch (error) {
    if (["backup_revision_conflict", "backup_state_conflict", "backup_lease_conflict", "backup_mutation_conflict"].includes(error.code)) return null;
    throw error;
  }
}

function cancelRestoreSync(backupId, reason = "cancelled", { clock } = {}) {
  let backup = backupRepository.getBackup(backupId);
  const current = backup?.metadata?.restoreSync;
  if (!backup || !current || ["completed", "cancelled"].includes(current.state)) return backup;
  const at = syncNow(clock);
  for (const entry of current.entries || []) {
    if (entry.state === "cancelled" || entry.state === "completed") continue;
    try {
      backup = backupRepository.mutateRestoreSyncEntry({
        backupId,
        operationId: backup.metadata.restoreSync.operationId,
        entryId: entry.entryId,
        expectedState: entry.state,
        expectedLeaseToken: entry.leaseToken || null,
        expectedRevision: Number(backup.metadata.restoreSync.revision) || 0,
        mutate: (latestEntry) => ({
          entry: { ...latestEntry, state: "cancelled", leaseToken: null, leaseUntil: null, nextAttemptAt: null },
          details: { cancellationReason: String(reason).slice(0, 120) },
          at,
        }),
      });
    } catch (error) {
      if (!["backup_revision_conflict", "backup_state_conflict", "backup_lease_conflict", "backup_mutation_conflict"].includes(error.code)) throw error;
      backup = backupRepository.getBackup(backupId) || backup;
    }
  }
  return backupRepository.getBackup(backupId) || backup;
}

const STARTUP_INVENTORY_RECONCILIATION = Symbol("startup-inventory-reconciliation");

async function processRestoreSyncInternal({ backupId, clock, uploader, leaseMs = 60 * 1000, workerId, runFileLifecycleMutation } = {}, authority) {
  const provider = uploader || cloudStorage;
  let latest = backupRepository.getBackup(backupId);
  if (!latest || !latest.metadata?.restoreSync || !provider?.enabled?.()) return latest;
  if (restoreProviderOrphans.isInventoryUnknown(provider) && authority !== STARTUP_INVENTORY_RECONCILIATION) restoreProviderOrphans.assertProviderAvailable(provider);
  if (latest.metadata.restoreSync.entries?.length
    && latest.metadata.restoreSync.entries.every((entry) => entry.state === "completed")
    && latest.metadata.restoreSync.state !== "completed") {
    const entry = latest.metadata.restoreSync.entries[0];
    try {
      latest = backupRepository.mutateRestoreSyncEntry({
        backupId,
        operationId: latest.metadata.restoreSync.operationId,
        entryId: entry.entryId,
        expectedState: "completed",
        expectedLeaseToken: null,
        expectedRevision: Number(latest.metadata.restoreSync.revision) || 0,
        mutate: (latestEntry) => ({ entry: latestEntry, details: { failureCategory: null }, at: syncNow(clock) }),
      });
    } catch (error) {
      if (!["backup_revision_conflict", "backup_state_conflict", "backup_lease_conflict", "backup_mutation_conflict"].includes(error.code)) throw error;
      latest = backupRepository.getBackup(backupId) || latest;
    }
  }
  if (["completed", "cancelled"].includes(latest.metadata.restoreSync.state)) return latest;
  const now = typeof clock === "function" ? clock() : clock?.now ? clock.now() : Date.now();
  const providerIdentity = String(provider.provider || provider.name || "cloud").toLowerCase();
  for (const candidate of latest.metadata.restoreSync.entries || []) {
    if (candidate.state === "completed") continue;
    if (candidate.nextAttemptAt && new Date(candidate.nextAttemptAt).getTime() > now) continue;
    const lease = claimSyncEntry(backupId, candidate.entryId, { now, leaseMs, workerId, providerIdentity });
    if (!lease) continue;
    try {
      const reconcileObject = async () => {
        const localPath = resolveRuntimePath(lease.entry.path);
        const sourceStat = fs.lstatSync(localPath, { throwIfNoEntry: false });
        if (!sourceStat?.isFile() || sourceStat.isSymbolicLink()) {
          throw Object.assign(new Error("restore source unavailable"), { code: "source_unavailable" });
        }
        if (lease.entry.sourceHash && await backupService.calculateFileHash(localPath) !== lease.entry.sourceHash) {
          throw Object.assign(new Error("restore source changed during reconciliation"), { code: "source_unavailable" });
        }
          let entryForUpload = lease.entry;
          if (providerIdentity === "gdrive") {
            if (typeof provider.resolveUploadId !== "function") {
              throw Object.assign(new Error("Google Drive adapter cannot reserve an idempotent restore target"), { code: "configuration" });
            }
            let providerFileId = String(entryForUpload.providerFileId || "").trim();
            if (!providerFileId) {
              providerFileId = String(await provider.resolveUploadId(entryForUpload.folderId, entryForUpload.name, entryForUpload.area) || "").trim();
              if (!providerFileId) throw Object.assign(new Error("Google Drive did not provide a stable restore target"), { code: "configuration" });
              const beforePin = backupRepository.getBackup(backupId);
              const currentEntry = beforePin?.metadata?.restoreSync?.entries?.find((value) => value.entryId === lease.entry.entryId);
              if (!currentEntry || currentEntry.leaseToken !== lease.token) return false;
              const pinned = backupRepository.mutateRestoreSyncEntry({
                backupId,
                operationId: beforePin.metadata.restoreSync.operationId,
                entryId: lease.entry.entryId,
                expectedState: "in_progress",
                expectedLeaseToken: lease.token,
                expectedRevision: Number(beforePin.metadata.restoreSync.revision) || 0,
                mutate: (latestEntry) => ({
                  entry: { ...latestEntry, providerFileId },
                  details: {},
                  at: syncNow(clock),
                }),
              });
              entryForUpload = pinned.metadata.restoreSync.entries.find((value) => value.entryId === lease.entry.entryId);
              if (!entryForUpload || entryForUpload.leaseToken !== lease.token || entryForUpload.providerFileId !== providerFileId) return false;
            }
          }
          const uploaded = await provider.upload(localPath, entryForUpload.folderId, entryForUpload.name, entryForUpload.area,
            providerIdentity === "gdrive" ? { providerFileId: entryForUpload.providerFileId } : undefined);
          if (!uploaded) throw Object.assign(new Error("restore source unavailable"), { code: "source_unavailable" });
          if (lease.entry.sourceHash && await backupService.calculateFileHash(localPath) !== lease.entry.sourceHash) {
            throw Object.assign(new Error("restore source changed during upload"), { code: "source_unavailable" });
          }
          if (authority !== STARTUP_INVENTORY_RECONCILIATION) {
            await restoreProviderOrphans.clear(entryForUpload.folderId, entryForUpload.name, entryForUpload.area, provider);
          }
          return true;
      };
      const runMutation = typeof runFileLifecycleMutation === "function"
        ? runFileLifecycleMutation
        : (_folderId, _fileName, work) => work();
      if (await runMutation(lease.entry.folderId, lease.entry.name, reconcileObject) === false) {
        latest = backupRepository.getBackup(backupId) || latest;
        continue;
      }
      const current = backupRepository.getBackup(backupId);
      const entry = current?.metadata?.restoreSync?.entries?.find((value) => value.entryId === lease.entry.entryId);
      if (!entry || entry.leaseToken !== lease.token) continue;
      const at = syncNow(clock);
      backupRepository.mutateRestoreSyncEntry({
        backupId,
        operationId: current.metadata.restoreSync.operationId,
        entryId: lease.entry.entryId,
        expectedState: "in_progress",
        expectedLeaseToken: lease.token,
        expectedRevision: Number(current.metadata.restoreSync.revision) || 0,
        mutate: (latestEntry) => ({ entry: { ...latestEntry, state: "completed", failureCategory: null, nextAttemptAt: null, leaseToken: null, leaseUntil: null }, details: { failureCategory: null }, at }),
      });
    } catch (error) {
      if (error.code?.startsWith("backup_")) throw error;
      const current = backupRepository.getBackup(backupId);
      const entry = current?.metadata?.restoreSync?.entries?.find((value) => value.entryId === lease.entry.entryId && value.leaseToken === lease.token);
      if (!entry) continue;
      const attempts = Math.max(1, Number(entry.attempts) || 1);
      const failureCategory = ["source_unavailable", "configuration"].includes(error.code) ? error.code : "provider_error";
      const at = syncNow(clock);
      const nextAttemptAt = new Date(Date.parse(at) + Math.min(MAX_RESTORE_SYNC_RETRY_DELAY_MS, 1000 * (2 ** (attempts - 1)))).toISOString();
      try {
        backupRepository.mutateRestoreSyncEntry({
          backupId,
          operationId: current.metadata.restoreSync.operationId,
          entryId: lease.entry.entryId,
          expectedState: "in_progress",
          expectedLeaseToken: lease.token,
          expectedRevision: Number(current.metadata.restoreSync.revision) || 0,
          mutate: (latestEntry) => ({ entry: { ...latestEntry, state: "retry_wait", failureCategory, nextAttemptAt, leaseToken: null, leaseUntil: null }, details: { failureCategory: null }, at }),
        });
      } catch (mutationError) {
        if (!["backup_revision_conflict", "backup_state_conflict", "backup_lease_conflict", "backup_mutation_conflict"].includes(mutationError.code)) throw mutationError;
      }
    }
    latest = backupRepository.getBackup(backupId) || latest;
  }
  return backupRepository.getBackup(backupId) || latest;
}

async function processRestoreSync(options = {}) {
  return processRestoreSyncInternal(options);
}

function isZipSymlink(entry) {
  if (entry.type === "SymbolicLink") return true;
  const madeByUnix = (Number(entry.versionMadeBy) >>> 8) === 3;
  const unixMode = Number(entry.externalFileAttributes) >>> 16;
  return madeByUnix && (unixMode & S_IFMT) === S_IFLNK;
}

function assertSafeZipPath(entryPath) {
  const archivePath = String(entryPath || "").replace(/\\/g, "/");
  if (!archivePath || archivePath.startsWith("/") || /^[a-zA-Z]:/.test(archivePath)) {
    throw new Error(`Caminho invalido no backup: ${entryPath}`);
  }
  const parts = archivePath.split("/");
  if (parts.includes("..")) throw new Error(`Path traversal bloqueado: ${entryPath}`);
  const normalized = path.posix.normalize(archivePath);
  if (parts[0] !== "backup-manifest.json" && !RESTORABLE_ROOTS.has(parts[0])) {
    throw new Error(`Entrada nao permitida no backup: ${entryPath}`);
  }
  const normalizedFolded = normalized.replace(/\/+$/, "").toLowerCase();
  if (normalizedFolded === "data/.rootark-quarantine-restore-journal.json"
    || normalizedFolded.startsWith("data/.rootark-quarantine-restore-metadata-")
    || normalizedFolded.startsWith("data/.rootark-restore-coordinator.json")
    || normalizedFolded === `data/${path.basename(restoreProviderOrphans.POLICY_PATH)}`
    || normalizedFolded === `data/${path.basename(restoreProviderOrphans.STATE_PATH)}`
    || normalizedFolded.startsWith("data/.rootark-active-requests/")
    || normalizedFolded.startsWith("data/.rootark-restore-restart-acks/")
    || (normalizedFolded === "data/quarantine.json" && normalized !== "data/quarantine.json")) {
    throw new Error(`Entrada de controle bloqueada no backup: ${entryPath}`);
  }
  const sensitiveName = path.posix.basename(normalized).toLowerCase();
  if (normalized.includes("data/backups/") || sensitiveName === "server-master.key"
    || sensitiveName === ".env" || sensitiveName.startsWith(".env.")) {
    throw new Error(`Entrada sensivel bloqueada no backup: ${entryPath}`);
  }
  return normalized;
}

async function readManifest(archivePath) {
  const zip = await unzipper.Open.file(archivePath);
  const manifestEntry = zip.files.find((entry) => entry.path === "backup-manifest.json");
  if (!manifestEntry) throw new Error("Manifest ausente no backup");
  const raw = await manifestEntry.buffer();
  const manifest = JSON.parse(raw.toString("utf-8"));
  return { zip, manifest };
}

async function validateBackupArchive(backup, archivePath) {
  if (backup.checksum) {
    const checksum = await backupService.calculateFileHash(archivePath);
    if (checksum !== backup.checksum) {
      throw new Error("Checksum do backup nao confere");
    }
  }

  const { zip, manifest } = await readManifest(archivePath);
  const destinations = new Set();
  for (const entry of zip.files) {
    if (isZipSymlink(entry)) throw new Error(`Symlink bloqueado no backup: ${entry.path}`);
    const safePath = assertSafeZipPath(entry.path);
    const destinationKey = safePath.replace(/\/+$/, "").toLowerCase();
    if (destinations.has(destinationKey)) throw new Error(`Entrada duplicada no backup: ${entry.path}`);
    destinations.add(destinationKey);
  }
  if (!manifest.backup_id) throw new Error("Manifest invalido");
  await attestCiphertextOnlyArchive(zip);
  return { zip, manifest };
}

async function extractArchive(zip, targetDir) {
  const paths = restoreExtractionPaths(path.basename(path.resolve(targetDir)), { createRoot: true });
  const { restoreDir: target, stageStat: targetStat } = paths;
  if (path.resolve(targetDir) !== target) throw new Error("Restore staging directory escaped its root");
  if (targetStat) fs.rmSync(target, { recursive: true, force: false });
  restorePreimage.ensureSafeDirectory(RESTORE_TMP_DIR);
  fs.mkdirSync(target, { mode: 0o700 });

  for (const entry of zip.files) {
    const safePath = assertSafeZipPath(entry.path);
    if (safePath === "backup-manifest.json") continue;
    if (entry.type === "Directory") continue;
    if (isZipSymlink(entry)) throw new Error(`Symlink bloqueado no backup: ${entry.path}`);

    const destination = path.resolve(target, safePath);
    const relative = path.relative(target, destination);
    if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
      throw new Error(`Path traversal bloqueado: ${entry.path}`);
    }
    restorePreimage.ensureSafeDirectory(path.dirname(destination), { create: true });
    fs.writeFileSync(destination, await entry.buffer(), { flag: "wx", mode: 0o600 });
  }
}

function isPathWithin(basePath, targetPath) {
  const base = path.resolve(basePath);
  const target = path.resolve(targetPath);
  const comparableBase = process.platform === "win32" ? base.toLowerCase() : base;
  const comparableTarget = process.platform === "win32" ? target.toLowerCase() : target;
  const relative = path.relative(comparableBase, comparableTarget);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function canonicalPathWithMissingSuffix(value) {
  let current = path.resolve(value);
  const missing = [];
  while (true) {
    try {
      const realpath = fs.realpathSync.native || fs.realpathSync;
      return path.resolve(realpath(current), ...missing);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }

    try {
      fs.lstatSync(current);
      throw new Error("Cannot safely resolve quarantine path");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }

    const parent = path.dirname(current);
    if (parent === current) throw new Error("Cannot safely resolve quarantine path");
    missing.unshift(path.basename(current));
    current = parent;
  }
}

function pathVariants(value) {
  const resolved = path.resolve(value);
  const variants = new Map();
  const add = (candidate) => {
    const normalized = path.resolve(candidate);
    const key = process.platform === "win32" ? normalized.toLowerCase() : normalized;
    if (!variants.has(key)) variants.set(key, normalized);
  };
  add(resolved);
  try { add(fs.realpathSync.native ? fs.realpathSync.native(resolved) : fs.realpathSync(resolved)); } catch {}
  try { add(canonicalPathWithMissingSuffix(resolved)); } catch {}
  return [...variants.values()];
}

function isPathWithinAliases(basePath, targetPath) {
  return pathVariants(basePath).some((base) => pathVariants(targetPath).some((target) => isPathWithin(base, target)));
}

function nestedPathDepth(basePath, targetPath) {
  let depth = 0;
  for (const base of pathVariants(basePath)) {
    for (const target of pathVariants(targetPath)) {
      if (!isPathWithin(base, target) || isPathWithin(target, base)) continue;
      depth = Math.max(depth, path.relative(base, target).split(path.sep).filter(Boolean).length);
    }
  }
  return depth;
}

function assertSafeQuarantineRestoreLocation() {
  const uploads = resolveRuntimePath("uploads");
  const quarantine = getUploadQuarantineDir();
  if (quarantineDirContainsUploads(uploads, quarantine)) {
    throw new Error("Restore is not supported when the quarantine directory equals or contains uploads");
  }
  if (nestedPathDepth(uploads, quarantine) > 1) {
    throw new Error("Restore is not supported when the quarantine directory is nested below an uploads subdirectory; configure it outside uploads or as a direct child of uploads");
  }
}

function samePathComponent(left, right) {
  return process.platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right;
}

function hasSymlinkInPath(pathname) {
  const absolute = path.resolve(pathname);
  const root = path.parse(absolute).root;
  let current = root;
  for (const component of absolute.slice(root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    let stat;
    try { stat = fs.lstatSync(current); } catch (error) {
      if (error.code === "ENOENT") return false;
      throw error;
    }
    if (stat.isSymbolicLink()) return true;
  }
  return false;
}

function clearDirectoryPreservingQuarantine(destination, quarantinePath) {
  let rootStat;
  try { rootStat = fs.lstatSync(destination); } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) return;

  const resolveProtectedChild = () => {
    const matches = [];
    for (const destinationReal of pathVariants(destination)) {
      for (const quarantineReal of pathVariants(quarantinePath)) {
        if (!isPathWithin(destinationReal, quarantineReal) || isPathWithin(quarantineReal, destinationReal)) continue;
        const remaining = path.relative(destinationReal, quarantineReal).split(path.sep).filter(Boolean);
        if (remaining.length !== 1) {
          throw new Error("Restore is not supported when the quarantine directory is nested below an uploads subdirectory; configure it outside uploads or as a direct child of uploads");
        }
        matches.push({ destinationReal, component: remaining[0] });
      }
    }
    if (!matches.length) {
      throw new Error("Restore is not supported when the quarantine directory resolves outside uploads during restore");
    }
    const first = matches[0];
    if (matches.some((match) => !samePathComponent(match.component, first.component))) {
      throw new Error("Restore is not supported when the quarantine directory changes during restore");
    }
    return first;
  };
  const initial = resolveProtectedChild();
  const confirmProtectedChild = () => {
    const current = resolveProtectedChild();
    const sameDestination = isPathWithin(initial.destinationReal, current.destinationReal)
      && isPathWithin(current.destinationReal, initial.destinationReal);
    if (!sameDestination || !samePathComponent(current.component, initial.component)) {
      throw new Error("Restore is not supported when the quarantine directory changes during restore");
    }
  };

  const entries = fs.readdirSync(initial.destinationReal, { withFileTypes: true });
  confirmProtectedChild();
  for (const entry of entries) {
    confirmProtectedChild();
    if (samePathComponent(entry.name, initial.component)) continue;
    fs.rmSync(path.join(initial.destinationReal, entry.name), { recursive: true, force: true });
    confirmProtectedChild();
  }
}

function copyDirectoryContents(source, destination, protectedPath = null, onFile = null) {
  if (!fs.existsSync(source)) return;
  fs.mkdirSync(destination, { recursive: true });
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    const sourcePath = path.join(source, entry.name);
    const destinationPath = path.join(destination, entry.name);
    if (protectedPath && isPathWithinAliases(protectedPath, destinationPath)) continue;
    if (protectedPath && isPathWithinAliases(destinationPath, protectedPath)) {
      if (entry.isDirectory() && !hasSymlinkInPath(destinationPath)) {
        fs.mkdirSync(destinationPath, { recursive: true });
        copyDirectoryContents(sourcePath, destinationPath, protectedPath, onFile);
      }
      continue;
    }
    if (entry.isDirectory()) {
      fs.rmSync(destinationPath, { recursive: true, force: true });
      copyDirectoryContents(sourcePath, destinationPath, protectedPath, onFile);
    } else if (entry.isFile()) {
      fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
      onFile?.(sourcePath, destinationPath, "before-copy");
      fs.copyFileSync(sourcePath, destinationPath);
      onFile?.(sourcePath, destinationPath, "copied");
    }
  }
}

function restoreDataFiles(extractedRoot, onFile = null) {
  const extractedData = path.join(extractedRoot, "data");
  if (!fs.existsSync(extractedData)) return;

  closeDb();
  fs.mkdirSync(resolveRuntimePath("data"), { recursive: true });
  for (const name of fs.readdirSync(extractedData)) {
    const foldedName = name.toLowerCase();
    if (foldedName === "backups" || foldedName === "quarantine.json" || foldedName === ".rootark-quarantine-restore-journal.json" || foldedName.startsWith(".rootark-quarantine-restore-metadata-") || foldedName.startsWith(".rootark-restore-coordinator.json") || foldedName === path.basename(restoreProviderOrphans.POLICY_PATH) || foldedName === path.basename(restoreProviderOrphans.STATE_PATH) || foldedName === "server-master.key" || foldedName.endsWith(".key") || foldedName.startsWith("rootark.sqlite")) continue;
    const sourcePath = path.join(extractedData, name);
    const destinationPath = resolveRuntimePath("data", name);
    if (fs.statSync(sourcePath).isFile()) {
      onFile?.(sourcePath, destinationPath, "before-copy");
      fs.copyFileSync(sourcePath, destinationPath);
      onFile?.(sourcePath, destinationPath, "copied");
    }
  }
}

function restoreUploads(extractedRoot, onFile = null) {
  const extractedUploads = path.join(extractedRoot, "uploads");
  if (!fs.existsSync(extractedUploads)) return;

  const destinationUploads = resolveRuntimePath("uploads");
  const quarantineDir = path.resolve(getUploadQuarantineDir());
  const uploadsContainQuarantine = isPathWithinAliases(destinationUploads, quarantineDir);
  const quarantineContainsUploads = isPathWithinAliases(quarantineDir, destinationUploads);
  if (uploadsContainQuarantine && !quarantineContainsUploads) {
    clearDirectoryPreservingQuarantine(destinationUploads, quarantineDir);
    onFile?.(null, destinationUploads, "cleared");
    const uploadsStat = (() => { try { return fs.lstatSync(destinationUploads); } catch { return null; } })();
    if (uploadsStat?.isSymbolicLink()) return;
    copyDirectoryContents(extractedUploads, destinationUploads, quarantineDir, onFile);
    return;
  }
  if (quarantineContainsUploads) return;

  fs.rmSync(destinationUploads, { recursive: true, force: true });
  onFile?.(null, destinationUploads, "cleared");
  copyDirectoryContents(extractedUploads, destinationUploads, null, onFile);
}

function restoreFailureHook(options = {}) {
  let stepNumber = 0;
  return (step, details = {}) => {
    if (typeof options.failureInjector !== "function") return;
    stepNumber += 1;
    options.failureInjector(step, { ...details, stepNumber });
  };
}

function validateQuarantineArchive(extractedRoot, manifest) {
  if (manifest?.quarantine_format_version !== undefined && manifest.quarantine_format_version !== 1) {
    throw new Error("Quarantine archive format is not supported");
  }
  const hasQuarantineFormat = manifest?.quarantine_format_version === 1;
  const metadataPath = path.join(extractedRoot, "data", "quarantine.json");
  const metadata = readQuarantineMetadata(metadataPath);
  if (!metadata) {
    if (hasQuarantineFormat) throw new Error("Quarantine metadata is missing");
    return false;
  }
  const payloadRoot = path.join(extractedRoot, "data", "quarantine");
  if (!hasQuarantineFormat && metadata.items.length > 0 && !pathExists(payloadRoot)) {
    throw new Error("Quarantine archive payloads are missing");
  }
  validateQuarantinePayloads(metadata.items, payloadRoot);
  return true;
}

function pathExists(pathname) {
  try { fs.lstatSync(pathname); return true; }
  catch (error) { if (error.code === "ENOENT") return false; throw error; }
}

function sameRuntimeRoot(left, right) {
  const a = path.normalize(String(left || ""));
  const b = path.normalize(String(right || ""));
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function validateQuarantineDestination(destination) {
  const resolved = path.resolve(destination);
  const root = path.parse(resolved).root;
  if (resolved === root) throw new Error("Quarantine directory cannot be a filesystem root");
  if (pathExists(resolved)) {
    if (!fs.statSync(resolved).isDirectory()) throw new Error("Quarantine destination is not a directory");
    const actual = fs.realpathSync(resolved);
    if (actual === path.parse(actual).root) throw new Error("Quarantine directory cannot be a filesystem root");
  }
  return resolved;
}

function prepareQuarantineRestore(extractedRoot) {
  const metadataPath = path.join(extractedRoot, "data", "quarantine.json");
  const metadata = readQuarantineMetadata(metadataPath);
  if (!metadata) return null;

  const destination = validateQuarantineDestination(getUploadQuarantineDir());
  const metadataDestination = resolveRuntimePath("data", "quarantine.json");
  const dataStat = fs.lstatSync(path.dirname(metadataDestination));
  if (!dataStat.isDirectory() || dataStat.isSymbolicLink()) throw new Error("Quarantine metadata directory is unsafe");
  const archivedPayloads = validateQuarantinePayloads(metadata.items, path.join(extractedRoot, "data", "quarantine"));
  const currentMetadata = readQuarantineMetadata(metadataDestination);
  const currentPayloads = currentMetadata ? validateQuarantinePayloads(currentMetadata.items, destination) : [];
  const preservedSensitiveItems = (currentMetadata?.items || []).filter((item) => isSensitiveQuarantineItem(item));
  const preservedNames = new Set(preservedSensitiveItems.map((item) => item.storedQuarantineFilename.toLowerCase()));
  const preservedIds = new Set(preservedSensitiveItems.map((item) => item.id).filter(Boolean));
  const archivedItems = metadata.items.filter((item) => !isSensitiveQuarantineItem(item)
    && !preservedNames.has(item.storedQuarantineFilename.toLowerCase())
    && !(item.id && preservedIds.has(item.id)));
  const archivedNames = new Set(archivedItems.map((item) => item.storedQuarantineFilename.toLowerCase()));
  const extractedPayloads = archivedPayloads.filter((payload) => archivedNames.has(payload.filename.toLowerCase()));
  const restoredPayloads = [
    ...extractedPayloads,
    ...currentPayloads.filter((payload) => preservedNames.has(payload.filename.toLowerCase())),
  ];
  const currentFilenames = new Set(currentPayloads.map((payload) => payload.filename.toLowerCase()));
  for (const payload of restoredPayloads) {
    let targetExists = false;
    try { fs.lstatSync(path.join(destination, payload.filename)); targetExists = true; }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    if (targetExists && !currentFilenames.has(payload.filename.toLowerCase())) {
      throw new Error("Quarantine payload destination already exists");
    }
  }

  return {
    destination,
    extractedPayloads,
    restoredPayloads,
    metadataContents: Buffer.from(JSON.stringify({ ...metadata, items: [...archivedItems, ...preservedSensitiveItems] })),
    metadataDestination,
    oldMetadataExists: Boolean(currentMetadata),
    currentPayloads,
  };
}

function quarantineJournalPath() {
  return resolveRuntimePath("data", ".rootark-quarantine-restore-journal.json");
}

function quarantineMetadataStagePath(transactionId, kind) {
  if (!/^[a-f0-9-]{36}$/i.test(transactionId || "") || !["old", "new"].includes(kind)) {
    throw new Error("Quarantine metadata staging path is invalid");
  }
  return resolveRuntimePath("data", `.rootark-quarantine-restore-metadata-${transactionId}-${kind}.tmp`);
}

function hasPendingQuarantineRestore() {
  return pathExists(quarantineJournalPath());
}

function quarantineStagePath(destination, transactionId) {
  const root = path.resolve(destination);
  const stage = path.resolve(root, `.rootark-quarantine-restore-${transactionId}`);
  if (!stage.startsWith(`${root}${path.sep}`)) throw new Error("Quarantine restore staging escaped its boundary");
  return stage;
}

function validQuarantineRestoreJournal(value) {
  if (!value || value.version !== 1 || !/^[a-f0-9-]{36}$/i.test(value.transactionId || "")) return false;
  if (typeof value.destination !== "string" || !sameRuntimeRoot(value.destination, getUploadQuarantineDir())) return false;
  if (typeof value.oldMetadataExists !== "boolean" || !/^[a-f0-9]{64}$/.test(value.metadataHash || "")) return false;
  if (!Array.isArray(value.oldPayloads) || !Array.isArray(value.newPayloads)) return false;
  const oldNames = new Set();
  for (const filename of value.oldPayloads) {
    if (!isSafeQuarantineFilename(filename) || oldNames.has(filename)) return false;
    oldNames.add(filename);
  }
  const newNames = new Set();
  for (const payload of value.newPayloads) {
    if (!payload || !isSafeQuarantineFilename(payload.filename) || !/^[a-f0-9]{64}$/.test(payload.sha256 || "") || newNames.has(payload.filename)) return false;
    newNames.add(payload.filename);
  }
  return true;
}

function isSafeQuarantineFilename(filename) {
  return typeof filename === "string" && Boolean(filename) && filename !== "." && filename !== ".."
    && path.basename(filename) === filename && !/[\\/<>:"|?*\u0000-\u001f]/.test(filename) && !/[. ]$/.test(filename)
    && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(filename);
}

function writeQuarantineJournal(journalPath, journal) {
  const temporary = `${journalPath}.${journal.transactionId}.tmp`;
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(journal)}\n`, { encoding: "utf8", flag: "wx" });
    fsyncFile(temporary);
    fs.renameSync(temporary, journalPath);
    fsyncDirectory(path.dirname(journalPath));
  } catch (error) {
    fs.rmSync(temporary, { force: true });
    throw error;
  }
}

function readQuarantineJournal(journalPath) {
  let journal;
  let contents;
  try { contents = readQuarantineRegularFile(journalPath, "utf8"); }
  catch (error) {
    if (error.code === "ENOENT") return null;
    throw new Error("Quarantine restore journal is invalid");
  }
  try { journal = JSON.parse(contents); }
  catch { throw new Error("Quarantine restore journal is invalid"); }
  if (!validQuarantineRestoreJournal(journal)) throw new Error("Quarantine restore journal is invalid");
  return journal;
}

function quarantineJournalStage(journal) {
  const destination = validateQuarantineDestination(journal.destination);
  const stage = quarantineStagePath(destination, journal.transactionId);
  const stat = fs.lstatSync(stage);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("Quarantine restore staging is invalid");
  return stage;
}

function expectedFileHash(pathname, expectedHash) {
  if (!pathExists(pathname)) return false;
  const stat = fs.lstatSync(pathname);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Quarantine restore found an unexpected file");
  return fileSha256(pathname) === expectedHash;
}

function rollbackQuarantineRestore(journal, stage) {
  const destination = journal.destination;
  for (let index = 0; index < journal.newPayloads.length; index += 1) {
    const payload = journal.newPayloads[index];
    const stagedNew = path.join(stage, `new-${index}`);
    if (pathExists(stagedNew)) continue;
    const target = path.join(destination, payload.filename);
    if (pathExists(target)) {
      if (!expectedFileHash(target, payload.sha256)) throw new Error("Quarantine rollback found a changed destination payload");
      fs.rmSync(target, { force: false });
    }
  }
  for (let index = journal.oldPayloads.length - 1; index >= 0; index -= 1) {
    const filename = journal.oldPayloads[index];
    const stagedOld = path.join(stage, `old-${index}`);
    if (!pathExists(stagedOld)) continue;
    const target = path.join(destination, filename);
    if (pathExists(target)) {
      const newPayload = journal.newPayloads.find((payload) => payload.filename === filename);
      if (!newPayload || !expectedFileHash(target, newPayload.sha256)) throw new Error("Quarantine rollback found a changed destination payload");
      fs.rmSync(target, { force: false });
    }
    fs.renameSync(stagedOld, target);
  }

  const metadataDestination = resolveRuntimePath("data", "quarantine.json");
  const stagedOldMetadata = quarantineMetadataStagePath(journal.transactionId, "old");
  const stagedNewMetadata = quarantineMetadataStagePath(journal.transactionId, "new");
  if (pathExists(stagedOldMetadata)) {
    if (pathExists(metadataDestination)) {
      if (!expectedFileHash(metadataDestination, journal.metadataHash)) throw new Error("Quarantine rollback found changed metadata");
      fs.rmSync(metadataDestination, { force: false });
    }
    fs.renameSync(stagedOldMetadata, metadataDestination);
  } else if (!journal.oldMetadataExists && pathExists(metadataDestination)) {
    if (!expectedFileHash(metadataDestination, journal.metadataHash)) throw new Error("Quarantine rollback found changed metadata");
    fs.rmSync(metadataDestination, { force: false });
  } else if (journal.oldMetadataExists && !pathExists(metadataDestination)) {
    throw new Error("Quarantine rollback could not find prior metadata");
  }
  if (pathExists(stagedNewMetadata)) fs.rmSync(stagedNewMetadata, { force: false });
  fsyncDirectory(destination);
  fsyncDirectory(path.dirname(metadataDestination));
}

function cleanupOrphanQuarantineStages(destination) {
  if (!pathExists(destination)) return;
  for (const entry of fs.readdirSync(destination, { withFileTypes: true })) {
    if (!/^\.rootark-quarantine-restore-[a-f0-9-]{36}$/i.test(entry.name) || !entry.isDirectory() || entry.isSymbolicLink()) continue;
    fs.rmSync(path.join(destination, entry.name), { recursive: true, force: true });
  }
}

function cleanupQuarantineMetadataStages(transactionId) {
  fs.rmSync(quarantineMetadataStagePath(transactionId, "old"), { force: true });
  fs.rmSync(quarantineMetadataStagePath(transactionId, "new"), { force: true });
  fsyncDirectory(path.dirname(quarantineJournalPath()));
}

function cleanupOrphanQuarantineMetadataStages(dataDirectory) {
  if (!pathExists(dataDirectory)) return;
  for (const name of fs.readdirSync(dataDirectory)) {
    if (!/^\.rootark-quarantine-restore-metadata-[a-f0-9-]{36}-(?:old|new)\.tmp$/i.test(name)) continue;
    const stagedPath = path.join(dataDirectory, name);
    const stat = fs.lstatSync(stagedPath);
    if (stat.isFile() && !stat.isSymbolicLink()) fs.rmSync(stagedPath, { force: false });
  }
  fsyncDirectory(dataDirectory);
}

function recoverQuarantineRestore(options = {}) {
  if (!fs.existsSync(backupService.BACKUPS_DIR)) {
    if (hasPendingQuarantineRestore()) throw new Error("Quarantine recovery cannot acquire its backup lock");
    return false;
  }
  const release = options.lockHeld ? null : backupService.acquireLock("restore");
  try {
    const destination = validateQuarantineDestination(getUploadQuarantineDir());
    const journalPath = quarantineJournalPath();
    const journal = readQuarantineJournal(journalPath);
    if (!journal) {
      cleanupOrphanQuarantineStages(destination);
      cleanupOrphanQuarantineMetadataStages(path.dirname(journalPath));
      return false;
    }
    const stage = quarantineJournalStage(journal);
    const commitMarker = path.join(stage, "committed");
    if (pathExists(commitMarker)) {
      const marker = fs.readFileSync(commitMarker, "utf8");
      if (marker !== journal.transactionId) throw new Error("Quarantine restore commit marker is invalid");
      cleanupQuarantineMetadataStages(journal.transactionId);
      fs.rmSync(journalPath, { force: false });
      fsyncDirectory(path.dirname(journalPath));
      fs.rmSync(stage, { recursive: true, force: true });
      return true;
    }
    rollbackQuarantineRestore(journal, stage);
    cleanupQuarantineMetadataStages(journal.transactionId);
    fs.rmSync(journalPath, { force: false });
    fsyncDirectory(path.dirname(journalPath));
    fs.rmSync(stage, { recursive: true, force: true });
    return true;
  } finally { release?.(); }
}

function restoreQuarantine(plan, onProgress = null) {
  if (!plan) return;
  const destination = validateQuarantineDestination(plan.destination);
  fs.mkdirSync(destination, { recursive: true });
  validateQuarantineDestination(destination);
  const transactionId = crypto.randomUUID();
  const stagingDirectory = quarantineStagePath(destination, transactionId);
  const journalPath = quarantineJournalPath();
  const stagedOldMetadata = quarantineMetadataStagePath(transactionId, "old");
  const stagedNewMetadata = quarantineMetadataStagePath(transactionId, "new");
  const journal = {
    version: 1,
    transactionId,
    destination,
    oldMetadataExists: plan.oldMetadataExists,
    metadataHash: crypto.createHash("sha256").update(plan.metadataContents).digest("hex"),
    oldPayloads: plan.currentPayloads.map((payload) => payload.filename),
    newPayloads: plan.restoredPayloads.map((payload) => ({ filename: payload.filename, sha256: fileSha256(payload.absolutePath) })),
  };
  let journalWritten = false;
  try {
    if (pathExists(journalPath)) throw new Error("A quarantine restore recovery is pending");
    fs.mkdirSync(stagingDirectory);
    plan.restoredPayloads.forEach((payload, index) => {
      const stagedPath = path.join(stagingDirectory, `new-${index}`);
      fs.copyFileSync(payload.absolutePath, stagedPath, fs.constants.COPYFILE_EXCL);
      fsyncFile(stagedPath);
    });
    fsyncDirectory(stagingDirectory);
    fsyncDirectory(destination);
    writeQuarantineJournal(journalPath, journal);
    journalWritten = true;
    onProgress?.("restore.quarantine.journal.persisted", { transactionId });

    fs.writeFileSync(stagedNewMetadata, plan.metadataContents, { flag: "wx" });
    fsyncFile(stagedNewMetadata);
    fsyncDirectory(path.dirname(plan.metadataDestination));
    plan.currentPayloads.forEach((payload, index) => {
      const stagedOldPath = path.join(stagingDirectory, `old-${index}`);
      fsyncFile(payload.absolutePath);
      fs.renameSync(payload.absolutePath, stagedOldPath);
      onProgress?.("restore.quarantine.old-payload.moved", { filename: payload.filename, index });
    });
    fsyncDirectory(destination);
    fsyncDirectory(stagingDirectory);
    for (let index = 0; index < plan.restoredPayloads.length; index += 1) {
      const payload = plan.restoredPayloads[index];
      const targetPath = path.join(destination, payload.filename);
      fs.renameSync(path.join(stagingDirectory, `new-${index}`), targetPath);
      onProgress?.("restore.quarantine.new-payload.installed", { filename: payload.filename, index });
    }
    fsyncDirectory(destination);
    fsyncDirectory(stagingDirectory);
    if (plan.oldMetadataExists) {
      fsyncFile(plan.metadataDestination);
      fs.renameSync(plan.metadataDestination, stagedOldMetadata);
      fsyncDirectory(path.dirname(plan.metadataDestination));
      onProgress?.("restore.quarantine.old-metadata.moved", { transactionId });
    }
    fs.renameSync(stagedNewMetadata, plan.metadataDestination);
    fsyncDirectory(path.dirname(plan.metadataDestination));
    onProgress?.("restore.quarantine.metadata.installed", { transactionId });
    const markerTemporary = path.join(stagingDirectory, "committed.tmp");
    fs.writeFileSync(markerTemporary, transactionId, { flag: "wx" });
    fsyncFile(markerTemporary);
    fs.renameSync(markerTemporary, path.join(stagingDirectory, "committed"));
    fsyncDirectory(stagingDirectory);
    onProgress?.("restore.quarantine.committed-marker.persisted", { transactionId });
  } catch (error) {
    if (journalWritten) {
      try {
        const activeJournal = readQuarantineJournal(journalPath);
        if (activeJournal) {
          const stage = quarantineJournalStage(activeJournal);
          if (pathExists(path.join(stage, "committed"))) {
            const marker = fs.readFileSync(path.join(stage, "committed"), "utf8");
            if (marker !== activeJournal.transactionId) throw new Error("Quarantine restore commit marker is invalid");
            fs.rmSync(path.join(stage, "committed"), { force: false });
            fsyncDirectory(stage);
          }
          rollbackQuarantineRestore(activeJournal, stage);
          cleanupQuarantineMetadataStages(activeJournal.transactionId);
        }
        fs.rmSync(journalPath, { force: true });
        fsyncDirectory(path.dirname(journalPath));
        fs.rmSync(stagingDirectory, { recursive: true, force: true });
      } catch (recoveryError) {
        error.recoveryError = recoveryError;
      }
    } else {
      fs.rmSync(stagingDirectory, { recursive: true, force: true });
    }
    throw error;
  }
  try {
    cleanupQuarantineMetadataStages(transactionId);
    fs.rmSync(journalPath, { force: false });
    fsyncDirectory(path.dirname(journalPath));
    fs.rmSync(stagingDirectory, { recursive: true, force: true });
  } catch {
    console.error("[restore] QUARANTINE_RESTORE_CLEANUP_FAILED");
  }
}

function validateDatabase(pathname) {
  const database = new Database(pathname, { readonly: true, fileMustExist: true });
  try {
    if (database.pragma("integrity_check", { simple: true }) !== "ok") throw new Error("Integridade SQLite invalida");
    if (database.pragma("foreign_key_check", { simple: true }) !== undefined) throw new Error("Chaves estrangeiras SQLite invalidas");
  } finally {
    database.close();
  }
}

const SQLITE_SUFFIXES = ["", "-wal", "-shm"];
const RESTORE_JOURNAL_VERSION = 1;

function databaseJournalPath(destinationPath) {
  return `${destinationPath}.restore-journal.json`;
}

function artifactPath(prefix, suffix) {
  return `${prefix}${suffix}`;
}

function fileSha256(pathname) {
  if (!fs.existsSync(pathname)) return null;
  return crypto.createHash("sha256").update(fs.readFileSync(pathname)).digest("hex");
}

function fsyncFile(pathname) {
  const fd = fs.openSync(pathname, "r");
  try {
    try { fs.fsyncSync(fd); } catch (error) {
      if (!(["EPERM", "ENOTSUP", "EINVAL"].includes(error.code) && process.platform === "win32")) throw error;
    }
  } finally { fs.closeSync(fd); }
}

function fsyncDirectory(dirname) {
  if (process.platform === "win32") return;
  const fd = fs.openSync(dirname, "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function fsyncCoordinatorDirectory(dirname) {
  if (process.platform === "win32") return false;
  const fd = fs.openSync(dirname, "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return true;
}

function writeRestoreJournal(journal) {
  const pathname = journal.journalPath;
  const temporary = `${pathname}.${crypto.randomUUID()}.tmp`;
  fs.mkdirSync(path.dirname(pathname), { recursive: true });
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(journal, null, 2)}\n`, { flag: "wx" });
    fsyncFile(temporary);
    fs.renameSync(temporary, pathname);
    fsyncDirectory(path.dirname(pathname));
  } catch (error) {
    try { fs.rmSync(temporary, { force: true }); } catch {}
    throw error;
  }
}

function readRestoreJournal(destinationPath) {
  const pathname = databaseJournalPath(destinationPath);
  if (!fs.existsSync(pathname)) return null;
  let journal;
  try {
    journal = JSON.parse(fs.readFileSync(pathname, "utf8"));
  } catch (error) {
    throw new Error(`Journal SQLite invalido; recuperacao interrompida: ${error.message}`);
  }
  const expectedDestination = path.resolve(destinationPath);
  if (journal.version !== RESTORE_JOURNAL_VERSION ||
      journal.destination !== expectedDestination ||
      !/^[a-f0-9-]{36}$/i.test(String(journal.transactionId || "")) ||
      !journal.stagePrefix || !journal.rollbackPrefix ||
      journal.journalPath !== pathname ||
      path.resolve(journal.stagePrefix) !== `${expectedDestination}.restore-stage-${journal.transactionId}` ||
      path.resolve(journal.rollbackPrefix) !== `${expectedDestination}.restore-rollback-${journal.transactionId}` ||
      !Array.isArray(journal.completedOperations)) {
    throw new Error("Journal SQLite ambiguo; recuperacao interrompida");
  }
  return journal;
}

function failureHook(options = {}) {
  const requested = options.failAfter ?? options.failureAfter ?? options.failAt ?? process.env.ROOTARK_SQLITE_FAIL_AFTER;
  let count = 0;
  return (name, journal) => {
    count += 1;
    if (typeof options.failureInjector === "function") options.failureInjector(name, { ...journal, step: name, stepNumber: count });
    if (requested !== undefined && (String(requested) === name || Number(requested) === count)) {
      const error = new Error(`Falha injetada no passo SQLite: ${name}`);
      error.code = "SQLITE_RESTORE_INJECTED_FAILURE";
      error.step = name;
      throw error;
    }
  };
}

function journalHas(journal, operation) {
  return journal.completedOperations.includes(operation);
}

function updateJournal(journal, phase) {
  journal.phase = phase;
  journal.updatedAt = new Date().toISOString();
  writeRestoreJournal(journal);
}

function recordOperation(journal, operation) {
  if (!journalHas(journal, operation)) journal.completedOperations.push(operation);
  journal.updatedAt = new Date().toISOString();
  writeRestoreJournal(journal);
}

function validateJournalArtifacts(journal) {
  const expected = new Set(SQLITE_SUFFIXES);
  for (const suffix of Object.keys(journal.originalPresent || {})) {
    if (!expected.has(suffix)) throw new Error("Journal SQLite contem sidecar desconhecido");
  }
  for (const suffix of SQLITE_SUFFIXES) {
    if (typeof journal.originalPresent?.[suffix] !== "boolean" || typeof journal.stagedPresent?.[suffix] !== "boolean") {
      throw new Error("Journal SQLite incompleto; recuperacao interrompida");
    }
  }
}

function rollbackRestoreJournal(journal, options = {}) {
  validateJournalArtifacts(journal);
  const hook = failureHook(options);
  updateJournal(journal, "rolling_back");

  for (const suffix of SQLITE_SUFFIXES) {
    const destination = artifactPath(journal.destination, suffix);
    const rollback = artifactPath(journal.rollbackPrefix, suffix);
    const stage = artifactPath(journal.stagePrefix, suffix);
    const originalMove = `original.move${suffix || ".primary"}`;
    const replacementMove = `replacement.move${suffix || ".primary"}`;
    const rollbackMove = `rollback.restore${suffix || ".primary"}`;

    if (journal.originalPresent[suffix]) {
      if (fs.existsSync(rollback)) {
        if (fs.existsSync(destination)) {
          fs.rmSync(destination, { force: true });
          recordOperation(journal, `rollback.remove-replacement${suffix || ".primary"}`);
          hook(`rollback.remove-replacement${suffix || ".primary"}`, journal);
        }
        fs.renameSync(rollback, destination);
        recordOperation(journal, rollbackMove);
        hook(rollbackMove, journal);
      } else if (!journalHas(journal, originalMove) && !journalHas(journal, rollbackMove)) {
        // The original was not moved. Leave it untouched.
      } else if (!fs.existsSync(destination)) {
        throw new Error(`Journal SQLite perdeu o original ${suffix || "principal"}`);
      }
    } else if (fs.existsSync(destination) && (journalHas(journal, replacementMove) || journal.phase !== "staged")) {
      fs.rmSync(destination, { force: true });
      recordOperation(journal, `rollback.remove-new${suffix || ".primary"}`);
      hook(`rollback.remove-new${suffix || ".primary"}`, journal);
    }
    fs.rmSync(stage, { force: true });
  }

  updateJournal(journal, "rolled_back");
  fs.rmSync(journal.journalPath, { force: true });
  fsyncDirectory(path.dirname(journal.journalPath));
}

function recoverDatabaseRestore(destinationPath, options = {}) {
  const resolvedDestination = path.resolve(destinationPath);
  const journal = readRestoreJournal(resolvedDestination);
  if (!journal) return { recovered: false, reason: "no_journal" };

  if (!["staged", "validated", "originals_moving", "originals_preserved", "replacement_moving", "replacement_installed", "reopened_verified", "rolling_back", "rolled_back", "committed"].includes(journal.phase)) {
    throw new Error("Journal SQLite contem fase desconhecida; recuperacao interrompida");
  }

  if (journal.phase === "committed") {
    validateJournalArtifacts(journal);
    for (const suffix of SQLITE_SUFFIXES) {
      fs.rmSync(artifactPath(journal.stagePrefix, suffix), { force: true });
      fs.rmSync(artifactPath(journal.rollbackPrefix, suffix), { force: true });
    }
    fs.rmSync(journal.journalPath, { force: true });
    fsyncDirectory(path.dirname(journal.journalPath));
    return { recovered: true, phase: "committed" };
  }

  rollbackRestoreJournal(journal, options);
  return { recovered: true, phase: "rolled_back" };
}

function recoverDatabaseRollback(destinationPath) {
  const journalResult = recoverDatabaseRestore(destinationPath);
  if (journalResult.recovered) return journalResult;
  if (fs.existsSync(destinationPath)) return { recovered: false, reason: "destination_exists" };
  const prefix = `${path.basename(destinationPath)}.restore-rollback-`;
  const candidates = fs.readdirSync(path.dirname(destinationPath)).filter((name) => name.startsWith(prefix) && !name.endsWith("-wal") && !name.endsWith("-shm"));
  if (candidates.length > 1) throw new Error("Rollbacks SQLite ambiguos; recuperacao interrompida");
  if (!candidates.length) return { recovered: false, reason: "no_rollback" };
  const rollbackPath = path.join(path.dirname(destinationPath), candidates[0]);
  fs.renameSync(rollbackPath, destinationPath);
  for (const suffix of ["-wal", "-shm"]) {
    const sidecar = `${rollbackPath}${suffix}`;
    if (fs.existsSync(sidecar)) fs.renameSync(sidecar, `${destinationPath}${suffix}`);
  }
  return { recovered: true, phase: "legacy_rollback" };
}

function restoreDatabaseFiles(extractedRoot, options = {}) {
  if (!isDbEnabled()) return false;
  const sourcePath = path.join(extractedRoot, "data", "rootark.sqlite");
  if (!fs.existsSync(sourcePath)) return false;

  const destinationPath = getDatabasePath();
  closeDb();
  fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
  recoverDatabaseRollback(destinationPath);
  const token = crypto.randomUUID();
  const stagePath = `${destinationPath}.restore-stage-${token}`;
  const rollbackPath = `${destinationPath}.restore-rollback-${token}`;
  const journal = {
    version: RESTORE_JOURNAL_VERSION,
    transactionId: token,
    destination: path.resolve(destinationPath),
    journalPath: databaseJournalPath(destinationPath),
    stagePrefix: stagePath,
    rollbackPrefix: rollbackPath,
    phase: "staged",
    startedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    completedOperations: [],
    originalPresent: Object.fromEntries(SQLITE_SUFFIXES.map((suffix) => [suffix, fs.existsSync(artifactPath(destinationPath, suffix))])),
    stagedPresent: Object.fromEntries(SQLITE_SUFFIXES.map((suffix) => [suffix, fs.existsSync(artifactPath(sourcePath, suffix))])),
    originalSha256: Object.fromEntries(SQLITE_SUFFIXES.map((suffix) => [suffix, fileSha256(artifactPath(destinationPath, suffix))])),
  };
  validateJournalArtifacts(journal);
  writeRestoreJournal(journal);
  const hook = failureHook(options);

  try {
  for (const suffix of SQLITE_SUFFIXES) {
    const source = artifactPath(sourcePath, suffix);
    if (fs.existsSync(source)) {
      fs.copyFileSync(source, artifactPath(stagePath, suffix));
      fsyncFile(artifactPath(stagePath, suffix));
      recordOperation(journal, `stage.copy${suffix || ".primary"}`);
      hook(`stage.copy${suffix || ".primary"}`, journal);
    }
  }
    validateDatabase(stagePath);
    recordOperation(journal, "stage.validate");
    hook("stage.validate", journal);
    updateJournal(journal, "staged");

    updateJournal(journal, "originals_moving");
    for (const suffix of SQLITE_SUFFIXES) {
      const destination = artifactPath(destinationPath, suffix);
      if (fs.existsSync(destination)) {
        fs.renameSync(destination, artifactPath(rollbackPath, suffix));
        recordOperation(journal, `original.move${suffix || ".primary"}`);
        hook(`original.move${suffix || ".primary"}`, journal);
      }
    }
    updateJournal(journal, "originals_preserved");
    updateJournal(journal, "replacement_moving");
    for (const suffix of SQLITE_SUFFIXES) {
      const staged = artifactPath(stagePath, suffix);
      if (fs.existsSync(staged)) {
        fs.renameSync(staged, artifactPath(destinationPath, suffix));
        recordOperation(journal, `replacement.move${suffix || ".primary"}`);
        hook(`replacement.move${suffix || ".primary"}`, journal);
      }
    }
    updateJournal(journal, "replacement_installed");
    validateDatabase(destinationPath);
    recordOperation(journal, "replacement.reopen-validate");
    hook("replacement.reopen-validate", journal);
    updateJournal(journal, "reopened_verified");
    updateJournal(journal, "committed");
    for (const suffix of SQLITE_SUFFIXES) {
      fs.rmSync(artifactPath(rollbackPath, suffix), { force: true });
      fs.rmSync(artifactPath(stagePath, suffix), { force: true });
    }
    fs.rmSync(journal.journalPath, { force: true });
    fsyncDirectory(path.dirname(destinationPath));
  } catch (error) {
    if (!options.simulateCrash && !options.leaveJournalOnFailure) {
      try { recoverDatabaseRestore(destinationPath); } catch (recoveryError) { error.recoveryError = recoveryError; }
    }
    throw error;
  }
  return true;
}

async function restoreBackup(id, options = {}) {
  if (String(options.confirmation || "") !== "RESTORE") {
    throw new Error("Confirmacao invalida. Digite RESTORE para restaurar.");
  }

  const pending = assertNoPendingWholeRestore();
  if (pending.restartRequired) throw new Error("Reinicie todas as instancias do servidor antes de iniciar outro restore");
  if (cloudStorage?.enabled?.() && restoreProviderOrphans.isInventoryUnknown(cloudStorage)) restoreProviderOrphans.assertProviderAvailable(cloudStorage);
  const requiredRestartInstances = configuredRestartInstanceCount();
  restoreInstanceId(requiredRestartInstances);

  assertSafeQuarantineRestoreLocation();
  const release = backupService.acquireLock("restore");
  let restoreDir = null;
  const injectFailure = restoreFailureHook(options);
  let coordinator = null;
  let mutationStarted = false;
  try {
    const { backup, archivePath } = backupService.getBackupOrThrow(id);
    const staging = restoreExtractionPaths(backup.id, { createRoot: true });
    restoreDir = staging.restoreDir;
    coordinator = persistWholeRestoreCoordinator({ backupId: backup.id, requiredRestartInstances });
    await options.waitForRequestQuiescence?.();
    let providerInventory = null;
    if (cloudStorage?.enabled()) {
      if (typeof cloudStorage.inventory !== "function") throw new Error("Cloud provider inventory is required before restore can protect unarchived objects");
      providerInventory = await cloudStorage.inventory();
      coordinator = updateWholeRestoreCoordinator(coordinator, { providerPolicyRequired: true });
      restoreProviderOrphans.assertUnambiguousProviderInventory(providerInventory
        .filter((entry) => ["uploads", "temp"].includes(entry.area))
        .map(({ area, folderId, name }) => ({ area, folderId, name })));
    }
    const preRestore = await backupService.createBackup({
      lockHeld: true,
      type: "pre-restore",
      createdBy: options.username || null,
      notes: `Backup automatico antes de restaurar ${id}`,
    });
    coordinator = updateWholeRestoreCoordinator(coordinator, {
      preRestoreBackupId: preRestore.id,
      selectedBackup: backup,
      preRestoreBackup: preRestore,
    });
    const { zip, manifest } = await validateBackupArchive(backup, archivePath);
    await extractArchive(zip, restoreDir);
    const hasQuarantineState = validateQuarantineArchive(restoreDir, manifest);
    const quarantinePlan = hasQuarantineState ? prepareQuarantineRestore(restoreDir) : null;
    const preimagePlan = wholePreimagePlan(restoreDir, quarantinePlan);
    let providerOrphans = null;
    if (providerInventory !== null) {
      const archivedObjects = archivedProviderObjects(manifest);
      providerOrphans = restoreProviderOrphans.normalizeObjects(providerInventory
        .filter((entry) => ["uploads", "temp"].includes(entry.area) && !archivedObjects.has(`${entry.area}\0${entry.folderId}\0${entry.name}`))
        .map(({ area, folderId, name }) => ({ area, folderId, name })));
    }
    const cloudSync = providerInventory !== null && syncEntries(manifest).length > 0
      ? createRestoreSync(manifest)
      : { state: "not_required" };
    const providerReconciliation = cloudSync.state === "pending"
      ? { backupId: backup.id, sync: cloudSync }
      : [];
    coordinator = updateWholeRestoreCoordinator(coordinator, {
      preimagePlan,
      preimageProgress: [],
      providerReconciliation,
      selectedBackup: cloudSync.state === "pending"
        ? { ...backup, metadata: { ...backup.metadata, restoreSync: cloudSync } }
        : backup,
    });
    const preimage = createWholeRestorePreimages(coordinator, restoreDir, quarantinePlan, (domain) => {
      coordinator = updateWholeRestoreCoordinator(coordinator, { preimageProgress: [...coordinator.preimageProgress, domain] });
      injectFailure(`restore.preimage.${domain}.verified`);
    });
    coordinator = updateWholeRestoreCoordinator(coordinator, { ...preimage, phase: "prepared" });
    injectFailure("restore.preimage.completed");
    injectFailure("restore.coordinator.persisted");
    injectFailure("restore.before-local-commit");
    mutationStarted = true;
    restoreQuarantine(quarantinePlan, (step, details) => injectFailure(step, details));
    if (quarantinePlan) {
      coordinator = updateWholeRestoreCoordinator(coordinator, { lastCompletedStage: "quarantine" });
      injectFailure("restore.quarantine.committed");
    }
    const restoredDataNames = restorableDataNames(restoreDir)
      .filter((name) => pathExists(path.join(restoreDir, "data", name)));
    restoreDataFiles(restoreDir, (sourcePath, destinationPath, phase) => {
      injectFailure(`restore.data.${phase}`, { sourcePath, destinationPath });
    });
    restorePreimage.syncFileSet(restoredDataNames.map((name) => resolveRuntimePath("data", name)));
    coordinator = updateWholeRestoreCoordinator(coordinator, { lastCompletedStage: "data" });
    restoreUploads(restoreDir, (sourcePath, destinationPath, phase) => {
      const step = phase === "cleared" ? "restore.uploads.cleared" : `restore.uploads.${phase}`;
      injectFailure(step, { sourcePath, destinationPath });
    });
    if (pathExists(path.join(restoreDir, "uploads"))) restorePreimage.syncTree(resolveRuntimePath("uploads"));
    coordinator = updateWholeRestoreCoordinator(coordinator, { lastCompletedStage: "uploads" });
    injectFailure("restore.sqlite.before-replacement");
    const restoredDatabase = restoreDatabaseFiles(restoreDir, {
      failureInjector(step, details) { injectFailure(`restore.sqlite.${step}`, details); },
    });
    coordinator = updateWholeRestoreCoordinator(coordinator, { lastCompletedStage: "sqlite" });
    if (restoredDatabase) injectFailure("restore.sqlite.committed");
    if (providerOrphans !== null) {
      injectFailure("restore.provider-orphans.before-persist");
      await restoreProviderOrphans.write(providerOrphans);
      injectFailure("restore.provider-orphans.persisted");
    } else {
      injectFailure("restore.provider-inventory-unknown.before-persist");
      await restoreProviderOrphans.markInventoryUnknown(backup.id, {}, {
        validateBaseline: () => {
          const archiveStat = fs.lstatSync(archivePath);
          if (!archiveStat.isFile() || archiveStat.isSymbolicLink()) throw new Error("Restore provider inventory baseline archive is unavailable");
        },
      });
      injectFailure("restore.provider-inventory-unknown.persisted");
    }
    const restoredBackup = coordinator.selectedBackup;
    backupRepository.saveBackup(restoredBackup);
    if (cloudSync.state === "pending") {
      injectFailure("restore.cloud-sync.persisted");
    }
    backupRepository.saveBackup(preRestore);
    injectFailure("restore.backup-history.reconciled");
    coordinator = updateWholeRestoreCoordinator(coordinator, {
      phase: "restart_required",
      completedAt: new Date().toISOString(),
      lastCompletedStage: "backup-history",
      selectedBackup: restoredBackup,
      preRestoreBackup: preRestore,
    });
    return {
      backup: restoredBackup,
      manifest,
      preRestore,
      restartRecommended: true,
      cloudSync,
    };
  } catch (error) {
    if (!mutationStarted && pathExists(WHOLE_RESTORE_COORDINATOR_PATH)) {
      try { completeWholeRestoreCoordinator(); } catch (cleanupError) { error.coordinatorCleanupError = cleanupError; }
    }
    throw error;
  } finally {
    try {
      if (restoreDir) cleanupRestoreExtraction(path.basename(restoreDir));
    } finally {
      release();
    }
  }
}

async function getBackupManifest(id) {
  const { backup, archivePath } = backupService.getBackupOrThrow(id);
  const { manifest } = await validateBackupArchive(backup, archivePath);
  return manifest;
}

module.exports = {
  cancelRestoreSync,
  createRestoreSync,
  getBackupManifest,
  reconcileUnknownProviderInventory,
  hasPendingQuarantineRestore,
  prepareQuarantineRestore,
  processRestoreSync,
  recoverQuarantineRestore,
  restoreBackup,
  setCloudStorage,
  validateBackupArchive,
  validateDatabase,
  recoverDatabaseRollback,
  recoverDatabaseRestore,
  assertNoPendingWholeRestore,
  prepareWholeRestoreStartup,
  acknowledgeWholeRestoreInstance,
  isWholeRestoreBlocked,
  requiresProviderOrphanPolicyAtStartup,
  getWholeRestorePhase,
  restoreDatabaseFiles,
  databaseJournalPath,
  SQLITE_SUFFIXES,
};
