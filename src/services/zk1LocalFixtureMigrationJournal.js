"use strict";

// Offline ciphertext relocation experiment for disposable synthetic fixtures ONLY.
// No production route, cloud adapter, client authorization or ZK cutover may call
// this module as an authorization decision. The source is never modified.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const SCHEMA = "rootark-zk1-local-fixture-migration-journal/v1";
const MODE = "rootark-zk-local-fixture-only/v1";
const MARKER = ".rootark-disposable-fixture";
const KINDS = ["versions", "backups", "trash"];
const PHASES = new Set(["planned", "committed", "rollback-pending", "rolled-back"]);
const MAX_BYTES = 16 * 1024 * 1024;

function refuse() {
  const error = new Error("LOCAL_FIXTURE_MIGRATION_REFUSED");
  error.code = error.message;
  throw error;
}
function sha(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function isId(value) { return typeof value === "string" && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(value); }
function isDigest(value) { return typeof value === "string" && /^[a-f0-9]{64}$/.test(value); }
function keys(value, expected) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join("|") === [...expected].sort().join("|");
}
function directory(dir) {
  try {
    const stat = fs.lstatSync(dir);
    if (!stat.isDirectory() || stat.isSymbolicLink()) refuse();
  } catch (_) { refuse(); }
}
function safeRoot(dir, mode) {
  if (mode !== MODE || typeof dir !== "string" || !path.isAbsolute(dir)) refuse();
  const root = path.resolve(dir);
  const temporary = path.resolve(os.tmpdir());
  if (path.dirname(root) !== temporary || !path.basename(root).startsWith("rootark-zk-local-fixture-")) refuse();
  // The whole path, including Windows reparse point ancestors, is checked. As
  // with the inventory probe, this requires a trusted, non-concurrent fixture.
  let segment = path.parse(root).root;
  for (const part of root.slice(segment.length).split(path.sep).filter(Boolean)) {
    segment = path.join(segment, part);
    directory(segment);
  }
  for (const sub of ["source", "target", "journal", "references", ...KINDS.map((k) => `references/${k}`)])
    directory(path.join(root, sub));
  const marker = readRegular(path.join(root, MARKER), 128).toString("utf8");
  if (marker !== "rootark-zk-local-fixture-v1\n") refuse();
  return root;
}
function sameFile(first, second) {
  return first.dev === second.dev && first.ino === second.ino;
}
function readRegular(file, maximum = MAX_BYTES, allowedLinks = 1) {
  let fd;
  try {
    const before = fs.lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== allowedLinks
      || before.size > maximum) refuse();
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || !sameFile(before, opened) || opened.nlink !== allowedLinks
      || opened.size > maximum) refuse();
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    const lastPath = fs.lstatSync(file);
    if (bytes.length > maximum || !sameFile(opened, after) || !sameFile(after, lastPath)
      || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs
      || after.nlink !== allowedLinks || lastPath.nlink !== allowedLinks
      || lastPath.isSymbolicLink()) refuse();
    return bytes;
  } catch (_) { refuse(); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function pathPresent(file) {
  try { fs.lstatSync(file); return true; }
  catch (error) { if (error.code === "ENOENT") return false; refuse(); }
}
function maybeRegular(file, expectedDigest, links = 1) {
  if (!pathPresent(file)) return false;
  if (sha(readRegular(file, MAX_BYTES, links)) !== expectedDigest) refuse();
  return true;
}
function flushDirectory(dir) {
  // Windows Node does not offer a portable durable directory-entry fsync.
  if (process.platform === "win32") return;
  let fd;
  try { fd = fs.openSync(dir, fs.constants.O_RDONLY); fs.fsyncSync(fd); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function writeNew(file, bytes) {
  let fd;
  try {
    fd = fs.openSync(file, "wx", 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
  } finally { if (fd !== undefined) fs.closeSync(fd); }
  flushDirectory(path.dirname(file));
}
function journalData(plan, phase) {
  const body = { schema: SCHEMA, phase, plan, planDigest: sha(Buffer.from(JSON.stringify(plan))) };
  return { ...body, recordDigest: sha(Buffer.from(JSON.stringify(body))) };
}
function storeJournal(file, record, initial) {
  // A fresh same-directory file is synced before atomic journal publication.
  // link() gives initial publication exclusive/no-clobber semantics; updates
  // rename over the old journal, which leaves either revision after a crash.
  const temporary = path.join(path.dirname(file), `.${path.basename(file)}.${crypto.randomBytes(12).toString("hex")}.tmp`);
  writeNew(temporary, JSON.stringify(record));
  try {
    if (initial) fs.linkSync(temporary, file);
    else fs.renameSync(temporary, file);
    flushDirectory(path.dirname(file));
  } finally {
    // Orphans left by process termination are inert; never ingest them.
    if (pathPresent(temporary)) fs.unlinkSync(temporary);
  }
}
function parseJournal(file, allowedLinks = 1) {
  const bytes = readRegular(file, 128 * 1024, allowedLinks);
  let data;
  try { data = JSON.parse(bytes.toString("utf8")); } catch (_) { refuse(); }
  if (!keys(data, ["schema", "phase", "plan", "planDigest", "recordDigest"])
    || data.schema !== SCHEMA || !PHASES.has(data.phase)
    || JSON.stringify(data) !== bytes.toString("utf8")) refuse();
  const body = { schema: data.schema, phase: data.phase, plan: data.plan, planDigest: data.planDigest };
  if (data.planDigest !== sha(Buffer.from(JSON.stringify(data.plan)))
    || data.recordDigest !== sha(Buffer.from(JSON.stringify(body)))) refuse();
  return data;
}
function normalizedPlan(input) {
  if (!input || !keys(input.sourceProvenance, ["role", "provider", "identity"])
    || !keys(input.targetProvenance, ["role", "provider", "identity"])
    || input.sourceProvenance.role !== "source"
    || input.sourceProvenance.provider !== "fixture-source"
    || input.targetProvenance.role !== "target"
    || input.targetProvenance.provider !== "fixture-target"
    || !isId(input.sourceProvenance.identity) || !isId(input.targetProvenance.identity)
    || input.sourceProvenance.identity === input.targetProvenance.identity
    || !isId(input.objectId) || !isId(input.operationId) || !isDigest(input.sourceDigest)
    || !keys(input.references, KINDS)) refuse();
  const references = {};
  for (const kind of KINDS) {
    const entries = input.references[kind];
    if (!Array.isArray(entries) || !entries.length || entries.length > 32) refuse();
    const ids = new Set();
    references[kind] = entries.map((entry) => {
      if (!keys(entry, ["id", "digest"]) || !isId(entry.id) || !isDigest(entry.digest)
        || ids.has(entry.id)) refuse();
      ids.add(entry.id);
      return { id: entry.id, digest: entry.digest };
    });
  }
  return {
    operationId: input.operationId, objectId: input.objectId, sourceDigest: input.sourceDigest,
    sourceProvenance: { ...input.sourceProvenance }, targetProvenance: { ...input.targetProvenance }, references,
  };
}
function paths(root, plan) {
  return { source: path.join(root, "source", `${plan.objectId}.ct`),
    target: path.join(root, "target", `${plan.objectId}.ct`),
    stage: path.join(root, "target", `.${plan.operationId}.stage`),
    journal: path.join(root, "journal", `${plan.operationId}.json`) };
}
function exactEntries(dir, names, type) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_) { refuse(); }
  if (entries.length !== names.length) refuse();
  const expected = new Set(names);
  for (const entry of entries) {
    if (!expected.delete(entry.name)
      || (type === "directory" ? !entry.isDirectory() : !entry.isFile())
      || entry.isSymbolicLink()) refuse();
  }
  if (expected.size) refuse();
}
function verifyInventory(root, plan, locations) {
  if (!maybeRegular(locations.source, plan.sourceDigest)) refuse();
  // A caller-supplied list is not evidence that all version/backup/trash
  // references were accounted for. This test-only fixture is explicit and
  // closed-world: reject additional, omitted or unexpected directory entries.
  exactEntries(path.join(root, "references"), KINDS, "directory");
  for (const kind of KINDS) {
    const folder = path.join(root, "references", kind);
    exactEntries(folder, plan.references[kind].map((entry) => `${entry.id}.ct`), "file");
    for (const item of plan.references[kind]) {
      if (!maybeRegular(path.join(folder, `${item.id}.ct`), item.digest)) refuse();
    }
  }
}
function checkpoint(input, name) { if (typeof input.onCheckpoint === "function") input.onCheckpoint(name); }
function report(phase, verified) {
  return Object.freeze({ schema: SCHEMA, canMigrate: false, rollbackScope: "local-fixture-only",
    state: phase, localVerified: verified,
    blockers: ["missing-owner-approved-migration", "missing-authoritative-provider-roles",
      "missing-client-decrypt-and-verify", "missing-live-version-backup-trash-sync-authority"] });
}
function readOperation(input) {
  const root = safeRoot(input?.fixtureDir, input?.fixtureMode);
  const plan = normalizedPlan(input);
  const locations = paths(root, plan);
  return { root, plan, locations };
}
function recoverInterruptedInitialJournalLink(file, plan) {
  let published;
  try { published = fs.lstatSync(file); }
  catch (_) { refuse(); }
  if (!published.isFile() || published.isSymbolicLink()) refuse();
  if (published.nlink === 1) return;
  // The initial exclusive link() briefly creates two names for one synced
  // inode. A process killed before temp unlink leaves exactly this state.
  if (published.nlink !== 2) refuse();
  const dir = path.dirname(file);
  // Journal basenames consist of a validated opaque ID followed by '.json'.
  const escaped = path.basename(file).replaceAll(".", "\\.");
  const pattern = new RegExp("^\\." + escaped + "\\.[a-f0-9]{24}\\.tmp$");
  let found;
  try { found = fs.readdirSync(dir, { withFileTypes: true }).filter((entry) => pattern.test(entry.name)); }
  catch (_) { refuse(); }
  if (found.length !== 1 || !found[0].isFile() || found[0].isSymbolicLink()) refuse();
  const temp = path.join(dir, found[0].name);
  const original = parseJournal(file, 2);
  if (original.phase !== "planned" || JSON.stringify(original.plan) !== JSON.stringify(plan)) refuse();
  const journalBytes = readRegular(file, 128 * 1024, 2);
  const tempBytes = readRegular(temp, 128 * 1024, 2);
  const temporary = fs.lstatSync(temp);
  if (!sameFile(published, temporary) || temporary.nlink !== 2
    || !journalBytes.equals(tempBytes)) refuse();
  // Unlink only the exact verified temporary name; never arbitrary links.
  fs.unlinkSync(temp);
  flushDirectory(dir);
  const remaining = fs.lstatSync(file);
  if (!remaining.isFile() || remaining.isSymbolicLink()
    || !sameFile(published, remaining) || remaining.nlink !== 1) refuse();
}
function checkedJournal(file, plan) {
  recoverInterruptedInitialJournalLink(file, plan);
  const stored = parseJournal(file);
  if (JSON.stringify(stored.plan) !== JSON.stringify(plan)) refuse();
  return stored;
}
function runLocalFixtureCiphertextMigration(input) {
  const { root, plan, locations } = readOperation(input);
  verifyInventory(root, plan, locations);
  let record;
  if (pathPresent(locations.journal)) {
    record = checkedJournal(locations.journal, plan);
    if (record.phase === "rollback-pending" || record.phase === "rolled-back") refuse();
  } else {
    // Prevent initial adoption/overwrite of any preexisting target or stage.
    if (pathPresent(locations.target) || pathPresent(locations.stage)) refuse();
    record = journalData(plan, "planned");
    storeJournal(locations.journal, record, true);
    checkpoint(input, "journal-created");
  }
  if (record.phase === "committed") {
    if (pathPresent(locations.stage) || !maybeRegular(locations.target, plan.sourceDigest)) refuse();
    return report("committed", true);
  }
  const targetExists = pathPresent(locations.target);
  const stageExists = pathPresent(locations.stage);
  if (targetExists) {
    if (!maybeRegular(locations.target, plan.sourceDigest, stageExists ? 2 : 1)) refuse();
    if (stageExists) {
      if (!maybeRegular(locations.stage, plan.sourceDigest, 2)) refuse();
      if (!sameFile(fs.lstatSync(locations.stage), fs.lstatSync(locations.target))) refuse();
    }
  } else {
    if (stageExists) {
      if (!maybeRegular(locations.stage, plan.sourceDigest)) refuse();
    } else {
      const source = readRegular(locations.source);
      if (sha(source) !== plan.sourceDigest) refuse();
      writeNew(locations.stage, source);
      checkpoint(input, "staging-synced");
    }
    // Hard-linking the synced stage to an absent target is atomic/no-clobber.
    // It is never a rename that can silently overwrite an existing target.
    fs.linkSync(locations.stage, locations.target);
    flushDirectory(path.dirname(locations.target));
    checkpoint(input, "target-published");
  }
  if (pathPresent(locations.stage)) {
    fs.unlinkSync(locations.stage);
    flushDirectory(path.dirname(locations.stage));
  }
  // The verifier re-opens disk content independently of the staged buffer.
  verifyInventory(root, plan, locations);
  if (!maybeRegular(locations.target, plan.sourceDigest)) refuse();
  checkpoint(input, "target-verified");
  storeJournal(locations.journal, journalData(plan, "committed"), false);
  checkpoint(input, "commit-recorded");
  return report("committed", true);
}
function verifyLocalFixtureCiphertextMigration(input) {
  const { root, plan, locations } = readOperation(input);
  const record = checkedJournal(locations.journal, plan);
  verifyInventory(root, plan, locations);
  if (record.phase !== "committed" || pathPresent(locations.stage)
    || !maybeRegular(locations.target, plan.sourceDigest)) refuse();
  return report(record.phase, true);
}
function rollbackLocalFixtureCiphertextMigration(input) {
  const { root, plan, locations } = readOperation(input);
  const record = checkedJournal(locations.journal, plan);
  verifyInventory(root, plan, locations);
  if (record.phase === "rolled-back") {
    if (pathPresent(locations.target) || pathPresent(locations.stage)) refuse();
    return report("rolled-back", false);
  }
  if (record.phase !== "rollback-pending") {
    // Refuse to delete a target whose bytes are unverified, including a
    // partially published stage with unexpectedly high link count.
    const stagePresent = pathPresent(locations.stage);
    if (pathPresent(locations.target)
      && !maybeRegular(locations.target, plan.sourceDigest, stagePresent ? 2 : 1)) refuse();
    if (stagePresent && !maybeRegular(locations.stage, plan.sourceDigest,
      pathPresent(locations.target) ? 2 : 1)) refuse();
    storeJournal(locations.journal, journalData(plan, "rollback-pending"), false);
    checkpoint(input, "rollback-intent-recorded");
  }
  const stagePresent = pathPresent(locations.stage);
  const targetPresent = pathPresent(locations.target);
  if (stagePresent) {
    const expectedLinks = targetPresent ? 2 : 1;
    if (!maybeRegular(locations.stage, plan.sourceDigest, expectedLinks)) refuse();
    if (targetPresent && !sameFile(fs.lstatSync(locations.stage), fs.lstatSync(locations.target))) refuse();
  }
  if (targetPresent && !maybeRegular(locations.target, plan.sourceDigest, stagePresent ? 2 : 1)) refuse();
  // The source and all inventory references are revalidated immediately before
  // unlinking, so the target never becomes the sole verified local copy.
  verifyInventory(root, plan, locations);
  if (targetPresent) {
    fs.unlinkSync(locations.target);
    flushDirectory(path.dirname(locations.target));
  }
  checkpoint(input, "target-unlinked");
  if (stagePresent) {
    if (!maybeRegular(locations.stage, plan.sourceDigest)) refuse();
    fs.unlinkSync(locations.stage);
    flushDirectory(path.dirname(locations.stage));
  }
  storeJournal(locations.journal, journalData(plan, "rolled-back"), false);
  return report("rolled-back", false);
}

module.exports = { runLocalFixtureCiphertextMigration, verifyLocalFixtureCiphertextMigration,
  rollbackLocalFixtureCiphertextMigration };
