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
// This is a closed-world, disposable filesystem fixture. A selected version
// alone cannot prove that links, derived data or retention references survived
// a migration. All modeled classes must exist and match their on-disk payloads.
const KINDS = ["versions", "backups", "trash", "links", "derived", "retention"];
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
function snapshotFields(value, expected, exact = true) {
  // Read each caller-controlled field exactly once via its own data descriptor.
  // A getter/Proxy must never validate object A and then persist/move object B.
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) refuse();
    if (exact && (Reflect.ownKeys(value).length !== expected.length
      || expected.some((name) => !Object.hasOwn(value, name)))) refuse();
    const detached = Object.create(null);
    for (const name of expected) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!descriptor || !Object.hasOwn(descriptor, "value")) refuse();
      detached[name] = descriptor.value;
    }
    return detached;
  } catch (_) { refuse(); }
}
function directory(dir) {
  try {
    const stat = fs.lstatSync(dir);
    if (!stat.isDirectory() || stat.isSymbolicLink()) refuse();
    return stat;
  } catch (_) { refuse(); }
}
function safeRoot(dir, mode) {
  if (mode !== MODE || typeof dir !== "string" || !path.isAbsolute(dir)) refuse();
  const root = path.resolve(dir);
  const temporary = path.resolve(os.tmpdir());
  if (path.dirname(root) !== temporary || !path.basename(root).startsWith("rootark-zk-local-fixture-")) refuse();
  // Pin every directory identity (including Windows junction ancestors) so a
  // checkpoint cannot redirect subsequent writes or rollback outside this
  // disposable fixture. Native openat-style protection against a hostile
  // concurrent writer is not available in portable Node; callers must still
  // own and exclusively control the fixture for the operation's lifetime.
  const pinned = [];
  function remember(segment) { pinned.push([segment, directory(segment)]); }
  let segment = path.parse(root).root;
  for (const part of root.slice(segment.length).split(path.sep).filter(Boolean)) {
    segment = path.join(segment, part);
    remember(segment);
  }
  const rootStat = pinned[pinned.length - 1][1];
  if (process.platform !== "win32"
    && (rootStat.uid !== process.getuid() || (rootStat.mode & 0o077) !== 0)) refuse();
  for (const sub of ["source", "target", "journal", "references", ...KINDS.map((k) => `references/${k}`)])
    remember(path.join(root, sub));
  const marker = readRegular(path.join(root, MARKER), 128).toString("utf8");
  if (marker !== "rootark-zk-local-fixture-v1\n") refuse();
  function guard() {
    for (const [name, identity] of pinned) {
      if (!sameFile(directory(name), identity)) refuse();
    }
  }
  guard();
  return { root, guard };
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
    // The same inode may grow after the size check. Never allocate bytes
    // beyond the opened descriptor's already-authorized fixture budget.
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset,
        Math.min(64 * 1024, bytes.length - offset), offset);
      if (count <= 0 || count > bytes.length - offset) refuse();
      offset += count;
    }
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
  try {
    const before = directory(dir);
    fd = fs.openSync(dir, fs.constants.O_RDONLY
      | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_DIRECTORY || 0));
    const opened = fs.fstatSync(fd);
    if (!opened.isDirectory() || !sameFile(before, opened)) refuse();
    fs.fsyncSync(fd);
    if (!sameFile(opened, directory(dir))) refuse();
  } catch (_) { refuse(); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function writeNew(file, bytes, guard) {
  let fd;
  let created;
  try {
    guard();
    fd = fs.openSync(file, "wx", 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
    const opened = fs.fstatSync(fd);
    const published = fs.lstatSync(file);
    if (!opened.isFile() || opened.nlink !== 1 || published.isSymbolicLink()
      || !sameFile(opened, published) || published.nlink !== 1) refuse();
    created = opened;
    guard();
  } finally { if (fd !== undefined) fs.closeSync(fd); }
  flushDirectory(path.dirname(file));
  guard();
  return created;
}
function journalData(plan, phase) {
  const body = { schema: SCHEMA, phase, plan, planDigest: sha(Buffer.from(JSON.stringify(plan))) };
  return { ...body, recordDigest: sha(Buffer.from(JSON.stringify(body))) };
}
function storeJournal(file, record, initial, guard, expectedJournal) {
  // A fresh same-directory file is synced before atomic journal publication.
  // link() gives initial publication exclusive/no-clobber semantics; updates
  // rename over the old journal, which leaves either revision after a crash.
  function checkExpectedJournal() {
    if (initial) return;
    if (!expectedJournal || !expectedJournal.isFile() || expectedJournal.nlink !== 1) refuse();
    let current;
    try { current = fs.lstatSync(file); } catch (_) { refuse(); }
    if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1
      || !sameFile(current, expectedJournal)) refuse();
  }
  guard();
  checkExpectedJournal();
  const temporary = path.join(path.dirname(file), `.${path.basename(file)}.${crypto.randomBytes(12).toString("hex")}.tmp`);
  const tempIdentity = writeNew(temporary, JSON.stringify(record), guard);
  try {
    guard();
    checkExpectedJournal();
    const staged = fs.lstatSync(temporary);
    if (!staged.isFile() || staged.isSymbolicLink() || staged.nlink !== 1
      || !sameFile(tempIdentity, staged)) refuse();
    if (initial) fs.linkSync(temporary, file);
    else fs.renameSync(temporary, file);
    guard();
    const published = fs.lstatSync(file);
    if (!published.isFile() || published.isSymbolicLink()
      || !sameFile(tempIdentity, published) || published.nlink !== (initial ? 2 : 1)) refuse();
    flushDirectory(path.dirname(file));
  } finally {
    // Orphans left by process termination are inert; never ingest them.
    guard();
    if (pathPresent(temporary)) {
      const present = fs.lstatSync(temporary);
      if (!present.isFile() || present.isSymbolicLink() || !sameFile(tempIdentity, present)
        || present.nlink < 1 || present.nlink > 2) refuse();
      fs.unlinkSync(temporary);
    }
  }
  guard();
  if (JSON.stringify(parseJournal(file)) !== JSON.stringify(record)) refuse();
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
  const raw = snapshotFields(input, [
    "sourceProvenance", "targetProvenance", "objectId", "operationId", "sourceDigest", "references",
  ], false);
  const source = snapshotFields(raw.sourceProvenance, ["role", "provider", "identity"]);
  const target = snapshotFields(raw.targetProvenance, ["role", "provider", "identity"]);
  const supplied = snapshotFields(raw.references, KINDS);
  if (source.role !== "source" || source.provider !== "fixture-source"
    || target.role !== "target" || target.provider !== "fixture-target"
    || !isId(source.identity) || !isId(target.identity)
    || source.identity === target.identity
    || !isId(raw.objectId) || !isId(raw.operationId) || !isDigest(raw.sourceDigest)) refuse();
  const references = {};
  for (const kind of KINDS) {
    const entries = supplied[kind];
    if (!Array.isArray(entries) || !entries.length || entries.length > 32
      || Reflect.ownKeys(entries).length !== entries.length + 1) refuse();
    const ids = new Set();
    references[kind] = [];
    for (let index = 0; index < entries.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(entries, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, "value")) refuse();
      const entry = snapshotFields(descriptor.value, ["id", "digest"]);
      if (!isId(entry.id) || !isDigest(entry.digest) || ids.has(entry.id)) refuse();
      ids.add(entry.id);
      references[kind].push({ id: entry.id, digest: entry.digest });
    }
  }
  return {
    operationId: raw.operationId, objectId: raw.objectId, sourceDigest: raw.sourceDigest,
    sourceProvenance: { role: source.role, provider: source.provider, identity: source.identity },
    targetProvenance: { role: target.role, provider: target.provider, identity: target.identity },
    references,
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
function checkpoint(input, name, guard) {
  guard();
  if (typeof input.onCheckpoint === "function") input.onCheckpoint(name);
  guard();
}
function report(phase, verified) {
  return Object.freeze({ schema: SCHEMA, canMigrate: false, rollbackScope: "local-fixture-only",
    state: phase, localVerified: verified,
    blockers: ["missing-owner-approved-migration", "missing-authoritative-provider-roles",
      "missing-client-decrypt-and-verify", "missing-live-version-backup-trash-sync-authority",
      "missing-live-link-derived-retention-reference-authority",
      "missing-global-backup-completeness-and-retention-proof"] });
}
function readOperation(input) {
  const { root, guard } = safeRoot(input?.fixtureDir, input?.fixtureMode);
  const plan = normalizedPlan(input);
  const locations = paths(root, plan);
  guard();
  return { root, plan, locations, guard };
}
function recoverInterruptedInitialJournalLink(file, plan, guard) {
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
  try {
    found = fs.readdirSync(dir, { withFileTypes: true })
      .filter((entry) => pattern.test(entry.name));
    // An earlier crash before link() may leave another one-link .tmp with a
    // similarly shaped filename. It is inert, not the published inode, and
    // must not be removed or prevent recovery of this genuine two-link pair.
    if (found.some((entry) => !entry.isFile() || entry.isSymbolicLink())) refuse();
    found = found.filter((entry) =>
      sameFile(published, fs.lstatSync(path.join(dir, entry.name))));
  } catch (_) { refuse(); }
  if (found.length !== 1) refuse();
  const temp = path.join(dir, found[0].name);
  const original = parseJournal(file, 2);
  if (original.phase !== "planned" || JSON.stringify(original.plan) !== JSON.stringify(plan)) refuse();
  const journalBytes = readRegular(file, 128 * 1024, 2);
  const tempBytes = readRegular(temp, 128 * 1024, 2);
  const temporary = fs.lstatSync(temp);
  if (!sameFile(published, temporary) || temporary.nlink !== 2
    || !journalBytes.equals(tempBytes)) refuse();
  // Unlink only the exact verified temporary name; never arbitrary links.
  guard();
  fs.unlinkSync(temp);
  flushDirectory(dir);
  guard();
  const remaining = fs.lstatSync(file);
  if (!remaining.isFile() || remaining.isSymbolicLink()
    || !sameFile(published, remaining) || remaining.nlink !== 1) refuse();
}
function checkedJournal(file, plan, guard) {
  guard();
  recoverInterruptedInitialJournalLink(file, plan, guard);
  const stored = parseJournal(file);
  if (JSON.stringify(stored.plan) !== JSON.stringify(plan)) refuse();
  guard();
  return stored;
}
function runLocalFixtureCiphertextMigration(input) {
  const { root, plan, locations, guard } = readOperation(input);
  verifyInventory(root, plan, locations);
  guard();
  let record;
  let journalIdentity;
  if (pathPresent(locations.journal)) {
    record = checkedJournal(locations.journal, plan, guard);
    journalIdentity = fs.lstatSync(locations.journal);
    if (record.phase === "rollback-pending" || record.phase === "rolled-back") refuse();
  } else {
    // Prevent initial adoption/overwrite of any preexisting target or stage.
    if (pathPresent(locations.target) || pathPresent(locations.stage)) refuse();
    record = journalData(plan, "planned");
    storeJournal(locations.journal, record, true, guard);
    journalIdentity = fs.lstatSync(locations.journal);
    checkpoint(input, "journal-created", guard);
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
      writeNew(locations.stage, source, guard);
      checkpoint(input, "staging-synced", guard);
    }
    // Hard-linking the synced stage to an absent target is atomic/no-clobber.
    // It is never a rename that can silently overwrite an existing target.
    guard();
    fs.linkSync(locations.stage, locations.target);
    flushDirectory(path.dirname(locations.target));
    checkpoint(input, "target-published", guard);
  }
  if (pathPresent(locations.stage)) {
    guard();
    fs.unlinkSync(locations.stage);
    flushDirectory(path.dirname(locations.stage));
    guard();
  }
  // The verifier re-opens disk content independently of the staged buffer.
  verifyInventory(root, plan, locations);
  if (!maybeRegular(locations.target, plan.sourceDigest)) refuse();
  checkpoint(input, "target-verified", guard);
  storeJournal(locations.journal, journalData(plan, "committed"), false, guard, journalIdentity);
  checkpoint(input, "commit-recorded", guard);
  return report("committed", true);
}
function verifyLocalFixtureCiphertextMigration(input) {
  const { root, plan, locations, guard } = readOperation(input);
  const record = checkedJournal(locations.journal, plan, guard);
  verifyInventory(root, plan, locations);
  guard();
  if (record.phase !== "committed" || pathPresent(locations.stage)
    || !maybeRegular(locations.target, plan.sourceDigest)) refuse();
  return report(record.phase, true);
}
function rollbackLocalFixtureCiphertextMigration(input) {
  const { root, plan, locations, guard } = readOperation(input);
  const record = checkedJournal(locations.journal, plan, guard);
  let journalIdentity = fs.lstatSync(locations.journal);
  verifyInventory(root, plan, locations);
  guard();
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
    storeJournal(locations.journal, journalData(plan, "rollback-pending"), false, guard, journalIdentity);
    journalIdentity = fs.lstatSync(locations.journal);
    checkpoint(input, "rollback-intent-recorded", guard);
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
    guard();
    fs.unlinkSync(locations.target);
    flushDirectory(path.dirname(locations.target));
    guard();
  }
  checkpoint(input, "target-unlinked", guard);
  if (stagePresent) {
    if (!maybeRegular(locations.stage, plan.sourceDigest)) refuse();
    guard();
    fs.unlinkSync(locations.stage);
    flushDirectory(path.dirname(locations.stage));
    guard();
  }
  storeJournal(locations.journal, journalData(plan, "rolled-back"), false, guard, journalIdentity);
  return report("rolled-back", false);
}

module.exports = { runLocalFixtureCiphertextMigration, verifyLocalFixtureCiphertextMigration,
  rollbackLocalFixtureCiphertextMigration };
