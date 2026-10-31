"use strict";

// DISK-backed legacy WebDAV recovery boundary matrix. Every positive phase
// transition is backed by actual local filesystem mutations and durable
// SyncJournal writes. These are physical-recovery tests, NOT claims of HTTP
// authorization, Ed25519 signing, or a real power-loss simulation.
// Node22 exclusive test gate is CLOSED: do not execute without prime approval.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");

const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const BODY = Buffer.from("HTTP_INDEPENDENT_PHYSICAL_RECOVERY_BYTES_64");
const ORIGINAL = Buffer.from("PREVIOUS_DESTINATION_BYTES_29");
const TEST_TIMEOUT = 45_000;

const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");
const witnessed = (stat) => {
  assert.equal(stat.isSymbolicLink(), false);
  assert.ok(stat.dev >= 0n && stat.ino > 0n, "usable physical inode required");
  assert.ok(stat.isFile() || stat.isDirectory());
  if (stat.isFile()) assert.equal(stat.nlink, 1n, "no preexisting aliases");
  return { dev: String(stat.dev), ino: String(stat.ino),
    type: stat.isFile() ? "file" : "directory" };
};
const statIdentity = async (filename) => witnessed(await fsp.lstat(filename, { bigint: true }));

function outboxRecord(operation) {
  return { operationId: `recovered-${operation.operationId}`, operation: operation.kind,
    // A byte digest is useful correlation, but is NOT signed authorization.
    ...(operation.kind === "put" ? { putSha256: operation.putSha256 } : {}) };
}

async function matrixFixture(t, { kind, phase, overwrite = false }) {
  const parent = createPrivateAuthorityFixture("cos-pr235-matrix-");
  t.after(async () => { await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 }); });
  const root = path.join(parent, "private");
  const trash = path.join(root, ".rootark-trash");
  await fsp.mkdir(root, { recursive: true, mode: 0o700 });
  await fsp.mkdir(trash, { mode: 0o700 });
  const mutationPath = path.join(parent, "mutation.json");
  const outboxPath = path.join(parent, "outbox.json");
  const mutation = await new SyncJournal(mutationPath).open();
  const outbox = await new SyncJournal(outboxPath).open();
  const source = path.join(root, kind === "move" ? "from.txt"
    : kind === "delete" ? "erase.txt" : "item.txt");
  const destination = path.join(root, kind === "move" ? "to.txt" : "item.txt");
  const backup = path.join(trash, "admitted-backup.txt");
  const temporary = path.join(root, ".rootark-put-matrix-temp");
  const paths = [source, destination, backup,
    temporary,
    path.join(root, "kept-original.txt"), path.join(root, "alias.txt"),
    path.join(root, "foreign.txt")];
  let previousIdentity = null;
  let sourceIdentity = null;
  let installedIdentity = null;
  const operationId = `phase-${kind}-${phase}-${crypto.randomUUID()}`;

  if (kind === "put") {
    if (overwrite) {
      await fsp.writeFile(destination, ORIGINAL, { flag: "wx", mode: 0o600 });
      previousIdentity = await statIdentity(destination);
    }
  } else {
    await fsp.writeFile(source, BODY, { flag: "wx", mode: 0o600 });
    sourceIdentity = await statIdentity(source);
    if (kind === "move" && overwrite) {
      await fsp.writeFile(destination, ORIGINAL, { flag: "wx", mode: 0o600 });
      previousIdentity = await statIdentity(destination);
    }
  }
  const event = kind === "put"
    ? { operationId, journalType: "webdav-mutation", kind, phase: "prepared",
      path: "/item.txt", source: "/item.txt", destination: "/item.txt",
      existed: overwrite, putBytes: BODY.length, putSha256: digest(BODY),
      previousIdentity, trash: overwrite ? ".rootark-trash/admitted-backup.txt" : null }
    : kind === "move"
      ? { operationId, journalType: "webdav-mutation", kind, phase: "prepared",
        source: "/from.txt", destination: "/to.txt",
        sourceIdentity, previousDestinationIdentity: previousIdentity,
        trash: overwrite ? ".rootark-trash/admitted-backup.txt" : null }
      : { operationId, journalType: "webdav-mutation", kind, phase: "prepared",
        source: "/erase.txt", sourceIdentity,
        trash: ".rootark-trash/admitted-backup.txt" };

  await mutation.enqueue(event);
  assert.deepEqual((await new SyncJournal(mutationPath).open()).pending(), [event],
    "admitted PREPARED mutation must persist on disk before physical modification");
  if (kind === "put" && phase !== "prepared") {
    // The real PUT stages and syncs new bytes before backup/publication.
    // A staged crash leaves an orphan temporary file; do not claim that it
    // was installed or silently delete it during journal recovery.
    const handle = await fsp.open(temporary, "wx", 0o600);
    try { await handle.writeFile(BODY); await handle.sync(); }
    finally { await handle.close(); }
    assert.deepEqual(await fsp.readFile(temporary), BODY);
  }

  // PUT/MOVE overwrite stage: link original destination to trusted backup,
  // then remove old name. No synthetic backup inode is invented.
  if (overwrite && phase !== "prepared") {
    await fsp.link(destination, backup);
    const linkedBackup = await fsp.lstat(backup, { bigint: true });
    assert.equal(linkedBackup.nlink, 2n, "the temporary backup is a second link");
    assert.deepEqual({ dev: String(linkedBackup.dev), ino: String(linkedBackup.ino),
      type: "file" }, previousIdentity);
    await fsp.unlink(destination);
    assert.deepEqual(await statIdentity(backup), previousIdentity,
      "staged original must return to one trusted link");
    await mutation.update(operationId, { phase: "staged" });
  }
  if (["source-moved", "protocol-queued"].includes(phase)) {
    if (kind === "put") {
      const temporaryIdentity = await statIdentity(temporary);
      await fsp.link(temporary, destination);
      const published = await fsp.lstat(destination, { bigint: true });
      assert.equal(published.nlink, 2n, "atomic publication temporarily has two links");
      assert.deepEqual({ dev: String(published.dev), ino: String(published.ino),
        type: "file" }, temporaryIdentity);
      await fsp.unlink(temporary);
      installedIdentity = await statIdentity(destination);
      assert.deepEqual(installedIdentity, temporaryIdentity,
        "PUT installation must publish the actual temporary inode");
      await mutation.update(operationId, { phase: "source-moved", installedIdentity });
    } else if (kind === "move") {
      await fsp.link(source, destination);
      const published = await fsp.lstat(destination, { bigint: true });
      assert.equal(published.nlink, 2n);
      assert.deepEqual({ dev: String(published.dev), ino: String(published.ino),
        type: "file" }, sourceIdentity, "MOVE publishes exactly the source inode");
      await fsp.unlink(source);
      assert.deepEqual(await statIdentity(destination), sourceIdentity,
        "after unlink only the admitted destination link remains");
      await mutation.update(operationId, { phase: "source-moved" });
    } else {
      await fsp.link(source, backup);
      const published = await fsp.lstat(backup, { bigint: true });
      assert.equal(published.nlink, 2n);
      assert.deepEqual({ dev: String(published.dev), ino: String(published.ino),
        type: "file" }, sourceIdentity, "DELETE trashes exactly the source inode");
      await fsp.unlink(source);
      assert.deepEqual(await statIdentity(backup), sourceIdentity,
        "the original DELETE inode has a single surviving trash link");
      await mutation.update(operationId, { phase: "source-moved" });
    }
    const published = (await new SyncJournal(mutationPath).open()).pending()[0];
    assert.equal(published.phase, "source-moved");
    if (kind === "put") assert.deepEqual(published.installedIdentity, installedIdentity);
    else assert.deepEqual(published.sourceIdentity, sourceIdentity);
  }
  if (phase === "protocol-queued") {
    // This is a *durably queued* legacy operation, not an invented ACK.
    // Replay should deduplicate against the actual persisted outbox record.
    await outbox.enqueue(outboxRecord(event));
    assert.deepEqual((await new SyncJournal(outboxPath).open()).pending(),
      [outboxRecord(event)]);
    await mutation.update(operationId, { phase: "protocol-queued" });
  }

  const disk = (await new SyncJournal(mutationPath).open()).pending();
  assert.equal(disk.length, 1);
  assert.equal(disk[0].phase, phase);
  return { parent, root, trash, source, destination, backup, paths,
    kind, phase, overwrite, mutationPath, outboxPath, event: disk[0] };
}

async function independentBridge(f, translator = (operation) => outboxRecord(operation)) {
  const mutation = await new SyncJournal(f.mutationPath).open();
  const outbox = await new SyncJournal(f.outboxPath).open();
  const bridge = new LocalSyncWebDavBridge({ rootDir: f.root,
    token: "matrix-only-legacy-private-replay", journal: mutation,
    protocolJournal: outbox, toProtocolOperation: translator });
  return { bridge, mutation, outbox };
}

async function physicalSnapshot(f) {
  const result = {};
  for (const filename of [...new Set(f.paths)]) {
    let stat;
    try { stat = await fsp.lstat(filename, { bigint: true }); }
    catch (error) { if (error.code === "ENOENT") { result[filename] = null; continue; } throw error; }
    result[filename] = { dev: String(stat.dev), ino: String(stat.ino),
      nlink: String(stat.nlink), mode: String(stat.mode), size: String(stat.size),
      type: stat.isSymbolicLink() ? "symlink"
        : stat.isFile() ? "file" : stat.isDirectory() ? "directory" : "other",
      ...(stat.isSymbolicLink() ? { link: await fsp.readlink(filename) }
        : stat.isFile() ? { sha256: digest(await fsp.readFile(filename)) } : {}) };
  }
  return result;
}

async function expectSuccessfulRecovery(f, enqueues) {
  const beforeOutbox = (await new SyncJournal(f.outboxPath).open()).pending();
  assert.equal(beforeOutbox.length, f.phase === "protocol-queued" ? 1 : 0);
  let translations = 0;
  const { bridge } = await independentBridge(f, (operation) => {
    translations += 1;
    return outboxRecord(operation);
  });
  await bridge.recoverPending();
  assert.equal(translations, enqueues, "only a physically applied mutation may enter outbox");
  const reopenedMutation = await new SyncJournal(f.mutationPath).open();
  const reopenedOutbox = await new SyncJournal(f.outboxPath).open();
  assert.deepEqual(reopenedMutation.pending(), [], "mutation must be durably acknowledged");
  assert.equal(reopenedMutation.hasSeen(f.event.operationId), true);
  assert.deepEqual(reopenedOutbox.pending(), enqueues ? [outboxRecord(f.event)] : [],
    "disk outbox must contain precisely the authorized-by-physical-state outcome");
  const again = await independentBridge(f, () => {
    throw new Error("duplicate replay translation must never be invoked");
  });
  await again.bridge.recoverPending();
  assert.deepEqual((await new SyncJournal(f.outboxPath).open()).pending(),
    enqueues ? [outboxRecord(f.event)] : [], "second boot must be idempotent");
}

async function expectIndeterminatePreserved(f, { unsafePath = false } = {}) {
  const beforeFiles = await physicalSnapshot(f);
  const beforeMutation = (await new SyncJournal(f.mutationPath).open()).pending();
  const beforeOutbox = (await new SyncJournal(f.outboxPath).open()).pending();
  assert.equal(beforeMutation.length, 1, "adversary must start with pending disk evidence");
  let translations = 0;
  const { bridge } = await independentBridge(f, () => {
    translations += 1;
    return outboxRecord(f.event);
  });
  await assert.rejects(() => bridge.recoverPending(), (error) => {
    // A symlink can be rejected by canonical path validation *before* the
    // recovery-specific error wrapping. Unrelated fixture/runtime errors are
    // never counted as a valid security rejection.
    if (error?.code === "WEBDAV_RECOVERY_INDETERMINATE") return true;
    return unsafePath && /symlink|unsafe path|untrusted bridge path|outside root/i.test(
      String(error?.message || ""));
  }, "insufficient disk witness must fail closed with no protocol translation");
  assert.equal(translations, 0, "no speculative encrypted/protocol operation");
  const afterMutation = await new SyncJournal(f.mutationPath).open();
  const afterOutbox = await new SyncJournal(f.outboxPath).open();
  assert.deepEqual(afterMutation.pending(), beforeMutation, "unknown state stays pending");
  assert.equal(afterMutation.hasSeen(f.event.operationId), false,
    "rejection must not be disguised as an acknowledgement");
  assert.deepEqual(afterOutbox.pending(), beforeOutbox,
    "rejection must preserve the durable outbox");
  assert.deepEqual(await physicalSnapshot(f), beforeFiles,
    "untrusted replay must preserve every physical inode, link and payload");
}

// Exhaustive reachable base phases: DELETE has no legitimate staged phase in
// the live handler; that forged phase is tested negatively below.
for (const spec of [
  { kind: "put", phase: "prepared", overwrite: false, enqueues: 0 },
  { kind: "put", phase: "prepared", overwrite: true, enqueues: 0 },
  { kind: "move", phase: "prepared", overwrite: false, enqueues: 0 },
  { kind: "move", phase: "prepared", overwrite: true, enqueues: 0 },
  { kind: "delete", phase: "prepared", enqueues: 0 },
  { kind: "put", phase: "staged", overwrite: true, enqueues: 0 },
  { kind: "move", phase: "staged", overwrite: true, enqueues: 0 },
  { kind: "put", phase: "source-moved", enqueues: 1 },
  { kind: "move", phase: "source-moved", enqueues: 1 },
  { kind: "delete", phase: "source-moved", enqueues: 1 },
  { kind: "put", phase: "protocol-queued", enqueues: 1 },
  { kind: "move", phase: "protocol-queued", enqueues: 1 },
  { kind: "delete", phase: "protocol-queued", enqueues: 1 },
]) {
  test(`physical disk matrix accepts ${spec.kind} ${spec.phase} overwrite=${Boolean(spec.overwrite)} without false replay`,
    { timeout: TEST_TIMEOUT }, async (t) => {
      const f = await matrixFixture(t, spec);
      await expectSuccessfulRecovery(f, spec.enqueues);
      if (spec.phase === "staged" || spec.phase === "prepared") {
        if (spec.kind !== "delete") {
          if (spec.kind === "put" && !spec.overwrite) {
            assert.equal(fs.existsSync(f.destination), false,
              "prepared new PUT must not invent a target");
          } else {
            const name = spec.kind === "move" && spec.phase === "prepared"
              ? f.source : f.destination;
            assert.equal(await fsp.readFile(name, "utf8"),
              spec.kind === "move" ? BODY.toString() : ORIGINAL.toString(),
              "prepared/staged abort restores physical state, not a completed mutation");
          }
          if (spec.kind === "move") {
            assert.deepEqual(await fsp.readFile(f.source), BODY,
              "MOVE aborted before publication must retain its original source");
            if (spec.overwrite) assert.deepEqual(await fsp.readFile(f.destination), ORIGINAL,
              "MOVE rollback restores the previous destination, not the source payload");
          }
          if (spec.kind === "put" && spec.phase === "staged") {
            assert.deepEqual(await fsp.readFile(path.join(f.root, ".rootark-put-matrix-temp")), BODY,
              "aborted staged PUT leaves separate uninstalled temporary evidence");
            assert.equal(fs.existsSync(f.backup), false,
              "successful trusted backup restoration consumes only its original link");
          }
        } else {
          assert.deepEqual(await fsp.readFile(f.source), BODY);
        }
      } else if (spec.kind === "delete") {
        assert.deepEqual(await fsp.readFile(f.backup), BODY);
        assert.equal(fs.existsSync(f.source), false);
      } else {
        assert.deepEqual(await fsp.readFile(f.destination), BODY);
        if (spec.kind === "move") assert.equal(fs.existsSync(f.source), false);
      }
    });
}

async function replaceInodeWithSameBytes(f, filename) {
  // Keep the witnessed original inode alive under another name, preventing
  // reuse of its inode number, while presenting identical bytes at the path.
  const held = path.join(f.root, "kept-original.txt");
  const bytes = await fsp.readFile(filename);
  const identity = await statIdentity(filename);
  await fsp.rename(filename, held);
  await fsp.writeFile(filename, bytes, { flag: "wx", mode: 0o600 });
  assert.notDeepEqual(await statIdentity(filename), identity);
  assert.deepEqual(await fsp.readFile(filename), bytes);
}

test("staged MOVE recovery must not restore a prior destination after source inode substitution", {
  timeout: TEST_TIMEOUT,
}, async (t) => {
  const f = await matrixFixture(t, { kind: "move", phase: "staged", overwrite: true });
  assert.equal(fs.existsSync(f.destination), false);
  assert.deepEqual(await fsp.readFile(f.backup), ORIGINAL);
  const exactAdmittedSource = f.event.sourceIdentity;
  await replaceInodeWithSameBytes(f, f.source);
  assert.notDeepEqual(await statIdentity(f.source), exactAdmittedSource,
    "adversary installed a foreign inode with byte-for-byte identical content");
  await expectIndeterminatePreserved(f);
  assert.equal(fs.existsSync(f.destination), false,
    "recovery cannot restore the displaced target and clear pending when original source is lost");
  assert.deepEqual(await fsp.readFile(f.backup), ORIGINAL,
    "preserve trusted backup rather than consuming it to disguise source substitution");
});

for (const scenario of [
  ["put", "source-moved", false, "missing installed inode",
    (f, journal) => journal.update(f.event.operationId, { installedIdentity: null })],
  ["put", "source-moved", false, "forged SHA with valid installed inode",
    (f, journal) => journal.update(f.event.operationId,
      { putSha256: digest(Buffer.from("FOREIGN_UNAUTHORIZED_DIGEST")) })],
  ["put", "source-moved", false, "identical bytes substituted at different inode",
    (f) => replaceInodeWithSameBytes(f, f.destination)],
  ["put", "protocol-queued", false, "in-place tampering after durable outbox",
    async (f) => {
      const corrupted = Buffer.from(BODY);
      corrupted[0] ^= 0x55;
      await fsp.writeFile(f.destination, corrupted);
      assert.deepEqual(await statIdentity(f.destination), f.event.installedIdentity);
      assert.equal(corrupted.length, BODY.length);
      assert.notEqual(digest(corrupted), f.event.putSha256);
    }],
  ["put", "source-moved", false, "second hardlink of installed inode nlink2",
    async (f) => {
      await fsp.link(f.destination, path.join(f.root, "alias.txt"));
      assert.equal((await fsp.lstat(f.destination, { bigint: true })).nlink, 2n);
    }],
  ["move", "source-moved", false, "destination substituted by same-content foreign inode",
    (f) => replaceInodeWithSameBytes(f, f.destination)],
  ["move", "protocol-queued", false, "destination replaced after durable enqueue",
    (f) => replaceInodeWithSameBytes(f, f.destination)],
  // MOVE/DELETE nlink2 may be currently RED because matchesDurableIdentity
  // checks dev/ino/type but not nlink. Preserve that security signal.
  ["move", "source-moved", false, "destination hardlink alias nlink2",
    async (f) => {
      await fsp.link(f.destination, path.join(f.root, "alias.txt"));
      assert.equal((await fsp.lstat(f.destination, { bigint: true })).nlink, 2n);
    }],
  ["delete", "source-moved", false, "trash substituted by same-content foreign inode",
    (f) => replaceInodeWithSameBytes(f, f.backup)],
  ["delete", "protocol-queued", false, "trash hardlink alias nlink2",
    async (f) => {
      await fsp.link(f.backup, path.join(f.root, "alias.txt"));
      assert.equal((await fsp.lstat(f.backup, { bigint: true })).nlink, 2n);
    }],
  ["move", "staged", true, "foreign backup restore",
    (f) => replaceInodeWithSameBytes(f, f.backup)],
  ["put", "staged", true, "foreign backup restore",
    (f) => replaceInodeWithSameBytes(f, f.backup)],
  ["move", "source-moved", true, "foreign preexisting-destination backup",
    (f) => replaceInodeWithSameBytes(f, f.backup)],
  ["put", "source-moved", true, "foreign preexisting-destination backup",
    (f) => replaceInodeWithSameBytes(f, f.backup)],
  ["move", "prepared", false, "missing prepared source witness",
    (f, journal) => journal.update(f.event.operationId, { sourceIdentity: null })],
  ["delete", "prepared", false, "missing prepared source witness",
    (f, journal) => journal.update(f.event.operationId, { sourceIdentity: null })],
  ["put", "prepared", true, "missing original destination witness",
    (f, journal) => journal.update(f.event.operationId, { previousIdentity: null })],
  ["move", "prepared", false, "source disappears without completed MOVE",
    (f) => fsp.rename(f.source, path.join(f.root, "kept-original.txt"))],
  ["delete", "prepared", false, "fabricated staged DELETE and foreign backup",
    async (f, journal) => {
      await fsp.writeFile(f.backup, "FOREIGN_BACKUP", { flag: "wx", mode: 0o600 });
      await journal.update(f.event.operationId, { phase: "staged" });
    }],
]) {
  const [kind, phase, overwrite, label, corrupt] = scenario;
  test(`disk matrix denies ${kind}/${phase}: ${label}`,
    { timeout: TEST_TIMEOUT }, async (t) => {
      const f = await matrixFixture(t, { kind, phase, overwrite });
      const journal = await new SyncJournal(f.mutationPath).open();
      await corrupt(f, journal);
      await expectIndeterminatePreserved(f);
    });
}

for (const kind of ["put", "move", "delete"]) {
  test(`disk matrix rejects unknown journal phase for physically admitted ${kind}`,
    { timeout: TEST_TIMEOUT }, async (t) => {
      const f = await matrixFixture(t, { kind, phase: "source-moved" });
      const journal = await new SyncJournal(f.mutationPath).open();
      await journal.update(f.event.operationId, { phase: "unrecognized-finished" });
      await expectIndeterminatePreserved(f);
    });
}

for (const kind of ["put", "delete"]) {
  test(`disk matrix rejects substituted symlink during ${kind} source-moved replay`,
    { timeout: TEST_TIMEOUT }, async (t) => {
      const f = await matrixFixture(t, { kind, phase: "source-moved" });
      const original = kind === "put" ? f.destination : f.backup;
      const held = path.join(f.root, "kept-original.txt");
      await fsp.rename(original, held);
      try {
        await fsp.symlink(path.relative(path.dirname(original), held), original, "file");
      } catch (error) {
        if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) {
          t.skip("The operating system denies test-process symlink creation");
          return;
        }
        throw error;
      }
      assert.equal((await fsp.lstat(original)).isSymbolicLink(), true);
      assert.deepEqual(await fsp.readFile(held), BODY);
      await expectIndeterminatePreserved(f, { unsafePath: true });
    });
}
