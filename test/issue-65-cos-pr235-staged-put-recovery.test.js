"use strict";

// TEST_UNRUN until the exclusive Node22 gate opens.
// A real authenticated HTTP PUT persists a prepared record, moves an existing
// file into private trash and fsyncs a staged SyncJournal update. Suspend the
// live request BEFORE it can publish its new payload, then independently open
// the journal and replay exactly that physical state. A live suspended request
// is intentional: killing a Windows Node child could orphan the native ACL
// verifier, so this tests the equivalent durable interruption without claiming
// to have performed a hard process crash.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "cos-pr235-staged-put-recovery-fixture";
const ORIGINAL = "HTTP_PUT_PREVIOUS_ORIGINAL_BYTES";
const UPLOAD = "NEW_HTTP_PUT_PAYLOAD_NOT_YET_INSTALLED";
const FOREIGN_BACKUP = "FOREIGN_REPLACEMENT_BACKUP_DO_NOT_TRUST";
const FOREIGN_TARGET = "FOREIGN_OCCUPIED_DESTINATION_DO_NOT_CLOBBER";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function httpPut(bridge, data) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: "127.0.0.1", port: bridge.address().port,
      method: "PUT", path: "/original.txt",
      headers: { authorization: `Bearer ${TOKEN}` },
    }, (res) => {
      const buffers = [];
      res.on("data", (part) => buffers.push(part));
      res.on("error", reject);
      res.on("end", () => resolve({
        status: res.statusCode, body: Buffer.concat(buffers).toString("utf8"),
      }));
    });
    req.setTimeout(30000, () => req.destroy(new Error("HTTP PUT timed out")));
    req.on("error", reject);
    req.end(data);
  });
}

function sameIdentity(actual, previous) {
  return actual.dev === previous.dev && actual.ino === previous.ino
    && actual.isFile() && previous.isFile();
}

async function setup(t) {
  const parent = createPrivateAuthorityFixture("cos-pr235-staged-");
  const root = path.join(parent, "bridge");
  const target = path.join(root, "original.txt");
  const journalPath = path.join(parent, "mutation-journal.json");
  fs.mkdirSync(root, { mode: 0o700 });
  fs.writeFileSync(target, ORIGINAL, { mode: 0o600 });
  const originalStat = fs.lstatSync(target, { bigint: true });
  const journal = await new SyncJournal(journalPath).open();
  const entered = deferred();
  const resume = deferred();
  const bridge = new LocalSyncWebDavBridge({
    rootDir: root, token: TOKEN, port: 0, journal,
  });
  const actualUpdate = bridge.updateJournal.bind(bridge);
  let stagedAcks = 0;
  bridge.updateJournal = async (id, patch) => {
    await actualUpdate(id, patch); // real fsync-backed, rename-committed journal
    if (patch.phase === "staged") {
      stagedAcks++;
      entered.resolve(id);
      await resume.promise; // original request cannot publish new target
    }
  };
  t.after(async () => {
    resume.resolve();
    await bridge.stop();
    fs.rmSync(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  await bridge.start();
  return { parent, root, target, journal, journalPath, bridge,
    originalStat, entered, resume, getStagedAcks: () => stagedAcks };
}

async function stagedHttpOperation(t) {
  const f = await setup(t);
  const request = httpPut(f.bridge, UPLOAD);
  try {
    const operationId = await Promise.race([
      f.entered.promise,
      request.then(
        (answer) => { throw new Error(`HTTP PUT completed before durable staged: ${answer.status}`); },
        (error) => { throw error; },
      ),
    ]);
    assert.equal(f.getStagedAcks(), 1,
      "exactly one actual HTTP PUT crossed the durable staged phase");
    assert.equal(fs.existsSync(f.target), false,
      "the original pathname must be absent before any new bytes are published");

    // Prove the exact staged entry exists ON DISK independently of the
    // running journal object. No hand-constructed operation/identity is fed
    // into recovery, and the SHA is derived from the real request body.
    const raw = JSON.parse(fs.readFileSync(f.journalPath, "utf8"));
    const records = raw.pending.filter((item) => item.operationId === operationId);
    assert.equal(records.length, 1);
    const recorded = records[0];
    assert.equal(recorded.kind, "put");
    assert.equal(recorded.journalType, "webdav-mutation");
    assert.equal(recorded.phase, "staged");
    assert.equal(recorded.existed, true);
    assert.equal(recorded.putBytes, Buffer.byteLength(UPLOAD));
    assert.equal(recorded.putSha256, crypto.createHash("sha256")
      .update(UPLOAD).digest("hex"));
    assert.equal(recorded.previousIdentity.dev, String(f.originalStat.dev));
    assert.equal(recorded.previousIdentity.ino, String(f.originalStat.ino));
    assert.equal(recorded.previousIdentity.type, "file");
    assert.equal(recorded.destination, "/original.txt");
    assert.equal(typeof recorded.trash, "string");
    const backup = path.resolve(f.root, recorded.trash);
    assert.equal(path.dirname(backup), path.join(f.root, ".rootark-trash"));
    const backupStat = fs.lstatSync(backup, { bigint: true });
    assert.equal(sameIdentity(backupStat, f.originalStat), true,
      "the true old inode must be physically linked in trash");
    assert.equal(fs.readFileSync(backup, "utf8"), ORIGINAL);
    assert.equal(fs.existsSync(f.target), false);

    const reopened = await new SyncJournal(f.journalPath).open();
    assert.deepEqual((await reopened.recover()).map((item) => item.operationId),
      [operationId], "independent journal reopen must see actual durable operation");
    assert.equal((await reopened.recover())[0].phase, "staged");
    // Invoke only the independent recovery boundary; starting another Windows
    // HTTP server/ACL worker would be unsafe with the original request held.
    const recovery = new LocalSyncWebDavBridge({
      rootDir: f.root, token: TOKEN, journal: reopened,
    });
    return { ...f, request, recorded, backup, operationId, reopened, recovery };
  } catch (error) {
    f.resume.resolve();
    await request.catch(() => {});
    throw error;
  }
}

async function settleOriginalRequest(f) {
  // After independent recovery, an outstanding request must not claim a
  // success response or overwrite the already restored/occupied path.
  f.resume.resolve();
  const response = await f.request;
  assert.ok(response.status < 200 || response.status >= 300,
    `interrupted PUT must not claim success after independent recovery: ${response.status}`);
}

test("real staged HTTP overwrite restores exact previous inode via independently reopened SyncJournal", {
  timeout: 120000,
}, async (t) => {
  const f = await stagedHttpOperation(t);
  try {
    await f.recovery.recoverPending();
    assert.equal(fs.readFileSync(f.target, "utf8"), ORIGINAL);
    assert.equal(sameIdentity(fs.lstatSync(f.target, { bigint: true }),
      f.originalStat), true, "recovery must restore the real original inode");
    assert.equal(fs.existsSync(f.backup), false,
      "exclusive hard-link restoration must consume only the verified backup");
    assert.deepEqual(await f.reopened.recover(), []);
    assert.equal(f.reopened.hasSeen(f.operationId), true);
    const reopenedAgain = await new SyncJournal(f.journalPath).open();
    assert.equal(reopenedAgain.hasSeen(f.operationId), true,
      "markSeen must itself survive a second independent disk reopen");
    assert.deepEqual(await reopenedAgain.recover(), []);
    await settleOriginalRequest(f);
    assert.equal(fs.readFileSync(f.target, "utf8"), ORIGINAL);
    assert.equal(sameIdentity(fs.lstatSync(f.target, { bigint: true }),
      f.originalStat), true);
  } finally {
    f.resume.resolve();
    await f.request.catch(() => {});
  }
});

test("real staged HTTP overwrite refuses substituted backup, preserving foreign and original evidence", {
  timeout: 120000,
}, async (t) => {
  const f = await stagedHttpOperation(t);
  const preserved = path.join(f.root, "preserved-original-outside-trash.txt");
  try {
    fs.renameSync(f.backup, preserved);
    fs.writeFileSync(f.backup, FOREIGN_BACKUP, { flag: "wx", mode: 0o600 });
    assert.notEqual(fs.lstatSync(f.backup, { bigint: true }).ino, f.originalStat.ino);
    await assert.rejects(f.recovery.recoverPending(),
      { code: "WEBDAV_RECOVERY_INDETERMINATE" });
    assert.equal(fs.readFileSync(f.backup, "utf8"), FOREIGN_BACKUP);
    assert.equal(fs.readFileSync(preserved, "utf8"), ORIGINAL);
    assert.equal(fs.existsSync(f.target), false);
    assert.equal(f.reopened.hasSeen(f.operationId), false);
    assert.equal((await f.reopened.recover())[0].phase, "staged");
    // Occupy the destination before allowing the original suspended HTTP
    // request to terminate; otherwise it could continue publishing after
    // this assertion and misrepresent a crashed-process snapshot.
    fs.writeFileSync(f.target, FOREIGN_TARGET, { flag: "wx", mode: 0o600 });
    await settleOriginalRequest(f);
    assert.equal(fs.readFileSync(f.target, "utf8"), FOREIGN_TARGET);
    assert.equal(fs.readFileSync(f.backup, "utf8"), FOREIGN_BACKUP);
    assert.equal(fs.readFileSync(preserved, "utf8"), ORIGINAL);
  } finally {
    f.resume.resolve();
    await f.request.catch(() => {});
  }
});

test("real staged HTTP overwrite refuses occupied destination without overwriting foreign bytes", {
  timeout: 120000,
}, async (t) => {
  const f = await stagedHttpOperation(t);
  try {
    fs.writeFileSync(f.target, FOREIGN_TARGET, { flag: "wx", mode: 0o600 });
    const foreignStat = fs.lstatSync(f.target, { bigint: true });
    await assert.rejects(f.recovery.recoverPending(),
      { code: "WEBDAV_RECOVERY_INDETERMINATE" });
    assert.equal(fs.readFileSync(f.target, "utf8"), FOREIGN_TARGET);
    assert.equal(fs.lstatSync(f.target, { bigint: true }).ino, foreignStat.ino);
    assert.equal(fs.readFileSync(f.backup, "utf8"), ORIGINAL);
    assert.equal(sameIdentity(fs.lstatSync(f.backup, { bigint: true }),
      f.originalStat), true);
    assert.equal(f.reopened.hasSeen(f.operationId), false);
    assert.equal((await f.reopened.recover())[0].phase, "staged");
    await settleOriginalRequest(f);
    assert.equal(fs.readFileSync(f.target, "utf8"), FOREIGN_TARGET);
    assert.equal(fs.readFileSync(f.backup, "utf8"), ORIGINAL);
  } finally {
    f.resume.resolve();
    await f.request.catch(() => {});
  }
});
