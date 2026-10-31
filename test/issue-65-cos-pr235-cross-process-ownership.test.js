"use strict";

// TEST_UNRUN until the exclusive Node22 gate is granted.
// This is intentionally an end-to-end RED ownership test against WebDAV
// implementations that have only a per-instance Promise lock. No lock/lease
// file, native owner, journal admission or filesystem failure is mocked.
// A separately spawned Node process owns its own bridge, SyncJournal and ACL
// worker; it calls bridge.stop() even if start() unexpectedly succeeds.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { SyncJournal, durableWrite } = require("../sync-client/rootark-sync-journal");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "pr235-cross-process-owner-test-only";
const CONTENT = "PHYSICALLY_PRESERVED_OWNER_CONTENT";
const AFTER = "DURABLY_WRITTEN_BY_FIRST_BRIDGE";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

async function setup(t) {
  const parent = createPrivateAuthorityFixture("cos-pr235-owner-");
  const root = path.join(parent, "root");
  fs.mkdirSync(root, { mode: 0o700 });
  const journalPath = path.join(parent, "local-journal.json");
  const ownerJournal = await new SyncJournal(journalPath).open();
  const bridges = [];
  t.after(async () => {
    await Promise.allSettled(bridges.map((bridge) => bridge.stop()));
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  const makeBridge = (journal, onOperation) => {
    const options = { rootDir: root, token: TOKEN, port: 0, journal };
    if (onOperation) options.onOperation = onOperation;
    const bridge = new LocalSyncWebDavBridge(options);
    bridges.push(bridge);
    return bridge;
  };
  return { root, journalPath, ownerJournal, makeBridge };
}

function request(bridge, method, route, data) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: "127.0.0.1", port: bridge.address().port, method, path: route,
      headers: { authorization: `Bearer ${TOKEN}` },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("error", reject);
      res.on("end", () => resolve({
        status: res.statusCode, body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.setTimeout(30000, () => req.destroy(Error("WebDAV owner HTTP request timed out")));
    req.on("error", reject);
    req.end(data);
  });
}

function exactDiskJournal(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function identity(filename) {
  const stat = fs.lstatSync(filename, { bigint: true });
  return { dev: String(stat.dev), ino: String(stat.ino),
    type: stat.isFile() ? "file" : "directory" };
}

const childSource = String.raw`
"use strict";
const { SyncJournal } = require(process.argv[1]);
const { LocalSyncWebDavBridge } = require(process.argv[2]);
const root = process.argv[3];
const filePath = process.argv[4];
const token = process.argv[5];
let bridge;
let timedOut = false;
const watchdog = setTimeout(async () => {
  timedOut = true;
  try { await bridge?.stop(); } finally { process.exit(78); }
}, 25000);
async function send(message) {
  await new Promise((resolve, reject) => {
    if (!process.send) return reject(Error("Child IPC unavailable"));
    process.send(message, (error) => error ? reject(error) : resolve());
  });
}
(async () => {
  let outcome;
  try {
    // Open the same fsync-backed JSON on disk, NEVER share the first process's
    // in-memory journal or any JavaScript bridge/lock instance.
    const journal = await new SyncJournal(filePath).open();
    bridge = new LocalSyncWebDavBridge({ rootDir: root, journal, token, port: 0 });
    try {
      await bridge.start();
      outcome = { kind: "STARTED_UNEXPECTEDLY", port: bridge.address()?.port };
    } catch (error) {
      outcome = { kind: "REJECTED", code: String(error?.code || ""),
        message: String(error?.message || "") };
    }
  } catch (error) {
    outcome = { kind: "SETUP_ERROR", code: String(error?.code || ""),
      message: String(error?.message || "") };
  } finally {
    try {
      await bridge?.stop();
    } catch (error) {
      outcome = { kind: "STOP_ERROR", message: String(error?.message || "") };
    }
    if (!timedOut) await send(outcome);
    clearTimeout(watchdog);
    process.disconnect?.();
  }
})().catch((error) => {
  process.stderr.write(String(error?.stack || error));
  process.exitCode = 1;
});
`;

function contenderProcess(root, journalPath) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      "-e", childSource,
      require.resolve("../sync-client/rootark-sync-journal"),
      require.resolve("../sync-client/rootark-sync-webdav"),
      root, journalPath, TOKEN,
    ], {
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      windowsHide: true,
      env: { ...process.env, NODE_OPTIONS: "" },
    });
    let report;
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.stdout.resume();
    child.on("message", (message) => {
      assert.equal(report, undefined, "child must emit exactly one final startup report");
      report = message;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0 || !report) {
        reject(Error(`Contender exited ${code} without clean report: ${stderr}`));
      } else {
        resolve(report);
      }
    });
  });
}

function assertOwnerConflict(report) {
  assert.equal(report.kind, "REJECTED",
    "independent second process must never start listening on the same root/journal");
  assert.match(`${report.code} ${report.message}`,
    /(?:root|journal|process|owner|already|exclusive|lock|lease|held|claim|busy|contend)/i,
    "second startup must fail for actual ownership conflict, not an unrelated ACL/JSON error");
}

test("two independent OS processes cannot own same root/journal; first durable pending survives failed contender", {
  timeout: 120000,
}, async (t) => {
  const f = await setup(t);
  const entered = deferred();
  const release = deferred();
  const physical = path.join(f.root, "preserved.txt");
  fs.writeFileSync(physical, CONTENT, { mode: 0o600 });
  const oldIdentity = identity(physical);
  let callbacks = 0;
  const owner = f.makeBridge(f.ownerJournal, async (op) => {
    callbacks++;
    assert.equal(op.kind, "delete");
    assert.equal(op.source, "/preserved.txt");
    await f.ownerJournal.enqueue(op); // real fsync-backed prepared journal
    entered.resolve(op);
    await release.promise;
    throw new Error("Controlled pre-physical abort: leave genuine prepared witness");
  });
  await owner.start();
  const original = request(owner, "DELETE", "/preserved.txt");
  let contender;
  try {
    const recorded = await Promise.race([
      entered.promise,
      original.then((response) => {
        throw Error(`Owner DELETE finished before journal prepared: ${response.status}`);
      }),
    ]);
    assert.equal(callbacks, 1);
    assert.deepEqual(recorded.sourceIdentity, oldIdentity);
    assert.equal(fs.readFileSync(physical, "utf8"), CONTENT);
    const beforeBytes = fs.readFileSync(f.journalPath);
    const before = JSON.parse(beforeBytes.toString("utf8"));
    assert.equal(before.pending.length, 1);
    assert.equal(before.pending[0].operationId, recorded.operationId);
    assert.equal(before.pending[0].phase, "prepared");
    assert.equal(before.seen.includes(recorded.operationId), false);
    // This contender has a truly separate OS process, SyncJournal instance,
    // Node module cache, HTTP server and native ACL-verifier lifecycle.
    contender = await contenderProcess(f.root, f.journalPath);
    // Inspect physical damage BEFORE judging the contender's response:
    // an illegally successful second owner could already have consumed the
    // pending receipt, so capture that evidence even in a RED run.
    assert.equal(fs.readFileSync(f.journalPath).equals(beforeBytes), true,
      "failed second startup must not replay/drop the first owner's pending receipt");
    assert.equal(fs.readFileSync(physical, "utf8"), CONTENT);
    assert.deepEqual(identity(physical), oldIdentity);
    assert.equal((await f.ownerJournal.recover()).length, 1);
    assertOwnerConflict(contender);
    assert.equal((await request(owner, "GET", "/preserved.txt")).status, 200,
      "first owner remains usable while contender is refused");
    release.resolve();
    const aborted = await original;
    assert.equal(aborted.status, 500, "controlled pre-physical failure is intentional");
    assert.equal(callbacks, 1);
    assert.equal(fs.readFileSync(physical, "utf8"), CONTENT);
    assert.equal(fs.readFileSync(f.journalPath).equals(beforeBytes), true);
    await owner.stop();

    const successorJournal = await new SyncJournal(f.journalPath).open();
    assert.equal((await successorJournal.recover()).length, 1,
      "durably pending entry must survive original owner's clean stop");
    const successor = f.makeBridge(successorJournal);
    await successor.start();
    assert.equal((await request(successor, "GET", "/preserved.txt")).status, 200);
    assert.equal(fs.readFileSync(physical, "utf8"), CONTENT);
    assert.deepEqual(identity(physical), oldIdentity);
    assert.deepEqual(await successorJournal.recover(), [],
      "new owner correctly resolves a prepared-but-unapplied DELETE");
    assert.equal(successorJournal.hasSeen(recorded.operationId), true);
    const freshRead = await new SyncJournal(f.journalPath).open();
    assert.equal(freshRead.hasSeen(recorded.operationId), true,
      "successor's recovery decision must itself survive another durable reopen");
  } finally {
    release.resolve();
    await original.catch(() => {});
  }
});

test("pre-opened stale contender journal must be refreshed on startup after owner handoff", {
  timeout: 120000,
}, async (t) => {
  const f = await setup(t);
  // Open BEFORE the owner commits anything. This object must not later be
  // allowed to claim possession with a stale, empty in-memory journal.
  const staleJournal = await new SyncJournal(f.journalPath).open();
  const contender = f.makeBridge(staleJournal);
  const owner = f.makeBridge(f.ownerJournal);
  await owner.start();
  const response = await request(owner, "PUT", "/durable.txt", AFTER);
  assert.equal(response.status, 201);
  const saved = path.join(f.root, "durable.txt");
  const savedIdentity = identity(saved);
  assert.equal(fs.readFileSync(saved, "utf8"), AFTER);
  const receipts = exactDiskJournal(f.journalPath);
  assert.equal(receipts.pending.length, 0);
  assert.equal(receipts.seen.length, 1, "first owner must commit a real HTTP mutation receipt");
  assert.equal(staleJournal.hasSeen(receipts.seen[0]), false,
    "second journal must genuinely predate the first owner's write");
  await owner.stop();
  await contender.start(); // required implementation must reread disk before ownership
  assert.equal(staleJournal.hasSeen(receipts.seen[0]), true,
    "new owner must not treat its stale pre-opened journal as authoritative");
  assert.deepEqual(await staleJournal.recover(), []);
  assert.equal(fs.readFileSync(saved, "utf8"), AFTER);
  assert.deepEqual(identity(saved), savedIdentity);
  const reopened = await new SyncJournal(f.journalPath).open();
  assert.deepEqual(reopened.state.seen, receipts.seen);
  assert.equal((await request(contender, "GET", "/durable.txt")).status, 200);
});

test("actual stale root-owner directory claim is never stolen, erased or treated as proof of a dead process", {
  timeout: 120000,
}, async (t) => {
  const f = await setup(t);
  const owner = f.makeBridge(f.ownerJournal);
  const claim = owner.rootOwnerLockPath;
  assert.equal(path.dirname(claim), f.root);
  assert.equal(path.basename(claim), ".rootark-webdav-owner.lock",
    "use the real current WebDAV lifetime claim, not a test-invented lock file");
  // A crash can leave this exact mkdir-based claim without a live process.
  // The safe response is still NO-GO until a separate operator reconciles it:
  // PID freshness or timeout alone cannot prove safe exclusive ownership.
  fs.mkdirSync(claim, { mode: 0o700 });
  const marker = path.join(claim, "evidence-kept.txt");
  fs.writeFileSync(marker, "PRIOR_CLAIM_EVIDENCE_NOT_OUR_AUTHORITY", { mode: 0o600 });
  const claimIdentity = identity(claim);
  const markerIdentity = identity(marker);
  await assert.rejects(owner.start(), (error) => {
    assert.equal(error.code, "EEXIST",
      "atomic mkdir must refuse existing stale claim, not infer prior owner is dead");
    return true;
  });
  assert.equal(owner.server.listening, false);
  assert.equal(owner.rootOwnerIdentity, null,
    "failed claim must not set local ownership of somebody else's directory");
  assert.deepEqual(identity(claim), claimIdentity);
  assert.deepEqual(identity(marker), markerIdentity);
  assert.equal(fs.readFileSync(marker, "utf8"), "PRIOR_CLAIM_EVIDENCE_NOT_OUR_AUTHORITY");
  await owner.stop(); // failed startup cleanup must never remove foreign claim
  assert.deepEqual(identity(claim), claimIdentity);
  assert.equal(fs.readFileSync(marker, "utf8"), "PRIOR_CLAIM_EVIDENCE_NOT_OUR_AUTHORITY");

  // Explicit manual reconciliation in this disposable fixture only.
  fs.unlinkSync(marker);
  fs.rmdirSync(claim);
  await owner.start();
  assert.equal(owner.server.listening, true);
  const response = await request(owner, "PUT", "/post-reconciliation.txt", AFTER);
  assert.equal(response.status, 201);
  assert.equal(fs.readFileSync(path.join(f.root, "post-reconciliation.txt"), "utf8"), AFTER);
  await owner.stop();
  assert.equal(fs.existsSync(claim), false,
    "the legitimately acquired lifetime claim must be released after clean stop");
});

test("invalid on-disk journal refuses bridge startup before listen; repairing exact durable state permits new owner", {
  timeout: 120000,
}, async (t) => {
  const f = await setup(t);
  const owner = f.makeBridge(f.ownerJournal);
  await owner.start();
  const put = await request(owner, "PUT", "/preserved.txt", CONTENT);
  assert.equal(put.status, 201);
  const originalFile = path.join(f.root, "preserved.txt");
  const originalIdentity = identity(originalFile);
  const validJournal = exactDiskJournal(f.journalPath);
  assert.equal(validJournal.seen.length, 1, "positive on-disk journal prerequisite");
  await owner.stop();

  // Controlled corrupted disk input, NOT a fake ownership decision or a
  // monkeypatch of fsync/rename. Restoring uses real durableWrite with flush.
  await fsp.writeFile(f.journalPath, "{invalid-committed-journal", "utf8");
  const malformed = f.makeBridge(new SyncJournal(f.journalPath));
  await assert.rejects(malformed.start(),
    /(?:sync journal|JSON|unexpected|invalid|parse|syntax)/i,
    "malformed journal must be rejected by WebDAV startup, not silently ignored");
  assert.equal(malformed.server.listening, false);
  assert.equal(fs.readFileSync(originalFile, "utf8"), CONTENT);
  assert.deepEqual(identity(originalFile), originalIdentity);
  await malformed.stop();

  await durableWrite(f.journalPath, validJournal); // genuine fsync-backed repair
  const repaired = await new SyncJournal(f.journalPath).open();
  const next = f.makeBridge(repaired);
  await next.start();
  assert.equal((await request(next, "GET", "/preserved.txt")).status, 200);
  assert.equal(fs.readFileSync(originalFile, "utf8"), CONTENT);
  assert.deepEqual(identity(originalFile), originalIdentity);
  assert.deepEqual((await new SyncJournal(f.journalPath).open()).state.seen,
    validJournal.seen, "failed startup may not erase legitimate durable receipts");
});
