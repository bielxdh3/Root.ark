"use strict";

// Adversarial disk-journal replay tests plus a genuine authenticated HTTP PUT
// interrupted by process termination. Synthetic records are not provenance.
// Node22 tests MUST NOT run until the exclusive gate opens. Disposable only.
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const test = require("node:test");

const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

function putEvidence(bytes) {
  return {
    putBytes: bytes.length,
    putSha256: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
}

async function disposableDiskReplay(t, operation) {
  const parent = createPrivateAuthorityFixture("cos-pr235-replay-");
  const root = path.join(parent, "bridge");
  fs.mkdirSync(root, { mode: 0o700 });
  t.after(() => fs.rmSync(parent, { recursive: true, force: true, maxRetries: 5 }));

  // These journals really are fsync/rename-backed JSON files. The injected
  // entry has never passed through an HTTP request or bridge.onOperation().
  const journalPath = path.join(parent, "mutation-journal.json");
  const forgedWriter = await new SyncJournal(journalPath).open();
  await forgedWriter.enqueue(operation);
  const disk = JSON.parse(await fsp.readFile(journalPath, "utf8"));
  assert.deepEqual(disk.pending, [operation], "forged entry reached real disk");

  // A distinct instance must parse the persisted record, not reuse the first
  // object's state or a mock recover() callback.
  const reopened = await new SyncJournal(journalPath).open();
  assert.notStrictEqual(reopened, forgedWriter);
  assert.deepEqual(await reopened.recover(), [operation], "reopened real journal");
  const outbound = await new SyncJournal(path.join(parent, "outbox-journal.json")).open();
  const bridge = new LocalSyncWebDavBridge({
    rootDir: root,
    token: "test-only-replay-bearer-never-used",
    journal: reopened,
    protocolJournal: outbound,
    // Intentionally observable legacy ingress: if replay is admitted, the
    // genuine durable outbox records it. No fake signature is ever produced.
    toProtocolOperation: async (entry) => ({
      operationId: `outbox-${entry.operationId}`,
      operation: entry.kind,
    }),
  });
  return { root, bridge, journalPath, outboxPath: outbound.filePath, operation };
}

async function assertIndeterminateWithoutOutbox(f) {
  await assert.rejects(() => f.bridge.recoverPending(),
    { code: "WEBDAV_RECOVERY_INDETERMINATE" },
    "unproven replay must fail closed instead of becoming a protocol operation");

  // Reopen both actual journals after recovery, independent of the bridge's
  // in-memory journal instances. An exception after enqueue is insufficient.
  const mutationAfter = await new SyncJournal(f.journalPath).open();
  const outboundAfter = await new SyncJournal(f.outboxPath).open();
  assert.deepEqual(await mutationAfter.recover(), [f.operation],
    "ambiguous operation must remain pending for manual reconciliation");
  assert.equal(mutationAfter.hasSeen(f.operation.operationId), false,
    "forged mutation must not be acknowledged");
  assert.deepEqual(await outboundAfter.recover(), [],
    "forged mutation must never enter the durable protocol outbox");
}

test("forged source-moved PUT with matching SHA/size of an unrelated file is not authenticated replay", async (t) => {
  const foreign = Buffer.from("PREEXISTING_FOREIGN_BYTES_NEVER_HTTP_PUT");
  const operation = {
    operationId: "forged-put", kind: "put", journalType: "webdav-mutation",
    phase: "source-moved", path: "/foreign.txt", existed: false,
    ...putEvidence(foreign),
  };
  const f = await disposableDiskReplay(t, operation);
  const target = path.join(f.root, "foreign.txt");
  fs.writeFileSync(target, foreign, { flag: "wx", mode: 0o600 });
  await assertIndeterminateWithoutOutbox(f);
  assert.deepEqual(fs.readFileSync(target), foreign, "unrelated local bytes remain untouched");
});

test("forged source-moved MOVE cannot promote an independently created destination", async (t) => {
  const operation = {
    operationId: "forged-move", kind: "move", journalType: "webdav-mutation",
    phase: "source-moved", source: "/missing-source.txt",
    destination: "/foreign-destination.txt", trash: null,
  };
  const f = await disposableDiskReplay(t, operation);
  const target = path.join(f.root, "foreign-destination.txt");
  fs.writeFileSync(target, "UNRELATED_MOVE_DESTINATION", { flag: "wx", mode: 0o600 });
  assert.equal(fs.existsSync(path.join(f.root, "missing-source.txt")), false);
  await assertIndeterminateWithoutOutbox(f);
  assert.equal(fs.readFileSync(target, "utf8"), "UNRELATED_MOVE_DESTINATION");
});

test("forged source-moved DELETE cannot promote an unrelated backup to a delete", async (t) => {
  const operation = {
    operationId: "forged-delete", kind: "delete", journalType: "webdav-mutation",
    phase: "source-moved", source: "/never-deleted.txt",
    trash: ".rootark-trash/unrelated-backup.txt",
  };
  const f = await disposableDiskReplay(t, operation);
  const trash = path.join(f.root, ".rootark-trash");
  fs.mkdirSync(trash, { mode: 0o700 });
  const backup = path.join(trash, "unrelated-backup.txt");
  fs.writeFileSync(backup, "UNRELATED_TRASH_BYTES", { flag: "wx", mode: 0o600 });
  assert.equal(fs.existsSync(path.join(f.root, "never-deleted.txt")), false);
  await assertIndeterminateWithoutOutbox(f);
  assert.equal(fs.readFileSync(backup, "utf8"), "UNRELATED_TRASH_BYTES");
});

test("forged protocol-queued phase cannot skip PUT existence and payload proof", async (t) => {
  const operation = {
    operationId: "forged-queued-put", kind: "put", journalType: "webdav-mutation",
    phase: "protocol-queued", path: "/never-uploaded.txt", existed: false,
    // Deliberately no content digest, no bytes, and no destination inode.
  };
  const f = await disposableDiskReplay(t, operation);
  assert.equal(fs.existsSync(path.join(f.root, "never-uploaded.txt")), false);
  await assertIndeterminateWithoutOutbox(f);
});

test("ambiguous staged MOVE with backup and unrelated destination cannot be replayed as applied", async (t) => {
  const operation = {
    operationId: "forged-staged-move", kind: "move", journalType: "webdav-mutation",
    phase: "staged", source: "/missing-source.txt",
    destination: "/occupied-destination.txt",
    trash: ".rootark-trash/original-destination.txt",
  };
  const f = await disposableDiskReplay(t, operation);
  const trash = path.join(f.root, ".rootark-trash");
  fs.mkdirSync(trash, { mode: 0o700 });
  const backup = path.join(trash, "original-destination.txt");
  const target = path.join(f.root, "occupied-destination.txt");
  fs.writeFileSync(backup, "BACKUP_OF_PRIOR_DESTINATION", { flag: "wx", mode: 0o600 });
  fs.writeFileSync(target, "FOREIGN_OCCUPIED_DESTINATION", { flag: "wx", mode: 0o600 });
  assert.equal(fs.existsSync(path.join(f.root, "missing-source.txt")), false);
  await assertIndeterminateWithoutOutbox(f);
  assert.equal(fs.readFileSync(backup, "utf8"), "BACKUP_OF_PRIOR_DESTINATION");
  assert.equal(fs.readFileSync(target, "utf8"), "FOREIGN_OCCUPIED_DESTINATION");
});

async function realHttpPutCrashChild() {
  // Executed through node -e in an isolated process. Terminating this process
  // models a crash before protocol enqueue; throwing inside the HTTP handler
  // would instead invoke the bridge rollback and invalidate the experiment.
  const path = require("node:path");
  const { root, journalPath, outboxPath, projectRoot, token } =
    JSON.parse(process.env.ROOTARK_COS_DISPOSABLE_CRASH_CONFIG);
  const { SyncJournal } = require(path.join(projectRoot, "sync-client", "rootark-sync-journal.js"));
  const { LocalSyncWebDavBridge } =
    require(path.join(projectRoot, "sync-client", "rootark-sync-webdav.js"));
  const mutation = await new SyncJournal(journalPath).open();
  const outbox = await new SyncJournal(outboxPath).open();
  let releasePrepared;
  const afterPrepared = new Promise((resolve) => { releasePrepared = resolve; });
  process.on("message", (message) => {
    if (message?.kind === "continue-after-prepared") releasePrepared();
  });
  const announce = (message) => new Promise((resolve, reject) => {
    process.send(message, (error) => error ? reject(error) : resolve());
  });
  const bridge = new LocalSyncWebDavBridge({
    rootDir: root, token, port: 0, journal: mutation, protocolJournal: outbox,
    onOperation: async (event) => {
      await mutation.enqueue(event);
      await announce({ kind: "prepared", operationId: event.operationId });
      await afterPrepared;
    },
    toProtocolOperation: async (event) => ({
      operationId: `recovered-${event.operationId}`, operation: "create",
      payloadDigest: event.putSha256,
    }),
  });
  bridge.enqueueProtocol = async () => {
    // Real PUT already installed and recorded its durable source-moved inode
    // when the handler reaches this boundary. There is no outbox ACK yet.
    // Windows start() creates a separate long-lived native PowerShell ACL
    // worker. Stop JUST that helper after the HTTP ACL checks have completed;
    // SIGKILL of Node alone could orphan the worker. Do not stop() the bridge
    // or settle the request: this must remain a real interrupted PUT.
    bridge.windowsAclVerifier?.stop();
    bridge.windowsAclVerifier = null;
    await announce({ kind: "outbox-blocked" });
    await new Promise(() => {});
  };
  await bridge.start();
  await announce({ kind: "listening", port: bridge.address().port });
}

function createCrashEventReader(child, stderr) {
  const observed = [];
  const waiting = [];
  let failure = null;
  const remove = (waiter) => {
    const index = waiting.indexOf(waiter);
    if (index >= 0) waiting.splice(index, 1);
    clearTimeout(waiter.timer);
  };
  const fail = (error) => {
    if (failure) return;
    failure = error;
    for (const waiter of [...waiting]) {
      remove(waiter);
      waiter.reject(failure);
    }
  };
  child.on("message", (event) => {
    observed.push(event);
    for (const waiter of [...waiting]) {
      if (event?.kind !== waiter.kind) continue;
      remove(waiter);
      waiter.resolve(event);
    }
  });
  child.on("error", fail);
  child.on("exit", (code, signal) => {
    fail(new Error(`PUT crash fixture terminated before checkpoint: ${code}/${signal}; ${stderr()}`));
  });
  return (kind) => {
    const already = observed.find((event) => event?.kind === kind);
    if (already) return Promise.resolve(already);
    if (failure) return Promise.reject(failure);
    return new Promise((resolve, reject) => {
      const waiter = { kind, resolve, reject, timer: null };
      waiter.timer = setTimeout(() => {
        remove(waiter);
        reject(new Error(`Timeout awaiting real HTTP PUT checkpoint ${kind}: ${stderr()}`));
      }, 90000);
      waiting.push(waiter);
    });
  };
}

async function awaitCrashChildClosed(closed) {
  // `close` can be delayed by a leaked descendant holding a subprocess pipe.
  // A bounded test teardown reports the leak rather than hanging Node22's
  // exclusive test runner after a failed assertion.
  let timer;
  try {
    await Promise.race([closed, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(
        "Crash-test child did not close after SIGKILL (possible process/pipe leak)")), 15000);
    })]);
  } finally { clearTimeout(timer); }
}

test("genuine authenticated HTTP PUT survives a hard crash before outbox ACK and replays exactly once", {
  timeout: 180000,
}, async (t) => {
  const parent = createPrivateAuthorityFixture("cos-pr235-real-put-");
  const root = path.join(parent, "bridge");
  fs.mkdirSync(root, { mode: 0o700 });
  const journalPath = path.join(parent, "real-mutation.json");
  const outboxPath = path.join(parent, "real-outbox.json");
  const target = path.join(root, "from-http.txt");
  const token = "disposable-real-http-crash-test-token";
  const bytes = Buffer.from("ACTUAL_HTTP_BODY_WITH_PERSISTED_INODE_PROVENANCE");
  const childCode = `(${realHttpPutCrashChild.toString()})().catch((error) => {
    process.stderr.write(String(error?.stack || error));
    process.exitCode = 1;
  });`;
  const child = spawn(process.execPath, ["-e", childCode], {
    cwd: path.resolve(__dirname, ".."),
    env: { ...process.env, ROOTARK_COS_DISPOSABLE_CRASH_CONFIG: JSON.stringify({
      root, journalPath, outboxPath, projectRoot: path.resolve(__dirname, ".."), token,
    }) },
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    windowsHide: true,
  });
  let childStderr = "";
  child.stderr.on("data", (part) => { childStderr = (childStderr + part.toString()).slice(-4096); });
  child.stdout.resume();
  const waitFor = createCrashEventReader(child, () => childStderr);
  const closed = new Promise((resolve) => child.once("close", resolve));
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await awaitCrashChildClosed(closed);
    fs.rmSync(parent, { recursive: true, force: true, maxRetries: 5 });
  });

  const listening = await waitFor("listening");
  assert.ok(Number.isInteger(listening.port) && listening.port > 0);
  assert.equal(fs.existsSync(target), false, "the target must not exist before the real HTTP PUT");
  const httpResult = new Promise((resolve) => {
    const req = http.request({ host: "127.0.0.1", port: listening.port,
      method: "PUT", path: "/from-http.txt",
      headers: { authorization: `Bearer ${token}`, "content-length": bytes.length },
    }, (response) => {
      response.resume();
      response.on("end", () => resolve({ status: response.statusCode }));
      response.on("error", (error) => resolve({ error: error.code }));
    });
    req.on("error", (error) => resolve({ error: error.code }));
    req.setTimeout(60000, () => req.destroy(Object.assign(
      new Error("HTTP fixture timed out before child termination"), { code: "HTTP_FIXTURE_TIMEOUT" })));
    req.end(bytes);
  });

  const preparedCheckpoint = await waitFor("prepared");
  const freshPrepared = await new SyncJournal(journalPath).open();
  const prepared = await freshPrepared.recover();
  assert.equal(prepared.length, 1);
  assert.equal(prepared[0].operationId, preparedCheckpoint.operationId);
  assert.equal(prepared[0].journalType, "webdav-mutation");
  assert.equal(prepared[0].kind, "put");
  assert.equal(prepared[0].phase, "prepared");
  assert.equal(prepared[0].path, "/from-http.txt");
  assert.equal(prepared[0].existed, false);
  assert.deepEqual({ putBytes: prepared[0].putBytes, putSha256: prepared[0].putSha256 },
    putEvidence(bytes), "payload digest and length must come from the authenticated HTTP body");
  assert.equal(Object.hasOwn(prepared[0], "installedIdentity"), false,
    "installed inode must not be claimed before the physical publication");
  assert.equal(fs.existsSync(target), false,
    "the paused prepared phase must not have installed the destination");

  child.send({ kind: "continue-after-prepared" });
  await waitFor("outbox-blocked");
  const afterInstall = await new SyncJournal(journalPath).open();
  const installed = await afterInstall.recover();
  assert.equal(installed.length, 1);
  assert.equal(installed[0].operationId, prepared[0].operationId);
  assert.equal(installed[0].phase, "source-moved");
  assert.deepEqual({ putBytes: installed[0].putBytes, putSha256: installed[0].putSha256 },
    putEvidence(bytes));
  const liveInode = fs.lstatSync(target, { bigint: true });
  assert.equal(liveInode.isFile(), true);
  assert.equal(liveInode.nlink, 1n);
  assert.deepEqual(installed[0].installedIdentity, {
    dev: String(liveInode.dev), ino: String(liveInode.ino), type: "file",
  }, "durable source-moved update must bind the exact inode installed by real HTTP PUT");
  assert.deepEqual(fs.readFileSync(target), bytes);
  const beforeCrashOutbox = await new SyncJournal(outboxPath).open();
  assert.deepEqual(await beforeCrashOutbox.recover(), [], "no outbox enqueue/ACK before crash");

  assert.equal(child.kill("SIGKILL"), true, "terminate the process before it can return HTTP success");
  await awaitCrashChildClosed(closed);
  const interruptedHttp = await httpResult;
  assert.equal(interruptedHttp.status, undefined,
    "a completed 201 response would mean this was not an unacknowledged crash");
  assert.notEqual(interruptedHttp.error, "HTTP_FIXTURE_TIMEOUT");

  // Both journals are reopened from DISK after the old process is dead.
  const recoveredMutation = await new SyncJournal(journalPath).open();
  const recoveredOutbox = await new SyncJournal(outboxPath).open();
  assert.deepEqual(await recoveredMutation.recover(), installed,
    "restart must see the same durable source-moved witness from genuine HTTP");
  const freshBridge = new LocalSyncWebDavBridge({ rootDir: root, token,
    journal: recoveredMutation, protocolJournal: recoveredOutbox,
    toProtocolOperation: async (event) => ({
      operationId: `recovered-${event.operationId}`, operation: "create",
      payloadDigest: event.putSha256,
    }),
  });
  await freshBridge.recoverPending();
  const newOutbox = await new SyncJournal(outboxPath).open();
  assert.deepEqual(await newOutbox.recover(), [{
    operationId: `recovered-${prepared[0].operationId}`,
    operation: "create", payloadDigest: putEvidence(bytes).putSha256,
  }], "real outbox journal must contain exactly the original HTTP payload once");
  const completedMutation = await new SyncJournal(journalPath).open();
  assert.deepEqual(await completedMutation.recover(), []);
  assert.equal(completedMutation.hasSeen(prepared[0].operationId), true);
  assert.deepEqual(fs.readFileSync(target), bytes);

  // A subsequent independent reboot-style recovery cannot emit a duplicate.
  const secondBridge = new LocalSyncWebDavBridge({ rootDir: root, token,
    journal: await new SyncJournal(journalPath).open(),
    protocolJournal: await new SyncJournal(outboxPath).open(),
    toProtocolOperation: async () => { throw new Error("unexpected second translation"); },
  });
  await secondBridge.recoverPending();
  assert.equal((await new SyncJournal(outboxPath).open()).pending().length, 1,
    "replay once, then persistently suppress another replay");
});
