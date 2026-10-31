"use strict";

// TEST_UNRUN until the shared exclusive Node22 gate is genuinely open.
// These are real filesystem + bridge startup/stop tests, not mocked locks.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "owner-start-stop-race-test-only";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { resolve, promise };
}

async function setup(t) {
  const parent = createPrivateAuthorityFixture("cos-pr235-start-stop-");
  const root = path.join(parent, "root");
  fs.mkdirSync(root, { mode: 0o700 });
  const journal = await new SyncJournal(path.join(parent, "mutation.json")).open();
  const bridges = [];
  t.after(async () => {
    await Promise.allSettled(bridges.map((bridge) => bridge.stop()));
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  const bridge = (options = {}) => {
    const instance = new LocalSyncWebDavBridge({
      rootDir: root, journal, token: TOKEN, host: "127.0.0.1", port: 0, ...options,
    });
    bridges.push(instance);
    return instance;
  };
  return { parent, root, journal, bridge };
}

test("pre-listen stop preserves root ownership until pending recovery finishes", {
  timeout: 90000,
}, async (t) => {
  const f = await setup(t);
  const entered = deferred();
  const release = deferred();
  t.after(() => release.resolve());

  const owner = f.bridge();
  owner.recoverPending = async () => {
    entered.resolve();
    await release.promise;
  };

  const starting = owner.start();
  // Attach rejection handling immediately so a quick startup failure cannot
  // surface as an unrelated unhandled rejection.
  const completedStart = starting.then(
    () => ({ ok: true }),
    (error) => ({ ok: false, error }),
  );
  await entered.promise;
  const lock = path.join(f.root, ".rootark-webdav-owner.lock");
  const before = await fsp.lstat(lock, { bigint: true });
  assert.ok(before.isDirectory() && before.ino > 0n);

  await owner.stop();
  const afterStop = await fsp.lstat(lock, { bigint: true });
  assert.equal(afterStop.dev, before.dev);
  assert.equal(afterStop.ino, before.ino,
    "stop must not drop the exclusive lifetime claim while start still recovers");

  const contender = f.bridge({ journal: new SyncJournal(path.join(f.parent, "contender.json")) });
  await assert.rejects(contender.start(), (error) =>
    error?.code === "EEXIST",
  "another bridge must fail due to the exact exclusive root claim");
  assert.equal(await fsp.stat(lock).then((stat) => stat.isDirectory()), true);

  release.resolve();
  const outcome = await completedStart;
  assert.equal(outcome.ok, false, "cancelled startup must never finish listening");
  assert.match(String(outcome.error?.message), /cancelled by stop/i);
  await assert.rejects(fsp.lstat(lock), { code: "ENOENT" });
  assert.equal(owner.address(), null);

  await contender.start();
  assert.ok(contender.address()?.port > 0);
  await contender.stop();
  await assert.rejects(fsp.lstat(lock), { code: "ENOENT" });
});

test("rejected protected contender cannot create or change journals before root ownership", {
  timeout: 90000,
}, async (t) => {
  const f = await setup(t);
  const owner = f.bridge();
  await owner.start();
  const journalPath = path.join(f.parent, "contender-mutation.json");
  const outboxPath = path.join(f.parent, "contender-outbox.json");
  const contender = f.bridge({
    journal: new SyncJournal(journalPath),
    protocolJournal: new SyncJournal(outboxPath),
    requireSignedProtocolIngress: true,
    trustedProtocolPolicy: async () => ({ trusted: false }),
    toProtocolOperation: async () => [],
    resolveProtectedFileKey: async () => Buffer.alloc(32),
  });

  await assert.rejects(contender.start(), (error) => error?.code === "EEXIST");
  await assert.rejects(fsp.lstat(journalPath), { code: "ENOENT" });
  await assert.rejects(fsp.lstat(outboxPath), { code: "ENOENT" });
  assert.ok(owner.address()?.port > 0, "first owner remains live");
  await owner.stop();
});

test("protected ingress rejects one journal pathname shared by mutation and signed outbox", {
  timeout: 90000,
}, async (t) => {
  const f = await setup(t);
  const filePath = path.join(f.parent, "same-journal.json");
  const bridge = f.bridge({
    journal: new SyncJournal(filePath),
    protocolJournal: new SyncJournal(filePath),
    requireSignedProtocolIngress: true,
    trustedProtocolPolicy: async () => ({ trusted: false }),
    toProtocolOperation: async () => [],
    resolveProtectedFileKey: async () => Buffer.alloc(32),
  });
  await assert.rejects(bridge.start(), /distinct mutation and signed outbox journals/i);
  await assert.rejects(fsp.lstat(filePath), { code: "ENOENT" });
  await assert.rejects(fsp.lstat(path.join(f.root, ".rootark-webdav-owner.lock")),
    { code: "ENOENT" });
});

test("protected ingress rejects distinct journal paths hardlinked to the same inode", {
  timeout: 90000,
}, async (t) => {
  const f = await setup(t);
  const localPath = path.join(f.parent, "mutation-hardlinked.json");
  const outboxPath = path.join(f.parent, "outbox-hardlinked.json");
  await new SyncJournal(localPath).open();
  try {
    await fsp.link(localPath, outboxPath);
  } catch (error) {
    if (["EPERM", "EOPNOTSUPP", "ENOTSUP"].includes(error?.code)) {
      t.skip("The local filesystem does not permit a same-inode hardlink fixture");
      return;
    }
    throw error;
  }
  const before = await fsp.lstat(localPath, { bigint: true });
  assert.equal(before.nlink, 2n, "both paths genuinely reference the same inode");
  const bridge = f.bridge({
    journal: new SyncJournal(localPath),
    protocolJournal: new SyncJournal(outboxPath),
    requireSignedProtocolIngress: true,
    trustedProtocolPolicy: async () => ({ trusted: false }),
    toProtocolOperation: async () => [],
    resolveProtectedFileKey: async () => Buffer.alloc(32),
  });
  await assert.rejects(bridge.start(), /journals share one physical inode/i);
  const first = await fsp.lstat(localPath, { bigint: true });
  const second = await fsp.lstat(outboxPath, { bigint: true });
  assert.equal(first.ino, before.ino);
  assert.equal(first.ino, second.ino);
  assert.equal(second.nlink, 2n);
  await assert.rejects(fsp.lstat(path.join(f.root, ".rootark-webdav-owner.lock")),
    { code: "ENOENT" });
});

test("protected journal admission cannot be replaced with a prototype-inherited no-op hook", {
  timeout: 90000,
}, async (t) => {
  const f = await setup(t);
  let skippedAdmissions = 0;
  const options = Object.create({
    onOperation: async () => { skippedAdmissions += 1; },
  });
  Object.assign(options, {
    rootDir: f.root,
    token: TOKEN,
    journal: new SyncJournal(path.join(f.parent, "protected-local.json")),
    protocolJournal: new SyncJournal(path.join(f.parent, "protected-outbox.json")),
    toProtocolOperation: async () => [],
    requireSignedProtocolIngress: true,
    trustedProtocolPolicy: async () => ({ trusted: false }),
    resolveProtectedFileKey: async () => Buffer.alloc(32),
  });
  const bridge = new LocalSyncWebDavBridge(options);
  t.after(() => bridge.stop());
  await assert.rejects(bridge.start(), /durable admission hook/i);
  assert.equal(skippedAdmissions, 0);
  await assert.rejects(
    fsp.lstat(path.join(f.root, ".rootark-webdav-owner.lock")), { code: "ENOENT" },
  );
});

test("cancelled listen closes the real HTTP socket before relinquishing root ownership", {
  timeout: 90000,
}, async (t) => {
  const f = await setup(t);
  const bridge = f.bridge();
  const releaseObservedListening = [];
  const originalRelease = bridge.releaseRootOwnership.bind(bridge);
  bridge.releaseRootOwnership = async () => {
    // Instrument ordering without replacing the real lock release or
    // monkeypatching network/filesystem calls.
    if (bridge.rootOwnerIdentity) {
      releaseObservedListening.push(bridge.server.listening);
    }
    return originalRelease();
  };

  let stopping;
  bridge.server.once("listening", () => {
    // A real listen() event fires before the callback awaited by start().
    // Cancel in this precise admission window, not via a synthetic flag.
    stopping = bridge.stop();
  });
  await assert.rejects(bridge.start(), /cancelled by stop/i);
  assert.ok(stopping, "listen event must fire in a genuine server start");
  await stopping;
  assert.deepEqual(releaseObservedListening, [false],
    "cross-process ownership may be released only after the actual listener is closed");
  assert.equal(bridge.server.listening, false);
  assert.equal(bridge.address(), null);
  await assert.rejects(
    fsp.lstat(path.join(f.root, ".rootark-webdav-owner.lock")), { code: "ENOENT" },
  );
});

test("separate bridge roots cannot concurrently own one physical journal, and successor rereads durable receipts", {
  timeout: 90000,
}, async (t) => {
  const parent = createPrivateAuthorityFixture("cos-pr235-shared-journal-");
  const firstRoot = path.join(parent, "first-root");
  const secondRoot = path.join(parent, "second-root");
  fs.mkdirSync(firstRoot, { mode: 0o700 });
  fs.mkdirSync(secondRoot, { mode: 0o700 });
  const journalPath = path.join(parent, "shared-journal.json");
  const firstJournal = await new SyncJournal(journalPath).open();
  const successorJournal = await new SyncJournal(journalPath).open();
  const first = new LocalSyncWebDavBridge({
    rootDir: firstRoot, token: TOKEN, journal: firstJournal,
  });
  const successor = new LocalSyncWebDavBridge({
    rootDir: secondRoot, token: TOKEN, journal: successorJournal,
  });
  t.after(async () => {
    await Promise.allSettled([first.stop(), successor.stop()]);
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });

  const claim = journalPath + ".webdav-owner.lock";
  await first.start();
  const ownerStat = await fsp.lstat(claim, { bigint: true });
  assert.equal(ownerStat.isDirectory(), true);
  await firstJournal.enqueue({ operationId: "first-owner-durable-receipt" });
  await firstJournal.markSeen("first-owner-durable-receipt");
  const firstDiskBytes = await fsp.readFile(journalPath);

  await assert.rejects(successor.start(), (error) => error?.code === "EEXIST",
    "a different root cannot seize the SAME journal path while a real owner is live");
  assert.deepEqual(await fsp.readFile(journalPath), firstDiskBytes,
    "rejected contender must not touch even one byte of the shared journal");
  assert.equal((await fsp.lstat(claim, { bigint: true })).ino, ownerStat.ino,
    "failed owner may not replace the first bridge's lifetime claim");
  await assert.rejects(
    fsp.lstat(path.join(secondRoot, ".rootark-webdav-owner.lock")),
    { code: "ENOENT" },
    "failed journal claim must also release the contender's separate root claim");

  await first.stop();
  await assert.rejects(fsp.lstat(claim), { code: "ENOENT" });
  await successor.start();
  assert.equal(successorJournal.hasSeen("first-owner-durable-receipt"), true,
    "pre-opened stale journal must refresh under its newly acquired lock");
  assert.deepEqual(await fsp.readFile(journalPath), firstDiskBytes);
  await successor.stop();
  await assert.rejects(fsp.lstat(claim), { code: "ENOENT" });
});

test("legacy bridge creates a missing private journal parent before claiming journal ownership", {
  timeout: 90000,
}, async (t) => {
  const parent = createPrivateAuthorityFixture("cos-pr235-journal-bootstrap-");
  const root = path.join(parent, "root");
  fs.mkdirSync(root, { mode: 0o700 });
  const journalDir = path.join(parent, "new-private-journal-directory");
  const journalPath = path.join(journalDir, "journal.json");
  assert.equal(fs.existsSync(journalDir), false, "fixture must start without a journal parent");
  const journal = new SyncJournal(journalPath);
  const bridge = new LocalSyncWebDavBridge({
    rootDir: root, token: TOKEN, journal,
  });
  t.after(async () => {
    await bridge.stop();
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  await bridge.start();
  assert.equal(bridge.server.listening, true);
  assert.equal((await fsp.lstat(journalPath)).isFile(), true,
    "legacy bootstrap must create the real persisted journal under the private parent");
  const claim = journalPath + ".webdav-owner.lock";
  assert.equal((await fsp.lstat(claim)).isDirectory(), true,
    "a journal claim must remain owned for the entire bridge lifetime");
  await journal.enqueue({ operationId: "bootstrap-physical", phase: "prepared" });
  await journal.markSeen("bootstrap-physical");
  assert.equal((await new SyncJournal(journalPath).open()).hasSeen("bootstrap-physical"), true);
  await bridge.stop();
  await assert.rejects(fsp.lstat(claim), { code: "ENOENT" });
  assert.equal((await new SyncJournal(journalPath).open()).hasSeen("bootstrap-physical"), true);
});
