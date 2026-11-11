"use strict";

// TEST_UNRUN: gated by exclusive Node22/host RAM. All requests use a genuine
// loopback WebDAV server and the same bearer token as a legitimate client.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { validatePortableRelativePath } = require("../sync-client/rootark-sync-paths");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

const TOKEN = "cos-pr235-private-namespace-test";

async function readPinnedEvidence(filename, expectedStat) {
  // A pathname-only read after rejecting hardlink aliasing or MOVE could
  // inspect a substituted inode with identical content. Keep the expected
  // physical file open while checking its bytes and pathname identity.
  const handle = await fsp.open(filename,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const before = await handle.stat({ bigint: true });
    const namedBefore = await fsp.lstat(filename, { bigint: true });
    for (const observed of [before, namedBefore]) {
      assert.equal(observed.isFile(), true);
      assert.equal(observed.dev, expectedStat.dev);
      assert.equal(observed.ino, expectedStat.ino);
      assert.equal(observed.nlink, expectedStat.nlink);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const namedAfter = await fsp.lstat(filename, { bigint: true });
    for (const observed of [after, namedAfter]) {
      assert.equal(observed.isFile(), true);
      assert.equal(observed.dev, before.dev);
      assert.equal(observed.ino, before.ino);
      assert.equal(observed.nlink, before.nlink);
      assert.equal(observed.size, BigInt(bytes.length));
    }
    assert.equal(before.size, after.size,
      "the pinned inode must not be resized during readback");
    return bytes;
  } finally {
    await handle.close();
  }
}

async function request(bridge, method, route, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port: bridge.address().port,
      method,
      path: route,
      headers: { authorization: "Bearer " + TOKEN, ...headers },
    }, (res) => {
      const parts = [];
      res.on("data", (part) => parts.push(part));
      res.on("error", reject);
      res.on("end", () => resolve({
        status: res.statusCode,
        body: Buffer.concat(parts).toString("utf8"),
      }));
    });
    req.setTimeout(30000, () => req.destroy(Error("internal namespace HTTP timed out")));
    req.on("error", reject);
    req.end();
  });
}

test("authenticated WebDAV cannot read, delete, or enumerate private owner, trash or PUT staging", {
  timeout: 90000,
}, async (t) => {
  const parent = createPrivateAuthorityFixture("cos-pr235-hidden-");
  const root = path.join(parent, "root");
  fs.mkdirSync(root, { mode: 0o700 });
  const stage = path.join(root, ".rootark-put-secret");
  const trash = path.join(root, ".rootark-trash");
  fs.mkdirSync(trash, { mode: 0o700 });
  const oldFile = path.join(trash, "deleted-private.txt");
  const secret = "SECRET_PRIVATE_FILE_NEVER_PUBLIC_WEBDAV";
  fs.writeFileSync(stage, secret, { mode: 0o600 });
  fs.writeFileSync(oldFile, secret, { mode: 0o600 });
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: TOKEN, port: 0 });
  t.after(async () => {
    await bridge.stop();
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  await bridge.start();
  const lock = path.join(root, ".rootark-webdav-owner.lock");
  assert.equal((await fsp.lstat(lock)).isDirectory(), true);
  for (const incoming of [".rootark-webdav-owner.lock",
    ".ROOTARK-WEBDAV-OWNER.LOCK", "other/.rootark-webdav-owner.lock"]) {
    assert.throws(() => validatePortableRelativePath(incoming), { code: "unsafe_path" },
      "remote ciphertext paths must not target the protected bridge owner lock");
  }
  const engine = new SyncEngine({
    rootDir: root,
    adapter: { push: async () => {}, list: async () => ({ objects: [] }) },
  });
  assert.equal(Object.keys(await engine.scanFiles()).length, 0,
    "the sync engine must not replicate bridge ownership locks or private staging");

  for (const route of [
    "/.rootark-put-secret",
    "/.rootark-trash/deleted-private.txt",
    "/.rootark-webdav-owner.lock",
  ]) {
    for (const method of ["GET", "DELETE"]) {
      const reply = await request(bridge, method, route);
      assert.equal(reply.status, 400, method + " " + route + " must reject internal evidence");
      assert.equal(reply.body.includes(secret), false);
    }
  }
  if (process.platform === "win32") {
    for (const route of ["/.ROOTARK-PUT-SECRET", "/.ROOTARK-WEBDAV-OWNER.LOCK"]) {
      for (const method of ["GET", "DELETE"]) {
        const reply = await request(bridge, method, route);
        assert.equal(reply.status, 400,
          "case-folded NTFS internal path must reject " + method + " " + route);
      }
    }
  }
  const listing = await request(bridge, "PROPFIND", "/", { Depth: "1" });
  assert.equal(listing.status, 207, "healthy authenticated root enumeration still works");
  assert.equal(listing.body.includes(".rootark-put-"), false);
  assert.equal(listing.body.includes(".rootark-webdav-owner.lock"), false);
  assert.equal(listing.body.includes("deleted-private.txt"), false);
  assert.equal(listing.body.includes(secret), false);
  assert.equal(await fsp.readFile(stage, "utf8"), secret);
  assert.equal(await fsp.readFile(oldFile, "utf8"), secret);
  assert.equal((await fsp.lstat(lock)).isDirectory(), true);
});

test("a private mutation journal under the public WebDAV root fails startup without touching its bytes", {
  timeout: 90000,
}, async (t) => {
  const parent = createPrivateAuthorityFixture("cos-pr235-journal-hidden-");
  const root = path.join(parent, "root");
  fs.mkdirSync(root, { mode: 0o700 });
  const journalPath = path.join(root, "user-chosen-private-state.json");
  const journal = await new SyncJournal(journalPath).open();
  const before = await fsp.readFile(journalPath);
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: TOKEN, journal });
  t.after(async () => {
    await bridge.stop();
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  await assert.rejects(bridge.start(), /journals must reside outside/i);
  assert.deepEqual(await fsp.readFile(journalPath), before);
  await assert.rejects(fsp.lstat(path.join(root, ".rootark-webdav-owner.lock")),
    { code: "ENOENT" });
  assert.equal(bridge.address(), null);
});

test("a protected signed outbox under the public WebDAV root fails startup", {
  timeout: 90000,
}, async (t) => {
  const parent = createPrivateAuthorityFixture("cos-pr235-outbox-hidden-");
  const root = path.join(parent, "root");
  fs.mkdirSync(root, { mode: 0o700 });
  const privateJournal = await new SyncJournal(path.join(parent, "mutation.json")).open();
  const exposedOutboxPath = path.join(root, "otherwise-readable-outbox.json");
  const privateOutbox = await new SyncJournal(exposedOutboxPath).open();
  const before = await fsp.readFile(exposedOutboxPath);
  const bridge = new LocalSyncWebDavBridge({
    rootDir: root, token: TOKEN,
    journal: privateJournal, protocolJournal: privateOutbox,
    requireSignedProtocolIngress: true,
    trustedProtocolPolicy: async () => ({ trusted: false }),
    toProtocolOperation: async () => [],
    resolveProtectedFileKey: async () => Buffer.alloc(32),
  });
  t.after(async () => {
    await bridge.stop();
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  await assert.rejects(bridge.start(), /journals must reside outside/i);
  assert.deepEqual(await fsp.readFile(exposedOutboxPath), before);
  await assert.rejects(fsp.lstat(path.join(root, ".rootark-webdav-owner.lock")),
    { code: "ENOENT" });
  assert.equal(bridge.address(), null);
});

test("protected startup refuses a journal inode hardlinked into the served root", {
  timeout: 90000,
}, async (t) => {
  const parent = createPrivateAuthorityFixture("cos-pr235-linked-journal-");
  let bridge;
  t.after(async () => {
    if (bridge) await bridge.stop();
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  const root = path.join(parent, "root");
  fs.mkdirSync(root, { mode: 0o700 });
  const mutationPath = path.join(parent, "private-mutation.json");
  const outboxPath = path.join(parent, "private-outbox.json");
  const mutation = await new SyncJournal(mutationPath).open();
  const outbox = await new SyncJournal(outboxPath).open();
  const exposedAlias = path.join(root, "document-looking-like-journal.json");
  try {
    await fsp.link(mutationPath, exposedAlias);
  } catch (error) {
    if (["EPERM", "ENOTSUP", "EOPNOTSUPP"].includes(error?.code)) {
      t.skip("Owner-only test volume does not support hardlink aliases");
      return;
    }
    throw error;
  }
  const witness = await fsp.lstat(mutationPath, { bigint: true });
  assert.equal(witness.nlink, 2n);
  const originalBytes = await readPinnedEvidence(mutationPath, witness);
  bridge = new LocalSyncWebDavBridge({
    rootDir: root, token: TOKEN,
    journal: mutation, protocolJournal: outbox,
    requireSignedProtocolIngress: true,
    trustedProtocolPolicy: async () => ({ trusted: false }),
    toProtocolOperation: async () => [],
    resolveProtectedFileKey: async () => Buffer.alloc(32),
  });
  // The held SyncJournal FD now rejects a multi-link inode BEFORE WebDAV's
  // later namespace check. Require that exact fail-closed admission error.
  await assert.rejects(bridge.start(), {
    code: "invalid_sync_journal", message: "Sync journal inode changed during cold read",
  });
  assert.deepEqual(await readPinnedEvidence(mutationPath, witness), originalBytes);
  assert.equal((await fsp.lstat(mutationPath, { bigint: true })).ino, witness.ino);
  assert.equal((await fsp.lstat(exposedAlias, { bigint: true })).ino, witness.ino);
  await assert.rejects(fsp.lstat(path.join(root, ".rootark-webdav-owner.lock")),
    { code: "ENOENT" });
});

test("legacy startup rejects an outside journal path resolving through an alias into public root", {
  timeout: 90000,
}, async (t) => {
  const parent = createPrivateAuthorityFixture("cos-pr235-journal-alias-");
  const root = path.join(parent, "root");
  fs.mkdirSync(root, { mode: 0o700 });
  const alias = path.join(parent, "outside-looking-alias");
  let bridge;
  t.after(async () => {
    if (bridge) await bridge.stop();
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  try {
    await fsp.symlink(root, alias, process.platform === "win32" ? "junction" : "dir");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error?.code)) {
      t.skip("Owner-only test account cannot create a directory alias");
      return;
    }
    throw error;
  }
  const journalPath = path.join(alias, "hidden-state.json");
  const journal = await new SyncJournal(journalPath).open();
  const actual = await fsp.realpath(journalPath);
  assert.equal(actual, await fsp.realpath(path.join(root, "hidden-state.json")),
    "the supposedly external file must actually reside under the HTTP document root");
  const before = await fsp.readFile(journalPath);
  bridge = new LocalSyncWebDavBridge({ rootDir: root, journal, token: TOKEN });
  await assert.rejects(bridge.start(), /journal resolves inside the served document root/i);
  assert.deepEqual(await fsp.readFile(journalPath), before);
  await assert.rejects(fsp.lstat(path.join(root, ".rootark-webdav-owner.lock")),
    { code: "ENOENT" });

  const neverCreated = path.join(alias, "new-state-that-must-not-be-written.json");
  const freshBridge = new LocalSyncWebDavBridge({
    rootDir: root, token: TOKEN, journal: new SyncJournal(neverCreated),
  });
  t.after(() => freshBridge.stop());
  await assert.rejects(freshBridge.start(),
    /journal resolves inside the served document root/i);
  await assert.rejects(fsp.lstat(neverCreated), { code: "ENOENT" });
  await assert.rejects(fsp.lstat(path.join(root, ".rootark-webdav-owner.lock")),
    { code: "ENOENT" });
});

test("malformed WebDAV body limits cannot silently disable the 8 MiB admission cap", () => {
  for (const invalid of [
    NaN, Infinity, -1, 1.5, "not-a-number", 8 * 1024 * 1024 + 1,
  ]) {
    assert.throws(() => new LocalSyncWebDavBridge({
      rootDir: process.cwd(), token: TOKEN, maxBodyBytes: invalid,
    }), /Invalid bounded WebDAV PUT body limit/i,
    "malformed configured size must reject at construction");
  }
  const ordinary = new LocalSyncWebDavBridge({
    rootDir: process.cwd(), token: TOKEN, maxBodyBytes: 1024,
  });
  assert.equal(ordinary.maxBodyBytes, 1024,
    "legitimate stricter limits remain supported");
});

test("a legacy bridge also rejects shared journal inodes aliased under separate filenames", {
  timeout: 90000,
}, async (t) => {
  const parent = createPrivateAuthorityFixture("cos-pr235-legacy-hardlink-");
  const root = path.join(parent, "root");
  fs.mkdirSync(root, { mode: 0o700 });
  const first = path.join(parent, "mutation.json");
  const second = path.join(parent, "other-name-for-same-inode.json");
  const journal = await new SyncJournal(first).open();
  let bridge;
  t.after(async () => {
    if (bridge) await bridge.stop();
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  try {
    await fsp.link(first, second);
  } catch (error) {
    if (["EPERM", "ENOTSUP", "EOPNOTSUPP"].includes(error?.code)) {
      t.skip("Owner-only test volume does not support hardlinks");
      return;
    }
    throw error;
  }
  const before = await fsp.lstat(first, { bigint: true });
  assert.equal(before.nlink, 2n);
  assert.equal((await fsp.lstat(second, { bigint: true })).ino, before.ino);
  const disk = await readPinnedEvidence(first, before);
  bridge = new LocalSyncWebDavBridge({ rootDir: root, journal, token: TOKEN });
  await assert.rejects(bridge.start(), {
    code: "invalid_sync_journal", message: "Sync journal inode changed during cold read",
  });
  assert.deepEqual(await readPinnedEvidence(first, before), disk);
  assert.deepEqual(await readPinnedEvidence(second, before), disk);
  await assert.rejects(fsp.lstat(first + ".webdav-owner.lock"), { code: "ENOENT" });
  await assert.rejects(fsp.lstat(path.join(root, ".rootark-webdav-owner.lock")),
    { code: "ENOENT" });
});

test("MOVE validates original Destination path before URL dot-segment normalization", {
  timeout: 90000,
}, async (t) => {
  const parent = createPrivateAuthorityFixture("cos-pr235-destination-raw-");
  const root = path.join(parent, "root");
  fs.mkdirSync(root, { mode: 0o700 });
  const sourcePath = path.join(root, "original.txt");
  const sourceContent = "SAFE_ORIGINAL_DESTINATION_SOURCE";
  fs.writeFileSync(sourcePath, sourceContent, { mode: 0o600 });
  const original = fs.lstatSync(sourcePath, { bigint: true });
  let admissions = 0;
  const bridge = new LocalSyncWebDavBridge({
    rootDir: root, token: TOKEN, port: 0,
    onOperation: async () => { admissions += 1; },
  });
  t.after(async () => {
    await bridge.stop();
    await fsp.rm(parent, { recursive: true, force: true, maxRetries: 5 });
  });
  await bridge.start();
  const port = bridge.address().port;
  for (const rawDestination of [
    "http://127.0.0.1:" + port + "/temporary/../target.txt",
    "http://127.0.0.1:" + port + "/temporary/%2e%2e/target.txt",
    "/temporary/%2E%2E/target.txt",
    "http://127.0.0.1:" + port + "/%2e/target.txt",
    "target.txt",
  ]) {
    const reply = await request(bridge, "MOVE", "/original.txt", {
      Destination: rawDestination,
      Overwrite: "F",
    });
    assert.equal(reply.status, 400,
      "raw normalized/relative Destination must fail before journal admission");
    assert.equal(admissions, 0);
    assert.deepEqual(await readPinnedEvidence(sourcePath, original),
      Buffer.from(sourceContent, "utf8"));
    assert.equal((await fsp.lstat(sourcePath, { bigint: true })).ino, original.ino);
    assert.equal(fs.existsSync(path.join(root, "target.txt")), false);
    assert.deepEqual(await fsp.readdir(path.join(root, ".rootark-trash")), []);
  }
  const valid = await request(bridge, "MOVE", "/original.txt", {
    Destination: "http://127.0.0.1:" + port + "/target.txt",
    Overwrite: "F",
  });
  assert.equal(valid.status, 201,
    "normal absolute WebDAV Destination must remain functional");
  assert.equal(admissions, 1);
  assert.equal(await fsp.readFile(path.join(root, "target.txt"), "utf8"), sourceContent);
  assert.equal(fs.existsSync(sourcePath), false);
});
