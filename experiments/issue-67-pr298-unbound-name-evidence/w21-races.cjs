"use strict";

// Explicit, non-canonical RED evidence. Never import this file into production.
// Run: node --test experiments/issue-67-pr298-unbound-name-evidence/w21-races.cjs
// All renamed, hardlinked and deleted files are disposable synthetic fixtures.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const Module = require("node:module");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../../sync-client/rootark-sync-engine");
const { createPrivateAuthorityFixture } =
  require("../../test/support/issue-65-private-authority-fixture");

const engineFile = require.resolve("../../sync-client/rootark-sync-engine.js");
function readPrivateProgressPublisher() {
  // The helper is intentionally private. Compile an extra export in MEMORY
  // without altering or monkey-patching the production source on disk.
  const source = fs.readFileSync(engineFile, "utf8");
  const local = new Module(engineFile, module);
  local.filename = engineFile;
  local.paths = Module._nodeModulePaths(path.dirname(engineFile));
  local._compile(source +
    "\nmodule.exports.__w21Evidence = {createDurableRestoreProgress};\n", engineFile);
  return local.exports.__w21Evidence.createDurableRestoreProgress;
}

function disposable(t, prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test("positive: original durable progress hardlinks its actual fsynced bytes", async (t) => {
  const root = disposable(t, "rootark67-w21-progress-positive-");
  const final = path.join(root, ".rootark-recovery-execution-" + "a".repeat(64) + ".json");
  const payload = { version: 1, items: [], scope: { deviceId: "synthetic" }, planDigest: "a".repeat(64) };
  await readPrivateProgressPublisher()(final, payload);
  const names = await fsp.readdir(root);
  const original = names.find((name) => name.startsWith(path.basename(final) + ".tmp-"));
  assert.ok(original, "original fsynced alias must remain accessible");
  const expected = Buffer.from(JSON.stringify(payload) + "\n");
  assert.deepEqual(await fsp.readFile(final), expected);
  assert.equal((await fsp.lstat(final, { bigint: true })).ino,
    (await fsp.lstat(path.join(root, original), { bigint: true })).ino);
  assert.equal((await fsp.lstat(final, { bigint: true })).nlink, 2n);
});

test("RED: createDurableRestoreProgress publishes substituted foreign inode (real link syscall)", async (t) => {
  const root = disposable(t, "rootark67-w21-progress-swap-");
  const final = path.join(root, ".rootark-recovery-execution-" + "b".repeat(64) + ".json");
  const originalLink = fsp.link;
  let affected = false;
  let originalFd, foreignFd, savedName;
  try {
    fsp.link = async (from, to, ...rest) => {
      if (to !== final) return originalLink(from, to, ...rest);
      affected = true;
      // Interpose immediately before the *actual* native link syscall.
      // The genuine fsynced inode remains under a retained private alias.
      savedName = from + ".verified-retained";
      originalFd = await fsp.open(from, "r");
      await fsp.rename(from, savedName);
      await fsp.writeFile(from, "FOREIGN SYNTHETIC BYTES", { flag: "wx" });
      foreignFd = await fsp.open(from, "r");
      return originalLink(from, to, ...rest);
    };
    await readPrivateProgressPublisher()(final, {
      version: 1, planDigest: "b".repeat(64), scope: { test: "w21" }, items: [],
    });
  } finally {
    fsp.link = originalLink;
  }
  try {
    assert.equal(affected, true, "real publication link was reached");
    const actual = await fsp.lstat(final, { bigint: true });
    const foreign = await foreignFd.stat({ bigint: true });
    const authentic = await originalFd.stat({ bigint: true });
    assert.equal(actual.dev, foreign.dev);
    assert.equal(actual.ino, foreign.ino, "RED: published final IS the attacker's foreign inode");
    assert.notDeepEqual([actual.dev, actual.ino], [authentic.dev, authentic.ino],
      "verified fsynced inode was NOT published");
    assert.equal((await fsp.readFile(final, "utf8")), "FOREIGN SYNTHETIC BYTES");
    assert.deepEqual(await originalFd.readFile(), await fsp.readFile(savedName));
    console.log("EXPECTED_SECURITY_RED W21_PROGRESS_FOREIGN_INODE_PUBLISHED");
  } finally {
    if (foreignFd) await foreignFd.close();
    if (originalFd) await originalFd.close();
  }
});

test("RED: stageExisting renames a replaced source inode into trash (real rename syscall)", async (t) => {
  const root = disposable(t, "rootark67-w21-stage-source-");
  const engine = Object.create(SyncEngine.prototype);
  engine.rootDir = root;
  const target = path.join(root, "owned.txt");
  const owned = Buffer.from("ORIGINAL CLEAN OWNER BYTES");
  await fsp.writeFile(target, owned, { flag: "wx" });
  const originalRename = fsp.rename;
  let entered = false, originalFd, foreignFd, retained;
  let stage;
  try {
    fsp.rename = async (from, to, ...rest) => {
      if (from !== target || !to.includes(".rootark-trash")) {
        return originalRename(from, to, ...rest);
      }
      entered = true;
      retained = path.join(root, "owner-unchanged.retained");
      originalFd = await fsp.open(target, "r");
      await originalRename(target, retained);
      await fsp.writeFile(target, "FOREIGN SYNTHETIC SOURCE", { flag: "wx" });
      foreignFd = await fsp.open(target, "r");
      return originalRename(from, to, ...rest);
    };
    stage = await engine.stageExisting(target);
  } finally {
    fsp.rename = originalRename;
  }
  try {
    assert.equal(entered, true);
    assert.ok(stage && stage.includes(".rootark-trash"));
    const stagedStats = await fsp.lstat(stage, { bigint: true });
    const foreignStats = await foreignFd.stat({ bigint: true });
    assert.deepEqual([stagedStats.dev, stagedStats.ino],
      [foreignStats.dev, foreignStats.ino],
      "RED: stage contains foreign source inode, not originally selected inode");
    const originalStats = await originalFd.stat({ bigint: true });
    assert.notDeepEqual([originalStats.dev, originalStats.ino],
      [foreignStats.dev, foreignStats.ino]);
    assert.deepEqual(await fsp.readFile(retained), owned);
    assert.equal(await fsp.readFile(stage, "utf8"), "FOREIGN SYNTHETIC SOURCE");
    console.log("EXPECTED_SECURITY_RED W21_STAGE_EXISTING_FOREIGN_SOURCE_RENAMED");
  } finally {
    if (originalFd) await originalFd.close();
    if (foreignFd) await foreignFd.close();
  }
});

async function signedRestoreFixture(t) {
  const root = createPrivateAuthorityFixture("rootark67-w21-signed-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const local = path.join(root, "client");
  await fsp.mkdir(local);
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const key = crypto.randomBytes(32);
  const policy = { username: "alice", trustedDevicePublicKeys: { "device-a": pub }, revokedDeviceIds: [] };
  const signed = async (input) => {
    const operation = protocol.createOperation({
      objectId: "file-1", fileId: "file-1", deviceId: "device-a",
      keyEpoch: "epoch-1", compartmentId: "private", fileKey: key, ...input,
    });
    return { ...operation, authorization: await createAuthorizationProof(operation,
      { username: "alice", publicKey: pub, privateKey }) };
  };
  const original = await signed({ operation: "create", versionId: "first", operationId: "first-op",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "document.txt" }, plaintext: Buffer.from("AUTHENTICATED RESTORE BYTES") });
  const deleted = await signed({ operation: "delete", versionId: "deleted", operationId: "delete-op",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: original.revision,
    metadata: { path: "document.txt" } });
  let current = deleted, pushed = 0;
  const adapter = {
    history: async () => ({ protocolVersion: 2, versions: structuredClone([original, deleted]) }),
    list: async () => structuredClone(current),
    push: async (operation) => {
      pushed++;
      assert.equal(await verifyAuthorizationProof(operation.authorization, operation, policy), true);
      current = structuredClone(operation);
      return structuredClone(current);
    },
  };
  const engine = await new SyncEngine({
    rootDir: local, adapter, deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    requireAuthorization: true, authorize: () => true, authorizeOutgoing: () => true,
    verifyIncoming: (record) => verifyAuthorizationProof(record.authorization, record, policy),
    authorizationFactory: (record) => createAuthorizationProof(record,
      { username: "alice", privateKey, publicKey: pub }),
  }).open();
  return { root, local, engine, getPushed: () => pushed };
}

test("positive: historical signed restore materializes original authenticated bytes", async (t) => {
  const f = await signedRestoreFixture(t);
  const result = await f.engine.restoreHistoricalVersion("file-1", "first");
  assert.equal(result.restored, true);
  assert.equal(result.pushed, true);
  assert.equal(f.getPushed(), 1);
  assert.equal(await fsp.readFile(path.join(f.local, "document.txt"), "utf8"),
    "AUTHENTICATED RESTORE BYTES");
});

test("GREEN: _apply history rejects substituted foreign temporary and never publishes foreign bytes", async (t) => {
  const f = await signedRestoreFixture(t);
  const target = path.join(f.local, "document.txt");
  const originalLink = fsp.link;
  let triggered = false, originalFd, foreignFd, retained;
  try {
    fsp.link = async (from, to, ...rest) => {
      if (to !== target || !from.includes(".tmp-")) {
        return originalLink(from, to, ...rest);
      }
      triggered = true;
      retained = from + ".retained-original";
      originalFd = await fsp.open(from, "r");
      await fsp.rename(from, retained);
      await fsp.writeFile(from, "FOREIGN SYNTHETIC RESTORE BYTES", { flag: "wx" });
      foreignFd = await fsp.open(from, "r");
      return originalLink(from, to, ...rest);
    };
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_local_conflict");
  } finally {
    fsp.link = originalLink;
  }
  try {
    assert.equal(triggered, true, "the original historical publication path was exercised");
    assert.equal(await fsp.readFile(retained, "utf8"), "AUTHENTICATED RESTORE BYTES");
    assert.equal(f.getPushed(), 0, "the existing signed outbound digest gate MUST stay effective");
    assert.equal(f.engine.snapshot.files["document.txt"], undefined, "no corrupt snapshot entry is persisted");
  } finally {
    if (originalFd) await originalFd.close();
    if (foreignFd) await foreignFd.close();
  }
});

test("GREEN: in-place modification of temporary bytes (r+) preserving dev/ino/nlink is rejected fail-closed with restore_local_conflict and persists zero snapshot/outbox", async (t) => {
  const f = await signedRestoreFixture(t);
  const target = path.join(f.local, "document.txt");
  const originalLink = fsp.link;
  let triggered = false;
  try {
    fsp.link = async (from, to, ...rest) => {
      if (to === target && from.includes(".tmp-")) {
        triggered = true;
        const handle = await fsp.open(from, "r+");
        try {
          await handle.write(Buffer.from("CORRUPTED SAME-INODE IN-PLACE BYTES"), 0);
          await handle.sync();
        } finally {
          await handle.close();
        }
      }
      return originalLink(from, to, ...rest);
    };
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_local_conflict");
  } finally {
    fsp.link = originalLink;
  }
  assert.equal(triggered, true, "the in-place modification interceptor was exercised");
  assert.equal(f.getPushed(), 0, "persists zero outbox pushes");
  assert.equal(f.engine.snapshot.files["document.txt"], undefined, "persists zero snapshot entries");
  assert.equal((await f.engine.journal.recover()).length, 0, "zero journal outbox persisted");
});

test("GREEN: requireNativeRootSession option fails closed before mutable-path publication", async (t) => {
  const f = await signedRestoreFixture(t);
  f.engine.options.requireNativeRootSession = true;
  let linkAttempted = false;
  const originalLink = fsp.link;
  try {
    fsp.link = async (...args) => {
      linkAttempted = true;
      return originalLink(...args);
    };
    await assert.rejects(f.engine.restoreHistoricalVersion("file-1", "first"),
      (error) => error.code === "restore_local_conflict");
    assert.equal(linkAttempted, false, "mutable-path link must not be attempted when requireNativeRootSession is set");
    assert.equal(f.getPushed(), 0, "zero pushes");
  } finally {
    fsp.link = originalLink;
  }
});
