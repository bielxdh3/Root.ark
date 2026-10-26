"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const { once } = require("node:events");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { privateAuthorityChild } =
  require("./support/issue-65-private-authority-directory");
const { Zk1ProtectedObjectStore } =
  require("../src/services/zk1ProtectedObjectStore");

function config() {
  const { publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    witnessProvider: { freshHead: async () => { throw Error("TEST_OFFLINE"); } },
    witnessPinned: { keyId: crypto.randomBytes(16), publicKey },
    manifestProvider: async () => { throw Error("TEST_OFFLINE"); },
    trustedScope: {
      account_id: crypto.randomBytes(16), compartment_id: Buffer.from("fixture"),
      keyring_id: crypto.randomBytes(16),
    },
    minimumHead: { revision: 1, witnessSequence: 1, digest: crypto.randomBytes(32) },
  };
}

function grantUsersModify(dir) {
  const result = spawnSync("C:\\Windows\\System32\\icacls.exe",
    [dir, "/grant", "*S-1-5-32-545:(OI)(CI)(M)"],
    { encoding: "utf8", windowsHide: true });
  assert.equal(result.status, 0, "must install real Users Modify ACE on NTFS");
}

function fixture(t, prefix) {
  const root = createPrivateAuthorityFixture(prefix);
  t.after(() => fs.rmSync(root, { recursive: true, force: true,
    maxRetries: 10, retryDelay: 100 }));
  return root;
}

test("content store bootstraps and restarts with a private SQLite authority", (t) => {
  const root = fixture(t, "rootark-w38-content-private-");
  const db = path.join(root, "content.sqlite");
  const opts = config();
  const first = new Zk1ProtectedObjectStore(db, { ...opts, bootstrapNew: true });
  try { assert.equal(first.db.prepare("SELECT COUNT(*) AS n FROM zk_content_identity").get().n, 1); }
  finally { first.close(); }
  const restarted = new Zk1ProtectedObjectStore(db, opts);
  restarted.close();
});

test("Windows content bootstrap denies a real Users Modify DACL before creating SQLite", (t) => {
  if (process.platform !== "win32") return t.skip("real NTFS DACL test");
  const root = fixture(t, "rootark-w38-content-bootstrap-");
  grantUsersModify(root);
  const db = path.join(root, "content.sqlite");
  let store;
  assert.throws(() => { store = new Zk1ProtectedObjectStore(db,
    { ...config(), bootstrapNew: true }); }, /ZK_CONTENT_BOOTSTRAP_REQUIRED/);
  store?.close();
  assert.equal(fs.existsSync(db), false, "unsafe directory must remain free of SQLite authority files");
});

test("Windows content restart denies Users Modify added after a valid bootstrap", (t) => {
  if (process.platform !== "win32") return t.skip("real NTFS DACL test");
  const root = fixture(t, "rootark-w38-content-restart-");
  const db = path.join(root, "content.sqlite");
  const opts = config();
  const first = new Zk1ProtectedObjectStore(db, { ...opts, bootstrapNew: true });
  first.close();
  grantUsersModify(root);
  let second;
  assert.throws(() => { second = new Zk1ProtectedObjectStore(db, opts); },
    /ZK_CONTENT_BOOTSTRAP_REQUIRED/);
  second?.close();
  assert.equal(fs.existsSync(db), true, "denied restart must not destroy existing DB");
});

test("Windows concurrent untrusted WAL tamper cannot enter a new SQLite authority connection", async (t) => {
  if (process.platform !== "win32") return t.skip("real NTFS DACL test");
  const root = fixture(t, "rootark-w38-content-concurrent-");
  const db = path.join(root, "content.sqlite");
  const opts = config();
  const first = new Zk1ProtectedObjectStore(db, { ...opts, bootstrapNew: true });
  first.close();
  grantUsersModify(root);
  // Another process can now write the SQLite sidecar by name. Start it as a
  // separate process while the service attempts to reopen its signed ledger.
  const poisonedWal = db + "-wal";
  const attacker = spawn(process.execPath, ["-e",
    "require('node:fs').writeFileSync(process.argv[1], 'UNTRUSTED_WAL')", poisonedWal],
  { stdio: "ignore", windowsHide: true });
  const attackerExited = once(attacker, "exit");
  let reopened;
  try {
    assert.throws(() => { reopened = new Zk1ProtectedObjectStore(db, opts); },
      /ZK_CONTENT_BOOTSTRAP_REQUIRED/);
  } finally {
    reopened?.close();
    const [exitCode] = await attackerExited;
    assert.equal(exitCode, 0, "concurrent process must prove physical sidecar write");
  }
  assert.equal(fs.readFileSync(poisonedWal, "utf8"), "UNTRUSTED_WAL",
    "rejected authority must never open, truncate or delete hostile WAL");
});

test("Windows content rejects a privately owned child under an attacker-writable ancestor", (t) => {
  if (process.platform !== "win32") return t.skip("real NTFS DACL test");
  const root = fixture(t, "rootark-w38-content-ancestor-");
  const parent = privateAuthorityChild(root, "parent");
  const child = privateAuthorityChild(parent, "child");
  grantUsersModify(parent);
  const db = path.join(child, "content.sqlite");
  let store;
  assert.throws(() => { store = new Zk1ProtectedObjectStore(db,
    { ...config(), bootstrapNew: true }); }, /ZK_CONTENT_BOOTSTRAP_REQUIRED/);
  store?.close();
  assert.equal(fs.existsSync(db), false);
});
