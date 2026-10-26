"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cas-dir-swap-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const parent = path.join(root, "journal");
  fs.mkdirSync(parent, { mode: 0o700 });
  const filename = path.join(parent, "anchor.log");
  const anchor = new Zk1CasTerminalAnchor(filename, {
    bootstrapNew: true, statusKeyId: crypto.randomBytes(16),
    statusPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey,
  });
  function swapParent() {
    const detached = path.join(root, "detached");
    fs.renameSync(parent, detached);
    fs.symlinkSync(detached, parent, process.platform === "win32" ? "junction" : "dir");
  }
  return { root, parent, filename, anchor, swapParent };
}

function query() {
  return { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("main"),
    keyring_id: crypto.randomBytes(16), reservation_id: crypto.randomBytes(16) };
}

test("CAS journal rejects an ancestor junction/symlink even when its FD inode is unchanged", (t) => {
  const f = fixture(t);
  f.swapParent();
  assert.throws(() => f.anchor.headCheckpoint(), /CAS_ANCHOR_INVALID/);
});

test("CAS journal fails closed when its ancestor becomes a symlink between lstat and open", (t) => {
  const f = fixture(t);
  const nativeOpen = fs.openSync;
  let swapped = false;
  try {
    fs.openSync = function (name, flags) {
      if (!swapped && name === f.filename && typeof flags === "number"
        && (flags & fs.constants.O_RDONLY) === 0 && !(flags & fs.constants.O_APPEND)) {
        swapped = true;
        f.swapParent();
      }
      return nativeOpen.apply(this, arguments);
    };
    assert.throws(() => f.anchor.headCheckpoint(), /CAS_ANCHOR_INVALID/);
  } finally { fs.openSync = nativeOpen; }
  assert.equal(swapped, true);
});

test("CAS append refuses ancestor symlink substituted between lstat and append FD", async (t) => {
  const f = fixture(t);
  const originalBytes = fs.readFileSync(f.filename);
  const q = query();
  const ticket = crypto.randomBytes(80);
  const manifest = crypto.randomBytes(64);
  const seal = crypto.randomBytes(64);
  f.anchor.prepare(q, ticket, "committed", manifest);
  const nativeOpen = fs.openSync;
  let swapped = false;
  try {
    fs.openSync = function (name, flags) {
      if (!swapped && name === f.filename && typeof flags === "number"
        && (flags & fs.constants.O_APPEND)) {
        swapped = true;
        f.swapParent();
      }
      return nativeOpen.apply(this, arguments);
    };
    await assert.rejects(f.anchor.append(q, ticket, "committed", manifest, seal),
      /CAS_ANCHOR_INVALID/);
  } finally { fs.openSync = nativeOpen; }
  assert.equal(swapped, true);
  const activeFile = fs.existsSync(path.join(f.root, "detached", "anchor.log"))
    ? path.join(f.root, "detached", "anchor.log") : f.filename;
  assert.deepEqual(fs.readFileSync(activeFile), originalBytes,
    "a rejected path swap cannot append a terminal record to the relocated journal");
});

test("CAS bootstrap refuses to create its signed journal through a junction/symlink", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cas-bootstrap-link-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const target = path.join(root, "target");
  const redirected = path.join(root, "redirected");
  fs.mkdirSync(target);
  fs.symlinkSync(target, redirected, process.platform === "win32" ? "junction" : "dir");
  assert.throws(() => new Zk1CasTerminalAnchor(path.join(redirected, "anchor.log"), {
    bootstrapNew: true, statusKeyId: crypto.randomBytes(16),
    statusPrivateKey: crypto.generateKeyPairSync("ed25519").privateKey,
  }), /CAS_ANCHOR_INVALID/);
  assert.equal(fs.existsSync(path.join(target, "anchor.log")), false);
});

test("CAS journal rejects group/world-writable anchor file on Unix", (t) => {
  if (process.platform === "win32") return t.skip("Windows access control uses ACLs");
  const f = fixture(t);
  fs.chmodSync(f.filename, 0o666);
  assert.throws(() => f.anchor.headCheckpoint(), /CAS_ANCHOR_INVALID/);
});

test("CAS journal refuses a locally writable directory on Unix", (t) => {
  if (process.platform === "win32") return t.skip("Windows access control uses ACLs");
  const f = fixture(t);
  fs.chmodSync(f.parent, 0o777);
  assert.throws(() => f.anchor.headCheckpoint(), /CAS_ANCHOR_INVALID/);
});

test("CAS intent rejects oversized and hardlinked names before reading their bytes", (t) => {
  const f = fixture(t);
  const q = query();
  const intent = f.anchor.intentPath(q);
  const foreign = path.join(f.root, "attacker-file");
  fs.writeFileSync(foreign, Buffer.alloc(128 * 1024, 0x61));
  const nativeReadFile = fs.readFileSync;
  let readUnsafeName = 0;
  try {
    fs.readFileSync = function (filename) {
      if (filename === intent) readUnsafeName += 1;
      return nativeReadFile.apply(this, arguments);
    };
    fs.linkSync(foreign, intent);
    assert.throws(() => f.anchor.getIntent(q), /CAS_ANCHOR_INVALID/);
    assert.equal(readUnsafeName, 0, "hardlinked foreign data must never be loaded");
    fs.unlinkSync(intent);

    fs.writeFileSync(intent, Buffer.alloc(128 * 1024, 0x62));
    assert.throws(() => f.anchor.getIntent(q), /CAS_ANCHOR_INVALID/);
    assert.equal(readUnsafeName, 0, "oversized intent must be rejected before allocation/read");
  } finally { fs.readFileSync = nativeReadFile; }
  assert.equal(fs.statSync(foreign).size, 128 * 1024);
});

test("CAS intent reads valid signed state through its pinned file descriptor", (t) => {
  const f = fixture(t);
  const q = query();
  const ticket = crypto.randomBytes(80);
  const manifest = crypto.randomBytes(64);
  f.anchor.prepare(q, ticket, "committed", manifest);
  const verified = f.anchor.getIntent(q);
  assert.equal(verified.status, "committed");
  assert.equal(verified.reservation, q.reservation_id.toString("base64url"));
});

test("CAS intent refuses a same-size inode swapped between checking the name and opening it", (t) => {
  const f = fixture(t);
  const q = query();
  f.anchor.prepare(q, crypto.randomBytes(80), "committed", crypto.randomBytes(64));
  const intent = f.anchor.intentPath(q);
  const replacement = path.join(f.parent, "replacement-intent");
  fs.writeFileSync(replacement, fs.readFileSync(intent));
  const nativeOpen = fs.openSync;
  let swapped = false;
  try {
    fs.openSync = function (filename, flags) {
      if (!swapped && filename === intent && typeof flags === "number"
        && !(flags & fs.constants.O_APPEND)) {
        fs.renameSync(intent, `${intent}.before-race`);
        fs.renameSync(replacement, intent);
        swapped = true;
      }
      return nativeOpen.apply(this, arguments);
    };
    assert.throws(() => f.anchor.getIntent(q), /CAS_ANCHOR_INVALID/);
  } finally { fs.openSync = nativeOpen; }
  assert.equal(swapped, true, "the adversarial inode substitution must happen");
});
