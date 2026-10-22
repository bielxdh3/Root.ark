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
