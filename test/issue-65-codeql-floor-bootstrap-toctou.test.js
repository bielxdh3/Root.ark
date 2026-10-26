"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const { Zk1OpaqueCatalogIndependentFloorLedger } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { privateAuthorityDirectory, privateAuthorityChild } =
  require("./support/issue-65-private-authority-directory");

const sha = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

test("independent floor denies post-O_EXCL substitution before any foreign SQLite writes", (t) => {
  const root = privateAuthorityDirectory("zk1-floor-bootstrap-race-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const privateDir = privateAuthorityChild(root, "private");
  if (process.platform !== "win32") fs.chmodSync(privateDir, 0o700);
  const target = path.join(privateDir, "floor.sqlite");
  const foreign = path.join(root, "foreign.sqlite");
  const db = new Database(foreign);
  db.exec("CREATE TABLE foreign_identity (id INTEGER PRIMARY KEY, marker TEXT)");
  db.prepare("INSERT INTO foreign_identity VALUES (1, 'unchanged')").run();
  db.close();
  if (process.platform !== "win32") fs.chmodSync(foreign, 0o600);
  const originalDigest = sha(foreign);
  const keys = Array.from({ length: 3 }, () => crypto.generateKeyPairSync("ed25519"));
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("floor-bootstrap-race"), keyring_id: crypto.randomBytes(16) };
  const realOpen = fs.openSync;
  const realClose = fs.closeSync;
  let createdFd;
  let swapped = false;
  fs.openSync = function (name, flags, ...rest) {
    const fd = realOpen.call(fs, name, flags, ...rest);
    if (name === target && (flags & fs.constants.O_EXCL)) createdFd = fd;
    return fd;
  };
  fs.closeSync = function (fd, ...rest) {
    const result = realClose.call(fs, fd, ...rest);
    if (fd === createdFd && !swapped) {
      swapped = true;
      fs.renameSync(target, path.join(privateDir, "original.sqlite"));
      fs.linkSync(foreign, target);
    }
    return result;
  };
  let opened;
  let denied;
  try {
    opened = new Zk1OpaqueCatalogIndependentFloorLedger(target, {
      bootstrapNew: true, trustedScope: scope, signingPrivateKey: keys[0].privateKey,
      casSignerPublicKey: keys[1].publicKey, catalogSignerPublicKey: keys[2].publicKey,
    });
  } catch (error) { denied = error; }
  finally {
    fs.openSync = realOpen;
    fs.closeSync = realClose;
    opened?.db.close();
  }
  assert.equal(swapped, true, "the malicious replacement must occur at the real file boundary");
  assert.equal(sha(foreign), originalDigest,
    "no schema changes or SQLite WAL writes may reach a foreign database");
  const check = new Database(foreign, { readonly: true, fileMustExist: true });
  try {
    assert.deepEqual(check.prepare("SELECT name FROM sqlite_master WHERE type='table'").all(),
      [{ name: "foreign_identity" }]);
  } finally { check.close(); }
  assert.match(denied?.message || "", /ZK_OPAQUE_FLOOR_UNAVAILABLE/,
    "the floor authority must reject a different inode after exclusive creation");
});
