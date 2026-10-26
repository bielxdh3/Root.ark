"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const { Zk1OpaqueCatalogCheckpointV2Stage } =
  require("../src/services/zk1OpaqueCatalogCheckpointV2Stage");
const { createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");

function hash(filename) {
  return crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
}

test("stage rejects single-link SQLite swap after exclusive create, before WAL/schema writes", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-stage-fd-race-"));
  if (process.platform !== "win32") fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const target = path.join(root, "stage.sqlite");
  const foreign = path.join(root, "foreign.sqlite");
  const original = path.join(root, "original-created.sqlite");
  const external = new Database(foreign);
  external.exec("CREATE TABLE foreign_identity (value TEXT NOT NULL);");
  external.prepare("INSERT INTO foreign_identity (value) VALUES (?)").run("untouched");
  external.close();
  if (process.platform !== "win32") fs.chmodSync(foreign, 0o600);
  const untouchedHash = hash(foreign);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("stage-single-link-swap"), keyring_id: crypto.randomBytes(16) };
  const owner = crypto.generateKeyPairSync("ed25519");
  const checkpoint = crypto.generateKeyPairSync("ed25519");
  const cas = crypto.generateKeyPairSync("ed25519");
  const floor = crypto.generateKeyPairSync("ed25519");
  const floorClient = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: "https://127.0.0.1:9443/", ca: Buffer.from("fixture"),
    clientKey: Buffer.from("fixture"), clientCert: Buffer.from("fixture"),
    serverFingerprint256: Array(32).fill("AA").join(":"),
    floorPublicKey: floor.publicKey, casSignerPublicKey: cas.publicKey,
    trustedScope: scope,
  });
  const realOpen = fs.openSync;
  const realClose = fs.closeSync;
  let createdHandle;
  let attacked = false;
  fs.openSync = function (name, flags, ...args) {
    const fd = realOpen.call(fs, name, flags, ...args);
    if (name === target && (flags & fs.constants.O_EXCL) !== 0) createdHandle = fd;
    return fd;
  };
  fs.closeSync = function (fd, ...args) {
    const result = realClose.call(fs, fd, ...args);
    if (fd === createdHandle && !attacked) {
      attacked = true;
      fs.renameSync(target, original);
      fs.renameSync(foreign, target); // regular file, one link: no hardlink rejection shortcut
      assert.equal(fs.statSync(target).nlink, 1);
    }
    return result;
  };
  let stage;
  let rejected;
  try {
    stage = new Zk1OpaqueCatalogCheckpointV2Stage(target, {
      bootstrapNew: true, trustedScope: scope,
      ownerPublicKey: owner.publicKey, checkpointPublicKey: checkpoint.publicKey,
      casClient: { publicKey: cas.publicKey, readHead: async () => Buffer.alloc(0) },
      floorClient, resolveCatalogSigner: async () => owner.publicKey,
    });
  } catch (error) { rejected = error; }
  finally {
    fs.openSync = realOpen;
    fs.closeSync = realClose;
    stage?.close();
  }
  assert.equal(attacked, true, "single-link malicious rename must really happen");
  assert.equal(hash(target), untouchedHash,
    "must not mutate foreign SQLite after fileCheck's exclusive handle was swapped");
  assert.equal(fs.existsSync(target + "-wal"), false);
  assert.equal(fs.existsSync(target + "-shm"), false);
  const check = new Database(target, { readonly: true, fileMustExist: true });
  try {
    assert.deepEqual(check.prepare("SELECT name FROM sqlite_master WHERE type='table'").all(),
      [{ name: "foreign_identity" }]);
  } finally { check.close(); }
  assert.match(rejected?.message || "", /ZK_OPAQUE_CHECKPOINT_STAGE_DENIED/,
    "reject substitution rather than pinning a foreign inode after exclusive close");
});
