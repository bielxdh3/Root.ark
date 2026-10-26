"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const { OpaqueCheckpointV2Authority } =
  require("../src/services/zk1OpaqueCheckpointV2Remote");
const { privateAuthorityDirectory } =
  require("./support/issue-65-private-authority-directory");

function digest(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

for (const role of ["CAS", "FLOOR"]) {
  test(`v2 remote ${role} denies single-link SQLite replacement after O_EXCL close`, (t) => {
    const root = privateAuthorityDirectory("zk65-v2-remote-fd-swap-");
    if (process.platform !== "win32") fs.chmodSync(root, 0o700);
    t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
    const filename = path.join(root, "authority.sqlite");
    const foreign = path.join(root, "external.sqlite");
    const original = path.join(root, "exclusive-original.sqlite");
    const db = new Database(foreign);
    db.exec("CREATE TABLE foreign_identity (id INTEGER PRIMARY KEY, marker TEXT)");
    db.prepare("INSERT INTO foreign_identity VALUES (1, 'unchanged')").run();
    db.close();
    if (process.platform !== "win32") fs.chmodSync(foreign, 0o600);
    const expectedHash = digest(foreign);

    const keys = Array.from({ length: 5 }, () => crypto.generateKeyPairSync("ed25519"));
    const [cas, floor, checkpoint, owner, witness] = keys;
    const scope = { account_id: crypto.randomBytes(16),
      compartment_id: Buffer.from("v2-remote-fd-swap"), keyring_id: crypto.randomBytes(16) };
    const trust = { genesisDigest: crypto.randomBytes(32),
      pinnedWitness: { keyId: crypto.randomBytes(16), publicKey: witness.publicKey },
      minimumHead: { revision: 1, witnessSequence: 1, digest: crypto.randomBytes(32) },
      freshWitnessHead: async () => Buffer.alloc(0) };
    const opts = { role, bootstrapNew: true, scope,
      signingPrivateKey: (role === "CAS" ? cas : floor).privateKey,
      casSignerPublicKey: cas.publicKey, floorSignerPublicKey: floor.publicKey,
      checkpointPublicKey: checkpoint.publicKey, ownerPublicKey: owner.publicKey,
      ownerTrust: trust, baseDigest: crypto.randomBytes(32),
      baseCheckpoint: crypto.randomBytes(32) };

    const open = fs.openSync;
    const close = fs.closeSync;
    let exclusiveFd;
    let swapped = false;
    fs.openSync = function (name, flags, ...args) {
      const fd = open.call(fs, name, flags, ...args);
      if (name === filename && (flags & fs.constants.O_EXCL)) exclusiveFd = fd;
      return fd;
    };
    fs.closeSync = function (fd, ...args) {
      const result = close.call(fs, fd, ...args);
      if (fd === exclusiveFd && !swapped) {
        swapped = true;
        fs.renameSync(filename, original);
        fs.renameSync(foreign, filename); // single link, not caught by hardlink guards
        assert.equal(fs.statSync(filename).nlink, 1);
      }
      return result;
    };
    let authority;
    let denied;
    try {
      authority = new OpaqueCheckpointV2Authority(filename, opts);
    } catch (error) { denied = error; }
    finally {
      fs.openSync = open;
      fs.closeSync = close;
      authority?.close();
    }
    assert.equal(swapped, true, "actual attacker rename must happen on exclusive descriptor close");
    assert.equal(digest(filename), expectedHash,
      "the foreign database must remain byte-for-byte untouched by WAL/schema");
    assert.equal(fs.existsSync(filename + "-wal"), false);
    assert.equal(fs.existsSync(filename + "-shm"), false);
    const foreignDb = new Database(filename, { readonly: true, fileMustExist: true });
    try {
      assert.deepEqual(foreignDb.prepare("SELECT name FROM sqlite_master WHERE type='table'").all(),
        [{ name: "foreign_identity" }]);
    } finally { foreignDb.close(); }
    assert.match(denied?.message || "", /ZK_CHECKPOINT_V2_UNAVAILABLE/,
      "identity must be bound to original exclusive file, not post-close pathname");
  });
}
