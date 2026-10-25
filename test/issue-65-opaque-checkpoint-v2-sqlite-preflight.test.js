"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const { OpaqueCheckpointV2Authority } =
  require("../src/services/zk1OpaqueCheckpointV2Remote");
const { Zk1OpaqueCatalogCheckpointV2Stage } =
  require("../src/services/zk1OpaqueCatalogCheckpointV2Stage");
const { createZk1OpaqueCatalogIndependentFloorHttpsClient } =
  require("../src/services/zk1OpaqueCatalogIndependentFloor");
const { privateAuthorityDirectory } =
  require("./support/issue-65-private-authority-directory");

const hash = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const signingKeys = () => crypto.generateKeyPairSync("ed25519");

test("v2 authority and stage reject swapped DB, absent and forged guards without mutation", (t) => {
  const root = privateAuthorityDirectory("zk65-v2-readonly-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("readonly-preflight"),
    keyring_id: crypto.randomBytes(16) };
  const owner = signingKeys();
  const checkpoint = signingKeys();
  const cas = signingKeys();
  const floor = signingKeys();
  const witness = signingKeys();
  const baselineDigest = crypto.randomBytes(32);
  const baselineCheckpoint = crypto.randomBytes(32);
  const trust = { genesisDigest: crypto.randomBytes(32),
    pinnedWitness: { keyId: crypto.randomBytes(16), publicKey: witness.publicKey },
    minimumHead: { revision: 1, witnessSequence: 1, digest: crypto.randomBytes(32) },
    freshWitnessHead: async () => Buffer.alloc(0) };
  const signedFloor = createZk1OpaqueCatalogIndependentFloorHttpsClient({
    endpoint: "https://127.0.0.1:9443/", ca: Buffer.from("fixture"),
    clientKey: Buffer.from("fixture"), clientCert: Buffer.from("fixture"),
    serverFingerprint256: Array(32).fill("AA").join(":"),
    floorPublicKey: floor.publicKey, casSignerPublicKey: cas.publicKey,
    trustedScope: scope,
  });
  const configs = [
    ["remote-cas", OpaqueCheckpointV2Authority, {
      role: "CAS", scope, signingPrivateKey: cas.privateKey,
      casSignerPublicKey: cas.publicKey, floorSignerPublicKey: floor.publicKey,
      checkpointPublicKey: checkpoint.publicKey, ownerPublicKey: owner.publicKey,
      ownerTrust: trust, baseDigest: baselineDigest, baseCheckpoint: baselineCheckpoint,
    }, "no_transition_replace", "transitions"],
    ["remote-floor", OpaqueCheckpointV2Authority, {
      role: "FLOOR", scope, signingPrivateKey: floor.privateKey,
      casSignerPublicKey: cas.publicKey, floorSignerPublicKey: floor.publicKey,
      checkpointPublicKey: checkpoint.publicKey, ownerPublicKey: owner.publicKey,
      ownerTrust: trust, baseDigest: baselineDigest, baseCheckpoint: baselineCheckpoint,
    }, "no_transition_downgrade", "transitions"],
    ["local-stage", Zk1OpaqueCatalogCheckpointV2Stage, {
      trustedScope: scope, ownerPublicKey: owner.publicKey,
      checkpointPublicKey: checkpoint.publicKey,
      casClient: { publicKey: cas.publicKey, readHead: async () => Buffer.alloc(0) },
      floorClient: signedFloor, resolveCatalogSigner: async () => owner.publicKey,
    }, "checkpoint_stage_no_rewrite", "checkpoint_stages"],
  ];
  for (const [name, Type, opts, guardedTrigger, guardedTable] of configs) {
    t.diagnostic(`strict authority SQLite preflight ${name}`);
    const filename = path.join(root, name + ".sqlite");
    const open = (bootstrapNew, options = opts, file = filename) =>
      new Type(file, { ...options, bootstrapNew });
    const created = open(true);
    created.close();
    assert.equal(fs.existsSync(filename), true);
    const validRestart = open(false);
    validRestart.close();
    const original = fs.readFileSync(filename);
    const originalDigest = hash(filename);
    // A foreign DB with no original schema must remain byte-for-byte identical.
    const alien = path.join(root, name + "-alien.sqlite");
    const db = new Database(alien);
    db.exec("CREATE TABLE other_authority (marker TEXT); INSERT INTO other_authority VALUES ('foreign')");
    db.close();
    const foreignHash = hash(alien);
    assert.throws(() => open(false, opts, alien));
    assert.equal(hash(alien), foreignHash);
    assert.equal(fs.existsSync(alien + "-wal"), false);
    assert.equal(fs.existsSync(alien + "-shm"), false);
    // A perfectly valid schema with a wrong scope or pin also must be unchanged.
    const wrong = { ...opts };
    if (name === "local-stage") wrong.ownerPublicKey = signingKeys().publicKey;
    else wrong.ownerTrust = { ...trust, genesisDigest: crypto.randomBytes(32) };
    assert.throws(() => open(false, wrong));
    assert.equal(hash(filename), originalDigest);
    assert.equal(fs.existsSync(filename + "-wal"), false);
    assert.equal(fs.existsSync(filename + "-shm"), false);
    // Original trigger name, attached to another table: IF NOT EXISTS would
    // previously skip it, incorrectly admitting a mutable transition.
    const forged = new Database(filename);
    forged.exec("CREATE TABLE dummy_guard_target (x INTEGER)");
    forged.exec("DROP TRIGGER " + guardedTrigger);
    forged.exec("CREATE TRIGGER " + guardedTrigger
      + " BEFORE UPDATE ON dummy_guard_target BEGIN SELECT RAISE(ABORT,'NO'); END");
    forged.close();
    const forgedDigest = hash(filename);
    assert.throws(() => open(false));
    assert.equal(hash(filename), forgedDigest);
    assert.equal(fs.existsSync(filename + "-wal"), false);
    assert.equal(fs.existsSync(filename + "-shm"), false);
    // Missing guard also fails before any schema recreation.
    const missing = new Database(filename);
    missing.exec("DROP TRIGGER " + guardedTrigger);
    missing.close();
    const missingDigest = hash(filename);
    assert.throws(() => open(false));
    assert.equal(hash(filename), missingDigest);
    // Even a trigger attached to the correct table must keep the exact
    // immutable conditions and abort message, not a WHEN that never fires.
    const falseGuard = new Database(filename);
    falseGuard.exec("CREATE TRIGGER " + guardedTrigger + " BEFORE UPDATE ON "
      + guardedTable + " WHEN 0 BEGIN SELECT RAISE(ABORT,'NO'); END");
    falseGuard.close();
    const falseGuardDigest = hash(filename);
    assert.throws(() => open(false));
    assert.equal(hash(filename), falseGuardDigest);
    // Original bytes restored; valid restart should still work.
    fs.writeFileSync(filename, original);
    const reopened = open(false);
    reopened.close();
    const sentinel = path.join(root, name + "-sentinel.bin");
    fs.writeFileSync(sentinel, crypto.randomBytes(128));
    const sentinelHash = hash(sentinel);
    fs.linkSync(sentinel, filename + "-shm");
    assert.throws(() => open(false), "foreign hard-linked SHM sidecar rejected");
    assert.equal(hash(sentinel), sentinelHash);
    fs.unlinkSync(filename + "-shm");
    // The file itself is regular, but a junction/symlink in the parent path
    // must be refused even when the referenced DB is otherwise valid.
    const real = path.join(root, name + "-real");
    const alias = path.join(root, name + "-alias");
    fs.mkdirSync(real, { mode: 0o700 });
    fs.copyFileSync(filename, path.join(real, "database.sqlite"));
    let aliasCreated = false;
    try {
      fs.symlinkSync(real, alias, process.platform === "win32" ? "junction" : "dir");
      aliasCreated = true;
      const expectedHash = hash(path.join(real, "database.sqlite"));
      assert.throws(() => open(false, opts, path.join(alias, "database.sqlite")));
      assert.equal(hash(path.join(real, "database.sqlite")), expectedHash);
    } catch (error) {
      if (!["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) throw error;
      t.diagnostic(name + ": junction unavailable: " + error.code);
    } finally {
      // Windows authority ACL preflight scans the entire staging tree. Leaving
      // our deliberately hostile junction installed would (correctly) reject
      // every subsequent fixture, not just the attempted alias access.
      if (aliasCreated) {
        assert.equal(fs.lstatSync(alias).isSymbolicLink(), true);
        if (process.platform === "win32") fs.rmdirSync(alias);
        else fs.unlinkSync(alias);
      }
    }
    t.diagnostic(name + ": wrong identity, forged/missing trigger, ancestor symlink and restart passed");
  }
});
