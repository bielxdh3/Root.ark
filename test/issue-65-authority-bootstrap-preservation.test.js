"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const Database = require("better-sqlite3");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { Zk1DurableCasStatusLedger } = require("../src/services/zk1DurableCasStatusLedger");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");

function testDirectory(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk1-authority-bootstrap-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true,
    maxRetries: 10, retryDelay: 100 }));
  return dir;
}
function createForeign(filename) {
  const db = new Database(filename);
  db.exec("CREATE TABLE private_fixture (value TEXT NOT NULL)");
  db.prepare("INSERT INTO private_fixture(value) VALUES(?)").run("must-not-change");
  db.close();
}
function hash(filename) {
  return crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
}
function runAfterExclusiveCloseSwap(target, foreign, run) {
  const originalClose = fs.closeSync;
  let swapped = false;
  const orphan = target + ".orphaned-exclusive-fixture";
  try {
    fs.closeSync = (fd) => {
      originalClose(fd);
      if (!swapped && fs.existsSync(target)) {
        fs.renameSync(target, orphan);
        fs.renameSync(foreign, target);
        swapped = true;
      }
    };
    run();
  } finally { fs.closeSync = originalClose; }
  assert.equal(swapped, true, "the adversarial replacement must have happened");
}

test("witness rejects an unrelated SQLite file without modifying rows or schema", (t) => {
  const dir = testDirectory(t);
  const witness = crypto.generateKeyPairSync("ed25519");
  const cas = crypto.generateKeyPairSync("ed25519");
  const options = { bootstrapNew: false, witnessKeyId: crypto.randomBytes(16),
    witnessPrivateKey: witness.privateKey,
    statusPinned: { keyId: crypto.randomBytes(16), publicKey: cas.publicKey },
    statusProvider: { getTerminalProof: async () => { throw Error("not called"); } },
  };
  const foreign = path.join(dir, "foreign-witness.sqlite");
  createForeign(foreign);
  const before = hash(foreign);
  assert.throws(() => new Zk1DurableWitnessLedger(foreign, options), /WITNESS_STATE_MISSING/);
  assert.equal(hash(foreign), before);
  const replacement = path.join(dir, "raced-witness.sqlite");
  const racedSource = path.join(dir, "source-witness.sqlite");
  createForeign(racedSource);
  const racedBefore = hash(racedSource);
  runAfterExclusiveCloseSwap(replacement, racedSource, () => {
    assert.throws(() => new Zk1DurableWitnessLedger(replacement,
      { ...options, bootstrapNew: true }), /WITNESS_STATE_MISSING/);
  });
  assert.equal(hash(replacement), racedBefore,
    "exclusive creation must not accept a replacement foreign witness database");
});

test("CAS validates SQLite and its anchor before mutations; rejects exclusive-create swap", (t) => {
  const dir = testDirectory(t);
  const witness = crypto.generateKeyPairSync("ed25519");
  const cas = crypto.generateKeyPairSync("ed25519");
  const options = { bootstrapNew: false, statusKeyId: crypto.randomBytes(16),
    statusPrivateKey: cas.privateKey,
    witnessPinned: { keyId: crypto.randomBytes(16), publicKey: witness.publicKey },
    anchorPath: path.join(dir, "foreign-anchor.log"),
  };
  const foreign = path.join(dir, "foreign-cas.sqlite");
  createForeign(foreign);
  new Zk1CasTerminalAnchor(options.anchorPath, {
    bootstrapNew: true, statusKeyId: options.statusKeyId,
    statusPrivateKey: options.statusPrivateKey,
  });
  const before = hash(foreign);
  const anchorBefore = hash(options.anchorPath);
  assert.throws(() => new Zk1DurableCasStatusLedger(foreign, options), /CAS_STATE_MISSING/);
  assert.equal(hash(foreign), before);
  assert.equal(hash(options.anchorPath), anchorBefore);
  const replacement = path.join(dir, "raced-cas.sqlite");
  const racedSource = path.join(dir, "source-cas.sqlite");
  createForeign(racedSource);
  const racedBefore = hash(racedSource);
  runAfterExclusiveCloseSwap(replacement, racedSource, () => {
    assert.throws(() => new Zk1DurableCasStatusLedger(replacement, {
      ...options, anchorPath: path.join(dir, "raced-cas-anchor.log"),
      bootstrapNew: true,
    }), /CAS_STATE_MISSING/);
  });
  assert.equal(hash(replacement), racedBefore,
    "exclusive creation must not accept a replacement foreign CAS database");
});
