"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { Zk1DurableWitnessLedger } = require("../src/services/zk1DurableWitnessLedger");
const { Zk1DurableContentInventoryLedger } = require("../src/services/zk1DurableContentInventoryLedger");
const { Zk1WitnessCasAnchorFloor } = require("../src/services/zk1WitnessCasAnchorFloor");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-sqlite-trust-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const foreign = path.join(root, "foreign");
  const alias = path.join(root, "alias");
  fs.mkdirSync(foreign, { mode: 0o700 });
  fs.symlinkSync(foreign, alias, process.platform === "win32" ? "junction" : "dir");
  const status = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  return { root, foreign, alias, status, witness, witnessKeyId, statusKeyId };
}

test("witness bootstrap refuses a redirected ancestor before creating its database", (t) => {
  const f = fixture(t);
  assert.throws(() => new Zk1DurableWitnessLedger(path.join(f.alias, "witness.sqlite"), {
    bootstrapNew: true, witnessKeyId: f.witnessKeyId,
    witnessPrivateKey: f.witness.privateKey,
    statusPinned: { keyId: f.statusKeyId, publicKey: f.status.publicKey },
    statusProvider: { getTerminalProof: async () => { throw Error("UNUSED"); } },
  }), /WITNESS_STATE_MISSING/);
  assert.equal(fs.existsSync(path.join(f.foreign, "witness.sqlite")), false);
});

test("inventory bootstrap refuses a redirected ancestor before creating its database", async (t) => {
  const f = fixture(t);
  await assert.rejects(Zk1DurableContentInventoryLedger.open(path.join(f.alias, "inventory.sqlite"), {
    bootstrapNew: true,
    signerKeyId: f.witnessKeyId, signerPrivateKey: f.witness.privateKey,
    scope: { account_id: crypto.randomBytes(16),
      compartment_id: Buffer.from("private"), keyring_id: crypto.randomBytes(16) },
  }), /INVENTORY_STATE/);
  assert.equal(fs.existsSync(path.join(f.foreign, "inventory.sqlite")), false);
});

test("independent witness floor bootstrap refuses a redirected ancestor", (t) => {
  const f = fixture(t);
  assert.throws(() => new Zk1WitnessCasAnchorFloor(path.join(f.alias, "floor.sqlite"), {
    bootstrapNew: true,
    witnessKeyId: f.witnessKeyId, witnessPrivateKey: f.witness.privateKey,
    statusKeyId: f.statusKeyId, statusPublicKey: f.status.publicKey,
  }), /WITNESS_CAS_FLOOR_DENIED/);
  assert.equal(fs.existsSync(path.join(f.foreign, "floor.sqlite")), false);
});

test("witness bootstrap refuses a writable SQLite parent on Unix", (t) => {
  if (process.platform === "win32") return t.skip("Windows ACLs require separate verification");
  const f = fixture(t);
  fs.chmodSync(f.foreign, 0o777);
  assert.throws(() => new Zk1DurableWitnessLedger(path.join(f.foreign, "witness.sqlite"), {
    bootstrapNew: true, witnessKeyId: f.witnessKeyId,
    witnessPrivateKey: f.witness.privateKey,
    statusPinned: { keyId: f.statusKeyId, publicKey: f.status.publicKey },
    statusProvider: { getTerminalProof: async () => { throw Error("UNUSED"); } },
  }), /WITNESS_STATE_MISSING/);
  assert.equal(fs.existsSync(path.join(f.foreign, "witness.sqlite")), false);
});
