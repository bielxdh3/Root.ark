"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Zk1CasTerminalAnchor } = require("../src/services/zk1CasTerminalAnchor");
const { Zk1WitnessCasAnchorFloor } = require("../src/services/zk1WitnessCasAnchorFloor");

const nonce = () => crypto.randomBytes(32);
function make(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-witness-floor-"));
  const openFloors = new Set();
  t.after(() => {
    for (const floor of openFloors) floor.close();
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const status = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const statusKeyId = crypto.randomBytes(16);
  const witnessKeyId = crypto.randomBytes(16);
  const scope = { account_id: crypto.randomBytes(16), compartment_id: Buffer.from("test"),
    keyring_id: crypto.randomBytes(16) };
  const casPath = path.join(directory, "cas-anchor.log");
  const witnessPath = path.join(directory, "independent-witness-floor.sqlite");
  const anchorOptions = { bootstrapNew: true,
    statusKeyId, statusPrivateKey: status.privateKey };
  const floorOptions = { bootstrapNew: true, witnessKeyId,
    witnessPrivateKey: witness.privateKey, statusKeyId,
    statusPublicKey: status.publicKey };
  const anchor = new Zk1CasTerminalAnchor(casPath, anchorOptions);
  const floor = new Zk1WitnessCasAnchorFloor(witnessPath, floorOptions);
  openFloors.add(floor);
  async function append(to = anchor) {
    const query = { ...scope, reservation_id: crypto.randomBytes(16) };
    const receipt = crypto.randomBytes(100);
    const manifest = crypto.randomBytes(120);
    to.prepare(query, receipt, "committed", manifest);
    await to.append(query, receipt, "committed", manifest, crypto.randomBytes(64));
    return fs.readFileSync(to.filename, "utf8").trimEnd().split("\n").at(-1);
  }
  return { anchor, floor, openFloors, casPath, witnessPath, anchorOptions, floorOptions,
    append, status, witness };
}

test("witness-owned full-sync floor accepts only contiguous genuine CAS signed terminal records; ACK replay exact", async (t) => {
  const f = make(t);
  const n = nonce();
  const genesis = f.floor.freshHead({ nonce: n });
  assert.equal(genesis.sequence, 0);
  assert.equal(genesis.nonce, n.toString("base64url"));
  assert.match(genesis.signature, /^[A-Za-z0-9_-]{86}$/);
  const one = await f.append();
  const two = await f.append();
  await assert.rejects(async () => f.floor.advance({ records: [two] }), /WITNESS_CAS_FLOOR_DENIED/,
    "cannot skip predecessor despite valid Ed25519 signature");
  assert.throws(() => f.floor.advance({ records: [one, one] }),
    /WITNESS_CAS_FLOOR_DENIED/,
    "one request cannot duplicate a new event and desynchronize the pinned digest");
  assert.equal(f.floor.head().sequence, 0);
  assert.equal(f.floor.advance({ records: [one] }).sequence, 1);
  assert.equal(f.floor.advance({ records: [one] }).sequence, 1,
    "retry after lost response reuses exact durable outcome");
  const actual = f.floor.advance({ records: [one, two] });
  assert.equal(actual.sequence, 2);
  assert.equal(actual.lastHash, f.anchor.headCheckpoint().lastHash);
  const signed = f.floor.freshHead({ nonce: n });
  const { signature, ...unsigned } = signed;
  assert.equal(crypto.verify(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/witness-cas-anchor-floor/v1\0"),
    Buffer.from(JSON.stringify(unsigned)),
  ]), f.witness.publicKey, Buffer.from(signature, "base64url")), true);
  f.floor.close();
  const reopened = new Zk1WitnessCasAnchorFloor(f.witnessPath,
    { ...f.floorOptions, bootstrapNew: false });
  f.openFloors.add(reopened);
  assert.deepEqual(reopened.head(), actual);
  const oldSigned = fs.readFileSync(f.casPath, "utf8").split("\n").slice(0, 2).join("\n") + "\n";
  fs.writeFileSync(f.casPath, oldSigned);
  assert.throws(() => new Zk1CasTerminalAnchor(f.casPath, {
    ...f.anchorOptions, bootstrapNew: false,
    trustedMinimumHead: reopened.head(),
  }), /CAS_ANCHOR_INVALID/, "witness state survives restoration of BOTH CAS database/journal files");
});

test("witness floor refuses forged credentials, bad canonical signatures, replayed alternative fork and mutilated store", async (t) => {
  const f = make(t);
  const first = await f.append();
  const second = await f.append();
  const forged = JSON.parse(first);
  forged.ticketHash = "f".repeat(64);
  assert.throws(() => f.floor.advance({ records: [JSON.stringify(forged)] }),
    /WITNESS_CAS_FLOOR_DENIED/);
  assert.throws(() => f.floor.advance({ records: [JSON.stringify({
    ...JSON.parse(first), unexpected: true })] }), /WITNESS_CAS_FLOOR_DENIED/);
  assert.throws(() => f.floor.advance({ records: [first.replace("\"sequence\":1", "\"sequence\": 1")] }),
    /WITNESS_CAS_FLOOR_DENIED/, "noncanonical JSON cannot be used as a second hash preimage");
  f.floor.advance({ records: [first, second] });
  const forkPath = path.join(path.dirname(f.casPath), "cas-fork.log");
  fs.writeFileSync(forkPath,
    fs.readFileSync(f.casPath, "utf8").split("\n").slice(0, 2).join("\n") + "\n");
  const alternative = new Zk1CasTerminalAnchor(forkPath,
    { ...f.anchorOptions, bootstrapNew: false });
  const changed = await f.append(alternative);
  assert.throws(() => f.floor.advance({ records: [changed] }),
    /WITNESS_CAS_FLOOR_DENIED/, "a genuine same-sequence Ed25519 fork must fail");
  f.floor.close();
  assert.throws(() => new Zk1WitnessCasAnchorFloor(f.witnessPath, {
    ...f.floorOptions, bootstrapNew: false,
    statusPublicKey: crypto.generateKeyPairSync("ed25519").publicKey,
  }), /WITNESS_CAS_FLOOR_DENIED/);
  const Database = require("better-sqlite3");
  const db = new Database(f.witnessPath);
  db.prepare("UPDATE witness_cas_floor_event SET line=? WHERE sequence=2").run(first);
  db.close();
  assert.throws(() => new Zk1WitnessCasAnchorFloor(f.witnessPath, {
    ...f.floorOptions, bootstrapNew: false,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "SQL-only tampering with canonical signed events fails startup integrity verification");
});

test("witness floor refuses empty-DB bootstrap on restart and caller-controlled unsigned head", (t) => {
  const f = make(t);
  assert.throws(() => new Zk1WitnessCasAnchorFloor(f.witnessPath, f.floorOptions),
    /WITNESS_CAS_FLOOR_DENIED/);
  assert.throws(() => f.floor.advance({ records: [] }), /WITNESS_CAS_FLOOR_DENIED/);
  assert.throws(() => f.floor.advance({ records: [{ sequence: 100,
    lastHash: "0".repeat(64) }] }), /WITNESS_CAS_FLOOR_DENIED/);
  assert.deepEqual(f.floor.head(), { sequence: 0, lastHash: "0".repeat(64) });
});

test("separately owner-retained witness minimum blocks even correctly signed witness SQLite prefix rewind", async (t) => {
  const f = make(t);
  const one = await f.append();
  f.floor.advance({ records: [one] });
  const beforeSecond = f.floor.head();
  const two = await f.append();
  f.floor.advance({ records: [two] });
  const separatelyRetained = { ...f.floor.head() };
  f.floor.close();
  // A witness storage administrator can truncate to an *authentic signed*
  // earlier head; the check must not treat this as a valid latest state.
  const Database = require("better-sqlite3");
  const admin = new Database(f.witnessPath);
  admin.prepare("DELETE FROM witness_cas_floor_event WHERE sequence=2").run();
  admin.close();
  const vulnerableWithoutExternalFloor = new Zk1WitnessCasAnchorFloor(f.witnessPath,
    { ...f.floorOptions, bootstrapNew: false });
  assert.deepEqual(vulnerableWithoutExternalFloor.head(), beforeSecond,
    "this is a real, signed prefix rollback indistinguishable without a third-party minimum");
  vulnerableWithoutExternalFloor.close();
  assert.throws(() => new Zk1WitnessCasAnchorFloor(f.witnessPath, {
    ...f.floorOptions, bootstrapNew: false, trustedMinimumHead: separatelyRetained,
  }), /WITNESS_CAS_FLOOR_DENIED/,
  "external owner floor refuses a legitimate signed witness SQL prefix rollback");
  const attemptedRewind = { ...separatelyRetained };
  const ownMinimum = new Zk1WitnessCasAnchorFloor(f.witnessPath, {
    ...f.floorOptions, bootstrapNew: false, trustedMinimumHead: beforeSecond,
  });
  f.openFloors.add(ownMinimum);
  attemptedRewind.sequence = 0;
  assert.deepEqual(ownMinimum.head(), beforeSecond);
  assert.throws(() => new Zk1WitnessCasAnchorFloor(f.witnessPath, {
    ...f.floorOptions, bootstrapNew: false, trustedMinimumHead: {
      sequence: 2, lastHash: "f".repeat(64),
    },
  }), /WITNESS_CAS_FLOOR_DENIED/);
});

test("running witness refuses SQL injection and signed rollback after startup before signing a new head", async (t) => {
  const f = make(t);
  const first = await f.append();
  const next = await f.append();
  f.floor.advance({ records: [first, next] });
  const Database = require("better-sqlite3");
  const attacker = new Database(f.witnessPath);
  try {
    const originalFirst = attacker.prepare("SELECT line FROM witness_cas_floor_event WHERE sequence=1").get();
    attacker.prepare("UPDATE witness_cas_floor_event SET line=? WHERE sequence=1").run(next);
    assert.throws(() => f.floor.freshHead({ nonce: nonce() }), /WITNESS_CAS_FLOOR_DENIED/,
      "an active witness must not sign the high-water while an earlier signed row is corrupt");
    attacker.prepare("UPDATE witness_cas_floor_event SET line=? WHERE sequence=1").run(originalFirst.line);
    const legitimate = attacker.prepare("SELECT * FROM witness_cas_floor_event WHERE sequence=2").get();
    attacker.prepare("UPDATE witness_cas_floor_event SET line=? WHERE sequence=2").run(first);
    assert.throws(() => f.floor.freshHead({ nonce: nonce() }), /WITNESS_CAS_FLOOR_DENIED/,
      "an active witness must not sign a corrupt live SQLite head");
    attacker.prepare("UPDATE witness_cas_floor_event SET line=? WHERE sequence=2")
      .run(legitimate.line);
    assert.equal(f.floor.freshHead({ nonce: nonce() }).sequence, 2);
    attacker.prepare("DELETE FROM witness_cas_floor_event WHERE sequence=2").run();
    assert.throws(() => f.floor.freshHead({ nonce: nonce() }), /WITNESS_CAS_FLOOR_DENIED/,
      "even a legitimately signed old journal prefix cannot become the live witness head");
    assert.throws(() => f.floor.advance({ records: [next] }), /WITNESS_CAS_FLOOR_DENIED/,
      "an offline-SQL rollback does not self-heal through a signed duplicate append");
  } finally { attacker.close(); }
});
