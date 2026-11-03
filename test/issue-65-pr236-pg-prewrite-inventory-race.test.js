"use strict";

// Regression for a lost inventory-head race at the actual bridge boundary.
// Real FULL/WAL SQLite signed ledger; only external PG intent, sealed sink,
// and physical readback are modelled. No production DB, network or service.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const { Zk1DurableContentInventoryLedger } =
  require("../src/services/zk1DurableContentInventoryLedger");
const { Zk1PgPhysicalInventoryBridge } =
  require("../src/services/zk1PgPhysicalInventoryBridge");
const { Zk1SharedPgPhysicalInventoryIntent } =
  require("../src/services/zk1SharedPgPhysicalInventoryIntent");
const { Zk1SharedPgCiphertextSink } =
  require("../src/services/zk1SharedPgCiphertextSink");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../src/services/zk1SharedPgPhysicalCiphertextVerifier");

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function request({ scope, head, objectId, operationId, name }) {
  const chunks = [Buffer.from(`ciphertext-${name}-first`), Buffer.from(`ciphertext-${name}-last`)];
  return {
    scope,
    operation: {
      operation_id: operationId,
      expected_sequence: head.sequence,
      expected_root: Buffer.from(head.root),
      object_id: objectId,
      revision: 1,
      epoch: 1,
      ciphertext_sha256: crypto.createHash("sha256").update(Buffer.concat(chunks)).digest(),
    },
    digest: crypto.randomBytes(32),
    expectedRootHash: computeZk1CiphertextRoot(chunks),
    expectedChunkCount: chunks.length,
    chunks,
  };
}

function simulatedPgBoundary({ loserId, releaseLoser, winnerId, winnerWriting, winnerResume }) {
  const physical = new Map();
  const calls = [];
  const intentAuthority = Object.create(Zk1SharedPgPhysicalInventoryIntent.prototype);
  intentAuthority.reserveExact = async ({ operation }) => {
    const id = operation.operation_id.toString("hex");
    if (id === loserId) await releaseLoser.promise;
    calls.push({ kind: "reserve", id });
    const slot = `${operation.object_id.toString("hex")}:${operation.revision}`;
    const prior = physical.get(slot);
    if (prior && prior.id !== id) throw Error("PG_OBJECT_REVISION_ALREADY_RESERVED");
    if (!prior) physical.set(slot, { id, sealed: false });
    return { status: "IMMUTABLE_PREWRITE_INTENT", operationId: Buffer.from(operation.operation_id),
      generation: 1, replay: Boolean(prior), sealed: Boolean(prior?.sealed), authorizesIo: false };
  };
  const sink = Object.create(Zk1SharedPgCiphertextSink.prototype);
  sink.putSealed = async ({ objectId, revision, operationId, expectedChunkCount }) => {
    const id = operationId.toString("hex");
    if (winnerId && id === winnerId) {
      winnerWriting.resolve();
      await winnerResume.promise;
    }
    calls.push({ kind: "seal", id });
    const slot = `${Buffer.from(objectId, "base64url").toString("hex")}:${revision}`;
    const reserved = physical.get(slot);
    assert.equal(reserved?.id, id, "PG seal requires its matching immutable reservation");
    reserved.sealed = true;
    return { status: "SEALED", chunkCount: expectedChunkCount };
  };
  const verifier = Object.create(Zk1SharedPgPhysicalCiphertextVerifier.prototype);
  verifier.verifyExact = async ({ operationId, root, expectedRootHash, expectedSha256, objectId, revision }) => {
    const slot = `${Buffer.from(objectId, "base64url").toString("hex")}:${revision}`;
    if (!physical.get(slot)?.sealed) throw Error("PG_PHYSICAL_SEAL_MISSING");
    return { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, operationId: Buffer.from(operationId),
      root: Buffer.from(expectedRootHash || root), ciphertextSha256: Buffer.from(expectedSha256),
      authorizesIo: false };
  };
  return { physical, calls, intentAuthority, sink, verifier };
}

test("stale concurrent inventory writer must terminalize before PG reservation; rebased operation can claim its revision", { timeout: 60_000 }, async (t) => {
  const directory = createPrivateAuthorityFixture("zk65-pr236-pg-race-");
  const keys = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = crypto.randomBytes(16);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("vault"), keyring_id: crypto.randomBytes(16) };
  const ledger = await Zk1DurableContentInventoryLedger.open(path.join(directory, "inventory.sqlite"), {
    bootstrapNew: true, scope, signerKeyId, signerPrivateKey: keys.privateKey,
  });
  t.after(() => { ledger.close(); fs.rmSync(directory, { recursive: true, force: true }); });

  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const objectWinner = crypto.randomBytes(16);
  const objectLoser = crypto.randomBytes(16);
  const winner = request({ scope, head: genesis, objectId: objectWinner,
    operationId: crypto.randomBytes(16), name: "winner" });
  const loser = request({ scope, head: genesis, objectId: objectLoser,
    operationId: crypto.randomBytes(16), name: "stale-loser" });
  const loserId = loser.operation.operation_id.toString("hex");
  const winnerId = winner.operation.operation_id.toString("hex");
  const releaseLoser = deferred();
  const winnerWriting = deferred();
  const winnerResume = deferred();
  const pg = simulatedPgBoundary({ loserId, releaseLoser, winnerId,
    winnerWriting, winnerResume });
  const bridge = new Zk1PgPhysicalInventoryBridge({ ...pg,
    ledger, pinnedPublicKey: keys.publicKey, pinnedSignerKeyId: signerKeyId });

  // Both clients prepared different object writes against the SAME genesis.
  // Pin the winning writer between PG reserve and physical seal. The losing
  // request starts while the winner's logical inventory position is held,
  // rather than depending on event-loop scheduling to choose the winner.
  const winningWrite = bridge.putAndAttest(winner);
  await winnerWriting.promise;
  const losingWrite = bridge.putAndAttest(loser);
  winnerResume.resolve();
  let winningResult;
  try {
    winningResult = await winningWrite;
  } finally { releaseLoser.resolve(); }
  const losingResult = await losingWrite;
  assert.equal(winningResult.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  assert.equal(losingResult.status, "not_committed_final");
  assert.equal(losingResult.authorizesIo, false);
  const denied = await ledger.getOperationStatus(loser.operation.operation_id);
  assert.equal(denied.status, "not_committed_final", "real signed ledger must terminalize the stale operation");
  assert.ok(["EXPECTED_HEAD_CHANGED", "UNRESOLVED_PENDING"].includes(denied.reason));
  assert.equal(losingResult.reason, denied.reason);
  const terminal = await inventory.verifyTerminalProof({ serialized: denied.proof,
    pinnedPublicKey: keys.publicKey, pinnedSignerKeyId: signerKeyId,
    expectedScope: scope, operation: loser.operation });
  assert.equal(terminal.outcome, "NOT_COMMITTED_FINAL");

  // The losing operation must NOT leave a PostgreSQL intent/seal for object B
  // revision 1, otherwise a corrected, fresh-head upload is permanently stuck
  // behind the immutable physical slot of a terminally denied operation.
  const loserSlot = `${objectLoser.toString("hex")}:1`;
  assert.equal(pg.physical.has(loserSlot), false,
    "the terminally denied contender must not reserve any physical storage");
  assert.deepEqual(pg.calls.filter((entry) => entry.id === loserId), [],
    "losing operation must be denied before any PG reserve or seal call");
  const afterWinner = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const rebased = request({ scope, head: afterWinner, objectId: objectLoser,
    operationId: crypto.randomBytes(16), name: "fresh-rebase" });
  let rebasedResult;
  let rebasedError;
  try { rebasedResult = await bridge.putAndAttest(rebased); }
  catch (error) { rebasedError = error; }

  assert.ifError(rebasedError);
  assert.equal(rebasedResult.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  assert.equal(rebasedResult.sequence, 2);
  assert.equal(pg.physical.get(loserSlot)?.id, rebased.operation.operation_id.toString("hex"),
    "new operation must be able to reserve and seal the previously unoccupied object revision");
  assert.equal(pg.physical.get(loserSlot)?.sealed, true);
});

test("pinned floor survives prewrite pending, PG rejection, restart and exact retry without public pending snapshots", { timeout: 60_000 }, async (t) => {
  const directory = createPrivateAuthorityFixture("zk65-pr236-floor-race-");
  const filename = path.join(directory, "inventory.sqlite");
  const keys = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = crypto.randomBytes(16);
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("vault"), keyring_id: crypto.randomBytes(16) };
  const options = { scope, signerKeyId, signerPrivateKey: keys.privateKey };
  let ledger = await Zk1DurableContentInventoryLedger.open(filename,
    { ...options, bootstrapNew: true });
  t.after(() => { ledger.close(); fs.rmSync(directory, { recursive: true, force: true }); });
  const genesis = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  const trustedInventoryFloor = { minimumHead: { sequence: genesis.sequence,
    root: Buffer.from(genesis.root) }, minimumSnapshot: Buffer.from(genesis.bytes) };
  const operation = request({ scope, head: genesis, objectId: crypto.randomBytes(16),
    operationId: crypto.randomBytes(16), name: "pending-floor-retry" });
  const gate = deferred();
  const pg = simulatedPgBoundary({ loserId: crypto.randomBytes(16).toString("hex"),
    releaseLoser: gate });
  const originalReserve = pg.intentAuthority.reserveExact;
  let rejectedOnce = false;
  pg.intentAuthority.reserveExact = async (request) => {
    if (!rejectedOnce) { rejectedOnce = true; throw Error("PG_TRANSIENT_UNAVAILABLE"); }
    return originalReserve(request);
  };
  const makeBridge = () => new Zk1PgPhysicalInventoryBridge({ ...pg, ledger,
    pinnedPublicKey: keys.publicKey, pinnedSignerKeyId: signerKeyId,
    trustedInventoryFloor });
  await assert.rejects(makeBridge().putAndAttest(operation), /PG_TRANSIENT_UNAVAILABLE/);
  assert.equal((await ledger.getOperationStatus(operation.operation.operation_id)).status, "pending");
  assert.equal((await ledger.getSnapshot({ nonce: crypto.randomBytes(32) })).status, "pending",
    "public snapshot must not leak signed absence while any prewrite is pending");
  assert.equal((await ledger.getCommittedProofPage({ afterSequence: 0, limit: 1 })).status,
    "pending", "public chain page remains fail-closed");
  await assert.rejects(ledger.getPrewriteFloorEvidence({
    operationId: crypto.randomBytes(16), nonce: crypto.randomBytes(32), afterSequence: 0,
  }), /INVENTORY_PREWRITE_FLOOR_UNAVAILABLE/,
  "a different operation cannot borrow the pending writer's signed-prefix evidence");

  ledger.close();
  ledger = await Zk1DurableContentInventoryLedger.open(filename,
    { ...options, bootstrapNew: false });
  const result = await makeBridge().putAndAttest(operation);
  assert.equal(result.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  assert.equal(result.sequence, 1);
  assert.equal((await ledger.getOperationStatus(operation.operation.operation_id)).status, "committed");
  const visible = await ledger.getSnapshot({ nonce: crypto.randomBytes(32) });
  assert.equal(visible.status, "snapshot", "public signed view returns only after commit");
  assert.equal(visible.sequence, 1);
  const next = request({ scope, head: visible, objectId: crypto.randomBytes(16),
    operationId: crypto.randomBytes(16), name: "signed-prefix-chain" });
  assert.equal((await ledger.prepareAppend(next.operation)).status, "pending");
  const second = await makeBridge().putAndAttest(next);
  assert.equal(second.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  assert.equal(second.sequence, 2,
    "pending floor verification must include the fully signed earlier commit chain");
});
