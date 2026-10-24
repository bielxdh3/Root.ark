"use strict";

// Fail-closed *reference* coordinator across an isolated shared PG write gate
// and the existing independently-pinned witness. PG is closed FIRST; only a
// matching drained local witness and PG gate can attempt a signed reservation.
// This is NOT atomic two-phase commit or the normative distributed ZK1 gate.
const crypto = require("node:crypto");
const { inspectVerifiedWitnessReservationV1 } =
  require("../crypto/rootark-zk-witness-operation-wire-v1");

const REQUIRED = ["account_id", "compartment_id", "keyring_id",
  "reservation_id", "operation_id", "expected_revision", "expected_manifest_digest",
  "proposed_revision", "proposed_manifest_digest", "request_digest",
  "package_envelope_digest", "expires_at"];
function fail() {
  const error = new Error("ZK_GATE_COORDINATION_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function bytes(v, min, max = min) {
  if ((!Buffer.isBuffer(v) && !(v instanceof Uint8Array))
    || v.length < min || v.length > max) fail();
  return Buffer.from(v);
}
function snapshot(operation) {
  if (!operation || typeof operation !== "object" || Array.isArray(operation)
    || Reflect.ownKeys(operation).length !== REQUIRED.length
    || REQUIRED.some((name) => !Object.hasOwn(operation, name))) fail();
  const output = {
    account_id: bytes(operation.account_id, 16),
    compartment_id: bytes(operation.compartment_id, 1, 128),
    keyring_id: bytes(operation.keyring_id, 16),
    reservation_id: bytes(operation.reservation_id, 16),
    operation_id: bytes(operation.operation_id, 16),
    expected_revision: operation.expected_revision,
    expected_manifest_digest: bytes(operation.expected_manifest_digest, 32),
    proposed_revision: operation.proposed_revision,
    proposed_manifest_digest: bytes(operation.proposed_manifest_digest, 32),
    request_digest: bytes(operation.request_digest, 32),
    package_envelope_digest: operation.package_envelope_digest === null
      ? null : bytes(operation.package_envelope_digest, 32),
    expires_at: operation.expires_at,
  };
  if (!Number.isSafeInteger(output.expected_revision) || output.expected_revision < 1
    || !Number.isSafeInteger(output.proposed_revision)
    || output.proposed_revision !== output.expected_revision + 1
    || !Number.isSafeInteger(output.expires_at) || output.expires_at < 1) fail();
  return output;
}
class Zk1SharedGateWitnessCoordinator {
  constructor({ gate, witness, witnessPinned, verifyOwnerIntent,
    nowSeconds = () => Math.floor(Date.now() / 1000) }) {
    if (!gate || !witness || !witnessPinned
      || typeof gate.beginQuiesce !== "function"
      || typeof gate.markPending !== "function"
      || typeof witness.prepareQuiesce !== "function"
      || typeof witness.reserve !== "function"
      || !(witnessPinned.publicKey instanceof crypto.KeyObject)
      || witnessPinned.publicKey.type !== "public"
      || witnessPinned.publicKey.asymmetricKeyType !== "ed25519"
      || typeof verifyOwnerIntent !== "function"
      || typeof nowSeconds !== "function") fail();
    this.gate = gate;
    this.witness = witness;
    this.pinned = { keyId: bytes(witnessPinned.keyId, 16),
      publicKey: witnessPinned.publicKey };
    this.verifyOwnerIntent = verifyOwnerIntent;
    this.nowSeconds = nowSeconds;
  }

  async reserveAfterDrain({ operation, ownerAuthorization }) {
    const op = snapshot(operation);
    try {
      const now = this.nowSeconds();
      // Never close the gate for a knowingly expired/implausibly future
      // request. Once closed, an uncertain remote operation stays closed.
      if (!Number.isSafeInteger(now) || op.expires_at <= now
        || op.expires_at - now > 360) fail();
      // This verifier is provided by a separately trusted owner/device
      // authorization context; it cannot be self-reported by an HTTP client.
      // Owner-verification callbacks are independently trusted, but must not
      // be able to change the authoritative request after checking it. Typed
      // arrays remain mutable even when their containing object is frozen.
      const intentView = snapshot(op);
      const owner = await this.verifyOwnerIntent({ operation: intentView, ownerAuthorization });
      if (owner !== true || REQUIRED.some((field) => {
        const before = op[field];
        const after = intentView[field];
        return Buffer.isBuffer(before)
          ? !Buffer.isBuffer(after) || !before.equals(after)
          : before !== after;
      })) fail();
      // Every independently operated adapter receives fresh byte copies.
      // Neither the gate client nor the witness client may mutate the exact
      // owner-approved operation after an await and change its meaning.
      const scope = () => ({ account_id: Buffer.from(op.account_id),
        compartment_id: Buffer.from(op.compartment_id),
        keyring_id: Buffer.from(op.keyring_id) });
      // FIRST, durable physical PG generation fence. If any later call fails
      // this scope stays blocked, including after process restart/retry.
      const pg = await this.gate.beginQuiesce({ scope: scope(),
        operationId: Buffer.from(op.operation_id), reservationId: Buffer.from(op.reservation_id),
        revision: op.expected_revision, digest: Buffer.from(op.expected_manifest_digest) });
      if (!pg || !["QUIESCING", "PENDING"].includes(pg.state)
        || !Number.isSafeInteger(pg.activeCount) || pg.activeCount < 0) fail();
      if (pg.state === "QUIESCING") {
        const local = await this.witness.prepareQuiesce({ operation: snapshot(op) });
        if (!local || !["QUIESCING", "DRAINED"].includes(local.status)
          || !Number.isSafeInteger(local.activeCount) || local.activeCount < 0) fail();
        // A zero count is not a durable STOP acknowledgment. The independent
        // witness must explicitly report DRAINED, not merely QUIESCING/0;
        // otherwise a stale or inconsistent adapter could issue a ticket
        // before that authority has completed its own stop protocol.
        if (pg.activeCount !== 0 || local.activeCount !== 0
          || local.status !== "DRAINED") {
          return { status: "QUIESCING", pgActive: pg.activeCount,
            witnessActive: local.activeCount, generation: pg.generation };
        }
      } else if (pg.activeCount !== 0) fail();
      const beforePending = this.nowSeconds();
      if (!Number.isSafeInteger(beforePending) || op.expires_at <= beforePending
        || op.expires_at - beforePending > 360) fail();
      const pending = await this.gate.markPending({ scope: scope(),
        operationId: Buffer.from(op.operation_id),
        reservationId: Buffer.from(op.reservation_id) });
      if (pending?.status !== "PENDING" || pending.generation !== pg.generation) fail();
      const raw = await this.witness.reserve({ operation: snapshot(op) });
      const reservation = bytes(raw, 1, 8192);
      await inspectVerifiedWitnessReservationV1({ raw: reservation, operation: snapshot(op),
        pinned: this.pinned });
      const afterVerification = this.nowSeconds();
      if (!Number.isSafeInteger(afterVerification)
        || afterVerification < now || afterVerification >= op.expires_at) fail();
      return { status: "PENDING", generation: pending.generation,
        reservation };
    } catch (_) { fail(); }
  }
}
module.exports = { Zk1SharedGateWitnessCoordinator };
