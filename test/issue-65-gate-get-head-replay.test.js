"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");

// Deterministic restricted-PG transaction double. It holds the same head
// tuple across an admission's exact replay, then simulates a trusted authority
// head replacement without a generation advance (e.g. partial recovery).
// The GET worker must not treat its old admission as a new read grant.
function fixture() {
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(9), keyring_id: crypto.randomBytes(16) };
  const io = { scope, workerId: crypto.randomBytes(16), principal: "test-supervisor",
    action: "get", objectId: crypto.randomBytes(16).toString("base64url"),
    revision: 7, digest: crypto.randomBytes(32) };
  const head = { keyring_id: Buffer.from(scope.keyring_id), phase: "OPEN",
    require_stop_proof: false, revision: io.revision,
    digest: Buffer.from(io.digest), generation: 1 };
  let existing;
  const history = [];
  const pool = { async connect() { return {
    async query(sql, params = []) {
      history.push(sql.trim().split(/\s+/).slice(0, 4).join(" "));
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(sql)) return { rows: [], rowCount: 0 };
      if (sql.startsWith("SELECT * FROM zk1_gate.head")) {
        return { rows: [{ ...head, keyring_id: Buffer.from(head.keyring_id),
          digest: Buffer.from(head.digest) }], rowCount: 1 };
      }
      if (sql.startsWith("SELECT * FROM zk1_gate.admission")) {
        return { rows: existing ? [{ ...existing }] : [], rowCount: existing ? 1 : 0 };
      }
      if (sql.includes("INSERT INTO zk1_gate.admission")) {
        assert.equal(existing, undefined);
        existing = { id: Buffer.from(params[0]), scope_key: params[1],
          worker_id: Buffer.from(params[2]), principal: params[3], action: params[4],
          object_id: params[5], revision: params[6], digest: Buffer.from(params[7]),
          generation: params[8], state: "ACTIVE" };
        return { rows: [], rowCount: 1 };
      }
      throw new Error(`UNEXPECTED_SQL ${sql}`);
    }, release() {},
  }; } };
  return { io, head, history, gate: new Zk1SharedPgGateAuthority({ pool }) };
}

test("an admitted GET cannot replay across a same-generation signed head revision or digest replacement", async () => {
  const f = fixture();
  const first = await f.gate.beginIoAdmission(f.io);
  assert.equal(first.proceed, true);
  assert.deepEqual(await f.gate.beginIoAdmission(f.io), first,
    "lost admission ACK may retry while authority is unchanged");

  f.head.revision = f.io.revision + 1;
  await assert.rejects(f.gate.beginIoAdmission(f.io), /ZK_GATE_DENIED/,
    "a stale worker cannot send GET bytes after the trusted manifest revision changes");
  f.head.revision = f.io.revision;
  f.head.digest = crypto.randomBytes(32);
  await assert.rejects(f.gate.beginIoAdmission(f.io), /ZK_GATE_DENIED/,
    "same-generation digest replacement must also revoke the previous GET admission");
  assert.equal(f.history.filter((command) => command.startsWith("INSERT INTO zk1_gate.admission")).length, 1,
    "replay must never issue a second admission");
});

test("quiescing and stale generation never reenable old GET admission", async () => {
  const f = fixture();
  await f.gate.beginIoAdmission(f.io);
  f.head.phase = "QUIESCING";
  assert.equal((await f.gate.beginIoAdmission(f.io)).proceed, false);
  f.head.phase = "OPEN";
  f.head.generation += 1;
  assert.equal((await f.gate.beginIoAdmission(f.io)).proceed, false);
});
