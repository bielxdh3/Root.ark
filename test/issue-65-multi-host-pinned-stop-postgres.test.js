"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority, createZk1OperatorPinnedStopHostPolicy } =
  require("../src/services/zk1SharedPgGateAuthority");
const { Zk1IsolatedProcessStopSupervisor } =
  require("../src/services/zk1IsolatedProcessStopSupervisor");
const { Zk1SharedPgStrictStopOperator } =
  require("../src/services/zk1SharedPgStrictStopOperator");
const { createZk1PhysicalStopRecorder } =
  require("../src/services/zk1SharedPgPhysicalStopRecorder");

const urls = { admin: process.env.ROOTARK_ZK1_TEST_PG_URL,
  gate: process.env.ROOTARK_ZK1_RUNTIME_PG_URL,
  stop: process.env.ROOTARK_ZK1_STOP_PG_URL };
const random = (n) => crypto.randomBytes(n);
const newScope = () => ({ account_id: random(16), compartment_id: random(8), keyring_id: random(16) });
const keyOf = (s) => s.account_id.toString("hex") + ":" +
  s.compartment_id.length.toString(16) + ":" + s.compartment_id.toString("hex");
const signers = () => [0, 1].map(() => ({ hostKeyId: random(16),
  keys: crypto.generateKeyPairSync("ed25519") }));
const host = (identity, scopes, status = "active") => ({ hostKeyId: identity.hostKeyId,
  hostPublicKey: identity.keys.publicKey, scopes, status });
const policy = (hosts) => createZk1OperatorPinnedStopHostPolicy({ hosts });

test("pinned two-host policy is branded and deep-snapshotted; duplicate or forged policy rejects", () => {
  const [a, b] = signers();
  const s = newScope();
  const entries = [host(a, [s]), host(b, [s])];
  const trusted = policy(entries);
  assert.equal(Object.isFrozen(trusted), true);
  assert.throws(() => new Zk1SharedPgGateAuthority({ pool: { connect() {} },
    stopHostPolicy: { hosts: entries } }), /ZK_GATE_CONFIG_INVALID/);
  assert.throws(() => policy([host(a, [s]), host(a, [s])]), /ZK_GATE_CONFIG_INVALID/);
  assert.throws(() => policy([host(a, [s]), { ...host(b, [s]), hostPublicKey: a.keys.publicKey }]),
    /ZK_GATE_CONFIG_INVALID/);
  assert.throws(() => policy([{ ...host(a, [s]), status: "mystery" }, host(b, [s])]),
    /ZK_GATE_CONFIG_INVALID/);
  assert.throws(() => policy([host(a, [s]), host(b, [])]), /ZK_GATE_CONFIG_INVALID/);
  assert.throws(() => new Zk1SharedPgGateAuthority({ pool: { connect() {} },
    stopPinned: { hostKeyId: a.hostKeyId, hostPublicKey: a.keys.publicKey },
    stopHostPolicy: trusted }), /ZK_GATE_CONFIG_INVALID/);
  const gate = new Zk1SharedPgGateAuthority({ pool: { connect() {} }, stopHostPolicy: trusted });
  entries[0].hostKeyId.fill(0);
  entries[0].scopes[0].account_id.fill(0);
  entries[0].status = "revoked";
  entries.splice(0, entries.length);
  assert.equal(gate.allowsActivePinnedStopHost(a.hostKeyId, a.keys.publicKey), false,
    "mutated caller ID does not refer to the original snapshot");
  assert.equal(gate.allowsActivePinnedStopHost(b.hostKeyId, b.keys.publicKey), true);
});

test("two simulated hosts independently sign STOP; rotate to verify-only and restart before PENDING", {
  skip: !Object.values(urls).every(Boolean) && "requires disposable PG18 admin/gate/stop roles",
}, async (t) => {
  const admin = new Pool({ connectionString: urls.admin, max: 2 });
  const gatePool = new Pool({ connectionString: urls.gate, max: 3 });
  const stopPool = new Pool({ connectionString: urls.stop, max: 2 });
  const pools = [admin, gatePool, stopPool];
  const supervisors = [];
  const secondLogin = "zkstopmultihost_" + random(6).toString("hex");
  let createdSecondLogin = false;
  t.after(async () => {
    supervisors.forEach((s) => s.dispose());
    try {
      await Promise.all(pools.filter((p) => p !== admin).map((p) => p.end()));
      if (createdSecondLogin) await admin.query("DROP ROLE " + secondLogin);
    } finally { await admin.end(); }
  });
  // Both synthetic hosts use different LOGINs delegated to the same restricted
  // STOP role; sharing one physical machine does not prove host independence.
  const secondPassword = random(24).toString("hex");
  await admin.query("CREATE ROLE " + secondLogin + " LOGIN PASSWORD '" + secondPassword + "'");
  createdSecondLogin = true;
  await admin.query("GRANT zk1_stop_runtime TO " + secondLogin);
  const stop2Url = new URL(urls.stop);
  stop2Url.username = secondLogin;
  stop2Url.password = secondPassword;
  const stopPool2 = new Pool({ connectionString: stop2Url.toString(), max: 2 });
  pools.push(stopPool2);
  const [a, b] = signers();
  const scope = newScope();
  const foreignScope = newScope();
  const digest = random(32);
  for (const s of [scope, foreignScope]) await admin.query(
    "INSERT INTO zk1_gate.head (scope_key,keyring_id,revision,digest,require_stop_proof) VALUES($1,$2,1,$3,TRUE)",
    [keyOf(s), s.keyring_id, digest]);
  const trusted = policy([host(a, [scope, foreignScope]), host(b, [scope])]);
  const gate = new Zk1SharedPgGateAuthority({ pool: gatePool, stopHostPolicy: trusted });
  const op = [];
  const recorders = [];
  for (const [i, identity] of [a, b].entries()) {
    const supervisor = new Zk1IsolatedProcessStopSupervisor({ hostKeyId: identity.hostKeyId,
      hostPrivateKey: identity.keys.privateKey,
      workerScript: path.resolve(__dirname, "../lab/issue-65-packet-b/stop-child-worker.js") });
    supervisors.push(supervisor);
    const recorder = await createZk1PhysicalStopRecorder({ pool: i === 0 ? stopPool : stopPool2,
      trustedHostKeyId: identity.hostKeyId, trustedHostPublicKey: identity.keys.publicKey });
    recorders.push(recorder);
    op.push(new Zk1SharedPgStrictStopOperator({ gate, supervisor, recorder }));
  }
  const spoofSupervisor = new Zk1IsolatedProcessStopSupervisor({
    hostKeyId: b.hostKeyId, hostPrivateKey: a.keys.privateKey,
    workerScript: path.resolve(__dirname, "../lab/issue-65-packet-b/stop-child-worker.js"),
  });
  supervisors.push(spoofSupervisor);
  assert.throws(() => new Zk1SharedPgStrictStopOperator({
    gate, supervisor: spoofSupervisor, recorder: recorders[1],
  }), /ZK_GATE_DENIED/, "pinned host ID cannot authenticate a foreign supervisor signing key");
  const makeIo = () => ({ scope, workerId: random(16), principal: "AB:".repeat(31) + "AB",
    action: "put", objectId: random(16).toString("base64url"), revision: 1, digest });
  const inputs = [makeIo(), makeIo()];
  for (let i = 0; i < 2; i++) {
    op[i].prepare(inputs[i]);
    assert.equal((await op[i].beginTrustedLocalAdmission(inputs[i])).proceed, true);
  }
  const epochs = op.map((operator) => [...operator.entries.values()][0].process.processEpoch.toString("hex"));
  assert.notEqual(epochs[0], epochs[1], "simulated hosts use distinct physical process epochs");
  const reserved = { scope, operationId: random(16), reservationId: random(16), revision: 1, digest };
  assert.equal((await gate.beginQuiesce(reserved)).activeCount, 2);
  for (let i = 0; i < 2; i++) {
    const entry = [...op[i].entries.values()][0];
    assert.equal((await op[i].finishTrustedLocalAdmission({ scope,
      admissionId: entry.bound.admissionId, workerId: inputs[i].workerId,
      principal: inputs[i].principal })).status, "FINISHED");
    assert.equal(supervisors[i].sessions.get(entry.process.processEpoch.toString("hex")).closed, true);
  }
  const rotated = policy([host(a, [scope, foreignScope], "verify-only"),
    host(b, [scope], "verify-only")]);
  const restarted = new Zk1SharedPgGateAuthority({ pool: gatePool, stopHostPolicy: rotated });
  const rogue = crypto.generateKeyPairSync("ed25519");
  const incorrectKey = policy([
    { ...host(a, [scope]), hostPublicKey: rogue.publicKey },
    host(b, [scope]),
  ]);
  await assert.rejects(new Zk1SharedPgGateAuthority({
    pool: gatePool, stopHostPolicy: incorrectKey,
  }).markPending(reserved), /ZK_GATE_STOP_PROOF_INVALID/,
  "a matching host-key ID with a different public key cannot forge old STOP");
  const revoked = policy([host(a, [scope], "revoked"), host(b, [scope])]);
  await assert.rejects(new Zk1SharedPgGateAuthority({
    pool: gatePool, stopHostPolicy: revoked,
  }).markPending(reserved), /ZK_GATE_STOP_PROOF_INVALID/,
  "revoked host cannot validate a historical proof");
  assert.equal((await restarted.markPending(reserved)).status, "PENDING");
  const signs = await admin.query("SELECT DISTINCT encode(host_key_id,'hex') AS host FROM zk1_gate.physical_stop_receipt WHERE scope_key=$1", [keyOf(scope)]);
  assert.deepEqual(new Set(signs.rows.map((x) => x.host)),
    new Set([a.hostKeyId.toString("hex"), b.hostKeyId.toString("hex")]));
  assert.equal(restarted.allowsActivePinnedStopHost(a.hostKeyId, a.keys.publicKey), false);
  assert.equal(restarted.allowsActivePinnedStopHost(b.hostKeyId, b.keys.publicKey), false);
  assert.equal(gate.allowsActivePinnedStopHost(b.hostKeyId, a.keys.publicKey), false,
    "host ID alone is insufficient to select another host's public key");
  await assert.rejects(restarted.beginIoAdmission({ ...makeIo(), hostKeyId: a.hostKeyId,
    processEpoch: random(16), processPid: 12345 }), /ZK_GATE_DENIED/);
  await assert.rejects(restarted.beginIoAdmission({ ...makeIo(), scope: foreignScope,
    hostKeyId: a.hostKeyId, processEpoch: random(16), processPid: 12345 }),
  /ZK_GATE_DENIED/, "verify-only host must not START even in another currently OPEN permitted scope");
  const revokedGate = new Zk1SharedPgGateAuthority({ pool: gatePool, stopHostPolicy: policy([
    host(a, [scope, foreignScope], "revoked"), host(b, [scope]),
  ]) });
  await assert.rejects(revokedGate.beginIoAdmission({ ...makeIo(), scope: foreignScope,
    hostKeyId: a.hostKeyId, processEpoch: random(16), processPid: 12345 }),
  /ZK_GATE_DENIED/, "revoked host must not START a new admission");
  const other = { ...makeIo(), scope: foreignScope, hostKeyId: b.hostKeyId,
    processEpoch: random(16), processPid: 12345 };
  await assert.rejects(gate.beginIoAdmission(other), /ZK_GATE_DENIED/,
    "a host key pinned only for scope A cannot START in scope B");
  await assert.rejects(gate.beginIoAdmission({ ...other, hostKeyId: random(16) }),
    /ZK_GATE_DENIED/, "unknown host key ID does not fall back");
});
