"use strict";

// LAB ONLY: actual PostgreSQL ciphertext INSERT executes INSIDE the
// supervisor-owned direct ChildProcess. No HTTP, S3, Drive, GET or descendants.
// Restricted gate login arrives once over parent-owned local IPC after START;
// neither PG credentials nor STOP signer key are inherited in environment.
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { verifyZk1SharedPgRuntimePool } = require("../../src/services/zk1SharedPgGateRuntime");

const fail = () => { throw new Error("LAB_WORKER_DENIED"); };
const decode = (s, min, max = min) => {
  if (typeof s !== "string" || !/^[a-zA-Z0-9_-]+$/.test(s)) fail();
  const buffer = Buffer.from(s, "base64url");
  if (buffer.length < min || buffer.length > max || buffer.toString("base64url") !== s) fail();
  return buffer;
};
function parse(init) {
  if (!init || init.kind !== "init" || typeof init.pgUrl !== "string"
    || typeof init.objectId !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(init.objectId)
    || !Number.isSafeInteger(init.revision) || init.revision < 1
    || !Number.isSafeInteger(init.generation) || init.generation < 1
    || init.processPid !== process.pid || init.action !== "put"
    || typeof init.principal !== "string" || init.principal.length < 1) fail();
  const url = new URL(init.pgUrl);
  if (url.protocol !== "postgresql:" || url.hostname !== "127.0.0.1"
    || !/^zkgatefixture_[a-f0-9]{12}$/.test(decodeURIComponent(url.username))
    || url.pathname !== "/gatefixture" || !url.port || url.search || url.hash) fail();
  const scope = { account_id: decode(init.scope?.account_id, 16),
    compartment_id: decode(init.scope?.compartment_id, 1, 128),
    keyring_id: decode(init.scope?.keyring_id, 16) };
  return { connectionString: init.pgUrl, scope,
    key: scope.account_id.toString("hex") + ":"
      + scope.compartment_id.length.toString(16) + ":"
      + scope.compartment_id.toString("hex"),
    workerId: decode(init.workerId, 16), admissionId: decode(init.admissionId, 16),
    hostKeyId: decode(init.hostKeyId, 16), processEpoch: decode(init.processEpoch, 16),
    digest: decode(init.digest, 32), revision: init.revision, generation: init.generation,
    objectId: init.objectId, principal: init.principal };
}
let pool;
let expected;
let state = "new";
let release;
let indexHeld = -1;
let denied = false;
function say(kind) { if (process.connected) process.send({ kind }); }
function bad() { denied = true; state = "failed"; say("failed"); }

async function hold(message) {
  let c;
  try {
    const index = message.index;
    const blob = decode(message.ciphertext, 1, 4 * 1024 * 1024);
    if (!Number.isSafeInteger(index) || index < 0 || index > 4095
      || index <= indexHeld || state !== "ready") fail();
    state = "busy";
    c = await pool.connect();
    await c.query("BEGIN ISOLATION LEVEL READ COMMITTED");
    // Physical row lock is held throughout real insertion and until COMMIT.
    // No independent JS gateway callback or network effect escapes this lock.
    const { rows: heads, rowCount: hc } = await c.query(`SELECT keyring_id,phase,revision,digest,
      generation,require_stop_proof FROM zk1_gate.head WHERE scope_key=$1 FOR UPDATE`, [expected.key]);
    const h = heads[0];
    if (hc !== 1 || !h.keyring_id.equals(expected.scope.keyring_id)
      || h.phase !== "OPEN" || h.require_stop_proof !== true
      || Number(h.revision) !== expected.revision || !h.digest.equals(expected.digest)
      || Number(h.generation) !== expected.generation) fail();
    const { rows: admissions, rowCount: ac } = await c.query(`SELECT scope_key,worker_id,
      principal,action,object_id,revision,digest,generation,host_key_id,
      process_epoch,process_pid,state FROM zk1_gate.admission WHERE id=$1`, [expected.admissionId]);
    const a = admissions[0];
    if (ac !== 1 || a.scope_key !== expected.key
      || !a.worker_id.equals(expected.workerId) || a.principal !== expected.principal
      || a.action !== "put" || a.object_id !== expected.objectId
      || Number(a.revision) !== expected.revision || !a.digest.equals(expected.digest)
      || Number(a.generation) !== expected.generation || a.state !== "ACTIVE"
      || !a.host_key_id?.equals(expected.hostKeyId)
      || !a.process_epoch?.equals(expected.processEpoch)
      || Number(a.process_pid) !== process.pid) fail();
    const result = await c.query(`INSERT INTO zk1_gate.ciphertext_chunk
      (scope_key,object_id,chunk_index,ciphertext) VALUES($1,$2,$3,$4)
      ON CONFLICT DO NOTHING RETURNING chunk_index`,
    [expected.key, expected.objectId, index, blob]);
    if (result.rowCount !== 1) fail();
    indexHeld = index;
    state = "held";
    say("held");
    await new Promise((resolve) => { release = resolve; });
    release = null;
    await c.query("COMMIT");
    state = "ready";
    say("committed");
  } catch (_) {
    if (c) try { await c.query("ROLLBACK"); } catch (_) { /* fail closed */ }
    bad();
  } finally { if (c) c.release(); }
}
process.on("message", async (message) => {
  try {
    if (state === "new" && message?.kind === "init") {
      // Never echo or log the IPC database password or any ciphertext bytes.
      state = "bootstrapping";
      expected = parse(message);
      pool = new Pool({ connectionString: expected.connectionString, max: 1,
        connectionTimeoutMillis: 3000 });
      await verifyZk1SharedPgRuntimePool(pool);
      state = "ready";
      process.send({ kind: "bootstrapped", restrictedRoleVerified: true,
        inheritedSecrets: Object.keys(process.env).some((k) =>
          /(?:ROOTARK|PG(?:PASSWORD|USER|HOST|DATABASE)|PRIVATE_KEY|SECRET)/i.test(k)) });
      return;
    }
    if (state === "ready" && message?.kind === "hold") {
      void hold(message);
      return;
    }
    if (state === "held" && message?.kind === "release" && release) {
      release();
      return;
    }
    fail();
  } catch (_) { bad(); }
});
process.on("disconnect", () => {
  // Parent death is not an authorization to COMMIT queued bytes.
  // Release of open socket/transaction is performed by terminating the child.
  process.exit(2);
});
