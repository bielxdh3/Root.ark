"use strict";

// LAB ONLY: actual PostgreSQL ciphertext INSERT executes INSIDE the
// supervisor-owned direct ChildProcess. No HTTP, S3, Drive, GET or descendants.
// Dedicated chunk-WRITER login arrives over parent-owned IPC after START;
// neither PG credentials nor STOP signer key are inherited in environment.
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { verifyZk1ChunkWriterRuntimePool } =
  require("../../src/services/zk1SharedPgChunkWriterRuntime");

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
    || !/^zkwriterfixture_[a-f0-9]{12}$/.test(decodeURIComponent(url.username))
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
    // A delegated child has ZERO raw SELECT or INSERT rights over shared
    // tables. This boolean verifier examines only the immutable gate-owned
    // tuple selected by authenticated PostgreSQL session_user, and the
    // SECURITY DEFINER write function holds HEAD FOR UPDATE through COMMIT.
    const preflight = await c.query(`SELECT zk1_gate.verify_chunk_writer_binding(
      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) AS allowed`,
    [expected.key, expected.admissionId, expected.objectId,
      expected.generation, expected.workerId, expected.processEpoch,
      process.pid, expected.revision, expected.digest,
      expected.scope.keyring_id, expected.principal]);
    if (preflight.rowCount !== 1 || preflight.rows[0]?.allowed !== true) fail();
    const result = await c.query(
      "SELECT zk1_gate.write_bound_chunk($1,$2) AS stored", [index, blob]);
    if (result.rowCount !== 1 || result.rows[0]?.stored !== true) fail();
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
      await verifyZk1ChunkWriterRuntimePool(pool);
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
