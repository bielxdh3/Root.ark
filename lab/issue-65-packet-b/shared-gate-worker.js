"use strict";

// Synthetic *separate process* trusted PostgreSQL chunk worker for the
// disposable lab. It must not be run as a web-exposed service.
const { Pool } = require("pg");

function decode(s) { return Buffer.from(s, "base64url"); }
const pool = new Pool({ connectionString: process.env.ROOTARK_ZK1_TEST_PG_URL,
  max: 1, connectionTimeoutMillis: 3000 });

process.once("message", async (request) => {
  if (request?.kind !== "hold-effect") process.exit(2);
  const step = { ...request.step,
    scope: {
      account_id: decode(request.step.scope.account_id),
      compartment_id: decode(request.step.scope.compartment_id),
      keyring_id: decode(request.step.scope.keyring_id),
    },
    workerId: decode(request.step.workerId), admissionId: decode(request.step.admissionId),
    digest: decode(request.step.digest),
  };
  try {
    // Test-only raw transaction to hold the PostgreSQL head row lock across
    // a synthetic write. Product data-plane code does NOT expose a generic
    // arbitrary asynchronous-effect callback (unsafe on PG lock loss).
    const connection = await pool.connect();
    try {
      await connection.query("BEGIN");
      const key = step.scope.account_id.toString("hex") + ":"
        + step.scope.compartment_id.length.toString(16) + ":"
        + step.scope.compartment_id.toString("hex");
      await connection.query("SELECT scope_key FROM zk1_gate.head WHERE scope_key=$1 FOR UPDATE", [key]);
      await connection.query(`INSERT INTO zk1_gate.ciphertext_chunk
        (scope_key,object_id,chunk_index,ciphertext) VALUES($1,$2,$3,$4)`,
      [key, step.objectId, request.index, Buffer.from("disposable-ciphertext")]);
      process.send?.({ kind: "effect-held" });
      await new Promise((resolve) => process.once("message", (message) => {
        if (message?.kind === "release-effect") resolve();
      }));
      await connection.query("COMMIT");
    } finally { connection.release(); }
    process.send?.({ kind: "effect-complete" });
    await pool.end();
  } catch (_) {
    process.send?.({ kind: "effect-failed" });
    await pool.end();
    process.exitCode = 1;
  }
});
