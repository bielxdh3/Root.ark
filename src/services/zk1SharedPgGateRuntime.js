"use strict";

// Explicit fail-closed startup path for the standalone PostgreSQL gate.
// A web-application pool and a PostgreSQL superuser must NEVER be accepted
// as this service's runtime credential. Operator provisions a distinct login
// with inherited zk1_gate_runtime membership out of band.
const { Zk1SharedPgGateAuthority } = require("./zk1SharedPgGateAuthority");
const { createZk1SharedPgGateHttpsServer } = require("./zk1SharedPgGateHttpsServer");

function refuse() {
  const error = new Error("ZK_GATE_RUNTIME_IDENTITY_INVALID");
  error.code = "ZK_GATE_RUNTIME_IDENTITY_INVALID";
  throw error;
}

async function verifyZk1SharedPgRuntimePool(pool) {
  if (!pool || typeof pool.connect !== "function") refuse();
  let c;
  try {
    c = await pool.connect();
    const result = await c.query(`SELECT
      session_user AS session_identity, current_user AS active_identity,
      r.rolcanlogin AS can_login, r.rolsuper AS is_superuser,
      r.rolcreatedb AS can_create_db, r.rolcreaterole AS can_create_role,
      pg_has_role(current_user, 'zk1_gate_runtime', 'USAGE') AS gate_access,
      has_schema_privilege(current_user,'zk1_gate','USAGE') AS schema_access,
      has_schema_privilege(current_user,'zk1_gate','CREATE') AS schema_create,
      has_column_privilege(current_user,'zk1_gate.head','revision','UPDATE') AS can_change_revision,
      has_column_privilege(current_user,'zk1_gate.head','phase','UPDATE') AS can_change_phase,
      has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','DELETE') AS can_delete_ciphertext,
      has_table_privilege(current_user,'zk1_gate.ciphertext_chunk','TRUNCATE') AS can_truncate_ciphertext
      FROM pg_roles AS r WHERE r.rolname=current_user`);
    const x = result.rows?.[0];
    if (result.rowCount !== 1 || !x || x.session_identity !== x.active_identity
      || x.active_identity === "zk1_gate_runtime" || x.can_login !== true
      || x.is_superuser !== false || x.can_create_db !== false
      || x.can_create_role !== false || x.gate_access !== true
      || x.schema_access !== true || x.schema_create !== false
      || x.can_change_revision !== false || x.can_change_phase !== true
      || x.can_delete_ciphertext !== false || x.can_truncate_ciphertext !== false) refuse();
    return Object.freeze({ verified: true, runtimeRole: x.active_identity });
  } catch (_) { refuse(); }
  finally { if (c) c.release(); }
}

async function createIsolatedZk1SharedPgGateServer({ pool, key, cert, clientCa,
  principals } = {}) {
  // No listener/socket exists until the live PostgreSQL login and permissions
  // have been reconciled from the same pool used by gate transactions.
  await verifyZk1SharedPgRuntimePool(pool);
  return createZk1SharedPgGateHttpsServer({ key, cert, clientCa,
    gate: new Zk1SharedPgGateAuthority({ pool }), principals });
}

module.exports = { verifyZk1SharedPgRuntimePool,
  createIsolatedZk1SharedPgGateServer };
